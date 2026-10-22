"""
synthetic_logs.py

Deterministic labeled log generator with injected anomalies, so detection
quality can be measured against ground truth (public log datasets are
sanitised and unlabeled).

generate_labeled_lines(...) yields (line, label) where
    label = {"anomalous": bool,
             "type": "normal" | "bruteforce" | "portscan" | "malformed"
                     | "odd_hour" | "slow_bruteforce"}

Anomaly types
  bruteforce       burst of 5-15 failed logins from one IP, 0.1-1 s apart
  portscan         burst of 8-20 firewall drops (syslog) or 404 path probes
                   (access log) from one IP, 0.01-0.2 s apart
  malformed        a garbage line the parser cannot read
  odd_hour         a successful login at 03:xx
  slow_bruteforce  the subtle one: one failed login every 20-60 s from one
                   IP, interleaved with normal traffic, so recall cannot
                   look good just because every attack is a loud burst

Modes
  "syslog"  auth.log-style lines only (the original generator)
  "access"  Apache/Nginx combined access-log lines only
  "mixed"   each event picks a format at random

Determinism: all randomness comes from one random.Random(seed), and dates
are formatted without locale-dependent strftime codes, so the same
arguments give byte-identical output on any machine. With
anomaly_types=LEGACY_ANOMALY_TYPES, mode="syslog" and rich=False the
random call sequence is identical to the original generator, which is what lets
evaluate.py reproduce the original README numbers.
"""

import argparse
import hashlib
import random
import time
from collections import Counter
from datetime import datetime, timedelta

USERS = ["root", "admin", "deploy", "alice", "bob", "svc_backup"]
HOSTS = ["web01", "web02", "db01", "auth01"]
NORMAL_IPS = ["10.0.0.5", "10.0.0.7", "10.0.0.12", "192.168.1.20"]
SUSPICIOUS_IPS = ["203.0.113.55", "198.51.100.23", "185.220.101.7"]
SLOW_ATTACKER_IPS = ["45.155.205.10", "91.240.118.66", "176.111.174.20"]
WEB_CLIENT_IPS = NORMAL_IPS + ["192.168.1.21", "192.168.1.34", "10.0.1.8"]

LEGACY_ANOMALY_TYPES = ("bruteforce", "portscan", "malformed", "odd_hour")
ANOMALY_TYPES = LEGACY_ANOMALY_TYPES + ("slow_bruteforce",)
LABEL_TYPES = ("normal",) + ANOMALY_TYPES
MODES = ("syslog", "access", "mixed")

DEFAULT_START = datetime(2026, 8, 28, 0, 0, 0)

_MONTHS = ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
           "Jul", "Aug", "Sep", "Oct", "Nov", "Dec")

WEB_PATHS = [("GET", "/"), ("GET", "/index.html"), ("GET", "/static/app.js"),
             ("GET", "/static/style.css"), ("GET", "/api/items"),
             ("GET", "/api/items/42"), ("POST", "/api/cart"), ("GET", "/about")]
SCAN_PATHS = ["/wp-admin/", "/.env", "/phpmyadmin/", "/.git/config", "/admin.php",
              "/cgi-bin/test.cgi", "/backup.zip", "/server-status", "/config.json",
              "/vendor/phpunit/phpunit/src/Util/PHP/eval-stdin.php"]
USER_AGENTS = ["Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
               "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) Safari/605.1.15",
               "Mozilla/5.0 (X11; Linux x86_64) Firefox/128.0"]
ATTACK_AGENTS = ["python-requests/2.31", "curl/8.4.0", "Nikto/2.5.0", "masscan/1.3"]

# Ordinary system chatter at every severity, so the severity classifier
# has a real task (with only logins, "ERROR" just means "failed login").
SYSTEM_MESSAGES = [
    ("systemd", "Started Daily apt download activities."),
    ("systemd", "Started Session 4242 of user deploy."),
    ("sudo", "alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/apt update"),
    ("CRON", "pam_unix(cron:session): session opened for user root by (uid=0)"),
    ("sshd", "error: kex_exchange_identification: read: Connection reset by peer"),
    ("app", "ERROR worker 3 crashed while processing job 8812, restarting"),
    ("nginx", "upstream timeout while reading response header from upstream"),
    ("kernel", "EXT4-fs warning (device sda1): ext4_dx_add_entry: directory index full"),
    ("dhclient", "DHCPREQUEST retry on eth0 to 10.0.0.1 port 67"),
    ("postgres", 'FATAL: password authentication failed for user "app"'),
    ("smartd", "Device: /dev/sda, SMART Failure: critical temperature reached"),
    ("app", "panic: runtime error: invalid memory address or nil pointer dereference"),
]


def _syslog_ts(dt):
    return f"{_MONTHS[dt.month - 1]} {dt.day:02d} {dt.hour:02d}:{dt.minute:02d}:{dt.second:02d}"


def _normal_line(dt, host, process, pid, message):
    return f"{_syslog_ts(dt)} {host} {process}[{pid}]: {message}"


def _access_line(dt, ip, method, path, status, size, agent):
    ts = f"{dt.day:02d}/{_MONTHS[dt.month - 1]}/{dt.year}:{dt.hour:02d}:{dt.minute:02d}:{dt.second:02d} +0000"
    return f'{ip} - - [{ts}] "{method} {path} HTTP/1.1" {status} {size} "-" "{agent}"'


def _label(kind):
    return {"anomalous": kind != "normal", "type": kind}


class _Clock:
    """Mutable simulated clock shared between consecutive streams, so a
    live stream continues where the baseline stream stopped instead of
    jumping back to the start time."""

    def __init__(self, t):
        self.t = t


def _generate(n, anomaly_rate, clock, seed, anomaly_types, mode, rich):
    rng = random.Random(seed)
    anomaly_types = list(anomaly_types)
    use_slow = "slow_bruteforce" in anomaly_types
    t = clock.t
    pid_counter = 1000
    attacker = None  # active slow brute-force: {ip, user, remaining, next_t, access}
    i = 0

    def pick_access():
        if mode == "syslog":
            return False
        if mode == "access":
            return True
        return rng.random() < 0.5

    while n is None or i < n:
        if rng.random() < anomaly_rate:
            burst_type = rng.choice(anomaly_types)

            if burst_type == "bruteforce":
                access = pick_access()
                ip = rng.choice(SUSPICIOUS_IPS)
                user = rng.choice(["root", "admin"])
                burst_len = rng.randint(5, 15)
                for _ in range(burst_len):
                    if n is not None and i >= n:
                        break
                    t += timedelta(seconds=rng.uniform(0.1, 1.0))
                    pid_counter += 1
                    if access:
                        line = _access_line(t, ip, "POST", "/login", 401,
                                            rng.randint(180, 260), rng.choice(ATTACK_AGENTS))
                    else:
                        line = _normal_line(
                            t, rng.choice(HOSTS), "sshd", pid_counter,
                            f"Failed password for {user} from {ip} port {rng.randint(1024, 65000)} ssh2",
                        )
                    clock.t = t
                    yield line, _label("bruteforce")
                    i += 1
                continue

            if burst_type == "portscan":
                access = pick_access()
                ip = rng.choice(SUSPICIOUS_IPS)
                burst_len = rng.randint(8, 20)
                for _ in range(burst_len):
                    if n is not None and i >= n:
                        break
                    t += timedelta(seconds=rng.uniform(0.01, 0.2))
                    pid_counter += 1
                    if access:
                        line = _access_line(t, ip, "GET", rng.choice(SCAN_PATHS), 404,
                                            rng.randint(150, 400), rng.choice(ATTACK_AGENTS))
                    else:
                        port = rng.randint(1, 65000)
                        line = _normal_line(
                            t, rng.choice(HOSTS), "kernel", pid_counter,
                            f"DROP IN= OUT= SRC={ip} DST=10.0.0.1 PROTO=TCP DPT={port}",
                        )
                    clock.t = t
                    yield line, _label("portscan")
                    i += 1
                continue

            if burst_type == "malformed":
                t += timedelta(seconds=rng.uniform(1, 5))
                garbage_lines = [
                    "###CORRUPTED_ENTRY###",
                    f"{rng.randint(0, 999999)},,,,\x00\x00broken",
                    "sshd: incomplete entry no timestamp",
                ]
                clock.t = t
                yield rng.choice(garbage_lines), _label("malformed")
                i += 1
                continue

            if burst_type == "odd_hour":
                # Jump forward to 03:xx on the current (or next) day; the
                # clock must stay monotonic or every later time delta and
                # per-IP rate would be corrupted.
                access = pick_access()
                t += timedelta(seconds=rng.uniform(2, 30))
                odd_time = t.replace(hour=3, minute=rng.randint(0, 59), second=rng.randint(0, 59))
                if odd_time < t:
                    odd_time += timedelta(days=1)
                t = odd_time
                pid_counter += 1
                user = rng.choice(USERS)
                ip = rng.choice(NORMAL_IPS)
                if access:
                    line = _access_line(t, ip, "POST", "/admin/login", 302,
                                        rng.randint(300, 500), rng.choice(USER_AGENTS))
                else:
                    line = _normal_line(
                        t, rng.choice(HOSTS), "sshd", pid_counter,
                        f"Accepted password for {user} from {ip} port {rng.randint(1024, 65000)} ssh2",
                    )
                clock.t = t
                yield line, _label("odd_hour")
                i += 1
                continue

            if burst_type == "slow_bruteforce" and attacker is None:
                attacker = {
                    "ip": rng.choice(SLOW_ATTACKER_IPS),
                    "user": rng.choice(["root", "admin", "oracle", "test"]),
                    "remaining": rng.randint(6, 20),
                    "next_t": t + timedelta(seconds=rng.uniform(20, 60)),
                    "access": pick_access(),
                }
            # slow_bruteforce only schedules the attacker; this iteration
            # still produces normal traffic below.

        # Normal traffic. A scheduled slow brute-force attempt that falls
        # before the next normal event is emitted first, at its own time.
        target = t + timedelta(seconds=rng.uniform(2, 30))
        if use_slow:
            while attacker is not None and attacker["next_t"] <= target:
                if n is not None and i >= n:
                    break
                t = max(t, attacker["next_t"])
                pid_counter += 1
                if attacker["access"]:
                    line = _access_line(t, attacker["ip"], "POST", "/login", 401,
                                        rng.randint(180, 260), rng.choice(ATTACK_AGENTS))
                else:
                    line = _normal_line(
                        t, rng.choice(HOSTS), "sshd", pid_counter,
                        f"Failed password for {attacker['user']} from {attacker['ip']} "
                        f"port {rng.randint(1024, 65000)} ssh2",
                    )
                clock.t = t
                yield line, _label("slow_bruteforce")
                i += 1
                attacker["remaining"] -= 1
                if attacker["remaining"] <= 0:
                    attacker = None
                else:
                    attacker["next_t"] = t + timedelta(seconds=rng.uniform(20, 60))
            if n is not None and i >= n:
                break

        t = max(t, target)
        pid_counter += 1
        if pick_access():
            ip = rng.choice(WEB_CLIENT_IPS)
            roll = rng.random()
            if roll < 0.08:
                # ordinary users mistype passwords too
                method, path, status = "POST", "/login", 401 if rng.random() < 0.3 else 302
            else:
                method, path = rng.choice(WEB_PATHS)
                status = 404 if roll > 0.97 else (304 if roll > 0.85 else 200)
            line = _access_line(t, ip, method, path, status,
                                rng.randint(200, 25000), rng.choice(USER_AGENTS))
        else:
            user = rng.choice(USERS)
            ip = rng.choice(NORMAL_IPS)
            host = rng.choice(HOSTS)
            event_type = rng.choice(["accepted_login", "failed_login_once", "cron", "info"])
            if event_type == "accepted_login":
                message = f"Accepted password for {user} from {ip} port {rng.randint(1024, 65000)} ssh2"
            elif event_type == "failed_login_once":
                message = f"Failed password for {user} from {ip} port {rng.randint(1024, 65000)} ssh2"
            elif event_type == "cron":
                message = "(CRON) CMD (/usr/bin/backup.sh)"
            else:
                message = "Connection established"
            process = "sshd" if "login" in event_type else "CRON"
            if rich and event_type == "info" and rng.random() < 0.6:
                process, message = rng.choice(SYSTEM_MESSAGES)
            line = _normal_line(t, host, process, pid_counter, message)
        clock.t = t
        yield line, _label("normal")
        i += 1


def generate_labeled_lines(n=2000, anomaly_rate=0.05, start_time=None, seed=None,
                           anomaly_types=ANOMALY_TYPES, mode="syslog", rich=True):
    """
    Yield (line, label) pairs. n=None streams forever. Deterministic for a
    given seed. rich=False drops the varied system messages (original
    traffic mix).
    """
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    clock = _Clock(start_time or DEFAULT_START)
    yield from _generate(n, anomaly_rate, clock, seed, anomaly_types, mode, rich)


def calibrated_stream(baseline_n=300, n=2000, anomaly_rate=0.05, seed=42,
                      start_time=None, anomaly_types=ANOMALY_TYPES, mode="syslog", rich=True):
    """
    A quiet calibration period followed by live traffic, on ONE continuous
    simulated clock: `baseline_n` anomaly-free lines (seed), then `n` lines
    at `anomaly_rate` (seed + 1; n=None streams forever). This is how a
    SOC would calibrate: learn "normal" from a known-quiet window, then
    monitor. The original pipeline restarted the clock for the live stream
    so the first live timestamp jumped backwards; here it continues.
    """
    if mode not in MODES:
        raise ValueError(f"mode must be one of {MODES}")
    clock = _Clock(start_time or DEFAULT_START)
    yield from _generate(baseline_n, 0.0, clock, seed, anomaly_types, mode, rich)
    live_seed = None if seed is None else seed + 1
    yield from _generate(n, anomaly_rate, clock, live_seed, anomaly_types, mode, rich)


def generate_lines(n=2000, anomaly_rate=0.05, seed=None, **kwargs):
    """Just the raw lines, no labels."""
    for line, _ in generate_labeled_lines(n=n, anomaly_rate=anomaly_rate, seed=seed, **kwargs):
        yield line


def live_generator(rate=20.0, anomaly_rate=0.05, seed=None, baseline_n=300,
                   mode="mixed", stop_event=None):
    """
    Endless (line, label) stream paced at roughly `rate` lines per second
    of real time, for demoing the dashboard. One continuous clock: the
    original version restarted the simulated time every 200 lines.
    """
    interval = 1.0 / rate if rate > 0 else 0.0
    next_at = time.monotonic()
    for item in calibrated_stream(baseline_n=baseline_n, n=None, anomaly_rate=anomaly_rate,
                                  seed=seed, mode=mode):
        if stop_event is not None and stop_event.is_set():
            return
        if interval:
            next_at += interval
            delay = next_at - time.monotonic()
            if delay > 0:
                time.sleep(delay)
            elif delay < -1.0:
                next_at = time.monotonic()  # fell behind; don't try to catch up in a burst
        yield item


def main():
    ap = argparse.ArgumentParser(description="Generate labeled synthetic logs.")
    ap.add_argument("--n", type=int, default=10_000)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--anomaly-rate", type=float, default=0.05)
    ap.add_argument("--mode", choices=MODES, default="syslog")
    ap.add_argument("--legacy", action="store_true",
                    help="original generator: four anomaly types, no system messages")
    ap.add_argument("--show", type=int, default=8, help="print the first N lines")
    ap.add_argument("--out", help="write lines to this file")
    args = ap.parse_args()

    types = LEGACY_ANOMALY_TYPES if args.legacy else ANOMALY_TYPES
    counts = Counter()
    digest = hashlib.sha256()
    out = open(args.out, "w", encoding="utf-8") if args.out else None
    try:
        for idx, (line, label) in enumerate(generate_labeled_lines(
                n=args.n, anomaly_rate=args.anomaly_rate, seed=args.seed,
                anomaly_types=types, mode=args.mode, rich=not args.legacy)):
            counts[label["type"]] += 1
            digest.update(line.encode("utf-8") + b"\n")
            if out:
                out.write(line + "\n")
            if idx < args.show:
                print(f"{label['type']:<16} {line!r}")
    finally:
        if out:
            out.close()

    print(f"\n{args.n:,} lines  mode={args.mode}  seed={args.seed}  sha256={digest.hexdigest()[:16]}")
    print(f"{'type':<16}{'count':>8}{'share':>9}")
    for kind in LABEL_TYPES:
        if kind in counts:
            print(f"{kind:<16}{counts[kind]:>8}{counts[kind] / args.n:>9.2%}")


if __name__ == "__main__":
    main()
