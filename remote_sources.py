"""
remote_sources.py

Log input from other machines, with the same generator contract as
log_source.py (yield one str per line), so the engine does not care where
lines come from.

syslog_udp_listener(...)
    A UDP syslog receiver. Binds to 127.0.0.1 by default: listening on
    every interface (0.0.0.0) must be asked for explicitly, because anyone
    who can reach the port can inject log lines. A socket thread reads
    datagrams into a bounded queue.Queue; when the consumer falls behind,
    new datagrams are dropped and counted instead of buffered without
    bound. RFC 3164 <PRI> prefixes are stripped.

    UDP is lossy by design: datagrams dropped by the network or by the
    kernel's receive buffer never reach us and cannot be counted; only
    drops in our own queue are.

ssh_tail(...)
    Runs `tail -F` on a remote host over SSH (paramiko) and streams the
    output. Host keys are verified: RejectPolicy plus the system
    known_hosts (and an optional extra known_hosts file). Accepting
    unknown keys (AutoAddPolicy) needs insecure=True and emits a warning,
    since it allows a man-in-the-middle to read the stream or feed it
    fake lines. The remote path is shell-quoted with shlex.quote. If the
    connection drops it reconnects with exponential backoff and jitter.
"""

import queue
import random
import re
import shlex
import socket
import threading
import time
import warnings

PRI_RE = re.compile(r"^<\d{1,3}>")
MAX_LINE_BYTES = 64 * 1024


def strip_pri(line):
    """Remove a leading RFC 3164 <PRI> tag, e.g. '<38>Aug 28 ...'."""
    return PRI_RE.sub("", line, count=1)


def _stopped(stop_event):
    return stop_event is not None and stop_event.is_set()


def syslog_udp_listener(host="127.0.0.1", port=5140, max_lines=None, queue_size=10_000,
                        stop_event=None, counters=None, ready_event=None, strip=True):
    """
    Yield lines received as UDP syslog datagrams.

    host          interface to bind; pass "0.0.0.0" explicitly to accept
                  datagrams from other machines
    port          UDP port (0 picks a free port; see counters["bound"])
    max_lines     stop after this many lines (None = run forever)
    queue_size    bound on datagrams waiting between socket and consumer
    stop_event    threading.Event to stop the generator from another thread
    counters      dict updated in place: received, dropped, lines, bound
    ready_event   set once the socket is bound (handy for tests and demos)
    """
    counters = counters if counters is not None else {}
    counters.update(received=0, dropped=0, lines=0)
    buffer = queue.Queue(maxsize=queue_size)
    halt = threading.Event()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind((host, port))
    sock.settimeout(0.5)
    counters["bound"] = sock.getsockname()
    if ready_event is not None:
        ready_event.set()

    def reader():
        while not halt.is_set():
            try:
                data, _addr = sock.recvfrom(65535)
            except socket.timeout:
                continue
            except OSError:
                break
            counters["received"] += 1
            try:
                buffer.put_nowait(data)
            except queue.Full:
                counters["dropped"] += 1

    thread = threading.Thread(target=reader, name="udp-syslog-reader", daemon=True)
    thread.start()

    count = 0
    try:
        while max_lines is None or count < max_lines:
            if _stopped(stop_event):
                break
            try:
                data = buffer.get(timeout=0.5)
            except queue.Empty:
                continue
            # One datagram may carry several newline-separated messages.
            for raw in data.decode("utf-8", errors="replace").splitlines():
                line = raw.strip()
                if strip:
                    line = strip_pri(line).strip()
                if not line:
                    continue
                count += 1
                counters["lines"] = count
                yield line
                if max_lines is not None and count >= max_lines:
                    break
    finally:
        halt.set()
        sock.close()
        thread.join(timeout=2)


class SSHConfigError(Exception):
    """Errors that retrying cannot fix (bad credentials, unknown host key)."""


def ssh_tail(hostname, username, remote_path, password=None, key_filename=None, port=22,
             known_hosts=None, insecure=False, from_end=True, max_retries=None,
             backoff_base=1.0, backoff_max=60.0, connect_timeout=10.0,
             stop_event=None, counters=None):
    """
    Yield lines appended to `remote_path` on `hostname`, via `tail -F`.

    known_hosts   extra known_hosts file to trust in addition to the
                  system one (~/.ssh/known_hosts)
    insecure      accept unknown host keys (AutoAddPolicy). Off by default.
    from_end      start at the end of the file (tail -n 0) rather than
                  replaying it from the top (tail -n +1)
    max_retries   reconnect attempts after a drop before giving up
                  (None = keep trying forever)

    Limitation: lines written while disconnected are not replayed when
    from_end=True, because the reconnect starts at the end again.
    """
    try:
        import paramiko
    except ImportError as exc:  # pragma: no cover - paramiko is in requirements
        raise ImportError("ssh_tail needs paramiko: pip install paramiko") from exc

    counters = counters if counters is not None else {}
    counters.update(connects=0, reconnects=0, lines=0)
    start = "0" if from_end else "+1"
    command = f"tail -n {start} -F {shlex.quote(remote_path)}"
    if insecure:
        warnings.warn("ssh_tail(insecure=True) accepts unknown host keys; "
                      "a man-in-the-middle could read or forge the log stream",
                      RuntimeWarning, stacklevel=2)

    attempt = 0
    while not _stopped(stop_event):
        client = paramiko.SSHClient()
        client.load_system_host_keys()
        if known_hosts:
            client.load_host_keys(known_hosts)
        client.set_missing_host_key_policy(
            paramiko.AutoAddPolicy() if insecure else paramiko.RejectPolicy())
        try:
            try:
                client.connect(hostname=hostname, port=port, username=username,
                               password=password, key_filename=key_filename,
                               timeout=connect_timeout, banner_timeout=connect_timeout,
                               auth_timeout=connect_timeout,
                               allow_agent=password is None and key_filename is None,
                               look_for_keys=password is None and key_filename is None)
            except paramiko.AuthenticationException as exc:
                raise SSHConfigError(f"SSH authentication failed for {username}@{hostname}") from exc
            except paramiko.BadHostKeyException as exc:
                raise SSHConfigError(f"host key for {hostname} does not match known_hosts") from exc
            except paramiko.SSHException as exc:
                if "known_hosts" in str(exc):
                    raise SSHConfigError(
                        f"{hostname} is not in known_hosts; add its key (ssh-keyscan) "
                        f"or pass known_hosts=..., or insecure=True if you accept the risk"
                    ) from exc
                raise

            counters["connects"] += 1
            transport = client.get_transport()
            transport.set_keepalive(15)
            channel = transport.open_session()
            channel.settimeout(1.0)
            channel.exec_command(command)
            attempt = 0  # connected: reset the backoff

            buf = b""
            while not _stopped(stop_event):
                try:
                    data = channel.recv(32768)
                except socket.timeout:
                    if channel.exit_status_ready() or not transport.is_active():
                        break
                    continue
                if not data:
                    break  # remote side closed the channel
                buf += data
                *lines, buf = buf.split(b"\n")
                if len(buf) > MAX_LINE_BYTES:
                    buf = b""  # runaway line without newline: drop it
                for raw in lines:
                    line = raw.decode("utf-8", errors="replace").strip()
                    if line:
                        counters["lines"] += 1
                        yield line
        except SSHConfigError:
            raise
        except (paramiko.SSHException, OSError, EOFError):
            pass  # connection-level failure: fall through to backoff
        finally:
            client.close()

        if _stopped(stop_event):
            return
        attempt += 1
        if max_retries is not None and attempt > max_retries:
            raise ConnectionError(f"ssh_tail: gave up after {max_retries} reconnect attempts")
        counters["reconnects"] += 1
        delay = min(backoff_max, backoff_base * 2 ** (attempt - 1))
        delay *= 0.5 + random.random() / 2  # jitter so many tailers don't stampede
        deadline = time.monotonic() + delay
        while time.monotonic() < deadline and not _stopped(stop_event):
            time.sleep(min(0.2, max(0.0, deadline - time.monotonic())))
