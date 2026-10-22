"""
demo_remote_pipeline.py

Runs the StreamingEngine on logs arriving over the network instead of a
local file.

UDP syslog (two terminals):
    Terminal 1:  python demo_remote_pipeline.py --source udp
    Terminal 2:  python demo_syslog_sender.py

SSH tail (any host you can ssh to; its key must be in known_hosts):
    python demo_remote_pipeline.py --source ssh --ssh-host myserver \\
        --ssh-user me --ssh-path /var/log/auth.log --ssh-key ~/.ssh/id_ed25519

Output: a line when the baseline is fitted, every anomaly as it happens,
and a status line every --status-every lines (with UDP drop counts).
"""

import argparse
import getpass
import os
import time

from engine import Stats, StreamingEngine
from remote_sources import ssh_tail, syslog_udp_listener


def main():
    ap = argparse.ArgumentParser(description="Live remote log ingestion demo.")
    ap.add_argument("--source", choices=["udp", "ssh"], default="udp")
    ap.add_argument("--host", default="127.0.0.1", help="UDP bind address (0.0.0.0 = all interfaces)")
    ap.add_argument("--port", type=int, default=5140, help="UDP port")
    ap.add_argument("--ssh-host")
    ap.add_argument("--ssh-port", type=int, default=22)
    ap.add_argument("--ssh-user", default=getpass.getuser())
    ap.add_argument("--ssh-path", default="/var/log/auth.log")
    ap.add_argument("--ssh-key")
    ap.add_argument("--known-hosts")
    ap.add_argument("--insecure", action="store_true", help="accept unknown SSH host keys (MITM risk)")
    ap.add_argument("--baseline", type=int, default=300)
    ap.add_argument("--max-lines", type=int, help="exit after this many lines")
    ap.add_argument("--status-every", type=int, default=250)
    args = ap.parse_args()

    stats = Stats()
    counters = {}
    if args.source == "udp":
        source = syslog_udp_listener(host=args.host, port=args.port,
                                     max_lines=args.max_lines, counters=counters)
        where = f"udp://{args.host}:{args.port}"
        print(f"Listening on {where}. Waiting for {args.baseline} lines to calibrate...")
        print("(start demo_syslog_sender.py in another terminal now)\n")
    else:
        if not args.ssh_host:
            ap.error("--ssh-host is required for --source ssh")
        source = ssh_tail(args.ssh_host, args.ssh_user, args.ssh_path, port=args.ssh_port,
                          key_filename=os.path.expanduser(args.ssh_key) if args.ssh_key else None,
                          password=os.environ.get("LFE_SSH_PASSWORD"),
                          known_hosts=args.known_hosts, insecure=args.insecure,
                          counters=counters)
        where = f"ssh://{args.ssh_user}@{args.ssh_host}:{args.ssh_path}"
        print(f"Tailing {where}. Waiting for {args.baseline} lines to calibrate...\n")
    stats.attach_source_counters(counters)

    engine = StreamingEngine(source, baseline_size=args.baseline, stats=stats,
                             source_type=args.source)
    started = time.time()
    live_announced = False
    try:
        for event in engine.run():
            if event["phase"] == "live" and not live_announced:
                live_announced = True
                print(f"--- Baseline fitted from {args.baseline} remote records "
                      f"(threshold {engine.detector.threshold:.3f}). Live scoring begins. ---")
            if event["is_anomaly"] and event["phase"] == "live" or not event["parsed"]:
                if event["parsed"]:
                    print(f"[ANOMALY] dist={event['distance']:6.2f} sev={event['severity']:<8} "
                          f"ip={event['ip'] or '-':<15} {event['message'][:60]}  ({event['reason']})")
                else:
                    print(f"[UNPARSEABLE] {event['raw'][:80]!r}")
            if event["seq"] % args.status_every == 0:
                snap = stats.snapshot()
                print(f"  .. {snap['total_lines']} lines, {snap['anomalies']} anomalies, "
                      f"{snap['lines_per_sec']:.0f} lines/s, phase={snap['phase']}, "
                      f"udp received={counters.get('received', '-')} dropped={counters.get('dropped', '-')}")
    except KeyboardInterrupt:
        pass
    snap = stats.snapshot()
    print(f"\nProcessed {snap['total_lines']} lines from {where} in {time.time() - started:.1f}s: "
          f"{snap['anomalies']} anomalies, {snap['unparseable']} unparseable, "
          f"severity counts {snap['severity_counts']}, "
          f"UDP dropped={counters.get('dropped', 'n/a')}")


if __name__ == "__main__":
    main()
