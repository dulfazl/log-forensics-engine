"""
demo_syslog_sender.py

Plays the "remote machine": sends synthetic log lines as UDP syslog
datagrams, each with an RFC 3164 <PRI> prefix like a real syslog daemon.
The first --baseline lines are quiet traffic so the receiver can calibrate,
then anomalies start at --anomaly-rate.

    python demo_syslog_sender.py --host 127.0.0.1 --port 5140 --count 1500
"""

import argparse
import socket
import time

from synthetic_logs import MODES, calibrated_stream

# facility 4 (auth) * 8 + severity 6 (informational)
AUTH_INFO_PRI = 38


def main():
    ap = argparse.ArgumentParser(description="Send synthetic syslog over UDP.")
    ap.add_argument("--host", default="127.0.0.1")
    ap.add_argument("--port", type=int, default=5140)
    ap.add_argument("--count", type=int, default=1500, help="live lines after the baseline")
    ap.add_argument("--baseline", type=int, default=300, help="quiet lines sent first")
    ap.add_argument("--anomaly-rate", type=float, default=0.05)
    ap.add_argument("--delay", type=float, default=0.01, help="seconds between datagrams")
    ap.add_argument("--mode", choices=MODES, default="syslog")
    ap.add_argument("--seed", type=int, default=99)
    ap.add_argument("--no-pri", action="store_true", help="send without the <PRI> prefix")
    args = ap.parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    total = args.baseline + args.count
    print(f"Sending {total} lines ({args.baseline} quiet baseline + {args.count} live) "
          f"to udp://{args.host}:{args.port} ...")
    sent = anomalies = 0
    for line, label in calibrated_stream(baseline_n=args.baseline, n=args.count,
                                         anomaly_rate=args.anomaly_rate, seed=args.seed,
                                         mode=args.mode):
        payload = line if args.no_pri else f"<{AUTH_INFO_PRI}>{line}"
        sock.sendto(payload.encode("utf-8"), (args.host, args.port))
        sent += 1
        anomalies += label["anomalous"]
        if sent % 250 == 0:
            print(f"  sent {sent:>6} lines ({anomalies} injected anomalies so far)")
        if args.delay:
            time.sleep(args.delay)
    sock.close()
    print(f"Done: {sent} lines sent, {anomalies} of them injected anomalies.")


if __name__ == "__main__":
    main()
