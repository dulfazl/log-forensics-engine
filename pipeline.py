"""
pipeline.py

Thin command-line front end over engine.StreamingEngine.

    python pipeline.py --n 1500 --baseline 300 --anomaly-rate 0.05       # synthetic + metrics
    python pipeline.py --legacy --quiet                                  # original configuration
    python pipeline.py --file /var/log/auth.log --baseline 500           # a real file
    python pipeline.py --tail /var/log/auth.log                          # follow a live file

With synthetic input the baseline is a quiet stretch followed by live
traffic on one continuous simulated clock, and the run ends with the
evaluation table from evaluate.py. Real files have no ground truth, so
only the anomalies are printed.
"""

import argparse

from engine import StreamingEngine
from evaluate import CONFIGS, Evaluator, print_report
from log_source import stream_from_file, tail_file
from synthetic_logs import DEFAULT_START, MODES, calibrated_stream


def format_event(event):
    sev = event["severity"] or "-"
    if not event["parsed"]:
        return f"[UNPARSEABLE] {event['raw'][:100]!r}"
    truth = ""
    if event.get("label"):
        truth = f" truth={event['label']['type']}"
    return (f"[ANOMALY] dist={event['distance']:.2f} severity={sev:<8}{truth} "
            f":: {event['message'][:80]}  ({event['reason']})")


def main():
    ap = argparse.ArgumentParser(description="Run the Log Forensics Engine.")
    src = ap.add_mutually_exclusive_group()
    src.add_argument("--file", help="analyse a log file")
    src.add_argument("--tail", help="follow a log file like tail -F")
    ap.add_argument("--n", type=int, default=2000, help="synthetic live lines")
    ap.add_argument("--baseline", type=int, default=300, help="baseline (calibration) size")
    ap.add_argument("--anomaly-rate", type=float, default=0.05)
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--mode", choices=MODES, default="syslog", help="synthetic traffic mode")
    ap.add_argument("--threshold", type=float, default=99.5, help="threshold percentile")
    ap.add_argument("--legacy", action="store_true",
                    help="original configuration (4 anomaly types, 5 features, no refresh)")
    ap.add_argument("--batch-size", type=int, default=1)
    ap.add_argument("--quiet", action="store_true", help="suppress per-anomaly output")
    args = ap.parse_args()

    current_year = None
    if args.file:
        source, source_type = stream_from_file(args.file), "file"
        cfg = CONFIGS["current"]
    elif args.tail:
        source, source_type = tail_file(args.tail), "tail"
        cfg = CONFIGS["current"]
    else:
        cfg = CONFIGS["legacy" if args.legacy else ("current-mixed" if args.mode == "mixed" else "current")]
        mode = "syslog" if args.legacy else args.mode
        source = calibrated_stream(baseline_n=args.baseline, n=args.n, anomaly_rate=args.anomaly_rate,
                                   seed=args.seed, anomaly_types=cfg["anomaly_types"], mode=mode,
                                   rich=cfg["rich"])
        source_type, current_year = "synthetic", DEFAULT_START.year

    engine = StreamingEngine(source, baseline_size=args.baseline,
                             threshold_percentile=args.threshold,
                             feature_set=cfg["feature_set"], refresh_every=cfg["refresh_every"],
                             current_year=current_year, batch_size=args.batch_size,
                             source_type=source_type)
    evaluator = Evaluator()
    announced = False
    total = unparseable = anomalies = 0
    try:
        for event in engine.run():
            total += 1
            unparseable += not event["parsed"]
            evaluator.add(event)
            if event["phase"] == "live" and not announced:
                announced = True
                print(f"--- Baseline of {args.baseline} records fitted "
                      f"(threshold {engine.detector.threshold:.3f}). Live scoring begins. ---\n")
            if event["is_anomaly"]:
                anomalies += 1
                if not args.quiet:
                    print(format_event(event))
    except KeyboardInterrupt:
        print("\nstopped")

    print(f"\nTotal lines processed: {total:,}  (anomalies flagged: {anomalies:,}, "
          f"unparseable: {unparseable:,})")
    result = evaluator.result()
    if result["lines"]:
        name = "legacy" if args.legacy else "current"
        print_report({name: result}, args.n, [args.seed])


if __name__ == "__main__":
    main()
