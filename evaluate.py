"""
evaluate.py

Measures the engine against synthetic ground truth and prints:
  * precision / recall / F1 overall, both WITH unparseable lines counted
    (a malformed line is auto-flagged, which flatters both numbers) and
    WITHOUT them (parsed lines only: what the KNN detector really does);
  * recall per anomaly type, which shows where recall is lost;
  * false-positive rate on normal traffic;
  * severity accuracy (KNN prediction vs. the keyword seed label).

Configurations
  legacy          the original README setup: syslog only, the four original
                  anomaly types, 5 behavioural features for both models,
                  no baseline refresh. Should land close to 0.96 / 0.68 / 0.79.
  current         syslog, all five anomaly types (adds slow_bruteforce),
                  keyword features for severity, baseline refresh on.
  current-mixed   as current, with syslog and access-log traffic mixed.

    python evaluate.py                         # all configs, README sizes
    python evaluate.py --n 20000 --seeds 5     # larger, pooled over 5 seeds
"""

import argparse
from collections import deque

from engine import StreamingEngine
from models import SEVERITY_LABELS
from synthetic_logs import ANOMALY_TYPES, DEFAULT_START, LEGACY_ANOMALY_TYPES, calibrated_stream

CONFIGS = {
    "legacy": dict(anomaly_types=LEGACY_ANOMALY_TYPES, mode="syslog", rich=False,
                   feature_set="legacy", refresh_every=0),
    "current": dict(anomaly_types=ANOMALY_TYPES, mode="syslog", rich=True,
                    feature_set="full", refresh_every=1000),
    "current-mixed": dict(anomaly_types=ANOMALY_TYPES, mode="mixed", rich=True,
                          feature_set="full", refresh_every=1000),
}


def prf(tp, fp, fn):
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return {"precision": precision, "recall": recall, "f1": f1, "tp": tp, "fp": fp, "fn": fn}


class Evaluator:
    """
    Streaming accumulator: add() one event at a time, result() at the end.
    Only live-phase events with a ground-truth label are scored. Memory is
    a fixed set of counters plus capped distance samples for charts.
    """

    def __init__(self, keep_distances=50_000):
        self.counts = {"all": [0, 0, 0, 0], "parsed": [0, 0, 0, 0]}  # tp fp fn tn
        self.per_type = {}  # type -> [support, detected, parsed_support, parsed_detected]
        self.sev_labels = list(SEVERITY_LABELS)
        self.sev_cm = {(t, p): 0 for t in self.sev_labels for p in self.sev_labels}
        self.sev_total = 0
        self.sev_correct = 0
        self.lines = 0
        self.normal_distances = deque(maxlen=keep_distances)
        self.anomaly_distances = deque(maxlen=keep_distances)
        self.threshold = None

    def add(self, event):
        if event["phase"] != "live" or not event.get("label"):
            return
        self.lines += 1
        truth = bool(event["label"]["anomalous"])
        pred = bool(event["is_anomaly"])
        idx = (0 if pred else 2) if truth else (1 if pred else 3)
        self.counts["all"][idx] += 1
        if event["parsed"]:
            self.counts["parsed"][idx] += 1

        kind = event["label"]["type"]
        slot = self.per_type.setdefault(kind, [0, 0, 0, 0])
        slot[0] += 1
        slot[1] += pred
        if event["parsed"]:
            slot[2] += 1
            slot[3] += pred

        if event["distance"] is not None:
            (self.anomaly_distances if truth else self.normal_distances).append(event["distance"])
            self.threshold = event["threshold"]

        seed, guess = event["severity_seed"], event["severity_pred"]
        if seed is not None and guess is not None:
            self.sev_total += 1
            self.sev_correct += seed == guess
            if (seed, guess) in self.sev_cm:
                self.sev_cm[(seed, guess)] += 1

    def result(self):
        tp, fp, fn, tn = self.counts["all"]
        ptp, pfp, pfn, ptn = self.counts["parsed"]
        normal = self.per_type.get("normal", [0, 0, 0, 0])
        per_type = {}
        for kind in ANOMALY_TYPES:
            if kind in self.per_type:
                s, d, ps, pd = self.per_type[kind]
                per_type[kind] = {"support": s, "detected": d, "recall": d / s if s else 0.0,
                                  "parsed_support": ps,
                                  "parsed_recall": pd / ps if ps else None}
        return {
            "lines": self.lines,
            "with_unparseable": {**prf(tp, fp, fn), "tn": tn},
            "parsed_only": {**prf(ptp, pfp, pfn), "tn": ptn},
            "per_type": per_type,
            "normal": {"support": normal[0], "false_positives": normal[1],
                       "fpr": normal[1] / normal[0] if normal[0] else 0.0},
            "severity": {
                "accuracy": self.sev_correct / self.sev_total if self.sev_total else None,
                "n": self.sev_total,
                "labels": self.sev_labels,
                "confusion_matrix": [[self.sev_cm[(t, p)] for p in self.sev_labels]
                                     for t in self.sev_labels],
            },
            "threshold": self.threshold,
        }


def evaluate_events(events):
    """Convenience: evaluate any iterable of engine events."""
    ev = Evaluator()
    for event in events:
        ev.add(event)
    return ev.result()


def run_config(name="current", n=1500, baseline=300, anomaly_rate=0.05, seed=42,
               threshold_percentile=99.5, batch_size=1, keep=None):
    """Run one configuration end to end; returns (result, evaluator)."""
    cfg = CONFIGS[name]
    source = calibrated_stream(baseline_n=baseline, n=n, anomaly_rate=anomaly_rate, seed=seed,
                               anomaly_types=cfg["anomaly_types"], mode=cfg["mode"],
                               rich=cfg["rich"])
    engine = StreamingEngine(source, baseline_size=baseline,
                             threshold_percentile=threshold_percentile,
                             feature_set=cfg["feature_set"], refresh_every=cfg["refresh_every"],
                             current_year=DEFAULT_START.year, batch_size=batch_size,
                             explain=False, source_type="synthetic")
    ev = Evaluator()
    for event in engine.run():
        ev.add(event)
        if keep is not None:
            keep.append(event)
    return ev.result(), ev


def run_pooled(name, seeds, **kwargs):
    """Run several seeds and pool the raw counts (not an average of ratios)."""
    pooled = Evaluator()
    for s in seeds:
        _, ev = run_config(name, seed=s, **kwargs)
        for key in pooled.counts:
            pooled.counts[key] = [a + b for a, b in zip(pooled.counts[key], ev.counts[key])]
        for kind, slot in ev.per_type.items():
            acc = pooled.per_type.setdefault(kind, [0, 0, 0, 0])
            pooled.per_type[kind] = [a + b for a, b in zip(acc, slot)]
        for cell in pooled.sev_cm:
            pooled.sev_cm[cell] += ev.sev_cm[cell]
        pooled.sev_total += ev.sev_total
        pooled.sev_correct += ev.sev_correct
        pooled.lines += ev.lines
        pooled.normal_distances.extend(ev.normal_distances)
        pooled.anomaly_distances.extend(ev.anomaly_distances)
        pooled.threshold = ev.threshold
    return pooled.result(), pooled


def _fmt(x):
    return "  n/a" if x is None else f"{x:5.3f}"


def print_report(results, n, seeds):
    print(f"\n=== Overall anomaly detection  (n={n:,} live lines per run, seeds={seeds}) ===")
    print(f"{'config':<15}{'lines':>8} | {'P':>6}{'R':>7}{'F1':>7}  (all lines)"
          f" | {'P':>6}{'R':>7}{'F1':>7}  (parsed only) | {'FPR':>6} | {'sev acc':>7}")
    for name, r in results.items():
        a, p = r["with_unparseable"], r["parsed_only"]
        print(f"{name:<15}{r['lines']:>8} | {a['precision']:6.3f}{a['recall']:7.3f}{a['f1']:7.3f}"
              f"              | {p['precision']:6.3f}{p['recall']:7.3f}{p['f1']:7.3f}"
              f"                | {r['normal']['fpr']:6.3f} | {_fmt(r['severity']['accuracy']):>7}")

    for name, r in results.items():
        print(f"\n--- Recall per anomaly type: {name} ---")
        print(f"{'type':<17}{'support':>8}{'detected':>10}{'recall':>8}")
        for kind, row in r["per_type"].items():
            print(f"{kind:<17}{row['support']:>8}{row['detected']:>10}{row['recall']:>8.2f}")
        nm = r["normal"]
        print(f"{'normal (FP)':<17}{nm['support']:>8}{nm['false_positives']:>10}"
              f"{'FPR ' + format(nm['fpr'], '.3f'):>14}")


def main():
    ap = argparse.ArgumentParser(description="Per-anomaly-type evaluation of the engine.")
    ap.add_argument("--config", choices=list(CONFIGS) + ["all"], default="all")
    ap.add_argument("--n", type=int, default=1500, help="live lines per run")
    ap.add_argument("--baseline", type=int, default=300)
    ap.add_argument("--anomaly-rate", type=float, default=0.05)
    ap.add_argument("--threshold", type=float, default=99.5, help="threshold percentile")
    ap.add_argument("--seed", type=int, default=42)
    ap.add_argument("--seeds", type=int, default=1, help="pool results over this many seeds")
    ap.add_argument("--batch-size", type=int, default=1)
    args = ap.parse_args()

    names = list(CONFIGS) if args.config == "all" else [args.config]
    seeds = list(range(args.seed, args.seed + args.seeds * 100, 100))
    results = {}
    for name in names:
        results[name], _ = run_pooled(name, seeds, n=args.n, baseline=args.baseline,
                                      anomaly_rate=args.anomaly_rate,
                                      threshold_percentile=args.threshold,
                                      batch_size=args.batch_size)
    print_report(results, args.n, seeds)


if __name__ == "__main__":
    main()
