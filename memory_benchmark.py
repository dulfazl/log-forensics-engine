"""
memory_benchmark.py

Runs the FULL engine (parse, featurize, anomaly scoring, severity
prediction, periodic severity retraining and baseline refresh, Stats)
over a growing synthetic stream and records memory at each checkpoint:

  * tracemalloc "current": bytes held by live Python/numpy allocations
    right now. This is the number that must stay flat for a streaming
    system; it ignores interpreter and library code.
  * tracemalloc "peak": the high-water mark since the start, which
    includes transient spikes such as a model refit.
  * RSS (psutil): what the OS sees for the whole process, including the
    interpreter, numpy/scikit-learn shared libraries and memory the
    allocator keeps around after objects are freed. It rises during
    warm-up and then should plateau.

    python memory_benchmark.py                 # 1K .. 1M lines (a few minutes)
    python memory_benchmark.py --max 100000    # quick run

Results are also written to docs/benchmark_results.json for the chart.
"""

import argparse
import gc
import json
import os
import time
import tracemalloc

import psutil

from engine import Stats, StreamingEngine
from synthetic_logs import DEFAULT_START, calibrated_stream

DEFAULT_CHECKPOINTS = (1_000, 10_000, 100_000, 500_000, 1_000_000)
RESULTS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                            "docs", "benchmark_results.json")


def run_benchmark(checkpoints=DEFAULT_CHECKPOINTS, batch_size=256, anomaly_rate=0.02,
                  seed=1, mode="mixed", verbose=True):
    checkpoints = sorted(checkpoints)
    proc = psutil.Process()
    gc.collect()
    rss_before = proc.memory_info().rss

    source = calibrated_stream(baseline_n=300, n=checkpoints[-1], anomaly_rate=anomaly_rate,
                               seed=seed, mode=mode)
    stats = Stats()
    engine = StreamingEngine(source, baseline_size=300, batch_size=batch_size,
                             current_year=DEFAULT_START.year, explain=False,
                             stats=stats, source_type="synthetic")

    results = []
    tracemalloc.start()
    started = time.perf_counter()
    processed = anomalies = 0
    idx = 0
    # Checkpoints count live lines; the 300 baseline lines come first.
    for event in engine.run():
        if event["phase"] != "live":
            continue
        processed += 1
        anomalies += event["is_anomaly"]
        if processed == checkpoints[idx]:
            gc.collect()
            current, peak = tracemalloc.get_traced_memory()
            rss = proc.memory_info().rss
            elapsed = time.perf_counter() - started
            row = {"lines": processed, "tracemalloc_current_kb": current / 1024,
                   "tracemalloc_peak_kb": peak / 1024, "rss_mb": rss / 2**20,
                   "elapsed_s": elapsed, "anomalies": anomalies,
                   "severity_retrains": engine.classifier.retrain_count,
                   "baseline_refreshes": engine.detector.refresh_count,
                   "tracked_ips": len(engine.state["ip_recent"])}
            results.append(row)
            if verbose:
                print(f"{processed:>10,} lines | tracemalloc current {row['tracemalloc_current_kb']:>8.1f} KB"
                      f"  peak {row['tracemalloc_peak_kb']:>8.1f} KB | RSS {row['rss_mb']:>7.1f} MB"
                      f" | {elapsed:>7.1f}s ({processed / elapsed:,.0f} lines/s)"
                      f" | retrains {row['severity_retrains']:>6} refreshes {row['baseline_refreshes']:>4}")
            idx += 1
            if idx == len(checkpoints):
                break
    tracemalloc.stop()
    return {"rss_before_mb": rss_before / 2**20, "batch_size": batch_size, "mode": mode,
            "checkpoints": results}


def verdict(report):
    rows = report["checkpoints"]
    if len(rows) < 2:
        return "Not enough checkpoints for a verdict."
    # Compare against the second checkpoint: the first still includes
    # one-off warm-up (models fitted, windows filling up).
    ref, last = rows[1] if len(rows) > 2 else rows[0], rows[-1]
    growth_lines = last["lines"] / ref["lines"]
    cur_ratio = last["tracemalloc_current_kb"] / ref["tracemalloc_current_kb"]
    rss_delta = last["rss_mb"] - ref["rss_mb"]
    lines = [
        f"Lines grew {growth_lines:,.0f}x ({ref['lines']:,} -> {last['lines']:,}).",
        f"tracemalloc current: {ref['tracemalloc_current_kb']:.0f} KB -> "
        f"{last['tracemalloc_current_kb']:.0f} KB ({cur_ratio:.2f}x).",
        f"tracemalloc peak (includes refit spikes): {last['tracemalloc_peak_kb']:.0f} KB.",
        f"RSS: {ref['rss_mb']:.1f} MB -> {last['rss_mb']:.1f} MB ({rss_delta:+.1f} MB), "
        f"of which ~{report['rss_before_mb']:.0f} MB is the interpreter and libraries.",
    ]
    if cur_ratio < 1.5 and rss_delta < 25:
        lines.append("PASS: memory held by the engine is flat while the input grew by orders of "
                     "magnitude. Nothing accumulates per line; all state is bounded.")
    else:
        lines.append("WARNING: memory grew with the input. Look for an unbounded list, dict or "
                     "cache somewhere in the pipeline.")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser(description="Memory benchmark of the full streaming engine.")
    ap.add_argument("--max", type=int, default=DEFAULT_CHECKPOINTS[-1],
                    help="largest checkpoint (checkpoints above it are skipped)")
    ap.add_argument("--batch-size", type=int, default=256)
    ap.add_argument("--no-save", action="store_true")
    args = ap.parse_args()

    checkpoints = [c for c in DEFAULT_CHECKPOINTS if c <= args.max] or [args.max]
    print(f"Memory benchmark: full engine incl. retraining, up to {checkpoints[-1]:,} lines "
          f"(batch_size={args.batch_size}; tracemalloc slows Python down 2-3x)\n")
    report = run_benchmark(checkpoints, batch_size=args.batch_size)
    print("\n=== Verdict ===")
    print(verdict(report))
    if not args.no_save:
        os.makedirs(os.path.dirname(RESULTS_PATH), exist_ok=True)
        with open(RESULTS_PATH, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        print(f"\nSaved {os.path.relpath(RESULTS_PATH)}")


if __name__ == "__main__":
    main()
