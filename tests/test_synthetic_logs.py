import hashlib
from collections import Counter
from datetime import datetime

from log_parser import YearTracker, parse_log_line
from synthetic_logs import ANOMALY_TYPES, LABEL_TYPES, LEGACY_ANOMALY_TYPES, calibrated_stream, generate_labeled_lines


def _digest(**kwargs):
    h = hashlib.sha256()
    for line, label in generate_labeled_lines(**kwargs):
        h.update(line.encode() + b"\x1e" + label["type"].encode() + b"\n")
    return h.hexdigest()


def test_same_seed_is_byte_identical():
    for mode in ("syslog", "access", "mixed"):
        assert _digest(n=3000, seed=7, mode=mode) == _digest(n=3000, seed=7, mode=mode)
    assert _digest(n=3000, seed=7) != _digest(n=3000, seed=8)


def test_label_shape_and_types():
    counts = Counter()
    for _line, label in generate_labeled_lines(n=20_000, anomaly_rate=0.08, seed=1, mode="mixed"):
        assert set(label) == {"anomalous", "type"}
        assert label["type"] in LABEL_TYPES
        assert label["anomalous"] == (label["type"] != "normal")
        counts[label["type"]] += 1
    for kind in ("normal",) + ANOMALY_TYPES:
        assert counts[kind] > 0, kind
    print(dict(counts))


def test_legacy_types_only_when_asked():
    kinds = {lab["type"] for _, lab in generate_labeled_lines(
        n=5000, anomaly_rate=0.1, seed=2, anomaly_types=LEGACY_ANOMALY_TYPES)}
    assert "slow_bruteforce" not in kinds


def test_timestamps_monotonic_and_formats_parse():
    yt = YearTracker(2026)
    last = None
    formats = Counter()
    for line, label in generate_labeled_lines(n=5000, anomaly_rate=0.05, seed=4, mode="mixed"):
        r = yt.parse(line)
        if label["type"] == "malformed":
            assert r is None
            continue
        assert r is not None, line
        formats[r["format"]] += 1
        if last is not None:
            assert r["timestamp"] >= last
        last = r["timestamp"]
    assert formats["syslog"] > 1000 and formats["access_log"] > 1000


def test_slow_bruteforce_is_slow():
    times = {}
    for line, label in generate_labeled_lines(n=30_000, anomaly_rate=0.05, seed=5,
                                              anomaly_types=("slow_bruteforce",)):
        if label["type"] == "slow_bruteforce":
            r = parse_log_line(line, current_year=2026)
            times.setdefault(r["ip"], []).append(r["timestamp"])
    gaps = [(b - a).total_seconds() for ts in times.values() for a, b in zip(ts, ts[1:])]
    # Consecutive attempts within a run are 20-60 s apart; the few outside
    # that range are the boundary between two runs from the same IP.
    in_range = sum(20 <= g <= 60 for g in gaps)
    assert len(gaps) > 100 and in_range / len(gaps) > 0.85


def test_calibrated_stream_continues_the_clock():
    lines = list(calibrated_stream(baseline_n=200, n=200, anomaly_rate=0.0, seed=9))
    stamps = [parse_log_line(line, current_year=2026)["timestamp"] for line, _ in lines]
    assert stamps[200] >= stamps[199]       # no jump back at the baseline -> live switch
    assert stamps[0] >= datetime(2026, 8, 28)
    assert all(not lab["anomalous"] for _, lab in lines[:200])
