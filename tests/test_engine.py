import threading

import pytest

from engine import EVENT_KEYS, Stats, StreamingEngine
from evaluate import evaluate_events, run_config
from synthetic_logs import calibrated_stream


def _engine(n=600, baseline=200, **kwargs):
    src = calibrated_stream(baseline_n=baseline, n=n, anomaly_rate=0.05, seed=11, mode="mixed")
    return StreamingEngine(src, baseline_size=baseline, current_year=2026, **kwargs)


def test_one_event_per_line_with_required_keys():
    events = list(_engine().run())
    assert len(events) == 800
    for e in events:
        assert set(EVENT_KEYS) <= set(e)
    assert [e["seq"] for e in events] == list(range(1, 801))


def test_calibration_then_live():
    events = list(_engine().run())
    phases = [e["phase"] for e in events]
    assert phases[:200] == ["calibrating"] * 200
    assert set(phases[200:]) == {"live"}
    live = [e for e in events if e["phase"] == "live" and e["parsed"]]
    assert all(e["distance"] is not None and e["threshold"] for e in live)
    assert all(e["severity_pred"] in {"CRITICAL", "ERROR", "WARNING", "INFO"} for e in live)


def test_unparseable_lines_are_flagged():
    src = ["garbage line one"] + [
        f"Aug 28 10:{i // 60:02d}:{i % 60:02d} h sshd[{i}]: Accepted password for u from 10.0.0.{i % 5} port 22 ssh2"
        for i in range(60)
    ] + ["###"]
    events = list(StreamingEngine(src, baseline_size=30, current_year=2026).run())
    assert events[0]["parsed"] is False and events[0]["is_anomaly"] is True
    assert events[0]["reason"] == "unparseable"
    assert events[-1]["reason"] == "unparseable"


def test_batch_size_keeps_order_and_results_close():
    single = list(_engine(batch_size=1, explain=False).run())
    batched = list(_engine(batch_size=64, explain=False).run())
    assert [e["raw"] for e in single] == [e["raw"] for e in batched]
    agree = sum(a["is_anomaly"] == b["is_anomaly"] for a, b in zip(single, batched))
    assert agree / len(single) > 0.97


def test_labels_pass_through_and_stats_update():
    stats = Stats()
    events = list(_engine(stats=stats).run())
    assert all(e["label"] is not None for e in events)
    snap = stats.snapshot()
    assert snap["total_lines"] == 800 and snap["phase"] == "live"
    assert snap["anomalies"] == sum(e["is_anomaly"] for e in events)
    assert snap["unparseable"] == sum(not e["parsed"] for e in events)
    assert snap["evaluation"]["labeled_events"] == 600
    assert snap["threshold"] is not None
    assert sum(snap["severity_counts"].values()) == snap["parsed"]
    assert len(snap["top_failed_ips"]) <= 10


def test_stats_failed_ip_window_is_bounded():
    stats = Stats(failed_window=50)
    base = {k: None for k in EVENT_KEYS}
    for i in range(1000):
        stats.record({**base, "seq": i, "parsed": True, "phase": "live", "is_anomaly": False,
                      "auth_failed": True, "ip": f"10.0.{i // 256}.{i % 256}", "format": "syslog"})
    assert sum(stats._failed_counter.values()) == 50
    assert len(stats._failed_counter) <= 50


def test_stop_event_stops_run():
    stop = threading.Event()

    def endless():
        i = 0
        while True:
            i += 1
            yield f"Aug 28 10:00:00 h app[{i}]: started job {i}"

    engine = StreamingEngine(endless(), baseline_size=20, current_year=2026, stop_event=stop)
    count = 0
    for _ in engine.run():
        count += 1
        if count == 50:
            stop.set()
    assert 50 <= count <= 51


def test_evaluate_reports_per_type_and_parsed_only():
    result = evaluate_events(_engine(n=1500, baseline=300).run())
    assert result["lines"] == 1500
    assert set(result["per_type"]) <= {"bruteforce", "portscan", "malformed", "odd_hour", "slow_bruteforce"}
    assert result["per_type"]["malformed"]["recall"] == 1.0
    assert result["per_type"]["malformed"]["parsed_support"] == 0
    # counting malformed lines as caught can only help recall
    assert result["with_unparseable"]["recall"] >= result["parsed_only"]["recall"]
    assert 0.0 <= result["normal"]["fpr"] < 0.1
    assert result["severity"]["accuracy"] > 0.9


def test_legacy_config_reproduces_readme_numbers():
    result, _ = run_config("legacy", n=1500, baseline=300, seed=42)
    r = result["with_unparseable"]
    # README of the original project: precision 0.96, recall 0.68, F1 0.79
    assert r["precision"] == pytest.approx(0.96, abs=0.03)
    assert r["recall"] == pytest.approx(0.68, abs=0.03)
    assert r["f1"] == pytest.approx(0.79, abs=0.03)


def test_current_config_beats_legacy_recall():
    legacy, _ = run_config("legacy", n=1500, seed=42)
    current, _ = run_config("current", n=1500, seed=42)
    assert current["with_unparseable"]["recall"] > legacy["with_unparseable"]["recall"]
