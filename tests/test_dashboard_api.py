import json
import time

import pytest
from fastapi.testclient import TestClient

from dashboard.server import EngineConfig, create_app, parse_args


def _wait_for(client, cond, timeout=15):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        snap = client.get("/api/stats").json()
        if cond(snap):
            return snap
        time.sleep(0.1)
    raise AssertionError(f"condition not met; last stats: {snap}")


@pytest.fixture
def client():
    cfg = EngineConfig(source="synthetic", rate=400, baseline_size=60, seed=1, anomaly_rate=0.1)
    with TestClient(create_app(cfg, heartbeat_seconds=0.5)) as c:
        yield c


def _parse_sse(text):
    messages = []
    for block in text.strip().split("\n\n"):
        fields = {}
        for line in block.splitlines():
            if line.startswith(":"):
                fields.setdefault("comment", line)
                continue
            key, _, value = line.partition(": ")
            fields[key] = value
        messages.append(fields)
    return messages


def test_index_served_with_csp(client):
    r = client.get("/")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert "Log Forensics Engine" in r.text
    assert "cdnjs.cloudflare.com" in r.headers["content-security-policy"]
    assert "chart.umd.min.js" in r.text


def test_head_requests_for_uptime_checks(client):
    assert client.head("/").status_code == 200
    assert client.head("/healthz").status_code == 200


def test_stats_snapshot_keys_and_calibration(client):
    snap = _wait_for(client, lambda s: s["phase"] == "live" and s["total_lines"] > 100)
    for key in ("lines_per_sec", "total_lines", "anomalies", "unparseable", "severity_counts",
                "top_failed_ips", "threshold", "baseline", "source_type", "uptime_seconds",
                "dropped_udp", "timeline", "status"):
        assert key in snap
    assert snap["source_type"] == "synthetic" and snap["status"] == "running"
    assert snap["baseline"] == {"have": 60, "need": 60}
    assert snap["threshold"] > 0
    assert set(snap["severity_counts"]) == {"CRITICAL", "ERROR", "WARNING", "INFO"}
    assert snap["evaluation"]["labeled_events"] > 0


def test_anomalies_endpoint_is_bounded_and_newest_first(client):
    _wait_for(client, lambda s: s["anomalies"] > 10)
    data = client.get("/api/anomalies?limit=5").json()
    items = data["anomalies"]
    assert 0 < len(items) <= 5
    assert all(e["is_anomaly"] for e in items)
    assert [e["seq"] for e in items] == sorted((e["seq"] for e in items), reverse=True)
    assert client.get("/api/anomalies?limit=0").status_code == 422
    assert client.get("/api/anomalies?limit=100000").status_code == 422


def test_recent_events_endpoint(client):
    _wait_for(client, lambda s: s["total_lines"] > 50)
    events = client.get("/api/events?limit=20").json()["events"]
    assert len(events) == 20 and events[0]["seq"] > events[-1]["seq"]


def test_sse_stream_sends_hello_then_json_events(client):
    _wait_for(client, lambda s: s["total_lines"] > 0)
    r = client.get("/events?max_events=5")
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("text/event-stream")
    msgs = _parse_sse(r.text)
    assert msgs[0].get("retry") == "3000"
    assert msgs[1]["event"] == "hello"
    data_msgs = [m for m in msgs if "id" in m]
    assert len(data_msgs) == 5
    seqs = []
    for m in data_msgs:
        event = json.loads(m["data"])
        assert {"ts", "raw", "parsed", "severity_pred", "severity_seed", "distance", "is_anomaly",
                "reason", "ip", "host", "process"} <= set(event)
        assert m["id"] == f"{event['gen']}-{event['seq']}"
        seqs.append(event["seq"])
    assert seqs == sorted(seqs)


def test_sse_resumes_after_last_event_id(client):
    _wait_for(client, lambda s: s["total_lines"] > 100)
    latest = client.get("/api/events?limit=1").json()
    gen, seq = latest["generation"], latest["events"][0]["seq"]
    r = client.get("/events?max_events=3", headers={"Last-Event-ID": f"{gen}-{seq - 20}"})
    data = [json.loads(m["data"]) for m in _parse_sse(r.text) if "id" in m]
    assert [e["seq"] for e in data] == [seq - 19, seq - 18, seq - 17]


def test_sse_slow_client_gets_dropped_notice(client):
    _wait_for(client, lambda s: s["total_lines"] > 600)
    gen = client.get("/api/stats").json()["generation"]
    r = client.get("/events?max_events=1", headers={"Last-Event-ID": f"{gen}-1"})
    msgs = _parse_sse(r.text)
    dropped = [m for m in msgs if m.get("event") == "dropped"]
    assert dropped and json.loads(dropped[0]["data"])["dropped"] > 0


def test_config_get_and_post_restarts_engine(client):
    cfg = client.get("/api/config").json()
    assert cfg["config"]["source"] == "synthetic"
    assert set(cfg["allowed_sources"]) == {"synthetic", "udp", "ssh", "tail"}
    gen = cfg["generation"]
    time.sleep(2.1)  # restart throttle
    r = client.post("/api/config", json={"threshold_percentile": 97.0, "anomaly_rate": 0.2})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["generation"] == gen + 1
    assert body["config"]["threshold_percentile"] == 97.0
    snap = _wait_for(client, lambda s: s["generation"] == gen + 1 and s["total_lines"] > 0)
    assert snap["config"]["anomaly_rate"] == 0.2


def test_config_validation_errors(client):
    assert client.post("/api/config", json={"threshold_percentile": 120}).status_code == 422
    assert client.post("/api/config", json={"source": "carrier-pigeon"}).status_code == 422
    assert client.post("/api/config", json={"nope": 1}).status_code == 422


def test_config_change_throttled(client):
    time.sleep(2.1)
    assert client.post("/api/config", json={"anomaly_rate": 0.05}).status_code == 200
    assert client.post("/api/config", json={"anomaly_rate": 0.06}).status_code == 429


def test_public_demo_only_allows_synthetic():
    with TestClient(create_app(EngineConfig(rate=200, baseline_size=30), public_demo=True)) as c:
        cfg = c.get("/api/config").json()
        assert cfg["allowed_sources"] == ["synthetic"] and cfg["public_demo"] is True
        time.sleep(2.1)
        r = c.post("/api/config", json={"source": "tail", "tail_path": "/etc/passwd"})
        assert r.status_code == 403
        assert c.post("/api/config", json={"rate": 400}).status_code == 403


def test_bad_source_surfaces_error_instead_of_crashing(tmp_path):
    cfg = EngineConfig(source="ssh", ssh_host=None)
    with TestClient(create_app(cfg)) as c:
        snap = _wait_for(c, lambda s: s["status"] == "error")
        assert "ssh_host" in snap["error"]
        assert c.get("/healthz").json()["ok"] is True


def test_cli_defaults_bind_localhost():
    args = parse_args(["--source", "udp", "--port", "5140"])
    assert args.http_host == "127.0.0.1" and args.http_port == 8000
    assert args.source == "udp" and args.port == 5140 and args.udp_host == "127.0.0.1"
