import json

from fastapi.testclient import TestClient

from dashboard.serverless import create_serverless_app


def _messages(text):
    out = []
    for block in text.strip().split("\n\n"):
        fields = {}
        for line in block.splitlines():
            key, _, value = line.partition(": ")
            fields[key] = value
        out.append(fields)
    return out


def test_session_streams_events_stats_and_bye():
    client = TestClient(create_serverless_app(stream_seconds=4))
    r = client.get("/events?rate=50&baseline_size=40")
    msgs = _messages(r.text)
    assert msgs[1]["event"] == "hello"
    events = [json.loads(m["data"]) for m in msgs if "id" in m]
    stats = [json.loads(m["data"]) for m in msgs if m.get("event") == "stats"]
    assert msgs[-1]["event"] == "bye"
    assert any(e["phase"] == "live" for e in events)
    gen = json.loads(msgs[1]["data"])["generation"]
    assert all(e["gen"] == gen for e in events)
    assert stats and stats[-1]["generation"] == gen and stats[-1]["phase"] == "live"
    assert stats[-1]["config"]["baseline_size"] == 40


def test_config_is_per_visitor_and_synthetic_only():
    client = TestClient(create_serverless_app(stream_seconds=1))
    cfg = client.get("/api/config").json()
    assert cfg["stateless"] is True and cfg["allowed_sources"] == ["synthetic"]
    ok = client.post("/api/config", json={"threshold_percentile": 99.0, "anomaly_rate": 0.1})
    assert ok.status_code == 200 and ok.json()["config"]["threshold_percentile"] == 99.0
    assert client.post("/api/config", json={"source": "tail"}).status_code == 403
    assert client.post("/api/config", json={"rate": 400}).status_code == 403
    assert client.get("/events?rate=100").status_code == 403
    assert client.get("/events?nope=1").status_code == 422


def test_index_and_health():
    client = TestClient(create_serverless_app(stream_seconds=1))
    assert "Log Forensics Engine" in client.get("/").text
    assert client.head("/healthz").status_code == 200
