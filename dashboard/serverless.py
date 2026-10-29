"""
dashboard/serverless.py

Serverless variant of the dashboard, for hosts such as Vercel where code
only runs while a request is open and nothing survives between requests:
no background engine thread, no shared ring buffer, no shared Stats.

Each Server-Sent Events connection runs its own StreamingEngine on
synthetic traffic. The baseline is calibrated quickly (paced at 100
lines/s), live lines are paced at `rate` per second, and a Stats snapshot
is pushed every second as `event: stats` (there is no shared state for
/api/stats to read). A session ends after STREAM_SECONDS, just under the
host's time limit, with `event: bye`; the browser reconnects and a fresh
session calibrates again. Settings are per visitor, passed as query
parameters, and limited to the synthetic source like --public-demo.

Trade-off against dashboard/server.py: every visitor has an independent
engine and statistics restart with each session. The always-on server is
still the one to use locally and for UDP, tail and SSH sources.
"""

import json
import os
import secrets
import time

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import ValidationError

from dashboard.server import STATIC_DIR, EngineConfig, _sse
from engine import Stats, StreamingEngine
from featurizer import BASE_FEATURES, FEATURE_NAMES
from synthetic_logs import DEFAULT_START, calibrated_stream

STREAM_SECONDS = float(os.environ.get("LFE_STREAM_SECONDS", "270"))
CALIBRATION_RATE = 100.0
MAX_PUBLIC_RATE = 50.0
TUNABLE = ("threshold_percentile", "anomaly_rate", "baseline_size", "rate", "mode")


def _config_from(params):
    unknown = set(params) - set(TUNABLE) - {"source"}
    if unknown:
        raise HTTPException(422, f"unknown config keys: {sorted(unknown)}")
    if params.get("source", "synthetic") != "synthetic":
        raise HTTPException(403, "only the synthetic source is available on this deployment")
    values = {k: params[k] for k in TUNABLE if k in params}
    try:
        cfg = EngineConfig(**values)
    except ValidationError as exc:
        raise HTTPException(422, json.loads(exc.json(include_url=False))) from exc
    if cfg.rate > MAX_PUBLIC_RATE:
        raise HTTPException(403, f"public demo is limited to {MAX_PUBLIC_RATE:.0f} lines/s")
    return cfg


def session_events(cfg, generation, seconds=STREAM_SECONDS):
    """Yield ("event", dict) and ("stats", dict) for one paced session."""
    stats = Stats()
    source = calibrated_stream(baseline_n=cfg.baseline_size, n=None, anomaly_rate=cfg.anomaly_rate,
                               seed=cfg.seed, mode=cfg.mode)
    engine = StreamingEngine(source, baseline_size=cfg.baseline_size,
                             threshold_percentile=cfg.threshold_percentile,
                             current_year=DEFAULT_START.year, stats=stats, source_type="synthetic")
    started = time.monotonic()
    deadline = started + seconds
    next_at = started
    last_stats = 0.0
    summary = {k: getattr(cfg, k) for k in TUNABLE}
    summary["source"] = "synthetic"

    for event in engine.run():
        now = time.monotonic()
        if now >= deadline:
            return
        rate = cfg.rate if event["phase"] == "live" else max(cfg.rate, CALIBRATION_RATE)
        next_at += 1.0 / rate
        delay = next_at - now
        if delay > 0:
            time.sleep(delay)
        elif delay < -1.0:
            next_at = now  # fell behind: don't catch up in a burst
        event["gen"] = generation
        yield "event", event
        if now - last_stats >= 1.0:
            last_stats = now
            snap = stats.snapshot()
            snap.update(status="running", error=None, generation=generation, config=summary,
                        session_seconds_left=round(deadline - now))
            yield "stats", snap


def create_serverless_app(stream_seconds=STREAM_SECONDS):
    app = FastAPI(title="Log Forensics Engine (serverless)")
    defaults = EngineConfig()

    @app.middleware("http")
    async def security_headers(request: Request, call_next):
        response = await call_next(request)
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["Referrer-Policy"] = "no-referrer"
        if request.url.path == "/":
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; "
                "style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; "
                "frame-ancestors 'self'; base-uri 'none'; form-action 'none'")
        return response

    @app.api_route("/", methods=["GET", "HEAD"], include_in_schema=False)
    def index():
        return FileResponse(os.path.join(STATIC_DIR, "index.html"), media_type="text/html")

    @app.api_route("/healthz", methods=["GET", "HEAD"])
    def healthz():
        return {"ok": True, "status": "serverless"}

    def payload(cfg):
        return {"config": cfg.model_dump(), "allowed_sources": ["synthetic"], "public_demo": True,
                "stateless": True, "generation": None, "feature_names": FEATURE_NAMES,
                "anomaly_features": BASE_FEATURES, "session_seconds": stream_seconds}

    @app.get("/api/config")
    def get_config():
        return payload(defaults)

    @app.post("/api/config")
    def post_config(update: dict):
        # Nothing to restart: the browser reconnects /events with these settings.
        return payload(_config_from(update))

    @app.get("/api/stats")
    def get_stats():
        return {"stateless": True, "detail": "stats arrive on the /events stream as `event: stats`"}

    @app.get("/api/events")
    def get_events():
        return {"generation": None, "events": []}

    @app.get("/api/anomalies")
    def get_anomalies():
        return {"generation": None, "anomalies": []}

    @app.get("/events")
    def events(request: Request):
        cfg = _config_from(dict(request.query_params))
        generation = secrets.randbelow(10**9) + 1

        def stream():
            yield "retry: 1500\n\n"
            yield _sse({"generation": generation, "source": "synthetic",
                        "session_seconds": stream_seconds}, event="hello")
            for kind, data in session_events(cfg, generation, stream_seconds):
                if kind == "event":
                    yield _sse(data, event_id=f"{generation}-{data['seq']}")
                else:
                    yield _sse(data, event="stats")
            yield _sse({"reason": "session time limit reached; reconnecting"}, event="bye")

        headers = {"Cache-Control": "no-cache, no-transform", "X-Accel-Buffering": "no"}
        return StreamingResponse(stream(), media_type="text/event-stream", headers=headers)

    return app
