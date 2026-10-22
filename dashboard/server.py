"""
dashboard/server.py

Live web dashboard for the Log Forensics Engine.

    source (synthetic | udp | ssh | tail)
            |
       StreamingEngine  --(thread)-->  ring deque(maxlen=2000) + Stats
                                              |
                                       GET /events            (Server-Sent Events)
                                       GET /api/stats, /api/anomalies, /api/events
                                       GET/POST /api/config
                                              |
                                      static/index.html + Chart.js

The engine runs in a background thread and appends every event to a
bounded ring buffer. Each SSE client holds a cursor into that ring; when a
client falls behind by more than MAX_BATCH events it skips ahead (the
skipped events are counted as dropped) instead of the server buffering for
it, so memory stays constant however many or however slow the clients are.

    python -m dashboard.server --source synthetic
    python -m dashboard.server --source udp --port 5140
    python -m dashboard.server --source tail --path /var/log/auth.log
    python -m dashboard.server --source ssh --ssh-host srv --ssh-user me --ssh-path /var/log/auth.log

Binds to 127.0.0.1:8000 by default. POST /api/config can point the
engine at any file or SSH host, so before exposing the server publicly run
it with --public-demo, which only allows the synthetic source.
"""

import argparse
import asyncio
import json
import os
import sys
import threading
import time
from collections import deque
from typing import Literal, Optional

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.responses import FileResponse, StreamingResponse
from pydantic import BaseModel, Field, ValidationError

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from engine import Stats, StreamingEngine  # noqa: E402
from log_source import tail_file  # noqa: E402
from remote_sources import ssh_tail, syslog_udp_listener  # noqa: E402
from synthetic_logs import DEFAULT_START, live_generator  # noqa: E402

STATIC_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "static")
SOURCES = ("synthetic", "udp", "ssh", "tail")
RING_SIZE = 2000
ANOMALY_RING_SIZE = 500
MAX_BATCH = 200          # most events one SSE poll will send; older ones are dropped
POLL_INTERVAL = 0.2      # seconds between ring polls per SSE client
HEARTBEAT_SECONDS = 15.0
MIN_RESTART_INTERVAL = 2.0


class EngineConfig(BaseModel):
    source: Literal["synthetic", "udp", "ssh", "tail"] = "synthetic"
    threshold_percentile: float = Field(99.5, ge=50.0, le=100.0)
    anomaly_rate: float = Field(0.02, ge=0.0, le=0.5)
    baseline_size: int = Field(300, ge=20, le=5000)
    rate: float = Field(20.0, gt=0.0, le=500.0, description="synthetic lines per second")
    mode: Literal["syslog", "access", "mixed"] = "mixed"
    seed: Optional[int] = None
    udp_host: str = "127.0.0.1"
    udp_port: int = Field(5140, ge=0, le=65535)
    tail_path: Optional[str] = None
    ssh_host: Optional[str] = None
    ssh_port: int = Field(22, ge=1, le=65535)
    ssh_user: Optional[str] = None
    ssh_path: str = "/var/log/auth.log"
    ssh_key: Optional[str] = None
    known_hosts: Optional[str] = None
    insecure: bool = False


class EngineRunner:
    """Owns the engine thread, the bounded event rings and the Stats."""

    def __init__(self, config, ssh_password=None):
        self.config = config
        self.ssh_password = ssh_password
        self._lock = threading.Lock()
        self.events = deque(maxlen=RING_SIZE)
        self.anomalies = deque(maxlen=ANOMALY_RING_SIZE)
        self.generation = 0
        self.stats = Stats()
        self.status = "stopped"
        self.error = None
        self.engine = None
        self._thread = None
        self._stop = None
        self.last_restart = 0.0
        self.sse_clients = 0
        self.sse_dropped = 0

    # -- lifecycle ---------------------------------------------------------
    def start(self):
        with self._lock:
            self.generation += 1
            gen = self.generation
            self.events.clear()
            self.anomalies.clear()
            self.stats = Stats()
            self.status = "starting"
            self.error = None
            self.engine = None
            self._stop = threading.Event()
            self._thread = threading.Thread(target=self._run, name=f"engine-{gen}",
                                            args=(gen, self.config, self._stop, self.stats),
                                            daemon=True)
            self.last_restart = time.monotonic()
        self._thread.start()

    def stop(self, timeout=5.0):
        if self._stop is not None:
            self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)
        self.status = "stopped"

    def restart(self, config):
        self.stop()
        self.config = config
        self.start()

    def _build_source(self, cfg, stop, counters):
        """(iterable, current_year) for a config."""
        if cfg.source == "synthetic":
            gen = live_generator(rate=cfg.rate, anomaly_rate=cfg.anomaly_rate, seed=cfg.seed,
                                 baseline_n=cfg.baseline_size, mode=cfg.mode, stop_event=stop)
            return gen, DEFAULT_START.year
        if cfg.source == "udp":
            return syslog_udp_listener(host=cfg.udp_host, port=cfg.udp_port,
                                       stop_event=stop, counters=counters), None
        if cfg.source == "tail":
            if not cfg.tail_path:
                raise ValueError("tail source needs tail_path")
            return tail_file(cfg.tail_path, stop_event=stop), None
        if cfg.source == "ssh":
            if not (cfg.ssh_host and cfg.ssh_user):
                raise ValueError("ssh source needs ssh_host and ssh_user")
            return ssh_tail(cfg.ssh_host, cfg.ssh_user, cfg.ssh_path, port=cfg.ssh_port,
                            password=self.ssh_password,
                            key_filename=os.path.expanduser(cfg.ssh_key) if cfg.ssh_key else None,
                            known_hosts=cfg.known_hosts, insecure=cfg.insecure,
                            stop_event=stop, counters=counters), None
        raise ValueError(f"unknown source {cfg.source}")

    def _run(self, gen, cfg, stop, stats):
        try:
            counters = {}
            source, current_year = self._build_source(cfg, stop, counters)
            if cfg.source in ("udp", "ssh"):
                stats.attach_source_counters(counters)
            engine = StreamingEngine(source, baseline_size=cfg.baseline_size,
                                     threshold_percentile=cfg.threshold_percentile,
                                     current_year=current_year, stats=stats, stop_event=stop,
                                     source_type=cfg.source)
            with self._lock:
                if gen == self.generation:
                    self.engine = engine
                    self.status = "running"
            for event in engine.run():
                event["gen"] = gen
                with self._lock:
                    if gen != self.generation:
                        return
                    self.events.append(event)
                    if event["is_anomaly"]:
                        self.anomalies.append(event)
            with self._lock:
                if gen == self.generation and not stop.is_set():
                    self.status = "finished"
        except Exception as exc:  # surfaced on /api/stats instead of killing the server
            with self._lock:
                if gen == self.generation:
                    self.status = "error"
                    self.error = f"{type(exc).__name__}: {exc}"

    # -- reads (called from request handlers) ---------------------------
    def events_after(self, gen, seq, limit=MAX_BATCH):
        """
        (current_generation, events newer than seq, dropped). If the
        generation changed (engine restarted) the caller must reset; if
        more than `limit` events are pending, only the newest are returned
        and the rest are reported as dropped.
        """
        with self._lock:
            if gen != self.generation:
                return self.generation, None, 0
            newer = []
            for event in reversed(self.events):
                if event["seq"] <= seq:
                    break
                newer.append(event)
        newer.reverse()
        # Events that already fell out of the ring before we got to them.
        dropped = max(0, newer[0]["seq"] - seq - 1) if newer else 0
        if len(newer) > limit:
            dropped += len(newer) - limit
            newer = newer[-limit:]
        return gen, newer, dropped

    def recent(self, limit, anomalies_only=False):
        with self._lock:
            ring = self.anomalies if anomalies_only else self.events
            items = list(ring)[-limit:]
        items.reverse()  # newest first
        return items


def _sse(data, event=None, event_id=None):
    parts = []
    if event_id is not None:
        parts.append(f"id: {event_id}")
    if event is not None:
        parts.append(f"event: {event}")
    parts.append("data: " + json.dumps(data, separators=(",", ":")))
    return "\n".join(parts) + "\n\n"


def create_app(config=None, public_demo=False, ssh_password=None, autostart=True,
               heartbeat_seconds=HEARTBEAT_SECONDS):
    config = config or EngineConfig()
    allowed = ("synthetic",) if public_demo else SOURCES
    runner = EngineRunner(config, ssh_password=ssh_password)

    from contextlib import asynccontextmanager

    @asynccontextmanager
    async def lifespan(app):
        if autostart:
            runner.start()
        yield
        runner.stop(timeout=2.0)

    app = FastAPI(title="Log Forensics Engine", lifespan=lifespan)
    app.state.runner = runner
    app.state.public_demo = public_demo
    started_at = time.time()

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

    @app.get("/", include_in_schema=False)
    def index():
        return FileResponse(os.path.join(STATIC_DIR, "index.html"), media_type="text/html")

    @app.get("/healthz")
    def healthz():
        return {"ok": True, "status": runner.status}

    def config_payload():
        engine = runner.engine
        return {
            "config": runner.config.model_dump(),
            "allowed_sources": list(allowed),
            "public_demo": public_demo,
            "generation": runner.generation,
            "feature_names": engine.feature_names if engine else None,
            "anomaly_features": engine.anomaly_feature_names if engine else None,
        }

    @app.get("/api/config")
    def get_config():
        return config_payload()

    @app.post("/api/config")
    def post_config(update: dict):
        unknown = set(update) - set(EngineConfig.model_fields)
        if unknown:
            raise HTTPException(422, f"unknown config keys: {sorted(unknown)}")
        try:
            new_config = EngineConfig(**{**runner.config.model_dump(), **update})
        except ValidationError as exc:
            raise HTTPException(422, json.loads(exc.json(include_url=False))) from exc
        if new_config.source not in allowed:
            raise HTTPException(403, f"source '{new_config.source}' is disabled on this server "
                                     f"(allowed: {', '.join(allowed)})")
        if public_demo and new_config.rate > 50:
            raise HTTPException(403, "public demo is limited to 50 lines/s")
        if time.monotonic() - runner.last_restart < MIN_RESTART_INTERVAL:
            raise HTTPException(429, "engine restarted moments ago; try again in a second")
        runner.restart(new_config)
        return config_payload()

    @app.get("/api/stats")
    def get_stats():
        snap = runner.stats.snapshot()
        snap.update(
            status=runner.status,
            error=runner.error,
            generation=runner.generation,
            server_uptime_seconds=round(time.time() - started_at, 1),
            sse_clients=runner.sse_clients,
            sse_dropped=runner.sse_dropped,
            config={k: getattr(runner.config, k) for k in
                    ("source", "threshold_percentile", "anomaly_rate", "baseline_size", "rate", "mode")},
        )
        return snap

    @app.get("/api/anomalies")
    def get_anomalies(limit: int = Query(100, ge=1, le=ANOMALY_RING_SIZE)):
        return {"generation": runner.generation, "anomalies": runner.recent(limit, anomalies_only=True)}

    @app.get("/api/events")
    def get_events(limit: int = Query(100, ge=1, le=RING_SIZE)):
        return {"generation": runner.generation, "events": runner.recent(limit)}

    @app.get("/events")
    async def events(request: Request, max_events: Optional[int] = Query(None, ge=1, le=10_000),
                     after: Optional[str] = Query(None, max_length=40)):
        """
        Server-Sent Events: one JSON engine event per message (id = gen-seq,
        so a reconnecting browser resumes via Last-Event-ID). Also sends
        `event: hello` on connect, `event: reset` when the engine restarts,
        `event: dropped` when this client fell behind, and a heartbeat
        comment every 15 s. `after=gen-seq` resumes after an event the page
        already has (e.g. from /api/events); Last-Event-ID wins if present.
        """
        gen, seq = runner.generation, 0
        last_id = request.headers.get("last-event-id") or after or ""
        if "-" in last_id:
            try:
                g, s = (int(x) for x in last_id.split("-", 1))
                if g == runner.generation:
                    gen, seq = g, s
            except ValueError:
                pass
        if not seq:
            # Fresh connection: start from "now"; the page backfills from /api/events.
            with runner._lock:
                seq = runner.events[-1]["seq"] if runner.events else 0

        async def stream():
            nonlocal gen, seq
            runner.sse_clients += 1
            sent = 0
            last_write = time.monotonic()
            try:
                yield "retry: 3000\n\n"
                yield _sse({"generation": gen, "source": runner.config.source}, event="hello")
                while True:
                    current, batch, dropped = runner.events_after(gen, seq)
                    if batch is None:
                        gen, seq = current, 0
                        yield _sse({"generation": gen}, event="reset")
                        last_write = time.monotonic()
                        continue
                    if dropped:
                        runner.sse_dropped += dropped
                        yield _sse({"dropped": dropped}, event="dropped")
                    for event in batch:
                        seq = event["seq"]
                        yield _sse(event, event_id=f"{gen}-{seq}")
                        sent += 1
                        if max_events and sent >= max_events:
                            return
                    if batch:
                        last_write = time.monotonic()
                    elif time.monotonic() - last_write >= heartbeat_seconds:
                        yield ": heartbeat\n\n"
                        last_write = time.monotonic()
                    if await request.is_disconnected():
                        return
                    await asyncio.sleep(POLL_INTERVAL)
            finally:
                runner.sse_clients -= 1

        headers = {"Cache-Control": "no-cache", "X-Accel-Buffering": "no", "Connection": "keep-alive"}
        return StreamingResponse(stream(), media_type="text/event-stream", headers=headers)

    return app


def parse_args(argv=None):
    ap = argparse.ArgumentParser(description="Log Forensics Engine dashboard")
    ap.add_argument("--source", choices=SOURCES, default="synthetic")
    ap.add_argument("--port", type=int, default=5140, help="UDP syslog port (--source udp)")
    ap.add_argument("--udp-host", default="127.0.0.1",
                    help="UDP bind address; 0.0.0.0 accepts datagrams from other machines")
    ap.add_argument("--path", help="file to follow (--source tail)")
    ap.add_argument("--ssh-host")
    ap.add_argument("--ssh-port", type=int, default=22)
    ap.add_argument("--ssh-user")
    ap.add_argument("--ssh-path", default="/var/log/auth.log")
    ap.add_argument("--ssh-key")
    ap.add_argument("--known-hosts")
    ap.add_argument("--insecure", action="store_true", help="accept unknown SSH host keys (MITM risk)")
    ap.add_argument("--rate", type=float, default=20.0, help="synthetic lines per second")
    ap.add_argument("--mode", choices=["syslog", "access", "mixed"], default="mixed")
    ap.add_argument("--anomaly-rate", type=float, default=0.02,
                    help="chance per synthetic event of starting an attack burst")
    ap.add_argument("--threshold", type=float, default=99.5, help="threshold percentile")
    ap.add_argument("--baseline", type=int, default=300)
    ap.add_argument("--seed", type=int)
    ap.add_argument("--http-host", default="127.0.0.1", help="dashboard bind address")
    ap.add_argument("--http-port", type=int, default=8000, help="dashboard port")
    ap.add_argument("--public-demo", action="store_true",
                    default=os.environ.get("LFE_PUBLIC_DEMO") == "1",
                    help="only allow the synthetic source (use when exposing the server)")
    return ap.parse_args(argv)


def main(argv=None):
    args = parse_args(argv)
    config = EngineConfig(
        source=args.source, threshold_percentile=args.threshold, anomaly_rate=args.anomaly_rate,
        baseline_size=args.baseline, rate=args.rate, mode=args.mode, seed=args.seed,
        udp_host=args.udp_host, udp_port=args.port, tail_path=args.path,
        ssh_host=args.ssh_host, ssh_port=args.ssh_port, ssh_user=args.ssh_user,
        ssh_path=args.ssh_path, ssh_key=args.ssh_key, known_hosts=args.known_hosts,
        insecure=args.insecure,
    )
    if args.public_demo and args.source != "synthetic":
        raise SystemExit("--public-demo only allows --source synthetic")
    if args.http_host not in ("127.0.0.1", "localhost", "::1") and not args.public_demo:
        print("WARNING: dashboard reachable from the network without --public-demo; "
              "anyone who can reach it can make it tail files or open SSH connections.",
              file=sys.stderr)
    app = create_app(config, public_demo=args.public_demo,
                     ssh_password=os.environ.get("LFE_SSH_PASSWORD"))
    import uvicorn
    print(f"Dashboard: http://{args.http_host}:{args.http_port}  (source={args.source})")
    uvicorn.run(app, host=args.http_host, port=args.http_port, log_level="warning")


if __name__ == "__main__":
    main()
