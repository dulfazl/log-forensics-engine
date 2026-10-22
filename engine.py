"""
engine.py

StreamingEngine: the one reusable piece both the CLI (pipeline.py) and the
dashboard use. It wires source -> parser -> featurizer -> models and turns
every input line into exactly one event dict.

    engine = StreamingEngine(source, baseline_size=300)
    for event in engine.run():
        ...

`source` yields either raw strings or (line, label) pairs; labels (ground
truth from synthetic_logs) are passed through untouched on the event so
evaluation never has to zip two streams back together.

The engine owns:
  * baseline calibration: the first `baseline_size` parsed records train
    the anomaly detector (events in this phase have phase="calibrating");
  * periodic severity retraining on a sliding window of seed labels;
  * periodic baseline refresh with normal-scored points only.

Stats keeps bounded rolling counters for the dashboard. Everything here is
O(1) memory in the length of the stream: the only buffers are deques with
a maxlen, the bounded featurizer state, and the models' capped windows.
"""

import threading
import time
from collections import Counter, deque

from featurizer import (
    BASE_FEATURES,
    BASE_IDX,
    HOUR_FEATURES,
    KEYWORD_FEATURES,
    KEYWORD_IDX,
    LEGACY_IDX,
    featurize,
    new_state,
)
from log_parser import YearTracker, parse_log_line
from models import SEVERITY_LABELS, AnomalyDetector, SeverityClassifier

MAX_RAW_CHARS = 2000      # raw text carried on an event (dashboard payload cap)
MAX_MESSAGE_CHARS = 500

EVENT_KEYS = ("seq", "ingest_ts", "ts", "raw", "parsed", "format", "phase",
              "severity_seed", "severity_pred", "severity", "distance", "threshold",
              "is_anomaly", "reason", "ip", "host", "process", "user", "message",
              "status", "auth_failed", "features", "label")


class Stats:
    """
    Thread-safe rolling counters. The engine thread calls record(); API
    threads call snapshot(). All containers are bounded:
      * per-second buckets: deque(maxlen=timeline_seconds)
      * recent failed-login IPs: deque(maxlen=failed_window) mirrored by a
        Counter that is decremented on eviction, so it never holds more
        than failed_window distinct IPs
      * everything else is a fixed set of integer counters
    """

    def __init__(self, window_seconds=60, timeline_seconds=120, top_n=10,
                 failed_window=1000, clock=time.time):
        self._lock = threading.Lock()
        self._clock = clock
        self.window_seconds = window_seconds
        self.top_n = top_n
        self.started_at = clock()
        self.source_type = None
        self.source_counters = None  # e.g. the UDP listener's {"received", "dropped"}

        self.total_lines = 0
        self.parsed = 0
        self.unparseable = 0
        self.anomalies = 0
        self.live_lines = 0
        self.severity_counts = {label: 0 for label in SEVERITY_LABELS}
        self.threshold = None
        self.phase = "calibrating"
        self.baseline_have = 0
        self.baseline_need = 0
        self.retrains = 0
        self.refreshes = 0

        self._timeline = deque(maxlen=timeline_seconds)  # [second, lines, anomalies]
        self._failed_ips = deque(maxlen=failed_window)
        self._failed_counter = Counter()

        # Ground-truth evaluation (only when events carry labels).
        self._eval = {"tp": 0, "fp": 0, "fn": 0, "tn": 0,
                      "tp_parsed": 0, "fp_parsed": 0, "fn_parsed": 0, "tn_parsed": 0}
        self._per_type = {}  # type -> [support, detected]
        self._sev_total = 0
        self._sev_agree = 0

    def attach_source_counters(self, counters):
        self.source_counters = counters

    def record(self, event):
        with self._lock:
            now_sec = int(event.get("ingest_ts") or self._clock())
            if self._timeline and self._timeline[-1][0] == now_sec:
                bucket = self._timeline[-1]
            else:
                bucket = [now_sec, 0, 0]
                self._timeline.append(bucket)
            bucket[1] += 1

            self.total_lines += 1
            self.phase = event["phase"]
            if event["threshold"] is not None:
                self.threshold = event["threshold"]
            if event["parsed"]:
                self.parsed += 1
            else:
                self.unparseable += 1
            if event["is_anomaly"]:
                self.anomalies += 1
                bucket[2] += 1
            sev = event["severity"]
            if sev in self.severity_counts:
                self.severity_counts[sev] += 1

            if event.get("auth_failed") and event["ip"]:
                if len(self._failed_ips) == self._failed_ips.maxlen:
                    old = self._failed_ips[0]
                    self._failed_counter[old] -= 1
                    if self._failed_counter[old] <= 0:
                        del self._failed_counter[old]
                self._failed_ips.append(event["ip"])
                self._failed_counter[event["ip"]] += 1

            if event["phase"] != "live":
                return
            self.live_lines += 1
            if event["severity_pred"] is not None and event["severity_seed"] is not None:
                self._sev_total += 1
                self._sev_agree += event["severity_pred"] == event["severity_seed"]

            label = event.get("label")
            if not label:
                return
            truth, pred = bool(label["anomalous"]), bool(event["is_anomaly"])
            key = ("tp" if pred else "fn") if truth else ("fp" if pred else "tn")
            self._eval[key] += 1
            if event["parsed"]:
                self._eval[key + "_parsed"] += 1
            if truth:
                slot = self._per_type.setdefault(label["type"], [0, 0])
                slot[0] += 1
                slot[1] += pred

    @staticmethod
    def _prf(tp, fp, fn):
        precision = tp / (tp + fp) if tp + fp else 0.0
        recall = tp / (tp + fn) if tp + fn else 0.0
        f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
        return {"precision": precision, "recall": recall, "f1": f1}

    def snapshot(self):
        with self._lock:
            now = self._clock()
            uptime = max(0.0, now - self.started_at)
            cutoff = int(now) - self.window_seconds
            recent = [b for b in self._timeline if b[0] > cutoff]
            span = max(1.0, min(float(self.window_seconds), uptime))
            lines_per_sec = sum(b[1] for b in recent) / span
            anomalies_per_sec = sum(b[2] for b in recent) / span

            ev = self._eval
            labeled = sum(ev[k] for k in ("tp", "fp", "fn", "tn"))
            evaluation = None
            if labeled:
                evaluation = {
                    "labeled_events": labeled,
                    "with_unparseable": {**self._prf(ev["tp"], ev["fp"], ev["fn"]),
                                         "tp": ev["tp"], "fp": ev["fp"], "fn": ev["fn"], "tn": ev["tn"]},
                    "parsed_only": self._prf(ev["tp_parsed"], ev["fp_parsed"], ev["fn_parsed"]),
                    "per_type": {t: {"support": s, "detected": d, "recall": d / s if s else 0.0}
                                 for t, (s, d) in sorted(self._per_type.items())},
                }

            dropped = received = None
            if self.source_counters is not None:
                dropped = self.source_counters.get("dropped")
                received = self.source_counters.get("received")

            return {
                "source_type": self.source_type,
                "phase": self.phase,
                "baseline": {"have": self.baseline_have, "need": self.baseline_need},
                "uptime_seconds": round(uptime, 1),
                "lines_per_sec": round(lines_per_sec, 2),
                "anomalies_per_sec": round(anomalies_per_sec, 3),
                "total_lines": self.total_lines,
                "live_lines": self.live_lines,
                "parsed": self.parsed,
                "unparseable": self.unparseable,
                "anomalies": self.anomalies,
                "anomaly_rate": self.anomalies / self.total_lines if self.total_lines else 0.0,
                "severity_counts": dict(self.severity_counts),
                "top_failed_ips": [{"ip": ip, "count": c}
                                   for ip, c in self._failed_counter.most_common(self.top_n)],
                "threshold": self.threshold,
                "dropped_udp": dropped,
                "received_udp": received,
                "severity_retrains": self.retrains,
                "baseline_refreshes": self.refreshes,
                "severity_agreement": (self._sev_agree / self._sev_total) if self._sev_total else None,
                "timeline": [list(b) for b in self._timeline],
                "evaluation": evaluation,
            }


class StreamingEngine:
    """
    Parameters
      source               iterable of str or (str, label)
      baseline_size        parsed records used to calibrate the detector
      k, threshold_percentile, max_baseline   AnomalyDetector settings
      severity_k, severity_window             SeverityClassifier settings
      retrain_every        live records between severity refits
      refresh_every        live records between baseline refreshes (0 = off)
      refresh_buffer       recent live vectors offered to refresh_baseline
      feature_set          "full": severity sees keyword flags, anomaly
                           detector sees the behavioural features;
                           "legacy": both see only the original 5
                           features, and the parser does not read SRC=
                           from firewall lines (the original behaviour),
                           so the README numbers can be reproduced
      use_hour             add sin/cos hour features (needs a week-long baseline)
      current_year         start year for BSD syslog timestamps of an ordered
                           replay/synthetic stream; None = wall-clock rule
      batch_size           live records scored per kneighbors call. 1 keeps
                           per-line latency for live sources; larger values
                           are much faster for files / benchmarks
      stats                a Stats instance to update (optional)
      stop_event           threading.Event; run() returns when it is set
    """

    def __init__(self, source, baseline_size=300, k=5, threshold_percentile=99.5,
                 severity_k=5, severity_window=500, retrain_every=100,
                 refresh_every=1000, refresh_buffer=500, max_baseline=5000,
                 feature_set="full", use_hour=False, current_year=None,
                 batch_size=1, stats=None, stop_event=None, source_type="custom",
                 explain=True):
        if feature_set not in ("full", "legacy"):
            raise ValueError("feature_set must be 'full' or 'legacy'")
        if baseline_size < 2:
            raise ValueError("baseline_size must be at least 2")
        self.source = source
        self.baseline_size = baseline_size
        self.retrain_every = retrain_every
        self.refresh_every = refresh_every
        self.feature_set = feature_set
        self.use_hour = use_hour
        self.batch_size = max(1, int(batch_size))
        self.stats = stats
        self.stop_event = stop_event
        self.source_type = source_type
        self.explain_anomalies = explain

        self.detector = AnomalyDetector(k=k, threshold_percentile=threshold_percentile,
                                        max_baseline=max_baseline)
        self.classifier = SeverityClassifier(k=severity_k, window_size=severity_window)
        self.state = new_state()
        self._firewall = feature_set != "legacy"
        self._years = YearTracker(current_year, firewall=self._firewall) if current_year else None
        self._refresh_buf = deque(maxlen=refresh_buffer)

        self.feature_names = BASE_FEATURES + KEYWORD_FEATURES + (HOUR_FEATURES if use_hour else [])
        hour_idx = list(range(len(BASE_FEATURES) + len(KEYWORD_FEATURES), len(self.feature_names)))
        if feature_set == "legacy":
            self.severity_idx = list(LEGACY_IDX)
            self.anomaly_idx = list(LEGACY_IDX)
        else:
            # Severity sees what the seed rule depends on: the keyword flags,
            # the failed-login flag and the status bucket. The per-IP rate
            # features only add noise to that neighbourhood.
            self.severity_idx = [BASE_FEATURES.index("is_failed_login"),
                                 BASE_FEATURES.index("status_code_bucket")] + list(KEYWORD_IDX)
            self.anomaly_idx = list(BASE_IDX) + hour_idx
        self.anomaly_feature_names = [self.feature_names[i] for i in self.anomaly_idx]

        self.seq = 0
        self.live_count = 0
        self.phase = "calibrating"
        self._baseline = []  # only during calibration, at most baseline_size rows

        if stats is not None:
            stats.source_type = source_type
            stats.baseline_need = baseline_size

    # -- helpers ---------------------------------------------------------
    def _stopped(self):
        return self.stop_event is not None and self.stop_event.is_set()

    def _parse(self, line):
        if self._years is not None:
            return self._years.parse(line)
        return parse_log_line(line, firewall=self._firewall)

    def _event(self, line, label, record):
        self.seq += 1
        parsed = record is not None
        message = record["message"] if parsed else None
        return {
            "seq": self.seq,
            "ingest_ts": time.time(),
            "ts": record["timestamp"].isoformat() if parsed and record["timestamp"] else None,
            "raw": line[:MAX_RAW_CHARS],
            "parsed": parsed,
            "format": record["format"] if parsed else None,
            "phase": self.phase,
            "severity_seed": record["severity"] if parsed else None,
            "severity_pred": None,
            "severity": record["severity"] if parsed else None,
            "distance": None,
            "threshold": self.detector.threshold,
            "is_anomaly": not parsed,
            "reason": None if parsed else "unparseable",
            "ip": record["ip"] if parsed else None,
            "host": record["host"] if parsed else None,
            "process": record["process"] if parsed else None,
            "user": record["user"] if parsed else None,
            "message": message[:MAX_MESSAGE_CHARS] if message else message,
            "status": record["status"] if parsed else None,
            "auth_failed": parsed and record["auth_result"] == "failed",
            "features": None,
            "label": label,
        }

    def _emit(self, event):
        if self.stats is not None:
            self.stats.record(event)
        return event

    def _calibrate(self, event, vector):
        self._baseline.append([vector[i] for i in self.anomaly_idx])
        self.classifier.add_labeled([vector[i] for i in self.severity_idx], event["severity_seed"])
        event["reason"] = "calibrating"
        if self.stats is not None:
            self.stats.baseline_have = len(self._baseline)
        if len(self._baseline) >= self.baseline_size:
            self.detector.fit(self._baseline)
            self._baseline = []
            self.classifier.retrain()
            self.phase = "live"
            if self.stats is not None:
                self.stats.retrains = self.classifier.retrain_count
                self.stats.threshold = self.detector.threshold

    def _score_batch(self, batch):
        """batch: list of (event, vector). Fills in predictions in place."""
        anomaly_rows = [[v[i] for i in self.anomaly_idx] for _, v in batch]
        severity_rows = [[v[i] for i in self.severity_idx] for _, v in batch]
        flags, distances = self.detector.score_batch(anomaly_rows)
        preds = self.classifier.predict_batch(severity_rows)
        threshold = self.detector.threshold

        for (event, _), arow, srow, flag, dist, pred in zip(
                batch, anomaly_rows, severity_rows, flags, distances, preds):
            event["distance"] = round(float(dist), 4)
            event["threshold"] = threshold
            event["is_anomaly"] = bool(flag)
            event["severity_pred"] = pred
            event["severity"] = pred or event["severity_seed"]
            if flag:
                event["reason"] = self._reason(arow, float(dist), threshold)

            self.classifier.add_labeled(srow, event["severity_seed"])
            self._refresh_buf.append(arow)
            self.live_count += 1
            if self.retrain_every and self.live_count % self.retrain_every == 0:
                self.classifier.retrain()
                if self.stats is not None:
                    self.stats.retrains = self.classifier.retrain_count
            if self.refresh_every and self.live_count % self.refresh_every == 0:
                self.detector.refresh_baseline(list(self._refresh_buf))
                self._refresh_buf.clear()
                if self.stats is not None:
                    self.stats.refreshes = self.detector.refresh_count
                    self.stats.threshold = self.detector.threshold

    def _reason(self, arow, dist, threshold):
        text = f"distance {dist:.2f} > threshold {threshold:.2f}"
        if self.explain_anomalies:
            top = self.detector.explain(arow, self.anomaly_feature_names)[:2]
            parts = [f"{name} {diff:+.1f}σ" for name, diff in top if abs(diff) >= 0.5]
            if parts:
                text += "; " + ", ".join(parts)
        return text

    # -- main loop ---------------------------------------------------------
    def run(self):
        """Generator: one event dict per input line, in input order."""
        pending = []  # events waiting for their batch to be scored, in order
        batch = []    # (event, vector) pairs among `pending` that need scoring

        def flush():
            if batch:
                self._score_batch(batch)
                batch.clear()
            out = [self._emit(e) for e in pending]
            pending.clear()
            return out

        for item in self.source:
            if self._stopped():
                break
            if isinstance(item, tuple):
                line, label = item
            else:
                line, label = item, None
            if not isinstance(line, str):
                line = str(line)

            record = self._parse(line)
            event = self._event(line, label, record)

            if record is None:
                pending.append(event)
            else:
                vector = featurize(record, self.state, use_hour=self.use_hour)
                event["features"] = [round(x, 4) for x in vector]
                if self.phase == "calibrating":
                    self._calibrate(event, vector)
                    pending.append(event)
                else:
                    pending.append(event)
                    batch.append((event, vector))

            if len(batch) >= self.batch_size or (not batch and pending):
                yield from flush()

        yield from flush()
