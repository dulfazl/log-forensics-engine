"""
featurizer.py

Turns parsed records into numeric feature vectors for the KNN models,
using only small, bounded running state. Nothing here grows with the
length of the stream.

Default vector (FEATURE_NAMES):
  0 time_delta_seconds   seconds since the previous timestamped record,
                         clamped to [0, 3600] (out-of-order -> 0)
  1 message_length       characters in the message
  2 is_failed_login      1.0 for a failed / invalid-user login (syslog or HTTP 401/403 on a login path)
  3 ip_recent_rate       events per second over this IP's last 20 events, capped at 20
  4 status_code_bucket   coarse bucket of the auth / firewall / HTTP status
  5 ip_events_60s        this IP's events in the last 60 s (from its last 20), 0-20
  6 ip_fail_ratio        share of failed logins among this IP's last 20 events
  7 kw_critical          message contains a CRITICAL keyword
  8 kw_error             ... an ERROR keyword
  9 kw_warning           ... a WARNING keyword
 10 kw_info              ... an INFO keyword

Features 0-4 are the original set (the "legacy" configuration uses only
these). ip_recent_rate has a blind spot: when an IP's last 20 events
stretch back to an earlier burst, the window is long and the rate looks
low even while a new burst is under way. ip_events_60s measures the
current burst directly, and ip_fail_ratio catches attackers that fail
constantly but slowly (one attempt a minute never looks like a burst).

Features 7-10 exist so the severity classifier has something to learn
from: its seed labels come from these keywords (log_parser._guess_severity),
and without message content in the vector it could only learn a weak
proxy of a rule it cannot see.

Bounded state:
  * per-IP history lives in an LRU OrderedDict capped at MAX_TRACKED_IPS;
    the least recently seen IP is evicted when a new one arrives, so a
    scan from a million source addresses cannot grow memory forever.
  * each IP keeps at most IP_WINDOW_SIZE timestamps (deque(maxlen=...)).

Hour of day is NOT in the default vector. featurize(..., use_hour=True)
appends sin/cos of the hour so 23:00 and 01:00 are neighbours. Only turn
it on with a baseline that spans at least a week: a baseline covering a
few hours only ever sees a narrow slice of the clock, and every later
hour of perfectly normal traffic would then look anomalous.
"""

import math
from collections import OrderedDict, deque

from log_parser import SEVERITY_KEYWORDS

IP_WINDOW_SIZE = 20       # events remembered per IP
MAX_TRACKED_IPS = 10_000  # LRU cap on distinct IPs
MAX_TIME_DELTA = 3600.0
MAX_IP_RATE = 20.0

LEGACY_FEATURES = [
    "time_delta_seconds",
    "message_length",
    "is_failed_login",
    "ip_recent_rate",
    "status_code_bucket",
]
IP_FEATURES = ["ip_events_60s", "ip_fail_ratio"]
BASE_FEATURES = LEGACY_FEATURES + IP_FEATURES
KEYWORD_FEATURES = ["kw_critical", "kw_error", "kw_warning", "kw_info"]
HOUR_FEATURES = ["hour_sin", "hour_cos"]
FEATURE_NAMES = BASE_FEATURES + KEYWORD_FEATURES

# Index sets the engine uses to feed each model a different view.
LEGACY_IDX = list(range(len(LEGACY_FEATURES)))
BASE_IDX = list(range(len(BASE_FEATURES)))
KEYWORD_IDX = list(range(len(BASE_FEATURES), len(FEATURE_NAMES)))
BURST_WINDOW_SECONDS = 60.0

_KEYWORD_GROUPS = [tuple(SEVERITY_KEYWORDS[level])
                   for level in ("CRITICAL", "ERROR", "WARNING", "INFO")]


def feature_names(use_hour=False):
    return FEATURE_NAMES + (HOUR_FEATURES if use_hour else [])


def new_state(max_ips=MAX_TRACKED_IPS):
    """Fresh running state. Everything in it is bounded."""
    return {
        "last_timestamp": None,
        "ip_recent": OrderedDict(),  # ip -> deque of datetimes, LRU order
        "max_ips": max_ips,
        "evicted_ips": 0,
        "event_index": 0,
    }


def _status_bucket(record):
    status = record["status"]
    if status is None:
        return 0
    if status in ("failed_login", "invalid_user"):
        return 4
    if status == "accepted_login":
        return 1
    if status == "firewall_drop":
        return 3
    code = record["status_code"]
    if code is None:
        return 0
    if code >= 500:
        return 5
    if code >= 400:
        return 4
    if code >= 300:
        return 2
    return 1


def _ip_history(state, ip):
    """LRU lookup: returns this IP's deque, evicting the stalest IP if
    the table is full."""
    table = state["ip_recent"]
    history = table.get(ip)
    if history is not None:
        table.move_to_end(ip)
        return history
    if len(table) >= state["max_ips"]:
        table.popitem(last=False)
        state["evicted_ips"] += 1
    history = deque(maxlen=IP_WINDOW_SIZE)  # (timestamp or None, failed 0/1)
    table[ip] = history
    return history


def keyword_flags(message):
    msg = message.lower()
    return [1.0 if any(kw in msg for kw in group) else 0.0 for group in _KEYWORD_GROUPS]


def featurize(record, state, use_hour=False):
    """
    One parsed record -> list of floats. Updates `state` in place.
    Missing timestamps are tolerated: the time delta is 0 and the IP
    rate falls back to 0 for that record.
    """
    ts = record["timestamp"]
    last = state["last_timestamp"]

    if ts is not None and last is not None:
        raw_delta = (ts - last).total_seconds()
        time_delta = min(max(0.0, raw_delta), MAX_TIME_DELTA)
    else:
        time_delta = 0.0

    message = record["message"] or ""
    is_failed = 1.0 if record["auth_result"] == "failed" else 0.0

    state["event_index"] += 1
    ip_rate = ip_burst = ip_fail_ratio = 0.0
    ip = record["ip"]
    if ip:
        recent = _ip_history(state, ip)
        stamped = [t for t, _ in recent if t is not None]
        if ts is not None and stamped:
            # Floor the window at 1 s and cap the rate so one odd timestamp
            # cannot produce an unbounded value that dominates distances;
            # abs() tolerates out-of-order timestamps.
            window = max(1.0, abs((ts - stamped[0]).total_seconds()))
            ip_rate = min(len(stamped) / window, MAX_IP_RATE)
            ip_burst = float(sum(1 for t in stamped
                                 if abs((ts - t).total_seconds()) <= BURST_WINDOW_SECONDS))
        recent.append((ts, is_failed))
        ip_fail_ratio = sum(f for _, f in recent) / len(recent)

    # Only move the clock forward: one late record must not make the
    # next in-order record look like a long gap.
    if ts is not None and (last is None or ts > last):
        state["last_timestamp"] = ts

    vector = [
        time_delta,
        float(len(message)),
        is_failed,
        ip_rate,
        float(_status_bucket(record)),
        ip_burst,
        ip_fail_ratio,
        *keyword_flags(message),
    ]
    if use_hour:
        hour = 0.0 if ts is None else ts.hour + ts.minute / 60.0
        angle = 2.0 * math.pi * hour / 24.0
        vector += [math.sin(angle), math.cos(angle)]
    return vector
