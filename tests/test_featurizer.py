import math
from datetime import datetime, timedelta

from featurizer import (
    FEATURE_NAMES,
    HOUR_FEATURES,
    IP_WINDOW_SIZE,
    MAX_TRACKED_IPS,
    feature_names,
    featurize,
    new_state,
)
from log_parser import RECORD_KEYS

IDX = {name: i for i, name in enumerate(FEATURE_NAMES)}
T0 = datetime(2026, 8, 28, 12, 0, 0)


def rec(ts=T0, ip="10.0.0.5", message="Accepted password for bob", auth=None, status=None, code=None):
    r = dict.fromkeys(RECORD_KEYS)
    r.update(timestamp=ts, ip=ip, message=message, auth_result=auth, status=status, status_code=code,
             format="syslog")
    return r


def test_vector_shape_and_names():
    v = featurize(rec(), new_state())
    assert len(v) == len(FEATURE_NAMES)
    assert all(isinstance(x, float) for x in v)
    assert len(featurize(rec(), new_state(), use_hour=True)) == len(feature_names(use_hour=True))


def test_time_delta_is_clamped():
    s = new_state()
    featurize(rec(ts=T0), s)
    assert featurize(rec(ts=T0 + timedelta(seconds=5)), s)[IDX["time_delta_seconds"]] == 5.0
    assert featurize(rec(ts=T0 + timedelta(hours=10)), s)[IDX["time_delta_seconds"]] == 3600.0


def test_out_of_order_timestamp_gives_zero_and_keeps_clock():
    s = new_state()
    featurize(rec(ts=T0), s)
    featurize(rec(ts=T0 + timedelta(seconds=100)), s)
    late = featurize(rec(ts=T0 + timedelta(seconds=40)), s)
    assert late[IDX["time_delta_seconds"]] == 0.0
    assert s["last_timestamp"] == T0 + timedelta(seconds=100)
    nxt = featurize(rec(ts=T0 + timedelta(seconds=103)), s)
    assert nxt[IDX["time_delta_seconds"]] == 3.0  # measured from the newest, not the late one
    assert all(math.isfinite(x) for x in late)


def test_missing_timestamp_is_tolerated():
    s = new_state()
    v = featurize(rec(ts=None), s)
    assert v[IDX["time_delta_seconds"]] == 0.0 and v[IDX["ip_recent_rate"]] == 0.0
    featurize(rec(ts=T0), s)
    v = featurize(rec(ts=None), s)
    assert v[IDX["time_delta_seconds"]] == 0.0
    assert s["last_timestamp"] == T0


def test_ip_rate_and_burst_features():
    s = new_state()
    for i in range(10):
        v = featurize(rec(ts=T0 + timedelta(seconds=i * 0.5), ip="203.0.113.5",
                          message="Failed password", auth="failed", status="failed_login"), s)
    assert v[IDX["ip_recent_rate"]] > 1.0
    assert v[IDX["ip_events_60s"]] == 9.0
    assert v[IDX["ip_fail_ratio"]] == 1.0
    assert v[IDX["is_failed_login"]] == 1.0
    assert v[IDX["ip_recent_rate"]] <= 20.0


def test_keyword_flags():
    v = featurize(rec(message="FATAL: password authentication failed"), new_state())
    assert v[IDX["kw_critical"]] == 1.0 and v[IDX["kw_error"]] == 1.0
    assert v[IDX["kw_warning"]] == 0.0


def test_status_buckets():
    s = new_state()
    assert featurize(rec(status="failed_login"), s)[IDX["status_code_bucket"]] == 4.0
    assert featurize(rec(status="firewall_drop"), s)[IDX["status_code_bucket"]] == 3.0
    assert featurize(rec(status="503", code=503), s)[IDX["status_code_bucket"]] == 5.0
    assert featurize(rec(status="200", code=200), s)[IDX["status_code_bucket"]] == 1.0


def test_hour_encoding_wraps_midnight():
    def hour_vec(h):
        v = featurize(rec(ts=T0.replace(hour=h, minute=0)), new_state(), use_hour=True)
        return v[-2:]
    a, b, c = hour_vec(23), hour_vec(1), hour_vec(12)
    assert math.dist(a, b) < math.dist(a, c)
    assert HOUR_FEATURES == ["hour_sin", "hour_cos"]


def test_one_million_unique_ips_stay_under_cap():
    s = new_state()
    for i in range(1_000_000):
        ip = f"{(i >> 16) & 255}.{(i >> 8) & 255}.{i & 255}.{i % 7}"
        featurize(rec(ts=T0 + timedelta(milliseconds=i), ip=ip), s)
        if i % 100_000 == 0:
            assert len(s["ip_recent"]) <= MAX_TRACKED_IPS
    assert len(s["ip_recent"]) == MAX_TRACKED_IPS
    assert s["evicted_ips"] == 1_000_000 - MAX_TRACKED_IPS
    assert all(len(d) <= IP_WINDOW_SIZE for d in s["ip_recent"].values())


def test_lru_keeps_recently_seen_ip():
    s = new_state(max_ips=3)
    for ip in ["a", "b", "c"]:
        featurize(rec(ip=ip), s)
    featurize(rec(ip="a"), s)   # touch a: b is now the stalest
    featurize(rec(ip="d"), s)
    assert list(s["ip_recent"]) == ["c", "a", "d"]
