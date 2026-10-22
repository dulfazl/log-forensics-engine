import itertools
import time
from datetime import datetime

import pytest

from log_parser import RECORD_KEYS, YearTracker, _guess_severity, parse_log_line

SYSLOG_LINES = [
    "Aug 28 03:14:07 web01 sshd[1234]: Failed password for root from 10.0.0.5 port 51514 ssh2",
    "Aug 28 03:14:09 web01 sshd[1235]: Failed password for invalid user oracle from 203.0.113.9 port 40022 ssh2",
    "Aug  2 11:00:01 db01 sshd[88]: Accepted publickey for deploy from 192.168.1.20 port 50111 ssh2: ED25519 SHA256:abc",
    "Sep 10 22:01:59 auth01 sshd[4242]: Invalid user admin from 198.51.100.23 port 6000",
    "Oct 11 22:14:15 mymachine su: 'su root' failed for lonvick on /dev/pts/8",
    "Aug 28 03:14:07 web02 CRON[1096]: (root) CMD (/usr/bin/backup.sh)",
    "Aug 28 03:14:07 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= SRC=185.220.101.7 DST=10.0.0.1 PROTO=TCP DPT=22",
]

ACCESS_LINES = [
    '127.0.0.1 - - [28/Aug/2026:03:14:07 +0000] "GET /index.html HTTP/1.1" 200 512',
    '203.0.113.55 - - [28/Aug/2026:03:14:08 +0000] "POST /login HTTP/1.1" 401 210 "-" "curl/8.4.0"',
    '10.0.0.7 - alice [28/Aug/2026:05:00:00 +0200] "GET /api/items?page=2 HTTP/2.0" 304 - "https://example.com/" "Mozilla/5.0"',
    '2001:db8::1 - - [28/Aug/2026:03:14:09 +0000] "GET /.env HTTP/1.1" 404 153 "-" "Nikto/2.5.0"',
    '192.168.1.34 - - [28/Aug/2026:03:15:00 +0000] "POST /api/cart HTTP/1.1" 502 0 "-" "Mozilla/5.0"',
]

MALFORMED_LINES = [
    "",
    "\x00\x01\x02\xff\xfe binary junk \x9c",
    "Aug 28 03:14:07 web01",                               # truncated
    "Aug|28|03:14:07|web01|sshd[1]:|Failed password",      # wrong delimiter
    "A" * 100_000,                                         # extremely long
    "###CORRUPTED_ENTRY###",
    '127.0.0.1 - - [28/Aug/2026:03:14:07 +0000] "GET /x HTTP/1.1"',  # truncated access line
    "Foo 28 03:14:07 web01 sshd[1]: bad month",
    "Aug 28 25:61:07 web01 sshd[1]: bad time",
]


@pytest.mark.parametrize("line", SYSLOG_LINES + ACCESS_LINES)
def test_every_record_has_the_same_keys(line):
    record = parse_log_line(line, current_year=2026)
    assert record is not None, line
    assert tuple(record) == RECORD_KEYS


@pytest.mark.parametrize("line", MALFORMED_LINES)
def test_malformed_lines_return_none(line):
    assert parse_log_line(line, current_year=2026) is None


def test_failed_login_fields():
    r = parse_log_line(SYSLOG_LINES[0], current_year=2026)
    assert r["format"] == "syslog"
    assert r["timestamp"] == datetime(2026, 8, 28, 3, 14, 7)
    assert (r["host"], r["process"], r["pid"]) == ("web01", "sshd", 1234)
    assert (r["ip"], r["user"], r["port"]) == ("10.0.0.5", "root", 51514)
    assert r["status"] == "failed_login" and r["auth_result"] == "failed"
    assert r["severity"] == "ERROR"


def test_invalid_user_variants():
    r = parse_log_line(SYSLOG_LINES[1], current_year=2026)
    assert (r["user"], r["ip"], r["status"]) == ("oracle", "203.0.113.9", "failed_login")
    r = parse_log_line(SYSLOG_LINES[3], current_year=2026)
    assert (r["user"], r["ip"], r["status"]) == ("admin", "198.51.100.23", "invalid_user")
    assert r["auth_result"] == "failed"
    empty_user = "Aug 28 03:14:07 h sshd[1]: Failed password for invalid user  from 1.2.3.4 port 22 ssh2"
    r = parse_log_line(empty_user, current_year=2026)
    assert r["user"] == "" and r["ip"] == "1.2.3.4"


def test_accepted_login_and_single_digit_day():
    r = parse_log_line(SYSLOG_LINES[2], current_year=2026)
    assert r["status"] == "accepted_login" and r["auth_result"] == "accepted"
    assert r["user"] == "deploy" and r["timestamp"].day == 2
    assert r["severity"] == "INFO"


def test_firewall_line_extracts_source_ip():
    r = parse_log_line(SYSLOG_LINES[6], current_year=2026)
    assert r["status"] == "firewall_drop" and r["ip"] == "185.220.101.7" and r["port"] == 22
    assert parse_log_line(SYSLOG_LINES[6], current_year=2026, firewall=False)["ip"] is None


def test_pri_prefix_is_handled():
    r = parse_log_line("<38>" + SYSLOG_LINES[0], current_year=2026)
    assert r["pri"] == 38 and r["ip"] == "10.0.0.5" and r["raw"].startswith("<38>")


def test_rfc3339_syslog_timestamp():
    line = "2026-08-28T03:14:07.123456+02:00 web01 sshd[9]: Accepted password for bob from 10.0.0.7 port 2222 ssh2"
    r = parse_log_line(line)
    assert r["timestamp"] == datetime(2026, 8, 28, 1, 14, 7, 123456)
    assert r["year_inferred"] is False and r["user"] == "bob"


def test_access_log_fields_and_timezone():
    r = parse_log_line(ACCESS_LINES[1])
    assert r["format"] == "access_log" and r["process"] == "http" and r["host"] is None
    assert (r["status"], r["status_code"], r["auth_result"]) == ("401", 401, "failed")
    assert r["severity"] == "WARNING" and r["size"] == 210
    r = parse_log_line(ACCESS_LINES[2])
    assert r["timestamp"] == datetime(2026, 8, 28, 3, 0, 0)   # +0200 normalised to UTC
    assert r["user"] == "alice" and r["size"] is None and r["status_code"] == 304
    assert parse_log_line(ACCESS_LINES[4])["severity"] == "ERROR"
    assert parse_log_line(ACCESS_LINES[3])["ip"] == "2001:db8::1"


def test_missing_year_rolls_back_when_date_is_in_the_future():
    now = datetime(2027, 1, 1, 0, 30)
    r = parse_log_line("Dec 31 23:59:00 h sshd[1]: Accepted password for a from 1.1.1.1 port 1 ssh2", now=now)
    assert r["timestamp"].year == 2026
    r = parse_log_line("Jan  1 00:10:00 h sshd[1]: Accepted password for a from 1.1.1.1 port 1 ssh2", now=now)
    assert r["timestamp"].year == 2027


def test_feb_29_without_leap_year_does_not_crash():
    r = parse_log_line("Feb 29 10:00:00 h app[1]: started", current_year=2027)
    assert r is not None and r["timestamp"].year == 2024


def test_year_tracker_handles_new_year_rollover():
    yt = YearTracker(2026)
    a = yt.parse("Dec 31 23:59:58 h app[1]: tick")
    b = yt.parse("Jan  1 00:00:03 h app[1]: tock")
    assert a["timestamp"].year == 2026 and b["timestamp"].year == 2027
    assert b["timestamp"] > a["timestamp"]


def test_guess_severity_priority():
    assert _guess_severity("FATAL: password authentication failed") == "CRITICAL"
    assert _guess_severity("connection timeout, will retry") == "WARNING"
    assert _guess_severity("nothing interesting") == "INFO"


def test_parsing_100k_lines_is_fast():
    pool = SYSLOG_LINES + ACCESS_LINES + MALFORMED_LINES[:4]
    lines = list(itertools.islice(itertools.cycle(pool), 100_000))
    start = time.perf_counter()
    parsed = sum(parse_log_line(line, current_year=2026) is not None for line in lines)
    elapsed = time.perf_counter() - start
    assert parsed == 100_000 * 12 // 16
    assert elapsed < 10, f"parsing 100k lines took {elapsed:.1f}s"
