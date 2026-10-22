"""
log_parser.py

Turns raw log lines into structured records with regex. Never raises on
garbage: anything that does not match a known format returns None, and
the caller decides what to do with it (the engine flags it as an
"unparseable" anomaly).

Supported formats
  * syslog / auth.log, classic BSD timestamp (no year):
        Aug 28 03:14:07 web01 sshd[1234]: Failed password for root from 10.0.0.5 port 51514 ssh2
    optionally preceded by an RFC 3164 <PRI> prefix, which real syslog
    senders put on the wire:
        <38>Aug 28 03:14:07 web01 sshd[1234]: ...
  * syslog with an RFC 3339 timestamp (modern rsyslog / Ubuntu 24.04):
        2026-08-28T03:14:07.123456+00:00 web01 sshd[1234]: ...
  * Apache / Nginx access log, common or combined:
        203.0.113.9 - - [28/Aug/2026:03:14:07 +0000] "POST /login HTTP/1.1" 401 512 "-" "curl/8.0"

Every record has exactly the keys in RECORD_KEYS, whatever the format, so
downstream code can index record["ip"] without .get() guesswork.

Severity: _guess_severity() is a keyword heuristic. It is used only as
the *seed label* the KNN severity classifier learns from; it is not the
classifier itself.
"""

import re
from datetime import datetime, timedelta, timezone

# Anything longer is treated as unparseable rather than run through the
# regexes: keeps worst-case parse time bounded on hostile input.
MAX_LINE_LENGTH = 16 * 1024

RECORD_KEYS = (
    "raw",            # original line
    "format",         # "syslog" | "access_log"
    "timestamp",      # naive datetime (syslog: local time; access log: UTC) or None
    "year_inferred",  # True if the year was guessed (BSD syslog has none)
    "pri",            # RFC 3164 PRI value (int) or None
    "host",           # syslog host, None for access logs
    "process",        # syslog program name, "http" for access logs
    "pid",            # int or None
    "message",        # free text (access log: "METHOD path -> status")
    "ip",             # client / source IP if present
    "user",           # user name if present
    "port",           # source port (SSH) or destination port (firewall)
    "status",         # "failed_login" | "accepted_login" | "invalid_user" |
                      # "firewall_drop" | HTTP status as str | None
    "status_code",    # HTTP status as int, None for syslog
    "auth_result",    # "failed" | "accepted" | None, for both formats
    "method",         # HTTP method or None
    "path",           # HTTP path or None
    "size",           # HTTP response bytes (int) or None
    "severity",       # seed label: CRITICAL | ERROR | WARNING | INFO
)

MONTHS = {m: i for i, m in enumerate(
    ("Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"), start=1)}

# --- line formats ---------------------------------------------------------
_PRI = r"(?:<(?P<pri>\d{1,3})>)?"
_TAIL = (r"(?P<host>\S+)\s+(?P<process>[^\s\[:]+)(?:\[(?P<pid>\d+)\])?:"
         r"(?:\s+(?P<message>.*))?$")

SYSLOG_RE = re.compile(
    r"^" + _PRI +
    r"(?P<month>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})\s+" + _TAIL
)

SYSLOG_ISO_RE = re.compile(
    r"^" + _PRI +
    r"(?P<iso>\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}(?:\.\d{1,6})?(?:Z|[+-]\d{2}:\d{2})?)\s+"
    + _TAIL
)

ACCESS_LOG_RE = re.compile(
    r'^(?P<ip>[0-9A-Fa-f:.]+) (?P<ident>\S+) (?P<authuser>\S+) '
    r'\[(?P<day>\d{2})/(?P<month>[A-Z][a-z]{2})/(?P<year>\d{4}):'
    r'(?P<hh>\d{2}):(?P<mm>\d{2}):(?P<ss>\d{2})(?: (?P<tz>[+-]\d{4}))?\] '
    r'"(?P<method>[A-Z]{3,10}) (?P<path>\S+)(?: (?P<protocol>HTTP/\d(?:\.\d)?))?" '
    r'(?P<status>\d{3}) (?P<size>\d+|-)'
    r'(?: "(?P<referrer>[^"]*)" "(?P<agent>[^"]*)")?\s*$'
)

# --- message sub-patterns (auth.log, firewall) ----------------------------
_IP = r"(?P<ip>[0-9A-Fa-f:.]+)"
FAILED_LOGIN_RE = re.compile(
    r"Failed (?:password|publickey|keyboard-interactive/pam|none) for "
    r"(?P<invalid>invalid user )?(?P<user>\S*) from " + _IP + r" port (?P<port>\d+)"
)
ACCEPTED_LOGIN_RE = re.compile(
    r"Accepted (?:password|publickey|keyboard-interactive/pam|gssapi-with-mic) for "
    r"(?P<user>\S+) from " + _IP + r" port (?P<port>\d+)"
)
INVALID_USER_RE = re.compile(
    r"^Invalid user (?P<user>\S*) from " + _IP + r"(?: port (?P<port>\d+))?"
)
PAM_FAILURE_RE = re.compile(
    r"authentication failure;.*?\brhost=(?P<ip>[0-9A-Fa-f:.]+)(?:\s+user=(?P<user>\S+))?"
)
FIREWALL_RE = re.compile(r"\bSRC=" + _IP + r"\b(?:.*?\bDPT=(?P<port>\d+))?")

LOGIN_PATH_RE = re.compile(r"login|signin|auth|wp-login|session", re.IGNORECASE)

SEVERITY_KEYWORDS = {
    "CRITICAL": ["critical", "fatal", "panic", "emergency"],
    "ERROR": ["error", "failed", "failure", "denied", "invalid"],
    "WARNING": ["warn", "warning", "retry", "timeout"],
    "INFO": ["accepted", "success", "started", "connected", "info"],
}
SEVERITY_LEVELS = tuple(SEVERITY_KEYWORDS)  # most to least severe


def _guess_severity(message):
    """Keyword heuristic used only as the seed label for the KNN
    classifier. First matching level wins, most severe first."""
    msg_lower = message.lower()
    for severity, keywords in SEVERITY_KEYWORDS.items():
        if any(kw in msg_lower for kw in keywords):
            return severity
    return "INFO"


def _http_severity(code):
    if code >= 500:
        return "ERROR"
    if code >= 400:
        return "WARNING"
    return "INFO"


def _make_date(year, month, day, hh, mm, ss):
    """datetime or None. Feb 29 in a non-leap year falls back to the most
    recent leap year (that is the only date a year can make invalid)."""
    try:
        return datetime(year, month, day, hh, mm, ss)
    except ValueError:
        if month == 2 and day == 29:
            for back in range(1, 8):
                try:
                    return datetime(year - back, month, day, hh, mm, ss)
                except ValueError:
                    continue
        return None


def _new_record(line, fmt):
    record = dict.fromkeys(RECORD_KEYS)
    record["raw"] = line
    record["format"] = fmt
    record["year_inferred"] = False
    return record


def _apply_auth_fields(record, message, firewall=True):
    """Fill ip/user/port/status/auth_result from an auth.log message."""
    m = FAILED_LOGIN_RE.search(message)
    if m:
        record.update(ip=m["ip"], user=m["user"], port=int(m["port"]),
                      status="failed_login", auth_result="failed")
        return
    m = ACCEPTED_LOGIN_RE.search(message)
    if m:
        record.update(ip=m["ip"], user=m["user"], port=int(m["port"]),
                      status="accepted_login", auth_result="accepted")
        return
    m = INVALID_USER_RE.search(message)
    if m:
        record.update(ip=m["ip"], user=m["user"],
                      port=int(m["port"]) if m["port"] else None,
                      status="invalid_user", auth_result="failed")
        return
    m = PAM_FAILURE_RE.search(message)
    if m:
        record.update(ip=m["ip"], user=m["user"], status="failed_login",
                      auth_result="failed")
        return
    m = FIREWALL_RE.search(message) if firewall else None
    if m:
        record.update(ip=m["ip"], port=int(m["port"]) if m["port"] else None,
                      status="firewall_drop")


def _syslog_record(line, m, timestamp, year_inferred, firewall):
    record = _new_record(line, "syslog")
    message = m["message"] or ""
    record.update(
        timestamp=timestamp,
        year_inferred=year_inferred,
        pri=int(m["pri"]) if m["pri"] else None,
        host=m["host"],
        process=m["process"],
        pid=int(m["pid"]) if m["pid"] else None,
        message=message,
    )
    _apply_auth_fields(record, message, firewall)
    record["severity"] = _guess_severity(message)
    return record


def parse_log_line(line, current_year=None, now=None, firewall=True):
    """
    Parse one line. Returns a dict with exactly RECORD_KEYS, or None.

    BSD syslog timestamps carry no year. If `current_year` is given it is
    used as-is (the caller knows better, e.g. a replayed archive or a
    synthetic stream). Otherwise the year of `now` (default: the wall
    clock) is assumed, and if that puts the date more than one day in the
    future the previous year is used instead: a line stamped "Dec 31"
    read on Jan 1 belongs to last year.

    firewall=False skips reading SRC=/DPT= from iptables/UFW lines; it
    exists only so the "legacy" evaluation reproduces the original parser.
    """
    if not line or len(line) > MAX_LINE_LENGTH:
        return None

    m = SYSLOG_RE.match(line)
    if m:
        month = MONTHS.get(m["month"])
        if month is None:
            return None
        hh, mm, ss = int(m["hh"]), int(m["mm"]), int(m["ss"])
        if hh > 23 or mm > 59 or ss > 60:
            return None
        if current_year is not None:
            ts = _make_date(current_year, month, int(m["day"]), hh, mm, min(ss, 59))
        else:
            ref = now or datetime.now()
            ts = _make_date(ref.year, month, int(m["day"]), hh, mm, min(ss, 59))
            if ts is not None and ts - ref > timedelta(days=1):
                ts = _make_date(ref.year - 1, month, int(m["day"]), hh, mm, min(ss, 59))
        if ts is None:
            return None
        return _syslog_record(line, m, ts, year_inferred=True, firewall=firewall)

    m = SYSLOG_ISO_RE.match(line)
    if m:
        try:
            ts = datetime.fromisoformat(m["iso"].replace("Z", "+00:00"))
        except ValueError:
            return None
        if ts.tzinfo is not None:
            ts = ts.astimezone(timezone.utc).replace(tzinfo=None)
        return _syslog_record(line, m, ts, year_inferred=False, firewall=firewall)

    m = ACCESS_LOG_RE.match(line)
    if m:
        month = MONTHS.get(m["month"])
        if month is None:
            return None
        ts = _make_date(int(m["year"]), month, int(m["day"]),
                        int(m["hh"]), int(m["mm"]), min(int(m["ss"]), 59))
        if ts is None:
            return None
        if m["tz"]:
            sign = 1 if m["tz"][0] == "+" else -1
            offset = timedelta(hours=int(m["tz"][1:3]), minutes=int(m["tz"][3:5]))
            ts = ts - sign * offset  # normalise to UTC

        code = int(m["status"])
        method, path = m["method"], m["path"]
        auth_result = None
        if LOGIN_PATH_RE.search(path):
            if code in (401, 403):
                auth_result = "failed"
            elif method == "POST" and code < 400:
                auth_result = "accepted"

        record = _new_record(line, "access_log")
        record.update(
            timestamp=ts,
            process="http",
            message=f"{method} {path} -> {code}",
            ip=m["ip"],
            user=m["authuser"] if m["authuser"] != "-" else None,
            status=m["status"],
            status_code=code,
            auth_result=auth_result,
            method=method,
            path=path,
            size=int(m["size"]) if m["size"] != "-" else None,
            severity=_http_severity(code),
        )
        return record

    return None


class YearTracker:
    """
    Resolves the missing syslog year for an *ordered* stream whose start
    year is known (a synthetic stream, or an archive you are replaying).

    parse_log_line's wall-clock rule is right for live logs, but wrong
    for replaying last year's file. This tracker starts at `start_year`
    and bumps the year when a timestamp jumps backwards by more than
    ROLLOVER_DAYS (the Dec 31 -> Jan 1 wrap).
    """

    ROLLOVER_DAYS = 180

    def __init__(self, start_year, firewall=True):
        self.year = start_year
        self.firewall = firewall
        self._last = None

    def parse(self, line):
        record = parse_log_line(line, current_year=self.year, firewall=self.firewall)
        if record is None or record["timestamp"] is None:
            return record
        ts = record["timestamp"]
        if record["year_inferred"]:
            if self._last is not None and (self._last - ts).days > self.ROLLOVER_DAYS:
                self.year += 1
                ts = _make_date(self.year, ts.month, ts.day, ts.hour, ts.minute, ts.second)
                record["timestamp"] = ts
        elif ts.year > self.year:
            self.year = ts.year
        self._last = ts
        return record
