import queue
import shutil
import socket
import threading
import time

import pytest

from engine import StreamingEngine
from remote_sources import SSHConfigError, ssh_tail, strip_pri, syslog_udp_listener
from ssh_test_server import FakeSSHServer
from synthetic_logs import calibrated_stream


def _run_in_thread(gen, out):
    def run():
        try:
            for item in gen:
                out.put(item)
        except Exception as exc:  # surface errors to the test
            out.put(exc)
    t = threading.Thread(target=run, daemon=True)
    t.start()
    return t


def _take(out, n, timeout=10.0):
    got = []
    deadline = time.monotonic() + timeout
    while len(got) < n and time.monotonic() < deadline:
        try:
            item = out.get(timeout=0.1)
        except queue.Empty:
            continue
        if isinstance(item, Exception):
            raise item
        got.append(item)
    return got


def test_strip_pri():
    assert strip_pri("<38>Aug 28 03:14:07 h sshd[1]: x") == "Aug 28 03:14:07 h sshd[1]: x"
    assert strip_pri("no pri here") == "no pri here"
    assert strip_pri("<999> too long?") == " too long?"


# ---- UDP ---------------------------------------------------------------------
def _udp_listener(**kwargs):
    ready, stop, counters, out = threading.Event(), threading.Event(), {}, queue.Queue()
    gen = syslog_udp_listener(port=0, stop_event=stop, counters=counters, ready_event=ready, **kwargs)
    thread = _run_in_thread(gen, out)
    assert ready.wait(5)
    return stop, counters, out, thread


def test_udp_defaults_to_localhost_and_strips_pri():
    stop, counters, out, thread = _udp_listener()
    host, port = counters["bound"]
    assert host == "127.0.0.1"
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.sendto(b"<38>Aug 28 03:14:07 web01 sshd[1]: Failed password for root from 1.2.3.4 port 22 ssh2",
                  (host, port))
    sender.sendto(b"<13>first\n<13>second\n", (host, port))   # several messages in one datagram
    got = _take(out, 3)
    assert got[0].startswith("Aug 28 03:14:07 web01 sshd[1]")
    assert got[1:] == ["first", "second"]
    assert counters["received"] == 2 and counters["dropped"] == 0
    stop.set()
    thread.join(3)
    assert not thread.is_alive()


def test_udp_drops_when_consumer_is_slow():
    ready, counters = threading.Event(), {}
    gen = syslog_udp_listener(port=0, queue_size=5, counters=counters, ready_event=ready, max_lines=1)
    first = []
    t = threading.Thread(target=lambda: first.append(next(gen)), daemon=True)
    t.start()
    assert ready.wait(5)
    host, port = counters["bound"]
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.sendto(b"line 0", (host, port))
    t.join(5)
    # The consumer is now paused at its first yield; flood the bounded queue.
    for i in range(1, 200):
        sender.sendto(f"line {i}".encode(), (host, port))
    deadline = time.monotonic() + 5
    while counters["received"] < 200 and time.monotonic() < deadline:
        time.sleep(0.05)
    assert first == ["line 0"]
    assert counters["dropped"] > 0
    assert counters["received"] - counters["dropped"] <= 5 + 1
    gen.close()


def test_udp_feeds_the_engine_end_to_end():
    stop, counters, out, thread = _udp_listener()
    host, port = counters["bound"]
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    lines = [line for line, _ in calibrated_stream(baseline_n=100, n=150, anomaly_rate=0.05, seed=5)]
    for line in lines:
        sender.sendto(f"<38>{line}".encode(), (host, port))
        time.sleep(0.0005)
    received = _take(out, len(lines))
    stop.set()
    events = list(StreamingEngine(iter(received), baseline_size=100).run())
    assert len(events) == len(lines)
    assert any(e["phase"] == "live" for e in events)


# ---- SSH ---------------------------------------------------------------------
needs_tail = pytest.mark.skipif(shutil.which("tail") is None, reason="needs a tail binary")


@pytest.fixture
def ssh_server():
    server = FakeSSHServer()
    yield server
    server.close()


@needs_tail
def test_ssh_rejects_unknown_host_key(ssh_server, tmp_path):
    gen = ssh_tail("127.0.0.1", "tester", str(tmp_path / "x.log"), password="secret",
                   port=ssh_server.port, max_retries=0)
    with pytest.raises(SSHConfigError, match="known_hosts"):
        next(gen)


@needs_tail
def test_ssh_bad_password_is_not_retried(ssh_server, tmp_path):
    kh = ssh_server.write_known_hosts(tmp_path / "known_hosts")
    gen = ssh_tail("127.0.0.1", "tester", str(tmp_path / "x.log"), password="wrong",
                   port=ssh_server.port, known_hosts=kh)
    with pytest.raises(SSHConfigError, match="authentication"):
        next(gen)


@needs_tail
def test_ssh_tail_streams_quoted_path_and_reconnects(ssh_server, tmp_path):
    log = tmp_path / "dir with spaces; and $chars" / "auth.log"
    log.parent.mkdir()
    log.write_text("", encoding="utf-8")
    kh = ssh_server.write_known_hosts(tmp_path / "known_hosts")
    stop, out, counters = threading.Event(), queue.Queue(), {}
    gen = ssh_tail("127.0.0.1", "tester", str(log), password="secret", port=ssh_server.port,
                   known_hosts=kh, backoff_base=0.1, stop_event=stop, counters=counters)
    thread = _run_in_thread(gen, out)

    def wait_for(cond, timeout=10):
        deadline = time.monotonic() + timeout
        while not cond() and time.monotonic() < deadline:
            time.sleep(0.05)
        assert cond()

    wait_for(lambda: ssh_server.connections >= 1)
    time.sleep(0.5)  # remote tail starts at the end of the file
    with open(log, "a", encoding="utf-8") as f:
        f.write("Aug 28 03:14:07 web01 sshd[1]: first line\nsecond line\n")
    assert _take(out, 2) == ["Aug 28 03:14:07 web01 sshd[1]: first line", "second line"]
    assert ssh_server.commands[0].endswith("'" + str(log) + "'")

    ssh_server.drop_connections()
    wait_for(lambda: ssh_server.connections >= 2)
    time.sleep(0.5)
    with open(log, "a", encoding="utf-8") as f:
        f.write("after reconnect\n")
    assert _take(out, 1) == ["after reconnect"]
    assert counters["reconnects"] >= 1

    stop.set()
    thread.join(5)
    assert not thread.is_alive()


@needs_tail
def test_ssh_insecure_flag_warns_and_connects(ssh_server, tmp_path):
    log = tmp_path / "a.log"
    log.write_text("existing line\n", encoding="utf-8")
    with pytest.warns(RuntimeWarning, match="unknown host keys"):
        gen = ssh_tail("127.0.0.1", "tester", str(log), password="secret", port=ssh_server.port,
                       insecure=True, from_end=False, max_retries=0)
        assert next(gen) == "existing line"
    gen.close()


def test_ssh_gives_up_after_max_retries(tmp_path):
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()  # nothing listens here: connection refused
    gen = ssh_tail("127.0.0.1", "x", "/var/log/x", password="p", port=port,
                   max_retries=2, backoff_base=0.01)
    with pytest.raises(ConnectionError, match="gave up after 2"):
        next(gen)
