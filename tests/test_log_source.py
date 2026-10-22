import os
import queue
import threading
import time

from log_source import stream_from_file, stream_from_generator, tail_file


def _consume(gen, out, stop):
    try:
        for line in gen:
            out.put(line)
    finally:
        stop.set()


def _start_tail(path, **kwargs):
    stop = threading.Event()
    out = queue.Queue()
    gen = tail_file(str(path), poll_interval=0.05, stop_event=stop, **kwargs)
    done = threading.Event()
    thread = threading.Thread(target=_consume, args=(gen, out, done), daemon=True)
    thread.start()
    return stop, out, thread


def _collect(out, n, timeout=5.0):
    got = []
    deadline = time.monotonic() + timeout
    while len(got) < n and time.monotonic() < deadline:
        try:
            got.append(out.get(timeout=0.1))
        except queue.Empty:
            pass
    return got


def test_empty_lines_skipped(tmp_path):
    p = tmp_path / "a.log"
    p.write_text("first\n\n   \nsecond\n\n\nthird", encoding="utf-8")
    assert list(stream_from_file(p)) == ["first", "second", "third"]


def test_invalid_bytes_do_not_crash(tmp_path):
    p = tmp_path / "bin.log"
    p.write_bytes(b"ok line\n\xff\xfe\x00garbage\x80\nlast \xe2\x82 line\n")
    lines = list(stream_from_file(p))
    assert lines[0] == "ok line"
    assert len(lines) == 3
    assert "�" in lines[1] and "�" in lines[2]


def test_stream_from_file_is_lazy(tmp_path):
    p = tmp_path / "big.log"
    p.write_text("".join(f"line {i}\n" for i in range(10_000)), encoding="utf-8")
    gen = stream_from_file(p)
    assert next(gen) == "line 0"
    assert next(gen) == "line 1"
    gen.close()


def test_overlong_line_is_truncated_not_buffered(tmp_path):
    p = tmp_path / "long.log"
    p.write_bytes(b"short\n" + b"A" * 300_000 + b"\nafter\n")
    lines = list(stream_from_file(p, max_line_bytes=1024))
    assert lines[0] == "short"
    assert lines[1] == "A" * 1024
    assert lines[2] == "after"
    assert len(lines) == 3


def test_stream_from_generator_passthrough():
    items = ["a", ("b", {"anomalous": False})]
    assert list(stream_from_generator(iter(items))) == items


def test_tail_yields_appended_lines_only(tmp_path):
    p = tmp_path / "live.log"
    p.write_text("old line that must not appear\n", encoding="utf-8")
    stop, out, thread = _start_tail(p)
    time.sleep(0.3)  # let tail open the file and seek to the end
    with open(p, "a", encoding="utf-8") as f:
        f.write("new 1\nnew 2\n")
    assert _collect(out, 2) == ["new 1", "new 2"]
    stop.set()
    thread.join(2)
    assert not thread.is_alive()


def test_tail_holds_partial_lines(tmp_path):
    p = tmp_path / "partial.log"
    p.write_text("", encoding="utf-8")
    stop, out, thread = _start_tail(p)
    time.sleep(0.3)
    with open(p, "a", encoding="utf-8") as f:
        f.write("half a li")
        f.flush()
        time.sleep(0.3)
        f.write("ne\n")
    assert _collect(out, 1) == ["half a line"]
    stop.set()
    thread.join(2)


def test_tail_survives_rotation(tmp_path):
    p = tmp_path / "rot.log"
    p.write_text("", encoding="utf-8")
    stop, out, thread = _start_tail(p)
    time.sleep(0.3)
    with open(p, "a", encoding="utf-8") as f:
        f.write("before rotate\n")
    assert _collect(out, 1) == ["before rotate"]

    os.rename(p, tmp_path / "rot.log.1")          # logrotate moves the file...
    time.sleep(0.2)
    p.write_text("after rotate 1\n", encoding="utf-8")  # ...and creates a new one
    with open(p, "a", encoding="utf-8") as f:
        f.write("after rotate 2\n")
    assert _collect(out, 2) == ["after rotate 1", "after rotate 2"]
    stop.set()
    thread.join(2)


def test_tail_survives_truncation(tmp_path):
    p = tmp_path / "trunc.log"
    p.write_text("", encoding="utf-8")
    stop, out, thread = _start_tail(p)
    time.sleep(0.3)
    with open(p, "a", encoding="utf-8") as f:
        f.write("a fairly long line before truncation\n")
    assert _collect(out, 1) == ["a fairly long line before truncation"]
    with open(p, "w", encoding="utf-8") as f:   # copytruncate / `> file`
        f.write("x\n")
    assert _collect(out, 1) == ["x"]
    stop.set()
    thread.join(2)


def test_tail_waits_for_missing_file(tmp_path):
    p = tmp_path / "later.log"
    stop, out, thread = _start_tail(p, from_end=False)
    time.sleep(0.2)
    p.write_text("created later\n", encoding="utf-8")
    assert _collect(out, 1) == ["created later"]
    stop.set()
    thread.join(2)
