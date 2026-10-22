"""
log_source.py

Gets log lines into the pipeline one at a time, without ever loading a
whole file into memory. Every function here is a generator, so the
memory cost is "one line plus a small read buffer" no matter how large
(or infinite) the input is.

Three ways to get lines in:
  1. stream_from_file(path)       read a file once, line by line
  2. tail_file(path)              like `tail -F`: follow a file forever,
                                  surviving log rotation and truncation
  3. stream_from_generator(gen)   pass-through for any iterator (synthetic
                                  data, sockets, SSH channels, ...)

Bounded line length: a "line" with no newline for gigabytes would make a
naive reader buffer all of it. We read with readline(limit) and truncate
over-long lines to MAX_LINE_BYTES, discarding the rest up to the next
newline, so even hostile input cannot blow up memory.
"""

import os
import time

# Lines longer than this are truncated (the remainder up to the next
# newline is skipped). 64 KiB is far above any sane log line.
MAX_LINE_BYTES = 64 * 1024


def _decode(raw):
    """bytes -> str, never raising on invalid UTF-8."""
    return raw.decode("utf-8", errors="replace").strip()


def _bounded_lines(f, max_line_bytes=MAX_LINE_BYTES):
    """
    Yield raw byte lines from a binary file object, each at most
    `max_line_bytes` long. An over-long line yields its first
    `max_line_bytes` bytes once; the rest of it is read and dropped in
    fixed-size chunks so it never sits in memory.
    """
    while True:
        chunk = f.readline(max_line_bytes)
        if not chunk:
            return
        if chunk.endswith(b"\n") or len(chunk) < max_line_bytes:
            yield chunk
            continue
        # Over-long line: keep the head, skip to the next newline.
        yield chunk
        while True:
            rest = f.readline(max_line_bytes)
            if not rest or rest.endswith(b"\n"):
                break


def stream_from_file(path, max_line_bytes=MAX_LINE_BYTES):
    """
    Yield stripped, non-empty lines from a file, one at a time.

    Decodes as UTF-8 with errors="replace", so binary junk becomes U+FFFD
    instead of raising UnicodeDecodeError halfway through a 500 MB file.
    Never calls .readlines() or .read().
    """
    with open(path, "rb") as f:
        for raw in _bounded_lines(f, max_line_bytes):
            line = _decode(raw)
            if line:
                yield line


def _file_id(st):
    return (st.st_dev, st.st_ino)


def tail_file(path, poll_interval=0.5, from_end=True, stop_event=None,
              max_line_bytes=MAX_LINE_BYTES):
    """
    Follow a file like `tail -F`, yielding complete lines as they are
    appended. Runs until the caller stops iterating or `stop_event`
    (a threading.Event) is set.

    Rotation handling:
      * inode/device changed (logrotate moved the file and created a new
        one): finish the old handle, then re-open the new file from the
        start.
      * file shrank below our read position (copytruncate / `> file`):
        seek back to the start.
      * file missing (between rotate and re-create): keep polling.

    Partial lines (a writer flushed half a line) are held back until the
    newline arrives, so consumers never see half a record. The pending
    buffer is capped at `max_line_bytes`.
    """
    f = None
    current_id = None
    pending = b""
    skipping = False  # inside the tail end of an over-long line

    def stopped():
        return stop_event is not None and stop_event.is_set()

    def open_file(seek_end):
        nonlocal f, current_id
        try:
            nf = open(path, "rb")
        except FileNotFoundError:
            return False
        if f is not None:
            f.close()
        f = nf
        current_id = _file_id(os.fstat(f.fileno()))
        if seek_end:
            f.seek(0, os.SEEK_END)
        return True

    try:
        # Wait for the file to exist at all.
        while not open_file(seek_end=from_end):
            if stopped():
                return
            time.sleep(poll_interval)

        while not stopped():
            chunk = f.readline(max_line_bytes)
            if chunk:
                if skipping:
                    skipping = not chunk.endswith(b"\n")
                    continue
                pending += chunk
                if pending.endswith(b"\n"):
                    line = _decode(pending)
                    pending = b""
                    if line:
                        yield line
                elif len(pending) >= max_line_bytes:
                    line = _decode(pending[:max_line_bytes])
                    pending = b""
                    skipping = True
                    if line:
                        yield line
                continue

            # EOF on the current handle: check for rotation / truncation.
            try:
                st = os.stat(path)
            except FileNotFoundError:
                time.sleep(poll_interval)
                continue

            if _file_id(st) != current_id:
                # Rotated. Anything left in the old handle was already
                # read (we are at EOF), so switch to the new file from 0.
                if pending and not skipping:
                    line = _decode(pending)
                    if line:
                        yield line
                pending, skipping = b"", False
                open_file(seek_end=False)
                continue

            if st.st_size < f.tell():
                # Truncated in place.
                pending, skipping = b"", False
                f.seek(0)
                continue

            time.sleep(poll_interval)
    finally:
        if f is not None:
            f.close()


def stream_from_generator(gen):
    """
    Pass-through wrapper for any iterator of lines (or (line, label)
    tuples). Exists so every source exposes the same generator interface
    to the engine.
    """
    yield from gen
