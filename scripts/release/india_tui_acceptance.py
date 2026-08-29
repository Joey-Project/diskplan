#!/usr/bin/env python3
"""Drive the installed TUI through a bounded PTY acceptance scenario."""

from __future__ import annotations

import argparse
import fcntl
import os
import pty
import select
import struct
import subprocess
import sys
import termios
import time
from pathlib import Path
from typing import Optional, Sequence


MAX_TRANSCRIPT_BYTES = 1024 * 1024
SCENARIO_SECONDS = 30.0


def parse_args(arguments: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frontend", type=Path, required=True)
    return parser.parse_args(arguments)


def read_available(master: int, transcript: bytearray) -> bool:
    try:
        chunk = os.read(master, 16 * 1024)
    except OSError:
        return False
    if not chunk:
        return False
    if len(transcript) + len(chunk) > MAX_TRANSCRIPT_BYTES:
        raise RuntimeError("TUI transcript exceeded its byte limit")
    transcript.extend(chunk)
    return True


def main(arguments: Optional[Sequence[str]] = None) -> int:
    args = parse_args(arguments)
    if (
        not args.frontend.is_absolute()
        or not args.frontend.is_file()
        or not os.access(args.frontend, os.X_OK)
    ):
        print("TUI frontend is unavailable", file=sys.stderr)
        return 69

    master, slave = pty.openpty()
    fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", 24, 80, 0, 0))
    process = subprocess.Popen(
        [str(args.frontend)],
        stdin=slave,
        stdout=slave,
        stderr=slave,
        close_fds=True,
    )
    os.close(slave)
    transcript = bytearray()
    actions = [
        (1.0, b"?"),
        (1.3, b"?"),
        (1.6, b" "),
        (2.0, b"p"),
        (2.5, b"r"),
        (3.0, b"q"),
    ]
    started = time.monotonic()
    action_index = 0
    try:
        while True:
            elapsed = time.monotonic() - started
            if elapsed >= SCENARIO_SECONDS:
                raise RuntimeError("TUI acceptance scenario timed out")
            while action_index < len(actions) and elapsed >= actions[action_index][0]:
                os.write(master, actions[action_index][1])
                action_index += 1
            readable, _, _ = select.select([master], [], [], 0.05)
            if readable:
                read_available(master, transcript)
            if process.poll() is not None:
                while read_available(master, transcript):
                    pass
                break
        if process.returncode != 0:
            return process.returncode
        required = (
            b"Hotkeys",
            b"Pause acknowledged",
            b"provisional",
            b"partial plan finalized",
            b"Resume acknow",
            b"scan can",
            b"\x1b[?1049h",
            b"\x1b[?1049l",
        )
        if any(marker not in transcript for marker in required):
            print("integrated TUI transcript is incomplete", file=sys.stderr)
            return 69
        os.write(sys.stdout.fileno(), transcript)
        print("TUI PTY control/restore smoke test passed")
        return 0
    finally:
        os.close(master)
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=1)
            except subprocess.TimeoutExpired:
                process.kill()
                process.wait(timeout=2)


if __name__ == "__main__":
    raise SystemExit(main())
