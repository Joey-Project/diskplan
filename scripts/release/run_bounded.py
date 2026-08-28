#!/usr/bin/env python3
"""Run one release acceptance command with time and output bounds."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import selectors
import signal
import subprocess
import time
from pathlib import Path


READ_BYTES = 16 * 1024
TERMINATE_GRACE_SECONDS = 1.0


def write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("acceptance output write made no progress")
        offset += written


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout-seconds", type=int, required=True)
    parser.add_argument("--max-output-bytes", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not 1 <= args.timeout_seconds <= 86400:
        parser.error("--timeout-seconds must be from 1 through 86400")
    if not 1 <= args.max_output_bytes <= 1024 * 1024:
        parser.error("--max-output-bytes must be from 1 through 1048576")
    if not args.command:
        parser.error("a command is required after --")
    return args


def terminate_group(process: subprocess.Popen[bytes]) -> None:
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    deadline = time.monotonic() + TERMINATE_GRACE_SECONDS
    while process.poll() is None and time.monotonic() < deadline:
        time.sleep(0.02)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=2)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("acceptance command could not be reaped") from error


def main() -> int:
    args = parse_args()
    if os.name != "posix":
        raise RuntimeError("bounded acceptance commands require POSIX")
    args.output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    process: subprocess.Popen[bytes] | None = None
    retained = hashlib.sha256()
    retained_bytes = 0
    result = "command_failed"
    exit_code: int | None = None
    started = time.monotonic()
    try:
        process = subprocess.Popen(
            args.command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        assert process.stdout is not None
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        deadline = started + args.timeout_seconds
        try:
            while True:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    result = "timed_out"
                    terminate_group(process)
                    exit_code = 124
                    break
                events = selector.select(min(remaining, 0.25))
                if not events:
                    continue
                chunk = os.read(process.stdout.fileno(), READ_BYTES)
                if not chunk:
                    exit_code = process.wait(timeout=max(0.01, remaining))
                    result = "passed" if exit_code == 0 else "command_failed"
                    break
                available = args.max_output_bytes - retained_bytes
                if len(chunk) > available:
                    if available > 0:
                        prefix = chunk[:available]
                        write_all(descriptor, prefix)
                        retained.update(prefix)
                        retained_bytes += len(prefix)
                    result = "output_limit_exceeded"
                    terminate_group(process)
                    exit_code = 125
                    break
                write_all(descriptor, chunk)
                retained.update(chunk)
                retained_bytes += len(chunk)
        finally:
            selector.close()
            process.stdout.close()
    except BaseException:
        if process is not None and process.poll() is None:
            terminate_group(process)
        raise
    finally:
        os.fsync(descriptor)
        os.close(descriptor)

    report = {
        "elapsed_millis": int((time.monotonic() - started) * 1000),
        "exit_code": exit_code,
        "output_bytes": retained_bytes,
        "output_sha256": retained.hexdigest(),
        "result": result,
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return 0 if result == "passed" else (exit_code or 1)


if __name__ == "__main__":
    raise SystemExit(main())
