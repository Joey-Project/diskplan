#!/usr/bin/env python3
"""Run one diagnostic command with strict output and wall-clock bounds."""

from __future__ import annotations

import argparse
import os
import selectors
import signal
import subprocess
import sys
import time
from typing import Optional, Sequence


READ_CHUNK_BYTES = 4096
TERMINATE_GRACE_SECONDS = 0.05
REAP_TIMEOUT_SECONDS = 0.5


def parse_args(arguments: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--max-bytes", type=int, required=True)
    parser.add_argument("--probe-max-bytes", type=int)
    parser.add_argument("--timeout-seconds", type=float, required=True)
    parser.add_argument("--manifest", choices=("none", "huge", "hang"))
    parser.add_argument("command", nargs=argparse.REMAINDER)
    parsed = parser.parse_args(arguments)
    if parsed.command[:1] == ["--"]:
        parsed.command = parsed.command[1:]
    if not 1 <= parsed.max_bytes <= 65536:
        parser.error("--max-bytes must be from 1 through 65536")
    if not 0.05 <= parsed.timeout_seconds <= 30:
        parser.error("--timeout-seconds must be from 0.05 through 30")
    if parsed.probe_max_bytes is not None and not 1 <= parsed.probe_max_bytes <= 65536:
        parser.error("--probe-max-bytes must be from 1 through 65536")
    if parsed.manifest is not None and parsed.probe_max_bytes is None:
        parser.error("--probe-max-bytes is required with --manifest")
    if parsed.manifest is not None and parsed.command:
        parser.error("a manifest cannot also run a command")
    if parsed.manifest is None and not parsed.command:
        parser.error("a command is required after --")
    return parsed


def terminate_process_group(process: subprocess.Popen[bytes]) -> None:
    """Terminate the owned process group while its leader is still unreaped."""

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except OSError:
        try:
            process.terminate()
        except OSError:
            pass
    time.sleep(TERMINATE_GRACE_SECONDS)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except OSError:
        try:
            process.kill()
        except OSError:
            pass
    try:
        process.wait(timeout=REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("probe process did not terminate after SIGKILL") from error


def bounded_result(payload: bytes, marker: Optional[bytes], limit: int) -> bytes:
    if marker is None:
        return payload[:limit]
    separator = b"" if not payload or payload.endswith(b"\n") else b"\n"
    suffix = separator + marker + b"\n"
    if len(suffix) >= limit:
        return suffix[:limit]
    return payload[: limit - len(suffix)] + suffix


def run_bounded(command: Sequence[str], limit: int, timeout: float) -> bytes:
    try:
        process = subprocess.Popen(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )
    except OSError as error:
        marker = f"[probe unavailable: {type(error).__name__}]".encode("ascii")
        return bounded_result(b"", marker, limit)

    assert process.stdout is not None
    output = bytearray()
    marker: Optional[bytes] = None
    deadline = time.monotonic() + timeout
    selector: Optional[selectors.BaseSelector] = None
    try:
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining_time = deadline - time.monotonic()
            if remaining_time <= 0:
                marker = b"[probe timed out]"
                terminate_process_group(process)
                break
            events = selector.select(remaining_time)
            if not events:
                marker = b"[probe timed out]"
                terminate_process_group(process)
                break
            chunk = os.read(
                process.stdout.fileno(),
                min(READ_CHUNK_BYTES, limit + 1 - len(output)),
            )
            if not chunk:
                try:
                    process.wait(timeout=max(0.05, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    marker = b"[probe timed out]"
                    terminate_process_group(process)
                break
            output.extend(chunk)
            if len(output) > limit:
                marker = b"[probe output truncated]"
                terminate_process_group(process)
                break
    except BaseException:
        terminate_process_group(process)
        raise
    finally:
        if selector is not None:
            selector.close()
        process.stdout.close()

    return bounded_result(bytes(output), marker, limit)


def build_manifest(
    test_mode: str,
    total_limit: int,
    probe_limit: int,
    timeout: float,
) -> bytes:
    manifest = bytearray()

    def append_bytes(value: bytes) -> None:
        remaining = total_limit - len(manifest)
        if remaining > 0:
            manifest.extend(value[:remaining])

    def append_line(value: str) -> None:
        encoded = value.encode("utf-8", errors="backslashreplace") + b"\n"
        if len(encoded) <= total_limit - len(manifest):
            append_bytes(encoded)
            return
        marker = b"[diagnostic value omitted: byte budget exhausted]\n"
        if len(marker) <= total_limit - len(manifest):
            append_bytes(marker)

    append_line("diskplan foundation CI diagnostics")
    append_line(f"runner_os={os.environ.get('RUNNER_OS', 'unavailable')}")
    append_line(f"runner_arch={os.environ.get('RUNNER_ARCH', 'unavailable')}")
    append_line(f"image_os={os.environ.get('ImageOS', 'unavailable')}")
    append_line(f"image_version={os.environ.get('ImageVersion', 'unavailable')}")

    probes = (
        ("commit", ("git", "rev-parse", "HEAD")),
        ("kernel", ("uname", "-mrs")),
        ("macos", ("sw_vers", "-productVersion")),
        ("xcode", ("xcodebuild", "-version")),
        ("swift", ("swift", "--version")),
        ("rustc", ("rustc", "--version")),
        ("cargo", ("cargo", "--version")),
        ("protoc", ("protoc", "--version")),
        ("protoc-gen-swift", ("protoc-gen-swift", "--version")),
    )
    for label, default_command in probes:
        append_line(f"{label}:")
        remaining = total_limit - len(manifest)
        if remaining <= 0:
            break
        command = default_command
        if label == "xcode" and test_mode == "huge":
            command = (
                sys.executable,
                "-c",
                'import os; os.write(1, b"x" * 1048576)',
            )
        elif label == "xcode" and test_mode == "hang":
            command = (sys.executable, "-c", "import time; time.sleep(60)")
        append_bytes(run_bounded(command, min(probe_limit, remaining), timeout))
        append_line("")

    return bytes(manifest)


def main(arguments: Optional[Sequence[str]] = None) -> int:
    parsed = parse_args(arguments)
    if parsed.manifest is not None:
        result = build_manifest(
            parsed.manifest,
            parsed.max_bytes,
            parsed.probe_max_bytes,
            parsed.timeout_seconds,
        )
    else:
        result = run_bounded(
            parsed.command,
            parsed.max_bytes,
            parsed.timeout_seconds,
        )
    sys.stdout.buffer.write(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
