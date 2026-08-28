#!/usr/bin/env python3
"""Run one diagnostic command with strict output and wall-clock bounds."""

from __future__ import annotations

import argparse
import errno
import os
import select
import selectors
import signal
import subprocess
import sys
import time
from typing import Optional, Sequence


READ_CHUNK_BYTES = 4096
TERMINATE_GRACE_SECONDS = 0.05
REAP_TIMEOUT_SECONDS = 0.5
GROUP_QUIESCENCE_POLL_SECONDS = 0.01


class LeaderExitObserver:
    """Observe direct-child exit without releasing its PID/PGID identity fence."""

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process
        self._kqueue: Optional[select.kqueue] = None
        self._already_exited = False
        if sys.platform == "darwin":
            self._kqueue = select.kqueue()
            event = select.kevent(
                process.pid,
                filter=select.KQ_FILTER_PROC,
                flags=select.KQ_EV_ADD | select.KQ_EV_ONESHOT,
                fflags=select.KQ_NOTE_EXIT,
            )
            try:
                self._kqueue.control([event], 0, 0)
            except OSError as error:
                if error.errno != errno.ESRCH:
                    raise
                # Popen succeeded and this process has not called a reaping API.
                self._already_exited = True
        elif not (
            hasattr(os, "waitid")
            and hasattr(os, "P_PID")
            and hasattr(os, "WEXITED")
            and hasattr(os, "WNOWAIT")
            and hasattr(os, "WNOHANG")
        ):
            raise RuntimeError("non-reaping child-exit observation is unavailable")

    def wait_until(self, deadline: float) -> bool:
        if self._already_exited:
            return True
        if self._kqueue is not None:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            return bool(self._kqueue.control(None, 1, remaining))

        while True:
            result = os.waitid(
                os.P_PID,
                self._process.pid,
                os.WEXITED | os.WNOWAIT | os.WNOHANG,
            )
            if result is not None:
                return True
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(0.01, remaining))

    def close(self) -> None:
        if self._kqueue is not None:
            self._kqueue.close()
            self._kqueue = None


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


def terminate_process_group(
    process: subprocess.Popen[bytes],
    *,
    leader_exited: bool = False,
) -> None:
    """Terminate the owned process group while its leader is still unreaped."""

    term_sent = False
    try:
        os.killpg(process.pid, signal.SIGTERM)
        term_sent = True
    except (ProcessLookupError, PermissionError):
        if not leader_exited:
            try:
                process.terminate()
            except OSError:
                pass
    if term_sent or not leader_exited:
        time.sleep(TERMINATE_GRACE_SECONDS)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except (ProcessLookupError, PermissionError):
        if not leader_exited:
            try:
                process.kill()
            except OSError:
                pass
    cleanup_deadline = time.monotonic() + REAP_TIMEOUT_SECONDS
    wait_for_process_group_quiescence(
        process.pid,
        cleanup_deadline,
    )
    remaining = cleanup_deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("probe process-group cleanup timed out before reap")
    try:
        process.wait(timeout=remaining)
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("probe process did not terminate after SIGKILL") from error


def wait_for_process_group_quiescence(pgid: int, deadline: float) -> None:
    while process_group_has_live_members(pgid, deadline):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("probe process group did not become quiescent")
        time.sleep(min(GROUP_QUIESCENCE_POLL_SECONDS, remaining))


def process_group_has_live_members(pgid: int, deadline: float) -> bool:
    if sys.platform == "darwin":
        try:
            os.killpg(pgid, 0)
            return True
        except (ProcessLookupError, PermissionError):
            # All group members inherit the probe identity. Darwin reports EPERM
            # for the retained zombie leader once no signalable member remains.
            return False
    if sys.platform.startswith("linux"):
        return linux_process_group_has_live_members(pgid, deadline)
    raise RuntimeError("process-group quiescence inspection is unavailable")


def linux_process_group_has_live_members(pgid: int, deadline: float) -> bool:
    try:
        entries = os.scandir("/proc")
    except OSError as error:
        raise RuntimeError("cannot inspect Linux process groups") from error
    with entries:
        for entry in entries:
            if time.monotonic() >= deadline:
                raise RuntimeError("probe process-group inspection timed out")
            if not entry.name.isdigit() or int(entry.name) == pgid:
                continue
            try:
                with open(f"{entry.path}/stat", "rb") as stat_file:
                    stat_data = stat_file.read(4097)
            except FileNotFoundError:
                continue
            except OSError as error:
                raise RuntimeError("cannot inspect Linux process-group member") from error
            if len(stat_data) > 4096:
                raise RuntimeError("Linux process stat exceeded its byte limit")
            command_end = stat_data.rfind(b")")
            fields = stat_data[command_end + 2 :].split() if command_end >= 0 else []
            if len(fields) < 3:
                raise RuntimeError("Linux process stat was malformed")
            try:
                member_group = int(fields[2])
            except ValueError as error:
                raise RuntimeError("Linux process group was malformed") from error
            if member_group == pgid and fields[0] != b"Z":
                return True
    return False


def bounded_result(payload: bytes, marker: Optional[bytes], limit: int) -> bytes:
    if marker is None:
        return payload[:limit]
    separator = b"" if not payload or payload.endswith(b"\n") else b"\n"
    suffix = separator + marker + b"\n"
    if len(suffix) >= limit:
        return suffix[:limit]
    return payload[: limit - len(suffix)] + suffix


def run_bounded(command: Sequence[str], limit: int, timeout: float) -> bytes:
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise RuntimeError("probe cleanup requires default waitable SIGCHLD semantics")
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
    exit_observer: Optional[LeaderExitObserver] = None
    selector: Optional[selectors.BaseSelector] = None
    try:
        exit_observer = LeaderExitObserver(process)
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
                if not exit_observer.wait_until(deadline):
                    marker = b"[probe timed out]"
                    terminate_process_group(process)
                else:
                    terminate_process_group(process, leader_exited=True)
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
        if exit_observer is not None:
            exit_observer.close()
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
