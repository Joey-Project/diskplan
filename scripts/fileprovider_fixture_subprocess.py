#!/usr/bin/env python3
"""Run File Provider fixture commands with strict resource bounds."""

from __future__ import annotations

from dataclasses import dataclass
import os
import selectors
import signal
import subprocess
import time
from typing import Sequence


READ_CHUNK_BYTES = 4096
TERMINATE_GRACE_SECONDS = 0.02
REAP_TIMEOUT_SECONDS = 0.5


class BoundedCommandFailure(RuntimeError):
    """Base class for a command that cannot produce a trusted result."""

    def __init__(self, message: str, *, process_id: int | None = None) -> None:
        super().__init__(message)
        self.process_id = process_id


class CommandStartFailed(BoundedCommandFailure):
    pass


class CommandTimedOut(BoundedCommandFailure):
    pass


class CommandOutputLimitExceeded(BoundedCommandFailure):
    pass


class CommandOutputInvalidUTF8(BoundedCommandFailure):
    pass


class CommandCaptureFailed(BoundedCommandFailure):
    pass


class CommandCleanupFailed(BoundedCommandFailure):
    pass


class CommandExited(BoundedCommandFailure):
    def __init__(self, returncode: int, output: str, *, process_id: int) -> None:
        super().__init__(f"command exited {returncode}", process_id=process_id)
        self.returncode = returncode
        self.output = output


@dataclass(frozen=True)
class CommandResult:
    output: str
    process_id: int


def _terminate_and_reap(process: subprocess.Popen[bytes]) -> None:
    """Terminate the command's owned process group before reaping its leader."""

    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    except PermissionError:
        try:
            process.terminate()
        except OSError:
            pass

    # Do not reap the leader before the group-wide SIGKILL. Keeping the leader's
    # PID allocated also keeps the process-group identity fenced against reuse.
    time.sleep(TERMINATE_GRACE_SECONDS)
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    except PermissionError:
        try:
            process.kill()
        except OSError:
            pass

    try:
        process.wait(timeout=REAP_TIMEOUT_SECONDS)
    except subprocess.TimeoutExpired as error:
        raise CommandCleanupFailed(
            "command process group could not be reaped",
            process_id=process.pid,
        ) from error


def run_bounded_text(
    command: Sequence[str],
    *,
    timeout_seconds: float,
    maximum_output_bytes: int,
) -> CommandResult:
    """Capture combined output incrementally under one absolute deadline."""

    if timeout_seconds <= 0:
        raise ValueError("timeout_seconds must be positive")
    if maximum_output_bytes <= 0:
        raise ValueError("maximum_output_bytes must be positive")

    try:
        process = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            bufsize=0,
        )
    except OSError as error:
        raise CommandStartFailed(f"command could not start: {type(error).__name__}") from error

    assert process.stdout is not None
    output = bytearray()
    deadline = time.monotonic() + timeout_seconds
    selector: selectors.BaseSelector | None = None
    try:
        selector = selectors.DefaultSelector()
        selector.register(process.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                _terminate_and_reap(process)
                raise CommandTimedOut("command exceeded its absolute deadline", process_id=process.pid)

            if not selector.select(remaining):
                _terminate_and_reap(process)
                raise CommandTimedOut("command exceeded its absolute deadline", process_id=process.pid)

            chunk = os.read(
                process.stdout.fileno(),
                min(READ_CHUNK_BYTES, maximum_output_bytes + 1 - len(output)),
            )
            if not chunk:
                try:
                    returncode = process.wait(timeout=max(0.0, deadline - time.monotonic()))
                except subprocess.TimeoutExpired:
                    _terminate_and_reap(process)
                    raise CommandTimedOut(
                        "command exceeded its absolute deadline",
                        process_id=process.pid,
                    ) from None
                break

            output.extend(chunk)
            if len(output) > maximum_output_bytes:
                _terminate_and_reap(process)
                raise CommandOutputLimitExceeded(
                    f"command exceeded {maximum_output_bytes} combined output bytes",
                    process_id=process.pid,
                )
    except OSError as error:
        if process.returncode is None:
            _terminate_and_reap(process)
        raise CommandCaptureFailed(
            f"command output capture failed: {type(error).__name__}",
            process_id=process.pid,
        ) from error
    except BaseException:
        if process.returncode is None:
            _terminate_and_reap(process)
        raise
    finally:
        if selector is not None:
            selector.close()
        process.stdout.close()

    try:
        decoded = bytes(output).decode("utf-8", errors="strict")
    except UnicodeDecodeError as error:
        raise CommandOutputInvalidUTF8(
            "command output is not valid UTF-8",
            process_id=process.pid,
        ) from error
    if returncode != 0:
        raise CommandExited(returncode, decoded, process_id=process.pid)
    return CommandResult(output=decoded, process_id=process.pid)
