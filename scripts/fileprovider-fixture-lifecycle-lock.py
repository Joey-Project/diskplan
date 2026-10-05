#!/usr/bin/env python3
"""Hold the fixture's host-global lifecycle lock while running one shell lifecycle."""

import argparse
import fcntl
import os
from pathlib import Path
import signal
import stat
import subprocess
import sys


LOCK_FD_ENV = "DISKPLAN_FILEPROVIDER_LIFECYCLE_LOCK_FD"
LOCK_CAPABILITY_FD = 9


def open_lock(path: Path) -> int:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    descriptor = os.open(
        path,
        os.O_RDWR | os.O_CREAT | os.O_CLOEXEC | os.O_NOFOLLOW,
        0o600,
    )
    metadata = os.fstat(descriptor)
    if (
        metadata.st_uid != os.geteuid()
        or not stat.S_ISREG(metadata.st_mode)
        or metadata.st_mode & 0o077
    ):
        os.close(descriptor)
        raise PermissionError("lifecycle lock has unsafe ownership, type, or mode")
    return descriptor


def verify_held_lock(descriptor: int, path: Path) -> bool:
    """Prove that descriptor is the inherited open-file description holding this lock."""
    try:
        metadata = os.fstat(descriptor)
        path_metadata = os.stat(path, follow_symlinks=False)
        if (
            metadata.st_dev != path_metadata.st_dev
            or metadata.st_ino != path_metadata.st_ino
            or metadata.st_uid != os.geteuid()
            or not stat.S_ISREG(metadata.st_mode)
            or metadata.st_mode & 0o077
        ):
            return False
        probe = open_lock(path)
        try:
            try:
                fcntl.flock(probe, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                pass
            else:
                fcntl.flock(probe, fcntl.LOCK_UN)
                return False
        finally:
            os.close(probe)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        return True
    except (OSError, PermissionError, ValueError):
        return False


def lock_is_busy(path: Path) -> bool:
    try:
        descriptor = open_lock(path)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        else:
            fcntl.flock(descriptor, fcntl.LOCK_UN)
            return False
        finally:
            os.close(descriptor)
    except (OSError, PermissionError):
        return False


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--lock", type=Path, required=True)
    parser.add_argument("--verify-held-fd", type=int)
    parser.add_argument("--verify-lock-busy", action="store_true")
    parser.add_argument("command", nargs=argparse.REMAINDER)
    arguments = parser.parse_args()
    if arguments.verify_held_fd is not None:
        return 0 if verify_held_lock(arguments.verify_held_fd, arguments.lock) else 75
    if arguments.verify_lock_busy:
        return 0 if lock_is_busy(arguments.lock) else 75
    command = arguments.command
    if command and command[0] == "--":
        command = command[1:]
    if not command:
        parser.error("a command is required")

    try:
        descriptor = open_lock(arguments.lock)
        fcntl.flock(descriptor, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except (OSError, PermissionError) as error:
        print(
            '{"status":"blocked","reason":"file-provider-lifecycle-already-active"}',
            file=sys.stderr,
        )
        return 75

    environment = os.environ.copy()
    if descriptor != LOCK_CAPABILITY_FD:
        os.dup2(descriptor, LOCK_CAPABILITY_FD, inheritable=True)
    else:
        os.set_inheritable(descriptor, True)
    environment[LOCK_FD_ENV] = str(LOCK_CAPABILITY_FD)
    child = subprocess.Popen(
        command,
        env=environment,
        pass_fds=(LOCK_CAPABILITY_FD,),
        start_new_session=True,
    )

    def forward(signum: int, _frame: object) -> None:
        try:
            os.killpg(child.pid, signum)
        except ProcessLookupError:
            pass

    previous = {
        signum: signal.signal(signum, forward)
        for signum in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP)
    }
    try:
        return child.wait()
    finally:
        for signum, handler in previous.items():
            signal.signal(signum, handler)
        if descriptor != LOCK_CAPABILITY_FD:
            os.close(LOCK_CAPABILITY_FD)
        os.close(descriptor)


if __name__ == "__main__":
    raise SystemExit(main())
