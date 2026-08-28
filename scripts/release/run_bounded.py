#!/usr/bin/env python3
"""Run one release acceptance command with strict process-group bounds."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import select
import selectors
import signal
import subprocess
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from types import FrameType
from typing import Any, Optional, Sequence


READ_BYTES = 16 * 1024
TERMINATE_GRACE_SECONDS = 1.0
CLEANUP_TIMEOUT_SECONDS = 3.0
GROUP_QUIESCENCE_POLL_SECONDS = 0.01
SIGNALS = (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
DARWIN_PGRP_PID_CAPACITY = 4096
DARWIN_PROC_PIDTBSDINFO = 3
DARWIN_SZOMB = 5
DARWIN_MAXCOMLEN = 16


class DarwinProcBSDInfo(ctypes.Structure):
    """ABI layout of Darwin's struct proc_bsdinfo."""

    _fields_ = [
        ("pbi_flags", ctypes.c_uint32),
        ("pbi_status", ctypes.c_uint32),
        ("pbi_xstatus", ctypes.c_uint32),
        ("pbi_pid", ctypes.c_uint32),
        ("pbi_ppid", ctypes.c_uint32),
        ("pbi_uid", ctypes.c_uint32),
        ("pbi_gid", ctypes.c_uint32),
        ("pbi_ruid", ctypes.c_uint32),
        ("pbi_rgid", ctypes.c_uint32),
        ("pbi_svuid", ctypes.c_uint32),
        ("pbi_svgid", ctypes.c_uint32),
        ("rfu_1", ctypes.c_uint32),
        ("pbi_comm", ctypes.c_char * DARWIN_MAXCOMLEN),
        ("pbi_name", ctypes.c_char * (2 * DARWIN_MAXCOMLEN)),
        ("pbi_nfiles", ctypes.c_uint32),
        ("pbi_pgid", ctypes.c_uint32),
        ("pbi_pjobc", ctypes.c_uint32),
        ("e_tdev", ctypes.c_uint32),
        ("e_tpgid", ctypes.c_uint32),
        ("pbi_nice", ctypes.c_int32),
        ("pbi_start_tvsec", ctypes.c_uint64),
        ("pbi_start_tvusec", ctypes.c_uint64),
    ]


_darwin_libproc: Optional[Any] = None


@dataclass
class CleanupReport:
    attempted: bool = False
    term_attempted: bool = False
    term_sent: bool = False
    kill_attempted: bool = False
    kill_sent: bool = False
    quiescent: bool = False


class SignalController:
    """Record termination signals and wake the selector without raising."""

    def __init__(self) -> None:
        self.received: Optional[int] = None
        self._read_descriptor, self._write_descriptor = os.pipe()
        os.set_blocking(self._read_descriptor, False)
        os.set_blocking(self._write_descriptor, False)
        os.set_inheritable(self._read_descriptor, False)
        os.set_inheritable(self._write_descriptor, False)
        self._previous_handlers: dict[int, Any] = {}
        self._previous_wakeup_descriptor = -1

    @property
    def descriptor(self) -> int:
        return self._read_descriptor

    def __enter__(self) -> "SignalController":
        self._previous_wakeup_descriptor = signal.set_wakeup_fd(
            self._write_descriptor,
            warn_on_full_buffer=False,
        )
        for signal_number in SIGNALS:
            self._previous_handlers[signal_number] = signal.getsignal(signal_number)
            signal.signal(signal_number, self._handle)
        return self

    def _handle(self, signal_number: int, _frame: Optional[FrameType]) -> None:
        if self.received is None:
            self.received = signal_number

    def drain(self) -> None:
        while True:
            try:
                if not os.read(self._read_descriptor, 4096):
                    return
            except BlockingIOError:
                return

    def __exit__(self, *_unused: object) -> None:
        signal.set_wakeup_fd(self._previous_wakeup_descriptor)
        for signal_number, previous_handler in self._previous_handlers.items():
            signal.signal(signal_number, previous_handler)
        os.close(self._read_descriptor)
        os.close(self._write_descriptor)


class LeaderExitObserver:
    """Observe child exit without releasing its PID/PGID identity fence."""

    def __init__(self, process: subprocess.Popen[bytes]) -> None:
        self._process = process
        self._kqueue: Optional[Any] = None
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
                self._already_exited = True
        elif not (
            hasattr(os, "waitid")
            and hasattr(os, "P_PID")
            and hasattr(os, "WEXITED")
            and hasattr(os, "WNOWAIT")
            and hasattr(os, "WNOHANG")
        ):
            raise RuntimeError("non-reaping child-exit observation is unavailable")

    def exited(self) -> bool:
        if self._already_exited:
            return True
        if self._kqueue is not None:
            self._already_exited = bool(self._kqueue.control(None, 1, 0))
            return self._already_exited
        result = os.waitid(
            os.P_PID,
            self._process.pid,
            os.WEXITED | os.WNOWAIT | os.WNOHANG,
        )
        self._already_exited = result is not None
        return self._already_exited

    def wait_until(self, deadline: float) -> bool:
        while not self.exited():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                return False
            time.sleep(min(GROUP_QUIESCENCE_POLL_SECONDS, remaining))
        return True

    def close(self) -> None:
        if self._kqueue is not None:
            self._kqueue.close()
            self._kqueue = None


def write_all(descriptor: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        written = os.write(descriptor, payload[offset:])
        if written <= 0:
            raise OSError("acceptance output write made no progress")
        offset += written


def parse_args(arguments: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--timeout-seconds", type=int, required=True)
    parser.add_argument("--max-output-bytes", type=int, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(arguments)
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not 1 <= args.timeout_seconds <= 86400:
        parser.error("--timeout-seconds must be from 1 through 86400")
    if not 1 <= args.max_output_bytes <= 1024 * 1024:
        parser.error("--max-output-bytes must be from 1 through 1048576")
    if not args.command:
        parser.error("a command is required after --")
    return args


def normalize_exit_code(return_code: int) -> int:
    return 128 - return_code if return_code < 0 else return_code


def validate_process_group(process: subprocess.Popen[bytes]) -> int:
    pgid = os.getpgid(process.pid)
    session_id = os.getsid(process.pid)
    if pgid != process.pid or session_id != process.pid:
        raise RuntimeError("acceptance command did not create its promised session")
    return pgid


def send_group_signal(pgid: int, signal_number: int) -> bool:
    try:
        os.killpg(pgid, signal_number)
        return True
    except (ProcessLookupError, PermissionError):
        return False


def darwin_libproc() -> Any:
    global _darwin_libproc
    if _darwin_libproc is None:
        if ctypes.sizeof(DarwinProcBSDInfo) != 136:
            raise RuntimeError("Darwin proc_bsdinfo ABI size is unexpected")
        library = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
        library.proc_listpgrppids.argtypes = [
            ctypes.c_int,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        library.proc_listpgrppids.restype = ctypes.c_int
        library.proc_pidinfo.argtypes = [
            ctypes.c_int,
            ctypes.c_int,
            ctypes.c_uint64,
            ctypes.c_void_p,
            ctypes.c_int,
        ]
        library.proc_pidinfo.restype = ctypes.c_int
        _darwin_libproc = library
    return _darwin_libproc


def process_group_has_live_members(
    pgid: int,
    leader_pid: int,
    leader_exited: bool,
    deadline: float,
) -> bool:
    if leader_pid != pgid or not leader_exited:
        raise RuntimeError("process-group inspection requires an exited fenced leader")
    if sys.platform == "darwin":
        return darwin_process_group_has_live_members(pgid, leader_pid, deadline)
    if sys.platform.startswith("linux"):
        return linux_process_group_has_live_members(pgid, leader_pid, deadline)
    raise RuntimeError("process-group quiescence inspection is unavailable")


def darwin_process_group_has_live_members(
    pgid: int,
    leader_pid: int,
    deadline: float,
) -> bool:
    """Use bounded libproc snapshots, never killpg(0), to prove quiescence."""

    library = darwin_libproc()
    pid_buffer_type = ctypes.c_int * DARWIN_PGRP_PID_CAPACITY
    stable_zombies: set[tuple[int, int, int]] = set()
    while True:
        if time.monotonic() >= deadline:
            raise RuntimeError("Darwin process-group inspection timed out")
        pid_buffer = pid_buffer_type()
        ctypes.set_errno(0)
        pid_count = library.proc_listpgrppids(
            pgid,
            pid_buffer,
            ctypes.sizeof(pid_buffer),
        )
        list_errno = ctypes.get_errno()
        if pid_count < 0 or (pid_count == 0 and list_errno != 0):
            raise RuntimeError("cannot enumerate Darwin process-group members")
        if pid_count >= DARWIN_PGRP_PID_CAPACITY:
            raise RuntimeError("Darwin process-group enumeration may be truncated")

        current_zombies: set[tuple[int, int, int]] = set()
        unstable_snapshot = False
        for member_pid in pid_buffer[:pid_count]:
            if time.monotonic() >= deadline:
                raise RuntimeError("Darwin process-group inspection timed out")
            if member_pid <= 0:
                raise RuntimeError("Darwin process-group enumeration was malformed")
            if member_pid == leader_pid:
                continue

            info = DarwinProcBSDInfo()
            ctypes.set_errno(0)
            info_size = library.proc_pidinfo(
                member_pid,
                DARWIN_PROC_PIDTBSDINFO,
                0,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            info_errno = ctypes.get_errno()
            if info_size == 0 and info_errno in (errno.ENOENT, errno.ESRCH):
                unstable_snapshot = True
                continue
            if info_size != ctypes.sizeof(info):
                raise RuntimeError("cannot read Darwin process-group member state")
            if info.pbi_pid != member_pid:
                raise RuntimeError("Darwin process identity changed during inspection")
            if info.pbi_pgid != pgid:
                unstable_snapshot = True
                continue
            if info.pbi_status != DARWIN_SZOMB:
                return True
            current_zombies.add(
                (member_pid, info.pbi_start_tvsec, info.pbi_start_tvusec)
            )

        # A clean snapshot containing only the proven-exited leader is final.
        # Non-leader zombies require one matching follow-up snapshot because a
        # process may have forked immediately before becoming a zombie.
        if not unstable_snapshot and current_zombies.issubset(stable_zombies):
            return False
        stable_zombies = current_zombies


def linux_process_group_has_live_members(
    pgid: int,
    leader_pid: int,
    deadline: float,
) -> bool:
    try:
        entries = os.scandir("/proc")
    except OSError as error:
        raise RuntimeError("cannot inspect Linux process groups") from error
    with entries:
        for entry in entries:
            if time.monotonic() >= deadline:
                raise RuntimeError("process-group inspection timed out")
            if not entry.name.isdigit() or int(entry.name) == leader_pid:
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


def wait_for_group_quiescence(
    pgid: int,
    leader_pid: int,
    observer: LeaderExitObserver,
    deadline: float,
) -> None:
    while process_group_has_live_members(
        pgid,
        leader_pid,
        observer.exited(),
        deadline,
    ):
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise RuntimeError("acceptance process group did not become quiescent")
        time.sleep(min(GROUP_QUIESCENCE_POLL_SECONDS, remaining))


def terminate_process_group(
    process: subprocess.Popen[bytes],
    observer: LeaderExitObserver,
    pgid: int,
    cleanup: CleanupReport,
) -> int:
    """TERM, grace, KILL, prove quiescence, then release the PID fence."""

    cleanup.attempted = True
    cleanup.term_attempted = True
    cleanup.term_sent = send_group_signal(pgid, signal.SIGTERM) or cleanup.term_sent
    grace_deadline = time.monotonic() + TERMINATE_GRACE_SECONDS
    while time.monotonic() < grace_deadline:
        time.sleep(min(GROUP_QUIESCENCE_POLL_SECONDS, grace_deadline - time.monotonic()))
    cleanup.kill_attempted = True
    cleanup.kill_sent = send_group_signal(pgid, signal.SIGKILL) or cleanup.kill_sent

    cleanup_deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
    if not observer.wait_until(cleanup_deadline):
        raise RuntimeError("acceptance leader did not exit after SIGKILL")
    wait_for_group_quiescence(
        pgid,
        process.pid,
        observer,
        cleanup_deadline,
    )
    cleanup.quiescent = True
    remaining = cleanup_deadline - time.monotonic()
    if remaining <= 0:
        raise RuntimeError("acceptance cleanup timed out before leader reap")
    try:
        return normalize_exit_code(process.wait(timeout=remaining))
    except subprocess.TimeoutExpired as error:
        raise RuntimeError("acceptance leader could not be reaped") from error


def reap_quiescent_group(
    process: subprocess.Popen[bytes],
    observer: LeaderExitObserver,
    pgid: int,
    cleanup: CleanupReport,
) -> int:
    """Force lingering descendants out before reaping a completed leader."""

    inspection_deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
    if process_group_has_live_members(
        pgid,
        process.pid,
        observer.exited(),
        inspection_deadline,
    ):
        return terminate_process_group(process, observer, pgid, cleanup)
    cleanup.quiescent = True
    return normalize_exit_code(process.wait(timeout=CLEANUP_TIMEOUT_SECONDS))


def retain_chunk(
    chunk: bytes,
    descriptor: int,
    maximum: int,
    digest: Any,
    retained_bytes: int,
) -> tuple[int, bool]:
    available = maximum - retained_bytes
    prefix = chunk[:available]
    if prefix:
        write_all(descriptor, prefix)
        digest.update(prefix)
        retained_bytes += len(prefix)
    return retained_bytes, len(chunk) > available


def main() -> int:
    args = parse_args()
    if os.name != "posix":
        raise RuntimeError("bounded acceptance commands require POSIX")
    if signal.getsignal(signal.SIGCHLD) != signal.SIG_DFL:
        raise RuntimeError("bounded acceptance requires default waitable SIGCHLD semantics")

    args.output.parent.mkdir(parents=True, exist_ok=True)
    descriptor = os.open(args.output, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    retained = hashlib.sha256()
    retained_bytes = 0
    result = "supervisor_failed"
    exit_code = 70
    leader_exit_code: Optional[int] = None
    termination_signal: Optional[str] = None
    cleanup = CleanupReport()
    error_type: Optional[str] = None
    process_group_verified = False
    started = time.monotonic()
    process: Optional[subprocess.Popen[bytes]] = None
    observer: Optional[LeaderExitObserver] = None
    pgid: Optional[int] = None
    selector: Optional[selectors.BaseSelector] = None

    try:
        with SignalController() as signals:
            try:
                process = subprocess.Popen(
                    args.command,
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    start_new_session=True,
                )
            except OSError as error:
                result = "launch_failed"
                exit_code = 127 if error.errno == errno.ENOENT else 126
                error_type = type(error).__name__
            else:
                assert process.stdout is not None
                observer = LeaderExitObserver(process)
                # Popen(start_new_session=True) promises PID == PGID == SID.
                # Retaining the unreaped child makes this numeric identity safe
                # even if validation itself reports a platform invariant error.
                pgid = process.pid
                pgid = validate_process_group(process)
                process_group_verified = True
                os.set_blocking(process.stdout.fileno(), False)
                selector = selectors.DefaultSelector()
                selector.register(process.stdout, selectors.EVENT_READ, "output")
                selector.register(signals.descriptor, selectors.EVENT_READ, "signal")
                deadline = started + args.timeout_seconds
                pipe_eof = False

                while True:
                    if signals.received is not None:
                        termination_signal = signal.Signals(signals.received).name
                        result = "interrupted"
                        exit_code = 128 + signals.received
                        leader_exit_code = terminate_process_group(
                            process, observer, pgid, cleanup
                        )
                        break

                    now = time.monotonic()
                    if now >= deadline:
                        result = "timed_out"
                        exit_code = 124
                        leader_exit_code = terminate_process_group(
                            process, observer, pgid, cleanup
                        )
                        break

                    if observer.exited():
                        leader_exit_code = reap_quiescent_group(
                            process, observer, pgid, cleanup
                        )
                        while not pipe_eof:
                            try:
                                chunk = os.read(process.stdout.fileno(), READ_BYTES)
                            except BlockingIOError as error:
                                raise RuntimeError(
                                    "acceptance output pipe remained open after group cleanup"
                                ) from error
                            if not chunk:
                                pipe_eof = True
                                break
                            retained_bytes, exceeded = retain_chunk(
                                chunk,
                                descriptor,
                                args.max_output_bytes,
                                retained,
                                retained_bytes,
                            )
                            if exceeded:
                                result = "output_limit_exceeded"
                                exit_code = 125
                                break
                        if result == "output_limit_exceeded":
                            break
                        exit_code = leader_exit_code
                        result = "passed" if exit_code == 0 else "command_failed"
                        break

                    timeout = min(deadline - now, 0.25)
                    for key, _mask in selector.select(timeout):
                        if key.data == "signal":
                            signals.drain()
                            continue
                        try:
                            chunk = os.read(process.stdout.fileno(), READ_BYTES)
                        except BlockingIOError:
                            continue
                        if not chunk:
                            selector.unregister(process.stdout)
                            pipe_eof = True
                            continue
                        retained_bytes, exceeded = retain_chunk(
                            chunk,
                            descriptor,
                            args.max_output_bytes,
                            retained,
                            retained_bytes,
                        )
                        if exceeded:
                            result = "output_limit_exceeded"
                            exit_code = 125
                            leader_exit_code = terminate_process_group(
                                process, observer, pgid, cleanup
                            )
                            break
                    if result == "output_limit_exceeded":
                        break
    except Exception as error:
        error_type = type(error).__name__
        if (
            process is not None
            and observer is not None
            and pgid is not None
            and leader_exit_code is None
        ):
            try:
                leader_exit_code = terminate_process_group(
                    process, observer, pgid, cleanup
                )
            except Exception as cleanup_error:
                error_type = f"{error_type}+{type(cleanup_error).__name__}"
        result = "supervisor_failed"
        exit_code = 70
    finally:
        if selector is not None:
            selector.close()
        if observer is not None:
            observer.close()
        if process is not None and process.stdout is not None:
            process.stdout.close()
        os.fsync(descriptor)
        os.close(descriptor)

    report = {
        "cleanup": asdict(cleanup),
        "elapsed_millis": int((time.monotonic() - started) * 1000),
        "error_type": error_type,
        "exit_code": exit_code,
        "leader_exit_code": leader_exit_code,
        "limits": {
            "max_output_bytes": args.max_output_bytes,
            "timeout_seconds": args.timeout_seconds,
        },
        "output_bytes": retained_bytes,
        "output_sha256": retained.hexdigest(),
        "process_group_verified": process_group_verified,
        "result": result,
        "termination_signal": termination_signal,
    }
    print(json.dumps(report, sort_keys=True, separators=(",", ":")))
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())
