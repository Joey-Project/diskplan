#!/usr/bin/python3
"""Run one command while holding its exited leader until its group is quiescent."""

import ctypes
import errno
import os
import signal
import sys
import time


GROUP_QUIESCENCE_TIMEOUT = 252
GROUP_PROBE_FAILURE = 253
SUPERVISOR_SETUP_FAILURE = 254
TERM_GRACE_SECONDS = 0.1
GROUP_QUIESCENCE_SECONDS = 2.0
TARGET_REAP_SECONDS = 2.0
MAXIMUM_GROUP_MEMBERS = 1_024
MAXIMUM_SYSTEM_PROCESSES = 65_536
P_PID = 1
WEXITED = 0x00000004
WNOWAIT = 0x00000020
STARTUP_DEADLINE_STAGES = {
    "none",
    "before-target-fork",
    "at-target-exec",
}

target_pid = None
command_argv = None
libc = ctypes.CDLL(None, use_errno=True)
libc.waitid.argtypes = [ctypes.c_int, ctypes.c_uint32, ctypes.c_void_p, ctypes.c_int]
libc.waitid.restype = ctypes.c_int
libproc = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
libproc.proc_listpgrppids.argtypes = [
    ctypes.c_int32,
    ctypes.c_void_p,
    ctypes.c_int,
]
libproc.proc_listpgrppids.restype = ctypes.c_int
libproc.proc_listallpids.argtypes = [ctypes.c_void_p, ctypes.c_int]
libproc.proc_listallpids.restype = ctypes.c_int


def signal_target_group(signum):
    if target_pid is None:
        return False
    try:
        os.killpg(target_pid, signum)
        return True
    except ProcessLookupError:
        if live_target_descendants():
            os._exit(GROUP_PROBE_FAILURE)
        return False
    except PermissionError:
        # macOS can reject signalling a held zombie's otherwise empty group.
        # Accept that only after an independent bounded enumeration proves no
        # live descendants remain; any live member keeps this fail-closed.
        if live_target_descendants():
            kill_target_best_effort()
            os._exit(GROUP_PROBE_FAILURE)
        return False


def kill_target_best_effort():
    if target_pid is not None and target_pid > 0:
        try:
            os.killpg(target_pid, signal.SIGKILL)
        except OSError:
            pass
        try:
            os.kill(target_pid, signal.SIGKILL)
        except OSError:
            pass


def terminate_supervisor(_signum, _frame):
    kill_target_best_effort()
    os._exit(SUPERVISOR_SETUP_FAILURE)


def close_capture_writers():
    for descriptor in (1, 2):
        try:
            os.close(descriptor)
        except OSError as error:
            if error.errno != errno.EBADF:
                raise


def install_capture_writers():
    global command_argv
    if (
        len(sys.argv) < 15
        or sys.argv[1] != "--capture-control-fd"
        or sys.argv[3] != "--stdout-fifo"
        or sys.argv[5] != "--stderr-fifo"
        or sys.argv[7] != "--startup-delay-milliseconds"
        or sys.argv[9] != "--startup-deadline-uptime-nanoseconds"
        or sys.argv[11] != "--startup-deadline-test-stage"
        or sys.argv[13] != "--"
    ):
        raise RuntimeError("invalid capture supervisor arguments")
    control_descriptor = int(sys.argv[2])
    if control_descriptor < 3:
        raise RuntimeError("invalid capture control descriptor")
    startup_delay_milliseconds = int(sys.argv[8])
    if not 0 <= startup_delay_milliseconds <= 60_000:
        raise RuntimeError("invalid startup delay")
    startup_deadline_uptime_nanoseconds = int(sys.argv[10])
    if startup_deadline_uptime_nanoseconds <= 0:
        raise RuntimeError("invalid startup deadline")
    startup_deadline_test_stage = sys.argv[12]
    if startup_deadline_test_stage not in STARTUP_DEADLINE_STAGES:
        raise RuntimeError("invalid startup deadline test stage")
    if startup_delay_milliseconds:
        time.sleep(startup_delay_milliseconds / 1_000)
    stdout_descriptor = -1
    stderr_descriptor = -1
    try:
        stdout_descriptor = os.open(sys.argv[4], os.O_WRONLY | os.O_CLOEXEC)
        stderr_descriptor = os.open(sys.argv[6], os.O_WRONLY | os.O_CLOEXEC)
        os.dup2(stdout_descriptor, 1)
        os.dup2(stderr_descriptor, 2)
    finally:
        if stdout_descriptor >= 0:
            os.close(stdout_descriptor)
        if stderr_descriptor >= 0:
            os.close(stderr_descriptor)
    command_argv = sys.argv[14:]
    if os.write(control_descriptor, b"R") != 1:
        raise RuntimeError("capture-ready write failed")
    if os.read(control_descriptor, 1) != b"G":
        raise RuntimeError("capture grant was not received")
    if os.write(control_descriptor, b"A") != 1:
        raise RuntimeError("capture-grant acknowledgement failed")
    if os.read(control_descriptor, 1) != b"P":
        raise RuntimeError("target-fork permission was not received")
    return (
        control_descriptor,
        startup_deadline_uptime_nanoseconds,
        startup_deadline_test_stage,
    )


def startup_deadline_expired(
    deadline_uptime_nanoseconds,
    test_stage,
    current_stage,
):
    observed_uptime_nanoseconds = time.monotonic_ns()
    if test_stage == current_stage:
        observed_uptime_nanoseconds = max(
            observed_uptime_nanoseconds,
            deadline_uptime_nanoseconds,
        )
    return observed_uptime_nanoseconds >= deadline_uptime_nanoseconds


def enforce_startup_deadline(
    control_descriptor,
    deadline_uptime_nanoseconds,
    test_stage,
    current_stage,
):
    if not startup_deadline_expired(
        deadline_uptime_nanoseconds,
        test_stage,
        current_stage,
    ):
        return
    if os.write(control_descriptor, b"D") != 1:
        raise RuntimeError("startup-deadline write failed")
    raise TimeoutError("startup deadline expired")


def kill_and_reap_target():
    if target_pid is None or target_pid <= 0:
        return
    kill_target_best_effort()
    deadline = time.monotonic() + TARGET_REAP_SECONDS
    while True:
        try:
            waited_pid, _ = os.waitpid(target_pid, os.WNOHANG)
        except InterruptedError:
            continue
        except ChildProcessError:
            return
        if waited_pid == target_pid:
            return
        if time.monotonic() >= deadline:
            raise TimeoutError("target reap timed out")
        time.sleep(0.01)


def process_group_members():
    members = (ctypes.c_int32 * MAXIMUM_GROUP_MEMBERS)()
    byte_capacity = ctypes.sizeof(members)
    member_count = libproc.proc_listpgrppids(
        target_pid,
        ctypes.byref(members),
        byte_capacity,
    )
    if member_count < 0:
        os._exit(GROUP_PROBE_FAILURE)
    if member_count >= MAXIMUM_GROUP_MEMBERS:
        os._exit(GROUP_PROBE_FAILURE)
    result = {pid for pid in members[:member_count] if pid > 0}
    if result:
        return result

    # macOS omits a WNOWAIT zombie leader from proc_listpgrppids. A zero result
    # is also the libproc failure sentinel, so disambiguate it with a bounded
    # all-process snapshot that must contain this live supervisor.
    processes = (ctypes.c_int32 * MAXIMUM_SYSTEM_PROCESSES)()
    process_count = libproc.proc_listallpids(
        ctypes.byref(processes), ctypes.sizeof(processes)
    )
    if process_count <= 0 or process_count >= MAXIMUM_SYSTEM_PROCESSES:
        os._exit(GROUP_PROBE_FAILURE)
    process_ids = {pid for pid in processes[:process_count] if pid > 0}
    if os.getpid() not in process_ids:
        os._exit(GROUP_PROBE_FAILURE)
    for process_id in process_ids:
        try:
            if os.getpgid(process_id) == target_pid:
                result.add(process_id)
        except ProcessLookupError:
            pass
        except PermissionError:
            os._exit(GROUP_PROBE_FAILURE)
    return result


def live_target_descendants():
    members = process_group_members()
    members.discard(target_pid)
    return members


def wait_for_group_quiescence():
    deadline = time.monotonic() + GROUP_QUIESCENCE_SECONDS
    while True:
        members = live_target_descendants()
        if not members:
            return
        if time.monotonic() >= deadline:
            os._exit(GROUP_QUIESCENCE_TIMEOUT)
        time.sleep(0.01)


def wait_for_target_without_reaping():
    signal_info = (ctypes.c_byte * 256)()
    while True:
        if libc.waitid(P_PID, target_pid, ctypes.byref(signal_info), WEXITED | WNOWAIT) == 0:
            return
        failure = ctypes.get_errno()
        if failure != errno.EINTR:
            raise OSError(failure, "waitid")


def mirror_wait_status(wait_status):
    if os.WIFEXITED(wait_status):
        os._exit(os.WEXITSTATUS(wait_status))
    if os.WIFSIGNALED(wait_status):
        signum = os.WTERMSIG(wait_status)
        if signum != signal.SIGKILL:
            signal.signal(signum, signal.SIG_DFL)
        os.kill(os.getpid(), signum)
    os._exit(SUPERVISOR_SETUP_FAILURE)


def main():
    global target_pid
    (
        control_descriptor,
        startup_deadline_uptime_nanoseconds,
        startup_deadline_test_stage,
    ) = install_capture_writers()

    try:
        os.setsid()
    except PermissionError:
        # Direct posix_spawn launches the supervisor as its own process-group leader.
        if os.getpgrp() != os.getpid():
            raise
    signal.signal(signal.SIGTERM, terminate_supervisor)
    signal.signal(signal.SIGINT, terminate_supervisor)
    blocked = {signal.SIGTERM, signal.SIGINT}
    previous_mask = signal.pthread_sigmask(signal.SIG_BLOCK, blocked)
    launch_gate_read, launch_gate_write = os.pipe()
    launch_status_read, launch_status_write = os.pipe()
    # EOF on this non-inheritable writer proves exec committed; every pre-exec
    # exit must report an explicit status byte instead.
    os.set_inheritable(launch_status_write, False)
    enforce_startup_deadline(
        control_descriptor,
        startup_deadline_uptime_nanoseconds,
        startup_deadline_test_stage,
        "before-target-fork",
    )
    target_pid = os.fork()
    if target_pid == 0:
        os.close(control_descriptor)
        os.close(launch_gate_write)
        os.close(launch_status_read)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.pthread_sigmask(signal.SIG_SETMASK, previous_mask)
        try:
            if os.read(launch_gate_read, 1) != b"S":
                raise RuntimeError("target-launch gate was not received")
            os.close(launch_gate_read)
            # A separate process group is sufficient for bounded descendant cleanup.
            # Keeping it in the supervisor's session avoids macOS denying killpg
            # across the session boundary after the exact leader has exited.
            os.setpgid(0, 0)
            if startup_deadline_expired(
                startup_deadline_uptime_nanoseconds,
                startup_deadline_test_stage,
                "at-target-exec",
            ):
                if os.write(launch_status_write, b"D") != 1:
                    raise RuntimeError("target deadline status write failed")
                os._exit(SUPERVISOR_SETUP_FAILURE)
            os.execv(command_argv[0], command_argv)
        except BaseException:
            try:
                os.write(launch_status_write, b"E")
            except OSError:
                pass
            os._exit(SUPERVISOR_SETUP_FAILURE)

    os.close(launch_gate_read)
    os.close(launch_status_write)
    # The target remains blocked in the supervisor group until the parent has
    # closed its writers, acknowledged the safe fork, and restored signal
    # handling. Before that point one group signal terminates both processes.
    close_capture_writers()
    if os.write(control_descriptor, b"F") != 1:
        raise RuntimeError("target-fork acknowledgement failed")
    if os.read(control_descriptor, 1) != b"C":
        raise RuntimeError("target-launch permission was not received")
    signal.pthread_sigmask(signal.SIG_UNBLOCK, blocked)
    if os.write(launch_gate_write, b"S") != 1:
        raise RuntimeError("target-launch gate failed")
    os.close(launch_gate_write)
    launch_status = os.read(launch_status_read, 1)
    os.close(launch_status_read)
    if launch_status == b"D":
        # X is emitted only after the gated target is no longer waitable by its
        # supervisor, so Swift can distinguish target-level reap from D before fork.
        kill_and_reap_target()
        if os.write(control_descriptor, b"X") != 1:
            raise RuntimeError("target-reaped deadline write failed")
        raise TimeoutError("target startup deadline expired")
    if launch_status:
        kill_and_reap_target()
        raise RuntimeError("target exec failed")
    if os.write(control_descriptor, b"L") != 1:
        raise RuntimeError("target-launch write failed")
    os.close(control_descriptor)

    wait_for_target_without_reaping()
    # Keeping the exited leader waitable prevents its PID/process-group ID from
    # being reused while inherited-writer descendants are terminated.
    if live_target_descendants():
        signal_target_group(signal.SIGTERM)
        time.sleep(TERM_GRACE_SECONDS)
        if live_target_descendants():
            signal_target_group(signal.SIGKILL)
    wait_for_group_quiescence()
    _, wait_status = os.waitpid(target_pid, 0)
    mirror_wait_status(wait_status)
    return SUPERVISOR_SETUP_FAILURE


if __name__ == "__main__":
    try:
        main()
    except BaseException:
        kill_target_best_effort()
        os._exit(SUPERVISOR_SETUP_FAILURE)
    os._exit(SUPERVISOR_SETUP_FAILURE)
