#!/usr/bin/env python3
"""Validate optional artifact zero-write and no-clobber publication behavior."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import os
import select
import stat
import subprocess
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Sequence

from india_acceptance import (
    AcceptanceError,
    canonical_json,
    read_bounded_regular,
    validate_batch,
)
from run_bounded import (
    DARWIN_PROC_PIDTBSDINFO,
    DARWIN_PGRP_PID_CAPACITY,
    DARWIN_SZOMB,
    DarwinProcBSDInfo,
    darwin_libproc,
)


MAX_COMMAND_OUTPUT = 1024 * 1024
MAX_TREE_ENTRIES = 4096
MAX_TREE_BYTES = 32 * 1024 * 1024
TREE_SNAPSHOT_TIMEOUT_SECONDS = 10.0
COMMAND_TIMEOUT_SECONDS = 1200


@dataclass(frozen=True)
class Entry:
    kind: str
    device: int
    inode: int
    uid: int
    gid: int
    mode: int
    size: int
    sha256: Optional[str]


def parse_args(arguments: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--mode", choices=("disabled", "enabled"), required=True)
    parser.add_argument("--frontend", type=Path, required=True)
    parser.add_argument("--scan-root", type=Path, required=True)
    parser.add_argument("--state-root", type=Path, required=True)
    return parser.parse_args(arguments)


def command_output(
    argv: Sequence[str], environment: dict[str, str]
) -> tuple[int, bytes]:
    process = subprocess.Popen(
        argv,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=environment,
    )
    assert process.stdout is not None
    descriptor = process.stdout.fileno()
    os.set_blocking(descriptor, False)
    output = bytearray()
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    while True:
        if time.monotonic() >= deadline:
            process.terminate()
            return 124, bytes(output)
        if process.poll() is not None:
            while True:
                try:
                    chunk = os.read(descriptor, 64 * 1024)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_COMMAND_OUTPUT:
                    return 125, bytes(output[:MAX_COMMAND_OUTPUT])
            require_group_quiescence()
            return process.returncode, bytes(output)
        readable, _, _ = select.select([descriptor], [], [], 0.1)
        if readable:
            try:
                chunk = os.read(descriptor, 64 * 1024)
            except BlockingIOError:
                continue
            if chunk:
                output.extend(chunk)
                if len(output) > MAX_COMMAND_OUTPUT:
                    process.terminate()
                    return 125, bytes(output[:MAX_COMMAND_OUTPUT])


def require_group_quiescence() -> None:
    if sys.platform != "darwin":
        raise AcceptanceError("artifact acceptance group inspection requires Darwin")
    library = darwin_libproc()
    buffer_type = ctypes.c_int * DARWIN_PGRP_PID_CAPACITY
    deadline = time.monotonic() + 3.0
    stable_zombies: set[tuple[int, int, int]] = set()
    while time.monotonic() < deadline:
        buffer = buffer_type()
        ctypes.set_errno(0)
        count = library.proc_listpgrppids(os.getpgrp(), buffer, ctypes.sizeof(buffer))
        if count < 0 or count >= DARWIN_PGRP_PID_CAPACITY:
            raise AcceptanceError("artifact acceptance process group is uninspectable")
        current_zombies: set[tuple[int, int, int]] = set()
        unstable = False
        for process_id in buffer[:count]:
            if process_id == os.getpid():
                continue
            info = DarwinProcBSDInfo()
            ctypes.set_errno(0)
            size = library.proc_pidinfo(
                process_id,
                DARWIN_PROC_PIDTBSDINFO,
                0,
                ctypes.byref(info),
                ctypes.sizeof(info),
            )
            if size == 0:
                unstable = True
                continue
            if size != ctypes.sizeof(info) or info.pbi_pid != process_id:
                raise AcceptanceError(
                    "artifact acceptance process identity is uninspectable"
                )
            if info.pbi_pgid != os.getpgrp():
                unstable = True
                continue
            if info.pbi_status != DARWIN_SZOMB:
                raise AcceptanceError("artifact acceptance retained a live descendant")
            current_zombies.add(
                (process_id, info.pbi_start_tvsec, info.pbi_start_tvusec)
            )
        if not unstable and current_zombies.issubset(stable_zombies):
            return
        stable_zombies = current_zombies
        time.sleep(0.01)
    raise AcceptanceError("artifact acceptance descendants did not become quiescent")


def snapshot_tree(root: Path) -> dict[str, Entry]:
    root_metadata = os.stat(root, follow_symlinks=False)
    if not stat.S_ISDIR(root_metadata.st_mode) or root_metadata.st_uid != os.getuid():
        raise AcceptanceError("artifact root is not an owned directory")
    entries: dict[str, Entry] = {}
    total_bytes = 0
    deadline = time.monotonic() + TREE_SNAPSHOT_TIMEOUT_SECONDS
    stack = [(root, "")]
    while stack:
        if time.monotonic() >= deadline:
            raise AcceptanceError("artifact tree snapshot exceeded its deadline")
        directory, prefix = stack.pop()
        children: list[Path] = []
        for child in directory.iterdir():
            if time.monotonic() >= deadline:
                raise AcceptanceError("artifact tree snapshot exceeded its deadline")
            children.append(child)
            if len(entries) + len(children) > MAX_TREE_ENTRIES:
                raise AcceptanceError("artifact tree exceeded its entry limit")
        children.sort(key=lambda value: os.fsencode(value.name))
        for child in children:
            relative = f"{prefix}/{child.name}" if prefix else child.name
            metadata = os.stat(child, follow_symlinks=False)
            if (
                metadata.st_dev != root_metadata.st_dev
                or metadata.st_uid != os.getuid()
            ):
                raise AcceptanceError("artifact escaped its task filesystem or owner")
            if stat.S_ISDIR(metadata.st_mode):
                if stat.S_IMODE(metadata.st_mode) & 0o077:
                    raise AcceptanceError("artifact directory is not owner-private")
                entry = Entry(
                    "directory",
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_uid,
                    metadata.st_gid,
                    stat.S_IMODE(metadata.st_mode),
                    0,
                    None,
                )
                stack.append((child, relative))
            elif stat.S_ISREG(metadata.st_mode):
                if stat.S_IMODE(metadata.st_mode) != 0o600:
                    raise AcceptanceError("artifact file mode is not 0600")
                total_bytes += metadata.st_size
                if total_bytes > MAX_TREE_BYTES:
                    raise AcceptanceError("artifact tree exceeded its byte limit")
                entry = Entry(
                    "file",
                    metadata.st_dev,
                    metadata.st_ino,
                    metadata.st_uid,
                    metadata.st_gid,
                    stat.S_IMODE(metadata.st_mode),
                    metadata.st_size,
                    hashlib.sha256(
                        read_bounded_regular(child, MAX_TREE_BYTES, "optional artifact")
                    ).hexdigest(),
                )
            else:
                raise AcceptanceError(
                    "artifact tree contains a symlink or special object"
                )
            entries[relative] = entry
            if len(entries) > MAX_TREE_ENTRIES:
                raise AcceptanceError("artifact tree exceeded its entry limit")
    return entries


def run_batch(
    args: argparse.Namespace, enabled: bool, environment: dict[str, str]
) -> bytes:
    argv = [
        str(args.frontend),
        "--batch",
        "--dry-run",
        "--profile",
        "full-audit",
        "--root",
        str(args.scan_root),
    ]
    if enabled:
        argv.extend(
            [
                "--history-dir",
                str(args.state_root / "artifacts/history"),
                "--audit-dir",
                str(args.state_root / "artifacts/audit"),
            ]
        )
    else:
        argv.extend(["--no-history", "--no-audit-file"])
    status, output = command_output(argv, environment)
    if status == 64 and enabled:
        raise SystemExit(69)
    if status != 0:
        raise SystemExit(status)
    validate_batch(output, "full-audit", persistence_enabled=enabled)
    return output


def main(arguments: Optional[Sequence[str]] = None) -> int:
    args = parse_args(arguments)
    if not all(
        path.is_absolute() for path in (args.frontend, args.scan_root, args.state_root)
    ):
        return 64
    args.state_root.mkdir(mode=0o700)
    home = args.state_root / "home"
    temporary = args.state_root / "tmp"
    home.mkdir(mode=0o700)
    temporary.mkdir(mode=0o700)
    environment = dict(os.environ)
    environment.update(
        {
            "HOME": str(home),
            "TMPDIR": str(temporary),
            "XDG_CACHE_HOME": str(home / "cache"),
            "XDG_CONFIG_HOME": str(home / "config"),
            "XDG_STATE_HOME": str(home / "state"),
        }
    )
    before = snapshot_tree(args.state_root)
    scan_before = snapshot_tree(args.scan_root)
    first_output = run_batch(args, args.mode == "enabled", environment)
    first = snapshot_tree(args.state_root)
    if snapshot_tree(args.scan_root) != scan_before:
        raise AcceptanceError("optional persistence mutated the active scan root")
    if args.mode == "disabled":
        if before != first:
            raise AcceptanceError("disabled optional persistence changed task state")
        os.write(sys.stdout.fileno(), first_output)
        return 0

    history_files = {
        path
        for path, entry in first.items()
        if entry.kind == "file" and path.startswith("artifacts/history/")
    }
    audit_files = {
        path
        for path, entry in first.items()
        if entry.kind == "file" and path.startswith("artifacts/audit/")
    }
    if not history_files or not audit_files:
        raise AcceptanceError(
            "enabled optional persistence did not publish both artifacts"
        )
    run_batch(args, True, environment)
    second = snapshot_tree(args.state_root)
    if snapshot_tree(args.scan_root) != scan_before:
        raise AcceptanceError(
            "repeated optional persistence mutated the active scan root"
        )
    for path, entry in first.items():
        if second.get(path) != entry:
            raise AcceptanceError(
                "repeated optional persistence overwrote a published object"
            )
    new_history = {
        path
        for path, entry in second.items()
        if entry.kind == "file" and path.startswith("artifacts/history/")
    } - history_files
    new_audit = {
        path
        for path, entry in second.items()
        if entry.kind == "file" and path.startswith("artifacts/audit/")
    } - audit_files
    if not new_history or not new_audit:
        raise AcceptanceError(
            "repeated optional persistence did not publish both no-clobber artifacts"
        )
    sys.stdout.buffer.write(
        canonical_json(
            {
                "schema": 1,
                "event": "artifact_acceptance",
                "status": "accepted",
                "first_entries": len(first),
                "second_entries": len(second),
            }
        )
    )
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AcceptanceError as error:
        print(f"artifact acceptance failed: {error}", file=sys.stderr)
        raise SystemExit(65)
