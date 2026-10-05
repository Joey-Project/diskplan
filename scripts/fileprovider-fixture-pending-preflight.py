#!/usr/bin/env python3
"""Fail closed when an earlier File Provider fixture run still has durable evidence."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
from pathlib import Path
import pwd
import stat
import sys


MAXIMUM_RUNS_ROOT_ENTRIES = 4096
ACL_TYPE_EXTENDED = 0x00000100


class PreflightBlocked(RuntimeError):
    pass


def default_runs_root() -> Path:
    home = Path(pwd.getpwuid(os.geteuid()).pw_dir)
    return (
        home
        / "Library"
        / "Group Containers"
        / "group.com.joeyteng.diskplan.fileprovider-fixture"
        / "runs"
    )


def _same_identity(left: os.stat_result, right: os.stat_result) -> bool:
    return left.st_dev == right.st_dev and left.st_ino == right.st_ino


def _private_directory(metadata: os.stat_result) -> bool:
    return (
        metadata.st_uid == os.geteuid()
        and stat.S_ISDIR(metadata.st_mode)
        and not metadata.st_mode & 0o077
    )


def _require_no_extended_acl(descriptor: int) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    acl_get_fd_np = libc.acl_get_fd_np
    acl_get_fd_np.argtypes = [ctypes.c_int, ctypes.c_int]
    acl_get_fd_np.restype = ctypes.c_void_p
    acl_free = libc.acl_free
    acl_free.argtypes = [ctypes.c_void_p]
    acl_free.restype = ctypes.c_int
    ctypes.set_errno(0)
    acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED)
    if not acl:
        code = ctypes.get_errno()
        if code == errno.ENOENT:
            return
        raise PreflightBlocked(f"inspect-runs-root-acl:{code or errno.EIO}")
    acl_free(acl)
    raise PreflightBlocked("runs-root-access-policy")


def unresolved_evidence(runs_root: Path) -> list[bytes]:
    if not runs_root.is_absolute() or any(part in (".", "..") for part in runs_root.parts):
        raise PreflightBlocked("runs-root-path")
    try:
        descriptor = os.open(
            runs_root,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | os.O_NOFOLLOW,
        )
    except FileNotFoundError:
        return []
    except OSError as error:
        raise PreflightBlocked(f"open-runs-root:{error.errno or errno.EIO}") from error
    try:
        before = os.fstat(descriptor)
        if not _private_directory(before):
            raise PreflightBlocked("runs-root-access-policy")
        _require_no_extended_acl(descriptor)
        try:
            path_before = os.stat(runs_root, follow_symlinks=False)
        except OSError as error:
            raise PreflightBlocked(f"stat-runs-root:{error.errno or errno.EIO}") from error
        if not _same_identity(before, path_before):
            raise PreflightBlocked("runs-root-identity")

        evidence: list[bytes] = []
        try:
            with os.scandir(descriptor) as entries:
                for index, entry in enumerate(entries, start=1):
                    if index > MAXIMUM_RUNS_ROOT_ENTRIES:
                        raise PreflightBlocked("runs-root-entry-limit")
                    # The runs root is fixture-owned and successful cleanup leaves it empty.
                    # Treat every child as unresolved evidence so malformed or partially
                    # published run names cannot bypass the host-global acceptance gate.
                    evidence.append(os.fsencode(entry.name))
        except OSError as error:
            raise PreflightBlocked(f"enumerate-runs-root:{error.errno or errno.EIO}") from error

        after = os.fstat(descriptor)
        try:
            path_after = os.stat(runs_root, follow_symlinks=False)
        except OSError as error:
            raise PreflightBlocked(f"restat-runs-root:{error.errno or errno.EIO}") from error
        if not _same_identity(before, after) or not _same_identity(before, path_after):
            raise PreflightBlocked("runs-root-identity")
        if (
            after.st_uid != before.st_uid
            or after.st_mode != before.st_mode
            or path_after.st_uid != before.st_uid
            or path_after.st_mode != before.st_mode
        ):
            raise PreflightBlocked("runs-root-access-policy")
        if (
            after.st_mtime_ns != before.st_mtime_ns
            or after.st_ctime_ns != before.st_ctime_ns
            or path_after.st_mtime_ns != before.st_mtime_ns
            or path_after.st_ctime_ns != before.st_ctime_ns
        ):
            raise PreflightBlocked("runs-root-content-changed")
        _require_no_extended_acl(descriptor)
        return sorted(evidence)
    finally:
        os.close(descriptor)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--runs-root", type=Path, default=default_runs_root())
    arguments = parser.parse_args()
    try:
        evidence = unresolved_evidence(arguments.runs_root)
    except PreflightBlocked as error:
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "reason": "unresolved_external_mutation",
                    "detail": str(error),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 75
    if evidence:
        print(
            json.dumps(
                {
                    "status": "blocked",
                    "reason": "unresolved_external_mutation",
                    "evidence_count": len(evidence),
                    "evidence_sha256": hashlib.sha256(b"\0".join(evidence)).hexdigest(),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 75
    print(json.dumps({"status": "clear", "preflight": "pending-run"}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
