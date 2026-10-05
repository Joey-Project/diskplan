#!/usr/bin/env python3
"""Seal and compare an exact, bounded, no-follow release source snapshot.

The cross-build seal protects namespace, content, and access policy: relative
path, entry kind, exact mode, regular-file size and digest, and symlink target.
Device, inode, and timestamps are observations only across builds. They still
protect object identity and content stability while each snapshot is read, so a
concurrent replacement or write cannot produce a mixed snapshot.
"""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import json
import os
import stat
import struct
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


MAX_ENTRIES = 100_000
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
MAX_RECORD_BYTES = 64 * 1024 * 1024
MAX_PATH_BYTES = 4096
MAX_DIAGNOSTICS = 20
CHUNK_BYTES = 1024 * 1024
RECORD_SCHEMA = "diskplan.release-source-snapshot.v1"
KINDS = frozenset(("directory", "file", "symlink"))
ACL_TYPE_EXTENDED = 0x00000100
ACL_FIRST_ENTRY = 0


@dataclass(frozen=True)
class SnapshotEntry:
    relative: bytes
    kind: str
    mode: int
    size: int
    payload: bytes
    device: int
    inode: int
    mtime_ns: int
    ctime_ns: int


@dataclass(frozen=True)
class Snapshot:
    protected_digest: str
    entries: tuple[SnapshotEntry, ...]


@dataclass(frozen=True)
class SnapshotChange:
    relative: bytes
    fields: tuple[str, ...]


@dataclass(frozen=True)
class SnapshotComparison:
    protected: tuple[SnapshotChange, ...]
    observations: tuple[SnapshotChange, ...]


def frame(value: bytes) -> bytes:
    return struct.pack(">Q", len(value)) + value


def identity(value: os.stat_result) -> tuple[int, int]:
    return value.st_dev, value.st_ino


def content_state(value: os.stat_result) -> tuple[int, int, int, int]:
    return (
        stat.S_IMODE(value.st_mode),
        value.st_size,
        value.st_mtime_ns,
        value.st_ctime_ns,
    )


def hash_regular(path: Path, initial: os.stat_result) -> tuple[bytes, int]:
    if initial.st_size > MAX_FILE_BYTES:
        raise ValueError(f"source file exceeds {MAX_FILE_BYTES} bytes: {path}")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    try:
        opened = os.fstat(descriptor)
        if not stat.S_ISREG(opened.st_mode) or identity(opened) != identity(initial):
            raise ValueError(f"source file was replaced before hashing: {path}")
        if content_state(opened) != content_state(initial):
            raise ValueError(f"source file changed before hashing: {path}")
        hasher = hashlib.sha256()
        consumed = 0
        while chunk := os.read(descriptor, CHUNK_BYTES):
            consumed += len(chunk)
            if consumed > MAX_FILE_BYTES:
                raise ValueError(f"source file grew beyond {MAX_FILE_BYTES} bytes: {path}")
            hasher.update(chunk)
        final = os.fstat(descriptor)
    finally:
        os.close(descriptor)
    path_final = path.lstat()
    if (
        identity(opened) != identity(final)
        or identity(opened) != identity(path_final)
        or content_state(opened) != content_state(final)
        or content_state(opened) != content_state(path_final)
        or consumed != opened.st_size
    ):
        raise ValueError(f"source file changed while hashing: {path}")
    return hasher.digest(), consumed


def entry_from_metadata(
    relative: bytes,
    kind: str,
    metadata: os.stat_result,
    size: int,
    payload: bytes,
) -> SnapshotEntry:
    return SnapshotEntry(
        relative=relative,
        kind=kind,
        mode=stat.S_IMODE(metadata.st_mode),
        size=size,
        payload=payload,
        device=metadata.st_dev,
        inode=metadata.st_ino,
        mtime_ns=metadata.st_mtime_ns,
        ctime_ns=metadata.st_ctime_ns,
    )


def update_entry(hasher: "hashlib._Hash", entry: SnapshotEntry) -> None:
    hasher.update(frame(entry.relative))
    hasher.update(frame(entry.kind.encode("ascii")))
    hasher.update(frame(f"{entry.mode:04o}".encode("ascii")))
    hasher.update(frame(str(entry.size).encode("ascii")))
    hasher.update(frame(entry.payload))


def protected_digest(entries: tuple[SnapshotEntry, ...]) -> str:
    hasher = hashlib.sha256()
    for entry in entries:
        update_entry(hasher, entry)
    return hasher.hexdigest()


def snapshot(root: Path) -> Snapshot:
    root = root.absolute()
    root_metadata = root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode) or root.is_symlink():
        raise ValueError("source snapshot root must be a non-symlink directory")

    entries: list[SnapshotEntry] = [
        entry_from_metadata(b"", "directory", root_metadata, 0, b"")
    ]
    total_bytes = 0
    enumerated_entries = 1

    def walk(directory: Path, relative_prefix: bytes) -> None:
        nonlocal enumerated_entries, total_bytes
        before = directory.lstat()
        if not stat.S_ISDIR(before.st_mode):
            raise ValueError(f"source directory was replaced: {directory}")
        if not relative_prefix and (
            identity(root_metadata) != identity(before)
            or content_state(root_metadata) != content_state(before)
        ):
            raise ValueError("source snapshot root changed before walking")
        children: list[os.DirEntry[str]] = []
        with os.scandir(directory) as iterator:
            for child in iterator:
                enumerated_entries += 1
                if enumerated_entries > MAX_ENTRIES:
                    raise ValueError(f"source snapshot exceeds {MAX_ENTRIES} entries")
                children.append(child)
        children.sort(key=lambda entry: os.fsencode(entry.name))
        for child in children:
            name = os.fsencode(child.name)
            relative = name if not relative_prefix else relative_prefix + b"/" + name
            path = Path(child.path)
            metadata = path.lstat()
            if stat.S_ISREG(metadata.st_mode):
                file_digest, file_bytes = hash_regular(path, metadata)
                total_bytes += file_bytes
                if total_bytes > MAX_TOTAL_BYTES:
                    raise ValueError(f"source snapshot exceeds {MAX_TOTAL_BYTES} bytes")
                entries.append(
                    entry_from_metadata(relative, "file", metadata, file_bytes, file_digest)
                )
            elif stat.S_ISDIR(metadata.st_mode):
                entries.append(entry_from_metadata(relative, "directory", metadata, 0, b""))
                walk(path, relative)
            elif stat.S_ISLNK(metadata.st_mode):
                target = os.fsencode(os.readlink(path))
                final = path.lstat()
                if identity(metadata) != identity(final) or content_state(
                    metadata
                ) != content_state(final):
                    raise ValueError(f"source symlink changed while reading: {path}")
                entries.append(
                    entry_from_metadata(relative, "symlink", metadata, len(target), target)
                )
            else:
                raise ValueError(f"unsupported source snapshot entry: {path}")
        after = directory.lstat()
        if identity(before) != identity(after) or content_state(before) != content_state(after):
            raise ValueError(f"source directory changed while walking: {directory}")

    walk(root, b"")
    ordered = tuple(sorted(entries, key=lambda entry: entry.relative))
    return Snapshot(protected_digest(ordered), ordered)


def snapshot_manifest(root: Path) -> str:
    return snapshot(root).protected_digest


def entry_record(entry: SnapshotEntry) -> dict[str, Any]:
    return {
        "kind": entry.kind,
        "mode": entry.mode,
        "observation": {
            "ctime_ns": entry.ctime_ns,
            "device": entry.device,
            "inode": entry.inode,
            "mtime_ns": entry.mtime_ns,
        },
        "path_hex": entry.relative.hex(),
        "payload_hex": entry.payload.hex(),
        "size": entry.size,
    }


def snapshot_record(value: Snapshot) -> bytes:
    record = {
        "entries": [entry_record(entry) for entry in value.entries],
        "protected_digest": value.protected_digest,
        "schema": RECORD_SCHEMA,
    }
    return json.dumps(
        record, ensure_ascii=True, separators=(",", ":"), sort_keys=True
    ).encode("ascii") + b"\n"


def fd_acl_free(descriptor: int) -> bool:
    if sys.platform != "darwin":
        return True
    libc = ctypes.CDLL(None, use_errno=True)
    acl_get_fd = libc.acl_get_fd_np
    acl_get_fd.argtypes = [ctypes.c_int, ctypes.c_int]
    acl_get_fd.restype = ctypes.c_void_p
    acl_get_entry = libc.acl_get_entry
    acl_get_entry.argtypes = [
        ctypes.c_void_p,
        ctypes.c_int,
        ctypes.POINTER(ctypes.c_void_p),
    ]
    acl_get_entry.restype = ctypes.c_int
    acl_free = libc.acl_free
    acl_free.argtypes = [ctypes.c_void_p]
    acl_free.restype = ctypes.c_int
    acl = acl_get_fd(descriptor, ACL_TYPE_EXTENDED)
    if not acl:
        error_number = ctypes.get_errno()
        if error_number in {errno.ENOENT, errno.ENOTSUP}:
            return True
        raise OSError(error_number, os.strerror(error_number))
    try:
        entry = ctypes.c_void_p()
        result = acl_get_entry(acl, ACL_FIRST_ENTRY, ctypes.byref(entry))
        if result < 0:
            error_number = ctypes.get_errno()
            raise OSError(error_number, os.strerror(error_number))
        return False
    finally:
        acl_free(acl)


def open_private_record_parent(path: Path) -> tuple[int, str]:
    absolute = path.absolute()
    name = absolute.name
    if name in ("", ".", ".."):
        raise ValueError("source snapshot record name is invalid")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_DIRECTORY"):
        flags |= os.O_DIRECTORY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(absolute.parent, flags)
    try:
        metadata = os.fstat(descriptor)
        if (
            not stat.S_ISDIR(metadata.st_mode)
            or metadata.st_uid != os.geteuid()
            or stat.S_IMODE(metadata.st_mode) & 0o077
            or not fd_acl_free(descriptor)
        ):
            raise ValueError(
                "source snapshot record directory must be current-euid-owned, "
                "owner-private, and ACL-free"
            )
    except Exception:
        os.close(descriptor)
        raise
    return descriptor, name


def write_snapshot_record(path: Path, value: Snapshot) -> None:
    data = snapshot_record(value)
    if len(data) > MAX_RECORD_BYTES:
        raise ValueError(f"source snapshot record exceeds {MAX_RECORD_BYTES} bytes")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    parent_descriptor, name = open_private_record_parent(path)
    try:
        descriptor = os.open(name, flags, 0o600, dir_fd=parent_descriptor)
        try:
            written = 0
            while written < len(data):
                count = os.write(descriptor, data[written:])
                if count <= 0:
                    raise OSError("short write while creating source snapshot record")
                written += count
            os.fsync(descriptor)
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or not fd_acl_free(descriptor)
            ):
                raise ValueError(
                    "source snapshot record is not an owner-private ACL-free regular file"
                )
            named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if identity(metadata) != identity(named) or content_state(
                metadata
            ) != content_state(named):
                raise ValueError("source snapshot record slot changed while creating")
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_descriptor)


def reject_duplicate_keys(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    result: dict[str, Any] = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate source snapshot record key: {key}")
        result[key] = value
    return result


def require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    if set(value) != expected:
        raise ValueError(f"{label} keys are invalid")


def require_int(value: Any, label: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{label} must be a non-negative integer")
    return value


def decode_hex(value: Any, label: str) -> bytes:
    if not isinstance(value, str) or len(value) % 2 != 0:
        raise ValueError(f"{label} must be lowercase hexadecimal")
    try:
        decoded = bytes.fromhex(value)
    except ValueError as error:
        raise ValueError(f"{label} must be lowercase hexadecimal") from error
    if decoded.hex() != value:
        raise ValueError(f"{label} must be lowercase hexadecimal")
    return decoded


def parse_snapshot_record(data: bytes) -> Snapshot:
    if len(data) > MAX_RECORD_BYTES:
        raise ValueError(f"source snapshot record exceeds {MAX_RECORD_BYTES} bytes")
    try:
        raw = json.loads(data, object_pairs_hook=reject_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("source snapshot record is not valid JSON") from error
    if not isinstance(raw, dict):
        raise ValueError("source snapshot record must be an object")
    require_exact_keys(raw, {"entries", "protected_digest", "schema"}, "record")
    if raw["schema"] != RECORD_SCHEMA:
        raise ValueError("source snapshot record schema is incompatible")
    digest = raw["protected_digest"]
    if not isinstance(digest, str) or len(digest) != 64 or any(
        character not in "0123456789abcdef" for character in digest
    ):
        raise ValueError("source snapshot protected digest is malformed")
    raw_entries = raw["entries"]
    if (
        not isinstance(raw_entries, list)
        or not raw_entries
        or len(raw_entries) > MAX_ENTRIES
    ):
        raise ValueError("source snapshot record entry count is invalid")
    entries: list[SnapshotEntry] = []
    previous: bytes | None = None
    total_bytes = 0
    for index, raw_entry in enumerate(raw_entries):
        if not isinstance(raw_entry, dict):
            raise ValueError(f"source snapshot entry {index} must be an object")
        require_exact_keys(
            raw_entry,
            {"kind", "mode", "observation", "path_hex", "payload_hex", "size"},
            f"source snapshot entry {index}",
        )
        relative = decode_hex(raw_entry["path_hex"], f"entry {index} path")
        if len(relative) > MAX_PATH_BYTES:
            raise ValueError(f"source snapshot entry {index} path is too long")
        components = relative.split(b"/")
        if index == 0:
            if relative != b"":
                raise ValueError("source snapshot record must begin with the root entry")
        elif (
            not relative
            or relative.startswith(b"/")
            or relative.endswith(b"/")
            or any(component in (b"", b".", b"..") for component in components)
            or b"\x00" in relative
        ):
            raise ValueError(f"source snapshot entry {index} path is not canonical")
        if previous is not None and relative <= previous:
            raise ValueError("source snapshot record paths must be unique and sorted")
        previous = relative
        kind = raw_entry["kind"]
        if kind not in KINDS:
            raise ValueError(f"source snapshot entry {index} kind is invalid")
        mode = require_int(raw_entry["mode"], f"entry {index} mode")
        if mode > 0o7777:
            raise ValueError(f"source snapshot entry {index} mode is invalid")
        size = require_int(raw_entry["size"], f"entry {index} size")
        payload = decode_hex(raw_entry["payload_hex"], f"entry {index} payload")
        if kind == "directory" and (size != 0 or payload):
            raise ValueError(f"source snapshot directory entry {index} payload is invalid")
        if kind == "file" and (
            len(payload) != hashlib.sha256().digest_size or size > MAX_FILE_BYTES
        ):
            raise ValueError(f"source snapshot file entry {index} payload is invalid")
        if kind == "symlink" and size != len(payload):
            raise ValueError(f"source snapshot symlink entry {index} size is invalid")
        if index == 0 and kind != "directory":
            raise ValueError("source snapshot root entry must be a directory")
        if kind == "file":
            total_bytes += size
            if total_bytes > MAX_TOTAL_BYTES:
                raise ValueError(f"source snapshot exceeds {MAX_TOTAL_BYTES} bytes")
        observation = raw_entry["observation"]
        if not isinstance(observation, dict):
            raise ValueError(f"source snapshot entry {index} observation is invalid")
        require_exact_keys(
            observation,
            {"ctime_ns", "device", "inode", "mtime_ns"},
            f"source snapshot entry {index} observation",
        )
        entries.append(
            SnapshotEntry(
                relative=relative,
                kind=kind,
                mode=mode,
                size=size,
                payload=payload,
                device=require_int(observation["device"], f"entry {index} device"),
                inode=require_int(observation["inode"], f"entry {index} inode"),
                mtime_ns=require_int(observation["mtime_ns"], f"entry {index} mtime"),
                ctime_ns=require_int(observation["ctime_ns"], f"entry {index} ctime"),
            )
        )
    parsed = Snapshot(digest, tuple(entries))
    if protected_digest(parsed.entries) != digest:
        raise ValueError("source snapshot record protected digest does not match entries")
    if snapshot_record(parsed) != data:
        raise ValueError("source snapshot record is not canonical")
    return parsed


def load_snapshot_record(path: Path, expected_sha256: str) -> Snapshot:
    if len(expected_sha256) != 64 or any(
        character not in "0123456789abcdef" for character in expected_sha256
    ):
        raise ValueError("expected source snapshot record digest is malformed")
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    parent_descriptor, name = open_private_record_parent(path)
    try:
        descriptor = os.open(name, flags, dir_fd=parent_descriptor)
        try:
            metadata = os.fstat(descriptor)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or stat.S_IMODE(metadata.st_mode) != 0o600
                or metadata.st_uid != os.geteuid()
                or metadata.st_nlink != 1
                or not fd_acl_free(descriptor)
            ):
                raise ValueError(
                    "source snapshot record must be an owner-private ACL-free regular file"
                )
            if metadata.st_size > MAX_RECORD_BYTES:
                raise ValueError(f"source snapshot record exceeds {MAX_RECORD_BYTES} bytes")
            chunks: list[bytes] = []
            consumed = 0
            while chunk := os.read(
                descriptor, min(CHUNK_BYTES, MAX_RECORD_BYTES + 1 - consumed)
            ):
                consumed += len(chunk)
                if consumed > MAX_RECORD_BYTES:
                    raise ValueError(
                        f"source snapshot record exceeds {MAX_RECORD_BYTES} bytes"
                    )
                chunks.append(chunk)
            final = os.fstat(descriptor)
            named = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if identity(metadata) != identity(final) or content_state(
                metadata
            ) != content_state(final) or identity(final) != identity(
                named
            ) or content_state(final) != content_state(named):
                raise ValueError("source snapshot record changed while reading")
        finally:
            os.close(descriptor)
    finally:
        os.close(parent_descriptor)
    data = b"".join(chunks)
    if hashlib.sha256(data).hexdigest() != expected_sha256:
        raise ValueError("source snapshot record digest does not match sealed baseline")
    return parse_snapshot_record(data)


def compare_snapshots(before: Snapshot, after: Snapshot) -> SnapshotComparison:
    before_by_path = {entry.relative: entry for entry in before.entries}
    after_by_path = {entry.relative: entry for entry in after.entries}
    protected: list[SnapshotChange] = []
    observations: list[SnapshotChange] = []
    for relative in sorted(set(before_by_path) | set(after_by_path)):
        old = before_by_path.get(relative)
        new = after_by_path.get(relative)
        if old is None:
            protected.append(SnapshotChange(relative, ("added",)))
            continue
        if new is None:
            protected.append(SnapshotChange(relative, ("removed",)))
            continue
        protected_fields: list[str] = []
        if old.kind != new.kind:
            protected_fields.append("kind")
        if old.mode != new.mode:
            protected_fields.append("mode")
        if old.size != new.size:
            protected_fields.append("size")
        if old.payload != new.payload:
            protected_fields.append(
                "content" if old.kind == new.kind == "file" else "payload"
            )
        if protected_fields:
            protected.append(SnapshotChange(relative, tuple(protected_fields)))
            continue
        observation_fields = tuple(
            field
            for field in ("device", "inode", "mtime_ns", "ctime_ns")
            if getattr(old, field) != getattr(new, field)
        )
        if observation_fields:
            observations.append(SnapshotChange(relative, observation_fields))
    return SnapshotComparison(tuple(protected), tuple(observations))


def display_path(relative: bytes) -> str:
    if not relative:
        return "."
    displayed = repr(os.fsdecode(relative))[1:-1]
    if len(displayed) > 240:
        return displayed[:237] + "..."
    return displayed


def report_changes(label: str, changes: tuple[SnapshotChange, ...]) -> None:
    for change in changes[:MAX_DIAGNOSTICS]:
        print(
            f"{label}: {display_path(change.relative)}: {','.join(change.fields)}",
            file=sys.stderr,
        )
    remaining = len(changes) - MAX_DIAGNOSTICS
    if remaining > 0:
        print(f"{label}: {remaining} additional path changes omitted", file=sys.stderr)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    parser.add_argument("--output-record", type=Path)
    parser.add_argument("--compare-to", type=Path)
    parser.add_argument("--expected-record-sha256")
    args = parser.parse_args()
    if (args.compare_to is None) != (args.expected_record_sha256 is None):
        parser.error("--compare-to and --expected-record-sha256 must be used together")
    current = snapshot(args.root)
    if args.output_record is not None:
        write_snapshot_record(args.output_record, current)
    if args.compare_to is not None:
        baseline = load_snapshot_record(args.compare_to, args.expected_record_sha256)
        comparison = compare_snapshots(baseline, current)
        if comparison.protected:
            report_changes("protected source change", comparison.protected)
            return 1
        if comparison.observations:
            report_changes("source observation changed only", comparison.observations)
    print(current.protected_digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
