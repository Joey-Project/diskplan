#!/usr/bin/env python3
"""Hash an exact, bounded, no-follow release source snapshot."""

from __future__ import annotations

import argparse
import hashlib
import os
import stat
import struct
from pathlib import Path


MAX_ENTRIES = 100_000
MAX_FILE_BYTES = 512 * 1024 * 1024
MAX_TOTAL_BYTES = 4 * 1024 * 1024 * 1024
CHUNK_BYTES = 1024 * 1024


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


def hash_regular(path: Path, initial: os.stat_result) -> tuple[str, int]:
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
    return hasher.hexdigest(), consumed


def update_entry(
    hasher: "hashlib._Hash",
    relative: bytes,
    kind: bytes,
    metadata: os.stat_result,
    payload: bytes,
) -> None:
    hasher.update(frame(relative))
    hasher.update(frame(kind))
    hasher.update(frame(f"{stat.S_IMODE(metadata.st_mode):04o}".encode("ascii")))
    hasher.update(frame(str(metadata.st_size).encode("ascii")))
    hasher.update(frame(str(metadata.st_mtime_ns).encode("ascii")))
    hasher.update(frame(str(metadata.st_ctime_ns).encode("ascii")))
    hasher.update(frame(payload))


def snapshot_manifest(root: Path) -> str:
    root = root.absolute()
    root_metadata = root.lstat()
    if not stat.S_ISDIR(root_metadata.st_mode) or root.is_symlink():
        raise ValueError("source snapshot root must be a non-symlink directory")

    hasher = hashlib.sha256()
    entries = 0
    total_bytes = 0

    def walk(directory: Path, relative_prefix: bytes) -> None:
        nonlocal entries, total_bytes
        before = directory.lstat()
        if not stat.S_ISDIR(before.st_mode):
            raise ValueError(f"source directory was replaced: {directory}")
        children = sorted(os.scandir(directory), key=lambda entry: os.fsencode(entry.name))
        for child in children:
            entries += 1
            if entries > MAX_ENTRIES:
                raise ValueError(f"source snapshot exceeds {MAX_ENTRIES} entries")
            name = os.fsencode(child.name)
            relative = name if not relative_prefix else relative_prefix + b"/" + name
            path = Path(child.path)
            metadata = path.lstat()
            if stat.S_ISREG(metadata.st_mode):
                file_digest, file_bytes = hash_regular(path, metadata)
                total_bytes += file_bytes
                if total_bytes > MAX_TOTAL_BYTES:
                    raise ValueError(f"source snapshot exceeds {MAX_TOTAL_BYTES} bytes")
                update_entry(hasher, relative, b"file", metadata, file_digest.encode("ascii"))
            elif stat.S_ISDIR(metadata.st_mode):
                update_entry(hasher, relative, b"directory", metadata, b"")
                walk(path, relative)
            elif stat.S_ISLNK(metadata.st_mode):
                target = os.fsencode(os.readlink(path))
                final = path.lstat()
                if identity(metadata) != identity(final) or content_state(metadata) != content_state(final):
                    raise ValueError(f"source symlink changed while reading: {path}")
                update_entry(hasher, relative, b"symlink", metadata, target)
            else:
                raise ValueError(f"unsupported source snapshot entry: {path}")
        after = directory.lstat()
        if identity(before) != identity(after) or content_state(before) != content_state(after):
            raise ValueError(f"source directory changed while walking: {directory}")

    walk(root, b"")
    return hasher.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", type=Path)
    args = parser.parse_args()
    print(snapshot_manifest(args.root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
