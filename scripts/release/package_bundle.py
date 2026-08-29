#!/usr/bin/env python3
"""Build a deterministic Diskplan macOS arm64 release archive."""

from __future__ import annotations

import argparse
import ctypes
import errno
import hashlib
import io
import json
import os
import re
import secrets
import stat
import struct
import subprocess
import sys
import tarfile
import tempfile
import unicodedata
import zlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any, BinaryIO


SEMVER = re.compile(
    r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?$"
)
GIT_SHA = re.compile(r"^[0-9a-f]{40}$")
MACOS_VERSION = re.compile(r"^[0-9]+(?:\.[0-9]+){1,2}$")
MAX_BINARY_BYTES = 512 * 1024 * 1024
MAX_METADATA_BYTES = 64 * 1024
MAX_IDENTITY_BYTES = 4096
PROBE_TIMEOUT_SECONDS = 10
# Three bounded Mach-O files, metadata, tar padding, and gzip framing.
MAX_ARCHIVE_BYTES = 3 * MAX_BINARY_BYTES + 1024 * MAX_METADATA_BYTES
COPY_CHUNK_BYTES = 1024 * 1024
GZIP_LEVEL = 9
GZIP_HEADER = b"\x1f\x8b\x08\x00\x00\x00\x00\x00\x02\xff"
PINNED_ZLIB_VERSION = "1.2.12"
MANIFEST_SCHEMA_VERSION = "diskplan.bundle-manifest.v2"
CONTRACT_SCHEMA_VERSION = "diskplan.bundle-contract.v1"
MAX_CONTRACT_BYTES = 1024 * 1024
MAX_BUNDLE_ARTIFACTS = 4096
PATH_PATTERN = re.compile(r"^[A-Za-z0-9._/-]{1,1024}$")
COMPATIBILITY_PATTERN = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,127}$")
ROLE_PATTERN = re.compile(r"^[a-z][a-z0-9-]{0,63}$")
ALLOWED_ROLES = {
    "compatibility-fixture",
    "compatibility-fixture-documentation",
    "declarative-rules",
    "default-policy",
    "executable",
    "lifecycle-library",
    "lifecycle-script",
    "product-version",
    "protocol-metadata",
    "protocol-schema",
    "protocol-toolchain-lock",
    "protocol-version",
    "runtime-capability-manifest",
}
DERIVED_BUNDLE_FILES = {
    "manifest.json": (0o644, MAX_METADATA_BYTES),
    "SHA256SUMS": (0o644, MAX_METADATA_BYTES),
}
RENAME_EXCL = 0x00000004
ACL_TYPE_EXTENDED = 0x00000100
ACL_FIRST_ENTRY = 0


@dataclass(frozen=True)
class DirectorySlot:
    parent_fd: int
    name: str
    child_fd: int
    state: FileState


class BoundDirectory:
    """A directory reached through retained, no-follow descriptor slots."""

    def __init__(self, display_path: Path, descriptors: list[int], slots: list[DirectorySlot]):
        self.display_path = display_path
        self.descriptors = descriptors
        self.slots = slots
        self.fd = descriptors[-1]

    def assert_stable(self) -> None:
        for slot in self.slots:
            held = FileState.from_stat(os.fstat(slot.child_fd))
            try:
                named_metadata = os.stat(
                    slot.name,
                    dir_fd=slot.parent_fd,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise ValueError(
                    f"bound directory slot became unreadable: {self.display_path}"
                ) from error
            named = FileState.from_stat(named_metadata)
            if (
                not stat.S_ISDIR(named_metadata.st_mode)
                or not slot.state.same_object(held)
                or not slot.state.same_object(named)
            ):
                raise ValueError(f"bound directory slot was replaced: {self.display_path}")

    def close(self) -> None:
        for descriptor in reversed(self.descriptors):
            os.close(descriptor)
        self.descriptors = []


class BoundSource:
    """A regular-file descriptor plus every retained path slot used to reach it."""

    def __init__(
        self,
        display_path: Path,
        root: BoundDirectory,
        directory_fds: list[int],
        directory_slots: list[DirectorySlot],
        leaf_name: str,
        file_fd: int,
        maximum: int,
        owns_root: bool,
    ):
        self.display_path = display_path
        self.root = root
        self.directory_fds = directory_fds
        self.directory_slots = directory_slots
        self.leaf_name = leaf_name
        self.file_fd = file_fd
        self.maximum = maximum
        self.owns_root = owns_root

    @property
    def parent_fd(self) -> int:
        return self.directory_fds[-1] if self.directory_fds else self.root.fd

    def assert_stable(self) -> None:
        self.root.assert_stable()
        for slot in self.directory_slots:
            held = FileState.from_stat(os.fstat(slot.child_fd))
            try:
                named_metadata = os.stat(
                    slot.name,
                    dir_fd=slot.parent_fd,
                    follow_symlinks=False,
                )
            except OSError as error:
                raise ValueError(
                    f"source ancestor became unreadable: {self.display_path}"
                ) from error
            named = FileState.from_stat(named_metadata)
            if (
                not stat.S_ISDIR(named_metadata.st_mode)
                or not slot.state.same_object(held)
                or not slot.state.same_object(named)
            ):
                raise ValueError(f"source ancestor was replaced: {self.display_path}")
        try:
            named_metadata = os.stat(
                self.leaf_name,
                dir_fd=self.parent_fd,
                follow_symlinks=False,
            )
        except OSError as error:
            raise ValueError(f"source path became unreadable: {self.display_path}") from error
        held = FileState.from_stat(os.fstat(self.file_fd))
        named = FileState.from_stat(named_metadata)
        if (
            not stat.S_ISREG(named_metadata.st_mode)
            or not held.same_object(named)
        ):
            raise ValueError(f"source path was replaced: {self.display_path}")

    def close(self) -> None:
        os.close(self.file_fd)
        for descriptor in reversed(self.directory_fds):
            os.close(descriptor)
        self.directory_fds = []
        if self.owns_root:
            self.root.close()


@dataclass(frozen=True)
class FileState:
    device: int
    inode: int
    size: int
    mtime_ns: int
    ctime_ns: int

    @classmethod
    def from_stat(cls, value: os.stat_result) -> "FileState":
        return cls(
            device=value.st_dev,
            inode=value.st_ino,
            size=value.st_size,
            mtime_ns=value.st_mtime_ns,
            ctime_ns=value.st_ctime_ns,
        )

    def same_object(self, other: "FileState") -> bool:
        return (self.device, self.inode) == (other.device, other.inode)

    def same_content_state(self, other: "FileState") -> bool:
        return (
            self.size,
            self.mtime_ns,
            self.ctime_ns,
        ) == (
            other.size,
            other.mtime_ns,
            other.ctime_ns,
        )


@dataclass
class StagedFile:
    source: Path
    path: Path
    bound_source: BoundSource
    staged_fd: int
    source_state: FileState
    staged_state: FileState
    sha256: str
    maximum: int

    @property
    def source_fd(self) -> int:
        return self.bound_source.file_fd

    def assert_source_stable(self) -> None:
        self.bound_source.assert_stable()
        current = regular_file_state(self.source_fd, self.source, self.maximum)
        if not self.source_state.same_object(current):
            raise ValueError(f"source object identity changed: {self.source}")
        if self.source_state.size != current.size or digest_fd(
            self.source_fd, self.maximum
        ) != self.sha256:
            raise ValueError(f"source content changed: {self.source}")
        reopened = open_regular_at(
            self.bound_source.parent_fd,
            self.bound_source.leaf_name,
            self.source,
            self.maximum,
        )
        try:
            path_state = FileState.from_stat(os.fstat(reopened))
            path_digest = digest_fd(reopened, self.maximum)
        finally:
            os.close(reopened)
        if not self.source_state.same_object(path_state):
            raise ValueError(f"source path was replaced: {self.source}")
        if self.source_state.size != path_state.size or path_digest != self.sha256:
            raise ValueError(f"source path content changed: {self.source}")

    def assert_staged_stable(self) -> None:
        current = regular_file_state(self.staged_fd, self.path, self.maximum)
        if not self.staged_state.same_object(current):
            raise ValueError(f"staged object identity changed: {self.path}")
        if self.staged_state.size != current.size:
            raise ValueError(f"staged content state changed: {self.path}")
        reopened = open_regular_nofollow(self.path, self.maximum)
        try:
            path_state = FileState.from_stat(os.fstat(reopened))
            path_digest = digest_fd(reopened, self.maximum)
        finally:
            os.close(reopened)
        if not self.staged_state.same_object(path_state):
            raise ValueError(f"staged path was replaced: {self.path}")
        if self.staged_state.size != path_state.size or path_digest != self.sha256:
            raise ValueError(f"staged path content changed: {self.path}")
        if digest_fd(self.staged_fd, self.maximum) != self.sha256:
            raise ValueError(f"staged content digest changed: {self.path}")

    def bytes(self) -> bytes:
        self.assert_staged_stable()
        return read_fd(self.staged_fd, self.maximum)

    def close(self) -> None:
        self.bound_source.close()
        os.close(self.staged_fd)


@dataclass(frozen=True)
class ProbeResult:
    stdout: bytes
    returncode: int


@dataclass(frozen=True)
class BundleArtifactSpec:
    bundle_path: str
    compatibility_version: str
    maximum_bytes: int
    mode: int
    role: str
    source: str


def canonical_path_key(value: str) -> str:
    return unicodedata.normalize("NFC", value).casefold()


def validate_relative_path(value: Any, label: str) -> str:
    if type(value) is not str or not PATH_PATTERN.fullmatch(value):
        raise ValueError(f"{label} is not a canonical relative path")
    parts = value.split("/")
    if value.startswith("/") or any(part in {"", ".", ".."} for part in parts):
        raise ValueError(f"{label} contains an escaping or empty path component")
    return value


def canonical_compact_json(value: Any) -> bytes:
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def load_bundle_contract(
    source: Path | BoundSource,
) -> tuple[list[BundleArtifactSpec], list[str]]:
    path = source.display_path if isinstance(source, BoundSource) else source
    data = (
        read_fd(source.file_fd, MAX_CONTRACT_BYTES)
        if isinstance(source, BoundSource)
        else read_regular_file(path, MAX_CONTRACT_BYTES)
    )
    value = read_json_bytes(data, path)
    if data != canonical_compact_json(value):
        raise ValueError("bundle contract is not canonical JSON")
    if set(value) != {"artifacts", "excluded", "schema_version"}:
        raise ValueError("bundle contract has an unsupported shape")
    if value["schema_version"] != CONTRACT_SCHEMA_VERSION:
        raise ValueError("bundle contract schema version is unsupported")
    raw_artifacts = value["artifacts"]
    excluded = value["excluded"]
    if type(raw_artifacts) is not list or not 1 <= len(raw_artifacts) <= MAX_BUNDLE_ARTIFACTS:
        raise ValueError("bundle contract artifact count is invalid")
    if type(excluded) is not list or any(type(item) is not str for item in excluded):
        raise ValueError("bundle contract exclusions are invalid")
    if excluded != sorted(set(excluded), key=os.fsencode):
        raise ValueError("bundle contract exclusions must be unique and sorted")

    artifacts: list[BundleArtifactSpec] = []
    exact_paths: set[str] = set(DERIVED_BUNDLE_FILES)
    folded_paths = {canonical_path_key(item) for item in DERIVED_BUNDLE_FILES}
    sources: set[str] = set()
    expected_keys = {
        "bundle_path",
        "compatibility_version",
        "maximum_bytes",
        "mode",
        "role",
        "source",
    }
    for raw in raw_artifacts:
        if type(raw) is not dict or set(raw) != expected_keys:
            raise ValueError("bundle contract artifact has an unsupported shape")
        bundle_path = validate_relative_path(raw["bundle_path"], "bundle path")
        compatibility = raw["compatibility_version"]
        role = raw["role"]
        source = raw["source"]
        maximum = raw["maximum_bytes"]
        mode_text = raw["mode"]
        if (
            type(compatibility) is not str
            or not COMPATIBILITY_PATTERN.fullmatch(compatibility)
            or type(role) is not str
            or not ROLE_PATTERN.fullmatch(role)
            or role not in ALLOWED_ROLES
            or type(source) is not str
            or type(maximum) is not int
            or not 1 <= maximum <= MAX_BINARY_BYTES
            or mode_text not in {"0644", "0755"}
        ):
            raise ValueError(f"bundle contract metadata is invalid: {bundle_path}")
        if source.startswith("@"):
            if source not in {
                "@activator",
                "@common-library",
                "@engine",
                "@frontend",
                "@fs-helper",
                "@installer",
                "@protocol-metadata",
                "@protocol-version",
                "@uninstaller",
                "@version-file",
            }:
                raise ValueError(f"bundle contract source token is unsupported: {source}")
        else:
            validate_relative_path(source, "bundle source path")
        folded = canonical_path_key(bundle_path)
        if bundle_path in exact_paths or folded in folded_paths:
            raise ValueError(f"duplicate or case-fold-colliding bundle path: {bundle_path}")
        if source in sources:
            raise ValueError(f"bundle contract repeats a source: {source}")
        exact_paths.add(bundle_path)
        folded_paths.add(folded)
        sources.add(source)
        artifacts.append(
            BundleArtifactSpec(
                bundle_path=bundle_path,
                compatibility_version=compatibility,
                maximum_bytes=maximum,
                mode=int(mode_text, 8),
                role=role,
                source=source,
            )
        )
    if [item.bundle_path for item in artifacts] != sorted(
        (item.bundle_path for item in artifacts), key=os.fsencode
    ):
        raise ValueError("bundle contract artifacts must be sorted by canonical path bytes")
    directories = bundle_directories(list(exact_paths))
    file_keys = {canonical_path_key(item): item for item in exact_paths}
    for directory in directories:
        if canonical_path_key(directory) in file_keys:
            raise ValueError(
                f"bundle contract path is both a file and directory: {directory}"
            )
    return artifacts, excluded


def bundle_directories(paths: list[str]) -> list[str]:
    directories: set[str] = set()
    for path in paths:
        parts = path.split("/")[:-1]
        for index in range(1, len(parts) + 1):
            directories.add("/".join(parts[:index]))
    folded: dict[str, str] = {}
    for directory in directories:
        key = canonical_path_key(directory)
        if key in folded and folded[key] != directory:
            raise ValueError(f"case-fold-colliding bundle directories: {folded[key]} and {directory}")
        folded[key] = directory
    return sorted(directories, key=lambda item: (item.count("/"), os.fsencode(item)))


def render_c_bundle_contract(artifacts: list[BundleArtifactSpec]) -> bytes:
    records = [
        (
            item.bundle_path,
            item.mode,
            item.maximum_bytes,
            item.role,
            item.compatibility_version,
        )
        for item in artifacts
    ]
    records.extend(
        [
            (
                "manifest.json",
                0o644,
                MAX_METADATA_BYTES,
                "bundle-manifest",
                MANIFEST_SCHEMA_VERSION,
            ),
            ("SHA256SUMS", 0o644, MAX_METADATA_BYTES, "bundle-checksums", "sha256-v1"),
        ]
    )
    records.sort(key=lambda item: os.fsencode(item[0]))
    directories = bundle_directories([item[0] for item in records])
    lines = [
        "/* Generated from release/bundle-contract.json; do not edit directly. */",
        "static const struct artifact k_artifacts[] = {",
    ]
    for path, mode, maximum, role, compatibility in records:
        lines.append(
            f'    {{"{path}", 0{mode:o}, (off_t){maximum}, "{role}", "{compatibility}"}},'
        )
    lines.extend(
        [
            "};",
            "",
            "static const char *k_bundle_directories[] = {",
        ]
    )
    lines.extend(f'    "{directory}",' for directory in directories)
    lines.extend(["};", ""])
    return "\n".join(lines).encode("ascii")


class DeterministicGzipWriter(io.RawIOBase):
    """A gzip writer whose complete header, trailer, and level are fixed."""

    def __init__(self, raw: BinaryIO, maximum: int) -> None:
        super().__init__()
        self.raw = raw
        self.maximum = maximum
        self.compressor = zlib.compressobj(
            GZIP_LEVEL,
            zlib.DEFLATED,
            -zlib.MAX_WBITS,
            zlib.DEF_MEM_LEVEL,
            zlib.Z_DEFAULT_STRATEGY,
        )
        self.crc = 0
        self.input_size = 0
        self.output_size = 0
        self.finished = False
        self._write_raw(GZIP_HEADER)

    def writable(self) -> bool:
        return True

    def tell(self) -> int:
        return self.input_size

    def _write_raw(self, data: bytes) -> None:
        if self.output_size + len(data) > self.maximum:
            raise ValueError(f"archive exceeds {self.maximum} bytes")
        self.raw.write(data)
        self.output_size += len(data)

    def write(self, data: bytes | bytearray) -> int:
        if self.finished:
            raise ValueError("gzip stream is already finished")
        value = bytes(data)
        self.crc = zlib.crc32(value, self.crc)
        self.input_size = (self.input_size + len(value)) & 0xFFFFFFFFFFFFFFFF
        self._write_raw(self.compressor.compress(value))
        return len(value)

    def finish(self) -> None:
        if self.finished:
            return
        self._write_raw(self.compressor.flush(zlib.Z_FINISH))
        self._write_raw(struct.pack("<II", self.crc & 0xFFFFFFFF, self.input_size & 0xFFFFFFFF))
        self.finished = True


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--frontend", type=Path, required=True)
    parser.add_argument("--engine", type=Path, required=True)
    parser.add_argument("--fs-helper", type=Path, required=True)
    parser.add_argument("--installer", type=Path, required=True)
    parser.add_argument("--activator", type=Path, required=True)
    parser.add_argument("--uninstaller", type=Path, required=True)
    parser.add_argument("--common-library", type=Path, required=True)
    parser.add_argument("--version-file", type=Path, required=True)
    parser.add_argument("--protocol-metadata", type=Path, required=True)
    parser.add_argument("--asset-root", type=Path)
    parser.add_argument("--bundle-contract", type=Path)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    # Retained for callers of the original interface. Validation is unconditional.
    parser.add_argument("--require-macho-arm64", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def _directory_open_flags() -> int:
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return flags


def _open_directory_at(parent_fd: int, name: str, display_path: Path) -> int:
    try:
        descriptor = os.open(name, _directory_open_flags(), dir_fd=parent_fd)
    except OSError as error:
        raise ValueError(f"cannot bind directory without following links: {display_path}") from error
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise ValueError(f"not a directory: {display_path}")
    return descriptor


def bind_absolute_directory(path: Path) -> BoundDirectory:
    """Bind an absolute directory while rejecting a symlink at the caller-selected leaf."""
    if not path.is_absolute():
        raise ValueError(f"directory path must be absolute: {path}")
    if path == Path("/"):
        descriptor = os.open("/", _directory_open_flags())
        return BoundDirectory(path, [descriptor], [])

    # Resolving only the parent accommodates platform aliases such as /var -> /private/var,
    # while the selected leaf is always opened with O_NOFOLLOW.
    canonical_parent = path.parent.resolve(strict=True)
    components = list(canonical_parent.parts[1:]) + [path.name]
    descriptors = [os.open("/", _directory_open_flags())]
    slots: list[DirectorySlot] = []
    try:
        for index, component in enumerate(components):
            child = _open_directory_at(
                descriptors[-1],
                component,
                Path("/").joinpath(*components[: index + 1]),
            )
            state = FileState.from_stat(os.fstat(child))
            slots.append(DirectorySlot(descriptors[-1], component, child, state))
            descriptors.append(child)
        bound = BoundDirectory(path, descriptors, slots)
        bound.assert_stable()
        return bound
    except Exception:
        for descriptor in reversed(descriptors):
            os.close(descriptor)
        raise


def open_regular_at(
    parent_fd: int,
    name: str,
    display_path: Path,
    maximum: int,
) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(name, flags, dir_fd=parent_fd)
    except OSError as error:
        raise ValueError(f"cannot safely open regular file: {display_path}") from error
    try:
        regular_file_state(descriptor, display_path, maximum)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def bind_relative_source(
    root: BoundDirectory,
    relative: str,
    maximum: int,
) -> BoundSource:
    validate_relative_path(relative, "repository source path")
    root.assert_stable()
    components = relative.split("/")
    directory_fds: list[int] = []
    directory_slots: list[DirectorySlot] = []
    file_fd = -1
    parent_fd = root.fd
    try:
        for index, component in enumerate(components[:-1]):
            child = _open_directory_at(
                parent_fd,
                component,
                root.display_path.joinpath(*components[: index + 1]),
            )
            state = FileState.from_stat(os.fstat(child))
            directory_slots.append(DirectorySlot(parent_fd, component, child, state))
            directory_fds.append(child)
            parent_fd = child
        display_path = root.display_path / relative
        file_fd = open_regular_at(parent_fd, components[-1], display_path, maximum)
        bound = BoundSource(
            display_path,
            root,
            directory_fds,
            directory_slots,
            components[-1],
            file_fd,
            maximum,
            False,
        )
        bound.assert_stable()
        return bound
    except Exception:
        if file_fd >= 0:
            os.close(file_fd)
        for descriptor in reversed(directory_fds):
            os.close(descriptor)
        raise


def bind_absolute_source(path: Path, maximum: int) -> BoundSource:
    if not path.is_absolute():
        raise ValueError(f"source path must be absolute: {path}")
    parent = bind_absolute_directory(path.parent)
    file_fd = -1
    try:
        file_fd = open_regular_at(parent.fd, path.name, path, maximum)
        bound = BoundSource(path, parent, [], [], path.name, file_fd, maximum, True)
        bound.assert_stable()
        return bound
    except Exception:
        if file_fd >= 0:
            os.close(file_fd)
        parent.close()
        raise


def require_safe_repository_source(
    root: BoundDirectory | Path,
    relative: str,
    maximum: int = MAX_BINARY_BYTES,
) -> BoundSource:
    if isinstance(root, BoundDirectory):
        return bind_relative_source(root, relative, maximum)
    bound_root = bind_absolute_directory(root)
    try:
        source = bind_relative_source(bound_root, relative, maximum)
        source.owns_root = True
        return source
    except Exception:
        bound_root.close()
        raise


def regular_file_state(fd: int, display_path: Path, maximum: int) -> FileState:
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"not a regular file: {display_path}")
    if metadata.st_size > maximum:
        raise ValueError(f"file exceeds {maximum} bytes: {display_path}")
    return FileState.from_stat(metadata)


def open_regular_nofollow(path: Path, maximum: int) -> int:
    bound = bind_absolute_source(path, maximum)
    descriptor = os.dup(bound.file_fd)
    bound.close()
    return descriptor


def read_fd(fd: int, maximum: int) -> bytes:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise ValueError("descriptor is not a bounded regular file")
    chunks: list[bytes] = []
    consumed = 0
    offset = 0
    while chunk := os.pread(fd, min(COPY_CHUNK_BYTES, maximum - consumed + 1), offset):
        consumed += len(chunk)
        if consumed > maximum:
            raise ValueError(f"file grew beyond {maximum} bytes")
        chunks.append(chunk)
        offset += len(chunk)
    after = os.fstat(fd)
    if consumed != before.st_size:
        raise ValueError("file size changed while reading")
    if not FileState.from_stat(before).same_object(FileState.from_stat(after)):
        raise ValueError("file object identity changed while reading")
    if not FileState.from_stat(before).same_content_state(FileState.from_stat(after)):
        raise ValueError("file content state changed while reading")
    return b"".join(chunks)


def digest_fd(fd: int, maximum: int) -> str:
    before = os.fstat(fd)
    if not stat.S_ISREG(before.st_mode) or before.st_size > maximum:
        raise ValueError("descriptor is not a bounded regular file")
    hasher = hashlib.sha256()
    consumed = 0
    offset = 0
    while chunk := os.pread(fd, min(COPY_CHUNK_BYTES, maximum - consumed + 1), offset):
        consumed += len(chunk)
        if consumed > maximum:
            raise ValueError(f"file grew beyond {maximum} bytes")
        hasher.update(chunk)
        offset += len(chunk)
    after = os.fstat(fd)
    if consumed != before.st_size:
        raise ValueError("file size changed while hashing")
    if not FileState.from_stat(before).same_object(FileState.from_stat(after)):
        raise ValueError("file object identity changed while hashing")
    if not FileState.from_stat(before).same_content_state(FileState.from_stat(after)):
        raise ValueError("file content state changed while hashing")
    return hasher.hexdigest()


def write_all(fd: int, data: bytes) -> None:
    view = memoryview(data)
    while view:
        written = os.write(fd, view)
        if written <= 0:
            raise OSError("short write while staging release input")
        view = view[written:]


def create_exclusive_file(path: Path, mode: int) -> int:
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    return os.open(path, flags, mode)


def stage_source(
    source: Path | BoundSource,
    destination: Path,
    maximum: int,
    mode: int,
) -> StagedFile:
    bound_source = (
        source if isinstance(source, BoundSource) else bind_absolute_source(source, maximum)
    )
    if bound_source.maximum != maximum:
        bound_source.close()
        raise ValueError("bound source byte limit does not match artifact contract")
    source_path = bound_source.display_path
    source_fd = bound_source.file_fd
    staged_fd = -1
    try:
        source_state = regular_file_state(source_fd, source_path, maximum)
        staged_fd = create_exclusive_file(destination, 0o600)
        hasher = hashlib.sha256()
        consumed = 0
        while True:
            chunk = os.read(source_fd, COPY_CHUNK_BYTES)
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum:
                raise ValueError(f"file grew beyond {maximum} bytes: {source_path}")
            write_all(staged_fd, chunk)
            hasher.update(chunk)
        if consumed != source_state.size:
            raise ValueError(f"file size changed while staging: {source_path}")
        os.fchmod(staged_fd, mode)
        os.fsync(staged_fd)
        staged_state = regular_file_state(staged_fd, destination, maximum)
        staged = StagedFile(
            source=source_path,
            path=destination,
            bound_source=bound_source,
            staged_fd=staged_fd,
            source_state=source_state,
            staged_state=staged_state,
            sha256=hasher.hexdigest(),
            maximum=maximum,
        )
        staged.assert_source_stable()
        staged.assert_staged_stable()
        return staged
    except Exception:
        bound_source.close()
        if staged_fd >= 0:
            os.close(staged_fd)
        destination.unlink(missing_ok=True)
        raise


def read_json_bytes(data: bytes, display_path: Path) -> dict[str, Any]:
    value = json.loads(data)
    if type(value) is not dict:
        raise ValueError(f"expected a JSON object: {display_path}")
    return value


def canonical_json(value: Any) -> bytes:
    return (json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n").encode(
        "ascii"
    )


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def require_pinned_zlib() -> None:
    if (
        zlib.ZLIB_VERSION != PINNED_ZLIB_VERSION
        or zlib.ZLIB_RUNTIME_VERSION != PINNED_ZLIB_VERSION
    ):
        raise RuntimeError(
            "deterministic release compression requires zlib "
            f"{PINNED_ZLIB_VERSION} at compile time and runtime"
        )


def bounded_probe_failure_summary(report: Any, supervisor_returncode: int) -> str:
    """Render fixed report fields without retaining command output."""

    summary: dict[str, Any] = {"supervisor_returncode": supervisor_returncode}
    if type(report) is not dict:
        summary["report_type"] = type(report).__name__
        return json.dumps(summary, sort_keys=True, separators=(",", ":"))

    for key in ("exit_code", "leader_exit_code", "elapsed_millis", "output_bytes"):
        value = report.get(key)
        if value is None and key == "leader_exit_code":
            summary[key] = None
        elif type(value) is int:
            summary[key] = value

    for key in ("process_group_verified",):
        value = report.get(key)
        if type(value) is bool:
            summary[key] = value

    for key in ("result", "error_type", "termination_signal"):
        value = report.get(key)
        if type(value) is str and re.fullmatch(r"[A-Za-z0-9_.+-]{1,128}", value):
            summary[key] = value

    cleanup = report.get("cleanup")
    if type(cleanup) is dict:
        safe_cleanup = {
            key: cleanup[key]
            for key in (
                "attempted",
                "term_attempted",
                "term_sent",
                "kill_attempted",
                "kill_sent",
                "quiescent",
            )
            if type(cleanup.get(key)) is bool
        }
        if safe_cleanup:
            summary["cleanup"] = safe_cleanup
    return json.dumps(summary, sort_keys=True, separators=(",", ":"))


def run_staged(file: StagedFile, command: list[str], label: str) -> ProbeResult:
    file.assert_staged_stable()
    supervisor = Path(__file__).resolve().with_name("run_bounded.py")
    if not supervisor.is_file() or supervisor.is_symlink():
        raise ValueError("bounded probe supervisor is missing or unsafe")
    output = file.path.parent / f".probe-{secrets.token_hex(16)}.output"
    try:
        completed = subprocess.run(
            [
                sys.executable,
                str(supervisor),
                "--timeout-seconds",
                str(PROBE_TIMEOUT_SECONDS),
                "--max-output-bytes",
                str(MAX_IDENTITY_BYTES),
                "--output",
                str(output),
                "--",
                *command,
            ],
            check=False,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if len(completed.stdout) > MAX_METADATA_BYTES or len(completed.stderr) > MAX_METADATA_BYTES:
            raise ValueError(f"bounded supervisor output was excessive for {label}")
        if completed.stderr:
            raise ValueError(f"bounded supervisor wrote to stderr for {label}")
        try:
            report = json.loads(completed.stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise ValueError(f"bounded supervisor returned a malformed report for {label}") from error
        if (
            type(report) is not dict
            or report.get("result") != "passed"
            or report.get("exit_code") != 0
            or report.get("process_group_verified") is not True
            or type(report.get("cleanup")) is not dict
            or report["cleanup"].get("quiescent") is not True
            or completed.returncode != 0
        ):
            summary = bounded_probe_failure_summary(report, completed.returncode)
            raise ValueError(
                f"{label} failed its bounded process-group probe; "
                f"supervisor report {summary}"
            )
        probe_output = read_regular_file(output, MAX_IDENTITY_BYTES)
        file.assert_staged_stable()
        return ProbeResult(stdout=probe_output, returncode=completed.returncode)
    finally:
        output.unlink(missing_ok=True)
        file.assert_staged_stable()


def component_identity(file: StagedFile, expected_component: str) -> dict[str, Any]:
    completed = run_staged(
        file,
        [str(file.path), "--version-json"],
        f"{expected_component} --version-json",
    )
    if len(completed.stdout) > MAX_IDENTITY_BYTES:
        raise ValueError(
            f"{expected_component} --version-json exceeded {MAX_IDENTITY_BYTES} bytes"
        )
    try:
        identity = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{expected_component} returned malformed version JSON") from error
    if type(identity) is not dict or identity.get("component") != expected_component:
        raise ValueError(f"{expected_component} returned the wrong component identity")
    expected_keys = {
        "component",
        "product_version",
        "protocol_major",
        "protocol_minor",
    }
    if set(identity) != expected_keys:
        raise ValueError(f"{expected_component} returned an unsupported identity shape")
    if (
        type(identity["product_version"]) is not str
        or type(identity["protocol_major"]) is not int
        or type(identity["protocol_minor"]) is not int
    ):
        raise ValueError(f"{expected_component} returned identity fields with wrong types")
    return identity


def helper_identity(file: StagedFile) -> dict[str, Any]:
    completed = run_staged(
        file,
        [str(file.path), "--version-json"],
        "diskplan-fs-helper --version-json",
    )
    if len(completed.stdout) > MAX_IDENTITY_BYTES:
        raise ValueError(
            f"diskplan-fs-helper --version-json exceeded {MAX_IDENTITY_BYTES} bytes"
        )
    try:
        identity = json.loads(completed.stdout)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError("diskplan-fs-helper returned malformed version JSON") from error
    expected_keys = {
        "component",
        "product_version",
        "protocol_major",
        "protocol_minor",
        "helper_abi",
    }
    if type(identity) is not dict or set(identity) != expected_keys:
        raise ValueError("diskplan-fs-helper returned an unsupported identity shape")
    if identity["component"] != "diskplan-fs-helper":
        raise ValueError("diskplan-fs-helper returned the wrong component identity")
    if (
        type(identity["product_version"]) is not str
        or type(identity["protocol_major"]) is not int
        or type(identity["protocol_minor"]) is not int
        or type(identity["helper_abi"]) is not int
        or identity["helper_abi"] != 1
    ):
        raise ValueError("diskplan-fs-helper returned identity fields with wrong values")
    return identity


def version_tuple(value: str) -> tuple[int, int, int]:
    if not MACOS_VERSION.fullmatch(value):
        raise ValueError(f"invalid macOS version: {value}")
    parts = [int(part) for part in value.split(".")]
    padded = parts + [0, 0]
    return padded[0], padded[1], padded[2]


def parse_vtool_build(output: bytes, path: Path) -> tuple[str, str]:
    try:
        lines = [line.strip() for line in output.decode("ascii", errors="strict").splitlines()]
    except UnicodeDecodeError as error:
        raise ValueError(f"vtool returned non-ASCII output: {path}") from error
    contracts: list[tuple[str, str]] = []
    index = 0
    while index < len(lines):
        line = lines[index]
        if line == "cmd LC_BUILD_VERSION":
            platform = ""
            minimum = ""
            index += 1
            while index < len(lines) and not lines[index].startswith("cmd "):
                fields = lines[index].split()
                if len(fields) == 2 and fields[0] == "platform":
                    platform = fields[1]
                elif len(fields) == 2 and fields[0] == "minos":
                    minimum = fields[1]
                index += 1
            contracts.append((platform, minimum))
            continue
        if line == "cmd LC_VERSION_MIN_MACOSX":
            minimum = ""
            index += 1
            while index < len(lines) and not lines[index].startswith("cmd "):
                fields = lines[index].split()
                if len(fields) == 2 and fields[0] == "version":
                    minimum = fields[1]
                index += 1
            contracts.append(("MACOS", minimum))
            continue
        index += 1
    if len(contracts) != 1:
        raise ValueError(f"Mach-O must contain exactly one macOS build contract: {path}")
    return contracts[0]


def require_macho_contract(file: StagedFile, deployment_target: str) -> None:
    lipo = run_staged(
        file,
        ["/usr/bin/lipo", "-archs", str(file.path)],
        f"lipo probe for {file.path.name}",
    )
    try:
        arches = lipo.stdout.decode("ascii", errors="strict").split()
    except UnicodeDecodeError as error:
        raise ValueError(f"lipo returned non-ASCII output: {file.path}") from error
    if arches != ["arm64"]:
        raise ValueError(f"release binary is not exact arm64 Mach-O: {file.path}")

    vtool = run_staged(
        file,
        ["/usr/bin/vtool", "-arch", "arm64", "-show-build", str(file.path)],
        f"vtool probe for {file.path.name}",
    )
    platform, minimum = parse_vtool_build(vtool.stdout, file.path)
    if platform != "MACOS" or version_tuple(minimum) != version_tuple(deployment_target):
        raise ValueError(
            f"release binary has wrong platform or minimum macOS version: {file.path}"
        )


def validate_macho_components(
    staged: dict[str, StagedFile], deployment_target: str
) -> None:
    for name in ("diskplan", "diskplan-engine", "diskplan-fs-helper"):
        require_macho_contract(staged[name], deployment_target)


def validate_protocol(metadata: dict[str, Any]) -> None:
    expected_types = {
        "architecture": str,
        "bundle_format": int,
        "deployment_target_macos": str,
        "protocol_major": int,
        "protocol_minor": int,
        "release_gate_macos": str,
        "required_capabilities": list,
    }
    if set(metadata) != set(expected_types):
        raise ValueError("protocol metadata has an unsupported shape")
    for key, expected_type in expected_types.items():
        if type(metadata[key]) is not expected_type:
            raise ValueError(f"protocol metadata field has wrong type: {key}")
    if metadata["architecture"] != "arm64" or metadata["bundle_format"] != 1:
        raise ValueError("unsupported release architecture or bundle format")
    if metadata["protocol_major"] < 1 or metadata["protocol_minor"] < 0:
        raise ValueError("invalid protocol version")
    version_tuple(metadata["deployment_target_macos"])
    version_tuple(metadata["release_gate_macos"])
    capabilities = metadata["required_capabilities"]
    if (
        any(type(item) is not str or not item for item in capabilities)
        or capabilities != sorted(set(capabilities))
    ):
        raise ValueError("required capabilities must be unique and sorted")


def write_private_file(path: Path, data: bytes, mode: int) -> dict[str, Any]:
    descriptor = create_exclusive_file(path, 0o600)
    try:
        write_all(descriptor, data)
        os.fchmod(descriptor, mode)
        os.fsync(descriptor)
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode) or metadata.st_size != len(data):
            raise ValueError(f"staged bundle artifact changed: {path}")
    finally:
        os.close(descriptor)
    return {
        "path": path.name,
        "mode": f"{mode:04o}",
        "sha256": digest(data),
        "size": len(data),
    }


def write_bundle_artifact(
    bundle: Path, spec: BundleArtifactSpec, data: bytes
) -> dict[str, Any]:
    if len(data) > spec.maximum_bytes:
        raise ValueError(f"bundle artifact exceeds its contract limit: {spec.bundle_path}")
    path = bundle / spec.bundle_path
    result = write_private_file(path, data, spec.mode)
    result["path"] = spec.bundle_path
    result["role"] = spec.role
    result["compatibility_version"] = spec.compatibility_version
    return result


def read_regular_file(path: Path, maximum: int) -> bytes:
    descriptor = open_regular_nofollow(path, maximum)
    try:
        before = regular_file_state(descriptor, path, maximum)
        data = read_fd(descriptor, maximum)
        after = regular_file_state(descriptor, path, maximum)
        if not before.same_object(after) or not before.same_content_state(after):
            raise ValueError(f"file changed while reading: {path}")
        return data
    finally:
        os.close(descriptor)


def make_bundle_directories(bundle: Path, paths: list[str]) -> None:
    for relative in bundle_directories(paths):
        path = bundle / relative
        path.mkdir(mode=0o700)
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(path, flags)
        try:
            os.fchmod(descriptor, 0o755)
            held_metadata = os.fstat(descriptor)
            named_metadata = path.lstat()
            held = FileState.from_stat(held_metadata)
            named = FileState.from_stat(named_metadata)
            if (
                not stat.S_ISDIR(held_metadata.st_mode)
                or stat.S_IMODE(held_metadata.st_mode) != 0o755
                or not held.same_object(named)
            ):
                raise ValueError(f"cannot create exact bundle directory: {relative}")
        finally:
            os.close(descriptor)


def validate_runtime_capabilities(data: bytes, display_path: Path) -> None:
    value = read_json_bytes(data, display_path)
    if data != canonical_compact_json(value):
        raise ValueError("runtime capability manifest is not canonical JSON")
    if set(value) != {"capabilities", "schema_version"} or value["schema_version"] != (
        "diskplan.runtime-capabilities.v1"
    ):
        raise ValueError("runtime capability manifest schema is unsupported")
    capabilities = value["capabilities"]
    if type(capabilities) is not list or not capabilities:
        raise ValueError("runtime capability manifest is empty")
    expected_keys = {"default_enabled", "id", "kind", "package_effect"}
    ids: list[str] = []
    for capability in capabilities:
        if (
            type(capability) is not dict
            or set(capability) != expected_keys
            or capability["default_enabled"] is not False
            or capability["kind"] != "optional-persistence"
            or capability["package_effect"] != "declaration-only"
            or type(capability["id"]) is not str
            or not ROLE_PATTERN.fullmatch(capability["id"])
        ):
            raise ValueError("runtime capability manifest entry is unsupported")
        ids.append(capability["id"])
    if ids != sorted(set(ids), key=os.fsencode):
        raise ValueError("runtime capabilities must be unique and sorted")


def validate_emitted_manifest(value: Any) -> list[dict[str, Any]]:
    expected_keys = {
        "architecture",
        "artifacts",
        "bundle_format",
        "deployment_target_macos",
        "excluded_inputs",
        "manifest_schema_version",
        "optional_capabilities",
        "product_version",
        "protocol_major",
        "protocol_minor",
        "release_gate_macos",
        "required_capabilities",
        "source_revision",
    }
    if type(value) is not dict or set(value) != expected_keys:
        raise ValueError("bundle manifest has an unsupported shape")
    if value["manifest_schema_version"] != MANIFEST_SCHEMA_VERSION:
        raise ValueError("bundle manifest schema version is unsupported")
    if not GIT_SHA.fullmatch(value.get("source_revision", "")):
        raise ValueError("bundle manifest source revision is invalid")
    if (
        value["architecture"] != "arm64"
        or type(value["bundle_format"]) is not int
        or value["bundle_format"] != 1
        or type(value["deployment_target_macos"]) is not str
        or type(value["release_gate_macos"]) is not str
        or type(value["product_version"]) is not str
        or not SEMVER.fullmatch(value["product_version"])
        or type(value["protocol_major"]) is not int
        or value["protocol_major"] < 1
        or type(value["protocol_minor"]) is not int
        or value["protocol_minor"] < 0
    ):
        raise ValueError("bundle manifest product or platform contract is invalid")
    version_tuple(value["deployment_target_macos"])
    version_tuple(value["release_gate_macos"])
    if (
        type(value["required_capabilities"]) is not list
        or any(type(item) is not str or not item for item in value["required_capabilities"])
        or value["required_capabilities"]
        != sorted(set(value["required_capabilities"]), key=os.fsencode)
    ):
        raise ValueError("bundle manifest required capabilities are invalid")
    artifacts = value["artifacts"]
    if type(artifacts) is not list or not 1 <= len(artifacts) <= MAX_BUNDLE_ARTIFACTS:
        raise ValueError("bundle manifest artifact count is invalid")
    expected_artifact_keys = {
        "compatibility_version",
        "mode",
        "path",
        "role",
        "sha256",
        "size",
    }
    paths: list[str] = []
    folded: set[str] = set()
    for item in artifacts:
        if type(item) is not dict or set(item) != expected_artifact_keys:
            raise ValueError("bundle manifest artifact has an unsupported shape")
        path = validate_relative_path(item["path"], "manifest artifact path")
        if (
            item["mode"] not in {"0644", "0755"}
            or type(item["size"]) is not int
            or item["size"] < 0
            or type(item["sha256"]) is not str
            or not re.fullmatch(r"[0-9a-f]{64}", item["sha256"])
            or type(item["role"]) is not str
            or item["role"] not in ALLOWED_ROLES
            or type(item["compatibility_version"]) is not str
            or not COMPATIBILITY_PATTERN.fullmatch(item["compatibility_version"])
        ):
            raise ValueError(f"bundle manifest artifact metadata is invalid: {path}")
        key = canonical_path_key(path)
        if key in folded:
            raise ValueError(f"bundle manifest path collision: {path}")
        folded.add(key)
        paths.append(path)
    if paths != sorted(paths, key=os.fsencode):
        raise ValueError("bundle manifest artifacts are not canonically ordered")
    if (
        type(value["excluded_inputs"]) is not list
        or any(type(item) is not str for item in value["excluded_inputs"])
        or value["excluded_inputs"]
        != sorted(set(value["excluded_inputs"]), key=os.fsencode)
    ):
        raise ValueError("bundle manifest exclusions are invalid")
    if (
        type(value["optional_capabilities"]) is not list
        or any(type(item) is not str for item in value["optional_capabilities"])
        or value["optional_capabilities"]
        != sorted(set(value["optional_capabilities"]), key=os.fsencode)
    ):
        raise ValueError("bundle manifest optional capabilities are invalid")
    return artifacts


def enumerate_bundle_tree(bundle: Path) -> tuple[list[str], list[str]]:
    files: list[str] = []
    directories: list[str] = []
    pending: list[tuple[Path, str]] = [(bundle, "")]
    entries = 0
    while pending:
        directory, prefix = pending.pop()
        with os.scandir(directory) as iterator:
            children = sorted(iterator, key=lambda item: os.fsencode(item.name))
        local_folded: set[str] = set()
        for child in children:
            entries += 1
            if entries > MAX_BUNDLE_ARTIFACTS * 4:
                raise ValueError("bundle tree contains too many entries")
            key = canonical_path_key(child.name)
            if key in local_folded:
                raise ValueError(f"bundle directory contains a case-fold collision: {prefix}")
            local_folded.add(key)
            relative = f"{prefix}/{child.name}" if prefix else child.name
            validate_relative_path(relative, "bundle tree path")
            metadata = child.stat(follow_symlinks=False)
            if stat.S_ISREG(metadata.st_mode):
                files.append(relative)
            elif stat.S_ISDIR(metadata.st_mode):
                directories.append(relative)
                pending.append((Path(child.path), relative))
            else:
                raise ValueError(f"bundle contains a symlink or special file: {relative}")
    return sorted(files, key=os.fsencode), sorted(
        directories, key=lambda item: (item.count("/"), os.fsencode(item))
    )


def enumerate_bound_bundle_tree(root: BoundDirectory) -> tuple[list[str], list[str]]:
    files: list[str] = []
    directories: list[str] = []
    pending: list[tuple[int, str]] = [(os.dup(root.fd), "")]
    retained: list[int] = []
    entries = 0
    try:
        while pending:
            directory_fd, prefix = pending.pop()
            retained.append(directory_fd)
            with os.scandir(directory_fd) as iterator:
                children = sorted(iterator, key=lambda item: os.fsencode(item.name))
            local_folded: set[str] = set()
            for child in children:
                entries += 1
                if entries > MAX_BUNDLE_ARTIFACTS * 4:
                    raise ValueError("bundle tree contains too many entries")
                key = canonical_path_key(child.name)
                if key in local_folded:
                    raise ValueError(
                        f"bundle directory contains a case-fold collision: {prefix}"
                    )
                local_folded.add(key)
                relative = f"{prefix}/{child.name}" if prefix else child.name
                validate_relative_path(relative, "bundle tree path")
                metadata = os.stat(
                    child.name,
                    dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                if stat.S_ISREG(metadata.st_mode):
                    files.append(relative)
                elif stat.S_ISDIR(metadata.st_mode):
                    if stat.S_IMODE(metadata.st_mode) != 0o755:
                        raise ValueError(f"bundle directory has wrong mode: {relative}")
                    nested = _open_directory_at(directory_fd, child.name, Path(relative))
                    rebound = os.fstat(nested)
                    if not FileState.from_stat(metadata).same_object(
                        FileState.from_stat(rebound)
                    ):
                        os.close(nested)
                        raise ValueError(f"bundle directory was replaced: {relative}")
                    directories.append(relative)
                    pending.append((nested, relative))
                else:
                    raise ValueError(
                        f"bundle contains a symlink or special file: {relative}"
                    )
        return sorted(files, key=os.fsencode), sorted(
            directories,
            key=lambda item: (item.count("/"), os.fsencode(item)),
        )
    finally:
        for descriptor, _prefix in pending:
            os.close(descriptor)
        for descriptor in retained:
            os.close(descriptor)


class VerifiedBundle:
    def __init__(
        self,
        root: BoundDirectory,
        expected: dict[str, tuple[int, int]],
        manifest_data: bytes,
        files: dict[str, BoundSource],
        digests: dict[str, str],
    ):
        self.root = root
        self.expected = expected
        self.manifest_data = manifest_data
        self.files = files
        self.digests = digests

    def assert_stable(self) -> None:
        self.root.assert_stable()
        names, directories = enumerate_bound_bundle_tree(self.root)
        if names != sorted(self.expected, key=os.fsencode):
            raise ValueError("bundle contains missing or extra files")
        if directories != bundle_directories(list(self.expected)):
            raise ValueError("bundle contains missing or extra directories")
        for relative, source in self.files.items():
            source.assert_stable()
            metadata = os.fstat(source.file_fd)
            mode, size = self.expected[relative]
            if stat.S_IMODE(metadata.st_mode) != mode or metadata.st_size != size:
                raise ValueError(f"bundle file mode or size changed: {relative}")
            if digest_fd(source.file_fd, max(size, 1)) != self.digests[relative]:
                raise ValueError(f"bundle file digest changed: {relative}")

    def bytes(self, relative: str) -> bytes:
        source = self.files[relative]
        mode, size = self.expected[relative]
        source.assert_stable()
        metadata = os.fstat(source.file_fd)
        if stat.S_IMODE(metadata.st_mode) != mode or metadata.st_size != size:
            raise ValueError(f"bundle file mode or size changed: {relative}")
        data = read_fd(source.file_fd, max(size, 1))
        if digest(data) != self.digests[relative]:
            raise ValueError(f"bundle file digest changed: {relative}")
        return data

    def close(self) -> None:
        for source in self.files.values():
            source.close()
        self.files = {}
        self.root.close()


def bind_verified_bundle(bundle: Path) -> VerifiedBundle:
    root = bind_absolute_directory(bundle)
    files: dict[str, BoundSource] = {}
    try:
        manifest_source = bind_relative_source(root, "manifest.json", MAX_METADATA_BYTES)
        files["manifest.json"] = manifest_source
        manifest_data = read_fd(manifest_source.file_fd, MAX_METADATA_BYTES)
        manifest = read_json_bytes(manifest_data, bundle / "manifest.json")
        if manifest_data != canonical_json(manifest):
            raise ValueError("bundle manifest is not canonical JSON")
        artifacts = validate_emitted_manifest(manifest)
        expected: dict[str, tuple[int, int]] = {
            item["path"]: (int(item["mode"], 8), item["size"]) for item in artifacts
        }
        expected.update(
            {
                "manifest.json": (0o644, len(manifest_data)),
                "SHA256SUMS": (0o644, -1),
            }
        )
        names, directories = enumerate_bound_bundle_tree(root)
        if names != sorted(expected, key=os.fsencode):
            raise ValueError("bundle contains missing or extra files")
        if directories != bundle_directories(list(expected)):
            raise ValueError("bundle contains missing or extra directories")
        digests: dict[str, str] = {"manifest.json": digest(manifest_data)}
        checksummed: list[tuple[str, str]] = []
        for item in artifacts:
            source = bind_relative_source(root, item["path"], max(item["size"], 1))
            files[item["path"]] = source
            metadata = os.fstat(source.file_fd)
            if stat.S_IMODE(metadata.st_mode) != int(item["mode"], 8):
                raise ValueError(f"bundle file has wrong mode: {item['path']}")
            if metadata.st_size != item["size"]:
                raise ValueError(f"bundle file has wrong size: {item['path']}")
            if digest_fd(source.file_fd, max(item["size"], 1)) != item["sha256"]:
                raise ValueError(f"bundle file digest mismatch: {item['path']}")
            digests[item["path"]] = item["sha256"]
            checksummed.append((item["path"], item["sha256"]))
        checksummed.append(("manifest.json", digest(manifest_data)))
        expected_sums = "".join(
            f"{sha256}  {path}\n"
            for path, sha256 in sorted(
                checksummed, key=lambda item: os.fsencode(item[0])
            )
        ).encode("ascii")
        sums_source = bind_relative_source(root, "SHA256SUMS", MAX_METADATA_BYTES)
        files["SHA256SUMS"] = sums_source
        sums_data = read_fd(sums_source.file_fd, MAX_METADATA_BYTES)
        if sums_data != expected_sums:
            raise ValueError("SHA256SUMS does not cover the exact manifested bundle")
        expected["SHA256SUMS"] = (0o644, len(sums_data))
        digests["SHA256SUMS"] = digest(sums_data)
        verified = VerifiedBundle(root, expected, manifest_data, files, digests)
        verified.assert_stable()
        return verified
    except Exception:
        for source in files.values():
            source.close()
        root.close()
        raise


def verify_bundle_tree(bundle: Path) -> tuple[dict[str, tuple[int, int]], bytes]:
    verified = bind_verified_bundle(bundle)
    try:
        return verified.expected, verified.manifest_data
    finally:
        verified.close()


def add_tar_directory(archive: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name=name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "wheel"
    info.mtime = 0
    archive.addfile(info)


def add_tar_file(
    archive: tarfile.TarFile, data: bytes, name: str, expected_mode: int
) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mode = expected_mode
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "wheel"
    info.mtime = 0
    archive.addfile(info, io.BytesIO(data))


def create_output_temp(directory_fd: int, label: str) -> tuple[str, int]:
    require_trusted_output_directory(directory_fd)
    flags = os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    for _ in range(128):
        name = f".{label}.{secrets.token_hex(16)}.tmp"
        try:
            return name, os.open(name, flags, 0o600, dir_fd=directory_fd)
        except FileExistsError:
            continue
    raise RuntimeError("could not allocate an unpredictable release temporary file")


def build_archive(bundle: Path, directory_fd: int, label: str) -> tuple[str, int, str]:
    temporary_name, descriptor = create_output_temp(directory_fd, label)
    verified: VerifiedBundle | None = None
    try:
        verified = bind_verified_bundle(bundle)
        expected = verified.expected
        with os.fdopen(descriptor, "wb", closefd=False) as raw:
            compressed = DeterministicGzipWriter(raw, MAX_ARCHIVE_BYTES)
            with tarfile.open(
                fileobj=compressed,
                mode="w|",
                format=tarfile.GNU_FORMAT,
            ) as archive:
                add_tar_directory(archive, bundle.name)
                for relative in bundle_directories(list(expected)):
                    add_tar_directory(archive, f"{bundle.name}/{relative}")
                for relative in sorted(expected, key=os.fsencode):
                    mode, _size = expected[relative]
                    add_tar_file(
                        archive,
                        verified.bytes(relative),
                        f"{bundle.name}/{relative}",
                        mode,
                    )
            compressed.finish()
            raw.flush()
            os.fsync(descriptor)
        verified.assert_stable()
        if os.pread(descriptor, len(GZIP_HEADER), 0) != GZIP_HEADER:
            raise ValueError("archive gzip header is not deterministic")
        archive_digest = digest_fd(descriptor, MAX_ARCHIVE_BYTES)
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        return temporary_name, descriptor, archive_digest
    except Exception:
        try:
            unlink_if_same(directory_fd, temporary_name, descriptor, MAX_ARCHIVE_BYTES)
        finally:
            os.close(descriptor)
        raise
    finally:
        if verified is not None:
            verified.close()


def create_sidecar(
    directory_fd: int,
    archive_name: str,
    archive_digest: str,
) -> tuple[str, int, bytes]:
    data = f"{archive_digest}  {archive_name}\n".encode("ascii")
    temporary_name, descriptor = create_output_temp(directory_fd, f"{archive_name}.sha256")
    try:
        write_all(descriptor, data)
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        if read_fd(descriptor, MAX_METADATA_BYTES) != data:
            raise ValueError("checksum sidecar failed verification")
        return temporary_name, descriptor, data
    except Exception:
        try:
            unlink_if_same(directory_fd, temporary_name, descriptor, MAX_METADATA_BYTES)
        finally:
            os.close(descriptor)
        raise


def open_named_regular(directory_fd: int, name: str, maximum: int) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        regular_file_state(descriptor, Path(name), maximum)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def output_directory_acl_free(directory_fd: int) -> bool:
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

    acl = acl_get_fd(directory_fd, ACL_TYPE_EXTENDED)
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


def require_trusted_output_directory(directory_fd: int) -> None:
    """Require a namespace writable only by the current effective UID.

    This is the authority boundary that makes the documented post-quarantine
    compare-to-unlink residual exclude every writer except the same-euid threat.
    """
    metadata = os.fstat(directory_fd)
    if (
        not stat.S_ISDIR(metadata.st_mode)
        or metadata.st_uid != os.geteuid()
        or stat.S_IMODE(metadata.st_mode) & 0o022
        or not output_directory_acl_free(directory_fd)
    ):
        raise ValueError(
            "release output directory must be current-euid-owned, "
            "non-group/world-writable, and ACL-free"
        )


def open_output_file(directory_fd: int, name: str, maximum: int) -> int:
    descriptor = open_named_regular(directory_fd, name, maximum)
    try:
        metadata = os.fstat(descriptor)
        if stat.S_IMODE(metadata.st_mode) != 0o644 or metadata.st_uid != os.geteuid():
            raise ValueError(f"release output has unsafe owner or mode: {name}")
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def existing_output_is_exact(
    directory_fd: int,
    archive_name: str,
    checksum_name: str,
    archive_digest: str,
    sidecar_data: bytes,
) -> bool:
    descriptors: list[int] = []
    try:
        descriptors.append(open_output_file(directory_fd, archive_name, MAX_ARCHIVE_BYTES))
        descriptors.append(open_output_file(directory_fd, checksum_name, MAX_METADATA_BYTES))
    except FileNotFoundError:
        for descriptor in descriptors:
            os.close(descriptor)
        return False
    except Exception:
        for descriptor in descriptors:
            os.close(descriptor)
        raise
    try:
        return (
            digest_fd(descriptors[0], MAX_ARCHIVE_BYTES) == archive_digest
            and read_fd(descriptors[1], MAX_METADATA_BYTES) == sidecar_data
        )
    finally:
        for descriptor in descriptors:
            os.close(descriptor)


def output_matches_digest(
    directory_fd: int,
    name: str,
    expected_digest: str,
) -> bool:
    try:
        descriptor = open_output_file(directory_fd, name, MAX_ARCHIVE_BYTES)
    except FileNotFoundError:
        return False
    try:
        if digest_fd(descriptor, MAX_ARCHIVE_BYTES) != expected_digest:
            raise FileExistsError(f"existing release output has different content: {name}")
        return True
    finally:
        os.close(descriptor)


def output_matches_bytes(
    directory_fd: int,
    name: str,
    expected: bytes,
) -> bool:
    try:
        descriptor = open_output_file(directory_fd, name, MAX_METADATA_BYTES)
    except FileNotFoundError:
        return False
    try:
        if read_fd(descriptor, MAX_METADATA_BYTES) != expected:
            raise FileExistsError(f"existing release output has different content: {name}")
        return True
    finally:
        os.close(descriptor)


def rename_exclusive(
    source_fd: int,
    source: str,
    destination_fd: int,
    destination: str,
) -> None:
    libc = ctypes.CDLL(None, use_errno=True)
    renameatx = libc.renameatx_np
    renameatx.argtypes = [
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_int,
        ctypes.c_char_p,
        ctypes.c_uint,
    ]
    renameatx.restype = ctypes.c_int
    if (
        renameatx(
            source_fd,
            os.fsencode(source),
            destination_fd,
            os.fsencode(destination),
            RENAME_EXCL,
        )
        != 0
    ):
        error_number = ctypes.get_errno()
        raise OSError(error_number, os.strerror(error_number), source)


def unlink_if_same(directory_fd: int, name: str, descriptor: int, maximum: int) -> None:
    """Remove only the held object by first moving its name to an unpredictable slot.

    Object identity is the protected property. Metadata-only changes do not redirect
    deletion, while a replacement is restored or retained under its quarantine name.
    """
    require_trusted_output_directory(directory_fd)
    expected = FileState.from_stat(os.fstat(descriptor))
    try:
        current_fd = open_named_regular(directory_fd, name, maximum)
    except FileNotFoundError:
        return
    try:
        current = FileState.from_stat(os.fstat(current_fd))
        if not expected.same_object(current):
            return

        quarantine = ""
        for _ in range(16):
            candidate = f".diskplan-remove-{secrets.token_hex(16)}"
            try:
                rename_exclusive(directory_fd, name, directory_fd, candidate)
                quarantine = candidate
                break
            except FileNotFoundError:
                return
            except FileExistsError:
                continue
        if not quarantine:
            raise RuntimeError("could not allocate a bounded cleanup quarantine name")

        try:
            quarantined_fd = open_named_regular(directory_fd, quarantine, maximum)
        except Exception as error:
            raise RuntimeError(
                f"cleanup retained an unreadable object as {quarantine} while removing {name}"
            ) from error
        try:
            quarantined = FileState.from_stat(os.fstat(quarantined_fd))
            if (
                not expected.same_object(quarantined)
                or not current.same_object(quarantined)
            ):
                raise ValueError(
                    f"cleanup retained a replaced object as {quarantine} while removing {name}"
                )
            require_trusted_output_directory(directory_fd)
            os.unlink(quarantine, dir_fd=directory_fd)
            os.fsync(directory_fd)
        finally:
            os.close(quarantined_fd)
    finally:
        os.close(current_fd)


def publish_verified_set(
    directory_fd: int,
    archive_temp_name: str,
    archive_fd: int,
    archive_name: str,
    archive_digest: str,
    sidecar_temp_name: str,
    sidecar_fd: int,
    sidecar_data: bytes,
) -> None:
    require_trusted_output_directory(directory_fd)
    checksum_name = f"{archive_name}.sha256"
    archive_present = output_matches_digest(
        directory_fd,
        archive_name,
        archive_digest,
    )
    sidecar_present = output_matches_bytes(
        directory_fd,
        checksum_name,
        sidecar_data,
    )
    if archive_present and sidecar_present:
        return

    sidecar_published_by_us = False
    archive_published_by_us = False
    try:
        if not sidecar_present:
            try:
                os.link(
                    sidecar_temp_name,
                    checksum_name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                sidecar_published_by_us = True
            except FileExistsError:
                output_matches_bytes(directory_fd, checksum_name, sidecar_data)
        if not archive_present:
            try:
                os.link(
                    archive_temp_name,
                    archive_name,
                    src_dir_fd=directory_fd,
                    dst_dir_fd=directory_fd,
                    follow_symlinks=False,
                )
                archive_published_by_us = True
            except FileExistsError:
                output_matches_digest(directory_fd, archive_name, archive_digest)
        if not existing_output_is_exact(
            directory_fd,
            archive_name,
            checksum_name,
            archive_digest,
            sidecar_data,
        ):
            raise ValueError("published archive and checksum set failed verification")
        os.fsync(directory_fd)
    except Exception:
        if archive_published_by_us:
            unlink_if_same(directory_fd, archive_name, archive_fd, MAX_ARCHIVE_BYTES)
        if sidecar_published_by_us:
            unlink_if_same(directory_fd, checksum_name, sidecar_fd, MAX_METADATA_BYTES)
        raise


def open_output_directory(path: Path) -> int:
    path.mkdir(parents=True, exist_ok=True)
    flags = os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(path, flags)
    metadata = os.fstat(descriptor)
    if not stat.S_ISDIR(metadata.st_mode):
        os.close(descriptor)
        raise ValueError(f"output path is not a directory: {path}")
    try:
        require_trusted_output_directory(descriptor)
    except Exception:
        os.close(descriptor)
        raise
    return descriptor


def main() -> int:
    args = parse_args()
    if not GIT_SHA.fullmatch(args.source_revision):
        raise ValueError("source revision must be an exact lowercase Git SHA")
    require_pinned_zlib()

    asset_root = args.asset_root or args.protocol_metadata.parent.parent
    if not asset_root.is_absolute():
        asset_root = asset_root.absolute()
    asset_root_binding = bind_absolute_directory(asset_root)
    contract_binding = (
        bind_absolute_source(args.bundle_contract, MAX_CONTRACT_BYTES)
        if args.bundle_contract
        else bind_relative_source(
            asset_root_binding,
            "release/bundle-contract.json",
            MAX_CONTRACT_BYTES,
        )
    )
    contract, excluded_inputs = load_bundle_contract(contract_binding)
    contract_digest = digest_fd(contract_binding.file_fd, MAX_CONTRACT_BYTES)

    output_fd = open_output_directory(args.output_dir)
    staged_files: list[StagedFile] = []
    archive_fd = -1
    sidecar_fd = -1
    archive_temp_name = ""
    sidecar_temp_name = ""
    try:
        with tempfile.TemporaryDirectory(prefix="diskplan-package-") as staging_name:
            staging_root = Path(staging_name)
            os.chmod(staging_root, 0o700)
            inputs = staging_root / "inputs"
            inputs.mkdir(mode=0o700)
            token_sources = {
                "@activator": args.activator,
                "@common-library": args.common_library,
                "@engine": args.engine,
                "@frontend": args.frontend,
                "@fs-helper": args.fs_helper,
                "@installer": args.installer,
                "@protocol-metadata": args.protocol_metadata,
                "@uninstaller": args.uninstaller,
                "@version-file": args.version_file,
            }
            staged: dict[str, StagedFile] = {}
            for index, spec in enumerate(contract):
                if spec.source == "@protocol-version":
                    continue
                source = (
                    bind_absolute_source(token_sources[spec.source], spec.maximum_bytes)
                    if spec.source.startswith("@")
                    else require_safe_repository_source(
                        asset_root_binding,
                        spec.source,
                        spec.maximum_bytes,
                    )
                )
                item = stage_source(
                    source,
                    inputs / f"artifact-{index:04d}",
                    spec.maximum_bytes,
                    spec.mode,
                )
                staged_files.append(item)
                staged[spec.bundle_path] = item

            version = staged["VERSION"].bytes().decode("ascii").strip()
            if not SEMVER.fullmatch(version):
                raise ValueError("VERSION is not a canonical semantic version")
            protocol = read_json_bytes(staged["protocol.json"].bytes(), args.protocol_metadata)
            validate_protocol(protocol)
            protocol_compatibility = (
                f"protocol-{protocol['protocol_major']}.{protocol['protocol_minor']}"
            )
            for spec in contract:
                if spec.role in {"protocol-metadata", "protocol-schema", "protocol-version"}:
                    if spec.compatibility_version != protocol_compatibility:
                        raise ValueError(
                            f"bundle contract protocol compatibility mismatch: {spec.bundle_path}"
                        )

            runtime_capabilities = staged["runtime-capabilities.json"].bytes()
            validate_runtime_capabilities(
                runtime_capabilities,
                asset_root / "release/runtime-capabilities.json",
            )
            optional_capabilities = [
                item["id"]
                for item in read_json_bytes(
                    runtime_capabilities, asset_root / "release/runtime-capabilities.json"
                )["capabilities"]
            ]

            validate_macho_components(staged, protocol["deployment_target_macos"])

            frontend_identity = component_identity(staged["diskplan"], "diskplan")
            engine_identity = component_identity(staged["diskplan-engine"], "diskplan-engine")
            fs_helper_identity = helper_identity(staged["diskplan-fs-helper"])
            expected_identity = {
                "product_version": version,
                "protocol_major": protocol["protocol_major"],
                "protocol_minor": protocol["protocol_minor"],
            }
            for component in (frontend_identity, engine_identity, fs_helper_identity):
                for key, expected in expected_identity.items():
                    if component[key] != expected:
                        raise ValueError(
                            f"component identity mismatch for {component['component']}: {key}"
                        )
            bundle_name = f"diskplan-{version}-macos-arm64"
            bundle = staging_root / bundle_name
            bundle.mkdir(mode=0o755)
            make_bundle_directories(bundle, [item.bundle_path for item in contract])
            artifacts: list[dict[str, Any]] = []
            for spec in contract:
                if spec.source == "@protocol-version":
                    data = (
                        f"{protocol['protocol_major']}.{protocol['protocol_minor']}\n"
                    ).encode("ascii")
                elif spec.bundle_path == "VERSION":
                    data = f"{version}\n".encode("ascii")
                elif spec.bundle_path == "protocol.json":
                    data = canonical_json(protocol)
                else:
                    data = staged[spec.bundle_path].bytes()
                artifacts.append(write_bundle_artifact(bundle, spec, data))
            artifacts.sort(key=lambda item: os.fsencode(item["path"]))

            manifest = {
                "architecture": protocol["architecture"],
                "artifacts": artifacts,
                "bundle_format": protocol["bundle_format"],
                "deployment_target_macos": protocol["deployment_target_macos"],
                "excluded_inputs": excluded_inputs,
                "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
                "optional_capabilities": optional_capabilities,
                "product_version": version,
                "protocol_major": protocol["protocol_major"],
                "protocol_minor": protocol["protocol_minor"],
                "release_gate_macos": protocol["release_gate_macos"],
                "required_capabilities": protocol["required_capabilities"],
                "source_revision": args.source_revision,
            }
            manifest_data = canonical_json(manifest)
            write_private_file(bundle / "manifest.json", manifest_data, 0o644)
            checksummed = artifacts + [
                {"path": "manifest.json", "sha256": digest(manifest_data)}
            ]
            checksummed.sort(key=lambda item: os.fsencode(item["path"]))
            sums_data = "".join(
                f"{item['sha256']}  {item['path']}\n" for item in checksummed
            ).encode("ascii")
            write_private_file(bundle / "SHA256SUMS", sums_data, 0o644)

            verify_bundle_tree(bundle)

            for item in staged_files:
                item.assert_source_stable()
                item.assert_staged_stable()
            asset_root_binding.assert_stable()
            contract_binding.assert_stable()
            if digest_fd(contract_binding.file_fd, MAX_CONTRACT_BYTES) != contract_digest:
                raise ValueError("bundle contract content changed during packaging")

            archive_name = f"{bundle_name}.tar.gz"
            archive_temp_name, archive_fd, archive_digest = build_archive(
                bundle,
                output_fd,
                archive_name,
            )
            sidecar_temp_name, sidecar_fd, sidecar_data = create_sidecar(
                output_fd,
                archive_name,
                archive_digest,
            )
            publish_verified_set(
                output_fd,
                archive_temp_name,
                archive_fd,
                archive_name,
                archive_digest,
                sidecar_temp_name,
                sidecar_fd,
                sidecar_data,
            )
            print(args.output_dir / archive_name)
        return 0
    finally:
        for item in staged_files:
            item.close()
        if archive_fd >= 0:
            try:
                unlink_if_same(
                    output_fd,
                    archive_temp_name,
                    archive_fd,
                    MAX_ARCHIVE_BYTES,
                )
            finally:
                os.close(archive_fd)
        if sidecar_fd >= 0:
            try:
                unlink_if_same(
                    output_fd,
                    sidecar_temp_name,
                    sidecar_fd,
                    MAX_METADATA_BYTES,
                )
            finally:
                os.close(sidecar_fd)
        os.close(output_fd)
        contract_binding.close()
        asset_root_binding.close()


if __name__ == "__main__":
    raise SystemExit(main())
