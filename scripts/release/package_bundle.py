#!/usr/bin/env python3
"""Build a deterministic Diskplan macOS arm64 release archive."""

from __future__ import annotations

import argparse
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
BUNDLE_FILE_LIMITS = {
    "SHA256SUMS": MAX_METADATA_BYTES,
    "VERSION": 256,
    "activate.sh": MAX_METADATA_BYTES,
    "diskplan": MAX_BINARY_BYTES,
    "diskplan-engine": MAX_BINARY_BYTES,
    "diskplan-fs-helper": MAX_BINARY_BYTES,
    "install.sh": MAX_METADATA_BYTES,
    "manifest.json": MAX_METADATA_BYTES,
    "protocol.json": MAX_METADATA_BYTES,
    "release-common.sh": MAX_METADATA_BYTES,
    "uninstall.sh": MAX_METADATA_BYTES,
}
BUNDLE_FILE_MODES = {
    name: 0o755
    if name
    in {
        "activate.sh",
        "diskplan",
        "diskplan-engine",
        "diskplan-fs-helper",
        "install.sh",
        "uninstall.sh",
    }
    else 0o644
    for name in BUNDLE_FILE_LIMITS
}


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
    source_fd: int
    staged_fd: int
    source_state: FileState
    staged_state: FileState
    sha256: str
    maximum: int

    def assert_source_stable(self) -> None:
        current = regular_file_state(self.source_fd, self.source, self.maximum)
        if not self.source_state.same_object(current):
            raise ValueError(f"source object identity changed: {self.source}")
        if not self.source_state.same_content_state(current):
            raise ValueError(f"source content state changed: {self.source}")
        reopened = open_regular_nofollow(self.source, self.maximum)
        try:
            path_state = FileState.from_stat(os.fstat(reopened))
        finally:
            os.close(reopened)
        if not self.source_state.same_object(path_state):
            raise ValueError(f"source path was replaced: {self.source}")
        if not self.source_state.same_content_state(path_state):
            raise ValueError(f"source path content changed: {self.source}")

    def assert_staged_stable(self) -> None:
        current = regular_file_state(self.staged_fd, self.path, self.maximum)
        if not self.staged_state.same_object(current):
            raise ValueError(f"staged object identity changed: {self.path}")
        if not self.staged_state.same_content_state(current):
            raise ValueError(f"staged content state changed: {self.path}")
        reopened = open_regular_nofollow(self.path, self.maximum)
        try:
            path_state = FileState.from_stat(os.fstat(reopened))
        finally:
            os.close(reopened)
        if not self.staged_state.same_object(path_state):
            raise ValueError(f"staged path was replaced: {self.path}")
        if not self.staged_state.same_content_state(path_state):
            raise ValueError(f"staged path content changed: {self.path}")
        if digest_fd(self.staged_fd, self.maximum) != self.sha256:
            raise ValueError(f"staged content digest changed: {self.path}")

    def bytes(self) -> bytes:
        self.assert_staged_stable()
        return read_fd(self.staged_fd, self.maximum)

    def close(self) -> None:
        os.close(self.source_fd)
        os.close(self.staged_fd)


@dataclass(frozen=True)
class ProbeResult:
    stdout: bytes
    returncode: int


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
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--output-dir", type=Path, required=True)
    # Retained for callers of the original interface. Validation is unconditional.
    parser.add_argument("--require-macho-arm64", action="store_true", help=argparse.SUPPRESS)
    return parser.parse_args()


def regular_file_state(fd: int, display_path: Path, maximum: int) -> FileState:
    metadata = os.fstat(fd)
    if not stat.S_ISREG(metadata.st_mode):
        raise ValueError(f"not a regular file: {display_path}")
    if metadata.st_size > maximum:
        raise ValueError(f"file exceeds {maximum} bytes: {display_path}")
    return FileState.from_stat(metadata)


def open_regular_nofollow(path: Path, maximum: int) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags)
    except OSError as error:
        raise ValueError(f"cannot safely open regular file: {path}") from error
    try:
        regular_file_state(descriptor, path, maximum)
    except Exception:
        os.close(descriptor)
        raise
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


def stage_source(source: Path, destination: Path, maximum: int, mode: int) -> StagedFile:
    source_fd = open_regular_nofollow(source, maximum)
    staged_fd = -1
    try:
        source_state = regular_file_state(source_fd, source, maximum)
        staged_fd = create_exclusive_file(destination, 0o600)
        hasher = hashlib.sha256()
        consumed = 0
        while True:
            chunk = os.read(source_fd, COPY_CHUNK_BYTES)
            if not chunk:
                break
            consumed += len(chunk)
            if consumed > maximum:
                raise ValueError(f"file grew beyond {maximum} bytes: {source}")
            write_all(staged_fd, chunk)
            hasher.update(chunk)
        if consumed != source_state.size:
            raise ValueError(f"file size changed while staging: {source}")
        os.fchmod(staged_fd, mode)
        os.fsync(staged_fd)
        staged_state = regular_file_state(staged_fd, destination, maximum)
        staged = StagedFile(
            source=source,
            path=destination,
            source_fd=source_fd,
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
        os.close(source_fd)
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
        "name": path.name,
        "mode": f"{mode:04o}",
        "sha256": digest(data),
        "size": len(data),
    }


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


def add_tar_file(archive: tarfile.TarFile, path: Path, name: str) -> None:
    if path.name not in BUNDLE_FILE_LIMITS:
        raise ValueError(f"unexpected bundle file: {path.name}")
    maximum = BUNDLE_FILE_LIMITS[path.name]
    data = read_regular_file(path, maximum)
    metadata = path.lstat()
    expected_mode = BUNDLE_FILE_MODES[path.name]
    if not stat.S_ISREG(metadata.st_mode) or stat.S_IMODE(metadata.st_mode) != expected_mode:
        raise ValueError(f"bundle file has wrong type or mode: {path.name}")
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
    try:
        with os.fdopen(descriptor, "wb", closefd=False) as raw:
            compressed = DeterministicGzipWriter(raw, MAX_ARCHIVE_BYTES)
            with tarfile.open(
                fileobj=compressed,
                mode="w|",
                format=tarfile.GNU_FORMAT,
            ) as archive:
                add_tar_directory(archive, bundle.name)
                for path in sorted(bundle.iterdir(), key=lambda item: os.fsencode(item.name)):
                    add_tar_file(archive, path, f"{bundle.name}/{path.name}")
            compressed.finish()
            raw.flush()
            os.fsync(descriptor)
        if os.pread(descriptor, len(GZIP_HEADER), 0) != GZIP_HEADER:
            raise ValueError("archive gzip header is not deterministic")
        archive_digest = digest_fd(descriptor, MAX_ARCHIVE_BYTES)
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        return temporary_name, descriptor, archive_digest
    except Exception:
        os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise


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
        os.close(descriptor)
        try:
            os.unlink(temporary_name, dir_fd=directory_fd)
        except FileNotFoundError:
            pass
        raise


def open_output_file(directory_fd: int, name: str, maximum: int) -> int:
    flags = os.O_RDONLY | os.O_CLOEXEC | os.O_NONBLOCK
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(name, flags, dir_fd=directory_fd)
    try:
        metadata = os.fstat(descriptor)
        regular_file_state(descriptor, Path(name), maximum)
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


def unlink_if_same(directory_fd: int, name: str, descriptor: int, maximum: int) -> None:
    expected = FileState.from_stat(os.fstat(descriptor))
    try:
        current_fd = open_output_file(directory_fd, name, maximum)
    except FileNotFoundError:
        return
    try:
        current = FileState.from_stat(os.fstat(current_fd))
    finally:
        os.close(current_fd)
    if expected.same_object(current):
        os.unlink(name, dir_fd=directory_fd)


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
    return descriptor


def main() -> int:
    args = parse_args()
    if not GIT_SHA.fullmatch(args.source_revision):
        raise ValueError("source revision must be an exact lowercase Git SHA")
    require_pinned_zlib()

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
            source_specs = [
                (args.frontend, "diskplan", MAX_BINARY_BYTES, 0o755),
                (args.engine, "diskplan-engine", MAX_BINARY_BYTES, 0o755),
                (args.fs_helper, "diskplan-fs-helper", MAX_BINARY_BYTES, 0o755),
                (args.installer, "install.sh", MAX_METADATA_BYTES, 0o755),
                (args.activator, "activate.sh", MAX_METADATA_BYTES, 0o755),
                (args.uninstaller, "uninstall.sh", MAX_METADATA_BYTES, 0o755),
                (args.common_library, "release-common.sh", MAX_METADATA_BYTES, 0o644),
                (args.version_file, "VERSION", 256, 0o644),
                (args.protocol_metadata, "protocol.json", MAX_METADATA_BYTES, 0o644),
            ]
            for source, name, maximum, mode in source_specs:
                staged_files.append(stage_source(source, inputs / name, maximum, mode))
            staged = {item.path.name: item for item in staged_files}

            version = staged["VERSION"].bytes().decode("ascii").strip()
            if not SEMVER.fullmatch(version):
                raise ValueError("VERSION is not a canonical semantic version")
            protocol = read_json_bytes(staged["protocol.json"].bytes(), args.protocol_metadata)
            validate_protocol(protocol)

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
            artifacts = []
            for name in (
                "diskplan",
                "diskplan-engine",
                "diskplan-fs-helper",
                "install.sh",
                "activate.sh",
                "uninstall.sh",
                "release-common.sh",
            ):
                mode = 0o644 if name == "release-common.sh" else 0o755
                artifacts.append(write_private_file(bundle / name, staged[name].bytes(), mode))
            artifacts.append(write_private_file(bundle / "VERSION", f"{version}\n".encode("ascii"), 0o644))
            artifacts.append(
                write_private_file(bundle / "protocol.json", canonical_json(protocol), 0o644)
            )
            artifacts.sort(key=lambda item: os.fsencode(item["name"]))

            manifest = {
                "architecture": protocol["architecture"],
                "artifacts": artifacts,
                "bundle_format": protocol["bundle_format"],
                "deployment_target_macos": protocol["deployment_target_macos"],
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
                {"name": "manifest.json", "sha256": digest(manifest_data)}
            ]
            checksummed.sort(key=lambda item: os.fsencode(item["name"]))
            sums_data = "".join(
                f"{item['sha256']}  {item['name']}\n" for item in checksummed
            ).encode("ascii")
            write_private_file(bundle / "SHA256SUMS", sums_data, 0o644)

            for item in staged_files:
                item.assert_source_stable()
                item.assert_staged_stable()

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


if __name__ == "__main__":
    raise SystemExit(main())
