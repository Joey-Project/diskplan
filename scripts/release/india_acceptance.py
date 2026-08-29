#!/usr/bin/env python3
"""Run the deterministic macOS 26 Apple Silicon release acceptance matrix."""

from __future__ import annotations

import argparse
import ctypes
import hashlib
import json
import os
import plistlib
import re
import shutil
import signal
import stat
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Mapping, Optional, Sequence


SCHEMA = 1
EXPECTED_HOST = "India-mac-mini-m4-hoteng"
EXPECTED_MACOS_MAJOR = 26
EXPECTED_ARCHITECTURE = "arm64"
MAX_CATALOG_BYTES = 64 * 1024
MAX_MANIFEST_BYTES = 1024 * 1024
MAX_STATUS_BYTES = 64 * 1024
MAX_CLEANUP_ENTRIES = 5_000_000
CLEANUP_TIMEOUT_SECONDS = 120
VALID_REQUIREMENTS = frozenset({"required", "conditional"})
VALID_STATUSES = frozenset({"passed", "unsupported", "skipped", "failure"})
UNSUPPORTED_EXIT_CODES = frozenset({69, 77, 78})
SEMVER_PATTERN = re.compile(
    r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)"
    r"(?:-(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)"
    r"(?:\.(?:0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*))*)?"
    r"(?:\+[0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*)?"
)


class AcceptanceError(RuntimeError):
    """Stable release acceptance failure without unbounded external detail."""


@dataclass(frozen=True)
class Lane:
    lane_id: str
    requirement: str
    capability: str
    executor: str
    dependencies: tuple[str, ...]
    timeout_seconds: int
    max_output_bytes: int
    max_resident_bytes: Optional[int]
    expected_test_count: Optional[int]
    swift_filter: Optional[str]


@dataclass(frozen=True)
class HostFacts:
    hostname: str
    macos_version: str
    macos_build: str
    architecture: str
    hardware_model: str


@dataclass(frozen=True)
class ProductFacts:
    version: str
    protocol_major: int
    protocol_minor: int
    source_revision: str
    manifest_sha256: str


@dataclass(frozen=True)
class CommandResult:
    status: Mapping[str, Any]
    output: bytes
    argv: tuple[str, ...]
    argv_template: tuple[str, ...] = ()


@dataclass
class AuditScope:
    canonical_path: Path
    descriptor: int
    binding: tuple[int, int, int, int, int, int]

    def receipt(self) -> Mapping[str, Any]:
        device, inode, uid, gid, mode, flags = self.binding
        return {
            "path_sha256": hashlib.sha256(os.fsencode(self.canonical_path)).hexdigest(),
            "device": device,
            "inode": inode,
            "uid": uid,
            "gid": gid,
            "mode": mode,
            "flags": flags,
        }

    def revalidate(self) -> None:
        if (
            directory_scope_binding(os.fstat(self.descriptor)) != self.binding
            or directory_scope_binding(self.canonical_path.lstat()) != self.binding
        ):
            raise AcceptanceError("audit root identity or access policy changed")

    def close(self) -> None:
        os.close(self.descriptor)


def canonical_json(value: Any) -> bytes:
    return (
        json.dumps(
            value,
            allow_nan=False,
            ensure_ascii=False,
            sort_keys=True,
            separators=(",", ":"),
        )
        + "\n"
    ).encode()


def read_bounded_regular(path: Path, maximum: int, label: str) -> bytes:
    flags = (
        os.O_RDONLY
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0)
    )
    descriptor = os.open(path, flags)
    try:
        metadata = os.fstat(descriptor)
        if not stat.S_ISREG(metadata.st_mode):
            raise AcceptanceError(f"{label} must be a non-symlink regular file")
        if metadata.st_size > maximum:
            raise AcceptanceError(f"{label} exceeds its byte limit")
        first = read_descriptor_pass(descriptor, maximum, label)
        os.lseek(descriptor, 0, os.SEEK_SET)
        second = read_descriptor_pass(descriptor, maximum, label)
        after = os.fstat(descriptor)
        slot = path.lstat()
        if (
            first != second
            or regular_file_binding(metadata) != regular_file_binding(after)
            or regular_file_binding(metadata) != regular_file_binding(slot)
        ):
            raise AcceptanceError(f"{label} changed while being read")
        return first
    finally:
        os.close(descriptor)


def regular_file_binding(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int, int, int]:
    """Seal object identity, access policy, size, and selected filesystem flags."""

    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IFMT(metadata.st_mode),
        stat.S_IMODE(metadata.st_mode),
        metadata.st_size,
        getattr(metadata, "st_flags", 0),
    )


def directory_scope_binding(
    metadata: os.stat_result,
) -> tuple[int, int, int, int, int, int]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_uid,
        metadata.st_gid,
        stat.S_IMODE(metadata.st_mode),
        getattr(metadata, "st_flags", 0),
    )


def bind_audit_scope(path: Path) -> AuditScope:
    canonical = path.resolve(strict=True)
    if canonical != path or path.is_symlink():
        raise AcceptanceError("audit root must be a canonical non-symlink path")
    before = path.lstat()
    descriptor = os.open(
        path,
        os.O_RDONLY
        | os.O_DIRECTORY
        | os.O_CLOEXEC
        | getattr(os, "O_NOFOLLOW", 0)
        | getattr(os, "O_NONBLOCK", 0),
    )
    try:
        binding = directory_scope_binding(before)
        if (
            not stat.S_ISDIR(before.st_mode)
            or directory_scope_binding(os.fstat(descriptor)) != binding
        ):
            raise AcceptanceError("audit root identity changed while being bound")
        return AuditScope(canonical, descriptor, binding)
    except Exception:
        os.close(descriptor)
        raise


def read_descriptor_pass(descriptor: int, maximum: int, label: str) -> bytes:
    chunks: list[bytes] = []
    count = 0
    while True:
        chunk = os.read(descriptor, min(64 * 1024, maximum + 1 - count))
        if not chunk:
            return b"".join(chunks)
        chunks.append(chunk)
        count += len(chunk)
        if count > maximum:
            raise AcceptanceError(f"{label} grew beyond its byte limit")


def parse_lane(raw: Mapping[str, Any]) -> Lane:
    expected = {
        "capability",
        "depends_on",
        "executor",
        "id",
        "max_output_bytes",
        "requirement",
        "timeout_seconds",
    }
    allowed = expected | {"expected_test_count", "max_resident_bytes", "swift_filter"}
    if set(raw) - allowed or not expected.issubset(raw):
        raise AcceptanceError("acceptance lane has an invalid field set")
    lane_id = raw["id"]
    requirement = raw["requirement"]
    capability = raw["capability"]
    executor = raw["executor"]
    dependencies = raw["depends_on"]
    timeout_seconds = raw["timeout_seconds"]
    max_output_bytes = raw["max_output_bytes"]
    max_resident_bytes = raw.get("max_resident_bytes")
    expected_test_count = raw.get("expected_test_count")
    swift_filter = raw.get("swift_filter")
    identifiers = (lane_id, capability, executor)
    if not all(
        isinstance(value, str) and 1 <= len(value) <= 128 for value in identifiers
    ):
        raise AcceptanceError("acceptance lane identifiers are invalid")
    if requirement not in VALID_REQUIREMENTS:
        raise AcceptanceError("acceptance lane requirement is invalid")
    if not isinstance(dependencies, list) or not all(
        isinstance(value, str) and 1 <= len(value) <= 128 for value in dependencies
    ):
        raise AcceptanceError("acceptance lane dependencies are invalid")
    if not isinstance(timeout_seconds, int) or not 1 <= timeout_seconds <= 86400:
        raise AcceptanceError("acceptance lane timeout is invalid")
    if not isinstance(max_output_bytes, int) or not 1 <= max_output_bytes <= 1048576:
        raise AcceptanceError("acceptance lane output limit is invalid")
    if max_resident_bytes is not None and (
        not isinstance(max_resident_bytes, int)
        or not 1 <= max_resident_bytes <= 8 * 1024**3
    ):
        raise AcceptanceError("acceptance lane resident-memory limit is invalid")
    if expected_test_count is not None and (
        not isinstance(expected_test_count, int) or not 1 <= expected_test_count <= 64
    ):
        raise AcceptanceError("acceptance lane test count is invalid")
    if swift_filter is not None and (
        not isinstance(swift_filter, str) or not 1 <= len(swift_filter) <= 1024
    ):
        raise AcceptanceError("acceptance Swift filter is invalid")
    return Lane(
        lane_id=lane_id,
        requirement=requirement,
        capability=capability,
        executor=executor,
        dependencies=tuple(dependencies),
        timeout_seconds=timeout_seconds,
        max_output_bytes=max_output_bytes,
        max_resident_bytes=max_resident_bytes,
        expected_test_count=expected_test_count,
        swift_filter=swift_filter,
    )


def load_catalog(path: Path) -> tuple[Mapping[str, Any], tuple[Lane, ...]]:
    try:
        document = json.loads(
            read_bounded_regular(path, MAX_CATALOG_BYTES, "acceptance catalog"),
            object_pairs_hook=reject_duplicate_json_keys,
            parse_constant=reject_nonfinite_json_number,
        )
    except (
        AcceptanceError,
        OSError,
        UnicodeDecodeError,
        json.JSONDecodeError,
    ) as error:
        raise AcceptanceError("acceptance catalog is unreadable") from error
    if not isinstance(document, dict) or set(document) != {"lanes", "schema", "target"}:
        raise AcceptanceError("acceptance catalog has an invalid top-level shape")
    if document["schema"] != SCHEMA:
        raise AcceptanceError("acceptance catalog schema is unsupported")
    target = document["target"]
    if target != {
        "architecture": EXPECTED_ARCHITECTURE,
        "host": EXPECTED_HOST,
        "macos_major": EXPECTED_MACOS_MAJOR,
    }:
        raise AcceptanceError("acceptance catalog target is not the release target")
    raw_lanes = document["lanes"]
    if not isinstance(raw_lanes, list) or not 1 <= len(raw_lanes) <= 32:
        raise AcceptanceError("acceptance catalog lane count is invalid")
    lanes = tuple(parse_lane(raw) for raw in raw_lanes if isinstance(raw, dict))
    if len(lanes) != len(raw_lanes):
        raise AcceptanceError("acceptance catalog contains a non-object lane")
    lane_ids = [lane.lane_id for lane in lanes]
    if len(set(lane_ids)) != len(lane_ids):
        raise AcceptanceError("acceptance catalog repeats a lane identifier")
    seen: set[str] = set()
    for lane in lanes:
        if any(dependency not in seen for dependency in lane.dependencies):
            raise AcceptanceError(
                "acceptance lane dependency is missing or not earlier"
            )
        seen.add(lane.lane_id)
    return target, lanes


def read_system_version(
    path: Path = Path("/System/Library/CoreServices/SystemVersion.plist"),
) -> tuple[str, str]:
    try:
        document = plistlib.loads(
            read_bounded_regular(path, 64 * 1024, "system version")
        )
    except (OSError, plistlib.InvalidFileException) as error:
        raise AcceptanceError("macOS version metadata is unreadable") from error
    version = document.get("ProductVersion")
    build = document.get("ProductBuildVersion")
    if not isinstance(version, str) or not isinstance(build, str):
        raise AcceptanceError("macOS version metadata is incomplete")
    return version, build


def collect_host_facts(
    system_version_path: Path = Path(
        "/System/Library/CoreServices/SystemVersion.plist"
    ),
) -> HostFacts:
    uname = os.uname()
    hostname = uname.nodename.split(".", 1)[0]
    version, build = read_system_version(system_version_path)
    model = darwin_sysctl_string("hw.model") if sys.platform == "darwin" else "unknown"
    return HostFacts(hostname, version, build, uname.machine, model)


def darwin_sysctl_string(name: str) -> str:
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    function = library.sysctlbyname
    function.argtypes = [
        ctypes.c_char_p,
        ctypes.c_void_p,
        ctypes.POINTER(ctypes.c_size_t),
        ctypes.c_void_p,
        ctypes.c_size_t,
    ]
    function.restype = ctypes.c_int
    encoded = name.encode("ascii")
    size = ctypes.c_size_t()
    if (
        function(encoded, None, ctypes.byref(size), None, 0) != 0
        or not 1 <= size.value <= 4096
    ):
        raise AcceptanceError("hardware model capability is unavailable")
    buffer = ctypes.create_string_buffer(size.value)
    if function(encoded, buffer, ctypes.byref(size), None, 0) != 0:
        raise AcceptanceError("hardware model capability is unavailable")
    try:
        return bytes(buffer[: size.value]).rstrip(b"\0").decode("ascii")
    except UnicodeDecodeError as error:
        raise AcceptanceError("hardware model is malformed") from error


def enforce_release_target(facts: HostFacts) -> None:
    try:
        macos_major = int(facts.macos_version.split(".", 1)[0])
    except ValueError as error:
        raise AcceptanceError("macOS product version is malformed") from error
    if facts.hostname != EXPECTED_HOST:
        raise AcceptanceError(f"release gate requires exact host {EXPECTED_HOST}")
    if (
        macos_major != EXPECTED_MACOS_MAJOR
        or facts.architecture != EXPECTED_ARCHITECTURE
    ):
        raise AcceptanceError("release gate requires macOS 26 on Apple Silicon")


def validate_bundle_path(bundle: Path) -> Path:
    if not bundle.is_absolute():
        raise AcceptanceError("bundle path must be absolute")
    metadata = bundle.lstat()
    if not stat.S_ISDIR(metadata.st_mode) or bundle.is_symlink():
        raise AcceptanceError("bundle must be a non-symlink directory")
    return bundle


def read_product_facts(bundle: Path) -> ProductFacts:
    version_payload = read_bounded_regular(bundle / "VERSION", 4096, "bundle VERSION")
    try:
        version = version_payload.decode("ascii").rstrip("\n")
        manifest_payload = read_bounded_regular(
            bundle / "manifest.json", MAX_MANIFEST_BYTES, "bundle manifest"
        )
        manifest = json.loads(
            manifest_payload,
            object_pairs_hook=reject_duplicate_json_keys,
            parse_constant=reject_nonfinite_json_number,
        )
    except (AcceptanceError, UnicodeDecodeError, json.JSONDecodeError) as error:
        raise AcceptanceError("bundle metadata is malformed") from error
    if SEMVER_PATTERN.fullmatch(version) is None:
        raise AcceptanceError("bundle version metadata is malformed")
    fields = ("protocol_major", "protocol_minor", "source_revision")
    if not isinstance(manifest, dict) or any(field not in manifest for field in fields):
        raise AcceptanceError("bundle manifest is incomplete")
    if manifest.get("product_version") != version:
        raise AcceptanceError("bundle version metadata disagrees")
    major = manifest["protocol_major"]
    minor = manifest["protocol_minor"]
    revision = manifest["source_revision"]
    if (
        not isinstance(major, int)
        or isinstance(major, bool)
        or major < 1
        or not isinstance(minor, int)
        or isinstance(minor, bool)
        or minor < 0
        or not isinstance(revision, str)
        or not 1 <= len(revision) <= 128
    ):
        raise AcceptanceError("bundle protocol metadata is malformed")
    return ProductFacts(
        version=version,
        protocol_major=major,
        protocol_minor=minor,
        source_revision=revision,
        manifest_sha256=hashlib.sha256(manifest_payload).hexdigest(),
    )


class BoundedRunner:
    def __init__(self, supervisor: Path, output_root: Path) -> None:
        self.supervisor = supervisor
        self.output_root = output_root
        self.active: Optional[subprocess.Popen[bytes]] = None
        self.received_signal: Optional[int] = None

    def forward(self, signal_number: int, _frame: object) -> None:
        if self.received_signal is None:
            self.received_signal = signal_number
        process = self.active
        if process is not None and process.poll() is None:
            try:
                process.send_signal(signal_number)
            except ProcessLookupError:
                pass

    def run(
        self,
        lane: Lane,
        argv: Sequence[str],
        argv_template: Sequence[str],
    ) -> CommandResult:
        output = self.output_root / f"{lane.lane_id}.log"
        command = [
            sys.executable,
            str(self.supervisor),
            "--timeout-seconds",
            str(lane.timeout_seconds),
            "--max-output-bytes",
            str(lane.max_output_bytes),
            "--output",
            str(output),
            "--",
            *argv,
        ]
        environment = dict(os.environ)
        environment["PYTHONDONTWRITEBYTECODE"] = "1"
        self.active = subprocess.Popen(
            command,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=environment,
        )
        stdout, stderr = self.active.communicate()
        supervisor_exit_code = self.active.returncode
        self.active = None
        if len(stdout) > MAX_STATUS_BYTES or len(stderr) > MAX_STATUS_BYTES:
            raise AcceptanceError("bounded supervisor diagnostics exceeded their limit")
        if stderr:
            raise AcceptanceError("bounded supervisor emitted unexpected diagnostics")
        try:
            status = json.loads(stdout)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            raise AcceptanceError("bounded supervisor status is malformed") from error
        if not isinstance(status, dict):
            raise AcceptanceError("bounded supervisor status is not an object")
        payload = read_bounded_regular(output, lane.max_output_bytes, "lane output")
        validate_supervisor_status(status, lane, payload, supervisor_exit_code)
        return CommandResult(
            status=status,
            output=payload,
            argv=tuple(argv),
            argv_template=tuple(argv_template),
        )


def validate_supervisor_status(
    status: Mapping[str, Any],
    lane: Lane,
    payload: bytes,
    process_exit_code: int,
) -> None:
    expected_fields = {
        "cleanup",
        "elapsed_millis",
        "error_type",
        "exit_code",
        "leader_exit_code",
        "limits",
        "output_bytes",
        "output_sha256",
        "process_group_verified",
        "resource_usage",
        "result",
        "termination_signal",
    }
    if set(status) != expected_fields:
        raise AcceptanceError("bounded supervisor status fields are invalid")
    if status.get("exit_code") != process_exit_code:
        raise AcceptanceError(
            "bounded supervisor exit status disagrees with its process"
        )
    if status.get("limits") != {
        "max_output_bytes": lane.max_output_bytes,
        "timeout_seconds": lane.timeout_seconds,
    }:
        raise AcceptanceError("bounded supervisor limits disagree with the lane")
    if (
        status.get("output_bytes") != len(payload)
        or status.get("output_sha256") != hashlib.sha256(payload).hexdigest()
    ):
        raise AcceptanceError(
            "bounded supervisor output proof disagrees with the retained log"
        )
    cleanup = status.get("cleanup")
    if (
        not isinstance(cleanup, dict)
        or set(cleanup)
        != {
            "attempted",
            "term_attempted",
            "term_sent",
            "kill_attempted",
            "kill_sent",
            "quiescent",
        }
        or not all(isinstance(value, bool) for value in cleanup.values())
    ):
        raise AcceptanceError("bounded supervisor cleanup proof is invalid")
    result = status.get("result")
    verified = status.get("process_group_verified")
    if not isinstance(verified, bool) or result not in {
        "passed",
        "command_failed",
        "launch_failed",
        "interrupted",
        "timed_out",
        "output_limit_exceeded",
        "supervisor_failed",
    }:
        raise AcceptanceError("bounded supervisor process-group proof is invalid")
    if result != "supervisor_failed" and (not verified or not cleanup["quiescent"]):
        raise AcceptanceError("bounded supervisor did not prove descendant quiescence")
    elapsed = status.get("elapsed_millis")
    if not isinstance(elapsed, int) or isinstance(elapsed, bool) or elapsed < 0:
        raise AcceptanceError("bounded supervisor duration is invalid")
    usage = status.get("resource_usage")
    if (
        not isinstance(usage, dict)
        or set(usage)
        != {
            "max_resident_bytes",
            "swap_operations",
            "system_cpu_millis",
            "user_cpu_millis",
        }
        or any(
            not isinstance(value, int) or isinstance(value, bool) or value < 0
            for value in usage.values()
        )
    ):
        raise AcceptanceError("bounded supervisor resource usage is invalid")


def batch_events(
    payload: bytes, *, require_canonical: bool = True
) -> list[Mapping[str, Any]]:
    if not payload.endswith(b"\n") or b"\r" in payload:
        raise AcceptanceError("batch output is not canonical JSONL framing")
    try:
        lines = payload.decode("utf-8").split("\n")[:-1]
    except UnicodeDecodeError as error:
        raise AcceptanceError("batch output is not strict UTF-8") from error
    if not 1 <= len(lines) <= 4096:
        raise AcceptanceError("batch output record count is invalid")
    events: list[Mapping[str, Any]] = []
    for line in lines:
        try:
            value = json.loads(
                line,
                object_pairs_hook=reject_duplicate_json_keys,
                parse_constant=reject_nonfinite_json_number,
            )
        except (AcceptanceError, json.JSONDecodeError) as error:
            raise AcceptanceError("batch output contains malformed JSON") from error
        if not isinstance(value, dict):
            raise AcceptanceError("batch output contains a non-object record")
        if require_canonical and canonical_json(value) != (line + "\n").encode("utf-8"):
            raise AcceptanceError("batch output contains a non-canonical record")
        events.append(value)
    return events


def reject_duplicate_json_keys(pairs: Sequence[tuple[str, Any]]) -> Mapping[str, Any]:
    value: dict[str, Any] = {}
    for key, item in pairs:
        if key in value:
            raise AcceptanceError("JSON object repeats a key")
        value[key] = item
    return value


def reject_nonfinite_json_number(value: str) -> None:
    raise AcceptanceError(f"JSON contains non-finite number: {value}")


def file_provider_lifecycle(
    payload: bytes,
) -> tuple[str, Optional[str], Optional[str], Optional[str]]:
    try:
        lines = payload.decode("utf-8").splitlines()
    except UnicodeDecodeError as error:
        raise AcceptanceError("File Provider output is not strict UTF-8") from error
    completion: list[Mapping[str, Any]] = []
    recovery: list[Mapping[str, Any]] = []
    for line in lines:
        try:
            value = json.loads(
                line,
                object_pairs_hook=reject_duplicate_json_keys,
                parse_constant=reject_nonfinite_json_number,
            )
        except json.JSONDecodeError:
            continue
        if not isinstance(value, dict):
            continue
        event = value.get("event")
        if event not in {"file_provider_acceptance", "file_provider_recovery"}:
            continue
        if canonical_json(value) != (line + "\n").encode("utf-8"):
            raise AcceptanceError("File Provider lifecycle receipt is not canonical")
        if event == "file_provider_acceptance":
            completion.append(value)
        else:
            recovery.append(value)
    if len(completion) == 1 and not recovery:
        value = completion[0]
        if (
            value.get("status") == "accepted"
            and value.get("lifecycle_completion") == "complete"
        ):
            return "complete", None, None, None
    if len(recovery) == 1 and not completion:
        value = recovery[0]
        locator = value.get("recovery_locator")
        derived_dir = value.get("derived_dir")
        recovery_kind = value.get("recovery_kind")
        if (
            value.get("status") == "recovery_required"
            and value.get("lifecycle_completion") == "incomplete"
            and recovery_kind in {"manifest", "run_id"}
            and isinstance(locator, str)
            and 1 <= len(locator) <= 4096
            and isinstance(derived_dir, str)
            and Path(derived_dir).is_absolute()
            and 1 <= len(derived_dir) <= 4096
            and (
                (recovery_kind == "manifest" and Path(locator).is_absolute())
                or (
                    recovery_kind == "run_id"
                    and re.fullmatch(
                        r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}",
                        locator,
                    )
                    is not None
                )
            )
        ):
            return "recovery_required", locator, derived_dir, recovery_kind
    return "unknown", None, None, None


def validate_batch(
    payload: bytes, expected_profile: str, persistence_enabled: bool = False
) -> None:
    events = batch_events(payload)
    started = [event for event in events if event.get("event") == "batch_started"]
    completed = [event for event in events if event.get("event") == "batch_completed"]
    if len(started) != 1 or len(completed) != 1:
        raise AcceptanceError(
            "batch output does not contain one start and one completion"
        )
    start = started[0]
    finish = completed[0]
    if start.get("schema") != 1 or start.get("profile") != expected_profile:
        raise AcceptanceError("batch start does not match the requested profile")
    if start.get("dry_run") is not True:
        raise AcceptanceError("batch start is not dry-run-only")
    if persistence_enabled:
        if start.get("history") is not True or start.get("audit_file") is not True:
            raise AcceptanceError(
                "batch start did not bind enabled optional persistence"
            )
    elif start.get("history") not in (None, False) or start.get("audit_file") not in (
        None,
        False,
    ):
        raise AcceptanceError("batch start did not bind disabled optional persistence")
    if finish.get("status") != "success" or finish.get("dry_run_complete") is not True:
        raise AcceptanceError(
            "batch completion is not an authoritative dry-run success"
        )
    if finish.get("mutation_attempts") != 0:
        raise AcceptanceError("batch completion reported a mutation attempt")
    history_attempts = finish.get("history_persistence_attempts")
    audit_attempts = finish.get("audit_file_persistence_attempts")
    if persistence_enabled:
        if not all(
            isinstance(value, int) and value >= 1
            for value in (history_attempts, audit_attempts)
        ):
            raise AcceptanceError(
                "enabled persistence did not attempt both optional artifacts"
            )
    elif history_attempts != 0 or audit_attempts != 0:
        raise AcceptanceError("disabled persistence reported an artifact write attempt")


def command_digest(argv: Iterable[str]) -> str:
    digest = hashlib.sha256()
    for argument in argv:
        encoded = os.fsencode(argument)
        digest.update(len(encoded).to_bytes(8, "big"))
        digest.update(encoded)
    return digest.hexdigest()


def lane_receipt(
    lane: Lane,
    status: str,
    reason: str,
    host: HostFacts,
    product: ProductFacts,
    audit_scope: Mapping[str, Any],
    gate_identity: Mapping[str, Any],
    result: Optional[CommandResult],
) -> Mapping[str, Any]:
    if status not in VALID_STATUSES:
        raise AcceptanceError("internal lane status is invalid")
    supervisor = result.status if result is not None else None
    return {
        "schema": SCHEMA,
        "lane": lane.lane_id,
        "requirement": lane.requirement,
        "status": status,
        "reason": reason,
        "host": {
            "hostname": host.hostname,
            "macos_version": host.macos_version,
            "macos_build": host.macos_build,
            "architecture": host.architecture,
            "hardware_model": host.hardware_model,
        },
        "product": {
            "version": product.version,
            "protocol": f"{product.protocol_major}.{product.protocol_minor}",
            "source_revision": product.source_revision,
            "manifest_sha256": product.manifest_sha256,
        },
        "audit_scope": audit_scope,
        "gate": gate_identity,
        "capabilities": {
            lane.capability: {
                "status": status,
                "reason": reason,
            }
        },
        "limits": {
            "timeout_seconds": lane.timeout_seconds,
            "max_output_bytes": lane.max_output_bytes,
            "max_resident_bytes": lane.max_resident_bytes,
        },
        "tools": {
            "harness": "india-acceptance-v1",
            "python": sys.version.split()[0],
            "supervisor": "run-bounded-v1",
            "executor": lane.executor,
        },
        "command": None
        if result is None
        else {
            "argv_template": list(result.argv_template),
            "argv_sha256": command_digest(result.argv_template),
            "output_sha256": hashlib.sha256(result.output).hexdigest(),
            "output_bytes": len(result.output),
        },
        "supervisor": supervisor,
    }


def executable_path(name: str) -> str:
    resolved = shutil.which(name)
    if resolved is None:
        raise AcceptanceError(f"required tool is unavailable: {name}")
    return resolved


def build_argv(
    lane: Lane,
    repo_root: Path,
    bundle: Path,
    prefix: Path,
    audit_root: Path,
    task_root: Path,
) -> list[str]:
    frontend = prefix / "bin/diskplan"

    def product_scoped(command: Sequence[str]) -> list[str]:
        home = task_root / f"{lane.lane_id}-home"
        temporary = task_root / f"{lane.lane_id}-tmp"
        return [
            executable_path("env"),
            f"HOME={home}",
            f"TMPDIR={temporary}",
            f"XDG_CACHE_HOME={home / 'cache'}",
            f"XDG_CONFIG_HOME={home / 'config'}",
            f"XDG_STATE_HOME={home / 'state'}",
            *command,
        ]

    def source_sealed(command: Sequence[str]) -> list[str]:
        return [
            sys.executable,
            str(repo_root / "scripts/release/india_source_acceptance.py"),
            "--repo-root",
            str(repo_root),
            "--expected-revision",
            read_product_facts(bundle).source_revision,
            "--",
            *command,
        ]

    batch_base = [
        str(frontend),
        "--batch",
        "--dry-run",
        "--no-history",
        "--no-audit-file",
    ]
    if lane.executor == "source-integrity":
        return [
            sys.executable,
            str(repo_root / "scripts/release/india_source_acceptance.py"),
            "--repo-root",
            str(repo_root),
            "--expected-revision",
            read_product_facts(bundle).source_revision,
        ]
    if lane.executor == "install":
        return product_scoped(
            [str(bundle / "install.sh"), "--prefix", str(prefix), str(bundle)]
        )
    if lane.executor == "handshake":
        return product_scoped([str(frontend), "--handshake"])
    if lane.executor == "standard-scan":
        return product_scoped(
            [*batch_base, "--profile", "standard", "--root", str(audit_root)]
        )
    if lane.executor == "full-audit":
        return product_scoped(
            [*batch_base, "--profile", "full-audit", "--root", str(audit_root)]
        )
    if lane.executor == "batch-dry-run":
        return product_scoped(
            [
                *batch_base,
                "--profile",
                "full-audit",
                "--root",
                str(task_root / "scan-root"),
            ]
        )
    if lane.executor in {"artifact-disabled", "artifact-enabled"}:
        return [
            sys.executable,
            str(repo_root / "scripts/release/india_artifact_acceptance.py"),
            "--mode",
            "enabled" if lane.executor == "artifact-enabled" else "disabled",
            "--frontend",
            str(frontend),
            "--scan-root",
            str(task_root / "scan-root"),
            "--state-root",
            str(task_root / (lane.lane_id + "-state")),
        ]
    if lane.executor == "file-provider":
        return source_sealed(
            [
                executable_path("env"),
                f"DISKPLAN_FILEPROVIDER_DERIVED_DIR={task_root / 'file-provider-derived'}",
                f"DISKPLAN_FILEPROVIDER_PACKAGES_DIR={task_root / 'file-provider-packages'}",
                f"DISKPLAN_FILEPROVIDER_BUILD_LOG={task_root / 'file-provider-build/signed-build.log'}",
                str(repo_root / "scripts/fileprovider-fixture.sh"),
                "accept",
            ]
        )
    if lane.executor == "tui-controls":
        return [
            executable_path("env"),
            f"HOME={task_root / 'tui-home'}",
            f"TMPDIR={task_root / 'tui-tmp'}",
            f"XDG_CACHE_HOME={task_root / 'tui-home/cache'}",
            f"XDG_CONFIG_HOME={task_root / 'tui-home/config'}",
            f"XDG_STATE_HOME={task_root / 'tui-home/state'}",
            sys.executable,
            str(repo_root / "scripts/release/india_tui_acceptance.py"),
            "--frontend",
            str(frontend),
        ]
    if lane.executor in {"swift-test", "million-entry"}:
        if lane.swift_filter is None:
            raise AcceptanceError("Swift acceptance lane is missing its filter")
        argv = [
            executable_path("env"),
            f"TMPDIR={task_root / (lane.lane_id + '-tmp')}",
        ]
        if lane.executor == "million-entry":
            argv.append("DISKPLAN_RUN_MILLION_ENTRY_GATE=1")
        swift_argv = [
            *argv,
            executable_path("swift"),
            "test",
            "--package-path",
            str(repo_root),
            "--scratch-path",
            str(task_root / (lane.lane_id + "-build")),
            "--filter",
            lane.swift_filter,
        ]
        if lane.lane_id == "apfs_owner_graph":
            return source_sealed(
                [
                    sys.executable,
                    str(repo_root / "scripts/release/india_apfs_acceptance.py"),
                    "--fixture-root",
                    str(task_root / "apfs-fixture"),
                    "--",
                    *swift_argv,
                ]
            )
        return source_sealed(swift_argv)
    raise AcceptanceError("acceptance lane executor is unknown")


def classify(
    lane: Lane,
    result: CommandResult,
) -> tuple[str, str]:
    exit_code = result.status.get("exit_code")
    supervisor_result = result.status.get("result")
    if not isinstance(exit_code, int) or not isinstance(supervisor_result, str):
        return "failure", "supervisor_status_invalid"
    if supervisor_result != "passed" or exit_code != 0:
        if (
            exit_code in UNSUPPORTED_EXIT_CODES
            and supervisor_result == "command_failed"
        ):
            return "unsupported", "capability_unavailable"
        if lane.executor == "artifact-enabled" and exit_code == 64:
            return "unsupported", "artifact_cli_seam_unavailable"
        return "failure", f"command_{supervisor_result}"
    try:
        if lane.executor == "source-integrity":
            events = batch_events(result.output)
            accepted = [
                event for event in events if event.get("event") == "source_acceptance"
            ]
            if len(accepted) != 1 or accepted[0].get("status") != "accepted":
                raise AcceptanceError("release source acceptance receipt is missing")
        elif lane.executor == "handshake":
            if not result.output.startswith(b"handshake ok: "):
                raise AcceptanceError("handshake output is invalid")
        elif lane.executor == "standard-scan":
            validate_batch(result.output, "standard")
        elif lane.executor in {"full-audit", "batch-dry-run", "artifact-disabled"}:
            validate_batch(result.output, "full-audit")
        elif lane.executor == "artifact-enabled":
            events = batch_events(result.output)
            accepted = [
                event for event in events if event.get("event") == "artifact_acceptance"
            ]
            if len(accepted) != 1 or accepted[0].get("status") != "accepted":
                raise AcceptanceError("enabled artifact acceptance receipt is missing")
        elif lane.executor == "file-provider":
            lifecycle, _locator, _derived_dir, _kind = file_provider_lifecycle(
                result.output
            )
            if lifecycle != "complete":
                raise AcceptanceError("File Provider lifecycle did not complete")
            events = batch_events(result.output, require_canonical=False)
            accepted = [event for event in events if event.get("status") == "accepted"]
            if (
                len(accepted) != 1
                or accepted[0].get("scanner_acceptance") != "accepted"
            ):
                return "unsupported", "scanner_file_provider_hook_unavailable"
        elif lane.executor == "tui-controls":
            required = (
                b"TUI PTY control/restore smoke test passed",
                b"partial plan finalized",
            )
            if any(marker not in result.output for marker in required):
                return "unsupported", "integrated_tui_acceptance_seam_unavailable"
        elif lane.executor in {"swift-test", "million-entry"}:
            if lane.expected_test_count is None:
                raise AcceptanceError("focused Swift test count is unavailable")
            marker = f"Test run with {lane.expected_test_count} test".encode()
            if marker not in result.output or b" passed" not in result.output:
                raise AcceptanceError(
                    "focused Swift tests did not prove the exact passing count"
                )
            if lane.executor == "million-entry":
                usage = result.status.get("resource_usage")
                if not isinstance(usage, dict):
                    raise AcceptanceError("million-entry resource usage is missing")
                resident = usage.get("max_resident_bytes")
                swaps = usage.get("swap_operations")
                if (
                    not isinstance(resident, int)
                    or lane.max_resident_bytes is None
                    or resident > lane.max_resident_bytes
                ):
                    raise AcceptanceError(
                        "million-entry resident-memory limit was exceeded"
                    )
                if swaps != 0:
                    raise AcceptanceError(
                        "million-entry process reported swap activity"
                    )
    except AcceptanceError as error:
        return "failure", str(error).replace(" ", "_")[:128]
    return "passed", "accepted"


def source_acceptance_identity(
    payload: bytes, expected_revision: str
) -> Mapping[str, str]:
    events = batch_events(payload)
    accepted = [event for event in events if event.get("event") == "source_acceptance"]
    if len(accepted) != 1 or accepted[0].get("status") != "accepted":
        raise AcceptanceError("release source acceptance receipt is missing")
    commit = accepted[0].get("repository_commit")
    tree = accepted[0].get("repository_tree")
    if (
        commit != expected_revision
        or not isinstance(commit, str)
        or not isinstance(tree, str)
        or len(commit) not in (40, 64)
        or len(tree) != len(commit)
        or any(character not in "0123456789abcdef" for character in commit + tree)
    ):
        raise AcceptanceError("release source acceptance identity is invalid")
    return {"repository_commit": commit, "repository_tree": tree}


def aggregate_status(receipts: Sequence[Mapping[str, Any]]) -> str:
    for receipt in receipts:
        status = receipt["status"]
        requirement = receipt["requirement"]
        if status == "failure" or (requirement == "required" and status != "passed"):
            return "failure"
    return "passed"


def path_is_within(path: Path, root: Path) -> bool:
    try:
        return os.path.commonpath((str(path), str(root))) == str(root)
    except ValueError:
        return False


def installed_product_matches(prefix: Path, expected: ProductFacts) -> bool:
    try:
        installed = read_product_facts(prefix / "libexec/diskplan" / expected.version)
    except (AcceptanceError, OSError):
        return False
    return installed == expected


def file_provider_requires_retention(lifecycle_state: str) -> bool:
    return lifecycle_state in {"started", "unknown", "recovery_required"}


def file_provider_recovery_argv(
    repo_root: Path,
    lifecycle_state: str,
    recovery_kind: Optional[str],
    recovery_locator: Optional[str],
    derived_dir: Optional[str],
) -> Optional[list[str]]:
    if lifecycle_state != "recovery_required":
        return None
    if (
        recovery_kind not in {"manifest", "run_id"}
        or recovery_locator is None
        or derived_dir is None
    ):
        raise AcceptanceError("File Provider recovery command is incomplete")
    return [
        executable_path("env"),
        f"DISKPLAN_FILEPROVIDER_DERIVED_DIR={derived_dir}",
        str(repo_root / "scripts/fileprovider-fixture.sh"),
        "recover" if recovery_kind == "manifest" else "recover-unpublished",
        recovery_locator,
    ]


def harness_source_identity(repo_root: Path) -> Mapping[str, str]:
    sources = (
        "fixtures/release/india-acceptance-v1.json",
        "scripts/fileprovider-fixture.sh",
        "scripts/release/india-acceptance.sh",
        "scripts/release/india_acceptance.py",
        "scripts/release/india_apfs_acceptance.py",
        "scripts/release/india_artifact_acceptance.py",
        "scripts/release/india_source_acceptance.py",
        "scripts/release/india_tui_acceptance.py",
        "scripts/release/run_bounded.py",
    )
    digest = hashlib.sha256()
    individual: dict[str, str] = {}
    for relative in sources:
        payload = read_bounded_regular(repo_root / relative, 2 * 1024 * 1024, relative)
        source_digest = hashlib.sha256(payload).hexdigest()
        individual[relative] = source_digest
        encoded = relative.encode("utf-8")
        digest.update(len(encoded).to_bytes(4, "big"))
        digest.update(encoded)
        digest.update(bytes.fromhex(source_digest))
    return {
        "catalog_sha256": individual["fixtures/release/india-acceptance-v1.json"],
        "source_set_sha256": digest.hexdigest(),
    }


def command_template(
    argv: Sequence[str],
    *,
    repo_root: Path,
    bundle: Path,
    task_root: Path,
    audit_root: Path,
) -> tuple[str, ...]:
    roots = (
        (task_root, "$TASK_ROOT"),
        (bundle, "$BUNDLE"),
        (repo_root, "$REPO"),
        (audit_root, "$AUDIT_ROOT"),
    )

    def redact(argument: str) -> str:
        prefix = ""
        value = argument
        if "=" in argument:
            candidate_prefix, candidate_value = argument.split("=", 1)
            if candidate_prefix.isidentifier():
                prefix, value = candidate_prefix + "=", candidate_value
        value_path = Path(value)
        if value_path.is_absolute():
            for root, token in roots:
                if value_path == root:
                    return prefix + token
                try:
                    relative = value_path.relative_to(root)
                except ValueError:
                    continue
                return prefix + token + "/" + str(relative)
        return argument

    return tuple(redact(argument) for argument in argv)


class CleanupBudget:
    def __init__(self) -> None:
        self.deadline = time.monotonic() + CLEANUP_TIMEOUT_SECONDS
        self.entries = 0

    def consume(self) -> None:
        self.entries += 1
        if self.entries > MAX_CLEANUP_ENTRIES or time.monotonic() >= self.deadline:
            raise AcceptanceError("task-root cleanup exceeded its bound")


def access_tuple(metadata: os.stat_result) -> tuple[int, int, int]:
    return metadata.st_uid, metadata.st_gid, stat.S_IMODE(metadata.st_mode)


def remove_directory_contents(
    descriptor: int,
    root_device: int,
    budget: CleanupBudget,
) -> None:
    for name in os.listdir(descriptor):
        budget.consume()
        before = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
        if stat.S_ISDIR(before.st_mode):
            if before.st_dev != root_device:
                raise AcceptanceError("task-root cleanup encountered a mount boundary")
            child = os.open(
                name,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=descriptor,
            )
            try:
                opened = os.fstat(child)
                if (before.st_dev, before.st_ino, access_tuple(before)) != (
                    opened.st_dev,
                    opened.st_ino,
                    access_tuple(opened),
                ):
                    raise AcceptanceError("task-root directory changed before cleanup")
                remove_directory_contents(child, root_device, budget)
                final = os.fstat(child)
                slot = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
                if (opened.st_dev, opened.st_ino, access_tuple(opened)) != (
                    final.st_dev,
                    final.st_ino,
                    access_tuple(final),
                ) or (opened.st_dev, opened.st_ino, access_tuple(opened)) != (
                    slot.st_dev,
                    slot.st_ino,
                    access_tuple(slot),
                ):
                    raise AcceptanceError("task-root directory changed during cleanup")
            finally:
                os.close(child)
            os.rmdir(name, dir_fd=descriptor)
        else:
            slot = os.stat(name, dir_fd=descriptor, follow_symlinks=False)
            if (before.st_dev, before.st_ino, before.st_mode, access_tuple(before)) != (
                slot.st_dev,
                slot.st_ino,
                slot.st_mode,
                access_tuple(slot),
            ):
                raise AcceptanceError("task-root leaf changed before cleanup")
            os.unlink(name, dir_fd=descriptor)


def remove_task_root(task_root: Path) -> tuple[bool, str]:
    try:
        parent = task_root.parent
        name = task_root.name
        parent_descriptor = os.open(
            parent,
            os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC | getattr(os, "O_NOFOLLOW", 0),
        )
        try:
            before = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
            if not stat.S_ISDIR(before.st_mode) or before.st_uid != os.getuid():
                raise AcceptanceError("task root is not an owned directory")
            root = os.open(
                name,
                os.O_RDONLY
                | os.O_DIRECTORY
                | os.O_CLOEXEC
                | getattr(os, "O_NOFOLLOW", 0),
                dir_fd=parent_descriptor,
            )
            try:
                opened = os.fstat(root)
                if (before.st_dev, before.st_ino, access_tuple(before)) != (
                    opened.st_dev,
                    opened.st_ino,
                    access_tuple(opened),
                ):
                    raise AcceptanceError("task root changed before cleanup")
                remove_directory_contents(root, opened.st_dev, CleanupBudget())
                final = os.fstat(root)
                slot = os.stat(name, dir_fd=parent_descriptor, follow_symlinks=False)
                if (opened.st_dev, opened.st_ino, access_tuple(opened)) != (
                    final.st_dev,
                    final.st_ino,
                    access_tuple(final),
                ) or (opened.st_dev, opened.st_ino, access_tuple(opened)) != (
                    slot.st_dev,
                    slot.st_ino,
                    access_tuple(slot),
                ):
                    raise AcceptanceError("task root changed during cleanup")
            finally:
                os.close(root)
            os.rmdir(name, dir_fd=parent_descriptor)
        finally:
            os.close(parent_descriptor)
        return True, "removed"
    except (AcceptanceError, OSError) as error:
        return False, type(error).__name__


def parse_args(arguments: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--audit-root", type=Path, default=Path.home())
    parser.add_argument("--describe", action="store_true")
    parser.add_argument("--keep-task-root", action="store_true")
    args = parser.parse_args(arguments)
    if not args.describe and args.bundle is None:
        parser.error("--bundle is required")
    return args


def main(arguments: Optional[Sequence[str]] = None) -> int:
    args = parse_args(arguments)
    script_dir = Path(__file__).resolve().parent
    repo_root = script_dir.parent.parent
    catalog_path = repo_root / "fixtures/release/india-acceptance-v1.json"
    target, lanes = load_catalog(catalog_path)
    if args.describe:
        sys.stdout.buffer.write(
            canonical_json(
                {
                    "schema": SCHEMA,
                    "target": target,
                    "lanes": [lane.__dict__ for lane in lanes],
                }
            )
        )
        return 0

    facts = collect_host_facts()
    enforce_release_target(facts)
    bundle = validate_bundle_path(args.bundle)
    audit_root = args.audit_root
    if not audit_root.is_absolute() or not audit_root.is_dir():
        raise AcceptanceError("audit root must be an existing absolute directory")
    audit_scope = bind_audit_scope(audit_root)
    product = read_product_facts(bundle)
    gate_identity: dict[str, str] = {
        "version": "india-acceptance-v1",
        **harness_source_identity(repo_root),
    }

    temporary_parent = Path("/private/tmp")
    if not temporary_parent.is_dir():
        raise AcceptanceError("the fixed task-state parent is unavailable")
    temporary_identity_path = temporary_parent.resolve(strict=True)
    if path_is_within(temporary_identity_path, audit_scope.canonical_path):
        audit_scope.close()
        raise AcceptanceError("task state would be visible inside the active scan root")
    task_root = Path(
        tempfile.mkdtemp(prefix="diskplan-india-acceptance.", dir=temporary_parent)
    )
    os.chmod(task_root, 0o700)
    output_root = task_root / "outputs"
    output_root.mkdir(mode=0o700)
    (task_root / "scan-root").mkdir(mode=0o700)
    (task_root / "artifacts").mkdir(mode=0o700)
    for lane in lanes:
        if lane.executor in {"swift-test", "million-entry", "tui-controls"}:
            (task_root / (lane.lane_id + "-tmp")).mkdir(mode=0o700, exist_ok=True)
        if lane.executor in {
            "install",
            "handshake",
            "standard-scan",
            "full-audit",
            "batch-dry-run",
        }:
            (task_root / (lane.lane_id + "-home")).mkdir(mode=0o700)
            (task_root / (lane.lane_id + "-tmp")).mkdir(mode=0o700)
    (task_root / "tui-home").mkdir(mode=0o700)
    (task_root / "tui-tmp").mkdir(mode=0o700)

    runner = BoundedRunner(script_dir / "run_bounded.py", output_root)
    previous_handlers = {
        number: signal.getsignal(number)
        for number in (signal.SIGHUP, signal.SIGINT, signal.SIGTERM)
    }
    for number in previous_handlers:
        signal.signal(number, runner.forward)
    receipts: list[Mapping[str, Any]] = []
    statuses: dict[str, str] = {}
    file_provider_state = "not_started"
    file_provider_recovery_locator: Optional[str] = None
    file_provider_recovery_derived_dir: Optional[str] = None
    file_provider_recovery_kind: Optional[str] = None
    for lane in lanes:
        failed_dependencies = [
            dependency
            for dependency in lane.dependencies
            if statuses.get(dependency) != "passed"
        ]
        if runner.received_signal is not None:
            receipt = lane_receipt(
                lane,
                "skipped",
                "acceptance_interrupted",
                facts,
                product,
                audit_scope.receipt(),
                gate_identity,
                None,
            )
        elif failed_dependencies:
            receipt = lane_receipt(
                lane,
                "skipped",
                "dependency_not_passed",
                facts,
                product,
                audit_scope.receipt(),
                gate_identity,
                None,
            )
        else:
            try:
                audit_scope.revalidate()
                argv = build_argv(
                    lane, repo_root, bundle, task_root / "prefix", audit_root, task_root
                )
                template = command_template(
                    argv,
                    repo_root=repo_root,
                    bundle=bundle,
                    task_root=task_root,
                    audit_root=audit_root,
                )
                if lane.executor == "file-provider":
                    file_provider_state = "started"
                result = runner.run(lane, argv, template)
                if lane.executor == "file-provider":
                    (
                        file_provider_state,
                        file_provider_recovery_locator,
                        file_provider_recovery_derived_dir,
                        file_provider_recovery_kind,
                    ) = file_provider_lifecycle(result.output)
                    if (
                        file_provider_state == "recovery_required"
                        and file_provider_recovery_derived_dir
                        != str(task_root / "file-provider-derived")
                    ):
                        file_provider_state = "unknown"
                        file_provider_recovery_locator = None
                        file_provider_recovery_derived_dir = None
                        file_provider_recovery_kind = None
                audit_scope.revalidate()
                status, reason = classify(lane, result)
                if lane.executor == "source-integrity" and status == "passed":
                    gate_identity.update(
                        source_acceptance_identity(
                            result.output, product.source_revision
                        )
                    )
                if (
                    lane.executor == "install"
                    and status == "passed"
                    and not installed_product_matches(task_root / "prefix", product)
                ):
                    status, reason = "failure", "installed_product_identity_mismatch"
                receipt = lane_receipt(
                    lane,
                    status,
                    reason,
                    facts,
                    product,
                    audit_scope.receipt(),
                    gate_identity,
                    result,
                )
            except (AcceptanceError, OSError) as error:
                receipt = lane_receipt(
                    lane,
                    "failure",
                    type(error).__name__,
                    facts,
                    product,
                    audit_scope.receipt(),
                    gate_identity,
                    None,
                )
        statuses[lane.lane_id] = receipt["status"]
        receipts.append(receipt)
        sys.stdout.buffer.write(canonical_json({"event": "lane_receipt", **receipt}))
        sys.stdout.buffer.flush()

    overall = aggregate_status(receipts)
    integrity_status = "passed"
    integrity_reason = "accepted"
    try:
        audit_scope.revalidate()
        current_gate_identity = {
            "version": "india-acceptance-v1",
            **harness_source_identity(repo_root),
        }
        if any(
            gate_identity.get(key) != value
            for key, value in current_gate_identity.items()
        ):
            raise AcceptanceError("acceptance harness source changed during the run")
    except (AcceptanceError, OSError):
        overall = "failure"
        integrity_status = "failure"
        integrity_reason = "gate_or_audit_identity_changed"
    cleanup_succeeded = False
    cleanup_reason = "retained_by_request"
    retain_for_file_provider = file_provider_requires_retention(file_provider_state)
    if retain_for_file_provider:
        overall = "failure"
        cleanup_reason = "file_provider_recovery_required"
    elif not args.keep_task_root:
        cleanup_succeeded, cleanup_reason = remove_task_root(task_root)
        if not cleanup_succeeded:
            overall = "failure"
    report = canonical_json(
        {
            "schema": SCHEMA,
            "event": "acceptance_summary",
            "status": overall,
            "target": target,
            "lane_count": len(receipts),
            "receipts_sha256": hashlib.sha256(
                b"".join(canonical_json(receipt) for receipt in receipts)
            ).hexdigest(),
            "audit_scope": audit_scope.receipt(),
            "gate": gate_identity,
            "integrity": {"status": integrity_status, "reason": integrity_reason},
            "file_provider_recovery": {
                "lifecycle_state": file_provider_state,
                "recovery_locator": file_provider_recovery_locator,
                "derived_dir": file_provider_recovery_derived_dir,
                "recovery_kind": file_provider_recovery_kind,
                "recovery_argv": file_provider_recovery_argv(
                    repo_root,
                    file_provider_state,
                    file_provider_recovery_kind,
                    file_provider_recovery_locator,
                    file_provider_recovery_derived_dir,
                ),
            },
            "termination_signal": None
            if runner.received_signal is None
            else signal.Signals(runner.received_signal).name,
            "cleanup": {
                "status": "passed"
                if cleanup_succeeded
                else "failure"
                if retain_for_file_provider or not args.keep_task_root
                else "skipped",
                "reason": cleanup_reason,
                "retained_locator": None if cleanup_succeeded else str(task_root),
            },
        }
    )
    sys.stdout.buffer.write(report)
    exit_status = (
        128 + runner.received_signal
        if runner.received_signal is not None
        else 0
        if overall == "passed"
        else 1
    )
    audit_scope.close()
    for number, handler in previous_handlers.items():
        signal.signal(number, handler)
    return exit_status


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except AcceptanceError as error:
        print(f"diskplan India acceptance: {error}", file=sys.stderr)
        raise SystemExit(1)
