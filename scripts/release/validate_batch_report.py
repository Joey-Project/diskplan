#!/usr/bin/env python3

import json
import hashlib
import os
import pathlib
import stat
import sys

MAXIMUM_REPORT_BYTES = 1024 * 1024
MAXIMUM_REPORT_LINES = 4096
EXPECTED_TERMINAL_KEYS = {
    "schema",
    "event",
    "status",
    "authoritative_plan",
    "dry_run_complete",
    "scan_session_id",
    "scan_checkpoint_id",
    "checkpoint_evidence_hash",
    "evidence_id",
    "evidence_hash",
    "completed_roots",
    "partial_roots",
    "observed_entries",
    "projection_id",
    "projection_hash",
    "plan_id",
    "plan_hash",
    "plan_actions",
    "cleanup_candidates",
    "overlay_id",
    "overlay_revision",
    "overlay_hash",
    "selected_actions",
    "execution_epoch_id",
    "current_binding_hash",
    "dry_run_manifest_hash",
    "revalidation_hash",
    "revalidated_actions",
    "would_apply_actions",
    "blocked_actions",
    "mutation_attempts",
    "history_persistence_attempts",
    "audit_file_persistence_attempts",
}


def fail(message: str) -> None:
    raise ValueError(message)


def parse_supervisor_status(raw_status: str) -> tuple[int, str]:
    try:
        status = json.loads(raw_status, object_pairs_hook=unique_object)
    except json.JSONDecodeError as error:
        fail(f"supervisor status is not valid JSON: {error}")
    if not isinstance(status, dict):
        fail("supervisor status is not a JSON object")
    output_bytes = status.get("output_bytes")
    output_sha256 = status.get("output_sha256")
    cleanup = status.get("cleanup")
    if (
        status.get("result") != "passed"
        or status.get("exit_code") != 0
        or status.get("leader_exit_code") != 0
        or status.get("process_group_verified") is not True
        or not isinstance(cleanup, dict)
        or cleanup.get("quiescent") is not True
    ):
        fail("supervisor status is not a quiescent successful command")
    if (
        not isinstance(output_bytes, int)
        or isinstance(output_bytes, bool)
        or not 0 <= output_bytes <= MAXIMUM_REPORT_BYTES
    ):
        fail("supervisor status has an invalid output_bytes")
    if (
        not isinstance(output_sha256, str)
        or len(output_sha256) != 64
        or any(character not in "0123456789abcdef" for character in output_sha256)
    ):
        fail("supervisor status has an invalid output_sha256")
    return output_bytes, output_sha256


def report_seal(metadata: os.stat_result) -> tuple[int, ...]:
    return (
        metadata.st_dev,
        metadata.st_ino,
        metadata.st_mode,
        metadata.st_uid,
        metadata.st_gid,
        metadata.st_nlink,
        metadata.st_size,
        getattr(metadata, "st_flags", 0),
    )


def read_sealed_report(
    report_path: pathlib.Path,
    expected_bytes: int,
    expected_sha256: str,
) -> bytes:
    if not hasattr(os, "O_NOFOLLOW"):
        fail("no-follow report open is unavailable")
    descriptor = os.open(
        report_path,
        os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW,
    )
    try:
        before = os.fstat(descriptor)
        if (
            not stat.S_ISREG(before.st_mode)
            or before.st_uid != os.geteuid()
            or before.st_gid != os.getegid()
            or stat.S_IMODE(before.st_mode) != 0o600
            or before.st_nlink != 1
        ):
            fail("batch report object or access policy is unsafe")
        if before.st_size != expected_bytes:
            fail("batch report size does not match supervisor output_bytes")

        chunks: list[bytes] = []
        total = 0
        while True:
            chunk = os.read(descriptor, min(64 * 1024, MAXIMUM_REPORT_BYTES + 1 - total))
            if not chunk:
                break
            chunks.append(chunk)
            total += len(chunk)
            if total > MAXIMUM_REPORT_BYTES:
                fail("batch report exceeds the retained-output bound")
        after = os.fstat(descriptor)
    finally:
        os.close(descriptor)

    if report_seal(before) != report_seal(after):
        fail("batch report identity, size, or access policy changed during validation")
    payload = b"".join(chunks)
    if len(payload) != expected_bytes:
        fail("batch report bytes do not match supervisor output_bytes")
    if hashlib.sha256(payload).hexdigest() != expected_sha256:
        fail("batch report digest does not match supervisor output_sha256")
    return payload


def read_events(payload: bytes) -> list[dict[str, object]]:
    if not payload:
        fail("batch report is empty")
    raw_lines = payload.splitlines()
    if not raw_lines or len(raw_lines) > MAXIMUM_REPORT_LINES:
        fail("batch report has an invalid line count")

    events: list[dict[str, object]] = []
    for index, raw_line in enumerate(raw_lines, start=1):
        if not raw_line or len(raw_line) > 64 * 1024:
            fail(f"batch report line {index} is empty or oversized")
        try:
            event = json.loads(raw_line, object_pairs_hook=unique_object)
        except (UnicodeDecodeError, json.JSONDecodeError) as error:
            fail(f"batch report line {index} is not valid NDJSON: {error}")
        if not isinstance(event, dict):
            fail(f"batch report line {index} is not a JSON object")
        events.append(event)
    return events


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        if key in result:
            fail(f"duplicate JSON object key: {key}")
        result[key] = value
    return result


def validate_started(event: dict[str, object], root: str) -> None:
    expected = {
        "schema": 1,
        "event": "batch_started",
        "profile": "full-audit",
        "selection_preset": "safe-stageable-without-waiver",
        "root_hex": os.fsencode(root).hex(),
        "dry_run": True,
        "history": False,
        "audit_file": False,
    }
    if event != expected:
        fail("batch_started does not exactly bind the requested no-persistence dry-run")


def bounded_identifier(event: dict[str, object], key: str) -> None:
    value = event.get(key)
    if (
        not isinstance(value, str)
        or not value
        or len(value) > 256
        or any(ord(character) < 0x20 or ord(character) > 0x7E for character in value)
        or '"' in value
        or "\\" in value
    ):
        fail(f"terminal batch report has an invalid {key}")


def nonnegative_integer(event: dict[str, object], key: str) -> int:
    value = event.get(key)
    if not isinstance(value, int) or isinstance(value, bool) or value < 0:
        fail(f"terminal batch report has an invalid {key}")
    return value


def validate_terminal(event: dict[str, object]) -> None:
    if set(event) != EXPECTED_TERMINAL_KEYS:
        fail("terminal batch report has missing or unknown fields")
    if (
        event.get("schema") != 1
        or event.get("event") != "batch_completed"
        or event.get("status") != "success"
        or event.get("authoritative_plan") is not True
        or event.get("dry_run_complete") is not True
    ):
        fail("terminal batch report is not an authoritative dry-run success")

    for key in (
        "scan_session_id",
        "scan_checkpoint_id",
        "projection_id",
        "overlay_id",
        "execution_epoch_id",
    ):
        bounded_identifier(event, key)
    for key in (
        "checkpoint_evidence_hash",
        "evidence_id",
        "evidence_hash",
        "projection_hash",
        "plan_id",
        "plan_hash",
        "overlay_hash",
        "current_binding_hash",
        "dry_run_manifest_hash",
        "revalidation_hash",
    ):
        digest = event.get(key)
        if (
            not isinstance(digest, str)
            or len(digest) != 64
            or any(character not in "0123456789abcdef" for character in digest)
            or set(digest) == {"0"}
        ):
            fail(f"terminal batch report has an invalid {key}")

    for key in (
        "completed_roots",
        "partial_roots",
        "observed_entries",
        "plan_actions",
        "cleanup_candidates",
        "overlay_revision",
        "selected_actions",
        "revalidated_actions",
        "would_apply_actions",
        "blocked_actions",
        "mutation_attempts",
        "history_persistence_attempts",
        "audit_file_persistence_attempts",
    ):
        nonnegative_integer(event, key)
    if event["mutation_attempts"] != 0:
        fail("dry-run reported a mutation attempt")
    if event["history_persistence_attempts"] != 0:
        fail("no-history batch reported a history persistence attempt")
    if event["audit_file_persistence_attempts"] != 0:
        fail("no-audit-file batch reported an audit persistence attempt")
    if event["cleanup_candidates"] > event["plan_actions"]:
        fail("cleanup candidates exceed plan actions")
    if event["selected_actions"] > event["plan_actions"]:
        fail("selected actions exceed plan actions")
    if event["overlay_revision"] == 0:
        fail("overlay revision must be non-zero")
    if event["scan_checkpoint_id"] != event["evidence_hash"]:
        fail("scan checkpoint ID is not the lowercase final evidence digest")
    if event["evidence_id"] != event["evidence_hash"]:
        fail("evidence ID does not match evidence hash")
    if event["plan_id"] != event["plan_hash"]:
        fail("plan ID does not match plan hash")
    if event["revalidated_actions"] != event["selected_actions"]:
        fail("dry-run did not revalidate the selected plan")
    if event["would_apply_actions"] + event["blocked_actions"] != event["selected_actions"]:
        fail("dry-run outcomes do not cover the selected plan")


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: validate_batch_report.py REPORT ROOT SUPERVISOR_STATUS_JSON", file=sys.stderr)
        return 64
    try:
        expected_bytes, expected_sha256 = parse_supervisor_status(sys.argv[3])
        payload = read_sealed_report(
            pathlib.Path(sys.argv[1]),
            expected_bytes,
            expected_sha256,
        )
        events = read_events(payload)
        if len(events) != 2:
            fail("batch report must contain one start and one terminal event")
        validate_started(events[0], sys.argv[2])
        validate_terminal(events[1])
    except (OSError, ValueError) as error:
        print(f"invalid batch report: {error}", file=sys.stderr)
        return 65
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
