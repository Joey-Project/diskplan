#!/usr/bin/env python3
"""Behavior tests for the India batch terminal-report validator."""

from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


VALIDATOR = Path(__file__).with_name("validate_batch_report.py")
ROOT = "/private/tmp/audit-root"


def started() -> dict[str, object]:
    return {
        "schema": 1,
        "event": "batch_started",
        "profile": "full-audit",
        "selection_preset": "safe-stageable-without-waiver",
        "root_hex": os.fsencode(ROOT).hex(),
        "dry_run": True,
        "history": False,
        "audit_file": False,
    }


def completed() -> dict[str, object]:
    return {
        "schema": 1,
        "event": "batch_completed",
        "status": "success",
        "authoritative_plan": True,
        "dry_run_complete": True,
        "scan_session_id": "scan-1",
        "scan_checkpoint_id": "22" * 32,
        "checkpoint_evidence_hash": "11" * 32,
        "evidence_id": "22" * 32,
        "evidence_hash": "22" * 32,
        "completed_roots": 1,
        "partial_roots": 0,
        "observed_entries": 10,
        "projection_id": "projection-1",
        "projection_hash": "33" * 32,
        "plan_id": "5a" * 32,
        "plan_hash": "5a" * 32,
        "plan_actions": 3,
        "cleanup_candidates": 2,
        "overlay_id": "overlay-1",
        "overlay_revision": 1,
        "overlay_hash": "a5" * 32,
        "selected_actions": 2,
        "execution_epoch_id": "epoch-1",
        "current_binding_hash": "44" * 32,
        "dry_run_manifest_hash": "55" * 32,
        "revalidation_hash": "66" * 32,
        "revalidated_actions": 2,
        "would_apply_actions": 1,
        "blocked_actions": 1,
        "mutation_attempts": 0,
        "history_persistence_attempts": 0,
        "audit_file_persistence_attempts": 0,
    }


def supervisor_status(payload: bytes) -> str:
    return json.dumps(
        {
            "cleanup": {"quiescent": True},
            "exit_code": 0,
            "leader_exit_code": 0,
            "output_bytes": len(payload),
            "output_sha256": hashlib.sha256(payload).hexdigest(),
            "process_group_verified": True,
            "result": "passed",
        },
        separators=(",", ":"),
    )


class ValidateBatchReportTests(unittest.TestCase):
    def validate(self, events: list[dict[str, object]]) -> subprocess.CompletedProcess[str]:
        payload = "".join(
            json.dumps(event, separators=(",", ":")) + "\n" for event in events
        ).encode()
        return self.validate_raw(payload, supervisor_status(payload))

    def validate_raw(
        self,
        payload: bytes,
        status: str,
        *,
        report_is_symlink: bool = False,
    ) -> subprocess.CompletedProcess[str]:
        with tempfile.TemporaryDirectory(prefix="diskplan-batch-report-test.") as temporary:
            root = Path(temporary)
            target = root / "target.ndjson"
            target.write_bytes(payload)
            target.chmod(0o600)
            report = root / "batch.ndjson"
            if report_is_symlink:
                report.symlink_to(target)
            else:
                report.write_bytes(payload)
                report.chmod(0o600)
            return subprocess.run(
                [sys.executable, str(VALIDATOR), str(report), ROOT, status],
                check=False,
                capture_output=True,
                text=True,
                timeout=5,
            )

    def test_authoritative_dry_run_report_passes(self) -> None:
        result = self.validate([started(), completed()])
        self.assertEqual(result.returncode, 0, result.stderr)

    def test_scan_only_or_empty_report_cannot_pass(self) -> None:
        for events in ([], [started()], [started(), {"schema": 1, "event": "scan_completed"}]):
            with self.subTest(events=events):
                self.assertEqual(self.validate(events).returncode, 65)

    def test_mutation_or_incomplete_action_coverage_cannot_pass(self) -> None:
        for key, value in (
            ("mutation_attempts", 1),
            ("history_persistence_attempts", 1),
            ("audit_file_persistence_attempts", 1),
            ("revalidated_actions", 1),
            ("would_apply_actions", 0),
            ("scan_checkpoint_id", "11" * 32),
            ("plan_id", "99" * 32),
            ("evidence_id", "99" * 32),
        ):
            terminal = completed()
            terminal[key] = value
            with self.subTest(key=key):
                self.assertEqual(self.validate([started(), terminal]).returncode, 65)

    def test_unknown_terminal_fields_cannot_weaken_the_contract(self) -> None:
        terminal = completed()
        terminal["scan_only_success"] = True
        self.assertEqual(self.validate([started(), terminal]).returncode, 65)

    def test_duplicate_terminal_keys_cannot_override_a_failure(self) -> None:
        terminal = json.dumps(completed(), separators=(",", ":")).replace(
            '"mutation_attempts":0',
            '"mutation_attempts":1,"mutation_attempts":0',
        )
        payload = (
            json.dumps(started(), separators=(",", ":")) + "\n" + terminal + "\n"
        ).encode()
        result = self.validate_raw(payload, supervisor_status(payload))
        self.assertEqual(result.returncode, 65)

    def test_supervisor_size_digest_and_quiescence_are_exact(self) -> None:
        payload = (
            json.dumps(started(), separators=(",", ":"))
            + "\n"
            + json.dumps(completed(), separators=(",", ":"))
            + "\n"
        ).encode()
        status = json.loads(supervisor_status(payload))
        for key, value in (
            ("output_bytes", len(payload) + 1),
            ("output_sha256", "00" * 32),
            ("result", "command_failed"),
        ):
            invalid = dict(status)
            invalid[key] = value
            with self.subTest(key=key):
                result = self.validate_raw(payload, json.dumps(invalid, separators=(",", ":")))
                self.assertEqual(result.returncode, 65)

    def test_report_symlink_is_rejected_before_reading(self) -> None:
        payload = b"not consulted"
        result = self.validate_raw(
            payload,
            supervisor_status(payload),
            report_is_symlink=True,
        )
        self.assertEqual(result.returncode, 65)


if __name__ == "__main__":
    unittest.main()
