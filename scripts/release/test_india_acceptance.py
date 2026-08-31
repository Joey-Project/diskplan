#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import hashlib
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).with_name("india_acceptance.py")
SPEC = importlib.util.spec_from_file_location("india_acceptance", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
india_acceptance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = india_acceptance
SPEC.loader.exec_module(india_acceptance)


class IndiaAcceptanceTests(unittest.TestCase):
    def catalog(self) -> Path:
        return Path(__file__).parents[2] / "fixtures/release/india-acceptance-v1.json"

    def test_catalog_is_ordered_and_covers_the_release_matrix(self) -> None:
        target, lanes = india_acceptance.load_catalog(self.catalog())
        self.assertEqual(target["host"], "India-mac-mini-m4-hoteng")
        self.assertEqual(
            [lane.lane_id for lane in lanes],
            [
                "source_integrity",
                "install",
                "handshake",
                "standard_scan",
                "bounded_full_audit",
                "file_provider_no_materialization",
                "apfs_owner_graph",
                "activity_snapshot",
                "million_entry_performance",
                "batch_dry_run",
                "tui_controls",
                "optional_artifact_disabled",
                "optional_artifact_enabled",
                "source_integrity_final",
            ],
        )
        self.assertTrue(all(lane.requirement == "required" for lane in lanes))
        apfs = next(lane for lane in lanes if lane.lane_id == "apfs_owner_graph")
        self.assertEqual(apfs.expected_test_count, 4)
        self.assertEqual(len((apfs.swift_filter or "").split("|")), 4)

    def test_release_target_rejects_every_hostname_except_india(self) -> None:
        accepted = india_acceptance.HostFacts(
            "India-mac-mini-m4-hoteng", "26.0", "25A1", "arm64", "Mac16,1"
        )
        india_acceptance.enforce_release_target(accepted)
        for hostname in ("BL-mac-mini-m4-hoteng", "india-mac-mini-m4-hoteng", "India"):
            with (
                self.subTest(hostname=hostname),
                self.assertRaises(india_acceptance.AcceptanceError),
            ):
                india_acceptance.enforce_release_target(
                    india_acceptance.HostFacts(
                        hostname, "26.0", "25A1", "arm64", "Mac16,1"
                    )
                )

    def test_release_target_rejects_wrong_os_or_architecture(self) -> None:
        for version, architecture in (
            ("25.9", "arm64"),
            ("26.0", "x86_64"),
            ("future", "arm64"),
        ):
            with (
                self.subTest(version=version, architecture=architecture),
                self.assertRaises(india_acceptance.AcceptanceError),
            ):
                india_acceptance.enforce_release_target(
                    india_acceptance.HostFacts(
                        "India-mac-mini-m4-hoteng",
                        version,
                        "build",
                        architecture,
                        "model",
                    )
                )

    def test_task_state_must_not_be_inside_the_active_scan_root(self) -> None:
        self.assertTrue(
            india_acceptance.path_is_within(
                Path("/private/tmp/task"), Path("/private/tmp")
            )
        )
        self.assertFalse(
            india_acceptance.path_is_within(
                Path("/private/tmp/task"), Path("/Users/example")
            )
        )

    def test_installed_product_identity_must_match_preflight_bundle(self) -> None:
        expected = india_acceptance.ProductFacts(
            "1.2.3", 1, 3, "revision-a", "digest-a"
        )
        with tempfile.TemporaryDirectory() as parent:
            installed = Path(parent) / "libexec/diskplan/1.2.3"
            installed.mkdir(parents=True)
            (installed / "VERSION").write_text("1.2.3\n", encoding="ascii")
            manifest = {
                "product_version": "1.2.3",
                "protocol_major": 1,
                "protocol_minor": 3,
                "source_revision": "revision-a",
            }
            payload = json.dumps(manifest, sort_keys=True).encode()
            (installed / "manifest.json").write_bytes(payload)
            actual = india_acceptance.ProductFacts(
                "1.2.3",
                1,
                3,
                "revision-a",
                hashlib.sha256(payload).hexdigest(),
            )
            self.assertTrue(
                india_acceptance.installed_product_matches(Path(parent), actual)
            )
            self.assertFalse(
                india_acceptance.installed_product_matches(Path(parent), expected)
            )

    def test_batch_validator_accepts_only_authoritative_zero_mutation_dry_run(
        self,
    ) -> None:
        started = {
            "schema": 1,
            "event": "batch_started",
            "profile": "full-audit",
            "agent_mode": "ask",
            "dry_run": True,
            "history": False,
            "audit_file": False,
        }
        completed = {
            "event": "batch_completed",
            "status": "success",
            "dry_run_complete": True,
            "mutation_attempts": 0,
            "history_persistence_attempts": 0,
            "audit_file_persistence_attempts": 0,
        }
        payload = india_acceptance.canonical_json(
            started
        ) + india_acceptance.canonical_json(completed)
        india_acceptance.validate_batch(payload, "full-audit")
        completed["mutation_attempts"] = 1
        with self.assertRaises(india_acceptance.AcceptanceError):
            india_acceptance.validate_batch(
                india_acceptance.canonical_json(started)
                + india_acceptance.canonical_json(completed),
                "full-audit",
            )

    def test_batch_parser_rejects_duplicate_keys_and_noncanonical_framing(self) -> None:
        for payload in (
            b'{"event":"batch_completed","mutation_attempts":1,"mutation_attempts":0}\n',
            b'{"event": "batch_completed"}\n',
            b'{"event":"batch_completed"}\r\n',
            b'{"event":"batch_completed"}',
            b'{"event":"batch_completed","value":NaN}\n',
        ):
            with (
                self.subTest(payload=payload),
                self.assertRaises(india_acceptance.AcceptanceError),
            ):
                india_acceptance.batch_events(payload)

    def test_enabled_artifacts_require_both_persistence_attempts(self) -> None:
        started = {
            "schema": 1,
            "event": "batch_started",
            "profile": "full-audit",
            "agent_mode": "ask",
            "dry_run": True,
            "history": True,
            "audit_file": True,
        }
        completed = {
            "event": "batch_completed",
            "status": "success",
            "dry_run_complete": True,
            "mutation_attempts": 0,
            "history_persistence_attempts": 1,
            "audit_file_persistence_attempts": 1,
        }
        payload = india_acceptance.canonical_json(
            started
        ) + india_acceptance.canonical_json(completed)
        india_acceptance.validate_batch(payload, "full-audit", persistence_enabled=True)
        completed["audit_file_persistence_attempts"] = 0
        with self.assertRaises(india_acceptance.AcceptanceError):
            india_acceptance.validate_batch(
                payload[:0]
                + india_acceptance.canonical_json(started)
                + india_acceptance.canonical_json(completed),
                "full-audit",
                persistence_enabled=True,
            )

    def test_required_unsupported_blocks_but_conditional_unsupported_does_not(
        self,
    ) -> None:
        required = {"status": "unsupported", "requirement": "required"}
        conditional = {"status": "unsupported", "requirement": "conditional"}
        passed = {"status": "passed", "requirement": "required"}
        self.assertEqual(
            india_acceptance.aggregate_status([passed, conditional]), "passed"
        )
        self.assertEqual(
            india_acceptance.aggregate_status([passed, required]), "failure"
        )

    def test_file_provider_probe_level_result_is_not_scanner_acceptance(self) -> None:
        lane = next(
            lane
            for lane in india_acceptance.load_catalog(self.catalog())[1]
            if lane.lane_id == "file_provider_no_materialization"
        )
        result = india_acceptance.CommandResult(
            status={"exit_code": 0, "result": "passed"},
            output=(
                b'{"event":"file_provider_acceptance","fixture":"file-provider-probe-level",'
                b'"lifecycle_completion":"complete","scanner_acceptance":"not-run",'
                b'"status":"accepted"}\n'
            ),
            argv=("fixture",),
        )
        self.assertEqual(
            india_acceptance.classify(lane, result),
            ("unsupported", "scanner_file_provider_hook_unavailable"),
        )

    def test_file_provider_recovery_receipt_forces_task_root_retention(self) -> None:
        recovery = (
            b'{"derived_dir":"/task/file-provider-derived",'
            b'"event":"file_provider_recovery","lifecycle_completion":"incomplete",'
            b'"recovery_kind":"manifest","recovery_locator":"/recovery/manifest.json",'
            b'"status":"recovery_required"}\n'
        )
        state, locator, derived_dir, recovery_kind = (
            india_acceptance.file_provider_lifecycle(recovery)
        )
        self.assertEqual(state, "recovery_required")
        self.assertEqual(locator, "/recovery/manifest.json")
        self.assertEqual(derived_dir, "/task/file-provider-derived")
        self.assertEqual(recovery_kind, "manifest")
        self.assertTrue(india_acceptance.file_provider_requires_retention(state))
        self.assertTrue(india_acceptance.file_provider_requires_retention("started"))
        self.assertTrue(india_acceptance.file_provider_requires_retention("unknown"))
        self.assertFalse(india_acceptance.file_provider_requires_retention("complete"))
        self.assertFalse(
            india_acceptance.file_provider_requires_retention("not_started")
        )
        self.assertEqual(
            india_acceptance.file_provider_recovery_argv(
                Path("/repo"), state, recovery_kind, locator, derived_dir
            ),
            [
                "/usr/bin/env",
                "DISKPLAN_FILEPROVIDER_DERIVED_DIR=/task/file-provider-derived",
                "/repo/scripts/fileprovider-fixture.sh",
                "recover",
                "/recovery/manifest.json",
            ],
        )
        unpublished = india_acceptance.file_provider_recovery_argv(
            Path("/repo"),
            "recovery_required",
            "run_id",
            "01234567-89ab-cdef-0123-456789abcdef",
            "/task/file-provider-derived",
        )
        self.assertIsNotNone(unpublished)
        assert unpublished is not None
        self.assertEqual(unpublished[3], "recover-unpublished")

    def test_million_entry_lane_requires_resident_and_zero_swap_evidence(self) -> None:
        lane = next(
            lane
            for lane in india_acceptance.load_catalog(self.catalog())[1]
            if lane.lane_id == "million_entry_performance"
        )
        passing = india_acceptance.CommandResult(
            status={
                "exit_code": 0,
                "result": "passed",
                "resource_usage": {"max_resident_bytes": 1024, "swap_operations": 0},
            },
            output=b"Test run with 1 test passed\n",
            argv=("swift", "test"),
        )
        self.assertEqual(
            india_acceptance.classify(lane, passing), ("passed", "accepted")
        )
        swapped = india_acceptance.CommandResult(
            status={
                **passing.status,
                "resource_usage": {"max_resident_bytes": 1024, "swap_operations": 1},
            },
            output=passing.output,
            argv=passing.argv,
        )
        self.assertEqual(
            india_acceptance.classify(lane, swapped),
            ("failure", "million-entry_process_reported_swap_activity"),
        )

    def test_enabled_artifact_lane_requires_its_exact_receipt(self) -> None:
        lane = next(
            lane
            for lane in india_acceptance.load_catalog(self.catalog())[1]
            if lane.lane_id == "optional_artifact_enabled"
        )
        accepted = india_acceptance.CommandResult(
            status={"exit_code": 0, "result": "passed"},
            output=b'{"event":"artifact_acceptance","schema":1,"status":"accepted"}\n',
            argv=("artifact",),
        )
        self.assertEqual(
            india_acceptance.classify(lane, accepted), ("passed", "accepted")
        )
        duplicate = india_acceptance.CommandResult(
            status=accepted.status,
            output=accepted.output + accepted.output,
            argv=accepted.argv,
        )
        self.assertEqual(
            india_acceptance.classify(lane, duplicate),
            ("failure", "enabled_artifact_acceptance_receipt_is_missing"),
        )

    def test_supervisor_receipt_must_bind_limits_output_and_quiescence(self) -> None:
        lane = india_acceptance.load_catalog(self.catalog())[1][0]
        payload = b"bounded output\n"
        status = {
            "cleanup": {
                "attempted": False,
                "term_attempted": False,
                "term_sent": False,
                "kill_attempted": False,
                "kill_sent": False,
                "quiescent": True,
            },
            "elapsed_millis": 1,
            "error_type": None,
            "exit_code": 0,
            "leader_exit_code": 0,
            "limits": {
                "max_output_bytes": lane.max_output_bytes,
                "timeout_seconds": lane.timeout_seconds,
            },
            "output_bytes": len(payload),
            "output_sha256": hashlib.sha256(payload).hexdigest(),
            "process_group_verified": True,
            "resource_usage": {
                "max_resident_bytes": 1,
                "swap_operations": 0,
                "system_cpu_millis": 0,
                "user_cpu_millis": 0,
            },
            "result": "passed",
            "termination_signal": None,
        }
        india_acceptance.validate_supervisor_status(status, lane, payload, 0)
        for mutation in ("digest", "quiescence", "limit"):
            changed = json.loads(json.dumps(status))
            if mutation == "digest":
                changed["output_sha256"] = "0" * 64
            elif mutation == "quiescence":
                changed["cleanup"]["quiescent"] = False
            else:
                changed["limits"]["timeout_seconds"] += 1
            with (
                self.subTest(mutation=mutation),
                self.assertRaises(india_acceptance.AcceptanceError),
            ):
                india_acceptance.validate_supervisor_status(changed, lane, payload, 0)

    def test_command_template_replaces_every_task_scoped_random_path(self) -> None:
        template = india_acceptance.command_template(
            [
                "/repo/scripts/release/india_artifact_acceptance.py",
                "HOME=/private/tmp/task.random/home",
                "--root",
                "/Users/example",
                "/bundle/install.sh",
            ],
            repo_root=Path("/repo"),
            bundle=Path("/bundle"),
            task_root=Path("/private/tmp/task.random"),
            audit_root=Path("/Users/example"),
        )
        self.assertEqual(
            template,
            (
                "$REPO/scripts/release/india_artifact_acceptance.py",
                "HOME=$TASK_ROOT/home",
                "--root",
                "$AUDIT_ROOT",
                "$BUNDLE/install.sh",
            ),
        )

    def test_product_and_file_provider_commands_bind_task_scoped_state(self) -> None:
        lanes = india_acceptance.load_catalog(self.catalog())[1]
        with tempfile.TemporaryDirectory() as parent:
            root = Path(parent)
            bundle = root / "bundle"
            bundle.mkdir()
            (bundle / "VERSION").write_text("1.2.3\n", encoding="ascii")
            (bundle / "manifest.json").write_text(
                json.dumps(
                    {
                        "product_version": "1.2.3",
                        "protocol_major": 1,
                        "protocol_minor": 3,
                        "source_revision": "a" * 40,
                    }
                ),
                encoding="utf-8",
            )
            task_root = root / "task"
            for lane_id in (
                "install",
                "handshake",
                "standard_scan",
                "bounded_full_audit",
                "batch_dry_run",
            ):
                lane = next(value for value in lanes if value.lane_id == lane_id)
                argv = india_acceptance.build_argv(
                    lane,
                    Path("/repo"),
                    bundle,
                    task_root / "prefix",
                    Path("/audit"),
                    task_root,
                )
                self.assertIn(f"HOME={task_root / (lane_id + '-home')}", argv)
                self.assertIn(f"TMPDIR={task_root / (lane_id + '-tmp')}", argv)

            provider = next(
                value
                for value in lanes
                if value.lane_id == "file_provider_no_materialization"
            )
            provider_argv = india_acceptance.build_argv(
                provider,
                Path("/repo"),
                bundle,
                task_root / "prefix",
                Path("/audit"),
                task_root,
            )
            self.assertIn(
                f"DISKPLAN_FILEPROVIDER_DERIVED_DIR={task_root / 'file-provider-derived'}",
                provider_argv,
            )
            self.assertIn(
                f"DISKPLAN_FILEPROVIDER_PACKAGES_DIR={task_root / 'file-provider-packages'}",
                provider_argv,
            )
            self.assertIn(
                f"DISKPLAN_FILEPROVIDER_BUILD_LOG={task_root / 'file-provider-build/signed-build.log'}",
                provider_argv,
            )

    def test_task_root_cleanup_unlinks_symlink_without_following_it(self) -> None:
        with tempfile.TemporaryDirectory() as parent:
            parent_path = Path(parent)
            task_root = parent_path / "task"
            task_root.mkdir(mode=0o700)
            child = task_root / "child"
            child.mkdir(mode=0o700)
            (child / "payload").write_bytes(b"fixture")
            outside = parent_path / "outside"
            outside.write_bytes(b"must survive")
            os.symlink(outside, child / "link")
            removed, reason = india_acceptance.remove_task_root(task_root)
            self.assertTrue(removed, reason)
            self.assertFalse(task_root.exists())
            self.assertEqual(outside.read_bytes(), b"must survive")


if __name__ == "__main__":
    unittest.main()
