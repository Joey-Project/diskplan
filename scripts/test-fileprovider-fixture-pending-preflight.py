#!/usr/bin/env python3
import importlib.util
import os
from pathlib import Path
import tempfile
import unittest
import uuid


MODULE_PATH = Path(__file__).with_name("fileprovider-fixture-pending-preflight.py")
SPEC = importlib.util.spec_from_file_location("fileprovider_fixture_pending_preflight", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PendingRunPreflightTests(unittest.TestCase):
    def make_runs(self, root: str) -> Path:
        runs = Path(root) / "runs"
        runs.mkdir(mode=0o700)
        os.chmod(runs, 0o700)
        return runs

    def test_missing_or_empty_root_is_clear(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            missing = Path(root) / "missing"
            self.assertEqual(MODULE.unresolved_evidence(missing), [])
            runs = self.make_runs(root)
            self.assertEqual(MODULE.unresolved_evidence(runs), [])

    def test_any_prior_uuid_run_blocks_cross_run_acceptance(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            runs = self.make_runs(root)
            (runs / str(uuid.uuid4())).mkdir(mode=0o700)
            evidence = MODULE.unresolved_evidence(runs)
            self.assertEqual(len(evidence), 1)

    def test_global_gate_and_external_mutation_temporaries_block(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            runs = self.make_runs(root)
            names = [
                ".fileprovider-pending-run.json",
                ".fileprovider-pending-run-publish-crash",
                ".external-mutation-run-domain-add.json",
                ".external-mutation-publish-crash",
            ]
            for name in names:
                (runs / name).write_text("evidence")
            self.assertEqual(
                MODULE.unresolved_evidence(runs),
                sorted(name.encode() for name in names),
            )

    def test_cleanup_and_manifest_recovery_evidence_block(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            runs = self.make_runs(root)
            for name in (".cleanup-dead", ".manifest-recovery-dead.json"):
                (runs / name).write_text("evidence")
            self.assertEqual(len(MODULE.unresolved_evidence(runs)), 2)

    def test_unknown_child_blocks_instead_of_bypassing_the_gate(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            runs = self.make_runs(root)
            (runs / "partially-published-run").write_text("evidence")
            self.assertEqual(
                MODULE.unresolved_evidence(runs),
                [b"partially-published-run"],
            )

    def test_replaced_or_public_runs_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            runs = self.make_runs(root)
            os.chmod(runs, 0o755)
            with self.assertRaisesRegex(MODULE.PreflightBlocked, "access-policy"):
                MODULE.unresolved_evidence(runs)

    def test_symlink_root_fails_closed(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            runs = self.make_runs(root)
            alias = Path(root) / "alias"
            alias.symlink_to(runs)
            with self.assertRaisesRegex(MODULE.PreflightBlocked, "open-runs-root"):
                MODULE.unresolved_evidence(alias)


if __name__ == "__main__":
    unittest.main()
