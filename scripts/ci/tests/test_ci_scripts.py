from __future__ import annotations

import stat
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path


CI_ROOT = Path(__file__).resolve().parents[1]
EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
ZERO_SHA = "0" * 40
BASE_SHA = "1" * 40
HEAD_SHA = "2" * 40


def run_script(name: str, *arguments: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(CI_ROOT / name), *arguments],
        check=False,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=20,
    )


class CiScriptTests(unittest.TestCase):
    def test_range_selection_for_each_event_shape(self) -> None:
        cases = {
            "pull_request": (BASE_SHA, HEAD_SHA, BASE_SHA),
            "push": (BASE_SHA, HEAD_SHA, BASE_SHA),
            "new_branch": (ZERO_SHA, HEAD_SHA, EMPTY_TREE_SHA),
            "workflow_dispatch": (HEAD_SHA, HEAD_SHA, EMPTY_TREE_SHA),
        }
        for name, (base, head, expected_base) in cases.items():
            with self.subTest(name=name):
                event = "push" if name == "new_branch" else name
                result = run_script("check-diff-range.sh", "select", event, base, head)
                self.assertEqual(0, result.returncode, result.stderr)
                self.assertEqual([expected_base, head], result.stdout.splitlines())

    def test_range_selection_rejects_ref_text(self) -> None:
        result = run_script(
            "check-diff-range.sh",
            "select",
            "pull_request",
            "refs/heads/main",
            HEAD_SHA,
        )
        self.assertEqual(64, result.returncode)
        self.assertIn("exact lowercase 40-character SHA", result.stderr)

    def test_oversized_diagnostics_leave_no_destination_or_temporary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "runner.txt"
            output.write_bytes(b"stale" * 4096)
            result = run_script("write-diagnostics.sh", str(output), "20000")
            self.assertEqual(1, result.returncode)
            self.assertIn("exceeded 16384 bytes", result.stderr)
            self.assertFalse(output.exists())
            self.assertEqual([], list(output.parent.glob(f".{output.name}.tmp.*")))

    def test_valid_diagnostics_publish_private_bounded_file(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "runner.txt"
            output.write_text("stale", encoding="utf-8")
            result = run_script("write-diagnostics.sh", str(output))
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertLessEqual(output.stat().st_size, 16384)
            self.assertEqual(stat.S_IRUSR | stat.S_IWUSR, stat.S_IMODE(output.stat().st_mode))
            self.assertEqual([], list(output.parent.glob(f".{output.name}.tmp.*")))

    def test_package_resolved_guard_rejects_missing_lockfile(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lockfile = Path(directory) / "Package.resolved"
            result = run_script("package-resolved-guard.sh", "check", str(lockfile))
            self.assertEqual(1, result.returncode)
            self.assertIn("must be a non-symlink regular file", result.stderr)

    def test_package_resolved_guard_detects_content_drift(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lockfile = Path(directory) / "Package.resolved"
            lockfile.write_bytes(b"locked")
            result = run_script(
                "package-resolved-guard.sh",
                "run",
                str(lockfile),
                "--",
                sys.executable,
                "-c",
                "from pathlib import Path; import sys; Path(sys.argv[1]).write_bytes(b'drift')",
                str(lockfile),
            )
            self.assertEqual(1, result.returncode)
            self.assertIn("content changed", result.stderr)

    def test_package_resolved_guard_preserves_command_status_when_stable(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lockfile = Path(directory) / "Package.resolved"
            lockfile.write_bytes(b"locked")
            result = run_script(
                "package-resolved-guard.sh",
                "run",
                str(lockfile),
                "--",
                sys.executable,
                "-c",
                "raise SystemExit(7)",
            )
            self.assertEqual(7, result.returncode)
            self.assertEqual(b"locked", lockfile.read_bytes())


if __name__ == "__main__":
    unittest.main()
