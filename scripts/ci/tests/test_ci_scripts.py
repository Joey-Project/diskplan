from __future__ import annotations

import os
import re
import signal
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path


CI_ROOT = Path(__file__).resolve().parents[1]
REPO_ROOT = CI_ROOT.parents[1]
EMPTY_TREE_SHA = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"
ZERO_SHA = "0" * 40
BASE_SHA = "1" * 40
HEAD_SHA = "2" * 40


def run_script(
    name: str,
    *arguments: str,
    environment: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [str(CI_ROOT / name), *arguments],
        check=False,
        env=environment,
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

    def test_huge_single_line_diagnostic_is_bounded_while_produced(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "runner.txt"
            output.write_bytes(b"stale" * 4096)
            started = time.monotonic()
            result = run_script("write-diagnostics.sh", str(output), "huge")
            elapsed = time.monotonic() - started
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertLess(elapsed, 5)
            self.assertLessEqual(output.stat().st_size, 16384)
            self.assertIn(b"[probe output truncated]", output.read_bytes())
            self.assertEqual([], list(output.parent.glob(f".{output.name}.tmp.*")))

    def test_hanging_diagnostic_probe_is_killed_before_job_timeout(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "runner.txt"
            started = time.monotonic()
            result = run_script("write-diagnostics.sh", str(output), "hang")
            elapsed = time.monotonic() - started
            self.assertEqual(0, result.returncode, result.stderr)
            self.assertLess(elapsed, 5)
            self.assertLessEqual(output.stat().st_size, 16384)
            self.assertIn(b"[probe timed out]", output.read_bytes())
            self.assertEqual([], list(output.parent.glob(f".{output.name}.tmp.*")))

    def test_normal_probe_quiesces_redirected_background_process(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            pid_path = Path(directory) / "background.pid"
            child_code = (
                "import os, signal, sys, time; "
                "from pathlib import Path; "
                "signal.signal(signal.SIGTERM, signal.SIG_IGN); "
                "Path(sys.argv[1]).write_text(str(os.getpid()), encoding='ascii'); "
                "time.sleep(60)"
            )
            parent_code = (
                "import subprocess, sys, time; "
                "from pathlib import Path; "
                "path = Path(sys.argv[1]); "
                "subprocess.Popen([sys.executable, '-c', sys.argv[2], str(path)], "
                "stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL); "
                "deadline = time.monotonic() + 2; "
                "\nwhile not path.exists():\n"
                "    assert time.monotonic() < deadline\n"
                "    time.sleep(0.01)\n"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(CI_ROOT / "bounded_probe.py"),
                    "--max-bytes",
                    "1024",
                    "--timeout-seconds",
                    "3",
                    "--",
                    sys.executable,
                    "-c",
                    parent_code,
                    str(pid_path),
                    child_code,
                ],
                check=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=5,
            )
            background_pid = int(pid_path.read_text(encoding="ascii"))
            background_gone = False
            try:
                self.assertEqual(0, result.returncode, result.stderr.decode())
                deadline = time.monotonic() + 2
                while True:
                    try:
                        os.kill(background_pid, 0)
                    except ProcessLookupError:
                        background_gone = True
                        break
                    self.assertLess(time.monotonic(), deadline)
                    time.sleep(0.01)
            finally:
                if not background_gone:
                    try:
                        os.kill(background_pid, signal.SIGKILL)
                    except ProcessLookupError:
                        pass

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

    def test_nested_scripts_lock_every_swiftpm_invocation(self) -> None:
        expected_counts = {
            "scripts/canonical-fixture.sh": 1,
            "scripts/protocol13-fixtures.sh": 1,
            "scripts/test-cross-language.sh": 2,
        }
        pattern = re.compile(r"\bswift\s+(?:build|run)\b")
        for relative_path, expected_count in expected_counts.items():
            with self.subTest(script=relative_path):
                source = (REPO_ROOT / relative_path).read_text(encoding="utf-8")
                commands = [
                    line.strip()
                    for line in source.splitlines()
                    if pattern.search(line) and not line.lstrip().startswith("#")
                ]
                self.assertEqual(expected_count, len(commands), commands)
                for command in commands:
                    self.assertIn("--disable-automatic-resolution", command)

    def test_cross_language_executes_locked_nested_swiftpm_commands(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            tool_directory = root / "tools"
            engine_directory = root / "engine"
            tool_directory.mkdir()
            engine_directory.mkdir()
            log = root / "swift.log"

            fake_swift = tool_directory / "swift"
            fake_swift.write_text(
                "#!/bin/bash\n"
                "printf '%s\\n' \"$*\" >> \"$FAKE_SWIFT_LOG\"\n"
                "if [[ \" $* \" == *\" --show-bin-path \"* ]]; then\n"
                "    printf '%s\\n' \"$FAKE_SWIFT_BIN_DIR\"\n"
                "fi\n",
                encoding="utf-8",
            )
            fake_swift.chmod(0o700)
            fake_cargo = tool_directory / "cargo"
            fake_cargo.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
            fake_cargo.chmod(0o700)
            fake_engine = engine_directory / "diskplan-engine"
            fake_engine.write_text("#!/bin/bash\nexit 0\n", encoding="utf-8")
            fake_engine.chmod(0o700)

            environment = os.environ.copy()
            environment["PATH"] = f"{tool_directory}{os.pathsep}{environment['PATH']}"
            environment["FAKE_SWIFT_LOG"] = str(log)
            environment["FAKE_SWIFT_BIN_DIR"] = str(engine_directory)
            result = run_script(
                "../test-cross-language.sh",
                environment=environment,
            )
            self.assertEqual(0, result.returncode, result.stderr)
            invocations = log.read_text(encoding="utf-8").splitlines()
            self.assertEqual(4, len(invocations), invocations)
            for invocation in invocations:
                self.assertIn("--disable-automatic-resolution", invocation)

    def test_cross_language_runs_protocol13_authority_check(self) -> None:
        source = (REPO_ROOT / "scripts/test-cross-language.sh").read_text(encoding="utf-8")
        self.assertEqual(1, source.count("scripts/protocol13-fixtures.sh check"))


if __name__ == "__main__":
    unittest.main()
