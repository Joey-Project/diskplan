#!/usr/bin/env python3
"""Behavior tests for the release acceptance supervisor."""

from __future__ import annotations

import errno
import importlib.util
import json
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from types import ModuleType, SimpleNamespace
from typing import Any, Sequence
from unittest import mock


RUNNER = Path(__file__).with_name("run_bounded.py")


def load_module(name: str, path: Path) -> ModuleType:
    specification = importlib.util.spec_from_file_location(name, path)
    if specification is None or specification.loader is None:
        raise RuntimeError(f"cannot load test module: {path}")
    module = importlib.util.module_from_spec(specification)
    sys.modules[name] = module
    specification.loader.exec_module(module)
    return module


runner = load_module("diskplan_test_run_bounded", RUNNER)


@unittest.skipUnless(
    os.name == "posix" and (sys.platform == "darwin" or sys.platform.startswith("linux")),
    "process-group inspection requires Darwin or Linux",
)
class RunBoundedTests(unittest.TestCase):
    def invoke(
        self,
        command: Sequence[str],
        *,
        timeout_seconds: int = 5,
        maximum_bytes: int = 4096,
    ) -> tuple[subprocess.CompletedProcess[str], dict[str, Any], bytes]:
        with tempfile.TemporaryDirectory(prefix="diskplan-bounded-test.") as temporary:
            output = Path(temporary) / "command.log"
            completed = subprocess.run(
                [
                    sys.executable,
                    str(RUNNER),
                    "--timeout-seconds",
                    str(timeout_seconds),
                    "--max-output-bytes",
                    str(maximum_bytes),
                    "--output",
                    str(output),
                    "--",
                    *command,
                ],
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds + 8,
            )
            report = json.loads(completed.stdout)
            return completed, report, output.read_bytes()

    def test_eof_does_not_bypass_monotonic_deadline(self) -> None:
        completed, report, _output = self.invoke(
            [
                sys.executable,
                "-c",
                "import os,time; os.close(1); os.close(2); time.sleep(30)",
            ],
            timeout_seconds=1,
        )

        self.assertEqual(completed.returncode, 124)
        self.assertEqual(report["result"], "timed_out")
        self.assertEqual(report["exit_code"], 124)
        self.assertTrue(report["cleanup"]["quiescent"])

    def test_signal_exit_is_normalized(self) -> None:
        completed, report, _output = self.invoke(
            [
                sys.executable,
                "-c",
                "import os,signal; os.kill(os.getpid(), signal.SIGTERM)",
            ]
        )

        self.assertEqual(completed.returncode, 128 + signal.SIGTERM)
        self.assertEqual(report["leader_exit_code"], 128 + signal.SIGTERM)
        self.assertEqual(report["result"], "command_failed")

    def test_successful_leader_only_group_is_quiescent(self) -> None:
        completed, report, _output = self.invoke(
            [sys.executable, "-c", "pass"]
        )

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(report["result"], "passed")
        self.assertFalse(report["cleanup"]["attempted"])
        self.assertTrue(report["cleanup"]["quiescent"])

    def test_immediate_exit_repeatedly_preserves_the_identity_fence(self) -> None:
        true_path = shutil.which("true")
        self.assertIsNotNone(true_path)
        assert true_path is not None

        for iteration in range(16):
            with self.subTest(iteration=iteration):
                completed, report, output = self.invoke([true_path])
                self.assertEqual(completed.returncode, 0)
                self.assertEqual(report["result"], "passed")
                self.assertTrue(report["process_group_verified"])
                self.assertTrue(report["cleanup"]["quiescent"])
                self.assertEqual(output, b"")

    def test_verified_fast_exit_closes_the_getpgid_and_getsid_esrch_windows(self) -> None:
        expected = 4242
        deadline = time.monotonic() + 1
        process = SimpleNamespace(pid=expected)

        for failed_call in ("getpgid", "getsid"):
            with self.subTest(failed_call=failed_call):
                observer = mock.Mock()
                observer.wait_until.return_value = True
                getpgid = (
                    mock.Mock(side_effect=ProcessLookupError(errno.ESRCH, "exited"))
                    if failed_call == "getpgid"
                    else mock.Mock(return_value=expected)
                )
                getsid = mock.Mock(
                    side_effect=ProcessLookupError(errno.ESRCH, "exited")
                )
                with mock.patch.object(runner.os, "getpgid", getpgid):
                    with mock.patch.object(runner.os, "getsid", getsid):
                        self.assertEqual(
                            runner.validate_process_group(process, observer, deadline),
                            expected,
                        )
                observer.wait_until.assert_called_once_with(deadline)

    def test_unverified_or_non_esrch_session_lookup_still_fails_closed(self) -> None:
        expected = 4242
        deadline = time.monotonic() + 1
        process = SimpleNamespace(pid=expected)

        observer = mock.Mock()
        observer.wait_until.return_value = False
        with mock.patch.object(
            runner.os,
            "getpgid",
            side_effect=ProcessLookupError(errno.ESRCH, "exited"),
        ):
            with self.assertRaisesRegex(RuntimeError, "without a verified exit"):
                runner.validate_process_group(process, observer, deadline)

        with mock.patch.object(
            runner.os,
            "getpgid",
            side_effect=PermissionError(errno.EPERM, "denied"),
        ):
            with self.assertRaises(PermissionError):
                runner.validate_process_group(process, observer, deadline)

    def test_successful_leader_forces_lingering_group_quiescent(self) -> None:
        completed, report, _output = self.invoke(
            [
                sys.executable,
                "-c",
                (
                    "import subprocess,sys; "
                    "subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'])"
                ),
            ]
        )

        self.assertEqual(completed.returncode, 0)
        self.assertEqual(report["result"], "passed")
        self.assertTrue(report["cleanup"]["attempted"])
        self.assertTrue(report["cleanup"]["quiescent"])

    def test_output_limit_is_exact(self) -> None:
        completed, report, output = self.invoke(
            [sys.executable, "-c", "import os; os.write(1, b'x' * 4096)"],
            maximum_bytes=127,
        )

        self.assertEqual(completed.returncode, 125)
        self.assertEqual(report["result"], "output_limit_exceeded")
        self.assertEqual(report["output_bytes"], 127)
        self.assertEqual(output, b"x" * 127)

    def test_supervisor_interrupt_is_reported_after_group_cleanup(self) -> None:
        with tempfile.TemporaryDirectory(prefix="diskplan-bounded-signal-test.") as temporary:
            output = Path(temporary) / "command.log"
            process = subprocess.Popen(
                [
                    sys.executable,
                    str(RUNNER),
                    "--timeout-seconds",
                    "30",
                    "--max-output-bytes",
                    "4096",
                    "--output",
                    str(output),
                    "--",
                    sys.executable,
                    "-c",
                    "import os,time; os.write(1, b'ready'); time.sleep(30)",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            readiness_deadline = time.monotonic() + 5
            while (
                (not output.exists() or output.read_bytes() != b"ready")
                and time.monotonic() < readiness_deadline
            ):
                time.sleep(0.01)
            self.assertEqual(output.read_bytes(), b"ready")
            os.kill(process.pid, signal.SIGINT)
            stdout, stderr = process.communicate(timeout=8)
            self.assertEqual(stderr, "")
            report = json.loads(stdout)

        self.assertEqual(process.returncode, 128 + signal.SIGINT)
        self.assertEqual(report["result"], "interrupted")
        self.assertEqual(report["termination_signal"], "SIGINT")
        self.assertTrue(report["cleanup"]["quiescent"])


if __name__ == "__main__":
    unittest.main()
