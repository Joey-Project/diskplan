#!/usr/bin/env python3
"""Behavior tests for the release acceptance supervisor."""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import time
import unittest
from pathlib import Path
from typing import Any, Sequence


RUNNER = Path(__file__).with_name("run_bounded.py")


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
