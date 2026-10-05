#!/usr/bin/env python3
from pathlib import Path
import os
import sys
import tempfile
import time
import unittest


sys.dont_write_bytecode = True
sys.path.insert(0, str(Path(__file__).parent))

from fileprovider_fixture_subprocess import (  # noqa: E402
    CommandExited,
    CommandOutputInvalidUTF8,
    CommandOutputLimitExceeded,
    CommandTimedOut,
    run_bounded_text,
)


class BoundedSubprocessTests(unittest.TestCase):
    def test_combined_output_limit_is_enforced_while_process_is_running(self) -> None:
        command = [
            sys.executable,
            "-c",
            (
                "import os, time; "
                "os.write(1, b'o' * 40000); "
                "os.write(2, b'e' * 40000); "
                "time.sleep(10)"
            ),
        ]
        started = time.monotonic()
        with self.assertRaises(CommandOutputLimitExceeded) as caught:
            run_bounded_text(command, timeout_seconds=5, maximum_output_bytes=64 * 1024)

        self.assertLess(time.monotonic() - started, 2)
        assert caught.exception.process_id is not None
        with self.assertRaises(ChildProcessError):
            os.waitpid(caught.exception.process_id, os.WNOHANG)

    def test_output_limit_terminates_the_owned_process_group(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            escaped = Path(root) / "escaped"
            child = (
                "from pathlib import Path; import sys, time; "
                "time.sleep(0.5); Path(sys.argv[1]).write_text('escaped')"
            )
            leader = (
                "import os, subprocess, sys, time; "
                "subprocess.Popen([sys.executable, '-c', sys.argv[1], sys.argv[2]]); "
                "os.write(1, b'x' * 70000); time.sleep(10)"
            )
            with self.assertRaises(CommandOutputLimitExceeded):
                run_bounded_text(
                    [sys.executable, "-c", leader, child, str(escaped)],
                    timeout_seconds=5,
                    maximum_output_bytes=64 * 1024,
                )
            time.sleep(0.7)
            self.assertFalse(escaped.exists())

    def test_absolute_timeout_terminates_and_reaps_the_process(self) -> None:
        started = time.monotonic()
        with self.assertRaises(CommandTimedOut) as caught:
            run_bounded_text(
                [
                    sys.executable,
                    "-c",
                    (
                        "import os, time\n"
                        "while True:\n"
                        "    os.write(1, b'x')\n"
                        "    time.sleep(0.01)"
                    ),
                ],
                timeout_seconds=0.1,
                maximum_output_bytes=64 * 1024,
            )

        self.assertLess(time.monotonic() - started, 2)
        assert caught.exception.process_id is not None
        with self.assertRaises(ChildProcessError):
            os.waitpid(caught.exception.process_id, os.WNOHANG)

    def test_exact_output_limit_is_accepted(self) -> None:
        result = run_bounded_text(
            [sys.executable, "-c", "import os; os.write(1, b'x' * 65536)"],
            timeout_seconds=1,
            maximum_output_bytes=64 * 1024,
        )
        self.assertEqual(len(result.output.encode("utf-8")), 64 * 1024)

    def test_invalid_utf8_is_a_typed_failure(self) -> None:
        with self.assertRaises(CommandOutputInvalidUTF8):
            run_bounded_text(
                [sys.executable, "-c", "import os; os.write(1, b'\\xff')"],
                timeout_seconds=1,
                maximum_output_bytes=64 * 1024,
            )

    def test_nonzero_exit_is_a_typed_failure_with_bounded_output(self) -> None:
        with self.assertRaises(CommandExited) as caught:
            run_bounded_text(
                [sys.executable, "-c", "import sys; print('failure'); sys.exit(7)"],
                timeout_seconds=1,
                maximum_output_bytes=64 * 1024,
            )
        self.assertEqual(caught.exception.returncode, 7)
        self.assertEqual(caught.exception.output, "failure\n")


if __name__ == "__main__":
    unittest.main()
