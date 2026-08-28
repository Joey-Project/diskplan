#!/usr/bin/env python3
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import time
import unittest


ROOT = Path(__file__).resolve().parents[1]
HELPER = ROOT / "scripts" / "fileprovider-fixture-lifecycle-lock.py"


class LifecycleLockTests(unittest.TestCase):
    def test_unlocked_inherited_descriptor_is_not_a_capability(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            lock = Path(directory) / "lifecycle.lock"
            descriptor = os.open(lock, os.O_RDWR | os.O_CREAT, 0o600)
            try:
                result = subprocess.run(
                    [
                        sys.executable,
                        str(HELPER),
                        "--lock",
                        str(lock),
                        "--verify-held-fd",
                        str(descriptor),
                    ],
                    pass_fds=(descriptor,),
                    check=False,
                )
            finally:
                os.close(descriptor)
            self.assertEqual(result.returncode, 75)

    def test_helper_passes_a_verified_lock_descriptor(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "lifecycle.lock"
            verified = root / "verified"
            program = (
                "import os,pathlib,subprocess,sys; "
                "fd=int(os.environ['DISKPLAN_FILEPROVIDER_LIFECYCLE_LOCK_FD']); "
                "result=subprocess.run([sys.executable,sys.argv[1],'--lock',sys.argv[2],"
                "'--verify-held-fd',str(fd)],pass_fds=(fd,)); "
                "pathlib.Path(sys.argv[3]).write_text(str(result.returncode)); "
                "raise SystemExit(result.returncode)"
            )
            result = subprocess.run(
                [
                    sys.executable,
                    str(HELPER),
                    "--lock",
                    str(lock),
                    "--",
                    sys.executable,
                    "-c",
                    program,
                    str(HELPER),
                    str(lock),
                    str(verified),
                ],
                check=False,
            )
            self.assertEqual(result.returncode, 0)
            self.assertEqual(verified.read_text(), "0")

    def test_shell_does_not_trust_the_legacy_boolean_environment(self) -> None:
        shell = (ROOT / "scripts" / "fileprovider-fixture.sh").read_text()
        self.assertNotIn("DISKPLAN_FILEPROVIDER_LIFECYCLE_LOCK_HELD", shell)
        self.assertIn("--verify-held-fd", shell)
        self.assertIn("exec 9>&-", shell)
        self.assertIn("--verify-lock-busy", shell)

    def test_consumed_capability_blocks_nested_run_and_does_not_pin_lock(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "lifecycle.lock"
            result_path = root / "nested-result"
            program = (
                "import os,pathlib,subprocess,sys; "
                "fd=int(os.environ.pop('DISKPLAN_FILEPROVIDER_LIFECYCLE_LOCK_FD')); "
                "os.close(fd); "
                "nested=subprocess.run([sys.executable,sys.argv[1],'--lock',sys.argv[2],"
                "'--','/usr/bin/true']); "
                "subprocess.Popen(['/bin/sleep','0.5'],start_new_session=True); "
                "pathlib.Path(sys.argv[3]).write_text(str(nested.returncode)); "
                "raise SystemExit(0 if nested.returncode == 75 else 1)"
            )
            lifecycle = subprocess.run(
                [
                    sys.executable,
                    str(HELPER),
                    "--lock",
                    str(lock),
                    "--",
                    sys.executable,
                    "-c",
                    program,
                    str(HELPER),
                    str(lock),
                    str(result_path),
                ],
                check=False,
            )
            self.assertEqual(lifecycle.returncode, 0)
            self.assertEqual(result_path.read_text(), "75")

            immediate_recovery = subprocess.run(
                [
                    sys.executable,
                    str(HELPER),
                    "--lock",
                    str(lock),
                    "--",
                    "/usr/bin/true",
                ],
                check=False,
            )
            self.assertEqual(immediate_recovery.returncode, 0)

    def test_two_runs_cannot_interleave_and_recovery_can_acquire_after_exit(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            lock = root / "lifecycle.lock"
            ready = root / "ready"
            recovered = root / "recovered"
            holder_program = (
                "from pathlib import Path; import sys,time; "
                "Path(sys.argv[1]).write_text('ready'); time.sleep(0.5)"
            )
            holder = subprocess.Popen(
                [
                    sys.executable,
                    str(HELPER),
                    "--lock",
                    str(lock),
                    "--",
                    sys.executable,
                    "-c",
                    holder_program,
                    str(ready),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
            deadline = time.monotonic() + 2
            while not ready.exists() and time.monotonic() < deadline:
                time.sleep(0.01)
            self.assertTrue(ready.exists(), "first lifecycle did not acquire the lock")

            contender = subprocess.run(
                [
                    sys.executable,
                    str(HELPER),
                    "--lock",
                    str(lock),
                    "--",
                    "/usr/bin/true",
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2,
                check=False,
            )
            self.assertEqual(contender.returncode, 75)
            self.assertIn("file-provider-lifecycle-already-active", contender.stderr)
            _, holder_error = holder.communicate(timeout=2)
            self.assertEqual(holder.returncode, 0, holder_error)

            recovery = subprocess.run(
                [
                    sys.executable,
                    str(HELPER),
                    "--lock",
                    str(lock),
                    "--",
                    sys.executable,
                    "-c",
                    "from pathlib import Path; import sys; Path(sys.argv[1]).write_text('ok')",
                    str(recovered),
                ],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                timeout=2,
                check=False,
            )
            self.assertEqual(recovery.returncode, 0, recovery.stderr)
            self.assertEqual(recovered.read_text(), "ok")


if __name__ == "__main__":
    unittest.main()
