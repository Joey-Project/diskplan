#!/usr/bin/env python3
import importlib.util
import contextlib
import io
from pathlib import Path
import tempfile
import unittest
from unittest import mock


MODULE_PATH = Path(__file__).with_name("fileprovider-fixture-pluginkit.py")
SPEC = importlib.util.spec_from_file_location("fileprovider_fixture_pluginkit", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class PlugInKitCompletionTests(unittest.TestCase):
    def run_with(self, effect: object) -> int:
        with tempfile.TemporaryDirectory() as root:
            appex = Path(root) / "Fixture.appex"
            appex.mkdir()
            with mock.patch.object(MODULE, "run_bounded_text", side_effect=effect):
                with contextlib.redirect_stdout(io.StringIO()), contextlib.redirect_stderr(
                    io.StringIO()
                ):
                    return MODULE.run_mutation("add", appex)

    def test_normal_process_completion_is_authoritative_success(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            appex = Path(root) / "Fixture.appex"
            appex.mkdir()
            with mock.patch.object(MODULE, "run_bounded_text", return_value=object()):
                with contextlib.redirect_stdout(io.StringIO()):
                    self.assertEqual(MODULE.run_mutation("add", appex), 0)

    def test_nonzero_process_completion_is_authoritative_failure(self) -> None:
        self.assertEqual(self.run_with(MODULE.CommandExited(7, "failed", process_id=42)), 65)

    def test_start_failure_is_authoritative_nondispatch(self) -> None:
        self.assertEqual(self.run_with(MODULE.CommandStartFailed("unavailable")), 65)

    def test_timeout_keeps_the_mutation_unresolved(self) -> None:
        self.assertEqual(self.run_with(MODULE.CommandTimedOut("timeout", process_id=42)), 75)

    def test_output_limit_keeps_the_mutation_unresolved(self) -> None:
        self.assertEqual(
            self.run_with(MODULE.CommandOutputLimitExceeded("limit", process_id=42)),
            75,
        )


if __name__ == "__main__":
    unittest.main()
