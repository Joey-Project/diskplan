#!/usr/bin/env python3
import importlib.util
from pathlib import Path
import sys
import tempfile
import unittest


sys.dont_write_bytecode = True
MODULE_PATH = Path(__file__).with_name("fileprovider-fixture-registration.py")
SPEC = importlib.util.spec_from_file_location("fileprovider_fixture_registration", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


class RegistrationParserTests(unittest.TestCase):
    def test_extracts_only_exact_elected_bundle_block(self) -> None:
        output = """
        -    com.example.fixture(1.0)
             Path = /old/Fixture.appex
        +    com.example.fixture(1.0)
             Path = /current/Fixture.appex
        +    com.example.fixture.extra(1.0)
             Path = /other/Fixture.appex
        """
        self.assertEqual(
            MODULE.elected_paths(output, "com.example.fixture"),
            ["/current/Fixture.appex"],
        )

    def test_verification_requires_one_matching_physical_path(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            expected = Path(root) / "Fixture.appex"
            expected.mkdir()
            output = f"+    com.example.fixture(1.0)\n    Path = {expected}\n"
            MODULE.verify_registration("com.example.fixture", expected, output)
            with self.assertRaisesRegex(ValueError, "observed 0"):
                MODULE.verify_registration("com.example.other", expected, output)

    def test_verification_rejects_different_elected_path(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            expected = Path(root) / "Fixture.appex"
            other = Path(root) / "Other.appex"
            expected.mkdir()
            other.mkdir()
            output = f"+    com.example.fixture(1.0)\n    Path = {other}\n"
            with self.assertRaisesRegex(ValueError, "does not match"):
                MODULE.verify_registration("com.example.fixture", expected, output)

    def test_registered_paths_include_all_exact_bundle_states(self) -> None:
        output = """
        -    com.example.fixture(1.0)
             Path = /old/Fixture.appex
        +    com.example.fixture(1.0)
             Path = /current/Fixture.appex
        !    com.example.fixture.extra(1.0)
             Path = /other/Fixture.appex
        """
        self.assertEqual(
            MODULE.registered_paths(output, "com.example.fixture"),
            ["/old/Fixture.appex", "/current/Fixture.appex"],
        )

    def test_removal_rejects_non_elected_reference_to_expected_path(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            expected = Path(root) / "Fixture.appex"
            expected.mkdir()
            output = f"-    com.example.fixture(1.0)\n    Path = {expected}\n"
            with self.assertRaisesRegex(ValueError, "still references"):
                MODULE.verify_removal("com.example.fixture", expected, output)

    def test_removal_allows_other_installation_of_same_bundle(self) -> None:
        with tempfile.TemporaryDirectory() as root:
            expected = Path(root) / "Fixture.appex"
            other = Path(root) / "Other.appex"
            expected.mkdir()
            other.mkdir()
            output = f"+    com.example.fixture(1.0)\n    Path = {other}\n"
            MODULE.verify_removal("com.example.fixture", expected, output)


if __name__ == "__main__":
    unittest.main()
