#!/usr/bin/env python3

from __future__ import annotations

import importlib.util
import subprocess
import sys
import unittest
from pathlib import Path
from unittest import mock


MODULE_PATH = Path(__file__).with_name("india_source_acceptance.py")
SPEC = importlib.util.spec_from_file_location("india_source_acceptance", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
source_acceptance = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = source_acceptance
SPEC.loader.exec_module(source_acceptance)


class IndiaSourceAcceptanceTests(unittest.TestCase):
    def test_clean_exact_revision_returns_commit_and_tree(self) -> None:
        commit = "a" * 40
        tree = "b" * 40
        responses = [
            (0, (commit + "\n").encode()),
            (0, (tree + "\n").encode()),
            (0, b""),
            (0, b""),
            (0, b""),
        ]
        with mock.patch.object(source_acceptance, "bounded_git", side_effect=responses):
            self.assertEqual(
                source_acceptance.verify_source(Path("/repo"), commit),
                (commit, tree),
            )

    def test_local_source_state_fails_closed(self) -> None:
        commit = "a" * 40
        responses = [
            (0, (commit + "\n").encode()),
            (0, ("b" * 40 + "\n").encode()),
            (0, b""),
            (0, b""),
            (0, b"?? swift/Sources/injected.swift\0"),
        ]
        with mock.patch.object(source_acceptance, "bounded_git", side_effect=responses):
            with self.assertRaises(RuntimeError):
                source_acceptance.verify_source(Path("/repo"), commit)

    def test_sealed_command_requires_matching_pre_and_post_identity(self) -> None:
        commit = "a" * 40
        tree = "b" * 40
        with (
            mock.patch.object(Path, "is_dir", return_value=True),
            mock.patch.object(
                source_acceptance,
                "verify_source",
                side_effect=[(commit, tree), (commit, "c" * 40)],
            ),
            mock.patch.object(
                source_acceptance.subprocess,
                "run",
                return_value=subprocess.CompletedProcess(["true"], 0),
            ),
        ):
            self.assertEqual(
                source_acceptance.main(
                    [
                        "--repo-root",
                        "/repo",
                        "--expected-revision",
                        commit,
                        "--",
                        "true",
                    ]
                ),
                65,
            )


if __name__ == "__main__":
    unittest.main()
