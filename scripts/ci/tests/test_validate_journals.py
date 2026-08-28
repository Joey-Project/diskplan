from __future__ import annotations

import importlib.util
import sys
import unittest
from pathlib import Path


MODULE_PATH = Path(__file__).resolve().parents[1] / "validate_journals.py"
SPEC = importlib.util.spec_from_file_location("validate_journals", MODULE_PATH)
assert SPEC is not None and SPEC.loader is not None
VALIDATOR = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = VALIDATOR
SPEC.loader.exec_module(VALIDATOR)


class JournalValidatorTests(unittest.TestCase):
    def test_accepts_minimal_valid_entry(self) -> None:
        path = Path("docs/project_journal/2026/08/2026-08-28-ci-c10a26.md")
        journal = VALIDATOR.parse_frontmatter(
            path,
            """---
id: 20260828-c10a26
title: CI
status: active
created: 2026-08-28
updated: 2026-08-28
branch: wip/phase0-ci
pr:
supersedes: []
superseded_by:
---

# CI
""",
        )
        self.assertEqual([], VALIDATOR.validate_journal(journal))

    def test_rejects_duplicate_field(self) -> None:
        path = Path("docs/project_journal/2026/08/2026-08-28-ci-c10a26.md")
        with self.assertRaisesRegex(VALIDATOR.JournalError, "duplicate"):
            VALIDATOR.parse_frontmatter(
                path,
                """---
id: 20260828-c10a26
id: 20260828-other
---
""",
            )

    def test_rejects_date_and_directory_mismatch(self) -> None:
        path = Path("docs/project_journal/2026/08/2026-08-28-ci-c10a26.md")
        journal = VALIDATOR.Journal(
            path=path,
            fields={
                "id": "20260828-c10a26",
                "title": "CI",
                "status": "active",
                "created": "2026-07-28",
                "updated": "2026-07-27",
                "branch": "wip/phase0-ci",
                "pr": "",
                "supersedes": "[]",
                "superseded_by": "",
            },
        )
        issues = VALIDATOR.validate_journal(journal)
        self.assertIn("updated precedes created", issues)
        self.assertIn("created does not match the journal filename date", issues)
        self.assertIn("journal directory does not match created year/month", issues)

    def test_rejects_invalid_supersedes_list(self) -> None:
        with self.assertRaisesRegex(VALIDATOR.JournalError, "invalid id"):
            VALIDATOR.parse_id_list("[not-an-id]")

    def test_missing_required_field_has_stable_diagnostic(self) -> None:
        path = Path("docs/project_journal/2026/08/2026-08-28-ci-c10a26.md")
        journal = VALIDATOR.Journal(
            path=path,
            fields={
                "id": "20260828-c10a26",
                "title": "CI",
                "status": "active",
                "created": "2026-08-28",
                "updated": "2026-08-28",
                "branch": "wip/phase0-ci",
                "pr": "",
                "superseded_by": "",
            },
        )
        self.assertEqual(
            ["missing fields: supersedes"],
            VALIDATOR.validate_journal(journal),
        )

    def test_missing_created_skips_path_consistency_checks(self) -> None:
        path = Path("docs/project_journal/2026/08/2026-08-28-ci-c10a26.md")
        journal = VALIDATOR.Journal(
            path=path,
            fields={
                "id": "20260828-c10a26",
                "title": "CI",
                "status": "active",
                "updated": "2026-08-28",
                "branch": "wip/phase0-ci",
                "pr": "",
                "supersedes": "[]",
                "superseded_by": "",
            },
        )
        issues = VALIDATOR.validate_journal(journal)
        self.assertEqual(["missing fields: created"], issues)
        self.assertNotIn("created does not match the journal filename date", issues)
        self.assertNotIn("journal directory does not match created year/month", issues)


if __name__ == "__main__":
    unittest.main()
