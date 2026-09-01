#!/usr/bin/env python3

from __future__ import annotations

import datetime as dt
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path


REQUIRED_FIELDS = {
    "id",
    "title",
    "status",
    "created",
    "updated",
    "branch",
    "pr",
    "supersedes",
    "superseded_by",
}
ALLOWED_STATUS = {"planned", "active", "blocked", "completed", "superseded"}
ID_PATTERN = re.compile(r"^[0-9]{8}-[a-z0-9][a-z0-9-]{0,63}$")
DATE_PATTERN = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}$")


@dataclass(frozen=True)
class Journal:
    path: Path
    fields: dict[str, str]


class JournalError(ValueError):
    pass


def parse_frontmatter(path: Path, text: str) -> Journal:
    lines = text.splitlines()
    if not lines or lines[0] != "---":
        raise JournalError("missing opening frontmatter delimiter")
    try:
        closing = lines.index("---", 1)
    except ValueError as error:
        raise JournalError("missing closing frontmatter delimiter") from error

    fields: dict[str, str] = {}
    for line_number, line in enumerate(lines[1:closing], start=2):
        if not line or line.startswith((" ", "\t", "#")):
            raise JournalError(f"unsupported frontmatter syntax on line {line_number}")
        key, separator, value = line.partition(":")
        if not separator or not key or key in fields:
            raise JournalError(f"invalid or duplicate field on line {line_number}")
        fields[key] = value.strip()

    missing = sorted(REQUIRED_FIELDS - fields.keys())
    extra = sorted(fields.keys() - REQUIRED_FIELDS)
    if missing:
        raise JournalError(f"missing fields: {', '.join(missing)}")
    if extra:
        raise JournalError(f"unknown fields: {', '.join(extra)}")
    return Journal(path=path, fields=fields)


def parse_id_list(value: str) -> list[str]:
    if not (value.startswith("[") and value.endswith("]")):
        raise JournalError("supersedes must be an inline list")
    body = value[1:-1].strip()
    if not body:
        return []
    values = [item.strip() for item in body.split(",")]
    if any(not ID_PATTERN.fullmatch(item) for item in values):
        raise JournalError("supersedes contains an invalid id")
    if len(values) != len(set(values)):
        raise JournalError("supersedes contains a duplicate id")
    return values


def validate_journal(journal: Journal) -> list[str]:
    fields = journal.fields
    issues: list[str] = []
    missing = sorted(REQUIRED_FIELDS - fields.keys())
    extra = sorted(fields.keys() - REQUIRED_FIELDS)
    if missing:
        issues.append(f"missing fields: {', '.join(missing)}")
    if extra:
        issues.append(f"unknown fields: {', '.join(extra)}")

    journal_id = fields.get("id")
    if journal_id is not None and not ID_PATTERN.fullmatch(journal_id):
        issues.append("id has an invalid format")
    if fields.get("title") == "":
        issues.append("title is empty")
    status = fields.get("status")
    if status is not None and status not in ALLOWED_STATUS:
        issues.append(f"unsupported status: {status}")

    dates: dict[str, dt.date] = {}
    for name in ("created", "updated"):
        value = fields.get(name)
        if value is None:
            continue
        if not DATE_PATTERN.fullmatch(value):
            issues.append(f"{name} has an invalid format")
            continue
        try:
            dates[name] = dt.date.fromisoformat(value)
        except ValueError:
            issues.append(f"{name} is not a real date")
    if dates.keys() >= {"created", "updated"} and dates["updated"] < dates["created"]:
        issues.append("updated precedes created")

    supersedes = fields.get("supersedes")
    if supersedes is not None:
        try:
            parse_id_list(supersedes)
        except JournalError as error:
            issues.append(str(error))
    superseded_by = fields.get("superseded_by")
    if superseded_by is not None and superseded_by and not ID_PATTERN.fullmatch(superseded_by):
        issues.append("superseded_by has an invalid id")

    created = fields.get("created")
    if created is not None:
        expected_date = journal.path.name[:10]
        if created != expected_date:
            issues.append("created does not match the journal filename date")
        expected_parts = created.split("-")[:2]
        if len(expected_parts) == 2 and journal.path.parts[-3:-1] != tuple(expected_parts):
            issues.append("journal directory does not match created year/month")
    return issues


def candidate_journal_paths(repo_root: Path) -> list[Path]:
    result = subprocess.run(
        [
            "git",
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
            "docs/project_journal/**/*.md",
        ],
        cwd=repo_root,
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        timeout=10,
    )
    paths = [Path(line) for line in result.stdout.splitlines() if line]
    return sorted(path for path in paths if path.name != "INDEX.md")


def validate_repository(repo_root: Path) -> list[str]:
    issues: list[str] = []
    ids: dict[str, Path] = {}
    paths = candidate_journal_paths(repo_root)
    if not paths:
        return ["no tracked project journal entries found"]

    for relative_path in paths:
        path = repo_root / relative_path
        try:
            journal = parse_frontmatter(relative_path, path.read_text(encoding="utf-8"))
        except (OSError, UnicodeError, JournalError) as error:
            issues.append(f"{relative_path}: {error}")
            continue
        for issue in validate_journal(journal):
            issues.append(f"{relative_path}: {issue}")
        journal_id = journal.fields.get("id")
        if journal_id is not None:
            if journal_id in ids:
                issues.append(f"{relative_path}: duplicate id also used by {ids[journal_id]}")
            else:
                ids[journal_id] = relative_path
    return issues


def main() -> int:
    repo_root = Path(__file__).resolve().parents[2]
    issues = validate_repository(repo_root)
    if issues:
        for issue in issues:
            print(issue, file=sys.stderr)
        return 1
    print("project journals validated")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
