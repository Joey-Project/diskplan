#!/usr/bin/env python3
"""Prove that local acceptance sources exactly match the release revision."""

from __future__ import annotations

import argparse
import json
import os
import select
import subprocess
import time
from pathlib import Path
from typing import Optional, Sequence


COMMAND_TIMEOUT_SECONDS = 30.0
MAX_COMMAND_OUTPUT = 4096
SOURCE_PATHS = (
    "Package.swift",
    "Package.resolved",
    "swift/Sources",
    "swift/Tests",
    "swift/Tools",
    "fixtures/FileProviderAcceptance",
    "scripts/fileprovider-fixture.sh",
    ":(glob)scripts/fileprovider-fixture*.py",
    "scripts/release",
)


def parse_args(arguments: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repo-root", type=Path, required=True)
    parser.add_argument("--expected-revision", required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(arguments)
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    return args


def bounded_git(repo_root: Path, arguments: Sequence[str]) -> tuple[int, bytes]:
    environment = dict(os.environ)
    environment["GIT_OPTIONAL_LOCKS"] = "0"
    environment["LC_ALL"] = "C"
    process = subprocess.Popen(
        [
            "/usr/bin/git",
            "-c",
            "core.fsmonitor=false",
            "-c",
            "core.untrackedCache=false",
            "-C",
            str(repo_root),
            *arguments,
        ],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        env=environment,
    )
    assert process.stdout is not None
    descriptor = process.stdout.fileno()
    os.set_blocking(descriptor, False)
    output = bytearray()
    deadline = time.monotonic() + COMMAND_TIMEOUT_SECONDS
    while True:
        if time.monotonic() >= deadline:
            process.terminate()
            return 124, bytes(output)
        readable, _, _ = select.select([descriptor], [], [], 0.1)
        if readable:
            try:
                chunk = os.read(descriptor, 4096)
            except BlockingIOError:
                chunk = b""
            output.extend(chunk)
            if len(output) > MAX_COMMAND_OUTPUT:
                process.terminate()
                return 125, bytes(output[:MAX_COMMAND_OUTPUT])
        if process.poll() is not None:
            while True:
                try:
                    chunk = os.read(descriptor, 4096)
                except BlockingIOError:
                    break
                if not chunk:
                    break
                output.extend(chunk)
                if len(output) > MAX_COMMAND_OUTPUT:
                    return 125, bytes(output[:MAX_COMMAND_OUTPUT])
            return process.returncode, bytes(output)


def exact_line(repo_root: Path, arguments: Sequence[str]) -> str:
    status, output = bounded_git(repo_root, arguments)
    lines = output.decode("ascii", errors="strict").splitlines()
    if status != 0 or len(lines) != 1 or not lines[0]:
        raise RuntimeError("git identity command did not return one exact line")
    return lines[0]


def verify_source(repo_root: Path, expected_revision: str) -> tuple[str, str]:
    try:
        commit = exact_line(repo_root, ["rev-parse", "--verify", "HEAD^{commit}"])
        tree = exact_line(repo_root, ["rev-parse", "--verify", "HEAD^{tree}"])
    except (OSError, RuntimeError, UnicodeDecodeError) as error:
        raise RuntimeError("repository identity is unavailable") from error
    if commit != expected_revision:
        raise RuntimeError("repository revision does not match the release")
    for arguments in (
        ["diff", "--quiet", "--no-ext-diff"],
        ["diff", "--cached", "--quiet", "--no-ext-diff"],
    ):
        status, output = bounded_git(repo_root, arguments)
        if status != 0 or output:
            raise RuntimeError("tracked repository state is not clean")
    status, output = bounded_git(
        repo_root,
        [
            "status",
            "--porcelain=v1",
            "--untracked-files=all",
            "--ignored=matching",
            "--",
            *SOURCE_PATHS,
        ],
    )
    if status != 0 or output:
        raise RuntimeError("acceptance source paths contain local state")
    return commit, tree


def main(arguments: Optional[Sequence[str]] = None) -> int:
    args = parse_args(arguments)
    if not args.repo_root.is_absolute() or not args.repo_root.is_dir():
        return 64
    try:
        commit, tree = verify_source(args.repo_root, args.expected_revision)
    except RuntimeError:
        return 65
    if args.command:
        try:
            completed = subprocess.run(args.command, check=False)
        except OSError:
            return 65
        try:
            final_commit, final_tree = verify_source(
                args.repo_root, args.expected_revision
            )
        except RuntimeError:
            return 65
        if (final_commit, final_tree) != (commit, tree):
            return 65
        return completed.returncode
    receipt = {
        "event": "source_acceptance",
        "repository_commit": commit,
        "repository_tree": tree,
        "schema": 1,
        "status": "accepted",
    }
    print(json.dumps(receipt, sort_keys=True, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
