#!/usr/bin/env python3
"""Require live APFS clone and hardlink primitives before focused graph tests."""

from __future__ import annotations

import argparse
import ctypes
import os
import stat
import subprocess
import sys
from pathlib import Path
from typing import Optional, Sequence


def parse_args(arguments: Optional[Sequence[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixture-root", type=Path, required=True)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args(arguments)
    if args.command[:1] == ["--"]:
        args.command = args.command[1:]
    if not args.command:
        parser.error("a command is required after --")
    return args


def clonefile(source: Path, destination: Path) -> None:
    library = ctypes.CDLL("/usr/lib/libSystem.B.dylib", use_errno=True)
    function = library.clonefile
    function.argtypes = [ctypes.c_char_p, ctypes.c_char_p, ctypes.c_int]
    function.restype = ctypes.c_int
    if function(os.fsencode(source), os.fsencode(destination), 0) != 0:
        raise OSError(ctypes.get_errno(), "clonefile failed")


def main(arguments: Optional[Sequence[str]] = None) -> int:
    args = parse_args(arguments)
    if sys.platform != "darwin" or not args.fixture_root.is_absolute():
        return 77
    args.fixture_root.mkdir(mode=0o700)
    try:
        filesystem = subprocess.run(
            ["/usr/bin/stat", "-f", "%T", str(args.fixture_root)],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return 77
    if filesystem.returncode != 0 or filesystem.stdout.strip() != b"apfs":
        return 77
    source = args.fixture_root / "source"
    clone = args.fixture_root / "clone"
    alias = args.fixture_root / "clone-hardlink"
    source.write_bytes(b"diskplan-apfs-acceptance-v1\0" * 4096)
    try:
        clonefile(source, clone)
    except OSError:
        return 77
    os.link(clone, alias)
    source_stat = os.stat(source, follow_symlinks=False)
    clone_stat = os.stat(clone, follow_symlinks=False)
    alias_stat = os.stat(alias, follow_symlinks=False)
    if not all(
        stat.S_ISREG(value.st_mode) for value in (source_stat, clone_stat, alias_stat)
    ):
        return 65
    if (clone_stat.st_dev, clone_stat.st_ino) != (alias_stat.st_dev, alias_stat.st_ino):
        return 65
    if clone_stat.st_nlink != 2 or source_stat.st_ino == clone_stat.st_ino:
        return 65
    environment = dict(os.environ)
    environment["TMPDIR"] = str(args.fixture_root)
    completed = subprocess.run(args.command, env=environment, check=False)
    return completed.returncode


if __name__ == "__main__":
    raise SystemExit(main())
