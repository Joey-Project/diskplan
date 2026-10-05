#!/usr/bin/env python3
"""Generate or check the C release-bundle contract from its canonical JSON source."""

from __future__ import annotations

import argparse
import os
import tempfile
from pathlib import Path

import package_bundle


SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent.parent
CONTRACT = REPO_ROOT / "release/bundle-contract.json"
HEADER = SCRIPT_DIR / "bundle-contract.generated.h"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("mode", choices=("check", "generate"))
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    artifacts, _excluded = package_bundle.load_bundle_contract(CONTRACT)
    expected = package_bundle.render_c_bundle_contract(artifacts)
    if arguments.mode == "check":
        if package_bundle.read_regular_file(HEADER, package_bundle.MAX_CONTRACT_BYTES) != expected:
            raise ValueError("generated C bundle contract is stale")
        return 0

    descriptor, temporary_name = tempfile.mkstemp(
        prefix=".bundle-contract.", suffix=".tmp", dir=SCRIPT_DIR
    )
    temporary = Path(temporary_name)
    try:
        package_bundle.write_all(descriptor, expected)
        os.fchmod(descriptor, 0o644)
        os.fsync(descriptor)
        os.close(descriptor)
        descriptor = -1
        os.replace(temporary, HEADER)
        directory = os.open(SCRIPT_DIR, os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        temporary.unlink(missing_ok=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
