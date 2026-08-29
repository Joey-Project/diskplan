#!/usr/bin/env python3
"""Rewrite the three protocol-bound package assets for release fixtures."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path

import package_bundle


PROTOCOL_VERSION = re.compile(r"[1-9][0-9]*\.(0|[1-9][0-9]*)")
PROTOCOL_ASSETS = {
    "proto/diskplan/v1/ipc.proto": (
        "protocol-schema",
        "proto/diskplan/v1/ipc.proto",
    ),
    "protocol-version": ("protocol-version", "@protocol-version"),
    "protocol.json": ("protocol-metadata", "@protocol-metadata"),
}


def parse_version(value: str) -> str:
    if not PROTOCOL_VERSION.fullmatch(value):
        raise argparse.ArgumentTypeError("protocol version must be canonical major.minor")
    return value


def rewrite_contract(
    source: Path,
    output: Path,
    source_version: str,
    target_version: str,
) -> None:
    package_bundle.load_bundle_contract(source)
    source_data = package_bundle.read_regular_file(source, package_bundle.MAX_CONTRACT_BYTES)
    contract = package_bundle.read_json_bytes(source_data, source)
    artifacts = contract["artifacts"]
    expected_compatibility = f"protocol-{source_version}"
    target_compatibility = f"protocol-{target_version}"
    seen: set[str] = set()

    for artifact in artifacts:
        path = artifact["bundle_path"]
        expected = PROTOCOL_ASSETS.get(path)
        if expected is None:
            if re.fullmatch(
                r"protocol-[0-9]+\.[0-9]+",
                artifact["compatibility_version"],
            ):
                raise ValueError(f"unexpected protocol-bound bundle asset: {path}")
            continue
        expected_role, expected_source = expected
        if (
            artifact["role"] != expected_role
            or artifact["source"] != expected_source
            or artifact["mode"] != "0644"
            or artifact["compatibility_version"] != expected_compatibility
        ):
            raise ValueError(f"protocol-bound bundle asset metadata mismatch: {path}")
        artifact["compatibility_version"] = target_compatibility
        seen.add(path)

    if seen != set(PROTOCOL_ASSETS):
        missing = sorted(set(PROTOCOL_ASSETS) - seen)
        raise ValueError(f"protocol-bound bundle assets are missing: {', '.join(missing)}")

    package_bundle.write_private_file(
        output,
        package_bundle.canonical_compact_json(contract),
        0o600,
    )
    package_bundle.load_bundle_contract(output)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--source-version", type=parse_version, required=True)
    parser.add_argument("--target-version", type=parse_version, required=True)
    return parser.parse_args()


def main() -> int:
    arguments = parse_args()
    try:
        rewrite_contract(
            arguments.source,
            arguments.output,
            arguments.source_version,
            arguments.target_version,
        )
    except (OSError, ValueError) as error:
        print(f"protocol contract fixture: {error}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
