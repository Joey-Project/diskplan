#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys


MAXIMUM_OUTPUT_BYTES = 64 * 1024
HEADER = re.compile(r"^\s*([+!-])\s+([^\s(]+)(?:\(|\s|$)")
PATH_LINE = re.compile(r"^\s*Path\s*=\s*(.*?)\s*$")


def elected_paths(output: str, bundle_id: str) -> list[str]:
    matches: list[str] = []
    elected = False
    for line in output.splitlines():
        header = HEADER.match(line)
        if header:
            elected = header.group(1) == "+" and header.group(2) == bundle_id
            continue
        path = PATH_LINE.match(line)
        if elected and path:
            matches.append(path.group(1))
            elected = False
    return matches


def verify_registration(bundle_id: str, expected_path: Path, output: str) -> None:
    if expected_path.is_symlink() or not expected_path.is_dir():
        raise ValueError("expected appex is not a physical directory")
    expected_physical = expected_path.resolve(strict=True)
    matches = elected_paths(output, bundle_id)
    if len(matches) != 1:
        raise ValueError(f"expected one elected path, observed {len(matches)}")
    elected = Path(matches[0])
    if elected.resolve(strict=True) != expected_physical:
        raise ValueError("elected extension path does not match the embedded appex")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-id", required=True)
    parser.add_argument("--expected-path", type=Path, required=True)
    arguments = parser.parse_args()
    try:
        result = subprocess.run(
            ["pluginkit", "-m", "-A", "-D", "-v", "-i", arguments.bundle_id],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print('{"status":"failed","reason":"pluginkit-query-timeout"}', file=sys.stderr)
        return 1
    if len(result.stdout) > MAXIMUM_OUTPUT_BYTES:
        print('{"status":"failed","reason":"pluginkit-query-output-limit"}', file=sys.stderr)
        return 1
    output = result.stdout.decode("utf-8", errors="backslashreplace")
    if result.returncode != 0:
        print(
            f'{{"status":"failed","reason":"pluginkit-query","exit":{result.returncode}}}',
            file=sys.stderr,
        )
        return 1
    try:
        verify_registration(arguments.bundle_id, arguments.expected_path, output)
    except (OSError, ValueError) as error:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "reason": "pluginkit-election",
                    "detail": str(error),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print('{"status":"verified","registration":"exact-elected-physical-path"}')
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
