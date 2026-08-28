#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import re
import subprocess
import sys
import time


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


def registered_paths(output: str, bundle_id: str) -> list[str]:
    matches: list[str] = []
    exact_bundle = False
    for line in output.splitlines():
        header = HEADER.match(line)
        if header:
            exact_bundle = header.group(2) == bundle_id
            continue
        path = PATH_LINE.match(line)
        if exact_bundle and path:
            matches.append(path.group(1))
            exact_bundle = False
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


def verify_removal(bundle_id: str, expected_path: Path, output: str) -> None:
    if expected_path.is_symlink() or not expected_path.is_dir():
        raise ValueError("expected appex is not a physical directory")
    expected_physical = expected_path.resolve(strict=True)
    for registered in registered_paths(output, bundle_id):
        if Path(registered).resolve(strict=False) == expected_physical:
            raise ValueError("registry still references the embedded appex")


def query_registration(bundle_id: str, timeout_seconds: float) -> str:
    result = subprocess.run(
        ["pluginkit", "-m", "-A", "-D", "-v", "-i", bundle_id],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        timeout=timeout_seconds,
        check=False,
    )
    if len(result.stdout) > MAXIMUM_OUTPUT_BYTES:
        raise ValueError("pluginkit query exceeded output limit")
    if result.returncode != 0:
        raise RuntimeError(f"pluginkit query exited {result.returncode}")
    return result.stdout.decode("utf-8", errors="backslashreplace")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--bundle-id", required=True)
    parser.add_argument("--expected-path", type=Path, required=True)
    parser.add_argument("--state", choices=("elected", "absent"), required=True)
    arguments = parser.parse_args()
    verifier = verify_registration if arguments.state == "elected" else verify_removal
    deadline = time.monotonic() + 10.0
    last_error = "registry state did not converge"
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        try:
            output = query_registration(arguments.bundle_id, min(2.0, remaining))
            verifier(arguments.bundle_id, arguments.expected_path, output)
        except (OSError, RuntimeError, subprocess.TimeoutExpired, ValueError) as error:
            last_error = str(error)
        else:
            registration = (
                "exact-elected-physical-path"
                if arguments.state == "elected"
                else "exact-physical-path-absent"
            )
            print(json.dumps({"status": "verified", "registration": registration}, sort_keys=True))
            return 0
        time.sleep(min(0.1, max(0.0, deadline - time.monotonic())))
    print(
        json.dumps(
            {
                "status": "failed",
                "reason": f"pluginkit-{arguments.state}",
                "detail": last_error,
            },
            sort_keys=True,
        ),
        file=sys.stderr,
    )
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
