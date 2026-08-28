#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import subprocess
import sys


MAXIMUM_OUTPUT_BYTES = 64 * 1024


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--action", choices=("add", "remove"), required=True)
    parser.add_argument("--path", type=Path, required=True)
    arguments = parser.parse_args()
    if arguments.path.is_symlink() or not arguments.path.is_dir():
        print('{"status":"failed","reason":"pluginkit-path"}', file=sys.stderr)
        return 1
    option = "-a" if arguments.action == "add" else "-r"
    try:
        result = subprocess.run(
            ["pluginkit", option, str(arguments.path.resolve(strict=True))],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            timeout=10,
            check=False,
        )
    except subprocess.TimeoutExpired:
        print('{"status":"failed","reason":"pluginkit-command-timeout"}', file=sys.stderr)
        return 1
    if len(result.stdout) > MAXIMUM_OUTPUT_BYTES:
        print('{"status":"failed","reason":"pluginkit-command-output-limit"}', file=sys.stderr)
        return 1
    if result.returncode != 0:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "reason": "pluginkit-command",
                    "action": arguments.action,
                    "exit": result.returncode,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    print(json.dumps({"status": "completed", "action": arguments.action}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
