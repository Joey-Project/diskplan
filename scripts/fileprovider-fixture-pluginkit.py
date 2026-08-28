#!/usr/bin/env python3
import argparse
import json
from pathlib import Path
import sys

from fileprovider_fixture_subprocess import (
    BoundedCommandFailure,
    CommandExited,
    CommandOutputInvalidUTF8,
    CommandOutputLimitExceeded,
    CommandStartFailed,
    CommandTimedOut,
    run_bounded_text,
)

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
        run_bounded_text(
            ["pluginkit", option, str(arguments.path.resolve(strict=True))],
            timeout_seconds=10,
            maximum_output_bytes=MAXIMUM_OUTPUT_BYTES,
        )
    except CommandTimedOut:
        print('{"status":"failed","reason":"pluginkit-command-timeout"}', file=sys.stderr)
        return 1
    except CommandOutputLimitExceeded:
        print('{"status":"failed","reason":"pluginkit-command-output-limit"}', file=sys.stderr)
        return 1
    except CommandOutputInvalidUTF8:
        print('{"status":"failed","reason":"pluginkit-command-invalid-utf8"}', file=sys.stderr)
        return 1
    except CommandStartFailed:
        print('{"status":"failed","reason":"pluginkit-command-unavailable"}', file=sys.stderr)
        return 1
    except CommandExited as error:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "reason": "pluginkit-command",
                    "action": arguments.action,
                    "exit": error.returncode,
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 1
    except BoundedCommandFailure:
        print('{"status":"failed","reason":"pluginkit-command-internal"}', file=sys.stderr)
        return 1
    print(json.dumps({"status": "completed", "action": arguments.action}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
