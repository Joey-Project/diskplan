#!/bin/bash

set -euo pipefail

if (( $# < 2 )); then
    echo "usage: scripts/ci/package-resolved-guard.sh <check|run> <Package.resolved> [-- <command> ...]" >&2
    exit 64
fi

readonly MODE="$1"
readonly LOCKFILE="$2"

lockfile_digest() {
    if [[ ! -f "${LOCKFILE}" || -L "${LOCKFILE}" ]]; then
        echo "Package.resolved must be a non-symlink regular file" >&2
        return 1
    fi
    shasum -a 256 "${LOCKFILE}" | awk '{print $1}'
}

BEFORE_DIGEST="$(lockfile_digest)" || exit 1
readonly BEFORE_DIGEST

case "${MODE}" in
    check)
        if (( $# != 2 )); then
            echo "check mode does not accept a command" >&2
            exit 64
        fi
        echo "Package.resolved content verified: ${BEFORE_DIGEST}" >&2
        exit 0
        ;;
    run)
        if (( $# < 4 )) || [[ "$3" != "--" ]]; then
            echo "run mode requires -- followed by a command" >&2
            exit 64
        fi
        shift 3
        ;;
    *)
        echo "guard mode must be check or run" >&2
        exit 64
        ;;
esac

set +e
"$@"
COMMAND_STATUS=$?
set -e
readonly COMMAND_STATUS

AFTER_DIGEST="$(lockfile_digest)" || {
    echo "Package.resolved became missing or unsafe while running the guarded command" >&2
    exit 1
}
readonly AFTER_DIGEST
if [[ "${AFTER_DIGEST}" != "${BEFORE_DIGEST}" ]]; then
    echo "Package.resolved content changed while running the guarded command" >&2
    exit 1
fi

exit "${COMMAND_STATUS}"
