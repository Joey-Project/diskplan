#!/bin/bash

set -euo pipefail

if (( $# < 1 || $# > 2 )); then
    echo "usage: scripts/ci/write-diagnostics.sh <output> [none|huge|hang]" >&2
    exit 64
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly PROBE_HELPER="${SCRIPT_DIR}/bounded_probe.py"
readonly OUTPUT="$1"
readonly TEST_MODE="${2:-none}"
readonly BYTE_LIMIT=16384
readonly PROBE_BYTE_LIMIT=1024
readonly PROBE_TIMEOUT_SECONDS=1

case "${TEST_MODE}" in
    none | huge | hang) ;;
    *)
        echo "diagnostic test mode must be none, huge, or hang" >&2
        exit 64
        ;;
esac

OUTPUT_DIRECTORY="$(dirname "${OUTPUT}")"
readonly OUTPUT_DIRECTORY
OUTPUT_NAME="$(basename "${OUTPUT}")"
readonly OUTPUT_NAME
mkdir -p "${OUTPUT_DIRECTORY}"
umask 077

if [[ -e "${OUTPUT}" || -L "${OUTPUT}" ]]; then
    rm -f -- "${OUTPUT}"
fi

TEMP_OUTPUT="$(mktemp "${OUTPUT_DIRECTORY}/.${OUTPUT_NAME}.tmp.XXXXXX")"
cleanup() {
    if [[ -n "${TEMP_OUTPUT}" && ( -e "${TEMP_OUTPUT}" || -L "${TEMP_OUTPUT}" ) ]]; then
        rm -f -- "${TEMP_OUTPUT}"
    fi
}
trap cleanup EXIT
trap 'exit 1' HUP INT TERM

python3 "${PROBE_HELPER}" \
    --max-bytes "${BYTE_LIMIT}" \
    --probe-max-bytes "${PROBE_BYTE_LIMIT}" \
    --timeout-seconds "${PROBE_TIMEOUT_SECONDS}" \
    --manifest "${TEST_MODE}" > "${TEMP_OUTPUT}"

ACTUAL_BYTES="$(wc -c < "${TEMP_OUTPUT}" | tr -d ' ')"
readonly ACTUAL_BYTES
if (( ACTUAL_BYTES > BYTE_LIMIT )); then
    echo "diagnostic manifest exceeded ${BYTE_LIMIT} bytes" >&2
    exit 1
fi

mv -f -- "${TEMP_OUTPUT}" "${OUTPUT}"
TEMP_OUTPUT=""
