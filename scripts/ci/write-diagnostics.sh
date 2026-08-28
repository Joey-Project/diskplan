#!/bin/bash

set -euo pipefail

if (( $# < 1 || $# > 2 )); then
    echo "usage: scripts/ci/write-diagnostics.sh <output> [test-payload-bytes]" >&2
    exit 64
fi

readonly OUTPUT="$1"
readonly TEST_PAYLOAD_BYTES="${2:-0}"
readonly BYTE_LIMIT=16384
if [[ ! "${TEST_PAYLOAD_BYTES}" =~ ^[0-9]+$ ]] || (( TEST_PAYLOAD_BYTES > 65536 )); then
    echo "test payload bytes must be an integer from 0 through 65536" >&2
    exit 64
fi

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

compact_version() {
    "$@" 2>&1 | head -n 4 || true
}

{
    echo "diskplan foundation CI diagnostics"
    echo "commit=$(git rev-parse HEAD 2>/dev/null || echo unavailable)"
    echo "runner_os=${RUNNER_OS:-unavailable}"
    echo "runner_arch=${RUNNER_ARCH:-unavailable}"
    echo "image_os=${ImageOS:-unavailable}"
    echo "image_version=${ImageVersion:-unavailable}"
    echo "kernel=$(uname -mrs 2>/dev/null || echo unavailable)"
    echo "macos=$(sw_vers -productVersion 2>/dev/null || echo unavailable)"
    echo "xcode:"
    compact_version xcodebuild -version
    echo "swift:"
    compact_version swift --version
    echo "rustc:"
    compact_version rustc --version
    echo "cargo:"
    compact_version cargo --version
    echo "protoc:"
    compact_version protoc --version
    echo "protoc-gen-swift:"
    compact_version protoc-gen-swift --version
    if (( TEST_PAYLOAD_BYTES > 0 )); then
        dd if=/dev/zero bs="${TEST_PAYLOAD_BYTES}" count=1 2>/dev/null | LC_ALL=C tr '\0' x
        echo
    fi
} > "${TEMP_OUTPUT}"

ACTUAL_BYTES="$(wc -c < "${TEMP_OUTPUT}" | tr -d ' ')"
readonly ACTUAL_BYTES
if (( ACTUAL_BYTES > BYTE_LIMIT )); then
    echo "diagnostic manifest exceeded ${BYTE_LIMIT} bytes" >&2
    exit 1
fi

mv -f -- "${TEMP_OUTPUT}" "${OUTPUT}"
TEMP_OUTPUT=""
