#!/bin/bash

set -euo pipefail

if (( $# != 1 )); then
    echo "usage: scripts/ci/write-diagnostics.sh <output>" >&2
    exit 64
fi

readonly OUTPUT="$1"
mkdir -p "$(dirname "${OUTPUT}")"

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
} > "${OUTPUT}"

readonly BYTE_LIMIT=16384
ACTUAL_BYTES="$(wc -c < "${OUTPUT}" | tr -d ' ')"
readonly ACTUAL_BYTES
if (( ACTUAL_BYTES > BYTE_LIMIT )); then
    echo "diagnostic manifest exceeded ${BYTE_LIMIT} bytes" >&2
    exit 1
fi
