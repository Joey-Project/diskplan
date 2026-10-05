#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT
readonly MODE="${1:-check}"
readonly FIXTURE_DIR="${REPO_ROOT}/proto/fixtures/scan-stream-v1.3"

if (( $# > 1 )) || [[ "${MODE}" != "check" && "${MODE}" != "generate" ]]; then
    echo "usage: scripts/protocol13-fixtures.sh [check|generate]" >&2
    exit 64
fi

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/diskplan-protocol13-fixtures.XXXXXX")"
readonly TMP_ROOT
trap 'rm -rf "${TMP_ROOT}"' EXIT

swift run --package-path "${REPO_ROOT}" --disable-automatic-resolution \
    DiskplanProtocolFixtureGenerator \
    "${FIXTURE_DIR}/fixtures.json" "${TMP_ROOT}"

if [[ "${MODE}" == "generate" ]]; then
    cargo run --locked --quiet -p generated-source-publish -- \
        publish \
        "${REPO_ROOT}" \
        "${TMP_ROOT}/zero-ready.frames.hex" "${FIXTURE_DIR}/zero-ready.frames.hex" \
        "${TMP_ROOT}/single-ready.frames.hex" "${FIXTURE_DIR}/single-ready.frames.hex" \
        "${TMP_ROOT}/multi-finalized.frames.hex" "${FIXTURE_DIR}/multi-finalized.frames.hex"
    echo "generated protocol 1.3 scan-stream fixtures"
else
    cargo run --locked --quiet -p generated-source-publish -- \
        verify \
        "${REPO_ROOT}" \
        "${TMP_ROOT}/zero-ready.frames.hex" "${FIXTURE_DIR}/zero-ready.frames.hex" \
        "${TMP_ROOT}/single-ready.frames.hex" "${FIXTURE_DIR}/single-ready.frames.hex" \
        "${TMP_ROOT}/multi-finalized.frames.hex" "${FIXTURE_DIR}/multi-finalized.frames.hex"
    echo "protocol 1.3 scan-stream fixtures match the Swift authority"
fi
