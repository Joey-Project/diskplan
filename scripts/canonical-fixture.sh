#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT
readonly MODE="${1:-check}"
readonly FIXTURE_DIR="${REPO_ROOT}/proto/fixtures/canonical-binary-v1"

if (( $# > 1 )) || [[ "${MODE}" != "check" && "${MODE}" != "generate" ]]; then
    echo "usage: scripts/canonical-fixture.sh [check|generate]" >&2
    exit 64
fi

TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/diskplan-fixture.XXXXXX")"
readonly TEMP_ROOT

cleanup() {
    rm -rf -- "${TEMP_ROOT}"
}

trap cleanup EXIT

cd "${REPO_ROOT}"
swift run --disable-automatic-resolution DiskplanFixtureGenerator \
    "${FIXTURE_DIR}/evidence.json" "${TEMP_ROOT}"

if [[ "${MODE}" == "generate" ]]; then
    cargo run --locked --quiet -p generated-source-publish -- \
        publish \
        "${REPO_ROOT}" \
        "${TEMP_ROOT}/evidence.bin" "${FIXTURE_DIR}/evidence.bin" \
        "${TEMP_ROOT}/evidence.sha256" "${FIXTURE_DIR}/evidence.sha256"
    echo "updated canonical-binary-v1 golden vector with per-file atomic replacement" >&2
else
    cargo run --locked --quiet -p generated-source-publish -- \
        verify \
        "${REPO_ROOT}" \
        "${TEMP_ROOT}/evidence.bin" "${FIXTURE_DIR}/evidence.bin" \
        "${TEMP_ROOT}/evidence.sha256" "${FIXTURE_DIR}/evidence.sha256"
    echo "canonical-binary-v1 golden vector matches Swift authority" >&2
fi
