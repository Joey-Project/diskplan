#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT
readonly MODE="${1:-check}"
readonly FIXTURE_DIR="${REPO_ROOT}/proto/fixtures/runtime-v1.4"

if (( $# > 1 )) || [[ "${MODE}" != "check" && "${MODE}" != "generate" ]]; then
    echo "usage: scripts/protocol14-fixtures.sh [check|generate]" >&2
    exit 64
fi

TMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/diskplan-protocol14-fixtures.XXXXXX")"
readonly TMP_ROOT
trap 'rm -rf "${TMP_ROOT}"' EXIT

swift run --package-path "${REPO_ROOT}" --disable-automatic-resolution \
    DiskplanProtocolFixtureGenerator \
    "${FIXTURE_DIR}/fixtures.json" "${TMP_ROOT}"

readonly EMPTY_SOURCE="${TMP_ROOT}/empty-batch-dry-run.frames.hex"
readonly EMPTY_DESTINATION="${FIXTURE_DIR}/empty-batch-dry-run.frames.hex"
readonly FORCE_SOURCE="${TMP_ROOT}/force-action-execution.frames.hex"
readonly FORCE_DESTINATION="${FIXTURE_DIR}/force-action-execution.frames.hex"
readonly GIT_SOURCE="${TMP_ROOT}/git-evidence-action.frames.hex"
readonly GIT_DESTINATION="${FIXTURE_DIR}/git-evidence-action.frames.hex"
readonly CODEX_SOURCE="${TMP_ROOT}/codex-scope-action.frames.hex"
readonly CODEX_DESTINATION="${FIXTURE_DIR}/codex-scope-action.frames.hex"
readonly VERSION_SOURCE="${TMP_ROOT}/version-survivor-action.frames.hex"
readonly VERSION_DESTINATION="${FIXTURE_DIR}/version-survivor-action.frames.hex"

if [[ "${MODE}" == "generate" ]]; then
    cargo run --locked --quiet -p generated-source-publish -- \
        publish \
        "${REPO_ROOT}" \
        "${EMPTY_SOURCE}" "${EMPTY_DESTINATION}" \
        "${FORCE_SOURCE}" "${FORCE_DESTINATION}" \
        "${GIT_SOURCE}" "${GIT_DESTINATION}" \
        "${CODEX_SOURCE}" "${CODEX_DESTINATION}" \
        "${VERSION_SOURCE}" "${VERSION_DESTINATION}"
    echo "generated protocol 1.4 runtime fixtures"
else
    cargo run --locked --quiet -p generated-source-publish -- \
        verify \
        "${REPO_ROOT}" \
        "${EMPTY_SOURCE}" "${EMPTY_DESTINATION}" \
        "${FORCE_SOURCE}" "${FORCE_DESTINATION}" \
        "${GIT_SOURCE}" "${GIT_DESTINATION}" \
        "${CODEX_SOURCE}" "${CODEX_DESTINATION}" \
        "${VERSION_SOURCE}" "${VERSION_DESTINATION}"
    echo "protocol 1.4 runtime fixtures match the Swift authority"
fi
