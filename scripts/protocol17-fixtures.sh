#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT
readonly MODE="${1:-check}"
readonly FIXTURE="${REPO_ROOT}/proto/fixtures/runtime-v1.7/fixtures.json"

if (( $# > 1 )) || [[ "${MODE}" != "check" && "${MODE}" != "generate" ]]; then
    echo "usage: scripts/protocol17-fixtures.sh [check|generate]" >&2
    exit 64
fi

TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/diskplan-protocol17-fixtures.XXXXXX")"
readonly TEMP_ROOT
trap 'rm -rf -- "${TEMP_ROOT}"' EXIT

cd "${REPO_ROOT}"
cargo run --locked --quiet -p diskplan-proto --example effect_runtime_fixture_generator -- \
    "${TEMP_ROOT}/fixtures.json"

if [[ "${MODE}" == "generate" ]]; then
    cargo run --locked --quiet -p generated-source-publish -- \
        publish "${REPO_ROOT}" "${TEMP_ROOT}/fixtures.json" "${FIXTURE}"
    echo "updated runtime-v1.7 component vectors with per-file atomic replacement"
else
    cargo run --locked --quiet -p generated-source-publish -- \
        verify "${REPO_ROOT}" "${TEMP_ROOT}/fixtures.json" "${FIXTURE}"
    echo "runtime-v1.7 component vectors match the generated protobuf bindings"
fi
