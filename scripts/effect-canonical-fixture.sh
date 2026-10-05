#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT
readonly MODE="${1:-check}"
readonly FIXTURE="${REPO_ROOT}/proto/fixtures/canonical-effect-v2/fixtures.json"

if (( $# > 1 )) || [[ "${MODE}" != "check" && "${MODE}" != "generate" ]]; then
    echo "usage: scripts/effect-canonical-fixture.sh [check|generate]" >&2
    exit 64
fi

TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/diskplan-effect-canonical.XXXXXX")"
readonly TEMP_ROOT
trap 'rm -rf -- "${TEMP_ROOT}"' EXIT

cd "${REPO_ROOT}"
cargo run --locked --quiet -p diskplan-core --example effect_canonical_fixture_generator -- \
    "${TEMP_ROOT}/fixtures.json"

if [[ "${MODE}" == "generate" ]]; then
    cargo run --locked --quiet -p generated-source-publish -- \
        publish "${REPO_ROOT}" "${TEMP_ROOT}/fixtures.json" "${FIXTURE}"
    echo "updated canonical-effect-v2 vectors with per-file atomic replacement"
else
    cargo run --locked --quiet -p generated-source-publish -- \
        verify "${REPO_ROOT}" "${TEMP_ROOT}/fixtures.json" "${FIXTURE}"
    echo "canonical-effect-v2 vectors match the Rust canonical encoder"
fi
