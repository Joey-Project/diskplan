#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT

cd "${REPO_ROOT}"
swift build --product diskplan-engine
SWIFT_BIN_DIR="$(swift build --show-bin-path)"
readonly SWIFT_BIN_DIR
readonly ENGINE_BIN="${SWIFT_BIN_DIR}/diskplan-engine"
if [[ ! -x "${ENGINE_BIN}" ]]; then
    echo "Swift engine binary is missing: ${ENGINE_BIN}" >&2
    exit 1
fi
DISKPLAN_ENGINE_BIN="${ENGINE_BIN}" cargo test --locked -p diskplan --test engine_integration \
    rust_client_negotiates_and_keeps_swift_engine_ready -- --ignored --exact
DISKPLAN_ENGINE_BIN="${ENGINE_BIN}" cargo test --locked -p diskplan --test engine_integration \
    swift_engine_rejects_pre_handshake_major_and_capability_errors -- --ignored --exact
DISKPLAN_ENGINE_BIN="${ENGINE_BIN}" cargo test --locked -p diskplan --test engine_integration \
    rust_client_drives_swift_scan_control_protocol -- --ignored --exact
DISKPLAN_ENGINE_BIN="${ENGINE_BIN}" cargo test --locked -p diskplan --test engine_integration \
    swift_engine_malformed_embedding_consumes_request_id -- --ignored --exact
scripts/canonical-fixture.sh check
