#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT

cd "${REPO_ROOT}"
swift build --disable-automatic-resolution --product diskplan-engine
SWIFT_BIN_DIR="$(swift build --disable-automatic-resolution --show-bin-path)"
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
    swift_engine_gates_scan_stream_on_negotiated_capabilities -- --ignored --exact
DISKPLAN_ENGINE_BIN="${ENGINE_BIN}" cargo test --locked -p diskplan --test engine_integration \
    swift_engine_reports_typed_scan_setup_rejections -- --ignored --exact
DISKPLAN_ENGINE_BIN="${ENGINE_BIN}" cargo test --locked -p diskplan --test engine_integration \
    swift_engine_rejects_legacy_plan_control_without_plan_events -- --ignored --exact
DISKPLAN_ENGINE_BIN="${ENGINE_BIN}" cargo test --locked -p diskplan --test engine_integration \
    rust_client_drives_swift_scan_control_protocol -- --ignored --exact
DISKPLAN_ENGINE_BIN="${ENGINE_BIN}" cargo test --locked -p diskplan --test engine_integration \
    rust_client_cancels_scan_with_final_evidence_and_keeps_session_ready -- --ignored --exact
DISKPLAN_ENGINE_BIN="${ENGINE_BIN}" cargo test --locked -p diskplan --test engine_integration \
    swift_engine_orders_root_failures_deterministically -- --ignored --exact
DISKPLAN_ENGINE_BIN="${ENGINE_BIN}" cargo test --locked -p diskplan --test engine_integration \
    swift_engine_malformed_embedding_consumes_request_id -- --ignored --exact
scripts/canonical-fixture.sh check
