#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly REPO_ROOT

OUTPUT_DIR="${1:-${REPO_ROOT}/dist}"
if [[ "${OUTPUT_DIR}" != /* ]]; then
    OUTPUT_DIR="${REPO_ROOT}/${OUTPUT_DIR}"
fi
readonly OUTPUT_DIR

if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
    echo "release builds require an arm64 macOS host" >&2
    exit 69
fi

if [[ -n "${DISKPLAN_RELEASE_WORK_ROOT:-}" ]]; then
    WORK_ROOT="${DISKPLAN_RELEASE_WORK_ROOT}"
    mkdir -p "${WORK_ROOT}"
    CLEAN_WORK_ROOT=0
else
    TEMP_PARENT="${TMPDIR:-/tmp}"
    TEMP_PARENT="${TEMP_PARENT%/}"
    WORK_ROOT="$(mktemp -d "${TEMP_PARENT}/diskplan-release.XXXXXX")"
    CLEAN_WORK_ROOT=1
fi
readonly WORK_ROOT CLEAN_WORK_ROOT

cleanup() {
    if (( CLEAN_WORK_ROOT == 1 )); then
        rm -rf -- "${WORK_ROOT}"
    fi
}
trap cleanup EXIT

readonly CARGO_TARGET_DIR="${WORK_ROOT}/cargo-target"
readonly SWIFT_SCRATCH_PATH="${WORK_ROOT}/swift-build"
export CARGO_TARGET_DIR

cd "${REPO_ROOT}"
cargo build --locked --release --target aarch64-apple-darwin -p diskplan
swift build \
    --disable-automatic-resolution \
    --configuration release \
    --scratch-path "${SWIFT_SCRATCH_PATH}" \
    --product diskplan-engine

readonly FRONTEND="${CARGO_TARGET_DIR}/aarch64-apple-darwin/release/diskplan"
SWIFT_BIN_DIR="$(swift build \
    --disable-automatic-resolution \
    --configuration release \
    --scratch-path "${SWIFT_SCRATCH_PATH}" \
    --show-bin-path)"
readonly SWIFT_BIN_DIR
readonly ENGINE="${SWIFT_BIN_DIR}/diskplan-engine"
SOURCE_REVISION="$(git rev-parse HEAD)"
readonly SOURCE_REVISION

python3 "${SCRIPT_DIR}/package_bundle.py" \
    --frontend "${FRONTEND}" \
    --engine "${ENGINE}" \
    --installer "${SCRIPT_DIR}/install.sh" \
    --activator "${SCRIPT_DIR}/activate.sh" \
    --uninstaller "${SCRIPT_DIR}/uninstall.sh" \
    --common-library "${SCRIPT_DIR}/release-common.sh" \
    --version-file "${REPO_ROOT}/release/VERSION" \
    --protocol-metadata "${REPO_ROOT}/release/protocol.json" \
    --source-revision "${SOURCE_REVISION}" \
    --output-dir "${OUTPUT_DIR}" \
    --require-macho-arm64
