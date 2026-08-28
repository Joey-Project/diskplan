#!/bin/bash

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd -P)"
readonly REPO_ROOT

if (( $# > 1 )); then
    echo "usage: build-release.sh [output-directory]" >&2
    exit 64
fi

OUTPUT_DIR="${1:-${REPO_ROOT}/dist}"
if [[ "${OUTPUT_DIR}" != /* ]]; then
    OUTPUT_DIR="${REPO_ROOT}/${OUTPUT_DIR}"
fi
readonly OUTPUT_DIR

if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
    echo "release builds require an arm64 macOS host" >&2
    exit 69
fi

TEMP_PARENT="${DISKPLAN_RELEASE_WORK_ROOT:-${TMPDIR:-/tmp}}"
TEMP_PARENT="${TEMP_PARENT%/}"
mkdir -p -- "${TEMP_PARENT}"
WORK_ROOT="$(mktemp -d "${TEMP_PARENT}/diskplan-release.XXXXXX")"
WORK_ROOT="$(cd "${WORK_ROOT}" && pwd -P)"
readonly WORK_ROOT

cleanup() {
    rm -rf -- "${WORK_ROOT}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

source_state() {
    local revision tree input_manifest status
    git -C "${REPO_ROOT}" update-index -q --refresh
    status="$(git -C "${REPO_ROOT}" status --porcelain=v1 --untracked-files=all)"
    if [[ -n "${status}" ]]; then
        echo "release builds require a clean source checkout" >&2
        return 1
    fi
    revision="$(git -C "${REPO_ROOT}" rev-parse --verify 'HEAD^{commit}')"
    tree="$(git -C "${REPO_ROOT}" rev-parse --verify "${revision}^{tree}")"
    input_manifest="$(git -C "${REPO_ROOT}" ls-tree -r --full-tree "${revision}" | /usr/bin/shasum -a 256 | /usr/bin/awk '{print $1}')"
    [[ "${revision}" =~ ^[0-9a-f]{40}$ && "${tree}" =~ ^[0-9a-f]{40}$ && "${input_manifest}" =~ ^[0-9a-f]{64}$ ]] || {
        echo "release source identity is malformed" >&2
        return 1
    }
    /usr/bin/printf '%s\n%s\n%s\n' "${revision}" "${tree}" "${input_manifest}"
}

INITIAL_SOURCE_STATE="$(source_state)"
readonly INITIAL_SOURCE_STATE
SOURCE_REVISION="$(/usr/bin/printf '%s\n' "${INITIAL_SOURCE_STATE}" | /usr/bin/sed -n '1p')"
readonly SOURCE_REVISION

readonly SOURCE_ROOT="${WORK_ROOT}/source"
mkdir "${SOURCE_ROOT}"
git -C "${REPO_ROOT}" archive --format=tar "${SOURCE_REVISION}" | /usr/bin/tar -xf - -C "${SOURCE_ROOT}"
SOURCE_SNAPSHOT_MANIFEST="$(python3 "${SOURCE_ROOT}/scripts/release/source_manifest.py" "${SOURCE_ROOT}")"
readonly SOURCE_SNAPSHOT_MANIFEST
[[ "${SOURCE_SNAPSHOT_MANIFEST}" =~ ^[0-9a-f]{64}$ ]] || {
    echo "release source snapshot manifest is malformed" >&2
    exit 1
}

DEPLOYMENT_TARGET="$(/usr/bin/plutil -extract deployment_target_macos raw -o - "${SOURCE_ROOT}/release/protocol.json")"
readonly DEPLOYMENT_TARGET
[[ "${DEPLOYMENT_TARGET}" =~ ^[0-9]+\.[0-9]+(\.[0-9]+)?$ ]] || {
    echo "release deployment target is malformed" >&2
    exit 1
}
export MACOSX_DEPLOYMENT_TARGET="${DEPLOYMENT_TARGET}"

PRODUCT_VERSION="$(<"${SOURCE_ROOT}/release/VERSION")"
PROTOCOL_MAJOR="$(/usr/bin/plutil -extract protocol_major raw -o - "${SOURCE_ROOT}/release/protocol.json")"
PROTOCOL_MINOR="$(/usr/bin/plutil -extract protocol_minor raw -o - "${SOURCE_ROOT}/release/protocol.json")"
readonly PRODUCT_VERSION PROTOCOL_MAJOR PROTOCOL_MINOR
SEMVER_CORE='(0|[1-9][0-9]*)'
SEMVER_IDENTIFIER='(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)'
SEMVER_PRERELEASE="${SEMVER_IDENTIFIER}(\\.${SEMVER_IDENTIFIER})*"
SEMVER_BUILD='[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*'
readonly SEMVER_CORE SEMVER_IDENTIFIER SEMVER_PRERELEASE SEMVER_BUILD
[[ "${PRODUCT_VERSION}" =~ ^${SEMVER_CORE}\.${SEMVER_CORE}\.${SEMVER_CORE}(-${SEMVER_PRERELEASE})?(\+${SEMVER_BUILD})?$ ]] || {
    echo "release product version is malformed" >&2
    exit 1
}
[[ "${PROTOCOL_MAJOR}" =~ ^[1-9][0-9]*$ && "${PROTOCOL_MINOR}" =~ ^[0-9]+$ ]] || {
    echo "release protocol version is malformed" >&2
    exit 1
}

readonly CARGO_TARGET_DIR="${WORK_ROOT}/cargo-target"
readonly SWIFT_SCRATCH_PATH="${WORK_ROOT}/swift-build"
readonly FS_HELPER="${WORK_ROOT}/diskplan-fs-helper"
export CARGO_TARGET_DIR

cd "${SOURCE_ROOT}"
python3 "${SOURCE_ROOT}/scripts/release/generate_bundle_contract.py" check
cargo build --locked --release --target aarch64-apple-darwin -p diskplan
swift build \
    --disable-automatic-resolution \
    --configuration release \
    --scratch-path "${SWIFT_SCRATCH_PATH}" \
    -Xswiftc -file-prefix-map \
    -Xswiftc "${WORK_ROOT}=/diskplan-release" \
    -Xlinker -S \
    --product diskplan-engine
/usr/bin/xcrun clang \
    -arch arm64 \
    "-mmacosx-version-min=${DEPLOYMENT_TARGET}" \
    -std=c11 \
    -Os \
    -Wall \
    -Wextra \
    -Werror \
    "-DDISKPLAN_PRODUCT_VERSION=\"${PRODUCT_VERSION}\"" \
    "-DDISKPLAN_PROTOCOL_MAJOR=${PROTOCOL_MAJOR}" \
    "-DDISKPLAN_PROTOCOL_MINOR=${PROTOCOL_MINOR}" \
    "${SOURCE_ROOT}/scripts/release/diskplan-fs-helper.c" \
    -o "${FS_HELPER}"

readonly FRONTEND="${CARGO_TARGET_DIR}/aarch64-apple-darwin/release/diskplan"
SWIFT_BIN_DIR="$(swift build \
    --disable-automatic-resolution \
    --configuration release \
    --scratch-path "${SWIFT_SCRATCH_PATH}" \
    --show-bin-path)"
readonly SWIFT_BIN_DIR
readonly ENGINE="${SWIFT_BIN_DIR}/diskplan-engine"

AFTER_BUILD_SOURCE_STATE="$(source_state)"
readonly AFTER_BUILD_SOURCE_STATE
[[ "${AFTER_BUILD_SOURCE_STATE}" == "${INITIAL_SOURCE_STATE}" ]] || {
    echo "release source revision or input manifest changed during compilation" >&2
    exit 1
}
AFTER_BUILD_SNAPSHOT_MANIFEST="$(python3 "${SOURCE_ROOT}/scripts/release/source_manifest.py" "${SOURCE_ROOT}")"
readonly AFTER_BUILD_SNAPSHOT_MANIFEST
[[ "${AFTER_BUILD_SNAPSHOT_MANIFEST}" == "${SOURCE_SNAPSHOT_MANIFEST}" ]] || {
    echo "private release source snapshot changed during compilation" >&2
    exit 1
}

python3 "${SOURCE_ROOT}/scripts/release/package_bundle.py" \
    --frontend "${FRONTEND}" \
    --engine "${ENGINE}" \
    --fs-helper "${FS_HELPER}" \
    --installer "${SOURCE_ROOT}/scripts/release/install.sh" \
    --activator "${SOURCE_ROOT}/scripts/release/activate.sh" \
    --uninstaller "${SOURCE_ROOT}/scripts/release/uninstall.sh" \
    --common-library "${SOURCE_ROOT}/scripts/release/release-common.sh" \
    --version-file "${SOURCE_ROOT}/release/VERSION" \
    --protocol-metadata "${SOURCE_ROOT}/release/protocol.json" \
    --source-revision "${SOURCE_REVISION}" \
    --output-dir "${OUTPUT_DIR}" \
    --require-macho-arm64
