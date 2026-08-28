#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT
readonly EXPECTED_MINIMUM="14.0"

if (( $# > 1 )); then
    echo "usage: scripts/test-deployment-target.sh [aarch64-apple-darwin|x86_64-apple-darwin]" >&2
    exit 64
fi

if (( $# == 1 )); then
    TARGET_TRIPLE="$1"
else
    TARGET_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
fi
readonly TARGET_TRIPLE

case "${TARGET_TRIPLE}" in
    aarch64-apple-darwin)
        EXPECTED_ARCH="arm64"
        ;;
    x86_64-apple-darwin)
        EXPECTED_ARCH="x86_64"
        ;;
    *)
        echo "unsupported deployment assertion target: ${TARGET_TRIPLE}" >&2
        exit 64
        ;;
esac
readonly EXPECTED_ARCH

TARGET_ROOT="${DISKPLAN_DEPLOYMENT_TARGET_DIR:-${REPO_ROOT}/.build/deployment-target}"
readonly TARGET_ROOT

cd "${REPO_ROOT}"
CARGO_TARGET_DIR="${TARGET_ROOT}" cargo build --locked --package diskplan --target "${TARGET_TRIPLE}"

BINARY_PATH="${TARGET_ROOT}/${TARGET_TRIPLE}/debug/diskplan"
readonly BINARY_PATH
if [[ ! -f "${BINARY_PATH}" || -L "${BINARY_PATH}" ]]; then
    echo "deployment assertion binary is not a regular file: ${BINARY_PATH}" >&2
    exit 1
fi

VTOOL_BIN="$(xcrun --find vtool)"
readonly VTOOL_BIN
BUILD_VERSION="$(${VTOOL_BIN} -show-build "${BINARY_PATH}")"
readonly BUILD_VERSION
MINIMUMS="$(awk '$1 == "minos" { print $2 }' <<< "${BUILD_VERSION}")"
readonly MINIMUMS
PLATFORMS="$(awk '$1 == "platform" { print $2 }' <<< "${BUILD_VERSION}")"
readonly PLATFORMS
ARCHITECTURES="$(lipo -archs "${BINARY_PATH}")"
readonly ARCHITECTURES

if [[ "${MINIMUMS}" != "${EXPECTED_MINIMUM}" ]]; then
    echo "unexpected LC_BUILD_VERSION minos for ${BINARY_PATH}; expected ${EXPECTED_MINIMUM}, found ${MINIMUMS:-none}" >&2
    exit 1
fi
if [[ "${PLATFORMS}" != "MACOS" ]]; then
    echo "unexpected LC_BUILD_VERSION platform for ${BINARY_PATH}; expected MACOS, found ${PLATFORMS:-none}" >&2
    exit 1
fi
if [[ "${ARCHITECTURES}" != "${EXPECTED_ARCH}" ]]; then
    echo "unexpected Mach-O architecture for ${BINARY_PATH}; expected ${EXPECTED_ARCH}, found ${ARCHITECTURES:-none}" >&2
    exit 1
fi

echo "Rust CLI deployment target verified: ${TARGET_TRIPLE} minos ${EXPECTED_MINIMUM}" >&2
