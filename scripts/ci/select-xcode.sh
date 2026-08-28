#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
readonly LOCK_FILE="${SCRIPT_DIR}/toolchain.lock"

XCODE_VERSION="$(sed -n 's/^xcode=//p' "${LOCK_FILE}")"
readonly XCODE_VERSION
if [[ -z "${XCODE_VERSION}" || "$(sed -n 's/^xcode=//p' "${LOCK_FILE}" | wc -l | tr -d ' ')" != "1" ]]; then
    echo "CI toolchain lock must contain exactly one non-empty xcode entry" >&2
    exit 1
fi

readonly XCODE_PATH="/Applications/Xcode_${XCODE_VERSION}.app"
if [[ ! -d "${XCODE_PATH}" ]]; then
    echo "pinned Xcode is unavailable: ${XCODE_PATH}" >&2
    exit 1
fi

sudo xcode-select --switch "${XCODE_PATH}"
xcodebuild -version
