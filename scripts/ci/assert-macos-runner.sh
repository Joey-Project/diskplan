#!/bin/bash

set -euo pipefail

if (( $# != 3 )); then
    echo "usage: scripts/ci/assert-macos-runner.sh <minimum|exact> <major> <architecture>" >&2
    exit 64
fi

readonly VERSION_MODE="$1"
readonly EXPECTED_MAJOR="$2"
readonly EXPECTED_ARCH="$3"

if [[ "${VERSION_MODE}" != "minimum" && "${VERSION_MODE}" != "exact" ]]; then
    echo "version mode must be minimum or exact" >&2
    exit 64
fi
if [[ ! "${EXPECTED_MAJOR}" =~ ^[0-9]+$ ]]; then
    echo "macOS major must be an integer" >&2
    exit 64
fi
if [[ "$(uname -s)" != "Darwin" ]]; then
    echo "foundation CI requires macOS" >&2
    exit 1
fi
if [[ "${RUNNER_OS:-macOS}" != "macOS" ]]; then
    echo "GitHub runner OS mismatch: ${RUNNER_OS}" >&2
    exit 1
fi

ACTUAL_ARCH="$(uname -m)"
readonly ACTUAL_ARCH
if [[ "${ACTUAL_ARCH}" != "${EXPECTED_ARCH}" ]]; then
    echo "runner architecture mismatch; expected ${EXPECTED_ARCH}, found ${ACTUAL_ARCH}" >&2
    exit 1
fi

PRODUCT_VERSION="$(sw_vers -productVersion)"
readonly PRODUCT_VERSION
PRODUCT_MAJOR="${PRODUCT_VERSION%%.*}"
readonly PRODUCT_MAJOR
if [[ ! "${PRODUCT_MAJOR}" =~ ^[0-9]+$ ]]; then
    echo "runner returned an invalid macOS version: ${PRODUCT_VERSION}" >&2
    exit 1
fi
if [[ "${VERSION_MODE}" == "minimum" ]] && (( PRODUCT_MAJOR < EXPECTED_MAJOR )); then
    echo "runner OS mismatch; expected macOS ${EXPECTED_MAJOR}+, found ${PRODUCT_VERSION}" >&2
    exit 1
fi
if [[ "${VERSION_MODE}" == "exact" ]] && (( PRODUCT_MAJOR != EXPECTED_MAJOR )); then
    echo "runner OS mismatch; expected macOS ${EXPECTED_MAJOR}, found ${PRODUCT_VERSION}" >&2
    exit 1
fi

echo "runner verified: macOS ${PRODUCT_VERSION} ${ACTUAL_ARCH}" >&2
