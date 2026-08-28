#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT

TIMEOUT_BIN="$(command -v gtimeout || command -v timeout || true)"
readonly TIMEOUT_BIN
if [[ -z "${TIMEOUT_BIN}" ]]; then
    echo "a timeout executable is required for the PTY smoke test" >&2
    exit 1
fi

TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/diskplan-tui-pty.XXXXXX")"
readonly TEMP_ROOT
cleanup() {
    rm -rf -- "${TEMP_ROOT}"
}
trap cleanup EXIT

cd "${REPO_ROOT}"
swift build --product diskplan-engine
cargo build --locked -p diskplan --target-dir "${TEMP_ROOT}/cargo-target"

SWIFT_BIN_DIR="$(swift build --show-bin-path)"
readonly SWIFT_BIN_DIR
readonly ENGINE_BIN="${SWIFT_BIN_DIR}/diskplan-engine"
readonly CLI_BIN="${TEMP_ROOT}/cargo-target/debug/diskplan"
readonly TRANSCRIPT="${TEMP_ROOT}/transcript"

if [[ ! -x "${ENGINE_BIN}" || ! -x "${CLI_BIN}" ]]; then
    echo "required TUI smoke-test binary is missing" >&2
    exit 1
fi

{
    sleep 1
    printf '?'
    sleep 0.1
    printf '?'
    sleep 0.1
    printf 'p'
    sleep 0.1
    printf 'r'
    sleep 0.1
    printf 'q'
} | "${TIMEOUT_BIN}" 20 /usr/bin/script -q "${TRANSCRIPT}" /bin/bash -c \
    'stty columns 80 rows 24; exec "$@"' diskplan-pty "${CLI_BIN}" "${ENGINE_BIN}" \
    > /dev/null

if ! grep -aq "diskplan" "${TRANSCRIPT}"; then
    echo "PTY transcript did not contain the Diskplan TUI" >&2
    exit 1
fi

echo "TUI PTY control/restore smoke test passed" >&2
