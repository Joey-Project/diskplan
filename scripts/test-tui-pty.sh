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
    if [[ "${DISKPLAN_KEEP_PTY_ARTIFACTS:-0}" == "1" ]]; then
        echo "PTY artifacts retained at ${TEMP_ROOT}" >&2
    else
        rm -rf -- "${TEMP_ROOT}"
    fi
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
readonly BEFORE_MODE="${TEMP_ROOT}/before-mode"
readonly AFTER_MODE="${TEMP_ROOT}/after-mode"
readonly RESTORED_STATE="${TEMP_ROOT}/restored-state"

if [[ ! -x "${ENGINE_BIN}" || ! -x "${CLI_BIN}" ]]; then
    echo "required TUI smoke-test binary is missing" >&2
    exit 1
fi

# Positional parameters intentionally expand only inside the child PTY shell.
# shellcheck disable=SC2016
{
    sleep 1
    printf '?'
    sleep 0.3
    printf '?'
    sleep 0.3
    printf ' '
    sleep 0.3
    printf 'p'
    sleep 0.4
    printf 'r'
    sleep 0.3
    printf 'q'
} | "${TIMEOUT_BIN}" 20 /usr/bin/script -q "${TRANSCRIPT}" /bin/bash -c \
    'stty columns 80 rows 24
     stty -g > "$3"
     "$1" "$2"
     status=$?
     stty -g > "$4"
     stty -a > "$5"
     printf "terminal-restored\n"
     if ! cmp -s "$3" "$4"; then exit 97; fi
     exit "$status"' \
    diskplan-pty "${CLI_BIN}" "${ENGINE_BIN}" "${BEFORE_MODE}" "${AFTER_MODE}" \
    "${RESTORED_STATE}" \
    > /dev/null

require_transcript() {
    local evidence="$1"
    local description="$2"
    if ! grep -aFq -- "${evidence}" "${TRANSCRIPT}"; then
        echo "PTY transcript did not prove ${description}" >&2
        exit 1
    fi
}

require_transcript "Hotkeys" "contextual help overlay"
require_transcript "pause/resume after engine" "contextual pause/resume help"
require_transcript "acknowledgement" "contextual acknowledgement barrier help"
require_transcript "Pause acknowledged" "pause acknowledgement"
require_transcript "Plan-first" "provisional-plan screen"
require_transcript "se0-provisional-0001" "provisional-plan identity"
require_transcript $'\033[2;12HRead-only scan' "resume invalidation returning to scan"
require_transcript "Resume acknow" "resume acknowledgement"
require_transcript $'\033[24;1HCancell' "single cancel request"
require_transcript $'\033[24;1Hscan can' "terminal cancellation transition"
require_transcript $'\033[24;10Helled' "terminal cancellation completion"
require_transcript "terminal-restored" "return to the invoking terminal"
require_transcript $'\033[?1049h' "alternate-screen entry"
require_transcript $'\033[?1049l' "alternate-screen leave"

if ! cmp -s "${BEFORE_MODE}" "${AFTER_MODE}"; then
    echo "PTY terminal mode did not match its pre-TUI state" >&2
    exit 1
fi
if ! grep -Eq '(^|[ ;])icanon([ ;]|$)' "${RESTORED_STATE}" \
    || ! grep -Eq '(^|[ ;])echo([ ;]|$)' "${RESTORED_STATE}"; then
    echo "PTY terminal did not restore canonical input and echo" >&2
    exit 1
fi

echo "TUI PTY control/restore smoke test passed" >&2
