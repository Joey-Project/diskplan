#!/bin/bash

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
BUNDLE=""
EXPECTED_HOST="India-mac-mini-m4-hoteng"
AUDIT_ROOT="${HOME:?HOME must be set}"
REPORT_PATH=""
TIMEOUT_SECONDS=21600
while (( $# > 0 )); do
    case "$1" in
        --bundle)
            (( $# >= 2 )) || { echo "--bundle needs a directory" >&2; exit 64; }
            BUNDLE="$2"
            shift 2
            ;;
        --expected-host)
            (( $# >= 2 )) || { echo "--expected-host needs a value" >&2; exit 64; }
            EXPECTED_HOST="$2"
            shift 2
            ;;
        --audit-root)
            (( $# >= 2 )) || { echo "--audit-root needs a path" >&2; exit 64; }
            AUDIT_ROOT="$2"
            shift 2
            ;;
        --report)
            (( $# >= 2 )) || { echo "--report needs a path" >&2; exit 64; }
            REPORT_PATH="$2"
            shift 2
            ;;
        --timeout-seconds)
            (( $# >= 2 )) || { echo "--timeout-seconds needs a value" >&2; exit 64; }
            TIMEOUT_SECONDS="$2"
            shift 2
            ;;
        *) echo "unknown India acceptance option: $1" >&2; exit 64 ;;
    esac
done
[[ -n "${BUNDLE}" ]] || { echo "usage: india-acceptance.sh --bundle DIR [options]" >&2; exit 64; }
if [[ ! "${TIMEOUT_SECONDS}" =~ ^[0-9]+$ ]] || (( TIMEOUT_SECONDS < 1 || TIMEOUT_SECONDS > 86400 )); then
    echo "invalid timeout" >&2
    exit 64
fi
[[ -d "${AUDIT_ROOT}" ]] || { echo "audit root is not a directory" >&2; exit 66; }

HOST_NAME="$(hostname -s)"
OS_VERSION="$(sw_vers -productVersion)"
ARCHITECTURE="$(uname -m)"
readonly HOST_NAME OS_VERSION ARCHITECTURE
[[ "${HOST_NAME}" == "${EXPECTED_HOST}" ]] || { echo "expected host ${EXPECTED_HOST}, found ${HOST_NAME}" >&2; exit 69; }
[[ "${OS_VERSION%%.*}" == "26" && "${ARCHITECTURE}" == "arm64" ]] || { echo "India release gate requires macOS 26 arm64" >&2; exit 69; }

TEMP_PARENT="${TMPDIR:-/tmp}"
TEMP_PARENT="${TEMP_PARENT%/}"
TASK_ROOT="$(mktemp -d "${TEMP_PARENT}/diskplan-india-acceptance.XXXXXX")"
TASK_ROOT="$(cd "${TASK_ROOT}" && pwd -P)"
readonly TASK_ROOT
cleanup() {
    rm -rf -- "${TASK_ROOT}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

readonly PREFIX="${TASK_ROOT}/prefix"
"${BUNDLE}/install.sh" --prefix "${PREFIX}" "${BUNDLE}"
VERSION="$(<"${BUNDLE}/VERSION")"
PROTOCOL_MAJOR="$(/usr/bin/plutil -extract protocol_major raw -o - "${BUNDLE}/manifest.json")"
PROTOCOL_MINOR="$(/usr/bin/plutil -extract protocol_minor raw -o - "${BUNDLE}/manifest.json")"
SOURCE_REVISION="$(/usr/bin/plutil -extract source_revision raw -o - "${BUNDLE}/manifest.json")"
BUNDLE_MANIFEST_SHA256="$(/usr/bin/shasum -a 256 "${BUNDLE}/manifest.json" | /usr/bin/awk '{print $1}')"
readonly VERSION PROTOCOL_MAJOR PROTOCOL_MINOR SOURCE_REVISION BUNDLE_MANIFEST_SHA256

HANDSHAKE_OUTPUT="${TASK_ROOT}/handshake.log"
HANDSHAKE_STATUS="$(python3 "${SCRIPT_DIR}/run_bounded.py" \
    --timeout-seconds 30 \
    --max-output-bytes 65536 \
    --output "${HANDSHAKE_OUTPUT}" \
    -- "${PREFIX}/bin/diskplan" --handshake)" || {
        echo "India acceptance handshake failed: ${HANDSHAKE_STATUS:-no status}" >&2
        exit 1
    }

# This exact interface is intentionally dry-run-only. It may inspect real user
# data but cannot request apply, persistent audit output, history, or spill.
AUDIT_OUTPUT="${TASK_ROOT}/full-audit.log"
AUDIT_STATUS="$(python3 "${SCRIPT_DIR}/run_bounded.py" \
    --timeout-seconds "${TIMEOUT_SECONDS}" \
    --max-output-bytes 1048576 \
    --output "${AUDIT_OUTPUT}" \
    -- "${PREFIX}/bin/diskplan" \
        --batch \
        --profile full-audit \
        --dry-run \
        --no-history \
        --no-audit-file \
        --root "${AUDIT_ROOT}")" || {
        echo "India acceptance full-audit dry-run failed: ${AUDIT_STATUS:-no status}" >&2
        exit 1
    }

REPORT="${TASK_ROOT}/acceptance-report.txt"
{
    echo "diskplan_india_acceptance=passed"
    echo "host=${HOST_NAME}"
    echo "macos=${OS_VERSION}"
    echo "architecture=${ARCHITECTURE}"
    echo "product_version=${VERSION}"
    echo "protocol=${PROTOCOL_MAJOR}.${PROTOCOL_MINOR}"
    echo "source_revision=${SOURCE_REVISION}"
    echo "bundle_manifest_sha256=${BUNDLE_MANIFEST_SHA256}"
    echo "audit_root=${AUDIT_ROOT}"
    echo "handshake=${HANDSHAKE_STATUS}"
    echo "full_audit_dry_run=${AUDIT_STATUS}"
} > "${REPORT}"
/bin/cat "${REPORT}"

if [[ -n "${REPORT_PATH}" ]]; then
    REPORT_PARENT="$(dirname "${REPORT_PATH}")"
    if mkdir -p -- "${REPORT_PARENT}" 2>/dev/null && /usr/bin/install -m 0600 "${REPORT}" "${REPORT_PATH}" 2>/dev/null; then
        echo "optional_report=${REPORT_PATH}"
    else
        echo "warning: optional acceptance report could not be persisted" >&2
    fi
fi
