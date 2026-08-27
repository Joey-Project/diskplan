#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"
readonly REPO_ROOT
readonly TOOLCHAIN_LOCK="${REPO_ROOT}/proto/toolchain.lock"
readonly MODE="${1:-check}"

if (( $# > 1 )) || [[ "${MODE}" != "check" && "${MODE}" != "generate" ]]; then
    echo "usage: scripts/proto-codegen.sh [check|generate]" >&2
    exit 64
fi

read_lock_value() {
    local key="$1"
    local values
    local count
    values="$(sed -n "s/^${key}=//p" "${TOOLCHAIN_LOCK}")"
    count="$(sed -n "s/^${key}=//p" "${TOOLCHAIN_LOCK}" | wc -l | tr -d ' ')"
    if [[ "${count}" != "1" || -z "${values}" ]]; then
        echo "toolchain lock must contain exactly one non-empty ${key} entry" >&2
        exit 1
    fi
    printf '%s\n' "${values}"
}

validate_lock_schema() {
    local key
    local value
    local entries=0
    while IFS='=' read -r key value; do
        if [[ -z "${key}" || -z "${value}" ]]; then
            echo "toolchain lock contains a malformed entry" >&2
            exit 1
        fi
        case "${key}" in
            protoc | protoc-gen-swift | swift-protobuf | prost | prost-build) ;;
            *)
                echo "toolchain lock contains an unenforced key: ${key}" >&2
                exit 1
                ;;
        esac
        entries=$((entries + 1))
    done < "${TOOLCHAIN_LOCK}"
    if [[ "${entries}" != "5" ]]; then
        echo "toolchain lock must contain exactly five enforced entries" >&2
        exit 1
    fi
}

require_exact_line() {
    local path="$1"
    local line="$2"
    local label="$3"
    local count
    count="$(grep -Fxc "${line}" "${path}" || true)"
    if [[ "${count}" != "1" ]]; then
        echo "${label} is not pinned exactly once in ${path#"${REPO_ROOT}/"}" >&2
        exit 1
    fi
}

locked_cargo_version() {
    local package="$1"
    awk -v expected_name="${package}" '
        /^\[\[package\]\]$/ {
            if (name == expected_name) {
                print version
            }
            name = ""
            version = ""
            next
        }
        /^name = "/ {
            name = $0
            sub(/^name = "/, "", name)
            sub(/"$/, "", name)
            next
        }
        /^version = "/ {
            version = $0
            sub(/^version = "/, "", version)
            sub(/"$/, "", version)
        }
        END {
            if (name == expected_name) {
                print version
            }
        }
    ' "${REPO_ROOT}/Cargo.lock"
}

resolved_swift_protobuf_version() {
    awk '
        /"identity" : "swift-protobuf"/ {
            matches++
            active = 1
            next
        }
        active && /"version" : "/ {
            version = $0
            sub(/^.*"version" : "/, "", version)
            sub(/".*$/, "", version)
            print version
            active = 0
        }
        END {
            if (matches != 1) {
                exit 2
            }
        }
    ' "${REPO_ROOT}/Package.resolved"
}

validate_lock_schema
EXPECTED_PROTOC="$(read_lock_value protoc)"
readonly EXPECTED_PROTOC
EXPECTED_SWIFT_PLUGIN="$(read_lock_value protoc-gen-swift)"
readonly EXPECTED_SWIFT_PLUGIN
EXPECTED_SWIFT_PROTOBUF="$(read_lock_value swift-protobuf)"
readonly EXPECTED_SWIFT_PROTOBUF
EXPECTED_PROST="$(read_lock_value prost)"
readonly EXPECTED_PROST
EXPECTED_PROST_BUILD="$(read_lock_value prost-build)"
readonly EXPECTED_PROST_BUILD

require_exact_line \
    "${REPO_ROOT}/Package.swift" \
    "            exact: \"${EXPECTED_SWIFT_PROTOBUF}\"" \
    "swift-protobuf manifest version"
RESOLVED_SWIFT_PROTOBUF="$(resolved_swift_protobuf_version)" || {
    echo "Package.resolved must contain exactly one swift-protobuf pin" >&2
    exit 1
}
readonly RESOLVED_SWIFT_PROTOBUF
if [[ "${RESOLVED_SWIFT_PROTOBUF}" != "${EXPECTED_SWIFT_PROTOBUF}" ]]; then
    echo "swift-protobuf lock mismatch; expected ${EXPECTED_SWIFT_PROTOBUF}, resolved ${RESOLVED_SWIFT_PROTOBUF}" >&2
    exit 1
fi
require_exact_line \
    "${REPO_ROOT}/Cargo.toml" \
    "prost = \"=${EXPECTED_PROST}\"" \
    "prost workspace version"
require_exact_line \
    "${REPO_ROOT}/Cargo.toml" \
    "prost-build = \"=${EXPECTED_PROST_BUILD}\"" \
    "prost-build workspace version"
LOCKED_PROST="$(locked_cargo_version prost)"
readonly LOCKED_PROST
LOCKED_PROST_BUILD="$(locked_cargo_version prost-build)"
readonly LOCKED_PROST_BUILD
if [[ "${LOCKED_PROST}" != "${EXPECTED_PROST}" ]]; then
    echo "prost lock mismatch; expected ${EXPECTED_PROST}, resolved ${LOCKED_PROST:-missing or duplicated}" >&2
    exit 1
fi
if [[ "${LOCKED_PROST_BUILD}" != "${EXPECTED_PROST_BUILD}" ]]; then
    echo "prost-build lock mismatch; expected ${EXPECTED_PROST_BUILD}, resolved ${LOCKED_PROST_BUILD:-missing or duplicated}" >&2
    exit 1
fi

PROTOC_BIN="$(command -v protoc || true)"
readonly PROTOC_BIN
SWIFT_PLUGIN_BIN="$(command -v protoc-gen-swift || true)"
readonly SWIFT_PLUGIN_BIN

if [[ -z "${PROTOC_BIN}" ]]; then
    echo "required code generator is unavailable: protoc" >&2
    exit 1
fi
if [[ -z "${SWIFT_PLUGIN_BIN}" ]]; then
    echo "required code generator is unavailable: protoc-gen-swift" >&2
    exit 1
fi

if [[ "$("${PROTOC_BIN}" --version)" != "libprotoc ${EXPECTED_PROTOC}" ]]; then
    echo "protoc version mismatch; expected ${EXPECTED_PROTOC}" >&2
    exit 1
fi
if [[ "$("${SWIFT_PLUGIN_BIN}" --version)" != "protoc-gen-swift ${EXPECTED_SWIFT_PLUGIN}" ]]; then
    echo "protoc-gen-swift version mismatch; expected ${EXPECTED_SWIFT_PLUGIN}" >&2
    exit 1
fi

TEMP_ROOT="$(mktemp -d "${TMPDIR:-/tmp}/diskplan-codegen.XXXXXX")"
readonly TEMP_ROOT
cleanup() {
    rm -rf -- "${TEMP_ROOT}"
}
trap cleanup EXIT
mkdir -p "${TEMP_ROOT}/swift" "${TEMP_ROOT}/rust"

cd "${REPO_ROOT}"
"${PROTOC_BIN}" \
    --plugin="protoc-gen-swift=${SWIFT_PLUGIN_BIN}" \
    --proto_path=proto \
    --swift_opt=Visibility=Public \
    --swift_opt=FileNaming=PathToUnderscores \
    --swift_out="${TEMP_ROOT}/swift" \
    proto/diskplan/v1/ipc.proto
cargo run --locked --quiet -p proto-codegen -- "${PROTOC_BIN}" "${TEMP_ROOT}/rust"

readonly SWIFT_GENERATED="diskplan_v1_ipc.pb.swift"
readonly RUST_GENERATED="diskplan.v1.rs"
readonly SWIFT_DEST="${REPO_ROOT}/swift/Sources/DiskplanProto/${SWIFT_GENERATED}"
readonly RUST_DEST="${REPO_ROOT}/rust/crates/diskplan-proto/src/generated/${RUST_GENERATED}"

if [[ "${MODE}" == "generate" ]]; then
    cargo run --locked --quiet -p generated-source-publish -- \
        publish \
        "${REPO_ROOT}" \
        "${TEMP_ROOT}/swift/${SWIFT_GENERATED}" "${SWIFT_DEST}" \
        "${TEMP_ROOT}/rust/${RUST_GENERATED}" "${RUST_DEST}"
    echo "updated tracked protobuf sources with per-file atomic replacement" >&2
else
    cargo run --locked --quiet -p generated-source-publish -- \
        verify \
        "${REPO_ROOT}" \
        "${TEMP_ROOT}/swift/${SWIFT_GENERATED}" "${SWIFT_DEST}" \
        "${TEMP_ROOT}/rust/${RUST_GENERATED}" "${RUST_DEST}"
    echo "tracked protobuf sources match pinned code generators" >&2
fi
