#!/bin/bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly REPO_ROOT
readonly LOCK_FILE="${SCRIPT_DIR}/toolchain.lock"
readonly MODE="${1:-foundation}"

if (( $# > 1 )) || [[ "${MODE}" != "foundation" && "${MODE}" != "rust-only" ]]; then
    echo "usage: scripts/ci/bootstrap-macos-tools.sh [foundation|rust-only]" >&2
    exit 64
fi
if [[ "$(uname -s)" != "Darwin" || "$(uname -m)" != "arm64" ]]; then
    echo "CI tool bootstrap currently supports only macOS arm64" >&2
    exit 1
fi

read_lock_value() {
    local key="$1"
    local value
    local count
    value="$(sed -n "s/^${key}=//p" "${LOCK_FILE}")"
    count="$(sed -n "s/^${key}=//p" "${LOCK_FILE}" | wc -l | tr -d ' ')"
    if [[ "${count}" != "1" || -z "${value}" ]]; then
        echo "CI toolchain lock must contain exactly one non-empty ${key} entry" >&2
        exit 1
    fi
    printf '%s\n' "${value}"
}

validate_lock_schema() {
    local key
    local value
    local entries=0
    while IFS='=' read -r key value; do
        if [[ -z "${key}" || -z "${value}" ]]; then
            echo "CI toolchain lock contains a malformed entry" >&2
            exit 1
        fi
        case "${key}" in
            xcode | rust | protoc | protoc-darwin-arm64-sha256 | swift-protobuf | swift-protobuf-revision | shellcheck | shellcheck-darwin-arm64-sha256 | actionlint | actionlint-darwin-arm64-sha256) ;;
            *)
                echo "CI toolchain lock contains an unenforced key: ${key}" >&2
                exit 1
                ;;
        esac
        entries=$((entries + 1))
    done < "${LOCK_FILE}"
    if [[ "${entries}" != "10" ]]; then
        echo "CI toolchain lock must contain exactly ten enforced entries" >&2
        exit 1
    fi
}

verify_sha256() {
    local path="$1"
    local expected="$2"
    local actual
    actual="$(shasum -a 256 "${path}" | awk '{print $1}')"
    if [[ "${actual}" != "${expected}" ]]; then
        echo "checksum mismatch for ${path##*/}" >&2
        exit 1
    fi
}

download() {
    local url="$1"
    local destination="$2"
    curl --fail --location --retry 3 --retry-delay 2 --silent --show-error --output "${destination}" "${url}"
}

validate_lock_schema

RUST_VERSION="$(read_lock_value rust)"
readonly RUST_VERSION
rustup toolchain install "${RUST_VERSION}" --profile minimal --component clippy,rustfmt
cargo "+${RUST_VERSION}" --version
rustc "+${RUST_VERSION}" --version
if [[ -z "${GITHUB_ENV:-}" ]]; then
    echo "CI tool bootstrap requires GITHUB_ENV" >&2
    exit 1
fi
printf 'RUSTUP_TOOLCHAIN=%s\n' "${RUST_VERSION}" >> "${GITHUB_ENV}"

if [[ "${MODE}" == "rust-only" ]]; then
    exit 0
fi

if [[ -z "${RUNNER_TEMP:-}" || -z "${GITHUB_PATH:-}" ]]; then
    echo "foundation bootstrap requires RUNNER_TEMP and GITHUB_PATH" >&2
    exit 1
fi

TOOLS_ROOT="$(mktemp -d "${RUNNER_TEMP}/diskplan-tools.XXXXXX")"
readonly TOOLS_ROOT
readonly BIN_DIR="${TOOLS_ROOT}/bin"
mkdir -p "${BIN_DIR}"

PROTOC_VERSION="$(read_lock_value protoc)"
readonly PROTOC_VERSION
PROTOC_SHA256="$(read_lock_value protoc-darwin-arm64-sha256)"
readonly PROTOC_SHA256
readonly PROTOC_ARCHIVE="${TOOLS_ROOT}/protoc-${PROTOC_VERSION}-osx-aarch_64.zip"
download \
    "https://github.com/protocolbuffers/protobuf/releases/download/v${PROTOC_VERSION}/protoc-${PROTOC_VERSION}-osx-aarch_64.zip" \
    "${PROTOC_ARCHIVE}"
verify_sha256 "${PROTOC_ARCHIVE}" "${PROTOC_SHA256}"
mkdir -p "${TOOLS_ROOT}/protoc"
unzip -q "${PROTOC_ARCHIVE}" -d "${TOOLS_ROOT}/protoc"
install -m 0755 "${TOOLS_ROOT}/protoc/bin/protoc" "${BIN_DIR}/protoc"
if [[ "$(sed -n 's/^protoc=//p' "${REPO_ROOT}/proto/toolchain.lock")" != "${PROTOC_VERSION}" ]]; then
    echo "Protobuf version mismatch between CI and protocol locks" >&2
    exit 1
fi

SWIFT_PROTOBUF_VERSION="$(read_lock_value swift-protobuf)"
readonly SWIFT_PROTOBUF_VERSION
SWIFT_PROTOBUF_REVISION="$(read_lock_value swift-protobuf-revision)"
readonly SWIFT_PROTOBUF_REVISION
if [[ "$(sed -n 's/^swift-protobuf=//p' "${REPO_ROOT}/proto/toolchain.lock")" != "${SWIFT_PROTOBUF_VERSION}" ]]; then
    echo "SwiftProtobuf version mismatch between CI and protocol locks" >&2
    exit 1
fi
if ! grep -Fq "\"revision\" : \"${SWIFT_PROTOBUF_REVISION}\"" "${REPO_ROOT}/Package.resolved"; then
    echo "SwiftProtobuf revision mismatch between CI lock and Package.resolved" >&2
    exit 1
fi

cd "${REPO_ROOT}"
swift package resolve
readonly SWIFT_PROTOBUF_CHECKOUT="${REPO_ROOT}/.build/checkouts/swift-protobuf"
if [[ "$(git -C "${SWIFT_PROTOBUF_CHECKOUT}" rev-parse HEAD)" != "${SWIFT_PROTOBUF_REVISION}" ]]; then
    echo "resolved SwiftProtobuf checkout does not match the pinned revision" >&2
    exit 1
fi
swift build --package-path "${SWIFT_PROTOBUF_CHECKOUT}" -c release --product protoc-gen-swift
SWIFT_PROTOBUF_BIN_DIR="$(swift build --package-path "${SWIFT_PROTOBUF_CHECKOUT}" -c release --show-bin-path)"
readonly SWIFT_PROTOBUF_BIN_DIR
install -m 0755 "${SWIFT_PROTOBUF_BIN_DIR}/protoc-gen-swift" "${BIN_DIR}/protoc-gen-swift"

SHELLCHECK_VERSION="$(read_lock_value shellcheck)"
readonly SHELLCHECK_VERSION
SHELLCHECK_SHA256="$(read_lock_value shellcheck-darwin-arm64-sha256)"
readonly SHELLCHECK_SHA256
readonly SHELLCHECK_ARCHIVE="${TOOLS_ROOT}/shellcheck-v${SHELLCHECK_VERSION}.darwin.aarch64.tar.xz"
download \
    "https://github.com/koalaman/shellcheck/releases/download/v${SHELLCHECK_VERSION}/shellcheck-v${SHELLCHECK_VERSION}.darwin.aarch64.tar.xz" \
    "${SHELLCHECK_ARCHIVE}"
verify_sha256 "${SHELLCHECK_ARCHIVE}" "${SHELLCHECK_SHA256}"
tar -xJf "${SHELLCHECK_ARCHIVE}" -C "${TOOLS_ROOT}"
install -m 0755 "${TOOLS_ROOT}/shellcheck-v${SHELLCHECK_VERSION}/shellcheck" "${BIN_DIR}/shellcheck"

ACTIONLINT_VERSION="$(read_lock_value actionlint)"
readonly ACTIONLINT_VERSION
ACTIONLINT_SHA256="$(read_lock_value actionlint-darwin-arm64-sha256)"
readonly ACTIONLINT_SHA256
readonly ACTIONLINT_ARCHIVE="${TOOLS_ROOT}/actionlint_${ACTIONLINT_VERSION}_darwin_arm64.tar.gz"
download \
    "https://github.com/rhysd/actionlint/releases/download/v${ACTIONLINT_VERSION}/actionlint_${ACTIONLINT_VERSION}_darwin_arm64.tar.gz" \
    "${ACTIONLINT_ARCHIVE}"
verify_sha256 "${ACTIONLINT_ARCHIVE}" "${ACTIONLINT_SHA256}"
tar -xzf "${ACTIONLINT_ARCHIVE}" -C "${TOOLS_ROOT}"
install -m 0755 "${TOOLS_ROOT}/actionlint" "${BIN_DIR}/actionlint"

printf '%s\n' "${BIN_DIR}" >> "${GITHUB_PATH}"
