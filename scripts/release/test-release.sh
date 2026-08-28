#!/bin/bash

set -euo pipefail
umask 077

if (( $# != 1 )); then
    echo "usage: test-release.sh /absolute/path/diskplan-VERSION-macos-arm64.tar.gz" >&2
    exit 64
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly REPO_ROOT
ARCHIVE="$1"
if [[ "${ARCHIVE}" != /* ]]; then
    ARCHIVE="$(cd "$(dirname "${ARCHIVE}")" && pwd -P)/$(basename "${ARCHIVE}")"
fi
readonly ARCHIVE
[[ -f "${ARCHIVE}" && ! -L "${ARCHIVE}" ]] || { echo "release archive is missing or unsafe" >&2; exit 1; }

TEMP_PARENT="${TMPDIR:-/tmp}"
TEMP_PARENT="${TEMP_PARENT%/}"
TEST_ROOT="$(mktemp -d "${TEMP_PARENT}/diskplan-release-test.XXXXXX")"
TEST_ROOT="$(cd "${TEST_ROOT}" && pwd -P)"
readonly TEST_ROOT
cleanup() {
    rm -rf -- "${TEST_ROOT}"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "${TEST_ROOT}/extract"
/usr/bin/tar -xzf "${ARCHIVE}" -C "${TEST_ROOT}/extract"
BUNDLE_COUNT="$(/usr/bin/find "${TEST_ROOT}/extract" -mindepth 1 -maxdepth 1 -type d -print | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
readonly BUNDLE_COUNT
[[ "${BUNDLE_COUNT}" == "1" ]] || { echo "archive must contain exactly one bundle directory" >&2; exit 1; }
BUNDLE="$(/usr/bin/find "${TEST_ROOT}/extract" -mindepth 1 -maxdepth 1 -type d -print)"
readonly BUNDLE

# BSD tar applies the caller's 077 umask while retaining deterministic numeric
# archive ownership. The installer accepts only this permission narrowing, then
# normalizes every copied descriptor into its owner-private managed staging area.
/bin/chmod 0700 "${BUNDLE}/uninstall.sh"
/bin/chmod 0600 "${BUNDLE}/protocol.json"

readonly PREFIX="${TEST_ROOT}/prefix"

# No-follow prefix traversal rejects redirection before any outside object changes.
readonly OUTSIDE_SENTINEL="${TEST_ROOT}/outside-sentinel"
mkdir "${OUTSIDE_SENTINEL}"
/usr/bin/printf '%s\n' sentinel > "${OUTSIDE_SENTINEL}/sentinel"
ln -s "${OUTSIDE_SENTINEL}" "${TEST_ROOT}/symlink-prefix"
if "${BUNDLE}/install.sh" --prefix "${TEST_ROOT}/symlink-prefix" "${BUNDLE}" >/dev/null 2>&1; then
    echo "symlink install prefix was accepted" >&2
    exit 1
fi
[[ "$(<"${OUTSIDE_SENTINEL}/sentinel")" == "sentinel" ]]
[[ -z "$(/usr/bin/find "${OUTSIDE_SENTINEL}" -mindepth 1 ! -name sentinel -print -quit)" ]]

readonly SYMLINK_BIN_PREFIX="${TEST_ROOT}/symlink-bin-prefix"
mkdir "${SYMLINK_BIN_PREFIX}" "${TEST_ROOT}/outside-bin"
ln -s "${TEST_ROOT}/outside-bin" "${SYMLINK_BIN_PREFIX}/bin"
if "${BUNDLE}/install.sh" --prefix "${SYMLINK_BIN_PREFIX}" "${BUNDLE}" >/dev/null 2>&1; then
    echo "symlink managed bin directory was accepted" >&2
    exit 1
fi
[[ -z "$(/usr/bin/find "${TEST_ROOT}/outside-bin" -mindepth 1 -print -quit)" ]]

readonly SYMLINK_LIBEXEC_PREFIX="${TEST_ROOT}/symlink-libexec-prefix"
mkdir "${SYMLINK_LIBEXEC_PREFIX}" "${SYMLINK_LIBEXEC_PREFIX}/bin" "${TEST_ROOT}/outside-libexec"
ln -s "${TEST_ROOT}/outside-libexec" "${SYMLINK_LIBEXEC_PREFIX}/libexec"
if "${BUNDLE}/install.sh" --prefix "${SYMLINK_LIBEXEC_PREFIX}" "${BUNDLE}" >/dev/null 2>&1; then
    echo "symlink managed libexec directory was accepted" >&2
    exit 1
fi
[[ -z "$(/usr/bin/find "${TEST_ROOT}/outside-libexec" -mindepth 1 -print -quit)" ]]

# A dead, identity-bound lifecycle owner is recovered without manual broad cleanup.
readonly STALE_PREFIX="${TEST_ROOT}/stale-prefix"
STALE_PREFIX_IDENTITY="$("${BUNDLE}/diskplan-fs-helper" prepare-prefix "${STALE_PREFIX}")"
readonly STALE_PREFIX_IDENTITY
/bin/bash -c '"$1" acquire-lock "$2" "$3" "$$"; status=$?; exit "$status"' \
    diskplan-stale-lock-owner \
    "${BUNDLE}/diskplan-fs-helper" \
    "${STALE_PREFIX}" \
    "${STALE_PREFIX_IDENTITY}" >/dev/null
[[ -d "${STALE_PREFIX}/.diskplan-install.lock" ]]
"${BUNDLE}/install.sh" --prefix "${STALE_PREFIX}" "${BUNDLE}" >/dev/null
"${STALE_PREFIX}/libexec/diskplan/$(<"${BUNDLE}/VERSION")/uninstall.sh" \
    --prefix "${STALE_PREFIX}" "$(<"${BUNDLE}/VERSION")" >/dev/null
[[ ! -e "${STALE_PREFIX}/.diskplan-install.lock" ]]

# The acceptance supervisor enforces both independent resource ceilings.
set +e
python3 "${SCRIPT_DIR}/run_bounded.py" \
    --timeout-seconds 5 \
    --max-output-bytes 1024 \
    --output "${TEST_ROOT}/bounded-output.log" \
    -- /usr/bin/yes > "${TEST_ROOT}/bounded-output.json"
BOUNDED_OUTPUT_STATUS=$?
python3 "${SCRIPT_DIR}/run_bounded.py" \
    --timeout-seconds 1 \
    --max-output-bytes 1024 \
    --output "${TEST_ROOT}/bounded-time.log" \
    -- /bin/sleep 3 > "${TEST_ROOT}/bounded-time.json"
BOUNDED_TIME_STATUS=$?
set -e
[[ "${BOUNDED_OUTPUT_STATUS}" == "125" && "$(/usr/bin/stat -f '%z' "${TEST_ROOT}/bounded-output.log")" == "1024" ]]
[[ "${BOUNDED_TIME_STATUS}" == "124" ]]
/usr/bin/grep -F '"result":"output_limit_exceeded"' "${TEST_ROOT}/bounded-output.json" >/dev/null
/usr/bin/grep -F '"result":"timed_out"' "${TEST_ROOT}/bounded-time.json" >/dev/null

"${BUNDLE}/install.sh" --prefix "${PREFIX}" "${BUNDLE}"
VERSION="$(<"${BUNDLE}/VERSION")"
readonly VERSION
[[ "$(/usr/bin/stat -f '%Lp' "${PREFIX}/libexec/diskplan/${VERSION}/uninstall.sh")" == "755" ]]
[[ "$(/usr/bin/stat -f '%Lp' "${PREFIX}/libexec/diskplan/${VERSION}/protocol.json")" == "644" ]]
[[ "$(/usr/bin/stat -f '%g' "${PREFIX}/libexec/diskplan/${VERSION}/uninstall.sh")" == "$(/usr/bin/id -g)" ]]
[[ "$(readlink "${PREFIX}/bin/diskplan")" == "../libexec/diskplan/${VERSION}/diskplan" ]]
"${PREFIX}/bin/diskplan" --version-json | /usr/bin/grep -F "\"product_version\":\"${VERSION}\"" >/dev/null
"${PREFIX}/bin/diskplan" --handshake | /usr/bin/grep -F "handshake ok:" >/dev/null

# Reinstalling identical bytes is idempotent and does not disturb activation.
"${BUNDLE}/install.sh" --prefix "${PREFIX}" "${BUNDLE}"

# Timestamp churn is only a bounded rehash trigger and does not change the
# identity/access-policy/SHA-256 bundle proof.
readonly INSTALLED_VERSION="${PREFIX}/libexec/diskplan/${VERSION}"
/usr/bin/touch "${INSTALLED_VERSION}/protocol.json"
"${INSTALLED_VERSION}/activate.sh" --prefix "${PREFIX}" "${VERSION}" >/dev/null

# In-place content drift changes the SHA-256 proof even if the object identity
# and access policy remain unchanged. Restoring the exact bytes restores proof.
/bin/cp "${INSTALLED_VERSION}/protocol.json" "${TEST_ROOT}/protocol-original"
/usr/bin/printf '\n' >> "${INSTALLED_VERSION}/protocol.json"
if "${INSTALLED_VERSION}/activate.sh" --prefix "${PREFIX}" "${VERSION}" >/dev/null 2>&1; then
    echo "content-mutated installed metadata was accepted" >&2
    exit 1
fi
/bin/cat "${TEST_ROOT}/protocol-original" > "${INSTALLED_VERSION}/protocol.json"
"${INSTALLED_VERSION}/activate.sh" --prefix "${PREFIX}" "${VERSION}" >/dev/null

# Installed access-policy drift is distinct from content mismatch and fails closed.
/bin/chmod 0777 "${INSTALLED_VERSION}/diskplan-engine"
if "${INSTALLED_VERSION}/activate.sh" --prefix "${PREFIX}" "${VERSION}" >/dev/null 2>&1; then
    echo "world-writable installed engine was accepted" >&2
    exit 1
fi
/bin/chmod 0755 "${INSTALLED_VERSION}/diskplan-engine"
"${INSTALLED_VERSION}/activate.sh" --prefix "${PREFIX}" "${VERSION}" >/dev/null

# A second hard link violates the immutable one-owner artifact policy.
/bin/ln "${INSTALLED_VERSION}/protocol.json" "${TEST_ROOT}/protocol-hardlink"
if "${INSTALLED_VERSION}/activate.sh" --prefix "${PREFIX}" "${VERSION}" >/dev/null 2>&1; then
    echo "multiply-linked installed metadata was accepted" >&2
    exit 1
fi
/bin/rm "${TEST_ROOT}/protocol-hardlink"
"${INSTALLED_VERSION}/activate.sh" --prefix "${PREFIX}" "${VERSION}" >/dev/null

# Supplying more than one positional bundle is always a usage error, including
# when the first path is the install script's own bundle directory.
set +e
"${BUNDLE}/install.sh" --prefix "${PREFIX}" "${BUNDLE}" "${BUNDLE}" >/dev/null 2>&1
DUPLICATE_BUNDLE_STATUS=$?
set -e
[[ "${DUPLICATE_BUNDLE_STATUS}" == "64" ]]

# The archive is reproducible from the exact bundled inputs and source identity.
mkdir "${TEST_ROOT}/repack"
SOURCE_REVISION="$(/usr/bin/plutil -extract source_revision raw -o - "${BUNDLE}/manifest.json")"
readonly SOURCE_REVISION
python3 "${SCRIPT_DIR}/package_bundle.py" \
    --frontend "${BUNDLE}/diskplan" \
    --engine "${BUNDLE}/diskplan-engine" \
    --fs-helper "${BUNDLE}/diskplan-fs-helper" \
    --installer "${BUNDLE}/install.sh" \
    --activator "${BUNDLE}/activate.sh" \
    --uninstaller "${BUNDLE}/uninstall.sh" \
    --common-library "${BUNDLE}/release-common.sh" \
    --version-file "${BUNDLE}/VERSION" \
    --protocol-metadata "${BUNDLE}/protocol.json" \
    --asset-root "${REPO_ROOT}" \
    --bundle-contract "${REPO_ROOT}/release/bundle-contract.json" \
    --source-revision "${SOURCE_REVISION}" \
    --output-dir "${TEST_ROOT}/repack" \
    --require-macho-arm64 >/dev/null
REPACKED="${TEST_ROOT}/repack/$(basename "${ARCHIVE}")"
readonly REPACKED
[[ "$(/usr/bin/shasum -a 256 "${ARCHIVE}" | /usr/bin/awk '{print $1}')" == "$(/usr/bin/shasum -a 256 "${REPACKED}" | /usr/bin/awk '{print $1}')" ]]

# A checksum failure cannot change the selected installed version.
/bin/cp -R "${BUNDLE}" "${TEST_ROOT}/tampered"
/bin/chmod u+w "${TEST_ROOT}/tampered/protocol.json"
/usr/bin/printf '\n' >> "${TEST_ROOT}/tampered/protocol.json"
if "${TEST_ROOT}/tampered/install.sh" --prefix "${PREFIX}" "${TEST_ROOT}/tampered" >/dev/null 2>&1; then
    echo "tampered bundle was accepted" >&2
    exit 1
fi
[[ "$(readlink "${PREFIX}/bin/diskplan")" == "../libexec/diskplan/${VERSION}/diskplan" ]]

build_identity_binary() {
    local output="$1"
    local component="$2"
    local version="$3"
    local major="$4"
    local minor="$5"
    local source="${output}.c"
    /usr/bin/printf '%s\n' \
        '#include <stdio.h>' \
        '#include <string.h>' \
        'int main(int argc, char **argv) {' \
        '  if (argc == 2 && strcmp(argv[1], "--version-json") == 0) {' \
        "    puts(\"{\\\"component\\\":\\\"${component}\\\",\\\"product_version\\\":\\\"${version}\\\",\\\"protocol_major\\\":${major},\\\"protocol_minor\\\":${minor}}\");" \
        '    return 0;' \
        '  }' \
        '  return 64;' \
        '}' > "${source}"
    /usr/bin/xcrun clang -arch arm64 -mmacosx-version-min=14.0 -Os "${source}" -o "${output}"
}

build_fs_helper() {
    local output="$1"
    local version="$2"
    local major="$3"
    local minor="$4"
    /usr/bin/xcrun clang \
        -arch arm64 \
        -mmacosx-version-min=14.0 \
        -std=c11 \
        -Os \
        -Wall \
        -Wextra \
        -Werror \
        "-DDISKPLAN_PRODUCT_VERSION=\"${version}\"" \
        "-DDISKPLAN_PROTOCOL_MAJOR=${major}" \
        "-DDISKPLAN_PROTOCOL_MINOR=${minor}" \
        "${SCRIPT_DIR}/diskplan-fs-helper.c" \
        -o "${output}"
}

build_fs_helper_tests() {
    local output="$1"
    /usr/bin/xcrun clang \
        -arch arm64 \
        -mmacosx-version-min=14.0 \
        -std=c11 \
        -Os \
        -Wall \
        -Wextra \
        -Werror \
        "${SCRIPT_DIR}/diskplan-fs-helper-tests.c" \
        -o "${output}"
}

build_fs_helper_tests "${TEST_ROOT}/diskplan-fs-helper-tests"
mkdir "${TEST_ROOT}/fs-helper-test-root"
"${TEST_ROOT}/diskplan-fs-helper-tests" "${TEST_ROOT}/fs-helper-test-root"

make_fixture_bundle() {
    local version="$1"
    local major="$2"
    local output="$3"
    local fixture="${TEST_ROOT}/fixture-${version}-${major}"
    local minor
    mkdir "${fixture}"
    /usr/bin/printf '%s\n' "${version}" > "${fixture}/VERSION"
    /bin/cp "${REPO_ROOT}/release/protocol.json" "${fixture}/protocol.json"
    /usr/bin/plutil -replace protocol_major -integer "${major}" "${fixture}/protocol.json"
    minor="$(/usr/bin/plutil -extract protocol_minor raw -o - "${fixture}/protocol.json")"
    /usr/bin/sed \
        "s/\"compatibility_version\":\"protocol-1.3\"/\"compatibility_version\":\"protocol-${major}.${minor}\"/g" \
        "${REPO_ROOT}/release/bundle-contract.json" > "${fixture}/bundle-contract.json"
    build_identity_binary "${fixture}/diskplan" diskplan "${version}" "${major}" "${minor}"
    build_identity_binary "${fixture}/diskplan-engine" diskplan-engine "${version}" "${major}" "${minor}"
    build_fs_helper "${fixture}/diskplan-fs-helper" "${version}" "${major}" "${minor}"
    mkdir "${output}"
    python3 "${SCRIPT_DIR}/package_bundle.py" \
        --frontend "${fixture}/diskplan" \
        --engine "${fixture}/diskplan-engine" \
        --fs-helper "${fixture}/diskplan-fs-helper" \
        --installer "${SCRIPT_DIR}/install.sh" \
        --activator "${SCRIPT_DIR}/activate.sh" \
        --uninstaller "${SCRIPT_DIR}/uninstall.sh" \
        --common-library "${SCRIPT_DIR}/release-common.sh" \
        --version-file "${fixture}/VERSION" \
        --protocol-metadata "${fixture}/protocol.json" \
        --asset-root "${REPO_ROOT}" \
        --bundle-contract "${fixture}/bundle-contract.json" \
        --source-revision "0000000000000000000000000000000000000000" \
        --output-dir "${output}" \
        --require-macho-arm64 >/dev/null
    mkdir "${output}/extract"
    /usr/bin/tar -xzf "${output}/diskplan-${version}-macos-arm64.tar.gz" -C "${output}/extract"
}

# Upgrades publish a new immutable version and retain the old version for rollback.
make_fixture_bundle 0.2.0 1 "${TEST_ROOT}/upgrade"
readonly UPGRADE_BUNDLE="${TEST_ROOT}/upgrade/extract/diskplan-0.2.0-macos-arm64"
"${UPGRADE_BUNDLE}/install.sh" --prefix "${PREFIX}" "${UPGRADE_BUNDLE}"
[[ -d "${PREFIX}/libexec/diskplan/${VERSION}" && -d "${PREFIX}/libexec/diskplan/0.2.0" ]]
[[ "$(readlink "${PREFIX}/bin/diskplan")" == "../libexec/diskplan/0.2.0/diskplan" ]]
"${PREFIX}/libexec/diskplan/${VERSION}/activate.sh" --prefix "${PREFIX}" "${VERSION}"
[[ "$(readlink "${PREFIX}/bin/diskplan")" == "../libexec/diskplan/${VERSION}/diskplan" ]]

# A protocol-major mismatch is rejected before publication or activation.
make_fixture_bundle 0.3.0 2 "${TEST_ROOT}/mixed-major"
readonly MIXED_BUNDLE="${TEST_ROOT}/mixed-major/extract/diskplan-0.3.0-macos-arm64"
if "${MIXED_BUNDLE}/install.sh" --prefix "${PREFIX}" "${MIXED_BUNDLE}" >/dev/null 2>&1; then
    echo "mixed protocol-major bundle was accepted" >&2
    exit 1
fi
[[ ! -e "${PREFIX}/libexec/diskplan/0.3.0" ]]
[[ "$(readlink "${PREFIX}/bin/diskplan")" == "../libexec/diskplan/${VERSION}/diskplan" ]]

# The packager rejects frontend/engine version skew before producing an archive.
readonly SKEW_ROOT="${TEST_ROOT}/component-skew"
mkdir "${SKEW_ROOT}" "${SKEW_ROOT}/output"
/usr/bin/printf '%s\n' 0.4.0 > "${SKEW_ROOT}/VERSION"
/bin/cp "${REPO_ROOT}/release/protocol.json" "${SKEW_ROOT}/protocol.json"
SKEW_PROTOCOL_MAJOR="$(/usr/bin/plutil -extract protocol_major raw -o - "${SKEW_ROOT}/protocol.json")"
SKEW_PROTOCOL_MINOR="$(/usr/bin/plutil -extract protocol_minor raw -o - "${SKEW_ROOT}/protocol.json")"
readonly SKEW_PROTOCOL_MAJOR SKEW_PROTOCOL_MINOR
build_identity_binary "${SKEW_ROOT}/diskplan" diskplan 0.4.0 "${SKEW_PROTOCOL_MAJOR}" "${SKEW_PROTOCOL_MINOR}"
build_identity_binary "${SKEW_ROOT}/diskplan-engine" diskplan-engine 0.4.1 "${SKEW_PROTOCOL_MAJOR}" "${SKEW_PROTOCOL_MINOR}"
build_fs_helper "${SKEW_ROOT}/diskplan-fs-helper" 0.4.0 "${SKEW_PROTOCOL_MAJOR}" "${SKEW_PROTOCOL_MINOR}"
if python3 "${SCRIPT_DIR}/package_bundle.py" \
    --frontend "${SKEW_ROOT}/diskplan" \
    --engine "${SKEW_ROOT}/diskplan-engine" \
    --fs-helper "${SKEW_ROOT}/diskplan-fs-helper" \
    --installer "${SCRIPT_DIR}/install.sh" \
    --activator "${SCRIPT_DIR}/activate.sh" \
    --uninstaller "${SCRIPT_DIR}/uninstall.sh" \
    --common-library "${SCRIPT_DIR}/release-common.sh" \
    --version-file "${SKEW_ROOT}/VERSION" \
    --protocol-metadata "${SKEW_ROOT}/protocol.json" \
    --asset-root "${REPO_ROOT}" \
    --bundle-contract "${REPO_ROOT}/release/bundle-contract.json" \
    --source-revision "0000000000000000000000000000000000000000" \
    --output-dir "${SKEW_ROOT}/output" \
    --require-macho-arm64 >/dev/null 2>&1; then
    echo "component version skew was accepted" >&2
    exit 1
fi
[[ -z "$(/usr/bin/find "${SKEW_ROOT}/output" -mindepth 1 -maxdepth 1 -print -quit)" ]]

"${PREFIX}/libexec/diskplan/0.2.0/uninstall.sh" --prefix "${PREFIX}" 0.2.0
"${PREFIX}/libexec/diskplan/${VERSION}/uninstall.sh" --prefix "${PREFIX}" "${VERSION}"
[[ ! -e "${PREFIX}/bin/diskplan" && ! -e "${PREFIX}/libexec/diskplan/${VERSION}" ]]
[[ -d "${PREFIX}" && ! -e "${PREFIX}/bin" && ! -e "${PREFIX}/libexec" ]]
[[ ! -e "${PREFIX}/.diskplan-install.lock" ]]

echo "release package/install/upgrade/rollback/mixed-version tests passed"
