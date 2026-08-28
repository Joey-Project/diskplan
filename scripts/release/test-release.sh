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

readonly PREFIX="${TEST_ROOT}/prefix"

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
[[ "$(readlink "${PREFIX}/bin/diskplan")" == "../libexec/diskplan/${VERSION}/diskplan" ]]
"${PREFIX}/bin/diskplan" --version-json | /usr/bin/grep -F "\"product_version\":\"${VERSION}\"" >/dev/null
"${PREFIX}/bin/diskplan" --handshake | /usr/bin/grep -F "handshake ok:" >/dev/null

# Reinstalling identical bytes is idempotent and does not disturb activation.
"${BUNDLE}/install.sh" --prefix "${PREFIX}" "${BUNDLE}"

# The archive is reproducible from the exact bundled inputs and source identity.
mkdir "${TEST_ROOT}/repack"
SOURCE_REVISION="$(/usr/bin/plutil -extract source_revision raw -o - "${BUNDLE}/manifest.json")"
readonly SOURCE_REVISION
python3 "${SCRIPT_DIR}/package_bundle.py" \
    --frontend "${BUNDLE}/diskplan" \
    --engine "${BUNDLE}/diskplan-engine" \
    --installer "${BUNDLE}/install.sh" \
    --activator "${BUNDLE}/activate.sh" \
    --uninstaller "${BUNDLE}/uninstall.sh" \
    --common-library "${BUNDLE}/release-common.sh" \
    --version-file "${BUNDLE}/VERSION" \
    --protocol-metadata "${BUNDLE}/protocol.json" \
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
    /usr/bin/xcrun clang -arch arm64 -Os "${source}" -o "${output}"
}

make_fixture_bundle() {
    local version="$1"
    local major="$2"
    local output="$3"
    local fixture="${TEST_ROOT}/fixture-${version}-${major}"
    mkdir "${fixture}"
    /usr/bin/printf '%s\n' "${version}" > "${fixture}/VERSION"
    /bin/cp "${REPO_ROOT}/release/protocol.json" "${fixture}/protocol.json"
    /usr/bin/plutil -replace protocol_major -integer "${major}" "${fixture}/protocol.json"
    build_identity_binary "${fixture}/diskplan" diskplan "${version}" "${major}" 2
    build_identity_binary "${fixture}/diskplan-engine" diskplan-engine "${version}" "${major}" 2
    mkdir "${output}"
    python3 "${SCRIPT_DIR}/package_bundle.py" \
        --frontend "${fixture}/diskplan" \
        --engine "${fixture}/diskplan-engine" \
        --installer "${SCRIPT_DIR}/install.sh" \
        --activator "${SCRIPT_DIR}/activate.sh" \
        --uninstaller "${SCRIPT_DIR}/uninstall.sh" \
        --common-library "${SCRIPT_DIR}/release-common.sh" \
        --version-file "${fixture}/VERSION" \
        --protocol-metadata "${fixture}/protocol.json" \
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
build_identity_binary "${SKEW_ROOT}/diskplan" diskplan 0.4.0 1 2
build_identity_binary "${SKEW_ROOT}/diskplan-engine" diskplan-engine 0.4.1 1 2
if python3 "${SCRIPT_DIR}/package_bundle.py" \
    --frontend "${SKEW_ROOT}/diskplan" \
    --engine "${SKEW_ROOT}/diskplan-engine" \
    --installer "${SCRIPT_DIR}/install.sh" \
    --activator "${SCRIPT_DIR}/activate.sh" \
    --uninstaller "${SCRIPT_DIR}/uninstall.sh" \
    --common-library "${SCRIPT_DIR}/release-common.sh" \
    --version-file "${SKEW_ROOT}/VERSION" \
    --protocol-metadata "${SKEW_ROOT}/protocol.json" \
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

echo "release package/install/upgrade/rollback/mixed-version tests passed"
