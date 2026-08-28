#!/bin/bash

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/release-common.sh"

PREFIX="${HOME:?HOME must be set}/.local"
BUNDLE="${SCRIPT_DIR}"
while (( $# > 0 )); do
    case "$1" in
        --prefix)
            (( $# >= 2 )) || diskplan_usage_error "usage: install.sh [--prefix ABSOLUTE_PATH] [BUNDLE_DIR]"
            PREFIX="$2"
            shift 2
            ;;
        --*) diskplan_usage_error "unknown install option: $1" ;;
        *)
            [[ "${BUNDLE}" == "${SCRIPT_DIR}" ]] || diskplan_usage_error "only one bundle directory may be specified"
            BUNDLE="$1"
            shift
            ;;
    esac
done

PREFIX="$(diskplan_resolve_prefix "${PREFIX}")"
BUNDLE="$(cd "${BUNDLE}" && pwd -P)"
readonly PREFIX BUNDLE
diskplan_verify_bundle "${BUNDLE}"
readonly VERSION="${DISKPLAN_VERIFIED_VERSION}"
readonly INSTALL_ROOT="${PREFIX}/libexec/diskplan"
readonly DESTINATION="${INSTALL_ROOT}/${VERSION}"
mkdir -p -- "${INSTALL_ROOT}" "${PREFIX}/bin"

diskplan_acquire_install_lock "${PREFIX}"
STAGING=""
cleanup() {
    if [[ -n "${STAGING}" && -d "${STAGING}" ]]; then
        local staging_safe=1
        local name
        local actual_count
        actual_count="$(/usr/bin/find "${STAGING}" -mindepth 1 -maxdepth 1 -print | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
        [[ "${actual_count}" =~ ^[0-9]+$ && "${actual_count}" -le 10 ]] || staging_safe=0
        while IFS= read -r name; do
            if [[ -e "${STAGING}/${name}" || -L "${STAGING}/${name}" ]]; then
                [[ -f "${STAGING}/${name}" && ! -L "${STAGING}/${name}" ]] || staging_safe=0
            fi
        done < <(diskplan_expected_files)
        if (( staging_safe == 1 )); then
            while IFS= read -r name; do
                if [[ -f "${STAGING}/${name}" && ! -L "${STAGING}/${name}" ]]; then
                    rm -- "${STAGING}/${name}"
                fi
            done < <(diskplan_expected_files)
            rmdir -- "${STAGING}" 2>/dev/null || true
        else
            echo "diskplan release: retained unverified staging directory: ${STAGING}" >&2
        fi
    fi
    diskplan_release_install_lock
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

if [[ -e "${DESTINATION}" || -L "${DESTINATION}" ]]; then
    [[ -d "${DESTINATION}" && ! -L "${DESTINATION}" ]] || diskplan_die "installed version path is unsafe"
    diskplan_verify_bundle "${DESTINATION}"
    [[ "$(diskplan_sha256 "${DESTINATION}/manifest.json")" == "$(diskplan_sha256 "${BUNDLE}/manifest.json")" ]] || diskplan_die "version ${VERSION} is already installed with different content"
else
    STAGING="$(mktemp -d "${INSTALL_ROOT}/.install-${VERSION}.XXXXXX")"
    while IFS= read -r name; do
        case "${name}" in
            diskplan|diskplan-engine|install.sh|activate.sh|uninstall.sh)
                /usr/bin/install -m 0755 "${BUNDLE}/${name}" "${STAGING}/${name}"
                ;;
            *) /usr/bin/install -m 0644 "${BUNDLE}/${name}" "${STAGING}/${name}" ;;
        esac
    done < <(diskplan_expected_files)
    diskplan_verify_bundle "${STAGING}"
    mv -- "${STAGING}" "${DESTINATION}"
    STAGING=""
fi

diskplan_atomic_activate "${PREFIX}" "${VERSION}"
echo "Installed Diskplan ${VERSION} at ${DESTINATION}"
echo "Launcher: ${PREFIX}/bin/diskplan"
