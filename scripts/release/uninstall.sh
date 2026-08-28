#!/bin/bash

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/release-common.sh"

PREFIX="${HOME:?HOME must be set}/.local"
VERSION=""
while (( $# > 0 )); do
    case "$1" in
        --prefix)
            (( $# >= 2 )) || diskplan_usage_error "usage: uninstall.sh [--prefix ABSOLUTE_PATH] VERSION"
            PREFIX="$2"
            shift 2
            ;;
        --*) diskplan_usage_error "unknown uninstall option: $1" ;;
        *)
            [[ -z "${VERSION}" ]] || diskplan_usage_error "only one version may be removed"
            VERSION="$1"
            shift
            ;;
    esac
done
[[ -n "${VERSION}" ]] || diskplan_usage_error "usage: uninstall.sh [--prefix ABSOLUTE_PATH] VERSION"
diskplan_validate_version "${VERSION}" || diskplan_die "version is invalid"
PREFIX="$(diskplan_resolve_prefix "${PREFIX}")"
readonly PREFIX VERSION
readonly DESTINATION="${PREFIX}/libexec/diskplan/${VERSION}"
diskplan_acquire_install_lock "${PREFIX}"
trap diskplan_release_install_lock EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
diskplan_verify_bundle "${DESTINATION}"
[[ "${DISKPLAN_VERIFIED_VERSION}" == "${VERSION}" ]] || diskplan_die "installed bundle version does not match its directory"

readonly LAUNCHER="${PREFIX}/bin/diskplan"
readonly EXPECTED_TARGET="../libexec/diskplan/${VERSION}/diskplan"
if [[ -L "${LAUNCHER}" && "$(readlink "${LAUNCHER}")" == "${EXPECTED_TARGET}" ]]; then
    rm -- "${LAUNCHER}"
elif [[ -e "${LAUNCHER}" && ! -L "${LAUNCHER}" ]]; then
    diskplan_die "refusing to replace a non-symlink launcher"
fi

while IFS= read -r name; do
    rm -- "${DESTINATION}/${name}"
done < <(diskplan_expected_files)
rmdir -- "${DESTINATION}"
rmdir -- "${PREFIX}/libexec/diskplan" 2>/dev/null || true
rmdir -- "${PREFIX}/libexec" 2>/dev/null || true
rmdir -- "${PREFIX}/bin" 2>/dev/null || true
echo "Uninstalled Diskplan ${VERSION}"
