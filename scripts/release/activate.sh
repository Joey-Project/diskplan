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
            (( $# >= 2 )) || diskplan_usage_error "usage: activate.sh [--prefix ABSOLUTE_PATH] VERSION"
            PREFIX="$2"
            shift 2
            ;;
        --*) diskplan_usage_error "unknown activate option: $1" ;;
        *)
            [[ -z "${VERSION}" ]] || diskplan_usage_error "only one version may be activated"
            VERSION="$1"
            shift
            ;;
    esac
done
[[ -n "${VERSION}" ]] || diskplan_usage_error "usage: activate.sh [--prefix ABSOLUTE_PATH] VERSION"
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
diskplan_atomic_activate "${PREFIX}" "${VERSION}"
echo "Activated Diskplan ${VERSION}"
