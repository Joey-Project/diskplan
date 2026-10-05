#!/bin/bash

set -euo pipefail
umask 077

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
# shellcheck source=/dev/null
source "${SCRIPT_DIR}/release-common.sh"
diskplan_require_fs_helper

PREFIX="${HOME:?HOME must be set}/.local"
BUNDLE="${SCRIPT_DIR}"
BUNDLE_SET=0
while (( $# > 0 )); do
    case "$1" in
        --prefix)
            (( $# >= 2 )) || diskplan_usage_error "usage: install.sh [--prefix ABSOLUTE_PATH] [BUNDLE_DIR]"
            PREFIX="$2"
            shift 2
            ;;
        --*) diskplan_usage_error "unknown install option: $1" ;;
        *)
            (( BUNDLE_SET == 0 )) || diskplan_usage_error "only one bundle directory may be specified"
            BUNDLE="$1"
            BUNDLE_SET=1
            shift
            ;;
    esac
done

PREFIX="$(diskplan_resolve_prefix "${PREFIX}")"
readonly PREFIX BUNDLE
diskplan_bind_prefix "${PREFIX}" create
diskplan_acquire_install_lock "${PREFIX}"
STAGING_NAME=""
STAGING_PROOF=""
cleanup() {
    if [[ -n "${STAGING_NAME}" && -n "${STAGING_PROOF}" ]]; then
        if ! diskplan_cleanup_stage "${PREFIX}" "${STAGING_NAME}" "${STAGING_PROOF}"; then
            echo "diskplan release: retained staging directory after identity-safe cleanup failed: ${STAGING_NAME}" >&2
        fi
    fi
    diskplan_release_install_lock
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

STAGE_OUTPUT="$("${DISKPLAN_FS_HELPER}" stage-bundle \
    "${PREFIX}" "${DISKPLAN_PREFIX_IDENTITY}" "${DISKPLAN_INSTALL_LOCK}" "${BUNDLE}")" ||
    diskplan_die "cannot create a stable descriptor-bound bundle snapshot"
IFS=$'\t' read -r STAGING_NAME STAGING_PROOF <<< "${STAGE_OUTPUT}"
[[ -n "${STAGING_NAME}" && -n "${STAGING_PROOF}" ]] || diskplan_die "filesystem helper returned malformed staging identity"

diskplan_verify_managed_bundle "${PREFIX}" "${STAGING_NAME}" "${STAGING_PROOF}"
STAGING_PROOF="${DISKPLAN_VERIFIED_PROOF}"
readonly VERSION="${DISKPLAN_VERIFIED_VERSION}"
readonly DESTINATION="${PREFIX}/libexec/diskplan/${VERSION}"

set +e
PUBLISHED_PROOF="$("${DISKPLAN_FS_HELPER}" publish-version \
    "${PREFIX}" "${DISKPLAN_PREFIX_IDENTITY}" "${DISKPLAN_INSTALL_LOCK}" \
    "${STAGING_NAME}" "${STAGING_PROOF}" "${VERSION}")"
PUBLISH_STATUS=$?
set -e
case "${PUBLISH_STATUS}" in
    0)
        [[ "${PUBLISHED_PROOF}" == "${STAGING_PROOF}" ]] || diskplan_die "published bundle identity proof changed"
        STAGING_NAME=""
        STAGING_PROOF=""
        ;;
    17)
        diskplan_verify_managed_bundle "${PREFIX}" "${VERSION}" -
        INSTALLED_PROOF="${DISKPLAN_VERIFIED_PROOF}"
        INSTALLED_MANIFEST_SHA256="$(diskplan_sha256 "${DESTINATION}/manifest.json")"
        STAGED_MANIFEST_SHA256="$(diskplan_sha256 "${PREFIX}/libexec/diskplan/${STAGING_NAME}/manifest.json")"
        [[ "${INSTALLED_MANIFEST_SHA256}" == "${STAGED_MANIFEST_SHA256}" ]] ||
            diskplan_die "version ${VERSION} is already installed with different content"
        diskplan_cleanup_stage "${PREFIX}" "${STAGING_NAME}" "${STAGING_PROOF}" ||
            diskplan_die "cannot remove redundant descriptor-bound staging bundle"
        STAGING_NAME=""
        STAGING_PROOF=""
        PUBLISHED_PROOF="${INSTALLED_PROOF}"
        ;;
    *) diskplan_die "cannot publish version directory exclusively" ;;
esac

diskplan_atomic_activate "${PREFIX}" "${VERSION}" "${PUBLISHED_PROOF}"
echo "Installed Diskplan ${VERSION} at ${DESTINATION}"
echo "Launcher: ${PREFIX}/bin/diskplan"
