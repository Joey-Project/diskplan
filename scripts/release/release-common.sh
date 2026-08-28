#!/bin/bash

diskplan_die() {
    echo "diskplan release: $*" >&2
    exit 1
}

diskplan_usage_error() {
    echo "$*" >&2
    exit 64
}

diskplan_validate_version() {
    local core='(0|[1-9][0-9]*)'
    local identifier='(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)'
    local prerelease="${identifier}(\\.${identifier})*"
    local build='[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*'
    [[ "$1" =~ ^${core}\.${core}\.${core}(-${prerelease})?(\+${build})?$ ]]
}

diskplan_resolve_prefix() {
    local requested="$1"
    if [[ "${requested}" != /* || "${requested}" == "/" || "${requested}" == *$'\n'* ]]; then
        diskplan_die "install prefix must be a single-line absolute path other than /"
    fi
    if [[ "${requested}" == *"//"* || "${requested}" == */./* || "${requested}" == */../* || "${requested}" == */. || "${requested}" == */.. ]]; then
        diskplan_die "install prefix must be lexically normalized"
    fi
    printf '%s\n' "${requested}"
}

diskplan_require_fs_helper() {
    DISKPLAN_FS_HELPER="${SCRIPT_DIR}/diskplan-fs-helper"
    [[ -f "${DISKPLAN_FS_HELPER}" && ! -L "${DISKPLAN_FS_HELPER}" && -x "${DISKPLAN_FS_HELPER}" ]] ||
        diskplan_die "native filesystem helper is missing or unsafe"
}

diskplan_bind_prefix() {
    local prefix="$1"
    local disposition="$2"
    case "${disposition}" in
        create)
            DISKPLAN_PREFIX_IDENTITY="$("${DISKPLAN_FS_HELPER}" prepare-prefix "${prefix}")" ||
                diskplan_die "cannot create and bind install prefix"
            ;;
        existing)
            DISKPLAN_PREFIX_IDENTITY="$("${DISKPLAN_FS_HELPER}" bind-prefix "${prefix}")" ||
                diskplan_die "cannot bind existing install prefix"
            ;;
        *) diskplan_die "internal prefix disposition is invalid" ;;
    esac
}

diskplan_plist_value() {
    local file="$1"
    local key="$2"
    /usr/bin/plutil -extract "${key}" raw -o - "${file}" 2>/dev/null
}

diskplan_sha256() {
    /usr/bin/shasum -a 256 "$1" | /usr/bin/awk '{print $1}'
}

diskplan_require_arm64_macho() {
    local path="$1"
    local arches
    arches="$(/usr/bin/lipo -archs "${path}" 2>/dev/null)" || diskplan_die "not a Mach-O binary: ${path##*/}"
    case " ${arches} " in
        *" arm64 "*) ;;
        *) diskplan_die "binary does not contain arm64 code: ${path##*/}" ;;
    esac
}

diskplan_expected_files() {
    printf '%s\n' \
        SHA256SUMS \
        VERSION \
        activate.sh \
        diskplan \
        diskplan-engine \
        diskplan-fs-helper \
        install.sh \
        manifest.json \
        protocol.json \
        release-common.sh \
        uninstall.sh
}

diskplan_verify_bundle() {
    local bundle="$1"
    [[ -d "${bundle}" && ! -L "${bundle}" ]] || diskplan_die "bundle must be a non-symlink directory"

    local expected_count=0
    local name
    while IFS= read -r name; do
        expected_count=$((expected_count + 1))
        [[ -f "${bundle}/${name}" && ! -L "${bundle}/${name}" ]] || diskplan_die "bundle file is missing or unsafe: ${name}"
    done < <(diskplan_expected_files)

    local actual_count
    actual_count="$(/usr/bin/find "${bundle}" -mindepth 1 -maxdepth 1 -print | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
    [[ "${actual_count}" == "${expected_count}" ]] || diskplan_die "bundle contains unexpected top-level entries"

    local version
    version="$(<"${bundle}/VERSION")"
    diskplan_validate_version "${version}" || diskplan_die "bundle VERSION is invalid"

    local bundle_format architecture manifest_version protocol_major protocol_minor
    local deployment_target release_gate manifest_capability
    bundle_format="$(diskplan_plist_value "${bundle}/manifest.json" bundle_format)" || diskplan_die "manifest bundle format is unreadable"
    architecture="$(diskplan_plist_value "${bundle}/manifest.json" architecture)" || diskplan_die "manifest architecture is unreadable"
    manifest_version="$(diskplan_plist_value "${bundle}/manifest.json" product_version)" || diskplan_die "manifest product version is unreadable"
    protocol_major="$(diskplan_plist_value "${bundle}/manifest.json" protocol_major)" || diskplan_die "manifest protocol major is unreadable"
    protocol_minor="$(diskplan_plist_value "${bundle}/manifest.json" protocol_minor)" || diskplan_die "manifest protocol minor is unreadable"
    deployment_target="$(diskplan_plist_value "${bundle}/manifest.json" deployment_target_macos)" || diskplan_die "manifest deployment target is unreadable"
    release_gate="$(diskplan_plist_value "${bundle}/manifest.json" release_gate_macos)" || diskplan_die "manifest release gate is unreadable"
    manifest_capability="$(diskplan_plist_value "${bundle}/manifest.json" required_capabilities.0)" || diskplan_die "manifest capability is unreadable"
    [[ "${bundle_format}" == "1" && "${architecture}" == "arm64" ]] || diskplan_die "unsupported bundle format or architecture"
    [[ "${manifest_version}" == "${version}" ]] || diskplan_die "manifest and VERSION disagree"
    [[ "${protocol_major}" == "1" ]] || diskplan_die "unsupported protocol major: ${protocol_major}"
    [[ "${deployment_target}" == "14.0" && "${release_gate}" == "26.0" && "${manifest_capability}" == "framing-v1" ]] || diskplan_die "manifest platform or capability contract is unsupported"
    if diskplan_plist_value "${bundle}/manifest.json" required_capabilities.1 >/dev/null; then
        diskplan_die "manifest contains unsupported additional required capabilities"
    fi

    local metadata_major metadata_minor metadata_architecture metadata_format required_capability
    local metadata_deployment metadata_release_gate
    metadata_major="$(diskplan_plist_value "${bundle}/protocol.json" protocol_major)" || diskplan_die "protocol metadata major is unreadable"
    metadata_minor="$(diskplan_plist_value "${bundle}/protocol.json" protocol_minor)" || diskplan_die "protocol metadata minor is unreadable"
    metadata_architecture="$(diskplan_plist_value "${bundle}/protocol.json" architecture)" || diskplan_die "protocol metadata architecture is unreadable"
    metadata_format="$(diskplan_plist_value "${bundle}/protocol.json" bundle_format)" || diskplan_die "protocol metadata format is unreadable"
    required_capability="$(diskplan_plist_value "${bundle}/protocol.json" required_capabilities.0)" || diskplan_die "required capability metadata is unreadable"
    metadata_deployment="$(diskplan_plist_value "${bundle}/protocol.json" deployment_target_macos)" || diskplan_die "protocol deployment target is unreadable"
    metadata_release_gate="$(diskplan_plist_value "${bundle}/protocol.json" release_gate_macos)" || diskplan_die "protocol release gate is unreadable"
    [[ "${metadata_major}" == "${protocol_major}" && "${metadata_minor}" == "${protocol_minor}" ]] || diskplan_die "manifest and protocol metadata disagree"
    [[ "${metadata_architecture}" == "arm64" && "${metadata_format}" == "1" && "${required_capability}" == "framing-v1" ]] || diskplan_die "protocol metadata is unsupported"
    [[ "${metadata_deployment}" == "${deployment_target}" && "${metadata_release_gate}" == "${release_gate}" ]] || diskplan_die "manifest and protocol platform metadata disagree"
    if diskplan_plist_value "${bundle}/protocol.json" required_capabilities.1 >/dev/null; then
        diskplan_die "protocol metadata contains unsupported additional capabilities"
    fi

    local expected_artifacts="|VERSION|activate.sh|diskplan|diskplan-engine|diskplan-fs-helper|install.sh|protocol.json|release-common.sh|uninstall.sh|"
    local artifact_seen="|"
    local artifact_index artifact_name artifact_sha artifact_size artifact_mode
    local artifact_actual_size expected_mode
    for artifact_index in 0 1 2 3 4 5 6 7 8; do
        artifact_name="$(diskplan_plist_value "${bundle}/manifest.json" "artifacts.${artifact_index}.name")" || diskplan_die "manifest artifact name is unreadable"
        artifact_sha="$(diskplan_plist_value "${bundle}/manifest.json" "artifacts.${artifact_index}.sha256")" || diskplan_die "manifest artifact checksum is unreadable"
        artifact_size="$(diskplan_plist_value "${bundle}/manifest.json" "artifacts.${artifact_index}.size")" || diskplan_die "manifest artifact size is unreadable"
        artifact_mode="$(diskplan_plist_value "${bundle}/manifest.json" "artifacts.${artifact_index}.mode")" || diskplan_die "manifest artifact mode is unreadable"
        [[ "${expected_artifacts}" == *"|${artifact_name}|"* && "${artifact_seen}" != *"|${artifact_name}|"* ]] || diskplan_die "manifest artifact set is invalid"
        [[ "${artifact_sha}" =~ ^[0-9a-f]{64}$ && "${artifact_size}" =~ ^[0-9]+$ && "${artifact_mode}" =~ ^0(644|755)$ ]] || diskplan_die "manifest artifact metadata is malformed"
        case "${artifact_name}" in
            diskplan|diskplan-engine|diskplan-fs-helper|install.sh|activate.sh|uninstall.sh) expected_mode="0755" ;;
            *) expected_mode="0644" ;;
        esac
        [[ "${artifact_mode}" == "${expected_mode}" ]] || diskplan_die "manifest artifact mode is invalid: ${artifact_name}"
        [[ "$(diskplan_sha256 "${bundle}/${artifact_name}")" == "${artifact_sha}" ]] || diskplan_die "manifest artifact checksum mismatch: ${artifact_name}"
        artifact_actual_size="$(/usr/bin/stat -f '%z' "${bundle}/${artifact_name}")"
        [[ "${artifact_actual_size}" == "${artifact_size}" ]] || diskplan_die "manifest artifact size mismatch: ${artifact_name}"
        artifact_seen="${artifact_seen}${artifact_name}|"
    done
    [[ "${artifact_seen}" == "${expected_artifacts}" ]] || diskplan_die "manifest does not cover the exact artifact set"
    if diskplan_plist_value "${bundle}/manifest.json" artifacts.9.name >/dev/null; then
        diskplan_die "manifest contains unexpected artifacts"
    fi

    local expected_sums="|"
    while IFS= read -r name; do
        [[ "${name}" == "SHA256SUMS" ]] || expected_sums="${expected_sums}${name}|"
    done < <(diskplan_expected_files)
    local seen="|"
    local line hash file actual
    local sum_count=0
    while IFS= read -r line || [[ -n "${line}" ]]; do
        if [[ ! "${line}" =~ ^([0-9a-f]{64})[[:space:]][[:space:]]([A-Za-z0-9._-]+)$ ]]; then
            diskplan_die "SHA256SUMS contains a malformed entry"
        fi
        hash="${BASH_REMATCH[1]}"
        file="${BASH_REMATCH[2]}"
        [[ "${expected_sums}" == *"|${file}|"* ]] || diskplan_die "SHA256SUMS names an unexpected file: ${file}"
        [[ "${seen}" != *"|${file}|"* ]] || diskplan_die "SHA256SUMS repeats a file: ${file}"
        actual="$(diskplan_sha256 "${bundle}/${file}")"
        [[ "${actual}" == "${hash}" ]] || diskplan_die "checksum mismatch: ${file}"
        seen="${seen}${file}|"
        sum_count=$((sum_count + 1))
    done < "${bundle}/SHA256SUMS"
    [[ "${sum_count}" == "$((expected_count - 1))" && "${seen}" == "${expected_sums}" ]] || diskplan_die "SHA256SUMS does not cover the exact bundle file set"

    diskplan_require_arm64_macho "${bundle}/diskplan"
    diskplan_require_arm64_macho "${bundle}/diskplan-engine"
    diskplan_require_arm64_macho "${bundle}/diskplan-fs-helper"
    [[ -x "${bundle}/diskplan" && -x "${bundle}/diskplan-engine" && -x "${bundle}/diskplan-fs-helper" ]] || diskplan_die "bundle binaries are not executable"
    [[ -x "${bundle}/install.sh" && -x "${bundle}/activate.sh" && -x "${bundle}/uninstall.sh" ]] || diskplan_die "bundle lifecycle scripts are not executable"

    local expected_frontend expected_engine expected_helper frontend_identity engine_identity helper_identity
    expected_frontend="{\"component\":\"diskplan\",\"product_version\":\"${version}\",\"protocol_major\":${protocol_major},\"protocol_minor\":${protocol_minor}}"
    expected_engine="{\"component\":\"diskplan-engine\",\"product_version\":\"${version}\",\"protocol_major\":${protocol_major},\"protocol_minor\":${protocol_minor}}"
    expected_helper="{\"component\":\"diskplan-fs-helper\",\"product_version\":\"${version}\",\"protocol_major\":${protocol_major},\"protocol_minor\":${protocol_minor},\"helper_abi\":1}"
    frontend_identity="$("${bundle}/diskplan" --version-json)" || diskplan_die "frontend identity probe failed"
    engine_identity="$("${bundle}/diskplan-engine" --version-json)" || diskplan_die "engine identity probe failed"
    helper_identity="$("${bundle}/diskplan-fs-helper" --version-json)" || diskplan_die "filesystem helper identity probe failed"
    [[ "${frontend_identity}" == "${expected_frontend}" ]] || diskplan_die "frontend identity does not match the bundle"
    [[ "${engine_identity}" == "${expected_engine}" ]] || diskplan_die "engine identity does not match the bundle"
    [[ "${helper_identity}" == "${expected_helper}" ]] || diskplan_die "filesystem helper identity does not match the bundle"

    # shellcheck disable=SC2034
    DISKPLAN_VERIFIED_VERSION="${version}"
    # shellcheck disable=SC2034
    DISKPLAN_VERIFIED_PROTOCOL_MAJOR="${protocol_major}"
    # shellcheck disable=SC2034
    DISKPLAN_VERIFIED_PROTOCOL_MINOR="${protocol_minor}"
}

diskplan_verify_managed_bundle() {
    local prefix="$1"
    local name="$2"
    local expected_proof="${3:--}"
    local before after bundle
    before="$("${DISKPLAN_FS_HELPER}" bundle-proof \
        "${prefix}" "${DISKPLAN_PREFIX_IDENTITY}" "${DISKPLAN_INSTALL_LOCK}" \
        "${name}" "${expected_proof}")" || diskplan_die "cannot bind managed bundle"
    bundle="${prefix}/libexec/diskplan/${name}"
    diskplan_verify_bundle "${bundle}"
    after="$("${DISKPLAN_FS_HELPER}" bundle-proof \
        "${prefix}" "${DISKPLAN_PREFIX_IDENTITY}" "${DISKPLAN_INSTALL_LOCK}" \
        "${name}" "${before}")" || diskplan_die "managed bundle changed during verification"
    [[ "${before}" == "${after}" ]] || diskplan_die "managed bundle identity proof changed"
    # shellcheck disable=SC2034 # Returned to lifecycle scripts after sourcing this library.
    DISKPLAN_VERIFIED_PROOF="${after}"
}

diskplan_atomic_activate() {
    local prefix="$1"
    local version="$2"
    local proof="$3"
    "${DISKPLAN_FS_HELPER}" activate \
        "${prefix}" "${DISKPLAN_PREFIX_IDENTITY}" "${DISKPLAN_INSTALL_LOCK}" \
        "${version}" "${proof}" || diskplan_die "cannot activate selected version"
}

diskplan_acquire_install_lock() {
    local prefix="$1"
    DISKPLAN_LOCK_PREFIX="${prefix}"
    DISKPLAN_INSTALL_LOCK="$("${DISKPLAN_FS_HELPER}" acquire-lock \
        "${prefix}" "${DISKPLAN_PREFIX_IDENTITY}" "$$")" ||
        diskplan_die "cannot acquire install lock"
}

diskplan_release_install_lock() {
    if [[ -n "${DISKPLAN_INSTALL_LOCK:-}" ]]; then
        if ! "${DISKPLAN_FS_HELPER}" release-lock \
            "${DISKPLAN_LOCK_PREFIX}" "${DISKPLAN_PREFIX_IDENTITY}" "${DISKPLAN_INSTALL_LOCK}"; then
            echo "diskplan release: failed to release install lock; the next operation will recover it if its owner is gone" >&2
        fi
        DISKPLAN_INSTALL_LOCK=""
        DISKPLAN_LOCK_PREFIX=""
    fi
}

diskplan_forget_install_lock() {
    DISKPLAN_INSTALL_LOCK=""
    DISKPLAN_LOCK_PREFIX=""
}

diskplan_cleanup_stage() {
    local prefix="$1"
    local name="$2"
    local proof="$3"
    "${DISKPLAN_FS_HELPER}" cleanup-stage \
        "${prefix}" "${DISKPLAN_PREFIX_IDENTITY}" "${DISKPLAN_INSTALL_LOCK}" \
        "${name}" "${proof}"
}
