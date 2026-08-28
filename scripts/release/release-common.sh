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
    [[ "$1" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?(\+[0-9A-Za-z-]+(\.[0-9A-Za-z-]+)*)?$ ]]
}

diskplan_resolve_prefix() {
    local requested="$1"
    if [[ "${requested}" != /* || "${requested}" == "/" || "${requested}" == *$'\n'* ]]; then
        diskplan_die "install prefix must be a single-line absolute path other than /"
    fi
    if [[ "${requested}" == *"//"* || "${requested}" == */./* || "${requested}" == */../* || "${requested}" == */. || "${requested}" == */.. ]]; then
        diskplan_die "install prefix must be lexically normalized"
    fi
    mkdir -p -- "${requested}"
    local resolved
    resolved="$(cd "${requested}" && pwd -P)"
    if [[ "${resolved}" != "${requested}" ]]; then
        diskplan_die "install prefix must not traverse symbolic links"
    fi
    printf '%s\n' "${resolved}"
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

    local expected_artifacts="|VERSION|activate.sh|diskplan|diskplan-engine|install.sh|protocol.json|release-common.sh|uninstall.sh|"
    local artifact_seen="|"
    local artifact_index artifact_name artifact_sha artifact_size artifact_mode
    local artifact_actual_size expected_mode
    for artifact_index in 0 1 2 3 4 5 6 7; do
        artifact_name="$(diskplan_plist_value "${bundle}/manifest.json" "artifacts.${artifact_index}.name")" || diskplan_die "manifest artifact name is unreadable"
        artifact_sha="$(diskplan_plist_value "${bundle}/manifest.json" "artifacts.${artifact_index}.sha256")" || diskplan_die "manifest artifact checksum is unreadable"
        artifact_size="$(diskplan_plist_value "${bundle}/manifest.json" "artifacts.${artifact_index}.size")" || diskplan_die "manifest artifact size is unreadable"
        artifact_mode="$(diskplan_plist_value "${bundle}/manifest.json" "artifacts.${artifact_index}.mode")" || diskplan_die "manifest artifact mode is unreadable"
        [[ "${expected_artifacts}" == *"|${artifact_name}|"* && "${artifact_seen}" != *"|${artifact_name}|"* ]] || diskplan_die "manifest artifact set is invalid"
        [[ "${artifact_sha}" =~ ^[0-9a-f]{64}$ && "${artifact_size}" =~ ^[0-9]+$ && "${artifact_mode}" =~ ^0(644|755)$ ]] || diskplan_die "manifest artifact metadata is malformed"
        case "${artifact_name}" in
            diskplan|diskplan-engine|install.sh|activate.sh|uninstall.sh) expected_mode="0755" ;;
            *) expected_mode="0644" ;;
        esac
        [[ "${artifact_mode}" == "${expected_mode}" ]] || diskplan_die "manifest artifact mode is invalid: ${artifact_name}"
        [[ "$(diskplan_sha256 "${bundle}/${artifact_name}")" == "${artifact_sha}" ]] || diskplan_die "manifest artifact checksum mismatch: ${artifact_name}"
        artifact_actual_size="$(/usr/bin/stat -f '%z' "${bundle}/${artifact_name}")"
        [[ "${artifact_actual_size}" == "${artifact_size}" ]] || diskplan_die "manifest artifact size mismatch: ${artifact_name}"
        artifact_seen="${artifact_seen}${artifact_name}|"
    done
    [[ "${artifact_seen}" == "${expected_artifacts}" ]] || diskplan_die "manifest does not cover the exact artifact set"
    if diskplan_plist_value "${bundle}/manifest.json" artifacts.8.name >/dev/null; then
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
    [[ -x "${bundle}/diskplan" && -x "${bundle}/diskplan-engine" ]] || diskplan_die "bundle binaries are not executable"
    [[ -x "${bundle}/install.sh" && -x "${bundle}/activate.sh" && -x "${bundle}/uninstall.sh" ]] || diskplan_die "bundle lifecycle scripts are not executable"

    local expected_frontend expected_engine frontend_identity engine_identity
    expected_frontend="{\"component\":\"diskplan\",\"product_version\":\"${version}\",\"protocol_major\":${protocol_major},\"protocol_minor\":${protocol_minor}}"
    expected_engine="{\"component\":\"diskplan-engine\",\"product_version\":\"${version}\",\"protocol_major\":${protocol_major},\"protocol_minor\":${protocol_minor}}"
    frontend_identity="$("${bundle}/diskplan" --version-json)" || diskplan_die "frontend identity probe failed"
    engine_identity="$("${bundle}/diskplan-engine" --version-json)" || diskplan_die "engine identity probe failed"
    [[ "${frontend_identity}" == "${expected_frontend}" ]] || diskplan_die "frontend identity does not match the bundle"
    [[ "${engine_identity}" == "${expected_engine}" ]] || diskplan_die "engine identity does not match the bundle"

    # shellcheck disable=SC2034
    DISKPLAN_VERIFIED_VERSION="${version}"
    # shellcheck disable=SC2034
    DISKPLAN_VERIFIED_PROTOCOL_MAJOR="${protocol_major}"
    # shellcheck disable=SC2034
    DISKPLAN_VERIFIED_PROTOCOL_MINOR="${protocol_minor}"
}

diskplan_atomic_activate() {
    local prefix="$1"
    local version="$2"
    local bin_dir="${prefix}/bin"
    local target="../libexec/diskplan/${version}/diskplan"
    mkdir -p -- "${bin_dir}"
    if [[ -e "${bin_dir}/diskplan" && ! -L "${bin_dir}/diskplan" ]]; then
        diskplan_die "refusing to replace a non-symlink launcher"
    fi
    local temporary
    temporary="$(mktemp "${bin_dir}/.diskplan-link.XXXXXX")"
    rm -- "${temporary}"
    ln -s -- "${target}" "${temporary}"
    mv -f -- "${temporary}" "${bin_dir}/diskplan"
}

diskplan_acquire_install_lock() {
    local prefix="$1"
    local install_root="${prefix}/libexec/diskplan"
    mkdir -p -- "${install_root}"
    DISKPLAN_INSTALL_LOCK="${install_root}/.install.lock"
    if ! mkdir -- "${DISKPLAN_INSTALL_LOCK}" 2>/dev/null; then
        diskplan_die "another Diskplan install operation is active"
    fi
}

diskplan_release_install_lock() {
    if [[ -n "${DISKPLAN_INSTALL_LOCK:-}" ]]; then
        rmdir -- "${DISKPLAN_INSTALL_LOCK}" 2>/dev/null || true
        DISKPLAN_INSTALL_LOCK=""
    fi
}
