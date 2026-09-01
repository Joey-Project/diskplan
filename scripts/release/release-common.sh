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
        proto/diskplan/v1/ipc.proto \
        proto/fixtures/canonical-binary-v1/evidence.bin \
        proto/fixtures/canonical-binary-v1/evidence.json \
        proto/fixtures/canonical-binary-v1/evidence.sha256 \
        proto/fixtures/runtime-v1.4/README.md \
        proto/fixtures/runtime-v1.4/codex-scope-action.frames.hex \
        proto/fixtures/runtime-v1.4/empty-batch-dry-run.frames.hex \
        proto/fixtures/runtime-v1.4/fixtures.json \
        proto/fixtures/runtime-v1.4/force-action-execution.frames.hex \
        proto/fixtures/runtime-v1.4/git-evidence-action.frames.hex \
        proto/fixtures/runtime-v1.4/version-survivor-action.frames.hex \
        proto/fixtures/runtime-v1.5/README.md \
        proto/fixtures/runtime-v1.5/codex-scope-action.frames.hex \
        proto/fixtures/runtime-v1.5/empty-batch-dry-run.frames.hex \
        proto/fixtures/runtime-v1.5/fixtures.json \
        proto/fixtures/runtime-v1.5/force-action-execution.frames.hex \
        proto/fixtures/runtime-v1.5/git-evidence-action.frames.hex \
        proto/fixtures/runtime-v1.5/version-survivor-action.frames.hex \
        proto/fixtures/runtime-v1.6/README.md \
        proto/fixtures/runtime-v1.6/codex-scope-action.frames.hex \
        proto/fixtures/runtime-v1.6/empty-batch-dry-run.frames.hex \
        proto/fixtures/runtime-v1.6/execution-stream-failure.frames.hex \
        proto/fixtures/runtime-v1.6/fixtures.json \
        proto/fixtures/runtime-v1.6/force-action-execution.frames.hex \
        proto/fixtures/runtime-v1.6/git-evidence-action.frames.hex \
        proto/fixtures/runtime-v1.6/version-survivor-action.frames.hex \
        proto/fixtures/scan-stream-v1.3/README.md \
        proto/fixtures/scan-stream-v1.3/fixtures.json \
        proto/fixtures/scan-stream-v1.3/multi-finalized.frames.hex \
        proto/fixtures/scan-stream-v1.3/single-ready.frames.hex \
        proto/fixtures/scan-stream-v1.3/zero-ready.frames.hex \
        proto/toolchain.lock \
        protocol-version \
        protocol.json \
        release-common.sh \
        rules/builtin-v1.json \
        rules/user-policy-default-v1.json \
        runtime-capabilities.json \
        uninstall.sh
}

diskplan_expected_directories() {
    printf '%s\n' \
        proto \
        rules \
        proto/diskplan \
        proto/fixtures \
        proto/diskplan/v1 \
        proto/fixtures/canonical-binary-v1 \
        proto/fixtures/runtime-v1.4 \
        proto/fixtures/runtime-v1.5 \
        proto/fixtures/runtime-v1.6 \
        proto/fixtures/scan-stream-v1.3
}

diskplan_expected_artifact_contract() {
    printf '%s\n' \
        $'VERSION\t0644\tproduct-version\tproduct-v1' \
        $'activate.sh\t0755\tlifecycle-script\tlocal-install-v1' \
        $'diskplan\t0755\texecutable\tproduct-v1' \
        $'diskplan-engine\t0755\texecutable\tproduct-v1' \
        $'diskplan-fs-helper\t0755\texecutable\tfilesystem-helper-v1' \
        $'install.sh\t0755\tlifecycle-script\tlocal-install-v1' \
        $'proto/diskplan/v1/ipc.proto\t0644\tprotocol-schema\tprotocol-1.6' \
        $'proto/fixtures/canonical-binary-v1/evidence.bin\t0644\tcompatibility-fixture\tcanonical-binary-v1' \
        $'proto/fixtures/canonical-binary-v1/evidence.json\t0644\tcompatibility-fixture\tcanonical-binary-v1' \
        $'proto/fixtures/canonical-binary-v1/evidence.sha256\t0644\tcompatibility-fixture\tcanonical-binary-v1' \
        $'proto/fixtures/runtime-v1.4/README.md\t0644\tcompatibility-fixture-documentation\truntime-v1.4' \
        $'proto/fixtures/runtime-v1.4/codex-scope-action.frames.hex\t0644\tcompatibility-fixture\truntime-v1.4' \
        $'proto/fixtures/runtime-v1.4/empty-batch-dry-run.frames.hex\t0644\tcompatibility-fixture\truntime-v1.4' \
        $'proto/fixtures/runtime-v1.4/fixtures.json\t0644\tcompatibility-fixture\truntime-v1.4' \
        $'proto/fixtures/runtime-v1.4/force-action-execution.frames.hex\t0644\tcompatibility-fixture\truntime-v1.4' \
        $'proto/fixtures/runtime-v1.4/git-evidence-action.frames.hex\t0644\tcompatibility-fixture\truntime-v1.4' \
        $'proto/fixtures/runtime-v1.4/version-survivor-action.frames.hex\t0644\tcompatibility-fixture\truntime-v1.4' \
        $'proto/fixtures/runtime-v1.5/README.md\t0644\tcompatibility-fixture-documentation\truntime-v1.5' \
        $'proto/fixtures/runtime-v1.5/codex-scope-action.frames.hex\t0644\tcompatibility-fixture\truntime-v1.5' \
        $'proto/fixtures/runtime-v1.5/empty-batch-dry-run.frames.hex\t0644\tcompatibility-fixture\truntime-v1.5' \
        $'proto/fixtures/runtime-v1.5/fixtures.json\t0644\tcompatibility-fixture\truntime-v1.5' \
        $'proto/fixtures/runtime-v1.5/force-action-execution.frames.hex\t0644\tcompatibility-fixture\truntime-v1.5' \
        $'proto/fixtures/runtime-v1.5/git-evidence-action.frames.hex\t0644\tcompatibility-fixture\truntime-v1.5' \
        $'proto/fixtures/runtime-v1.5/version-survivor-action.frames.hex\t0644\tcompatibility-fixture\truntime-v1.5' \
        $'proto/fixtures/runtime-v1.6/README.md\t0644\tcompatibility-fixture-documentation\truntime-v1.6' \
        $'proto/fixtures/runtime-v1.6/codex-scope-action.frames.hex\t0644\tcompatibility-fixture\truntime-v1.6' \
        $'proto/fixtures/runtime-v1.6/empty-batch-dry-run.frames.hex\t0644\tcompatibility-fixture\truntime-v1.6' \
        $'proto/fixtures/runtime-v1.6/execution-stream-failure.frames.hex\t0644\tcompatibility-fixture\truntime-v1.6' \
        $'proto/fixtures/runtime-v1.6/fixtures.json\t0644\tcompatibility-fixture\truntime-v1.6' \
        $'proto/fixtures/runtime-v1.6/force-action-execution.frames.hex\t0644\tcompatibility-fixture\truntime-v1.6' \
        $'proto/fixtures/runtime-v1.6/git-evidence-action.frames.hex\t0644\tcompatibility-fixture\truntime-v1.6' \
        $'proto/fixtures/runtime-v1.6/version-survivor-action.frames.hex\t0644\tcompatibility-fixture\truntime-v1.6' \
        $'proto/fixtures/scan-stream-v1.3/README.md\t0644\tcompatibility-fixture-documentation\tscan-stream-v1.3' \
        $'proto/fixtures/scan-stream-v1.3/fixtures.json\t0644\tcompatibility-fixture\tscan-stream-v1.3' \
        $'proto/fixtures/scan-stream-v1.3/multi-finalized.frames.hex\t0644\tcompatibility-fixture\tscan-stream-v1.3' \
        $'proto/fixtures/scan-stream-v1.3/single-ready.frames.hex\t0644\tcompatibility-fixture\tscan-stream-v1.3' \
        $'proto/fixtures/scan-stream-v1.3/zero-ready.frames.hex\t0644\tcompatibility-fixture\tscan-stream-v1.3' \
        $'proto/toolchain.lock\t0644\tprotocol-toolchain-lock\tprotocol-toolchain-v1' \
        $'protocol-version\t0644\tprotocol-version\tprotocol-1.6' \
        $'protocol.json\t0644\tprotocol-metadata\tprotocol-1.6' \
        $'release-common.sh\t0644\tlifecycle-library\tlocal-install-v1' \
        $'rules/builtin-v1.json\t0644\tdeclarative-rules\tdiskplan.rules.v1' \
        $'rules/user-policy-default-v1.json\t0644\tdefault-policy\tdiskplan.user-policy.v1' \
        $'runtime-capabilities.json\t0644\truntime-capability-manifest\tdiskplan.runtime-capabilities.v1' \
        $'uninstall.sh\t0755\tlifecycle-script\tlocal-install-v1'
}

diskplan_verify_manifest_schema() {
    local manifest="$1"
    local manifest_key_count expected_manifest_key_count=13
    manifest_key_count="$(/usr/bin/plutil -convert xml1 -o - "${manifest}" | /usr/bin/grep -c '<key>')" ||
        diskplan_die "manifest schema cannot be enumerated"
    while IFS= read -r _; do
        expected_manifest_key_count=$((expected_manifest_key_count + 6))
    done < <(diskplan_expected_artifact_contract)
    [[ "${manifest_key_count}" == "${expected_manifest_key_count}" ]] ||
        diskplan_die "manifest contains missing or unknown fields"
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

    local expected_directory_count=0
    while IFS= read -r name; do
        expected_directory_count=$((expected_directory_count + 1))
        [[ -d "${bundle}/${name}" && ! -L "${bundle}/${name}" ]] || diskplan_die "bundle directory is missing or unsafe: ${name}"
    done < <(diskplan_expected_directories)

    local actual_count
    actual_count="$(/usr/bin/find "${bundle}" -mindepth 1 -print | /usr/bin/wc -l | /usr/bin/tr -d ' ')"
    [[ "${actual_count}" == "$((expected_count + expected_directory_count))" ]] || diskplan_die "bundle contains missing or unexpected entries"

    local version
    version="$(<"${bundle}/VERSION")"
    diskplan_validate_version "${version}" || diskplan_die "bundle VERSION is invalid"

    local capability_key_count
    diskplan_verify_manifest_schema "${bundle}/manifest.json"
    capability_key_count="$(/usr/bin/plutil -convert xml1 -o - "${bundle}/runtime-capabilities.json" | /usr/bin/grep -c '<key>')" || diskplan_die "runtime capability schema cannot be enumerated"
    [[ "${capability_key_count}" == "18" ]] || diskplan_die "runtime capability manifest contains missing or unknown fields"

    local bundle_format architecture manifest_version protocol_major protocol_minor manifest_schema
    local deployment_target release_gate manifest_capability
    bundle_format="$(diskplan_plist_value "${bundle}/manifest.json" bundle_format)" || diskplan_die "manifest bundle format is unreadable"
    architecture="$(diskplan_plist_value "${bundle}/manifest.json" architecture)" || diskplan_die "manifest architecture is unreadable"
    manifest_version="$(diskplan_plist_value "${bundle}/manifest.json" product_version)" || diskplan_die "manifest product version is unreadable"
    protocol_major="$(diskplan_plist_value "${bundle}/manifest.json" protocol_major)" || diskplan_die "manifest protocol major is unreadable"
    protocol_minor="$(diskplan_plist_value "${bundle}/manifest.json" protocol_minor)" || diskplan_die "manifest protocol minor is unreadable"
    deployment_target="$(diskplan_plist_value "${bundle}/manifest.json" deployment_target_macos)" || diskplan_die "manifest deployment target is unreadable"
    release_gate="$(diskplan_plist_value "${bundle}/manifest.json" release_gate_macos)" || diskplan_die "manifest release gate is unreadable"
    manifest_capability="$(diskplan_plist_value "${bundle}/manifest.json" required_capabilities.0)" || diskplan_die "manifest capability is unreadable"
    manifest_schema="$(diskplan_plist_value "${bundle}/manifest.json" manifest_schema_version)" || diskplan_die "manifest schema is unreadable"
    [[ "${bundle_format}" == "1" && "${architecture}" == "arm64" ]] || diskplan_die "unsupported bundle format or architecture"
    [[ "${manifest_version}" == "${version}" ]] || diskplan_die "manifest and VERSION disagree"
    [[ "${manifest_schema}" == "diskplan.bundle-manifest.v2" ]] || diskplan_die "manifest schema is unsupported"
    [[ "${protocol_major}" == "1" ]] || diskplan_die "unsupported protocol major: ${protocol_major}"
    [[ "${deployment_target}" == "14.0" && "${release_gate}" == "26.0" && "${manifest_capability}" == "framing-v1" ]] || diskplan_die "manifest platform or capability contract is unsupported"
    if diskplan_plist_value "${bundle}/manifest.json" required_capabilities.1 >/dev/null; then
        diskplan_die "manifest contains unsupported additional required capabilities"
    fi
    local expected_optional='audit-artifact-v1 execution-record-artifact-v1 history-artifact-v1 saved-plan-artifact-v1'
    local actual_optional=""
    local optional_index optional_value
    for optional_index in 0 1 2 3; do
        optional_value="$(diskplan_plist_value "${bundle}/manifest.json" "optional_capabilities.${optional_index}")" || diskplan_die "manifest optional capability is unreadable"
        actual_optional="${actual_optional}${actual_optional:+ }${optional_value}"
    done
    [[ "${actual_optional}" == "${expected_optional}" ]] || diskplan_die "manifest optional capability contract is unsupported"
    if diskplan_plist_value "${bundle}/manifest.json" optional_capabilities.4 >/dev/null; then
        diskplan_die "manifest contains unexpected optional capabilities"
    fi
    local expected_excluded='.codex-tmp/** .git/** docs/project_journal/INDEX.md rust/crates/diskplan-proto/src/generated.rs rust/target/** swift/.build/** swift/Sources/DiskplanProto/**'
    local actual_excluded=""
    local excluded_index excluded_value
    for excluded_index in 0 1 2 3 4 5 6; do
        excluded_value="$(diskplan_plist_value "${bundle}/manifest.json" "excluded_inputs.${excluded_index}")" || diskplan_die "manifest excluded input is unreadable"
        actual_excluded="${actual_excluded}${actual_excluded:+ }${excluded_value}"
    done
    [[ "${actual_excluded}" == "${expected_excluded}" ]] || diskplan_die "manifest excluded-input contract is unsupported"
    if diskplan_plist_value "${bundle}/manifest.json" excluded_inputs.7 >/dev/null; then
        diskplan_die "manifest contains unexpected excluded inputs"
    fi
    [[ "$(<"${bundle}/protocol-version")" == "${protocol_major}.${protocol_minor}" ]] || diskplan_die "protocol-version disagrees with manifest"

    local capability_id
    for optional_index in 0 1 2 3; do
        capability_id="$(diskplan_plist_value "${bundle}/runtime-capabilities.json" "capabilities.${optional_index}.id")" || diskplan_die "runtime capability ID is unreadable"
        [[ "${capability_id}" == "$(diskplan_plist_value "${bundle}/manifest.json" "optional_capabilities.${optional_index}")" ]] || diskplan_die "runtime capability and manifest disagree"
        [[ "$(diskplan_plist_value "${bundle}/runtime-capabilities.json" "capabilities.${optional_index}.default_enabled")" == "false" ]] || diskplan_die "runtime persistence capability must default off"
        [[ "$(diskplan_plist_value "${bundle}/runtime-capabilities.json" "capabilities.${optional_index}.kind")" == "optional-persistence" ]] || diskplan_die "runtime capability kind is unsupported"
        [[ "$(diskplan_plist_value "${bundle}/runtime-capabilities.json" "capabilities.${optional_index}.package_effect")" == "declaration-only" ]] || diskplan_die "packaging must not enable persistent output"
    done
    [[ "$(diskplan_plist_value "${bundle}/runtime-capabilities.json" schema_version)" == "diskplan.runtime-capabilities.v1" ]] || diskplan_die "runtime capability schema is unsupported"
    if diskplan_plist_value "${bundle}/runtime-capabilities.json" capabilities.4.id >/dev/null; then
        diskplan_die "runtime capability manifest contains unexpected entries"
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

    local artifact_index=0 artifact_name artifact_sha artifact_size artifact_mode artifact_role artifact_compatibility
    local artifact_actual_size expected_name expected_mode expected_role expected_compatibility
    while IFS=$'\t' read -r expected_name expected_mode expected_role expected_compatibility; do
        artifact_name="$(diskplan_plist_value "${bundle}/manifest.json" "artifacts.${artifact_index}.path")" || diskplan_die "manifest artifact path is unreadable"
        artifact_sha="$(diskplan_plist_value "${bundle}/manifest.json" "artifacts.${artifact_index}.sha256")" || diskplan_die "manifest artifact checksum is unreadable"
        artifact_size="$(diskplan_plist_value "${bundle}/manifest.json" "artifacts.${artifact_index}.size")" || diskplan_die "manifest artifact size is unreadable"
        artifact_mode="$(diskplan_plist_value "${bundle}/manifest.json" "artifacts.${artifact_index}.mode")" || diskplan_die "manifest artifact mode is unreadable"
        artifact_role="$(diskplan_plist_value "${bundle}/manifest.json" "artifacts.${artifact_index}.role")" || diskplan_die "manifest artifact role is unreadable"
        artifact_compatibility="$(diskplan_plist_value "${bundle}/manifest.json" "artifacts.${artifact_index}.compatibility_version")" || diskplan_die "manifest artifact compatibility version is unreadable"
        [[ "${artifact_name}" == "${expected_name}" ]] || diskplan_die "manifest artifact order or path is invalid"
        [[ "${artifact_sha}" =~ ^[0-9a-f]{64}$ && "${artifact_size}" =~ ^[0-9]+$ && "${artifact_mode}" =~ ^0(644|755)$ ]] || diskplan_die "manifest artifact metadata is malformed"
        [[ "${artifact_mode}" == "${expected_mode}" ]] || diskplan_die "manifest artifact mode is invalid: ${artifact_name}"
        [[ "${artifact_role}" == "${expected_role}" && "${artifact_compatibility}" == "${expected_compatibility}" ]] || diskplan_die "manifest artifact role or compatibility is invalid: ${artifact_name}"
        [[ "$(diskplan_sha256 "${bundle}/${artifact_name}")" == "${artifact_sha}" ]] || diskplan_die "manifest artifact checksum mismatch: ${artifact_name}"
        artifact_actual_size="$(/usr/bin/stat -f '%z' "${bundle}/${artifact_name}")"
        [[ "${artifact_actual_size}" == "${artifact_size}" ]] || diskplan_die "manifest artifact size mismatch: ${artifact_name}"
        artifact_index=$((artifact_index + 1))
    done < <(diskplan_expected_artifact_contract)
    if diskplan_plist_value "${bundle}/manifest.json" "artifacts.${artifact_index}.path" >/dev/null; then
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
        if [[ ! "${line}" =~ ^([0-9a-f]{64})[[:space:]][[:space:]]([A-Za-z0-9._/-]+)$ ]]; then
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
