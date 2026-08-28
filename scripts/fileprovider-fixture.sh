#!/usr/bin/env bash
set -euo pipefail

usage() {
  echo "usage: scripts/fileprovider-fixture.sh build-unsigned|build-signed|accept|recover <manifest>|recover-unpublished <run-id>" >&2
  exit 64
}

if (($# < 1)); then
  usage
fi

repo_root=$(git rev-parse --show-toplevel)
lifecycle_lock="/tmp/com.joeyteng.diskplan.fileprovider-fixture.$EUID.lifecycle.lock"
lifecycle_lock_fd=${DISKPLAN_FILEPROVIDER_LIFECYCLE_LOCK_FD:-}
lifecycle_capability_valid=0
if [[ $lifecycle_lock_fd == 9 ]] &&
  python3 "$repo_root/scripts/fileprovider-fixture-lifecycle-lock.py" \
    --lock "$lifecycle_lock" \
    --verify-held-fd "$lifecycle_lock_fd"
then
  exec 9>&-
  unset DISKPLAN_FILEPROVIDER_LIFECYCLE_LOCK_FD
  if python3 "$repo_root/scripts/fileprovider-fixture-lifecycle-lock.py" \
    --lock "$lifecycle_lock" \
    --verify-lock-busy
  then
    lifecycle_capability_valid=1
  fi
fi
if [[ $lifecycle_capability_valid != 1 ]]; then
  unset DISKPLAN_FILEPROVIDER_LIFECYCLE_LOCK_FD
  exec python3 "$repo_root/scripts/fileprovider-fixture-lifecycle-lock.py" \
    --lock "$lifecycle_lock" \
    -- "$0" "$@"
fi
project="$repo_root/fixtures/FileProviderAcceptance/DiskplanFileProviderFixture.xcodeproj"
derived="$repo_root/.codex-tmp/fileprovider-fixture-derived"
packages="$repo_root/.codex-tmp/fileprovider-fixture-packages"
app="$derived/Build/Products/Release/DiskplanFileProviderFixture.app"
host="$app/Contents/MacOS/DiskplanFileProviderFixture"
appex="$app/Contents/PlugIns/DiskplanFileProviderFixtureExtension.appex"
extension_bundle_id=com.joeyteng.diskplan.fileprovider-fixture.extension
team_id=XCTTZ89923

verify_signed_artifacts() {
  if [[ ! -x $host || ! -d $appex || -L $app || -L $host || -L $appex ]]; then
    echo '{"status":"blocked","reason":"trusted-fixture-artifact-unavailable"}' >&2
    return 1
  fi
  physical_app=$(realpath "$app")
  physical_host=$(realpath "$host")
  physical_appex=$(realpath "$appex")
  if [[ $physical_host != "$physical_app/Contents/MacOS/DiskplanFileProviderFixture" ||
    $physical_appex != "$physical_app/Contents/PlugIns/DiskplanFileProviderFixtureExtension.appex" ]]
  then
    echo '{"status":"blocked","reason":"trusted-fixture-artifact-not-physical"}' >&2
    return 1
  fi
  app=$physical_app
  host=$physical_host
  appex=$physical_appex
  if ! codesign --verify --strict "$app" || ! codesign --verify --strict "$appex"; then
    echo '{"status":"blocked","reason":"trusted-fixture-signature"}' >&2
    return 1
  fi
  app_identity=$(codesign -d --verbose=4 "$app" 2>&1)
  appex_identity=$(codesign -d --verbose=4 "$appex" 2>&1)
  if ! grep -Fxq 'Identifier=com.joeyteng.diskplan.fileprovider-fixture' <<<"$app_identity" ||
    ! grep -Fxq "TeamIdentifier=$team_id" <<<"$app_identity" ||
    ! grep -Fxq "Identifier=$extension_bundle_id" <<<"$appex_identity" ||
    ! grep -Fxq "TeamIdentifier=$team_id" <<<"$appex_identity"
  then
    echo '{"status":"blocked","reason":"trusted-fixture-identity"}' >&2
    return 1
  fi
}

verify_elected_extension() {
  python3 "$repo_root/scripts/fileprovider-fixture-registration.py" \
    --bundle-id "$extension_bundle_id" \
    --expected-path "$appex" \
    --state elected
}

verify_removed_extension() {
  python3 "$repo_root/scripts/fileprovider-fixture-registration.py" \
    --bundle-id "$extension_bundle_id" \
    --expected-path "$appex" \
    --state absent
}

register_extension() {
  "$host" mutation-begin --manifest "$manifest" --kind extension-add
  "$host" mutation-dispatched --manifest "$manifest" --kind extension-add
  set +e
  python3 "$repo_root/scripts/fileprovider-fixture-pluginkit.py" --action add --path "$appex"
  mutation_status=$?
  set -e
  if ((mutation_status == 0)); then
    "$host" mutation-complete --manifest "$manifest" --kind extension-add --outcome succeeded
  elif ((mutation_status == 65)); then
    "$host" mutation-complete --manifest "$manifest" --kind extension-add --outcome failed
    return "$mutation_status"
  else
    return "$mutation_status"
  fi
}

unregister_extension() {
  "$host" mutation-begin --manifest "$manifest" --kind extension-remove
  "$host" mutation-dispatched --manifest "$manifest" --kind extension-remove
  set +e
  python3 "$repo_root/scripts/fileprovider-fixture-pluginkit.py" --action remove --path "$appex"
  mutation_status=$?
  set -e
  if ((mutation_status == 0)); then
    "$host" mutation-complete --manifest "$manifest" --kind extension-remove --outcome succeeded
  elif ((mutation_status == 65)); then
    "$host" mutation-complete --manifest "$manifest" --kind extension-remove --outcome failed
    return "$mutation_status"
  else
    return "$mutation_status"
  fi
}

confirm_registered_extension() {
  "$host" mutation-confirm --manifest "$manifest" --kind extension-add --state present
}

confirm_removed_extension() {
  "$host" mutation-confirm --manifest "$manifest" --kind extension-remove --state absent
}

build_unsigned() {
  xcodebuild \
    -project "$project" \
    -scheme DiskplanFileProviderFixture \
    -configuration Release \
    -quiet \
    -derivedDataPath "$derived" \
    -clonedSourcePackagesDirPath "$packages" \
    CODE_SIGNING_ALLOWED=NO \
    build
}

build_signed() {
  if ! security find-identity -v -p codesigning | grep -Eq 'Apple Development:.*\(XCTTZ89923\)'; then
    echo '{"status":"blocked","reason":"signing-identity","team":"XCTTZ89923"}' >&2
    exit 78
  fi
  mkdir -p "$repo_root/.codex-tmp"
  build_log="$repo_root/.codex-tmp/fileprovider-fixture-signed-build.log"
  provisioning=()
  if [[ ${DISKPLAN_ALLOW_PROVISIONING_UPDATES:-0} == 1 ]]; then
    provisioning=(-allowProvisioningUpdates)
  fi
  if ! xcodebuild \
    -project "$project" \
    -scheme DiskplanFileProviderFixture \
    -configuration Release \
    -quiet \
    -derivedDataPath "$derived" \
    -clonedSourcePackagesDirPath "$packages" \
    -destination 'platform=macOS,arch=arm64' \
    "${provisioning[@]}" \
    build >"$build_log" 2>&1
  then
    if grep -Eqi 'requires a provisioning profile|No profiles for|provisioning profile.*Application[ -]Groups|does not support.*Application[ -]Groups' "$build_log"; then
      echo '{"status":"blocked","reason":"provisioning-profile","team":"XCTTZ89923","detail":"host and extension profiles must authorize group.com.joeyteng.diskplan.fileprovider-fixture"}' >&2
      tail -n 20 "$build_log" >&2
      exit 78
    fi
    echo '{"status":"failed","reason":"signed-build","log":".codex-tmp/fileprovider-fixture-signed-build.log"}' >&2
    tail -n 20 "$build_log" >&2
    exit 1
  fi
  verify_signed_artifacts
}

recover() {
  if (($# != 1)); then
    usage
  fi
  manifest=$1
  if [[ $manifest != /* || ! -f $manifest || -L $manifest ]]; then
    echo "recovery requires an absolute existing manifest path" >&2
    exit 64
  fi
  verify_signed_artifacts
  domain_status=$("$host" status --manifest "$manifest")
  manifest_app=$("$host" app-path --manifest "$manifest")
  manifest_appex=$("$host" extension-path --manifest "$manifest")
  if [[ $manifest_app != "$app" || $manifest_appex != "$appex" ]]; then
    echo '{"status":"blocked","reason":"manifest-build-identity-mismatch"}' >&2
    exit 1
  fi
  if [[ $domain_status == *'"status":"present"'* ]]; then
    verify_elected_extension
  fi
  echo "$domain_status"
  recovery_unresolved=0
  set +e
  "$host" teardown --manifest "$manifest"
  teardown_status=$?
  set -e
  if ((teardown_status == 75)); then
    recovery_unresolved=1
  elif ((teardown_status != 0)); then
    return "$teardown_status"
  fi

  set +e
  verify_removed_extension >/dev/null 2>&1
  extension_absent_status=$?
  set -e
  if ((extension_absent_status == 0)); then
    "$host" mutation-resolve-after-boot \
      --manifest "$manifest" \
      --kind extension-add \
      --state absent
  fi

  set +e
  unregister_extension
  unregister_status=$?
  set -e
  if ((unregister_status == 0)); then
    verify_removed_extension
    confirm_removed_extension
  elif ((unregister_status == 75)); then
    recovery_unresolved=1
  else
    return "$unregister_status"
  fi

  set +e
  "$host" cleanup --manifest "$manifest"
  cleanup_status=$?
  set -e
  if ((cleanup_status == 75)); then
    recovery_unresolved=1
  elif ((cleanup_status != 0)); then
    return "$cleanup_status"
  fi
  if ((recovery_unresolved != 0)); then
    echo '{"status":"blocked","reason":"unresolved_external_mutation"}' >&2
    return 75
  fi
}

recover_unpublished() {
  if (($# != 1)); then
    usage
  fi
  verify_signed_artifacts
  "$host" recover-unpublished --run-id "$1"
}

accept() {
  python3 "$repo_root/scripts/fileprovider-fixture-pending-preflight.py"
  build_signed
  run_id=$(uuidgen | tr '[:upper:]' '[:lower:]')
  manifest=$($host manifest-path --run-id "$run_id")
  complete=0
  report_recovery() {
    if ((complete == 0)); then
      retained_manifest=$manifest
      run_directory=$(dirname "$manifest")
      run_name=$(basename "$run_directory")
      sibling_manifest=$(dirname "$run_directory")/.manifest-recovery-"$run_name".json
      if [[ ! -f $retained_manifest && -f $sibling_manifest && ! -L $sibling_manifest ]]; then
        retained_manifest=$sibling_manifest
      fi
      if [[ -f $retained_manifest && ! -L $retained_manifest ]]; then
        echo "fixture did not complete; retained manifest: $retained_manifest" >&2
        echo "recover with: scripts/fileprovider-fixture.sh recover '$retained_manifest'" >&2
      else
        echo "fixture prepare did not publish a recoverable manifest for run: $run_id" >&2
        echo "recover with: scripts/fileprovider-fixture.sh recover-unpublished '$run_id'" >&2
      fi
    fi
  }
  trap report_recovery EXIT
  "$host" prepare \
    --run-id "$run_id" \
    --app-path "$app" \
    --extension-path "$appex"
  register_extension
  verify_elected_extension
  confirm_registered_extension
  "$host" setup --manifest "$manifest"
  "$host" oracle-begin --manifest "$manifest"
  "$host" probe --manifest "$manifest"
  "$host" probe --manifest "$manifest"
  "$host" oracle-health --manifest "$manifest"
  "$host" oracle-end --manifest "$manifest" --quiet-ms 2000 --timeout-ms 30000
  "$host" assert --manifest "$manifest"
  "$host" teardown --manifest "$manifest"
  unregister_extension
  verify_removed_extension
  confirm_removed_extension
  "$host" cleanup --manifest "$manifest"
  complete=1
  trap - EXIT
  echo '{"status":"accepted","fixture":"file-provider-probe-level","scanner_acceptance":"not-run"}'
}

command=$1
shift
case "$command" in
  build-unsigned)
    (($# == 0)) || usage
    build_unsigned
    ;;
  build-signed)
    (($# == 0)) || usage
    build_signed
    ;;
  accept)
    (($# == 0)) || usage
    accept
    ;;
  recover)
    recover "$@"
    ;;
  recover-unpublished)
    recover_unpublished "$@"
    ;;
  *)
    usage
    ;;
esac
