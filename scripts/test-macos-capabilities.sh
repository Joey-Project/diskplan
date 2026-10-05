#!/usr/bin/env bash
set -euo pipefail

if (($# != 0)); then
  echo "usage: scripts/test-macos-capabilities.sh" >&2
  exit 64
fi

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

swift test --filter DiskplanMacOSTests
swift run diskplan-macos-probe --self-test

fixture_hook_present=0

if [[ ${DISKPLAN_RUN_FILE_PROVIDER_FIXTURE:-0} == 1 ]]; then
  scripts/fileprovider-fixture.sh accept
else
  echo "file-provider-fixture: not-available (set DISKPLAN_RUN_FILE_PROVIDER_FIXTURE=1 on India-mac-mini-m4-hoteng)"
fi

if [[ ${DISKPLAN_APFS_VOLUME_GROUP_FIXTURE_ROOT:-} == "" ]]; then
  echo "apfs-volume-group-fixture: not-available (set DISKPLAN_APFS_VOLUME_GROUP_FIXTURE_ROOT on India-mac-mini-m4-hoteng)"
elif [[ ! -d ${DISKPLAN_APFS_VOLUME_GROUP_FIXTURE_ROOT} ]]; then
  echo "apfs-volume-group-fixture: configured root is not a directory" >&2
  exit 1
else
  echo "apfs-volume-group-fixture: hook-present, cross-volume real-device oracle not implemented"
  fixture_hook_present=1
fi

if ((fixture_hook_present)); then
  exit 77
fi
