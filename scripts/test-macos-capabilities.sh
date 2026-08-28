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

if [[ ${DISKPLAN_FILE_PROVIDER_FIXTURE_ROOT:-} == "" ]]; then
  echo "file-provider-fixture: not-available (set DISKPLAN_FILE_PROVIDER_FIXTURE_ROOT on India-mac-mini-m4-hoteng)"
  exit 0
fi

if [[ ! -d ${DISKPLAN_FILE_PROVIDER_FIXTURE_ROOT} ]]; then
  echo "file-provider-fixture: configured root is not a directory" >&2
  exit 1
fi

echo "file-provider-fixture: hook-present, controlled extension callback oracle not implemented"
exit 77
