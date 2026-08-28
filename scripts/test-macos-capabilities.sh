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

if [[ ${DISKPLAN_RUN_FILE_PROVIDER_FIXTURE:-0} != 1 ]]; then
  echo "file-provider-fixture: not-available (set DISKPLAN_RUN_FILE_PROVIDER_FIXTURE=1 on India-mac-mini-m4-hoteng)"
  exit 0
fi

scripts/fileprovider-fixture.sh accept
