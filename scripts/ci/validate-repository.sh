#!/bin/bash

set -euo pipefail

if (( $# != 3 )); then
    echo "usage: scripts/ci/validate-repository.sh <pull_request|push|workflow_dispatch> <base-sha> <head-sha>" >&2
    exit 64
fi

readonly EVENT_NAME="$1"
readonly BASE_SHA="$2"
readonly HEAD_SHA="$3"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
readonly SCRIPT_DIR
REPO_ROOT="$(cd "${SCRIPT_DIR}/../.." && pwd)"
readonly REPO_ROOT

cd "${REPO_ROOT}"
actionlint -shellcheck shellcheck

while IFS= read -r script; do
    bash -n "${script}"
    shellcheck "${script}"
done < <(git ls-files --cached --others --exclude-standard '*.sh')

scripts/ci/check-diff-range.sh check "${EVENT_NAME}" "${BASE_SHA}" "${HEAD_SHA}"
