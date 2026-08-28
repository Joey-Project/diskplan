#!/bin/bash

set -euo pipefail

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

git diff --check
