#!/bin/bash

set -euo pipefail

if (( $# != 4 )); then
    echo "usage: scripts/ci/check-diff-range.sh <check|select> <pull_request|push|workflow_dispatch> <base-sha> <head-sha>" >&2
    exit 64
fi

readonly MODE="$1"
readonly EVENT_NAME="$2"
readonly BASE_SHA="$3"
readonly HEAD_SHA="$4"
readonly ZERO_SHA="0000000000000000000000000000000000000000"
readonly EMPTY_TREE_SHA="4b825dc642cb6eb9a060e54bf8d69288fbee4904"

if [[ "${MODE}" != "check" && "${MODE}" != "select" ]]; then
    echo "range mode must be check or select" >&2
    exit 64
fi

validate_sha() {
    local label="$1"
    local value="$2"
    if [[ ! "${value}" =~ ^[0-9a-f]{40}$ ]]; then
        echo "${label} must be an exact lowercase 40-character SHA" >&2
        exit 64
    fi
}

validate_sha "base SHA" "${BASE_SHA}"
validate_sha "head SHA" "${HEAD_SHA}"

case "${EVENT_NAME}" in
    pull_request)
        if [[ "${BASE_SHA}" == "${ZERO_SHA}" || "${HEAD_SHA}" == "${ZERO_SHA}" ]]; then
            echo "pull request SHAs must not be all-zero" >&2
            exit 64
        fi
        SELECTED_BASE_SHA="${BASE_SHA}"
        ;;
    push)
        if [[ "${HEAD_SHA}" == "${ZERO_SHA}" ]]; then
            echo "push head SHA must not be all-zero" >&2
            exit 64
        fi
        if [[ "${BASE_SHA}" == "${ZERO_SHA}" ]]; then
            SELECTED_BASE_SHA="${EMPTY_TREE_SHA}"
        else
            SELECTED_BASE_SHA="${BASE_SHA}"
        fi
        ;;
    workflow_dispatch)
        if [[ "${HEAD_SHA}" == "${ZERO_SHA}" || "${BASE_SHA}" != "${HEAD_SHA}" ]]; then
            echo "workflow dispatch requires one identical non-zero revision" >&2
            exit 64
        fi
        SELECTED_BASE_SHA="${EMPTY_TREE_SHA}"
        ;;
    *)
        echo "unsupported GitHub event: ${EVENT_NAME}" >&2
        exit 64
        ;;
esac
readonly SELECTED_BASE_SHA

if [[ "${MODE}" == "select" ]]; then
    printf '%s\n%s\n' "${SELECTED_BASE_SHA}" "${HEAD_SHA}"
    exit 0
fi

if ! git cat-file -e "${HEAD_SHA}^{commit}"; then
    echo "head commit is unavailable from the checked-out repository: ${HEAD_SHA}" >&2
    exit 1
fi
if [[ "${SELECTED_BASE_SHA}" != "${EMPTY_TREE_SHA}" ]] && ! git cat-file -e "${SELECTED_BASE_SHA}^{commit}"; then
    echo "base commit is unavailable from the checked-out repository: ${SELECTED_BASE_SHA}" >&2
    exit 1
fi

git diff --check "${SELECTED_BASE_SHA}" "${HEAD_SHA}" --
