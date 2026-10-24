---
id: 20261024-codex-gate-v2212
title: Codex Review Gate Consumer Event Upgrade
status: completed
created: 2026-10-24
updated: 2026-10-24
branch: wip/review-gate-stacked-retarget
pr:
supersedes: []
superseded_by:
---

# Codex Review Gate Consumer Event Upgrade

## Summary

- Synchronize the verifier and controller with the published v2.2.12 consumer workflows from source commit `0746d53`, including stacked pull requests and guarded edited events.
- Preserve the v2 action reference and existing runner, token, automatic-request, and limits configuration. No transport workflow or CODEOWNERS changes are included.
- Scope the repository `actionlint` compatibility exception to the unsupported `stacked` activity on `pull_request`; a negative-control test confirms another invalid activity still fails.

## Validation

- The focused actionlint negative-control test passes; `bash -n` and `shellcheck` pass for `scripts/ci/validate-repository.sh`.
- Both workflow files compare byte-for-byte with the canonical pair; project-journal validation and `git diff --check` pass.
- No remote activation or runtime execution is claimed.
