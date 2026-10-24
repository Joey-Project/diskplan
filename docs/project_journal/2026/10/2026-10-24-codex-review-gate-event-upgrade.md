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

## Validation

- Both workflow files compare byte-for-byte with the canonical pair; project-journal validation and `git diff --check` pass.
- Installed `actionlint` rejects the canonical `stacked` pull-request activity type as unknown to its event table. `actionlint -ignore 'invalid activity type "stacked"'` passes the remaining workflow checks.
- No remote activation or runtime execution is claimed.
