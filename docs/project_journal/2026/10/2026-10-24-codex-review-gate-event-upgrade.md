---
id: 20261024-codex-gate-v2212
title: Codex Review Gate v2.2.13 Consumer Event Upgrade
status: completed
created: 2026-10-24
updated: 2026-10-24
branch: wip/review-gate-stacked-retarget
pr: https://github.com/Joey-Project/diskplan/pull/33
supersedes: []
superseded_by:
---

# Codex Review Gate Consumer Event Upgrade

## Summary

- Synchronize the verifier and controller with the canonical v2.2.13 consumer pair, replacing the v2.2.12 ignored-edit bypass.
- All six configured pull-request activity types now use the same verifier job and stable run title; edited events are not skipped. Concurrency stays scoped to one cancellable group per pull request.
- Preserve the floating `@v2` action reference and existing runner, token, automatic-request, limits, and permission configuration. No transport workflow or CODEOWNERS changes are included.
- The existing actionlint compatibility exception for `stacked` on `pull_request` remains narrow and unchanged; the negative control still guards other invalid activities.

## Validation

- Both workflow files match the canonical pair byte-for-byte; exported workflow validators, project-journal validation, and `git diff --check` pass.
- Installed actionlint 1.7.12 reports only `invalid activity type "stacked" for "pull_request" Webhook event.`; the same schema diagnostic applies to the canonical verifier.
- Product tests and remote CI were not rerun for this consumer-only update. No remote activation or runtime execution is claimed.

## Earlier Runtime Canary

- Before this YAML checkpoint, [verifier run 40105726361, attempt 2](https://github.com/Joey-Project/diskplan/actions/runs/40105726361) at head `618aac150e10e834d2ef1a7ab3401c992bfc230d` loaded Action v2.2.13 (`e965263162351e61ceb8cecc725f6327eab3a8c3`) and passed using existing clean comment `6385025990`, without a new request or commit.
- That observation demonstrates the runtime recovery only. It does not supply CI or review evidence for the newer consumer-YAML checkpoint.
