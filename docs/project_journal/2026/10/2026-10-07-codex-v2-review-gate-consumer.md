---
id: 20261007-codex-v2-review-gate-consumer
title: Install v2 Codex review-gate consumer workflows
status: completed
created: 2026-10-07
updated: 2026-10-07
branch: wip/codex-review-gate-v218-consumer-install-20261007
pr:
supersedes: []
superseded_by:
---

# Install v2 Codex review-gate consumer workflows

## Summary

- Install the canonical v2 verifier and controller workflows in diskplan, without changing the existing application CI gate or organization policy.

## Current State

- The verifier and controller match the canonical consumer templates byte-for-byte and call `JoeyTeng/codex-review-gate-action@v2`.
- This installs the consumer workflows only. Custom-property activation remains a separate owner action; this change does not claim that the gate is active or required.
- No CODEOWNERS file, repository ruleset, organization rule, or custom property was added or changed.

## Next Steps

- The repository owner may update the custom property separately after the workflow installation is merged.

## Evidence

- Canonical templates at source commit `02bc718cd63724b991255ab5a8b9504aca597556`: `templates/codex-gated-repo/.github/workflows/codex-review-gate.yml` and `templates/codex-gated-repo/.github/workflows/codex-review-gate-controller.yml`.
- Published compatible action release: [v2.1.8](https://github.com/JoeyTeng/codex-review-gate-action/releases/tag/v2.1.8)
