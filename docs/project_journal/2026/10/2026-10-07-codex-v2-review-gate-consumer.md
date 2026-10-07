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

- Install the canonical v2 verifier and controller workflows in diskplan, and document their narrow first-party floating-major exception without changing GitHub branch or organization settings.

## Current State

- The verifier and controller match the canonical consumer templates at source commit `02bc718cd63724b991255ab5a8b9504aca597556` byte-for-byte and use the controlled first-party `JoeyTeng/codex-review-gate-action@v2` floating-major exception documented in `.github/CI.md`. This intentionally receives compatible v2 releases automatically. The audited v2.1.8 commit `299c0fde3cdd921e8d756f792edc056afb0f2ec9` is release provenance, not a binding runtime pin.
- This installs the consumer workflows only. Custom-property activation remains a separate owner action; this change does not claim that the gate is active or required.
- No CODEOWNERS file, GitHub branch-protection rule, repository ruleset, organization setting, or custom property was added or changed.

## Next Steps

- The repository owner may update the custom property separately after the workflow installation is merged.

## Evidence

- Canonical templates at source commit `02bc718cd63724b991255ab5a8b9504aca597556`: `templates/codex-gated-repo/.github/workflows/codex-review-gate.yml` and `templates/codex-gated-repo/.github/workflows/codex-review-gate-controller.yml`.
- Published compatible action release: [v2.1.8](https://github.com/JoeyTeng/codex-review-gate-action/releases/tag/v2.1.8)
