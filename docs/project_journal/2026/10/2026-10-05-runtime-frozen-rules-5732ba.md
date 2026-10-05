---
id: 20261005-5732ba
title: Runtime Frozen Rules Configuration
status: active
created: 2026-10-05
updated: 2026-10-05
branch: wip/effect-permission-integration
pr: https://github.com/Joey-Project/diskplan/pull/30
supersedes: []
superseded_by:
---

# Runtime Frozen Rules Configuration

## Contract And Ownership

Consume the accepted immutable Rules input model without introducing a Rules
path, client authority, or another IPC configuration channel. Primary author:
OpenAI Codex (GPT-6.1 Sol Extra High); GPT-6 Luna supplies narrow internal audits.
The parent [integration workstream](2026-10-05-effect-permission-integration-c6hbgn.md)
owns the complete Phase 0-6 delivery. This slice does not enable live protocol
1.7 or install a production session caller.

The new typed stageable configuration factory uses the compiled baseline via
`FrozenRulesPolicyInputs`. An absent overlay is valid. A rejected explicit
overlay retains baseline planning/recognition, but mutation eligibility is
derived only from `mutationConfiguration`, never its planning fallback.
`genericRemoveEnabled` requires that independent eligibility bit. Root discovery
remains the existing Foundation cache-directory selection and no-follow
descriptor identity check; no client path substitutes for that root.

The protected binding property is immutable policy-input intent and mutation
eligibility, not all filesystem metadata. The v2 configuration framing binds
the complete snapshot digest, the explicit eligibility bit, existing cache
root identity binding, adapter identity, effective Rules digest and effective
UID. This distinguishes absent, explicit default, rejected, missing and
unreadable overlay inputs even when planning uses the same baseline. The old
v1 fixture constructor remains source-compatible and does not acquire a new
permission. Provider observations are neither replaced nor promoted to local.

## Tasks

- [x] Add typed factory and complete configuration framing.
- [x] Preserve planning separately from mutation eligibility.
- [x] Add six bounded configuration-mechanism tests.
- [x] Validate formatting and targeted Swift tests on India.
- [x] Complete narrow fixed-source internal audit.
- [ ] Install production session callers after runtime/policy ownership freezes.
- [ ] Validate default compiled assets through the privately installed engine.

## India Evidence

Only `India-mac-mini-m4-hoteng` performed formatting, lint and tests. Staged
source tree: `4ce4ce479b6cca0684ab6d3461474bff021d792b`; source archive SHA-256:
`89ff9e8c70eb7a709cbe912f08a6fbff4841d6db2c209b7097a44c357dc7f714`.
The owner-private main task root is
`/private/tmp/diskplan-release-baseline-20261005.NlIPngd0`, UID 501 / mode 0700;
the new source subdirectory is `frozen-rules-runtime-source-v1`.

The task runner passed `bash -n` and shellcheck on India. India formatted both
changed Swift files, then strict lint passed. The package-lock-guarded command
`swift test --disable-automatic-resolution --scratch-path
/private/tmp/diskplan-release-baseline-20261005.NlIPngd0/swift-build --jobs 4
--filter frozenRuntimeRules` compiled successfully and executed six Swift
Testing tests, all passing. XCTest's separate zero-test count is not the selected
test result. The 900-second / 1-MiB supervisor exited 0 after 34,789 ms, verified
quiescent process-group termination and recorded log SHA-256:
`f2fb56824ce9c044d4009da719dd4194f63cc0bee7b09e7190b67e2d7ad0f228`.

Formatted files were copied back mechanically and both hashes matched India:

- `RuntimeStageableActionAuthority.swift`:
  `f599967c7de047341dd2ac5f2907ac4a4be724954d9d44e7ef6bdda7dd28b163`.
- `RuntimeFrozenRulesConfigurationTests.swift`:
  `45f618073d24f6508a4afe24d1965c734adc9fad10d7d0280c6095eaddb9dbc3`.
- `Package.resolved` remained
  `9c858ad2ab85466112834e09bfa270f01d0835e028244ee6a8e2e5b4ca677e98`.

The fixture constructor only tests immutable configuration framing. It does
not open its synthetic path, issue a scan session or current-evidence receipt,
prove Provider ownership, or authorize deletion. Required-baseline failure is
also tested at the actual production factory's early rejection boundary.
Existing user data was not mutated. Full-suite, installed-product and formal
review results remain separate gates.

A separate GPT-6 Luna read-only internal audit checked the two exact formatted
source hashes above and their necessary tracked callers. It found no concrete
invalid-fallback grant, missing binding field or scope expansion. It confirmed
that production callers remain uninstalled. This is not a formal named review
or an installed-platform acceptance receipt.
