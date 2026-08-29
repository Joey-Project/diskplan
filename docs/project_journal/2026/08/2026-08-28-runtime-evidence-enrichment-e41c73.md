---
id: 20260828-e41c73
title: Runtime Read-Only Evidence Enrichment
status: active
created: 2026-08-28
updated: 2026-08-28
branch: wip/runtime-evidence-enrichment
pr:
supersedes: []
superseded_by:
---

# Runtime Read-Only Evidence Enrichment

## Summary

- Extend production scan evidence without weakening the phase-one read-only or
  File Provider non-materialization contracts.
- Keep object identity, content stability, and access policy as separate protected
  properties instead of treating ordinary metadata churn as replacement.

## Task List

- [x] Add descriptor-bound ACL observations to access-policy evidence.
- [x] Add deterministic root and ancestor access-policy seals to scanner output.
- [x] Add an opt-in, held-descriptor, bounded content-digest collector seam whose
  default evidence remains `notRequested`.
- [x] Make content collection one-shot by closed request ID; keep descriptor,
  raw-slot, root, access-policy, and authoritative File Provider receipts inside
  the trusted registry and revalidate them before every read.
- [x] Add typed Git status, registration, held-metadata, nested-repository,
  submodule, and sparse-checkout evidence contracts.
- [x] Require Git command specifications to disable optional locks, fsmonitor,
  maintenance, credentials, prompts, lazy fetch, hooks, and ambient config.
- [x] Stream Git porcelain-v2 records into counters and one digest without
  retaining the path corpus; bind per-target and aggregate byte/record/deadline
  budgets.
- [x] Close the Git command vocabulary to fixed `/usr/bin/git` specs and keep
  production Git coverage unavailable until the shared supervised runner returns
  an exact authority receipt.
- [x] Add configured-scope provenance for Codex temporary cleanup and versioned
  artifacts; name-only matches remain report-only hints.
- [x] Require a bound active selector, complete version metadata, and known update
  state before publishing an authoritative survivor set.
- [x] Replace string-based adapter authority with internal configured-scope tokens
  bound to raw root, directory identity/access policy, helper capability, and
  selector namespace.
- [x] Make ancestor access seals provisional until their exact directory-close
  epoch receipts finalize successfully; close mismatch/failure remains typed.
- [x] Separate Darwin access-control flags from advisory/storage flag metadata.
- [x] Close follow-up review findings for owned content-descriptor lifetime, Git
  raw-registration/metadata digest binding, current adapter receipt matching, and
  pre-sort version budget admission.
- [x] Run focused scanner tests and the complete Swift gate after the shared
  dynamic-test slot is assigned.
- [ ] Complete fresh-context review and PR delivery.

## Protected Properties

- Object identity uses real device, file ID, and object type. Directory child-entry
  churn, timestamps, and link count do not enter the replacement predicate.
- Content stability is collected only for an exact plan-requested regular file from
  an already held target descriptor. Size and SHA-256 are protected; timestamp
  transitions cause a fresh-read requirement rather than a content-mutation claim.
- Access policy uses owner, group, mode, the exact documented Darwin
  immutable/append/data-vault/restricted/no-unlink flag mask, and a
  descriptor-bound serialized ACL digest. The ancestor seal hashes only those
  access-policy and identity fields plus the previous chain seal.

## Current State

- The seven fresh safety findings are implemented in source and negative-test
  fixtures. Strict Swift formatting, parser validation, project-journal
  validation, and `git diff --check` pass on the current static revision.
- The focused evidence gate passed 6 tests, covering provider/content reads,
  descriptor ownership, close epochs, Git metadata cross-join, configured version
  survivors, and adapter budgets. The complete serial Swift gate then passed all
  361 tests with `--no-parallel -j 1` on Apple Swift 6.3.3 targeting arm64 macOS
  26. Neither bounded run reached its wall-clock or retained-log limit.
- The Git layer defines closed read-only command specs, session budgets, streamed
  parsing, and critical held-object cross-join validation. It deliberately has no
  caller-assembled output API: until the existing shared supervisor is connected
  and returns executable/spec/environment/cwd/binding/deadline/output receipts,
  production Git evidence is typed unavailable/report-only.
- Follow-up review identified four static gaps. Content receipts now transfer an
  internal RAII descriptor owner and retain durable one-shot request tombstones,
  Git cross-join has positive and single-field digest fixtures, adapter builders
  revalidate current raw-root/helper/selector receipts, and version lists pass
  count plus checked byte admission before any sort, map, or set allocation.
- The third narrow fresh-context review found no P0--P3 issues in the stabilized
  static snapshot. It specifically rechecked selector token storage and digest
  binding, configured-versus-bound selector equality, durable content request
  replay rejection, bounded authority surfaces, overflow handling, and the
  read-only/no-materialization contract. The reviewer ran only
  `git diff --check`; no build or dynamic test was implied.

## Next Steps

1. Connect the already-reviewed shared subprocess supervisor before allowing Git
   evidence to become authoritative; otherwise keep it typed unavailable.
2. Complete PR delivery after the parent workstream integrates this slice.

## Evidence

- Accepted architecture: `docs/design/accepted-plan.md`.
- Scanner contract: `docs/design/scanner-core.md`.
- Policy evidence contract: `docs/design/policy-core.md`.
