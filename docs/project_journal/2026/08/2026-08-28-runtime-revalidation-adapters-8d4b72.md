---
id: 20260828-8d4b72
title: Runtime Revalidation And Typed Adapters
status: active
created: 2026-08-28
updated: 2026-08-29
branch: wip/runtime-revalidation-adapters
pr:
supersedes: []
superseded_by:
---

# Runtime Revalidation And Typed Adapters

## Summary

- Connect Phase 4/5 to descriptor-bound live evidence without creating a second access, ACL, or
  File Provider authority.
- Make Swift emit the exact command/native preview rendered by shell and Rust frontends.
- Enable typed Codex-temporary and versioned-artifact removal with exact scope binding.

## Current State

- `AuthoritativeCommandPreview` is derived only from validated engine actions. Command previews
  contain raw executable/argv/working-directory bytes plus force and path-race facts; Git and APFS
  compound operations remain typed native previews instead of fabricated shell commands.
- Dry-run and apply review receive the same deterministic preview list. The capability registry
  binds that complete list, so a frontend cannot edit argv or hide a force/path-race warning and
  still authorize apply.
- Codex-temporary and versioned-artifact actions are explicit typed routes to the accepted v1
  ordinary `/bin/rm` implementation. Codex scope must exactly match the raw suffix beneath
  `.codex-tmp`; versioned artifacts must end in the bound `artifactKind/version` components.
  Neither route can silently fall back from an unsupported specialized contract.
- `requiresForceWithWarning` is now part of both specialized policy contracts, canonical action
  binding, command preview, apply review, and runtime operation. A normal failure never upgrades
  itself to `-f`; every forced removal is displayed at least at the review tier.
- A generic action selecting content stability receives a capability-free report-only preview in
  v1. Dry-run preserves its evidence and warnings, while apply preparation cannot advertise an
  `rm` command or mint a capability for an unsupported mutation.
- Versioned-artifact scope binds the exact raw parent namespace and version leaf. Runtime policy
  derives both from the recognized path instead of substituting a classification label.
- Phase 5 uses the accepted report-only firewall for dirty Git worktrees. A discard action and a
  remove action whose contract requires discard are policy-blocked, cannot be waiver-unlocked,
  emit capability-free report-only previews, and are rejected by both the production router and
  the Git quarantine adapter before Git can run. Clean descriptor-bound quarantine removal remains
  executable.
- The evidence-authority baseline is now integrated. `DiskplanScan.RuntimeEvidenceSession`
  strongly owns the content authority and issues one active non-replayable lease at a time for
  whole-plan, per-unit JIT, and final-descriptor captures. Finish, epoch advance, close, and
  cancellation drain pending one-shot descriptor receipts.
- `RuntimeRevalidationCollector` joins a fresh-policy/global backing to descriptor-bound Scan
  evidence under one preallocated capture ID. The backing must rebuild fresh evidence with that
  exact ID; immutable scan evidence cannot be passed through as current evidence. Final preflight
  transfers only CLOEXEC duplicates of held descriptors.
- Regular-file protection maps exact logical size plus SHA-256 into one domain-separated policy
  digest. Identity includes generation; access keeps owner/group/mode/masked flags, ACL, File
  Provider state, and mount identity separate. Unknown provider ownership remains fail-closed.

## Protected Properties

- Object identity remains device, inode/file ID, type, and generation when available. Every typed
  remove operation receives the same held-descriptor final preflight before `/bin/rm` starts.
- Pathname-backed v1 Codex-temporary and versioned-artifact actions require content stability to
  be explicitly not applicable. Evidence with a required digest remains report-only until a
  native descriptor-bound or quarantine adapter can preserve that property through mutation.
- Access policy remains owner/group/mode, masked access-control flags, ACL, provider state, and
  namespace/mount boundary. Missing, unreadable, collection failure, identity mismatch, content
  mismatch, and access-policy mismatch retain distinct outcomes.
- Pathname-backed removal retains the explicit `pathRaceResidual`; typed scope checks constrain
  which disposable slot is authorized but do not claim atomic identity continuity after the final
  descriptor check.

## Dependency

- The integrated evidence-authority slice owns canonical ACL serialization, masked access-control
  flags, File Provider no-materialization checks, descriptor binding, and one-shot receipt
  lifecycle. Execution receives only package-scoped facade evidence and does not expose or recreate
  the authority, receipt registry, or request-ID constructor.

## Task List

- [x] Add engine-issued raw command/native previews.
- [x] Bind the preview list and every force warning into apply authorization.
- [x] Add typed Codex temporary-scope removal.
- [x] Add typed versioned-artifact removal.
- [x] Add fixture-only scoped adapter and preview tests.
- [x] Add the dirty-Git report-only firewall without weakening clean quarantine removal.
- [x] Merge the validated evidence-authority baseline and add the concrete live collector.
- [x] Run focused and full Swift tests in the shared dynamic slot.
- [x] Complete fresh-context static review with no P0-P2 findings.
- [ ] Complete the signed landing workflow after dynamic validation.

## Handoff

- Phase: the evidence authority, concrete descriptor collector, capture lifecycle, authoritative
  previews, typed adapters, and dirty-Git report-only firewall are implemented. The new live slice
  passes its exact focused dynamic gate.
- Next step: freeze and review this slice, merge the latest integration package-assets commit, then
  run the smallest affected gates required by the resulting diff before landing.
- Blocker: none.

## Evidence

- Architecture: `docs/design/accepted-plan.md`.
- Phase 4 contract: `docs/design/revalidation-and-dry-run.md`.
- Phase 5 contract: `docs/design/best-effort-apply.md`.
- Static parse gate: changed Swift production and test sources parse successfully.
- Static formatting gate: `swift-format lint --strict` passes for every changed Swift source and
  test file; `git diff --check` and project-journal validation also pass.
- Fresh-context review: initial findings covered content-stable pathname removal, APFS owner
  preview binding, specialized force warnings, Codex scope ambiguity, report-only preparation,
  versioned scope derivation, and force-tier promotion. All were fixed; the final current-tree
  review reported no P0-P2 findings without running dynamic tests.
- Dynamic tests on the local Apple Silicon host with SwiftPM's nested sandbox disabled while the
  outer workspace sandbox remained active:
  - 12/12 focused preview, report-only, specialized-adapter, force, and APFS regressions passed.
  - `DiskplanPolicyTests`: 64/64 passed.
  - `DiskplanExecutionTests`: 73/73 passed.
  - `DiskplanEngineCoreTests`: 53/53 passed.
  - Full Swift suite: 392/392 passed.
- The first focused run exposed a non-canonical multi-component parent chain in the execution test
  fixture; the first policy target run exposed a specialized alias fixture that had not declared
  content stability not applicable. Both task-scoped fixtures were corrected before the passing
  reruns above.
- Preservation before integration: binary patch
  `/tmp/diskplan-runtime-revalidation-adapters-premerge.patch` is 68,243 bytes with SHA-256
  `4b822946089b3668a993f3fbedf734bad1bbf4df7f79fc6830bb5d8691fb7012`; signed commit
  `81ef51c` preserves all 13 tracked and two previously untracked files.
- Integration merge: signed commit `3b840bb` merges `5ca93b9` without rebasing. The union retains
  SafeArtifacts recovery locators, epoch-aware optional audit handling, and the first-failure
  persistence latch.
- Current A-firewall gate: `git diff --check`, `swift-format 602.0.0 lint --strict`, and
  `swiftc -parse` pass for all changed Swift files. A bounded source/design search finds no retained
  `git reset --hard` or `git clean -ffdx` execution path. Four focused Swift regressions pass for
  dirty policy blocking, capability-free report-only preparation, no-Git dirty adapter/router
  rejection, and successful clean quarantine removal. The first policy run exposed only a test
  assumption that discard would sort before its dependent remove ActionID; the assertion now
  accepts either member of the fully blocked chain, and its rerun passes. Broader target gates are
  deferred until the newly landed evidence-authority integration merge invalidates this build.
- Live-evidence focused gate: the first bounded compile exposed one Swift 6 sendable-closure capture
  of mutable `jitReport`; freezing the accepted JIT capture ID before creating the final-preflight
  closure fixed it. A host-dependent File Provider result in the transferred-descriptor fixture was
  replaced with an injected, explicitly local provider observation; production still calls the
  real File Provider API and fails closed on uncertainty. The final exact six-filter run passes 6/6
  with bounded supervisor output SHA-256
  `f242339e02ffe30b7d149d99d86aa7425fd7fe4b37bc1f56e48721299669ab04` and quiescent process-group
  cleanup. The generated `.build` directory was removed immediately afterward.
