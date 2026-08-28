---
id: 20260828-9c2e6f
title: Phase 1 Deterministic Scanner Core
status: active
created: 2026-08-28
updated: 2026-08-28
branch: wip/phase1-scan-core
pr:
supersedes: []
superseded_by:
---

# Phase 1 Deterministic Scanner Core

## Summary

- Add the authoritative Swift read-only traversal and evidence model without IPC,
  TUI, semantic classification, or cleanup policy.
- Preserve raw filesystem names, descriptor-relative object identity, explicit
  uncertainty, and partial coverage through pause/resume/finalization.

## Task List

- [x] Add versioned quick/standard/deep/full-audit root resolution and budgets.
- [x] Add raw path, observation, coverage, byte-measure, root-binding, and global-fact types.
- [x] Add the deterministic descriptor-relative, no-follow, no-cross-mount walker.
- [x] Add File Provider metadata-only/rejected boundary propagation without an exclusion table.
- [x] Add streaming closed-directory aggregation and deterministic bounded top-K retention.
- [x] Preserve APFS/hardlink topology and File Provider identity/metadata as typed node evidence.
- [x] Preserve independent filesystem times and a pre/post access-policy seal.
- [x] Add actor scan control, checkpoints, provisional snapshots, partial finalization, and transcripts.
- [x] Add a bounded process-activity collector abstraction and normalized `lsof -nP -F0` parser.
- [x] Add deterministic fake-filesystem and controlled temporary-root tests.
- [x] Re-run the live Darwin temporary-root path after the authoritative directory
  packed-attribute parser fix is integrated.
- [x] Gate every production path-touch boundary with live no-materialization policy
  revalidation and fail configured roots closed on unverified provider ownership.
- [x] Unify item, root, descriptor, mount, and close identity on real device/file ID/type.
- [x] Retain parent-slot bindings through close and preserve close-time
  missing/mismatch/unreadable/access-policy distinctions.
- [x] Bound deterministic directory enumeration by count, pending raw-name bytes,
  and the scan deadline with explicit partial coverage.
- [x] Bind complete resolved raw scope, budgets, and collector configuration into
  scan provenance.
- [x] Revalidate provider/dataless/sync-root, byte-credit, and sharing-topology
  evidence after provider probing before accepting traversal or exact credit.
- [x] Preserve typed File Provider rejection outcomes through scan coverage.
- [x] Reject duplicate root IDs before scope freeze and retain actual root bindings
  in traversal frames.
- [x] Require authoritative provider probing whenever dataless or sync-root state
  is unavailable instead of treating it as local evidence.
- [x] Merge active stack and unstarted-root coverage into provisional snapshots.
- [x] Preserve close-time identity and access-policy observations independently.
- [x] Keep unknown sync-root state fail-closed after positive provider evidence and
  discard exact byte credit at rejected provider boundaries.
- [x] Bracket close-time access-policy observation with parent-slot identity before
  and after the policy read.
- [x] Bind close-time access policy and real identity to the same no-follow slot
  descriptor so replace-policy-restore cannot cross-associate evidence.
- [x] Preserve active-frame provider, mount, and frontier coverage on cancellation.
- [ ] Complete independent frozen-range review and PR delivery.
- [ ] Integrate scanner evidence into the versioned IPC workstream.

## Current State

- Missing, unreadable, unknown, failed, and identity-mismatch observations remain distinct.
- Budget-exhausted, time-bounded, provider-bound, mount-boundary, and cancelled scans cannot be returned as complete.
- The production walker constructs no child path and reads no file content. Only test-created temporary roots are mutated by integration tests.
- Global VM, swap, and APFS snapshot evidence is typed unavailable rather than inferred.

## Handoff

- Phase: Phase 1 fifth frozen-review repair complete and validated.
- Next step: repeat independent frozen-range review, then prepare PR delivery.
- Blocker: none for the scanner slice. The authoritative directory packed-attribute
  parser fix is integrated from foundation head
  `e2135d9c708d5515c3cd5b6f965908d60a4ed44b`; the scanner keeps the live gate strict
  and does not bypass or relax that probe.

## Evidence

- Accepted architecture: `docs/design/accepted-plan.md`.
- Scanner contract: `docs/design/scanner-core.md`.
- Before Phase 0 integration, focused `DiskplanScanTests` passed 21 tests covering
  raw invalid UTF-8 names, enumeration permutations, missing/mismatch/unreadable and
  access-policy-change distinctions, symlink/mount/provider boundaries, provider
  evidence propagation, budgets/timeouts, aggregation, top-K versus the complete
  event stream, control transcripts, a typed lsof parser, and the controlled Darwin
  temporary root's typed live-gate failure.
- After integrating Phase 0, focused `DiskplanMacOSTests` pass 29 tests and
  `diskplan-macos-probe --self-test` succeeds. That intermediate scanner integration
  passed 20 tests and exposed the directory packed-buffer gap through its sole live
  failure.
- After integrating foundation head `e2135d9c708d5515c3cd5b6f965908d60a4ed44b`,
  focused `DiskplanScanTests` pass all 21 tests, including descriptor-relative
  inspection of a controlled live directory root.
- Before the frozen-review repair, the complete Swift suite passed 69 tests and
  the explicit Swift build with automatic dependency resolution disabled succeeded.
- `scripts/test-macos-capabilities.sh` passes 32 focused macOS tests plus the CLI
  self-test. Controlled File Provider and APFS volume-group fixtures remain
  explicitly unavailable on this local host rather than being inferred as passes.
- Scanner Swift format lint, CI journal tests (17 tests), both journal validators,
  `bash -n`, and ShellCheck pass for the relevant scanner/capability scope.
- Frozen review identified six scanner safety gaps covering live path policy gates,
  authoritative configured-root provider evidence, real-device identity namespace,
  close-time parent-slot revalidation, bounded enumeration, and complete provenance.
  The repair adds focused fake and controlled-live regressions for all six; the
  focused scanner suite passes all 27 tests.
- After the frozen-review repair, the complete Swift suite passes all 75 tests and
  the explicit Swift build with automatic dependency resolution disabled succeeds.
  `scripts/test-macos-capabilities.sh` passes its 32 focused macOS tests plus the
  CLI self-test; unavailable controlled fixtures remain reported as unavailable.
- Strict Swift format lint, `git diff --check`, CI journal tests (17 tests), both
  journal validators, `bash -n`, and ShellCheck pass for the final repair range.
- The second frozen review identified stale provider postflight state, collapsed
  typed provider rejections, and duplicate root-ID aliasing. The follow-up compares
  the complete policy-relevant item snapshot, maps every provider rejection into a
  typed observation and coverage outcome, rejects duplicate IDs before scope
  freeze, and retains the actual root binding in each frame. Focused scanner tests
  pass all 30 tests.
- After the second frozen-review repair, the complete Swift suite passes all 78
  tests and the explicit Swift build with automatic dependency resolution disabled
  succeeds. The macOS capability gate again passes 32 focused tests plus the CLI
  self-test, with controlled fixtures explicitly unavailable on this local host.
- Strict Swift format lint, `git diff --check`, CI journal tests (17 tests), both
  journal validators, `bash -n`, and ShellCheck pass for the second repair range.
- The third frozen review identified provider flags that could fall through from
  unavailable to local, provisional coverage that omitted the active frontier, and
  close evidence that coupled identity with access policy. The follow-up forces an
  authoritative provider probe unless both flags are known false, merges active and
  unstarted roots into snapshot coverage/progress, and carries close identity and
  access policy as separate observations. Focused scanner tests pass all 32 tests.
- After the third frozen-review repair, the complete Swift suite passes all 80 tests
  and the explicit Swift build with automatic dependency resolution disabled
  succeeds. The macOS capability gate again passes 32 focused tests plus the CLI
  self-test, with controlled fixtures explicitly unavailable on this local host.
- Strict Swift format lint, `git diff --check`, CI journal tests (17 tests), both
  journal validators, `bash -n`, and ShellCheck pass for the third repair range.
- The fourth frozen review identified a sync-root unknown-state escape after
  positive provider evidence, an unbracketed close-time policy read, and dropped
  active-frame coverage during cancellation. The repair requires known dataless
  and sync-root state after provider postflight, drops exact byte credit at rejected
  boundaries, brackets policy with two descriptor/parent-slot identity reads, and
  merges every active frame before close. Focused scanner tests pass all 36 tests.
- After the fourth frozen-review repair, the complete Swift suite passes all 84
  tests and the explicit Swift build with automatic dependency resolution disabled
  succeeds. The macOS capability gate passes 32 focused tests plus the CLI
  self-test; controlled File Provider and APFS volume-group fixtures remain
  explicitly unavailable on this local host.
- Strict Swift format lint on all changed Swift files, `git diff --check`, CI
  journal tests (6 tests), the repository journal validator, and the bundled
  project-journal validator pass for the fourth repair range.
- The fifth frozen review identified that a path-based policy read could observe a
  temporary replacement while the outer identity bracket observed the original on
  both sides. The repair binds real identity and policy to one descriptor-relative,
  no-follow slot open and rejects an identity mismatch before accepting policy. A
  controlled temporary-root regression performs the exact replace, policy read,
  and restore sequence.
- Focused scanner tests pass all 37 tests. The complete Swift suite passes all 85
  tests, the explicit Swift build with automatic dependency resolution disabled
  succeeds, and the macOS capability gate passes 32 focused tests plus the CLI
  self-test. Controlled File Provider and APFS volume-group fixtures remain
  explicitly unavailable on this local host.
- Strict Swift format lint on both changed Swift files, `git diff --check`, CI
  journal tests (6 tests), the repository journal validator, and the bundled
  project-journal validator pass for the fifth repair range.
