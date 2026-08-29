---
id: 20260828-a5d210
title: Phase 5 Best-Effort Apply
status: active
created: 2026-08-28
updated: 2026-08-29
branch: wip/phase5-best-effort-apply
pr:
supersedes: []
superseded_by:
---

# Phase 5 Best-Effort Apply

## Summary

- Add the typed best-effort apply coordinator behind the Phase 4 authorization boundary.
- Add a raw-argv generic removal adapter, per-step post-verification, event streaming, and
  optional nonfatal audit output.

## Current State

- Runtime units preserve the validated dependency direction and collapse authorized APFS
  release components so every owner executes at most once. Compound owners retain and execute
  their internal DAG, and only downstream owners skip after a failure.
- A unit receives an exact read-only JIT snapshot before mutation. The request binds the current
  authorization, generation, epoch, exact actions/groups, and a one-shot nonce; stale, reused,
  incomplete, or failed evidence cannot reach an adapter.
- Independent units continue after adapter failure or cancellation. Dependents are skipped
  when any prerequisite unit is not successful. Cancellation, expiry, and supersession stop new
  owner actions; no rollback is claimed.
- Generic removal uses `/bin/rm` through raw `posix_spawn` argv with descriptor-relative
  no-follow namespace, identity, access, provider/mount, ACL/flags, and content preflights.
  Content-stable actions cannot use this pathname adapter. The child has no terminal stdin and
  is supervised as a process group across cancellation and deadline expiry.
- Force warnings are bound into apply review and require explicit confirmation before
  authorization. Runtime warnings remain a secondary event.
- Connected APFS units require a typed `allocationGroupReleased` topology proof after their
  owner steps; target absence alone cannot claim shared-space release.
- Git worktree removal now uses exclusive same-filesystem quarantine, descriptor identity and
  subtree verification, typed restore/retained recovery, and post-removal administrative
  cleanup. Administrative cancellation, deadline, or failure after root deletion is a typed
  partial/expected residual, and no new cleanup process starts after cancellation or expiry.
  The production composition router cannot send Git or unconfigured specialized actions
  through generic removal.
- Authorization is registry/generation-backed until its single claim, so any newer preparation
  revokes an older unconsumed authorization. The opaque claim now atomically consumes the
  authoritative engine record while checking generation, deadline, and manifest binding.
- Release graph, runtime-unit, JIT topology, and post-verification joins use raw UTF-8 keys, so
  NFC/NFD-equivalent allocation-group and file-object identifiers remain distinct.
- Typed unknown-recoverability waivers revalidate a stable semantic proof rather than a fresh
  capture/evidence ID; missing, unreadable, and failed observations remain fail-closed.
- Dirty Git worktrees and their dependent remove chains remain evidence-rich but report-only in
  v1. Policy blocks them without a waiver path, apply preparation cannot mint authority for them,
  and both production routing and the quarantine adapter reject them without a Git executable in
  the mutation implementation. Clean quarantine removal remains executable.
- Quarantine uses a per-execution exclusive directory sealed for identity and access policy,
  including ACL/flags/`fstatfs` mount. Restore and recovery-locator publication reopen the raw
  root without following links, rebind every parent identity and access seal, and prove the
  quarantine directory name still resolves to the held object. Administrative cleanup binds the
  planned metadata digest and canonical root slot. Coverage timestamps trigger only a bounded
  reread, while content and access digests remain separate.
- Shell/TUI events require no persistence. Optional audit failures, including `ENOSPC`, are
  reported but cannot stop cleanup.

## Task List

- [x] Add typed execution units, adapter operations, outcomes, post-verification, and events.
- [x] Add best-effort dependency scheduling and compound release owner deduplication.
- [x] Add per-unit JIT revalidation and mutation firewall boundaries.
- [x] Add raw-byte generic remove with explicit ordinary/force command shapes.
- [x] Add fixture test source for partial failure, cancellation, JIT replacement, APFS owner
  deduplication, authorization replay, audit failure, and temporary-root removal races.
- [x] Integrate the corrected Phase 4 engine-owned authorization/evidence source and fresh epoch
  contract.
- [x] Bind force confirmation, single-use authorization generation, fresh JIT capture/nonce, and
  final descriptor recollection into the apply authority.
- [x] Add compound owner DAG semantics and typed allocation-group post-verification.
- [x] Finish the dedicated Git worktree quarantine adapter and production adapter composition.
- [x] Add review follow-up fixtures for registry claims, NFC/NFD IDs, mixed global facts,
  dirty-to-clean Git baselines, sibling registrations, external filters, ACL/flag drift, and
  timestamp-only versus byte drift.
- [x] Replace the provisional pathname-opened dirty Git discard path with the accepted v1
  report-only boundary at policy, router, adapter, test, and design layers.
- [x] Statically audit the slice against immutable plan/overlay authority, force confirmation,
  best-effort continuation, optional audit output, provider evidence, and APFS allocation-owner
  closure requirements.
- [x] Complete static review follow-up implementation and documentation updates.
- [ ] Run the focused/full Swift follow-up gates on India-mac-mini-m4-hoteng after the shared
  dynamic-test slot is released.
- [ ] Run release integration, journal validation, and formatting for the follow-up head.
- [ ] Complete frozen-range review and the signed landing commit.

## Handoff

- Phase: Phase 5 best-effort apply and the accepted dirty-Git report-only boundary are complete at
  the static gate.
- Next step: run the focused and serial full Swift gates on India-mac-mini-m4-hoteng, resolve any
  compiler/runtime findings, reconcile the branch with the current integration head, then freeze
  the range for review and a signed landing commit.
- Dependency: the final live production route must consume the separately owned concrete
  revalidation collector and typed survivor/terminal-namespace invariant proofs. This slice does
  not fabricate or weaken those inputs and does not depend on their two pending hookup decisions.

## Evidence

- Accepted architecture: `docs/design/accepted-plan.md`.
- Detailed contract: `docs/design/best-effort-apply.md`.
- Phase 4 boundary: `docs/design/revalidation-and-dry-run.md`.
- Pre-follow-up head: focused `swift test --filter DiskplanExecutionTests`: 62 tests passed.
- Pre-follow-up head: serial full `swift test --no-parallel`: 133 tests passed.
- Parallel `swift test`: all Phase 5 execution tests passed, but the pre-existing
  `boundProviderProbePreservesSubsecondDeadlineAndRereadsPolicy` timing assertion failed in two
  full concurrent runs and passed when run alone; no production change was made for this
  parallel-only flake.
- Pre-follow-up head: production `swift build -c release --product diskplan-engine`: passed.
- Current dirty head: `swift-format lint --strict`, `swiftc -frontend -parse`, and
  `git diff --check` passed locally as static-only checks; Swift build/test gates are reserved for
  India-mac-mini-m4-hoteng and remain pending the shared slot.
- Fresh review of checkpoint `714d13e` found one compile-time coverage-token mismatch and one
  missing quarantine-payload identity rebind before restore. The follow-up wraps administrative
  coverage in its typed token and binds the restore leaf to the still-held original descriptor.
  A changed leaf or unsafe quarantine namespace now reports an unverified recovery binding rather
  than restoring a replacement or publishing a false recovery locator.
- Fresh full-range rereview through `dc55593` found that the held descriptors did not prove the
  recovery path was still reachable through the original raw-root and parent name slots. The
  follow-up captures root/parent access seals, reopens the complete no-follow parent chain, and
  verifies the quarantine directory slot before either restore or locator publication. A moved
  raw root now produces an unverified typed recovery state and leaves the quarantined payload
  untouched.
- India focused validation of `5c5a28b` stopped at five compile errors after 9.937 seconds; the
  bounded process group was quiescent and the serial full gate was not started. The follow-up
  keeps the authorization closure single-use while avoiding Swift 6 shadowing, reads the
  already-policy-validated dirty change-set observation without crossing an internal API
  boundary, makes raw administrative path splitting type-explicit, and uses the macOS 26 ACL C
  import signatures for entry enumeration and release. Local static format, parse, and diff
  checks pass; the corrected exact head still requires the same India focused/full rerun.
