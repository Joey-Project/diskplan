---
id: 20260828-a5d210
title: Phase 5 Best-Effort Apply
status: active
created: 2026-08-28
updated: 2026-08-31
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
- Recovery safety is now typed independently from diagnostic failure strings. The adapter retains
  a complete pre-quarantine subtree token and compares path membership, object identity, content,
  and access policy separately after rename and immediately before deletion. Stable access drift
  on the root, an ordinary file, a symbolic link, or a descendant directory requires manual
  recovery; missing, unreadable, collection failure, identity drift, and content drift keep their
  distinct failure paths.
- Symlink coverage now opens the link object itself and binds its ACL through that descriptor.
  Post-rename token comparison precedes cancellation and deadline handling, so an interruption
  cannot auto-restore a tree whose access policy changed. Recursive deletion revalidates each
  exact node's identity, content, and access policy immediately before `unlinkat`; directory
  size/timestamp churn caused by deleting its already-verified children is not misclassified as
  content drift, while a newly introduced child still makes directory removal fail closed.
- A recursive-deletion failure no longer publishes the cached quarantine pathname. It first
  rebinds the raw root, every source parent, the quarantine namespace, and the payload identity;
  if that proof fails, the result is a typed unverified binding without a locator.
- Each apply attempt now receives a unique quarantine namespace. Before payload rename commits,
  every exit best-effort removes only the exact still-empty directory after descriptor-relative
  identity and access-seal revalidation. A changed or replaced attempt directory is retained, not
  deleted, but cannot block a newly prepared retry because the next attempt uses a new name.
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
- Integration dependency: the production `RuntimeSessionController` still exposes only
  plan/overlay behavior and intentionally rejects dry-run, apply, confirm, and cancel. The later
  Phase 5/controller integration owns the positive preview/confirm/cancel dispatcher, an
  intent-bound receipt, and midstream cancellation; this failure-fix checkpoint does not invent a
  success path around that typed fail-closed boundary.

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
  keeps the authorization closure single-use while avoiding Swift 6 shadowing, removes the
  obsolete dirty-Git consent-discharge path now that policy/overlay/router all enforce report-only,
  makes raw administrative path splitting type-explicit, and uses the macOS 26 ACL C import
  signatures for entry enumeration and release.
- India focused validation of `f9caa48` compiled and ran 86 tests, then reported two failed tests
  with four issues after 13.748 seconds; the bounded process group was quiescent and the serial
  full gate was not started. One test still expected the superseded dirty-Git consent flow and now
  asserts the three-layer report-only boundary. The other expected automatic restore after the
  quarantined target's access mode changed; access policy is a separately protected property, so
  the adapter now deliberately retains the identity- and namespace-verified quarantine and emits
  its typed recovery locator for manual handling instead of restoring altered access state.
- Static audit of `b952060` found that its four-code recovery allowlist did not cover stable access
  drift in ordinary subtree files, symbolic links, or descendant directories, and that recursive
  deletion failure still published a cached locator. The follow-up replaces that string policy
  with typed recovery safety, binds post-rename verification to the pre-quarantine token, adds
  descriptor-bound failure recovery, and corrects the design contract. Focused fixtures cover all
  three subtree node kinds plus a moved quarantine namespace during recursive-delete failure.
  `swift-format lint --strict`, `swiftc -frontend -parse`, and `git diff --check` pass locally; no
  local build or dynamic test was run, and the exact follow-up head still requires India focused
  and serial full gates.
- Fresh full-range review of signed checkpoint `ed6f7ba` found one P2: the stable action-derived
  quarantine directory name could leave a pre-rename failure marker that permanently rejected a
  retry. The follow-up gives each execution a unique nonce, reclaims an unchanged exact empty
  attempt directory through the held parent descriptor, and never removes a changed or replaced
  object. New fixtures cover cancellation cleanup followed by retry and a retained changed attempt
  followed by a successful unique retry. The replacement head requires static gates and a fresh
  closure review before India validation.
- Fresh full-range closure review of signed checkpoint `023bca3` found three P1 gaps: recursive
  deletion rechecked only identity after the last full snapshot, cancellation/deadline handling
  preceded the post-quarantine token comparison, and symbolic-link ACLs were represented as an
  empty digest. The follow-up moves interruption handling behind the protected-property comparison,
  measures symlink ACLs through an `O_SYMLINK` descriptor, and performs per-node descriptor-bound
  identity/content/access revalidation immediately before removal. New fixtures cover access
  drift plus cancellation, same-inode content drift, mode drift, and symlink ACL drift. The exact
  follow-up head still requires static gates, a fresh frozen-range closure review, and India
  focused/full dynamic validation.
