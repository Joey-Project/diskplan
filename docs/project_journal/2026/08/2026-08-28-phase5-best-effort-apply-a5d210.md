---
id: 20260828-a5d210
title: Phase 5 Best-Effort Apply
status: active
created: 2026-08-28
updated: 2026-09-01
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
- Automatic recovery now snapshots the exact descriptor-bound quarantine payload before invoking
  the restore hook and compares identity, content, and access policy again immediately before the
  no-clobber restore rename. Cancellation/deadline recovery uses the already verified token as
  that baseline. Any access drift in either restore window remains typed as manual recovery and
  publishes a locator only after the ordinary recovery namespace rebind succeeds.
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
- [x] Run the focused/full Swift follow-up gates on India-mac-mini-m4-hoteng for the corrected
  successor to `69542257`.
- [x] Run the final India targeted/full validation plus local journal, formatting, parse, and diff
  gates.
- [x] Complete frozen-range review and the signed landing commits.
- [ ] Revalidate the signed integration merge with targeted Phase 5 and serial full Swift gates on
  India-mac-mini-m4-hoteng.

## Handoff

- Phase: Phase 5 best-effort apply and the accepted dirty-Git report-only boundary are complete;
  the merge with the current Protocol 1.5, batch, and TUI integration baseline is awaiting fresh
  dynamic validation.
- Next step: validate the signed integration merge on India, then integrate the branch and remove
  the remote validation worktree, `.build` directory, and retained Phase 5 logs.
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
- Fresh full-range review of signed checkpoint `8eac6da` found one remaining P1: both automatic
  restore paths rechecked only root identity after the deterministic `beforeRestore` window, so a
  same-object mode/ACL/flag change could still be renamed back into the source slot. The follow-up
  takes a stable descriptor-bound recovery snapshot, rechecks identity/content/access immediately
  before restore commit, and keeps access drift typed as manual recovery. Deterministic fixtures
  cover both verification-failure recovery and cancellation recovery hooks. The successor head
  requires static gates, signed append, fresh closure review, and India focused/full validation.
- The 2026-09-01 closure audit found that ordinary-file access drift could be hidden by an earlier
  content mismatch, restore publication lacked a final namespace/payload binding, recursive delete
  had one remaining hook-to-commit window, and Git `HEAD` resolution was not part of the mutation
  boundary. The follow-up keeps access policy independently protected, proves restore source and
  quarantine slots before and after the exclusive rename, repeats the complete subtree token at
  the deletion commit point, and binds both administrative coverage and the exact loose symbolic
  `HEAD` target. Packed-ref-only symbolic resolution remains fail-closed and therefore report-only
  in this v1 executable subset.
- Mutation recovery is now returned atomically with the exact adapter invocation. Production
  post-verification, step outcomes, shell/TUI events, optional audit events, and the final report
  consume that attempt-scoped value; the old ActionID lookup remains SPI-only test compatibility.
  This prevents a retry from inheriting a stale locator or administrative residual from an earlier
  attempt. The current checkpoint passed local `swiftc -frontend -parse`, strict Swift formatting,
  and `git diff --check`; no local build or dynamic test was run.
- Attempt-directory cleanup is now a separate typed result from the primary mutation. Every
  post-`mkdirat` preparation exit attempts descriptor-relative cleanup of only the captured object;
  successful deletion and automatic restore also remove the exact empty wrapper after held
  source-parent, wrapper-seal, and slot-identity checks. A retained or unverified wrapper is visible
  in the ordinary step/event/audit/report path, preserves cancellation and timeout, and makes an
  otherwise successful step partial. Deterministic fixtures cover post-mkdir failure followed by a
  clean retry, changed and replaced pre-rename wrappers, successful removal with a retained exact
  wrapper, and report propagation.
- Recovery-locator publication now proves the payload slot with descriptor-relative no-follow stat
  rather than reopening the directory, so mode-`000` access drift can still publish a verified
  manual-recovery locator. New commit-point fixtures mutate both the Git index and resolved loose
  `HEAD`; a separate late-child fixture reaches a real `unlinkat(..., AT_REMOVEDIR)` `ENOTEMPTY`
  failure instead of approximating recursive-delete failure through an earlier seal mismatch.
- Fresh single review of signed head `9f798d7299b04e55361073411f5720053d00a77f`
  found four in-scope binding gaps plus one point-in-time race already excluded by the accepted v1
  same-UID threat model. The follow-up repeats the complete subtree token immediately before and
  after automatic restore, rechecks the root-removal parent seal, and carries a private
  attempt-scoped root/parent seal binding into Git post-verification. Administrative residual now
  layers on top of that bound absence proof rather than bypassing it. Deterministic fixtures cover
  descendant restore drift in both windows, final parent-seal drift, replaced raw-root
  post-verification, and a recreated source slot accompanying an administrative residual.
- Fresh single frozen review of signed head `69542257d27bc94af225f369a0669f285fd27daf`
  returned no findings. India then compiled and ran 117 focused execution tests: 10 tests failed
  with 11 issues after 15.459 seconds, the supervisor exited 1, and the process group was
  quiescent. Eight failures were superseded assertions: production now consumes attempt-scoped
  recovery rather than the legacy ActionID test store, full-token or namespace-seal checks report
  earlier and more precise protected-property codes, and dirty Git has no legacy waiver
  predicate. The remaining two Git index hook fixtures did not mutate anything because their
  administrative fixture had no index file. The successor adds a captured index to that fixture,
  checks that both race-hook writes succeed, keeps the commit-point checks unchanged, and updates
  the affected tests to assert the exact attempt result and typed post-verification outcome. The
  serial full gate was not started. Focused static review then caught three replacement-binding
  assertions missing the production helper's `quarantine-` failure-code prefix; the successor
  uses the exact typed code without changing production behavior.
- India focused validation of `a1c0195c1fdf8f88d73415b9e79d77b525a657d7` passed all 117
  execution tests after 15.023 seconds with a quiescent process group. The serial full gate then
  ran 191 tests and found one obsolete PolicyCore assertion: it expected an unsequenced dirty-Git
  remove action to survive until plan validation, while the authoritative action builder now
  rejects that internally invalid chain immediately. The successor asserts that earlier rejection
  and retains the valid evidence-rich discard/remove chain to prove both actions remain report-only
  and cannot be staged or waived. No production validation is weakened.
- India targeted validation of `8376664fdc556479ab2bae0ce28d11a1e5daffce` passed the corrected
  dirty-Git policy test (1/1) in 0.008 seconds; the bounded supervisor completed in 5.771 seconds,
  emitted 1,131 bytes with SHA-256 prefix `98f4ab68`, and verified a quiescent process group.
- India serial full validation of the same exact code head passed all 191 tests in 0.706 seconds;
  the bounded supervisor completed in 4.837 seconds, emitted 39,795 bytes with SHA-256
  `781158a72c126f6b3714c3567f131942629cd74163b377c4530519f93ca8d573`, and verified the process
  group quiescent. Because the final successor is journal-only, this is the final dynamic code
  evidence; the docs-only head receives a separate accuracy review before integration.
- The Phase 5 branch now merges integration baseline
  `08891e7437eee779411741573f15dc37b7e407db`. Conflict resolution retains the Phase 5
  attempt-scoped recovery, descriptor-bound mutation, and dirty-Git report-only boundaries while
  adopting the integration policy's executable Git subset: only an exact linked-worktree
  registration with distinct administrative/common objects is executable; ordinary worktrees
  remain report-only. The merge also retains the integration branch's Protocol 1.5, batch, TUI,
  deterministic policy diagnostics, and DEBUG-only test authority changes. The earlier India
  evidence predates this merge, so the signed merge head requires fresh targeted and serial full
  Swift gates.
- India execution validation of merge head `64f9dcec4ebd5124125be10fefc09e81e5a4580f`
  stopped during test compilation after 14.949 seconds; no tests ran, the bounded supervisor
  emitted 20,256 bytes with SHA-256 prefix `6c77351f`, and verified a quiescent process group.
  Production sources compiled far enough for every reported error to be a stale Phase 5 test API:
  one removed caller-supplied display tier and four pre-manifest `releaseSets: []` plan
  initializers. The successor uses the integration authority's derived display tier and
  `releaseGraphBundle: nil` for plans without release topology. Policy and serial full gates were
  not started for the failed merge head.
