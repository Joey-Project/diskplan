---
id: 20260828-a5d210
title: Phase 5 Best-Effort Apply
status: completed
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
- Release postverification now derives each complete connected owner/group/topology component
  from the exact unit in the one-shot registry-backed apply claim. The authority recomputes the
  claim's current binding against the immutable plan, accepts only matching descriptor locators,
  and rejects missing, extra, replayed, or replaced members before freezing descriptor state.
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
  capture/evidence ID. Operational unknowns such as incomplete coverage remain rejected even when
  an unrelated recoverability review fact exists; missing, unreadable, and failed observations
  remain fail-closed.
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
- [x] Revalidate the signed integration merge with targeted Phase 5 and serial full Swift gates on
  India-mac-mini-m4-hoteng.
- [x] Bind descriptor-held release postverification to the registry claim, freeze its engine-only
  v1 component encoding in a shared golden fixture, and make that fixture a required India lane.

## Handoff

- Phase: Phase 5 best-effort apply and the accepted dirty-Git report-only boundary are complete on
  the current Protocol 1.5, batch, and TUI integration baseline.
- Next step: none within this completed workstream. Repository delivery owns landing the reviewed
  branch and reclaiming the remote validation worktree, `.build` directory, and retained logs.
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
- Final code head `d078f5e1b117a01f61a290a7cf722e03244c3429`: `swift-format lint --strict`,
  `swiftc -frontend -parse`, `git diff --check`, and the project-journal validator passed locally
  as static-only checks. Dynamic validation ran only on India-mac-mini-m4-hoteng.
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
- India execution validation of successor `c420ecc4afdf1b43f7f28f4d70248ee2ac51a8cb`
  compiled and ran 152 tests; one dirty-Git preparation test produced two assertion issues. The
  bounded supervisor completed in 22.276 seconds, emitted 44,421 bytes with SHA-256 prefix
  `9eec5fb6`, and verified a quiescent process group. Both policy validation and async preparation
  deterministically rejected the blocked dependent remove action first in canonical evaluated-
  action order, while the stale assertion expected the discard action ID. The successor asserts
  the exact remove ID and preserves the collector-not-called proof. Policy and serial full gates
  were not started for this failed head.
- India execution validation of successor `22085b87c79c161521aa546509f17124844799ef`
  passed all 152 tests; the bounded supervisor completed in 22.613 seconds, emitted 43,594 bytes
  with SHA-256 prefix `8bc66b75`, and verified a quiescent process group. The focused policy gate
  then compiled and ran 66 tests; one assertion produced one issue after the bounded supervisor
  completed in 7.370 seconds, emitted 12,827 bytes with SHA-256 prefix `e3375527`, and verified a
  quiescent process group. It was the PolicyCore counterpart of the corrected execution fixture:
  canonical evaluated-action order rejected the blocked dependent remove action, while the stale
  assertion expected the discard action ID. The successor updates only that test expectation;
  production behavior is unchanged. The serial full gate was not started for this failed head.
- India policy validation of successor `f3ac3d7b67488aa737b14f541b27d4e661662bf3` passed all
  66 tests; the bounded supervisor completed in 26.558 seconds with SHA-256 prefix `2afc8dee` and
  verified a quiescent process group. The serial full gate then failed deterministically in
  `authorityUsesCompleteCorpusInsteadOfRetainedViewport`: the complete authority corpus projected
  zero report-only items instead of one and the stale unchecked subscript then terminated the test
  process with signal 5. The bounded supervisor completed in 10.582 seconds, emitted 12,311 bytes
  with SHA-256 prefix `16a072ed`, and verified a quiescent process group. An isolated rerun failed
  the same way after 3.065 seconds with 1,650 output bytes and SHA-256 prefix `0758f68b`. The merge
  exposed an invalid cross-module combination: transient incomplete-coverage recoverability has no
  stable waiver proof, but snapshot validation required one while policy construction attempted an
  empty waiver. The successor permits proof-free operational unknowns only as rejected report-only
  evidence, retains stable typed proof for unsupported/public-API unknown waivers, and hardens the
  corpus test against an unchecked index. Dirty Git remains non-stageable and non-executable.
- Focused review of the first authority-projection fix found that checking only for a nonempty
  recoverability predicate list could let an unrelated review fact make an operational unknown
  waivable. The successor branches on the typed unknown reason: only `unsupported` and
  `unavailableViaPublicAPI`, whose exact stable semantic facts are structurally required, can
  require waiver; `notRequested`, `budgetExhausted`, `timedOut`, and `incompleteCoverage` remain
  rejected even when another recoverability fact is present.
- India final validation of exact code head `d078f5e1b117a01f61a290a7cf722e03244c3429`
  passed the isolated complete-corpus authority regression (1/1, 0.003-second test runtime); its
  bounded supervisor completed in 23.961 seconds, emitted 15,174 bytes with SHA-256
  `dee4f4ce66b530d377bedf10dadc363ec4a87a663b43c4294ec6701872a03cc4`, and verified a
  quiescent process group. Focused policy validation passed all 66 tests in 4.696 seconds; its
  supervisor completed in 8.921 seconds, emitted 17,870 bytes with SHA-256
  `7e31950f70e00e2f46ead1bc10fa16277891303278aeaed702b07866cb3d08dd`, and verified a
  quiescent process group. Serial full validation passed all 594 tests in 15.313 seconds; its
  supervisor completed in 19.613 seconds, emitted 112,407 bytes with SHA-256
  `0acedfd407c1b06c631df017ebac2a0f07e308fb1876a7131173138528281155`, and verified the
  process group quiescent. Execution validation from `22085b87c79c161521aa546509f17124844799ef`
  remains applicable because subsequent commits did not change execution production or tests; it
  passed all 152 tests in 0.461 seconds with a 22.613-second supervisor, SHA-256 prefix `8bc66b75`,
  and a quiescent process group.
- India release-postverification closure validation passed the exact v1 golden fixture (1/1) and
  the complete `DiskplanExecutionTests` suite (185/185). Their bounded supervisors emitted output
  SHA-256 `c6b8979c13fba2c486b2d5888f5d8994f3fa2bca3dc165e1e2f33b787b6b586c` and
  `ad75d712d18bfca477aac3a60d4851895b830765a23abffc57c3496c7c5395bc`; both verified the
  process group and terminal quiescence. The India release acceptance validator then passed all
  18 tests with output SHA-256
  `7bc83929f79c8678737a5724da0d7fb69194a01ca52394499c61abcb93823e0b` under the same
  supervisor guarantees. Strict Swift formatting passed on the macOS 26 release host.
- A final release-postverification audit found that the claimed manifest's whole-plan capture was
  incorrectly occupying the per-unit JIT capture slot. The successor keeps plan capture P,
  whole-plan capture A, actual JIT capture B, and postverification capture C distinct. A successful
  JIT report now mints an engine-internal, single-consume claim that binds the exact execution unit,
  canonical JIT action and release-group membership, apply-authorization claim hash, current
  binding, preparation generation, epoch, nonce, and B. Manifest authority consumes that opaque
  claim before deriving the connected owner/group closure; caller input remains limited to exact
  descriptor locators. The v1 component binding and shared golden now include the apply claim,
  generation, nonce, A, B, and JIT action membership without changing IPC.
- India validation of the JIT-claim successor passed all 187 `DiskplanExecutionTests` in
  0.424 seconds. Its bounded supervisor completed in 6.680 seconds, emitted 43,153 bytes with
  SHA-256 `96e32e36675844c46cb44aa6ca55a15cbf551207943053a6826566a2f9033451`,
  verified the process group, and reached terminal quiescence. The descriptor-bound targeted gate
  passed 21 tests, including actual-B issuance, cross-unit rejection, every bound claim dimension,
  replay, and the exact v1 golden; its supervisor completed in 2.790 seconds, emitted 5,835 bytes
  with SHA-256 `83f84574bd9a911336cc0e798b40d89f87d70ed1d8877641d0cf55522421fd08`,
  and provided the same process-group guarantees. The release acceptance validator passed all 18
  tests with output SHA-256
  `7bc83929f79c8678737a5724da0d7fb69194a01ca52394499c61abcb93823e0b`, and strict Swift
  formatting passed on the macOS 26 release host.
- Production execution now consumes the per-unit JIT claim through manifest authority before the
  first release mutation. The authority derives descriptor locators from the exact engine-owned
  adapter operations, opens and seals the root/parent chain, freezes the complete connected
  owner/group component, and retains only duplicated close-on-exec descriptors across mutation.
  Locator acquisition failure invalidates the claim, while authorization, freeze, cancellation,
  mutation failure, and postverification all converge on one-shot claim and descriptor ownership.
  The legacy boolean release result remains available only to DEBUG compatibility fixtures and is
  never consulted by `EngineExecutionComposition`.
- End-to-end production-composition fixtures prove successful P/A/B/C execution with a real POSIX
  removal, reject missing and replaced namespace locators before mutation, reject JIT replay and
  cross-unit splice attempts, keep mutation-preflight failure separate from topology collection,
  and reject a false C allocation release even when the legacy source returns `.known(true)`.
- Final India validation used the repository's bounded process-group supervisor. The descriptor-
  bound targeted gate passed 26 tests in 9.400 supervisor seconds with 13,531 output bytes and
  SHA-256 `712d647a2382a48f7bb920a0071e8d557376617c9fff236aa9c244732b63453d`;
  the BestEffort targeted gate passed 30 tests in 2.791 seconds with 6,709 bytes and SHA-256
  `be77910d4275d71b2a37469443daac562ead74b698c62475fcd64945d06cd35c`.
  The complete `DiskplanExecutionTests` gate passed all 192 tests in 4.603 seconds with 44,380
  bytes and SHA-256 `9960099a219dfa5146e88b2fe3dae1cd75e9bc813aa92dd83fdfc0769ed8e1f5`.
  The incremental release build passed in 2.684 seconds, the 18-test release acceptance validator
  passed with SHA-256 `7bc83929f79c8678737a5724da0d7fb69194a01ca52394499c61abcb93823e0b`,
  and strict Swift formatting passed. Every supervisor verified its process group and reported
  terminal quiescence.
- The release-postverification branch now contains a signed no-fast-forward merge of production
  runtime baseline `cd016f66a1233683abbc535e0544d2bff2090d58`. The merge preserves the strict
  runtime projection and fixture behavior together with production descriptor-bound release
  postverification. A semantic merge audit found that the baseline's injected-clock composition
  initializer neither retained its collector nor passed the release topology core to its apply
  coordinators. The successor stores the collector, injects the same descriptor-bound core in both
  coordinator paths, and binds the core's freeze/freshness clock to the composition clock. A new
  real-removal regression proves that the injected-clock path reaches typed topology C and never
  consults the legacy boolean result. Swift formatter changes in three baseline files are purely
  mechanical.
- Post-merge India validation passed 27 descriptor-bound tests in 10.033 supervisor seconds with
  9,560 output bytes and SHA-256
  `eea8a670b222d1f36b9e5cfa50c7c792bad2d06f0abadb5327b7efb1b689e930`, 30 BestEffort tests
  in 4.249 seconds with 12,192 bytes and SHA-256
  `415783bfee10b039eebeac11327acd7b6e7247430b8c066c177e9777226ec73a`, and all 193
  `DiskplanExecutionTests` in 4.495 seconds with 44,579 bytes and SHA-256
  `250176134fe1d69782b11d2f6e2f807740d8c4567c62474362645365cbbc1956`. The release build
  passed in 19.362 seconds with SHA-256
  `0ada712ce5feb0310da194a3f074f92f03ef88e8733eba5f5faa86e4fadecee5`; the 18-test release
  validator passed with SHA-256
  `7bc83929f79c8678737a5724da0d7fb69194a01ca52394499c61abcb93823e0b`; and strict Swift
  formatting passed. Every final supervisor verified its process group and reported terminal
  quiescence.
- The branch now contains a signed no-fast-forward merge of production head
  `381ab8c14a383662a9f0f20945c7dc421c76e9bb`, which adds Scan-owned one-shot fresh-evidence
  receipts and EngineCore fresh survivor/terminal invariant validation. The merge was conflict-free
  and does not alter descriptor-bound release composition. Its exact release-composite ownership
  model remains compatible with the postverification connected-component authority: only an exact
  owner namespace/identity binding can authorize a composite terminal replacement, while all
  unrelated aliases and namespace drift remain reject votes.
- India targeted validation passed all 15 fresh Scan receipt tests in 26.270 supervisor seconds
  with SHA-256 `5a790f290de787d27af63e79be254c692470204008f188db243054363115fffc`
  and all 12 fresh invariant tests in 4.318 seconds with SHA-256
  `3657322419d084d7783a6dc733e09641273f13b823c5d2093feb68d90d33d26d`.
  The complete Scan suite passed 127 tests in 3.253 seconds with SHA-256
  `4539baf61b3de1636119116baa954e203164d20f4556b8da51fb9bac0e9fc4b6`. The first parallel
  EngineCore full run produced eight failures at the same pre-existing asynchronous review-
  publication assertion; the isolated representative passed, and the authoritative serial full
  gate then passed all 141 tests in 9.760 seconds with SHA-256
  `9efc8a91723fd47cfe144ed57f9042bc3c7fa87fd70405058505781cef7f76c6`.
  Serial full Execution passed all 193 tests in 3.585 seconds with SHA-256
  `07f7962768bb36a6fd3bbcb4db330dccc79462e44d47330fe0d36e40889139c9`.
- The India release build passed in 55.940 seconds with SHA-256
  `4ff0767598517dbca2a9e4eb7f0a7f0c5dee0ae1ad33d7cd873e32072a82ebbc`; the 18-test release
  validator passed with SHA-256
  `5b2b5ea9111172196c7541126fdb8c4583ebf35f00bf4dd969e57faa405b1c13`; and strict formatting
  passed for every newly added or modified Swift source and fixture. Every final supervisor
  verified its process group and reported terminal quiescence.
