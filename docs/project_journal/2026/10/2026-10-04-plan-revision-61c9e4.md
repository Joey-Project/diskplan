---
id: 20261004-61c9e4
title: Full Plan Revision And Product Acceptance Recovery
status: active
created: 2026-10-04
updated: 2026-10-04
branch: wip/plan-revision-pr
pr:
supersedes: []
superseded_by:
---

# Full Plan Revision And Product Acceptance Recovery

## Summary

Preserve the complete Phase 0-6 product scope while separating implementation,
production integration, and installed-product acceptance. Incorporate the user's
accepted residency/ownership and read-only/mutation policy decisions into the
[accepted architecture](../../../design/accepted-plan.md), especially Sections 3,
9, 15, 16, and 20. Joey authorized the recovery sequence and a documentation PR
on 2026-10-04. This is not a claim that the existing code implements the revised
contract.

Joey accepted three contract refinements on 2026-10-04: a concrete ordinary
removal-authority matrix as the first R1 gate, eviction-specific logical identity
and state transitions, and separate invocation/post-verification/allocation
results. Their stable specification is
[locality and provider action contracts](../../../design/locality-and-provider-actions.md).

Use GPT-6 Luna subagents for bounded, token-heavy inventories, fixture matrices,
mechanical wiring, and targeted implementation/testing. The primary agent owns
architecture, protected-property contracts, integration decisions, and final
evidence-backed acceptance. Formal independent review still follows the adopted
delivery/review gates.

## Current State

- The initial read-only audit found local canonical `main` at `667f555` and
  remote `main` at `18e5106`, after runner PR #28. After delivery authorization,
  canonical `main` was fetched and fast-forwarded to
  `18e510655c5b2798a7c9a1c98763053fa122f5f1`. The documentation PR uses a new
  linked worktree at this base; it does not import the closure branch's 141
  non-main commits.
- The only open PR observed is draft [#6](https://github.com/Joey-Project/diskplan/pull/6),
  `wip/integrate-phase0-6` at `5e12e3b`, targeting `main`. Its historical checks
  include successful required macOS 26 gates but predate the current runner
  update and later closure branches.
- [#28](https://github.com/Joey-Project/diskplan/pull/28), head `e69e04e`, is merged
  to remote `main`. Its required macOS 26 and best-effort macOS 15 checks were
  reported successful by the live GitHub audit. The required release platform
  remains macOS 26 on Apple Silicon.
- Runtime PR #24 was merged into the integration branch, not `main`. PRs #25-27
  were merged into the production closure chain, not `main`. An intermediate
  `MERGED` state is not product delivery.
- Existing journals record substantial implementation and historical validation:
  policy, revalidation, best-effort execution, packaging, scanner/IPC, and TUI.
  Several production-wiring and real-host tasks remain open. Their historical
  test records were inspected; no new builds or tests were run for this audit.
- The old post-verification journal blocks ordinary local-directory apply on a
  non-provider authority contract. The revised design keeps action-specific
  ownership gates, but does not require that authority to admit read-only scans
  or treat local residency as ownership. Positive ordinary removal still needs
  the accepted scoped capability contract to pass its production gate.

### Code Preservation Inventory

| Branch / head | Observed worktree state | Role |
| --- | --- | --- |
| `wip/integrate-phase0-6` / `5e12e3b` | Clean | PR #6 base integration |
| `wip/production-revalidation-closure` / `6e72478` | Clean | Committed closure chain; source of the latest architecture text, not the documentation PR base |
| `wip/frontend-product-closure` / `653b985` | Clean | Unintegrated frontend work |
| `wip/stageable-cache-actions` / `5ab8ee0` | Clean | Unintegrated first cache-action work |
| `wip/revalidation-release-postverify` / `12be062` | 21 tracked modifications, 2 untracked entries | Pending release post-verification work; preserve intact |
| `wip/runtime-revalidation-adapters` / `5d2091d` | 10 tracked modifications, 4 untracked entries | Pending runtime adapters; preserve intact |
| `wip/india-product-acceptance` / `32caf3a` | Branch retained, no worktree | Unintegrated acceptance work |

This is a point-in-time inventory, not a cleanup authorization. Do not discard
dirty work, remove unique commits, or absorb another workstream blindly. No
existing worktree was judged safely disposable from this inventory alone.

## Accepted Contract Corrections

- Keep deterministic, independent one-vote rejects; no blended safety score.
- Measure local residency separately from provider ownership. Dataless does not
  imply zero allocation, local volumes do not imply non-provider ownership, and
  uncertainty does not hide otherwise useful measured allocation.
- Metadata-only reads are permitted by default subject to non-materialization,
  TCC, mount, and resource boundaries. Missing mutation evidence blocks the
  affected action, not independently valid scan/reporting work.
- Confirmed provider-owned resident content is a local-copy eviction candidate,
  never an ordinary `rm` candidate. Only verified standalone eviction adapters
  can be stageable; unsupported cases are guided/report-only. No automatic
  unpin, cloud deletion, or deletion fallback is admitted.
- Keep complete APFS owner dependencies and private-versus-conditional reclaim
  separate. A provider eviction needs its own allocation-release postcondition.
- Built-in policy is always present; an optional overlay may be absent. An
  explicitly requested broken overlay permits read-only reporting but blocks
  mutations whose protection scope cannot be verified. Bind effective policy to
  the immutable plan and require fresh consent after relevant changes.
- Keep best-effort execution, optional persistence, explicit force warnings,
  current-user operation, and real-user-data scan/dry-run-only testing.

## Accepted Recovery Sequence

### R0: Reconcile The Delivery Graph

Freeze a branch/commit/dependency map before integrating. Preserve both dirty
worktrees, distinguish duplicated from unique work, and select a reviewable
integration head that includes the current runner baseline. Use append-only
topic commits/merges and the existing worktree+PR workflow; do not default to
history rewriting or blindly merge the stale draft PR. Complete exact-head
review and affected checks before landing each integration layer.

Exit: every retained implementation has an explicit integration destination and
owner; canonical stays clean; no required work is hidden only in an abandoned
worktree or intermediate merged PR.

### R1: Land The Revised Evidence And Policy Contract

First close the ordinary-removal capability matrix: actual platform sources,
supported scope/assumptions, bound lifetime/invalidation, typed failure, and India
production-path counterexamples. Do not add a positive authority implementation
merely to make the first cache fixture executable.

Split read-only collection from mutation eligibility, then integrate local
residency/ownership and built-in/optional-overlay Rules semantics. Freeze the
typed action/evidence/protocol changes once, update both generated languages and
compatibility fixtures together, and project classifications only from Swift.

Exit: the real engine produces useful deterministic plans with typed per-root
and per-candidate uncertainty; ordinary scan is not globally denied by missing
mutation authority. Provider metadata-only/non-materialization and the scoped
local-removal capability are validated separately on India.

### R2: Prove One Complete Production Execution Flow

Use the accepted ordinary cache slice to close the actual engine/frontend seam:
scan -> immutable plan -> explicit selection/edit -> revalidate -> dry-run ->
apply review -> fixture-only apply -> post-verification. Include force-warning
selection, cancellation, partial failure, independent-action continuation,
policy/plan changes, and no-persistence operation. Fake engines remain useful
test aids, not the production acceptance substitute.

Exit: the installed product completes this flow using only test-created temporary
roots for mutation. This is an integration checkpoint, not an MVP release or a
reduction of the full accepted scope.

### R3: Close The Full Adapter And TUI Matrix

For every executable type in accepted-plan Section 15, record production
reachability, evidence/capability gates, protected properties, preview/force
behavior, best-effort outcomes, postconditions, and unsupported boundaries.
Cover generic build/temp, clean linked Git worktrees, `.codex-tmp`, versioned
artifacts, complete APFS release sets, and app-exit cache flows. Keep dirty Git
discard and the already deferred system/package mutations report-only.

For provider local copies, implement the residency-aware plan/display and guided
fallback. Admit actual eviction only for capabilities that independently pass
standalone, sync/activity, identity/access, allocation-release, and preservation
acceptance. Do not promise generic third-party eviction support.

Finish real-engine TUI hierarchy, columns, contextual hotkeys, partial-plan
finalization/resume invalidation, and large-plan behavior against the same
authoritative protocol. The plan remains primary; directory expansion stays
inside an item.

Exit: all required first-version behaviors have explicit accepted evidence, not
merely module completion labels or one successful cache action.

### R4: Validate The Frozen Installed Release

Run affected checkpoint tests, required macOS 26 Apple Silicon gates, and the
installed release flow on `India-mac-mini-m4-hoteng`. Exercise standard and
bounded full-audit on real data only through scan/dry-run; APFS/activity/Provider
fixtures and all actual mutations use test-created roots. Validate packaging,
install/upgrade/rollback/uninstall, protocol compatibility, deterministic output,
performance budgets, and optional persistence failures against the frozen
candidate artifact. Public GitHub macOS runners provide CI evidence; older
deployment targets remain best effort.

Exit: default-branch delivery, independent review, exact-head checks, installed
product acceptance, and release journal agree. No release-complete claim is made
from historical or intermediate-branch evidence alone.

## Parallel Work And Resource Rules

- Start with at most three bounded Luna lanes: evidence/collector seams,
  policy/Rules/adapter coverage, and frontend/IPC/acceptance matrices. Expand only
  for genuinely independent owned work.
- Assign explicit file/module ownership. Shared schema/binding changes have one
  owner and a frozen contract before consumers edit in parallel. Workers must
  preserve and accommodate others' changes.
- Use Luna for high-volume reading, case enumeration, mechanical implementation,
  generated binding updates, and bounded remote test execution. Escalate design
  uncertainty or authority changes to the primary agent rather than letting each
  lane invent a safety contract.
- All builds and tests that would otherwise run locally run on India; use public
  macOS CI where the accepted gate calls for it. Do not use BL as a substitute.
- Run targeted tests by default; widen only at relevant integration/release
  checkpoints. Evidence must name the actual head, host, command, and outcome.
- Reclaim worktrees promptly after their work is integrated or explicitly
  superseded, preserving unique work first. Remove unneeded, exactly identified
  `.build`/build outputs after use; do not run broad cleanup during inventory.
- Keep goals and this task list aligned. The existing full-delivery goal was
  observed paused during the revision; this draft does not claim to resume it or
  mark the full objective achieved. Do not use an unsupported goal transition.
- Ask uncertain product/safety choices in plain conversation, not timed input
  tools. Block a goal only according to the goal tool's repeated-blocker contract.

## Task List

- [x] Audit phase scope and distinguish implementation from installed acceptance.
- [x] Audit current branch/PR/dirty-worktree delivery state without changing it.
- [x] Identify residency/ownership and Rules implementation seams.
- [x] Record accepted contract corrections and the authorized recovery sequence.
- [x] Align and record the three additional authority/eviction/result contracts.
- [x] Record the initial R1 primary-source and production-interface matrix,
  including the unresolved ordinary-removal positive authority.
- [x] Validate the three documentation files and journal frontmatter on India.
- [x] Run the minimal read-only India capability probe on a test-created root.
- [ ] Submit the signed documentation commit as a PR; independent internal
  document review is not a substitute for a formal release/readiness lane.
- [ ] Close the ordinary-removal authority contract before changing eligibility.
- [ ] R0: reconcile and land reviewable delivery layers.
- [ ] R1: integrate revised evidence and Rules contracts.
- [ ] R2: pass the first complete installed production flow.
- [ ] R3: pass the full first-version adapter and real-engine TUI matrix.
- [ ] R4: pass frozen release acceptance and complete the full-delivery goal.

## Evidence And Limits

- This revision used three explicitly requested GPT-6 Luna read-only audit lanes:
  phase/acceptance coverage, branch/PR state, and residency/Rules code seams.
- Follow-up Luna audits collected primary platform sources and concrete ownership
  interfaces. The interface audit found that `mapProviderState` promotes
  `localOrUnindicated` to known-local, while release topology also accepts an
  identifier-absent path in some conditions. These are implementation findings,
  not validated non-provider capabilities; reconcile them before release.
- Architecture source: `6e724784fee48d18a5ec110e5b2416e86ad25fea`; the committed
  accepted-plan file matched `12be062` during comparison. The actual docs-only
  PR base is `18e510655c5b2798a7c9a1c98763053fa122f5f1`. Its macOS 15 deployment
  baseline is preserved. Dirty closure code is not part of this PR.
- Related historical workstreams:
  [runtime positive flow](https://github.com/Joey-Project/diskplan/blob/6e724784fee48d18a5ec110e5b2416e86ad25fea/docs/project_journal/2026/09/2026-09-01-runtime-positive-flow-5e9a17.md),
  [Phase 5 apply](https://github.com/Joey-Project/diskplan/blob/6e724784fee48d18a5ec110e5b2416e86ad25fea/docs/project_journal/2026/08/2026-08-28-phase5-best-effort-apply-a5d210.md),
  [Phase 6 packaging](https://github.com/Joey-Project/diskplan/blob/6e724784fee48d18a5ec110e5b2416e86ad25fea/docs/project_journal/2026/08/2026-08-28-phase6-release-packaging-b61c42.md).
- The initial audit was read-only apart from its isolated documentation draft.
  The authorized delivery follow-up fetched and fast-forwarded canonical main,
  created a docs-only linked worktree, and ran the targeted India checks below.
  It did not merge any implementation branch or mutate existing user data.
- Recorded contract acceptance is not ordinary-removal capability acceptance,
  installed-product acceptance, or completion of the full goal.

### Minimal India Validation

Host: `India-mac-mini-m4-hoteng`, macOS 26.5.1, arm64. Compiler:
`/Applications/Xcode-26.6.0.app/Contents/Developer/Toolchains/XcodeDefault.xctoolchain/usr/bin/swift`.
The scratch repo and probe were scoped to one owner-private `mktemp` directory.
Only the probe's newly created file was written and removed; no existing user
file was opened for content, evicted, or deleted.

- The bundled project-journal helper's `validate` command passed for the new
  journal in the scratch repo. This does not claim a full-repository journal
  validation.
- The three-file documentation check passed: five relative file links resolve,
  Phase 0-6 remain present, and the macOS 15 deployment line is preserved.
  External URLs and all Markdown anchors were not validated by this check.
- `bash -n` and `shellcheck` passed for the temporary probe runner.
- The first Swift compilation rejected an exposed private type. After a local
  declaration fix, the same probe compiled and completed successfully on India.
  This was a targeted standalone probe, not a production-engine or release test.

```text
policy_process_set result=0 errno=0 read=1 read_errno=0
policy_thread_set result=0 errno=0 read=1 read_errno=0
file_stat result=0 errno=0 dataless=false allocated_bytes=4096
volume result=0 errno=0 local=true
provider_identity callback=error domain=NSCocoaErrorDomain code=4
provider_services callback=error domain=NSFileProviderInternalErrorDomain code=0 count=unknown
ownership=unknown authority=report_only
cleanup=removed_task_root
```

Interpretation: the test file occupies local space, and process/thread
non-materialization policy setup/readback succeeded. The provider API outcomes
do not establish non-provider ownership. No real-provider positive/dataless
case, eviction, or ordinary-removal authority was proved. Keep R1's positive
ordinary-removal capability gate open.

Probe source SHA-256:
`091a977d910f4a58c5f3143fc12062f5f9f93516c2bc750b0342acde6262874b`.
Runner SHA-256:
`5f55c4897ba5486f18dbba3fb3d7632bc11dd2a71174a707db6cde8a5d30f007`.
The small source files remain a local R1 experiment; they are not implementation
changes in this documentation PR. Unneeded compiler/cache outputs are disposable
only after the process has reached a verified terminal state.
