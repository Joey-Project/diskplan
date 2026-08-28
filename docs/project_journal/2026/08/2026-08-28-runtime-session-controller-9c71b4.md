---
id: 20260828-9c71b4
title: Runtime Session Controller
status: active
created: 2026-08-28
updated: 2026-08-28
branch: wip/runtime-session-controller
pr:
supersedes: []
superseded_by:
---

# Runtime Session Controller

## Summary

- Install the Swift engine's production runtime handler and keep plan and overlay authority inside
  `DiskplanEngineCore`.
- Bind every `BuildPlan` request to an exact writer-acknowledged final or explicitly allowed partial
  scan receipt.
- Project engine-domain immutable plans and overlays to the protocol without advertising later
  revalidation, apply, artifact, or provisional-plan capabilities.

## Current State

- The production `diskplan-engine` entrypoint installs `RuntimeSessionController`; the injected
  server overload remains available for tests but now requires an explicit handler choice.
- `ScanCoordinator` creates an authority session only when the installed runtime handler supplies
  the authority seam. It finalizes the authority result, awaits the exact final checkpoint writer
  acknowledgement, and publishes a `RuntimeFinalizedScanReceipt` only after that acknowledgement
  succeeds. Writer failure leaves no consumable receipt.
- `BuildPlan` requires exact scan-session, checkpoint, and final-evidence identity. Partial scans
  additionally require the request's explicit partial-plan allowance. A successfully encoded and
  delivered projection becomes the live plan; responder failure cannot commit hidden controller
  state.
- The wire projection is derived from the engine-owned `ImmutablePlan`, policy evaluations,
  release-owner topology, and bounded report-only items. Wire checkpoint identity remains bound to
  the scan's final evidence digest; the immutable plan hash remains the separate domain plan
  identity.
- Overlay edits are applied atomically to the engine-domain immutable overlay. The controller
  checks exact live-plan identity and overlay revision, validates stage/unstage, waiver, note, and
  safe-preset edits, and publishes only the sealed engine projection.
- Runtime capabilities advertise only `plan-projection-v1` and `decision-overlay-v1`. Agent
  authorization, provisional plans, revalidation, dry-run/apply streaming, and artifacts remain
  disabled. Execution previews report mutation as unsupported.

## Task List

- [x] Install the authoritative production runtime business handler.
- [x] Gate finalized and partial receipt publication on the exact final writer acknowledgement.
- [x] Require exact finalized receipt binding and explicit partial-plan allowance.
- [x] Project engine-domain immutable plans into the protocol manifest.
- [x] Keep overlay edits and the safe-stageable preset under engine authority.
- [x] Fail closed for unsupported future Git action projection.
- [x] Advertise only implemented runtime capabilities.
- [x] Add receipt, writer-failure, exact-plan, overlay, and partial-allowance tests.
- [x] Run strict formatting, parser, diff, targeted, engine-target, and stable full Swift gates.
- [x] Close fresh-review findings for prerequisite closure, opaque consent bytes, and canonical raw
  path component binding.
- [x] Bind the full protected namespace, preflight duplicate overlay edits, and emit safe full-root
  display paths.
- [x] Prove projected lineage and prerequisite action IDs exactly match the validated immutable
  plan instead of presentation items.
- [x] Complete fresh post-dynamic review and hand the uncommitted slice to parent integration.

## Handoff

- Phase: the minimum S0/S1 runtime controller slice is implemented and dynamically validated in
  the linked worktree. It remains intentionally uncommitted for parent integration.
- Next step: hand the uncommitted worktree to the integration owner.
- Constraint: production policy evidence currently emits an unverified namespace binding. A legal
  empty plan is therefore expected until authoritative namespace evidence exists; the controller
  does not manufacture executable actions or claim action capabilities.
- Constraint: the current policy authority does not construct Git cleanup actions, and the wire
  projector rejects any future Git action kind until exact Git safety evidence has a protocol
  projection.

## Evidence

- Architecture: `docs/design/accepted-plan.md`.
- Runtime protocol: `proto/diskplan/v1/ipc.proto`.
- Static gates: `swift-format lint --strict`, `swiftc -parse`, and `git diff --check` pass for the
  controller-owned sources and tests.
- Targeted dynamic gate: controller and receipt tests pass 11/11, including both fresh-review
  correction sets and the exact immutable-plan graph mapping invariant.
- Production target gate: `swift build --target DiskplanEngine` passes.
- Stable full Swift gate: 463/463 tests pass after the review corrections.
- The initial fresh static review found one prerequisite-closure defect and two exact-binding
  defects. The corrected preset computes the maximal prerequisite-closed stageable subset; opaque
  consent IDs are length-checked and reversibly encoded without UTF-8 interpretation; namespace
  hashes use nested domain-separated component and ancestor bindings.
- A post-dynamic review found three further exactness and presentation issues. The protected
  namespace projection now binds root and target identities including generation observations, the
  complete root seal, raw target path, and every ordered ancestor identity and seal. Overlay edits
  reject duplicate targets and mixed batch/interactive requests before mutation. Target display
  paths include the raw root and reuse the scanner's control/format/separator-safe byte renderer.
- The final fresh read-only review of the corrected current diff is clean with no P0-P2 findings.
  It rechecked writer-ack receipt reachability, exact BuildPlan and action-graph binding, atomic
  overlay admission, namespace binding completeness, display-path safety, capability honesty, and
  fail-closed future Git projection.
