---
id: 20260828-7f4c2a
title: Runtime Protocol 1.4
status: active
created: 2026-08-28
updated: 2026-08-28
branch: wip/runtime-protocol-1-4
pr:
supersedes: []
superseded_by:
---

# Runtime Protocol 1.4

## Summary

- Extend the scan-only 1.3 IPC into a sealed engine-authoritative runtime for
  immutable plan projection, decision edits, dry-run, apply review, and
  best-effort execution events.
- Keep every path, classification, stageability result, adapter choice, and
  command preview authored by Swift. Rust retains and returns only opaque IDs,
  user decisions, and exact engine bindings.
- Preserve the protocol 1.3 schema and golden fixtures as compatibility
  evidence while adding independent 1.4 capabilities and fixtures.

## Task List

- [x] Add closed plan/action/target/release-set/blocker/waiver projections.
- [x] Add bounded plan records, chunks, descriptors, manifest, and
  domain-separated digest contract.
- [x] Add atomic revision-bound decision edits and complete acknowledgements.
- [x] Separate `AgentMode` (`off`, `ask`, `auto`) from the deterministic batch
  selection preset.
- [x] Add capability-free dry-run and same-session apply-review projections.
- [x] Add typed JIT, adapter, post-verification, unit, audit, cancellation, and
  terminal execution events.
- [x] Raise both handshakes to minor 1.4 with independently negotiated runtime
  capabilities.
- [x] Make runtime capability advertisement handler-driven and add typed
  unsupported/capability/transport rejection dispatch.
- [x] Generate matching Swift and Rust protobuf sources with the pinned tools.
- [x] Add the Swift-authority projection codec and Rust strict verifier.
- [x] Add a stateful verifier for the exact plan, overlay, dry-run,
  apply-review, and execution predecessor chain.
- [x] Add bounded, typed safety-evidence summaries that bind the richer policy
  evidence without exporting unbounded Git or namespace records.
- [x] Add protocol 1.4 golden frames while retaining all 1.3 fixtures.
- [x] Run focused Swift/Rust, codegen, fixture, and cross-language gates after
  the shared dynamic-test slot is released.
- [x] Close the post-gate review findings for sealed handler emissions,
  canonical raw ingress, exact overlay waivers/stageability, force-warning
  cardinality, Swift prerequisite DAG parity, and systematic negative tests.
- [x] Bind runtime handler output to session-local, writer-confirmed authority
  receipts and invalidate every dependent receipt on predecessor replacement.
- [x] Separate sealed-payload, raw-plan, and framed-envelope byte budgets, and
  fail closed at each public ingress or emission boundary.

## Current State

- `proto/diskplan/v1/ipc.proto` contains the complete 1.4 message and event
  union without adding any inbound path or argv mutation slot.
- Plan, overlay, dry-run, apply-review, and apply-start projections repeat the
  exact scan/checkpoint, plan/evidence, overlay, revalidation, and epoch
  references needed for a consumer to reject a broken chain without deriving
  policy.
- Plan targets are flat records with raw path components plus a separate
  engine-authored display path. Plan manifests bind explicit record, byte,
  blocker, waiver, disposition, and recommendation counts.
- Decision edits can reference only projected IDs. The batch
  `SAFE_STAGEABLE_WITHOUT_WAIVER` preset is engine evaluated and permits an
  explicitly empty selection without degrading dry-run to scan-only output.
- Dry-run exposes no apply capability. Apply review returns a same-session
  registry lookup plus exact binding and force list; the module-private
  capability remains inside Swift.
- A scan-only process advertises only the 1.3 capabilities. An injected
  `RuntimeBusinessHandler` explicitly opts into the 1.4 capabilities it can
  service; transport dispatch otherwise returns a typed unsupported event and
  never manufactures policy, overlay, or execution authority.
- The Rust `RuntimeChainVerifier` retains the verified immutable plan and
  accepted overlay/apply review. It rejects valid-but-foreign projections,
  selected-action or preview substitution, unknown execution units, incomplete
  compound-release references, and terminal authority mismatch.
- Every runtime scan binding now requires the checkpoint ID to equal lowercase
  hexadecimal final evidence SHA-256. Apply terminals repeat review ID and
  review-binding digest even when execution fails before `apply_started`.
- Pinned code generation publishes matching Swift and Rust bindings; the
  source-of-truth check regenerates and compares them successfully.
- Swift transport sealers and Rust strict verifiers now cover bounded plan
  chunks, overlay acknowledgements, canonical dry-run and apply-review
  projections, and canonical execution records. Five Swift-authority runtime
  vectors cover empty selection, force, Git, Codex scope, and version-survivor
  chains and pass strict Rust decode/re-encode verification.
- Strict projection checks also align the Swift/Rust action-count limit,
  cancellation acknowledgement cardinality, mutation postcondition, finding-ID
  uniqueness, and typed finding-detail contracts.
- Action safety evidence now binds the exact frozen policy evidence ID and
  exposes closed target/root/ancestor access-policy and ACL observations,
  scanner-authored root/ancestor seals, opt-in content baseline kind, fixed Git
  worktree observations plus five bounded status counters and closed coverage,
  configured-vs-hint Codex provenance/root/helper coverage, and bounded
  versioned-artifact selector/update/survivor evidence. Raw namespace/Git path
  records and per-version/survivor arrays remain engine-internal and are
  represented by domain-separated canonical digests plus counts.
- Runtime handlers can now emit only `RuntimeBusinessEmission` values whose
  private payloads are re-encoded and revalidated at the single responder send
  boundary. Plan, overlay, dry-run, review, execution, invalidation, and typed
  rejection factories all enforce their per-kind and aggregate byte budgets.
- One authority state is scoped to each negotiated engine session. A plan
  receipt is committed only after the final manifest reaches the actual writer;
  overlay, dry-run, review, and execution emissions must consume the exact live
  predecessor receipt. Plan or overlay replacement clears all descendants,
  execution consumes its review binding, and duplicate or out-of-order request
  completion is rejected without letting a handler supply predecessor records
  or force-warning IDs.
- Handler completion and handler failure share one atomic responder
  terminalization path. The broker flush barrier distinguishes an enqueued
  event from a successfully written event, preventing authority state from
  advancing when output fails. Midstream cancellation remains a typed
  unsupported operation for this first complete-batch execution seam rather
  than advertising cancellation semantics it cannot honor.
- Runtime emission now uses a two-phase, session-owned authority transaction:
  prepare creates an unforgeable in-process token under the authority lock,
  writer I/O and the broker flush run after releasing that lock, and only an
  exact token/request match can commit the receipt afterward. A failed or
  partial write aborts the token without publishing a plan or successor
  receipt, while the active request continues to reject concurrent authority
  transitions fail closed.
- Runtime authority admission is single-flight before invoking a handler that
  may retain its responder. A confirmation atomically claims the exact live
  review and force set before mutation code can run; duplicate confirmation or
  any conflicting plan/overlay/review transition is rejected before handler
  dispatch. Terminal rejection or handler failure conservatively consumes the
  claimed review, and consumed review bindings remain monotonic for the full
  runtime session under an explicit bounded budget.
- Overlay rejections bind the exact live projection and base revision as well
  as the identifiers in the triggering edit. Typed action and waiver rejection
  codes are checked against the authoritative plan's exact stageability and
  required-waiver set; duplicate authoritative action IDs fail closed.
- Execution events may reference only selected actions and compound release
  sets whose complete member set is selected. A completed execution consumes
  its review binding so the same review cannot be restored or replayed. JIT
  rejection outcomes must exactly equal the action unit or the authoritative
  union of the compound unit's release-set members; a self-consistent but
  foreign nested revalidation payload is rejected by both Swift and Rust.
- The Rust chain verifier consumes successful execution reviews and exposes a
  canonical-envelope-only rejected-confirm transition. That transition binds
  request and event sequence, request ID, runtime session, review ID/digest,
  and the exact confirmed force set before clearing the review, keeping
  consumer lifecycle parity with Swift authority failures.
- Swift and Rust now admit runtime protobufs from original sealed bytes. Both
  reject non-byte-identical decode/re-encode results; Swift additionally walks
  retained unknown fields recursively because SwiftProtobuf preserves them,
  while Prost's byte-identity check rejects discarded unknown fields at any
  nested level.
- Overlay chain validation now rejects selected report-only actions and
  requires the complete authoritative waiver set exactly once. Execution
  sealing/verifying requires every review force-warning action exactly once,
  and Swift plan projection validation now rejects prerequisite cycles.
- Negative coverage now includes envelope and nested unknown fields, unknown
  closed evidence states, evidence byte bounds, not-stageable selection,
  missing/duplicate waivers, prerequisite cycles, and force-warning
  omission/duplication.

## Handoff

- Phase: schema, capability-honest dispatch seam, generated bindings, sealed
  codecs, stateful verifier, compatibility fixtures, and dynamic gates complete.
- Next step: runtime integration can implement the injected business handler
  and advertise only the capabilities it actually services.
- Blocker: none in the protocol workstream.

## Evidence

- Accepted architecture: `docs/design/accepted-plan.md`.
- Runtime wire contract: `proto/README.md`.
- Revalidation contract: `docs/design/revalidation-and-dry-run.md`.
- Apply contract: `docs/design/best-effort-apply.md`.
- Static syntax: pinned `protoc 35.1` emitted a descriptor set for the updated
  schema.
- Static source checks: `swift-format`, `cargo fmt`, `bash -n`, `shellcheck`,
  `git diff --check`, and the project-journal validator pass for the changed
  files.
- Post-review static checks: strict `swift-format lint` on the touched Swift
  runtime/fixture/test files, `cargo fmt --all -- --check`, and
  `git diff --check` pass. The authority-receipt, rejection-binding, JIT
  membership, and budget-domain hardening received a clean static re-review.
- Pinned `scripts/proto-codegen.sh check` passes after publishing the generated
  Swift and Rust sources with `protoc 35.1`; generated oneof lint attributes
  remain owned by the pinned Rust codegen input rather than hand edits.
- Apple Swift 6.3.3 on arm64 macOS 26 builds the serial targeted gates.
  `DiskplanCoreTests` passes 17 tests and `DiskplanEngineCoreTests` passes 31
  receipt, JIT, canonical-ingress, budget, and negative tests.
- After merging the latest integration work, the bounded EngineCore gate
  passes 73 tests. Targeted coverage confirms bounded semantic backpressure,
  exact final-scan writer acknowledgement, nonblocking authority admission
  during a stalled writer, and plan-receipt nonpublication after writer
  failure. The runner completed in 31.496 seconds with a verified quiescent
  process group and an untruncated 17,752-byte log.
- Rust 1.95.0 passes `cargo check --locked --workspace`, all-target Clippy with
  warnings denied, and formatting. `cargo test --locked -p diskplan-proto`
  passes four unit tests plus four runtime-golden tests; the golden test covers
  all five positive runtime vectors and systematic negative mutations.
- The CI-script source checks pass 12 tests.
- Protocol 1.3 and 1.4 fixture authority checks pass; the five 1.4 files contain
  56 framed records. `scripts/test-cross-language.sh` passes all 10 exact
  Rust-to-Swift integration cases plus canonical, 1.3, and 1.4 fixture checks.
