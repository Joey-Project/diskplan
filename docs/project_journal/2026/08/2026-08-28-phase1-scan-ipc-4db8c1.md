---
id: 20260828-4db8c1
title: Phase 1 Scan IPC
status: active
created: 2026-08-28
updated: 2026-08-28
branch: wip/phase1-scan-ipc
pr:
supersedes: []
superseded_by:
---

# Phase 1 Scan IPC

## Summary

- Stream the authoritative Swift scanner evidence over protocol minor 1.3
  without adding Phase 1 classification or plan construction.
- Preserve raw path bytes, event provenance, scan-session identity, and typed
  uncertainty across the Swift engine and Rust session boundary.
- Keep the engine session ready after scan finalization so later planning phases
  can reuse the negotiated process.

## Task List

- [x] Add `scan-stream-v1` and `raw-path-bytes-v1` while retaining
  `scan-control-v1`.
- [x] Generate matching Swift and Rust protocol bindings and compatibility
  fixtures.
- [x] Add an asynchronous Swift scan producer and one serial stdout broker.
- [x] Bound semantic backpressure and coalesce only pending progress telemetry.
- [x] Chunk retained checkpoint evidence below the frame cap and verify its
  canonical manifest before exposing ready/finalized evidence.
- [x] Project scanner nodes, roots, coverage, collector configuration, and global
  facts without changing scanner safety semantics.
- [x] Preserve raw path bytes separately from engine-authored display strings.
- [x] Add checkpoint, provisional-evidence checkpoint, partial-finalization, and
  cancellation flows without exposing plan symbols.
- [x] Validate event sequence, request provenance, and stable scan-session
  identity in Rust.
- [x] Keep the Rust/Swift session alive after finalization and cancellation.
- [x] Run broker pressure, progress coalescing, control flow, final evidence,
  cancellation, and cross-language session reuse.
- [x] Update the protocol contract and project journal.
- [x] Validate scanner/IPC canonical raw-root parity, including exact `/` and
  rejection of lexical aliases.
- [x] Validate finite O(1) inbound control admission and priority EOF shutdown
  under a control flood.
- [x] Author immediate descriptor-open access-policy sealing and bounded
  cancellation-tail shutdown repairs with regression coverage.
- [x] Author reproducible protocol 1.3 zero/single/multi-chunk golden fixture
  sources plus exact Swift/Rust validation and negative cases.
- [x] Generate the checked-in protocol 1.3 frame vectors and run the follow-up
  dynamic gates after the test slot is released.

## Current State

- The Swift scanner runs on a dedicated thread and reaches stdout only through
  the serial event broker.
- Natural events use request ID zero plus a stable scan-session ID; direct
  acknowledgements keep their originating non-zero request ID.
- Phase 1 uses a dedicated provisional-evidence control and rejects the retained
  Phase 0 provisional-plan control without emitting plan symbols.
- Start-scan setup failures retain a typed setup code in addition to their broad
  control rejection class.
- Semantic events are lossless and bounded. Only a contiguous pending progress
  run can be replaced by newer telemetry.
- Inbound controls use a separate 256-entry FIFO ring. Overflow is rejected
  with a typed capacity code, while out-of-band shutdown preempts queued
  controls and drains their bounded remainder in request order.
- IPC setup calls the scanner-owned canonical raw-root parser on the original
  bytes, preserving exact `/` while rejecting relative, empty, NUL-containing,
  trailing-separator, repeated-separator, dot, and dot-dot forms.
- Retained checkpoint nodes use lossless, contiguous, digest-bound chunks. The
  manifest binds explicit entry/byte budgets, ordered chunk descriptors, the
  checkpoint coverage/frontier payload, and the final evidence hash; Rust
  rejects a duplicate, gap, interleave, digest mismatch, or aggregate mismatch
  before the checkpoint reaches the reducer.
- `ScanFinalized` ends the scan worker but not the engine session. The Rust TUI
  retains that checkpoint and does not enable `q` exit on the earlier terminal
  state-change event.
- Shutdown now drains frames while concurrently waiting for the child. After a
  cancelled finalization, only the unique contiguous `ScanCancelled` tail is
  accepted before clean EOF; all other extra or malformed frames remain errors.
- The Swift-authority fixture specification and generator cover zero-, single-,
  and multi-chunk ready/finalized streams. The checked-in exact frames match the
  authority and pass independent Swift and Rust semantic validation.
- The Phase 1 stream contains evidence only. Candidate classification, reclaim
  estimates, actions, and immutable plan production remain later-phase work.

## Handoff

- Phase: frozen integrated advisory follow-up on signed head
  `65d77cfb3566dd5f1f382cf0ad7fc65730b29f3f`.
- Next step: freeze the signed clean repair checkpoint and hand its exact range
  to the next frozen review lane.
- Follow-up: controlled File Provider and APFS volume-group fixtures remain in
  the India acceptance lane; the local capability gate reports them unavailable.
- Blocker: none.

## Evidence

- Accepted architecture: `docs/design/accepted-plan.md`.
- Scanner contract: `docs/design/scanner-core.md`.
- Protocol contract: `proto/README.md`.
- Swift projection and broker tests are authored for byte-preserving paths,
  telemetry-only coalescing, lossless semantic order, bounded producer
  backpressure, and typed setup projection.
- Rust reducer and session tests are authored for accepted control transitions,
  Phase 1 evidence-only events, request/session provenance, final-checkpoint
  retention, and terminal behavior.
- Cross-language cases are authored for pause, resume, checkpoint, provisional
  evidence, deterministic root failures, typed setup rejection, partial
  finalization, cancellation, and post-finalization session reuse.
- `swift test --disable-automatic-resolution`: 104 tests passed.
- `cargo test --locked --workspace`: 82 tests passed, 9 cross-language tests
  intentionally ignored by the ordinary workspace invocation.
- `scripts/test-cross-language.sh`: 9 ignored-process cases passed and the
  canonical Swift-authority fixture matched.
- `cargo fmt --all -- --check`, `cargo check --locked --workspace --all-targets`,
  and `cargo clippy --locked --workspace --all-targets -- -D warnings` passed.
- `scripts/proto-codegen.sh check` confirmed that both tracked generated sides
  match the pinned generators.
- Internal advisory findings were closed with fail-closed legacy-finalization
  handling, setup-time root-binding budget admission, exact checkpoint frontier
  validation, and regression coverage for each case.
- Follow-up tests passed for canonical raw-root parity, finite 10,000-request
  flood admission, FIFO drain order, priority EOF stop, typed Rust capacity
  rejection, lexical-alias setup rejection, and exact `/` setup admission.
- `scripts/test-macos-capabilities.sh` passed 32 focused macOS tests plus the
  probe self-test after scanner-core integration.
- The frozen-review follow-up passes 48 focused scanner tests, 2 Swift and 2
  Rust protocol 1.3 golden-vector tests, 2 Rust shutdown-tail unit tests, and the
  Swift-authority fixture reproduction check.
- The complete Swift suite passes all 109 tests. The Rust workspace passes 86
  ordinary tests, with 10 process cases intentionally ignored by that invocation.
- `scripts/test-cross-language.sh` passes all 10 Swift/Rust process cases,
  including cancel-finalize-q shutdown with the terminal tail left in the
  capacity-one decoder, plus the canonical Swift-authority fixture.
- `scripts/test-macos-capabilities.sh` again passes 32 focused macOS tests plus
  the probe self-test; controlled File Provider and APFS volume-group fixtures
  remain unavailable locally and reserved for India.
- `scripts/proto-codegen.sh check`, `scripts/protocol13-fixtures.sh check`, Rust
  format/check/clippy, strict Swift format lint, Bash syntax, and ShellCheck pass.
