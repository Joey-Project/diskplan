---
id: 20260828-8d3a41
title: Runtime Batch CLI
status: active
created: 2026-08-28
updated: 2026-08-29
branch: wip/runtime-batch-cli
pr:
supersedes: []
superseded_by:
---

# Runtime Batch CLI

## Summary

- Implement the exact non-interactive India acceptance argv shape while
  preserving the audit root as raw filesystem bytes.
- Keep the Rust batch boundary fail-closed until the engine proves both an
  authoritative immutable plan and a complete dry-run over its selected actions.
- Emit bounded deterministic NDJSON and independently validate the terminal
  proof in the host-local India runner.

## Task List

- [x] Add an exact-once parser for batch, full-audit, dry-run, no-history,
  no-audit-file, and one absolute raw root.
- [x] Reject unknown, repeated, persistence-capable, mutation-capable, and
  incomplete combinations with usage status 64.
- [x] Add a frontend-owned batch engine trait and typed completion proof.
- [x] Reject scan-only output and inconsistent plan/dry-run action coverage.
- [x] Add bounded deterministic start and terminal NDJSON records.
- [x] Add explicit stable batch exit statuses.
- [x] Make India acceptance reject empty, scan-only, mutation-reporting, and
  internally inconsistent reports independently of subprocess status.
- [x] Add parser, fake-client, reporter, and validator regression coverage.
- [x] Close scan, evidence, plan, overlay, and dry-run authority transitions
  with exact repeated ID/hash bindings.
- [x] Bind India report validation to the supervisor byte count and digest using
  one sealed no-follow descriptor read.
- [x] Map batch sibling-engine setup failures into stable exit classes without
  changing interactive or handshake behavior.
- [x] Require the scan checkpoint ID to be the lowercase final-evidence digest
  in both the Rust completion proof and India validator.
- [x] Preserve sibling unavailable, invalid identity/protocol, and other I/O as
  typed setup failures before selecting batch exit status.
- [x] Align the protocol 1.4 seam so plan, overlay, and dry-run references each
  repeat the complete scan-evidence four-tuple.
- [x] Add one mixed scan/runtime transport with global request and event
  sequence validation plus request-kind correlation.
- [x] Connect batch scan finalization to verified plan, acknowledged overlay
  preset, and sealed dry-run receipts without local policy reconstruction.
- [x] Connect the TUI driver to the same transport and replace product-path
  local staging with pending edits committed only after an engine overlay ack.
- [x] Make `p` finalize the scanned prefix before building an immutable partial
  plan, and keep unsupported apply review typed and fail-closed.
- [ ] Merge the protocol 1.5 preview extension and require its raw working
  directory/path-race binding before enabling mutation review.
- [ ] Pass the focused Rust, Python, and mixed-transport dynamic gates.
- [x] Run focused Rust and release-runner tests after the integration workstream
  releases the shared dynamic test slot.
- [x] Re-run focused and full gates for the advisory follow-up after the shared
  dynamic test slot is released again.
- [x] Re-run focused and full gates for the second review follow-up after the
  shared dynamic test slot is released.

## Current State

- Batch mode never initializes the TUI or decodes the raw root as UTF-8.
- The frontend now carries scan and runtime events over one framed session with
  one request-ID high-water mark and one contiguous event sequence. Runtime
  bodies must match the exact pending request kind and stable runtime session.
- Batch finalization now requests the engine-authored plan, applies the
  `SAFE_STAGEABLE_WITHOUT_WAIVER` edit, verifies the complete predecessor chain,
  and only then accepts a dry-run projection. Missing capabilities and typed
  unsupported responses retain unavailable status 69.
- `BatchEngineClient` is the narrow seam for the version-aware mixed transport. A
  successful result must carry bounded scan/plan/dry-run identifiers, a nonzero
  SHA-256 plan hash, a separate engine-acknowledged overlay ID/hash, exact
  selected-action coverage, and zero mutation attempts.
- The request selects the engine-owned `safe-stageable-without-waiver` preset;
  Rust does not derive a selection from plan dispositions. Terminal proof also
  binds zero history and audit-file persistence attempts.
- Total plan actions and engine-authored cleanup candidates remain distinct;
  overlay selection is checked against the former so connected prerequisites do
  not make a valid selection appear larger than its candidate subset.
- The India report validator requires the exact no-persistence request binding
  followed by one authoritative terminal result.
- Advisory follow-up closes every authority edge with exact IDs and SHA-256
  bindings; plan, overlay, and dry-run may not rely on count agreement alone.
- India validation parses the supervisor's retained byte count and digest, then
  uses one no-follow descriptor and pre/post object/access/size seals for its
  bounded report read. It never performs a second pathname read.
- Batch sibling-engine setup maps unavailable, invalid identity/protocol, and
  other I/O into stable statuses 69, 70, and 74; interactive and handshake setup
  retain status 1. Exit selection consumes the typed failure rather than
  reinterpreting semantic rejection through `io::ErrorKind`.
- A checkpoint ID is accepted only when it is the lowercase hex encoding of the
  final evidence SHA-256, and India independently rechecks the same relation.
- Overlay and dry-run references repeat the complete scan-evidence four-tuple;
  exact plan-reference comparison therefore closes every later authority edge.
- Opaque runtime identifiers are retained as bytes and hex-encoded only at the
  NDJSON boundary. Agent modes `off`, `ask`, and `auto` are accepted explicitly,
  with `ask` as the CLI default.
- The TUI maps only a strictly verified wire plan into its plan-first model.
  Stage/unstage keys enqueue engine edits; selection and revision change only
  after a sealed overlay acknowledgement. Dry-run is real. Apply review remains
  a typed unavailable operation on protocol minor 1.4 and also fails closed on
  1.5 until the raw working-directory/path-race preview receipt is present.
- The Rust adapter additionally proves that every plan repeats the exact scan
  session, checkpoint, checkpoint-evidence, and final-evidence binding from its
  request. Interactive overlay acknowledgements must advance exactly one
  revision and reproduce the requested edit delta; the engine-owned batch
  preset remains a sealed policy transform rather than frontend reconstruction.
- Target projection is indexed and assembled bottom-up instead of recursively
  rescanning the full target set. The presentation boundary rejects depth above
  512, and the UI permits only one unacknowledged overlay edit at a time.

## Evidence

- Static validation on 2026-08-29 passed `rustfmt --edition 2024 --check`, Python AST parsing
  for the changed India validators, and `git diff --check`.
- `cargo check -p diskplan --all-targets` passed for the connected adapter. The
  focused `event_sequence_tests` module then passed 20/20, including mixed
  scan/runtime sequencing, reserved confirmation rejection, terminal request
  retirement, and the shared request-ID high-water mark. No Swift build/test has
  run for this connected adapter.
- A fresh-context read-only review of `76a2ebb..158edb8` found four authority or
  boundedness gaps: request-to-plan scan binding, edit-to-overlay transition,
  recursive target assembly, and duplicate pending overlay edits. The static
  follow-up closes all four and adds focused regression coverage; its dynamic
  checks must run on `India-mac-mini-m4-hoteng` under the current host policy.

- `cargo fmt --all -- --check` completed successfully.
- Second-review-focused Rust tests passed all six batch cases, including
  seventeen exact authority-chain mutations and the protocol-failure exit
  contract. Typed setup mapping and real nonzero/mismatched identity probes also
  passed their focused tests.
- The final complete `diskplan` package rerun passed 85 library, seven launcher,
  and nine fake-engine tests; ten real Swift-engine cases remained intentionally
  ignored for the cross-language gate.
- `cargo check --locked -p diskplan --all-targets` and warning-free package
  Clippy completed successfully.
- The India report validator passed all seven Python unit tests, including
  noncanonical checkpoint IDs; empty and scan-only output; mutation,
  persistence, authority, byte-count, and digest mismatches; extra and duplicate
  keys; and no-follow symlink rejection.
- `bash -n` and ShellCheck completed successfully for the changed India runner.
- No release archive, lifecycle, cross-language, or India host command ran in
  this focused runtime batch gate.
- The first advisory full-package run had one transient `ENOENT` while the
  existing process-group timeout test waited for its descendant PID record. An
  exact rerun passed 1/1 in 2.28 seconds, and the immediately following complete
  package rerun also passed that test and every other enabled test.
- The second review follow-up passed its focused and complete package gates,
  including canonical-checkpoint, full scan-reference, typed-setup, and
  protocol-exit negative cases.

## Handoff

- Protocol owner: land the protocol 1.5 preview receipts without changing 1.4
  canonical fixtures or enabling mutation on a downgraded session.
- Integration owner: merge that boundary, run the focused tests, and replace
  `status: active` with completed only after the authoritative adapter and exact
  India-shape gate pass.
