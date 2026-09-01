---
id: 20260901-f83c1d
title: Installed CLI and TUI Product Closure
status: completed
created: 2026-09-01
updated: 2026-09-01
branch: wip/frontend-product-closure
pr:
supersedes: []
superseded_by:
---

# Installed CLI and TUI Product Closure

## Summary

- Close the installed Rust frontend over the accepted deterministic scan, immutable plan plus
  editable overlay, authoritative apply-review, confirmation, cancellation, and verified execution
  stream contracts without duplicating Swift safety classification.

## Current State

- Batch mode accepts `standard` and `full-audit`; interactive mode defaults to `standard` with
  agent mode `ask`, while `off`, `ask`, and `auto` remain explicit choices.
- Typed agent-provider unavailability retries plan construction once with agent mode `off`; the
  deterministic authoritative plan remains available and every other rejection fails closed.
- A provisional scan checkpoint enters a reversible checkpoint-only UI without claiming plan
  authority. Resume continues scanning; explicit freeze first obtains the Swift controller's
  writer-acknowledged final partial receipt, and only then builds an immutable partial plan.
- The plan-first TUI opens the authoritative apply review with `A`, shows force warnings at staging
  and final review, requires explicit confirmation or back, consumes the Protocol 1.6 execution
  stream without blocking input, and sends at most one queued or immediate cancellation request.
- The driver alone allocates engine request IDs and projects scan-control acknowledgements back to
  reducer-local correlations. Typed confirmation mismatch consumes its review only through the
  sealed verifier; pre-claim rejection retains the review, and late cancel terminals remain valid.
- Every queued plan mutation carries the exact plan, overlay, review, or execution generation seen
  by the UI. A bounded response demultiplexer replays earlier invalidations before a synchronous
  response; only exact stale, invalid-state, or unavailable codes are recoverable, while malformed,
  internal, unknown, and confirmation-mismatch responses continue to fail closed.
- Execution admission applies the canonical event-count and framed-byte limits before retaining a
  record, including only the protocol's terminal slack. A cancellation response must contain its
  typed acknowledgement and exactly mirror the confirmed stream before terminal authority retires.
- Help aliases, filtering, dry-run, scan progress, pause, resume, and quit bindings remain available;
  terminal teardown continues to restore raw mode, alternate-screen state, and cursor visibility.

## Next Steps

- Land this completed frontend slice through the repository PR workflow with the related Swift
  runtime and installed-product integration work.

## Evidence

- Design authority: `docs/design/accepted-plan.md`.
- On `India-mac-mini-m4-hoteng` (macOS 26.5.1, Apple Silicon; Cargo 1.98.0),
  `cargo test -p diskplan` passed 123 library tests, 7 executable tests, and 9 runnable integration
  tests; 10 existing
  cross-language cases remained explicitly ignored because they require `DISKPLAN_ENGINE_BIN`.
  Bounded output SHA-256: `ba7db613e9ee3e61f62916d91f5addf9bb15dd16a6fcb95627a554481d9cec65`.
- The subsequent exact rejection-allowlist and response-routing regression lane,
  `cargo test -p diskplan runtime_client::tests`, passed 6 tests on the same host. Bounded output
  SHA-256: `7f3c528081a9cea725302027758a4bee78c731ec58c6ba215daced14e65fb6bb`.
- On the same host, `cargo clippy -p diskplan --all-targets -- -D warnings` passed for the final
  source delta. Bounded output SHA-256:
  `f7afd0a79f1a14658a4836ced5d7a01df7ba6a4cda5583148d8a317f24819e50`.
- Fresh whole-range review found provisional-authority, global sequence, visible review/execution
  binding, cancellation mirror, incremental admission, stale-command, synchronous response-routing,
  and rejection-classification issues. After the fixes, a fresh final review of the complete delta
  reported no remaining findings.
- Local validation was static only: `cargo fmt --all -- --check`, `git diff --check`, and the project
  journal validator passed.
