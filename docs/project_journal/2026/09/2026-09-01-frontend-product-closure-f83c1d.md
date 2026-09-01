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
- A provisional scan checkpoint may produce a reversible plan. Resume invalidates that plan, and
  only the explicit freeze command converts the checkpoint into immutable partial evidence.
- The plan-first TUI opens the authoritative apply review with `A`, shows force warnings at staging
  and final review, requires explicit confirmation or back, consumes the Protocol 1.6 execution
  stream without blocking input, and sends at most one queued or immediate cancellation request.
- The driver alone allocates engine request IDs and projects scan-control acknowledgements back to
  reducer-local correlations. Typed confirmation mismatch consumes its review only through the
  sealed verifier; pre-claim rejection retains the review, and late cancel terminals remain valid.
- Help aliases, filtering, dry-run, scan progress, pause, resume, and quit bindings remain available;
  terminal teardown continues to restore raw mode, alternate-screen state, and cursor visibility.

## Next Steps

- Land this completed frontend slice through the repository PR workflow with the related Swift
  runtime and installed-product integration work.

## Evidence

- Design authority: `docs/design/accepted-plan.md`.
- On `India-mac-mini-m4-hoteng` (macOS 26.5.1, Apple Silicon), `cargo test -p diskplan`
  passed 119 library tests, 7 executable tests, and 9 runnable integration tests; 10 existing
  cross-language cases remained explicitly ignored because they require `DISKPLAN_ENGINE_BIN`.
  Bounded output SHA-256: `a2946e7574a283a54623fc6373f56037c4d1c3e1227b2a77b5938744245e1c6a`.
- On the same host, `cargo clippy -p diskplan --all-targets -- -D warnings` passed. Bounded output
  SHA-256: `9b58de029fc7491915d11d7818c6b12f1897caf30a4f1328e905808a7ec1087d`.
- The internal read-only review found four P1/P2 issues in request-ID ownership, sealed rejection
  verification, late cancellation response handling, and filter help-key precedence. After the
  fixes, the focused rereview reported no remaining P0-P2 findings.
- Local validation was static only: `cargo fmt --all -- --check`, `git diff --check`, and the project
  journal validator passed.
