---
id: 20260828-7c0a91
title: Phase 0 Ratatui Shell
status: active
created: 2026-08-28
updated: 2026-08-28
branch: wip/phase0-tui-shell
pr:
supersedes: []
superseded_by:
---

# Phase 0 Ratatui Shell

## Summary

- Implements the minimal plan-first Ratatui frontend and Swift scan-control protocol from `docs/design/accepted-plan.md`.
- Keeps Swift authoritative for scan facts and provisional-plan projections; Rust performs presentation and input routing only.
- Uses a deterministic, filesystem-free Phase 0 engine fixture. The real read-only scanner remains a Phase 1 workstream.

## Current State

- Protocol minor 1.2 defines typed start, pause, resume, provisional-plan, cancel, acknowledgement, progress, projection, invalidation, and terminal events.
- Every engine event has a request ID and strictly monotonic event sequence; the Rust session validates every wire event before the UI bridge coalesces a contiguous progress run to its latest value.
- Semantic acknowledgements, state changes, projections, and terminal events use bounded lossless delivery. The reducer accepts only explicitly proven progress gaps; malformed acknowledgements or state values terminal-fail the session and stop the driver.
- Rust tracks one finite active-request lifecycle: every non-ack event must bind to its known non-zero origin, accepted control/state transitions are exhaustive, and plan invalidation must name the exact current plan.
- Swift uses a constant-space monotonic request-ID high-water mark. Malformed envelope/request embedding mismatches consume IDs through the same duplicate-aware path as ordinary requests.
- The TUI is implemented as a pure reducer plus renderer and replaceable event source. It has wide, medium, compact, and 1x1-safe layouts.
- `q`, `Space`, `p`, `r`, `?`, and the scan-only `/` help alias follow engine acknowledgement barriers. Repeat/release key events and duplicate pending controls are ignored.
- Engine supervision remains bounded: cancellation waits for the terminal event and direct-child/process-group cleanup; terminal state restoration is covered by a real PTY smoke path.

## Task List

- [x] Extend the versioned IPC schema and regenerate both language bindings.
- [x] Add the Swift deterministic scan-control state machine and tests.
- [x] Add the Rust typed session API, pure reducer, renderer, event source, and engine driver.
- [x] Add fixed-buffer snapshots, resize matrix, scripted barrier session, and real Swift integration.
- [x] Complete the final local validation and hand the frozen branch to review/PR orchestration.
- [ ] Run the final macOS 26 Apple Silicon acceptance on `India-mac-mini-m4-hoteng` as part of the parent Phase 0 gate.

## Handoff

- Phase: implementation and local validation complete; ready for the parent workstream's independent review and PR readiness flow.
- Next steps: freeze and review this worktree range, then run the remote macOS 26 acceptance at the parent Phase 0 gate.
- Blockers: no implementation blocker. The remote India-host acceptance intentionally remains owned by the parent Phase 0 release gate.

## Evidence

- Accepted design: `docs/design/accepted-plan.md`.
- `swift test` passed 16 tests, including monotonic high-water, malformed-request consumption, duplicate/out-of-order rejection, and control transition suites.
- `INSTA_UPDATE=no cargo test --locked --workspace` passed on the final worktree state: 23 TUI/session library tests (including exhaustive accepted-transition and event-provenance tables, exact/stale/unknown invalidation, bounded semantic backpressure, progress-flood coalescing, checked request/event-ID exhaustion, driver-stop cleanup, six unchanged snapshots, and the complete 1x1 through 160x50 resize matrix), 9 fake-engine process tests with 4 explicit real-engine ignores, 8 core tests, 5 canonical tests, and 20 generated-source publisher tests.
- `cargo fmt --all -- --check`, `cargo check --locked --workspace --all-targets`, and `cargo clippy --locked --workspace --all-targets -- -D warnings` passed.
- `scripts/test-cross-language.sh` passed after the final review fixes: four real Swift/Rust process tests, including the full scan-control loop and envelope/embed mismatch ID consumption, plus canonical fixture drift.
- `scripts/test-tui-pty.sh` passed after the final review fixes: 80x24 contextual-help content, pause acknowledgement, provisional-plan identity, resume invalidation, single cancel, terminal cancellation, alternate-screen enter/leave, exact pre/post terminal modes, restored canonical input/echo, and process exit.
- `scripts/proto-codegen.sh check` passed with the pinned generator set.
- `scripts/test-deployment-target.sh` verified the Rust CLI as `aarch64-apple-darwin` with Mach-O `minos 14.0`.
- Bash syntax and ShellCheck 0.11.0 passed for all scripts, including the new PTY smoke test.
