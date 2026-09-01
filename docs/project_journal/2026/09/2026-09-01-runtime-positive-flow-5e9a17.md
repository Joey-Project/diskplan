---
id: 20260901-5e9a17
title: Runtime Positive Execution Flow
status: active
created: 2026-09-01
updated: 2026-09-01
branch: wip/runtime-positive-flow
pr:
supersedes: []
superseded_by:
---

# Runtime Positive Execution Flow

## Summary

- Replace the controller's blanket dry-run/apply/cancel rejection with an optional, fail-closed
  execution backend seam and an engine-owned positive dispatcher.
- Keep exact plan, overlay, review, epoch, force-confirmation, execution-ID, and single-use apply
  authority bindings inside Swift EngineCore.
- Admit one exact midstream cancellation while preserving a sealed best-effort terminal report for
  both the original confirmation and cancellation requests.

## Current State

- EngineCore defines immutable preparation context, a package-only prepared attempt, a
  controller-owned one-shot authority box, and sealed run/tail handles without importing
  DiskplanExecution or exposing raw argv/path mutation authority.
- RuntimeSessionController advertises dry-run and execution capabilities only when a backend is
  installed. An absent production bridge remains typed unavailable and fail-closed.
- Apply-review publication installs its exact one-shot box inside the responder transaction before
  the review becomes visible and restores the predecessor on writer or commit failure. Exact
  confirmation consumes the box before backend entry; stale, mismatched, and replayed confirmation
  cannot invoke the backend again.
- The registered execution ID becomes visible through an early `apply_started` prefix. One exact
  cancellation mirrors the same prefix, appends one typed acknowledgement, cancels the retained
  run, and gives both pending requests the same sealed terminal stream.
- Once a validated run handle exists, every post-start error requests cancellation and awaits the
  same non-throwing sealed tail. The run remains retained through the joint confirm/cancel terminal
  commit, while a finishing authority phase rejects late cancellation without token competition.
- EngineServer no longer pre-rejects cancellation and calls the handler lifecycle before closing
  the broker at EOF. Controller teardown cancels and waits for all retained asynchronous work.

## Next Steps

- Complete fresh frozen-range review and address any P0-P2 findings.
- After the concrete revalidation collector lands, add the executable composition-root conformer
  that imports EngineCore and DiskplanExecution and injects the real backend into production main.

## Evidence

- Base: `23718ae6c898a5bc42534bced9fec82ff54c033d`.
- Static checks: strict Swift formatting, Swift parser validation, and `git diff --check`.
- India focused gate: `swift test --filter DiskplanEngineCoreTests` passed all 96 tests under the
  bounded supervisor in 13.793 seconds; process-group verification and quiescence both passed.
  Log: `/Users/cisco/Program/GitHub/diskplan/.codex-tmp/india-gates/runtime-positive-enginecore-retry6.log`;
  bounded output SHA-256: `17256cbf1555d74c76c9de275295fdfd811d0477718aec2f74e0920ab614c470`.
- India review-fix gate: the same command passed all 103 tests, including the external-package
  compile-surface fixture, under the bounded supervisor in 15.011 seconds; process-group
  verification and quiescence both passed. Log:
  `/Users/cisco/Program/GitHub/diskplan/.codex-tmp/india-gates/runtime-positive-review-fixes-4.log`;
  bounded output SHA-256: `1d9b099f7d4163fb699ba94daeeba1d66aa772e9260e0e717ccbde015e049800`.
- Focused fixtures cover absent-backend fail-closed behavior, exact dry-run binding, single-use
  confirmation/replay, wrong execution-ID cancellation, mirrored cancelled terminal streams, and
  retained-run teardown.
