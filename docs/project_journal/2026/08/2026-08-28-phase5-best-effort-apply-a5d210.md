---
id: 20260828-a5d210
title: Phase 5 Best-Effort Apply
status: active
created: 2026-08-28
updated: 2026-08-28
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
  release components so every owner executes at most once.
- A unit receives an exact read-only JIT snapshot before mutation. Typed JIT findings remain
  distinct and a rejection cannot reach an adapter.
- Independent units continue after adapter failure or cancellation. Dependents are skipped
  when any prerequisite unit is not successful; no rollback is claimed.
- Generic removal uses `/bin/rm` through raw `posix_spawn` argv with descriptor-relative
  no-follow namespace and identity preflights. Force is plan-bound and warned before mutation.
- Shell/TUI events require no persistence. Optional audit failures, including `ENOSPC`, are
  reported but cannot stop cleanup.

## Task List

- [x] Add typed execution units, adapter operations, outcomes, post-verification, and events.
- [x] Add best-effort dependency scheduling and compound release owner deduplication.
- [x] Add per-unit JIT revalidation and mutation firewall boundaries.
- [x] Add raw-byte generic remove with explicit ordinary/force command shapes.
- [x] Add fixture test source for partial failure, cancellation, JIT replacement, APFS owner
  deduplication, authorization replay, audit failure, and temporary-root removal races.
- [ ] Integrate the corrected Phase 4 engine-owned authorization/evidence source and fresh epoch
  contract.
- [ ] Run focused/full Swift gates, journal validation, formatting, and frozen review after the
  upstream Phase 4 gate and local disk-capacity gate reopen.

## Handoff

- Phase: static Phase 5 implementation in progress.
- Next step: signed-merge the corrected Phase 4 frozen head, adapt the coordinator to its
  authority/source/epoch/generation fencing, then run the complete local gate.
- Blocker: builds and tests are intentionally paused while the shared host is in the ENOSPC
  recovery window.

## Evidence

- Accepted architecture: `docs/design/accepted-plan.md`.
- Detailed contract: `docs/design/best-effort-apply.md`.
- Phase 4 boundary: `docs/design/revalidation-and-dry-run.md`.
