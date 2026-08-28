---
id: 20260828-9c2e6f
title: Phase 1 Deterministic Scanner Core
status: active
created: 2026-08-28
updated: 2026-08-28
branch: wip/phase1-scan-core
pr:
supersedes: []
superseded_by:
---

# Phase 1 Deterministic Scanner Core

## Summary

- Add the authoritative Swift read-only traversal and evidence model without IPC,
  TUI, semantic classification, or cleanup policy.
- Preserve raw filesystem names, descriptor-relative object identity, explicit
  uncertainty, and partial coverage through pause/resume/finalization.

## Task List

- [x] Add versioned quick/standard/deep/full-audit root resolution and budgets.
- [x] Add raw path, observation, coverage, byte-measure, root-binding, and global-fact types.
- [x] Add the deterministic descriptor-relative, no-follow, no-cross-mount walker.
- [x] Add File Provider metadata-only/rejected boundary propagation without an exclusion table.
- [x] Add streaming closed-directory aggregation and deterministic bounded top-K retention.
- [x] Preserve APFS/hardlink topology and File Provider identity/metadata as typed node evidence.
- [x] Preserve independent filesystem times and a pre/post access-policy seal.
- [x] Add actor scan control, checkpoints, provisional snapshots, partial finalization, and transcripts.
- [x] Add a bounded process-activity collector abstraction and normalized `lsof -nP -F0` parser.
- [x] Add deterministic fake-filesystem and controlled temporary-root tests.
- [ ] Re-run the live Darwin temporary-root path after the authoritative Phase 0
  validity-mask/returned-length shim fix is integrated.
- [ ] Complete independent frozen-range review and PR delivery.
- [ ] Integrate scanner evidence into the versioned IPC workstream.

## Current State

- Missing, unreadable, unknown, failed, and identity-mismatch observations remain distinct.
- Budget-exhausted, time-bounded, provider-bound, mount-boundary, and cancelled scans cannot be returned as complete.
- The production walker constructs no child path and reads no file content. Only test-created temporary roots are mutated by integration tests.
- Global VM, swap, and APFS snapshot evidence is typed unavailable rather than inferred.

## Handoff

- Phase: local Phase 1 implementation.
- Next step: integrate the exact reviewed Phase 0 shim follow-up, re-run the live
  Darwin path, then complete full Swift gates and independent review.
- Blocker: the current Phase 0 C shim returns typed `EPROTO` when `getattrlistat`
  reports a validity-mask-sized response shorter than its fixed packed buffer. The
  scanner does not bypass or relax that authoritative probe.

## Evidence

- Accepted architecture: `docs/design/accepted-plan.md`.
- Scanner contract: `docs/design/scanner-core.md`.
- Focused `DiskplanScanTests` passed 21 tests covering raw invalid UTF-8 names,
  enumeration permutations, missing/mismatch/unreadable and access-policy-change
  distinctions, symlink/mount/provider boundaries, provider evidence propagation,
  budgets/timeouts, aggregation, top-K versus the complete event stream, control
  transcripts, a typed lsof parser, and the controlled Darwin temporary root's typed
  live-gate failure.
