---
id: 20260828-c61e40
title: Phase 4 Revalidation and Dry-Run Isolation
status: completed
created: 2026-08-28
updated: 2026-08-28
branch: wip/phase4-revalidate-dry-run
pr:
supersedes: []
superseded_by:
---

# Phase 4 Revalidation and Dry-Run Isolation

## Summary

- Add the read-only whole-plan revalidation boundary and capability-free dry-run result.
- Bind an apply preparation to one current execution epoch with a private one-time capability.

## Current State

- `DiskplanExecution` retains distinct missing, unknown, unreadable, collection-failed,
  identity, content, access-policy, Git-prerequisite, topology, and survivor outcomes.
- Only action-selected protected properties are compared; unselected directory and provider
  metadata cannot reject revalidation.
- Selected APFS release sets are revalidated as connected compound units with every owner and
  topology expectation.
- Dry-run has no capability surface. Apply capabilities are CSPRNG-generated, non-Codable,
  registry-backed, expiry-aware, exact-binding checked, and consumed on the first authorization
  attempt. A new revalidation invalidates every earlier capability in the engine session.

## Task List

- [x] Add typed current-evidence and deterministic outcome models.
- [x] Add whole-selected-plan, Git, survivor, namespace, and APFS topology revalidation.
- [x] Add execution epoch and current manifest binding.
- [x] Isolate dry-run from apply authorization.
- [x] Add opaque single-use capability and single-claim authorization handoff.
- [x] Add adversarial unit coverage for replay, forgery, binding, expiry, partial selection,
  protected-property changes, collection states, benign churn, and complete release units.

## Handoff

- Phase: Phase 4 pure execution-preparation implementation complete.
- Next step: integrate the production read-only collector, then let Phase 5 claim the
  authorization for JIT revalidation and best-effort execution.
- Constraint: no execution adapter may accept a dry-run report or serialized/hash-derived
  substitute for `ApplyAuthorization`.

## Evidence

- Accepted architecture: `docs/design/accepted-plan.md`.
- Detailed contract: `docs/design/revalidation-and-dry-run.md`.
- Focused tests: `swift test --filter DiskplanExecutionTests`.
