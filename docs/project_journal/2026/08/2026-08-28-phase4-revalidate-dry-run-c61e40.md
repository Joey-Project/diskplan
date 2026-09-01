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
- A fresh engine-clock execution reference time re-freezes evidence, rebuilds every selected
  action prototype, and reruns all seven one-vote policy dimensions. Every validated waiver
  epoch requirement must match exactly one unchanged consent predicate and value bucket. One
  new capture binding encloses action, release-topology, and survivor observations.
- Production preparation accepts only the engine-owned sealed collector. Injectable evidence
  sources, collector factories, and raw authoritative snapshot construction are limited to
  internal implementation or `@testable` fixtures; the SPI exposes only the sealed handle.
- Dry-run has no capability surface. Apply capabilities are CSPRNG-generated, non-Codable,
  registry-backed, expiry-aware, exact-binding checked, and consumed on the first authorization
  attempt. Actor-owned preparation generations ensure any newer success or failure supersedes
  an older in-flight result before registry insertion.

## Task List

- [x] Add typed current-evidence and deterministic outcome models.
- [x] Add whole-selected-plan, Git, survivor, namespace, and APFS topology revalidation.
- [x] Add execution epoch and current manifest binding.
- [x] Re-evaluate current policy and consume every waiver epoch requirement at a fresh reference
  time.
- [x] Isolate dry-run from apply authorization.
- [x] Add opaque single-use capability and single-claim authorization handoff.
- [x] Seal the production evidence authority and supersede out-of-order in-flight preparations.
- [x] Add adversarial unit coverage for replay, forgery, binding, expiry, partial selection,
  protected-property changes, collection states, benign churn, stale waiver predicates,
  out-of-order preparations, forged policy evidence, and complete release units.

## Handoff

- Phase: Phase 4 pure execution-preparation implementation complete, including frozen-review
  authority, fresh-epoch waiver, and actor-reentrancy hardening.
- Next step: add the engine-internal live collector factory, then let Phase 5 claim the
  authorization for JIT revalidation and best-effort execution.
- Constraint: no execution adapter may accept a dry-run report or serialized/hash-derived
  substitute for `ApplyAuthorization`.

## Evidence

- Accepted architecture: `docs/design/accepted-plan.md`.
- Detailed contract: `docs/design/revalidation-and-dry-run.md`.
- Static hardening gates: strict `swift-format` lint and `git diff --check` pass.
- Frozen-review hardening focused gate: 22 `DiskplanExecutionTests` pass.
- Full Swift gate: 93 tests pass.
- Release gate: `swift build -c release --target DiskplanExecution` passes.
