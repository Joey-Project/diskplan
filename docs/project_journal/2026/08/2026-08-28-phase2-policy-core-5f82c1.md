---
id: 20260828-5f82c1
title: Phase 2 Deterministic Policy Core
status: completed
created: 2026-08-28
updated: 2026-08-28
branch: wip/phase2-policy-core
pr:
supersedes: []
superseded_by:
---

# Phase 2 Deterministic Policy Core

## Summary

- Implement the filesystem-free Swift classification, seven-gate policy, release graph,
  immutable plan, and decision-overlay core.
- Keep the evolving Phase 1 scanner behind an explicit adapter seam.

## Current State

- `DiskplanPolicy` preserves absent, known, unknown, unreadable, and failed observations.
- Classification is facet-scoped and permutation-invariant; source type fixes deterministic
  rank, same-rank value conflicts remain explicit, and agent output is excluded from
  resolution and retained only for deterministically missing facets.
- The policy retains exactly seven independent votes, permits only the accepted waiver set on
  semantic or recoverability gates, and treats `safe-after-exit` as unmet revalidation only.
- The release graph rejects invalid topology and fails closed on incomplete clone/hardlink
  ownership, cross-group reuse, snapshots, provider or hard-rejected owners, unknown shared
  bytes, missing owners, overlap, and overflow.
- Immutable plans store and hash complete canonical evidence/global facts, use ActionID-byte
  canonical order, and derive release sets only from complete graph evaluation. Versioned,
  hashed overlay validation binds selections and every exact waiver predicate to the current
  action, lineage, evidence, policy, and plan; partial owner selection never activates shared
  credit.
- Generic removal is a typed adapter contract with an explicit prototype-path slot, trusted
  namespace, path-race residual, and force-warning state; it cannot inject arbitrary argv.
- Hardened review now seals canonical root/relative paths, root and ancestor identity plus
  access/ACL/provider/mount evidence, separate typed identity/content/access contracts, and
  typed postconditions through evidence, lineage, action, and plan hashes.
- Release plans are built atomically from one successful full-graph evaluation and retain its
  digest, owner provenance, exact target binding, and JIT topology expectations. Overflow or
  any incomplete observation cannot produce a release set.
- Editable overlays retain lineage-only consent cores. Validation resolves each lineage
  uniquely and emits current action/plan/evidence epoch requirements; Phase 4 owns the opaque
  credential and execution epoch/deadline.
- Frozen typed evidence, global facts, file topology, and classification claims share one
  capture/global-facts provenance. The adapter cannot declare votes or stageability; policy
  construction authoritatively derives all seven votes and fails closed on explicit
  protection, provider ancestors, incomplete matching-root coverage, collector, activity,
  content, access, dependency, and failed recoverability evidence.
- Independent semantic, agent-per-missing-facet, recoverability, and local-Git-discard
  predicates are unioned with all reasons preserved. Fact collections and gate payloads are
  canonicalized before their respective evidence/action hash boundaries.
- Git worktree remove contracts bind no-follow traversal, HEAD, index, local changes, exact
  worktree registration/root identity, administrative and common directory identity,
  registration/metadata digests, linked-worktree and sparse-checkout state, nested
  repositories, submodules, trusted-exclusive namespace, and post-quarantine coverage. V1
  execution requires an ordinary worktree with sparse checkout disabled and exact equality
  between administrative and common directory identity; linked, sparse, identity-mismatched,
  absent, unknown, unreadable, or failed evidence stays report-only. Dirty work requires a
  separate explicit discard action prerequisite whose typed clean successor preserves HEAD
  identity and becomes the remove action's JIT content baseline. Action-aware policy records
  the prerequisite discharge before action hashing.
- Complete-release actions bind the exact verified release graph, owner topology, actions,
  candidates, and bytes; plans reject empty, duplicate, or mismatched action bindings. Bound
  owners are mandatory prerequisites for consent validation. A closed composite execution
  step retains every owner JIT contract and rewritten prerequisite edges while preventing
  duplicate individual deletion; credit-only release sets remain independent of aggregates.
- Raw-path and raw-UTF8 identity are preserved across graph keys, adapter scopes, release
  owners, and hashes. Full-corpus absolute-namespace overlap blocks selected parents even
  when nested candidates are not selected, while unrelated sibling and distinct-root targets
  remain independent.
- Frozen claim/source payloads and adapter-scope sets are validated and canonicalized before
  hashing. Overlay terminal effects, including Git discard, are checked against the complete
  frozen corpus and reject unauthorized alias or ancestor effects. Duplicate-survivor consent
  protects every plan-declared survivor namespace even when the declaring duplicate is not
  selected.
- Git-scope dominance uses symmetric path/identity overlap for non-Git actions at plan and
  overlay boundaries, blocking nested children, ancestors, and aliases while preserving
  directional non-Git survivor checks and allowing disjoint targets. Display tiers are derived
  from final action-aware policy and force-warning semantics; recomputation rejects forged
  safe labels for blocked or review-required actions.

## Task List

- [x] Add typed observations and deterministic classification resolution.
- [x] Add seven named one-vote gates and strict waiver validation.
- [x] Add clone/hardlink/snapshot release-set evaluation with no double counting.
- [x] Add closed immutable-plan/action/waiver bindings and overlay validation.
- [x] Close review findings around evidence construction, typed gate outcomes, agent
  isolation, release topology, typed removal adapters, and overlay/action consent hashes.
- [x] Close hardened findings around canonical roots, ancestor seals, full-graph release
  provenance, exact global-facts epochs, typed protected properties, and split consent epochs.
- [x] Add permutation, individual/combined gate, waiver, graph, DAG, stale overlay, and hash
  mutation tests.
- [x] Close final hardened review findings for evidence-derived policy, raw-UTF8 identifiers,
  full-corpus overlap, capture-bound topology, exact evaluated ActionID, typed content
  baseline, disconnected graph nodes, duplicate binding traps, and checked total release
  arithmetic. Reject duplicate selected action lineages even when no waiver is present.
- [x] Remove adapter-declared votes, add authoritative typed-fact derivation with additive
  exact waivers, bind complete Git worktree evidence and explicit discard actions, require
  exact verified release-set action bindings, and canonicalize all gate payloads.
- [x] Close frozen-review execution findings with successor baselines, action-aware Git
  discharge, composite release steps, terminal namespace exclusivity, and survivor invariants.
- [x] Bind Git worktree registration and administrative metadata plus linked/sparse typed
  facts, and fail closed outside the exact ordinary, sparse-disabled v1 execution predicate.
- [x] Close full-range review findings for symmetric Git dominance, ordinary admin/common
  metadata consistency, and authoritative display tiers.

## Handoff

- Phase: pure policy-core implementation and local validation.
- Next step: parent review/integration, then a narrow adapter commit after Phase 1 types freeze.
- Constraint: the adapter must consume the complete scan stream plus closed-directory coverage;
  stable top-K viewport entries are not a candidate corpus.

## Evidence

- Accepted architecture: `docs/design/accepted-plan.md`.
- Policy contract: `docs/design/policy-core.md`.
- Focused Swift policy tests cover classification permutations, every gate and waiver,
  release-set failure modes, canonical ordering, DAG validation, immutable hashes, and exact
  overlay consent binding; the latest focused run passed all 44 tests.
- The final full local `swift test --package-path swift` run passed all 72 tests, including
  all 44 focused policy tests.
- `swift-format lint --strict`, `git diff --check`, and project-journal validation passed after
  the final safety review fixes.
