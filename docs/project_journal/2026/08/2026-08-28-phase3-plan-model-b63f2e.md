---
id: 20260828-b63f2e
title: Phase 3 Plan Presentation Model
status: active
created: 2026-08-28
updated: 2026-08-28
branch: wip/phase3-plan-model
pr:
supersedes: []
superseded_by:
---

# Phase 3 Plan Presentation Model

## Summary

- Adds the Rust-only presentation model for the plan-first hierarchy defined in `docs/design/accepted-plan.md`.
- Keeps every safety classification and display value engine-supplied; Rust validates projection structure but does not derive policy or stageability.
- Leaves protocol mapping, reducer integration, rendering, and decision-overlay acknowledgement to later Phase 3 slices.

## Current State

- The main projection is fixed to disposition, action kind, and action levels; target directories are available only through an action's Targets detail API.
- Stable typed row keys preserve cursor identity across group-local sorting, filtering, collapsing, and viewport resizing.
- A flattened row-key cache is rebuilt only when projection state changes; render, row-count, cursor, and viewport queries are bounded by the requested viewport instead of repeatedly sorting or allocating across the full plan.
- Visible-row materialization is bounded to the viewport, while linear indexed structural validation rejects invalid or duplicate action, target, waiver, blocker, prerequisite, and release-set identities.
- Stable action and release-set ID lookups let Targets and Dependencies views resolve complete APFS member sets and shared-unlock values without rescanning the plan.
- Typed DTOs preserve engine-provided stageability, known or unknown byte estimates, activity, recoverability, blockers, prerequisites, APFS release sets, force requirements, and path-race status.
- Exact plan invalidation removes all actionable projection state; reset prepares the model for a replacement projection.

## Task List

- [x] Define engine-mappable plan projection DTOs without duplicating Swift policy.
- [x] Implement the plan-first hierarchy, stable row identity, cursor, filter, group sort, and viewport model.
- [x] Keep directory expansion data scoped to action Targets details.
- [x] Add structural validation, invalidation, reset, and large-plan tests.
- [ ] Map the final protobuf projection into the model after the Phase 1 and Phase 2 seams are frozen.
- [ ] Connect the model to decision-overlay acknowledgement, reducer events, and Ratatui rendering.

## Handoff

- Phase: the isolated plan presentation model is complete.
- Next steps: map the frozen engine projection into these DTOs, then integrate staging acknowledgements and the plan renderer without moving safety classification into Rust.
- Blockers: none in this slice; protocol and policy integration intentionally follow their authoritative workstreams.

## Evidence

- Accepted design: `docs/design/accepted-plan.md`.
- Sixteen focused model tests cover hierarchy order, invalid IDs, release-set consistency and lookup, cursor/filter/resize behavior, cache reuse, group-local stable sorting, target-path isolation, invalidation, a 20,000-action virtualized projection, and 5,000 nonempty indexed release sets.
- `cargo fmt --all -- --check`, `cargo check --locked --workspace --all-targets`, and `cargo clippy --locked --workspace --all-targets -- -D warnings` passed.
- `INSTA_UPDATE=no cargo test --locked --workspace` passed 42 library tests, 9 fake-engine process tests with 4 explicit real-engine ignores, 8 core tests, 5 canonical tests, and 20 generated-source publisher tests.
