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
- Stable typed row keys preserve cursor identity across group-local sorting, filtering, collapsing, and viewport resizing. A rejected replacement projection clears the old plan and every actionable detail-view reference before returning its validation error.
- A load-time lowercase search index, shared immutable ID storage, and reusable flattened row-key storage avoid repeated per-keystroke field normalization, ID heap copies, and full-plan-capacity allocation; render, row-count, cursor, and viewport queries remain bounded by the requested viewport.
- Visible-row materialization is bounded to the viewport, while linear indexed structural validation rejects invalid or duplicate action, target, waiver, blocker, prerequisite, and release-set identities.
- Stable action and release-set ID lookups let Targets and Dependencies views resolve complete APFS member sets and shared-unlock values without rescanning the plan.
- The action-scoped Targets projection has stable `(action ID, target ID)` row keys, nested directory expansion, a path-only filter, and independent cursor/viewport caches; target paths never become top-level plan matches.
- Column configuration preserves the accepted seven-column default order, allows deterministic reordering and visibility toggles, and keeps `Plan/action` visible as the hierarchy anchor. Main-tree search is independent of column visibility and is limited to action, action-kind, disposition, and blocker text.
- Typed DTOs preserve engine-provided stageability, known or unknown byte estimates, activity, recoverability, blockers, prerequisites, APFS release sets, force requirements, and path-race status.
- Exact plan invalidation removes all actionable projection state; reset prepares the model for a replacement projection.

## Task List

- [x] Define engine-mappable plan projection DTOs without duplicating Swift policy.
- [x] Implement the plan-first hierarchy, stable row identity, cursor, indexed filter, group sort, and viewport model.
- [x] Keep directory expansion, filtering, cursor state, and virtualization scoped to action Targets details.
- [x] Model the accepted seven-column order and visibility contract without coupling search results to presentation settings.
- [x] Add structural validation, invalidation, reset, and large-plan tests.
- [ ] Map the final protobuf projection into the model after the Phase 1 and Phase 2 seams are frozen.
- [ ] Connect the model to decision-overlay acknowledgement, reducer events, and Ratatui rendering.

## Handoff

- Phase: the isolated plan presentation model and its review follow-up are complete.
- Next steps: map the frozen engine projection into these DTOs, then integrate staging acknowledgements and the plan renderer without moving safety classification into Rust.
- Blockers: none in this slice; protocol and policy integration intentionally follow their authoritative workstreams.

## Evidence

- Accepted design: `docs/design/accepted-plan.md`.
- Twenty-two focused model tests cover hierarchy order, invalid IDs and replacement fail-closed behavior, release-set consistency and lookup, cursor/filter/resize behavior, cache reuse, shared immutable IDs, group-local stable sorting, target-path isolation, invalidation, selective and no-match 20,000-action searches, column invariants, nested target collapse/filter/resize behavior, a virtualized 20,001-row target tree, and 5,000 nonempty indexed release sets.
- `cargo fmt --all -- --check`, `cargo check --locked --workspace --all-targets`, and `cargo clippy --locked --workspace --all-targets -- -D warnings` passed with a task-scoped Cargo target to prevent cross-worktree artifact reuse.
- `INSTA_UPDATE=no cargo test --locked --workspace` passed 48 library tests, 9 fake-engine process tests with 4 explicit real-engine ignores, 8 core tests, 5 canonical tests, and 20 generated-source publisher tests.
- The fixed-size render snapshot suite passed 3/3, terminal-guard restoration tests passed 2/2, and the repository PTY control/restore smoke test passed on the host.
