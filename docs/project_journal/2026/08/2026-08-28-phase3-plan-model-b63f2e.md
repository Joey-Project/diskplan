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
- Keeps protocol 1.4 mapping behind an adapter boundary while the reducer, rendering, and decision-overlay lifecycle are implemented in this slice.

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
- The runtime integration now keeps the immutable engine snapshot and decision overlay separate, routes every stage decision through engine-issued stageability and opaque IDs, and clears consent state on exact plan invalidation.
- AppState, reducer, rendering, and contextual input now expose the plan-first hierarchy plus Summary, Targets, Evidence, Dependencies, Coverage, Revalidation, Selected Actions, and Execution Preview views. Targets remain the only directory-expanding view; Execution Preview accepts only an engine-issued DAG projection bound to the exact overlay digest.
- `j/k`, arrows, `Enter/l`, `h`, `Space`, `e`, `t`, `g`, `c`, `s`, `/`, `p`, `D`, `A`, and `?` are connected. Staging surfaces force requirements, provisional plans reject dry-run/apply intents until frozen, and the TUI never constructs paths, classifications, commands, or argv.
- Overlay edits advance a deterministic revision and digest and revoke pending intents. Each dry-run or apply-review intent freezes the exact plan ID, evidence reference, selected opaque action IDs, overlay revision, and digest; Apply Review remains a selection request and is never presented as execution authorization.
- Detail rendering is independently virtualized and bounded by visible rows plus encoded bytes. Unicode display-cell truncation prevents body rows from wrapping behind the cursor viewport, and staged details retain engine-issued waiver reasons, force requirements, and residual path-race explanations.
- Detail pages now skip logical prefix rows before invoking their formatting closures, so scrolling remains reachable at arbitrary depth and the 16 KiB encoded-byte budget applies only to the visible page. Apply Review pins waiver, force, and residual path-race warnings ahead of overlay hashes and action labels.
- Execution Preview models engine-issued execution units rather than assuming a one-to-one action/step mapping. Validation requires a topologically ordered unit DAG, exact once-only coverage of every staged logical action, no extra action IDs, unique unit and warning IDs, and nonempty final engine warnings; composite APFS release-set units can cover multiple logical actions.
- Snapshot loading rejects an empty or whitespace-only evidence reference before creating an overlay. Every replacement attempt first clears the prior actionable model, consent overlay, pending intent, and execution preview, including when its projection or evidence binding is invalid.
- Warning details preserve their warning type plus warning/action/unit ID prefix and bound only the untrusted reason, message, label, or status field. A single oversized field therefore cannot consume the 16 KiB visible-page budget or hide later warning and DAG rows.
- A protocol-independent adapter trait and injected runtime events isolate the pending protocol 1.4 mapping; no protocol 1.3 transport or generated source was changed in this slice.

## Task List

- [x] Define engine-mappable plan projection DTOs without duplicating Swift policy.
- [x] Implement the plan-first hierarchy, stable row identity, cursor, indexed filter, group sort, and viewport model.
- [x] Keep directory expansion, filtering, cursor state, and virtualization scoped to action Targets details.
- [x] Model the accepted seven-column order and visibility contract without coupling search results to presentation settings.
- [x] Add structural validation, invalidation, reset, and large-plan tests.
- [ ] Map the final protobuf projection into the model after the Phase 1 and Phase 2 seams are frozen.
- [x] Connect the model to decision-overlay acknowledgement, reducer events, and Ratatui rendering.
- [ ] Bind the protocol-independent adapter to the protocol 1.4 projection and intent envelopes when that schema lands.

## Handoff

- Phase: the final fresh-review follow-ups are implemented and dynamically validated on the synchronized integration baseline.
- Next steps: bind the protocol 1.4 projection and intent envelopes after that schema lands.
- Blockers: none for the protocol-independent TUI slice.

## Evidence

- Accepted design: `docs/design/accepted-plan.md`.
- Twenty-two focused model tests cover hierarchy order, invalid IDs and replacement fail-closed behavior, release-set consistency and lookup, cursor/filter/resize behavior, cache reuse, shared immutable IDs, group-local stable sorting, target-path isolation, invalidation, selective and no-match 20,000-action searches, column invariants, nested target collapse/filter/resize behavior, a virtualized 20,001-row target tree, and 5,000 nonempty indexed release sets.
- `cargo fmt --all -- --check`, `cargo check --locked --workspace --all-targets`, and `cargo clippy --locked --workspace --all-targets -- -D warnings` passed with a task-scoped Cargo target to prevent cross-worktree artifact reuse.
- `INSTA_UPDATE=no cargo test --locked --workspace` passed 48 library tests, 9 fake-engine process tests with 4 explicit real-engine ignores, 8 core tests, 5 canonical tests, and 20 generated-source publisher tests.
- The fixed-size render snapshot suite passed 3/3, terminal-guard restoration tests passed 2/2, and the repository PTY control/restore smoke test passed on the host.
- Advisory-review validation passed 7/7 focused runtime tests, 20/20 reducer/input tests, and 6/6 render tests. Render coverage includes independent detail row/byte caps, Unicode display-cell truncation, the complete 1×1 through 160×50 resize matrix, and reviewed plan-first snapshots at 120×34, 80×24, and 40×12.
- `cargo check --locked -p diskplan --all-targets` and `cargo clippy --locked -p diskplan --all-targets -- -D warnings` passed after the review fixes.
- Full relevant package tests passed: 87/87 library tests, 4/4 binary tests, and 9/9 fake-engine integration tests; 10 existing real Swift-engine integration tests remained explicitly ignored pending their dedicated cross-language gate. The first full run hit the known process-start timing flake (`timeout_terminates_and_reaps_the_engine_process_group` could not observe its descendant PID file); the exact test then passed 1/1 and the single authorized full rerun passed without failures.
- Second-review focused validation passed 7/7 runtime tests, 20/20 reducer/input tests, and 7/7 render tests. The render gate includes a 50,000-row lazy deep-prefix probe, visible-page byte caps, two reviewed 80-column warning snapshots, and the complete resize matrix. `cargo check --locked -p diskplan --all-targets` and clippy with `-D warnings` passed.
- The second-review full-package attempt passed 88/88 library tests and 4/4 binary tests, then passed 8/9 fake-engine integration tests with 10 real-engine tests expectedly ignored. Its only failure was `engine_integration.rs:1035`: `descendant.pid` was absent because the fixture has no ready handshake before the timeout begins. This is the second first-run reproduction on this branch and also reproduced in the batch lane; no further retry was performed, and the integration-fixture owner will repair the handshake before the final TUI full-package rerun.
- Final validation used signed baseline merge `2339b5ea1131ea38fd17a69b31c8fc5e1ec61c0a`, which incorporates integration head `4a1faa849651b591547599895c0d3e1720d179c4` and its stable process-group fixture. Focused gates passed 7/7 runtime, 20/20 reducer/input, and 7/7 render tests with all snapshots unchanged and no `.snap.new` artifacts.
- The single final full-package run passed 89/89 library tests, 4/4 binary tests, and 9/9 fake-engine integration tests; 10 real-engine tests remained expectedly ignored. Both `timeout_terminates_and_reaps_the_engine_process_group` and shutdown frame/tail validation passed without a retry.
- `cargo check --locked --workspace --all-targets`, workspace clippy with `-D warnings`, and `cargo fmt --all -- --check` passed on the final dirty feature state.
- Final fresh-review validation passed the blank-evidence and independent oversized-warning exact tests 1/1 each, 8/8 runtime tests, 20/20 reducer/input tests, and 8/8 render tests. Existing selected-warning and execution-preview snapshots remained unchanged, no `.snap.new` artifacts were produced, and package clippy with `-D warnings` plus `cargo fmt --all -- --check` passed.
