---
id: 20260827-dp0001
title: Initial Architecture And Delivery Plan
status: active
created: 2026-08-27
updated: 2026-08-27
branch: main
pr:
supersedes: []
superseded_by:
---

# Initial Architecture And Delivery Plan

## Summary

- The product design is confirmed and recorded in `docs/design/accepted-plan.md`.
- This workstream bootstraps the previously empty canonical repository and establishes the project-journal plus linked-worktree/PR workflow.
- Product implementation has not started; the next delivery gate is the Phase 0 capability slice.

## Current State

- Canonical repository: `/Users/hoteng/Program/GitHub/diskplan`.
- GitHub repository: `Joey-Project/diskplan`.
- Required release environment: Apple Silicon and macOS 26.
- Preferred real-host validation target: `India-mac-mini-m4-hoteng`.
- Architecture: Swift safety/execution engine, Rust/Ratatui frontend, versioned Protobuf over stdio.

## Task List

- [x] Recover and analyze the original manual disk-cleanup workflow.
- [x] Align classification, activity, recoverability, APFS, File Provider, UI, execution, persistence, testing, and platform decisions.
- [x] Confirm the complete product and delivery plan.
- [x] Bootstrap repository guidance, README, ignore rules, accepted design, and project journal.
- [ ] Phase 0: validate APFS attributes, File Provider metadata-only access, Swift/Rust Protobuf IPC, and minimal scan TUI.
- [ ] Phase 1: implement read-only scan-to-evidence.
- [ ] Phase 2: implement deterministic classification, policy, dependency graph, and immutable plan.
- [ ] Phase 3: implement the plan-first TUI.
- [ ] Phase 4: implement revalidation and dry-run.
- [ ] Phase 5: enable fixture-tested best-effort apply adapters.
- [ ] Phase 6: complete macOS 26 real-host release acceptance.

## Handoff

- Phase: design to implementation.
- Summary: the architecture and safety contracts are frozen for Phase 0; independent modules may develop concurrently after their shared schema is stable.
- Next step: create a linked worktree and `wip/<topic>` branch for the Phase 0 capability slice, then land it through a pull request.
- Blockers: none currently known.

## Evidence

- Accepted design: `docs/design/accepted-plan.md`.
- Original cleanup task: `codex://threads/019e4f9b-d3cb-7c92-9637-722ebb48c3db`.
- Design-alignment task: `codex://threads/01a04386-7151-7b11-98c6-b7c805e66b03`.
