---
id: 20260828-7e4f19
title: India Runtime Release Gate
status: active
created: 2026-08-28
updated: 2026-08-28
branch: wip/runtime-india-release-gate
pr:
supersedes: []
superseded_by:
---

# India Runtime Release Gate

## Summary

- Added the declarative macOS 26 Apple Silicon acceptance matrix for the exact
  `India-mac-mini-m4-hoteng` target.
- Added a host-local runner that emits canonical per-lane receipts and keeps every
  external command behind the existing bounded process-group supervisor.
- Kept existing user data read-only and dry-run-only; mutable fixtures, build
  scratch paths, TUI state, and optional artifacts are task-scoped.

## Current State

- The matrix has explicit lanes for standard/full-audit, File Provider, APFS
  clone/hardlink ownership, activity/process evidence, million-entry performance,
  batch/TUI, and disabled/enabled optional persistence.
- Required/conditional status and `passed`/`unsupported`/`skipped`/`failure` are
  separate. The current probe-level File Provider result cannot satisfy the
  scanner-level gate, and missing runtime seams fail closed instead of being
  inferred from lower-level tests.
- Receipts bind OS/build/architecture/model, product/protocol/source identity,
  capability result, limits, canonical command templates, audit-root identity,
  catalog/harness/repository source identity, command/output digests, and
  supervisor cleanup.
- The required source-integrity lane rejects local Swift/File Provider source or
  fixture drift from the bundle revision. Supervisor receipts are checked against
  the retained log, configured limits, process exit, process-group proof, and
  descendant quiescence; batch receipts require strict canonical JSONL.
- Task-root cleanup is descriptor-relative, no-follow, same-device, identity and
  access-policy checked, and bounded by both entries and monotonic time.
- Install, handshake, batch/scan, TUI, Swift scratch, and optional artifact state
  are task-scoped. The File Provider fixture retains only its contract-required
  global lifecycle/App Group state while DerivedData, package cache, and build log
  are redirected into the acceptance task root.
- File Provider completion/recovery is machine-readable. Failure, interruption,
  or an unknown lifecycle state retains that task root so the manifest-bound
  signed app and extension remain available; the summary surfaces both locators
  and an exact recovery argv that reselects the retained DerivedData root.
- This slice has not connected to any remote host and has not run a Swift/Rust
  build, macOS fixture, release bundle, full-audit, or performance gate.

## Next Steps

- Integrate the scanner-level File Provider hook, live activity collector test,
  authoritative standard/batch runtime, enabled optional-artifact CLI seam, and
  partial-plan finalization marker as their owning workstreams land.
- Re-run focused static validation after integration rebases and then execute the
  complete matrix only on `India-mac-mini-m4-hoteng`.
- Record the final machine-readable receipt digest and real-host gate evidence.

## Evidence

- Catalog: `fixtures/release/india-acceptance-v1.json`
- Runner: `scripts/release/india_acceptance.py`
- PTY driver: `scripts/release/india_tui_acceptance.py`
- Static tests: `scripts/release/test_india_acceptance.py`
- Contract: `docs/release.md`
- Static validation: 29 Python unit tests passed; Python bytecode compilation,
  Ruff, `bash -n`, ShellCheck, project-journal validation, and `git diff --check`
  passed. No remote or dynamic release acceptance command was run.
