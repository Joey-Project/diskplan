---
id: 20260828-b61c42
title: Phase 6 Release Packaging
status: completed
created: 2026-08-28
updated: 2026-08-28
branch: wip/phase6-packaging
pr:
supersedes: []
superseded_by:
---

# Phase 6 Release Packaging

## Summary

- Added deterministic macOS arm64 release packaging and machine-verifiable component, product-version, and protocol identities.
- Added no-sudo versioned installation, atomic launcher activation, retained-version rollback, and exact non-recursive uninstall.
- Added required public macOS 26 release CI, best-effort macOS 14 build evidence, and a bounded host-local India dry-run acceptance entrypoint.
- Hardened the release boundary after frozen-range review: filesystem operations
  are descriptor-bound, package inputs are frozen before probing, and bounded
  acceptance owns every descendant until quiescence.

## Current State

- The archive contains sibling `diskplan` and `diskplan-engine` binaries plus checksummed lifecycle and protocol metadata.
- The launcher pins the installed product version before resolving its sibling
  engine, so an activation change cannot mix frontend and engine versions.
- Package tests cover deterministic reproduction, tamper rejection, install, upgrade, rollback, protocol-major mismatch, and uninstall in task-scoped roots.
- India acceptance is deliberately dry-run-only on real data and prints its audit record to the shell; optional report persistence is non-fatal.
- The protected installer properties are explicit: no-follow descriptor and
  device/inode checks preserve object identity; hashes and sizes preserve content
  stability; owner, mode, and ACL checks preserve access policy. Missing,
  unreadable, replaced, and policy-mismatched objects remain distinct failures.
- Release publication treats the archive and checksum as one verified set, while
  lifecycle publication uses exclusive version-directory creation and a
  conditional launcher switch under a recoverable owner-identified lock.

## Next Steps

- Integrate the Phase 4/5 batch frontend so the documented `--batch --profile full-audit --dry-run --no-history --no-audit-file --root` acceptance seam becomes executable.
- Run the signed integrated release bundle on `India-mac-mini-m4-hoteng`; do not run apply against existing user data.
- Re-run the dynamic release lifecycle, cross-language, and deployment gates once
  the coordinated build slot is available; the post-review hardening was prepared
  while new builds were paused for host disk pressure.

## Evidence

- Release contract: `docs/release.md`
- Required workflow: `.github/workflows/release-ci.yml`
- Local lifecycle gate: `scripts/release/test-release.sh`
- Host-local gate: `scripts/release/india-acceptance.sh`
- Pre-review local validation (head `9096a571`): 48 Swift tests; complete Rust
  workspace tests and clippy; four live Swift/Rust process tests; canonical and
  generated Protobuf checks; macOS 14 deployment-target check; 17 CI helper tests;
  ShellCheck, actionlint, and both journal validators. Post-review dynamic gates
  are intentionally pending the coordinated build slot.
