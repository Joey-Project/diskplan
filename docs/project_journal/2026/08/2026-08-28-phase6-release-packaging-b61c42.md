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
- Archive extraction is now a distinct trust boundary: numeric group `0` and
  restrictive umask mode removal are accepted only for the source snapshot;
  every copied artifact is normalized to the caller's uid/gid and exact mode in
  owner-private staging before the strict managed policy and content proof run.
- Repeated bundle enumeration reopens `.` relative to the held directory FD and
  verifies object identity, avoiding the shared directory offset created by
  `dup(2)` while preserving no-follow binding.
- Managed-prefix traversal now retains the complete root-to-prefix descriptor
  chain and revalidates every child slot, object/access-policy identity,
  device/filesystem boundary, and security-relevant mount flags. Missing,
  mismatched, and failed revalidation remain distinct outcomes.
- The frontend binds the no-follow engine source by identity, access policy, and
  SHA-256, creates one bounded owner-private executable snapshot, and uses that
  same snapshot for the product/protocol probe and operational session. Source,
  private-directory, snapshot-descriptor, and snapshot-slot drift fail closed.
- Bundle proof no longer hashes timestamps. Mtime or ctime movement triggers at
  most one reopen and rehash; final proof binds identity, access policy, size,
  and SHA-256, so benign `touch` churn is accepted while content or policy drift
  is rejected.

## Next Steps

- Integrate the Phase 4/5 batch frontend so the documented `--batch --profile full-audit --dry-run --no-history --no-audit-file --root` acceptance seam becomes executable.
- Run the signed integrated release bundle on `India-mac-mini-m4-hoteng`; do not run apply against existing user data.
- Re-run the cross-language and deployment gates after the integrated frontend
  and engine branches land.

## Evidence

- Release contract: `docs/release.md`
- Required workflow: `.github/workflows/release-ci.yml`
- Local lifecycle gate: `scripts/release/test-release.sh`
- Host-local gate: `scripts/release/india-acceptance.sh`
- Pre-review local validation (head `9096a571`): 48 Swift tests; complete Rust
  workspace tests and clippy; four live Swift/Rust process tests; canonical and
  generated Protobuf checks; macOS 14 deployment-target check; 17 CI helper tests;
  ShellCheck, actionlint, and both journal validators.
- Post-hardening macOS 26.6.1 Apple Silicon validation: 21 release helper tests;
  clean deterministic arm64 archive build; complete archive/package/install/
  upgrade/rollback/mixed-version/uninstall lifecycle; real sibling frontend and
  engine handshake; Cargo workspace check and warning-free clippy; Bash syntax,
  ShellCheck, Python bytecode compilation, actionlint, and C `-Wall -Wextra
  -Werror` with the macOS 14 deployment target.
- Review-follow-up pre-landing validation: the production helper and white-box
  harness compile for arm64 with the macOS 14 deployment target and `-Werror`;
  ancestor replacement, ancestor access-policy drift, and mount-boundary
  mismatch regressions pass; complete Rust workspace tests and check pass;
  warning-free workspace Clippy passes; 21 release Python tests, Bash syntax,
  ShellCheck 0.11.0, actionlint 1.7.12, Python bytecode compilation, zlib pin,
  and diff checks pass. The initial `/dev/fd` launch design was rejected by a
  real macOS `EACCES` result and replaced by the verified private snapshot path.
