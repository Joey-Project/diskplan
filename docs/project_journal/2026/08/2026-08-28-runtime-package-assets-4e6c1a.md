---
id: 20260828-4e6c1a
title: Runtime Package Assets
status: active
created: 2026-08-28
updated: 2026-08-28
branch: wip/runtime-package-assets
pr:
supersedes: []
superseded_by:
---

# Runtime Package Assets

## Summary

- Extends the deterministic release bundle from executables and lifecycle metadata to the complete runtime rules, default policy, authoritative protocol schema, compatibility fixtures, and capability metadata required by the accepted installation layout.
- Keeps one canonical package contract across Python staging, the generated native allowlist, and shell verification; runtime manifests cannot expand filesystem authority.

## Current State

- Every manifested payload binds canonical relative path, exact mode, byte size, SHA-256, role, and compatibility version.
- Nested copy, proof, cleanup, publication, and uninstall use descriptor-relative no-follow traversal with fixed directories and regular-file-only leaves.
- Optional history, saved-plan, audit, and execution-record persistence is declaration-only and defaults off; packaging writes no user data.
- Generated protocol bindings, build trees, repository metadata, local temporary state, and the generated journal index are explicitly excluded.
- Packaging binds the asset root, every source ancestor, every payload leaf, and
  the complete staged bundle tree through retained no-follow descriptors. Archive
  bytes come only from those held descriptors and are checked against the exact
  manifest size and digest before and after tar emission.
- Native exact deletion uses proof-time identity/access/content receipts; partial
  cleanup uses creation-time receipts and retains entries it cannot associate with
  those receipts. Nested traversal rejects device, filesystem, mount-policy, and
  regular-file boundary changes.
- Quarantine cleanup keeps the rebound descriptor open through `unlinkat`. The
  documented phase-one residual is macOS's lack of atomic compare-and-unlink-by-FD;
  the lifecycle therefore requires its existing owner-private exclusive namespace
  precondition and excludes malicious same-effective-UID mutation.

## Next Steps

- Pending integration work: synchronize the canonical package contract,
  generated C allowlist, shell expectations, and compatibility fixtures with
  protocol 1.4 when that workstream lands. This journal remains active until
  that synchronization is completed and revalidated.
- Re-run the complete deterministic release build and install lifecycle at the integration checkpoint.

## Evidence

- `scripts/release/test_package_bundle.py`
- `scripts/release/diskplan-fs-helper-tests.c`
- `release/bundle-contract.json`
- `python3 -m unittest scripts/release/test_package_bundle.py`: 33 tests passed,
  including deterministic archive identity, descriptor-bound archive races,
  conditional output cleanup, contract/schema/collision rejection, and exact
  packaged runtime contents.
- The packaging output namespace rejects non-owner, group/world-writable, or
  extended-ACL directories before creating a temporary output.
- The arm64 macOS 14 C white-box harness compiled with `-Wall -Wextra -Werror`
  and passed ancestor/child-slot/mount, nested lifecycle, creation/proof receipt,
  and quarantine replacement cases.
- The production helper compiled with the same deployment target and warning
  policy and returned its expected protocol 1.3 JSON identity.
- Bash syntax, ShellCheck, actionlint, Python bytecode compilation, generated
  contract verification, both project-journal validators, and `git diff --check`
  passed on the latest worktree.
- A fresh read-only security review covered the canonical/generated/shell
  contract chain, descriptor-bound archive seal, output namespace, lifecycle
  receipts and quarantine, collision rejection, and declaration-only optional
  persistence; it reported no findings on the final diff.
