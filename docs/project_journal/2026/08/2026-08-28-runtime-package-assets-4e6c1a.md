---
id: 20260828-4e6c1a
title: Runtime Package Assets
status: completed
created: 2026-08-28
updated: 2026-08-29
branch: wip/runtime-package-assets
pr: https://github.com/Joey-Project/diskplan/pull/18
supersedes: []
superseded_by:
---

# Runtime Package Assets

## Summary

- Extends the deterministic release bundle from executables and lifecycle metadata to the complete runtime rules, default policy, authoritative protocol schema, compatibility fixtures, and capability metadata required by the accepted installation layout.
- Keeps one canonical package contract across Python staging, the generated native allowlist, and shell verification; runtime manifests cannot expand filesystem authority.

## Current State

- The exact macOS 26.6.1 Apple Silicon release build passes twice from the same
  signed source head. Both archives are byte-for-byte identical, and the full
  install, upgrade, rollback, mixed-version rejection, and uninstall lifecycle
  passes on the resulting archive.
- The replacement seal defines its protected properties explicitly: canonical
  namespace and entry kind, exact access mode, regular-file size and SHA-256,
  and symlink target. Device, inode, mtime, and ctime remain strict during each
  no-follow snapshot read but are observation-only across compilation. This
  accepts an equivalent-byte replacement without accepting content, namespace,
  or access-policy drift.
- The owner-private baseline now retains canonical per-path records outside the
  source tree. Post-build comparison reports bounded exact protected changes and
  separately reports metadata/identity-only observations, while malformed,
  tampered, duplicate, unsorted, noncanonical, or non-private records fail closed.
- Both comparison passes execute separate read-only descriptors for the same
  unlinked comparator inode, so compilation cannot rewrite the code that judges
  its source tree. A shell-held SHA-256 binds the complete baseline bytes,
  including observation fields and canonical JSON encoding.
- macOS 26 SDK documentation and a minimal C probe establish the extended-ACL
  contract: no ACL returns `NULL` with `ENOENT`, a present ACL returns an object
  whose first entry succeeds with `0`, and API errors remain distinct. Python
  packaging, source sealing, and the C lifecycle helper now share that exact
  fail-closed interpretation for owner-private files and directories.
- Release helpers disable Python bytecode emission before creating the private
  source copy, and bundle subdirectories normalize their exact descriptor-bound
  mode after creation under the release process's `077` umask. The C lifecycle
  harness fixes the same umask as a regression boundary and normalizes receipt
  fixtures before testing production access-policy proofs.

- Every manifested payload binds canonical relative path, exact mode, byte size, SHA-256, role, and compatibility version.
- Nested copy, proof, cleanup, publication, and uninstall use descriptor-relative no-follow traversal with fixed directories and regular-file-only leaves.
- Optional history, saved-plan, audit, and execution-record persistence is declaration-only and defaults off; packaging writes no user data.
- Generated protocol bindings, build trees, repository metadata, local temporary state, and the generated journal index are explicitly excluded.
- Protocol 1.4 is synchronized across the canonical package contract, generated
  native allowlist, shell verifier, manifest metadata, and packaged sealed
  runtime compatibility fixtures. Protocol 1.3 scan fixtures remain bundled as
  immutable backward-compatibility evidence.
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

- None for this package-assets workstream. The repository-wide release
  acceptance and distribution checkpoints remain tracked by the integration
  workstream.

## Evidence

- `scripts/release/test_package_bundle.py`
- `scripts/release/source_manifest.py`
- `scripts/release/diskplan-fs-helper-tests.c`
- `release/bundle-contract.json`
- `python3 -m unittest scripts/release/test_package_bundle.py
  scripts/release/test_run_bounded.py`: 66 tests passed,
  including deterministic archive identity, descriptor-bound archive races,
  source-seal protected/observation classification, extended-ACL rejection,
  private-umask directory normalization, conditional output cleanup,
  contract/schema/collision rejection, and exact packaged runtime contents.
- Release upgrade and mixed-major fixtures rewrite only the three exact
  protocol-bound contract paths after validating their role, source, mode, and
  original compatibility version; same-count path drift and noncanonical
  numeric protocol compatibility on unrelated assets are rejected.
- The exact release build ran twice from signed head
  `519b67a866397371ce8225a9a953eef9ab284109`; both 4,614,152-byte archives
  are byte-for-byte identical with SHA-256
  `cfb17cbaa1bbe5c502d01817427a1b6bf8374e4e67190dffef56e31e32d77c1b`.
- `scripts/release/test-release.sh` passed the full release package lifecycle on
  that archive. The exact `-Os -Wall -Wextra -Werror` C harness also passed 20
  consecutive canonical-TMPDIR iterations under `umask 077`.
- The packaging output namespace rejects non-owner, group/world-writable, or
  extended-ACL directories before creating a temporary output.
- The arm64 macOS 14 C white-box harness compiled with `-Wall -Wextra -Werror`
  and passed ancestor/child-slot/mount, nested lifecycle, creation/proof receipt,
  and quarantine replacement cases.
- The production helper compiled with the same deployment target and warning
  policy and returned its expected protocol 1.4 JSON identity.
- Bash syntax, ShellCheck, actionlint, Python bytecode compilation, generated
  contract verification, both project-journal validators, and `git diff --check`
  passed on the latest worktree.
- A fresh read-only security review covered the canonical/generated/shell
  contract chain, descriptor-bound archive seal, output namespace, lifecycle
  receipts and quarantine, collision rejection, and declaration-only optional
  persistence; it reported no findings on the final diff.
