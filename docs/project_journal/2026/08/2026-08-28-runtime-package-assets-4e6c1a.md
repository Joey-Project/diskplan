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

- Release CI run `33212730509`, job `98989478657`, completed both release
  compilations but rejected the private source tree afterward. The former seal
  retained only an aggregate digest, so that historical run cannot identify the
  changed path. External Cargo and Swift scratch roots exclude ordinary build
  products; an equivalent-byte SwiftPM rewrite, most plausibly
  `Package.resolved`, remains the leading inference rather than a proven path.
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

- Run the exact release build after the static source-seal gates and fresh review.
  Preserve the first path-level diagnostic as CI root-cause evidence, then close
  this workstream only after the release build passes without protected source
  drift.

## Evidence

- `scripts/release/test_package_bundle.py`
- `scripts/release/source_manifest.py`
- `scripts/release/diskplan-fs-helper-tests.c`
- `release/bundle-contract.json`
- `python3 -m unittest scripts/release/test_package_bundle.py`: 36 tests passed,
  including deterministic archive identity, descriptor-bound archive races,
  conditional output cleanup, contract/schema/collision rejection, and exact
  packaged runtime contents.
- Release upgrade and mixed-major fixtures rewrite only the three exact
  protocol-bound contract paths after validating their role, source, mode, and
  original compatibility version; same-count path drift and noncanonical
  numeric protocol compatibility on unrelated assets are rejected.
- The deterministic gzip fixture was emitted twice; both archives have SHA-256
  `5bce31c2eb91417c4354d3a82d18062a397fe07b5345234c22e741f8e14391c2`.
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
