---
id: 20260901-6f8d32
title: Runtime Release Topology Authority
status: completed
created: 2026-09-01
updated: 2026-09-01
branch: wip/revalidation-release-topology
pr:
supersedes: []
superseded_by:
---

# Runtime Release Topology Authority

## Summary

- Bind live hardlink, clone, namespace, provider, and snapshot evidence to one exact immutable
  plan, validated overlay, and release execution step.
- Admit directory cleanup candidates while retaining every descendant owner's complete raw
  namespace chain and rejecting any escape or unverified provider ancestor.

## Current State

- Production topology construction derives candidate/action membership from the exact
  `ImmutablePlan`, opaque `ValidatedDecisionOverlay`, and selected release execution step. The
  topology receipt commits the plan hash, overlay hash, release-step action ID, graph file and
  allocation-group membership, live object identities, owner chains, and volume set.
- Graph file IDs, owner links, link counts, allocation-group membership, and candidate action IDs
  must match the validated release sets exactly. Duplicate or cross-plan membership fails before
  descriptor admission. A one-file allocation group is bound as a non-clone; a complete
  multi-file group must supply the exact plan-derived typed clone identity `(device, cloneID)` and
  reference count, so omitted, partial, or substituted live clone associations cannot bypass the
  release-set topology.
- A candidate action namespace remains distinct from each descendant owner's full raw chain. The
  plan now commits every descendant root, parent identity and namespace seal, mount and provider
  state, access policy, and leaf identity. The runtime owner must match that complete binding
  before live probing, then pass component-by-component identity and File Provider checks while
  preserving the final parent/leaf slot across the existing preflight/postflight TOCTOU bracket.
- Descriptor leases remain real read-only, close-on-exec file descriptors; generation-aware
  identity checks, deadline rechecks, replay protection, and fail-closed collection states remain
  unchanged. The live no-materialization policy is revalidated immediately before every direct
  `openat` path access, with unavailable, unreadable, and failed states preserved separately.
  Metadata and `openat` races that report `ENOENT` retain an explicit missing outcome rather than
  collapsing into replacement mismatch or generic probe failure, including a leaf that disappears
  while its already-open descriptor remains valid.
  Every snapshot probe volume must own every file object in its allocation group, and APFS clone
  groups continue to receive no conditional shared-byte credit.
- Production owner-chain construction verifies that every selected raw descendant ancestor is the
  exact expected prefix of the observed owner path. A missing intermediate directory cannot be
  compacted away and relabeled as a complete plan-bound namespace.
- Every root and parent descriptor is now re-sealed around namespace metadata and `openat`
  traversal. The runtime compares the exact plan-bound owner, group, mode, protected flags, ACL
  digest, mount identity, and local-provider state while revalidating the no-materialization policy
  before each probe. Directory child-entry churn does not alter this selected access-policy seal,
  while same-inode permission, ACL, ownership, flag, or mount drift fails closed.
- Local-provider state is observed live for each held root and parent descriptor through a bounded
  descriptor-to-slot File Provider probe. The probe rebinds the current raw path to the held
  directory identity, uses only metadata and the public File Provider identity API under repeated
  no-materialization checks, and brackets both identities. Descriptor provider drift now stops
  before the next child lookup; root drift performs no child access, while intermediate drift can
  resolve that intermediate but cannot touch its child.
- Topology aggregation preserves typed failed, unreadable, unknown, and missing observations ahead
  of a known mismatch. Identity and access-policy mismatches are also retained as explicit issues,
  so a concurrent replacement cannot hide a simultaneous collector or accessibility outcome.

## Task List

- [x] Replace the production raw plan-hash constructor with exact plan/overlay/release-step
  derivation.
- [x] Bind graph membership and selection identity into the topology receipt.
- [x] Separate candidate namespace containment from descendant owner raw-chain validation.
- [x] Reject path escape, malformed chain identities, provider ancestors, duplicate graph
  membership, stale selection, and cross-plan topology substitution.
- [x] Preserve generation, deadline, replay, descriptor, TOCTOU, and no-shared-credit contracts.
- [x] Reject omitted, partial, or mismatched clone membership required by the exact release set.
- [x] Commit typed clone identity and every descendant namespace identity/seal into the release
  graph, action binding, immutable plan hash, and runtime topology receipt.
- [x] Reject descendant directory replacement, mount/device drift, provider or access-policy
  transition, and relabeled leaf replacement before live probing.
- [x] Preserve a typed missing namespace outcome across metadata, File Provider, and `openat`
  races.
- [x] Preserve typed missing through collect-time leaf disappearance and reject compacted raw
  ancestor chains with an intermediate gap.
- [x] Revalidate live materialization policy immediately before each path open and retain typed
  failure propagation.
- [x] Revalidate descriptor-bound access-policy seals before and after every relevant root or
  parent namespace access without treating benign child-entry churn as a policy change.
- [x] Observe and compare live descriptor-bound File Provider state for every root and parent,
  stopping before child access on a same-inode provider transition.
- [x] Preserve typed missing, unreadable, and failed evidence when it co-occurs with an explicit
  identity or access-policy mismatch at file, group, and report levels.
- [x] Run targeted build, tests, and stress validation on the macOS 26 Apple Silicon release host.

## Evidence

- `India-mac-mini-m4-hoteng`, macOS 26.5.1, Apple Swift 6.3.3: the two focused collect-time leaf
  missing and raw-ancestor-gap regressions passed in 15.247 command seconds, including the
  incremental rebuild; retained output SHA-256 was
  `881e0b04585a3b2060c1670ce6984fef3f3bd035a5ea5fce6e13efd535a4b399`.
- The complete `DiskplanEngineCoreTests` gate passed all 150 tests in 10.947 command seconds;
  retained output SHA-256 was
  `47b20c9060dfa46fc2a1d781346e4b544f2bcda322727158bf958bc80e6bd571`.
- The complete `DiskplanPolicyTests` gate passed all 66 tests in 8.644 supervisor seconds; retained
  output SHA-256 was
  `f76388ec0acc7bbbf48eff20d00f118324e12901b93ecf33c1ad7295b35d9234`.
- Seven clone, provider, namespace, replacement, typed-missing, alias, and ancestor-gap tests
  passed 20 consecutive iterations each (140 executions total) in 11.755 command seconds;
  retained output SHA-256 was
  `b0f219dd228eb161c0ae1589f4f010ba05c6523124bf75246ab63c9a464049b1`.
- `swift build --disable-automatic-resolution` passed in 5.244 command seconds; retained output
  SHA-256 was
  `c4a24bd0e24eaef2416eb5aa2b8848e1cb0370daaf48fbcd827c847f10e1a08d`.
- `swift-format` formatted all seven changed Swift files and `swift-format lint --strict` accepted
  the resulting sources and tests without diagnostics.
- A fresh read-only whole-diff review found the collect-time leaf-absence and compacted-ancestor
  edge cases above; both were corrected, and the reviewer's focused rerun reported no remaining
  findings.
- Every final supervisor verified the child process group and reported it quiescent. Tests used
  only task-created temporary filesystem fixtures and did not mutate existing user data.
- The final access-policy-seal regressions passed on `India-mac-mini-m4-hoteng`: live same-inode
  mode drift versus benign child churn, exact access/ACL/mount comparison, plan-bound descendant
  traversal, typed bind failures, and mixed mismatch plus missing/unreadable/failed collection.
  The complete `DiskplanEngineCoreTests` gate passed all 155 tests (retained output SHA-256
  `7e8fc2454e7bf36be78e3d0ab762abf1c689af701f2cffe7236e5a9bf3331c46`) and the complete
  `DiskplanPolicyTests` gate passed all 66 tests (retained output SHA-256
  `2c93512b90a3e517a2932a97479cf8d8e7caae5e449ed032d98fd8f688e7144b`). Eight
  access-policy, materialization-race, descendant, and typed-evidence tests also passed 20
  consecutive stress iterations (160 executions; retained output SHA-256
  `5f9fb82b2e516ae1f31ba36074f239f22973f76dbbe8437f327154581d487783`). The final build
  passed with retained output SHA-256
  `7ae5c4e40ede74d47b52ef4bf37ce6bf7ccb0bca911b16265295867ce8190bb3`, and strict
  `swift-format` lint produced no diagnostics.
- The final descriptor-provider closure passed on `India-mac-mini-m4-hoteng`: the complete
  `DiskplanEngineCoreTests` gate passed all 157 tests (retained output SHA-256
  `4f5d1787d66e369f534220c19e3db7a70f2dd84ad20928012d6761c16d723dd6`) and the complete
  `DiskplanPolicyTests` gate passed all 66 tests (retained output SHA-256
  `c8849bc12801af0ee32b417d04bd597dec02a539c850fcb4d47c2b2797fac729`). Eight
  provider-transition, access-policy, namespace-race, and typed-evidence regressions passed 20
  consecutive stress iterations (160 executions; retained output SHA-256
  `56c282a6a61669115f23c9f9d19e64c74f69c62312f9cc65c0bcbaadb22004fa`). The final build
  passed with retained output SHA-256
  `370a3de17cbc23915bbd607b48ae3e38db460e34553526382b8af33f2b2d85fd`, and strict
  `swift-format` lint produced no diagnostics.
- Production runtime base `cd016f66a1233683abbc535e0544d2bff2090d58` was absorbed through
  signed no-fast-forward merge `0ec92567e4674cadba3581172822ebd602251a41`; both signatures
  verified as Good EDDSA. The merge preserved the production strict runtime fixture semantics and
  the complete topology authority. On the final formatted merge tree, six focused topology tests
  passed with bounded-supervisor SHA-256
  `9e9a9127c694bca08c87816de7433049a1c8a49d2ccc662f8ec21b885002b9f0`, all 166
  `DiskplanEngineCoreTests` passed with SHA-256
  `472dd0d23eed377bfd652f34ac7fb5a52275efd7921444fbf13dea6111950d7d`, and all 66
  `DiskplanPolicyTests` passed with SHA-256
  `c2630f701d8477c32fa99125f2c73986098a7327b6655afa719471b36e1a0f93`. The final build passed
  with SHA-256 `85f6e895c7ee0fee14e617e821ce001b7fe2ac074e0151285adab2cbcec12da4`.
  Every command ran under the bounded process-group supervisor, which verified the target group
  and reported a quiescent successful exit. The merge did not change topology production source,
  so the earlier topology stress evidence remained applicable and was not rerun.
