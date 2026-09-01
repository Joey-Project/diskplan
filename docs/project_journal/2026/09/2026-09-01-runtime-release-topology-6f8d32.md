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
