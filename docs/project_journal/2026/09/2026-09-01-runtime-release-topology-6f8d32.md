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
  multi-file group must supply one clone identity and the exact plan-derived reference count, so
  omitted or partial live clone associations cannot bypass the release-set topology.
- A candidate action namespace remains distinct from each descendant owner's full raw chain. The
  owner chain must retain the candidate's root and parent prefix, pass component-by-component
  identity and File Provider checks, and preserve the final parent/leaf slot across the existing
  preflight/postflight TOCTOU bracket.
- Descriptor leases remain real read-only, close-on-exec file descriptors; generation-aware
  identity checks, deadline rechecks, replay protection, and fail-closed collection states remain
  unchanged. The live no-materialization policy is revalidated immediately before every direct
  `openat` path access, with unavailable, unreadable, and failed states preserved separately.
  Every snapshot probe volume must own every file object in its allocation group, and APFS clone
  groups continue to receive no conditional shared-byte credit.

## Task List

- [x] Replace the production raw plan-hash constructor with exact plan/overlay/release-step
  derivation.
- [x] Bind graph membership and selection identity into the topology receipt.
- [x] Separate candidate namespace containment from descendant owner raw-chain validation.
- [x] Reject path escape, malformed chain identities, provider ancestors, duplicate graph
  membership, stale selection, and cross-plan topology substitution.
- [x] Preserve generation, deadline, replay, descriptor, TOCTOU, and no-shared-credit contracts.
- [x] Reject omitted, partial, or mismatched clone membership required by the exact release set.
- [x] Revalidate live materialization policy immediately before each path open and retain typed
  failure propagation.
- [x] Run targeted build, tests, and stress validation on the macOS 26 Apple Silicon release host.

## Evidence

- `India-mac-mini-m4-hoteng`, macOS 26.5.1, Apple Swift 6.3.3: the three focused clone-presence,
  legal non-clone, and pre-open materialization-policy race tests passed under the bounded
  process-group supervisor in 23.742 seconds; retained output SHA-256 was
  `66781ab50e6f82bdd0300520c0691c09d8a779b2977d8edcef750f59540ebe97`.
- The complete `DiskplanEngineCoreTests` gate passed all 147 tests in 9.825 supervisor seconds;
  retained output SHA-256 was
  `070dc765aef5882d6be66456830b044296af25e1e9d3a925a4202673cfc80aa5`.
- Seven clone, provider, namespace, deadline, replacement, and snapshot-volume tests passed 20
  consecutive iterations each (140 executions total) in 11.523 supervisor seconds; retained
  output SHA-256 was
  `ef13dcace5239ad8d76e65dec16af558aca9aeec1c3d05737ff539298a20f6c0`.
- `swift build --disable-automatic-resolution` passed in 4.060 supervisor seconds; retained output
  SHA-256 was
  `4c657743b56a70da318451291c6fdf0c4dca1ab06a940cba5f0394debd32e518`.
- Every final supervisor verified the child process group and reported it quiescent. Tests used
  only task-created temporary filesystem fixtures and did not mutate existing user data.
