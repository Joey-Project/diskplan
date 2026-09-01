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
  descriptor admission.
- A candidate action namespace remains distinct from each descendant owner's full raw chain. The
  owner chain must retain the candidate's root and parent prefix, pass component-by-component
  identity and File Provider checks, and preserve the final parent/leaf slot across the existing
  preflight/postflight TOCTOU bracket.
- Descriptor leases remain real read-only, close-on-exec file descriptors; generation-aware
  identity checks, deadline rechecks, replay protection, and fail-closed collection states remain
  unchanged. Every snapshot probe volume must own every file object in its allocation group, and
  APFS clone groups continue to receive no conditional shared-byte credit.

## Task List

- [x] Replace the production raw plan-hash constructor with exact plan/overlay/release-step
  derivation.
- [x] Bind graph membership and selection identity into the topology receipt.
- [x] Separate candidate namespace containment from descendant owner raw-chain validation.
- [x] Reject path escape, malformed chain identities, provider ancestors, duplicate graph
  membership, stale selection, and cross-plan topology substitution.
- [x] Preserve generation, deadline, replay, descriptor, TOCTOU, and no-shared-credit contracts.
- [x] Run targeted build, tests, and stress validation on the macOS 26 Apple Silicon release host.

## Evidence

- `India-mac-mini-m4-hoteng`, macOS 26.5.1, Apple Swift 6.3.3: the
  `swift build --disable-automatic-resolution` gate passed under the bounded process-group
  supervisor in 2.593
  seconds; retained output SHA-256 was
  `7ae5c4e40ede74d47b52ef4bf37ce6bf7ccb0bca911b16265295867ce8190bb3`.
- The focused `DiskplanEngineCoreTests` gate passed all 144 tests in 13.179 supervisor seconds;
  retained output SHA-256 was
  `29fb0aa657aba54ce6a7ec39d7f4ee007e351d8fcc21461437ebb8fc7ad45f3c`.
- Five namespace, provider, deadline, parent-chain replacement, and snapshot-volume tests passed
  20 consecutive iterations each (100 executions total) in 11.197 supervisor seconds; retained
  output SHA-256 was
  `23a8c4fca88c98d670ff8b0e9c89cfdc6861db32fdd385636e71e681e0194703`.
- Every final supervisor verified the child process group and reported it quiescent. Tests used
  only task-created temporary filesystem fixtures and did not mutate existing user data.
