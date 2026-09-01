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
  unchanged. APFS clone groups continue to receive no conditional shared-byte credit.

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
  supervisor in 2.629
  seconds; retained output SHA-256 was
  `75f29ec382b74bbd4be53c9eb746441ccf38882c16adfb602cbc072a198ea00c`.
- The focused `DiskplanEngineCoreTests` gate passed all 143 tests in 11.899 supervisor seconds;
  retained output SHA-256 was
  `a392fe95ce04ce7527571cdbdf035d0144c86f7da5a0bb4962ad0521b37e04f0`.
- Four namespace, provider, deadline, and parent-chain replacement tests passed 20 consecutive
  iterations each (80 executions total) in 13.065 supervisor seconds; retained output SHA-256 was
  `a57392a7d3369df0e7355bbd042e49b5cfeab9b70a7fcd14c58bcd0ba9b40813`.
- Every final supervisor verified the child process group and reported it quiescent. Tests used
  only task-created temporary filesystem fixtures and did not mutate existing user data.
