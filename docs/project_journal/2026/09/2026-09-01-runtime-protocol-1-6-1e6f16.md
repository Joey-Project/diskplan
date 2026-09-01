---
id: 20260901-1e6f16
title: Runtime Protocol 1.6 Execution Stream Failure
status: active
created: 2026-09-01
updated: 2026-09-01
branch: wip/protocol16-execution-failure
pr:
supersedes: []
superseded_by:
---

# Runtime Protocol 1.6 Execution Stream Failure

## Summary

- Advance the Swift/Rust runtime handshake to Protocol 1.6 while retaining
  byte-identical Protocol 1.4 and 1.5 fixtures.
- Add a fail-closed execution-stream terminal for the point where mutation may
  already have begun but Swift cannot safely author a positive `apply_finished`.
- Bind the terminal to the execution and apply-review authority and seal the exact
  emitted prefix without claiming complete force warnings or a successful unit
  summary.

## Task List

- [x] Add the closed execution-stream failure kind and projection to the source
  schema at event tag 21.
- [x] Publish matching pinned Swift and Rust generated protobuf sources.
- [x] Require Protocol 1.6 for apply and reject the failure terminal under older
  negotiated minors.
- [x] Seal exactly one failure terminal after a valid `apply_started`, authoring
  the actual record digest, event count, encoded bytes, and projection limits.
- [x] Validate execution ID, apply-review ID, review binding, mutation uncertainty,
  terminal exclusivity, closed failure kind, and record metadata in Rust.
- [x] Preserve the positive `apply_finished` contract and its exact force-warning
  and unit-summary checks.
- [x] Add Protocol 1.6 positive and failure compatibility fixtures while preserving
  Protocol 1.4 and 1.5 byte-for-byte fixtures.
- [x] Cover malformed, old-minor, digest, count, encoded-byte, limit, authority,
  and mutation-flag failures in Swift and Rust tests.
- [x] Update release compatibility metadata, bundle contracts, CI fixture authority,
  and accepted protocol documentation.
- [x] Run focused generation, fixture, Swift, Rust, and release checks on
  `India-mac-mini-m4-hoteng` under bounded supervisors.
- [x] Keep release packaging descriptor-bounded as the Protocol 1.6 fixture set
  grows while preserving source/staged identity, content, access-policy, and
  no-follow namespace authority.
- [ ] Complete frozen-head review, signed commits, PR readiness, and integration
  branch handoff.

## Current State

- Protocol 1.6 introduces `ExecutionStreamFailureProjection` as the only alternate
  execution terminal to `ApplyFinished`. It is legal only as the final event after
  exactly one valid leading `ApplyStarted`; the two terminals cannot coexist.
- Swift authors authoritative execution and review bindings plus the digest, count,
  encoded bytes, and negotiated maxima over the exact prefix and failure terminal.
- Rust independently verifies the closed failure kind, mutation uncertainty, chain
  authority, structural prefix, record metadata, and negotiated protocol minor.
- Failure streams validate emitted force warnings but intentionally do not claim
  that the warning set is complete, and they carry no successful unit summary.
- Protocol 1.4 and 1.5 retain their exact fixtures. Protocol 1.6 contains the five
  positive compatibility vectors plus one failure vector that demonstrates a
  post-start terminal without a completeness claim.
- Release packaging now closes every per-file source, staged, and ancestor
  descriptor after staging. Final validation reopens one file at a time from a
  small set of retained trust roots and compares the initial object identity,
  SHA-256 digest, and exact mode. Timestamp-only churn remains benign; missing,
  unreadable, replaced, content-changed, and access-policy-changed states remain
  distinct failures.

## Handoff

- Phase: implementation, focused India validation, and the signed landing commit
  are ready for the frozen-range review gate.
- Next step: complete frozen-head review and the integration PR handoff.
- Blocker: none.

## Evidence

- Pinned Protocol 1.6 Swift and Rust generation completed on
  `India-mac-mini-m4-hoteng`; the generated-source check passed with process-group
  verification and a quiescent supervisor result.
- Protocol 1.4, 1.5, and 1.6 fixture checks passed independently on India. The two
  older suites remained byte-identical, and Protocol 1.6 verified all six vectors.
- The focused Swift execution-failure filter passed 3 tests with 0 failures on
  India. The focused Rust runtime-golden suite passed 8 tests with 0 failures.
- The generated bundle-contract header check and the 12-test CI script suite passed
  on India.
- The first 61-test release-package run exposed a real `EMFILE` failure after the
  new fixture assets crossed macOS's default descriptor ceiling. The first
  descriptor-bounded revision then passed 64 unit tests but exhausted its synthetic
  64-descriptor whole-package budget because repository-internal token sources
  still retained duplicate absolute trust-root chains.
- Repository-internal token sources now share the canonical asset-root binding;
  only external component inputs retain a separate trust root. The final India
  release-package suite passed 65 tests with 0 failures, including the complete
  64-descriptor packaging path and the source/staged replacement, content,
  access-policy, missing, unreadable, and benign timestamp cases. Its bounded
  supervisor reported output SHA-256
  `da05ce477883ff7e2c7b6cf96bfc69f1b9e0c4f73eeafac469885749111f7f2f`, verified
  its process group, and ended quiescent.
- Final local validation was static only: Python AST parsing and Ruff, Cargo format,
  Swift format lint, shell syntax and ShellCheck, JSON parsing, `git diff --check`,
  and project-journal validation all passed. Frozen-head review, PR, and CI evidence
  remain in the delivery gate.
