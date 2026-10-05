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
- [x] Close the first frozen review findings: enforce the Swift Protocol 1.6
  mutation boundary before handler dispatch, accept a bound failure terminal as
  the authoritative execution result, cover below/current/future UI minors, bind
  archive reads to one verified descriptor, and exercise a real low-RLIMIT package.
- [x] Close the targeted review follow-ups by preserving typed missing/unreadable
  categories and source/staged subjects across post-bind namespace races, and by
  exercising failure delivery through the real authority/responder transaction.
- [x] Keep release manifest schema validation synchronized with the canonical
  Protocol 1.6 artifact contract and exercise the emitted manifest with the
  validator shipped in the real archive.
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
- `EngineServer` rejects apply-review preparation and apply confirmation below
  Protocol 1.6 before handler dispatch or authority claim. Read-only and dry-run
  flows retain Protocol 1.4/1.5 compatibility.
- Runtime execution authority now validates either positive `apply_finished` or
  typed `execution_stream_failure` as the sole live terminal. Failure binds the
  outer execution ID plus the live review ID and review digest, so a valid
  post-start failure remains an execution terminal instead of being rewritten as
  an ordinary runtime rejection.
- Archive bytes are read from the same no-follow rebound descriptor on which
  staged object identity, exact access mode, SHA-256 content, namespace stability,
  and post-read identity/mode are revalidated.
- Retained root, ancestor, and leaf revalidation uses the same classified error
  mapping as the initial bind. `ENOENT`, `EACCES`/`EPERM`, replacement/type drift,
  content drift, and access-policy drift remain distinct, with the correct source
  or staged subject after the descriptor has already been opened.
- Release manifest validation derives its expected artifact-field count from the
  canonical bundle contract instead of a stale artifact-count constant. The
  validator still rejects any missing or unknown manifest field.

## Handoff

- Phase: Protocol 1.6 implementation and the release-manifest CI repair are
  validated on the macOS 26 release host.
- Next step: complete the signed PR delivery and integration handoff.
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
- The review-fix India package suite passed 67 tests in 6.709 seconds, including a
  real subprocess `RLIMIT_NOFILE=64` whole-package run whose ordinary executable
  components exercised the production component/helper bounded probes. The
  supervisor output SHA-256 was
  `636ce6becad22e5eb9198993a9c78b5f2ad9f92cc2ff88c366a3769b5b4e106e`.
- Focused Swift mutation-boundary, failure-authority, and existing failure-sealer
  tests each passed 1/1. Their supervisor output SHA-256 values were respectively
  `18a5cb05df516d2a88c13886560fa17b8085ef397a58a43efb4847e94728f0cb`,
  `9781564486e58befeee67f7b0e4970a6f4d212c559823c4c32064c86dca50d35`, and
  `199db4c890ab3161718505b50157a367dfd3d7ac1223b6a95ae5ad324e17328b`.
- The focused Rust apply-review transport test passed below/current/future minor
  and capability cases; supervisor output SHA-256 was
  `1af55e2acb530e83e1b694477efebef38925d09cebcb9d01f9d2068ed1f929bc`.
- Protocol 1.4, 1.5, and 1.6 exact fixture checks passed with supervisor output
  SHA-256 values
  `fbe01a448e89ed36927ed28e2e6f85125a08db8b72bb6b8164d42c10d623ff4e`,
  `7c6e2b139a002411ea7346289a16430c515f28418bcff30b2920dc4d2b54630a`, and
  `e0ca0d6157400506048f623452ba180e04595f0b829543b3829cbd3db5d030f5`.
  Every final India supervisor verified its process group and ended quiescent;
  the remote task worktree, `.build`, and raw logs were then removed.
- The targeted P2 closure package suite passed 69 tests in 6.854 seconds. It adds
  staged-leaf post-read unlink and `EACCES` races plus retained-root missing and
  unreadable races; supervisor output SHA-256 was
  `ba86575007c7b65f076bab662ed2c297084f956fe630461fed51416479b8b277`.
- The final focused Swift test passed 1/1 after traversing the real
  `RuntimeBusinessAuthorityState` and `RuntimeBusinessResponder` chain from plan
  receipt through overlay, review, confirmation, and execution. It observed a
  typed failure terminal, no runtime rejection, and a consumed confirmation claim.
  Supervisor output SHA-256 was
  `d4403471152d070c23b9010a665427f2c01d43b57ede37583483c16d723b89a9`.
  Both closure supervisors verified their process groups and ended quiescent; the
  exact India worktree, `.build`, temporary ref/bundle, and raw logs were removed.
- Release CI exposed a stale manifest schema key count: Protocol 1.6 expanded the
  bundle contract from 37 to 45 artifacts, while `release-common.sh` still required
  the former total of 235 keys. The validator now derives the expected total as 13
  top-level keys plus six keys for each canonical artifact-contract row.
- On India, the real-archive manifest regression passed 1/1 with supervisor output
  SHA-256
  `3921436c6f6cc3b997a2e7af910baa69e3a7827b581fea9d6bb36c2160034c6d`.
  The exact package-resolved guard plus release build passed with output SHA-256
  `bc920cf4c232de926db6d8fc80c9ec91ebcc709733efc4dd0d321c12b4e47811`,
  and `test-release.sh` passed the package, install, upgrade, rollback, and
  mixed-version lifecycle with output SHA-256
  `047fcaa7787788e3d195427bd6e44f478667f3f419b82ab27d998961582b9633`.
  All three supervisors verified their process groups and ended quiescent; the
  India worktree, build directories, release artifacts, and raw logs were removed.
