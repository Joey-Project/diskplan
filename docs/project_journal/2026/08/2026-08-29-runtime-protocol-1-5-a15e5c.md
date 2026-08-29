---
id: 20260829-a15e5c
title: Runtime Protocol 1.5 Execution Preview
status: completed
created: 2026-08-29
updated: 2026-08-29
branch: wip/runtime-protocol-1-5
pr:
supersedes: []
superseded_by:
---

# Runtime Protocol 1.5 Execution Preview

## Summary

- Advance the Swift/Rust runtime handshake to protocol minor 1.5 while retaining
  byte-identical Protocol 1.4 fixtures.
- Bind the exact raw working-directory bytes and closed path-race projection to
  every execution preview and every downstream sealed runtime chain.
- Keep path authority in Swift. Rust validates and escapes the raw bytes for
  display without joining, normalizing, resolving, canonicalizing, or opening
  the working directory.

## Task List

- [x] Add `raw_working_directory` at preview tag 7 and closed `path_race` at tag 8.
- [x] Publish matching pinned Swift and Rust generated protobuf sources.
- [x] Thread the negotiated protocol minor through runtime handlers, plan projection,
  dry-run, apply-review, force-warning, and execution sealing and verification.
- [x] Require the complete 1.5 preview shape and reject frontend mutation after a
  negotiated 1.4 downgrade.
- [x] Preserve and independently check byte-identical Protocol 1.4 fixtures.
- [x] Add Protocol 1.5 fixture sources, generated frames, authority script, and
  cross-language runtime-golden coverage.
- [x] Add exact-byte tamper coverage for plan, dry-run, apply-review, force-warning,
  and execution predecessor bindings.
- [x] Update release metadata, exact bundle contracts, protocol documentation, and
  CI-script authority checks.
- [x] Bound release-bundle traversal and per-file verification descriptor lifetimes
  independently of artifact count.
- [x] Synchronize protocol-contract fixture rewrite expectations with the canonical
  Protocol 1.5 package assets.
- [x] Run the remaining focused fixture, runtime-golden, and release checks on
  `India-mac-mini-m4-hoteng`.
- [x] Complete frozen-head local review, sign the landing commit, and hand the
  branch to the parent integration workstream.

## Current State

- Protocol 1.5 previews always carry tag 7, including a present empty byte string
  for a non-mutating preview, and a recognized non-unspecified tag 8 matching the
  owning action. Mutation previews additionally require an absolute, NUL-free raw
  working directory.
- Negotiated Protocol 1.4 emissions omit tags 7 and 8. The production Swift plan
  projector emits a non-mutating legacy preview, while the Rust frontend rejects
  every mutation-enabled 1.4 preview because the working-directory evidence is
  unavailable.
- `RuntimeBusinessResponder` carries the selected minor from `EngineServer` into
  authority receipts and every sealer. Rust stores the selected minor in the
  verified plan and reuses it for all successor verification.
- The existing canonical protobuf record and event digests bind both new fields.
  Focused tamper tests alter plan, dry-run, apply-review, and force-warning preview
  bytes and require the applicable digest or predecessor-chain check to fail.
- Protocol 1.5 provides five Swift-authored runtime vectors matching the Protocol
  1.4 case matrix. Release bundles retain both fixture versions and advertise
  protocol compatibility 1.5 for the schema and version metadata.
- Bundle tree traversal now retains descriptors only for the currently visited
  directory ancestry. File verification records initial device, inode, and macOS
  generation identities and then rebinds, hashes, and closes one file at a time;
  a later replacement, content change, mode change, or path-access failure still
  fails closed.

## Handoff

- Phase: implementation, India validation, signed-head review, and integration-branch
  PR handoff are complete.
- Next step: the parent integration workstream owns consumption of this completed
  slice.
- Blocker: none.

## Evidence

- `scripts/proto-codegen.sh generate` completed with the pinned toolchain before the
  local dynamic-test prohibition took effect.
- `scripts/protocol15-fixtures.sh generate` completed, and
  `scripts/protocol14-fixtures.sh check` confirmed the Protocol 1.4 vectors remain
  byte-identical.
- Local focused Swift gates passed before the host-policy change: Handshake 4/4 and
  RuntimeBusinessHandler 22/22 after switching the force-warning test to the new
  Protocol 1.5 vector.
- Local focused Rust `runtime_golden` passed 6/6 before the final exact-byte tamper
  case was added. At that checkpoint, the final case was assigned to the later
  India-only rerun recorded below.
- The first India rerun of signed head `f55b35c` stopped at Rust compile error
  `E0596`: the new force-warning tamper test borrowed `warning.1.body` mutably but
  bound the `(bytes, event)` tuple as immutable. The focused fix changes only that
  binding to `let mut warning`; no test result is claimed from the failed run.
- India reran signed head `987393b`: Rust `runtime_golden` and the CI script checks
  passed. The 57-test release package suite reported two failures and two errors.
  The positive package test exhausted the default 256-descriptor limit while
  retaining every traversed directory and verified file, and three protocol
  contract fixture cases still supplied Protocol 1.4 as the canonical source
  version after the package contract advanced to 1.5.
- The follow-up adds separate synthetic 24-descriptor regression budgets over 64
  files and 64 directories without changing the process limit. Typed tests also
  cover macOS generation changes and keep missing, unreadable, replaced/type-changed,
  and other revalidation failures distinct. At that checkpoint, the head had
  received static-only local validation and the corrected release suite was assigned
  to the later India rerun recorded below.
- The follow-up head passes Python AST parsing, Ruff static lint,
  `git diff --check`, and project-journal validation. No local dynamic command was
  run after the India-only host policy took effect.
- India validated exact signed head `fbfe1597`: the release package suite passed
  61/61, the bundle-contract check passed, and the full cross-language gate passed.
  The gate supervisor also confirmed all process groups were quiescent at terminal
  completion. These dynamic results apply to `fbfe1597`; the successor journal-only
  commit was not locally built or tested.
- Fresh review of `987393b..ecc24e67` reported four P2 findings in object-identity
  hardening, descriptor cleanup, typed revalidation errors, and directory-width
  coverage. Signed follow-up `fbfe1597` closed all four, and the same reviewer
  returned `No findings.` on the closure pass.
- Natural Foundation CI for PR #21 at journal-only head `842e3e3` reached the Rust
  library-test compile and failed with `E0063`: two module-local test helpers in
  `sealed.rs` had not supplied the newly required `negotiated_protocol_minor` field
  for `RuntimeChainVerifier` and `VerifiedPlanProjection`. The production and
  cross-language paths had already passed at `fbfe1597`; this failure specifically
  exposed the broader `cfg(test)` compile surface. The signed follow-up assigns both
  helpers the current `PROTOCOL15_MINOR`. No local build or test result is claimed
  for that correction.
- India validated exact signed fix head `8ab2bad2` with Rust 1.95.0:
  `cargo test -p diskplan-proto --lib` passed 4 tests in a bounded 2.248 seconds.
  `cargo test --workspace --all-targets` passed in a bounded 46.774 seconds with
  suite totals of 91, 4, 9 (plus 10 ignored), 10, 5, 4, 7, 20, and 0 tests; every
  suite reported 0 failures. The supervisor confirmed process-group quiescence
  after both commands. These dynamic results apply to `8ab2bad2`; the successor
  journal-only commit was not built or tested locally.
