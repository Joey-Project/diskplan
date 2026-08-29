---
id: 20260829-a15e5c
title: Runtime Protocol 1.5 Execution Preview
status: active
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
- [ ] Run the remaining focused fixture, runtime-golden, and release checks on
  `India-mac-mini-m4-hoteng`.
- [ ] Complete frozen-head local review, sign the landing commit, and hand the
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
  directory ancestry. File verification records initial object identities and then
  rebinds, hashes, and closes one file at a time; a later replacement, content
  change, mode change, or path-access failure still fails closed.

## Handoff

- Phase: static implementation, generated bindings, fixtures, release contract,
  documentation, and local focused gates are complete; India-only final gates and
  frozen-head review remain.
- Next step: run the recorded focused commands on `India-mac-mini-m4-hoteng`, then
  update this journal with exact evidence and sign the reviewed head.
- Blocker: none; local dynamic execution is intentionally disabled after the global
  host policy changed on 2026-08-29.

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
  case was added. The final case remains assigned to the India-only rerun.
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
- The follow-up adds a synthetic 24-descriptor regression budget over a 64-artifact
  bundle without changing the process limit. This head has received static-only
  local validation; the corrected 57-test release suite remains assigned to India.
- The follow-up head passes Python AST parsing, Ruff static lint,
  `git diff --check`, and project-journal validation. No local dynamic command was
  run after the India-only host policy took effect.
