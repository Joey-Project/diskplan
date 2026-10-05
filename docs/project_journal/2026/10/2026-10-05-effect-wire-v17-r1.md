---
id: 20261005-v17r1
title: Effect Permission IPC 1.7 Wire And Canonical Slice
status: active
created: 2026-10-05
updated: 2026-10-05
branch: wip/effect-wire-v17
pr:
supersedes: []
superseded_by:
---

# Effect Permission IPC 1.7 Wire And Canonical Slice

## Scope And Frozen Interface

Implement the additive protobuf wire types, Rust canonical encoding and digest
verification, and explicit protocol 1.7 runtime/sealed structural validators
for the effect-permission contract. The accepted
[binding contract](../../../design/effect-permission-bindings-v2.md) and
[accepted plan](../../../design/accepted-plan.md) remain authoritative. This
slice does not redefine fields, tags, hash domains, canonical order, limits, or
policy.

The implementation owner for this slice is OpenAI Codex (GPT-6 Luna). It is a
bounded wire/canonical contribution to the larger effect-permission workstream,
not proof that the live engine or frontend supports effect-authorized mutation.

## Delivered

- Appended protocol 1.7 requirement, consent, edit, acknowledgement, and review
  fields to `proto/diskplan/v1/ipc.proto`; regenerated Rust and Swift bindings
  with the pinned Protobuf toolchain.
- Added pure Rust v2 canonical requirement/consent encoders, strict decoders,
  domain-separated SHA-256 digests, and verification of exact action/manifest
  references in `diskplan-core`; consent action and lineage identifiers are
  exactly 32 bytes.
- Added explicit `PROTOCOL17_MINOR` structural validators in `diskplan-proto`:
  old minors reject the additive fields, protocol 1.7 requires schema v2 and
  complete executable-action bindings, and consent/apply-review records check
  closed permissions, limits, exact references, selected-action coverage, and
  conflicting variant groups. Requirement operation and permission accept
  only explicit values 1 or 2; present zero is rejected. The live negotiation
  default was not changed.
- Added shared `canonical-effect-v2` byte/digest vectors and separate
  `runtime-v1.7` component-level protobuf vectors, with independent
  generator/check scripts. Historical runtime 1.4-1.6 fixture files were not
  edited.

## Validation

All generation, formatting, build, shell lint, and test commands ran on
`India-mac-mini-m4-hoteng` under `scripts/release/run_bounded.py` with a
900-second / 1-MiB cap, in owner-private task root
`/private/tmp/diskplan-effect-wire-v17.4shOAX` (uid 501, mode 0700).

- `scripts/proto-codegen.sh check` passed with protoc 35.1 and the task-local
  `protoc-gen-swift` 1.38.0.
- `scripts/effect-canonical-fixture.sh check` and
  `scripts/protocol17-fixtures.sh check` passed.
- `cargo test --locked -p diskplan-core` passed: 10 unit tests, 9 integration
  tests across the two canonical fixture suites, and doc tests.
- `cargo test --locked -p diskplan-proto` passed: 6 unit tests, 8 runtime
  golden tests, and doc tests. Existing protocol 1.4-1.6 golden compatibility
  checks passed unchanged.
- `bash -n` and `shellcheck` passed for both new fixture scripts.
- Review corrections were rerun on India from source commit
  `5cd933dc5100eab5f44bc0cb196b2472711bfe14`: the component fixture generator
  now includes `Some(0)` operation and permission cases, and canonical tests
  reject 31- and 33-byte action/lineage IDs through encode, decode, and public
  acknowledged-consent verification. The bounded runner terminated with
  `result: passed`, `exit_code: 0`, `leader_exit_code: 0`,
  `process_group_verified: true`, and `cleanup.quiescent: true` after 25,495 ms.
  Its captured child output was 4,445 bytes with SHA-256
  `a5d9dcb56c37d16895d1e84a3ddf77c8490b5e71c1872e786fd8fc4cace349d6`; the
  regenerated `runtime-v1.7/fixtures.json` SHA-256 is
  `50130ca40277239d881ac914d256d7557f432b727c49b2769c08b1fff6a64cdf`.
  India source snapshots under that task root matched these SHA-256 values:
  `runtime.rs` `a1be7a67d0564800e289a53a51b2fe1b8c386a4ffa82dd8d67cd4b2d223e11d8`,
  `effect_canonical.rs` `444fc80bc08a6c0ef23898e2ef66fbf2c825dfba9954d18491d1dba135497b22`,
  `effect_canonical_golden.rs` `1ec43b56dc0563f12f014434e63e31688b3c1022e92b8aa3a65ef2de49b32c0f`,
  and `effect_runtime_fixture_generator.rs`
  `8e8e654d510b09db478d528fc757b524847daab7ca754e8201eafbb0d83f9388`.
  Git reports no changes under the historical runtime 1.4, 1.5, or 1.6 fixture
  directories.
- `cargo check --locked --workspace` is blocked by two unowned exhaustive
  matches in `rust/crates/diskplan-cli/src/runtime_client.rs` (lines 258 and
  274) that do not yet handle `SetEffectConsent`. The CLI was not modified in
  this slice; the exact integration gap was reported to the parent agent.

The last targeted validation runner output SHA-256 was
`e3f2bac1397b315a09ca9df93bd3a7460c60c48b8131367874df7e236a1f785e`. The
workspace-check failure output SHA-256 was
`afc134846ad7a3215a7c4858755fe663732449ddd6fee4a90770ac2130ab926f`.

## Remaining Integration

- Engine policy/runtime authorities, evidence sessions, live overlay editing,
  fresh-revalidation provenance, and production mutation admission still need
  the subsequent integration slices.
- Swift frontend consumers still need the coordinated fail-closed
  `setEffectConsent` exhaustive-case bridge; `RuntimeOverlayAuthority.swift`
  was not modified here.
- Rust CLI `SetEffectConsent` exhaustive matches still block workspace builds.
- The high-level `RuntimeChainVerifier` still performs only shape/reference
  admission. `verify_acknowledged_effect_consent_v2` has no production caller
  and is exercised only by core tests; connecting canonical verification to a
  production 1.7 consumer remains required work. Do not infer complete runtime
  chain validation from the component validators or fixtures.
- No protocol 1.7 live default/negotiation bump was made. These component-level
  validators do not establish complete 1.7 runtime-chain or production
  execution support.
