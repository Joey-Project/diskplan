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
  references in `diskplan-core`.
- Added explicit `PROTOCOL17_MINOR` structural validators in `diskplan-proto`:
  old minors reject the additive fields, protocol 1.7 requires schema v2 and
  complete executable-action bindings, and consent/apply-review records check
  closed permissions, limits, exact references, selected-action coverage, and
  conflicting variant groups. The live negotiation default was not changed.
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
- No protocol 1.7 live default/negotiation bump was made. These component-level
  validators do not establish complete 1.7 runtime-chain or production
  execution support.
