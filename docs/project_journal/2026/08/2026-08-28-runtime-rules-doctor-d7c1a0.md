---
id: 20260828-d7c1a0
title: Runtime Declarative Rules and Read-Only Doctor
status: active
created: 2026-08-28
updated: 2026-08-28
branch: wip/runtime-rules-doctor
pr:
supersedes: []
superseded_by:
---

# Runtime Declarative Rules and Read-Only Doctor

## Summary

- Add a platform-neutral strict canonical JSON rules and restricted user-policy boundary.
- Add a separate macOS composition target for typed, read-only doctor observations.

## Current State

- `DiskplanRules` parses at most 1 MiB through a bounded tokenizer that rejects duplicate or
  unsorted keys before object construction, noncanonical document framing and escapes, floats,
  non-minimal or out-of-range integers, unknown fields, and over-limit collections.
- Built-in rules consume raw path components encoded as lowercase hex and produce only
  candidate-bound report-only hints. Managed or future actions cover File Provider, APFS snapshot,
  CoreSpotlight, SQLite VACUUM, process close, archive or migration, Git GC/LFS, and package or
  container prune without exposing a stageability promotion initializer.
- Restricted user policy is limited to root-bound raw-byte protections, adapter enablement,
  thresholds, profile, budgets, and agent mode. No schema field accepts shell, argv, executable,
  environment, download, plugin, or arbitrary command input.
- Agent mode is `off`, `ask`, or `auto` with `ask` as the shipped default. The interface fixes the
  metadata allowlist and binds cache identity to model, schema, prompt, policy, disclosure profile,
  exact typed disclosed metadata, and evidence digests without selecting a provider, transport,
  credentials, or persistence backend. Every digest purpose has a distinct
  `diskplan/<binding-kind>/v1` domain. The metadata object retains the exact canonical payload
  bytes, rejects closed authentication schemes and bounded opaque/Base64 credential shapes, caps
  every public variant before encoding, and uses only the signed 64-bit canonical JSON integer
  range. Cache lookup and future transport seams consume one immutable invocation so its payload
  and binding cannot be selected independently. Transport accepts only a sealed authorized
  invocation: validated `auto` policy can authorize directly, while `ask` remains unavailable
  until a candidate-bound user-consent authority is integrated.
- `DiskplanDoctor` depends only on the macOS capability target and keeps composition outside the
  pure rules target. Its production operations
  expose only reads and return distinct unknown, unsupported, permission-denied, unavailable,
  unreadable, failed, and inconsistent states. TCC and APFS remain unavailable when an authoritative
  read-only proof would require a resource-specific probe; SIP remains unknown without a public
  authoritative read-only API. The doctor does not materialize paths,
  launch `lsof`, or modify process/system configuration. Effective user identity is reported
  separately and is never presented as filesystem permission or TCC capability.

## Task List

- [x] Define canonical bundled-rule and restricted user-policy schemas, versions, and digests.
- [x] Add raw-byte candidate recognizers and root-bound protection matching.
- [x] Add report-only managed/future-adapter hints and agent/cache authority seams.
- [x] Add typed read-only doctor service and injected production read operations.
- [x] Add negative fixtures for canonical JSON, command-shaped fields, unsafe path data,
  report-only authority, and doctor no-write behavior.
- [x] Close static review findings for disclosed-metadata cache binding, digest domain separation,
  managed-action tagged combinations, effective-user semantics, and whole-root protection.
- [x] Seal doctor probe injection, bind agent cache authority to validated effective policy, fix
  shipped rule ordering, and close credential/privacy plus metadata boundedness findings.
- [x] Couple exact agent payload and cache authority in one invocation and close short auth-scheme,
  bare Base64, common digest, and non-ASCII credential-classification boundaries.
- [x] Separate prepared and transport-authorized agent invocations so the default `ask` mode cannot
  cause metadata egress without a future explicit consent receipt.
- [x] Restrict model, schema, and prompt identifiers to a credential-screened closed ASCII grammar
  and keep them explicitly outside argv, environment, executable, path, and transport authority.
- [x] Run focused and full Swift validation when the shared dynamic test slot is assigned.
- [ ] Complete fresh-context review and delivery after dynamic validation.

## Handoff

- Phase: implementation, static validation, focused validation, and one serial full Swift pass
  complete.
- Next step: complete the parent-coordinated final review and delivery workflow.
- Blockers: none within this workstream.

## Evidence

- Accepted architecture: `docs/design/accepted-plan.md` sections 15.3 and 16.
- Existing authority contracts: `docs/design/policy-core.md` and
  `docs/design/macos-capability-probes.md`.
- Static validation: strict `swift-format lint`, `swiftc -frontend -parse`, and
  `git diff --check` pass for the changed Swift/package paths.
- Dynamic validation: `swift build --disable-sandbox` passes; focused `DiskplanRulesTests` passes
  11/11, `DiskplanDoctorTests` passes 4/4, `DiskplanPolicyTests` passes 63/63, and
  `DiskplanMacOSTests` passes 33/33. One serial `swift test --disable-sandbox --skip-build
  --no-parallel` pass completes 356/356.
- Asset validation: `shippedRuleAssetsAreCanonicalAndUseConservativeDefaults` reads
  `rules/builtin-v1.json` and `rules/user-policy-default-v1.json` from the repository source path,
  validates canonical ordering/schema, and passes in both focused and full runs.
- Final identifier hardening: `automaticAgentAuthorizationRejectsUnsafeIdentifiersForEveryField`
  passes 1/1 with Apple Swift 6.3.3 (`swift-driver` 1.148.6), covering exact-field rejection before
  auto authorization.
