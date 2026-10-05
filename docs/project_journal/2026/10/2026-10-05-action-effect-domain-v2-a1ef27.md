---
id: 20261005-a1ef27
title: Action Effect Binding V2 Swift Domain Slice
status: active
created: 2026-10-05
updated: 2026-10-05
branch: wip/effect-domain-v2
pr: https://github.com/Joey-Project/diskplan/pull/30
supersedes: []
superseded_by:
---

# Action Effect Binding V2 Swift Domain Slice

## Summary

Added immutable Swift records and canonical SHA-256 bindings for action-effect
requirements and per-action effect consents. The raw records are untrusted
transport/model data; constructing one does not authorize mutation. Later plan
validation must bind every reference and match the exact policy/schema version
bytes supported by that plan.

## Current State

- `ActionEffectRequirementBindingV2` and `EffectConsentBindingV2` validate raw
  tags, widths, version bytes, operation/permission compatibility, bounded
  canonical input, and raw UTF-8 version strings. Canonical digest domains are
  `diskplan/effect-requirement/v2\0` and `diskplan/effect-consent/v2\0`.
- The requirement digest covers its operation, permission, variant group,
  target-scope digest, and operation-contract digest. Consent covers all exact
  action, lineage, requirement, target, plan, evidence, version, and event
  references. Policy/schema bytes are preserved without normalization; the
  event identifier remains opaque bytes.
- Plan/action construction, semantic reference validation, consent creation,
  epoch authority, IPC/Rust integration, and runtime wiring remain with their
  owning integration lanes. This slice implements no default permission grant.

## Validation Evidence

- Source archive: `git archive --format=tar
  368ba199a3b8b7e8eecff160f39cf0ea80df23e4`; SHA-256
  `2a9aef593c633c57a8556ff8da479d25c3034a6f2b494fcb0fa04120f87cb296`.
  The India source snapshot used that tracked archive plus the two new Swift
  files below. Its base worktree head was
  `368ba199a3b8b7e8eecff160f39cf0ea80df23e4` on
  `wip/effect-domain-v2`.
- Swift source SHA-256:
  `34618b4e6e9aedd75240e68c2da7be0c74ed1139990542e60ba3b4d04d23e468`.
  Test source SHA-256:
  `cb19eadd838272ba57aadff4ee1a0ff5b2d18f693ceb800dbfdefd2df57bfad2`.
- India environment: `India-mac-mini-m4-hoteng`, macOS 26, Apple Swift
  6.3.3. Package lock SHA-256 remained
  `9c858ad2ab85466112834e09bfa270f01d0835e028244ee6a8e2e5b4ca677e98`.
- Targeted command, run under the 900-second / 1-MiB process-group-bounded
  runner and `scripts/ci/package-resolved-guard.sh`:
  `python3 scripts/release/run_bounded.py --timeout-seconds 900 --max-output-bytes 1048576 --output /private/tmp/diskplan-effect-domain-v2.k0REW1/swift-test-final.log -- bash scripts/ci/package-resolved-guard.sh run Package.resolved -- swift test --filter actionEffect`.
  Result: exit 0; all seven selected tests passed; process group verified
  quiescent. Captured command output was 7,778 bytes with SHA-256
  `785eed3eb4648da1c70c1c77dcc92aaa4939f4d6dae7c90c393d7651389d0cb3`.
- `xcrun swift-format lint --strict` on the two new Swift files passed.
- An initial runner attempt passed the shell guard to Python and failed before
  running Swift. The command was corrected to invoke the guard with Bash; the
  successful bounded result above is the validation evidence.

## Next Steps

- Integrate the records with plan/action construction and exact consent
  reference validation in the owning runtime/policy lane.
- Integrate the coordinated IPC 1.7 and Rust canonical implementation and
  shared fixture under `proto/fixtures/canonical-effect-v2/`.
- Add the plan-bound consent constructor and fresh execution-epoch checks in
  their assigned implementation lanes.

## Review Boundary

This is targeted implementation validation, not a formal release review or an
exact-head PR readiness result.
