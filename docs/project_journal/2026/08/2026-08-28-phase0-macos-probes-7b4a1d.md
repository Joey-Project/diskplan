---
id: 20260828-7b4a1d
title: Phase 0 macOS Capability Probes
status: active
created: 2026-08-28
updated: 2026-08-28
branch: wip/phase0-macos-probes
pr:
supersedes: []
superseded_by:
---

# Phase 0 macOS Capability Probes

## Summary

- Implement the high-risk APFS and File Provider capability slice behind a typed Swift API.
- Preserve read-only scan behavior and explicit unknown/no-credit states where public macOS APIs cannot prove reclaim.

## Current State

- `DiskplanMacOS` requires a verified process-wide dataless materialization policy token before volume, item, or provider path probes.
- The Darwin shim performs descriptor-relative, single-component, no-follow/beneath item probes and bounds-checks fixed attribute buffers before Swift parses a versioned wire representation.
- APFS evidence distinguishes logical bytes, nominal allocated bytes, immediate private reclaim, sharing flags, clone ID, and clone refcount. Conditional shared reclaim, snapshot attribution, and provider hidden backing remain unavailable/no-credit.
- File Provider evidence uses public filesystem flags, provider identity, immediate metadata-only coordination, and promised values. Dataless directories do not descend; materialized provider directories may descend metadata-only while remaining report-only.
- Provider identity is fail-closed: only a returned provider identity or the API's authoritative not-provider result continues ordinary classification. Permission, timeout, failure, and inconsistent results do not descend without positive sync-root or inherited provider-bound evidence.
- The controlled CLI accepts only `--self-test`, creates its own temporary root, and has no arbitrary-path mode.

## Task List

- [x] Add typed capability and process materialization-policy APIs.
- [x] Add volume and item `getattrlist` probes with returned-mask interpretation.
- [x] Add File Provider boundary and metadata-only evidence.
- [x] Add deterministic malformed/mask/degradation tests and an APFS clone fixture.
- [x] Add a controlled local probe and India-host File Provider fixture hook.
- [x] Make indeterminate File Provider identity report-only and non-descending.
- [ ] Run independent review and real-host File Provider callback-zero acceptance.

## Handoff

- Phase: local Phase 0 implementation and Tier 1 validation.
- Next step: independent frozen-range review, then run the controlled extension fixture gate on `India-mac-mini-m4-hoteng` when that fixture exists.
- Blocker: no controlled File Provider extension fixture is implemented in this slice, so callback-zero non-materialization acceptance is explicitly unavailable rather than inferred.

## Evidence

- Accepted design: `docs/design/accepted-plan.md`.
- Implementation contract: `docs/design/macos-capability-probes.md`.
- Local `swift build` passed on macOS 26.6.1 with Swift 6.3.3.
- Local `swift test --filter DiskplanMacOSTests` passed 11 focused tests, including real APFS `clonefile`, no-follow symlink fixtures, and all indeterminate identity/flags/inherited combinations.
- Local full `swift test` passed all 22 Swift tests after the fail-closed provider disposition fix.
- `swift-format lint` passed for the new Swift source, test, and probe-tool paths.
- `bash -n` and ShellCheck 0.11.0 passed for `scripts/test-macos-capabilities.sh`.
- Local `swift run diskplan-macos-probe --self-test` reported APFS logical/private evidence as known, local provider identity as unsupported, and controlled provider acceptance as unavailable.
- `scripts/test-macos-capabilities.sh` leaves the extension-backed India-host oracle as an explicit hook; it does not claim that gate passed.
