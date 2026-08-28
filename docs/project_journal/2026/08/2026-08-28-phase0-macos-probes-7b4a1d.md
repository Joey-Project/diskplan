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

- `DiskplanMacOS` exposes only the real-syscall policy installer publicly and re-reads the live process-wide dataless materialization policy immediately before every path-touching probe step.
- The Darwin shim performs descriptor-relative, single-component, no-follow/beneath item probes, requests the real backing device with `FSOPT_RETURN_REALDEV`, and parses short kernel attribute results by returned masks and declared bounds before Swift receives a versioned wire representation.
- APFS evidence distinguishes logical bytes, nominal allocated bytes, immediate private reclaim, sharing flags, clone ID, and clone refcount. Conditional shared reclaim, snapshot attribution, and provider hidden backing remain unavailable/no-credit.
- File Provider evidence uses public filesystem flags and provider identity. In-process metadata coordination is disabled and promised metadata is typed unavailable because a running accessor cannot be killed and reaped safely.
- Provider identity is fail-closed: `NSFileNoSuchFileError` means identifier-absent, not local. Absent, permission, timeout, failure, and inconsistent results do not descend without positive sync-root or inherited provider-bound evidence.
- File Provider Foundation identity operations are derived from the held parent FD/raw slot, seal both held/derived parent and child identity before and after, separately reject same-object `isDataless` transitions, and use one identity deadline without spawning metadata background work.
- Descent requires a typed directory result and uses stable postflight evidence; provider-bound regular files remain non-descending.
- The controlled CLI accepts only `--self-test`, creates its own temporary root, and has no arbitrary-path mode.

## Task List

- [x] Add typed capability and process materialization-policy APIs.
- [x] Add volume and item `getattrlist` probes with returned-mask interpretation.
- [x] Add File Provider boundary evidence and conservatively keep promised metadata unavailable.
- [x] Add deterministic malformed/mask/degradation tests and an APFS clone fixture.
- [x] Add a controlled local probe and India-host File Provider fixture hook.
- [x] Make indeterminate File Provider identity report-only and non-descending.
- [x] Bind Foundation URL operations to the descriptor-relative slot and preserve typed replacement/failure evidence.
- [x] Revalidate live materialization policy and bound provider identity by one subsecond-capable deadline.
- [x] Separate object identity from materialization stability and use postflight evidence for traversal.
- [x] Request real device identity and require a typed directory before any descent decision.
- [x] Accept valid short Darwin attribute buffers without padding or crediting omitted fields.
- [x] Disable unkillable in-process coordination and bind the derived parent path to the held parent FD identity.
- [ ] Run independent review and real-host File Provider callback-zero acceptance.
- [ ] Run real APFS volume-group device-identity acceptance on the India host when its fixture exists.

## Handoff

- Phase: local Phase 0 implementation and Tier 1 validation.
- Next step: independent frozen-range review, then run the controlled extension fixture gate on `India-mac-mini-m4-hoteng` when that fixture exists.
- Blocker: no controlled File Provider extension or true APFS volume-group fixture is implemented in this slice, so callback-zero non-materialization and cross-volume real-device acceptance remain explicitly unavailable rather than inferred.

## Evidence

- Accepted design: `docs/design/accepted-plan.md`.
- Implementation contract: `docs/design/macos-capability-probes.md`.
- Local `swift build` passed on macOS 26.6.1 with Swift 6.3.3.
- Local `swift test --filter DiskplanMacOSTests` passed 28 focused tests, including APFS clone, live-policy mutation, child and parent replacement, child-hardlink parent mismatch, renamed-parent missing and unreadable classification, both same-object materialization directions, stable postflight traversal, real-device option, valid short/malformed kernel buffers, metadata-unavailable behavior, typed directory guards, and the subsecond identity deadline.
- Local full `swift test` passed all 39 tests after the release-review changes.
- `swift-format lint` passed for the new Swift source, test, and probe-tool paths.
- The C shim passed `clang -std=c11 -Wall -Wextra -Werror -fsyntax-only` against the active macOS SDK.
- `bash -n` and ShellCheck 0.11.0 passed for `scripts/test-macos-capabilities.sh`.
- Local `swift run diskplan-macos-probe --self-test` reports APFS logical/private evidence and `provider_identity_status: unavailable`, keeping absent provider identity non-authoritative.
- The complete local `scripts/test-macos-capabilities.sh` gate passed its 28 focused tests and controlled CLI probe; it leaves both the extension-backed and real APFS volume-group India-host oracles as explicit `not-available` hooks and does not claim either gate passed.
