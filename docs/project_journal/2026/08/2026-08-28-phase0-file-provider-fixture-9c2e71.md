---
id: 20260828-9c2e71
title: Phase 0 Controlled File Provider Fixture
status: active
created: 2026-08-28
updated: 2026-08-28
branch: wip/phase0-fileprovider-fixture
pr:
supersedes: []
superseded_by:
---

# Phase 0 Controlled File Provider Fixture

## Summary

- Add the signed, real-host oracle needed to prove Diskplan's metadata-only File Provider
  probing does not materialize dataless items.
- Keep compile-only validation independent of signing and keep provisioning failures distinct
  from product failures.

## Current State

- A deterministic Xcode project builds an `LSUIElement` host plus embedded replicated
  File Provider extension against the repository's `DiskplanMacOS` package.
- The hidden UUID domain exposes a real 64 KiB sentinel fetch path and a sealed dataless
  directory that records any incorrect descent.
- The App Group JSONL oracle, immutable recovery manifest, and post-registration ready overlay
  are owner-private and UUID-scoped.
- Lifecycle teardown is exact-domain and exact-extension only; cleanup is limited to validated
  App Group run paths.
- Control records use bounded descriptor-bound reads with distinct missing, unreadable, and
  mismatch results. Cleanup atomically isolates the exact run directory and validates object
  identity/access policy without treating directory child churn as replacement.
- Recovery executes only the known signed host after physical-path, bundle/team identity, and
  signature validation. Registration verifies the elected bundle ID resolves to the current
  embedded extension, and unregister must converge to absence of that exact physical path.
- Both provider probes and a postflight extension-liveness barrier run inside the oracle window.
  Closure requires two continuous quiet seconds within 30 seconds; post-close assertion reads
  only descriptor-bound control data and verifies the persisted event fingerprint.
- Extension append failures poison the recorder and fail callbacks. File Provider callbacks and
  `pluginkit` operations are bounded, and late callbacks are atomically discarded.
- Recorder poison and teardown seal are immutable run-scoped evidence shared across extension
  instance recreation; append cannot recreate a missing run directory.
- Quiet timestamps follow fingerprint reads, deadline expiry wins over quiet success, and exact
  registry records require one absolute path.
- Cleanup validates an explicit manifest recovery copy and never suppresses restoration errors.
- Oracle append uses durable write-ahead poison and one absolute deadline for both recorder and
  JSONL lock acquisition; injected poison/event-storage failures remain poisoned across instance
  recreation.
- Final directory-removal failure restores and directly validates `manifest.json` at the original
  UUID path. Registry parsing requires strict UTF-8 and rejects malformed exact-bundle mentions.
- Cleanup rejects mount/device-boundary traversal before inventory. The current gate is
  explicitly probe-level; full scanner acceptance remains a later engine integration.
- Local unsigned compile and support tests are available without provisioning.

## Task List

- [x] Add the host and embedded replicated extension targets without testing mode.
- [x] Add deterministic item, fetch, enumeration, and callback-oracle behavior.
- [x] Add manifest-bound setup, status, acceptance, teardown, and recovery commands.
- [x] Add local unit, static-contract, shell, and unsigned build validation.
- [x] Harden control-file reads, manifest-bound cleanup, recovery trust, registration election,
  and quiet-window closure.
- [x] Close acceptance-window, callback-failure, timeout, registry-removal, window-semantic, and
  mounted-volume cleanup gaps found during integrated review.
- [x] Close cross-instance poison, post-read quiet timing, deadline precedence, malformed
  registry, late-append orphan, and cleanup-manifest rollback gaps from frozen rereview.
- [x] Close write-ahead poison durability, bounded lock contention, deterministic final-rmdir
  recovery, and strict registry-text parsing gaps from the second frozen rereview.
- [ ] Connect the controlled oracle to the real scanner `scan -> plan` acceptance entrypoint.
- [ ] Run the signed acceptance lifecycle on `India-mac-mini-m4-hoteng`.
- [ ] Resolve host/extension App Group provisioning if Xcode reports the expected blocker.
- [ ] Complete frozen-range review and land through the stacked Phase 0 PR chain.

## Handoff

- Phase: locally integrated with the reviewed macOS probe and Phase 0 foundation CI heads.
- Next step: review the integrated fixture merge, then copy or check out the accepted head on the
  India host and run the signed lifecycle.
- Blocker semantics: exit 78 with `provisioning-profile` means team profiles for both bundle IDs
  and the shared App Group are unavailable; it is not a non-materialization test result.

## Evidence

- Accepted architecture: `docs/design/accepted-plan.md`.
- Fixture contract and recovery procedure: `docs/design/file-provider-fixture.md`.
- `swift test --filter DiskplanFileProviderFixtureSupportTests`: 27 targeted support tests pass
  and cover
  concurrent JSONL writers, manifest/ready validation, typed secure-read failures,
  symlink-retaining cleanup, recursive cleanup, device-boundary rejection, append-failure
  poisoning, poison/event-storage injection across recorder recreation, recorder/event lock
  contention, deterministic final-rmdir recovery, late-callback arbitration, semantic window
  validation, and deterministic two-second quiet-window reset after a one-second-late callback.
- `python3 scripts/test-fileprovider-fixture-registration.py`: 12 parser/physical-path election,
  strict-UTF-8, malformed exact-bundle text, and exact-path removal tests pass.
- `scripts/fileprovider-fixture.sh build-unsigned`: Release host app and embedded extension
  compiled successfully with signing disabled.
- The resolved-only complete Swift gate passed 67 tests on the integrated tree. Canonical binary
  generation and the Swift/Rust cross-language process tests also passed.
- `scripts/test-macos-capabilities.sh`: 29 `DiskplanMacOS` tests and the live self-test passed;
  the signed fixture and real-host APFS fixture remained explicitly unavailable without their
  opt-in environment variables.
- `swift format lint`, `bash -n`, ShellCheck, plist validation, the fixture static safety test,
  and `git diff --check` passed.
- Signed India acceptance was intentionally not run in this worktree. It remains the next
  host-only gate and may return the documented provisioning-profile blocker.
