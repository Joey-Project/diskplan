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
- The complete lifecycle and recovery path share one host-global single-flight lock. Every domain
  or extension registry mutation has durable exact-operation and host-global ambiguity evidence
  outside the run tree. Same-boot unknown add completion remains unresolved until an original
  completion record or reboot ordering barrier exists, and cleanup rejects pending evidence.
- Control records use bounded descriptor-bound reads with distinct missing, unreadable, and
  mismatch results. Cleanup atomically isolates the exact run directory and validates object
  identity/access policy without treating directory child churn as replacement.
- Callback admission now has durable pre-attempt evidence, one absolute failure-publication
  deadline, and an atomic sealing cutoff. Extension initialization fails closed if the admission
  capability cannot be established, while enumerators retain that minimal capability across
  extension lifetime changes.
- Oracle acceptance binds one run-directory descriptor through locks, events, window, and markers;
  rejects canonical replacement or extended-ACL drift; validates every event identity and exact
  sequence; and treats every sealed-directory enumerator operation as forbidden evidence.
- Manifest, window, cleanup-recovery, and sibling-evidence publication now use explicit file and
  directory durability barriers. Injected crash/fsync tests prove that a sealed oracle or completed
  cleanup cannot be reported before its recovery evidence is durable.
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
- Oracle closure now atomically checks health, snapshots events, publishes the closed window, and
  seals under one recorder lock; assertion consumes only the immutable sealed snapshot.
- Callback claim, bounded local/recorder/JSONL locks, recorder state, append, and poison all obey
  their original absolute deadline. Cleanup keeps durable sibling recovery evidence outside the
  staging tree until final `rmdir` succeeds.
- The callback gate owns and evaluates its monotonic deadline atomically with the completion
  claim. Callback-only materialization notifications always complete while durable poison keeps
  recording failures fail-closed.
- Final staging removal is parent-directory durable before sibling recovery evidence is deleted.
  The production recovery entry validates the exact sibling manifest and finishes only the
  deterministic UUID staging path, including the already-removed post-crash state.
- Every non-sealed recorder failure persists an immutable failure marker before callback
  completion, including local-lock timeout and state-read failure. The marker is independent of
  successful append cleanup and remains fail-closed across extension instances.
- Sibling recovery is opened descriptor-relative from the trusted App Group `runs` parent using
  only the exact expected basename; Host argument parsing rejects noncanonical and symlink plus
  dot-dot aliases before status, path reads, teardown, or cleanup.
- A separate cross-process attempt gate spans each record attempt through durable failure-marker
  publication. Health, fingerprint, final seal, and sealed snapshot take the gate exclusively,
  share the original absolute deadline, and fail closed rather than accepting across an in-flight
  failure.
- Every admitted record attempt persists a unique incomplete marker before callback logic and
  clears it only after a durable event or failure marker. Publication failure and simulated crash
  leave evidence that remains poisoned across recorder recreation.
- Teardown sealing is idempotent across recovery runs and resumes a clean durable
  sealing-plus-cutoff intermediate without appending a malformed second cutoff. Strict JSONL
  decoding rejects unknown and duplicate event keys.
- The host-global lifecycle lock now passes and verifies the inherited locked open-file
  description instead of trusting a caller-set boolean environment variable. Cleanup fsyncs the
  parent immediately after staging rename and before inventory or deletion.
- The shell consumes the inherited lock descriptor before running lifecycle children and proves
  the helper parent still owns the lock, preventing nested reuse or detached-child pinning. The
  strict JSON scanner has an explicit depth bound before decoding.
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
- [x] Close atomic acceptance sealing, late-callback deadline claim, single-entry recorder
  deadline, strict lock acquisition, and crash-surviving external recovery gaps from the third
  frozen rereview.
- [x] Close parent-sync ordering, gate-owned atomic deadline comparison, production sibling
  recovery, and callback-only completion gaps from the fourth frozen rereview.
- [x] Close durable poison for all non-sealed recorder failures and descriptor-bound rejection of
  aliased sibling recovery manifests from the fifth frozen rereview.
- [x] Close the record-failure publication race with bounded cross-process in-flight
  synchronization from the sixth frozen rereview.
- [x] Preserve durable incomplete-attempt evidence across failure-marker publication errors and
  process crashes from the seventh frozen rereview.
- [x] Close idempotent teardown sealing, lifecycle-lock capability, staging-rename durability,
  and strict event-key parsing gaps from final frozen review.
- [x] Close lifecycle capability propagation and deep-JSON stack exhaustion gaps from final
  rereview.
- [x] Replace same-boot absence heuristics with durable prepared/dispatched/original-completion
  states, an exact host-global pending-run gate, and a boot-session ordering barrier for late
  File Provider and PlugInKit add success.
- [x] Bind cleanup recovery to the exact pre-rename staging generation and retain evidence on replacement.
- [x] Keep every active removal predecessor durable across successor publication crashes until an
  authoritative successor completion plus exact absence, including the shared extension path.
- [x] Attribute late predecessor callbacks by operation UUID, require post-completion absence for
  every same-boot dispatched removal, and recursively retain legacy predecessor cohorts.
- [x] Carry prepared/failed removal leaves with active predecessors as merge tombstones until the
  gate and leaf durably share the successor operation ID, including repeated successor-gate
  crashes before leaf overwrite.
- [x] Add a reachable same-successor recovery regression for a completion-state crash that leaves
  the leaf with a durably pruned inactive tombstone while the gate retains the older cohort,
  verified by the focused, fixture-support, and full serial Swift gates.
- [x] Add manifestless prepare rollback, pre-prepare shell recovery, and durable empty-event creation.
- [x] Seal exact event bytes and held events/window identities, enforce strict JSONL framing, and bind the oracle to one boot session.
- [x] Treat ctime/mtime as control-byte revalidation triggers and keep content, identity, and access-policy failures distinct.
- [x] Apply the same exact-byte revalidation and typed metadata distinctions to host-global mutation
  journals.
- [x] Revalidate mutation-journal generation, bytes, and access policy through the final canonical
  name lookup, with distinct missing, identity, unavailable, and unstable results.
- [x] Make canonical-name `fstatat` the final journal-read seal after every descriptor/content/ACL
  check, including post-preliminary-lookup replacement detection.
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
- The Phase 0 integration merge passed all 104 focused
  `DiskplanFileProviderFixtureSupportTests` on the combined scanner, policy, and execution tree.
- `swift test --no-parallel`: all 146 Swift tests pass. External-mutation
  tests cover same-boot late success, authoritative failure and success-plus-remove, injected boot
  changes, reboot-absent and reboot-present reconciliation, independent recovery instances,
  cross-run gate exclusion, extension-add parity, prepared-state nondispatch recovery, successful
  compensation re-confirmation, and interrupted gate/state/fsync ordering. The
  wider support coverage includes
  concurrent JSONL writers, manifest/ready validation, typed secure-read failures,
  symlink-retaining cleanup, recursive cleanup, device-boundary rejection, append-failure
  poisoning, poison/event-storage injection across recorder recreation, recorder/event lock
  contention, one-entry deadline propagation, atomic final-snapshot sealing against a racing
  callback, gate-owned delayed-timeout callback arbitration, crash-surviving sibling manifest
  evidence before and after parent-durable final removal, production recovery of partial and
  already-removed staging state, exact rejection of symlink-plus-dot-dot recovery aliases,
  durable poison after local-lock and state-read failure, bounded sealing contention, atomic
  failure-marker publication against a racing final seal, injected failure-marker publication,
  abandoned-attempt recovery across recorder recreation, deterministic final-rmdir recovery,
  semantic window validation, deterministic two-second quiet-window reset after a one-second-late
  callback, idempotent teardown sealing, strict event-key decoding, and staging-rename crash
  recovery before any deletion. Follow-up regressions also cover exact cleanup-staging replacement,
  predecessor-to-successor mutation recovery, durable domain/extension removal predecessor cohorts,
  operation-ID-attributed late predecessor completion, recursive legacy-chain recovery,
  prepared/failed leaf merge tombstones across two consecutive successor gate-before-leaf crashes,
  same-operation cohort recovery after a leaf durably prunes an inactive gate tombstone,
  timestamp-only mutation-journal revalidation, true initial/final-window byte drift, final-window
  ACL drift, post-preliminary-lookup identity replacement caught by the final name seal, typed
  final-name missing/unavailable results, bounded unstable-window failure, manifestless prepare
  rollback, first-event durability,
  exact sealed-byte and canonical-entry drift, strict JSONL framing, boot-session rejection,
  metadata-only ctime changes, distinct content/access-policy changes, and cross-boot PID reuse.
- `python3 scripts/test-fileprovider-fixture-registration.py`: 13 parser/physical-path election,
  strict-UTF-8, malformed exact-bundle text, and exact-path removal tests pass.
- `python3 scripts/test-fileprovider-fixture-pending-preflight.py`: 7 descriptor-pinned root,
  cross-run, interrupted-publication, cleanup-recovery, access-policy, and symlink tests pass.
- `python3 scripts/test-fileprovider-fixture-pluginkit.py`: 5 process-completion classification
  tests pass; timeout and output uncertainty remain unresolved while normal/nonzero terminal exit
  are recorded as authoritative completion.
- `scripts/fileprovider-fixture.sh build-unsigned`: Release host app and embedded extension
  compiled successfully with signing disabled.
- The resolved-only complete serial Swift gate passed all 146 tests on the integrated tree. The
  unrelated subsecond macOS probe deadline test timed out in one concurrent run but immediately
  passed its focused rerun and the complete serial run.
  Canonical binary generation and the Swift/Rust cross-language process tests passed.
- `scripts/test-macos-capabilities.sh`: 30 `DiskplanMacOS` tests and the live self-test passed;
  the signed fixture and real-host APFS fixture remained explicitly unavailable without their
  opt-in environment variables.
- `swift-format lint --strict`, `bash -n`, ShellCheck, plist validation, the fixture static safety
  test, registration (13), pending-preflight (7), PlugInKit (5), subprocess (6), lifecycle-lock
  (5), cross-language, deployment-target, and `git diff --check` gates passed.
- Signed India acceptance was intentionally not run in this worktree. It remains the next
  host-only gate and may return the documented provisioning-profile blocker.
