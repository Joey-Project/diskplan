# Best-Effort Apply

`DiskplanExecution` owns the Phase 5 boundary from an authoritative Phase 4 apply
authorization to typed mutation outcomes. No API accepts `DryRunReport`, a serialized token,
or a caller-created manifest as mutation authority.

## Execution units

The coordinator reconstructs the validated overlay DAG and verifies that its execution and
JIT action IDs exactly match the authorized manifest. Ordinary execution steps become one
unit each. Selected release actions whose APFS release sets share owner ActionIDs or file
objects are represented by the connected compound units already frozen in the manifest.

A compound unit:

- collects one JIT snapshot for every synthetic release action and every owner action;
- revalidates every allocation-group topology in the connected component before mutation;
- executes each owner action at most once, even when it contributes to multiple release sets;
- reports every owner result and the compound unit result together; and
- never reports rollback or transactional completion.

The scheduler preserves `prerequisite -> dependent` direction. A failed, partial, cancelled,
expired, skipped, or JIT-rejected unit blocks only its downstream dependents. Independent
units continue. Task cancellation starts no new unit, while a cancellation reported by one
adapter remains a typed outcome and does not cancel independent units.

## JIT protected properties

Immediately before one unit begins mutation, a sealed `EngineJITRevalidationCollector` handle
collects exactly that unit's actions, global survivor/namespace invariants, and release
topologies. Its source, factory, collection method, and snapshot construction remain internal;
only the engine-composition SPI may receive the opaque handle. JIT evaluation uses the same
selected protected properties as whole-plan
revalidation:

- object identity, including filesystem generation when the collector can prove it;
- selected content stability;
- access policy, ACL, provider state, and mount identity;
- root and parent-chain object identity and access-policy seals;
- frozen policy evidence and Git prerequisites; and
- every owner/refcount/link/snapshot expectation for APFS release units.

Missing, unknown, unreadable, collection-failed, identity-mismatched, content-mismatched, and
access-policy-mismatched evidence remain distinct. Directory child churn and unrelated
metadata are not promoted into a protected-property change. No mutation adapter is called
after a JIT rejection.

## Typed adapters and generic remove

All mutations use an `ExecutionAdapterOperation` derived from the immutable action contract.
The operation carries raw root/path bytes, expected namespace identities, the expected target
identity, and the typed postcondition. Specialized Git, Codex temporary, and versioned artifact
operations cannot silently fall back to generic removal.

The first generic adapter invokes `/bin/rm` with raw argv bytes through `posix_spawn`; it never
uses a shell, glob expansion, or UTF-8 reconstruction:

| Target | Arguments |
| --- | --- |
| File or symlink | `rm -- <raw-path>` |
| Forced file or symlink | `rm -f -- <raw-path>` |
| Directory | `rm -Rx -- <raw-path>` |
| Forced directory | `rm -Rfx -- <raw-path>` |

Before spawn it opens the root and each parent descriptor-relative with no-follow flags,
compares device, inode, type, and available generation against the authorized namespace, and
performs one final no-follow leaf check. This protects the point-in-time root/parent/target
object identities. The pathname consumed by `/bin/rm` still has the explicit
`path_race_residual` recorded by policy; this adapter does not claim continuous identity or
content stability after its final check.

`requiresForceWithWarning` is the only source of `-f`. The coordinator publishes a force
warning before JIT and mutation. An ordinary failure is never retried with force, privilege,
or a different adapter.

## Outcomes, post-verification, and recovery

Every mutation step records its adapter outcome and post-verification separately. The unit
status is derived from all steps, preserving success, partial failure, failure, cancellation,
prerequisite skip, JIT rejection, and epoch expiry. Target absence is the generic adapter's
authoritative postcondition; free-space deltas are not used as success proof.

There is no rollback. Failures, cancellations, post-verification uncertainty, and expected
residuals remain observable, and the next ordinary scan is the recovery source of truth.

## Event and audit sinks

The shell/TUI event stream is the default execution record. Persistent audit is optional. Each
event is sent to the interactive sink even when no audit sink exists. Audit errors, including
`ENOSPC`, are recorded as nonfatal `AuditWriteFailure` values and surfaced to the event sink;
they never suppress or reverse cleanup.

## Mutation firewall

The dry-run path terminates in `DryRunReport`, which has no adapter, capability, or coordinator
entry point. Phase 5 begins only after an authoritative authorization is claimed and only with
an engine-owned sealed JIT collector. The claim is single-use, and manifest/overlay/plan/epoch
mismatches fail before runtime-unit construction or adapter access.
