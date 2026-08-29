# Best-Effort Apply

`DiskplanExecution` owns the Phase 5 boundary from an authoritative Phase 4 apply
authorization to typed mutation outcomes. No API accepts `DryRunReport`, a serialized token,
or a caller-created manifest as mutation authority.

## Execution units

The coordinator reconstructs the validated overlay DAG and verifies that its execution and
JIT action IDs exactly match the authorized manifest. Ordinary execution steps become one
unit each. Selected release actions whose APFS release sets share owner ActionIDs or file
objects are represented by the connected compound units already frozen in the manifest.
Allocation-group and file-object identities are keyed by raw UTF-8 bytes throughout topology
lookup, runtime-unit construction, and post-verification; canonically equivalent Swift strings
do not collapse distinct filesystem identifiers.

A compound unit:

- collects one JIT snapshot for every synthetic release action and every owner action;
- revalidates every allocation-group topology in the connected component before mutation;
- executes each owner action at most once, even when it contributes to multiple release sets;
- reports every owner result and the compound unit result together; and
- never reports rollback or transactional completion.

The scheduler preserves `prerequisite -> dependent` direction. A failed, partial, cancelled,
expired, skipped, or JIT-rejected unit blocks only its downstream dependents. Independent
units continue. Compound owners retain their internal DAG: a failed owner skips only its
downstream owners, while independent owners continue. Task cancellation, epoch expiry, or a
superseding preparation starts no new owner action. An adapter call that has already begun is
allowed to finish and is post-verified before later owners are marked not started.

## JIT protected properties

Immediately before one unit begins mutation, the sealed `EngineRevalidationCollector` handle
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

Each JIT request binds the authorization's current binding hash, preparation generation,
epoch/reference time, exact unit actions, exact allocation groups, and a random 32-byte
one-shot nonce. The collector must echo that envelope and return a complete fresh policy
snapshot from a capture distinct from both the immutable plan and whole-plan preparation.
Every action in that snapshot must also bind the same global-facts hash. Absent, failed, stale,
mixed-global-facts, or reused captures and nonces fail closed. A newer preparation also
revokes any older authorization that has not yet been claimed.

## Typed adapters and generic remove

All mutations use an `ExecutionAdapterOperation` derived from the immutable action contract.
The operation carries raw root/path bytes, root and parent namespace identity/access seals,
the target identity/access/content contract, and the typed postcondition. Specialized Git,
Codex temporary, and versioned artifact operations cannot silently fall back to generic
removal.

The first generic adapter invokes `/bin/rm` with raw argv bytes through `posix_spawn`; it never
uses a shell, glob expansion, or UTF-8 reconstruction:

| Target | Arguments |
| --- | --- |
| File or symlink | `rm -- <raw-path>` |
| Forced file or symlink | `rm -f -- <raw-path>` |
| Directory | `rm -Rx -- <raw-path>` |
| Forced directory | `rm -Rfx -- <raw-path>` |

Before spawn it opens the root, each parent, and target descriptor-relative with no-follow
flags; compares device, inode, type, and available generation; and asks the engine-owned
collector to recollect the selected root/parent seals and target access/content properties
through those held descriptors. Missing, unreadable, identity mismatch, access mismatch, and
namespace mismatch remain distinct. This protects the point-in-time root/parent/target
preconditions. The pathname consumed by `/bin/rm` still has the explicit
`path_race_residual` recorded by policy; this adapter does not claim continuous identity or
content stability after its final check.

Generic removal therefore accepts only an explicit path-slot action whose content contract is
`explicitlyNotApplicable`. An action that requires content stability must use a native
descriptor-bound/quarantine adapter or remain report-only; it cannot silently reach `/bin/rm`.
The child receives `/dev/null` as stdin and runs in its own process group. Cancellation or epoch
expiry supervises it with `TERM`, a bounded grace interval, `KILL`, and reap; POSIX errno,
normal exit status, terminating signal, cancellation, and timeout stay typed separately.

Git worktree removal uses a dedicated descriptor-bound quarantine adapter. It verifies the
owner-private source namespace and complete raw-byte subtree coverage, creates a per-execution
exclusive `0700` same-filesystem quarantine directory, and seals its object identity and access
policy. The held source parent receives the same runtime seal. UID/GID, mode, ACL, flags,
device, `fstatfs` mount identity, missing state, unreadability, and collection failure are
rechecked independently at rename/restore and before deletion. It
atomically moves the exact root into the fixed leaf, proves the held source and destination
descriptors name the same object, and repeats coverage before recursive native deletion.
Verification failure attempts an exclusive restore; restore collision or deletion failure
retains a typed recovery locator.

Only after root deletion may the adapter delete administrative metadata, and it deletes only
the descriptor-bound worktree registration whose full metadata coverage digest was frozen in
the plan. Immediately before unlinking the registration root, the canonical raw leaf must still
name the held administrative identity. It never runs repository-
wide `git worktree prune`, so unrelated registered or stale worktrees remain untouched.
Cancellation, deadline, or registration identity/coverage drift produces an explicit typed
residual and a partially successful step without changing the root-deletion result.

Dirty worktrees and every remove chain that requires discarding local changes are report-only in
v1. The immutable plan retains their observed change set and clean-successor evidence for
explanation, but policy marks both the discard and dependent remove actions blocked. A waiver
cannot stage them, apply preparation cannot mint a capability for them, and both the production
router and quarantine adapter reject them before any Git process starts. Clean descriptor-bound
quarantine removal remains executable. No Git worktree operation can route to generic removal.

Raw subtree coverage protects three independent properties. Device/inode/type/generation protect
object identity; owner/group/mode/ACL/flags protect access policy; and size plus digest protect
content stability. Access fields are excluded from the content digest, so a stable ACL/flag
change reports an access-policy failure rather than a content mismatch. `mtime`/`ctime` changes only trigger one bounded reread within the same byte
budget. Matching bytes and identity after that reread are accepted, while byte drift rejects
even if the file identity is unchanged. Missing, unreadable, failed collection, and each
property mismatch remain typed separately.

`EngineExecutionComposition` is the production Phase 4/5 factory. It binds one sealed collector
to the preparation engine, final descriptor verification, JIT/release verification, and a typed
adapter router. Codex-temporary and versioned-artifact operations remain explicitly
unconfigured in this slice and return a typed unsupported failure; they never fall back to
generic removal.

`requiresForceWithWarning` is the only source of `-f`. `ApplyReadyReport` lists every such
action and binds the exact list into an apply-review hash. Authorization requires an explicit
frontend confirmation of that hash and list. The coordinator publishes a second runtime
warning before JIT and mutation. An ordinary failure is never retried with force, privilege,
or a different adapter.

## Outcomes, post-verification, and recovery

Every mutation step records its adapter outcome and post-verification separately. After all
owners of a compound release unit have stopped, the engine recollects a typed
`allocationGroupReleased` proof for every connected allocation group. Target absence alone is
not sufficient; false, missing, duplicate, unknown, unreadable, or failed topology proof makes
the compound result partial or failed. The unit
status is derived from all steps, preserving success, partial failure, failure, cancellation,
prerequisite skip, JIT rejection, and epoch expiry. Target absence is the generic adapter's
authoritative ordinary postcondition; free-space deltas are not used as success proof.

An expected residual is distinct from an unsatisfied destructive postcondition. The adapter
returns the successful root mutation separately, post-verification carries the typed residual
failure, the step is `partiallySucceeded`, and the containing unit is `partiallyFailed` so every
downstream prerequisite remains blocked.

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
