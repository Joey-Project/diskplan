# Revalidation and Dry-Run Isolation

`DiskplanExecution` is the Phase 4 boundary between a validated immutable plan and any
future mutation adapter. It accepts only an `ImmutablePlan`, its `DecisionOverlay`, and a
read-only `RevalidationEvidenceSource`.

## Protected properties

Revalidation compares only properties selected by each action contract:

- target object identity;
- a required content digest, when content stability is selected;
- target access policy, ACL, provider state, and mount identity;
- root and parent-chain object identities and namespace seals;
- the complete typed Git worktree prerequisite bundle for Git actions; and
- APFS release topology for selected complete-release actions.

The current-evidence schema has no timestamp, directory size, directory link count, or
directory-entry generation field. Child-entry churn and File Provider metadata transitions
therefore cannot accidentally become an identity or content mismatch. If an action selects a
required content digest, a different digest is a real content-stability failure. Missing,
unknown, unreadable, collector failure, identity mismatch, content mismatch, and access-policy
mismatch remain separate typed outcomes.

## Whole-plan boundary

The policy validator first resolves the editable overlay into deterministic execution steps.
Phase 4 then collects one read-only snapshot for every unique JIT-revalidation action. It
rejects missing, duplicate, and unexpected action observations. Duplicate-survivor and
terminal-namespace invariants are collected and checked as explicit global observations.

Release sets are joined into connected compound units by shared owner ActionIDs or file-object
IDs. Selecting any complete-release action selects the entire connected unit. Every owner
action and every current allocation-group topology in that unit must revalidate together.
Partial release selection, missing topology, a changed refcount/link-count/owner topology, or
an unreadable APFS observation rejects the whole preparation.

## Execution epoch and current binding

A successful preparation creates a strict-deadline `ExecutionEpochContext` and a deterministic
manifest that binds:

- the immutable plan and overlay hashes;
- the epoch ID, issue time, and deadline;
- topologically ordered execution actions and every JIT action; and
- complete connected release units.

The current binding hash is meaningful only after every typed observation equals the protected
contract. It does not hash unselected metadata. Starting another revalidation invalidates every
previously issued capability before collection begins; failed, changed, or newly scanned
evidence cannot leave an older capability usable.

## Dry-run and apply capabilities

Dry-run returns `DryRunReport`, which structurally has no capability field and has no dependency
on an execution adapter. The module contains no filesystem mutation API.

Apply preparation returns a separate `ApplyReadyReport` plus `ApplyCapability`. The public engine
API obtains issue and authorization times from its private wall clock; the frontend cannot extend
a lifetime by supplying timestamps. Capability bytes
come from `SystemRandomNumberGenerator`, remain private to the module, are not hash-derived, and
are stored only in an engine-private registry. The registry binds them to the exact plan,
overlay, epoch, deadline, and manifest. Authorization removes the registry entry before checking
the supplied binding, so replay and wrong-binding attempts consume the capability. Expired,
forged, and unknown capabilities fail closed. The resulting `ApplyAuthorization` also permits
its manifest to be claimed once, forming the handoff to Phase 5 without making the editable
overlay or dry-run output mutation-capable.

## Phase 5 boundary

Phase 5 must claim `ApplyAuthorization` immediately before JIT revalidation and execution. It
must not accept a serialized token, a plan hash, a dry-run report, or a caller-created manifest
as substitute authorization.
