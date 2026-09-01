# Revalidation and Dry-Run Isolation

`DiskplanExecution` is the Phase 4 boundary between a validated immutable plan and any
future mutation adapter. Its production entry point accepts only an `ImmutablePlan`, its
`DecisionOverlay`, and the engine-owned `EngineRevalidationCollector`. The current-evidence
protocol, injectable source initializer, sealed-collector factory, and snapshot/request
constructors remain internal. The `DiskplanEngine` SPI exposes only the sealed collector handle
and preparation entry point, so even an SPI caller cannot inject a fabricated authoritative
snapshot or collector closure.

## Protected properties

Revalidation compares only properties selected by each action contract:

- target object identity;
- a required content digest, when content stability is selected;
- target access policy, ACL, provider state, and mount identity;
- root and parent-chain object identities and namespace seals;
- the complete typed Git worktree prerequisite bundle for Git actions; and
- APFS release topology for selected complete-release actions.

Object identity is the bound device/inode/type tuple plus generation when it is available.
Content stability is the selected size/digest contract, never a timestamp alone. Access policy
is the bound owner, group, mode, ACL, flags, provider boundary, and mount identity. The
current-evidence schema has no directory size, directory link count, or directory-entry
generation field. Child-entry churn and File Provider metadata transitions therefore cannot
accidentally become an identity or content mismatch. Missing, unknown, unreadable, collector
failure, identity mismatch, content mismatch, and access-policy mismatch remain separate typed
outcomes.

An unknown recoverability observation can be waived only when it carries a typed semantic fact
for the same stable unknown reason and source binding. Capture IDs, timestamps, and whole
evidence IDs are deliberately excluded from that semantic predicate so a fresh capture can
reproduce it. A changed reason, missing typed fact, absent observation, unreadable source, or
collector failure still rejects.

## Whole-plan boundary

The policy validator first resolves the editable overlay into deterministic execution steps.
Phase 4 then collects one read-only snapshot for every unique JIT-revalidation action. It
rejects missing, duplicate, and unexpected action observations. Duplicate-survivor and
terminal-namespace invariants are collected and checked as explicit global observations.
Every selected action also carries a freshly frozen policy evidence snapshot from the same
capture and one snapshot-wide global-facts binding. Mixed global-facts hashes reject even when
all action observations report the same capture ID. The snapshot-level fresh capture ID also encloses release
topology and survivor observations and must differ from the immutable plan capture. Phase 4
rebuilds the action prototype and reruns all seven
one-vote policy dimensions at the new execution reference time; a blocked vote, changed
predicate, changed value bucket, or mismatched current typed observation rejects preparation.

Release sets are joined into connected compound units by shared owner ActionIDs or raw UTF-8
file-object IDs. Allocation-group and file-object identifiers are keyed by their raw UTF-8 bytes;
Swift canonical-equivalent strings are distinct graph identities. Selecting any complete-release action selects the entire connected unit. Every owner
action and every current allocation-group topology in that unit must revalidate together.
Partial release selection, missing topology, a changed refcount/link-count/owner topology, or
an unreadable APFS observation rejects the whole preparation.

## Execution epoch and current binding

A preparation creates a new semantic reference time from the engine clock and a strict-deadline
`ExecutionEpochContext`. It consumes every waiver epoch requirement produced by overlay
validation. Each requirement must still resolve to exactly one current predicate and the
original consent; plan, plan-evidence, overlay, action, predicate, value bucket, semantic
evidence, original reference time, current evidence, current global facts, epoch ID, and
deadline are all bound into the deterministic manifest. A missing, extra, duplicate, or stale
requirement rejects preparation.

The manifest also binds:

- the immutable plan and overlay hashes;
- the epoch ID, issue time, and deadline;
- topologically ordered execution actions and every JIT action;
- complete connected release units;
- the single fresh capture and global-facts binding shared by all selected actions; and
- the complete current waiver requirement set.

The current binding hash is meaningful only after every typed observation equals the protected
contract. It does not hash unselected metadata. Before any suspension, each preparation takes a
new actor-owned monotonic generation and invalidates every previously issued capability. After
collection and immediately before capability registration, the generation must still be current.
A newer successful or failed preparation therefore supersedes an older in-flight result, even
when collector completions arrive out of order.

## Dry-run and apply capabilities

Dry-run returns `DryRunReport`, which structurally has no capability field and has no dependency
on an execution adapter. The dry-run preparation path never constructs or invokes an adapter,
final-descriptor verifier, authorization, or mutation context.

Dirty Git worktree discard is report-only in v1. The plan retains the observed change-set and
successor evidence for explanation, but the discard action and any dependent remove chain are
blocked rather than waiver-stageable. They cannot mint an apply capability, and production
execution rejects them before invoking Git. Clean worktree quarantine removal remains a typed
native action.

Apply preparation returns a separate `ApplyReadyReport` plus `ApplyCapability`. The public engine
API obtains issue and authorization times from its private wall clock; the frontend cannot extend
a lifetime by supplying timestamps. Capability bytes come from `SystemRandomNumberGenerator`,
remain private to the module, are not hash-derived, and are stored only in an engine-private
registry. The registry binds them to the exact plan,
overlay, epoch, deadline, and manifest. Authorization removes the registry entry before checking
the supplied binding, so replay and wrong-binding attempts consume the capability. Expired,
forged, and unknown capabilities fail closed. The resulting `ApplyAuthorization` is only an
opaque claim handle: the authoritative manifest remains in an engine-owned authorization
registry. Claim atomically consumes that record while checking its preparation generation,
deadline, and manifest/current-binding envelope against the handle and current engine state.
Starting any newer preparation removes every older unclaimed authorization, even if its
deadline has not expired. Its internal-only initializer means Phase 5 can treat a successful claim as proof
that the engine performed authoritative current collection and whole-plan revalidation, without
making the editable overlay or dry-run output mutation-capable.

When any selected mutation requires force, `ApplyReadyReport` carries the exact sorted ActionID
list and a review binding derived from the manifest, plan, overlay, epoch, and warning list.
Authorization requires an explicit `ApplyReviewConfirmation` for the same binding and exact
list. A runtime warning is additional observability, not the consent boundary.

## Phase 5 boundary

Phase 5 must claim `ApplyAuthorization` immediately before JIT revalidation and execution. It
must not accept a serialized token, a plan hash, a dry-run report, or a caller-created manifest
as substitute authorization.
