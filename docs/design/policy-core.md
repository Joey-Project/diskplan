# Deterministic Policy Core

`DiskplanPolicy` is a pure Swift library. It performs no filesystem access, launches no
processes, and has no dependency on the scanner, protobuf schema, engine executable, or
frontend. The Phase 1 scanner remains behind `PolicyEvidenceAdapter` until its public model
is frozen.

## Scanner adapter boundary

The eventual production adapter must freeze the complete scanner stream into
`FrozenEvidenceSnapshot` values. In particular, it must consume closed-directory events and
their typed coverage state. A stable top-K is a viewport optimization, not a complete
candidate corpus, and cannot be used as policy input by itself. Missing, unknown,
unreadable, and failed observations remain distinct across the adapter boundary.
Every snapshot binds one scan capture ID and the exact full-global-facts hash. Its seven
policy facts and classification claims are part of the frozen evidence bytes; callers cannot
attach unrelated gate results or classification from another candidate or capture after the
fact. The evidence-freeze context is constructible only from those frozen global facts.

The adapter must construct canonical `RawRootPath` and `RawTargetPath` values. A target is a
non-empty relative component sequence; empty components, `.`, `..`, slash, and NUL are
rejected. The scan root is a separate absolute-root type, so root and target cannot be
confused. Every frozen target also carries a protected namespace binding: raw root, root
identity, target identity, and every ancestor identity. Root and ancestor seals retain typed
trusted-namespace, access-policy, ACL-digest, provider-boundary, and mount-identity evidence.
The policy core hashes these engine-collected seals but performs no filesystem collection.

## Classification

Classification is resolved independently for purpose, lifecycle, ownership, and
recoverability facets. Source type fixes the effective rank:

1. authoritative adapter;
2. structural recognizer;
3. path convention;
4. generic fallback.

The highest rank wins within one facet. Different values at the same winning rank create a
typed conflict. Claims on different facets are compatible and do not conflict. Agent claims
do not participate in deterministic rank resolution at all: they cannot create or resolve a
conflict and cannot make a classification ready. They remain visible as review evidence only
for facets with no deterministic resolution or conflict, where policy may require the exact
agent-assisted waiver predicate. Explicit type hints are represented only as recognizer
routes, not as classification claims.

## One-vote policy

`OneVotePolicyInputs` has exactly seven named fields and produces exactly one retained vote
per safety dimension:

- protection and provider boundary;
- evidence completeness;
- current activity;
- object identity and access policy;
- semantic uniqueness;
- recoverability;
- dependency and release-set completeness.

Each vote has one typed result: satisfied, not applicable, requires waiver, unmet
revalidation condition, or rejected. Every result retains a non-empty set of stable reason
codes and their semantic evidence bindings; multiple reasons and predicates are never
collapsed into one string. There is no combined score. Any hard reject blocks staging.
Provider state and classification conflict must also be represented by the corresponding
hard-reject vote; they cannot be hidden in display-only state. Current activity may produce
`safeAfterExit` only as the `activityCleared` unmet condition, distinct from a hard reject,
and it remains non-stageable until revalidation satisfies that condition. Gate reasons are
not localized display strings because they are part of the closed action binding.
The builder derives those votes from the same frozen evidence bundle. Target and ancestor
provider boundaries, matching-root global coverage, collector state, activity, object and
namespace access evidence, content baseline, dependency observations, recoverability, and
classification are checked before a source-bound evaluation can enter an action. Unknown,
unreadable, or failed hard evidence cannot be papered over by a caller-supplied satisfied
vote. Unknown recoverability becomes an exact waiver predicate rather than ready state.

Waivers are closed to the accepted eight cases. Recency, agent, task-semantic, duplicate,
and normal-keep waivers belong only to the semantic gate. Static rebuild, unknown rebuild
cost, and fully observed local Git discard belong only to the recoverability gate. The other
five dimensions cannot carry a waiver. Multiple exact predicates can coexist within a gate;
each requires a separately bound consent. No API accepts a set of waiver kinds as a shortcut.

## Storage dependency graph

The graph keeps candidates, file objects, and allocation groups separate. It rejects empty
owner sets, zero or impossible known reference counts, owner paths outside their candidate
target, disconnected file objects, and one owner path attributed to multiple file objects.
Candidate, file, and allocation observations must share one capture and exact global-facts
provenance. Hardlink credit
requires every observed owner path and an exact `st_nlink` match. Clone credit requires an
exact clone-refcount match to observed file-object owners. Every owner candidate must be
selected and safe. Provider ownership, any hard reject, snapshot evidence other than known
false, unknown shared bytes, missing owners, and target overlap each independently suppress
shared credit. Private bytes remain available only for non-overlapping safe local candidates.

A file object appearing in multiple allocation groups blocks every affected group, so the
same shared ownership cannot receive credit twice. The complete graph receives a canonical
digest over candidates, exact identities and provenance, owner paths, hardlink counts,
allocation groups, clone counts, snapshot observations, and byte observations.
`PlanReleaseSet.buildAll` is atomic over one complete successful graph evaluation; any global
or group blocker, unknown total, within-bucket or cross-bucket arithmetic failure rejects the
aggregate. Selection uses raw-UTF8 `CandidateActionBinding` records rather than a Swift
`String` dictionary, so canonically equivalent but byte-distinct identifiers cannot collapse.
Each retained
set carries the full graph digest, exact candidate/action/target/identity/evidence provenance,
conditional bytes, and file-owner/refcount/snapshot topology expectations needed by Phase 4
whole-group preflight and JIT revalidation. Overlay validation activates that shared credit
only when all bound owner actions are selected; a partial selection retains only independently
known private reclaim.

## Immutable plans and overlays

Actions are built from a complete `FrozenEvidenceSnapshot`, never a caller-provided digest.
Construction verifies policy/schema versions, namespace/root binding, object identity,
display path, semantic reference time, and exact global-facts hash. Identity, content, and
access policy are separate typed protection contracts derived from evidence. Content is
either a required known digest or an explicit typed not-applicable reason; unknown,
unreadable, and failed content observations cannot form an action. Postconditions
are a closed enum for ordinary removal, quarantined worktree removal, cleanup scope, artifact
version, or allocation-group release; no string placeholder claims enforcement. Action
lineage seals those contracts, the complete protected namespace, adapter contract, and
prerequisite lineages. Action IDs add the full snapshot and global-facts digests,
prerequisite action IDs, and seven canonical gate votes. A plan rejects mixed semantic
reference times, scan roots outside global coverage, or actions built from different global
facts, then hashes complete global facts/evidence alongside ActionID-byte order, metrics, and
release topology.

The unified action-prototype builder has no arbitrary argv surface. Generic removal derives
the exact target kind, prototype path slot, unavoidable path-race residual, trusted namespace,
and `rm -f` warning state from evidence. Worktree removal requires directory identity and
known quarantine capability. Cleanup scope, artifact kind/version, and allocation-group IDs
must be non-empty, match the evidence-frozen adapter scope by raw UTF-8 bytes, and produce the
matching typed postcondition. Production filesystem
binding remains outside this pure target.

The private policy binding encoder uses the accepted fixed-width, length-prefixed,
domain-separated v1 rules. It does not modify the existing cross-language
`canonical-binary-v1` fixture and does not introduce a proto or canonical-binary v2 schema.

An overlay has an explicit binding version and a canonical hash covering policy/schema,
plan/evidence references, selected actions, lineage consent cores, and user notes. Notes
affect the audit hash but never safety decisions. A consent core binds stable action lineage,
policy, exact predicate and semantic evidence, reason, and event; it deliberately does not
bind a current ActionID. Validation requires each consent lineage to resolve to exactly one
selected current action and emits a non-editable epoch requirement binding consent, action,
plan, evidence, and semantic reference time.

Phase 4 supplies an authenticated opaque credential for that requirement and an execution
epoch ID, issue time, and strict deadline. The credential is not stored in the editable
overlay. This target only defines the exact binding seam and checks reference-time/deadline
shape; the Phase 4 engine owns issuance and authentication.

An overlay can only select existing actions and supply exact consent cores. Validation
rejects stale plan/evidence hashes, injected or duplicate selections, missing prerequisites,
duplicate selected lineages, hard-blocked actions, missing predicates, extra predicates, and
any consent whose lineage,
policy version, predicate, value bucket, semantic evidence, reason, event, or consent hash
does not match. Display order is separate from canonical action order: UI
metrics use typed known/unknown lexicographic ordering, while execution order is always
ActionID bytes.
