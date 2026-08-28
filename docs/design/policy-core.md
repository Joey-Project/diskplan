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
policy fact families and classification claims are part of the frozen evidence bytes. The
adapter cannot provide `GateResult`, `GateVote`, stageability, or any other final safety
declaration. The policy core alone derives all seven votes from typed protection, collector,
activity, semantic-review, recoverability-review, dependency, Git, and topology facts. The
evidence-freeze context is constructible only from the frozen global facts.

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

The freeze boundary rejects empty claim values, evidence keys, and typed source identifiers,
as well as duplicate claims. Adapter scopes are one canonical unordered set; equivalent
primary/additional input permutations produce the same evidence bytes. Git scope is exclusive,
and generic scope may coexist only with exact release-set scopes, so a generic action cannot
downgrade a worktree-specific safety contract.

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
vote. Explicit protection is a typed hard gate. Unknown recoverability becomes an exact
waiver predicate rather than ready state.

`PolicyEvaluation` is a read-only public projection, not a public construction surface. Its
source binding is mandatory, and the binding constructor is private. The package creates it
only after checking the capture, evidence, global-facts, policy/schema, reference-time,
matching-root coverage, and classification-resolution bindings against the frozen inputs.
`GateVote` construction and the evaluation reducer remain package-internal; only a
debug-only `@testable` helper accepts arbitrary votes for reducer unit tests. Consequently a
frontend or another package consumer cannot turn caller-selected votes into `safeToClean`,
`stageable`, or any other policy result. Action construction independently recomputes the
authoritative evaluation from the same evidence and rejects a source-binding transplant or
vote mutation before it can enter a plan.

Independent review facts are additive. Recency, task-semantic, duplicate-survivor, normal
keep, static-rebuild, rebuild-cost, and fully observed local-Git-discard predicates are
canonicalized and unioned; none replaces another. Each deterministically missing
classification facet requires its own matching agent suggestion and exact facet-bound
predicate. A missing facet without such a suggestion hard rejects. Gate reasons,
predicates, and conditions are deduplicated and canonically ordered before action hashing;
typed fact collections are canonicalized before evidence hashing.

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
`PlanReleaseSet.buildAll` is atomic over one complete successful graph evaluation and returns
one immutable graph bundle rather than a caller-sliceable release-set list. The bundle manifest
binds the graph digest and provenance, complete allocation-group ID set and count, global
candidate-to-ActionID map, and connected-component topology. `ImmutablePlan` recomputes that
manifest and rejects missing, duplicated, sliced, or mixed groups. Aggregate actions may cover
one verified group, but their JIT contract carries the full manifest so execution cannot mistake
an aggregate subset for a complete graph. Any global or group blocker, unknown total,
within-bucket or cross-bucket arithmetic failure rejects the bundle. Selection uses raw-UTF8
`CandidateActionBinding` records rather than a Swift
`String` dictionary, so canonically equivalent but byte-distinct identifiers cannot collapse.
The graph evaluation itself freezes the complete candidate-to-ActionID map. Bundle construction
matches every candidate against that exact evaluated action, including private-only candidates
that own no shared allocation group, so omitted, substituted, or blocked actions cannot enter the
manifest through a release-owner-only check.
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
prerequisite lineages. Complete-release lineage is narrower by design: it binds stable release
scope and owner topology plus stable owner lineages, while excluding graph digest, reference
time, current evidence and owner ActionIDs. Current graph topology, owner ActionIDs, evidence,
and epoch facts remain in the ActionID, plan, and JIT bindings. Advancing reference time alone
therefore preserves a consent lineage, while a semantic owner-topology change does not. Action
IDs add the full snapshot and global-facts digests, prerequisite action IDs, and seven canonical
gate votes. A plan rejects mixed semantic
reference times, scan roots outside global coverage, or actions built from different global
facts, then hashes complete global facts/evidence alongside ActionID-byte order, metrics, and
release topology.

The public display-metrics input accepts only reclaim, age, rebuild, cleanup, and raw-path
facts. It starts at the conservative blocked tier; callers cannot submit a safe or review tier.
Action construction replaces that placeholder with the tier derived from the final
source-bound evaluation and the closed force-warning contract.

The unified action-prototype builder has no arbitrary argv surface. Generic removal derives
the exact target kind, prototype path slot, unavoidable path-race residual, trusted namespace,
and `rm -f` warning state from evidence. Worktree removal requires directory identity and
known quarantine capability. Its closed contract also binds a complete no-follow traversal,
HEAD identity, index digest, local-change digest, exact registered worktree/root identity,
administrative-directory and common-directory identities, registration/metadata digests,
linked-worktree state, sparse-checkout state, absence of nested repositories and submodules,
trusted-exclusive namespace, and complete post-quarantine coverage. The v1 executable
predicate is intentionally closed to an exact linked-worktree registration and disabled sparse
checkout. The linkage registration ID must exactly equal the registration evidence ID, while
the administrative-directory and common-directory identities must be distinct. Both exact
identities, the registration and metadata digests, and the raw registration binding remain in
evidence, lineage, action, and plan hashes. The execution adapter separately proves the `.git`
gitdir-file target and its descriptor-relative administrative-to-common directory relationship.
Ordinary worktrees, enabled sparse checkout, a linkage-ID mismatch, equal administrative/common
identity, and any absent, unknown, unreadable, failed, or target-mismatched registration fact
remain report-only. Dirty local work is
represented by a separate discard-local-changes action and exact waiver. Its typed
postcondition seals a clean successor HEAD/index/content baseline, preserves HEAD identity,
and becomes the dependent remove action's JIT baseline. The remove's action-aware evaluation
records that the exact discard prerequisite discharges the local-work predicate, rather than
silently changing consent requirements during overlay validation. Cleanup
scope and artifact kind/version must be non-empty, match a canonical evidence-frozen adapter
scope by raw UTF-8 bytes, and produce the matching typed postcondition. Production filesystem
binding remains outside this pure target.

A complete-release-set action can only be built from the closed binding exported by a
successfully evaluated `PlanReleaseSet`. The binding includes allocation-group ID, full graph
digest, complete topology expectation, exact owner candidate/action IDs, and conditional
bytes. `ImmutablePlan` rejects an empty or non-matching release-set list for such an action,
as well as duplicate release-action bindings, and requires every bound owner action as an
explicit prerequisite. Overlay validation therefore checks every owner action's stageability
and exact consents. A selected aggregate produces a closed composite execution step containing
the exact release set, every owner JIT-revalidation action, and rewritten external prerequisite
step IDs. Individual owner removals are not also executed. Credit-only release sets remain
valid without an aggregate action and activate shared credit only when all owners are selected.

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
any consent whose lineage, policy version, predicate, value bucket, semantic evidence,
reason, event, or consent hash does not match. Terminal mutations are mutually exclusive
across alias and ancestor/descendant namespaces, except for an exact owner-to-release-composite
replacement. Duplicate-survivor consent requires one plan-consistent survivor and rejects
direct or ancestor deletion of its namespace. A selected terminal mutation, including a Git
discard transition, is checked directionally against the complete frozen evidence corpus; it
cannot mutate an alias or descendant snapshot whose independent seven-gate evidence was not
authorized. Git-specific evidence uses symmetric absolute-path and identity overlap to
dominate every non-Git adapter across the whole plan and at overlay validation, including a
generic child nested below the worktree; a second generic snapshot therefore cannot downgrade
discard consent or quarantine. Directional mutation checks remain in place for non-Git
survivor semantics, and disjoint namespaces remain independent. Display order is separate
from canonical action order: policy core derives the tier from final action-aware
stageability/recommendation and force-warning semantics, while callers provide only the other
typed known/unknown metrics. Recommendation is likewise derived from the final seven votes:
`likelyRebuildable` is available only when every required consent is a static-only rebuild
predicate, while any additional semantic or recoverability uncertainty remains review-tier and
any hard reject remains blocked. Recomputed plans reject forged tiers or transplanted
recommendations. Plan hashing uses
ActionID-byte order; validated execution steps use deterministic topological order with
ActionID-byte tie breaking.
