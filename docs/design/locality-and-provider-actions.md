# Locality And Provider Action Contracts

## Scope And Status

These refinements were accepted on 2026-10-04. They specify the first R1 capability
gate and the provider local-copy action contract; they do not assert that a
production implementation or universal provider API has already passed it.
The [accepted plan](accepted-plan.md) remains authoritative for complete scope,
read-only admission, one-vote rejects, immutable consent, and APFS groups.

## 1. Ordinary Removal Authority

Local allocation answers whether storage is resident on this host, not whether
removal propagates cloud deletion. A concrete scoped platform contract must
support the latter action decision. An abstract interface, a fixture oracle,
optional API absence, or a cache-looking basename does not establish it.

Maintain one capability matrix for every proposed production scope:

| Field | Required contract |
| --- | --- |
| Scope | Root class, volume/filesystem, bound root/ancestry, candidate types, OS/capability versions |
| Source | System API or filesystem signal, documented caller/domain scope, meaning of positive and negative results |
| Preconditions | Required probes, namespace/access assumptions, coverage, provider boundaries, non-materialization |
| Conclusion | Exact supported action decision; no stronger global ownership claim |
| Lifetime | Plan/epoch binding, expiry, JIT checks, root/ancestry/candidate invalidation |
| Failure | Distinct absent, unsupported, unknown, unreadable, timeout, failure, identity mismatch, access-policy mismatch |
| Acceptance | India host/OS, revision, command, positive/counterexample fixtures, real-engine reachability, observed outcome |

The first experiment targets ordinary cache/temp and declared build-root use
cases without making pathname conventions authoritative. The same production
contract must admit a legitimate ordinary candidate and reject managed,
dataless, remote, replaced, and unreadable counterexamples. Tests may create
temporary roots, but cannot inject a fixture-only non-provider answer into the
production path and call that platform acceptance.

If no supported contract establishes a scope, keep it report-only and report the
missing capability. Scanning remains useful. Bring bounded evidence and any
proposed residual-risk change to Joey before changing authority policy. Do not
manufacture a global negative oracle or silently relax the deletion gate. The
first cache flow does not reduce the remaining first-version adapter scope.

### Initial Source And Interface Matrix

This matrix records conclusions supported on 2026-10-04, not completed India
validation. The ordinary-removal positive capability is still open.

| Source / interface | Supported conclusion | Unsupported conclusion / next gate |
| --- | --- | --- |
| Local-volume evidence | Storage filesystem is local to the host | Does not establish non-provider ownership; wire per-volume locality independently |
| `SF_DATALESS` and allocation evidence | Dataless state and measurable local allocation, when safely collected | Flag absence is not an ownership proof; test protected ancestry/non-materialization and residual allocation |
| `NSFileProviderManager.getIdentifierForUserVisibleFile` | Item/domain identity under the API's documented provider scope | `NSFileNoSuchFileError` also covers an item not yet assigned an identifier; no global non-provider certificate |
| `NSFileProviderManager.getDomainsWithCompletionHandler` | Registered domains under the documented File Provider extension scope | Does not establish a complete cross-provider negative inventory |
| `FileManager.getFileProviderServicesForItem` | Services exposed for the item | An empty successful dictionary does not establish non-provider ownership |
| `localOrUnindicated` scan boundary | No indicated managed boundary in this scan observation | Cannot be promoted to confirmed-local without the missing scoped capability |
| `identifierAbsent` topology observation | No identifier under the queried API contract | Dataless=false and sync-root=false do not strengthen it into global local-ownership authority |
| Proposed scoped ordinary-removal authority | Not yet supported by the collected sources/interfaces | Keep report-only; identify a supported source/assumption contract or obtain a new risk decision before granting authority |

The code audit covered the existing `revalidation-release-postverify` and
`runtime-revalidation-adapters` worktrees. `RuntimePolicyAuthority.mapProviderState`
and `mapProviderBoundary` promote `localOrUnindicated` to known-local;
`RuntimeReleaseTopologyAuthority.providerLocalObservation` accepts identifier
absence together with negative dataless/sync-root flags. These mappings are
findings to reconcile, not evidence that the platform gate has passed. Dirty
worktree findings do not claim a frozen committed acceptance result.

Primary sources:

- [Identifier API](https://developer.apple.com/documentation/fileprovider/nsfileprovidermanager/getidentifierforuservisiblefile(at:completionhandler:)):
  the documented negative result is scoped to the caller's File Provider
  extension. The Xcode 26.6.0 SDK inspected on India additionally documents the
  same `NSFileNoSuchFileError` for a provider item that has not yet been assigned
  an identifier. A negative lookup cannot distinguish those cases and does not
  establish the desired global conclusion.
- [Registered domains](https://developer.apple.com/documentation/fileprovider/nsfileprovidermanager/getdomainswithcompletionhandler(_:)):
  the documentation describes the File Provider extension's domains, not a
  complete inventory across all installed providers. The SDK's shorter
  registered-domains comment does not expand that documented scope.
- [File Provider services](https://developer.apple.com/documentation/foundation/filemanager/getfileproviderservicesforitem(at:completionhandler:)):
  successful service discovery may return an empty dictionary; service absence
  cannot authorize ordinary removal.
- [Apple TN3150](https://developer.apple.com/documentation/technotes/tn3150-getting-ready-for-data-less-files):
  even metadata/path operations may materialize intermediate directories. Use
  the supported no-materialization I/O policy, preserve its scope/lifecycle, and
  report blocked accesses distinctly; a flags-only precheck is insufficient.

## 2. Eviction Identity And State Transitions

The protected property is continuity of the same provider-managed logical object
while local content residency changes, with required sync, access, activity, and
namespace preconditions preserved. Deletion's target-absence postcondition does
not apply.

Each independently admitted adapter declares:

- Before-state: provider/domain and logical object identity, bound namespace,
  filesystem identity, residency/allocation, sync eligibility, pinned or
  non-evictable restrictions, access policy, and activity coverage.
- Allowed transition: the exact supported resident-to-local-copy-evicted state,
  including any explicitly verified placeholder/filesystem-identity transition.
  Neither blanket inode equality nor arbitrary benign identity drift is assumed.
  Establish the actual contract from platform sources and India validation.
- After-state: the same provider logical object and expected placeholder or
  documented residual remain; required ownership/access constraints hold;
  residency/allocation are recollected without implicitly downloading content.
- Rejections: unrelated object/occupant, changed provider/domain, unsynced or
  non-evictable data, new external activity, access-policy change, or missing
  required capability/coverage. Failed reads and unsupported observations are
  distinct from verified mismatches.

Document the observer descriptor lifecycle. Tool-held regular-file descriptors
must not themselves invalidate an otherwise legitimate eviction. Closing one
must not be presented as retaining an atomic object-use guarantee. Keep the
namespace/provider binding the actual API supports, declare the check-to-use
residual, and remain report-only when the protected property cannot be met. No
quarantine, unlink, force, unpin, or ordinary-remove fallback is allowed.

Prefer independently observable targets over undocumented recursive behavior.
An admitted recursive operation needs per-target partial results, non-materializing
coverage, and cancellation semantics before becoming stageable. Preserved
namespace entries satisfy APFS prerequisites only when the relevant local
allocation reference has been verified released.

[Apple's eviction contract](https://developer.apple.com/documentation/fileprovider/nsfileprovidermanager/evictitem(identifier:completionhandler:))
documents completion after eviction or an error, permits partial recursive
effects before an error, and includes open-descriptor, unsynced, non-evictable,
and hardlink failure cases. Preserve that completion meaning, but separately
validate standalone applicability, logical identity, and allocation observation.
Do not weaken a documented completed result into mere acceptance or infer that
every other eviction API has the same contract.

## 3. Invocation, Post-Verification, And Space Reporting

Preserve three independent typed results through Swift authority, IPC, shell/TUI,
and optional audit:

| Result | Meaning |
| --- | --- |
| Invocation | Not started, rejected, accepted/pending, completed as documented by the platform, failed, or cancelled/uncertain |
| Post-verification | Satisfied, expected residual, unsatisfied, unknown, unsupported, unreadable, or collection-failed, with protected-property evidence |
| Allocation observation | Before/after nominal allocation, supported private lower bounds, conditional group evidence, or typed unavailable/partial values |

Only report verified completion when the admitted adapter postcondition is
satisfied. An API accepting a request is not promoted to completion merely by
returning without an error. Respect APIs that explicitly document completion,
without making their callback prove stronger identity or allocation properties.
Allocation decrease is not automatically exact physical free-space reclaim;
clone/hardlink/snapshot and incomplete-owner limits remain. Unknown bytes are not
zero.

An accepted or possibly started operation with unknown completion/post-verification
is an uncertain attempt. Do not automatically retry, synthesize release credit,
or roll back. Rescan/replan is default recovery. A future retry contract must
independently establish idempotence and bind fresh plan/consent; ordinary best
effort grants no retry authority.

Independent actions may continue. A dependent proceeds only when its exact
required postcondition is proved, not when an upstream request was merely
accepted. Audit persistence stays optional and does not change authoritative
in-memory outcomes.

## 4. Validation Order

1. Collect primary platform sources and map existing production interfaces.
2. Fill the removal matrix before adding positive authority paths.
3. Run minimal non-mutating capability checks on India; distinguish platform
   conclusions from fixtures and assumptions.
4. Define each eviction adapter's transition/result contract before mutation
   tests on test-created roots.
5. Where existing fields are insufficient, update typed bindings/schema, both
   generated consumers, compatibility fixtures, and event presentation together.
   Do not duplicate safety policy in Rust.
6. Validate the installed product and report unsupported cases explicitly.
