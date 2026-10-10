# Locality And Provider Action Contracts

## Scope And Status

The initial refinements were accepted on 2026-10-04; deletion effect permissions
were accepted on 2026-10-05. They specify the mode-specific R1 capability
gate and the provider local-copy action contract; they do not assert that a
production implementation or universal provider API has already passed it.
The [accepted plan](accepted-plan.md) remains authoritative for complete scope,
read-only admission, one-vote rejects, immutable consent, and APFS groups.

## 1. Ordinary Removal Authority

Local allocation answers whether storage is resident on this host, not whether
removal propagates cloud deletion. The user may permit that possible effect
without changing the factual ownership evidence. Under the default local-only
permission, a concrete scoped no-propagation contract is still required for
ordinary removal. An abstract interface, a fixture oracle, optional API absence,
or a cache-looking basename does not establish it.

### Deletion Effect Permissions

| Permission | Admitted operation | Missing capability / failure |
| --- | --- | --- |
| `local-remove-only` (default) | Independently admitted provider/iCloud dehydration, or ordinary removal with independent reliable no-propagation evidence | Retain and report; no automatic `rm` after a failed, unsupported, timed-out, partial, or uncertain dehydration |
| `may-delete-across-devices` (explicit) | A declared ordinary removal action, without first dehydrating, when all remaining action-specific gates pass | Ownership may remain unknown; failure does not authorize force, elevation, retry, or another operation |

Cross-device permission explicitly accepts that ordinary deletion may propagate
to cloud storage and other devices and may be irreversible. It is not a promise
of remote deletion and does not establish `confirmed-local`. It addresses only
the ownership/propagation barrier: protection, semantic/recoverability, activity,
coverage, identity/content/access, mount, APFS, and dedicated-adapter restrictions
remain independent gates. In particular, the existing generic-remove path-slot
trust contract and Git worktree namespace restrictions are unchanged.

Bind consent to the exact declared action variant, targets/subtree scope,
plan/evidence/policy versions, and execution credential. The immutable plan
declares mutually exclusive eviction/removal variants; the overlay selects them
and records per-action effect permission, never arbitrary paths or argv. New-plan
UI intent defaults to local-only; missing required execution bindings or
incompatible/unsupported variants cannot authorize a mutation. Never reinterpret
an older overlay as cross-device consent, persist a
global deletion grant, or automatically upgrade local-only permission. Changed
permission/operation requires explicit fresh consent under the existing binding
and epoch rules. Force permission remains separate and visible at selection.

No dehydration result currently audited proves that an arbitrary existing URL
is outside every provider. A later delete after a failed/partial/uncertain
dehydration requires rescan/replan and explicit selection of a separate removal
variant; higher effect permission never creates an automatic fallback chain.
Provider-specific remote-delete APIs, unpin/reset, hidden backing cleanup, and
implicit materialization remain out of scope.

Maintain one capability matrix for every proposed production scope:

| Field | Required contract |
| --- | --- |
| Scope | Root class, volume/filesystem, bound root/ancestry, candidate types, OS/capability versions |
| Effect permission | Default local-only or explicit cross-device variant; plan/target/consent binding and allowed operation |
| Source | System API or filesystem signal, documented caller/domain scope, meaning of positive and negative results |
| Preconditions | Required probes, namespace/access assumptions, coverage, provider boundaries, non-materialization |
| Conclusion | Exact supported action decision; no stronger global ownership claim |
| Lifetime | Plan/epoch binding, expiry, JIT checks, root/ancestry/candidate invalidation |
| Failure | Distinct absent, unsupported, unknown, unreadable, timeout, failure, identity mismatch, access-policy mismatch |
| Acceptance | India host/OS, revision, command, positive/counterexample fixtures, real-engine reachability, observed outcome |

The first experiment targets ordinary cache/temp and declared build-root use
cases without making pathname conventions authoritative. Local-only fixtures
must reject unknown/managed propagation without an independent no-propagation
contract; cross-device fixtures must retain the same unknown/managed facts and
admit an otherwise eligible declared removal only after explicit bound consent.
Remote, replaced, unreadable, protected, active, incomplete, and adapter-specific
counterexamples retain their existing rejections in both modes. Tests may create
temporary roots, but cannot inject a fixture-only non-provider answer into the
production path and call that platform acceptance. Existing user data remains
scan/dry-run-only; actual mutation is limited to test-created roots.

If no supported no-propagation contract establishes a local-only scope, keep
that operation report-only and report the missing capability. Cross-device
permission is the accepted alternative, not a negative ownership oracle or an
implicit waiver of the remaining gates. Its production consent/variant path
still needs real-host acceptance before execution. Scanning remains useful and
the first cache flow does not reduce the remaining first-version adapter scope.

### Initial Source And Interface Matrix

This matrix records source conclusions collected on 2026-10-04 and the accepted
permission refinement on 2026-10-05, not completed production acceptance.
Local-only ordinary-removal capability is still open; explicit cross-device
permission no longer requires a global non-provider certificate.

| Source / interface | Supported conclusion | Unsupported conclusion / next gate |
| --- | --- | --- |
| Local-volume evidence | Storage filesystem is local to the host | Does not establish non-provider ownership; wire per-volume locality independently |
| `SF_DATALESS` and allocation evidence | Dataless state and measurable local allocation, when safely collected | Flag absence is not an ownership proof; test protected ancestry/non-materialization and residual allocation |
| `NSFileProviderManager.getIdentifierForUserVisibleFile` | Item/domain identity under the API's documented provider scope | `NSFileNoSuchFileError` also covers an item not yet assigned an identifier; no global non-provider certificate |
| `NSFileProviderManager.getDomainsWithCompletionHandler` | Registered domains under the documented File Provider extension scope | Does not establish a complete cross-provider negative inventory |
| `FileManager.getFileProviderServicesForItem` | Services exposed for the item | An empty successful dictionary does not establish non-provider ownership |
| `localOrUnindicated` scan boundary | No indicated managed boundary in this scan observation | Cannot be promoted to confirmed-local without the missing scoped capability |
| `identifierAbsent` topology observation | No identifier under the queried API contract | Dataless=false and sync-root=false do not strengthen it into global local-ownership authority |
| Proposed local-only ordinary-removal authority | Not yet supported by the collected sources/interfaces | Keep local-only ordinary removal report-only until an independent no-propagation contract passes acceptance |
| Explicit cross-device ordinary-removal permission | The user accepts possible deletion propagation for a declared target/action | Bind fresh per-action consent in the real engine; preserve unknown ownership and every remaining hard gate |

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
- [Provider eviction](https://developer.apple.com/documentation/fileprovider/nsfileprovidermanager/evictitem(identifier:completionhandler:)):
  the call takes an item identifier on a domain manager, not an arbitrary URL.
  Managed items may fail for unsynced edits, non-evictable restrictions, open
  descriptors, hardlinks, or access failures; a directory may be partly evicted
  before an error. The audited contract does not supply a global not-managed
  result that authorizes local-only removal.
- [iCloud eviction](https://developer.apple.com/documentation/foundation/filemanager/evictubiquitousitem(at:)):
  this URL-based API removes the local copy of an iCloud item. Its scope does
  not provide universal third-party File Provider eviction or a negative
  cross-provider certificate.

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
quarantine, unlink, force, unpin, or ordinary-remove fallback is allowed inside
the eviction adapter. A separately consented cross-device removal has its own
operation, protected properties, and revalidation; it is never an eviction retry.

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
and optional audit, alongside the selected effect permission and operation:

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
zero. Ordinary-removal target absence proves only the declared local deletion
postcondition, not propagation to a remote service or another device. Keep any
independently available remote outcome separate; unknown is not success.

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
2. Fill the mode-specific removal matrix before adding positive authority paths;
   freeze default permission, declared variants, consent, and failure behavior.
3. Run minimal non-mutating capability checks on India; distinguish platform
   conclusions from fixtures and assumptions.
4. Define each eviction adapter's transition/result contract before mutation
   tests on test-created roots.
5. Add the closed effect-permission/variant/consent bindings with a new binding
   version. Update typed bindings/schema, both
   generated consumers, compatibility fixtures, and event presentation together.
   Do not duplicate safety policy in Rust.
6. Validate the installed product and report unsupported cases explicitly. Cover
   both modes, unknown/managed ownership preservation, mutually exclusive
   operations, old/missing/unsupported consent, independent force warnings, and
   no removal fallback for every eviction failure/partial/uncertain result.
