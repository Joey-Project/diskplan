# macOS Capability Probe Contract

This document describes the Phase 0 implementation boundary for the accepted
[storage and File Provider design](accepted-plan.md#8-storage-metrics-and-apfs-dependency-graph).

## Path Access Boundary

The engine must install `IOPOL_MATERIALIZE_DATALESS_FILES_OFF` at process scope and verify
the readback before it performs any path access. Probe entry points require the resulting
`NoMaterializationPolicy` token and re-read the live process policy immediately before every
path-touching step. The token is not proof that the current policy is still OFF. The protected
access-policy property assumes Diskplan is the only code in its process that changes this
process-wide policy; another same-process thread can still race the readback and syscall, so
the engine must centralize policy mutation and never turn materialization back on while probing.

Item metadata is collected from a held parent directory descriptor with a single raw-name
component. The C shim rejects empty names, separators, NUL, `.` and `..`, and uses
`FSOPT_NOFOLLOW | FSOPT_RESOLVE_BENEATH | FSOPT_RETURN_REALDEV`. The last option makes
`ATTR_CMN_DEVID` identify the real backing device rather than a synthetic volume-group device.
The object identity tuple is the returned real device, file ID, and object type; if any member
is unsupported or unavailable, identity validation fails closed. The protected property is the
selected pathname slot beneath the already-bound parent; this probe does not claim to bind an
entire ancestor chain or make later pathname use race-free.

File Provider operations accept the same held parent descriptor and raw single-component name,
not an arbitrary URL. The implementation derives a Foundation URL internally, verifies its
filesystem-representation round trip, opens the derived parent no-follow, and compares its real
device, file ID, and directory type against the held parent FD before and after the Foundation
identity operation. It also probes the child raw slot through both parents and compares the child
object identity tuple. A parent rename makes the captured path missing; a rename plus replacement
makes its parent identity mismatch, even when a child hardlink preserves the child's identity.
Either case fails closed, so an `F_GETPATH` result is never trusted after its parent binding stops
matching. Content/materialization stability is a separate protected property: the probe
compares the semantic `isDataless` state without treating link count, timestamps, ordinary
allocation changes, or child-entry churn as object replacement. A same-object materialization
or eviction is a typed content-state mismatch. Missing, unreadable, malformed/inconsistent,
identity mismatch, and content-state mismatch remain distinct typed rejections. The traversal
decision uses the stable postflight evidence, never the stale preflight snapshot. The scanner
remains responsible for binding the inherited parent namespace. These point-in-time checks
detect an observed replacement or materialization transition; they do not exclude a hostile
transient swap and restoration entirely between checks.

## Typed Availability

Each fact is `known`, `unsupported`, `permissionDenied`, `unavailable`, `failed`, or
`inconsistent`. Returned-attribute masks decide whether a parsed value is known. A default
value packed for an unsupported filesystem attribute never becomes evidence.

The Darwin item buffer parser accepts a declared length shorter than the full requested layout
when the returned masks omit the trailing attributes. It reads only fields whose returned bit is
set and whose complete fixed-layout range is inside the declared length. An omitted bit stays
unavailable even if a default byte range exists; a returned bit whose field is outside the
declared length is malformed/inconsistent. The parser never pads a short kernel result or grants
evidence from zero-initialized storage.

The item probe reports:

- logical and nominal allocated bytes;
- `ATTR_CMNEXT_PRIVATESIZE` as immediate private reclaim only;
- `EF_MAY_SHARE_BLOCKS`, `EF_SHARES_ALL_BLOCKS`, clone ID, and clone refcount;
- VFS dataless and sync-root flags; and
- no-credit unavailable values for conditional shared reclaim, snapshot attribution, and
  File Provider hidden backing.

Clone ID/refcount identify full-clone topology when the volume reports that capability.
They do not expose partial shared-byte ownership. Phase 2 must build and validate complete
release sets before assigning conditional reclaim credit.

## File Provider Boundary

Provider discovery combines VFS flags and `NSFileProviderManager` identity lookup. It does not
use a provider-name or provider-path table and never reads item contents. Phase 0 deliberately
does not run `NSFileCoordinator` or promised-value accessors in-process: cancellation cannot stop
an accessor that is already running, so a timeout could otherwise leave accumulating path-touching
work. Promised metadata therefore remains typed `unavailable` until a killable, bounded, reaped
helper-process contract exists.

Provider identity is interpreted as an explicit disposition. A returned identity is
`confirmedProvider`. `NSFileNoSuchFileError` means only `identifierAbsent`: the item may still
be provider-owned but not yet assigned an identifier. Permission denial, timeout/unavailability,
lookup failure, and inconsistent callbacks are `indeterminate`. Neither absent nor indeterminate
identity authorizes local descent. With no positive sync-root or inherited provider-bound
evidence, the result is `doNotDescendUnverifiedProviderOwnership` and report-only. Positive
provider-bound evidence permits metadata-only descent but never changes report-only handling.

- A dataless directory is `doNotDescendDataless` and report-only.
- A materialized provider directory is `descendMetadataOnlyProviderBoundary` and report-only;
  its provider-bound state is passed back as `inheritedProviderBoundary` for descendants.
- A known non-directory is `doNotDescendNonDirectory`; an unavailable object type is
  `doNotDescendUnverifiedItemType`. Provider evidence never turns a regular file into a
  descent candidate.
- This Phase 0 API never invents proven-local ancestry; a future scanner contract may supply
  that evidence separately.

Identity lookup has one monotonic deadline, including subsecond durations. Its heap-owned
completion box closes to late callback writes. Once the semaphore reports timeout, the timeout
path atomically closes and discards any value, including a callback that completes after the
deadline but acquires the box lock before the timeout thread. A post-deadline result can never
turn timeout into success. No metadata accessor or background coordination task is spawned, and
the identity deadline is not represented as control over unrelated, unkillable in-process work.

The controlled extension fixture and callback-zero oracle are defined in
[file-provider-fixture.md](file-provider-fixture.md). Local unsigned compilation and unit tests
do not count as non-materialization acceptance; that result requires the signed lifecycle on
the India host. The true APFS volume-group identity fixture remains unavailable until it can
prove real-device identity across the relevant synthetic/real volume boundary; a local
temporary-root unit test is not a substitute. No local result is presented as cross-volume
acceptance.

## Controlled Probe

`diskplan-macos-probe --self-test` installs the process policy, creates a task-scoped root
under the system temporary directory, probes only content it created, prints compact JSON,
and removes the root. No arbitrary path argument is accepted.
