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
`FSOPT_NOFOLLOW | FSOPT_RESOLVE_BENEATH`. The protected property is the selected pathname
slot beneath the already-bound parent; this probe does not claim to bind an entire ancestor
chain or make later pathname use race-free.

File Provider operations accept the same held parent descriptor and raw single-component name,
not an arbitrary URL. The implementation derives a Foundation URL internally, verifies its
filesystem-representation round trip, probes the raw slot through both the held parent and the
derived parent path, and compares no-follow device, file ID, and object type before and after
Foundation operations. Missing, unreadable, other failures, and identity mismatch remain
distinct typed rejections. The scanner remains responsible for binding the inherited parent
namespace. These point-in-time checks detect an observed replacement; they do not exclude a
hostile transient swap and restoration entirely between checks.

## Typed Availability

Each fact is `known`, `unsupported`, `permissionDenied`, `unavailable`, `failed`, or
`inconsistent`. Returned-attribute masks decide whether a parsed value is known. A default
value packed for an unsupported filesystem attribute never becomes evidence.

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

Provider discovery combines VFS flags, `NSFileProviderManager` identity lookup, immediate
metadata-only `NSFileCoordinator` access, and promised resource values. It does not use a
provider-name or provider-path table and never reads item contents.

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
- This Phase 0 API never invents proven-local ancestry; a future scanner contract may supply
  that evidence separately.

Identity lookup and synchronous metadata coordination share one monotonic deadline, including
subsecond durations. Coordination runs away from the caller thread. Timeout cancels the
coordinator, closes heap-owned completion boxes to late writes, and returns a typed report-only,
non-descending result.

The controlled extension fixture and callback-zero oracle are defined in
[file-provider-fixture.md](file-provider-fixture.md). Local unsigned compilation and unit tests
do not count as non-materialization acceptance; that result requires the signed lifecycle on
the India host.

## Controlled Probe

`diskplan-macos-probe --self-test` installs the process policy, creates a task-scoped root
under the system temporary directory, probes only content it created, prints compact JSON,
and removes the root. No arbitrary path argument is accepted.
