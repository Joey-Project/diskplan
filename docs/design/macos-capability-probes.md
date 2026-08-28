# macOS Capability Probe Contract

This document describes the Phase 0 implementation boundary for the accepted
[storage and File Provider design](accepted-plan.md#8-storage-metrics-and-apfs-dependency-graph).

## Path Access Boundary

The engine must install `IOPOL_MATERIALIZE_DATALESS_FILES_OFF` at process scope and verify
the readback before it performs any path access. Probe entry points require the resulting
`NoMaterializationPolicy` token.

Item metadata is collected from a held parent directory descriptor with a single raw-name
component. The C shim rejects empty names, separators, NUL, `.` and `..`, and uses
`FSOPT_NOFOLLOW | FSOPT_RESOLVE_BENEATH`. The protected property is the selected pathname
slot beneath the already-bound parent; this probe does not claim to bind an entire ancestor
chain or make later pathname use race-free.

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
`confirmedProvider`; the public API's `NSFileNoSuchFileError` result is `confirmedLocal`.
Permission denial, timeout/unavailability, lookup failure, and inconsistent callbacks are
`indeterminate`, never local. With no positive sync-root or inherited provider-bound evidence,
an indeterminate result is `doNotDescendUnverifiedProviderOwnership` and report-only. Positive
provider-bound evidence permits metadata-only descent but never changes report-only handling.

- A dataless directory is `doNotDescendDataless` and report-only.
- A materialized provider directory is `descendMetadataOnlyProviderBoundary` and report-only;
  its provider-bound state is passed back as `inheritedProviderBoundary` for descendants.
- A local directory is `descendLocal` with normal handling.

The India-host script hook deliberately reports the controlled extension fixture as
not available until a real File Provider extension and callback-zero oracle exist. No local
unit result is presented as real non-materialization acceptance.

## Controlled Probe

`diskplan-macos-probe --self-test` installs the process policy, creates a task-scoped root
under the system temporary directory, probes only content it created, prints compact JSON,
and removes the root. No arbitrary path argument is accepted.
