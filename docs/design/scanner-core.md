# Phase 1 Scanner Core

`DiskplanScan` is the deterministic, read-only evidence collector that sits between
the macOS capability layer and the later classification/policy pipeline. It does
not classify files, select cleanup actions, or infer safety.

## Filesystem identity contract

The protected property during traversal is object identity: device, file ID, and
object type for one descriptor-relative directory slot. The walker:

1. binds each configured root to an open directory descriptor and stable identity;
2. enumerates raw directory-entry bytes and sorts them lexicographically;
3. inspects children relative to the held parent descriptor without following
   symbolic links;
4. opens a child directory relative to that same descriptor and compares all three
   identity fields before enumeration.

A missing slot, unreadable slot, collector failure, and replacement mismatch are
different observations. Child-entry churn alone does not constitute root identity
mutation. The production backend never constructs child paths; only the explicitly
configured root and its parent slot are path-opened to establish the root binding.

## Evidence model

- `Observation` preserves known, absent, unknown, unreadable, and failed states.
- `Coverage` carries completeness independently from a canonical set of reasons.
- `ByteMeasure` distinguishes exact values, lower bounds, and unknown values.
- APFS/hardlink topology preserves link count, clone ID/refcount, sharing flags,
  and conditional reclaim uncertainty as independent typed observations.
- Filesystem atime, mtime, ctime, and birthtime stay separate advisory metadata;
  the scanner never synthesizes a `last_used_at`. UID, GID, mode, and flags form a
  separate access-policy seal. Pre/post access-policy changes are unstable scan
  evidence, while timestamp changes alone are not treated as object replacement.
- File Provider boundaries come from the system probes, never provider-name or path
  exclusion tables. Dataless/rejected boundaries stop traversal. Positively
  provider-bound materialized directories may be enumerated metadata-only, remain
  partial/report-only evidence, and propagate the provider boundary to descendants.
  Provider item/domain identity, promised metadata, hidden-byte unavailability, and
  controlled non-materialization acceptance remain typed rather than being reduced
  to a Boolean boundary flag.
- Mount boundaries and symbolic links are reported but never traversed.

Closed directories are aggregated incrementally, so the scanner need not retain the
entire filesystem tree. A synchronous typed event sink receives every observation
and completed-directory replacement for downstream evidence storage. A bounded
stable top-K view is retained by immediate-private-reclaim lower bound descending
and raw path ascending. This is an evidence viewport, not a cleanup recommendation
or the complete candidate corpus. Directories retain `subtree_incomplete` until a
closed-directory event proves their current observed subtree complete.

## Profiles and control

`ScanRootResolver.version == 1` resolves quick, standard, deep, and full-audit
profiles with the structural budgets accepted in the project design. Explicit
maximum duration is optional; when it fires, the result is `partial` with
`timed_out` coverage. Structural budget exhaustion likewise cannot yield a complete
machine state.

`ScanSession` is an actor-controlled batch scanner. It records a deterministic,
monotonic transcript for start, advance, pause, checkpoint, provisional snapshot,
resume, partial finalization, completion, and cancellation. Checkpoints are
resumable only while the original process retains its descriptor-bound scanner.

Process activity is represented by a bounded collector protocol. The included
parser accepts normalized `lsof -nP -F0pcfn` records and canonicalizes typed results;
it does not run recursive per-directory `lsof` probes. VM, swap, and APFS snapshot
facts stay explicitly unavailable until their public collectors are implemented.

## Phase boundary

This module intentionally excludes recognizers, semantic classification, one-vote
policy decisions, release-set graph construction, immutable plan creation, IPC, and
TUI behavior. Those consume the scanner evidence in later phases.
