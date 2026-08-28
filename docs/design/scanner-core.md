# Phase 1 Scanner Core

`DiskplanScan` is the deterministic, read-only evidence collector that sits between
the macOS capability layer and the later classification/policy pipeline. It does
not classify files, select cleanup actions, or infer safety.

## Filesystem identity contract

The protected property during traversal is object identity: device, file ID, and
object type for one descriptor-relative directory slot. The walker:

1. revalidates the live process no-materialization policy immediately before every
   root/parent open, descriptor-relative path inspection, child open, and `readdir`;
2. requires every configured root to pass the authoritative File Provider boundary
   probe before the root itself is opened; absent or unavailable provider identity
   does not become local evidence;
3. binds each accepted root to an open directory descriptor and stable identity;
4. enumerates raw directory-entry bytes into a bounded lexicographic retention set;
5. inspects children relative to the held parent descriptor without following
   symbolic links;
6. opens a child directory relative to that same descriptor and compares all three
   identity fields before enumeration; and
7. retains the parent-slot descriptor, raw name, identity, and access-policy seal
   until the directory closes, then revalidates the open descriptor and parent slot.

An authoritative provider probe is bracketed by complete policy-relevant item
snapshots. The postflight must match provider flags, dataless/sync-root state,
logical and allocation evidence, private-reclaim credit, link count, clone/sharing
topology, and unavailable-state evidence before either traversal or exact byte
credit is accepted. A mismatch is typed as unstable, provider-unverified evidence;
the stale boundary and byte snapshot are never returned as known.

`ItemProbe`, root descriptors, child descriptors, mount comparisons, and close
revalidation all use the same real-device, file-ID, and object-type namespace.
Ordinary `st_dev` is never compared with an `FSOPT_RETURN_REALDEV` identity.

A missing slot, unreadable slot, access-policy mutation, collector failure, and
replacement mismatch are different observations both during inspection and at
directory close. Child-entry churn alone does not constitute root identity mutation.
The production backend never constructs descendant paths; only the configured root's
parent path is path-opened to establish the descriptor-relative root slot. A root
with unproved provider ownership is retained in provenance and root failures but is
never opened or treated as `localOrUnindicated`.

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
  to a Boolean boundary flag. Probe rejection is not converted into a known
  rejected node: missing, unreadable, identity/content mismatch, unavailable state,
  and timeout remain distinct `Observation` variants and coverage reasons.
- Mount boundaries and symbolic links are reported but never traversed.

Closed directories are aggregated incrementally, so the scanner need not retain the
entire filesystem tree. A synchronous typed event sink receives every observation
and completed-directory replacement for downstream evidence storage. A bounded
stable top-K view is retained by immediate-private-reclaim lower bound descending
and raw path ascending. This is an evidence viewport, not a cleanup recommendation
or the complete candidate corpus. Directories retain `subtree_incomplete` until a
closed-directory event proves their current observed subtree complete and stable.

Directory enumeration is bounded independently from result retention. Each profile
binds a per-directory name-count ceiling and a global pending raw-name byte ceiling.
The backend scans entries under the scan deadline while retaining only the
lexicographically smallest names that fit both limits, so complete enumeration is
stable under kernel enumeration permutations. Truncation and in-enumeration timeout
are explicit partial coverage; they can never produce a complete root.

## Profiles and control

`ScanRootResolver.version == 1` resolves quick, standard, deep, and full-audit
profiles with the structural budgets accepted in the project design. Explicit
maximum duration is optional; when it fires, the result is `partial` with
`timed_out` coverage. Structural budget exhaustion likewise cannot yield a complete
machine state. Root IDs are unique provenance keys: both direct scope construction
and profile resolution reject duplicates before `ResolvedScanScope` is frozen.
Traversal frames retain the actual bound `RootBinding`; completion never recovers a
binding by looking up a possibly aliased display/path ID.

`ScanSession` is an actor-controlled batch scanner. It records a deterministic,
monotonic transcript for start, advance, pause, checkpoint, provisional snapshot,
resume, partial finalization, completion, and cancellation. Checkpoints are
resumable only while the original process retains its descriptor-bound scanner.

Every `ScanResult.reference` binds the complete resolved scope, including failed and
not-yet-started raw roots, the profile and resolver version, entry/depth/enumeration/
pending-name/retention limits, the scan time limit, and the canonical collector
configuration. A partial or failed scan therefore cannot be detached from omitted
scope or weaker budgets while retaining the same provenance.

Process activity is represented by a bounded collector protocol. The included
parser accepts normalized `lsof -nP -F0pcfn` records and canonicalizes typed results;
it does not run recursive per-directory `lsof` probes. VM, swap, and APFS snapshot
facts stay explicitly unavailable until their public collectors are implemented.

## Phase boundary

This module intentionally excludes recognizers, semantic classification, one-vote
policy decisions, release-set graph construction, immutable plan creation, IPC, and
TUI behavior. Those consume the scanner evidence in later phases.
