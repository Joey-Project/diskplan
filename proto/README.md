# Diskplan Protocol

`proto/diskplan/v1/ipc.proto` is the only authoritative IPC schema. Generated
Swift and Rust files are tracked, so ordinary builds and tests never require
`protoc`.

Frames contain a four-byte unsigned big-endian payload length followed by one
serialized `diskplan.v1.Envelope`. The maximum payload is 16 MiB. A zero-byte
read before a prefix is clean EOF; partial prefixes, partial payloads, and
oversized lengths are distinct typed errors. Engine stdout is reserved for
binary frames. Diagnostics go to stderr.

The exact code-generator and runtime versions are recorded in
`proto/toolchain.lock`, `Package.resolved`, and `Cargo.lock`.

```sh
scripts/proto-codegen.sh check
scripts/proto-codegen.sh generate
```

Both commands reject mismatched `protoc` or `protoc-gen-swift` versions.
`check` generates into a task-scoped temporary directory and compares bytes;
`generate` is the explicit operation that replaces tracked generated sources.
It rejects destination symlinks, non-regular pathname slots, and destination
directories that escape the repository through symlinks. Each generated file
is staged, synced, byte-checked, and replaced atomically within its own
directory. The two directories cannot form one filesystem transaction; an
ordinary second-file failure rolls back the first replacement, while a process
or machine crash can still leave one old and one new file. A following `check`
detects that source mismatch without treating it as an access-boundary error.

`proto/fixtures/canonical-binary-v1` contains a human-readable fixture, its
exact canonical bytes, and its domain-separated SHA-256 digest. Canonical
bindings are deliberately independent of Protobuf serialization.

`proto/fixtures/scan-stream-v1.3` contains the human-readable source and exact
framing-v1 protobuf vectors for zero-, single-, and multi-chunk checkpoint
streams. The vectors cover both ready and finalized terminals. Swift authors
them; Swift and Rust independently decode, validate, and byte-for-byte
re-encode every frame, then exercise truncation and mismatched count, digest,
and frontier mutations.

```sh
scripts/protocol13-fixtures.sh check
scripts/protocol13-fixtures.sh generate
```

## `canonical-binary-v1` evidence skeleton

The first skeleton is intentionally small, closed, and strict. Its fixed field
order and wire types are:

1. ASCII magic `DPCB` (four raw bytes).
2. Schema version (`u16`, big-endian; exactly `1`).
3. Candidate ID (UTF-8 bytes with a `u32` big-endian length).
4. Raw filesystem path (`u32` big-endian length plus uninterpreted bytes).
5. Logical bytes (`u64`, big-endian).
6. Observed time: variant byte `0` for absent or `1` followed by signed `i64`
   UTC seconds and `u32` nanoseconds, all big-endian.
7. Activity variant byte: `0` absent, `1` unknown, `2` inactive, `3` active.
8. Coverage variant byte: `0` unknown, `1` complete, `2` partial, `3`
   unreadable, `4` failed.
9. Label count (`u32`, big-endian), followed by unique UTF-8 labels in raw-byte
   ascending order, each with a `u32` big-endian length.

Unknown variants, invalid UTF-8 for typed strings, invalid nanoseconds,
non-canonical label order, truncation, unsupported versions, and trailing bytes
all fail closed. The evidence digest is SHA-256 over the exact bytes
`diskplan/evidence/v1\0` followed by the canonical record.

Swift's `CanonicalBinaryV1` is the production binding authority: it hashes
only bytes it has just encoded from a typed binding, or external bytes that
strictly decode and re-encode byte-for-byte. Rust exposes only the independent
strict verifier and verified digest API; its production surface cannot author
evidence bytes. Fixture JSON rejects unknown fields and requires the exact
`schema` and `binding_kind` tags. `generate` atomically replaces each tracked
binary or digest file after the Swift authority has produced it.

```sh
scripts/canonical-fixture.sh check
scripts/canonical-fixture.sh generate
scripts/test-cross-language.sh
```

## Phase 1 scan stream

Protocol minor `1.3` retains `scan-control-v1` and adds the independently
negotiated `scan-stream-v1` and `raw-path-bytes-v1` capabilities. The client
sends `StartScanRequest` once and then typed controls for pause, resume,
checkpoint, provisional-evidence checkpoint, partial finalization, or cancel.
The provisional-evidence operation uses
`CHECKPOINT_PROVISIONAL_EVIDENCE`; the older
`PAUSE_AND_BUILD_PROVISIONAL_PLAN` value remains decodable for minor-version
compatibility but is rejected by the Phase 1 producer.
Every request has a non-zero, strictly increasing `request_id`; its envelope
sequence equals that request ID. Malformed embedded requests, replays,
duplicates, and out-of-order IDs pass through the same bounded high-water path.

Every engine event has an `event_sequence` that starts at one and increases by
exactly one, and its envelope sequence equals that event sequence. Direct
acknowledgements repeat their non-zero request ID. Naturally produced scan
events use `request_id = 0` and carry the stable, non-empty `scan_session_id`
created for that scan. The Rust session validates both provenance forms, exact
sequence continuity, and immutable scan-session identity before forwarding an
event to the reducer.

After the handshake, one serial Swift broker is the sole stdout writer. It
keeps semantic events in a finite lossless queue and backpressures the scanner
when that queue is full. Only the last member of one contiguous pending
`ScanProgress` run may be replaced by fresher telemetry. Event sequence numbers
are assigned at write time, so coalescing never creates a protocol gap and can
never discard node evidence, state changes, control responses, checkpoints,
finalization, cancellation, or failures.

Inbound controls use a separate 256-entry FIFO ring. Admission is O(1); a
request that arrives while all slots are occupied receives
`CAPACITY_EXCEEDED` and is never partially admitted. Admitted controls retain
request order and produce exactly one accepted or rejected response. Engine
shutdown is an out-of-band priority signal rather than another FIFO member: it
cancels the scanner before executing any queued control, then drains the
bounded remainder as ordered rejections so an input flood cannot starve EOF
shutdown.

Node observations are lossless stream events. Retained checkpoint nodes are
also encoded as an ordered stream of `ScanCheckpointChunk` events before the
matching ready or finalized event. Each chunk contains at most 4 MiB of
canonical node records, well below the 16 MiB frame limit. A record is a
four-byte unsigned big-endian length followed by the canonical protobuf bytes
of one `ScannedNodeEvidence`; the chunk digest covers that exact concatenation.
The terminal manifest declares protocol version, chunk and retained-node
counts, entry and byte budgets, ordered chunk IDs and SHA-256 digests, the
checkpoint-evidence digest, and the final evidence digest. The unchunked
checkpoint payload and encoded manifest are independently capped at 4 MiB and
2 MiB, while total retained-node payload is capped at 768 MiB and 10,000 entries.
The checkpoint payload omits retained nodes but includes and is bound to the
complete coverage/frontier projection: progress, coverage, completed and failed
roots, machine state, and resumable/provisional state.
Setup rejects root collections whose duplicated checkpoint root-binding
projection exceeds 1 MiB, leaving headroom inside the 4 MiB unchunked
checkpoint budget for terminal evidence instead of accepting a scan that can
never finalize.

The Rust receiver admits chunks only at exact contiguous indices, verifies
every canonical record and digest, and rejects duplicates, gaps, interleaved
checkpoint IDs, mismatched counts, or budget overruns. `ScanCheckpointReady`
and `ScanFinalized` become visible to the reducer only after the manifest,
checkpoint bytes, coverage/frontier mirror, ordered descriptors, aggregate
counts, evidence digest, and final digest all agree. Chunks and manifests are
semantic events and are never coalesced; only adjacent progress remains
coalescible.

The final evidence hash is SHA-256 over the ASCII domain
`diskplan/scan-checkpoint-final/v1\0`, followed by these fields in order:
manifest version (`u32` big-endian), length-prefixed checkpoint digest, chunk
count (`u32`), retained-node count (`u64`), retained-node entry budget (`u32`),
retained-node payload bytes (`u64`), the checkpoint/chunk/manifest maximum byte
budgets (`u32` each), the total retained-node maximum byte budget (`u64`), then
every descriptor in manifest order. A descriptor contributes its
index (`u32`), length-prefixed UTF-8 chunk ID, node count (`u32`), payload bytes
(`u64`), and length-prefixed digest. Every length prefix is an unsigned
big-endian `u32`. `checkpoint_id` is the lowercase hexadecimal final digest;
`chunk_id` is `<decimal-index>-<lowercase-payload-digest>`. The checkpoint
digest is SHA-256 over `diskplan/scan-checkpoint-evidence/v1\0` followed by the
exact canonical checkpoint protobuf bytes. Validating the manifest's mirrored
frontier against that decoded payload therefore binds coverage and frontier to
the same final hash without trusting presentation strings.

Control state does not change speculatively in the frontend. A
`ControlAccepted` acknowledges the request and supplies the resulting engine
state; `ControlRejected` leaves the prior state intact. Checkpoint and
finalization events contain scanner evidence rather than plan symbols. The
Phase 0 provisional-plan messages remain reserved for wire compatibility but
are not emitted by the Phase 1 producer. A `ScanFinalized` event terminates the
scan worker, not the engine process or negotiated session; later protocol
requests remain valid until stdin closes. The Rust TUI retains the final
checkpoint and enables `q` exit only after `ScanFinalized` has arrived, rather
than treating the preceding terminal state-change event as final evidence.
Cancelled scans follow the same rule: `ScanCancelled` reports status but does
not close the driver; a subsequent explicit `q` exits the verified session.
If `q` closes stdin immediately after cancelled `ScanFinalized`, the Rust
session concurrently drains stdout while waiting for or terminating the child.
It accepts exactly the next contiguous `ScanCancelled` tail event for that
cancelled finalization, continues through an explicit clean EOF, and rejects a
duplicate, wrong-state, out-of-order, malformed, or otherwise extra frame.
This bounded concurrent drain prevents the capacity-one decoder from blocking
the child before exit without weakening shutdown frame validation.

A rejected `StartScanRequest` carries both the broad `ControlRejectCode` and,
when rejection occurred while validating or constructing the scan, a stable
`ScanSetupRejectCode`. Capability negotiation, profile/root/budget validation,
duplicate root IDs, no-materialization policy installation, root discovery,
and scanner initialization remain distinct. A control-plane rejection that
happens before setup begins leaves the setup code unspecified.

`ScanCheckpoint` preserves the frozen profile, raw resolved scope, structural
budgets, root coverage and failures, retained nodes, process-activity evidence,
collector configuration, global VM/swap/APFS facts, and progress facts. Phase 1
does not classify candidates, calculate reclaim, or construct actions. Partial
finalization and cancellation are typed evidence outcomes that a later planning
phase may consume. The legacy progress `candidates` and
`reclaim_estimate_bytes` fields are therefore always zero in this stream;
authoritative byte observations remain in their typed evidence fields. An
authoritatively empty resolved-root list is valid evidence and is not rewritten
as a setup failure.

Filesystem paths have two separate representations. `raw_absolute_path` and
each raw component preserve uninterpreted filesystem bytes; `display_path` is
an engine-authored projection for presentation only. Rust must not reconstruct
an authoritative path from display text or use display strings for filesystem
operations. The engine ignores `display_path` on an inbound scan-root request
and replaces it in emitted evidence. Invalid UTF-8 and terminal control or
format characters are rendered as byte escapes rather than passed through.

Before any path access, scan setup applies the scanner's lexical root contract
to the original bytes. Exact `/` is supported. Every other root must start with
one `/`, end in a non-empty ordinary component, and contain neither NUL,
repeated separators, a trailing separator, nor `.` or `..` components. Alias
forms are rejected rather than normalized, so setup cannot bind two different
wire values to one canonical scanner root.

## Protocol 1.4 plan and execution runtime

Protocol minor `1.4` keeps every `1.3` field and fixture byte-for-byte
decodable and adds four independently negotiated capabilities:
`plan-projection-v1`, `decision-overlay-v1`, `dry-run-projection-v1`, and
`execution-stream-v1`. A request that uses a capability which was not
negotiated is rejected without changing engine state. All runtime requests and
events retain the framing, envelope-sequence, request-ID, and single-writer
rules above.

An engine advertises a runtime capability only when an injected business
handler implements it. A scan-only engine therefore continues to advertise
only the `1.3` scan capabilities and returns a typed
`RUNTIME_REJECT_CODE_BUSINESS_UNSUPPORTED` event for a `1.4` runtime request.
Execution events use the ordinary framing maximum for each frame and the
manifest-declared aggregate event-count and encoded-byte budgets for the full
stream; there is no smaller runtime-specific per-event byte limit.

The Swift engine is the only classification and execution authority. Runtime
identifiers are opaque byte strings. The Rust frontend may retain and compare
them, and may return identifiers that appeared in the current projection, but
must not parse an identifier into a path, action kind, release dependency, or
command. `PlanRawPathProjection` preserves raw root and component bytes while
also carrying an engine-authored display string. The frontend must never
reconstruct an authoritative path from that string. `raw_executable` and
`raw_argv` occur only in engine-to-frontend execution previews; no request has
an argv or path slot.

`BuildPlanRequest` binds one held scan checkpoint by session ID, checkpoint ID,
and evidence digest. Partial evidence is consumed only when
`allow_partial_evidence` is explicit and policy accepts it. The engine streams
zero or more `PlanProjectionChunk` events followed by exactly one
`PlanProjection` manifest. A chunk payload is a concatenation of records, each
encoded as a four-byte unsigned big-endian length followed by the exact
protobuf bytes of one `PlanProjectionRecord`. Records have contiguous indices
and a closed action, target, or release-set body. Target hierarchy is flat:
each target names its action and optional parent, which prevents protobuf
recursion from bypassing the declared record and depth budgets.

Every opaque identifier is non-empty and at most 256 bytes; every digest
wrapper and typed digest ID contains exactly 32 bytes. The chunk payload digest is
ordinary SHA-256 over `canonical_record_payload`. A chunk ID is SHA-256 over
`diskplan/plan-projection-chunk-id/v1\0`, its `u32` big-endian index, and its
length-prefixed payload digest. The terminal projection digest is SHA-256 over
`diskplan/plan-projection-final/v1\0` followed, in order, by manifest version
(`u32`); length-prefixed plan and evidence digests; length-prefixed UTF-8
policy and schema versions; chunk, record, action, target, release-set,
blocker, and waiver counts (chunk is `u32`, the rest are `u64`); total record
payload bytes, maximum record count, and maximum record payload bytes (`u64`);
maximum chunk payload and manifest encoded bytes (`u32`); then every descriptor
in order. A descriptor contributes its index (`u32`), length-prefixed chunk ID,
record count (`u32`), payload bytes (`u64`), and length-prefixed payload
digest. `projection_id` is the exact projection digest bytes. Counts, declared
budgets, descriptor order, record order, IDs, cross-record references, digest
lengths, duplicate IDs, unknown enum values, unknown fields, non-canonical
record re-encoding, or a digest mismatch all fail closed before the TUI can
stage an action. After the descriptors, the digest also binds the complete
canonical disposition-count table and recommendation-count table. Each table
is enum-value ordered, contains every supported non-unspecified value exactly
once, and each row contributes its enum as `u32` followed by its action count
as `u64`; each table is prefixed by a `u32` row count.
The final `u64` value is the engine-authored cleanup-candidate count used by
noninteractive summaries; a client must not recreate it by classifying rows.
The digest then binds the length-prefixed scan-session ID, scan-checkpoint ID,
plan ID, evidence ID, and checkpoint-evidence digest. The plan and evidence IDs
are exactly their matching 32-byte digests; the scan IDs remain opaque
provenance values. `evidence_sha256` is the scan's final evidence digest, while
`scan_checkpoint_evidence_sha256` preserves the distinct unchunked checkpoint
payload digest from protocol 1.3. As in the 1.3 manifest,
`scan_checkpoint_id` is the lowercase hexadecimal final evidence digest; every
later projection repeats that exact three-part scan binding.

Each action also carries a bounded `PlanSafetyEvidenceProjection`. Its
`policy_evidence_sha256` is exactly the Swift policy model's
`FrozenEvidenceSnapshot.evidenceID`; it is not recomputed by Rust. Because the
complete action record is inside the chunk payload, the plan projection digest
binds both that authoritative evidence ID and every domain-separated scan
bundle/display summary. The policy evidence ID and scan bundle digests are
separate exact predecessors; Rust verifies their placement in the sealed plan
but never reconstructs either digest or maps scan facts back into policy.

Namespace evidence remains engine-internal except for closed observation
states, counts, and digests. `namespace_binding_sha256` binds the policy
model's canonical `ProtectedNamespaceBinding`: raw absolute root bytes, root
identity and seal, raw target components, target identity, then every ordered
parent's raw relative components, identity, and access-policy seal. The
target and root access-policy/ACL observations separately bind their canonical
values. Scanner-authored root and terminal-ancestor seal observations bind the
descriptor-derived ACL/access-policy chain without exporting parent records.
The ancestor-chain observation value digest binds the same ordered parent
chain; the transmitted count is capped at 1,024. The frontend receives target raw
bytes only through the bounded `PlanTargetProjection`; no namespace path is
normalized into a safety-relevant `String` or copied into an unbounded list.

Content protection is opt-in and distinguishes a required content digest from
an explicitly inapplicable object with one closed reason. Non-collected content
stays a typed not-requested, unknown, unreadable, or failed observation rather
than silently becoming metadata-only.

Git worktree evidence exposes the policy model's 12 fixed observations and
canonical binding digest. A separate bounded scan summary binds the domain
`diskplan/git-worktree-scan-evidence/v1\0`, collector/budget inputs, marker,
worktree/admin/common identities, registration and metadata digests, linkage,
feature states, five status counters, and the streamed change-set digest. The
status counter total is capped at 50,000 and the closed command coverage carries
canonical typed reasons. Neither layer exports status paths or another
unbounded record list.

Codex cleanup evidence distinguishes configured bound scope from type-hint-only
provenance. Only the configured variant may carry an opaque scope ID. Bound-root
identity, helper capability, and closed coverage are display summaries inside
the `diskplan/codex-cleanup-scope-evidence/v1\0` binding; a type hint is always
partial and never upgrades authority.

Versioned-artifact evidence uses opaque artifact/version/scope identifiers,
closed active/survivor states, and a 4,096-entry maximum matching the configured
adapter budget. The bounded display summary carries install-root and active
selector identities, the exact raw selector leaf (maximum 4 KiB), inventory and
metadata-complete counts, update state, survivor count and survivor-set digest,
and closed coverage. Exact version names, per-version identities/metadata, and
survivor names remain inside the Swift engine and the domain-separated canonical
bundle. Unknown, absent, unreadable, and failed observations remain distinct.
These fields exist for evidence/reason display and exact binding checks; Rust
must not turn them into stageability, adapter, survivor, or cleanup authority.

Decision edits are atomic against one projection and one overlay revision.
They can stage or unstage an existing action, allow or revoke one projected
waiver, or replace notes. A batch client can instead ask the engine to apply
one closed `BatchSelectionPreset`; it is separate from the interactive edit
model and from the agent fallback mode.
`SAFE_STAGEABLE_WITHOUT_WAIVER` selects only actions whose authoritative
engine result is stageable without waiver; zero selected actions remains a
valid explicit overlay and never degrades dry-run into scan-only output. The
engine maps waiver IDs back to the closed
predicate and lineage; the frontend cannot supply either. An acknowledgement
returns the complete selected-action, consent, notes, and force-warning state,
plus the new revision, opaque overlay ID, overlay digest, and exact plan/evidence
ID-and-digest tuple. A stale revision, unknown ID,
duplicate edit, non-stageable action, invalid reason, or count/byte limit is a
typed rejection and leaves the prior overlay unchanged.
The v1 acknowledgement limits are 100,000 selected actions, 100,000 waiver
consents, 10,000 notes, 1 MiB of UTF-8 note bytes, and 12 MiB encoded total.
`projection_sha256` is SHA-256 over
`diskplan/decision-overlay-projection/v1\0` followed by the exact canonical
protobuf bytes of an acknowledgement copy with only `projection_sha256`
absent. It seals all selected IDs, waiver consents, notes, force warnings,
budgets, and plan/evidence/scan references. The distinct `overlay_sha256`
remains the engine's canonical editable-overlay hash consumed by preparation.

Planning also receives one explicit `AgentMode`: `OFF`, `ASK`, or `AUTO`.
`ASK` is the product default and permits remote fallback only through the
separate per-use disclosure/confirmation policy; `AUTO` permits configured
automatic fallback for unknown classification; `OFF` is local-only. This enum
does not select actions and cannot relax any one-vote policy gate.

`PrepareDryRunRequest` binds the acknowledged projection, overlay ID, revision,
and overlay digest. `DryRunProjection` has no apply capability or confirmation field. Its
payload is the exact protobuf encoding of `DryRunProjectionPayload`, capped by
the manifest and accepted only when decode/re-encode is byte-identical. The
payload digest is SHA-256 over
`diskplan/dry-run-projection-payload/v1\0` followed by those bytes. The final
typed revalidation digest is SHA-256 over
`diskplan/revalidation-projection/v1\0` followed by the exact canonical
`RevalidationProjectionPayload` bytes. The final
projection digest is SHA-256 over
`diskplan/dry-run-projection-final/v1\0` followed by the manifest version,
length-prefixed projection ID, plan and overlay digests, the four epoch fields,
the current flag, action and finding counts, the corresponding maximum counts,
the maximum payload bytes, length-prefixed payload digest, length-prefixed
dry-run ID, selected-action count, length-prefixed overlay ID, plan ID,
evidence ID, evidence digest, current-binding digest, revalidation digest, and
overlay revision, followed by the scan-session ID, scan-checkpoint ID, and
checkpoint-evidence digest. Integer
fields use fixed-width big-endian encoding and byte/string fields use `u32`
big-endian length prefixes.
`current_binding_sha256` is present exactly when `current` is true; a rejected
dry-run binds an empty length-prefixed slot instead of inventing current
authority.
The v1 limits are 100,000 selected actions, 1,000,000 typed findings, and a
12 MiB canonical payload. The lower single-payload limit leaves framing and
manifest headroom beneath the 16 MiB envelope ceiling.

`PrepareApplyReviewRequest` binds the same exact overlay tuple and performs a
separate current revalidation. The
result binds the engine-authored action previews, exact sorted force-warning
action IDs, overlay ID and selected count, epoch deadline, and typed findings
into `review_binding_sha256`.
`apply_review_id` is only a lookup in the current negotiated-session registry;
it is not an apply capability and is insufficient without that exact binding
and force list. The registry retains the module-private, one-use apply
capability. `ConfirmApplyRequest` returns only the review ID, binding digest,
and exact confirmed force list. A new preparation, expiry, disconnect,
binding/list mismatch, or replay invalidates the lookup before any adapter is
reached. The review projection digest is SHA-256 over
`diskplan/apply-review-projection/v1\0` followed by the exact canonical
protobuf bytes of a copy whose `projection_sha256` field is absent; receivers
must reject unknown fields and require byte-identical decode, clear, and
re-encode before checking the digest.
The v1 apply-review limits are the same 100,000 actions and 1,000,000 findings,
with a 12 MiB encoded projection ceiling.
`RUNTIME_REJECT_CODE_CONFIRMATION_MISMATCH` is reserved for a terminal
`ConfirmApplyRequest` response emitted only after the Swift authority has
atomically claimed and conservatively consumed that exact live review. Request
ID, capability, unsupported-business, malformed, stale-binding, and other
pre-claim failures must use their own rejection codes and never this reserved
value. Stateful consumers may consume a rejected confirmation only from the
canonical request/rejection envelope pair with this code and matching request,
runtime-session, review-binding, and force-confirmation tuple.

Execution events use a contiguous `execution_event_index` starting at one and
scoped to one opaque
execution ID. The first event repeats the exact apply-review, plan, overlay,
review-binding, selected-count, and epoch tuple consumed by the private
authorization boundary. Adapter outcomes, post-verification, JIT rejection,
prerequisite skip, cancellation acknowledgement, expiry, supersession,
partial success, audit failure, and apply-start failure remain separate typed
variants. The terminal separates successful, partial, failed, cancelled,
prerequisite-skipped, JIT-rejected, expired, and superseded unit counts; their
sum equals the exact unit count. `ApplyFinishedProjection` declares exact
event/count/byte totals and their maxima, and repeats `apply_review_id` plus
`review_binding_sha256` even for a typed start failure. This lets a stateful
receiver reject a valid-but-foreign execution stream without relying on an
`ApplyStartedProjection` that does not exist when start fails. Its execution-record
digest is SHA-256 over `diskplan/execution-record/v1\0`, followed by every
preceding `ExecutionStreamEvent` as a `u32` length plus the exact canonical
protobuf bytes, then the terminal event encoded the same way with
`execution_record_sha256` absent. Unknown fields, an event gap, a changed
execution ID, count or byte overrun, a non-canonical event, an event after the
terminal, or a final digest mismatch fails the stream without changing an
already reported best-effort mutation outcome.
The v1 execution-record limits are 1,000,000 events and 768 MiB of canonical
length-prefixed event bytes.
