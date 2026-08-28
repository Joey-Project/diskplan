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
