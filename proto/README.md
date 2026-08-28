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

## `scan-control-v1`

Protocol minor `1.2` adds a typed Phase 0 scan-control stream. The client sends
`StartScanRequest` once and then `ScanControlRequest` values for pause, resume,
pause-and-build-provisional-plan, or cancel. Every request has a non-zero,
session-unique `request_id`; its envelope sequence must equal that request ID.

The engine responds only with `EngineEvent`. Every event repeats its originating
`request_id`, has an `event_sequence` that starts at one and increases by exactly
one, and is framed in an envelope whose sequence equals the event sequence. The
Rust session rejects gaps, replay, reordering, and envelope/event sequence
disagreement before the TUI consumes an event.

After that validation, the frontend bridge keeps semantic events in a bounded,
lossless queue and coalesces only contiguous `ScanProgress` runs to their latest
value. The reducer receives the exact number of omitted progress events and
accepts only the corresponding strictly increasing sequence gap. It still
rejects duplicate, out-of-order, unproven-gap, or malformed semantic events and
stops the engine driver on such a protocol invariant failure.

Control state does not change speculatively in the frontend. A
`ControlAccepted` acknowledges the request and supplies the resulting engine
state; `ControlRejected` leaves the prior state intact. State, progress,
provisional-plan projection, invalidation, cancellation, completion, and engine
failure are separate event variants.

`ScanProgress` carries only engine facts: elapsed time, entry/directory/candidate
counts, observed allocation, the current reclaim estimate, root coverage, rate,
current root, profile, and structural budget. It deliberately has no completion
percentage. `ProvisionalPlanReady` similarly carries engine-authored plan groups
and reclaim projections. Rust may format these values for display but must not
reclassify candidates, calculate reclaim, regroup plans, or construct paths or
commands.
