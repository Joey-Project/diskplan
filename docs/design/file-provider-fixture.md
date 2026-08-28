# Controlled File Provider Acceptance Fixture

This document defines the real-host acceptance gate for the File Provider portion of
[the macOS capability contract](macos-capability-probes.md).

## Fixture Shape

The tracked Xcode project has two targets:

- `DiskplanFileProviderFixture`, an `LSUIElement` host used only for setup, evidence probes,
  oracle control, status, assertion, teardown, and manifest recovery; and
- `DiskplanFileProviderFixtureExtension`, an embedded replicated
  `NSFileProviderReplicatedExtension` with the `com.apple.fileprovider-nonui` extension point.

Both targets use `group.com.joeyteng.diskplan.fileprovider-fixture`. The extension bundle ID
has the host bundle ID as its prefix. Neither entitlement file contains
`com.apple.developer.fileprovider.testing-mode`; the hidden per-run domain also sets
`testingModes = []`.

Every run uses one random UUID and exact domain ID `diskplan-fixture-<uuid>`. The immutable
recovery manifest is written before the domain is added. A separate `ready.json` overlay is
written only after the system resolves the provider-visible sentinel and sealed-directory URLs.
Both records and the callback oracle live in the owner-private App Group path `runs/<uuid>`.
Oracle JSONL is opened no-follow with append/create/close-on-exec flags, mode `0600`, and an
exclusive advisory lock. Events contain a lock-assigned sequence, run/domain/item identity,
callback kind, PID, monotonic timestamp, and request flags.

Manifest, ready, window, and event reads bind owner-private directory and regular-file
descriptors with no-follow/nonblocking flags. They enforce byte ceilings, take a shared lock,
and revalidate endpoint identity and access policy before returning. Immutable control records
also revalidate size and modification/change timestamps as content-stability signals. A missing
record, an unreadable record, and an identity/access/content mismatch remain distinct typed
results; malformed or semantically inconsistent JSON is a mismatch rather than “missing.”

## Acceptance Property

The protected property is no content materialization or provider-side mutation while Diskplan
collects metadata for a provider-owned dataless item. The gate requires all of these facts:

1. The host installs and re-reads `IOPOL_MATERIALIZE_DATALESS_FILES_OFF` before path access.
2. `sentinel.txt` and `sealed-dir` both retain `SF_DATALESS` before and after the evidence probe.
3. The descriptor-relative `FileProviderBoundaryProbe` returns the exact fixture domain
   identity and report-only handling. The sealed directory returns
   `doNotDescendDataless`.
4. A postflight root-enumerator signal inside the still-open window produces a new allowed
   callback, proving that the extension can append to the selected run log after both probes.
5. The window contains zero `fetchContents`, create, modify, delete,
   `materializedItemsDidChange`, or sealed-directory enumeration events.

Root and working-set enumeration plus item metadata callbacks are allowed. The sentinel's
`fetchContents` path writes deterministic 64 KiB contents to
`NSFileProviderManager.temporaryDirectoryURL()` before completing. Therefore a future negative
control can prove real materialization rather than passing because fetch is a stub.

Both provider/path postflight probes and the oracle-health barrier run before the window closes.
After closure, assertion reads only the immutable sealed snapshot; it never touches the provider
path. The window closes only after the JSONL sequence/count fingerprint remains
unchanged for a continuous two seconds, within a 30-second total bound. Each timestamp is taken
after the fingerprint read and its locks complete, and the total deadline is checked before
quiet success. Time spent reading is never credited as silence, and quiet cannot pass at the
timeout boundary. An independent run-scoped attempt gate holds a shared lock from callback record
entry through any failure-marker publication. Health, fingerprint, final closure, and sealed
snapshot reads take its exclusive lock with the same absolute deadline. At quiet success, the
recorder lock checks healthy state and publishes a persistent sealing transition before final
exclusive-gate acquisition. That transition keeps not-yet-admitted callbacks from racing the
seal. The exclusive attempt gate then waits for admitted records and their failure publication;
under the recorder lock, closure rechecks failure evidence, reads the final descriptor-bound
event snapshot, writes the closed window, and persists the seal. A changed fingerprint after the
transition, gate contention, or incomplete failure publication fails closed. No callback can
append or poison the recorder between that snapshot and acceptance. The persisted
close record binds its end timestamp, quiet interval, event count, and final sequence. Assertion
requires sealed state and rechecks that immutable fingerprint; malformed or internally
inconsistent close metadata fails as a typed semantic mismatch.

Oracle writes fail closed. A run-scoped recorder lock serializes all extension instances. Under
that lock, every append first creates and `fsync`s immutable `recorder-poisoned` evidence, then
appends and `fsync`s the JSONL event, and clears the marker only after the event is durable. An
append failure or a failure while initially persisting poison leaves evidence checked by existing
and recreated instances and by host health, closure, and assertion. The in-window oracle-health
barrier therefore cannot succeed after a hidden recording failure. Callback APIs with an error
result return the recording error, and enumeration fails its observer. The
`materializedItemsDidChange` callback has no error channel, so it always invokes its completion
handler even if recording fails. Before that completion, every non-sealed `record` failure also
durably creates an immutable `recorder-failed` marker outside the recorder lock. This covers
local-lock timeout, deadline expiry, state-read failure, and append/poison failure; successful
append cannot clear that marker. Host health, closure, and sealed-snapshot assertion all interpret
it as poisoned, so the callback-only API cannot turn a recording failure into callback-zero. The
record attempt retains its shared attempt-gate lock until this immutable failure marker is
durable; therefore closure cannot observe healthy state and return a sealed snapshot while
failure publication is still in flight. Each admitted attempt also creates and directory-syncs
a unique `recorder-incomplete-attempt-<uuid>.marker` before running callback logic. It removes
that marker descriptor-relative only after either the JSONL event or the immutable failure marker
is durable. A crash or failure while publishing `recorder-failed` therefore leaves persistent
incomplete-attempt evidence. Exclusive health, closure, and sealed-snapshot reads treat any such
marker, or an over-limit run-directory inventory, as poisoned. Record-internal state and append
ignore these markers while holding the shared attempt gate so concurrent live attempts do not
poison one another.

The attempt, recorder, and nested JSONL locks all use nonblocking `flock` acquisition and share
the same absolute 30-second monotonic deadline for an append. Lock contention cannot turn a
provider callback or closure into an unbounded wait, and a timeout after write-ahead poison
remains visible as poisoned state. The in-process recorder lock is also acquired with bounded
`tryLock` polling; one entry deadline is passed unchanged through attempt admission, local
locking, state read, append, poison, and failure publication. Every filesystem lock checks that
deadline before each attempt and immediately after acquisition.

Extension append opens only the already-existing owner-private run directory and pre-created
recorder lock; it never prepares or recreates the run. Teardown writes an immutable
`recorder-sealed` marker under that lock before domain removal, so late callbacks fail without
creating an orphan App Group path.

## Acceptance Levels

The current fixture is a **probe-level gate**. It executes `FileProviderBoundaryProbe` against
the controlled placeholders and proves the primitive metadata/evidence path is report-only and
does not invoke dangerous provider callbacks. Its result explicitly reports
`scanner_acceptance: not-run`.

The later scanner acceptance hook must invoke the real `scan -> plan` engine entrypoint while
this same oracle window is open, assert that the fixture items appear only as report-only plan
evidence, and then apply the same callback-zero and dataless postconditions. A generic shell
command hook is intentionally not accepted as a substitute because it would not bind the tested
binary, IPC schema, or plan result.

## Lifecycle and Recovery

Compile without signing or File Provider registration:

```bash
scripts/fileprovider-fixture.sh build-unsigned
```

Run the complete signed lifecycle only on `India-mac-mini-m4-hoteng`:

```bash
DISKPLAN_RUN_FILE_PROVIDER_FIXTURE=1 scripts/test-macos-capabilities.sh
```

The lifecycle writes the immutable UUID recovery manifest first, registers one exact embedded
`.appex`, and verifies that `pluginkit` elects that exact bundle ID from the physical path of the
current embedded extension. It then adds one exact hidden UUID domain, writes the ready overlay,
opens the oracle, runs two Diskplan provider probes, proves postflight oracle health, waits for
bounded event quiescence, asserts only the sealed control data, removes that exact domain with
mode `.removeAll`, waits until it is absent, unregisters that exact `.appex`, polls until the
registry no longer references that physical extension path, and removes only the UUID paths
named by the validated manifest. Registry add/remove mutation and convergence checks are each
bounded. A timeout or stale exact-path registration fails closed and retains the manifest and
build artifacts for recovery.
The shell holds one nonblocking, host-and-user-global advisory lock across the entire build,
registration, domain, assertion, cleanup, or recovery lifecycle. Concurrent runs therefore
cannot unregister the shared extension bundle out from under one another; a crashed holder
releases the kernel-owned lock so the next explicit recovery can proceed.
`pluginkit` output must be strict UTF-8. Every exact-bundle registry block must use a recognized
header and contain exactly one absolute `Path`; missing, duplicate, empty, relative, or otherwise
malformed records or text that mentions the exact bundle fail closed instead of being interpreted
as successful removal.

All File Provider add, list, remove, signal, and user-visible-URL callbacks share one monotonic
20-second deadline per lifecycle phase. The one-shot gate owns that deadline and compares its
clock while holding the same lock that claims callback completion. Therefore a stale
precomputed comparison cannot let a late callback win merely because the timeout task was
delayed; a daemon that never replies or replies late cannot hang the host or resume a
continuation twice.

Callback admission and the sealing cutoff share the recorder attempt gate. A live extension opens
its run-directory, attempt-lock, and append-only admission descriptors before accepting callbacks;
failure to establish that capability terminates the extension instead of creating an unwitnessed
callback path. Every callback first durably appends a unique admission token. Successful event
append or durable failure publication resolves it. Sealing appends a durable cutoff while holding
the exclusive gate and rejects any unresolved token admitted before that cutoff; records proven to
start after the cutoff cannot change the immutable snapshot. Failure publication uses the same
absolute callback deadline and a dedicated thread, so a blocked failure path cannot hold callback
completion indefinitely or be mistaken for callback-zero.

The final oracle snapshot is descriptor-bound to one verified run-directory object. Attempt lock,
recorder lock, events, window, state markers, and sealed snapshot use that held descriptor and
revalidate canonical path identity and access policy before success. The events and window leaves
are opened and double-read while the recorder lock is held, then both held descriptors, their exact
canonical entries, and the run-directory identity are revalidated after the read. The window
durably seals the exact event bytes with SHA-256, byte count, file identity, and access policy, so
equal count/last-sequence rewrites cannot pass. The protected properties are object identity
(`st_dev` plus `st_ino`) and owner-only access policy (uid, type, mode, and absence of an extended
ACL); child-entry churn is deliberately not treated as replacement. The closed window is written
and fsynced, atomically renamed, and followed by a run-directory fsync before the sealed marker is
published.

Acceptance validates every sealed event rather than filtering unexpected identities: run ID,
domain ID, boot-session generation, exact sequence `1...N`, structure, and window membership must
all match. The open and closed window carry the same boot-session generation. A reboot therefore
invalidates the old window even if a producer PID is reused. Enumerator JSONL parsing requires an
empty file or exactly one terminal LF, rejects empty frames, requires the exact top-level key set,
and rejects duplicate or unknown keys.
Its structural scanner enforces a small explicit nesting bound before Foundation decoding, so a
bounded-but-deep tampered event cannot exhaust the call stack.
acquisition is itself recorded. Acquisition, item enumeration, change enumeration, or sync-anchor
access for `sealed-dir` is forbidden evidence, and enumerators strongly retain the minimal
recording capability so extension instance teardown cannot create a silent callback path.

Before `NSFileProviderManager.add`, domain removal, or either non-cancellable `pluginkit`
mutation begins, the Host durably publishes a UUID-and-operation-scoped ambiguity journal beside
the run directory and advances the host-global pending-run gate to `dispatched`. Both records bind
the exact run, domain, host and extension bundle identities and physical paths, operation UUID,
mutation kind, lifecycle provenance, and boot-session generation. The original callback or
`pluginkit` process then durably records `original-succeeded` or `original-failed`; a timeout,
forced process-group cleanup, output-capture uncertainty, or process death leaves `dispatched`.
The journal and global gate use file and parent-directory durability barriers. Their update order
is intentionally fail closed: dispatch reaches the gate first, completion reaches the operation
record first, and resolution first publishes a gate without the resolved entry while retaining
the operation record until the next durable step.
Removal retries carry a bounded, exact summary of every predecessor that was dispatched or
authoritatively succeeded without a final exact-absence observation. If a crash occurs after
successor state B is durable in the gate but before its per-kind leaf replaces predecessor A,
recovery recognizes only the exact persisted A-to-B relation. A prepared or failed B cannot make A
inactive: the host-global gate and per-run evidence remain until a successor is durably dispatched,
authoritatively completes, every same-boot dispatched predecessor has an operation-ID-attributed
completion, and exact absence is observed after those completions. A reboot is the only ordering
barrier for a predecessor whose authoritative completion remains unknown. Legacy immediate-
predecessor records are recursively flattened, terminal failures are pruned only after their durable
completion is merged, duplicates must agree, and the complete cohort is capped at 64 operations.
When a prepared or authoritatively failed leaf still carries active predecessors, successor
publication also carries that non-active leaf as an exact merge tombstone. Recovery prunes the
tombstone only after the old leaf has successfully merged, so a gate-durable/leaf-overwrite crash
cannot turn a valid predecessor chain into an unrelated-operation mismatch.
This also keeps a timed-out PlugInKit removal from an older run from later unregistering the shared
extension path after a newer run starts. Unrelated operation UUIDs remain a typed mismatch.

Mutation-journal reads protect object identity (`st_dev`, `st_ino`, and `st_gen`),
owner/group/mode/ACL access policy, and exact JSON bytes as separate properties. Size, mtime, or
ctime drift triggers bounded reread/restat. The reader finishes all held-descriptor byte, metadata,
and ACL checks before one final `fstatat` canonical-name seal; no descriptor-only observation follows
that seal. Equal bytes on the same object with the same access policy are accepted. Byte drift,
identity replacement, policy drift, missing canonical entry, unavailable lookup, and an unstable
final revalidation window retain distinct typed results.

Same-boot absence polling is never terminal evidence for an unresolved add. Even an
authoritatively completed compensating removal cannot clear an earlier add whose original
completion is still unknown, because the non-cancellable add may succeed later. Recovery reports
`unresolved_external_mutation`, retains the manifest and gate, and every later acceptance remains
blocked for that boot. An original failure clears the add; an original success followed by an
authoritative exact-state observation can proceed normally. A changed
`kern.bootsessionuuid` is the platform-backed ordering barrier for a lost original completion.
After reboot, recovery re-observes the exact domain or embedded extension path: absence clears the
old add directly, while presence requires a newly dispatched, authoritatively completed remove
and a final exact absence observation. No fixed grace period substitutes for this ordering.

Before signed build or allocation of a new run UUID, while the shell lifecycle lock is still held,
a separate descriptor-pinned preflight enumerates the owner-private App Group `runs` root. Any
remaining child blocks new acceptance: successful cleanup leaves this fixture-owned directory
empty, so this conservative rule also catches malformed run names and interrupted publication
temporaries. Endpoint identity, owner-only access policy, and absence of extended ACLs are
revalidated across enumeration. Cleanup refuses to remove the manifest while any mutation or
pending-run evidence for that run remains.
The shell lifecycle is additionally serialized by an owner-private global lock. Only the
inherited descriptor for the open-file description that actually holds that exact lock is
accepted as the helper capability; a caller-provided boolean environment variable cannot bypass
single-flight execution. The shell consumes that descriptor immediately after validation, clears
the environment capability, and verifies that the helper parent still owns the lock. Nested or
detached lifecycle children therefore cannot reuse or pin the capability.

The initial canonical manifest is atomically published and durably synced before any extension or
domain mutation. Run-directory creation, manifest publication, and recorder initialization form a
transaction: before manifest publication, an initialization failure removes only the known
descriptor-inventoried recorder files and the manifestless UUID directory; after publication, the
normal manifest recovery path owns the run. The shell installs its recovery trap before prepare
and can explicitly recover a retained unpublished transaction. Recorder initialization precreates
and fsyncs the empty `events.jsonl` entry and then fsyncs the run directory before any callback can
append, so a first-event fsync cannot be separated from its durable name while poison evidence is
cleared. Cleanup recovery preserves a deterministic sibling manifest until the staging
directory removal and canonical-parent fsync are durable. Existing sibling evidence is freshly
synced before reuse; restored canonical evidence is fsynced before rename-back and the parent is
fsynced before sibling deletion. Protected directories, control leaves, mutation journals, and
recovery evidence reject extended ACL grants or unreadable ACL state.

It never performs bulk domain removal and never deletes paths under the user-visible File
Provider storage location. If the lifecycle fails, it retains the owner-private manifest and
prints an exact recovery command:

```bash
scripts/fileprovider-fixture.sh recover '/absolute/app-group/runs/<uuid>/manifest.json'
```

If a process crash occurs after cleanup has renamed the UUID directory, the same production
entrypoint also accepts only the exact sibling manifest and maps it to the deterministic staging
directory:

```bash
scripts/fileprovider-fixture.sh recover \
  '/absolute/app-group/runs/.manifest-recovery-<uuid>.json'
```

Recovery never executes `appPath` from an untrusted manifest. It first verifies the known
DerivedData host and embedded extension as physical nonsymlink artifacts, validates both code
signatures, both exact bundle IDs, and team `XCTTZ89923`, and only then asks that known host to
securely load the manifest. The manifest build paths must equal those already trusted artifacts.
Recovery removes only the exact domain, unregisters only that exact embedded extension, and
then removes only the App Group UUID run directory. A sibling recovery manifest is accepted only
when its exact lowercased UUID path, lifecycle provenance, operation UUID, embedded manifest bytes
and digest, expected App Group run path, deterministic `.cleanup-<uuid>` staging path, and the
pre-rename staging device/inode/generation/access-policy binding all agree. Recovery revalidates
that persisted binding before inventory, after deletion, and immediately before final unlink;
replacement retains both recovery evidence and unrelated staging content. If the exact domain
still exists, the
host must seal the recorder in that staging directory before removal. Teardown sealing is
idempotent across recovery runs: an existing sealed state reuses its single durable admission
cutoff, and a clean sealing-plus-cutoff crash intermediate can be completed without appending a
second cutoff. Missing or mismatched
staging state fails closed. The Host rejects noncanonical manifest strings before constructing
the lifecycle request. The support layer then opens the recovery file by its exact basename from
a descriptor for the trusted expected App Group `runs` parent; it never opens a caller-supplied
parent path. Symlink plus `..` aliases therefore fail before status, build-path reads, teardown,
or cleanup can consume manifest bytes.

Cleanup protects object identity and owner/group/mode/ACL access policy for every held descriptor.
Regular files additionally protect descriptor bytes with two stable SHA-256 passes before deletion,
and regular control reads compare exact bytes when metadata triggers a revalidation. Size, mtime,
and ctime changes are revalidation triggers, not content proof: unchanged bytes remain acceptable,
a byte change is `contentChanged`, and owner/group/mode/ACL drift is separately `accessPolicy`. Directories
deliberately do not compare mtime/ctime after child deletion because child-entry churn is benign for
the protected property.
The run root must be on the same device as its held parent, and every directory descent must
remain on that root device. A mount point or any directory whose device cannot be proven equal
fails closed before inventory, so cleanup never traverses or deletes a mounted volume.
The exact UUID directory is atomically renamed with exclusive semantics inside the held
owner-private `runs` directory before recursive deletion; symlinks and special objects fail
closed. The held parent directory is fsynced immediately after that staging rename and before
inventory or any deletion, so a crash cannot expose a partially deleted tree under an undurable
name transition. Before that rename, cleanup durably creates and validates the sibling recovery record
`.manifest-recovery-<uuid>.json` outside the staging directory. It remains present while the
staging tree, its manifest, and the staging directory itself are removed. After final `rmdir`,
cleanup `fsync`s the held parent directory before it validates and unlinks the sibling evidence.
A crash before that ordering completes therefore leaves a deterministic owner-private manifest
path outside the partially deleted tree; production recovery can safely finish either a partial
staging tree or the already-removed staging state. On an ordinary failure, cleanup recreates and
directly validates `manifest.json`,
restores the original UUID directory name, and then removes the sibling record. Any recovery or
evidence-cleanup failure is an explicit retained-state error, never discarded with `try?`.
These are point-in-time replacement checks and do not claim
to exclude a malicious same-UID process that races after the final identity check.

The device-boundary contract has a deterministic synthetic-device unit test. Creating and
mounting a real filesystem inside the task-scoped run directory requires privileged mount
operations and is intentionally not attempted by the ordinary local test suite.

## Signing Gate

The unsigned build is the local compile gate. Real acceptance requires an Apple Development
identity plus host and extension provisioning profiles for team `XCTTZ89923` that authorize the
shared App Group. The India host currently has the identity but may not have those profiles.
When Xcode reports that condition, the script exits with code 78 and structured reason
`provisioning-profile`; it does not reinterpret the result as a File Provider failure.

Set `DISKPLAN_ALLOW_PROVISIONING_UPDATES=1` only when provisioning updates have been explicitly
authorized for that host.
