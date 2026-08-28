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
4. The setup enumeration leaves at least one allowed callback in the oracle before assertion,
   proving that the extension can append to the selected run log.
5. The window contains zero `fetchContents`, create, modify, delete,
   `materializedItemsDidChange`, or sealed-directory enumeration events.

Root and working-set enumeration plus item metadata callbacks are allowed. The sentinel's
`fetchContents` path writes deterministic 64 KiB contents to
`NSFileProviderManager.temporaryDirectoryURL()` before completing. Therefore a future negative
control can prove real materialization rather than passing because fetch is a stub.

The window closes only after the JSONL sequence/count fingerprint remains unchanged for a
bounded quiet interval. Polling is bounded by both a 50 ms cadence and an overall timeout;
there is no fixed sleep interpreted as quiescence.

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
opens the oracle, runs the Diskplan provider probe, waits for bounded event quiescence, asserts
the oracle, removes that exact domain with mode `.removeAll`, waits until it is absent,
unregisters that exact `.appex`, and removes only the UUID paths named by the validated manifest.

It never performs bulk domain removal and never deletes paths under the user-visible File
Provider storage location. If the lifecycle fails, it retains the owner-private manifest and
prints an exact recovery command:

```bash
scripts/fileprovider-fixture.sh recover '/absolute/app-group/runs/<uuid>/manifest.json'
```

Recovery never executes `appPath` from an untrusted manifest. It first verifies the known
DerivedData host and embedded extension as physical nonsymlink artifacts, validates both code
signatures, both exact bundle IDs, and team `XCTTZ89923`, and only then asks that known host to
securely load the manifest. The manifest build paths must equal those already trusted artifacts.
Recovery removes only the exact domain, unregisters only that exact embedded extension, and
then removes only the App Group UUID run directory.

Cleanup protects object identity and owner/group/mode access policy for every held descriptor.
Regular files additionally protect content stability. Directories deliberately do not compare
mtime/ctime after child deletion because child-entry churn is benign for the protected property.
The exact UUID directory is atomically renamed with exclusive semantics inside the held
owner-private `runs` directory before recursive deletion; symlinks and special objects fail
closed. The manifest is deleted last, and an ordinary failure restores the isolated directory
to its original path for recovery. These are point-in-time replacement checks and do not claim
to exclude a malicious same-UID process that races after the final identity check.

## Signing Gate

The unsigned build is the local compile gate. Real acceptance requires an Apple Development
identity plus host and extension provisioning profiles for team `XCTTZ89923` that authorize the
shared App Group. The India host currently has the identity but may not have those profiles.
When Xcode reports that condition, the script exits with code 78 and structured reason
`provisioning-profile`; it does not reinterpret the result as a File Provider failure.

Set `DISKPLAN_ALLOW_PROVISIONING_UPDATES=1` only when provisioning updates have been explicitly
authorized for that host.
