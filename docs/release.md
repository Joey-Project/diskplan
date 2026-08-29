# Release Packaging And Local Install

Diskplan publishes a versioned macOS arm64 archive containing the Rust `diskplan`
launcher, its sibling Swift `diskplan-engine`, a narrow native filesystem helper,
install lifecycle scripts, and deterministic identity metadata. The required
release build runs on Apple Silicon macOS 26. macOS 14 remains a non-blocking
deployment-compatibility build.

## Build

Run the release build from the repository root on an arm64 Mac:

```sh
scripts/release/build-release.sh /absolute/output/directory
```

The output contains:

```text
diskplan-<version>-macos-arm64.tar.gz
diskplan-<version>-macos-arm64.tar.gz.sha256
```

The packager first copies every executable through a no-follow file descriptor
into a private staging directory. Identity, architecture, platform, and minimum
macOS probes run only against those immutable staged bytes; the exact same bytes
are then archived. It rejects any product-version, protocol, arm64, Mach-O
platform, or minimum-deployment-target mismatch before publication.
`manifest.json`, `protocol.json`,
`VERSION`, and `SHA256SUMS` make the exact archive contents auditable. Tar entry
ownership, modes, ordering, and timestamps plus every gzip header field and the
compression level are pinned, so the same input bytes and source revision produce
the same archive bytes. The Swift release build maps its private random work root
to one logical source path and excludes debug STABS at link time, before the
linker derives the required Mach-O UUID and ad-hoc signature; random checkout
paths and object timestamps therefore cannot perturb the published engine.
Release packaging deliberately pins both the compile-time
and runtime zlib implementation to `1.2.12`; a toolchain change fails closed until
that reproducibility input is reviewed and updated. The archive and its checksum
sidecar are published as one verified output set using private, exclusive
temporary files.

`build-release.sh` accepts only a clean, stable source checkout. It binds the
manifest revision to the exact Git tree and revalidates tracked and untracked
build inputs before and after compilation. Release tags must be canonical SemVer
and exactly equal `v$(cat release/VERSION)`.

## Install, Upgrade, And Rollback

Extract the archive and run its installer without `sudo`:

```sh
shasum -a 256 -c diskplan-<version>-macos-arm64.tar.gz.sha256
tar -xzf diskplan-<version>-macos-arm64.tar.gz
diskplan-<version>-macos-arm64/install.sh
```

The checksum detects transport corruption; it is not a code-signing identity.
Developer ID signing and notarization remain deferred by the accepted plan.

The default layout is:

```text
~/.local/bin/diskplan
  -> ../libexec/diskplan/<version>/diskplan

~/.local/libexec/diskplan/<version>/
  diskplan
  diskplan-engine
  identity and lifecycle metadata
```

The installer verifies the exact file set, checksums, metadata, arm64 slices,
source access policy, and process identities before publication. Deterministic
tar headers use numeric root ownership; after an ordinary user extraction, the
source must be owned by that user and may use only numeric group `0` or the
caller's effective group. A restrictive extraction umask may remove group or
other permission bits, but it cannot add permissions or alter owner bits. The
native helper copies each no-follow descriptor into an owner-private staging
directory, explicitly normalizes the copy to the caller's uid/gid and exact
packaged mode, and revalidates type, owner, group, mode, link count, ACL, flags,
size, and content before publication.

The helper also holds no-follow descriptors for the complete managed ancestor
chain and for the managed `bin`, `libexec`, and `libexec/diskplan` child slots.
It reopens every child slot relative to its retained parent and
revalidates object identity, owner/group/mode/flags/ACL access policy, device,
filesystem identity, mount boundary, and security-relevant mount flags. An
ancestor or managed child replacement therefore fails closed before and after
publication, activation, and deletion. Bundle content proof
uses artifact identity, access policy, size, and SHA-256; mtime and ctime changes
only trigger one bounded reopen and rehash and are never treated as content
proof. The copy path applies the same rule: a timestamp-only transition during
copy triggers a bounded source reopen and digest comparison instead of rejection.
Access-policy flag proof uses an explicit immutable/append/restricted/data-vault/
no-unlink mask; benign `UF_HIDDEN` and `UF_NODUMP` churn is ignored. The helper
publishes a new immutable version with an exclusive
same-filesystem rename, proves the published directory is the verified staging
object, and conditionally replaces only the launcher leaf it observed. Existing
versions are retained. Roll back by activating one verified installed version:

```sh
~/.local/libexec/diskplan/<old-version>/activate.sh <old-version>
```

Remove one exact verified version without recursive cleanup. Deletion stays
descriptor-relative to the directory object that was verified, so a pathname
replacement cannot redirect it:

```sh
~/.local/libexec/diskplan/<version>/uninstall.sh <version>
```

Use `--prefix /absolute/path` with any lifecycle script for an isolated install.
The installer never calls `sudo`, modifies TCC, or removes an older version.

The Rust launcher opens the selected engine once with `O_NOFOLLOW`, binds its
object identity, access policy, bounded size, and SHA-256, then creates one exact
copy inside an owner-private launch directory. It retains and revalidates the
complete root-to-launch-directory descriptor chain, every parent/child slot,
mount/access signals, the snapshot descriptor, and the snapshot slot at the
actual internal spawn boundary. No caller can retain a naked `Command` pathname.
Restrictive ancestor flags such as `SF_NOUNLINK` are sealed into that identity
proof and must remain stable, but do not by themselves make traversal unsafe.
Operation-specific mutability checks distinguish changing a parent's child
namespace from renaming or removing the object itself. The temporary parent may
retain stable `SF_NOUNLINK` because Diskplan only creates and removes child
entries there, but immutable or append-only parent flags fail closed. The
private launch directory and snapshot must themselves remain mutable, so
`SF_NOUNLINK`, immutable, append-only, or other selected restrictive flags on
those objects are rejected. All selected flags remain exact-sealed across
revalidation; benign `UF_HIDDEN` and `UF_NODUMP` remain outside the
security-relevant flag mask.
Native macOS Mach-O execution through `/dev/fd/<fd>` is rejected with `EACCES`,
so the private snapshot pathname remains an internal implementation detail and
is revalidated immediately before and after the single operational `spawn()`.
The exact product/protocol identity probe and operational session both execute
that same retained snapshot. Digest reads consume at most the expected size or
the 512 MiB engine ceiling plus one byte and distinguish an oversize object from
a size mismatch. Launch-directory creation and cleanup do not use `TempDir`
pathname recursion: the launcher creates the private child through its bound
parent descriptor, then removes only the descriptor-bound snapshot and proved
parent slot. A mismatch retains the directory and emits a typed cleanup report.
Replacing the original engine pathname between launches cannot redirect
execution; unlink or hard-link drift separately invalidates the source one-link
policy.

## Release Tests

Validate an already-built archive with:

```sh
scripts/release/test-release.sh /absolute/path/diskplan-<version>-macos-arm64.tar.gz
```

The test uses task-scoped temporary roots and covers deterministic repackaging,
fresh and idempotent install, restrictive extraction-mode normalization,
sibling-engine launch, checksum rejection, upgrade, rollback activation,
protocol-major mismatch rejection, and exact uninstall. Its adversarial cases
cover symlinked prefix ancestors, replacement races, artifact mode drift, stale
lifecycle locks on the system Bash 3.2 runtime, launcher activation races,
hostile packager output leaves, engine probe-to-launch replacement, launch-chain
replacement and cleanup retention, managed-child and mount-boundary
revalidation, copy-time and proof-time timestamp-only churn, selected-flags
behavior, SHA-256 content drift,
closed-output timeouts, signal cancellation, and background descendants.

## India Host Acceptance

`scripts/release/india-acceptance.sh` is a host-local runner; it never connects to
another machine. It requires the exact `India-mac-mini-m4-hoteng` short hostname,
macOS 26, and arm64. The target cannot be overridden; in particular, the BL host
is never an alternate release target. `--describe` is the only host-independent
mode and prints the checked-in lane catalog without running a command.

The catalog at `fixtures/release/india-acceptance-v1.json` fixes lane order,
dependencies, capability names, required versus conditional status, deadlines,
and retained-output ceilings. The matrix covers:

- clean local-source/fixture identity at the exact bundle source revision;
- install and sibling-engine handshake;
- standard and bounded full-audit dry-run scans;
- scanner-level File Provider no-materialization;
- APFS clone/hardlink owner-graph and activity/open-handle/process snapshots;
- synthetic million-entry retention with performance, memory, and swap evidence;
- authoritative batch dry-run and integrated TUI pause/provisional/finalize/cancel;
- optional artifact persistence disabled and enabled.

Every external command runs under `run_bounded.py`. The supervisor owns a new
session and process group, enforces one monotonic deadline and output ceiling,
converts `HUP`, `INT`, and `TERM` into bounded TERM-to-KILL cleanup, and reports
success only after descendant quiescence. A lane receipt is canonical JSON with
the exact OS version/build, architecture, hardware model, product/protocol/source
identity, capability status, limits, command/output digests, and the complete
bounded-supervisor status. Lane status is one of `passed`, `unsupported`,
`skipped`, or `failure`.

The runner admits supervisor results only when their declared deadline/output
limits, process exit, process-group verification, quiescence, retained byte count,
and SHA-256 match the observed process and log. Batch output uses strict canonical
JSONL: duplicate keys, non-finite numbers, non-LF framing, and non-canonical
records fail the lane. Receipts include a privacy-safe resolved audit-root path
digest plus its device/inode/access-policy binding, an argv template with random
task and private source paths replaced by stable tokens, and SHA-256 identities
for the catalog and complete harness source set. The source-integrity lane also
requires the clean local Swift/File Provider sources and fixtures to match the
bundle revision and records the exact Git commit and tree. Every lane that builds
local Swift or File Provider code repeats the source seal immediately before and
after its command; a final required lane repeats the repository proof before the
summary.

`required` lanes block the release unless they pass. A `conditional` lane may be
`unsupported` only when its platform capability is absent; a failure still blocks.
The current probe-level File Provider fixture explicitly reports
`scanner_acceptance: not-run`, which the matrix classifies as unsupported rather
than accepting as scanner evidence. Likewise, a missing integrated artifact or
TUI acceptance seam cannot be inferred from unit-test success.

The runner installs into an owner-private task root created under the fixed local
`/private/tmp` parent. It rejects an audit root that contains that parent, so
changing harness state can never appear in the active scan. Existing user data is
passed only to standard/full-audit scan-to-plan dry-run commands with history and
audit files disabled:

```text
diskplan --batch --profile full-audit --dry-run --no-history --no-audit-file --root <path>
```

The batch parser accepts those options in any order, exactly once. It preserves
the root as raw platform path bytes and rejects relative roots, duplicate or
unknown options, other profiles, persistence, and mutation-capable combinations
with exit 64. Batch mode does not initialize a terminal.

Standard output is a bounded two-record NDJSON report. `batch_started` exactly
binds the `full-audit`, dry-run, no-history, no-audit-file request and hex-encodes
the raw root. It requests the engine-owned `safe-stageable-without-waiver`
selection preset; the Rust frontend never infers selections from dispositions.
A successful `batch_completed` record is emitted only after the
engine returns both an authoritative immutable-plan proof and dry-run outcomes
covering every action in an engine-acknowledged decision overlay with zero
mutation attempts. Plan and overlay carry separate nonzero SHA-256 bindings. A finalized scan,
including a scan with no observed candidates, is not an empty-plan success.
The engine proof must also report zero history and audit-file persistence
attempts; these are terminal proof fields, not parser-only switches.
The frontend accepts completion only when every authority transition repeats the
exact upstream binding: finalized scan session/checkpoint and evidence hashes,
plan projection/evidence/plan IDs and hashes, acknowledged overlay ID/revision/
hash, then dry-run plan/overlay references plus execution epoch, current-binding,
sealed projection-manifest, and revalidation hashes. Counts are supplemental and
cannot substitute for any binding. The scan checkpoint ID is the lowercase hex
encoding of the final evidence SHA-256; a merely nonempty opaque checkpoint
label is not accepted. Plan, overlay, and dry-run references each repeat the
complete scan session/checkpoint/checkpoint-evidence/final-evidence binding.
The summary keeps total plan actions separate from engine-authored cleanup
candidates. Overlay selection is bounded by the full plan action set, not by the
candidate count, because prerequisite-connected selections may add actions that
are not themselves cleanup candidates.

Batch exit statuses are stable: 0 means an authoritative dry-run completed; 64
is command-line usage; 65 is an incomplete or invalid engine result (including
scan-only); 69 means the sibling engine or authoritative batch protocol is
unavailable; 70 is an invalid sibling identity or engine protocol failure; and
74 is engine setup, report, or transport I/O failure. Interactive and handshake
startup failures retain their legacy status 1. Protocol 1.3
therefore fails closed with 69 until the protocol 1.4 batch adapter is available.
The sibling setup boundary classifies unavailable, invalid identity/protocol,
and other I/O failures as typed outcomes before selecting a batch exit status;
an `io::ErrorKind` cannot reinterpret a semantic identity rejection.
The India runner independently parses the retained NDJSON and rejects an empty,
scan-only, mutation-reporting, or internally inconsistent terminal record even
when the subprocess returned zero.
The validator parses the supervisor status, then reads the report exactly once
through a no-follow descriptor. A regular owner-private mode-0600 single-link
object is required; identity, size, access policy, and selected flags are sealed
with `fstat` before and after the bounded read. Its exact byte count and SHA-256
must match the supervisor's retained-output proof before NDJSON is parsed.

The command has an external wall-clock limit and a 1 MiB retained-output limit.
The supervisor owns a separate process group, converts `HUP`, `INT`, and `TERM`
into bounded TERM-to-KILL cleanup, and does not report success until descendants
are gone. Closing output early cannot bypass the monotonic deadline.
The normal report is printed to the shell. `--report <path>` is optional and a
failure to persist it, including `ENOSPC`, is reported but does not change a
successful acceptance result. This infrastructure intentionally exposes the
required CLI seam; the real-host gate cannot pass until the integrated frontend
implements that exact dry-run-only batch interface.
All mutation fixtures, build scratch paths, enabled artifact destinations, and
TUI state live under that task root. Every installed-product invocation receives
lane-private `HOME`, `TMPDIR`, and XDG roots, including install, handshake, and
real-data scans. The File Provider lifecycle keeps its global lock/App Group
recovery contract, but its DerivedData, package cache, and signed-build log are
explicitly redirected into the acceptance task root. Cleanup is
descriptor-relative, no-follow,
same-device, identity/access-policy checked, entry-count bounded, and time
bounded. A cleanup uncertainty fails the gate and reports the retained locator;
`--keep-task-root` is an explicit diagnostic opt-in. The signed File Provider
fixture remains governed by its separate durable recovery-manifest contract.
Termination signals remain handled through cleanup and summary publication; the
runner reports the signal and returns the conventional `128 + signal` status.
The File Provider fixture emits a canonical lifecycle-complete or
recovery-required receipt. Until completion is explicit, the harness retains the
entire task root containing the exact signed app/extension and prints both the
task-root locator and fixture recovery locator in the summary. The same receipt
binds the exact retained DerivedData root; the summary emits a machine-readable
recovery argv that reapplies that override for either manifest or run-ID recovery.
A completed lifecycle permits normal bounded cleanup even when the scanner-level
result is still unsupported.

The acceptance report is printed as JSONL to the shell. The harness deliberately
does not add its own report-file writer: product history and audit files are
validated through the enabled artifact lane and its File Provider-aware safe
writer contract. No harness-owned report file is required on a low-disk host.
