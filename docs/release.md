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
The selected output directory is itself a trust boundary: it must be owned by
the current effective UID, have no group/other write bits, and carry no extended
ACL entries. The packager retains its directory FD and revalidates that access
policy before conditional quarantine cleanup. This excludes other-UID namespace
writers from the documented final compare-to-`unlinkat` residual; an unsafe
output directory is rejected before any temporary output is created.

`release/bundle-contract.json` is the canonical package-input allowlist. It
names every bundle-relative path, exact mode, byte ceiling, role, compatibility
version, and source. The native install helper's tracked generated contract and
the shell verifier are checked against those same records. An unverified
`manifest.json` therefore cannot grant access to another path. The bundle
contains the executables and lifecycle files plus:

```text
protocol-version
runtime-capabilities.json
rules/
  builtin-v1.json
  user-policy-default-v1.json
proto/
  diskplan/v1/ipc.proto
  toolchain.lock
  fixtures/...
```

Each `manifest.json` artifact record binds its canonical relative `path`, exact
`mode`, `size`, SHA-256, `role`, and `compatibility_version`. The packager and
installer reject missing, changed, additional, symlink, special-file,
path-escape, duplicate, case-fold-colliding, or unsupported-schema entries.
Nested copy, proof, rollback cleanup, and uninstall remain descriptor-relative
and no-follow. Directory and archive metadata do not enter artifact content
digests; tar ownership, directory/file modes, mtime, and ordering are emitted
from the fixed contract, so source enumeration order, uid/gid, and timestamps
cannot perturb the archive.

Generated Swift/Rust protocol sources, build trees, `.git`, `.codex-tmp`, and
the local generated project-journal index are explicitly excluded. The shipped
`runtime-capabilities.json` declares optional history, saved-plan, audit, and
execution-record persistence with `default_enabled: false` and
`package_effect: declaration-only`; packaging never creates user history or
artifact data.

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

Exact and rollback cleanup bind creation/proof-time receipts, move the selected
object to an exclusive random quarantine name on the same filesystem, reopen it
without following links, and retain it on any identity, content, access-policy,
or mount mismatch. macOS does not expose an atomic compare-and-unlink-by-FD
operation. The final `unlinkat` therefore relies on the managed staging/version
directories being owner-private (`0700`) and exclusively controlled for the
lifecycle operation. As established by the accepted plan, malicious concurrent
namespace mutation by another process with the same effective UID is outside the
phase-one threat model; the helper does not claim to resist it. A deployment
that cannot provide this exclusive namespace must treat deletion as report-only.

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
another machine. It requires the exact `India-mac-mini-m4-hoteng` hostname by
default, macOS 26, and arm64. It installs into a task-scoped prefix, checks the
real sibling-engine handshake, and runs only this non-mutating real-data shape:

```text
diskplan --batch --profile full-audit --dry-run --no-history --no-audit-file --root <path>
```

The command has an external wall-clock limit and a 1 MiB retained-output limit.
The supervisor owns a separate process group, converts `HUP`, `INT`, and `TERM`
into bounded TERM-to-KILL cleanup, and does not report success until descendants
are gone. Closing output early cannot bypass the monotonic deadline.
The normal report is printed to the shell. `--report <path>` is optional and a
failure to persist it, including `ENOSPC`, is reported but does not change a
successful acceptance result. This infrastructure intentionally exposes the
required CLI seam; the real-host gate cannot pass until the integrated frontend
implements that exact dry-run-only batch interface.
