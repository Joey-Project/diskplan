# Release Packaging And Local Install

Diskplan publishes a versioned macOS arm64 archive containing the Rust `diskplan`
launcher, its sibling Swift `diskplan-engine`, install lifecycle scripts, and
deterministic identity metadata. The required release build runs on Apple Silicon
macOS 26. macOS 14 remains a non-blocking deployment-compatibility build.

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

The packager executes both binaries with `--version-json` and rejects any
product-version or protocol mismatch before it writes the archive. It also checks
that both Mach-O binaries contain arm64 code. `manifest.json`, `protocol.json`,
`VERSION`, and `SHA256SUMS` make the exact archive contents auditable. Tar entry
ownership, modes, ordering, and timestamps plus the gzip timestamp are normalized,
so the same input bytes and source revision produce the same archive bytes.

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
and the two process identities before publication. It stages a new immutable
version under the destination filesystem, publishes it while holding the
cooperating-installer lock, and atomically switches the launcher symlink. Existing
versions are retained. Roll back by activating one verified installed version:

```sh
~/.local/libexec/diskplan/<old-version>/activate.sh <old-version>
```

Remove one exact verified version without recursive cleanup:

```sh
~/.local/libexec/diskplan/<version>/uninstall.sh <version>
```

Use `--prefix /absolute/path` with any lifecycle script for an isolated install.
The installer never calls `sudo`, modifies TCC, or removes an older version.

## Release Tests

Validate an already-built archive with:

```sh
scripts/release/test-release.sh /absolute/path/diskplan-<version>-macos-arm64.tar.gz
```

The test uses task-scoped temporary roots and covers deterministic repackaging,
fresh and idempotent install, sibling-engine launch, checksum rejection, upgrade,
rollback activation, protocol-major mismatch rejection, and exact uninstall.

## India Host Acceptance

`scripts/release/india-acceptance.sh` is a host-local runner; it never connects to
another machine. It requires the exact `India-mac-mini-m4-hoteng` hostname by
default, macOS 26, and arm64. It installs into a task-scoped prefix, checks the
real sibling-engine handshake, and runs only this non-mutating real-data shape:

```text
diskplan --batch --profile full-audit --dry-run --no-history --no-audit-file --root <path>
```

The command has an external wall-clock limit and a 1 MiB retained-output limit.
The normal report is printed to the shell. `--report <path>` is optional and a
failure to persist it, including `ENOSPC`, is reported but does not change a
successful acceptance result. This infrastructure intentionally exposes the
required CLI seam; the real-host gate cannot pass until the integrated frontend
implements that exact dry-run-only batch interface.
