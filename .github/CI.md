# Foundation CI Maintenance

`foundation-ci.yml` separates the release gate from compatibility evidence:

- `Required / macOS 26 Apple Silicon` is the blocking foundation gate. It uses
  the explicit `macos-26` arm64 label and validates the complete Swift/Rust
  foundation on the Xcode version pinned in `scripts/ci/toolchain.lock`. The
  runtime assertion requires macOS 26 exactly; macOS 27+ remains best effort
  until promoted by the accepted release policy.
- `Best effort / macOS 14 deployment compatibility` is non-blocking. It verifies
  the Rust launcher still records a macOS 14 deployment target while that public
  runner remains available.

GitHub's hosted-runner reference listed `macos-26` and `macos-14` as standard M1
labels on 2026-08-28:
<https://docs.github.com/en/actions/reference/runners/github-hosted-runners>.
The image inventory is maintained at
<https://github.com/actions/runner-images/blob/main/images/macos/macos-26-arm64-Readme.md>.
The first repository run must still confirm the selected labels and Xcode path
in this repository. GitHub has announced that the macOS 14 image will be removed
after 2026-11-02, so remove or replace only the best-effort job when that happens.

## Immutable action pins

The workflow uses full commit SHAs. Version comments are review aids, not
authority.

| Action | Version | Commit |
| --- | --- | --- |
| `actions/checkout` | `v7` | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/cache` | `v5.0.5` | `27d5ce7f107fe9357f9df03efb73ab90386fccae` |
| `actions/upload-artifact` | `v7.0.1` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |

## Release CI

`release-ci.yml` adds a separate required macOS 26 Apple Silicon release lane.
It validates release scripts, builds the Rust launcher and Swift engine into a
deterministic arm64 archive, exercises the complete versioned install lifecycle,
and uploads only the archive plus its SHA-256 sidecar. The best-effort macOS 14
lane builds both components and retains the initial deployment-target evidence;
it does not gate release.

The release workflow uses the same immutable `actions/checkout` and
`actions/upload-artifact` pins listed above. The uploaded archive is already
compressed, so artifact transport uses compression level zero.

To update an action, resolve its release tag from the action's official GitHub
repository, review the release and runtime requirement, replace the full SHA,
and update the adjacent version comment plus this table in the same change.

## Tool pins and caches

`scripts/ci/toolchain.lock` pins Xcode, Rust, Protobuf, ShellCheck, actionlint,
download checksums, and the SwiftProtobuf source revision. The bootstrap script
also checks the shared `proto/toolchain.lock` and `Package.resolved` pins before
installing generators. SwiftPM resolve, build, and test commands use
resolved-only mode. A content-stability guard verifies the exact
`Package.resolved` bytes before and after every such command, including failure
paths; a same-byte file replacement is intentionally benign. The nested
SwiftPM calls in `scripts/canonical-fixture.sh` and
`scripts/test-cross-language.sh` also pass `--disable-automatic-resolution`, so
the digest guard is not the first barrier against dependency resolution.

Only Cargo and SwiftPM dependency downloads are cached. Compiled targets,
generated sources, test results, and tool downloads are not cached. `Cargo.lock`,
`Package.resolved`, checksummed downloads, source-revision checks, and drift
tests remain authoritative even when a cache is restored. The cache key binds
both dependency manifests, both resolved lockfiles, the protocol toolchain lock,
and the CI toolchain lock, after an explicit `Package.resolved` preflight.

The required job checks whitespace against the exact event SHA pair. Pull
requests use base/head SHAs, pushes use before/after SHAs, new branches map the
all-zero before SHA to Git's empty tree, and manual dispatch checks the selected
revision as a complete tree. Ref names and shell evaluation are not accepted.

On failure, CI uploads only a small allowlisted runner/toolchain manifest for
seven days. Each command probe has a one-second wall-clock deadline and a
1 KiB output allowance enforced while its merged output is read; excess output
or a timeout terminates the probe process group before the bounded result is
appended. Normal completion also retains the unreaped leader as a PID/PGID
identity fence until any same-group background processes are terminated and the
group is quiescent. The private same-directory temporary manifest has a
separately enforced 16 KiB total ceiling and is atomically published only after
final validation. CI does not upload source trees, dependency stores, build
products, process dumps, or unrestricted logs.
