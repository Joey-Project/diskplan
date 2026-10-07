# Foundation CI Maintenance

`foundation-ci.yml` separates the release gate from compatibility evidence:

- `Required / macOS 26 Apple Silicon` is the blocking foundation gate. It uses
  the explicit `macos-26` arm64 label and validates the complete Swift/Rust
  foundation on the Xcode version pinned in `scripts/ci/toolchain.lock`. The
  runtime assertion requires macOS 26 exactly; macOS 27+ remains best effort
  until promoted by the accepted release policy.
- `Best effort / macOS 15 deployment target` is non-blocking. It builds the
  Rust launcher for arm64 and verifies that its Mach-O metadata records a
  macOS 15 minimum deployment target on the `macos-15` runner. This checks the
  build target; it does not exercise the launcher at runtime.

GitHub's hosted-runner reference lists `macos-26` and `macos-15` as standard
Apple Silicon labels:
<https://docs.github.com/en/actions/reference/runners/github-hosted-runners>.
The image inventories are maintained at
<https://github.com/actions/runner-images/blob/main/images/macos/macos-26-arm64-Readme.md>
and
<https://github.com/actions/runner-images/blob/main/images/macos/macos-15-arm64-Readme.md>.
The first repository run must still confirm the selected labels and Xcode path
in this repository.

## Immutable action pins

Workflow action references use full commit SHAs, except for the single
controlled first-party floating-major exception below. Version comments are
review aids, not authority.

| Action | Version | Commit |
| --- | --- | --- |
| `actions/checkout` | `v7` | `3d3c42e5aac5ba805825da76410c181273ba90b1` |
| `actions/cache` | `v5.0.5` | `27d5ce7f107fe9357f9df03efb73ab90386fccae` |
| `actions/upload-artifact` | `v7.0.1` | `043fb46d1a93c77aae656e7c1c64a875d1fc6a0a` |

The consumer workflows intentionally use
`JoeyTeng/codex-review-gate-action@v2` as a controlled first-party exception so
they automatically receive compatible v2 releases from the action publisher.
This exception applies only to that exact repository and major alias; every
other action remains subject to the full-SHA pinning rule. The audited v2.1.8
release resolved to commit `299c0fde3cdd921e8d756f792edc056afb0f2ec9` when this
consumer was installed. That SHA is release provenance, not a binding runtime
pin; the workflow runtime reference remains `@v2`.

For any other action, resolve its release tag from the action's official GitHub
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
