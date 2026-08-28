---
id: 20260828-8f4c1a
title: Runtime Evidence Collectors
status: active
created: 2026-08-28
updated: 2026-08-28
branch: wip/runtime-collectors
pr:
supersedes: []
superseded_by:
---

# Runtime Evidence Collectors

## Summary

- `DiskplanScan` now has an injectable production collector bundle for one bounded normalized
  `lsof -nP -F0pcfn` snapshot plus public VM, swap, and APFS snapshot facts.
- Every collector retains `known`, `absent`, `unknown`, `unreadable`, and `failed` as distinct typed
  observations. Canonical sorting and deduplication make injected and production results independent
  of collector completion and kernel enumeration order.
- Process activity is classified as open file, current working directory, or mapped image and mapped
  to candidate ancestors using raw absolute path bytes and component boundaries.

## Current State

- The process runner rejects an already-expired absolute monotonic deadline before spawn and applies
  that deadline plus a 64 MiB default aggregate stdout/stderr ceiling to the supervised process.
  `posix_spawn` atomically places the fixed local `/usr/sbin/lsof` executable in a new process group;
  the synchronous spawn syscall itself is an accepted non-interruptible platform boundary. Deadline,
  output-limit, and task-cancellation paths share one idempotent TERM-to-KILL cleanup state machine.
  A fixed supervisor hard deadline closes inherited readers instead of waiting indefinitely for
  descendant-held EOF and reports whether a residual process group was still observable.
- Production process snapshots use `lsof -nP -Di -F0pcfn`. `-Di` disables the device cache, and the
  spawn shim receives only an explicit deterministic `LANG`, `LC_ALL`, and `PATH` environment. It
  does not inherit `HOME`, `LSOFDEVCACHE`, temporary-directory overrides, loader overrides, or other
  variables that could redirect cache or diagnostic writes.
- A zero exit with any standard-error output is typed as degraded coverage rather than complete.
  Positive process references remain available to block cleanup, while empty ancestor matches are
  unknown and cannot authorize negative-evidence staging. The supervisor retains only the bounded
  standard-error byte count; diagnostic content is neither retained nor projected into reasons.
- Launch classification comes from the actual spawn error domain and recursively discovered
  underlying POSIX error. `ENOENT` is absent, `EACCES`/`EPERM` is unreadable, and all other launch
  failures remain failed; no pathname executability preflight is used.
- VM facts use `host_statistics64`; swap facts use `sysctlbyname("vm.swapusage")`; snapshot facts use
  descriptor-relative `fs_snapshot_list` with bounded records and raw snapshot-name bytes.
- Snapshot collection borrows dedicated, already-open volume-root descriptors. Its protected property
  is the descriptor-bound filesystem object identity: pathname replacement is irrelevant after the
  descriptor is supplied. The collector changes only that dedicated descriptor's enumeration offset.
- No collector opens candidate paths, reads candidate contents, requests File Provider coordination,
  or changes the process materialization policy. Scan-path metadata churn therefore cannot be
  misclassified as object replacement by this slice.
- Injectable unit coverage was added for normalized process invocation, deadline/limit/permission
  distinctions, cancellation/group cleanup, descendant-held EOF, the aggregate output cap, complete
  macOS mapped-descriptor forms, raw ancestor boundaries, VM overflow, swap coverage, snapshot buffer
  bounds, bundle canonicalization, and per-volume snapshot coverage.
- macOS mapped-image descriptors include `txt`, `mem`, `mmap`, `ltx`, and hexadecimal `M...` forms.
- Process supervision now has a package-internal closed backend interface for monotonic time,
  scheduling, group signals, group liveness, reader closure, and reap delivery. The public runner
  always constructs the real POSIX backend; public production callers cannot inject an alternate.
  Deterministic tests drive the same state machine without OS processes and assert exact TERM,
  grace, KILL, and hard-finish deadlines, quiescent/reaped completion, retained-reader closure, and
  typed residual reporting. Separate production-runner fixtures retain real `posix_spawn` `ENOENT`
  and non-executable permission coverage without a recording runner.

## Next Steps

- Integrate `ProductionScanCollectorBundle` at engine scan setup and project its richer typed global
  facts through IPC in the schema-owned workstream; this branch intentionally does not edit proto,
  generated sources, policy, Rust/TUI, or execution adapters.
- Freeze the integration branch head and run the broader release checkpoints defined by the accepted
  plan after the schema-owned and engine-owned workstreams have consumed this collector seam.

## Evidence

- `swift test --no-parallel --filter DiskplanScanTests` passed 56 of 56 Swift Testing tests,
  before the process-supervisor advisory pass. After that pass,
  `swift test --no-parallel --filter DiskplanScanTests` passed 60 of 60 tests.
- The focused advisory filter covering normalized F0 parsing, launch error mapping, descendant-held
  EOF, task cancellation, and aggregate output limiting passed 8 of 8 tests. The three process-group
  fixtures completed their bounded cleanup with no reported residual group.
- The final `swift test --no-parallel` passed 353 of 353 Swift Testing tests with zero XCTest
  failures after the first supervisor review. After the zero-write and degraded-coverage pass, the
  final serial full gate passed 355 of 355 tests.
- After adding the public snapshot syscall shim's typed-error test,
  `swift test --no-parallel --filter DiskplanMacOSTests` passed 34 of 34 tests. The only delta after
  the full gate was this test-only coverage.
- `swift-format lint --strict` passed for every changed Swift source and test file.
- `git diff --check` passed.
- Tests used injected collectors or invalid descriptors only. No live `lsof` process, real APFS
  snapshot enumeration, APFS mutation, candidate-content read, or File Provider materialization was
  performed.
- The process-supervisor fixtures launch only test-owned `/bin/sh`, `sleep`, and `/usr/bin/yes`
  processes. No real `lsof` or user-data path is used; a post-gate process query found no surviving
  test executable or test bundle.
- The focused zero-write and degraded-coverage filter passed 10 of 10 tests, including the actual
  sanitized `/usr/bin/env` child environment and all three bounded process-group cleanup fixtures.
  `DiskplanScanTests` passed 62 of 62 and `DiskplanMacOSTests` passed 34 of 34. A post-gate process
  query found no surviving `env`, `sleep`, `yes`, or test-bundle process.
- The two exact fresh follow-up fixtures passed 2 of 2 tests. The expanded collector/activity filter
  passed 17 of 17, including a second TERM-ignoring group run. No additional full gate was requested;
  the production code remained unchanged from the 355-of-355 serial full gate above. A post-gate
  process query found no surviving fixture script, task-scoped fixture path, `sleep`, `yes`, or test
  bundle process.
- A real TERM-ignoring fixture previously passed its exact 1-of-1 and related 2-of-2 filters with no
  residual process, but final review rejected PID/PGID watchdogs as an unsafe test-harness boundary.
  That fixture and its product launch-observer hook were removed. The replacement deterministic
  state-machine tests are statically implemented. Fresh static review then identified terminal-claim,
  late-timer, fake-clock, and coupled-event gaps. The follow-up makes terminal selection and cleanup
  generation claims atomic, rejects delayed cancelled-timer handlers before signaling, preserves
  monotonic overdue delivery, and independently drives liveness, reap, and reader EOF. It adds normal
  pre-deadline completion, TERM convergence, delayed timer delivery, retained-reader hard finish,
  and parent-reaped/descendant-residual coverage. The same fresh reviewer found all four findings
  closed with no new P0-P2. A narrower concurrency audit then identified two additional P2s: an
  already-expired deadline still reached `posix_spawn`, and a failed `waitpid` was collapsed into an
  ordinary exit status. The runner now rejects stale work before spawn, while the backend and state
  preserve a typed reap outcome and exact POSIX error through `supervisionFailed`. Reader callback
  installation, in-flight reads, and terminal close are additionally serialized inside the real
  backend, preventing a terminal close between stdout and stderr handler installation. The blocking
  reaper intentionally remains alive until the owned child exits because abandoning it can create a
  zombie; it holds only a weak state completion after the caller-visible hard deadline. The exact
  concurrency child re-reviewed the deadline, reap, reader installation, and lock-order changes as
  clean with no provable P0-P2. Dynamic execution was then performed only in the serialized slot.
- After the final supervision changes, the focused deterministic/real-bridge filter passed 15 of 15
  tests, `DiskplanScanTests` passed 73 of 73, and the serial full Swift gate passed 366 of 366. The
  toolchain was swift-driver 1.148.6 / Apple Swift 6.3.3 targeting arm64 macOS 26. A post-gate query
  found no surviving test bundle, shell/sleep, `yes`, or retired TERM-ignore fixture process.
