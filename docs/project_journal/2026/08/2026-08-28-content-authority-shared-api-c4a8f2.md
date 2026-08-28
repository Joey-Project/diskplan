---
id: 20260828-c4a8f2
title: Scanner Content Authority Shared API
status: completed
created: 2026-08-28
updated: 2026-08-28
branch: wip/runtime-evidence-enrichment
pr:
supersedes: []
superseded_by:
---

# Scanner Content Authority Shared API

## Summary

- Expose a package-scoped consumer capability without exposing raw descriptors,
  mutable authority facts, or request-ID construction.
- Keep descriptor binding, provider validation, session epochs, and registry
  ownership inside `DiskplanScan` so revalidation adapters do not duplicate the
  safety contract.

## Current State

- Only the scanner-owned session can bind a transferred descriptor to exact root,
  slot, access-policy, provider, and session-epoch observations. It atomically
  registers the request before returning an opaque closed ID, so no intermediate
  descriptor receipt can escape the session budget or drain lifecycle.
- The package consumer capability can only call `collect` with that opaque ID.
- Session close and epoch advance drain pending RAII descriptors. Receipt or ID
  replay, cross-session misrouting, provider uncertainty, and live authority
  drift fail closed.
- Cross-target positive-use coverage is paired with bounded compile-fail fixtures
  for request-ID construction, consumer construction, scanner-authority access,
  and external-package access.
- Fresh review found and closed an invalid intermediate-lifetime design: a bound
  but unregistered request could have pinned an FD outside the registry budget and
  drain lifecycle. Removing that intermediate capability made binding and
  registration one scanner-internal operation. The review also found and closed
  one exact expected-result string mismatch in the misroute test.
- Final fresh-context static review reports no P0-P3 findings. The compile-fail
  runner uses a private process group, bounded diagnostic retention, and bounded
  TERM/KILL escalation so compiler descendants cannot outlive a timed-out case.
- Dynamic compilation required the registry methods whose signatures mention
  file-private payload types to be file-private as well; this further narrows the
  surface without changing runtime semantics. The compile-fail harness now binds
  the module directory associated with its currently loaded test bundle plus the
  exact sibling C-module include directory; it has no stale default-build fallback.
  It accepts `setsid` `EPERM` only when Foundation already launched the wrapper as
  its own process-group leader.
- Focused and affected-target dynamic gates pass on Apple Swift 6.3.3: six content
  authority tests, two EngineCore API tests (including all four compile-fail
  fixtures), all 72 DiskplanScan tests, and all 40 RuntimePolicyAuthority tests.
  No harness compiler or wrapper process remained after the run.
- The final serial Swift suite passes all 423 tests. Final post-fix static review
  reports no P0-P3 findings after binding compile-fail module lookup exclusively
  to the currently loaded test bundle.
- The required macOS 26 PR gate later exposed a diagnostic-model weakness rather
  than an authority failure: three same-package compile-fail subprocesses returned
  nonzero status with empty merged output, while the harness had discarded
  termination reason, separate stdout/stderr, and capture/drain state. The
  remaining 456 tests were green.
- The follow-up harness records launch/setup errors, timeout, exit versus signal,
  status, bounded stdout and stderr, truncation, and drain completion separately.
  A compile-fail case is accepted only after a normal nonzero exit emits an LLVM-
  style access-control error on its exact `#sourceLocation` marker. Synthetic
  classifier coverage rejects empty stderr, timeout, signal, module lookup,
  stdout-only diagnostics, launch failure, truncation, and drain timeout. Dynamic
  validation also closed two portability gaps: the same-package compiler identity
  is read from the current SwiftPM build description instead of hard-coded, the
  description is retained through one held handle with a strict 16 MiB plus-one
  rejection boundary, and fixture arguments are type-correct so each fixture
  emits exactly one intended access-control error.
- Post-fix gates pass on Apple Swift 6.3.3: the focused harness passes two tests
  covering four real compile-fail fixtures plus thirteen synthetic rejection
  cases, the shared-authority API passes 2/2, `DiskplanScanTests` passes 72/72,
  and the serial full Swift suite passes 458/458.
- The next required macOS 26 run proved the semantic rejection and stderr EOF but
  exposed nondeterministic ownership of the empty stdout pipe. Because the macOS 26
  SDK exposes neither `pipe2` nor `SOCK_CLOEXEC`, the follow-up creates each capture
  endpoint through `open(... | O_CLOEXEC)` on a private task-scoped FIFO, then
  immediately unlinks the FIFO and its 0700 directory. Both endpoints therefore
  receive CLOEXEC atomically at creation rather than through a pipe-to-fcntl window.
  The compiler supervisor is launched with direct `posix_spawn`,
  `POSIX_SPAWN_CLOEXEC_DEFAULT`, and exact `dup2` file actions for descriptors 1 and
  2; the source writer descriptors are explicitly closed in the child actions and
  by their parent close-once owners immediately after successful spawn. A
  fixed supervisor forks the semantic compiler into a dedicated process group in
  the supervisor's session,
  holds the exited leader waitable so its PID/process-group ID cannot be reused,
  and closes the supervisor's capture writers before waiting. It then sends
  bounded TERM/KILL to that exact group and uses the macOS `proc_listpgrppids`
  process-group view to prove that no live member remains before reaping the held
  leader. TERM/KILL is necessary only when an independent group snapshot finds a
  live descendant. macOS may reject signalling an otherwise empty group whose
  only member is the held zombie; ESRCH or EPERM is accepted only when a second
  bounded snapshot independently proves that no live descendant remains. Because
  macOS omits a WNOWAIT zombie leader from that view and maps a
  failed group query to the same zero result, zero is cross-checked with a fixed-cap
  `proc_listallpids` snapshot that must contain the live supervisor, followed by
  exact `getpgid` checks. EOF may arrive earlier, but the parent accepts EOF and the
  semantic status only after the supervisor has confirmed group quiescence;
  supervisor timeout/probe/setup exit codes remain typed infrastructure failures.
  Separate retained-writer and already-silent descendant modes plus repeated
  zero-output launches cover endpoint ownership and group quiescence independently.
  A deterministic endpoint-creation hook launches unrelated long-lived processes
  after every atomic endpoint open; the compiler must still reach EOF while all
  unrelated processes remain alive, proving they did not inherit capture writers.
  Dynamic validation on Apple Swift 6.3.3 passes the focused supervisor test,
  including four concurrent unrelated-spawn hooks, 32 immediate zero-output
  launches, retained-writer and already-silent descendants, and partial-launch
  cleanup. All four semantic compile-fail fixtures, every synthetic infrastructure
  rejection, the shared authority compile/use test, and all 72 DiskplanScan tests
  pass. A fresh build and the full Swift suite pass all 459 tests with no timeout
  or unexpected failure.
- A later required full-parallel macOS 26 run exposed a second capture-liveness
  weakness: zero-output and semantic compiler processes exited with confirmed
  group quiescence, but both drain tasks could remain unstarted on the saturated
  global dispatch executor. The empty output plus timed-out drains therefore did
  not identify an inherited writer. The replacement keeps each FIFO path until
  teardown for bounded exact-path ownership diagnostics, starts stdout and stderr
  drains on dedicated threads, and requires both start acknowledgements before
  releasing the compiler wrapper. The parent no longer opens either capture
  writer: the wrapper opens both private FIFO writer endpoints with `O_CLOEXEC`,
  redirects them to stdout and stderr, acknowledges readiness over a separate
  control socket, and only then receives permission to fork and execute the
  compiler. This removes both global-executor starvation and the pre-exec
  fork-inheritance window from the protected capture-writer ownership property.
- A test-only C shim creates a deterministic fork-only child in the exact
  immediately-before-spawn hook. Eight concurrent harness executions prove that
  those unrelated children cannot inherit capture writers; 32 zero-output
  launches, retained-writer and silent-descendant cases, setup failure, and
  wrapper handshake failure retain bounded cleanup coverage. Failure-only owner
  diagnostics use direct `posix_spawn`, bounded regular-file output, and bounded
  TERM/KILL cleanup without Foundation `Process` or the shared dispatch executor.
- Post-fix gates pass on Apple Swift 6.3.3: the fork-only ownership regression,
  supervisor stress, four semantic compile-fail fixtures, infrastructure
  classifier negatives, and shared-authority cross-target compile/use test each
  pass their focused gate. The unsandboxed read-only host-probe full-parallel
  Swift suite passes all 460 tests in 10.544 seconds. No compiler wrapper,
  retained-writer helper, fork-only child, capture directory, or diagnostic file
  remains after the run. The outer sandbox cannot apply SwiftPM's nested manifest
  sandbox on this host, so the accepted repository host-probe shape remains the
  authoritative local full-suite result.

## Next Steps

1. Land and push the signed follow-up without manually rerunning CI.
2. Let the required macOS 26 PR lane validate the dedicated-drain handshake and
   parent-writer-free capture contract under the full parallel suite.

## Evidence

- Parent evidence design: `docs/project_journal/2026/08/2026-08-28-runtime-evidence-enrichment-e41c73.md`.
- Scanner contract: `docs/design/scanner-core.md`.
