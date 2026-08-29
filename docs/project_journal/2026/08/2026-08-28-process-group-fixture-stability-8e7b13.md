---
id: 20260828-8e7b13
title: Process Group and Bounded Runner Stability
status: completed
created: 2026-08-28
updated: 2026-08-28
branch: wip/process-group-fixture-stability
pr:
supersedes: []
superseded_by:
---

# Process Group and Bounded Runner Stability

## Summary

- Removed the readiness race from the Rust fake-engine process-group cleanup regression without adding a fixed setup sleep.
- Made shutdown transport-error classification independent of child-exit and decoder scheduling order.
- Closed the release supervisor's fast-leader `ESRCH` window while preserving its unreaped PID/PGID identity fence and descendant quiescence proof.
- Added a fixed-field bounded supervisor report summary to packaging failures without retaining command output.

## Current State

- The fake engine writes its descendant PID to a staging file, closes the writer, atomically renames the complete record into place, and only then emits a valid handshake response.
- The successful handshake is the exact readiness barrier. Engine startup and readiness use the existing bounded fixture setup budget; the tested response timeout begins independently after that barrier through `read_engine_event_with_timeout`.
- Missing publication, malformed record framing, invalid numeric content, handshake timeout, early engine exit, and protocol framing failures remain distinct failure surfaces.
- The protected property is descendant identity publication before timeout cleanup begins. The staging-file close plus atomic rename protects complete record visibility; the accepted handshake orders that publication before the test starts its independent monotonic response deadline. The production TERM-to-KILL and process-group reaping behavior is unchanged.
- A decoder-reported `FrameError` now terminates the stdout stream while preserving that first protocol error. A later channel disconnect can no longer replace an oversized, truncated, or I/O frame error with `DecoderDisconnected`; a disconnect without any terminal decoder report remains a distinct failure.
- A successful `Popen(..., start_new_session=True)` proves that `setsid(2)` completed before exec. If `getpgid` or `getsid` subsequently returns only `ESRCH`, the supervisor accepts the promised PID-equals-PGID-equals-SID contract only after `LeaderExitObserver` confirms exit within the original monotonic deadline. The direct child remains unreaped until descendant inspection and cleanup complete, so the numeric identity cannot be reused. Wrong identities, other errno values, and unverified exit still fail closed; no signal-zero probe was introduced.
- Packaging exceptions retain only typed scalar supervisor state and cleanup booleans. Unknown report fields and captured command bytes are excluded from the bounded summary.

## Next Steps

- Merge this stability slice before rerunning full-package and release gates in the dependent runtime branches that exposed the races.

## Evidence

- The pre-fix concurrent integration run captured the shutdown race as `DecoderDisconnected` where `FrameError::Oversized` was required; the deterministic terminal-frame regression and the concurrent integration suite pass after the fix.
- The readiness implementation passed five bounded repetitions; the final combined head passed both focused process-group and shutdown-tail regressions.
- Full `diskplan` package: 76 library, 4 launcher, and 9 fake-engine tests passed; 10 live Swift-engine tests remained intentionally ignored.
- Release supervisor tests passed 9 of 9, including deterministic `getpgid`/`getsid` `ESRCH` injection and 16 immediate-exit process launches.
- Release packager tests passed 16 of 16, including bounded failure-summary redaction.
- GitHub evidence that motivated the fixes: PR #7 Foundation CI run `33188681983`, job `98908248252` for the shutdown-tail classification race; Release CI run `33188681841`, job `98908246383` for the fast filesystem-helper bounded probe.
- `cargo check --workspace --all-targets` passed.
- `cargo clippy --workspace --all-targets -- -D warnings` passed.
- Python bytecode compilation, `cargo fmt --all -- --check`, project-journal validation, and `git diff --check` passed.
