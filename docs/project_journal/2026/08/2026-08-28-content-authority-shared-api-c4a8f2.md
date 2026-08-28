---
id: 20260828-c4a8f2
title: Scanner Content Authority Shared API
status: active
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

## Next Steps

1. Land the reviewed and dynamically verified follow-up.

## Evidence

- Parent evidence design: `docs/project_journal/2026/08/2026-08-28-runtime-evidence-enrichment-e41c73.md`.
- Scanner contract: `docs/design/scanner-core.md`.
