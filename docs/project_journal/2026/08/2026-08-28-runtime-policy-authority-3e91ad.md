---
id: 20260828-3e91ad
title: Runtime Policy Authority
status: active
created: 2026-08-28
updated: 2026-08-28
branch: wip/runtime-policy-authority
pr:
supersedes: []
superseded_by:
---

# Runtime Policy Authority

## Summary

- Connect the complete scanner event stream to a bounded policy accumulator without using the
  scanner's retained top-K viewport as candidate evidence.
- Keep evidence freezing, recognizer precedence, seven-vote evaluation, release-owner topology,
  immutable-plan construction, and presentation projection under Swift engine authority.

## Current State

- `ScanCoordinator` has an explicit authority-enabled session factory and tee seam, but ordinary
  production scans leave it disabled. A future concrete runtime plan handler must opt a scan into
  authority collection before path traversal and consume the same finalized session. Until that
  handler lands, plan consumption remains capability-off and scan-only production pays no new
  accumulator CPU or memory cost.
- `BoundedAuthorityEvidenceAccumulator` keeps deterministic stable top-K candidate summaries plus
  bounded shared-object and physical-owner indexes. Accepted profile limits are 250,000 candidates,
  2,000,000 shared keys, and 5,000,000 owner references. The 768 MiB contract bounds authority-owned
  retention and planning: retained evidence receives one eighth, post-scan planning receives seven
  eighths, and each retained byte reserves six planning bytes plus one eighth of headroom. The
  scanner's retained viewport is stripped from the authority result; process/global/final root
  inputs are separately estimated with overflow-reporting arithmetic and degrade to typed unknown
  evidence when admission fails. Peak admission covers the retained source model, one sorting/index
  copy, the single canonical configuration artifact, and one downstream COW/hash-boundary copy.
  Capture hashing streams large fields instead of appending another aggregate configuration buffer.
  The broker's fixed-capacity queue and checkpoint encoder remain a separately owned bound, not part
  of the authority estimate. Any count, retained-byte, final-input, or planning-reservation omission
  is typed and makes topology/dependency coverage incomplete without upgrading negative evidence.
  Candidate eviction is transactional:
  the complete lower-priority eviction set is planned first, and a rejected insertion/update leaves
  the prior stable top-K unchanged.
- The registry recognizes Git linked-worktree structure. `.codex-tmp`, generic
  cache/build/temporary, and versioned-artifact names are type hints only: they are report-only with
  generic-remove scope and unknown recoverability until candidate-specific cleanup-scope, manifest,
  producer, and rebuild provenance is available. Provider state comes only from scanner File
  Provider evidence and forces report-only policy; no provider-name or path exclusion table exists.
- `ProductionPolicyEvidenceAdapter` freezes scanner observations into policy observations and lets
  the policy core derive all seven votes. Missing activity, provider state, root/candidate coverage,
  dependency ownership, ACLs, content baselines, and Git registration evidence remain distinct and
  fail closed.
- The engine builds deterministic object-owner and hardlink/clone allocation-group indexes from
  the bounded event-derived evidence. Clone keys include device scope; clone reference counts count
  distinct file-object identities, while each object's hardlink count must separately match every
  physical owner path and every alias must report identical sharing topology. Raw absolute-path
  relations and root object identity detect nested explicit roots and same-directory aliases across
  different root IDs. Same-object aliases use relative-coordinate depth; distinct root objects use
  raw-absolute depth, and mixed matches compare containment distance rather than incomparable raw
  depth values. They assign a physical path to the deepest canonical candidate once and carry
  one-way overlap edges/blockers separately. The APFS snapshot blocker remains unknown until public
  attribution exists, preventing release credit.
- Finalization is not complete merely when `scanFinalized` enters the broker queue. Its exact writer
  operation carries an acknowledgement that resolves success or failure; only successful delivery
  permits `workerFinished` and plan reachability.
- `RuntimePolicyAuthorityResult` carries an engine-owned `ImmutablePlan`, evidence-only/report-only
  plan items, pre-freeze typed rejections, the owner index, and any successfully constructed release
  graph. The bounded projection is plan-type-first and reports truncation explicitly.

## Protected Properties

- Object identity is device, file ID, and object type. A close event seals completeness only when
  both the provisional and closed observations prove the same identity. A different or unavailable
  identity cannot prove continuity; a timestamp-only transition is benign metadata and does not
  become replacement evidence.
- Content stability requires a scanner- or adapter-supplied digest. Directories and symlinks may use
  the closed metadata-only not-applicable contract; a regular file without a digest stays unknown.
- Access policy is UID, GID, mode, flags, ACL digest, provider state, and mount identity. Immutable,
  append-only, restricted, or no-unlink flags are explicit protection. Advisory filesystem times do
  not substitute for access evidence.
- Closed-directory coverage protects subtree completeness. Child-entry churn is admissible only
  inside the scanner's descriptor-bound traversal; policy consumes the final close event and never
  upgrades a provisional `subtree_incomplete` node.
- Shared-storage identity is scoped by device, file ID, and object type. Equal clone IDs on different
  devices are unrelated; hardlink aliases share one file object but remain distinct physical path
  owners. Candidate nesting changes plan ownership, not filesystem identity, and is represented by
  an explicit overlap edge rather than duplicate owners.

## Task List

- [x] Add the deterministic bounded event-stream accumulator independent of scanner top-K retention.
- [x] Add an opt-in authority session factory and tee seam to the production coordinator; leave it
  capability-off until a concrete runtime plan handler supplies and consumes the session.
- [x] Add the first production recognizer registry, name-only type-hint route, and provider
  report-only route.
- [x] Add the scanner-to-policy evidence adapter with typed fail-closed mappings.
- [x] Scope clone IDs by device, count distinct clone objects, and validate every object's hardlinks.
- [x] Add canonical deepest nested ownership plus explicit overlap blockers.
- [x] Add bounded owner/shared-key indexes and typed budget-exhaustion degradation.
- [x] Make byte-pressure top-K replacement transactional, including existing-record rollback.
- [x] Reserve an independent bounded post-scan planning budget with overflow-reporting arithmetic.
- [x] Keep finalized plans unreachable until the coordinator worker has successfully crossed the
  complete/finalized-partial broker boundary.
- [x] Add engine-owned immutable-plan and bounded presentation projections.
- [x] Add tests for opt-in authority collection, cross-volume clone collisions, hardlink-clone
  ownership, budget exhaustion, name-only fail-closed behavior, and cross-root overlap ownership.
- [x] Add static tests for multi-eviction byte pressure, rejected-update rollback, and the final
  broker/checkpoint reachability window.
- [x] Add the opt-in synthetic million-entry streaming checkpoint: no million-node array/files,
  opposite event order and different chunk sizes, exact retained-set/omission/capture/order checks,
  and a fixed retained-memory bound. Run with `DISKPLAN_RUN_MILLION_ENTRY_GATE=1` at the accepted
  checkpoint rather than every focused development gate.
- [x] Run the 15-test focused authority correction set, 48-test EngineCore suite, and 63-test Policy
  suite under the explicitly assigned dynamic slot.
- [x] Run the serial full Swift gate and opt-in million-entry checkpoint.
- [x] Complete post-validation self-review and hand off the uncommitted worktree.
- [x] Add exact final-frame writer acknowledgement and blocked/failing writer regression fixtures.
- [x] Reuse one budgeted canonical authority configuration and stream it through capture hashing.
- [x] Fail a whole file object and related groups closed on contradictory hardlink-alias topology.
- [x] Rank same-object aliases by relative depth and prevent bidirectional duplicate overlap edges.
- [x] Close the narrow review's mixed-coordinate finding with containment-distance ordering and a
  three-root raw-ancestor/same-object-alias regression fixture.
- [x] Run the new residual focused, EngineCore, Policy, and serial full Swift gates after the parent
  explicitly releases the slot.

## Handoff

- Phase: the follow-up review residuals and their tests are implemented and dynamically validated.
  The worktree remains intentionally uncommitted and no dynamic command is running.
- Next step: hand the uncommitted slice to the parent for integration. Runtime plan consumption
  remains a separately owned capability-off integration task.
- Constraint: scanner evidence currently lacks ACL digests, regular-file content digests, root
  access-policy seals, and exact linked-worktree registration facts. Those candidates therefore
  remain evidence-only/report-only instead of receiving a forged executable action.

## Evidence

- Architecture: `docs/design/accepted-plan.md`.
- Scanner contract: `docs/design/scanner-core.md`.
- Policy contract: `docs/design/policy-core.md`.
- Current-revision dynamic gates: latest residual focused set 10/10,
  `DiskplanEngineCoreTests` 53/53, `DiskplanPolicyTests` 63/63, and serial full Swift 380/380.
- The opt-in million-entry checkpoint passed 1/1. The test body took 108.514 seconds; the complete
  timed command took 121.36 seconds including its build. `/usr/bin/time -l` reported 255,590,400
  bytes maximum resident set size, zero swaps, and a 48,726,712-byte peak-memory-footprint metric.
- After the full gate, the final fail-closed adapter-scope tightening passed its exact name-only
  tests 2/2, and the candidate-depth-index optimization passed its exact overlap/owner tests 3/3.
- The latest residual focused set covers exact final-frame writer acknowledgement and failure,
  final-input peak budgeting and streaming hashing, contradictory hardlink-alias topology, and
  mixed containment-distance/alias overlap behavior.
- A read-only narrow follow-up review found one mixed-coordinate nearest-owner issue. After the
  containment-distance correction and three-root fixture were added, the same reviewer returned
  no findings. The reviewer did not edit files or run build/tests.
- Current-revision static gates: strict `swift-format`, `git diff --check`, and the project-journal
  validator pass after the correction set and dynamic evidence update.
