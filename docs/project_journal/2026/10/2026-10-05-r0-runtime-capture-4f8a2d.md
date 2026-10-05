---
id: 20261005-r0c4f8a2d
title: R0 Runtime Capture Integration
status: active
created: 2026-10-05
updated: 2026-10-05
branch: wip/r0-runtime-capture
pr:
supersedes: []
superseded_by:
---

# R0 Runtime Capture Integration

## Scope And Contract

Integrate the preserved runtime-revalidation implementation on top of the
signed 368 integration base while keeping the current macOS 15 deployment
target, accepted-plan behavior, effect contract, stageable-cache semantics,
and release-topology evidence intact. The original dirty
`runtime-revalidation-adapters` worktree is read-only and is not a delivery
target.

The complete seven-commit unique history ending at `5d2091d` is an input; the
command-preview, dirty-worktree report-only, deterministic binding, assertion
ordering, and fresh-policy capture commits must remain in the branch graph.
Wire/protobuf/Rust/generated integration, effect-permission design, and the
main integration journal remain outside this lane.

## Runtime Boundary

`RuntimeEvidenceSession` remains the sole outer capture-ID and lease boundary.
Whole-plan and JIT policy collection consumes an opaque one-shot permit minted
by that lease. A Scan-private path/descriptor/content helper cannot issue a
capture ID or production permission independently. Final-descriptor evidence
uses a distinct lease in the same session. Close and cancellation retire the
outer lease and use its bounded drain; pending descriptor/content work is not
allowed to publish after retirement.

Revalidation keeps object identity, selected size/digest content, and access
policy/provider/mount evidence as separate properties. Benign timestamp and
sibling-entry churn must not become content or identity mutation; replacement,
content change, and access-policy drift remain independently observable.
Absence, unknown, unreadable, and failed evidence are not collapsed.

## Validation And Boundaries

All builds, tests, formatting, and code generation run only on
`India-mac-mini-m4-hoteng`, under `scripts/release/run_bounded.py` with the
approved 900-second / 1-MiB bound. No Swift validation has been run on the
local host. The assigned India scratch root is
`/private/tmp/diskplan-r1-integration-20261005.C6HbGnbf`; the exact uploaded
candidate snapshot was `/private/tmp/diskplan-r1-integration-20261005.C6HbGnbf/source-current.tar.gz`, SHA-256
`0dc49addc435398d6d754c8068b15219c251e5ff932ae38e99f69ad05fe91cf2` on both
the local archive and India copy. The `swift test` scratch path is
`/private/tmp/diskplan-r1-integration-20261005.C6HbGnbf/swift-build`.

The targeted gate is limited to `RuntimeFreshPolicyAuthorityTests`,
`RuntimeEvidenceSessionTests`, `EvidenceEnrichmentTests`, `ExecutionPreparation`,
`BestEffortApply`, `PolicyCoreTests`, and affected API compile-fail fixtures.
No full-suite result, installation acceptance, or completion of Phase 0-6 is
claimed by this lane.

Validation receipts below are from that uploaded snapshot. The production
capture positives are reported separately from the mechanism-only checks;
mechanism success does not establish host/provider admission.

| Scope | Result | India bounded-run receipt |
| --- | --- | --- |
| `ExecutionPreparationTests`, `BestEffortApplyTests`, and `PolicyCoreTests` (151 declared functions used as the filter source; 144 tests selected) | 144 passed, 0 failed. The merged dirty-worktree mismatch test follows the base's fail-fast contract and rejects a mismatched prerequisite while constructing the action. | 8.417 s; output SHA-256 `47bfd87e60222b4a78888843c1a4ea3f8b6b86386e46fa18cf851b4f142af466`; log `policy-targets-rerun-2.log`. |
| Fresh-invariant mechanism, content replacement/churn, typed unreadable classification, session lease/lifecycle/drain, and forbidden-surface compile-fail tests | 11 passed, 0 failed. These tests either exercise isolated mechanism seams or preserve the real outer lease/drain; they do not override the production provider reader. | 6.614 s; output SHA-256 `dd7280663a244ca9dfc52d6f51ff319d73f468f68bcd09bbc20d0e62595d1114`; log `runtime-mechanisms-2.log`. |
| Production fresh-invariant collector positives and real descriptor-content positive | 3 tests failed with 4 retained assertion failures. Both real fresh-invariant positives returned `unknown(incompleteCoverage)` instead of their asserted known results; terminal namespace exclusivity was also `unknown(incompleteCoverage)`. The real descriptor content assertion observed `.failed(reason: "provider-managed content cannot be bound", errorCode: 71)`. No test was skipped or weakened. | 4.759 s; output SHA-256 `05174de5e660cb583598ab2e12f29723571cfbbf72fbbca36acae312fa0e1082`; log `runtime-provider-gaps-2.log`. |

The production failures are host-admission gaps, not evidence that the
mechanism accepts a replacement or loses typed failures. The exact fresh
positive assertions remain in `RuntimeFreshPolicyAuthorityTests`; the content
positive remains in `RuntimeEvidenceSessionTests`. The provider-managed
content result is fail-closed. This lane does not reinterpret it as local or
claim the host proves absence of File Provider ownership. A separate R1
read-admission slice owns that unresolved boundary.

## Known Gaps

The source provider probe's negative-to-known-local interpretation remains an
R1 follow-up. This lane does not add or claim proof that no File Provider owns
the source. Effect-permission bindings remain frozen and are not implemented
here. Formal release and installation gates remain with the integration owner.

The India Swift build scratch is intentionally retained for the concurrent
Wire worker's read-only use of the locked SwiftProtobuf 1.38.0 checkout. It is
not this lane's repository `.build` directory.
