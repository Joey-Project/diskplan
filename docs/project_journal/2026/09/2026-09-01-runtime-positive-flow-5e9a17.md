---
id: 20260901-5e9a17
title: Runtime Positive Execution Flow
status: active
created: 2026-09-01
updated: 2026-09-01
branch: wip/runtime-positive-flow
pr: https://github.com/Joey-Project/diskplan/pull/24
supersedes: []
superseded_by:
---

# Runtime Positive Execution Flow

## Summary

- Replace the controller's blanket dry-run/apply/cancel rejection with an optional, fail-closed
  execution backend seam and an engine-owned positive dispatcher.
- Keep exact plan, overlay, review, epoch, force-confirmation, execution-ID, and single-use apply
  authority bindings inside Swift EngineCore.
- Admit one exact midstream cancellation while preserving a sealed best-effort terminal report for
  both the original confirmation and cancellation requests.

## Current State

- EngineCore defines immutable preparation context, a package-only prepared attempt, a
  controller-owned one-shot authority box, and sealed run/tail handles without importing
  DiskplanExecution or exposing raw argv/path mutation authority.
- RuntimeSessionController advertises dry-run and execution capabilities only when a backend is
  installed. An absent production bridge remains typed unavailable and fail-closed.
- Apply-review publication installs its exact one-shot box inside the responder transaction before
  the review becomes visible and restores the predecessor on writer or commit failure. Exact
  confirmation consumes the box before backend entry; stale, mismatched, and replayed confirmation
  cannot invoke the backend again.
- A confirmation that arrives after review bytes flush waits for the same publication transaction
  to commit or roll back. It then sees the committed review or a typed stale-binding rejection,
  never the transient active prepare request.
- Controller-owned async tasks never perform a condition-backed responder flush on the Swift
  cooperative executor. One broker-owned, serial Foundation worker executes every blocking
  responder transaction, rejects work beyond its finite pending bound, and resumes owning tasks
  through checked continuations; synchronous server request paths retain their existing authority
  and ordering boundaries.
- Runtime lifecycle stop closes that worker to new submissions, cancels queued operations, and
  fails closed plus interrupts the transport when an operation is already executing. In-flight
  batch acknowledgements are resolved exactly once, the writer and worker are joined before EOF
  teardown returns, and broker finish remains idempotent.
- The registered execution ID becomes visible through an early `apply_started` prefix. One exact
  cancellation mirrors the same prefix, appends one typed acknowledgement, cancels the retained
  run, and gives both pending requests the same sealed terminal stream.
- Once a validated run handle exists, every post-start error requests cancellation and awaits the
  same non-throwing sealed tail. The run remains retained through the joint confirm/cancel terminal
  commit, while a finishing authority phase rejects late cancellation without token competition.
- EngineServer no longer pre-rejects cancellation and calls the handler lifecycle before closing
  the broker at EOF. Controller teardown atomically prevents new run installation, then cancels and
  waits even when a backend start returns only after teardown has begun.
- The executable target now contains an injectable `DiskplanRuntimeExecutionBackend` bridge. It
  consumes Phase 4 preparation, opaque capability, review, and authorization objects, and projects
  the exact Phase 5 coordinator event/report stream into EngineCore's sealed runtime wire. Dynamic
  detail text and generated identifiers are bounded before publication; an invalid authoritative
  tail is supervised as cancel-and-await plus a typed failure instead of crashing.
- Allocation-group-to-release-set identity now travels from the authoritative plan projection into
  execution context, so equal owner sets cannot collapse distinct allocation groups. Force
  confirmation accepts only unique set equality and is independent of presentation order.
- Phase 5 unit completion carries the complete authoritative outcome into an immediate wire
  projection. The capture retains only projected events under a 25,000-event, 32 MiB in-memory
  budget with 512 bytes of per-event accounting and a 4 KiB terminal reserve; overflow clears the
  buffer and requests coordinator cancellation exactly once.
- Before protobuf construction, source-event preflight traverses every projected nested collection,
  validates digest, raw-component, and dynamic-string lengths, and reserves a saturating
  fixed-overhead upper bound against the remaining capture budget. An oversized single JIT event
  therefore fails before its projector or serializer can allocate the report projection.
- Apply launch distinguishes a started run from an authoritative pre-mutation start-failure
  terminal. A started stream whose bounded projection cannot be completed is retained as an
  EngineCore typed tail failure for the protocol 1.6 terminal mapper and is never projected as a
  generic runtime rejection.
- Protocol 1.6 started-stream failure now uses the same authority transaction discipline as a
  normal terminal. EngineCore maps projection-limit, projection-validation, and backend-contract
  outcomes to one sealed `execution_stream_failure` over the exact emitted prefix, mirrors it to
  any admitted cancellation responder, and jointly consumes both claims. Protocol 1.4/1.5 apply
  review fails closed before backend preparation while dry-run remains compatible.
- Mirrored cancellation prefixes and terminals are prevalidated and serialized before entering the
  broker as one queue item with one writer acknowledgement. Authority commit, responder completion,
  and run cancellation occur only after that shared barrier succeeds; a physical between-envelope
  write failure closes the transport, aborts the authority transaction, and leaves the run retained
  for teardown. Normal-tail membership rejection instead falls back to a Protocol 1.6
  `backend_contract_violation` terminal over the unchanged transmitted prefix.
- Joint batches use the execution capture's per-responder 25,000-event/32 MiB framed limit and a
  conservative doubled broker boundary, independent of ordinary queue depth. A monotonic FIFO
  reservation prevents later semantic or telemetry producers from overtaking a waiting mirrored
  prefix or terminal while prior output drains.
- Production `DiskplanEngineMain` intentionally does not inject the bridge yet. The repository does
  not expose a production revalidation collector factory, so production apply remains fail-closed
  rather than substituting a fixture collector or bypassing Phase 4 authority.
- Runtime concurrency fixtures no longer put condition-backed broker, authority, cancellation, or
  teardown calls in detached Swift tasks. Their one-shot latch broadcasts to every waiter, retains
  an early signal, and removes cancelled waiters; publication-race fixtures use structured async
  teardown so gate release, controller join, and broker closure occur on success and failure.

## Next Steps

- Complete fresh frozen-range review and address any P0-P2 findings.
- After the concrete revalidation collector factory lands, construct an
  `EngineExecutionComposition` from the live collector and inject the existing backend bridge into
  production main.

## Evidence

- Base: `23718ae6c898a5bc42534bced9fec82ff54c033d`.
- Protocol 1.6 integration merge: `4594e864a95712caf648252ec1cb593bf70e8128`, with exact
  integration parent `b50dd50a9c6d63ef44ecf4ac406d901045d6723c`; signature verified good.
- Static checks: strict Swift formatting, Swift parser validation, and `git diff --check`.
- India Protocol 1.6 runtime gate passed 166 `DiskplanExecutionTests` in 11.939 seconds and 115
  `DiskplanEngineCoreTests` in 16.330 seconds. Both 900-second supervised runs verified their
  target process groups and post-run quiescence; retained output SHA-256 values were
  `e6cb09b8f543ed612348bc61189743a26a4eae8eb126171666f5fb1fa274c05e` and
  `a3716b60aa1fa74d88ecf9fd734e3a247465f131568206ff416a29f8963d1bc4`.
- India `scripts/protocol16-fixtures.sh` passed after installing the missing Homebrew Rust 1.98.0
  toolchain. The supervised fixture run completed in 8.631 seconds, verified process-group
  quiescence, and confirmed that the Protocol 1.6 runtime fixtures match the Swift authority;
  retained output SHA-256 was
  `17349332d9176d53aeff4f82bc65e554462d6b3276be799f7edddbbf1468443d`.
- India joint-broker closure retained the earlier 166/166 passing `DiskplanExecutionTests`, then
  passed all 118 `DiskplanEngineCoreTests` after the exact writer-failure synchronization barrier.
  The final EngineCore supervisor completed in 13.818 seconds with process-group verification and
  post-run quiescence; retained output SHA-256 was
  `8bcb2d4b3097ad619ee8e06ee6cc2dc777d0f75a134159cf2bf98df0ab91789c`.
  The subsequent Protocol 1.6 fixture gate passed in 5.220 seconds with the same supervisor
  guarantees and retained output SHA-256
  `83653f0a9a3c2efdafd7a8afb9d96929f9ed7016667255bf065ebbdf10932ae4`.
- India queue-limit and FIFO-reservation closure passed all 120 `DiskplanEngineCoreTests`, including
  the 65-event cancelled tail and sustained later-producer fixtures, in 18.138 seconds under the
  bounded supervisor. Process-group verification and post-run quiescence passed; retained output
  SHA-256 was `07742850beb2e4c1b4047d847a091367be705fc4e148186d1cf454c89741d0c8`.
  The subsequent Protocol 1.6 fixture gate passed in 5.070 seconds with the same supervisor
  guarantees and retained output SHA-256
  `83653f0a9a3c2efdafd7a8afb9d96929f9ed7016667255bf065ebbdf10932ae4`.
- PR #24's full Swift foundation command reproduced one full-suite-only test failure on India:
  635 of 636 tests passed before `redirectedDescendantReadinessReportsEarlyExit()` threw `EINVAL`.
  Concurrent anonymous-pipe allocation could assign source descriptor 40 or 41 while the fixture
  hard-coded those same values as child targets, violating the production spawner's required
  source/target disjointness. The test fixture now selects child targets dynamically from 40 while
  excluding stdio, every source descriptor, and prior selections; the production validator remains
  unchanged. After the fix, the focused `RuntimeCollectorsTests` gate passed all 40 tests under the
  bounded supervisor in 25.048 seconds, with output SHA-256
  `cf14727d13366cc514dcf521436aa511659e59a0b1640947651108e5758388ac`. The exact full command
  `scripts/ci/package-resolved-guard.sh run Package.resolved -- swift test
  --disable-automatic-resolution` then passed all 637 tests in 10.340 supervisor seconds (5.859
  test seconds), with process-group verification, post-run quiescence, and output SHA-256
  `dc3646f6243a06e388e02db58a93ea5a500b3e9118f6dbb07193761f5068c134`.
- India focused gate: `swift test --filter DiskplanEngineCoreTests` passed all 96 tests under the
  bounded supervisor in 13.793 seconds; process-group verification and quiescence both passed.
  Log: `/Users/cisco/Program/GitHub/diskplan/.codex-tmp/india-gates/runtime-positive-enginecore-retry6.log`;
  bounded output SHA-256: `17256cbf1555d74c76c9de275295fdfd811d0477718aec2f74e0920ab614c470`.
- India review-fix gate: the same command passed all 103 tests, including the external-package
  compile-surface fixture, under the bounded supervisor in 15.011 seconds; process-group
  verification and quiescence both passed. Log:
  `/Users/cisco/Program/GitHub/diskplan/.codex-tmp/india-gates/runtime-positive-review-fixes-4.log`;
  bounded output SHA-256: `1d9b099f7d4163fb699ba94daeeba1d66aa772e9260e0e717ccbde015e049800`.
- India rereview gate: the same command passed all 105 tests under a 900-second process-group
  deadline and a 2 MiB retained-log quota in 13.505 seconds. Target process-group verification and
  post-run quiescence passed; the quota was not reached. Log:
  `/Users/cisco/Program/GitHub/diskplan/.codex-tmp/india-gates/runtime-positive-rereview.log`;
  bounded output SHA-256: `d67a15d051cf609f5f42b70e71aab56d832188227048f0c308349e54a0d8ddea`.
- India replacement-review race gate: the same command passed all 106 tests under the same
  deadline and retained-log quota in 13.708 seconds. Target process-group verification and post-run
  quiescence passed; the quota was not reached. Log:
  `/Users/cisco/Program/GitHub/diskplan/.codex-tmp/india-gates/runtime-positive-rereview-5.log`;
  bounded output SHA-256: `9245d5cecd640525372162ede362ce418967e953946bca8600278ea5235f0944`.
- India final test-stability gate: the same 106 tests passed after adding the exact authority-commit
  barrier in 15.009 seconds. Process-group verification and post-run quiescence passed; the quota
  was not reached. Log:
  `/Users/cisco/Program/GitHub/diskplan/.codex-tmp/india-gates/runtime-positive-rereview-6.log`;
  bounded output SHA-256: `19d06a76de2614f48276de1b2e1a0e8fa49e5a7b72cd401e0050bea656532491`.
- India composition bridge gate ran `swift test --filter DiskplanExecutionTests` followed by
  `swift test --filter DiskplanEngineCoreTests` under one 900-second process-group deadline and a
  2 MiB retained-log quota. All 158 execution tests and 107 EngineCore tests passed in 13.725
  seconds; process-group verification and post-run quiescence passed, and the quota was not
  reached. Log:
  `/Users/cisco/Program/GitHub/diskplan/.codex-tmp/india-gates/runtime-positive-composition-8.log`;
  bounded output SHA-256: `0b606131347138f4b1315bcd725216133b40d388de18e67694f5445fd62136d1`.
- India non-protocol bridge-fix gate ran the combined Execution and EngineCore filters under one
  900-second process-group deadline and a 2 MiB retained-log quota. All 272 tests passed in 15.895
  seconds; process-group verification and post-run quiescence passed, and the quota was not
  reached. Log:
  `/Users/cisco/Program/GitHub/diskplan/.codex-tmp/india-gates/runtime-positive-composition-9-retry2.log`;
  bounded output SHA-256: `11f3c9cf35d1cb73825b8365bb8f6260c922c8edbcf06dfddec2f2f48410e888`.
- India targeted P1 closure ran the combined Execution and EngineCore filters under the same
  900-second process-group deadline and 2 MiB retained-log quota. All 274 tests passed in 15.182
  seconds; process-group verification and post-run quiescence passed, and the quota was not
  reached. Log:
  `/Users/cisco/Program/GitHub/diskplan/.codex-tmp/india-gates/runtime-positive-p1-rereview-retry4.log`;
  bounded output SHA-256: `3ea1f178344e73ca6a6c234523297f4cbc3a41f57262dcc5e4bb59a8a5a32fae`.
- The public macOS 26 Foundation timeout was reproduced as fixture executor starvation: synchronous
  review/start gates occupied cooperative executor threads while their matching test tasks waited
  to release them, and one composition fixture let a wall-clock epoch expire behind that backlog.
  The fixtures now use bounded asynchronous one-shot signals, publication commit remains serialized
  by the production authority transaction, and the composition fixture injects one shared internal
  deterministic clock while production construction remains real-time. On India, the five exact
  barrier regressions passed 5/5 in 13.833 supervisor seconds (0.014 test seconds), SHA-256
  `ee9241055923e037680050c4984b616e2d21d7393b3f51ccae66ad62c3c59b60`; the composition regression
  passed 1/1 in 4.456 supervisor seconds, SHA-256
  `99c398694781276274629b91c2a4a29e169ced5c9ab8d5605ebb5965768a2354`; and the exact full Foundation
  command passed all 637 tests in 10.341 supervisor seconds (5.966 test seconds), SHA-256
  `e925680d7f71e178e56be9602b70a7f46549d61810d6e2edffcea94de8218393`. Every supervisor verified
  its process group and ended quiescent. The diagnostic deadlock run was intentionally terminated
  after sampling, with supervisor output SHA-256
  `cbfc97405de97754b7264390cd477cb076dad58981fcf025a142e6714a7bd022`; its reparented SwiftPM helper
  had created a separate process group, so it was subsequently identified by exact workspace
  cwd/argv/open-file evidence, terminated with `TERM`, and the isolated India workspace, `.build`,
  and retained logs were removed.
- The publication-wait fixtures now observe an authority-owned waiter count set under the same
  condition lock immediately before a confirm claim sleeps, rather than inferring entry from task
  scheduling. The three exact publication-race regressions passed 3/3 on India in 24.531 supervisor
  seconds (0.016 test seconds), SHA-256
  `245fae136c7d56435afddf8c4f5e11ae5a62b1c5685bfb0360f5955db2d652d0`. The exact full Foundation
  command then passed all 637 tests in 10.268 supervisor seconds (6.021 test seconds), SHA-256
  `d4de3f4555b570b68293794fac397f29d36f33ac39cd15e23d3f3c5377236746`. Both supervisors verified
  their process groups and ended quiescent; the isolated workspace, `.build`, and logs were removed.
- The public full-parallel hang was reproduced deterministically on India by setting
  `LIBDISPATCH_COOPERATIVE_POOL_STRICT=1`. The old batch fixture occupied the only cooperative
  worker in `SerialEventBroker.sendRuntimeBatchAwaitingWrite()` while its dedicated writer waited
  for the test gate; a second sample showed an async controller task synchronously blocked in
  `SerialEventBroker.flush()`. After moving async responder transactions and all blocking fixture
  bridges to joined named threads, the six exact batch, publication, multi-waiter, early-signal,
  and cancellation regressions passed together in 0.015 test seconds. The bounded supervisor
  completed in 12.008 seconds with verified process-group quiescence and output SHA-256
  `f2e6b7f1f38f60bce6cc792489b2a2d00ee7da99dfeae1513ae4ef383bdac2c2`.
- The exact Foundation command then passed all 639 tests five consecutive times on macOS 26.5.1
  Apple Silicon. Test runtimes were 5.489, 5.698, 5.883, 5.469, and 5.604 seconds; every bounded
  supervisor verified its process group and ended quiescent. Retained-output SHA-256 values were
  `2bbd2c32617dbc2f4b00ee6a4a04925439cc7ded03d431265f236760c2bd7bd4`,
  `ed85288977361412e1b39a1de599ef897bbbb0c1f27a3fc0bd102e39dfb58c4f`,
  `7ab54763def06880fce6b4b74ba0f9de5ad75b792542883810faf06d27220db2`,
  `93a24aa526627c0cc088cd1b2c28989d9725b93d3b997e11db7cf472bac1cebd`, and
  `5046b305346db58fdf896db994db91467d728705f8cc5c2ebc29c359a24d94b2`.
- After the final mechanical indentation cleanup, the same six strict-pool regressions passed in
  0.015 test seconds, followed by all 639 Foundation tests in 5.594 test seconds. Their supervisors
  again verified process-group quiescence; output SHA-256 values were
  `1abaa6c717eeb815a036c070412a938166842e192b3147e536d50ef2380c6d3b` and
  `872e9d5abc64245eb0779d01d89252e912249c889d9d60b55ae3b5ec61ffcd9a`.
- Frozen review found that the first bridge created one uncancellable native thread per send and
  could deadlock lifecycle stop behind an unread stdout writer. The replacement uses one serial
  worker with a 128-operation pending bound and cancellation-aware queue removal. Eight exact
  strict-pool regressions, including 128 concurrent submissions, deterministic overflow rejection,
  and a blocked-writer stop without manual gate release, passed on the final source; supervisor
  output SHA-256 was `e9a6dbbdad27bd0e58514a8c5b5ed377d8a24f2c5c69631c128fd3d098ae89f4`.
- The exact CI build passed with output SHA-256
  `2c8b0760877ab457f3d0534f56bc7c331d962fca5ed98f7bbd2a495b2e7cd5d9`. Two subsequent exact
  Foundation runs passed all 641 tests with verified process-group quiescence; supervisor output
  SHA-256 values were `80956aa201c8a004d0571370a87584a5959305360cbbb2eeae396be7b6ff1f66`
  and `7f6025d469e80d362f5461f1cd7814a95f0ea31b07e7e9d6a9d9333eee52e47a`. After the final
  capacity and completed-operation cancellation-race assertions, all 641 tests passed once more
  with output SHA-256 `6aad600df636890d29818dfc3e4674573b399327e58217f0aa3c992bf1a3b2a9`.
- Focused fixtures cover absent-backend fail-closed behavior, exact dry-run binding, single-use
  confirmation/replay, wrong execution-ID cancellation, mirrored cancelled terminal streams, and
  retained-run teardown, including gated backend start and review-publication races. Bridge
  fixtures also cover dry-run/review/apply projection, cancellation, non-current revalidation,
  empty and oversized detail normalization, invalid generated identifiers, protocol budget
  metadata, and supervised authoritative-tail validation failure.
