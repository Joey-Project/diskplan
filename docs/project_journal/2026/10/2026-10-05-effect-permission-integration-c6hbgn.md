---
id: 20261005-c6hbgn
title: Effect Permission Integration And Runtime Admission
status: active
created: 2026-10-05
updated: 2026-10-05
branch: wip/effect-permission-integration
pr: https://github.com/Joey-Project/diskplan/pull/30
supersedes: []
superseded_by:
---

# Effect Permission Integration And Runtime Admission

## Scope And Contract

Continue the complete Phase 0-6 recovery authorised by Joey. The accepted
[architecture](../../../design/accepted-plan.md) and
[locality and provider action contract](../../../design/locality-and-provider-actions.md)
remain authoritative. This workstream integrates preserved implementation before
introducing explicit action-effect permissions; it is not a reduced MVP.

Primary authorship is OpenAI Codex (GPT-6.1 Sol Extra High). GPT-6 Luna assists
with bounded source audits and separately owned implementation slices.

## Integration Sources And Ownership

- Use committed `12be062cee2306e5ecde4cb09b4ab4ee01a2845a` as the revalidation
  skeleton. The original post-verification worktree and its uncommitted changes
  remain untouched; allocation-result integration follows in its own slice.
- Append committed cache workstream `5ab8ee06647d0149c971ec449bb6a5beaf1421f8`
  and accepted documentation `9f4575bd30cc9480df97df2e9882bdb0b36a0284`. The latter
  includes canonical main `18e510655c5b2798a7c9a1c98763053fa122f5f1`, including
  the current macOS 26 runner and macOS 15 deployment baseline.
- Preserve the full implementation target list when resolving `Package.swift`;
  retain macOS 15. Resolve architecture links to the integrated tracked files.
- Integrate the runtime branch ending at `5d2091d` and its fresh-policy capture
  unit separately. Its seven unique commits include required command-preview
  authority (`81ef51c`), report-only dirty preview (`b1529d4`), deterministic
  dirty-worktree binding (`03f2769`) and assertion ordering (`06ce459`); copying
  only the final adapter commit would omit these dependencies. The two merge
  commits carry already shared ancestors. Preserve all required semantics and
  never change or discard either original dirty tree.
- Frontend `653b985` and India acceptance `32caf3a` remain explicit later inputs,
  owned by this recovery workstream, after the permission/wire interface freezes.
- Do not modify old PRs while assembling this new branch. Canonical main stays
  clean; this implementation layer will be delivered through a new PR.

## Tasks

- [x] Freeze the preserved branch graph and select a committed integration base.
- [x] Create an isolated linked worktree; begin append-only baseline integration.
- [x] Validate the integrated cache/revalidation baseline on India; record exact
  staged source-tree and command evidence.
- [x] Form and signature-verify integration checkpoint `368ba199a3b8b7e8eecff160f39cf0ea80df23e4`.
- [x] Repair the exact-checkpoint release baseline mismatch and two APFS
  post-verification fixture construction failures; validate the affected paths
  on India without relaxing production gates or historical golden bytes.
- [ ] Complete the independent exact-head review and release gates.
- [ ] Integrate concrete current/JIT collection and preserve fresh-policy capture.
- [x] Freeze the typed permission, per-action consent and canonical binding
  implementation interface in
  [effect-permission-bindings-v2.md](../../../design/effect-permission-bindings-v2.md).
- [x] Integrate checked Swift raw binding records, additive IPC 1.7 schema,
  generated sides/canonical fixtures, and frozen Rules input-state records.
- [ ] Separate scan permission from mutation authority and preserve unknown
  Provider ownership without promoting missing markers to confirmed-local.
- [ ] Wire canonical built-in/optional user rules into production cache planning.
- [ ] Implement whole-plan/JIT effect-consent validation without changing other
  vetoes, force consent, adapter scope or path-slot trust.
- [ ] Complete live IPC 1.7 consumers and cross-language semantic references.
- [ ] Integrate plan-first frontend consent/warnings and installed-product paths.
- [ ] Complete fixture-only apply/post-verification and installed India acceptance.
- [ ] Complete exact-head review and affected PR gates; land reviewable layers.

## Validation And Boundaries

All builds, tests and code generation run on `India-mac-mini-m4-hoteng`, not BL
or this local machine. The current preflight reports macOS 26.5.1, arm64,
Xcode 26.6.0 / Swift 6.3.3, Rust/Cargo 1.98.0, protoc 35.1 and shellcheck 0.11.0.
The preflight and baseline runner scripts passed `bash -n` and shellcheck on
India. The first integrated staged tree was
`77db543a08233bc4f7df9623e8c3c2a47e6bc282`; its source archive SHA-256 was
`ba572c28619b7247201b9aabf310e642679bc1281e29b24e389408005505b536`, verified on
India after upload completion.

- `cargo check --locked --workspace --all-targets --jobs 4` passed (exit 0),
  externally supervised with a 900-second / 1-MiB log limit and verified
  process-group quiescence.
- Targeted Swift tests compiled successfully, then ran 179 tests with five
  issues at the shared apply-review fixture helper. The helper observed an
  installed controller review before its writer publication, contrary to the
  intended publication/authority commit sequence. Change its existing bounded
  predicate to wait for the published review event, retaining the final
  authority-commit assertion. This is a fixture synchronisation correction,
  not a skipped test or a claim of a production-policy fix. The corrected helper
  also requires the installed ID to match the published ID, retaining the
  original installation condition and final exact authority-commit assertion.
- Final code validation used staged tree
  `7d18a5685e322ce23243717e0a7776505bf0bf92`, source archive SHA-256
  `64a332ee89b80202386e1e8b3596671926712b868014c1313752bdfaaf1b1c11` (verified on
  India after upload). The same targeted Swift command passed, as did the Rust
  workspace check; both exited 0 and their supervised process groups were
  quiescent. Swift log SHA-256:
  `e700d32908677775c18cb1022c8d74992c64056c08ea1eb9a60497855113b3da`.
  Rust log SHA-256:
  `732186322402325172940531d8d6d7cfac85dc902585b2bef6715ad6839dacfd`.
- `scripts/ci/validate_journals.py`, `bash -n scripts/test-deployment-target.sh`
  and shellcheck on that deployment script passed on India. Final subsequent
  edits are contract/journal documentation only; they do not constitute new
  runtime evidence or transfer these results to later implementation heads.

Baseline/source verification uses one new owner-private task root and bounded
command logs. Existing user data is scan/dry-run only; mutations belong only to
test-created fixture roots. Build outputs are reclaimed after their users finish.
Generic Luna internal audits are not formal named/release review receipts.

### Exact Checkpoint CI Repairs

PR #30's `368ba199a3b8b7e8eecff160f39cf0ea80df23e4` pull-request runs exposed
two distinct failures. Foundation run `37309734071` ran 751 Swift tests and
reported two issues in `ownerReplacementStillRequiresTopologyCapture` and
`connectedComponentPublishesNoPartialRelease`. Their multi-group fixture used
a regular-file owner and invented child paths without owner-namespace
bindings, so the complete-graph gate correctly refused construction. The
fixture now creates a real owner directory and real member files, binds their
actual identities and descriptor-derived ACL/mount seals, and retains the
single-group regular-file case. All original assertions and the production
complete-graph requirement remain intact. The adjacent race test remains
selected as well. A separate Luna read-only internal audit found no concrete
candidate/owner namespace inconsistency; this was not a formal review receipt.

Release run `37309733962` failed its strict Mach-O minimum-version check:
release metadata still declared macOS 14 although the accepted Swift/Rust
baseline was macOS 15. Release metadata, strict installer verification,
synthetic helper binaries and the best-effort compatibility runner now agree
on macOS 15. Required macOS 26 acceptance is unchanged. Added regression tests
reject both older and newer mismatched minima. The historical deterministic
gzip vector's synthetic macOS 14 metadata and pinned bytes are unchanged.

- Release-only source tree: `96cc719ed4726331dc1ceaa6da68c4894d7d21e5`;
  archive SHA-256:
  `f0b12f605d4a26321c24296228cdc1b44a960b7b0fa20476af35c128f4dc2899`.
  India passed `bash -n`, shellcheck, actionlint on the changed workflow,
  all 71 packaging unit tests, and the journal validator. Its 180-second /
  1-MiB bounded runner exited 0 and verified process-group quiescence; log
  SHA-256:
  `9cd5726319b74d54389b17fad5da6e582bc56a8bbc86178830f8c41aa674f251`.
- Fixture source tree: `7c8ae870525430643e5c6afa18e46bead2c3c2a9`;
  archive SHA-256:
  `1d936cecb1157daee5b7fd1c56db93a8bab2675217f0f2c8fb0263dfea0775bd`.
  India ran `swift test --disable-automatic-resolution --scratch-path
  /private/tmp/diskplan-release-baseline-20261005.NlIPngd0/swift-build --jobs 4
  --filter 'ownerReplacementStillRequiresTopologyCapture|connectedComponentPublishesNoPartialRelease|topologyCaptureCannotRaceOwnerReappearance'`
  through the package-lock guard. All three selected Swift Testing tests passed.
  The 900-second / 1-MiB supervisor exited 0 after 51,370 ms, verified
  process-group quiescence, and recorded log SHA-256
  `a7e25c2b6c4b518425192eddd7573d76639b81d9410f4d0531af9119d7074dd3`.

These are targeted repair receipts, not a full-suite result or a claim that
later integration heads have passed the required release gates. The remote
task root is owner-private; existing user data was not mutated.

### Additive Interface Checkpoints

Signed Swift checkpoint `2d42fc5495c6e50df08efe48aa79907e79320f9a` is retained in
published merge `c97fe4a1a5fcb00e36925a9ea8c9850461740e28`, alongside CI repair
`fd5edad939ee304f5198a17af8c2973f3d400d15`. Its India receipt covers seven new
codec tests and strict formatting; a separate internal fixed-commit audit found
no concrete codec mismatch. Raw records are not authorization. The completed
clean domain worktree was removed after checking published ancestry, no local
untracked/ignored files and no active reader; its branch remains recoverable.

The published `c97fe4a1a5fcb00e36925a9ea8c9850461740e28` pull-request head then
passed Foundation CI run `37315149444` and Release CI run `37315149542`.
The exact job results were success for required macOS 26 Apple Silicon,
best-effort macOS 15 deployment, required macOS 26 release, and best-effort
macOS 15 release compatibility. These results apply only to that checkpoint,
not the subsequent additive wire/Rules merges or production permission work.

Signed additive wire checkpoint `5cd933dc5100eab5f44bc0cb196b2472711bfe14`
and Rules checkpoint `2d20d4177d6329bc35db869a179942570132af23` are now integrated.
Their exact scoped source/test/generation receipts remain in their individual
journals. The wire worker explicitly reported its workspace check as failed:
the new generated `SetEffectConsent` case required CLI consumers outside its
file ownership. Swift had the corresponding exhaustive-match integration gap.
The integration layer adds explicit rejection of the uninstalled edit in both
consumers, with negative tests. Live protocol defaults remain unchanged until
the real permission consumers, frontend and execution authority are complete.

Rules absence is a valid state; a requested invalid overlay remains bound as
unverified and blocks mutation while retaining safe baseline planning. Exact
JSON bytes are compiled into Swift so descriptor-bound private engine launches
do not depend on sibling resources or the current directory. This model does
not itself install production callers or issue deletion consent. The worker's
India build root was reclaimed only after bounded test completion and a scoped
process check. Cross-language integration and fixed-head review remain pending.

The wire slice's fixed-commit internal audit identified two follow-up defects:
prost's `TryFrom(0)` admitted the explicitly defined `UNSPECIFIED` requirement
enum, and the public Rust canonical consent codec accepted non-32-byte action
and lineage identifiers unlike Swift. Signed append-only wire checkpoint
`c5a95b645c5abfa22290ac6496786d2e0aac4392` fixes both with negative tests;
integration merge `6515c6199267da39d9c2ffd479b5bba6f8b80d88` preserves that
checkpoint and its India receipt. The higher-level frontend must still invoke the core
canonical verifier; proto-only shape/reference validation is not complete
binding admission. None of these unfinished 1.7 paths is enabled as a live
permission consumer.

### Additive Consumer Integration Validation

The integration shims reject unsupported effect edits explicitly rather than
granting permission from the new generated cases. Swift rejection-code switches
likewise refuse uninstalled effect consumers, and an atomic mixed edit batch
cannot hide an unsupported consent. Added Swift checks read the shared canonical
fixture used by Rust and compare every requirement/consent field and digest.

- Rust source tree: `26bcb3395a6b9d58e14e7499e6d7462e0d0276d7`; archive SHA-256
  `b8e04b272c08e8df20f0faa333246a191f64d00e4f4268de810dfa31138ffc3d`.
  India `cargo fmt --all -- --check` passed, as did bounded
  `cargo check --locked --workspace --all-targets --jobs 4` and the selected
  `diskplan` crate negative test
  `effect_consent_edits_do_not_gain_authority_from_additive_schema` (one test
  executed and passed). Workspace log SHA-256:
  `4c360d98ac8af147d9e57d57c1e044bdba6d6f598722e27948c0554cc7baa9c1`;
  test log SHA-256:
  `5441f72c2d80efe38b3652ef390942ddeb5a91dfdbb3c14eb436ca51ccb13924`.
- Swift source tree: `cb470f2dcbf71344b5a1d44ba5d7f4d0894cea1c`; archive SHA-256
  `88955edbc44f9a2facc96a5cca5de3da6dfad49c5345ae9cd3331cff93b191d3`.
  India strict formatting passed on all four affected Swift files; generated
  Rules assets were current. Package-lock-guarded Swift compilation and the
  selected codec, Rules, unsupported-edit and shared-fixture tests passed:
  18 Swift Testing tests executed. Its 900-second / 1-MiB supervisor exited 0
  after 46,929 ms; log SHA-256:
  `d78d6072c4ddf0ef06c1e555cc79dc764531b7b4566643263ee83e8dbda7eb3d`.
  A separate skip-build command against the same compiled source executed and
  passed the remaining effect-rejection-code test (one test, 3,963 ms, exit 0,
  quiescent); log SHA-256:
  `db9169c11fd1dc0aeffac03d802564e00aac9f6ac5a98a7f5a9dc20f55c794f3`.
- Each successful supervised command reported a verified quiescent process
  group. Earlier attempts caught long diagnostics in strict formatting, a
  wrong Cargo package selector, and remaining generated enum cases in the Swift
  business handler; those failed attempts are not passing test receipts.

The final Swift-specific repairs do not change the previously tested Rust
source, lockfile or fixture bytes. These are additive checkpoint receipts only:
real 1.7 permission/epoch consumers, production Rules wiring, current/JIT
collection and final complete-range review remain unfinished.

The required Foundation CI job now explicitly checks compiled Rules assets,
the canonical effect fixture, and protocol 1.7 runtime fixtures. These checks
do not change live negotiation or grant permission; they prevent generated
data drift from bypassing the normal required integration checkpoint.
India actionlint passed on the updated workflow, the compiled Rules asset
check passed, and both newly wired fixture check commands passed under a
180-second / 1-MiB supervisor (13,097 ms, exit 0, verified quiescence, log
SHA-256 `7bb7bded95db6e0ca0e927ddf6e9c1ad7a6b496c2c3618a4613ce005be128344`).
The workstream journal validator also passed on India after the receipt update.

Draft PR #30 owns this workstream. The clean cache worktree was
removed only after confirming no retained untracked/ignored files, complete
`5ab8ee0` ancestry in the published checkpoint, and no active worker reader.
Its branch and commits remain recoverable; original dirty worktrees remain
untouched. Active, disjoint worktrees now own runtime capture, frontend
effect consumers, and the India acceptance harness. Completed additive
domain/wire/Rules slices retain their signed branches and precise source
receipts; those receipts do not transfer to the subsequent combined head.

## Known Integration Gaps

The next published additive head `91d64fd7fc5b526a12b648dcc2ab3621c4fe4c62`
passed Swift tests and Rust tests in required Foundation job `111801640281`
(run `37321562135`), then failed strict Clippy at the new canonical consent
negative test's single-arm `match`. Later fixture/process steps were skipped,
not successful. The frontend/core owner is correcting that lint error without
changing the negative assertions. The bounded exact-job log fetch exited 0,
was quiescent and has SHA-256
`44d2a194ce91cf79de85b177332bbe35f680b01a086f904f91815743cb609ebd`.
Earlier escape-sequence-rejected fetch attempts are not valid CI-log receipts.

The separate [runtime frozen Rules configuration slice](2026-10-05-runtime-frozen-rules-5732ba.md)
binds complete input intent and separates planning from mutation eligibility.
Its six India configuration-mechanism tests pass; production session callers
and private installed-engine acceptance remain pending.

The committed production session currently constructs an unconfigured cache
authority; fixture positive paths do not prove installed production wiring.
Provider traversal decisions are also conflated with ownership facts in current
mappers. These are implementation gaps, not new design questions: repair them
under the accepted two-tier effect-permission contract and retain independent
identity, content, access, activity, coverage, mount and adapter gates.
