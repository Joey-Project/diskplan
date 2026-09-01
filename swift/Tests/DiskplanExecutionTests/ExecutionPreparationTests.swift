import DiskplanPolicy
import Foundation
import Testing

@_spi(DiskplanEngine) @testable import DiskplanExecution

@Test
func dryRunHasNoApplyCapabilityAndDoesNotInvokeMutation() async throws {
  let fixture = try Fixture()
  let source = SequenceSource([fixture.currentSnapshot()])
  let entropy = RecordingEntropy()
  let engine = ExecutionPreparationEngine(
    evidenceSource: source,
    randomBytes: entropy.bytes
  )
  let result = try await engine.prepare(
    plan: fixture.plan,
    overlay: fixture.overlay,
    mode: .dryRun,
    issuedAtSeconds: 200,
    lifetimeSeconds: 30
  )
  guard case .dryRun(let report) = result else {
    Issue.record("expected structurally capability-free dry-run result")
    return
  }
  #expect(report.revalidation.isCurrent)
  #expect(await source.collectionCount == 1)
  #expect(entropy.requestedCounts == [16])
}

@Test
func applyCapabilityAndAuthorizationAreSingleUse() async throws {
  let fixture = try Fixture()
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([fixture.currentSnapshot()]),
    randomBytes: deterministicEntropy,
    clock: { 205 }
  )
  let (ready, capability) = try await prepareApply(engine, fixture: fixture)
  let authorization = try await engine.authorizeApply(
    capability,
    ready: ready,
    plan: fixture.plan,
    overlay: fixture.overlay,
    nowSeconds: 205
  )
  #expect(await authorization.claimManifest() == ready.revalidation.manifest)
  #expect(await authorization.claimManifest() == nil)
  await #expect(throws: ExecutionPreparationError.capabilityUnknown) {
    try await engine.authorizeApply(
      capability,
      ready: ready,
      plan: fixture.plan,
      overlay: fixture.overlay,
      nowSeconds: 206
    )
  }
}

@Test
func registryBackedAuthorizationExpiresBeforeClaim() async throws {
  let fixture = try Fixture()
  let clock = LockedPreparationClock(200)
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([fixture.currentSnapshot()]),
    randomBytes: deterministicEntropy,
    clock: { clock.value }
  )
  let result = try await engine.prepare(
    plan: fixture.plan,
    overlay: fixture.overlay,
    mode: .apply,
    lifetimeSeconds: 30
  )
  guard case .applyReady(let ready, let capability) = result else {
    Issue.record("expected apply preparation")
    return
  }
  let authorization = try await engine.authorizeApply(
    capability, ready: ready, plan: fixture.plan, overlay: fixture.overlay)
  clock.value = 230
  #expect(await authorization.claimManifest() == nil)
  #expect(await authorization.claimManifest() == nil)
}

@Test
func concurrentAuthorizationClaimsConsumeOneRegistryRecord() async throws {
  let fixture = try Fixture()
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([fixture.currentSnapshot()]),
    randomBytes: deterministicEntropy,
    clock: { 205 }
  )
  let (ready, capability) = try await prepareApply(engine, fixture: fixture)
  let authorization = try await engine.authorizeApply(
    capability,
    ready: ready,
    plan: fixture.plan,
    overlay: fixture.overlay,
    nowSeconds: 205
  )
  async let first = authorization.claimManifest()
  async let second = authorization.claimManifest()
  let values = await (first, second)
  let claimed = [values.0, values.1]
  #expect(claimed.compactMap { $0 }.count == 1)
  #expect(claimed.compactMap { $0 }.first == ready.revalidation.manifest)
}

@Test
func forceWarningsRequireAnExactlyBoundApplyReviewConfirmation() async throws {
  let fixture = try Fixture(
    content: .explicitlyNotApplicable(.metadataOnlyObject),
    forceRequirement: .requiresForceWithWarning
  )
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([fixture.currentSnapshot(), fixture.currentSnapshot()]),
    randomBytes: deterministicEntropy,
    clock: { 205 }
  )
  let (missingReady, missingCapability) = try await prepareApply(engine, fixture: fixture)
  #expect(missingReady.forceWarningActionIDs == [fixture.action.id])
  await #expect(throws: ExecutionPreparationError.forceConfirmationRequired) {
    try await engine.authorizeApply(
      missingCapability,
      ready: missingReady,
      plan: fixture.plan,
      overlay: fixture.overlay,
      nowSeconds: 205
    )
  }

  let (ready, capability) = try await prepareApply(engine, fixture: fixture)
  let forgedReview = ApplyReadyReport(
    revalidation: ready.revalidation,
    forceWarningActionIDs: ready.forceWarningActionIDs,
    reviewBindingHash: digest(0xfe)
  )
  await #expect(throws: ExecutionPreparationError.forceConfirmationMismatch) {
    try await engine.authorizeApply(
      capability,
      ready: ready,
      plan: fixture.plan,
      overlay: fixture.overlay,
      confirmation: ApplyReviewConfirmation.confirm(forgedReview),
      nowSeconds: 205
    )
  }
}

@Test
func newerPreparationRevokesAnUnclaimedMintedAuthorization() async throws {
  let fixture = try Fixture()
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([fixture.currentSnapshot(), fixture.currentSnapshot()]),
    randomBytes: deterministicEntropy,
    clock: { 205 }
  )
  let (ready, capability) = try await prepareApply(engine, fixture: fixture)
  let authorization = try await engine.authorizeApply(
    capability,
    ready: ready,
    plan: fixture.plan,
    overlay: fixture.overlay,
    nowSeconds: 205
  )
  _ = try await engine.prepare(
    plan: fixture.plan,
    overlay: fixture.overlay,
    mode: .dryRun,
    issuedAtSeconds: 210,
    lifetimeSeconds: 30
  )

  #expect(await authorization.claimManifest() == nil)
}

@Test
func publicCapabilityLifetimeUsesTheEngineClock() async throws {
  let fixture = try Fixture()
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([fixture.currentSnapshot()]),
    randomBytes: deterministicEntropy,
    clock: { 200 }
  )
  let result = try await engine.prepare(
    plan: fixture.plan,
    overlay: fixture.overlay,
    mode: .apply,
    lifetimeSeconds: 30
  )
  guard case .applyReady(let ready, let capability) = result else {
    Issue.record("expected apply preparation")
    return
  }
  let authorization = try await engine.authorizeApply(
    capability,
    ready: ready,
    plan: fixture.plan,
    overlay: fixture.overlay
  )
  #expect(await authorization.claimManifest() != nil)
}

@Test
func sealedCollectorHandleFeedsTheProductionPreparationBoundary() async throws {
  let fixture = try Fixture()
  let action = fixture.action
  let collector = EngineRevalidationCollector { request in
    CurrentRevalidationSnapshot(
      captureID: digest(90),
      actions: [
        currentEvidence(
          action,
          executionReferenceTimeSeconds: request.epoch.semanticReferenceTimeSeconds
        )
      ],
      releaseTopologies: [],
      invariants: passingInvariants
    )
  }
  let engine = ExecutionPreparationEngine(collector: collector)
  let result = try await engine.prepare(
    plan: fixture.plan,
    overlay: fixture.overlay,
    mode: .dryRun,
    lifetimeSeconds: 30
  )
  guard case .dryRun(let report) = result else {
    Issue.record("the sealed engine collector must feed production preparation")
    return
  }
  #expect(report.revalidation.isCurrent)
}

@Test
func productionCompositionBindsTheSealedCollectorToPreparation() async throws {
  let fixture = try Fixture()
  let action = fixture.action
  let collector = EngineRevalidationCollector { request in
    CurrentRevalidationSnapshot(
      captureID: digest(90),
      actions: [
        currentEvidence(
          action,
          executionReferenceTimeSeconds: request.epoch.semanticReferenceTimeSeconds
        )
      ],
      releaseTopologies: [],
      invariants: passingInvariants
    )
  }
  let composition = EngineExecutionComposition(
    collector: collector,
    eventSink: NoOpExecutionEventSink()
  )
  let result = try await composition.preparation.prepare(
    plan: fixture.plan,
    overlay: fixture.overlay,
    mode: .dryRun,
    lifetimeSeconds: 30
  )

  guard case .dryRun(let report) = result else {
    Issue.record("production composition must expose the sealed preparation boundary")
    return
  }
  #expect(report.revalidation.isCurrent)
}

@Test
func forgedWrongBindingAndExpiredCapabilitiesFailClosed() async throws {
  let fixture = try Fixture()
  let source = SequenceSource([
    fixture.currentSnapshot(), fixture.currentSnapshot(), fixture.currentSnapshot(),
  ])
  let engine = ExecutionPreparationEngine(
    evidenceSource: source,
    randomBytes: deterministicEntropy,
    clock: { 201 }
  )

  let forged = ApplyCapability(opaqueBytes: Data(repeating: 0xff, count: 32))
  let (firstReady, _) = try await prepareApply(engine, fixture: fixture)
  await #expect(throws: ExecutionPreparationError.capabilityUnknown) {
    try await engine.authorizeApply(
      forged,
      ready: firstReady,
      plan: fixture.plan,
      overlay: fixture.overlay,
      nowSeconds: 201
    )
  }

  let (wrongReady, wrongCapability) = try await prepareApply(engine, fixture: fixture)
  var changedReport = wrongReady.revalidation
  let wrongEpoch = try ExecutionEpochContext(
    epochID: "wrong-epoch",
    semanticReferenceTimeSeconds: changedReport.epoch.semanticReferenceTimeSeconds,
    issuedAtSeconds: changedReport.epoch.issuedAtSeconds,
    deadlineSeconds: changedReport.epoch.deadlineSeconds
  )
  changedReport = RevalidationReport(
    planHash: changedReport.planHash,
    overlayHash: changedReport.overlayHash,
    epoch: wrongEpoch,
    actionOutcomes: changedReport.actionOutcomes,
    globalFindings: changedReport.globalFindings,
    manifest: changedReport.manifest
  )
  let forgedReady = ApplyReadyReport(revalidation: changedReport)
  await #expect(throws: ExecutionPreparationError.applyReportNotCurrent) {
    try await engine.authorizeApply(
      wrongCapability,
      ready: forgedReady,
      plan: fixture.plan,
      overlay: fixture.overlay,
      nowSeconds: 202
    )
  }

  let (expiredReady, expiredCapability) = try await prepareApply(engine, fixture: fixture)
  await #expect(throws: ExecutionPreparationError.capabilityExpired) {
    try await engine.authorizeApply(
      expiredCapability,
      ready: expiredReady,
      plan: fixture.plan,
      overlay: fixture.overlay,
      nowSeconds: 231
    )
  }
}

@Test
func capabilityRejectsWrongPlanAndOverlayBindings() async throws {
  let fixture = try Fixture()
  let other = try Fixture(candidateID: "b", path: "b", object: 2)
  let source = SequenceSource([fixture.currentSnapshot(), fixture.currentSnapshot()])
  let engine = ExecutionPreparationEngine(
    evidenceSource: source,
    randomBytes: deterministicEntropy,
    clock: { 201 }
  )

  let (wrongPlanReady, wrongPlanCapability) = try await prepareApply(engine, fixture: fixture)
  await #expect(throws: ExecutionPreparationError.capabilityBindingMismatch) {
    try await engine.authorizeApply(
      wrongPlanCapability,
      ready: wrongPlanReady,
      plan: other.plan,
      overlay: fixture.overlay,
      nowSeconds: 201
    )
  }

  let (wrongOverlayReady, wrongOverlayCapability) = try await prepareApply(engine, fixture: fixture)
  let changedOverlay = DecisionOverlay.create(
    plan: fixture.plan,
    selectedActionIDs: [fixture.action.id],
    waiverConsents: [],
    userNotes: ["changed audit note"]
  )
  await #expect(throws: ExecutionPreparationError.capabilityBindingMismatch) {
    try await engine.authorizeApply(
      wrongOverlayCapability,
      ready: wrongOverlayReady,
      plan: fixture.plan,
      overlay: changedOverlay,
      nowSeconds: 201
    )
  }
}

@Test
func everyRevalidationAttemptInvalidatesPriorCapabilities() async throws {
  let fixture = try Fixture()
  let changed = fixture.currentSnapshot(
    identity: .known(
      ObjectIdentity(
        device: 1, object: 999, generation: .known(1), type: .directory)))
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([fixture.currentSnapshot(), changed]),
    randomBytes: deterministicEntropy
  )
  let (ready, capability) = try await prepareApply(engine, fixture: fixture)
  let rejected = try await engine.prepare(
    plan: fixture.plan,
    overlay: fixture.overlay,
    mode: .apply,
    issuedAtSeconds: 210,
    lifetimeSeconds: 30
  )
  guard case .rejected(let report) = rejected else {
    Issue.record("expected changed identity to reject revalidation")
    return
  }
  #expect(report.actionOutcomes[0].findings.map(\.kind).contains(.identityMismatch))
  await #expect(throws: ExecutionPreparationError.capabilityUnknown) {
    try await engine.authorizeApply(
      capability,
      ready: ready,
      plan: fixture.plan,
      overlay: fixture.overlay,
      nowSeconds: 211
    )
  }
}

@Test
func aNewPlanRevalidationInvalidatesAnOlderPlanCapability() async throws {
  let first = try Fixture()
  let second = try Fixture(candidateID: "b", path: "b", object: 2)
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([first.currentSnapshot(), second.currentSnapshot()]),
    randomBytes: deterministicEntropy
  )
  let (ready, capability) = try await prepareApply(engine, fixture: first)
  _ = try await engine.prepare(
    plan: second.plan,
    overlay: second.overlay,
    mode: .dryRun,
    issuedAtSeconds: 210,
    lifetimeSeconds: 30
  )
  await #expect(throws: ExecutionPreparationError.capabilityUnknown) {
    try await engine.authorizeApply(
      capability,
      ready: ready,
      plan: first.plan,
      overlay: first.overlay,
      nowSeconds: 211
    )
  }
}

@Test
func newerFailedPreparationSupersedesOlderInFlightSuccess() async throws {
  let fixture = try Fixture()
  let source = ControlledSource()
  let engine = ExecutionPreparationEngine(
    evidenceSource: source,
    randomBytes: deterministicEntropy,
    clock: { 201 }
  )
  let older = Task {
    try await engine.prepare(
      plan: fixture.plan,
      overlay: fixture.overlay,
      mode: .apply,
      issuedAtSeconds: 200,
      lifetimeSeconds: 30
    )
  }
  await source.waitUntilEntered(1)
  let newer = Task {
    try await engine.prepare(
      plan: fixture.plan,
      overlay: fixture.overlay,
      mode: .apply,
      issuedAtSeconds: 200,
      lifetimeSeconds: 30
    )
  }
  await source.waitUntilEntered(2)
  await source.resolve(1, with: .failure(.collectorFailed))
  guard case .rejected = try await newer.value else {
    Issue.record("newer collector failure must reject")
    return
  }
  await source.resolve(0, with: .success(fixture.currentSnapshot()))
  await #expect(throws: ExecutionPreparationError.preparationSuperseded) {
    try await older.value
  }
}

@Test
func newerSuccessfulPreparationSupersedesOlderInFlightSuccess() async throws {
  let fixture = try Fixture()
  let source = ControlledSource()
  let engine = ExecutionPreparationEngine(
    evidenceSource: source,
    randomBytes: deterministicEntropy,
    clock: { 201 }
  )
  let older = Task {
    try await engine.prepare(
      plan: fixture.plan,
      overlay: fixture.overlay,
      mode: .apply,
      issuedAtSeconds: 200,
      lifetimeSeconds: 30
    )
  }
  await source.waitUntilEntered(1)
  let newer = Task {
    try await engine.prepare(
      plan: fixture.plan,
      overlay: fixture.overlay,
      mode: .apply,
      issuedAtSeconds: 200,
      lifetimeSeconds: 30
    )
  }
  await source.waitUntilEntered(2)
  await source.resolve(1, with: .success(fixture.currentSnapshot()))
  guard case .applyReady(let ready, let capability) = try await newer.value else {
    Issue.record("newer current preparation must win")
    return
  }
  await source.resolve(0, with: .success(fixture.currentSnapshot()))
  await #expect(throws: ExecutionPreparationError.preparationSuperseded) {
    try await older.value
  }
  let authorization = try await engine.authorizeApply(
    capability,
    ready: ready,
    plan: fixture.plan,
    overlay: fixture.overlay,
    nowSeconds: 201
  )
  #expect(await authorization.claimManifest() != nil)
}

@Test(arguments: [
  (Observation<ObjectIdentity>.absent, RevalidationFailureKind.missing),
  (
    .unreadable(ObservationFailure(code: "EACCES", collector: "stat")),
    .unreadable
  ),
  (
    .failed(ObservationFailure(code: "EIO", collector: "stat")),
    .collectionFailed
  ),
])
func missingUnreadableAndFailedRemainDistinct(
  identity: Observation<ObjectIdentity>, expectedKind: RevalidationFailureKind
) async throws {
  let fixture = try Fixture()
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([fixture.currentSnapshot(identity: identity)]),
    randomBytes: deterministicEntropy
  )
  let result = try await engine.prepare(
    plan: fixture.plan,
    overlay: fixture.overlay,
    mode: .dryRun,
    issuedAtSeconds: 200,
    lifetimeSeconds: 30
  )
  guard case .rejected(let report) = result else {
    Issue.record("expected typed identity observation failure")
    return
  }
  #expect(report.actionOutcomes[0].findings.map(\.kind).contains(expectedKind))
}

@Test
func identityContentAndAccessMismatchesRemainDistinct() async throws {
  let fixture = try Fixture()
  let wrongIdentity = ObjectIdentity(
    device: 1, object: 998, generation: .known(1), type: .directory)
  let wrongAccess = RequiredAccessPolicyBaseline(
    accessPolicyBytes: Data("changed".utf8),
    aclDigest: digest(93),
    providerState: .local,
    mountIdentityBytes: Data("mount-1".utf8)
  )
  let snapshot = fixture.currentSnapshot(
    identity: .known(wrongIdentity),
    content: .known(.requiredDigest(digest(201))),
    access: .known(wrongAccess)
  )
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([snapshot]),
    randomBytes: deterministicEntropy
  )
  let result = try await engine.prepare(
    plan: fixture.plan,
    overlay: fixture.overlay,
    mode: .dryRun,
    issuedAtSeconds: 200,
    lifetimeSeconds: 30
  )
  guard case .rejected(let report) = result else {
    Issue.record("expected protected-property mismatches")
    return
  }
  let kinds = Set(report.actionOutcomes[0].findings.map(\.kind))
  #expect(kinds.contains(.identityMismatch))
  #expect(kinds.contains(.contentMismatch))
  #expect(kinds.contains(.accessPolicyMismatch))
}

@Test
func activityProviderAndDependencyAreRevalidatedIndependently() async throws {
  let fixture = try Fixture()
  let snapshot = fixture.currentSnapshot(
    activity: .known(.active),
    providerState: .known(.fileProviderManaged),
    dependencyState: .unknown(.incompleteCoverage)
  )
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([snapshot]),
    randomBytes: deterministicEntropy
  )
  let result = try await engine.prepare(
    plan: fixture.plan,
    overlay: fixture.overlay,
    mode: .dryRun,
    issuedAtSeconds: 200,
    lifetimeSeconds: 30
  )
  guard case .rejected(let report) = result else {
    Issue.record("changed live policy facts must reject")
    return
  }
  let kinds = Set(report.actionOutcomes[0].findings.map(\.kind))
  #expect(kinds.contains(.activityMismatch))
  #expect(kinds.contains(.providerMismatch))
  #expect(kinds.contains(.unknown))
  #expect(
    report.actionOutcomes[0].findings.contains {
      $0.subject == .dependency && $0.kind == .unknown
    })
}

@Test
func explicitlyUnprotectedContentIgnoresBenignMetadataChurn() async throws {
  let fixture = try Fixture(content: .explicitlyNotApplicable(.metadataOnlyObject))
  let changedContent: Observation<ContentProtectionBaseline> =
    .known(.requiredDigest(digest(222)))
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([fixture.currentSnapshot(content: changedContent)]),
    randomBytes: deterministicEntropy
  )
  let result = try await engine.prepare(
    plan: fixture.plan,
    overlay: fixture.overlay,
    mode: .dryRun,
    issuedAtSeconds: 200,
    lifetimeSeconds: 30
  )
  guard case .dryRun(let report) = result else {
    Issue.record("unselected metadata must not become a content mutation")
    return
  }
  #expect(report.revalidation.isCurrent)
}

@Test
func selectedGitPrerequisitesAreRevalidatedAsTypedEvidence() async throws {
  let git = gitEvidence(worktreeObject: 1)
  let facts = globalFacts()
  let evidence = snapshot(gitWorktree: git, adapterScope: .gitWorktree)
  let action = try makeAction(
    evidence: evidence, facts: facts, request: .gitWorktreeRemove)
  let plan = try ImmutablePlan(
    policyVersion: "policy-1",
    schemaVersion: "schema-1",
    globalFacts: facts,
    evidenceSnapshots: [evidence],
    actions: [action],
    releaseGraphBundle: nil
  )
  let overlay = DecisionOverlay.create(
    plan: plan, selectedActionIDs: [action.id], waiverConsents: [], userNotes: [])
  let changedGit = gitEvidence(worktreeObject: 1, indexDigest: .known(digest(202)))
  let current = CurrentActionEvidence(
    actionID: action.id,
    targetIdentity: .known(action.prototype.protectedProperties.identity.expectedIdentity),
    targetContent: .known(action.prototype.protectedProperties.content.expectedBaseline),
    targetAccessPolicy: .known(action.prototype.protectedProperties.accessPolicy.requiredBaseline),
    coverage: .known(action.evidence.coverage),
    collectorStatus: action.evidence.collectorStatus,
    activity: action.evidence.activity,
    explicitProtection: action.evidence.explicitProtection,
    providerState: action.evidence.providerState,
    recoverability: action.evidence.recoverability,
    dependencyState: action.evidence.dependencyState,
    freshPolicyEvidence: .known(retimedPolicyEvidence(action, referenceTimeSeconds: 200)),
    root: CurrentNamespaceComponent(
      relativePath: nil,
      identity: .known(action.prototype.namespaceBinding.rootIdentity),
      seal: .known(action.prototype.namespaceBinding.rootSeal)
    ),
    parents: [],
    gitWorktree: .known(changedGit)
  )
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([
      CurrentRevalidationSnapshot(
        captureID: digest(90), actions: [current], releaseTopologies: [],
        invariants: passingInvariants)
    ]),
    randomBytes: deterministicEntropy
  )
  let result = try await engine.prepare(
    plan: plan,
    overlay: overlay,
    mode: .apply,
    issuedAtSeconds: 200,
    lifetimeSeconds: 30
  )
  guard case .rejected(let report) = result else {
    Issue.record("changed Git prerequisites must reject")
    return
  }
  #expect(report.actionOutcomes[0].findings.map(\.kind).contains(.gitPrerequisiteMismatch))
}

@Test
func dirtyDiscardRemovePreparationRemainsReportOnly() async throws {
  let dirtyContent = ContentProtectionBaseline.requiredDigest(digest(92))
  let git = gitEvidence(
    worktreeObject: 1,
    localChanges: .present(changeSetDigest: digest(73))
  )
  let facts = globalFacts()
  let evidence = snapshot(
    content: dirtyContent,
    gitWorktree: git,
    adapterScope: .gitWorktree
  )
  let discard = try makeAction(
    evidence: evidence,
    facts: facts,
    request: .gitWorktreeDiscardLocalChanges
  )
  let remove = try makeAction(
    evidence: evidence,
    facts: facts,
    prerequisites: [discard],
    request: .gitWorktreeRemove
  )
  #expect(discard.evaluation.stageability == .blocked)
  #expect(remove.evaluation.stageability == .blocked)
  let plan = try ImmutablePlan(
    policyVersion: "policy-1",
    schemaVersion: "schema-1",
    globalFacts: facts,
    evidenceSnapshots: [evidence],
    actions: [discard, remove],
    releaseGraphBundle: nil
  )
  let overlay = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: [discard.id, remove.id],
    waiverConsents: [],
    userNotes: []
  )
  #expect(throws: PolicyModelError.actionNotStageable(remove.id)) {
    try DecisionOverlayValidator.validate(overlay, against: plan)
  }
  let source = SequenceSource([])
  let engine = ExecutionPreparationEngine(
    evidenceSource: source,
    randomBytes: deterministicEntropy
  )
  await #expect(throws: PolicyModelError.actionNotStageable(remove.id)) {
    _ = try await engine.prepare(
      plan: plan,
      overlay: overlay,
      mode: .apply,
      issuedAtSeconds: 200,
      lifetimeSeconds: 30
    )
  }
  #expect(await source.collectionCount == 0)
}

@Test
func freshExecutionEpochConsumesAndBindsEveryWaiverRequirement() async throws {
  let fixture = try ConsentFixture()
  let snapshot = CurrentRevalidationSnapshot(
    captureID: digest(90),
    actions: [currentEvidence(fixture.action)],
    releaseTopologies: [],
    invariants: passingInvariants
  )
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([snapshot]),
    randomBytes: deterministicEntropy
  )
  let result = try await engine.prepare(
    plan: fixture.plan,
    overlay: fixture.overlay,
    mode: .dryRun,
    issuedAtSeconds: 200,
    lifetimeSeconds: 30
  )
  guard case .dryRun(let report) = result,
    let manifest = report.revalidation.manifest,
    let requirement = manifest.consentRequirements.first(where: {
      $0.consentHash == fixture.consent.consentHash
    })
  else {
    Issue.record("fresh waiver requirement must authorize dry-run")
    return
  }
  #expect(report.revalidation.epoch.semanticReferenceTimeSeconds == 200)
  #expect(manifest.currentCaptureID == digest(90))
  #expect(manifest.currentPolicyBindings.count == 1)
  #expect(manifest.consentRequirements.count == fixture.consents.count)
  #expect(
    manifest.consentRequirements.map(\.consentHash).sorted()
      == fixture.consents.map(\.consentHash).sorted())
  #expect(requirement.consentHash == fixture.consent.consentHash)
  #expect(requirement.actionID == fixture.action.id)
  #expect(requirement.planHash == fixture.plan.planHash)
  #expect(requirement.planEvidenceHash == fixture.plan.evidenceHash)
  #expect(requirement.overlayHash == fixture.overlay.overlayHash)
  #expect(requirement.originalSemanticReferenceTimeSeconds == 100)
  #expect(requirement.executionReferenceTimeSeconds == 200)
  #expect(requirement.currentPredicate == fixture.predicate)
}

@Test
func typedUnknownRecoverabilityConsentRevalidatesAcrossFreshCapture() async throws {
  let facts = globalFacts()
  let semantic = try UnknownRecoverabilitySemanticEvidence(
    reason: .unsupported,
    kind: .rebuildCostUnknown,
    sourceBindingHash: digest(152)
  )
  let evidence = snapshot(
    recoverability: .unknown(.unsupported),
    recoverabilityReviewFacts: [.unknownRecoverability(semantic)]
  )
  let action = try makeAction(evidence: evidence, facts: facts)
  guard case .requiresConsents(let predicates) = action.evaluation.stageability,
    let predicate = predicates.first(where: { $0.predicate == "recoverability-unknown" })
  else {
    Issue.record("typed unknown recoverability must produce a stable consent predicate")
    return
  }
  let consent = WaiverConsentCore.create(
    action: action,
    predicate: predicate,
    reason: "accept stable public API limitation",
    consentEventID: "unknown-recoverability-consent"
  )
  let plan = try ImmutablePlan(
    policyVersion: "policy-1",
    schemaVersion: "schema-1",
    globalFacts: facts,
    evidenceSnapshots: [evidence],
    actions: [action],
    releaseGraphBundle: nil
  )
  let overlay = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: [action.id],
    waiverConsents: [consent],
    userNotes: []
  )
  let current = CurrentRevalidationSnapshot(
    captureID: digest(90),
    actions: [currentEvidence(action)],
    releaseTopologies: [],
    invariants: passingInvariants
  )
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([current]),
    randomBytes: deterministicEntropy
  )

  let result = try await engine.prepare(
    plan: plan,
    overlay: overlay,
    mode: .dryRun,
    issuedAtSeconds: 200,
    lifetimeSeconds: 30
  )
  guard case .dryRun(let report) = result else {
    Issue.record("stable typed unknown recoverability must remain authorizable")
    return
  }
  #expect(report.revalidation.isCurrent)
  #expect(report.revalidation.manifest?.consentRequirements.first?.currentPredicate == predicate)
}

@Test
func typedUnknownRecoverabilityRejectsSemanticSourceDrift() async throws {
  let facts = globalFacts()
  let plannedSemantic = try UnknownRecoverabilitySemanticEvidence(
    reason: .unsupported,
    kind: .rebuildCostUnknown,
    sourceBindingHash: digest(152)
  )
  let evidence = snapshot(
    recoverability: .unknown(.unsupported),
    recoverabilityReviewFacts: [.unknownRecoverability(plannedSemantic)]
  )
  let action = try makeAction(evidence: evidence, facts: facts)
  guard case .requiresConsents(let predicates) = action.evaluation.stageability else {
    Issue.record("typed unknown recoverability must require consent")
    return
  }
  let consents = predicates.map {
    WaiverConsentCore.create(
      action: action,
      predicate: $0,
      reason: "accept the planned public API limitation",
      consentEventID: "planned-unknown-\($0.semanticEvidenceHash.hex)"
    )
  }
  let plan = try ImmutablePlan(
    policyVersion: "policy-1",
    schemaVersion: "schema-1",
    globalFacts: facts,
    evidenceSnapshots: [evidence],
    actions: [action],
    releaseGraphBundle: nil
  )
  let overlay = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: [action.id],
    waiverConsents: consents,
    userNotes: []
  )
  let changedSemantic = try UnknownRecoverabilitySemanticEvidence(
    reason: .unsupported,
    kind: .rebuildCostUnknown,
    sourceBindingHash: digest(154)
  )
  let current = CurrentRevalidationSnapshot(
    captureID: digest(90),
    actions: [
      currentEvidence(
        action,
        freshPolicyEvidence: .known(
          retimedPolicyEvidence(
            action,
            referenceTimeSeconds: 200,
            recoverabilityReviewFacts: [.unknownRecoverability(changedSemantic)]
          )))
    ],
    releaseTopologies: [],
    invariants: passingInvariants
  )
  let result = try await ExecutionPreparationEngine(
    evidenceSource: SequenceSource([current]),
    randomBytes: deterministicEntropy
  ).prepare(
    plan: plan,
    overlay: overlay,
    mode: .dryRun,
    issuedAtSeconds: 200,
    lifetimeSeconds: 30
  )

  guard case .rejected(let report) = result else {
    Issue.record("changed typed recoverability semantics must reject stale consent")
    return
  }
  #expect(report.actionOutcomes.first?.findings.map(\.kind).contains(.staleConsent) == true)
  #expect(report.manifest == nil)
}

@Test
func unknownRecoverabilityAbsentUnreadableAndFailedRemainDistinct() async throws {
  let facts = globalFacts()
  let semantic = try UnknownRecoverabilitySemanticEvidence(
    reason: .unsupported,
    kind: .rebuildCostUnknown,
    sourceBindingHash: digest(153)
  )
  let evidence = snapshot(
    recoverability: .unknown(.unsupported),
    recoverabilityReviewFacts: [.unknownRecoverability(semantic)]
  )
  let action = try makeAction(evidence: evidence, facts: facts)
  guard case .requiresConsents(let predicates) = action.evaluation.stageability else {
    Issue.record("missing unknown recoverability predicate")
    return
  }
  let consents = predicates.map {
    WaiverConsentCore.create(
      action: action,
      predicate: $0,
      reason: "test consent",
      consentEventID: "unknown-\($0.semanticEvidenceHash.hex)"
    )
  }
  let plan = try ImmutablePlan(
    policyVersion: "policy-1",
    schemaVersion: "schema-1",
    globalFacts: facts,
    evidenceSnapshots: [evidence],
    actions: [action],
    releaseGraphBundle: nil
  )
  let overlay = DecisionOverlay.create(
    plan: plan, selectedActionIDs: [action.id], waiverConsents: consents, userNotes: [])
  let failure = ObservationFailure(code: "recoverability-read", collector: "test")
  let cases: [(Observation<RecoverabilityState>, RevalidationFailureKind)] = [
    (.absent, .missing),
    (.unreadable(failure), .unreadable),
    (.failed(failure), .collectionFailed),
  ]
  for (recoverability, expectedKind) in cases {
    let snapshot = CurrentRevalidationSnapshot(
      captureID: digest(90),
      actions: [currentEvidence(action, recoverability: recoverability)],
      releaseTopologies: [],
      invariants: passingInvariants
    )
    let engine = ExecutionPreparationEngine(
      evidenceSource: SequenceSource([snapshot]),
      randomBytes: deterministicEntropy
    )
    let result = try await engine.prepare(
      plan: plan,
      overlay: overlay,
      mode: .apply,
      issuedAtSeconds: 200,
      lifetimeSeconds: 30
    )
    guard case .rejected(let report) = result else {
      Issue.record("unavailable recoverability must reject")
      continue
    }
    #expect(report.actionOutcomes.first?.findings.map(\.kind).contains(expectedKind) == true)
    #expect(report.manifest == nil)
  }
}

@Test
func changedWaiverValueBucketRejectsStaleConsentAtFreshReferenceTime() async throws {
  let fixture = try ConsentFixture()
  let changed = retimedPolicyEvidence(
    fixture.action,
    referenceTimeSeconds: 200,
    recoverabilityReviewFacts: [
      .unknownRebuildCost(valueBucket: "days", evidenceHash: digest(150)),
      .unknownRebuildCost(valueBucket: "cost", evidenceHash: digest(151)),
    ]
  )
  let snapshot = CurrentRevalidationSnapshot(
    captureID: digest(90),
    actions: [currentEvidence(fixture.action, freshPolicyEvidence: .known(changed))],
    releaseTopologies: [],
    invariants: passingInvariants
  )
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([snapshot]),
    randomBytes: deterministicEntropy
  )
  let result = try await engine.prepare(
    plan: fixture.plan,
    overlay: fixture.overlay,
    mode: .apply,
    issuedAtSeconds: 200,
    lifetimeSeconds: 30
  )
  guard case .rejected(let report) = result else {
    Issue.record("changed value bucket must reject stale consent")
    return
  }
  #expect(report.actionOutcomes[0].findings.map(\.kind).contains(.staleConsent))
}

@Test
func forgedFreshPolicyEvidenceCannotAuthorizeApply() async throws {
  let fixture = try Fixture()
  let other = try Fixture(candidateID: "other", path: "other", object: 2)
  let forged = retimedPolicyEvidence(other.action, referenceTimeSeconds: 200)
  let snapshot = CurrentRevalidationSnapshot(
    captureID: digest(90),
    actions: [currentEvidence(fixture.action, freshPolicyEvidence: .known(forged))],
    releaseTopologies: [],
    invariants: passingInvariants
  )
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([snapshot]),
    randomBytes: deterministicEntropy
  )
  let result = try await engine.prepare(
    plan: fixture.plan,
    overlay: fixture.overlay,
    mode: .apply,
    issuedAtSeconds: 200,
    lifetimeSeconds: 30
  )
  guard case .rejected(let report) = result else {
    Issue.record("foreign current-policy evidence must reject")
    return
  }
  #expect(report.actionOutcomes[0].findings.map(\.kind).contains(.policyEvidenceMismatch))
}

@Test
func replayedPlanCaptureCannotBecomeFreshByRetiming() async throws {
  let fixture = try Fixture()
  let replayed = retimedPolicyEvidence(
    fixture.action,
    referenceTimeSeconds: 200,
    captureID: fixture.facts.captureID
  )
  let snapshot = CurrentRevalidationSnapshot(
    captureID: digest(90),
    actions: [currentEvidence(fixture.action, freshPolicyEvidence: .known(replayed))],
    releaseTopologies: [],
    invariants: passingInvariants
  )
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([snapshot]),
    randomBytes: deterministicEntropy
  )
  let result = try await engine.prepare(
    plan: fixture.plan,
    overlay: fixture.overlay,
    mode: .apply,
    issuedAtSeconds: 200,
    lifetimeSeconds: 30
  )
  guard case .rejected(let report) = result else {
    Issue.record("a retimed plan capture must not count as fresh evidence")
    return
  }
  #expect(report.actionOutcomes[0].findings.map(\.kind).contains(.policyEvidenceMismatch))
}

@Test
func selectedPlanRequiresOneFreshCaptureAndGlobalFactsBinding() async throws {
  let release = try ReleaseFixture()
  let currentActions =
    release.ownerActions.map { action in
      currentEvidence(action)
    } + [
      currentEvidence(
        release.releaseAction,
        freshPolicyEvidence: .known(
          retimedPolicyEvidence(
            release.releaseAction,
            referenceTimeSeconds: 200,
            captureID: digest(99)
          ))
      )
    ]
  let snapshot = CurrentRevalidationSnapshot(
    captureID: digest(90),
    actions: currentActions,
    releaseTopologies: [
      CurrentReleaseTopology(
        allocationGroupID: release.releaseSet.allocationGroupID,
        topology: .known(release.releaseSet.topologyExpectation)
      )
    ],
    invariants: passingInvariants
  )
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([snapshot]),
    randomBytes: deterministicEntropy
  )
  let result = try await engine.prepare(
    plan: release.plan,
    overlay: release.overlay,
    mode: .dryRun,
    issuedAtSeconds: 200,
    lifetimeSeconds: 30
  )
  guard case .rejected(let report) = result else {
    Issue.record("mixed fresh captures must reject whole-plan preparation")
    return
  }
  #expect(report.globalFindings.map(\.kind).contains(.policyEvidenceMismatch))
}

@Test
func jitRejectsMixedGlobalFactsWithinOneFreshCapture() async throws {
  let release = try ReleaseFixture()
  let initialSnapshot = CurrentRevalidationSnapshot(
    captureID: digest(90),
    actions: release.ownerActions.map { currentEvidence($0) }
      + [currentEvidence(release.releaseAction)],
    releaseTopologies: [
      CurrentReleaseTopology(
        allocationGroupID: release.releaseSet.allocationGroupID,
        topology: .known(release.releaseSet.topologyExpectation)
      )
    ],
    invariants: passingInvariants
  )
  let preparation = try await ExecutionPreparationEngine(
    evidenceSource: SequenceSource([initialSnapshot]),
    randomBytes: deterministicEntropy
  ).prepare(
    plan: release.plan,
    overlay: release.overlay,
    mode: .dryRun,
    issuedAtSeconds: 200,
    lifetimeSeconds: 30
  )
  guard case .dryRun(let prepared) = preparation,
    let manifest = prepared.revalidation.manifest
  else {
    Issue.record("expected a current preparation manifest")
    return
  }

  let captureID = digest(91)
  let currentActions = zip(
    release.ownerActions,
    [Data("config-a".utf8), Data("config-b".utf8)]
  ).map { action, configuration in
    currentEvidence(
      action,
      freshCaptureID: captureID,
      freshPolicyEvidence: .known(
        retimedPolicyEvidence(
          action,
          referenceTimeSeconds: 200,
          captureID: captureID,
          globalFactsConfiguration: configuration
        )
      )
    )
  }
  let validated = try DecisionOverlayValidator.validate(release.overlay, against: release.plan)
  let nonce = Data(repeating: 0xa6, count: 32)
  let request = JITRevalidationRequest(
    plan: release.plan,
    validatedOverlay: validated,
    manifest: manifest,
    actionIDs: release.ownerActions.map(\.id),
    releaseGroupIDs: [],
    preparationGeneration: 1,
    oneShotNonce: nonce
  )
  let report = Revalidator.evaluateJIT(
    request: request,
    collected: JITRevalidationSnapshot(
      oneShotNonce: nonce,
      authorizationCurrentBindingHash: manifest.currentBindingHash,
      preparationGeneration: 1,
      epochID: manifest.epoch.epochID,
      snapshot: CurrentRevalidationSnapshot(
        captureID: captureID,
        actions: currentActions,
        releaseTopologies: [],
        invariants: passingInvariants
      )
    )
  )

  #expect(!report.isCurrent)
  #expect(report.globalFindings.map(\.kind).contains(.policyEvidenceMismatch))
}

@Test
func partialSelectionCannotForgeACompleteReleaseAction() throws {
  let release = try ReleaseFixture()
  let partial = DecisionOverlay.create(
    plan: release.plan,
    selectedActionIDs: [release.releaseAction.id, release.ownerActions[0].id],
    waiverConsents: [],
    userNotes: []
  )
  #expect(throws: PolicyModelError.self) {
    try DecisionOverlayValidator.validate(partial, against: release.plan)
  }
}

@Test
func releaseFixtureRejectsMissingAndMismatchedTypedCloneIdentity() throws {
  let facts = globalFacts()
  let aEvidence = snapshot(
    candidateID: "a",
    path: "a",
    object: 1,
    additionalAdapterScopes: [.completeReleaseSetRemove(allocationGroupID: "clone-group")]
  )
  let bEvidence = snapshot(candidateID: "b", path: "b", object: 2)
  #expect(
    throws: PolicyModelError.invalidStorageGraph("invalid-clone-identity:clone-group")
  ) {
    try completeStorageGraph(
      aEvidence: aEvidence,
      bEvidence: bEvidence,
      cloneIdentity: .absent)
  }

  let fixture = try ReleaseFixture()
  let substitutedGraph = try completeStorageGraph(
    aEvidence: fixture.ownerActions[0].evidence,
    bEvidence: fixture.ownerActions[1].evidence,
    cloneIdentity: .known(ReleaseCloneIdentity(device: 1, cloneID: 45)))
  let bindings = [
    CandidateActionBinding(candidateID: "a", action: fixture.ownerActions[0]),
    CandidateActionBinding(candidateID: "b", action: fixture.ownerActions[1]),
  ]
  let substitutedBundle = try PlanReleaseSet.buildAll(
    from: substitutedGraph.evaluate(selectedCandidateActions: bindings),
    candidateActions: bindings)
  let substitutedRelease = try #require(substitutedBundle.releaseSets.first)
  let substitutedAction = try makeAction(
    evidence: fixture.ownerActions[0].evidence,
    facts: facts,
    prerequisites: fixture.ownerActions,
    request: .completeReleaseSetRemove(binding: substitutedRelease.actionBinding))

  #expect(throws: PolicyModelError.incompleteReleaseGraph) {
    try ImmutablePlan(
      policyVersion: "policy-1",
      schemaVersion: "schema-1",
      globalFacts: facts,
      evidenceSnapshots: fixture.ownerActions.map(\.evidence),
      actions: fixture.ownerActions + [substitutedAction],
      releaseGraphBundle: fixture.releaseGraphBundle)
  }
}

@Test
func completeReleaseUnitRevalidatesEveryOwnerAndTopology() async throws {
  let release = try ReleaseFixture()
  let currentActions =
    release.ownerActions.map { currentEvidence($0) }
    + [currentEvidence(release.releaseAction)]
  let currentTopology = CurrentReleaseTopology(
    allocationGroupID: release.releaseSet.allocationGroupID,
    topology: .known(release.releaseSet.topologyExpectation)
  )
  let snapshot = CurrentRevalidationSnapshot(
    captureID: digest(90),
    actions: currentActions,
    releaseTopologies: [currentTopology],
    invariants: passingInvariants
  )
  let engine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([snapshot]),
    randomBytes: deterministicEntropy
  )
  let result = try await engine.prepare(
    plan: release.plan,
    overlay: release.overlay,
    mode: .dryRun,
    issuedAtSeconds: 200,
    lifetimeSeconds: 30
  )
  guard case .dryRun(let report) = result,
    let unit = report.revalidation.manifest?.compoundReleaseUnits.first
  else {
    Issue.record("expected complete compound release unit")
    return
  }
  #expect(unit.ownerActionIDs == release.ownerActions.map(\.id).sorted())

  let badSnapshot = CurrentRevalidationSnapshot(
    captureID: digest(90),
    actions: currentActions,
    releaseTopologies: [
      CurrentReleaseTopology(
        allocationGroupID: release.releaseSet.allocationGroupID,
        topology: .unreadable(ObservationFailure(code: "EACCES", collector: "apfs"))
      )
    ],
    invariants: passingInvariants
  )
  let badEngine = ExecutionPreparationEngine(
    evidenceSource: SequenceSource([badSnapshot]),
    randomBytes: deterministicEntropy
  )
  let rejected = try await badEngine.prepare(
    plan: release.plan,
    overlay: release.overlay,
    mode: .apply,
    issuedAtSeconds: 200,
    lifetimeSeconds: 30
  )
  guard case .rejected(let badReport) = rejected else {
    Issue.record("unreadable release topology must reject")
    return
  }
  #expect(badReport.globalFindings.map(\.kind).contains(.unreadable))
}

private actor SequenceSource: RevalidationEvidenceSource {
  private var snapshots: [CurrentRevalidationSnapshot]
  private(set) var collectionCount = 0

  init(_ snapshots: [CurrentRevalidationSnapshot]) { self.snapshots = snapshots }

  func collectCurrentEvidence(for _: RevalidationRequest) async throws
    -> CurrentRevalidationSnapshot
  {
    collectionCount += 1
    guard !snapshots.isEmpty else { throw SourceError.exhausted }
    return snapshots.removeFirst()
  }

  enum SourceError: Error { case exhausted }
}

private final class LockedPreparationClock: @unchecked Sendable {
  private let lock = NSLock()
  private var stored: Int64

  init(_ value: Int64) { stored = value }

  var value: Int64 {
    get { lock.withLock { stored } }
    set { lock.withLock { stored = newValue } }
  }
}

private actor ControlledSource: RevalidationEvidenceSource {
  enum SourceError: Error, Sendable { case collectorFailed }

  private var nextIndex = 0
  private var pending: [Int: CheckedContinuation<CurrentRevalidationSnapshot, any Error>] = [:]
  private var entryWaiters: [(Int, CheckedContinuation<Void, Never>)] = []

  func collectCurrentEvidence(for _: RevalidationRequest) async throws
    -> CurrentRevalidationSnapshot
  {
    let index = nextIndex
    nextIndex += 1
    let ready = entryWaiters.filter { $0.0 <= nextIndex }
    entryWaiters.removeAll { $0.0 <= nextIndex }
    for (_, continuation) in ready { continuation.resume() }
    return try await withCheckedThrowingContinuation { continuation in
      pending[index] = continuation
    }
  }

  func waitUntilEntered(_ count: Int) async {
    guard nextIndex < count else { return }
    await withCheckedContinuation { continuation in
      entryWaiters.append((count, continuation))
    }
  }

  func resolve(
    _ index: Int,
    with result: Result<CurrentRevalidationSnapshot, SourceError>
  ) {
    guard let continuation = pending.removeValue(forKey: index) else {
      Issue.record("missing controlled source continuation")
      return
    }
    switch result {
    case .success(let snapshot): continuation.resume(returning: snapshot)
    case .failure(let error): continuation.resume(throwing: error)
    }
  }
}

func prepareApply(
  _ engine: ExecutionPreparationEngine,
  fixture: Fixture
) async throws -> (ApplyReadyReport, ApplyCapability) {
  let result = try await engine.prepare(
    plan: fixture.plan,
    overlay: fixture.overlay,
    mode: .apply,
    issuedAtSeconds: 200,
    lifetimeSeconds: 30
  )
  guard case .applyReady(let ready, let capability) = result else {
    throw FixtureError.unexpectedResult
  }
  return (ready, capability)
}

func deterministicEntropy(count: Int) throws -> Data {
  Data((0..<count).map { UInt8(($0 + count) & 0xff) })
}

private final class RecordingEntropy: @unchecked Sendable {
  private let lock = NSLock()
  private var counts: [Int] = []

  func bytes(count: Int) throws -> Data {
    lock.withLock { counts.append(count) }
    return try deterministicEntropy(count: count)
  }

  var requestedCounts: [Int] { lock.withLock { counts } }
}

let passingInvariants = CurrentPlanInvariants(
  duplicateSurvivorsPreserved: .known(true),
  terminalNamespacesExclusive: .known(true)
)

struct Fixture {
  let facts: FrozenGlobalFacts
  let evidence: FrozenEvidenceSnapshot
  let action: ActionDefinition
  let plan: ImmutablePlan
  let overlay: DecisionOverlay

  init(
    candidateID: String = "a",
    path: String = "a",
    object: UInt64 = 1,
    content: ContentProtectionBaseline = .requiredDigest(digest(92)),
    forceRequirement: ForceRequirement = .notRequired
  ) throws {
    facts = globalFacts()
    evidence = snapshot(
      candidateID: candidateID,
      path: path,
      object: object,
      content: content,
      forceRequirement: forceRequirement
    )
    action = try makeAction(evidence: evidence, facts: facts)
    plan = try ImmutablePlan(
      policyVersion: "policy-1",
      schemaVersion: "schema-1",
      globalFacts: facts,
      evidenceSnapshots: [evidence],
      actions: [action],
      releaseGraphBundle: nil
    )
    overlay = DecisionOverlay.create(
      plan: plan, selectedActionIDs: [action.id], waiverConsents: [], userNotes: [])
  }

  func currentSnapshot(
    identity: Observation<ObjectIdentity>? = nil,
    content: Observation<ContentProtectionBaseline>? = nil,
    access: Observation<RequiredAccessPolicyBaseline>? = nil,
    activity: Observation<ActivityState>? = nil,
    providerState: Observation<ProviderState>? = nil,
    dependencyState: Observation<DependencyState>? = nil,
    executionReferenceTimeSeconds: Int64 = 200
  ) -> CurrentRevalidationSnapshot {
    CurrentRevalidationSnapshot(
      captureID: digest(90),
      actions: [
        currentEvidence(
          action,
          identity: identity,
          content: content,
          access: access,
          activity: activity,
          providerState: providerState,
          dependencyState: dependencyState,
          executionReferenceTimeSeconds: executionReferenceTimeSeconds
        )
      ],
      releaseTopologies: [],
      invariants: passingInvariants
    )
  }
}

struct ReleaseFixture {
  let ownerActions: [ActionDefinition]
  let releaseAction: ActionDefinition
  let releaseSet: PlanReleaseSet
  let releaseGraphBundle: PlanReleaseGraphBundle
  let plan: ImmutablePlan
  let overlay: DecisionOverlay

  init(
    content: ContentProtectionBaseline = .requiredDigest(digest(92)),
    ownerDependency: Bool = false
  ) throws {
    let facts = globalFacts()
    let aEvidence = snapshot(
      candidateID: "a",
      path: "a",
      object: 1,
      content: content,
      additionalAdapterScopes: [.completeReleaseSetRemove(allocationGroupID: "clone-group")]
    )
    let bEvidence = snapshot(candidateID: "b", path: "b", object: 2, content: content)
    let a = try makeAction(evidence: aEvidence, facts: facts)
    let b = try makeAction(
      evidence: bEvidence,
      facts: facts,
      prerequisites: ownerDependency ? [a] : []
    )
    let graph = try completeStorageGraph(aEvidence: aEvidence, bEvidence: bEvidence)
    let bindings = [
      CandidateActionBinding(candidateID: "a", action: a),
      CandidateActionBinding(candidateID: "b", action: b),
    ]
    let evaluation = try graph.evaluate(selectedCandidateActions: bindings)
    releaseGraphBundle = try PlanReleaseSet.buildAll(
      from: evaluation, candidateActions: bindings
    )
    releaseSet = try #require(releaseGraphBundle.releaseSets.first)
    releaseAction = try makeAction(
      evidence: aEvidence,
      facts: facts,
      prerequisites: [a, b],
      request: .completeReleaseSetRemove(binding: releaseSet.actionBinding)
    )
    ownerActions = [a, b]
    plan = try ImmutablePlan(
      policyVersion: "policy-1",
      schemaVersion: "schema-1",
      globalFacts: facts,
      evidenceSnapshots: [aEvidence, bEvidence],
      actions: [a, b, releaseAction],
      releaseGraphBundle: releaseGraphBundle
    )
    overlay = DecisionOverlay.create(
      plan: plan,
      selectedActionIDs: [a.id, b.id, releaseAction.id],
      waiverConsents: [],
      userNotes: []
    )
  }
}

private struct ConsentFixture {
  let action: ActionDefinition
  let plan: ImmutablePlan
  let predicates: [WaiverPredicate]
  let consents: [WaiverConsentCore]
  let overlay: DecisionOverlay
  var predicate: WaiverPredicate { predicates[0] }
  var consent: WaiverConsentCore { consents[0] }

  init() throws {
    let facts = globalFacts()
    let evidence = snapshot(
      recoverability: .known(.reviewRequired),
      recoverabilityReviewFacts: [
        .unknownRebuildCost(valueBucket: "hours", evidenceHash: digest(150)),
        .unknownRebuildCost(valueBucket: "cost", evidenceHash: digest(151)),
      ]
    )
    let builtAction = try makeAction(evidence: evidence, facts: facts)
    guard case .requiresConsents(let requiredPredicates) = builtAction.evaluation.stageability,
      requiredPredicates.count == 2
    else { throw FixtureError.unexpectedResult }
    let sortedPredicates = requiredPredicates.sorted()
    let builtConsents = sortedPredicates.enumerated().map { index, predicate in
      WaiverConsentCore.create(
        action: builtAction,
        predicate: predicate,
        reason: "accept current rebuild uncertainty",
        consentEventID: "consent-\(index + 1)"
      )
    }
    let builtPlan = try ImmutablePlan(
      policyVersion: "policy-1",
      schemaVersion: "schema-1",
      globalFacts: facts,
      evidenceSnapshots: [evidence],
      actions: [builtAction],
      releaseGraphBundle: nil
    )
    action = builtAction
    predicates = sortedPredicates
    consents = builtConsents
    plan = builtPlan
    overlay = DecisionOverlay.create(
      plan: builtPlan,
      selectedActionIDs: [builtAction.id],
      waiverConsents: builtConsents,
      userNotes: []
    )
  }
}

func currentEvidence(
  _ action: ActionDefinition,
  identity: Observation<ObjectIdentity>? = nil,
  content: Observation<ContentProtectionBaseline>? = nil,
  access: Observation<RequiredAccessPolicyBaseline>? = nil,
  activity: Observation<ActivityState>? = nil,
  providerState: Observation<ProviderState>? = nil,
  recoverability: Observation<RecoverabilityState>? = nil,
  dependencyState: Observation<DependencyState>? = nil,
  executionReferenceTimeSeconds: Int64 = 200,
  freshCaptureID: PolicyDigest = digest(90),
  freshPolicyEvidence: Observation<FreshPolicyEvidence>? = nil,
  gitWorktree: Observation<GitWorktreeEvidence>? = nil
) -> CurrentActionEvidence {
  let namespace = action.prototype.namespaceBinding
  return CurrentActionEvidence(
    actionID: action.id,
    targetIdentity: identity
      ?? .known(action.prototype.protectedProperties.identity.expectedIdentity),
    targetContent: content ?? .known(action.prototype.protectedProperties.content.expectedBaseline),
    targetAccessPolicy: access
      ?? .known(action.prototype.protectedProperties.accessPolicy.requiredBaseline),
    coverage: .known(action.evidence.coverage),
    collectorStatus: action.evidence.collectorStatus,
    activity: activity ?? action.evidence.activity,
    explicitProtection: action.evidence.explicitProtection,
    providerState: providerState ?? action.evidence.providerState,
    recoverability: recoverability ?? action.evidence.recoverability,
    dependencyState: dependencyState ?? action.evidence.dependencyState,
    freshPolicyEvidence: freshPolicyEvidence
      ?? .known(
        retimedPolicyEvidence(
          action,
          referenceTimeSeconds: executionReferenceTimeSeconds,
          captureID: freshCaptureID
        )),
    root: CurrentNamespaceComponent(
      relativePath: nil,
      identity: .known(namespace.rootIdentity),
      seal: .known(namespace.rootSeal)
    ),
    parents: namespace.parentChain.map {
      CurrentNamespaceComponent(
        relativePath: $0.relativePath,
        identity: .known($0.identity),
        seal: .known($0.seal)
      )
    },
    gitWorktree: gitWorktree
      ?? {
        switch action.prototype.adapterContract {
        case .gitWorktreeRemove(let contract): return .known(contract.verifiedEvidence)
        case .gitWorktreeDiscardLocalChanges(let contract): return .known(contract.verifiedEvidence)
        default: return .absent
        }
      }()
  )
}

func digest(_ byte: UInt8) -> PolicyDigest {
  try! PolicyDigest(bytes: Data(repeating: byte, count: 32))
}

func globalFacts(
  semanticReferenceTimeSeconds: Int64 = 100,
  captureID: PolicyDigest = digest(89),
  configuration: Data = Data("config".utf8)
) -> FrozenGlobalFacts {
  FrozenGlobalFacts(
    captureID: captureID,
    profile: "standard",
    configuration: configuration,
    coverage: [
      GlobalCoverageFact(
        rawRoot: try! RawRootPath(absoluteBytes: Data("/root".utf8)),
        coverage: .complete,
        reasons: ["complete"]
      )
    ],
    semanticReferenceTimeSeconds: semanticReferenceTimeSeconds,
    policyVersion: "policy-1",
    schemaVersion: "schema-1"
  )
}

private func retimedPolicyEvidence(
  _ action: ActionDefinition,
  referenceTimeSeconds: Int64,
  recoverabilityReviewFacts: [RecoverabilityReviewFact]? = nil,
  contentProtection: Observation<ContentProtectionBaseline>? = nil,
  gitWorktree: GitWorktreeEvidence? = nil,
  captureID: PolicyDigest = digest(90),
  globalFactsConfiguration: Data = Data("config".utf8)
) -> FreshPolicyEvidence {
  let source = action.evidence
  let facts = globalFacts(
    semanticReferenceTimeSeconds: referenceTimeSeconds,
    captureID: captureID,
    configuration: globalFactsConfiguration
  )
  let evidence = try! FrozenEvidenceSnapshot(
    captureID: facts.captureID,
    globalFactsHash: facts.globalFactsHash,
    candidateID: source.candidateID,
    namespaceBinding: source.namespaceBinding,
    identity: source.identity,
    coverage: source.coverage,
    collectorStatus: source.collectorStatus,
    activity: source.activity,
    explicitProtection: source.explicitProtection,
    providerState: source.providerState,
    recoverability: source.recoverability,
    recoverabilityReviewFacts: recoverabilityReviewFacts ?? source.recoverabilityReviewFacts,
    dependencyState: source.dependencyState,
    semanticReviewFacts: source.semanticReviewFacts,
    accessPolicy: source.accessPolicy,
    contentProtection: contentProtection ?? source.contentProtection,
    aclDigest: source.aclDigest,
    targetMountIdentity: source.targetMountIdentity,
    removalForceRequirement: source.removalForceRequirement,
    quarantineCapability: source.quarantineCapability,
    gitWorktree: gitWorktree ?? source.gitWorktree,
    adapterScope: source.adapterScope,
    additionalAdapterScopes: source.additionalAdapterScopes,
    classificationClaims: source.classificationClaims,
    semanticReferenceTimeSeconds: referenceTimeSeconds,
    policyVersion: source.policyVersion,
    schemaVersion: source.schemaVersion
  )
  return FreshPolicyEvidence(evidence: evidence, globalFacts: facts)
}

func snapshot(
  candidateID: String = "a",
  path: String = "a",
  object: UInt64 = 1,
  content: ContentProtectionBaseline = .requiredDigest(digest(92)),
  gitWorktree: GitWorktreeEvidence? = nil,
  recoverability: Observation<RecoverabilityState> = .known(.recoverable),
  recoverabilityReviewFacts: [RecoverabilityReviewFact] = [],
  adapterScope: AdapterScopeEvidence = .genericRemove,
  additionalAdapterScopes: [AdapterScopeEvidence] = [],
  forceRequirement: ForceRequirement = .notRequired
) -> FrozenEvidenceSnapshot {
  let facts = globalFacts()
  let components = path.split(separator: "/").map { Data($0.utf8) }
  let identity = ObjectIdentity(
    device: 1, object: object, generation: .known(1), type: .directory)
  let seal = NamespaceSealEvidence(
    trustedNamespace: .ownerPrivate,
    accessPolicy: .known("owner-private"),
    aclDigest: .known(digest(91)),
    providerBoundary: .known(.local),
    mountIdentity: .known("mount-1")
  )
  let namespace = try! ProtectedNamespaceBinding(
    rawRoot: try! RawRootPath(absoluteBytes: Data("/root".utf8)),
    rootIdentity: ObjectIdentity(
      device: 1, object: 900, generation: .known(1), type: .directory),
    rootSeal: seal,
    targetPath: try! RawTargetPath(components: components),
    targetIdentity: identity,
    parentChain: []
  )
  return try! FrozenEvidenceSnapshot(
    captureID: facts.captureID,
    globalFactsHash: facts.globalFactsHash,
    candidateID: candidateID,
    namespaceBinding: namespace,
    identity: .known(identity),
    coverage: .complete,
    collectorStatus: .known(.complete),
    activity: .known(.inactive),
    explicitProtection: .known(.notProtected),
    providerState: .known(.local),
    recoverability: recoverability,
    recoverabilityReviewFacts: recoverabilityReviewFacts,
    dependencyState: .known(.complete),
    semanticReviewFacts: [],
    accessPolicy: .known("owner-private"),
    contentProtection: .known(content),
    aclDigest: .known(digest(93)),
    targetMountIdentity: .known("mount-1"),
    removalForceRequirement: .known(forceRequirement),
    quarantineCapability: .known(true),
    gitWorktree: gitWorktree,
    adapterScope: adapterScope,
    additionalAdapterScopes: additionalAdapterScopes,
    classificationClaims: completeClassificationClaims(),
    semanticReferenceTimeSeconds: 100,
    policyVersion: "policy-1",
    schemaVersion: "schema-1"
  )
}

func gitEvidence(
  worktreeObject: UInt64,
  indexDigest: Observation<PolicyDigest> = .known(digest(71)),
  localChanges: GitLocalChangesState = .clean
) -> GitWorktreeEvidence {
  let identity = ObjectIdentity(
    device: 1, object: worktreeObject, generation: .known(1), type: .directory)
  let registration = try! GitWorktreeRegistrationEvidence(
    registeredWorktreeIdentity: identity,
    administrativeDirectoryIdentity: ObjectIdentity(
      device: 1, object: 700, generation: .known(1), type: .directory),
    commonDirectoryIdentity: ObjectIdentity(
      device: 1, object: 701, generation: .known(1), type: .directory),
    registrationID: digest(75),
    metadataDigest: digest(74),
    headResolutionDigest: digest(77)
  )
  let successor: Observation<GitWorktreeExecutionBaseline>
  switch localChanges {
  case .clean:
    successor = .absent
  case .present:
    successor = .known(
      try! GitWorktreeExecutionBaseline(
        headIdentity: digest(70),
        indexDigest: digest(72),
        localChanges: .clean,
        contentProtection: .requiredDigest(digest(76))
      ))
  }
  return GitWorktreeEvidence(
    noFollowTraversalComplete: .known(true),
    headIdentity: .known(digest(70)),
    indexDigest: indexDigest,
    localChanges: .known(localChanges),
    registration: .known(registration),
    linkage: .known(.linked(registrationID: registration.registrationID)),
    sparseCheckout: .known(.disabled),
    nestedRepositories: .known(.none),
    submodules: .known(.none),
    trustedExclusiveNamespace: .known(true),
    postQuarantineCoverage: .known(.complete),
    postDiscardSuccessor: successor
  )
}

private func postDiscardGitEvidence(
  _ contract: GitWorktreeRemoveContract
) -> GitWorktreeEvidence {
  let source = contract.verifiedEvidence
  let successor = contract.executionBaseline
  return GitWorktreeEvidence(
    noFollowTraversalComplete: source.noFollowTraversalComplete,
    headIdentity: .known(successor.headIdentity),
    indexDigest: .known(successor.indexDigest),
    localChanges: .known(.clean),
    registration: source.registration,
    linkage: source.linkage,
    sparseCheckout: source.sparseCheckout,
    nestedRepositories: source.nestedRepositories,
    submodules: source.submodules,
    trustedExclusiveNamespace: source.trustedExclusiveNamespace,
    postQuarantineCoverage: source.postQuarantineCoverage,
    postDiscardSuccessor: .absent
  )
}

func completeClassificationClaims() -> [ClassificationClaim] {
  ClassificationFacet.allCases.map { facet in
    ClassificationClaim(
      facet: facet,
      value: "known-\(facet.rawValue)",
      source: .genericFallback,
      evidenceKey: "fixture-\(facet.rawValue)"
    )
  }
}

func makeAction(
  evidence: FrozenEvidenceSnapshot,
  facts: FrozenGlobalFacts,
  prerequisites: [ActionDefinition] = [],
  request: ActionAdapterRequest = .genericRemove
) throws -> ActionDefinition {
  let evaluation = try OneVotePolicy.evaluate(
    OneVotePolicyInputs.build(evidence: evidence, globalFacts: facts))
  return try ActionDefinition.build(
    prototype: try ActionPrototype.build(request: request, evidence: evidence),
    evidence: evidence,
    globalFacts: facts,
    prerequisites: prerequisites,
    evaluation: evaluation,
    displayMetrics: ActionDisplayMetrics(
      immediateReclaimBytes: .known(1),
      inactiveDurationSeconds: .known(10),
      rebuildCost: .known(1),
      cleanupCost: .known(1),
      canonicalRawPath: evidence.namespaceBinding.targetPath.components
        .enumerated().reduce(into: Data()) { result, pair in
          if pair.offset > 0 { result.append(UInt8(ascii: "/")) }
          result.append(pair.element)
        }
    )
  )
}

func completeStorageGraph(
  aEvidence: FrozenEvidenceSnapshot,
  bEvidence: FrozenEvidenceSnapshot,
  cloneIdentity: Observation<ReleaseCloneIdentity> = .known(
    ReleaseCloneIdentity(device: 1, cloneID: 44))
) throws -> StorageReleaseGraph {
  let facts = globalFacts()
  let a = try StorageCandidate(id: "a", evidence: aEvidence, immediatePrivateBytes: .known(1))
  let b = try StorageCandidate(id: "b", evidence: bEvidence, immediatePrivateBytes: .known(1))
  let provenance = GraphObservationProvenance(globalFacts: facts)
  let fileA = FileObjectNode(
    provenance: provenance,
    id: "file-a",
    observedOwners: [FileOwnerLink(candidateID: "a", path: a.target)],
    linkCount: .known(1)
  )
  let fileB = FileObjectNode(
    provenance: provenance,
    id: "file-b",
    observedOwners: [FileOwnerLink(candidateID: "b", path: b.target)],
    linkCount: .known(1)
  )
  let group = AllocationGroupNode(
    provenance: provenance,
    id: "clone-group",
    ownerFileObjectIDs: ["file-a", "file-b"],
    cloneIdentity: cloneIdentity,
    cloneRefCount: .known(2),
    sharedBytes: .known(100),
    snapshotBlocker: .known(false)
  )
  return try StorageReleaseGraph(
    globalFacts: facts,
    candidates: [a, b],
    fileObjects: [fileA, fileB],
    allocationGroups: [group]
  )
}

enum FixtureError: Error { case unexpectedResult }
