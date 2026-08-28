@_spi(DiskplanEngine) @testable import DiskplanExecution
import DiskplanPolicy
import Foundation
import Testing

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
    randomBytes: deterministicEntropy
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
func forgedWrongBindingAndExpiredCapabilitiesFailClosed() async throws {
  let fixture = try Fixture()
  let source = SequenceSource([
    fixture.currentSnapshot(), fixture.currentSnapshot(), fixture.currentSnapshot(),
  ])
  let engine = ExecutionPreparationEngine(
    evidenceSource: source,
    randomBytes: deterministicEntropy
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
    randomBytes: deterministicEntropy
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
    randomBytes: deterministicEntropy
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
    randomBytes: deterministicEntropy
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
    releaseSets: []
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
    content: ContentProtectionBaseline = .requiredDigest(digest(92))
  ) throws {
    facts = globalFacts()
    evidence = snapshot(
      candidateID: candidateID, path: path, object: object, content: content)
    action = try makeAction(evidence: evidence, facts: facts)
    plan = try ImmutablePlan(
      policyVersion: "policy-1",
      schemaVersion: "schema-1",
      globalFacts: facts,
      evidenceSnapshots: [evidence],
      actions: [action],
      releaseSets: []
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
  let plan: ImmutablePlan
  let overlay: DecisionOverlay

  init() throws {
    let facts = globalFacts()
    let aEvidence = snapshot(
      candidateID: "a",
      path: "a",
      object: 1,
      additionalAdapterScopes: [.completeReleaseSetRemove(allocationGroupID: "clone-group")]
    )
    let bEvidence = snapshot(candidateID: "b", path: "b", object: 2)
    let a = try makeAction(evidence: aEvidence, facts: facts)
    let b = try makeAction(evidence: bEvidence, facts: facts)
    let graph = try completeStorageGraph(aEvidence: aEvidence, bEvidence: bEvidence)
    let bindings = [
      CandidateActionBinding(candidateID: "a", action: a),
      CandidateActionBinding(candidateID: "b", action: b),
    ]
    let evaluation = try graph.evaluate(selectedCandidateActions: bindings)
    releaseSet = try #require(
      PlanReleaseSet.buildAll(
        from: evaluation, candidateActions: bindings
      ).first)
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
      releaseSets: [releaseSet]
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
      releaseSets: []
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
  dependencyState: Observation<DependencyState>? = nil,
  executionReferenceTimeSeconds: Int64 = 200,
  freshPolicyEvidence: Observation<FreshPolicyEvidence>? = nil
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
    recoverability: action.evidence.recoverability,
    dependencyState: dependencyState ?? action.evidence.dependencyState,
    freshPolicyEvidence: freshPolicyEvidence
      ?? .known(
        retimedPolicyEvidence(action, referenceTimeSeconds: executionReferenceTimeSeconds)),
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
    gitWorktree: {
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
  captureID: PolicyDigest = digest(89)
) -> FrozenGlobalFacts {
  FrozenGlobalFacts(
    captureID: captureID,
    profile: "standard",
    configuration: Data("config".utf8),
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
  captureID: PolicyDigest = digest(90)
) -> FreshPolicyEvidence {
  let source = action.evidence
  let facts = globalFacts(
    semanticReferenceTimeSeconds: referenceTimeSeconds,
    captureID: captureID
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
    contentProtection: source.contentProtection,
    aclDigest: source.aclDigest,
    targetMountIdentity: source.targetMountIdentity,
    removalForceRequirement: source.removalForceRequirement,
    quarantineCapability: source.quarantineCapability,
    gitWorktree: source.gitWorktree,
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
  indexDigest: Observation<PolicyDigest> = .known(digest(71))
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
    metadataDigest: digest(74)
  )
  return GitWorktreeEvidence(
    noFollowTraversalComplete: .known(true),
    headIdentity: .known(digest(70)),
    indexDigest: indexDigest,
    localChanges: .known(.clean),
    registration: .known(registration),
    linkage: .known(.ordinary),
    sparseCheckout: .known(.disabled),
    nestedRepositories: .known(.none),
    submodules: .known(.none),
    trustedExclusiveNamespace: .known(true),
    postQuarantineCoverage: .known(.complete),
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
      tier: .safe,
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
  bEvidence: FrozenEvidenceSnapshot
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
