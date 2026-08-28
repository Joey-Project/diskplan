import Darwin
@_spi(DiskplanEngine) @testable import DiskplanExecution
import DiskplanPolicy
import Foundation
import Testing

@Test
func bestEffortContinuesIndependentUnitsAndSkipsDependents() async throws {
  let fixture = try MultiActionFixture(includeDependency: true)
  let authorization = try await makeAuthorization(plan: fixture.plan, overlay: fixture.overlay)
  let adapter = RecordingMutationAdapter(
    outcomes: [fixture.first.id: .failed(ExecutionAdapterFailure(code: "simulated-failure"))]
  )
  let coordinator = BestEffortApplyCoordinator(
    collector: EngineJITRevalidationCollector(source: LiveJITSource()),
    adapter: adapter,
    eventSink: RecordingEventSink(),
    auditSink: nil,
    clock: { 202 }
  )

  let report = await coordinator.apply(
    authorization: authorization,
    plan: fixture.plan,
    overlay: fixture.overlay
  )

  #expect(report.didStart)
  #expect(status(for: fixture.first.id, in: report) == .failed)
  #expect(status(for: fixture.independent.id, in: report) == .succeeded)
  #expect(status(for: fixture.dependent.id, in: report) == .skippedPrerequisite)
  #expect(await adapter.appliedActionIDs.contains(fixture.independent.id))
  #expect(!(await adapter.appliedActionIDs.contains(fixture.dependent.id)))
}

@Test
func adapterCancellationDoesNotStopAnIndependentUnit() async throws {
  let fixture = try MultiActionFixture(includeDependency: false)
  let authorization = try await makeAuthorization(plan: fixture.plan, overlay: fixture.overlay)
  let adapter = RecordingMutationAdapter(outcomes: [fixture.first.id: .cancelled])
  let coordinator = BestEffortApplyCoordinator(
    collector: EngineJITRevalidationCollector(source: LiveJITSource()),
    adapter: adapter,
    eventSink: RecordingEventSink(),
    auditSink: nil,
    clock: { 202 }
  )

  let report = await coordinator.apply(
    authorization: authorization, plan: fixture.plan, overlay: fixture.overlay)

  #expect(status(for: fixture.first.id, in: report) == .cancelled)
  #expect(status(for: fixture.independent.id, in: report) == .succeeded)
}

@Test
func jitIdentityReplacementRejectsBeforeMutation() async throws {
  let fixture = try Fixture()
  let authorization = try await makeAuthorization(plan: fixture.plan, overlay: fixture.overlay)
  let replacement = ObjectIdentity(
    device: fixture.action.prototype.targetIdentity.device,
    object: fixture.action.prototype.targetIdentity.object + 1,
    generation: fixture.action.prototype.targetIdentity.generation,
    type: fixture.action.prototype.targetIdentity.type
  )
  let adapter = RecordingMutationAdapter()
  let coordinator = BestEffortApplyCoordinator(
    collector: EngineJITRevalidationCollector(
      source: LiveJITSource(identityOverrides: [fixture.action.id: .known(replacement)])),
    adapter: adapter,
    eventSink: RecordingEventSink(),
    auditSink: nil,
    clock: { 202 }
  )

  let report = await coordinator.apply(
    authorization: authorization, plan: fixture.plan, overlay: fixture.overlay)

  #expect(report.unitOutcomes.first?.status == .jitRejected)
  #expect(
    report.unitOutcomes.first?.jitReport?.actionOutcomes.first?.findings.map(\.kind)
      .contains(.identityMismatch) == true)
  #expect(await adapter.appliedActionIDs.isEmpty)
}

@Test
func forceWarningPrecedesTheMutationAndAuditFailureIsNonfatal() async throws {
  let facts = globalFacts()
  let evidence = snapshot(forceRequirement: .requiresForceWithWarning)
  let action = try makeAction(evidence: evidence, facts: facts)
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
  let authorization = try await makeAuthorization(plan: plan, overlay: overlay)
  let events = RecordingEventSink()
  let adapter = RecordingMutationAdapter(eventSink: events)
  let coordinator = BestEffortApplyCoordinator(
    collector: EngineJITRevalidationCollector(source: LiveJITSource()),
    adapter: adapter,
    eventSink: events,
    auditSink: AlwaysFailingAuditSink(),
    clock: { 202 }
  )

  let report = await coordinator.apply(
    authorization: authorization, plan: plan, overlay: overlay)
  let transcript = await events.events
  let warningIndex = transcript.firstIndex(of: .forceRequiredWarning(action.id))
  let mutationIndex = transcript.firstIndex(of: .adapterObservedMutation(action.id))

  #expect(report.unitOutcomes.first?.status == .succeeded)
  #expect(!report.auditFailures.isEmpty)
  #expect(warningIndex != nil)
  #expect(mutationIndex != nil)
  if let warningIndex, let mutationIndex { #expect(warningIndex < mutationIndex) }
}

@Test
func compoundReleaseExecutesEveryOwnerOnceAndReportsPartialFailure() async throws {
  let fixture = try ReleaseFixture()
  let authorization = try await makeAuthorization(plan: fixture.plan, overlay: fixture.overlay)
  let failedOwner = fixture.ownerActions[0].id
  let adapter = RecordingMutationAdapter(
    outcomes: [failedOwner: .failed(ExecutionAdapterFailure(code: "owner-failed"))]
  )
  let coordinator = BestEffortApplyCoordinator(
    collector: EngineJITRevalidationCollector(source: LiveJITSource()),
    adapter: adapter,
    eventSink: RecordingEventSink(),
    auditSink: nil,
    clock: { 202 }
  )

  let report = await coordinator.apply(
    authorization: authorization, plan: fixture.plan, overlay: fixture.overlay)
  let applied = await adapter.appliedActionIDs

  #expect(report.unitOutcomes.count == 1)
  #expect(report.unitOutcomes.first?.status == .partiallyFailed)
  #expect(Set(applied) == Set(fixture.ownerActions.map(\.id)))
  #expect(applied.count == Set(applied).count)
}

@Test
func claimedAuthorizationCannotBeReplayedThroughApply() async throws {
  let fixture = try Fixture()
  let authorization = try await makeAuthorization(plan: fixture.plan, overlay: fixture.overlay)
  let adapter = RecordingMutationAdapter()
  let coordinator = BestEffortApplyCoordinator(
    collector: EngineJITRevalidationCollector(source: LiveJITSource()),
    adapter: adapter,
    eventSink: RecordingEventSink(),
    auditSink: nil,
    clock: { 202 }
  )

  let first = await coordinator.apply(
    authorization: authorization, plan: fixture.plan, overlay: fixture.overlay)
  let replay = await coordinator.apply(
    authorization: authorization, plan: fixture.plan, overlay: fixture.overlay)

  #expect(first.didStart)
  #expect(replay.startFailure == .authorizationAlreadyClaimed)
  #expect(await adapter.appliedActionIDs.count == 1)
}

@Test
func posixRemoveUsesRawArgvAndDoesNotFollowTheTargetSymlink() async throws {
  let root = try TemporaryRemovalRoot()
  defer { root.cleanup() }
  let outside = root.parent.appendingPathComponent("outside-\(UUID().uuidString)")
  try Data("keep".utf8).write(to: outside)
  defer { try? FileManager.default.removeItem(at: outside) }
  let link = root.url.appendingPathComponent("link")
  try FileManager.default.createSymbolicLink(at: link, withDestinationURL: outside)
  let action = try filesystemAction(root: root.url, targetName: "link", kind: .symbolicLink)
  guard case .genericRemove(let contract) = action.prototype.adapterContract else {
    Issue.record("expected generic remove")
    return
  }
  let operation = ExecutionAdapterOperation.genericRemove(
    BoundMutationTarget(action: action), contract)
  let adapter = PosixRemoveAdapter()

  #expect(await adapter.apply(operation) == .succeeded(detailCode: "rm-completed"))
  #expect(await adapter.postverify(operation) == .satisfied)
  #expect(FileManager.default.fileExists(atPath: outside.path))
  #expect(!FileManager.default.fileExists(atPath: link.path))
}

@Test
func posixRemoveRejectsReplacementBetweenPreflights() async throws {
  let root = try TemporaryRemovalRoot()
  defer { root.cleanup() }
  let target = root.url.appendingPathComponent("victim")
  try Data("original".utf8).write(to: target)
  let outside = root.parent.appendingPathComponent("outside-\(UUID().uuidString)")
  try Data("keep".utf8).write(to: outside)
  defer { try? FileManager.default.removeItem(at: outside) }
  let action = try filesystemAction(root: root.url, targetName: "victim", kind: .regularFile)
  guard case .genericRemove(let contract) = action.prototype.adapterContract else {
    Issue.record("expected generic remove")
    return
  }
  let operation = ExecutionAdapterOperation.genericRemove(
    BoundMutationTarget(action: action), contract)
  let adapter = PosixRemoveAdapter(beforeFinalPreflight: {
    try? FileManager.default.removeItem(at: target)
    try? FileManager.default.createSymbolicLink(at: target, withDestinationURL: outside)
  })

  guard case .failed(let failure) = await adapter.apply(operation) else {
    Issue.record("replacement must fail the final identity preflight")
    return
  }
  #expect(failure.code == "target-identity-mismatch")
  #expect(FileManager.default.fileExists(atPath: outside.path))
}

@Test
func forceRequirementChangesOnlyTheExplicitRMOption() throws {
  let root = try TemporaryRemovalRoot()
  defer { root.cleanup() }
  let firstURL = root.url.appendingPathComponent("ordinary")
  let forcedURL = root.url.appendingPathComponent("forced")
  try Data("ordinary".utf8).write(to: firstURL)
  try Data("forced".utf8).write(to: forcedURL)
  try FileManager.default.setAttributes([.posixPermissions: 0o444], ofItemAtPath: firstURL.path)
  try FileManager.default.setAttributes([.posixPermissions: 0o444], ofItemAtPath: forcedURL.path)
  let ordinary = try filesystemAction(
    root: root.url, targetName: "ordinary", kind: .regularFile, force: .notRequired)
  let forced = try filesystemAction(
    root: root.url,
    targetName: "forced",
    kind: .regularFile,
    force: .requiresForceWithWarning
  )
  guard case .genericRemove(let ordinaryContract) = ordinary.prototype.adapterContract,
    case .genericRemove(let forcedContract) = forced.prototype.adapterContract
  else {
    Issue.record("expected generic remove contracts")
    return
  }

  let ordinaryArguments = try PosixRemoveAdapter.arguments(
    target: BoundMutationTarget(action: ordinary), contract: ordinaryContract)
  let forcedArguments = try PosixRemoveAdapter.arguments(
    target: BoundMutationTarget(action: forced), contract: forcedContract)

  #expect(!ordinaryArguments.contains(Data("-f".utf8)))
  #expect(forcedArguments.contains(Data("-f".utf8)))
  #expect(ordinaryArguments.last == Data(firstURL.path.utf8))
  #expect(forcedArguments.last == Data(forcedURL.path.utf8))
}

private actor PreparationSnapshotSource: RevalidationEvidenceSource {
  func collectCurrentEvidence(for request: RevalidationRequest) async throws
    -> CurrentRevalidationSnapshot
  {
    let actions = Dictionary(
      uniqueKeysWithValues: request.validatedOverlay.executionSteps
        .flatMap(\.jitRevalidationActions).map { ($0.id, $0) }
    ).values.map { currentEvidence($0) }
    let groups = Set(
      request.validatedOverlay.executionSteps.compactMap { $0.releaseSet?.allocationGroupID })
    return CurrentRevalidationSnapshot(
      actions: actions,
      releaseTopologies: request.plan.releaseSets.filter {
        groups.contains($0.allocationGroupID)
      }.map {
        CurrentReleaseTopology(
          allocationGroupID: $0.allocationGroupID,
          topology: .known($0.topologyExpectation)
        )
      },
      invariants: passingInvariants
    )
  }
}

private actor LiveJITSource: JITRevalidationEvidenceSource {
  let identityOverrides: [ActionID: Observation<ObjectIdentity>]

  init(identityOverrides: [ActionID: Observation<ObjectIdentity>] = [:]) {
    self.identityOverrides = identityOverrides
  }

  func collectJITEvidence(for request: JITRevalidationRequest) async throws
    -> CurrentRevalidationSnapshot
  {
    let byID = Dictionary(uniqueKeysWithValues: request.plan.actions.map { ($0.id, $0) })
    return CurrentRevalidationSnapshot(
      actions: request.actionIDs.compactMap { actionID in
        byID[actionID].map {
          currentEvidence($0, identity: identityOverrides[actionID])
        }
      },
      releaseTopologies: request.releaseGroupIDs.compactMap { groupID in
        request.plan.releaseSets.first(where: { $0.allocationGroupID == groupID }).map {
          CurrentReleaseTopology(
            allocationGroupID: groupID, topology: .known($0.topologyExpectation))
        }
      },
      invariants: passingInvariants
    )
  }
}

private actor RecordingMutationAdapter: ExecutionMutationAdapter {
  let outcomes: [ActionID: AdapterOperationOutcome]
  let postOutcomes: [ActionID: PostVerificationOutcome]
  let eventSink: RecordingEventSink?
  private(set) var appliedActionIDs: [ActionID] = []

  init(
    outcomes: [ActionID: AdapterOperationOutcome] = [:],
    postOutcomes: [ActionID: PostVerificationOutcome] = [:],
    eventSink: RecordingEventSink? = nil
  ) {
    self.outcomes = outcomes
    self.postOutcomes = postOutcomes
    self.eventSink = eventSink
  }

  func apply(_ operation: ExecutionAdapterOperation) async -> AdapterOperationOutcome {
    appliedActionIDs.append(operation.actionID)
    await eventSink?.recordAdapterMutation(operation.actionID)
    return outcomes[operation.actionID] ?? .succeeded(detailCode: "mock-success")
  }

  func postverify(_ operation: ExecutionAdapterOperation) async -> PostVerificationOutcome {
    postOutcomes[operation.actionID] ?? .satisfied
  }
}

private actor RecordingEventSink: ExecutionEventSink {
  enum RecordedEvent: Equatable, Sendable {
    case execution(ExecutionEvent)
    case adapterObservedMutation(ActionID)
  }

  private(set) var recordedEvents: [RecordedEvent] = []
  var events: [RecordedEvent] { recordedEvents }

  func emit(_ event: ExecutionEvent) { recordedEvents.append(.execution(event)) }
  func recordAdapterMutation(_ actionID: ActionID) {
    recordedEvents.append(.adapterObservedMutation(actionID))
  }
}

private actor AlwaysFailingAuditSink: ExecutionAuditSink {
  struct NoSpace: Error, Sendable {}
  func record(_: ExecutionEvent) async throws { throw NoSpace() }
}

private func makeAuthorization(
  plan: ImmutablePlan,
  overlay: DecisionOverlay
) async throws -> ApplyAuthorization {
  let engine = ExecutionPreparationEngine(
    evidenceSource: PreparationSnapshotSource(), randomBytes: deterministicEntropy)
  let prepared = try await engine.prepare(
    plan: plan,
    overlay: overlay,
    mode: .apply,
    issuedAtSeconds: 200,
    lifetimeSeconds: 30
  )
  guard case .applyReady(let ready, let capability) = prepared else {
    throw FixtureError.unexpectedResult
  }
  return try await engine.authorizeApply(
    capability, ready: ready, plan: plan, overlay: overlay, nowSeconds: 201)
}

private struct MultiActionFixture {
  let first: ActionDefinition
  let independent: ActionDefinition
  let dependent: ActionDefinition
  let plan: ImmutablePlan
  let overlay: DecisionOverlay

  init(includeDependency: Bool) throws {
    let facts = globalFacts()
    let firstEvidence = snapshot(candidateID: "first", path: "first", object: 11)
    let independentEvidence = snapshot(
      candidateID: "independent", path: "independent", object: 12)
    let dependentEvidence = snapshot(candidateID: "dependent", path: "dependent", object: 13)
    first = try makeAction(evidence: firstEvidence, facts: facts)
    independent = try makeAction(evidence: independentEvidence, facts: facts)
    dependent = try makeAction(
      evidence: dependentEvidence,
      facts: facts,
      prerequisites: includeDependency ? [first] : []
    )
    plan = try ImmutablePlan(
      policyVersion: "policy-1",
      schemaVersion: "schema-1",
      globalFacts: facts,
      evidenceSnapshots: [firstEvidence, independentEvidence, dependentEvidence],
      actions: [first, independent, dependent],
      releaseSets: []
    )
    overlay = DecisionOverlay.create(
      plan: plan,
      selectedActionIDs: [first.id, independent.id, dependent.id],
      waiverConsents: [],
      userNotes: []
    )
  }
}

private func status(
  for actionID: ActionID,
  in report: BestEffortApplyReport
) -> ExecutionUnitStatus? {
  report.unitOutcomes.first(where: { $0.logicalActionIDs.contains(actionID) })?.status
}

private struct TemporaryRemovalRoot {
  let parent: URL
  let url: URL

  init() throws {
    parent = FileManager.default.temporaryDirectory
    url = parent.appendingPathComponent("diskplan-phase5-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
  }

  func cleanup() { try? FileManager.default.removeItem(at: url) }
}

private func filesystemAction(
  root: URL,
  targetName: String,
  kind: ObjectKind,
  force: ForceRequirement = .notRequired
) throws -> ActionDefinition {
  let rawRoot = try RawRootPath(absoluteBytes: Data(root.path.utf8))
  let facts = FrozenGlobalFacts(
    captureID: digest(201),
    profile: "standard",
    configuration: Data("filesystem-test".utf8),
    coverage: [GlobalCoverageFact(rawRoot: rawRoot, coverage: .complete, reasons: ["complete"])],
    semanticReferenceTimeSeconds: 100,
    policyVersion: "policy-1",
    schemaVersion: "schema-1"
  )
  let rootIdentity = try filesystemIdentity(root, kind: .directory)
  let targetURL = root.appendingPathComponent(targetName)
  let targetIdentity = try filesystemIdentity(targetURL, kind: kind)
  let seal = NamespaceSealEvidence(
    trustedNamespace: .ownerPrivate,
    accessPolicy: .known("owner-private"),
    aclDigest: .known(digest(202)),
    providerBoundary: .known(.local),
    mountIdentity: .known("test-mount")
  )
  let namespace = try ProtectedNamespaceBinding(
    rawRoot: rawRoot,
    rootIdentity: rootIdentity,
    rootSeal: seal,
    targetPath: try RawTargetPath(components: [Data(targetName.utf8)]),
    targetIdentity: targetIdentity,
    parentChain: []
  )
  let evidence = try FrozenEvidenceSnapshot(
    captureID: facts.captureID,
    globalFactsHash: facts.globalFactsHash,
    candidateID: targetName,
    namespaceBinding: namespace,
    identity: .known(targetIdentity),
    coverage: .complete,
    collectorStatus: .known(.complete),
    activity: .known(.inactive),
    explicitProtection: .known(.notProtected),
    providerState: .known(.local),
    recoverability: .known(.recoverable),
    recoverabilityReviewFacts: [],
    dependencyState: .known(.complete),
    semanticReviewFacts: [],
    accessPolicy: .known("owner-private"),
    contentProtection: .known(.requiredDigest(digest(203))),
    aclDigest: .known(digest(204)),
    targetMountIdentity: .known("test-mount"),
    removalForceRequirement: .known(force),
    quarantineCapability: .known(true),
    gitWorktree: nil,
    adapterScope: .genericRemove,
    classificationClaims: completeClassificationClaims(),
    semanticReferenceTimeSeconds: 100,
    policyVersion: "policy-1",
    schemaVersion: "schema-1"
  )
  return try makeAction(evidence: evidence, facts: facts)
}

private func filesystemIdentity(_ url: URL, kind: ObjectKind) throws -> ObjectIdentity {
  var status = stat()
  let result = url.path.withCString { Darwin.lstat($0, &status) }
  guard result == 0 else { throw CocoaError(.fileReadUnknown) }
  return ObjectIdentity(
    device: UInt64(UInt32(bitPattern: status.st_dev)),
    object: UInt64(status.st_ino),
    generation: .known(UInt64(status.st_gen)),
    type: kind
  )
}

extension RecordingEventSink.RecordedEvent {
  fileprivate static func forceRequiredWarning(_ actionID: ActionID) -> Self {
    .execution(.forceRequiredWarning(actionID))
  }
}
