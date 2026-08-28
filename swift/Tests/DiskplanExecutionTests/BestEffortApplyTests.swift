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
  let fixture = try Fixture(content: .explicitlyNotApplicable(.metadataOnlyObject))
  let replacement = ObjectIdentity(
    device: fixture.action.prototype.targetIdentity.device,
    object: fixture.action.prototype.targetIdentity.object + 1,
    generation: fixture.action.prototype.targetIdentity.generation,
    type: fixture.action.prototype.targetIdentity.type
  )
  let authorization = try await makeAuthorization(
    plan: fixture.plan,
    overlay: fixture.overlay,
    jitSource: LiveJITSource(
      identityOverrides: [fixture.action.id: .known(replacement)]
    )
  )
  let adapter = RecordingMutationAdapter()
  let coordinator = BestEffortApplyCoordinator(
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
  let evidence = snapshot(
    content: .explicitlyNotApplicable(.metadataOnlyObject),
    forceRequirement: .requiresForceWithWarning
  )
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
  #expect(report.auditFailures.allSatisfy { $0.errno == ENOSPC })
  #expect(warningIndex != nil)
  #expect(mutationIndex != nil)
  if let warningIndex, let mutationIndex { #expect(warningIndex < mutationIndex) }
}

@Test
func compoundReleaseExecutesEveryOwnerOnceAndReportsPartialFailure() async throws {
  let fixture = try ReleaseFixture(
    content: .explicitlyNotApplicable(.metadataOnlyObject)
  )
  let authorization = try await makeAuthorization(plan: fixture.plan, overlay: fixture.overlay)
  let failedOwner = fixture.ownerActions[0].id
  let adapter = RecordingMutationAdapter(
    outcomes: [failedOwner: .failed(ExecutionAdapterFailure(code: "owner-failed"))]
  )
  let coordinator = BestEffortApplyCoordinator(
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
func compoundOwnerFailureSkipsOnlyItsDownstreamOwner() async throws {
  let fixture = try ReleaseFixture(
    content: .explicitlyNotApplicable(.metadataOnlyObject),
    ownerDependency: true
  )
  let authorization = try await makeAuthorization(plan: fixture.plan, overlay: fixture.overlay)
  let prerequisite = fixture.ownerActions[0].id
  let dependent = fixture.ownerActions[1].id
  let adapter = RecordingMutationAdapter(
    outcomes: [prerequisite: .failed(ExecutionAdapterFailure(code: "owner-failed"))]
  )
  let report = await BestEffortApplyCoordinator(
    adapter: adapter,
    eventSink: RecordingEventSink(),
    auditSink: nil,
    clock: { 202 }
  ).apply(authorization: authorization, plan: fixture.plan, overlay: fixture.overlay)

  #expect(await adapter.appliedActionIDs == [prerequisite])
  #expect(
    report.unitOutcomes.first?.steps.first(where: { $0.actionID == dependent })?.status
      == .skippedPrerequisite
  )
}

@Test
func claimedAuthorizationCannotBeReplayedThroughApply() async throws {
  let fixture = try Fixture(content: .explicitlyNotApplicable(.metadataOnlyObject))
  let authorization = try await makeAuthorization(plan: fixture.plan, overlay: fixture.overlay)
  let adapter = RecordingMutationAdapter()
  let coordinator = BestEffortApplyCoordinator(
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
func jitRejectsThePreparationCaptureAndDoesNotMutate() async throws {
  let fixture = try Fixture(content: .explicitlyNotApplicable(.metadataOnlyObject))
  let authorization = try await makeAuthorization(
    plan: fixture.plan,
    overlay: fixture.overlay,
    jitSource: LiveJITSource(fixedCaptureByte: 90)
  )
  let adapter = RecordingMutationAdapter()
  let report = await BestEffortApplyCoordinator(
    adapter: adapter,
    eventSink: RecordingEventSink(),
    auditSink: nil,
    clock: { 202 }
  ).apply(authorization: authorization, plan: fixture.plan, overlay: fixture.overlay)

  #expect(report.unitOutcomes.first?.status == .jitRejected)
  #expect(await adapter.appliedActionIDs.isEmpty)
}

@Test(arguments: [false, true])
func jitRejectsMissingAndFailedFreshPolicyEvidence(failed: Bool) async throws {
  let fixture = try Fixture(content: .explicitlyNotApplicable(.metadataOnlyObject))
  let failure = Observation<FreshPolicyEvidence>.failed(
    ObservationFailure(code: "EIO", collector: "fresh-policy"))
  let authorization = try await makeAuthorization(
    plan: fixture.plan,
    overlay: fixture.overlay,
    jitSource: LiveJITSource(
      freshPolicyOverrides: [fixture.action.id: failed ? failure : .absent]
    )
  )
  let adapter = RecordingMutationAdapter()
  let report = await BestEffortApplyCoordinator(
    adapter: adapter,
    eventSink: RecordingEventSink(),
    auditSink: nil,
    clock: { 202 }
  ).apply(authorization: authorization, plan: fixture.plan, overlay: fixture.overlay)

  #expect(report.unitOutcomes.first?.status == .jitRejected)
  #expect(await adapter.appliedActionIDs.isEmpty)
}

@Test
func jitRejectsAMismatchedNonceAndAReusedCapture() async throws {
  let fixture = try MultiActionFixture(includeDependency: false)
  let nonceAuthorization = try await makeAuthorization(
    plan: fixture.plan,
    overlay: fixture.overlay,
    jitSource: LiveJITSource(nonceOverride: Data(repeating: 0xee, count: 32))
  )
  let nonceAdapter = RecordingMutationAdapter()
  let nonceReport = await BestEffortApplyCoordinator(
    adapter: nonceAdapter,
    eventSink: RecordingEventSink(),
    auditSink: nil,
    clock: { 202 }
  ).apply(
    authorization: nonceAuthorization,
    plan: fixture.plan,
    overlay: fixture.overlay
  )
  #expect(nonceReport.unitOutcomes.allSatisfy { $0.status == .jitRejected })
  #expect(await nonceAdapter.appliedActionIDs.isEmpty)

  let captureAuthorization = try await makeAuthorization(
    plan: fixture.plan,
    overlay: fixture.overlay,
    jitSource: LiveJITSource(fixedCaptureByte: 91)
  )
  let captureAdapter = RecordingMutationAdapter()
  let captureReport = await BestEffortApplyCoordinator(
    adapter: captureAdapter,
    eventSink: RecordingEventSink(),
    auditSink: nil,
    clock: { 202 }
  ).apply(
    authorization: captureAuthorization,
    plan: fixture.plan,
    overlay: fixture.overlay
  )
  #expect(
    captureReport.unitOutcomes.map(\.status)
      == [.succeeded, .jitRejected, .jitRejected])
  #expect(await captureAdapter.appliedActionIDs.count == 1)
}

@Test
func cancellationDuringJITIsDistinctAndDoesNotMutate() async throws {
  let fixture = try Fixture(content: .explicitlyNotApplicable(.metadataOnlyObject))
  let source = LiveJITSource(blockJITUntilCancelled: true)
  let authorization = try await makeAuthorization(
    plan: fixture.plan,
    overlay: fixture.overlay,
    jitSource: source
  )
  let adapter = RecordingMutationAdapter()
  let coordinator = BestEffortApplyCoordinator(
    adapter: adapter,
    eventSink: RecordingEventSink(),
    auditSink: nil,
    clock: { 202 }
  )
  let task = Task {
    await coordinator.apply(
      authorization: authorization,
      plan: fixture.plan,
      overlay: fixture.overlay
    )
  }
  await source.waitUntilJITEntered()
  task.cancel()
  let report = await task.value

  #expect(report.unitOutcomes.first?.status == .cancelled)
  #expect(
    report.unitOutcomes.first?.jitReport?.globalFindings.map(\.kind).contains(.cancelled)
      == true)
  #expect(await adapter.appliedActionIDs.isEmpty)
}

@Test
func compoundCancellationAfterTheFirstOwnerDoesNotStartLaterOwners() async throws {
  let fixture = try ReleaseFixture(content: .explicitlyNotApplicable(.metadataOnlyObject))
  let authorization = try await makeAuthorization(plan: fixture.plan, overlay: fixture.overlay)
  let adapter = FirstMutationGateAdapter()
  let coordinator = BestEffortApplyCoordinator(
    adapter: adapter,
    eventSink: RecordingEventSink(),
    auditSink: nil,
    clock: { 202 }
  )
  let task = Task {
    await coordinator.apply(
      authorization: authorization,
      plan: fixture.plan,
      overlay: fixture.overlay
    )
  }
  await adapter.waitUntilFirstMutationStarted()
  task.cancel()
  await adapter.releaseFirstMutation()
  let report = await task.value

  #expect(await adapter.appliedActionIDs.count == 1)
  #expect(report.unitOutcomes.first?.steps.first?.status == .succeeded)
  #expect(
    report.unitOutcomes.first?.steps.dropFirst().allSatisfy { $0.status == .cancelled }
      == true)
}

@Test
func compoundDeadlineAfterTheFirstOwnerDoesNotStartLaterOwners() async throws {
  let fixture = try ReleaseFixture(content: .explicitlyNotApplicable(.metadataOnlyObject))
  let authorization = try await makeAuthorization(plan: fixture.plan, overlay: fixture.overlay)
  let adapter = FirstMutationGateAdapter()
  let clock = LockedTestClock(202)
  let coordinator = BestEffortApplyCoordinator(
    adapter: adapter,
    eventSink: RecordingEventSink(),
    auditSink: nil,
    clock: clock.now
  )
  let task = Task {
    await coordinator.apply(
      authorization: authorization,
      plan: fixture.plan,
      overlay: fixture.overlay
    )
  }
  await adapter.waitUntilFirstMutationStarted()
  clock.set(230)
  await adapter.releaseFirstMutation()
  let report = await task.value

  #expect(await adapter.appliedActionIDs.count == 1)
  #expect(report.unitOutcomes.first?.steps.first?.status == .succeeded)
  #expect(
    report.unitOutcomes.first?.steps.dropFirst().allSatisfy { $0.status == .expired }
      == true)
}

@Test(arguments: [
  Observation<Bool>.known(false),
  .unknown(.incompleteCoverage),
])
func compoundReleaseRequiresPositiveAllocationTopologyProof(
  releaseOutcome: Observation<Bool>
) async throws {
  let fixture = try ReleaseFixture(content: .explicitlyNotApplicable(.metadataOnlyObject))
  let authorization = try await makeAuthorization(
    plan: fixture.plan,
    overlay: fixture.overlay,
    jitSource: LiveJITSource(releaseOutcome: releaseOutcome)
  )
  let report = await BestEffortApplyCoordinator(
    adapter: RecordingMutationAdapter(),
    eventSink: RecordingEventSink(),
    auditSink: nil,
    clock: { 202 }
  ).apply(authorization: authorization, plan: fixture.plan, overlay: fixture.overlay)

  #expect(report.unitOutcomes.first?.status == .failed)
  #expect(report.unitOutcomes.first?.releasePostVerification.first?.outcome != .satisfied)
}

@Test(arguments: [false, true])
func missingAndDuplicateReleasePostverificationFailClosed(duplicate: Bool) async throws {
  let fixture = try ReleaseFixture(content: .explicitlyNotApplicable(.metadataOnlyObject))
  let authorization = try await makeAuthorization(
    plan: fixture.plan,
    overlay: fixture.overlay,
    jitSource: LiveJITSource(
      omitReleaseOutcome: !duplicate,
      duplicateReleaseOutcome: duplicate
    )
  )
  let report = await BestEffortApplyCoordinator(
    adapter: RecordingMutationAdapter(),
    eventSink: RecordingEventSink(),
    auditSink: nil,
    clock: { 202 }
  ).apply(authorization: authorization, plan: fixture.plan, overlay: fixture.overlay)

  #expect(report.unitOutcomes.first?.status == .failed)
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

  #expect(
    await adapter.apply(operation, context: testMutationContext())
      == .succeeded(detailCode: "rm-completed")
  )
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

  guard
    case .failed(let failure) = await adapter.apply(
      operation,
      context: testMutationContext()
    )
  else {
    Issue.record("replacement must fail the final identity preflight")
    return
  }
  #expect(failure.code == "target-identity-mismatch")
  #expect(FileManager.default.fileExists(atPath: outside.path))
}

@Test
func posixRemoveRejectsFinalAccessPolicyMismatchWithoutMutation() async throws {
  let root = try TemporaryRemovalRoot()
  defer { root.cleanup() }
  let target = root.url.appendingPathComponent("victim")
  try Data("original".utf8).write(to: target)
  let action = try filesystemAction(root: root.url, targetName: "victim", kind: .regularFile)
  guard case .genericRemove(let contract) = action.prototype.adapterContract else {
    Issue.record("expected generic remove")
    return
  }
  let operation = ExecutionAdapterOperation.genericRemove(
    BoundMutationTarget(action: action), contract)
  let context = MutationExecutionContext(
    deadlineSeconds: 1_000,
    nowSeconds: { 0 },
    finalDescriptorPreflight: { _ in .accessPolicyMismatch }
  )

  guard
    case .failed(let failure) = await PosixRemoveAdapter().apply(
      operation,
      context: context
    )
  else {
    Issue.record("access-policy mismatch must fail before rm")
    return
  }
  #expect(failure.code == "final-preflight-access-policy-mismatch")
  #expect(FileManager.default.fileExists(atPath: target.path))
}

@Test
func posixRemoveDoesNotSpawnAfterItsDeadline() async throws {
  let root = try TemporaryRemovalRoot()
  defer { root.cleanup() }
  let target = root.url.appendingPathComponent("victim")
  try Data("original".utf8).write(to: target)
  let action = try filesystemAction(root: root.url, targetName: "victim", kind: .regularFile)
  guard case .genericRemove(let contract) = action.prototype.adapterContract else {
    Issue.record("expected generic remove")
    return
  }
  let operation = ExecutionAdapterOperation.genericRemove(
    BoundMutationTarget(action: action), contract)
  let expired = MutationExecutionContext(
    deadlineSeconds: 10,
    nowSeconds: { 10 },
    finalDescriptorPreflight: { _ in .verified }
  )

  #expect(await PosixRemoveAdapter().apply(operation, context: expired) == .timedOut)
  #expect(FileManager.default.fileExists(atPath: target.path))
}

@Test
func postverificationKeepsAbsentPresentAndIdentityMismatchDistinct() async throws {
  let root = try TemporaryRemovalRoot()
  defer { root.cleanup() }
  let target = root.url.appendingPathComponent("victim")
  try Data("original".utf8).write(to: target)
  let action = try filesystemAction(root: root.url, targetName: "victim", kind: .regularFile)
  guard case .genericRemove(let contract) = action.prototype.adapterContract else {
    Issue.record("expected generic remove")
    return
  }
  let operation = ExecutionAdapterOperation.genericRemove(
    BoundMutationTarget(action: action), contract)
  let adapter = PosixRemoveAdapter()

  #expect(await adapter.postverify(operation) == .notSatisfied(code: "target-still-present"))
  try FileManager.default.removeItem(at: target)
  #expect(await adapter.postverify(operation) == .satisfied)
  try Data("replacement".utf8).write(to: target)
  guard case .failed(let failure) = await adapter.postverify(operation) else {
    Issue.record("replacement must remain distinct from absence")
    return
  }
  #expect(failure.code == "target-identity-mismatch")
}

@Test
func posixRemoveRejectsRootSymlinkReplacementBetweenPreflights() async throws {
  let root = try TemporaryRemovalRoot()
  let movedRoot = root.parent.appendingPathComponent("moved-root-\(UUID().uuidString)")
  let outsideRoot = root.parent.appendingPathComponent("outside-root-\(UUID().uuidString)")
  try FileManager.default.createDirectory(at: outsideRoot, withIntermediateDirectories: false)
  defer {
    try? FileManager.default.removeItem(at: root.url)
    try? FileManager.default.removeItem(at: movedRoot)
    try? FileManager.default.removeItem(at: outsideRoot)
  }
  let target = root.url.appendingPathComponent("victim")
  try Data("original".utf8).write(to: target)
  let outsideTarget = outsideRoot.appendingPathComponent("victim")
  try Data("outside".utf8).write(to: outsideTarget)
  let action = try filesystemAction(root: root.url, targetName: "victim", kind: .regularFile)
  guard case .genericRemove(let contract) = action.prototype.adapterContract else {
    Issue.record("expected generic remove")
    return
  }
  let operation = ExecutionAdapterOperation.genericRemove(
    BoundMutationTarget(action: action), contract)
  let adapter = PosixRemoveAdapter(beforeFinalPreflight: {
    try? FileManager.default.moveItem(at: root.url, to: movedRoot)
    try? FileManager.default.createSymbolicLink(at: root.url, withDestinationURL: outsideRoot)
  })

  guard
    case .failed(let failure) = await adapter.apply(
      operation,
      context: testMutationContext()
    )
  else {
    Issue.record("root replacement must fail no-follow final preflight")
    return
  }
  #expect(failure.code == "open-root")
  #expect(try Data(contentsOf: outsideTarget) == Data("outside".utf8))
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

@Test
func posixRemovePreservesLeadingDashAndShellMetacharacterBytes() async throws {
  let root = try TemporaryRemovalRoot()
  defer { root.cleanup() }
  let rawName = Data("-$(touch pwned);*?".utf8)
  let rootDescriptor = root.url.path.withCString {
    Darwin.open($0, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
  }
  guard rootDescriptor >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
  defer { _ = Darwin.close(rootDescriptor) }
  let created = try withTestRawCString(rawName) {
    Darwin.openat(rootDescriptor, $0, O_CREAT | O_EXCL | O_WRONLY | O_CLOEXEC, 0o600)
  }
  guard created >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
  _ = Darwin.close(created)
  let action = try filesystemAction(
    root: root.url,
    targetNameBytes: rawName,
    candidateID: "raw-name",
    kind: .regularFile
  )
  guard case .genericRemove(let contract) = action.prototype.adapterContract else {
    Issue.record("expected generic remove")
    return
  }
  let operation = ExecutionAdapterOperation.genericRemove(
    BoundMutationTarget(action: action), contract)

  #expect(
    await PosixRemoveAdapter().apply(operation, context: testMutationContext())
      == .succeeded(detailCode: "rm-completed")
  )
  var status = stat()
  let result = try withTestRawCString(rawName) {
    Darwin.fstatat(rootDescriptor, $0, &status, AT_SYMLINK_NOFOLLOW)
  }
  #expect(result == -1)
  #expect(errno == ENOENT)
  #expect(!FileManager.default.fileExists(atPath: root.url.appendingPathComponent("pwned").path))
}

@Test
func relativeRMArgumentsPreserveNonUTF8BytesWithoutLocaleConversion() {
  let rawLeaf = Data([0xff, 0xfe, 0x80])
  let arguments = PosixRemoveAdapter.relativeArguments(
    leaf: rawLeaf,
    kind: .regularFile,
    force: .notRequired
  )
  var expected = Data("./".utf8)
  expected.append(rawLeaf)

  #expect(arguments == [Data("rm".utf8), Data("--".utf8), expected])
}

@Test
func directoryRemovalArgumentsAreRecursiveAndForceIsNeverImplicit() throws {
  let root = try TemporaryRemovalRoot()
  defer { root.cleanup() }
  let ordinaryURL = root.url.appendingPathComponent("ordinary-dir")
  let forcedURL = root.url.appendingPathComponent("forced-dir")
  try FileManager.default.createDirectory(at: ordinaryURL, withIntermediateDirectories: false)
  try FileManager.default.createDirectory(at: forcedURL, withIntermediateDirectories: false)
  let ordinary = try filesystemAction(
    root: root.url,
    targetName: "ordinary-dir",
    kind: .directory
  )
  let forced = try filesystemAction(
    root: root.url,
    targetName: "forced-dir",
    kind: .directory,
    force: .requiresForceWithWarning
  )
  guard case .genericRemove(let ordinaryContract) = ordinary.prototype.adapterContract,
    case .genericRemove(let forcedContract) = forced.prototype.adapterContract
  else {
    Issue.record("expected generic remove contracts")
    return
  }

  #expect(
    try PosixRemoveAdapter.arguments(
      target: BoundMutationTarget(action: ordinary),
      contract: ordinaryContract
    )[1] == Data("-Rx".utf8)
  )
  #expect(
    try PosixRemoveAdapter.arguments(
      target: BoundMutationTarget(action: forced),
      contract: forcedContract
    )[1] == Data("-Rfx".utf8)
  )
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
      captureID: digest(90),
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
  let freshPolicyOverrides: [ActionID: Observation<FreshPolicyEvidence>]
  let releaseOutcome: Observation<Bool>
  let fixedCaptureByte: UInt8?
  let nonceOverride: Data?
  let omitReleaseOutcome: Bool
  let duplicateReleaseOutcome: Bool
  let blockJITUntilCancelled: Bool
  private var nextCaptureByte: UInt8
  private var jitEntered = false
  private var jitEntryWaiters: [CheckedContinuation<Void, Never>] = []

  init(
    identityOverrides: [ActionID: Observation<ObjectIdentity>] = [:],
    freshPolicyOverrides: [ActionID: Observation<FreshPolicyEvidence>] = [:],
    releaseOutcome: Observation<Bool> = .known(true),
    initialCaptureByte: UInt8 = 91,
    fixedCaptureByte: UInt8? = nil,
    nonceOverride: Data? = nil,
    omitReleaseOutcome: Bool = false,
    duplicateReleaseOutcome: Bool = false,
    blockJITUntilCancelled: Bool = false
  ) {
    self.identityOverrides = identityOverrides
    self.freshPolicyOverrides = freshPolicyOverrides
    self.releaseOutcome = releaseOutcome
    self.fixedCaptureByte = fixedCaptureByte
    self.nonceOverride = nonceOverride
    self.omitReleaseOutcome = omitReleaseOutcome
    self.duplicateReleaseOutcome = duplicateReleaseOutcome
    self.blockJITUntilCancelled = blockJITUntilCancelled
    self.nextCaptureByte = initialCaptureByte
  }

  func collectJITEvidence(for request: JITRevalidationRequest) async throws
    -> JITRevalidationSnapshot
  {
    jitEntered = true
    let waiters = jitEntryWaiters
    jitEntryWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
    if blockJITUntilCancelled {
      try await Task.sleep(for: .seconds(60))
    }
    let captureID = digest(fixedCaptureByte ?? nextCaptureByte)
    if fixedCaptureByte == nil { nextCaptureByte &+= 1 }
    let byID = Dictionary(uniqueKeysWithValues: request.plan.actions.map { ($0.id, $0) })
    return JITRevalidationSnapshot(
      oneShotNonce: nonceOverride ?? request.oneShotNonce,
      authorizationCurrentBindingHash: request.authorizationCurrentBindingHash,
      preparationGeneration: request.preparationGeneration,
      epochID: request.epoch.epochID,
      snapshot: CurrentRevalidationSnapshot(
        captureID: captureID,
        actions: request.actionIDs.compactMap { actionID in
          byID[actionID].map {
            currentEvidence(
              $0,
              identity: identityOverrides[actionID],
              executionReferenceTimeSeconds: request.epoch.semanticReferenceTimeSeconds,
              freshCaptureID: captureID,
              freshPolicyEvidence: freshPolicyOverrides[actionID]
            )
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
    )
  }

  func collectReleasePostVerification(
    for request: ReleasePostVerificationRequest
  ) async throws -> [CurrentReleasePostcondition] {
    guard !omitReleaseOutcome else { return [] }
    let outcomes = request.allocationGroupIDs.map {
      CurrentReleasePostcondition(allocationGroupID: $0, released: releaseOutcome)
    }
    return duplicateReleaseOutcome ? outcomes + outcomes : outcomes
  }

  func collectFinalDescriptorEvidence(
    for request: FinalDescriptorPreflightRequest
  ) async throws -> FinalDescriptorEvidenceSnapshot {
    matchingFinalDescriptorEvidence(request)
  }

  func waitUntilJITEntered() async {
    guard !jitEntered else { return }
    await withCheckedContinuation { continuation in
      jitEntryWaiters.append(continuation)
    }
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

  func apply(
    _ operation: ExecutionAdapterOperation,
    context _: MutationExecutionContext
  ) async -> AdapterOperationOutcome {
    appliedActionIDs.append(operation.actionID)
    await eventSink?.recordAdapterMutation(operation.actionID)
    return outcomes[operation.actionID] ?? .succeeded(detailCode: "mock-success")
  }

  func postverify(_ operation: ExecutionAdapterOperation) async -> PostVerificationOutcome {
    postOutcomes[operation.actionID] ?? .satisfied
  }
}

private actor FirstMutationGateAdapter: ExecutionMutationAdapter {
  private(set) var appliedActionIDs: [ActionID] = []
  private var firstStarted = false
  private var firstStartWaiters: [CheckedContinuation<Void, Never>] = []
  private var firstRelease: CheckedContinuation<Void, Never>?

  func apply(
    _ operation: ExecutionAdapterOperation,
    context _: MutationExecutionContext
  ) async -> AdapterOperationOutcome {
    appliedActionIDs.append(operation.actionID)
    guard appliedActionIDs.count == 1 else {
      return .succeeded(detailCode: "unexpected-later-owner")
    }
    firstStarted = true
    let waiters = firstStartWaiters
    firstStartWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
    await withCheckedContinuation { continuation in
      firstRelease = continuation
    }
    return .succeeded(detailCode: "first-owner-completed")
  }

  func postverify(_: ExecutionAdapterOperation) async -> PostVerificationOutcome {
    .satisfied
  }

  func waitUntilFirstMutationStarted() async {
    guard !firstStarted else { return }
    await withCheckedContinuation { continuation in
      firstStartWaiters.append(continuation)
    }
  }

  func releaseFirstMutation() {
    firstRelease?.resume()
    firstRelease = nil
  }
}

private final class LockedTestClock: @unchecked Sendable {
  private let lock = NSLock()
  private var value: Int64

  init(_ value: Int64) { self.value = value }

  func now() -> Int64 { lock.withLock { value } }

  func set(_ value: Int64) { lock.withLock { self.value = value } }
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
  func record(_: ExecutionEvent) async throws { throw POSIXError(.ENOSPC) }
}

private func makeAuthorization(
  plan: ImmutablePlan,
  overlay: DecisionOverlay,
  jitSource: any JITRevalidationEvidenceSource = LiveJITSource()
) async throws -> ApplyAuthorization {
  let engine = ExecutionPreparationEngine(
    evidenceSource: PreparationSnapshotSource(),
    jitEvidenceSource: jitSource,
    randomBytes: deterministicEntropy
  )
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
  let confirmation =
    ready.forceWarningActionIDs.isEmpty
    ? nil
    : ApplyReviewConfirmation.confirm(ready)
  return try await engine.authorizeApply(
    capability,
    ready: ready,
    plan: plan,
    overlay: overlay,
    confirmation: confirmation,
    nowSeconds: 201
  )
}

private struct MultiActionFixture {
  let first: ActionDefinition
  let independent: ActionDefinition
  let dependent: ActionDefinition
  let plan: ImmutablePlan
  let overlay: DecisionOverlay

  init(includeDependency: Bool) throws {
    let facts = globalFacts()
    let content = ContentProtectionBaseline.explicitlyNotApplicable(.metadataOnlyObject)
    let firstEvidence = snapshot(
      candidateID: "first", path: "first", object: 11, content: content)
    let independentEvidence = snapshot(
      candidateID: "independent", path: "independent", object: 12, content: content)
    let dependentEvidence = snapshot(
      candidateID: "dependent", path: "dependent", object: 13, content: content)
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

private func testMutationContext() -> MutationExecutionContext {
  MutationExecutionContext(
    deadlineSeconds: 1_000,
    nowSeconds: { 0 },
    finalDescriptorPreflight: { request in
      EngineRevalidationCollector.evaluateFinalDescriptorEvidence(
        matchingFinalDescriptorEvidence(request),
        target: request.target
      )
    }
  )
}

private func matchingFinalDescriptorEvidence(
  _ request: FinalDescriptorPreflightRequest
) -> FinalDescriptorEvidenceSnapshot {
  let target = request.target
  return FinalDescriptorEvidenceSnapshot(
    targetIdentity: .known(target.expectedIdentity),
    targetAccessPolicy: .known(target.expectedTargetAccessPolicy),
    targetContent: .known(target.expectedContent),
    root: CurrentNamespaceComponent(
      relativePath: nil,
      identity: .known(target.expectedRootIdentity),
      seal: .known(target.expectedRootSeal)
    ),
    parents: target.expectedParentIdentities.indices.map { index in
      CurrentNamespaceComponent(
        relativePath: try? RawTargetPath(
          components: Array(target.targetPath.components.prefix(index + 1))),
        identity: .known(target.expectedParentIdentities[index]),
        seal: .known(target.expectedParentSeals[index])
      )
    }
  )
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
  try filesystemAction(
    root: root,
    targetNameBytes: Data(targetName.utf8),
    candidateID: targetName,
    kind: kind,
    force: force
  )
}

private func filesystemAction(
  root: URL,
  targetNameBytes: Data,
  candidateID: String,
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
  let targetIdentity = try filesystemIdentity(
    root: root,
    rawName: targetNameBytes,
    kind: kind
  )
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
    targetPath: try RawTargetPath(components: [targetNameBytes]),
    targetIdentity: targetIdentity,
    parentChain: []
  )
  let evidence = try FrozenEvidenceSnapshot(
    captureID: facts.captureID,
    globalFactsHash: facts.globalFactsHash,
    candidateID: candidateID,
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
    contentProtection: .known(.explicitlyNotApplicable(.metadataOnlyObject)),
    aclDigest: .known(digest(204)),
    targetMountIdentity: .known("test-mount"),
    removalForceRequirement: .known(force),
    quarantineCapability: .known(true),
    gitWorktree: nil,
    adapterScope: .genericRemove,
    additionalAdapterScopes: [],
    classificationClaims: completeClassificationClaims(),
    semanticReferenceTimeSeconds: 100,
    policyVersion: "policy-1",
    schemaVersion: "schema-1"
  )
  return try makeAction(evidence: evidence, facts: facts)
}

private func filesystemIdentity(
  root: URL,
  rawName: Data,
  kind: ObjectKind
) throws -> ObjectIdentity {
  let rootDescriptor = root.path.withCString {
    Darwin.open($0, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
  }
  guard rootDescriptor >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
  defer { _ = Darwin.close(rootDescriptor) }
  var status = stat()
  let result = try withTestRawCString(rawName) {
    Darwin.fstatat(rootDescriptor, $0, &status, AT_SYMLINK_NOFOLLOW)
  }
  guard result == 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
  return ObjectIdentity(
    device: UInt64(UInt32(bitPattern: status.st_dev)),
    object: UInt64(status.st_ino),
    generation: .known(UInt64(status.st_gen)),
    type: kind
  )
}

private func withTestRawCString<Result>(
  _ bytes: Data,
  _ body: (UnsafePointer<CChar>) throws -> Result
) throws -> Result {
  var storage = bytes.map { CChar(bitPattern: $0) }
  storage.append(0)
  return try storage.withUnsafeBufferPointer { buffer in
    try body(buffer.baseAddress!)
  }
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
