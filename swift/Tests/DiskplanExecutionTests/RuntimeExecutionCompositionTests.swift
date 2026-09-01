import DiskplanCore
@_spi(DiskplanEngine) @testable import DiskplanExecution
import DiskplanPolicy
import DiskplanProto
import Foundation
import Testing

@testable import DiskplanEngine
@testable import DiskplanEngineCore

@Test
func runtimeCompositionProjectsCurrentDryRunFromAuthoritativePreparation() async throws {
  let fixture = try Fixture()
  let backend = DiskplanRuntimeExecutionBackend(
    composition: productionTestComposition(fixture: fixture)
  )
  let context = runtimeContext(fixture)

  let prepared = try await backend.prepareDryRun(context: context, lifetimeSeconds: 30)
  let sealed = try SealedRuntimeWire.sealDryRun(
    payload: prepared.payload,
    manifest: prepared.manifest,
    negotiatedProtocolMinor: protocol15Minor
  )

  #expect(sealed.manifest.current)
  #expect(sealed.manifest.selectedActionCount == 1)
  #expect(sealed.manifest.maximumActionCount == SealedRuntimeWire.maximumActionCount)
  #expect(sealed.manifest.maximumFindingCount == SealedRuntimeWire.maximumFindingCount)
  #expect(prepared.payload.actions.map(\.actionID.value) == [fixture.action.id.digest.bytes])
}

@Test
func runtimeCompositionProjectsReviewAndSealedApplyTail() async throws {
  let fixture = try Fixture(content: .explicitlyNotApplicable(.metadataOnlyObject))
  let backend = DiskplanRuntimeExecutionBackend(
    composition: productionTestComposition(fixture: fixture)
  )
  let context = runtimeContext(fixture)
  let prepared = try await backend.prepareApplyReview(context: context, lifetimeSeconds: 30)
  let sealedReview = try SealedRuntimeWire.sealApplyReview(
    prepared.projection,
    negotiatedProtocolMinor: protocol15Minor
  )

  let launch = try await prepared.attempt.start(
    confirmation: RuntimeApplyConfirmation(
      review: sealedReview,
      confirmedForceActionIDs: sealedReview.forceWarningActionIds
    ),
    context: context
  )
  let run = try #require(startedRun(launch))
  let tail = try #require(sealedTail(await run.awaitTail()))
  let hasFinishedUnit = tail.events.contains { event in
    if case .unitFinished? = event.body { true } else { false }
  }

  #expect(tail.events.last?.body.isApplyFinished == true)
  #expect(hasFinishedUnit)
  guard case .applyFinished(let terminal)? = tail.events.last?.body else {
    Issue.record("expected terminal apply_finished")
    return
  }
  #expect(terminal.eventCount == UInt64(tail.events.count + 1))
  #expect(terminal.maximumEventCount == SealedRuntimeWire.maximumExecutionEventCount)
  #expect(terminal.maximumEncodedEventBytes == SealedRuntimeWire.maximumExecutionBytes)
}

@Test
func runtimeCompositionCancellationStopsCoordinatorAndReturnsSealedTail() async throws {
  let fixture = try Fixture(content: .explicitlyNotApplicable(.metadataOnlyObject))
  let backend = DiskplanRuntimeExecutionBackend(
    composition: productionTestComposition(fixture: fixture, jitDelayNanoseconds: 30_000_000_000)
  )
  let context = runtimeContext(fixture)
  let prepared = try await backend.prepareApplyReview(context: context, lifetimeSeconds: 60)
  let sealedReview = try SealedRuntimeWire.sealApplyReview(
    prepared.projection,
    negotiatedProtocolMinor: protocol15Minor
  )
  let launch = try await prepared.attempt.start(
    confirmation: RuntimeApplyConfirmation(
      review: sealedReview,
      confirmedForceActionIDs: sealedReview.forceWarningActionIds
    ),
    context: context
  )
  let run = try #require(startedRun(launch))

  run.cancel()
  let tail = try #require(sealedTail(await run.awaitTail()))
  let hasCancelledUnit = tail.events.contains { event in
    if case .unitFinished(let unit)? = event.body {
      unit.status == .cancelled
    } else {
      false
    }
  }

  #expect(hasCancelledUnit)
}

@Test
func runtimeCompositionRejectsApplyReviewWhenRevalidationIsNotCurrent() async throws {
  let fixture = try Fixture()
  let collector = EngineRevalidationCollector { request in
    fixture.currentSnapshot(
      identity: .known(
        ObjectIdentity(
          device: 999,
          object: 999,
          generation: .unknown(.notRequested),
          type: .regularFile
        )),
      executionReferenceTimeSeconds: request.epoch.semanticReferenceTimeSeconds
    )
  }
  let backend = DiskplanRuntimeExecutionBackend(
    composition: EngineExecutionComposition(
      collector: collector,
      eventSink: NoOpExecutionEventSink()
    )
  )

  await #expect(throws: RuntimeExecutionBackendFailure.revalidationFailed) {
    try await backend.prepareApplyReview(
      context: runtimeContext(fixture),
      lifetimeSeconds: 30
    )
  }
}

@Test
func runtimeCompositionNormalizesUnknownAndObservationFailureDetails() throws {
  let fixture = try Fixture()
  let context = runtimeContext(fixture)
  let oversized = String(repeating: "é", count: 4_096)
  let report = try noncurrentDryRunReport(
    fixture: fixture,
    findings: [
      RevalidationFinding(
        actionID: nil,
        subject: .collectorStatus,
        kind: .collectionFailed,
        observationFailure: ObservationFailure(code: "", collector: "")
      ),
      RevalidationFinding(
        actionID: nil,
        subject: .providerState,
        kind: .unknown
      ),
      RevalidationFinding(
        actionID: nil,
        subject: .collectorStatus,
        kind: .collectionFailed,
        observationFailure: ObservationFailure(code: oversized, collector: oversized)
      ),
    ]
  )
  let prepared = try RuntimeExecutionProjector(
    context: context,
    nextID: { Data("normalized-dry-run".utf8) }
  ).dryRun(report)
  let sealed = try SealedRuntimeWire.sealDryRun(
    payload: prepared.payload,
    manifest: prepared.manifest,
    negotiatedProtocolMinor: protocol15Minor
  )

  #expect(sealed.manifest.findingCount == 3)
  guard
    case .observationFailure(let emptyDetail)? = prepared.payload.revalidation
      .globalFindings[0].detail,
    case .unknown(let unknownDetail)? = prepared.payload.revalidation.globalFindings[1].detail,
    case .observationFailure(let oversizedDetail)? = prepared.payload.revalidation
      .globalFindings[2].detail
  else {
    Issue.record("expected normalized finding detail variants")
    return
  }
  #expect(emptyDetail.code == "observation-failed")
  #expect(emptyDetail.collector == "unknown-collector")
  #expect(unknownDetail.code == "unspecified-unknown")
  #expect(unknownDetail.summary == "unspecified unknown observation")
  #expect(oversizedDetail.code.utf8.count == 4_096)
  #expect(oversizedDetail.collector.utf8.count == 4_096)
  #expect(String(data: Data(oversizedDetail.code.utf8), encoding: .utf8) != nil)
}

@Test(arguments: [Data(), Data(repeating: 0x61, count: 257)])
func runtimeCompositionRejectsInvalidGeneratedIdentifiers(identifier: Data) throws {
  let fixture = try Fixture()
  let projector = try RuntimeExecutionProjector(
    context: runtimeContext(fixture),
    nextID: { identifier }
  )
  let report = try noncurrentDryRunReport(fixture: fixture, findings: [])

  #expect(throws: DiskplanRuntimeExecutionProjectionError.invalidGeneratedIdentifier) {
    try projector.dryRun(report)
  }
}

@Test
func runtimeCompositionAcceptsReorderedUniqueForceConfirmationSet() {
  let first = Data(repeating: 0x31, count: 32)
  let second = Data(repeating: 0x32, count: 32)

  #expect(
    runtimeForceConfirmationMatches(
      confirmed: [second, first],
      expected: [first, second]
    ))
}

@Test
func runtimeCompositionRejectsDuplicateForceConfirmationSet() {
  let first = Data(repeating: 0x31, count: 32)
  let second = Data(repeating: 0x32, count: 32)

  #expect(
    !runtimeForceConfirmationMatches(
      confirmed: [first, first, second],
      expected: [first, second]
    ))
  #expect(
    !runtimeForceConfirmationMatches(
      confirmed: [first, second],
      expected: [first, first, second]
    ))
}

@Test
func runtimeCompositionKeepsExactReleaseSetIDsWhenOwnerSetsMatch() throws {
  let owner = Data(repeating: 0x44, count: 32)
  let firstGroup = "allocation-a"
  let secondGroup = "allocation-b"
  let firstID = Data(repeating: 0xa1, count: 32)
  let secondID = Data(repeating: 0xb2, count: 32)
  var firstWire = Diskplan_V1_PlanReleaseSetProjection()
  firstWire.releaseSetID.value = firstID
  firstWire.actionIds = [opaqueIdentifier(owner)]
  var secondWire = Diskplan_V1_PlanReleaseSetProjection()
  secondWire.releaseSetID.value = secondID
  secondWire.actionIds = [opaqueIdentifier(owner)]

  let result = try runtimeExactReleaseSetBindings(
    domains: [
      RuntimeReleaseSetDomainBinding(
        allocationGroupID: firstGroup,
        ownerActionIDs: [owner]
      ),
      RuntimeReleaseSetDomainBinding(
        allocationGroupID: secondGroup,
        ownerActionIDs: [owner]
      ),
    ],
    exactIDsByAllocationGroup: [
      Data(firstGroup.utf8): firstID,
      Data(secondGroup.utf8): secondID,
    ],
    wireReleaseSets: [firstID: firstWire, secondID: secondWire]
  )

  #expect(result[firstGroup] == firstID)
  #expect(result[secondGroup] == secondID)
}

@Test
func runtimeCompositionProjectsCompleteSkippedUnitOutcomeImmediately() throws {
  let fixture = try Fixture()
  let projector = try RuntimeExecutionProjector(
    context: runtimeContext(fixture),
    nextID: { Data("projected-event".utf8) }
  )
  let outcome = ExecutionUnitOutcome(
    id: .action(fixture.action.id),
    logicalActionIDs: [fixture.action.id],
    prerequisiteActionIDs: [fixture.action.id],
    status: .skippedPrerequisite,
    jitReport: nil,
    steps: []
  )
  let events = projector.project(
    .unitFinished(outcome),
    executionID: Data("execution".utf8),
    review: Diskplan_V1_ApplyReviewProjection()
  )

  #expect(events.count == 2)
  guard case .unitSkippedPrerequisite(let skipped)? = events.first?.body,
    case .unitFinished(let finished)? = events.last?.body
  else {
    Issue.record("expected skipped-prerequisite detail followed by unit_finished")
    return
  }
  #expect(skipped.blockingPrerequisites.count == 1)
  #expect(finished.status == .skippedPrerequisite)
}

@Test
func runtimeProjectedExecutionBufferRejectsEventCountOverflow() throws {
  var first = Diskplan_V1_ExecutionStreamEvent()
  first.executionID.value = Data("execution".utf8)
  first.body = .applyStarted(Diskplan_V1_ApplyStartedProjection())
  var second = Diskplan_V1_ExecutionStreamEvent()
  second.executionID = first.executionID
  second.body = .applyFinished(Diskplan_V1_ApplyFinishedProjection())
  var buffer = RuntimeProjectedExecutionBuffer(
    budget: RuntimeApplyCaptureBudget(
      maximumEventCount: 1,
      maximumAccountedBytes: .max,
      perEventOverheadBytes: 0,
      terminalReserveBytes: 0
    ))
  let encodedBytes = UInt64(
    try first.serializedData().count + second.serializedData().count
  )

  #expect(buffer.append([first]) == nil)
  #expect(
    buffer.append([second])
      == .projectionLimitExceeded(
        observedEventCount: 2,
        observedEncodedBytes: encodedBytes
      ))
  #expect(buffer.events == [first])
}

@Test
func runtimeProjectedExecutionBufferRejectsSerializedMemoryOverflow() throws {
  var event = Diskplan_V1_ExecutionStreamEvent()
  event.executionID.value = Data("execution".utf8)
  event.body = .applyStarted(Diskplan_V1_ApplyStartedProjection())
  let encodedBytes = UInt64(try event.serializedData().count)
  var buffer = RuntimeProjectedExecutionBuffer(
    budget: RuntimeApplyCaptureBudget(
      maximumEventCount: 1,
      maximumAccountedBytes: encodedBytes + 511,
      perEventOverheadBytes: 512,
      terminalReserveBytes: 0
    ))

  #expect(
    buffer.append([event])
      == .projectionLimitExceeded(
        observedEventCount: 1,
        observedEncodedBytes: encodedBytes
      ))
  #expect(buffer.events.isEmpty)
}

private func productionTestComposition(
  fixture: Fixture,
  jitDelayNanoseconds: UInt64 = 0
) -> EngineExecutionComposition {
  let action = fixture.action
  let collector = EngineRevalidationCollector(
    collectCurrent: { request in
      fixture.currentSnapshot(
        executionReferenceTimeSeconds: request.epoch.semanticReferenceTimeSeconds
      )
    },
    collectJIT: { request in
      if jitDelayNanoseconds > 0 {
        try await Task.sleep(nanoseconds: jitDelayNanoseconds)
      }
      return JITRevalidationSnapshot(
        oneShotNonce: request.oneShotNonce,
        authorizationCurrentBindingHash: request.authorizationCurrentBindingHash,
        preparationGeneration: request.preparationGeneration,
        epochID: request.epoch.epochID,
        snapshot: CurrentRevalidationSnapshot(
          captureID: digest(91),
          actions: [
            currentEvidence(
              action,
              executionReferenceTimeSeconds: request.epoch.semanticReferenceTimeSeconds
            )
          ],
          releaseTopologies: [],
          invariants: passingInvariants
        )
      )
    },
    collectReleasePostconditions: { _ in [] },
    collectFinalDescriptors: { _ in throw RuntimeCompositionTestError.finalDescriptorUnavailable }
  )
  return EngineExecutionComposition(
    collector: collector,
    eventSink: NoOpExecutionEventSink()
  )
}

private func runtimeContext(_ fixture: Fixture) -> RuntimeExecutionPlanContext {
  let planDigest = fixture.plan.planHash.bytes
  let evidenceDigest = fixture.evidence.evidenceID.bytes
  var preview = Diskplan_V1_ActionExecutionPreviewProjection()
  preview.adapter = .genericRemove
  preview.rawExecutable = Data("/bin/rm".utf8)
  preview.rawArgv = [Data("rm".utf8), Data("--".utf8), Data("target".utf8)]
  preview.displayArgv = ["rm", "--", "target"]
  preview.postcondition = "target missing"
  preview.mutationSupported = true
  preview.rawWorkingDirectory = Data("/tmp".utf8)
  preview.pathRace = .residual

  var action = Diskplan_V1_PlanActionProjection()
  action.actionID.value = fixture.action.id.digest.bytes
  action.executionPreview = preview
  action.requiresForce = false
  var record = Diskplan_V1_PlanProjectionRecord()
  record.recordIndex = 0
  record.body = .action(action)

  var manifest = Diskplan_V1_PlanProjectionManifest()
  manifest.projectionID.value = Data("projection".utf8)
  manifest.planID.value = planDigest
  manifest.planSha256.value = planDigest
  manifest.evidenceID.value = evidenceDigest
  manifest.evidenceSha256.value = evidenceDigest
  manifest.scanSessionID.value = Data("scan".utf8)
  manifest.scanCheckpointID.value = lowercaseHex(evidenceDigest)
  manifest.scanCheckpointEvidenceSha256.value = evidenceDigest

  var overlay = Diskplan_V1_DecisionOverlayAcknowledged()
  overlay.projectionID = manifest.projectionID
  overlay.revision = 1
  overlay.overlayID.value = Data("overlay".utf8)
  overlay.overlaySha256.value = fixture.overlay.overlayHash.bytes
  overlay.selectedActionIds = [opaqueIdentifier(fixture.action.id.digest.bytes)]
  overlay.selectedActionCount = 1

  return RuntimeExecutionPlanContext(
    plan: fixture.plan,
    overlay: fixture.overlay,
    planRecords: [record],
    releaseSetIDByAllocationGroup: [:],
    planManifest: manifest,
    overlayProjection: overlay,
    negotiatedProtocolMinor: protocol15Minor
  )
}

private func noncurrentDryRunReport(
  fixture: Fixture,
  findings: [RevalidationFinding]
) throws -> DryRunReport {
  let epoch = try ExecutionEpochContext(
    epochID: "projection-normalization",
    semanticReferenceTimeSeconds: 100,
    issuedAtSeconds: 100,
    deadlineSeconds: 200
  )
  return DryRunReport(
    revalidation: RevalidationReport(
      planHash: fixture.plan.planHash,
      overlayHash: fixture.overlay.overlayHash,
      epoch: epoch,
      actionOutcomes: [ActionRevalidationOutcome(actionID: fixture.action.id, findings: [])],
      globalFindings: findings,
      manifest: nil
    )
  )
}

private func opaqueIdentifier(_ bytes: Data) -> Diskplan_V1_OpaqueIdentifier {
  var value = Diskplan_V1_OpaqueIdentifier()
  value.value = bytes
  return value
}

private func startedRun(_ launch: RuntimeApplyLaunchResult) -> RuntimeExecutionRunHandle? {
  guard case .started(let run) = launch else { return nil }
  return run
}

private func sealedTail(_ outcome: RuntimeExecutionTailOutcome) -> RuntimeExecutionTail? {
  guard case .sealed(let tail) = outcome else { return nil }
  return tail
}

private func lowercaseHex(_ bytes: Data) -> Data {
  Data(bytes.map { String(format: "%02x", $0) }.joined().utf8)
}

private enum RuntimeCompositionTestError: Error {
  case finalDescriptorUnavailable
}

extension Optional where Wrapped == Diskplan_V1_ExecutionStreamEvent.OneOf_Body {
  fileprivate var isApplyFinished: Bool {
    if case .applyFinished? = self { true } else { false }
  }
}
