import DiskplanCore
import DiskplanProto
import Foundation
import Testing

@testable import DiskplanEngineCore

@Test func scanOnlyEngineDoesNotAdvertiseRuntimeAndRejectsRequestTyped() throws {
  let envelopes = try runRuntimeExchange(handler: nil)
  #expect(envelopes.count == 2)
  guard case .helloAccepted(let accepted) = envelopes[0].body else {
    Issue.record("expected accepted handshake")
    return
  }
  #expect(Set(accepted.negotiatedCapabilities).isDisjoint(with: protocol14RuntimeCapabilities))
  guard case .runtimeEvent(let event) = envelopes[1].body,
    case .runtimeRejected(let rejected) = event.body
  else {
    Issue.record("expected typed runtime rejection")
    return
  }
  #expect(envelopes[1].sequence == event.eventSequence)
  #expect(event.requestID == 2)
  #expect(!event.runtimeSessionID.value.isEmpty)
  #expect(rejected.code == .businessUnsupported)
}

@Test func installedRuntimeHandlerAdvertisesAndReceivesNegotiatedRequest() throws {
  let handler = RecordingRuntimeHandler()
  let envelopes = try runRuntimeExchange(handler: handler)
  #expect(envelopes.count == 2)
  guard case .helloAccepted(let accepted) = envelopes[0].body else {
    Issue.record("expected accepted handshake")
    return
  }
  #expect(accepted.negotiatedCapabilities.contains("plan-projection-v1"))
  #expect(!accepted.negotiatedCapabilities.contains("decision-overlay-v1"))
  #expect(handler.requestIDs == [2])
  #expect(handler.negotiatedProtocolMinors == [protocol16Minor])
  guard case .runtimeEvent(let event) = envelopes[1].body,
    case .runtimeRejected(let rejected) = event.body
  else {
    Issue.record("expected fake handler response")
    return
  }
  #expect(rejected.code == .invalidState)
}

@Test func runtimeResponderReceivesDowngradedNegotiatedProtocolMinor() throws {
  let handler = RecordingRuntimeHandler()
  let envelopes = try runRuntimeExchange(handler: handler, peerProtocolMinor: protocol14Minor)
  guard case .helloAccepted(let accepted) = envelopes.first?.body else {
    Issue.record("expected accepted handshake")
    return
  }
  #expect(accepted.selectedVersion.minor == protocol14Minor)
  #expect(handler.negotiatedProtocolMinors == [protocol14Minor])
}

@Test func engineRequiresProtocol16BeforeMutationDispatchButKeepsDryRunCompatible() throws {
  var review = Diskplan_V1_PrepareApplyReviewRequest()
  review.requestID = 2
  var confirmation = Diskplan_V1_ConfirmApplyRequest()
  confirmation.requestID = 2
  for body in [
    Diskplan_V1_Envelope.OneOf_Body.prepareApplyReviewRequest(review),
    .confirmApplyRequest(confirmation),
  ] {
    let envelopes = try runRuntimeExchange(
      handler: ExecutionRecordingRuntimeHandler(),
      requestBody: body,
      peerProtocolMinor: protocol15Minor
    )
    guard case .runtimeEvent(let event) = envelopes.last?.body,
      case .runtimeRejected(let rejected) = event.body
    else {
      Issue.record("expected protocol-1.6 mutation rejection")
      continue
    }
    #expect(rejected.code == .capabilityNotNegotiated)
    #expect(rejected.summary.contains("protocol 1.6"))
  }

  var dryRun = Diskplan_V1_PrepareDryRunRequest()
  dryRun.requestID = 2
  let handler = DryRunRecordingRuntimeHandler()
  let envelopes = try runRuntimeExchange(
    handler: handler,
    requestBody: .prepareDryRunRequest(dryRun),
    peerProtocolMinor: protocol15Minor
  )
  #expect(handler.requestIDs == [2])
  guard case .runtimeEvent(let event) = envelopes.last?.body,
    case .runtimeRejected(let rejected) = event.body
  else {
    Issue.record("expected dry-run fixture response")
    return
  }
  #expect(rejected.code == .invalidState)
}

@Test func externalHandlerCannotSelfReportPlanOrForceAuthority() throws {
  let envelopes = try runRuntimeExchange(handler: MaliciousAuthorityHandler())
  guard case .runtimeEvent(let event) = envelopes.last?.body,
    case .runtimeRejected(let rejected) = event.body
  else {
    Issue.record("expected typed authority rejection")
    return
  }
  #expect(rejected.code == .invalidState)
}

@Test func handlerThrowAfterTerminalDoesNotEmitASecondResponse() throws {
  let envelopes = try runRuntimeExchange(handler: SendThenThrowHandler())
  #expect(envelopes.count == 2)
  guard case .runtimeEvent(let event) = envelopes.last?.body,
    case .runtimeRejected(let rejected) = event.body
  else {
    Issue.record("expected the first terminal rejection")
    return
  }
  #expect(rejected.code == .invalidState)
}

@Test func nonconfirmHandlerCannotEmitReservedConsumedReviewCode() throws {
  let envelopes = try runRuntimeExchange(handler: ReservedRejectionRuntimeHandler())
  guard case .runtimeEvent(let event) = envelopes.last?.body,
    case .runtimeRejected(let rejected) = event.body
  else {
    Issue.record("expected typed handler failure")
    return
  }
  #expect(rejected.code == .internalError)
  #expect(rejected.code != .confirmationMismatch)
}

@Test func retainedResponderClaimBlocksConcurrentRuntimeTransitions() throws {
  let broker = SerialEventBroker { _ in }
  let authority = RuntimeBusinessAuthorityState()
  var first = Diskplan_V1_BuildPlanRequest()
  first.requestID = 1
  #expect(authority.claim(.buildPlan(first))?.code == nil)
  let responder = RuntimeBusinessResponder(
    broker: broker,
    request: .buildPlan(first),
    runtimeSessionID: Data("runtime-session".utf8),
    authority: authority
  )

  var duplicate = Diskplan_V1_BuildPlanRequest()
  duplicate.requestID = 2
  #expect(authority.claim(.buildPlan(duplicate))?.code == .invalidState)
  var overlay = Diskplan_V1_DecisionOverlayEditRequest()
  overlay.requestID = 3
  #expect(authority.claim(.editDecisionOverlay(overlay))?.code == .invalidState)

  try responder.send(try .rejected(code: .invalidState, summary: "terminal"))
  #expect(authority.claim(.buildPlan(duplicate))?.code == nil)
  let duplicateResponder = RuntimeBusinessResponder(
    broker: broker,
    request: .buildPlan(duplicate),
    runtimeSessionID: Data("runtime-session".utf8),
    authority: authority
  )
  try duplicateResponder.send(try .rejected(code: .invalidState, summary: "terminal"))
  try broker.finish()
}

@Test func responderDoesNotCommitAuthorityWhenWriterFails() throws {
  let broker = SerialEventBroker { _ in throw RuntimeTransactionWriterError.failed }
  let authority = RuntimeBusinessAuthorityState()
  let (first, emission) = try runtimePlanTransactionFixture()
  #expect(authority.claim(.buildPlan(first))?.code == nil)
  let responder = RuntimeBusinessResponder(
    broker: broker,
    request: .buildPlan(first),
    runtimeSessionID: Data("runtime-session".utf8),
    authority: authority
  )

  #expect(throws: EventBrokerError.self) {
    try responder.send(emission)
  }
  #expect(!authority.hasLivePlanReceiptForTesting())
  var duplicate = Diskplan_V1_BuildPlanRequest()
  duplicate.requestID = 2
  #expect(authority.claim(.buildPlan(duplicate))?.code == .invalidState)
  #expect(throws: EventBrokerError.self) { try broker.finish() }
}

@Test func responderDoesNotHoldAuthorityLockAcrossWriter() throws {
  let writerGate = RuntimeTransactionGate()
  let writerEntered = RuntimeTransactionFlag()
  let responseFinished = RuntimeTransactionFlag()
  let claimResult = RuntimeTransactionClaimResult()
  let broker = SerialEventBroker { _ in
    writerEntered.set()
    writerGate.wait()
  }
  let authority = RuntimeBusinessAuthorityState()
  var first = Diskplan_V1_BuildPlanRequest()
  first.requestID = 1
  #expect(authority.claim(.buildPlan(first))?.code == nil)
  let responder = RuntimeBusinessResponder(
    broker: broker,
    request: .buildPlan(first),
    runtimeSessionID: Data("runtime-session".utf8),
    authority: authority
  )
  Thread {
    do {
      try responder.send(try .rejected(code: .invalidState, summary: "terminal"))
    } catch {
      Issue.record("runtime response unexpectedly failed: \(error)")
    }
    responseFinished.set()
  }.start()
  defer { writerGate.open() }
  #expect(writerEntered.wait(timeout: 1.0))

  var duplicate = Diskplan_V1_BuildPlanRequest()
  duplicate.requestID = 2
  let duplicateRequest = duplicate
  Thread {
    claimResult.set(authority.claim(.buildPlan(duplicateRequest))?.code)
  }.start()
  #expect(claimResult.wait(timeout: 1.0) == .invalidState)
  #expect(!responseFinished.value())

  writerGate.open()
  #expect(responseFinished.wait(timeout: 1.0))
  #expect(authority.claim(.buildPlan(duplicateRequest))?.code == nil)
  let duplicateResponder = RuntimeBusinessResponder(
    broker: broker,
    request: .buildPlan(duplicateRequest),
    runtimeSessionID: Data("runtime-session".utf8),
    authority: authority
  )
  try duplicateResponder.send(try .rejected(code: .invalidState, summary: "terminal"))
  try broker.finish()
}

@Test func runtimeIngressRejectsEnvelopeAndNestedUnknownFields() throws {
  let handler = RecordingRuntimeHandler()
  for transform in [
    { (canonical: Data) -> Data in canonical + Data([0x98, 0x06, 0x01]) },
    { (_: Data) -> Data in nestedUnknownBuildPlanEnvelope() },
  ] {
    let envelopes = try runRuntimeExchange(handler: handler, requestPayloadTransform: transform)
    guard envelopes.count == 2,
      case .helloRejected(let rejected) = envelopes[1].body
    else {
      Issue.record("expected malformed-envelope rejection")
      continue
    }
    #expect(rejected.code == .malformedEnvelope)
  }
}

@Test func overlaySelectionUsesExactAuthoritativeStageabilityAndWaiverSet() throws {
  let actionID = Data(repeating: 0x31, count: 32)
  var notStageable = Diskplan_V1_PlanActionProjection()
  notStageable.actionID.value = actionID
  notStageable.stageability = .notStageable
  var record = Diskplan_V1_PlanProjectionRecord()
  record.body = .action(notStageable)
  let base = overlayFixture(selectedActionID: actionID)
  #expect(throws: SealedRuntimeWireError.self) {
    try SealedRuntimeWire.sealDecisionOverlayAcknowledged(
      base,
      authoritativePlanRecords: [record]
    )
  }

  let waiverID = Data("required-waiver".utf8)
  var requiresWaiver = notStageable
  requiresWaiver.stageability = .requiresWaivers
  var required = Diskplan_V1_PlanWaiverProjection()
  required.waiverID.value = waiverID
  requiresWaiver.requiredWaivers = [required]
  record.body = .action(requiresWaiver)
  #expect(throws: SealedRuntimeWireError.self) {
    try SealedRuntimeWire.sealDecisionOverlayAcknowledged(
      base,
      authoritativePlanRecords: [record]
    )
  }

  var exact = base
  var consent = Diskplan_V1_AcknowledgedWaiver()
  consent.actionID.value = actionID
  consent.waiverID.value = waiverID
  consent.consentSha256.value = Data(repeating: 0x91, count: 32)
  exact.acknowledgedWaivers = [consent]
  _ = try SealedRuntimeWire.sealDecisionOverlayAcknowledged(
    exact,
    authoritativePlanRecords: [record]
  )

  var extra = consent
  extra.waiverID.value = Data("extra-waiver".utf8)
  exact.acknowledgedWaivers.append(extra)
  #expect(throws: SealedRuntimeWireError.self) {
    try SealedRuntimeWire.sealDecisionOverlayAcknowledged(
      exact,
      authoritativePlanRecords: [record]
    )
  }

  exact.acknowledgedWaivers = [consent]
  exact.acknowledgedWaivers.append(consent)
  #expect(throws: SealedRuntimeWireError.self) {
    try SealedRuntimeWire.sealDecisionOverlayAcknowledged(
      exact,
      authoritativePlanRecords: [record]
    )
  }

  var requiresForce = notStageable
  requiresForce.stageability = .stageable
  requiresForce.requiresForce = true
  requiresForce.requiredWaivers = []
  record.body = .action(requiresForce)
  #expect(throws: SealedRuntimeWireError.self) {
    try SealedRuntimeWire.sealDecisionOverlayAcknowledged(
      base,
      authoritativePlanRecords: [record]
    )
  }
  var exactForce = base
  exactForce.forceWarningActionIds = exactForce.selectedActionIds
  _ = try SealedRuntimeWire.sealDecisionOverlayAcknowledged(
    exactForce,
    authoritativePlanRecords: [record]
  )
  #expect(throws: SealedRuntimeWireError.self) {
    try SealedRuntimeWire.sealDecisionOverlayAcknowledged(
      exactForce,
      authoritativePlanRecords: [record, record]
    )
  }
}

@Test func planPrerequisiteProjectionRejectsCycles() throws {
  let a = Data(repeating: 0x01, count: 32)
  let b = Data(repeating: 0x02, count: 32)
  #expect(throws: RuntimeProjectionWireError.self) {
    try PlanProjectionWireEncoder.validatePrerequisiteDAG([a: [b], b: [a]])
  }
  try PlanProjectionWireEncoder.validatePrerequisiteDAG([a: [], b: [a]])
}

@Test func safetyEvidenceRejectsUnknownClosedStateAndOversizedRawSelector() throws {
  var evidence = Diskplan_V1_PlanSafetyEvidenceProjection()
  evidence.policyEvidenceSha256.value = Data(repeating: 0x71, count: 32)
  evidence.namespaceAccess.targetAccessPolicy.status = .UNRECOGNIZED(999)
  evidence.namespaceAccess.targetAccessPolicy.code = "unknown-enum"
  evidence.namespaceAccess.targetAccessPolicy.summary = "Unknown enum fixture."
  evidence.contentBaseline.observation.status = .unknown
  evidence.contentBaseline.observation.code = "unknown"
  evidence.contentBaseline.observation.summary = "Unknown baseline fixture."
  #expect(throws: RuntimeProjectionWireError.self) {
    try PlanProjectionWireEncoder.validateSafetyEvidenceForTesting(
      evidence,
      actionKind: .genericRemove
    )
  }
  #expect(throws: RuntimeProjectionWireError.self) {
    try PlanProjectionWireEncoder.validateRawSelectorTargetForTesting(
      Data(repeating: 0x61, count: PlanProjectionWireEncoder.maximumRawSelectorTargetBytes + 1)
    )
  }
}

@Test func executionPreviewShapeIsClosedByNegotiatedProtocolMinor() throws {
  var protocol14 = Diskplan_V1_ActionExecutionPreviewProjection()
  protocol14.adapter = .genericRemove
  try SealedRuntimeWire.requirePreview(
    protocol14,
    negotiatedProtocolMinor: protocol14Minor
  )

  var incomplete15 = protocol14
  incomplete15.pathRace = .noneObserved
  #expect(throws: SealedRuntimeWireError.self) {
    try SealedRuntimeWire.requirePreview(
      incomplete15,
      negotiatedProtocolMinor: protocol15Minor
    )
  }

  incomplete15.rawWorkingDirectory = Data()
  try SealedRuntimeWire.requirePreview(
    incomplete15,
    negotiatedProtocolMinor: protocol15Minor
  )
  #expect(throws: SealedRuntimeWireError.self) {
    try SealedRuntimeWire.requirePreview(
      incomplete15,
      negotiatedProtocolMinor: protocol14Minor
    )
  }

  var mutation15 = incomplete15
  mutation15.mutationSupported = true
  mutation15.rawExecutable = Data("/bin/rm".utf8)
  mutation15.rawArgv = [Data("rm".utf8), Data("target".utf8)]
  mutation15.displayArgv = ["rm", "target"]
  mutation15.postcondition = "Target is absent."
  mutation15.rawWorkingDirectory = Data("/fixture".utf8)
  try SealedRuntimeWire.requirePreview(
    mutation15,
    negotiatedProtocolMinor: protocol15Minor
  )
}

@Test func executionForceWarningsAreAnExactSet() throws {
  let fixture = try forceExecutionFixture()
  _ = try SealedRuntimeWire.sealExecutionStream(
    fixture.events,
    requiredForceWarningActionIDs: fixture.required
  )
  var omitted = fixture.events
  omitted.removeAll { event in
    if case .forceRequiredWarning? = event.body { return true }
    return false
  }
  #expect(throws: SealedRuntimeWireError.self) {
    try SealedRuntimeWire.sealExecutionStream(
      omitted,
      requiredForceWarningActionIDs: fixture.required
    )
  }
  var duplicated = fixture.events
  guard
    let warning = duplicated.first(where: {
      if case .forceRequiredWarning? = $0.body { return true }
      return false
    })
  else {
    Issue.record("force fixture omitted warning")
    return
  }
  duplicated.insert(warning, at: duplicated.index(before: duplicated.endIndex))
  #expect(throws: SealedRuntimeWireError.self) {
    try SealedRuntimeWire.sealExecutionStream(
      duplicated,
      requiredForceWarningActionIDs: fixture.required
    )
  }
}

@Test func protocol16FailureTerminalSealsTheActualPrefixWithoutPositiveClaims() throws {
  let fixture = executionFailureFixture()
  let sealed = try SealedRuntimeWire.sealExecutionStream(
    fixture.events,
    requiredForceWarningActionIDs: fixture.requiredForceActionIDs,
    negotiatedProtocolMinor: protocol16Minor
  )
  #expect(sealed.count == 2)
  guard case .executionStreamFailure(let terminal)? = sealed.last?.body else {
    Issue.record("expected execution-stream failure terminal")
    return
  }
  #expect(terminal.kind == .backendContractViolation)
  #expect(terminal.mutationMayHaveOccurred)
  #expect(terminal.executionID == sealed.last?.executionID)
  #expect(terminal.eventCount == UInt64(sealed.count))
  #expect(terminal.encodedEventBytes > 0)
  #expect(terminal.maximumEventCount == SealedRuntimeWire.maximumExecutionEventCount)
  #expect(terminal.maximumEncodedEventBytes == SealedRuntimeWire.maximumExecutionBytes)
  #expect(terminal.executionRecordSha256.value.count == 32)
  #expect(
    !sealed.contains(where: {
      if case .forceRequiredWarning? = $0.body { return true }
      return false
    })
  )
}

@Test func executionAuthorityAcceptsBoundFailureTerminalWithoutRuntimeRejection() throws {
  let fixture = executionFailureFixture()
  let events = try SealedRuntimeWire.sealExecutionStream(
    fixture.events,
    requiredForceWarningActionIDs: fixture.requiredForceActionIDs,
    negotiatedProtocolMinor: protocol16Minor
  )
  guard case .applyStarted(let started)? = events.first?.body,
    case .executionStreamFailure(let failure)? = events.last?.body
  else {
    Issue.record("expected a started execution with a typed failure terminal")
    return
  }
  var manifest = Diskplan_V1_PlanProjectionManifest()
  manifest.projectionID = started.projectionID
  manifest.planID = started.planID
  manifest.planSha256 = started.planSha256
  manifest.evidenceID = started.evidenceID
  manifest.evidenceSha256 = started.evidenceSha256
  manifest.scanSessionID = started.scanSessionID
  manifest.scanCheckpointID = started.scanCheckpointID
  manifest.scanCheckpointEvidenceSha256 = started.scanCheckpointEvidenceSha256
  var overlay = Diskplan_V1_DecisionOverlayAcknowledged()
  overlay.overlayID = started.overlayID
  overlay.overlaySha256 = started.overlaySha256
  overlay.revision = started.overlayRevision
  overlay.selectedActionCount = started.selectedActionCount
  var review = Diskplan_V1_ApplyReviewProjection()
  review.applyReviewID = failure.applyReviewID
  review.reviewBindingSha256 = failure.reviewBindingSha256
  review.currentBindingSha256 = started.currentBindingSha256
  review.revalidationSha256 = started.revalidationSha256
  review.epoch = started.epoch

  try RuntimeExecutionAuthorityValidator.validateLiveBindings(
    events: events,
    planManifest: manifest,
    overlay: overlay,
    review: review
  )
  #expect(
    events.allSatisfy {
      if case .executionStreamFailure? = $0.body { return true }
      if case .applyStarted? = $0.body { return true }
      return false
    }
  )

  review.reviewBindingSha256.value = Data(repeating: 0xee, count: 32)
  #expect(throws: SealedRuntimeWireError.self) {
    try RuntimeExecutionAuthorityValidator.validateLiveBindings(
      events: events,
      planManifest: manifest,
      overlay: overlay,
      review: review
    )
  }
}

@Test func executionFailureTerminalIsStrictlyProtocol16AndFailClosed() throws {
  let fixture = executionFailureFixture()
  #expect(throws: SealedRuntimeWireError.self) {
    try SealedRuntimeWire.sealExecutionStream(
      fixture.events,
      requiredForceWarningActionIDs: fixture.requiredForceActionIDs,
      negotiatedProtocolMinor: protocol15Minor
    )
  }

  var notFailClosed = fixture.events
  guard case .executionStreamFailure(var terminal)? = notFailClosed.last?.body else {
    Issue.record("expected execution-stream failure terminal")
    return
  }
  terminal.mutationMayHaveOccurred = false
  notFailClosed[notFailClosed.index(before: notFailClosed.endIndex)].body =
    .executionStreamFailure(terminal)
  #expect(throws: SealedRuntimeWireError.self) {
    try SealedRuntimeWire.sealExecutionStream(
      notFailClosed,
      requiredForceWarningActionIDs: fixture.requiredForceActionIDs,
      negotiatedProtocolMinor: protocol16Minor
    )
  }

  terminal = fixture.failure
  terminal.kind = .unspecified
  var unspecified = fixture.events
  unspecified[unspecified.index(before: unspecified.endIndex)].body =
    .executionStreamFailure(terminal)
  #expect(throws: SealedRuntimeWireError.self) {
    try SealedRuntimeWire.sealExecutionStream(
      unspecified,
      requiredForceWarningActionIDs: fixture.requiredForceActionIDs,
      negotiatedProtocolMinor: protocol16Minor
    )
  }
}

@Test func executionFailureTerminalRejectsMalformedAuthorityAndRewritesRecordFields() throws {
  let fixture = executionFailureFixture()
  var malformed = fixture.events
  var failure = fixture.failure
  failure.executionID.value = Data("foreign-execution".utf8)
  malformed[malformed.index(before: malformed.endIndex)].body = .executionStreamFailure(failure)
  #expect(throws: SealedRuntimeWireError.self) {
    try SealedRuntimeWire.sealExecutionStream(
      malformed,
      requiredForceWarningActionIDs: fixture.requiredForceActionIDs,
      negotiatedProtocolMinor: protocol16Minor
    )
  }

  malformed = fixture.events
  failure = fixture.failure
  failure.applyReviewID.value = Data("foreign-review".utf8)
  malformed[malformed.index(before: malformed.endIndex)].body = .executionStreamFailure(failure)
  #expect(throws: SealedRuntimeWireError.self) {
    try SealedRuntimeWire.sealExecutionStream(
      malformed,
      requiredForceWarningActionIDs: fixture.requiredForceActionIDs,
      negotiatedProtocolMinor: protocol16Minor
    )
  }

  #expect(throws: SealedRuntimeWireError.self) {
    try SealedRuntimeWire.sealExecutionStream(
      [fixture.events.last!],
      requiredForceWarningActionIDs: fixture.requiredForceActionIDs,
      negotiatedProtocolMinor: protocol16Minor
    )
  }

  var unsealed = fixture.events
  failure = fixture.failure
  failure.executionRecordSha256.value = Data(repeating: 0xff, count: 32)
  failure.eventCount = UInt64.max
  failure.encodedEventBytes = UInt64.max
  failure.maximumEventCount = 1
  failure.maximumEncodedEventBytes = 1
  unsealed[unsealed.index(before: unsealed.endIndex)].body = .executionStreamFailure(failure)
  let sealed = try SealedRuntimeWire.sealExecutionStream(
    unsealed,
    requiredForceWarningActionIDs: fixture.requiredForceActionIDs,
    negotiatedProtocolMinor: protocol16Minor
  )
  guard case .executionStreamFailure(let rewritten)? = sealed.last?.body else {
    Issue.record("expected execution-stream failure terminal")
    return
  }
  #expect(rewritten.executionRecordSha256.value != Data(repeating: 0xff, count: 32))
  #expect(rewritten.eventCount == UInt64(sealed.count))
  #expect(rewritten.encodedEventBytes < UInt64.max)
  #expect(rewritten.maximumEventCount == SealedRuntimeWire.maximumExecutionEventCount)
  #expect(rewritten.maximumEncodedEventBytes == SealedRuntimeWire.maximumExecutionBytes)
}

@Test func responderRejectsAnOversizedRuntimeEnvelopeBeforeEnqueue() throws {
  let broker = SerialEventBroker { _ in }
  let authority = RuntimeBusinessAuthorityState()
  var request = Diskplan_V1_BuildPlanRequest()
  request.requestID = 1
  #expect(authority.claim(.buildPlan(request))?.code == nil)
  let responder = RuntimeBusinessResponder(
    broker: broker,
    request: .buildPlan(request),
    runtimeSessionID: Data("runtime-session".utf8),
    authority: authority
  )
  let emission = try RuntimeBusinessEmission.rejected(
    code: .invalidState,
    summary: String(repeating: "x", count: maximumFrameLength)
  )
  #expect(throws: FrameError.self) { try responder.send(emission) }
  try broker.finish()
}

@Test func runtimeOuterBudgetAcceptsExactBoundaryAndRejectsOneByteOver() throws {
  try RuntimeEmissionBudget.validateEncodedEnvelopeLengths(
    envelopeLengths(totalFramedBytes: SealedRuntimeWire.maximumRuntimeFramedEmissionBytes)
  )
  #expect(throws: SealedRuntimeWireError.self) {
    try RuntimeEmissionBudget.validateEncodedEnvelopeLengths(
      envelopeLengths(
        totalFramedBytes: SealedRuntimeWire.maximumRuntimeFramedEmissionBytes + 1
      )
    )
  }
}

@Test func cancellationRequestRemainsInExecutionCapabilityDomain() {
  var cancellation = Diskplan_V1_CancelExecutionRequest()
  cancellation.requestID = 2
  #expect(
    RuntimeBusinessRequest.cancelExecution(cancellation).requiredCapability
      == "execution-stream-v1"
  )
}

@Test func batchRuntimeRejectsMidstreamCancellationTyped() throws {
  var cancellation = Diskplan_V1_CancelExecutionRequest()
  cancellation.requestID = 2
  cancellation.executionID.value = Data("execution".utf8)
  let envelopes = try runRuntimeExchange(
    handler: RecordingRuntimeHandler(),
    requestBody: .cancelExecutionRequest(cancellation)
  )
  guard case .runtimeEvent(let event) = envelopes.last?.body,
    case .runtimeRejected(let rejected) = event.body
  else {
    Issue.record("expected typed cancellation rejection")
    return
  }
  #expect(rejected.code == .businessUnsupported)
}

@Test func preclaimConfirmRejectionsNeverUseConsumedReviewCode() throws {
  var confirmation = Diskplan_V1_ConfirmApplyRequest()
  confirmation.requestID = 2
  confirmation.applyReviewID.value = Data("review".utf8)
  confirmation.reviewBindingSha256.value = Data(repeating: 0x51, count: 32)
  for (handler, expected) in [
    (nil as (any RuntimeBusinessHandler)?, Diskplan_V1_RuntimeRejectCode.businessUnsupported),
    (RecordingRuntimeHandler(), .capabilityNotNegotiated),
    (ExecutionRecordingRuntimeHandler(), .staleBinding),
  ] {
    let envelopes = try runRuntimeExchange(
      handler: handler,
      requestBody: .confirmApplyRequest(confirmation)
    )
    guard case .runtimeEvent(let event) = envelopes.last?.body,
      case .runtimeRejected(let rejected) = event.body
    else {
      Issue.record("expected typed pre-claim rejection")
      continue
    }
    #expect(rejected.code == expected)
    #expect(rejected.code != .confirmationMismatch)
  }
}

@Test func executionMembershipRejectsForeignActionsAndReleaseSets() throws {
  let selectedID = Data(repeating: 0x11, count: 32)
  let foreignID = Data(repeating: 0x22, count: 32)
  var selected = Diskplan_V1_OpaqueIdentifier()
  selected.value = selectedID

  var foreignUnit = Diskplan_V1_ExecutionUnitProjection()
  foreignUnit.actionID.value = foreignID
  var started = Diskplan_V1_UnitStartedProjection()
  started.unit = foreignUnit
  var event = Diskplan_V1_ExecutionStreamEvent()
  event.body = .unitStarted(started)
  #expect(throws: SealedRuntimeWireError.self) {
    try RuntimeExecutionAuthorityValidator.validateMembership(
      events: [event],
      planRecords: [],
      selectedActionIDs: [selected]
    )
  }

  var selectedUnit = Diskplan_V1_ExecutionUnitProjection()
  selectedUnit.actionID.value = selectedID
  var finished = Diskplan_V1_UnitFinishedProjection()
  finished.unit = foreignUnit
  event.body = .unitFinished(finished)
  #expect(throws: SealedRuntimeWireError.self) {
    try RuntimeExecutionAuthorityValidator.validateMembership(
      events: [event], planRecords: [], selectedActionIDs: [selected]
    )
  }

  var rejected = Diskplan_V1_UnitJITRejectedProjection()
  rejected.unit = selectedUnit
  var foreignOutcome = Diskplan_V1_ActionRevalidationProjection()
  foreignOutcome.actionID.value = foreignID
  rejected.revalidation.actionOutcomes = [foreignOutcome]
  event.body = .unitJitRejected(rejected)
  #expect(throws: SealedRuntimeWireError.self) {
    try RuntimeExecutionAuthorityValidator.validateMembership(
      events: [event], planRecords: [], selectedActionIDs: [selected]
    )
  }

  var skipped = Diskplan_V1_UnitSkippedPrerequisiteProjection()
  skipped.unit = selectedUnit
  skipped.blockingPrerequisites = [foreignUnit]
  event.body = .unitSkippedPrerequisite(skipped)
  #expect(throws: SealedRuntimeWireError.self) {
    try RuntimeExecutionAuthorityValidator.validateMembership(
      events: [event], planRecords: [], selectedActionIDs: [selected]
    )
  }

  var step = Diskplan_V1_ExecutionStepFinishedProjection()
  step.actionID.value = foreignID
  event.body = .stepFinished(step)
  #expect(throws: SealedRuntimeWireError.self) {
    try RuntimeExecutionAuthorityValidator.validateMembership(
      events: [event], planRecords: [], selectedActionIDs: [selected]
    )
  }

  var compound = Diskplan_V1_ExecutionUnitProjection()
  var release = Diskplan_V1_CompoundReleaseUnitProjection()
  release.releaseSetIds = [
    {
      var value = Diskplan_V1_OpaqueIdentifier()
      value.value = Data("foreign-release".utf8)
      return value
    }()
  ]
  compound.unit = .compoundRelease(release)
  started.unit = compound
  event.body = .unitStarted(started)
  #expect(throws: SealedRuntimeWireError.self) {
    try RuntimeExecutionAuthorityValidator.validateMembership(
      events: [event],
      planRecords: [],
      selectedActionIDs: [selected]
    )
  }

  var releasePost = Diskplan_V1_ReleasePostVerificationProjection()
  releasePost.releaseSetID.value = Data("foreign-release".utf8)
  event.body = .releasePostVerificationFinished(releasePost)
  #expect(throws: SealedRuntimeWireError.self) {
    try RuntimeExecutionAuthorityValidator.validateMembership(
      events: [event], planRecords: [], selectedActionIDs: [selected]
    )
  }
}

@Test func overlayRejectionBindsLiveRevisionAndEditedIdentifiers() throws {
  let actionID = Data(repeating: 0x11, count: 32)
  var projectionID = Diskplan_V1_OpaqueIdentifier()
  projectionID.value = Data(repeating: 0x10, count: 32)
  var request = Diskplan_V1_DecisionOverlayEditRequest()
  request.projectionID = projectionID
  var stage = Diskplan_V1_StageActionEdit()
  stage.actionID.value = actionID
  var edit = Diskplan_V1_DecisionOverlayEdit()
  edit.edit = .stageAction(stage)
  request.edits = [edit]

  var stale = Diskplan_V1_DecisionOverlayRejected()
  stale.code = .staleRevision
  stale.summary = "stale"
  stale.currentRevision = 0
  #expect(throws: SealedRuntimeWireError.self) {
    try RuntimeBusinessAuthorityState.validateOverlayRejectionBinding(
      stale,
      request: request,
      liveRevision: 7,
      liveProjectionID: projectionID,
      planRecords: []
    )
  }

  var foreign = Diskplan_V1_DecisionOverlayRejected()
  foreign.code = .actionNotStageable
  foreign.summary = "foreign"
  foreign.currentRevision = 7
  foreign.actionID.value = actionID
  #expect(throws: SealedRuntimeWireError.self) {
    try RuntimeBusinessAuthorityState.validateOverlayRejectionBinding(
      foreign,
      request: request,
      liveRevision: 7,
      liveProjectionID: projectionID,
      planRecords: []
    )
  }

  let waiverID = Data("known-waiver".utf8)
  var action = Diskplan_V1_PlanActionProjection()
  action.actionID.value = actionID
  action.stageability = .requiresWaivers
  var waiver = Diskplan_V1_PlanWaiverProjection()
  waiver.waiverID.value = waiverID
  action.requiredWaivers = [waiver]
  var record = Diskplan_V1_PlanProjectionRecord()
  record.body = .action(action)
  var allow = Diskplan_V1_AllowWaiverEdit()
  allow.actionID.value = actionID
  allow.waiverID.value = waiverID
  edit.edit = .allowWaiver(allow)
  request.edits = [edit]
  request.baseRevision = 7
  var falselyUnknown = Diskplan_V1_DecisionOverlayRejected()
  falselyUnknown.code = .unknownWaiver
  falselyUnknown.summary = "unknown"
  falselyUnknown.currentRevision = 7
  falselyUnknown.actionID.value = actionID
  falselyUnknown.waiverID.value = waiverID
  #expect(throws: SealedRuntimeWireError.self) {
    try RuntimeBusinessAuthorityState.validateOverlayRejectionBinding(
      falselyUnknown,
      request: request,
      liveRevision: 7,
      liveProjectionID: projectionID,
      planRecords: [record]
    )
  }

  var wrongProjection = falselyUnknown
  wrongProjection.code = .invalidReason
  request.projectionID.value = Data(repeating: 0x20, count: 32)
  #expect(throws: SealedRuntimeWireError.self) {
    try RuntimeBusinessAuthorityState.validateOverlayRejectionBinding(
      wrongProjection,
      request: request,
      liveRevision: 7,
      liveProjectionID: projectionID,
      planRecords: [record]
    )
  }
}

private final class RecordingRuntimeHandler: RuntimeBusinessHandler {
  let supportedCapabilities: Set<String> = ["plan-projection-v1"]
  private(set) var requestIDs: [UInt64] = []
  private(set) var negotiatedProtocolMinors: [UInt32] = []

  func handle(
    _ request: RuntimeBusinessRequest,
    responder: RuntimeBusinessResponder
  ) throws {
    requestIDs.append(request.requestID)
    negotiatedProtocolMinors.append(responder.negotiatedProtocolMinor)
    try responder.send(
      try .rejected(code: .invalidState, summary: "fixture response")
    )
  }
}

private final class ExecutionRecordingRuntimeHandler: RuntimeBusinessHandler {
  let supportedCapabilities: Set<String> = ["execution-stream-v1"]

  func handle(
    _ request: RuntimeBusinessRequest,
    responder: RuntimeBusinessResponder
  ) throws {
    Issue.record("pre-claim rejection must not dispatch to the handler")
  }
}

private final class DryRunRecordingRuntimeHandler: RuntimeBusinessHandler {
  let supportedCapabilities: Set<String> = ["dry-run-projection-v1"]
  private(set) var requestIDs: [UInt64] = []

  func handle(
    _ request: RuntimeBusinessRequest,
    responder: RuntimeBusinessResponder
  ) throws {
    requestIDs.append(request.requestID)
    try responder.send(
      try .rejected(code: .invalidState, summary: "fixture response")
    )
  }
}

private final class MaliciousAuthorityHandler: RuntimeBusinessHandler {
  let supportedCapabilities: Set<String> = ["plan-projection-v1"]

  func handle(
    _ request: RuntimeBusinessRequest,
    responder: RuntimeBusinessResponder
  ) throws {
    let overlay = overlayFixture(selectedActionID: Data(repeating: 0x31, count: 32))
    try responder.send(try .decisionOverlay(overlay))
  }
}

private final class SendThenThrowHandler: RuntimeBusinessHandler {
  let supportedCapabilities: Set<String> = ["plan-projection-v1"]

  func handle(
    _ request: RuntimeBusinessRequest,
    responder: RuntimeBusinessResponder
  ) throws {
    try responder.send(try .rejected(code: .invalidState, summary: "first terminal"))
    throw FixtureHandlerError.afterTerminal
  }
}

private final class ReservedRejectionRuntimeHandler: RuntimeBusinessHandler {
  let supportedCapabilities: Set<String> = ["plan-projection-v1"]

  func handle(
    _ request: RuntimeBusinessRequest,
    responder: RuntimeBusinessResponder
  ) throws {
    try responder.send(
      try .rejected(code: .confirmationMismatch, summary: "forged consumed review")
    )
  }
}

private enum FixtureHandlerError: Error {
  case afterTerminal
}

private enum RuntimeTransactionWriterError: Error {
  case failed
}

private final class RuntimeTransactionGate: @unchecked Sendable {
  private let condition = NSCondition()
  private var opened = false

  func wait() {
    condition.lock()
    while !opened { condition.wait() }
    condition.unlock()
  }

  func open() {
    condition.lock()
    opened = true
    condition.broadcast()
    condition.unlock()
  }
}

private final class RuntimeTransactionFlag: @unchecked Sendable {
  private let condition = NSCondition()
  private var isSet = false

  func set() {
    condition.lock()
    isSet = true
    condition.broadcast()
    condition.unlock()
  }

  func value() -> Bool {
    condition.lock()
    defer { condition.unlock() }
    return isSet
  }

  func wait(timeout: TimeInterval) -> Bool {
    condition.lock()
    let deadline = Date(timeIntervalSinceNow: timeout)
    while !isSet && condition.wait(until: deadline) {}
    let result = isSet
    condition.unlock()
    return result
  }
}

private final class RuntimeTransactionClaimResult: @unchecked Sendable {
  private let condition = NSCondition()
  private var isSet = false
  private var code: Diskplan_V1_RuntimeRejectCode?

  func set(_ code: Diskplan_V1_RuntimeRejectCode?) {
    condition.lock()
    self.code = code
    isSet = true
    condition.broadcast()
    condition.unlock()
  }

  func wait(timeout: TimeInterval) -> Diskplan_V1_RuntimeRejectCode? {
    condition.lock()
    let deadline = Date(timeIntervalSinceNow: timeout)
    while !isSet && condition.wait(until: deadline) {}
    let result = code
    condition.unlock()
    return result
  }
}

private func runtimePlanTransactionFixture() throws -> (
  Diskplan_V1_BuildPlanRequest, RuntimeBusinessEmission
) {
  let scanSessionID = Data("scan-session".utf8)
  let evidenceSHA256 = Data(repeating: 0x42, count: 32)
  let checkpointID = Data(evidenceSHA256.map { String(format: "%02x", $0) }.joined().utf8)
  var request = Diskplan_V1_BuildPlanRequest()
  request.requestID = 1
  request.scanSessionID.value = scanSessionID
  request.scanCheckpointID.value = checkpointID
  request.scanEvidenceSha256.value = evidenceSHA256
  let metadata = PlanProjectionWireMetadata(
    scanSessionID: scanSessionID,
    scanCheckpointID: checkpointID,
    scanCheckpointEvidenceSHA256: Data(repeating: 0x43, count: 32),
    planSHA256: Data(repeating: 0x44, count: 32),
    evidenceSHA256: evidenceSHA256,
    cleanupCandidateCount: 0,
    policyVersion: "fixture-policy-v1",
    schemaVersion: "fixture-schema-v1"
  )
  return (
    request,
    try RuntimeBusinessEmission.plan(
      planBuildID: Data("plan-build".utf8),
      records: [],
      metadata: metadata
    )
  )
}

private func runRuntimeExchange(
  handler: (any RuntimeBusinessHandler)?,
  requestBody: Diskplan_V1_Envelope.OneOf_Body? = nil,
  requestPayloadTransform: ((Data) -> Data)? = nil,
  peerProtocolMinor: UInt32 = protocolMinor
) throws -> [Diskplan_V1_Envelope] {
  let input = Pipe()
  let output = Pipe()

  var peer = Handshake.swiftEngineHello(runtimeCapabilities: protocol14RuntimeCapabilities)
  peer.version.minor = peerProtocolMinor
  peer.implementation = "diskplan-runtime-handler-test"
  var hello = Diskplan_V1_Envelope()
  hello.sequence = 1
  hello.body = .hello(peer)
  try FrameCodec.write(try hello.serializedData(), to: input.fileHandleForWriting)

  var build = Diskplan_V1_BuildPlanRequest()
  build.requestID = 2
  var request = Diskplan_V1_Envelope()
  request.sequence = 2
  request.body = requestBody ?? .buildPlanRequest(build)
  let canonicalRequest = try request.serializedData()
  try FrameCodec.write(
    requestPayloadTransform?(canonicalRequest) ?? canonicalRequest,
    to: input.fileHandleForWriting
  )
  try input.fileHandleForWriting.close()

  try EngineServer.run(
    input: input.fileHandleForReading,
    output: output.fileHandleForWriting,
    runtimeHandler: handler
  )
  try output.fileHandleForWriting.close()

  var envelopes: [Diskplan_V1_Envelope] = []
  while let payload = try FrameCodec.read(from: output.fileHandleForReading) {
    envelopes.append(try Diskplan_V1_Envelope(serializedBytes: payload))
  }
  return envelopes
}

private func overlayFixture(selectedActionID: Data) -> Diskplan_V1_DecisionOverlayAcknowledged {
  let plan = Data(repeating: 0x41, count: 32)
  let evidence = Data(repeating: 0x42, count: 32)
  var overlay = Diskplan_V1_DecisionOverlayAcknowledged()
  overlay.projectionID.value = Data("projection".utf8)
  overlay.overlayID.value = Data("overlay".utf8)
  overlay.overlaySha256.value = Data(repeating: 0x43, count: 32)
  overlay.planID.value = plan
  overlay.planSha256.value = plan
  overlay.evidenceID.value = evidence
  overlay.evidenceSha256.value = evidence
  overlay.scanSessionID.value = Data("scan-session".utf8)
  overlay.scanCheckpointID.value = Data(evidence.map { String(format: "%02x", $0) }.joined().utf8)
  overlay.scanCheckpointEvidenceSha256.value = Data(repeating: 0x44, count: 32)
  overlay.selectedActionIds = [
    {
      var value = Diskplan_V1_OpaqueIdentifier()
      value.value = selectedActionID
      return value
    }()
  ]
  overlay.selectedActionCount = 1
  overlay.maximumSelectedActions = SealedRuntimeWire.maximumActionCount
  overlay.maximumWaiverConsents = SealedRuntimeWire.maximumOverlayWaiverCount
  overlay.maximumUserNotes = SealedRuntimeWire.maximumOverlayNoteCount
  overlay.maximumNoteBytes = SealedRuntimeWire.maximumOverlayNoteBytes
  overlay.maximumEncodedBytes = SealedRuntimeWire.maximumProjectionBytes
  return overlay
}

private func nestedUnknownBuildPlanEnvelope() -> Data {
  var nested = Data([0x08, 0x02])
  nested.append(contentsOf: [0x98, 0x06, 0x01])
  var envelope = Data([0x08, 0x02, 0xC2, 0x01])
  appendVarint(UInt64(nested.count), to: &envelope)
  envelope.append(nested)
  return envelope
}

private func appendVarint(_ value: UInt64, to data: inout Data) {
  var remaining = value
  while remaining >= 0x80 {
    data.append(UInt8(remaining & 0x7f) | 0x80)
    remaining >>= 7
  }
  data.append(UInt8(remaining))
}

private func envelopeLengths(totalFramedBytes: UInt64) -> [Int] {
  let maximumFramed = UInt64(maximumFrameLength + 4)
  let count = Int((totalFramedBytes + maximumFramed - 1) / maximumFramed)
  var remaining = totalFramedBytes
  var output: [Int] = []
  output.reserveCapacity(count)
  for index in 0..<count {
    let remainingSlots = UInt64(count - index - 1)
    let framed = min(maximumFramed, remaining - remainingSlots * 4)
    output.append(Int(framed - 4))
    remaining -= framed
  }
  return output
}

private func forceExecutionFixture() throws -> (
  events: [Diskplan_V1_ExecutionStreamEvent],
  required: [Diskplan_V1_OpaqueIdentifier]
) {
  let root = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
  let text = try String(
    contentsOf: root.appendingPathComponent(
      "proto/fixtures/runtime-v1.5/force-action-execution.frames.hex"
    ),
    encoding: .utf8
  )
  var events: [Diskplan_V1_ExecutionStreamEvent] = []
  var required: [Diskplan_V1_OpaqueIdentifier] = []
  for line in text.split(whereSeparator: \.isNewline) {
    let bytes = stride(from: 0, to: line.count, by: 2).compactMap { offset -> UInt8? in
      let start = line.index(line.startIndex, offsetBy: offset)
      let end = line.index(start, offsetBy: 2)
      return UInt8(line[start..<end], radix: 16)
    }
    let frame = Data(bytes)
    let envelope = try Diskplan_V1_Envelope(serializedBytes: frame.dropFirst(4))
    guard case .runtimeEvent(let runtime)? = envelope.body else { continue }
    switch runtime.body {
    case .applyReviewProjection(let review): required = review.forceWarningActionIds
    case .executionStreamEvent(let event): events.append(event)
    default: break
    }
  }
  return (events, required)
}

private struct ExecutionFailureFixture {
  let events: [Diskplan_V1_ExecutionStreamEvent]
  let failure: Diskplan_V1_ExecutionStreamFailureProjection
  let requiredForceActionIDs: [Diskplan_V1_OpaqueIdentifier]
}

private func executionFailureFixture() -> ExecutionFailureFixture {
  let executionID = Data("fixture-execution".utf8)
  let applyReviewID = Data("fixture-apply-review".utf8)
  let planDigest = Data(repeating: 0xa1, count: 32)
  let evidenceDigest = Data(repeating: 0xe1, count: 32)
  let reviewBinding = Data(repeating: 0xd1, count: 32)

  var started = Diskplan_V1_ApplyStartedProjection()
  started.epoch.epochID.value = Data("fixture-epoch".utf8)
  started.epoch.semanticReferenceTimeSeconds = 1
  started.epoch.issuedAtSeconds = 2
  started.epoch.deadlineSeconds = 3
  started.applyReviewID.value = applyReviewID
  started.projectionID.value = Data("fixture-projection".utf8)
  started.planSha256.value = planDigest
  started.overlayID.value = Data("fixture-overlay".utf8)
  started.overlaySha256.value = Data(repeating: 0xb1, count: 32)
  started.reviewBindingSha256.value = reviewBinding
  started.planID.value = planDigest
  started.evidenceID.value = evidenceDigest
  started.evidenceSha256.value = evidenceDigest
  started.currentBindingSha256.value = Data(repeating: 0xc1, count: 32)
  started.revalidationSha256.value = Data(repeating: 0xc2, count: 32)
  started.scanSessionID.value = Data("fixture-scan-session".utf8)
  started.scanCheckpointID.value = Data(
    evidenceDigest.map { String(format: "%02x", $0) }.joined().utf8
  )
  started.scanCheckpointEvidenceSha256.value = Data(repeating: 0xe2, count: 32)

  var failure = Diskplan_V1_ExecutionStreamFailureProjection()
  failure.kind = .backendContractViolation
  failure.executionID.value = executionID
  failure.applyReviewID.value = applyReviewID
  failure.reviewBindingSha256.value = reviewBinding
  failure.mutationMayHaveOccurred = true

  var startEvent = Diskplan_V1_ExecutionStreamEvent()
  startEvent.executionID.value = executionID
  startEvent.body = .applyStarted(started)
  var failureEvent = Diskplan_V1_ExecutionStreamEvent()
  failureEvent.executionID.value = executionID
  failureEvent.body = .executionStreamFailure(failure)
  var forceActionID = Diskplan_V1_OpaqueIdentifier()
  forceActionID.value = Data(repeating: 0x11, count: 32)
  return ExecutionFailureFixture(
    events: [startEvent, failureEvent],
    failure: failure,
    requiredForceActionIDs: [forceActionID]
  )
}
