import DiskplanCore
import DiskplanProto
import Foundation

/// A typed runtime request after envelope and request-ID validation.
///
/// The engine server owns transport and capability admission. Implementations
/// remain the sole authority for plan, overlay, revalidation, and execution
/// semantics.
public enum RuntimeBusinessRequest {
  case buildPlan(Diskplan_V1_BuildPlanRequest)
  case editDecisionOverlay(Diskplan_V1_DecisionOverlayEditRequest)
  case prepareDryRun(Diskplan_V1_PrepareDryRunRequest)
  case prepareApplyReview(Diskplan_V1_PrepareApplyReviewRequest)
  case confirmApply(Diskplan_V1_ConfirmApplyRequest)
  case cancelExecution(Diskplan_V1_CancelExecutionRequest)

  public var requestID: UInt64 {
    switch self {
    case .buildPlan(let request): request.requestID
    case .editDecisionOverlay(let request): request.requestID
    case .prepareDryRun(let request): request.requestID
    case .prepareApplyReview(let request): request.requestID
    case .confirmApply(let request): request.requestID
    case .cancelExecution(let request): request.requestID
    }
  }

  public var requiredCapability: String {
    switch self {
    case .buildPlan: "plan-projection-v1"
    case .editDecisionOverlay: "decision-overlay-v1"
    case .prepareDryRun: "dry-run-projection-v1"
    case .prepareApplyReview, .confirmApply, .cancelExecution: "execution-stream-v1"
    }
  }
}

public protocol RuntimeBusinessHandler: AnyObject {
  /// Capabilities this concrete handler can service in the current process.
  var supportedCapabilities: Set<String> { get }

  /// The handler may retain the responder for asynchronous projection events.
  /// Throwing reports a typed internal failure for this request.
  func handle(
    _ request: RuntimeBusinessRequest,
    responder: RuntimeBusinessResponder
  ) throws
}

/// A sealed engine-authored response. Its private payload prevents handlers
/// from injecting arbitrary protobuf oneof values into the transport broker.
public struct RuntimeBusinessEmission: Sendable {
  fileprivate enum Payload: Sendable {
    case plan(Data, [Diskplan_V1_PlanProjectionRecord], PlanProjectionWireMetadata)
    case planInvalidated(Data, String, String)
    case overlay(Diskplan_V1_DecisionOverlayAcknowledged)
    case overlayRejected(Diskplan_V1_DecisionOverlayRejected)
    case dryRun(Diskplan_V1_DryRunProjectionPayload, Diskplan_V1_DryRunProjectionManifest)
    case applyReview(Diskplan_V1_ApplyReviewProjection)
    case execution([Diskplan_V1_ExecutionStreamEvent])
    case rejected(Diskplan_V1_RuntimeRejectCode, String)
  }

  fileprivate let payload: Payload

  public static func plan(
    planBuildID: Data,
    records: [Diskplan_V1_PlanProjectionRecord],
    metadata: PlanProjectionWireMetadata,
    negotiatedProtocolMinor: UInt32 = protocolMinor
  ) throws -> Self {
    _ = try sealedBodies(
      for: .plan(planBuildID, records, metadata),
      negotiatedProtocolMinor: negotiatedProtocolMinor
    )
    return Self(payload: .plan(planBuildID, records, metadata))
  }

  public static func decisionOverlay(
    _ overlay: Diskplan_V1_DecisionOverlayAcknowledged
  ) throws -> Self {
    _ = try SealedRuntimeWire.sealDecisionOverlayAcknowledged(overlay)
    return Self(payload: .overlay(overlay))
  }

  public static func planInvalidated(
    projectionID: Data,
    reasonCode: String,
    summary: String
  ) throws -> Self {
    _ = try sealedBodies(
      for: .planInvalidated(projectionID, reasonCode, summary),
      negotiatedProtocolMinor: protocolMinor
    )
    return Self(payload: .planInvalidated(projectionID, reasonCode, summary))
  }

  public static func decisionOverlayRejected(
    _ rejection: Diskplan_V1_DecisionOverlayRejected
  ) throws -> Self {
    _ = try sealedBodies(
      for: .overlayRejected(rejection),
      negotiatedProtocolMinor: protocolMinor
    )
    return Self(payload: .overlayRejected(rejection))
  }

  public static func dryRun(
    payload: Diskplan_V1_DryRunProjectionPayload,
    manifest: Diskplan_V1_DryRunProjectionManifest,
    negotiatedProtocolMinor: UInt32 = protocolMinor
  ) throws -> Self {
    _ = try sealedBodies(
      for: .dryRun(payload, manifest),
      negotiatedProtocolMinor: negotiatedProtocolMinor
    )
    return Self(payload: .dryRun(payload, manifest))
  }

  public static func applyReview(
    _ projection: Diskplan_V1_ApplyReviewProjection,
    negotiatedProtocolMinor: UInt32 = protocolMinor
  ) throws -> Self {
    _ = try sealedBodies(
      for: .applyReview(projection),
      negotiatedProtocolMinor: negotiatedProtocolMinor
    )
    return Self(payload: .applyReview(projection))
  }

  public static func execution(
    _ events: [Diskplan_V1_ExecutionStreamEvent]
  ) throws -> Self {
    guard !events.isEmpty else {
      throw SealedRuntimeWireError.invalid(field: "execution events")
    }
    return Self(payload: .execution(events))
  }

  public static func rejected(
    code: Diskplan_V1_RuntimeRejectCode,
    summary: String
  ) throws -> Self {
    _ = try sealedBodies(
      for: .rejected(code, summary),
      negotiatedProtocolMinor: protocolMinor
    )
    return Self(payload: .rejected(code, summary))
  }

  fileprivate func sealedBodies(
    negotiatedProtocolMinor: UInt32 = protocolMinor
  ) throws -> [Diskplan_V1_RuntimeEvent.OneOf_Body] {
    try Self.sealedBodies(
      for: payload,
      negotiatedProtocolMinor: negotiatedProtocolMinor
    )
  }

  fileprivate static func sealedBodies(
    for payload: Payload,
    negotiatedProtocolMinor: UInt32 = protocolMinor
  ) throws -> [Diskplan_V1_RuntimeEvent.OneOf_Body] {
    try SealedRuntimeWire.requireSupportedProtocolMinor(negotiatedProtocolMinor)
    let bodies: [Diskplan_V1_RuntimeEvent.OneOf_Body]
    switch payload {
    case .plan(let planBuildID, let records, let metadata):
      guard !planBuildID.isEmpty,
        planBuildID.count <= SealedRuntimeWire.maximumOpaqueIdentifierBytes
      else { throw SealedRuntimeWireError.invalid(field: "plan_build_id") }
      let wire = try PlanProjectionWireEncoder.encode(
        records: records,
        metadata: metadata,
        negotiatedProtocolMinor: negotiatedProtocolMinor
      )
      var accepted = Diskplan_V1_BuildPlanAccepted()
      accepted.planBuildID.value = planBuildID
      var projection = Diskplan_V1_PlanProjection()
      projection.manifest = wire.manifest
      bodies =
        [.buildPlanAccepted(accepted)]
        + wire.chunks.map(Diskplan_V1_RuntimeEvent.OneOf_Body.planProjectionChunk)
        + [.planProjection(projection)]
    case .planInvalidated(let projectionID, let reasonCode, let summary):
      guard !projectionID.isEmpty,
        projectionID.count <= SealedRuntimeWire.maximumOpaqueIdentifierBytes,
        !reasonCode.isEmpty, !summary.isEmpty
      else { throw SealedRuntimeWireError.invalid(field: "plan invalidation") }
      var invalidated = Diskplan_V1_PlanProjectionInvalidated()
      invalidated.projectionID.value = projectionID
      invalidated.reasonCode = reasonCode
      invalidated.summary = summary
      bodies = [.planProjectionInvalidated(invalidated)]
    case .overlay(let overlay):
      bodies = [
        .decisionOverlayAcknowledged(
          try SealedRuntimeWire.sealDecisionOverlayAcknowledged(overlay)
        )
      ]
    case .overlayRejected(let rejection):
      switch rejection.code {
      case .unknownProjection, .staleRevision, .unknownAction, .actionNotStageable,
        .unknownWaiver, .waiverNotAllowed, .invalidReason, .limitExceeded, .invalidEdit,
        .internalError:
        break
      case .unspecified, .UNRECOGNIZED:
        throw SealedRuntimeWireError.invalid(field: "decision overlay rejection")
      }
      guard !rejection.summary.isEmpty else {
        throw SealedRuntimeWireError.invalid(field: "decision overlay rejection")
      }
      if rejection.hasActionID {
        guard rejection.actionID.value.count == 32 else {
          throw SealedRuntimeWireError.invalid(field: "rejected action_id")
        }
      }
      if rejection.hasWaiverID {
        guard !rejection.waiverID.value.isEmpty,
          rejection.waiverID.value.count <= SealedRuntimeWire.maximumOpaqueIdentifierBytes
        else { throw SealedRuntimeWireError.invalid(field: "rejected waiver_id") }
      }
      bodies = [.decisionOverlayRejected(rejection)]
    case .dryRun(let payload, let manifest):
      bodies = [
        .dryRunProjection(
          try SealedRuntimeWire.sealDryRun(
            payload: payload,
            manifest: manifest,
            negotiatedProtocolMinor: negotiatedProtocolMinor
          )
        )
      ]
    case .applyReview(let projection):
      bodies = [
        .applyReviewProjection(
          try SealedRuntimeWire.sealApplyReview(
            projection,
            negotiatedProtocolMinor: negotiatedProtocolMinor
          )
        )
      ]
    case .execution:
      throw SealedRuntimeWireError.invalid(field: "execution predecessor receipt")
    case .rejected(let code, let summary):
      switch code {
      case .capabilityNotNegotiated, .invalidState, .unknownProjection, .staleBinding,
        .limitExceeded, .revalidationFailed, .internalError, .businessUnsupported,
        .malformedRequest, .duplicateRequestID:
        break
      case .confirmationMismatch, .unspecified, .UNRECOGNIZED:
        throw SealedRuntimeWireError.invalid(field: "runtime rejection")
      }
      guard !summary.isEmpty else {
        throw SealedRuntimeWireError.invalid(field: "runtime rejection")
      }
      var rejected = Diskplan_V1_RuntimeRejected()
      rejected.code = code
      rejected.summary = summary
      bodies = [.runtimeRejected(rejected)]
    }
    var aggregate = 0
    for body in bodies {
      var event = Diskplan_V1_RuntimeEvent()
      event.body = body
      let (next, overflow) = aggregate.addingReportingOverflow(try event.serializedData().count)
      guard !overflow else { throw SealedRuntimeWireError.integerOverflow(field: "emission bytes") }
      aggregate = next
    }
    guard aggregate <= Int(SealedRuntimeWire.maximumRuntimeSealedEmissionBytes) else {
      throw SealedRuntimeWireError.encodedBytesExceeded(
        actual: UInt64(aggregate),
        maximum: SealedRuntimeWire.maximumRuntimeSealedEmissionBytes
      )
    }
    return bodies
  }
}

private struct RuntimeAuthorityError: Error {
  let code: Diskplan_V1_RuntimeRejectCode
  let summary: String
}

private enum RuntimeResponderError: Error {
  case alreadyTerminal
}

private struct RuntimePlanReceipt {
  let records: [Diskplan_V1_PlanProjectionRecord]
  let manifest: Diskplan_V1_PlanProjectionManifest
  let negotiatedProtocolMinor: UInt32
}

private struct RuntimeWaiverKey: Hashable {
  let actionID: Data
  let waiverID: Data
}

private enum RuntimeAuthorityTransition {
  case none
  case plan(RuntimePlanReceipt)
  case invalidatePlan
  case overlay(Diskplan_V1_DecisionOverlayAcknowledged)
  case review(Diskplan_V1_ApplyReviewProjection)
  case executionCompleted(requestID: UInt64, reviewBinding: Data)
  case executionAborted(requestID: UInt64, reviewBinding: Data)

  var consumesExecutionClaim: Bool {
    switch self {
    case .executionCompleted, .executionAborted: true
    default: false
    }
  }
}

private struct RuntimeExecutionClaim {
  let requestID: UInt64
  let reviewBinding: Data
}

private struct PreparedRuntimeEmission {
  let bodies: [Diskplan_V1_RuntimeEvent.OneOf_Body]
  let transition: RuntimeAuthorityTransition
}

private final class RuntimeAuthorityEmissionToken: @unchecked Sendable {}

private struct RuntimeAuthorityEmissionTransaction {
  let requestID: UInt64
  let token: RuntimeAuthorityEmissionToken
  let prepared: PreparedRuntimeEmission
}

package enum RuntimeExecutionAuthorityValidator {
  package static func validateMembership(
    events: [Diskplan_V1_ExecutionStreamEvent],
    planRecords: [Diskplan_V1_PlanProjectionRecord],
    selectedActionIDs: [Diskplan_V1_OpaqueIdentifier]
  ) throws {
    let selected = Set(selectedActionIDs.map(\.value))
    let allowedReleaseSets = Dictionary(
      uniqueKeysWithValues: planRecords.compactMap { record -> (Data, Set<Data>)? in
        guard case .releaseSet(let releaseSet)? = record.body,
          releaseSet.actionIds.allSatisfy({ selected.contains($0.value) })
        else { return nil }
        return (releaseSet.releaseSetID.value, Set(releaseSet.actionIds.map(\.value)))
      })
    func validateUnit(_ unit: Diskplan_V1_ExecutionUnitProjection) throws -> Set<Data> {
      switch unit.unit {
      case .actionID(let actionID):
        guard selected.contains(actionID.value) else {
          throw SealedRuntimeWireError.invalid(field: "execution unit action_id")
        }
        return [actionID.value]
      case .compoundRelease(let compound):
        guard !compound.releaseSetIds.isEmpty,
          Set(compound.releaseSetIds.map(\.value)).count == compound.releaseSetIds.count,
          compound.releaseSetIds.allSatisfy({ allowedReleaseSets[$0.value] != nil })
        else { throw SealedRuntimeWireError.invalid(field: "execution release_set_id") }
        return compound.releaseSetIds.reduce(into: Set<Data>()) { actions, releaseSetID in
          actions.formUnion(allowedReleaseSets[releaseSetID.value] ?? [])
        }
      case nil:
        throw SealedRuntimeWireError.invalid(field: "execution unit")
      }
    }
    for event in events {
      switch event.body {
      case .unitStarted(let started):
        _ = try validateUnit(started.unit)
      case .unitFinished(let finished):
        _ = try validateUnit(finished.unit)
      case .unitJitRejected(let rejected):
        let unitActions = try validateUnit(rejected.unit)
        let outcomeActions = rejected.revalidation.actionOutcomes.map { $0.actionID.value }
        guard Set(outcomeActions).count == outcomeActions.count,
          Set(outcomeActions) == unitActions
        else {
          throw SealedRuntimeWireError.invalid(field: "JIT revalidation action_id")
        }
      case .unitSkippedPrerequisite(let skipped):
        _ = try validateUnit(skipped.unit)
        for prerequisite in skipped.blockingPrerequisites {
          _ = try validateUnit(prerequisite)
        }
      case .stepFinished(let step):
        guard selected.contains(step.actionID.value) else {
          throw SealedRuntimeWireError.invalid(field: "execution step action_id")
        }
      case .releasePostVerificationFinished(let release):
        guard allowedReleaseSets[release.releaseSetID.value] != nil else {
          throw SealedRuntimeWireError.invalid(field: "execution release_set_id")
        }
      default:
        break
      }
    }
  }
}

package enum RuntimeEmissionBudget {
  package static func validateEncodedEnvelopeLengths(_ lengths: [Int]) throws {
    var aggregate: UInt64 = 0
    for length in lengths {
      guard length >= 0, length <= maximumFrameLength else {
        throw FrameError.oversized(length: length, maximum: maximumFrameLength)
      }
      let (framed, frameOverflow) = UInt64(length).addingReportingOverflow(4)
      let (next, aggregateOverflow) = aggregate.addingReportingOverflow(framed)
      guard !frameOverflow, !aggregateOverflow else {
        throw SealedRuntimeWireError.integerOverflow(field: "runtime emission bytes")
      }
      aggregate = next
    }
    guard aggregate <= SealedRuntimeWire.maximumRuntimeFramedEmissionBytes else {
      throw SealedRuntimeWireError.encodedBytesExceeded(
        actual: aggregate,
        maximum: SealedRuntimeWire.maximumRuntimeFramedEmissionBytes
      )
    }
  }
}

final class RuntimeBusinessAuthorityState: @unchecked Sendable {
  private static let maximumConsumedReviewBindingCount = 100_000
  private let lock = NSLock()
  private var plan: RuntimePlanReceipt?
  private var overlay: Diskplan_V1_DecisionOverlayAcknowledged?
  private var review: Diskplan_V1_ApplyReviewProjection?
  private var consumedReviewBindings: Set<Data> = []
  private var executionClaim: RuntimeExecutionClaim?
  private var activeRequestID: UInt64?
  private var activeEmissionToken: RuntimeAuthorityEmissionToken?

  func withLock<T>(_ body: () throws -> T) rethrows -> T {
    lock.lock()
    defer { lock.unlock() }
    return try body()
  }

  func claim(_ request: RuntimeBusinessRequest) -> (
    code: Diskplan_V1_RuntimeRejectCode, summary: String
  )? {
    withLock {
      if activeRequestID != nil {
        return (.invalidState, "another runtime authority request is still active")
      }
      if case .prepareApplyReview = request,
        consumedReviewBindings.count >= Self.maximumConsumedReviewBindingCount
      {
        return (.limitExceeded, "consumed review binding budget is exhausted")
      }
      if case .confirmApply(let confirmation) = request {
        guard let review,
          confirmation.applyReviewID == review.applyReviewID,
          confirmation.reviewBindingSha256 == review.reviewBindingSha256,
          Set(confirmation.confirmedForceActionIds.map(\.value)).count
            == confirmation.confirmedForceActionIds.count,
          Set(confirmation.confirmedForceActionIds.map(\.value))
            == Set(review.forceWarningActionIds.map(\.value)),
          !consumedReviewBindings.contains(review.reviewBindingSha256.value)
        else { return (.staleBinding, "apply confirmation differs from the live review") }
        executionClaim = RuntimeExecutionClaim(
          requestID: request.requestID,
          reviewBinding: review.reviewBindingSha256.value
        )
      }
      activeRequestID = request.requestID
      return nil
    }
  }

  fileprivate func authorize(
    _ emission: RuntimeBusinessEmission,
    for request: RuntimeBusinessRequest,
    negotiatedProtocolMinor: UInt32
  ) throws -> RuntimeAuthorityEmissionTransaction {
    try withLock {
      try beginEmission(
        try prepareUnderLock(
          emission,
          for: request,
          negotiatedProtocolMinor: negotiatedProtocolMinor
        ),
        request: request
      )
    }
  }

  fileprivate func authorize(
    _ prepared: PreparedRuntimeEmission,
    for request: RuntimeBusinessRequest
  ) throws -> RuntimeAuthorityEmissionTransaction {
    try withLock { try beginEmission(prepared, request: request) }
  }

  fileprivate func rejectionTransition(
    for request: RuntimeBusinessRequest
  ) -> RuntimeAuthorityTransition {
    withLock { rejectionTransitionUnderLock(for: request) }
  }

  fileprivate func commit(_ transaction: RuntimeAuthorityEmissionTransaction) throws {
    try withLock {
      guard activeRequestID == transaction.requestID,
        activeEmissionToken === transaction.token
      else { throw invalidState("runtime emission transaction is no longer active") }
      commitUnderLock(transaction.prepared.transition, requestID: transaction.requestID)
      activeEmissionToken = nil
    }
  }

  fileprivate func abort(_ transaction: RuntimeAuthorityEmissionTransaction) {
    withLock {
      guard activeRequestID == transaction.requestID,
        activeEmissionToken === transaction.token
      else { return }
      activeEmissionToken = nil
    }
  }

  func hasLivePlanReceiptForTesting() -> Bool {
    withLock { plan != nil }
  }

  private func beginEmission(
    _ prepared: PreparedRuntimeEmission,
    request: RuntimeBusinessRequest
  ) throws -> RuntimeAuthorityEmissionTransaction {
    guard activeRequestID == request.requestID else {
      throw invalidState("runtime request has no active authority claim")
    }
    guard activeEmissionToken == nil else {
      throw invalidState("runtime request already has an active emission transaction")
    }
    let token = RuntimeAuthorityEmissionToken()
    activeEmissionToken = token
    return RuntimeAuthorityEmissionTransaction(
      requestID: request.requestID,
      token: token,
      prepared: prepared
    )
  }

  private func prepareUnderLock(
    _ emission: RuntimeBusinessEmission,
    for request: RuntimeBusinessRequest,
    negotiatedProtocolMinor: UInt32
  ) throws -> PreparedRuntimeEmission {
    do {
      try SealedRuntimeWire.requireSupportedProtocolMinor(negotiatedProtocolMinor)
    } catch {
      throw invalidState("runtime request uses an unsupported negotiated protocol minor")
    }
    guard activeRequestID == request.requestID else {
      throw invalidState("runtime request has no active authority claim")
    }
    if let plan, plan.negotiatedProtocolMinor != negotiatedProtocolMinor {
      throw invalidState("runtime request protocol minor differs from the live plan")
    }
    switch emission.payload {
    case .plan(_, let records, let metadata):
      guard case .buildPlan(let build) = request,
        build.scanSessionID.value == metadata.scanSessionID,
        build.scanCheckpointID.value == metadata.scanCheckpointID,
        build.scanEvidenceSha256.value == metadata.evidenceSHA256
      else { throw invalidState("plan emission differs from build-plan request") }
      let bodies = try RuntimeBusinessEmission.sealedBodies(
        for: emission.payload,
        negotiatedProtocolMinor: negotiatedProtocolMinor
      )
      guard case .planProjection(let projection)? = bodies.last,
        projection.hasManifest
      else { throw invalidState("plan emission omitted its terminal manifest") }
      return PreparedRuntimeEmission(
        bodies: bodies,
        transition: .plan(
          RuntimePlanReceipt(
            records: records,
            manifest: projection.manifest,
            negotiatedProtocolMinor: negotiatedProtocolMinor
          )
        )
      )

    case .planInvalidated(let projectionID, _, _):
      guard case .buildPlan = request, let plan,
        plan.manifest.projectionID.value == projectionID
      else { throw invalidState("plan invalidation has no exact live predecessor") }
      return PreparedRuntimeEmission(
        bodies: try RuntimeBusinessEmission.sealedBodies(
          for: emission.payload,
          negotiatedProtocolMinor: negotiatedProtocolMinor
        ),
        transition: .invalidatePlan
      )

    case .overlay(let candidate):
      guard case .editDecisionOverlay(let edit) = request, let plan else {
        throw invalidState("overlay emission has no live plan predecessor")
      }
      let expectedBaseRevision = overlay?.revision ?? 0
      guard edit.projectionID == plan.manifest.projectionID,
        edit.baseRevision == expectedBaseRevision,
        candidate.revision == expectedBaseRevision + 1,
        matchesPlan(candidate, plan.manifest)
      else { throw stale("overlay request or plan binding is stale") }
      let sealed = try SealedRuntimeWire.sealDecisionOverlayAcknowledged(
        candidate,
        authoritativePlanRecords: plan.records
      )
      return PreparedRuntimeEmission(
        bodies: [.decisionOverlayAcknowledged(sealed)],
        transition: .overlay(sealed)
      )

    case .overlayRejected(let rejection):
      guard case .editDecisionOverlay(let edit) = request else {
        throw invalidState("overlay rejection differs from request kind")
      }
      try validateOverlayRejection(rejection, request: edit)
      return PreparedRuntimeEmission(
        bodies: try RuntimeBusinessEmission.sealedBodies(
          for: emission.payload,
          negotiatedProtocolMinor: negotiatedProtocolMinor
        ),
        transition: .none
      )

    case .dryRun(let payload, let manifest):
      guard case .prepareDryRun(let prepare) = request, let plan, let overlay,
        prepare.projectionID == plan.manifest.projectionID,
        prepare.overlayID == overlay.overlayID,
        prepare.overlayRevision == overlay.revision,
        prepare.overlaySha256 == overlay.overlaySha256,
        matchesPlan(manifest, plan.manifest),
        matchesOverlay(manifest, overlay)
      else { throw stale("dry-run request or predecessor binding is stale") }
      let sealed = try SealedRuntimeWire.sealDryRun(
        payload: payload,
        manifest: manifest,
        negotiatedProtocolMinor: negotiatedProtocolMinor
      )
      try validateSelectedActions(
        payload.actions.map { ($0.actionID, $0.executionPreview) },
        plan: plan,
        overlay: overlay
      )
      return PreparedRuntimeEmission(bodies: [.dryRunProjection(sealed)], transition: .none)

    case .applyReview(let candidate):
      guard case .prepareApplyReview(let prepare) = request, let plan, let overlay,
        !consumedReviewBindings.contains(candidate.reviewBindingSha256.value),
        prepare.projectionID == plan.manifest.projectionID,
        prepare.overlayID == overlay.overlayID,
        prepare.overlayRevision == overlay.revision,
        prepare.overlaySha256 == overlay.overlaySha256,
        matchesPlan(candidate, plan.manifest),
        matchesOverlay(candidate, overlay)
      else { throw stale("apply-review request or predecessor binding is stale") }
      let sealed = try SealedRuntimeWire.sealApplyReview(
        candidate,
        negotiatedProtocolMinor: negotiatedProtocolMinor
      )
      try validateSelectedReviewActions(sealed.actions, plan: plan, overlay: overlay)
      guard
        Set(sealed.forceWarningActionIds.map(\.value))
          == Set(overlay.forceWarningActionIds.map(\.value))
      else {
        throw invalidState("apply-review force warnings differ from accepted overlay")
      }
      return PreparedRuntimeEmission(
        bodies: [.applyReviewProjection(sealed)],
        transition: .review(sealed)
      )

    case .execution(let events):
      guard let plan, let overlay, let review,
        let executionClaim,
        executionClaim.requestID == request.requestID,
        executionClaim.reviewBinding == review.reviewBindingSha256.value
      else {
        throw invalidState("execution emission has no live apply-review predecessor")
      }
      switch request {
      case .confirmApply(let confirmation):
        let confirmedForce = confirmation.confirmedForceActionIds.map(\.value)
        guard confirmation.applyReviewID == review.applyReviewID,
          confirmation.reviewBindingSha256 == review.reviewBindingSha256,
          Set(confirmedForce).count == confirmedForce.count,
          Set(confirmedForce) == Set(review.forceWarningActionIds.map(\.value))
        else { throw stale("apply confirmation differs from live review") }
      case .cancelExecution:
        throw invalidState("execution cancellation is not supported by this batch runtime")
      default:
        throw invalidState("execution emission differs from request kind")
      }
      let sealed = try SealedRuntimeWire.sealExecutionStream(
        events,
        requiredForceWarningActionIDs: review.forceWarningActionIds,
        negotiatedProtocolMinor: negotiatedProtocolMinor
      )
      try validateExecution(sealed, plan: plan, overlay: overlay, review: review)
      return PreparedRuntimeEmission(
        bodies: sealed.map(Diskplan_V1_RuntimeEvent.OneOf_Body.executionStreamEvent),
        transition: .executionCompleted(
          requestID: request.requestID,
          reviewBinding: review.reviewBindingSha256.value
        )
      )

    case .rejected(_, let summary):
      let transition = rejectionTransitionUnderLock(for: request)
      if transition.consumesExecutionClaim {
        var rejected = Diskplan_V1_RuntimeRejected()
        rejected.code = .confirmationMismatch
        rejected.summary = summary
        return PreparedRuntimeEmission(
          bodies: [.runtimeRejected(rejected)],
          transition: transition
        )
      }
      return PreparedRuntimeEmission(
        bodies: try RuntimeBusinessEmission.sealedBodies(
          for: emission.payload,
          negotiatedProtocolMinor: negotiatedProtocolMinor
        ),
        transition: transition
      )
    }
  }

  private func commitUnderLock(_ transition: RuntimeAuthorityTransition, requestID: UInt64) {
    guard activeRequestID == requestID else { return }
    switch transition {
    case .none:
      break
    case .plan(let receipt):
      plan = receipt
      overlay = nil
      review = nil
    case .invalidatePlan:
      plan = nil
      overlay = nil
      review = nil
    case .overlay(let receipt):
      overlay = receipt
      review = nil
    case .review(let receipt):
      review = receipt
    case .executionCompleted(let requestID, let reviewBinding),
      .executionAborted(let requestID, let reviewBinding):
      guard executionClaim?.requestID == requestID,
        executionClaim?.reviewBinding == reviewBinding
      else { return }
      consumedReviewBindings.insert(reviewBinding)
      review = nil
      executionClaim = nil
    }
    activeRequestID = nil
  }

  private func rejectionTransitionUnderLock(
    for request: RuntimeBusinessRequest
  ) -> RuntimeAuthorityTransition {
    guard case .confirmApply = request,
      let executionClaim,
      executionClaim.requestID == request.requestID
    else { return .none }
    return .executionAborted(
      requestID: executionClaim.requestID,
      reviewBinding: executionClaim.reviewBinding
    )
  }

  private func validateSelectedActions(
    _ actions: [(Diskplan_V1_OpaqueIdentifier, Diskplan_V1_ActionExecutionPreviewProjection)],
    plan: RuntimePlanReceipt,
    overlay: Diskplan_V1_DecisionOverlayAcknowledged
  ) throws {
    let authoritative = Dictionary(
      uniqueKeysWithValues: plan.records.compactMap {
        record -> (Data, Diskplan_V1_PlanActionProjection)? in
        guard case .action(let action)? = record.body else { return nil }
        return (action.actionID.value, action)
      })
    guard Set(actions.map { $0.0.value }) == Set(overlay.selectedActionIds.map(\.value)),
      actions.allSatisfy({ pair in
        authoritative[pair.0.value]?.executionPreview == pair.1
      })
    else { throw invalidState("selected action projection differs from live plan/overlay") }
  }

  private func validateOverlayRejection(
    _ rejection: Diskplan_V1_DecisionOverlayRejected,
    request: Diskplan_V1_DecisionOverlayEditRequest
  ) throws {
    do {
      try Self.validateOverlayRejectionBinding(
        rejection,
        request: request,
        liveRevision: overlay?.revision ?? 0,
        liveProjectionID: plan?.manifest.projectionID,
        planRecords: plan?.records ?? []
      )
    } catch {
      throw invalidState("overlay rejection differs from live request/plan state")
    }
  }

  package static func validateOverlayRejectionBinding(
    _ rejection: Diskplan_V1_DecisionOverlayRejected,
    request: Diskplan_V1_DecisionOverlayEditRequest,
    liveRevision: UInt64,
    liveProjectionID: Diskplan_V1_OpaqueIdentifier?,
    planRecords: [Diskplan_V1_PlanProjectionRecord]
  ) throws {
    guard rejection.currentRevision == liveRevision else {
      throw SealedRuntimeWireError.invalid(field: "overlay rejection current_revision")
    }
    var editedActions = Set<Data>()
    var editedWaivers = Set<RuntimeWaiverKey>()
    for edit in request.edits {
      switch edit.edit {
      case .stageAction(let stage), .unstageAction(let stage):
        editedActions.insert(stage.actionID.value)
      case .allowWaiver(let waiver):
        editedActions.insert(waiver.actionID.value)
        editedWaivers.insert(
          RuntimeWaiverKey(actionID: waiver.actionID.value, waiverID: waiver.waiverID.value)
        )
      case .revokeWaiver(let waiver):
        editedActions.insert(waiver.actionID.value)
        editedWaivers.insert(
          RuntimeWaiverKey(actionID: waiver.actionID.value, waiverID: waiver.waiverID.value)
        )
      case .replaceNotes, .applyBatchSelectionPreset, nil:
        break
      }
    }
    if rejection.hasActionID {
      guard editedActions.contains(rejection.actionID.value) else {
        throw SealedRuntimeWireError.invalid(field: "overlay rejection action_id")
      }
    }
    if rejection.hasWaiverID {
      guard rejection.hasActionID,
        editedWaivers.contains(
          RuntimeWaiverKey(
            actionID: rejection.actionID.value,
            waiverID: rejection.waiverID.value
          ))
      else { throw SealedRuntimeWireError.invalid(field: "overlay rejection waiver_id") }
    }
    var planActions: [Data: Diskplan_V1_PlanActionProjection] = [:]
    for record in planRecords {
      guard case .action(let action)? = record.body else { continue }
      guard planActions.updateValue(action, forKey: action.actionID.value) == nil else {
        throw SealedRuntimeWireError.invalid(field: "duplicate plan action_id")
      }
    }
    let hasLiveProjection = liveProjectionID.map { request.projectionID == $0 } ?? false
    let hasLiveRevision = request.baseRevision == liveRevision
    switch rejection.code {
    case .unknownProjection, .staleRevision:
      guard !rejection.hasActionID, !rejection.hasWaiverID else {
        throw SealedRuntimeWireError.invalid(field: "projection/revision rejection shape")
      }
      if rejection.code == .unknownProjection {
        guard !hasLiveProjection else {
          throw SealedRuntimeWireError.invalid(field: "unknown-projection rejection binding")
        }
      } else {
        guard hasLiveProjection, !hasLiveRevision else {
          throw SealedRuntimeWireError.invalid(field: "stale-revision rejection binding")
        }
      }
    case .unknownAction:
      guard hasLiveProjection, hasLiveRevision,
        rejection.hasActionID, !rejection.hasWaiverID,
        planActions[rejection.actionID.value] == nil
      else { throw SealedRuntimeWireError.invalid(field: "unknown-action rejection shape") }
    case .actionNotStageable:
      guard hasLiveProjection, hasLiveRevision,
        rejection.hasActionID, !rejection.hasWaiverID,
        planActions[rejection.actionID.value]?.stageability == .notStageable
      else { throw SealedRuntimeWireError.invalid(field: "not-stageable rejection shape") }
    case .unknownWaiver:
      guard hasLiveProjection, hasLiveRevision,
        rejection.hasActionID, rejection.hasWaiverID,
        let action = planActions[rejection.actionID.value],
        !action.requiredWaivers.contains(where: {
          $0.waiverID == rejection.waiverID
        })
      else {
        throw SealedRuntimeWireError.invalid(field: "unknown-waiver rejection shape")
      }
    case .waiverNotAllowed, .invalidReason:
      guard hasLiveProjection, hasLiveRevision,
        rejection.hasActionID, rejection.hasWaiverID,
        let action = planActions[rejection.actionID.value],
        action.requiredWaivers.contains(where: {
          $0.waiverID == rejection.waiverID
        })
      else {
        throw SealedRuntimeWireError.invalid(field: "waiver rejection shape")
      }
    case .limitExceeded, .invalidEdit, .internalError:
      guard hasLiveProjection, hasLiveRevision else {
        throw SealedRuntimeWireError.invalid(field: "overlay rejection predecessor binding")
      }
    case .unspecified, .UNRECOGNIZED:
      throw SealedRuntimeWireError.invalid(field: "overlay rejection code")
    }
  }

  private func validateSelectedReviewActions(
    _ actions: [Diskplan_V1_ApplyReviewActionProjection],
    plan: RuntimePlanReceipt,
    overlay: Diskplan_V1_DecisionOverlayAcknowledged
  ) throws {
    try validateSelectedActions(
      actions.map { ($0.actionID, $0.executionPreview) },
      plan: plan,
      overlay: overlay
    )
    let authoritative = Dictionary(
      uniqueKeysWithValues: plan.records.compactMap { record -> (Data, Bool)? in
        guard case .action(let action)? = record.body else { return nil }
        return (action.actionID.value, action.requiresForce)
      })
    guard actions.allSatisfy({ authoritative[$0.actionID.value] == $0.requiresForce }) else {
      throw invalidState("apply-review force bit differs from live plan")
    }
  }

  private func validateExecution(
    _ events: [Diskplan_V1_ExecutionStreamEvent],
    plan: RuntimePlanReceipt,
    overlay: Diskplan_V1_DecisionOverlayAcknowledged,
    review: Diskplan_V1_ApplyReviewProjection
  ) throws {
    try RuntimeExecutionAuthorityValidator.validateMembership(
      events: events,
      planRecords: plan.records,
      selectedActionIDs: overlay.selectedActionIds
    )
    guard let terminal = events.last?.applyFinished,
      terminal.applyReviewID == review.applyReviewID,
      terminal.reviewBindingSha256 == review.reviewBindingSha256
    else { throw invalidState("execution terminal differs from live apply review") }
    if terminal.startFailure == .unspecified {
      guard case .applyStarted(let started)? = events.first?.body,
        started.applyReviewID == review.applyReviewID,
        started.projectionID == plan.manifest.projectionID,
        started.planID == plan.manifest.planID,
        started.planSha256 == plan.manifest.planSha256,
        started.evidenceID == plan.manifest.evidenceID,
        started.evidenceSha256 == plan.manifest.evidenceSha256,
        started.scanSessionID == plan.manifest.scanSessionID,
        started.scanCheckpointID == plan.manifest.scanCheckpointID,
        started.scanCheckpointEvidenceSha256 == plan.manifest.scanCheckpointEvidenceSha256,
        started.overlayID == overlay.overlayID,
        started.overlaySha256 == overlay.overlaySha256,
        started.overlayRevision == overlay.revision,
        started.selectedActionCount == overlay.selectedActionCount,
        started.reviewBindingSha256 == review.reviewBindingSha256,
        started.currentBindingSha256 == review.currentBindingSha256,
        started.revalidationSha256 == review.revalidationSha256,
        started.epoch == review.epoch
      else { throw invalidState("execution start differs from live apply review") }
    }
    let reviewActions = Dictionary(
      uniqueKeysWithValues: review.actions.map {
        ($0.actionID.value, $0.executionPreview)
      })
    for event in events {
      if case .forceRequiredWarning(let warning)? = event.body,
        reviewActions[warning.actionID.value] != warning.preview
      {
        throw invalidState("execution force preview differs from live apply review")
      }
    }
  }

  private func matchesPlan(
    _ value: Diskplan_V1_DecisionOverlayAcknowledged,
    _ manifest: Diskplan_V1_PlanProjectionManifest
  ) -> Bool {
    value.projectionID == manifest.projectionID && value.planID == manifest.planID
      && value.planSha256 == manifest.planSha256 && value.evidenceID == manifest.evidenceID
      && value.evidenceSha256 == manifest.evidenceSha256
      && value.scanSessionID == manifest.scanSessionID
      && value.scanCheckpointID == manifest.scanCheckpointID
      && value.scanCheckpointEvidenceSha256 == manifest.scanCheckpointEvidenceSha256
  }

  private func matchesPlan(
    _ value: Diskplan_V1_DryRunProjectionManifest,
    _ manifest: Diskplan_V1_PlanProjectionManifest
  ) -> Bool {
    value.projectionID == manifest.projectionID && value.planID == manifest.planID
      && value.planSha256 == manifest.planSha256 && value.evidenceID == manifest.evidenceID
      && value.evidenceSha256 == manifest.evidenceSha256
      && value.scanSessionID == manifest.scanSessionID
      && value.scanCheckpointID == manifest.scanCheckpointID
      && value.scanCheckpointEvidenceSha256 == manifest.scanCheckpointEvidenceSha256
  }

  private func matchesPlan(
    _ value: Diskplan_V1_ApplyReviewProjection,
    _ manifest: Diskplan_V1_PlanProjectionManifest
  ) -> Bool {
    value.projectionID == manifest.projectionID && value.planID == manifest.planID
      && value.planSha256 == manifest.planSha256 && value.evidenceID == manifest.evidenceID
      && value.evidenceSha256 == manifest.evidenceSha256
      && value.scanSessionID == manifest.scanSessionID
      && value.scanCheckpointID == manifest.scanCheckpointID
      && value.scanCheckpointEvidenceSha256 == manifest.scanCheckpointEvidenceSha256
  }

  private func matchesOverlay(
    _ value: Diskplan_V1_DryRunProjectionManifest,
    _ overlay: Diskplan_V1_DecisionOverlayAcknowledged
  ) -> Bool {
    value.overlayID == overlay.overlayID && value.overlayRevision == overlay.revision
      && value.overlaySha256 == overlay.overlaySha256
      && value.selectedActionCount == overlay.selectedActionCount
  }

  private func matchesOverlay(
    _ value: Diskplan_V1_ApplyReviewProjection,
    _ overlay: Diskplan_V1_DecisionOverlayAcknowledged
  ) -> Bool {
    value.overlayID == overlay.overlayID && value.overlayRevision == overlay.revision
      && value.overlaySha256 == overlay.overlaySha256
      && value.selectedActionCount == overlay.selectedActionCount
  }

  private func invalidState(_ summary: String) -> RuntimeAuthorityError {
    RuntimeAuthorityError(code: .invalidState, summary: summary)
  }

  private func stale(_ summary: String) -> RuntimeAuthorityError {
    RuntimeAuthorityError(code: .staleBinding, summary: summary)
  }
}

public final class RuntimeBusinessResponder: @unchecked Sendable {
  private let responseLock = NSLock()
  private let broker: SerialEventBroker
  private let requestID: UInt64
  private let runtimeSessionID: Data
  private let request: RuntimeBusinessRequest
  private let authority: RuntimeBusinessAuthorityState
  private var completed = false

  /// The exact protocol minor selected by the version handshake for this
  /// runtime session. Handlers use it to author the closed preview shape.
  public let negotiatedProtocolMinor: UInt32

  init(
    broker: SerialEventBroker,
    request: RuntimeBusinessRequest,
    negotiatedProtocolMinor: UInt32 = protocolMinor,
    runtimeSessionID: Data,
    authority: RuntimeBusinessAuthorityState
  ) {
    self.broker = broker
    self.negotiatedProtocolMinor = negotiatedProtocolMinor
    requestID = request.requestID
    self.request = request
    self.runtimeSessionID = runtimeSessionID
    self.authority = authority
  }

  public func send(_ emission: RuntimeBusinessEmission) throws {
    responseLock.lock()
    defer { responseLock.unlock() }
    guard !completed else {
      throw RuntimeResponderError.alreadyTerminal
    }
    let transaction: RuntimeAuthorityEmissionTransaction
    do {
      transaction = try authority.authorize(
        emission,
        for: request,
        negotiatedProtocolMinor: negotiatedProtocolMinor
      )
    } catch let error as RuntimeAuthorityError {
      let transition = authority.rejectionTransition(for: request)
      transaction = try authority.authorize(
        typedRejection(
          code: transition.consumesExecutionClaim ? .confirmationMismatch : error.code,
          summary: error.summary,
          transition: transition
        ),
        for: request
      )
    }
    try transmit(transaction)
  }

  func rejectHandlerFailure() throws {
    responseLock.lock()
    defer { responseLock.unlock() }
    guard !completed else { return }
    let transition = authority.rejectionTransition(for: request)
    let transaction = try authority.authorize(
      typedRejection(
        code: transition.consumesExecutionClaim ? .confirmationMismatch : .internalError,
        summary: "runtime business handler failed",
        transition: transition
      ),
      for: request
    )
    try transmit(transaction)
  }

  private func transmit(_ transaction: RuntimeAuthorityEmissionTransaction) throws {
    do {
      try sendPrepared(transaction.prepared)
      try authority.commit(transaction)
      completed = true
    } catch {
      authority.abort(transaction)
      throw error
    }
  }

  private func typedRejection(
    code: Diskplan_V1_RuntimeRejectCode,
    summary: String,
    transition: RuntimeAuthorityTransition = .none
  ) -> PreparedRuntimeEmission {
    var rejected = Diskplan_V1_RuntimeRejected()
    rejected.code = code
    rejected.summary = summary
    return PreparedRuntimeEmission(bodies: [.runtimeRejected(rejected)], transition: transition)
  }

  private func sendPrepared(_ prepared: PreparedRuntimeEmission) throws {
    let bodies = prepared.bodies
    var envelopeLengths: [Int] = []
    envelopeLengths.reserveCapacity(bodies.count)
    for body in bodies {
      var event = Diskplan_V1_RuntimeEvent()
      event.eventSequence = UInt64.max
      event.requestID = requestID
      event.runtimeSessionID.value = runtimeSessionID
      event.body = body
      var envelope = Diskplan_V1_Envelope()
      envelope.sequence = UInt64.max
      envelope.body = .runtimeEvent(event)
      let encoded = try envelope.serializedData()
      envelopeLengths.append(encoded.count)
    }
    try RuntimeEmissionBudget.validateEncodedEnvelopeLengths(envelopeLengths)
    for body in bodies {
      try broker.sendRuntime(
        requestID: requestID,
        runtimeSessionID: runtimeSessionID,
        body: body
      )
    }
    try broker.flush()
  }
}
