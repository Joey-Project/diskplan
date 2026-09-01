import DiskplanPolicy
import DiskplanProto
import Foundation

/// Immutable engine-owned input to one execution preparation.
///
/// This package surface is available to the executable composition root but
/// cannot become external caller-authored mutation authority.
package struct RuntimeExecutionPlanContext: Sendable {
  package let plan: ImmutablePlan
  package let overlay: DecisionOverlay
  package let planRecords: [Diskplan_V1_PlanProjectionRecord]
  package let releaseSetIDByAllocationGroup: [Data: Data]
  package let planManifest: Diskplan_V1_PlanProjectionManifest
  package let overlayProjection: Diskplan_V1_DecisionOverlayAcknowledged
  package let negotiatedProtocolMinor: UInt32
}

package struct RuntimePreparedDryRun: Sendable {
  package let payload: Diskplan_V1_DryRunProjectionPayload
  package let manifest: Diskplan_V1_DryRunProjectionManifest

  package init(
    payload: Diskplan_V1_DryRunProjectionPayload,
    manifest: Diskplan_V1_DryRunProjectionManifest
  ) {
    self.payload = payload
    self.manifest = manifest
  }
}

package struct RuntimeApplyConfirmation: Sendable {
  package let review: Diskplan_V1_ApplyReviewProjection
  package let confirmedForceActionIDs: [Diskplan_V1_OpaqueIdentifier]

  package init(
    review: Diskplan_V1_ApplyReviewProjection,
    confirmedForceActionIDs: [Diskplan_V1_OpaqueIdentifier]
  ) {
    self.review = review
    self.confirmedForceActionIDs = confirmedForceActionIDs
  }
}

/// A package-owned projection result that cannot be constructed from unchecked protobuf bytes.
package struct RuntimeAuthoritativeExecutionProjection: Sendable {
  fileprivate let sealedEvents: [Diskplan_V1_ExecutionStreamEvent]
  fileprivate let validationFailed: Bool

  private init(
    sealedEvents: [Diskplan_V1_ExecutionStreamEvent],
    validationFailed: Bool
  ) {
    self.sealedEvents = sealedEvents
    self.validationFailed = validationFailed
  }

  package static func validating(
    applyStarted: Diskplan_V1_ExecutionStreamEvent,
    remainingEvents: [Diskplan_V1_ExecutionStreamEvent],
    requiredForceWarningActionIDs: [Diskplan_V1_OpaqueIdentifier],
    negotiatedProtocolMinor: UInt32
  ) -> Self {
    do {
      guard !remainingEvents.isEmpty,
        remainingEvents.dropLast().allSatisfy({ event in
          guard event.body != nil else { return false }
          if case .applyStarted? = event.body { return false }
          if case .cancellationAcknowledged? = event.body { return false }
          if case .applyFinished? = event.body { return false }
          return true
        }),
        case .applyFinished? = remainingEvents.last?.body
      else { throw SealedRuntimeWireError.invalid(field: "runtime execution tail") }
      let sealed = try SealedRuntimeWire.sealExecutionStream(
        [applyStarted] + remainingEvents,
        requiredForceWarningActionIDs: requiredForceWarningActionIDs,
        negotiatedProtocolMinor: negotiatedProtocolMinor
      )
      return Self(sealedEvents: Array(sealed.dropFirst()), validationFailed: false)
    } catch {
      return Self(sealedEvents: [], validationFailed: true)
    }
  }
}

package enum RuntimeExecutionTailFailure: Equatable, Sendable {
  case projectionLimitExceeded(observedEventCount: UInt64, observedEncodedBytes: UInt64)
  case projectionValidationFailed
  case backendContractViolation
}

/// A package-owned, semantically sealed tail for one already-started run.
package struct RuntimeExecutionTail: Sendable {
  let events: [Diskplan_V1_ExecutionStreamEvent]

  private init(sealedEvents: [Diskplan_V1_ExecutionStreamEvent]) {
    events = sealedEvents
  }

  package static func outcome(
    authoritativeProjection: RuntimeAuthoritativeExecutionProjection
  ) -> RuntimeExecutionTailOutcome {
    guard !authoritativeProjection.validationFailed else {
      return .failed(.projectionValidationFailed)
    }
    return .sealed(RuntimeExecutionTail(sealedEvents: authoritativeProjection.sealedEvents))
  }

  package init(
    applyStarted: Diskplan_V1_ExecutionStreamEvent,
    remainingEvents: [Diskplan_V1_ExecutionStreamEvent],
    requiredForceWarningActionIDs: [Diskplan_V1_OpaqueIdentifier],
    negotiatedProtocolMinor: UInt32
  ) throws {
    let projection = RuntimeAuthoritativeExecutionProjection.validating(
      applyStarted: applyStarted,
      remainingEvents: remainingEvents,
      requiredForceWarningActionIDs: requiredForceWarningActionIDs,
      negotiatedProtocolMinor: negotiatedProtocolMinor
    )
    guard !projection.validationFailed else {
      throw SealedRuntimeWireError.invalid(field: "runtime execution tail")
    }
    events = projection.sealedEvents
  }
}

package enum RuntimeExecutionTailOutcome: Sendable {
  case sealed(RuntimeExecutionTail)
  case failed(RuntimeExecutionTailFailure)
}

package struct RuntimeApplyStartFailureTerminal: Sendable {
  package let event: Diskplan_V1_ExecutionStreamEvent

  package init(
    validating event: Diskplan_V1_ExecutionStreamEvent,
    negotiatedProtocolMinor: UInt32
  ) throws {
    guard case .applyFinished(let terminal)? = event.body,
      terminal.startFailure != .unspecified
    else { throw SealedRuntimeWireError.invalid(field: "apply start failure terminal") }
    let sealed = try SealedRuntimeWire.sealExecutionStream(
      [event],
      requiredForceWarningActionIDs: [],
      negotiatedProtocolMinor: negotiatedProtocolMinor
    )
    guard sealed.count == 1 else {
      throw SealedRuntimeWireError.invalid(field: "apply start failure terminal")
    }
    self.event = sealed[0]
  }
}

package enum RuntimeApplyLaunchResult: Sendable {
  case started(RuntimeExecutionRunHandle)
  case startFailed(RuntimeApplyStartFailureTerminal)
}

/// EngineCore-owned handle for one already-started best-effort execution.
///
/// Construction validates the execution identifier and `apply_started`
/// shape. The tail task is created once, never throws, and is shared by normal
/// completion, cancellation, and teardown.
package final class RuntimeExecutionRunHandle: @unchecked Sendable {
  package let executionID: Data
  package let applyStarted: Diskplan_V1_ExecutionStreamEvent

  private let cancellationLock = NSLock()
  private let cancellation: @Sendable () -> Void
  private let tailTask: Task<RuntimeExecutionTailOutcome, Never>
  private var cancellationRequested = false

  private init(
    executionID: Data,
    applyStarted: Diskplan_V1_ExecutionStreamEvent,
    tailTask: Task<RuntimeExecutionTailOutcome, Never>,
    cancel: @escaping @Sendable () -> Void
  ) {
    self.executionID = executionID
    self.applyStarted = applyStarted
    cancellation = cancel
    self.tailTask = tailTask
  }

  package static func start(
    executionID: Data,
    applyStarted: Diskplan_V1_ExecutionStreamEvent,
    awaitTail: @escaping @Sendable () async -> RuntimeExecutionTailOutcome,
    cancel: @escaping @Sendable () -> Void
  ) async throws -> RuntimeExecutionRunHandle {
    let tailTask = Task { await awaitTail() }
    guard !executionID.isEmpty,
      executionID.count <= SealedRuntimeWire.maximumOpaqueIdentifierBytes,
      applyStarted.executionID.value == executionID,
      case .applyStarted? = applyStarted.body
    else {
      cancel()
      _ = await tailTask.value
      throw SealedRuntimeWireError.invalid(field: "runtime execution start")
    }
    return RuntimeExecutionRunHandle(
      executionID: executionID,
      applyStarted: applyStarted,
      tailTask: tailTask,
      cancel: cancel
    )
  }

  package func awaitTail() async -> RuntimeExecutionTailOutcome {
    await tailTask.value
  }

  package func cancel() {
    cancellationLock.lock()
    let shouldCancel = !cancellationRequested
    cancellationRequested = true
    cancellationLock.unlock()
    if shouldCancel { cancellation() }
  }
}

/// Package-only prepared attempt. The controller wraps it in its own one-shot
/// box before the corresponding review becomes visible to confirmation.
package struct RuntimePreparedApplyAttempt: Sendable {
  fileprivate let starter:
    @Sendable (RuntimeApplyConfirmation, RuntimeExecutionPlanContext) async throws ->
      RuntimeApplyLaunchResult

  package init(
    start:
      @escaping @Sendable (RuntimeApplyConfirmation, RuntimeExecutionPlanContext) async throws ->
      RuntimeApplyLaunchResult
  ) {
    starter = start
  }

  package func start(
    confirmation: RuntimeApplyConfirmation,
    context: RuntimeExecutionPlanContext
  ) async throws -> RuntimeApplyLaunchResult {
    try await starter(confirmation, context)
  }
}

package struct RuntimePreparedApplyReview: Sendable {
  package let projection: Diskplan_V1_ApplyReviewProjection
  package let attempt: RuntimePreparedApplyAttempt

  package init(
    projection: Diskplan_V1_ApplyReviewProjection,
    attempt: RuntimePreparedApplyAttempt
  ) {
    self.projection = projection
    self.attempt = attempt
  }
}

/// Composition-root seam between EngineCore authority and Phase 4/5.
///
/// The conformer belongs in the executable target. An absent backend remains
/// fail-closed and does not advertise dry-run or execution capabilities.
package protocol RuntimeExecutionBackend: AnyObject, Sendable {
  func prepareDryRun(
    context: RuntimeExecutionPlanContext,
    lifetimeSeconds: Int64
  ) async throws -> RuntimePreparedDryRun

  func prepareApplyReview(
    context: RuntimeExecutionPlanContext,
    lifetimeSeconds: Int64
  ) async throws -> RuntimePreparedApplyReview
}

package enum RuntimeExecutionBackendFailure: Error, Equatable {
  case revalidationFailed
}
