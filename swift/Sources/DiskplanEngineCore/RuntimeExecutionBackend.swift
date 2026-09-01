import DiskplanPolicy
import DiskplanProto
import Foundation

/// The immutable engine-owned input to one execution preparation.
///
/// A backend receives domain objects and closed wire projections, never raw
/// frontend argv or a caller-authored mutation capability.
public struct RuntimeExecutionPlanContext: Sendable {
  public let plan: ImmutablePlan
  public let overlay: DecisionOverlay
  public let planRecords: [Diskplan_V1_PlanProjectionRecord]
  public let planManifest: Diskplan_V1_PlanProjectionManifest
  public let overlayProjection: Diskplan_V1_DecisionOverlayAcknowledged
  public let negotiatedProtocolMinor: UInt32

  public init(
    plan: ImmutablePlan,
    overlay: DecisionOverlay,
    planRecords: [Diskplan_V1_PlanProjectionRecord],
    planManifest: Diskplan_V1_PlanProjectionManifest,
    overlayProjection: Diskplan_V1_DecisionOverlayAcknowledged,
    negotiatedProtocolMinor: UInt32
  ) {
    self.plan = plan
    self.overlay = overlay
    self.planRecords = planRecords
    self.planManifest = planManifest
    self.overlayProjection = overlayProjection
    self.negotiatedProtocolMinor = negotiatedProtocolMinor
  }
}

/// Opaque, in-process apply authority. Concrete implementations wrap the
/// Phase 4 single-use capability and never serialize it onto the runtime wire.
public protocol RuntimePreparedApplyAuthority: AnyObject, Sendable {}

public struct RuntimePreparedDryRun: Sendable {
  public let payload: Diskplan_V1_DryRunProjectionPayload
  public let manifest: Diskplan_V1_DryRunProjectionManifest

  public init(
    payload: Diskplan_V1_DryRunProjectionPayload,
    manifest: Diskplan_V1_DryRunProjectionManifest
  ) {
    self.payload = payload
    self.manifest = manifest
  }
}

public struct RuntimePreparedApplyReview: Sendable {
  public let projection: Diskplan_V1_ApplyReviewProjection
  public let authority: any RuntimePreparedApplyAuthority

  public init(
    projection: Diskplan_V1_ApplyReviewProjection,
    authority: any RuntimePreparedApplyAuthority
  ) {
    self.projection = projection
    self.authority = authority
  }
}

public struct RuntimeApplyConfirmation: Sendable {
  public let review: Diskplan_V1_ApplyReviewProjection
  public let confirmedForceActionIDs: [Diskplan_V1_OpaqueIdentifier]

  public init(
    review: Diskplan_V1_ApplyReviewProjection,
    confirmedForceActionIDs: [Diskplan_V1_OpaqueIdentifier]
  ) {
    self.review = review
    self.confirmedForceActionIDs = confirmedForceActionIDs
  }
}

/// One already-started best-effort execution. `applyStarted` is available
/// immediately so the frontend learns the exact execution ID before it may
/// request cancellation. `remainingEvents()` must end in `apply_finished`.
public protocol RuntimeExecutionRun: AnyObject, Sendable {
  var executionID: Data { get }
  var applyStarted: Diskplan_V1_ExecutionStreamEvent { get }

  func remainingEvents() async throws -> [Diskplan_V1_ExecutionStreamEvent]
  func cancel()
}

/// Composition-root seam between EngineCore authority and Phase 4/5.
///
/// The production conformer belongs in the executable target that can import
/// both EngineCore and DiskplanExecution. An absent backend is fail-closed and
/// must not advertise dry-run or execution capabilities.
public protocol RuntimeExecutionBackend: AnyObject, Sendable {
  func prepareDryRun(
    context: RuntimeExecutionPlanContext,
    lifetimeSeconds: Int64
  ) async throws -> RuntimePreparedDryRun

  func prepareApplyReview(
    context: RuntimeExecutionPlanContext,
    lifetimeSeconds: Int64
  ) async throws -> RuntimePreparedApplyReview

  func startApply(
    authority: any RuntimePreparedApplyAuthority,
    confirmation: RuntimeApplyConfirmation,
    context: RuntimeExecutionPlanContext
  ) async throws -> any RuntimeExecutionRun
}
