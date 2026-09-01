import CryptoKit
import DiskplanPolicy
import DiskplanProto
import DiskplanScan
import Foundation

struct RuntimeFinalizedScanReceipt: @unchecked Sendable {
  let scanSessionID: Data
  let checkpointID: Data
  let finalEvidenceSHA256: Data
  let checkpointEvidenceSHA256: Data
  let isPartial: Bool
  let authoritySession: RuntimePolicyAuthoritySession
}

protocol RuntimeScanAuthority: RuntimeBusinessHandler, Sendable {
  func makeAuthoritySession(
    scope: ResolvedScanScope,
    scanSessionID: String
  ) -> RuntimePolicyAuthoritySession

  func publishFinalizedReceipt(_ receipt: RuntimeFinalizedScanReceipt)
}

enum RuntimeSessionControllerError: Error, Equatable {
  case receiptNotFound
  case staleReceipt
  case partialEvidenceNotAllowed
  case unsupportedAgentMode
  case planNotBuilt
}

/// The production runtime authority for the Phase S0+S1 slice.
///
/// Scan receipts become visible only after `ScanCoordinator` receives the
/// final checkpoint writer acknowledgement. Plan and overlay state remain
/// engine-owned domain models; protobufs are projections of that state.
public final class RuntimeSessionController: RuntimeScanAuthority, RuntimeBusinessLifecycle,
  @unchecked Sendable
{
  public var supportedCapabilities: Set<String> {
    var capabilities: Set<String> = [
      "decision-overlay-v1",
      "plan-projection-v1",
    ]
    if executionBackend != nil {
      capabilities.formUnion(["dry-run-projection-v1", "execution-stream-v1"])
    }
    return capabilities
  }

  private struct LivePlan {
    let receipt: RuntimeFinalizedScanReceipt
    let result: RuntimePolicyAuthorityResult
    let records: [Diskplan_V1_PlanProjectionRecord]
    let metadata: PlanProjectionWireMetadata
    let manifest: Diskplan_V1_PlanProjectionManifest
    var domainOverlay: DecisionOverlay?
    var overlayProjection: Diskplan_V1_DecisionOverlayAcknowledged?
    var overlayRevision: UInt64
  }

  private struct PreparedApply {
    let context: RuntimeExecutionPlanContext
    let projection: Diskplan_V1_ApplyReviewProjection
    let authority: any RuntimePreparedApplyAuthority
  }

  private struct ActiveExecution {
    let run: any RuntimeExecutionRun
    let context: RuntimeExecutionPlanContext
    let review: Diskplan_V1_ApplyReviewProjection
    let confirmationResponder: RuntimeBusinessResponder
    var events: [Diskplan_V1_ExecutionStreamEvent]
    var cancellationResponder: RuntimeBusinessResponder?
  }

  private let lock = NSLock()
  private let taskCondition = NSCondition()
  private let executionBackend: (any RuntimeExecutionBackend)?
  private var finalizedReceipts: [Data: RuntimeFinalizedScanReceipt] = [:]
  private var livePlan: LivePlan?
  private var preparedApply: PreparedApply?
  private var activeExecution: ActiveExecution?
  private var ownedTasks: [UUID: RuntimeOwnedTask] = [:]
  private var stopping = false

  public init(executionBackend: (any RuntimeExecutionBackend)? = nil) {
    self.executionBackend = executionBackend
  }

  func makeAuthoritySession(
    scope: ResolvedScanScope,
    scanSessionID _: String
  ) -> RuntimePolicyAuthoritySession {
    RuntimePolicyAuthoritySession(scope: scope)
  }

  func publishFinalizedReceipt(_ receipt: RuntimeFinalizedScanReceipt) {
    lock.lock()
    finalizedReceipts[receipt.scanSessionID] = receipt
    lock.unlock()
  }

  public func handle(
    _ request: RuntimeBusinessRequest,
    responder: RuntimeBusinessResponder
  ) throws {
    switch request {
    case .buildPlan(let build):
      try handleBuildPlan(build, responder: responder)
    case .editDecisionOverlay(let edit):
      try handleOverlayEdit(edit, responder: responder)
    case .prepareDryRun(let prepare):
      try handleDryRun(prepare, responder: responder)
    case .prepareApplyReview(let prepare):
      try handleApplyReview(prepare, responder: responder)
    case .confirmApply(let confirmation):
      try handleConfirmApply(confirmation, responder: responder)
    case .cancelExecution(let cancellation):
      try handleCancelExecution(cancellation, responder: responder)
    }
  }

  private func handleBuildPlan(
    _ request: Diskplan_V1_BuildPlanRequest,
    responder: RuntimeBusinessResponder
  ) throws {
    switch request.agentMode {
    case .unspecified, .off:
      break
    case .ask, .auto, .UNRECOGNIZED:
      try responder.send(
        try .rejected(
          code: .businessUnsupported,
          summary: "agent-assisted planning is not installed"
        ))
      return
    }

    let receipt: RuntimeFinalizedScanReceipt?
    lock.lock()
    receipt = finalizedReceipts[request.scanSessionID.value]
    lock.unlock()
    guard let receipt else {
      try responder.send(
        try .rejected(
          code: .invalidState,
          summary: "no writer-acknowledged final scan receipt exists for this session"
        ))
      return
    }
    guard receipt.checkpointID == request.scanCheckpointID.value,
      receipt.finalEvidenceSHA256 == request.scanEvidenceSha256.value
    else {
      try responder.send(
        try .rejected(
          code: .staleBinding,
          summary: "build-plan request differs from the finalized scan receipt"
        ))
      return
    }
    guard !receipt.isPartial || request.allowPartialEvidence else {
      try responder.send(
        try .rejected(
          code: .invalidState,
          summary: "partial scan evidence requires allow_partial_evidence"
        ))
      return
    }

    let result = try receipt.authoritySession.makePlan()
    let records = try RuntimePlanDomainProjector.project(
      result,
      negotiatedProtocolMinor: responder.negotiatedProtocolMinor
    )
    let metadata = PlanProjectionWireMetadata(
      scanSessionID: receipt.scanSessionID,
      scanCheckpointID: receipt.checkpointID,
      scanCheckpointEvidenceSHA256: receipt.checkpointEvidenceSHA256,
      planSHA256: result.plan.planHash.bytes,
      evidenceSHA256: receipt.finalEvidenceSHA256,
      cleanupCandidateCount: UInt64(result.plan.actions.count),
      policyVersion: result.plan.policyVersion,
      schemaVersion: result.plan.schemaVersion
    )
    let wire = try PlanProjectionWireEncoder.encode(
      records: records,
      metadata: metadata,
      negotiatedProtocolMinor: responder.negotiatedProtocolMinor
    )
    let planBuildID = runtimeDigest(
      domain: "diskplan/plan-build/v1\0",
      fields: [receipt.scanSessionID, receipt.checkpointID, result.plan.planHash.bytes]
    )
    try responder.send(
      try .plan(
        planBuildID: planBuildID,
        records: records,
        metadata: metadata,
        negotiatedProtocolMinor: responder.negotiatedProtocolMinor
      ))

    lock.lock()
    livePlan = LivePlan(
      receipt: receipt,
      result: result,
      records: records,
      metadata: metadata,
      manifest: wire.manifest,
      domainOverlay: nil,
      overlayProjection: nil,
      overlayRevision: 0
    )
    lock.unlock()
  }

  private func handleOverlayEdit(
    _ request: Diskplan_V1_DecisionOverlayEditRequest,
    responder: RuntimeBusinessResponder
  ) throws {
    lock.lock()
    let snapshot = livePlan
    lock.unlock()
    guard var live = snapshot else {
      try sendOverlayRejection(
        code: .unknownProjection,
        summary: "no live plan projection exists",
        currentRevision: 0,
        responder: responder
      )
      return
    }
    guard request.projectionID == live.manifest.projectionID else {
      try sendOverlayRejection(
        code: .unknownProjection,
        summary: "projection_id is not the live plan projection",
        currentRevision: live.overlayRevision,
        responder: responder
      )
      return
    }
    guard request.baseRevision == live.overlayRevision else {
      try sendOverlayRejection(
        code: .staleRevision,
        summary: "base_revision is not the live overlay revision",
        currentRevision: live.overlayRevision,
        responder: responder
      )
      return
    }
    guard !request.edits.isEmpty else {
      try sendOverlayRejection(
        code: .invalidEdit,
        summary: "an overlay edit request must contain at least one edit",
        currentRevision: live.overlayRevision,
        responder: responder
      )
      return
    }

    do {
      let edited = try RuntimeOverlayEditor.apply(
        request.edits,
        to: live.domainOverlay,
        plan: live.result.plan
      )
      let nextRevision = try incrementedRevision(live.overlayRevision)
      let projected = try RuntimeOverlayProjector.project(
        edited,
        revision: nextRevision,
        manifest: live.manifest,
        records: live.records
      )
      try responder.send(try .decisionOverlay(projected))
      live.domainOverlay = edited
      live.overlayProjection = projected
      live.overlayRevision = nextRevision
      lock.lock()
      self.livePlan = live
      preparedApply = nil
      lock.unlock()
    } catch let rejection as RuntimeOverlayEditRejection {
      try sendOverlayRejection(
        code: rejection.code,
        summary: rejection.summary,
        actionID: rejection.actionID,
        waiverID: rejection.waiverID,
        currentRevision: live.overlayRevision,
        responder: responder
      )
    } catch {
      try sendOverlayRejection(
        code: .invalidEdit,
        summary: "overlay edits do not form a valid authoritative selection",
        currentRevision: live.overlayRevision,
        responder: responder
      )
    }
  }

  private func handleDryRun(
    _ request: Diskplan_V1_PrepareDryRunRequest,
    responder: RuntimeBusinessResponder
  ) throws {
    guard let executionBackend else {
      try responder.send(
        try .rejected(
          code: .businessUnsupported,
          summary: "runtime execution backend is not installed"
        ))
      return
    }
    guard
      let context = executionContext(
        projectionID: request.projectionID,
        overlayID: request.overlayID,
        overlayRevision: request.overlayRevision,
        overlaySHA256: request.overlaySha256,
        negotiatedProtocolMinor: responder.negotiatedProtocolMinor
      )
    else {
      try responder.send(
        try .rejected(code: .staleBinding, summary: "dry-run predecessor binding is stale"))
      return
    }
    startTask { [weak self] in
      do {
        let prepared = try await executionBackend.prepareDryRun(
          context: context,
          lifetimeSeconds: 300
        )
        guard self?.contextIsCurrent(context) == true else {
          try responder.send(
            try .rejected(
              code: .staleBinding,
              summary: "plan or overlay changed during dry-run preparation"
            ))
          return
        }
        try responder.send(
          try .dryRun(
            payload: prepared.payload,
            manifest: prepared.manifest,
            negotiatedProtocolMinor: responder.negotiatedProtocolMinor
          ))
      } catch {
        try? responder.rejectHandlerFailure()
      }
    }
  }

  private func handleApplyReview(
    _ request: Diskplan_V1_PrepareApplyReviewRequest,
    responder: RuntimeBusinessResponder
  ) throws {
    guard let executionBackend else {
      try responder.send(
        try .rejected(
          code: .businessUnsupported,
          summary: "runtime execution backend is not installed"
        ))
      return
    }
    guard
      let context = executionContext(
        projectionID: request.projectionID,
        overlayID: request.overlayID,
        overlayRevision: request.overlayRevision,
        overlaySHA256: request.overlaySha256,
        negotiatedProtocolMinor: responder.negotiatedProtocolMinor
      )
    else {
      try responder.send(
        try .rejected(code: .staleBinding, summary: "apply-review predecessor binding is stale"))
      return
    }
    startTask { [weak self] in
      do {
        let prepared = try await executionBackend.prepareApplyReview(
          context: context,
          lifetimeSeconds: 300
        )
        let sealed = try SealedRuntimeWire.sealApplyReview(
          prepared.projection,
          negotiatedProtocolMinor: responder.negotiatedProtocolMinor
        )
        guard self?.contextIsCurrent(context) == true else {
          try responder.send(
            try .rejected(
              code: .staleBinding,
              summary: "plan or overlay changed during apply-review preparation"
            ))
          return
        }
        try responder.send(
          try .applyReview(
            sealed,
            negotiatedProtocolMinor: responder.negotiatedProtocolMinor
          ))
        self?.installPreparedApplyIfCurrent(
          PreparedApply(
            context: context,
            projection: sealed,
            authority: prepared.authority
          )
        )
      } catch {
        try? responder.rejectHandlerFailure()
      }
    }
  }

  private func handleConfirmApply(
    _ request: Diskplan_V1_ConfirmApplyRequest,
    responder: RuntimeBusinessResponder
  ) throws {
    guard let executionBackend else {
      try responder.send(
        try .rejected(
          code: .businessUnsupported,
          summary: "runtime execution backend is not installed"
        ))
      return
    }
    lock.lock()
    let prepared = preparedApply
    if let prepared,
      request.applyReviewID == prepared.projection.applyReviewID,
      request.reviewBindingSha256 == prepared.projection.reviewBindingSha256,
      Set(request.confirmedForceActionIds.map(\.value))
        == Set(prepared.projection.forceWarningActionIds.map(\.value)),
      request.confirmedForceActionIds.count
        == Set(request.confirmedForceActionIds.map(\.value)).count
    {
      preparedApply = nil
    }
    lock.unlock()
    guard let prepared,
      request.applyReviewID == prepared.projection.applyReviewID,
      request.reviewBindingSha256 == prepared.projection.reviewBindingSha256,
      Set(request.confirmedForceActionIds.map(\.value))
        == Set(prepared.projection.forceWarningActionIds.map(\.value)),
      request.confirmedForceActionIds.count
        == Set(request.confirmedForceActionIds.map(\.value)).count
    else {
      try responder.send(
        try .rejected(
          code: .confirmationMismatch,
          summary: "apply confirmation differs from the prepared single-use review"
        ))
      return
    }

    startTask { [weak self] in
      guard let self else { return }
      do {
        let run = try await executionBackend.startApply(
          authority: prepared.authority,
          confirmation: RuntimeApplyConfirmation(
            review: prepared.projection,
            confirmedForceActionIDs: request.confirmedForceActionIds
          ),
          context: prepared.context
        )
        guard !run.executionID.isEmpty,
          run.executionID.count <= SealedRuntimeWire.maximumOpaqueIdentifierBytes,
          run.applyStarted.executionID.value == run.executionID
        else { throw RuntimeSessionControllerError.staleReceipt }
        try responder.registerExecution(run.executionID)
        var started = run.applyStarted
        started.executionEventIndex = 1
        try installActiveExecution(
          run: run,
          context: prepared.context,
          review: prepared.projection,
          responder: responder,
          started: started
        )

        let remaining = try await run.remainingEvents()
        guard !remaining.isEmpty,
          remaining.dropLast().allSatisfy({ event in
            if case .applyStarted? = event.body { return false }
            if case .cancellationAcknowledged? = event.body { return false }
            if case .applyFinished? = event.body { return false }
            return event.body != nil
          }),
          remaining.last?.applyFinished != nil
        else { throw RuntimeSessionControllerError.staleReceipt }
        try finishExecution(run: run, remaining: remaining)
      } catch {
        failExecution(fallbackResponder: responder)
      }
    }
  }

  private func handleCancelExecution(
    _ request: Diskplan_V1_CancelExecutionRequest,
    responder: RuntimeBusinessResponder
  ) throws {
    lock.lock()
    guard var active = activeExecution,
      active.run.executionID == request.executionID.value,
      active.cancellationResponder == nil
    else {
      lock.unlock()
      try responder.send(
        try .rejected(code: .staleBinding, summary: "execution_id is not active"))
      return
    }
    var acknowledgement = Diskplan_V1_ExecutionCancellationAcknowledgedProjection()
    acknowledgement.reason = "frontend-requested"
    var event = Diskplan_V1_ExecutionStreamEvent()
    event.executionID.value = active.run.executionID
    event.body = .cancellationAcknowledged(acknowledgement)
    event.executionEventIndex = UInt64(active.events.count + 1)
    let prefix = active.events + [event]
    do {
      try active.confirmationResponder.sendExecutionPrefix(prefix)
      try responder.sendExecutionPrefix(prefix)
      active.events = prefix
      active.cancellationResponder = responder
      activeExecution = active
      lock.unlock()
      active.run.cancel()
    } catch {
      lock.unlock()
      throw error
    }
  }

  private func finishExecution(
    run: any RuntimeExecutionRun,
    remaining: [Diskplan_V1_ExecutionStreamEvent]
  ) throws {
    lock.lock()
    guard let active = activeExecution,
      (active.run as AnyObject) === (run as AnyObject)
    else {
      lock.unlock()
      return
    }
    activeExecution = nil
    lock.unlock()
    let events = active.events + remaining
    if let cancellationResponder = active.cancellationResponder {
      try cancellationResponder.finishExecution(events)
    }
    try active.confirmationResponder.finishExecution(events)
  }

  private func failExecution(fallbackResponder: RuntimeBusinessResponder) {
    lock.lock()
    let active = activeExecution
    activeExecution = nil
    lock.unlock()
    if let cancellationResponder = active?.cancellationResponder {
      try? cancellationResponder.rejectHandlerFailure()
    }
    try? (active?.confirmationResponder ?? fallbackResponder).rejectHandlerFailure()
  }

  private func executionContext(
    projectionID: Diskplan_V1_OpaqueIdentifier,
    overlayID: Diskplan_V1_OpaqueIdentifier,
    overlayRevision: UInt64,
    overlaySHA256: Diskplan_V1_Digest256,
    negotiatedProtocolMinor: UInt32
  ) -> RuntimeExecutionPlanContext? {
    lock.lock()
    defer { lock.unlock() }
    guard let live = livePlan,
      let overlay = live.domainOverlay,
      let overlayProjection = live.overlayProjection,
      projectionID == live.manifest.projectionID,
      overlayID == overlayProjection.overlayID,
      overlayRevision == overlayProjection.revision,
      overlaySHA256 == overlayProjection.overlaySha256
    else { return nil }
    return RuntimeExecutionPlanContext(
      plan: live.result.plan,
      overlay: overlay,
      planRecords: live.records,
      planManifest: live.manifest,
      overlayProjection: overlayProjection,
      negotiatedProtocolMinor: negotiatedProtocolMinor
    )
  }

  private func contextIsCurrent(_ context: RuntimeExecutionPlanContext) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return contextIsCurrentUnderLock(context)
  }

  private func contextIsCurrentUnderLock(_ context: RuntimeExecutionPlanContext) -> Bool {
    guard let live = livePlan,
      let overlay = live.domainOverlay,
      let overlayProjection = live.overlayProjection
    else { return false }
    return live.result.plan.planHash == context.plan.planHash
      && overlay.overlayHash == context.overlay.overlayHash
      && live.manifest.projectionID == context.planManifest.projectionID
      && overlayProjection.overlayID == context.overlayProjection.overlayID
      && overlayProjection.revision == context.overlayProjection.revision
      && overlayProjection.overlaySha256 == context.overlayProjection.overlaySha256
  }

  private func installPreparedApplyIfCurrent(_ prepared: PreparedApply) {
    lock.lock()
    defer { lock.unlock() }
    guard contextIsCurrentUnderLock(prepared.context) else { return }
    preparedApply = prepared
  }

  private func installActiveExecution(
    run: any RuntimeExecutionRun,
    context: RuntimeExecutionPlanContext,
    review: Diskplan_V1_ApplyReviewProjection,
    responder: RuntimeBusinessResponder,
    started: Diskplan_V1_ExecutionStreamEvent
  ) throws {
    lock.lock()
    defer { lock.unlock() }
    guard contextIsCurrentUnderLock(context) else {
      throw RuntimeSessionControllerError.staleReceipt
    }
    activeExecution = ActiveExecution(
      run: run,
      context: context,
      review: review,
      confirmationResponder: responder,
      events: [started],
      cancellationResponder: nil
    )
    do {
      try responder.sendExecutionPrefix([started])
    } catch {
      activeExecution = nil
      throw error
    }
  }

  func stopAndWait() {
    lock.lock()
    let run = activeExecution?.run
    lock.unlock()
    run?.cancel()

    taskCondition.lock()
    stopping = true
    let tasks = Array(ownedTasks.values)
    taskCondition.unlock()
    for task in tasks { task.cancel() }

    taskCondition.lock()
    while !ownedTasks.isEmpty { taskCondition.wait() }
    taskCondition.unlock()
  }

  @discardableResult
  private func startTask(
    _ operation: @escaping @Sendable () async -> Void
  ) -> Bool {
    let id = UUID()
    let owner = RuntimeOwnedTask()
    taskCondition.lock()
    guard !stopping else {
      taskCondition.unlock()
      return false
    }
    ownedTasks[id] = owner
    taskCondition.unlock()

    let task = Task { [weak self] in
      await operation()
      self?.taskDidFinish(id)
    }
    owner.install(task)
    return true
  }

  private func taskDidFinish(_ id: UUID) {
    taskCondition.lock()
    ownedTasks.removeValue(forKey: id)
    taskCondition.broadcast()
    taskCondition.unlock()
  }

  private func sendOverlayRejection(
    code: Diskplan_V1_DecisionOverlayRejectCode,
    summary: String,
    actionID: Data? = nil,
    waiverID: Data? = nil,
    currentRevision: UInt64,
    responder: RuntimeBusinessResponder
  ) throws {
    var rejection = Diskplan_V1_DecisionOverlayRejected()
    rejection.code = code
    rejection.summary = summary
    rejection.currentRevision = currentRevision
    if let actionID { rejection.actionID.value = actionID }
    if let waiverID { rejection.waiverID.value = waiverID }
    try responder.send(try .decisionOverlayRejected(rejection))
  }

  private func incrementedRevision(_ revision: UInt64) throws -> UInt64 {
    let (next, overflow) = revision.addingReportingOverflow(1)
    guard !overflow else {
      throw RuntimeOverlayEditRejection(
        code: .limitExceeded,
        summary: "overlay revision space is exhausted"
      )
    }
    return next
  }

  func hasFinalizedReceiptForTesting(
    scanSessionID: Data,
    checkpointID: Data
  ) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return finalizedReceipts[scanSessionID]?.checkpointID == checkpointID
  }

  func finalizedReceiptCountForTesting() -> Int {
    lock.lock()
    defer { lock.unlock() }
    return finalizedReceipts.count
  }

  func preparedApplyReviewIDForTesting() -> Data? {
    lock.lock()
    defer { lock.unlock() }
    return preparedApply?.projection.applyReviewID.value
  }

  func activeExecutionIDForTesting() -> Data? {
    lock.lock()
    defer { lock.unlock() }
    return activeExecution?.run.executionID
  }
}

private final class RuntimeOwnedTask: @unchecked Sendable {
  private let lock = NSLock()
  private var task: Task<Void, Never>?
  private var cancellationRequested = false

  func install(_ task: Task<Void, Never>) {
    lock.lock()
    self.task = task
    let shouldCancel = cancellationRequested
    lock.unlock()
    if shouldCancel { task.cancel() }
  }

  func cancel() {
    lock.lock()
    cancellationRequested = true
    let task = task
    lock.unlock()
    task?.cancel()
  }
}

func runtimeDigest(domain: String, fields: [Data]) -> Data {
  var bytes = Data(domain.utf8)
  for field in fields {
    var length = UInt64(field.count).bigEndian
    withUnsafeBytes(of: &length) { bytes.append(contentsOf: $0) }
    bytes.append(field)
  }
  return Data(SHA256.hash(data: bytes))
}
