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
    let releaseSetIDByAllocationGroup: [Data: Data]
    let metadata: PlanProjectionWireMetadata
    let manifest: Diskplan_V1_PlanProjectionManifest
    var domainOverlay: DecisionOverlay?
    var overlayProjection: Diskplan_V1_DecisionOverlayAcknowledged?
    var overlayRevision: UInt64
  }

  private struct PreparedApply {
    let context: RuntimeExecutionPlanContext
    let projection: Diskplan_V1_ApplyReviewProjection
    let authority: RuntimeApplyAuthorityBox
  }

  private struct ActiveExecution {
    let run: RuntimeExecutionRunHandle
    let context: RuntimeExecutionPlanContext
    let review: Diskplan_V1_ApplyReviewProjection
    let confirmationResponder: RuntimeBusinessResponder
    var events: [Diskplan_V1_ExecutionStreamEvent]
    var cancellationResponder: RuntimeBusinessResponder?
    var prefixSent: Bool
    var finishing: Bool
  }

  private final class RuntimeApplyAuthorityBox: @unchecked Sendable {
    private enum State {
      case fresh(RuntimePreparedApplyAttempt)
      case claimed
      case invalidated
    }

    private let lock = NSLock()
    private var state: State

    init(_ attempt: RuntimePreparedApplyAttempt) {
      state = .fresh(attempt)
    }

    func claim() -> RuntimePreparedApplyAttempt? {
      lock.lock()
      defer { lock.unlock() }
      guard case .fresh(let attempt) = state else { return nil }
      state = .claimed
      return attempt
    }

    func invalidate() {
      lock.lock()
      if case .fresh = state { state = .invalidated }
      lock.unlock()
    }
  }

  private final class PreparedApplyPublication: @unchecked Sendable {
    let candidate: PreparedApply
    var previous: PreparedApply?

    init(_ candidate: PreparedApply) {
      self.candidate = candidate
    }
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

  public init() {
    executionBackend = nil
  }

  package init(executionBackend: any RuntimeExecutionBackend) {
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
    let projection = try RuntimePlanDomainProjector.project(
      result,
      negotiatedProtocolMinor: responder.negotiatedProtocolMinor
    )
    let records = projection.records
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
      releaseSetIDByAllocationGroup: projection.releaseSetIDByAllocationGroup,
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
      } catch RuntimeExecutionBackendFailure.revalidationFailed {
        try? responder.send(
          try .rejected(
            code: .revalidationFailed,
            summary: "current evidence no longer matches the prepared plan"
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
        let authority = RuntimeApplyAuthorityBox(prepared.attempt)
        let candidate = PreparedApply(
          context: context,
          projection: sealed,
          authority: authority
        )
        let publication = PreparedApplyPublication(candidate)
        let installed = try responder.sendApplyReview(
          try .applyReview(
            sealed,
            negotiatedProtocolMinor: responder.negotiatedProtocolMinor
          ),
          install: { self?.installPreparedApplyIfCurrent(publication) == true },
          rollback: { self?.rollbackPreparedApply(publication) }
        )
        guard installed else {
          authority.invalidate()
          try responder.send(
            try .rejected(
              code: .staleBinding,
              summary: "plan or overlay changed during apply-review publication"
            ))
          return
        }
        publication.previous?.authority.invalidate()
      } catch RuntimeExecutionBackendFailure.revalidationFailed {
        try? responder.send(
          try .rejected(
            code: .revalidationFailed,
            summary: "current evidence no longer matches the prepared plan"
          ))
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
    guard let (prepared, attempt) = claimPreparedApply(request)
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
        let launch = try await attempt.start(
          confirmation: RuntimeApplyConfirmation(
            review: prepared.projection,
            confirmedForceActionIDs: request.confirmedForceActionIds
          ),
          context: prepared.context
        )
        guard case .started(let run) = launch else {
          if case .startFailed(let terminal) = launch {
            do {
              try responder.finishApplyStartFailure(terminal)
            } catch {
              try? responder.abortExecutionStreamWithoutEmission()
            }
          }
          return
        }
        var started = run.applyStarted
        started.executionEventIndex = 1
        guard
          installActiveExecution(
            run: run,
            context: prepared.context,
            review: prepared.projection,
            responder: responder,
            started: started
          )
        else {
          run.cancel()
          _ = await run.awaitTail()
          try? responder.rejectHandlerFailure()
          return
        }
        await driveStartedExecution(run: run, fallbackResponder: responder)
      } catch {
        try? responder.rejectHandlerFailure()
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
      active.prefixSent = true
      activeExecution = active
      lock.unlock()
      active.run.cancel()
    } catch {
      lock.unlock()
      throw error
    }
  }

  private func driveStartedExecution(
    run: RuntimeExecutionRunHandle,
    fallbackResponder: RuntimeBusinessResponder
  ) async {
    do {
      guard contextIsCurrentForActiveRun(run) else {
        throw RuntimeSessionControllerError.staleReceipt
      }
      try fallbackResponder.registerExecution(run.executionID)
      try fallbackResponder.sendExecutionPrefix([run.applyStarted])
      markExecutionPrefixSent(run)
    } catch {
      await abortStartedExecutionBeforePrefix(run, fallbackResponder: fallbackResponder)
      return
    }

    let outcome = await run.awaitTail()
    guard case .sealed(let tail) = outcome else {
      run.cancel()
      _ = await run.awaitTail()
      let cancellationResponder = cancellationResponder(for: run)
      clearActiveExecution(run)
      try? fallbackResponder.abortExecutionStreamWithoutEmission(
        mirroredTo: cancellationResponder
      )
      return
    }
    while !Task.isCancelled {
      do {
        try finishExecution(run: run, tail: tail)
        return
      } catch RuntimeTerminalCommitError.pendingCancellation {
        await Task.yield()
      } catch {
        run.cancel()
        _ = await run.awaitTail()
        return
      }
    }
    run.cancel()
    _ = await run.awaitTail()
  }

  private func abortStartedExecutionBeforePrefix(
    _ run: RuntimeExecutionRunHandle,
    fallbackResponder: RuntimeBusinessResponder
  ) async {
    run.cancel()
    _ = await run.awaitTail()
    clearActiveExecution(run)
    try? fallbackResponder.rejectHandlerFailure()
  }

  private func clearActiveExecution(_ run: RuntimeExecutionRunHandle) {
    lock.lock()
    if activeExecution?.run === run { activeExecution = nil }
    lock.unlock()
  }

  private func cancellationResponder(
    for run: RuntimeExecutionRunHandle
  ) -> RuntimeBusinessResponder? {
    lock.lock()
    defer { lock.unlock() }
    guard activeExecution?.run === run else { return nil }
    return activeExecution?.cancellationResponder
  }

  private func finishExecution(
    run: RuntimeExecutionRunHandle,
    tail: RuntimeExecutionTail
  ) throws {
    lock.lock()
    guard var active = activeExecution, active.run === run
    else {
      lock.unlock()
      return
    }
    active.finishing = true
    activeExecution = active
    lock.unlock()
    let events = active.events + tail.events
    try active.confirmationResponder.finishExecution(
      events,
      mirroredTo: active.cancellationResponder
    )
    lock.lock()
    if activeExecution?.run === run { activeExecution = nil }
    lock.unlock()
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
      releaseSetIDByAllocationGroup: live.releaseSetIDByAllocationGroup,
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

  private func claimPreparedApply(
    _ request: Diskplan_V1_ConfirmApplyRequest
  ) -> (PreparedApply, RuntimePreparedApplyAttempt)? {
    lock.lock()
    defer { lock.unlock() }
    guard let prepared = preparedApply,
      request.applyReviewID == prepared.projection.applyReviewID,
      request.reviewBindingSha256 == prepared.projection.reviewBindingSha256,
      Set(request.confirmedForceActionIds.map(\.value))
        == Set(prepared.projection.forceWarningActionIds.map(\.value)),
      request.confirmedForceActionIds.count
        == Set(request.confirmedForceActionIds.map(\.value)).count,
      let attempt = prepared.authority.claim()
    else { return nil }
    preparedApply = nil
    return (prepared, attempt)
  }

  private func installPreparedApplyIfCurrent(_ publication: PreparedApplyPublication) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard contextIsCurrentUnderLock(publication.candidate.context) else { return false }
    publication.previous = preparedApply
    preparedApply = publication.candidate
    return true
  }

  private func rollbackPreparedApply(_ publication: PreparedApplyPublication) {
    lock.lock()
    if preparedApply?.authority === publication.candidate.authority {
      preparedApply = publication.previous
    }
    lock.unlock()
    publication.candidate.authority.invalidate()
  }

  private func installActiveExecution(
    run: RuntimeExecutionRunHandle,
    context: RuntimeExecutionPlanContext,
    review: Diskplan_V1_ApplyReviewProjection,
    responder: RuntimeBusinessResponder,
    started: Diskplan_V1_ExecutionStreamEvent
  ) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard !stopping, activeExecution == nil else { return false }
    activeExecution = ActiveExecution(
      run: run,
      context: context,
      review: review,
      confirmationResponder: responder,
      events: [started],
      cancellationResponder: nil,
      prefixSent: false,
      finishing: false
    )
    return true
  }

  private func contextIsCurrentForActiveRun(_ run: RuntimeExecutionRunHandle) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard let active = activeExecution, active.run === run else { return false }
    return contextIsCurrentUnderLock(active.context)
  }

  private func markExecutionPrefixSent(_ run: RuntimeExecutionRunHandle) {
    lock.lock()
    if var active = activeExecution, active.run === run {
      active.prefixSent = true
      activeExecution = active
    }
    lock.unlock()
  }

  func stopAndWait() {
    lock.lock()
    stopping = true
    let run = activeExecution?.run
    taskCondition.lock()
    let tasks = Array(ownedTasks.values)
    taskCondition.unlock()
    lock.unlock()

    run?.cancel()
    for task in tasks { task.cancel() }

    taskCondition.lock()
    while !ownedTasks.isEmpty { taskCondition.wait() }
    taskCondition.unlock()

    lock.lock()
    activeExecution = nil
    lock.unlock()
  }

  @discardableResult
  private func startTask(
    _ operation: @escaping @Sendable () async -> Void
  ) -> Bool {
    let id = UUID()
    let owner = RuntimeOwnedTask()
    lock.lock()
    guard !stopping else {
      lock.unlock()
      return false
    }
    taskCondition.lock()
    ownedTasks[id] = owner
    taskCondition.unlock()
    lock.unlock()

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

  func isStoppingForTesting() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return stopping
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
