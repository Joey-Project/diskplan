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
public final class RuntimeSessionController: RuntimeScanAuthority, @unchecked Sendable {
  public let supportedCapabilities: Set<String> = [
    "decision-overlay-v1",
    "plan-projection-v1",
  ]

  private struct LivePlan {
    let receipt: RuntimeFinalizedScanReceipt
    let result: RuntimePolicyAuthorityResult
    let records: [Diskplan_V1_PlanProjectionRecord]
    let metadata: PlanProjectionWireMetadata
    let manifest: Diskplan_V1_PlanProjectionManifest
    var domainOverlay: DecisionOverlay?
    var overlayRevision: UInt64
  }

  private let lock = NSLock()
  private var finalizedReceipts: [Data: RuntimeFinalizedScanReceipt] = [:]
  private var livePlan: LivePlan?

  public init() {}

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
    case .prepareDryRun, .prepareApplyReview, .confirmApply, .cancelExecution:
      try responder.send(
        try .rejected(
          code: .businessUnsupported,
          summary: "this runtime slice does not implement revalidation or execution"
        ))
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
    let records = try RuntimePlanDomainProjector.project(result)
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
    let wire = try PlanProjectionWireEncoder.encode(records: records, metadata: metadata)
    let planBuildID = runtimeDigest(
      domain: "diskplan/plan-build/v1\0",
      fields: [receipt.scanSessionID, receipt.checkpointID, result.plan.planHash.bytes]
    )
    try responder.send(
      try .plan(
        planBuildID: planBuildID,
        records: records,
        metadata: metadata
      ))

    lock.lock()
    livePlan = LivePlan(
      receipt: receipt,
      result: result,
      records: records,
      metadata: metadata,
      manifest: wire.manifest,
      domainOverlay: nil,
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
      live.overlayRevision = nextRevision
      lock.lock()
      self.livePlan = live
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
