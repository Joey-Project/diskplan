import CryptoKit
import DiskplanCore
import DiskplanProto
import Foundation

package enum SealedRuntimeWireError: Error, Equatable {
  case invalid(field: String)
  case countExceeded(field: String, actual: UInt64, maximum: UInt64)
  case encodedBytesExceeded(actual: UInt64, maximum: UInt64)
  case integerOverflow(field: String)
}

/// Transport-only sealing for engine-authored dry-run, apply-review, and
/// execution projections. This layer validates closed wire structure and
/// computes transport digests; it never derives policy or adapter behavior.
package enum SealedRuntimeWire {
  package static let manifestVersion: UInt32 = 1
  package static let maximumActionCount: UInt32 = 100_000
  package static let maximumFindingCount: UInt32 = 1_000_000
  package static let maximumProjectionBytes: UInt32 = 12 * 1_024 * 1_024
  package static let maximumOverlayWaiverCount: UInt32 = 100_000
  package static let maximumOverlayNoteCount: UInt32 = 10_000
  package static let maximumOverlayNoteBytes: UInt32 = 1 * 1_024 * 1_024
  package static let maximumExecutionEventCount: UInt64 = 1_000_000
  package static let maximumExecutionBytes: UInt64 = 768 * 1_024 * 1_024
  package static let maximumRuntimeSealedEmissionBytes: UInt64 =
    maximumExecutionBytes + 128 * 1_024 * 1_024
  package static let maximumRuntimeFramedEmissionBytes: UInt64 =
    maximumRuntimeSealedEmissionBytes + maximumExecutionEventCount * 512
  package static let maximumOpaqueIdentifierBytes = 256

  package static func requireSupportedProtocolMinor(_ minor: UInt32) throws {
    guard minor == protocol14Minor || minor == protocol15Minor else {
      throw SealedRuntimeWireError.invalid(field: "negotiated protocol minor")
    }
  }

  private static let dryRunPayloadDomain = Data("diskplan/dry-run-projection-payload/v1\0".utf8)
  private static let dryRunFinalDomain = Data("diskplan/dry-run-projection-final/v1\0".utf8)
  private static let applyReviewDomain = Data("diskplan/apply-review-projection/v1\0".utf8)
  private static let executionRecordDomain = Data("diskplan/execution-record/v1\0".utf8)
  private static let revalidationDomain = Data("diskplan/revalidation-projection/v1\0".utf8)
  private static let overlayProjectionDomain = Data(
    "diskplan/decision-overlay-projection/v1\0".utf8
  )

  package static func sealDecisionOverlayAcknowledged(
    _ base: Diskplan_V1_DecisionOverlayAcknowledged
  ) throws -> Diskplan_V1_DecisionOverlayAcknowledged {
    guard base.maximumSelectedActions == maximumActionCount,
      base.maximumWaiverConsents == maximumOverlayWaiverCount,
      base.maximumUserNotes == maximumOverlayNoteCount,
      base.maximumNoteBytes == maximumOverlayNoteBytes,
      base.maximumEncodedBytes == maximumProjectionBytes,
      base.selectedActionCount == UInt64(base.selectedActionIds.count),
      base.selectedActionIds.count <= Int(maximumActionCount),
      base.acknowledgedWaivers.count <= Int(maximumOverlayWaiverCount),
      base.userNotes.count <= Int(maximumOverlayNoteCount)
    else {
      throw SealedRuntimeWireError.invalid(field: "decision overlay budget")
    }
    try requireNonempty(base.projectionID.value, field: "projection_id")
    try requireNonempty(base.overlayID.value, field: "overlay_id")
    try requireDigest(base.overlaySha256.value, field: "overlay_sha256")
    try requireDigest(base.planID.value, field: "plan_id")
    try requireDigest(base.planSha256.value, field: "plan_sha256")
    try requireDigest(base.evidenceID.value, field: "evidence_id")
    try requireDigest(base.evidenceSha256.value, field: "evidence_sha256")
    guard base.planID.value == base.planSha256.value,
      base.evidenceID.value == base.evidenceSha256.value
    else {
      throw SealedRuntimeWireError.invalid(field: "overlay plan/evidence binding")
    }
    try requireScanBinding(
      sessionID: base.scanSessionID.value,
      checkpointID: base.scanCheckpointID.value,
      checkpointEvidenceSHA256: base.scanCheckpointEvidenceSha256.value,
      finalEvidenceSHA256: base.evidenceSha256.value
    )
    let selected = base.selectedActionIds.map(\.value)
    try requireUniqueDigests(selected, field: "selected action_id")
    let selectedSet = Set(selected)
    let force = base.forceWarningActionIds.map(\.value)
    try requireUniqueDigests(force, field: "force warning action_id")
    guard force.allSatisfy(selectedSet.contains) else {
      throw SealedRuntimeWireError.invalid(field: "force warning selection")
    }
    var waiverPairs = Set<Data>()
    for waiver in base.acknowledgedWaivers {
      try requireDigest(waiver.actionID.value, field: "waiver action_id")
      try requireNonempty(waiver.waiverID.value, field: "waiver_id")
      try requireDigest(waiver.consentSha256.value, field: "consent_sha256")
      guard selectedSet.contains(waiver.actionID.value) else {
        throw SealedRuntimeWireError.invalid(field: "waiver action selection")
      }
      var pair = Data()
      appendLengthPrefixed(waiver.actionID.value, to: &pair)
      appendLengthPrefixed(waiver.waiverID.value, to: &pair)
      guard waiverPairs.insert(pair).inserted else {
        throw SealedRuntimeWireError.invalid(field: "duplicate acknowledged waiver")
      }
    }
    let noteBytes = try base.userNotes.reduce(UInt64(0)) {
      try adding($0, UInt64($1.utf8.count), field: "overlay note bytes")
    }
    try requireMaximumBytes(noteBytes, maximum: UInt64(maximumOverlayNoteBytes))

    var overlay = base
    overlay.clearProjectionSha256()
    let canonical = try overlay.serializedData()
    try requireMaximumBytes(UInt64(canonical.count), maximum: UInt64(maximumProjectionBytes))
    overlay.projectionSha256 = digestMessage(digest(overlayProjectionDomain + canonical))
    try requireMaximumBytes(
      UInt64(try overlay.serializedData().count),
      maximum: UInt64(maximumProjectionBytes)
    )
    return overlay
  }

  /// Seals an overlay only after proving that its selection and waiver consent
  /// exactly match the authoritative plan records. The frontend cannot promote
  /// a report-only action or synthesize a partial waiver set.
  package static func sealDecisionOverlayAcknowledged(
    _ base: Diskplan_V1_DecisionOverlayAcknowledged,
    authoritativePlanRecords: [Diskplan_V1_PlanProjectionRecord]
  ) throws -> Diskplan_V1_DecisionOverlayAcknowledged {
    let sealed = try sealDecisionOverlayAcknowledged(base)
    var actions: [Data: Diskplan_V1_PlanActionProjection] = [:]
    for record in authoritativePlanRecords {
      guard case .action(let action)? = record.body else { continue }
      guard actions.updateValue(action, forKey: action.actionID.value) == nil else {
        throw SealedRuntimeWireError.invalid(field: "duplicate authoritative action_id")
      }
    }
    let selected = Set(sealed.selectedActionIds.map(\.value))
    guard selected.allSatisfy({ actions[$0] != nil }) else {
      throw SealedRuntimeWireError.invalid(field: "selected action_id")
    }
    var acknowledgedByAction: [Data: Set<Data>] = [:]
    for waiver in sealed.acknowledgedWaivers {
      acknowledgedByAction[waiver.actionID.value, default: []].insert(waiver.waiverID.value)
    }
    for actionID in selected {
      guard let action = actions[actionID] else {
        throw SealedRuntimeWireError.invalid(field: "selected action_id")
      }
      let required = Set(action.requiredWaivers.map { $0.waiverID.value })
      let acknowledged = acknowledgedByAction.removeValue(forKey: actionID) ?? []
      switch action.stageability {
      case .stageable where required.isEmpty && acknowledged.isEmpty:
        break
      case .requiresWaivers where !required.isEmpty && acknowledged == required:
        break
      case .notStageable:
        throw SealedRuntimeWireError.invalid(field: "not-stageable selected action")
      case .unspecified, .stageable, .requiresWaivers, .UNRECOGNIZED:
        throw SealedRuntimeWireError.invalid(field: "selected action waiver set")
      }
    }
    guard acknowledgedByAction.isEmpty else {
      throw SealedRuntimeWireError.invalid(field: "unselected action waiver")
    }
    let expectedForceWarnings = Set(
      selected.filter { actions[$0]?.requiresForce == true }
    )
    guard Set(sealed.forceWarningActionIds.map(\.value)) == expectedForceWarnings else {
      throw SealedRuntimeWireError.invalid(field: "force warning authoritative set")
    }
    return sealed
  }

  package static func sealDryRun(
    payload: Diskplan_V1_DryRunProjectionPayload,
    manifest base: Diskplan_V1_DryRunProjectionManifest,
    negotiatedProtocolMinor: UInt32 = protocolMinor
  ) throws -> Diskplan_V1_DryRunProjection {
    try requireSupportedProtocolMinor(negotiatedProtocolMinor)
    try requireNonempty(base.projectionID.value, field: "projection_id")
    try requireDigest(base.planSha256.value, field: "plan_sha256")
    try requireDigest(base.overlaySha256.value, field: "overlay_sha256")
    try requireEpoch(base.epoch)
    try requireNonempty(base.dryRunID.value, field: "dry_run_id")
    try requireNonempty(base.overlayID.value, field: "overlay_id")
    try requireDigest(base.planID.value, field: "plan_id")
    try requireDigest(base.evidenceID.value, field: "evidence_id")
    try requireDigest(base.evidenceSha256.value, field: "evidence_sha256")
    try requireScanBinding(
      sessionID: base.scanSessionID.value,
      checkpointID: base.scanCheckpointID.value,
      checkpointEvidenceSHA256: base.scanCheckpointEvidenceSha256.value,
      finalEvidenceSHA256: base.evidenceSha256.value
    )
    if base.current {
      try requireDigest(base.currentBindingSha256.value, field: "current_binding_sha256")
    } else if base.hasCurrentBindingSha256 {
      throw SealedRuntimeWireError.invalid(field: "non-current dry-run current_binding_sha256")
    }
    guard base.planID.value == base.planSha256.value,
      base.evidenceID.value == base.evidenceSha256.value
    else {
      throw SealedRuntimeWireError.invalid(field: "dry-run plan/evidence binding")
    }

    let summary = try validateRevalidationProjection(
      actionOutcomes: payload.revalidation.actionOutcomes,
      globalFindings: payload.revalidation.globalFindings,
      actionIDs: payload.actions.map { $0.actionID.value },
      requireCompleteOutcomes: base.current
    )
    for action in payload.actions {
      try requireDigest(action.actionID.value, field: "dry-run action_id")
      try requirePreview(
        action.executionPreview,
        negotiatedProtocolMinor: negotiatedProtocolMinor
      )
    }
    guard base.current == summary.current else {
      throw SealedRuntimeWireError.invalid(field: "dry-run current")
    }
    guard base.selectedActionCount == summary.actionCount else {
      throw SealedRuntimeWireError.invalid(field: "dry-run selected_action_count")
    }

    let encodedPayload = try payload.serializedData()
    try requireMaximumBytes(UInt64(encodedPayload.count), maximum: UInt64(maximumProjectionBytes))
    let payloadDigest = digest(dryRunPayloadDomain + encodedPayload)
    let revalidationDigest = digest(
      revalidationDomain + (try payload.revalidation.serializedData())
    )

    var manifest = base
    manifest.manifestVersion = manifestVersion
    manifest.actionCount = summary.actionCount
    manifest.findingCount = summary.findingCount
    manifest.maximumActionCount = maximumActionCount
    manifest.maximumFindingCount = maximumFindingCount
    manifest.maximumProjectionPayloadBytes = maximumProjectionBytes
    manifest.payloadSha256 = digestMessage(payloadDigest)
    manifest.revalidationSha256 = digestMessage(revalidationDigest)
    manifest.clearProjectionSha256()
    manifest.projectionSha256 = digestMessage(dryRunFinalDigest(manifest))

    var projection = Diskplan_V1_DryRunProjection()
    projection.canonicalProjectionPayload = encodedPayload
    projection.manifest = manifest
    return projection
  }

  package static func sealApplyReview(
    _ base: Diskplan_V1_ApplyReviewProjection,
    negotiatedProtocolMinor: UInt32 = protocolMinor
  ) throws -> Diskplan_V1_ApplyReviewProjection {
    try requireSupportedProtocolMinor(negotiatedProtocolMinor)
    try requireNonempty(base.applyReviewID.value, field: "apply_review_id")
    try requireNonempty(base.projectionID.value, field: "projection_id")
    try requireDigest(base.planSha256.value, field: "plan_sha256")
    try requireDigest(base.overlaySha256.value, field: "overlay_sha256")
    try requireDigest(base.reviewBindingSha256.value, field: "review_binding_sha256")
    try requireNonempty(base.overlayID.value, field: "overlay_id")
    try requireDigest(base.planID.value, field: "plan_id")
    try requireDigest(base.evidenceID.value, field: "evidence_id")
    try requireDigest(base.evidenceSha256.value, field: "evidence_sha256")
    try requireScanBinding(
      sessionID: base.scanSessionID.value,
      checkpointID: base.scanCheckpointID.value,
      checkpointEvidenceSHA256: base.scanCheckpointEvidenceSha256.value,
      finalEvidenceSHA256: base.evidenceSha256.value
    )
    try requireDigest(base.currentBindingSha256.value, field: "current_binding_sha256")
    guard base.planID.value == base.planSha256.value,
      base.evidenceID.value == base.evidenceSha256.value
    else {
      throw SealedRuntimeWireError.invalid(field: "apply-review plan/evidence binding")
    }
    try requireEpoch(base.epoch)

    let actionIDs = base.actions.map { $0.actionID.value }
    let summary = try validateRevalidationProjection(
      actionOutcomes: base.revalidation.actionOutcomes,
      globalFindings: base.revalidation.globalFindings,
      actionIDs: actionIDs,
      requireCompleteOutcomes: true
    )
    for action in base.actions {
      try requireDigest(action.actionID.value, field: "apply-review action_id")
      try requirePreview(
        action.executionPreview,
        negotiatedProtocolMinor: negotiatedProtocolMinor
      )
    }
    let expectedForceIDs = base.actions.filter(\.requiresForce).map { $0.actionID.value }.sorted {
      $0.lexicographicallyPrecedes($1)
    }
    let actualForceIDs = base.forceWarningActionIds.map(\.value)
    guard actualForceIDs == expectedForceIDs else {
      throw SealedRuntimeWireError.invalid(field: "force_warning_action_ids")
    }
    guard base.selectedActionCount == summary.actionCount else {
      throw SealedRuntimeWireError.invalid(field: "apply-review selected_action_count")
    }

    var projection = base
    projection.maximumActionCount = maximumActionCount
    projection.maximumFindingCount = maximumFindingCount
    projection.maximumEncodedBytes = maximumProjectionBytes
    projection.revalidationSha256 = digestMessage(
      digest(revalidationDomain + (try projection.revalidation.serializedData()))
    )
    projection.clearProjectionSha256()
    let canonical = try projection.serializedData()
    try requireMaximumBytes(UInt64(canonical.count), maximum: UInt64(maximumProjectionBytes))
    projection.projectionSha256 = digestMessage(digest(applyReviewDomain + canonical))
    try requireMaximumBytes(
      UInt64(try projection.serializedData().count),
      maximum: UInt64(maximumProjectionBytes)
    )
    return projection
  }

  package static func sealExecutionStream(
    _ baseEvents: [Diskplan_V1_ExecutionStreamEvent],
    requiredForceWarningActionIDs: [Diskplan_V1_OpaqueIdentifier],
    negotiatedProtocolMinor: UInt32 = protocolMinor
  ) throws -> [Diskplan_V1_ExecutionStreamEvent] {
    try requireSupportedProtocolMinor(negotiatedProtocolMinor)
    guard !baseEvents.isEmpty else {
      throw SealedRuntimeWireError.invalid(field: "execution events")
    }
    try requireCount(
      UInt64(baseEvents.count),
      maximum: maximumExecutionEventCount,
      field: "execution event_count"
    )
    let executionID = baseEvents[0].executionID.value
    try requireNonempty(executionID, field: "execution_id")

    var events = baseEvents
    for index in events.indices {
      guard events[index].executionID.value == executionID else {
        throw SealedRuntimeWireError.invalid(field: "execution_id")
      }
      events[index].executionEventIndex = UInt64(index + 1)
      guard events[index].body != nil else {
        throw SealedRuntimeWireError.invalid(field: "execution event body")
      }
      if index != events.index(before: events.endIndex),
        case .applyFinished? = events[index].body
      {
        throw SealedRuntimeWireError.invalid(field: "nonterminal apply_finished")
      }
    }
    guard case .applyFinished(var terminal)? = events[events.index(before: events.endIndex)].body
    else {
      throw SealedRuntimeWireError.invalid(field: "missing apply_finished")
    }
    try requireNonempty(terminal.applyReviewID.value, field: "terminal apply_review_id")
    try requireDigest(
      terminal.reviewBindingSha256.value,
      field: "terminal review_binding_sha256"
    )

    let summary = try executionSummary(
      events.dropLast(),
      negotiatedProtocolMinor: negotiatedProtocolMinor
    )
    let requiredForceWarnings = requiredForceWarningActionIDs.map(\.value)
    try requireUniqueDigests(requiredForceWarnings, field: "review force warning action_id")
    let observedForceWarnings = events.dropLast().compactMap { event -> Data? in
      guard case .forceRequiredWarning(let warning)? = event.body else { return nil }
      return warning.actionID.value
    }
    try requireUniqueDigests(observedForceWarnings, field: "execution force warning action_id")
    guard Set(observedForceWarnings) == Set(requiredForceWarnings) else {
      throw SealedRuntimeWireError.invalid(field: "execution force warning set")
    }
    let applyStartedCount = events.dropLast().reduce(0) {
      if case .applyStarted? = $1.body { $0 + 1 } else { $0 }
    }
    if terminal.startFailure != .unspecified {
      guard validApplyStartFailure(terminal.startFailure), events.count == 1,
        applyStartedCount == 0,
        summary.unitCount == 0, summary.auditFailureCount == 0
      else {
        throw SealedRuntimeWireError.invalid(field: "apply start failure stream")
      }
    } else {
      guard applyStartedCount == 1,
        case .applyStarted(let started)? = events.first?.body
      else {
        throw SealedRuntimeWireError.invalid(field: "missing apply_started")
      }
      try requireApplyStarted(started)
      guard terminal.applyReviewID == started.applyReviewID,
        terminal.reviewBindingSha256 == started.reviewBindingSha256
      else {
        throw SealedRuntimeWireError.invalid(field: "terminal apply authority")
      }
    }

    terminal.unitCount = summary.unitCount
    terminal.succeededUnitCount = summary.succeeded
    terminal.partialUnitCount = summary.partial
    terminal.failedUnitCount = summary.failed
    terminal.cancelledUnitCount = summary.cancelled
    terminal.skippedUnitCount = summary.skipped
    terminal.auditFailureCount = summary.auditFailureCount
    terminal.jitRejectedUnitCount = summary.jitRejected
    terminal.expiredUnitCount = summary.expired
    terminal.supersededUnitCount = summary.superseded
    terminal.eventCount = UInt64(events.count)
    terminal.maximumEventCount = maximumExecutionEventCount
    terminal.maximumEncodedEventBytes = maximumExecutionBytes
    terminal.clearExecutionRecordSha256()

    let terminalIndex = events.index(before: events.endIndex)
    events[terminalIndex].body = .applyFinished(terminal)
    terminal.encodedEventBytes = try stableExecutionByteCount(events)
    events[terminalIndex].body = .applyFinished(terminal)
    let canonical = try canonicalExecutionBytes(events)
    guard UInt64(canonical.count) == terminal.encodedEventBytes else {
      throw SealedRuntimeWireError.invalid(field: "execution encoded_event_bytes")
    }
    try requireMaximumBytes(UInt64(canonical.count), maximum: maximumExecutionBytes)
    terminal.executionRecordSha256 = digestMessage(digest(executionRecordDomain + canonical))
    events[terminalIndex].body = .applyFinished(terminal)
    return events
  }

  private struct RevalidationSummary {
    let actionCount: UInt64
    let findingCount: UInt64
    let current: Bool
  }

  private static func validateRevalidationProjection(
    actionOutcomes: [Diskplan_V1_ActionRevalidationProjection],
    globalFindings: [Diskplan_V1_RevalidationFindingProjection],
    actionIDs: [Data],
    requireCompleteOutcomes: Bool
  ) throws -> RevalidationSummary {
    try requireUniqueDigests(actionIDs, field: "selected action_id")
    let outcomeIDs = actionOutcomes.map { $0.actionID.value }
    try requireUniqueDigests(outcomeIDs, field: "action outcome action_id")
    let actionIDSet = Set(actionIDs)
    let outcomeIDSet = Set(outcomeIDs)
    let findingIDs =
      globalFindings.map { $0.findingID.value }
      + actionOutcomes.flatMap { $0.findings.map { $0.findingID.value } }
    guard findingIDs.allSatisfy({ !$0.isEmpty }), Set(findingIDs).count == findingIDs.count else {
      throw SealedRuntimeWireError.invalid(field: "finding_id")
    }
    guard outcomeIDSet.isSubset(of: actionIDSet),
      !requireCompleteOutcomes || outcomeIDSet == actionIDSet
    else {
      throw SealedRuntimeWireError.invalid(field: "action outcome membership")
    }
    var findingCount = UInt64(globalFindings.count)
    for finding in globalFindings {
      try requireFinding(finding, expectedActionID: nil)
    }
    for outcome in actionOutcomes {
      guard outcome.current == outcome.findings.isEmpty else {
        throw SealedRuntimeWireError.invalid(field: "action outcome current")
      }
      findingCount = try adding(
        findingCount,
        UInt64(outcome.findings.count),
        field: "finding_count"
      )
      for finding in outcome.findings {
        try requireFinding(finding, expectedActionID: outcome.actionID.value)
      }
    }
    try requireCount(
      UInt64(actionIDs.count),
      maximum: UInt64(maximumActionCount),
      field: "action_count"
    )
    try requireCount(
      findingCount,
      maximum: UInt64(maximumFindingCount),
      field: "finding_count"
    )
    return RevalidationSummary(
      actionCount: UInt64(actionIDs.count),
      findingCount: findingCount,
      current: outcomeIDSet == actionIDSet && globalFindings.isEmpty
        && actionOutcomes.allSatisfy(\.current)
    )
  }

  private struct ExecutionSummary {
    var unitCount: UInt64 = 0
    var succeeded: UInt64 = 0
    var partial: UInt64 = 0
    var failed: UInt64 = 0
    var cancelled: UInt64 = 0
    var skipped: UInt64 = 0
    var jitRejected: UInt64 = 0
    var expired: UInt64 = 0
    var superseded: UInt64 = 0
    var auditFailureCount: UInt64 = 0
  }

  private static func executionSummary(
    _ events: ArraySlice<Diskplan_V1_ExecutionStreamEvent>,
    negotiatedProtocolMinor: UInt32
  ) throws -> ExecutionSummary {
    var summary = ExecutionSummary()
    var cancellationCount = 0
    for (offset, event) in events.enumerated() {
      switch event.body {
      case .unitFinished(let finished):
        try requireExecutionUnit(finished.unit)
        summary.unitCount = try adding(summary.unitCount, 1, field: "unit_count")
        switch finished.status {
        case .succeeded: summary.succeeded += 1
        case .partiallyFailed: summary.partial += 1
        case .failed: summary.failed += 1
        case .cancelled: summary.cancelled += 1
        case .skippedPrerequisite: summary.skipped += 1
        case .jitRejected: summary.jitRejected += 1
        case .expired: summary.expired += 1
        case .superseded: summary.superseded += 1
        case .unspecified, .UNRECOGNIZED:
          throw SealedRuntimeWireError.invalid(field: "execution unit status")
        }
      case .auditWriteFailed(let failure):
        guard !failure.code.isEmpty else {
          throw SealedRuntimeWireError.invalid(field: "audit failure code")
        }
        summary.auditFailureCount += 1
      case .unitStarted(let started):
        try requireExecutionUnit(started.unit)
      case .unitJitRejected(let rejected):
        try requireExecutionUnit(rejected.unit)
        let revalidation = try validateRevalidationProjection(
          actionOutcomes: rejected.revalidation.actionOutcomes,
          globalFindings: rejected.revalidation.globalFindings,
          actionIDs: rejected.revalidation.actionOutcomes.map { $0.actionID.value },
          requireCompleteOutcomes: true
        )
        guard !revalidation.current else {
          throw SealedRuntimeWireError.invalid(field: "current JIT rejection")
        }
      case .unitSkippedPrerequisite(let skipped):
        try requireExecutionUnit(skipped.unit)
        guard !skipped.blockingPrerequisites.isEmpty else {
          throw SealedRuntimeWireError.invalid(field: "blocking_prerequisites")
        }
        for unit in skipped.blockingPrerequisites { try requireExecutionUnit(unit) }
      case .forceRequiredWarning(let warning):
        try requireDigest(warning.actionID.value, field: "force warning action_id")
        try requirePreview(
          warning.preview,
          negotiatedProtocolMinor: negotiatedProtocolMinor
        )
      case .stepFinished(let step):
        try requireStep(step)
      case .releasePostVerificationFinished(let release):
        try requireNonempty(release.releaseSetID.value, field: "release_set_id")
        try requirePostVerification(release.outcome)
      case .cancellationAcknowledged(let acknowledgement):
        cancellationCount += 1
        guard cancellationCount == 1, !acknowledgement.reason.isEmpty else {
          throw SealedRuntimeWireError.invalid(field: "cancellation reason")
        }
      case .applyStarted where offset != 0:
        throw SealedRuntimeWireError.invalid(field: "duplicate apply_started")
      case .applyStarted, .applyFinished, nil:
        break
      }
    }
    return summary
  }

  private static func stableExecutionByteCount(
    _ events: [Diskplan_V1_ExecutionStreamEvent]
  ) throws -> UInt64 {
    var candidate: UInt64 = 0
    for _ in 0..<10 {
      var adjusted = events
      let terminalIndex = adjusted.index(before: adjusted.endIndex)
      guard case .applyFinished(var terminal)? = adjusted[terminalIndex].body else {
        throw SealedRuntimeWireError.invalid(field: "missing apply_finished")
      }
      terminal.encodedEventBytes = candidate
      terminal.clearExecutionRecordSha256()
      adjusted[terminalIndex].body = .applyFinished(terminal)
      let next = UInt64(try canonicalExecutionBytes(adjusted).count)
      if next == candidate { return next }
      candidate = next
    }
    throw SealedRuntimeWireError.invalid(field: "unstable execution byte count")
  }

  private static func canonicalExecutionBytes(
    _ events: [Diskplan_V1_ExecutionStreamEvent]
  ) throws -> Data {
    var canonical = Data()
    for index in events.indices {
      var event = events[index]
      if index == events.index(before: events.endIndex),
        case .applyFinished(var terminal)? = event.body
      {
        terminal.clearExecutionRecordSha256()
        event.body = .applyFinished(terminal)
      }
      let encoded = try event.serializedData()
      guard let count = UInt32(exactly: encoded.count) else {
        throw SealedRuntimeWireError.integerOverflow(field: "execution event bytes")
      }
      appendBigEndian(count, to: &canonical)
      canonical.append(encoded)
    }
    return canonical
  }

  private static func dryRunFinalDigest(
    _ manifest: Diskplan_V1_DryRunProjectionManifest
  ) -> Data {
    var canonical = dryRunFinalDomain
    appendBigEndian(manifest.manifestVersion, to: &canonical)
    appendLengthPrefixed(manifest.projectionID.value, to: &canonical)
    appendLengthPrefixed(manifest.planSha256.value, to: &canonical)
    appendLengthPrefixed(manifest.overlaySha256.value, to: &canonical)
    appendLengthPrefixed(manifest.epoch.epochID.value, to: &canonical)
    appendBigEndian(manifest.epoch.semanticReferenceTimeSeconds, to: &canonical)
    appendBigEndian(manifest.epoch.issuedAtSeconds, to: &canonical)
    appendBigEndian(manifest.epoch.deadlineSeconds, to: &canonical)
    canonical.append(manifest.current ? 1 : 0)
    appendBigEndian(manifest.actionCount, to: &canonical)
    appendBigEndian(manifest.findingCount, to: &canonical)
    appendBigEndian(manifest.maximumActionCount, to: &canonical)
    appendBigEndian(manifest.maximumFindingCount, to: &canonical)
    appendBigEndian(manifest.maximumProjectionPayloadBytes, to: &canonical)
    appendLengthPrefixed(manifest.payloadSha256.value, to: &canonical)
    appendLengthPrefixed(manifest.dryRunID.value, to: &canonical)
    appendBigEndian(manifest.selectedActionCount, to: &canonical)
    appendLengthPrefixed(manifest.overlayID.value, to: &canonical)
    appendLengthPrefixed(manifest.planID.value, to: &canonical)
    appendLengthPrefixed(manifest.evidenceID.value, to: &canonical)
    appendLengthPrefixed(manifest.evidenceSha256.value, to: &canonical)
    appendLengthPrefixed(manifest.currentBindingSha256.value, to: &canonical)
    appendLengthPrefixed(manifest.revalidationSha256.value, to: &canonical)
    appendBigEndian(manifest.overlayRevision, to: &canonical)
    appendLengthPrefixed(manifest.scanSessionID.value, to: &canonical)
    appendLengthPrefixed(manifest.scanCheckpointID.value, to: &canonical)
    appendLengthPrefixed(manifest.scanCheckpointEvidenceSha256.value, to: &canonical)
    return digest(canonical)
  }

  private static func requireFinding(
    _ finding: Diskplan_V1_RevalidationFindingProjection,
    expectedActionID: Data?
  ) throws {
    try requireNonempty(finding.findingID.value, field: "finding_id")
    if let expectedActionID {
      try requireDigest(finding.actionID.value, field: "finding action_id")
      guard finding.actionID.value == expectedActionID else {
        throw SealedRuntimeWireError.invalid(field: "finding action binding")
      }
    } else if finding.hasActionID {
      throw SealedRuntimeWireError.invalid(field: "global finding action_id")
    }
    guard validRevalidationSubject(finding.subject), validRevalidationKind(finding.kind),
      !finding.summary.isEmpty
    else {
      throw SealedRuntimeWireError.invalid(field: "revalidation finding")
    }
    switch (finding.kind, finding.detail) {
    case (.unknown, .unknown(let unknown)?)
    where !unknown.code.isEmpty && !unknown.summary.isEmpty:
      break
    case (.unreadable, .observationFailure(let failure)?)
    where !failure.code.isEmpty && !failure.collector.isEmpty:
      break
    case (.collectionFailed, .observationFailure(let failure)?)
    where !failure.code.isEmpty && !failure.collector.isEmpty:
      break
    case (.unknown, _), (.unreadable, _), (.collectionFailed, _):
      throw SealedRuntimeWireError.invalid(field: "revalidation finding detail")
    case (_, nil):
      break
    case (_, _):
      throw SealedRuntimeWireError.invalid(field: "unexpected revalidation finding detail")
    }
  }

  private static func requireEpoch(_ epoch: Diskplan_V1_ExecutionEpochProjection) throws {
    try requireNonempty(epoch.epochID.value, field: "epoch_id")
    guard epoch.semanticReferenceTimeSeconds <= epoch.issuedAtSeconds,
      epoch.issuedAtSeconds < epoch.deadlineSeconds
    else {
      throw SealedRuntimeWireError.invalid(field: "execution epoch")
    }
  }

  private static func requireApplyStarted(
    _ started: Diskplan_V1_ApplyStartedProjection
  ) throws {
    try requireEpoch(started.epoch)
    try requireNonempty(started.applyReviewID.value, field: "apply_review_id")
    try requireNonempty(started.projectionID.value, field: "projection_id")
    try requireDigest(started.planSha256.value, field: "plan_sha256")
    try requireNonempty(started.overlayID.value, field: "overlay_id")
    try requireDigest(started.overlaySha256.value, field: "overlay_sha256")
    try requireDigest(started.reviewBindingSha256.value, field: "review_binding_sha256")
    try requireDigest(started.planID.value, field: "plan_id")
    try requireDigest(started.evidenceID.value, field: "evidence_id")
    try requireDigest(started.evidenceSha256.value, field: "evidence_sha256")
    try requireDigest(started.currentBindingSha256.value, field: "current_binding_sha256")
    try requireDigest(started.revalidationSha256.value, field: "revalidation_sha256")
    try requireScanBinding(
      sessionID: started.scanSessionID.value,
      checkpointID: started.scanCheckpointID.value,
      checkpointEvidenceSHA256: started.scanCheckpointEvidenceSha256.value,
      finalEvidenceSHA256: started.evidenceSha256.value
    )
    guard started.planID.value == started.planSha256.value,
      started.evidenceID.value == started.evidenceSha256.value
    else {
      throw SealedRuntimeWireError.invalid(field: "apply-started plan/evidence binding")
    }
  }

  private static func requireExecutionUnit(
    _ unit: Diskplan_V1_ExecutionUnitProjection
  ) throws {
    switch unit.unit {
    case .actionID(let actionID):
      try requireDigest(actionID.value, field: "execution unit action_id")
    case .compoundRelease(let compound):
      let ids = compound.releaseSetIds.map(\.value)
      guard !ids.isEmpty, Set(ids).count == ids.count, ids.allSatisfy({ !$0.isEmpty }) else {
        throw SealedRuntimeWireError.invalid(field: "compound release unit")
      }
    case nil:
      throw SealedRuntimeWireError.invalid(field: "execution unit")
    }
  }

  package static func requirePreview(
    _ preview: Diskplan_V1_ActionExecutionPreviewProjection,
    negotiatedProtocolMinor: UInt32
  ) throws {
    try requireSupportedProtocolMinor(negotiatedProtocolMinor)
    guard validActionKind(preview.adapter) else {
      throw SealedRuntimeWireError.invalid(field: "preview adapter")
    }
    if negotiatedProtocolMinor == protocol14Minor {
      guard !preview.hasRawWorkingDirectory, preview.pathRace == .unspecified else {
        throw SealedRuntimeWireError.invalid(field: "protocol 1.4 execution preview")
      }
    } else {
      guard preview.hasRawWorkingDirectory, validPathRace(preview.pathRace) else {
        throw SealedRuntimeWireError.invalid(field: "protocol 1.5 execution preview")
      }
      if preview.mutationSupported {
        guard preview.rawWorkingDirectory.first == 47,
          !preview.rawWorkingDirectory.contains(0)
        else {
          throw SealedRuntimeWireError.invalid(field: "execution working directory")
        }
      } else if !preview.rawWorkingDirectory.isEmpty {
        throw SealedRuntimeWireError.invalid(field: "unsupported execution working directory")
      }
    }
    if preview.mutationSupported {
      guard !preview.rawExecutable.isEmpty, !preview.rawExecutable.contains(0),
        preview.rawArgv.allSatisfy({ !$0.contains(0) }),
        preview.rawArgv.count == preview.displayArgv.count,
        !preview.postcondition.isEmpty
      else {
        throw SealedRuntimeWireError.invalid(field: "execution preview")
      }
    } else if !preview.rawExecutable.isEmpty || !preview.rawArgv.isEmpty {
      throw SealedRuntimeWireError.invalid(field: "unsupported execution preview")
    }
  }

  private static func requireStep(
    _ step: Diskplan_V1_ExecutionStepFinishedProjection
  ) throws {
    try requireDigest(step.actionID.value, field: "step action_id")
    guard validExecutionStepStatus(step.status) else {
      throw SealedRuntimeWireError.invalid(field: "execution step status")
    }
    try requireAdapterOutcome(step.adapterOutcome)
    try requirePostVerification(step.postVerification)
  }

  private static func requireAdapterOutcome(
    _ outcome: Diskplan_V1_AdapterOutcomeProjection
  ) throws {
    switch (outcome.kind, outcome.detail) {
    case (.succeeded, nil), (.cancelled, nil):
      return
    case (.failed, .failure(let failure)?) where !failure.code.isEmpty:
      return
    case (.timedOut, .failure(let failure)?) where !failure.code.isEmpty:
      return
    case (.cancelled, .failure(_)?):
      return
    case (.notStarted, .notStartedReason(let reason)?) where !reason.isEmpty:
      return
    default:
      throw SealedRuntimeWireError.invalid(field: "adapter outcome")
    }
  }

  private static func requirePostVerification(
    _ verification: Diskplan_V1_PostVerificationProjection
  ) throws {
    guard !verification.code.isEmpty else {
      throw SealedRuntimeWireError.invalid(field: "post-verification code")
    }
    switch (verification.kind, verification.detail) {
    case (.satisfied, nil), (.missing, nil), (.notSatisfied, nil):
      return
    case (.expectedResidual, .residual(let residual)?) where !residual.code.isEmpty:
      return
    case (.unknown, .unknown(let unknown)?)
    where !unknown.code.isEmpty && !unknown.summary.isEmpty:
      return
    case (.unreadable, .observationFailure(let failure)?)
    where !failure.code.isEmpty && !failure.collector.isEmpty:
      return
    case (.failed, .observationFailure(let failure)?)
    where !failure.code.isEmpty && !failure.collector.isEmpty:
      return
    default:
      throw SealedRuntimeWireError.invalid(field: "post-verification")
    }
  }

  private static func requireUniqueDigests(_ values: [Data], field: String) throws {
    for value in values { try requireDigest(value, field: field) }
    guard Set(values).count == values.count else {
      throw SealedRuntimeWireError.invalid(field: field)
    }
  }

  private static func requireDigest(_ value: Data, field: String) throws {
    guard value.count == 32 else { throw SealedRuntimeWireError.invalid(field: field) }
  }

  private static func requireScanBinding(
    sessionID: Data,
    checkpointID: Data,
    checkpointEvidenceSHA256: Data,
    finalEvidenceSHA256: Data
  ) throws {
    try requireNonempty(sessionID, field: "scan_session_id")
    try requireNonempty(checkpointID, field: "scan_checkpoint_id")
    try requireDigest(checkpointEvidenceSHA256, field: "scan_checkpoint_evidence_sha256")
    try requireDigest(finalEvidenceSHA256, field: "evidence_sha256")
    guard checkpointID == lowercaseHexData(finalEvidenceSHA256) else {
      throw SealedRuntimeWireError.invalid(field: "scan_checkpoint_id")
    }
  }

  private static func lowercaseHexData(_ value: Data) -> Data {
    Data(value.map { String(format: "%02x", $0) }.joined().utf8)
  }

  private static func requireNonempty(_ value: Data, field: String) throws {
    guard !value.isEmpty, value.count <= maximumOpaqueIdentifierBytes else {
      throw SealedRuntimeWireError.invalid(field: field)
    }
  }

  private static func requireCount(_ value: UInt64, maximum: UInt64, field: String) throws {
    guard value <= maximum else {
      throw SealedRuntimeWireError.countExceeded(field: field, actual: value, maximum: maximum)
    }
  }

  private static func requireMaximumBytes(_ value: UInt64, maximum: UInt64) throws {
    guard value <= maximum else {
      throw SealedRuntimeWireError.encodedBytesExceeded(actual: value, maximum: maximum)
    }
  }

  private static func adding(_ lhs: UInt64, _ rhs: UInt64, field: String) throws -> UInt64 {
    let (value, overflow) = lhs.addingReportingOverflow(rhs)
    guard !overflow else { throw SealedRuntimeWireError.integerOverflow(field: field) }
    return value
  }

  private static func digest(_ value: Data) -> Data { Data(SHA256.hash(data: value)) }

  private static func digestMessage(_ value: Data) -> Diskplan_V1_Digest256 {
    var result = Diskplan_V1_Digest256()
    result.value = value
    return result
  }

  private static func appendLengthPrefixed(_ value: Data, to output: inout Data) {
    precondition(value.count <= Int(UInt32.max))
    appendBigEndian(UInt32(value.count), to: &output)
    output.append(value)
  }

  private static func appendBigEndian<T: FixedWidthInteger>(_ value: T, to output: inout Data) {
    var encoded = value.bigEndian
    withUnsafeBytes(of: &encoded) { output.append(contentsOf: $0) }
  }

  private static func validActionKind(_ value: Diskplan_V1_PlanActionKind) -> Bool {
    switch value {
    case .genericRemove, .gitWorktreeRemove, .gitWorktreeDiscardLocalChanges,
      .codexCleanTemporary, .versionedArtifactRemove, .completeReleaseSetRemove, .reportOnly:
      true
    case .unspecified, .UNRECOGNIZED: false
    }
  }

  private static func validPathRace(_ value: Diskplan_V1_PathRaceProjection) -> Bool {
    switch value {
    case .noneObserved, .residual, .unknown: true
    case .unspecified, .UNRECOGNIZED: false
    }
  }

  private static func validExecutionStepStatus(_ value: Diskplan_V1_ExecutionStepStatus) -> Bool {
    switch value {
    case .succeeded, .partiallySucceeded, .failed, .cancelled, .expired, .superseded,
      .skippedPrerequisite:
      true
    case .unspecified, .UNRECOGNIZED: false
    }
  }

  private static func validApplyStartFailure(_ value: Diskplan_V1_ApplyStartFailureKind) -> Bool {
    switch value {
    case .authorizationAlreadyClaimed, .invalidOverlay, .manifestBindingMismatch, .expired,
      .invalidExecutionGraph, .preparationSuperseded, .forceConfirmationBindingMismatch:
      true
    case .unspecified, .UNRECOGNIZED: false
    }
  }

  private static func validRevalidationSubject(_ value: Diskplan_V1_RevalidationSubject) -> Bool {
    switch value {
    case .targetIdentity, .targetContent, .targetAccessPolicy, .coverage, .collectorStatus,
      .activity, .explicitProtection, .providerState, .recoverability, .dependency,
      .rootIdentity, .rootAccessPolicy, .parentIdentity, .parentAccessPolicy, .gitPrerequisites,
      .releaseTopology, .duplicateSurvivors, .terminalNamespaces, .compoundReleaseUnit,
      .collector, .policyEvidence, .waiverConsent:
      true
    case .unspecified, .UNRECOGNIZED: false
    }
  }

  private static func validRevalidationKind(_ value: Diskplan_V1_RevalidationFailureKind) -> Bool {
    switch value {
    case .missing, .unknown, .unreadable, .collectionFailed, .cancelled, .identityMismatch,
      .contentMismatch, .accessPolicyMismatch, .namespaceIdentityMismatch,
      .namespaceAccessPolicyMismatch, .coverageMismatch, .activityMismatch,
      .protectionMismatch, .providerMismatch, .recoverabilityMismatch, .dependencyMismatch,
      .gitPrerequisiteMismatch, .releaseTopologyMismatch, .survivorInvariantViolated,
      .terminalNamespaceInvariantViolated, .incompleteCompoundReleaseUnit,
      .duplicateObservation, .unexpectedObservation, .policyEvidenceMismatch,
      .policyThresholdCrossed, .staleConsent:
      true
    case .unspecified, .UNRECOGNIZED: false
    }
  }
}
