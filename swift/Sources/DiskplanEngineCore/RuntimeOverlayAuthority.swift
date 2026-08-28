import DiskplanPolicy
import DiskplanProto
import Foundation

struct RuntimeOverlayEditRejection: Error {
  let code: Diskplan_V1_DecisionOverlayRejectCode
  let summary: String
  let actionID: Data?
  let waiverID: Data?

  init(
    code: Diskplan_V1_DecisionOverlayRejectCode,
    summary: String,
    actionID: Data? = nil,
    waiverID: Data? = nil
  ) {
    self.code = code
    self.summary = summary
    self.actionID = actionID
    self.waiverID = waiverID
  }
}

enum RuntimePlanIdentifiers {
  static func waiverID(_ predicate: WaiverPredicate) -> Data {
    runtimeDigest(
      domain: "diskplan/waiver-projection-id/v1\0",
      fields: [
        Data(predicate.kind.rawValue.utf8),
        Data(predicate.predicate.utf8),
        Data(predicate.valueBucket.utf8),
        predicate.semanticEvidenceHash.bytes,
      ]
    )
  }

  /// Maps the protocol's byte-preserving identifier into the policy core's
  /// string-backed consent field without losing or interpreting any bytes.
  static func consentEventIDBinding(_ bytes: Data) -> String? {
    guard !bytes.isEmpty, bytes.count <= SealedRuntimeWire.maximumOpaqueIdentifierBytes else {
      return nil
    }
    return "opaque-bytes-v1:" + bytes.base64EncodedString()
  }
}

enum RuntimeOverlayEditor {
  private enum EditKey: Hashable {
    case selection(Data)
    case waiver(Data, Data)
    case notes
    case preset
  }

  static func apply(
    _ edits: [Diskplan_V1_DecisionOverlayEdit],
    to current: DecisionOverlay?,
    plan: ImmutablePlan
  ) throws -> DecisionOverlay {
    try validateEditSet(edits)
    let actionByID = Dictionary(uniqueKeysWithValues: plan.actions.map { ($0.id, $0) })
    let actionByLineage = Dictionary(uniqueKeysWithValues: plan.actions.map { ($0.lineageID, $0) })
    var selected = Set(current?.selectedActionIDs ?? [])
    var consents: [ActionID: [WaiverPredicate: WaiverConsentCore]] = [:]
    for consent in current?.waiverConsents ?? [] {
      guard let action = actionByLineage[consent.actionLineageID] else {
        throw RuntimeOverlayEditRejection(
          code: .invalidEdit,
          summary: "the live overlay contains an unknown action lineage"
        )
      }
      consents[action.id, default: [:]][consent.predicate] = consent
    }
    var notes = current?.userNotes ?? []

    for edit in edits {
      switch edit.edit {
      case .stageAction(let stage):
        let action = try requireAction(stage.actionID.value, actionByID: actionByID)
        guard case .blocked = action.evaluation.stageability else {
          selected.insert(action.id)
          continue
        }
        throw RuntimeOverlayEditRejection(
          code: .actionNotStageable,
          summary: "the action is not stageable",
          actionID: stage.actionID.value
        )

      case .unstageAction(let stage):
        let action = try requireAction(stage.actionID.value, actionByID: actionByID)
        selected.remove(action.id)
        consents.removeValue(forKey: action.id)

      case .allowWaiver(let waiver):
        let action = try requireAction(waiver.actionID.value, actionByID: actionByID)
        guard
          case .requiresConsents(let required) = action.evaluation.stageability,
          let predicate = required.first(where: {
            RuntimePlanIdentifiers.waiverID($0) == waiver.waiverID.value
          })
        else {
          throw RuntimeOverlayEditRejection(
            code: .unknownWaiver,
            summary: "the waiver is not required by this action",
            actionID: waiver.actionID.value,
            waiverID: waiver.waiverID.value
          )
        }
        guard !waiver.reason.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
          let consentEventID = RuntimePlanIdentifiers.consentEventIDBinding(
            waiver.consentEventID.value
          )
        else {
          throw RuntimeOverlayEditRejection(
            code: .invalidReason,
            summary: "waiver reason must be non-empty and consent_event_id must be 1...256 bytes",
            actionID: waiver.actionID.value,
            waiverID: waiver.waiverID.value
          )
        }
        consents[action.id, default: [:]][predicate] = WaiverConsentCore.create(
          action: action,
          predicate: predicate,
          reason: waiver.reason,
          consentEventID: consentEventID
        )

      case .revokeWaiver(let waiver):
        let action = try requireAction(waiver.actionID.value, actionByID: actionByID)
        guard
          let predicate = consents[action.id]?.keys.first(where: {
            RuntimePlanIdentifiers.waiverID($0) == waiver.waiverID.value
          })
        else {
          throw RuntimeOverlayEditRejection(
            code: .unknownWaiver,
            summary: "the waiver is not acknowledged in the live overlay",
            actionID: waiver.actionID.value,
            waiverID: waiver.waiverID.value
          )
        }
        consents[action.id]?.removeValue(forKey: predicate)
        if consents[action.id]?.isEmpty == true { consents.removeValue(forKey: action.id) }

      case .replaceNotes(let replacement):
        notes = replacement.userNotes

      case .applyBatchSelectionPreset(let preset):
        guard preset.preset == .safeStageableWithoutWaiver else {
          throw RuntimeOverlayEditRejection(
            code: .invalidEdit,
            summary: "the batch selection preset is unsupported"
          )
        }
        selected = safeStageableSelection(plan.actions)
        consents.removeAll(keepingCapacity: true)

      case nil:
        throw RuntimeOverlayEditRejection(
          code: .invalidEdit,
          summary: "overlay edit body is missing"
        )
      }
    }

    guard selected.count <= Int(SealedRuntimeWire.maximumActionCount) else {
      throw RuntimeOverlayEditRejection(
        code: .limitExceeded,
        summary: "selected action count exceeds the protocol maximum"
      )
    }
    let flattenedConsents = consents.values.flatMap { $0.values }
    guard flattenedConsents.count <= Int(SealedRuntimeWire.maximumOverlayWaiverCount),
      notes.count <= Int(SealedRuntimeWire.maximumOverlayNoteCount),
      notes.reduce(0, { $0 + $1.utf8.count }) <= Int(SealedRuntimeWire.maximumOverlayNoteBytes)
    else {
      throw RuntimeOverlayEditRejection(
        code: .limitExceeded,
        summary: "overlay waiver or note budget is exceeded"
      )
    }
    let overlay = DecisionOverlay.create(
      plan: plan,
      selectedActionIDs: selected.sorted(),
      waiverConsents: flattenedConsents,
      userNotes: notes
    )
    _ = try DecisionOverlayValidator.validate(overlay, against: plan)
    return overlay
  }

  static func validateEditSet(_ edits: [Diskplan_V1_DecisionOverlayEdit]) throws {
    var seen = Set<EditKey>()
    var containsPreset = false
    for edit in edits {
      try validateShape(edit)
      let key: EditKey
      switch edit.edit {
      case .stageAction(let stage), .unstageAction(let stage):
        key = .selection(stage.actionID.value)
      case .allowWaiver(let waiver):
        key = .waiver(waiver.actionID.value, waiver.waiverID.value)
      case .revokeWaiver(let waiver):
        key = .waiver(waiver.actionID.value, waiver.waiverID.value)
      case .replaceNotes:
        key = .notes
      case .applyBatchSelectionPreset:
        key = .preset
        containsPreset = true
      case nil:
        throw RuntimeOverlayEditRejection(
          code: .invalidEdit,
          summary: "overlay edit body is missing"
        )
      }
      guard seen.insert(key).inserted else {
        throw RuntimeOverlayEditRejection(
          code: .invalidEdit,
          summary: "an overlay edit target appears more than once"
        )
      }
    }
    guard !containsPreset || edits.count == 1 else {
      throw RuntimeOverlayEditRejection(
        code: .invalidEdit,
        summary: "a batch selection preset cannot be mixed with interactive edits"
      )
    }
  }

  static func safeStageableSelection(_ actions: [ActionDefinition]) -> Set<ActionID> {
    let prerequisites = Dictionary(
      uniqueKeysWithValues: actions.map { ($0.id, Set($0.prerequisiteActionIDs)) }
    )
    let stageable = Set(
      actions.compactMap { action in
        if case .stageable = action.evaluation.stageability { return action.id }
        return nil
      })
    return prerequisiteClosedSelection(
      stageableActionIDs: stageable,
      prerequisitesByActionID: prerequisites
    )
  }

  static func prerequisiteClosedSelection(
    stageableActionIDs: Set<ActionID>,
    prerequisitesByActionID: [ActionID: Set<ActionID>]
  ) -> Set<ActionID> {
    var selected = stageableActionIDs
    var dependentsByPrerequisite: [ActionID: [ActionID]] = [:]
    for (actionID, prerequisites) in prerequisitesByActionID {
      for prerequisite in prerequisites {
        dependentsByPrerequisite[prerequisite, default: []].append(actionID)
      }
    }
    var pendingRemoval = Array(
      selected.filter { actionID in
        !(prerequisitesByActionID[actionID] ?? []).isSubset(of: selected)
      })

    while let removed = pendingRemoval.popLast() {
      guard selected.remove(removed) != nil else { continue }
      pendingRemoval.append(contentsOf: dependentsByPrerequisite[removed] ?? [])
    }
    return selected
  }

  private static func requireAction(
    _ bytes: Data,
    actionByID: [ActionID: ActionDefinition]
  ) throws -> ActionDefinition {
    guard let digest = try? PolicyDigest(bytes: bytes),
      let action = actionByID[ActionID(digest: digest)]
    else {
      throw RuntimeOverlayEditRejection(
        code: .unknownAction,
        summary: "the edit references an unknown action",
        actionID: bytes
      )
    }
    return action
  }

  private static func validateShape(_ edit: Diskplan_V1_DecisionOverlayEdit) throws {
    let matches: Bool
    switch edit.edit {
    case .stageAction: matches = edit.kind == .stageAction
    case .unstageAction: matches = edit.kind == .unstageAction
    case .allowWaiver: matches = edit.kind == .allowWaiver
    case .revokeWaiver: matches = edit.kind == .revokeWaiver
    case .replaceNotes: matches = edit.kind == .replaceNotes
    case .applyBatchSelectionPreset: matches = edit.kind == .applyBatchSelectionPreset
    case nil: matches = false
    }
    guard matches else {
      throw RuntimeOverlayEditRejection(
        code: .invalidEdit,
        summary: "decision edit kind does not match its body"
      )
    }
  }
}

enum RuntimeOverlayProjector {
  static func project(
    _ overlay: DecisionOverlay,
    revision: UInt64,
    manifest: Diskplan_V1_PlanProjectionManifest,
    records: [Diskplan_V1_PlanProjectionRecord]
  ) throws -> Diskplan_V1_DecisionOverlayAcknowledged {
    let actions = Dictionary(
      uniqueKeysWithValues: records.compactMap {
        record -> (Data, Diskplan_V1_PlanActionProjection)? in
        guard case .action(let action)? = record.body else { return nil }
        return (action.actionID.value, action)
      })
    let selected = overlay.selectedActionIDs.sorted().map {
      actionID -> Diskplan_V1_OpaqueIdentifier in
      var projected = Diskplan_V1_OpaqueIdentifier()
      projected.value = actionID.digest.bytes
      return projected
    }
    var acknowledged: [Diskplan_V1_AcknowledgedWaiver] = []
    for consent in overlay.waiverConsents {
      guard
        let action = overlay.selectedActionIDs.compactMap({
          id -> Diskplan_V1_PlanActionProjection? in
          guard let candidate = actions[id.digest.bytes],
            candidate.actionLineageID.value == consent.actionLineageID.digest.bytes
          else { return nil }
          return candidate
        }).first,
        let waiver = action.requiredWaivers.first(where: {
          $0.waiverID.value == RuntimePlanIdentifiers.waiverID(consent.predicate)
        })
      else {
        throw RuntimeOverlayEditRejection(
          code: .invalidEdit,
          summary: "waiver consent cannot be projected to the live plan"
        )
      }
      var row = Diskplan_V1_AcknowledgedWaiver()
      row.actionID = action.actionID
      row.waiverID = waiver.waiverID
      row.consentSha256.value = consent.consentHash.bytes
      acknowledged.append(row)
    }
    acknowledged.sort {
      if $0.actionID.value != $1.actionID.value {
        return $0.actionID.value.lexicographicallyPrecedes($1.actionID.value)
      }
      return $0.waiverID.value.lexicographicallyPrecedes($1.waiverID.value)
    }

    var projected = Diskplan_V1_DecisionOverlayAcknowledged()
    projected.projectionID = manifest.projectionID
    projected.revision = revision
    projected.overlaySha256.value = overlay.overlayHash.bytes
    projected.selectedActionIds = selected
    projected.acknowledgedWaivers = acknowledged
    projected.userNotes = overlay.userNotes
    projected.forceWarningActionIds = selected.filter { actions[$0.value]?.requiresForce == true }
    projected.maximumSelectedActions = SealedRuntimeWire.maximumActionCount
    projected.maximumWaiverConsents = SealedRuntimeWire.maximumOverlayWaiverCount
    projected.maximumUserNotes = SealedRuntimeWire.maximumOverlayNoteCount
    projected.selectedActionCount = UInt64(selected.count)
    projected.overlayID.value = runtimeDigest(
      domain: "diskplan/overlay-id/v1\0",
      fields: [manifest.projectionID.value, overlay.overlayHash.bytes]
    )
    projected.planID = manifest.planID
    projected.planSha256 = manifest.planSha256
    projected.evidenceID = manifest.evidenceID
    projected.evidenceSha256 = manifest.evidenceSha256
    projected.maximumEncodedBytes = SealedRuntimeWire.maximumProjectionBytes
    projected.maximumNoteBytes = SealedRuntimeWire.maximumOverlayNoteBytes
    projected.scanSessionID = manifest.scanSessionID
    projected.scanCheckpointID = manifest.scanCheckpointID
    projected.scanCheckpointEvidenceSha256 = manifest.scanCheckpointEvidenceSha256
    return try SealedRuntimeWire.sealDecisionOverlayAcknowledged(
      projected,
      authoritativePlanRecords: records
    )
  }
}
