import DiskplanEngineCore
import DiskplanProto
import Foundation

private struct FixtureSpec: Decodable {
  let schema: String
  let cases: [FixtureCase]
}

private struct FixtureHeader: Decodable { let schema: String }

private struct RuntimeFixtureSpec: Decodable {
  let schema: String
  let cases: [RuntimeFixtureCase]
}

private struct RuntimeFixtureCase: Decodable {
  let name: String
  let includeAction: Bool
  let requiresForce: Bool
  let actionKind: String?

  enum CodingKeys: String, CodingKey {
    case name
    case includeAction = "include_action"
    case requiresForce = "requires_force"
    case actionKind = "action_kind"
  }
}

private struct FixtureCase: Decodable {
  let name: String
  let terminal: String
  let chunkPayloadTargetBytes: Int
  let nodeComponentsHex: [[String]]

  enum CodingKeys: String, CodingKey {
    case name
    case terminal
    case chunkPayloadTargetBytes = "chunk_payload_target_bytes"
    case nodeComponentsHex = "node_components_hex"
  }
}

private enum GeneratorError: Error, CustomStringConvertible {
  case usage
  case invalidSchema(String)
  case invalidTerminal(String)
  case invalidRuntimeActionKind(String)
  case invalidHex(String)

  var description: String {
    switch self {
    case .usage:
      "usage: diskplan-protocol-fixture-generator <fixture.json> <output-directory>"
    case .invalidSchema(let schema):
      "unsupported fixture schema: \(schema)"
    case .invalidTerminal(let terminal):
      "unsupported fixture terminal: \(terminal)"
    case .invalidRuntimeActionKind(let kind):
      "unsupported runtime fixture action kind: \(kind)"
    case .invalidHex(let value):
      "invalid fixture hex: \(value)"
    }
  }
}

@main
private enum DiskplanProtocolFixtureGenerator {
  static func main() throws {
    guard CommandLine.arguments.count == 3 else { throw GeneratorError.usage }
    let input = URL(fileURLWithPath: CommandLine.arguments[1])
    let output = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
    let source = try Data(contentsOf: input)
    let header = try JSONDecoder().decode(FixtureHeader.self, from: source)
    try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
    let generated: [(String, [Data])]
    switch header.schema {
    case "scan-stream-v1.3":
      let spec = try JSONDecoder().decode(FixtureSpec.self, from: source)
      generated = try spec.cases.map { ($0.name, try frames(for: $0)) }
    case "runtime-v1.4":
      let spec = try JSONDecoder().decode(RuntimeFixtureSpec.self, from: source)
      generated = try spec.cases.map { ($0.name, try runtimeFrames(for: $0)) }
    default:
      throw GeneratorError.invalidSchema(header.schema)
    }
    for (name, frames) in generated {
      let contents = frames.map(hex).joined(separator: "\n") + "\n"
      try Data(contents.utf8).write(
        to: output.appendingPathComponent("\(name).frames.hex"),
        options: .atomic
      )
    }
  }

  private static func runtimeFrames(for fixture: RuntimeFixtureCase) throws -> [Data] {
    let planHash = repeated(0xa1)
    let evidenceHash = repeated(0xe1)
    let checkpointEvidenceHash = repeated(0xe2)
    let overlayHash = repeated(0xb1)
    let currentBindingHash = repeated(0xc1)
    let reviewBindingHash = repeated(0xd1)
    let actionID = repeated(0x11)
    let targetID = Data("target-1".utf8)
    let actionKind = try runtimeActionKind(fixture.actionKind)
    let records = try runtimeRecords(
      includeAction: fixture.includeAction,
      requiresForce: fixture.requiresForce,
      actionKind: actionKind,
      actionID: actionID,
      targetID: targetID
    )
    let targetBytes = try runtimeChunkTarget(records)
    let encodedPlan = try PlanProjectionWireEncoder.encode(
      records: records,
      metadata: PlanProjectionWireMetadata(
        scanSessionID: Data("fixture-session".utf8),
        scanCheckpointID: Data(hex(evidenceHash).utf8),
        scanCheckpointEvidenceSHA256: checkpointEvidenceHash,
        planSHA256: planHash,
        evidenceSHA256: evidenceHash,
        cleanupCandidateCount: fixture.includeAction ? 1 : 0,
        policyVersion: "fixture-policy-v1",
        schemaVersion: "runtime-v1.4"
      ),
      chunkPayloadTargetBytes: targetBytes
    )

    var bodies: [Diskplan_V1_RuntimeEvent.OneOf_Body] = []
    var accepted = Diskplan_V1_BuildPlanAccepted()
    accepted.planBuildID.value = Data("fixture-plan-build".utf8)
    bodies.append(.buildPlanAccepted(accepted))
    bodies.append(
      contentsOf: encodedPlan.chunks.map(Diskplan_V1_RuntimeEvent.OneOf_Body.planProjectionChunk))
    var planProjection = Diskplan_V1_PlanProjection()
    planProjection.manifest = encodedPlan.manifest
    bodies.append(.planProjection(planProjection))

    let selectedIDs = fixture.includeAction ? [opaque(actionID)] : []
    var overlay = Diskplan_V1_DecisionOverlayAcknowledged()
    overlay.projectionID = encodedPlan.manifest.projectionID
    overlay.revision = 1
    overlay.overlaySha256 = digestMessage(overlayHash)
    overlay.selectedActionIds = selectedIDs
    overlay.forceWarningActionIds = fixture.requiresForce ? selectedIDs : []
    overlay.maximumSelectedActions = SealedRuntimeWire.maximumActionCount
    overlay.maximumWaiverConsents = SealedRuntimeWire.maximumOverlayWaiverCount
    overlay.maximumUserNotes = SealedRuntimeWire.maximumOverlayNoteCount
    overlay.selectedActionCount = UInt64(selectedIDs.count)
    overlay.overlayID.value = Data("fixture-overlay".utf8)
    overlay.planID = encodedPlan.manifest.planID
    overlay.planSha256 = encodedPlan.manifest.planSha256
    overlay.evidenceID = encodedPlan.manifest.evidenceID
    overlay.evidenceSha256 = encodedPlan.manifest.evidenceSha256
    overlay.maximumEncodedBytes = SealedRuntimeWire.maximumProjectionBytes
    overlay.maximumNoteBytes = SealedRuntimeWire.maximumOverlayNoteBytes
    overlay.scanSessionID = encodedPlan.manifest.scanSessionID
    overlay.scanCheckpointID = encodedPlan.manifest.scanCheckpointID
    overlay.scanCheckpointEvidenceSha256 = encodedPlan.manifest.scanCheckpointEvidenceSha256
    overlay = try SealedRuntimeWire.sealDecisionOverlayAcknowledged(overlay)
    bodies.append(.decisionOverlayAcknowledged(overlay))

    let revalidation = runtimeRevalidation(includeAction: fixture.includeAction, actionID: actionID)
    var dryPayload = Diskplan_V1_DryRunProjectionPayload()
    dryPayload.revalidation = revalidation
    if fixture.includeAction {
      var action = Diskplan_V1_DryRunActionProjection()
      action.actionID = opaque(actionID)
      action.executionPreview = runtimePreview(adapter: actionKind)
      dryPayload.actions = [action]
    }
    var dryManifest = Diskplan_V1_DryRunProjectionManifest()
    dryManifest.projectionID = encodedPlan.manifest.projectionID
    dryManifest.planSha256 = encodedPlan.manifest.planSha256
    dryManifest.overlaySha256 = overlay.overlaySha256
    dryManifest.epoch = runtimeEpoch()
    dryManifest.current = true
    dryManifest.dryRunID.value = Data("fixture-dry-run".utf8)
    dryManifest.selectedActionCount = overlay.selectedActionCount
    dryManifest.overlayID = overlay.overlayID
    dryManifest.planID = overlay.planID
    dryManifest.evidenceID = overlay.evidenceID
    dryManifest.evidenceSha256 = overlay.evidenceSha256
    dryManifest.currentBindingSha256 = digestMessage(currentBindingHash)
    dryManifest.overlayRevision = overlay.revision
    dryManifest.scanSessionID = overlay.scanSessionID
    dryManifest.scanCheckpointID = overlay.scanCheckpointID
    dryManifest.scanCheckpointEvidenceSha256 = overlay.scanCheckpointEvidenceSha256
    let dryRun = try SealedRuntimeWire.sealDryRun(payload: dryPayload, manifest: dryManifest)
    bodies.append(.dryRunProjection(dryRun))

    var review = Diskplan_V1_ApplyReviewProjection()
    review.applyReviewID.value = Data("fixture-apply-review".utf8)
    review.projectionID = overlay.projectionID
    review.planSha256 = overlay.planSha256
    review.overlaySha256 = overlay.overlaySha256
    review.epoch = runtimeEpoch()
    review.revalidation = revalidation
    review.forceWarningActionIds = overlay.forceWarningActionIds
    if fixture.includeAction {
      var action = Diskplan_V1_ApplyReviewActionProjection()
      action.actionID = opaque(actionID)
      action.requiresForce = fixture.requiresForce
      action.executionPreview = runtimePreview(adapter: actionKind)
      review.actions = [action]
    }
    review.reviewBindingSha256 = digestMessage(reviewBindingHash)
    review.overlayID = overlay.overlayID
    review.selectedActionCount = overlay.selectedActionCount
    review.planID = overlay.planID
    review.evidenceID = overlay.evidenceID
    review.evidenceSha256 = overlay.evidenceSha256
    review.currentBindingSha256 = digestMessage(currentBindingHash)
    review.overlayRevision = overlay.revision
    review.scanSessionID = overlay.scanSessionID
    review.scanCheckpointID = overlay.scanCheckpointID
    review.scanCheckpointEvidenceSha256 = overlay.scanCheckpointEvidenceSha256
    let sealedReview = try SealedRuntimeWire.sealApplyReview(review)
    bodies.append(.applyReviewProjection(sealedReview))

    let execution = try runtimeExecution(
      review: sealedReview,
      actionID: actionID,
      includeAction: fixture.includeAction,
      requiresForce: fixture.requiresForce,
      adapter: actionKind
    )
    bodies.append(
      contentsOf: execution.map(Diskplan_V1_RuntimeEvent.OneOf_Body.executionStreamEvent))

    return try bodies.enumerated().map { index, body in
      let sequence = UInt64(index + 1)
      var event = Diskplan_V1_RuntimeEvent()
      event.eventSequence = sequence
      event.runtimeSessionID.value = Data("fixture-runtime-session".utf8)
      event.body = body
      var envelope = Diskplan_V1_Envelope()
      envelope.sequence = sequence
      envelope.body = .runtimeEvent(event)
      return try framed(envelope)
    }
  }

  private static func runtimeRecords(
    includeAction: Bool,
    requiresForce: Bool,
    actionKind: Diskplan_V1_PlanActionKind,
    actionID: Data,
    targetID: Data
  ) throws -> [Diskplan_V1_PlanProjectionRecord] {
    guard includeAction else { return [] }
    var action = Diskplan_V1_PlanActionProjection()
    action.actionID = opaque(actionID)
    action.actionLineageID = opaque(repeated(0x12))
    action.disposition = .ready
    action.kind = actionKind
    action.kindLabel = "Remove"
    action.label = "Fixture candidate"
    action.stageability = .stageable
    action.immediateReclaim.knownBytes = 4_096
    action.sharedUnlock.knownBytes = 0
    action.activity = .inactive
    action.recoverability = .rebuildable
    action.requiresForce = requiresForce
    action.forceReason = requiresForce ? "fixture force warning" : ""
    action.pathRace = .residual
    action.targetIds = [opaque(targetID)]
    action.executionPreview = runtimePreview(adapter: actionKind)
    action.recommendation = .safeToClean
    var evidence = Diskplan_V1_EvidenceSummaryProjection()
    evidence.status = .known
    evidence.code = "fixture"
    evidence.summary = "Fixture evidence is complete."
    action.evidence = [evidence]
    action.safetyEvidence = runtimeSafetyEvidence(actionKind: actionKind)

    var target = Diskplan_V1_PlanTargetProjection()
    target.targetID = opaque(targetID)
    target.actionID = opaque(actionID)
    target.path.rootID.value = Data("fixture-root".utf8)
    target.path.components = [Data([0xff, 0x61])]
    target.path.displayPath = "/fixture/\\xffa"
    target.kind = .file

    var actionRecord = Diskplan_V1_PlanProjectionRecord()
    actionRecord.recordIndex = 0
    actionRecord.body = .action(action)
    var targetRecord = Diskplan_V1_PlanProjectionRecord()
    targetRecord.recordIndex = 1
    targetRecord.body = .target(target)
    return [actionRecord, targetRecord]
  }

  private static func runtimeChunkTarget(
    _ records: [Diskplan_V1_PlanProjectionRecord]
  ) throws -> Int {
    guard !records.isEmpty else { return 1_024 }
    var maximum = 0
    for record in records {
      maximum = max(maximum, 4 + (try record.serializedData().count))
    }
    return maximum
  }

  private static func runtimeSafetyEvidence(
    actionKind: Diskplan_V1_PlanActionKind
  ) -> Diskplan_V1_PlanSafetyEvidenceProjection {
    var evidence = Diskplan_V1_PlanSafetyEvidenceProjection()
    evidence.policyEvidenceSha256 = digestMessage(repeated(0xf1))
    evidence.namespaceAccess.targetAccessPolicy = runtimeKnownObservation(
      code: "target_access_policy_known",
      summary: "Target access policy is sealed.",
      digestByte: 0xf7
    )
    evidence.namespaceAccess.targetAclDigest = runtimeKnownObservation(
      code: "target_acl_known",
      summary: "Target ACL digest is sealed.",
      digestByte: 0xf8
    )
    evidence.namespaceAccess.rootAccessPolicy = runtimeKnownObservation(
      code: "root_access_policy_known",
      summary: "Root access policy is sealed.",
      digestByte: 0xf2
    )
    evidence.namespaceAccess.rootAclDigest = runtimeKnownObservation(
      code: "root_acl_known",
      summary: "Root ACL digest is sealed.",
      digestByte: 0xf3
    )
    evidence.namespaceAccess.ancestorAccessPolicyChain = runtimeKnownObservation(
      code: "ancestor_chain_known",
      summary: "Ancestor access-policy chain is complete.",
      digestByte: 0xf4
    )
    evidence.namespaceAccess.rootAccessPolicySeal = runtimeKnownObservation(
      code: "root_access_policy_seal_known",
      summary: "Root access-policy seal is complete.",
      digestByte: 0xf9
    )
    evidence.namespaceAccess.ancestorAccessPolicySeal = runtimeKnownObservation(
      code: "ancestor_access_policy_seal_known",
      summary: "Terminal ancestor access-policy seal is complete.",
      digestByte: 0xfa
    )
    evidence.namespaceAccess.ancestorCount = 1
    evidence.namespaceAccess.maximumAncestorCount =
      PlanProjectionWireEncoder.maximumNamespaceAncestorCount
    evidence.namespaceAccess.namespaceBindingSha256 = digestMessage(repeated(0xf5))
    evidence.contentBaseline.observation = runtimeKnownObservation(
      code: "content_digest_required",
      summary: "Content stability is protected by digest.",
      digestByte: 0xf6
    )
    evidence.contentBaseline.knownKind = .requiredDigest
    switch actionKind {
    case .gitWorktreeRemove, .gitWorktreeDiscardLocalChanges:
      evidence.gitWorktree = runtimeGitEvidence()
    case .codexCleanTemporary:
      evidence.codexCleanupScope = runtimeCodexEvidence()
    case .versionedArtifactRemove:
      evidence.versionedArtifact = runtimeVersionedArtifactEvidence()
    case .genericRemove, .completeReleaseSetRemove, .reportOnly, .unspecified, .UNRECOGNIZED:
      break
    }
    return evidence
  }

  private static func runtimeKnownObservation(
    code: String,
    summary: String,
    digestByte: UInt8
  ) -> Diskplan_V1_EvidenceObservationProjection {
    var observation = Diskplan_V1_EvidenceObservationProjection()
    observation.status = .known
    observation.code = code
    observation.summary = summary
    observation.valueSha256 = digestMessage(repeated(digestByte))
    return observation
  }

  private static func runtimeGitEvidence() -> Diskplan_V1_GitWorktreeEvidenceProjection {
    var evidence = Diskplan_V1_GitWorktreeEvidenceProjection()
    evidence.bundleSha256 = digestMessage(repeated(0x81))
    evidence.noFollowTraversalComplete = runtimeKnownObservation(
      code: "git_no_follow_complete", summary: "Git traversal is no-follow complete.",
      digestByte: 0x82)
    evidence.headIdentity = runtimeKnownObservation(
      code: "git_head_known", summary: "Git HEAD is bound.", digestByte: 0x83)
    evidence.indexDigest = runtimeKnownObservation(
      code: "git_index_known", summary: "Git index is bound.", digestByte: 0x84)
    evidence.localChanges = runtimeKnownObservation(
      code: "git_changes_known", summary: "Git changes are counted.", digestByte: 0x85)
    evidence.registration = runtimeKnownObservation(
      code: "git_registration_known", summary: "Git registration is bound.", digestByte: 0x86)
    evidence.linkage = runtimeKnownObservation(
      code: "git_linkage_known", summary: "Git linkage is bound.", digestByte: 0x87)
    evidence.sparseCheckout = runtimeKnownObservation(
      code: "git_sparse_known", summary: "Sparse checkout state is known.", digestByte: 0x88)
    evidence.nestedRepositories = runtimeKnownObservation(
      code: "git_nested_known", summary: "Nested repository state is known.", digestByte: 0x89)
    evidence.submodules = runtimeKnownObservation(
      code: "git_submodules_known", summary: "Submodule state is known.", digestByte: 0x8a)
    evidence.trustedExclusiveNamespace = runtimeKnownObservation(
      code: "git_namespace_known", summary: "Git namespace is exclusive.", digestByte: 0x8b)
    evidence.postQuarantineCoverage = runtimeKnownObservation(
      code: "git_quarantine_known", summary: "Quarantine coverage is known.", digestByte: 0x8c)
    evidence.postDiscardSuccessor = runtimeKnownObservation(
      code: "git_successor_known", summary: "Discard successor is bound.", digestByte: 0x8d)
    evidence.scanSummary.bundleSha256 = digestMessage(repeated(0x8e))
    evidence.scanSummary.marker = runtimeKnownObservation(
      code: "git_marker_known", summary: "Git marker is an ordinary directory.",
      digestByte: 0x8f)
    evidence.scanSummary.knownMarkerKind = .ordinaryDirectory
    evidence.scanSummary.registration.worktreeIdentity = runtimeIdentity(
      device: 1, fileID: 101, kind: .directory, digestByte: 0x90)
    evidence.scanSummary.registration.administrativeDirectoryIdentity = runtimeIdentity(
      device: 1, fileID: 102, kind: .directory, digestByte: 0x91)
    evidence.scanSummary.registration.commonDirectoryIdentity = runtimeIdentity(
      device: 1, fileID: 103, kind: .directory, digestByte: 0x92)
    evidence.scanSummary.registration.registrationSha256 = digestMessage(repeated(0x93))
    evidence.scanSummary.registration.metadataSha256 = digestMessage(repeated(0x94))
    evidence.scanSummary.changes.ignored = 2
    evidence.scanSummary.changes.streamedChangeSetSha256 = digestMessage(repeated(0x95))
    evidence.scanSummary.changes.maximumStatusRecords =
      PlanProjectionWireEncoder.maximumGitStatusRecordCount
    evidence.scanSummary.knownLinkageKind = .ordinary
    evidence.scanSummary.knownNestedRepositories = .absent
    evidence.scanSummary.knownSubmodules = .absent
    evidence.scanSummary.knownSparseCheckout = .absent
    evidence.scanSummary.commandCoverage = runtimeCompleteCoverage(digestByte: 0x96)
    return evidence
  }

  private static func runtimeCodexEvidence() -> Diskplan_V1_CodexCleanupScopeEvidenceProjection {
    var evidence = Diskplan_V1_CodexCleanupScopeEvidenceProjection()
    evidence.provenanceKind = .configuredBoundScope
    evidence.cleanupScopeID.value = Data("codex-temporary-v1".utf8)
    evidence.provenance = runtimeKnownObservation(
      code: "configured_scope", summary: "Cleanup scope is configured and bound.",
      digestByte: 0x71)
    evidence.boundRootIdentity = runtimeKnownObservation(
      code: "codex_root_known", summary: "Cleanup root identity is bound.", digestByte: 0x72)
    evidence.knownBoundRootIdentity = runtimeIdentity(
      device: 1, fileID: 201, kind: .directory, digestByte: 0x73)
    evidence.helperCapability = runtimeKnownObservation(
      code: "codex_helper_available", summary: "Cleanup helper is available.",
      digestByte: 0x74)
    evidence.knownHelperCapability = .available
    evidence.coverage = runtimeCompleteCoverage(digestByte: 0x75)
    evidence.scopeBindingSha256 = digestMessage(repeated(0x76))
    return evidence
  }

  private static func runtimeVersionedArtifactEvidence()
    -> Diskplan_V1_VersionedArtifactEvidenceProjection
  {
    var evidence = Diskplan_V1_VersionedArtifactEvidenceProjection()
    evidence.artifactKindID.value = Data("fixture-runtime".utf8)
    evidence.versionID.value = Data([0xff, 0x76, 0x31])
    evidence.inventoryCoverage = runtimeKnownObservation(
      code: "version_inventory_known", summary: "Version inventory is complete.",
      digestByte: 0x61)
    evidence.activeState = .candidateInactive
    evidence.survivorState = .otherSurvivor
    evidence.survivorEvidenceID.value = repeated(0x62)
    evidence.observedVersionCount = 2
    evidence.metadataCompleteCount = 2
    evidence.activeVersionCount = 1
    evidence.survivorCount = 1
    evidence.maximumVersionCount = PlanProjectionWireEncoder.maximumVersionedArtifactCount
    evidence.bundleSha256 = digestMessage(repeated(0x63))
    evidence.provenanceKind = .configuredBoundScope
    evidence.configuredScopeID.value = Data("fixture-runtime-scope".utf8)
    evidence.provenance = runtimeKnownObservation(
      code: "configured_scope", summary: "Version scope is configured and bound.",
      digestByte: 0x64)
    evidence.installRootIdentity = runtimeKnownObservation(
      code: "install_root_known", summary: "Install root identity is bound.", digestByte: 0x65)
    evidence.knownInstallRootIdentity = runtimeIdentity(
      device: 1, fileID: 301, kind: .directory, digestByte: 0x66)
    evidence.activeSelector = runtimeKnownObservation(
      code: "active_selector_known", summary: "Active selector is bound.", digestByte: 0x67)
    evidence.knownActiveSelectorIdentity = runtimeIdentity(
      device: 1, fileID: 302, kind: .symbolicLink, digestByte: 0x68)
    evidence.rawActiveSelectorTarget = Data([0xfe, 0x76, 0x32])
    evidence.survivorSet = runtimeKnownObservation(
      code: "survivor_set_known", summary: "Survivor set is authoritative.", digestByte: 0x69)
    evidence.survivorSetSha256 = digestMessage(repeated(0x6a))
    evidence.currentUpdateMarker = runtimeKnownObservation(
      code: "update_marker_known", summary: "No update is in progress.", digestByte: 0x6b)
    evidence.currentUpdateInProgress = false
    evidence.coverage = runtimeCompleteCoverage(digestByte: 0x6c)
    return evidence
  }

  private static func runtimeIdentity(
    device: UInt64,
    fileID: UInt64,
    kind: Diskplan_V1_EvidenceObjectKindProjection,
    digestByte: UInt8
  ) -> Diskplan_V1_EvidenceObjectIdentityProjection {
    var identity = Diskplan_V1_EvidenceObjectIdentityProjection()
    identity.device = device
    identity.fileID = fileID
    identity.kind = kind
    identity.bindingSha256 = digestMessage(repeated(digestByte))
    return identity
  }

  private static func runtimeCompleteCoverage(
    digestByte: UInt8
  ) -> Diskplan_V1_EvidenceCoverageProjection {
    var coverage = Diskplan_V1_EvidenceCoverageProjection()
    coverage.completeness = .complete
    coverage.bindingSha256 = digestMessage(repeated(digestByte))
    return coverage
  }

  private static func runtimeRevalidation(
    includeAction: Bool,
    actionID: Data
  ) -> Diskplan_V1_RevalidationProjectionPayload {
    var revalidation = Diskplan_V1_RevalidationProjectionPayload()
    if includeAction {
      var outcome = Diskplan_V1_ActionRevalidationProjection()
      outcome.actionID = opaque(actionID)
      outcome.current = true
      revalidation.actionOutcomes = [outcome]
    }
    return revalidation
  }

  private static func runtimeExecution(
    review: Diskplan_V1_ApplyReviewProjection,
    actionID: Data,
    includeAction: Bool,
    requiresForce: Bool,
    adapter: Diskplan_V1_PlanActionKind
  ) throws -> [Diskplan_V1_ExecutionStreamEvent] {
    let executionID = opaque(Data("fixture-execution".utf8))
    var started = Diskplan_V1_ApplyStartedProjection()
    started.epoch = review.epoch
    started.applyReviewID = review.applyReviewID
    started.projectionID = review.projectionID
    started.planSha256 = review.planSha256
    started.overlayID = review.overlayID
    started.overlaySha256 = review.overlaySha256
    started.reviewBindingSha256 = review.reviewBindingSha256
    started.selectedActionCount = review.selectedActionCount
    started.planID = review.planID
    started.evidenceID = review.evidenceID
    started.evidenceSha256 = review.evidenceSha256
    started.currentBindingSha256 = review.currentBindingSha256
    started.revalidationSha256 = review.revalidationSha256
    started.overlayRevision = review.overlayRevision
    started.scanSessionID = review.scanSessionID
    started.scanCheckpointID = review.scanCheckpointID
    started.scanCheckpointEvidenceSha256 = review.scanCheckpointEvidenceSha256
    var events = [executionEvent(id: executionID, body: .applyStarted(started))]
    if includeAction {
      if requiresForce {
        var warning = Diskplan_V1_ForceRequiredWarningProjection()
        warning.actionID = opaque(actionID)
        warning.preview = runtimePreview(adapter: adapter)
        events.append(executionEvent(id: executionID, body: .forceRequiredWarning(warning)))
      }
      var unit = Diskplan_V1_ExecutionUnitProjection()
      unit.unit = .actionID(opaque(actionID))
      var unitStarted = Diskplan_V1_UnitStartedProjection()
      unitStarted.unit = unit
      events.append(executionEvent(id: executionID, body: .unitStarted(unitStarted)))
      var step = Diskplan_V1_ExecutionStepFinishedProjection()
      step.actionID = opaque(actionID)
      step.status = .succeeded
      step.adapterOutcome.kind = .succeeded
      step.postVerification.kind = .satisfied
      step.postVerification.code = "target_absent"
      events.append(executionEvent(id: executionID, body: .stepFinished(step)))
      var finished = Diskplan_V1_UnitFinishedProjection()
      finished.unit = unit
      finished.status = .succeeded
      events.append(executionEvent(id: executionID, body: .unitFinished(finished)))
    }
    var terminal = Diskplan_V1_ApplyFinishedProjection()
    terminal.applyReviewID = review.applyReviewID
    terminal.reviewBindingSha256 = review.reviewBindingSha256
    events.append(executionEvent(id: executionID, body: .applyFinished(terminal)))
    return try SealedRuntimeWire.sealExecutionStream(
      events,
      requiredForceWarningActionIDs: review.forceWarningActionIds
    )
  }

  private static func executionEvent(
    id: Diskplan_V1_OpaqueIdentifier,
    body: Diskplan_V1_ExecutionStreamEvent.OneOf_Body
  ) -> Diskplan_V1_ExecutionStreamEvent {
    var event = Diskplan_V1_ExecutionStreamEvent()
    event.executionID = id
    event.body = body
    return event
  }

  private static func runtimePreview(
    adapter: Diskplan_V1_PlanActionKind
  ) -> Diskplan_V1_ActionExecutionPreviewProjection {
    var preview = Diskplan_V1_ActionExecutionPreviewProjection()
    var rawPath = Data("/fixture/".utf8)
    rawPath.append(contentsOf: [0xff, 0x61])
    preview.adapter = adapter
    preview.rawExecutable = Data("/bin/rm".utf8)
    preview.rawArgv = [Data("rm".utf8), Data("--".utf8), rawPath]
    preview.displayArgv = ["rm", "--", "/fixture/\\xffa"]
    preview.postcondition = "target_absent"
    preview.mutationSupported = true
    return preview
  }

  private static func runtimeActionKind(
    _ raw: String?
  ) throws -> Diskplan_V1_PlanActionKind {
    switch raw ?? "generic_remove" {
    case "generic_remove": .genericRemove
    case "git_worktree_remove": .gitWorktreeRemove
    case "codex_clean_temporary": .codexCleanTemporary
    case "versioned_artifact_remove": .versionedArtifactRemove
    case let value: throw GeneratorError.invalidRuntimeActionKind(value)
    }
  }

  private static func runtimeEpoch() -> Diskplan_V1_ExecutionEpochProjection {
    var epoch = Diskplan_V1_ExecutionEpochProjection()
    epoch.epochID.value = Data("fixture-epoch".utf8)
    epoch.semanticReferenceTimeSeconds = 1_700_000_000
    epoch.issuedAtSeconds = 1_700_000_001
    epoch.deadlineSeconds = 1_700_000_061
    return epoch
  }

  private static func opaque(_ value: Data) -> Diskplan_V1_OpaqueIdentifier {
    var result = Diskplan_V1_OpaqueIdentifier()
    result.value = value
    return result
  }

  private static func digestMessage(_ value: Data) -> Diskplan_V1_Digest256 {
    var result = Diskplan_V1_Digest256()
    result.value = value
    return result
  }

  private static func repeated(_ value: UInt8) -> Data { Data(repeating: value, count: 32) }

  private static func framed(_ envelope: Diskplan_V1_Envelope) throws -> Data {
    let payload = try envelope.serializedData()
    var frame = Data()
    appendBigEndian(UInt32(payload.count), to: &frame)
    frame.append(payload)
    return frame
  }

  private static func frames(for fixture: FixtureCase) throws -> [Data] {
    var checkpoint = Diskplan_V1_ScanCheckpointEvidence()
    checkpoint.profile = "full-audit"
    checkpoint.resolverVersion = 1
    checkpoint.retainedNodeCount = 10_000
    checkpoint.maximumDepth = 128
    checkpoint.coverage.complete = fixture.terminal == "finalized"
    checkpoint.coverage.reasons = fixture.terminal == "finalized" ? [] : ["subtree_incomplete"]
    checkpoint.machineState = fixture.terminal == "finalized" ? .complete : .scanning
    checkpoint.resumableInProcess = fixture.terminal == "ready"
    checkpoint.progress.profile = "full-audit"
    checkpoint.progress.retainedNodes = UInt64(fixture.nodeComponentsHex.count)
    checkpoint.progress.structuralBudget = 10_000
    checkpoint.retainedNodes = try fixture.nodeComponentsHex.enumerated().map { index, components in
      var node = Diskplan_V1_ScannedNodeEvidence()
      node.path.rootID = "fixture-root"
      node.path.components = try components.map(data(hex:))
      node.path.displayPath = "/fixture/node-\(index)"
      return node
    }
    let encoded = try CheckpointWireEncoder.encode(
      checkpoint,
      chunkPayloadTargetBytes: fixture.chunkPayloadTargetBytes
    )
    var bodies = encoded.chunks.map(Diskplan_V1_EngineEvent.OneOf_Body.scanCheckpointChunk)
    switch fixture.terminal {
    case "ready":
      var ready = Diskplan_V1_ScanCheckpointReady()
      ready.canonicalCheckpointPayload = encoded.checkpointPayload
      ready.manifest = encoded.manifest
      bodies.append(.scanCheckpointReady(ready))
    case "finalized":
      var finalized = Diskplan_V1_ScanFinalized()
      finalized.reason = "fixture finalized"
      finalized.canonicalCheckpointPayload = encoded.checkpointPayload
      finalized.manifest = encoded.manifest
      bodies.append(.scanFinalized(finalized))
    default:
      throw GeneratorError.invalidTerminal(fixture.terminal)
    }
    return try bodies.enumerated().map { index, body in
      let sequence = UInt64(index + 1)
      var event = Diskplan_V1_EngineEvent()
      event.eventSequence = sequence
      event.scanSessionID = "fixture-session"
      event.body = body
      var envelope = Diskplan_V1_Envelope()
      envelope.sequence = sequence
      envelope.body = .engineEvent(event)
      let payload = try envelope.serializedData()
      var frame = Data()
      appendBigEndian(UInt32(payload.count), to: &frame)
      frame.append(payload)
      return frame
    }
  }

  private static func data(hex: String) throws -> Data {
    guard hex.count.isMultiple(of: 2) else { throw GeneratorError.invalidHex(hex) }
    var data = Data()
    var index = hex.startIndex
    while index < hex.endIndex {
      let end = hex.index(index, offsetBy: 2)
      guard let byte = UInt8(hex[index..<end], radix: 16) else {
        throw GeneratorError.invalidHex(hex)
      }
      data.append(byte)
      index = end
    }
    return data
  }

  private static func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
  }

  private static func appendBigEndian(_ value: UInt32, to output: inout Data) {
    withUnsafeBytes(of: value.bigEndian) { output.append(contentsOf: $0) }
  }
}
