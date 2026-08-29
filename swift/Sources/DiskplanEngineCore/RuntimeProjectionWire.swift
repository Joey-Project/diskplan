import CryptoKit
import DiskplanProto
import Foundation

package enum RuntimeProjectionWireError: Error, Equatable, CustomStringConvertible {
  case countOverflow(field: String)
  case digestLength(field: String, actual: Int)
  case duplicateIdentifier(field: String)
  case invalidIdentifier(field: String)
  case invalidRecord(index: UInt64, reason: String)
  case recordCountExceedsMaximum(actual: Int, maximum: Int)
  case recordPayloadTooLarge(actual: UInt64, maximum: UInt64)
  case recordTooLarge(actual: Int, maximum: Int)
  case manifestTooLarge(actual: Int, maximum: Int)

  package var description: String {
    switch self {
    case .countOverflow(let field):
      "runtime projection \(field) exceeds the protocol integer range"
    case .digestLength(let field, let actual):
      "runtime projection \(field) is \(actual) bytes; expected 32"
    case .duplicateIdentifier(let field):
      "runtime projection contains a duplicate \(field)"
    case .invalidIdentifier(let field):
      "runtime projection contains an invalid \(field)"
    case .invalidRecord(let index, let reason):
      "runtime projection record \(index) is invalid: \(reason)"
    case .recordCountExceedsMaximum(let actual, let maximum):
      "runtime projection has \(actual) records; maximum is \(maximum)"
    case .recordPayloadTooLarge(let actual, let maximum):
      "runtime projection payload is \(actual) bytes; maximum is \(maximum)"
    case .recordTooLarge(let actual, let maximum):
      "runtime projection record is \(actual) bytes; chunk maximum is \(maximum)"
    case .manifestTooLarge(let actual, let maximum):
      "runtime projection manifest is \(actual) bytes; maximum is \(maximum)"
    }
  }
}

public struct PlanProjectionWireMetadata: Equatable, Sendable {
  public let scanSessionID: Data
  public let scanCheckpointID: Data
  public let scanCheckpointEvidenceSHA256: Data
  public let planSHA256: Data
  public let evidenceSHA256: Data
  public let cleanupCandidateCount: UInt64
  public let policyVersion: String
  public let schemaVersion: String

  public init(
    scanSessionID: Data,
    scanCheckpointID: Data,
    scanCheckpointEvidenceSHA256: Data,
    planSHA256: Data,
    evidenceSHA256: Data,
    cleanupCandidateCount: UInt64,
    policyVersion: String,
    schemaVersion: String
  ) {
    self.scanSessionID = scanSessionID
    self.scanCheckpointID = scanCheckpointID
    self.scanCheckpointEvidenceSHA256 = scanCheckpointEvidenceSHA256
    self.planSHA256 = planSHA256
    self.evidenceSHA256 = evidenceSHA256
    self.cleanupCandidateCount = cleanupCandidateCount
    self.policyVersion = policyVersion
    self.schemaVersion = schemaVersion
  }
}

package struct EncodedPlanProjectionWire {
  package let chunks: [Diskplan_V1_PlanProjectionChunk]
  package let manifest: Diskplan_V1_PlanProjectionManifest
}

/// Pure transport sealing for an already engine-authored plan projection.
///
/// This encoder never classifies a target, chooses stageability, constructs an
/// adapter, or derives argv. Those values must already be present in records
/// projected by the authoritative policy/execution composition layer.
package enum PlanProjectionWireEncoder {
  package static let manifestVersion: UInt32 = 1
  package static let maximumRecordCount = 100_000
  package static let maximumRecordPayloadBytes: UInt64 = 768 * 1_024 * 1_024
  package static let maximumChunkPayloadBytes = 4 * 1_024 * 1_024
  package static let maximumManifestEncodedBytes = 2 * 1_024 * 1_024
  package static let maximumOpaqueIdentifierBytes = 256
  package static let maximumNamespaceAncestorCount: UInt32 = 1_024
  package static let maximumGitStatusRecordCount: UInt64 = 50_000
  package static let maximumVersionedArtifactCount: UInt64 = 4_096
  package static let maximumRawSelectorTargetBytes = 4_096

  private static let chunkIDDomain = Data("diskplan/plan-projection-chunk-id/v1\0".utf8)
  private static let finalDigestDomain = Data("diskplan/plan-projection-final/v1\0".utf8)

  package static func encode(
    records: [Diskplan_V1_PlanProjectionRecord],
    metadata: PlanProjectionWireMetadata,
    chunkPayloadTargetBytes: Int = maximumChunkPayloadBytes
  ) throws -> EncodedPlanProjectionWire {
    try requireNonempty(metadata.scanSessionID, field: "scan_session_id")
    try requireNonempty(metadata.scanCheckpointID, field: "scan_checkpoint_id")
    try requireDigest(
      metadata.scanCheckpointEvidenceSHA256,
      field: "scan_checkpoint_evidence_sha256"
    )
    try requireDigest(metadata.planSHA256, field: "plan_sha256")
    try requireDigest(metadata.evidenceSHA256, field: "evidence_sha256")
    guard metadata.scanCheckpointID == lowercaseHexData(metadata.evidenceSHA256) else {
      throw RuntimeProjectionWireError.invalidIdentifier(field: "scan_checkpoint_id")
    }
    guard !metadata.policyVersion.isEmpty else {
      throw RuntimeProjectionWireError.invalidIdentifier(field: "policy_version")
    }
    guard !metadata.schemaVersion.isEmpty else {
      throw RuntimeProjectionWireError.invalidIdentifier(field: "schema_version")
    }
    guard records.count <= maximumRecordCount else {
      throw RuntimeProjectionWireError.recordCountExceedsMaximum(
        actual: records.count,
        maximum: maximumRecordCount
      )
    }
    guard chunkPayloadTargetBytes > 0,
      chunkPayloadTargetBytes <= maximumChunkPayloadBytes
    else {
      throw RuntimeProjectionWireError.recordTooLarge(
        actual: chunkPayloadTargetBytes,
        maximum: maximumChunkPayloadBytes
      )
    }

    let summary = try validateAndSummarize(records)
    guard metadata.cleanupCandidateCount <= summary.actionCount else {
      throw RuntimeProjectionWireError.invalidIdentifier(field: "cleanup_candidate_count")
    }
    let payloads = try chunkedRecordPayloads(
      records,
      chunkPayloadTargetBytes: chunkPayloadTargetBytes
    )
    var descriptors: [Diskplan_V1_PlanProjectionChunkDescriptor] = []
    var chunks: [Diskplan_V1_PlanProjectionChunk] = []
    descriptors.reserveCapacity(payloads.count)
    chunks.reserveCapacity(payloads.count)
    var totalPayloadBytes: UInt64 = 0

    for (index, payload) in payloads.enumerated() {
      guard let chunkIndex = UInt32(exactly: index) else {
        throw RuntimeProjectionWireError.countOverflow(field: "chunk_count")
      }
      totalPayloadBytes = try addingExact(
        totalPayloadBytes,
        UInt64(payload.data.count),
        field: "record_payload_bytes"
      )
      guard totalPayloadBytes <= maximumRecordPayloadBytes else {
        throw RuntimeProjectionWireError.recordPayloadTooLarge(
          actual: totalPayloadBytes,
          maximum: maximumRecordPayloadBytes
        )
      }
      let payloadDigest = digest(payload.data)
      let chunkIdentifier = chunkID(index: chunkIndex, payloadDigest: payloadDigest)

      var descriptor = Diskplan_V1_PlanProjectionChunkDescriptor()
      descriptor.chunkIndex = chunkIndex
      descriptor.chunkID = opaque(chunkIdentifier)
      descriptor.recordCount = payload.recordCount
      descriptor.payloadBytes = UInt64(payload.data.count)
      descriptor.payloadSha256 = digestMessage(payloadDigest)
      descriptors.append(descriptor)

      var chunk = Diskplan_V1_PlanProjectionChunk()
      chunk.chunkIndex = chunkIndex
      chunk.chunkID = opaque(chunkIdentifier)
      chunk.recordCount = payload.recordCount
      chunk.canonicalRecordPayload = payload.data
      chunk.payloadSha256 = digestMessage(payloadDigest)
      chunks.append(chunk)
    }

    guard let chunkCount = UInt32(exactly: chunks.count) else {
      throw RuntimeProjectionWireError.countOverflow(field: "chunk_count")
    }
    var manifest = Diskplan_V1_PlanProjectionManifest()
    manifest.manifestVersion = manifestVersion
    manifest.planSha256 = digestMessage(metadata.planSHA256)
    manifest.evidenceSha256 = digestMessage(metadata.evidenceSHA256)
    manifest.policyVersion = metadata.policyVersion
    manifest.schemaVersion = metadata.schemaVersion
    manifest.chunkCount = chunkCount
    manifest.recordCount = UInt64(records.count)
    manifest.actionCount = summary.actionCount
    manifest.targetCount = summary.targetCount
    manifest.releaseSetCount = summary.releaseSetCount
    manifest.blockerCount = summary.blockerCount
    manifest.waiverCount = summary.waiverCount
    manifest.recordPayloadBytes = totalPayloadBytes
    manifest.maximumRecordCount = UInt64(maximumRecordCount)
    manifest.maximumRecordPayloadBytes = maximumRecordPayloadBytes
    manifest.maximumChunkPayloadBytes = UInt32(maximumChunkPayloadBytes)
    manifest.maximumManifestEncodedBytes = UInt32(maximumManifestEncodedBytes)
    manifest.chunks = descriptors
    manifest.dispositionCounts = summary.dispositionCounts
    manifest.recommendationCounts = summary.recommendationCounts
    manifest.cleanupCandidateCount = metadata.cleanupCandidateCount
    manifest.scanSessionID = opaque(metadata.scanSessionID)
    manifest.scanCheckpointID = opaque(metadata.scanCheckpointID)
    manifest.planID = opaque(metadata.planSHA256)
    manifest.evidenceID = opaque(metadata.evidenceSHA256)
    manifest.scanCheckpointEvidenceSha256 = digestMessage(metadata.scanCheckpointEvidenceSHA256)
    let projectionDigest = finalDigest(manifest)
    manifest.projectionID = opaque(projectionDigest)
    manifest.projectionSha256 = digestMessage(projectionDigest)
    for index in chunks.indices {
      chunks[index].projectionID = manifest.projectionID
    }
    let encodedManifestBytes = try manifest.serializedData().count
    guard encodedManifestBytes <= maximumManifestEncodedBytes else {
      throw RuntimeProjectionWireError.manifestTooLarge(
        actual: encodedManifestBytes,
        maximum: maximumManifestEncodedBytes
      )
    }
    return EncodedPlanProjectionWire(chunks: chunks, manifest: manifest)
  }

  private struct Summary {
    let actionCount: UInt64
    let targetCount: UInt64
    let releaseSetCount: UInt64
    let blockerCount: UInt64
    let waiverCount: UInt64
    let dispositionCounts: [Diskplan_V1_PlanDispositionCount]
    let recommendationCounts: [Diskplan_V1_PlanRecommendationCount]
  }

  private static func validateAndSummarize(
    _ records: [Diskplan_V1_PlanProjectionRecord]
  ) throws -> Summary {
    var actions: [Data: Diskplan_V1_PlanActionProjection] = [:]
    var targets: [Data: Diskplan_V1_PlanTargetProjection] = [:]
    var releaseSets: [Data: Diskplan_V1_PlanReleaseSetProjection] = [:]
    var blockerCount: UInt64 = 0
    var waiverCount: UInt64 = 0
    var dispositions: [Int: UInt64] = [:]
    var recommendations: [Int: UInt64] = [:]

    for (offset, record) in records.enumerated() {
      let index = UInt64(offset)
      guard record.recordIndex == index else {
        throw RuntimeProjectionWireError.invalidRecord(
          index: record.recordIndex,
          reason: "record_index is not contiguous"
        )
      }
      switch record.body {
      case .action(let action):
        try validateAction(action, index: index)
        try insertUnique(action.actionID.value, value: action, into: &actions, field: "action_id")
        blockerCount = try addingExact(
          blockerCount, UInt64(action.blockers.count), field: "blocker_count")
        waiverCount = try addingExact(
          waiverCount, UInt64(action.requiredWaivers.count), field: "waiver_count")
        dispositions[action.disposition.rawValue, default: 0] += 1
        recommendations[action.recommendation.rawValue, default: 0] += 1
      case .target(let target):
        try validateTarget(target, index: index)
        try insertUnique(target.targetID.value, value: target, into: &targets, field: "target_id")
      case .releaseSet(let releaseSet):
        try validateReleaseSet(releaseSet, index: index)
        try insertUnique(
          releaseSet.releaseSetID.value,
          value: releaseSet,
          into: &releaseSets,
          field: "release_set_id"
        )
        blockerCount = try addingExact(
          blockerCount, UInt64(releaseSet.blockers.count), field: "blocker_count")
      case nil:
        throw RuntimeProjectionWireError.invalidRecord(index: index, reason: "missing body")
      }
    }

    try validateReferences(actions: actions, targets: targets, releaseSets: releaseSets)
    let dispositionValues: [Diskplan_V1_PlanDisposition] = [
      .ready, .conditional, .needsReview, .blocked, .keepInformational,
    ]
    let recommendationValues: [Diskplan_V1_PlanRecommendation] = [
      .safeToClean, .safeAfterExit, .likelyRebuildable, .needsSemanticReview,
      .managedByProvider, .keep, .scanIncomplete, .classificationConflict,
    ]
    let dispositionCounts = dispositionValues.map { value in
      var row = Diskplan_V1_PlanDispositionCount()
      row.disposition = value
      row.actionCount = dispositions[value.rawValue, default: 0]
      return row
    }
    let recommendationCounts = recommendationValues.map { value in
      var row = Diskplan_V1_PlanRecommendationCount()
      row.recommendation = value
      row.actionCount = recommendations[value.rawValue, default: 0]
      return row
    }
    return Summary(
      actionCount: UInt64(actions.count),
      targetCount: UInt64(targets.count),
      releaseSetCount: UInt64(releaseSets.count),
      blockerCount: blockerCount,
      waiverCount: waiverCount,
      dispositionCounts: dispositionCounts,
      recommendationCounts: recommendationCounts
    )
  }

  private static func validateAction(
    _ action: Diskplan_V1_PlanActionProjection,
    index: UInt64
  ) throws {
    try requireDigest(action.actionID.value, field: "action_id")
    try requireDigest(action.actionLineageID.value, field: "action_lineage_id")
    guard validDisposition(action.disposition), validActionKind(action.kind),
      validStageability(action.stageability), validActivity(action.activity),
      validRecoverability(action.recoverability), validPathRace(action.pathRace),
      validRecommendation(action.recommendation),
      !action.kindLabel.isEmpty, !action.label.isEmpty
    else {
      throw RuntimeProjectionWireError.invalidRecord(
        index: index,
        reason: "missing typed action projection"
      )
    }
    if action.requiresForce && action.forceReason.isEmpty {
      throw RuntimeProjectionWireError.invalidRecord(
        index: index,
        reason: "force requirement has no reason"
      )
    }
    if action.stageability == .requiresWaivers && action.requiredWaivers.isEmpty {
      throw RuntimeProjectionWireError.invalidRecord(
        index: index,
        reason: "waiver stageability has no waiver"
      )
    }
    if action.stageability != .requiresWaivers && !action.requiredWaivers.isEmpty {
      throw RuntimeProjectionWireError.invalidRecord(
        index: index,
        reason: "waivers are present for a non-waiver stageability"
      )
    }
    try requireUnique(action.targetIds.map(\.value), field: "action target_id")
    try requireUnique(action.releaseSetIds.map(\.value), field: "action release_set_id")
    try requireUnique(
      action.prerequisites.map { $0.actionID.value }, field: "prerequisite action_id")
    try requireUnique(action.blockers.map { $0.blockerID.value }, field: "action blocker_id")
    try requireUnique(action.requiredWaivers.map { $0.waiverID.value }, field: "action waiver_id")
    try validateByteEstimate(action.immediateReclaim, index: index)
    try validateByteEstimate(action.sharedUnlock, index: index)
    for evidence in action.evidence {
      guard validEvidenceStatus(evidence.status), !evidence.code.isEmpty, !evidence.summary.isEmpty
      else {
        throw RuntimeProjectionWireError.invalidRecord(
          index: index,
          reason: "invalid evidence summary"
        )
      }
    }
    for waiver in action.requiredWaivers {
      try requireNonempty(waiver.waiverID.value, field: "waiver_id")
      try requireDigest(waiver.semanticEvidenceSha256.value, field: "semantic_evidence_sha256")
      guard validWaiverKind(waiver.kind), !waiver.predicate.isEmpty else {
        throw RuntimeProjectionWireError.invalidRecord(index: index, reason: "invalid waiver")
      }
    }
    for blocker in action.blockers {
      try validateBlocker(blocker, index: index)
    }
    for prerequisite in action.prerequisites {
      try requireDigest(prerequisite.actionID.value, field: "prerequisite action_id")
      guard prerequisite.actionID.value != action.actionID.value else {
        throw RuntimeProjectionWireError.invalidRecord(index: index, reason: "self prerequisite")
      }
    }
    try validatePreview(action.executionPreview, actionKind: action.kind, index: index)
    try validateSafetyEvidence(action.safetyEvidence, actionKind: action.kind, index: index)
  }

  private static func validateSafetyEvidence(
    _ evidence: Diskplan_V1_PlanSafetyEvidenceProjection,
    actionKind: Diskplan_V1_PlanActionKind,
    index: UInt64
  ) throws {
    try requireDigest(evidence.policyEvidenceSha256.value, field: "policy_evidence_sha256")
    guard evidence.hasNamespaceAccess, evidence.hasContentBaseline else {
      throw invalidSafetyVariant(index)
    }
    let namespace = evidence.namespaceAccess
    try validateObservation(namespace.targetAccessPolicy, index: index)
    try validateObservation(namespace.targetAclDigest, index: index)
    try validateObservation(namespace.rootAccessPolicy, index: index)
    try validateObservation(namespace.rootAclDigest, index: index)
    try validateObservation(namespace.ancestorAccessPolicyChain, index: index)
    try validateObservation(namespace.rootAccessPolicySeal, index: index)
    try validateObservation(namespace.ancestorAccessPolicySeal, index: index)
    try requireDigest(namespace.namespaceBindingSha256.value, field: "namespace_binding_sha256")
    guard namespace.maximumAncestorCount == maximumNamespaceAncestorCount,
      namespace.ancestorCount <= namespace.maximumAncestorCount
    else { throw invalidSafetyVariant(index) }

    let content = evidence.contentBaseline
    try validateObservation(content.observation, index: index)
    if content.observation.status == .known {
      guard (1...2).contains(content.knownKind.rawValue) else {
        throw invalidSafetyVariant(index)
      }
      switch content.knownKind {
      case .requiredDigest:
        guard content.notApplicableReason == .unspecified else {
          throw invalidSafetyVariant(index)
        }
      case .explicitlyNotApplicable:
        guard content.logicalBytes == 0,
          (1...5).contains(content.notApplicableReason.rawValue)
        else { throw invalidSafetyVariant(index) }
      case .unspecified, .UNRECOGNIZED:
        throw invalidSafetyVariant(index)
      }
    } else if content.knownKind != .unspecified || content.logicalBytes != 0
      || content.notApplicableReason != .unspecified
    {
      throw invalidSafetyVariant(index)
    }

    switch actionKind {
    case .gitWorktreeRemove, .gitWorktreeDiscardLocalChanges:
      guard evidence.hasGitWorktree, !evidence.hasCodexCleanupScope,
        !evidence.hasVersionedArtifact
      else { throw invalidSafetyVariant(index) }
      try validateGitEvidence(evidence.gitWorktree, index: index)
    case .codexCleanTemporary:
      guard !evidence.hasGitWorktree, evidence.hasCodexCleanupScope,
        !evidence.hasVersionedArtifact
      else { throw invalidSafetyVariant(index) }
      try validateCodexEvidence(evidence.codexCleanupScope, index: index)
    case .versionedArtifactRemove:
      guard !evidence.hasGitWorktree, !evidence.hasCodexCleanupScope,
        evidence.hasVersionedArtifact
      else { throw invalidSafetyVariant(index) }
      try validateVersionedArtifactEvidence(evidence.versionedArtifact, index: index)
    case .genericRemove, .completeReleaseSetRemove, .reportOnly:
      guard !evidence.hasGitWorktree, !evidence.hasCodexCleanupScope,
        !evidence.hasVersionedArtifact
      else { throw invalidSafetyVariant(index) }
    case .unspecified, .UNRECOGNIZED:
      throw invalidSafetyVariant(index)
    }
  }

  package static func validateSafetyEvidenceForTesting(
    _ evidence: Diskplan_V1_PlanSafetyEvidenceProjection,
    actionKind: Diskplan_V1_PlanActionKind
  ) throws {
    try validateSafetyEvidence(evidence, actionKind: actionKind, index: 0)
  }

  package static func validateRawSelectorTargetForTesting(_ target: Data) throws {
    guard !target.isEmpty,
      target.count <= maximumRawSelectorTargetBytes,
      !target.contains(0), !target.contains(47),
      target != Data(".".utf8), target != Data("..".utf8)
    else { throw RuntimeProjectionWireError.invalidIdentifier(field: "raw selector target") }
  }

  private static func validateGitEvidence(
    _ evidence: Diskplan_V1_GitWorktreeEvidenceProjection,
    index: UInt64
  ) throws {
    try requireDigest(evidence.bundleSha256.value, field: "git bundle_sha256")
    for observation in [
      evidence.noFollowTraversalComplete, evidence.headIdentity, evidence.indexDigest,
      evidence.localChanges, evidence.registration, evidence.linkage,
      evidence.sparseCheckout, evidence.nestedRepositories, evidence.submodules,
      evidence.trustedExclusiveNamespace, evidence.postQuarantineCoverage,
      evidence.postDiscardSuccessor,
    ] {
      try validateObservation(observation, index: index)
    }
    guard evidence.hasScanSummary else { throw invalidSafetyVariant(index) }
    let scan = evidence.scanSummary
    try requireDigest(scan.bundleSha256.value, field: "git scan bundle_sha256")
    try validateObservation(scan.marker, index: index)
    try requireKnownEnum(
      observation: scan.marker,
      isSpecified: (1...3).contains(scan.knownMarkerKind.rawValue),
      index: index
    )
    guard (evidence.registration.status == .known) == scan.hasRegistration,
      (evidence.localChanges.status == .known) == scan.hasChanges
    else { throw invalidSafetyVariant(index) }
    if scan.hasRegistration {
      try validateDirectoryIdentity(scan.registration.worktreeIdentity, index: index)
      try validateDirectoryIdentity(
        scan.registration.administrativeDirectoryIdentity, index: index)
      try validateDirectoryIdentity(scan.registration.commonDirectoryIdentity, index: index)
      try requireDigest(scan.registration.registrationSha256.value, field: "registration_sha256")
      try requireDigest(scan.registration.metadataSha256.value, field: "metadata_sha256")
    }
    if scan.hasChanges {
      let changes = scan.changes
      let (first, overflow1) = changes.staged.addingReportingOverflow(changes.unstaged)
      let (second, overflow2) = first.addingReportingOverflow(changes.unmerged)
      let (third, overflow3) = second.addingReportingOverflow(changes.untracked)
      let (total, overflow4) = third.addingReportingOverflow(changes.ignored)
      guard !overflow1, !overflow2, !overflow3, !overflow4,
        changes.maximumStatusRecords == maximumGitStatusRecordCount,
        total <= changes.maximumStatusRecords
      else { throw invalidSafetyVariant(index) }
      try requireDigest(
        changes.streamedChangeSetSha256.value, field: "streamed_change_set_sha256")
    }
    try requireKnownEnum(
      observation: evidence.linkage,
      isSpecified: (1...2).contains(scan.knownLinkageKind.rawValue),
      index: index
    )
    if scan.knownLinkageKind == .linked {
      try requireDigest(scan.linkedRegistrationID.value, field: "linked_registration_id")
    } else if scan.hasLinkedRegistrationID {
      throw invalidSafetyVariant(index)
    }
    try requireKnownEnum(
      observation: evidence.nestedRepositories,
      isSpecified: (1...2).contains(scan.knownNestedRepositories.rawValue),
      index: index
    )
    try requireKnownEnum(
      observation: evidence.submodules,
      isSpecified: (1...2).contains(scan.knownSubmodules.rawValue),
      index: index
    )
    try requireKnownEnum(
      observation: evidence.sparseCheckout,
      isSpecified: (1...2).contains(scan.knownSparseCheckout.rawValue),
      index: index
    )
    try validateCoverage(scan.commandCoverage, index: index)
  }

  private static func validateVersionedArtifactEvidence(
    _ evidence: Diskplan_V1_VersionedArtifactEvidenceProjection,
    index: UInt64
  ) throws {
    try requireNonempty(evidence.artifactKindID.value, field: "artifact_kind_id")
    try requireNonempty(evidence.versionID.value, field: "version_id")
    try validateObservation(evidence.inventoryCoverage, index: index)
    try validateObservation(evidence.provenance, index: index)
    try validateObservation(evidence.installRootIdentity, index: index)
    try validateObservation(evidence.activeSelector, index: index)
    try validateObservation(evidence.survivorSet, index: index)
    try validateObservation(evidence.currentUpdateMarker, index: index)
    try validateCoverage(evidence.coverage, index: index)
    try requireDigest(evidence.bundleSha256.value, field: "version bundle_sha256")
    try validateProvenance(
      evidence.provenanceKind,
      hasScopeID: evidence.hasConfiguredScopeID,
      index: index
    )
    guard evidence.provenance.status == .known else { throw invalidSafetyVariant(index) }
    if evidence.hasConfiguredScopeID {
      try requireNonempty(evidence.configuredScopeID.value, field: "configured_scope_id")
    }
    guard
      (evidence.installRootIdentity.status == .known)
        == evidence.hasKnownInstallRootIdentity,
      (evidence.activeSelector.status == .known)
        == evidence.hasKnownActiveSelectorIdentity
    else { throw invalidSafetyVariant(index) }
    if evidence.hasKnownInstallRootIdentity {
      try validateDirectoryIdentity(evidence.knownInstallRootIdentity, index: index)
    }
    if evidence.hasKnownActiveSelectorIdentity {
      try validateIdentity(evidence.knownActiveSelectorIdentity, index: index)
      do {
        try validateRawSelectorTargetForTesting(evidence.rawActiveSelectorTarget)
      } catch {
        throw invalidSafetyVariant(index)
      }
    } else if !evidence.rawActiveSelectorTarget.isEmpty {
      throw invalidSafetyVariant(index)
    }
    if evidence.survivorSet.status == .known {
      try requireDigest(evidence.survivorSetSha256.value, field: "survivor_set_sha256")
    } else if evidence.hasSurvivorSetSha256 {
      throw invalidSafetyVariant(index)
    }
    if evidence.currentUpdateMarker.status != .known,
      evidence.currentUpdateInProgress
    {
      throw invalidSafetyVariant(index)
    }
    guard evidence.maximumVersionCount == maximumVersionedArtifactCount,
      evidence.observedVersionCount <= evidence.maximumVersionCount,
      evidence.metadataCompleteCount <= evidence.observedVersionCount,
      evidence.activeVersionCount <= evidence.observedVersionCount,
      evidence.survivorCount <= evidence.observedVersionCount
    else { throw invalidSafetyVariant(index) }
    if evidence.inventoryCoverage.status == .known {
      guard (1...4).contains(evidence.activeState.rawValue),
        (1...5).contains(evidence.survivorState.rawValue)
      else { throw invalidSafetyVariant(index) }
    } else {
      guard evidence.activeState == .unspecified, evidence.survivorState == .unspecified,
        evidence.observedVersionCount == 0, evidence.activeVersionCount == 0,
        evidence.survivorCount == 0, !evidence.hasSurvivorEvidenceID
      else { throw invalidSafetyVariant(index) }
    }
    if evidence.survivorState == .otherSurvivor {
      try requireDigest(evidence.survivorEvidenceID.value, field: "survivor_evidence_id")
    } else if evidence.hasSurvivorEvidenceID {
      throw invalidSafetyVariant(index)
    }
    if evidence.provenanceKind == .typeHintOnly {
      guard evidence.coverage.completeness == .partial,
        evidence.survivorSet.status != .known,
        evidence.survivorState == .unspecified || evidence.survivorState == .unresolved
      else { throw invalidSafetyVariant(index) }
    }
  }

  private static func validateCodexEvidence(
    _ evidence: Diskplan_V1_CodexCleanupScopeEvidenceProjection,
    index: UInt64
  ) throws {
    try validateObservation(evidence.provenance, index: index)
    try validateObservation(evidence.boundRootIdentity, index: index)
    try validateObservation(evidence.helperCapability, index: index)
    try validateCoverage(evidence.coverage, index: index)
    try requireDigest(evidence.scopeBindingSha256.value, field: "scope_binding_sha256")
    try validateProvenance(
      evidence.provenanceKind,
      hasScopeID: evidence.hasCleanupScopeID,
      index: index
    )
    guard evidence.provenance.status == .known else { throw invalidSafetyVariant(index) }
    if evidence.hasCleanupScopeID {
      try requireNonempty(evidence.cleanupScopeID.value, field: "cleanup_scope_id")
    }
    guard
      (evidence.boundRootIdentity.status == .known)
        == evidence.hasKnownBoundRootIdentity
    else { throw invalidSafetyVariant(index) }
    if evidence.hasKnownBoundRootIdentity {
      try validateDirectoryIdentity(evidence.knownBoundRootIdentity, index: index)
    }
    try requireKnownEnum(
      observation: evidence.helperCapability,
      isSpecified: (1...2).contains(evidence.knownHelperCapability.rawValue),
      index: index
    )
    if evidence.provenanceKind == .typeHintOnly {
      guard evidence.coverage.completeness == .partial else {
        throw invalidSafetyVariant(index)
      }
    }
  }

  private static func validateObservation(
    _ observation: Diskplan_V1_EvidenceObservationProjection,
    index: UInt64
  ) throws {
    guard !observation.code.isEmpty, !observation.summary.isEmpty else {
      throw invalidSafetyVariant(index)
    }
    switch observation.status {
    case .known:
      guard observation.unknownReason == .unspecified, !observation.hasFailure,
        observation.hasValueSha256
      else { throw invalidSafetyVariant(index) }
      try requireDigest(observation.valueSha256.value, field: "observation value_sha256")
    case .absent:
      guard observation.unknownReason == .unspecified, !observation.hasFailure,
        !observation.hasValueSha256
      else { throw invalidSafetyVariant(index) }
    case .unknown:
      guard (1...6).contains(observation.unknownReason.rawValue), !observation.hasFailure,
        !observation.hasValueSha256
      else { throw invalidSafetyVariant(index) }
    case .unreadable, .failed:
      guard observation.unknownReason == .unspecified, observation.hasFailure,
        !observation.failure.code.isEmpty, !observation.failure.collector.isEmpty,
        !observation.hasValueSha256
      else { throw invalidSafetyVariant(index) }
    case .unspecified, .UNRECOGNIZED:
      throw invalidSafetyVariant(index)
    }
  }

  private static func validateCoverage(
    _ coverage: Diskplan_V1_EvidenceCoverageProjection,
    index: UInt64
  ) throws {
    try requireDigest(coverage.bindingSha256.value, field: "coverage binding_sha256")
    guard coverage.reasons.count <= 16 else { throw invalidSafetyVariant(index) }
    var previousRawValue: Int?
    for reason in coverage.reasons {
      guard (1...16).contains(reason.rawValue) else {
        throw invalidSafetyVariant(index)
      }
      if let previousRawValue, reason.rawValue <= previousRawValue {
        throw invalidSafetyVariant(index)
      }
      previousRawValue = reason.rawValue
    }
    switch coverage.completeness {
    case .complete:
      guard coverage.reasons.isEmpty else { throw invalidSafetyVariant(index) }
    case .partial:
      guard !coverage.reasons.isEmpty else { throw invalidSafetyVariant(index) }
    case .unspecified, .UNRECOGNIZED:
      throw invalidSafetyVariant(index)
    }
  }

  private static func validateIdentity(
    _ identity: Diskplan_V1_EvidenceObjectIdentityProjection,
    index: UInt64
  ) throws {
    guard (1...4).contains(identity.kind.rawValue) else {
      throw invalidSafetyVariant(index)
    }
    try requireDigest(identity.bindingSha256.value, field: "identity binding_sha256")
  }

  private static func validateDirectoryIdentity(
    _ identity: Diskplan_V1_EvidenceObjectIdentityProjection,
    index: UInt64
  ) throws {
    try validateIdentity(identity, index: index)
    guard identity.kind == .directory else { throw invalidSafetyVariant(index) }
  }

  private static func requireKnownEnum(
    observation: Diskplan_V1_EvidenceObservationProjection,
    isSpecified: Bool,
    index: UInt64
  ) throws {
    guard (observation.status == .known) == isSpecified else {
      throw invalidSafetyVariant(index)
    }
  }

  private static func validateProvenance(
    _ provenance: Diskplan_V1_AdapterScopeProvenanceKindProjection,
    hasScopeID: Bool,
    index: UInt64
  ) throws {
    switch provenance {
    case .configuredBoundScope:
      guard hasScopeID else { throw invalidSafetyVariant(index) }
    case .typeHintOnly:
      guard !hasScopeID else { throw invalidSafetyVariant(index) }
    case .unspecified, .UNRECOGNIZED:
      throw invalidSafetyVariant(index)
    }
  }

  private static func invalidSafetyVariant(_ index: UInt64) -> RuntimeProjectionWireError {
    .invalidRecord(index: index, reason: "invalid safety evidence variant")
  }

  private static func validateTarget(
    _ target: Diskplan_V1_PlanTargetProjection,
    index: UInt64
  ) throws {
    try requireNonempty(target.targetID.value, field: "target_id")
    try requireDigest(target.actionID.value, field: "target action_id")
    if target.hasParentTargetID {
      try requireNonempty(target.parentTargetID.value, field: "parent_target_id")
      guard target.parentTargetID.value != target.targetID.value else {
        throw RuntimeProjectionWireError.invalidRecord(index: index, reason: "self target parent")
      }
    } else if target.depth != 0 {
      throw RuntimeProjectionWireError.invalidRecord(
        index: index,
        reason: "root target has nonzero depth"
      )
    }
    try requireNonempty(target.path.rootID.value, field: "target root_id")
    guard validTargetKind(target.kind), !target.path.displayPath.isEmpty else {
      throw RuntimeProjectionWireError.invalidRecord(index: index, reason: "invalid target")
    }
    guard target.path.components.allSatisfy({ !$0.isEmpty && !$0.contains(0) && !$0.contains(47) })
    else {
      throw RuntimeProjectionWireError.invalidRecord(
        index: index,
        reason: "raw path component is not a leaf name"
      )
    }
  }

  private static func validateReleaseSet(
    _ releaseSet: Diskplan_V1_PlanReleaseSetProjection,
    index: UInt64
  ) throws {
    try requireNonempty(releaseSet.releaseSetID.value, field: "release_set_id")
    guard !releaseSet.actionIds.isEmpty else {
      throw RuntimeProjectionWireError.invalidRecord(index: index, reason: "empty release set")
    }
    try requireUnique(releaseSet.actionIds.map(\.value), field: "release-set action_id")
    for actionID in releaseSet.actionIds {
      try requireDigest(actionID.value, field: "release-set action_id")
    }
    try validateByteEstimate(releaseSet.sharedUnlock, index: index)
    try requireUnique(
      releaseSet.blockers.map { $0.blockerID.value }, field: "release-set blocker_id")
    for blocker in releaseSet.blockers {
      try validateBlocker(blocker, index: index)
    }
  }

  private static func validateBlocker(
    _ blocker: Diskplan_V1_PlanBlockerProjection,
    index: UInt64
  ) throws {
    try requireNonempty(blocker.blockerID.value, field: "blocker_id")
    guard validBlockerKind(blocker.kind), validBlockerDisposition(blocker.disposition),
      !blocker.code.isEmpty, !blocker.summary.isEmpty
    else {
      throw RuntimeProjectionWireError.invalidRecord(index: index, reason: "invalid blocker")
    }
  }

  private static func validateByteEstimate(
    _ estimate: Diskplan_V1_ByteEstimateProjection,
    index: UInt64
  ) throws {
    switch estimate.value {
    case .knownBytes:
      return
    case .unknown(let unknown) where !unknown.code.isEmpty && !unknown.summary.isEmpty:
      return
    case .unknown, nil:
      throw RuntimeProjectionWireError.invalidRecord(index: index, reason: "invalid byte estimate")
    }
  }

  private static func validatePreview(
    _ preview: Diskplan_V1_ActionExecutionPreviewProjection,
    actionKind: Diskplan_V1_PlanActionKind,
    index: UInt64
  ) throws {
    guard preview.adapter == actionKind else {
      throw RuntimeProjectionWireError.invalidRecord(
        index: index,
        reason: "preview adapter differs from action kind"
      )
    }
    if preview.mutationSupported {
      guard !preview.rawExecutable.isEmpty,
        !preview.rawExecutable.contains(0),
        preview.rawArgv.allSatisfy({ !$0.contains(0) }),
        preview.displayArgv.count == preview.rawArgv.count,
        !preview.postcondition.isEmpty
      else {
        throw RuntimeProjectionWireError.invalidRecord(
          index: index,
          reason: "invalid executable preview"
        )
      }
    } else if !preview.rawExecutable.isEmpty || !preview.rawArgv.isEmpty {
      throw RuntimeProjectionWireError.invalidRecord(
        index: index,
        reason: "unsupported mutation carries executable bytes"
      )
    }
  }

  private static func validDisposition(_ value: Diskplan_V1_PlanDisposition) -> Bool {
    switch value {
    case .ready, .conditional, .needsReview, .blocked, .keepInformational: true
    case .unspecified, .UNRECOGNIZED: false
    }
  }

  private static func validActionKind(_ value: Diskplan_V1_PlanActionKind) -> Bool {
    switch value {
    case .genericRemove, .gitWorktreeRemove, .gitWorktreeDiscardLocalChanges,
      .codexCleanTemporary, .versionedArtifactRemove, .completeReleaseSetRemove,
      .reportOnly:
      true
    case .unspecified, .UNRECOGNIZED: false
    }
  }

  private static func validStageability(_ value: Diskplan_V1_PlanStageability) -> Bool {
    switch value {
    case .stageable, .requiresWaivers, .notStageable: true
    case .unspecified, .UNRECOGNIZED: false
    }
  }

  private static func validActivity(_ value: Diskplan_V1_PlanActivity) -> Bool {
    switch value {
    case .inactive, .active, .mixed, .unknown: true
    case .unspecified, .UNRECOGNIZED: false
    }
  }

  private static func validRecoverability(_ value: Diskplan_V1_PlanRecoverability) -> Bool {
    switch value {
    case .rebuildable, .restorable, .irrecoverable, .reviewRequired, .unknown: true
    case .unspecified, .UNRECOGNIZED: false
    }
  }

  private static func validPathRace(_ value: Diskplan_V1_PathRaceProjection) -> Bool {
    switch value {
    case .noneObserved, .residual, .unknown: true
    case .unspecified, .UNRECOGNIZED: false
    }
  }

  private static func validRecommendation(_ value: Diskplan_V1_PlanRecommendation) -> Bool {
    switch value {
    case .safeToClean, .safeAfterExit, .likelyRebuildable, .needsSemanticReview,
      .managedByProvider, .keep, .scanIncomplete, .classificationConflict:
      true
    case .unspecified, .UNRECOGNIZED: false
    }
  }

  private static func validWaiverKind(_ value: Diskplan_V1_WaiverKind) -> Bool {
    switch value {
    case .recencyAgePolicy, .staticOnlyRebuildEvidence, .unknownRebuildCost,
      .agentAssistedClassification, .taskSemanticCompletion, .duplicateSurvivorChoice,
      .fullyObservedLocalGitWorkDiscard, .normalKeepPolicy:
      true
    case .unspecified, .UNRECOGNIZED: false
    }
  }

  private static func validTargetKind(_ value: Diskplan_V1_PlanTargetKind) -> Bool {
    switch value {
    case .file, .directory, .symbolicLink, .other, .unknown: true
    case .unspecified, .UNRECOGNIZED: false
    }
  }

  private static func validBlockerKind(_ value: Diskplan_V1_PlanBlockerKind) -> Bool {
    switch value {
    case .providerManaged, .incompleteEvidence, .currentActivity, .identityOrAccess,
      .semanticUniqueness, .recoverability, .dependency, .pathRace, .snapshot,
      .forceRequired, .unsupportedAdapter, .protocol:
      true
    case .unspecified, .UNRECOGNIZED: false
    }
  }

  private static func validBlockerDisposition(
    _ value: Diskplan_V1_PlanBlockerDisposition
  ) -> Bool {
    switch value {
    case .hard, .review, .warning, .informational: true
    case .unspecified, .UNRECOGNIZED: false
    }
  }

  private static func validEvidenceStatus(_ value: Diskplan_V1_EvidenceStatus) -> Bool {
    switch value {
    case .known, .absent, .unknown, .unreadable, .failed: true
    case .unspecified, .UNRECOGNIZED: false
    }
  }

  private static func validateReferences(
    actions: [Data: Diskplan_V1_PlanActionProjection],
    targets: [Data: Diskplan_V1_PlanTargetProjection],
    releaseSets: [Data: Diskplan_V1_PlanReleaseSetProjection]
  ) throws {
    for (actionID, action) in actions {
      guard action.prerequisites.allSatisfy({ actions[$0.actionID.value] != nil }) else {
        throw RuntimeProjectionWireError.invalidIdentifier(field: "prerequisite action_id")
      }
      let projectedTargets = Set(action.targetIds.map(\.value))
      let actualTargets = Set(
        targets.compactMap { targetID, target in
          target.actionID.value == actionID ? targetID : nil
        })
      guard projectedTargets == actualTargets else {
        throw RuntimeProjectionWireError.invalidIdentifier(field: "action target membership")
      }
      let projectedReleaseSets = Set(action.releaseSetIds.map(\.value))
      let actualReleaseSets = Set(
        releaseSets.compactMap { releaseSetID, releaseSet in
          releaseSet.actionIds.contains(where: { $0.value == actionID }) ? releaseSetID : nil
        })
      guard projectedReleaseSets == actualReleaseSets else {
        throw RuntimeProjectionWireError.invalidIdentifier(field: "action release-set membership")
      }
    }
    for target in targets.values {
      guard actions[target.actionID.value] != nil else {
        throw RuntimeProjectionWireError.invalidIdentifier(field: "target action_id")
      }
      if !target.parentTargetID.value.isEmpty {
        let (expectedDepth, depthOverflow) =
          targets[target.parentTargetID.value]
          .map { $0.depth.addingReportingOverflow(1) } ?? (0, true)
        guard let parent = targets[target.parentTargetID.value],
          parent.actionID.value == target.actionID.value,
          !depthOverflow,
          expectedDepth == target.depth
        else {
          throw RuntimeProjectionWireError.invalidIdentifier(field: "target parent binding")
        }
      }
    }
    for releaseSet in releaseSets.values {
      guard releaseSet.actionIds.allSatisfy({ actions[$0.value] != nil }) else {
        throw RuntimeProjectionWireError.invalidIdentifier(field: "release-set action_id")
      }
    }
    try validatePrerequisiteDAG(
      Dictionary(
        uniqueKeysWithValues: actions.map { actionID, action in
          (actionID, action.prerequisites.map { $0.actionID.value })
        })
    )
  }

  package static func validatePrerequisiteDAG(
    _ prerequisitesByAction: [Data: [Data]]
  ) throws {
    var indegree = Dictionary(uniqueKeysWithValues: prerequisitesByAction.keys.map { ($0, 0) })
    var dependents: [Data: [Data]] = [:]
    for (actionID, prerequisites) in prerequisitesByAction {
      for prerequisite in prerequisites {
        guard indegree[prerequisite] != nil else {
          throw RuntimeProjectionWireError.invalidIdentifier(field: "prerequisite action_id")
        }
        indegree[actionID, default: 0] += 1
        dependents[prerequisite, default: []].append(actionID)
      }
    }
    var ready = indegree.compactMap { actionID, degree in degree == 0 ? actionID : nil }
    var visited = 0
    while let actionID = ready.popLast() {
      visited += 1
      for dependent in dependents[actionID, default: []] {
        guard let degree = indegree[dependent], degree > 0 else {
          throw RuntimeProjectionWireError.invalidIdentifier(field: "prerequisite DAG")
        }
        indegree[dependent] = degree - 1
        if degree == 1 { ready.append(dependent) }
      }
    }
    guard visited == prerequisitesByAction.count else {
      throw RuntimeProjectionWireError.invalidIdentifier(field: "prerequisite cycle")
    }
  }

  private static func chunkedRecordPayloads(
    _ records: [Diskplan_V1_PlanProjectionRecord],
    chunkPayloadTargetBytes: Int
  ) throws -> [(data: Data, recordCount: UInt32)] {
    var payloads: [(Data, UInt32)] = []
    var payload = Data()
    var count: UInt32 = 0
    for record in records {
      let encoded = try record.serializedData()
      guard let encodedCount = UInt32(exactly: encoded.count) else {
        throw RuntimeProjectionWireError.countOverflow(field: "record_bytes")
      }
      var framed = Data()
      appendBigEndian(encodedCount, to: &framed)
      framed.append(encoded)
      guard framed.count <= chunkPayloadTargetBytes else {
        throw RuntimeProjectionWireError.recordTooLarge(
          actual: framed.count,
          maximum: chunkPayloadTargetBytes
        )
      }
      if !payload.isEmpty && payload.count + framed.count > chunkPayloadTargetBytes {
        payloads.append((payload, count))
        payload = Data()
        count = 0
      }
      payload.append(framed)
      let (next, overflow) = count.addingReportingOverflow(1)
      guard !overflow else {
        throw RuntimeProjectionWireError.countOverflow(field: "chunk_record_count")
      }
      count = next
    }
    if !payload.isEmpty {
      payloads.append((payload, count))
    }
    return payloads
  }

  private static func finalDigest(_ manifest: Diskplan_V1_PlanProjectionManifest) -> Data {
    var canonical = finalDigestDomain
    appendBigEndian(manifest.manifestVersion, to: &canonical)
    appendLengthPrefixed(manifest.planSha256.value, to: &canonical)
    appendLengthPrefixed(manifest.evidenceSha256.value, to: &canonical)
    appendLengthPrefixed(Data(manifest.policyVersion.utf8), to: &canonical)
    appendLengthPrefixed(Data(manifest.schemaVersion.utf8), to: &canonical)
    appendBigEndian(manifest.chunkCount, to: &canonical)
    appendBigEndian(manifest.recordCount, to: &canonical)
    appendBigEndian(manifest.actionCount, to: &canonical)
    appendBigEndian(manifest.targetCount, to: &canonical)
    appendBigEndian(manifest.releaseSetCount, to: &canonical)
    appendBigEndian(manifest.blockerCount, to: &canonical)
    appendBigEndian(manifest.waiverCount, to: &canonical)
    appendBigEndian(manifest.recordPayloadBytes, to: &canonical)
    appendBigEndian(manifest.maximumRecordCount, to: &canonical)
    appendBigEndian(manifest.maximumRecordPayloadBytes, to: &canonical)
    appendBigEndian(manifest.maximumChunkPayloadBytes, to: &canonical)
    appendBigEndian(manifest.maximumManifestEncodedBytes, to: &canonical)
    for descriptor in manifest.chunks {
      appendBigEndian(descriptor.chunkIndex, to: &canonical)
      appendLengthPrefixed(descriptor.chunkID.value, to: &canonical)
      appendBigEndian(descriptor.recordCount, to: &canonical)
      appendBigEndian(descriptor.payloadBytes, to: &canonical)
      appendLengthPrefixed(descriptor.payloadSha256.value, to: &canonical)
    }
    appendBigEndian(UInt32(manifest.dispositionCounts.count), to: &canonical)
    for row in manifest.dispositionCounts {
      appendBigEndian(UInt32(row.disposition.rawValue), to: &canonical)
      appendBigEndian(row.actionCount, to: &canonical)
    }
    appendBigEndian(UInt32(manifest.recommendationCounts.count), to: &canonical)
    for row in manifest.recommendationCounts {
      appendBigEndian(UInt32(row.recommendation.rawValue), to: &canonical)
      appendBigEndian(row.actionCount, to: &canonical)
    }
    appendBigEndian(manifest.cleanupCandidateCount, to: &canonical)
    appendLengthPrefixed(manifest.scanSessionID.value, to: &canonical)
    appendLengthPrefixed(manifest.scanCheckpointID.value, to: &canonical)
    appendLengthPrefixed(manifest.planID.value, to: &canonical)
    appendLengthPrefixed(manifest.evidenceID.value, to: &canonical)
    appendLengthPrefixed(manifest.scanCheckpointEvidenceSha256.value, to: &canonical)
    return digest(canonical)
  }

  private static func chunkID(index: UInt32, payloadDigest: Data) -> Data {
    var canonical = chunkIDDomain
    appendBigEndian(index, to: &canonical)
    appendLengthPrefixed(payloadDigest, to: &canonical)
    return digest(canonical)
  }

  private static func digest(_ data: Data) -> Data { Data(SHA256.hash(data: data)) }

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

  private static func requireDigest(_ value: Data, field: String) throws {
    guard value.count == 32 else {
      throw RuntimeProjectionWireError.digestLength(field: field, actual: value.count)
    }
  }

  private static func requireNonempty(_ value: Data, field: String) throws {
    guard !value.isEmpty, value.count <= maximumOpaqueIdentifierBytes else {
      throw RuntimeProjectionWireError.invalidIdentifier(field: field)
    }
  }

  private static func requireUnique(_ values: [Data], field: String) throws {
    guard values.allSatisfy({ !$0.isEmpty && $0.count <= maximumOpaqueIdentifierBytes }) else {
      throw RuntimeProjectionWireError.invalidIdentifier(field: field)
    }
    guard Set(values).count == values.count else {
      throw RuntimeProjectionWireError.duplicateIdentifier(field: field)
    }
  }

  private static func insertUnique<Value>(
    _ key: Data,
    value: Value,
    into values: inout [Data: Value],
    field: String
  ) throws {
    try requireNonempty(key, field: field)
    guard values.updateValue(value, forKey: key) == nil else {
      throw RuntimeProjectionWireError.duplicateIdentifier(field: field)
    }
  }

  private static func addingExact(_ lhs: UInt64, _ rhs: UInt64, field: String) throws -> UInt64 {
    let (value, overflow) = lhs.addingReportingOverflow(rhs)
    guard !overflow else { throw RuntimeProjectionWireError.countOverflow(field: field) }
    return value
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

  private static func lowercaseHexData(_ value: Data) -> Data {
    Data(value.map { String(format: "%02x", $0) }.joined().utf8)
  }
}
