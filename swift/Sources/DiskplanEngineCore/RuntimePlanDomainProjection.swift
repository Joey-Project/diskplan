import DiskplanCore
import DiskplanPolicy
import DiskplanProto
import Foundation

enum RuntimePlanDomainProjectionError: Error, Equatable {
  case unsupportedActionKind
  case ancestorLimitExceeded
  case integerOverflow
}

/// Projects an already validated `ImmutablePlan`; it never reclassifies or
/// upgrades policy evidence.
enum RuntimePlanDomainProjector {
  static func project(
    _ authority: RuntimePolicyAuthorityResult,
    negotiatedProtocolMinor: UInt32 = protocolMinor
  ) throws -> [Diskplan_V1_PlanProjectionRecord] {
    try SealedRuntimeWire.requireSupportedProtocolMinor(negotiatedProtocolMinor)
    let plan = authority.plan
    let releaseIDs = Dictionary(
      uniqueKeysWithValues: plan.releaseSets.map { release in
        (release.allocationGroupID, releaseID(release))
      })
    var records: [Diskplan_V1_PlanProjectionRecord] = []
    records.reserveCapacity(plan.actions.count * 2 + plan.releaseSets.count)

    for (order, action) in ActionOrdering.display(plan.actions).enumerated() {
      let target = try targetProjection(action: action, order: UInt64(order))
      let releaseSetIDs = plan.releaseSets.compactMap { release -> Data? in
        release.ownerActionIDs.contains(action.id) ? releaseIDs[release.allocationGroupID] : nil
      }
      var actionRecord = Diskplan_V1_PlanProjectionRecord()
      actionRecord.body = .action(
        try actionProjection(
          action,
          order: UInt64(order),
          targetID: target.targetID.value,
          releaseSetIDs: releaseSetIDs,
          releaseSets: plan.releaseSets,
          negotiatedProtocolMinor: negotiatedProtocolMinor
        ))
      records.append(actionRecord)

      var targetRecord = Diskplan_V1_PlanProjectionRecord()
      targetRecord.body = .target(target)
      records.append(targetRecord)
    }

    for release in plan.releaseSets {
      var record = Diskplan_V1_PlanProjectionRecord()
      record.body = .releaseSet(
        releaseProjection(release, id: releaseIDs[release.allocationGroupID]!))
      records.append(record)
    }
    for index in records.indices { records[index].recordIndex = UInt64(index) }
    return records
  }

  private static func actionProjection(
    _ action: ActionDefinition,
    order: UInt64,
    targetID: Data,
    releaseSetIDs: [Data],
    releaseSets: [PlanReleaseSet],
    negotiatedProtocolMinor: UInt32
  ) throws -> Diskplan_V1_PlanActionProjection {
    let kind = try actionKind(action.prototype.adapterContract)
    var projection = Diskplan_V1_PlanActionProjection()
    projection.actionID.value = action.id.digest.bytes
    projection.actionLineageID.value = action.lineageID.digest.bytes
    projection.disposition = disposition(action.evaluation)
    projection.kind = kind
    projection.kindLabel = kindLabel(kind)
    projection.kindOrder = UInt32(kind.rawValue)
    projection.label = action.evidence.candidateID
    projection.order = order
    projection.stageability = stageability(action.evaluation.stageability)
    projection.requiredWaivers = requiredWaivers(action.evaluation.stageability)
    projection.immediateReclaim = byteEstimate(action.displayMetrics.immediateReclaimBytes)
    projection.sharedUnlock = sharedUnlock(
      actionID: action.id,
      releaseSets: releaseSets
    )
    projection.activity = activity(action.evidence.activity)
    projection.recoverability = recoverability(action.evidence.recoverability)
    projection.blockers = blockers(action.evaluation, actionID: action.id)
    projection.prerequisites = action.prerequisiteActionIDs.map { prerequisite in
      var row = Diskplan_V1_PlanPrerequisiteProjection()
      row.actionID.value = prerequisite.digest.bytes
      row.summary = "Authoritative prerequisite action."
      return row
    }
    projection.releaseSetIds = releaseSetIDs.map(opaque)
    projection.requiresForce = requiresForce(action.prototype.adapterContract)
    if projection.requiresForce {
      projection.forceReason = "Removal requires the force variant selected by the Swift engine."
    }
    projection.pathRace = pathRace(action.prototype.adapterContract)
    projection.targetIds = [opaque(targetID)]
    projection.evidence = evidenceSummaries(action.evaluation)
    projection.executionPreview.adapter = kind
    projection.executionPreview.mutationSupported = false
    projection.executionPreview.postcondition = "Mutation is not implemented in this runtime slice."
    if negotiatedProtocolMinor >= protocol15Minor {
      projection.executionPreview.rawWorkingDirectory = Data()
      projection.executionPreview.pathRace = projection.pathRace
    }
    projection.recommendation = recommendation(action.evaluation.recommendation)
    projection.safetyEvidence = try safetyEvidence(action)
    return projection
  }

  private static func targetProjection(
    action: ActionDefinition,
    order: UInt64
  ) throws -> Diskplan_V1_PlanTargetProjection {
    let binding = action.prototype.namespaceBinding
    let components = binding.targetPath.components
    let targetID = runtimeDigest(
      domain: "diskplan/plan-target-id/v1\0",
      fields: [action.id.digest.bytes] + components
    )
    var path = Diskplan_V1_PlanRawPathProjection()
    path.rootID.value = runtimeDigest(
      domain: "diskplan/plan-root-id/v1\0",
      fields: [binding.rawRoot.absoluteBytes]
    )
    path.components = components
    path.displayPath = displayPath(
      root: binding.rawRoot.absoluteBytes,
      components: components
    )

    var target = Diskplan_V1_PlanTargetProjection()
    target.targetID.value = targetID
    target.actionID.value = action.id.digest.bytes
    target.depth = 0
    target.order = order
    target.path = path
    target.kind = targetKind(binding.targetIdentity.type)
    return target
  }

  private static func releaseProjection(
    _ release: PlanReleaseSet,
    id: Data
  ) -> Diskplan_V1_PlanReleaseSetProjection {
    var projection = Diskplan_V1_PlanReleaseSetProjection()
    projection.releaseSetID.value = id
    projection.actionIds = release.ownerActionIDs.sorted().map { opaque($0.digest.bytes) }
    projection.sharedUnlock.knownBytes = release.conditionalReclaimBytes
    return projection
  }

  private static func releaseID(_ release: PlanReleaseSet) -> Data {
    runtimeDigest(
      domain: "diskplan/release-set-projection-id/v1\0",
      fields: [Data(release.allocationGroupID.utf8), release.graphDigest.bytes]
    )
  }

  private static func safetyEvidence(
    _ action: ActionDefinition
  ) throws -> Diskplan_V1_PlanSafetyEvidenceProjection {
    let evidence = action.evidence
    let binding = action.prototype.namespaceBinding
    guard binding.parentChain.count <= Int(PlanProjectionWireEncoder.maximumNamespaceAncestorCount)
    else { throw RuntimePlanDomainProjectionError.ancestorLimitExceeded }

    var namespace = Diskplan_V1_NamespaceAccessEvidenceProjection()
    namespace.targetAccessPolicy = observation(
      evidence.accessPolicy,
      code: "target-access-policy",
      summary: "Target access policy captured by the Swift authority.",
      valueBytes: { Data($0.utf8) }
    )
    namespace.targetAclDigest = observation(
      evidence.aclDigest,
      code: "target-acl-digest",
      summary: "Target ACL digest captured by the Swift authority.",
      valueBytes: { $0.bytes }
    )
    namespace.rootAccessPolicy = observation(
      binding.rootSeal.accessPolicy,
      code: "root-access-policy",
      summary: "Root access policy captured by the Swift authority.",
      valueBytes: { Data($0.utf8) }
    )
    namespace.rootAclDigest = observation(
      binding.rootSeal.aclDigest,
      code: "root-acl-digest",
      summary: "Root ACL digest captured by the Swift authority.",
      valueBytes: { $0.bytes }
    )
    let ancestorBindings = binding.parentChain.map(parentNamespaceBinding)
    let ancestorChainBinding = runtimeDigest(
      domain: "diskplan/ancestor-access-chain/v1\0",
      fields: ancestorBindings
    )
    namespace.ancestorAccessPolicyChain = knownObservation(
      code: "ancestor-access-policy-chain",
      summary: "Ordered ancestor namespace chain retained by the Swift authority.",
      valueBytes: ancestorChainBinding
    )
    namespace.ancestorCount = UInt32(binding.parentChain.count)
    namespace.maximumAncestorCount = PlanProjectionWireEncoder.maximumNamespaceAncestorCount
    namespace.namespaceBindingSha256.value = protectedNamespaceBinding(binding)
    namespace.rootAccessPolicySeal = namespace.rootAccessPolicy
    namespace.ancestorAccessPolicySeal = namespace.ancestorAccessPolicyChain

    var content = Diskplan_V1_ContentBaselineEvidenceProjection()
    switch evidence.contentProtection {
    case .known(.requiredDigest(let digest)):
      content.observation = knownObservation(
        code: "content-required-digest",
        summary: "Content stability is protected by an exact digest.",
        valueBytes: digest.bytes
      )
      content.knownKind = .requiredDigest
    case .known(.explicitlyNotApplicable):
      content.observation = knownObservation(
        code: "content-explicitly-not-applicable",
        summary: "The action contract explicitly excludes content stability.",
        valueBytes: Data("metadata-only-object".utf8)
      )
      content.knownKind = .explicitlyNotApplicable
      content.notApplicableReason = .metadataOnlyObject
    case .absent:
      content.observation = absentObservation(
        code: "content-baseline-absent",
        summary: "No content baseline applies."
      )
    case .unknown(let reason):
      content.observation = unknownObservation(
        reason,
        code: "content-baseline-unknown",
        summary: "Content baseline is unavailable."
      )
    case .unreadable(let failure):
      content.observation = failedObservation(
        failure,
        status: .unreadable,
        code: "content-baseline-unreadable",
        summary: "Content baseline could not be read."
      )
    case .failed(let failure):
      content.observation = failedObservation(
        failure,
        status: .failed,
        code: "content-baseline-failed",
        summary: "Content baseline collection failed."
      )
    }

    var projection = Diskplan_V1_PlanSafetyEvidenceProjection()
    projection.policyEvidenceSha256.value = evidence.evidenceID.bytes
    projection.namespaceAccess = namespace
    projection.contentBaseline = content
    switch action.prototype.adapterContract {
    case .genericRemove, .completeReleaseSetRemove:
      break
    case .codexCleanTemporary(let contract):
      projection.codexCleanupScope = codexEvidence(
        contract: contract,
        action: action
      )
    case .versionedArtifactRemove(let contract):
      projection.versionedArtifact = versionedEvidence(
        contract: contract,
        action: action
      )
    case .gitWorktreeRemove, .gitWorktreeDiscardLocalChanges:
      throw RuntimePlanDomainProjectionError.unsupportedActionKind
    }
    return projection
  }

  static func rawRelativePathBinding(_ components: [Data]) -> Data {
    runtimeDigest(
      domain: "diskplan/raw-relative-path-binding/v1\0",
      fields: components
    )
  }

  static func protectedNamespaceBinding(_ binding: ProtectedNamespaceBinding) -> Data {
    let ancestorChain = runtimeDigest(
      domain: "diskplan/protected-namespace-ancestor-chain/v1\0",
      fields: binding.parentChain.map(parentNamespaceBinding)
    )
    return runtimeDigest(
      domain: "diskplan/protected-namespace-projection-binding/v1\0",
      fields: [
        binding.rawRoot.absoluteBytes,
        identityBytes(binding.rootIdentity),
        namespaceSealBinding(binding.rootSeal),
        rawRelativePathBinding(binding.targetPath.components),
        identityBytes(binding.targetIdentity),
        ancestorChain,
      ]
    )
  }

  private static func parentNamespaceBinding(_ parent: ParentNamespaceBinding) -> Data {
    runtimeDigest(
      domain: "diskplan/ancestor-namespace-entry/v1\0",
      fields: [
        rawRelativePathBinding(parent.relativePath.components),
        identityBytes(parent.identity),
        namespaceSealBinding(parent.seal),
      ]
    )
  }

  private static func namespaceSealBinding(_ seal: NamespaceSealEvidence) -> Data {
    runtimeDigest(
      domain: "diskplan/namespace-seal-projection-binding/v1\0",
      fields: [
        Data(seal.trustedNamespace.rawValue.utf8),
        observationBindingBytes(seal.accessPolicy) { Data($0.utf8) },
        observationBindingBytes(seal.aclDigest) { $0.bytes },
        observationBindingBytes(seal.providerBoundary) { Data($0.rawValue.utf8) },
        observationBindingBytes(seal.mountIdentity) { Data($0.utf8) },
      ]
    )
  }

  private static func codexEvidence(
    contract: CodexTemporaryRemoveContract,
    action: ActionDefinition
  ) -> Diskplan_V1_CodexCleanupScopeEvidenceProjection {
    var evidence = Diskplan_V1_CodexCleanupScopeEvidenceProjection()
    evidence.provenanceKind = .configuredBoundScope
    evidence.cleanupScopeID.value = Data(contract.cleanupScopeID.utf8)
    evidence.provenance = knownObservation(
      code: "configured-cleanup-scope",
      summary: "Cleanup scope is bound by the authoritative plan.",
      valueBytes: Data(contract.cleanupScopeID.utf8)
    )
    evidence.boundRootIdentity = knownObservation(
      code: "cleanup-root-identity",
      summary: "Cleanup root identity is bound by the authoritative plan.",
      valueBytes: identityBytes(action.prototype.namespaceBinding.rootIdentity)
    )
    evidence.knownBoundRootIdentity = identityProjection(
      action.prototype.namespaceBinding.rootIdentity)
    evidence.helperCapability = unknownObservation(
      .notRequested,
      code: "cleanup-helper-not-requested",
      summary: "Execution helper capability is outside the plan-only runtime slice."
    )
    evidence.coverage = partialCoverage(.notRequestedByProfile)
    evidence.scopeBindingSha256.value = runtimeDigest(
      domain: "diskplan/codex-scope-projection/v1\0",
      fields: [action.evidenceID.bytes, Data(contract.cleanupScopeID.utf8)]
    )
    return evidence
  }

  private static func versionedEvidence(
    contract: VersionedArtifactRemoveContract,
    action: ActionDefinition
  ) -> Diskplan_V1_VersionedArtifactEvidenceProjection {
    var evidence = Diskplan_V1_VersionedArtifactEvidenceProjection()
    evidence.artifactKindID.value = Data(contract.artifactKind.utf8)
    evidence.versionID.value = Data(contract.version.utf8)
    evidence.inventoryCoverage = unknownObservation(
      .notRequested,
      code: "version-inventory-not-requested",
      summary: "Version inventory projection is outside the plan-only runtime slice."
    )
    evidence.provenanceKind = .configuredBoundScope
    evidence.configuredScopeID.value = Data(contract.artifactKind.utf8)
    evidence.provenance = knownObservation(
      code: "configured-version-scope",
      summary: "Version scope is bound by the authoritative plan.",
      valueBytes: Data(contract.artifactKind.utf8)
    )
    evidence.installRootIdentity = knownObservation(
      code: "version-install-root-identity",
      summary: "Install root identity is bound by the authoritative plan.",
      valueBytes: identityBytes(action.prototype.namespaceBinding.rootIdentity)
    )
    evidence.knownInstallRootIdentity = identityProjection(
      action.prototype.namespaceBinding.rootIdentity)
    evidence.activeSelector = unknownObservation(
      .notRequested,
      code: "active-selector-not-requested",
      summary: "Active selector projection is outside the plan-only runtime slice."
    )
    evidence.survivorSet = unknownObservation(
      .notRequested,
      code: "survivor-set-not-requested",
      summary: "Survivor set projection is outside the plan-only runtime slice."
    )
    evidence.currentUpdateMarker = unknownObservation(
      .notRequested,
      code: "update-marker-not-requested",
      summary: "Update marker projection is outside the plan-only runtime slice."
    )
    evidence.maximumVersionCount = PlanProjectionWireEncoder.maximumVersionedArtifactCount
    evidence.coverage = partialCoverage(.notRequestedByProfile)
    evidence.bundleSha256.value = runtimeDigest(
      domain: "diskplan/versioned-artifact-projection/v1\0",
      fields: [
        action.evidenceID.bytes,
        Data(contract.artifactKind.utf8),
        Data(contract.version.utf8),
      ]
    )
    return evidence
  }

  private static func blockers(
    _ evaluation: PolicyEvaluation,
    actionID: ActionID
  ) -> [Diskplan_V1_PlanBlockerProjection] {
    evaluation.votes.flatMap { vote -> [Diskplan_V1_PlanBlockerProjection] in
      let reasons: [GateReason]
      let disposition: Diskplan_V1_PlanBlockerDisposition
      switch vote.result {
      case .rejected(let rejected):
        reasons = rejected
        disposition = .hard
      case .unmetCondition(_, let unmet):
        reasons = unmet
        disposition = .hard
      case .satisfied, .notApplicable, .requiresWaiver:
        return []
      }
      return reasons.map { reason in
        var blocker = Diskplan_V1_PlanBlockerProjection()
        blocker.blockerID.value = runtimeDigest(
          domain: "diskplan/plan-blocker-id/v1\0",
          fields: [
            actionID.digest.bytes,
            Data([vote.dimension.rawValue]),
            Data(reason.code.utf8),
            reason.semanticEvidenceHash.bytes,
          ]
        )
        blocker.kind = blockerKind(vote.dimension)
        blocker.disposition = disposition
        blocker.code = reason.code
        blocker.summary = "Authoritative one-vote policy blocker."
        return blocker
      }
    }
  }

  private static func evidenceSummaries(
    _ evaluation: PolicyEvaluation
  ) -> [Diskplan_V1_EvidenceSummaryProjection] {
    evaluation.votes.flatMap { vote -> [Diskplan_V1_EvidenceSummaryProjection] in
      let reasons: [GateReason]
      switch vote.result {
      case .satisfied(let value), .notApplicable(let value),
        .requiresWaiver(_, let value), .unmetCondition(_, let value),
        .rejected(let value):
        reasons = value
      }
      return reasons.map { reason in
        var summary = Diskplan_V1_EvidenceSummaryProjection()
        summary.status = .known
        summary.code = reason.code
        summary.summary = "Authoritative policy evidence."
        return summary
      }
    }
  }

  private static func requiredWaivers(
    _ stageability: Stageability
  ) -> [Diskplan_V1_PlanWaiverProjection] {
    guard case .requiresConsents(let predicates) = stageability else { return [] }
    return predicates.sorted().map { predicate in
      var waiver = Diskplan_V1_PlanWaiverProjection()
      waiver.waiverID.value = RuntimePlanIdentifiers.waiverID(predicate)
      waiver.kind = waiverKind(predicate.kind)
      waiver.predicate = predicate.predicate
      waiver.valueBucket = predicate.valueBucket
      waiver.semanticEvidenceSha256.value = predicate.semanticEvidenceHash.bytes
      waiver.summary = "Explicit consent required by the authoritative policy."
      return waiver
    }
  }

  private static func sharedUnlock(
    actionID: ActionID,
    releaseSets: [PlanReleaseSet]
  ) -> Diskplan_V1_ByteEstimateProjection {
    var total: UInt64 = 0
    for release in releaseSets where release.ownerActionIDs.contains(actionID) {
      let (next, overflow) = total.addingReportingOverflow(release.conditionalReclaimBytes)
      if overflow { return unknownByteEstimate("shared-unlock-overflow") }
      total = next
    }
    var estimate = Diskplan_V1_ByteEstimateProjection()
    estimate.knownBytes = total
    return estimate
  }

  private static func byteEstimate(
    _ value: KnownOrUnknown<UInt64>
  ) -> Diskplan_V1_ByteEstimateProjection {
    switch value {
    case .known(let bytes):
      var estimate = Diskplan_V1_ByteEstimateProjection()
      estimate.knownBytes = bytes
      return estimate
    case .unknown(let reason):
      return unknownByteEstimate(reason.rawValue)
    }
  }

  private static func unknownByteEstimate(_ code: String) -> Diskplan_V1_ByteEstimateProjection {
    var unknown = Diskplan_V1_UnknownProjectionValue()
    unknown.code = code
    unknown.summary = "The Swift authority does not have an exact byte estimate."
    var estimate = Diskplan_V1_ByteEstimateProjection()
    estimate.unknown = unknown
    return estimate
  }

  private static func actionKind(
    _ contract: ActionAdapterContract
  ) throws -> Diskplan_V1_PlanActionKind {
    switch contract {
    case .genericRemove: .genericRemove
    case .gitWorktreeRemove: .gitWorktreeRemove
    case .gitWorktreeDiscardLocalChanges: .gitWorktreeDiscardLocalChanges
    case .codexCleanTemporary: .codexCleanTemporary
    case .versionedArtifactRemove: .versionedArtifactRemove
    case .completeReleaseSetRemove: .completeReleaseSetRemove
    }
  }

  private static func kindLabel(_ kind: Diskplan_V1_PlanActionKind) -> String {
    switch kind {
    case .genericRemove: "Remove"
    case .gitWorktreeRemove: "Remove Git worktree"
    case .gitWorktreeDiscardLocalChanges: "Discard Git worktree changes"
    case .codexCleanTemporary: "Clean Codex temporary scope"
    case .versionedArtifactRemove: "Remove versioned artifact"
    case .completeReleaseSetRemove: "Release shared allocation set"
    case .reportOnly: "Report only"
    case .unspecified, .UNRECOGNIZED: "Unknown"
    }
  }

  private static func disposition(_ evaluation: PolicyEvaluation) -> Diskplan_V1_PlanDisposition {
    switch evaluation.stageability {
    case .stageable: return .ready
    case .requiresConsents: return .conditional
    case .blocked:
      switch evaluation.recommendation {
      case .managedByProvider, .keep: return .keepInformational
      case .needsSemanticReview: return .needsReview
      default: return .blocked
      }
    }
  }

  private static func stageability(_ value: Stageability) -> Diskplan_V1_PlanStageability {
    switch value {
    case .stageable: .stageable
    case .requiresConsents: .requiresWaivers
    case .blocked: .notStageable
    }
  }

  private static func activity(
    _ value: Observation<ActivityState>
  ) -> Diskplan_V1_PlanActivity {
    switch value {
    case .known(.inactive): .inactive
    case .known(.active): .active
    case .absent, .unknown, .unreadable, .failed: .unknown
    }
  }

  private static func recoverability(
    _ value: Observation<RecoverabilityState>
  ) -> Diskplan_V1_PlanRecoverability {
    switch value {
    case .known(.recoverable): .rebuildable
    case .known(.reviewRequired): .reviewRequired
    case .known(.irrecoverable): .irrecoverable
    case .absent, .unknown, .unreadable, .failed: .unknown
    }
  }

  private static func recommendation(
    _ value: Recommendation
  ) -> Diskplan_V1_PlanRecommendation {
    switch value {
    case .safeToClean: .safeToClean
    case .safeAfterExit: .safeAfterExit
    case .likelyRebuildable: .likelyRebuildable
    case .needsSemanticReview: .needsSemanticReview
    case .managedByProvider: .managedByProvider
    case .keep: .keep
    case .scanIncomplete: .scanIncomplete
    case .classificationConflict: .classificationConflict
    }
  }

  private static func waiverKind(_ value: WaiverKind) -> Diskplan_V1_WaiverKind {
    switch value {
    case .recencyAgePolicy: .recencyAgePolicy
    case .staticOnlyRebuildEvidence: .staticOnlyRebuildEvidence
    case .unknownRebuildCost: .unknownRebuildCost
    case .agentAssistedClassification: .agentAssistedClassification
    case .taskSemanticCompletion: .taskSemanticCompletion
    case .duplicateSurvivorChoice: .duplicateSurvivorChoice
    case .fullyObservedLocalGitWorkDiscard: .fullyObservedLocalGitWorkDiscard
    case .normalKeepPolicy: .normalKeepPolicy
    }
  }

  private static func blockerKind(
    _ dimension: GateDimension
  ) -> Diskplan_V1_PlanBlockerKind {
    switch dimension {
    case .protectionAndProvider: .providerManaged
    case .evidenceCompleteness: .incompleteEvidence
    case .currentActivity: .currentActivity
    case .identityAndAccess: .identityOrAccess
    case .semanticUniqueness: .semanticUniqueness
    case .recoverability: .recoverability
    case .dependencyCompleteness: .dependency
    }
  }

  private static func requiresForce(_ contract: ActionAdapterContract) -> Bool {
    guard case .genericRemove(let remove) = contract else { return false }
    return remove.forceRequirement == .requiresForceWithWarning
  }

  private static func pathRace(
    _ contract: ActionAdapterContract
  ) -> Diskplan_V1_PathRaceProjection {
    if case .genericRemove(let remove) = contract {
      return remove.pathRaceResidual ? .residual : .noneObserved
    }
    return .unknown
  }

  private static func targetKind(_ kind: ObjectKind) -> Diskplan_V1_PlanTargetKind {
    switch kind {
    case .regularFile: .file
    case .directory: .directory
    case .symbolicLink: .symbolicLink
    }
  }

  private static func opaque(_ bytes: Data) -> Diskplan_V1_OpaqueIdentifier {
    var value = Diskplan_V1_OpaqueIdentifier()
    value.value = bytes
    return value
  }

  static func displayPath(root: Data, components: [Data]) -> String {
    var fullPath = root
    for component in components {
      if fullPath.last != 47 { fullPath.append(47) }
      fullPath.append(component)
    }
    return ScanIPCProjection.displayRawBytes(fullPath)
  }

  private static func identityBytes(_ identity: ObjectIdentity) -> Data {
    runtimeDigest(
      domain: "diskplan/object-identity-projection/v1\0",
      fields: [
        bigEndian(identity.device),
        bigEndian(identity.object),
        observationBindingBytes(identity.generation) { bigEndian($0) },
        Data(identity.type.rawValue.utf8),
      ]
    )
  }

  private static func identityProjection(
    _ identity: ObjectIdentity
  ) -> Diskplan_V1_EvidenceObjectIdentityProjection {
    var projection = Diskplan_V1_EvidenceObjectIdentityProjection()
    projection.device = identity.device
    projection.fileID = identity.object
    switch identity.type {
    case .regularFile: projection.kind = .regular
    case .directory: projection.kind = .directory
    case .symbolicLink: projection.kind = .symbolicLink
    }
    projection.bindingSha256.value = identityBytes(identity)
    return projection
  }

  private static func observation<Value: Equatable & Sendable>(
    _ value: Observation<Value>,
    code: String,
    summary: String,
    valueBytes: (Value) -> Data
  ) -> Diskplan_V1_EvidenceObservationProjection {
    switch value {
    case .known(let known):
      return knownObservation(code: code, summary: summary, valueBytes: valueBytes(known))
    case .absent:
      return absentObservation(code: code, summary: summary)
    case .unknown(let reason):
      return unknownObservation(reason, code: code, summary: summary)
    case .unreadable(let failure):
      return failedObservation(failure, status: .unreadable, code: code, summary: summary)
    case .failed(let failure):
      return failedObservation(failure, status: .failed, code: code, summary: summary)
    }
  }

  private static func knownObservation(
    code: String,
    summary: String,
    valueBytes: Data
  ) -> Diskplan_V1_EvidenceObservationProjection {
    var observation = Diskplan_V1_EvidenceObservationProjection()
    observation.status = .known
    observation.code = code
    observation.summary = summary
    observation.valueSha256.value = runtimeDigest(
      domain: "diskplan/evidence-observation-projection/v1\0",
      fields: [valueBytes]
    )
    return observation
  }

  private static func absentObservation(
    code: String,
    summary: String
  ) -> Diskplan_V1_EvidenceObservationProjection {
    var observation = Diskplan_V1_EvidenceObservationProjection()
    observation.status = .absent
    observation.code = code
    observation.summary = summary
    return observation
  }

  private static func unknownObservation(
    _ reason: UnknownReason,
    code: String,
    summary: String
  ) -> Diskplan_V1_EvidenceObservationProjection {
    var observation = Diskplan_V1_EvidenceObservationProjection()
    observation.status = .unknown
    observation.code = code
    observation.summary = summary
    switch reason {
    case .notRequested: observation.unknownReason = .notRequested
    case .unsupported: observation.unknownReason = .unsupported
    case .budgetExhausted: observation.unknownReason = .budgetExhausted
    case .timedOut: observation.unknownReason = .timedOut
    case .incompleteCoverage: observation.unknownReason = .incompleteCoverage
    case .unavailableViaPublicAPI: observation.unknownReason = .unavailableViaPublicApi
    }
    return observation
  }

  private static func failedObservation(
    _ failure: ObservationFailure,
    status: Diskplan_V1_EvidenceStatus,
    code: String,
    summary: String
  ) -> Diskplan_V1_EvidenceObservationProjection {
    var observation = Diskplan_V1_EvidenceObservationProjection()
    observation.status = status
    observation.code = code
    observation.summary = summary
    observation.failure.code = failure.code
    observation.failure.collector = failure.collector
    return observation
  }

  private static func partialCoverage(
    _ reason: Diskplan_V1_EvidenceCoverageReasonProjection
  ) -> Diskplan_V1_EvidenceCoverageProjection {
    var coverage = Diskplan_V1_EvidenceCoverageProjection()
    coverage.completeness = .partial
    coverage.reasons = [reason]
    coverage.bindingSha256.value = runtimeDigest(
      domain: "diskplan/evidence-coverage-projection/v1\0",
      fields: [bigEndian(UInt64(reason.rawValue))]
    )
    return coverage
  }

  private static func observationBindingBytes<Value: Equatable & Sendable>(
    _ observation: Observation<Value>,
    valueBytes: (Value) -> Data
  ) -> Data {
    switch observation {
    case .known(let value):
      return runtimeDigest(
        domain: "diskplan/observation-binding-known/v1\0",
        fields: [valueBytes(value)]
      )
    case .absent:
      return runtimeDigest(domain: "diskplan/observation-binding-absent/v1\0", fields: [])
    case .unknown(let reason):
      return runtimeDigest(
        domain: "diskplan/observation-binding-unknown/v1\0",
        fields: [Data(reason.rawValue.utf8)]
      )
    case .unreadable(let failure):
      return runtimeDigest(
        domain: "diskplan/observation-binding-unreadable/v1\0",
        fields: [Data(failure.code.utf8), Data(failure.collector.utf8)]
      )
    case .failed(let failure):
      return runtimeDigest(
        domain: "diskplan/observation-binding-failed/v1\0",
        fields: [Data(failure.code.utf8), Data(failure.collector.utf8)]
      )
    }
  }

  private static func bigEndian<T: FixedWidthInteger>(_ value: T) -> Data {
    var encoded = value.bigEndian
    return withUnsafeBytes(of: &encoded) { Data($0) }
  }
}
