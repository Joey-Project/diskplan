import Foundation

/// The policy target deliberately has no dependency on the evolving scanner model.
/// A production adapter freezes scanner output into policy evidence after Phase 1 stabilizes.
public protocol PolicyEvidenceAdapter: Sendable {
  associatedtype ScannerEvidence: Sendable

  func freeze(
    _ evidence: ScannerEvidence,
    context: EvidenceFreezeContext
  ) throws -> FrozenEvidenceSnapshot
}

public struct EvidenceFreezeContext: Equatable, Sendable {
  public let captureID: PolicyDigest
  public let globalFactsHash: PolicyDigest
  public let semanticReferenceTimeSeconds: Int64
  public let policyVersion: String
  public let schemaVersion: String

  public init(globalFacts: FrozenGlobalFacts) {
    captureID = globalFacts.captureID
    globalFactsHash = globalFacts.globalFactsHash
    semanticReferenceTimeSeconds = globalFacts.semanticReferenceTimeSeconds
    policyVersion = globalFacts.policyVersion
    schemaVersion = globalFacts.schemaVersion
  }
}

public struct PolicyGateInput: Equatable, Sendable {
  public let result: GateResult

  fileprivate init(result: GateResult) {
    self.result = result
  }
}

/// Named fields make adding, dropping, or merging a safety dimension an API change.
public struct OneVotePolicyInputs: Equatable, Sendable {
  public let protectionAndProvider: PolicyGateInput
  public let evidenceCompleteness: PolicyGateInput
  public let currentActivity: PolicyGateInput
  public let identityAndAccess: PolicyGateInput
  public let semanticUniqueness: PolicyGateInput
  public let recoverability: PolicyGateInput
  public let dependencyCompleteness: PolicyGateInput
  fileprivate let providerBound: Bool
  fileprivate let classificationConflict: Bool
  fileprivate let sourceBinding: PolicyEvaluationSourceBinding

  private init(
    protectionAndProvider: GateResult,
    evidenceCompleteness: GateResult,
    currentActivity: GateResult,
    identityAndAccess: GateResult,
    semanticUniqueness: GateResult,
    recoverability: GateResult,
    dependencyCompleteness: GateResult,
    providerBound: Bool,
    classificationConflict: Bool,
    sourceBinding: PolicyEvaluationSourceBinding
  ) {
    self.protectionAndProvider = PolicyGateInput(result: protectionAndProvider)
    self.evidenceCompleteness = PolicyGateInput(result: evidenceCompleteness)
    self.currentActivity = PolicyGateInput(result: currentActivity)
    self.identityAndAccess = PolicyGateInput(result: identityAndAccess)
    self.semanticUniqueness = PolicyGateInput(result: semanticUniqueness)
    self.recoverability = PolicyGateInput(result: recoverability)
    self.dependencyCompleteness = PolicyGateInput(result: dependencyCompleteness)
    self.providerBound = providerBound
    self.classificationConflict = classificationConflict
    self.sourceBinding = sourceBinding
  }

  public static func build(
    evidence: FrozenEvidenceSnapshot,
    globalFacts: FrozenGlobalFacts
  ) throws -> Self {
    guard evidence.captureID == globalFacts.captureID,
      evidence.globalFactsHash == globalFacts.globalFactsHash,
      evidence.policyVersion.rawUTF8Equal(globalFacts.policyVersion),
      evidence.schemaVersion.rawUTF8Equal(globalFacts.schemaVersion),
      evidence.semanticReferenceTimeSeconds == globalFacts.semanticReferenceTimeSeconds,
      globalFacts.coverage.contains(where: { $0.rawRoot == evidence.namespaceBinding.rawRoot })
    else { throw PolicyModelError.actionEvidenceMismatch }
    let matchingRootCoverage = globalFacts.coverage.filter {
      $0.rawRoot == evidence.namespaceBinding.rawRoot
    }
    guard matchingRootCoverage.count == 1 else {
      throw PolicyModelError.duplicateIdentifier
    }
    let evidenceReason = GateReason(
      code: "evidence-bound-policy", semanticEvidenceHash: evidence.evidenceID
    )
    let classification = ClassificationResolver.resolve(evidence.classificationClaims)
    let classificationHash = classification.bindingHash
    let classificationReason = GateReason(
      code: "classification-bound-policy", semanticEvidenceHash: classificationHash
    )

    let namespaceSeals =
      [evidence.namespaceBinding.rootSeal]
      + evidence.namespaceBinding.parentChain.map(\.seal)
    let providerBound =
      evidence.providerState == .known(.fileProviderManaged)
      || namespaceSeals.contains { $0.providerBoundary == .known(.fileProviderManaged) }
    let providerEvidenceComplete =
      evidence.providerState == .known(.local)
      && namespaceSeals.allSatisfy { $0.providerBoundary == .known(.local) }
    let explicitProtectionClear = evidence.explicitProtection == .known(.notProtected)
    let boundProtection: GateResult
    if providerBound || !providerEvidenceComplete || !explicitProtectionClear {
      var reasons = [evidenceReason]
      if providerBound {
        reasons.append(
          GateReason(code: "provider-bound", semanticEvidenceHash: evidence.evidenceID)
        )
      }
      if !explicitProtectionClear {
        reasons.append(
          GateReason(
            code: "explicit-protection-not-clear", semanticEvidenceHash: evidence.evidenceID)
        )
      }
      boundProtection = .rejected(reasons: reasons)
    } else {
      boundProtection = .satisfied(reasons: [evidenceReason])
    }

    let rootCoverage = matchingRootCoverage[0]
    let collectorComplete: Bool
    collectorComplete = evidence.collectorStatus == .known(.complete)
    let boundCompleteness: GateResult =
      evidence.coverage == .complete && collectorComplete && rootCoverage.coverage == .complete
      ? .satisfied(reasons: [evidenceReason]) : .rejected(reasons: [evidenceReason])

    let boundActivity: GateResult
    switch evidence.activity {
    case .known(.inactive):
      boundActivity = .satisfied(reasons: [evidenceReason])
    case .known(.active):
      boundActivity = .unmetCondition(
        conditions: [.activityCleared], reasons: [evidenceReason]
      )
    default:
      boundActivity = .rejected(reasons: [evidenceReason])
    }

    let boundIdentityAndAccess: GateResult
    let namespaceAccessComplete = namespaceSeals.allSatisfy { seal in
      if case .known = seal.accessPolicy, case .known = seal.aclDigest,
        case .known = seal.mountIdentity
      {
        return true
      }
      return false
    }
    if case .known(let identity) = evidence.identity,
      identity == evidence.namespaceBinding.targetIdentity,
      case .known = evidence.accessPolicy,
      case .known = evidence.aclDigest,
      case .known = evidence.targetMountIdentity,
      case .known = evidence.contentProtection,
      namespaceAccessComplete
    {
      boundIdentityAndAccess = .satisfied(reasons: [evidenceReason])
    } else {
      boundIdentityAndAccess = .rejected(reasons: [evidenceReason])
    }

    let boundDependency: GateResult =
      evidence.dependencyState == .known(.complete)
      ? .satisfied(reasons: [evidenceReason]) : .rejected(reasons: [evidenceReason])

    let boundRecoverability: GateResult
    var recoverabilityPredicates = evidence.recoverabilityReviewFacts.map {
      $0.waiverPredicate
    }
    var recoverabilityReasons = evidence.recoverabilityReviewFacts.map {
      $0.gateReason
    }
    var gitWorktreeEvidenceComplete = !evidence.hasGitWorktreeScope
    if let gitWorktree = evidence.gitWorktree {
      gitWorktreeEvidenceComplete = true
      switch gitWorktree.verifiedLocalChanges(
        targetIdentity: evidence.namespaceBinding.targetIdentity)
      {
      case .clean:
        break
      case .present(let changeSetDigest):
        recoverabilityPredicates.append(
          WaiverPredicate(
            kind: .fullyObservedLocalGitWorkDiscard,
            predicate: "discard-fully-observed-local-git-work",
            valueBucket: changeSetDigest.hex,
            semanticEvidenceHash: changeSetDigest
          )
        )
        recoverabilityReasons.append(
          GateReason(code: "local-git-work-present", semanticEvidenceHash: changeSetDigest)
        )
      case nil:
        gitWorktreeEvidenceComplete = false
        recoverabilityReasons.append(
          GateReason(
            code: "git-worktree-evidence-incomplete",
            semanticEvidenceHash: evidence.evidenceID
          )
        )
      }
    }
    if !gitWorktreeEvidenceComplete {
      boundRecoverability = .rejected(
        reasons: recoverabilityReasons + [evidenceReason]
      )
    } else {
      switch evidence.recoverability {
      case .known(.recoverable):
        boundRecoverability =
          recoverabilityPredicates.isEmpty
          ? .satisfied(reasons: [evidenceReason])
          : .requiresWaiver(
            predicates: recoverabilityPredicates,
            reasons: recoverabilityReasons + [evidenceReason]
          )
      case .known(.reviewRequired):
        boundRecoverability =
          recoverabilityPredicates.isEmpty
          ? .rejected(reasons: [evidenceReason])
          : .requiresWaiver(
            predicates: recoverabilityPredicates,
            reasons: recoverabilityReasons + [evidenceReason]
          )
      case .known(.irrecoverable):
        boundRecoverability = .rejected(reasons: recoverabilityReasons + [evidenceReason])
      case .unknown:
        recoverabilityPredicates.append(
          WaiverPredicate(
            kind: .unknownRebuildCost,
            predicate: "recoverability-unknown",
            valueBucket: "unknown",
            semanticEvidenceHash: evidence.evidenceID
          )
        )
        boundRecoverability = .requiresWaiver(
          predicates: recoverabilityPredicates,
          reasons: recoverabilityReasons + [evidenceReason]
        )
      case .absent, .unreadable, .failed:
        boundRecoverability = .rejected(reasons: recoverabilityReasons + [evidenceReason])
      }
    }

    let boundSemantic = Self.deriveSemanticGate(
      evidence: evidence,
      classification: classification,
      classificationHash: classificationHash,
      classificationReason: classificationReason
    )

    return Self(
      protectionAndProvider: boundProtection,
      evidenceCompleteness: boundCompleteness,
      currentActivity: boundActivity,
      identityAndAccess: boundIdentityAndAccess,
      semanticUniqueness: boundSemantic,
      recoverability: boundRecoverability,
      dependencyCompleteness: boundDependency,
      providerBound: providerBound,
      classificationConflict: classification.isConflict,
      sourceBinding: Self.sourceBinding(
        evidence: evidence,
        globalFacts: globalFacts,
        classificationHash: classificationHash
      )
    )
  }

  private static func deriveSemanticGate(
    evidence: FrozenEvidenceSnapshot,
    classification: ClassificationResolution,
    classificationHash: PolicyDigest,
    classificationReason: GateReason
  ) -> GateResult {
    var predicates = evidence.semanticReviewFacts.map(\.waiverPredicate)
    var reasons = evidence.semanticReviewFacts.map(\.gateReason)
    reasons.append(classificationReason)

    if classification.isConflict {
      return .rejected(reasons: reasons)
    }

    var facetsWithoutSuggestion: [ClassificationFacet] = []
    for facet in classification.deterministicMissingFacets.sorted() {
      let suggestions = classification.agentSuggestions.filter { $0.facet == facet }
      if suggestions.isEmpty {
        facetsWithoutSuggestion.append(facet)
        reasons.append(
          GateReason(
            code: "classification-missing-\(facet.rawValue)",
            semanticEvidenceHash: classificationHash
          )
        )
        continue
      }
      let suggestionHash = PolicyBindings.digest(kind: "agent-suggestion-facet") { encoder in
        encoder.string(facet.rawValue)
        encoder.array(suggestions) { $0.bindingBytes }
      }
      predicates.append(
        WaiverPredicate(
          kind: .agentAssistedClassification,
          predicate: "agent-assisted-\(facet.rawValue)",
          valueBucket: facet.rawValue,
          semanticEvidenceHash: suggestionHash
        )
      )
      reasons.append(
        GateReason(
          code: "agent-suggestion-\(facet.rawValue)",
          semanticEvidenceHash: suggestionHash
        )
      )
    }
    if !facetsWithoutSuggestion.isEmpty {
      return .rejected(reasons: reasons)
    }
    return predicates.isEmpty
      ? .satisfied(reasons: reasons)
      : .requiresWaiver(predicates: predicates, reasons: reasons)
  }

  private static func sourceBinding(
    evidence: FrozenEvidenceSnapshot,
    globalFacts: FrozenGlobalFacts,
    classificationHash: PolicyDigest
  ) -> PolicyEvaluationSourceBinding {
    PolicyEvaluationSourceBinding(
      captureID: evidence.captureID,
      evidenceID: evidence.evidenceID,
      globalFactsHash: globalFacts.globalFactsHash,
      classificationResolutionHash: classificationHash,
      policyVersion: evidence.policyVersion,
      schemaVersion: evidence.schemaVersion,
      semanticReferenceTimeSeconds: evidence.semanticReferenceTimeSeconds
    )
  }
}

public enum OneVotePolicy {
  public static func evaluate(_ inputs: OneVotePolicyInputs) throws -> PolicyEvaluation {
    try PolicyEvaluation(
      votes: [
        vote(.protectionAndProvider, inputs.protectionAndProvider),
        vote(.evidenceCompleteness, inputs.evidenceCompleteness),
        vote(.currentActivity, inputs.currentActivity),
        vote(.identityAndAccess, inputs.identityAndAccess),
        vote(.semanticUniqueness, inputs.semanticUniqueness),
        vote(.recoverability, inputs.recoverability),
        vote(.dependencyCompleteness, inputs.dependencyCompleteness),
      ],
      providerBound: inputs.providerBound,
      classificationConflict: inputs.classificationConflict,
      sourceBinding: inputs.sourceBinding
    )
  }

  private static func vote(_ dimension: GateDimension, _ input: PolicyGateInput) -> GateVote {
    GateVote(dimension: dimension, result: input.result)
  }
}

extension SemanticReviewFact {
  fileprivate var waiverPredicate: WaiverPredicate {
    switch self {
    case .recencyAgePolicy(let valueBucket, let evidenceHash):
      WaiverPredicate(
        kind: .recencyAgePolicy,
        predicate: "recency-age-policy",
        valueBucket: valueBucket,
        semanticEvidenceHash: evidenceHash
      )
    case .taskSemanticCompletion(let taskID, let evidenceHash):
      WaiverPredicate(
        kind: .taskSemanticCompletion,
        predicate: "task-semantic-completion",
        valueBucket: taskID,
        semanticEvidenceHash: evidenceHash
      )
    case .duplicateSurvivorChoice(let groupID, let survivorCandidateID, let evidenceHash):
      WaiverPredicate(
        kind: .duplicateSurvivorChoice,
        predicate: "duplicate-survivor-choice-\(groupID)",
        valueBucket: survivorCandidateID,
        semanticEvidenceHash: evidenceHash
      )
    case .normalKeepPolicy(let policyID, let evidenceHash):
      WaiverPredicate(
        kind: .normalKeepPolicy,
        predicate: "normal-keep-policy",
        valueBucket: policyID,
        semanticEvidenceHash: evidenceHash
      )
    }
  }

  fileprivate var gateReason: GateReason {
    GateReason(
      code: "semantic-review-\(waiverPredicate.kind.rawValue)",
      semanticEvidenceHash: waiverPredicate.semanticEvidenceHash
    )
  }
}

extension RecoverabilityReviewFact {
  fileprivate var waiverPredicate: WaiverPredicate {
    switch self {
    case .staticOnlyRebuildEvidence(let artifactKind, let evidenceHash):
      WaiverPredicate(
        kind: .staticOnlyRebuildEvidence,
        predicate: "static-only-rebuild-evidence",
        valueBucket: artifactKind,
        semanticEvidenceHash: evidenceHash
      )
    case .unknownRebuildCost(let valueBucket, let evidenceHash):
      WaiverPredicate(
        kind: .unknownRebuildCost,
        predicate: "unknown-rebuild-cost",
        valueBucket: valueBucket,
        semanticEvidenceHash: evidenceHash
      )
    }
  }

  fileprivate var gateReason: GateReason {
    GateReason(
      code: "recoverability-review-\(waiverPredicate.kind.rawValue)",
      semanticEvidenceHash: waiverPredicate.semanticEvidenceHash
    )
  }
}

extension GitWorktreeEvidence {
  func verifiedLocalChanges(
    targetIdentity: ObjectIdentity
  ) -> GitLocalChangesState? {
    guard noFollowTraversalComplete == .known(true),
      case .known = headIdentity,
      case .known = indexDigest,
      case .known(let registration) = registration,
      registration.registeredWorktreeIdentity == targetIdentity,
      registration.administrativeDirectoryIdentity
        == registration.commonDirectoryIdentity,
      linkage == .known(.ordinary),
      sparseCheckout == .known(.disabled),
      nestedRepositories == .known(.none),
      submodules == .known(.none),
      trustedExclusiveNamespace == .known(true),
      postQuarantineCoverage == .known(.complete),
      case .known(let changes) = localChanges
    else { return nil }
    switch changes {
    case .clean:
      guard postDiscardSuccessor == .absent else { return nil }
    case .present:
      guard case .known(let currentHeadIdentity) = headIdentity,
        case .known(let successor) = postDiscardSuccessor,
        successor.headIdentity == currentHeadIdentity
      else { return nil }
    }
    return changes
  }

  func verifiedDiscardSuccessor(
    targetIdentity: ObjectIdentity
  ) -> GitWorktreeExecutionBaseline? {
    guard case .present = verifiedLocalChanges(targetIdentity: targetIdentity),
      case .known(let currentHeadIdentity) = headIdentity,
      case .known(let successor) = postDiscardSuccessor,
      successor.headIdentity == currentHeadIdentity
    else { return nil }
    return successor
  }

  func verifiedExecutionBaseline(
    currentContent: ContentProtectionBaseline,
    targetIdentity: ObjectIdentity
  ) -> GitWorktreeExecutionBaseline? {
    guard case .known(let headIdentity) = headIdentity,
      case .known(let indexDigest) = indexDigest,
      let changes = verifiedLocalChanges(targetIdentity: targetIdentity)
    else { return nil }
    switch changes {
    case .clean:
      return try? GitWorktreeExecutionBaseline(
        headIdentity: headIdentity,
        indexDigest: indexDigest,
        localChanges: .clean,
        contentProtection: currentContent
      )
    case .present:
      return verifiedDiscardSuccessor(targetIdentity: targetIdentity)
    }
  }
}

extension ClassificationResolution {
  fileprivate var bindingHash: PolicyDigest {
    PolicyBindings.digest(kind: "classification-resolution") { encoder in
      encoder.array(facets) { facet in
        var nested = PolicyBindingEncoder()
        nested.string(facet.facet.rawValue)
        nested.string(facet.value)
        nested.uint8(facet.rank.rawValue)
        nested.array(facet.supportingClaims) { $0.bindingBytes }
        return nested.data
      }
      encoder.array(conflicts) { conflict in
        var nested = PolicyBindingEncoder()
        nested.string(conflict.facet.rawValue)
        nested.uint8(conflict.rank.rawValue)
        nested.array(conflict.claims) { $0.bindingBytes }
        return nested.data
      }
      encoder.array(agentSuggestions) { $0.bindingBytes }
    }
  }
}

extension ClassificationClaim {
  var bindingBytes: Data {
    var encoder = PolicyBindingEncoder()
    encoder.string(facet.rawValue)
    encoder.string(value)
    encoder.string(evidenceKey)
    switch source {
    case .authoritativeAdapter(let identifier):
      encoder.uint8(0)
      encoder.string(identifier)
    case .structuralRecognizer(let identifier):
      encoder.uint8(1)
      encoder.string(identifier)
    case .pathConvention(let identifier):
      encoder.uint8(2)
      encoder.string(identifier)
    case .genericFallback:
      encoder.uint8(3)
    case .agentSuggestion(let identifier):
      encoder.uint8(4)
      encoder.string(identifier)
    }
    return encoder.data
  }
}

extension String {
  fileprivate func rawUTF8Equal(_ other: String) -> Bool {
    Data(utf8) == Data(other.utf8)
  }
}
