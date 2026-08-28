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
  public let defaultReviewRecommendation: Recommendation
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
    defaultReviewRecommendation: Recommendation,
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
    self.defaultReviewRecommendation = defaultReviewRecommendation
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
    let declaredEvaluation = try PolicyEvaluation(
      votes: evidence.policyVotes
    )
    let declared = Dictionary(
      uniqueKeysWithValues: declaredEvaluation.votes.map { ($0.dimension, $0.result) }
    )
    let protectionAndProvider = declared[.protectionAndProvider]!
    let evidenceCompleteness = declared[.evidenceCompleteness]!
    let currentActivity = declared[.currentActivity]!
    let identityAndAccess = declared[.identityAndAccess]!
    let semanticUniqueness = declared[.semanticUniqueness]!
    let recoverability = declared[.recoverability]!
    let dependencyCompleteness = declared[.dependencyCompleteness]!

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
    let boundProtection: GateResult
    if providerBound {
      boundProtection = .rejected(reasons: [evidenceReason])
    } else if !providerEvidenceComplete {
      boundProtection = .rejected(reasons: [evidenceReason])
    } else {
      boundProtection = protectionAndProvider
    }

    let rootCoverage = matchingRootCoverage[0]
    let collectorComplete: Bool
    if case .known(let status) = evidence.collectorStatus {
      collectorComplete = status.rawUTF8Equal("complete")
    } else {
      collectorComplete = false
    }
    let boundCompleteness: GateResult =
      evidence.coverage == .complete && collectorComplete && rootCoverage.coverage == .complete
      ? evidenceCompleteness : .rejected(reasons: [evidenceReason])

    let boundActivity: GateResult
    switch evidence.activity {
    case .known("inactive"):
      boundActivity = currentActivity
    case .known("active"):
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
      boundIdentityAndAccess = identityAndAccess
    } else {
      boundIdentityAndAccess = .rejected(reasons: [evidenceReason])
    }

    let boundDependency: GateResult =
      evidence.dependencyState == .known("complete")
      ? dependencyCompleteness : .rejected(reasons: [evidenceReason])

    let boundRecoverability: GateResult
    switch evidence.recoverability {
    case .known:
      boundRecoverability = recoverability
    case .unknown:
      if recoverability.isRejected {
        boundRecoverability = recoverability
      } else {
        boundRecoverability = .requiresWaiver(
          predicates: [
            WaiverPredicate(
              kind: .unknownRebuildCost,
              predicate: "recoverability-unknown",
              valueBucket: "unknown",
              semanticEvidenceHash: evidence.evidenceID
            )
          ],
          reasons: [evidenceReason]
        )
      }
    case .absent, .unreadable, .failed:
      boundRecoverability = .rejected(reasons: [evidenceReason])
    }

    let boundSemantic: GateResult
    if classification.isConflict {
      boundSemantic = .rejected(reasons: [classificationReason])
    } else if !classification.deterministicMissingFacets.isEmpty {
      if !classification.agentSuggestions.isEmpty, !semanticUniqueness.isRejected {
        boundSemantic = .requiresWaiver(
          predicates: [
            WaiverPredicate(
              kind: .agentAssistedClassification,
              predicate: "agent-suggestion-without-deterministic-classification",
              valueBucket: "review-required",
              semanticEvidenceHash: classificationHash
            )
          ],
          reasons: [classificationReason]
        )
      } else if semanticUniqueness.isRejected {
        boundSemantic = semanticUniqueness
      } else {
        boundSemantic = .rejected(reasons: [classificationReason])
      }
    } else {
      boundSemantic = semanticUniqueness
    }

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
      defaultReviewRecommendation: .needsSemanticReview,
      sourceBinding: PolicyEvaluationSourceBinding(
        captureID: evidence.captureID,
        evidenceID: evidence.evidenceID,
        globalFactsHash: globalFacts.globalFactsHash,
        classificationResolutionHash: classificationHash,
        policyVersion: evidence.policyVersion,
        schemaVersion: evidence.schemaVersion,
        semanticReferenceTimeSeconds: evidence.semanticReferenceTimeSeconds
      )
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
      defaultReviewRecommendation: inputs.defaultReviewRecommendation,
      sourceBinding: inputs.sourceBinding
    )
  }

  private static func vote(_ dimension: GateDimension, _ input: PolicyGateInput) -> GateVote {
    GateVote(dimension: dimension, result: input.result)
  }
}

extension GateResult {
  fileprivate var isRejected: Bool {
    if case .rejected = self { return true }
    return false
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
