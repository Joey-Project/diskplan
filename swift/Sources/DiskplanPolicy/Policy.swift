import Foundation

public enum GateDimension: UInt8, CaseIterable, Comparable, Hashable, Sendable {
  case protectionAndProvider = 0
  case evidenceCompleteness = 1
  case currentActivity = 2
  case identityAndAccess = 3
  case semanticUniqueness = 4
  case recoverability = 5
  case dependencyCompleteness = 6

  public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
}

public enum WaiverKind: String, CaseIterable, Comparable, Hashable, Sendable {
  case recencyAgePolicy
  case staticOnlyRebuildEvidence
  case unknownRebuildCost
  case agentAssistedClassification
  case taskSemanticCompletion
  case duplicateSurvivorChoice
  case fullyObservedLocalGitWorkDiscard
  case normalKeepPolicy

  public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }

  public var gateDimension: GateDimension {
    switch self {
    case .staticOnlyRebuildEvidence, .unknownRebuildCost,
      .fullyObservedLocalGitWorkDiscard:
      .recoverability
    case .recencyAgePolicy, .agentAssistedClassification, .taskSemanticCompletion,
      .duplicateSurvivorChoice, .normalKeepPolicy:
      .semanticUniqueness
    }
  }
}

public struct WaiverPredicate: Equatable, Hashable, Comparable, Sendable {
  public let kind: WaiverKind
  public let predicate: String
  public let valueBucket: String
  public let semanticEvidenceHash: PolicyDigest

  public init(
    kind: WaiverKind,
    predicate: String,
    valueBucket: String,
    semanticEvidenceHash: PolicyDigest
  ) {
    self.kind = kind
    self.predicate = predicate
    self.valueBucket = valueBucket
    self.semanticEvidenceHash = semanticEvidenceHash
  }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    if lhs.kind != rhs.kind { return lhs.kind < rhs.kind }
    let leftPredicate = Data(lhs.predicate.utf8)
    let rightPredicate = Data(rhs.predicate.utf8)
    if leftPredicate != rightPredicate {
      return leftPredicate.lexicographicallyPrecedes(rightPredicate)
    }
    let leftBucket = Data(lhs.valueBucket.utf8)
    let rightBucket = Data(rhs.valueBucket.utf8)
    if leftBucket != rightBucket {
      return leftBucket.lexicographicallyPrecedes(rightBucket)
    }
    return lhs.semanticEvidenceHash < rhs.semanticEvidenceHash
  }

  public static func == (lhs: Self, rhs: Self) -> Bool {
    lhs.kind == rhs.kind && Data(lhs.predicate.utf8) == Data(rhs.predicate.utf8)
      && Data(lhs.valueBucket.utf8) == Data(rhs.valueBucket.utf8)
      && lhs.semanticEvidenceHash == rhs.semanticEvidenceHash
  }

  public func hash(into hasher: inout Hasher) {
    hasher.combine(kind)
    hasher.combine(Data(predicate.utf8))
    hasher.combine(Data(valueBucket.utf8))
    hasher.combine(semanticEvidenceHash)
  }
}

public struct GateReason: Equatable, Hashable, Comparable, Sendable {
  public let code: String
  public let semanticEvidenceHash: PolicyDigest

  public init(code: String, semanticEvidenceHash: PolicyDigest) {
    self.code = code
    self.semanticEvidenceHash = semanticEvidenceHash
  }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    let left = Data(lhs.code.utf8)
    let right = Data(rhs.code.utf8)
    if left != right { return left.lexicographicallyPrecedes(right) }
    return lhs.semanticEvidenceHash < rhs.semanticEvidenceHash
  }

  public static func == (lhs: Self, rhs: Self) -> Bool {
    Data(lhs.code.utf8) == Data(rhs.code.utf8)
      && lhs.semanticEvidenceHash == rhs.semanticEvidenceHash
  }

  public func hash(into hasher: inout Hasher) {
    hasher.combine(Data(code.utf8))
    hasher.combine(semanticEvidenceHash)
  }
}

public enum RevalidationCondition: String, CaseIterable, Comparable, Hashable, Sendable {
  case activityCleared

  public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
}

public enum GateResult: Equatable, Sendable {
  case satisfied(reasons: [GateReason])
  case notApplicable(reasons: [GateReason])
  case requiresWaiver(predicates: [WaiverPredicate], reasons: [GateReason])
  case unmetCondition(conditions: [RevalidationCondition], reasons: [GateReason])
  case rejected(reasons: [GateReason])
}

public struct GateVote: Equatable, Sendable {
  public let dimension: GateDimension
  public let result: GateResult

  public init(dimension: GateDimension, result: GateResult) {
    self.dimension = dimension
    self.result = result
  }
}

public enum Recommendation: String, Equatable, Sendable {
  case safeToClean
  case safeAfterExit
  case likelyRebuildable
  case needsSemanticReview
  case managedByProvider
  case keep
  case scanIncomplete
  case classificationConflict
}

public enum Stageability: Equatable, Sendable {
  case stageable
  case requiresConsents([WaiverPredicate])
  case blocked
}

public struct PolicyEvaluationSourceBinding: Equatable, Sendable {
  public let captureID: PolicyDigest
  public let evidenceID: PolicyDigest
  public let globalFactsHash: PolicyDigest
  public let classificationResolutionHash: PolicyDigest
  public let policyVersion: String
  public let schemaVersion: String
  public let semanticReferenceTimeSeconds: Int64

}

public struct PolicyEvaluation: Equatable, Sendable {
  public let votes: [GateVote]
  public let recommendation: Recommendation
  public let stageability: Stageability
  public let unmetRevalidationConditions: [RevalidationCondition]
  public let sourceBinding: PolicyEvaluationSourceBinding?

  public init(
    votes: [GateVote],
    providerBound: Bool = false,
    classificationConflict: Bool = false,
    defaultReviewRecommendation: Recommendation = .needsSemanticReview
  ) throws {
    try self.init(
      votes: votes,
      providerBound: providerBound,
      classificationConflict: classificationConflict,
      defaultReviewRecommendation: defaultReviewRecommendation,
      sourceBinding: nil
    )
  }

  init(
    votes: [GateVote],
    providerBound: Bool,
    classificationConflict: Bool,
    defaultReviewRecommendation: Recommendation,
    sourceBinding: PolicyEvaluationSourceBinding
  ) throws {
    try self.init(
      votes: votes,
      providerBound: providerBound,
      classificationConflict: classificationConflict,
      defaultReviewRecommendation: defaultReviewRecommendation,
      sourceBinding: Optional(sourceBinding)
    )
  }

  private init(
    votes: [GateVote],
    providerBound: Bool,
    classificationConflict: Bool,
    defaultReviewRecommendation: Recommendation,
    sourceBinding: PolicyEvaluationSourceBinding?
  ) throws {
    guard
      [.likelyRebuildable, .needsSemanticReview, .keep].contains(
        defaultReviewRecommendation
      )
    else { throw PolicyModelError.invalidGateSet }
    let dimensions = votes.map(\.dimension)
    guard dimensions.count == GateDimension.allCases.count,
      Set(dimensions).count == GateDimension.allCases.count,
      Set(dimensions) == Set(GateDimension.allCases)
    else { throw PolicyModelError.invalidGateSet }

    let orderedVotes = try votes.map(Self.normalize).sorted { $0.dimension < $1.dimension }
    self.votes = orderedVotes
    if providerBound,
      !orderedVotes.contains(where: {
        $0.dimension == .protectionAndProvider && $0.result.isRejected
      })
    {
      throw PolicyModelError.invalidGateSet
    }
    if classificationConflict,
      !orderedVotes.contains(where: {
        $0.dimension == .semanticUniqueness && $0.result.isRejected
      })
    {
      throw PolicyModelError.invalidGateSet
    }

    let rejected = orderedVotes.filter(\.result.isRejected)
    let conditions = orderedVotes.flatMap(\.result.conditions)
    let predicates = orderedVotes.flatMap(\.result.predicates)
    let uniqueConditions = Array(Set(conditions)).sorted()
    let uniquePredicates = Array(Set(predicates)).sorted()

    if classificationConflict {
      recommendation = .classificationConflict
    } else if providerBound {
      recommendation = .managedByProvider
    } else if !rejected.isEmpty {
      recommendation =
        rejected.contains { $0.dimension == .evidenceCompleteness }
        ? .scanIncomplete : .keep
    } else if !conditions.isEmpty && predicates.isEmpty {
      recommendation = .safeAfterExit
    } else if !predicates.isEmpty || !conditions.isEmpty {
      recommendation = defaultReviewRecommendation
    } else {
      recommendation = .safeToClean
    }

    if !rejected.isEmpty || !conditions.isEmpty {
      stageability = .blocked
    } else if !uniquePredicates.isEmpty {
      stageability = .requiresConsents(uniquePredicates)
    } else {
      stageability = .stageable
    }
    unmetRevalidationConditions = uniqueConditions
    self.sourceBinding = sourceBinding
  }

  private static func normalize(_ vote: GateVote) throws -> GateVote {
    func normalizedReasons(_ reasons: [GateReason]) throws -> [GateReason] {
      let result = Array(Set(reasons)).sorted()
      guard !result.isEmpty else { throw PolicyModelError.invalidGateSet }
      return result
    }

    let result: GateResult
    switch vote.result {
    case .satisfied(let reasons):
      result = .satisfied(reasons: try normalizedReasons(reasons))
    case .notApplicable(let reasons):
      result = .notApplicable(reasons: try normalizedReasons(reasons))
    case .requiresWaiver(let predicates, let reasons):
      let predicates = Array(Set(predicates)).sorted()
      guard !predicates.isEmpty else { throw PolicyModelError.invalidGateSet }
      for predicate in predicates where predicate.kind.gateDimension != vote.dimension {
        throw PolicyModelError.invalidWaiverDimension(predicate.kind, actual: vote.dimension)
      }
      result = .requiresWaiver(
        predicates: predicates, reasons: try normalizedReasons(reasons)
      )
    case .unmetCondition(let conditions, let reasons):
      let conditions = Array(Set(conditions)).sorted()
      guard !conditions.isEmpty, vote.dimension == .currentActivity else {
        throw PolicyModelError.invalidGateSet
      }
      result = .unmetCondition(
        conditions: conditions, reasons: try normalizedReasons(reasons)
      )
    case .rejected(let reasons):
      result = .rejected(reasons: try normalizedReasons(reasons))
    }
    return GateVote(dimension: vote.dimension, result: result)
  }
}

extension GateResult {
  fileprivate var isRejected: Bool {
    if case .rejected = self { return true }
    return false
  }

  fileprivate var predicates: [WaiverPredicate] {
    guard case .requiresWaiver(let predicates, _) = self else { return [] }
    return predicates
  }

  fileprivate var conditions: [RevalidationCondition] {
    guard case .unmetCondition(let conditions, _) = self else { return [] }
    return conditions
  }
}

public enum PolicyModelError: Error, Equatable, CustomStringConvertible {
  case invalidGateSet
  case invalidWaiverDimension(WaiverKind, actual: GateDimension)
  case invalidDigestLength
  case invalidRawPath
  case invalidNamespaceBinding
  case duplicateIdentifier
  case invalidActionBinding(ActionID)
  case actionEvidenceMismatch
  case mixedPolicyOrSchemaVersion
  case invalidActionContract
  case danglingPrerequisite(ActionID)
  case actionCycle
  case invalidStorageGraph(String)
  case incompleteReleaseSet(String)
  case incompleteReleaseGraph
  case releaseOwnerBindingMismatch(String)
  case releaseSetDanglingAction(ActionID)
  case releaseSetEmpty
  case staleOverlay
  case invalidOverlayVersion
  case invalidOverlayHash
  case injectedSelection(ActionID)
  case actionNotStageable(ActionID)
  case missingWaiver(ActionID, WaiverKind)
  case unexpectedWaiver(ActionID, WaiverKind)
  case invalidWaiverBinding(ActionID, WaiverKind)
  case ambiguousSelectedLineage(ActionLineageID)
  case ambiguousConsentLineage(ActionLineageID)
  case invalidExecutionEpoch
  case missingPrerequisite(ActionID)

  public var description: String {
    switch self {
    case .invalidGateSet: "exactly one valid result for each gate dimension is required"
    case .invalidWaiverDimension(let kind, let actual):
      "waiver \(kind.rawValue) is not allowed for gate \(actual)"
    case .invalidDigestLength: "digest must contain exactly 32 bytes"
    case .invalidRawPath: "raw path is not canonical"
    case .invalidNamespaceBinding: "protected namespace chain is not canonical"
    case .duplicateIdentifier: "duplicate identifier"
    case .invalidActionBinding(let id): "action \(id.hex) does not match its closed binding"
    case .actionEvidenceMismatch: "action target does not match its complete evidence snapshot"
    case .mixedPolicyOrSchemaVersion: "plan mixes policy or schema versions"
    case .invalidActionContract: "action adapter contract is invalid"
    case .danglingPrerequisite(let id): "dangling prerequisite \(id.hex)"
    case .actionCycle: "action graph contains a cycle"
    case .invalidStorageGraph(let reason): "invalid storage graph: \(reason)"
    case .incompleteReleaseSet(let id): "allocation group \(id) is not a complete release set"
    case .incompleteReleaseGraph: "release sets require one complete successful graph evaluation"
    case .releaseOwnerBindingMismatch(let id):
      "release owner \(id) does not exactly match its action evidence"
    case .releaseSetDanglingAction(let id): "release set references missing action \(id.hex)"
    case .releaseSetEmpty: "release set must contain at least one owner action"
    case .staleOverlay: "overlay references stale plan or evidence"
    case .invalidOverlayVersion: "overlay policy or schema version is incompatible"
    case .invalidOverlayHash: "overlay hash does not match its canonical contents"
    case .injectedSelection(let id): "overlay injects unknown action \(id.hex)"
    case .actionNotStageable(let id): "action \(id.hex) is not stageable"
    case .missingWaiver(let id, let kind): "action \(id.hex) requires waiver \(kind.rawValue)"
    case .unexpectedWaiver(let id, let kind):
      "action \(id.hex) has unexpected waiver \(kind.rawValue)"
    case .invalidWaiverBinding(let id, let kind):
      "action \(id.hex) has invalid waiver binding \(kind.rawValue)"
    case .ambiguousSelectedLineage(let lineage):
      "selected action lineage \(lineage.digest.hex) does not resolve to exactly one action"
    case .ambiguousConsentLineage(let lineage):
      "waiver consent lineage \(lineage.digest.hex) does not resolve to exactly one action"
    case .invalidExecutionEpoch: "execution epoch credential binding is invalid"
    case .missingPrerequisite(let id): "selected action is missing prerequisite \(id.hex)"
    }
  }
}
