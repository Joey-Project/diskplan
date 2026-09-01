import CryptoKit
import Foundation

public struct PolicyDigest: Equatable, Hashable, Comparable, Sendable, CustomStringConvertible {
  public let bytes: Data

  public init(bytes: Data) throws {
    guard bytes.count == 32 else { throw PolicyModelError.invalidDigestLength }
    self.bytes = bytes
  }

  fileprivate init(unchecked bytes: Data) { self.bytes = bytes }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    lhs.bytes.lexicographicallyPrecedes(rhs.bytes)
  }

  public var hex: String { bytes.map { String(format: "%02x", $0) }.joined() }
  public var description: String { hex }
}

public struct ActionLineageID: Equatable, Hashable, Comparable, Sendable {
  public let digest: PolicyDigest
  public init(digest: PolicyDigest) { self.digest = digest }
  public static func < (lhs: Self, rhs: Self) -> Bool { lhs.digest < rhs.digest }
}

public struct ActionID: Equatable, Hashable, Comparable, Sendable {
  public let digest: PolicyDigest
  public init(digest: PolicyDigest) { self.digest = digest }
  public static func < (lhs: Self, rhs: Self) -> Bool { lhs.digest < rhs.digest }
  public var hex: String { digest.hex }
}

public enum ObjectKind: String, Equatable, Sendable {
  case regularFile
  case directory
  case symbolicLink
}

public struct ObjectIdentity: Equatable, Sendable {
  public let device: UInt64
  public let object: UInt64
  public let generation: Observation<UInt64>
  public let type: ObjectKind

  public init(
    device: UInt64, object: UInt64, generation: Observation<UInt64>, type: ObjectKind
  ) {
    self.device = device
    self.object = object
    self.generation = generation
    self.type = type
  }
}

public struct ParentNamespaceBinding: Equatable, Sendable {
  public let relativePath: RawTargetPath
  public let identity: ObjectIdentity
  public let seal: NamespaceSealEvidence

  public init(
    relativePath: RawTargetPath,
    identity: ObjectIdentity,
    seal: NamespaceSealEvidence
  ) {
    self.relativePath = relativePath
    self.identity = identity
    self.seal = seal
  }
}

public struct NamespaceSealEvidence: Equatable, Sendable {
  public let trustedNamespace: TrustedNamespace
  public let accessPolicy: Observation<String>
  public let aclDigest: Observation<PolicyDigest>
  public let providerBoundary: Observation<ProviderState>
  public let mountIdentity: Observation<String>

  public init(
    trustedNamespace: TrustedNamespace,
    accessPolicy: Observation<String>,
    aclDigest: Observation<PolicyDigest>,
    providerBoundary: Observation<ProviderState>,
    mountIdentity: Observation<String>
  ) {
    self.trustedNamespace = trustedNamespace
    self.accessPolicy = accessPolicy
    self.aclDigest = aclDigest
    self.providerBoundary = providerBoundary
    self.mountIdentity = mountIdentity
  }

  public var bindingBytes: Data {
    var encoder = PolicyBindingEncoder()
    encoder.string(trustedNamespace.rawValue)
    encoder.observation(accessPolicy) { $0.string($1) }
    encoder.observation(aclDigest) { $0.data($1.bytes) }
    encoder.observation(providerBoundary) { $0.string($1.rawValue) }
    encoder.observation(mountIdentity) { $0.string($1) }
    return encoder.data
  }

}

public struct ProtectedNamespaceBinding: Equatable, Sendable {
  public let rawRoot: RawRootPath
  public let rootIdentity: ObjectIdentity
  public let rootSeal: NamespaceSealEvidence
  public let targetPath: RawTargetPath
  public let targetIdentity: ObjectIdentity
  public let parentChain: [ParentNamespaceBinding]
  public var trustedNamespace: TrustedNamespace { rootSeal.trustedNamespace }

  public init(
    rawRoot: RawRootPath,
    rootIdentity: ObjectIdentity,
    rootSeal: NamespaceSealEvidence,
    targetPath: RawTargetPath,
    targetIdentity: ObjectIdentity,
    parentChain: [ParentNamespaceBinding]
  ) throws {
    guard rootIdentity.type == .directory else { throw PolicyModelError.invalidNamespaceBinding }
    let expectedParents = targetPath.components.dropLast().indices.map { index in
      Array(targetPath.components.prefix(index + 1))
    }
    guard parentChain.count == expectedParents.count else {
      throw PolicyModelError.invalidNamespaceBinding
    }
    for (parent, expected) in zip(parentChain, expectedParents) {
      guard parent.relativePath.components == expected, parent.identity.type == .directory,
        parent.seal.trustedNamespace == rootSeal.trustedNamespace
      else {
        throw PolicyModelError.invalidNamespaceBinding
      }
    }
    self.rawRoot = rawRoot
    self.rootIdentity = rootIdentity
    self.rootSeal = rootSeal
    self.targetPath = targetPath
    self.targetIdentity = targetIdentity
    self.parentChain = parentChain
  }

  var bindingBytes: Data {
    var encoder = PolicyBindingEncoder()
    encoder.data(rawRoot.absoluteBytes)
    encodeIdentity(rootIdentity, into: &encoder)
    encoder.data(rootSeal.bindingBytes)
    encoder.data(targetPath.bindingBytes)
    encodeIdentity(targetIdentity, into: &encoder)
    encoder.array(parentChain) { parent in
      var nested = PolicyBindingEncoder()
      nested.data(parent.relativePath.bindingBytes)
      encodeIdentity(parent.identity, into: &nested)
      nested.data(parent.seal.bindingBytes)
      return nested.data
    }
    return encoder.data
  }
}

public enum EvidenceCoverage: UInt8, Equatable, Sendable {
  case complete
  case partial
  case permissionDenied
  case tccDenied
  case budgetExhausted
  case timedOut
  case mountBoundary
  case providerMetadataOnly
  case collectorFailed
  case notRequestedByProfile
}

public enum ProviderState: String, Equatable, Sendable {
  case local
  case fileProviderManaged
}

public enum CollectorCompletionState: String, Equatable, Sendable {
  case complete
}

public enum ActivityState: String, Equatable, Sendable {
  case inactive
  case active
}

public enum ExplicitProtectionState: String, Equatable, Sendable {
  case notProtected
  case protected
}

public enum DependencyState: String, Equatable, Sendable {
  case complete
}

public enum RecoverabilityState: String, Equatable, Sendable {
  case recoverable
  case reviewRequired
  case irrecoverable
}

public enum SemanticReviewFact: Equatable, Sendable {
  case recencyAgePolicy(valueBucket: String, evidenceHash: PolicyDigest)
  case taskSemanticCompletion(taskID: String, evidenceHash: PolicyDigest)
  case duplicateSurvivorChoice(
    groupID: String, survivorCandidateID: String, evidenceHash: PolicyDigest)
  case normalKeepPolicy(policyID: String, evidenceHash: PolicyDigest)

  var bindingBytes: Data {
    var encoder = PolicyBindingEncoder()
    switch self {
    case .recencyAgePolicy(let valueBucket, let evidenceHash):
      encoder.uint8(0)
      encoder.string(valueBucket)
      encoder.data(evidenceHash.bytes)
    case .taskSemanticCompletion(let taskID, let evidenceHash):
      encoder.uint8(1)
      encoder.string(taskID)
      encoder.data(evidenceHash.bytes)
    case .duplicateSurvivorChoice(let groupID, let survivorCandidateID, let evidenceHash):
      encoder.uint8(2)
      encoder.string(groupID)
      encoder.string(survivorCandidateID)
      encoder.data(evidenceHash.bytes)
    case .normalKeepPolicy(let policyID, let evidenceHash):
      encoder.uint8(3)
      encoder.string(policyID)
      encoder.data(evidenceHash.bytes)
    }
    return encoder.data
  }
}

public enum RecoverabilityReviewFact: Equatable, Sendable {
  case staticOnlyRebuildEvidence(artifactKind: String, evidenceHash: PolicyDigest)
  case unknownRebuildCost(valueBucket: String, evidenceHash: PolicyDigest)
  case unknownRecoverability(UnknownRecoverabilitySemanticEvidence)

  var bindingBytes: Data {
    var encoder = PolicyBindingEncoder()
    switch self {
    case .staticOnlyRebuildEvidence(let artifactKind, let evidenceHash):
      encoder.uint8(0)
      encoder.string(artifactKind)
      encoder.data(evidenceHash.bytes)
    case .unknownRebuildCost(let valueBucket, let evidenceHash):
      encoder.uint8(1)
      encoder.string(valueBucket)
      encoder.data(evidenceHash.bytes)
    case .unknownRecoverability(let evidence):
      encoder.uint8(2)
      encoder.data(evidence.bindingBytes)
    }
    return encoder.data
  }
}

public enum UnknownRecoverabilitySemanticKind: String, Equatable, Sendable {
  case rebuildCostUnknown
}

/// Stable, policy-relevant proof for a recoverability value that cannot be reduced to a known
/// state. The source binding excludes capture IDs, reference times, and whole-snapshot hashes.
public struct UnknownRecoverabilitySemanticEvidence: Equatable, Sendable {
  public let reason: UnknownReason
  public let kind: UnknownRecoverabilitySemanticKind
  public let sourceBindingHash: PolicyDigest

  public init(
    reason: UnknownReason,
    kind: UnknownRecoverabilitySemanticKind,
    sourceBindingHash: PolicyDigest
  ) throws {
    guard reason == .unsupported || reason == .unavailableViaPublicAPI else {
      throw PolicyModelError.invalidGateSet
    }
    self.reason = reason
    self.kind = kind
    self.sourceBindingHash = sourceBindingHash
  }

  public var semanticHash: PolicyDigest {
    PolicyBindings.digest(kind: "recoverability-unknown-semantic") { encoder in
      encoder.string(reason.rawValue)
      encoder.string(kind.rawValue)
      encoder.data(sourceBindingHash.bytes)
    }
  }

  fileprivate var bindingBytes: Data {
    var encoder = PolicyBindingEncoder()
    encoder.string(reason.rawValue)
    encoder.string(kind.rawValue)
    encoder.data(sourceBindingHash.bytes)
    return encoder.data
  }
}

public enum GitLocalChangesState: Equatable, Sendable {
  case clean
  case present(changeSetDigest: PolicyDigest)
}

public enum GitContainedRepositoryState: String, Equatable, Sendable {
  case none
  case present
}

public struct GitWorktreeRegistrationEvidence: Equatable, Sendable {
  public let registeredWorktreeIdentity: ObjectIdentity
  public let administrativeDirectoryIdentity: ObjectIdentity
  public let commonDirectoryIdentity: ObjectIdentity
  public let registrationID: PolicyDigest
  public let metadataDigest: PolicyDigest
  public let headResolutionDigest: PolicyDigest

  public init(
    registeredWorktreeIdentity: ObjectIdentity,
    administrativeDirectoryIdentity: ObjectIdentity,
    commonDirectoryIdentity: ObjectIdentity,
    registrationID: PolicyDigest,
    metadataDigest: PolicyDigest,
    headResolutionDigest: PolicyDigest
  ) throws {
    guard registeredWorktreeIdentity.type == .directory,
      administrativeDirectoryIdentity.type == .directory,
      commonDirectoryIdentity.type == .directory
    else { throw PolicyModelError.invalidActionContract }
    self.registeredWorktreeIdentity = registeredWorktreeIdentity
    self.administrativeDirectoryIdentity = administrativeDirectoryIdentity
    self.commonDirectoryIdentity = commonDirectoryIdentity
    self.registrationID = registrationID
    self.metadataDigest = metadataDigest
    self.headResolutionDigest = headResolutionDigest
  }

  var bindingBytes: Data {
    var encoder = PolicyBindingEncoder()
    encodeIdentity(registeredWorktreeIdentity, into: &encoder)
    encodeIdentity(administrativeDirectoryIdentity, into: &encoder)
    encodeIdentity(commonDirectoryIdentity, into: &encoder)
    encoder.data(registrationID.bytes)
    encoder.data(metadataDigest.bytes)
    encoder.data(headResolutionDigest.bytes)
    return encoder.data
  }
}

public enum GitWorktreeLinkageState: Equatable, Sendable {
  case ordinary
  case linked(registrationID: PolicyDigest)
}

public enum GitSparseCheckoutState: Equatable, Sendable {
  case disabled
  case enabled(configurationDigest: PolicyDigest)
}

public struct GitWorktreeExecutionBaseline: Equatable, Sendable {
  public let headIdentity: PolicyDigest
  public let indexDigest: PolicyDigest
  public let localChanges: GitLocalChangesState
  public let contentProtection: ContentProtectionBaseline

  public init(
    headIdentity: PolicyDigest,
    indexDigest: PolicyDigest,
    localChanges: GitLocalChangesState,
    contentProtection: ContentProtectionBaseline
  ) throws {
    guard localChanges == .clean else { throw PolicyModelError.invalidActionContract }
    self.headIdentity = headIdentity
    self.indexDigest = indexDigest
    self.localChanges = localChanges
    self.contentProtection = contentProtection
  }

  var bindingBytes: Data {
    var encoder = PolicyBindingEncoder()
    encoder.data(headIdentity.bytes)
    encoder.data(indexDigest.bytes)
    encoder.uint8(0)
    switch contentProtection {
    case .requiredDigest(let digest):
      encoder.uint8(0)
      encoder.data(digest.bytes)
    case .explicitlyNotApplicable(let reason):
      encoder.uint8(1)
      encoder.string(reason.rawValue)
    }
    return encoder.data
  }
}

public struct GitWorktreeEvidence: Equatable, Sendable {
  public let noFollowTraversalComplete: Observation<Bool>
  public let headIdentity: Observation<PolicyDigest>
  public let indexDigest: Observation<PolicyDigest>
  public let localChanges: Observation<GitLocalChangesState>
  public let registration: Observation<GitWorktreeRegistrationEvidence>
  public let linkage: Observation<GitWorktreeLinkageState>
  public let sparseCheckout: Observation<GitSparseCheckoutState>
  public let nestedRepositories: Observation<GitContainedRepositoryState>
  public let submodules: Observation<GitContainedRepositoryState>
  public let trustedExclusiveNamespace: Observation<Bool>
  public let postQuarantineCoverage: Observation<EvidenceCoverage>
  public let postDiscardSuccessor: Observation<GitWorktreeExecutionBaseline>

  public init(
    noFollowTraversalComplete: Observation<Bool>,
    headIdentity: Observation<PolicyDigest>,
    indexDigest: Observation<PolicyDigest>,
    localChanges: Observation<GitLocalChangesState>,
    registration: Observation<GitWorktreeRegistrationEvidence>,
    linkage: Observation<GitWorktreeLinkageState>,
    sparseCheckout: Observation<GitSparseCheckoutState>,
    nestedRepositories: Observation<GitContainedRepositoryState>,
    submodules: Observation<GitContainedRepositoryState>,
    trustedExclusiveNamespace: Observation<Bool>,
    postQuarantineCoverage: Observation<EvidenceCoverage>,
    postDiscardSuccessor: Observation<GitWorktreeExecutionBaseline>
  ) {
    self.noFollowTraversalComplete = noFollowTraversalComplete
    self.headIdentity = headIdentity
    self.indexDigest = indexDigest
    self.localChanges = localChanges
    self.registration = registration
    self.linkage = linkage
    self.sparseCheckout = sparseCheckout
    self.nestedRepositories = nestedRepositories
    self.submodules = submodules
    self.trustedExclusiveNamespace = trustedExclusiveNamespace
    self.postQuarantineCoverage = postQuarantineCoverage
    self.postDiscardSuccessor = postDiscardSuccessor
  }

  var bindingBytes: Data {
    var encoder = PolicyBindingEncoder()
    encoder.observation(noFollowTraversalComplete) { $0.bool($1) }
    encoder.observation(headIdentity) { $0.data($1.bytes) }
    encoder.observation(indexDigest) { $0.data($1.bytes) }
    encoder.observation(localChanges) { encoder, state in
      switch state {
      case .clean:
        encoder.uint8(0)
      case .present(let digest):
        encoder.uint8(1)
        encoder.data(digest.bytes)
      }
    }
    encoder.observation(registration) { $0.data($1.bindingBytes) }
    encoder.observation(linkage) { encoder, state in
      switch state {
      case .ordinary:
        encoder.uint8(0)
      case .linked(let registrationID):
        encoder.uint8(1)
        encoder.data(registrationID.bytes)
      }
    }
    encoder.observation(sparseCheckout) { encoder, state in
      switch state {
      case .disabled:
        encoder.uint8(0)
      case .enabled(let configurationDigest):
        encoder.uint8(1)
        encoder.data(configurationDigest.bytes)
      }
    }
    encoder.observation(nestedRepositories) { $0.string($1.rawValue) }
    encoder.observation(submodules) { $0.string($1.rawValue) }
    encoder.observation(trustedExclusiveNamespace) { $0.bool($1) }
    encoder.observation(postQuarantineCoverage) { $0.uint8($1.rawValue) }
    encoder.observation(postDiscardSuccessor) { $0.data($1.bindingBytes) }
    return encoder.data
  }
}

public enum AdapterScopeEvidence: Equatable, Sendable {
  case genericRemove
  case gitWorktree
  case codexCleanTemporary(cleanupScopeID: String)
  case versionedArtifactRemove(artifactKind: String, version: String)
  case completeReleaseSetRemove(allocationGroupID: String)
}

public enum ContentNotApplicableReason: String, Equatable, Sendable {
  case metadataOnlyObject
}

public enum ContentProtectionBaseline: Equatable, Sendable {
  case requiredDigest(PolicyDigest)
  case explicitlyNotApplicable(ContentNotApplicableReason)
}

public struct FrozenEvidenceSnapshot: Equatable, Sendable {
  public let captureID: PolicyDigest
  public let globalFactsHash: PolicyDigest
  public let candidateID: String
  public let namespaceBinding: ProtectedNamespaceBinding
  public let identity: Observation<ObjectIdentity>
  public let coverage: EvidenceCoverage
  public let collectorStatus: Observation<CollectorCompletionState>
  public let activity: Observation<ActivityState>
  public let explicitProtection: Observation<ExplicitProtectionState>
  public let providerState: Observation<ProviderState>
  public let recoverability: Observation<RecoverabilityState>
  public let recoverabilityReviewFacts: [RecoverabilityReviewFact]
  public let dependencyState: Observation<DependencyState>
  public let semanticReviewFacts: [SemanticReviewFact]
  public let accessPolicy: Observation<String>
  public let contentProtection: Observation<ContentProtectionBaseline>
  public let aclDigest: Observation<PolicyDigest>
  public let targetMountIdentity: Observation<String>
  public let removalForceRequirement: Observation<ForceRequirement>
  public let quarantineCapability: Observation<Bool>
  public let gitWorktree: GitWorktreeEvidence?
  public let adapterScope: AdapterScopeEvidence
  public let additionalAdapterScopes: [AdapterScopeEvidence]
  public let classificationClaims: [ClassificationClaim]
  public let semanticReferenceTimeSeconds: Int64
  public let policyVersion: String
  public let schemaVersion: String

  var hasGitWorktreeScope: Bool {
    ([adapterScope] + additionalAdapterScopes).contains {
      if case .gitWorktree = $0 { return true }
      return false
    }
  }

  public init(
    captureID: PolicyDigest,
    globalFactsHash: PolicyDigest,
    candidateID: String,
    namespaceBinding: ProtectedNamespaceBinding,
    identity: Observation<ObjectIdentity>,
    coverage: EvidenceCoverage,
    collectorStatus: Observation<CollectorCompletionState>,
    activity: Observation<ActivityState>,
    explicitProtection: Observation<ExplicitProtectionState>,
    providerState: Observation<ProviderState>,
    recoverability: Observation<RecoverabilityState>,
    recoverabilityReviewFacts: [RecoverabilityReviewFact],
    dependencyState: Observation<DependencyState>,
    semanticReviewFacts: [SemanticReviewFact],
    accessPolicy: Observation<String>,
    contentProtection: Observation<ContentProtectionBaseline>,
    aclDigest: Observation<PolicyDigest>,
    targetMountIdentity: Observation<String>,
    removalForceRequirement: Observation<ForceRequirement>,
    quarantineCapability: Observation<Bool>,
    gitWorktree: GitWorktreeEvidence?,
    adapterScope: AdapterScopeEvidence,
    additionalAdapterScopes: [AdapterScopeEvidence],
    classificationClaims: [ClassificationClaim],
    semanticReferenceTimeSeconds: Int64,
    policyVersion: String,
    schemaVersion: String
  ) throws {
    let canonicalRecoverabilityFacts = recoverabilityReviewFacts.sorted {
      $0.bindingBytes.lexicographicallyPrecedes($1.bindingBytes)
    }
    let canonicalSemanticFacts = semanticReviewFacts.sorted {
      $0.bindingBytes.lexicographicallyPrecedes($1.bindingBytes)
    }
    let canonicalScopes = ([adapterScope] + additionalAdapterScopes).sorted {
      $0.bindingBytes.lexicographicallyPrecedes($1.bindingBytes)
    }
    guard let canonicalPrimaryScope = canonicalScopes.first else {
      throw PolicyModelError.invalidActionContract
    }
    let canonicalAdditionalScopes = Array(canonicalScopes.dropFirst())
    let canonicalClassificationClaims = classificationClaims.sorted {
      $0.bindingBytes.lexicographicallyPrecedes($1.bindingBytes)
    }
    let hasGitScope = canonicalScopes.contains {
      if case .gitWorktree = $0 { return true }
      return false
    }
    guard
      Set(canonicalRecoverabilityFacts.map(\.bindingBytes)).count
        == canonicalRecoverabilityFacts.count,
      Set(canonicalSemanticFacts.map(\.bindingBytes)).count == canonicalSemanticFacts.count,
      Set(canonicalScopes.map(\.bindingBytes)).count == canonicalScopes.count,
      Set(canonicalClassificationClaims.map(\.bindingBytes)).count
        == canonicalClassificationClaims.count,
      canonicalRecoverabilityFacts.allSatisfy(Self.valid),
      Self.hasConsistentRecoverabilitySemantics(
        recoverability, facts: canonicalRecoverabilityFacts),
      canonicalSemanticFacts.allSatisfy(Self.valid),
      Self.hasConsistentDuplicateSurvivors(canonicalSemanticFacts),
      canonicalClassificationClaims.allSatisfy(Self.valid),
      (gitWorktree != nil) == hasGitScope,
      Self.validAdapterScopes(
        primary: canonicalPrimaryScope, additional: canonicalAdditionalScopes)
    else { throw PolicyModelError.invalidGateSet }
    self.captureID = captureID
    self.globalFactsHash = globalFactsHash
    self.candidateID = candidateID
    self.namespaceBinding = namespaceBinding
    self.identity = identity
    self.coverage = coverage
    self.collectorStatus = collectorStatus
    self.activity = activity
    self.explicitProtection = explicitProtection
    self.providerState = providerState
    self.recoverability = recoverability
    self.recoverabilityReviewFacts = canonicalRecoverabilityFacts
    self.dependencyState = dependencyState
    self.semanticReviewFacts = canonicalSemanticFacts
    self.accessPolicy = accessPolicy
    self.contentProtection = contentProtection
    self.aclDigest = aclDigest
    self.targetMountIdentity = targetMountIdentity
    self.removalForceRequirement = removalForceRequirement
    self.quarantineCapability = quarantineCapability
    self.gitWorktree = gitWorktree
    self.adapterScope = canonicalPrimaryScope
    self.additionalAdapterScopes = canonicalAdditionalScopes
    self.classificationClaims = canonicalClassificationClaims
    self.semanticReferenceTimeSeconds = semanticReferenceTimeSeconds
    self.policyVersion = policyVersion
    self.schemaVersion = schemaVersion
  }

  private static func valid(_ fact: RecoverabilityReviewFact) -> Bool {
    switch fact {
    case .staticOnlyRebuildEvidence(let artifactKind, _): hasNonWhitespace(artifactKind)
    case .unknownRebuildCost(let valueBucket, _): hasNonWhitespace(valueBucket)
    case .unknownRecoverability:
      true
    }
  }

  private static func hasConsistentRecoverabilitySemantics(
    _ recoverability: Observation<RecoverabilityState>,
    facts: [RecoverabilityReviewFact]
  ) -> Bool {
    let semanticEvidence = facts.compactMap { fact -> UnknownRecoverabilitySemanticEvidence? in
      guard case .unknownRecoverability(let evidence) = fact else { return nil }
      return evidence
    }
    switch recoverability {
    case .unknown(let reason):
      switch reason {
      case .unsupported, .unavailableViaPublicAPI:
        return semanticEvidence.count == 1 && semanticEvidence[0].reason == reason
      case .notRequested, .budgetExhausted, .timedOut, .incompleteCoverage:
        return semanticEvidence.isEmpty
      }
    case .known, .absent, .unreadable, .failed:
      return semanticEvidence.isEmpty
    }
  }

  private static func valid(_ fact: SemanticReviewFact) -> Bool {
    switch fact {
    case .recencyAgePolicy(let valueBucket, _): hasNonWhitespace(valueBucket)
    case .taskSemanticCompletion(let taskID, _): hasNonWhitespace(taskID)
    case .duplicateSurvivorChoice(let groupID, let survivorCandidateID, _):
      hasNonWhitespace(groupID) && hasNonWhitespace(survivorCandidateID)
    case .normalKeepPolicy(let policyID, _): hasNonWhitespace(policyID)
    }
  }

  private static func hasConsistentDuplicateSurvivors(
    _ facts: [SemanticReviewFact]
  ) -> Bool {
    let choices = facts.compactMap { fact -> (Data, Data)? in
      guard case .duplicateSurvivorChoice(let groupID, let survivorCandidateID, _) = fact
      else { return nil }
      return (Data(groupID.utf8), Data(survivorCandidateID.utf8))
    }
    return Dictionary(grouping: choices, by: \.0).values.allSatisfy {
      Set($0.map(\.1)).count == 1
    }
  }

  private static func valid(_ claim: ClassificationClaim) -> Bool {
    guard hasNonWhitespace(claim.value), hasNonWhitespace(claim.evidenceKey) else {
      return false
    }
    switch claim.source {
    case .authoritativeAdapter(let identifier), .structuralRecognizer(let identifier),
      .pathConvention(let identifier), .agentSuggestion(let identifier):
      return hasNonWhitespace(identifier)
    case .genericFallback:
      return true
    }
  }

  private static func validAdapterScopes(
    primary: AdapterScopeEvidence,
    additional: [AdapterScopeEvidence]
  ) -> Bool {
    let scopes = [primary] + additional
    guard scopes.allSatisfy(Self.valid) else { return false }
    if scopes.contains(where: { if case .gitWorktree = $0 { true } else { false } }) {
      return scopes.allSatisfy { if case .gitWorktree = $0 { true } else { false } }
    }
    let hasGeneric = scopes.contains { if case .genericRemove = $0 { true } else { false } }
    if hasGeneric {
      return scopes.allSatisfy {
        switch $0 {
        case .genericRemove, .completeReleaseSetRemove: true
        default: false
        }
      }
    }
    let terminalScopes = scopes.filter {
      switch $0 {
      case .completeReleaseSetRemove: false
      default: true
      }
    }
    return terminalScopes.count <= 1
  }

  private static func valid(_ scope: AdapterScopeEvidence) -> Bool {
    switch scope {
    case .genericRemove, .gitWorktree:
      return true
    case .codexCleanTemporary(let cleanupScopeID):
      return hasNonWhitespace(cleanupScopeID)
    case .versionedArtifactRemove(let artifactKind, let version):
      return hasNonWhitespace(artifactKind) && hasNonWhitespace(version)
    case .completeReleaseSetRemove(let allocationGroupID):
      return hasNonWhitespace(allocationGroupID)
    }
  }

  public var evidenceID: PolicyDigest {
    PolicyBindings.digest(kind: "evidence") { $0.data(bindingBytes) }
  }

  var bindingBytes: Data {
    var encoder = PolicyBindingEncoder()
    encoder.data(captureID.bytes)
    encoder.data(globalFactsHash.bytes)
    encoder.string(candidateID)
    encoder.data(namespaceBinding.bindingBytes)
    encoder.observation(identity) { encoder, identity in
      encoder.uint64(identity.device)
      encoder.uint64(identity.object)
      encoder.observation(identity.generation) { $0.uint64($1) }
      encoder.string(identity.type.rawValue)
    }
    encoder.uint8(coverage.rawValue)
    encoder.observation(collectorStatus) { $0.string($1.rawValue) }
    encoder.observation(activity) { $0.string($1.rawValue) }
    encoder.observation(explicitProtection) { $0.string($1.rawValue) }
    encoder.observation(providerState) { $0.string($1.rawValue) }
    encoder.observation(recoverability) { $0.string($1.rawValue) }
    encoder.array(recoverabilityReviewFacts) { $0.bindingBytes }
    encoder.observation(dependencyState) { $0.string($1.rawValue) }
    encoder.array(semanticReviewFacts) { $0.bindingBytes }
    encoder.observation(accessPolicy) { $0.string($1) }
    encoder.observation(contentProtection) { encoder, baseline in
      switch baseline {
      case .requiredDigest(let digest):
        encoder.uint8(0)
        encoder.data(digest.bytes)
      case .explicitlyNotApplicable(let reason):
        encoder.uint8(1)
        encoder.string(reason.rawValue)
      }
    }
    encoder.observation(aclDigest) { $0.data($1.bytes) }
    encoder.observation(targetMountIdentity) { $0.string($1) }
    encoder.observation(removalForceRequirement) { $0.string($1.rawValue) }
    encoder.observation(quarantineCapability) { $0.bool($1) }
    if let gitWorktree {
      encoder.bool(true)
      encoder.data(gitWorktree.bindingBytes)
    } else {
      encoder.bool(false)
    }
    encodeAdapterScopeEvidence(adapterScope, into: &encoder)
    encoder.array(additionalAdapterScopes) { $0.bindingBytes }
    encoder.array(classificationClaims) { $0.bindingBytes }
    encoder.int64(semanticReferenceTimeSeconds)
    encoder.string(policyVersion)
    encoder.string(schemaVersion)
    return encoder.data
  }
}

public struct GlobalCoverageFact: Equatable, Sendable {
  public let rawRoot: RawRootPath
  public let coverage: EvidenceCoverage
  public let reasons: [String]

  public init(rawRoot: RawRootPath, coverage: EvidenceCoverage, reasons: [String]) {
    self.rawRoot = rawRoot
    self.coverage = coverage
    self.reasons = reasons.sorted(by: rawStringPrecedes)
  }
}

public struct FrozenGlobalFacts: Equatable, Sendable {
  public let captureID: PolicyDigest
  public let profile: String
  public let configuration: Data
  public let coverage: [GlobalCoverageFact]
  public let semanticReferenceTimeSeconds: Int64
  public let policyVersion: String
  public let schemaVersion: String

  public init(
    captureID: PolicyDigest,
    profile: String,
    configuration: Data,
    coverage: [GlobalCoverageFact],
    semanticReferenceTimeSeconds: Int64,
    policyVersion: String,
    schemaVersion: String
  ) {
    self.captureID = captureID
    self.profile = profile
    self.configuration = configuration
    self.coverage = coverage.sorted { left, right in
      if left.rawRoot != right.rawRoot {
        return left.rawRoot < right.rawRoot
      }
      if left.coverage != right.coverage {
        return left.coverage.rawValue < right.coverage.rawValue
      }
      return rawStringArrayPrecedes(left.reasons, right.reasons)
    }
    self.semanticReferenceTimeSeconds = semanticReferenceTimeSeconds
    self.policyVersion = policyVersion
    self.schemaVersion = schemaVersion
  }

  public var globalFactsHash: PolicyDigest {
    PolicyBindings.digest(kind: "global-facts") { $0.data(bindingBytes) }
  }

  var bindingBytes: Data {
    var encoder = PolicyBindingEncoder()
    encoder.data(captureID.bytes)
    encoder.string(profile)
    encoder.data(configuration)
    encoder.array(coverage) { fact in
      var nested = PolicyBindingEncoder()
      nested.data(fact.rawRoot.absoluteBytes)
      nested.uint8(fact.coverage.rawValue)
      nested.array(fact.reasons) { Data($0.utf8) }
      return nested.data
    }
    encoder.int64(semanticReferenceTimeSeconds)
    encoder.string(policyVersion)
    encoder.string(schemaVersion)
    return encoder.data
  }
}

public struct IdentityProtectionContract: Equatable, Sendable {
  public let expectedIdentity: ObjectIdentity
}

public struct ContentProtectionContract: Equatable, Sendable {
  public let expectedBaseline: ContentProtectionBaseline
}

public struct RequiredAccessPolicyBaseline: Equatable, Sendable {
  public let accessPolicyBytes: Data
  public let aclDigest: PolicyDigest
  public let providerState: ProviderState
  public let mountIdentityBytes: Data

  public init(
    accessPolicyBytes: Data,
    aclDigest: PolicyDigest,
    providerState: ProviderState,
    mountIdentityBytes: Data
  ) {
    self.accessPolicyBytes = accessPolicyBytes
    self.aclDigest = aclDigest
    self.providerState = providerState
    self.mountIdentityBytes = mountIdentityBytes
  }
}

public struct AccessPolicyProtectionContract: Equatable, Sendable {
  public let requiredBaseline: RequiredAccessPolicyBaseline
}

public struct ProtectedPropertyContracts: Equatable, Sendable {
  public let identity: IdentityProtectionContract
  public let content: ContentProtectionContract
  public let accessPolicy: AccessPolicyProtectionContract
}

public enum ActionPostcondition: Equatable, Sendable {
  case targetAbsent
  case gitWorktreeLocalChangesDiscarded(
    changeSetDigest: PolicyDigest,
    successor: GitWorktreeExecutionBaseline
  )
  case worktreeQuarantinedThenAbsent
  case cleanupScopeAbsent(String)
  case artifactVersionAbsent(kind: String, version: String)
  case allocationGroupReleased(String)
}

public enum TrustedNamespace: String, Equatable, Sendable {
  case ownerPrivate
  case explicitlyTrustedUserNamespace
  case unverified
}

public enum ForceRequirement: String, Equatable, Sendable {
  case notRequired
  case requiresForceWithWarning
}

public enum RemovalPathSlot: String, Equatable, Sendable {
  case prototypeRawTargetPath
}

public struct GenericRemoveContract: Equatable, Sendable {
  public let removalPathSlot: RemovalPathSlot
  public let targetKind: ObjectKind
  public let pathRaceResidual: Bool
  public let trustedNamespace: TrustedNamespace
  public let forceRequirement: ForceRequirement

  fileprivate init(
    removalPathSlot: RemovalPathSlot,
    targetKind: ObjectKind,
    pathRaceResidual: Bool,
    trustedNamespace: TrustedNamespace,
    forceRequirement: ForceRequirement
  ) throws {
    guard pathRaceResidual else { throw PolicyModelError.invalidActionContract }
    self.removalPathSlot = removalPathSlot
    self.targetKind = targetKind
    self.pathRaceResidual = pathRaceResidual
    self.trustedNamespace = trustedNamespace
    self.forceRequirement = forceRequirement
  }
}

public struct GitWorktreeRemoveContract: Equatable, Sendable {
  public let quarantineRequired: Bool
  public let verifiedEvidence: GitWorktreeEvidence
  public let executionBaseline: GitWorktreeExecutionBaseline
  public let requiresDiscardLocalChanges: Bool

  fileprivate init(
    verifiedEvidence: GitWorktreeEvidence,
    executionBaseline: GitWorktreeExecutionBaseline,
    requiresDiscardLocalChanges: Bool
  ) {
    quarantineRequired = true
    self.verifiedEvidence = verifiedEvidence
    self.executionBaseline = executionBaseline
    self.requiresDiscardLocalChanges = requiresDiscardLocalChanges
  }
}

public struct GitWorktreeDiscardLocalChangesContract: Equatable, Sendable {
  public let verifiedEvidence: GitWorktreeEvidence
  public let changeSetDigest: PolicyDigest
  public let successorBaseline: GitWorktreeExecutionBaseline

  fileprivate init(
    verifiedEvidence: GitWorktreeEvidence,
    changeSetDigest: PolicyDigest,
    successorBaseline: GitWorktreeExecutionBaseline
  ) {
    self.verifiedEvidence = verifiedEvidence
    self.changeSetDigest = changeSetDigest
    self.successorBaseline = successorBaseline
  }
}

public struct CodexTemporaryRemoveContract: Equatable, Sendable {
  public let cleanupScopeID: String
  fileprivate init(cleanupScopeID: String) { self.cleanupScopeID = cleanupScopeID }
}

public struct VersionedArtifactRemoveContract: Equatable, Sendable {
  public let artifactKind: String
  public let version: String
  fileprivate init(artifactKind: String, version: String) {
    self.artifactKind = artifactKind
    self.version = version
  }
}

public struct CompleteReleaseSetActionBinding: Equatable, Sendable {
  public let allocationGroupID: String
  public let graphDigest: PolicyDigest
  public let topologyExpectation: ReleaseTopologyExpectation
  public let ownerCandidateIDs: [String]
  public let ownerActionIDs: [ActionID]
  public let conditionalReclaimBytes: UInt64

  fileprivate init(releaseSet: PlanReleaseSet) {
    allocationGroupID = releaseSet.allocationGroupID
    graphDigest = releaseSet.graphDigest
    topologyExpectation = releaseSet.topologyExpectation
    ownerCandidateIDs = releaseSet.ownerCandidateIDs
    ownerActionIDs = releaseSet.ownerActionIDs
    conditionalReclaimBytes = releaseSet.conditionalReclaimBytes
  }

  var bindingBytes: Data {
    var encoder = PolicyBindingEncoder()
    encoder.string(allocationGroupID)
    encoder.data(graphDigest.bytes)
    encoder.data(encodeReleaseTopologyExpectation(topologyExpectation))
    encoder.array(ownerCandidateIDs) { Data($0.utf8) }
    encoder.array(ownerActionIDs) { $0.digest.bytes }
    encoder.uint64(conditionalReclaimBytes)
    return encoder.data
  }

  var stableLineageBytes: Data {
    var encoder = PolicyBindingEncoder()
    encoder.string(allocationGroupID)
    encoder.array(
      topologyExpectation.fileObjects.sorted {
        rawStringPrecedes($0.fileObjectID, $1.fileObjectID)
      }
    ) { file in
      var nested = PolicyBindingEncoder()
      nested.string(file.fileObjectID)
      nested.array(
        file.owners.sorted { left, right in
          if !rawStringEqual(left.candidateID, right.candidateID) {
            return rawStringPrecedes(left.candidateID, right.candidateID)
          }
          return left.path < right.path
        }
      ) { owner in
        var ownerEncoder = PolicyBindingEncoder()
        ownerEncoder.string(owner.candidateID)
        ownerEncoder.data(owner.path.bindingBytes)
        return ownerEncoder.data
      }
      return nested.data
    }
    encoder.array(ownerCandidateIDs) { Data($0.utf8) }
    return encoder.data
  }
}

public struct CompleteReleaseSetRemoveContract: Equatable, Sendable {
  public let binding: CompleteReleaseSetActionBinding
  fileprivate init(binding: CompleteReleaseSetActionBinding) { self.binding = binding }
}

public enum ActionAdapterRequest: Equatable, Sendable {
  case genericRemove
  case gitWorktreeRemove
  case gitWorktreeDiscardLocalChanges
  case codexCleanTemporary(cleanupScopeID: String)
  case versionedArtifactRemove(artifactKind: String, version: String)
  case completeReleaseSetRemove(binding: CompleteReleaseSetActionBinding)
}

public enum ActionAdapterContract: Equatable, Sendable {
  case genericRemove(GenericRemoveContract)
  case gitWorktreeRemove(GitWorktreeRemoveContract)
  case gitWorktreeDiscardLocalChanges(GitWorktreeDiscardLocalChangesContract)
  case codexCleanTemporary(CodexTemporaryRemoveContract)
  case versionedArtifactRemove(VersionedArtifactRemoveContract)
  case completeReleaseSetRemove(CompleteReleaseSetRemoveContract)
}

public enum RecommendationTier: UInt8, Comparable, Equatable, Sendable {
  case safe = 0
  case rebuildable = 1
  case review = 2
  case blocked = 3

  public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
}

public struct ActionDisplayMetrics: Equatable, Sendable {
  public let tier: RecommendationTier
  public let immediateReclaimBytes: KnownOrUnknown<UInt64>
  public let inactiveDurationSeconds: KnownOrUnknown<UInt64>
  public let rebuildCost: KnownOrUnknown<UInt64>
  public let cleanupCost: KnownOrUnknown<UInt64>
  public let canonicalRawPath: Data

  public init(
    immediateReclaimBytes: KnownOrUnknown<UInt64>,
    inactiveDurationSeconds: KnownOrUnknown<UInt64>,
    rebuildCost: KnownOrUnknown<UInt64>,
    cleanupCost: KnownOrUnknown<UInt64>,
    canonicalRawPath: Data
  ) {
    tier = .blocked
    self.immediateReclaimBytes = immediateReclaimBytes
    self.inactiveDurationSeconds = inactiveDurationSeconds
    self.rebuildCost = rebuildCost
    self.cleanupCost = cleanupCost
    self.canonicalRawPath = canonicalRawPath
  }

  private init(
    tier: RecommendationTier,
    immediateReclaimBytes: KnownOrUnknown<UInt64>,
    inactiveDurationSeconds: KnownOrUnknown<UInt64>,
    rebuildCost: KnownOrUnknown<UInt64>,
    cleanupCost: KnownOrUnknown<UInt64>,
    canonicalRawPath: Data
  ) {
    self.tier = tier
    self.immediateReclaimBytes = immediateReclaimBytes
    self.inactiveDurationSeconds = inactiveDurationSeconds
    self.rebuildCost = rebuildCost
    self.cleanupCost = cleanupCost
    self.canonicalRawPath = canonicalRawPath
  }

  fileprivate func replacingTier(_ tier: RecommendationTier) -> Self {
    Self(
      tier: tier,
      immediateReclaimBytes: immediateReclaimBytes,
      inactiveDurationSeconds: inactiveDurationSeconds,
      rebuildCost: rebuildCost,
      cleanupCost: cleanupCost,
      canonicalRawPath: canonicalRawPath
    )
  }

  #if DEBUG
    static func testing(
      tier: RecommendationTier,
      immediateReclaimBytes: KnownOrUnknown<UInt64>,
      inactiveDurationSeconds: KnownOrUnknown<UInt64>,
      rebuildCost: KnownOrUnknown<UInt64>,
      cleanupCost: KnownOrUnknown<UInt64>,
      canonicalRawPath: Data
    ) -> Self {
      Self(
        tier: tier,
        immediateReclaimBytes: immediateReclaimBytes,
        inactiveDurationSeconds: inactiveDurationSeconds,
        rebuildCost: rebuildCost,
        cleanupCost: cleanupCost,
        canonicalRawPath: canonicalRawPath
      )
    }
  #endif
}

public struct ActionPrototype: Equatable, Sendable {
  public let policyVersion: String
  public let schemaVersion: String
  public let adapterContract: ActionAdapterContract
  public let targetIdentity: ObjectIdentity
  public let namespaceBinding: ProtectedNamespaceBinding
  public let protectedProperties: ProtectedPropertyContracts
  public let postcondition: ActionPostcondition

  fileprivate init(
    policyVersion: String,
    schemaVersion: String,
    adapterContract: ActionAdapterContract,
    targetIdentity: ObjectIdentity,
    namespaceBinding: ProtectedNamespaceBinding,
    protectedProperties: ProtectedPropertyContracts,
    postcondition: ActionPostcondition
  ) {
    self.policyVersion = policyVersion
    self.schemaVersion = schemaVersion
    self.adapterContract = adapterContract
    self.targetIdentity = targetIdentity
    self.namespaceBinding = namespaceBinding
    self.protectedProperties = protectedProperties
    self.postcondition = postcondition
  }

  public static func build(
    request: ActionAdapterRequest,
    evidence: FrozenEvidenceSnapshot
  ) throws -> Self {
    guard case .known(let identity) = evidence.identity,
      identity == evidence.namespaceBinding.targetIdentity,
      evidence.namespaceBinding.trustedNamespace != .unverified,
      case .known(let contentBaseline) = evidence.contentProtection,
      case .known(let accessPolicy) = evidence.accessPolicy,
      case .known(let aclDigest) = evidence.aclDigest,
      case .known(let providerState) = evidence.providerState,
      case .known(let mountIdentity) = evidence.targetMountIdentity
    else { throw PolicyModelError.actionEvidenceMismatch }

    let adapter: ActionAdapterContract
    let postcondition: ActionPostcondition
    var protectedContentBaseline = contentBaseline
    switch request {
    case .genericRemove:
      guard evidenceSupportsAdapterScope(evidence, .genericRemove),
        case .known(let force) = evidence.removalForceRequirement
      else {
        throw PolicyModelError.invalidActionContract
      }
      adapter = .genericRemove(
        try GenericRemoveContract(
          removalPathSlot: .prototypeRawTargetPath,
          targetKind: identity.type,
          pathRaceResidual: true,
          trustedNamespace: evidence.namespaceBinding.trustedNamespace,
          forceRequirement: force
        )
      )
      postcondition = .targetAbsent
    case .gitWorktreeRemove:
      guard evidenceSupportsAdapterScope(evidence, .gitWorktree), identity.type == .directory,
        evidence.quarantineCapability == .known(true),
        evidence.namespaceBinding.trustedNamespace == .ownerPrivate,
        let gitWorktree = evidence.gitWorktree,
        let localChanges = gitWorktree.verifiedLocalChanges(targetIdentity: identity),
        let executionBaseline = gitWorktree.verifiedExecutionBaseline(
          currentContent: contentBaseline,
          targetIdentity: identity)
      else {
        throw PolicyModelError.invalidActionContract
      }
      adapter = .gitWorktreeRemove(
        GitWorktreeRemoveContract(
          verifiedEvidence: gitWorktree,
          executionBaseline: executionBaseline,
          requiresDiscardLocalChanges: {
            if case .present = localChanges { return true }
            return false
          }()
        )
      )
      protectedContentBaseline = executionBaseline.contentProtection
      postcondition = .worktreeQuarantinedThenAbsent
    case .gitWorktreeDiscardLocalChanges:
      guard evidenceSupportsAdapterScope(evidence, .gitWorktree), identity.type == .directory,
        evidence.namespaceBinding.trustedNamespace == .ownerPrivate,
        let gitWorktree = evidence.gitWorktree,
        case .present(let changeSetDigest) = gitWorktree.verifiedLocalChanges(
          targetIdentity: identity),
        let successorBaseline = gitWorktree.verifiedDiscardSuccessor(
          targetIdentity: identity)
      else {
        throw PolicyModelError.invalidActionContract
      }
      adapter = .gitWorktreeDiscardLocalChanges(
        GitWorktreeDiscardLocalChangesContract(
          verifiedEvidence: gitWorktree,
          changeSetDigest: changeSetDigest,
          successorBaseline: successorBaseline
        )
      )
      postcondition = .gitWorktreeLocalChangesDiscarded(
        changeSetDigest: changeSetDigest,
        successor: successorBaseline
      )
    case .codexCleanTemporary(let cleanupScopeID):
      guard hasNonWhitespace(cleanupScopeID),
        evidenceSupportsAdapterScope(
          evidence, .codexCleanTemporary(cleanupScopeID: cleanupScopeID))
      else { throw PolicyModelError.invalidActionContract }
      adapter = .codexCleanTemporary(
        CodexTemporaryRemoveContract(cleanupScopeID: cleanupScopeID)
      )
      postcondition = .cleanupScopeAbsent(cleanupScopeID)
    case .versionedArtifactRemove(let artifactKind, let version):
      guard hasNonWhitespace(artifactKind), hasNonWhitespace(version) else {
        throw PolicyModelError.invalidActionContract
      }
      guard
        evidenceSupportsAdapterScope(
          evidence,
          .versionedArtifactRemove(artifactKind: artifactKind, version: version)
        )
      else { throw PolicyModelError.invalidActionContract }
      adapter = .versionedArtifactRemove(
        VersionedArtifactRemoveContract(artifactKind: artifactKind, version: version)
      )
      postcondition = .artifactVersionAbsent(kind: artifactKind, version: version)
    case .completeReleaseSetRemove(let binding):
      guard hasNonWhitespace(binding.allocationGroupID),
        evidenceSupportsAdapterScope(
          evidence,
          .completeReleaseSetRemove(allocationGroupID: binding.allocationGroupID)),
        binding.ownerCandidateIDs.contains(where: {
          rawStringEqual($0, evidence.candidateID)
        }),
        !binding.ownerActionIDs.isEmpty,
        binding.ownerActionIDs.count == binding.ownerCandidateIDs.count,
        Set(binding.ownerActionIDs).count == binding.ownerActionIDs.count,
        Set(binding.ownerCandidateIDs.map { Data($0.utf8) }).count
          == binding.ownerCandidateIDs.count
      else {
        throw PolicyModelError.invalidActionContract
      }
      adapter = .completeReleaseSetRemove(
        CompleteReleaseSetRemoveContract(binding: binding)
      )
      postcondition = .allocationGroupReleased(binding.allocationGroupID)
    }
    return Self(
      policyVersion: evidence.policyVersion,
      schemaVersion: evidence.schemaVersion,
      adapterContract: adapter,
      targetIdentity: identity,
      namespaceBinding: evidence.namespaceBinding,
      protectedProperties: ProtectedPropertyContracts(
        identity: IdentityProtectionContract(expectedIdentity: identity),
        content: ContentProtectionContract(expectedBaseline: protectedContentBaseline),
        accessPolicy: AccessPolicyProtectionContract(
          requiredBaseline: RequiredAccessPolicyBaseline(
            accessPolicyBytes: Data(accessPolicy.utf8),
            aclDigest: aclDigest,
            providerState: providerState,
            mountIdentityBytes: Data(mountIdentity.utf8)
          )
        )
      ),
      postcondition: postcondition
    )
  }
}

public struct ActionDefinition: Equatable, Sendable {
  public let lineageID: ActionLineageID
  public let id: ActionID
  public let prototype: ActionPrototype
  public let evidence: FrozenEvidenceSnapshot
  public let globalFactsHash: PolicyDigest
  public let prerequisiteLineageIDs: [ActionLineageID]
  public let prerequisiteActionIDs: [ActionID]
  public let evaluation: PolicyEvaluation
  public let displayMetrics: ActionDisplayMetrics

  public var evidenceID: PolicyDigest { evidence.evidenceID }

  public static func build(
    prototype: ActionPrototype,
    evidence: FrozenEvidenceSnapshot,
    globalFacts: FrozenGlobalFacts,
    prerequisites: [ActionDefinition],
    evaluation: PolicyEvaluation,
    displayMetrics: ActionDisplayMetrics
  ) throws -> Self {
    try validate(
      prototype: prototype,
      evidence: evidence,
      globalFacts: globalFacts,
      evaluation: evaluation,
      displayMetrics: displayMetrics
    )
    guard
      prerequisites.allSatisfy({
        rawStringEqual($0.prototype.policyVersion, prototype.policyVersion)
          && rawStringEqual($0.prototype.schemaVersion, prototype.schemaVersion)
          && $0.globalFactsHash == globalFacts.globalFactsHash
          && $0.evidence.semanticReferenceTimeSeconds
            == globalFacts.semanticReferenceTimeSeconds
      })
    else { throw PolicyModelError.mixedPolicyOrSchemaVersion }
    let prerequisiteActionIDs = prerequisites.map(\.id)
    let prerequisiteLineageIDs = prerequisites.map(\.lineageID)
    guard Set(prerequisiteActionIDs).count == prerequisiteActionIDs.count,
      Set(prerequisiteLineageIDs).count == prerequisiteLineageIDs.count
    else { throw PolicyModelError.invalidActionContract }
    if case .completeReleaseSetRemove(let contract) = prototype.adapterContract {
      guard
        Set(contract.binding.ownerActionIDs).isSubset(of: Set(prerequisiteActionIDs)),
        let anchorIndex = contract.binding.ownerCandidateIDs.firstIndex(where: {
          rawStringEqual($0, evidence.candidateID)
        }),
        anchorIndex < contract.binding.ownerActionIDs.count,
        let anchor = prerequisites.first(where: {
          $0.id == contract.binding.ownerActionIDs[anchorIndex]
        }),
        rawStringEqual(anchor.evidence.candidateID, evidence.candidateID),
        anchor.evidenceID == evidence.evidenceID
      else {
        throw PolicyModelError.invalidActionContract
      }
    }
    let effectiveEvaluation = try actionAwareEvaluation(
      evaluation,
      prototype: prototype,
      prerequisites: prerequisites
    )
    return make(
      prototype: prototype,
      evidence: evidence,
      globalFactsHash: globalFacts.globalFactsHash,
      prerequisiteLineageIDs: prerequisiteLineageIDs.sorted(),
      prerequisiteActionIDs: prerequisiteActionIDs.sorted(),
      evaluation: effectiveEvaluation,
      displayMetrics: displayMetrics
    )
  }

  fileprivate var recomputed: Self {
    Self.make(
      prototype: prototype,
      evidence: evidence,
      globalFactsHash: globalFactsHash,
      prerequisiteLineageIDs: prerequisiteLineageIDs.sorted(),
      prerequisiteActionIDs: prerequisiteActionIDs.sorted(),
      evaluation: evaluation,
      displayMetrics: displayMetrics
    )
  }

  private static func validate(
    prototype: ActionPrototype,
    evidence: FrozenEvidenceSnapshot,
    globalFacts: FrozenGlobalFacts,
    evaluation: PolicyEvaluation,
    displayMetrics: ActionDisplayMetrics
  ) throws {
    guard rawStringEqual(prototype.policyVersion, evidence.policyVersion),
      rawStringEqual(prototype.schemaVersion, evidence.schemaVersion),
      prototype.namespaceBinding.bindingBytes == evidence.namespaceBinding.bindingBytes,
      displayMetrics.canonicalRawPath == prototype.namespaceBinding.targetPath.displayBytes,
      case .known(let identity) = evidence.identity,
      identity == prototype.targetIdentity,
      prototype.protectedProperties.identity.expectedIdentity == identity,
      contentProtectionBaselineMatches(prototype, evidence: evidence),
      accessPolicyBaselineMatches(
        prototype.protectedProperties.accessPolicy.requiredBaseline, evidence: evidence),
      rawStringEqual(globalFacts.policyVersion, evidence.policyVersion),
      rawStringEqual(globalFacts.schemaVersion, evidence.schemaVersion),
      globalFacts.semanticReferenceTimeSeconds == evidence.semanticReferenceTimeSeconds
        && evidence.captureID == globalFacts.captureID
        && evidence.globalFactsHash == globalFacts.globalFactsHash
    else { throw PolicyModelError.actionEvidenceMismatch }
    let source = evaluation.sourceBinding
    guard source.captureID == evidence.captureID,
      source.evidenceID == evidence.evidenceID,
      source.globalFactsHash == globalFacts.globalFactsHash,
      rawStringEqual(source.policyVersion, evidence.policyVersion),
      rawStringEqual(source.schemaVersion, evidence.schemaVersion),
      source.semanticReferenceTimeSeconds == evidence.semanticReferenceTimeSeconds
    else { throw PolicyModelError.actionEvidenceMismatch }
    let expectedEvaluation = try OneVotePolicy.evaluate(
      OneVotePolicyInputs.build(evidence: evidence, globalFacts: globalFacts)
    )
    guard evaluation == expectedEvaluation else {
      throw PolicyModelError.actionEvidenceMismatch
    }
    try validateAdapter(prototype, evidence: evidence, identity: identity)
  }

  private static func validateAdapter(
    _ prototype: ActionPrototype,
    evidence: FrozenEvidenceSnapshot,
    identity: ObjectIdentity
  ) throws {
    switch prototype.adapterContract {
    case .genericRemove(let contract):
      guard evidenceSupportsAdapterScope(evidence, .genericRemove),
        contract.removalPathSlot == .prototypeRawTargetPath,
        contract.targetKind == identity.type,
        contract.pathRaceResidual,
        contract.trustedNamespace == evidence.namespaceBinding.trustedNamespace,
        evidence.removalForceRequirement == .known(contract.forceRequirement),
        prototype.postcondition == .targetAbsent
      else { throw PolicyModelError.invalidActionContract }
    case .gitWorktreeRemove(let contract):
      guard evidenceSupportsAdapterScope(evidence, .gitWorktree), contract.quarantineRequired,
        identity.type == .directory,
        evidence.quarantineCapability == .known(true),
        evidence.namespaceBinding.trustedNamespace == .ownerPrivate,
        evidence.gitWorktree == contract.verifiedEvidence,
        contract.verifiedEvidence.verifiedLocalChanges(targetIdentity: identity) != nil,
        case .known(let currentContent) = evidence.contentProtection,
        contract.verifiedEvidence.verifiedExecutionBaseline(
          currentContent: currentContent,
          targetIdentity: identity)
          == contract.executionBaseline,
        prototype.protectedProperties.content.expectedBaseline
          == contract.executionBaseline.contentProtection,
        prototype.postcondition == .worktreeQuarantinedThenAbsent
      else { throw PolicyModelError.invalidActionContract }
      let expectedRequiresDiscard: Bool
      if case .present = contract.verifiedEvidence.verifiedLocalChanges(
        targetIdentity: identity)
      {
        expectedRequiresDiscard = true
      } else {
        expectedRequiresDiscard = false
      }
      guard contract.requiresDiscardLocalChanges == expectedRequiresDiscard else {
        throw PolicyModelError.invalidActionContract
      }
    case .gitWorktreeDiscardLocalChanges(let contract):
      guard evidenceSupportsAdapterScope(evidence, .gitWorktree),
        identity.type == .directory,
        evidence.namespaceBinding.trustedNamespace == .ownerPrivate,
        evidence.gitWorktree == contract.verifiedEvidence,
        contract.verifiedEvidence.verifiedLocalChanges(targetIdentity: identity)
          == .present(changeSetDigest: contract.changeSetDigest),
        contract.verifiedEvidence.verifiedDiscardSuccessor(targetIdentity: identity)
          == contract.successorBaseline,
        prototype.postcondition
          == .gitWorktreeLocalChangesDiscarded(
            changeSetDigest: contract.changeSetDigest,
            successor: contract.successorBaseline
          )
      else { throw PolicyModelError.invalidActionContract }
    case .codexCleanTemporary(let contract):
      guard hasNonWhitespace(contract.cleanupScopeID),
        evidenceSupportsAdapterScope(
          evidence,
          .codexCleanTemporary(cleanupScopeID: contract.cleanupScopeID)),
        postconditionMatches(
          prototype.postcondition, .cleanupScopeAbsent(contract.cleanupScopeID))
      else { throw PolicyModelError.invalidActionContract }
    case .versionedArtifactRemove(let contract):
      guard hasNonWhitespace(contract.artifactKind), hasNonWhitespace(contract.version),
        evidenceSupportsAdapterScope(
          evidence,
          .versionedArtifactRemove(
            artifactKind: contract.artifactKind, version: contract.version)),
        postconditionMatches(
          prototype.postcondition,
          .artifactVersionAbsent(kind: contract.artifactKind, version: contract.version))
      else { throw PolicyModelError.invalidActionContract }
    case .completeReleaseSetRemove(let contract):
      guard hasNonWhitespace(contract.binding.allocationGroupID),
        evidenceSupportsAdapterScope(
          evidence,
          .completeReleaseSetRemove(allocationGroupID: contract.binding.allocationGroupID)),
        postconditionMatches(
          prototype.postcondition,
          .allocationGroupReleased(contract.binding.allocationGroupID))
      else { throw PolicyModelError.invalidActionContract }
    }
  }

  fileprivate static func actionAwareEvaluation(
    _ base: PolicyEvaluation,
    prototype: ActionPrototype,
    prerequisites: [ActionDefinition]
  ) throws -> PolicyEvaluation {
    switch prototype.adapterContract {
    case .gitWorktreeDiscardLocalChanges(let contract):
      return try base.blockingUnsupportedGitDiscard(contract.changeSetDigest)
    case .gitWorktreeRemove(let contract) where contract.requiresDiscardLocalChanges:
      guard
        case .present(let changeSetDigest) = contract.verifiedEvidence.verifiedLocalChanges(
          targetIdentity: prototype.targetIdentity),
        prerequisites.contains(where: { prerequisite in
          guard
            case .gitWorktreeDiscardLocalChanges(let discard) =
              prerequisite.prototype.adapterContract
          else { return false }
          return discard.changeSetDigest == changeSetDigest
            && discard.verifiedEvidence == contract.verifiedEvidence
            && discard.successorBaseline == contract.executionBaseline
            && prerequisite.prototype.namespaceBinding.bindingBytes
              == prototype.namespaceBinding.bindingBytes
        })
      else { throw PolicyModelError.invalidActionContract }
      return try base.blockingUnsupportedGitDiscard(changeSetDigest)
    default:
      return base
    }
  }

  private static func make(
    prototype: ActionPrototype,
    evidence: FrozenEvidenceSnapshot,
    globalFactsHash: PolicyDigest,
    prerequisiteLineageIDs: [ActionLineageID],
    prerequisiteActionIDs: [ActionID],
    evaluation: PolicyEvaluation,
    displayMetrics: ActionDisplayMetrics
  ) -> Self {
    let displayMetrics = displayMetrics.replacingTier(
      authoritativeTier(evaluation: evaluation, prototype: prototype)
    )
    let lineage = ActionLineageID(
      digest: PolicyBindings.digest(kind: "action-lineage") { encoder in
        if case .completeReleaseSetRemove(let contract) = prototype.adapterContract {
          encoder.string(prototype.policyVersion)
          encoder.string(prototype.schemaVersion)
          encoder.uint8(5)
          encoder.data(contract.binding.stableLineageBytes)
          encodePostcondition(prototype.postcondition, into: &encoder)
        } else {
          encodePrototype(prototype, into: &encoder)
        }
        encoder.array(prerequisiteLineageIDs) { $0.digest.bytes }
      }
    )
    let action = ActionID(
      digest: PolicyBindings.digest(kind: "action") { encoder in
        encoder.data(lineage.digest.bytes)
        encoder.data(evidence.evidenceID.bytes)
        encoder.data(globalFactsHash.bytes)
        encoder.array(prerequisiteActionIDs) { $0.digest.bytes }
        if case .completeReleaseSetRemove(let contract) = prototype.adapterContract {
          encoder.data(contract.binding.bindingBytes)
        }
        encodeEvaluation(evaluation, into: &encoder)
      }
    )
    return Self(
      lineageID: lineage,
      id: action,
      prototype: prototype,
      evidence: evidence,
      globalFactsHash: globalFactsHash,
      prerequisiteLineageIDs: prerequisiteLineageIDs,
      prerequisiteActionIDs: prerequisiteActionIDs,
      evaluation: evaluation,
      displayMetrics: displayMetrics
    )
  }

  private static func authoritativeTier(
    evaluation: PolicyEvaluation,
    prototype: ActionPrototype
  ) -> RecommendationTier {
    switch evaluation.stageability {
    case .blocked:
      return .blocked
    case .requiresConsents:
      return evaluation.recommendation == .likelyRebuildable ? .rebuildable : .review
    case .stageable:
      break
    }
    if case .genericRemove(let contract) = prototype.adapterContract,
      contract.forceRequirement == .requiresForceWithWarning
    {
      return .review
    }
    switch evaluation.recommendation {
    case .safeToClean:
      return .safe
    case .likelyRebuildable:
      return .rebuildable
    case .needsSemanticReview:
      return .review
    case .safeAfterExit, .managedByProvider, .keep, .scanIncomplete,
      .classificationConflict:
      return .blocked
    }
  }

  private static func encodePrototype(
    _ prototype: ActionPrototype,
    into encoder: inout PolicyBindingEncoder
  ) {
    encoder.string(prototype.policyVersion)
    encoder.string(prototype.schemaVersion)
    encodeAdapter(prototype.adapterContract, into: &encoder)
    encodeIdentity(prototype.targetIdentity, into: &encoder)
    encoder.data(prototype.namespaceBinding.bindingBytes)
    encodeProtectedProperties(prototype.protectedProperties, into: &encoder)
    encodePostcondition(prototype.postcondition, into: &encoder)
  }

  private static func encodeAdapter(
    _ adapter: ActionAdapterContract,
    into encoder: inout PolicyBindingEncoder
  ) {
    switch adapter {
    case .genericRemove(let contract):
      encoder.uint8(0)
      encoder.string(contract.removalPathSlot.rawValue)
      encoder.string(contract.targetKind.rawValue)
      encoder.bool(contract.pathRaceResidual)
      encoder.string(contract.trustedNamespace.rawValue)
      encoder.string(contract.forceRequirement.rawValue)
    case .gitWorktreeRemove(let contract):
      encoder.uint8(1)
      encoder.bool(contract.quarantineRequired)
      encoder.data(contract.verifiedEvidence.bindingBytes)
      encoder.data(contract.executionBaseline.bindingBytes)
      encoder.bool(contract.requiresDiscardLocalChanges)
    case .gitWorktreeDiscardLocalChanges(let contract):
      encoder.uint8(2)
      encoder.data(contract.verifiedEvidence.bindingBytes)
      encoder.data(contract.changeSetDigest.bytes)
      encoder.data(contract.successorBaseline.bindingBytes)
    case .codexCleanTemporary(let contract):
      encoder.uint8(3)
      encoder.string(contract.cleanupScopeID)
    case .versionedArtifactRemove(let contract):
      encoder.uint8(4)
      encoder.string(contract.artifactKind)
      encoder.string(contract.version)
    case .completeReleaseSetRemove(let contract):
      encoder.uint8(5)
      encoder.data(contract.binding.bindingBytes)
    }
  }

  private static func encodeProtectedProperties(
    _ contracts: ProtectedPropertyContracts,
    into encoder: inout PolicyBindingEncoder
  ) {
    encodeIdentity(contracts.identity.expectedIdentity, into: &encoder)
    switch contracts.content.expectedBaseline {
    case .requiredDigest(let digest):
      encoder.uint8(0)
      encoder.data(digest.bytes)
    case .explicitlyNotApplicable(let reason):
      encoder.uint8(1)
      encoder.string(reason.rawValue)
    }
    encoder.data(contracts.accessPolicy.requiredBaseline.accessPolicyBytes)
    encoder.data(contracts.accessPolicy.requiredBaseline.aclDigest.bytes)
    encoder.string(contracts.accessPolicy.requiredBaseline.providerState.rawValue)
    encoder.data(contracts.accessPolicy.requiredBaseline.mountIdentityBytes)
  }

  private static func encodePostcondition(
    _ postcondition: ActionPostcondition,
    into encoder: inout PolicyBindingEncoder
  ) {
    switch postcondition {
    case .targetAbsent:
      encoder.uint8(0)
    case .gitWorktreeLocalChangesDiscarded(let changeSetDigest, let successor):
      encoder.uint8(1)
      encoder.data(changeSetDigest.bytes)
      encoder.data(successor.bindingBytes)
    case .worktreeQuarantinedThenAbsent:
      encoder.uint8(2)
    case .cleanupScopeAbsent(let scope):
      encoder.uint8(3)
      encoder.string(scope)
    case .artifactVersionAbsent(let kind, let version):
      encoder.uint8(4)
      encoder.string(kind)
      encoder.string(version)
    case .allocationGroupReleased(let group):
      encoder.uint8(5)
      encoder.string(group)
    }
  }

  private static func encodeEvaluation(
    _ evaluation: PolicyEvaluation,
    into encoder: inout PolicyBindingEncoder
  ) {
    encoder.array(evaluation.votes) { vote in
      var nested = PolicyBindingEncoder()
      nested.uint8(vote.dimension.rawValue)
      encodeGateResult(vote.result, into: &nested)
      return nested.data
    }
    encoder.string(evaluation.recommendation.rawValue)
    switch evaluation.stageability {
    case .stageable:
      encoder.uint8(0)
    case .requiresConsents(let predicates):
      encoder.uint8(1)
      encoder.array(predicates) { encodePredicate($0) }
    case .blocked:
      encoder.uint8(2)
    }
    encoder.array(evaluation.unmetRevalidationConditions) { Data($0.rawValue.utf8) }
    let source = evaluation.sourceBinding
    encoder.bool(true)
    encoder.data(source.captureID.bytes)
    encoder.data(source.evidenceID.bytes)
    encoder.data(source.globalFactsHash.bytes)
    encoder.data(source.classificationResolutionHash.bytes)
    encoder.string(source.policyVersion)
    encoder.string(source.schemaVersion)
    encoder.int64(source.semanticReferenceTimeSeconds)
  }

  static func encodeGateResult(
    _ result: GateResult,
    into encoder: inout PolicyBindingEncoder
  ) {
    switch result {
    case .satisfied(let reasons):
      encoder.uint8(0)
      encoder.array(reasons) { encodeReason($0) }
    case .notApplicable(let reasons):
      encoder.uint8(1)
      encoder.array(reasons) { encodeReason($0) }
    case .requiresWaiver(let predicates, let reasons):
      encoder.uint8(2)
      encoder.array(predicates) { encodePredicate($0) }
      encoder.array(reasons) { encodeReason($0) }
    case .unmetCondition(let conditions, let reasons):
      encoder.uint8(3)
      encoder.array(conditions) { Data($0.rawValue.utf8) }
      encoder.array(reasons) { encodeReason($0) }
    case .rejected(let reasons):
      encoder.uint8(4)
      encoder.array(reasons) { encodeReason($0) }
    }
  }

  static func encodePredicate(_ predicate: WaiverPredicate) -> Data {
    var encoder = PolicyBindingEncoder()
    encoder.string(predicate.kind.rawValue)
    encoder.string(predicate.predicate)
    encoder.string(predicate.valueBucket)
    encoder.data(predicate.semanticEvidenceHash.bytes)
    return encoder.data
  }

  static func encodeReason(_ reason: GateReason) -> Data {
    var encoder = PolicyBindingEncoder()
    encoder.string(reason.code)
    encoder.data(reason.semanticEvidenceHash.bytes)
    return encoder.data
  }
}

public enum ActionOrdering {
  public static func canonical(_ actions: [ActionDefinition]) -> [ActionDefinition] {
    actions.sorted { $0.id < $1.id }
  }

  public static func display(_ actions: [ActionDefinition]) -> [ActionDefinition] {
    actions.sorted { lhs, rhs in
      let left = lhs.displayMetrics
      let right = rhs.displayMetrics
      if left.tier != right.tier { return left.tier < right.tier }
      if left.immediateReclaimBytes != right.immediateReclaimBytes {
        return descendingKnown(left.immediateReclaimBytes, right.immediateReclaimBytes)
      }
      if left.inactiveDurationSeconds != right.inactiveDurationSeconds {
        return descendingKnown(left.inactiveDurationSeconds, right.inactiveDurationSeconds)
      }
      if left.rebuildCost != right.rebuildCost { return left.rebuildCost < right.rebuildCost }
      if left.cleanupCost != right.cleanupCost { return left.cleanupCost < right.cleanupCost }
      if left.canonicalRawPath != right.canonicalRawPath {
        return left.canonicalRawPath.lexicographicallyPrecedes(right.canonicalRawPath)
      }
      return lhs.id < rhs.id
    }
  }

  private static func descendingKnown<T: Comparable>(
    _ lhs: KnownOrUnknown<T>,
    _ rhs: KnownOrUnknown<T>
  ) -> Bool {
    switch (lhs, rhs) {
    case (.known(let left), .known(let right)): left > right
    case (.known, .unknown): true
    case (.unknown, .known): false
    case (.unknown(let left), .unknown(let right)): left.rawValue < right.rawValue
    }
  }
}

public struct ReleaseSetOwnerBinding: Equatable, Sendable {
  public let candidateID: String
  public let actionID: ActionID
  public let target: RawTargetPath
  public let targetIdentity: ObjectIdentity
  public let namespaceBinding: ProtectedNamespaceBinding
  public let evidence: FrozenEvidenceSnapshot

  fileprivate init(owner: EvaluatedReleaseOwner, actionID: ActionID) {
    candidateID = owner.candidateID
    self.actionID = actionID
    target = owner.target
    targetIdentity = owner.targetIdentity
    namespaceBinding = owner.namespaceBinding
    evidence = owner.evidence
  }
}

public struct PlanReleaseSet: Equatable, Sendable {
  public let allocationGroupID: String
  public let graphDigest: PolicyDigest
  public let graphProvenance: StorageGraphProvenance
  public let topologyExpectation: ReleaseTopologyExpectation
  public let owners: [ReleaseSetOwnerBinding]
  public let conditionalReclaimBytes: UInt64

  public var ownerCandidateIDs: [String] { owners.map(\.candidateID) }
  public var ownerActionIDs: [ActionID] { owners.map(\.actionID) }
  public var actionBinding: CompleteReleaseSetActionBinding {
    CompleteReleaseSetActionBinding(releaseSet: self)
  }

  fileprivate init(
    allocationGroupID: String,
    graphDigest: PolicyDigest,
    graphProvenance: StorageGraphProvenance,
    topologyExpectation: ReleaseTopologyExpectation,
    owners: [ReleaseSetOwnerBinding],
    conditionalReclaimBytes: UInt64
  ) {
    self.allocationGroupID = allocationGroupID
    self.graphDigest = graphDigest
    self.graphProvenance = graphProvenance
    self.topologyExpectation = topologyExpectation
    self.owners = owners.sorted { rawStringPrecedes($0.candidateID, $1.candidateID) }
    self.conditionalReclaimBytes = conditionalReclaimBytes
  }

  public static func buildAll(
    from evaluation: ReleaseGraphEvaluation,
    candidateActions: [CandidateActionBinding]
  ) throws -> PlanReleaseGraphBundle {
    guard evaluation.blockers.isEmpty,
      case .known(let immediateBytes) = evaluation.immediatePrivateReclaimBytes,
      case .known(let conditionalBytes) = evaluation.conditionalGroupReclaimBytes,
      !evaluation.releaseSets.isEmpty,
      Set(evaluation.releaseSets.map { Data($0.allocationGroupID.utf8) }).count
        == evaluation.releaseSets.count,
      evaluation.releaseSets.allSatisfy({
        $0.isComplete && $0.graphDigest == evaluation.graphDigest
      })
    else { throw PolicyModelError.incompleteReleaseGraph }
    guard !immediateBytes.addingReportingOverflow(conditionalBytes).overflow else {
      throw PolicyModelError.incompleteReleaseGraph
    }

    let candidateActionKeys = candidateActions.map { Data($0.candidateID.utf8) }
    let evaluationCandidateKeys = evaluation.candidateIDs.map { Data($0.utf8) }
    guard Set(candidateActionKeys).count == candidateActions.count,
      Set(evaluationCandidateKeys).count == evaluation.candidateIDs.count
    else { throw PolicyModelError.duplicateIdentifier }
    guard Set(candidateActionKeys) == Set(evaluationCandidateKeys),
      evaluation.evaluatedActionIDByCandidate.count == evaluation.candidateIDs.count,
      candidateActions.allSatisfy({ binding in
        evaluation.evaluatedActionIDByCandidate[Data(binding.candidateID.utf8)]
          == binding.action.id
          && rawStringEqual(binding.candidateID, binding.action.evidence.candidateID)
          && binding.action.globalFactsHash == evaluation.provenance.globalFactsHash
          && rawStringEqual(
            binding.action.prototype.policyVersion, evaluation.provenance.policyVersion)
          && rawStringEqual(
            binding.action.prototype.schemaVersion, evaluation.provenance.schemaVersion)
          && binding.action.evidence.semanticReferenceTimeSeconds
            == evaluation.provenance.semanticReferenceTimeSeconds
      })
    else {
      throw PolicyModelError.incompleteReleaseGraph
    }
    let actionByCandidateID = Dictionary(
      uniqueKeysWithValues: zip(candidateActionKeys, candidateActions.map(\.action))
    )
    let releaseSets = try evaluation.releaseSets.map { evaluated in
      guard let bytes = evaluated.conditionalReclaimBytes, !evaluated.owners.isEmpty else {
        throw PolicyModelError.incompleteReleaseSet(evaluated.allocationGroupID)
      }
      let owners = try evaluated.owners.map { owner -> ReleaseSetOwnerBinding in
        guard let action = actionByCandidateID[Data(owner.candidateID.utf8)],
          owner.evaluatedActionID == action.id,
          rawStringEqual(action.evidence.candidateID, owner.candidateID),
          action.evidenceID == owner.evidence.evidenceID,
          action.globalFactsHash == evaluation.provenance.globalFactsHash,
          action.prototype.namespaceBinding.bindingBytes == owner.namespaceBinding.bindingBytes,
          action.prototype.targetIdentity == owner.targetIdentity,
          owner.target == owner.namespaceBinding.targetPath,
          actionReleasesOwner(action, allocationGroupID: evaluated.allocationGroupID)
        else { throw PolicyModelError.releaseOwnerBindingMismatch(owner.candidateID) }
        return ReleaseSetOwnerBinding(owner: owner, actionID: action.id)
      }
      guard Set(owners.map(\.actionID)).count == owners.count else {
        throw PolicyModelError.incompleteReleaseSet(evaluated.allocationGroupID)
      }
      return Self(
        allocationGroupID: evaluated.allocationGroupID,
        graphDigest: evaluation.graphDigest,
        graphProvenance: evaluation.provenance,
        topologyExpectation: evaluated.topologyExpectation,
        owners: owners,
        conditionalReclaimBytes: bytes
      )
    }.sorted { rawStringPrecedes($0.allocationGroupID, $1.allocationGroupID) }
    let manifest = ReleaseGraphManifest.make(
      graphDigest: evaluation.graphDigest,
      graphProvenance: evaluation.provenance,
      releaseSets: releaseSets,
      candidateActions: candidateActions
    )
    return PlanReleaseGraphBundle(manifest: manifest, releaseSets: releaseSets)
  }

  private static func actionReleasesOwner(
    _ action: ActionDefinition,
    allocationGroupID: String
  ) -> Bool {
    switch action.prototype.postcondition {
    case .targetAbsent:
      evidenceSupportsAdapterScope(action.evidence, .genericRemove)
    case .gitWorktreeLocalChangesDiscarded:
      false
    case .worktreeQuarantinedThenAbsent:
      evidenceSupportsAdapterScope(action.evidence, .gitWorktree)
    case .cleanupScopeAbsent(let cleanupScopeID):
      evidenceSupportsAdapterScope(
        action.evidence,
        .codexCleanTemporary(cleanupScopeID: cleanupScopeID))
    case .artifactVersionAbsent(let artifactKind, let version):
      evidenceSupportsAdapterScope(
        action.evidence,
        .versionedArtifactRemove(artifactKind: artifactKind, version: version))
    case .allocationGroupReleased(let boundGroupID):
      rawStringEqual(boundGroupID, allocationGroupID)
    }
  }
}

public struct ReleaseGraphCandidateActionManifestEntry: Equatable, Sendable {
  public let candidateID: String
  public let actionID: ActionID

  fileprivate var bindingBytes: Data {
    var encoder = PolicyBindingEncoder()
    encoder.string(candidateID)
    encoder.data(actionID.digest.bytes)
    return encoder.data
  }
}

public struct ReleaseGraphComponentManifest: Equatable, Sendable {
  public let allocationGroupIDs: [String]
  public let candidateIDs: [String]
  public let topologyDigest: PolicyDigest

  fileprivate var bindingBytes: Data {
    var encoder = PolicyBindingEncoder()
    encoder.array(allocationGroupIDs) { Data($0.utf8) }
    encoder.array(candidateIDs) { Data($0.utf8) }
    encoder.data(topologyDigest.bytes)
    return encoder.data
  }
}

public struct ReleaseGraphManifest: Equatable, Sendable {
  public let graphDigest: PolicyDigest
  public let graphProvenance: StorageGraphProvenance
  public let allocationGroupIDs: [String]
  public let allocationGroupCount: UInt64
  public let candidateActions: [ReleaseGraphCandidateActionManifestEntry]
  public let connectedComponents: [ReleaseGraphComponentManifest]
  public let manifestDigest: PolicyDigest

  fileprivate static func make(
    graphDigest: PolicyDigest,
    graphProvenance: StorageGraphProvenance,
    releaseSets: [PlanReleaseSet],
    candidateActions: [CandidateActionBinding]
  ) -> Self {
    let actionEntries = candidateActions.map {
      ReleaseGraphCandidateActionManifestEntry(
        candidateID: $0.candidateID,
        actionID: $0.action.id
      )
    }.sorted { rawStringPrecedes($0.candidateID, $1.candidateID) }
    return make(
      graphDigest: graphDigest,
      graphProvenance: graphProvenance,
      releaseSets: releaseSets,
      candidateActionEntries: actionEntries
    )
  }

  fileprivate static func make(
    graphDigest: PolicyDigest,
    graphProvenance: StorageGraphProvenance,
    releaseSets: [PlanReleaseSet],
    candidateActionEntries: [ReleaseGraphCandidateActionManifestEntry]
  ) -> Self {
    let groupIDs = releaseSets.map(\.allocationGroupID).sorted(by: rawStringPrecedes)
    let actionEntries = candidateActionEntries.sorted {
      rawStringPrecedes($0.candidateID, $1.candidateID)
    }
    let components = connectedReleaseComponents(releaseSets)
    let binding = manifestBindingBytes(
      graphDigest: graphDigest,
      graphProvenance: graphProvenance,
      allocationGroupIDs: groupIDs,
      candidateActions: actionEntries,
      connectedComponents: components
    )
    return Self(
      graphDigest: graphDigest,
      graphProvenance: graphProvenance,
      allocationGroupIDs: groupIDs,
      allocationGroupCount: UInt64(groupIDs.count),
      candidateActions: actionEntries,
      connectedComponents: components,
      manifestDigest: PolicyBindings.digest(kind: "release-graph-manifest") {
        $0.data(binding)
      }
    )
  }

  fileprivate var bindingBytes: Data {
    var encoder = PolicyBindingEncoder()
    encoder.data(manifestCoreBindingBytes)
    encoder.data(manifestDigest.bytes)
    return encoder.data
  }

  fileprivate var manifestCoreBindingBytes: Data {
    manifestBindingBytes(
      graphDigest: graphDigest,
      graphProvenance: graphProvenance,
      allocationGroupIDs: allocationGroupIDs,
      candidateActions: candidateActions,
      connectedComponents: connectedComponents
    )
  }
}

public struct PlanReleaseGraphBundle: Equatable, Sendable {
  public let manifest: ReleaseGraphManifest
  public let releaseSets: [PlanReleaseSet]

  fileprivate init(manifest: ReleaseGraphManifest, releaseSets: [PlanReleaseSet]) {
    self.manifest = manifest
    self.releaseSets = releaseSets.sorted {
      rawStringPrecedes($0.allocationGroupID, $1.allocationGroupID)
    }
  }

  init(uncheckedManifest: ReleaseGraphManifest, releaseSets: [PlanReleaseSet]) {
    manifest = uncheckedManifest
    self.releaseSets = releaseSets
  }
}

public struct ImmutablePlan: Equatable, Sendable {
  public let policyVersion: String
  public let schemaVersion: String
  public let globalFacts: FrozenGlobalFacts
  public let evidenceSnapshots: [FrozenEvidenceSnapshot]
  public let evidenceHash: PolicyDigest
  public let actions: [ActionDefinition]
  public let releaseGraphManifest: ReleaseGraphManifest?
  public let releaseSets: [PlanReleaseSet]
  public let releaseGraphDigest: PolicyDigest?
  public let planHash: PolicyDigest

  public init(
    policyVersion: String,
    schemaVersion: String,
    globalFacts: FrozenGlobalFacts,
    evidenceSnapshots: [FrozenEvidenceSnapshot],
    actions: [ActionDefinition],
    releaseGraphBundle: PlanReleaseGraphBundle?
  ) throws {
    guard rawStringEqual(globalFacts.policyVersion, policyVersion),
      rawStringEqual(globalFacts.schemaVersion, schemaVersion)
    else { throw PolicyModelError.mixedPolicyOrSchemaVersion }
    guard Set(globalFacts.coverage.map(\.rawRoot)).count == globalFacts.coverage.count else {
      throw PolicyModelError.duplicateIdentifier
    }
    let coveredRoots = Set(globalFacts.coverage.map(\.rawRoot))
    let evidence = evidenceSnapshots.sorted { $0.evidenceID < $1.evidenceID }
    guard Set(evidence.map(\.evidenceID)).count == evidence.count,
      Set(evidence.map { Data($0.candidateID.utf8) }).count == evidence.count
    else { throw PolicyModelError.duplicateIdentifier }
    guard
      evidence.allSatisfy({
        rawStringEqual($0.policyVersion, policyVersion)
          && rawStringEqual($0.schemaVersion, schemaVersion)
          && $0.semanticReferenceTimeSeconds == globalFacts.semanticReferenceTimeSeconds
          && $0.captureID == globalFacts.captureID
          && $0.globalFactsHash == globalFacts.globalFactsHash
          && coveredRoots.contains($0.namespaceBinding.rawRoot)
      })
    else { throw PolicyModelError.mixedPolicyOrSchemaVersion }
    let evidenceByID = Dictionary(uniqueKeysWithValues: evidence.map { ($0.evidenceID, $0) })

    let canonicalActions = ActionOrdering.canonical(actions)
    guard Set(canonicalActions.map(\.id)).count == canonicalActions.count else {
      throw PolicyModelError.duplicateIdentifier
    }
    let actionByID = Dictionary(uniqueKeysWithValues: canonicalActions.map { ($0.id, $0) })
    for action in canonicalActions {
      guard rawStringEqual(action.prototype.policyVersion, policyVersion),
        rawStringEqual(action.prototype.schemaVersion, schemaVersion),
        action.globalFactsHash == globalFacts.globalFactsHash,
        action.evidence.semanticReferenceTimeSeconds
          == globalFacts.semanticReferenceTimeSeconds
      else { throw PolicyModelError.mixedPolicyOrSchemaVersion }
      guard evidenceByID[action.evidenceID] == action.evidence else {
        throw PolicyModelError.actionEvidenceMismatch
      }
      guard Set(action.prerequisiteActionIDs).count == action.prerequisiteActionIDs.count,
        Set(action.prerequisiteLineageIDs).count == action.prerequisiteLineageIDs.count
      else { throw PolicyModelError.invalidActionBinding(action.id) }
      for prerequisite in action.prerequisiteActionIDs where actionByID[prerequisite] == nil {
        throw PolicyModelError.danglingPrerequisite(prerequisite)
      }
    }
    guard Self.isAcyclic(canonicalActions) else { throw PolicyModelError.actionCycle }
    for action in canonicalActions {
      let expectedLineages = action.prerequisiteActionIDs.compactMap {
        actionByID[$0]?.lineageID
      }.sorted()
      let prerequisites = action.prerequisiteActionIDs.compactMap { actionByID[$0] }
      let baseEvaluation = try OneVotePolicy.evaluate(
        OneVotePolicyInputs.build(evidence: action.evidence, globalFacts: globalFacts)
      )
      let expectedEvaluation = try ActionDefinition.actionAwareEvaluation(
        baseEvaluation,
        prototype: action.prototype,
        prerequisites: prerequisites
      )
      guard action.prerequisiteLineageIDs == expectedLineages,
        action == action.recomputed,
        action.evaluation == expectedEvaluation
      else { throw PolicyModelError.invalidActionBinding(action.id) }
    }
    for action in canonicalActions {
      guard case .gitWorktreeRemove(let contract) = action.prototype.adapterContract,
        contract.requiresDiscardLocalChanges
      else { continue }
      let matchingDiscardActions = action.prerequisiteActionIDs.compactMap {
        actionByID[$0]
      }.filter { prerequisite in
        guard
          case .gitWorktreeDiscardLocalChanges(let discard) =
            prerequisite.prototype.adapterContract
        else { return false }
        return prerequisite.prototype.namespaceBinding.bindingBytes
          == action.prototype.namespaceBinding.bindingBytes
          && discard.verifiedEvidence == contract.verifiedEvidence
          && contract.verifiedEvidence.verifiedLocalChanges(
            targetIdentity: action.prototype.targetIdentity)
            == .present(changeSetDigest: discard.changeSetDigest)
          && discard.successorBaseline == contract.executionBaseline
      }
      guard matchingDiscardActions.count == 1 else {
        throw PolicyModelError.invalidActionContract
      }
    }
    let gitEvidenceSnapshots = evidence.filter(\.hasGitWorktreeScope)
    for action in canonicalActions {
      switch action.prototype.adapterContract {
      case .gitWorktreeRemove, .gitWorktreeDiscardLocalChanges:
        continue
      default:
        break
      }
      let overlappingGitEvidence = gitEvidenceSnapshots.filter {
        namespacesMayOverlap(
          action.prototype.namespaceBinding, $0.namespaceBinding)
      }
      guard !overlappingGitEvidence.isEmpty else { continue }
      guard case .completeReleaseSetRemove(let release) = action.prototype.adapterContract,
        overlappingGitEvidence.allSatisfy({ gitEvidence in
          release.binding.ownerActionIDs.contains(where: { ownerActionID in
            guard let ownerAction = actionByID[ownerActionID],
              case .gitWorktreeRemove = ownerAction.prototype.adapterContract
            else { return false }
            return ownerAction.evidenceID == gitEvidence.evidenceID
          })
        })
      else { throw PolicyModelError.invalidActionContract }
    }

    let canonicalReleaseSets = (releaseGraphBundle?.releaseSets ?? []).sorted {
      rawStringPrecedes($0.allocationGroupID, $1.allocationGroupID)
    }
    guard (releaseGraphBundle == nil) == canonicalReleaseSets.isEmpty else {
      throw PolicyModelError.incompleteReleaseGraph
    }
    guard
      Set(canonicalReleaseSets.map { Data($0.allocationGroupID.utf8) }).count
        == canonicalReleaseSets.count
    else { throw PolicyModelError.duplicateIdentifier }
    let graphDigests = Set(canonicalReleaseSets.map(\.graphDigest))
    guard graphDigests.count <= 1 else { throw PolicyModelError.incompleteReleaseGraph }
    let graphProvenances = canonicalReleaseSets.map(\.graphProvenance)
    guard Set(graphProvenances.map(\.globalFactsHash)).count <= 1,
      Set(graphProvenances.map(\.evidenceHash)).count <= 1,
      graphProvenances.allSatisfy({
        $0.globalFactsHash == globalFacts.globalFactsHash
          && rawStringEqual($0.policyVersion, policyVersion)
          && rawStringEqual($0.schemaVersion, schemaVersion)
          && $0.semanticReferenceTimeSeconds == globalFacts.semanticReferenceTimeSeconds
      })
    else { throw PolicyModelError.incompleteReleaseGraph }
    for releaseSet in canonicalReleaseSets {
      guard !releaseSet.ownerActionIDs.isEmpty,
        rawStringEqual(
          releaseSet.topologyExpectation.allocationGroupID, releaseSet.allocationGroupID),
        releaseSet.ownerActionIDs.count == releaseSet.ownerCandidateIDs.count,
        Set(releaseSet.ownerActionIDs).count == releaseSet.ownerActionIDs.count,
        Set(releaseSet.ownerCandidateIDs.map { Data($0.utf8) }).count
          == releaseSet.ownerCandidateIDs.count
      else { throw PolicyModelError.releaseSetEmpty }
      for owner in releaseSet.owners {
        guard let action = actionByID[owner.actionID],
          rawStringEqual(action.evidence.candidateID, owner.candidateID),
          action.evidenceID == owner.evidence.evidenceID,
          action.globalFactsHash == releaseSet.graphProvenance.globalFactsHash,
          action.prototype.namespaceBinding.bindingBytes == owner.namespaceBinding.bindingBytes,
          action.prototype.targetIdentity == owner.targetIdentity,
          owner.target == owner.namespaceBinding.targetPath
        else { throw PolicyModelError.releaseSetDanglingAction(owner.actionID) }
      }
    }

    let evidenceHash = PolicyBindings.digest(kind: "evidence-set") { encoder in
      encoder.array(evidence) { $0.bindingBytes }
    }
    guard graphProvenances.allSatisfy({ $0.evidenceHash == evidenceHash }) else {
      throw PolicyModelError.incompleteReleaseGraph
    }
    if let manifest = releaseGraphBundle?.manifest {
      let candidateKeys = manifest.candidateActions.map { Data($0.candidateID.utf8) }
      guard !manifest.candidateActions.isEmpty,
        Set(candidateKeys).count == manifest.candidateActions.count,
        Set(manifest.candidateActions.map(\.actionID)).count
          == manifest.candidateActions.count,
        Set(candidateKeys) == Set(evidence.map { Data($0.candidateID.utf8) }),
        graphDigests == Set([manifest.graphDigest]),
        graphProvenances.allSatisfy({ $0 == manifest.graphProvenance })
      else { throw PolicyModelError.incompleteReleaseGraph }
      for entry in manifest.candidateActions {
        guard let action = actionByID[entry.actionID],
          rawStringEqual(action.evidence.candidateID, entry.candidateID)
        else { throw PolicyModelError.incompleteReleaseGraph }
      }
      let manifestActionByCandidate = Dictionary(
        uniqueKeysWithValues: manifest.candidateActions.map {
          (Data($0.candidateID.utf8), $0.actionID)
        }
      )
      guard
        canonicalReleaseSets.allSatisfy({ releaseSet in
          releaseSet.owners.allSatisfy { owner in
            manifestActionByCandidate[Data(owner.candidateID.utf8)] == owner.actionID
          }
        })
      else { throw PolicyModelError.incompleteReleaseGraph }
      let expectedManifest = ReleaseGraphManifest.make(
        graphDigest: manifest.graphDigest,
        graphProvenance: manifest.graphProvenance,
        releaseSets: canonicalReleaseSets,
        candidateActionEntries: manifest.candidateActions
      )
      guard manifest == expectedManifest else {
        throw PolicyModelError.incompleteReleaseGraph
      }
    } else if !canonicalReleaseSets.isEmpty {
      throw PolicyModelError.incompleteReleaseGraph
    }
    let releaseActionBindings = canonicalActions.compactMap { action -> Data? in
      guard case .completeReleaseSetRemove(let contract) = action.prototype.adapterContract
      else { return nil }
      return contract.binding.bindingBytes
    }
    guard Set(releaseActionBindings).count == releaseActionBindings.count else {
      throw PolicyModelError.duplicateIdentifier
    }
    let verifiedReleaseBindings = Set(canonicalReleaseSets.map { $0.actionBinding.bindingBytes })
    guard releaseActionBindings.allSatisfy(verifiedReleaseBindings.contains) else {
      throw PolicyModelError.incompleteReleaseGraph
    }
    for action in canonicalActions {
      guard case .completeReleaseSetRemove(let contract) = action.prototype.adapterContract
      else { continue }
      guard
        let releaseSet = canonicalReleaseSets.first(where: {
          $0.actionBinding.bindingBytes == contract.binding.bindingBytes
        }),
        let anchorOwner = releaseSet.owners.first(where: {
          rawStringEqual($0.candidateID, action.evidence.candidateID)
        }),
        anchorOwner.evidence.evidenceID == action.evidenceID,
        Set(contract.binding.ownerActionIDs).isSubset(
          of: Set(action.prerequisiteActionIDs)
        )
      else {
        throw PolicyModelError.invalidActionContract
      }
      guard
        actionContractionsPreserveAcyclicity(
          [Set(releaseSet.ownerActionIDs + [action.id])],
          actions: canonicalActions
        )
      else {
        throw PolicyModelError.invalidActionContract
      }
    }
    let duplicateFacts = evidence.flatMap { snapshot in
      snapshot.semanticReviewFacts.compactMap { fact -> (String, String, String)? in
        guard case .duplicateSurvivorChoice(let groupID, let survivorCandidateID, _) = fact
        else { return nil }
        return (groupID, survivorCandidateID, snapshot.candidateID)
      }
    }
    let duplicateGroups = Dictionary(grouping: duplicateFacts, by: { Data($0.0.utf8) })
    for groupID in duplicateGroups.keys.sorted(by: { $0.lexicographicallyPrecedes($1) }) {
      guard let facts = duplicateGroups[groupID] else {
        throw PolicyModelError.invalidActionContract
      }
      let survivors = Set(facts.map { Data($0.1.utf8) })
      let members = Set(facts.map { Data($0.2.utf8) })
      guard survivors.count == 1, let survivor = survivors.first,
        members.contains(survivor)
      else { throw PolicyModelError.invalidActionContract }
    }
    self.policyVersion = policyVersion
    self.schemaVersion = schemaVersion
    self.globalFacts = globalFacts
    self.evidenceSnapshots = evidence
    self.evidenceHash = evidenceHash
    self.actions = canonicalActions
    self.releaseGraphManifest = releaseGraphBundle?.manifest
    self.releaseSets = canonicalReleaseSets
    self.releaseGraphDigest = graphDigests.first
    self.planHash = PolicyBindings.digest(kind: "plan") { encoder in
      encoder.string(policyVersion)
      encoder.string(schemaVersion)
      encoder.data(globalFacts.bindingBytes)
      encoder.array(evidence) { $0.bindingBytes }
      encoder.array(canonicalActions) { action in
        var nested = PolicyBindingEncoder()
        nested.data(action.id.digest.bytes)
        Self.encodeDisplayMetrics(action.displayMetrics, into: &nested)
        return nested.data
      }
      if let manifest = releaseGraphBundle?.manifest {
        encoder.bool(true)
        encoder.data(manifest.bindingBytes)
      } else {
        encoder.bool(false)
      }
      encoder.array(canonicalReleaseSets) { releaseSet in
        var nested = PolicyBindingEncoder()
        nested.string(releaseSet.allocationGroupID)
        nested.data(releaseSet.graphDigest.bytes)
        nested.data(releaseSet.graphProvenance.globalFactsHash.bytes)
        nested.data(releaseSet.graphProvenance.evidenceHash.bytes)
        nested.string(releaseSet.graphProvenance.policyVersion)
        nested.string(releaseSet.graphProvenance.schemaVersion)
        nested.int64(releaseSet.graphProvenance.semanticReferenceTimeSeconds)
        nested.data(Self.encodeTopologyExpectation(releaseSet.topologyExpectation))
        nested.array(releaseSet.owners) { owner in
          var ownerEncoder = PolicyBindingEncoder()
          ownerEncoder.string(owner.candidateID)
          ownerEncoder.data(owner.actionID.digest.bytes)
          ownerEncoder.data(owner.target.bindingBytes)
          encodeIdentity(owner.targetIdentity, into: &ownerEncoder)
          ownerEncoder.data(owner.namespaceBinding.bindingBytes)
          ownerEncoder.data(owner.evidence.bindingBytes)
          return ownerEncoder.data
        }
        nested.uint64(releaseSet.conditionalReclaimBytes)
        return nested.data
      }
    }
  }

  private static func isAcyclic(_ actions: [ActionDefinition]) -> Bool {
    let dependents = Dictionary(
      grouping: actions.flatMap { action in
        action.prerequisiteActionIDs.map { ($0, action.id) }
      }, by: \.0
    ).mapValues { $0.map(\.1) }
    var indegree = Dictionary(
      uniqueKeysWithValues: actions.map { ($0.id, $0.prerequisiteActionIDs.count) })
    var ready = PolicyMinHeap(indegree.filter { $0.value == 0 }.map(\.key))
    var visited = 0
    while let next = ready.popMin() {
      visited += 1
      for dependent in dependents[next] ?? [] {
        indegree[dependent, default: 0] -= 1
        if indegree[dependent] == 0 {
          ready.insert(dependent)
        }
      }
    }
    return visited == actions.count
  }

  private static func encodeDisplayMetrics(
    _ metrics: ActionDisplayMetrics,
    into encoder: inout PolicyBindingEncoder
  ) {
    encoder.uint8(metrics.tier.rawValue)
    encoder.knownOrUnknown(metrics.immediateReclaimBytes) { $0.uint64($1) }
    encoder.knownOrUnknown(metrics.inactiveDurationSeconds) { $0.uint64($1) }
    encoder.knownOrUnknown(metrics.rebuildCost) { $0.uint64($1) }
    encoder.knownOrUnknown(metrics.cleanupCost) { $0.uint64($1) }
    encoder.data(metrics.canonicalRawPath)
  }

  private static func encodeTopologyExpectation(
    _ topology: ReleaseTopologyExpectation
  ) -> Data {
    var encoder = PolicyBindingEncoder()
    encoder.string(topology.allocationGroupID)
    encoder.array(topology.fileObjects) { file in
      var nested = PolicyBindingEncoder()
      nested.string(file.fileObjectID)
      nested.array(file.owners) { owner in
        var ownerEncoder = PolicyBindingEncoder()
        ownerEncoder.string(owner.candidateID)
        ownerEncoder.data(owner.path.bindingBytes)
        return ownerEncoder.data
      }
      nested.array(file.ownerNamespaces) { owner in
        var ownerEncoder = PolicyBindingEncoder()
        ownerEncoder.string(owner.link.candidateID)
        ownerEncoder.data(owner.link.path.bindingBytes)
        ownerEncoder.data(owner.namespaceBinding.bindingBytes)
        return ownerEncoder.data
      }
      nested.observation(file.linkCount) { $0.uint64(UInt64($1)) }
      return nested.data
    }
    encoder.observation(topology.cloneIdentity) { encoder, identity in
      encoder.uint64(identity.device)
      encoder.uint64(identity.cloneID)
    }
    encoder.observation(topology.cloneRefCount) { $0.uint64(UInt64($1)) }
    encoder.observation(topology.sharedBytes) { $0.uint64($1) }
    encoder.observation(topology.snapshotBlocker) { $0.bool($1) }
    return encoder.data
  }
}

public struct WaiverConsentCore: Equatable, Sendable {
  public let actionLineageID: ActionLineageID
  public let policyVersion: String
  public let predicate: WaiverPredicate
  public let reason: String
  public let consentEventID: String
  public let consentHash: PolicyDigest

  public init(
    actionLineageID: ActionLineageID,
    policyVersion: String,
    predicate: WaiverPredicate,
    reason: String,
    consentEventID: String,
    consentHash: PolicyDigest
  ) {
    self.actionLineageID = actionLineageID
    self.policyVersion = policyVersion
    self.predicate = predicate
    self.reason = reason
    self.consentEventID = consentEventID
    self.consentHash = consentHash
  }

  public static func create(
    action: ActionDefinition,
    predicate: WaiverPredicate,
    reason: String,
    consentEventID: String
  ) -> Self {
    let hash = bindingHash(
      lineageID: action.lineageID,
      policyVersion: action.prototype.policyVersion,
      predicate: predicate,
      reason: reason,
      consentEventID: consentEventID
    )
    return Self(
      actionLineageID: action.lineageID,
      policyVersion: action.prototype.policyVersion,
      predicate: predicate,
      reason: reason,
      consentEventID: consentEventID,
      consentHash: hash
    )
  }

  fileprivate var recomputedHash: PolicyDigest {
    Self.bindingHash(
      lineageID: actionLineageID,
      policyVersion: policyVersion,
      predicate: predicate,
      reason: reason,
      consentEventID: consentEventID
    )
  }

  private static func bindingHash(
    lineageID: ActionLineageID,
    policyVersion: String,
    predicate: WaiverPredicate,
    reason: String,
    consentEventID: String
  ) -> PolicyDigest {
    PolicyBindings.digest(kind: "waiver-consent-core") { encoder in
      encoder.data(lineageID.digest.bytes)
      encoder.string(policyVersion)
      encoder.string(predicate.kind.rawValue)
      encoder.string(predicate.predicate)
      encoder.string(predicate.valueBucket)
      encoder.data(predicate.semanticEvidenceHash.bytes)
      encoder.string(reason)
      encoder.string(consentEventID)
    }
  }
}

public struct WaiverEpochRequirement: Equatable, Sendable {
  public let consentHash: PolicyDigest
  public let actionID: ActionID
  public let planHash: PolicyDigest
  public let evidenceHash: PolicyDigest
  public let semanticReferenceTimeSeconds: Int64

  fileprivate init(
    consentHash: PolicyDigest,
    actionID: ActionID,
    planHash: PolicyDigest,
    evidenceHash: PolicyDigest,
    semanticReferenceTimeSeconds: Int64
  ) {
    self.consentHash = consentHash
    self.actionID = actionID
    self.planHash = planHash
    self.evidenceHash = evidenceHash
    self.semanticReferenceTimeSeconds = semanticReferenceTimeSeconds
  }
}

public struct ExecutionEpochContext: Equatable, Sendable {
  public let epochID: String
  public let semanticReferenceTimeSeconds: Int64
  public let issuedAtSeconds: Int64
  public let deadlineSeconds: Int64

  public init(
    epochID: String,
    semanticReferenceTimeSeconds: Int64,
    issuedAtSeconds: Int64,
    deadlineSeconds: Int64
  ) throws {
    guard hasNonWhitespace(epochID), deadlineSeconds > issuedAtSeconds else {
      throw PolicyModelError.invalidExecutionEpoch
    }
    self.epochID = epochID
    self.semanticReferenceTimeSeconds = semanticReferenceTimeSeconds
    self.issuedAtSeconds = issuedAtSeconds
    self.deadlineSeconds = deadlineSeconds
  }
}

/// Phase 4 supplies and authenticates the opaque bytes; this value is never stored in an overlay.
public struct WaiverEpochCredential: Equatable, Sendable {
  public let requirement: WaiverEpochRequirement
  public let context: ExecutionEpochContext
  public let opaqueCredential: Data

  public init(
    requirement: WaiverEpochRequirement,
    context: ExecutionEpochContext,
    opaqueCredential: Data
  ) throws {
    guard context.semanticReferenceTimeSeconds == requirement.semanticReferenceTimeSeconds,
      !opaqueCredential.isEmpty
    else { throw PolicyModelError.invalidExecutionEpoch }
    self.requirement = requirement
    self.context = context
    self.opaqueCredential = opaqueCredential
  }
}

public struct DecisionOverlay: Equatable, Sendable {
  public static let currentBindingVersion = "decision-overlay-v1"

  public let bindingVersion: String
  public let policyVersion: String
  public let schemaVersion: String
  public let referencedPlanHash: PolicyDigest
  public let referencedEvidenceHash: PolicyDigest
  public let selectedActionIDs: [ActionID]
  public let waiverConsents: [WaiverConsentCore]
  public let userNotes: [String]
  public let overlayHash: PolicyDigest

  public init(
    bindingVersion: String,
    policyVersion: String,
    schemaVersion: String,
    referencedPlanHash: PolicyDigest,
    referencedEvidenceHash: PolicyDigest,
    selectedActionIDs: [ActionID],
    waiverConsents: [WaiverConsentCore],
    userNotes: [String],
    overlayHash: PolicyDigest
  ) {
    self.bindingVersion = bindingVersion
    self.policyVersion = policyVersion
    self.schemaVersion = schemaVersion
    self.referencedPlanHash = referencedPlanHash
    self.referencedEvidenceHash = referencedEvidenceHash
    self.selectedActionIDs = selectedActionIDs
    self.waiverConsents = waiverConsents
    self.userNotes = userNotes
    self.overlayHash = overlayHash
  }

  public static func create(
    plan: ImmutablePlan,
    selectedActionIDs: [ActionID],
    waiverConsents: [WaiverConsentCore],
    userNotes: [String]
  ) -> Self {
    let overlay = Self(
      bindingVersion: currentBindingVersion,
      policyVersion: plan.policyVersion,
      schemaVersion: plan.schemaVersion,
      referencedPlanHash: plan.planHash,
      referencedEvidenceHash: plan.evidenceHash,
      selectedActionIDs: selectedActionIDs,
      waiverConsents: waiverConsents,
      userNotes: userNotes,
      overlayHash: PolicyDigest(unchecked: Data(repeating: 0, count: 32))
    )
    return Self(
      bindingVersion: overlay.bindingVersion,
      policyVersion: overlay.policyVersion,
      schemaVersion: overlay.schemaVersion,
      referencedPlanHash: overlay.referencedPlanHash,
      referencedEvidenceHash: overlay.referencedEvidenceHash,
      selectedActionIDs: selectedActionIDs,
      waiverConsents: waiverConsents,
      userNotes: userNotes,
      overlayHash: overlay.recomputedHash
    )
  }

  fileprivate var recomputedHash: PolicyDigest {
    PolicyBindings.digest(kind: "decision-overlay") { encoder in
      encoder.string(bindingVersion)
      encoder.string(policyVersion)
      encoder.string(schemaVersion)
      encoder.data(referencedPlanHash.bytes)
      encoder.data(referencedEvidenceHash.bytes)
      encoder.array(Array(Set(selectedActionIDs)).sorted()) { $0.digest.bytes }
      encoder.array(
        waiverConsents.sorted(by: waiverConsentCorePrecedes)
      ) { consent in
        var nested = PolicyBindingEncoder()
        nested.data(consent.actionLineageID.digest.bytes)
        nested.data(consent.consentHash.bytes)
        return nested.data
      }
      encoder.array(userNotes) { Data($0.utf8) }
    }
  }
}

public struct ValidatedExecutionStep: Equatable, Sendable {
  public let action: ActionDefinition
  public let componentActions: [ActionDefinition]
  public let prerequisiteStepActionIDs: [ActionID]
  public let jitRevalidationActions: [ActionDefinition]
  public let releaseSet: PlanReleaseSet?
  public let releaseSets: [PlanReleaseSet]
  public let releaseGraphManifest: ReleaseGraphManifest?

  fileprivate init(
    action: ActionDefinition,
    componentActions: [ActionDefinition],
    prerequisiteStepActionIDs: [ActionID],
    jitRevalidationActions: [ActionDefinition],
    releaseSets: [PlanReleaseSet],
    releaseGraphManifest: ReleaseGraphManifest?
  ) {
    self.action = action
    self.componentActions = componentActions
    self.prerequisiteStepActionIDs = prerequisiteStepActionIDs
    self.jitRevalidationActions = jitRevalidationActions
    self.releaseSet = releaseSets.count == 1 ? releaseSets.first : nil
    self.releaseSets = releaseSets
    self.releaseGraphManifest = releaseGraphManifest
  }
}

public struct ValidatedDecisionOverlay: Equatable, Sendable {
  public let selectedActions: [ActionDefinition]
  public let executionSteps: [ValidatedExecutionStep]
  public let releaseGraphManifest: ReleaseGraphManifest?
  public let activatedReleaseSets: [PlanReleaseSet]
  public let waiverConsents: [WaiverConsentCore]
  public let epochRequirements: [WaiverEpochRequirement]
  public let userNotes: [String]
  public let overlayHash: PolicyDigest
}

public enum DecisionOverlayValidator {
  public static func validate(
    _ overlay: DecisionOverlay,
    against plan: ImmutablePlan
  ) throws -> ValidatedDecisionOverlay {
    guard overlay.bindingVersion == DecisionOverlay.currentBindingVersion,
      rawStringEqual(overlay.policyVersion, plan.policyVersion),
      rawStringEqual(overlay.schemaVersion, plan.schemaVersion)
    else { throw PolicyModelError.invalidOverlayVersion }
    guard overlay.overlayHash == overlay.recomputedHash else {
      throw PolicyModelError.invalidOverlayHash
    }
    guard overlay.referencedPlanHash == plan.planHash,
      overlay.referencedEvidenceHash == plan.evidenceHash
    else { throw PolicyModelError.staleOverlay }

    let actionByID = Dictionary(uniqueKeysWithValues: plan.actions.map { ($0.id, $0) })
    let selectedIDs = Set(overlay.selectedActionIDs)
    guard selectedIDs.count == overlay.selectedActionIDs.count else {
      throw PolicyModelError.duplicateIdentifier
    }
    let selectedActions = try overlay.selectedActionIDs.sorted().map { id -> ActionDefinition in
      guard let action = actionByID[id] else { throw PolicyModelError.injectedSelection(id) }
      return action
    }

    let actionsByLineage = Dictionary(grouping: selectedActions, by: \.lineageID)
    for lineage in actionsByLineage.keys.sorted()
    where actionsByLineage[lineage]?.count != 1 {
      throw PolicyModelError.ambiguousSelectedLineage(lineage)
    }
    var consentByActionAndPredicate: [ActionID: [WaiverPredicate: WaiverConsentCore]] = [:]
    var epochRequirements: [WaiverEpochRequirement] = []
    for consent in overlay.waiverConsents.sorted(by: waiverConsentCorePrecedes) {
      let lineageMatches = actionsByLineage[consent.actionLineageID] ?? []
      guard lineageMatches.count == 1, let action = lineageMatches.first else {
        throw PolicyModelError.ambiguousConsentLineage(consent.actionLineageID)
      }
      guard selectedIDs.contains(action.id) else {
        throw PolicyModelError.injectedSelection(action.id)
      }
      guard rawStringEqual(consent.policyVersion, action.prototype.policyVersion),
        consent.consentHash == consent.recomputedHash,
        hasNonWhitespace(consent.reason),
        hasNonWhitespace(consent.consentEventID)
      else { throw PolicyModelError.invalidWaiverBinding(action.id, consent.predicate.kind) }
      if consentByActionAndPredicate[action.id]?[consent.predicate] != nil {
        throw PolicyModelError.duplicateIdentifier
      }
      consentByActionAndPredicate[action.id, default: [:]][consent.predicate] = consent
      epochRequirements.append(
        WaiverEpochRequirement(
          consentHash: consent.consentHash,
          actionID: action.id,
          planHash: plan.planHash,
          evidenceHash: plan.evidenceHash,
          semanticReferenceTimeSeconds: plan.globalFacts.semanticReferenceTimeSeconds
        )
      )
    }

    for action in selectedActions {
      for prerequisite in action.prerequisiteActionIDs where !selectedIDs.contains(prerequisite) {
        throw PolicyModelError.missingPrerequisite(prerequisite)
      }
      let required: [WaiverPredicate]
      switch action.evaluation.stageability {
      case .stageable:
        required = []
      case .requiresConsents(let predicates):
        required = predicates
      case .blocked:
        throw PolicyModelError.actionNotStageable(action.id)
      }
      let requiredPredicates = Set(required)
      let provided = consentByActionAndPredicate[action.id] ?? [:]
      for predicate in required where provided[predicate] == nil {
        if provided.keys.contains(where: { $0.kind == predicate.kind }) {
          throw PolicyModelError.invalidWaiverBinding(action.id, predicate.kind)
        }
        throw PolicyModelError.missingWaiver(action.id, predicate.kind)
      }
      for predicate in provided.keys.sorted() where !requiredPredicates.contains(predicate) {
        throw PolicyModelError.unexpectedWaiver(action.id, predicate.kind)
      }
    }

    try validateDuplicateSurvivors(selectedActions, plan: plan)
    try validateFullCorpusDominance(selectedActions, plan: plan)
    try validateTerminalMutationExclusivity(selectedActions)

    let selectedReleaseActions = selectedActions.filter {
      if case .completeReleaseSetRemove = $0.prototype.adapterContract { return true }
      return false
    }
    let activated = plan.releaseSets.filter {
      Set($0.ownerActionIDs).isSubset(of: selectedIDs)
    }
    let releaseComponents = try selectedReleaseExecutionComponents(
      selectedReleaseActions: selectedReleaseActions,
      activatedReleaseSets: activated,
      plan: plan,
      actionByID: actionByID
    )
    guard
      actionContractionsPreserveAcyclicity(
        releaseComponents.map {
          Set($0.aggregateActions.map(\.id) + $0.owners.map(\.id))
        },
        actions: selectedActions
      )
    else {
      throw PolicyModelError.invalidActionContract
    }
    var replacementActionID: [ActionID: ActionID] = [:]
    for component in releaseComponents {
      for replacedID in component.aggregateActions.map(\.id) + component.owners.map(\.id) {
        if let previous = replacementActionID[replacedID], previous != component.representative.id {
          throw PolicyModelError.incompleteReleaseGraph
        }
        replacementActionID[replacedID] = component.representative.id
      }
    }
    let componentByRepresentative = Dictionary(
      uniqueKeysWithValues: releaseComponents.map { ($0.representative.id, $0) }
    )
    let retainedActions = selectedActions.filter {
      replacementActionID[$0.id] == nil || componentByRepresentative[$0.id] != nil
    }
    var executionSteps: [ValidatedExecutionStep] = []
    for action in retainedActions {
      if let component = componentByRepresentative[action.id] {
        let prerequisiteIDs = Set(
          (component.aggregateActions.flatMap(\.prerequisiteActionIDs)
            + component.owners.flatMap(\.prerequisiteActionIDs)).compactMap {
              let replacement = replacementActionID[$0] ?? $0
              return replacement == action.id ? nil : replacement
            }
        ).sorted()
        executionSteps.append(
          ValidatedExecutionStep(
            action: action,
            componentActions: component.aggregateActions,
            prerequisiteStepActionIDs: prerequisiteIDs,
            jitRevalidationActions: component.jitRevalidationActions,
            releaseSets: component.releaseSets,
            releaseGraphManifest: plan.releaseGraphManifest
          )
        )
      } else {
        let prerequisiteIDs = Set(
          action.prerequisiteActionIDs.map {
            replacementActionID[$0] ?? $0
          }
        ).subtracting([action.id]).sorted()
        executionSteps.append(
          ValidatedExecutionStep(
            action: action,
            componentActions: [action],
            prerequisiteStepActionIDs: prerequisiteIDs,
            jitRevalidationActions: [action],
            releaseSets: [],
            releaseGraphManifest: plan.releaseGraphManifest
          )
        )
      }
    }
    executionSteps = try topologicallyOrdered(executionSteps)
    return ValidatedDecisionOverlay(
      selectedActions: selectedActions,
      executionSteps: executionSteps,
      releaseGraphManifest: plan.releaseGraphManifest,
      activatedReleaseSets: activated,
      waiverConsents: overlay.waiverConsents.sorted(by: waiverConsentCorePrecedes),
      epochRequirements: epochRequirements.sorted { left, right in
        if left.actionID != right.actionID { return left.actionID < right.actionID }
        return left.consentHash < right.consentHash
      },
      userNotes: overlay.userNotes,
      overlayHash: overlay.overlayHash
    )
  }

  private static func hasNonWhitespace(_ value: String) -> Bool {
    value.unicodeScalars.contains { !CharacterSet.whitespacesAndNewlines.contains($0) }
  }

  private struct ReleaseExecutionComponent {
    let representative: ActionDefinition
    let aggregateActions: [ActionDefinition]
    let releaseSets: [PlanReleaseSet]
    let owners: [ActionDefinition]
    let jitRevalidationActions: [ActionDefinition]
  }

  private static func selectedReleaseExecutionComponents(
    selectedReleaseActions: [ActionDefinition],
    activatedReleaseSets: [PlanReleaseSet],
    plan: ImmutablePlan,
    actionByID: [ActionID: ActionDefinition]
  ) throws -> [ReleaseExecutionComponent] {
    guard !selectedReleaseActions.isEmpty else { return [] }
    guard let manifest = plan.releaseGraphManifest else {
      throw PolicyModelError.incompleteReleaseGraph
    }
    let releaseSetByBinding = Dictionary(
      uniqueKeysWithValues: plan.releaseSets.map { ($0.actionBinding.bindingBytes, $0) }
    )
    var selectedByGroup: [Data: ActionDefinition] = [:]
    for action in selectedReleaseActions.sorted(by: { $0.id < $1.id }) {
      guard case .completeReleaseSetRemove(let contract) = action.prototype.adapterContract,
        let releaseSet = releaseSetByBinding[contract.binding.bindingBytes]
      else { throw PolicyModelError.incompleteReleaseGraph }
      let groupKey = Data(releaseSet.allocationGroupID.utf8)
      guard selectedByGroup.updateValue(action, forKey: groupKey) == nil else {
        throw PolicyModelError.incompleteReleaseGraph
      }
    }

    let activatedGroupKeys = Set(
      activatedReleaseSets.map { Data($0.allocationGroupID.utf8) })
    let releaseSetByGroup = Dictionary(
      uniqueKeysWithValues: plan.releaseSets.map {
        (Data($0.allocationGroupID.utf8), $0)
      })
    var result: [ReleaseExecutionComponent] = []
    for component in manifest.connectedComponents {
      let componentGroupKeys = Set(component.allocationGroupIDs.map { Data($0.utf8) })
      let representedGroupKeys = componentGroupKeys.intersection(Set(selectedByGroup.keys))
      guard !representedGroupKeys.isEmpty else { continue }
      guard representedGroupKeys == componentGroupKeys.intersection(activatedGroupKeys) else {
        throw PolicyModelError.incompleteReleaseGraph
      }
      let releaseSets = representedGroupKeys.compactMap { releaseSetByGroup[$0] }.sorted {
        rawStringPrecedes($0.allocationGroupID, $1.allocationGroupID)
      }
      guard releaseSets.count == representedGroupKeys.count else {
        throw PolicyModelError.incompleteReleaseGraph
      }
      let aggregateActions = representedGroupKeys.compactMap { selectedByGroup[$0] }.sorted {
        $0.id < $1.id
      }
      guard aggregateActions.count == representedGroupKeys.count,
        let representative = aggregateActions.first
      else { throw PolicyModelError.incompleteReleaseGraph }
      let ownerIDs = Set(releaseSets.flatMap(\.ownerActionIDs))
      let owners = try ownerIDs.sorted().map { ownerID -> ActionDefinition in
        guard let owner = actionByID[ownerID] else {
          throw PolicyModelError.releaseSetDanglingAction(ownerID)
        }
        return owner
      }
      let exactDiscardPrerequisites = owners.flatMap { owner in
        owner.prerequisiteActionIDs.compactMap { prerequisiteID -> ActionDefinition? in
          guard let prerequisite = actionByID[prerequisiteID],
            isExactGitDiscardPrerequisite(prerequisite, remove: owner)
          else { return nil }
          return prerequisite
        }
      }
      let jitByID = Dictionary(
        (aggregateActions + owners + exactDiscardPrerequisites).map { ($0.id, $0) },
        uniquingKeysWith: { first, _ in first }
      )
      result.append(
        ReleaseExecutionComponent(
          representative: representative,
          aggregateActions: aggregateActions,
          releaseSets: releaseSets,
          owners: owners,
          jitRevalidationActions: jitByID.values.sorted { $0.id < $1.id }
        )
      )
    }
    guard
      result.reduce(0, { $0 + $1.aggregateActions.count })
        == selectedReleaseActions.count
    else { throw PolicyModelError.incompleteReleaseGraph }
    return result.sorted { $0.representative.id < $1.representative.id }
  }

  private static func validateDuplicateSurvivors(
    _ selectedActions: [ActionDefinition],
    plan: ImmutablePlan
  ) throws {
    let evidenceByCandidate = Dictionary(
      grouping: plan.evidenceSnapshots, by: { Data($0.candidateID.utf8) })
    let survivorCandidateIDs = Set(
      plan.evidenceSnapshots.flatMap { snapshot in
        snapshot.semanticReviewFacts.compactMap { fact -> Data? in
          guard case .duplicateSurvivorChoice(_, let survivorCandidateID, _) = fact else {
            return nil
          }
          return Data(survivorCandidateID.utf8)
        }
      })
    let mutationActions = selectedActions.filter {
      if case .completeReleaseSetRemove = $0.prototype.adapterContract { return false }
      return true
    }
    for survivorCandidateID in survivorCandidateIDs.sorted(by: {
      $0.lexicographicallyPrecedes($1)
    }) {
      let survivorMatches = evidenceByCandidate[survivorCandidateID] ?? []
      guard survivorMatches.count == 1, let survivor = survivorMatches.first,
        !mutationActions.contains(where: {
          namespacesMayOverlap(
            $0.prototype.namespaceBinding, survivor.namespaceBinding)
        })
      else { throw PolicyModelError.invalidActionContract }
    }
  }

  private static func validateTerminalMutationExclusivity(
    _ selectedActions: [ActionDefinition]
  ) throws {
    let actionByID = Dictionary(uniqueKeysWithValues: selectedActions.map { ($0.id, $0) })
    for leftIndex in selectedActions.indices {
      for rightIndex in selectedActions.indices where rightIndex > leftIndex {
        let left = selectedActions[leftIndex]
        let right = selectedActions[rightIndex]
        guard
          namespacesMayOverlap(
            left.prototype.namespaceBinding, right.prototype.namespaceBinding)
        else { continue }
        guard isAllowedMutationComposition(left, right, actionByID: actionByID) else {
          throw PolicyModelError.invalidActionContract
        }
      }
    }
  }

  private static func validateFullCorpusDominance(
    _ selectedActions: [ActionDefinition],
    plan: ImmutablePlan
  ) throws {
    let gitEvidence = plan.evidenceSnapshots.filter(\.hasGitWorktreeScope)
    for action in selectedActions {
      switch action.prototype.adapterContract {
      case .completeReleaseSetRemove:
        continue
      case .gitWorktreeRemove, .gitWorktreeDiscardLocalChanges:
        break
      default:
        guard
          !gitEvidence.contains(where: {
            namespacesMayOverlap(
              action.prototype.namespaceBinding, $0.namespaceBinding)
          })
        else {
          throw PolicyModelError.invalidActionContract
        }
      }
      let affectedEvidence = plan.evidenceSnapshots.filter {
        namespaceMutationAffects(
          action.prototype.namespaceBinding, evidence: $0.namespaceBinding)
      }
      guard affectedEvidence.allSatisfy({ $0.evidenceID == action.evidenceID }) else {
        throw PolicyModelError.invalidActionContract
      }
    }
  }

  private static func isAllowedMutationComposition(
    _ left: ActionDefinition,
    _ right: ActionDefinition,
    actionByID: [ActionID: ActionDefinition]
  ) -> Bool {
    if case .completeReleaseSetRemove(let release) = left.prototype.adapterContract {
      return release.binding.ownerActionIDs.contains(right.id)
        || releaseContainsExactDiscard(
          release, discardAction: right, actionByID: actionByID)
    }
    if case .completeReleaseSetRemove(let release) = right.prototype.adapterContract {
      return release.binding.ownerActionIDs.contains(left.id)
        || releaseContainsExactDiscard(
          release, discardAction: left, actionByID: actionByID)
    }
    return isExactGitDiscardPrerequisite(left, remove: right)
      || isExactGitDiscardPrerequisite(right, remove: left)
  }

  private static func releaseContainsExactDiscard(
    _ release: CompleteReleaseSetRemoveContract,
    discardAction: ActionDefinition,
    actionByID: [ActionID: ActionDefinition]
  ) -> Bool {
    release.binding.ownerActionIDs.contains { ownerActionID in
      guard let owner = actionByID[ownerActionID] else { return false }
      return isExactGitDiscardPrerequisite(discardAction, remove: owner)
    }
  }

  private static func isExactGitDiscardPrerequisite(
    _ discardAction: ActionDefinition,
    remove: ActionDefinition
  ) -> Bool {
    guard
      case .gitWorktreeDiscardLocalChanges(let discard) =
        discardAction.prototype.adapterContract,
      case .gitWorktreeRemove(let contract) = remove.prototype.adapterContract,
      remove.prerequisiteActionIDs.contains(discardAction.id)
    else { return false }
    return discard.verifiedEvidence == contract.verifiedEvidence
      && discard.successorBaseline == contract.executionBaseline
      && contract.verifiedEvidence.verifiedLocalChanges(
        targetIdentity: remove.prototype.targetIdentity)
        == .present(changeSetDigest: discard.changeSetDigest)
      && discardAction.prototype.namespaceBinding.bindingBytes
        == remove.prototype.namespaceBinding.bindingBytes
  }

  private static func topologicallyOrdered(
    _ steps: [ValidatedExecutionStep]
  ) throws -> [ValidatedExecutionStep] {
    let stepByID = Dictionary(uniqueKeysWithValues: steps.map { ($0.action.id, $0) })
    guard
      steps.allSatisfy({ step in
        step.prerequisiteStepActionIDs.allSatisfy { stepByID[$0] != nil }
      })
    else { throw PolicyModelError.invalidActionContract }
    let dependents = Dictionary(
      grouping: steps.flatMap { step in
        step.prerequisiteStepActionIDs.map { ($0, step.action.id) }
      }, by: \.0
    ).mapValues { $0.map(\.1) }
    var indegree = Dictionary(
      uniqueKeysWithValues: steps.map { ($0.action.id, $0.prerequisiteStepActionIDs.count) })
    var ready = PolicyMinHeap(indegree.filter { $0.value == 0 }.map(\.key))
    var result: [ValidatedExecutionStep] = []
    while let next = ready.popMin() {
      guard let step = stepByID[next] else { throw PolicyModelError.invalidActionContract }
      result.append(step)
      for dependent in dependents[next] ?? [] {
        indegree[dependent, default: 0] -= 1
        if indegree[dependent] == 0 {
          ready.insert(dependent)
        }
      }
    }
    guard result.count == steps.count else { throw PolicyModelError.actionCycle }
    return result
  }
}

private func waiverConsentCorePrecedes(
  _ lhs: WaiverConsentCore,
  _ rhs: WaiverConsentCore
) -> Bool {
  if lhs.actionLineageID != rhs.actionLineageID {
    return lhs.actionLineageID < rhs.actionLineageID
  }
  if lhs.predicate != rhs.predicate {
    return lhs.predicate < rhs.predicate
  }
  return lhs.consentHash < rhs.consentHash
}

private struct PolicyMinHeap<Element: Comparable> {
  private var storage: [Element]

  init<S: Sequence>(_ elements: S) where S.Element == Element {
    storage = Array(elements)
    guard storage.count > 1 else { return }
    for index in stride(from: (storage.count / 2) - 1, through: 0, by: -1) {
      siftDown(from: index)
    }
  }

  mutating func insert(_ element: Element) {
    storage.append(element)
    var child = storage.count - 1
    while child > 0 {
      let parent = (child - 1) / 2
      guard storage[child] < storage[parent] else { return }
      storage.swapAt(child, parent)
      child = parent
    }
  }

  mutating func popMin() -> Element? {
    guard !storage.isEmpty else { return nil }
    if storage.count == 1 { return storage.removeLast() }
    storage.swapAt(0, storage.count - 1)
    let minimum = storage.removeLast()
    siftDown(from: 0)
    return minimum
  }

  private mutating func siftDown(from start: Int) {
    var parent = start
    while true {
      let left = (parent * 2) + 1
      guard left < storage.count else { return }
      let right = left + 1
      let child = right < storage.count && storage[right] < storage[left] ? right : left
      guard storage[child] < storage[parent] else { return }
      storage.swapAt(parent, child)
      parent = child
    }
  }
}

private func actionContractionsPreserveAcyclicity(
  _ components: [Set<ActionID>],
  actions: [ActionDefinition]
) -> Bool {
  let actionIDs = Set(actions.map(\.id))
  var representativeByActionID: [ActionID: ActionID] = [:]
  for component in components where !component.isEmpty {
    guard component.isSubset(of: actionIDs), let representative = component.min() else {
      return false
    }
    for actionID in component {
      if let existing = representativeByActionID[actionID], existing != representative {
        return false
      }
      representativeByActionID[actionID] = representative
    }
  }
  let mappedID: (ActionID) -> ActionID = {
    representativeByActionID[$0] ?? $0
  }
  let contractedIDs = Set(actions.map { mappedID($0.id) })
  var dependents: [ActionID: Set<ActionID>] = [:]
  var indegree = Dictionary(uniqueKeysWithValues: contractedIDs.map { ($0, 0) })
  for action in actions {
    let dependentID = mappedID(action.id)
    for prerequisite in action.prerequisiteActionIDs {
      let prerequisiteID = mappedID(prerequisite)
      guard prerequisiteID != dependentID else { continue }
      if dependents[prerequisiteID, default: []].insert(dependentID).inserted {
        indegree[dependentID, default: 0] += 1
      }
    }
  }
  var ready = PolicyMinHeap(indegree.filter { $0.value == 0 }.map(\.key))
  var visited = 0
  while let next = ready.popMin() {
    visited += 1
    for dependent in dependents[next] ?? [] {
      indegree[dependent, default: 0] -= 1
      if indegree[dependent] == 0 {
        ready.insert(dependent)
      }
    }
  }
  return visited == contractedIDs.count
}

enum PolicyBindings {
  static func digest(
    kind: String,
    _ encode: (inout PolicyBindingEncoder) -> Void
  ) -> PolicyDigest {
    var encoder = PolicyBindingEncoder()
    encode(&encoder)
    var input = Data("diskplan/\(kind)/v1\0".utf8)
    input.append(encoder.data)
    return PolicyDigest(unchecked: Data(SHA256.hash(data: input)))
  }
}

struct PolicyBindingEncoder {
  var data = Data()

  mutating func uint8(_ value: UInt8) { data.append(value) }
  mutating func uint64(_ value: UInt64) { integer(value) }
  mutating func int64(_ value: Int64) { integer(value) }
  mutating func bool(_ value: Bool) { uint8(value ? 1 : 0) }
  mutating func string(_ value: String) { self.data(Data(value.utf8)) }

  mutating func data(_ value: Data) {
    uint64(UInt64(value.count))
    data.append(value)
  }

  mutating func array<Value>(_ values: [Value], encode: (Value) -> Data) {
    uint64(UInt64(values.count))
    for value in values { data(encode(value)) }
  }

  mutating func observation<Value: Equatable & Sendable>(
    _ observation: Observation<Value>,
    known: (inout Self, Value) -> Void
  ) {
    switch observation {
    case .absent:
      uint8(0)
    case .known(let value):
      uint8(1)
      known(&self, value)
    case .unknown(let reason):
      uint8(2)
      string(reason.rawValue)
    case .unreadable(let failure):
      uint8(3)
      string(failure.code)
      string(failure.collector)
    case .failed(let failure):
      uint8(4)
      string(failure.code)
      string(failure.collector)
    }
  }

  mutating func knownOrUnknown<Value: Comparable & Sendable>(
    _ value: KnownOrUnknown<Value>,
    known: (inout Self, Value) -> Void
  ) {
    switch value {
    case .known(let knownValue):
      uint8(0)
      known(&self, knownValue)
    case .unknown(let reason):
      uint8(1)
      string(reason.rawValue)
    }
  }

  private mutating func integer<T: FixedWidthInteger>(_ value: T) {
    var bigEndian = value.bigEndian
    withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
  }
}

func encodeIdentity(_ identity: ObjectIdentity, into encoder: inout PolicyBindingEncoder) {
  encoder.uint64(identity.device)
  encoder.uint64(identity.object)
  encoder.observation(identity.generation) { $0.uint64($1) }
  encoder.string(identity.type.rawValue)
}

private func encodeAdapterScopeEvidence(
  _ evidence: AdapterScopeEvidence,
  into encoder: inout PolicyBindingEncoder
) {
  switch evidence {
  case .genericRemove:
    encoder.uint8(0)
  case .gitWorktree:
    encoder.uint8(1)
  case .codexCleanTemporary(let cleanupScopeID):
    encoder.uint8(2)
    encoder.string(cleanupScopeID)
  case .versionedArtifactRemove(let artifactKind, let version):
    encoder.uint8(3)
    encoder.string(artifactKind)
    encoder.string(version)
  case .completeReleaseSetRemove(let allocationGroupID):
    encoder.uint8(4)
    encoder.string(allocationGroupID)
  }
}

extension AdapterScopeEvidence {
  fileprivate var bindingBytes: Data {
    var encoder = PolicyBindingEncoder()
    encodeAdapterScopeEvidence(self, into: &encoder)
    return encoder.data
  }
}

private func evidenceSupportsAdapterScope(
  _ evidence: FrozenEvidenceSnapshot,
  _ scope: AdapterScopeEvidence
) -> Bool {
  ([evidence.adapterScope] + evidence.additionalAdapterScopes).contains {
    adapterScopeMatches($0, scope)
  }
}

private func hasNonWhitespace(_ value: String) -> Bool {
  value.unicodeScalars.contains { !CharacterSet.whitespacesAndNewlines.contains($0) }
}

private func rawStringPrecedes(_ lhs: String, _ rhs: String) -> Bool {
  Data(lhs.utf8).lexicographicallyPrecedes(Data(rhs.utf8))
}

func rawStringEqual(_ lhs: String, _ rhs: String) -> Bool {
  Data(lhs.utf8) == Data(rhs.utf8)
}

private func accessPolicyBaselineMatches(
  _ baseline: RequiredAccessPolicyBaseline,
  evidence: FrozenEvidenceSnapshot
) -> Bool {
  guard case .known(let accessPolicy) = evidence.accessPolicy,
    case .known(let aclDigest) = evidence.aclDigest,
    case .known(let providerState) = evidence.providerState,
    case .known(let mountIdentity) = evidence.targetMountIdentity
  else { return false }
  return baseline.accessPolicyBytes == Data(accessPolicy.utf8)
    && baseline.aclDigest == aclDigest
    && baseline.providerState == providerState
    && baseline.mountIdentityBytes == Data(mountIdentity.utf8)
}

private func contentProtectionBaselineMatches(
  _ prototype: ActionPrototype,
  evidence: FrozenEvidenceSnapshot
) -> Bool {
  if case .gitWorktreeRemove(let contract) = prototype.adapterContract {
    return prototype.protectedProperties.content.expectedBaseline
      == contract.executionBaseline.contentProtection
  }
  return evidence.contentProtection
    == .known(prototype.protectedProperties.content.expectedBaseline)
}

private func namespacesMayOverlap(
  _ lhs: ProtectedNamespaceBinding,
  _ rhs: ProtectedNamespaceBinding
) -> Bool {
  let leftAbsolute = rawRootComponents(lhs.rawRoot) + lhs.targetPath.components
  let rightAbsolute = rawRootComponents(rhs.rawRoot) + rhs.targetPath.components
  if pathComponentsOverlap(leftAbsolute, rightAbsolute) { return true }
  if identitiesMayMatch(lhs.rootIdentity, rhs.rootIdentity),
    lhs.targetPath.overlaps(rhs.targetPath)
  {
    return true
  }
  let leftAncestors = [lhs.rootIdentity] + lhs.parentChain.map(\.identity)
  let rightAncestors = [rhs.rootIdentity] + rhs.parentChain.map(\.identity)
  return identitiesMayMatch(lhs.targetIdentity, rhs.targetIdentity)
    || rightAncestors.contains { identitiesMayMatch(lhs.targetIdentity, $0) }
    || leftAncestors.contains { identitiesMayMatch(rhs.targetIdentity, $0) }
}

private func namespaceMutationAffects(
  _ mutation: ProtectedNamespaceBinding,
  evidence: ProtectedNamespaceBinding
) -> Bool {
  let mutationAbsolute = rawRootComponents(mutation.rawRoot) + mutation.targetPath.components
  let evidenceAbsolute = rawRootComponents(evidence.rawRoot) + evidence.targetPath.components
  if pathComponentsIsAncestor(mutationAbsolute, of: evidenceAbsolute) { return true }
  if identitiesMayMatch(mutation.rootIdentity, evidence.rootIdentity),
    evidence.targetPath.isWithin(mutation.targetPath)
  {
    return true
  }
  let evidenceAncestors = [evidence.rootIdentity] + evidence.parentChain.map(\.identity)
  return identitiesMayMatch(mutation.targetIdentity, evidence.targetIdentity)
    || evidenceAncestors.contains { identitiesMayMatch(mutation.targetIdentity, $0) }
}

private func rawRootComponents(_ root: RawRootPath) -> [Data] {
  guard root.absoluteBytes != Data("/".utf8) else { return [] }
  return Array(root.absoluteBytes).dropFirst().split(separator: 47).map { Data($0) }
}

private func pathComponentsOverlap(_ lhs: [Data], _ rhs: [Data]) -> Bool {
  let sharedCount = Swift.min(lhs.count, rhs.count)
  return Array(lhs.prefix(sharedCount)) == Array(rhs.prefix(sharedCount))
}

private func pathComponentsIsAncestor(_ ancestor: [Data], of path: [Data]) -> Bool {
  guard ancestor.count <= path.count else { return false }
  return Array(path.prefix(ancestor.count)) == ancestor
}

private func identitiesMayMatch(_ lhs: ObjectIdentity, _ rhs: ObjectIdentity) -> Bool {
  guard lhs.device == rhs.device, lhs.object == rhs.object else { return false }
  switch (lhs.generation, rhs.generation) {
  case (.known(let left), .known(let right)):
    return left == right
  default:
    return true
  }
}

private func adapterScopeMatches(
  _ lhs: AdapterScopeEvidence,
  _ rhs: AdapterScopeEvidence
) -> Bool {
  switch (lhs, rhs) {
  case (.genericRemove, .genericRemove), (.gitWorktree, .gitWorktree):
    true
  case (.codexCleanTemporary(let left), .codexCleanTemporary(let right)):
    rawStringEqual(left, right)
  case (
    .versionedArtifactRemove(let leftKind, let leftVersion),
    .versionedArtifactRemove(let rightKind, let rightVersion)
  ):
    rawStringEqual(leftKind, rightKind) && rawStringEqual(leftVersion, rightVersion)
  case (.completeReleaseSetRemove(let left), .completeReleaseSetRemove(let right)):
    rawStringEqual(left, right)
  default:
    false
  }
}

private func postconditionMatches(
  _ lhs: ActionPostcondition,
  _ rhs: ActionPostcondition
) -> Bool {
  switch (lhs, rhs) {
  case (.targetAbsent, .targetAbsent),
    (.worktreeQuarantinedThenAbsent, .worktreeQuarantinedThenAbsent):
    true
  case (
    .gitWorktreeLocalChangesDiscarded(let leftDigest, let leftSuccessor),
    .gitWorktreeLocalChangesDiscarded(let rightDigest, let rightSuccessor)
  ):
    leftDigest == rightDigest && leftSuccessor == rightSuccessor
  case (.cleanupScopeAbsent(let left), .cleanupScopeAbsent(let right)):
    rawStringEqual(left, right)
  case (
    .artifactVersionAbsent(let leftKind, let leftVersion),
    .artifactVersionAbsent(let rightKind, let rightVersion)
  ):
    rawStringEqual(leftKind, rightKind) && rawStringEqual(leftVersion, rightVersion)
  case (.allocationGroupReleased(let left), .allocationGroupReleased(let right)):
    rawStringEqual(left, right)
  default:
    false
  }
}

func encodeReleaseTopologyExpectation(
  _ topology: ReleaseTopologyExpectation
) -> Data {
  var encoder = PolicyBindingEncoder()
  encoder.string(topology.allocationGroupID)
  encoder.array(
    topology.fileObjects.sorted {
      rawStringPrecedes($0.fileObjectID, $1.fileObjectID)
    }
  ) { file in
    var nested = PolicyBindingEncoder()
    nested.string(file.fileObjectID)
    nested.array(file.owners.sorted(by: releaseOwnerLinkPrecedes)) { owner in
      var ownerEncoder = PolicyBindingEncoder()
      ownerEncoder.string(owner.candidateID)
      ownerEncoder.data(owner.path.bindingBytes)
      return ownerEncoder.data
    }
    nested.array(file.ownerNamespaces.sorted(by: releaseOwnerNamespacePrecedes)) { owner in
      var ownerEncoder = PolicyBindingEncoder()
      ownerEncoder.string(owner.link.candidateID)
      ownerEncoder.data(owner.link.path.bindingBytes)
      ownerEncoder.data(owner.namespaceBinding.bindingBytes)
      return ownerEncoder.data
    }
    nested.observation(file.linkCount) { $0.uint64(UInt64($1)) }
    return nested.data
  }
  encoder.observation(topology.cloneIdentity) { encoder, identity in
    encoder.uint64(identity.device)
    encoder.uint64(identity.cloneID)
  }
  encoder.observation(topology.cloneRefCount) { $0.uint64(UInt64($1)) }
  encoder.observation(topology.sharedBytes) { $0.uint64($1) }
  encoder.observation(topology.snapshotBlocker) { $0.bool($1) }
  return encoder.data
}

private func releaseOwnerLinkPrecedes(_ lhs: FileOwnerLink, _ rhs: FileOwnerLink) -> Bool {
  if !rawStringEqual(lhs.candidateID, rhs.candidateID) {
    return rawStringPrecedes(lhs.candidateID, rhs.candidateID)
  }
  return lhs.path < rhs.path
}

private func releaseOwnerNamespacePrecedes(
  _ lhs: FileOwnerNamespaceExpectation,
  _ rhs: FileOwnerNamespaceExpectation
) -> Bool {
  releaseOwnerLinkPrecedes(lhs.link, rhs.link)
}

private func manifestBindingBytes(
  graphDigest: PolicyDigest,
  graphProvenance: StorageGraphProvenance,
  allocationGroupIDs: [String],
  candidateActions: [ReleaseGraphCandidateActionManifestEntry],
  connectedComponents: [ReleaseGraphComponentManifest]
) -> Data {
  var encoder = PolicyBindingEncoder()
  encoder.data(graphDigest.bytes)
  encoder.data(graphProvenance.globalFactsHash.bytes)
  encoder.data(graphProvenance.evidenceHash.bytes)
  encoder.string(graphProvenance.policyVersion)
  encoder.string(graphProvenance.schemaVersion)
  encoder.int64(graphProvenance.semanticReferenceTimeSeconds)
  encoder.uint64(UInt64(allocationGroupIDs.count))
  encoder.array(allocationGroupIDs) { Data($0.utf8) }
  encoder.array(candidateActions) { $0.bindingBytes }
  encoder.array(connectedComponents) { $0.bindingBytes }
  return encoder.data
}

private func connectedReleaseComponents(
  _ releaseSets: [PlanReleaseSet]
) -> [ReleaseGraphComponentManifest] {
  let canonicalSets = releaseSets.sorted {
    rawStringPrecedes($0.allocationGroupID, $1.allocationGroupID)
  }
  var unionFind = ReleaseComponentUnionFind(count: canonicalSets.count)
  let groupIndicesByCandidate = Dictionary(
    grouping: canonicalSets.enumerated().flatMap { index, releaseSet in
      releaseSet.ownerCandidateIDs.map { (Data($0.utf8), index) }
    },
    by: \.0
  ).mapValues { entries in
    entries.map(\.1).sorted()
  }
  for candidateKey in groupIndicesByCandidate.keys.sorted(by: {
    $0.lexicographicallyPrecedes($1)
  }) {
    guard let indices = groupIndicesByCandidate[candidateKey],
      let first = indices.first
    else { continue }
    for index in indices.dropFirst() {
      unionFind.union(first, index)
    }
  }
  var groupIndicesByRoot: [Int: [Int]] = [:]
  for index in canonicalSets.indices {
    groupIndicesByRoot[unionFind.find(index), default: []].append(index)
  }

  return groupIndicesByRoot.values.map { groupIndices in
    let orderedSets = groupIndices.sorted().map { canonicalSets[$0] }
    let candidateKeys = Set(
      orderedSets.flatMap { $0.ownerCandidateIDs.map { Data($0.utf8) } })
    let topologyDigest = PolicyBindings.digest(kind: "release-component-topology") {
      encoder in
      encoder.array(orderedSets) { releaseSet in
        var nested = PolicyBindingEncoder()
        nested.string(releaseSet.allocationGroupID)
        nested.data(encodeReleaseTopologyExpectation(releaseSet.topologyExpectation))
        nested.array(releaseSet.ownerCandidateIDs) { Data($0.utf8) }
        return nested.data
      }
    }
    return ReleaseGraphComponentManifest(
      allocationGroupIDs: orderedSets.map(\.allocationGroupID),
      candidateIDs: candidateKeys.sorted { $0.lexicographicallyPrecedes($1) }.map {
        String(decoding: $0, as: UTF8.self)
      },
      topologyDigest: topologyDigest
    )
  }.sorted { left, right in
    rawStringArrayPrecedes(left.allocationGroupIDs, right.allocationGroupIDs)
  }
}

private struct ReleaseComponentUnionFind {
  private var parents: [Int]

  init(count: Int) {
    parents = Array(0..<count)
  }

  mutating func find(_ index: Int) -> Int {
    var root = index
    while parents[root] != root {
      root = parents[root]
    }
    var current = index
    while parents[current] != current {
      let next = parents[current]
      parents[current] = root
      current = next
    }
    return root
  }

  mutating func union(_ lhs: Int, _ rhs: Int) {
    let leftRoot = find(lhs)
    let rightRoot = find(rhs)
    guard leftRoot != rightRoot else { return }
    let lower = min(leftRoot, rightRoot)
    let higher = max(leftRoot, rightRoot)
    parents[higher] = lower
  }
}

private func rawStringArrayPrecedes(_ lhs: [String], _ rhs: [String]) -> Bool {
  lhs.map { Data($0.utf8) }.lexicographicallyPrecedes(rhs.map { Data($0.utf8) }) {
    $0.lexicographicallyPrecedes($1)
  }
}
