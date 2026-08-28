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

  var bindingBytes: Data {
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

public enum AdapterScopeEvidence: Equatable, Sendable {
  case genericRemove
  case gitWorktreeRemove
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
  public let collectorStatus: Observation<String>
  public let activity: Observation<String>
  public let providerState: Observation<ProviderState>
  public let recoverability: Observation<String>
  public let dependencyState: Observation<String>
  public let accessPolicy: Observation<String>
  public let contentProtection: Observation<ContentProtectionBaseline>
  public let aclDigest: Observation<PolicyDigest>
  public let targetMountIdentity: Observation<String>
  public let removalForceRequirement: Observation<ForceRequirement>
  public let quarantineCapability: Observation<Bool>
  public let adapterScope: AdapterScopeEvidence
  public let policyVotes: [GateVote]
  public let classificationClaims: [ClassificationClaim]
  public let semanticReferenceTimeSeconds: Int64
  public let policyVersion: String
  public let schemaVersion: String

  public init(
    captureID: PolicyDigest,
    globalFactsHash: PolicyDigest,
    candidateID: String,
    namespaceBinding: ProtectedNamespaceBinding,
    identity: Observation<ObjectIdentity>,
    coverage: EvidenceCoverage,
    collectorStatus: Observation<String>,
    activity: Observation<String>,
    providerState: Observation<ProviderState>,
    recoverability: Observation<String>,
    dependencyState: Observation<String>,
    accessPolicy: Observation<String>,
    contentProtection: Observation<ContentProtectionBaseline>,
    aclDigest: Observation<PolicyDigest>,
    targetMountIdentity: Observation<String>,
    removalForceRequirement: Observation<ForceRequirement>,
    quarantineCapability: Observation<Bool>,
    adapterScope: AdapterScopeEvidence,
    policyVotes: [GateVote],
    classificationClaims: [ClassificationClaim],
    semanticReferenceTimeSeconds: Int64,
    policyVersion: String,
    schemaVersion: String
  ) {
    self.captureID = captureID
    self.globalFactsHash = globalFactsHash
    self.candidateID = candidateID
    self.namespaceBinding = namespaceBinding
    self.identity = identity
    self.coverage = coverage
    self.collectorStatus = collectorStatus
    self.activity = activity
    self.providerState = providerState
    self.recoverability = recoverability
    self.dependencyState = dependencyState
    self.accessPolicy = accessPolicy
    self.contentProtection = contentProtection
    self.aclDigest = aclDigest
    self.targetMountIdentity = targetMountIdentity
    self.removalForceRequirement = removalForceRequirement
    self.quarantineCapability = quarantineCapability
    self.adapterScope = adapterScope
    self.policyVotes = policyVotes.sorted { $0.dimension < $1.dimension }
    self.classificationClaims = classificationClaims.sorted {
      $0.bindingBytes.lexicographicallyPrecedes($1.bindingBytes)
    }
    self.semanticReferenceTimeSeconds = semanticReferenceTimeSeconds
    self.policyVersion = policyVersion
    self.schemaVersion = schemaVersion
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
    encoder.observation(collectorStatus) { $0.string($1) }
    encoder.observation(activity) { $0.string($1) }
    encoder.observation(providerState) { $0.string($1.rawValue) }
    encoder.observation(recoverability) { $0.string($1) }
    encoder.observation(dependencyState) { $0.string($1) }
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
    encodeAdapterScopeEvidence(adapterScope, into: &encoder)
    encoder.array(policyVotes) { vote in
      var nested = PolicyBindingEncoder()
      nested.uint8(vote.dimension.rawValue)
      ActionDefinition.encodeGateResult(vote.result, into: &nested)
      return nested.data
    }
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
  case worktreeQuarantinedThenAbsent
  case cleanupScopeAbsent(String)
  case artifactVersionAbsent(kind: String, version: String)
  case allocationGroupReleased(String)
}

public enum TrustedNamespace: String, Equatable, Sendable {
  case ownerPrivate
  case explicitlyTrustedUserNamespace
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
  fileprivate init() { quarantineRequired = true }
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

public struct CompleteReleaseSetRemoveContract: Equatable, Sendable {
  public let allocationGroupID: String
  fileprivate init(allocationGroupID: String) { self.allocationGroupID = allocationGroupID }
}

public enum ActionAdapterRequest: Equatable, Sendable {
  case genericRemove
  case gitWorktreeRemove
  case codexCleanTemporary(cleanupScopeID: String)
  case versionedArtifactRemove(artifactKind: String, version: String)
  case completeReleaseSetRemove(allocationGroupID: String)
}

public enum ActionAdapterContract: Equatable, Sendable {
  case genericRemove(GenericRemoveContract)
  case gitWorktreeRemove(GitWorktreeRemoveContract)
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
      case .known(let contentBaseline) = evidence.contentProtection,
      case .known(let accessPolicy) = evidence.accessPolicy,
      case .known(let aclDigest) = evidence.aclDigest,
      case .known(let providerState) = evidence.providerState,
      case .known(let mountIdentity) = evidence.targetMountIdentity
    else { throw PolicyModelError.actionEvidenceMismatch }

    let adapter: ActionAdapterContract
    let postcondition: ActionPostcondition
    switch request {
    case .genericRemove:
      guard evidence.adapterScope == .genericRemove,
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
      guard evidence.adapterScope == .gitWorktreeRemove, identity.type == .directory,
        evidence.quarantineCapability == .known(true)
      else {
        throw PolicyModelError.invalidActionContract
      }
      adapter = .gitWorktreeRemove(GitWorktreeRemoveContract())
      postcondition = .worktreeQuarantinedThenAbsent
    case .codexCleanTemporary(let cleanupScopeID):
      guard hasNonWhitespace(cleanupScopeID),
        adapterScopeMatches(
          evidence.adapterScope, .codexCleanTemporary(cleanupScopeID: cleanupScopeID))
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
        adapterScopeMatches(
          evidence.adapterScope,
          .versionedArtifactRemove(artifactKind: artifactKind, version: version)
        )
      else { throw PolicyModelError.invalidActionContract }
      adapter = .versionedArtifactRemove(
        VersionedArtifactRemoveContract(artifactKind: artifactKind, version: version)
      )
      postcondition = .artifactVersionAbsent(kind: artifactKind, version: version)
    case .completeReleaseSetRemove(let allocationGroupID):
      guard hasNonWhitespace(allocationGroupID),
        adapterScopeMatches(
          evidence.adapterScope,
          .completeReleaseSetRemove(allocationGroupID: allocationGroupID))
      else {
        throw PolicyModelError.invalidActionContract
      }
      adapter = .completeReleaseSetRemove(
        CompleteReleaseSetRemoveContract(allocationGroupID: allocationGroupID)
      )
      postcondition = .allocationGroupReleased(allocationGroupID)
    }
    return Self(
      policyVersion: evidence.policyVersion,
      schemaVersion: evidence.schemaVersion,
      adapterContract: adapter,
      targetIdentity: identity,
      namespaceBinding: evidence.namespaceBinding,
      protectedProperties: ProtectedPropertyContracts(
        identity: IdentityProtectionContract(expectedIdentity: identity),
        content: ContentProtectionContract(expectedBaseline: contentBaseline),
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
    return make(
      prototype: prototype,
      evidence: evidence,
      globalFactsHash: globalFacts.globalFactsHash,
      prerequisiteLineageIDs: Array(Set(prerequisites.map(\.lineageID))).sorted(),
      prerequisiteActionIDs: Array(Set(prerequisites.map(\.id))).sorted(),
      evaluation: evaluation,
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
      evidence.contentProtection
        == .known(prototype.protectedProperties.content.expectedBaseline),
      accessPolicyBaselineMatches(
        prototype.protectedProperties.accessPolicy.requiredBaseline, evidence: evidence),
      rawStringEqual(globalFacts.policyVersion, evidence.policyVersion),
      rawStringEqual(globalFacts.schemaVersion, evidence.schemaVersion),
      globalFacts.semanticReferenceTimeSeconds == evidence.semanticReferenceTimeSeconds
        && evidence.captureID == globalFacts.captureID
        && evidence.globalFactsHash == globalFacts.globalFactsHash
    else { throw PolicyModelError.actionEvidenceMismatch }
    guard let source = evaluation.sourceBinding,
      source.captureID == evidence.captureID,
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
      guard evidence.adapterScope == .genericRemove,
        contract.removalPathSlot == .prototypeRawTargetPath,
        contract.targetKind == identity.type,
        contract.pathRaceResidual,
        contract.trustedNamespace == evidence.namespaceBinding.trustedNamespace,
        evidence.removalForceRequirement == .known(contract.forceRequirement),
        prototype.postcondition == .targetAbsent
      else { throw PolicyModelError.invalidActionContract }
    case .gitWorktreeRemove(let contract):
      guard evidence.adapterScope == .gitWorktreeRemove, contract.quarantineRequired,
        identity.type == .directory,
        evidence.quarantineCapability == .known(true),
        prototype.postcondition == .worktreeQuarantinedThenAbsent
      else { throw PolicyModelError.invalidActionContract }
    case .codexCleanTemporary(let contract):
      guard hasNonWhitespace(contract.cleanupScopeID),
        adapterScopeMatches(
          evidence.adapterScope,
          .codexCleanTemporary(cleanupScopeID: contract.cleanupScopeID)),
        postconditionMatches(
          prototype.postcondition, .cleanupScopeAbsent(contract.cleanupScopeID))
      else { throw PolicyModelError.invalidActionContract }
    case .versionedArtifactRemove(let contract):
      guard hasNonWhitespace(contract.artifactKind), hasNonWhitespace(contract.version),
        adapterScopeMatches(
          evidence.adapterScope,
          .versionedArtifactRemove(
            artifactKind: contract.artifactKind, version: contract.version)),
        postconditionMatches(
          prototype.postcondition,
          .artifactVersionAbsent(kind: contract.artifactKind, version: contract.version))
      else { throw PolicyModelError.invalidActionContract }
    case .completeReleaseSetRemove(let contract):
      guard hasNonWhitespace(contract.allocationGroupID),
        adapterScopeMatches(
          evidence.adapterScope,
          .completeReleaseSetRemove(allocationGroupID: contract.allocationGroupID)),
        postconditionMatches(
          prototype.postcondition, .allocationGroupReleased(contract.allocationGroupID))
      else { throw PolicyModelError.invalidActionContract }
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
    let lineage = ActionLineageID(
      digest: PolicyBindings.digest(kind: "action-lineage") { encoder in
        encodePrototype(prototype, into: &encoder)
        encoder.array(prerequisiteLineageIDs) { $0.digest.bytes }
      }
    )
    let action = ActionID(
      digest: PolicyBindings.digest(kind: "action") { encoder in
        encoder.data(lineage.digest.bytes)
        encoder.data(evidence.evidenceID.bytes)
        encoder.data(globalFactsHash.bytes)
        encoder.array(prerequisiteActionIDs) { $0.digest.bytes }
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
    case .codexCleanTemporary(let contract):
      encoder.uint8(2)
      encoder.string(contract.cleanupScopeID)
    case .versionedArtifactRemove(let contract):
      encoder.uint8(3)
      encoder.string(contract.artifactKind)
      encoder.string(contract.version)
    case .completeReleaseSetRemove(let contract):
      encoder.uint8(4)
      encoder.string(contract.allocationGroupID)
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
    case .worktreeQuarantinedThenAbsent:
      encoder.uint8(1)
    case .cleanupScopeAbsent(let scope):
      encoder.uint8(2)
      encoder.string(scope)
    case .artifactVersionAbsent(let kind, let version):
      encoder.uint8(3)
      encoder.string(kind)
      encoder.string(version)
    case .allocationGroupReleased(let group):
      encoder.uint8(4)
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
    if let source = evaluation.sourceBinding {
      encoder.bool(true)
      encoder.data(source.captureID.bytes)
      encoder.data(source.evidenceID.bytes)
      encoder.data(source.globalFactsHash.bytes)
      encoder.data(source.classificationResolutionHash.bytes)
      encoder.string(source.policyVersion)
      encoder.string(source.schemaVersion)
      encoder.int64(source.semanticReferenceTimeSeconds)
    } else {
      encoder.bool(false)
    }
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
  ) throws -> [Self] {
    guard evaluation.blockers.isEmpty,
      case .known(let immediateBytes) = evaluation.immediatePrivateReclaimBytes,
      case .known(let conditionalBytes) = evaluation.conditionalGroupReclaimBytes,
      evaluation.releaseSets.allSatisfy({
        $0.isComplete && $0.graphDigest == evaluation.graphDigest
      })
    else { throw PolicyModelError.incompleteReleaseGraph }
    guard !immediateBytes.addingReportingOverflow(conditionalBytes).overflow else {
      throw PolicyModelError.incompleteReleaseGraph
    }

    let candidateActionKeys = candidateActions.map { Data($0.candidateID.utf8) }
    guard Set(candidateActionKeys).count == candidateActions.count else {
      throw PolicyModelError.duplicateIdentifier
    }
    let actionByCandidateID = Dictionary(
      uniqueKeysWithValues: zip(candidateActionKeys, candidateActions.map(\.action))
    )
    return try evaluation.releaseSets.map { evaluated in
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
  }

  private static func actionReleasesOwner(
    _ action: ActionDefinition,
    allocationGroupID: String
  ) -> Bool {
    switch action.prototype.postcondition {
    case .targetAbsent:
      adapterScopeMatches(action.evidence.adapterScope, .genericRemove)
    case .worktreeQuarantinedThenAbsent:
      adapterScopeMatches(action.evidence.adapterScope, .gitWorktreeRemove)
    case .cleanupScopeAbsent(let cleanupScopeID):
      adapterScopeMatches(
        action.evidence.adapterScope,
        .codexCleanTemporary(cleanupScopeID: cleanupScopeID))
    case .artifactVersionAbsent(let artifactKind, let version):
      adapterScopeMatches(
        action.evidence.adapterScope,
        .versionedArtifactRemove(artifactKind: artifactKind, version: version))
    case .allocationGroupReleased(let boundGroupID):
      rawStringEqual(boundGroupID, allocationGroupID)
    }
  }
}

public struct ImmutablePlan: Equatable, Sendable {
  public let policyVersion: String
  public let schemaVersion: String
  public let globalFacts: FrozenGlobalFacts
  public let evidenceSnapshots: [FrozenEvidenceSnapshot]
  public let evidenceHash: PolicyDigest
  public let actions: [ActionDefinition]
  public let releaseSets: [PlanReleaseSet]
  public let releaseGraphDigest: PolicyDigest?
  public let planHash: PolicyDigest

  public init(
    policyVersion: String,
    schemaVersion: String,
    globalFacts: FrozenGlobalFacts,
    evidenceSnapshots: [FrozenEvidenceSnapshot],
    actions: [ActionDefinition],
    releaseSets: [PlanReleaseSet]
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
      guard action.prerequisiteLineageIDs == expectedLineages,
        action == action.recomputed
      else { throw PolicyModelError.invalidActionBinding(action.id) }
    }

    let canonicalReleaseSets = releaseSets.sorted {
      rawStringPrecedes($0.allocationGroupID, $1.allocationGroupID)
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
    self.policyVersion = policyVersion
    self.schemaVersion = schemaVersion
    self.globalFacts = globalFacts
    self.evidenceSnapshots = evidence
    self.evidenceHash = evidenceHash
    self.actions = canonicalActions
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
    var ready = indegree.filter { $0.value == 0 }.map(\.key).sorted()
    var visited = 0
    while let next = ready.first {
      ready.removeFirst()
      visited += 1
      for dependent in (dependents[next] ?? []).sorted() {
        indegree[dependent, default: 0] -= 1
        if indegree[dependent] == 0 {
          ready.append(dependent)
          ready.sort()
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
      nested.observation(file.linkCount) { $0.uint64(UInt64($1)) }
      return nested.data
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

public struct ValidatedDecisionOverlay: Equatable, Sendable {
  public let selectedActions: [ActionDefinition]
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
    let selectedActions = try selectedIDs.map { id -> ActionDefinition in
      guard let action = actionByID[id] else { throw PolicyModelError.injectedSelection(id) }
      return action
    }.sorted { $0.id < $1.id }

    let actionsByLineage = Dictionary(grouping: selectedActions, by: \.lineageID)
    for (lineage, actions) in actionsByLineage where actions.count != 1 {
      throw PolicyModelError.ambiguousSelectedLineage(lineage)
    }
    var consentByActionAndPredicate: [ActionID: [WaiverPredicate: WaiverConsentCore]] = [:]
    var epochRequirements: [WaiverEpochRequirement] = []
    for consent in overlay.waiverConsents {
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
      for predicate in provided.keys where !requiredPredicates.contains(predicate) {
        throw PolicyModelError.unexpectedWaiver(action.id, predicate.kind)
      }
    }

    let activated = plan.releaseSets.filter { releaseSet in
      Set(releaseSet.ownerActionIDs).isSubset(of: selectedIDs)
    }
    return ValidatedDecisionOverlay(
      selectedActions: selectedActions,
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
  case .gitWorktreeRemove:
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

private func adapterScopeMatches(
  _ lhs: AdapterScopeEvidence,
  _ rhs: AdapterScopeEvidence
) -> Bool {
  switch (lhs, rhs) {
  case (.genericRemove, .genericRemove), (.gitWorktreeRemove, .gitWorktreeRemove):
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

private func rawStringArrayPrecedes(_ lhs: [String], _ rhs: [String]) -> Bool {
  lhs.map { Data($0.utf8) }.lexicographicallyPrecedes(rhs.map { Data($0.utf8) }) {
    $0.lexicographicallyPrecedes($1)
  }
}
