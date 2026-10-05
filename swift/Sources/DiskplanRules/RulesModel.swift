import CryptoKit
import DiskplanPolicy
import Foundation

public enum RulesSchema {
  public static let bundledVersion = "diskplan.rules.v1"
  public static let userPolicyVersion = "diskplan.user-policy.v1"
}

public struct RulesDigest: Equatable, Hashable, Sendable, CustomStringConvertible {
  public let bytes: Data

  fileprivate init(domain: RulesDigestDomain, bindingParts: [Data]) {
    var data = Data(domain.rawValue.utf8)
    for part in bindingParts {
      var count = UInt64(part.count).bigEndian
      withUnsafeBytes(of: &count) { data.append(contentsOf: $0) }
      data.append(part)
    }
    bytes = Data(SHA256.hash(data: data))
  }

  public var description: String { bytes.map { String(format: "%02x", $0) }.joined() }

  static func bundledAsset(schemaVersion: String, canonicalBytes: Data) -> Self {
    Self(
      domain: .bundledAsset,
      bindingParts: [Data(schemaVersion.utf8), canonicalBytes]
    )
  }

  static func userPolicyAsset(schemaVersion: String, canonicalBytes: Data) -> Self {
    Self(
      domain: .userPolicyAsset,
      bindingParts: [Data(schemaVersion.utf8), canonicalBytes]
    )
  }
}

enum RulesDigestDomain: String {
  case bundledAsset = "diskplan/rules-asset/v1\0"
  case userPolicyAsset = "diskplan/user-policy-asset/v1\0"
  case effectiveConfiguration = "diskplan/rules-configuration/v1\0"
  case candidateHint = "diskplan/candidate-hint/v1\0"
  case disclosedMetadata = "diskplan/agent-disclosed-metadata/v1\0"
  case agentInvocation = "diskplan/agent-invocation/v1\0"
  case agentAuthorization = "diskplan/agent-authorization/v1\0"
  case agentCache = "diskplan/agent-cache/v1\0"
}

public enum DeclarativeCandidateKind: String, CaseIterable, Equatable, Sendable {
  case ordinaryCache = "ordinary-cache"
  case buildOutput = "build-output"
  case temporaryData = "temporary-data"
  case managedMaintenance = "managed-maintenance"
}

public enum ManagedActionKind: String, CaseIterable, Equatable, Sendable {
  case fileProvider = "file-provider"
  case apfsSnapshot = "apfs-snapshot"
  case coreSpotlight = "core-spotlight"
  case sqliteVacuum = "sqlite-vacuum"
  case processClose = "process-close"
  case archiveOrMigration = "archive-or-migration"
  case gitGarbageCollection = "git-gc"
  case gitLFSPrune = "git-lfs-prune"
  case packagePrune = "package-prune"
  case containerPrune = "container-prune"
}

public enum CandidateHandling: String, Equatable, Sendable {
  case reportOnly = "report-only"
}

public enum RawMatcher: Equatable, Sendable {
  case rootRelativePrefix([Data])
  case nameExact(Data)
  case nameSuffix(Data)

  func matches(_ components: [Data]) -> Bool {
    switch self {
    case .rootRelativePrefix(let prefix):
      guard components.count >= prefix.count else { return false }
      return zip(prefix, components).allSatisfy { pair in pair.0 == pair.1 }
    case .nameExact(let name):
      return components.last == name
    case .nameSuffix(let suffix):
      guard let name = components.last, name.count >= suffix.count else { return false }
      return name.suffix(suffix.count) == suffix
    }
  }
}

public struct DeclarativeRule: Equatable, Sendable {
  public let id: String
  public let candidateKind: DeclarativeCandidateKind
  public let matcher: RawMatcher
  public let managedAction: ManagedActionKind?
  public let handling: CandidateHandling

}

public struct BundledRuleSet: Equatable, Sendable {
  public let schemaVersion: String
  public let digest: RulesDigest
  public let rules: [DeclarativeRule]

}

public struct CandidateHint: Equatable, Sendable {
  public let recognizerID: String
  public let ruleSetDigest: RulesDigest
  public let candidateKind: DeclarativeCandidateKind
  public let suggestedManagedAction: ManagedActionKind?
  public let handling: CandidateHandling
  public let candidateBinding: RulesDigest

  fileprivate init(
    rule: DeclarativeRule,
    ruleSetDigest: RulesDigest,
    rootBinding: PolicyDigest,
    rawRelativeComponents: [Data]
  ) {
    recognizerID = rule.id
    self.ruleSetDigest = ruleSetDigest
    candidateKind = rule.candidateKind
    suggestedManagedAction = rule.managedAction
    handling = .reportOnly
    candidateBinding = RulesDigest(
      domain: .candidateHint,
      bindingParts: [
        rootBinding.bytes, Data(rule.id.utf8), ruleSetDigest.bytes,
      ] + rawRelativeComponents
    )
  }

  /// Declarative hints never carry recoverability, rebuild, or action-adapter authority.
  public var requiresCandidateSpecificAuthoritativeProvenance: Bool { true }
}

public enum DeclarativeRecognizer {
  public static func recognize(
    ruleSet: BundledRuleSet,
    rootBinding: PolicyDigest,
    rawRelativeComponents: [Data]
  ) -> [CandidateHint] {
    _ = rootBinding
    guard Self.validRawComponents(rawRelativeComponents) else { return [] }
    return ruleSet.rules.compactMap { rule in
      guard rule.matcher.matches(rawRelativeComponents) else { return nil }
      return CandidateHint(
        rule: rule,
        ruleSetDigest: ruleSet.digest,
        rootBinding: rootBinding,
        rawRelativeComponents: rawRelativeComponents
      )
    }
  }

  static func validRawComponents(_ components: [Data]) -> Bool {
    !components.isEmpty && components.count <= 128
      && components.allSatisfy {
        !$0.isEmpty && $0.count <= 255 && !$0.contains(0) && !$0.contains(UInt8(ascii: "/"))
          && $0 != Data(".".utf8) && $0 != Data("..".utf8)
      }
  }
}

public enum AgentMode: String, CaseIterable, Equatable, Sendable {
  case off
  case ask
  case auto
}

public enum AgentMetadataField: String, CaseIterable, Equatable, Hashable, Sendable {
  case rootAlias = "root-alias"
  case relativeNames = "relative-names"
  case counts
  case types
  case sizes
  case timeBuckets = "time-buckets"
  case manifestNames = "manifest-names"
  case gitCounts = "git-counts"
  case failureRules = "failure-rules"
}

public struct AgentPolicy: Equatable, Sendable {
  public let mode: AgentMode
  public let disclosure: [AgentMetadataField]
  public let cacheEnabled: Bool
}

public enum ConfigurableAdapter: String, CaseIterable, Equatable, Sendable {
  case genericRemove = "generic-remove"
  case gitWorktreeRemove = "git-worktree-remove"
  case codexCleanTmp = "codex-clean-tmp"
  case versionedArtifactRemove = "versioned-artifact-remove"
  case completeReleaseSetRemove = "complete-release-set-remove"
}

public enum PolicyProfile: String, CaseIterable, Equatable, Sendable {
  case quick
  case standard
  case deep
  case fullAudit = "full-audit"
}

public struct PolicyBudgets: Equatable, Sendable {
  public let maximumEntriesPerRoot: UInt64
  public let maximumCandidates: UInt64
  public let maximumSharedObjectKeys: UInt64
  public let maximumOwnerReferences: UInt64
  public let maximumRetainedBytes: UInt64
}

public struct PolicyThresholds: Equatable, Sendable {
  public let minimumInactiveSeconds: UInt64
  public let minimumReclaimBytes: UInt64
}

public struct ProtectedRawPath: Equatable, Sendable {
  public let rootBinding: PolicyDigest
  public let components: [Data]

  public func protects(rootBinding: PolicyDigest, rawRelativeComponents: [Data]) -> Bool {
    guard self.rootBinding == rootBinding,
      rawRelativeComponents.count >= components.count
    else { return false }
    return zip(components, rawRelativeComponents).allSatisfy { pair in pair.0 == pair.1 }
  }
}

public struct RestrictedUserPolicy: Equatable, Sendable {
  public let schemaVersion: String
  public let digest: RulesDigest
  public let enabledAdapters: [ConfigurableAdapter]
  public let agent: AgentPolicy
  public let budgets: PolicyBudgets
  public let profile: PolicyProfile
  public let protections: [ProtectedRawPath]
  public let thresholds: PolicyThresholds

  public static var defaultAgentMode: AgentMode { .ask }
}

public struct RulesConfiguration: Equatable, Sendable {
  public let bundled: BundledRuleSet
  public let user: RestrictedUserPolicy
  public let effectiveDigest: RulesDigest

  public init(bundled: BundledRuleSet, user: RestrictedUserPolicy) {
    self.bundled = bundled
    self.user = user
    effectiveDigest = RulesDigest(
      domain: .effectiveConfiguration,
      bindingParts: [
        Data(bundled.schemaVersion.utf8), bundled.digest.bytes,
        Data(user.schemaVersion.utf8), user.digest.bytes,
      ]
    )
  }
}

/// A prepared agent request. Identifiers are metadata only and grant no argv, environment,
/// executable, path, or transport authority to future consumers.
public struct AgentInvocation: Equatable, Sendable {
  public let modelID: String
  public let schemaVersion: String
  public let promptVersion: String
  public let disclosedMetadata: AgentDisclosedMetadata
  public let digest: RulesDigest
  public let authorizationRequirement: AgentAuthorizationRequirement
  private let cacheEnabled: Bool

  public init(
    modelID: String,
    schemaVersion: String,
    promptVersion: String,
    configuration: RulesConfiguration,
    disclosedMetadata: AgentDisclosedMetadata,
    evidenceDigest: PolicyDigest
  ) throws {
    guard configuration.user.agent.mode != .off else { throw AgentBindingError.agentDisabled }
    let profile = Set(configuration.user.agent.disclosure)
    guard disclosedMetadata.fields.allSatisfy({ profile.contains($0) }) else {
      throw AgentBindingError.disclosureNotAllowed
    }
    try Self.validateInvocationIdentifier(modelID, field: .modelID)
    try Self.validateInvocationIdentifier(schemaVersion, field: .schemaVersion)
    try Self.validateInvocationIdentifier(promptVersion, field: .promptVersion)
    self.modelID = modelID
    self.schemaVersion = schemaVersion
    self.promptVersion = promptVersion
    self.disclosedMetadata = disclosedMetadata
    authorizationRequirement =
      configuration.user.agent.mode == .auto ? .automaticPolicy : .userConsent
    cacheEnabled = configuration.user.agent.cacheEnabled
    let canonicalDisclosure = profile.map(\.rawValue).sorted().joined(separator: "\0")
    digest = RulesDigest(
      domain: .agentInvocation,
      bindingParts: [
        Data(modelID.utf8), Data(schemaVersion.utf8), Data(promptVersion.utf8),
        configuration.effectiveDigest.bytes, configuration.user.digest.bytes,
        Data("restricted-user-policy".utf8),
        Data(configuration.user.agent.mode.rawValue.utf8), Data(canonicalDisclosure.utf8),
        disclosedMetadata.digest.bytes, evidenceDigest.bytes,
      ]
    )
  }

  public func cacheLookup() throws -> AgentCacheLookup {
    guard cacheEnabled else { throw AgentBindingError.cacheDisabled }
    let binding = AgentCacheBinding(
      digest: RulesDigest(domain: .agentCache, bindingParts: [digest.bytes]))
    return AgentCacheLookup(invocation: self, binding: binding)
  }

  public func authorizeForAutomaticMode() throws -> AuthorizedAgentInvocation {
    guard authorizationRequirement == .automaticPolicy else {
      throw AgentBindingError.userConsentRequired
    }
    return AuthorizedAgentInvocation(
      invocation: self,
      authorizationDigest: RulesDigest(
        domain: .agentAuthorization,
        bindingParts: [digest.bytes, Data("validated-auto-policy".utf8)]
      )
    )
  }

  private static func validateInvocationIdentifier(
    _ value: String,
    field: AgentInvocationIdentifierField
  ) throws {
    let bytes = Array(value.utf8)
    guard !bytes.isEmpty, bytes.count <= 256,
      bytes.allSatisfy({ Self.isASCIIAlphanumeric($0) || Self.isIdentifierSeparator($0) }),
      Self.validIdentifierStructure(bytes, field: field),
      !CredentialShapeClassifier.containsCredentialLikeSequence(Data(bytes)),
      !CredentialShapeClassifier.containsIdentifierAuthorizationScheme(Data(bytes))
    else {
      throw AgentBindingError.invalidInvocationIdentifier(field: field)
    }
  }

  private static func validIdentifierStructure(
    _ bytes: [UInt8],
    field: AgentInvocationIdentifierField
  ) -> Bool {
    guard
      !zip(bytes, bytes.dropFirst()).contains(where: {
        $0.0 == UInt8(ascii: ".") && $0.1 == UInt8(ascii: ".")
      })
    else { return false }
    let segments = bytes.split(separator: UInt8(ascii: "/"), omittingEmptySubsequences: false)
    guard field == .modelID || segments.count == 1 else { return false }
    return segments.allSatisfy { segment in
      !segment.isEmpty && segment.first.map(Self.isASCIIAlphanumeric) == true
        && segment.last.map(Self.isASCIIAlphanumeric) == true
    }
  }

  private static func isASCIIAlphanumeric(_ byte: UInt8) -> Bool {
    (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte)
      || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte)
      || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
  }

  private static func isIdentifierSeparator(_ byte: UInt8) -> Bool {
    [UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "/"), UInt8(ascii: "-")]
      .contains(byte)
  }
}

public enum AgentInvocationIdentifierField: String, Equatable, Sendable {
  case modelID = "model-id"
  case schemaVersion = "schema-version"
  case promptVersion = "prompt-version"
}

public enum AgentAuthorizationRequirement: String, Equatable, Sendable {
  case automaticPolicy = "automatic-policy"
  case userConsent = "user-consent"
}

/// The only transport-capable agent value. Ask-mode authorization is intentionally unavailable
/// until a user-consent authority can issue a candidate-bound receipt.
public struct AuthorizedAgentInvocation: Equatable, Sendable {
  public let invocation: AgentInvocation
  public let authorizationDigest: RulesDigest

  fileprivate init(invocation: AgentInvocation, authorizationDigest: RulesDigest) {
    self.invocation = invocation
    self.authorizationDigest = authorizationDigest
  }
}

public struct AgentCacheBinding: Equatable, Sendable {
  public let digest: RulesDigest

  fileprivate init(digest: RulesDigest) {
    self.digest = digest
  }
}

/// Couples the exact transport payload and its cache identity in one immutable value.
public struct AgentCacheLookup: Equatable, Sendable {
  public let invocation: AgentInvocation
  public let binding: AgentCacheBinding

  fileprivate init(invocation: AgentInvocation, binding: AgentCacheBinding) {
    self.invocation = invocation
    self.binding = binding
  }
}

public enum AgentBindingError: Error, Equatable, Sendable {
  case invalidMetadata
  case invalidInvocationIdentifier(field: AgentInvocationIdentifierField)
  case agentDisabled
  case cacheDisabled
  case disclosureNotAllowed
  case userConsentRequired
}

public struct AgentNamedCount: Equatable, Sendable {
  fileprivate let name: String
  fileprivate let value: UInt64

  public init(name: String, value: UInt64) throws {
    guard AgentDisclosedField.validToken(name), value <= UInt64(Int64.max) else {
      throw AgentBindingError.invalidMetadata
    }
    self.name = name
    self.value = value
  }
}

public struct AgentDisclosedField: Equatable, Sendable {
  public let field: AgentMetadataField
  fileprivate let canonicalJSONValue: Data

  private init(field: AgentMetadataField, canonicalJSONValue: Data) throws {
    guard canonicalJSONValue.count <= 1_048_576 else {
      throw AgentBindingError.invalidMetadata
    }
    self.field = field
    self.canonicalJSONValue = canonicalJSONValue
  }

  public static func rootAlias(_ value: String) throws -> Self {
    guard validToken(value) else { throw AgentBindingError.invalidMetadata }
    return try Self(field: .rootAlias, canonicalJSONValue: quoted(value))
  }

  public static func relativeNames(_ values: [Data]) throws -> Self {
    try rawNames(field: .relativeNames, values: values)
  }

  public static func counts(_ values: [AgentNamedCount]) throws -> Self {
    try namedCounts(field: .counts, values: values)
  }

  public static func types(_ values: [String]) throws -> Self {
    try tokens(field: .types, values: values)
  }

  public static func sizes(_ values: [UInt64]) throws -> Self {
    try unsignedValues(field: .sizes, values: values)
  }

  public static func timeBuckets(_ values: [String]) throws -> Self {
    try tokens(field: .timeBuckets, values: values)
  }

  public static func manifestNames(_ values: [Data]) throws -> Self {
    try rawNames(field: .manifestNames, values: values)
  }

  public static func gitCounts(_ values: [AgentNamedCount]) throws -> Self {
    try namedCounts(field: .gitCounts, values: values)
  }

  public static func failureRules(_ values: [String]) throws -> Self {
    try tokens(field: .failureRules, values: values)
  }

  fileprivate static func validToken(_ value: String) -> Bool {
    !value.isEmpty && value.utf8.count <= 256
      && !CredentialShapeClassifier.containsCredentialLikeSequence(Data(value.utf8))
      && value.utf8.allSatisfy {
        (UInt8(ascii: "a")...UInt8(ascii: "z")).contains($0)
          || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains($0)
          || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0)
          || [UInt8(ascii: "-"), UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: ":")]
            .contains($0)
      }
  }

  private static func rawNames(field: AgentMetadataField, values: [Data]) throws -> Self {
    guard
      values.count <= 4_096,
      values.allSatisfy({
        !$0.isEmpty && $0.count <= 255 && !$0.contains(0) && !$0.contains(UInt8(ascii: "/"))
          && !CredentialShapeClassifier.containsCredentialLikeSequence($0)
      }), values.elementsAreStrictlyIncreasing
    else { throw AgentBindingError.invalidMetadata }
    try preflightJSONArray(values.map { 2 + 2 * $0.count })
    return try Self(
      field: field,
      canonicalJSONValue: jsonArray(values.map { quoted(hex($0)) })
    )
  }

  private static func tokens(field: AgentMetadataField, values: [String]) throws -> Self {
    guard values.count <= 4_096, values.allSatisfy(Self.validToken),
      values.elementsAreStrictlyIncreasing
    else {
      throw AgentBindingError.invalidMetadata
    }
    try preflightJSONArray(values.map { 2 + $0.utf8.count })
    return try Self(
      field: field,
      canonicalJSONValue: jsonArray(values.map { quoted($0) })
    )
  }

  private static func namedCounts(
    field: AgentMetadataField,
    values: [AgentNamedCount]
  ) throws -> Self {
    guard values.count <= 4_096, values.map(\.name).elementsAreStrictlyIncreasing else {
      throw AgentBindingError.invalidMetadata
    }
    try preflightJSONArray(
      values.map { 20 + $0.name.utf8.count + String($0.value).utf8.count }
    )
    return try Self(
      field: field,
      canonicalJSONValue: jsonArray(
        values.map { value in
          Data("{\"name\":\"\(value.name)\",\"value\":\(value.value)}".utf8)
        }
      )
    )
  }

  private static func unsignedValues(
    field: AgentMetadataField,
    values: [UInt64]
  ) throws -> Self {
    guard values.count <= 4_096, values.allSatisfy({ $0 <= UInt64(Int64.max) }) else {
      throw AgentBindingError.invalidMetadata
    }
    try preflightJSONArray(values.map { String($0).utf8.count })
    return try Self(
      field: field,
      canonicalJSONValue: jsonArray(values.map { Data(String($0).utf8) })
    )
  }

  private static func quoted(_ value: String) -> Data {
    Data("\"\(value)\"".utf8)
  }

  private static func hex(_ value: Data) -> String {
    value.map { String(format: "%02x", $0) }.joined()
  }

  private static func jsonArray(_ values: [Data]) -> Data {
    var data = Data([UInt8(ascii: "[")])
    for (index, value) in values.enumerated() {
      if index != 0 { data.append(UInt8(ascii: ",")) }
      data.append(value)
    }
    data.append(UInt8(ascii: "]"))
    return data
  }

  private static func preflightJSONArray(_ payloadLengths: [Int]) throws {
    var total = 2
    for (index, length) in payloadLengths.enumerated() {
      let (withPayload, payloadOverflow) = total.addingReportingOverflow(length)
      let (withSeparator, separatorOverflow) = withPayload.addingReportingOverflow(
        index == 0 ? 0 : 1)
      guard !payloadOverflow, !separatorOverflow, withSeparator <= 1_048_576 else {
        throw AgentBindingError.invalidMetadata
      }
      total = withSeparator
    }
  }
}

public struct AgentDisclosedMetadata: Equatable, Sendable {
  public let fields: [AgentMetadataField]
  /// The exact canonical JSON bytes that an agent transport is permitted to disclose.
  public let canonicalData: Data
  public let digest: RulesDigest

  public init(_ values: [AgentDisclosedField]) throws {
    guard values.count <= AgentMetadataField.allCases.count,
      values.map({ $0.field.rawValue }).elementsAreStrictlyIncreasing
    else {
      throw AgentBindingError.invalidMetadata
    }
    var totalBytes = 3
    for (index, value) in values.enumerated() {
      let keyBytes = value.field.rawValue.utf8.count + 3
      let separatorBytes = index == 0 ? 0 : 1
      let (withKey, keyOverflow) = totalBytes.addingReportingOverflow(keyBytes)
      let (withValue, valueOverflow) = withKey.addingReportingOverflow(
        value.canonicalJSONValue.count)
      let (withSeparator, separatorOverflow) = withValue.addingReportingOverflow(separatorBytes)
      guard !keyOverflow, !valueOverflow, !separatorOverflow,
        withSeparator <= CanonicalJSONParser.maximumInputBytes
      else { throw AgentBindingError.invalidMetadata }
      totalBytes = withSeparator
    }
    fields = values.map(\.field)
    var document = Data([UInt8(ascii: "{")])
    for (index, value) in values.enumerated() {
      if index != 0 { document.append(UInt8(ascii: ",")) }
      document.append(Data("\"\(value.field.rawValue)\":".utf8))
      document.append(value.canonicalJSONValue)
    }
    document.append(contentsOf: [UInt8(ascii: "}"), UInt8(ascii: "\n")])
    guard document.count <= CanonicalJSONParser.maximumInputBytes else {
      throw AgentBindingError.invalidMetadata
    }
    do {
      var parser = try CanonicalJSONParser(data: document)
      _ = try parser.parse()
    } catch {
      throw AgentBindingError.invalidMetadata
    }
    canonicalData = document
    digest = RulesDigest(domain: .disclosedMetadata, bindingParts: [document])
  }
}

extension Array where Element == Data {
  fileprivate var elementsAreStrictlyIncreasing: Bool {
    zip(self, dropFirst()).allSatisfy { pair in pair.0.lexicographicallyPrecedes(pair.1) }
  }
}

extension Array where Element == String {
  fileprivate var elementsAreStrictlyIncreasing: Bool {
    zip(self, dropFirst()).allSatisfy { pair in pair.0 < pair.1 }
  }
}

public enum AgentAvailability: Equatable, Sendable {
  case available
  case unavailable(reason: String)
}

public struct AgentAssistanceDisposition: Equatable, Sendable {
  public let availability: AgentAvailability
  public let handling: CandidateHandling

  public init(availability: AgentAvailability) {
    self.availability = availability
    handling = .reportOnly
  }
}

public protocol AgentCacheAuthority: Sendable {
  func lookup(_ request: AgentCacheLookup) async -> AgentAssistanceDisposition?
}

public protocol AgentAssistanceTransport: Sendable {
  func request(_ invocation: AuthorizedAgentInvocation) async -> AgentAssistanceDisposition
}
