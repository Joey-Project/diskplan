import CryptoKit
import Foundation

/// Permission bound to one declared action effect.
public enum ActionEffectPermission: UInt8, CaseIterable, Sendable {
  case localRemoveOnly = 1
  case mayDeleteAcrossDevices = 2
}

/// Operation bound to one declared action effect.
public enum ActionEffectOperation: UInt8, CaseIterable, Sendable {
  case ordinaryRemove = 1
  case providerEvictLocalCopy = 2
}

/// Validation failures for untrusted effect-binding records and canonical bytes.
public enum ActionEffectBindingError: Error, Equatable, CustomStringConvertible {
  case unsupportedVersion(UInt64)
  case unknownOperation(UInt8)
  case unknownPermission(UInt8)
  case invalidDigestLength(field: String)
  case invalidVariantGroupLength
  case invalidTextUTF8(field: String)
  case invalidTextLength(field: String)
  case invalidConsentEventLength
  case invalidOperationPermissionCombination
  case recordTooLarge
  case invalidBlobLength(field: String)
  case truncatedCanonicalBytes
  case trailingCanonicalBytes
  case nonCanonicalBytes

  public var description: String {
    switch self {
    case .unsupportedVersion(let version): "unsupported effect-binding version \(version)"
    case .unknownOperation(let raw): "unknown action-effect operation \(raw)"
    case .unknownPermission(let raw): "unknown action-effect permission \(raw)"
    case .invalidDigestLength(let field): "\(field) must contain exactly 32 bytes"
    case .invalidVariantGroupLength: "variant group ID must contain exactly 32 bytes"
    case .invalidTextUTF8(let field): "\(field) is not valid UTF-8"
    case .invalidTextLength(let field): "\(field) must contain 1 through 256 UTF-8 bytes"
    case .invalidConsentEventLength: "consent event ID must contain 1 through 256 bytes"
    case .invalidOperationPermissionCombination:
      "provider eviction requires local-remove-only permission"
    case .recordTooLarge: "effect-binding canonical record exceeds 4096 bytes"
    case .invalidBlobLength(let field): "\(field) has a missing or overlong length"
    case .truncatedCanonicalBytes: "effect-binding canonical record is truncated"
    case .trailingCanonicalBytes: "effect-binding canonical record has trailing bytes"
    case .nonCanonicalBytes: "effect-binding canonical record is not canonical"
    }
  }
}

/// Checked, immutable requirement data from an untrusted transport or model.
/// Constructing this record does not authorize an action; consumers must validate its exact
/// references against the plan and action before treating it as an execution binding.
public struct ActionEffectRequirementBindingV2: Equatable, Sendable {
  public static let currentVersion: UInt64 = 2

  public let version: UInt64
  public let operation: ActionEffectOperation
  public let permission: ActionEffectPermission
  public let variantGroupID: Data
  public let targetScopeSHA256: Data
  public let operationContractSHA256: Data
  public let canonicalBytes: Data
  public let digest: PolicyDigest

  public init(
    rawVersion: UInt64,
    rawOperation: UInt8,
    rawPermission: UInt8,
    rawVariantGroupID: Data,
    rawTargetScopeSHA256: Data,
    rawOperationContractSHA256: Data
  ) throws {
    guard rawVersion == Self.currentVersion else {
      throw ActionEffectBindingError.unsupportedVersion(rawVersion)
    }
    guard let operation = ActionEffectOperation(rawValue: rawOperation) else {
      throw ActionEffectBindingError.unknownOperation(rawOperation)
    }
    guard let permission = ActionEffectPermission(rawValue: rawPermission) else {
      throw ActionEffectBindingError.unknownPermission(rawPermission)
    }
    guard rawVariantGroupID.count == 32 else {
      throw ActionEffectBindingError.invalidVariantGroupLength
    }
    try Self.validateDigest(rawTargetScopeSHA256, field: "target scope SHA-256")
    try Self.validateDigest(rawOperationContractSHA256, field: "operation contract SHA-256")
    guard operation != .providerEvictLocalCopy || permission == .localRemoveOnly else {
      throw ActionEffectBindingError.invalidOperationPermissionCombination
    }

    var writer = ActionEffectCanonicalWriter()
    writer.uint64(rawVersion)
    writer.uint8(rawOperation)
    writer.uint8(rawPermission)
    writer.blob(rawVariantGroupID)
    writer.blob(rawTargetScopeSHA256)
    writer.blob(rawOperationContractSHA256)
    guard writer.bytes.count <= ActionEffectCanonicalCodec.maximumRecordBytes else {
      throw ActionEffectBindingError.recordTooLarge
    }

    self.version = rawVersion
    self.operation = operation
    self.permission = permission
    self.variantGroupID = rawVariantGroupID
    self.targetScopeSHA256 = rawTargetScopeSHA256
    self.operationContractSHA256 = rawOperationContractSHA256
    self.canonicalBytes = writer.bytes
    self.digest = try ActionEffectCanonicalCodec.digest(
      domain: "diskplan/effect-requirement/v2\0",
      canonicalBytes: writer.bytes
    )
  }

  /// Decodes a bounded canonical record supplied by an untrusted transport or model.
  public init(rawCanonicalBytes: Data) throws {
    guard !rawCanonicalBytes.isEmpty else {
      throw ActionEffectBindingError.truncatedCanonicalBytes
    }
    guard rawCanonicalBytes.count <= ActionEffectCanonicalCodec.maximumRecordBytes else {
      throw ActionEffectBindingError.recordTooLarge
    }
    var reader = ActionEffectCanonicalReader(rawCanonicalBytes)
    let version = try reader.uint64()
    let operation = try reader.uint8()
    let permission = try reader.uint8()
    let groupID = try reader.blob(field: "variant group ID", maximumLength: 32)
    let targetScope = try reader.blob(field: "target scope SHA-256", maximumLength: 32)
    let contract = try reader.blob(field: "operation contract SHA-256", maximumLength: 32)
    try reader.finish()

    try self.init(
      rawVersion: version,
      rawOperation: operation,
      rawPermission: permission,
      rawVariantGroupID: groupID,
      rawTargetScopeSHA256: targetScope,
      rawOperationContractSHA256: contract
    )
    guard canonicalBytes == rawCanonicalBytes else {
      throw ActionEffectBindingError.nonCanonicalBytes
    }
  }

  private static func validateDigest(_ bytes: Data, field: String) throws {
    guard bytes.count == 32 else {
      throw ActionEffectBindingError.invalidDigestLength(field: field)
    }
  }
}

/// Checked, immutable consent data from an untrusted transport or model.
/// It is not an authorization token: consumers must bind every field to the validated plan,
/// selected action, requirement, and exact supported policy/schema versions.
public struct EffectConsentBindingV2: Equatable, Sendable {
  public static let currentVersion: UInt64 = 2

  public let version: UInt64
  public let permission: ActionEffectPermission
  public let requirementSHA256: Data
  public let actionID: Data
  public let actionLineageID: Data
  public let targetScopeSHA256: Data
  public let planSHA256: Data
  public let evidenceSHA256: Data
  public let policyVersionUTF8: Data
  public let schemaVersionUTF8: Data
  /// Opaque event identifier bytes. It is not interpreted as text.
  public let consentEventID: Data
  public let canonicalBytes: Data
  public let digest: PolicyDigest

  public init(
    rawVersion: UInt64,
    rawPermission: UInt8,
    rawRequirementSHA256: Data,
    rawActionID: Data,
    rawActionLineageID: Data,
    rawTargetScopeSHA256: Data,
    rawPlanSHA256: Data,
    rawEvidenceSHA256: Data,
    rawPolicyVersionUTF8: Data,
    rawSchemaVersionUTF8: Data,
    rawConsentEventID: Data
  ) throws {
    guard rawVersion == Self.currentVersion else {
      throw ActionEffectBindingError.unsupportedVersion(rawVersion)
    }
    guard let permission = ActionEffectPermission(rawValue: rawPermission) else {
      throw ActionEffectBindingError.unknownPermission(rawPermission)
    }
    try Self.validateDigest(rawRequirementSHA256, field: "requirement SHA-256")
    try Self.validateDigest(rawActionID, field: "action ID")
    try Self.validateDigest(rawActionLineageID, field: "action lineage ID")
    try Self.validateDigest(rawTargetScopeSHA256, field: "target scope SHA-256")
    try Self.validateDigest(rawPlanSHA256, field: "plan SHA-256")
    try Self.validateDigest(rawEvidenceSHA256, field: "evidence SHA-256")
    try Self.validateVersionText(rawPolicyVersionUTF8, field: "policy version")
    try Self.validateVersionText(rawSchemaVersionUTF8, field: "schema version")
    guard (1...256).contains(rawConsentEventID.count) else {
      throw ActionEffectBindingError.invalidConsentEventLength
    }

    var writer = ActionEffectCanonicalWriter()
    writer.uint64(rawVersion)
    writer.uint8(rawPermission)
    writer.blob(rawRequirementSHA256)
    writer.blob(rawActionID)
    writer.blob(rawActionLineageID)
    writer.blob(rawTargetScopeSHA256)
    writer.blob(rawPlanSHA256)
    writer.blob(rawEvidenceSHA256)
    writer.blob(rawPolicyVersionUTF8)
    writer.blob(rawSchemaVersionUTF8)
    writer.blob(rawConsentEventID)
    guard writer.bytes.count <= ActionEffectCanonicalCodec.maximumRecordBytes else {
      throw ActionEffectBindingError.recordTooLarge
    }

    self.version = rawVersion
    self.permission = permission
    self.requirementSHA256 = rawRequirementSHA256
    self.actionID = rawActionID
    self.actionLineageID = rawActionLineageID
    self.targetScopeSHA256 = rawTargetScopeSHA256
    self.planSHA256 = rawPlanSHA256
    self.evidenceSHA256 = rawEvidenceSHA256
    self.policyVersionUTF8 = rawPolicyVersionUTF8
    self.schemaVersionUTF8 = rawSchemaVersionUTF8
    self.consentEventID = rawConsentEventID
    self.canonicalBytes = writer.bytes
    self.digest = try ActionEffectCanonicalCodec.digest(
      domain: "diskplan/effect-consent/v2\0",
      canonicalBytes: writer.bytes
    )
  }

  /// Decodes a bounded canonical record supplied by an untrusted transport or model.
  public init(rawCanonicalBytes: Data) throws {
    guard !rawCanonicalBytes.isEmpty else {
      throw ActionEffectBindingError.truncatedCanonicalBytes
    }
    guard rawCanonicalBytes.count <= ActionEffectCanonicalCodec.maximumRecordBytes else {
      throw ActionEffectBindingError.recordTooLarge
    }
    var reader = ActionEffectCanonicalReader(rawCanonicalBytes)
    let version = try reader.uint64()
    let permission = try reader.uint8()
    let requirement = try reader.blob(field: "requirement SHA-256", maximumLength: 32)
    let action = try reader.blob(field: "action ID", maximumLength: 32)
    let lineage = try reader.blob(field: "action lineage ID", maximumLength: 32)
    let targetScope = try reader.blob(field: "target scope SHA-256", maximumLength: 32)
    let plan = try reader.blob(field: "plan SHA-256", maximumLength: 32)
    let evidence = try reader.blob(field: "evidence SHA-256", maximumLength: 32)
    let policy = try reader.blob(field: "policy version", maximumLength: 256)
    let schema = try reader.blob(field: "schema version", maximumLength: 256)
    let event = try reader.blob(field: "consent event ID", maximumLength: 256)
    try reader.finish()

    try self.init(
      rawVersion: version,
      rawPermission: permission,
      rawRequirementSHA256: requirement,
      rawActionID: action,
      rawActionLineageID: lineage,
      rawTargetScopeSHA256: targetScope,
      rawPlanSHA256: plan,
      rawEvidenceSHA256: evidence,
      rawPolicyVersionUTF8: policy,
      rawSchemaVersionUTF8: schema,
      rawConsentEventID: event
    )
    guard canonicalBytes == rawCanonicalBytes else {
      throw ActionEffectBindingError.nonCanonicalBytes
    }
  }

  private static func validateDigest(_ bytes: Data, field: String) throws {
    guard bytes.count == 32 else {
      throw ActionEffectBindingError.invalidDigestLength(field: field)
    }
  }

  private static func validateVersionText(_ bytes: Data, field: String) throws {
    guard (1...256).contains(bytes.count) else {
      throw ActionEffectBindingError.invalidTextLength(field: field)
    }
    guard String(data: bytes, encoding: .utf8) != nil else {
      throw ActionEffectBindingError.invalidTextUTF8(field: field)
    }
  }
}

private enum ActionEffectCanonicalCodec {
  static let maximumRecordBytes = 4096

  static func digest(domain: String, canonicalBytes: Data) throws -> PolicyDigest {
    var input = Data(domain.utf8)
    input.append(canonicalBytes)
    return try PolicyDigest(bytes: Data(SHA256.hash(data: input)))
  }
}

private struct ActionEffectCanonicalWriter {
  var bytes = Data()

  mutating func uint8(_ value: UInt8) {
    bytes.append(value)
  }

  mutating func uint64(_ value: UInt64) {
    for shift in stride(from: 56, through: 0, by: -8) {
      bytes.append(UInt8(truncatingIfNeeded: value >> shift))
    }
  }

  mutating func blob(_ value: Data) {
    uint64(UInt64(value.count))
    bytes.append(value)
  }
}

private struct ActionEffectCanonicalReader {
  private let bytes: [UInt8]
  private var offset = 0

  init(_ data: Data) {
    // The public decoder checks the 4096-byte ceiling before this bounded copy.
    bytes = Array(data)
  }

  mutating func uint8() throws -> UInt8 {
    guard offset < bytes.count else {
      throw ActionEffectBindingError.truncatedCanonicalBytes
    }
    defer { offset += 1 }
    return bytes[offset]
  }

  mutating func uint64() throws -> UInt64 {
    guard offset <= bytes.count, bytes.count - offset >= 8 else {
      throw ActionEffectBindingError.truncatedCanonicalBytes
    }
    var value: UInt64 = 0
    for _ in 0..<8 {
      value = (value << 8) | UInt64(bytes[offset])
      offset += 1
    }
    return value
  }

  mutating func blob(field: String, maximumLength: Int) throws -> Data {
    let declaredLength = try uint64()
    guard let length = Int(exactly: declaredLength), length > 0, length <= maximumLength else {
      throw ActionEffectBindingError.invalidBlobLength(field: field)
    }
    guard offset <= bytes.count, length <= bytes.count - offset else {
      throw ActionEffectBindingError.truncatedCanonicalBytes
    }
    let result = Data(bytes[offset..<(offset + length)])
    offset += length
    return result
  }

  mutating func finish() throws {
    guard offset == bytes.count else {
      throw ActionEffectBindingError.trailingCanonicalBytes
    }
  }
}
