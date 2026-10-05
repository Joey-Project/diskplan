import DiskplanPolicy
import Foundation
import Testing

private struct CanonicalEffectVectors: Decodable {
  struct Requirement: Decodable {
    let version: UInt64
    let operation: UInt8
    let permission: UInt8
    let variantGroupIDHex: String
    let targetScopeSHA256Hex: String
    let operationContractSHA256Hex: String
    let canonicalHex: String
    let sha256Hex: String

    enum CodingKeys: String, CodingKey {
      case version
      case operation
      case permission
      case variantGroupIDHex = "variant_group_id_hex"
      case targetScopeSHA256Hex = "target_scope_sha256_hex"
      case operationContractSHA256Hex = "operation_contract_sha256_hex"
      case canonicalHex = "canonical_hex"
      case sha256Hex = "sha256_hex"
    }

  }

  struct Consent: Decodable {
    let version: UInt64
    let permission: UInt8
    let requirementSHA256Hex: String
    let actionIDHex: String
    let actionLineageIDHex: String
    let targetScopeSHA256Hex: String
    let planSHA256Hex: String
    let evidenceSHA256Hex: String
    let policyVersion: String
    let schemaVersion: String
    let consentEventIDHex: String
    let canonicalHex: String
    let sha256Hex: String

    enum CodingKeys: String, CodingKey {
      case version
      case permission
      case requirementSHA256Hex = "requirement_sha256_hex"
      case actionIDHex = "action_id_hex"
      case actionLineageIDHex = "action_lineage_id_hex"
      case targetScopeSHA256Hex = "target_scope_sha256_hex"
      case planSHA256Hex = "plan_sha256_hex"
      case evidenceSHA256Hex = "evidence_sha256_hex"
      case policyVersion = "policy_version"
      case schemaVersion = "schema_version"
      case consentEventIDHex = "consent_event_id_hex"
      case canonicalHex = "canonical_hex"
      case sha256Hex = "sha256_hex"
    }

  }

  let schema: String
  let requirement: Requirement
  let consent: Consent

}

@Test
func actionEffectBindingsMatchFrozenCanonicalGoldenVectors() throws {
  let vectors = try canonicalEffectVectors()
  #expect(vectors.schema == "canonical-effect-v2")

  let requirement = try makeRequirement(vectors.requirement)
  #expect(requirement.version == 2)
  #expect(requirement.operation == .ordinaryRemove)
  #expect(requirement.permission == .localRemoveOnly)
  #expect(requirement.canonicalBytes == (try data(hex: vectors.requirement.canonicalHex)))
  #expect(requirement.digest.hex == vectors.requirement.sha256Hex)
  #expect(
    try ActionEffectRequirementBindingV2(rawCanonicalBytes: requirement.canonicalBytes)
      == requirement
  )

  let consent = try makeConsent(vectors.consent)
  #expect(consent.version == 2)
  #expect(consent.permission == .localRemoveOnly)
  #expect(consent.requirementSHA256 == requirement.digest.bytes)
  #expect(consent.canonicalBytes == (try data(hex: vectors.consent.canonicalHex)))
  #expect(consent.digest.hex == vectors.consent.sha256Hex)
  #expect(try EffectConsentBindingV2(rawCanonicalBytes: consent.canonicalBytes) == consent)
}

@Test
func actionEffectRequirementFieldsChangeTheirDomainDigest() throws {
  let vector = try canonicalEffectVectors().requirement
  let base = try makeRequirement(vector)
  let group = try data(hex: vector.variantGroupIDHex)
  let scope = try data(hex: vector.targetScopeSHA256Hex)
  let contract = try data(hex: vector.operationContractSHA256Hex)
  let changed = [
    try makeRequirement(vector, operation: ActionEffectOperation.providerEvictLocalCopy.rawValue),
    try makeRequirement(vector, permission: ActionEffectPermission.mayDeleteAcrossDevices.rawValue),
    try makeRequirement(vector, variantGroupID: replacingFirstByte(group)),
    try makeRequirement(vector, targetScopeSHA256: replacingFirstByte(scope)),
    try makeRequirement(vector, operationContractSHA256: replacingFirstByte(contract)),
  ]
  #expect(changed.allSatisfy { $0.digest != base.digest })
}

@Test
func actionEffectConsentReferencesChangeTheirDomainDigest() throws {
  let vector = try canonicalEffectVectors().consent
  let base = try makeConsent(vector)
  let requirement = try data(hex: vector.requirementSHA256Hex)
  let action = try data(hex: vector.actionIDHex)
  let lineage = try data(hex: vector.actionLineageIDHex)
  let scope = try data(hex: vector.targetScopeSHA256Hex)
  let plan = try data(hex: vector.planSHA256Hex)
  let evidence = try data(hex: vector.evidenceSHA256Hex)
  let event = try data(hex: vector.consentEventIDHex)
  let changed = [
    try makeConsent(vector, permission: ActionEffectPermission.mayDeleteAcrossDevices.rawValue),
    try makeConsent(vector, requirementSHA256: replacingFirstByte(requirement)),
    try makeConsent(vector, actionID: replacingFirstByte(action)),
    try makeConsent(vector, actionLineageID: replacingFirstByte(lineage)),
    try makeConsent(vector, targetScopeSHA256: replacingFirstByte(scope)),
    try makeConsent(vector, planSHA256: replacingFirstByte(plan)),
    try makeConsent(vector, evidenceSHA256: replacingFirstByte(evidence)),
    try makeConsent(vector, policyVersionUTF8: Data("policy-test-v2".utf8)),
    try makeConsent(vector, schemaVersionUTF8: Data("schema-test-v2".utf8)),
    try makeConsent(vector, consentEventID: replacingFirstByte(event)),
  ]
  #expect(changed.allSatisfy { $0.digest != base.digest })
}

@Test
func actionEffectRequirementRejectsUnknownEnumsVersionsWidthsAndConflicts() throws {
  let vector = try canonicalEffectVectors().requirement
  let base = try makeRequirement(vector)
  let group = try data(hex: vector.variantGroupIDHex)
  let scope = try data(hex: vector.targetScopeSHA256Hex)
  let contract = try data(hex: vector.operationContractSHA256Hex)

  #expect(throws: ActionEffectBindingError.unknownOperation(0)) {
    try makeRequirement(vector, operation: 0)
  }
  #expect(throws: ActionEffectBindingError.unknownOperation(3)) {
    try makeRequirement(vector, operation: 3)
  }
  #expect(throws: ActionEffectBindingError.unknownPermission(0)) {
    try makeRequirement(vector, permission: 0)
  }
  #expect(throws: ActionEffectBindingError.unknownPermission(3)) {
    try makeRequirement(vector, permission: 3)
  }
  #expect(throws: ActionEffectBindingError.unsupportedVersion(1)) {
    try makeRequirement(vector, version: 1)
  }
  for length in [0, 31, 33] {
    #expect(throws: ActionEffectBindingError.invalidVariantGroupLength) {
      try makeRequirement(vector, variantGroupID: Data(repeating: 0, count: length))
    }
  }
  for length in [0, 31, 33] {
    #expect(throws: ActionEffectBindingError.invalidDigestLength(field: "target scope SHA-256")) {
      try makeRequirement(vector, targetScopeSHA256: Data(repeating: 0, count: length))
    }
  }
  for length in [0, 31, 33] {
    #expect(
      throws: ActionEffectBindingError.invalidDigestLength(field: "operation contract SHA-256")
    ) {
      try makeRequirement(vector, operationContractSHA256: Data(repeating: 0, count: length))
    }
  }
  #expect(
    throws: ActionEffectBindingError.invalidOperationPermissionCombination
  ) {
    try ActionEffectRequirementBindingV2(
      rawVersion: 2,
      rawOperation: ActionEffectOperation.providerEvictLocalCopy.rawValue,
      rawPermission: ActionEffectPermission.mayDeleteAcrossDevices.rawValue,
      rawVariantGroupID: group,
      rawTargetScopeSHA256: scope,
      rawOperationContractSHA256: contract
    )
  }
  #expect(base.operation == .ordinaryRemove)
}

@Test
func actionEffectConsentRejectsUnknownEnumsVersionsWidthsTextAndEventLengths() throws {
  let vector = try canonicalEffectVectors().consent
  let requirement = try data(hex: vector.requirementSHA256Hex)
  let action = try data(hex: vector.actionIDHex)
  let lineage = try data(hex: vector.actionLineageIDHex)
  let scope = try data(hex: vector.targetScopeSHA256Hex)
  let plan = try data(hex: vector.planSHA256Hex)
  let evidence = try data(hex: vector.evidenceSHA256Hex)
  let event = try data(hex: vector.consentEventIDHex)

  #expect(throws: ActionEffectBindingError.unknownPermission(0)) {
    try makeConsent(vector, permission: 0)
  }
  #expect(throws: ActionEffectBindingError.unknownPermission(3)) {
    try makeConsent(vector, permission: 3)
  }
  #expect(throws: ActionEffectBindingError.unsupportedVersion(1)) {
    try makeConsent(vector, version: 1)
  }

  let digestInputs: [(String, Data)] = [
    ("requirement SHA-256", requirement),
    ("action ID", action),
    ("action lineage ID", lineage),
    ("target scope SHA-256", scope),
    ("plan SHA-256", plan),
    ("evidence SHA-256", evidence),
  ]
  for (field, bytes) in digestInputs {
    for length in [0, 31, 33] {
      #expect(throws: ActionEffectBindingError.invalidDigestLength(field: field)) {
        try makeConsentVector(vector, replacing: field, with: Data(repeating: 0, count: length))
      }
    }
    #expect(bytes.count == 32)
  }

  #expect(
    throws: ActionEffectBindingError.invalidTextUTF8(field: "policy version")
  ) {
    try makeConsent(vector, policyVersionUTF8: Data([0xff]))
  }
  #expect(
    throws: ActionEffectBindingError.invalidTextUTF8(field: "schema version")
  ) {
    try makeConsent(vector, schemaVersionUTF8: Data([0xff]))
  }
  #expect(
    throws: ActionEffectBindingError.invalidTextLength(field: "policy version")
  ) {
    try makeConsent(vector, policyVersionUTF8: Data())
  }
  #expect(
    throws: ActionEffectBindingError.invalidTextLength(field: "schema version")
  ) {
    try makeConsent(vector, schemaVersionUTF8: Data())
  }
  #expect(
    throws: ActionEffectBindingError.invalidTextLength(field: "policy version")
  ) {
    try makeConsent(vector, policyVersionUTF8: Data(repeating: 0x61, count: 257))
  }
  #expect(
    throws: ActionEffectBindingError.invalidTextLength(field: "schema version")
  ) {
    try makeConsent(vector, schemaVersionUTF8: Data(repeating: 0x61, count: 257))
  }
  #expect(throws: ActionEffectBindingError.invalidConsentEventLength) {
    try makeConsent(vector, consentEventID: Data())
  }
  #expect(throws: ActionEffectBindingError.invalidConsentEventLength) {
    try makeConsent(vector, consentEventID: Data(repeating: 0x61, count: 257))
  }
  #expect(try makeConsent(vector, consentEventID: Data([0xff])).consentEventID == Data([0xff]))
  #expect(event.count > 0)
}

@Test
func actionEffectCanonicalDecodersRejectInvalidTagsLengthsTruncationAndTrailingBytes() throws {
  let vectors = try canonicalEffectVectors()
  let requirement = try makeRequirement(vectors.requirement)
  let consent = try makeConsent(vectors.consent)

  var invalidOperation = requirement.canonicalBytes
  invalidOperation[8] = 0
  #expect(throws: ActionEffectBindingError.unknownOperation(0)) {
    try ActionEffectRequirementBindingV2(rawCanonicalBytes: invalidOperation)
  }
  var invalidPermission = requirement.canonicalBytes
  invalidPermission[9] = 0
  #expect(throws: ActionEffectBindingError.unknownPermission(0)) {
    try ActionEffectRequirementBindingV2(rawCanonicalBytes: invalidPermission)
  }
  var invalidVersion = requirement.canonicalBytes
  invalidVersion[7] = 3
  #expect(throws: ActionEffectBindingError.unsupportedVersion(3)) {
    try ActionEffectRequirementBindingV2(rawCanonicalBytes: invalidVersion)
  }

  #expect(throws: ActionEffectBindingError.truncatedCanonicalBytes) {
    try ActionEffectRequirementBindingV2(rawCanonicalBytes: Data())
  }
  #expect(throws: ActionEffectBindingError.truncatedCanonicalBytes) {
    try ActionEffectRequirementBindingV2(
      rawCanonicalBytes: Data(requirement.canonicalBytes.dropLast())
    )
  }
  var trailingRequirement = requirement.canonicalBytes
  trailingRequirement.append(0)
  #expect(throws: ActionEffectBindingError.trailingCanonicalBytes) {
    try ActionEffectRequirementBindingV2(rawCanonicalBytes: trailingRequirement)
  }
  var trailingConsent = consent.canonicalBytes
  trailingConsent.append(0)
  #expect(throws: ActionEffectBindingError.trailingCanonicalBytes) {
    try EffectConsentBindingV2(rawCanonicalBytes: trailingConsent)
  }
  #expect(throws: ActionEffectBindingError.truncatedCanonicalBytes) {
    try EffectConsentBindingV2(rawCanonicalBytes: Data())
  }

  var impossibleLength = requirement.canonicalBytes
  for index in 10..<18 { impossibleLength[index] = 0xff }
  #expect(throws: ActionEffectBindingError.invalidBlobLength(field: "variant group ID")) {
    try ActionEffectRequirementBindingV2(rawCanonicalBytes: impossibleLength)
  }
  var emptyGroup = requirement.canonicalBytes
  for index in 10..<18 { emptyGroup[index] = 0 }
  #expect(throws: ActionEffectBindingError.invalidBlobLength(field: "variant group ID")) {
    try ActionEffectRequirementBindingV2(rawCanonicalBytes: emptyGroup)
  }
  var emptyPolicy = consent.canonicalBytes
  for index in 249..<257 { emptyPolicy[index] = 0 }
  #expect(throws: ActionEffectBindingError.invalidBlobLength(field: "policy version")) {
    try EffectConsentBindingV2(rawCanonicalBytes: emptyPolicy)
  }
  #expect(throws: ActionEffectBindingError.recordTooLarge) {
    try ActionEffectRequirementBindingV2(rawCanonicalBytes: Data(repeating: 0, count: 4097))
  }
  #expect(throws: ActionEffectBindingError.recordTooLarge) {
    try EffectConsentBindingV2(rawCanonicalBytes: Data(repeating: 0, count: 4097))
  }
}

@Test
func actionEffectVersionStringsPreserveUTF8BytesWithoutNormalization() throws {
  let vector = try canonicalEffectVectors().consent
  let composed = Data("policy-\u{00e9}-v1".utf8)
  let decomposed = Data("policy-e\u{301}-v1".utf8)
  let composedConsent = try makeConsent(vector, policyVersionUTF8: composed)
  let decomposedConsent = try makeConsent(vector, policyVersionUTF8: decomposed)

  #expect(composed != decomposed)
  #expect(composedConsent.policyVersionUTF8 == composed)
  #expect(decomposedConsent.policyVersionUTF8 == decomposed)
  #expect(composedConsent.canonicalBytes != decomposedConsent.canonicalBytes)
  #expect(composedConsent.digest != decomposedConsent.digest)
}

private func canonicalEffectVectors() throws -> CanonicalEffectVectors {
  CanonicalEffectVectors(
    schema: "canonical-effect-v2",
    requirement: .init(
      version: 2,
      operation: 1,
      permission: 1,
      variantGroupIDHex: "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
      targetScopeSHA256Hex: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      operationContractSHA256Hex: [
        "404142434445464748494a4b4c4d4e4f",
        "505152535455565758595a5b5c5d5e5f",
      ].joined(),
      canonicalHex: [
        "00000000000000020101",
        "0000000000000020000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        "0000000000000020202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "0000000000000020404142434445464748494a4b4c4d4e4f505152535455565758595a5b5c5d5e5f",
      ].joined(),
      sha256Hex: "8c4be6db748e64af3949bee715afdedb7a3346199778ec45f832dde425469b36"
    ),
    consent: .init(
      version: 2,
      permission: 1,
      requirementSHA256Hex: "8c4be6db748e64af3949bee715afdedb7a3346199778ec45f832dde425469b36",
      actionIDHex: "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
      actionLineageIDHex: "808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
      targetScopeSHA256Hex: "202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
      planSHA256Hex: "a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
      evidenceSHA256Hex: "c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
      policyVersion: "policy-test-v1",
      schemaVersion: "schema-test-v1",
      consentEventIDHex: "617070726f76652dc3a92d6576656e74",
      canonicalHex: [
        "000000000000000201",
        "00000000000000208c4be6db748e64af3949bee715afdedb7a3346199778ec45f832dde425469b36",
        "0000000000000020606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f",
        "0000000000000020808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f",
        "0000000000000020202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f",
        "0000000000000020a0a1a2a3a4a5a6a7a8a9aaabacadaeafb0b1b2b3b4b5b6b7b8b9babbbcbdbebf",
        "0000000000000020c0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedf",
        "000000000000000e706f6c6963792d746573742d7631",
        "000000000000000e736368656d612d746573742d7631",
        "0000000000000010617070726f76652dc3a92d6576656e74",
      ].joined(),
      sha256Hex: "58c72a09dcf85db1d710317da47913782ea582477d8eb99efd85245aa3127da6"
    )
  )
}

private func makeRequirement(
  _ vector: CanonicalEffectVectors.Requirement,
  version: UInt64? = nil,
  operation: UInt8? = nil,
  permission: UInt8? = nil,
  variantGroupID: Data? = nil,
  targetScopeSHA256: Data? = nil,
  operationContractSHA256: Data? = nil
) throws -> ActionEffectRequirementBindingV2 {
  try ActionEffectRequirementBindingV2(
    rawVersion: version ?? vector.version,
    rawOperation: operation ?? vector.operation,
    rawPermission: permission ?? vector.permission,
    rawVariantGroupID: variantGroupID ?? data(hex: vector.variantGroupIDHex),
    rawTargetScopeSHA256: targetScopeSHA256 ?? data(hex: vector.targetScopeSHA256Hex),
    rawOperationContractSHA256: operationContractSHA256
      ?? data(hex: vector.operationContractSHA256Hex)
  )
}

private func makeConsent(
  _ vector: CanonicalEffectVectors.Consent,
  version: UInt64? = nil,
  permission: UInt8? = nil,
  requirementSHA256: Data? = nil,
  actionID: Data? = nil,
  actionLineageID: Data? = nil,
  targetScopeSHA256: Data? = nil,
  planSHA256: Data? = nil,
  evidenceSHA256: Data? = nil,
  policyVersionUTF8: Data? = nil,
  schemaVersionUTF8: Data? = nil,
  consentEventID: Data? = nil
) throws -> EffectConsentBindingV2 {
  try EffectConsentBindingV2(
    rawVersion: version ?? vector.version,
    rawPermission: permission ?? vector.permission,
    rawRequirementSHA256: requirementSHA256 ?? data(hex: vector.requirementSHA256Hex),
    rawActionID: actionID ?? data(hex: vector.actionIDHex),
    rawActionLineageID: actionLineageID ?? data(hex: vector.actionLineageIDHex),
    rawTargetScopeSHA256: targetScopeSHA256 ?? data(hex: vector.targetScopeSHA256Hex),
    rawPlanSHA256: planSHA256 ?? data(hex: vector.planSHA256Hex),
    rawEvidenceSHA256: evidenceSHA256 ?? data(hex: vector.evidenceSHA256Hex),
    rawPolicyVersionUTF8: policyVersionUTF8 ?? Data(vector.policyVersion.utf8),
    rawSchemaVersionUTF8: schemaVersionUTF8 ?? Data(vector.schemaVersion.utf8),
    rawConsentEventID: consentEventID ?? data(hex: vector.consentEventIDHex)
  )
}

private func makeConsentVector(
  _ vector: CanonicalEffectVectors.Consent,
  replacing field: String,
  with bytes: Data
) throws -> EffectConsentBindingV2 {
  switch field {
  case "requirement SHA-256":
    try makeConsent(vector, requirementSHA256: bytes)
  case "action ID":
    try makeConsent(vector, actionID: bytes)
  case "action lineage ID":
    try makeConsent(vector, actionLineageID: bytes)
  case "target scope SHA-256":
    try makeConsent(vector, targetScopeSHA256: bytes)
  case "plan SHA-256":
    try makeConsent(vector, planSHA256: bytes)
  case "evidence SHA-256":
    try makeConsent(vector, evidenceSHA256: bytes)
  default:
    throw TestFixtureError.unknownField(field)
  }
}

private enum TestFixtureError: Error {
  case malformedHex
  case unknownField(String)
}

private func data(hex: String) throws -> Data {
  guard hex.utf8.count.isMultiple(of: 2) else { throw TestFixtureError.malformedHex }
  var result = Data()
  result.reserveCapacity(hex.utf8.count / 2)
  var highNibble: UInt8?
  for byte in hex.utf8 {
    let value: UInt8
    switch byte {
    case 48...57: value = byte - 48
    case 97...102: value = byte - 97 + 10
    default: throw TestFixtureError.malformedHex
    }
    if let pendingNibble = highNibble {
      result.append((pendingNibble << 4) | value)
      highNibble = nil
    } else {
      highNibble = value
    }
  }
  return result
}

private func replacingFirstByte(_ value: Data) -> Data {
  var result = value
  result[0] ^= 1
  return result
}
