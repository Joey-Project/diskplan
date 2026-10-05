import Foundation
import Testing

@testable import DiskplanPolicy

@Test func sharedEffectCanonicalRequirementMatchesSwift() throws {
  let record = try sharedEffectCanonicalRecord("requirement")
  let requirement = try ActionEffectRequirementBindingV2(
    rawCanonicalBytes: sharedEffectFixtureBytes(record, "canonical_hex")
  )
  #expect(requirement.version == 2)
  #expect(requirement.operation == .ordinaryRemove)
  #expect(requirement.permission == .localRemoveOnly)
  #expect(
    requirement.variantGroupID == (try sharedEffectFixtureBytes(record, "variant_group_id_hex")))
  #expect(
    requirement.targetScopeSHA256
      == (try sharedEffectFixtureBytes(record, "target_scope_sha256_hex")))
  #expect(
    requirement.operationContractSHA256
      == (try sharedEffectFixtureBytes(record, "operation_contract_sha256_hex")))
  #expect(requirement.digest.bytes == (try sharedEffectFixtureBytes(record, "sha256_hex")))
}

@Test func sharedEffectCanonicalConsentMatchesSwift() throws {
  let record = try sharedEffectCanonicalRecord("consent")
  let consent = try EffectConsentBindingV2(
    rawCanonicalBytes: sharedEffectFixtureBytes(record, "canonical_hex")
  )
  #expect(consent.version == 2)
  #expect(consent.permission == .localRemoveOnly)
  #expect(
    consent.requirementSHA256 == (try sharedEffectFixtureBytes(record, "requirement_sha256_hex")))
  #expect(consent.actionID == (try sharedEffectFixtureBytes(record, "action_id_hex")))
  #expect(
    consent.actionLineageID == (try sharedEffectFixtureBytes(record, "action_lineage_id_hex")))
  #expect(
    consent.targetScopeSHA256 == (try sharedEffectFixtureBytes(record, "target_scope_sha256_hex")))
  #expect(consent.planSHA256 == (try sharedEffectFixtureBytes(record, "plan_sha256_hex")))
  #expect(consent.evidenceSHA256 == (try sharedEffectFixtureBytes(record, "evidence_sha256_hex")))
  #expect(
    consent.policyVersionUTF8 == Data((try #require(record["policy_version"] as? String)).utf8))
  #expect(
    consent.schemaVersionUTF8 == Data((try #require(record["schema_version"] as? String)).utf8))
  #expect(consent.consentEventID == (try sharedEffectFixtureBytes(record, "consent_event_id_hex")))
  #expect(consent.digest.bytes == (try sharedEffectFixtureBytes(record, "sha256_hex")))
}

private func sharedEffectCanonicalRecord(_ key: String) throws -> [String: Any] {
  var repository = URL(fileURLWithPath: #filePath)
  for _ in 0..<4 { repository.deleteLastPathComponent() }
  let file = repository.appendingPathComponent("proto/fixtures/canonical-effect-v2/fixtures.json")
  let fixture = try #require(
    JSONSerialization.jsonObject(with: Data(contentsOf: file)) as? [String: Any])
  #expect(fixture["schema"] as? String == "canonical-effect-v2")
  return try #require(fixture[key] as? [String: Any])
}

private func sharedEffectFixtureBytes(_ record: [String: Any], _ key: String) throws -> Data {
  let hex = try #require(record[key] as? String)
  let characters = Array(hex.utf8)
  try #require(characters.count.isMultiple(of: 2))
  var bytes = Data()
  for offset in stride(from: 0, to: characters.count, by: 2) {
    let end = min(offset + 2, characters.count)
    let pair = String(decoding: characters[offset..<end], as: UTF8.self)
    bytes.append(try #require(UInt8(pair, radix: 16)))
  }
  return bytes
}
