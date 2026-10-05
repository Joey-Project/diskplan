import DiskplanPolicy
import DiskplanProto
import Foundation
import SwiftProtobuf
import Testing

@testable import DiskplanEngineCore

@Test func runtimeEffectRequirementProjectionRetainsEveryCheckedField() throws {
  let variants: [(ActionEffectOperation, ActionEffectPermission)] = [
    (.ordinaryRemove, .localRemoveOnly),
    (.ordinaryRemove, .mayDeleteAcrossDevices),
    (.providerEvictLocalCopy, .localRemoveOnly),
  ]
  for (operation, permission) in variants {
    let binding = try ActionEffectRequirementBindingV2(
      rawVersion: 2,
      rawOperation: operation.rawValue,
      rawPermission: permission.rawValue,
      rawVariantGroupID: Data(repeating: 0x21, count: 32),
      rawTargetScopeSHA256: Data(repeating: 0x22, count: 32),
      rawOperationContractSHA256: Data(repeating: 0x23, count: 32)
    )
    let projected = RuntimeEffectBindingProjection.requirement(binding)
    let decoded = try Diskplan_V1_ActionEffectRequirementBindingV2(
      serializedBytes: projected.serializedData()
    )
    #expect(decoded.version == 2)
    #expect(decoded.hasOperation && decoded.hasPermission)
    #expect(decoded.operation.rawValue == Int(operation.rawValue))
    #expect(decoded.permission.rawValue == Int(permission.rawValue))
    #expect(decoded.variantGroupID.value == binding.variantGroupID)
    #expect(decoded.targetScopeSha256.value == binding.targetScopeSHA256)
    #expect(decoded.operationContractSha256.value == binding.operationContractSHA256)
    let reconstructed = try ActionEffectRequirementBindingV2(
      rawVersion: UInt64(decoded.version),
      rawOperation: UInt8(decoded.operation.rawValue),
      rawPermission: UInt8(decoded.permission.rawValue),
      rawVariantGroupID: decoded.variantGroupID.value,
      rawTargetScopeSHA256: decoded.targetScopeSha256.value,
      rawOperationContractSHA256: decoded.operationContractSha256.value
    )
    #expect(reconstructed.canonicalBytes == binding.canonicalBytes)
    #expect(reconstructed.digest == binding.digest)
  }
}

@Test func runtimeEffectConsentProjectionRetainsReferencesAndOpaqueEvent() throws {
  for permission in ActionEffectPermission.allCases {
    let binding = try runtimeEffectProjectionFixtureConsent(permission: permission)
    let projected = RuntimeEffectBindingProjection.acknowledgedConsent(binding)
    let acknowledged = try Diskplan_V1_AcknowledgedEffectConsent(
      serializedBytes: projected.serializedData()
    )
    let decoded = acknowledged.binding
    #expect(acknowledged.hasBinding && acknowledged.hasConsentSha256)
    #expect(decoded.version == 2)
    #expect(decoded.hasPermission)
    #expect(decoded.permission.rawValue == Int(permission.rawValue))
    #expect(decoded.requirementSha256.value == binding.requirementSHA256)
    #expect(decoded.actionID.value == binding.actionID)
    #expect(decoded.actionLineageID.value == binding.actionLineageID)
    #expect(decoded.targetScopeSha256.value == binding.targetScopeSHA256)
    #expect(decoded.planSha256.value == binding.planSHA256)
    #expect(decoded.evidenceSha256.value == binding.evidenceSHA256)
    #expect(Data(decoded.policyVersion.utf8) == binding.policyVersionUTF8)
    #expect(Data(decoded.schemaVersion.utf8) == binding.schemaVersionUTF8)
    #expect(decoded.consentEventID == binding.consentEventID)
    #expect(acknowledged.consentSha256.value == binding.digest.bytes)
    let reconstructed = try EffectConsentBindingV2(
      rawVersion: UInt64(decoded.version),
      rawPermission: UInt8(decoded.permission.rawValue),
      rawRequirementSHA256: decoded.requirementSha256.value,
      rawActionID: decoded.actionID.value,
      rawActionLineageID: decoded.actionLineageID.value,
      rawTargetScopeSHA256: decoded.targetScopeSha256.value,
      rawPlanSHA256: decoded.planSha256.value,
      rawEvidenceSHA256: decoded.evidenceSha256.value,
      rawPolicyVersionUTF8: Data(decoded.policyVersion.utf8),
      rawSchemaVersionUTF8: Data(decoded.schemaVersion.utf8),
      rawConsentEventID: decoded.consentEventID
    )
    #expect(reconstructed.canonicalBytes == binding.canonicalBytes)
    #expect(reconstructed.digest.bytes == acknowledged.consentSha256.value)
  }
}

private func runtimeEffectProjectionFixtureConsent(
  permission: ActionEffectPermission
) throws -> EffectConsentBindingV2 {
  try EffectConsentBindingV2(
    rawVersion: 2,
    rawPermission: permission.rawValue,
    rawRequirementSHA256: Data(repeating: 0x31, count: 32),
    rawActionID: Data(repeating: 0x32, count: 32),
    rawActionLineageID: Data(repeating: 0x33, count: 32),
    rawTargetScopeSHA256: Data(repeating: 0x34, count: 32),
    rawPlanSHA256: Data(repeating: 0x35, count: 32),
    rawEvidenceSHA256: Data(repeating: 0x36, count: 32),
    rawPolicyVersionUTF8: Data("policy-e\u{301}".utf8),
    rawSchemaVersionUTF8: Data("schema-v2".utf8),
    rawConsentEventID: Data([0x00, 0xff, 0x2f, 0x45])
  )
}
