import DiskplanPolicy
import DiskplanProto
import Foundation

/// Transport projection only. Checked raw records still require exact plan/action
/// reference admission and live execution credentials at their production consumer.
enum RuntimeEffectBindingProjection {
  static func requirement(
    _ binding: ActionEffectRequirementBindingV2
  ) -> Diskplan_V1_ActionEffectRequirementBindingV2 {
    var projection = Diskplan_V1_ActionEffectRequirementBindingV2()
    projection.version = UInt32(binding.version)
    switch binding.operation {
    case .ordinaryRemove: projection.operation = .ordinaryRemove
    case .providerEvictLocalCopy: projection.operation = .providerEvictLocalCopy
    }
    projection.permission = permission(binding.permission)
    projection.variantGroupID.value = binding.variantGroupID
    projection.targetScopeSha256.value = binding.targetScopeSHA256
    projection.operationContractSha256.value = binding.operationContractSHA256
    return projection
  }

  static func acknowledgedConsent(
    _ binding: EffectConsentBindingV2
  ) -> Diskplan_V1_AcknowledgedEffectConsent {
    var projection = Diskplan_V1_EffectConsentBindingV2()
    projection.version = UInt32(binding.version)
    projection.permission = permission(binding.permission)
    projection.requirementSha256.value = binding.requirementSHA256
    projection.actionID.value = binding.actionID
    projection.actionLineageID.value = binding.actionLineageID
    projection.targetScopeSha256.value = binding.targetScopeSHA256
    projection.planSha256.value = binding.planSHA256
    projection.evidenceSha256.value = binding.evidenceSHA256
    projection.policyVersion = String(decoding: binding.policyVersionUTF8, as: UTF8.self)
    projection.schemaVersion = String(decoding: binding.schemaVersionUTF8, as: UTF8.self)
    projection.consentEventID = binding.consentEventID
    var acknowledged = Diskplan_V1_AcknowledgedEffectConsent()
    acknowledged.binding = projection
    acknowledged.consentSha256.value = binding.digest.bytes
    return acknowledged
  }

  static func permission(
    _ permission: ActionEffectPermission
  ) -> Diskplan_V1_ActionEffectPermission {
    switch permission {
    case .localRemoveOnly: .localRemoveOnly
    case .mayDeleteAcrossDevices: .mayDeleteAcrossDevices
    }
  }
}
