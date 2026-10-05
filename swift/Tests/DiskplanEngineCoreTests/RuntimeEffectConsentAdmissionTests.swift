import DiskplanProto
import Foundation
import Testing

@testable import DiskplanEngineCore

@Test func additiveEffectConsentEditRequiresInstalledPermissionConsumer() throws {
  var consent = Diskplan_V1_SetEffectConsentEdit()
  consent.actionID.value = Data(repeating: 0x41, count: 32)
  consent.permission = .localRemoveOnly
  consent.consentEventID = Data("explicit-event".utf8)
  consent.requirementSha256.value = Data(repeating: 0x42, count: 32)
  var edit = Diskplan_V1_DecisionOverlayEdit()
  edit.kind = .setEffectConsent
  edit.edit = .setEffectConsent(consent)

  do {
    try RuntimeOverlayEditor.validateEditSet([edit])
    Issue.record("additive schema must not install a live permission consumer")
  } catch let rejection as RuntimeOverlayEditRejection {
    #expect(rejection.code == .invalidEdit)
    #expect(rejection.summary.contains("live permission consumer"))
  }
}

@Test func additiveEffectConsentEditCannotHideInAnAtomicSelectionBatch() throws {
  var stage = Diskplan_V1_StageActionEdit()
  stage.actionID.value = Data(repeating: 0x41, count: 32)
  var selection = Diskplan_V1_DecisionOverlayEdit()
  selection.kind = .stageAction
  selection.edit = .stageAction(stage)
  var consent = Diskplan_V1_DecisionOverlayEdit()
  consent.kind = .setEffectConsent
  consent.edit = .setEffectConsent(Diskplan_V1_SetEffectConsentEdit())

  do {
    try RuntimeOverlayEditor.validateEditSet([selection, consent])
    Issue.record("unsupported effect edit must reject the entire edit batch")
  } catch let rejection as RuntimeOverlayEditRejection {
    #expect(rejection.code == .invalidEdit)
  }
}

@Test func additiveEffectConsentRejectionsRequireInstalledPermissionConsumer() throws {
  let codes: [Diskplan_V1_DecisionOverlayRejectCode] = [
    .invalidOrMissingEffectConsent, .conflictingEffectVariants,
  ]
  for code in codes {
    var rejection = Diskplan_V1_DecisionOverlayRejected()
    rejection.code = code
    rejection.summary = "effect permission consumer is unavailable"
    #expect(throws: SealedRuntimeWireError.self) {
      try RuntimeBusinessEmission.decisionOverlayRejected(rejection)
    }
  }
}
