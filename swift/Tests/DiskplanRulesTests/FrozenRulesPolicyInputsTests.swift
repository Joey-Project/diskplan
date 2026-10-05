import DiskplanPolicy
import Foundation
import Testing

@testable import DiskplanRules

@Test
func frozenRulesPolicyInputsDistinguishNoneFromExplicitDefaultOverlay() throws {
  let noOverlay = FrozenRulesPolicyInputs()
  let sourceIdentity = try FrozenRulesPolicySourceIdentity(rawBytes: Data("/policy/user.json".utf8))
  let explicitDefault = FrozenRulesPolicyInputs(
    overlayInput: .requested(
      canonicalBytes: BundledRuleAssets.defaultPolicyData,
      sourceIdentity: sourceIdentity
    )
  )

  #expect(noOverlay.state == .verifiedNone)
  #expect(noOverlay.overlayState == .none)
  #expect(noOverlay.planningConfiguration != nil)
  #expect(noOverlay.mutationConfiguration == noOverlay.planningConfiguration)
  #expect(noOverlay.isMutationEligible)
  #expect(noOverlay.planningConfiguration?.user.enabledAdapters == [.genericRemove])

  #expect(explicitDefault.state == .verifiedOverlay)
  #expect(explicitDefault.planningConfiguration == noOverlay.planningConfiguration)
  #expect(explicitDefault.mutationConfiguration == explicitDefault.planningConfiguration)
  #expect(explicitDefault.bindingDigest != noOverlay.bindingDigest)
}

@Test
func verifiedOverlayProtectionIsRetainedWithoutAddingAdapterAuthority() throws {
  let defaultJSON = String(decoding: BundledRuleAssets.defaultPolicyData, as: UTF8.self)
  let protectedJSON = defaultJSON.replacingOccurrences(
    of: "\"protections\":[]",
    with:
      "\"protections\":[{\"effect\":\"protect\",\"path\":{\"components_hex\":[\"ff\"],\"root_binding\":\"0000000000000000000000000000000000000000000000000000000000000000\"}}]"
  )
  let sourceIdentity = try FrozenRulesPolicySourceIdentity(rawBytes: Data([0xff, 0x2f, 0x70]))
  let frozen = FrozenRulesPolicyInputs(
    overlayInput: .requested(
      canonicalBytes: Data(protectedJSON.utf8),
      sourceIdentity: sourceIdentity
    )
  )
  let configuration = try #require(frozen.planningConfiguration)
  let root = try PolicyDigest(bytes: Data(repeating: 0, count: 32))
  let protection = try #require(configuration.user.protections.first)

  #expect(frozen.state == .verifiedOverlay)
  #expect(frozen.isMutationEligible)
  #expect(configuration.user.enabledAdapters == [.genericRemove])
  #expect(
    protection.protects(
      rootBinding: root,
      rawRelativeComponents: [Data([0xff]), Data("child".utf8)]
    )
  )
  #expect(
    !protection.protects(
      rootBinding: root,
      rawRelativeComponents: [Data([0xfe]), Data("child".utf8)]
    )
  )
}

@Test
func malformedMissingUnreadableAndOversizedOverlaysKeepPlanningReadOnly() throws {
  let baseline = FrozenRulesPolicyInputs()
  let sourceIdentity = try FrozenRulesPolicySourceIdentity(
    rawBytes: Data("/policy/custom.json".utf8))
  let malformedInputs = [
    Data("not-json\n".utf8),
    Data("different-invalid-input\n".utf8),
  ]

  for bytes in malformedInputs {
    let frozen = FrozenRulesPolicyInputs(
      overlayInput: .requested(canonicalBytes: bytes, sourceIdentity: sourceIdentity)
    )
    #expect(frozen.state == .policyUnverified)
    #expect(frozen.planningConfiguration == baseline.planningConfiguration)
    #expect(frozen.mutationConfiguration == nil)
    #expect(!frozen.isMutationEligible)
    #expect(frozen.bindingDigest != baseline.bindingDigest)
  }

  for failure in [FrozenRulesPolicyInputFailure.missing, .unreadable] {
    let frozen = FrozenRulesPolicyInputs(
      overlayInput: .requestedUnavailable(sourceIdentity: sourceIdentity, failure: failure)
    )
    #expect(frozen.state == .policyUnverified)
    #expect(frozen.planningConfiguration == baseline.planningConfiguration)
    #expect(frozen.mutationConfiguration == nil)
    #expect(!frozen.isMutationEligible)
  }

  let oversized = FrozenRulesPolicyInputs(
    overlayInput: .requested(
      canonicalBytes: Data(
        repeating: 0x41, count: FrozenRulesPolicyInputs.maximumCanonicalInputBytes + 1),
      sourceIdentity: sourceIdentity
    )
  )
  #expect(oversized.state == .policyUnverified)
  #expect(oversized.planningConfiguration == baseline.planningConfiguration)
  #expect(oversized.mutationConfiguration == nil)
  #expect(oversized.bindingDigest != baseline.bindingDigest)
  guard
    case .policyUnverified(_, .oversized, let byteCount, let rejectedDigest) =
      oversized.overlayState
  else {
    Issue.record("oversized overlay did not retain its typed failure")
    return
  }
  #expect(byteCount == UInt64(FrozenRulesPolicyInputs.maximumCanonicalInputBytes + 1))
  #expect(rejectedDigest == nil)
}

@Test
func unavailableRequiredBaselineIsDistinctAndDoesNotAbortReadOnlyInterpretation() {
  let missingBuiltIn = FrozenRulesPolicyInputs(
    builtInRulesInput: .unavailable(.missing),
    defaultPolicyInput: .canonicalBytes(BundledRuleAssets.defaultPolicyData)
  )
  let unreadableBuiltIn = FrozenRulesPolicyInputs(
    builtInRulesInput: .unavailable(.unreadable),
    defaultPolicyInput: .canonicalBytes(BundledRuleAssets.defaultPolicyData)
  )
  let missingDefault = FrozenRulesPolicyInputs(
    builtInRulesInput: .canonicalBytes(BundledRuleAssets.builtInRulesData),
    defaultPolicyInput: .unavailable(.missing)
  )
  let invalidBuiltIn = FrozenRulesPolicyInputs(
    builtInRulesInput: .canonicalBytes(Data("not-json\n".utf8)),
    defaultPolicyInput: .canonicalBytes(BundledRuleAssets.defaultPolicyData)
  )
  let oversizedDefault = FrozenRulesPolicyInputs(
    builtInRulesInput: .canonicalBytes(BundledRuleAssets.builtInRulesData),
    defaultPolicyInput: .canonicalBytes(
      Data(repeating: 0x41, count: FrozenRulesPolicyInputs.maximumCanonicalInputBytes + 1))
  )

  #expect(missingBuiltIn.state == .requiredBaselineUnusable)
  #expect(missingBuiltIn.planningConfiguration == nil)
  #expect(missingBuiltIn.mutationConfiguration == nil)
  #expect(missingBuiltIn.bindingDigest != unreadableBuiltIn.bindingDigest)
  #expect(missingBuiltIn.bindingDigest != missingDefault.bindingDigest)
  #expect(invalidBuiltIn.state == .requiredBaselineUnusable)
  #expect(invalidBuiltIn.planningConfiguration == nil)
  #expect(oversizedDefault.state == .requiredBaselineUnusable)
  guard case .unusable(.oversized, _, let rawInputDigest) = oversizedDefault.defaultPolicyState
  else {
    Issue.record("oversized default policy did not retain its typed failure")
    return
  }
  #expect(rawInputDigest == nil)
  #expect(oversizedDefault.bindingDigest != missingDefault.bindingDigest)
}

@Test
func everyBoundInputAndProvenanceChangeChangesTheFrozenDigest() throws {
  let baseRules = String(decoding: BundledRuleAssets.builtInRulesData, as: UTF8.self)
  let changedRules = Data(
    baseRules.replacingOccurrences(of: "2e736e617073686f74", with: "2e736e61707368").utf8
  )
  let basePolicy = String(decoding: BundledRuleAssets.defaultPolicyData, as: UTF8.self)
  let changedPolicy = Data(
    basePolicy.replacingOccurrences(of: "1048576", with: "2097152").utf8
  )
  let base = FrozenRulesPolicyInputs()
  let changedBuiltIn = FrozenRulesPolicyInputs(
    builtInRulesInput: .canonicalBytes(changedRules),
    defaultPolicyInput: .canonicalBytes(BundledRuleAssets.defaultPolicyData)
  )
  let changedDefault = FrozenRulesPolicyInputs(
    builtInRulesInput: .canonicalBytes(BundledRuleAssets.builtInRulesData),
    defaultPolicyInput: .canonicalBytes(changedPolicy)
  )
  let identityA = try FrozenRulesPolicySourceIdentity(rawBytes: Data("/policy/a.json".utf8))
  let identityB = try FrozenRulesPolicySourceIdentity(rawBytes: Data("/policy/b.json".utf8))
  let overlayA = FrozenRulesPolicyInputs(
    overlayInput: .requested(
      canonicalBytes: BundledRuleAssets.defaultPolicyData, sourceIdentity: identityA)
  )
  let overlayB = FrozenRulesPolicyInputs(
    overlayInput: .requested(
      canonicalBytes: BundledRuleAssets.defaultPolicyData, sourceIdentity: identityB)
  )
  let changedVerifiedOverlay = FrozenRulesPolicyInputs(
    overlayInput: .requested(canonicalBytes: changedPolicy, sourceIdentity: identityA)
  )
  let failedA = FrozenRulesPolicyInputs(
    overlayInput: .requested(canonicalBytes: Data("not-json\n".utf8), sourceIdentity: identityA)
  )
  let failedB = FrozenRulesPolicyInputs(
    overlayInput: .requested(
      canonicalBytes: Data("still-not-json\n".utf8), sourceIdentity: identityA)
  )
  let unavailableMissing = FrozenRulesPolicyInputs(
    overlayInput: .requestedUnavailable(sourceIdentity: identityA, failure: .missing)
  )
  let unavailableUnreadable = FrozenRulesPolicyInputs(
    overlayInput: .requestedUnavailable(sourceIdentity: identityA, failure: .unreadable)
  )

  #expect(changedBuiltIn.bindingDigest != base.bindingDigest)
  #expect(changedDefault.bindingDigest != base.bindingDigest)
  #expect(overlayA.bindingDigest != overlayB.bindingDigest)
  #expect(overlayA.bindingDigest != changedVerifiedOverlay.bindingDigest)
  #expect(failedA.bindingDigest != failedB.bindingDigest)
  #expect(unavailableMissing.bindingDigest != unavailableUnreadable.bindingDigest)
}

@Test
func sourceIdentityIsBoundedAndPreservedAsRawProvenance() throws {
  let identityBytes = Data([0xff, 0x2f, 0x2e, 0x2e, 0x00])
  #expect(throws: FrozenRulesPolicySourceIdentityError.self) {
    try FrozenRulesPolicySourceIdentity(rawBytes: identityBytes)
  }
  #expect(throws: FrozenRulesPolicySourceIdentityError.self) {
    try FrozenRulesPolicySourceIdentity(rawBytes: Data())
  }
  #expect(throws: FrozenRulesPolicySourceIdentityError.self) {
    try FrozenRulesPolicySourceIdentity(
      rawBytes: Data(repeating: 0x61, count: FrozenRulesPolicySourceIdentity.maximumByteCount + 1)
    )
  }

  let rawPathBytes = Data([0xff, 0x2f, 0x66, 0x6f, 0x6f])
  let sourceIdentity = try FrozenRulesPolicySourceIdentity(rawBytes: rawPathBytes)
  #expect(sourceIdentity.rawBytes == rawPathBytes)
}

@Test
func compileTimeAssetsMatchTheShippedCanonicalFilesExactly() throws {
  let repositoryRoot = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
  let builtInRules = try Data(
    contentsOf: repositoryRoot.appending(path: "rules/builtin-v1.json"))
  let defaultPolicy = try Data(
    contentsOf: repositoryRoot.appending(path: "rules/user-policy-default-v1.json"))

  #expect(BundledRuleAssets.builtInRulesData == builtInRules)
  #expect(BundledRuleAssets.defaultPolicyData == defaultPolicy)
  let firstSnapshot = FrozenRulesPolicyInputs()
  let secondSnapshot = FrozenRulesPolicyInputs()
  #expect(firstSnapshot.bindingDigest == secondSnapshot.bindingDigest)
}
