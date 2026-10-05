import DiskplanRules
import DiskplanScan
import Foundation
import Testing

@testable import DiskplanEngineCore

@Test func frozenRuntimeRulesBindAbsentAndExplicitDefaultSeparately() throws {
  let absent = FrozenRulesPolicyInputs()
  let explicit = FrozenRulesPolicyInputs(
    overlayInput: .requested(
      canonicalBytes: BundledRuleAssets.defaultPolicyData,
      sourceIdentity: try FrozenRulesPolicySourceIdentity(rawBytes: Data("explicit-default".utf8))
    )
  )
  let absentAuthority = try frozenRulesFixtureAuthority(absent)
  let explicitAuthority = try frozenRulesFixtureAuthority(explicit)

  #expect(absentAuthority.genericRemoveEnabled)
  #expect(absentAuthority.rules == explicitAuthority.rules)
  #expect(absentAuthority.rootBinding == explicitAuthority.rootBinding)
  #expect(absentAuthority.rulesInputsBinding == absent.bindingDigest)
  #expect(explicitAuthority.rulesInputsBinding == explicit.bindingDigest)
  #expect(absentAuthority.bindingBytes != explicitAuthority.bindingBytes)
}

@Test func frozenRuntimeRulesNeverUsePlanningFallbackForMutation() throws {
  let source = try FrozenRulesPolicySourceIdentity(rawBytes: Data("requested-policy".utf8))
  let invalid = FrozenRulesPolicyInputs(
    overlayInput: .requested(canonicalBytes: Data("invalid-json".utf8), sourceIdentity: source)
  )
  #expect(invalid.planningConfiguration != nil)
  #expect(invalid.mutationConfiguration == nil)

  let authority = try frozenRulesFixtureAuthority(invalid)
  #expect(authority.rules == invalid.planningConfiguration)
  #expect(authority.rulesInputsBinding == invalid.bindingDigest)
  #expect(!authority.mutationEligible)
  #expect(!authority.genericRemoveEnabled)
}

@Test func frozenRuntimeRulesBindMutationEligibilityIndependently() throws {
  let inputs = FrozenRulesPolicyInputs()
  let eligible = try frozenRulesFixtureAuthority(inputs)
  let ineligible = RuntimeStageableActionAuthority(
    rules: eligible.rules,
    rawCacheRoot: eligible.rawCacheRoot,
    cacheRootIdentity: eligible.cacheRootIdentity,
    effectiveUserID: eligible.effectiveUserID,
    rulesInputsBinding: inputs.bindingDigest,
    mutationEligible: false
  )

  #expect(eligible.rootBinding == ineligible.rootBinding)
  #expect(eligible.rulesInputsBinding == ineligible.rulesInputsBinding)
  #expect(eligible.bindingBytes != ineligible.bindingBytes)
  #expect(!ineligible.genericRemoveEnabled)
}

@Test func frozenRuntimeRulesBindDistinctRejectedInputs() throws {
  let source = try FrozenRulesPolicySourceIdentity(rawBytes: Data("requested-policy".utf8))
  let first = FrozenRulesPolicyInputs(
    overlayInput: .requested(canonicalBytes: Data("invalid-one".utf8), sourceIdentity: source)
  )
  let second = FrozenRulesPolicyInputs(
    overlayInput: .requested(canonicalBytes: Data("invalid-two".utf8), sourceIdentity: source)
  )
  let firstConfiguration = try frozenRulesFixtureAuthority(first)
  let secondConfiguration = try frozenRulesFixtureAuthority(second)

  #expect(first.planningConfiguration == second.planningConfiguration)
  #expect(firstConfiguration.bindingBytes != secondConfiguration.bindingBytes)
}

@Test func frozenRuntimeRulesKeepMissingAndUnreadableIntentDistinct() throws {
  let source = try FrozenRulesPolicySourceIdentity(rawBytes: Data("requested-policy".utf8))
  let missing = FrozenRulesPolicyInputs(
    overlayInput: .requestedUnavailable(sourceIdentity: source, failure: .missing)
  )
  let unreadable = FrozenRulesPolicyInputs(
    overlayInput: .requestedUnavailable(sourceIdentity: source, failure: .unreadable)
  )

  #expect(missing.mutationConfiguration == nil)
  #expect(unreadable.mutationConfiguration == nil)
  #expect(
    try frozenRulesFixtureAuthority(missing).bindingBytes
      != frozenRulesFixtureAuthority(unreadable).bindingBytes
  )
}

@Test func frozenRuntimeRulesRequiredBaselineFailureRemainsBound() {
  let unusable = FrozenRulesPolicyInputs(
    builtInRulesInput: .unavailable(.unreadable),
    defaultPolicyInput: .canonicalBytes(BundledRuleAssets.defaultPolicyData)
  )
  #expect(unusable.planningConfiguration == nil)
  #expect(unusable.mutationConfiguration == nil)
  guard
    case .policyUnavailable(let reason, let binding) =
      RuntimeStageableActionAuthority.production(policyInputs: unusable)
  else {
    Issue.record("an unusable required baseline must not produce mutation configuration")
    return
  }
  #expect(reason == .rulesConfigurationUnavailable)
  #expect(binding == unusable.bindingDigest)
}

// This exercises immutable configuration framing, not platform root discovery,
// Provider admission, scan-session issuance, or permission to delete this path.
private func frozenRulesFixtureAuthority(
  _ inputs: FrozenRulesPolicyInputs
) throws -> RuntimeStageableActionAuthority {
  RuntimeStageableActionAuthority(
    rules: try #require(inputs.planningConfiguration),
    rawCacheRoot: Data("/fixture/cache".utf8),
    cacheRootIdentity: DiskplanScan.ObjectIdentity(device: 1, fileID: 2, objectType: .directory),
    effectiveUserID: 501,
    rulesInputsBinding: inputs.bindingDigest,
    mutationEligible: inputs.mutationConfiguration != nil
  )
}
