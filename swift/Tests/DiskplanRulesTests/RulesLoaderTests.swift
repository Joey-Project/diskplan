import DiskplanPolicy
import Foundation
import Testing

@testable import DiskplanRules

@Test
func shippedRuleAssetsAreCanonicalAndUseConservativeDefaults() throws {
  let repositoryRoot = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
  let rules = try BundledRuleSetLoader.load(
    canonicalData: Data(contentsOf: repositoryRoot.appending(path: "rules/builtin-v1.json"))
  )
  let userPolicy = try RestrictedUserPolicyLoader.load(
    canonicalData: Data(
      contentsOf: repositoryRoot.appending(path: "rules/user-policy-default-v1.json"))
  )
  #expect(rules.rules.count == 10)
  #expect(rules.rules.allSatisfy { $0.handling == .reportOnly })
  #expect(userPolicy.agent.mode == .ask)
  #expect(userPolicy.protections.isEmpty)
  #expect(userPolicy.enabledAdapters.isEmpty)
  #expect(RulesConfiguration(bundled: rules, user: userPolicy).effectiveDigest.bytes.count == 32)
}

@Test
func canonicalParserRejectsDuplicateKeysWhitespaceFloatsAndNonMinimalEscapes() {
  let invalidDocuments = [
    "{\"rules\":[],\"rules\":[],\"schema_version\":\"diskplan.rules.v1\"}\n",
    "{ \"rules\":[],\"schema_version\":\"diskplan.rules.v1\"}\n",
    "{\"rules\":[],\"schema_version\":1.0}\n",
    "{\"rules\":[],\"schema_version\":9223372036854775808}\n",
    "{\"rules\":[],\"schema_version\":\"diskplan\\/rules.v1\"}\n",
    "{\"rules\":[],\"schema_version\":\"diskplan.rules.v\\u0031\"}\n",
    "{\"rules\":[],\"schema_version\":\"diskplan.rules.v1\"}",
    "{\"rules\":[],\"schema_version\":\"diskplan.rules.v1\"}\n\n",
  ]
  for document in invalidDocuments {
    #expect(throws: RulesLoadError.self) {
      try BundledRuleSetLoader.load(canonicalData: Data(document.utf8))
    }
  }
}

@Test
func restrictedPolicyRejectsUnknownAndCommandShapedFields() {
  for (needle, replacement) in [
    ("{\"cache_enabled\"", "{\"argv\":[\"rm\",\"-rf\"],\"cache_enabled\""),
    ("true,\"disclosure\"", "true,\"command\":\"rm -rf /\",\"disclosure\""),
    ("],\"mode\"", "],\"environment\":{\"PATH\":\"/tmp\"},\"mode\""),
    ("],\"mode\"", "],\"executable\":\"/bin/sh\",\"mode\""),
    ("\"mode\":\"ask\"}", "\"mode\":\"ask\",\"shell\":\"$(touch /tmp/pwned)\"}"),
  ] {
    let document = validUserPolicy.replacingOccurrences(of: needle, with: replacement)
    #expect(throws: RulesLoadError.self) {
      try RestrictedUserPolicyLoader.load(canonicalData: Data(document.utf8))
    }
  }
}

@Test
func restrictedPolicyBindsRawProtectionAndDefaultsAgentModeToAsk() throws {
  let policy = try RestrictedUserPolicyLoader.load(canonicalData: Data(validUserPolicy.utf8))
  #expect(policy.agent.mode == .ask)
  #expect(RestrictedUserPolicy.defaultAgentMode == .ask)
  #expect(policy.enabledAdapters == [.codexCleanTmp, .genericRemove])
  let root = try PolicyDigest(bytes: Data(repeating: 0, count: 32))
  #expect(
    policy.protections[0].protects(
      rootBinding: root,
      rawRelativeComponents: [Data([0xFF]), Data("child".utf8)]
    )
  )
  #expect(
    !policy.protections[0].protects(
      rootBinding: root,
      rawRelativeComponents: [Data([0xFE]), Data("child".utf8)]
    )
  )

  let wholeRootDocument = validUserPolicy.replacingOccurrences(
    of: "\"components_hex\":[\"ff\"]",
    with: "\"components_hex\":[]"
  )
  let wholeRoot = try RestrictedUserPolicyLoader.load(
    canonicalData: Data(wholeRootDocument.utf8)
  ).protections[0]
  #expect(wholeRoot.protects(rootBinding: root, rawRelativeComponents: []))
  #expect(
    wholeRoot.protects(
      rootBinding: root,
      rawRelativeComponents: [Data("any-raw-child".utf8)]
    )
  )
}

@Test
func declarativeRecognizerCanOnlyProduceReportOnlyHints() throws {
  let rules = try BundledRuleSetLoader.load(canonicalData: Data(validRuleSet.utf8))
  let root = try PolicyDigest(bytes: Data(repeating: 3, count: 32))
  let hints = DeclarativeRecognizer.recognize(
    ruleSet: rules,
    rootBinding: root,
    rawRelativeComponents: [Data("cache.sqlite".utf8)]
  )
  let hint = try #require(hints.first)
  #expect(hint.handling == .reportOnly)
  #expect(hint.suggestedManagedAction == .sqliteVacuum)
  #expect(hint.requiresCandidateSpecificAuthoritativeProvenance)
}

@Test
func invalidRawPathAndUnsortedSemanticArraysFailClosed() {
  let invalidPath = validUserPolicy.replacingOccurrences(of: "ff", with: "2f")
  #expect(throws: RulesLoadError.self) {
    try RestrictedUserPolicyLoader.load(canonicalData: Data(invalidPath.utf8))
  }
  let unsortedAdapters = validUserPolicy.replacingOccurrences(
    of: "[\"codex-clean-tmp\",\"generic-remove\"]",
    with: "[\"generic-remove\",\"codex-clean-tmp\"]"
  )
  #expect(throws: RulesLoadError.self) {
    try RestrictedUserPolicyLoader.load(canonicalData: Data(unsortedAdapters.utf8))
  }
}

@Test
func managedRuleKindsAndActionsFormAClosedTaggedCombination() {
  let ordinaryWithManagedAction = validRuleSet.replacingOccurrences(
    of: "\"managed-maintenance\"",
    with: "\"ordinary-cache\""
  )
  #expect(throws: RulesLoadError.self) {
    try BundledRuleSetLoader.load(canonicalData: Data(ordinaryWithManagedAction.utf8))
  }
  let managedWithoutAction = validRuleSet.replacingOccurrences(
    of: "\"sqlite-vacuum\"",
    with: "null"
  )
  #expect(throws: RulesLoadError.self) {
    try BundledRuleSetLoader.load(canonicalData: Data(managedWithoutAction.utf8))
  }
}

@Test
func agentCacheBindsExactDisclosedMetadataAndEveryDigestPurposeIsSeparated() throws {
  let rules = try BundledRuleSetLoader.load(canonicalData: Data(validRuleSet.utf8))
  let policy = try RestrictedUserPolicyLoader.load(canonicalData: Data(validUserPolicy.utf8))
  let configuration = RulesConfiguration(bundled: rules, user: policy)
  let evidence = try PolicyDigest(bytes: Data(repeating: 7, count: 32))
  let counts = try AgentNamedCount(name: "candidates", value: 3)
  let firstMetadata = try AgentDisclosedMetadata([
    .counts([counts]), .rootAlias("home"),
  ])
  let secondMetadata = try AgentDisclosedMetadata([
    .counts([counts]), .rootAlias("temporary"),
  ])
  let firstInvocation = try AgentInvocation(
    modelID: "model-v1",
    schemaVersion: "agent-schema-v1",
    promptVersion: "prompt-v1",
    configuration: configuration,
    disclosedMetadata: firstMetadata,
    evidenceDigest: evidence
  )
  let secondInvocation = try AgentInvocation(
    modelID: "model-v1",
    schemaVersion: "agent-schema-v1",
    promptVersion: "prompt-v1",
    configuration: configuration,
    disclosedMetadata: secondMetadata,
    evidenceDigest: evidence
  )
  let firstCache = try firstInvocation.cacheLookup()
  let secondCache = try secondInvocation.cacheLookup()
  #expect(firstInvocation.authorizationRequirement == .userConsent)
  #expect(throws: AgentBindingError.userConsentRequired) {
    try firstInvocation.authorizeForAutomaticMode()
  }
  #expect(firstMetadata.canonicalData != secondMetadata.canonicalData)
  #expect(firstCache.invocation.disclosedMetadata.canonicalData == firstMetadata.canonicalData)
  #expect(firstCache.binding.digest != secondCache.binding.digest)
  let disallowedMetadata = try AgentDisclosedMetadata([.sizes([1])])
  #expect(throws: AgentBindingError.disclosureNotAllowed) {
    try AgentInvocation(
      modelID: "model-v1",
      schemaVersion: "agent-schema-v1",
      promptVersion: "prompt-v1",
      configuration: configuration,
      disclosedMetadata: disallowedMetadata,
      evidenceDigest: evidence
    )
  }

  let disabledPolicy = try RestrictedUserPolicyLoader.load(
    canonicalData: Data(validUserPolicy.replacingOccurrences(of: "\"ask\"", with: "\"off\"").utf8)
  )
  #expect(throws: AgentBindingError.agentDisabled) {
    try AgentInvocation(
      modelID: "model-v1",
      schemaVersion: "agent-schema-v1",
      promptVersion: "prompt-v1",
      configuration: RulesConfiguration(bundled: rules, user: disabledPolicy),
      disclosedMetadata: firstMetadata,
      evidenceDigest: evidence
    )
  }

  let cacheDisabledPolicy = try RestrictedUserPolicyLoader.load(
    canonicalData: Data(
      validUserPolicy.replacingOccurrences(
        of: "\"cache_enabled\":true", with: "\"cache_enabled\":false"
      ).utf8)
  )
  let cacheDisabledInvocation = try AgentInvocation(
    modelID: "model-v1",
    schemaVersion: "agent-schema-v1",
    promptVersion: "prompt-v1",
    configuration: RulesConfiguration(bundled: rules, user: cacheDisabledPolicy),
    disclosedMetadata: firstMetadata,
    evidenceDigest: evidence
  )
  #expect(throws: AgentBindingError.cacheDisabled) {
    try cacheDisabledInvocation.cacheLookup()
  }

  let automaticPolicy = try RestrictedUserPolicyLoader.load(
    canonicalData: Data(validUserPolicy.replacingOccurrences(of: "\"ask\"", with: "\"auto\"").utf8)
  )
  let automaticInvocation = try AgentInvocation(
    modelID: "model-v1",
    schemaVersion: "agent-schema-v1",
    promptVersion: "prompt-v1",
    configuration: RulesConfiguration(bundled: rules, user: automaticPolicy),
    disclosedMetadata: firstMetadata,
    evidenceDigest: evidence
  )
  let authorizedInvocation = try automaticInvocation.authorizeForAutomaticMode()
  #expect(authorizedInvocation.invocation.authorizationRequirement == .automaticPolicy)
  #expect(authorizedInvocation.authorizationDigest != automaticInvocation.digest)

  #expect(firstInvocation.disclosedMetadata.canonicalData == firstMetadata.canonicalData)
  #expect(firstInvocation.digest != firstCache.binding.digest)

  let root = try PolicyDigest(bytes: Data(repeating: 9, count: 32))
  let hint = try #require(
    DeclarativeRecognizer.recognize(
      ruleSet: rules,
      rootBinding: root,
      rawRelativeComponents: [Data("cache.sqlite".utf8)]
    ).first
  )
  #expect(
    Set([
      rules.digest.bytes, policy.digest.bytes, configuration.effectiveDigest.bytes,
      hint.candidateBinding.bytes, firstMetadata.digest.bytes, firstInvocation.digest.bytes,
      firstCache.binding.digest.bytes,
    ]).count == 7
  )
}

@Test
func automaticAgentAuthorizationRejectsUnsafeIdentifiersForEveryField() throws {
  let rules = try BundledRuleSetLoader.load(canonicalData: Data(validRuleSet.utf8))
  let automaticPolicy = try RestrictedUserPolicyLoader.load(
    canonicalData: Data(validUserPolicy.replacingOccurrences(of: "\"ask\"", with: "\"auto\"").utf8)
  )
  let configuration = RulesConfiguration(bundled: rules, user: automaticPolicy)
  let metadata = try AgentDisclosedMetadata([.rootAlias("home")])
  let evidence = try PolicyDigest(bytes: Data(repeating: 8, count: 32))
  let invalidCases:
    [(
      field: AgentInvocationIdentifierField,
      modelID: String,
      schemaVersion: String,
      promptVersion: String
    )] = [
      (.modelID, "Bearer placeholder", "agent-schema-v1", "prompt-v1"),
      (.schemaVersion, "model-v1", "Basic placeholder", "prompt-v1"),
      (.promptVersion, "model-v1", "agent-schema-v1", "X-Api-Key: placeholder"),
      (.modelID, "Bearer_placeholder", "agent-schema-v1", "prompt-v1"),
      (.schemaVersion, "model-v1", "Basic.placeholder", "prompt-v1"),
      (.promptVersion, "model-v1", "agent-schema-v1", "X-Api-Key-placeholder"),
      (.modelID, "X-Api-Key/placeholder", "agent-schema-v1", "prompt-v1"),
      (.modelID, "model$(id)", "agent-schema-v1", "prompt-v1"),
      (.schemaVersion, "model-v1", "schema\nv1", "prompt-v1"),
      (.promptVersion, "model-v1", "agent-schema-v1", "prompt\u{0}v1"),
      (.modelID, "-model-v1", "agent-schema-v1", "prompt-v1"),
      (.schemaVersion, "model-v1", ".agent-schema-v1", "prompt-v1"),
      (.promptVersion, "model-v1", "agent-schema-v1", "_prompt-v1"),
      (.modelID, "model-v1-", "agent-schema-v1", "prompt-v1"),
      (.schemaVersion, "model-v1", "agent-schema-v1.", "prompt-v1"),
      (.promptVersion, "model-v1", "agent-schema-v1", "prompt-v1_"),
      (.modelID, "model/../../bin/sh", "agent-schema-v1", "prompt-v1"),
      (.modelID, "org//model-v1", "agent-schema-v1", "prompt-v1"),
      (.schemaVersion, "model-v1", "schema/v1", "prompt-v1"),
      (.promptVersion, "model-v1", "agent-schema-v1", "prompt/v1"),
    ]

  for invalid in invalidCases {
    #expect(throws: AgentBindingError.invalidInvocationIdentifier(field: invalid.field)) {
      let invocation = try AgentInvocation(
        modelID: invalid.modelID,
        schemaVersion: invalid.schemaVersion,
        promptVersion: invalid.promptVersion,
        configuration: configuration,
        disclosedMetadata: metadata,
        evidenceDigest: evidence
      )
      _ = try invocation.authorizeForAutomaticMode()
    }
  }
}

@Test
func agentMetadataRejectsCredentialShapesAndOverLimitCollections() throws {
  // Synthetic token catalog: joey-private-v3 / api-key-a.
  let syntheticCredentialShapedFilename = "codex_synth_v1_api_key_a"
  let credentialBytes = Data(syntheticCredentialShapedFilename.utf8)
  #expect(throws: AgentBindingError.invalidMetadata) {
    try AgentDisclosedField.relativeNames([credentialBytes])
  }
  #expect(throws: AgentBindingError.invalidMetadata) {
    try AgentDisclosedField.manifestNames([credentialBytes])
  }
  #expect(throws: AgentBindingError.invalidMetadata) {
    try AgentDisclosedField.rootAlias(syntheticCredentialShapedFilename)
  }
  #expect(throws: AgentBindingError.invalidMetadata) {
    try AgentDisclosedField.sizes(Array(repeating: 1, count: 4_097))
  }
  #expect(throws: AgentBindingError.invalidMetadata) {
    try AgentDisclosedField.types(Array(repeating: "type", count: 4_097))
  }
}

@Test
func credentialShapeClassifierUsesClosedASCIICaseInsensitiveSchemes() {
  #expect(
    CredentialShapeClassifier.classify(Data("bEaReR\tshort-placeholder".utf8))
      == .authorizationScheme(.bearer)
  )
  #expect(
    CredentialShapeClassifier.classify(Data("Basic YQ==".utf8))
      == .authorizationScheme(.basic)
  )
  #expect(
    CredentialShapeClassifier.classify(Data("Digest username=sample".utf8))
      == .authorizationScheme(.digest)
  )
  #expect(
    CredentialShapeClassifier.classify(Data("X-Api-Key: short-placeholder".utf8))
      == .authorizationScheme(.apiKey)
  )
  #expect(
    CredentialShapeClassifier.classify(Data(String(repeating: "Ab1+", count: 11).utf8))
      == .standardBase64
  )
  #expect(
    CredentialShapeClassifier.classify(
      Data((String(repeating: "Ab1+", count: 10) + "Ab1").utf8)
    ) == .standardBase64
  )
  #expect(
    CredentialShapeClassifier.classify(Data("b\u{0435}arer short-placeholder".utf8)) == nil
  )
  #expect(CredentialShapeClassifier.classify(Data("basic-cache".utf8)) == nil)
  #expect(CredentialShapeClassifier.classify(Data("disk-cache".utf8)) == nil)
  #expect(CredentialShapeClassifier.classify(Data("task-cache".utf8)) == nil)
  #expect(
    CredentialShapeClassifier.classify(Data("0123456789abcdef0123456789abcdef".utf8)) == nil
  )
  #expect(
    CredentialShapeClassifier.classify(
      Data((String(repeating: "a1", count: 16) + "a").utf8)
    ) == .opaqueToken
  )
}

@Test
func agentMetadataCanonicalIntegersUseTheSignedSchemaRange() throws {
  let maximum = UInt64(Int64.max)
  let count = try AgentNamedCount(name: "maximum", value: maximum)
  let metadata = try AgentDisclosedMetadata([
    .counts([count]), .sizes([maximum]),
  ])
  var parser = try CanonicalJSONParser(data: metadata.canonicalData)
  _ = try parser.parse()
  #expect(String(decoding: metadata.canonicalData, as: UTF8.self).contains(String(Int64.max)))

  #expect(throws: AgentBindingError.invalidMetadata) {
    try AgentNamedCount(name: "overflow", value: UInt64.max)
  }
  #expect(throws: AgentBindingError.invalidMetadata) {
    try AgentDisclosedField.sizes([UInt64.max])
  }
}

private let validRuleSet =
  "{\"rules\":[{\"candidate_kind\":\"managed-maintenance\",\"handling\":\"report-only\",\"id\":\"sqlite-vacuum-hint\",\"managed_action\":\"sqlite-vacuum\",\"matcher\":{\"kind\":\"name-suffix\",\"value_hex\":\"2e73716c697465\"}}],\"schema_version\":\"diskplan.rules.v1\"}\n"

private let validUserPolicy =
  "{\"adapter_enablement\":[\"codex-clean-tmp\",\"generic-remove\"],\"agent\":{\"cache_enabled\":true,\"disclosure\":[\"counts\",\"relative-names\",\"root-alias\"],\"mode\":\"ask\"},\"budgets\":{\"maximum_candidates\":250000,\"maximum_entries_per_root\":2000000,\"maximum_owner_references\":5000000,\"maximum_retained_bytes\":805306368,\"maximum_shared_object_keys\":2000000},\"profile\":\"standard\",\"protections\":[{\"effect\":\"protect\",\"path\":{\"components_hex\":[\"ff\"],\"root_binding\":\"0000000000000000000000000000000000000000000000000000000000000000\"}}],\"schema_version\":\"diskplan.user-policy.v1\",\"thresholds\":{\"minimum_inactive_seconds\":604800,\"minimum_reclaim_bytes\":1048576}}\n"
