import Foundation
import Testing

@testable import DiskplanPolicy

@Test
func observationKeepsAbsenceUnknownUnreadableAndFailureDistinct() {
  let failure = ObservationFailure(code: "denied", collector: "scanner")
  let values: [Observation<Int>] = [
    .absent, .unknown(.notRequested), .unreadable(failure), .failed(failure), .known(1),
  ]
  #expect(Set(values.map(String.init(describing:))).count == values.count)
  #expect(Observation<Int>.unknown(.timedOut).map(String.init) == .unknown(.timedOut))
}

@Test
func rawTargetAndRootPathsRejectAmbiguousOrEscapingForms() throws {
  let invalidTargets: [[Data]] = [
    [],
    [Data()],
    [Data(".".utf8)],
    [Data("..".utf8)],
    [Data("a/b".utf8)],
    [Data([0x61, 0, 0x62])],
  ]
  for components in invalidTargets {
    #expect(throws: PolicyModelError.invalidRawPath) {
      try RawTargetPath(components: components)
    }
  }
  for root in ["", "relative", "/a/", "/a//b", "/a/./b", "/a/../b"] {
    #expect(throws: PolicyModelError.invalidRawPath) {
      try RawRootPath(absoluteBytes: Data(root.utf8))
    }
  }
  #expect(try RawRootPath(absoluteBytes: Data("/".utf8)).absoluteBytes == Data("/".utf8))
  #expect(
    try RawTargetPath(components: [Data("child".utf8)]).components == [Data("child".utf8)]
  )
}

@Test
func deterministicClassificationUsesRankFacetsAndPermutationInvariantResolution() {
  let claims = [
    claim(.purpose, "path", .pathConvention("path"), "p"),
    claim(.purpose, "structural", .structuralRecognizer("manifest"), "s"),
    claim(.ownership, "tool", .authoritativeAdapter("tool"), "a"),
    claim(.lifecycle, "fallback", .genericFallback, "f"),
  ]
  let expected = ClassificationResolver.resolve(claims)
  for permutation in permutations(claims) {
    #expect(ClassificationResolver.resolve(permutation) == expected)
  }
  #expect(expected.facets.first(where: { $0.facet == .purpose })?.value == "structural")
  #expect(expected.facets.first(where: { $0.facet == .ownership })?.value == "tool")
  #expect(!expected.isConflict)
}

@Test
func sameRankConflictIsFacetScopedAndUsesRawUTF8Identity() {
  let decomposed = "e\u{301}"
  let composed = "\u{e9}"
  #expect(decomposed == composed)
  let resolution = ClassificationResolver.resolve([
    claim(.purpose, decomposed, .structuralRecognizer("a"), "same"),
    claim(.purpose, composed, .structuralRecognizer("a"), "same"),
    claim(.ownership, "local", .structuralRecognizer("a"), "other"),
  ])
  #expect(resolution.conflicts.count == 1)
  #expect(resolution.conflicts.first?.facet == .purpose)
  #expect(resolution.conflicts.first?.claims.count == 2)
  #expect(resolution.facets.first?.facet == .ownership)
}

@Test
func agentSuggestionsAreExcludedFromDeterministicResolution() {
  let agent = claim(.purpose, "agent", .agentSuggestion("model"), "agent")
  let agentOnly = ClassificationResolver.resolve([agent])
  #expect(agentOnly.facets.isEmpty)
  #expect(agentOnly.conflicts.isEmpty)
  #expect(agentOnly.agentSuggestions == [agent])
  #expect(agentOnly.deterministicMissingFacets.contains(.purpose))

  let authoritative = claim(
    .purpose, "deterministic", .authoritativeAdapter("adapter"), "authoritative"
  )
  let mixed = ClassificationResolver.resolve([agent, authoritative])
  #expect(mixed.facets.first?.value == "deterministic")
  #expect(!mixed.isConflict)
  #expect(mixed.agentSuggestions.isEmpty)

  let missingOwnership = claim(.ownership, "agent-owner", .agentSuggestion("model"), "owner")
  let partiallyClassified = ClassificationResolver.resolve([
    agent, authoritative, missingOwnership,
  ])
  #expect(partiallyClassified.agentSuggestions == [missingOwnership])
}

@Test
func typedGateResultsPreserveEveryDimensionAndReason() throws {
  let evaluation = try testingEvaluation(votes: baseVotes())
  #expect(evaluation.votes.map(\.dimension) == GateDimension.allCases)
  for (index, vote) in evaluation.votes.enumerated() {
    guard case .satisfied(let reasons) = vote.result else {
      Issue.record("expected satisfied result")
      return
    }
    #expect(reasons == [reason("satisfied-\(index)", UInt8(index + 1))])
  }
  #expect(evaluation.stageability == .stageable)
}

@Test
func everyHardRejectAloneAndCombinedBlocksWithoutScoring() throws {
  for dimension in GateDimension.allCases {
    let evaluation = try testingEvaluation(votes: votes(rejecting: [dimension]))
    #expect(evaluation.stageability == .blocked)
  }
  let combined = try testingEvaluation(votes: votes(rejecting: Set(GateDimension.allCases)))
  #expect(combined.stageability == .blocked)
  #expect(
    combined.votes.filter { if case .rejected = $0.result { true } else { false } }.count == 7)
}

@Test
func safeAfterExitIsAnUnmetConditionNotAHardRejectOrWaiver() throws {
  var inputs = baseVotes()
  inputs[Int(GateDimension.currentActivity.rawValue)] = GateVote(
    dimension: .currentActivity,
    result: .unmetCondition(
      conditions: [.activityCleared],
      reasons: [reason("open-handle", 20), reason("mapped-image", 21)]
    )
  )
  let evaluation = try testingEvaluation(votes: inputs)
  #expect(evaluation.recommendation == .safeAfterExit)
  #expect(evaluation.stageability == .blocked)
  #expect(evaluation.unmetRevalidationConditions == [.activityCleared])
  guard case .unmetCondition(_, let reasons) = evaluation.votes[2].result else {
    Issue.record("activity should remain an unmet condition")
    return
  }
  #expect(reasons.count == 2)
}

@Test
func exactWaiverPredicatesAreRetainedAndCannotAttachToHardDimensions() throws {
  let first = waiver(.agentAssistedClassification, "agent", 31)
  let second = waiver(.normalKeepPolicy, "keep", 32)
  var all = baseVotes()
  all[Int(GateDimension.semanticUniqueness.rawValue)] = GateVote(
    dimension: .semanticUniqueness,
    result: .requiresWaiver(
      predicates: [second, first], reasons: [reason("semantic-review", 33)]
    )
  )
  let evaluation = try testingEvaluation(votes: all)
  #expect(evaluation.stageability == .requiresConsents([first, second].sorted()))

  all[Int(GateDimension.identityAndAccess.rawValue)] = GateVote(
    dimension: .identityAndAccess,
    result: .requiresWaiver(
      predicates: [waiver(.unknownRebuildCost, "cost", 34)],
      reasons: [reason("invalid", 35)]
    )
  )
  #expect(
    throws: PolicyModelError.invalidWaiverDimension(
      .unknownRebuildCost, actual: .identityAndAccess
    )
  ) { try testingEvaluation(votes: all) }
}

@Test
func everyClosedWaiverKindWorksOnlyOnItsDeclaredDimension() throws {
  for (index, kind) in WaiverKind.allCases.enumerated() {
    let predicate = waiver(kind, "predicate-\(index)", UInt8(40 + index))
    var allowed = baseVotes()
    allowed[Int(kind.gateDimension.rawValue)] = GateVote(
      dimension: kind.gateDimension,
      result: .requiresWaiver(
        predicates: [predicate], reasons: [reason("waiver-\(index)", UInt8(60 + index))]
      )
    )
    #expect(
      try testingEvaluation(votes: allowed).stageability == .requiresConsents([predicate])
    )
  }

  let nonWaivableDimensions: [GateDimension] = [
    .protectionAndProvider,
    .evidenceCompleteness,
    .currentActivity,
    .identityAndAccess,
    .dependencyCompleteness,
  ]
  for dimension in nonWaivableDimensions {
    var invalid = baseVotes()
    invalid[Int(dimension.rawValue)] = GateVote(
      dimension: dimension,
      result: .requiresWaiver(
        predicates: [waiver(.normalKeepPolicy, "forbidden", 80)],
        reasons: [reason("forbidden", 81)]
      )
    )
    #expect(throws: PolicyModelError.self) { try testingEvaluation(votes: invalid) }
  }
}

@Test
func oneVotePolicyHasSevenNamedTypedInputs() throws {
  let evidence = snapshot(candidateID: "a", path: "a", object: 1)
  let evaluation = try OneVotePolicy.evaluate(
    OneVotePolicyInputs.build(
      evidence: evidence,
      globalFacts: globalFacts()
    )
  )
  #expect(evaluation.votes.count == 7)
  #expect(evaluation.stageability == .stageable)
}

@Test
func evaluationAuthorityBindsFrozenEvidenceAndRejectsForgedVotesAtActionBoundary() throws {
  let facts = globalFacts()
  let evidence = snapshot(
    candidateID: "protected", path: "protected", object: 1,
    explicitProtection: .known(.protected),
    globalFactsOverride: facts
  )
  let evaluation = try OneVotePolicy.evaluate(
    OneVotePolicyInputs.build(evidence: evidence, globalFacts: facts)
  )
  let source = evaluation.sourceBinding
  #expect(source.captureID == evidence.captureID)
  #expect(source.evidenceID == evidence.evidenceID)
  #expect(source.globalFactsHash == facts.globalFactsHash)
  #expect(source.policyVersion == evidence.policyVersion)
  #expect(source.schemaVersion == evidence.schemaVersion)
  #expect(source.semanticReferenceTimeSeconds == evidence.semanticReferenceTimeSeconds)
  #expect(
    source.classificationResolutionHash
      == ClassificationResolver.resolve(evidence.classificationClaims).bindingHash
  )
  #expect(evaluation.stageability == .blocked)

  let forged = try PolicyEvaluation.testing(
    votes: baseVotes(), evidence: evidence, globalFacts: facts
  )
  #expect(forged.sourceBinding == source)
  #expect(forged.stageability == .stageable)
  #expect(throws: PolicyModelError.actionEvidenceMismatch) {
    try ActionDefinition.build(
      prototype: ActionPrototype.build(request: .genericRemove, evidence: evidence),
      evidence: evidence,
      globalFacts: facts,
      prerequisites: [],
      evaluation: forged,
      displayMetrics: metrics(path: "protected")
    )
  }
}

@Test
func publicDisplayMetricsCannotClaimAnAuthoritativeSafeTier() {
  let metrics = ActionDisplayMetrics(
    immediateReclaimBytes: .known(1),
    inactiveDurationSeconds: .known(2),
    rebuildCost: .known(3),
    cleanupCost: .known(4),
    canonicalRawPath: Data("target".utf8)
  )
  #expect(metrics.tier == .blocked)
}

@Test
func policyAuthoritativelyDerivesAndUnionsEveryTypedReviewFact() throws {
  let claims = [
    claim(.purpose, "cache", .structuralRecognizer("cache"), "purpose"),
    claim(.lifecycle, "stale", .agentSuggestion("agent"), "lifecycle"),
    claim(.ownership, "user", .agentSuggestion("agent"), "ownership"),
    claim(.recoverability, "rebuildable", .agentSuggestion("agent"), "recoverability"),
  ]
  let worktree = gitWorktreeEvidence(localChanges: .present(changeSetDigest: digest(44)))
  let evidence = snapshot(
    candidateID: "typed", path: "typed", object: 1,
    adapterScope: .gitWorktree,
    recoverability: .known(.reviewRequired),
    recoverabilityReviewFacts: [
      .staticOnlyRebuildEvidence(artifactKind: "cache", evidenceHash: digest(42)),
      .unknownRebuildCost(valueBucket: "expensive", evidenceHash: digest(43)),
    ],
    semanticReviewFacts: [
      .taskSemanticCompletion(taskID: "task-1", evidenceHash: digest(41)),
      .recencyAgePolicy(valueBucket: "under-30-days", evidenceHash: digest(40)),
    ],
    classificationClaims: claims,
    gitWorktree: worktree
  )
  let evaluation = try OneVotePolicy.evaluate(
    OneVotePolicyInputs.build(evidence: evidence, globalFacts: globalFacts())
  )

  let semantic = try #require(
    evaluation.votes.first { $0.dimension == .semanticUniqueness }
  )
  guard case .requiresWaiver(let semanticPredicates, let semanticReasons) = semantic.result else {
    Issue.record("semantic facts must require exact consents")
    return
  }
  #expect(semanticPredicates.count == 5)
  #expect(semanticReasons.count >= 5)
  #expect(
    Set(semanticPredicates.filter { $0.kind == .agentAssistedClassification }.map(\.valueBucket))
      == Set(["lifecycle", "ownership", "recoverability"])
  )
  #expect(semanticPredicates.contains { $0.kind == .recencyAgePolicy })
  #expect(semanticPredicates.contains { $0.kind == .taskSemanticCompletion })

  let recoverability = try #require(
    evaluation.votes.first { $0.dimension == .recoverability }
  )
  guard case .requiresWaiver(let recoverabilityPredicates, _) = recoverability.result else {
    Issue.record("recoverability facts must require exact consents")
    return
  }
  #expect(
    Set(recoverabilityPredicates.map(\.kind))
      == Set([
        .staticOnlyRebuildEvidence,
        .unknownRebuildCost,
        .fullyObservedLocalGitWorkDiscard,
      ])
  )

  let missingSuggestion = snapshot(
    candidateID: "missing", path: "missing", object: 2,
    classificationClaims: Array(claims.dropLast())
  )
  let missingEvaluation = try OneVotePolicy.evaluate(
    OneVotePolicyInputs.build(evidence: missingSuggestion, globalFacts: globalFacts())
  )
  let missingSemantic = try #require(
    missingEvaluation.votes.first { $0.dimension == .semanticUniqueness }
  )
  guard case .rejected = missingSemantic.result else {
    Issue.record("every missing deterministic facet needs a matching agent suggestion")
    return
  }

  let protected = snapshot(
    candidateID: "protected", path: "protected", object: 3,
    explicitProtection: .known(.protected)
  )
  let protectedEvaluation = try OneVotePolicy.evaluate(
    OneVotePolicyInputs.build(evidence: protected, globalFacts: globalFacts())
  )
  let protectedVote = try #require(
    protectedEvaluation.votes.first { $0.dimension == .protectionAndProvider }
  )
  guard case .rejected = protectedVote.result else {
    Issue.record("explicit protection must hard reject")
    return
  }
}

@Test
func typedFactAndGatePayloadPermutationsCanonicalizeBeforeHashing() throws {
  let semanticFacts: [SemanticReviewFact] = [
    .recencyAgePolicy(valueBucket: "recent", evidenceHash: digest(50)),
    .normalKeepPolicy(policyID: "keep", evidenceHash: digest(51)),
  ]
  let recoverabilityFacts: [RecoverabilityReviewFact] = [
    .staticOnlyRebuildEvidence(artifactKind: "cache", evidenceHash: digest(52)),
    .unknownRebuildCost(valueBucket: "unknown", evidenceHash: digest(53)),
  ]
  let first = snapshot(
    candidateID: "canonical", path: "canonical", object: 1,
    recoverability: .known(.reviewRequired),
    recoverabilityReviewFacts: recoverabilityFacts,
    semanticReviewFacts: semanticFacts
  )
  let second = snapshot(
    candidateID: "canonical", path: "canonical", object: 1,
    recoverability: .known(.reviewRequired),
    recoverabilityReviewFacts: Array(recoverabilityFacts.reversed()),
    semanticReviewFacts: Array(semanticFacts.reversed())
  )
  #expect(first.evidenceID == second.evidenceID)
  let firstAction = try makeAction(evidence: first)
  let secondAction = try makeAction(evidence: second)
  #expect(firstAction.evaluation.votes == secondAction.evaluation.votes)
  #expect(firstAction.id == secondAction.id)

  let firstPredicate = waiver(.recencyAgePolicy, "recent", 54)
  let secondPredicate = waiver(.normalKeepPolicy, "keep", 55)
  var forward = baseVotes()
  var reverse = baseVotes()
  forward[Int(GateDimension.semanticUniqueness.rawValue)] = GateVote(
    dimension: .semanticUniqueness,
    result: .requiresWaiver(
      predicates: [secondPredicate, firstPredicate],
      reasons: [reason("second", 57), reason("first", 56)]
    )
  )
  reverse[Int(GateDimension.semanticUniqueness.rawValue)] = GateVote(
    dimension: .semanticUniqueness,
    result: .requiresWaiver(
      predicates: [firstPredicate, secondPredicate],
      reasons: [reason("first", 56), reason("second", 57)]
    )
  )
  #expect(
    try testingEvaluation(votes: forward) == testingEvaluation(votes: reverse)
  )
}

@Test
func unknownRecoverabilityUsesStableTypedSemanticsAcrossFreshCaptures() throws {
  let semantic = try UnknownRecoverabilitySemanticEvidence(
    reason: .unsupported,
    kind: .rebuildCostUnknown,
    sourceBindingHash: digest(59)
  )
  let firstFacts = globalFacts(
    configuration: Data("first-capture".utf8),
    semanticReferenceTimeSeconds: 100
  )
  let secondFacts = FrozenGlobalFacts(
    captureID: digest(90),
    profile: "standard",
    configuration: Data("second-capture".utf8),
    coverage: firstFacts.coverage,
    semanticReferenceTimeSeconds: 200,
    policyVersion: firstFacts.policyVersion,
    schemaVersion: firstFacts.schemaVersion
  )
  let first = snapshot(
    candidateID: "unknown", path: "unknown", object: 71,
    recoverability: .unknown(.unsupported),
    recoverabilityReviewFacts: [.unknownRecoverability(semantic)],
    globalFactsOverride: firstFacts
  )
  let second = snapshot(
    candidateID: "unknown", path: "unknown", object: 71,
    recoverability: .unknown(.unsupported),
    recoverabilityReviewFacts: [.unknownRecoverability(semantic)],
    semanticReferenceTimeSeconds: 200,
    globalFactsOverride: secondFacts
  )
  #expect(first.evidenceID != second.evidenceID)

  let firstEvaluation = try OneVotePolicy.evaluate(
    OneVotePolicyInputs.build(evidence: first, globalFacts: firstFacts))
  let secondEvaluation = try OneVotePolicy.evaluate(
    OneVotePolicyInputs.build(evidence: second, globalFacts: secondFacts))
  let firstVote = try #require(
    firstEvaluation.votes.first { $0.dimension == .recoverability })
  let secondVote = try #require(
    secondEvaluation.votes.first { $0.dimension == .recoverability })
  guard case .requiresWaiver(let firstPredicates, _) = firstVote.result,
    case .requiresWaiver(let secondPredicates, _) = secondVote.result
  else {
    Issue.record("typed unknown recoverability must require an explicit waiver")
    return
  }
  #expect(firstPredicates == secondPredicates)
  #expect(firstPredicates.map(\.predicate) == ["recoverability-unknown"])
}

@Test
func unknownRecoverabilitySemanticProofIsStructurallyRequiredAndFailClosed() throws {
  #expect(throws: PolicyModelError.invalidGateSet) {
    try UnknownRecoverabilitySemanticEvidence(
      reason: .timedOut,
      kind: .rebuildCostUnknown,
      sourceBindingHash: digest(60)
    )
  }
  let known = snapshot(candidateID: "known", path: "known", object: 72)
  let semantic = try UnknownRecoverabilitySemanticEvidence(
    reason: .unavailableViaPublicAPI,
    kind: .rebuildCostUnknown,
    sourceBindingHash: digest(61)
  )
  #expect(throws: PolicyModelError.invalidGateSet) {
    try refreeze(
      known,
      recoverability: .unknown(.unavailableViaPublicAPI),
      recoverabilityReviewFacts: []
    )
  }
  #expect(throws: PolicyModelError.invalidGateSet) {
    try refreeze(
      known,
      recoverability: .known(.recoverable),
      recoverabilityReviewFacts: [.unknownRecoverability(semantic)]
    )
  }
  #expect(throws: PolicyModelError.invalidGateSet) {
    try refreeze(
      known,
      recoverability: .unknown(.unsupported),
      recoverabilityReviewFacts: [.unknownRecoverability(semantic)]
    )
  }

  let operationalUnknown = try refreeze(
    known,
    recoverability: .unknown(.incompleteCoverage),
    recoverabilityReviewFacts: []
  )
  let operationalEvaluation = try OneVotePolicy.evaluate(
    OneVotePolicyInputs.build(
      evidence: operationalUnknown,
      globalFacts: globalFacts()
    )
  )
  let recoverabilityVote = try #require(
    operationalEvaluation.votes.first { $0.dimension == .recoverability }
  )
  guard case .rejected = recoverabilityVote.result else {
    Issue.record("operationally unknown recoverability must remain report-only")
    return
  }
}

@Test
func storageGraphRejectsEmptyOwnersImpossibleCountsAndEscapedPaths() throws {
  let candidate = storageCandidate("a", ["a"], 1)
  let owner = FileOwnerLink(candidateID: "a", path: candidate.target)
  #expect(throws: PolicyModelError.self) {
    try StorageReleaseGraph(
      globalFacts: globalFacts(),
      candidates: [candidate],
      fileObjects: [
        FileObjectNode(
          provenance: graphProvenance(), id: "empty", observedOwners: [], linkCount: .known(1)
        )
      ],
      allocationGroups: []
    )
  }
  #expect(throws: PolicyModelError.self) {
    try StorageReleaseGraph(
      globalFacts: globalFacts(),
      candidates: [candidate],
      fileObjects: [
        FileObjectNode(
          provenance: graphProvenance(),
          id: "disconnected",
          observedOwners: [owner],
          linkCount: .unknown(.incompleteCoverage)
        )
      ],
      allocationGroups: []
    )
  }
  let otherCaptureFacts = FrozenGlobalFacts(
    captureID: digest(90),
    profile: "standard",
    configuration: Data("config".utf8),
    coverage: [
      GlobalCoverageFact(
        rawRoot: try RawRootPath(absoluteBytes: Data("/root".utf8)),
        coverage: .complete,
        reasons: ["complete"]
      )
    ],
    semanticReferenceTimeSeconds: 100,
    policyVersion: "policy-1",
    schemaVersion: "schema-1"
  )
  #expect(throws: PolicyModelError.self) {
    try StorageReleaseGraph(
      globalFacts: globalFacts(),
      candidates: [candidate],
      fileObjects: [
        FileObjectNode(
          provenance: graphProvenance(facts: otherCaptureFacts),
          id: "mixed-capture",
          observedOwners: [owner],
          linkCount: .known(1)
        )
      ],
      allocationGroups: []
    )
  }
  #expect(throws: PolicyModelError.self) {
    try StorageReleaseGraph(
      globalFacts: globalFacts(),
      candidates: [candidate],
      fileObjects: [
        FileObjectNode(
          provenance: graphProvenance(), id: "zero", observedOwners: [owner],
          linkCount: .known(0)
        )
      ],
      allocationGroups: []
    )
  }
  #expect(throws: PolicyModelError.self) {
    try StorageReleaseGraph(
      globalFacts: globalFacts(),
      candidates: [candidate],
      fileObjects: [
        FileObjectNode(
          provenance: graphProvenance(), id: "file", observedOwners: [owner],
          linkCount: .known(1)
        )
      ],
      allocationGroups: [
        AllocationGroupNode(
          provenance: graphProvenance(),
          id: "empty",
          ownerFileObjectIDs: [],
          cloneRefCount: .known(1),
          sharedBytes: .known(1),
          snapshotBlocker: .known(false)
        )
      ]
    )
  }
  let escaped = FileOwnerLink(
    candidateID: "a", path: try RawTargetPath(components: [Data("elsewhere".utf8)])
  )
  #expect(throws: PolicyModelError.self) {
    try StorageReleaseGraph(
      globalFacts: globalFacts(),
      candidates: [candidate],
      fileObjects: [
        FileObjectNode(
          provenance: graphProvenance(), id: "escaped", observedOwners: [escaped],
          linkCount: .known(1)
        )
      ],
      allocationGroups: []
    )
  }
  #expect(throws: PolicyModelError.self) {
    try StorageReleaseGraph(
      globalFacts: globalFacts(),
      candidates: [candidate],
      fileObjects: [
        FileObjectNode(
          provenance: graphProvenance(), id: "first", observedOwners: [owner],
          linkCount: .known(1)
        ),
        FileObjectNode(
          provenance: graphProvenance(), id: "second", observedOwners: [owner],
          linkCount: .known(1)
        ),
      ],
      allocationGroups: []
    )
  }
}

@Test
func releaseTopologyUsesRawUTF8IdentityForGroupAndFileIDs() {
  let nfc = "\u{00e9}"
  let nfd = "e\u{0301}"
  let owner = FileOwnerLink(
    candidateID: "owner",
    path: try! RawTargetPath(components: [Data("owner".utf8)]))
  let first = ReleaseTopologyExpectation(
    allocationGroupID: nfc,
    fileObjects: [
      FileTopologyExpectation(fileObjectID: nfc, owners: [owner], linkCount: .known(1))
    ],
    cloneRefCount: .known(1),
    sharedBytes: .known(1),
    snapshotBlocker: .known(false)
  )
  let differentGroup = ReleaseTopologyExpectation(
    allocationGroupID: nfd,
    fileObjects: first.fileObjects,
    cloneRefCount: first.cloneRefCount,
    sharedBytes: first.sharedBytes,
    snapshotBlocker: first.snapshotBlocker
  )
  let differentFile = ReleaseTopologyExpectation(
    allocationGroupID: nfc,
    fileObjects: [
      FileTopologyExpectation(fileObjectID: nfd, owners: [owner], linkCount: .known(1))
    ],
    cloneRefCount: first.cloneRefCount,
    sharedBytes: first.sharedBytes,
    snapshotBlocker: first.snapshotBlocker
  )
  #expect(first != differentGroup)
  #expect(first != differentFile)
}

@Test
func storageGraphInvalidDiagnosticsArePermutationInvariant() throws {
  let foreignFacts = globalFacts(configuration: Data("foreign".utf8))
  let invalidCandidates = [
    storageCandidate("z", ["z"], 1, facts: foreignFacts),
    storageCandidate("a", ["a"], 1, facts: foreignFacts),
  ]
  for candidates in [invalidCandidates, Array(invalidCandidates.reversed())] {
    #expect(throws: PolicyModelError.invalidStorageGraph("candidate-binding:a")) {
      try StorageReleaseGraph(
        globalFacts: globalFacts(),
        candidates: candidates,
        fileObjects: [],
        allocationGroups: []
      )
    }
  }

  let owner = storageCandidate("owner", ["owner"], 1)
  let outsidePath = try RawTargetPath(components: [Data("outside".utf8)])
  let invalidFiles = ["z-file", "a-file"].map { fileID in
    FileObjectNode(
      provenance: graphProvenance(),
      id: fileID,
      observedOwners: [FileOwnerLink(candidateID: owner.id, path: outsidePath)],
      linkCount: .known(1)
    )
  }
  for files in [invalidFiles, Array(invalidFiles.reversed())] {
    #expect(throws: PolicyModelError.invalidStorageGraph("owner-outside-candidate:a-file")) {
      try StorageReleaseGraph(
        globalFacts: globalFacts(),
        candidates: [owner],
        fileObjects: files,
        allocationGroups: []
      )
    }
  }

  let invalidGroups = ["z-group", "a-group"].map { groupID in
    AllocationGroupNode(
      provenance: graphProvenance(facts: foreignFacts),
      id: groupID,
      ownerFileObjectIDs: ["missing"],
      cloneRefCount: .known(1),
      sharedBytes: .known(1),
      snapshotBlocker: .known(false)
    )
  }
  for groups in [invalidGroups, Array(invalidGroups.reversed())] {
    #expect(throws: PolicyModelError.invalidStorageGraph("group-provenance:a-group")) {
      try StorageReleaseGraph(
        globalFacts: globalFacts(),
        candidates: [],
        fileObjects: [],
        allocationGroups: groups
      )
    }
  }
}

@Test
func completeCloneAndHardlinkGraphCreditsSharedBytesOnce() throws {
  let graph = try completeStorageGraph()
  let evaluated = try evaluateGraph(graph, selectedCandidateIDs: ["a", "b"])
  #expect(evaluated.immediatePrivateReclaimBytes == .known(30))
  #expect(evaluated.conditionalGroupReclaimBytes == .known(100))
  #expect(evaluated.releaseSets.count == 1)
  #expect(evaluated.releaseSets.first?.isComplete == true)
}

@Test
func duplicateCandidateActionBindingsFailWithoutTrapping() throws {
  let graph = try completeStorageGraph()
  let aEvidence = snapshot(candidateID: "a", path: "a", object: 1)
  let bEvidence = snapshot(candidateID: "b", path: "b", object: 2)
  let a = try makeAction(evidence: aEvidence)
  let b = try makeAction(evidence: bEvidence)

  let duplicateEvaluationBindings = actionBindings([("a", a), ("a", a)])
  #expect(throws: PolicyModelError.duplicateIdentifier) {
    try graph.evaluate(selectedCandidateActions: duplicateEvaluationBindings)
  }

  let evaluated = try evaluateGraph(graph, selectedCandidateIDs: ["a", "b"])
  let duplicatePlanBindings = actionBindings([("a", a), ("a", a), ("b", b)])
  #expect(throws: PolicyModelError.duplicateIdentifier) {
    try PlanReleaseSet.buildAll(
      from: evaluated, candidateActions: duplicatePlanBindings
    )
  }
}

@Test
func sharedOwnerAcrossAllocationGroupsFailsClosedWithoutDoubleCredit() throws {
  let a = storageCandidate("a", ["a"], 10)
  let file = FileObjectNode(
    provenance: graphProvenance(),
    id: "file",
    observedOwners: [FileOwnerLink(candidateID: "a", path: a.target)],
    linkCount: .known(1)
  )
  let groupOne = allocationGroup("g1", owners: ["file"], refCount: 1, bytes: 100)
  let groupTwo = allocationGroup("g2", owners: ["file"], refCount: 1, bytes: 100)
  let graph = try StorageReleaseGraph(
    globalFacts: globalFacts(),
    candidates: [a], fileObjects: [file], allocationGroups: [groupOne, groupTwo]
  )
  let evaluated = try evaluateGraph(graph, selectedCandidateIDs: ["a"])
  #expect(evaluated.conditionalGroupReclaimBytes == .known(0))
  #expect(
    evaluated.releaseSets.allSatisfy {
      $0.blockers.contains(.sharedOwnerInMultipleGroups("file"))
    }
  )
}

@Test
func snapshotsProviderOwnersIncompleteCountsAndOverlapGiveNoSharedCredit() throws {
  let base = try completeStorageGraph()
  let cases = [
    try replaceGroup(base, refCount: .known(3)),
    try replaceGroup(base, snapshot: .known(true)),
    try replaceGroup(base, snapshot: .unknown(.unsupported)),
    try replaceGroup(base, sharedBytes: .unknown(.incompleteCoverage)),
    try completeStorageGraph(providerCandidateID: "b"),
    try replaceFile(base, id: "file-b", linkCount: .known(2)),
  ]
  for graph in cases {
    let evaluated = try evaluateGraph(graph, selectedCandidateIDs: ["a", "b"])
    #expect(evaluated.conditionalGroupReclaimBytes == .known(0))
  }
  let overlap = try StorageReleaseGraph(
    globalFacts: globalFacts(),
    candidates: [
      storageCandidate("parent", ["root"], 1),
      storageCandidate("child", ["root", "child"], 1),
    ], fileObjects: [], allocationGroups: []
  )
  let overlapEvaluation = try evaluateGraph(
    overlap, selectedCandidateIDs: ["parent", "child"]
  )
  #expect(overlapEvaluation.immediatePrivateReclaimBytes == .known(0))
  #expect(overlapEvaluation.blockers.contains(.targetOverlap("child", "parent")))
}

@Test
func genericRemoveContractRequiresExplicitPathRaceResidualAndForceState() throws {
  let evidence = snapshot(
    candidateID: "a",
    path: "a",
    object: 1,
    forceRequirement: .requiresForceWithWarning,
    trustedNamespace: .explicitlyTrustedUserNamespace,
    objectKind: .regularFile
  )
  let prototype = try ActionPrototype.build(request: .genericRemove, evidence: evidence)
  guard case .genericRemove(let contract) = prototype.adapterContract else {
    Issue.record("expected generic remove")
    return
  }
  #expect(contract.removalPathSlot == .prototypeRawTargetPath)
  #expect(contract.targetKind == .regularFile)
  #expect(contract.pathRaceResidual)
  #expect(contract.forceRequirement == .requiresForceWithWarning)
  #expect(contract.trustedNamespace == .explicitlyTrustedUserNamespace)
  #expect(prototype.postcondition == .targetAbsent)

  let unavailableContent = snapshot(
    candidateID: "content-failed", path: "content-failed", object: 11,
    contentProtection: .failed(
      ObservationFailure(code: "digest-failed", collector: "content-digest")
    )
  )
  #expect(throws: PolicyModelError.actionEvidenceMismatch) {
    try ActionPrototype.build(request: .genericRemove, evidence: unavailableContent)
  }
  let metadataOnly = snapshot(
    candidateID: "metadata-only", path: "metadata-only", object: 12,
    contentProtection: .known(.explicitlyNotApplicable(.metadataOnlyObject))
  )
  #expect(
    try ActionPrototype.build(request: .genericRemove, evidence: metadataOnly)
      .protectedProperties.content.expectedBaseline
      == .explicitlyNotApplicable(.metadataOnlyObject)
  )

  let noQuarantine = snapshot(
    candidateID: "w", path: "w", object: 2, quarantineCapability: .known(false)
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try ActionPrototype.build(request: .gitWorktreeRemove, evidence: noQuarantine)
  }
  #expect(throws: PolicyModelError.invalidActionContract) {
    try ActionPrototype.build(
      request: .versionedArtifactRemove(artifactKind: "", version: "1"), evidence: evidence
    )
  }
  #expect(throws: PolicyModelError.invalidActionContract) {
    try ActionPrototype.build(
      request: .codexCleanTemporary(cleanupScopeID: " "), evidence: evidence)
  }
}

@Test
func dirtyGitWorktreeContractsRemainBoundButCannotBeStagedOrWaived() throws {
  let worktree = gitWorktreeEvidence(
    localChanges: .present(changeSetDigest: digest(60))
  )
  let evidence = snapshot(
    candidateID: "worktree", path: "worktree", object: 1,
    adapterScope: .gitWorktree,
    gitWorktree: worktree
  )
  let discard = try makeAction(
    evidence: evidence,
    request: .gitWorktreeDiscardLocalChanges
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try makeAction(
      evidence: evidence,
      request: .gitWorktreeRemove
    )
  }

  let remove = try makeAction(
    evidence: evidence,
    prerequisites: [discard],
    request: .gitWorktreeRemove
  )
  let plan = try makePlan(actions: [discard, remove], evidence: [evidence])
  #expect(plan.actions.count == 2)
  guard
    case .gitWorktreeDiscardLocalChanges(let discardContract) =
      discard.prototype.adapterContract,
    case .gitWorktreeRemove(let removeContract) = remove.prototype.adapterContract
  else {
    Issue.record("expected separate worktree discard and remove contracts")
    return
  }
  #expect(discardContract.verifiedEvidence == worktree)
  #expect(discardContract.changeSetDigest == digest(60))
  #expect(discardContract.successorBaseline == removeContract.executionBaseline)
  #expect(
    discard.prototype.postcondition
      == .gitWorktreeLocalChangesDiscarded(
        changeSetDigest: digest(60),
        successor: discardContract.successorBaseline
      )
  )
  #expect(removeContract.verifiedEvidence == worktree)
  #expect(removeContract.requiresDiscardLocalChanges)
  #expect(
    remove.prototype.protectedProperties.content.expectedBaseline
      == discardContract.successorBaseline.contentProtection
  )

  #expect(discard.evaluation.stageability == .blocked)
  #expect(remove.evaluation.stageability == .blocked)
  let overlay = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: [remove.id, discard.id],
    waiverConsents: [],
    userNotes: []
  )
  #expect(throws: PolicyModelError.actionNotStageable(remove.id)) {
    try DecisionOverlayValidator.validate(overlay, against: plan)
  }

  let mismatchedWorktree = gitWorktreeEvidence(
    indexDigest: .known(digest(99)),
    localChanges: .present(changeSetDigest: digest(60))
  )
  let mismatchedEvidence = snapshot(
    candidateID: "mismatched-worktree", path: "worktree", object: 1,
    adapterScope: .gitWorktree,
    gitWorktree: mismatchedWorktree
  )
  let mismatchedDiscard = try makeAction(
    evidence: mismatchedEvidence,
    request: .gitWorktreeDiscardLocalChanges
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try makeAction(
      evidence: evidence,
      prerequisites: [mismatchedDiscard],
      request: .gitWorktreeRemove
    )
  }
  #expect(mismatchedDiscard.evaluation.stageability == .blocked)

  let invalidEvidence = [
    gitWorktreeEvidence(
      noFollowTraversalComplete: .known(false),
      localChanges: .present(changeSetDigest: digest(60))
    ),
    gitWorktreeEvidence(
      localChanges: .present(changeSetDigest: digest(60)),
      nestedRepositories: .known(.present)
    ),
    gitWorktreeEvidence(
      localChanges: .present(changeSetDigest: digest(60)),
      submodules: .known(.present)
    ),
    gitWorktreeEvidence(
      localChanges: .present(changeSetDigest: digest(60)),
      trustedExclusiveNamespace: .known(false)
    ),
    gitWorktreeEvidence(
      localChanges: .present(changeSetDigest: digest(60)),
      postQuarantineCoverage: .known(.partial)
    ),
    gitWorktreeEvidence(
      localChanges: .present(changeSetDigest: digest(60)),
      postDiscardSuccessor: .known(
        try GitWorktreeExecutionBaseline(
          headIdentity: digest(99),
          indexDigest: digest(72),
          localChanges: .clean,
          contentProtection: .requiredDigest(digest(73))
        )
      )
    ),
    gitWorktreeEvidence(
      localChanges: .present(changeSetDigest: digest(60)),
      linkage: .known(.linked(registrationID: digest(76)))
    ),
    gitWorktreeEvidence(
      localChanges: .present(changeSetDigest: digest(60)),
      sparseCheckout: .known(.enabled(configurationDigest: digest(76)))
    ),
    gitWorktreeEvidence(
      localChanges: .present(changeSetDigest: digest(60)),
      registration: .unknown(.unavailableViaPublicAPI)
    ),
    gitWorktreeEvidence(
      localChanges: .present(changeSetDigest: digest(60)),
      linkage: .unreadable(
        ObservationFailure(code: "unreadable", collector: "git-registration"))
    ),
    gitWorktreeEvidence(
      localChanges: .present(changeSetDigest: digest(60)),
      sparseCheckout: .failed(
        ObservationFailure(code: "failed", collector: "git-config"))
    ),
  ]
  for (index, invalid) in invalidEvidence.enumerated() {
    let invalidSnapshot = snapshot(
      candidateID: "invalid-\(index)", path: "invalid-\(index)",
      object: 1, adapterScope: .gitWorktree,
      gitWorktree: invalid
    )
    let invalidEvaluation = try OneVotePolicy.evaluate(
      OneVotePolicyInputs.build(evidence: invalidSnapshot, globalFacts: globalFacts())
    )
    #expect(invalidEvaluation.stageability == .blocked)
    #expect(throws: PolicyModelError.invalidActionContract) {
      try ActionPrototype.build(request: .gitWorktreeRemove, evidence: invalidSnapshot)
    }
  }
}

@Test
func gitWorktreeRegistrationTopologyAndSparseFactsFailClosed() throws {
  let linkedEvidence = snapshot(
    candidateID: "linked", path: "linked", object: 1,
    adapterScope: .gitWorktree,
    gitWorktree: gitWorktreeEvidence()
  )
  let linkedAction = try makeAction(
    evidence: linkedEvidence,
    request: .gitWorktreeRemove
  )
  #expect(linkedAction.evaluation.stageability == .stageable)

  let changedRegistration = try GitWorktreeRegistrationEvidence(
    registeredWorktreeIdentity: ObjectIdentity(
      device: 1, object: 1, generation: .known(1), type: .directory),
    administrativeDirectoryIdentity: ObjectIdentity(
      device: 1, object: 702, generation: .known(1), type: .directory),
    commonDirectoryIdentity: ObjectIdentity(
      device: 1, object: 703, generation: .known(1), type: .directory),
    registrationID: digest(75),
    metadataDigest: digest(77),
    headResolutionDigest: digest(78)
  )
  let changedEvidence = snapshot(
    candidateID: "linked", path: "linked", object: 1,
    adapterScope: .gitWorktree,
    gitWorktree: gitWorktreeEvidence(registration: .known(changedRegistration))
  )
  let changedAction = try makeAction(
    evidence: changedEvidence,
    request: .gitWorktreeRemove
  )
  #expect(changedAction.evaluation.stageability == .stageable)
  #expect(changedEvidence.evidenceID != linkedEvidence.evidenceID)
  #expect(changedAction.lineageID != linkedAction.lineageID)
  #expect(changedAction.id != linkedAction.id)

  let sameIdentityRegistration = try GitWorktreeRegistrationEvidence(
    registeredWorktreeIdentity: ObjectIdentity(
      device: 1, object: 1, generation: .known(1), type: .directory),
    administrativeDirectoryIdentity: ObjectIdentity(
      device: 1, object: 700, generation: .known(1), type: .directory),
    commonDirectoryIdentity: ObjectIdentity(
      device: 1, object: 700, generation: .known(1), type: .directory),
    registrationID: digest(75),
    metadataDigest: digest(74),
    headResolutionDigest: digest(77)
  )
  let topologyMatrix: [(String, GitWorktreeEvidence)] = [
    (
      "linked-registration-id-mismatch",
      gitWorktreeEvidence(linkage: .known(.linked(registrationID: digest(76))))
    ),
    (
      "linked-same-admin-common-identity",
      gitWorktreeEvidence(registration: .known(sameIdentityRegistration))
    ),
    (
      "ordinary-distinct-admin-common-identity",
      gitWorktreeEvidence(linkage: .known(.ordinary))
    ),
    (
      "ordinary-same-admin-common-identity",
      gitWorktreeEvidence(
        registration: .known(sameIdentityRegistration),
        linkage: .known(.ordinary)
      )
    ),
  ]
  for (label, worktree) in topologyMatrix {
    let evidence = snapshot(
      candidateID: label, path: label, object: 1,
      adapterScope: .gitWorktree,
      gitWorktree: worktree
    )
    let evaluation = try OneVotePolicy.evaluate(
      OneVotePolicyInputs.build(evidence: evidence, globalFacts: globalFacts())
    )
    #expect(evaluation.stageability == .blocked)
    #expect(throws: PolicyModelError.invalidActionContract) {
      try ActionPrototype.build(request: .gitWorktreeRemove, evidence: evidence)
    }
  }

  let sparseEvidence = snapshot(
    candidateID: "sparse", path: "sparse", object: 1,
    adapterScope: .gitWorktree,
    gitWorktree: gitWorktreeEvidence(
      sparseCheckout: .known(.enabled(configurationDigest: digest(76))))
  )
  let sparseEvaluation = try OneVotePolicy.evaluate(
    OneVotePolicyInputs.build(evidence: sparseEvidence, globalFacts: globalFacts())
  )
  #expect(sparseEvaluation.stageability == .blocked)
  #expect(sparseEvidence.evidenceID != linkedEvidence.evidenceID)
  #expect(throws: PolicyModelError.invalidActionContract) {
    try ActionPrototype.build(request: .gitWorktreeRemove, evidence: sparseEvidence)
  }

  let invalidFacts = [
    gitWorktreeEvidence(worktreeObject: 2),
    gitWorktreeEvidence(
      sparseCheckout: .known(.enabled(configurationDigest: digest(76)))),
    gitWorktreeEvidence(registration: .unknown(.unavailableViaPublicAPI)),
    gitWorktreeEvidence(registration: .absent),
    gitWorktreeEvidence(linkage: .unknown(.unavailableViaPublicAPI)),
    gitWorktreeEvidence(sparseCheckout: .unknown(.unavailableViaPublicAPI)),
    gitWorktreeEvidence(
      linkage: .unreadable(
        ObservationFailure(code: "unreadable", collector: "git-registration"))),
    gitWorktreeEvidence(
      sparseCheckout: .failed(
        ObservationFailure(code: "failed", collector: "git-config"))),
  ]
  for (index, invalid) in invalidFacts.enumerated() {
    let invalidEvidence = snapshot(
      candidateID: "typed-git-invalid-\(index)", path: "typed-git-invalid-\(index)", object: 1,
      adapterScope: .gitWorktree,
      gitWorktree: invalid
    )
    let evaluation = try OneVotePolicy.evaluate(
      OneVotePolicyInputs.build(evidence: invalidEvidence, globalFacts: globalFacts())
    )
    #expect(evaluation.stageability == .blocked)
    #expect(throws: PolicyModelError.invalidActionContract) {
      try ActionPrototype.build(request: .gitWorktreeRemove, evidence: invalidEvidence)
    }
  }
}

@Test
func frozenEvidenceRejectsInvalidClaimsAndCanonicalizesAdapterScopes() throws {
  let base = snapshot(candidateID: "a", path: "a", object: 1)
  let valid = claim(.purpose, "cache", .structuralRecognizer("cache"), "evidence")
  #expect(throws: PolicyModelError.invalidGateSet) {
    try refreeze(base, classificationClaims: [valid, valid])
  }
  let invalidClaims = [
    claim(.purpose, " ", .structuralRecognizer("cache"), "evidence"),
    claim(.purpose, "cache", .structuralRecognizer(" "), "evidence"),
    claim(.purpose, "cache", .agentSuggestion(" "), "evidence"),
    claim(.purpose, "cache", .structuralRecognizer("cache"), " "),
  ]
  for invalid in invalidClaims {
    #expect(throws: PolicyModelError.invalidGateSet) {
      try refreeze(base, classificationClaims: [invalid])
    }
  }

  let releaseScope = AdapterScopeEvidence.completeReleaseSetRemove(
    allocationGroupID: "group-1")
  let genericFirst = try refreeze(
    base,
    adapterScope: .genericRemove,
    additionalAdapterScopes: [releaseScope]
  )
  let releaseFirst = try refreeze(
    base,
    adapterScope: releaseScope,
    additionalAdapterScopes: [.genericRemove]
  )
  #expect(genericFirst == releaseFirst)
  #expect(genericFirst.evidenceID == releaseFirst.evidenceID)
  #expect(throws: PolicyModelError.invalidGateSet) {
    try refreeze(
      base,
      adapterScope: .genericRemove,
      additionalAdapterScopes: [.genericRemove]
    )
  }
  #expect(throws: PolicyModelError.invalidGateSet) {
    try refreeze(
      base,
      adapterScope: .genericRemove,
      additionalAdapterScopes: [.gitWorktree]
    )
  }
  #expect(throws: PolicyModelError.invalidGateSet) {
    try refreeze(
      base,
      adapterScope: .genericRemove,
      additionalAdapterScopes: [],
      gitWorktreeOverride: gitWorktreeEvidence(
        localChanges: .present(changeSetDigest: digest(60)))
    )
  }
  #expect(throws: PolicyModelError.invalidGateSet) {
    try refreeze(
      base,
      adapterScope: .gitWorktree,
      additionalAdapterScopes: []
    )
  }
  #expect(throws: PolicyModelError.invalidGateSet) {
    try refreeze(
      base,
      adapterScope: .completeReleaseSetRemove(allocationGroupID: " "),
      additionalAdapterScopes: []
    )
  }
}

@Test
func overlayRejectsAliasAndAncestorTerminalMutations() throws {
  let genericEvidence = snapshot(candidateID: "generic", path: "same", object: 1)
  let codexEvidence = snapshot(
    candidateID: "codex", path: "same", object: 1,
    adapterScope: .codexCleanTemporary(cleanupScopeID: "scope")
  )
  let generic = try makeAction(evidence: genericEvidence)
  let codex = try makeAction(
    evidence: codexEvidence,
    request: .codexCleanTemporary(cleanupScopeID: "scope")
  )
  let aliasPlan = try makePlan(
    actions: [generic, codex], evidence: [genericEvidence, codexEvidence]
  )
  let aliasOverlay = DecisionOverlay.create(
    plan: aliasPlan,
    selectedActionIDs: [generic.id, codex.id],
    waiverConsents: [],
    userNotes: []
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try DecisionOverlayValidator.validate(aliasOverlay, against: aliasPlan)
  }

  let parentEvidence = snapshot(candidateID: "parent", path: "tree", object: 10)
  let childEvidence = snapshot(candidateID: "child", path: "tree/child", object: 11)
  let parent = try makeAction(evidence: parentEvidence)
  let child = try makeAction(evidence: childEvidence)
  let ancestorPlan = try makePlan(
    actions: [parent, child], evidence: [parentEvidence, childEvidence]
  )
  let ancestorOverlay = DecisionOverlay.create(
    plan: ancestorPlan,
    selectedActionIDs: [parent.id, child.id],
    waiverConsents: [],
    userNotes: []
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try DecisionOverlayValidator.validate(ancestorOverlay, against: ancestorPlan)
  }

  let blockedDescendant = snapshot(
    candidateID: "blocked-descendant", path: "tree/blocked", object: 12,
    explicitProtection: .known(.protected)
  )
  let parentOnlyPlan = try makePlan(
    actions: [parent], evidence: [parentEvidence, blockedDescendant]
  )
  let parentOnlyOverlay = DecisionOverlay.create(
    plan: parentOnlyPlan,
    selectedActionIDs: [parent.id],
    waiverConsents: [],
    userNotes: []
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try DecisionOverlayValidator.validate(parentOnlyOverlay, against: parentOnlyPlan)
  }

  let descendantOnlyPlan = try makePlan(
    actions: [child], evidence: [parentEvidence, childEvidence]
  )
  let descendantOnlyOverlay = DecisionOverlay.create(
    plan: descendantOnlyPlan,
    selectedActionIDs: [child.id],
    waiverConsents: [],
    userNotes: []
  )
  #expect(
    try DecisionOverlayValidator.validate(descendantOnlyOverlay, against: descendantOnlyPlan)
      .executionSteps.map(\.action) == [child]
  )
}

@Test
func planRejectsCrossSnapshotGitContractDowngrades() throws {
  let dirtyGitEvidence = snapshot(
    candidateID: "git", path: "tree/worktree", object: 20,
    adapterScope: .gitWorktree,
    gitWorktree: gitWorktreeEvidence(
      worktreeObject: 20,
      localChanges: .present(changeSetDigest: digest(60)))
  )
  let aliasEvidence = snapshot(
    candidateID: "alias", path: "tree/alias", object: 20)
  let alias = try makeAction(evidence: aliasEvidence)
  #expect(throws: PolicyModelError.invalidActionContract) {
    try makePlan(
      actions: [alias],
      evidence: [aliasEvidence, dirtyGitEvidence]
    )
  }

  let ancestorEvidence = snapshot(candidateID: "ancestor", path: "tree", object: 21)
  let ancestor = try makeAction(evidence: ancestorEvidence)
  #expect(throws: PolicyModelError.invalidActionContract) {
    try makePlan(
      actions: [ancestor],
      evidence: [ancestorEvidence, dirtyGitEvidence]
    )
  }

  let nestedEvidence = snapshot(
    candidateID: "nested", path: "tree/worktree/cache", object: 22)
  let nested = try makeAction(evidence: nestedEvidence)
  #expect(throws: PolicyModelError.invalidActionContract) {
    try makePlan(
      actions: [nested],
      evidence: [nestedEvidence, dirtyGitEvidence]
    )
  }

  let disjointEvidence = snapshot(
    candidateID: "disjoint", path: "tree/other", object: 23)
  let disjoint = try makeAction(evidence: disjointEvidence)
  let disjointPlan = try makePlan(
    actions: [disjoint],
    evidence: [disjointEvidence, dirtyGitEvidence]
  )
  let disjointOverlay = DecisionOverlay.create(
    plan: disjointPlan,
    selectedActionIDs: [disjoint.id],
    waiverConsents: [],
    userNotes: []
  )
  #expect(
    try DecisionOverlayValidator.validate(disjointOverlay, against: disjointPlan)
      .executionSteps.map(\.action) == [disjoint]
  )
}

@Test
func duplicateSurvivorConsentPreservesTheSurvivorNamespace() throws {
  let aEvidence = snapshot(
    candidateID: "a", path: "a", object: 1,
    semanticReviewFacts: [
      .duplicateSurvivorChoice(
        groupID: "duplicates", survivorCandidateID: "b", evidenceHash: digest(88))
    ]
  )
  let bEvidence = snapshot(
    candidateID: "b", path: "survivor-root/b", object: 2,
    semanticReviewFacts: [
      .duplicateSurvivorChoice(
        groupID: "duplicates", survivorCandidateID: "b", evidenceHash: digest(88))
    ]
  )
  let ancestorEvidence = snapshot(
    candidateID: "ancestor", path: "survivor-root", object: 3)
  let descendantEvidence = snapshot(
    candidateID: "descendant", path: "survivor-root/b/cache", object: 4)
  let a = try makeAction(evidence: aEvidence)
  let b = try makeAction(evidence: bEvidence)
  let ancestor = try makeAction(evidence: ancestorEvidence)
  let descendant = try makeAction(evidence: descendantEvidence)
  guard case .requiresConsents(let predicates) = a.evaluation.stageability,
    let predicate = predicates.first(where: { $0.kind == .duplicateSurvivorChoice })
  else {
    Issue.record("expected duplicate survivor consent")
    return
  }
  let consent = WaiverConsentCore.create(
    action: a,
    predicate: predicate,
    reason: "keep exact survivor",
    consentEventID: "duplicate-event"
  )
  guard case .requiresConsents(let survivorPredicates) = b.evaluation.stageability,
    let survivorPredicate = survivorPredicates.first(where: {
      $0.kind == .duplicateSurvivorChoice
    })
  else {
    Issue.record("expected survivor duplicate consent")
    return
  }
  let survivorConsent = WaiverConsentCore.create(
    action: b,
    predicate: survivorPredicate,
    reason: "confirm survivor contract",
    consentEventID: "survivor-event"
  )

  let directPlan = try makePlan(
    actions: [a, b], evidence: [aEvidence, bEvidence]
  )
  let directOverlay = DecisionOverlay.create(
    plan: directPlan,
    selectedActionIDs: [a.id, b.id],
    waiverConsents: [consent, survivorConsent],
    userNotes: []
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try DecisionOverlayValidator.validate(directOverlay, against: directPlan)
  }

  let factOnlyOnUnselectedDuplicatePlan = try makePlan(
    actions: [b], evidence: [aEvidence, bEvidence]
  )
  let survivorRemovalOverlay = DecisionOverlay.create(
    plan: factOnlyOnUnselectedDuplicatePlan,
    selectedActionIDs: [b.id],
    waiverConsents: [survivorConsent],
    userNotes: []
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try DecisionOverlayValidator.validate(
      survivorRemovalOverlay,
      against: factOnlyOnUnselectedDuplicatePlan
    )
  }

  let ancestorPlan = try makePlan(
    actions: [a, ancestor], evidence: [aEvidence, bEvidence, ancestorEvidence]
  )
  let ancestorOverlay = DecisionOverlay.create(
    plan: ancestorPlan,
    selectedActionIDs: [a.id, ancestor.id],
    waiverConsents: [consent],
    userNotes: []
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try DecisionOverlayValidator.validate(ancestorOverlay, against: ancestorPlan)
  }

  let descendantPlan = try makePlan(
    actions: [a, descendant],
    evidence: [aEvidence, bEvidence, descendantEvidence]
  )
  let descendantOverlay = DecisionOverlay.create(
    plan: descendantPlan,
    selectedActionIDs: [a.id, descendant.id],
    waiverConsents: [consent],
    userNotes: []
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try DecisionOverlayValidator.validate(descendantOverlay, against: descendantPlan)
  }

  let decoyEvidence = snapshot(candidateID: "decoy", path: "decoy", object: 5)
  let wrongGroupMemberA = snapshot(
    candidateID: "wrong-a", path: "wrong-a", object: 6,
    semanticReviewFacts: [
      .duplicateSurvivorChoice(
        groupID: "wrong-group", survivorCandidateID: "decoy", evidenceHash: digest(90))
    ]
  )
  let wrongGroupMemberB = snapshot(
    candidateID: "wrong-b", path: "wrong-b", object: 7,
    semanticReviewFacts: [
      .duplicateSurvivorChoice(
        groupID: "wrong-group", survivorCandidateID: "decoy", evidenceHash: digest(90))
    ]
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try makePlan(
      actions: [],
      evidence: [wrongGroupMemberA, wrongGroupMemberB, decoyEvidence]
    )
  }
}

@Test
func actionBuildRequiresFullMatchingEvidenceSnapshot() throws {
  let evidence = snapshot(candidateID: "a", path: "a", object: 1)
  let prototype = try genericPrototype(evidence)
  let action = try makeAction(evidence: evidence)
  #expect(action.evidence == evidence)
  #expect(action.evidenceID == evidence.evidenceID)

  let changedIdentity = snapshot(candidateID: "a", path: "a", object: 2)
  #expect(throws: PolicyModelError.actionEvidenceMismatch) {
    try ActionDefinition.build(
      prototype: prototype,
      evidence: changedIdentity,
      globalFacts: globalFacts(),
      prerequisites: [],
      evaluation: try allowEvaluation(),
      displayMetrics: metrics(path: "a")
    )
  }
  let changedForce = snapshot(
    candidateID: "a", path: "a", object: 1,
    forceRequirement: .requiresForceWithWarning
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try ActionDefinition.build(
      prototype: prototype,
      evidence: changedForce,
      globalFacts: globalFacts(),
      prerequisites: [],
      evaluation: try bindEvaluation(
        allowEvaluation(), evidence: changedForce, facts: globalFacts()
      ),
      displayMetrics: metrics(path: "a")
    )
  }
}

@Test
func namespaceAndProtectedPropertyMutationsSealEveryHashLayer() throws {
  let baseEvidence = snapshot(candidateID: "a", path: "parent/target", object: 1)
  let baseAction = try makeAction(evidence: baseEvidence)
  let basePlan = try makePlan(actions: [baseAction], evidence: [baseEvidence])
  #expect(
    baseAction.prototype.protectedProperties.identity.expectedIdentity
      == baseAction.prototype.targetIdentity)
  #expect(
    baseAction.prototype.protectedProperties.content.expectedBaseline
      == .requiredDigest(digest(92))
  )
  #expect(
    baseAction.prototype.protectedProperties.accessPolicy.requiredBaseline.aclDigest
      == digest(93)
  )

  let variants: [(FrozenEvidenceSnapshot, FrozenGlobalFacts)] = [
    (
      snapshot(candidateID: "a", path: "parent/target", object: 1, rootObject: 901),
      globalFacts()
    ),
    (
      snapshot(candidateID: "a", path: "parent/target", object: 1, rawRoot: "/other"),
      globalFacts(rawRoot: "/other")
    ),
    (
      snapshot(
        candidateID: "a", path: "parent/target", object: 1,
        ancestorAccessPolicy: "changed"
      ),
      globalFacts()
    ),
    (
      snapshot(
        candidateID: "a", path: "parent/target", object: 1, ancestorACLByte: 94
      ),
      globalFacts()
    ),
    (
      snapshot(
        candidateID: "a", path: "parent/target", object: 1,
        providerBoundary: .fileProviderManaged
      ),
      globalFacts()
    ),
    (
      snapshot(
        candidateID: "a", path: "parent/target", object: 1,
        mountIdentity: "mount-2"
      ),
      globalFacts()
    ),
    (
      snapshot(
        candidateID: "a", path: "parent/target", object: 1,
        targetAccessPolicy: "changed-target-policy"
      ),
      globalFacts()
    ),
    (
      snapshot(
        candidateID: "a", path: "parent/target", object: 1, contentDigestByte: 95
      ),
      globalFacts()
    ),
    (
      snapshot(
        candidateID: "a", path: "parent/target", object: 1, targetACLByte: 96
      ),
      globalFacts()
    ),
    (
      snapshot(
        candidateID: "a", path: "parent/target", object: 1,
        targetProviderState: .fileProviderManaged
      ),
      globalFacts()
    ),
  ]
  for (variantEvidence, facts) in variants {
    let variantAction = try makeAction(evidence: variantEvidence, facts: facts)
    let variantPlan = try makePlan(
      actions: [variantAction], evidence: [variantEvidence], facts: facts
    )
    #expect(variantEvidence.evidenceID != baseEvidence.evidenceID)
    #expect(variantAction.lineageID != baseAction.lineageID)
    #expect(variantAction.id != baseAction.id)
    #expect(variantPlan.planHash != basePlan.planHash)
  }
}

@Test
func planRequiresOneSemanticReferenceTimeAndExactGlobalFacts() throws {
  let facts101 = globalFacts(semanticReferenceTimeSeconds: 101)
  let evidence101 = snapshot(
    candidateID: "a", path: "a", object: 1, semanticReferenceTimeSeconds: 101
  )
  let action101 = try makeAction(evidence: evidence101, facts: facts101)
  #expect(throws: PolicyModelError.mixedPolicyOrSchemaVersion) {
    try makePlan(actions: [action101], evidence: [evidence101])
  }

  let evidence100 = snapshot(candidateID: "b", path: "b", object: 2)
  let action100 = try makeAction(evidence: evidence100)
  #expect(throws: PolicyModelError.mixedPolicyOrSchemaVersion) {
    try makePlan(
      actions: [action100, action101], evidence: [evidence100, evidence101], facts: facts101
    )
  }
}

@Test
func immutablePlanCanonicalizesFullEvidenceAndRejectsMixedOrMissingBindings() throws {
  let aEvidence = snapshot(candidateID: "a", path: "a", object: 1)
  let bEvidence = snapshot(candidateID: "b", path: "b", object: 2)
  let a = try makeAction(evidence: aEvidence)
  let b = try makeAction(evidence: bEvidence)
  let forward = try makePlan(actions: [a, b], evidence: [aEvidence, bEvidence])
  let reverse = try makePlan(actions: [b, a], evidence: [bEvidence, aEvidence])
  #expect(forward.planHash == reverse.planHash)
  #expect(
    forward.evidenceSnapshots.map(\.evidenceID) == reverse.evidenceSnapshots.map(\.evidenceID))

  #expect(throws: PolicyModelError.self) {
    try makePlan(actions: [a], evidence: [bEvidence])
  }
  let otherVersion = snapshot(
    candidateID: "other", path: "other", object: 3, policyVersion: "policy-2"
  )
  #expect(throws: PolicyModelError.mixedPolicyOrSchemaVersion) {
    try makePlan(actions: [a], evidence: [aEvidence, otherVersion])
  }
}

@Test
func evidenceAndGlobalFactMutationsChangePlanHash() throws {
  let firstEvidence = snapshot(candidateID: "a", path: "a", object: 1)
  let changedEvidence = snapshot(candidateID: "a", path: "a", object: 1, activity: .active)
  let firstAction = try makeAction(evidence: firstEvidence)
  let changedAction = try makeAction(evidence: changedEvidence)
  let first = try makePlan(actions: [firstAction], evidence: [firstEvidence])
  let changed = try makePlan(actions: [changedAction], evidence: [changedEvidence])
  #expect(first.planHash != changed.planHash)

  let changedFacts = globalFacts(configuration: Data("changed".utf8))
  #expect(throws: PolicyModelError.mixedPolicyOrSchemaVersion) {
    try ImmutablePlan(
      policyVersion: "policy-1",
      schemaVersion: "schema-1",
      globalFacts: changedFacts,
      evidenceSnapshots: [firstEvidence],
      actions: [firstAction],
      releaseGraphBundle: nil
    )
  }
  let changedGlobalEvidence = snapshot(
    candidateID: "a", path: "a", object: 1,
    globalFactsConfiguration: Data("changed".utf8)
  )
  let changedGlobalAction = try makeAction(
    evidence: changedGlobalEvidence, facts: changedFacts
  )
  let changedGlobal = try ImmutablePlan(
    policyVersion: "policy-1",
    schemaVersion: "schema-1",
    globalFacts: changedFacts,
    evidenceSnapshots: [changedGlobalEvidence],
    actions: [changedGlobalAction],
    releaseGraphBundle: nil
  )
  #expect(first.planHash != changedGlobal.planHash)

  let duplicateCoverageFacts = FrozenGlobalFacts(
    captureID: digest(89),
    profile: "standard",
    configuration: Data("config".utf8),
    coverage: [
      GlobalCoverageFact(
        rawRoot: try! RawRootPath(absoluteBytes: Data("/root".utf8)),
        coverage: .complete,
        reasons: ["a"]
      ),
      GlobalCoverageFact(
        rawRoot: try! RawRootPath(absoluteBytes: Data("/root".utf8)),
        coverage: .partial,
        reasons: ["b"]
      ),
    ],
    semanticReferenceTimeSeconds: 100,
    policyVersion: "policy-1",
    schemaVersion: "schema-1"
  )
  #expect(throws: PolicyModelError.duplicateIdentifier) {
    try ImmutablePlan(
      policyVersion: "policy-1",
      schemaVersion: "schema-1",
      globalFacts: duplicateCoverageFacts,
      evidenceSnapshots: [firstEvidence],
      actions: [firstAction],
      releaseGraphBundle: nil
    )
  }
}

@Test
func planRejectsDanglingCyclesAndMismatchedPrerequisiteLineage() throws {
  let evidence = snapshot(candidateID: "a", path: "a", object: 1)
  let original = try makeAction(evidence: evidence)
  let unknown = ActionID(digest: digest(99))
  let dangling = forged(original, prerequisiteIDs: [unknown], lineageIDs: [])
  #expect(throws: PolicyModelError.danglingPrerequisite(unknown)) {
    try makePlan(actions: [dangling], evidence: [evidence])
  }

  let bEvidence = snapshot(candidateID: "b", path: "b", object: 2)
  let second = try makeAction(evidence: bEvidence)
  let cycleA = forged(original, prerequisiteIDs: [second.id], lineageIDs: [second.lineageID])
  let cycleB = forged(second, prerequisiteIDs: [original.id], lineageIDs: [original.lineageID])
  #expect(throws: PolicyModelError.actionCycle) {
    try makePlan(actions: [cycleA, cycleB], evidence: [evidence, bEvidence])
  }

  let dependent = try makeAction(evidence: bEvidence, prerequisites: [original])
  let badLineage = forged(
    dependent,
    prerequisiteIDs: dependent.prerequisiteActionIDs,
    lineageIDs: [dependent.lineageID]
  )
  #expect(throws: PolicyModelError.invalidActionBinding(dependent.id)) {
    try makePlan(actions: [original, badLineage], evidence: [evidence, bEvidence])
  }
}

@Test
func wideDagExecutionOrderingIsDeterministicAcrossInputPermutations() throws {
  let width = 256
  let sourceEvidence = (0..<width).map { index in
    snapshot(
      candidateID: "source-\(index)", path: "source-\(index)",
      object: UInt64(index + 100)
    )
  }
  let sources = try sourceEvidence.map { try makeAction(evidence: $0) }
  let leafEvidence = (0..<width).map { index in
    snapshot(
      candidateID: "leaf-\(index)", path: "leaf-\(index)",
      object: UInt64(index + width + 100)
    )
  }
  let leaves = try leafEvidence.enumerated().map { index, evidence in
    try makeAction(evidence: evidence, prerequisites: [sources[index]])
  }
  let actions = sources + leaves
  let plan = try makePlan(
    actions: Array(actions.reversed()), evidence: sourceEvidence + leafEvidence)
  let forward = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: actions.map(\.id),
    waiverConsents: [],
    userNotes: []
  )
  let reverse = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: actions.reversed().map(\.id),
    waiverConsents: [],
    userNotes: []
  )
  let forwardIDs = try DecisionOverlayValidator.validate(forward, against: plan)
    .executionSteps.map(\.action.id)
  let reverseIDs = try DecisionOverlayValidator.validate(reverse, against: plan)
    .executionSteps.map(\.action.id)
  #expect(forwardIDs == reverseIDs)
  let orderedIndex = Dictionary(uniqueKeysWithValues: forwardIDs.enumerated().map { ($0.1, $0.0) })
  for index in 0..<width {
    let sourceIndex = try #require(orderedIndex[sources[index].id])
    let leafIndex = try #require(orderedIndex[leaves[index].id])
    #expect(sourceIndex < leafIndex)
  }
}

@Test
func planReleaseSetBuildsOnlyFromCompleteEvaluatedGraph() throws {
  let graph = try completeStorageGraph()
  let evaluated = try evaluateGraph(graph, selectedCandidateIDs: ["a", "b"])
  let aEvidence = snapshot(candidateID: "a", path: "a", object: 1)
  let bEvidence = snapshot(candidateID: "b", path: "b", object: 2)
  let a = try makeAction(evidence: aEvidence)
  let b = try makeAction(evidence: bEvidence)
  let releaseBundle = try PlanReleaseSet.buildAll(
    from: evaluated, candidateActions: actionBindings([("a", a), ("b", b)])
  )
  let release = try #require(releaseBundle.releaseSets.first)
  #expect(release.ownerCandidateIDs == ["a", "b"])
  #expect(release.conditionalReclaimBytes == 100)
  #expect(release.graphDigest == graph.graphDigest)
  #expect(release.topologyExpectation.fileObjects.count == 2)
  #expect(release.owners.first?.evidence.evidenceID == aEvidence.evidenceID)

  let incomplete = try evaluateGraph(
    try replaceGroup(graph, snapshot: .known(true)), selectedCandidateIDs: ["a", "b"]
  )
  #expect(throws: PolicyModelError.self) {
    try PlanReleaseSet.buildAll(
      from: incomplete, candidateActions: actionBindings([("a", a), ("b", b)])
    )
  }
  #expect(try replaceGroup(graph, refCount: .known(3)).graphDigest != graph.graphDigest)

  let wrongAEvidence = snapshot(
    candidateID: "a", path: "a", object: 1, rootObject: 999
  )
  let wrongA = try makeAction(evidence: wrongAEvidence)
  #expect(throws: PolicyModelError.incompleteReleaseGraph) {
    try PlanReleaseSet.buildAll(
      from: evaluated, candidateActions: actionBindings([("a", wrongA), ("b", b)])
    )
  }

  let alternateA = try makeAction(evidence: aEvidence, prerequisites: [b])
  #expect(alternateA.id != a.id)
  #expect(throws: PolicyModelError.incompleteReleaseGraph) {
    try PlanReleaseSet.buildAll(
      from: evaluated, candidateActions: actionBindings([("a", alternateA), ("b", b)])
    )
  }

  let overflowGraph = try StorageReleaseGraph(
    globalFacts: globalFacts(),
    candidates: [
      storageCandidate("a", ["a"], UInt64.max),
      storageCandidate("b", ["b"], 1),
    ],
    fileObjects: [],
    allocationGroups: []
  )
  let overflowEvaluation = try evaluateGraph(
    overflowGraph, selectedCandidateIDs: ["a", "b"]
  )
  guard case .failed = overflowEvaluation.immediatePrivateReclaimBytes else {
    Issue.record("expected overflow to remain typed failure")
    return
  }
  #expect(throws: PolicyModelError.incompleteReleaseGraph) {
    try PlanReleaseSet.buildAll(
      from: overflowEvaluation, candidateActions: actionBindings([("a", a), ("b", b)])
    )
  }

  let maxCandidate = storageCandidate("a", ["a"], UInt64.max)
  let zeroCandidate = storageCandidate("b", ["b"], 0)
  let crossBucketGraph = try StorageReleaseGraph(
    globalFacts: globalFacts(),
    candidates: [maxCandidate, zeroCandidate],
    fileObjects: [
      FileObjectNode(
        provenance: graphProvenance(),
        id: "max-file",
        observedOwners: [FileOwnerLink(candidateID: "a", path: maxCandidate.target)],
        linkCount: .known(1)
      ),
      FileObjectNode(
        provenance: graphProvenance(),
        id: "zero-file",
        observedOwners: [FileOwnerLink(candidateID: "b", path: zeroCandidate.target)],
        linkCount: .known(1)
      ),
    ],
    allocationGroups: [
      allocationGroup("one-byte-shared", owners: ["max-file", "zero-file"], refCount: 2, bytes: 1)
    ]
  )
  let crossBucketEvaluation = try evaluateGraph(
    crossBucketGraph, selectedCandidateIDs: ["a", "b"]
  )
  #expect(crossBucketEvaluation.immediatePrivateReclaimBytes == .known(UInt64.max))
  #expect(crossBucketEvaluation.conditionalGroupReclaimBytes == .known(1))
  #expect(throws: PolicyModelError.incompleteReleaseGraph) {
    try PlanReleaseSet.buildAll(
      from: crossBucketEvaluation, candidateActions: actionBindings([("a", a), ("b", b)])
    )
  }
}

@Test
func completeReleaseActionRequiresExactVerifiedPlanReleaseSetBinding() throws {
  let graph = try completeStorageGraph(includeReleaseActionScope: true)
  let aEvidence = try #require(graph.candidates.first { $0.id == "a" }?.evidence)
  let bEvidence = try #require(graph.candidates.first { $0.id == "b" }?.evidence)
  let a = try makeAction(evidence: aEvidence, facts: graph.globalFacts)
  let b = try makeAction(evidence: bEvidence, facts: graph.globalFacts)
  let evaluated = try graph.evaluate(
    selectedCandidateActions: actionBindings([("a", a), ("b", b)])
  )
  let releaseBundle = try PlanReleaseSet.buildAll(
    from: evaluated,
    candidateActions: actionBindings([("a", a), ("b", b)])
  )
  let release = try #require(releaseBundle.releaseSets.first)
  let releaseAction = try makeAction(
    evidence: aEvidence,
    facts: graph.globalFacts,
    prerequisites: [a, b],
    request: .completeReleaseSetRemove(binding: release.actionBinding)
  )
  let plan = try makePlan(
    actions: [a, b, releaseAction],
    evidence: [aEvidence, bEvidence],
    facts: graph.globalFacts,
    releaseGraphBundle: releaseBundle
  )
  #expect(plan.releaseSets == [release])

  #expect(throws: PolicyModelError.invalidActionContract) {
    try makeAction(
      evidence: aEvidence,
      facts: graph.globalFacts,
      request: .completeReleaseSetRemove(binding: release.actionBinding)
    )
  }

  #expect(throws: PolicyModelError.incompleteReleaseGraph) {
    try makePlan(
      actions: [a, b, releaseAction],
      evidence: [aEvidence, bEvidence],
      facts: graph.globalFacts,
      releaseGraphBundle: nil
    )
  }

  let changedGraph = try replaceGroup(graph, sharedBytes: .known(101))
  let changedEvaluation = try changedGraph.evaluate(
    selectedCandidateActions: actionBindings([("a", a), ("b", b)])
  )
  let changedBundle = try PlanReleaseSet.buildAll(
    from: changedEvaluation,
    candidateActions: actionBindings([("a", a), ("b", b)])
  )
  let changedRelease = try #require(changedBundle.releaseSets.first)
  let unmatchedAction = try makeAction(
    evidence: aEvidence,
    facts: graph.globalFacts,
    prerequisites: [a, b],
    request: .completeReleaseSetRemove(binding: changedRelease.actionBinding)
  )
  #expect(throws: PolicyModelError.incompleteReleaseGraph) {
    try makePlan(
      actions: [a, b, unmatchedAction],
      evidence: [aEvidence, bEvidence],
      facts: graph.globalFacts,
      releaseGraphBundle: releaseBundle
    )
  }

  let missingOwners = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: [releaseAction.id],
    waiverConsents: [],
    userNotes: []
  )
  #expect(throws: PolicyModelError.self) {
    try DecisionOverlayValidator.validate(missingOwners, against: plan)
  }
  let fullSelection = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: [a.id, b.id, releaseAction.id],
    waiverConsents: [],
    userNotes: []
  )
  let validated = try DecisionOverlayValidator.validate(fullSelection, against: plan)
  #expect(validated.selectedActions.count == 3)
  #expect(validated.executionSteps.map(\.action) == [releaseAction])
  #expect(
    validated.executionSteps.first?.jitRevalidationActions
      == [a, b, releaseAction].sorted {
        $0.id < $1.id
      })
  #expect(validated.executionSteps.first?.prerequisiteStepActionIDs == [])
  #expect(validated.executionSteps.first?.releaseGraphManifest == releaseBundle.manifest)
  #expect(validated.activatedReleaseSets == [release])
}

@Test
func completeReleaseBuildersRejectNonOwnerAndMismatchedOwnerAnchors() throws {
  let graph = try completeStorageGraph(includeReleaseActionScope: true)
  let aEvidence = try #require(graph.candidates.first { $0.id == "a" }?.evidence)
  let bEvidence = try #require(graph.candidates.first { $0.id == "b" }?.evidence)
  let a = try makeAction(evidence: aEvidence, facts: graph.globalFacts)
  let b = try makeAction(evidence: bEvidence, facts: graph.globalFacts)
  let bindings = actionBindings([("a", a), ("b", b)])
  let bundle = try PlanReleaseSet.buildAll(
    from: graph.evaluate(selectedCandidateActions: bindings),
    candidateActions: bindings
  )
  let release = try #require(bundle.releaseSets.first)
  let outsiderEvidence = snapshot(
    candidateID: "outsider", path: "outsider", object: 3,
    additionalAdapterScopes: [
      .completeReleaseSetRemove(allocationGroupID: release.allocationGroupID)
    ],
    globalFactsOverride: graph.globalFacts
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try ActionPrototype.build(
      request: .completeReleaseSetRemove(binding: release.actionBinding),
      evidence: outsiderEvidence
    )
  }

  let prototype = try ActionPrototype.build(
    request: .completeReleaseSetRemove(binding: release.actionBinding),
    evidence: aEvidence
  )
  let forgedAnchor = ActionDefinition(
    lineageID: a.lineageID,
    id: a.id,
    prototype: try genericPrototype(outsiderEvidence),
    evidence: outsiderEvidence,
    globalFactsHash: a.globalFactsHash,
    prerequisiteLineageIDs: [],
    prerequisiteActionIDs: [],
    evaluation: try bindEvaluation(
      allowEvaluation(), evidence: outsiderEvidence, facts: graph.globalFacts),
    displayMetrics: metrics(path: "outsider")
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try ActionDefinition.build(
      prototype: prototype,
      evidence: aEvidence,
      globalFacts: graph.globalFacts,
      prerequisites: [forgedAnchor, b],
      evaluation: try bindEvaluation(
        allowEvaluation(), evidence: aEvidence, facts: graph.globalFacts),
      displayMetrics: metrics(path: "a")
    )
  }
}

@Test
func actionBuilderRejectsPrerequisiteLineageMultiplicity() throws {
  let firstEvidence = snapshot(candidateID: "first", path: "shared", object: 11)
  let secondEvidence = snapshot(candidateID: "second", path: "shared", object: 11)
  let dependentEvidence = snapshot(candidateID: "dependent", path: "dependent", object: 12)
  let first = try makeAction(evidence: firstEvidence)
  let second = try makeAction(evidence: secondEvidence)
  #expect(first.id != second.id)
  #expect(first.lineageID == second.lineageID)
  #expect(throws: PolicyModelError.invalidActionContract) {
    try makeAction(evidence: dependentEvidence, prerequisites: [first, second])
  }
  #expect(throws: PolicyModelError.invalidActionContract) {
    try makeAction(evidence: dependentEvidence, prerequisites: [first, first])
  }
}

@Test
func releaseGraphManifestRejectsSlicesMixesDuplicatesAndMissingGroups() throws {
  let graph = try twoGroupStorageGraph()
  let actions = try graph.candidates.map {
    try makeAction(evidence: $0.evidence, facts: graph.globalFacts)
  }
  let bindings = zip(graph.candidates, actions).map { pair in
    CandidateActionBinding(candidateID: pair.0.id, action: pair.1)
  }
  let evaluation = try graph.evaluate(selectedCandidateActions: bindings)
  let bundle = try PlanReleaseSet.buildAll(
    from: evaluation, candidateActions: bindings
  )
  let reversedBundle = try PlanReleaseSet.buildAll(
    from: graph.evaluate(selectedCandidateActions: Array(bindings.reversed())),
    candidateActions: Array(bindings.reversed())
  )
  #expect(bundle == reversedBundle)
  #expect(bundle.manifest.allocationGroupIDs == ["group-one", "group-two"])
  #expect(bundle.manifest.allocationGroupCount == 2)
  #expect(bundle.manifest.candidateActions.map(\.candidateID) == ["a", "b", "c", "d"])
  #expect(bundle.manifest.connectedComponents.count == 2)
  _ = try makePlan(
    actions: actions,
    evidence: graph.candidates.map(\.evidence),
    facts: graph.globalFacts,
    releaseGraphBundle: bundle
  )

  let first = try #require(bundle.releaseSets.first)
  let last = try #require(bundle.releaseSets.last)
  let sliced = PlanReleaseGraphBundle(
    uncheckedManifest: bundle.manifest, releaseSets: [first]
  )
  #expect(throws: PolicyModelError.incompleteReleaseGraph) {
    try makePlan(
      actions: actions,
      evidence: graph.candidates.map(\.evidence),
      facts: graph.globalFacts,
      releaseGraphBundle: sliced
    )
  }

  let missing = PlanReleaseGraphBundle(
    uncheckedManifest: bundle.manifest, releaseSets: [last]
  )
  #expect(throws: PolicyModelError.incompleteReleaseGraph) {
    try makePlan(
      actions: actions,
      evidence: graph.candidates.map(\.evidence),
      facts: graph.globalFacts,
      releaseGraphBundle: missing
    )
  }

  let duplicated = PlanReleaseGraphBundle(
    uncheckedManifest: bundle.manifest, releaseSets: [first, first, last]
  )
  #expect(throws: PolicyModelError.duplicateIdentifier) {
    try makePlan(
      actions: actions,
      evidence: graph.candidates.map(\.evidence),
      facts: graph.globalFacts,
      releaseGraphBundle: duplicated
    )
  }

  let secondGroup = graph.allocationGroups[1]
  let changedSecondGroup = AllocationGroupNode(
    provenance: secondGroup.provenance,
    id: secondGroup.id,
    ownerFileObjectIDs: secondGroup.ownerFileObjectIDs,
    cloneRefCount: secondGroup.cloneRefCount,
    sharedBytes: .known(201),
    snapshotBlocker: secondGroup.snapshotBlocker
  )
  let changedGraph = try StorageReleaseGraph(
    globalFacts: graph.globalFacts,
    candidates: graph.candidates,
    fileObjects: graph.fileObjects,
    allocationGroups: [graph.allocationGroups[0], changedSecondGroup]
  )
  let changedEvaluation = try changedGraph.evaluate(selectedCandidateActions: bindings)
  let changedBundle = try PlanReleaseSet.buildAll(
    from: changedEvaluation, candidateActions: bindings
  )
  let mixed = PlanReleaseGraphBundle(
    uncheckedManifest: bundle.manifest,
    releaseSets: [first, try #require(changedBundle.releaseSets.last)]
  )
  #expect(throws: PolicyModelError.incompleteReleaseGraph) {
    try makePlan(
      actions: actions,
      evidence: graph.candidates.map(\.evidence),
      facts: graph.globalFacts,
      releaseGraphBundle: mixed
    )
  }

  let originalA = try #require(actions.first { $0.evidence.candidateID == "a" })
  let originalB = try #require(actions.first { $0.evidence.candidateID == "b" })
  let alternateA = try makeAction(
    evidence: originalA.evidence,
    facts: graph.globalFacts,
    prerequisites: [originalB]
  )
  let alternateBindings = bindings.map { binding in
    binding.candidateID == "a"
      ? CandidateActionBinding(candidateID: "a", action: alternateA) : binding
  }
  let alternateBundle = try PlanReleaseSet.buildAll(
    from: graph.evaluate(selectedCandidateActions: alternateBindings),
    candidateActions: alternateBindings
  )
  let mismatchedCandidateMap = PlanReleaseGraphBundle(
    uncheckedManifest: alternateBundle.manifest,
    releaseSets: bundle.releaseSets
  )
  #expect(throws: PolicyModelError.incompleteReleaseGraph) {
    try makePlan(
      actions: actions + [alternateA],
      evidence: graph.candidates.map(\.evidence),
      facts: graph.globalFacts,
      releaseGraphBundle: mismatchedCandidateMap
    )
  }
}

@Test
func releaseManifestBindsPrivateOnlyCandidatesToTheirEvaluatedActionIDs() throws {
  let base = try completeStorageGraph()
  let privateOnly = storageCandidate("c", ["c"], 30)
  let graph = try StorageReleaseGraph(
    globalFacts: base.globalFacts,
    candidates: base.candidates + [privateOnly],
    fileObjects: base.fileObjects,
    allocationGroups: base.allocationGroups
  )
  let actions = try graph.candidates.map {
    try makeAction(evidence: $0.evidence, facts: graph.globalFacts)
  }
  let bindings = zip(graph.candidates, actions).map { pair in
    CandidateActionBinding(candidateID: pair.0.id, action: pair.1)
  }
  let evaluation = try graph.evaluate(selectedCandidateActions: bindings)
  let bundle = try PlanReleaseSet.buildAll(
    from: evaluation, candidateActions: bindings
  )
  #expect(bundle.manifest.candidateActions.map(\.candidateID) == ["a", "b", "c"])

  let omittedEvaluation = try graph.evaluate(
    selectedCandidateActions: Array(bindings.prefix(2))
  )
  #expect(throws: PolicyModelError.incompleteReleaseGraph) {
    try PlanReleaseSet.buildAll(from: omittedEvaluation, candidateActions: bindings)
  }

  let originalA = actions[0]
  let originalC = actions[2]
  let alternateC = try makeAction(
    evidence: originalC.evidence,
    facts: graph.globalFacts,
    prerequisites: [originalA]
  )
  let substitutedBindings = bindings.map { binding in
    binding.candidateID == "c"
      ? CandidateActionBinding(candidateID: "c", action: alternateC) : binding
  }
  #expect(throws: PolicyModelError.incompleteReleaseGraph) {
    try PlanReleaseSet.buildAll(
      from: evaluation, candidateActions: substitutedBindings
    )
  }

  let blockedSource = snapshot(
    candidateID: "blocked-source", path: "blocked-source", object: 99,
    explicitProtection: .known(.protected)
  )
  let blockedSourceAction = try makeAction(evidence: blockedSource)
  let blockedC = ActionDefinition(
    lineageID: alternateC.lineageID,
    id: alternateC.id,
    prototype: alternateC.prototype,
    evidence: alternateC.evidence,
    globalFactsHash: alternateC.globalFactsHash,
    prerequisiteLineageIDs: alternateC.prerequisiteLineageIDs,
    prerequisiteActionIDs: alternateC.prerequisiteActionIDs,
    evaluation: blockedSourceAction.evaluation,
    displayMetrics: alternateC.displayMetrics
  )
  let blockedBindings = bindings.map { binding in
    binding.candidateID == "c"
      ? CandidateActionBinding(candidateID: "c", action: blockedC) : binding
  }
  let blockedGraphEvaluation = try graph.evaluate(
    selectedCandidateActions: blockedBindings
  )
  #expect(throws: PolicyModelError.incompleteReleaseGraph) {
    try PlanReleaseSet.buildAll(
      from: blockedGraphEvaluation, candidateActions: blockedBindings
    )
  }
}

@Test
func fullReleaseManifestAllowsAggregateActionsForOnlyOneVerifiedGroup() throws {
  let graph = try twoGroupStorageGraph()
  let actions = try graph.candidates.map {
    try makeAction(evidence: $0.evidence, facts: graph.globalFacts)
  }
  let bindings = zip(graph.candidates, actions).map { pair in
    CandidateActionBinding(candidateID: pair.0.id, action: pair.1)
  }
  let bundle = try PlanReleaseSet.buildAll(
    from: graph.evaluate(selectedCandidateActions: bindings),
    candidateActions: bindings
  )
  let firstRelease = try #require(
    bundle.releaseSets.first { $0.allocationGroupID == "group-one" }
  )
  let ownerActions = actions.filter { firstRelease.ownerActionIDs.contains($0.id) }
  let anchor = try #require(ownerActions.first { $0.evidence.candidateID == "a" })
  let aggregate = try makeAction(
    evidence: anchor.evidence,
    facts: graph.globalFacts,
    prerequisites: ownerActions,
    request: .completeReleaseSetRemove(binding: firstRelease.actionBinding)
  )
  let plan = try makePlan(
    actions: actions + [aggregate],
    evidence: graph.candidates.map(\.evidence),
    facts: graph.globalFacts,
    releaseGraphBundle: bundle
  )
  let overlay = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: firstRelease.ownerActionIDs + [aggregate.id],
    waiverConsents: [],
    userNotes: []
  )
  let validated = try DecisionOverlayValidator.validate(overlay, against: plan)
  #expect(validated.activatedReleaseSets == [firstRelease])
  #expect(validated.executionSteps.map(\.action) == [aggregate])
  #expect(validated.executionSteps.first?.releaseGraphManifest == bundle.manifest)
}

@Test
func overlappingReleaseSetsExecuteAsOneCompleteComponent() throws {
  let graph = try overlappingReleaseComponentGraph()
  let owners = try graph.candidates.map {
    try makeAction(evidence: $0.evidence, facts: graph.globalFacts)
  }
  let bindings = zip(graph.candidates, owners).map { pair in
    CandidateActionBinding(candidateID: pair.0.id, action: pair.1)
  }
  let bundle = try PlanReleaseSet.buildAll(
    from: graph.evaluate(selectedCandidateActions: bindings),
    candidateActions: bindings
  )
  let aggregates = try bundle.releaseSets.map { release -> ActionDefinition in
    let releaseOwners = owners.filter { release.ownerActionIDs.contains($0.id) }
    let anchorID = release.allocationGroupID == "group-one" ? "b" : "c"
    let anchor = try #require(releaseOwners.first { $0.evidence.candidateID == anchorID })
    return try makeAction(
      evidence: anchor.evidence,
      facts: graph.globalFacts,
      prerequisites: releaseOwners,
      request: .completeReleaseSetRemove(binding: release.actionBinding)
    )
  }
  let plan = try makePlan(
    actions: owners + aggregates,
    evidence: graph.candidates.map(\.evidence),
    facts: graph.globalFacts,
    releaseGraphBundle: bundle
  )
  let full = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: (owners + aggregates).map(\.id),
    waiverConsents: [],
    userNotes: []
  )
  let validated = try DecisionOverlayValidator.validate(full, against: plan)
  let step = try #require(validated.executionSteps.first)
  #expect(validated.executionSteps.count == 1)
  #expect(step.componentActions == aggregates.sorted { $0.id < $1.id })
  #expect(step.releaseSet == nil)
  #expect(step.releaseSets == bundle.releaseSets)
  #expect(step.jitRevalidationActions == (owners + aggregates).sorted { $0.id < $1.id })
  #expect(validated.activatedReleaseSets == bundle.releaseSets)

  let partial = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: owners.map(\.id) + [aggregates[0].id],
    waiverConsents: [],
    userNotes: []
  )
  #expect(throws: PolicyModelError.incompleteReleaseGraph) {
    try DecisionOverlayValidator.validate(partial, against: plan)
  }
}

@Test
func releaseComponentManifestScalesForOneOwnerAcrossManyGroups() throws {
  let groupCount = 512
  let graph = try manyConnectedReleaseGroupsGraph(groupCount: groupCount)
  let owner = try makeAction(
    evidence: try #require(graph.candidates.first?.evidence),
    facts: graph.globalFacts
  )
  let bindings = [CandidateActionBinding(candidateID: "owner", action: owner)]
  let bundle = try PlanReleaseSet.buildAll(
    from: graph.evaluate(selectedCandidateActions: bindings),
    candidateActions: bindings
  )
  let component = try #require(bundle.manifest.connectedComponents.first)
  #expect(bundle.releaseSets.count == groupCount)
  #expect(bundle.manifest.connectedComponents.count == 1)
  #expect(component.allocationGroupIDs.count == groupCount)
  #expect(component.candidateIDs == ["owner"])
}

@Test
func completeReleasePlanRejectsLeaveAndReenterContraction() throws {
  let graph = try releaseContractionGraph()
  let actionByCandidate = try contractionCandidateActions(graph: graph)
  let bindings = graph.candidates.map {
    CandidateActionBinding(candidateID: $0.id, action: actionByCandidate[$0.id]!)
  }
  let bundle = try PlanReleaseSet.buildAll(
    from: graph.evaluate(selectedCandidateActions: bindings),
    candidateActions: bindings
  )
  let release = try #require(bundle.releaseSets.first)
  let owners = release.ownerCandidateIDs.map { actionByCandidate[$0]! }
  let anchor = try #require(owners.first { $0.evidence.candidateID == "a" })
  let aggregate = try makeAction(
    evidence: anchor.evidence,
    facts: graph.globalFacts,
    prerequisites: owners,
    request: .completeReleaseSetRemove(binding: release.actionBinding)
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try makePlan(
      actions: Array(actionByCandidate.values) + [aggregate],
      evidence: graph.candidates.map(\.evidence),
      facts: graph.globalFacts,
      releaseGraphBundle: bundle
    )
  }
}

@Test
func disjointReleaseContractionsPreserveCrossComponentPrerequisites() throws {
  let graph = try crossComponentReleaseGraph()
  let actionByCandidate = try crossComponentCandidateActions(graph: graph)
  let bindings = graph.candidates.map {
    CandidateActionBinding(candidateID: $0.id, action: actionByCandidate[$0.id]!)
  }
  let bundle = try PlanReleaseSet.buildAll(
    from: graph.evaluate(selectedCandidateActions: bindings),
    candidateActions: bindings
  )
  let aggregates = try bundle.releaseSets.map { release -> ActionDefinition in
    let owners = release.ownerCandidateIDs.map { actionByCandidate[$0]! }
    let anchorCandidateID = release.allocationGroupID == "group-one" ? "a" : "c"
    let anchor = try #require(
      owners.first { $0.evidence.candidateID == anchorCandidateID })
    return try makeAction(
      evidence: anchor.evidence,
      facts: graph.globalFacts,
      prerequisites: owners,
      request: .completeReleaseSetRemove(binding: release.actionBinding)
    )
  }
  let plan = try makePlan(
    actions: Array(actionByCandidate.values) + aggregates,
    evidence: graph.candidates.map(\.evidence),
    facts: graph.globalFacts,
    releaseGraphBundle: bundle
  )
  let overlay = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: plan.actions.map(\.id),
    waiverConsents: [],
    userNotes: []
  )
  let validated = try DecisionOverlayValidator.validate(overlay, against: plan)
  let x = try #require(actionByCandidate["x"])
  let xIndex = try #require(validated.executionSteps.firstIndex { $0.action.id == x.id })
  let componentIndices = validated.executionSteps.indices.filter {
    !validated.executionSteps[$0].releaseSets.isEmpty
  }
  #expect(componentIndices.count == 2)
  #expect(try #require(componentIndices.first) < xIndex)
  #expect(xIndex < (try #require(componentIndices.last)))
}

@Test
func simultaneousReleaseContractionsRejectCrossComponentCycle() throws {
  let graph = try twoGroupStorageGraph()
  let evidenceByCandidate = Dictionary(
    uniqueKeysWithValues: graph.candidates.map { ($0.id, $0.evidence) })
  let a = try makeAction(
    evidence: evidenceByCandidate["a"]!, facts: graph.globalFacts)
  let d = try makeAction(
    evidence: evidenceByCandidate["d"]!, facts: graph.globalFacts)
  let c = try makeAction(
    evidence: evidenceByCandidate["c"]!, facts: graph.globalFacts,
    prerequisites: [a]
  )
  let b = try makeAction(
    evidence: evidenceByCandidate["b"]!, facts: graph.globalFacts,
    prerequisites: [d]
  )
  let actionByCandidate = ["a": a, "b": b, "c": c, "d": d]
  let bindings = graph.candidates.map {
    CandidateActionBinding(candidateID: $0.id, action: actionByCandidate[$0.id]!)
  }
  let bundle = try PlanReleaseSet.buildAll(
    from: graph.evaluate(selectedCandidateActions: bindings),
    candidateActions: bindings
  )
  let aggregates = try bundle.releaseSets.map { release -> ActionDefinition in
    let owners = release.ownerCandidateIDs.map { actionByCandidate[$0]! }
    let anchorCandidateID = release.allocationGroupID == "group-one" ? "a" : "c"
    let anchor = try #require(
      owners.first { $0.evidence.candidateID == anchorCandidateID })
    return try makeAction(
      evidence: anchor.evidence,
      facts: graph.globalFacts,
      prerequisites: owners,
      request: .completeReleaseSetRemove(binding: release.actionBinding)
    )
  }
  let plan = try makePlan(
    actions: Array(actionByCandidate.values) + aggregates,
    evidence: graph.candidates.map(\.evidence),
    facts: graph.globalFacts,
    releaseGraphBundle: bundle
  )
  let overlay = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: plan.actions.map(\.id),
    waiverConsents: [],
    userNotes: []
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try DecisionOverlayValidator.validate(overlay, against: plan)
  }
}

@Test
func completeReleaseLineageIgnoresReferenceEpochButBindsSemanticTopology() throws {
  func aggregateAction(
    facts: FrozenGlobalFacts,
    changedTopology: Bool
  ) throws -> ActionDefinition {
    let original = try completeStorageGraph(
      includeReleaseActionScope: true, facts: facts
    )
    let graph: StorageReleaseGraph
    if changedTopology {
      let changedFiles = original.fileObjects.map { file -> FileObjectNode in
        guard file.id == "file-a" else { return file }
        return FileObjectNode(
          provenance: file.provenance,
          id: "file-a-v2",
          observedOwners: file.observedOwners,
          linkCount: file.linkCount
        )
      }
      let originalGroup = original.allocationGroups[0]
      let changedGroup = AllocationGroupNode(
        provenance: originalGroup.provenance,
        id: originalGroup.id,
        ownerFileObjectIDs: originalGroup.ownerFileObjectIDs.map {
          $0 == "file-a" ? "file-a-v2" : $0
        },
        cloneRefCount: originalGroup.cloneRefCount,
        sharedBytes: originalGroup.sharedBytes,
        snapshotBlocker: originalGroup.snapshotBlocker
      )
      graph = try StorageReleaseGraph(
        globalFacts: facts,
        candidates: original.candidates,
        fileObjects: changedFiles,
        allocationGroups: [changedGroup]
      )
    } else {
      graph = original
    }
    let ownerActions = try graph.candidates.map {
      try makeAction(evidence: $0.evidence, facts: facts)
    }
    let bindings = zip(graph.candidates, ownerActions).map { pair in
      CandidateActionBinding(candidateID: pair.0.id, action: pair.1)
    }
    let bundle = try PlanReleaseSet.buildAll(
      from: graph.evaluate(selectedCandidateActions: bindings),
      candidateActions: bindings
    )
    let release = try #require(bundle.releaseSets.first)
    let anchor = try #require(ownerActions.first { $0.evidence.candidateID == "a" })
    return try makeAction(
      evidence: anchor.evidence,
      facts: facts,
      prerequisites: ownerActions,
      request: .completeReleaseSetRemove(binding: release.actionBinding)
    )
  }

  let epoch100 = try aggregateAction(
    facts: globalFacts(semanticReferenceTimeSeconds: 100),
    changedTopology: false
  )
  let epoch101 = try aggregateAction(
    facts: globalFacts(semanticReferenceTimeSeconds: 101),
    changedTopology: false
  )
  #expect(epoch100.lineageID == epoch101.lineageID)
  #expect(epoch100.id != epoch101.id)

  let changedTopology = try aggregateAction(
    facts: globalFacts(semanticReferenceTimeSeconds: 101),
    changedTopology: true
  )
  #expect(epoch101.lineageID != changedTopology.lineageID)
}

@Test
func releaseTopologyEncodingCanonicalizesEquivalentArrayOrders() throws {
  let firstPath = try RawTargetPath(components: [Data("a".utf8)])
  let secondPath = try RawTargetPath(components: [Data("b".utf8)])
  let owners = [
    FileOwnerLink(candidateID: "a", path: firstPath),
    FileOwnerLink(candidateID: "b", path: secondPath),
  ]
  let first = FileTopologyExpectation(
    fileObjectID: "first", owners: owners, linkCount: .known(2)
  )
  let second = FileTopologyExpectation(
    fileObjectID: "second", owners: Array(owners.reversed()), linkCount: .known(2)
  )
  let forward = ReleaseTopologyExpectation(
    allocationGroupID: "group",
    fileObjects: [first, second],
    cloneRefCount: .known(4),
    sharedBytes: .known(100),
    snapshotBlocker: .known(false)
  )
  let reverse = ReleaseTopologyExpectation(
    allocationGroupID: "group",
    fileObjects: [second, first],
    cloneRefCount: .known(4),
    sharedBytes: .known(100),
    snapshotBlocker: .known(false)
  )
  #expect(encodeReleaseTopologyExpectation(forward) == encodeReleaseTopologyExpectation(reverse))
}

@Test
func overlayHashBindsVersionsSelectionsConsentsAndNotes() throws {
  let evidence = snapshot(candidateID: "a", path: "a", object: 1)
  let action = try makeAction(evidence: evidence)
  let plan = try makePlan(actions: [action], evidence: [evidence])
  let first = DecisionOverlay.create(
    plan: plan, selectedActionIDs: [action.id], waiverConsents: [], userNotes: ["first"]
  )
  let second = DecisionOverlay.create(
    plan: plan, selectedActionIDs: [action.id], waiverConsents: [], userNotes: ["second"]
  )
  #expect(first.overlayHash != second.overlayHash)
  #expect(try DecisionOverlayValidator.validate(first, against: plan).selectedActions == [action])

  let tampered = rawOverlay(first, notes: ["tampered"])
  #expect(throws: PolicyModelError.invalidOverlayHash) {
    try DecisionOverlayValidator.validate(tampered, against: plan)
  }
  let wrongVersion = rawOverlay(first, bindingVersion: "decision-overlay-v2")
  #expect(throws: PolicyModelError.invalidOverlayVersion) {
    try DecisionOverlayValidator.validate(wrongVersion, against: plan)
  }
}

@Test
func overlayRejectsInjectedStaleBlockedAndMissingPrerequisiteSelections() throws {
  let aEvidence = snapshot(candidateID: "a", path: "a", object: 1)
  let bEvidence = snapshot(candidateID: "b", path: "b", object: 2)
  let a = try makeAction(evidence: aEvidence)
  let dependent = try makeAction(evidence: bEvidence, prerequisites: [a])
  let blockedEvidence = snapshot(
    candidateID: "blocked", path: "blocked", object: 3,
    explicitProtection: .known(.protected)
  )
  let blocked = try makeAction(evidence: blockedEvidence)
  let plan = try makePlan(
    actions: [a, dependent, blocked], evidence: [aEvidence, bEvidence, blocked.evidence]
  )
  let missing = DecisionOverlay.create(
    plan: plan, selectedActionIDs: [dependent.id], waiverConsents: [], userNotes: []
  )
  #expect(throws: PolicyModelError.missingPrerequisite(a.id)) {
    try DecisionOverlayValidator.validate(missing, against: plan)
  }
  let blockedOverlay = DecisionOverlay.create(
    plan: plan, selectedActionIDs: [blocked.id], waiverConsents: [], userNotes: []
  )
  #expect(throws: PolicyModelError.actionNotStageable(blocked.id)) {
    try DecisionOverlayValidator.validate(blockedOverlay, against: plan)
  }
  let injectedID = ActionID(digest: digest(88))
  let injected = DecisionOverlay.create(
    plan: plan, selectedActionIDs: [injectedID], waiverConsents: [], userNotes: []
  )
  #expect(throws: PolicyModelError.injectedSelection(injectedID)) {
    try DecisionOverlayValidator.validate(injected, against: plan)
  }
  let smallerInjectedID = ActionID(digest: digest(87))
  for ids in [[injectedID, smallerInjectedID], [smallerInjectedID, injectedID]] {
    let multipleInjected = DecisionOverlay.create(
      plan: plan, selectedActionIDs: ids, waiverConsents: [], userNotes: []
    )
    #expect(throws: PolicyModelError.injectedSelection(smallerInjectedID)) {
      try DecisionOverlayValidator.validate(multipleInjected, against: plan)
    }
  }

  let otherPlan = try makePlan(actions: [a], evidence: [aEvidence])
  let stale = DecisionOverlay.create(
    plan: otherPlan, selectedActionIDs: [a.id], waiverConsents: [], userNotes: []
  )
  #expect(throws: PolicyModelError.staleOverlay) {
    try DecisionOverlayValidator.validate(stale, against: plan)
  }
}

@Test
func overlayRejectsDuplicateSelectedLineageWithoutWaivers() throws {
  let firstEvidence = snapshot(candidateID: "a", path: "same", object: 1)
  let secondEvidence = snapshot(candidateID: "b", path: "same", object: 1)
  let first = try makeAction(evidence: firstEvidence)
  let second = try makeAction(evidence: secondEvidence)
  #expect(first.lineageID == second.lineageID)
  #expect(first.id != second.id)

  let plan = try makePlan(
    actions: [first, second], evidence: [firstEvidence, secondEvidence]
  )
  let overlay = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: [first.id, second.id],
    waiverConsents: [],
    userNotes: []
  )
  #expect(throws: PolicyModelError.ambiguousSelectedLineage(first.lineageID)) {
    try DecisionOverlayValidator.validate(overlay, against: plan)
  }
}

@Test
func overlayDiagnosticsChooseCanonicalLineageAndWaiverErrors() throws {
  let firstEvidence = snapshot(candidateID: "a", path: "first", object: 1)
  let secondEvidence = snapshot(candidateID: "b", path: "first", object: 1)
  let thirdEvidence = snapshot(candidateID: "c", path: "second", object: 2)
  let fourthEvidence = snapshot(candidateID: "d", path: "second", object: 2)
  let actions = try [firstEvidence, secondEvidence, thirdEvidence, fourthEvidence].map {
    try makeAction(evidence: $0)
  }
  #expect(actions[0].lineageID == actions[1].lineageID)
  #expect(actions[2].lineageID == actions[3].lineageID)
  let plan = try makePlan(
    actions: actions,
    evidence: [firstEvidence, secondEvidence, thirdEvidence, fourthEvidence]
  )
  let expectedLineage = min(actions[0].lineageID, actions[2].lineageID)
  for selected in [actions.map(\.id), actions.reversed().map(\.id)] {
    let overlay = DecisionOverlay.create(
      plan: plan, selectedActionIDs: selected, waiverConsents: [], userNotes: []
    )
    #expect(throws: PolicyModelError.ambiguousSelectedLineage(expectedLineage)) {
      try DecisionOverlayValidator.validate(overlay, against: plan)
    }
  }

  let stageableEvidence = snapshot(candidateID: "stageable", path: "stageable", object: 9)
  let stageable = try makeAction(evidence: stageableEvidence)
  let stageablePlan = try makePlan(actions: [stageable], evidence: [stageableEvidence])
  let predicates = [
    WaiverPredicate(
      kind: .normalKeepPolicy,
      predicate: "normal-keep",
      valueBucket: "known",
      semanticEvidenceHash: digest(92)
    ),
    WaiverPredicate(
      kind: .agentAssistedClassification,
      predicate: "classification",
      valueBucket: "known",
      semanticEvidenceHash: digest(93)
    ),
  ]
  let consents = predicates.enumerated().map { index, predicate in
    WaiverConsentCore.create(
      action: stageable,
      predicate: predicate,
      reason: "unexpected",
      consentEventID: "unexpected-\(index)"
    )
  }
  let expectedPredicate = try #require(predicates.min())
  for orderedConsents in [consents, Array(consents.reversed())] {
    let overlay = DecisionOverlay.create(
      plan: stageablePlan,
      selectedActionIDs: [stageable.id],
      waiverConsents: Array(orderedConsents),
      userNotes: []
    )
    #expect(throws: PolicyModelError.unexpectedWaiver(stageable.id, expectedPredicate.kind)) {
      try DecisionOverlayValidator.validate(overlay, against: stageablePlan)
    }
  }
}

@Test
func overlayRequiresEveryExactConsentNeverJustWaiverKind() throws {
  let first = WaiverPredicate(
    kind: .unknownRebuildCost,
    predicate: "unknown-rebuild-cost",
    valueBucket: "cost",
    semanticEvidenceHash: digest(1)
  )
  let second = WaiverPredicate(
    kind: .unknownRebuildCost,
    predicate: "unknown-rebuild-cost",
    valueBucket: "duration",
    semanticEvidenceHash: digest(2)
  )
  let evidence = snapshot(
    candidateID: "a", path: "a", object: 1,
    recoverability: .known(.reviewRequired),
    recoverabilityReviewFacts: [
      .unknownRebuildCost(valueBucket: "duration", evidenceHash: digest(2)),
      .unknownRebuildCost(valueBucket: "cost", evidenceHash: digest(1)),
    ]
  )
  let action = try makeAction(evidence: evidence)
  let plan = try makePlan(actions: [action], evidence: [evidence])
  let firstConsent = WaiverConsentCore.create(
    action: action, predicate: first, reason: "accept first", consentEventID: "event-1"
  )
  let incomplete = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: [action.id],
    waiverConsents: [firstConsent],
    userNotes: []
  )
  #expect(throws: PolicyModelError.invalidWaiverBinding(action.id, .unknownRebuildCost)) {
    try DecisionOverlayValidator.validate(incomplete, against: plan)
  }
  let secondConsent = WaiverConsentCore.create(
    action: action, predicate: second, reason: "accept second", consentEventID: "event-2"
  )
  let complete = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: [action.id],
    waiverConsents: [firstConsent, secondConsent],
    userNotes: []
  )
  let validated = try DecisionOverlayValidator.validate(complete, against: plan)
  #expect(validated.waiverConsents.count == 2)
  #expect(validated.epochRequirements.count == 2)
  let permuted = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: [action.id],
    waiverConsents: [secondConsent, firstConsent],
    userNotes: []
  )
  #expect(complete.overlayHash == permuted.overlayHash)
}

@Test
func waiverConsentCoreIsLineageStableButRequiresUniqueEpochResolution() throws {
  let predicate = WaiverPredicate(
    kind: .unknownRebuildCost,
    predicate: "unknown-rebuild-cost",
    valueBucket: "cost",
    semanticEvidenceHash: digest(1)
  )
  let firstEvidence = snapshot(
    candidateID: "a", path: "same", object: 1,
    recoverability: .known(.reviewRequired),
    recoverabilityReviewFacts: [
      .unknownRebuildCost(valueBucket: "cost", evidenceHash: digest(1))
    ]
  )
  let secondEvidence = snapshot(
    candidateID: "b", path: "same", object: 1,
    recoverability: .known(.reviewRequired),
    recoverabilityReviewFacts: [
      .unknownRebuildCost(valueBucket: "cost", evidenceHash: digest(1))
    ]
  )
  let first = try makeAction(evidence: firstEvidence)
  let second = try makeAction(evidence: secondEvidence)
  #expect(first.lineageID == second.lineageID)
  #expect(first.id != second.id)
  let original = WaiverConsentCore.create(
    action: first, predicate: predicate, reason: "accept", consentEventID: "event"
  )
  let sameCore = WaiverConsentCore.create(
    action: second, predicate: predicate, reason: "accept", consentEventID: "event"
  )
  #expect(original.consentHash == sameCore.consentHash)

  let secondPlan = try makePlan(actions: [second], evidence: [secondEvidence])
  let secondOverlay = DecisionOverlay.create(
    plan: secondPlan, selectedActionIDs: [second.id], waiverConsents: [original], userNotes: []
  )
  let validated = try DecisionOverlayValidator.validate(secondOverlay, against: secondPlan)
  let requirement = try #require(validated.epochRequirements.first)
  #expect(requirement.actionID == second.id)
  #expect(requirement.planHash == secondPlan.planHash)
  #expect(requirement.evidenceHash == secondPlan.evidenceHash)
  let context = try ExecutionEpochContext(
    epochID: "epoch-1",
    semanticReferenceTimeSeconds: 100,
    issuedAtSeconds: 110,
    deadlineSeconds: 120
  )
  let credential = try WaiverEpochCredential(
    requirement: requirement, context: context, opaqueCredential: Data("opaque".utf8)
  )
  #expect(credential.requirement.actionID == second.id)
  let wrongReferenceContext = try ExecutionEpochContext(
    epochID: "epoch-2",
    semanticReferenceTimeSeconds: 101,
    issuedAtSeconds: 110,
    deadlineSeconds: 120
  )
  #expect(throws: PolicyModelError.invalidExecutionEpoch) {
    try WaiverEpochCredential(
      requirement: requirement,
      context: wrongReferenceContext,
      opaqueCredential: Data("opaque".utf8)
    )
  }
  #expect(throws: PolicyModelError.invalidExecutionEpoch) {
    try ExecutionEpochContext(
      epochID: "epoch-expired",
      semanticReferenceTimeSeconds: 100,
      issuedAtSeconds: 120,
      deadlineSeconds: 120
    )
  }

  let ambiguousPlan = try makePlan(
    actions: [first, second], evidence: [firstEvidence, secondEvidence]
  )
  let ambiguousOverlay = DecisionOverlay.create(
    plan: ambiguousPlan,
    selectedActionIDs: [first.id, second.id],
    waiverConsents: [original],
    userNotes: []
  )
  #expect(throws: PolicyModelError.ambiguousSelectedLineage(original.actionLineageID)) {
    try DecisionOverlayValidator.validate(ambiguousOverlay, against: ambiguousPlan)
  }
}

@Test
func overlayActivatesSharedReleaseOnlyWhenEveryOwnerActionIsSelected() throws {
  let graph = try completeStorageGraph()
  let evaluated = try evaluateGraph(graph, selectedCandidateIDs: ["a", "b"])
  let aEvidence = snapshot(candidateID: "a", path: "a", object: 1)
  let bEvidence = snapshot(candidateID: "b", path: "b", object: 2)
  let a = try makeAction(evidence: aEvidence)
  let b = try makeAction(evidence: bEvidence)
  let releaseBundle = try PlanReleaseSet.buildAll(
    from: evaluated, candidateActions: actionBindings([("a", a), ("b", b)])
  )
  let release = try #require(releaseBundle.releaseSets.first)
  let plan = try makePlan(
    actions: [a, b], evidence: [aEvidence, bEvidence], releaseGraphBundle: releaseBundle
  )
  let partial = DecisionOverlay.create(
    plan: plan, selectedActionIDs: [a.id], waiverConsents: [], userNotes: []
  )
  let partialResult = try DecisionOverlayValidator.validate(partial, against: plan)
  #expect(partialResult.selectedActions == [a])
  #expect(partialResult.activatedReleaseSets.isEmpty)
  #expect(partialResult.releaseGraphManifest == releaseBundle.manifest)
  #expect(partialResult.executionSteps.first?.releaseGraphManifest == releaseBundle.manifest)

  let full = DecisionOverlay.create(
    plan: plan, selectedActionIDs: [a.id, b.id], waiverConsents: [], userNotes: []
  )
  #expect(
    try DecisionOverlayValidator.validate(full, against: plan).activatedReleaseSets == [release])
}

@Test
func evidenceBoundPolicyFailsClosedForProviderActivityCoverageAndCollectorFailures() throws {
  let provider = snapshot(
    candidateID: "provider", path: "provider", object: 1,
    targetProviderState: .fileProviderManaged
  )
  let providerEvaluation = try bindEvaluation(
    allowEvaluation(), evidence: provider, facts: globalFacts()
  )
  #expect(providerEvaluation.stageability == .blocked)
  #expect(providerEvaluation.recommendation == .managedByProvider)

  let ancestorProvider = snapshot(
    candidateID: "ancestor-provider", path: "ancestor/provider", object: 2,
    providerBoundary: .fileProviderManaged
  )
  let ancestorEvaluation = try bindEvaluation(
    allowEvaluation(), evidence: ancestorProvider, facts: globalFacts()
  )
  #expect(ancestorEvaluation.stageability == .blocked)
  #expect(ancestorEvaluation.recommendation == .managedByProvider)

  let active = snapshot(candidateID: "active", path: "active", object: 3, activity: .active)
  let activeEvaluation = try bindEvaluation(
    allowEvaluation(), evidence: active, facts: globalFacts()
  )
  #expect(activeEvaluation.stageability == .blocked)
  #expect(activeEvaluation.recommendation == .safeAfterExit)
  #expect(activeEvaluation.unmetRevalidationConditions == [.activityCleared])

  let failedRecoverability = snapshot(
    candidateID: "failed", path: "failed", object: 4,
    recoverability: .failed(ObservationFailure(code: "failed", collector: "recoverability"))
  )
  #expect(
    try bindEvaluation(
      allowEvaluation(), evidence: failedRecoverability, facts: globalFacts()
    ).stageability == .blocked
  )

  let partialFacts = FrozenGlobalFacts(
    captureID: digest(89),
    profile: "standard",
    configuration: Data("config".utf8),
    coverage: [
      GlobalCoverageFact(
        rawRoot: try RawRootPath(absoluteBytes: Data("/root".utf8)),
        coverage: .partial,
        reasons: ["partial"]
      )
    ],
    semanticReferenceTimeSeconds: 100,
    policyVersion: "policy-1",
    schemaVersion: "schema-1"
  )
  let partialEvidence = snapshot(
    candidateID: "partial", path: "partial", object: 5,
    globalFactsOverride: partialFacts
  )
  #expect(
    try bindEvaluation(
      allowEvaluation(), evidence: partialEvidence, facts: partialFacts
    ).stageability == .blocked
  )
}

@Test
func graphOverlapUsesFullCorpusAndAbsoluteNamespace() throws {
  let parent = storageCandidate("parent", ["parent"], 10)
  let child = storageCandidate("child", ["parent", "child"], 20)
  let parentGraph = try StorageReleaseGraph(
    globalFacts: globalFacts(), candidates: [parent, child], fileObjects: [], allocationGroups: []
  )
  let parentOnly = try evaluateGraph(parentGraph, selectedCandidateIDs: ["parent"])
  #expect(parentOnly.immediatePrivateReclaimBytes == .known(0))
  #expect(parentOnly.blockers.contains(.targetOverlap("child", "parent")))

  let siblingEvidence = snapshot(
    candidateID: "sibling", path: "sibling", object: 101
  )
  let sibling = try StorageCandidate(
    id: "sibling", evidence: siblingEvidence, immediatePrivateBytes: .known(20)
  )
  let siblingGraph = try StorageReleaseGraph(
    globalFacts: globalFacts(), candidates: [parent, sibling], fileObjects: [], allocationGroups: []
  )
  #expect(
    try evaluateGraph(siblingGraph, selectedCandidateIDs: ["parent", "sibling"])
      .immediatePrivateReclaimBytes == .known(30)
  )

  let multiRootFacts = FrozenGlobalFacts(
    captureID: digest(89),
    profile: "standard",
    configuration: Data("config".utf8),
    coverage: [
      GlobalCoverageFact(
        rawRoot: try RawRootPath(absoluteBytes: Data("/one".utf8)),
        coverage: .complete,
        reasons: ["complete"]
      ),
      GlobalCoverageFact(
        rawRoot: try RawRootPath(absoluteBytes: Data("/two".utf8)),
        coverage: .complete,
        reasons: ["complete"]
      ),
    ],
    semanticReferenceTimeSeconds: 100,
    policyVersion: "policy-1",
    schemaVersion: "schema-1"
  )
  let firstEvidence = snapshot(
    candidateID: "first", path: "same", object: 31, rawRoot: "/one", rootObject: 901,
    globalFactsOverride: multiRootFacts
  )
  let secondEvidence = snapshot(
    candidateID: "second", path: "same", object: 32, rawRoot: "/two", rootObject: 902,
    globalFactsOverride: multiRootFacts
  )
  let distinctRoots = try StorageReleaseGraph(
    globalFacts: multiRootFacts,
    candidates: [
      try StorageCandidate(id: "first", evidence: firstEvidence, immediatePrivateBytes: .known(1)),
      try StorageCandidate(
        id: "second", evidence: secondEvidence, immediatePrivateBytes: .known(1)),
    ],
    fileObjects: [],
    allocationGroups: []
  )
  #expect(
    try evaluateGraph(distinctRoots, selectedCandidateIDs: ["first", "second"])
      .immediatePrivateReclaimBytes == .known(2)
  )
}

@Test
func adapterScopesAndGraphIdentifiersUseRawUTF8Identity() throws {
  let composed = "\u{00E9}"
  let decomposed = "e\u{0301}"
  #expect(composed == decomposed)
  let evidence = snapshot(
    candidateID: "scope", path: "scope", object: 1,
    adapterScope: .codexCleanTemporary(cleanupScopeID: decomposed)
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try ActionPrototype.build(
      request: .codexCleanTemporary(cleanupScopeID: composed), evidence: evidence
    )
  }

  let composedCandidate = storageCandidate(composed, ["composed"], 1)
  let decomposedCandidate = storageCandidate(decomposed, ["decomposed"], 1)
  let forward = try StorageReleaseGraph(
    globalFacts: globalFacts(), candidates: [composedCandidate, decomposedCandidate],
    fileObjects: [], allocationGroups: []
  )
  let reverse = try StorageReleaseGraph(
    globalFacts: globalFacts(), candidates: [decomposedCandidate, composedCandidate],
    fileObjects: [], allocationGroups: []
  )
  #expect(forward.graphDigest == reverse.graphDigest)
}

@Test
func displayOrderIsSeparateFromCanonicalActionIDOrder() throws {
  let firstEvidence = snapshot(candidateID: "a", path: "z", object: 1)
  let secondEvidence = snapshot(candidateID: "b", path: "a", object: 2)
  let known = try makeAction(evidence: firstEvidence, immediate: .known(100))
  let unknown = try makeAction(evidence: secondEvidence, immediate: .unknown(.unsupported))
  #expect(ActionOrdering.display([unknown, known]).map(\.id) == [known.id, unknown.id])
  #expect(ActionOrdering.canonical([unknown, known]).map(\.id) == [known.id, unknown.id].sorted())
}

@Test
func displayTierIsDerivedFromFinalSafetyAndRejectsForgedPlanMetrics() throws {
  let safeEvidence = snapshot(candidateID: "safe", path: "z-safe", object: 1)
  let safe = try makeAction(evidence: safeEvidence)
  #expect(safe.displayMetrics.tier == .safe)

  let forceEvidence = snapshot(
    candidateID: "force", path: "a-force", object: 2,
    forceRequirement: .requiresForceWithWarning
  )
  let force = try makeAction(evidence: forceEvidence)
  #expect(force.evaluation.stageability == .stageable)
  #expect(force.displayMetrics.tier == .review)

  let providerEvidence = snapshot(
    candidateID: "provider", path: "0-provider", object: 3,
    targetProviderState: .fileProviderManaged
  )
  let provider = try makeAction(evidence: providerEvidence)
  #expect(provider.evaluation.recommendation == .managedByProvider)
  #expect(provider.evaluation.stageability == .blocked)
  #expect(provider.displayMetrics.tier == .blocked)

  let blockedEvidence = snapshot(
    candidateID: "blocked", path: "00-blocked", object: 4,
    explicitProtection: .known(.protected)
  )
  let blocked = try makeAction(evidence: blockedEvidence)
  #expect(blocked.evaluation.stageability == .blocked)
  #expect(blocked.displayMetrics.tier == .blocked)

  #expect(
    ActionOrdering.display([provider, force, safe]).map(\.id)
      == [safe.id, force.id, provider.id]
  )

  let forgedTier = ActionDisplayMetrics.testing(
    tier: .safe,
    immediateReclaimBytes: blocked.displayMetrics.immediateReclaimBytes,
    inactiveDurationSeconds: blocked.displayMetrics.inactiveDurationSeconds,
    rebuildCost: blocked.displayMetrics.rebuildCost,
    cleanupCost: blocked.displayMetrics.cleanupCost,
    canonicalRawPath: blocked.displayMetrics.canonicalRawPath
  )
  let forgedBlocked = ActionDefinition(
    lineageID: blocked.lineageID,
    id: blocked.id,
    prototype: blocked.prototype,
    evidence: blocked.evidence,
    globalFactsHash: blocked.globalFactsHash,
    prerequisiteLineageIDs: blocked.prerequisiteLineageIDs,
    prerequisiteActionIDs: blocked.prerequisiteActionIDs,
    evaluation: blocked.evaluation,
    displayMetrics: forgedTier
  )
  #expect(throws: PolicyModelError.invalidActionBinding(blocked.id)) {
    try makePlan(actions: [forgedBlocked], evidence: [blockedEvidence])
  }
}

@Test
func sourceBoundVotesAuthoritativelyDeriveRecommendationAndRejectTransplants() throws {
  let rebuildableEvidence = snapshot(
    candidateID: "rebuildable", path: "rebuildable", object: 1,
    recoverability: .known(.reviewRequired),
    recoverabilityReviewFacts: [
      .staticOnlyRebuildEvidence(artifactKind: "cache", evidenceHash: digest(101))
    ]
  )
  let rebuildable = try makeAction(evidence: rebuildableEvidence)
  #expect(rebuildable.evaluation.sourceBinding.evidenceID == rebuildableEvidence.evidenceID)
  #expect(rebuildable.evaluation.recommendation == .likelyRebuildable)
  #expect(rebuildable.evaluation.stageability != .stageable)
  #expect(rebuildable.displayMetrics.tier == .rebuildable)

  let reviewEvidence = snapshot(
    candidateID: "review", path: "review", object: 2,
    recoverability: .known(.reviewRequired),
    recoverabilityReviewFacts: [
      .staticOnlyRebuildEvidence(artifactKind: "cache", evidenceHash: digest(102)),
      .unknownRebuildCost(valueBucket: "unknown", evidenceHash: digest(103)),
    ]
  )
  let review = try makeAction(evidence: reviewEvidence)
  #expect(review.evaluation.sourceBinding.evidenceID == reviewEvidence.evidenceID)
  #expect(review.evaluation.recommendation == .needsSemanticReview)
  #expect(review.displayMetrics.tier == .review)

  let semanticReviewEvidence = snapshot(
    candidateID: "semantic", path: "semantic", object: 3,
    recoverability: .known(.reviewRequired),
    recoverabilityReviewFacts: [
      .staticOnlyRebuildEvidence(artifactKind: "cache", evidenceHash: digest(104))
    ],
    semanticReviewFacts: [
      .recencyAgePolicy(valueBucket: "recent", evidenceHash: digest(105))
    ]
  )
  let semanticReview = try makeAction(evidence: semanticReviewEvidence)
  #expect(semanticReview.evaluation.recommendation == .needsSemanticReview)
  #expect(semanticReview.displayMetrics.tier == .review)

  let blockedEvidence = snapshot(
    candidateID: "blocked-recommendation", path: "blocked-recommendation", object: 4,
    explicitProtection: .known(.protected)
  )
  let blocked = try makeAction(evidence: blockedEvidence)
  #expect(blocked.evaluation.recommendation == .keep)
  #expect(blocked.displayMetrics.tier == .blocked)

  let forgedRecommendation = ActionDefinition(
    lineageID: review.lineageID,
    id: review.id,
    prototype: review.prototype,
    evidence: review.evidence,
    globalFactsHash: review.globalFactsHash,
    prerequisiteLineageIDs: review.prerequisiteLineageIDs,
    prerequisiteActionIDs: review.prerequisiteActionIDs,
    evaluation: rebuildable.evaluation,
    displayMetrics: review.displayMetrics
  )
  #expect(throws: PolicyModelError.invalidActionBinding(review.id)) {
    try makePlan(actions: [forgedRecommendation], evidence: [reviewEvidence])
  }
}

private func claim(
  _ facet: ClassificationFacet,
  _ value: String,
  _ source: ClassificationSource,
  _ evidenceKey: String
) -> ClassificationClaim {
  ClassificationClaim(facet: facet, value: value, source: source, evidenceKey: evidenceKey)
}

private func permutations<Element>(_ values: [Element]) -> [[Element]] {
  guard values.count > 1 else { return [values] }
  return values.indices.flatMap { index in
    var remainder = values
    let head = remainder.remove(at: index)
    return permutations(remainder).map { [head] + $0 }
  }
}

private func reason(_ code: String, _ byte: UInt8) -> GateReason {
  GateReason(code: code, semanticEvidenceHash: digest(byte))
}

private func waiver(_ kind: WaiverKind, _ predicate: String, _ byte: UInt8) -> WaiverPredicate {
  WaiverPredicate(
    kind: kind,
    predicate: predicate,
    valueBucket: "bucket",
    semanticEvidenceHash: digest(byte)
  )
}

private func digest(_ byte: UInt8) -> PolicyDigest {
  try! PolicyDigest(bytes: Data(repeating: byte, count: 32))
}

private func baseVotes() -> [GateVote] {
  GateDimension.allCases.enumerated().map { index, dimension in
    GateVote(
      dimension: dimension,
      result: .satisfied(reasons: [reason("satisfied-\(index)", UInt8(index + 1))])
    )
  }
}

private func votes(rejecting rejected: Set<GateDimension>) -> [GateVote] {
  GateDimension.allCases.enumerated().map { index, dimension in
    if rejected.contains(dimension) {
      return GateVote(
        dimension: dimension,
        result: .rejected(reasons: [reason("rejected-\(index)", UInt8(index + 20))])
      )
    }
    return GateVote(
      dimension: dimension,
      result: .satisfied(reasons: [reason("satisfied-\(index)", UInt8(index + 1))])
    )
  }
}

private func allowEvaluation() throws -> PolicyEvaluation {
  try testingEvaluation(votes: baseVotes())
}

private func testingEvaluation(votes: [GateVote]) throws -> PolicyEvaluation {
  let facts = globalFacts()
  return try PolicyEvaluation.testing(
    votes: votes,
    evidence: snapshot(
      candidateID: "test-evaluation", path: "test-evaluation", object: 1,
      globalFactsOverride: facts
    ),
    globalFacts: facts
  )
}

func publicPolicyFixture() -> (evidence: FrozenEvidenceSnapshot, facts: FrozenGlobalFacts) {
  let facts = globalFacts()
  return (
    snapshot(
      candidateID: "public-api", path: "public-api", object: 1,
      globalFactsOverride: facts
    ),
    facts
  )
}

private func gitWorktreeEvidence(
  worktreeObject: UInt64 = 1,
  noFollowTraversalComplete: Observation<Bool> = .known(true),
  headIdentity: Observation<PolicyDigest> = .known(digest(70)),
  indexDigest: Observation<PolicyDigest> = .known(digest(71)),
  localChanges: GitLocalChangesState = .clean,
  registration: Observation<GitWorktreeRegistrationEvidence>? = nil,
  linkage: Observation<GitWorktreeLinkageState> = .known(
    .linked(registrationID: digest(75))),
  sparseCheckout: Observation<GitSparseCheckoutState> = .known(.disabled),
  nestedRepositories: Observation<GitContainedRepositoryState> = .known(.none),
  submodules: Observation<GitContainedRepositoryState> = .known(.none),
  trustedExclusiveNamespace: Observation<Bool> = .known(true),
  postQuarantineCoverage: Observation<EvidenceCoverage> = .known(.complete),
  postDiscardSuccessor: Observation<GitWorktreeExecutionBaseline>? = nil
) -> GitWorktreeEvidence {
  let defaultSuccessor: Observation<GitWorktreeExecutionBaseline>
  switch localChanges {
  case .clean:
    defaultSuccessor = .absent
  case .present:
    defaultSuccessor = .known(
      try! GitWorktreeExecutionBaseline(
        headIdentity: digest(70),
        indexDigest: digest(72),
        localChanges: .clean,
        contentProtection: .requiredDigest(digest(73))
      )
    )
  }
  let defaultRegistration = try! GitWorktreeRegistrationEvidence(
    registeredWorktreeIdentity: ObjectIdentity(
      device: 1,
      object: worktreeObject,
      generation: .known(1),
      type: .directory
    ),
    administrativeDirectoryIdentity: ObjectIdentity(
      device: 1,
      object: 700,
      generation: .known(1),
      type: .directory
    ),
    commonDirectoryIdentity: ObjectIdentity(
      device: 1,
      object: 701,
      generation: .known(1),
      type: .directory
    ),
    registrationID: digest(75),
    metadataDigest: digest(74),
    headResolutionDigest: digest(77)
  )
  return GitWorktreeEvidence(
    noFollowTraversalComplete: noFollowTraversalComplete,
    headIdentity: headIdentity,
    indexDigest: indexDigest,
    localChanges: .known(localChanges),
    registration: registration ?? .known(defaultRegistration),
    linkage: linkage,
    sparseCheckout: sparseCheckout,
    nestedRepositories: nestedRepositories,
    submodules: submodules,
    trustedExclusiveNamespace: trustedExclusiveNamespace,
    postQuarantineCoverage: postQuarantineCoverage,
    postDiscardSuccessor: postDiscardSuccessor ?? defaultSuccessor
  )
}

private func snapshot(
  candidateID: String,
  path: String,
  object: UInt64,
  activity: ActivityState = .inactive,
  forceRequirement: ForceRequirement = .notRequired,
  quarantineCapability: Observation<Bool> = .known(true),
  adapterScope: AdapterScopeEvidence = .genericRemove,
  additionalAdapterScopes: [AdapterScopeEvidence] = [],
  evidenceCoverage: EvidenceCoverage = .complete,
  collectorStatus: Observation<CollectorCompletionState> = .known(.complete),
  explicitProtection: Observation<ExplicitProtectionState> = .known(.notProtected),
  recoverability: Observation<RecoverabilityState> = .known(.recoverable),
  recoverabilityReviewFacts: [RecoverabilityReviewFact] = [],
  dependencyState: Observation<DependencyState> = .known(.complete),
  semanticReviewFacts: [SemanticReviewFact] = [],
  accessPolicy: Observation<String>? = nil,
  classificationClaims: [ClassificationClaim]? = nil,
  trustedNamespace: TrustedNamespace = .ownerPrivate,
  objectKind: ObjectKind = .directory,
  rawRoot: String = "/root",
  rootObject: UInt64 = 900,
  ancestorAccessPolicy: String = "owner-private",
  ancestorACLByte: UInt8 = 91,
  providerBoundary: ProviderState = .local,
  mountIdentity: String = "mount-1",
  targetAccessPolicy: String = "owner-private",
  targetMountIdentity: String = "mount-1",
  contentDigestByte: UInt8 = 92,
  contentProtection: Observation<ContentProtectionBaseline>? = nil,
  targetACLByte: UInt8 = 93,
  targetProviderState: ProviderState = .local,
  gitWorktree: GitWorktreeEvidence? = nil,
  semanticReferenceTimeSeconds: Int64 = 100,
  policyVersion: String = "policy-1",
  schemaVersion: String = "schema-1", globalFactsConfiguration: Data = Data("config".utf8),
  globalFactsOverride: FrozenGlobalFacts? = nil
) -> FrozenEvidenceSnapshot {
  let facts =
    globalFactsOverride
    ?? globalFacts(
      configuration: globalFactsConfiguration,
      rawRoot: rawRoot,
      semanticReferenceTimeSeconds: semanticReferenceTimeSeconds
    )
  let components = path.split(separator: "/").map { Data($0.utf8) }
  let targetPath = try! RawTargetPath(components: components)
  let targetIdentity = ObjectIdentity(
    device: 1, object: object, generation: .known(1), type: objectKind
  )
  let namespaceSeal = NamespaceSealEvidence(
    trustedNamespace: trustedNamespace,
    accessPolicy: .known(ancestorAccessPolicy),
    aclDigest: .known(digest(ancestorACLByte)),
    providerBoundary: .known(providerBoundary),
    mountIdentity: .known(mountIdentity)
  )
  let parentChain = components.dropLast().indices.map { index in
    ParentNamespaceBinding(
      relativePath: try! RawTargetPath(components: Array(components.prefix(index + 1))),
      identity: ObjectIdentity(
        device: 1, object: UInt64(800 + index), generation: .known(1), type: .directory
      ),
      seal: namespaceSeal
    )
  }
  let namespace = try! ProtectedNamespaceBinding(
    rawRoot: try! RawRootPath(absoluteBytes: Data(rawRoot.utf8)),
    rootIdentity: ObjectIdentity(
      device: 1, object: rootObject, generation: .known(1), type: .directory
    ),
    rootSeal: namespaceSeal,
    targetPath: targetPath,
    targetIdentity: targetIdentity,
    parentChain: parentChain
  )
  let defaultGitWorktree = gitWorktreeEvidence(worktreeObject: object)
  return try! FrozenEvidenceSnapshot(
    captureID: facts.captureID,
    globalFactsHash: facts.globalFactsHash,
    candidateID: candidateID,
    namespaceBinding: namespace,
    identity: .known(targetIdentity),
    coverage: evidenceCoverage,
    collectorStatus: collectorStatus,
    activity: .known(activity),
    explicitProtection: explicitProtection,
    providerState: .known(targetProviderState),
    recoverability: recoverability,
    recoverabilityReviewFacts: recoverabilityReviewFacts,
    dependencyState: dependencyState,
    semanticReviewFacts: semanticReviewFacts,
    accessPolicy: accessPolicy ?? .known(targetAccessPolicy),
    contentProtection: contentProtection ?? .known(.requiredDigest(digest(contentDigestByte))),
    aclDigest: .known(digest(targetACLByte)),
    targetMountIdentity: .known(targetMountIdentity),
    removalForceRequirement: .known(forceRequirement),
    quarantineCapability: quarantineCapability,
    gitWorktree: gitWorktree ?? (adapterScope == .gitWorktree ? defaultGitWorktree : nil),
    adapterScope: adapterScope,
    additionalAdapterScopes: additionalAdapterScopes,
    classificationClaims: classificationClaims ?? completeClassificationClaims(),
    semanticReferenceTimeSeconds: semanticReferenceTimeSeconds,
    policyVersion: policyVersion,
    schemaVersion: schemaVersion
  )
}

private func refreeze(
  _ source: FrozenEvidenceSnapshot,
  adapterScope: AdapterScopeEvidence? = nil,
  additionalAdapterScopes: [AdapterScopeEvidence]? = nil,
  classificationClaims: [ClassificationClaim]? = nil,
  semanticReviewFacts: [SemanticReviewFact]? = nil,
  gitWorktreeOverride: GitWorktreeEvidence? = nil,
  recoverability: Observation<RecoverabilityState>? = nil,
  recoverabilityReviewFacts: [RecoverabilityReviewFact]? = nil
) throws -> FrozenEvidenceSnapshot {
  try FrozenEvidenceSnapshot(
    captureID: source.captureID,
    globalFactsHash: source.globalFactsHash,
    candidateID: source.candidateID,
    namespaceBinding: source.namespaceBinding,
    identity: source.identity,
    coverage: source.coverage,
    collectorStatus: source.collectorStatus,
    activity: source.activity,
    explicitProtection: source.explicitProtection,
    providerState: source.providerState,
    recoverability: recoverability ?? source.recoverability,
    recoverabilityReviewFacts:
      recoverabilityReviewFacts ?? source.recoverabilityReviewFacts,
    dependencyState: source.dependencyState,
    semanticReviewFacts: semanticReviewFacts ?? source.semanticReviewFacts,
    accessPolicy: source.accessPolicy,
    contentProtection: source.contentProtection,
    aclDigest: source.aclDigest,
    targetMountIdentity: source.targetMountIdentity,
    removalForceRequirement: source.removalForceRequirement,
    quarantineCapability: source.quarantineCapability,
    gitWorktree: gitWorktreeOverride ?? source.gitWorktree,
    adapterScope: adapterScope ?? source.adapterScope,
    additionalAdapterScopes: additionalAdapterScopes ?? source.additionalAdapterScopes,
    classificationClaims: classificationClaims ?? source.classificationClaims,
    semanticReferenceTimeSeconds: source.semanticReferenceTimeSeconds,
    policyVersion: source.policyVersion,
    schemaVersion: source.schemaVersion
  )
}

private func globalFacts(
  configuration: Data = Data("config".utf8),
  rawRoot: String = "/root",
  semanticReferenceTimeSeconds: Int64 = 100,
  captureID: PolicyDigest = digest(89)
) -> FrozenGlobalFacts {
  FrozenGlobalFacts(
    captureID: captureID,
    profile: "standard",
    configuration: configuration,
    coverage: [
      GlobalCoverageFact(
        rawRoot: try! RawRootPath(absoluteBytes: Data(rawRoot.utf8)),
        coverage: .complete,
        reasons: ["complete"]
      )
    ],
    semanticReferenceTimeSeconds: semanticReferenceTimeSeconds,
    policyVersion: "policy-1",
    schemaVersion: "schema-1"
  )
}

private func genericPrototype(_ evidence: FrozenEvidenceSnapshot) throws -> ActionPrototype {
  try ActionPrototype.build(request: .genericRemove, evidence: evidence)
}

private func metrics(
  path: String,
  immediate: KnownOrUnknown<UInt64> = .known(1)
) -> ActionDisplayMetrics {
  ActionDisplayMetrics(
    immediateReclaimBytes: immediate,
    inactiveDurationSeconds: .known(10),
    rebuildCost: .known(1),
    cleanupCost: .known(1),
    canonicalRawPath: Data(path.utf8)
  )
}

private func makeAction(
  evidence: FrozenEvidenceSnapshot,
  facts: FrozenGlobalFacts = globalFacts(),
  prerequisites: [ActionDefinition] = [],
  evaluation: PolicyEvaluation? = nil,
  request: ActionAdapterRequest = .genericRemove,
  immediate: KnownOrUnknown<UInt64> = .known(1)
) throws -> ActionDefinition {
  let rawEvaluation = try evaluation ?? allowEvaluation()
  return try ActionDefinition.build(
    prototype: try ActionPrototype.build(request: request, evidence: evidence),
    evidence: evidence,
    globalFacts: facts,
    prerequisites: prerequisites,
    evaluation: try bindEvaluation(
      rawEvaluation, evidence: evidence, facts: facts
    ),
    displayMetrics: metrics(
      path: String(data: evidence.namespaceBinding.targetPath.displayBytes, encoding: .utf8)!,
      immediate: immediate
    )
  )
}

private func bindEvaluation(
  _: PolicyEvaluation,
  evidence: FrozenEvidenceSnapshot,
  facts: FrozenGlobalFacts
) throws -> PolicyEvaluation {
  let input = try OneVotePolicyInputs.build(
    evidence: evidence,
    globalFacts: facts
  )
  return try OneVotePolicy.evaluate(input)
}

private func completeClassificationClaims() -> [ClassificationClaim] {
  ClassificationFacet.allCases.map { facet in
    ClassificationClaim(
      facet: facet,
      value: "known-\(facet.rawValue)",
      source: .genericFallback,
      evidenceKey: "fixture-\(facet.rawValue)"
    )
  }
}

private func makePlan(
  actions: [ActionDefinition],
  evidence: [FrozenEvidenceSnapshot],
  facts: FrozenGlobalFacts = globalFacts(),
  releaseGraphBundle: PlanReleaseGraphBundle? = nil
) throws -> ImmutablePlan {
  try ImmutablePlan(
    policyVersion: "policy-1",
    schemaVersion: "schema-1",
    globalFacts: facts,
    evidenceSnapshots: evidence,
    actions: actions,
    releaseGraphBundle: releaseGraphBundle
  )
}

private func forged(
  _ action: ActionDefinition,
  prerequisiteIDs: [ActionID],
  lineageIDs: [ActionLineageID]
) -> ActionDefinition {
  ActionDefinition(
    lineageID: action.lineageID,
    id: action.id,
    prototype: action.prototype,
    evidence: action.evidence,
    globalFactsHash: action.globalFactsHash,
    prerequisiteLineageIDs: lineageIDs,
    prerequisiteActionIDs: prerequisiteIDs,
    evaluation: action.evaluation,
    displayMetrics: action.displayMetrics
  )
}

private func storageCandidate(
  _ id: String,
  _ path: [String],
  _ bytes: UInt64,
  providerState: ProviderState = .local,
  additionalAdapterScopes: [AdapterScopeEvidence] = [],
  facts: FrozenGlobalFacts = globalFacts()
) -> StorageCandidate {
  let object: UInt64
  switch id {
  case "a": object = 1
  case "b": object = 2
  case "c": object = 3
  case "d": object = 4
  default: object = 100
  }
  let evidence = snapshot(
    candidateID: id, path: path.joined(separator: "/"), object: object,
    additionalAdapterScopes: additionalAdapterScopes,
    targetProviderState: providerState,
    semanticReferenceTimeSeconds: facts.semanticReferenceTimeSeconds,
    globalFactsOverride: facts
  )
  return try! StorageCandidate(
    id: id,
    evidence: evidence,
    immediatePrivateBytes: .known(bytes)
  )
}

private func evaluateGraph(
  _ graph: StorageReleaseGraph,
  selectedCandidateIDs: Set<String>
) throws -> ReleaseGraphEvaluation {
  let actions: [CandidateActionBinding] = try graph.candidates.compactMap { candidate in
    guard selectedCandidateIDs.contains(candidate.id) else { return nil }
    return CandidateActionBinding(
      candidateID: candidate.id,
      action: try makeAction(
        evidence: candidate.evidence,
        facts: graph.globalFacts,
        evaluation: try allowEvaluation()
      )
    )
  }
  return try graph.evaluate(selectedCandidateActions: actions)
}

private func actionBindings(
  _ values: [(String, ActionDefinition)]
) -> [CandidateActionBinding] {
  values.map { CandidateActionBinding(candidateID: $0.0, action: $0.1) }
}

private func allocationGroup(
  _ id: String,
  owners: [String],
  refCount: UInt32,
  bytes: UInt64,
  facts: FrozenGlobalFacts = globalFacts()
) -> AllocationGroupNode {
  AllocationGroupNode(
    provenance: graphProvenance(facts: facts),
    id: id,
    ownerFileObjectIDs: owners,
    cloneRefCount: .known(refCount),
    sharedBytes: .known(bytes),
    snapshotBlocker: .known(false)
  )
}

private func graphProvenance(
  facts: FrozenGlobalFacts = globalFacts()
) -> GraphObservationProvenance {
  GraphObservationProvenance(globalFacts: facts)
}

private func completeStorageGraph(
  providerCandidateID: String? = nil,
  includeReleaseActionScope: Bool = false,
  facts: FrozenGlobalFacts = globalFacts()
) throws -> StorageReleaseGraph {
  let releaseScopes: [AdapterScopeEvidence] =
    includeReleaseActionScope ? [.completeReleaseSetRemove(allocationGroupID: "clone")] : []
  let a = storageCandidate(
    "a", ["a"], 10, additionalAdapterScopes: releaseScopes, facts: facts
  )
  let b = storageCandidate(
    "b", ["b"], 20,
    providerState: providerCandidateID == "b" ? .fileProviderManaged : .local,
    facts: facts
  )
  return try StorageReleaseGraph(
    globalFacts: facts,
    candidates: [a, b],
    fileObjects: [
      FileObjectNode(
        provenance: graphProvenance(facts: facts),
        id: "file-a",
        observedOwners: [FileOwnerLink(candidateID: "a", path: a.target)],
        linkCount: .known(1)
      ),
      FileObjectNode(
        provenance: graphProvenance(facts: facts),
        id: "file-b",
        observedOwners: [FileOwnerLink(candidateID: "b", path: b.target)],
        linkCount: .known(1)
      ),
    ],
    allocationGroups: [
      allocationGroup(
        "clone", owners: ["file-a", "file-b"], refCount: 2, bytes: 100, facts: facts
      )
    ]
  )
}

private func twoGroupStorageGraph(
  facts: FrozenGlobalFacts = globalFacts()
) throws -> StorageReleaseGraph {
  let a = storageCandidate(
    "a", ["a"], 10,
    additionalAdapterScopes: [.completeReleaseSetRemove(allocationGroupID: "group-one")],
    facts: facts
  )
  let b = storageCandidate("b", ["b"], 20, facts: facts)
  let c = storageCandidate(
    "c", ["c"], 30,
    additionalAdapterScopes: [.completeReleaseSetRemove(allocationGroupID: "group-two")],
    facts: facts
  )
  let d = storageCandidate("d", ["d"], 40, facts: facts)
  let candidates = [a, b, c, d]
  let files = candidates.map { candidate in
    FileObjectNode(
      provenance: graphProvenance(facts: facts),
      id: "file-\(candidate.id)",
      observedOwners: [
        FileOwnerLink(candidateID: candidate.id, path: candidate.target)
      ],
      linkCount: .known(1)
    )
  }
  return try StorageReleaseGraph(
    globalFacts: facts,
    candidates: candidates,
    fileObjects: files,
    allocationGroups: [
      allocationGroup(
        "group-one", owners: ["file-a", "file-b"], refCount: 2, bytes: 100,
        facts: facts
      ),
      allocationGroup(
        "group-two", owners: ["file-c", "file-d"], refCount: 2, bytes: 200,
        facts: facts
      ),
    ]
  )
}

private func overlappingReleaseComponentGraph(
  facts: FrozenGlobalFacts = globalFacts()
) throws -> StorageReleaseGraph {
  let a = storageCandidate("a", ["a"], 10, facts: facts)
  let b = storageCandidate(
    "b", ["b"], 20,
    additionalAdapterScopes: [.completeReleaseSetRemove(allocationGroupID: "group-one")],
    facts: facts
  )
  let c = storageCandidate(
    "c", ["c"], 30,
    additionalAdapterScopes: [.completeReleaseSetRemove(allocationGroupID: "group-two")],
    facts: facts
  )
  func file(
    _ id: String,
    owner: StorageCandidate,
    path: RawTargetPath? = nil
  ) -> FileObjectNode {
    FileObjectNode(
      provenance: graphProvenance(facts: facts),
      id: id,
      observedOwners: [FileOwnerLink(candidateID: owner.id, path: path ?? owner.target)],
      linkCount: .known(1)
    )
  }
  let aOne = try RawTargetPath(components: [Data("a".utf8), Data("one".utf8)])
  let aTwo = try RawTargetPath(components: [Data("a".utf8), Data("two".utf8)])
  return try StorageReleaseGraph(
    globalFacts: facts,
    candidates: [a, b, c],
    fileObjects: [
      file("file-a-one", owner: a, path: aOne),
      file("file-b", owner: b),
      file("file-a-two", owner: a, path: aTwo),
      file("file-c", owner: c),
    ],
    allocationGroups: [
      allocationGroup(
        "group-one", owners: ["file-a-one", "file-b"], refCount: 2, bytes: 100,
        facts: facts
      ),
      allocationGroup(
        "group-two", owners: ["file-a-two", "file-c"], refCount: 2, bytes: 200,
        facts: facts
      ),
    ]
  )
}

private func manyConnectedReleaseGroupsGraph(
  groupCount: Int,
  facts: FrozenGlobalFacts = globalFacts()
) throws -> StorageReleaseGraph {
  let owner = storageCandidate("owner", ["owner"], 0, facts: facts)
  let files = try (0..<groupCount).map { index -> FileObjectNode in
    let path = try RawTargetPath(
      components: [Data("owner".utf8), Data("file-\(index)".utf8)])
    return FileObjectNode(
      provenance: graphProvenance(facts: facts),
      id: "file-\(index)",
      observedOwners: [FileOwnerLink(candidateID: owner.id, path: path)],
      linkCount: .known(1)
    )
  }
  let groups = (0..<groupCount).map { index in
    allocationGroup(
      "group-\(index)",
      owners: ["file-\(index)"],
      refCount: 1,
      bytes: 1,
      facts: facts
    )
  }
  return try StorageReleaseGraph(
    globalFacts: facts,
    candidates: [owner],
    fileObjects: files,
    allocationGroups: groups
  )
}

private func releaseContractionGraph(
  facts: FrozenGlobalFacts = globalFacts()
) throws -> StorageReleaseGraph {
  let a = storageCandidate(
    "a", ["a"], 10,
    additionalAdapterScopes: [.completeReleaseSetRemove(allocationGroupID: "clone")],
    facts: facts
  )
  let b = storageCandidate("b", ["b"], 20, facts: facts)
  let x = storageCandidate("x", ["x"], 0, facts: facts)
  return try StorageReleaseGraph(
    globalFacts: facts,
    candidates: [a, b, x],
    fileObjects: [a, b].map { candidate in
      FileObjectNode(
        provenance: graphProvenance(facts: facts),
        id: "file-\(candidate.id)",
        observedOwners: [
          FileOwnerLink(candidateID: candidate.id, path: candidate.target)
        ],
        linkCount: .known(1)
      )
    },
    allocationGroups: [
      allocationGroup(
        "clone", owners: ["file-a", "file-b"], refCount: 2, bytes: 100,
        facts: facts
      )
    ]
  )
}

private func contractionCandidateActions(
  graph: StorageReleaseGraph
) throws -> [String: ActionDefinition] {
  let evidenceByCandidate = Dictionary(
    uniqueKeysWithValues: graph.candidates.map { ($0.id, $0.evidence) })
  let b = try makeAction(
    evidence: evidenceByCandidate["b"]!, facts: graph.globalFacts)
  let x = try makeAction(
    evidence: evidenceByCandidate["x"]!, facts: graph.globalFacts,
    prerequisites: [b]
  )
  let a = try makeAction(
    evidence: evidenceByCandidate["a"]!, facts: graph.globalFacts,
    prerequisites: [x]
  )
  return ["a": a, "b": b, "x": x]
}

private func crossComponentReleaseGraph(
  facts: FrozenGlobalFacts = globalFacts()
) throws -> StorageReleaseGraph {
  let a = storageCandidate(
    "a", ["a"], 10,
    additionalAdapterScopes: [.completeReleaseSetRemove(allocationGroupID: "group-one")],
    facts: facts
  )
  let b = storageCandidate("b", ["b"], 20, facts: facts)
  let c = storageCandidate(
    "c", ["c"], 30,
    additionalAdapterScopes: [.completeReleaseSetRemove(allocationGroupID: "group-two")],
    facts: facts
  )
  let d = storageCandidate("d", ["d"], 40, facts: facts)
  let x = storageCandidate("x", ["x"], 0, facts: facts)
  let releaseOwners = [a, b, c, d]
  return try StorageReleaseGraph(
    globalFacts: facts,
    candidates: releaseOwners + [x],
    fileObjects: releaseOwners.map { candidate in
      FileObjectNode(
        provenance: graphProvenance(facts: facts),
        id: "file-\(candidate.id)",
        observedOwners: [
          FileOwnerLink(candidateID: candidate.id, path: candidate.target)
        ],
        linkCount: .known(1)
      )
    },
    allocationGroups: [
      allocationGroup(
        "group-one", owners: ["file-a", "file-b"], refCount: 2, bytes: 100,
        facts: facts
      ),
      allocationGroup(
        "group-two", owners: ["file-c", "file-d"], refCount: 2, bytes: 200,
        facts: facts
      ),
    ]
  )
}

private func crossComponentCandidateActions(
  graph: StorageReleaseGraph
) throws -> [String: ActionDefinition] {
  let evidenceByCandidate = Dictionary(
    uniqueKeysWithValues: graph.candidates.map { ($0.id, $0.evidence) })
  let a = try makeAction(
    evidence: evidenceByCandidate["a"]!, facts: graph.globalFacts)
  let b = try makeAction(
    evidence: evidenceByCandidate["b"]!, facts: graph.globalFacts)
  let x = try makeAction(
    evidence: evidenceByCandidate["x"]!, facts: graph.globalFacts,
    prerequisites: [b]
  )
  let c = try makeAction(
    evidence: evidenceByCandidate["c"]!, facts: graph.globalFacts,
    prerequisites: [x]
  )
  let d = try makeAction(
    evidence: evidenceByCandidate["d"]!, facts: graph.globalFacts)
  return ["a": a, "b": b, "c": c, "d": d, "x": x]
}

private func replaceGroup(
  _ graph: StorageReleaseGraph,
  refCount: Observation<UInt32>? = nil,
  sharedBytes: Observation<UInt64>? = nil,
  snapshot: Observation<Bool>? = nil
) throws -> StorageReleaseGraph {
  let old = graph.allocationGroups[0]
  return try StorageReleaseGraph(
    globalFacts: graph.globalFacts,
    candidates: graph.candidates,
    fileObjects: graph.fileObjects,
    allocationGroups: [
      AllocationGroupNode(
        provenance: old.provenance,
        id: old.id,
        ownerFileObjectIDs: old.ownerFileObjectIDs,
        cloneRefCount: refCount ?? old.cloneRefCount,
        sharedBytes: sharedBytes ?? old.sharedBytes,
        snapshotBlocker: snapshot ?? old.snapshotBlocker
      )
    ]
  )
}

private func replaceFile(
  _ graph: StorageReleaseGraph,
  id: String,
  linkCount: Observation<UInt32>
) throws -> StorageReleaseGraph {
  try StorageReleaseGraph(
    globalFacts: graph.globalFacts,
    candidates: graph.candidates,
    fileObjects: graph.fileObjects.map {
      guard $0.id == id else { return $0 }
      return FileObjectNode(
        provenance: $0.provenance,
        id: $0.id,
        observedOwners: $0.observedOwners,
        linkCount: linkCount
      )
    },
    allocationGroups: graph.allocationGroups
  )
}

private func rawOverlay(
  _ overlay: DecisionOverlay,
  bindingVersion: String? = nil,
  notes: [String]? = nil
) -> DecisionOverlay {
  DecisionOverlay(
    bindingVersion: bindingVersion ?? overlay.bindingVersion,
    policyVersion: overlay.policyVersion,
    schemaVersion: overlay.schemaVersion,
    referencedPlanHash: overlay.referencedPlanHash,
    referencedEvidenceHash: overlay.referencedEvidenceHash,
    selectedActionIDs: overlay.selectedActionIDs,
    waiverConsents: overlay.waiverConsents,
    userNotes: notes ?? overlay.userNotes,
    overlayHash: overlay.overlayHash
  )
}
