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
  let evaluation = try PolicyEvaluation(votes: baseVotes())
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
    let evaluation = try PolicyEvaluation(votes: votes(rejecting: [dimension]))
    #expect(evaluation.stageability == .blocked)
  }
  let combined = try PolicyEvaluation(votes: votes(rejecting: Set(GateDimension.allCases)))
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
  let evaluation = try PolicyEvaluation(votes: inputs)
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
  let evaluation = try PolicyEvaluation(votes: all)
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
  ) { try PolicyEvaluation(votes: all) }
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
    #expect(try PolicyEvaluation(votes: allowed).stageability == .requiresConsents([predicate]))
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
    #expect(throws: PolicyModelError.self) { try PolicyEvaluation(votes: invalid) }
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
  #expect(try PolicyEvaluation(votes: forward) == PolicyEvaluation(votes: reverse))
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
func gitWorktreeContractsBindCompleteEvidenceAndRequireSeparateDiscardAction() throws {
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
  let unsequencedRemove = try makeAction(
    evidence: evidence,
    request: .gitWorktreeRemove
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try makePlan(actions: [unsequencedRemove], evidence: [evidence])
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

  let discardPredicate: WaiverPredicate
  guard case .requiresConsents(let predicates) = discard.evaluation.stageability,
    let exactPredicate = predicates.first(where: {
      $0.kind == .fullyObservedLocalGitWorkDiscard
    })
  else {
    Issue.record("expected exact local-work discard predicate")
    return
  }
  discardPredicate = exactPredicate
  let consent = WaiverConsentCore.create(
    action: discard,
    predicate: discardPredicate,
    reason: "discard observed local changes",
    consentEventID: "discard-event"
  )
  let overlay = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: [remove.id, discard.id],
    waiverConsents: [consent],
    userNotes: []
  )
  let validated = try DecisionOverlayValidator.validate(overlay, against: plan)
  #expect(validated.executionSteps.map(\.action.id) == [discard.id, remove.id])
  #expect(validated.epochRequirements.count == 1)

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
  let removeWithMismatchedPrerequisite = try makeAction(
    evidence: evidence,
    prerequisites: [mismatchedDiscard],
    request: .gitWorktreeRemove
  )
  guard
    case .requiresConsents(let mismatchedPredicates) =
      removeWithMismatchedPrerequisite.evaluation.stageability
  else {
    Issue.record("mismatched Git evidence must not discharge local-work consent")
    return
  }
  #expect(mismatchedPredicates.contains { $0.kind == .fullyObservedLocalGitWorkDiscard })

  let twoDiscardPlan = try makePlan(
    actions: [discard, mismatchedDiscard],
    evidence: [evidence, mismatchedEvidence]
  )
  let singleDiscardOverlay = DecisionOverlay.create(
    plan: twoDiscardPlan,
    selectedActionIDs: [discard.id],
    waiverConsents: [consent],
    userNotes: []
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try DecisionOverlayValidator.validate(singleDiscardOverlay, against: twoDiscardPlan)
  }
  let blockedDescendant = snapshot(
    candidateID: "blocked-worktree-child", path: "worktree/blocked", object: 101,
    explicitProtection: .known(.protected)
  )
  let discardWithBlockedDescendantPlan = try makePlan(
    actions: [discard],
    evidence: [evidence, blockedDescendant]
  )
  let discardWithBlockedDescendantOverlay = DecisionOverlay.create(
    plan: discardWithBlockedDescendantPlan,
    selectedActionIDs: [discard.id],
    waiverConsents: [consent],
    userNotes: []
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try DecisionOverlayValidator.validate(
      discardWithBlockedDescendantOverlay,
      against: discardWithBlockedDescendantPlan
    )
  }
  guard
    case .requiresConsents(let secondPredicates) =
      mismatchedDiscard.evaluation.stageability,
    let secondPredicate = secondPredicates.first(where: {
      $0.kind == .fullyObservedLocalGitWorkDiscard
    })
  else {
    Issue.record("expected second exact local-work discard predicate")
    return
  }
  let secondConsent = WaiverConsentCore.create(
    action: mismatchedDiscard,
    predicate: secondPredicate,
    reason: "discard second observed local changes",
    consentEventID: "discard-event-2"
  )
  let twoDiscardOverlay = DecisionOverlay.create(
    plan: twoDiscardPlan,
    selectedActionIDs: [discard.id, mismatchedDiscard.id],
    waiverConsents: [consent, secondConsent],
    userNotes: []
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try DecisionOverlayValidator.validate(twoDiscardOverlay, against: twoDiscardPlan)
  }

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
      linkage: .known(.linked(registrationID: digest(75)))
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
func gitWorktreeRegistrationLinkageAndSparseFactsFailClosed() throws {
  let ordinaryEvidence = snapshot(
    candidateID: "ordinary", path: "ordinary", object: 1,
    adapterScope: .gitWorktree,
    gitWorktree: gitWorktreeEvidence()
  )
  let ordinaryAction = try makeAction(
    evidence: ordinaryEvidence,
    request: .gitWorktreeRemove
  )
  #expect(ordinaryAction.evaluation.stageability == .stageable)

  let changedRegistration = try GitWorktreeRegistrationEvidence(
    registeredWorktreeIdentity: ObjectIdentity(
      device: 1, object: 1, generation: .known(1), type: .directory),
    administrativeDirectoryIdentity: ObjectIdentity(
      device: 1, object: 702, generation: .known(1), type: .directory),
    commonDirectoryIdentity: ObjectIdentity(
      device: 1, object: 703, generation: .known(1), type: .directory),
    registrationID: digest(75),
    metadataDigest: digest(77)
  )
  let changedEvidence = snapshot(
    candidateID: "ordinary", path: "ordinary", object: 1,
    adapterScope: .gitWorktree,
    gitWorktree: gitWorktreeEvidence(registration: .known(changedRegistration))
  )
  let changedAction = try makeAction(
    evidence: changedEvidence,
    request: .gitWorktreeRemove
  )
  #expect(changedEvidence.evidenceID != ordinaryEvidence.evidenceID)
  #expect(changedAction.lineageID != ordinaryAction.lineageID)
  #expect(changedAction.id != ordinaryAction.id)

  let linkedEvidence = snapshot(
    candidateID: "linked", path: "linked", object: 1,
    adapterScope: .gitWorktree,
    gitWorktree: gitWorktreeEvidence(
      linkage: .known(.linked(registrationID: digest(75))))
  )
  let linkedEvaluation = try OneVotePolicy.evaluate(
    OneVotePolicyInputs.build(evidence: linkedEvidence, globalFacts: globalFacts())
  )
  #expect(linkedEvaluation.stageability == .blocked)
  #expect(linkedEvidence.evidenceID != ordinaryEvidence.evidenceID)
  #expect(throws: PolicyModelError.invalidActionContract) {
    try ActionPrototype.build(request: .gitWorktreeRemove, evidence: linkedEvidence)
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
  #expect(sparseEvidence.evidenceID != ordinaryEvidence.evidenceID)
  #expect(throws: PolicyModelError.invalidActionContract) {
    try ActionPrototype.build(request: .gitWorktreeRemove, evidence: sparseEvidence)
  }

  let invalidFacts = [
    gitWorktreeEvidence(worktreeObject: 2),
    gitWorktreeEvidence(linkage: .known(.linked(registrationID: digest(75)))),
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
    candidateID: "alias", path: "tree/worktree", object: 20)
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
  let bEvidence = snapshot(candidateID: "b", path: "survivor-root/b", object: 2)
  let ancestorEvidence = snapshot(
    candidateID: "ancestor", path: "survivor-root", object: 3)
  let a = try makeAction(evidence: aEvidence)
  let b = try makeAction(evidence: bEvidence)
  let ancestor = try makeAction(evidence: ancestorEvidence)
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

  let directPlan = try makePlan(
    actions: [a, b], evidence: [aEvidence, bEvidence]
  )
  let directOverlay = DecisionOverlay.create(
    plan: directPlan,
    selectedActionIDs: [a.id, b.id],
    waiverConsents: [consent],
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
    waiverConsents: [],
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
      releaseSets: []
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
    releaseSets: []
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
      releaseSets: []
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
func planReleaseSetBuildsOnlyFromCompleteEvaluatedGraph() throws {
  let graph = try completeStorageGraph()
  let evaluated = try evaluateGraph(graph, selectedCandidateIDs: ["a", "b"])
  let aEvidence = snapshot(candidateID: "a", path: "a", object: 1)
  let bEvidence = snapshot(candidateID: "b", path: "b", object: 2)
  let a = try makeAction(evidence: aEvidence)
  let b = try makeAction(evidence: bEvidence)
  let release = try #require(
    PlanReleaseSet.buildAll(
      from: evaluated, candidateActions: actionBindings([("a", a), ("b", b)])
    ).first
  )
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
  #expect(throws: PolicyModelError.releaseOwnerBindingMismatch("a")) {
    try PlanReleaseSet.buildAll(
      from: evaluated, candidateActions: actionBindings([("a", wrongA), ("b", b)])
    )
  }

  let alternateA = try makeAction(evidence: aEvidence, prerequisites: [b])
  #expect(alternateA.id != a.id)
  #expect(throws: PolicyModelError.releaseOwnerBindingMismatch("a")) {
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
  let release = try #require(
    PlanReleaseSet.buildAll(
      from: evaluated,
      candidateActions: actionBindings([("a", a), ("b", b)])
    ).first
  )
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
    releaseSets: [release]
  )
  #expect(plan.releaseSets == [release])

  let unsequencedReleaseAction = try makeAction(
    evidence: aEvidence,
    facts: graph.globalFacts,
    request: .completeReleaseSetRemove(binding: release.actionBinding)
  )
  #expect(throws: PolicyModelError.invalidActionContract) {
    try makePlan(
      actions: [a, b, unsequencedReleaseAction],
      evidence: [aEvidence, bEvidence],
      facts: graph.globalFacts,
      releaseSets: [release]
    )
  }

  #expect(throws: PolicyModelError.incompleteReleaseGraph) {
    try makePlan(
      actions: [a, b, releaseAction],
      evidence: [aEvidence, bEvidence],
      facts: graph.globalFacts,
      releaseSets: []
    )
  }

  let changedGraph = try replaceGroup(graph, sharedBytes: .known(101))
  let changedEvaluation = try changedGraph.evaluate(
    selectedCandidateActions: actionBindings([("a", a), ("b", b)])
  )
  let changedRelease = try #require(
    PlanReleaseSet.buildAll(
      from: changedEvaluation,
      candidateActions: actionBindings([("a", a), ("b", b)])
    ).first
  )
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
      releaseSets: [release]
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
  #expect(validated.activatedReleaseSets == [release])
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
  let release = try #require(
    PlanReleaseSet.buildAll(
      from: evaluated, candidateActions: actionBindings([("a", a), ("b", b)])
    ).first
  )
  let plan = try makePlan(
    actions: [a, b], evidence: [aEvidence, bEvidence], releaseSets: [release]
  )
  let partial = DecisionOverlay.create(
    plan: plan, selectedActionIDs: [a.id], waiverConsents: [], userNotes: []
  )
  let partialResult = try DecisionOverlayValidator.validate(partial, against: plan)
  #expect(partialResult.selectedActions == [a])
  #expect(partialResult.activatedReleaseSets.isEmpty)

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
  try PolicyEvaluation(votes: baseVotes())
}

private func gitWorktreeEvidence(
  worktreeObject: UInt64 = 1,
  noFollowTraversalComplete: Observation<Bool> = .known(true),
  headIdentity: Observation<PolicyDigest> = .known(digest(70)),
  indexDigest: Observation<PolicyDigest> = .known(digest(71)),
  localChanges: GitLocalChangesState = .clean,
  registration: Observation<GitWorktreeRegistrationEvidence>? = nil,
  linkage: Observation<GitWorktreeLinkageState> = .known(.ordinary),
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
    metadataDigest: digest(74)
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
  gitWorktreeOverride: GitWorktreeEvidence? = nil
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
    recoverability: source.recoverability,
    recoverabilityReviewFacts: source.recoverabilityReviewFacts,
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
    tier: .safe,
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
  releaseSets: [PlanReleaseSet] = []
) throws -> ImmutablePlan {
  try ImmutablePlan(
    policyVersion: "policy-1",
    schemaVersion: "schema-1",
    globalFacts: facts,
    evidenceSnapshots: evidence,
    actions: actions,
    releaseSets: releaseSets
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
  additionalAdapterScopes: [AdapterScopeEvidence] = []
) -> StorageCandidate {
  let object: UInt64 = id == "a" ? 1 : (id == "b" ? 2 : 100)
  let evidence = snapshot(
    candidateID: id, path: path.joined(separator: "/"), object: object,
    additionalAdapterScopes: additionalAdapterScopes,
    targetProviderState: providerState
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
  bytes: UInt64
) -> AllocationGroupNode {
  AllocationGroupNode(
    provenance: graphProvenance(),
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
  includeReleaseActionScope: Bool = false
) throws -> StorageReleaseGraph {
  let releaseScopes: [AdapterScopeEvidence] =
    includeReleaseActionScope ? [.completeReleaseSetRemove(allocationGroupID: "clone")] : []
  let a = storageCandidate("a", ["a"], 10, additionalAdapterScopes: releaseScopes)
  let b = storageCandidate(
    "b", ["b"], 20,
    providerState: providerCandidateID == "b" ? .fileProviderManaged : .local
  )
  return try StorageReleaseGraph(
    globalFacts: globalFacts(),
    candidates: [a, b],
    fileObjects: [
      FileObjectNode(
        provenance: graphProvenance(),
        id: "file-a",
        observedOwners: [FileOwnerLink(candidateID: "a", path: a.target)],
        linkCount: .known(1)
      ),
      FileObjectNode(
        provenance: graphProvenance(),
        id: "file-b",
        observedOwners: [FileOwnerLink(candidateID: "b", path: b.target)],
        linkCount: .known(1)
      ),
    ],
    allocationGroups: [
      allocationGroup("clone", owners: ["file-a", "file-b"], refCount: 2, bytes: 100)
    ]
  )
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
