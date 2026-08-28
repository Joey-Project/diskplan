import DiskplanPolicy
import DiskplanProto
import Foundation
import SwiftProtobuf
import Testing

@testable import DiskplanEngineCore
@testable import DiskplanScan

@Test func boundedEvidenceReplacesOnlyDirectoryProvisionalEvidence() {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  let provisional = authorityNode(
    path: ["cache"],
    object: 2,
    type: .directory,
    coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
  )
  let closed = authorityNode(path: ["cache"], object: 2, type: .directory)
  let leaf = authorityNode(path: ["cache", "entry"], object: 3, type: .regular)

  accumulator.receive(.observed(leaf))
  accumulator.receive(.observed(provisional))
  accumulator.receive(.directoryClosed(closed))

  let evidence = accumulator.snapshot()
  #expect(evidence.candidatesByPath.values.map(\.node) == [closed])
  #expect(evidence.candidatesByPath.values.allSatisfy { $0.isClosed })
  #expect(evidence.sharedFileObservationsByPath.isEmpty)
  #expect(evidence.issues.isEmpty)
}

@Test func conflictingCorpusEventsRemainTypedAndFailClosed() {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  accumulator.receive(.observed(authorityNode(path: ["cache"], object: 2, type: .directory)))
  accumulator.receive(.observed(authorityNode(path: ["cache"], object: 9, type: .directory)))

  let evidence = accumulator.snapshot()
  #expect(evidence.issues == [.conflictingObservation(authorityPath(["cache"]))])
}

@Test func directoryCloseCannotReplaceAProvisionalObjectWithAnotherIdentity() {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  accumulator.receive(
    .observed(authorityNode(path: ["cache"], object: 2, type: .directory))
  )
  accumulator.receive(
    .directoryClosed(authorityNode(path: ["cache"], object: 9, type: .directory))
  )

  let evidence = accumulator.snapshot()
  #expect(evidence.candidatesByPath.values.first?.node.identity.value?.fileID == 2)
  #expect(evidence.candidatesByPath.values.first?.isClosed == false)
  #expect(evidence.issues == [.conflictingDirectoryClose(authorityPath(["cache"]))])
}

@Test func directoryCloseRequiresKnownContinuousObjectIdentity() {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  accumulator.receive(
    .observed(
      authorityNode(
        path: ["cache"],
        object: 2,
        type: .directory,
        identity: .unknown(reason: "identity collector incomplete")
      )
    )
  )
  accumulator.receive(
    .directoryClosed(authorityNode(path: ["cache"], object: 2, type: .directory))
  )

  let evidence = accumulator.snapshot()
  #expect(evidence.candidatesByPath.isEmpty)
  #expect(evidence.issues == [.conflictingDirectoryClose(authorityPath(["cache"]))])
}

@Test func authorityUsesCompleteCorpusInsteadOfRetainedViewport() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  let provisional = authorityNode(
    path: ["cache"],
    object: 2,
    type: .directory,
    coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
  )
  let closed = authorityNode(path: ["cache"], object: 2, type: .directory)
  accumulator.receive(.observed(provisional))
  accumulator.receive(.directoryClosed(closed))
  let corpus = accumulator.snapshot()

  let emptyViewport = authorityScanResult(retainedNodes: [])
  let populatedViewport = authorityScanResult(retainedNodes: [closed])
  let first = try RuntimePolicyAuthority().makePlan(
    scanResult: emptyViewport,
    evidence: corpus
  )
  let second = try RuntimePolicyAuthority().makePlan(
    scanResult: populatedViewport,
    evidence: corpus
  )

  #expect(first.plan == second.plan)
  #expect(first.items == second.items)
  #expect(first.items.count == 1)
  #expect(first.items[0].kind == .cache)
  #expect(first.items[0].actionID == nil)
  #expect(first.items[0].reasons.contains(.aclEvidenceUnavailable))
  #expect(first.items[0].reasons.contains(.rootNamespaceSealUnavailable))
  #expect(first.items[0].reasons.contains(.nameOnlyTypeHint))
  #expect(first.items[0].reasons.contains(.recoverabilityProvenanceUnavailable))
  #expect(first.plan.evidenceSnapshots.count == 1)
  #expect(first.plan.evidenceSnapshots[0].namespaceBinding.trustedNamespace == .unverified)
  #expect(
    first.items[0].evaluation.votes.first(where: { $0.dimension == .identityAndAccess })?.result
      .isRejectedForAuthorityTest == true
  )
  #expect(first.plan.actions.isEmpty)
}

@Test func deepLongPathViewportDoesNotEnterAuthorityFinalizationBudgetOrCapture() throws {
  let corpus = singleClosedCandidateCorpus(
    authorityNode(path: ["cache"], object: 2, type: .directory)
  )
  let longComponent = String(repeating: "v", count: 4_096)
  let viewport = (0..<128).map { index in
    authorityNode(
      path: Array(repeating: longComponent, count: 7) + ["leaf-\(index)"],
      object: UInt64(index + 100),
      type: .regular
    )
  }

  let empty = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(retainedNodes: []),
    evidence: corpus
  )
  let populated = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(retainedNodes: viewport),
    evidence: corpus
  )

  #expect(populated == empty)
}

@Test func referenceTimeAtRoundedInt64UpperBoundaryFailsWithoutTrapping() {
  #expect(throws: RuntimePolicyAuthorityError.invalidReferenceTime) {
    try RuntimePolicyAuthority().makePlan(
      scanResult: authorityScanResult(wallClockSeconds: Double(Int64.max)),
      evidence: BoundedAuthorityEvidenceAccumulator().snapshot()
    )
  }
}

@Test func unclosedRecognizedDirectoryRemainsVisibleAsIncompleteEvidence() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  accumulator.receive(
    .observed(
      authorityNode(
        path: ["cache"],
        object: 2,
        type: .directory,
        coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
      )
    )
  )

  let result = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(),
    evidence: accumulator.snapshot()
  )

  #expect(result.items.count == 1)
  #expect(result.rejectedCandidates.isEmpty)
  #expect(result.items[0].reasons.contains(.candidateCoverageIncomplete))
  #expect(result.items[0].reasons.contains(.collectorIncomplete))
}

@Test func missingActivityIsAnIndependentRejectVote() throws {
  let corpus = singleClosedCandidateCorpus(
    authorityNode(path: ["build"], object: 2, type: .directory)
  )
  let result = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(
      processActivity: .unknown(reason: "collector unavailable")
    ),
    evidence: corpus
  )

  #expect(result.items[0].reasons.contains(.activityUnavailable))
  #expect(
    result.items[0].evaluation.votes.first(where: { $0.dimension == .currentActivity })?.result
      .isRejectedForAuthorityTest == true
  )
}

@Test func providerCandidateIsReportOnlyWithoutPathExclusionRules() throws {
  let providerNode = authorityNode(
    path: ["cache"],
    object: 2,
    type: .directory,
    providerBoundary: .metadataOnly(reason: "system File Provider evidence")
  )
  let result = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(),
    evidence: singleClosedCandidateCorpus(providerNode)
  )

  #expect(result.items[0].kind == .providerReportOnly)
  #expect(result.items[0].reasons.contains(.providerManaged))
  #expect(result.items[0].evaluation.recommendation == .managedByProvider)
  #expect(result.items[0].actionID == nil)
}

@Test func providerAncestorMakesNestedCandidateReportOnly() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  let parentProvider = ProviderBoundary.metadataOnly(reason: "provider ancestor")
  accumulator.receive(
    .observed(
      authorityNode(
        path: ["provider"],
        object: 2,
        type: .directory,
        coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete]),
        providerBoundary: parentProvider
      )
    )
  )
  accumulator.receive(
    .observed(
      authorityNode(
        path: ["provider", "cache"],
        object: 3,
        type: .directory,
        coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
      )
    )
  )
  accumulator.receive(
    .directoryClosed(
      authorityNode(path: ["provider", "cache"], object: 3, type: .directory)
    )
  )
  accumulator.receive(
    .directoryClosed(
      authorityNode(
        path: ["provider"],
        object: 2,
        type: .directory,
        providerBoundary: parentProvider
      )
    )
  )

  let result = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(),
    evidence: accumulator.snapshot()
  )

  #expect(result.items.count == 1)
  #expect(result.items[0].kind == .providerReportOnly)
  #expect(result.items[0].evaluation.recommendation == .managedByProvider)
}

@Test func gitShapedCandidateDoesNotDowngradeToGenericExecution() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  let provisional = authorityNode(
    path: ["workspace"],
    object: 2,
    type: .directory,
    coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
  )
  let closed = authorityNode(path: ["workspace"], object: 2, type: .directory)
  let gitFile = authorityNode(path: ["workspace", ".git"], object: 3, type: .regular)
  accumulator.receive(.observed(provisional))
  accumulator.receive(.observed(gitFile))
  accumulator.receive(.directoryClosed(closed))

  let result = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(),
    evidence: accumulator.snapshot()
  )

  #expect(result.items.count == 1)
  #expect(result.items[0].kind == .gitLinkedWorktree)
  #expect(result.items[0].actionID == nil)
  #expect(result.items[0].reasons.contains(.gitExecutionEvidenceUnavailable))
}

@Test func releaseOwnerIndexRetainsAllCloneOwnersAcrossRoots() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  for (rootID, object) in [("root", UInt64(2)), ("second", UInt64(20))] {
    let provisional = authorityNode(
      rootID: rootID,
      path: ["cache"],
      object: object,
      type: .directory,
      coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
    )
    let file = authorityNode(
      rootID: rootID,
      path: ["cache", "object"],
      device: 1,
      object: object + 1,
      type: .regular,
      topology: StorageTopologyEvidence(
        linkCount: .known(1),
        mayShareBlocks: .known(true),
        sharesAllBlocks: .known(true),
        cloneID: .known(44),
        cloneRefcount: .known(2),
        conditionalGroupReclaim: .exact(4_096)
      )
    )
    accumulator.receive(.observed(provisional))
    accumulator.receive(.observed(file))
    accumulator.receive(
      .directoryClosed(
        authorityNode(rootID: rootID, path: ["cache"], object: object, type: .directory)
      )
    )
  }

  let result = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(includeSecondRoot: true),
    evidence: accumulator.snapshot()
  )

  #expect(result.releaseOwnerIndex.owners.count == 2)
  #expect(result.releaseOwnerIndex.allocationGroups.count == 1)
  #expect(result.releaseOwnerIndex.allocationGroups[0].fileObjectIDs.count == 2)
  #expect(result.releaseOwnerIndex.dependencyCompleteByCandidate.values.allSatisfy { $0 })
  #expect(result.releaseGraph != nil)
}

@Test func partialCloneAndLinkFactsNeverUpgradeToKnown() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  for (rootID, directoryObject, linkCount, groupBytes) in [
    ("root", UInt64(2), DiskplanScan.Observation<UInt32>.known(2), ByteMeasure.exact(4_096)),
    (
      "second", UInt64(20), DiskplanScan.Observation<UInt32>.unknown(reason: "unavailable"),
      ByteMeasure.unknown(reason: "unavailable")
    ),
  ] {
    accumulator.receive(
      .observed(
        authorityNode(
          rootID: rootID,
          path: ["cache"],
          object: directoryObject,
          type: .directory,
          coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
        )
      )
    )
    accumulator.receive(
      .observed(
        authorityNode(
          rootID: rootID,
          path: ["cache", "object"],
          device: 1,
          object: 55,
          type: .regular,
          topology: StorageTopologyEvidence(
            linkCount: linkCount,
            mayShareBlocks: .known(true),
            sharesAllBlocks: .known(true),
            cloneID: .known(44),
            cloneRefcount: rootID == "root" ? .known(2) : .unknown(reason: "unavailable"),
            conditionalGroupReclaim: groupBytes
          )
        )
      )
    )
    accumulator.receive(
      .directoryClosed(
        authorityNode(
          rootID: rootID, path: ["cache"], object: directoryObject, type: .directory)
      )
    )
  }

  let result = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(includeSecondRoot: true),
    evidence: accumulator.snapshot()
  )

  #expect(result.releaseOwnerIndex.allocationGroups[0].cloneRefCount.knownValue == nil)
  #expect(result.releaseOwnerIndex.allocationGroups[0].sharedBytes.knownValue == nil)
  #expect(result.releaseGraph?.fileObjects[0].linkCount.knownValue == nil)
}

@Test func contradictoryCloneEvidenceNeverUpgradesSharedFacts() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  accumulator.receive(
    .observed(
      authorityNode(
        path: ["cache"],
        object: 2,
        type: .directory,
        coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
      )
    )
  )
  accumulator.receive(
    .observed(
      authorityNode(
        path: ["cache", "object"],
        object: 3,
        type: .regular,
        topology: StorageTopologyEvidence(
          linkCount: .known(1),
          mayShareBlocks: .known(false),
          sharesAllBlocks: .known(false),
          cloneID: .known(44),
          cloneRefcount: .known(1),
          conditionalGroupReclaim: .exact(4_096)
        )
      )
    )
  )
  accumulator.receive(
    .directoryClosed(authorityNode(path: ["cache"], object: 2, type: .directory))
  )

  let result = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(),
    evidence: accumulator.snapshot()
  )

  #expect(result.releaseOwnerIndex.allocationGroups[0].cloneRefCount.knownValue == nil)
  #expect(result.releaseOwnerIndex.allocationGroups[0].sharedBytes.knownValue == nil)
  #expect(result.releaseOwnerIndex.dependencyCompleteByCandidate.values.allSatisfy { !$0 })
}

@Test func hardlinkOwnersFormAReleaseGroupOnlyWithExplicitNonCloneEvidence() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  for (rootID, directoryObject) in [("root", UInt64(2)), ("second", UInt64(20))] {
    accumulator.receive(
      .observed(
        authorityNode(
          rootID: rootID,
          path: ["cache"],
          object: directoryObject,
          type: .directory,
          coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
        )
      )
    )
    accumulator.receive(
      .observed(
        authorityNode(
          rootID: rootID,
          path: ["cache", "hardlink"],
          device: 1,
          object: 55,
          type: .regular,
          topology: StorageTopologyEvidence(
            linkCount: .known(2),
            mayShareBlocks: .known(false),
            sharesAllBlocks: .known(false),
            cloneID: .absent(reason: "not cloned"),
            cloneRefcount: .absent(reason: "not cloned"),
            conditionalGroupReclaim: .exact(4_096)
          )
        )
      )
    )
    accumulator.receive(
      .directoryClosed(
        authorityNode(
          rootID: rootID, path: ["cache"], object: directoryObject, type: .directory)
      )
    )
  }

  let result = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(includeSecondRoot: true),
    evidence: accumulator.snapshot()
  )

  #expect(result.releaseOwnerIndex.allocationGroups.map(\.id) == ["hardlink:object:1:55:regular"])
  #expect(result.releaseOwnerIndex.allocationGroups[0].fileObjectIDs == ["object:1:55:regular"])
  #expect(result.releaseOwnerIndex.allocationGroups[0].sharedBytes.knownValue == 4_096)
  #expect(result.releaseOwnerIndex.dependencyCompleteByCandidate.values.allSatisfy { $0 })
  #expect(result.releaseGraph?.fileObjects[0].observedOwners.count == 2)
}

@Test func unknownCloneEvidenceCannotBecomeANonCloneHardlinkGroup() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  accumulator.receive(
    .observed(
      authorityNode(
        path: ["cache"],
        object: 2,
        type: .directory,
        coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
      )
    )
  )
  accumulator.receive(
    .observed(
      authorityNode(
        path: ["cache", "object"],
        object: 3,
        type: .regular,
        topology: StorageTopologyEvidence(
          linkCount: .known(2),
          mayShareBlocks: .unknown(reason: "collector incomplete"),
          sharesAllBlocks: .unknown(reason: "collector incomplete"),
          cloneID: .unknown(reason: "collector incomplete"),
          cloneRefcount: .unknown(reason: "collector incomplete"),
          conditionalGroupReclaim: .unknown(reason: "collector incomplete")
        )
      )
    )
  )
  accumulator.receive(
    .directoryClosed(authorityNode(path: ["cache"], object: 2, type: .directory))
  )

  let result = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(),
    evidence: accumulator.snapshot()
  )

  #expect(result.releaseOwnerIndex.allocationGroups.isEmpty)
  #expect(result.releaseGraph?.fileObjects.isEmpty == true)
}

@Test func candidateIDsBindRootIDWhenRawRootsAlias() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  for (rootID, object) in [("root", UInt64(2)), ("second", UInt64(20))] {
    accumulator.receive(
      .observed(
        authorityNode(
          rootID: rootID,
          path: ["cache"],
          object: object,
          type: .directory,
          coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
        )
      )
    )
    accumulator.receive(
      .directoryClosed(
        authorityNode(rootID: rootID, path: ["cache"], object: object, type: .directory)
      )
    )
  }

  let result = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(includeSecondRoot: true, aliasSecondRawRoot: true),
    evidence: accumulator.snapshot()
  )

  #expect(result.items.count == 2)
  #expect(Set(result.items.map(\.candidateID)).count == 2)
}

@Test func boundedProjectionIsPlanTypeFirstAndReportsTruncation() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  for (name, object) in [("temp", UInt64(2)), ("cache", UInt64(3))] {
    let provisional = authorityNode(
      path: [name],
      object: object,
      type: .directory,
      coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
    )
    accumulator.receive(.observed(provisional))
    accumulator.receive(
      .directoryClosed(authorityNode(path: [name], object: object, type: .directory))
    )
  }
  let result = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(),
    evidence: accumulator.snapshot()
  )
  let projection = result.presentation(maximumEntries: 1)

  #expect(projection.totalEntryCount == 2)
  #expect(projection.wasTruncated)
  #expect(projection.entries.map(\.kind) == [.cache])
}

@Test func explicitlyEnabledAuthorityTeeCanPlanFinalizedScannerEvents() throws {
  let result = authorityScanResult()
  let session = RuntimePolicyAuthoritySession(scope: result.reference.resolvedScope)
  let broker = SerialEventBroker { _ in }
  let streaming = StreamingNodeSink(
    broker: broker,
    scanSessionID: "authority-reachability",
    roots: result.reference.resolvedScope.roots
  )
  let tee = AuthorityTeeNodeSink(authority: session, streaming: streaming)
  tee.receive(
    .observed(
      authorityNode(
        path: ["cache"],
        object: 2,
        type: .directory,
        coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
      )
    )
  )
  tee.receive(
    .directoryClosed(authorityNode(path: ["cache"], object: 2, type: .directory))
  )
  try broker.finish()

  #expect(throws: RuntimePolicyAuthoritySessionError.scanNotFinalized) {
    try session.makePlan()
  }
  try session.finalize(result)
  let plan = try session.makePlan()

  #expect(plan.items.count == 1)
  #expect(plan.items[0].kind == .cache)
  #expect(plan.plan.evidenceSnapshots.count == 1)
}

@Test func coordinatorDoesNotExposePlanDuringFinalBrokerWindow() {
  for state: Diskplan_V1_ScanState in [.finished, .finalizedPartial] {
    #expect(!ScanCoordinator.authorityPlanIsReachable(state: state, workerFinished: false))
    #expect(ScanCoordinator.authorityPlanIsReachable(state: state, workerFinished: true))
  }
}

@Test func coordinatorDoesNotExposePlanAfterFinalBrokerFailure() {
  #expect(!ScanCoordinator.authorityPlanIsReachable(state: .failed, workerFinished: true))
}

@Test func coordinatorWaitsForFinalBrokerBeforeExposingCompleteOrPartialPlan() throws {
  let terminalCases: [(Diskplan_V1_ScanState, ScanMachineState)] = [
    (.finished, .complete), (.finalizedPartial, .partial),
  ]
  for (terminalState, machineState) in terminalCases {
    let result = authorityScanResult(state: machineState)
    let session = seededAuthoritySession(result: result)
    let writerGate = AuthorityTestGate()
    let writerEntered = AuthorityTestFlag()
    let publicationFinished = AuthorityTestFlag()
    let broker = SerialEventBroker(semanticCapacity: 1) { data in
      if isScanFinalizedBrokerPayload(data) {
        writerEntered.set()
        writerGate.wait()
      }
    }
    let coordinator = ScanCoordinator(broker: broker, authoritySession: session)
    Thread {
      coordinator.publishFinalizedAuthorityResult(
        result,
        state: terminalState,
        reason: "authority concurrency fixture"
      )
      publicationFinished.set()
    }.start()
    defer { writerGate.open() }
    #expect(writerEntered.wait(timeout: 1.0))

    #expect(throws: RuntimePolicyAuthoritySessionError.scanNotFinalized) {
      try coordinator.makePlanForCurrentSession()
    }
    writerGate.open()
    #expect(publicationFinished.wait(timeout: 1.0))
    #expect(try coordinator.makePlanForCurrentSession().items.count == 1)
    try broker.finish()
  }
}

@Test func coordinatorKeepsFinalizedAuthorityUnavailableWhenFinalBrokerFails() throws {
  let result = authorityScanResult()
  let session = seededAuthoritySession(result: result)
  let writerGate = AuthorityTestGate()
  let writerEntered = AuthorityTestFlag()
  let publicationFinished = AuthorityTestFlag()
  let broker = SerialEventBroker(semanticCapacity: 1) { data in
    if isScanFinalizedBrokerPayload(data) {
      writerEntered.set()
      writerGate.wait()
      throw AuthorityTestWriterFailure.failed
    }
  }
  let coordinator = ScanCoordinator(broker: broker, authoritySession: session)
  Thread {
    coordinator.publishFinalizedAuthorityResult(
      result,
      state: .finished,
      reason: "authority failure fixture"
    )
    publicationFinished.set()
  }.start()
  defer { writerGate.open() }
  #expect(writerEntered.wait(timeout: 1.0))

  #expect(throws: RuntimePolicyAuthoritySessionError.scanNotFinalized) {
    try coordinator.makePlanForCurrentSession()
  }
  writerGate.open()
  #expect(publicationFinished.wait(timeout: 1.0))
  #expect(throws: RuntimePolicyAuthoritySessionError.scanNotFinalized) {
    try coordinator.makePlanForCurrentSession()
  }
  #expect(throws: EventBrokerError.self) { try broker.finish() }
}

@Test func equalCloneIDsOnDifferentDevicesRemainSeparateAllocationGroups() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  for (rootID, directoryObject, fileObject, device) in [
    ("root", UInt64(2), UInt64(3), Int64(1)),
    ("second", UInt64(20), UInt64(21), Int64(2)),
  ] {
    accumulator.receive(
      .observed(
        authorityNode(
          rootID: rootID,
          path: ["cache"],
          object: directoryObject,
          type: .directory,
          coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
        )
      )
    )
    accumulator.receive(
      .observed(
        authorityNode(
          rootID: rootID,
          path: ["cache", "clone"],
          device: device,
          object: fileObject,
          type: .regular,
          topology: StorageTopologyEvidence(
            linkCount: .known(1),
            mayShareBlocks: .known(true),
            sharesAllBlocks: .known(true),
            cloneID: .known(44),
            cloneRefcount: .known(1),
            conditionalGroupReclaim: .exact(4_096)
          )
        )
      )
    )
    accumulator.receive(
      .directoryClosed(
        authorityNode(
          rootID: rootID, path: ["cache"], object: directoryObject, type: .directory)
      )
    )
  }

  let plan = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(includeSecondRoot: true),
    evidence: accumulator.snapshot()
  )

  #expect(
    plan.releaseOwnerIndex.allocationGroups.map(\.id) == [
      "clone:device:1:id:44", "clone:device:2:id:44",
    ]
  )
  #expect(plan.releaseOwnerIndex.allocationGroups.allSatisfy { $0.fileObjectIDs.count == 1 })
}

@Test func cloneRefcountCountsDistinctObjectsAfterHardlinkOwnerValidation() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  accumulator.receive(
    .observed(
      authorityNode(
        path: ["cache"],
        object: 2,
        type: .directory,
        coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
      )
    )
  )
  for (name, object, linkCount) in [
    ("hard-a", UInt64(55), UInt32(2)),
    ("hard-b", UInt64(55), UInt32(2)),
    ("other", UInt64(56), UInt32(1)),
  ] {
    accumulator.receive(
      .observed(
        authorityNode(
          path: ["cache", name],
          device: 1,
          object: object,
          type: .regular,
          topology: StorageTopologyEvidence(
            linkCount: .known(linkCount),
            mayShareBlocks: .known(true),
            sharesAllBlocks: .known(true),
            cloneID: .known(44),
            cloneRefcount: .known(2),
            conditionalGroupReclaim: .exact(8_192)
          )
        )
      )
    )
  }
  accumulator.receive(
    .directoryClosed(authorityNode(path: ["cache"], object: 2, type: .directory))
  )

  let plan = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(),
    evidence: accumulator.snapshot()
  )

  #expect(plan.releaseOwnerIndex.owners.count == 3)
  #expect(plan.releaseOwnerIndex.allocationGroups.count == 1)
  #expect(plan.releaseOwnerIndex.allocationGroups[0].fileObjectIDs.count == 2)
  #expect(plan.releaseOwnerIndex.allocationGroups[0].cloneRefCount.knownValue == 2)
  #expect(plan.releaseOwnerIndex.dependencyCompleteByCandidate.values.allSatisfy { $0 })
}

@Test func authorityBudgetExhaustionRetainsStableTopCandidateAndFailsClosed() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator(
    budget: AuthorityRetentionBudget(
      maximumCandidateSummaries: 1,
      maximumSharedObjectKeys: 1,
      maximumOwnerReferences: 1,
      maximumEstimatedBytes: 1 * 1_024 * 1_024
    )
  )
  for (name, object) in [("temp", UInt64(2)), ("cache", UInt64(3))] {
    accumulator.receive(
      .observed(
        authorityNode(
          path: [name],
          object: object,
          type: .directory,
          coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
        )
      )
    )
    accumulator.receive(
      .directoryClosed(authorityNode(path: [name], object: object, type: .directory))
    )
  }
  let evidence = accumulator.snapshot()
  let plan = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(),
    evidence: evidence
  )

  #expect(
    evidence.candidatesByPath.values.map { $0.node.path.components.last?.displayName }
      == ["cache"]
  )
  #expect(evidence.retention.candidateSummariesOmitted > 0)
  #expect(evidence.retention.maximumPlanningBytes == 7 * 1_024 * 1_024 / 8)
  #expect(
    evidence.retention.estimatedPlanningBytes
      == evidence.retention.estimatedRetainedBytes * 6
  )
  #expect(evidence.retention.estimatedPlanningBytes <= evidence.retention.maximumPlanningBytes)
  #expect(!evidence.retention.planningBudgetExceeded)
  #expect(plan.items[0].reasons.contains(.authorityBudgetExhausted))
  #expect(plan.items[0].reasons.contains(.dependencyCoverageIncomplete))
  #expect(plan.plan.actions.isEmpty)
}

@Test func authorityConfigurationBudgetCountsPeakCopiesAndHashesLargeFieldsStreaming() {
  let limit = AuthorityRetentionBudget.maximumAcceptedBytes
  let sourceBytes = limit / 2 - 1_024
  #expect(
    authorityFinalizationPeakBytes(sourceBytes: sourceBytes, configurationBytes: 1_024)
      == limit
  )
  #expect(
    authorityFinalizationPeakBytes(sourceBytes: sourceBytes, configurationBytes: 1_025)
      > limit
  )
  #expect(
    authorityFinalizationPeakBytes(sourceBytes: Int.max - 1, configurationBytes: Int.max)
      == Int.max
  )

  var encoder = RuntimeAuthorityEncoder(domain: "streaming-spy", hashingOnly: true)
  encoder.data(Data(repeating: 0x5a, count: 128 * 1_024))
  #expect(encoder.maximumHashBufferBytes < 64 * 1_024)
  #expect(encoder.finalizeHash().count == 32)
}

@Test func bytePressurePlansAllEvictionsBeforeCommittingStableTopK() {
  func retainedPaths(existingRoots: [String]) -> (Set<RawPath>, AuthorityRetentionStatus) {
    let accumulator = BoundedAuthorityEvidenceAccumulator(
      budget: AuthorityRetentionBudget(
        maximumCandidateSummaries: 100,
        maximumSharedObjectKeys: 100,
        maximumOwnerReferences: 100,
        maximumEstimatedBytes: 1 * 1_024 * 1_024
      )
    )
    for (offset, rootID) in existingRoots.enumerated() {
      let node = authorityNode(
        rootID: rootID,
        path: ["cache"],
        object: UInt64(offset + 10),
        type: .directory,
        immediatePrivateReclaim: 1
      )
      accumulator.receive(.observed(node))
      accumulator.receive(.directoryClosed(node))
    }

    let first = String(repeating: "a", count: 4_000)
    let second = String(repeating: "b", count: 4_000)
    let firstAncestor = authorityNode(
      rootID: "priority",
      path: [first],
      object: 1_000,
      type: .directory
    )
    let secondAncestor = authorityNode(
      rootID: "priority",
      path: [first, second],
      object: 1_001,
      type: .directory
    )
    let candidate = authorityNode(
      rootID: "priority",
      path: [first, second, "cache"],
      object: 1_002,
      type: .directory,
      immediatePrivateReclaim: 1_000_000
    )
    accumulator.receive(.observed(firstAncestor))
    accumulator.receive(.observed(secondAncestor))
    accumulator.receive(.observed(candidate))
    accumulator.receive(.directoryClosed(candidate))

    let evidence = accumulator.snapshot()
    return (Set(evidence.candidatesByPath.keys), evidence.retention)
  }

  let roots = (0..<10).map { String(format: "root-%02d", $0) }
  let forward = retainedPaths(existingRoots: roots)
  let reverse = retainedPaths(existingRoots: Array(roots.reversed()))

  #expect(forward.0 == reverse.0)
  #expect(forward.0.contains { $0.rootID == "priority" })
  #expect(forward.0.count < roots.count + 1)
  #expect(forward.1.candidateSummariesOmitted > 2)
}

@Test func rejectedCandidateUpdateKeepsPreviouslyRetainedRecord() {
  let accumulator = BoundedAuthorityEvidenceAccumulator(
    budget: AuthorityRetentionBudget(
      maximumCandidateSummaries: 100,
      maximumSharedObjectKeys: 100,
      maximumOwnerReferences: 100,
      maximumEstimatedBytes: 480 * 1_024
    )
  )
  let parentName = String(repeating: "p", count: 4_000)
  let candidate = authorityNode(
    path: [parentName, "cache"],
    object: 2,
    type: .directory
  )
  accumulator.receive(.observed(candidate))
  accumulator.receive(
    .observed(authorityNode(path: [parentName], object: 3, type: .directory))
  )
  accumulator.receive(
    .observed(
      authorityNode(
        path: [String(repeating: "f", count: 1_000)],
        object: 4,
        type: .directory
      )
    )
  )
  accumulator.receive(.observed(candidate))

  let evidence = accumulator.snapshot()
  let retained = evidence.candidatesByPath[candidate.path]
  #expect(retained != nil)
  #expect(retained?.ancestors.isEmpty == true)
  #expect(evidence.topologyCoverageIncomplete)
}

/// Opt-in accepted-plan checkpoint. This emits one candidate at a time and never
/// constructs an array proportional to the synthetic corpus.
@Test func syntheticMillionEntryStreamingRetentionCheckpoint() throws {
  guard
    ProcessInfo.processInfo.environment["DISKPLAN_RUN_MILLION_ENTRY_GATE"] == "1"
  else { return }

  let entryCount = 1_000_000
  let budget = AuthorityRetentionBudget(
    maximumCandidateSummaries: 64,
    maximumSharedObjectKeys: 64,
    maximumOwnerReferences: 64,
    maximumEstimatedBytes: 2 * 1_024 * 1_024
  )

  func run(reverse: Bool, chunkSize: Int) throws -> (
    AuthorityEvidenceSnapshot, RuntimePolicyAuthorityResult
  ) {
    let accumulator = BoundedAuthorityEvidenceAccumulator(budget: budget)
    let parent = authorityNode(
      path: ["releases"],
      object: 2,
      type: .directory
    )
    accumulator.receive(.observed(parent))
    var emitted = 0
    while emitted < entryCount {
      let count = min(chunkSize, entryCount - emitted)
      for offset in 0..<count {
        let ordinal = emitted + offset
        let index = reverse ? entryCount - ordinal - 1 : ordinal
        let digits = String(index)
        let version = "v" + String(repeating: "0", count: 7 - digits.count) + digits
        let candidate = authorityNode(
          path: ["releases", version],
          object: UInt64(index + 10),
          type: .directory,
          immediatePrivateReclaim: UInt64(index % 10_007)
        )
        accumulator.receive(.observed(candidate))
        accumulator.receive(.directoryClosed(candidate))
      }
      emitted += count
    }
    accumulator.receive(.directoryClosed(parent))
    let evidence = accumulator.snapshot()
    let result = try RuntimePolicyAuthority().makePlan(
      scanResult: authorityScanResult(
        entriesObserved: UInt64(entryCount + 1),
        directoriesClosed: UInt64(entryCount + 1),
        entryBudget: UInt64(entryCount + 1)
      ),
      evidence: evidence
    )
    return (evidence, result)
  }

  let ascending = try run(reverse: false, chunkSize: 1)
  let descending = try run(reverse: true, chunkSize: 4_096)

  #expect(
    Set(ascending.0.candidatesByPath.keys) == Set(descending.0.candidatesByPath.keys)
  )
  #expect(ascending.0.retention == descending.0.retention)
  #expect(ascending.0.candidatesByPath.count <= budget.maximumCandidateSummaries)
  #expect(ascending.0.sharedFileObservationsByPath.isEmpty)
  #expect(
    ascending.0.retention.candidateSummariesOmitted
      == UInt64(entryCount - ascending.0.candidatesByPath.count)
  )
  #expect(ascending.0.retention.estimatedRetainedBytes <= 2 * 1_024 * 1_024 / 8)
  #expect(!ascending.0.retention.planningBudgetExceeded)
  #expect(
    ascending.1.plan.globalFacts.captureID
      == descending.1.plan.globalFacts.captureID
  )
  #expect(ascending.1.items.map(\.candidateID) == descending.1.items.map(\.candidateID))
  #expect(
    ascending.1.items.allSatisfy { $0.reasons.contains(.authorityBudgetExhausted) }
  )
}

@Test func nameOnlyRecognizerProducesAReportOnlyTypeHint() throws {
  let result = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(),
    evidence: singleClosedCandidateCorpus(
      authorityNode(path: ["build"], object: 2, type: .directory)
    )
  )

  #expect(result.items.count == 1)
  #expect(result.items[0].reasons.contains(.nameOnlyTypeHint))
  #expect(result.items[0].reasons.contains(.recoverabilityProvenanceUnavailable))
  #expect(result.plan.evidenceSnapshots[0].classificationClaims.isEmpty)
  #expect(result.plan.evidenceSnapshots[0].recoverability.knownValue == nil)
  #expect(result.plan.actions.isEmpty)
}

@Test func codexTemporaryNameAloneCannotClaimManagedCleanupAuthority() throws {
  let result = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(),
    evidence: singleClosedCandidateCorpus(
      authorityNode(path: [".codex-tmp"], object: 2, type: .directory)
    )
  )

  #expect(result.items.count == 1)
  #expect(result.items[0].kind == .codexTemporary)
  #expect(result.items[0].reasons.contains(.nameOnlyTypeHint))
  #expect(result.plan.evidenceSnapshots[0].classificationClaims.isEmpty)
  #expect(result.plan.evidenceSnapshots[0].adapterScope == .genericRemove)
  #expect(result.plan.evidenceSnapshots[0].recoverability.knownValue == nil)
  #expect(result.plan.actions.isEmpty)
}

@Test func nestedCandidatesAssignPhysicalOwnersOnlyToTheDeepestCandidate() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  accumulator.receive(
    .observed(
      authorityNode(
        path: ["cache"],
        object: 2,
        type: .directory,
        coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
      )
    )
  )
  accumulator.receive(
    .observed(
      authorityNode(
        path: ["cache", "temp"],
        object: 3,
        type: .directory,
        coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
      )
    )
  )
  accumulator.receive(
    .observed(
      authorityNode(
        path: ["cache", "temp", "clone"],
        object: 4,
        type: .regular,
        topology: StorageTopologyEvidence(
          linkCount: .known(1),
          mayShareBlocks: .known(true),
          sharesAllBlocks: .known(true),
          cloneID: .known(44),
          cloneRefcount: .known(1),
          conditionalGroupReclaim: .exact(4_096)
        )
      )
    )
  )
  accumulator.receive(
    .directoryClosed(authorityNode(path: ["cache", "temp"], object: 3, type: .directory))
  )
  accumulator.receive(
    .directoryClosed(authorityNode(path: ["cache"], object: 2, type: .directory))
  )

  let plan = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(),
    evidence: accumulator.snapshot()
  )
  let child = try #require(plan.items.first { $0.kind == .temporary })

  #expect(plan.releaseOwnerIndex.owners.count == 1)
  #expect(plan.releaseOwnerIndex.owners[0].candidateID == child.candidateID)
  #expect(plan.releaseOwnerIndex.overlaps.count == 1)
  #expect(plan.items.allSatisfy { $0.reasons.contains(.candidateOverlap) })
  #expect(plan.releaseOwnerIndex.dependencyCompleteByCandidate.values.allSatisfy { !$0 })
}

@Test func sameDirectoryAliasRootsCreateOnePhysicalOwnerAndAnOverlapBlocker() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  for rootID in ["root", "second"] {
    let directory = authorityNode(
      rootID: rootID,
      path: ["cache"],
      device: 1,
      object: 2,
      type: .directory
    )
    accumulator.receive(.observed(directory))
    accumulator.receive(
      .observed(
        authorityNode(
          rootID: rootID,
          path: ["cache", "clone"],
          device: 1,
          object: 3,
          type: .regular,
          topology: cloneTopologyFixture()
        )
      )
    )
    accumulator.receive(.directoryClosed(directory))
  }

  let plan = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(
      includeSecondRoot: true,
      aliasSecondRawRoot: true,
      secondRootIdentityAliasesFirst: true
    ),
    evidence: accumulator.snapshot()
  )

  #expect(plan.items.count == 2)
  #expect(plan.releaseOwnerIndex.owners.count == 1)
  #expect(plan.releaseOwnerIndex.overlaps.count == 1)
  #expect(plan.items.allSatisfy { $0.reasons.contains(.candidateOverlap) })
}

@Test func nestedExplicitRootsCreateOnePhysicalOwnerAndAnOverlapBlocker() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  accumulator.receive(
    .observed(authorityNode(path: ["nested"], object: 19, type: .directory))
  )
  let outer = authorityNode(
    path: ["nested", "cache"],
    device: 1,
    object: 20,
    type: .directory
  )
  let inner = authorityNode(
    rootID: "second",
    path: ["cache"],
    device: 1,
    object: 20,
    type: .directory
  )
  accumulator.receive(.observed(outer))
  accumulator.receive(.observed(inner))
  accumulator.receive(
    .observed(
      authorityNode(
        path: ["nested", "cache", "clone"],
        device: 1,
        object: 21,
        type: .regular,
        topology: cloneTopologyFixture()
      )
    )
  )
  accumulator.receive(
    .observed(
      authorityNode(
        rootID: "second",
        path: ["cache", "clone"],
        device: 1,
        object: 21,
        type: .regular,
        topology: cloneTopologyFixture()
      )
    )
  )
  accumulator.receive(.directoryClosed(outer))
  accumulator.receive(
    .directoryClosed(authorityNode(path: ["nested"], object: 19, type: .directory))
  )
  accumulator.receive(.directoryClosed(inner))

  let plan = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(
      includeSecondRoot: true,
      secondRootRawAbsolutePath: Data("/fixture/root/nested".utf8)
    ),
    evidence: accumulator.snapshot()
  )

  #expect(plan.items.count == 2)
  #expect(plan.releaseOwnerIndex.owners.count == 1)
  #expect(plan.releaseOwnerIndex.overlaps.count == 1)
  #expect(plan.items.allSatisfy { $0.reasons.contains(.candidateOverlap) })
}

@Test func sameObjectAliasesUseRelativeDepthAndEmitNoBidirectionalOverlap() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  let outer = authorityNode(path: ["cache"], device: 1, object: 2, type: .directory)
  let aliasOuter = authorityNode(
    rootID: "second", path: ["cache"], device: 1, object: 2, type: .directory)
  let container = authorityNode(
    rootID: "second",
    path: ["cache", "container"],
    device: 1,
    object: 3,
    type: .directory
  )
  let deepest = authorityNode(
    rootID: "second",
    path: ["cache", "container", "temp"],
    device: 1,
    object: 4,
    type: .directory
  )
  accumulator.receive(.observed(outer))
  accumulator.receive(.observed(aliasOuter))
  accumulator.receive(.observed(container))
  accumulator.receive(.observed(deepest))
  accumulator.receive(
    .observed(
      authorityNode(
        rootID: "second",
        path: ["cache", "container", "temp", "clone"],
        device: 1,
        object: 5,
        type: .regular,
        topology: cloneTopologyFixture()
      )
    )
  )
  accumulator.receive(.directoryClosed(deepest))
  accumulator.receive(.directoryClosed(container))
  accumulator.receive(.directoryClosed(aliasOuter))
  accumulator.receive(.directoryClosed(outer))

  let plan = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(
      includeSecondRoot: true,
      secondRootRawAbsolutePath: Data("/x".utf8),
      secondRootIdentityAliasesFirst: true
    ),
    evidence: accumulator.snapshot()
  )
  let deepestItem = try #require(plan.items.first { $0.kind == .temporary })

  #expect(plan.releaseOwnerIndex.owners.count == 1)
  #expect(plan.releaseOwnerIndex.owners[0].candidateID == deepestItem.candidateID)
  #expect(plan.releaseOwnerIndex.overlaps.count == 2)
  #expect(
    Set(
      plan.releaseOwnerIndex.overlaps.map {
        "\($0.ancestorCandidateID)->\($0.descendantCandidateID)"
      }
    ).count == plan.releaseOwnerIndex.overlaps.count
  )
  #expect(
    plan.releaseOwnerIndex.overlaps.allSatisfy { edge in
      !plan.releaseOwnerIndex.overlaps.contains {
        $0.ancestorCandidateID == edge.descendantCandidateID
          && $0.descendantCandidateID == edge.ancestorCandidateID
      }
    }
  )
}

@Test func mixedAliasAndRawContainmentUsesShortestDistanceForOwner() throws {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  let nested = authorityNode(path: ["nested"], device: 2, object: 19, type: .directory)
  let rawAncestor = authorityNode(
    path: ["nested", "cache"], device: 2, object: 20, type: .directory)
  let aliasCache = authorityNode(
    rootID: "third", path: ["cache"], device: 2, object: 20, type: .directory)
  let aliasContainer = authorityNode(
    rootID: "third",
    path: ["cache", "container"],
    device: 2,
    object: 21,
    type: .directory
  )
  let aliasDeepest = authorityNode(
    rootID: "third",
    path: ["cache", "container", "temp"],
    device: 2,
    object: 22,
    type: .directory
  )
  for node in [nested, rawAncestor, aliasCache, aliasContainer, aliasDeepest] {
    accumulator.receive(.observed(node))
  }
  accumulator.receive(
    .observed(
      authorityNode(
        rootID: "second",
        path: ["cache", "container", "temp", "clone"],
        device: 2,
        object: 23,
        type: .regular,
        topology: cloneTopologyFixture()
      )
    )
  )
  accumulator.receive(.directoryClosed(aliasDeepest))
  accumulator.receive(.directoryClosed(aliasContainer))
  accumulator.receive(.directoryClosed(aliasCache))
  accumulator.receive(.directoryClosed(rawAncestor))
  accumulator.receive(.directoryClosed(nested))

  let rawRoot = Data("/very/long/prefix/that/is/root".utf8)
  let plan = try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(
      firstRootRawAbsolutePath: rawRoot,
      includeSecondRoot: true,
      secondRootRawAbsolutePath: rawRoot + Data("/nested".utf8),
      includeThirdRootAliasOfSecond: true
    ),
    evidence: accumulator.snapshot()
  )
  let deepestItem = try #require(plan.items.first { $0.kind == .temporary })

  #expect(plan.releaseOwnerIndex.owners.count == 1)
  #expect(plan.releaseOwnerIndex.owners[0].candidateID == deepestItem.candidateID)
}

@Test func contradictoryCloneAndNonCloneHardlinkAliasesFailTheWholeObjectClosed() throws {
  let plan = try hardlinkAliasPlan(
    topologies: [
      StorageTopologyEvidence(
        linkCount: .known(2),
        mayShareBlocks: .known(true),
        sharesAllBlocks: .known(true),
        cloneID: .known(44),
        cloneRefcount: .known(1),
        conditionalGroupReclaim: .exact(4_096)
      ),
      StorageTopologyEvidence(
        linkCount: .known(2),
        mayShareBlocks: .known(false),
        sharesAllBlocks: .known(false),
        cloneID: .absent(reason: "not cloned"),
        cloneRefcount: .absent(reason: "not cloned"),
        conditionalGroupReclaim: .exact(0)
      ),
    ]
  )

  #expect(plan.releaseOwnerIndex.dependencyCompleteByCandidate.values.allSatisfy { !$0 })
  #expect(!plan.releaseOwnerIndex.allocationGroups.isEmpty)
  #expect(plan.releaseOwnerIndex.allocationGroups.allSatisfy { $0.sharedBytes.knownValue == nil })
}

@Test func mismatchedCloneIDOrRefcountAcrossHardlinkAliasesFailsGroupsClosed() throws {
  let variants: [[StorageTopologyEvidence]] = [
    [cloneAliasTopology(cloneID: 44, refcount: 2), cloneAliasTopology(cloneID: 45, refcount: 2)],
    [cloneAliasTopology(cloneID: 44, refcount: 2), cloneAliasTopology(cloneID: 44, refcount: 3)],
  ]
  for topologies in variants {
    let plan = try hardlinkAliasPlan(topologies: topologies)
    #expect(plan.releaseOwnerIndex.dependencyCompleteByCandidate.values.allSatisfy { !$0 })
    #expect(!plan.releaseOwnerIndex.allocationGroups.isEmpty)
    #expect(
      plan.releaseOwnerIndex.allocationGroups.allSatisfy {
        $0.cloneRefCount.knownValue == nil && $0.sharedBytes.knownValue == nil
      }
    )
  }
}

private func hardlinkAliasPlan(
  topologies: [StorageTopologyEvidence]
) throws -> RuntimePolicyAuthorityResult {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  let candidate = authorityNode(path: ["cache"], object: 2, type: .directory)
  accumulator.receive(.observed(candidate))
  for (index, topology) in topologies.enumerated() {
    accumulator.receive(
      .observed(
        authorityNode(
          path: ["cache", "alias-\(index)"],
          device: 1,
          object: 55,
          type: .regular,
          topology: topology
        )
      )
    )
  }
  accumulator.receive(.directoryClosed(candidate))
  return try RuntimePolicyAuthority().makePlan(
    scanResult: authorityScanResult(),
    evidence: accumulator.snapshot()
  )
}

private func cloneAliasTopology(cloneID: UInt64, refcount: UInt32) -> StorageTopologyEvidence {
  StorageTopologyEvidence(
    linkCount: .known(2),
    mayShareBlocks: .known(true),
    sharesAllBlocks: .known(true),
    cloneID: .known(cloneID),
    cloneRefcount: .known(refcount),
    conditionalGroupReclaim: .exact(4_096)
  )
}

private func cloneTopologyFixture() -> StorageTopologyEvidence {
  StorageTopologyEvidence(
    linkCount: .known(1),
    mayShareBlocks: .known(true),
    sharesAllBlocks: .known(true),
    cloneID: .known(44),
    cloneRefcount: .known(1),
    conditionalGroupReclaim: .exact(4_096)
  )
}

private func seededAuthoritySession(result: ScanResult) -> RuntimePolicyAuthoritySession {
  let session = RuntimePolicyAuthoritySession(scope: result.reference.resolvedScope)
  let provisional = authorityNode(
    path: ["cache"],
    object: 2,
    type: .directory,
    coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete])
  )
  session.receive(.observed(provisional))
  session.receive(
    .directoryClosed(authorityNode(path: ["cache"], object: 2, type: .directory))
  )
  return session
}

private enum AuthorityTestWriterFailure: Error {
  case failed
}

private func isScanFinalizedBrokerPayload(_ data: Data) -> Bool {
  guard let envelope = try? Diskplan_V1_Envelope(serializedBytes: data),
    case .engineEvent(let event) = envelope.body,
    let body = event.body,
    case .scanFinalized = body
  else { return false }
  return true
}

private final class AuthorityTestGate: @unchecked Sendable {
  private let condition = NSCondition()
  private var isOpen = false

  func wait() {
    condition.lock()
    while !isOpen { condition.wait() }
    condition.unlock()
  }

  func open() {
    condition.lock()
    isOpen = true
    condition.broadcast()
    condition.unlock()
  }
}

private final class AuthorityTestFlag: @unchecked Sendable {
  private let condition = NSCondition()
  private var isSet = false

  func set() {
    condition.lock()
    isSet = true
    condition.broadcast()
    condition.unlock()
  }

  func wait(timeout: TimeInterval) -> Bool {
    condition.lock()
    defer { condition.unlock() }
    let deadline = Date(timeIntervalSinceNow: timeout)
    while !isSet {
      guard condition.wait(until: deadline) else { return isSet }
    }
    return true
  }
}

private func singleClosedCandidateCorpus(_ node: ScannedNode) -> AuthorityEvidenceSnapshot {
  let accumulator = BoundedAuthorityEvidenceAccumulator()
  accumulator.receive(
    .observed(
      authorityNode(
        rootID: node.path.rootID,
        path: node.path.components.map(\.displayName),
        object: node.identity.value!.fileID,
        type: .directory,
        coverage: Coverage(completeness: .partial, reasons: [.subtreeIncomplete]),
        providerBoundary: node.providerBoundary
      )
    )
  )
  accumulator.receive(.directoryClosed(node))
  return accumulator.snapshot()
}

private func authorityScanResult(
  retainedNodes: [ScannedNode] = [],
  processActivity: DiskplanScan.Observation<[ProcessActivityRecord]> = .known([]),
  firstRootRawAbsolutePath: Data = Data("/fixture/root".utf8),
  includeSecondRoot: Bool = false,
  aliasSecondRawRoot: Bool = false,
  secondRootRawAbsolutePath: Data? = nil,
  secondRootIdentityAliasesFirst: Bool = false,
  includeThirdRootAliasOfSecond: Bool = false,
  state: ScanMachineState = .complete,
  wallClockSeconds: TimeInterval = 2_000_000_000,
  entriesObserved: UInt64 = 2,
  directoriesClosed: UInt64 = 1,
  entryBudget: UInt64 = 100
) -> ScanResult {
  let requests =
    [
      ScanRootRequest(rootID: "root", rawAbsolutePath: firstRootRawAbsolutePath)
    ]
    + (includeSecondRoot
      ? [
        ScanRootRequest(
          rootID: "second",
          rawAbsolutePath: secondRootRawAbsolutePath
            ?? (aliasSecondRawRoot
              ? Data("/fixture/root".utf8) : Data("/fixture/second".utf8))
        )
      ] : [])
    + (includeThirdRootAliasOfSecond
      ? [ScanRootRequest(rootID: "third", rawAbsolutePath: Data("/x".utf8))] : [])
  let scope = try! ResolvedScanScope(
    resolverVersion: 1,
    profile: .fullAudit,
    roots: requests,
    budget: StructuralBudget(
      maximumEntriesPerRoot: entryBudget,
      maximumDepth: 8,
      retainedNodeCount: 1
    ),
    maximumDurationNanoseconds: nil
  )
  let reference = ScanReference(
    wallClock: Date(timeIntervalSince1970: wallClockSeconds),
    monotonicNanoseconds: 99,
    resolvedScope: scope,
    collectorConfiguration: ScanCollectorConfiguration(
      processActivityCollectorID: "fixture",
      processActivityDeadlineNanoseconds: 100,
      globalFactCollectorIDs: ["fixture"]
    )
  )
  let roots = requests.enumerated().map { index, request in
    let identityIndex =
      includeThirdRootAliasOfSecond && index == 2
      ? 1 : (secondRootIdentityAliasesFirst && index == 1 ? 0 : index)
    return RootScanResult(
      binding: RootBinding(
        resolverVersion: 1,
        rootID: request.rootID,
        rawAbsolutePath: request.rawAbsolutePath,
        identity: DiskplanScan.ObjectIdentity(
          device: Int64(identityIndex + 1),
          fileID: UInt64(100 + identityIndex),
          objectType: .directory
        )
      ),
      providerBoundary: .localOrUnindicated,
      aggregateBytes: ItemByteEvidence(
        logical: .exact(4_096),
        nominalAllocated: .exact(4_096),
        immediatePrivateReclaim: .exact(4_096)
      ),
      coverage: .complete,
      entriesObserved: entriesObserved,
      directoriesClosed: directoriesClosed
    )
  }
  return ScanResult(
    reference: reference,
    state: state,
    roots: roots,
    rootFailures: [],
    progress: ScanProgress(
      entriesObserved: entriesObserved,
      directoriesClosed: directoriesClosed,
      rootsComplete: UInt64(roots.count),
      rootsPartial: 0,
      retainedNodes: retainedNodes
    ),
    coverage: .complete,
    globalFacts: .publicEvidenceUnavailable,
    processActivity: processActivity
  )
}

private func authorityNode(
  rootID: String = "root",
  path: [String],
  device: Int64? = nil,
  object: UInt64,
  type: ScannedObjectType,
  immediatePrivateReclaim: UInt64 = 4_096,
  identity: DiskplanScan.Observation<DiskplanScan.ObjectIdentity>? = nil,
  coverage: Coverage = .complete,
  providerBoundary: ProviderBoundary = .localOrUnindicated,
  topology: StorageTopologyEvidence = StorageTopologyEvidence(
    linkCount: .known(1),
    mayShareBlocks: .known(false),
    sharesAllBlocks: .known(false),
    cloneID: .absent(reason: "not cloned"),
    cloneRefcount: .absent(reason: "not cloned"),
    conditionalGroupReclaim: .exact(0)
  )
) -> ScannedNode {
  ScannedNode(
    path: authorityPath(path, rootID: rootID),
    identity: identity
      ?? .known(
        DiskplanScan.ObjectIdentity(
          device: device ?? (rootID == "root" ? 1 : 2), fileID: object, objectType: type)
      ),
    bytes: ItemByteEvidence(
      logical: .exact(4_096),
      nominalAllocated: .exact(4_096),
      immediatePrivateReclaim: .exact(immediatePrivateReclaim)
    ),
    storageTopology: topology,
    filesystemTimes: FilesystemTimeEvidence(
      accessTime: .known(CanonicalFilesystemTime(secondsSinceEpoch: 1_000, nanoseconds: 0)),
      modificationTime: .known(
        CanonicalFilesystemTime(secondsSinceEpoch: 2_000, nanoseconds: 0)),
      statusChangeTime: .known(
        CanonicalFilesystemTime(secondsSinceEpoch: 3_000, nanoseconds: 0)),
      birthTime: .known(CanonicalFilesystemTime(secondsSinceEpoch: 500, nanoseconds: 0))
    ),
    accessPolicy: .known(
      AccessPolicyEvidence(ownerUserID: 501, ownerGroupID: 20, mode: 0o700, flags: 0)
    ),
    coverage: coverage,
    providerBoundary: providerBoundary,
    providerEvidence: .absent(reason: "local object")
  )
}

private func authorityPath(_ components: [String], rootID: String = "root") -> RawPath {
  RawPath(
    rootID: rootID,
    components: components.map { RawPathComponent(Data($0.utf8)) }
  )
}

extension GateResult {
  fileprivate var isRejectedForAuthorityTest: Bool {
    if case .rejected = self { return true }
    return false
  }
}
