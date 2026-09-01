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
  let item = try #require(first.items.first)
  #expect(item.kind == .cache)
  #expect(item.actionID == nil)
  #expect(item.reasons.contains(.aclEvidenceUnavailable))
  #expect(item.reasons.contains(.rootNamespaceSealUnavailable))
  #expect(item.reasons.contains(.nameOnlyTypeHint))
  #expect(item.reasons.contains(.recoverabilityProvenanceUnavailable))
  #expect(first.plan.evidenceSnapshots.count == 1)
  #expect(first.plan.evidenceSnapshots[0].namespaceBinding.trustedNamespace == .unverified)
  #expect(
    item.evaluation.votes.first(where: { $0.dimension == .identityAndAccess })?.result
      .isRejectedForAuthorityTest == true
  )
  #expect(
    item.evaluation.votes.first(where: { $0.dimension == .recoverability })?.result
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

@Test func controllerPublishesFinalReceiptOnlyAfterFinalWriterAcknowledges() throws {
  let result = authorityScanResult()
  let session = seededAuthoritySession(result: result)
  let controller = RuntimeSessionController()
  let writerGate = AuthorityTestGate()
  let writerEntered = AuthorityTestFlag()
  let publicationFinished = AuthorityTestFlag()
  let broker = SerialEventBroker(semanticCapacity: 1) { data in
    if isScanFinalizedBrokerPayload(data) {
      writerEntered.set()
      writerGate.wait()
    }
  }
  let coordinator = ScanCoordinator(
    broker: broker,
    authoritySession: session,
    finalizedReceiptSink: controller.publishFinalizedReceipt
  )
  Thread {
    coordinator.publishFinalizedAuthorityResult(
      result,
      state: .finished,
      reason: "receipt acknowledgement fixture"
    )
    publicationFinished.set()
  }.start()
  defer { writerGate.open() }
  #expect(writerEntered.wait(timeout: 1.0))
  #expect(controller.finalizedReceiptCountForTesting() == 0)

  writerGate.open()
  #expect(publicationFinished.wait(timeout: 1.0))
  #expect(controller.finalizedReceiptCountForTesting() == 1)
  try broker.finish()
}

@Test func controllerNeverPublishesReceiptWhenFinalWriterFails() throws {
  let result = authorityScanResult()
  let session = seededAuthoritySession(result: result)
  let controller = RuntimeSessionController()
  let broker = SerialEventBroker(semanticCapacity: 1) { data in
    if isScanFinalizedBrokerPayload(data) { throw AuthorityTestWriterFailure.failed }
  }
  let coordinator = ScanCoordinator(
    broker: broker,
    authoritySession: session,
    finalizedReceiptSink: controller.publishFinalizedReceipt
  )
  coordinator.publishFinalizedAuthorityResult(
    result,
    state: .finished,
    reason: "receipt writer failure fixture"
  )

  #expect(controller.finalizedReceiptCountForTesting() == 0)
  #expect(throws: EventBrokerError.self) { try broker.finish() }
}

@Test func controllerBuildsExactFinalReceiptAndAppliesEmptySafePreset() throws {
  let result = authorityScanResult()
  let session = seededAuthoritySession(result: result)
  try session.finalize(result)
  let controller = RuntimeSessionController()
  let finalEvidence = Data(repeating: 0x41, count: 32)
  let checkpointID = Data(finalEvidence.map { String(format: "%02x", $0) }.joined().utf8)
  controller.publishFinalizedReceipt(
    RuntimeFinalizedScanReceipt(
      scanSessionID: Data("scan-session".utf8),
      checkpointID: checkpointID,
      finalEvidenceSHA256: finalEvidence,
      checkpointEvidenceSHA256: Data(repeating: 0x42, count: 32),
      isPartial: false,
      authoritySession: session
    ))

  let output = AuthorityTestOutput()
  let broker = SerialEventBroker { output.append($0) }
  let authority = RuntimeBusinessAuthorityState()
  var build = Diskplan_V1_BuildPlanRequest()
  build.requestID = 1
  build.scanSessionID.value = Data("scan-session".utf8)
  build.scanCheckpointID.value = checkpointID
  build.scanEvidenceSha256.value = finalEvidence
  build.agentMode = .off
  #expect(authority.claim(.buildPlan(build))?.code == nil)
  try controller.handle(
    .buildPlan(build),
    responder: RuntimeBusinessResponder(
      broker: broker,
      request: .buildPlan(build),
      runtimeSessionID: Data("runtime-session".utf8),
      authority: authority
    )
  )

  let planEvents = output.runtimeEvents()
  guard case .planProjection(let planProjection)? = planEvents.last?.body else {
    Issue.record("expected terminal plan projection")
    return
  }
  #expect(planProjection.manifest.scanSessionID.value == Data("scan-session".utf8))
  #expect(planProjection.manifest.scanCheckpointID.value == checkpointID)
  #expect(planProjection.manifest.evidenceSha256.value == finalEvidence)
  #expect(planProjection.manifest.actionCount == 0)

  var preset = Diskplan_V1_ApplyBatchSelectionPresetEdit()
  preset.preset = .safeStageableWithoutWaiver
  var edit = Diskplan_V1_DecisionOverlayEdit()
  edit.kind = .applyBatchSelectionPreset
  edit.edit = .applyBatchSelectionPreset(preset)
  var request = Diskplan_V1_DecisionOverlayEditRequest()
  request.requestID = 2
  request.projectionID = planProjection.manifest.projectionID
  request.baseRevision = 0
  request.edits = [edit]
  #expect(authority.claim(.editDecisionOverlay(request))?.code == nil)
  try controller.handle(
    .editDecisionOverlay(request),
    responder: RuntimeBusinessResponder(
      broker: broker,
      request: .editDecisionOverlay(request),
      runtimeSessionID: Data("runtime-session".utf8),
      authority: authority
    )
  )
  try broker.finish()

  guard case .decisionOverlayAcknowledged(let overlay)? = output.runtimeEvents().last?.body
  else {
    Issue.record("expected decision overlay acknowledgement")
    return
  }
  #expect(overlay.revision == 1)
  #expect(overlay.selectedActionIds.isEmpty)
  #expect(overlay.acknowledgedWaivers.isEmpty)
}

@Test func controllerSafePresetKeepsOnlyThePrerequisiteClosedStageableSubset() throws {
  let blocked = try runtimeActionID(0x11)
  let middle = try runtimeActionID(0x22)
  let leaf = try runtimeActionID(0x33)
  let independent = try runtimeActionID(0x44)

  let selected = RuntimeOverlayEditor.prerequisiteClosedSelection(
    stageableActionIDs: [middle, leaf, independent],
    prerequisitesByActionID: [
      middle: [blocked],
      leaf: [middle],
      independent: [],
    ]
  )

  #expect(selected == Set([independent]))
}

@Test func controllerConsentEventIdentifierPreservesOpaqueBytesAndEnforcesTheWireLimit() {
  let nonUTF8 = Data([0xff, 0x00, 0x80])
  let alternate = Data([0xff, 0x00, 0x81])

  let binding = RuntimePlanIdentifiers.consentEventIDBinding(nonUTF8)
  #expect(binding != nil)
  #expect(binding != RuntimePlanIdentifiers.consentEventIDBinding(alternate))
  #expect(RuntimePlanIdentifiers.consentEventIDBinding(Data()) == nil)
  #expect(RuntimePlanIdentifiers.consentEventIDBinding(Data(repeating: 0xaa, count: 256)) != nil)
  #expect(RuntimePlanIdentifiers.consentEventIDBinding(Data(repeating: 0xaa, count: 257)) == nil)
}

@Test func controllerRawRelativePathBindingPreservesComponentBoundaries() {
  let first = RuntimePlanDomainProjector.rawRelativePathBinding([
    Data("a".utf8), Data("bc".utf8),
  ])
  let second = RuntimePlanDomainProjector.rawRelativePathBinding([
    Data("ab".utf8), Data("c".utf8),
  ])

  #expect(first != second)
}

@Test func controllerNamespaceBindingCoversEveryProtectedNamespaceDimension() throws {
  let baseline = try runtimeNamespaceBinding(
    generation: .known(1),
    trustedNamespace: .ownerPrivate,
    providerBoundary: .known(.local),
    accessPolicy: .known("uid=501;mode=0700")
  )
  let changedGeneration = try runtimeNamespaceBinding(
    generation: .known(2),
    trustedNamespace: .ownerPrivate,
    providerBoundary: .known(.local),
    accessPolicy: .known("uid=501;mode=0700")
  )
  let changedProvider = try runtimeNamespaceBinding(
    generation: .known(1),
    trustedNamespace: .ownerPrivate,
    providerBoundary: .known(.fileProviderManaged),
    accessPolicy: .known("uid=501;mode=0700")
  )
  let changedTrust = try runtimeNamespaceBinding(
    generation: .known(1),
    trustedNamespace: .explicitlyTrustedUserNamespace,
    providerBoundary: .known(.local),
    accessPolicy: .known("uid=501;mode=0700")
  )
  let unreadable = try runtimeNamespaceBinding(
    generation: .known(1),
    trustedNamespace: .ownerPrivate,
    providerBoundary: .known(.local),
    accessPolicy: .unreadable(.init(code: "EACCES", collector: "namespace"))
  )
  let failed = try runtimeNamespaceBinding(
    generation: .known(1),
    trustedNamespace: .ownerPrivate,
    providerBoundary: .known(.local),
    accessPolicy: .failed(.init(code: "EACCES", collector: "namespace"))
  )
  let baselineDigest = RuntimePlanDomainProjector.protectedNamespaceBinding(baseline)

  #expect(
    baselineDigest
      != RuntimePlanDomainProjector.protectedNamespaceBinding(changedGeneration))
  #expect(
    baselineDigest != RuntimePlanDomainProjector.protectedNamespaceBinding(changedProvider))
  #expect(baselineDigest != RuntimePlanDomainProjector.protectedNamespaceBinding(changedTrust))
  #expect(
    RuntimePlanDomainProjector.protectedNamespaceBinding(unreadable)
      != RuntimePlanDomainProjector.protectedNamespaceBinding(failed))
}

@Test func controllerDisplayPathIncludesTheRawRootAndEscapesFormatCharacters() {
  #expect(
    RuntimePlanDomainProjector.displayPath(
      root: Data("/Users/example/Library/Caches".utf8),
      components: [Data("diskplan".utf8)]
    ) == "/Users/example/Library/Caches/diskplan"
  )
  let deceptive = RuntimePlanDomainProjector.displayPath(
    root: Data("/Users/example".utf8),
    components: [Data("left\u{202e}right".utf8)]
  )
  #expect(!deceptive.contains("\u{202e}"))
  #expect(deceptive.hasPrefix("\\x2f"))
}

@Test func controllerRejectsDuplicateAndMixedBatchOverlayEditsBeforeMutation() {
  var notes = Diskplan_V1_ReplaceNotesEdit()
  notes.userNotes = ["first"]
  var notesEdit = Diskplan_V1_DecisionOverlayEdit()
  notesEdit.kind = .replaceNotes
  notesEdit.edit = .replaceNotes(notes)
  #expect(throws: RuntimeOverlayEditRejection.self) {
    try RuntimeOverlayEditor.validateEditSet([notesEdit, notesEdit])
  }

  var stage = Diskplan_V1_StageActionEdit()
  stage.actionID.value = Data(repeating: 0x45, count: 32)
  var stageEdit = Diskplan_V1_DecisionOverlayEdit()
  stageEdit.kind = .stageAction
  stageEdit.edit = .stageAction(stage)
  var unstageEdit = Diskplan_V1_DecisionOverlayEdit()
  unstageEdit.kind = .unstageAction
  unstageEdit.edit = .unstageAction(stage)
  #expect(throws: RuntimeOverlayEditRejection.self) {
    try RuntimeOverlayEditor.validateEditSet([stageEdit, unstageEdit])
  }

  var waiver = Diskplan_V1_AllowWaiverEdit()
  waiver.actionID.value = Data(repeating: 0x46, count: 32)
  waiver.waiverID.value = Data("waiver".utf8)
  waiver.reason = "reviewed"
  waiver.consentEventID.value = Data([0xff])
  var waiverEdit = Diskplan_V1_DecisionOverlayEdit()
  waiverEdit.kind = .allowWaiver
  waiverEdit.edit = .allowWaiver(waiver)
  #expect(throws: RuntimeOverlayEditRejection.self) {
    try RuntimeOverlayEditor.validateEditSet([waiverEdit, waiverEdit])
  }

  var preset = Diskplan_V1_ApplyBatchSelectionPresetEdit()
  preset.preset = .safeStageableWithoutWaiver
  var presetEdit = Diskplan_V1_DecisionOverlayEdit()
  presetEdit.kind = .applyBatchSelectionPreset
  presetEdit.edit = .applyBatchSelectionPreset(preset)
  #expect(throws: RuntimeOverlayEditRejection.self) {
    try RuntimeOverlayEditor.validateEditSet([presetEdit, notesEdit])
  }
}

@Test func controllerProjectsExactImmutablePlanLineageAndPrerequisiteActionIDs() throws {
  let facts = try runtimeProjectionGlobalFacts()
  let firstEvidence = try runtimeProjectionEvidence(
    candidateID: "first",
    path: "first",
    object: 101,
    facts: facts
  )
  let secondEvidence = try runtimeProjectionEvidence(
    candidateID: "second",
    path: "second",
    object: 102,
    facts: facts
  )
  let first = try runtimeProjectionAction(evidence: firstEvidence, facts: facts)
  let second = try runtimeProjectionAction(
    evidence: secondEvidence,
    facts: facts,
    prerequisites: [first]
  )
  let plan = try ImmutablePlan(
    policyVersion: "policy-1",
    schemaVersion: "schema-1",
    globalFacts: facts,
    evidenceSnapshots: [firstEvidence, secondEvidence],
    actions: [first, second],
    releaseGraphBundle: nil
  )
  let result = RuntimePolicyAuthorityResult(
    plan: plan,
    items: [],
    rejectedCandidates: [],
    releaseOwnerIndex: RuntimeReleaseOwnerIndex(
      owners: [],
      allocationGroups: [],
      dependencyCompleteByCandidate: [:],
      overlaps: [],
      overlappingCandidateIDs: []
    ),
    releaseGraph: nil,
    releaseGraphFailure: nil
  )
  let projected = try RuntimePlanDomainProjector.project(result).compactMap {
    record -> Diskplan_V1_PlanActionProjection? in
    guard case .action(let action)? = record.body else { return nil }
    return action
  }
  let projectedByID = Dictionary(
    uniqueKeysWithValues: projected.map { ($0.actionID.value, $0) }
  )

  #expect(projectedByID.count == plan.actions.count)
  for action in plan.actions {
    let row = try #require(projectedByID[action.id.digest.bytes])
    #expect(row.actionLineageID.value == action.lineageID.digest.bytes)
    #expect(
      Set(row.prerequisites.map(\.actionID.value))
        == Set(action.prerequisiteActionIDs.map(\.digest.bytes)))
  }
}

@Test func controllerOverlayHandlesDomainValidDuplicateLineagesWithoutTrapping() throws {
  let facts = try runtimeProjectionGlobalFacts()
  let firstEvidence = try runtimeProjectionEvidence(
    candidateID: "lineage-a",
    path: "same-target",
    object: 201,
    facts: facts
  )
  let secondEvidence = try runtimeProjectionEvidence(
    candidateID: "lineage-b",
    path: "same-target",
    object: 201,
    facts: facts
  )
  let first = try runtimeProjectionAction(evidence: firstEvidence, facts: facts)
  let second = try runtimeProjectionAction(evidence: secondEvidence, facts: facts)
  #expect(first.lineageID == second.lineageID)
  #expect(first.id != second.id)
  let plan = try ImmutablePlan(
    policyVersion: "policy-1",
    schemaVersion: "schema-1",
    globalFacts: facts,
    evidenceSnapshots: [firstEvidence, secondEvidence],
    actions: [first, second],
    releaseGraphBundle: nil
  )
  let current = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: [],
    waiverConsents: [],
    userNotes: []
  )
  _ = try DecisionOverlayValidator.validate(current, against: plan)

  var notes = Diskplan_V1_ReplaceNotesEdit()
  notes.userNotes = ["retained"]
  var notesEdit = Diskplan_V1_DecisionOverlayEdit()
  notesEdit.kind = .replaceNotes
  notesEdit.edit = .replaceNotes(notes)
  let edited = try RuntimeOverlayEditor.apply([notesEdit], to: current, plan: plan)
  #expect(edited.selectedActionIDs.isEmpty)
  #expect(edited.userNotes == ["retained"])

  var preset = Diskplan_V1_ApplyBatchSelectionPresetEdit()
  preset.preset = .safeStageableWithoutWaiver
  var presetEdit = Diskplan_V1_DecisionOverlayEdit()
  presetEdit.kind = .applyBatchSelectionPreset
  presetEdit.edit = .applyBatchSelectionPreset(preset)
  let safe = try RuntimeOverlayEditor.apply([presetEdit], to: current, plan: plan)
  #expect(safe.selectedActionIDs.isEmpty)
}

@Test func controllerRejectsPartialReceiptWithoutExplicitAllowance() throws {
  let result = authorityScanResult(state: .partial)
  let session = seededAuthoritySession(result: result)
  try session.finalize(result)
  let controller = RuntimeSessionController()
  let finalEvidence = Data(repeating: 0x51, count: 32)
  let checkpointID = Data(finalEvidence.map { String(format: "%02x", $0) }.joined().utf8)
  controller.publishFinalizedReceipt(
    RuntimeFinalizedScanReceipt(
      scanSessionID: Data("partial-session".utf8),
      checkpointID: checkpointID,
      finalEvidenceSHA256: finalEvidence,
      checkpointEvidenceSHA256: Data(repeating: 0x52, count: 32),
      isPartial: true,
      authoritySession: session
    ))
  let output = AuthorityTestOutput()
  let broker = SerialEventBroker { output.append($0) }
  let authority = RuntimeBusinessAuthorityState()
  var build = Diskplan_V1_BuildPlanRequest()
  build.requestID = 1
  build.scanSessionID.value = Data("partial-session".utf8)
  build.scanCheckpointID.value = checkpointID
  build.scanEvidenceSha256.value = finalEvidence
  build.agentMode = .off
  #expect(authority.claim(.buildPlan(build))?.code == nil)
  try controller.handle(
    .buildPlan(build),
    responder: RuntimeBusinessResponder(
      broker: broker,
      request: .buildPlan(build),
      runtimeSessionID: Data("runtime-session".utf8),
      authority: authority
    )
  )
  try broker.finish()

  guard case .runtimeRejected(let rejection)? = output.runtimeEvents().last?.body else {
    Issue.record("expected typed partial-evidence rejection")
    return
  }
  #expect(rejection.code == .invalidState)
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

private func runtimeActionID(_ byte: UInt8) throws -> ActionID {
  ActionID(digest: try PolicyDigest(bytes: Data(repeating: byte, count: 32)))
}

private func runtimeNamespaceBinding(
  generation: DiskplanPolicy.Observation<UInt64>,
  trustedNamespace: TrustedNamespace,
  providerBoundary: DiskplanPolicy.Observation<ProviderState>,
  accessPolicy: DiskplanPolicy.Observation<String>
) throws -> ProtectedNamespaceBinding {
  let rootIdentity = ObjectIdentity(
    device: 1,
    object: 2,
    generation: generation,
    type: .directory
  )
  let targetIdentity = ObjectIdentity(
    device: 1,
    object: 3,
    generation: .known(1),
    type: .directory
  )
  let rootSeal = NamespaceSealEvidence(
    trustedNamespace: trustedNamespace,
    accessPolicy: accessPolicy,
    aclDigest: .absent,
    providerBoundary: providerBoundary,
    mountIdentity: .known("mount-1")
  )
  return try ProtectedNamespaceBinding(
    rawRoot: RawRootPath(absoluteBytes: Data("/Users/example/Library/Caches".utf8)),
    rootIdentity: rootIdentity,
    rootSeal: rootSeal,
    targetPath: RawTargetPath(components: [Data("diskplan".utf8)]),
    targetIdentity: targetIdentity,
    parentChain: []
  )
}

private func runtimeProjectionGlobalFacts() throws -> FrozenGlobalFacts {
  FrozenGlobalFacts(
    captureID: runtimePolicyDigest(0x90),
    profile: "standard",
    configuration: Data("runtime-projection-test".utf8),
    coverage: [
      GlobalCoverageFact(
        rawRoot: try RawRootPath(absoluteBytes: Data("/fixture/root".utf8)),
        coverage: .complete,
        reasons: ["complete"]
      )
    ],
    semanticReferenceTimeSeconds: 100,
    policyVersion: "policy-1",
    schemaVersion: "schema-1"
  )
}

private func runtimeProjectionEvidence(
  candidateID: String,
  path: String,
  object: UInt64,
  facts: FrozenGlobalFacts
) throws -> FrozenEvidenceSnapshot {
  let targetPath = try RawTargetPath(components: [Data(path.utf8)])
  let targetIdentity = ObjectIdentity(
    device: 1,
    object: object,
    generation: .known(1),
    type: .directory
  )
  let seal = NamespaceSealEvidence(
    trustedNamespace: .ownerPrivate,
    accessPolicy: .known("uid=501;mode=0700"),
    aclDigest: .known(runtimePolicyDigest(0x91)),
    providerBoundary: .known(.local),
    mountIdentity: .known("mount-1")
  )
  let namespace = try ProtectedNamespaceBinding(
    rawRoot: RawRootPath(absoluteBytes: Data("/fixture/root".utf8)),
    rootIdentity: ObjectIdentity(
      device: 1,
      object: 900,
      generation: .known(1),
      type: .directory
    ),
    rootSeal: seal,
    targetPath: targetPath,
    targetIdentity: targetIdentity,
    parentChain: []
  )
  let claims = ClassificationFacet.allCases.map { facet in
    ClassificationClaim(
      facet: facet,
      value: "known-\(facet.rawValue)",
      source: .genericFallback,
      evidenceKey: "runtime-projection-\(facet.rawValue)"
    )
  }
  return try FrozenEvidenceSnapshot(
    captureID: facts.captureID,
    globalFactsHash: facts.globalFactsHash,
    candidateID: candidateID,
    namespaceBinding: namespace,
    identity: .known(targetIdentity),
    coverage: .complete,
    collectorStatus: .known(.complete),
    activity: .known(.inactive),
    explicitProtection: .known(.notProtected),
    providerState: .known(.local),
    recoverability: .known(.recoverable),
    recoverabilityReviewFacts: [],
    dependencyState: .known(.complete),
    semanticReviewFacts: [],
    accessPolicy: .known("uid=501;mode=0700"),
    contentProtection: .known(.requiredDigest(runtimePolicyDigest(0x92))),
    aclDigest: .known(runtimePolicyDigest(0x93)),
    targetMountIdentity: .known("mount-1"),
    removalForceRequirement: .known(.notRequired),
    quarantineCapability: .known(true),
    gitWorktree: nil,
    adapterScope: .genericRemove,
    additionalAdapterScopes: [],
    classificationClaims: claims,
    semanticReferenceTimeSeconds: facts.semanticReferenceTimeSeconds,
    policyVersion: facts.policyVersion,
    schemaVersion: facts.schemaVersion
  )
}

private func runtimeProjectionAction(
  evidence: FrozenEvidenceSnapshot,
  facts: FrozenGlobalFacts,
  prerequisites: [ActionDefinition] = []
) throws -> ActionDefinition {
  var canonicalRawPath = Data()
  for (index, component) in evidence.namespaceBinding.targetPath.components.enumerated() {
    if index > 0 { canonicalRawPath.append(47) }
    canonicalRawPath.append(component)
  }
  let evaluation = try OneVotePolicy.evaluate(
    OneVotePolicyInputs.build(evidence: evidence, globalFacts: facts)
  )
  return try ActionDefinition.build(
    prototype: ActionPrototype.build(request: .genericRemove, evidence: evidence),
    evidence: evidence,
    globalFacts: facts,
    prerequisites: prerequisites,
    evaluation: evaluation,
    displayMetrics: ActionDisplayMetrics(
      immediateReclaimBytes: .known(1),
      inactiveDurationSeconds: .known(10),
      rebuildCost: .known(1),
      cleanupCost: .known(1),
      canonicalRawPath: canonicalRawPath
    )
  )
}

private func runtimePolicyDigest(_ byte: UInt8) -> PolicyDigest {
  try! PolicyDigest(bytes: Data(repeating: byte, count: 32))
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

private final class AuthorityTestOutput: @unchecked Sendable {
  private let lock = NSLock()
  private var payloads: [Data] = []

  func append(_ payload: Data) {
    lock.lock()
    payloads.append(payload)
    lock.unlock()
  }

  func runtimeEvents() -> [Diskplan_V1_RuntimeEvent] {
    lock.lock()
    let snapshot = payloads
    lock.unlock()
    return snapshot.compactMap { payload in
      guard let envelope = try? Diskplan_V1_Envelope(serializedBytes: payload),
        case .runtimeEvent(let event) = envelope.body
      else { return nil }
      return event
    }
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
