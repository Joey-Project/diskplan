import DiskplanCore
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

@Test func controllerExecutionBackendIsAbsentFailClosed() throws {
  let controller = RuntimeSessionController()
  #expect(!controller.supportedCapabilities.contains("dry-run-projection-v1"))
  #expect(!controller.supportedCapabilities.contains("execution-stream-v1"))
  let output = AuthorityTestOutput()
  let broker = SerialEventBroker { output.append($0) }
  let authority = RuntimeBusinessAuthorityState()
  var request = Diskplan_V1_PrepareDryRunRequest()
  request.requestID = 1
  #expect(authority.claim(.prepareDryRun(request))?.code == nil)
  try controller.handle(
    .prepareDryRun(request),
    responder: RuntimeBusinessResponder(
      broker: broker,
      request: .prepareDryRun(request),
      runtimeSessionID: Data("runtime-session".utf8),
      authority: authority
    )
  )
  try broker.finish()
  guard case .runtimeRejected(let rejection)? = output.runtimeEvents().last?.body else {
    Issue.record("expected typed unavailable rejection")
    return
  }
  #expect(rejection.code == .businessUnsupported)
}

@Test func controllerDryRunRequiresTheExactLiveOverlayBinding() async throws {
  let backend = RuntimePositiveBackend(waitForCancellation: false)
  let fixture = try runtimePositiveFixture(backend: backend)
  defer {
    fixture.controller.stopAndWait()
    try? fixture.broker.finish()
  }
  var stale = Diskplan_V1_PrepareDryRunRequest()
  stale.requestID = 3
  stale.projectionID = fixture.plan.projectionID
  stale.overlayID = fixture.overlay.overlayID
  stale.overlayRevision = fixture.overlay.revision + 1
  stale.overlaySha256 = fixture.overlay.overlaySha256
  #expect(fixture.authority.claim(.prepareDryRun(stale))?.code == nil)
  try fixture.controller.handle(
    .prepareDryRun(stale),
    responder: fixture.responder(.prepareDryRun(stale))
  )
  #expect(backend.dryRunCount == 0)

  var current = stale
  current.requestID = 4
  current.overlayRevision = fixture.overlay.revision
  #expect(fixture.authority.claim(.prepareDryRun(current))?.code == nil)
  try fixture.controller.handle(
    .prepareDryRun(current),
    responder: fixture.responder(.prepareDryRun(current))
  )
  #expect(
    await runtimeEventually {
      fixture.output.runtimeEvents().contains { event in
        guard case .dryRunProjection(let projection)? = event.body else { return false }
        return projection.manifest.projectionID == fixture.plan.projectionID
          && projection.manifest.overlayID == fixture.overlay.overlayID
          && projection.manifest.overlayRevision == fixture.overlay.revision
      }
    })
  #expect(backend.dryRunCount == 1)
}

@Test func controllerConfirmCancelAndReplayShareOneSealedExecution() async throws {
  let backend = RuntimePositiveBackend(waitForCancellation: true)
  let fixture = try runtimePositiveFixture(backend: backend)
  defer { try? fixture.broker.finish() }
  let review = try await prepareRuntimePositiveReview(fixture)

  var confirmation = Diskplan_V1_ConfirmApplyRequest()
  confirmation.requestID = 4
  confirmation.applyReviewID = review.applyReviewID
  confirmation.reviewBindingSha256 = review.reviewBindingSha256
  confirmation.confirmedForceActionIds = review.forceWarningActionIds
  #expect(fixture.authority.claim(.confirmApply(confirmation))?.code == nil)
  try fixture.controller.handle(
    .confirmApply(confirmation),
    responder: fixture.responder(.confirmApply(confirmation))
  )
  #expect(
    await runtimeEventually {
      fixture.controller.activeExecutionIDForTesting() == backend.executionID
    })

  var wrongCancellation = Diskplan_V1_CancelExecutionRequest()
  wrongCancellation.requestID = 5
  wrongCancellation.executionID.value = Data("wrong-execution".utf8)
  #expect(fixture.authority.claim(.cancelExecution(wrongCancellation))?.code == .staleBinding)
  #expect(backend.cancelCount == 0)

  var cancellation = Diskplan_V1_CancelExecutionRequest()
  cancellation.requestID = 6
  cancellation.executionID.value = backend.executionID
  #expect(fixture.authority.claim(.cancelExecution(cancellation))?.code == nil)
  try fixture.controller.handle(
    .cancelExecution(cancellation),
    responder: fixture.responder(.cancelExecution(cancellation))
  )
  #expect(
    await runtimeEventually {
      fixture.controller.activeExecutionIDForTesting() == nil
        && backend.cancelCount == 1
    })
  let confirmationRequestID = confirmation.requestID
  let cancellationRequestID = cancellation.requestID
  #expect(
    await runtimeEventually {
      fixture.output.runtimeEvents().contains { event in
        guard event.requestID == confirmationRequestID,
          case .executionStreamEvent(let streamEvent)? = event.body
        else { return false }
        if case .applyFinished? = streamEvent.body { return true }
        return false
      }
        && fixture.output.runtimeEvents().contains { event in
          guard event.requestID == cancellationRequestID,
            case .executionStreamEvent(let streamEvent)? = event.body
          else { return false }
          if case .applyFinished? = streamEvent.body { return true }
          return false
        }
    })

  var replay = confirmation
  replay.requestID = 7
  #expect(fixture.authority.claim(.confirmApply(replay))?.code == .staleBinding)
  #expect(backend.startCount == 1)

  let events = fixture.output.runtimeEvents()
  let confirmStream: [Diskplan_V1_ExecutionStreamEvent] =
    events
    .filter { $0.requestID == confirmation.requestID }
    .compactMap { runtimeEvent -> Diskplan_V1_ExecutionStreamEvent? in
      guard case .executionStreamEvent(let event)? = runtimeEvent.body else { return nil }
      return event
    }
  let cancelStream: [Diskplan_V1_ExecutionStreamEvent] =
    events
    .filter { $0.requestID == cancellation.requestID }
    .compactMap { runtimeEvent -> Diskplan_V1_ExecutionStreamEvent? in
      guard case .executionStreamEvent(let event)? = runtimeEvent.body else { return nil }
      return event
    }
  #expect(!confirmStream.isEmpty)
  #expect(confirmStream == cancelStream)
  #expect(confirmStream.last?.applyFinished != nil)
  let cancellationAcknowledgementCount = confirmStream.filter { event in
    if case .cancellationAcknowledged? = event.body { return true }
    return false
  }.count
  #expect(cancellationAcknowledgementCount == 1)
  _ = try SealedRuntimeWire.sealExecutionStream(
    confirmStream,
    requiredForceWarningActionIDs: review.forceWarningActionIds
  )
}

@Test func controllerTeardownCancelsAndWaitsForRetainedExecution() async throws {
  let backend = RuntimePositiveBackend(waitForCancellation: true)
  let fixture = try runtimePositiveFixture(backend: backend)
  let review = try await prepareRuntimePositiveReview(fixture)
  var confirmation = Diskplan_V1_ConfirmApplyRequest()
  confirmation.requestID = 4
  confirmation.applyReviewID = review.applyReviewID
  confirmation.reviewBindingSha256 = review.reviewBindingSha256
  #expect(fixture.authority.claim(.confirmApply(confirmation))?.code == nil)
  try fixture.controller.handle(
    .confirmApply(confirmation),
    responder: fixture.responder(.confirmApply(confirmation))
  )
  #expect(
    await runtimeEventually {
      fixture.controller.activeExecutionIDForTesting() == backend.executionID
    })

  fixture.controller.stopAndWait()
  #expect(backend.cancelCount == 1)
  #expect(fixture.controller.activeExecutionIDForTesting() == nil)
  try fixture.broker.finish()
}

@Test func controllerTeardownWaitsForRunReturnedAfterStopping() async throws {
  let startGate = RuntimePositiveGate()
  let backend = RuntimePositiveBackend(
    waitForCancellation: true,
    startGate: startGate
  )
  let fixture = try runtimePositiveFixture(backend: backend)
  defer {
    startGate.open()
    fixture.controller.stopAndWait()
    try? fixture.broker.finish()
  }
  let review = try await prepareRuntimePositiveReview(fixture)
  let confirmation = runtimePositiveConfirmation(review, requestID: 4)
  try #require(fixture.authority.claim(.confirmApply(confirmation)) == nil)
  try fixture.controller.handle(
    .confirmApply(confirmation),
    responder: fixture.responder(.confirmApply(confirmation))
  )
  try #require(startGate.waitUntilEntered())

  let teardown = Task.detached { fixture.controller.stopAndWait() }
  try #require(
    await runtimeEventually {
      fixture.controller.isStoppingForTesting()
    })
  startGate.open()
  await teardown.value

  #expect(backend.startCount == 1)
  #expect(backend.cancelCount == 1)
  #expect(backend.tailAwaitCount == 1)
  #expect(fixture.controller.activeExecutionIDForTesting() == nil)
}

@Test func confirmWaitsForVisibleReviewPublicationCommit() async throws {
  let commitGate = RuntimePositiveGate()
  let backend = RuntimePositiveBackend(waitForCancellation: false)
  let fixture = try runtimePositiveFixture(
    backend: backend,
    reviewCommitGate: commitGate
  )
  defer {
    commitGate.open()
    fixture.controller.stopAndWait()
    try? fixture.broker.finish()
  }

  var request = Diskplan_V1_PrepareApplyReviewRequest()
  request.requestID = 3
  request.projectionID = fixture.plan.projectionID
  request.overlayID = fixture.overlay.overlayID
  request.overlayRevision = fixture.overlay.revision
  request.overlaySha256 = fixture.overlay.overlaySha256
  try #require(fixture.authority.claim(.prepareApplyReview(request)) == nil)
  try fixture.controller.handle(
    .prepareApplyReview(request),
    responder: fixture.responder(.prepareApplyReview(request))
  )
  try #require(commitGate.waitUntilEntered())
  let reviews: [Diskplan_V1_ApplyReviewProjection] =
    fixture.output.runtimeEvents().compactMap { event in
      guard case .applyReviewProjection(let projection)? = event.body else { return nil }
      return projection
    }
  let review = try #require(reviews.last)

  let confirmation = runtimePositiveConfirmation(review, requestID: 4)
  let claimStarted = AuthorityTestFlag()
  let claimFinished = AuthorityTestFlag()
  let claim = Task.detached {
    claimStarted.set()
    let rejection = fixture.authority.claim(.confirmApply(confirmation))
    claimFinished.set()
    return rejection
  }
  try #require(claimStarted.wait(timeout: 2))
  #expect(!claimFinished.wait(timeout: 0.05))

  commitGate.open()
  let rejection = await claim.value
  #expect(rejection?.code == nil)
  try fixture.controller.handle(
    .confirmApply(confirmation),
    responder: fixture.responder(.confirmApply(confirmation))
  )
  #expect(
    await runtimeEventually {
      backend.startCount == 1
        && fixture.controller.activeExecutionIDForTesting() == nil
    })
}

@Test func failedReplacementReviewRestoresPreviousAuthorityBeforeConfirmWakes() async throws {
  let reviewAID = Data("positive-review-a".utf8)
  let reviewBID = Data("positive-review-b".utf8)
  let commitHook = RuntimePositiveFailingCommitHook(failingInvocation: 2)
  let backend = RuntimePositiveBackend(
    waitForCancellation: false,
    reviewIDs: [reviewAID, reviewBID]
  )
  let fixture = try runtimePositiveFixture(
    backend: backend,
    reviewCommitHook: { try commitHook.call() }
  )
  defer {
    commitHook.open()
    fixture.controller.stopAndWait()
    try? fixture.broker.finish()
  }
  let reviewA = try await prepareRuntimePositiveReview(fixture)
  #expect(reviewA.applyReviewID.value == reviewAID)

  var requestB = Diskplan_V1_PrepareApplyReviewRequest()
  requestB.requestID = 4
  requestB.projectionID = fixture.plan.projectionID
  requestB.overlayID = fixture.overlay.overlayID
  requestB.overlayRevision = fixture.overlay.revision
  requestB.overlaySha256 = fixture.overlay.overlaySha256
  try #require(fixture.authority.claim(.prepareApplyReview(requestB)) == nil)
  try fixture.controller.handle(
    .prepareApplyReview(requestB),
    responder: fixture.responder(.prepareApplyReview(requestB))
  )
  try #require(commitHook.waitUntilEntered())
  #expect(fixture.controller.preparedApplyReviewIDForTesting() == reviewBID)

  let confirmation = runtimePositiveConfirmation(reviewA, requestID: 5)
  let claimStarted = AuthorityTestFlag()
  let claimFinished = AuthorityTestFlag()
  let claim = Task.detached {
    claimStarted.set()
    let rejection = fixture.authority.claim(.confirmApply(confirmation))
    claimFinished.set()
    return rejection
  }
  try #require(claimStarted.wait(timeout: 2))
  #expect(!claimFinished.wait(timeout: 0.05))

  commitHook.open()
  #expect((await claim.value)?.code == nil)
  #expect(fixture.controller.preparedApplyReviewIDForTesting() == reviewAID)
  try fixture.controller.handle(
    .confirmApply(confirmation),
    responder: fixture.responder(.confirmApply(confirmation))
  )
  #expect(
    await runtimeEventually {
      backend.startCount == 1
        && fixture.controller.activeExecutionIDForTesting() == nil
    })

  var replay = confirmation
  replay.requestID = 6
  #expect(fixture.authority.claim(.confirmApply(replay))?.code == .staleBinding)
  #expect(backend.startCount == 1)
}

@Test func controllerInstallsReviewBeforePublicationAndRollsBackOnWriterFailure() async throws {
  let backend = RuntimePositiveBackend(waitForCancellation: false)
  let writer = RuntimePositiveWriter()
  let fixture = try runtimePositiveFixture(backend: backend, writer: writer)
  writer.observeInstalledReview()
  writer.block(at: .applyReview)
  writer.fail(at: .applyReview)

  var request = Diskplan_V1_PrepareApplyReviewRequest()
  request.requestID = 3
  request.projectionID = fixture.plan.projectionID
  request.overlayID = fixture.overlay.overlayID
  request.overlayRevision = fixture.overlay.revision
  request.overlaySha256 = fixture.overlay.overlaySha256
  try #require(fixture.authority.claim(.prepareApplyReview(request)) == nil)
  try fixture.controller.handle(
    .prepareApplyReview(request),
    responder: fixture.responder(.prepareApplyReview(request))
  )
  try #require(writer.waitUntilBlocked())
  #expect(writer.sawInstalledReview)
  #expect(fixture.controller.preparedApplyReviewIDForTesting() != nil)

  var confirmation = Diskplan_V1_ConfirmApplyRequest()
  confirmation.requestID = 4
  confirmation.applyReviewID.value = Data("positive-review".utf8)
  confirmation.reviewBindingSha256.value = Data(repeating: 0x83, count: 32)
  let claimStarted = AuthorityTestFlag()
  let claimFinished = AuthorityTestFlag()
  let claim = Task.detached {
    claimStarted.set()
    let rejection = fixture.authority.claim(.confirmApply(confirmation))
    claimFinished.set()
    return rejection
  }
  try #require(claimStarted.wait(timeout: 2))
  #expect(!claimFinished.wait(timeout: 0.05))

  writer.release()
  #expect((await claim.value)?.code == .staleBinding)
  #expect(
    await runtimeEventually {
      fixture.controller.preparedApplyReviewIDForTesting() == nil
    })
  fixture.controller.stopAndWait()
  #expect(backend.startCount == 0)
  #expect(throws: (any Error).self) { try fixture.broker.finish() }
}

@Test func controllerCancelsAndAwaitsInvalidStartedRun() async throws {
  let backend = RuntimePositiveBackend(waitForCancellation: true, executionID: Data())
  let fixture = try runtimePositiveFixture(backend: backend)
  defer {
    fixture.controller.stopAndWait()
    try? fixture.broker.finish()
  }
  let review = try await prepareRuntimePositiveReview(fixture)
  let confirmation = runtimePositiveConfirmation(review, requestID: 4)
  try #require(fixture.authority.claim(.confirmApply(confirmation)) == nil)
  try fixture.controller.handle(
    .confirmApply(confirmation),
    responder: fixture.responder(.confirmApply(confirmation))
  )
  #expect(
    await runtimeEventually {
      backend.startCount == 1 && backend.cancelCount == 1 && backend.tailAwaitCount == 1
        && fixture.controller.activeExecutionIDForTesting() == nil
    })
  let replay = runtimePositiveConfirmation(review, requestID: 5)
  #expect(
    await runtimeEventually {
      fixture.authority.claim(.confirmApply(replay))?.code == .staleBinding
    })
}

@Test func controllerCancelsAndAwaitsWhenExecutionRegistrationFails() async throws {
  let backend = RuntimePositiveBackend(waitForCancellation: true)
  let fixture = try runtimePositiveFixture(backend: backend)
  defer {
    fixture.controller.stopAndWait()
    try? fixture.broker.finish()
  }
  let review = try await prepareRuntimePositiveReview(fixture)
  let confirmation = runtimePositiveConfirmation(review, requestID: 4)

  // Deliberately bypass the server's authority claim to exercise the
  // post-start registration failure path without adding a production seam.
  try fixture.controller.handle(
    .confirmApply(confirmation),
    responder: fixture.responder(.confirmApply(confirmation))
  )
  #expect(
    await runtimeEventually {
      backend.startCount == 1 && backend.cancelCount == 1 && backend.tailAwaitCount == 1
        && fixture.controller.activeExecutionIDForTesting() == nil
    })
}

@Test func controllerCancelsAndAwaitsOnPrefixWriterFailure() async throws {
  let backend = RuntimePositiveBackend(waitForCancellation: true)
  let writer = RuntimePositiveWriter()
  let fixture = try runtimePositiveFixture(backend: backend, writer: writer)
  let review = try await prepareRuntimePositiveReview(fixture)
  writer.fail(at: .applyStarted)
  let confirmation = runtimePositiveConfirmation(review, requestID: 4)
  try #require(fixture.authority.claim(.confirmApply(confirmation)) == nil)
  try fixture.controller.handle(
    .confirmApply(confirmation),
    responder: fixture.responder(.confirmApply(confirmation))
  )
  #expect(
    await runtimeEventually {
      backend.cancelCount == 1 && backend.tailAwaitCount == 1
        && fixture.controller.activeExecutionIDForTesting() == nil
    })
  fixture.controller.stopAndWait()
  #expect(throws: (any Error).self) { try fixture.broker.finish() }
}

@Test func controllerRetainsRunAndAwaitsOnTerminalWriterFailure() async throws {
  let backend = RuntimePositiveBackend(waitForCancellation: false)
  let writer = RuntimePositiveWriter()
  let fixture = try runtimePositiveFixture(backend: backend, writer: writer)
  let review = try await prepareRuntimePositiveReview(fixture)
  writer.fail(at: .applyFinished)
  let confirmation = runtimePositiveConfirmation(review, requestID: 4)
  try #require(fixture.authority.claim(.confirmApply(confirmation)) == nil)
  try fixture.controller.handle(
    .confirmApply(confirmation),
    responder: fixture.responder(.confirmApply(confirmation))
  )
  #expect(
    await runtimeEventually {
      backend.cancelCount == 1 && backend.tailAwaitCount == 1
        && fixture.controller.activeExecutionIDForTesting() == backend.executionID
    })
  fixture.controller.stopAndWait()
  #expect(fixture.controller.activeExecutionIDForTesting() == nil)
  #expect(throws: (any Error).self) { try fixture.broker.finish() }
}

@Test func lateCancellationCannotRaceFinishingTerminal() async throws {
  let backend = RuntimePositiveBackend(waitForCancellation: false)
  let writer = RuntimePositiveWriter()
  let fixture = try runtimePositiveFixture(backend: backend, writer: writer)
  defer {
    writer.release()
    fixture.controller.stopAndWait()
    try? fixture.broker.finish()
  }
  let review = try await prepareRuntimePositiveReview(fixture)
  writer.block(at: .applyFinished)
  let confirmation = runtimePositiveConfirmation(review, requestID: 4)
  try #require(fixture.authority.claim(.confirmApply(confirmation)) == nil)
  try fixture.controller.handle(
    .confirmApply(confirmation),
    responder: fixture.responder(.confirmApply(confirmation))
  )
  try #require(writer.waitUntilBlocked())

  var cancellation = Diskplan_V1_CancelExecutionRequest()
  cancellation.requestID = 5
  cancellation.executionID.value = backend.executionID
  #expect(fixture.authority.claim(.cancelExecution(cancellation))?.code == .staleBinding)
  #expect(backend.cancelCount == 0)

  writer.release()
  #expect(
    await runtimeEventually {
      fixture.controller.activeExecutionIDForTesting() == nil
    })
}

@Test func runtimeExecutionTailRejectsMissingTerminal() {
  var started = Diskplan_V1_ExecutionStreamEvent()
  started.executionID.value = Data("sealed-tail".utf8)
  started.body = .applyStarted(Diskplan_V1_ApplyStartedProjection())
  #expect(throws: SealedRuntimeWireError.self) {
    try RuntimeExecutionTail(
      applyStarted: started,
      remainingEvents: [],
      requiredForceWarningActionIDs: [],
      negotiatedProtocolMinor: protocolMinor
    )
  }
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

private final class RuntimePositiveGate: @unchecked Sendable {
  private let condition = NSCondition()
  private var entered = false
  private var isOpen = false

  func wait() {
    condition.lock()
    entered = true
    condition.broadcast()
    while !isOpen { condition.wait() }
    condition.unlock()
  }

  func waitUntilEntered(timeout: TimeInterval = 2) -> Bool {
    condition.lock()
    defer { condition.unlock() }
    let deadline = Date(timeIntervalSinceNow: timeout)
    while !entered {
      guard condition.wait(until: deadline) else { return entered }
    }
    return true
  }

  func open() {
    condition.lock()
    isOpen = true
    condition.broadcast()
    condition.unlock()
  }
}

private enum RuntimePositiveCommitHookError: Error {
  case injected
}

private final class RuntimePositiveFailingCommitHook: @unchecked Sendable {
  private let condition = NSCondition()
  private let failingInvocation: Int
  private var invocationCount = 0
  private var entered = false
  private var isOpen = false

  init(failingInvocation: Int) {
    self.failingInvocation = failingInvocation
  }

  func call() throws {
    condition.lock()
    invocationCount += 1
    guard invocationCount == failingInvocation else {
      condition.unlock()
      return
    }
    entered = true
    condition.broadcast()
    while !isOpen { condition.wait() }
    condition.unlock()
    throw RuntimePositiveCommitHookError.injected
  }

  func waitUntilEntered(timeout: TimeInterval = 2) -> Bool {
    condition.lock()
    defer { condition.unlock() }
    let deadline = Date(timeIntervalSinceNow: timeout)
    while !entered {
      guard condition.wait(until: deadline) else { return entered }
    }
    return true
  }

  func open() {
    condition.lock()
    isOpen = true
    condition.broadcast()
    condition.unlock()
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

private final class RuntimePositiveFixture: @unchecked Sendable {
  let controller: RuntimeSessionController
  let authority: RuntimeBusinessAuthorityState
  let broker: SerialEventBroker
  let output: AuthorityTestOutput
  let plan: Diskplan_V1_PlanProjectionManifest
  let overlay: Diskplan_V1_DecisionOverlayAcknowledged

  init(
    controller: RuntimeSessionController,
    authority: RuntimeBusinessAuthorityState,
    broker: SerialEventBroker,
    output: AuthorityTestOutput,
    plan: Diskplan_V1_PlanProjectionManifest,
    overlay: Diskplan_V1_DecisionOverlayAcknowledged
  ) {
    self.controller = controller
    self.authority = authority
    self.broker = broker
    self.output = output
    self.plan = plan
    self.overlay = overlay
  }

  func responder(_ request: RuntimeBusinessRequest) -> RuntimeBusinessResponder {
    RuntimeBusinessResponder(
      broker: broker,
      request: request,
      runtimeSessionID: Data("runtime-session".utf8),
      authority: authority
    )
  }
}

private enum RuntimePositiveWritePoint: Equatable {
  case applyReview
  case applyStarted
  case applyFinished
}

private enum RuntimePositiveWriterError: Error {
  case injected
}

private final class RuntimePositiveWriter: @unchecked Sendable {
  let output = AuthorityTestOutput()
  weak var controller: RuntimeSessionController?

  private let condition = NSCondition()
  private var failurePoint: RuntimePositiveWritePoint?
  private var blockingPoint: RuntimePositiveWritePoint?
  private var blocked = false
  private var released = false
  private var observeReviewInstallation = false
  private var observedInstalledReview = false

  func observeInstalledReview() {
    condition.lock()
    observeReviewInstallation = true
    condition.unlock()
  }

  func fail(at point: RuntimePositiveWritePoint) {
    condition.lock()
    failurePoint = point
    condition.unlock()
  }

  func block(at point: RuntimePositiveWritePoint) {
    condition.lock()
    blockingPoint = point
    condition.unlock()
  }

  func waitUntilBlocked(timeout: TimeInterval = 2) -> Bool {
    condition.lock()
    defer { condition.unlock() }
    let deadline = Date(timeIntervalSinceNow: timeout)
    while !blocked {
      guard condition.wait(until: deadline) else { return blocked }
    }
    return true
  }

  func release() {
    condition.lock()
    released = true
    condition.broadcast()
    condition.unlock()
  }

  var sawInstalledReview: Bool {
    condition.lock()
    defer { condition.unlock() }
    return observedInstalledReview
  }

  func write(_ data: Data) throws {
    let point = Self.writePoint(data)
    condition.lock()
    if point == .applyReview, observeReviewInstallation {
      observedInstalledReview = controller?.preparedApplyReviewIDForTesting() != nil
    }
    if let blockingPoint, point == blockingPoint {
      blocked = true
      condition.broadcast()
      while !released { condition.wait() }
    }
    let shouldFail = failurePoint.map { point == $0 } ?? false
    condition.unlock()
    if shouldFail { throw RuntimePositiveWriterError.injected }
    output.append(data)
  }

  private static func writePoint(_ data: Data) -> RuntimePositiveWritePoint? {
    guard let envelope = try? Diskplan_V1_Envelope(serializedBytes: data),
      case .runtimeEvent(let runtimeEvent) = envelope.body
    else { return nil }
    if case .applyReviewProjection? = runtimeEvent.body { return .applyReview }
    guard case .executionStreamEvent(let event)? = runtimeEvent.body else { return nil }
    if case .applyStarted? = event.body { return .applyStarted }
    if case .applyFinished? = event.body { return .applyFinished }
    return nil
  }
}

private func runtimePositiveFixture(
  backend: RuntimePositiveBackend,
  writer: RuntimePositiveWriter? = nil,
  reviewCommitGate: RuntimePositiveGate? = nil,
  reviewCommitHook: (@Sendable () throws -> Void)? = nil
) throws -> RuntimePositiveFixture {
  let result = authorityScanResult()
  let session = seededAuthoritySession(result: result)
  try session.finalize(result)
  let controller = RuntimeSessionController(executionBackend: backend)
  let finalEvidence = Data(repeating: 0x71, count: 32)
  let checkpointID = Data(finalEvidence.map { String(format: "%02x", $0) }.joined().utf8)
  controller.publishFinalizedReceipt(
    RuntimeFinalizedScanReceipt(
      scanSessionID: Data("positive-scan".utf8),
      checkpointID: checkpointID,
      finalEvidenceSHA256: finalEvidence,
      checkpointEvidenceSHA256: Data(repeating: 0x72, count: 32),
      isPartial: false,
      authoritySession: session
    ))
  let output = writer?.output ?? AuthorityTestOutput()
  writer?.controller = controller
  let broker = SerialEventBroker { data in
    if let writer {
      try writer.write(data)
    } else {
      output.append(data)
    }
  }
  let gateHook: (@Sendable () throws -> Void)? = reviewCommitGate.map { gate in
    { @Sendable in gate.wait() }
  }
  let authority = RuntimeBusinessAuthorityState(
    reviewCommitHookForTesting: reviewCommitHook ?? gateHook
  )
  var build = Diskplan_V1_BuildPlanRequest()
  build.requestID = 1
  build.scanSessionID.value = Data("positive-scan".utf8)
  build.scanCheckpointID.value = checkpointID
  build.scanEvidenceSha256.value = finalEvidence
  build.agentMode = .off
  try #require(authority.claim(.buildPlan(build)) == nil)
  try controller.handle(
    .buildPlan(build),
    responder: RuntimeBusinessResponder(
      broker: broker,
      request: .buildPlan(build),
      runtimeSessionID: Data("runtime-session".utf8),
      authority: authority
    )
  )
  let manifests: [Diskplan_V1_PlanProjectionManifest] = output.runtimeEvents().compactMap {
    event -> Diskplan_V1_PlanProjectionManifest? in
    guard case .planProjection(let projection)? = event.body else { return nil }
    return projection.manifest
  }
  let plan = try #require(manifests.last)

  var preset = Diskplan_V1_ApplyBatchSelectionPresetEdit()
  preset.preset = .safeStageableWithoutWaiver
  var edit = Diskplan_V1_DecisionOverlayEdit()
  edit.kind = .applyBatchSelectionPreset
  edit.edit = .applyBatchSelectionPreset(preset)
  var request = Diskplan_V1_DecisionOverlayEditRequest()
  request.requestID = 2
  request.projectionID = plan.projectionID
  request.baseRevision = 0
  request.edits = [edit]
  try #require(authority.claim(.editDecisionOverlay(request)) == nil)
  try controller.handle(
    .editDecisionOverlay(request),
    responder: RuntimeBusinessResponder(
      broker: broker,
      request: .editDecisionOverlay(request),
      runtimeSessionID: Data("runtime-session".utf8),
      authority: authority
    )
  )
  let overlays: [Diskplan_V1_DecisionOverlayAcknowledged] = output.runtimeEvents().compactMap {
    event -> Diskplan_V1_DecisionOverlayAcknowledged? in
    guard case .decisionOverlayAcknowledged(let overlay)? = event.body else { return nil }
    return overlay
  }
  let overlay = try #require(overlays.last)
  return RuntimePositiveFixture(
    controller: controller,
    authority: authority,
    broker: broker,
    output: output,
    plan: plan,
    overlay: overlay
  )
}

private func prepareRuntimePositiveReview(
  _ fixture: RuntimePositiveFixture
) async throws -> Diskplan_V1_ApplyReviewProjection {
  var request = Diskplan_V1_PrepareApplyReviewRequest()
  request.requestID = 3
  request.projectionID = fixture.plan.projectionID
  request.overlayID = fixture.overlay.overlayID
  request.overlayRevision = fixture.overlay.revision
  request.overlaySha256 = fixture.overlay.overlaySha256
  try #require(fixture.authority.claim(.prepareApplyReview(request)) == nil)
  try fixture.controller.handle(
    .prepareApplyReview(request),
    responder: fixture.responder(.prepareApplyReview(request))
  )
  let ready = await runtimeEventually {
    fixture.controller.preparedApplyReviewIDForTesting() != nil
  }
  try #require(ready)
  let reviews: [Diskplan_V1_ApplyReviewProjection] = fixture.output.runtimeEvents().compactMap {
    event -> Diskplan_V1_ApplyReviewProjection? in
    guard case .applyReviewProjection(let projection)? = event.body else { return nil }
    return projection
  }
  let review = try #require(reviews.last)
  let authorityCommitted = await runtimeEventually {
    fixture.authority.liveApplyReviewIDForTesting() == review.applyReviewID.value
  }
  try #require(authorityCommitted)
  return review
}

private func runtimePositiveConfirmation(
  _ review: Diskplan_V1_ApplyReviewProjection,
  requestID: UInt64
) -> Diskplan_V1_ConfirmApplyRequest {
  var confirmation = Diskplan_V1_ConfirmApplyRequest()
  confirmation.requestID = requestID
  confirmation.applyReviewID = review.applyReviewID
  confirmation.reviewBindingSha256 = review.reviewBindingSha256
  confirmation.confirmedForceActionIds = review.forceWarningActionIds
  return confirmation
}

private func runtimeEventually(
  _ predicate: @escaping @Sendable () -> Bool
) async -> Bool {
  for _ in 0..<500 {
    if predicate() { return true }
    try? await Task.sleep(for: .milliseconds(2))
  }
  return predicate()
}

private final class RuntimePositiveBackend: RuntimeExecutionBackend, @unchecked Sendable {
  let executionID: Data
  private let lock = NSLock()
  private let waitForCancellation: Bool
  private let startGate: RuntimePositiveGate?
  private let reviewIDs: [Data]
  private var starts = 0
  private var cancellations = 0
  private var dryRuns = 0
  private var tailAwaits = 0
  private var reviewPreparationCount = 0

  var startCount: Int {
    lock.lock()
    defer { lock.unlock() }
    return starts
  }

  var cancelCount: Int {
    lock.lock()
    defer { lock.unlock() }
    return cancellations
  }

  var dryRunCount: Int {
    lock.lock()
    defer { lock.unlock() }
    return dryRuns
  }

  var tailAwaitCount: Int {
    lock.lock()
    defer { lock.unlock() }
    return tailAwaits
  }

  init(
    waitForCancellation: Bool,
    executionID: Data = Data("positive-execution".utf8),
    startGate: RuntimePositiveGate? = nil,
    reviewIDs: [Data] = [Data("positive-review".utf8)]
  ) {
    precondition(!reviewIDs.isEmpty)
    self.waitForCancellation = waitForCancellation
    self.executionID = executionID
    self.startGate = startGate
    self.reviewIDs = reviewIDs
  }

  func prepareDryRun(
    context: RuntimeExecutionPlanContext,
    lifetimeSeconds _: Int64
  ) async throws -> RuntimePreparedDryRun {
    recordDryRun()
    var manifest = Diskplan_V1_DryRunProjectionManifest()
    manifest.projectionID = context.planManifest.projectionID
    manifest.planSha256 = context.planManifest.planSha256
    manifest.overlayID = context.overlayProjection.overlayID
    manifest.overlayRevision = context.overlayProjection.revision
    manifest.overlaySha256 = context.overlayProjection.overlaySha256
    manifest.planID = context.planManifest.planID
    manifest.evidenceID = context.planManifest.evidenceID
    manifest.evidenceSha256 = context.planManifest.evidenceSha256
    manifest.scanSessionID = context.planManifest.scanSessionID
    manifest.scanCheckpointID = context.planManifest.scanCheckpointID
    manifest.scanCheckpointEvidenceSha256 = context.planManifest.scanCheckpointEvidenceSha256
    manifest.dryRunID.value = Data("positive-dry-run".utf8)
    manifest.epoch = runtimePositiveEpoch()
    manifest.current = true
    manifest.currentBindingSha256.value = Data(repeating: 0x81, count: 32)
    return RuntimePreparedDryRun(
      payload: Diskplan_V1_DryRunProjectionPayload(),
      manifest: manifest
    )
  }

  func prepareApplyReview(
    context: RuntimeExecutionPlanContext,
    lifetimeSeconds _: Int64
  ) async throws -> RuntimePreparedApplyReview {
    var projection = Diskplan_V1_ApplyReviewProjection()
    projection.applyReviewID.value = nextReviewID()
    projection.projectionID = context.planManifest.projectionID
    projection.planSha256 = context.planManifest.planSha256
    projection.overlayID = context.overlayProjection.overlayID
    projection.overlayRevision = context.overlayProjection.revision
    projection.overlaySha256 = context.overlayProjection.overlaySha256
    projection.selectedActionCount = context.overlayProjection.selectedActionCount
    projection.planID = context.planManifest.planID
    projection.evidenceID = context.planManifest.evidenceID
    projection.evidenceSha256 = context.planManifest.evidenceSha256
    projection.scanSessionID = context.planManifest.scanSessionID
    projection.scanCheckpointID = context.planManifest.scanCheckpointID
    projection.scanCheckpointEvidenceSha256 = context.planManifest.scanCheckpointEvidenceSha256
    projection.epoch = runtimePositiveEpoch()
    projection.currentBindingSha256.value = Data(repeating: 0x82, count: 32)
    projection.reviewBindingSha256.value = Data(repeating: 0x83, count: 32)
    return RuntimePreparedApplyReview(
      projection: projection,
      attempt: RuntimePreparedApplyAttempt { [weak self] confirmation, context in
        guard let self else { throw RuntimePositiveBackendError.unavailable }
        return try await self.startApply(confirmation: confirmation, context: context)
      }
    )
  }

  private func startApply(
    confirmation: RuntimeApplyConfirmation,
    context: RuntimeExecutionPlanContext
  ) async throws -> RuntimeExecutionRunHandle {
    startGate?.wait()
    recordStart()
    let sourceExecutionID =
      executionID.isEmpty ? Data("invalid-physical-execution".utf8) : executionID
    let source = try RuntimePositiveTailSource(
      executionID: sourceExecutionID,
      review: confirmation.review,
      context: context,
      waitForCancellation: waitForCancellation
    )
    return try await RuntimeExecutionRunHandle.start(
      executionID: executionID,
      applyStarted: source.applyStarted,
      awaitTail: { [weak self] in
        self?.recordTailAwait()
        return await source.awaitTail()
      },
      cancel: { [weak self] in
        self?.recordCancellation()
        source.release()
      }
    )
  }

  private func recordDryRun() {
    lock.lock()
    dryRuns += 1
    lock.unlock()
  }

  private func nextReviewID() -> Data {
    lock.lock()
    let index = min(reviewPreparationCount, reviewIDs.count - 1)
    reviewPreparationCount += 1
    let reviewID = reviewIDs[index]
    lock.unlock()
    return reviewID
  }

  private func recordStart() {
    lock.lock()
    starts += 1
    lock.unlock()
  }

  private func recordCancellation() {
    lock.lock()
    cancellations += 1
    lock.unlock()
  }

  private func recordTailAwait() {
    lock.lock()
    tailAwaits += 1
    lock.unlock()
  }
}

private enum RuntimePositiveBackendError: Error {
  case unavailable
}

private final class RuntimePositiveTailSource: @unchecked Sendable {
  let applyStarted: Diskplan_V1_ExecutionStreamEvent
  private let condition = NSCondition()
  private let tail: RuntimeExecutionTail
  private var released: Bool

  init(
    executionID: Data,
    review: Diskplan_V1_ApplyReviewProjection,
    context: RuntimeExecutionPlanContext,
    waitForCancellation: Bool
  ) throws {
    released = !waitForCancellation
    var started = Diskplan_V1_ApplyStartedProjection()
    started.epoch = review.epoch
    started.applyReviewID = review.applyReviewID
    started.projectionID = review.projectionID
    started.planSha256 = review.planSha256
    started.overlayID = review.overlayID
    started.overlaySha256 = review.overlaySha256
    started.reviewBindingSha256 = review.reviewBindingSha256
    started.selectedActionCount = review.selectedActionCount
    started.planID = review.planID
    started.evidenceID = review.evidenceID
    started.evidenceSha256 = review.evidenceSha256
    started.currentBindingSha256 = review.currentBindingSha256
    started.revalidationSha256 = review.revalidationSha256
    started.overlayRevision = review.overlayRevision
    started.scanSessionID = review.scanSessionID
    started.scanCheckpointID = review.scanCheckpointID
    started.scanCheckpointEvidenceSha256 = review.scanCheckpointEvidenceSha256
    var startEvent = Diskplan_V1_ExecutionStreamEvent()
    startEvent.executionID.value = executionID
    startEvent.body = .applyStarted(started)
    applyStarted = startEvent

    var finished = Diskplan_V1_ApplyFinishedProjection()
    finished.applyReviewID = review.applyReviewID
    finished.reviewBindingSha256 = review.reviewBindingSha256
    var terminalEvent = Diskplan_V1_ExecutionStreamEvent()
    terminalEvent.executionID.value = executionID
    terminalEvent.body = .applyFinished(finished)
    tail = try RuntimeExecutionTail(
      applyStarted: startEvent,
      remainingEvents: [terminalEvent],
      requiredForceWarningActionIDs: review.forceWarningActionIds,
      negotiatedProtocolMinor: context.negotiatedProtocolMinor
    )
  }

  func awaitTail() async -> RuntimeExecutionTail {
    while true {
      if isReleased() { return tail }
      try? await Task.sleep(for: .milliseconds(2))
    }
  }

  private func isReleased() -> Bool {
    condition.lock()
    defer { condition.unlock() }
    return released
  }

  func release() {
    condition.lock()
    released = true
    condition.broadcast()
    condition.unlock()
  }
}

private func runtimePositiveEpoch() -> Diskplan_V1_ExecutionEpochProjection {
  var epoch = Diskplan_V1_ExecutionEpochProjection()
  epoch.epochID.value = Data("positive-epoch".utf8)
  epoch.semanticReferenceTimeSeconds = 100
  epoch.issuedAtSeconds = 100
  epoch.deadlineSeconds = 400
  return epoch
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
