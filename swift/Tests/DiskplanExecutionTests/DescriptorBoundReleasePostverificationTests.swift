import Darwin
import DiskplanPolicy
import Foundation
import Testing

@_spi(DiskplanEngine) @testable import DiskplanExecution

@Test
func descriptorBoundReleaseMintsEngineReceiptFromFreshCurrentCapture() async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let topology = RecordingReleaseTopologySource(mode: .released)
  let core = testCore(topology)
  let frozen = try core.freeze(fixture.request())

  try fixture.removeOwner()
  let report = await core.postverify(frozen)

  #expect(report.ownerTransitions[fixture.actionID] == .missing)
  guard case .allocationGroupReleased(let receipt) = report.groups.first?.outcome else {
    Issue.record("expected an engine-owned allocationGroupReleased receipt")
    return
  }
  #expect(receipt.allocationGroupID == fixture.groupID)
  #expect(receipt.captureID == testDigest(240))
  #expect(receipt.executionBindingHash == fixture.execution.executionBindingHash)
  let collectedComponentID = await topology.requests.first?.componentID
  #expect(receipt.componentID == collectedComponentID)
  #expect(receipt.epochID == fixture.execution.epoch.epochID)
  #expect(receipt.releasedFileObjectIDs == [Data("file-object-a".utf8)])
}

@Test
func freezeRejectsUnauthorizedIdentityAccessContainmentAndLeaf() throws {
  let first = try ReleasePostverificationFixture()
  let second = try ReleasePostverificationFixture()
  defer {
    first.cleanUp()
    second.cleanUp()
  }
  let core = testCore(RecordingReleaseTopologySource(mode: .released))

  let foreignRoot = AuthorizedReleaseNamespaceComponent(
    rawNameFromParent: nil,
    descriptor: second.rootDescriptor,
    authorizedSeal: first.authorizedRootSeal
  )
  let boundOwner = first.ownerLocator()
  let wrongRootDescriptor = ReleasePostverificationOwnerLocator(
    actionID: boundOwner.actionID,
    candidateID: boundOwner.candidateID,
    expectedIdentity: boundOwner.expectedIdentity,
    namespace: [foreignRoot] + Array(boundOwner.namespace.dropFirst()),
    rawLeafName: boundOwner.rawLeafName
  )
  #expect(
    throws: ReleasePostverificationFreezeError.namespaceIdentityMismatch(
      first.actionID, .root
    )
  ) {
    try core.freeze(first.request(owner: wrongRootDescriptor))
  }

  let accessRequest = try first.request()
  guard Darwin.fchmod(first.rootDescriptor, 0o755) == 0 else {
    throw POSIXError(.init(rawValue: errno) ?? .EIO)
  }
  #expect(
    throws: ReleasePostverificationFreezeError.namespaceAccessMismatch(
      first.actionID, .root
    )
  ) {
    try core.freeze(accessRequest)
  }
  guard
    Darwin.fchmod(
      first.rootDescriptor, mode_t(first.authorizedRootSeal.access.mode & 0o7777)
    ) == 0
  else {
    throw POSIXError(.init(rawValue: errno) ?? .EIO)
  }

  let foreignParent = AuthorizedReleaseNamespaceComponent(
    rawNameFromParent: Data(first.namespaceName.utf8),
    descriptor: second.namespaceDescriptor,
    authorizedSeal: first.authorizedParentSeal
  )
  #expect(
    throws: ReleasePostverificationFreezeError.namespaceIdentityMismatch(
      first.actionID, .parentChain(index: 0)
    )
  ) {
    try core.freeze(
      first.request(
        owner: first.ownerLocator(parentOverride: foreignParent)
      )
    )
  }

  let targetRequest = try first.request()
  try first.replaceOwner()
  #expect(
    throws: ReleasePostverificationFreezeError.targetIdentityMismatch(first.actionID)
  ) {
    try core.freeze(targetRequest)
  }
}

@Test
func accessSealIncludesACLAndMountIdentity() throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }

  #expect(fixture.authorizedRootSeal.access.aclDigest.bytes.count == 32)
  #expect(!fixture.authorizedRootSeal.access.mountIdentity.isEmpty)
  #expect(fixture.authorizedParentSeal.access.aclDigest.bytes.count == 32)
  #expect(!fixture.authorizedParentSeal.access.mountIdentity.isEmpty)
}

@Test
func accessSealRejectsInCollectionPolicyDrift() throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let mutator = OneShotDescriptorModeMutator(mode: 0o755)
  let probe = POSIXReleasePostverificationDescriptorProbe { descriptor in
    mutator.mutate(descriptor)
  }

  guard
    case .failed(let failure) = probe.namespaceSeal(
      descriptor: fixture.namespaceDescriptor
    )
  else {
    Issue.record("expected in-collection access drift to fail")
    return
  }
  #expect(failure.code == "namespace-access-changed-during-seal")
}

@Test
func manifestHandleRejectsCallerReplacementAndComponentShrink() throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let topology = RecordingReleaseTopologySource(mode: .released)
  let core = testCore(topology)
  let authorizedOwner = fixture.ownerLocator()
  let replacement = ReleasePostverificationOwnerLocator(
    actionID: authorizedOwner.actionID,
    candidateID: "caller-replacement",
    expectedIdentity: authorizedOwner.expectedIdentity,
    namespace: authorizedOwner.namespace,
    rawLeafName: authorizedOwner.rawLeafName
  )
  #expect(throws: ReleasePostverificationFreezeError.componentBindingMismatch) {
    try core.freeze(
      fixture.request(owner: replacement, authorizedOwner: authorizedOwner)
    )
  }

  let authority = try EngineReleasePostverificationManifestAuthority(
    testingClaimedManifest: fixture.manifest,
    plan: fixture.plan
  )
  #expect(
    throws: ReleasePostverificationManifestClaimError.descriptorLocatorMembershipMismatch
  ) {
    try authority.authorize(jitClaim: fixture.jitClaim(), descriptorLocators: [])
  }
  let secondAuthority = try EngineReleasePostverificationManifestAuthority(
    testingClaimedManifest: fixture.manifest,
    plan: fixture.plan
  )
  #expect(
    throws: ReleasePostverificationManifestClaimError.descriptorLocatorMembershipMismatch
  ) {
    try secondAuthority.authorize(
      jitClaim: fixture.jitClaim(),
      descriptorLocators: [authorizedOwner, authorizedOwner]
    )
  }

  let bindingAuthority = try EngineReleasePostverificationManifestAuthority(
    testingClaimedManifest: fixture.manifest,
    plan: fixture.plan
  )
  let invalidLocator = ReleasePostverificationOwnerLocator(
    actionID: authorizedOwner.actionID,
    candidateID: "caller-replacement",
    expectedIdentity: authorizedOwner.expectedIdentity,
    namespace: authorizedOwner.namespace,
    rawLeafName: authorizedOwner.rawLeafName
  )
  #expect(
    throws: ReleasePostverificationManifestClaimError.descriptorLocatorBindingMismatch(
      fixture.actionID
    )
  ) {
    try bindingAuthority.authorize(
      jitClaim: fixture.jitClaim(),
      descriptorLocators: [invalidLocator]
    )
  }

  let oneShotAuthority = try EngineReleasePostverificationManifestAuthority(
    testingClaimedManifest: fixture.manifest,
    plan: fixture.plan
  )
  let consumedClaim = try fixture.jitClaim()
  _ = try oneShotAuthority.authorize(
    jitClaim: consumedClaim,
    descriptorLocators: [authorizedOwner]
  )
  #expect(throws: ReleasePostverificationManifestClaimError.jitClaimUnknownOrReplayed) {
    try oneShotAuthority.authorize(
      jitClaim: consumedClaim,
      descriptorLocators: [authorizedOwner]
    )
  }
  #expect(throws: ReleasePostverificationManifestClaimError.unitAlreadyAuthorized) {
    try oneShotAuthority.authorize(
      jitClaim: fixture.jitClaim(),
      descriptorLocators: [authorizedOwner]
    )
  }
}

@Test
func manifestAuthorityRejectsPlanSubstitutionAndUnclaimedUnits() throws {
  let fixture = try ReleasePostverificationFixture()
  let substituted = try ReleasePostverificationFixture(namespaceName: "substituted")
  defer {
    fixture.cleanUp()
    substituted.cleanUp()
  }

  #expect(throws: ReleasePostverificationManifestClaimError.manifestPlanMismatch) {
    try EngineReleasePostverificationManifestAuthority(
      testingClaimedManifest: fixture.manifest,
      plan: substituted.plan
    )
  }

  let authority = try EngineReleasePostverificationManifestAuthority(
    testingClaimedManifest: fixture.manifest,
    plan: fixture.plan
  )
  #expect(throws: ReleasePostverificationManifestClaimError.unitNotInClaimedManifest) {
    try authority.authorize(
      jitClaim: fixture.jitClaim(unitID: .action(fixture.actionID)),
      descriptorLocators: [fixture.ownerLocator()]
    )
  }

  #expect(throws: ReleasePostverificationManifestClaimError.claimBindingMismatch) {
    try EngineReleasePostverificationManifestAuthority(
      testingClaimedManifest: fixture.manifest,
      registryCurrentBindingHash: testDigest(254),
      plan: fixture.plan
    )
  }

  let replacedBindingManifest = fixture.manifestReplacingCurrentBindingHash(testDigest(253))
  #expect(throws: ReleasePostverificationManifestClaimError.claimBindingMismatch) {
    try EngineReleasePostverificationManifestAuthority(
      testingClaimedManifest: replacedBindingManifest,
      plan: fixture.plan
    )
  }
}

@Test
func jitExecutionClaimBindsActualCaptureAndRejectsCrossUnitSplices() throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }

  let request = try fixture.jitRequest()
  let report = fixture.currentJITReport(for: request)
  let claim = try EngineJITExecutionClaim.issueForTesting(after: request, report: report)
  let authority = try EngineReleasePostverificationManifestAuthority(
    testingClaimedManifest: fixture.manifest,
    plan: fixture.plan
  )
  _ = try authority.authorize(
    jitClaim: claim,
    descriptorLocators: [fixture.ownerLocator()]
  )

  let missingOutcome = JITRevalidationReport(
    captureID: testDigest(4),
    oneShotNonce: request.oneShotNonce,
    actionOutcomes: [],
    globalFindings: []
  )
  #expect(throws: EngineJITExecutionClaimError.jitNotCurrent) {
    try EngineJITExecutionClaim.issueForTesting(after: request, report: missingOutcome)
  }
  let wrongNonceReport = JITRevalidationReport(
    captureID: testDigest(4),
    oneShotNonce: Data(repeating: 0x73, count: 32),
    actionOutcomes: request.actionIDs.sorted().map {
      ActionRevalidationOutcome(actionID: $0, findings: [])
    },
    globalFindings: []
  )
  #expect(throws: EngineJITExecutionClaimError.jitNotCurrent) {
    try EngineJITExecutionClaim.issueForTesting(after: request, report: wrongNonceReport)
  }

  let actionRequest = try fixture.jitRequest(unitID: .action(fixture.actionID))
  let actionClaim = try EngineJITExecutionClaim.issueForTesting(
    after: actionRequest,
    report: fixture.currentJITReport(for: actionRequest, captureID: testDigest(5))
  )
  let crossUnitAuthority = try EngineReleasePostverificationManifestAuthority(
    testingClaimedManifest: fixture.manifest,
    plan: fixture.plan
  )
  #expect(throws: ReleasePostverificationManifestClaimError.unitNotInClaimedManifest) {
    try crossUnitAuthority.authorize(
      jitClaim: actionClaim,
      descriptorLocators: [fixture.ownerLocator()]
    )
  }
}

@Test
func manifestAuthorityRejectsEveryJITClaimBindingDimension() throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let wrongEpoch = try ExecutionEpochContext(
    epochID: "wrong-epoch",
    semanticReferenceTimeSeconds: fixture.manifest.epoch.semanticReferenceTimeSeconds,
    issuedAtSeconds: fixture.manifest.epoch.issuedAtSeconds,
    deadlineSeconds: fixture.manifest.epoch.deadlineSeconds
  )

  func rejects(_ claim: EngineJITExecutionClaim) throws {
    let authority = try EngineReleasePostverificationManifestAuthority(
      testingClaimedManifest: fixture.manifest,
      plan: fixture.plan
    )
    #expect(throws: ReleasePostverificationManifestClaimError.jitClaimBindingMismatch) {
      try authority.authorize(
        jitClaim: claim,
        descriptorLocators: [fixture.ownerLocator()]
      )
    }
  }

  try rejects(fixture.jitClaim(applyClaimIDHash: testDigest(0x80)))
  try rejects(fixture.jitClaim(actionIDs: []))
  try rejects(fixture.jitClaim(releaseGroupIDs: []))
  try rejects(fixture.jitClaim(currentBindingHash: testDigest(0x81)))
  try rejects(fixture.jitClaim(preparationGeneration: 2))
  try rejects(fixture.jitClaim(epoch: wrongEpoch))
  try rejects(fixture.jitClaim(oneShotNonce: Data(repeating: 0x82, count: 31)))
  try rejects(fixture.jitClaim(planCaptureID: testDigest(0x83)))
  try rejects(fixture.jitClaim(wholePlanCaptureID: testDigest(0x84)))
  try rejects(fixture.jitClaim(jitCaptureID: fixture.plan.globalFacts.captureID))
  try rejects(fixture.jitClaim(jitCaptureID: fixture.manifest.currentCaptureID))
}

@Test
func productionLocatorSourceFreezesExactOperationsAndRejectsMissingOrReplacedChains() throws {
  let success = try ReleasePostverificationFixture()
  defer { success.cleanUp() }
  let successAuthority = try EngineReleasePostverificationManifestAuthority(
    testingClaimedManifest: success.manifest,
    plan: success.plan
  )
  _ = try successAuthority.authorizeAndFreeze(
    jitClaim: success.jitClaim(),
    mutationOperations: [success.ownerOperation()],
    core: testCore(RecordingReleaseTopologySource(mode: .released))
  )

  let missing = try ReleasePostverificationFixture()
  defer { missing.cleanUp() }
  try missing.removeOwner()
  try FileManager.default.removeItem(at: missing.namespace)
  let missingAuthority = try EngineReleasePostverificationManifestAuthority(
    testingClaimedManifest: missing.manifest,
    plan: missing.plan
  )
  let missingClaim = try missing.jitClaim()
  #expect(
    throws: ReleasePostverificationLocatorError.namespaceOpenFailed(
      missing.actionID,
      .parentChain(index: 0),
      ENOENT
    )
  ) {
    try missingAuthority.authorizeAndFreeze(
      jitClaim: missingClaim,
      mutationOperations: [missing.ownerOperation()],
      core: testCore(RecordingReleaseTopologySource(mode: .released))
    )
  }
  #expect(throws: EngineJITExecutionClaimError.claimUnknownOrReplayed) {
    try missingClaim.claim()
  }

  let replaced = try ReleasePostverificationFixture()
  defer { replaced.cleanUp() }
  try replaced.replaceNamespaceWithEmptyDirectory()
  let replacedAuthority = try EngineReleasePostverificationManifestAuthority(
    testingClaimedManifest: replaced.manifest,
    plan: replaced.plan
  )
  #expect(
    throws: ReleasePostverificationManifestClaimError.descriptorLocatorBindingMismatch(
      replaced.actionID
    )
  ) {
    try replacedAuthority.authorizeAndFreeze(
      jitClaim: replaced.jitClaim(),
      mutationOperations: [replaced.ownerOperation()],
      core: testCore(RecordingReleaseTopologySource(mode: .released))
    )
  }
}

@Test
func engineExecutionCompositionUsesDescriptorBoundReleasePostverification() async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let result = try await productionCompositionApply(fixture: fixture)

  #expect(result.report.unitOutcomes.first?.status == .succeeded)
  #expect(
    result.report.unitOutcomes.first?.releasePostVerification.first?.outcome
      == .satisfied
  )
  #expect(!FileManager.default.fileExists(atPath: fixture.owner.path))
  #expect(await result.probe.topologyCalls == 1)
  #expect(await result.probe.legacyBooleanCalls == 0)
}

@Test
func injectedClockCompositionRetainsDescriptorBoundReleasePostverification() async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let result = try await productionCompositionApply(
    fixture: fixture,
    clock: { 100 }
  )

  #expect(result.report.unitOutcomes.first?.status == .succeeded)
  #expect(await result.probe.topologyCalls == 1)
  #expect(await result.probe.legacyBooleanCalls == 0)
}

@Test
func legacyReleaseBooleanCannotBypassMissingDescriptorBoundCollector() async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let result = try await productionCompositionApply(
    fixture: fixture,
    topologyMode: .collectorFailure
  )

  #expect(result.report.unitOutcomes.first?.status == .failed)
  #expect(
    result.report.unitOutcomes.first?.releasePostVerification.first?.outcome
      != .satisfied
  )
  #expect(await result.probe.legacyBooleanCalls == 0)
}

@Test(arguments: [
  ProductionReleaseCompositionFailure.missingLocator,
  .replacedLocator,
  .mutationPreflight,
  .postverification,
])
private func engineExecutionCompositionFailsClosedAcrossReleaseBoundaries(
  failure: ProductionReleaseCompositionFailure
) async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let result = try await productionCompositionApply(
    fixture: fixture,
    topologyMode: failure == .postverification ? .stillAllocated : .released,
    mutationPreflightFails: failure == .mutationPreflight,
    beforeJITReturn: {
      switch failure {
      case .missingLocator:
        try fixture.removeOwner()
        try FileManager.default.removeItem(at: fixture.namespace)
      case .replacedLocator:
        try fixture.replaceNamespaceWithEmptyDirectory()
      case .mutationPreflight, .postverification:
        break
      }
    }
  )

  #expect(result.report.unitOutcomes.first?.status != .succeeded)
  if failure == .missingLocator || failure == .replacedLocator {
    #expect(result.report.unitOutcomes.first?.status == .jitRejected)
    #expect(await result.probe.topologyCalls == 0)
  }
  if failure == .mutationPreflight {
    #expect(result.report.unitOutcomes.first?.steps.first?.status == .failed)
    #expect(await result.probe.topologyCalls == 0)
  }
  if failure == .postverification {
    #expect(await result.probe.topologyCalls == 1)
    #expect(
      result.report.unitOutcomes.first?.releasePostVerification.first?.outcome
        == .notSatisfied(code: "allocation-group-still-allocated")
    )
  }
}

@Test
func parentAndRootReplacementCannotUseMissingLeafInNewTree() async throws {
  let parentFixture = try ReleasePostverificationFixture()
  defer { parentFixture.cleanUp() }
  let parentTopology = RecordingReleaseTopologySource(mode: .released)
  let parentCore = testCore(parentTopology)
  let parentFrozen = try parentCore.freeze(parentFixture.request())
  try parentFixture.replaceNamespaceWithEmptyDirectory()

  let parentReport = await parentCore.postverify(parentFrozen)
  #expect(
    parentReport.groups.first?.outcome
      == .rejected(
        .namespaceContainmentMismatch(parentFixture.actionID, .parentChain(index: 0))
      )
  )
  #expect(await parentTopology.requestCount == 0)

  let rootFixture = try ReleasePostverificationFixture()
  defer { rootFixture.cleanUp() }
  let rootTopology = RecordingReleaseTopologySource(mode: .released)
  let rootCore = testCore(rootTopology)
  let rootFrozen = try rootCore.freeze(rootFixture.request())
  try rootFixture.replaceRootWithEmptyTree()

  let rootReport = await rootCore.postverify(rootFrozen)
  #expect(
    rootReport.groups.first?.outcome
      == .rejected(.ownerSlotStillReferencesExpectedObject(rootFixture.actionID))
  )
  #expect(await rootTopology.requestCount == 0)
}

@Test
func ownerReplacementStillRequiresTopologyCapture() async throws {
  let fixture = try ReleasePostverificationFixture(
    allocationGroupIDs: ["allocation-group-a", "allocation-group-b"]
  )
  defer { fixture.cleanUp() }
  let topology = RecordingReleaseTopologySource(mode: .missing)
  let core = testCore(topology)
  let frozen = try core.freeze(fixture.request())

  try fixture.replaceOwner()
  let report = await core.postverify(frozen)

  guard case .identityChanged(let current) = report.ownerTransitions[fixture.actionID] else {
    Issue.record("expected replacement identity transition")
    return
  }
  #expect(current != fixture.ownerIdentity)
  #expect(report.groups.first?.outcome == .rejected(.topologyMissing))
}

@Test
func topologyCaptureCannotRaceOwnerReappearance() async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let topology = RecordingReleaseTopologySource(mode: .released) {
    try Data("reappeared".utf8).write(to: fixture.owner)
  }
  let core = testCore(topology)
  let frozen = try core.freeze(fixture.request())
  try fixture.removeOwner()

  let report = await core.postverify(frozen)

  #expect(
    report.groups.allSatisfy {
      $0.outcome == .rejected(.ownerSlotChangedAfterTopology(fixture.actionID))
    }
  )
}

@Test
func topologyCaptureCannotRaceNamespaceAccessOrContainmentReplacement() async throws {
  let accessFixture = try ReleasePostverificationFixture()
  defer { accessFixture.cleanUp() }
  let accessTopology = RecordingReleaseTopologySource(mode: .released) {
    try accessFixture.changeNamespaceMode(to: 0o755)
  }
  let accessCore = testCore(accessTopology)
  let accessFrozen = try accessCore.freeze(accessFixture.request())
  try accessFixture.removeOwner()
  let accessReport = await accessCore.postverify(accessFrozen)
  #expect(
    accessReport.groups.allSatisfy {
      $0.outcome
        == .rejected(
          .namespaceAccessMismatch(accessFixture.actionID, .parentChain(index: 0))
        )
    }
  )

  let replacementFixture = try ReleasePostverificationFixture()
  defer { replacementFixture.cleanUp() }
  let replacementTopology = RecordingReleaseTopologySource(mode: .released) {
    try replacementFixture.replaceNamespaceWithEmptyDirectory()
  }
  let replacementCore = testCore(replacementTopology)
  let replacementFrozen = try replacementCore.freeze(replacementFixture.request())
  try replacementFixture.removeOwner()
  let replacementReport = await replacementCore.postverify(replacementFrozen)
  #expect(
    replacementReport.groups.allSatisfy {
      $0.outcome
        == .rejected(
          .namespaceContainmentMismatch(
            replacementFixture.actionID, .parentChain(index: 0)
          )
        )
    }
  )
}

@Test
func namespaceAccessMutationIsDistinctFromChildEntryChurn() async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let topology = RecordingReleaseTopologySource(mode: .released)
  let core = testCore(topology)
  let frozen = try core.freeze(fixture.request())

  try fixture.removeOwner()
  try fixture.changeNamespaceMode(to: 0o755)
  let report = await core.postverify(frozen)

  #expect(
    report.groups.first?.outcome
      == .rejected(.namespaceAccessMismatch(fixture.actionID, .parentChain(index: 0)))
  )
  #expect(await topology.requestCount == 0)
}

@Test(
  arguments: [
    ScriptedNamespaceFailure.missing,
    .unreadable,
    .collectorFailure,
    .identityMismatch,
    .accessMismatch,
  ])
private func namespaceFailureCategoriesRemainDistinct(
  failure: ScriptedNamespaceFailure
) async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let descriptorProbe = SwitchableReleaseDescriptorProbe(failure: failure)
  let topology = RecordingReleaseTopologySource(mode: .released)
  let core = testCore(topology, descriptorProbe: descriptorProbe)
  let frozen = try core.freeze(fixture.request())
  descriptorProbe.arm()

  try fixture.removeOwner()
  let report = await core.postverify(frozen)

  let expected: ReleasePostverificationFailure
  switch failure {
  case .missing:
    expected = .namespaceMissing(fixture.actionID, .root)
  case .unreadable:
    expected = .namespaceUnreadable(
      fixture.actionID,
      .root,
      ObservationFailure(code: "EACCES", collector: "scripted-namespace")
    )
  case .collectorFailure:
    expected = .namespaceCollectionFailed(
      fixture.actionID,
      .root,
      ObservationFailure(code: "EIO", collector: "scripted-namespace")
    )
  case .identityMismatch:
    expected = .namespaceIdentityMismatch(fixture.actionID, .root)
  case .accessMismatch:
    expected = .namespaceAccessMismatch(fixture.actionID, .root)
  }
  #expect(report.groups.first?.outcome == .rejected(expected))
  #expect(await topology.requestCount == 0)
}

@Test(
  arguments: [
    InvalidCaptureMode.wrongExecutionBinding,
    .wrongComponent,
    .wrongEpoch,
    .wrongNonce,
    .stale,
    .extremePast,
    .planCapture,
    .jitCapture,
  ])
private func captureBindingFreshnessAndLineageRejectEchoedProofs(
  mode: InvalidCaptureMode
) async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let topology = RecordingReleaseTopologySource(mode: .invalidCapture(mode))
  let core = testCore(topology)
  let frozen = try core.freeze(fixture.request())
  try fixture.removeOwner()

  let report = await core.postverify(frozen)

  let expected: ReleasePostverificationFailure =
    mode == .stale || mode == .extremePast
    ? .topologyReceiptNotFresh
    : (mode == .planCapture || mode == .jitCapture)
      ? .topologyCaptureReused
      : .topologyReceiptBindingMismatch
  #expect(report.groups.allSatisfy { $0.outcome == .rejected(expected) })
}

@Test
func captureIDIsOneShotAcrossComponents() async throws {
  let first = try ReleasePostverificationFixture()
  let second = try ReleasePostverificationFixture()
  defer {
    first.cleanUp()
    second.cleanUp()
  }
  let topology = RecordingReleaseTopologySource(mode: .released)
  let core = testCore(topology)
  let firstFrozen = try core.freeze(first.request())
  let secondFrozen = try core.freeze(second.request())
  try first.removeOwner()
  try second.removeOwner()

  let firstReport = await core.postverify(firstFrozen)
  let secondReport = await core.postverify(secondFrozen)

  guard case .allocationGroupReleased = firstReport.groups.first?.outcome else {
    Issue.record("expected first capture claim to succeed")
    return
  }
  #expect(
    secondReport.groups.allSatisfy {
      $0.outcome == .rejected(.topologyCaptureReused)
    }
  )
}

@Test
func connectedComponentPublishesNoPartialRelease() async throws {
  let fixture = try ReleasePostverificationFixture(
    allocationGroupIDs: ["allocation-group-a", "allocation-group-b"]
  )
  defer { fixture.cleanUp() }
  let topology = RecordingReleaseTopologySource(
    mode: .groupStillAllocated("allocation-group-b")
  )
  let core = testCore(topology)
  let frozen = try core.freeze(fixture.request())
  try fixture.removeOwner()

  let report = await core.postverify(frozen)

  #expect(report.groups.count == 2)
  #expect(
    report.groups.allSatisfy {
      $0.outcome == .rejected(.allocationGroupStillAllocated("allocation-group-b"))
    }
  )
}

@Test
func fileObjectIDsUseRawUTF8Equality() async throws {
  let fixture = try ReleasePostverificationFixture(fileObjectID: "\u{00e9}")
  defer { fixture.cleanUp() }
  #expect(
    ReleaseFileTopologyExpectation(
      fileObjectID: "\u{00e9}",
      owners: [],
      linkCount: .known(1)
    )
      != ReleaseFileTopologyExpectation(
        fileObjectID: "e\u{0301}",
        owners: [],
        linkCount: .known(1)
      )
  )
  let topology = RecordingReleaseTopologySource(
    mode: .rawFileObjectOverride(Data("e\u{0301}".utf8))
  )
  let core = testCore(topology)
  let frozen = try core.freeze(fixture.request())
  try fixture.removeOwner()

  let report = await core.postverify(frozen)

  #expect(
    report.groups.first?.outcome
      == .rejected(.invalidAllocationGroupReleaseEvidence(fixture.groupID))
  )
}

@Test
func releasePostverificationComponentBindingMatchesCanonicalReleaseFixture() throws {
  let fixtureURL = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .deletingLastPathComponent()
    .appendingPathComponent("fixtures/release/release-postverification-component-v1.json")
  let fixture = try JSONDecoder().decode(
    ReleasePostverificationBindingFixture.self,
    from: Data(contentsOf: fixtureURL)
  )
  let vector = try releasePostverificationBindingVector()
  let canonicalBytes = vector.schema.canonicalBytes(
    execution: vector.execution,
    owners: vector.owners,
    groups: vector.groups
  )
  let exactDomain = Data(
    "diskplan/release-postverification-component/v1\0".utf8
  )
  #expect(fixture.schema == "diskplan.release-postverification-component-binding.fixture.v1")
  #expect(fixture.bindingKind == ReleasePostverificationComponentBindingV1.bindingKind)
  #expect(Data(hex: fixture.domainHex) == exactDomain)
  #expect(canonicalBytes.starts(with: exactDomain))
  #expect(canonicalBytes[exactDomain.count] == 0)
  #expect(canonicalBytes.hex == fixture.canonicalHex)
  #expect(
    vector.schema.digest(
      execution: vector.execution,
      owners: vector.owners,
      groups: vector.groups
    ).hex == fixture.sha256)
}

private struct ReleasePostverificationBindingFixture: Decodable {
  let schema: String
  let bindingKind: String
  let domainHex: String
  let canonicalHex: String
  let sha256: String

  private enum CodingKeys: String, CodingKey {
    case schema
    case bindingKind = "binding_kind"
    case domainHex = "domain_hex"
    case canonicalHex = "canonical_hex"
    case sha256
  }
}

private func releasePostverificationBindingVector() throws -> (
  schema: ReleasePostverificationComponentBindingV1,
  execution: ReleasePostverificationExecutionBinding,
  owners: [ReleasePostverificationOwnerLocator],
  groups: [ReleasePostverificationGroupExpectation]
) {
  let epoch = try ExecutionEpochContext(
    epochID: "fixture-epoch",
    semanticReferenceTimeSeconds: 1_700_000_000,
    issuedAtSeconds: 1_700_000_000,
    deadlineSeconds: 1_700_000_300
  )
  let actionID = ActionID(digest: testDigest(10))
  let ownerPath = try RawTargetPath(
    components: [Data("namespace".utf8), Data([0x6f, 0x77, 0x6e, 0x65, 0x72, 0xcc, 0x81])]
  )
  let access = ReleaseDescriptorAccessSeal(
    mode: 0o100600,
    ownerUserID: 501,
    ownerGroupID: 20,
    authorizationFlags: 2,
    aclDigest: testDigest(11),
    mountIdentity: Data([0x00, 0x7f, 0x80, 0xff])
  )
  let rootIdentity = ObjectIdentity(
    device: 0x0102_0304_0506_0708,
    object: 0x1112_1314_1516_1718,
    generation: .known(23),
    type: .directory
  )
  let parentIdentity = ObjectIdentity(
    device: 0x2122_2324_2526_2728,
    object: 0x3132_3334_3536_3738,
    generation: .unknown(.unsupported),
    type: .directory
  )
  let targetIdentity = ObjectIdentity(
    device: 0x4142_4344_4546_4748,
    object: 0x5152_5354_5556_5758,
    generation: .unreadable(ObservationFailure(code: "gen-denied", collector: "fixture")),
    type: .regularFile
  )
  let owner = ReleasePostverificationOwnerLocator(
    actionID: actionID,
    candidateID: "candidate-\u{00e9}",
    expectedIdentity: targetIdentity,
    namespace: [
      AuthorizedReleaseNamespaceComponent(
        rawNameFromParent: nil,
        descriptor: -1,
        authorizedSeal: ReleaseDescriptorNamespaceSeal(
          identity: rootIdentity, access: access)
      ),
      AuthorizedReleaseNamespaceComponent(
        rawNameFromParent: Data("namespace".utf8),
        descriptor: -1,
        authorizedSeal: ReleaseDescriptorNamespaceSeal(
          identity: parentIdentity, access: access)
      ),
    ],
    rawLeafName: Data([0x6f, 0x77, 0x6e, 0x65, 0x72, 0xcc, 0x81])
  )
  let group = ReleasePostverificationGroupExpectation(
    allocationGroupID: "group-\u{00e9}",
    topology: ReleaseAllocationTopologyExpectation(
      allocationGroupID: "group-\u{00e9}",
      fileObjects: [
        ReleaseFileTopologyExpectation(
          fileObjectID: "file-e\u{0301}",
          owners: [FileOwnerLink(candidateID: owner.candidateID, path: ownerPath)],
          linkCount: .known(1)
        )
      ],
      cloneRefCount: .known(1),
      sharedBytes: .known(4_096),
      snapshotBlocker: .known(false)
    ),
    ownerActionIDs: [actionID]
  )
  let execution = ReleasePostverificationExecutionBinding(
    executionBindingHash: testDigest(9),
    applyClaimIDHash: testDigest(8),
    preparationGeneration: 42,
    epoch: epoch,
    jitOneShotNonce: Data(repeating: 0x44, count: 32),
    planCaptureID: testDigest(5),
    wholePlanCaptureID: testDigest(6),
    jitCaptureID: testDigest(7),
    freshnessLimitSeconds: 300
  )
  return (
    ReleasePostverificationComponentBindingV1(
      manifestCurrentBindingHash: testDigest(9),
      planHash: testDigest(1),
      overlayHash: testDigest(2),
      epoch: epoch,
      applyClaimIDHash: testDigest(8),
      preparationGeneration: 42,
      jitOneShotNonce: Data(repeating: 0x44, count: 32),
      planCaptureID: testDigest(5),
      wholePlanCaptureID: testDigest(6),
      jitCaptureID: testDigest(7),
      allocationGroupIDs: [group.allocationGroupID],
      ownerActionIDs: [actionID],
      jitActionIDs: [actionID]
    ),
    execution,
    [owner],
    [group]
  )
}

extension Data {
  fileprivate init?(hex: String) {
    guard hex.count.isMultiple(of: 2) else { return nil }
    var bytes: [UInt8] = []
    bytes.reserveCapacity(hex.count / 2)
    var index = hex.startIndex
    while index < hex.endIndex {
      let next = hex.index(index, offsetBy: 2)
      guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
      bytes.append(byte)
      index = next
    }
    self = Data(bytes)
  }

  fileprivate var hex: String { map { String(format: "%02x", $0) }.joined() }
}

private enum ProductionReleaseTopologyMode: Equatable, Sendable {
  case released
  case stillAllocated
  case collectorFailure
}

private enum ProductionReleaseCompositionFailure: Equatable, Sendable {
  case missingLocator
  case replacedLocator
  case mutationPreflight
  case postverification
}

private actor ProductionReleaseCompositionProbe {
  private(set) var legacyBooleanCalls = 0
  private(set) var topologyCalls = 0

  func legacyBoolean(
    _ request: ReleasePostVerificationRequest
  ) -> [CurrentReleasePostcondition] {
    legacyBooleanCalls += 1
    return request.allocationGroupIDs.map {
      CurrentReleasePostcondition(
        allocationGroupID: $0,
        released: .known(true)
      )
    }
  }

  func collectTopology(
    _ operation: EngineReleaseTopologyCollectionOperation,
    mode: ProductionReleaseTopologyMode
  ) -> Observation<CurrentReleaseTopologyCapture> {
    topologyCalls += 1
    if mode == .collectorFailure {
      return .failed(
        ObservationFailure(
          code: "simulated-descriptor-bound-topology-failure",
          collector: "release-composition-test"
        ))
    }
    let request = operation.request
    return .known(
      CurrentReleaseTopologyCapture(
        captureID: testDigest(0xf0),
        executionBindingHash: request.executionBindingHash,
        componentID: request.componentID,
        epochID: request.epoch.epochID,
        oneShotNonce: request.oneShotNonce,
        capturedAtSeconds: request.epoch.issuedAtSeconds,
        groups: request.groups.map { group in
          CurrentReleaseTopologyGroup(
            allocationGroupID: group.allocationGroupID,
            topology: mode == .stillAllocated
              ? .allocationGroupStillAllocated
              : .allocationGroupReleased(
                AllocationGroupReleasedTopologyEvidence(
                  allocationGroupID: group.allocationGroupID,
                  allocationGroupPresent: false,
                  fileObjects: group.topology.fileObjects.map {
                    ReleasedFileObjectTopologyEvidence(
                      fileObjectID: Data($0.fileObjectID.utf8),
                      remainingOwnerCount: 0
                    )
                  }
                ))
          )
        }
      ))
  }
}

private func productionCompositionApply(
  fixture: ReleasePostverificationFixture,
  topologyMode: ProductionReleaseTopologyMode = .released,
  mutationPreflightFails: Bool = false,
  beforeJITReturn: @escaping @Sendable () throws -> Void = {},
  clock: (@Sendable () -> Int64)? = nil
) async throws -> (
  report: BestEffortApplyReport,
  probe: ProductionReleaseCompositionProbe
) {
  let probe = ProductionReleaseCompositionProbe()
  let collector = EngineRevalidationCollector(
    collectCurrent: { request in
      fixture.currentSnapshot(
        captureID: testDigest(2),
        referenceTimeSeconds: request.epoch.semanticReferenceTimeSeconds
      )
    },
    collectJIT: { request in
      try beforeJITReturn()
      return JITRevalidationSnapshot(
        oneShotNonce: request.oneShotNonce,
        authorizationCurrentBindingHash: request.authorizationCurrentBindingHash,
        preparationGeneration: request.preparationGeneration,
        epochID: request.epoch.epochID,
        snapshot: fixture.currentSnapshot(
          captureID: testDigest(4),
          referenceTimeSeconds: request.epoch.semanticReferenceTimeSeconds,
          actionIDs: request.actionIDs
        )
      )
    },
    collectReleasePostconditions: { request in
      await probe.legacyBoolean(request)
    },
    collectFinalDescriptors: { request in
      guard !mutationPreflightFails else {
        let target = request.target
        return FinalDescriptorEvidenceSnapshot(
          targetIdentity: .absent,
          targetAccessPolicy: .known(target.expectedTargetAccessPolicy),
          targetContent: .known(target.expectedContent),
          root: CurrentNamespaceComponent(
            relativePath: nil,
            identity: .known(target.expectedRootIdentity),
            seal: .known(target.expectedRootSeal)
          ),
          parents: target.expectedParentIdentities.indices.map { index in
            CurrentNamespaceComponent(
              relativePath: try? RawTargetPath(
                components: Array(target.targetPath.components.prefix(index + 1))
              ),
              identity: .known(target.expectedParentIdentities[index]),
              seal: .known(target.expectedParentSeals[index])
            )
          }
        )
      }
      return fixture.matchingFinalDescriptorEvidence(request)
    },
    collectReleaseTopology: { operation in
      await probe.collectTopology(operation, mode: topologyMode)
    }
  )
  let composition: EngineExecutionComposition
  if let clock {
    composition = EngineExecutionComposition(
      collector: collector,
      eventSink: NoOpExecutionEventSink(),
      clock: clock
    )
  } else {
    composition = EngineExecutionComposition(
      collector: collector,
      eventSink: NoOpExecutionEventSink()
    )
  }
  let preparation = try await composition.preparation.prepare(
    plan: fixture.plan,
    overlay: fixture.overlay,
    mode: .apply,
    lifetimeSeconds: 300
  )
  guard case .applyReady(let ready, let capability) = preparation else {
    throw ReleasePostverificationLocatorError.operationMembershipMismatch
  }
  let authorization = try await composition.preparation.authorizeApply(
    capability,
    ready: ready,
    plan: fixture.plan,
    overlay: fixture.overlay
  )
  let report = await composition.applyCoordinator.apply(
    authorization: authorization,
    plan: fixture.plan,
    overlay: fixture.overlay
  )
  return (report, probe)
}

@Test
func topologyCollectorReceivesOpaqueCLOEXECDescriptorCapabilities() async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let topology = RecordingReleaseTopologySource(mode: .released)
  let core = testCore(topology)
  let frozen = try core.freeze(fixture.request())
  let componentDescriptors = frozen.ownedDescriptorValues
  try fixture.removeOwner()

  let report = await core.postverify(frozen)

  guard case .allocationGroupReleased = report.groups.first?.outcome else {
    Issue.record("expected topology release")
    return
  }
  #expect(await topology.allDescriptorsCloseOnExec)
  #expect(await topology.descriptorCount(for: fixture.actionID) == 2)
  #expect(await topology.requests.first?.owners.first?.namespaceComponentCount == 2)
  for descriptor in componentDescriptors {
    errno = 0
    #expect(Darwin.fcntl(descriptor, F_GETFD) == -1)
    #expect(errno == EBADF)
  }
}

@Test
func abandonedFrozenComponentClosesDescriptorsWithoutPostverification() throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  var descriptors: [Int32] = []
  do {
    let frozen = try testCore(
      RecordingReleaseTopologySource(mode: .released)
    ).freeze(fixture.request())
    descriptors = frozen.ownedDescriptorValues
    #expect(!descriptors.isEmpty)
  }

  for descriptor in descriptors {
    errno = 0
    #expect(Darwin.fcntl(descriptor, F_GETFD) == -1)
    #expect(errno == EBADF)
  }
}

@Test
func duplicateOwnerAndRepeatedConsumptionFailClosed() async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let topology = RecordingReleaseTopologySource(mode: .released)
  let core = testCore(topology)
  let owner = fixture.ownerLocator()
  #expect(
    throws: ReleasePostverificationManifestClaimError.descriptorLocatorMembershipMismatch
  ) {
    try fixture.request(actualOwners: [owner, owner])
  }

  let frozen = try core.freeze(fixture.request())
  try fixture.removeOwner()
  let first = await core.postverify(frozen)
  let second = await core.postverify(frozen)
  guard case .allocationGroupReleased = first.groups.first?.outcome else {
    Issue.record("expected first consumption to succeed")
    return
  }
  #expect(second.groups.first?.outcome == .rejected(.leaseAlreadyConsumed))
  #expect(await topology.requestCount == 1)
}

private enum TestTopologySourceError: Error { case failed }

private enum InvalidCaptureMode: CaseIterable, Sendable {
  case wrongExecutionBinding
  case wrongComponent
  case wrongEpoch
  case wrongNonce
  case stale
  case extremePast
  case planCapture
  case jitCapture
}

private final class RecordingReleaseTopologySource: @unchecked Sendable {
  enum Mode: Sendable {
    case released
    case missing
    case throwFailure
    case invalidCapture(InvalidCaptureMode)
    case groupStillAllocated(String)
    case rawFileObjectOverride(Data)
  }

  private actor State {
    var requests: [ReleasePostverificationTopologyRequest] = []
    var allDescriptorsCloseOnExec = true
    var descriptorCounts: [ActionID: Int] = [:]
    var requestCount: Int { requests.count }

    func collect(
      mode: Mode,
      hook: (@Sendable () throws -> Void)?,
      operation: EngineReleaseTopologyCollectionOperation
    ) async throws -> Observation<CurrentReleaseTopologyCapture> {
      let request = operation.request
      requests.append(request)
      allDescriptorsCloseOnExec =
        allDescriptorsCloseOnExec && operation.allNamespaceDescriptorsAreCloseOnExec()
      for owner in request.owners {
        descriptorCounts[owner.actionID] = operation.namespaceDescriptorCount(
          for: owner.actionID
        )
      }
      try hook?()
      if case .throwFailure = mode { throw TestTopologySourceError.failed }
      if case .missing = mode { return .absent }

      var captureID = testDigest(240)
      var executionBindingHash = request.executionBindingHash
      var componentID = request.componentID
      var epochID = request.epoch.epochID
      var nonce = request.oneShotNonce
      var capturedAt: Int64 = 200
      if case .invalidCapture(let invalid) = mode {
        switch invalid {
        case .wrongExecutionBinding: executionBindingHash = testDigest(88)
        case .wrongComponent: componentID = testDigest(89)
        case .wrongEpoch: epochID = "wrong-epoch"
        case .wrongNonce: nonce = Data(repeating: 91, count: 32)
        case .stale: capturedAt = 150
        case .extremePast: capturedAt = .min
        case .planCapture: captureID = testDigest(1)
        case .jitCapture: captureID = testDigest(2)
        }
      }
      let groups = request.groups.map { expected -> CurrentReleaseTopologyGroup in
        if case .groupStillAllocated(let retained) = mode,
          RawUTF8Key(retained) == RawUTF8Key(expected.allocationGroupID)
        {
          return CurrentReleaseTopologyGroup(
            allocationGroupID: expected.allocationGroupID,
            topology: .allocationGroupStillAllocated
          )
        }
        var fileIDs = expected.topology.fileObjects.map {
          Data($0.fileObjectID.utf8)
        }
        if case .rawFileObjectOverride(let override) = mode, !fileIDs.isEmpty {
          fileIDs[0] = override
        }
        return CurrentReleaseTopologyGroup(
          allocationGroupID: expected.allocationGroupID,
          topology: .allocationGroupReleased(
            AllocationGroupReleasedTopologyEvidence(
              allocationGroupID: expected.allocationGroupID,
              allocationGroupPresent: false,
              fileObjects: fileIDs.map {
                ReleasedFileObjectTopologyEvidence(
                  fileObjectID: $0,
                  remainingOwnerCount: 0
                )
              }
            )
          )
        )
      }
      return .known(
        CurrentReleaseTopologyCapture(
          captureID: captureID,
          executionBindingHash: executionBindingHash,
          componentID: componentID,
          epochID: epochID,
          oneShotNonce: nonce,
          capturedAtSeconds: capturedAt,
          groups: groups
        )
      )
    }
  }

  let collector: EngineReleasePostverificationTopologyCollector
  private let state: State

  init(mode: Mode, duringCollection: (@Sendable () throws -> Void)? = nil) {
    let state = State()
    self.state = state
    collector = EngineReleasePostverificationTopologyCollector { operation in
      try await state.collect(mode: mode, hook: duringCollection, operation: operation)
    }
  }

  var requests: [ReleasePostverificationTopologyRequest] {
    get async { await state.requests }
  }

  var requestCount: Int { get async { await state.requestCount } }
  var allDescriptorsCloseOnExec: Bool {
    get async { await state.allDescriptorsCloseOnExec }
  }

  func descriptorCount(for actionID: ActionID) async -> Int {
    await state.descriptorCounts[actionID] ?? 0
  }
}

private enum ScriptedNamespaceFailure: CaseIterable, Sendable {
  case missing
  case unreadable
  case collectorFailure
  case identityMismatch
  case accessMismatch
}

private final class OneShotDescriptorModeMutator: @unchecked Sendable {
  private let lock = NSLock()
  private let mode: mode_t
  private var didMutate = false

  init(mode: mode_t) { self.mode = mode }

  func mutate(_ descriptor: Int32) {
    lock.lock()
    guard !didMutate else {
      lock.unlock()
      return
    }
    didMutate = true
    lock.unlock()
    _ = Darwin.fchmod(descriptor, mode)
  }
}

private final class SwitchableReleaseDescriptorProbe: @unchecked Sendable,
  ReleasePostverificationDescriptorProbing
{
  private let underlying = POSIXReleasePostverificationDescriptorProbe()
  private let failure: ScriptedNamespaceFailure
  private let lock = NSLock()
  private var armed = false

  init(failure: ScriptedNamespaceFailure) { self.failure = failure }

  func arm() {
    lock.lock()
    armed = true
    lock.unlock()
  }

  func namespaceSeal(descriptor: Int32) -> Observation<ReleaseDescriptorNamespaceSeal> {
    lock.lock()
    let shouldOverride = armed
    lock.unlock()
    let actual = underlying.namespaceSeal(descriptor: descriptor)
    guard shouldOverride else { return actual }
    switch failure {
    case .missing:
      return .absent
    case .unreadable:
      return .unreadable(
        ObservationFailure(code: "EACCES", collector: "scripted-namespace")
      )
    case .collectorFailure:
      return .failed(
        ObservationFailure(code: "EIO", collector: "scripted-namespace")
      )
    case .identityMismatch:
      guard case .known(let seal) = actual else { return actual }
      return .known(
        ReleaseDescriptorNamespaceSeal(
          identity: ObjectIdentity(
            device: seal.identity.device,
            object: seal.identity.object &+ 1,
            generation: seal.identity.generation,
            type: seal.identity.type
          ),
          access: seal.access
        )
      )
    case .accessMismatch:
      guard case .known(let seal) = actual else { return actual }
      return .known(
        ReleaseDescriptorNamespaceSeal(
          identity: seal.identity,
          access: ReleaseDescriptorAccessSeal(
            mode: seal.access.mode ^ 0o100,
            ownerUserID: seal.access.ownerUserID,
            ownerGroupID: seal.access.ownerGroupID,
            authorizationFlags: seal.access.authorizationFlags,
            aclDigest: seal.access.aclDigest,
            mountIdentity: seal.access.mountIdentity
          )
        )
      )
    }
  }

  func ownerSlot(
    parentDescriptor: Int32,
    rawLeafName: Data
  ) -> ReleaseOwnerSlotObservation {
    underlying.ownerSlot(
      parentDescriptor: parentDescriptor,
      rawLeafName: rawLeafName
    )
  }

  func descendantDirectory(
    parentDescriptor: Int32,
    rawName: Data
  ) -> Observation<Int32> {
    underlying.descendantDirectory(
      parentDescriptor: parentDescriptor,
      rawName: rawName
    )
  }
}

private final class ReleasePostverificationFixture: @unchecked Sendable {
  let container: URL
  let root: URL
  let namespace: URL
  let owner: URL
  let namespaceName: String
  let rootDescriptor: Int32
  let namespaceDescriptor: Int32
  let actionID: ActionID
  let groupID = "allocation-group-a"
  let candidateID = "candidate-a"
  let ownerIdentity: ObjectIdentity
  let topology: ReleaseAllocationTopologyExpectation
  let authorizedRootSeal: ReleaseDescriptorNamespaceSeal
  let authorizedParentSeal: ReleaseDescriptorNamespaceSeal
  let execution: ReleasePostverificationExecutionBinding
  let plan: ImmutablePlan
  let overlay: DecisionOverlay
  let manifest: ExecutionManifest
  let unitID: ExecutionUnitID

  init(
    namespaceName: String = "namespace",
    fileObjectID: String = "file-object-a",
    allocationGroupIDs: [String] = ["allocation-group-a"]
  ) throws {
    self.namespaceName = namespaceName
    container = FileManager.default.temporaryDirectory
      .appendingPathComponent("diskplan-release-postverify-\(UUID().uuidString)")
    root = container.appendingPathComponent("root")
    namespace = root.appendingPathComponent(namespaceName)
    owner = namespace.appendingPathComponent("owner")
    try FileManager.default.createDirectory(
      at: namespace,
      withIntermediateDirectories: true
    )
    guard Darwin.chmod(root.path, 0o700) == 0,
      Darwin.chmod(namespace.path, 0o700) == 0
    else {
      throw POSIXError(.init(rawValue: errno) ?? .EIO)
    }
    try Data("payload".utf8).write(to: owner)
    rootDescriptor = root.path.withCString {
      Darwin.open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard rootDescriptor >= 0 else {
      throw POSIXError(.init(rawValue: errno) ?? .EIO)
    }
    namespaceDescriptor = namespace.path.withCString {
      Darwin.open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard namespaceDescriptor >= 0 else {
      _ = Darwin.close(rootDescriptor)
      throw POSIXError(.init(rawValue: errno) ?? .EIO)
    }
    let probe = POSIXReleasePostverificationDescriptorProbe()
    guard case .known(let rootSeal) = probe.namespaceSeal(descriptor: rootDescriptor),
      case .known(let parentSeal) = probe.namespaceSeal(descriptor: namespaceDescriptor)
    else {
      _ = Darwin.close(rootDescriptor)
      _ = Darwin.close(namespaceDescriptor)
      throw POSIXError(.EIO)
    }
    authorizedRootSeal = rootSeal
    authorizedParentSeal = parentSeal
    ownerIdentity = try Self.identity(
      parentDescriptor: namespaceDescriptor,
      leaf: Data("owner".utf8)
    )
    let rawRoot = try RawRootPath(absoluteBytes: Data(root.path.utf8))
    let targetPath = try RawTargetPath(
      components: [Data(namespaceName.utf8), Data("owner".utf8)]
    )
    let rootPolicySeal = Self.policySeal(authorizedRootSeal.access)
    let parentPolicySeal = Self.policySeal(authorizedParentSeal.access)
    let namespaceBinding = try ProtectedNamespaceBinding(
      rawRoot: rawRoot,
      rootIdentity: authorizedRootSeal.identity,
      rootSeal: rootPolicySeal,
      targetPath: targetPath,
      targetIdentity: ownerIdentity,
      parentChain: [
        ParentNamespaceBinding(
          relativePath: try RawTargetPath(components: [Data(namespaceName.utf8)]),
          identity: authorizedParentSeal.identity,
          seal: parentPolicySeal
        )
      ]
    )
    let facts = FrozenGlobalFacts(
      captureID: testDigest(1),
      profile: "standard",
      configuration: Data("release-postverification".utf8),
      coverage: [
        GlobalCoverageFact(rawRoot: rawRoot, coverage: .complete, reasons: ["complete"])
      ],
      semanticReferenceTimeSeconds: 100,
      policyVersion: "policy-1",
      schemaVersion: "schema-1"
    )
    let evidence = try FrozenEvidenceSnapshot(
      captureID: facts.captureID,
      globalFactsHash: facts.globalFactsHash,
      candidateID: candidateID,
      namespaceBinding: namespaceBinding,
      identity: .known(ownerIdentity),
      coverage: .complete,
      collectorStatus: .known(.complete),
      activity: .known(.inactive),
      explicitProtection: .known(.notProtected),
      providerState: .known(.local),
      recoverability: .known(.recoverable),
      recoverabilityReviewFacts: [],
      dependencyState: .known(.complete),
      semanticReviewFacts: [],
      accessPolicy: .known("owner-private"),
      contentProtection: .known(.explicitlyNotApplicable(.metadataOnlyObject)),
      aclDigest: .known(testDigest(93)),
      targetMountIdentity: .known(
        authorizedRootSeal.access.mountIdentity.base64EncodedString()
      ),
      removalForceRequirement: .known(.notRequired),
      quarantineCapability: .known(true),
      gitWorktree: nil,
      adapterScope: .genericRemove,
      additionalAdapterScopes: allocationGroupIDs.map {
        .completeReleaseSetRemove(allocationGroupID: $0)
      },
      classificationClaims: completeClassificationClaims(),
      semanticReferenceTimeSeconds: 100,
      policyVersion: "policy-1",
      schemaVersion: "schema-1"
    )
    let ownerAction = try makeAction(evidence: evidence, facts: facts)
    actionID = ownerAction.id
    let fixtureCandidateID = "candidate-a"
    let candidate = try StorageCandidate(
      id: fixtureCandidateID, evidence: evidence, immediatePrivateBytes: .known(1)
    )
    let provenance = GraphObservationProvenance(globalFacts: facts)
    let fileObjects = try allocationGroupIDs.enumerated().map { index, _ in
      let ownerPath =
        index == 0
        ? targetPath
        : try RawTargetPath(
          components: [
            Data(namespaceName.utf8), Data("owner".utf8), Data("member-\(index + 1)".utf8),
          ])
      return FileObjectNode(
        provenance: provenance,
        id: index == 0 ? fileObjectID : "file-object-\(index + 1)",
        observedOwners: [FileOwnerLink(candidateID: fixtureCandidateID, path: ownerPath)],
        linkCount: .known(1)
      )
    }
    let graph = try StorageReleaseGraph(
      globalFacts: facts,
      candidates: [candidate],
      fileObjects: fileObjects,
      allocationGroups: zip(allocationGroupIDs, fileObjects).map { groupID, file in
        AllocationGroupNode(
          provenance: provenance,
          id: groupID,
          ownerFileObjectIDs: [file.id],
          cloneRefCount: .known(1),
          sharedBytes: .known(4_096),
          snapshotBlocker: .known(false)
        )
      }
    )
    let candidateBindings = [
      CandidateActionBinding(candidateID: fixtureCandidateID, action: ownerAction)
    ]
    let releaseGraphBundle = try PlanReleaseSet.buildAll(
      from: graph.evaluate(selectedCandidateActions: candidateBindings),
      candidateActions: candidateBindings
    )
    let releaseActions = try releaseGraphBundle.releaseSets.map { releaseSet in
      try makeAction(
        evidence: evidence,
        facts: facts,
        prerequisites: [ownerAction],
        request: .completeReleaseSetRemove(binding: releaseSet.actionBinding)
      )
    }
    let builtPlan = try ImmutablePlan(
      policyVersion: "policy-1",
      schemaVersion: "schema-1",
      globalFacts: facts,
      evidenceSnapshots: [evidence],
      actions: [ownerAction] + releaseActions,
      releaseGraphBundle: releaseGraphBundle
    )
    plan = builtPlan
    overlay = DecisionOverlay.create(
      plan: builtPlan,
      selectedActionIDs: builtPlan.actions.map(\.id),
      waiverConsents: [],
      userNotes: []
    )
    let epoch = try ExecutionEpochContext(
      epochID: "epoch-release",
      semanticReferenceTimeSeconds: 100,
      issuedAtSeconds: 100,
      deadlineSeconds: 300
    )
    let compound = try #require(builtPlan.releaseGraphManifest?.connectedComponents.first)
    let releaseSetsByGroup = Dictionary(
      uniqueKeysWithValues: builtPlan.releaseSets.map { (RawUTF8Key($0.allocationGroupID), $0) }
    )
    let compoundOwners = Set(
      compound.allocationGroupIDs.flatMap {
        releaseSetsByGroup[RawUTF8Key($0)]?.ownerActionIDs ?? []
      }
    ).sorted()
    let manifestTemplate = ExecutionManifest(
      planHash: builtPlan.planHash,
      overlayHash: testDigest(8),
      epoch: epoch,
      currentCaptureID: testDigest(2),
      executionActionIDs: [ownerAction.id] + releaseActions.map(\.id),
      jitRevalidationActionIDs: [[]] + releaseActions.map { _ in compoundOwners },
      compoundReleaseUnits: [
        CompoundReleaseUnit(
          allocationGroupIDs: compound.allocationGroupIDs,
          ownerActionIDs: compoundOwners
        )
      ],
      currentPolicyBindings: [],
      consentRequirements: [],
      currentBindingHash: testDigest(3)
    )
    let bindingHash = try #require(
      Revalidator.recomputedManifestCurrentBindingHash(manifestTemplate, plan: builtPlan)
    )
    manifest = ExecutionManifest(
      planHash: manifestTemplate.planHash,
      overlayHash: manifestTemplate.overlayHash,
      epoch: manifestTemplate.epoch,
      currentCaptureID: manifestTemplate.currentCaptureID,
      executionActionIDs: manifestTemplate.executionActionIDs,
      jitRevalidationActionIDs: manifestTemplate.jitRevalidationActionIDs,
      compoundReleaseUnits: manifestTemplate.compoundReleaseUnits,
      currentPolicyBindings: manifestTemplate.currentPolicyBindings,
      consentRequirements: manifestTemplate.consentRequirements,
      currentBindingHash: bindingHash
    )
    unitID = .compoundRelease(compound.allocationGroupIDs)
    execution = ReleasePostverificationExecutionBinding(
      executionBindingHash: self.manifest.currentBindingHash,
      applyClaimIDHash: testDigest(0x71),
      preparationGeneration: 1,
      epoch: self.manifest.epoch,
      jitOneShotNonce: Data(repeating: 0x72, count: 32),
      planCaptureID: builtPlan.globalFacts.captureID,
      wholePlanCaptureID: self.manifest.currentCaptureID,
      jitCaptureID: testDigest(4),
      freshnessLimitSeconds: self.manifest.epoch.deadlineSeconds
        - self.manifest.epoch.issuedAtSeconds
    )
    topology = ReleaseAllocationTopologyExpectation(
      try #require(builtPlan.releaseSets.first).topologyExpectation
    )
  }

  func ownerLocator(
    rootSeal: ReleaseDescriptorNamespaceSeal? = nil,
    parentOverride: AuthorizedReleaseNamespaceComponent? = nil,
    expectedIdentity: ObjectIdentity? = nil
  ) -> ReleasePostverificationOwnerLocator {
    let parent =
      parentOverride
      ?? AuthorizedReleaseNamespaceComponent(
        rawNameFromParent: Data(namespaceName.utf8),
        descriptor: namespaceDescriptor,
        authorizedSeal: authorizedParentSeal
      )
    return ReleasePostverificationOwnerLocator(
      actionID: actionID,
      candidateID: candidateID,
      expectedIdentity: expectedIdentity ?? ownerIdentity,
      namespace: [
        AuthorizedReleaseNamespaceComponent(
          rawNameFromParent: nil,
          descriptor: rootDescriptor,
          authorizedSeal: rootSeal ?? authorizedRootSeal
        ),
        parent,
      ],
      rawLeafName: Data("owner".utf8)
    )
  }

  func groupExpectation(id: String? = nil) -> ReleasePostverificationGroupExpectation {
    let resolvedID = id ?? groupID
    let releaseSet = plan.releaseSets.first {
      RawUTF8Key($0.allocationGroupID) == RawUTF8Key(resolvedID)
    }!
    return ReleasePostverificationGroupExpectation(
      allocationGroupID: resolvedID,
      topology: ReleaseAllocationTopologyExpectation(releaseSet.topologyExpectation),
      ownerActionIDs: releaseSet.ownerActionIDs.sorted()
    )
  }

  func manifestReplacingCurrentBindingHash(
    _ bindingHash: PolicyDigest
  ) -> ExecutionManifest {
    ExecutionManifest(
      planHash: manifest.planHash,
      overlayHash: manifest.overlayHash,
      epoch: manifest.epoch,
      currentCaptureID: manifest.currentCaptureID,
      executionActionIDs: manifest.executionActionIDs,
      jitRevalidationActionIDs: manifest.jitRevalidationActionIDs,
      compoundReleaseUnits: manifest.compoundReleaseUnits,
      currentPolicyBindings: manifest.currentPolicyBindings,
      consentRequirements: manifest.consentRequirements,
      currentBindingHash: bindingHash
    )
  }

  func request(
    owner: ReleasePostverificationOwnerLocator? = nil,
    actualOwners: [ReleasePostverificationOwnerLocator]? = nil,
    authorizedOwner: ReleasePostverificationOwnerLocator? = nil
  ) throws -> ReleasePostverificationComponentRequest {
    let resolvedOwners = actualOwners ?? [owner ?? ownerLocator()]
    let authority = try EngineReleasePostverificationManifestAuthority(
      testingClaimedManifest: manifest,
      plan: plan
    )
    let handle = try authority.authorize(
      jitClaim: try jitClaim(),
      descriptorLocators: authorizedOwner.map { [$0] } ?? resolvedOwners
    )
    return ReleasePostverificationComponentRequest(
      componentHandle: handle,
      owners: resolvedOwners
    )
  }

  func jitClaim(
    applyClaimIDHash: PolicyDigest = testDigest(0x71),
    unitID overrideUnitID: ExecutionUnitID? = nil,
    actionIDs: [ActionID]? = nil,
    releaseGroupIDs: [String]? = nil,
    currentBindingHash: PolicyDigest? = nil,
    preparationGeneration: UInt64 = 1,
    epoch: ExecutionEpochContext? = nil,
    oneShotNonce: Data = Data(repeating: 0x72, count: 32),
    planCaptureID: PolicyDigest? = nil,
    wholePlanCaptureID: PolicyDigest? = nil,
    jitCaptureID: PolicyDigest = testDigest(4)
  ) throws -> EngineJITExecutionClaim {
    let resolvedUnitID = overrideUnitID ?? unitID
    let derived = try EngineJITExecutionUnitBinding.derive(
      unitID: resolvedUnitID,
      plan: plan,
      manifest: manifest
    )
    let overridden = EngineJITExecutionUnitBinding(
      unitID: resolvedUnitID,
      actionIDs: actionIDs ?? derived.actionIDs,
      releaseGroupIDs: releaseGroupIDs ?? derived.releaseGroupIDs
    )
    return EngineJITExecutionClaim.issueForTesting(
      record: EngineJITExecutionClaimRecord(
        applyClaimIDHash: applyClaimIDHash,
        unit: overridden,
        currentBindingHash: currentBindingHash ?? manifest.currentBindingHash,
        preparationGeneration: preparationGeneration,
        epoch: epoch ?? manifest.epoch,
        oneShotNonce: oneShotNonce,
        planCaptureID: planCaptureID ?? plan.globalFacts.captureID,
        wholePlanCaptureID: wholePlanCaptureID ?? manifest.currentCaptureID,
        jitCaptureID: jitCaptureID
      ))
  }

  func jitRequest(
    unitID overrideUnitID: ExecutionUnitID? = nil,
    actionIDs: [ActionID]? = nil,
    releaseGroupIDs: [String]? = nil,
    preparationGeneration: UInt64 = 1,
    oneShotNonce: Data = Data(repeating: 0x72, count: 32),
    applyClaimIDHash: PolicyDigest = testDigest(0x71)
  ) throws -> JITRevalidationRequest {
    let resolvedUnitID = overrideUnitID ?? unitID
    let derived = try EngineJITExecutionUnitBinding.derive(
      unitID: resolvedUnitID,
      plan: plan,
      manifest: manifest
    )
    let decisionOverlay = DecisionOverlay.create(
      plan: plan,
      selectedActionIDs: plan.actions.map(\.id),
      waiverConsents: [],
      userNotes: []
    )
    let validatedOverlay = try DecisionOverlayValidator.validate(
      decisionOverlay,
      against: plan
    )
    return JITRevalidationRequest(
      testingPlan: plan,
      validatedOverlay: validatedOverlay,
      manifest: manifest,
      unitID: resolvedUnitID,
      actionIDs: actionIDs ?? derived.actionIDs,
      releaseGroupIDs: releaseGroupIDs ?? derived.releaseGroupIDs,
      preparationGeneration: preparationGeneration,
      oneShotNonce: oneShotNonce,
      applyClaimIDHash: applyClaimIDHash
    )
  }

  func currentJITReport(
    for request: JITRevalidationRequest,
    captureID: PolicyDigest = testDigest(4)
  ) -> JITRevalidationReport {
    JITRevalidationReport(
      captureID: captureID,
      oneShotNonce: request.oneShotNonce,
      actionOutcomes: request.actionIDs.sorted().map {
        ActionRevalidationOutcome(actionID: $0, findings: [])
      },
      globalFindings: []
    )
  }

  func currentSnapshot(
    captureID: PolicyDigest,
    referenceTimeSeconds: Int64,
    actionIDs: [ActionID]? = nil
  ) -> CurrentRevalidationSnapshot {
    let selected = actionIDs.map(Set.init)
    return CurrentRevalidationSnapshot(
      captureID: captureID,
      actions: plan.actions.filter { selected?.contains($0.id) ?? true }.map {
        currentEvidence(
          $0,
          captureID: captureID,
          referenceTimeSeconds: referenceTimeSeconds
        )
      },
      releaseTopologies: plan.releaseSets.map {
        CurrentReleaseTopology(
          allocationGroupID: $0.allocationGroupID,
          topology: .known($0.topologyExpectation)
        )
      },
      invariants: CurrentPlanInvariants(
        duplicateSurvivorsPreserved: .known(true),
        terminalNamespacesExclusive: .known(true)
      )
    )
  }

  func matchingFinalDescriptorEvidence(
    _ request: FinalDescriptorPreflightRequest
  ) -> FinalDescriptorEvidenceSnapshot {
    let target = request.target
    return FinalDescriptorEvidenceSnapshot(
      targetIdentity: .known(target.expectedIdentity),
      targetAccessPolicy: .known(target.expectedTargetAccessPolicy),
      targetContent: .known(target.expectedContent),
      root: CurrentNamespaceComponent(
        relativePath: nil,
        identity: .known(target.expectedRootIdentity),
        seal: .known(target.expectedRootSeal)
      ),
      parents: target.expectedParentIdentities.indices.map { index in
        CurrentNamespaceComponent(
          relativePath: try? RawTargetPath(
            components: Array(target.targetPath.components.prefix(index + 1))
          ),
          identity: .known(target.expectedParentIdentities[index]),
          seal: .known(target.expectedParentSeals[index])
        )
      }
    )
  }

  func ownerOperation() throws -> ExecutionAdapterOperation {
    let action = try #require(plan.actions.first(where: { $0.id == self.actionID }))
    guard case .genericRemove(let contract) = action.prototype.adapterContract else {
      throw ReleasePostverificationLocatorError.operationMembershipMismatch
    }
    return .genericRemove(BoundMutationTarget(action: action), contract)
  }

  private func currentEvidence(
    _ action: ActionDefinition,
    captureID: PolicyDigest,
    referenceTimeSeconds: Int64
  ) -> CurrentActionEvidence {
    let namespace = action.prototype.namespaceBinding
    return CurrentActionEvidence(
      actionID: action.id,
      targetIdentity: .known(action.prototype.protectedProperties.identity.expectedIdentity),
      targetContent: .known(action.prototype.protectedProperties.content.expectedBaseline),
      targetAccessPolicy: .known(
        action.prototype.protectedProperties.accessPolicy.requiredBaseline
      ),
      coverage: .known(action.evidence.coverage),
      collectorStatus: action.evidence.collectorStatus,
      activity: action.evidence.activity,
      explicitProtection: action.evidence.explicitProtection,
      providerState: action.evidence.providerState,
      recoverability: action.evidence.recoverability,
      dependencyState: action.evidence.dependencyState,
      freshPolicyEvidence: .known(
        retimedPolicyEvidence(
          action,
          captureID: captureID,
          referenceTimeSeconds: referenceTimeSeconds
        )),
      root: CurrentNamespaceComponent(
        relativePath: nil,
        identity: .known(namespace.rootIdentity),
        seal: .known(namespace.rootSeal)
      ),
      parents: namespace.parentChain.map {
        CurrentNamespaceComponent(
          relativePath: $0.relativePath,
          identity: .known($0.identity),
          seal: .known($0.seal)
        )
      },
      gitWorktree: .absent
    )
  }

  private func retimedPolicyEvidence(
    _ action: ActionDefinition,
    captureID: PolicyDigest,
    referenceTimeSeconds: Int64
  ) -> FreshPolicyEvidence {
    let source = action.evidence
    let planFacts = plan.globalFacts
    let facts = FrozenGlobalFacts(
      captureID: captureID,
      profile: planFacts.profile,
      configuration: planFacts.configuration,
      coverage: planFacts.coverage,
      semanticReferenceTimeSeconds: referenceTimeSeconds,
      policyVersion: planFacts.policyVersion,
      schemaVersion: planFacts.schemaVersion
    )
    let evidence = try! FrozenEvidenceSnapshot(
      captureID: captureID,
      globalFactsHash: facts.globalFactsHash,
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
      semanticReviewFacts: source.semanticReviewFacts,
      accessPolicy: source.accessPolicy,
      contentProtection: source.contentProtection,
      aclDigest: source.aclDigest,
      targetMountIdentity: source.targetMountIdentity,
      removalForceRequirement: source.removalForceRequirement,
      quarantineCapability: source.quarantineCapability,
      gitWorktree: source.gitWorktree,
      adapterScope: source.adapterScope,
      additionalAdapterScopes: source.additionalAdapterScopes,
      classificationClaims: source.classificationClaims,
      semanticReferenceTimeSeconds: referenceTimeSeconds,
      policyVersion: source.policyVersion,
      schemaVersion: source.schemaVersion
    )
    return FreshPolicyEvidence(evidence: evidence, globalFacts: facts)
  }

  func removeOwner() throws {
    try FileManager.default.removeItem(at: owner)
  }

  func replaceOwner() throws {
    try removeOwner()
    try Data("replacement".utf8).write(to: owner)
  }

  func replaceNamespaceWithEmptyDirectory() throws {
    let retained = root.appendingPathComponent("retained-original")
    try FileManager.default.moveItem(at: namespace, to: retained)
    try FileManager.default.createDirectory(at: namespace, withIntermediateDirectories: false)
  }

  func replaceRootWithEmptyTree() throws {
    let retained = container.appendingPathComponent("retained-root")
    try FileManager.default.moveItem(at: root, to: retained)
    try FileManager.default.createDirectory(
      at: namespace,
      withIntermediateDirectories: true
    )
  }

  func changeNamespaceMode(to mode: mode_t) throws {
    guard Darwin.fchmod(namespaceDescriptor, mode) == 0 else {
      throw POSIXError(.init(rawValue: errno) ?? .EIO)
    }
  }

  func cleanUp() {
    _ = Darwin.close(rootDescriptor)
    _ = Darwin.close(namespaceDescriptor)
    try? FileManager.default.removeItem(at: container)
  }

  private static func identity(
    parentDescriptor: Int32,
    leaf: Data
  ) throws -> ObjectIdentity {
    var value = stat()
    var terminated = [UInt8](leaf)
    terminated.append(0)
    let result = terminated.withUnsafeBufferPointer { buffer in
      Darwin.fstatat(
        parentDescriptor,
        UnsafeRawPointer(buffer.baseAddress!).assumingMemoryBound(to: CChar.self),
        &value,
        AT_SYMLINK_NOFOLLOW
      )
    }
    guard result == 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
    return ObjectIdentity(
      device: UInt64(UInt32(bitPattern: value.st_dev)),
      object: UInt64(value.st_ino),
      generation: .known(UInt64(value.st_gen)),
      type: .regularFile
    )
  }

  private static func policySeal(
    _ access: ReleaseDescriptorAccessSeal
  ) -> NamespaceSealEvidence {
    NamespaceSealEvidence(
      trustedNamespace: .ownerPrivate,
      accessPolicy: .known("owner-private"),
      aclDigest: .known(access.aclDigest),
      providerBoundary: .known(.local),
      mountIdentity: .known(access.mountIdentity.base64EncodedString())
    )
  }
}

private func testCore(
  _ source: RecordingReleaseTopologySource,
  descriptorProbe: any ReleasePostverificationDescriptorProbing =
    POSIXReleasePostverificationDescriptorProbe()
) -> DescriptorBoundReleasePostverificationCore {
  DescriptorBoundReleasePostverificationCore(
    topologyCollector: source.collector,
    descriptorProbe: descriptorProbe,
    nowSeconds: { 200 },
    nonceGenerator: { Data(repeating: 9, count: 32) }
  )
}

private func testDigest(_ byte: UInt8) -> PolicyDigest {
  try! PolicyDigest(bytes: Data(repeating: byte, count: 32))
}
