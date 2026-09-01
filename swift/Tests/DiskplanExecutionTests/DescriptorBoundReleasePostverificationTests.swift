import Darwin
import DiskplanPolicy
import Foundation
import Testing

@testable import DiskplanExecution

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
  #expect(receipt.componentID == fixture.execution.componentID)
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

  var wrongIdentity = first.authorizedRootSeal
  wrongIdentity = ReleaseDescriptorNamespaceSeal(
    identity: ObjectIdentity(
      device: wrongIdentity.identity.device,
      object: wrongIdentity.identity.object &+ 1,
      generation: wrongIdentity.identity.generation,
      type: wrongIdentity.identity.type
    ),
    access: wrongIdentity.access
  )
  #expect(
    throws: ReleasePostverificationFreezeError.namespaceIdentityMismatch(
      first.actionID, .root
    )
  ) {
    try core.freeze(first.request(owner: first.ownerLocator(rootSeal: wrongIdentity)))
  }

  let wrongAccess = ReleaseDescriptorNamespaceSeal(
    identity: first.authorizedRootSeal.identity,
    access: ReleaseDescriptorAccessSeal(
      mode: first.authorizedRootSeal.access.mode,
      ownerUserID: first.authorizedRootSeal.access.ownerUserID,
      ownerGroupID: first.authorizedRootSeal.access.ownerGroupID,
      authorizationFlags: first.authorizedRootSeal.access.authorizationFlags,
      aclDigest: testDigest(199),
      mountIdentity: first.authorizedRootSeal.access.mountIdentity
    )
  )
  #expect(
    throws: ReleasePostverificationFreezeError.namespaceAccessMismatch(
      first.actionID, .root
    )
  ) {
    try core.freeze(first.request(owner: first.ownerLocator(rootSeal: wrongAccess)))
  }

  let foreignParent = AuthorizedReleaseNamespaceComponent(
    rawNameFromParent: Data(first.namespaceName.utf8),
    descriptor: second.namespaceDescriptor,
    authorizedSeal: second.authorizedParentSeal
  )
  #expect(
    throws: ReleasePostverificationFreezeError.namespaceContainmentMismatch(
      first.actionID, .parentChain(index: 0)
    )
  ) {
    try core.freeze(
      first.request(
        owner: first.ownerLocator(parentOverride: foreignParent)
      )
    )
  }

  let wrongLeafIdentity = ObjectIdentity(
    device: first.ownerIdentity.device,
    object: first.ownerIdentity.object &+ 1,
    generation: first.ownerIdentity.generation,
    type: first.ownerIdentity.type
  )
  #expect(
    throws: ReleasePostverificationFreezeError.targetIdentityMismatch(first.actionID)
  ) {
    try core.freeze(
      first.request(owner: first.ownerLocator(expectedIdentity: wrongLeafIdentity))
    )
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
  let fixture = try ReleasePostverificationFixture()
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
func namespaceAccessMutationIsDistinctFromChildEntryChurn() async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let topology = RecordingReleaseTopologySource(mode: .released)
  let core = testCore(topology)
  let frozen = try core.freeze(fixture.request())

  try fixture.removeOwner()
  try fixture.changeNamespaceMode(to: 0o700)
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
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let second = fixture.groupExpectation(id: "allocation-group-b")
  let topology = RecordingReleaseTopologySource(
    mode: .groupStillAllocated("allocation-group-b")
  )
  let core = testCore(topology)
  let frozen = try core.freeze(
    fixture.request(groups: [fixture.groupExpectation(), second])
  )
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
func topologyReceivesPerCallCLOEXECBorrowedDescriptorsAndReuseIsNotClosed() async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let topology = RecordingReleaseTopologySource(mode: .closeAndReuseFirstDescriptor)
  let core = testCore(topology)
  let frozen = try core.freeze(fixture.request())
  let componentDescriptors = frozen.ownedDescriptorValues
  try fixture.removeOwner()

  let report = await core.postverify(frozen)

  guard
    case .rejected(.topologyCollectorFailed(let failure)) =
      report.groups.first?.outcome
  else {
    Issue.record("expected borrowed descriptor ownership violation")
    return
  }
  #expect(failure.code == "borrowed-descriptor-ownership-violated")
  let borrowedFlags = await topology.borrowedDescriptorFlags
  #expect(!borrowedFlags.isEmpty)
  #expect(borrowedFlags.allSatisfy { $0 & FD_CLOEXEC != 0 })
  #expect(await topology.ownerships.allSatisfy { $0 == .borrowedUntilTopologyCallReturns })
  guard let reusedDescriptor = await topology.reusedDescriptor else {
    Issue.record("expected descriptor reuse fixture")
    return
  }
  var value = stat()
  #expect(Darwin.fstat(reusedDescriptor, &value) == 0)
  _ = Darwin.close(reusedDescriptor)
  for descriptor in componentDescriptors {
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
    throws: ReleasePostverificationFreezeError.duplicateOwner(fixture.actionID)
  ) {
    try core.freeze(
      ReleasePostverificationComponentRequest(
        execution: fixture.execution,
        owners: [owner, owner],
        groups: [fixture.groupExpectation()]
      )
    )
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

private actor RecordingReleaseTopologySource: ReleasePostverificationTopologySource {
  enum Mode: Sendable {
    case released
    case missing
    case throwFailure
    case invalidCapture(InvalidCaptureMode)
    case groupStillAllocated(String)
    case rawFileObjectOverride(Data)
    case closeAndReuseFirstDescriptor
  }

  let mode: Mode
  private(set) var requests: [ReleasePostverificationTopologyRequest] = []
  private(set) var borrowedDescriptorFlags: [Int32] = []
  private(set) var ownerships: [BorrowedReleaseDescriptorOwnership] = []
  private(set) var reusedDescriptor: Int32?
  var requestCount: Int { requests.count }

  init(mode: Mode) { self.mode = mode }

  func collectReleaseTopology(
    for request: ReleasePostverificationTopologyRequest
  ) async throws -> Observation<CurrentReleaseTopologyCapture> {
    requests.append(request)
    let descriptors = request.owners.flatMap(\.namespaceDescriptors)
    ownerships.append(contentsOf: descriptors.map(\.ownership))
    borrowedDescriptorFlags.append(
      contentsOf: descriptors.map { Darwin.fcntl($0.rawValue, F_GETFD) }
    )
    if case .throwFailure = mode { throw TestTopologySourceError.failed }
    if case .missing = mode { return .absent }
    if case .closeAndReuseFirstDescriptor = mode, let first = descriptors.first {
      _ = Darwin.close(first.rawValue)
      reusedDescriptor = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
    }

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

private enum ScriptedNamespaceFailure: CaseIterable, Sendable {
  case missing
  case unreadable
  case collectorFailure
  case identityMismatch
  case accessMismatch
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

private final class ReleasePostverificationFixture {
  let container: URL
  let root: URL
  let namespace: URL
  let owner: URL
  let namespaceName: String
  let rootDescriptor: Int32
  let namespaceDescriptor: Int32
  let actionID = ActionID(digest: testDigest(7))
  let groupID = "allocation-group-a"
  let candidateID = "candidate-a"
  let ownerIdentity: ObjectIdentity
  let topology: ReleaseAllocationTopologyExpectation
  let authorizedRootSeal: ReleaseDescriptorNamespaceSeal
  let authorizedParentSeal: ReleaseDescriptorNamespaceSeal
  let execution: ReleasePostverificationExecutionBinding

  init(
    namespaceName: String = "namespace",
    fileObjectID: String = "file-object-a"
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
    let ownerPath = try RawTargetPath(components: [Data("owner".utf8)])
    topology = ReleaseAllocationTopologyExpectation(
      allocationGroupID: groupID,
      fileObjects: [
        ReleaseFileTopologyExpectation(
          fileObjectID: fileObjectID,
          owners: [FileOwnerLink(candidateID: candidateID, path: ownerPath)],
          linkCount: .known(1)
        )
      ],
      cloneRefCount: .known(1),
      sharedBytes: .known(4_096),
      snapshotBlocker: .known(false)
    )
    execution = ReleasePostverificationExecutionBinding(
      executionBindingHash: testDigest(3),
      componentID: testDigest(4),
      epoch: try ExecutionEpochContext(
        epochID: "epoch-release",
        semanticReferenceTimeSeconds: 100,
        issuedAtSeconds: 100,
        deadlineSeconds: 300
      ),
      planCaptureID: testDigest(1),
      jitCaptureID: testDigest(2),
      freshnessLimitSeconds: 20
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
    return ReleasePostverificationGroupExpectation(
      allocationGroupID: resolvedID,
      topology: ReleaseAllocationTopologyExpectation(
        allocationGroupID: resolvedID,
        fileObjects: topology.fileObjects,
        cloneRefCount: topology.cloneRefCount,
        sharedBytes: topology.sharedBytes,
        snapshotBlocker: topology.snapshotBlocker
      ),
      ownerActionIDs: [actionID]
    )
  }

  func request(
    owner: ReleasePostverificationOwnerLocator? = nil,
    groups: [ReleasePostverificationGroupExpectation]? = nil
  ) -> ReleasePostverificationComponentRequest {
    ReleasePostverificationComponentRequest(
      execution: execution,
      owners: [owner ?? ownerLocator()],
      groups: groups ?? [groupExpectation()]
    )
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
}

private func testCore(
  _ source: RecordingReleaseTopologySource,
  descriptorProbe: any ReleasePostverificationDescriptorProbing =
    POSIXReleasePostverificationDescriptorProbe()
) -> DescriptorBoundReleasePostverificationCore {
  DescriptorBoundReleasePostverificationCore(
    topologySource: source,
    descriptorProbe: descriptorProbe,
    nowSeconds: { 200 },
    nonceGenerator: { Data(repeating: 9, count: 32) }
  )
}

private func testDigest(_ byte: UInt8) -> PolicyDigest {
  try! PolicyDigest(bytes: Data(repeating: byte, count: 32))
}
