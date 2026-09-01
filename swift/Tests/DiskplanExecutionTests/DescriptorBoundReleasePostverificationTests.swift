import Darwin
import DiskplanPolicy
import Foundation
import Testing

@testable import DiskplanExecution

@Test
func descriptorBoundReleaseRequiresTypedTopologyProof() async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let topology = RecordingReleaseTopologySource(mode: .released)
  let core = DescriptorBoundReleasePostverificationCore(topologySource: topology)
  let frozen = try core.freeze(fixture.request())

  try fixture.removeOwner()
  let report = await core.postverify(frozen)

  #expect(report.ownerTransitions[fixture.actionID] == .missing)
  guard case .allocationGroupReleased(let proof) = report.groups.first?.outcome else {
    Issue.record("expected a typed allocationGroupReleased topology proof")
    return
  }
  #expect(proof.allocationGroupID == fixture.groupID)
  #expect(proof.expectedTopology == fixture.topology)
  #expect(proof.ownerActionIDs == [fixture.actionID])
}

@Test
func missingLeafInReplacementNamespaceCannotSpoofRelease() async throws {
  let fixture = try ReleasePostverificationFixture(namespaceName: "original")
  defer { fixture.cleanUp() }
  let topology = RecordingReleaseTopologySource(mode: .released)
  let core = DescriptorBoundReleasePostverificationCore(topologySource: topology)
  let frozen = try core.freeze(fixture.request())

  try fixture.replaceNamespaceWithEmptyDirectory()
  let report = await core.postverify(frozen)

  #expect(
    report.groups.first?.outcome
      == .rejected(.ownerSlotStillReferencesExpectedObject(fixture.actionID))
  )
  #expect(await topology.requestCount == 0)
}

@Test
func missingLeafInReplacementRootCannotSpoofRelease() async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let topology = RecordingReleaseTopologySource(mode: .released)
  let core = DescriptorBoundReleasePostverificationCore(topologySource: topology)
  let frozen = try core.freeze(fixture.request())

  try fixture.replaceRootWithEmptyTree()
  let report = await core.postverify(frozen)

  #expect(
    report.groups.first?.outcome
      == .rejected(.ownerSlotStillReferencesExpectedObject(fixture.actionID))
  )
  #expect(await topology.requestCount == 0)
}

@Test
func replacementOwnerSlotIsATransitionButStillNeedsTopologyProof() async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let topology = RecordingReleaseTopologySource(mode: .missing)
  let core = DescriptorBoundReleasePostverificationCore(topologySource: topology)
  let frozen = try core.freeze(fixture.request())

  try fixture.replaceOwner()
  let report = await core.postverify(frozen)

  guard case .identityChanged(let current) = report.ownerTransitions[fixture.actionID] else {
    Issue.record("expected replacement identity transition")
    return
  }
  #expect(current != fixture.ownerIdentity)
  #expect(report.groups.first?.outcome == .rejected(.topologyMissing(fixture.groupID)))
}

@Test
func namespaceAccessMutationIsNotConfusedWithChildEntryChurn() async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let topology = RecordingReleaseTopologySource(mode: .released)
  let core = DescriptorBoundReleasePostverificationCore(topologySource: topology)
  let frozen = try core.freeze(fixture.request())

  try fixture.removeOwner()
  try fixture.changeNamespaceMode(to: 0o700)
  let report = await core.postverify(frozen)

  #expect(
    report.groups.first?.outcome
      == .rejected(.namespaceAccessMismatch(fixture.actionID, .parent))
  )
  #expect(await topology.requestCount == 0)
}

@Test(
  arguments: [
    ScriptedNamespaceFailure.missing,
    .unreadable,
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
  let core = DescriptorBoundReleasePostverificationCore(
    topologySource: topology,
    descriptorProbe: descriptorProbe
  )
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
  case .identityMismatch:
    expected = .namespaceIdentityMismatch(fixture.actionID, .root)
  case .accessMismatch:
    expected = .namespaceAccessMismatch(fixture.actionID, .root)
  }
  #expect(report.groups.first?.outcome == .rejected(expected))
  #expect(await topology.requestCount == 0)
}

@Test
func topologyCollectorFailureIsNotReportedAsMissingOrUnreadable() async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let topology = RecordingReleaseTopologySource(mode: .throwFailure)
  let core = DescriptorBoundReleasePostverificationCore(topologySource: topology)
  let frozen = try core.freeze(fixture.request())

  try fixture.removeOwner()
  let report = await core.postverify(frozen)

  guard
    case .rejected(.topologyCollectorFailed(let groupID, let failure)) =
      report.groups.first?.outcome
  else {
    Issue.record("expected a distinct topology collector failure")
    return
  }
  #expect(groupID == fixture.groupID)
  #expect(failure.collector == "release-topology-source")
}

@Test
func connectedComponentProbesSharedOwnerAtMostOnce() async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let descriptorProbe = CountingReleaseDescriptorProbe()
  let topology = RecordingReleaseTopologySource(mode: .released)
  let core = DescriptorBoundReleasePostverificationCore(
    topologySource: topology,
    descriptorProbe: descriptorProbe
  )
  let secondGroup = fixture.groupExpectation(id: "allocation-group-b")
  let frozen = try core.freeze(
    fixture.request(groups: [fixture.groupExpectation(), secondGroup])
  )
  descriptorProbe.resetOwnerSlotCount()

  try fixture.removeOwner()
  let report = await core.postverify(frozen)

  #expect(descriptorProbe.ownerSlotCount == 1)
  #expect(await topology.requestCount == 2)
  #expect(report.groups.count == 2)
  #expect(
    report.groups.allSatisfy {
      if case .allocationGroupReleased = $0.outcome { return true }
      return false
    }
  )
}

@Test
func duplicateOwnerCannotEnterAConnectedComponent() throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let core = DescriptorBoundReleasePostverificationCore(
    topologySource: RecordingReleaseTopologySource(mode: .released)
  )
  let owner = fixture.ownerLocator()
  let request = ReleasePostverificationComponentRequest(
    owners: [owner, owner],
    groups: [fixture.groupExpectation()]
  )

  #expect(
    throws: ReleasePostverificationFreezeError.duplicateOwner(fixture.actionID)
  ) {
    try core.freeze(request)
  }
}

@Test
func frozenComponentCanBePostverifiedOnlyOnce() async throws {
  let fixture = try ReleasePostverificationFixture()
  defer { fixture.cleanUp() }
  let topology = RecordingReleaseTopologySource(mode: .released)
  let core = DescriptorBoundReleasePostverificationCore(topologySource: topology)
  let frozen = try core.freeze(fixture.request())
  try fixture.removeOwner()

  let first = await core.postverify(frozen)
  let second = await core.postverify(frozen)

  guard case .allocationGroupReleased = first.groups.first?.outcome else {
    Issue.record("expected first verification to succeed")
    return
  }
  #expect(second.groups.first?.outcome == .rejected(.leaseAlreadyConsumed))
  #expect(await topology.requestCount == 1)
}

private enum TestTopologySourceError: Error { case failed }

private actor RecordingReleaseTopologySource: ReleasePostverificationTopologySource {
  enum Mode: Sendable {
    case released
    case missing
    case retained
    case throwFailure
  }

  let mode: Mode
  private(set) var requests: [ReleasePostverificationTopologyRequest] = []
  var requestCount: Int { requests.count }

  init(mode: Mode) { self.mode = mode }

  func collectReleaseTopology(
    for request: ReleasePostverificationTopologyRequest
  ) async throws -> Observation<CurrentAllocationGroupReleaseTopology> {
    requests.append(request)
    switch mode {
    case .released:
      return .known(
        .allocationGroupReleased(
          AllocationGroupReleasedTopologyProof(
            allocationGroupID: request.allocationGroupID,
            expectedTopology: request.expectedTopology,
            ownerActionIDs: request.owners.map(\.actionID).sorted(),
            captureID: testDigest(240)
          )
        ))
    case .missing:
      return .absent
    case .retained:
      return .known(.allocationGroupStillAllocated)
    case .throwFailure:
      throw TestTopologySourceError.failed
    }
  }
}

private enum ScriptedNamespaceFailure: CaseIterable, Sendable {
  case missing
  case unreadable
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
        ))
    case .accessMismatch:
      guard case .known(let seal) = actual else { return actual }
      return .known(
        ReleaseDescriptorNamespaceSeal(
          identity: seal.identity,
          access: ReleaseDescriptorAccessSeal(
            mode: seal.access.mode ^ 0o100,
            ownerUserID: seal.access.ownerUserID,
            ownerGroupID: seal.access.ownerGroupID,
            flags: seal.access.flags
          )
        ))
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
}

private final class CountingReleaseDescriptorProbe: @unchecked Sendable,
  ReleasePostverificationDescriptorProbing
{
  private let underlying = POSIXReleasePostverificationDescriptorProbe()
  private let lock = NSLock()
  private var storedOwnerSlotCount = 0

  var ownerSlotCount: Int {
    lock.lock()
    defer { lock.unlock() }
    return storedOwnerSlotCount
  }

  func resetOwnerSlotCount() {
    lock.lock()
    storedOwnerSlotCount = 0
    lock.unlock()
  }

  func namespaceSeal(descriptor: Int32) -> Observation<ReleaseDescriptorNamespaceSeal> {
    underlying.namespaceSeal(descriptor: descriptor)
  }

  func ownerSlot(
    parentDescriptor: Int32,
    rawLeafName: Data
  ) -> ReleaseOwnerSlotObservation {
    lock.lock()
    storedOwnerSlotCount += 1
    lock.unlock()
    return underlying.ownerSlot(
      parentDescriptor: parentDescriptor,
      rawLeafName: rawLeafName
    )
  }
}

private final class ReleasePostverificationFixture {
  let container: URL
  let root: URL
  let namespace: URL
  let owner: URL
  let rootDescriptor: Int32
  let namespaceDescriptor: Int32
  let actionID = ActionID(digest: testDigest(7))
  let groupID = "allocation-group-a"
  let candidateID = "candidate-a"
  let ownerIdentity: ObjectIdentity
  let topology: ReleaseAllocationTopologyExpectation

  init(namespaceName: String = "namespace") throws {
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
    ownerIdentity = try Self.identity(
      parentDescriptor: namespaceDescriptor,
      leaf: Data("owner".utf8)
    )
    let ownerPath = try RawTargetPath(components: [Data("owner".utf8)])
    topology = ReleaseAllocationTopologyExpectation(
      allocationGroupID: groupID,
      fileObjects: [
        ReleaseFileTopologyExpectation(
          fileObjectID: "file-object-a",
          owners: [FileOwnerLink(candidateID: candidateID, path: ownerPath)],
          linkCount: .known(1)
        )
      ],
      cloneRefCount: .known(1),
      sharedBytes: .known(4_096),
      snapshotBlocker: .known(false)
    )
  }

  func ownerLocator() -> ReleasePostverificationOwnerLocator {
    ReleasePostverificationOwnerLocator(
      actionID: actionID,
      candidateID: candidateID,
      expectedIdentity: ownerIdentity,
      rootDescriptor: rootDescriptor,
      parentDescriptor: namespaceDescriptor,
      rawLeafName: Data("owner".utf8)
    )
  }

  func groupExpectation(id: String? = nil) -> ReleasePostverificationGroupExpectation {
    let resolvedID = id ?? groupID
    let resolvedTopology = ReleaseAllocationTopologyExpectation(
      allocationGroupID: resolvedID,
      fileObjects: topology.fileObjects,
      cloneRefCount: topology.cloneRefCount,
      sharedBytes: topology.sharedBytes,
      snapshotBlocker: topology.snapshotBlocker
    )
    return ReleasePostverificationGroupExpectation(
      allocationGroupID: resolvedID,
      topology: resolvedTopology,
      ownerActionIDs: [actionID]
    )
  }

  func request(
    groups: [ReleasePostverificationGroupExpectation]? = nil
  ) -> ReleasePostverificationComponentRequest {
    ReleasePostverificationComponentRequest(
      owners: [ownerLocator()],
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
      device: UInt64(value.st_dev),
      object: UInt64(value.st_ino),
      generation: .known(UInt64(value.st_gen)),
      type: .regularFile
    )
  }
}

private func testDigest(_ byte: UInt8) -> PolicyDigest {
  try! PolicyDigest(bytes: Data(repeating: byte, count: 32))
}
