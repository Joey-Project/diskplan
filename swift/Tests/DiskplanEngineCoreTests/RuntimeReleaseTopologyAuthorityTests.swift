import Darwin
import DiskplanMacOS
import DiskplanPolicy
import Foundation
import Testing

@testable import DiskplanEngineCore

private enum ReleaseTopologyTestError: Error {
  case filesystem(Int32)
  case materializationPolicy
  case identity
}

private final class RealReleaseTopologyFixture {
  let rootURL: URL
  let rootDescriptor: Int32
  let firstDescriptor: Int32
  let hardlinkDescriptor: Int32
  let secondDescriptor: Int32
  let rootIdentity: RuntimeReleaseFileObjectIdentity
  let firstIdentity: RuntimeReleaseFileObjectIdentity
  let secondIdentity: RuntimeReleaseFileObjectIdentity

  init(policy: NoMaterializationPolicy) throws {
    rootURL = FileManager.default.temporaryDirectory.appendingPathComponent(
      "diskplan-release-topology-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
    let first = rootURL.appendingPathComponent("first")
    let hardlink = rootURL.appendingPathComponent("hardlink")
    let second = rootURL.appendingPathComponent("second")
    try Data("first".utf8).write(to: first, options: .withoutOverwriting)
    try Data("second".utf8).write(to: second, options: .withoutOverwriting)
    guard Darwin.link(first.path, hardlink.path) == 0 else {
      throw ReleaseTopologyTestError.filesystem(errno)
    }
    rootDescriptor = open(rootURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    firstDescriptor = open(first.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    hardlinkDescriptor = open(hardlink.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    secondDescriptor = open(second.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard rootDescriptor >= 0, firstDescriptor >= 0, hardlinkDescriptor >= 0,
      secondDescriptor >= 0
    else { throw ReleaseTopologyTestError.filesystem(errno) }
    rootIdentity = try runtimeIdentity(rootDescriptor, policy: policy)
    firstIdentity = try runtimeIdentity(firstDescriptor, policy: policy)
    secondIdentity = try runtimeIdentity(secondDescriptor, policy: policy)
  }

  deinit {
    if rootDescriptor >= 0 { close(rootDescriptor) }
    if firstDescriptor >= 0 { close(firstDescriptor) }
    if hardlinkDescriptor >= 0 { close(hardlinkDescriptor) }
    if secondDescriptor >= 0 { close(secondDescriptor) }
    try? FileManager.default.removeItem(at: rootURL)
  }
}

@Test func sealedAuthorityCollectsRealHardlinkDescriptorsAndCannotReplayLease() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let setup = try hardlinkSetup(fixture: fixture)
  let authority = testAuthority(kernel: nonCloneKernel(snapshot: .known(false)))
  let lease = try authority.bind(
    plan: setup.plan,
    executionEpochNonce: UUID(),
    validForNanoseconds: 100,
    policy: policy,
    owners: setup.descriptors,
    volumes: [
      BoundRuntimeReleaseVolumeDescriptor(
        expectedDevice: fixture.rootIdentity.device,
        rootFileDescriptor: fixture.rootDescriptor)
    ]
  )

  let report = try authority.collect(lease)

  #expect(report.collection == .known(true))
  #expect(report.topologyMatchesExpected == .known(true))
  #expect(report.seal.fileObjects.first?.linkCount == .known(2))
  #expect(report.seal.fileObjects.first?.ownerClosure == .known(true))
  #expect(report.seal.groups.first?.conditionalSharedReclaimCredit == nil)
  #expect(report.seal.components.first?.actionIDsAtMostOnce == [setup.actionID])
  #expect(throws: RuntimeReleaseTopologyAuthorityError.descriptorLeaseReplayed) {
    try authority.collect(lease)
  }
}

@Test func exactDescriptorSetsAndOneShotFreshReceiptAreRequired() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let setup = try hardlinkSetup(fixture: fixture)
  let authority = testAuthority(kernel: nonCloneKernel(snapshot: .known(false)))
  let volume = BoundRuntimeReleaseVolumeDescriptor(
    expectedDevice: fixture.rootIdentity.device,
    rootFileDescriptor: fixture.rootDescriptor)

  #expect(throws: RuntimeReleaseTopologyAuthorityError.descriptorSetMismatch) {
    try authority.bind(
      plan: setup.plan,
      executionEpochNonce: UUID(),
      validForNanoseconds: 100,
      policy: policy,
      owners: Array(setup.descriptors.dropLast()),
      volumes: [volume]
    )
  }
  #expect(throws: RuntimeReleaseTopologyAuthorityError.descriptorSetMismatch) {
    try authority.bind(
      plan: setup.plan,
      executionEpochNonce: UUID(),
      validForNanoseconds: 100,
      policy: policy,
      owners: setup.descriptors + [setup.descriptors[0]],
      volumes: [volume]
    )
  }

  let executionEpochNonce = UUID()
  _ = try authority.bind(
    plan: setup.plan,
    executionEpochNonce: executionEpochNonce,
    validForNanoseconds: 100,
    policy: policy,
    owners: setup.descriptors,
    volumes: [volume]
  )
  #expect(throws: RuntimeReleaseTopologyAuthorityError.captureReceiptReplayed) {
    try authority.bind(
      plan: setup.plan,
      executionEpochNonce: executionEpochNonce,
      validForNanoseconds: 100,
      policy: policy,
      owners: setup.descriptors,
      volumes: [volume]
    )
  }
}

@Test func staleLeaseAndProviderIncompleteEvidenceFailClosed() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let setup = try hardlinkSetup(fixture: fixture)
  let clock = TestMonotonicClock(now: 100)
  let authority = testAuthority(
    clock: clock,
    kernel: nonCloneKernel(snapshot: .known(false)))
  let volume = BoundRuntimeReleaseVolumeDescriptor(
    expectedDevice: fixture.rootIdentity.device,
    rootFileDescriptor: fixture.rootDescriptor)

  let staleLease = try authority.bind(
    plan: setup.plan,
    executionEpochNonce: UUID(),
    validForNanoseconds: 1,
    policy: policy,
    owners: setup.descriptors,
    volumes: [volume]
  )
  clock.now = 102
  #expect(throws: RuntimeReleaseTopologyAuthorityError.captureReceiptStale) {
    try authority.collect(staleLease)
  }

  let providerAuthority = testAuthority(
    kernel: nonCloneKernel(snapshot: .known(false), providerLocal: .known(false)))
  let providerLease = try providerAuthority.bind(
    plan: setup.plan,
    executionEpochNonce: UUID(),
    validForNanoseconds: 100,
    policy: policy,
    owners: setup.descriptors,
    volumes: [volume]
  )
  let providerReport = try providerAuthority.collect(providerLease)
  #expect(providerReport.topologyMatchesExpected == .known(false))
}

@Test func writableClosedAndReusedDescriptorsFailBeforeCollection() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let setup = try hardlinkSetup(fixture: fixture)
  let volume = BoundRuntimeReleaseVolumeDescriptor(
    expectedDevice: fixture.rootIdentity.device,
    rootFileDescriptor: fixture.rootDescriptor)
  let authority = testAuthority(kernel: nonCloneKernel(snapshot: .known(false)))

  let writable = open(
    fixture.rootURL.appendingPathComponent("first").path,
    O_RDWR | O_NOFOLLOW | O_CLOEXEC)
  defer { if writable >= 0 { close(writable) } }
  #expect(writable >= 0)
  #expect(throws: RuntimeReleaseTopologyAuthorityError.descriptorNotReadOnly(writable)) {
    try authority.bind(
      plan: setup.plan,
      executionEpochNonce: UUID(),
      validForNanoseconds: 100,
      policy: policy,
      owners: replacingFileDescriptor(setup.descriptors, at: 0, with: writable),
      volumes: [volume]
    )
  }

  var descriptorLimit = rlimit()
  #expect(getrlimit(RLIMIT_NOFILE, &descriptorLimit) == 0)
  let highMinimum = Int32(min(descriptorLimit.rlim_cur - 1, rlim_t(16_384)))
  let closed = fcntl(fixture.firstDescriptor, F_DUPFD_CLOEXEC, highMinimum)
  #expect(closed >= highMinimum)
  close(closed)
  #expect(fcntl(closed, F_GETFD) == -1 && errno == EBADF)
  #expect(throws: RuntimeReleaseTopologyAuthorityError.descriptorUnavailable(closed)) {
    try authority.bind(
      plan: setup.plan,
      executionEpochNonce: UUID(),
      validForNanoseconds: 100,
      policy: policy,
      owners: replacingFileDescriptor(setup.descriptors, at: 0, with: closed),
      volumes: [volume]
    )
  }

  let reused = fcntl(fixture.firstDescriptor, F_DUPFD_CLOEXEC, 0)
  #expect(reused >= 0)
  let replacement = dup2(fixture.secondDescriptor, reused)
  defer { if replacement >= 0 { close(replacement) } }
  #expect(replacement == reused)
  #expect(fcntl(replacement, F_SETFD, FD_CLOEXEC) == 0)
  #expect(
    throws: RuntimeReleaseTopologyAuthorityError.descriptorIdentityMismatch(
      setup.descriptors[0].slot.objectIdentity)
  ) {
    try authority.bind(
      plan: setup.plan,
      executionEpochNonce: UUID(),
      validForNanoseconds: 100,
      policy: policy,
      owners: replacingFileDescriptor(setup.descriptors, at: 0, with: replacement),
      volumes: [volume]
    )
  }
}

@Test func closeOnExecIsPartOfDescriptorAdmission() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let setup = try hardlinkSetup(fixture: fixture)
  let descriptor = dup(fixture.firstDescriptor)
  defer { if descriptor >= 0 { close(descriptor) } }
  #expect(descriptor >= 0)
  #expect(fcntl(descriptor, F_SETFD, 0) == 0)
  let authority = testAuthority(kernel: nonCloneKernel(snapshot: .known(false)))

  #expect(
    throws: RuntimeReleaseTopologyAuthorityError.descriptorMissingCloseOnExec(descriptor)
  ) {
    try authority.bind(
      plan: setup.plan,
      executionEpochNonce: UUID(),
      validForNanoseconds: 100,
      policy: policy,
      owners: replacingFileDescriptor(setup.descriptors, at: 0, with: descriptor),
      volumes: [
        BoundRuntimeReleaseVolumeDescriptor(
          expectedDevice: fixture.rootIdentity.device,
          rootFileDescriptor: fixture.rootDescriptor)
      ]
    )
  }
}

@Test func emptyPlanAndNamespaceAliasesAreRejectedBeforeDescriptorUse() throws {
  #expect(throws: RuntimeReleaseTopologyPlanError.emptyExpectedSet) {
    try RuntimeReleaseTopologyExpectedPlan(
      planHash: digest(1), candidateActions: [], fileObjects: [], groups: [], volumeDevices: [])
  }

  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let slot = try namespaceSlot(
    root: fixture.rootIdentity,
    name: "first",
    object: fixture.firstIdentity)
  let spoofedObjectSlot = try namespaceSlot(
    root: fixture.rootIdentity,
    name: "first",
    object: fixture.secondIdentity)
  let firstAction = try actionID(1)
  let secondAction = try actionID(2)
  let firstOwner = RuntimeReleaseExpectedOwner(
    link: try ownerLink("first-candidate", "first"), slot: slot, actionID: firstAction)
  let aliasedOwner = RuntimeReleaseExpectedOwner(
    link: try ownerLink("alias-candidate", "alias"),
    slot: spoofedObjectSlot,
    actionID: secondAction)
  let firstFile = RuntimeReleaseExpectedFileObject(
    identity: fixture.firstIdentity,
    owners: [firstOwner],
    linkCount: 1,
    cloneIdentity: nil
  )
  let spoofedFile = RuntimeReleaseExpectedFileObject(
    identity: fixture.secondIdentity,
    owners: [aliasedOwner],
    linkCount: 1,
    cloneIdentity: nil
  )

  #expect(throws: RuntimeReleaseTopologyPlanError.aliasedOwnerSlot) {
    try RuntimeReleaseTopologyExpectedPlan(
      planHash: digest(1),
      candidateActions: [
        RuntimeReleaseCandidateActionBinding(
          candidateID: "first-candidate", actionID: firstAction),
        RuntimeReleaseCandidateActionBinding(
          candidateID: "alias-candidate", actionID: secondAction),
      ],
      fileObjects: [firstFile, spoofedFile],
      groups: [
        RuntimeReleaseExpectedGroup(
          allocationGroupID: "hardlink",
          ownerFileObjects: [fixture.firstIdentity],
          cloneIdentity: nil,
          cloneRefCount: nil,
          snapshotDevice: fixture.rootIdentity.device)
      ],
      volumeDevices: [fixture.rootIdentity.device]
    )
  }
}

@Test func cloneAndHardlinkGroupsShareOneActionAndFileIdentityComponent() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let setup = try cloneSetup(fixture: fixture)
  let authority = testAuthority(
    kernel: cloneKernel(cloneID: setup.clone.cloneID, refCount: 2, snapshot: .known(false)))
  let lease = try authority.bind(
    plan: setup.plan,
    executionEpochNonce: UUID(),
    validForNanoseconds: 100,
    policy: policy,
    owners: setup.descriptors,
    volumes: [
      BoundRuntimeReleaseVolumeDescriptor(
        expectedDevice: fixture.rootIdentity.device,
        rootFileDescriptor: fixture.rootDescriptor)
    ]
  )

  let report = try authority.collect(lease)

  #expect(report.topologyMatchesExpected == .known(true))
  #expect(report.seal.groups.count == 2)
  #expect(report.seal.components.count == 1)
  #expect(report.seal.components[0].allocationGroupIDs == ["clone", "hardlink"])
  #expect(report.seal.components[0].ownerFileObjects.count == 2)
  #expect(report.seal.components[0].actionIDsAtMostOnce == setup.actionIDs.sorted())
  #expect(report.seal.groups.allSatisfy { $0.conditionalSharedReclaimCredit == nil })
  #expect(report.issues.contains(.sharedCloneBytesUnavailable(setup.clone)))
}

@Test func topologyBindingHashCoversGroupsAndCloneGroupsMustBeComplete() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let setup = try cloneSetup(fixture: fixture)
  let renamedGroups = setup.plan.groups.map { group in
    RuntimeReleaseExpectedGroup(
      allocationGroupID: "renamed-\(group.allocationGroupID)",
      ownerFileObjects: group.ownerFileObjects,
      cloneIdentity: group.cloneIdentity,
      cloneRefCount: group.cloneRefCount,
      snapshotDevice: group.snapshotDevice)
  }
  let renamed = try RuntimeReleaseTopologyExpectedPlan(
    planHash: setup.plan.planHash,
    candidateActions: setup.plan.candidateActions,
    fileObjects: setup.plan.fileObjects,
    groups: renamedGroups,
    volumeDevices: setup.plan.volumeDevices)
  #expect(renamed.topologyBindingHash != setup.plan.topologyBindingHash)

  let firstIdentity = setup.plan.fileObjects[0].identity
  #expect(throws: RuntimeReleaseTopologyPlanError.invalidCloneBinding) {
    try RuntimeReleaseTopologyExpectedPlan(
      planHash: setup.plan.planHash,
      candidateActions: setup.plan.candidateActions,
      fileObjects: setup.plan.fileObjects,
      groups: [
        RuntimeReleaseExpectedGroup(
          allocationGroupID: "hardlink-all",
          ownerFileObjects: setup.plan.fileObjects.map(\.identity),
          cloneIdentity: nil,
          cloneRefCount: nil,
          snapshotDevice: fixture.rootIdentity.device),
        RuntimeReleaseExpectedGroup(
          allocationGroupID: "partial-clone",
          ownerFileObjects: [firstIdentity],
          cloneIdentity: setup.clone,
          cloneRefCount: 1,
          snapshotDevice: fixture.rootIdentity.device),
      ],
      volumeDevices: setup.plan.volumeDevices)
  }
}

@Test func contradictoryOrFailedCloneSignalsRemainFailed() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let setup = try hardlinkSetup(fixture: fixture)
  let failure = RuntimeReleaseTopologyFailure(
    kind: .probeFailed, collector: "test-clone-id")
  let authority = testAuthority(
    kernel: inconsistentCloneKernel(cloneID: .failed(failure)))
  let lease = try authority.bind(
    plan: setup.plan,
    executionEpochNonce: UUID(),
    validForNanoseconds: 100,
    policy: policy,
    owners: setup.descriptors,
    volumes: [
      BoundRuntimeReleaseVolumeDescriptor(
        expectedDevice: fixture.rootIdentity.device,
        rootFileDescriptor: fixture.rootDescriptor)
    ])
  let report = try authority.collect(lease)
  #expect(report.topologyMatchesExpected == .failed(failure))

  let contradictoryAuthority = testAuthority(
    kernel: inconsistentCloneKernel(
      mayShareBlocks: .known(true), cloneID: .known(0)))
  let contradictoryLease = try contradictoryAuthority.bind(
    plan: setup.plan,
    executionEpochNonce: UUID(),
    validForNanoseconds: 100,
    policy: policy,
    owners: setup.descriptors,
    volumes: [
      BoundRuntimeReleaseVolumeDescriptor(
        expectedDevice: fixture.rootIdentity.device,
        rootFileDescriptor: fixture.rootDescriptor)
    ])
  let contradictory = try contradictoryAuthority.collect(contradictoryLease)
  #expect(
    contradictory.topologyMatchesExpected
      == .failed(
        RuntimeReleaseTopologyFailure(
          kind: .inconsistentEvidence, collector: "release-clone-association")))
}

@Test func externalCloneRefcountAndSnapshotBlockerFailClosedWithoutSharedCredit() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let setup = try cloneSetup(fixture: fixture)
  let authority = testAuthority(
    kernel: cloneKernel(cloneID: setup.clone.cloneID, refCount: 3, snapshot: .known(true)))
  let lease = try authority.bind(
    plan: setup.plan,
    executionEpochNonce: UUID(),
    validForNanoseconds: 100,
    policy: policy,
    owners: setup.descriptors,
    volumes: [
      BoundRuntimeReleaseVolumeDescriptor(
        expectedDevice: fixture.rootIdentity.device,
        rootFileDescriptor: fixture.rootDescriptor)
    ]
  )

  let report = try authority.collect(lease)

  #expect(report.topologyMatchesExpected == .known(false))
  #expect(report.collection == .known(false))
  #expect(
    report.issues.contains(
      .cloneOwnerCountMismatch(setup.clone, observed: 2, refCount: 3)))
  #expect(report.issues.contains(.snapshotBlocked(fixture.rootIdentity.device)))
  #expect(report.seal.groups.allSatisfy { $0.conditionalSharedReclaimCredit == nil })
}

private struct HardlinkSetup {
  let plan: RuntimeReleaseTopologyExpectedPlan
  let descriptors: [BoundRuntimeReleaseOwnerDescriptor]
  let actionID: ActionID
}

private struct CloneSetup {
  let plan: RuntimeReleaseTopologyExpectedPlan
  let descriptors: [BoundRuntimeReleaseOwnerDescriptor]
  let clone: RuntimeReleaseCloneIdentity
  let actionIDs: [ActionID]
}

private func hardlinkSetup(fixture: RealReleaseTopologyFixture) throws -> HardlinkSetup {
  let action = try actionID(1)
  let firstSlot = try namespaceSlot(
    root: fixture.rootIdentity, name: "first", object: fixture.firstIdentity)
  let hardlinkSlot = try namespaceSlot(
    root: fixture.rootIdentity, name: "hardlink", object: fixture.firstIdentity)
  let firstOwner = RuntimeReleaseExpectedOwner(
    link: try ownerLink("cache", "first"), slot: firstSlot, actionID: action)
  let hardlinkOwner = RuntimeReleaseExpectedOwner(
    link: try ownerLink("cache", "hardlink"), slot: hardlinkSlot, actionID: action)
  let plan = try RuntimeReleaseTopologyExpectedPlan(
    planHash: digest(1),
    candidateActions: [
      RuntimeReleaseCandidateActionBinding(candidateID: "cache", actionID: action)
    ],
    fileObjects: [
      RuntimeReleaseExpectedFileObject(
        identity: fixture.firstIdentity,
        owners: [firstOwner, hardlinkOwner],
        linkCount: 2,
        cloneIdentity: nil)
    ],
    groups: [
      RuntimeReleaseExpectedGroup(
        allocationGroupID: "hardlink",
        ownerFileObjects: [fixture.firstIdentity],
        cloneIdentity: nil,
        cloneRefCount: nil,
        snapshotDevice: fixture.rootIdentity.device)
    ],
    volumeDevices: [fixture.rootIdentity.device]
  )
  return HardlinkSetup(
    plan: plan,
    descriptors: [
      BoundRuntimeReleaseOwnerDescriptor(
        slot: firstSlot,
        rootFileDescriptor: fixture.rootDescriptor,
        parentFileDescriptor: fixture.rootDescriptor,
        fileDescriptor: fixture.firstDescriptor),
      BoundRuntimeReleaseOwnerDescriptor(
        slot: hardlinkSlot,
        rootFileDescriptor: fixture.rootDescriptor,
        parentFileDescriptor: fixture.rootDescriptor,
        fileDescriptor: fixture.hardlinkDescriptor),
    ],
    actionID: action
  )
}

private func cloneSetup(fixture: RealReleaseTopologyFixture) throws -> CloneSetup {
  let firstAction = try actionID(1)
  let secondAction = try actionID(2)
  let clone = RuntimeReleaseCloneIdentity(device: fixture.rootIdentity.device, cloneID: 900)
  let firstSlot = try namespaceSlot(
    root: fixture.rootIdentity, name: "first", object: fixture.firstIdentity)
  let hardlinkSlot = try namespaceSlot(
    root: fixture.rootIdentity, name: "hardlink", object: fixture.firstIdentity)
  let secondSlot = try namespaceSlot(
    root: fixture.rootIdentity, name: "second", object: fixture.secondIdentity)
  let firstOwner = RuntimeReleaseExpectedOwner(
    link: try ownerLink("first-cache", "first"), slot: firstSlot, actionID: firstAction)
  let hardlinkOwner = RuntimeReleaseExpectedOwner(
    link: try ownerLink("first-cache", "hardlink"),
    slot: hardlinkSlot,
    actionID: firstAction)
  let secondOwner = RuntimeReleaseExpectedOwner(
    link: try ownerLink("second-cache", "second"), slot: secondSlot, actionID: secondAction)
  let plan = try RuntimeReleaseTopologyExpectedPlan(
    planHash: digest(2),
    candidateActions: [
      RuntimeReleaseCandidateActionBinding(candidateID: "first-cache", actionID: firstAction),
      RuntimeReleaseCandidateActionBinding(candidateID: "second-cache", actionID: secondAction),
    ],
    fileObjects: [
      RuntimeReleaseExpectedFileObject(
        identity: fixture.firstIdentity,
        owners: [firstOwner, hardlinkOwner],
        linkCount: 2,
        cloneIdentity: clone),
      RuntimeReleaseExpectedFileObject(
        identity: fixture.secondIdentity,
        owners: [secondOwner],
        linkCount: 1,
        cloneIdentity: clone),
    ],
    groups: [
      RuntimeReleaseExpectedGroup(
        allocationGroupID: "hardlink",
        ownerFileObjects: [fixture.firstIdentity],
        cloneIdentity: nil,
        cloneRefCount: nil,
        snapshotDevice: fixture.rootIdentity.device),
      RuntimeReleaseExpectedGroup(
        allocationGroupID: "clone",
        ownerFileObjects: [fixture.firstIdentity, fixture.secondIdentity],
        cloneIdentity: clone,
        cloneRefCount: 2,
        snapshotDevice: fixture.rootIdentity.device),
    ],
    volumeDevices: [fixture.rootIdentity.device]
  )
  return CloneSetup(
    plan: plan,
    descriptors: [
      BoundRuntimeReleaseOwnerDescriptor(
        slot: firstSlot,
        rootFileDescriptor: fixture.rootDescriptor,
        parentFileDescriptor: fixture.rootDescriptor,
        fileDescriptor: fixture.firstDescriptor),
      BoundRuntimeReleaseOwnerDescriptor(
        slot: hardlinkSlot,
        rootFileDescriptor: fixture.rootDescriptor,
        parentFileDescriptor: fixture.rootDescriptor,
        fileDescriptor: fixture.hardlinkDescriptor),
      BoundRuntimeReleaseOwnerDescriptor(
        slot: secondSlot,
        rootFileDescriptor: fixture.rootDescriptor,
        parentFileDescriptor: fixture.rootDescriptor,
        fileDescriptor: fixture.secondDescriptor),
    ],
    clone: clone,
    actionIDs: [firstAction, secondAction]
  )
}

private func replacingFileDescriptor(
  _ descriptors: [BoundRuntimeReleaseOwnerDescriptor],
  at index: Int,
  with fileDescriptor: Int32
) -> [BoundRuntimeReleaseOwnerDescriptor] {
  var result = descriptors
  let original = result[index]
  result[index] = BoundRuntimeReleaseOwnerDescriptor(
    slot: original.slot,
    rootFileDescriptor: original.rootFileDescriptor,
    parentFileDescriptor: original.parentFileDescriptor,
    fileDescriptor: fileDescriptor
  )
  return result
}

private func namespaceSlot(
  root: RuntimeReleaseFileObjectIdentity,
  name: String,
  object: RuntimeReleaseFileObjectIdentity
) throws -> RuntimeReleaseNamespaceSlotIdentity {
  try RuntimeReleaseNamespaceSlotIdentity(
    rootIdentity: root,
    parentIdentity: root,
    rawBasename: Data(name.utf8),
    objectIdentity: object
  )
}

private func ownerLink(_ candidateID: String, _ name: String) throws -> FileOwnerLink {
  FileOwnerLink(
    candidateID: candidateID,
    path: try RawTargetPath(components: [Data(name.utf8)]))
}

private func materializationPolicy() throws -> NoMaterializationPolicy {
  guard let policy = MaterializationPolicyInstaller().installBeforePathAccess().value else {
    throw ReleaseTopologyTestError.materializationPolicy
  }
  return policy
}

private func runtimeIdentity(
  _ descriptor: Int32,
  policy: NoMaterializationPolicy
) throws -> RuntimeReleaseFileObjectIdentity {
  guard
    let identity = FileDescriptorIdentityProbe().probe(
      fileDescriptor: descriptor, policy: policy
    ).value
  else { throw ReleaseTopologyTestError.identity }
  let type: RuntimeReleaseObjectType = identity.objectType == .directory ? .directory : .regularFile
  return RuntimeReleaseFileObjectIdentity(
    device: UInt64(bitPattern: identity.device),
    fileID: identity.fileID,
    objectType: type
  )
}

private func testAuthority(
  now: UInt64 = 10,
  kernel: RuntimeReleaseTopologyKernel
) -> RuntimeReleaseTopologyAuthority {
  RuntimeReleaseTopologyAuthority(
    limits: RuntimeReleaseTopologyLimits(),
    monotonicNow: { now },
    kernel: kernel
  )
}

private final class TestMonotonicClock: @unchecked Sendable {
  private let lock = NSLock()
  private var storage: UInt64

  init(now: UInt64) { storage = now }

  var now: UInt64 {
    get {
      lock.lock()
      defer { lock.unlock() }
      return storage
    }
    set {
      lock.lock()
      storage = newValue
      lock.unlock()
    }
  }
}

private func testAuthority(
  clock: TestMonotonicClock,
  kernel: RuntimeReleaseTopologyKernel
) -> RuntimeReleaseTopologyAuthority {
  RuntimeReleaseTopologyAuthority(
    limits: RuntimeReleaseTopologyLimits(),
    monotonicNow: { clock.now },
    kernel: kernel
  )
}

private func nonCloneKernel(
  snapshot: RuntimeReleaseTopologyObservation<Bool>,
  providerLocal: RuntimeReleaseTopologyObservation<Bool>? = nil
) -> RuntimeReleaseTopologyKernel {
  let live = RuntimeReleaseTopologyKernel.live
  return RuntimeReleaseTopologyKernel(
    descriptorIdentity: live.descriptorIdentity,
    item: { parent, name, policy in
      let item = live.item(parent, name, policy)
      return RuntimeReleaseKernelItem(
        identity: item.identity,
        linkCount: item.linkCount,
        mayShareBlocks: .known(false),
        sharesAllBlocks: .absent,
        cloneID: .known(0),
        cloneRefCount: .absent,
        providerLocal: providerLocal ?? item.providerLocal
      )
    },
    snapshotBlocker: { _, _ in snapshot }
  )
}

private func cloneKernel(
  cloneID: UInt64,
  refCount: UInt32,
  snapshot: RuntimeReleaseTopologyObservation<Bool>
) -> RuntimeReleaseTopologyKernel {
  let live = RuntimeReleaseTopologyKernel.live
  return RuntimeReleaseTopologyKernel(
    descriptorIdentity: live.descriptorIdentity,
    item: { parent, name, policy in
      let item = live.item(parent, name, policy)
      return RuntimeReleaseKernelItem(
        identity: item.identity,
        linkCount: item.linkCount,
        mayShareBlocks: .known(true),
        sharesAllBlocks: .known(true),
        cloneID: .known(cloneID),
        cloneRefCount: .known(refCount),
        providerLocal: item.providerLocal
      )
    },
    snapshotBlocker: { _, _ in snapshot }
  )
}

private func inconsistentCloneKernel(
  mayShareBlocks: RuntimeReleaseTopologyObservation<Bool> = .known(false),
  cloneID: RuntimeReleaseTopologyObservation<UInt64>
) -> RuntimeReleaseTopologyKernel {
  let live = RuntimeReleaseTopologyKernel.live
  return RuntimeReleaseTopologyKernel(
    descriptorIdentity: live.descriptorIdentity,
    item: { parent, name, policy in
      let item = live.item(parent, name, policy)
      return RuntimeReleaseKernelItem(
        identity: item.identity,
        linkCount: item.linkCount,
        mayShareBlocks: mayShareBlocks,
        sharesAllBlocks: .absent,
        cloneID: cloneID,
        cloneRefCount: .absent,
        providerLocal: item.providerLocal
      )
    },
    snapshotBlocker: { _, _ in .known(false) }
  )
}

private func digest(_ byte: UInt8) throws -> PolicyDigest {
  try PolicyDigest(bytes: Data(repeating: byte, count: 32))
}

private func actionID(_ byte: UInt8) throws -> ActionID {
  ActionID(digest: try digest(byte))
}
