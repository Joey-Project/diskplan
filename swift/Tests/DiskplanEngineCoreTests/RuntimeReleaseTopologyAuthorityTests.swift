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

private final class NestedReleaseTopologyFixture: @unchecked Sendable {
  let rootURL: URL
  let rootDescriptor: Int32
  let parentDescriptor: Int32
  let fileDescriptor: Int32
  let rootIdentity: RuntimeReleaseFileObjectIdentity
  let parentIdentity: RuntimeReleaseFileObjectIdentity
  let fileIdentity: RuntimeReleaseFileObjectIdentity
  private let lock = NSLock()
  private var replacementSucceeded = false

  init(policy: NoMaterializationPolicy) throws {
    rootURL = FileManager.default.temporaryDirectory.appendingPathComponent(
      "diskplan-release-topology-nested-\(UUID().uuidString)", isDirectory: true)
    let parent = rootURL.appendingPathComponent("nested", isDirectory: true)
    let file = parent.appendingPathComponent("leaf")
    try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: true)
    try Data("leaf".utf8).write(to: file, options: .withoutOverwriting)
    rootDescriptor = open(rootURL.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    parentDescriptor = open(parent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    fileDescriptor = open(file.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    guard rootDescriptor >= 0, parentDescriptor >= 0, fileDescriptor >= 0 else {
      throw ReleaseTopologyTestError.filesystem(errno)
    }
    rootIdentity = try runtimeIdentity(rootDescriptor, policy: policy)
    parentIdentity = try runtimeIdentity(parentDescriptor, policy: policy)
    fileIdentity = try runtimeIdentity(fileDescriptor, policy: policy)
  }

  func replaceParentSlot() {
    lock.lock()
    defer { lock.unlock() }
    guard !replacementSucceeded else { return }
    let parent = rootURL.appendingPathComponent("nested", isDirectory: true)
    let displaced = rootURL.appendingPathComponent("displaced", isDirectory: true)
    guard Darwin.rename(parent.path, displaced.path) == 0 else { return }
    replacementSucceeded = mkdir(parent.path, S_IRWXU) == 0
  }

  var didReplaceParentSlot: Bool {
    lock.lock()
    defer { lock.unlock() }
    return replacementSucceeded
  }

  deinit {
    if rootDescriptor >= 0 { close(rootDescriptor) }
    if parentDescriptor >= 0 { close(parentDescriptor) }
    if fileDescriptor >= 0 { close(fileDescriptor) }
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
  #expect(report.seal.components.first?.actionIDsAtMostOnce == setup.actionIDs.sorted())
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

@Test func reportCannotPublishWhenCaptureExpiresDuringTopologyProbes() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let setup = try hardlinkSetup(fixture: fixture)
  let clock = TestMonotonicClock(now: 100)
  let base = nonCloneKernel(snapshot: .known(false))
  let expiring = RuntimeReleaseTopologyKernel(
    descriptorIdentity: base.descriptorIdentity,
    item: base.item,
    snapshotBlocker: { _, _ in
      clock.now = 200
      return .known(false)
    })
  let authority = testAuthority(clock: clock, kernel: expiring)
  let lease = try authority.bind(
    plan: setup.plan,
    executionEpochNonce: UUID(),
    validForNanoseconds: 50,
    policy: policy,
    owners: setup.descriptors,
    volumes: [
      BoundRuntimeReleaseVolumeDescriptor(
        expectedDevice: fixture.rootIdentity.device,
        rootFileDescriptor: fixture.rootDescriptor)
    ])

  #expect(throws: RuntimeReleaseTopologyAuthorityError.captureReceiptStale) {
    try authority.collect(lease)
  }
}

@Test func immutableActionPathAndRawParentChainCannotBeSubstituted() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let action = try actionID(7)
  let slot = try namespaceSlot(
    root: fixture.rootIdentity, name: "first", object: fixture.firstIdentity)
  let mismatchedOwner = RuntimeReleaseExpectedOwner(
    link: try ownerLink("candidate", "first"), slot: slot, actionID: action)
  #expect(throws: RuntimeReleaseTopologyPlanError.ownerBindingMismatch) {
    try singleOwnerPlan(
      fixture: fixture,
      action: action,
      actionTarget: ["second"],
      owner: mismatchedOwner)
  }

  let nestedOwner = RuntimeReleaseExpectedOwner(
    link: FileOwnerLink(
      candidateID: "candidate",
      path: try RawTargetPath(
        components: [Data("missing-parent".utf8), Data("first".utf8)])),
    slot: slot,
    actionID: action)
  let nestedPlan = try singleOwnerPlan(
    fixture: fixture,
    action: action,
    actionTarget: ["missing-parent", "first"],
    owner: nestedOwner,
    parentChain: [fixture.rootIdentity])
  let authority = testAuthority(kernel: nonCloneKernel(snapshot: .known(false)))
  #expect(throws: RuntimeReleaseTopologyAuthorityError.self) {
    try authority.bind(
      plan: nestedPlan,
      executionEpochNonce: UUID(),
      validForNanoseconds: 100,
      policy: policy,
      owners: [
        BoundRuntimeReleaseOwnerDescriptor(
          slot: slot,
          rootFileDescriptor: fixture.rootDescriptor,
          parentFileDescriptor: fixture.rootDescriptor,
          fileDescriptor: fixture.firstDescriptor)
      ],
      volumes: [
        BoundRuntimeReleaseVolumeDescriptor(
          expectedDevice: fixture.rootIdentity.device,
          rootFileDescriptor: fixture.rootDescriptor)
      ])
  }
}

@Test func inheritedProviderBoundaryRejectsMaterializedDescendant() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let action = try actionID(8)
  let slot = try namespaceSlot(
    root: fixture.rootIdentity, name: "first", object: fixture.firstIdentity)
  let owner = RuntimeReleaseExpectedOwner(
    link: try ownerLink("candidate", "first"),
    slot: slot,
    actionID: action,
    inheritedProviderBoundaryByComponent: [true])
  let plan = try singleOwnerPlan(
    fixture: fixture,
    action: action,
    actionTarget: ["first"],
    owner: owner,
    inheritedProviderBoundaryByComponent: [true])
  let authority = testAuthority(kernel: nonCloneKernel(snapshot: .known(false)))
  let lease = try authority.bind(
    plan: plan,
    executionEpochNonce: UUID(),
    validForNanoseconds: 100,
    policy: policy,
    owners: [
      BoundRuntimeReleaseOwnerDescriptor(
        slot: slot,
        rootFileDescriptor: fixture.rootDescriptor,
        parentFileDescriptor: fixture.rootDescriptor,
        fileDescriptor: fixture.firstDescriptor)
    ],
    volumes: [
      BoundRuntimeReleaseVolumeDescriptor(
        expectedDevice: fixture.rootIdentity.device,
        rootFileDescriptor: fixture.rootDescriptor)
    ])
  let report = try authority.collect(lease)
  #expect(report.topologyMatchesExpected == .known(false))
  #expect(report.seal.fileObjects[0].providerLocal == .known(false))
}

@Test func collectPreservesTypedMissingWhenLeafDisappearsFromNamespace() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let setup = try hardlinkSetup(fixture: fixture)
  let base = nonCloneKernel(snapshot: .known(false))
  let missingLeaf = RuntimeReleaseTopologyKernel(
    descriptorIdentity: base.descriptorIdentity,
    item: { _, _, _, _ in
      RuntimeReleaseKernelItem(
        identity: .absent,
        linkCount: .absent,
        mayShareBlocks: .absent,
        sharesAllBlocks: .absent,
        cloneID: .absent,
        cloneRefCount: .absent,
        providerLocal: .absent)
    },
    snapshotBlocker: base.snapshotBlocker)
  let authority = testAuthority(kernel: missingLeaf)
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

  #expect(report.collection == .absent)
  #expect(report.topologyMatchesExpected == .absent)
  #expect(report.seal.fileObjects[0].namespaceSlotsMatch == .absent)
  #expect(report.seal.fileObjects[0].linkCount == .absent)
  #expect(report.seal.fileObjects[0].ownerClosure == .absent)
}

@Test func liveDescriptorAccessPolicyDetectsPolicyDriftButIgnoresChildChurn() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let live = RuntimeReleaseTopologyKernel.live
  let initial = try #require(
    live.descriptorAccessPolicy(fixture.rootDescriptor, policy).knownValue)
  let initialIdentity = try #require(
    live.descriptorIdentity(fixture.rootDescriptor, policy).knownValue)
  let child = fixture.rootURL.appendingPathComponent("benign-child")
  try Data("child".utf8).write(to: child, options: .withoutOverwriting)
  try FileManager.default.removeItem(at: child)

  #expect(live.descriptorAccessPolicy(fixture.rootDescriptor, policy) == .known(initial))

  var status = stat()
  guard fstat(fixture.rootDescriptor, &status) == 0 else {
    throw ReleaseTopologyTestError.filesystem(errno)
  }
  let originalMode = status.st_mode & 0o7777
  let changedMode = originalMode ^ mode_t(S_IWGRP)
  guard fchmod(fixture.rootDescriptor, changedMode) == 0 else {
    throw ReleaseTopologyTestError.filesystem(errno)
  }
  defer { _ = fchmod(fixture.rootDescriptor, originalMode) }

  let changed = try #require(
    live.descriptorAccessPolicy(fixture.rootDescriptor, policy).knownValue)
  #expect(changed != initial)
  #expect(live.descriptorIdentity(fixture.rootDescriptor, policy) == .known(initialIdentity))
}

@Test func sameInodeAccessPolicyDriftIsAnExplicitNamespaceIssue() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let setup = try hardlinkSetup(fixture: fixture)
  let initial = try testingDescriptorAccessPolicy()
  let state = DescriptorAccessPolicyState(.known(initial))
  let authority = testAuthority(kernel: accessPolicyKernel(state: state))
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
  state.value = .known(
    RuntimeReleaseDescriptorAccessPolicy(
      accessPolicy: initial.accessPolicy + "-changed",
      aclDigest: initial.aclDigest,
      mountIdentity: initial.mountIdentity))

  let report = try authority.collect(lease)

  #expect(report.topologyMatchesExpected == .known(false))
  #expect(report.seal.fileObjects[0].namespaceAccessPolicyMatches == .known(false))
  #expect(
    report.issues.contains(
      .namespaceAccessPolicyMismatch(setup.descriptors[0].slot)))
}

@Test func descriptorAccessPolicySealRejectsEveryProtectedDimension() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let setup = try hardlinkSetup(fixture: fixture)
  let initial = try testingDescriptorAccessPolicy()
  let changedPolicies = [
    RuntimeReleaseDescriptorAccessPolicy(
      accessPolicy: initial.accessPolicy + "-changed",
      aclDigest: initial.aclDigest,
      mountIdentity: initial.mountIdentity),
    RuntimeReleaseDescriptorAccessPolicy(
      accessPolicy: initial.accessPolicy,
      aclDigest: try digest(0xEF),
      mountIdentity: initial.mountIdentity),
    RuntimeReleaseDescriptorAccessPolicy(
      accessPolicy: initial.accessPolicy,
      aclDigest: initial.aclDigest,
      mountIdentity: initial.mountIdentity + "-changed"),
  ]
  for changed in changedPolicies {
    let state = DescriptorAccessPolicyState(.known(initial))
    let authority = testAuthority(kernel: accessPolicyKernel(state: state))
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
    state.value = .known(changed)

    let report = try authority.collect(lease)

    #expect(report.topologyMatchesExpected == .known(false))
    #expect(report.seal.fileObjects[0].namespaceAccessPolicyMatches == .known(false))
    #expect(
      report.issues.contains(
        .namespaceAccessPolicyMismatch(setup.descriptors[0].slot)))
  }
}

@Test func mixedMismatchAndTypedAccessEvidenceRemainDistinguishable() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let setup = try hardlinkSetup(fixture: fixture)
  let initial = try testingDescriptorAccessPolicy()
  let unreadableFailure = RuntimeReleaseTopologyFailure(
    kind: .probeFailed, collector: "descriptor-policy-unreadable", errorCode: EACCES)
  let failedFailure = RuntimeReleaseTopologyFailure(
    kind: .probeFailed, collector: "descriptor-policy-failed", errorCode: EIO)
  let outcomes: [RuntimeReleaseTopologyObservation<RuntimeReleaseDescriptorAccessPolicy>] = [
    .absent,
    .unreadable(unreadableFailure),
    .failed(failedFailure),
  ]
  for outcome in outcomes {
    let state = DescriptorAccessPolicyState(.known(initial))
    let authority = testAuthority(
      kernel: accessPolicyKernel(
        state: state,
        itemIdentity: .known(fixture.secondIdentity)))
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
    state.value = outcome

    let report = try authority.collect(lease)
    let expected = booleanFailure(outcome)

    #expect(report.collection == expected)
    #expect(report.topologyMatchesExpected == expected)
    #expect(report.seal.fileObjects[0].namespaceSlotsMatch == expected)
    #expect(report.seal.fileObjects[0].namespaceAccessPolicyMatches == expected)
    #expect(report.seal.fileObjects[0].topologyMatchesExpected == expected)
    #expect(report.seal.groups[0].topologyMatchesExpected == expected)
    #expect(report.issues.contains(.namespaceSlotMismatch(setup.descriptors[0].slot)))
  }
}

@Test func bindPreservesTypedDescriptorAccessPolicyFailures() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let setup = try hardlinkSetup(fixture: fixture)
  let missing = DescriptorAccessPolicyState(.absent)
  #expect(throws: RuntimeReleaseTopologyAuthorityError.namespaceChainMissing) {
    try testAuthority(kernel: accessPolicyKernel(state: missing)).bind(
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
  }
  let unreadableFailure = RuntimeReleaseTopologyFailure(
    kind: .probeFailed, collector: "descriptor-policy-unreadable", errorCode: EACCES)
  let unreadable = DescriptorAccessPolicyState(.unreadable(unreadableFailure))
  #expect(
    throws: RuntimeReleaseTopologyAuthorityError.namespaceChainUnreadable(unreadableFailure)
  ) {
    try testAuthority(kernel: accessPolicyKernel(state: unreadable)).bind(
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
  }
  let failedFailure = RuntimeReleaseTopologyFailure(
    kind: .probeFailed, collector: "descriptor-policy-failed", errorCode: EIO)
  let failed = DescriptorAccessPolicyState(.failed(failedFailure))
  #expect(throws: RuntimeReleaseTopologyAuthorityError.namespaceChainProbeFailed(failedFailure)) {
    try testAuthority(kernel: accessPolicyKernel(state: failed)).bind(
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
  }
}

@Test func livePolicyRaceStopsAfterMetadataAndBeforeParentOpen() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let action = try actionID(22)
  let slot = try namespaceSlot(
    root: fixture.rootIdentity, name: "first", object: fixture.firstIdentity)
  let owner = RuntimeReleaseExpectedOwner(
    link: FileOwnerLink(
      candidateID: "candidate",
      path: try rawTarget(["missing-parent", "first"])),
    slot: slot,
    actionID: action,
    parentChain: [fixture.rootIdentity])
  let plan = try singleOwnerPlan(
    fixture: fixture,
    action: action,
    actionTarget: ["missing-parent", "first"],
    owner: owner,
    parentChain: [fixture.rootIdentity])
  let expectedParentIdentity = fixture.rootIdentity

  func bindFailure(
    _ policyObservation: RuntimeReleaseTopologyObservation<Bool>,
    itemIdentity: RuntimeReleaseTopologyObservation<RuntimeReleaseFileObjectIdentity>? = nil
  ) -> (error: RuntimeReleaseTopologyAuthorityError?, events: [String]) {
    let recorder = PathAccessOrderRecorder()
    let live = RuntimeReleaseTopologyKernel.live
    let kernel = RuntimeReleaseTopologyKernel(
      descriptorIdentity: live.descriptorIdentity,
      item: { _, _, _, _ in
        recorder.record("item")
        return RuntimeReleaseKernelItem(
          identity: itemIdentity ?? .known(expectedParentIdentity),
          linkCount: .known(1),
          mayShareBlocks: .known(false),
          sharesAllBlocks: .absent,
          cloneID: .known(0),
          cloneRefCount: .absent,
          providerLocal: .known(true))
      },
      snapshotBlocker: { _, _ in .known(false) },
      pathAccessPolicy: { _ in
        recorder.record("policy")
        return policyObservation
      })
    do {
      _ = try testAuthority(kernel: kernel).bind(
        plan: plan,
        executionEpochNonce: UUID(),
        validForNanoseconds: 100,
        policy: policy,
        owners: [
          BoundRuntimeReleaseOwnerDescriptor(
            slot: slot,
            rootFileDescriptor: fixture.rootDescriptor,
            parentFileDescriptor: fixture.rootDescriptor,
            fileDescriptor: fixture.firstDescriptor)
        ],
        volumes: [
          BoundRuntimeReleaseVolumeDescriptor(
            expectedDevice: fixture.rootIdentity.device,
            rootFileDescriptor: fixture.rootDescriptor)
        ])
      return (nil, recorder.events)
    } catch let error as RuntimeReleaseTopologyAuthorityError {
      return (error, recorder.events)
    } catch {
      return (nil, recorder.events)
    }
  }

  let metadataMissing = bindFailure(.known(true), itemIdentity: .absent)
  #expect(metadataMissing.error == .namespaceChainMissing)
  #expect(metadataMissing.events == ["item"])

  let openMissing = bindFailure(.known(true))
  #expect(openMissing.error == .namespaceChainMissing)
  #expect(openMissing.events == ["item", "policy"])

  let replacedParent = RuntimeReleaseFileObjectIdentity(
    device: expectedParentIdentity.device,
    fileID: expectedParentIdentity.fileID &+ 1,
    objectType: .directory)
  let replacementMismatch = bindFailure(.known(true), itemIdentity: .known(replacedParent))
  #expect(replacementMismatch.error == .namespaceChainMismatch)
  #expect(replacementMismatch.events == ["item"])

  let unavailable = bindFailure(.unknown(.unavailableViaPublicAPI))
  #expect(unavailable.error == .namespaceChainUnknown(.unavailableViaPublicAPI))
  #expect(unavailable.events == ["item", "policy"])

  let unreadableFailure = RuntimeReleaseTopologyFailure(
    kind: .probeFailed, collector: "dataless-policy-race", errorCode: EACCES)
  let unreadable = bindFailure(.unreadable(unreadableFailure))
  #expect(unreadable.error == .namespaceChainUnreadable(unreadableFailure))
  #expect(unreadable.events == ["item", "policy"])

  let replacementFailure = RuntimeReleaseTopologyFailure(
    kind: .inconsistentEvidence, collector: "replacement-policy-race")
  let replacement = bindFailure(.failed(replacementFailure))
  #expect(replacement.error == .namespaceChainProbeFailed(replacementFailure))
  #expect(replacement.events == ["item", "policy"])
}

@Test func productionLiveProbeCannotApproveInheritedProviderDescendant() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let item = RuntimeReleaseTopologyKernel.live.item(
    fixture.rootDescriptor,
    Data("first".utf8),
    policy,
    true)
  #expect(item.providerLocal != .known(true))
}

@Test func parentChainReplacementBetweenLeafProbeAndPostflightFailsClosed() throws {
  let policy = try materializationPolicy()
  let fixture = try NestedReleaseTopologyFixture(policy: policy)
  let action = try actionID(9)
  let slot = try RuntimeReleaseNamespaceSlotIdentity(
    rootIdentity: fixture.rootIdentity,
    parentIdentity: fixture.parentIdentity,
    rawBasename: Data("leaf".utf8),
    objectIdentity: fixture.fileIdentity)
  let owner = RuntimeReleaseExpectedOwner(
    link: FileOwnerLink(
      candidateID: "nested-candidate",
      path: try RawTargetPath(
        components: [Data("nested".utf8), Data("leaf".utf8)])),
    slot: slot,
    actionID: action)
  let plan = try RuntimeReleaseTopologyExpectedPlan(
    testingPlanHash: digest(12),
    candidateActions: [
      try actionBinding(
        candidateID: "nested-candidate",
        actionID: action,
        root: fixture.rootIdentity,
        target: ["nested", "leaf"],
        object: fixture.fileIdentity,
        parentChain: [fixture.parentIdentity])
    ],
    fileObjects: [
      RuntimeReleaseExpectedFileObject(
        identity: fixture.fileIdentity,
        owners: [owner],
        linkCount: 1,
        cloneIdentity: nil)
    ],
    groups: [
      RuntimeReleaseExpectedGroup(
        allocationGroupID: "nested",
        ownerFileObjects: [fixture.fileIdentity],
        cloneIdentity: nil,
        cloneRefCount: nil,
        snapshotDevice: fixture.rootIdentity.device)
    ],
    volumeDevices: [fixture.rootIdentity.device])
  let base = nonCloneKernel(snapshot: .known(false))
  let replacing = RuntimeReleaseTopologyKernel(
    descriptorIdentity: base.descriptorIdentity,
    item: { parent, name, livePolicy, inherited in
      let item = base.item(parent, name, livePolicy, inherited)
      if name == Data("leaf".utf8) { fixture.replaceParentSlot() }
      return item
    },
    snapshotBlocker: base.snapshotBlocker)
  let authority = testAuthority(kernel: replacing)
  let lease = try authority.bind(
    plan: plan,
    executionEpochNonce: UUID(),
    validForNanoseconds: 100,
    policy: policy,
    owners: [
      BoundRuntimeReleaseOwnerDescriptor(
        slot: slot,
        rootFileDescriptor: fixture.rootDescriptor,
        parentFileDescriptor: fixture.parentDescriptor,
        fileDescriptor: fixture.fileDescriptor)
    ],
    volumes: [
      BoundRuntimeReleaseVolumeDescriptor(
        expectedDevice: fixture.rootIdentity.device,
        rootFileDescriptor: fixture.rootDescriptor)
    ])
  let report = try authority.collect(lease)
  #expect(fixture.didReplaceParentSlot)
  #expect(report.topologyMatchesExpected != .known(true))
  #expect(report.seal.fileObjects[0].namespaceSlotsMatch != .known(true))
}

@Test func directoryCandidateCanAuthorizeAPlanBoundDescendantOwner() throws {
  let policy = try materializationPolicy()
  let fixture = try NestedReleaseTopologyFixture(policy: policy)
  let policyFixture = try releasePlanFixture(
    rootIdentity: fixture.rootIdentity,
    candidateIdentity: fixture.parentIdentity,
    fileIdentity: fixture.fileIdentity,
    ownerPath: ["nested", "leaf"])
  let namespace = try RuntimeReleaseOwnerNamespaceBinding(
    link: FileOwnerLink(
      candidateID: "cache",
      path: try rawTarget(["nested", "leaf"])),
    actionID: policyFixture.ownerAction.id,
    rawRoot: try RawRootPath(absoluteBytes: Data("/fixture".utf8)),
    rootIdentity: fixture.rootIdentity,
    rootSeal: try topologyRootSeal(),
    parentChain: [fixture.parentIdentity],
    parentSeals: [try topologyCandidateSeal()],
    targetIdentity: fixture.fileIdentity,
    inheritedProviderBoundaryByComponent: [false, false])
  let owner = RuntimeReleaseExpectedOwner(namespace: namespace)
  let plan = try RuntimeReleaseTopologyExpectedPlan(
    plan: policyFixture.plan,
    validatedSelection: policyFixture.validatedSelection,
    releaseStepActionID: policyFixture.releaseAction.id,
    fileObjects: [
      RuntimeReleaseExpectedFileObject(
        graphFileObjectID: "file",
        identity: fixture.fileIdentity,
        owners: [owner],
        linkCount: 1,
        cloneIdentity: nil)
    ],
    groups: [
      RuntimeReleaseExpectedGroup(
        allocationGroupID: "group",
        ownerGraphFileObjectIDs: ["file"],
        ownerFileObjects: [fixture.fileIdentity],
        cloneIdentity: nil,
        cloneRefCount: nil,
        snapshotDevice: fixture.rootIdentity.device)
    ],
    volumeDevices: [fixture.rootIdentity.device])
  let baseKernel = nonCloneKernel(snapshot: .known(false))
  let rootIdentity = fixture.rootIdentity
  let authority = testAuthority(
    kernel: RuntimeReleaseTopologyKernel(
      descriptorIdentity: baseKernel.descriptorIdentity,
      item: baseKernel.item,
      snapshotBlocker: baseKernel.snapshotBlocker,
      pathAccessPolicy: baseKernel.pathAccessPolicy,
      descriptorAccessPolicy: { descriptor, livePolicy in
        let identity = baseKernel.descriptorIdentity(descriptor, livePolicy)
        guard case .known(let identity) = identity else {
          return identity.map { _ in try! testingDescriptorAccessPolicy() }
        }
        let seal =
          identity == rootIdentity
          ? try! topologyRootSeal() : try! topologyCandidateSeal()
        return .known(try! descriptorAccessPolicy(seal))
      }))
  let lease = try authority.bind(
    plan: plan,
    executionEpochNonce: UUID(),
    validForNanoseconds: 100,
    policy: policy,
    owners: [
      BoundRuntimeReleaseOwnerDescriptor(
        slot: owner.slot,
        rootFileDescriptor: fixture.rootDescriptor,
        parentFileDescriptor: fixture.parentDescriptor,
        fileDescriptor: fixture.fileDescriptor)
    ],
    volumes: [
      BoundRuntimeReleaseVolumeDescriptor(
        expectedDevice: fixture.rootIdentity.device,
        rootFileDescriptor: fixture.rootDescriptor)
    ])

  let report = try authority.collect(lease)
  #expect(report.topologyMatchesExpected == .known(true))
  #expect(plan.planHash == policyFixture.plan.planHash)
}

@Test func directoryCandidateRejectsDescendantNamespaceEscape() throws {
  let policy = try materializationPolicy()
  let fixture = try NestedReleaseTopologyFixture(policy: policy)
  let action = try actionID(14)
  let escapedNamespace = try RuntimeReleaseOwnerNamespaceBinding(
    link: FileOwnerLink(candidateID: "cache", path: try rawTarget(["outside", "leaf"])),
    actionID: action,
    rawRoot: try RawRootPath(absoluteBytes: Data("/fixture".utf8)),
    rootIdentity: fixture.rootIdentity,
    rootSeal: try topologyRootSeal(),
    parentChain: [fixture.parentIdentity],
    parentSeals: [try topologyCandidateSeal()],
    targetIdentity: fixture.fileIdentity,
    inheritedProviderBoundaryByComponent: [false, false])

  #expect(throws: RuntimeReleaseTopologyPlanError.ownerBindingMismatch) {
    try RuntimeReleaseTopologyExpectedPlan(
      testingPlanHash: digest(14),
      candidateActions: [
        RuntimeReleaseCandidateActionBinding(
          candidateID: "cache",
          actionID: action,
          rawRoot: try RawRootPath(absoluteBytes: Data("/fixture".utf8)),
          targetPath: try rawTarget(["nested"]),
          rootIdentity: fixture.rootIdentity,
          parentChain: [],
          targetIdentity: fixture.parentIdentity,
          inheritedProviderBoundaryByComponent: [false])
      ],
      fileObjects: [
        RuntimeReleaseExpectedFileObject(
          graphFileObjectID: "file",
          identity: fixture.fileIdentity,
          owners: [RuntimeReleaseExpectedOwner(namespace: escapedNamespace)],
          linkCount: 1,
          cloneIdentity: nil)
      ],
      groups: [
        RuntimeReleaseExpectedGroup(
          allocationGroupID: "group",
          ownerGraphFileObjectIDs: ["file"],
          ownerFileObjects: [fixture.fileIdentity],
          cloneIdentity: nil,
          cloneRefCount: nil,
          snapshotDevice: fixture.rootIdentity.device)
      ],
      volumeDevices: [fixture.rootIdentity.device])
  }
}

@Test func validatedSelectionFromAnotherImmutablePlanCannotSubstituteTopology() throws {
  let policy = try materializationPolicy()
  let fixture = try NestedReleaseTopologyFixture(policy: policy)
  let first = try releasePlanFixture(
    rootIdentity: fixture.rootIdentity,
    candidateIdentity: fixture.parentIdentity,
    fileIdentity: fixture.fileIdentity,
    ownerPath: ["nested", "leaf"])
  let second = try releasePlanFixture(
    rootIdentity: fixture.rootIdentity,
    candidateIdentity: fixture.parentIdentity,
    fileIdentity: fixture.fileIdentity,
    ownerPath: ["nested", "other"])
  let substitutedNamespace = try RuntimeReleaseOwnerNamespaceBinding(
    link: FileOwnerLink(candidateID: "cache", path: try rawTarget(["nested", "other"])),
    actionID: second.ownerAction.id,
    rawRoot: try RawRootPath(absoluteBytes: Data("/fixture".utf8)),
    rootIdentity: fixture.rootIdentity,
    rootSeal: try topologyRootSeal(),
    parentChain: [fixture.parentIdentity],
    parentSeals: [try topologyCandidateSeal()],
    targetIdentity: fixture.fileIdentity,
    inheritedProviderBoundaryByComponent: [false, false])

  #expect(throws: RuntimeReleaseTopologyPlanError.staleValidatedSelection) {
    try RuntimeReleaseTopologyExpectedPlan(
      plan: first.plan,
      validatedSelection: second.validatedSelection,
      releaseStepActionID: second.releaseAction.id,
      fileObjects: [
        RuntimeReleaseExpectedFileObject(
          graphFileObjectID: "file",
          identity: fixture.fileIdentity,
          owners: [RuntimeReleaseExpectedOwner(namespace: substitutedNamespace)],
          linkCount: 1,
          cloneIdentity: nil)
      ],
      groups: [
        RuntimeReleaseExpectedGroup(
          allocationGroupID: "group",
          ownerGraphFileObjectIDs: ["file"],
          ownerFileObjects: [fixture.fileIdentity],
          cloneIdentity: nil,
          cloneRefCount: nil,
          snapshotDevice: fixture.rootIdentity.device)
      ],
      volumeDevices: [fixture.rootIdentity.device])
  }
}

@Test func topologyArraysFromAnotherPlanCannotSubstituteAnExactSelection() throws {
  let policy = try materializationPolicy()
  let fixture = try NestedReleaseTopologyFixture(policy: policy)
  let first = try releasePlanFixture(
    rootIdentity: fixture.rootIdentity,
    candidateIdentity: fixture.parentIdentity,
    fileIdentity: fixture.fileIdentity,
    ownerPath: ["nested", "leaf"])
  let substitutedNamespace = try RuntimeReleaseOwnerNamespaceBinding(
    link: FileOwnerLink(candidateID: "cache", path: try rawTarget(["nested", "other"])),
    actionID: first.ownerAction.id,
    rawRoot: try RawRootPath(absoluteBytes: Data("/fixture".utf8)),
    rootIdentity: fixture.rootIdentity,
    rootSeal: try topologyRootSeal(),
    parentChain: [fixture.parentIdentity],
    parentSeals: [try topologyCandidateSeal()],
    targetIdentity: fixture.fileIdentity,
    inheritedProviderBoundaryByComponent: [false, false])

  #expect(throws: RuntimeReleaseTopologyPlanError.releaseMembershipMismatch) {
    try RuntimeReleaseTopologyExpectedPlan(
      plan: first.plan,
      validatedSelection: first.validatedSelection,
      releaseStepActionID: first.releaseAction.id,
      fileObjects: [
        RuntimeReleaseExpectedFileObject(
          graphFileObjectID: "file",
          identity: fixture.fileIdentity,
          owners: [
            RuntimeReleaseExpectedOwner(namespace: substitutedNamespace)
          ],
          linkCount: 1,
          cloneIdentity: nil)
      ],
      groups: [
        RuntimeReleaseExpectedGroup(
          allocationGroupID: "group",
          ownerGraphFileObjectIDs: ["file"],
          ownerFileObjects: [fixture.fileIdentity],
          cloneIdentity: nil,
          cloneRefCount: nil,
          snapshotDevice: fixture.rootIdentity.device)
      ],
      volumeDevices: [fixture.rootIdentity.device])
  }
}

@Test func productionTopologyReceiptBindsTheValidatedOverlayAndReleaseStep() throws {
  let policy = try materializationPolicy()
  let fixture = try NestedReleaseTopologyFixture(policy: policy)
  let policyFixture = try releasePlanFixture(
    rootIdentity: fixture.rootIdentity,
    candidateIdentity: fixture.parentIdentity,
    fileIdentity: fixture.fileIdentity,
    ownerPath: ["nested", "leaf"])
  let namespace = try RuntimeReleaseOwnerNamespaceBinding(
    link: FileOwnerLink(candidateID: "cache", path: try rawTarget(["nested", "leaf"])),
    actionID: policyFixture.ownerAction.id,
    rawRoot: try RawRootPath(absoluteBytes: Data("/fixture".utf8)),
    rootIdentity: fixture.rootIdentity,
    rootSeal: try topologyRootSeal(),
    parentChain: [fixture.parentIdentity],
    parentSeals: [try topologyCandidateSeal()],
    targetIdentity: fixture.fileIdentity,
    inheritedProviderBoundaryByComponent: [false, false])
  let file = RuntimeReleaseExpectedFileObject(
    graphFileObjectID: "file",
    identity: fixture.fileIdentity,
    owners: [RuntimeReleaseExpectedOwner(namespace: namespace)],
    linkCount: 1,
    cloneIdentity: nil)
  let group = RuntimeReleaseExpectedGroup(
    allocationGroupID: "group",
    ownerGraphFileObjectIDs: ["file"],
    ownerFileObjects: [fixture.fileIdentity],
    cloneIdentity: nil,
    cloneRefCount: nil,
    snapshotDevice: fixture.rootIdentity.device)
  let plan = try RuntimeReleaseTopologyExpectedPlan(
    plan: policyFixture.plan,
    validatedSelection: policyFixture.validatedSelection,
    releaseStepActionID: policyFixture.releaseAction.id,
    fileObjects: [file],
    groups: [group],
    volumeDevices: [fixture.rootIdentity.device])
  let unboundFixturePlan = try RuntimeReleaseTopologyExpectedPlan(
    testingPlanHash: policyFixture.plan.planHash,
    candidateActions: plan.candidateActions,
    fileObjects: [file],
    groups: [group],
    volumeDevices: [fixture.rootIdentity.device])

  #expect(plan.validatedOverlayHash == policyFixture.validatedSelection.overlayHash)
  #expect(plan.releaseStepActionID == policyFixture.releaseAction.id)
  #expect(plan.topologyBindingHash != unboundFixturePlan.topologyBindingHash)
}

@Test func planBoundClonePresenceCannotBeOmittedOrPartiallySupplied() throws {
  let policy = try materializationPolicy()
  let fixture = try NestedReleaseTopologyFixture(policy: policy)
  let secondIdentity = RuntimeReleaseFileObjectIdentity(
    device: fixture.fileIdentity.device,
    fileID: fixture.fileIdentity.fileID &+ 1,
    objectType: .regularFile)
  let identities = [fixture.fileIdentity, secondIdentity]
  let ownerPaths = [["nested", "first"], ["nested", "second"]]
  let graphFileIDs = ["file-0", "file-1"]
  let policyFixture = try releasePlanFixture(
    rootIdentity: fixture.rootIdentity,
    candidateIdentity: fixture.parentIdentity,
    ownerPaths: ownerPaths,
    fileIdentities: identities,
    cloneIdentity: ReleaseCloneIdentity(
      device: fixture.fileIdentity.device, cloneID: 700),
    cloneRefCount: 2)
  let clone = RuntimeReleaseCloneIdentity(device: fixture.fileIdentity.device, cloneID: 700)
  let cloneFiles = try planBoundRuntimeFiles(
    graphFileIDs: graphFileIDs,
    ownerPaths: ownerPaths,
    actionID: policyFixture.ownerAction.id,
    rootIdentity: fixture.rootIdentity,
    candidateIdentity: fixture.parentIdentity,
    fileIdentities: identities,
    cloneIdentity: clone)

  #expect(throws: RuntimeReleaseTopologyPlanError.releaseMembershipMismatch) {
    try RuntimeReleaseTopologyExpectedPlan(
      plan: policyFixture.plan,
      validatedSelection: policyFixture.validatedSelection,
      releaseStepActionID: policyFixture.releaseAction.id,
      fileObjects: try planBoundRuntimeFiles(
        graphFileIDs: graphFileIDs,
        ownerPaths: ownerPaths,
        actionID: policyFixture.ownerAction.id,
        rootIdentity: fixture.rootIdentity,
        candidateIdentity: fixture.parentIdentity,
        fileIdentities: identities,
        cloneIdentity: nil),
      groups: [
        RuntimeReleaseExpectedGroup(
          allocationGroupID: "group",
          ownerGraphFileObjectIDs: graphFileIDs,
          ownerFileObjects: identities,
          cloneIdentity: nil,
          cloneRefCount: nil,
          snapshotDevice: fixture.rootIdentity.device)
      ],
      volumeDevices: [fixture.rootIdentity.device])
  }

  #expect(throws: RuntimeReleaseTopologyPlanError.invalidCloneBinding) {
    try RuntimeReleaseTopologyExpectedPlan(
      plan: policyFixture.plan,
      validatedSelection: policyFixture.validatedSelection,
      releaseStepActionID: policyFixture.releaseAction.id,
      fileObjects: cloneFiles,
      groups: [
        RuntimeReleaseExpectedGroup(
          allocationGroupID: "group",
          ownerGraphFileObjectIDs: graphFileIDs,
          ownerFileObjects: identities,
          cloneIdentity: clone,
          cloneRefCount: nil,
          snapshotDevice: fixture.rootIdentity.device)
      ],
      volumeDevices: [fixture.rootIdentity.device])
  }

  #expect(throws: RuntimeReleaseTopologyPlanError.invalidCloneBinding) {
    try RuntimeReleaseTopologyExpectedPlan(
      plan: policyFixture.plan,
      validatedSelection: policyFixture.validatedSelection,
      releaseStepActionID: policyFixture.releaseAction.id,
      fileObjects: cloneFiles,
      groups: [
        RuntimeReleaseExpectedGroup(
          allocationGroupID: "group",
          ownerGraphFileObjectIDs: graphFileIDs,
          ownerFileObjects: identities,
          cloneIdentity: clone,
          cloneRefCount: 3,
          snapshotDevice: fixture.rootIdentity.device)
      ],
      volumeDevices: [fixture.rootIdentity.device])
  }

  let substitutedCloneID = RuntimeReleaseCloneIdentity(
    device: fixture.fileIdentity.device, cloneID: 701)
  #expect(throws: RuntimeReleaseTopologyPlanError.releaseMembershipMismatch) {
    try RuntimeReleaseTopologyExpectedPlan(
      plan: policyFixture.plan,
      validatedSelection: policyFixture.validatedSelection,
      releaseStepActionID: policyFixture.releaseAction.id,
      fileObjects: try planBoundRuntimeFiles(
        graphFileIDs: graphFileIDs,
        ownerPaths: ownerPaths,
        actionID: policyFixture.ownerAction.id,
        rootIdentity: fixture.rootIdentity,
        candidateIdentity: fixture.parentIdentity,
        fileIdentities: identities,
        cloneIdentity: substitutedCloneID),
      groups: [
        RuntimeReleaseExpectedGroup(
          allocationGroupID: "group",
          ownerGraphFileObjectIDs: graphFileIDs,
          ownerFileObjects: identities,
          cloneIdentity: substitutedCloneID,
          cloneRefCount: 2,
          snapshotDevice: fixture.rootIdentity.device)
      ],
      volumeDevices: [fixture.rootIdentity.device])
  }

  let substitutedDeviceClone = RuntimeReleaseCloneIdentity(
    device: fixture.fileIdentity.device &+ 1, cloneID: 700)
  #expect(throws: RuntimeReleaseTopologyPlanError.invalidCloneBinding) {
    try RuntimeReleaseTopologyExpectedPlan(
      plan: policyFixture.plan,
      validatedSelection: policyFixture.validatedSelection,
      releaseStepActionID: policyFixture.releaseAction.id,
      fileObjects: try planBoundRuntimeFiles(
        graphFileIDs: graphFileIDs,
        ownerPaths: ownerPaths,
        actionID: policyFixture.ownerAction.id,
        rootIdentity: fixture.rootIdentity,
        candidateIdentity: fixture.parentIdentity,
        fileIdentities: identities,
        cloneIdentity: substitutedDeviceClone),
      groups: [
        RuntimeReleaseExpectedGroup(
          allocationGroupID: "group",
          ownerGraphFileObjectIDs: graphFileIDs,
          ownerFileObjects: identities,
          cloneIdentity: substitutedDeviceClone,
          cloneRefCount: 2,
          snapshotDevice: fixture.rootIdentity.device)
      ],
      volumeDevices: [fixture.rootIdentity.device])
  }

  let valid = try RuntimeReleaseTopologyExpectedPlan(
    plan: policyFixture.plan,
    validatedSelection: policyFixture.validatedSelection,
    releaseStepActionID: policyFixture.releaseAction.id,
    fileObjects: cloneFiles,
    groups: [
      RuntimeReleaseExpectedGroup(
        allocationGroupID: "group",
        ownerGraphFileObjectIDs: graphFileIDs,
        ownerFileObjects: identities,
        cloneIdentity: clone,
        cloneRefCount: 2,
        snapshotDevice: fixture.rootIdentity.device)
    ],
    volumeDevices: [fixture.rootIdentity.device])
  #expect(valid.groups.first?.cloneIdentity == clone)
}

@Test func planBoundSingleObjectGroupRemainsALegalNonClone() throws {
  let policy = try materializationPolicy()
  let fixture = try NestedReleaseTopologyFixture(policy: policy)
  let policyFixture = try releasePlanFixture(
    rootIdentity: fixture.rootIdentity,
    candidateIdentity: fixture.parentIdentity,
    fileIdentity: fixture.fileIdentity,
    ownerPath: ["nested", "leaf"])
  let files = try planBoundRuntimeFiles(
    graphFileIDs: ["file"],
    ownerPaths: [["nested", "leaf"]],
    actionID: policyFixture.ownerAction.id,
    rootIdentity: fixture.rootIdentity,
    candidateIdentity: fixture.parentIdentity,
    fileIdentities: [fixture.fileIdentity],
    cloneIdentity: nil)

  let plan = try RuntimeReleaseTopologyExpectedPlan(
    plan: policyFixture.plan,
    validatedSelection: policyFixture.validatedSelection,
    releaseStepActionID: policyFixture.releaseAction.id,
    fileObjects: files,
    groups: [
      RuntimeReleaseExpectedGroup(
        allocationGroupID: "group",
        ownerGraphFileObjectIDs: ["file"],
        ownerFileObjects: [fixture.fileIdentity],
        cloneIdentity: nil,
        cloneRefCount: nil,
        snapshotDevice: fixture.rootIdentity.device)
    ],
    volumeDevices: [fixture.rootIdentity.device])

  #expect(plan.groups.first?.cloneIdentity == nil)
  #expect(plan.groups.first?.cloneRefCount == nil)
}

@Test func planBoundDescendantNamespaceRejectsEveryCallerSuppliedSubstitution() throws {
  let policy = try materializationPolicy()
  let fixture = try NestedReleaseTopologyFixture(policy: policy)
  let intermediate = RuntimeReleaseFileObjectIdentity(
    device: fixture.parentIdentity.device,
    fileID: fixture.parentIdentity.fileID &+ 100,
    objectType: .directory)
  let ownerPath = ["nested", "intermediate", "leaf"]
  let policyFixture = try releasePlanFixture(
    rootIdentity: fixture.rootIdentity,
    candidateIdentity: fixture.parentIdentity,
    ownerPaths: [ownerPath],
    fileIdentities: [fixture.fileIdentity],
    ownerParentChains: [[fixture.parentIdentity, intermediate]],
    cloneIdentity: nil,
    cloneRefCount: 1)

  func expectedPlan(
    graphFileID: String = "file",
    intermediateIdentity: RuntimeReleaseFileObjectIdentity = intermediate,
    intermediateSeal: NamespaceSealEvidence = topologyDescendantSeal(),
    leafIdentity: RuntimeReleaseFileObjectIdentity = fixture.fileIdentity,
    inheritedProviderBoundary: [Bool] = [false, false, false]
  ) throws -> RuntimeReleaseTopologyExpectedPlan {
    let files = try planBoundRuntimeFiles(
      graphFileIDs: [graphFileID],
      ownerPaths: [ownerPath],
      actionID: policyFixture.ownerAction.id,
      rootIdentity: fixture.rootIdentity,
      candidateIdentity: fixture.parentIdentity,
      fileIdentities: [leafIdentity],
      cloneIdentity: nil,
      ownerParentChains: [[fixture.parentIdentity, intermediateIdentity]],
      ownerParentSeals: [[try topologyCandidateSeal(), intermediateSeal]],
      inheritedProviderBoundaries: [inheritedProviderBoundary])
    return try RuntimeReleaseTopologyExpectedPlan(
      plan: policyFixture.plan,
      validatedSelection: policyFixture.validatedSelection,
      releaseStepActionID: policyFixture.releaseAction.id,
      fileObjects: files,
      groups: [
        RuntimeReleaseExpectedGroup(
          allocationGroupID: "group",
          ownerGraphFileObjectIDs: [graphFileID],
          ownerFileObjects: [leafIdentity],
          cloneIdentity: nil,
          cloneRefCount: nil,
          snapshotDevice: fixture.rootIdentity.device)
      ],
      volumeDevices: [fixture.rootIdentity.device])
  }

  _ = try expectedPlan()

  let replacedDescendant = RuntimeReleaseFileObjectIdentity(
    device: intermediate.device,
    fileID: intermediate.fileID &+ 1,
    objectType: .directory)
  #expect(throws: RuntimeReleaseTopologyPlanError.releaseMembershipMismatch) {
    try expectedPlan(intermediateIdentity: replacedDescendant)
  }

  let insertedMount = RuntimeReleaseFileObjectIdentity(
    device: intermediate.device &+ 1,
    fileID: intermediate.fileID,
    objectType: .directory)
  #expect(throws: RuntimeReleaseTopologyPlanError.releaseMembershipMismatch) {
    try expectedPlan(
      intermediateIdentity: insertedMount,
      intermediateSeal: topologyDescendantSeal(mountIdentity: .known("inserted-volume")))
  }

  #expect(throws: RuntimeReleaseTopologyPlanError.releaseMembershipMismatch) {
    try expectedPlan(
      intermediateSeal: topologyDescendantSeal(
        providerBoundary: .known(.fileProviderManaged)),
      inheritedProviderBoundary: [false, false, true])
  }

  #expect(throws: RuntimeReleaseTopologyPlanError.releaseMembershipMismatch) {
    try expectedPlan(
      intermediateSeal: topologyDescendantSeal(
        accessPolicy: .known("owner-private-changed")))
  }

  let replacedLeaf = RuntimeReleaseFileObjectIdentity(
    device: fixture.fileIdentity.device,
    fileID: fixture.fileIdentity.fileID &+ 1,
    objectType: .regularFile)
  #expect(throws: RuntimeReleaseTopologyPlanError.releaseMembershipMismatch) {
    try expectedPlan(graphFileID: "relabeled-file", leafIdentity: replacedLeaf)
  }
}

@Test func malformedDescendantOwnerIdentityChainIsRejectedWithoutDeferredFailure() throws {
  let policy = try materializationPolicy()
  let fixture = try NestedReleaseTopologyFixture(policy: policy)

  #expect(throws: RuntimeReleaseTopologyPlanError.ownerBindingMismatch) {
    try RuntimeReleaseOwnerNamespaceBinding(
      link: FileOwnerLink(
        candidateID: "cache", path: try rawTarget(["nested", "leaf"])),
      actionID: try actionID(18),
      rawRoot: try RawRootPath(absoluteBytes: Data("/fixture".utf8)),
      rootIdentity: fixture.fileIdentity,
      rootSeal: try topologyRootSeal(),
      parentChain: [fixture.parentIdentity],
      parentSeals: [try topologyCandidateSeal()],
      targetIdentity: fixture.fileIdentity,
      inheritedProviderBoundaryByComponent: [false, false])
  }

  #expect(throws: RuntimeReleaseTopologyPlanError.ownerBindingMismatch) {
    try RuntimeReleaseOwnerNamespaceBinding(
      link: FileOwnerLink(
        candidateID: "cache", path: try rawTarget(["nested", "leaf"])),
      actionID: try actionID(19),
      rawRoot: try RawRootPath(absoluteBytes: Data("/fixture".utf8)),
      rootIdentity: fixture.rootIdentity,
      rootSeal: try topologyRootSeal(),
      parentChain: [fixture.fileIdentity],
      parentSeals: [try topologyCandidateSeal()],
      targetIdentity: fixture.fileIdentity,
      inheritedProviderBoundaryByComponent: [false, false])
  }
}

@Test func knownGenerationCannotBeSatisfiedByGenerationlessLiveProbe() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let expectedObject = RuntimeReleaseFileObjectIdentity(
    device: fixture.firstIdentity.device,
    fileID: fixture.firstIdentity.fileID,
    objectType: fixture.firstIdentity.objectType,
    generation: 42)
  let action = try actionID(10)
  let slot = try RuntimeReleaseNamespaceSlotIdentity(
    rootIdentity: fixture.rootIdentity,
    parentIdentity: fixture.rootIdentity,
    rawBasename: Data("first".utf8),
    objectIdentity: expectedObject)
  let owner = RuntimeReleaseExpectedOwner(
    link: try ownerLink("generation-candidate", "first"),
    slot: slot,
    actionID: action)
  let plan = try RuntimeReleaseTopologyExpectedPlan(
    testingPlanHash: digest(13),
    candidateActions: [
      try actionBinding(
        candidateID: "generation-candidate",
        actionID: action,
        root: fixture.rootIdentity,
        target: ["first"],
        object: expectedObject)
    ],
    fileObjects: [
      RuntimeReleaseExpectedFileObject(
        identity: expectedObject,
        owners: [owner],
        linkCount: 1,
        cloneIdentity: nil)
    ],
    groups: [
      RuntimeReleaseExpectedGroup(
        allocationGroupID: "generation",
        ownerFileObjects: [expectedObject],
        cloneIdentity: nil,
        cloneRefCount: nil,
        snapshotDevice: fixture.rootIdentity.device)
    ],
    volumeDevices: [fixture.rootIdentity.device])
  let authority = testAuthority(kernel: nonCloneKernel(snapshot: .known(false)))

  #expect(
    throws: RuntimeReleaseTopologyAuthorityError.descriptorIdentityUnknown(
      .unavailableViaPublicAPI)
  ) {
    try authority.bind(
      plan: plan,
      executionEpochNonce: UUID(),
      validForNanoseconds: 100,
      policy: policy,
      owners: [
        BoundRuntimeReleaseOwnerDescriptor(
          slot: slot,
          rootFileDescriptor: fixture.rootDescriptor,
          parentFileDescriptor: fixture.rootDescriptor,
          fileDescriptor: fixture.firstDescriptor)
      ],
      volumes: [
        BoundRuntimeReleaseVolumeDescriptor(
          expectedDevice: fixture.rootIdentity.device,
          rootFileDescriptor: fixture.rootDescriptor)
      ])
  }
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
      testingPlanHash: digest(1), candidateActions: [], fileObjects: [], groups: [],
      volumeDevices: [])
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
    link: try ownerLink("alias-candidate", "first"),
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
      testingPlanHash: digest(1),
      candidateActions: [
        try actionBinding(
          candidateID: "first-candidate",
          actionID: firstAction,
          root: fixture.rootIdentity,
          target: ["first"],
          object: fixture.firstIdentity),
        try actionBinding(
          candidateID: "alias-candidate",
          actionID: secondAction,
          root: fixture.rootIdentity,
          target: ["first"],
          object: fixture.secondIdentity),
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

@Test func duplicateGraphMembershipCannotAliasOneRuntimeFile() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let owner = RuntimeReleaseExpectedOwner(
    link: try ownerLink("first-candidate", "first"),
    slot: try namespaceSlot(
      root: fixture.rootIdentity,
      name: "first",
      object: fixture.firstIdentity),
    actionID: try actionID(20))

  #expect(throws: RuntimeReleaseTopologyPlanError.incompleteGroupCoverage) {
    try RuntimeReleaseTopologyExpectedPlan(
      testingPlanHash: digest(20),
      candidateActions: [
        try actionBinding(
          candidateID: "first-candidate",
          actionID: owner.actionID,
          root: fixture.rootIdentity,
          target: ["first"],
          object: fixture.firstIdentity)
      ],
      fileObjects: [
        RuntimeReleaseExpectedFileObject(
          graphFileObjectID: "file",
          identity: fixture.firstIdentity,
          owners: [owner],
          linkCount: 1,
          cloneIdentity: nil)
      ],
      groups: [
        RuntimeReleaseExpectedGroup(
          allocationGroupID: "group",
          ownerGraphFileObjectIDs: ["file", "file"],
          ownerFileObjects: [fixture.firstIdentity],
          cloneIdentity: nil,
          cloneRefCount: nil,
          snapshotDevice: fixture.rootIdentity.device)
      ],
      volumeDevices: [fixture.rootIdentity.device])
  }
}

@Test func snapshotVolumeMustOwnEveryRuntimeFileInTheGroup() throws {
  let policy = try materializationPolicy()
  let fixture = try RealReleaseTopologyFixture(policy: policy)
  let owner = RuntimeReleaseExpectedOwner(
    link: try ownerLink("first-candidate", "first"),
    slot: try namespaceSlot(
      root: fixture.rootIdentity,
      name: "first",
      object: fixture.firstIdentity),
    actionID: try actionID(21))
  let foreignDevice = fixture.firstIdentity.device &+ 1

  #expect(throws: RuntimeReleaseTopologyPlanError.incompleteGroupCoverage) {
    try RuntimeReleaseTopologyExpectedPlan(
      testingPlanHash: digest(21),
      candidateActions: [
        try actionBinding(
          candidateID: "first-candidate",
          actionID: owner.actionID,
          root: fixture.rootIdentity,
          target: ["first"],
          object: fixture.firstIdentity)
      ],
      fileObjects: [
        RuntimeReleaseExpectedFileObject(
          graphFileObjectID: "file",
          identity: fixture.firstIdentity,
          owners: [owner],
          linkCount: 1,
          cloneIdentity: nil)
      ],
      groups: [
        RuntimeReleaseExpectedGroup(
          allocationGroupID: "group",
          ownerGraphFileObjectIDs: ["file"],
          ownerFileObjects: [fixture.firstIdentity],
          cloneIdentity: nil,
          cloneRefCount: nil,
          snapshotDevice: foreignDevice)
      ],
      volumeDevices: [foreignDevice])
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
    testingPlanHash: setup.plan.planHash,
    candidateActions: setup.plan.candidateActions,
    fileObjects: setup.plan.fileObjects,
    groups: renamedGroups,
    volumeDevices: setup.plan.volumeDevices)
  #expect(renamed.topologyBindingHash != setup.plan.topologyBindingHash)

  let firstIdentity = setup.plan.fileObjects[0].identity
  #expect(throws: RuntimeReleaseTopologyPlanError.invalidCloneBinding) {
    try RuntimeReleaseTopologyExpectedPlan(
      testingPlanHash: setup.plan.planHash,
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
  let actionIDs: [ActionID]
}

private struct CloneSetup {
  let plan: RuntimeReleaseTopologyExpectedPlan
  let descriptors: [BoundRuntimeReleaseOwnerDescriptor]
  let clone: RuntimeReleaseCloneIdentity
  let actionIDs: [ActionID]
}

private func hardlinkSetup(fixture: RealReleaseTopologyFixture) throws -> HardlinkSetup {
  let firstAction = try actionID(1)
  let hardlinkAction = try actionID(2)
  let firstSlot = try namespaceSlot(
    root: fixture.rootIdentity, name: "first", object: fixture.firstIdentity)
  let hardlinkSlot = try namespaceSlot(
    root: fixture.rootIdentity, name: "hardlink", object: fixture.firstIdentity)
  let firstOwner = RuntimeReleaseExpectedOwner(
    link: try ownerLink("first-cache", "first"), slot: firstSlot, actionID: firstAction)
  let hardlinkOwner = RuntimeReleaseExpectedOwner(
    link: try ownerLink("hardlink-cache", "hardlink"),
    slot: hardlinkSlot,
    actionID: hardlinkAction)
  let plan = try RuntimeReleaseTopologyExpectedPlan(
    testingPlanHash: digest(1),
    candidateActions: [
      try actionBinding(
        candidateID: "first-cache",
        actionID: firstAction,
        root: fixture.rootIdentity,
        target: ["first"],
        object: fixture.firstIdentity),
      try actionBinding(
        candidateID: "hardlink-cache",
        actionID: hardlinkAction,
        root: fixture.rootIdentity,
        target: ["hardlink"],
        object: fixture.firstIdentity),
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
    actionIDs: [firstAction, hardlinkAction]
  )
}

private func cloneSetup(fixture: RealReleaseTopologyFixture) throws -> CloneSetup {
  let firstAction = try actionID(1)
  let hardlinkAction = try actionID(2)
  let secondAction = try actionID(3)
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
    link: try ownerLink("hardlink-cache", "hardlink"),
    slot: hardlinkSlot,
    actionID: hardlinkAction)
  let secondOwner = RuntimeReleaseExpectedOwner(
    link: try ownerLink("second-cache", "second"), slot: secondSlot, actionID: secondAction)
  let plan = try RuntimeReleaseTopologyExpectedPlan(
    testingPlanHash: digest(2),
    candidateActions: [
      try actionBinding(
        candidateID: "first-cache",
        actionID: firstAction,
        root: fixture.rootIdentity,
        target: ["first"],
        object: fixture.firstIdentity),
      try actionBinding(
        candidateID: "hardlink-cache",
        actionID: hardlinkAction,
        root: fixture.rootIdentity,
        target: ["hardlink"],
        object: fixture.firstIdentity),
      try actionBinding(
        candidateID: "second-cache",
        actionID: secondAction,
        root: fixture.rootIdentity,
        target: ["second"],
        object: fixture.secondIdentity),
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
    actionIDs: [firstAction, hardlinkAction, secondAction]
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

private func actionBinding(
  candidateID: String,
  actionID: ActionID,
  root: RuntimeReleaseFileObjectIdentity,
  target: [String],
  object: RuntimeReleaseFileObjectIdentity,
  parentChain: [RuntimeReleaseFileObjectIdentity] = [],
  inheritedProviderBoundaryByComponent: [Bool]? = nil
) throws -> RuntimeReleaseCandidateActionBinding {
  RuntimeReleaseCandidateActionBinding(
    candidateID: candidateID,
    actionID: actionID,
    rawRoot: try RawRootPath(absoluteBytes: Data("/fixture".utf8)),
    targetPath: try RawTargetPath(components: target.map { Data($0.utf8) }),
    rootIdentity: root,
    parentChain: parentChain,
    targetIdentity: object,
    inheritedProviderBoundaryByComponent: inheritedProviderBoundaryByComponent
      ?? Array(repeating: false, count: target.count)
  )
}

private func singleOwnerPlan(
  fixture: RealReleaseTopologyFixture,
  action: ActionID,
  actionTarget: [String],
  owner: RuntimeReleaseExpectedOwner,
  parentChain: [RuntimeReleaseFileObjectIdentity] = [],
  inheritedProviderBoundaryByComponent: [Bool]? = nil
) throws -> RuntimeReleaseTopologyExpectedPlan {
  try RuntimeReleaseTopologyExpectedPlan(
    testingPlanHash: digest(11),
    candidateActions: [
      try actionBinding(
        candidateID: owner.link.candidateID,
        actionID: action,
        root: fixture.rootIdentity,
        target: actionTarget,
        object: fixture.firstIdentity,
        parentChain: parentChain,
        inheritedProviderBoundaryByComponent: inheritedProviderBoundaryByComponent)
    ],
    fileObjects: [
      RuntimeReleaseExpectedFileObject(
        identity: fixture.firstIdentity,
        owners: [owner],
        linkCount: 1,
        cloneIdentity: nil)
    ],
    groups: [
      RuntimeReleaseExpectedGroup(
        allocationGroupID: "single-owner",
        ownerFileObjects: [fixture.firstIdentity],
        cloneIdentity: nil,
        cloneRefCount: nil,
        snapshotDevice: fixture.rootIdentity.device)
    ],
    volumeDevices: [fixture.rootIdentity.device])
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

private final class DescriptorAccessPolicyState: @unchecked Sendable {
  private let lock = NSLock()
  private var storage: RuntimeReleaseTopologyObservation<RuntimeReleaseDescriptorAccessPolicy>

  init(_ value: RuntimeReleaseTopologyObservation<RuntimeReleaseDescriptorAccessPolicy>) {
    storage = value
  }

  var value: RuntimeReleaseTopologyObservation<RuntimeReleaseDescriptorAccessPolicy> {
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

private final class PathAccessOrderRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var storage: [String] = []

  func record(_ event: String) {
    lock.lock()
    storage.append(event)
    lock.unlock()
  }

  var events: [String] {
    lock.lock()
    defer { lock.unlock() }
    return storage
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
    item: { parent, name, policy, inheritedProviderBoundary in
      let item = live.item(parent, name, policy, inheritedProviderBoundary)
      return RuntimeReleaseKernelItem(
        identity: item.identity,
        linkCount: item.linkCount,
        mayShareBlocks: .known(false),
        sharesAllBlocks: .absent,
        cloneID: .known(0),
        cloneRefCount: .absent,
        providerLocal: inheritedProviderBoundary ? .known(false) : (providerLocal ?? .known(true))
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
    item: { parent, name, policy, inheritedProviderBoundary in
      let item = live.item(parent, name, policy, inheritedProviderBoundary)
      return RuntimeReleaseKernelItem(
        identity: item.identity,
        linkCount: item.linkCount,
        mayShareBlocks: .known(true),
        sharesAllBlocks: .known(true),
        cloneID: .known(cloneID),
        cloneRefCount: .known(refCount),
        providerLocal: inheritedProviderBoundary ? .known(false) : .known(true)
      )
    },
    snapshotBlocker: { _, _ in snapshot }
  )
}

private func accessPolicyKernel(
  state: DescriptorAccessPolicyState,
  itemIdentity: RuntimeReleaseTopologyObservation<RuntimeReleaseFileObjectIdentity>? = nil
) -> RuntimeReleaseTopologyKernel {
  let base = nonCloneKernel(snapshot: .known(false))
  return RuntimeReleaseTopologyKernel(
    descriptorIdentity: base.descriptorIdentity,
    item: { parent, name, policy, inheritedProviderBoundary in
      let item = base.item(parent, name, policy, inheritedProviderBoundary)
      return RuntimeReleaseKernelItem(
        identity: itemIdentity ?? item.identity,
        linkCount: item.linkCount,
        mayShareBlocks: item.mayShareBlocks,
        sharesAllBlocks: item.sharesAllBlocks,
        cloneID: item.cloneID,
        cloneRefCount: item.cloneRefCount,
        providerLocal: item.providerLocal)
    },
    snapshotBlocker: base.snapshotBlocker,
    pathAccessPolicy: base.pathAccessPolicy,
    descriptorAccessPolicy: { _, _ in state.value })
}

private func inconsistentCloneKernel(
  mayShareBlocks: RuntimeReleaseTopologyObservation<Bool> = .known(false),
  cloneID: RuntimeReleaseTopologyObservation<UInt64>
) -> RuntimeReleaseTopologyKernel {
  let live = RuntimeReleaseTopologyKernel.live
  return RuntimeReleaseTopologyKernel(
    descriptorIdentity: live.descriptorIdentity,
    item: { parent, name, policy, inheritedProviderBoundary in
      let item = live.item(parent, name, policy, inheritedProviderBoundary)
      return RuntimeReleaseKernelItem(
        identity: item.identity,
        linkCount: item.linkCount,
        mayShareBlocks: mayShareBlocks,
        sharesAllBlocks: .absent,
        cloneID: cloneID,
        cloneRefCount: .absent,
        providerLocal: inheritedProviderBoundary ? .known(false) : .known(true)
      )
    },
    snapshotBlocker: { _, _ in .known(false) }
  )
}

private struct ReleasePlanFixture {
  let plan: ImmutablePlan
  let validatedSelection: ValidatedDecisionOverlay
  let ownerAction: ActionDefinition
  let releaseAction: ActionDefinition
}

private func releasePlanFixture(
  rootIdentity: RuntimeReleaseFileObjectIdentity,
  candidateIdentity: RuntimeReleaseFileObjectIdentity,
  fileIdentity: RuntimeReleaseFileObjectIdentity,
  ownerPath: [String]
) throws -> ReleasePlanFixture {
  try releasePlanFixture(
    rootIdentity: rootIdentity,
    candidateIdentity: candidateIdentity,
    ownerPaths: [ownerPath],
    fileIdentities: [fileIdentity],
    ownerParentChains: [[candidateIdentity]],
    cloneIdentity: nil,
    cloneRefCount: 1)
}

private func releasePlanFixture(
  rootIdentity: RuntimeReleaseFileObjectIdentity,
  candidateIdentity: RuntimeReleaseFileObjectIdentity,
  ownerPaths: [[String]],
  fileIdentities: [RuntimeReleaseFileObjectIdentity],
  ownerParentChains: [[RuntimeReleaseFileObjectIdentity]]? = nil,
  cloneIdentity: ReleaseCloneIdentity?,
  cloneRefCount: UInt32
) throws -> ReleasePlanFixture {
  let rawRoot = try RawRootPath(absoluteBytes: Data("/fixture".utf8))
  let facts = FrozenGlobalFacts(
    captureID: try digest(90),
    profile: "full",
    configuration: Data("release-topology-test".utf8),
    coverage: [
      GlobalCoverageFact(rawRoot: rawRoot, coverage: .complete, reasons: ["test-fixture"])
    ],
    semanticReferenceTimeSeconds: 100,
    policyVersion: "policy-1",
    schemaVersion: "schema-1")
  let seal = NamespaceSealEvidence(
    trustedNamespace: .ownerPrivate,
    accessPolicy: .known("owner-private"),
    aclDigest: .known(try digest(91)),
    providerBoundary: .known(.local),
    mountIdentity: .known("fixture-volume"))
  let targetPath = try rawTarget(["nested"])
  let namespace = try ProtectedNamespaceBinding(
    rawRoot: rawRoot,
    rootIdentity: policyIdentity(rootIdentity),
    rootSeal: seal,
    targetPath: targetPath,
    targetIdentity: policyIdentity(candidateIdentity),
    parentChain: [])
  let evidence = try FrozenEvidenceSnapshot(
    captureID: facts.captureID,
    globalFactsHash: facts.globalFactsHash,
    candidateID: "cache",
    namespaceBinding: namespace,
    identity: .known(policyIdentity(candidateIdentity)),
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
    contentProtection: .known(.requiredDigest(try digest(92))),
    aclDigest: .known(try digest(93)),
    targetMountIdentity: .known("fixture-volume"),
    removalForceRequirement: .known(.notRequired),
    quarantineCapability: .known(true),
    gitWorktree: nil,
    adapterScope: .genericRemove,
    additionalAdapterScopes: [.completeReleaseSetRemove(allocationGroupID: "group")],
    classificationClaims: ClassificationFacet.allCases.map { facet in
      ClassificationClaim(
        facet: facet,
        value: "known-\(facet.rawValue)",
        source: .genericFallback,
        evidenceKey: "fixture-\(facet.rawValue)")
    },
    semanticReferenceTimeSeconds: facts.semanticReferenceTimeSeconds,
    policyVersion: facts.policyVersion,
    schemaVersion: facts.schemaVersion)
  let evaluation = try OneVotePolicy.evaluate(
    OneVotePolicyInputs.build(evidence: evidence, globalFacts: facts))
  let ownerAction = try ActionDefinition.build(
    prototype: ActionPrototype.build(request: .genericRemove, evidence: evidence),
    evidence: evidence,
    globalFacts: facts,
    prerequisites: [],
    evaluation: evaluation,
    displayMetrics: ActionDisplayMetrics(
      immediateReclaimBytes: .known(1),
      inactiveDurationSeconds: .known(10),
      rebuildCost: .known(1),
      cleanupCost: .known(1),
      canonicalRawPath: Data("nested".utf8)))
  let candidate = try StorageCandidate(
    id: "cache", evidence: evidence, immediatePrivateBytes: .known(1))
  let candidateTargetSeal = NamespaceSealEvidence(
    trustedNamespace: .ownerPrivate,
    accessPolicy: evidence.accessPolicy,
    aclDigest: evidence.aclDigest,
    providerBoundary: evidence.providerState,
    mountIdentity: evidence.targetMountIdentity)
  let resolvedParentChains =
    ownerParentChains
    ?? Array(repeating: [candidateIdentity], count: ownerPaths.count)
  guard ownerPaths.count == fileIdentities.count,
    resolvedParentChains.count == ownerPaths.count
  else { throw ReleaseTopologyTestError.identity }
  let graphFileIDs = ownerPaths.indices.map { index in
    ownerPaths.count == 1 ? "file" : "file-\(index)"
  }
  let graph = try StorageReleaseGraph(
    globalFacts: facts,
    candidates: [candidate],
    fileObjects: try zip(
      zip(zip(graphFileIDs, ownerPaths), fileIdentities), resolvedParentChains
    ).map {
      value, parentChain in
      let (pair, fileIdentity) = value
      let (fileID, ownerPath) = pair
      guard parentChain.count == ownerPath.count - 1,
        parentChain.first == candidateIdentity
      else { throw ReleaseTopologyTestError.identity }
      let link = FileOwnerLink(candidateID: "cache", path: try rawTarget(ownerPath))
      let ownerNamespace = try ProtectedNamespaceBinding(
        rawRoot: rawRoot,
        rootIdentity: policyIdentity(rootIdentity),
        rootSeal: seal,
        targetPath: try rawTarget(ownerPath),
        targetIdentity: policyIdentity(fileIdentity),
        parentChain: try parentChain.indices.map { parentIndex in
          ParentNamespaceBinding(
            relativePath: try rawTarget(Array(ownerPath.prefix(parentIndex + 1))),
            identity: policyIdentity(parentChain[parentIndex]),
            seal: parentIndex == 0 ? candidateTargetSeal : topologyDescendantSeal())
        })
      return FileObjectNode(
        provenance: GraphObservationProvenance(globalFacts: facts),
        id: fileID,
        observedOwners: [link],
        ownerNamespaces: [
          FileOwnerNamespaceExpectation(link: link, namespaceBinding: ownerNamespace)
        ],
        linkCount: .known(1))
    },
    allocationGroups: [
      AllocationGroupNode(
        provenance: GraphObservationProvenance(globalFacts: facts),
        id: "group",
        ownerFileObjectIDs: graphFileIDs,
        cloneIdentity: cloneIdentity.map(Observation.known) ?? .absent,
        cloneRefCount: .known(cloneRefCount),
        sharedBytes: .known(100),
        snapshotBlocker: .known(false))
    ])
  let releaseBundle = try PlanReleaseSet.buildAll(
    from: graph.evaluate(
      selectedCandidateActions: [
        CandidateActionBinding(candidateID: "cache", action: ownerAction)
      ]),
    candidateActions: [CandidateActionBinding(candidateID: "cache", action: ownerAction)])
  let releaseSet = try #require(releaseBundle.releaseSets.first)
  let releaseAction = try ActionDefinition.build(
    prototype: ActionPrototype.build(
      request: .completeReleaseSetRemove(binding: releaseSet.actionBinding),
      evidence: evidence),
    evidence: evidence,
    globalFacts: facts,
    prerequisites: [ownerAction],
    evaluation: evaluation,
    displayMetrics: ActionDisplayMetrics(
      immediateReclaimBytes: .known(100),
      inactiveDurationSeconds: .known(10),
      rebuildCost: .known(1),
      cleanupCost: .known(1),
      canonicalRawPath: Data("nested".utf8)))
  let plan = try ImmutablePlan(
    policyVersion: facts.policyVersion,
    schemaVersion: facts.schemaVersion,
    globalFacts: facts,
    evidenceSnapshots: [evidence],
    actions: [ownerAction, releaseAction],
    releaseGraphBundle: releaseBundle)
  let overlay = DecisionOverlay.create(
    plan: plan,
    selectedActionIDs: [ownerAction.id, releaseAction.id],
    waiverConsents: [],
    userNotes: [])
  return ReleasePlanFixture(
    plan: plan,
    validatedSelection: try DecisionOverlayValidator.validate(overlay, against: plan),
    ownerAction: ownerAction,
    releaseAction: releaseAction)
}

private func rawTarget(_ components: [String]) throws -> RawTargetPath {
  try RawTargetPath(components: components.map { Data($0.utf8) })
}

private func planBoundRuntimeFiles(
  graphFileIDs: [String],
  ownerPaths: [[String]],
  actionID: ActionID,
  rootIdentity: RuntimeReleaseFileObjectIdentity,
  candidateIdentity: RuntimeReleaseFileObjectIdentity,
  fileIdentities: [RuntimeReleaseFileObjectIdentity],
  cloneIdentity: RuntimeReleaseCloneIdentity?,
  ownerParentChains: [[RuntimeReleaseFileObjectIdentity]]? = nil,
  ownerParentSeals: [[NamespaceSealEvidence]]? = nil,
  inheritedProviderBoundaries: [[Bool]]? = nil
) throws -> [RuntimeReleaseExpectedFileObject] {
  let resolvedParentChains =
    ownerParentChains
    ?? Array(repeating: [candidateIdentity], count: ownerPaths.count)
  let defaultParentSeal = try topologyCandidateSeal()
  let resolvedParentSeals =
    ownerParentSeals
    ?? Array(repeating: [defaultParentSeal], count: ownerPaths.count)
  let resolvedProviderBoundaries =
    inheritedProviderBoundaries
    ?? ownerPaths.map { Array(repeating: false, count: $0.count) }
  guard graphFileIDs.count == ownerPaths.count, ownerPaths.count == fileIdentities.count,
    resolvedParentChains.count == ownerPaths.count,
    resolvedParentSeals.count == ownerPaths.count,
    resolvedProviderBoundaries.count == ownerPaths.count
  else {
    throw ReleaseTopologyTestError.identity
  }
  return try graphFileIDs.indices.map { index in
    let namespace = try RuntimeReleaseOwnerNamespaceBinding(
      link: FileOwnerLink(
        candidateID: "cache", path: try rawTarget(ownerPaths[index])),
      actionID: actionID,
      rawRoot: try RawRootPath(absoluteBytes: Data("/fixture".utf8)),
      rootIdentity: rootIdentity,
      rootSeal: try topologyRootSeal(),
      parentChain: resolvedParentChains[index],
      parentSeals: resolvedParentSeals[index],
      targetIdentity: fileIdentities[index],
      inheritedProviderBoundaryByComponent: resolvedProviderBoundaries[index])
    return RuntimeReleaseExpectedFileObject(
      graphFileObjectID: graphFileIDs[index],
      identity: fileIdentities[index],
      owners: [RuntimeReleaseExpectedOwner(namespace: namespace)],
      linkCount: 1,
      cloneIdentity: cloneIdentity)
  }
}

private func policyIdentity(
  _ identity: RuntimeReleaseFileObjectIdentity
) -> ObjectIdentity {
  ObjectIdentity(
    device: identity.device,
    object: identity.fileID,
    generation: identity.generation.map(Observation.known)
      ?? .unknown(.unavailableViaPublicAPI),
    type: identity.objectType == .directory ? .directory : .regularFile)
}

private func topologyRootSeal() throws -> NamespaceSealEvidence {
  NamespaceSealEvidence(
    trustedNamespace: .ownerPrivate,
    accessPolicy: .known("owner-private"),
    aclDigest: .known(try digest(91)),
    providerBoundary: .known(.local),
    mountIdentity: .known("fixture-volume"))
}

private func topologyCandidateSeal() throws -> NamespaceSealEvidence {
  NamespaceSealEvidence(
    trustedNamespace: .ownerPrivate,
    accessPolicy: .known("owner-private"),
    aclDigest: .known(try digest(93)),
    providerBoundary: .known(.local),
    mountIdentity: .known("fixture-volume"))
}

private func topologyDescendantSeal(
  accessPolicy: Observation<String> = .known("owner-private"),
  providerBoundary: Observation<ProviderState> = .known(.local),
  mountIdentity: Observation<String> = .known("fixture-volume")
) -> NamespaceSealEvidence {
  NamespaceSealEvidence(
    trustedNamespace: .ownerPrivate,
    accessPolicy: accessPolicy,
    aclDigest: .unknown(.unavailableViaPublicAPI),
    providerBoundary: providerBoundary,
    mountIdentity: mountIdentity)
}

private func testingDescriptorAccessPolicy() throws -> RuntimeReleaseDescriptorAccessPolicy {
  RuntimeReleaseDescriptorAccessPolicy(
    accessPolicy: "fixture-access-policy",
    aclDigest: try digest(0xF0),
    mountIdentity: "fixture-mount")
}

private func descriptorAccessPolicy(
  _ seal: NamespaceSealEvidence
) throws -> RuntimeReleaseDescriptorAccessPolicy {
  guard case .known(let accessPolicy) = seal.accessPolicy,
    case .known(let aclDigest) = seal.aclDigest,
    case .known(let mountIdentity) = seal.mountIdentity
  else { throw ReleaseTopologyTestError.identity }
  return RuntimeReleaseDescriptorAccessPolicy(
    accessPolicy: accessPolicy,
    aclDigest: aclDigest,
    mountIdentity: mountIdentity)
}

private func booleanFailure<Value: Equatable & Sendable>(
  _ observation: RuntimeReleaseTopologyObservation<Value>
) -> RuntimeReleaseTopologyObservation<Bool> {
  switch observation {
  case .absent: return .absent
  case .known: return .known(true)
  case .unknown(let reason): return .unknown(reason)
  case .unreadable(let failure): return .unreadable(failure)
  case .failed(let failure): return .failed(failure)
  }
}

private func digest(_ byte: UInt8) throws -> PolicyDigest {
  try PolicyDigest(bytes: Data(repeating: byte, count: 32))
}

private func actionID(_ byte: UInt8) throws -> ActionID {
  ActionID(digest: try digest(byte))
}
