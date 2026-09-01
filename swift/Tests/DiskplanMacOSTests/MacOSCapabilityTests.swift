import CDiskplanMacOS
import Darwin
import Foundation
import Testing

@testable import DiskplanMacOS

@Test
func noMaterializationPolicyIsSetThenReadBack() throws {
  final class Calls: @unchecked Sendable {
    var values: [String] = []
  }
  let calls = Calls()
  let installer = MaterializationPolicyInstaller(
    setOff: {
      calls.values.append("set")
      return (0, 0)
    },
    readBack: {
      calls.values.append("get")
      return (Int32(IOPOL_MATERIALIZE_DATALESS_FILES_OFF), 0)
    }
  )
  let result = installer.installBeforePathAccess()
  #expect(result.status == .known)
  #expect(calls.values == ["set", "get"])
}

@Test
func snapshotListShimPreservesTypedPOSIXFailureWithoutPathAccess() {
  var buffer = Data(count: 64)
  let result = SnapshotListProbe().list(fileDescriptor: -1, buffer: &buffer)
  #expect(result.status == .failed)
  #expect(result.detail == "fs_snapshot_list")
  #expect(result.errorCode == EINVAL)
}

@Test
func noMaterializationPolicyRejectsInconsistentReadback() {
  let installer = MaterializationPolicyInstaller(
    setOff: { (0, 0) },
    readBack: { (Int32(IOPOL_MATERIALIZE_DATALESS_FILES_ON), 0) }
  )
  #expect(installer.installBeforePathAccess().status == .inconsistent)
}

@Test
func pathProbeRereadsLiveMaterializationPolicyInsteadOfTrustingToken() throws {
  final class State: @unchecked Sendable {
    let lock = NSLock()
    var reads = 0
  }
  let state = State()
  let installer = MaterializationPolicyInstaller(
    setOff: { (0, 0) },
    readBack: {
      state.lock.withLock {
        state.reads += 1
        let value =
          state.reads == 1
          ? Int32(IOPOL_MATERIALIZE_DATALESS_FILES_OFF)
          : Int32(IOPOL_MATERIALIZE_DATALESS_FILES_ON)
        return (value, 0)
      }
    }
  )
  let policy = try #require(installer.installBeforePathAccess().value)
  let result = ItemProbe().probe(
    parentFileDescriptor: -1,
    rawName: Data("unused".utf8),
    policy: policy
  )
  #expect(result.status == .inconsistent)
  #expect(state.lock.withLock { state.reads } == 2)
}

@Test
func itemWireRejectsMalformedAndNegativeSizes() throws {
  #expect(throws: ItemWireError.truncated) {
    try ItemWireV1.parse(Data([1, 2, 3]))
  }
  var short = Data(repeating: 0, count: ItemWireV1.size - 1)
  short.store(UInt32(short.count), at: 0)
  #expect(throws: ItemWireError.invalidLength(declared: UInt32(short.count), actual: short.count)) {
    try ItemWireV1.parse(short)
  }

  var negative = validWire()
  negative.store(UInt64.max, at: 52)
  #expect(throws: ItemWireError.negative(field: "logical_bytes")) {
    try ItemWireV1.parse(negative)
  }

  var overflow = validWire()
  overflow.store(UInt64(Int64.max) + 1, at: 60)
  #expect(throws: ItemWireError.overflow(field: "nominal_allocated_bytes")) {
    try ItemWireV1.parse(overflow)
  }

  var unexpectedMask = validWire()
  unexpectedMask.store(UInt32(ATTR_CMN_OWNERID), at: 4)
  #expect(throws: ItemWireError.self) {
    try ItemWireV1.parse(unexpectedMask)
  }
}

@Test
func returnedMasksDegradeUnavailableAttributesWithoutCredit() throws {
  var wire = validWire()
  wire.store(UInt32(0), at: 16)
  wire.store(UInt32(0), at: 20)
  let item = try ItemWireV1.parse(wire)
  #expect(item.logicalBytes.status == .unavailable)
  #expect(item.nominalAllocatedBytes.status == .unavailable)
  #expect(item.immediatePrivateReclaimBytes.status == .unavailable)
  #expect(item.sharing.cloneID.status == .unavailable)
  #expect(item.sharing.conditionalGroupReclaimBytes.status == .unavailable)
  #expect(item.snapshotAttributedBytes.status == .unavailable)
  #expect(item.providerHiddenFootprint.status == .unavailable)
}

@Test
func itemShimRequestsRealDeviceForObjectIdentity() {
  let options = dp_item_probe_options()
  #expect(options & UInt64(FSOPT_RETURN_REALDEV) != 0)
  #expect(options & UInt64(FSOPT_NOFOLLOW) != 0)
  #expect(options & UInt64(FSOPT_RESOLVE_BENEATH) != 0)
}

@Test
func packedDirectoryKernelItemBufferOmitsFileGroupWithoutShiftingExtendedFields() throws {
  let parsed = parseKernelItemBuffer(packedKernelItemBuffer(objectType: 2, directoryLayout: true))
  #expect(parsed.result == 0)
  #expect(parsed.written == ItemWireV1.size)
  let evidence = try ItemWireV1.parse(parsed.wire)
  #expect(evidence.objectType.value == .directory)
  #expect(evidence.logicalBytes.status == .unavailable)
  #expect(evidence.nominalAllocatedBytes.status == .unavailable)
  #expect(evidence.immediatePrivateReclaimBytes.value == 20)
  #expect(evidence.sharing.cloneID.value == 3)
  #expect(evidence.sharing.cloneRefcount.value == 2)
}

@Test
func packedInvalidAttributesRemainUnavailableWithoutShiftingLaterValues() throws {
  let common =
    UInt32(ATTR_CMN_RETURNED_ATTRS) | dp_attr_common_device()
    | dp_attr_common_object_type() | dp_attr_common_file_id()
  let parsed = parseKernelItemBuffer(
    packedKernelItemBuffer(
      objectType: 1,
      returnedCommon: common,
      returnedFile: dp_attr_file_total_size(),
      returnedExtended: dp_attr_extended_clone_id()
    )
  )
  #expect(parsed.result == 0)
  let evidence = try ItemWireV1.parse(parsed.wire)
  #expect(evidence.objectType.value == .regular)
  #expect(evidence.isDataless.status == .unavailable)
  #expect(evidence.linkCount.status == .unavailable)
  #expect(evidence.logicalBytes.value == 100)
  #expect(evidence.nominalAllocatedBytes.status == .unavailable)
  #expect(evidence.immediatePrivateReclaimBytes.status == .unavailable)
  #expect(evidence.sharing.cloneID.value == 3)
  #expect(evidence.isSyncRoot.status == .unavailable)
  #expect(evidence.sharing.cloneRefcount.status == .unavailable)
}

@Test
func missingObjectTypeRemainsUnavailableWhilePackedShapeStaysParseable() throws {
  let common =
    UInt32(ATTR_CMN_RETURNED_ATTRS) | dp_attr_common_device()
    | dp_attr_common_flags() | dp_attr_common_file_id()
  let parsed = parseKernelItemBuffer(
    packedKernelItemBuffer(objectType: 1, returnedCommon: common, returnedFile: 0)
  )
  #expect(parsed.result == 0)
  let evidence = try ItemWireV1.parse(parsed.wire)
  #expect(evidence.device.status == .known)
  #expect(evidence.objectType.status == .unavailable)
  #expect(evidence.fileID.status == .known)
  #expect(evidence.logicalBytes.status == .unavailable)
}

@Test
func shortPackedKernelItemBufferFailsClosedEvenWhenTrailingAttributeIsInvalid() {
  var raw = packedKernelItemBuffer(
    objectType: 1,
    returnedExtended: dp_attr_extended_clone_id()
  )
  raw.removeLast()
  raw.store(UInt32(raw.count), at: 0)
  let parsed = parseKernelItemBuffer(raw)
  #expect(parsed.result == -1)
  #expect(parsed.error == EPROTO)
  #expect(parsed.written == 0)
}

@Test
func packedDirectoryRejectsImpossibleReturnedFileAttributes() {
  let raw = packedKernelItemBuffer(
    objectType: 2,
    returnedFile: dp_attr_file_total_size(),
    directoryLayout: true
  )
  let parsed = parseKernelItemBuffer(raw)
  #expect(parsed.result == -1)
  #expect(parsed.error == EPROTO)
  #expect(parsed.written == 0)
}

@Test
func volumeCapabilitiesRespectValidityMasks() {
  let returned = ReturnedAttributeMasks(
    common: 0,
    volume: UInt32(ATTR_VOL_CAPABILITIES),
    directory: 0,
    file: 0,
    extended: 0
  )
  let unavailable = VolumeCapabilityEvidence.interpret(
    filesystemType: "apfs",
    returned: returned,
    validCapabilities: [0, 0, 0, 0],
    capabilities: [UInt32.max, UInt32.max, 0, 0],
    validAttributes: Array(repeating: 0, count: 5),
    nativeAttributes: Array(repeating: 0, count: 5)
  )
  #expect(unavailable.supportsClone.status == .unavailable)
  #expect(unavailable.supportsCloneMapping.status == .unavailable)

  let known = VolumeCapabilityEvidence.interpret(
    filesystemType: "apfs",
    returned: returned,
    validCapabilities: [UInt32.max, UInt32.max, 0, 0],
    capabilities: [dp_volume_clone_mapping_format(), dp_volume_clone_interface(), 0, 0],
    validAttributes: Array(repeating: 0, count: 5),
    nativeAttributes: Array(repeating: 0, count: 5)
  )
  #expect(known.supportsClone.status == .known)
  #expect(known.supportsClone.value == true)
  #expect(known.supportsSnapshot.status == .known)
  #expect(known.supportsSnapshot.value == false)
  #expect(known.supportsCloneMapping.status == .known)
  #expect(known.supportsCloneMapping.value == true)
}

@Test
func rawNameConversionFailureIsTypedUnavailable() {
  let invalidUTF8 = Data([0xff, 0xfe])
  #expect(ItemProbe().displayName(for: invalidUTF8).status == .unavailable)
}

@Test
func datalessDirectoriesNeverDescendButMaterializedProviderDirectoriesDo() throws {
  var dataless = validWire()
  dataless.store(UInt32(2), at: 32)
  dataless.store(dp_flag_dataless(), at: 36)
  let datalessItem = try ItemWireV1.parse(dataless)
  let datalessDecision = FileProviderBoundaryProbe.decideBoundary(
    item: datalessItem,
    identityDisposition: .confirmedProvider
  )
  #expect(datalessDecision.traversal == .doNotDescendDataless)
  #expect(datalessDecision.handling == .reportOnly)

  var materialized = validWire()
  materialized.store(UInt32(2), at: 32)
  let materializedItem = try ItemWireV1.parse(materialized)
  let materializedDecision = FileProviderBoundaryProbe.decideBoundary(
    item: materializedItem,
    identityDisposition: .identifierAbsent,
    inheritedProviderBoundary: true
  )
  #expect(materializedDecision.traversal == .descendMetadataOnlyProviderBoundary)
  #expect(materializedDecision.handling == .reportOnly)
}

@Test
func indeterminateProviderIdentityFailsClosedUnlessBoundaryEvidenceIsPositive() throws {
  var localDirectoryWire = validWire()
  localDirectoryWire.store(UInt32(2), at: 32)
  let localDirectory = try ItemWireV1.parse(localDirectoryWire)

  var syncRootWire = localDirectoryWire
  syncRootWire.store(dp_flag_sync_root(), at: 84)
  let syncRoot = try ItemWireV1.parse(syncRootWire)

  let failureStatuses: [CapabilityStatus] = [
    .permissionDenied, .unavailable, .failed, .inconsistent,
  ]
  for status in failureStatuses {
    let disposition = ProviderIdentityDisposition.indeterminate(status)
    #expect(disposition == .indeterminate(status))

    let unverified = FileProviderBoundaryProbe.decideBoundary(
      item: localDirectory,
      identityDisposition: disposition
    )
    #expect(unverified.traversal == .doNotDescendUnverifiedProviderOwnership)
    #expect(unverified.handling == .reportOnly)

    let flagged = FileProviderBoundaryProbe.decideBoundary(
      item: syncRoot,
      identityDisposition: disposition
    )
    #expect(flagged.traversal == .descendMetadataOnlyProviderBoundary)
    #expect(flagged.handling == .reportOnly)

    let inherited = FileProviderBoundaryProbe.decideBoundary(
      item: localDirectory,
      identityDisposition: disposition,
      inheritedProviderBoundary: true
    )
    #expect(inherited.traversal == .descendMetadataOnlyProviderBoundary)
    #expect(inherited.handling == .reportOnly)
  }
}

@Test
func absentIdentifierNeverAuthorizesLocalTraversal() throws {
  var wire = validWire()
  wire.store(UInt32(2), at: 32)
  let item = try ItemWireV1.parse(wire)

  let absent = ProviderIdentityDisposition.identifierAbsent
  #expect(
    FileProviderBoundaryProbe.decideBoundary(
      item: item,
      identityDisposition: absent
    ).traversal == .doNotDescendUnverifiedProviderOwnership
  )

  #expect(
    FileProviderBoundaryProbe.decideBoundary(
      item: item,
      identityDisposition: .confirmedProvider
    ).traversal == .descendMetadataOnlyProviderBoundary
  )
}

@Test
func providerBoundRegularFilesNeverReceiveDescentDecisions() throws {
  let regular = try providerItemEvidence(
    isDataless: false,
    isSyncRoot: true,
    objectType: 1
  )
  for inherited in [false, true] {
    let decision = FileProviderBoundaryProbe.decideBoundary(
      item: regular,
      identityDisposition: .confirmedProvider,
      inheritedProviderBoundary: inherited
    )
    #expect(decision.traversal == .doNotDescendNonDirectory)
    #expect(decision.handling == .reportOnly)
  }
}

@Test
func unavailableObjectTypeNeverReceivesDescentDecision() throws {
  let item = try providerItemEvidence(
    isDataless: false,
    isSyncRoot: true,
    includeObjectType: false
  )
  let decision = FileProviderBoundaryProbe.decideBoundary(
    item: item,
    identityDisposition: .confirmedProvider,
    inheritedProviderBoundary: true
  )
  #expect(decision.traversal == .doNotDescendUnverifiedItemType)
  #expect(decision.handling == .reportOnly)
}

@Test
func boundProviderProbePreservesSubsecondDeadlineAndRereadsPolicy() throws {
  let deadline = OperationDeadline(
    timeout: .milliseconds(100),
    nowUptimeNanoseconds: 1_000
  )
  #expect(deadline.dispatchTime.uptimeNanoseconds == 100_001_000)

  let fixture = try BoundProbeFixture()
  defer { fixture.close() }
  let reads = LockedCounter()
  let policy = try injectedPolicy(counter: reads)
  let operations = FileProviderProbeOperations(
    startIdentity: { _, completion in
      completion(.identifierAbsent)
    }
  )
  let outcome = FileProviderBoundaryProbe(operations: operations).probe(
    parentFileDescriptor: fixture.parentFD,
    rawName: fixture.rawName,
    policy: policy,
    timeout: .milliseconds(100)
  )
  guard case .evidence(let evidence) = outcome else {
    Issue.record("expected bound evidence, got \(outcome)")
    return
  }
  #expect(evidence.identityDisposition == .identifierAbsent)
  #expect(evidence.traversal == .doNotDescendNonDirectory)
  #expect(reads.value >= 10)
}

@Test
func descriptorProviderProbeTreatsCanonicalRootAsDescriptorBoundLocal() throws {
  let rootDescriptor = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  let descriptor = try #require(rootDescriptor >= 0 ? rootDescriptor : nil)
  defer { close(descriptor) }
  let identityStarts = LockedCounter()
  let boundaryProbe = FileProviderBoundaryProbe(
    operations: FileProviderProbeOperations(
      startIdentity: { _, completion in
        identityStarts.increment()
        completion(
          .known(ProviderIdentity(itemIdentifier: "unexpected", domainIdentifier: "unexpected")))
      }))

  let outcome = DescriptorFileProviderBoundaryProbe(boundaryProbe: boundaryProbe).probe(
    fileDescriptor: descriptor,
    policy: try injectedPolicy(),
    timeout: .milliseconds(100))

  guard case .evidence(let evidence) = outcome else {
    Issue.record("expected descriptor-bound root evidence, got \(outcome)")
    return
  }
  #expect(identityStarts.value == 0)
  #expect(evidence.identityDisposition == .identifierAbsent)
  #expect(evidence.traversal == .doNotDescendUnverifiedProviderOwnership)
}

@Test
func descriptorProviderProbeFailsClosedWhenRootPostflightPolicyChanges() throws {
  let rootDescriptor = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  let descriptor = try #require(rootDescriptor >= 0 ? rootDescriptor : nil)
  defer { close(descriptor) }
  let reads = LockedCounter()
  let installer = MaterializationPolicyInstaller(
    setOff: { (0, 0) },
    readBack: {
      reads.increment()
      let value =
        reads.value < 5
        ? Int32(IOPOL_MATERIALIZE_DATALESS_FILES_OFF)
        : Int32(IOPOL_MATERIALIZE_DATALESS_FILES_ON)
      return (value, 0)
    })
  let policy = try #require(installer.installBeforePathAccess().value)
  let identityStarts = LockedCounter()
  let boundaryProbe = FileProviderBoundaryProbe(
    operations: FileProviderProbeOperations(
      startIdentity: { _, completion in
        identityStarts.increment()
        completion(.identifierAbsent)
      }))

  let outcome = DescriptorFileProviderBoundaryProbe(boundaryProbe: boundaryProbe).probe(
    fileDescriptor: descriptor,
    policy: policy,
    timeout: .milliseconds(100))

  guard case .rejected(.policyUnavailable(let status, _, _)) = outcome else {
    Issue.record("expected root postflight policy rejection, got \(outcome)")
    return
  }
  #expect(status == .inconsistent)
  #expect(identityStarts.value == 0)
}

@Test
func boundProviderProbeTypesIdentityTimeoutWithoutMetadataWork() throws {
  let fixture = try BoundProbeFixture()
  defer { fixture.close() }
  let operations = FileProviderProbeOperations(
    startIdentity: { _, _ in }
  )
  let outcome = FileProviderBoundaryProbe(operations: operations).probe(
    parentFileDescriptor: fixture.parentFD,
    rawName: fixture.rawName,
    policy: try injectedPolicy(),
    timeout: .milliseconds(2)
  )
  #expect(outcome == .rejected(.timedOut(stage: .identityLookup)))
  #expect(outcome.traversal == .doNotDescendUnverifiedProviderOwnership)
}

@Test
func repeatedIdentityTimeoutsRetainOneBoundedOutstandingRequestUntilLateCompletion() throws {
  let fixture = try BoundProbeFixture()
  defer { fixture.close() }
  let starter = HeldIdentityStarter()
  let probe = FileProviderBoundaryProbe(
    operations: FileProviderProbeOperations(startIdentity: starter.start)
  )

  for _ in 0..<8 {
    let outcome = probe.probe(
      parentFileDescriptor: fixture.parentFD,
      rawName: fixture.rawName,
      policy: try injectedPolicy(),
      timeout: .milliseconds(2)
    )
    #expect(outcome == .rejected(.timedOut(stage: .identityLookup)))
  }
  #expect(starter.startCount == 1)

  starter.releaseHeldAndCompleteFuture(with: .identifierAbsent)
  let recovered = probe.probe(
    parentFileDescriptor: fixture.parentFD,
    rawName: fixture.rawName,
    policy: try injectedPolicy(),
    timeout: .milliseconds(100)
  )
  guard case .evidence(let evidence) = recovered else {
    Issue.record("expected a new request after the original late callback, got \(recovered)")
    return
  }
  #expect(evidence.identityDisposition == .identifierAbsent)
  #expect(starter.startCount == 2)
}

@Test
func deadlineResultBoxDiscardsCompletionAfterTimeoutBeforeCloseLock() {
  let box = DeadlineResultBox<Int>()
  let callbackRan = LockedFlag()
  let result = box.wait(until: .now()) {
    callbackRan.set()
    box.complete(42)
  }
  #expect(callbackRan.value)
  #expect(result == nil)

  box.complete(43)
  #expect(box.wait(until: .now()) == nil)
}

@Test
func boundProviderProbeReturnsMetadataUnavailableWithoutInProcessCoordination() throws {
  let fixture = try BoundProbeFixture()
  defer { fixture.close() }
  let operations = FileProviderProbeOperations(
    startIdentity: { _, completion in completion(.identifierAbsent) }
  )
  let outcome = FileProviderBoundaryProbe(operations: operations).probe(
    parentFileDescriptor: fixture.parentFD,
    rawName: fixture.rawName,
    policy: try injectedPolicy(),
    timeout: .milliseconds(100)
  )
  guard case .evidence(let evidence) = outcome else {
    Issue.record("expected provider evidence, got \(outcome)")
    return
  }
  #expect(evidence.promisedMetadata.status == .unavailable)
  #expect(evidence.promisedMetadata.value == nil)
  #expect(evidence.promisedMetadata.detail?.contains("disabled") == true)
}

@Test
func boundProviderProbeKeepsMissingUnreadableAndFailureDistinct() throws {
  let fixture = try BoundProbeFixture()
  defer { fixture.close() }
  let probe = FileProviderBoundaryProbe()
  let missing = probe.probe(
    parentFileDescriptor: fixture.parentFD,
    rawName: Data("missing".utf8),
    policy: try injectedPolicy(),
    timeout: .milliseconds(10)
  )
  #expect(missing == .rejected(.missing(stage: .preflight)))

  let unreadable = probe.rejection(
    for: Capability<Bool>(status: .permissionDenied, detail: "fixture", errorCode: EACCES),
    stage: .preflight
  )
  let failed = probe.rejection(
    for: Capability<Bool>(status: .failed, detail: "fixture", errorCode: EIO),
    stage: .preflight
  )
  let unreadableParent = probe.posixRejection(EACCES, stage: .derivedParentPostflight)
  #expect(unreadable == .unreadable(stage: .preflight, errorCode: EACCES))
  #expect(
    failed
      == .failed(stage: .preflight, status: .failed, detail: "fixture", errorCode: EIO)
  )
  #expect(FileProviderProbeOutcome.rejected(unreadable).handling == .reportOnly)
  #expect(
    unreadableParent == .unreadable(stage: .derivedParentPostflight, errorCode: EACCES)
  )
  #expect(
    FileProviderProbeOutcome.rejected(failed).traversal
      == .doNotDescendUnverifiedProviderOwnership
  )
}

@Test
func boundProviderProbeDetectsReplacementAcrossFoundationOperations() throws {
  let fixture = try BoundProbeFixture()
  defer { fixture.close() }
  let replacement = fixture.root.appendingPathComponent("replacement")
  try Data([2]).write(to: replacement)
  let renamed = LockedFlag()
  let operations = FileProviderProbeOperations(
    startIdentity: { url, completion in
      if rename(replacement.path, url.path) == 0 { renamed.set() }
      completion(.identifierAbsent)
    }
  )
  let outcome = FileProviderBoundaryProbe(operations: operations).probe(
    parentFileDescriptor: fixture.parentFD,
    rawName: fixture.rawName,
    policy: try injectedPolicy(),
    timeout: .milliseconds(100)
  )
  #expect(renamed.value)
  guard case .rejected(.identityMismatch(let stage, let expected, let observed)) = outcome else {
    Issue.record("expected identity mismatch, got \(outcome)")
    return
  }
  #expect(stage == .postflight)
  #expect(expected != observed)
  #expect(outcome.traversal == .doNotDescendUnverifiedProviderOwnership)
}

@Test
func boundProviderProbeDetectsParentReplacementDespiteChildHardlinkIdentity() throws {
  let fixture = try BoundProbeFixture()
  defer { fixture.close() }
  let movedParent = fixture.container.appendingPathComponent("moved-parent", isDirectory: true)
  let replacementParent = fixture.container.appendingPathComponent(
    "replacement-parent",
    isDirectory: true
  )
  try FileManager.default.createDirectory(
    at: replacementParent,
    withIntermediateDirectories: false
  )
  let replacementItem = replacementParent.appendingPathComponent("item")
  #expect(link(fixture.root.appendingPathComponent("item").path, replacementItem.path) == 0)
  let replaced = LockedFlag()
  let operations = FileProviderProbeOperations(
    startIdentity: { _, completion in
      if rename(fixture.root.path, movedParent.path) == 0,
        rename(replacementParent.path, fixture.root.path) == 0
      {
        replaced.set()
      }
      completion(.identifierAbsent)
    }
  )
  let outcome = FileProviderBoundaryProbe(operations: operations).probe(
    parentFileDescriptor: fixture.parentFD,
    rawName: fixture.rawName,
    policy: try injectedPolicy(),
    timeout: .milliseconds(100)
  )
  #expect(replaced.value)
  guard case .rejected(.parentIdentityMismatch(let stage, let expected, let observed)) = outcome
  else {
    Issue.record("expected parent identity mismatch, got \(outcome)")
    return
  }
  #expect(stage == .derivedParentPostflight)
  #expect(expected != observed)
  #expect(outcome.traversal == .doNotDescendUnverifiedProviderOwnership)
}

@Test
func boundProviderProbeKeepsRenamedDerivedParentMissingDistinct() throws {
  let fixture = try BoundProbeFixture()
  defer { fixture.close() }
  let movedParent = fixture.container.appendingPathComponent("moved-parent", isDirectory: true)
  let renamed = LockedFlag()
  let operations = FileProviderProbeOperations(
    startIdentity: { _, completion in
      if rename(fixture.root.path, movedParent.path) == 0 { renamed.set() }
      completion(.identifierAbsent)
    }
  )
  let outcome = FileProviderBoundaryProbe(operations: operations).probe(
    parentFileDescriptor: fixture.parentFD,
    rawName: fixture.rawName,
    policy: try injectedPolicy(),
    timeout: .milliseconds(100)
  )
  #expect(renamed.value)
  #expect(outcome == .rejected(.missing(stage: .derivedParentPostflight)))
  #expect(outcome.traversal == .doNotDescendUnverifiedProviderOwnership)
}

@Test
func boundProviderProbeRejectsDatalessToMaterializedTransitionOnSameObject() throws {
  let outcome = try contentTransitionOutcome(fromDataless: true, toDataless: false)
  #expect(
    outcome
      == .rejected(
        .contentStateMismatch(
          stage: .postflight,
          expectedDataless: true,
          observedDataless: false
        )
      )
  )
  #expect(outcome.traversal == .doNotDescendUnverifiedContentState)
}

@Test
func boundProviderProbeRejectsMaterializedToDatalessTransitionOnSameObject() throws {
  let outcome = try contentTransitionOutcome(fromDataless: false, toDataless: true)
  #expect(
    outcome
      == .rejected(
        .contentStateMismatch(
          stage: .postflight,
          expectedDataless: false,
          observedDataless: true
        )
      )
  )
  #expect(outcome.traversal == .doNotDescendUnverifiedContentState)
}

@Test
func boundProviderProbeUsesStablePostflightBoundaryEvidence() throws {
  let fixture = try BoundProbeFixture(isDirectory: true)
  defer { fixture.close() }
  let before = try providerItemEvidence(isDataless: false, isSyncRoot: false)
  let after = try providerItemEvidence(isDataless: false, isSyncRoot: true)
  let sequence = LockedEvidenceSequence([before, before, after, after])
  let operations = FileProviderProbeOperations(
    startIdentity: { _, completion in completion(.identifierAbsent) },
    readItem: { _, _, _ in sequence.next() }
  )
  let outcome = FileProviderBoundaryProbe(operations: operations).probe(
    parentFileDescriptor: fixture.parentFD,
    rawName: fixture.rawName,
    policy: try injectedPolicy(),
    timeout: .milliseconds(100)
  )
  guard case .evidence(let evidence) = outcome else {
    Issue.record("expected stable postflight evidence, got \(outcome)")
    return
  }
  #expect(evidence.traversal == .descendMetadataOnlyProviderBoundary)
  #expect(sequence.remaining == 0)
}

@Test
func unavailableRealDeviceIdentityFailsClosed() throws {
  let fixture = try BoundProbeFixture()
  defer { fixture.close() }
  let evidence = try providerItemEvidence(isDataless: false, includeDevice: false)
  let operations = FileProviderProbeOperations(
    startIdentity: { _, completion in completion(.identifierAbsent) },
    readItem: { _, _, _ in .known(evidence) }
  )
  let outcome = FileProviderBoundaryProbe(operations: operations).probe(
    parentFileDescriptor: fixture.parentFD,
    rawName: fixture.rawName,
    policy: try injectedPolicy(),
    timeout: .milliseconds(100)
  )
  guard case .rejected(.failed(let stage, let status, _, _)) = outcome else {
    Issue.record("expected unavailable identity rejection, got \(outcome)")
    return
  }
  #expect(stage == .preflight)
  #expect(status == .unavailable)
  #expect(outcome.traversal == .doNotDescendUnverifiedProviderOwnership)
}

@Test
func liveTempRootProbeAndCloneEvidenceWhenAvailable() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let manager = FileManager.default
  let root = manager.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
  try manager.createDirectory(at: root, withIntermediateDirectories: false)
  defer { try? manager.removeItem(at: root) }
  let source = root.appendingPathComponent("source")
  let clone = root.appendingPathComponent("clone")
  try Data(repeating: 7, count: 1 << 20).write(to: source)
  let cloneResult = clonefile(source.path, clone.path, 0)
  if cloneResult != 0, errno == ENOTSUP || errno == EXDEV {
    return
  }
  #expect(cloneResult == 0)

  let parentFD = open(root.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  let fd = try #require(parentFD >= 0 ? parentFD : nil)
  defer { close(fd) }
  let probe = ItemProbe()
  let sourceEvidence = try #require(
    probe.probe(parentFileDescriptor: fd, rawName: Data("source".utf8), policy: policy).value
  )
  let cloneEvidence = try #require(
    probe.probe(parentFileDescriptor: fd, rawName: Data("clone".utf8), policy: policy).value
  )
  #expect(sourceEvidence.immediatePrivateReclaimBytes.status == .known)
  #expect(cloneEvidence.immediatePrivateReclaimBytes.status == .known)
  #expect(sourceEvidence.sharing.conditionalGroupReclaimBytes.status == .unavailable)
  #expect(cloneEvidence.sharing.conditionalGroupReclaimBytes.status == .unavailable)
  if sourceEvidence.sharing.cloneID.status == .known,
    cloneEvidence.sharing.cloneID.status == .known
  {
    #expect(sourceEvidence.sharing.cloneID.value == cloneEvidence.sharing.cloneID.value)
  }
}

@Test
func liveItemProbeParsesDirectoryRegularAndSymlinkWithoutEscapingParent() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let manager = FileManager.default
  let root = manager.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
  try manager.createDirectory(at: root, withIntermediateDirectories: false)
  defer { try? manager.removeItem(at: root) }
  try manager.createDirectory(
    at: root.appendingPathComponent("directory", isDirectory: true),
    withIntermediateDirectories: false
  )
  try Data([1]).write(to: root.appendingPathComponent("target"))
  try manager.createSymbolicLink(
    at: root.appendingPathComponent("link"),
    withDestinationURL: root.appendingPathComponent("target")
  )
  let parentFD = open(root.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  let fd = try #require(parentFD >= 0 ? parentFD : nil)
  defer { close(fd) }
  let probe = ItemProbe()
  let directory = try #require(
    probe.probe(parentFileDescriptor: fd, rawName: Data("directory".utf8), policy: policy).value
  )
  let regular = try #require(
    probe.probe(parentFileDescriptor: fd, rawName: Data("target".utf8), policy: policy).value
  )
  let link = try #require(
    probe.probe(parentFileDescriptor: fd, rawName: Data("link".utf8), policy: policy).value
  )
  #expect(directory.objectType.value == .directory)
  #expect(directory.logicalBytes.status == .unavailable)
  #expect(regular.objectType.value == .regular)
  #expect(link.objectType.value == .symbolicLink)
  let escape = probe.probe(
    parentFileDescriptor: fd,
    rawName: Data("../target".utf8),
    policy: policy
  )
  #expect(escape.status == .failed)
  #expect(escape.errorCode == EINVAL)
}

private func packedKernelItemBuffer(
  objectType: UInt32,
  returnedCommon: UInt32? = nil,
  returnedFile: UInt32? = nil,
  returnedExtended: UInt32? = nil,
  directoryLayout: Bool = false
) -> Data {
  let common =
    returnedCommon
    ?? (UInt32(ATTR_CMN_RETURNED_ATTRS) | dp_attr_common_device()
      | dp_attr_common_object_type() | dp_attr_common_flags() | dp_attr_common_file_id())
  let file =
    returnedFile
    ?? (directoryLayout
      ? 0
      : dp_attr_file_link_count() | dp_attr_file_total_size()
        | dp_attr_file_allocated_size())
  let extended =
    returnedExtended
    ?? (dp_attr_extended_private_size() | dp_attr_extended_clone_id()
      | dp_attr_extended_flags() | dp_attr_extended_clone_refcount())
  let size = directoryLayout ? 72 : 92
  var data = Data(repeating: 0, count: size)
  data.store(UInt32(size), at: 0)
  data.store(common, at: 4)
  data.store(file, at: 16)
  data.store(extended, at: 20)
  data.store(UInt32(15), at: 24)
  data.store(objectType, at: 28)
  data.store(dp_flag_dataless(), at: 32)
  data.store(UInt64(42), at: 36)

  var cursor = 44
  if !directoryLayout {
    data.store(UInt32(1), at: cursor)
    cursor += 4
    data.store(UInt64(100), at: cursor)
    cursor += 8
    data.store(UInt64(80), at: cursor)
    cursor += 8
  }
  data.store(UInt64(20), at: cursor)
  cursor += 8
  data.store(UInt64(3), at: cursor)
  cursor += 8
  data.store(dp_flag_sync_root(), at: cursor)
  cursor += 8
  data.store(UInt32(2), at: cursor)
  return data
}

private func parseKernelItemBuffer(_ raw: Data) -> (
  result: Int32, error: Int32, written: Int, wire: Data
) {
  var wire = Data(repeating: 0, count: ItemWireV1.size)
  var written = 999
  errno = 0
  let result = wire.withUnsafeMutableBytes { output in
    raw.withUnsafeBytes { input in
      dp_parse_item_buffer(
        input.bindMemory(to: UInt8.self).baseAddress,
        input.count,
        output.bindMemory(to: UInt8.self).baseAddress,
        output.count,
        &written
      )
    }
  }
  return (result, errno, written, wire)
}

private func validWire() -> Data {
  var data = Data(repeating: 0, count: ItemWireV1.size)
  data.store(UInt32(ItemWireV1.size), at: 0)
  data.store(
    UInt32(ATTR_CMN_RETURNED_ATTRS) | dp_attr_common_device() | dp_attr_common_object_type()
      | dp_attr_common_flags()
      | dp_attr_common_file_id(),
    at: 4
  )
  data.store(
    dp_attr_file_link_count() | dp_attr_file_total_size() | dp_attr_file_allocated_size(),
    at: 16
  )
  data.store(
    dp_attr_extended_private_size() | dp_attr_extended_clone_id() | dp_attr_extended_flags()
      | dp_attr_extended_clone_refcount(),
    at: 20
  )
  data.store(UInt64(1), at: 24)
  data.store(UInt32(1), at: 32)
  data.store(UInt64(2), at: 40)
  data.store(UInt32(1), at: 48)
  data.store(UInt64(100), at: 52)
  data.store(UInt64(80), at: 60)
  data.store(UInt64(20), at: 68)
  data.store(UInt64(3), at: 76)
  data.store(dp_flag_may_share_blocks(), at: 84)
  data.store(UInt32(2), at: 92)
  return data
}

private func providerItemEvidence(
  isDataless: Bool,
  isSyncRoot: Bool = false,
  objectType: UInt32 = 2,
  includeDevice: Bool = true,
  includeObjectType: Bool = true
) throws -> ItemStorageEvidence {
  var wire = validWire()
  var common =
    UInt32(ATTR_CMN_RETURNED_ATTRS) | dp_attr_common_flags() | dp_attr_common_file_id()
  if includeDevice { common |= dp_attr_common_device() }
  if includeObjectType { common |= dp_attr_common_object_type() }
  wire.store(common, at: 4)
  wire.store(objectType, at: 32)
  wire.store(isDataless ? dp_flag_dataless() : UInt32(0), at: 36)
  var extendedFlags = dp_flag_may_share_blocks()
  if isSyncRoot { extendedFlags |= dp_flag_sync_root() }
  wire.store(extendedFlags, at: 84)
  return try ItemWireV1.parse(wire)
}

private func contentTransitionOutcome(
  fromDataless: Bool,
  toDataless: Bool
) throws -> FileProviderProbeOutcome {
  let fixture = try BoundProbeFixture(isDirectory: true)
  defer { fixture.close() }
  let before = try providerItemEvidence(isDataless: fromDataless)
  let after = try providerItemEvidence(isDataless: toDataless)
  let sequence = LockedEvidenceSequence([before, before, after, after])
  let operations = FileProviderProbeOperations(
    startIdentity: { _, completion in completion(.identifierAbsent) },
    readItem: { _, _, _ in sequence.next() }
  )
  return FileProviderBoundaryProbe(operations: operations).probe(
    parentFileDescriptor: fixture.parentFD,
    rawName: fixture.rawName,
    policy: try injectedPolicy(),
    timeout: .milliseconds(100)
  )
}

extension Data {
  fileprivate mutating func store<T: FixedWidthInteger>(_ value: T, at offset: Int) {
    var littleEndian = value.littleEndian
    Swift.withUnsafeBytes(of: &littleEndian) { bytes in
      replaceSubrange(offset..<offset + bytes.count, with: bytes)
    }
  }
}

private final class LockedCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var storage = 0

  var value: Int { lock.withLock { storage } }

  func increment() {
    lock.withLock { storage += 1 }
  }
}

private final class LockedFlag: @unchecked Sendable {
  private let lock = NSLock()
  private var storage = false

  var value: Bool { lock.withLock { storage } }

  func set() {
    lock.withLock { storage = true }
  }
}

private final class LockedEvidenceSequence: @unchecked Sendable {
  private let lock = NSLock()
  private var values: [ItemStorageEvidence]

  init(_ values: [ItemStorageEvidence]) { self.values = values }

  var remaining: Int { lock.withLock { values.count } }

  func next() -> Capability<ItemStorageEvidence> {
    lock.withLock {
      guard !values.isEmpty else {
        return Capability(status: .inconsistent, detail: "item evidence fixture exhausted")
      }
      return .known(values.removeFirst())
    }
  }
}

private final class HeldIdentityStarter: @unchecked Sendable {
  private let lock = NSLock()
  private var held: (@Sendable (ProviderIdentityOperationResult) -> Void)?
  private var immediate: ProviderIdentityOperationResult?
  private var starts = 0

  var startCount: Int { lock.withLock { starts } }

  func start(
    _ url: URL,
    _ completion: @escaping @Sendable (ProviderIdentityOperationResult) -> Void
  ) {
    _ = url
    let result = lock.withLock { () -> ProviderIdentityOperationResult? in
      starts += 1
      if let immediate { return immediate }
      held = completion
      return nil
    }
    if let result { completion(result) }
  }

  func releaseHeldAndCompleteFuture(with result: ProviderIdentityOperationResult) {
    let completion = lock.withLock {
      immediate = result
      let value = held
      held = nil
      return value
    }
    completion?(result)
  }
}

private struct BoundProbeFixture {
  let container: URL
  let root: URL
  let parentFD: Int32
  let rawName = Data("item".utf8)

  init(isDirectory: Bool = false) throws {
    container = FileManager.default.temporaryDirectory.appendingPathComponent(
      UUID().uuidString,
      isDirectory: true
    )
    root = container.appendingPathComponent("parent", isDirectory: true)
    try FileManager.default.createDirectory(at: container, withIntermediateDirectories: false)
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    let item = root.appendingPathComponent("item", isDirectory: isDirectory)
    if isDirectory {
      try FileManager.default.createDirectory(at: item, withIntermediateDirectories: false)
    } else {
      try Data([1]).write(to: item)
    }
    parentFD = open(root.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    guard parentFD >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
  }

  func close() {
    Darwin.close(parentFD)
    try? FileManager.default.removeItem(at: container)
  }
}

private func injectedPolicy(counter: LockedCounter? = nil) throws -> NoMaterializationPolicy {
  let installer = MaterializationPolicyInstaller(
    setOff: { (0, 0) },
    readBack: {
      counter?.increment()
      return (Int32(IOPOL_MATERIALIZE_DATALESS_FILES_OFF), 0)
    }
  )
  return try #require(installer.installBeforePathAccess().value)
}
