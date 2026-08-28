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
func shortKernelItemBufferPreservesUnavailableReturnedMasks() throws {
  var raw = Data(repeating: 0, count: 24)
  raw.store(UInt32(raw.count), at: 0)
  raw.store(UInt32(ATTR_CMN_RETURNED_ATTRS), at: 4)
  var wire = Data(repeating: 0, count: ItemWireV1.size)
  var written = 0
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
  #expect(result == 0)
  #expect(written == ItemWireV1.size)
  let evidence = try ItemWireV1.parse(wire)
  #expect(evidence.device.status == .unavailable)
  #expect(evidence.objectType.status == .unavailable)
  #expect(evidence.isDataless.status == .unavailable)
  #expect(evidence.immediatePrivateReclaimBytes.status == .unavailable)
}

@Test
func shortKernelItemBufferRejectsClaimedButAbsentField() {
  var raw = Data(repeating: 0, count: 24)
  raw.store(UInt32(raw.count), at: 0)
  raw.store(UInt32(ATTR_CMN_RETURNED_ATTRS) | dp_attr_common_device(), at: 4)
  var wire = Data(repeating: 0, count: ItemWireV1.size)
  var written = 0
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
  let error = errno
  #expect(result == -1)
  #expect(error == EPROTO)
  #expect(written == 0)
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
  let fixture = try BoundProbeFixture()
  defer { fixture.close() }
  let reads = LockedCounter()
  let policy = try injectedPolicy(counter: reads)
  let operations = FileProviderProbeOperations(
    startIdentity: { _, completion in
      DispatchQueue.global().asyncAfter(deadline: .now() + .milliseconds(5)) {
        completion(.identifierAbsent)
      }
    },
    makeMetadataCoordinator: { ImmediateMetadataCoordinator() }
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
func boundProviderProbeTypesIdentityTimeoutWithoutMetadataStart() throws {
  let fixture = try BoundProbeFixture()
  defer { fixture.close() }
  let metadataCreated = LockedFlag()
  let operations = FileProviderProbeOperations(
    startIdentity: { _, _ in },
    makeMetadataCoordinator: {
      metadataCreated.set()
      return ImmediateMetadataCoordinator()
    }
  )
  let outcome = FileProviderBoundaryProbe(operations: operations).probe(
    parentFileDescriptor: fixture.parentFD,
    rawName: fixture.rawName,
    policy: try injectedPolicy(),
    timeout: .milliseconds(2)
  )
  #expect(outcome == .rejected(.timedOut(stage: .identityLookup)))
  #expect(!metadataCreated.value)
  #expect(outcome.traversal == .doNotDescendUnverifiedProviderOwnership)
}

@Test
func boundProviderProbeCancelsBlockingMetadataAtSharedDeadline() throws {
  let fixture = try BoundProbeFixture()
  defer { fixture.close() }
  let coordinator = BlockingMetadataCoordinator()
  let operations = FileProviderProbeOperations(
    startIdentity: { _, completion in completion(.identifierAbsent) },
    makeMetadataCoordinator: { coordinator }
  )
  let outcome = FileProviderBoundaryProbe(operations: operations).probe(
    parentFileDescriptor: fixture.parentFD,
    rawName: fixture.rawName,
    policy: try injectedPolicy(),
    timeout: .milliseconds(10)
  )
  #expect(outcome == .rejected(.timedOut(stage: .metadata)))
  #expect(coordinator.cancelled)
  #expect(outcome.handling == .reportOnly)
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
  #expect(unreadable == .unreadable(stage: .preflight, errorCode: EACCES))
  #expect(
    failed
      == .failed(stage: .preflight, status: .failed, detail: "fixture", errorCode: EIO)
  )
  #expect(FileProviderProbeOutcome.rejected(unreadable).handling == .reportOnly)
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
    },
    makeMetadataCoordinator: { ImmediateMetadataCoordinator() }
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
    makeMetadataCoordinator: { ImmediateMetadataCoordinator() },
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
    makeMetadataCoordinator: { ImmediateMetadataCoordinator() },
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
func liveItemProbeDoesNotFollowSymlinksOrEscapeItsParent() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let manager = FileManager.default
  let root = manager.temporaryDirectory.appendingPathComponent(UUID().uuidString, isDirectory: true)
  try manager.createDirectory(at: root, withIntermediateDirectories: false)
  defer { try? manager.removeItem(at: root) }
  try Data([1]).write(to: root.appendingPathComponent("target"))
  try manager.createSymbolicLink(
    at: root.appendingPathComponent("link"),
    withDestinationURL: root.appendingPathComponent("target")
  )
  let parentFD = open(root.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  let fd = try #require(parentFD >= 0 ? parentFD : nil)
  defer { close(fd) }
  let probe = ItemProbe()
  let link = try #require(
    probe.probe(parentFileDescriptor: fd, rawName: Data("link".utf8), policy: policy).value
  )
  #expect(link.objectType.value == .symbolicLink)
  let escape = probe.probe(
    parentFileDescriptor: fd,
    rawName: Data("../target".utf8),
    policy: policy
  )
  #expect(escape.status == .failed)
  #expect(escape.errorCode == EINVAL)
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
    makeMetadataCoordinator: { ImmediateMetadataCoordinator() },
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

private final class ImmediateMetadataCoordinator: FileProviderMetadataCoordinating,
  @unchecked Sendable
{
  func collect(url _: URL) -> Capability<[String: String]> { .known([:]) }
  func cancel() {}
}

private final class BlockingMetadataCoordinator: FileProviderMetadataCoordinating,
  @unchecked Sendable
{
  private let lock = NSLock()
  private let release = DispatchSemaphore(value: 0)
  private var wasCancelled = false

  var cancelled: Bool { lock.withLock { wasCancelled } }

  func collect(url _: URL) -> Capability<[String: String]> {
    release.wait()
    return .known([:])
  }

  func cancel() {
    lock.withLock { wasCancelled = true }
    release.signal()
  }
}

private struct BoundProbeFixture {
  let root: URL
  let parentFD: Int32
  let rawName = Data("item".utf8)

  init(isDirectory: Bool = false) throws {
    root = FileManager.default.temporaryDirectory.appendingPathComponent(
      UUID().uuidString,
      isDirectory: true
    )
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
    try? FileManager.default.removeItem(at: root)
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
