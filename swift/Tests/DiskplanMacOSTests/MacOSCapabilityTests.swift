import CDiskplanMacOS
import Darwin
import DiskplanMacOS
import Foundation
import Testing

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
    identityDisposition: .confirmedLocal,
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
    let identity = Capability<ProviderIdentity>(status: status, detail: "fixture")
    let disposition = FileProviderBoundaryProbe.identityDisposition(for: identity)
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
func authoritativeProviderIdentityResultsChooseProviderOrLocalTraversal() throws {
  var wire = validWire()
  wire.store(UInt32(2), at: 32)
  let item = try ItemWireV1.parse(wire)

  let confirmedLocal = FileProviderBoundaryProbe.identityDisposition(
    for: Capability<ProviderIdentity>(
      status: .unsupported,
      detail: "URL is not owned by a File Provider"
    )
  )
  #expect(confirmedLocal == .confirmedLocal)
  #expect(
    FileProviderBoundaryProbe.decideBoundary(
      item: item,
      identityDisposition: confirmedLocal
    ).traversal == .descendLocal
  )

  let confirmedProvider = FileProviderBoundaryProbe.identityDisposition(
    for: .known(ProviderIdentity(itemIdentifier: "item", domainIdentifier: "domain"))
  )
  #expect(confirmedProvider == .confirmedProvider)
  #expect(
    FileProviderBoundaryProbe.decideBoundary(
      item: item,
      identityDisposition: confirmedProvider
    ).traversal == .descendMetadataOnlyProviderBoundary
  )
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

extension Data {
  fileprivate mutating func store<T: FixedWidthInteger>(_ value: T, at offset: Int) {
    var littleEndian = value.littleEndian
    Swift.withUnsafeBytes(of: &littleEndian) { bytes in
      replaceSubrange(offset..<offset + bytes.count, with: bytes)
    }
  }
}
