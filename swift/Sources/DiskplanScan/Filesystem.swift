import Darwin
import DiskplanMacOS
import Foundation

public struct DirectoryHandle: Equatable, Hashable, Sendable {
  public let rawValue: Int32
  public init(rawValue: Int32) { self.rawValue = rawValue }
}

public struct InspectedObject: Equatable, Sendable {
  public let identity: ObjectIdentity
  public let bytes: ItemByteEvidence
  public let storageTopology: StorageTopologyEvidence
  public let filesystemTimes: FilesystemTimeEvidence
  public let accessPolicy: Observation<AccessPolicyEvidence>
  public let providerBoundary: ProviderBoundary
  public let providerEvidence: Observation<ProviderScanEvidence>

  public init(
    identity: ObjectIdentity,
    bytes: ItemByteEvidence,
    storageTopology: StorageTopologyEvidence = .unknown,
    filesystemTimes: FilesystemTimeEvidence = .unknown,
    accessPolicy: Observation<AccessPolicyEvidence> = .unknown(reason: "not observed"),
    providerBoundary: ProviderBoundary,
    providerEvidence: Observation<ProviderScanEvidence> = .unknown(reason: "not observed")
  ) {
    self.identity = identity
    self.bytes = bytes
    self.storageTopology = storageTopology
    self.filesystemTimes = filesystemTimes
    self.accessPolicy = accessPolicy
    self.providerBoundary = providerBoundary
    self.providerEvidence = providerEvidence
  }
}

private struct SlotSeal: Equatable, Sendable {
  let identity: ObjectIdentity
  let accessPolicy: AccessPolicyEvidence
  let times: FilesystemTimeEvidence

  static func == (lhs: Self, rhs: Self) -> Bool {
    lhs.identity == rhs.identity && lhs.accessPolicy == rhs.accessPolicy
  }
}

public struct BoundScanRoot: Equatable, Sendable {
  public let binding: RootBinding
  public let directory: DirectoryHandle
  public let providerBoundary: ProviderBoundary

  public init(
    binding: RootBinding,
    directory: DirectoryHandle,
    providerBoundary: ProviderBoundary = .localOrUnindicated
  ) {
    self.binding = binding
    self.directory = directory
    self.providerBoundary = providerBoundary
  }
}

public protocol ScanFilesystem: Sendable {
  func bindRoot(_ request: ScanRootRequest, resolverVersion: UInt32) -> Observation<BoundScanRoot>
  func enumerate(_ directory: DirectoryHandle) -> Observation<[RawPathComponent]>
  func inspect(
    parent: DirectoryHandle,
    name: RawPathComponent,
    inheritedProviderBoundary: Bool
  ) -> Observation<InspectedObject>
  func openDirectory(
    parent: DirectoryHandle,
    name: RawPathComponent,
    expectedIdentity: ObjectIdentity
  ) -> Observation<DirectoryHandle>
  func close(_ directory: DirectoryHandle)
}

public final class DarwinScanFilesystem: ScanFilesystem, @unchecked Sendable {
  private let policy: NoMaterializationPolicy
  private let itemProbe = ItemProbe()
  private let providerProbe = FileProviderBoundaryProbe()

  public init(policy: NoMaterializationPolicy) { self.policy = policy }

  public func bindRoot(
    _ request: ScanRootRequest,
    resolverVersion: UInt32
  ) -> Observation<BoundScanRoot> {
    guard !request.rawAbsolutePath.isEmpty, request.rawAbsolutePath.first == UInt8(ascii: "/"),
      !request.rawAbsolutePath.contains(0)
    else {
      return .failed(reason: "root path is not an absolute raw filesystem path", errorCode: nil)
    }
    let fd = withNullTerminated(request.rawAbsolutePath) {
      open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard fd >= 0 else { return posixObservation(errno, operation: "open scan root") }
    guard let identity = statIdentity(fd: fd) else {
      let code = errno
      Darwin.close(fd)
      return posixObservation(code, operation: "fstat scan root")
    }
    guard identity.objectType == .directory else {
      Darwin.close(fd)
      return .failed(reason: "scan root is not a directory", errorCode: ENOTDIR)
    }
    let boundary: ProviderBoundary
    switch inspectRootSlot(request.rawAbsolutePath, expectedIdentity: identity) {
    case .known(let value): boundary = value
    case let failure:
      Darwin.close(fd)
      return failure.erasingValue()
    }
    return .known(
      BoundScanRoot(
        binding: RootBinding(
          resolverVersion: resolverVersion,
          rootID: request.rootID,
          rawAbsolutePath: request.rawAbsolutePath,
          identity: identity
        ),
        directory: DirectoryHandle(rawValue: fd),
        providerBoundary: boundary
      )
    )
  }

  public func enumerate(_ directory: DirectoryHandle) -> Observation<[RawPathComponent]> {
    let duplicate = dup(directory.rawValue)
    guard duplicate >= 0 else {
      return posixObservation(errno, operation: "duplicate directory descriptor")
    }
    guard let stream = fdopendir(duplicate) else {
      let code = errno
      Darwin.close(duplicate)
      return posixObservation(code, operation: "open directory stream")
    }
    defer { closedir(stream) }
    var components: [RawPathComponent] = []
    errno = 0
    while let entry = readdir(stream) {
      let bytes = withUnsafeBytes(of: entry.pointee.d_name) { raw -> Data in
        let length = raw.firstIndex(of: 0) ?? raw.count
        return Data(raw.prefix(length))
      }
      if bytes == Data(".".utf8) || bytes == Data("..".utf8) { continue }
      guard !bytes.isEmpty, !bytes.contains(0) else {
        return .failed(reason: "directory enumeration returned an invalid name", errorCode: nil)
      }
      components.append(RawPathComponent(bytes))
      errno = 0
    }
    if errno != 0 { return posixObservation(errno, operation: "enumerate directory") }
    return .known(components.sorted())
  }

  public func inspect(
    parent: DirectoryHandle,
    name: RawPathComponent,
    inheritedProviderBoundary: Bool
  ) -> Observation<InspectedObject> {
    let before = statSlotSeal(parent: parent, name: name)
    guard let beforeSeal = before.value else { return before.erasingValue() }
    let capability = itemProbe.probe(
      parentFileDescriptor: parent.rawValue,
      rawName: name.bytes,
      policy: policy
    )
    guard let item = capability.value else {
      return observation(capability, operation: "inspect item", as: InspectedObject.self)
    }
    guard let fileID = item.fileID.value, let objectType = item.objectType.value
    else { return .unknown(reason: "filesystem did not return stable object identity") }
    let after = statSlotSeal(parent: parent, name: name)
    guard let afterSeal = after.value else { return after.erasingValue() }
    guard beforeSeal.identity == afterSeal.identity else {
      return .failed(reason: "object identity changed during item inspection", errorCode: ESTALE)
    }
    guard beforeSeal.accessPolicy == afterSeal.accessPolicy else {
      return .failed(reason: "access policy changed during item inspection", errorCode: EAGAIN)
    }
    let identity = afterSeal.identity
    guard fileID == identity.fileID, scanType(objectType) == identity.objectType else {
      return .failed(reason: "filesystem probes disagreed on object identity", errorCode: ESTALE)
    }
    let boundary: ProviderBoundary
    let providerEvidence: Observation<ProviderScanEvidence>
    let hasProviderHint =
      inheritedProviderBoundary || item.isDataless.value == true || item.isSyncRoot.value == true
    if hasProviderHint {
      let outcome = providerProbe.probe(
        parentFileDescriptor: parent.rawValue,
        rawName: name.bytes,
        policy: policy,
        inheritedProviderBoundary: inheritedProviderBoundary
      )
      switch outcome {
      case .evidence(let evidence):
        switch evidence.traversal {
        case .descendMetadataOnlyProviderBoundary:
          boundary = .metadataOnly(reason: evidence.traversal.rawValue)
        case .doNotDescendDataless, .doNotDescendUnverifiedProviderOwnership:
          boundary = .rejected(reason: evidence.traversal.rawValue)
        }
        providerEvidence = .known(providerScanEvidence(evidence))
      case .rejected(let rejection):
        boundary = .rejected(reason: String(describing: rejection))
        providerEvidence = .failed(reason: String(describing: rejection), errorCode: nil)
      }
    } else {
      boundary = .localOrUnindicated
      providerEvidence = .unknown(reason: "no filesystem provider-boundary indication")
    }
    return .known(
      InspectedObject(
        identity: identity,
        bytes: byteEvidence(item),
        storageTopology: topologyEvidence(item),
        filesystemTimes: afterSeal.times,
        accessPolicy: .known(afterSeal.accessPolicy),
        providerBoundary: boundary,
        providerEvidence: providerEvidence
      )
    )
  }

  public func openDirectory(
    parent: DirectoryHandle,
    name: RawPathComponent,
    expectedIdentity: ObjectIdentity
  ) -> Observation<DirectoryHandle> {
    let fd = withNullTerminated(name.bytes) {
      openat(parent.rawValue, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard fd >= 0 else { return posixObservation(errno, operation: "open child directory") }
    guard let actual = statIdentity(fd: fd) else {
      let code = errno
      Darwin.close(fd)
      return posixObservation(code, operation: "fstat child directory")
    }
    guard actual == expectedIdentity else {
      Darwin.close(fd)
      return .failed(
        reason: "object identity changed between inspection and open", errorCode: ESTALE)
    }
    return .known(DirectoryHandle(rawValue: fd))
  }

  public func close(_ directory: DirectoryHandle) { Darwin.close(directory.rawValue) }

  private func inspectRootSlot(
    _ rawPath: Data,
    expectedIdentity: ObjectIdentity
  ) -> Observation<ProviderBoundary> {
    guard rawPath != Data("/".utf8) else { return .known(.localOrUnindicated) }
    guard rawPath.last != UInt8(ascii: "/"),
      let separator = rawPath.lastIndex(of: UInt8(ascii: "/"))
    else {
      return .failed(reason: "root path has no stable parent slot", errorCode: EINVAL)
    }
    let rawName = Data(rawPath[rawPath.index(after: separator)...])
    guard !rawName.isEmpty else {
      return .failed(reason: "root path has an empty final component", errorCode: EINVAL)
    }
    var parentPath = Data(rawPath[..<separator])
    if parentPath.isEmpty { parentPath = Data("/".utf8) }
    let parentFD = withNullTerminated(parentPath) {
      open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard parentFD >= 0 else { return posixObservation(errno, operation: "open scan root parent") }
    defer { Darwin.close(parentFD) }
    let result = inspect(
      parent: DirectoryHandle(rawValue: parentFD),
      name: RawPathComponent(rawName),
      inheritedProviderBoundary: false
    )
    guard let inspected = result.value else { return result.erasingValue() }
    guard inspected.identity == expectedIdentity else {
      return .failed(
        reason: "scan root identity changed while binding parent slot", errorCode: ESTALE)
    }
    return .known(inspected.providerBoundary)
  }

  private func statIdentity(fd: Int32) -> ObjectIdentity? {
    var value = stat()
    guard fstat(fd, &value) == 0 else { return nil }
    return ObjectIdentity(
      device: Int64(value.st_dev),
      fileID: UInt64(value.st_ino),
      objectType: scanType(mode: value.st_mode)
    )
  }

  private func statSlotSeal(
    parent: DirectoryHandle,
    name: RawPathComponent
  ) -> Observation<SlotSeal> {
    var value = stat()
    let result = withNullTerminated(name.bytes) {
      fstatat(parent.rawValue, $0, &value, AT_SYMLINK_NOFOLLOW)
    }
    guard result == 0 else { return posixObservation(errno, operation: "fstatat item identity") }
    return .known(
      SlotSeal(
        identity: ObjectIdentity(
          device: Int64(value.st_dev),
          fileID: UInt64(value.st_ino),
          objectType: scanType(mode: value.st_mode)
        ),
        accessPolicy: AccessPolicyEvidence(
          ownerUserID: value.st_uid,
          ownerGroupID: value.st_gid,
          mode: UInt32(value.st_mode),
          flags: value.st_flags
        ),
        times: FilesystemTimeEvidence(
          accessTime: .known(canonicalTime(value.st_atimespec)),
          modificationTime: .known(canonicalTime(value.st_mtimespec)),
          statusChangeTime: .known(canonicalTime(value.st_ctimespec)),
          birthTime: .known(canonicalTime(value.st_birthtimespec))
        )
      )
    )
  }

  private func canonicalTime(_ value: timespec) -> CanonicalFilesystemTime {
    CanonicalFilesystemTime(
      secondsSinceEpoch: Int64(value.tv_sec),
      nanoseconds: Int32(clamping: value.tv_nsec)
    )
  }

  private func scanType(_ type: FileSystemObjectType) -> ScannedObjectType {
    switch type {
    case .regular: .regular
    case .directory: .directory
    case .symbolicLink: .symbolicLink
    case .other: .other
    }
  }

  private func scanType(mode: mode_t) -> ScannedObjectType {
    switch mode & S_IFMT {
    case S_IFREG: .regular
    case S_IFDIR: .directory
    case S_IFLNK: .symbolicLink
    default: .other
    }
  }

  private func byteEvidence(_ item: ItemStorageEvidence) -> ItemByteEvidence {
    ItemByteEvidence(
      logical: measure(item.logicalBytes, label: "logical bytes"),
      nominalAllocated: measure(item.nominalAllocatedBytes, label: "allocated bytes"),
      immediatePrivateReclaim: measure(
        item.immediatePrivateReclaimBytes, label: "private reclaim bytes")
    )
  }

  private func topologyEvidence(_ item: ItemStorageEvidence) -> StorageTopologyEvidence {
    StorageTopologyEvidence(
      linkCount: capabilityObservation(item.linkCount),
      mayShareBlocks: capabilityObservation(item.sharing.mayShareBlocks),
      sharesAllBlocks: capabilityObservation(item.sharing.sharesAllBlocks),
      cloneID: capabilityObservation(item.sharing.cloneID),
      cloneRefcount: capabilityObservation(item.sharing.cloneRefcount),
      conditionalGroupReclaim: measure(
        item.sharing.conditionalGroupReclaimBytes,
        label: "conditional group reclaim bytes"
      )
    )
  }

  private func providerScanEvidence(_ evidence: FileProviderEvidence) -> ProviderScanEvidence {
    let identity: Observation<ProviderObjectIdentity>
    if let value = evidence.identity.value {
      identity = .known(
        ProviderObjectIdentity(
          itemIdentifier: value.itemIdentifier,
          domainIdentifier: value.domainIdentifier
        )
      )
    } else {
      identity = capabilityFailureObservation(evidence.identity)
    }
    return ProviderScanEvidence(
      identity: identity,
      promisedMetadata: capabilityObservation(evidence.promisedMetadata),
      hiddenBackingBytes: measure(
        evidence.hiddenBackingBytes, label: "provider hidden backing bytes"),
      controlledNonMaterializationAcceptance: capabilityObservation(
        evidence.controlledNonMaterializationAcceptance)
    )
  }

  private func capabilityFailureObservation<
    Source: Equatable & Sendable, Value: Equatable & Sendable
  >(
    _ capability: Capability<Source>
  ) -> Observation<Value> {
    switch capability.status {
    case .known:
      return .failed(
        reason: "capability value could not be converted", errorCode: capability.errorCode)
    case .permissionDenied:
      return .unreadable(
        reason: capability.detail ?? "capability denied", errorCode: capability.errorCode)
    case .unsupported, .unavailable:
      return .unknown(reason: capability.detail ?? "capability unavailable")
    case .failed, .inconsistent:
      return .failed(
        reason: capability.detail ?? "capability failed", errorCode: capability.errorCode)
    }
  }

  private func measure(_ capability: Capability<UInt64>, label: String) -> ByteMeasure {
    if let value = capability.value { return .exact(value) }
    return .unknown(reason: capability.detail ?? "\(label) unavailable")
  }

  private func capabilityObservation<Value: Equatable & Sendable>(
    _ capability: Capability<Value>
  ) -> Observation<Value> {
    if let value = capability.value { return .known(value) }
    switch capability.status {
    case .known:
      return .failed(reason: "known capability omitted its value", errorCode: capability.errorCode)
    case .permissionDenied:
      return .unreadable(
        reason: capability.detail ?? "capability denied", errorCode: capability.errorCode)
    case .unsupported, .unavailable:
      return .unknown(reason: capability.detail ?? "capability unavailable")
    case .failed, .inconsistent:
      return .failed(
        reason: capability.detail ?? "capability failed", errorCode: capability.errorCode)
    }
  }

  private func observation<Source: Equatable & Sendable, Value: Equatable & Sendable>(
    _ capability: Capability<Source>,
    operation: String,
    as: Value.Type
  ) -> Observation<Value> {
    if capability.errorCode == ENOENT { return .absent(reason: "\(operation): object disappeared") }
    if capability.status == .permissionDenied || capability.errorCode == EACCES
      || capability.errorCode == EPERM
    {
      return .unreadable(reason: capability.detail ?? operation, errorCode: capability.errorCode)
    }
    if capability.status == .unavailable || capability.status == .unsupported {
      return .unknown(reason: capability.detail ?? operation)
    }
    return .failed(reason: capability.detail ?? operation, errorCode: capability.errorCode)
  }

  private func posixObservation<Value: Equatable & Sendable>(
    _ code: Int32,
    operation: String
  ) -> Observation<Value> {
    switch code {
    case ENOENT: .absent(reason: "\(operation): object disappeared")
    case EACCES, EPERM: .unreadable(reason: operation, errorCode: code)
    default: .failed(reason: operation, errorCode: code)
    }
  }

  private func withNullTerminated<T>(_ data: Data, _ body: (UnsafePointer<CChar>) -> T) -> T {
    var bytes = Array(data) + [0]
    return bytes.withUnsafeMutableBytes { raw in
      body(raw.bindMemory(to: CChar.self).baseAddress!)
    }
  }
}
