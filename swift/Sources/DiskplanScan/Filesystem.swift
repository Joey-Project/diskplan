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
  let accessPolicy: AccessPolicyEvidence
  let times: FilesystemTimeEvidence
}

struct IdentityBoundAccessPolicy: Equatable, Sendable {
  let identity: ObjectIdentity
  let accessPolicy: AccessPolicyEvidence
}

private struct PolicyRelevantItemState: Equatable, Sendable {
  let identity: ObjectIdentity
  let linkCount: Capability<UInt32>
  let logicalBytes: Capability<UInt64>
  let nominalAllocatedBytes: Capability<UInt64>
  let immediatePrivateReclaimBytes: Capability<UInt64>
  let sharing: SharingEvidence
  let vfsFlags: Capability<UInt32>
  let isDataless: Capability<Bool>
  let isSyncRoot: Capability<Bool>
  let providerHiddenFootprint: Capability<UInt64>
  let snapshotAttributedBytes: Capability<UInt64>

  var providerState: ProviderPolicyState {
    ProviderPolicyState(vfsFlags: vfsFlags, isDataless: isDataless, isSyncRoot: isSyncRoot)
  }
}

private struct ProviderPolicyState: Equatable, Sendable {
  let vfsFlags: Capability<UInt32>
  let isDataless: Capability<Bool>
  let isSyncRoot: Capability<Bool>
}

public struct EnumerationLimits: Equatable, Sendable {
  public let maximumNames: UInt64
  public let maximumNameBytes: UInt64
  public let deadlineMonotonicNanoseconds: UInt64?

  public init(
    maximumNames: UInt64,
    maximumNameBytes: UInt64,
    deadlineMonotonicNanoseconds: UInt64?
  ) {
    self.maximumNames = maximumNames
    self.maximumNameBytes = maximumNameBytes
    self.deadlineMonotonicNanoseconds = deadlineMonotonicNanoseconds
  }
}

public struct DirectoryEnumeration: Equatable, Sendable {
  public let names: [RawPathComponent]
  public let retainedNameBytes: UInt64
  public let coverage: Coverage

  public init(names: [RawPathComponent], retainedNameBytes: UInt64, coverage: Coverage) {
    self.names = names
    self.retainedNameBytes = retainedNameBytes
    self.coverage = coverage
  }
}

public struct DirectorySlotBinding: Equatable, Sendable {
  public let parent: DirectoryHandle
  public let name: RawPathComponent
  public let expectedIdentity: ObjectIdentity
  public let expectedAccessPolicy: AccessPolicyEvidence
  public let ownsParent: Bool

  public init(
    parent: DirectoryHandle,
    name: RawPathComponent,
    expectedIdentity: ObjectIdentity,
    expectedAccessPolicy: AccessPolicyEvidence,
    ownsParent: Bool
  ) {
    self.parent = parent
    self.name = name
    self.expectedIdentity = expectedIdentity
    self.expectedAccessPolicy = expectedAccessPolicy
    self.ownsParent = ownsParent
  }
}

public struct BoundDirectory: Equatable, Sendable {
  public let handle: DirectoryHandle
  public let slotBinding: DirectorySlotBinding

  public init(handle: DirectoryHandle, slotBinding: DirectorySlotBinding) {
    self.handle = handle
    self.slotBinding = slotBinding
  }
}

public struct DirectoryCloseEvidence: Equatable, Sendable {
  public let identity: Observation<ObjectIdentity>
  public let accessPolicy: Observation<AccessPolicyEvidence>

  public init(
    identity: Observation<ObjectIdentity>,
    accessPolicy: Observation<AccessPolicyEvidence>
  ) {
    self.identity = identity
    self.accessPolicy = accessPolicy
  }
}

public struct BoundScanRoot: Equatable, Sendable {
  public let binding: RootBinding
  public let directory: BoundDirectory
  public let providerBoundary: ProviderBoundary
  public let providerEvidence: Observation<ProviderScanEvidence>
  public let filesystemTimes: FilesystemTimeEvidence
  public let accessPolicy: Observation<AccessPolicyEvidence>

  public init(
    binding: RootBinding,
    directory: BoundDirectory,
    providerBoundary: ProviderBoundary = .localOrUnindicated,
    providerEvidence: Observation<ProviderScanEvidence> = .unknown(reason: "not observed"),
    filesystemTimes: FilesystemTimeEvidence = .unknown,
    accessPolicy: Observation<AccessPolicyEvidence> = .unknown(reason: "not observed")
  ) {
    self.binding = binding
    self.directory = directory
    self.providerBoundary = providerBoundary
    self.providerEvidence = providerEvidence
    self.filesystemTimes = filesystemTimes
    self.accessPolicy = accessPolicy
  }
}

public protocol ScanFilesystem: Sendable {
  func bindRoot(_ request: ScanRootRequest, resolverVersion: UInt32) -> Observation<BoundScanRoot>
  func enumerate(
    _ directory: DirectoryHandle,
    limits: EnumerationLimits
  ) -> Observation<DirectoryEnumeration>
  func inspect(
    parent: DirectoryHandle,
    name: RawPathComponent,
    inheritedProviderBoundary: Bool,
    requiresAuthoritativeProviderEvidence: Bool
  ) -> Observation<InspectedObject>
  func openDirectory(
    parent: DirectoryHandle,
    name: RawPathComponent,
    expectedIdentity: ObjectIdentity,
    expectedAccessPolicy: AccessPolicyEvidence
  ) -> Observation<BoundDirectory>
  func close(_ directory: BoundDirectory) -> DirectoryCloseEvidence
}

public final class DarwinScanFilesystem: ScanFilesystem, @unchecked Sendable {
  private let policy: NoMaterializationPolicy
  private let descriptorIdentityProbe = FileDescriptorIdentityProbe()
  private let pathAccessValidator: @Sendable () -> Capability<NoMaterializationPolicy>
  private let monotonicNow: @Sendable () -> UInt64
  private let itemEvidenceReader:
    @Sendable (Int32, Data, NoMaterializationPolicy) -> Capability<ItemStorageEvidence>
  private let providerEvidenceReader:
    @Sendable (Int32, Data, NoMaterializationPolicy, Bool) -> FileProviderProbeOutcome
  private let boundAccessPolicyOpener: (@Sendable (Int32, Data) -> Int32)?

  public init(policy: NoMaterializationPolicy) {
    self.policy = policy
    pathAccessValidator = { policy.revalidateLive() }
    monotonicNow = { DispatchTime.now().uptimeNanoseconds }
    itemEvidenceReader = { parent, name, livePolicy in
      ItemProbe().probe(
        parentFileDescriptor: parent,
        rawName: name,
        policy: livePolicy
      )
    }
    providerEvidenceReader = { parent, name, livePolicy, inheritedBoundary in
      FileProviderBoundaryProbe().probe(
        parentFileDescriptor: parent,
        rawName: name,
        policy: livePolicy,
        inheritedProviderBoundary: inheritedBoundary
      )
    }
    boundAccessPolicyOpener = nil
  }

  init(
    policy: NoMaterializationPolicy,
    pathAccessValidator: @escaping @Sendable () -> Capability<NoMaterializationPolicy>,
    monotonicNow: @escaping @Sendable () -> UInt64 = {
      DispatchTime.now().uptimeNanoseconds
    },
    itemEvidenceReader:
      @escaping @Sendable (
        Int32, Data, NoMaterializationPolicy
      ) -> Capability<ItemStorageEvidence> = { parent, name, livePolicy in
        ItemProbe().probe(
          parentFileDescriptor: parent,
          rawName: name,
          policy: livePolicy
        )
      },
    providerEvidenceReader:
      @escaping @Sendable (
        Int32, Data, NoMaterializationPolicy, Bool
      ) -> FileProviderProbeOutcome = { parent, name, livePolicy, inheritedBoundary in
        FileProviderBoundaryProbe().probe(
          parentFileDescriptor: parent,
          rawName: name,
          policy: livePolicy,
          inheritedProviderBoundary: inheritedBoundary
        )
      },
    boundAccessPolicyOpener: (@Sendable (Int32, Data) -> Int32)? = nil
  ) {
    self.policy = policy
    self.pathAccessValidator = pathAccessValidator
    self.monotonicNow = monotonicNow
    self.itemEvidenceReader = itemEvidenceReader
    self.providerEvidenceReader = providerEvidenceReader
    self.boundAccessPolicyOpener = boundAccessPolicyOpener
  }

  public func bindRoot(
    _ request: ScanRootRequest,
    resolverVersion: UInt32
  ) -> Observation<BoundScanRoot> {
    guard !request.rawAbsolutePath.isEmpty, request.rawAbsolutePath.first == UInt8(ascii: "/"),
      !request.rawAbsolutePath.contains(0)
    else {
      return .failed(reason: "root path is not an absolute raw filesystem path", errorCode: nil)
    }
    guard request.rawAbsolutePath != Data("/".utf8),
      request.rawAbsolutePath.last != UInt8(ascii: "/"),
      let separator = request.rawAbsolutePath.lastIndex(of: UInt8(ascii: "/"))
    else {
      return .failed(
        reason: "configured root has no authoritative parent-slot provider proof",
        errorCode: ENODATA
      )
    }
    let rawName = Data(request.rawAbsolutePath[request.rawAbsolutePath.index(after: separator)...])
    guard !rawName.isEmpty, rawName != Data(".".utf8), rawName != Data("..".utf8) else {
      return .failed(reason: "root path has an invalid final component", errorCode: EINVAL)
    }
    var parentPath = Data(request.rawAbsolutePath[..<separator])
    if parentPath.isEmpty { parentPath = Data("/".utf8) }
    let parentGate = pathAccessGate(operation: "open scan root parent")
    guard parentGate.value != nil else {
      return observation(
        parentGate,
        operation: "open scan root parent",
        as: BoundScanRoot.self
      )
    }
    let parentFD = withNullTerminated(parentPath) {
      open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard parentFD >= 0 else {
      return posixObservation(errno, operation: "open scan root parent")
    }
    let parent = DirectoryHandle(rawValue: parentFD)
    let inspected = inspect(
      parent: parent,
      name: RawPathComponent(rawName),
      inheritedProviderBoundary: false,
      requiresAuthoritativeProviderEvidence: true
    )
    guard let item = inspected.value else {
      Darwin.close(parentFD)
      return inspected.erasingValue()
    }
    guard item.identity.objectType == .directory else {
      Darwin.close(parentFD)
      return .failed(reason: "scan root is not a directory", errorCode: ENOTDIR)
    }
    guard !item.providerBoundary.preventsNormalDescent else {
      Darwin.close(parentFD)
      return .failed(
        reason: "configured root provider ownership is unavailable or rejected",
        errorCode: ENODATA
      )
    }
    guard let expectedAccessPolicy = item.accessPolicy.value else {
      Darwin.close(parentFD)
      return .failed(reason: "scan root access policy is unavailable", errorCode: ENODATA)
    }
    let pathGate = pathAccessGate(operation: "open scan root")
    guard pathGate.value != nil else {
      Darwin.close(parentFD)
      return observation(pathGate, operation: "open scan root", as: BoundScanRoot.self)
    }
    let fd = withNullTerminated(rawName) {
      openat(parentFD, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard fd >= 0 else {
      let code = errno
      Darwin.close(parentFD)
      return posixObservation(code, operation: "open scan root")
    }
    let descriptorIdentity = descriptorIdentityProbe.probe(fileDescriptor: fd, policy: policy)
    guard let identity = descriptorIdentity.value else {
      Darwin.close(fd)
      Darwin.close(parentFD)
      return observation(
        descriptorIdentity,
        operation: "probe scan root descriptor identity",
        as: BoundScanRoot.self
      )
    }
    let scanIdentity = objectIdentity(identity)
    guard scanIdentity == item.identity else {
      Darwin.close(fd)
      Darwin.close(parentFD)
      return .failed(
        reason: "scan root identity changed between parent-slot proof and open",
        errorCode: ESTALE
      )
    }
    return .known(
      BoundScanRoot(
        binding: RootBinding(
          resolverVersion: resolverVersion,
          rootID: request.rootID,
          rawAbsolutePath: request.rawAbsolutePath,
          identity: scanIdentity
        ),
        directory: BoundDirectory(
          handle: DirectoryHandle(rawValue: fd),
          slotBinding: DirectorySlotBinding(
            parent: parent,
            name: RawPathComponent(rawName),
            expectedIdentity: scanIdentity,
            expectedAccessPolicy: expectedAccessPolicy,
            ownsParent: true
          )
        ),
        providerBoundary: item.providerBoundary,
        providerEvidence: item.providerEvidence,
        filesystemTimes: item.filesystemTimes,
        accessPolicy: item.accessPolicy
      )
    )
  }

  public func enumerate(
    _ directory: DirectoryHandle,
    limits: EnumerationLimits
  ) -> Observation<DirectoryEnumeration> {
    let streamGate = pathAccessGate(operation: "open directory stream")
    guard streamGate.value != nil else {
      return observation(
        streamGate,
        operation: "open directory stream",
        as: DirectoryEnumeration.self
      )
    }
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
    var accumulator = BoundedRawNameAccumulator(limits: limits)
    while true {
      if let deadline = limits.deadlineMonotonicNanoseconds, monotonicNow() >= deadline {
        return .known(accumulator.result(extraCoverage: [.timedOut]))
      }
      let entryGate = pathAccessGate(operation: "enumerate directory")
      guard entryGate.value != nil else {
        return observation(
          entryGate,
          operation: "enumerate directory",
          as: DirectoryEnumeration.self
        )
      }
      errno = 0
      guard let entry = readdir(stream) else {
        if errno != 0 { return posixObservation(errno, operation: "enumerate directory") }
        break
      }
      let bytes = withUnsafeBytes(of: entry.pointee.d_name) { raw -> Data in
        let length = raw.firstIndex(of: 0) ?? raw.count
        return Data(raw.prefix(length))
      }
      if bytes == Data(".".utf8) || bytes == Data("..".utf8) { continue }
      guard !bytes.isEmpty, !bytes.contains(0) else {
        return .failed(reason: "directory enumeration returned an invalid name", errorCode: nil)
      }
      accumulator.insert(RawPathComponent(bytes))
    }
    return .known(accumulator.result())
  }

  public func inspect(
    parent: DirectoryHandle,
    name: RawPathComponent,
    inheritedProviderBoundary: Bool,
    requiresAuthoritativeProviderEvidence: Bool
  ) -> Observation<InspectedObject> {
    let before = statSlotSeal(parent: parent, name: name)
    guard let beforeSeal = before.value else { return before.erasingValue() }
    let beforeCapability = itemEvidenceReader(parent.rawValue, name.bytes, policy)
    guard let beforeItem = beforeCapability.value else {
      return observation(beforeCapability, operation: "inspect item", as: InspectedObject.self)
    }
    guard let beforeIdentity = itemIdentity(beforeItem).value else {
      return itemIdentity(beforeItem).erasingValue()
    }
    let boundary: ProviderBoundary
    let providerEvidence: Observation<ProviderScanEvidence>
    let providerStateIsFullyLocal =
      beforeItem.isDataless.value == false && beforeItem.isSyncRoot.value == false
    if requiresAuthoritativeProviderEvidence || inheritedProviderBoundary
      || !providerStateIsFullyLocal
    {
      let outcome = providerEvidenceReader(
        parent.rawValue,
        name.bytes,
        policy,
        inheritedProviderBoundary
      )
      switch outcome {
      case .evidence(let evidence):
        switch evidence.traversal {
        case .descendMetadataOnlyProviderBoundary:
          boundary = .metadataOnly(reason: evidence.traversal.rawValue)
        case .doNotDescendDataless, .doNotDescendNonDirectory,
          .doNotDescendUnverifiedItemType, .doNotDescendUnverifiedContentState,
          .doNotDescendUnverifiedProviderOwnership:
          boundary = .rejected(reason: evidence.traversal.rawValue)
        }
        providerEvidence = .known(providerScanEvidence(evidence))
      case .rejected(let rejection):
        return providerRejectionObservation(rejection)
      }
    } else {
      boundary = .localOrUnindicated
      providerEvidence = .unknown(
        reason: "provider proof inherited from established local ancestry"
      )
    }
    let afterCapability = itemEvidenceReader(parent.rawValue, name.bytes, policy)
    guard let afterItem = afterCapability.value else {
      return observation(afterCapability, operation: "reinspect item", as: InspectedObject.self)
    }
    let afterIdentityObservation = itemIdentity(afterItem)
    guard let afterIdentity = afterIdentityObservation.value else {
      return afterIdentityObservation.erasingValue()
    }
    guard beforeIdentity == afterIdentity else {
      return .failed(reason: "object identity changed during item inspection", errorCode: ESTALE)
    }
    let beforeState = policyRelevantState(beforeItem, identity: beforeIdentity)
    let afterState = policyRelevantState(afterItem, identity: afterIdentity)
    guard beforeState == afterState else {
      let reason =
        beforeState.providerState == afterState.providerState
        ? "byte or storage-topology evidence changed during provider inspection"
        : "provider, dataless, or sync-root state changed during provider inspection"
      return .failed(reason: reason, errorCode: EBUSY)
    }
    guard beforeItem.isDataless.value != nil else {
      return observation(
        beforeItem.isDataless,
        operation: "prove dataless state after provider inspection",
        as: InspectedObject.self
      )
    }
    guard beforeItem.isSyncRoot.value != nil else {
      return observation(
        beforeItem.isSyncRoot,
        operation: "prove sync-root state after provider inspection",
        as: InspectedObject.self
      )
    }
    let after = statSlotSeal(parent: parent, name: name)
    guard let afterSeal = after.value else { return after.erasingValue() }
    guard beforeSeal.accessPolicy == afterSeal.accessPolicy else {
      return .failed(reason: "access policy changed during item inspection", errorCode: EAGAIN)
    }
    return .known(
      InspectedObject(
        identity: afterIdentity,
        bytes: boundary.preventsNormalDescent ? .unknown : byteEvidence(afterItem),
        storageTopology: topologyEvidence(afterItem),
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
    expectedIdentity: ObjectIdentity,
    expectedAccessPolicy: AccessPolicyEvidence
  ) -> Observation<BoundDirectory> {
    let gate = pathAccessGate(operation: "open child directory")
    guard gate.value != nil else {
      return observation(gate, operation: "open child directory", as: BoundDirectory.self)
    }
    let fd = withNullTerminated(name.bytes) {
      openat(parent.rawValue, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard fd >= 0 else { return posixObservation(errno, operation: "open child directory") }
    let actualCapability = descriptorIdentityProbe.probe(fileDescriptor: fd, policy: policy)
    guard let actual = actualCapability.value else {
      Darwin.close(fd)
      return observation(
        actualCapability,
        operation: "probe child directory descriptor identity",
        as: BoundDirectory.self
      )
    }
    guard objectIdentity(actual) == expectedIdentity else {
      Darwin.close(fd)
      return .failed(
        reason: "object identity changed between inspection and open", errorCode: ESTALE)
    }
    return .known(
      BoundDirectory(
        handle: DirectoryHandle(rawValue: fd),
        slotBinding: DirectorySlotBinding(
          parent: parent,
          name: name,
          expectedIdentity: expectedIdentity,
          expectedAccessPolicy: expectedAccessPolicy,
          ownsParent: false
        )
      )
    )
  }

  public func close(_ directory: BoundDirectory) -> DirectoryCloseEvidence {
    defer {
      Darwin.close(directory.handle.rawValue)
      if directory.slotBinding.ownsParent {
        Darwin.close(directory.slotBinding.parent.rawValue)
      }
    }
    let identityBeforePolicy = closeIdentity(directory)
    let boundPolicy = closeAccessPolicy(directory)
    let identityAfterPolicy = closeIdentity(directory)
    let outerIdentity = bracketedCloseIdentity(
      beforePolicy: identityBeforePolicy,
      afterPolicy: identityAfterPolicy
    )
    let bracketedIdentity = identityIncludingBoundPolicy(
      outerIdentity: outerIdentity,
      policyIdentity: boundPolicy.identity
    )
    let bracketedAccessPolicy: Observation<AccessPolicyEvidence>
    if bracketedIdentity.value != nil || boundPolicy.accessPolicy.value == nil {
      bracketedAccessPolicy = boundPolicy.accessPolicy
    } else {
      bracketedAccessPolicy = .unknown(
        reason: "access-policy observation was not bound to a stable directory identity"
      )
    }
    return DirectoryCloseEvidence(
      identity: bracketedIdentity,
      accessPolicy: bracketedAccessPolicy
    )
  }

  private func identityIncludingBoundPolicy(
    outerIdentity: Observation<ObjectIdentity>,
    policyIdentity: Observation<ObjectIdentity>
  ) -> Observation<ObjectIdentity> {
    guard let expectedIdentity = outerIdentity.value else { return outerIdentity }
    switch policyIdentity {
    case .known(let observedIdentity) where observedIdentity == expectedIdentity:
      return outerIdentity
    case .known, .absent, .failed(_, ESTALE):
      return .failed(
        reason: "directory slot identity changed during bound access-policy observation",
        errorCode: ESTALE
      )
    case .unknown, .unreadable, .failed:
      return outerIdentity
    }
  }

  private func bracketedCloseIdentity(
    beforePolicy: Observation<ObjectIdentity>,
    afterPolicy: Observation<ObjectIdentity>
  ) -> Observation<ObjectIdentity> {
    if beforePolicy == afterPolicy { return beforePolicy }
    if beforePolicy.value != nil, let afterIdentity = afterPolicy.value {
      return .known(afterIdentity)
    }
    return .failed(
      reason: "directory identity state changed while revalidating access policy",
      errorCode: ESTALE
    )
  }

  private func closeIdentity(_ directory: BoundDirectory) -> Observation<ObjectIdentity> {
    let descriptorCapability = descriptorIdentityProbe.probe(
      fileDescriptor: directory.handle.rawValue,
      policy: policy
    )
    guard let descriptorIdentity = descriptorCapability.value else {
      return observation(
        descriptorCapability,
        operation: "revalidate directory descriptor identity at close",
        as: ObjectIdentity.self
      )
    }
    let observedDescriptorIdentity = objectIdentity(descriptorIdentity)
    guard observedDescriptorIdentity == directory.slotBinding.expectedIdentity else {
      return .failed(
        reason: "directory descriptor identity changed before close",
        errorCode: ESTALE
      )
    }
    let slotCapability = itemEvidenceReader(
      directory.slotBinding.parent.rawValue,
      directory.slotBinding.name.bytes,
      policy
    )
    guard let slotItem = slotCapability.value else {
      return observation(
        slotCapability,
        operation: "revalidate directory parent slot at close",
        as: ObjectIdentity.self
      )
    }
    let slotIdentityObservation = itemIdentity(slotItem)
    guard let slotIdentity = slotIdentityObservation.value else {
      return slotIdentityObservation.erasingValue()
    }
    guard slotIdentity == directory.slotBinding.expectedIdentity else {
      return .failed(
        reason: "directory parent slot identity changed before close",
        errorCode: ESTALE
      )
    }
    return .known(slotIdentity)
  }

  private func closeAccessPolicy(
    _ directory: BoundDirectory
  ) -> DirectoryCloseEvidence {
    let boundSeal = identityBoundAccessPolicy(
      parent: directory.slotBinding.parent,
      name: directory.slotBinding.name
    )
    guard let observedSeal = boundSeal.value else {
      return DirectoryCloseEvidence(
        identity: boundSeal.erasingValue(),
        accessPolicy: boundSeal.erasingValue()
      )
    }
    guard observedSeal.identity == directory.slotBinding.expectedIdentity else {
      return DirectoryCloseEvidence(
        identity: .failed(
          reason: "directory slot identity changed during access-policy observation",
          errorCode: ESTALE
        ),
        accessPolicy: .unknown(
          reason: "access policy belongs to a replacement directory identity"
        )
      )
    }
    let accessPolicy: Observation<AccessPolicyEvidence>
    if observedSeal.accessPolicy == directory.slotBinding.expectedAccessPolicy {
      accessPolicy = .known(observedSeal.accessPolicy)
    } else {
      accessPolicy = .failed(
        reason: "directory access policy changed before close",
        errorCode: EAGAIN
      )
    }
    return DirectoryCloseEvidence(
      identity: .known(observedSeal.identity),
      accessPolicy: accessPolicy
    )
  }

  private func identityBoundAccessPolicy(
    parent: DirectoryHandle,
    name: RawPathComponent
  ) -> Observation<IdentityBoundAccessPolicy> {
    let gate = pathAccessGate(operation: "bind directory slot for access-policy inspection")
    guard let livePolicy = gate.value else {
      return observation(
        gate,
        operation: "bind directory slot for access-policy inspection",
        as: IdentityBoundAccessPolicy.self
      )
    }
    let fd =
      if let boundAccessPolicyOpener {
        boundAccessPolicyOpener(parent.rawValue, name.bytes)
      } else {
        withNullTerminated(name.bytes) {
          openat(parent.rawValue, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        }
      }
    guard fd >= 0 else {
      return posixObservation(errno, operation: "open directory slot for access-policy inspection")
    }
    defer { Darwin.close(fd) }
    let identityCapability = descriptorIdentityProbe.probe(
      fileDescriptor: fd,
      policy: livePolicy
    )
    guard let descriptorIdentity = identityCapability.value else {
      return observation(
        identityCapability,
        operation: "read identity bound to directory access policy",
        as: IdentityBoundAccessPolicy.self
      )
    }
    var value = stat()
    guard fstat(fd, &value) == 0 else {
      return posixObservation(errno, operation: "read descriptor-bound directory access policy")
    }
    return .known(
      IdentityBoundAccessPolicy(
        identity: objectIdentity(descriptorIdentity),
        accessPolicy: AccessPolicyEvidence(
          ownerUserID: value.st_uid,
          ownerGroupID: value.st_gid,
          mode: UInt32(value.st_mode),
          flags: value.st_flags
        )
      )
    )
  }

  private func statSlotSeal(
    parent: DirectoryHandle,
    name: RawPathComponent
  ) -> Observation<SlotSeal> {
    let gate = pathAccessGate(operation: "inspect item access policy")
    guard gate.value != nil else {
      return observation(gate, operation: "inspect item access policy", as: SlotSeal.self)
    }
    var value = stat()
    let result = withNullTerminated(name.bytes) {
      fstatat(parent.rawValue, $0, &value, AT_SYMLINK_NOFOLLOW)
    }
    guard result == 0 else { return posixObservation(errno, operation: "fstatat item identity") }
    return .known(
      SlotSeal(
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

  private func objectIdentity(_ identity: FileObjectIdentity) -> ObjectIdentity {
    ObjectIdentity(
      device: identity.device,
      fileID: identity.fileID,
      objectType: scanType(identity.objectType)
    )
  }

  private func itemIdentity(_ item: ItemStorageEvidence) -> Observation<ObjectIdentity> {
    guard let device = item.device.value else {
      return observation(
        item.device,
        operation: "read real device identity",
        as: ObjectIdentity.self
      )
    }
    guard let fileID = item.fileID.value else {
      return observation(item.fileID, operation: "read file ID", as: ObjectIdentity.self)
    }
    guard let objectType = item.objectType.value else {
      return observation(
        item.objectType,
        operation: "read object type",
        as: ObjectIdentity.self
      )
    }
    return .known(
      ObjectIdentity(device: device, fileID: fileID, objectType: scanType(objectType))
    )
  }

  private func policyRelevantState(
    _ item: ItemStorageEvidence,
    identity: ObjectIdentity
  ) -> PolicyRelevantItemState {
    PolicyRelevantItemState(
      identity: identity,
      linkCount: item.linkCount,
      logicalBytes: item.logicalBytes,
      nominalAllocatedBytes: item.nominalAllocatedBytes,
      immediatePrivateReclaimBytes: item.immediatePrivateReclaimBytes,
      sharing: item.sharing,
      vfsFlags: item.vfsFlags,
      isDataless: item.isDataless,
      isSyncRoot: item.isSyncRoot,
      providerHiddenFootprint: item.providerHiddenFootprint,
      snapshotAttributedBytes: item.snapshotAttributedBytes
    )
  }

  private func providerRejectionObservation(
    _ rejection: FileProviderProbeRejection
  ) -> Observation<InspectedObject> {
    switch rejection {
    case .policyUnavailable(let status, let detail, let code):
      return providerStatusObservation(
        status: status,
        reason: detail ?? "provider probe policy unavailable",
        errorCode: code
      )
    case .rawNameUnavailable:
      return .unknown(reason: "provider probe cannot represent the raw item name")
    case .missing(let stage):
      return .absent(reason: "provider probe item missing at \(stage.rawValue)")
    case .unreadable(let stage, let code):
      return .unreadable(
        reason: "provider probe item unreadable at \(stage.rawValue)",
        errorCode: code
      )
    case .failed(let stage, let status, let detail, let code):
      return providerStatusObservation(
        status: status,
        reason: detail ?? "provider probe failed at \(stage.rawValue)",
        errorCode: code
      )
    case .identityMismatch(let stage, _, _):
      return .failed(
        reason: "provider probe item identity changed at \(stage.rawValue)",
        errorCode: ESTALE
      )
    case .parentIdentityMismatch(let stage, _, _):
      return .failed(
        reason: "provider probe parent identity changed at \(stage.rawValue)",
        errorCode: ESTALE
      )
    case .contentStateUnavailable(let stage, let status, let detail, let code):
      return providerStatusObservation(
        status: status,
        reason: detail ?? "provider content state unavailable at \(stage.rawValue)",
        errorCode: code
      )
    case .contentStateMismatch(let stage, _, _):
      return .failed(
        reason: "provider content state changed at \(stage.rawValue)",
        errorCode: EBUSY
      )
    case .timedOut(let stage):
      return .failed(
        reason: "provider probe timed out at \(stage.rawValue)",
        errorCode: ETIMEDOUT
      )
    }
  }

  private func providerStatusObservation(
    status: CapabilityStatus,
    reason: String,
    errorCode: Int32?
  ) -> Observation<InspectedObject> {
    if status == .permissionDenied || errorCode == EACCES || errorCode == EPERM {
      return .unreadable(reason: reason, errorCode: errorCode)
    }
    if errorCode == ENOENT { return .absent(reason: reason) }
    switch status {
    case .unsupported, .unavailable:
      return .unknown(reason: reason)
    case .known, .failed, .inconsistent:
      return .failed(reason: reason, errorCode: errorCode)
    case .permissionDenied:
      return .unreadable(reason: reason, errorCode: errorCode)
    }
  }

  private func pathAccessGate(operation: String) -> Capability<NoMaterializationPolicy> {
    let capability = pathAccessValidator()
    guard capability.value != nil else {
      return Capability(
        status: capability.status,
        detail: capability.detail
          ?? "live no-materialization policy unavailable before \(operation)",
        errorCode: capability.errorCode
      )
    }
    return capability
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

struct BoundedRawNameAccumulator: Sendable {
  private let limits: EnumerationLimits
  private var names: [RawPathComponent] = []
  private var retainedBytes: UInt64 = 0
  private var truncated = false

  init(limits: EnumerationLimits) { self.limits = limits }

  mutating func insert(_ name: RawPathComponent) {
    var lower = 0
    var upper = names.count
    while lower < upper {
      let middle = lower + (upper - lower) / 2
      if name < names[middle] { upper = middle } else { lower = middle + 1 }
    }
    if lower > 0, names[lower - 1] == name { return }
    names.insert(name, at: lower)
    retainedBytes = addingSaturated(retainedBytes, UInt64(name.bytes.count))
    while UInt64(names.count) > limits.maximumNames
      || retainedBytes > limits.maximumNameBytes
    {
      let removed = names.removeLast()
      retainedBytes -= UInt64(removed.bytes.count)
      truncated = true
    }
  }

  func result(extraCoverage: [CoverageReason] = []) -> DirectoryEnumeration {
    DirectoryEnumeration(
      names: names,
      retainedNameBytes: retainedBytes,
      coverage: Coverage(
        completeness: truncated || !extraCoverage.isEmpty ? .partial : .complete,
        reasons: (truncated ? [.budgetExhausted] : []) + extraCoverage
      )
    )
  }

  private func addingSaturated(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
    let (sum, overflow) = lhs.addingReportingOverflow(rhs)
    return overflow ? UInt64.max : sum
  }
}
