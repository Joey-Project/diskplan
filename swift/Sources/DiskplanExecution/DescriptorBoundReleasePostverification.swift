import CryptoKit
import Darwin
import DiskplanPolicy
import Foundation

struct ReleaseDescriptorAccessSeal: Equatable, Sendable {
  let mode: UInt32
  let ownerUserID: UInt32
  let ownerGroupID: UInt32
  let authorizationFlags: UInt32
  let aclDigest: PolicyDigest
  let mountIdentity: Data
}

struct ReleaseDescriptorNamespaceSeal: Equatable, Sendable {
  let identity: ObjectIdentity
  let access: ReleaseDescriptorAccessSeal
}

enum ReleasePostverificationNamespaceLocation: Equatable, Sendable {
  case root
  case parentChain(index: Int)
}

enum ReleaseOwnerSlotTransition: Equatable, Sendable {
  case missing
  case identityChanged(current: ObjectIdentity)
}

struct AuthorizedReleaseNamespaceComponent: Sendable {
  let rawNameFromParent: Data?
  let descriptor: Int32
  let authorizedSeal: ReleaseDescriptorNamespaceSeal
}

struct ReleasePostverificationOwnerLocator: Sendable {
  let actionID: ActionID
  let candidateID: String
  let expectedIdentity: ObjectIdentity
  let namespace: [AuthorizedReleaseNamespaceComponent]
  let rawLeafName: Data
}

struct ReleaseFileTopologyExpectation: Equatable, Sendable {
  let fileObjectID: String
  let owners: [FileOwnerLink]
  let linkCount: Observation<UInt32>

  init(
    fileObjectID: String,
    owners: [FileOwnerLink],
    linkCount: Observation<UInt32>
  ) {
    self.fileObjectID = fileObjectID
    self.owners = owners
    self.linkCount = linkCount
  }

  init(_ value: FileTopologyExpectation) {
    fileObjectID = value.fileObjectID
    owners = value.owners
    linkCount = value.linkCount
  }

  static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.fileObjectID) == RawUTF8Key(rhs.fileObjectID)
      && lhs.owners == rhs.owners
      && lhs.linkCount == rhs.linkCount
  }
}

struct ReleaseAllocationTopologyExpectation: Equatable, Sendable {
  let allocationGroupID: String
  let fileObjects: [ReleaseFileTopologyExpectation]
  let cloneRefCount: Observation<UInt32>
  let sharedBytes: Observation<UInt64>
  let snapshotBlocker: Observation<Bool>

  init(_ value: ReleaseTopologyExpectation) {
    allocationGroupID = value.allocationGroupID
    fileObjects = value.fileObjects.map(ReleaseFileTopologyExpectation.init)
    cloneRefCount = value.cloneRefCount
    sharedBytes = value.sharedBytes
    snapshotBlocker = value.snapshotBlocker
  }

  init(
    allocationGroupID: String,
    fileObjects: [ReleaseFileTopologyExpectation],
    cloneRefCount: Observation<UInt32>,
    sharedBytes: Observation<UInt64>,
    snapshotBlocker: Observation<Bool>
  ) {
    self.allocationGroupID = allocationGroupID
    self.fileObjects = fileObjects
    self.cloneRefCount = cloneRefCount
    self.sharedBytes = sharedBytes
    self.snapshotBlocker = snapshotBlocker
  }

  static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.allocationGroupID) == RawUTF8Key(rhs.allocationGroupID)
      && lhs.fileObjects == rhs.fileObjects
      && lhs.cloneRefCount == rhs.cloneRefCount
      && lhs.sharedBytes == rhs.sharedBytes
      && lhs.snapshotBlocker == rhs.snapshotBlocker
  }
}

struct ReleasePostverificationGroupExpectation: Equatable, Sendable {
  let allocationGroupID: String
  let topology: ReleaseAllocationTopologyExpectation
  let ownerActionIDs: [ActionID]

  static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.allocationGroupID) == RawUTF8Key(rhs.allocationGroupID)
      && lhs.topology == rhs.topology
      && lhs.ownerActionIDs == rhs.ownerActionIDs
  }
}

struct ReleasePostverificationExecutionBinding: Equatable, Sendable {
  let executionBindingHash: PolicyDigest
  let componentID: PolicyDigest
  let epoch: ExecutionEpochContext
  let planCaptureID: PolicyDigest
  let jitCaptureID: PolicyDigest
  let freshnessLimitSeconds: Int64
}

struct ReleasePostverificationComponentRequest: Sendable {
  let execution: ReleasePostverificationExecutionBinding
  let owners: [ReleasePostverificationOwnerLocator]
  let groups: [ReleasePostverificationGroupExpectation]
}

enum ReleasePostverificationFreezeError: Error, Equatable, Sendable {
  case emptyComponent
  case invalidExecutionBinding
  case duplicateOwner(ActionID)
  case duplicateAllocationGroup(String)
  case invalidOwnerMembership(String)
  case invalidOwnerLeaf(ActionID)
  case invalidNamespaceChain(ActionID)
  case descriptorDuplicationFailed(ActionID, ReleasePostverificationNamespaceLocation, Int32)
  case namespaceMissing(ActionID, ReleasePostverificationNamespaceLocation)
  case namespaceUnreadable(
    ActionID, ReleasePostverificationNamespaceLocation, ObservationFailure
  )
  case namespaceCollectionFailed(
    ActionID, ReleasePostverificationNamespaceLocation, ObservationFailure
  )
  case namespaceUnknown(ActionID, ReleasePostverificationNamespaceLocation, UnknownReason)
  case namespaceIdentityMismatch(ActionID, ReleasePostverificationNamespaceLocation)
  case namespaceAccessMismatch(ActionID, ReleasePostverificationNamespaceLocation)
  case namespaceContainmentMismatch(ActionID, ReleasePostverificationNamespaceLocation)
  case targetMissing(ActionID)
  case targetUnreadable(ActionID, ObservationFailure)
  case targetCollectionFailed(ActionID, ObservationFailure)
  case targetUnknown(ActionID, UnknownReason)
  case targetIdentityMismatch(ActionID)
}

enum ReleasePostverificationFailure: Error, Equatable, Sendable {
  case leaseAlreadyConsumed
  case namespaceMissing(ActionID, ReleasePostverificationNamespaceLocation)
  case namespaceUnreadable(
    ActionID, ReleasePostverificationNamespaceLocation, ObservationFailure
  )
  case namespaceIdentityMismatch(ActionID, ReleasePostverificationNamespaceLocation)
  case namespaceAccessMismatch(ActionID, ReleasePostverificationNamespaceLocation)
  case namespaceContainmentMismatch(ActionID, ReleasePostverificationNamespaceLocation)
  case namespaceCollectionFailed(
    ActionID, ReleasePostverificationNamespaceLocation, ObservationFailure
  )
  case namespaceUnknown(ActionID, ReleasePostverificationNamespaceLocation, UnknownReason)
  case ownerSlotUnreadable(ActionID, ObservationFailure)
  case ownerSlotCollectionFailed(ActionID, ObservationFailure)
  case ownerSlotUnknown(ActionID, UnknownReason)
  case ownerSlotStillReferencesExpectedObject(ActionID)
  case topologyMissing
  case topologyUnreadable(ObservationFailure)
  case topologyCollectorFailed(ObservationFailure)
  case topologyUnknown(UnknownReason)
  case topologyReceiptBindingMismatch
  case topologyReceiptNotFresh
  case topologyCaptureReused
  case allocationGroupStillAllocated(String)
  case invalidAllocationGroupReleaseEvidence(String)
}

struct ReleasedFileObjectTopologyEvidence: Equatable, Sendable {
  let fileObjectID: Data
  let remainingOwnerCount: UInt32
}

struct AllocationGroupReleasedTopologyEvidence: Equatable, Sendable {
  let allocationGroupID: String
  let allocationGroupPresent: Bool
  let fileObjects: [ReleasedFileObjectTopologyEvidence]

  static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.allocationGroupID) == RawUTF8Key(rhs.allocationGroupID)
      && lhs.allocationGroupPresent == rhs.allocationGroupPresent
      && lhs.fileObjects == rhs.fileObjects
  }
}

enum CurrentAllocationGroupReleaseTopology: Equatable, Sendable {
  case allocationGroupReleased(AllocationGroupReleasedTopologyEvidence)
  case allocationGroupStillAllocated
}

struct CurrentReleaseTopologyGroup: Equatable, Sendable {
  let allocationGroupID: String
  let topology: CurrentAllocationGroupReleaseTopology

  static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.allocationGroupID) == RawUTF8Key(rhs.allocationGroupID)
      && lhs.topology == rhs.topology
  }
}

struct CurrentReleaseTopologyCapture: Equatable, Sendable {
  let captureID: PolicyDigest
  let executionBindingHash: PolicyDigest
  let componentID: PolicyDigest
  let epochID: String
  let oneShotNonce: Data
  let capturedAtSeconds: Int64
  let groups: [CurrentReleaseTopologyGroup]
}

enum BorrowedReleaseDescriptorOwnership: String, Equatable, Sendable {
  case borrowedUntilTopologyCallReturns
}

struct BorrowedReleaseDescriptor: Sendable {
  let rawValue: Int32
  let ownership: BorrowedReleaseDescriptorOwnership
}

struct ReleasePostverificationTopologyOwner: Sendable {
  let actionID: ActionID
  let candidateID: String
  let expectedIdentity: ObjectIdentity
  let namespaceDescriptors: [BorrowedReleaseDescriptor]
  let rawLeafName: Data
  let transition: ReleaseOwnerSlotTransition
}

struct ReleasePostverificationTopologyRequest: Sendable {
  let executionBindingHash: PolicyDigest
  let componentID: PolicyDigest
  let epoch: ExecutionEpochContext
  let oneShotNonce: Data
  let groups: [ReleasePostverificationGroupExpectation]
  let owners: [ReleasePostverificationTopologyOwner]
}

protocol ReleasePostverificationTopologySource: Sendable {
  /// Descriptors are CLOEXEC duplicates borrowed only for this call. The source must not close,
  /// retain, or transfer them. Logical bytes, free-space deltas, and pathname absence are not
  /// release proofs and do not appear in the returned current-capture evidence.
  func collectReleaseTopology(
    for request: ReleasePostverificationTopologyRequest
  ) async throws -> Observation<CurrentReleaseTopologyCapture>
}

enum ReleaseOwnerSlotObservation: Equatable, Sendable {
  case missing
  case present(ObjectIdentity)
  case unknown(UnknownReason)
  case unreadable(ObservationFailure)
  case failed(ObservationFailure)
}

protocol ReleasePostverificationDescriptorProbing: Sendable {
  func namespaceSeal(descriptor: Int32) -> Observation<ReleaseDescriptorNamespaceSeal>
  func ownerSlot(
    parentDescriptor: Int32,
    rawLeafName: Data
  ) -> ReleaseOwnerSlotObservation
  func descendantDirectory(
    parentDescriptor: Int32,
    rawName: Data
  ) -> Observation<Int32>
}

struct POSIXReleasePostverificationDescriptorProbe: ReleasePostverificationDescriptorProbing {
  private enum SealSubcollectionResult<Value> {
    case success(Value)
    case failure(Observation<ReleaseDescriptorNamespaceSeal>)
  }

  func namespaceSeal(descriptor: Int32) -> Observation<ReleaseDescriptorNamespaceSeal> {
    var before = stat()
    guard Darwin.fstat(descriptor, &before) == 0 else {
      return Self.observationFailure(errno, operation: "fstat-namespace")
    }
    guard let identity = Self.identity(before) else {
      return .failed(
        ObservationFailure(
          code: "unsupported-namespace-object-kind",
          collector: "release-postverification-descriptor"
        ))
    }
    let aclDigest: PolicyDigest
    switch Self.aclDigest(descriptor) {
    case .success(let value): aclDigest = value
    case .failure(let observation): return observation
    }
    let mountIdentity: Data
    switch Self.mountIdentity(descriptor) {
    case .success(let value): mountIdentity = value
    case .failure(let observation): return observation
    }
    var after = stat()
    guard Darwin.fstat(descriptor, &after) == 0 else {
      return Self.observationFailure(errno, operation: "fstat-namespace-after-access")
    }
    guard Self.identity(after) == identity else {
      return .failed(
        ObservationFailure(
          code: "namespace-identity-changed-during-access-seal",
          collector: "release-postverification-descriptor"
        ))
    }
    return .known(
      ReleaseDescriptorNamespaceSeal(
        identity: identity,
        access: ReleaseDescriptorAccessSeal(
          mode: UInt32(before.st_mode),
          ownerUserID: before.st_uid,
          ownerGroupID: before.st_gid,
          authorizationFlags: Self.authorizationFlags(before.st_flags),
          aclDigest: aclDigest,
          mountIdentity: mountIdentity
        )
      ))
  }

  func ownerSlot(
    parentDescriptor: Int32,
    rawLeafName: Data
  ) -> ReleaseOwnerSlotObservation {
    var value = stat()
    let result = Self.withRawCString(rawLeafName) { name in
      Darwin.fstatat(parentDescriptor, name, &value, AT_SYMLINK_NOFOLLOW)
    }
    guard result == 0 else {
      let currentErrno = errno
      if currentErrno == ENOENT { return .missing }
      let failure = ObservationFailure(
        code: "fstatat-owner-slot-errno-\(currentErrno)",
        collector: "release-postverification-descriptor"
      )
      return currentErrno == EACCES || currentErrno == EPERM
        ? .unreadable(failure)
        : .failed(failure)
    }
    guard let identity = Self.identity(value) else {
      return .failed(
        ObservationFailure(
          code: "unsupported-owner-object-kind",
          collector: "release-postverification-descriptor"
        ))
    }
    return .present(identity)
  }

  func descendantDirectory(
    parentDescriptor: Int32,
    rawName: Data
  ) -> Observation<Int32> {
    let descriptor = Self.withRawCString(rawName) { name in
      Darwin.openat(
        parentDescriptor,
        name,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
      )
    }
    guard descriptor >= 0 else {
      return Self.observationFailure(errno, operation: "open-namespace-descendant")
    }
    return .known(descriptor)
  }

  private static func aclDigest(
    _ descriptor: Int32
  ) -> SealSubcollectionResult<PolicyDigest> {
    errno = 0
    guard let acl = Darwin.acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
      if errno == ENOENT {
        return .success(
          try! PolicyDigest(
            bytes: Data(SHA256.hash(data: Data("diskplan/empty-acl/v1".utf8)))
          )
        )
      }
      return .failure(observationFailure(errno, operation: "read-namespace-acl"))
    }
    defer { _ = Darwin.acl_free(UnsafeMutableRawPointer(acl)) }
    var length: ssize_t = 0
    guard let text = Darwin.acl_to_text(acl, &length), length >= 0 else {
      return .failure(observationFailure(errno, operation: "serialize-namespace-acl"))
    }
    defer { _ = Darwin.acl_free(text) }
    return .success(
      try! PolicyDigest(
        bytes: Data(SHA256.hash(data: Data(bytes: text, count: Int(length))))
      )
    )
  }

  private static func mountIdentity(
    _ descriptor: Int32
  ) -> SealSubcollectionResult<Data> {
    var value = statfs()
    guard Darwin.fstatfs(descriptor, &value) == 0 else {
      return .failure(observationFailure(errno, operation: "fstatfs-namespace-mount"))
    }
    return .success(withUnsafeBytes(of: value.f_fsid) { Data($0) })
  }

  private static func observationFailure<Value: Equatable & Sendable>(
    _ currentErrno: Int32,
    operation: String
  ) -> Observation<Value> {
    if currentErrno == ENOENT { return .absent }
    let failure = ObservationFailure(
      code: "\(operation)-errno-\(currentErrno)",
      collector: "release-postverification-descriptor"
    )
    return currentErrno == EACCES || currentErrno == EPERM
      ? .unreadable(failure)
      : .failed(failure)
  }

  fileprivate static func identity(_ value: stat) -> ObjectIdentity? {
    let kind: ObjectKind
    switch value.st_mode & S_IFMT {
    case S_IFREG: kind = .regularFile
    case S_IFDIR: kind = .directory
    case S_IFLNK: kind = .symbolicLink
    default: return nil
    }
    return ObjectIdentity(
      device: UInt64(UInt32(bitPattern: value.st_dev)),
      object: UInt64(value.st_ino),
      generation: .known(UInt64(value.st_gen)),
      type: kind
    )
  }

  private static func authorizationFlags(_ flags: UInt32) -> UInt32 {
    flags & 0x001E_0086
  }

  private static func withRawCString<Result>(
    _ bytes: Data,
    _ body: (UnsafePointer<CChar>) -> Result
  ) -> Result {
    var terminated = [UInt8](bytes)
    terminated.append(0)
    return terminated.withUnsafeBufferPointer { buffer in
      body(UnsafeRawPointer(buffer.baseAddress!).assumingMemoryBound(to: CChar.self))
    }
  }
}

struct EngineAllocationGroupReleaseReceipt: Equatable, Sendable {
  let allocationGroupID: String
  let captureID: PolicyDigest
  let executionBindingHash: PolicyDigest
  let componentID: PolicyDigest
  let epochID: String
  let capturedAtSeconds: Int64
  let releasedFileObjectIDs: [Data]

  fileprivate init(
    allocationGroupID: String,
    captureID: PolicyDigest,
    executionBindingHash: PolicyDigest,
    componentID: PolicyDigest,
    epochID: String,
    capturedAtSeconds: Int64,
    releasedFileObjectIDs: [Data]
  ) {
    self.allocationGroupID = allocationGroupID
    self.captureID = captureID
    self.executionBindingHash = executionBindingHash
    self.componentID = componentID
    self.epochID = epochID
    self.capturedAtSeconds = capturedAtSeconds
    self.releasedFileObjectIDs = releasedFileObjectIDs
  }

  static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.allocationGroupID) == RawUTF8Key(rhs.allocationGroupID)
      && lhs.captureID == rhs.captureID
      && lhs.executionBindingHash == rhs.executionBindingHash
      && lhs.componentID == rhs.componentID
      && lhs.epochID == rhs.epochID
      && lhs.capturedAtSeconds == rhs.capturedAtSeconds
      && lhs.releasedFileObjectIDs == rhs.releasedFileObjectIDs
  }
}

struct DescriptorBoundAllocationGroupPostverification: Equatable, Sendable {
  let allocationGroupID: String
  let outcome: DescriptorBoundAllocationGroupOutcome

  static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.allocationGroupID) == RawUTF8Key(rhs.allocationGroupID)
      && lhs.outcome == rhs.outcome
  }
}

enum DescriptorBoundAllocationGroupOutcome: Equatable, Sendable {
  case allocationGroupReleased(EngineAllocationGroupReleaseReceipt)
  case rejected(ReleasePostverificationFailure)
}

struct DescriptorBoundReleasePostverificationReport: Equatable, Sendable {
  let ownerTransitions: [ActionID: ReleaseOwnerSlotTransition]
  let groups: [DescriptorBoundAllocationGroupPostverification]
}

private struct FrozenReleaseNamespaceComponent: Sendable {
  let rawNameFromParent: Data?
  let descriptor: Int32
  let authorizedSeal: ReleaseDescriptorNamespaceSeal
}

private struct FrozenReleasePostverificationOwner: Sendable {
  let actionID: ActionID
  let candidateID: String
  let expectedIdentity: ObjectIdentity
  let namespace: [FrozenReleaseNamespaceComponent]
  let rawLeafName: Data
}

final class FrozenReleasePostverificationComponent: @unchecked Sendable {
  fileprivate let execution: ReleasePostverificationExecutionBinding
  fileprivate let frozenAtSeconds: Int64
  fileprivate let owners: [FrozenReleasePostverificationOwner]
  fileprivate let groups: [ReleasePostverificationGroupExpectation]
  private let lock = NSLock()
  private var consumed = false
  private var descriptorsClosed = false

  fileprivate init(
    execution: ReleasePostverificationExecutionBinding,
    frozenAtSeconds: Int64,
    owners: [FrozenReleasePostverificationOwner],
    groups: [ReleasePostverificationGroupExpectation]
  ) {
    self.execution = execution
    self.frozenAtSeconds = frozenAtSeconds
    self.owners = owners
    self.groups = groups
  }

  deinit { closeOwnedDescriptors() }

  var ownedDescriptorValues: [Int32] {
    owners.flatMap { $0.namespace.map(\.descriptor) }
  }

  fileprivate func claim() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard !consumed else { return false }
    consumed = true
    return true
  }

  fileprivate func finishConsumption() {
    closeOwnedDescriptors()
  }

  private func closeOwnedDescriptors() {
    lock.lock()
    guard !descriptorsClosed else {
      lock.unlock()
      return
    }
    descriptorsClosed = true
    let descriptors = owners.flatMap { $0.namespace.map(\.descriptor) }
    lock.unlock()
    for descriptor in descriptors { _ = Darwin.close(descriptor) }
  }
}

private final class PerCallReleaseDescriptorOwner: @unchecked Sendable {
  private struct Entry {
    let descriptor: Int32
    let identity: ObjectIdentity
  }

  private var entries: [Entry]
  private let lock = NSLock()
  private var closed = false

  init(entries: [(Int32, ObjectIdentity)]) {
    self.entries = entries.map { Entry(descriptor: $0.0, identity: $0.1) }
  }

  deinit { closeWithoutTouchingReusedDescriptors() }

  func allDescriptorsStillBorrowedAndBound() -> Bool {
    lock.lock()
    let pending = entries
    let isClosed = closed
    lock.unlock()
    guard !isClosed else { return false }
    return pending.allSatisfy { entry in
      var value = stat()
      return Darwin.fstat(entry.descriptor, &value) == 0
        && POSIXReleasePostverificationDescriptorProbe.identity(value) == entry.identity
    }
  }

  func closeWithoutTouchingReusedDescriptors() {
    lock.lock()
    guard !closed else {
      lock.unlock()
      return
    }
    closed = true
    let pending = entries
    entries.removeAll()
    lock.unlock()
    for entry in pending {
      var value = stat()
      guard Darwin.fstat(entry.descriptor, &value) == 0 else { continue }
      guard POSIXReleasePostverificationDescriptorProbe.identity(value) == entry.identity else {
        continue
      }
      _ = Darwin.close(entry.descriptor)
    }
  }
}

private final class ReleaseTopologyCaptureRegistry: @unchecked Sendable {
  private let lock = NSLock()
  private var used = Set<PolicyDigest>()

  func claim(_ captureID: PolicyDigest) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return used.insert(captureID).inserted
  }
}

struct DescriptorBoundReleasePostverificationCore: Sendable {
  private let descriptorProbe: any ReleasePostverificationDescriptorProbing
  private let topologySource: any ReleasePostverificationTopologySource
  private let nowSeconds: @Sendable () -> Int64
  private let nonceGenerator: @Sendable () -> Data
  private let captureRegistry: ReleaseTopologyCaptureRegistry

  init(
    topologySource: any ReleasePostverificationTopologySource,
    descriptorProbe: any ReleasePostverificationDescriptorProbing =
      POSIXReleasePostverificationDescriptorProbe(),
    nowSeconds: @escaping @Sendable () -> Int64 = {
      Int64(Date().timeIntervalSince1970.rounded(.down))
    },
    nonceGenerator: @escaping @Sendable () -> Data = {
      var generator = SystemRandomNumberGenerator()
      return Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }
  ) {
    self.topologySource = topologySource
    self.descriptorProbe = descriptorProbe
    self.nowSeconds = nowSeconds
    self.nonceGenerator = nonceGenerator
    self.captureRegistry = ReleaseTopologyCaptureRegistry()
  }

  func freeze(
    _ request: ReleasePostverificationComponentRequest
  ) throws -> FrozenReleasePostverificationComponent {
    let frozenAtSeconds = nowSeconds()
    guard !request.owners.isEmpty, !request.groups.isEmpty else {
      throw ReleasePostverificationFreezeError.emptyComponent
    }
    guard request.execution.planCaptureID != request.execution.jitCaptureID,
      request.execution.freshnessLimitSeconds > 0,
      frozenAtSeconds >= request.execution.epoch.issuedAtSeconds,
      frozenAtSeconds < request.execution.epoch.deadlineSeconds
    else {
      throw ReleasePostverificationFreezeError.invalidExecutionBinding
    }
    var seenOwners = Set<ActionID>()
    for owner in request.owners {
      guard seenOwners.insert(owner.actionID).inserted else {
        throw ReleasePostverificationFreezeError.duplicateOwner(owner.actionID)
      }
      guard Self.isValidLeaf(owner.rawLeafName) else {
        throw ReleasePostverificationFreezeError.invalidOwnerLeaf(owner.actionID)
      }
      guard !owner.namespace.isEmpty,
        owner.namespace[0].rawNameFromParent == nil,
        owner.namespace[0].authorizedSeal.identity.type == .directory,
        owner.namespace.dropFirst().allSatisfy({
          $0.authorizedSeal.identity.type == .directory
            && $0.rawNameFromParent.map(Self.isValidLeaf) == true
        })
      else {
        throw ReleasePostverificationFreezeError.invalidNamespaceChain(owner.actionID)
      }
    }
    let allOwnerIDs = seenOwners
    var seenGroups = Set<RawUTF8Key>()
    for group in request.groups {
      guard seenGroups.insert(RawUTF8Key(group.allocationGroupID)).inserted else {
        throw ReleasePostverificationFreezeError.duplicateAllocationGroup(
          group.allocationGroupID
        )
      }
      guard
        RawUTF8Key(group.topology.allocationGroupID)
          == RawUTF8Key(group.allocationGroupID),
        !group.ownerActionIDs.isEmpty,
        Set(group.ownerActionIDs).count == group.ownerActionIDs.count,
        Set(group.ownerActionIDs).isSubset(of: allOwnerIDs)
      else {
        throw ReleasePostverificationFreezeError.invalidOwnerMembership(
          group.allocationGroupID
        )
      }
    }

    var frozenOwners: [FrozenReleasePostverificationOwner] = []
    do {
      for owner in request.owners.sorted(by: { $0.actionID < $1.actionID }) {
        frozenOwners.append(try freezeOwner(owner))
      }
    } catch {
      for owner in frozenOwners {
        for component in owner.namespace { _ = Darwin.close(component.descriptor) }
      }
      throw error
    }
    return FrozenReleasePostverificationComponent(
      execution: request.execution,
      frozenAtSeconds: frozenAtSeconds,
      owners: frozenOwners,
      groups: request.groups.sorted {
        RawUTF8Key($0.allocationGroupID) < RawUTF8Key($1.allocationGroupID)
      }
    )
  }

  func postverify(
    _ component: FrozenReleasePostverificationComponent
  ) async -> DescriptorBoundReleasePostverificationReport {
    guard component.claim() else {
      return rejectedReport(
        groups: component.groups,
        transitions: [:],
        failure: .leaseAlreadyConsumed
      )
    }
    defer { component.finishConsumption() }

    var transitions: [ActionID: ReleaseOwnerSlotTransition] = [:]
    var ownerFailures: [ActionID: ReleasePostverificationFailure] = [:]
    for owner in component.owners {
      if let failure = verifyNamespace(owner) {
        ownerFailures[owner.actionID] = failure
        continue
      }
      switch descriptorProbe.ownerSlot(
        parentDescriptor: owner.namespace.last!.descriptor,
        rawLeafName: owner.rawLeafName
      ) {
      case .missing:
        transitions[owner.actionID] = .missing
      case .present(let identity):
        if identity == owner.expectedIdentity {
          ownerFailures[owner.actionID] =
            .ownerSlotStillReferencesExpectedObject(owner.actionID)
        } else {
          transitions[owner.actionID] = .identityChanged(current: identity)
        }
      case .unknown(let reason):
        ownerFailures[owner.actionID] = .ownerSlotUnknown(owner.actionID, reason)
      case .unreadable(let failure):
        ownerFailures[owner.actionID] = .ownerSlotUnreadable(owner.actionID, failure)
      case .failed(let failure):
        ownerFailures[owner.actionID] = .ownerSlotCollectionFailed(owner.actionID, failure)
      }
    }
    if let failure = component.owners.map(\.actionID).sorted()
      .compactMap({ ownerFailures[$0] }).first
    {
      return rejectedReport(
        groups: component.groups,
        transitions: transitions,
        failure: failure
      )
    }

    switch await collectTopology(component: component, transitions: transitions) {
    case .failure(let failure):
      return rejectedReport(
        groups: component.groups,
        transitions: transitions,
        failure: failure
      )
    case .success(let receipts):
      let receiptByGroup = Dictionary(
        uniqueKeysWithValues: receipts.map { (RawUTF8Key($0.allocationGroupID), $0) }
      )
      return DescriptorBoundReleasePostverificationReport(
        ownerTransitions: transitions,
        groups: component.groups.map { group in
          DescriptorBoundAllocationGroupPostverification(
            allocationGroupID: group.allocationGroupID,
            outcome: .allocationGroupReleased(
              receiptByGroup[RawUTF8Key(group.allocationGroupID)]!
            )
          )
        }
      )
    }
  }

  private func freezeOwner(
    _ owner: ReleasePostverificationOwnerLocator
  ) throws -> FrozenReleasePostverificationOwner {
    var frozen: [FrozenReleaseNamespaceComponent] = []
    do {
      for (index, authorized) in owner.namespace.enumerated() {
        let location = Self.location(index)
        let descriptor = try duplicate(
          authorized.descriptor,
          ownerID: owner.actionID,
          location: location
        )
        do {
          try requireAuthorizedSeal(
            descriptorProbe.namespaceSeal(descriptor: descriptor),
            authorized: authorized.authorizedSeal,
            ownerID: owner.actionID,
            location: location
          )
          frozen.append(
            FrozenReleaseNamespaceComponent(
              rawNameFromParent: authorized.rawNameFromParent,
              descriptor: descriptor,
              authorizedSeal: authorized.authorizedSeal
            )
          )
        } catch {
          _ = Darwin.close(descriptor)
          throw error
        }
      }
      try requireContainedChain(frozen, ownerID: owner.actionID, freeze: true)
      switch descriptorProbe.ownerSlot(
        parentDescriptor: frozen.last!.descriptor,
        rawLeafName: owner.rawLeafName
      ) {
      case .missing:
        throw ReleasePostverificationFreezeError.targetMissing(owner.actionID)
      case .unknown(let reason):
        throw ReleasePostverificationFreezeError.targetUnknown(owner.actionID, reason)
      case .unreadable(let failure):
        throw ReleasePostverificationFreezeError.targetUnreadable(owner.actionID, failure)
      case .failed(let failure):
        throw ReleasePostverificationFreezeError.targetCollectionFailed(
          owner.actionID, failure
        )
      case .present(let identity):
        guard identity == owner.expectedIdentity else {
          throw ReleasePostverificationFreezeError.targetIdentityMismatch(owner.actionID)
        }
      }
      return FrozenReleasePostverificationOwner(
        actionID: owner.actionID,
        candidateID: owner.candidateID,
        expectedIdentity: owner.expectedIdentity,
        namespace: frozen,
        rawLeafName: owner.rawLeafName
      )
    } catch {
      for component in frozen { _ = Darwin.close(component.descriptor) }
      throw error
    }
  }

  private func verifyNamespace(
    _ owner: FrozenReleasePostverificationOwner
  ) -> ReleasePostverificationFailure? {
    for (index, component) in owner.namespace.enumerated() {
      let location = Self.location(index)
      switch descriptorProbe.namespaceSeal(descriptor: component.descriptor) {
      case .absent:
        return .namespaceMissing(owner.actionID, location)
      case .unknown(let reason):
        return .namespaceUnknown(owner.actionID, location, reason)
      case .unreadable(let failure):
        return .namespaceUnreadable(owner.actionID, location, failure)
      case .failed(let failure):
        return .namespaceCollectionFailed(owner.actionID, location, failure)
      case .known(let current):
        guard current.identity == component.authorizedSeal.identity else {
          return .namespaceIdentityMismatch(owner.actionID, location)
        }
        guard current.access == component.authorizedSeal.access else {
          return .namespaceAccessMismatch(owner.actionID, location)
        }
      }
    }
    do {
      try requireContainedChain(owner.namespace, ownerID: owner.actionID, freeze: false)
      return nil
    } catch let failure as ReleasePostverificationFailure {
      return failure
    } catch {
      return .namespaceCollectionFailed(
        owner.actionID,
        .root,
        ObservationFailure(
          code: String(reflecting: type(of: error)),
          collector: "release-postverification-descriptor"
        )
      )
    }
  }

  private func requireContainedChain(
    _ chain: [FrozenReleaseNamespaceComponent],
    ownerID: ActionID,
    freeze: Bool
  ) throws {
    guard chain.count > 1 else { return }
    for index in 1..<chain.count {
      let location = Self.location(index)
      let expected = chain[index].authorizedSeal
      guard let name = chain[index].rawNameFromParent else {
        if freeze {
          throw ReleasePostverificationFreezeError.invalidNamespaceChain(ownerID)
        }
        throw ReleasePostverificationFailure.namespaceContainmentMismatch(ownerID, location)
      }
      let opened: Int32
      switch descriptorProbe.descendantDirectory(
        parentDescriptor: chain[index - 1].descriptor,
        rawName: name
      ) {
      case .known(let descriptor):
        opened = descriptor
      case .absent:
        if freeze {
          throw ReleasePostverificationFreezeError.namespaceMissing(ownerID, location)
        }
        throw ReleasePostverificationFailure.namespaceMissing(ownerID, location)
      case .unknown(let reason):
        if freeze {
          throw ReleasePostverificationFreezeError.namespaceUnknown(ownerID, location, reason)
        }
        throw ReleasePostverificationFailure.namespaceUnknown(ownerID, location, reason)
      case .unreadable(let failure):
        if freeze {
          throw ReleasePostverificationFreezeError.namespaceUnreadable(
            ownerID, location, failure
          )
        }
        throw ReleasePostverificationFailure.namespaceUnreadable(ownerID, location, failure)
      case .failed(let failure):
        if freeze {
          throw ReleasePostverificationFreezeError.namespaceCollectionFailed(
            ownerID, location, failure
          )
        }
        throw ReleasePostverificationFailure.namespaceCollectionFailed(
          ownerID, location, failure
        )
      }
      defer { _ = Darwin.close(opened) }
      switch descriptorProbe.namespaceSeal(descriptor: opened) {
      case .known(let current):
        guard current.identity == expected.identity else {
          if freeze {
            throw ReleasePostverificationFreezeError.namespaceContainmentMismatch(
              ownerID, location
            )
          }
          throw ReleasePostverificationFailure.namespaceContainmentMismatch(
            ownerID, location
          )
        }
        guard current.access == expected.access else {
          if freeze {
            throw ReleasePostverificationFreezeError.namespaceAccessMismatch(
              ownerID, location
            )
          }
          throw ReleasePostverificationFailure.namespaceAccessMismatch(ownerID, location)
        }
      case .absent:
        if freeze {
          throw ReleasePostverificationFreezeError.namespaceMissing(ownerID, location)
        }
        throw ReleasePostverificationFailure.namespaceMissing(ownerID, location)
      case .unknown(let reason):
        if freeze {
          throw ReleasePostverificationFreezeError.namespaceUnknown(ownerID, location, reason)
        }
        throw ReleasePostverificationFailure.namespaceUnknown(ownerID, location, reason)
      case .unreadable(let failure):
        if freeze {
          throw ReleasePostverificationFreezeError.namespaceUnreadable(
            ownerID, location, failure
          )
        }
        throw ReleasePostverificationFailure.namespaceUnreadable(ownerID, location, failure)
      case .failed(let failure):
        if freeze {
          throw ReleasePostverificationFreezeError.namespaceCollectionFailed(
            ownerID, location, failure
          )
        }
        throw ReleasePostverificationFailure.namespaceCollectionFailed(
          ownerID, location, failure
        )
      }
    }
  }

  private func collectTopology(
    component: FrozenReleasePostverificationComponent,
    transitions: [ActionID: ReleaseOwnerSlotTransition]
  ) async -> Result<[EngineAllocationGroupReleaseReceipt], ReleasePostverificationFailure> {
    let nonce = nonceGenerator()
    guard nonce.count == 32 else { return .failure(.topologyReceiptBindingMismatch) }
    let borrowed:
      (
        owners: [ReleasePostverificationTopologyOwner],
        owner: PerCallReleaseDescriptorOwner
      )
    do {
      borrowed = try makeBorrowedTopologyOwners(
        component.owners,
        transitions: transitions
      )
    } catch let failure as ReleasePostverificationFailure {
      return .failure(failure)
    } catch {
      return .failure(
        .topologyCollectorFailed(
          ObservationFailure(
            code: String(reflecting: type(of: error)),
            collector: "release-topology-descriptor-duplication"
          )
        )
      )
    }
    defer { borrowed.owner.closeWithoutTouchingReusedDescriptors() }

    let observation: Observation<CurrentReleaseTopologyCapture>
    do {
      observation = try await topologySource.collectReleaseTopology(
        for: ReleasePostverificationTopologyRequest(
          executionBindingHash: component.execution.executionBindingHash,
          componentID: component.execution.componentID,
          epoch: component.execution.epoch,
          oneShotNonce: nonce,
          groups: component.groups,
          owners: borrowed.owners
        )
      )
    } catch {
      return .failure(
        .topologyCollectorFailed(
          ObservationFailure(
            code: error is CancellationError
              ? "cancelled" : String(reflecting: type(of: error)),
            collector: "release-topology-source"
          )
        )
      )
    }
    guard borrowed.owner.allDescriptorsStillBorrowedAndBound() else {
      return .failure(
        .topologyCollectorFailed(
          ObservationFailure(
            code: "borrowed-descriptor-ownership-violated",
            collector: "release-topology-source"
          )
        )
      )
    }
    switch observation {
    case .absent:
      return .failure(.topologyMissing)
    case .unknown(let reason):
      return .failure(.topologyUnknown(reason))
    case .unreadable(let failure):
      return .failure(.topologyUnreadable(failure))
    case .failed(let failure):
      return .failure(.topologyCollectorFailed(failure))
    case .known(let capture):
      return validateCapture(capture, component: component, nonce: nonce)
    }
  }

  private func validateCapture(
    _ capture: CurrentReleaseTopologyCapture,
    component: FrozenReleasePostverificationComponent,
    nonce: Data
  ) -> Result<[EngineAllocationGroupReleaseReceipt], ReleasePostverificationFailure> {
    let now = nowSeconds()
    let execution = component.execution
    guard capture.executionBindingHash == execution.executionBindingHash,
      capture.componentID == execution.componentID,
      capture.epochID == execution.epoch.epochID,
      capture.oneShotNonce == nonce
    else {
      return .failure(.topologyReceiptBindingMismatch)
    }
    guard capture.captureID != execution.planCaptureID,
      capture.captureID != execution.jitCaptureID
    else {
      return .failure(.topologyCaptureReused)
    }
    let captureAge = now.subtractingReportingOverflow(capture.capturedAtSeconds)
    guard capture.capturedAtSeconds >= component.frozenAtSeconds,
      capture.capturedAtSeconds >= execution.epoch.issuedAtSeconds,
      capture.capturedAtSeconds < execution.epoch.deadlineSeconds,
      capture.capturedAtSeconds <= now,
      !captureAge.overflow,
      captureAge.partialValue <= execution.freshnessLimitSeconds
    else {
      return .failure(.topologyReceiptNotFresh)
    }
    let capturesByGroup = Dictionary(grouping: capture.groups) {
      RawUTF8Key($0.allocationGroupID)
    }
    let expectedGroupKeys = Set(
      component.groups.map {
        RawUTF8Key($0.allocationGroupID)
      })
    guard capturesByGroup.count == component.groups.count,
      Set(capturesByGroup.keys) == expectedGroupKeys,
      capturesByGroup.values.allSatisfy({ $0.count == 1 })
    else {
      return .failure(.topologyReceiptBindingMismatch)
    }

    var receipts: [EngineAllocationGroupReleaseReceipt] = []
    for expected in component.groups {
      let groupID = expected.allocationGroupID
      let captured = capturesByGroup[RawUTF8Key(groupID)]!.first!
      switch captured.topology {
      case .allocationGroupStillAllocated:
        return .failure(.allocationGroupStillAllocated(groupID))
      case .allocationGroupReleased(let evidence):
        guard RawUTF8Key(evidence.allocationGroupID) == RawUTF8Key(groupID),
          !evidence.allocationGroupPresent
        else {
          return .failure(.invalidAllocationGroupReleaseEvidence(groupID))
        }
        let expectedFileIDs = expected.topology.fileObjects.map {
          Data($0.fileObjectID.utf8)
        }.sorted(by: { $0.lexicographicallyPrecedes($1) })
        let capturedFileIDs = evidence.fileObjects.map(\.fileObjectID)
          .sorted(by: { $0.lexicographicallyPrecedes($1) })
        guard Set(expectedFileIDs).count == expectedFileIDs.count,
          Set(capturedFileIDs).count == capturedFileIDs.count,
          expectedFileIDs == capturedFileIDs,
          evidence.fileObjects.allSatisfy({ $0.remainingOwnerCount == 0 })
        else {
          return .failure(.invalidAllocationGroupReleaseEvidence(groupID))
        }
        receipts.append(
          EngineAllocationGroupReleaseReceipt(
            allocationGroupID: groupID,
            captureID: capture.captureID,
            executionBindingHash: capture.executionBindingHash,
            componentID: capture.componentID,
            epochID: capture.epochID,
            capturedAtSeconds: capture.capturedAtSeconds,
            releasedFileObjectIDs: capturedFileIDs
          )
        )
      }
    }
    guard captureRegistry.claim(capture.captureID) else {
      return .failure(.topologyCaptureReused)
    }
    return .success(receipts)
  }

  private func makeBorrowedTopologyOwners(
    _ owners: [FrozenReleasePostverificationOwner],
    transitions: [ActionID: ReleaseOwnerSlotTransition]
  ) throws -> (
    owners: [ReleasePostverificationTopologyOwner],
    owner: PerCallReleaseDescriptorOwner
  ) {
    var owned: [(Int32, ObjectIdentity)] = []
    var borrowedOwners: [ReleasePostverificationTopologyOwner] = []
    do {
      for owner in owners {
        guard let transition = transitions[owner.actionID] else {
          throw ReleasePostverificationFailure.invalidAllocationGroupReleaseEvidence(
            "missing-owner-transition"
          )
        }
        var descriptors: [BorrowedReleaseDescriptor] = []
        for component in owner.namespace {
          let duplicate = Darwin.fcntl(component.descriptor, F_DUPFD_CLOEXEC, 0)
          guard duplicate >= 0 else {
            throw ReleasePostverificationFailure.topologyCollectorFailed(
              ObservationFailure(
                code: "duplicate-topology-descriptor-errno-\(errno)",
                collector: "release-topology-descriptor-duplication"
              )
            )
          }
          owned.append((duplicate, component.authorizedSeal.identity))
          descriptors.append(
            BorrowedReleaseDescriptor(
              rawValue: duplicate,
              ownership: .borrowedUntilTopologyCallReturns
            )
          )
        }
        borrowedOwners.append(
          ReleasePostverificationTopologyOwner(
            actionID: owner.actionID,
            candidateID: owner.candidateID,
            expectedIdentity: owner.expectedIdentity,
            namespaceDescriptors: descriptors,
            rawLeafName: owner.rawLeafName,
            transition: transition
          )
        )
      }
    } catch {
      PerCallReleaseDescriptorOwner(entries: owned)
        .closeWithoutTouchingReusedDescriptors()
      throw error
    }
    return (
      borrowedOwners,
      PerCallReleaseDescriptorOwner(entries: owned)
    )
  }

  private func rejectedReport(
    groups: [ReleasePostverificationGroupExpectation],
    transitions: [ActionID: ReleaseOwnerSlotTransition],
    failure: ReleasePostverificationFailure
  ) -> DescriptorBoundReleasePostverificationReport {
    DescriptorBoundReleasePostverificationReport(
      ownerTransitions: transitions,
      groups: groups.map {
        DescriptorBoundAllocationGroupPostverification(
          allocationGroupID: $0.allocationGroupID,
          outcome: .rejected(failure)
        )
      }
    )
  }

  private func requireAuthorizedSeal(
    _ observation: Observation<ReleaseDescriptorNamespaceSeal>,
    authorized: ReleaseDescriptorNamespaceSeal,
    ownerID: ActionID,
    location: ReleasePostverificationNamespaceLocation
  ) throws {
    switch observation {
    case .known(let current):
      guard current.identity == authorized.identity else {
        throw ReleasePostverificationFreezeError.namespaceIdentityMismatch(ownerID, location)
      }
      guard current.access == authorized.access else {
        throw ReleasePostverificationFreezeError.namespaceAccessMismatch(ownerID, location)
      }
    case .absent:
      throw ReleasePostverificationFreezeError.namespaceMissing(ownerID, location)
    case .unknown(let reason):
      throw ReleasePostverificationFreezeError.namespaceUnknown(ownerID, location, reason)
    case .unreadable(let failure):
      throw ReleasePostverificationFreezeError.namespaceUnreadable(
        ownerID, location, failure
      )
    case .failed(let failure):
      throw ReleasePostverificationFreezeError.namespaceCollectionFailed(
        ownerID, location, failure
      )
    }
  }

  private func duplicate(
    _ descriptor: Int32,
    ownerID: ActionID,
    location: ReleasePostverificationNamespaceLocation
  ) throws -> Int32 {
    let duplicate = Darwin.fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
    guard duplicate >= 0 else {
      throw ReleasePostverificationFreezeError.descriptorDuplicationFailed(
        ownerID, location, errno
      )
    }
    return duplicate
  }

  private static func location(_ index: Int) -> ReleasePostverificationNamespaceLocation {
    index == 0 ? .root : .parentChain(index: index - 1)
  }

  private static func isValidLeaf(_ leaf: Data) -> Bool {
    !leaf.isEmpty && leaf != Data(".".utf8) && leaf != Data("..".utf8)
      && !leaf.contains(0) && !leaf.contains(47)
  }
}
