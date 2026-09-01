import Darwin
import DiskplanPolicy
import Foundation

struct ReleaseDescriptorAccessSeal: Equatable, Sendable {
  let mode: UInt32
  let ownerUserID: UInt32
  let ownerGroupID: UInt32
  let flags: UInt32
}

struct ReleaseDescriptorNamespaceSeal: Equatable, Sendable {
  let identity: ObjectIdentity
  let access: ReleaseDescriptorAccessSeal
}

enum ReleasePostverificationNamespaceLocation: String, Equatable, Sendable {
  case root
  case parent
}

enum ReleaseOwnerSlotTransition: Equatable, Sendable {
  case missing
  case identityChanged(current: ObjectIdentity)
}

struct ReleasePostverificationOwnerLocator: Sendable {
  let actionID: ActionID
  let candidateID: String
  let expectedIdentity: ObjectIdentity
  let rootDescriptor: Int32
  let parentDescriptor: Int32
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

struct ReleasePostverificationComponentRequest: Sendable {
  let owners: [ReleasePostverificationOwnerLocator]
  let groups: [ReleasePostverificationGroupExpectation]
}

enum ReleasePostverificationFreezeError: Error, Equatable, Sendable {
  case emptyComponent
  case duplicateOwner(ActionID)
  case duplicateAllocationGroup(String)
  case invalidOwnerMembership(String)
  case invalidOwnerLeaf(ActionID)
  case descriptorDuplicationFailed(ActionID, ReleasePostverificationNamespaceLocation, Int32)
  case namespaceMissing(ActionID, ReleasePostverificationNamespaceLocation)
  case namespaceUnreadable(
    ActionID, ReleasePostverificationNamespaceLocation, ObservationFailure
  )
  case namespaceCollectionFailed(
    ActionID, ReleasePostverificationNamespaceLocation, ObservationFailure
  )
  case namespaceUnknown(ActionID, ReleasePostverificationNamespaceLocation, UnknownReason)
}

enum ReleasePostverificationFailure: Equatable, Sendable {
  case leaseAlreadyConsumed
  case namespaceMissing(ActionID, ReleasePostverificationNamespaceLocation)
  case namespaceUnreadable(
    ActionID, ReleasePostverificationNamespaceLocation, ObservationFailure
  )
  case namespaceIdentityMismatch(ActionID, ReleasePostverificationNamespaceLocation)
  case namespaceAccessMismatch(ActionID, ReleasePostverificationNamespaceLocation)
  case namespaceCollectionFailed(
    ActionID, ReleasePostverificationNamespaceLocation, ObservationFailure
  )
  case namespaceUnknown(ActionID, ReleasePostverificationNamespaceLocation, UnknownReason)
  case ownerSlotUnreadable(ActionID, ObservationFailure)
  case ownerSlotCollectionFailed(ActionID, ObservationFailure)
  case ownerSlotUnknown(ActionID, UnknownReason)
  case ownerSlotStillReferencesExpectedObject(ActionID)
  case topologyMissing(String)
  case topologyUnreadable(String, ObservationFailure)
  case topologyCollectorFailed(String, ObservationFailure)
  case topologyUnknown(String, UnknownReason)
  case allocationGroupStillAllocated(String)
  case invalidAllocationGroupReleaseProof(String)
}

struct AllocationGroupReleasedTopologyProof: Equatable, Sendable {
  let allocationGroupID: String
  let expectedTopology: ReleaseAllocationTopologyExpectation
  let ownerActionIDs: [ActionID]
  let captureID: PolicyDigest

  static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.allocationGroupID) == RawUTF8Key(rhs.allocationGroupID)
      && lhs.expectedTopology == rhs.expectedTopology
      && lhs.ownerActionIDs == rhs.ownerActionIDs
      && lhs.captureID == rhs.captureID
  }
}

enum CurrentAllocationGroupReleaseTopology: Equatable, Sendable {
  case allocationGroupReleased(AllocationGroupReleasedTopologyProof)
  case allocationGroupStillAllocated
}

struct ReleasePostverificationTopologyOwner: Sendable {
  let actionID: ActionID
  let candidateID: String
  let expectedIdentity: ObjectIdentity
  let rootDescriptor: Int32
  let parentDescriptor: Int32
  let rawLeafName: Data
  let transition: ReleaseOwnerSlotTransition
}

struct ReleasePostverificationTopologyRequest: Sendable {
  let allocationGroupID: String
  let expectedTopology: ReleaseAllocationTopologyExpectation
  let owners: [ReleasePostverificationTopologyOwner]
}

protocol ReleasePostverificationTopologySource: Sendable {
  /// Collects storage-topology evidence only. Logical bytes, filesystem free-space deltas,
  /// and pathname absence are not release proofs and do not appear in this interface.
  func collectReleaseTopology(
    for request: ReleasePostverificationTopologyRequest
  ) async throws -> Observation<CurrentAllocationGroupReleaseTopology>
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
}

struct POSIXReleasePostverificationDescriptorProbe: ReleasePostverificationDescriptorProbing {
  func namespaceSeal(descriptor: Int32) -> Observation<ReleaseDescriptorNamespaceSeal> {
    var value = stat()
    guard Darwin.fstat(descriptor, &value) == 0 else {
      return Self.observationFailure(errno, operation: "fstat-namespace")
    }
    guard let identity = Self.identity(value) else {
      return .failed(
        ObservationFailure(
          code: "unsupported-namespace-object-kind",
          collector: "release-postverification-descriptor"
        ))
    }
    return .known(
      ReleaseDescriptorNamespaceSeal(
        identity: identity,
        access: ReleaseDescriptorAccessSeal(
          mode: UInt32(value.st_mode),
          ownerUserID: value.st_uid,
          ownerGroupID: value.st_gid,
          flags: value.st_flags
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
        code: "fstatat-owner-slot-errno-(currentErrno)",
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

  private static func observationFailure<Value: Equatable & Sendable>(
    _ currentErrno: Int32,
    operation: String
  ) -> Observation<Value> {
    if currentErrno == ENOENT { return .absent }
    let failure = ObservationFailure(
      code: "(operation)-errno-(currentErrno)",
      collector: "release-postverification-descriptor"
    )
    return currentErrno == EACCES || currentErrno == EPERM
      ? .unreadable(failure)
      : .failed(failure)
  }

  private static func identity(_ value: stat) -> ObjectIdentity? {
    let kind: ObjectKind
    switch value.st_mode & S_IFMT {
    case S_IFREG: kind = .regularFile
    case S_IFDIR: kind = .directory
    case S_IFLNK: kind = .symbolicLink
    default: return nil
    }
    return ObjectIdentity(
      device: UInt64(value.st_dev),
      object: UInt64(value.st_ino),
      generation: .known(UInt64(value.st_gen)),
      type: kind
    )
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

struct DescriptorBoundAllocationGroupPostverification: Equatable, Sendable {
  let allocationGroupID: String
  let outcome: DescriptorBoundAllocationGroupOutcome

  static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.allocationGroupID) == RawUTF8Key(rhs.allocationGroupID)
      && lhs.outcome == rhs.outcome
  }
}

enum DescriptorBoundAllocationGroupOutcome: Equatable, Sendable {
  case allocationGroupReleased(AllocationGroupReleasedTopologyProof)
  case rejected(ReleasePostverificationFailure)
}

struct DescriptorBoundReleasePostverificationReport: Equatable, Sendable {
  let ownerTransitions: [ActionID: ReleaseOwnerSlotTransition]
  let groups: [DescriptorBoundAllocationGroupPostverification]
}

private struct FrozenReleasePostverificationOwner: Sendable {
  let actionID: ActionID
  let candidateID: String
  let expectedIdentity: ObjectIdentity
  let rootDescriptor: Int32
  let parentDescriptor: Int32
  let rawLeafName: Data
  let rootSeal: ReleaseDescriptorNamespaceSeal
  let parentSeal: ReleaseDescriptorNamespaceSeal
}

final class FrozenReleasePostverificationComponent: @unchecked Sendable {
  fileprivate let owners: [FrozenReleasePostverificationOwner]
  fileprivate let groups: [ReleasePostverificationGroupExpectation]
  private let lock = NSLock()
  private var consumed = false

  fileprivate init(
    owners: [FrozenReleasePostverificationOwner],
    groups: [ReleasePostverificationGroupExpectation]
  ) {
    self.owners = owners
    self.groups = groups
  }

  deinit {
    for owner in owners {
      _ = Darwin.close(owner.rootDescriptor)
      _ = Darwin.close(owner.parentDescriptor)
    }
  }

  fileprivate func claim() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard !consumed else { return false }
    consumed = true
    return true
  }
}

struct DescriptorBoundReleasePostverificationCore: Sendable {
  private let descriptorProbe: any ReleasePostverificationDescriptorProbing
  private let topologySource: any ReleasePostverificationTopologySource

  init(
    topologySource: any ReleasePostverificationTopologySource,
    descriptorProbe: any ReleasePostverificationDescriptorProbing =
      POSIXReleasePostverificationDescriptorProbe()
  ) {
    self.topologySource = topologySource
    self.descriptorProbe = descriptorProbe
  }

  /// Duplicates every borrowed locator before mutation. The frozen seals protect object identity
  /// and access policy; timestamps and child-entry churn are intentionally excluded.
  func freeze(
    _ request: ReleasePostverificationComponentRequest
  ) throws -> FrozenReleasePostverificationComponent {
    guard !request.owners.isEmpty, !request.groups.isEmpty else {
      throw ReleasePostverificationFreezeError.emptyComponent
    }
    var seenOwners = Set<ActionID>()
    for owner in request.owners {
      guard seenOwners.insert(owner.actionID).inserted else {
        throw ReleasePostverificationFreezeError.duplicateOwner(owner.actionID)
      }
      guard Self.isValidLeaf(owner.rawLeafName) else {
        throw ReleasePostverificationFreezeError.invalidOwnerLeaf(owner.actionID)
      }
    }
    let allOwnerIDs = seenOwners
    var seenGroups = Set<RawUTF8Key>()
    for group in request.groups {
      guard seenGroups.insert(RawUTF8Key(group.allocationGroupID)).inserted else {
        throw ReleasePostverificationFreezeError.duplicateAllocationGroup(
          group.allocationGroupID)
      }
      guard
        RawUTF8Key(group.topology.allocationGroupID)
          == RawUTF8Key(group.allocationGroupID),
        !group.ownerActionIDs.isEmpty,
        Set(group.ownerActionIDs).count == group.ownerActionIDs.count,
        Set(group.ownerActionIDs).isSubset(of: allOwnerIDs)
      else {
        throw ReleasePostverificationFreezeError.invalidOwnerMembership(
          group.allocationGroupID)
      }
    }

    var frozen: [FrozenReleasePostverificationOwner] = []
    do {
      for owner in request.owners.sorted(by: { $0.actionID < $1.actionID }) {
        let root = try duplicate(
          owner.rootDescriptor,
          ownerID: owner.actionID,
          location: .root
        )
        var parent: Int32?
        do {
          parent = try duplicate(
            owner.parentDescriptor,
            ownerID: owner.actionID,
            location: .parent
          )
          let rootSeal = try requireSeal(
            descriptorProbe.namespaceSeal(descriptor: root),
            ownerID: owner.actionID,
            location: .root
          )
          let parentSeal = try requireSeal(
            descriptorProbe.namespaceSeal(descriptor: parent!),
            ownerID: owner.actionID,
            location: .parent
          )
          frozen.append(
            FrozenReleasePostverificationOwner(
              actionID: owner.actionID,
              candidateID: owner.candidateID,
              expectedIdentity: owner.expectedIdentity,
              rootDescriptor: root,
              parentDescriptor: parent!,
              rawLeafName: owner.rawLeafName,
              rootSeal: rootSeal,
              parentSeal: parentSeal
            ))
          parent = nil
        } catch {
          _ = Darwin.close(root)
          if let parent { _ = Darwin.close(parent) }
          throw error
        }
      }
    } catch {
      for owner in frozen {
        _ = Darwin.close(owner.rootDescriptor)
        _ = Darwin.close(owner.parentDescriptor)
      }
      throw error
    }
    return FrozenReleasePostverificationComponent(
      owners: frozen,
      groups: request.groups.sorted {
        RawUTF8Key($0.allocationGroupID) < RawUTF8Key($1.allocationGroupID)
      }
    )
  }

  func postverify(
    _ component: FrozenReleasePostverificationComponent
  ) async -> DescriptorBoundReleasePostverificationReport {
    guard component.claim() else {
      return DescriptorBoundReleasePostverificationReport(
        ownerTransitions: [:],
        groups: component.groups.map {
          DescriptorBoundAllocationGroupPostverification(
            allocationGroupID: $0.allocationGroupID,
            outcome: .rejected(.leaseAlreadyConsumed)
          )
        }
      )
    }

    var transitions: [ActionID: ReleaseOwnerSlotTransition] = [:]
    var failures: [ActionID: ReleasePostverificationFailure] = [:]
    for owner in component.owners {
      if let failure = verifyNamespace(owner, location: .root) {
        failures[owner.actionID] = failure
        continue
      }
      if let failure = verifyNamespace(owner, location: .parent) {
        failures[owner.actionID] = failure
        continue
      }
      switch descriptorProbe.ownerSlot(
        parentDescriptor: owner.parentDescriptor,
        rawLeafName: owner.rawLeafName
      ) {
      case .missing:
        transitions[owner.actionID] = .missing
      case .present(let identity):
        if identity == owner.expectedIdentity {
          failures[owner.actionID] = .ownerSlotStillReferencesExpectedObject(owner.actionID)
        } else {
          transitions[owner.actionID] = .identityChanged(current: identity)
        }
      case .unknown(let reason):
        failures[owner.actionID] = .ownerSlotUnknown(owner.actionID, reason)
      case .unreadable(let failure):
        failures[owner.actionID] = .ownerSlotUnreadable(owner.actionID, failure)
      case .failed(let failure):
        failures[owner.actionID] = .ownerSlotCollectionFailed(owner.actionID, failure)
      }
    }

    let ownerByID = Dictionary(uniqueKeysWithValues: component.owners.map { ($0.actionID, $0) })
    var groupResults: [DescriptorBoundAllocationGroupPostverification] = []
    for group in component.groups {
      if let failure = group.ownerActionIDs.sorted().compactMap({ failures[$0] }).first {
        groupResults.append(
          DescriptorBoundAllocationGroupPostverification(
            allocationGroupID: group.allocationGroupID,
            outcome: .rejected(failure)
          ))
        continue
      }
      let topologyOwners = group.ownerActionIDs.sorted().compactMap {
        actionID
          -> ReleasePostverificationTopologyOwner? in
        guard let owner = ownerByID[actionID], let transition = transitions[actionID] else {
          return nil
        }
        return ReleasePostverificationTopologyOwner(
          actionID: owner.actionID,
          candidateID: owner.candidateID,
          expectedIdentity: owner.expectedIdentity,
          rootDescriptor: owner.rootDescriptor,
          parentDescriptor: owner.parentDescriptor,
          rawLeafName: owner.rawLeafName,
          transition: transition
        )
      }
      guard topologyOwners.count == group.ownerActionIDs.count else {
        groupResults.append(
          DescriptorBoundAllocationGroupPostverification(
            allocationGroupID: group.allocationGroupID,
            outcome: .rejected(.invalidAllocationGroupReleaseProof(group.allocationGroupID))
          ))
        continue
      }
      let outcome = await collectTopology(
        group: group,
        owners: topologyOwners
      )
      groupResults.append(
        DescriptorBoundAllocationGroupPostverification(
          allocationGroupID: group.allocationGroupID,
          outcome: outcome
        ))
    }
    return DescriptorBoundReleasePostverificationReport(
      ownerTransitions: transitions,
      groups: groupResults
    )
  }

  private func collectTopology(
    group: ReleasePostverificationGroupExpectation,
    owners: [ReleasePostverificationTopologyOwner]
  ) async -> DescriptorBoundAllocationGroupOutcome {
    let observation: Observation<CurrentAllocationGroupReleaseTopology>
    do {
      observation = try await topologySource.collectReleaseTopology(
        for: ReleasePostverificationTopologyRequest(
          allocationGroupID: group.allocationGroupID,
          expectedTopology: group.topology,
          owners: owners
        ))
    } catch {
      return .rejected(
        .topologyCollectorFailed(
          group.allocationGroupID,
          ObservationFailure(
            code: error is CancellationError
              ? "cancelled" : String(reflecting: type(of: error)),
            collector: "release-topology-source"
          )
        ))
    }
    switch observation {
    case .absent:
      return .rejected(.topologyMissing(group.allocationGroupID))
    case .unknown(let reason):
      return .rejected(.topologyUnknown(group.allocationGroupID, reason))
    case .unreadable(let failure):
      return .rejected(.topologyUnreadable(group.allocationGroupID, failure))
    case .failed(let failure):
      return .rejected(.topologyCollectorFailed(group.allocationGroupID, failure))
    case .known(.allocationGroupStillAllocated):
      return .rejected(.allocationGroupStillAllocated(group.allocationGroupID))
    case .known(.allocationGroupReleased(let proof)):
      let expectedOwnerIDs = group.ownerActionIDs.sorted()
      guard RawUTF8Key(proof.allocationGroupID) == RawUTF8Key(group.allocationGroupID),
        proof.expectedTopology == group.topology,
        proof.ownerActionIDs == expectedOwnerIDs
      else {
        return .rejected(.invalidAllocationGroupReleaseProof(group.allocationGroupID))
      }
      return .allocationGroupReleased(proof)
    }
  }

  private func verifyNamespace(
    _ owner: FrozenReleasePostverificationOwner,
    location: ReleasePostverificationNamespaceLocation
  ) -> ReleasePostverificationFailure? {
    let descriptor = location == .root ? owner.rootDescriptor : owner.parentDescriptor
    let expected = location == .root ? owner.rootSeal : owner.parentSeal
    switch descriptorProbe.namespaceSeal(descriptor: descriptor) {
    case .absent:
      return .namespaceMissing(owner.actionID, location)
    case .unknown(let reason):
      return .namespaceUnknown(owner.actionID, location, reason)
    case .unreadable(let failure):
      return .namespaceUnreadable(owner.actionID, location, failure)
    case .failed(let failure):
      return .namespaceCollectionFailed(owner.actionID, location, failure)
    case .known(let current):
      guard current.identity == expected.identity else {
        return .namespaceIdentityMismatch(owner.actionID, location)
      }
      guard current.access == expected.access else {
        return .namespaceAccessMismatch(owner.actionID, location)
      }
      return nil
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

  private func requireSeal(
    _ observation: Observation<ReleaseDescriptorNamespaceSeal>,
    ownerID: ActionID,
    location: ReleasePostverificationNamespaceLocation
  ) throws -> ReleaseDescriptorNamespaceSeal {
    switch observation {
    case .known(let seal): return seal
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

  private static func isValidLeaf(_ leaf: Data) -> Bool {
    !leaf.isEmpty && leaf != Data(".".utf8) && leaf != Data("..".utf8)
      && !leaf.contains(0) && !leaf.contains(47)
  }
}
