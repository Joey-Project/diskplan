import CryptoKit
import Darwin
import DiskplanMacOS
import DiskplanPolicy
import Foundation

public enum RuntimeReleaseTopologyUnknownReason: String, CaseIterable, Equatable, Sendable {
  case incompleteCoverage = "incomplete_coverage"
  case notObserved = "not_observed"
  case providerBoundary = "provider_boundary"
  case unavailableViaPublicAPI = "unavailable_via_public_api"
  case unsupported
}

public struct RuntimeReleaseTopologyFailure: Equatable, Sendable {
  public enum Kind: String, Equatable, Sendable {
    case inconsistentEvidence = "inconsistent_evidence"
    case invalidDescriptor = "invalid_descriptor"
    case probeFailed = "probe_failed"
  }

  public let kind: Kind
  public let collector: String
  public let errorCode: Int32?

  public init(kind: Kind, collector: String, errorCode: Int32? = nil) {
    self.kind = kind
    self.collector = collector
    self.errorCode = errorCode
  }
}

public enum RuntimeReleaseTopologyObservation<Value: Equatable & Sendable>: Equatable, Sendable {
  case absent
  case known(Value)
  case unknown(RuntimeReleaseTopologyUnknownReason)
  case unreadable(RuntimeReleaseTopologyFailure)
  case failed(RuntimeReleaseTopologyFailure)

  public var knownValue: Value? {
    guard case .known(let value) = self else { return nil }
    return value
  }

  public func map<Mapped: Equatable & Sendable>(
    _ transform: (Value) -> Mapped
  ) -> RuntimeReleaseTopologyObservation<Mapped> {
    switch self {
    case .absent: .absent
    case .known(let value): .known(transform(value))
    case .unknown(let reason): .unknown(reason)
    case .unreadable(let failure): .unreadable(failure)
    case .failed(let failure): .failed(failure)
    }
  }
}

public enum RuntimeReleaseObjectType: String, Equatable, Hashable, Sendable {
  case regularFile = "regular_file"
  case directory
  case symbolicLink = "symbolic_link"
  case other
}

public struct RuntimeReleaseFileObjectIdentity: Equatable, Hashable, Comparable, Sendable {
  public let device: UInt64
  public let fileID: UInt64
  public let objectType: RuntimeReleaseObjectType

  package init(device: UInt64, fileID: UInt64, objectType: RuntimeReleaseObjectType) {
    self.device = device
    self.fileID = fileID
    self.objectType = objectType
  }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    if lhs.device != rhs.device { return lhs.device < rhs.device }
    if lhs.fileID != rhs.fileID { return lhs.fileID < rhs.fileID }
    return lhs.objectType.rawValue < rhs.objectType.rawValue
  }
}

public struct RuntimeReleaseCloneIdentity: Equatable, Hashable, Comparable, Sendable {
  public let device: UInt64
  public let cloneID: UInt64

  package init(device: UInt64, cloneID: UInt64) {
    self.device = device
    self.cloneID = cloneID
  }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    lhs.device == rhs.device ? lhs.cloneID < rhs.cloneID : lhs.device < rhs.device
  }
}

public enum RuntimeReleaseCloneAssociation: Equatable, Sendable {
  case notCloned
  case clone(RuntimeReleaseCloneIdentity)
}

public struct RuntimeReleaseNamespaceSlotIdentity: Equatable, Hashable, Comparable, Sendable {
  public let rootIdentity: RuntimeReleaseFileObjectIdentity
  public let parentIdentity: RuntimeReleaseFileObjectIdentity
  public let rawBasename: Data
  public let objectIdentity: RuntimeReleaseFileObjectIdentity

  package init(
    rootIdentity: RuntimeReleaseFileObjectIdentity,
    parentIdentity: RuntimeReleaseFileObjectIdentity,
    rawBasename: Data,
    objectIdentity: RuntimeReleaseFileObjectIdentity
  ) throws {
    guard rootIdentity.objectType == .directory, parentIdentity.objectType == .directory,
      objectIdentity.objectType == .regularFile, !rawBasename.isEmpty,
      rawBasename != Data(".".utf8), rawBasename != Data("..".utf8),
      !rawBasename.contains(0), !rawBasename.contains(47)
    else { throw RuntimeReleaseTopologyPlanError.invalidNamespaceSlot }
    self.rootIdentity = rootIdentity
    self.parentIdentity = parentIdentity
    self.rawBasename = rawBasename
    self.objectIdentity = objectIdentity
  }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    if lhs.parentIdentity != rhs.parentIdentity { return lhs.parentIdentity < rhs.parentIdentity }
    if lhs.rawBasename != rhs.rawBasename {
      return lhs.rawBasename.lexicographicallyPrecedes(rhs.rawBasename)
    }
    if lhs.objectIdentity != rhs.objectIdentity { return lhs.objectIdentity < rhs.objectIdentity }
    return lhs.rootIdentity < rhs.rootIdentity
  }

  fileprivate var aliasKey: RuntimeReleaseNamespaceAliasKey {
    RuntimeReleaseNamespaceAliasKey(
      parentIdentity: parentIdentity,
      rawBasename: rawBasename
    )
  }
}

private struct RuntimeReleaseNamespaceAliasKey: Equatable, Hashable, Sendable {
  let parentIdentity: RuntimeReleaseFileObjectIdentity
  let rawBasename: Data
}

public struct RuntimeReleaseCandidateActionBinding: Equatable, Sendable {
  public let candidateID: String
  public let actionID: ActionID

  package init(candidateID: String, actionID: ActionID) {
    self.candidateID = candidateID
    self.actionID = actionID
  }
}

public struct RuntimeReleaseExpectedOwner: Equatable, Sendable {
  public let link: FileOwnerLink
  public let slot: RuntimeReleaseNamespaceSlotIdentity
  public let actionID: ActionID

  package init(link: FileOwnerLink, slot: RuntimeReleaseNamespaceSlotIdentity, actionID: ActionID) {
    self.link = link
    self.slot = slot
    self.actionID = actionID
  }
}

public struct RuntimeReleaseExpectedFileObject: Equatable, Sendable {
  public let identity: RuntimeReleaseFileObjectIdentity
  public let owners: [RuntimeReleaseExpectedOwner]
  public let linkCount: UInt32
  public let cloneIdentity: RuntimeReleaseCloneIdentity?

  package init(
    identity: RuntimeReleaseFileObjectIdentity,
    owners: [RuntimeReleaseExpectedOwner],
    linkCount: UInt32,
    cloneIdentity: RuntimeReleaseCloneIdentity?
  ) {
    self.identity = identity
    self.owners = owners.sorted(by: expectedOwnerPrecedes)
    self.linkCount = linkCount
    self.cloneIdentity = cloneIdentity
  }
}

public struct RuntimeReleaseExpectedGroup: Equatable, Sendable {
  public let allocationGroupID: String
  public let ownerFileObjects: [RuntimeReleaseFileObjectIdentity]
  public let cloneIdentity: RuntimeReleaseCloneIdentity?
  public let cloneRefCount: UInt32?
  public let snapshotDevice: UInt64

  package init(
    allocationGroupID: String,
    ownerFileObjects: [RuntimeReleaseFileObjectIdentity],
    cloneIdentity: RuntimeReleaseCloneIdentity?,
    cloneRefCount: UInt32?,
    snapshotDevice: UInt64
  ) {
    self.allocationGroupID = allocationGroupID
    self.ownerFileObjects = ownerFileObjects.sorted()
    self.cloneIdentity = cloneIdentity
    self.cloneRefCount = cloneRefCount
    self.snapshotDevice = snapshotDevice
  }
}

public enum RuntimeReleaseTopologyPlanError: Error, Equatable {
  case emptyExpectedSet
  case duplicateIdentifier
  case invalidNamespaceSlot
  case aliasedOwnerSlot
  case ownerBindingMismatch
  case impossibleOwnerCount
  case invalidCloneBinding
  case incompleteGroupCoverage
  case actionSetMismatch
  case volumeSetMismatch
}

public struct RuntimeReleaseTopologyExpectedPlan: Equatable, Sendable {
  public let planHash: PolicyDigest
  public let topologyBindingHash: PolicyDigest
  public let candidateActions: [RuntimeReleaseCandidateActionBinding]
  public let fileObjects: [RuntimeReleaseExpectedFileObject]
  public let groups: [RuntimeReleaseExpectedGroup]
  public let volumeDevices: [UInt64]

  package init(
    planHash: PolicyDigest,
    candidateActions: [RuntimeReleaseCandidateActionBinding],
    fileObjects: [RuntimeReleaseExpectedFileObject],
    groups: [RuntimeReleaseExpectedGroup],
    volumeDevices: [UInt64]
  ) throws {
    guard !candidateActions.isEmpty, !fileObjects.isEmpty, !groups.isEmpty,
      !volumeDevices.isEmpty
    else { throw RuntimeReleaseTopologyPlanError.emptyExpectedSet }
    guard Set(candidateActions.map { Data($0.candidateID.utf8) }).count == candidateActions.count,
      Set(fileObjects.map(\.identity)).count == fileObjects.count,
      Set(groups.map { Data($0.allocationGroupID.utf8) }).count == groups.count,
      Set(volumeDevices).count == volumeDevices.count
    else { throw RuntimeReleaseTopologyPlanError.duplicateIdentifier }
    let actionByCandidate = Dictionary(
      uniqueKeysWithValues: candidateActions.map { (Data($0.candidateID.utf8), $0.actionID) })

    var ownerLinks = Set<FileOwnerLink>()
    var aliasKeys = Set<RuntimeReleaseNamespaceAliasKey>()
    var ownerCandidateIDs = Set<Data>()
    var ownerActionIDs = Set<ActionID>()
    for file in fileObjects {
      guard file.identity.objectType == .regularFile, !file.owners.isEmpty,
        file.linkCount > 0, Int(file.linkCount) == file.owners.count
      else { throw RuntimeReleaseTopologyPlanError.impossibleOwnerCount }
      if let clone = file.cloneIdentity, clone.device != file.identity.device {
        throw RuntimeReleaseTopologyPlanError.invalidCloneBinding
      }
      for owner in file.owners {
        guard owner.slot.objectIdentity == file.identity,
          actionByCandidate[Data(owner.link.candidateID.utf8)] == owner.actionID
        else { throw RuntimeReleaseTopologyPlanError.ownerBindingMismatch }
        guard ownerLinks.insert(owner.link).inserted else {
          throw RuntimeReleaseTopologyPlanError.duplicateIdentifier
        }
        guard aliasKeys.insert(owner.slot.aliasKey).inserted else {
          throw RuntimeReleaseTopologyPlanError.aliasedOwnerSlot
        }
        ownerCandidateIDs.insert(Data(owner.link.candidateID.utf8))
        ownerActionIDs.insert(owner.actionID)
      }
    }
    guard ownerCandidateIDs == Set(candidateActions.map { Data($0.candidateID.utf8) }),
      ownerActionIDs == Set(candidateActions.map(\.actionID))
    else {
      throw RuntimeReleaseTopologyPlanError.actionSetMismatch
    }

    let fileByIdentity = Dictionary(uniqueKeysWithValues: fileObjects.map { ($0.identity, $0) })
    let expectedFilesByClone = Dictionary(
      grouping: fileObjects.compactMap { file in
        file.cloneIdentity.map { ($0, file.identity) }
      },
      by: { $0.0 }
    ).mapValues { Set($0.map(\.1)) }
    var referencedFiles = Set<RuntimeReleaseFileObjectIdentity>()
    var observedCloneGroups = Set<RuntimeReleaseCloneIdentity>()
    for group in groups {
      let groupFiles = Set(group.ownerFileObjects)
      guard !groupFiles.isEmpty, groupFiles.count == group.ownerFileObjects.count,
        groupFiles.allSatisfy({ fileByIdentity[$0] != nil })
      else { throw RuntimeReleaseTopologyPlanError.incompleteGroupCoverage }
      referencedFiles.formUnion(groupFiles)
      if let clone = group.cloneIdentity {
        guard clone.device == group.snapshotDevice, let refCount = group.cloneRefCount,
          refCount > 0, Int(refCount) == groupFiles.count,
          groupFiles.allSatisfy({ fileByIdentity[$0]?.cloneIdentity == clone }),
          groupFiles == expectedFilesByClone[clone],
          observedCloneGroups.insert(clone).inserted
        else { throw RuntimeReleaseTopologyPlanError.invalidCloneBinding }
      } else {
        guard group.cloneRefCount == nil else {
          throw RuntimeReleaseTopologyPlanError.invalidCloneBinding
        }
      }
    }
    guard referencedFiles == Set(fileObjects.map(\.identity)) else {
      throw RuntimeReleaseTopologyPlanError.incompleteGroupCoverage
    }
    guard observedCloneGroups == Set(expectedFilesByClone.keys) else {
      throw RuntimeReleaseTopologyPlanError.invalidCloneBinding
    }
    guard Set(volumeDevices) == Set(groups.map(\.snapshotDevice)) else {
      throw RuntimeReleaseTopologyPlanError.volumeSetMismatch
    }

    let canonicalActions = candidateActions.sorted(by: candidateActionPrecedes)
    let canonicalFiles = fileObjects.sorted { $0.identity < $1.identity }
    let canonicalGroups = groups.sorted {
      rawStringPrecedes($0.allocationGroupID, $1.allocationGroupID)
    }
    let canonicalVolumes = volumeDevices.sorted()
    self.planHash = planHash
    self.topologyBindingHash = releaseTopologyBindingHash(
      planHash: planHash,
      candidateActions: canonicalActions,
      fileObjects: canonicalFiles,
      groups: canonicalGroups,
      volumeDevices: canonicalVolumes
    )
    self.candidateActions = canonicalActions
    self.fileObjects = canonicalFiles
    self.groups = canonicalGroups
    self.volumeDevices = canonicalVolumes
  }
}

private struct RuntimeReleaseFreshCaptureBinding: Sendable {
  let planHash: PolicyDigest
  let topologyBindingHash: PolicyDigest
  let captureID: PolicyDigest
  let executionEpochNonce: UUID
  let issuedAtMonotonicNanoseconds: UInt64
  let deadlineMonotonicNanoseconds: UInt64
  let coveredOwnerSlots: Set<RuntimeReleaseNamespaceSlotIdentity>
  let coveredVolumes: Set<UInt64>
}

package struct BoundRuntimeReleaseOwnerDescriptor: Sendable {
  package let slot: RuntimeReleaseNamespaceSlotIdentity
  package let rootFileDescriptor: Int32
  package let parentFileDescriptor: Int32
  package let fileDescriptor: Int32

  package init(
    slot: RuntimeReleaseNamespaceSlotIdentity,
    rootFileDescriptor: Int32,
    parentFileDescriptor: Int32,
    fileDescriptor: Int32
  ) {
    self.slot = slot
    self.rootFileDescriptor = rootFileDescriptor
    self.parentFileDescriptor = parentFileDescriptor
    self.fileDescriptor = fileDescriptor
  }
}

package struct BoundRuntimeReleaseVolumeDescriptor: Sendable {
  package let expectedDevice: UInt64
  package let rootFileDescriptor: Int32

  package init(expectedDevice: UInt64, rootFileDescriptor: Int32) {
    self.expectedDevice = expectedDevice
    self.rootFileDescriptor = rootFileDescriptor
  }
}

public struct RuntimeReleaseTopologyLimits: Equatable, Sendable {
  public let maximumOwners: Int
  public let maximumVolumes: Int
  public let maximumCaptureAgeNanoseconds: UInt64

  public init(
    maximumOwners: Int = 5_000_000,
    maximumVolumes: Int = 4_096,
    maximumCaptureAgeNanoseconds: UInt64 = 300_000_000_000
  ) {
    precondition(maximumOwners >= 0)
    precondition(maximumVolumes >= 0)
    self.maximumOwners = maximumOwners
    self.maximumVolumes = maximumVolumes
    self.maximumCaptureAgeNanoseconds = maximumCaptureAgeNanoseconds
  }
}

public enum RuntimeReleaseTopologyAuthorityError: Error, Equatable {
  case captureReceiptReplayed
  case captureReceiptStale
  case captureReceiptMismatch
  case descriptorLeaseReplayed
  case descriptorSetMismatch
  case descriptorUnavailable(Int32)
  case descriptorNotReadOnly(Int32)
  case descriptorMissingCloseOnExec(Int32)
  case descriptorIdentityMismatch(RuntimeReleaseFileObjectIdentity)
  case descriptorIdentityUnknown(RuntimeReleaseTopologyUnknownReason)
  case descriptorIdentityUnreadable(RuntimeReleaseTopologyFailure)
  case descriptorIdentityProbeFailed(RuntimeReleaseTopologyFailure)
  case collectionLimitExceeded
}

public struct RuntimeReleaseFileObjectTopology: Equatable, Sendable {
  public let identity: RuntimeReleaseFileObjectIdentity
  public let owners: [FileOwnerLink]
  public let actionIDs: [ActionID]
  public let namespaceSlotsMatch: RuntimeReleaseTopologyObservation<Bool>
  public let providerLocal: RuntimeReleaseTopologyObservation<Bool>
  public let linkCount: RuntimeReleaseTopologyObservation<UInt32>
  public let ownerClosure: RuntimeReleaseTopologyObservation<Bool>
  public let cloneAssociation: RuntimeReleaseTopologyObservation<RuntimeReleaseCloneAssociation>
  public let cloneRefCount: RuntimeReleaseTopologyObservation<UInt32>
  public let sharesAllBlocks: RuntimeReleaseTopologyObservation<Bool>
  public let topologyMatchesExpected: RuntimeReleaseTopologyObservation<Bool>
}

public struct RuntimeReleaseGroupTopology: Equatable, Sendable {
  public let allocationGroupID: String
  public let ownerFileObjects: [RuntimeReleaseFileObjectIdentity]
  public let actionIDsAtMostOnce: [ActionID]
  public let ownerClosure: RuntimeReleaseTopologyObservation<Bool>
  public let cloneRefCount: RuntimeReleaseTopologyObservation<UInt32>
  public let sharesAllBlocks: RuntimeReleaseTopologyObservation<Bool>
  public let snapshotBlocker: RuntimeReleaseTopologyObservation<Bool>
  public let topologyMatchesExpected: RuntimeReleaseTopologyObservation<Bool>
  public let conditionalSharedReclaimCredit: UInt64?
}

public struct RuntimeReleaseTopologyComponent: Equatable, Sendable {
  public let allocationGroupIDs: [String]
  public let ownerFileObjects: [RuntimeReleaseFileObjectIdentity]
  public let actionIDsAtMostOnce: [ActionID]
  public let observedOwnerLinks: [FileOwnerLink]
  public let topologyMatchesExpected: RuntimeReleaseTopologyObservation<Bool>
}

public enum RuntimeReleaseTopologyIssue: Equatable, Sendable {
  case namespaceSlotMismatch(RuntimeReleaseNamespaceSlotIdentity)
  case hardlinkOwnerCountMismatch(
    RuntimeReleaseFileObjectIdentity, observed: UInt32, linkCount: UInt32)
  case cloneOwnerCountMismatch(
    RuntimeReleaseCloneIdentity, observed: UInt32, refCount: UInt32)
  case cloneAssociationChanged(RuntimeReleaseFileObjectIdentity)
  case snapshotBlocked(UInt64)
  case sharedCloneBytesUnavailable(RuntimeReleaseCloneIdentity)
  case topologyEvidenceIncomplete
}

public struct RuntimeReleaseTopologySeal: Equatable, Sendable {
  public let planHash: PolicyDigest
  public let topologyBindingHash: PolicyDigest
  public let captureID: PolicyDigest
  public let executionEpochNonce: UUID
  public let fileObjects: [RuntimeReleaseFileObjectTopology]
  public let groups: [RuntimeReleaseGroupTopology]
  public let components: [RuntimeReleaseTopologyComponent]
  public let snapshotBlockersByDevice: [UInt64: RuntimeReleaseTopologyObservation<Bool>]
}

public struct RuntimeReleaseTopologyReport: Equatable, Sendable {
  public let collection: RuntimeReleaseTopologyObservation<Bool>
  public let topologyMatchesExpected: RuntimeReleaseTopologyObservation<Bool>
  public let seal: RuntimeReleaseTopologySeal
  public let issues: [RuntimeReleaseTopologyIssue]
}

private final class OwnedReleaseDescriptor: @unchecked Sendable {
  let rawValue: Int32
  init(_ rawValue: Int32) { self.rawValue = rawValue }
  deinit { close(rawValue) }
}

private struct LeasedOwnerDescriptor: Sendable {
  let expected: RuntimeReleaseExpectedOwner
  let root: OwnedReleaseDescriptor
  let parent: OwnedReleaseDescriptor
  let file: OwnedReleaseDescriptor
}

private struct LeasedVolumeDescriptor: Sendable {
  let device: UInt64
  let root: OwnedReleaseDescriptor
}

package final class RuntimeReleaseTopologyDescriptorLease: @unchecked Sendable {
  fileprivate let lock = NSLock()
  fileprivate let authorityID: UUID
  fileprivate let plan: RuntimeReleaseTopologyExpectedPlan
  fileprivate let capture: RuntimeReleaseFreshCaptureBinding
  fileprivate let policy: NoMaterializationPolicy
  fileprivate let owners: [LeasedOwnerDescriptor]
  fileprivate let volumes: [LeasedVolumeDescriptor]
  fileprivate var consumed = false

  fileprivate init(
    authorityID: UUID,
    plan: RuntimeReleaseTopologyExpectedPlan,
    capture: RuntimeReleaseFreshCaptureBinding,
    policy: NoMaterializationPolicy,
    owners: [LeasedOwnerDescriptor],
    volumes: [LeasedVolumeDescriptor]
  ) {
    self.authorityID = authorityID
    self.plan = plan
    self.capture = capture
    self.policy = policy
    self.owners = owners
    self.volumes = volumes
  }

  fileprivate func consume(authorityID: UUID, now: UInt64) throws {
    lock.lock()
    defer { lock.unlock() }
    guard self.authorityID == authorityID else {
      throw RuntimeReleaseTopologyAuthorityError.captureReceiptMismatch
    }
    guard !consumed else { throw RuntimeReleaseTopologyAuthorityError.descriptorLeaseReplayed }
    consumed = true
    guard now <= capture.deadlineMonotonicNanoseconds else {
      throw RuntimeReleaseTopologyAuthorityError.captureReceiptStale
    }
  }
}

struct RuntimeReleaseKernelItem: Equatable, Sendable {
  let identity: RuntimeReleaseTopologyObservation<RuntimeReleaseFileObjectIdentity>
  let linkCount: RuntimeReleaseTopologyObservation<UInt32>
  let mayShareBlocks: RuntimeReleaseTopologyObservation<Bool>
  let sharesAllBlocks: RuntimeReleaseTopologyObservation<Bool>
  let cloneID: RuntimeReleaseTopologyObservation<UInt64>
  let cloneRefCount: RuntimeReleaseTopologyObservation<UInt32>
  let providerLocal: RuntimeReleaseTopologyObservation<Bool>
}

struct RuntimeReleaseTopologyKernel: Sendable {
  let descriptorIdentity:
    @Sendable (Int32, NoMaterializationPolicy) -> RuntimeReleaseTopologyObservation<
      RuntimeReleaseFileObjectIdentity
    >
  let item: @Sendable (Int32, Data, NoMaterializationPolicy) -> RuntimeReleaseKernelItem
  let snapshotBlocker:
    @Sendable (Int32, NoMaterializationPolicy) -> RuntimeReleaseTopologyObservation<Bool>

  static let live = RuntimeReleaseTopologyKernel(
    descriptorIdentity: { descriptor, policy in
      capabilityObservation(
        FileDescriptorIdentityProbe().probe(fileDescriptor: descriptor, policy: policy)
      ).map(runtimeIdentity)
    },
    item: { parent, name, policy in
      let beforeCapability = ItemProbe().probe(
        parentFileDescriptor: parent, rawName: name, policy: policy)
      guard let before = beforeCapability.value else {
        let failure: RuntimeReleaseTopologyObservation<RuntimeReleaseFileObjectIdentity> =
          capabilityObservation(beforeCapability).erased()
        return RuntimeReleaseKernelItem(
          identity: failure,
          linkCount: failure.erased(),
          mayShareBlocks: failure.erased(),
          sharesAllBlocks: failure.erased(),
          cloneID: failure.erased(),
          cloneRefCount: failure.erased(),
          providerLocal: failure.erased()
        )
      }
      let provider = FileProviderBoundaryProbe().probe(
        parentFileDescriptor: parent,
        rawName: name,
        policy: policy)
      let afterCapability = ItemProbe().probe(
        parentFileDescriptor: parent, rawName: name, policy: policy)
      guard let after = afterCapability.value else {
        let failure: RuntimeReleaseTopologyObservation<RuntimeReleaseFileObjectIdentity> =
          capabilityObservation(afterCapability).erased()
        return RuntimeReleaseKernelItem(
          identity: failure,
          linkCount: failure.erased(),
          mayShareBlocks: failure.erased(),
          sharesAllBlocks: failure.erased(),
          cloneID: failure.erased(),
          cloneRefCount: failure.erased(),
          providerLocal: failure.erased()
        )
      }
      let dataless = consensus(
        [
          capabilityObservation(before.isDataless),
          capabilityObservation(after.isDataless),
        ], collector: "release-provider-dataless-stability")
      let syncRoot = consensus(
        [
          capabilityObservation(before.isSyncRoot),
          capabilityObservation(after.isSyncRoot),
        ], collector: "release-provider-sync-root-stability")
      return RuntimeReleaseKernelItem(
        identity: consensus(
          [combineIdentity(before), combineIdentity(after)],
          collector: "release-item-identity-stability"),
        linkCount: consensus(
          [capabilityObservation(before.linkCount), capabilityObservation(after.linkCount)],
          collector: "release-link-count-stability"),
        mayShareBlocks: consensus(
          [
            capabilityObservation(before.sharing.mayShareBlocks),
            capabilityObservation(after.sharing.mayShareBlocks),
          ], collector: "release-may-share-stability"),
        sharesAllBlocks: consensus(
          [
            capabilityObservation(before.sharing.sharesAllBlocks),
            capabilityObservation(after.sharing.sharesAllBlocks),
          ], collector: "release-shares-all-stability"),
        cloneID: consensus(
          [
            capabilityObservation(before.sharing.cloneID),
            capabilityObservation(after.sharing.cloneID),
          ], collector: "release-clone-id-stability"),
        cloneRefCount: consensus(
          [
            capabilityObservation(before.sharing.cloneRefcount),
            capabilityObservation(after.sharing.cloneRefcount),
          ], collector: "release-clone-refcount-stability"),
        providerLocal: providerLocalObservation(
          provider,
          dataless: dataless,
          syncRoot: syncRoot)
      )
    },
    snapshotBlocker: { descriptor, policy in
      guard policy.revalidateLive().value != nil else {
        return .failed(
          RuntimeReleaseTopologyFailure(
            kind: .probeFailed, collector: "snapshot-materialization-policy"))
      }
      let isolated = openat(
        descriptor, ".", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      guard isolated >= 0 else {
        return posixObservation(errno, collector: "snapshot-volume-open")
      }
      defer { close(isolated) }
      var buffer = Data(count: 64 * 1_024)
      return capabilityObservation(
        SnapshotListProbe().list(fileDescriptor: isolated, buffer: &buffer)
      ).map { $0 > 0 }
    }
  )
}

public final class RuntimeReleaseTopologyAuthority: @unchecked Sendable {
  public let limits: RuntimeReleaseTopologyLimits
  private let authorityID = UUID()
  private let captureLock = NSLock()
  private var issuedExecutionEpochNonces = Set<UUID>()
  private let monotonicNow: @Sendable () -> UInt64
  private let kernel: RuntimeReleaseTopologyKernel

  public convenience init(limits: RuntimeReleaseTopologyLimits = RuntimeReleaseTopologyLimits()) {
    self.init(
      limits: limits,
      monotonicNow: { DispatchTime.now().uptimeNanoseconds },
      kernel: .live
    )
  }

  init(
    limits: RuntimeReleaseTopologyLimits,
    monotonicNow: @escaping @Sendable () -> UInt64,
    kernel: RuntimeReleaseTopologyKernel
  ) {
    self.limits = limits
    self.monotonicNow = monotonicNow
    self.kernel = kernel
  }

  package func bind(
    plan: RuntimeReleaseTopologyExpectedPlan,
    executionEpochNonce: UUID,
    validForNanoseconds: UInt64,
    policy: NoMaterializationPolicy,
    owners: [BoundRuntimeReleaseOwnerDescriptor],
    volumes: [BoundRuntimeReleaseVolumeDescriptor]
  ) throws -> RuntimeReleaseTopologyDescriptorLease {
    guard owners.count <= limits.maximumOwners, volumes.count <= limits.maximumVolumes else {
      throw RuntimeReleaseTopologyAuthorityError.collectionLimitExceeded
    }
    let expectedOwners = plan.fileObjects.flatMap(\.owners)
    let expectedSlots = Set(expectedOwners.map(\.slot))
    let suppliedSlots = Set(owners.map(\.slot))
    guard !owners.isEmpty, owners.count == suppliedSlots.count, suppliedSlots == expectedSlots,
      !volumes.isEmpty, volumes.count == Set(volumes.map(\.expectedDevice)).count,
      Set(volumes.map(\.expectedDevice)) == Set(plan.volumeDevices)
    else { throw RuntimeReleaseTopologyAuthorityError.descriptorSetMismatch }

    let expectedBySlot = Dictionary(uniqueKeysWithValues: expectedOwners.map { ($0.slot, $0) })
    var leasedOwners: [LeasedOwnerDescriptor] = []
    for owner in owners.sorted(by: { $0.slot < $1.slot }) {
      guard let expected = expectedBySlot[owner.slot] else {
        throw RuntimeReleaseTopologyAuthorityError.descriptorSetMismatch
      }
      let root = try duplicateReadOnlyDescriptor(owner.rootFileDescriptor)
      let parent = try duplicateReadOnlyDescriptor(owner.parentFileDescriptor)
      let file = try duplicateReadOnlyDescriptor(owner.fileDescriptor)
      try requireIdentity(root.rawValue, expected: owner.slot.rootIdentity, policy: policy)
      try requireIdentity(parent.rawValue, expected: owner.slot.parentIdentity, policy: policy)
      try requireIdentity(file.rawValue, expected: owner.slot.objectIdentity, policy: policy)
      leasedOwners.append(
        LeasedOwnerDescriptor(expected: expected, root: root, parent: parent, file: file))
    }
    var leasedVolumes: [LeasedVolumeDescriptor] = []
    for volume in volumes.sorted(by: { $0.expectedDevice < $1.expectedDevice }) {
      let root = try duplicateReadOnlyDescriptor(volume.rootFileDescriptor)
      try requireVolumeIdentity(
        root.rawValue, expectedDevice: volume.expectedDevice, policy: policy)
      leasedVolumes.append(LeasedVolumeDescriptor(device: volume.expectedDevice, root: root))
    }
    let capture = try mintCaptureBinding(
      plan: plan,
      executionEpochNonce: executionEpochNonce,
      validForNanoseconds: validForNanoseconds,
      ownerSlots: expectedSlots
    )
    return RuntimeReleaseTopologyDescriptorLease(
      authorityID: authorityID,
      plan: plan,
      capture: capture,
      policy: policy,
      owners: leasedOwners,
      volumes: leasedVolumes
    )
  }

  package func collect(
    _ lease: RuntimeReleaseTopologyDescriptorLease
  ) throws -> RuntimeReleaseTopologyReport {
    try lease.consume(authorityID: authorityID, now: monotonicNow())
    let plan = lease.plan
    var issues: [RuntimeReleaseTopologyIssue] = []
    var currentByFile: [RuntimeReleaseFileObjectIdentity: [OwnerCurrent]] = [:]
    for owner in lease.owners {
      let current = probe(owner, policy: lease.policy)
      currentByFile[owner.expected.slot.objectIdentity, default: []].append(current)
      if current.slotMatches != .known(true) {
        issues.append(.namespaceSlotMismatch(owner.expected.slot))
      }
    }
    var files: [RuntimeReleaseFileObjectTopology] = []
    for expected in plan.fileObjects {
      files.append(
        makeFile(
          expected: expected,
          currents: currentByFile[expected.identity] ?? [],
          issues: &issues
        ))
    }
    let snapshots = Dictionary(
      uniqueKeysWithValues: lease.volumes.map { volume in
        (volume.device, kernel.snapshotBlocker(volume.root.rawValue, lease.policy))
      }
    )
    let currentFileByIdentity = Dictionary(uniqueKeysWithValues: files.map { ($0.identity, $0) })
    let expectedFileByIdentity = Dictionary(
      uniqueKeysWithValues: plan.fileObjects.map { ($0.identity, $0) })
    var groups: [RuntimeReleaseGroupTopology] = []
    for expected in plan.groups {
      groups.append(
        makeGroup(
          expected: expected,
          currentFiles: currentFileByIdentity,
          expectedFiles: expectedFileByIdentity,
          snapshots: snapshots,
          issues: &issues
        ))
    }
    let components = makeComponents(groups: groups, files: currentFileByIdentity)
    let topologyMatches = allTrue(
      files.map(\.topologyMatchesExpected) + groups.map(\.topologyMatchesExpected))
    let collection = allTrue([
      topologyMatches,
      allTrue(Array(snapshots.values).map { $0.map { _ in true } }),
    ])
    return RuntimeReleaseTopologyReport(
      collection: collection,
      topologyMatchesExpected: topologyMatches,
      seal: RuntimeReleaseTopologySeal(
        planHash: plan.planHash,
        topologyBindingHash: plan.topologyBindingHash,
        captureID: lease.capture.captureID,
        executionEpochNonce: lease.capture.executionEpochNonce,
        fileObjects: files,
        groups: groups,
        components: components,
        snapshotBlockersByDevice: snapshots
      ),
      issues: issues
    )
  }

  private func mintCaptureBinding(
    plan: RuntimeReleaseTopologyExpectedPlan,
    executionEpochNonce: UUID,
    validForNanoseconds: UInt64,
    ownerSlots: Set<RuntimeReleaseNamespaceSlotIdentity>
  ) throws -> RuntimeReleaseFreshCaptureBinding {
    guard validForNanoseconds <= limits.maximumCaptureAgeNanoseconds else {
      throw RuntimeReleaseTopologyAuthorityError.captureReceiptMismatch
    }
    let issuedAt = monotonicNow()
    let (deadline, overflow) = issuedAt.addingReportingOverflow(validForNanoseconds)
    guard !overflow else { throw RuntimeReleaseTopologyAuthorityError.captureReceiptMismatch }
    captureLock.lock()
    defer { captureLock.unlock() }
    guard issuedExecutionEpochNonces.insert(executionEpochNonce).inserted else {
      throw RuntimeReleaseTopologyAuthorityError.captureReceiptReplayed
    }
    return RuntimeReleaseFreshCaptureBinding(
      planHash: plan.planHash,
      topologyBindingHash: plan.topologyBindingHash,
      captureID: releaseTopologyCaptureID(
        authorityID: authorityID,
        receiptID: UUID(),
        executionEpochNonce: executionEpochNonce,
        issuedAtMonotonicNanoseconds: issuedAt),
      executionEpochNonce: executionEpochNonce,
      issuedAtMonotonicNanoseconds: issuedAt,
      deadlineMonotonicNanoseconds: deadline,
      coveredOwnerSlots: ownerSlots,
      coveredVolumes: Set(plan.volumeDevices)
    )
  }

  private func duplicateReadOnlyDescriptor(_ descriptor: Int32) throws -> OwnedReleaseDescriptor {
    let status = fcntl(descriptor, F_GETFL)
    guard status >= 0 else {
      throw RuntimeReleaseTopologyAuthorityError.descriptorUnavailable(descriptor)
    }
    guard status & O_ACCMODE == O_RDONLY, status & O_EVTONLY == 0 else {
      throw RuntimeReleaseTopologyAuthorityError.descriptorNotReadOnly(descriptor)
    }
    let descriptorFlags = fcntl(descriptor, F_GETFD)
    guard descriptorFlags >= 0 else {
      throw RuntimeReleaseTopologyAuthorityError.descriptorUnavailable(descriptor)
    }
    guard descriptorFlags & FD_CLOEXEC != 0 else {
      throw RuntimeReleaseTopologyAuthorityError.descriptorMissingCloseOnExec(descriptor)
    }
    let duplicate = fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
    guard duplicate >= 0 else {
      throw RuntimeReleaseTopologyAuthorityError.descriptorUnavailable(descriptor)
    }
    let owned = OwnedReleaseDescriptor(duplicate)
    let duplicateStatus = fcntl(duplicate, F_GETFL)
    let duplicateFlags = fcntl(duplicate, F_GETFD)
    guard duplicateStatus >= 0, duplicateStatus & O_ACCMODE == O_RDONLY,
      duplicateStatus & O_EVTONLY == 0, duplicateFlags >= 0,
      duplicateFlags & FD_CLOEXEC != 0
    else { throw RuntimeReleaseTopologyAuthorityError.descriptorUnavailable(descriptor) }
    return owned
  }

  private func requireIdentity(
    _ descriptor: Int32,
    expected: RuntimeReleaseFileObjectIdentity,
    policy: NoMaterializationPolicy
  ) throws {
    switch kernel.descriptorIdentity(descriptor, policy) {
    case .known(let actual):
      guard actual == expected else {
        throw RuntimeReleaseTopologyAuthorityError.descriptorIdentityMismatch(expected)
      }
    case .absent:
      throw RuntimeReleaseTopologyAuthorityError.descriptorIdentityUnknown(.notObserved)
    case .unknown(let reason):
      throw RuntimeReleaseTopologyAuthorityError.descriptorIdentityUnknown(reason)
    case .unreadable(let failure):
      throw RuntimeReleaseTopologyAuthorityError.descriptorIdentityUnreadable(failure)
    case .failed(let failure):
      throw RuntimeReleaseTopologyAuthorityError.descriptorIdentityProbeFailed(failure)
    }
  }

  private func requireVolumeIdentity(
    _ descriptor: Int32,
    expectedDevice: UInt64,
    policy: NoMaterializationPolicy
  ) throws {
    switch kernel.descriptorIdentity(descriptor, policy) {
    case .known(let actual):
      guard actual.device == expectedDevice, actual.objectType == .directory else {
        throw RuntimeReleaseTopologyAuthorityError.descriptorIdentityMismatch(
          RuntimeReleaseFileObjectIdentity(
            device: expectedDevice, fileID: 0, objectType: .directory))
      }
    case .absent:
      throw RuntimeReleaseTopologyAuthorityError.descriptorIdentityUnknown(.notObserved)
    case .unknown(let reason):
      throw RuntimeReleaseTopologyAuthorityError.descriptorIdentityUnknown(reason)
    case .unreadable(let failure):
      throw RuntimeReleaseTopologyAuthorityError.descriptorIdentityUnreadable(failure)
    case .failed(let failure):
      throw RuntimeReleaseTopologyAuthorityError.descriptorIdentityProbeFailed(failure)
    }
  }

  private func probe(
    _ owner: LeasedOwnerDescriptor,
    policy: NoMaterializationPolicy
  ) -> OwnerCurrent {
    let expected = owner.expected.slot
    let root = kernel.descriptorIdentity(owner.root.rawValue, policy)
    let parent = kernel.descriptorIdentity(owner.parent.rawValue, policy)
    let file = kernel.descriptorIdentity(owner.file.rawValue, policy)
    let item = kernel.item(owner.parent.rawValue, expected.rawBasename, policy)
    let slotMatches = allTrue([
      root.map { $0 == expected.rootIdentity },
      parent.map { $0 == expected.parentIdentity },
      file.map { $0 == expected.objectIdentity },
      item.identity.map { $0 == expected.objectIdentity },
      allEqual([file, item.identity]),
    ])
    let clone = cloneAssociation(item: item, expectedDevice: expected.objectIdentity.device)
    return OwnerCurrent(
      expected: owner.expected,
      slotMatches: slotMatches,
      linkCount: item.linkCount,
      providerLocal: item.providerLocal,
      cloneAssociation: clone.association,
      cloneRefCount: clone.refCount,
      sharesAllBlocks: clone.sharesAllBlocks
    )
  }
}

private struct OwnerCurrent {
  let expected: RuntimeReleaseExpectedOwner
  let slotMatches: RuntimeReleaseTopologyObservation<Bool>
  let linkCount: RuntimeReleaseTopologyObservation<UInt32>
  let providerLocal: RuntimeReleaseTopologyObservation<Bool>
  let cloneAssociation: RuntimeReleaseTopologyObservation<RuntimeReleaseCloneAssociation>
  let cloneRefCount: RuntimeReleaseTopologyObservation<UInt32>
  let sharesAllBlocks: RuntimeReleaseTopologyObservation<Bool>
}

private struct CloneCurrent {
  let association: RuntimeReleaseTopologyObservation<RuntimeReleaseCloneAssociation>
  let refCount: RuntimeReleaseTopologyObservation<UInt32>
  let sharesAllBlocks: RuntimeReleaseTopologyObservation<Bool>
}

extension RuntimeReleaseTopologyAuthority {
  fileprivate func makeFile(
    expected: RuntimeReleaseExpectedFileObject,
    currents: [OwnerCurrent],
    issues: inout [RuntimeReleaseTopologyIssue]
  ) -> RuntimeReleaseFileObjectTopology {
    let slots = allTrue(currents.map(\.slotMatches))
    let providerLocal = allTrue(currents.map(\.providerLocal))
    let linkCount = consensus(currents.map(\.linkCount), collector: "release-link-count")
    let ownerClosure: RuntimeReleaseTopologyObservation<Bool>
    if case .known(let count) = linkCount,
      UInt64(count) != UInt64(currents.count) || count != expected.linkCount
    {
      ownerClosure = .known(false)
      issues.append(
        .hardlinkOwnerCountMismatch(
          expected.identity, observed: UInt32(currents.count), linkCount: count))
    } else if case .known = linkCount {
      ownerClosure = slots
    } else {
      ownerClosure = linkCount.map { _ in true }.asBooleanFailure()
    }
    let association = consensus(
      currents.map(\.cloneAssociation), collector: "release-clone-association")
    let refCount = consensus(
      currents.map(\.cloneRefCount), collector: "release-clone-refcount")
    let shares = consensus(
      currents.map(\.sharesAllBlocks), collector: "release-shares-all-blocks")
    let expectedAssociation: RuntimeReleaseCloneAssociation =
      expected.cloneIdentity.map {
        .clone($0)
      } ?? .notCloned
    let associationMatches = association.map { $0 == expectedAssociation }
    if associationMatches == .known(false) {
      issues.append(.cloneAssociationChanged(expected.identity))
    }
    let topologyMatches = allTrue([
      ownerClosure,
      providerLocal,
      associationMatches,
      expected.cloneIdentity == nil ? .known(true) : refCount.map { $0 > 0 },
      expected.cloneIdentity == nil ? .known(true) : shares,
    ])
    return RuntimeReleaseFileObjectTopology(
      identity: expected.identity,
      owners: expected.owners.map(\.link),
      actionIDs: Array(Set(expected.owners.map(\.actionID))).sorted(),
      namespaceSlotsMatch: slots,
      providerLocal: providerLocal,
      linkCount: linkCount,
      ownerClosure: ownerClosure,
      cloneAssociation: association,
      cloneRefCount: refCount,
      sharesAllBlocks: shares,
      topologyMatchesExpected: topologyMatches
    )
  }

  fileprivate func makeGroup(
    expected: RuntimeReleaseExpectedGroup,
    currentFiles: [RuntimeReleaseFileObjectIdentity: RuntimeReleaseFileObjectTopology],
    expectedFiles: [RuntimeReleaseFileObjectIdentity: RuntimeReleaseExpectedFileObject],
    snapshots: [UInt64: RuntimeReleaseTopologyObservation<Bool>],
    issues: inout [RuntimeReleaseTopologyIssue]
  ) -> RuntimeReleaseGroupTopology {
    let files = expected.ownerFileObjects.compactMap { currentFiles[$0] }
    let actionIDs = Array(Set(files.flatMap(\.actionIDs))).sorted()
    let ownerClosure = allTrue(files.map(\.ownerClosure))
    let snapshot = snapshots[expected.snapshotDevice] ?? .unknown(.notObserved)
    if snapshot == .known(true) { issues.append(.snapshotBlocked(expected.snapshotDevice)) }
    let refCount: RuntimeReleaseTopologyObservation<UInt32>
    let shares: RuntimeReleaseTopologyObservation<Bool>
    let cloneMatches: RuntimeReleaseTopologyObservation<Bool>
    if let clone = expected.cloneIdentity, let expectedRefCount = expected.cloneRefCount {
      refCount = consensus(files.map(\.cloneRefCount), collector: "release-clone-refcount")
      shares = allTrue(files.map(\.sharesAllBlocks))
      let associations = allTrue(
        files.map { file in
          file.cloneAssociation.map { $0 == .clone(clone) }
        })
      let currentRefMatches = refCount.map { $0 == expectedRefCount }
      if case .known(let current) = refCount, current != expectedRefCount {
        issues.append(
          .cloneOwnerCountMismatch(
            clone, observed: UInt32(expected.ownerFileObjects.count), refCount: current))
      }
      cloneMatches = allTrue([associations, currentRefMatches, shares])
      issues.append(.sharedCloneBytesUnavailable(clone))
    } else {
      refCount = .absent
      shares = .absent
      cloneMatches = .known(true)
    }
    let topology = allTrue([
      ownerClosure,
      cloneMatches,
      snapshot.map { !$0 },
      .known(Set(files.map(\.identity)) == Set(expected.ownerFileObjects)),
      .known(expected.ownerFileObjects.allSatisfy { expectedFiles[$0] != nil }),
    ])
    return RuntimeReleaseGroupTopology(
      allocationGroupID: expected.allocationGroupID,
      ownerFileObjects: expected.ownerFileObjects,
      actionIDsAtMostOnce: actionIDs,
      ownerClosure: ownerClosure,
      cloneRefCount: refCount,
      sharesAllBlocks: shares,
      snapshotBlocker: snapshot,
      topologyMatchesExpected: topology,
      conditionalSharedReclaimCredit: nil
    )
  }

  fileprivate func makeComponents(
    groups: [RuntimeReleaseGroupTopology],
    files: [RuntimeReleaseFileObjectIdentity: RuntimeReleaseFileObjectTopology]
  ) -> [RuntimeReleaseTopologyComponent] {
    guard !groups.isEmpty else { return [] }
    var union = RuntimeReleaseUnionFind(count: groups.count)
    var firstByAction: [ActionID: Int] = [:]
    var firstByFile: [RuntimeReleaseFileObjectIdentity: Int] = [:]
    for (index, group) in groups.enumerated() {
      for actionID in group.actionIDsAtMostOnce {
        if let first = firstByAction[actionID] {
          union.join(first, index)
        } else {
          firstByAction[actionID] = index
        }
      }
      for file in group.ownerFileObjects {
        if let first = firstByFile[file] {
          union.join(first, index)
        } else {
          firstByFile[file] = index
        }
      }
    }
    var indicesByRoot: [Int: [Int]] = [:]
    for index in groups.indices {
      indicesByRoot[union.root(of: index), default: []].append(index)
    }
    return indicesByRoot.values.map { indices in
      let members = indices.map { groups[$0] }.sorted {
        rawStringPrecedes($0.allocationGroupID, $1.allocationGroupID)
      }
      let fileIDs = Array(Set(members.flatMap(\.ownerFileObjects))).sorted()
      return RuntimeReleaseTopologyComponent(
        allocationGroupIDs: members.map(\.allocationGroupID),
        ownerFileObjects: fileIDs,
        actionIDsAtMostOnce: Array(Set(members.flatMap(\.actionIDsAtMostOnce))).sorted(),
        observedOwnerLinks: fileIDs.compactMap { files[$0] }.flatMap(\.owners).sorted(
          by: ownerLinkPrecedes),
        topologyMatchesExpected: allTrue(members.map(\.topologyMatchesExpected))
      )
    }.sorted { lhs, rhs in
      guard let left = lhs.allocationGroupIDs.first, let right = rhs.allocationGroupIDs.first else {
        return lhs.allocationGroupIDs.count < rhs.allocationGroupIDs.count
      }
      return rawStringPrecedes(left, right)
    }
  }
}

private struct RuntimeReleaseUnionFind {
  private var parents: [Int]
  private var ranks: [UInt8]

  init(count: Int) {
    parents = Array(0..<count)
    ranks = Array(repeating: 0, count: count)
  }

  mutating func root(of index: Int) -> Int {
    var node = index
    while parents[node] != node { node = parents[node] }
    let result = node
    node = index
    while parents[node] != node {
      let next = parents[node]
      parents[node] = result
      node = next
    }
    return result
  }

  mutating func join(_ lhs: Int, _ rhs: Int) {
    let left = root(of: lhs)
    let right = root(of: rhs)
    guard left != right else { return }
    if ranks[left] < ranks[right] {
      parents[left] = right
    } else if ranks[left] > ranks[right] {
      parents[right] = left
    } else {
      parents[right] = left
      ranks[left] &+= 1
    }
  }
}

private func cloneAssociation(
  item: RuntimeReleaseKernelItem,
  expectedDevice: UInt64
) -> CloneCurrent {
  switch item.mayShareBlocks {
  case .known(false):
    guard item.cloneID == .known(0), item.cloneRefCount == .absent,
      item.sharesAllBlocks == .absent
    else {
      return CloneCurrent(
        association: inconsistentCloneObservation(item),
        refCount: item.cloneRefCount,
        sharesAllBlocks: item.sharesAllBlocks)
    }
    return CloneCurrent(
      association: .known(.notCloned), refCount: .absent, sharesAllBlocks: .absent)
  case .known(true):
    guard case .known(let cloneID) = item.cloneID, cloneID > 0 else {
      return CloneCurrent(
        association: inconsistentCloneObservation(item),
        refCount: item.cloneRefCount,
        sharesAllBlocks: item.sharesAllBlocks)
    }
    return CloneCurrent(
      association: .known(
        .clone(RuntimeReleaseCloneIdentity(device: expectedDevice, cloneID: cloneID))),
      refCount: item.cloneRefCount,
      sharesAllBlocks: item.sharesAllBlocks
    )
  case .absent, .unknown, .unreadable, .failed:
    return CloneCurrent(
      association: item.mayShareBlocks.erased(),
      refCount: item.cloneRefCount,
      sharesAllBlocks: item.sharesAllBlocks)
  }
}

private func inconsistentCloneObservation(
  _ item: RuntimeReleaseKernelItem
) -> RuntimeReleaseTopologyObservation<RuntimeReleaseCloneAssociation> {
  if let failure: RuntimeReleaseTopologyObservation<RuntimeReleaseCloneAssociation> =
    propagatedCloneFailure(item.cloneID)
  {
    return failure
  }
  if let failure: RuntimeReleaseTopologyObservation<RuntimeReleaseCloneAssociation> =
    propagatedCloneFailure(item.cloneRefCount)
  {
    return failure
  }
  if let failure: RuntimeReleaseTopologyObservation<RuntimeReleaseCloneAssociation> =
    propagatedCloneFailure(item.sharesAllBlocks)
  {
    return failure
  }
  return .failed(
    RuntimeReleaseTopologyFailure(
      kind: .inconsistentEvidence, collector: "release-clone-association"))
}

private func propagatedCloneFailure<Observed: Equatable & Sendable>(
  _ observation: RuntimeReleaseTopologyObservation<Observed>
) -> RuntimeReleaseTopologyObservation<RuntimeReleaseCloneAssociation>? {
  switch observation {
  case .absent, .known: nil
  case .unknown(let reason): .unknown(reason)
  case .unreadable(let failure): .unreadable(failure)
  case .failed(let failure): .failed(failure)
  }
}

private func runtimeIdentity(_ identity: FileObjectIdentity) -> RuntimeReleaseFileObjectIdentity {
  RuntimeReleaseFileObjectIdentity(
    device: UInt64(bitPattern: identity.device),
    fileID: identity.fileID,
    objectType: runtimeObjectType(identity.objectType)
  )
}

private func runtimeObjectType(_ objectType: FileSystemObjectType) -> RuntimeReleaseObjectType {
  switch objectType {
  case .directory: .directory
  case .regular: .regularFile
  case .symbolicLink: .symbolicLink
  case .other: .other
  }
}

private func combineIdentity(
  _ item: ItemStorageEvidence
) -> RuntimeReleaseTopologyObservation<RuntimeReleaseFileObjectIdentity> {
  let device = capabilityObservation(item.device)
  let fileID = capabilityObservation(item.fileID)
  let objectType = capabilityObservation(item.objectType)
  guard let deviceValue = device.knownValue else { return device.erased() }
  guard let fileIDValue = fileID.knownValue else { return fileID.erased() }
  guard let objectTypeValue = objectType.knownValue else { return objectType.erased() }
  return .known(
    RuntimeReleaseFileObjectIdentity(
      device: UInt64(bitPattern: deviceValue),
      fileID: fileIDValue,
      objectType: runtimeObjectType(objectTypeValue)
    ))
}

private func capabilityObservation<Value: Equatable & Sendable>(
  _ capability: Capability<Value>
) -> RuntimeReleaseTopologyObservation<Value> {
  if let value = capability.value { return .known(value) }
  switch capability.status {
  case .unsupported: return .unknown(.unsupported)
  case .unavailable: return .unknown(.unavailableViaPublicAPI)
  case .permissionDenied:
    return .unreadable(
      RuntimeReleaseTopologyFailure(
        kind: .probeFailed, collector: capability.detail ?? "macos-capability",
        errorCode: capability.errorCode))
  case .failed, .inconsistent:
    return .failed(
      RuntimeReleaseTopologyFailure(
        kind: .probeFailed, collector: capability.detail ?? "macos-capability",
        errorCode: capability.errorCode))
  case .known:
    return .failed(
      RuntimeReleaseTopologyFailure(
        kind: .inconsistentEvidence, collector: "known-capability-without-value"))
  }
}

private func providerLocalObservation(
  _ outcome: FileProviderProbeOutcome,
  dataless: RuntimeReleaseTopologyObservation<Bool>,
  syncRoot: RuntimeReleaseTopologyObservation<Bool>
) -> RuntimeReleaseTopologyObservation<Bool> {
  switch outcome {
  case .evidence(let evidence):
    switch evidence.identityDisposition {
    case .confirmedProvider:
      return .known(false)
    case .identifierAbsent:
      return allTrue([
        dataless.map { !$0 },
        syncRoot.map { !$0 },
      ])
    case .indeterminate(let status):
      return providerStatusObservation(status, collector: "file-provider-identity")
    }
  case .rejected(let rejection):
    return providerRejectionObservation(rejection)
  }
}

private func providerStatusObservation(
  _ status: CapabilityStatus,
  collector: String,
  errorCode: Int32? = nil
) -> RuntimeReleaseTopologyObservation<Bool> {
  switch status {
  case .unsupported: return .unknown(.unsupported)
  case .unavailable: return .unknown(.unavailableViaPublicAPI)
  case .permissionDenied:
    return .unreadable(
      RuntimeReleaseTopologyFailure(
        kind: .probeFailed, collector: collector, errorCode: errorCode))
  case .failed, .inconsistent, .known:
    return .failed(
      RuntimeReleaseTopologyFailure(
        kind: status == .inconsistent ? .inconsistentEvidence : .probeFailed,
        collector: collector,
        errorCode: errorCode))
  }
}

private func providerRejectionObservation(
  _ rejection: FileProviderProbeRejection
) -> RuntimeReleaseTopologyObservation<Bool> {
  switch rejection {
  case .policyUnavailable(let status, _, let errorCode):
    return providerStatusObservation(
      status, collector: "file-provider-policy", errorCode: errorCode)
  case .rawNameUnavailable:
    return .unknown(.providerBoundary)
  case .missing:
    return .unknown(.incompleteCoverage)
  case .unreadable(_, let errorCode):
    return .unreadable(
      RuntimeReleaseTopologyFailure(
        kind: .probeFailed,
        collector: "file-provider-slot",
        errorCode: errorCode))
  case .failed(_, let status, _, let errorCode):
    return providerStatusObservation(
      status, collector: "file-provider-probe", errorCode: errorCode)
  case .identityMismatch, .parentIdentityMismatch, .contentStateMismatch:
    return .failed(
      RuntimeReleaseTopologyFailure(
        kind: .inconsistentEvidence, collector: "file-provider-slot"))
  case .contentStateUnavailable(_, let status, _, let errorCode):
    return providerStatusObservation(
      status, collector: "file-provider-content-state", errorCode: errorCode)
  case .timedOut:
    return .failed(
      RuntimeReleaseTopologyFailure(
        kind: .probeFailed, collector: "file-provider-timeout"))
  }
}

private func posixObservation<Value: Equatable & Sendable>(
  _ code: Int32,
  collector: String
) -> RuntimeReleaseTopologyObservation<Value> {
  let failure = RuntimeReleaseTopologyFailure(
    kind: .probeFailed, collector: collector, errorCode: code)
  return code == EACCES || code == EPERM ? .unreadable(failure) : .failed(failure)
}

private func consensus<Value: Equatable & Sendable>(
  _ observations: [RuntimeReleaseTopologyObservation<Value>],
  collector: String
) -> RuntimeReleaseTopologyObservation<Value> {
  guard let first = observations.first else { return .unknown(.notObserved) }
  guard observations.dropFirst().allSatisfy({ $0 == first }) else {
    return .failed(
      RuntimeReleaseTopologyFailure(kind: .inconsistentEvidence, collector: collector))
  }
  return first
}

private func allTrue(
  _ observations: [RuntimeReleaseTopologyObservation<Bool>]
) -> RuntimeReleaseTopologyObservation<Bool> {
  if observations.contains(.known(false)) { return .known(false) }
  if let failed = observations.first(where: { $0.isFailed }) { return failed }
  if let unreadable = observations.first(where: { $0.isUnreadable }) { return unreadable }
  if let unknown = observations.first(where: { $0.isUnknown }) { return unknown }
  if observations.contains(.absent) { return .unknown(.notObserved) }
  return .known(true)
}

private func allEqual<Value: Equatable & Sendable>(
  _ observations: [RuntimeReleaseTopologyObservation<Value>]
) -> RuntimeReleaseTopologyObservation<Bool> {
  consensus(observations, collector: "release-identity-consensus").map { _ in true }
    .asBooleanFailure()
}

extension RuntimeReleaseTopologyObservation {
  fileprivate var isFailed: Bool {
    if case .failed = self { return true }
    return false
  }

  fileprivate var isUnreadable: Bool {
    if case .unreadable = self { return true }
    return false
  }

  fileprivate var isUnknown: Bool {
    if case .unknown = self { return true }
    return false
  }

  fileprivate func asBooleanFailure() -> RuntimeReleaseTopologyObservation<Bool> {
    switch self {
    case .absent: .unknown(.notObserved)
    case .known: .known(true)
    case .unknown(let reason): .unknown(reason)
    case .unreadable(let failure): .unreadable(failure)
    case .failed(let failure): .failed(failure)
    }
  }

  fileprivate func erased<Mapped: Equatable & Sendable>() -> RuntimeReleaseTopologyObservation<
    Mapped
  > {
    switch self {
    case .absent: .absent
    case .known: .unknown(.notObserved)
    case .unknown(let reason): .unknown(reason)
    case .unreadable(let failure): .unreadable(failure)
    case .failed(let failure): .failed(failure)
    }
  }
}

private struct RuntimeReleaseTopologyBindingEncoder {
  var data = Data()

  mutating func uint64(_ value: UInt64) {
    var bigEndian = value.bigEndian
    withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
  }

  mutating func bytes(_ value: Data) {
    uint64(UInt64(value.count))
    data.append(value)
  }

  mutating func string(_ value: String) { bytes(Data(value.utf8)) }

  mutating func identity(_ value: RuntimeReleaseFileObjectIdentity) {
    uint64(value.device)
    uint64(value.fileID)
    string(value.objectType.rawValue)
  }

  mutating func optionalClone(_ value: RuntimeReleaseCloneIdentity?) {
    uint64(value == nil ? 0 : 1)
    if let value {
      uint64(value.device)
      uint64(value.cloneID)
    }
  }
}

private func releaseTopologyBindingHash(
  planHash: PolicyDigest,
  candidateActions: [RuntimeReleaseCandidateActionBinding],
  fileObjects: [RuntimeReleaseExpectedFileObject],
  groups: [RuntimeReleaseExpectedGroup],
  volumeDevices: [UInt64]
) -> PolicyDigest {
  var encoder = RuntimeReleaseTopologyBindingEncoder()
  encoder.bytes(planHash.bytes)
  encoder.uint64(UInt64(candidateActions.count))
  for binding in candidateActions {
    encoder.string(binding.candidateID)
    encoder.bytes(binding.actionID.digest.bytes)
  }
  encoder.uint64(UInt64(fileObjects.count))
  for file in fileObjects {
    encoder.identity(file.identity)
    encoder.uint64(UInt64(file.linkCount))
    encoder.optionalClone(file.cloneIdentity)
    encoder.uint64(UInt64(file.owners.count))
    for owner in file.owners {
      encoder.string(owner.link.candidateID)
      encoder.uint64(UInt64(owner.link.path.components.count))
      for component in owner.link.path.components { encoder.bytes(component) }
      encoder.identity(owner.slot.rootIdentity)
      encoder.identity(owner.slot.parentIdentity)
      encoder.bytes(owner.slot.rawBasename)
      encoder.identity(owner.slot.objectIdentity)
      encoder.bytes(owner.actionID.digest.bytes)
    }
  }
  encoder.uint64(UInt64(groups.count))
  for group in groups {
    encoder.string(group.allocationGroupID)
    encoder.uint64(UInt64(group.ownerFileObjects.count))
    for file in group.ownerFileObjects { encoder.identity(file) }
    encoder.optionalClone(group.cloneIdentity)
    encoder.uint64(group.cloneRefCount.map(UInt64.init) ?? UInt64.max)
    encoder.uint64(group.snapshotDevice)
  }
  encoder.uint64(UInt64(volumeDevices.count))
  for device in volumeDevices { encoder.uint64(device) }
  var input = Data("diskplan/runtime-release-topology-binding/v1\0".utf8)
  input.append(encoder.data)
  return try! PolicyDigest(bytes: Data(SHA256.hash(data: input)))
}

private func releaseTopologyCaptureID(
  authorityID: UUID,
  receiptID: UUID,
  executionEpochNonce: UUID,
  issuedAtMonotonicNanoseconds: UInt64
) -> PolicyDigest {
  var encoder = RuntimeReleaseTopologyBindingEncoder()
  encoder.string(authorityID.uuidString)
  encoder.string(receiptID.uuidString)
  encoder.string(executionEpochNonce.uuidString)
  encoder.uint64(issuedAtMonotonicNanoseconds)
  var input = Data("diskplan/runtime-release-topology-capture/v1\0".utf8)
  input.append(encoder.data)
  return try! PolicyDigest(bytes: Data(SHA256.hash(data: input)))
}

private func expectedOwnerPrecedes(
  _ lhs: RuntimeReleaseExpectedOwner,
  _ rhs: RuntimeReleaseExpectedOwner
) -> Bool {
  lhs.slot == rhs.slot ? ownerLinkPrecedes(lhs.link, rhs.link) : lhs.slot < rhs.slot
}

private func candidateActionPrecedes(
  _ lhs: RuntimeReleaseCandidateActionBinding,
  _ rhs: RuntimeReleaseCandidateActionBinding
) -> Bool {
  rawStringPrecedes(lhs.candidateID, rhs.candidateID)
}

private func ownerLinkPrecedes(_ lhs: FileOwnerLink, _ rhs: FileOwnerLink) -> Bool {
  if !rawStringEqual(lhs.candidateID, rhs.candidateID) {
    return rawStringPrecedes(lhs.candidateID, rhs.candidateID)
  }
  return lhs.path < rhs.path
}

private func rawStringEqual(_ lhs: String, _ rhs: String) -> Bool {
  Data(lhs.utf8) == Data(rhs.utf8)
}

private func rawStringPrecedes(_ lhs: String, _ rhs: String) -> Bool {
  Data(lhs.utf8).lexicographicallyPrecedes(Data(rhs.utf8))
}
