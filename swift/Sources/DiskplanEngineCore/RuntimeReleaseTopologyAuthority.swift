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
    case limitExceeded = "limit_exceeded"
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

/// Release-topology evidence never turns absence or collection failure into a numeric sentinel.
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

public struct RuntimeReleaseFileObjectIdentity: Equatable, Hashable, Comparable, Sendable {
  public let device: UInt64
  public let fileID: UInt64

  public init(device: UInt64, fileID: UInt64) {
    self.device = device
    self.fileID = fileID
  }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    lhs.device == rhs.device ? lhs.fileID < rhs.fileID : lhs.device < rhs.device
  }
}

/// Clone IDs are volume-local, so device identity is a required part of every clone key.
public struct RuntimeReleaseCloneIdentity: Equatable, Hashable, Comparable, Sendable {
  public let device: UInt64
  public let cloneID: UInt64

  public init(device: UInt64, cloneID: UInt64) {
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

public enum RuntimeReleaseSharedBytesSource: String, Equatable, Sendable {
  /// The adapter proved an exact group value with a public filesystem API.
  case exactPublicFilesystemAPI = "exact_public_filesystem_api"
}

public struct RuntimeReleaseExactSharedBytes: Equatable, Sendable {
  public let bytes: UInt64
  public let source: RuntimeReleaseSharedBytesSource

  public init(bytes: UInt64, source: RuntimeReleaseSharedBytesSource) {
    self.bytes = bytes
    self.source = source
  }
}

public struct RuntimeReleaseTopologyOwnerProbe: Equatable, Sendable {
  public let identity: RuntimeReleaseTopologyObservation<RuntimeReleaseFileObjectIdentity>
  public let coverage: RuntimeReleaseTopologyObservation<Bool>
  public let linkCount: RuntimeReleaseTopologyObservation<UInt32>
  public let cloneAssociation: RuntimeReleaseTopologyObservation<RuntimeReleaseCloneAssociation>
  public let cloneRefCount: RuntimeReleaseTopologyObservation<UInt32>
  public let sharesAllBlocks: RuntimeReleaseTopologyObservation<Bool>
  public let exactSharedBytes: RuntimeReleaseTopologyObservation<RuntimeReleaseExactSharedBytes>

  public init(
    identity: RuntimeReleaseTopologyObservation<RuntimeReleaseFileObjectIdentity>,
    coverage: RuntimeReleaseTopologyObservation<Bool>,
    linkCount: RuntimeReleaseTopologyObservation<UInt32>,
    cloneAssociation: RuntimeReleaseTopologyObservation<RuntimeReleaseCloneAssociation>,
    cloneRefCount: RuntimeReleaseTopologyObservation<UInt32>,
    sharesAllBlocks: RuntimeReleaseTopologyObservation<Bool>,
    exactSharedBytes: RuntimeReleaseTopologyObservation<RuntimeReleaseExactSharedBytes>
  ) {
    self.identity = identity
    self.coverage = coverage
    self.linkCount = linkCount
    self.cloneAssociation = cloneAssociation
    self.cloneRefCount = cloneRefCount
    self.sharesAllBlocks = sharesAllBlocks
    self.exactSharedBytes = exactSharedBytes
  }
}

public struct RuntimeReleaseTopologyVolumeProbe: Equatable, Sendable {
  public let device: RuntimeReleaseTopologyObservation<UInt64>
  public let snapshotBlocker: RuntimeReleaseTopologyObservation<Bool>

  public init(
    device: RuntimeReleaseTopologyObservation<UInt64>,
    snapshotBlocker: RuntimeReleaseTopologyObservation<Bool>
  ) {
    self.device = device
    self.snapshotBlocker = snapshotBlocker
  }
}

/// Implementations may only inspect the borrowed descriptors and must not read file contents,
/// resolve paths, materialize File Provider items, mutate namespace state, or close descriptors.
public protocol RuntimeReleaseTopologyReadOnlyProbing: Sendable {
  func probeOwner(fileDescriptor: Int32) -> RuntimeReleaseTopologyOwnerProbe
  func probeVolume(rootFileDescriptor: Int32) -> RuntimeReleaseTopologyVolumeProbe
}

public struct BoundRuntimeReleaseOwnerDescriptor: Equatable, Sendable {
  public let owner: FileOwnerLink
  public let expectedIdentity: RuntimeReleaseFileObjectIdentity
  public let fileDescriptor: Int32

  public init(
    owner: FileOwnerLink,
    expectedIdentity: RuntimeReleaseFileObjectIdentity,
    fileDescriptor: Int32
  ) {
    self.owner = owner
    self.expectedIdentity = expectedIdentity
    self.fileDescriptor = fileDescriptor
  }
}

public struct BoundRuntimeReleaseVolumeDescriptor: Equatable, Sendable {
  public let expectedDevice: UInt64
  public let rootFileDescriptor: Int32

  public init(expectedDevice: UInt64, rootFileDescriptor: Int32) {
    self.expectedDevice = expectedDevice
    self.rootFileDescriptor = rootFileDescriptor
  }
}

public struct RuntimeReleaseTopologyLimits: Equatable, Sendable {
  public let maximumOwners: Int
  public let maximumVolumes: Int

  public init(maximumOwners: Int = 5_000_000, maximumVolumes: Int = 4_096) {
    precondition(maximumOwners >= 0)
    precondition(maximumVolumes >= 0)
    self.maximumOwners = maximumOwners
    self.maximumVolumes = maximumVolumes
  }
}

public struct RuntimeReleaseFileObjectTopology: Equatable, Sendable {
  public let identity: RuntimeReleaseFileObjectIdentity
  public let owners: [FileOwnerLink]
  public let identityBindingsMatch: RuntimeReleaseTopologyObservation<Bool>
  public let linkCount: RuntimeReleaseTopologyObservation<UInt32>
  /// `known(false)` is authoritative whenever the unique observed-owner count differs from
  /// `st_nlink`, even if independent coverage evidence is also incomplete.
  public let ownerClosure: RuntimeReleaseTopologyObservation<Bool>
  public let cloneAssociation: RuntimeReleaseTopologyObservation<RuntimeReleaseCloneAssociation>
  public let cloneRefCount: RuntimeReleaseTopologyObservation<UInt32>
  public let sharesAllBlocks: RuntimeReleaseTopologyObservation<Bool>
  public let exactSharedBytes: RuntimeReleaseTopologyObservation<RuntimeReleaseExactSharedBytes>
  /// Proves that clone membership and its dependent field shape are internally complete.
  public let topologyCompleteness: RuntimeReleaseTopologyObservation<Bool>
}

public struct RuntimeReleaseCloneGroupTopology: Equatable, Sendable {
  public let identity: RuntimeReleaseCloneIdentity
  /// A hardlinked file object occurs once, regardless of how many link paths were observed.
  public let ownerFileObjects: [RuntimeReleaseFileObjectIdentity]
  public let owners: [FileOwnerLink]
  public let cloneRefCount: RuntimeReleaseTopologyObservation<UInt32>
  public let ownerClosure: RuntimeReleaseTopologyObservation<Bool>
  public let sharesAllBlocks: RuntimeReleaseTopologyObservation<Bool>
  public let snapshotBlocker: RuntimeReleaseTopologyObservation<Bool>
  public let exactSharedBytes: RuntimeReleaseTopologyObservation<RuntimeReleaseExactSharedBytes>
  /// This is non-nil only when every independent gate is exact and affirmative.
  public let conditionalSharedReclaimCredit: UInt64?

  public var isReleaseComplete: Bool {
    ownerClosure == .known(true) && sharesAllBlocks == .known(true)
      && snapshotBlocker == .known(false) && exactSharedBytes.knownValue != nil
  }
}

public struct RuntimeReleaseTopologyComponent: Equatable, Sendable {
  public let cloneGroups: [RuntimeReleaseCloneIdentity]
  public let ownerFileObjects: [RuntimeReleaseFileObjectIdentity]
  public let observedOwnerLinks: [FileOwnerLink]
  /// Canonical candidate-action de-duplication contract for an execution aggregate.
  public let ownerCandidateIDsAtMostOnce: [String]
  public let isExecutable: Bool
}

public enum RuntimeReleaseTopologyIssue: Equatable, Sendable {
  case collectionLimitExceeded
  case duplicateOwnerBinding(FileOwnerLink)
  case conflictingOwnerBinding(FileOwnerLink)
  case descriptorIdentityMismatch(FileOwnerLink)
  case inconsistentFileEvidence(RuntimeReleaseFileObjectIdentity)
  case hardlinkOwnerCountMismatch(
    RuntimeReleaseFileObjectIdentity, observed: UInt32, linkCount: UInt32)
  case cloneDeviceMismatch(RuntimeReleaseFileObjectIdentity, RuntimeReleaseCloneIdentity)
  case inconsistentCloneEvidence(RuntimeReleaseCloneIdentity)
  case cloneOwnerCountMismatch(RuntimeReleaseCloneIdentity, observed: UInt32, refCount: UInt32)
  case partialClone(RuntimeReleaseCloneIdentity)
  case sharedBytesUnavailable(RuntimeReleaseCloneIdentity)
  case snapshotBlocked(RuntimeReleaseCloneIdentity)
  case topologyEvidenceIncomplete
}

public struct RuntimeReleaseTopologySeal: Equatable, Sendable {
  public let fileObjects: [RuntimeReleaseFileObjectTopology]
  public let cloneGroups: [RuntimeReleaseCloneGroupTopology]
  public let components: [RuntimeReleaseTopologyComponent]
  public let snapshotBlockersByDevice: [UInt64: RuntimeReleaseTopologyObservation<Bool>]
}

public struct RuntimeReleaseTopologyReport: Equatable, Sendable {
  public let collection: RuntimeReleaseTopologyObservation<Bool>
  public let seal: RuntimeReleaseTopologySeal
  public let issues: [RuntimeReleaseTopologyIssue]

  public var conditionalSharedReclaimCredit: UInt64? {
    var total: UInt64 = 0
    for group in seal.cloneGroups {
      guard let credit = group.conditionalSharedReclaimCredit else { continue }
      let addition = total.addingReportingOverflow(credit)
      guard !addition.overflow else { return nil }
      total = addition.partialValue
    }
    return total
  }
}

public struct RuntimeReleaseTopologyValidation: Equatable, Sendable {
  public let topologyMatches: RuntimeReleaseTopologyObservation<Bool>
  public let current: RuntimeReleaseTopologyReport
}

public struct RuntimeReleaseTopologyAuthority: Sendable {
  public let limits: RuntimeReleaseTopologyLimits

  public init(limits: RuntimeReleaseTopologyLimits = RuntimeReleaseTopologyLimits()) {
    self.limits = limits
  }

  public func collect(
    owners: [BoundRuntimeReleaseOwnerDescriptor],
    volumes: [BoundRuntimeReleaseVolumeDescriptor],
    scopeCoverage: RuntimeReleaseTopologyObservation<Bool>,
    probe: some RuntimeReleaseTopologyReadOnlyProbing
  ) -> RuntimeReleaseTopologyReport {
    guard owners.count <= limits.maximumOwners, volumes.count <= limits.maximumVolumes else {
      return RuntimeReleaseTopologyReport(
        collection: .failed(
          RuntimeReleaseTopologyFailure(kind: .limitExceeded, collector: "release-topology")),
        seal: RuntimeReleaseTopologySeal(
          fileObjects: [], cloneGroups: [], components: [], snapshotBlockersByDevice: [:]),
        issues: [.collectionLimitExceeded]
      )
    }

    let canonicalOwners = owners.sorted(by: boundOwnerPrecedes)
    var issues: [RuntimeReleaseTopologyIssue] = []
    var seenOwners: [FileOwnerLink: RuntimeReleaseFileObjectIdentity] = [:]
    var captures: [RuntimeReleaseFileObjectIdentity: [OwnerCapture]] = [:]

    for descriptor in canonicalOwners {
      if let previous = seenOwners[descriptor.owner] {
        issues.append(
          previous == descriptor.expectedIdentity
            ? .duplicateOwnerBinding(descriptor.owner)
            : .conflictingOwnerBinding(descriptor.owner)
        )
        continue
      }
      seenOwners[descriptor.owner] = descriptor.expectedIdentity
      let ownerProbe: RuntimeReleaseTopologyOwnerProbe
      if descriptor.fileDescriptor < 0 {
        let failure = RuntimeReleaseTopologyFailure(
          kind: .invalidDescriptor, collector: "release-owner-descriptor")
        ownerProbe = RuntimeReleaseTopologyOwnerProbe(
          identity: .failed(failure),
          coverage: .failed(failure),
          linkCount: .failed(failure),
          cloneAssociation: .failed(failure),
          cloneRefCount: .failed(failure),
          sharesAllBlocks: .failed(failure),
          exactSharedBytes: .failed(failure)
        )
      } else {
        ownerProbe = probe.probeOwner(fileDescriptor: descriptor.fileDescriptor)
      }
      if let actual = ownerProbe.identity.knownValue, actual != descriptor.expectedIdentity {
        issues.append(.descriptorIdentityMismatch(descriptor.owner))
      }
      captures[descriptor.expectedIdentity, default: []].append(
        OwnerCapture(descriptor: descriptor, probe: ownerProbe)
      )
    }

    let volumeResult = collectVolumes(volumes, probe: probe, issues: &issues)
    var fileObjects: [RuntimeReleaseFileObjectTopology] = []
    for identity in captures.keys.sorted() {
      guard let fileCaptures = captures[identity] else { continue }
      fileObjects.append(
        makeFileObject(
          identity: identity,
          captures: fileCaptures,
          scopeCoverage: scopeCoverage,
          issues: &issues
        )
      )
    }

    let cloneGroups = makeCloneGroups(
      fileObjects: fileObjects,
      snapshotBlockersByDevice: volumeResult,
      collectionAdmission: issues.isEmpty
        ? scopeCoverage
        : .failed(
          RuntimeReleaseTopologyFailure(
            kind: .inconsistentEvidence, collector: "release-topology-admission")),
      issues: &issues
    )
    let components = makeComponents(cloneGroups)
    let collection = collectionState(
      scopeCoverage: scopeCoverage,
      files: fileObjects,
      groups: cloneGroups,
      issues: issues
    )
    return RuntimeReleaseTopologyReport(
      collection: collection,
      seal: RuntimeReleaseTopologySeal(
        fileObjects: fileObjects,
        cloneGroups: cloneGroups,
        components: components,
        snapshotBlockersByDevice: volumeResult
      ),
      issues: issues
    )
  }

  public func validate(
    _ current: RuntimeReleaseTopologyReport,
    against expected: RuntimeReleaseTopologySeal
  ) -> RuntimeReleaseTopologyValidation {
    guard current.seal == expected else {
      return RuntimeReleaseTopologyValidation(topologyMatches: .known(false), current: current)
    }
    return RuntimeReleaseTopologyValidation(
      topologyMatches: current.collection,
      current: current
    )
  }
}

private struct OwnerCapture {
  let descriptor: BoundRuntimeReleaseOwnerDescriptor
  let probe: RuntimeReleaseTopologyOwnerProbe
}

extension RuntimeReleaseTopologyAuthority {
  fileprivate func collectVolumes(
    _ volumes: [BoundRuntimeReleaseVolumeDescriptor],
    probe: some RuntimeReleaseTopologyReadOnlyProbing,
    issues: inout [RuntimeReleaseTopologyIssue]
  ) -> [UInt64: RuntimeReleaseTopologyObservation<Bool>] {
    var result: [UInt64: RuntimeReleaseTopologyObservation<Bool>] = [:]
    for descriptor in volumes.sorted(by: { lhs, rhs in
      lhs.expectedDevice == rhs.expectedDevice
        ? lhs.rootFileDescriptor < rhs.rootFileDescriptor
        : lhs.expectedDevice < rhs.expectedDevice
    }) {
      let volumeProbe: RuntimeReleaseTopologyVolumeProbe
      if descriptor.rootFileDescriptor < 0 {
        let failure = RuntimeReleaseTopologyFailure(
          kind: .invalidDescriptor, collector: "release-volume-descriptor")
        volumeProbe = RuntimeReleaseTopologyVolumeProbe(
          device: .failed(failure), snapshotBlocker: .failed(failure))
      } else {
        volumeProbe = probe.probeVolume(rootFileDescriptor: descriptor.rootFileDescriptor)
      }
      let evidence: RuntimeReleaseTopologyObservation<Bool>
      if let actual = volumeProbe.device.knownValue, actual != descriptor.expectedDevice {
        evidence = .failed(
          RuntimeReleaseTopologyFailure(
            kind: .inconsistentEvidence, collector: "release-volume-identity"))
      } else if volumeProbe.device.knownValue == nil {
        evidence = volumeProbe.device.map { _ in false }.asBooleanFailure()
      } else {
        evidence = volumeProbe.snapshotBlocker
      }
      if let previous = result[descriptor.expectedDevice], previous != evidence {
        result[descriptor.expectedDevice] = .failed(
          RuntimeReleaseTopologyFailure(
            kind: .inconsistentEvidence, collector: "release-volume-snapshot"))
        issues.append(.topologyEvidenceIncomplete)
      } else {
        result[descriptor.expectedDevice] = evidence
      }
    }
    return result
  }

  fileprivate func makeFileObject(
    identity: RuntimeReleaseFileObjectIdentity,
    captures: [OwnerCapture],
    scopeCoverage: RuntimeReleaseTopologyObservation<Bool>,
    issues: inout [RuntimeReleaseTopologyIssue]
  ) -> RuntimeReleaseFileObjectTopology {
    let owners = captures.map(\.descriptor.owner).sorted(by: ownerPrecedes)
    let identityBindings = captures.map { capture -> RuntimeReleaseTopologyObservation<Bool> in
      capture.probe.identity.map { $0 == capture.descriptor.expectedIdentity }
    }
    let identityBindingsMatch = allTrue(identityBindings)
    let linkCount = consensus(captures.map(\.probe.linkCount), collector: "release-link-count")
    let cloneAssociation = consensus(
      captures.map(\.probe.cloneAssociation), collector: "release-clone-association")
    let cloneRefCount = consensus(
      captures.map(\.probe.cloneRefCount), collector: "release-clone-refcount")
    let sharesAllBlocks = consensus(
      captures.map(\.probe.sharesAllBlocks), collector: "release-shares-all-blocks")
    let exactSharedBytes = consensus(
      captures.map(\.probe.exactSharedBytes), collector: "release-shared-bytes")
    let topologyCompleteness = cloneTopologyCompleteness(
      fileIdentity: identity,
      association: cloneAssociation,
      refCount: cloneRefCount,
      sharesAllBlocks: sharesAllBlocks,
      exactSharedBytes: exactSharedBytes
    )
    let coverage = allTrue([scopeCoverage] + captures.map(\.probe.coverage))

    let ownerClosure: RuntimeReleaseTopologyObservation<Bool>
    if case .known(let count) = linkCount, UInt64(count) != UInt64(owners.count) {
      ownerClosure = .known(false)
      issues.append(
        .hardlinkOwnerCountMismatch(identity, observed: UInt32(owners.count), linkCount: count))
    } else if identityBindingsMatch == .known(false) {
      ownerClosure = .known(false)
    } else if case .known = linkCount {
      ownerClosure = allTrue([identityBindingsMatch, coverage])
    } else {
      ownerClosure = linkCount.map { _ in true }.asBooleanFailure()
    }

    if topologyCompleteness == .known(false) || topologyCompleteness.isFailure {
      issues.append(.inconsistentFileEvidence(identity))
    }
    if case .known(.clone(let clone)) = cloneAssociation, clone.device != identity.device {
      issues.append(.cloneDeviceMismatch(identity, clone))
    }
    return RuntimeReleaseFileObjectTopology(
      identity: identity,
      owners: owners,
      identityBindingsMatch: identityBindingsMatch,
      linkCount: linkCount,
      ownerClosure: ownerClosure,
      cloneAssociation: cloneAssociation,
      cloneRefCount: cloneRefCount,
      sharesAllBlocks: sharesAllBlocks,
      exactSharedBytes: exactSharedBytes,
      topologyCompleteness: topologyCompleteness
    )
  }

  fileprivate func makeCloneGroups(
    fileObjects: [RuntimeReleaseFileObjectTopology],
    snapshotBlockersByDevice: [UInt64: RuntimeReleaseTopologyObservation<Bool>],
    collectionAdmission: RuntimeReleaseTopologyObservation<Bool>,
    issues: inout [RuntimeReleaseTopologyIssue]
  ) -> [RuntimeReleaseCloneGroupTopology] {
    var filesByClone: [RuntimeReleaseCloneIdentity: [RuntimeReleaseFileObjectTopology]] = [:]
    for file in fileObjects {
      guard case .known(.clone(let clone)) = file.cloneAssociation else { continue }
      guard clone.device == file.identity.device else { continue }
      filesByClone[clone, default: []].append(file)
    }

    return filesByClone.keys.sorted().compactMap { clone in
      guard let files = filesByClone[clone] else { return nil }
      let uniqueFiles = Dictionary(uniqueKeysWithValues: files.map { ($0.identity, $0) })
      let canonicalFiles = uniqueFiles.keys.sorted().compactMap { uniqueFiles[$0] }
      let owners = Array(Set(canonicalFiles.flatMap(\.owners))).sorted(by: ownerPrecedes)
      let cloneRefCount = consensus(
        canonicalFiles.map(\.cloneRefCount), collector: "release-clone-refcount")
      let fileClosures = allTrue(
        canonicalFiles.flatMap { [$0.ownerClosure, $0.topologyCompleteness] })
      let cloneOwnerClosure: RuntimeReleaseTopologyObservation<Bool>
      if case .known(let refCount) = cloneRefCount,
        UInt64(refCount) != UInt64(canonicalFiles.count)
      {
        cloneOwnerClosure = .known(false)
        issues.append(
          .cloneOwnerCountMismatch(
            clone, observed: UInt32(canonicalFiles.count), refCount: refCount))
      } else if case .known = cloneRefCount {
        cloneOwnerClosure = allTrue([fileClosures, collectionAdmission])
      } else {
        cloneOwnerClosure = cloneRefCount.map { _ in true }.asBooleanFailure()
      }

      let sharesAllBlocks = allTrue(canonicalFiles.map(\.sharesAllBlocks))
      if sharesAllBlocks == .known(false) { issues.append(.partialClone(clone)) }
      let exactSharedBytes = consensus(
        canonicalFiles.map(\.exactSharedBytes), collector: "release-shared-bytes")
      if exactSharedBytes.knownValue == nil { issues.append(.sharedBytesUnavailable(clone)) }
      let snapshotBlocker =
        snapshotBlockersByDevice[clone.device]
        ?? .unknown(.notObserved)
      if snapshotBlocker == .known(true) { issues.append(.snapshotBlocked(clone)) }

      let credit: UInt64?
      if cloneOwnerClosure == .known(true), sharesAllBlocks == .known(true),
        snapshotBlocker == .known(false), let exact = exactSharedBytes.knownValue
      {
        credit = exact.bytes
      } else {
        credit = nil
      }
      return RuntimeReleaseCloneGroupTopology(
        identity: clone,
        ownerFileObjects: canonicalFiles.map(\.identity),
        owners: owners,
        cloneRefCount: cloneRefCount,
        ownerClosure: cloneOwnerClosure,
        sharesAllBlocks: sharesAllBlocks,
        snapshotBlocker: snapshotBlocker,
        exactSharedBytes: exactSharedBytes,
        conditionalSharedReclaimCredit: credit
      )
    }
  }

  fileprivate func makeComponents(
    _ groups: [RuntimeReleaseCloneGroupTopology]
  ) -> [RuntimeReleaseTopologyComponent] {
    guard !groups.isEmpty else { return [] }
    var union = ReleaseTopologyUnionFind(count: groups.count)
    var firstGroupByOwnerCandidate: [Data: Int] = [:]
    for (index, group) in groups.enumerated() {
      for candidateID in Set(group.owners.map { Data($0.candidateID.utf8) }) {
        if let first = firstGroupByOwnerCandidate[candidateID] {
          union.join(first, index)
        } else {
          firstGroupByOwnerCandidate[candidateID] = index
        }
      }
    }
    var indicesByRoot: [Int: [Int]] = [:]
    for index in groups.indices {
      indicesByRoot[union.root(of: index), default: []].append(index)
    }
    return indicesByRoot.values.map { indices in
      let componentGroups = indices.map { groups[$0] }.sorted { $0.identity < $1.identity }
      let observedOwners = Array(Set(componentGroups.flatMap(\.owners))).sorted(
        by: ownerPrecedes)
      let candidateIDsByBytes = Dictionary(
        componentGroups.flatMap(\.owners).map { (Data($0.candidateID.utf8), $0.candidateID) },
        uniquingKeysWith: { first, _ in first }
      )
      return RuntimeReleaseTopologyComponent(
        cloneGroups: componentGroups.map(\.identity),
        ownerFileObjects: Array(Set(componentGroups.flatMap(\.ownerFileObjects))).sorted(),
        observedOwnerLinks: observedOwners,
        ownerCandidateIDsAtMostOnce: candidateIDsByBytes.keys.sorted(by: {
          $0.lexicographicallyPrecedes($1)
        }).compactMap { candidateIDsByBytes[$0] },
        isExecutable: componentGroups.allSatisfy(\.isReleaseComplete)
      )
    }.sorted { lhs, rhs in
      guard let left = lhs.cloneGroups.first, let right = rhs.cloneGroups.first else {
        return lhs.cloneGroups.count < rhs.cloneGroups.count
      }
      return left < right
    }
  }

  fileprivate func collectionState(
    scopeCoverage: RuntimeReleaseTopologyObservation<Bool>,
    files: [RuntimeReleaseFileObjectTopology],
    groups: [RuntimeReleaseCloneGroupTopology],
    issues: [RuntimeReleaseTopologyIssue]
  ) -> RuntimeReleaseTopologyObservation<Bool> {
    let fileClosure = allTrue(files.flatMap { [$0.ownerClosure, $0.topologyCompleteness] })
    let groupClosure = allTrue(
      groups.map { group in
        if group.isReleaseComplete { return .known(true) }
        if group.ownerClosure == .known(false) || group.sharesAllBlocks == .known(false)
          || group.snapshotBlocker == .known(true)
        {
          return .known(false)
        }
        return allTrue([
          group.ownerClosure,
          group.sharesAllBlocks,
          group.snapshotBlocker.map { !$0 },
          group.exactSharedBytes.map { _ in true },
        ])
      })
    let state = allTrue([scopeCoverage, fileClosure, groupClosure])
    if !issues.isEmpty, state == .known(true) {
      return .unknown(.incompleteCoverage)
    }
    return state
  }
}

private struct ReleaseTopologyUnionFind {
  private var parents: [Int]
  private var ranks: [UInt8]

  init(count: Int) {
    parents = Array(0..<count)
    ranks = Array(repeating: 0, count: count)
  }

  mutating func root(of index: Int) -> Int {
    var node = index
    while parents[node] != node { node = parents[node] }
    let root = node
    node = index
    while parents[node] != node {
      let next = parents[node]
      parents[node] = root
      node = next
    }
    return root
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

private func boundOwnerPrecedes(
  _ lhs: BoundRuntimeReleaseOwnerDescriptor,
  _ rhs: BoundRuntimeReleaseOwnerDescriptor
) -> Bool {
  if lhs.owner != rhs.owner { return ownerPrecedes(lhs.owner, rhs.owner) }
  if lhs.expectedIdentity != rhs.expectedIdentity {
    return lhs.expectedIdentity < rhs.expectedIdentity
  }
  return lhs.fileDescriptor < rhs.fileDescriptor
}

private func ownerPrecedes(_ lhs: FileOwnerLink, _ rhs: FileOwnerLink) -> Bool {
  let leftID = Data(lhs.candidateID.utf8)
  let rightID = Data(rhs.candidateID.utf8)
  if leftID != rightID { return leftID.lexicographicallyPrecedes(rightID) }
  return lhs.path < rhs.path
}

private func consensus<Value: Equatable & Sendable>(
  _ observations: [RuntimeReleaseTopologyObservation<Value>],
  collector: String
) -> RuntimeReleaseTopologyObservation<Value> {
  guard let first = observations.first else { return .absent }
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

private func cloneTopologyCompleteness(
  fileIdentity: RuntimeReleaseFileObjectIdentity,
  association: RuntimeReleaseTopologyObservation<RuntimeReleaseCloneAssociation>,
  refCount: RuntimeReleaseTopologyObservation<UInt32>,
  sharesAllBlocks: RuntimeReleaseTopologyObservation<Bool>,
  exactSharedBytes: RuntimeReleaseTopologyObservation<RuntimeReleaseExactSharedBytes>
) -> RuntimeReleaseTopologyObservation<Bool> {
  switch association {
  case .known(.notCloned):
    guard refCount == .absent, sharesAllBlocks == .absent, exactSharedBytes == .absent else {
      return .known(false)
    }
    return .known(true)
  case .known(.clone(let clone)):
    guard clone.device == fileIdentity.device else { return .known(false) }
    return allTrue([
      refCount.map { $0 > 0 },
      sharesAllBlocks.map { _ in true },
    ])
  case .absent:
    return .unknown(.notObserved)
  case .unknown(let reason):
    return .unknown(reason)
  case .unreadable(let failure):
    return .unreadable(failure)
  case .failed(let failure):
    return .failed(failure)
  }
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

  fileprivate var isFailure: Bool { isFailed || isUnreadable }

  fileprivate func asBooleanFailure() -> RuntimeReleaseTopologyObservation<Bool> {
    switch self {
    case .absent: .unknown(.notObserved)
    case .known: .known(true)
    case .unknown(let reason): .unknown(reason)
    case .unreadable(let failure): .unreadable(failure)
    case .failed(let failure): .failed(failure)
    }
  }
}
