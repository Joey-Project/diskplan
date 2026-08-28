import Foundation

public struct RawPathComponent: Equatable, Hashable, Sendable, Comparable {
  public let bytes: Data

  public init(_ bytes: Data) {
    precondition(
      !bytes.isEmpty && !bytes.contains(0) && bytes != Data(".".utf8) && bytes != Data("..".utf8))
    self.bytes = bytes
  }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    lhs.bytes.lexicographicallyPrecedes(rhs.bytes)
  }

  public var displayName: String {
    String(data: bytes, encoding: .utf8) ?? bytes.map { String(format: "\\x%02x", $0) }.joined()
  }
}

public struct RawPath: Equatable, Hashable, Sendable, Comparable {
  public let rootID: String
  public let components: [RawPathComponent]

  public init(rootID: String, components: [RawPathComponent] = []) {
    self.rootID = rootID
    self.components = components
  }

  public func appending(_ component: RawPathComponent) -> Self {
    Self(rootID: rootID, components: components + [component])
  }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    if lhs.rootID != rhs.rootID { return lhs.rootID < rhs.rootID }
    return lhs.components.lexicographicallyPrecedes(rhs.components)
  }
}

public struct ObjectIdentity: Equatable, Hashable, Sendable {
  public let device: Int64
  public let fileID: UInt64
  public let objectType: ScannedObjectType

  public init(device: Int64, fileID: UInt64, objectType: ScannedObjectType) {
    self.device = device
    self.fileID = fileID
    self.objectType = objectType
  }
}

public struct CanonicalFilesystemTime: Equatable, Sendable {
  public let secondsSinceEpoch: Int64
  public let nanoseconds: Int32

  public init(secondsSinceEpoch: Int64, nanoseconds: Int32) {
    precondition((0..<1_000_000_000).contains(nanoseconds))
    self.secondsSinceEpoch = secondsSinceEpoch
    self.nanoseconds = nanoseconds
  }
}

public enum FilesystemTimeTrust: String, Equatable, Sendable {
  case advisoryMetadata = "advisory_metadata"
}

public struct FilesystemTimeEvidence: Equatable, Sendable {
  public let accessTime: Observation<CanonicalFilesystemTime>
  public let modificationTime: Observation<CanonicalFilesystemTime>
  public let statusChangeTime: Observation<CanonicalFilesystemTime>
  public let birthTime: Observation<CanonicalFilesystemTime>
  public let trust: FilesystemTimeTrust

  public init(
    accessTime: Observation<CanonicalFilesystemTime>,
    modificationTime: Observation<CanonicalFilesystemTime>,
    statusChangeTime: Observation<CanonicalFilesystemTime>,
    birthTime: Observation<CanonicalFilesystemTime>,
    trust: FilesystemTimeTrust = .advisoryMetadata
  ) {
    self.accessTime = accessTime
    self.modificationTime = modificationTime
    self.statusChangeTime = statusChangeTime
    self.birthTime = birthTime
    self.trust = trust
  }

  public static let unknown = Self(
    accessTime: .unknown(reason: "not observed"),
    modificationTime: .unknown(reason: "not observed"),
    statusChangeTime: .unknown(reason: "not observed"),
    birthTime: .unknown(reason: "not observed")
  )
}

public struct AccessPolicyEvidence: Equatable, Sendable {
  public let ownerUserID: UInt32
  public let ownerGroupID: UInt32
  public let mode: UInt32
  public let flags: UInt32

  public init(ownerUserID: UInt32, ownerGroupID: UInt32, mode: UInt32, flags: UInt32) {
    self.ownerUserID = ownerUserID
    self.ownerGroupID = ownerGroupID
    self.mode = mode
    self.flags = flags
  }
}

public enum ScannedObjectType: String, Equatable, Hashable, Sendable {
  case regular
  case directory
  case symbolicLink
  case other
}

public enum Observation<Value: Equatable & Sendable>: Equatable, Sendable {
  case known(Value)
  case absent(reason: String)
  case unknown(reason: String)
  case unreadable(reason: String, errorCode: Int32?)
  case failed(reason: String, errorCode: Int32?)

  public var value: Value? {
    if case .known(let value) = self { return value }
    return nil
  }

  func erasingValue<NewValue: Equatable & Sendable>() -> Observation<NewValue> {
    switch self {
    case .known: .unknown(reason: "observation value erased")
    case .absent(let reason): .absent(reason: reason)
    case .unknown(let reason): .unknown(reason: reason)
    case .unreadable(let reason, let code): .unreadable(reason: reason, errorCode: code)
    case .failed(let reason, let code): .failed(reason: reason, errorCode: code)
    }
  }
}

public enum ByteMeasure: Equatable, Sendable {
  case exact(UInt64)
  case lowerBound(UInt64, unknownReason: String)
  case unknown(reason: String)

  public var conservativeLowerBound: UInt64 {
    switch self {
    case .exact(let value), .lowerBound(let value, _): value
    case .unknown: 0
    }
  }

  static func adding(_ lhs: Self, _ rhs: Self) -> Self {
    let (sum, overflow) = lhs.conservativeLowerBound.addingReportingOverflow(
      rhs.conservativeLowerBound)
    let value = overflow ? UInt64.max : sum
    switch (lhs, rhs) {
    case (.exact, .exact) where !overflow: return .exact(value)
    default:
      return .lowerBound(
        value, unknownReason: "one or more descendants have incomplete byte evidence")
    }
  }
}

public enum CoverageCompleteness: Int, Equatable, Sendable {
  case complete
  case partial
}

public enum CoverageReason: String, CaseIterable, Equatable, Hashable, Sendable, Comparable {
  case budgetExhausted = "budget_exhausted"
  case accessPolicyChanged = "access_policy_changed"
  case cancelled
  case collectorFailed = "collector_failed"
  case identityMismatch = "identity_mismatch"
  case missing
  case mountBoundary = "mount_boundary"
  case notRequestedByProfile = "not_requested_by_profile"
  case permissionDenied = "permission_denied"
  case providerMetadataOnly = "provider_metadata_only"
  case providerStateUnverified = "provider_state_unverified"
  case subtreeIncomplete = "subtree_incomplete"
  case timedOut = "timed_out"
  case unreadable
  case unstableDuringScan = "unstable_during_scan"
  case userFinalizedPartial = "user_finalized_partial"

  public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
}

public struct Coverage: Equatable, Sendable {
  public let completeness: CoverageCompleteness
  public let reasons: [CoverageReason]

  public init(completeness: CoverageCompleteness, reasons: some Sequence<CoverageReason> = []) {
    let canonical = Array(Set(reasons)).sorted()
    self.completeness = canonical.isEmpty ? completeness : .partial
    self.reasons = canonical
  }

  public static let complete = Self(completeness: .complete)

  public func merging(_ other: Self) -> Self {
    Self(
      completeness: completeness == .complete && other.completeness == .complete
        ? .complete : .partial,
      reasons: reasons + other.reasons
    )
  }
}

public enum ProviderBoundary: Equatable, Sendable {
  case localOrUnindicated
  case metadataOnly(reason: String)
  case rejected(reason: String)
  case unverified(reason: String)

  public var preventsNormalDescent: Bool {
    switch self {
    case .rejected, .unverified: true
    case .localOrUnindicated, .metadataOnly: false
    }
  }

  public var isProviderManaged: Bool {
    switch self {
    case .metadataOnly, .rejected: true
    case .localOrUnindicated, .unverified: false
    }
  }
}

public struct ProviderObjectIdentity: Equatable, Sendable {
  public let itemIdentifier: String
  public let domainIdentifier: String

  public init(itemIdentifier: String, domainIdentifier: String) {
    self.itemIdentifier = itemIdentifier
    self.domainIdentifier = domainIdentifier
  }
}

public struct ProviderScanEvidence: Equatable, Sendable {
  public let identity: Observation<ProviderObjectIdentity>
  public let promisedMetadata: Observation<[String: String]>
  public let hiddenBackingBytes: ByteMeasure
  public let controlledNonMaterializationAcceptance: Observation<Bool>

  public init(
    identity: Observation<ProviderObjectIdentity>,
    promisedMetadata: Observation<[String: String]>,
    hiddenBackingBytes: ByteMeasure,
    controlledNonMaterializationAcceptance: Observation<Bool>
  ) {
    self.identity = identity
    self.promisedMetadata = promisedMetadata
    self.hiddenBackingBytes = hiddenBackingBytes
    self.controlledNonMaterializationAcceptance = controlledNonMaterializationAcceptance
  }
}

public struct ItemByteEvidence: Equatable, Sendable {
  public let logical: ByteMeasure
  public let nominalAllocated: ByteMeasure
  public let immediatePrivateReclaim: ByteMeasure

  public init(
    logical: ByteMeasure, nominalAllocated: ByteMeasure, immediatePrivateReclaim: ByteMeasure
  ) {
    self.logical = logical
    self.nominalAllocated = nominalAllocated
    self.immediatePrivateReclaim = immediatePrivateReclaim
  }

  public static let unknown = Self(
    logical: .unknown(reason: "not observed"),
    nominalAllocated: .unknown(reason: "not observed"),
    immediatePrivateReclaim: .unknown(reason: "not observed")
  )

  static let lowerBoundZero = Self(
    logical: .lowerBound(0, unknownReason: "directory root metadata was not measured"),
    nominalAllocated: .lowerBound(0, unknownReason: "directory root metadata was not measured"),
    immediatePrivateReclaim: .lowerBound(
      0, unknownReason: "directory root metadata was not measured")
  )

  static func adding(_ lhs: Self, _ rhs: Self) -> Self {
    Self(
      logical: .adding(lhs.logical, rhs.logical),
      nominalAllocated: .adding(lhs.nominalAllocated, rhs.nominalAllocated),
      immediatePrivateReclaim: .adding(lhs.immediatePrivateReclaim, rhs.immediatePrivateReclaim)
    )
  }
}

public struct StorageTopologyEvidence: Equatable, Sendable {
  public let linkCount: Observation<UInt32>
  public let mayShareBlocks: Observation<Bool>
  public let sharesAllBlocks: Observation<Bool>
  public let cloneID: Observation<UInt64>
  public let cloneRefcount: Observation<UInt32>
  public let conditionalGroupReclaim: ByteMeasure

  public init(
    linkCount: Observation<UInt32>,
    mayShareBlocks: Observation<Bool>,
    sharesAllBlocks: Observation<Bool>,
    cloneID: Observation<UInt64>,
    cloneRefcount: Observation<UInt32>,
    conditionalGroupReclaim: ByteMeasure
  ) {
    self.linkCount = linkCount
    self.mayShareBlocks = mayShareBlocks
    self.sharesAllBlocks = sharesAllBlocks
    self.cloneID = cloneID
    self.cloneRefcount = cloneRefcount
    self.conditionalGroupReclaim = conditionalGroupReclaim
  }

  public static let unknown = Self(
    linkCount: .unknown(reason: "not observed"),
    mayShareBlocks: .unknown(reason: "not observed"),
    sharesAllBlocks: .unknown(reason: "not observed"),
    cloneID: .unknown(reason: "not observed"),
    cloneRefcount: .unknown(reason: "not observed"),
    conditionalGroupReclaim: .unknown(reason: "release-set ownership is not proven")
  )
}

public struct ScannedNode: Equatable, Sendable {
  public let path: RawPath
  public let identity: Observation<ObjectIdentity>
  public let bytes: ItemByteEvidence
  public let storageTopology: StorageTopologyEvidence
  public let filesystemTimes: FilesystemTimeEvidence
  public let accessPolicy: Observation<AccessPolicyEvidence>
  public let coverage: Coverage
  public let providerBoundary: ProviderBoundary
  public let providerEvidence: Observation<ProviderScanEvidence>

  public init(
    path: RawPath,
    identity: Observation<ObjectIdentity>,
    bytes: ItemByteEvidence,
    storageTopology: StorageTopologyEvidence = .unknown,
    filesystemTimes: FilesystemTimeEvidence = .unknown,
    accessPolicy: Observation<AccessPolicyEvidence> = .unknown(reason: "not observed"),
    coverage: Coverage,
    providerBoundary: ProviderBoundary,
    providerEvidence: Observation<ProviderScanEvidence> = .unknown(reason: "not observed")
  ) {
    self.path = path
    self.identity = identity
    self.bytes = bytes
    self.storageTopology = storageTopology
    self.filesystemTimes = filesystemTimes
    self.accessPolicy = accessPolicy
    self.coverage = coverage
    self.providerBoundary = providerBoundary
    self.providerEvidence = providerEvidence
  }
}

public enum ScanNodeEvent: Equatable, Sendable {
  case observed(ScannedNode)
  case directoryClosed(ScannedNode)
}

public protocol ScanNodeSink: Sendable {
  func receive(_ event: ScanNodeEvent)
}

public struct DiscardingScanNodeSink: ScanNodeSink {
  public init() {}
  public func receive(_ event: ScanNodeEvent) {}
}

public struct RootBinding: Equatable, Sendable {
  public let resolverVersion: UInt32
  public let rootID: String
  public let rawAbsolutePath: Data
  public let identity: ObjectIdentity

  public init(
    resolverVersion: UInt32, rootID: String, rawAbsolutePath: Data, identity: ObjectIdentity
  ) {
    self.resolverVersion = resolverVersion
    self.rootID = rootID
    self.rawAbsolutePath = rawAbsolutePath
    self.identity = identity
  }
}

public struct RootScanResult: Equatable, Sendable {
  public let binding: RootBinding
  public let providerBoundary: ProviderBoundary
  public let aggregateBytes: ItemByteEvidence
  public let coverage: Coverage
  public let entriesObserved: UInt64
  public let directoriesClosed: UInt64

  public init(
    binding: RootBinding,
    providerBoundary: ProviderBoundary,
    aggregateBytes: ItemByteEvidence,
    coverage: Coverage,
    entriesObserved: UInt64,
    directoriesClosed: UInt64
  ) {
    self.binding = binding
    self.providerBoundary = providerBoundary
    self.aggregateBytes = aggregateBytes
    self.coverage = coverage
    self.entriesObserved = entriesObserved
    self.directoriesClosed = directoriesClosed
  }
}

public struct ScanProgress: Equatable, Sendable {
  public let entriesObserved: UInt64
  public let directoriesClosed: UInt64
  public let rootsComplete: UInt64
  public let rootsPartial: UInt64
  public let retainedNodes: [ScannedNode]
}

public struct ScanCollectorConfiguration: Equatable, Sendable {
  public let processActivityCollectorID: String
  public let processActivityDeadlineNanoseconds: UInt64?
  public let globalFactCollectorIDs: [String]

  public init(
    processActivityCollectorID: String,
    processActivityDeadlineNanoseconds: UInt64?,
    globalFactCollectorIDs: [String]
  ) {
    self.processActivityCollectorID = processActivityCollectorID
    self.processActivityDeadlineNanoseconds = processActivityDeadlineNanoseconds
    self.globalFactCollectorIDs = Array(Set(globalFactCollectorIDs)).sorted()
  }

  public static let precollectedOrUnavailable = Self(
    processActivityCollectorID: "precollected-or-unavailable",
    processActivityDeadlineNanoseconds: nil,
    globalFactCollectorIDs: ["public-evidence-unavailable"]
  )
}

public struct ScanReference: Equatable, Sendable {
  public let wallClock: Date
  public let monotonicNanoseconds: UInt64
  public let resolvedScope: ResolvedScanScope
  public let collectorConfiguration: ScanCollectorConfiguration

  public var profileID: String { resolvedScope.profile.rawValue }
  public var resolverVersion: UInt32 { resolvedScope.resolverVersion }

  public init(
    wallClock: Date,
    monotonicNanoseconds: UInt64,
    resolvedScope: ResolvedScanScope,
    collectorConfiguration: ScanCollectorConfiguration
  ) {
    self.wallClock = wallClock
    self.monotonicNanoseconds = monotonicNanoseconds
    self.resolvedScope = resolvedScope
    self.collectorConfiguration = collectorConfiguration
  }
}

public enum GlobalFact<Value: Equatable & Sendable>: Equatable, Sendable {
  case known(Value)
  case unavailable(reason: String)
}

public struct GlobalScanFacts: Equatable, Sendable {
  public let vm: GlobalFact<[String: UInt64]>
  public let swap: GlobalFact<[String: UInt64]>
  public let apfsSnapshots: GlobalFact<[String]>

  public static let publicEvidenceUnavailable = Self(
    vm: .unavailable(reason: "not requested by this scanner slice"),
    swap: .unavailable(reason: "not requested by this scanner slice"),
    apfsSnapshots: .unavailable(reason: "public snapshot attribution evidence is unavailable")
  )
}
