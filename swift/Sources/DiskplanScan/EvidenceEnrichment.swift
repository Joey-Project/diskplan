import CryptoKit
import Darwin
import DiskplanMacOS
import Foundation

public struct EvidenceDigest: Equatable, Hashable, Sendable, Comparable {
  public let bytes: Data

  public init(bytes: Data) throws {
    guard bytes.count == SHA256.byteCount else { throw EvidenceEnrichmentError.invalidDigest }
    self.bytes = bytes
  }

  init(unchecked bytes: Data) { self.bytes = bytes }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    lhs.bytes.lexicographicallyPrecedes(rhs.bytes)
  }
}

public enum EvidenceEnrichmentError: Error, Equatable {
  case invalidDigest
  case invalidBudget
}

public struct AncestorAccessPolicySeal: Equatable, Sendable {
  public let rootIdentity: ObjectIdentity
  public let depth: UInt32
  public let digest: EvidenceDigest
  public let pendingCloseEpochIDs: [EvidenceDigest]

  init(
    rootIdentity: ObjectIdentity,
    depth: UInt32,
    digest: EvidenceDigest,
    pendingCloseEpochIDs: [EvidenceDigest]
  ) {
    self.rootIdentity = rootIdentity
    self.depth = depth
    self.digest = digest
    self.pendingCloseEpochIDs = pendingCloseEpochIDs.sorted()
  }

  public var isFinalized: Bool { pendingCloseEpochIDs.isEmpty }
}

public struct DirectoryCloseEpochReceipt: Equatable, Sendable {
  public let epochID: EvidenceDigest
  public let result: Observation<Bool>
}

public final class AccessPolicyEpochLedger: AccessPolicyEpochSink, @unchecked Sendable {
  private let lock = NSLock()
  private var receipts: [EvidenceDigest: Observation<Bool>] = [:]

  public init() {}

  public func receive(_ receipt: DirectoryCloseEpochReceipt) {
    lock.withLock {
      if let existing = receipts[receipt.epochID], existing != receipt.result {
        receipts[receipt.epochID] = .failed(
          reason: "conflicting directory close epoch receipts", errorCode: EPROTO)
      } else {
        receipts[receipt.epochID] = receipt.result
      }
    }
  }

  public func finalize(
    _ observation: Observation<AncestorAccessPolicySeal>
  ) -> Observation<AncestorAccessPolicySeal> {
    guard case .known(let seal) = observation else { return observation }
    guard !seal.pendingCloseEpochIDs.isEmpty else { return observation }
    return lock.withLock {
      for epochID in seal.pendingCloseEpochIDs {
        guard let receipt = receipts[epochID] else {
          return .unknown(reason: "directory close epoch receipt is pending")
        }
        guard receipt == .known(true) else { return receipt.erasingValue() }
      }
      return .known(
        AncestorAccessPolicySeal(
          rootIdentity: seal.rootIdentity,
          depth: seal.depth,
          digest: seal.digest,
          pendingCloseEpochIDs: []
        ))
    }
  }
}

public struct ContentDigestBaseline: Equatable, Sendable {
  public let algorithm: String
  public let logicalBytes: UInt64
  public let digest: EvidenceDigest

  public init(logicalBytes: UInt64, digest: EvidenceDigest) {
    algorithm = "sha256"
    self.logicalBytes = logicalBytes
    self.digest = digest
  }
}

public enum ContentNotCollectedReason: String, Equatable, Sendable {
  case notRegularFile = "not_regular_file"
  case planContractDoesNotRequireContent = "plan_contract_does_not_require_content"
  case providerManaged = "provider_managed"
  case providerStateUnverified = "provider_state_unverified"
}

public enum ContentEvidence: Equatable, Sendable {
  case notRequested
  case notApplicable(ContentNotCollectedReason)
  case collected(ContentDigestBaseline)
  case unavailable(reason: String, errorCode: Int32?)
}

public struct ContentCollectionBudget: Equatable, Sendable {
  public let maximumBytesPerFile: UInt64
  public let maximumAggregateBytes: UInt64
  public let maximumFiles: UInt32
  public let deadlineMonotonicNanoseconds: UInt64

  public init(
    maximumBytesPerFile: UInt64,
    maximumAggregateBytes: UInt64,
    maximumFiles: UInt32,
    deadlineMonotonicNanoseconds: UInt64
  ) throws {
    guard maximumBytesPerFile > 0, maximumAggregateBytes >= maximumBytesPerFile,
      maximumFiles > 0
    else { throw EvidenceEnrichmentError.invalidBudget }
    self.maximumBytesPerFile = maximumBytesPerFile
    self.maximumAggregateBytes = maximumAggregateBytes
    self.maximumFiles = maximumFiles
    self.deadlineMonotonicNanoseconds = deadlineMonotonicNanoseconds
  }

  public static func standard(deadlineMonotonicNanoseconds: UInt64) -> Self {
    try! Self(
      maximumBytesPerFile: 64 * 1024 * 1024,
      maximumAggregateBytes: 256 * 1024 * 1024,
      maximumFiles: 64,
      deadlineMonotonicNanoseconds: deadlineMonotonicNanoseconds
    )
  }
}

public struct ContentCollectionRequestID: Equatable, Hashable, Sendable {
  public let rawValue: EvidenceDigest
}

final class OwnedFileDescriptor: @unchecked Sendable {
  private let lock = NSLock()
  private var stored: Int32?

  init(transferring fileDescriptor: Int32) {
    precondition(fileDescriptor >= 0)
    stored = fileDescriptor
  }

  deinit { close() }

  func take() -> Int32? {
    lock.withLock {
      defer { stored = nil }
      return stored
    }
  }

  func close() {
    let fileDescriptor = lock.withLock { () -> Int32? in
      defer { stored = nil }
      return stored
    }
    if let fileDescriptor { Darwin.close(fileDescriptor) }
  }
}

struct TrustedBoundContentReceipt: @unchecked Sendable {
  let requestID: ContentCollectionRequestID
  let target: RawPath
  let ownedDescriptor: OwnedFileDescriptor
  let rootIdentity: ObjectIdentity
  let expectedIdentity: ObjectIdentity
  let expectedAccessPolicy: AccessPolicyEvidence
  let rootIdentityObservation: @Sendable () -> Observation<ObjectIdentity>
  let slotPathObservation: @Sendable () -> Observation<RawPath>
  let slotIdentityObservation: @Sendable () -> Observation<ObjectIdentity>
  let providerObservation: @Sendable () -> Observation<ProviderBoundary>

  init(
    requestID: ContentCollectionRequestID,
    target: RawPath,
    ownedDescriptor: OwnedFileDescriptor,
    rootIdentity: ObjectIdentity,
    expectedIdentity: ObjectIdentity,
    expectedAccessPolicy: AccessPolicyEvidence,
    rootIdentityObservation: @escaping @Sendable () -> Observation<ObjectIdentity>,
    slotPathObservation: @escaping @Sendable () -> Observation<RawPath>,
    slotIdentityObservation: @escaping @Sendable () -> Observation<ObjectIdentity>,
    providerObservation: @escaping @Sendable () -> Observation<ProviderBoundary>
  ) {
    self.requestID = requestID
    self.target = target
    self.ownedDescriptor = ownedDescriptor
    self.rootIdentity = rootIdentity
    self.expectedIdentity = expectedIdentity
    self.expectedAccessPolicy = expectedAccessPolicy
    self.rootIdentityObservation = rootIdentityObservation
    self.slotPathObservation = slotPathObservation
    self.slotIdentityObservation = slotIdentityObservation
    self.providerObservation = providerObservation
  }
}

final class TrustedContentReceiptRegistry: @unchecked Sendable {
  private let lock = NSLock()
  private var receipts: [ContentCollectionRequestID: TrustedBoundContentReceipt] = [:]
  private var descriptorOwners: Set<ObjectIdentifier> = []
  private var issuedRequestIDs: Set<ContentCollectionRequestID> = []

  func insert(_ receipt: TrustedBoundContentReceipt) -> Bool {
    lock.withLock {
      let descriptorOwner = ObjectIdentifier(receipt.ownedDescriptor)
      guard !issuedRequestIDs.contains(receipt.requestID),
        !descriptorOwners.contains(descriptorOwner)
      else { return false }
      receipts[receipt.requestID] = receipt
      descriptorOwners.insert(descriptorOwner)
      issuedRequestIDs.insert(receipt.requestID)
      return true
    }
  }

  func take(_ requestID: ContentCollectionRequestID) -> TrustedBoundContentReceipt? {
    lock.withLock {
      guard let receipt = receipts.removeValue(forKey: requestID) else { return nil }
      descriptorOwners.remove(ObjectIdentifier(receipt.ownedDescriptor))
      return receipt
    }
  }
}

public protocol ContentEvidenceCollecting: Sendable {
  func collect(_ requestID: ContentCollectionRequestID) -> ContentEvidence
}

final class ContentCollectionSessionBudget: @unchecked Sendable {
  private let configuration: ContentCollectionBudget
  private let monotonicNow: @Sendable () -> UInt64
  private let lock = NSLock()
  private var aggregateBytes: UInt64 = 0
  private var files: UInt32 = 0

  init(
    configuration: ContentCollectionBudget,
    monotonicNow: @escaping @Sendable () -> UInt64
  ) {
    self.configuration = configuration
    self.monotonicNow = monotonicNow
  }

  func reserve(logicalBytes: UInt64) -> ContentEvidence? {
    lock.withLock {
      guard monotonicNow() < configuration.deadlineMonotonicNanoseconds else {
        return .unavailable(reason: "content collection deadline exceeded", errorCode: ETIMEDOUT)
      }
      guard logicalBytes <= configuration.maximumBytesPerFile else {
        return .unavailable(
          reason: "content target exceeds per-file byte budget", errorCode: EFBIG)
      }
      guard files < configuration.maximumFiles else {
        return .unavailable(
          reason: "content collection file budget exhausted", errorCode: EFBIG)
      }
      let (next, overflow) = aggregateBytes.addingReportingOverflow(logicalBytes)
      guard !overflow, next <= configuration.maximumAggregateBytes else {
        return .unavailable(
          reason: "content collection aggregate byte budget exhausted", errorCode: EFBIG)
      }
      files += 1
      aggregateBytes = next
      return nil
    }
  }

  var deadlineMonotonicNanoseconds: UInt64 {
    configuration.deadlineMonotonicNanoseconds
  }
}

final class DarwinBoundedContentEvidenceCollector: ContentEvidenceCollecting,
  @unchecked Sendable
{
  typealias DescriptorReader = @Sendable (Int32, UnsafeMutableRawPointer?, Int, off_t) -> ssize_t

  private let policy: NoMaterializationPolicy
  private let registry: TrustedContentReceiptRegistry
  private let budget: ContentCollectionSessionBudget
  private let monotonicNow: @Sendable () -> UInt64
  private let descriptorReader: DescriptorReader

  init(
    policy: NoMaterializationPolicy,
    registry: TrustedContentReceiptRegistry,
    budget: ContentCollectionBudget
  ) {
    let now: @Sendable () -> UInt64 = { DispatchTime.now().uptimeNanoseconds }
    self.policy = policy
    self.registry = registry
    monotonicNow = now
    descriptorReader = Darwin.pread
    self.budget = ContentCollectionSessionBudget(
      configuration: budget,
      monotonicNow: now
    )
  }

  init(
    policy: NoMaterializationPolicy,
    registry: TrustedContentReceiptRegistry,
    budget: ContentCollectionBudget,
    monotonicNow: @escaping @Sendable () -> UInt64,
    descriptorReader: @escaping DescriptorReader = Darwin.pread
  ) {
    self.policy = policy
    self.registry = registry
    self.monotonicNow = monotonicNow
    self.descriptorReader = descriptorReader
    self.budget = ContentCollectionSessionBudget(
      configuration: budget,
      monotonicNow: monotonicNow
    )
  }

  func collect(_ requestID: ContentCollectionRequestID) -> ContentEvidence {
    guard let request = registry.take(requestID) else {
      return .unavailable(
        reason: "content collection request is unknown or consumed", errorCode: ENOENT)
    }
    guard let fileDescriptor = request.ownedDescriptor.take() else {
      return .unavailable(reason: "invalid held content descriptor", errorCode: EBADF)
    }
    defer { Darwin.close(fileDescriptor) }
    guard request.expectedIdentity.objectType == .regular else {
      return .notApplicable(.notRegularFile)
    }
    if let failure = validateTrustedReceipt(request, fileDescriptor: fileDescriptor) {
      return failure
    }
    guard
      let before = descriptorSeal(
        fileDescriptor: fileDescriptor,
        policy: policy
      )
    else {
      return .unavailable(reason: "content target seal unavailable", errorCode: errno)
    }
    guard before.identity == request.expectedIdentity else {
      return .unavailable(reason: "content target identity mismatch", errorCode: ESTALE)
    }
    guard before.accessPolicy == request.expectedAccessPolicy else {
      return .unavailable(reason: "content target access policy mismatch", errorCode: EAGAIN)
    }
    if let failure = budget.reserve(logicalBytes: before.logicalBytes) { return failure }
    var hasher = SHA256()
    var remaining = before.logicalBytes
    var offset: off_t = 0
    var buffer = [UInt8](repeating: 0, count: 64 * 1024)
    while remaining > 0 {
      if let failure = validateTrustedReceipt(request, fileDescriptor: fileDescriptor) {
        return failure
      }
      guard monotonicNow() < budget.deadlineMonotonicNanoseconds else {
        return .unavailable(reason: "content collection deadline exceeded", errorCode: ETIMEDOUT)
      }
      let count = min(UInt64(buffer.count), remaining)
      let readCount = buffer.withUnsafeMutableBytes { raw in
        descriptorReader(fileDescriptor, raw.baseAddress, Int(count), offset)
      }
      guard readCount > 0 else {
        let code = readCount == 0 ? EIO : errno
        return contentFailure(code, operation: "read descriptor-bound content target")
      }
      hasher.update(data: Data(buffer.prefix(readCount)))
      remaining -= UInt64(readCount)
      offset += off_t(readCount)
    }
    if let failure = validateTrustedReceipt(request, fileDescriptor: fileDescriptor) {
      return failure
    }
    var trailingByte: UInt8 = 0
    guard descriptorReader(fileDescriptor, &trailingByte, 1, offset) == 0 else {
      return .unavailable(reason: "content target grew during digest", errorCode: EBUSY)
    }
    guard
      let after = descriptorSeal(
        fileDescriptor: fileDescriptor,
        policy: policy
      )
    else {
      return .unavailable(reason: "content target postflight seal unavailable", errorCode: errno)
    }
    guard after.identity == before.identity else {
      return .unavailable(
        reason: "content target identity changed during digest", errorCode: ESTALE)
    }
    guard after.accessPolicy == before.accessPolicy else {
      return .unavailable(
        reason: "content target access policy changed during digest", errorCode: EAGAIN)
    }
    guard after.logicalBytes == before.logicalBytes else {
      return .unavailable(reason: "content target size changed during digest", errorCode: EBUSY)
    }
    guard sameTime(before.modificationTime, after.modificationTime),
      sameTime(before.statusChangeTime, after.statusChangeTime)
    else {
      return .unavailable(
        reason: "content metadata changed; a fresh digest pass is required", errorCode: EAGAIN)
    }
    if let failure = validateTrustedReceipt(request, fileDescriptor: fileDescriptor) {
      return failure
    }
    return .collected(
      ContentDigestBaseline(
        logicalBytes: before.logicalBytes,
        digest: EvidenceDigest(unchecked: Data(hasher.finalize()))
      ))
  }

  private func validateTrustedReceipt(
    _ request: TrustedBoundContentReceipt,
    fileDescriptor: Int32
  ) -> ContentEvidence? {
    guard policy.revalidateLive().value != nil else {
      return .unavailable(reason: "no-materialization policy unavailable", errorCode: nil)
    }
    guard request.rootIdentityObservation() == .known(request.rootIdentity),
      request.slotPathObservation() == .known(request.target),
      request.slotIdentityObservation() == .known(request.expectedIdentity)
    else {
      return .unavailable(reason: "bound content root or slot identity changed", errorCode: ESTALE)
    }
    guard
      let descriptor = descriptorSeal(
        fileDescriptor: fileDescriptor,
        policy: policy
      )
    else {
      return .unavailable(reason: "bound content descriptor seal unavailable", errorCode: errno)
    }
    guard descriptor.identity == request.expectedIdentity else {
      return .unavailable(reason: "bound content descriptor identity changed", errorCode: ESTALE)
    }
    guard descriptor.accessPolicy == request.expectedAccessPolicy else {
      return .unavailable(
        reason: "bound content descriptor access policy changed", errorCode: EAGAIN)
    }
    switch request.providerObservation() {
    case .known(.localOrUnindicated):
      return nil
    case .known(.metadataOnly), .known(.rejected):
      return .notApplicable(.providerManaged)
    case .known(.unverified), .absent, .unknown, .unreadable, .failed:
      return .notApplicable(.providerStateUnverified)
    }
  }
}

public enum GitWorktreeMarkerKind: String, Equatable, Sendable {
  case ordinaryDirectory = "ordinary_directory"
  case linkedGitdirFile = "linked_gitdir_file"
  case absent
}

public struct GitChangeSummary: Equatable, Sendable {
  public let staged: UInt64
  public let unstaged: UInt64
  public let unmerged: UInt64
  public let untracked: UInt64
  public let ignored: UInt64
  public let streamedChangeSetDigest: EvidenceDigest

  public init(
    staged: UInt64,
    unstaged: UInt64,
    unmerged: UInt64,
    untracked: UInt64,
    ignored: UInt64,
    streamedChangeSetDigest: EvidenceDigest
  ) {
    self.staged = staged
    self.unstaged = unstaged
    self.unmerged = unmerged
    self.untracked = untracked
    self.ignored = ignored
    self.streamedChangeSetDigest = streamedChangeSetDigest
  }
}

public struct GitRegistrationEvidence: Equatable, Sendable {
  public let worktreeIdentity: ObjectIdentity
  public let administrativeDirectoryIdentity: ObjectIdentity
  public let commonDirectoryIdentity: ObjectIdentity
  public let rawRegistrationBinding: Data
  public let registrationDigest: EvidenceDigest
  public let metadataDigest: EvidenceDigest

  public init(
    worktreeIdentity: ObjectIdentity,
    administrativeDirectoryIdentity: ObjectIdentity,
    commonDirectoryIdentity: ObjectIdentity,
    rawRegistrationBinding: Data,
    registrationDigest: EvidenceDigest,
    metadataDigest: EvidenceDigest
  ) {
    self.worktreeIdentity = worktreeIdentity
    self.administrativeDirectoryIdentity = administrativeDirectoryIdentity
    self.commonDirectoryIdentity = commonDirectoryIdentity
    self.rawRegistrationBinding = rawRegistrationBinding
    self.registrationDigest = registrationDigest
    self.metadataDigest = metadataDigest
  }
}

public struct GitHeldObjectSeal: Equatable, Sendable {
  public let identity: ObjectIdentity
  public let accessPolicy: AccessPolicyEvidence
  public let contentDigest: Observation<EvidenceDigest>

  public init(
    identity: ObjectIdentity,
    accessPolicy: AccessPolicyEvidence,
    contentDigest: Observation<EvidenceDigest>
  ) {
    self.identity = identity
    self.accessPolicy = accessPolicy
    self.contentDigest = contentDigest
  }
}

public struct GitMetadataSnapshot: Equatable, Sendable {
  public let worktreeRoot: GitHeldObjectSeal
  public let administrativeDirectory: GitHeldObjectSeal
  public let commonDirectory: GitHeldObjectSeal
  public let index: GitHeldObjectSeal
  public let head: GitHeldObjectSeal
  public let registration: GitHeldObjectSeal

  public init(
    worktreeRoot: GitHeldObjectSeal,
    administrativeDirectory: GitHeldObjectSeal,
    commonDirectory: GitHeldObjectSeal,
    index: GitHeldObjectSeal,
    head: GitHeldObjectSeal,
    registration: GitHeldObjectSeal
  ) {
    self.worktreeRoot = worktreeRoot
    self.administrativeDirectory = administrativeDirectory
    self.commonDirectory = commonDirectory
    self.index = index
    self.head = head
    self.registration = registration
  }
}

public enum GitFeatureState: Equatable, Sendable {
  case absent
  case present(digest: EvidenceDigest)
}

public struct GitWorktreeScanEvidence: Equatable, Sendable {
  public let marker: Observation<GitWorktreeMarkerKind>
  public let headIdentity: Observation<EvidenceDigest>
  public let indexDigest: Observation<EvidenceDigest>
  public let changes: Observation<GitChangeSummary>
  public let registration: Observation<GitRegistrationEvidence>
  public let nestedRepositories: Observation<GitFeatureState>
  public let submodules: Observation<GitFeatureState>
  public let sparseCheckout: Observation<GitFeatureState>
  public let commandCoverage: Coverage
}

public struct GitEvidenceBudget: Equatable, Sendable {
  public let maximumTargets: UInt32
  public let maximumOutputBytesPerTarget: UInt64
  public let maximumAggregateOutputBytes: UInt64
  public let maximumStatusRecordsPerTarget: UInt64
  public let maximumAggregateStatusRecords: UInt64
  public let deadlineMonotonicNanoseconds: UInt64

  public init(
    maximumTargets: UInt32 = 32,
    maximumOutputBytesPerTarget: UInt64 = 2 * 1024 * 1024,
    maximumAggregateOutputBytes: UInt64 = 16 * 1024 * 1024,
    maximumStatusRecordsPerTarget: UInt64 = 50_000,
    maximumAggregateStatusRecords: UInt64 = 200_000,
    deadlineMonotonicNanoseconds: UInt64
  ) throws {
    guard maximumTargets > 0, maximumOutputBytesPerTarget > 0,
      maximumAggregateOutputBytes >= maximumOutputBytesPerTarget,
      maximumStatusRecordsPerTarget > 0,
      maximumAggregateStatusRecords >= maximumStatusRecordsPerTarget
    else { throw EvidenceEnrichmentError.invalidBudget }
    self.maximumTargets = maximumTargets
    self.maximumOutputBytesPerTarget = maximumOutputBytesPerTarget
    self.maximumAggregateOutputBytes = maximumAggregateOutputBytes
    self.maximumStatusRecordsPerTarget = maximumStatusRecordsPerTarget
    self.maximumAggregateStatusRecords = maximumAggregateStatusRecords
    self.deadlineMonotonicNanoseconds = deadlineMonotonicNanoseconds
  }
}

public struct ConfiguredAdapterEvidenceBudget: Equatable, Sendable {
  public let maximumScopes: UInt32
  public let maximumEntriesPerScope: UInt32
  public let maximumMetadataBytesPerEntry: UInt64
  public let maximumAggregateMetadataBytes: UInt64
  public let deadlineMonotonicNanoseconds: UInt64

  public init(
    maximumScopes: UInt32 = 256,
    maximumEntriesPerScope: UInt32 = 4_096,
    maximumMetadataBytesPerEntry: UInt64 = 1024 * 1024,
    maximumAggregateMetadataBytes: UInt64 = 32 * 1024 * 1024,
    deadlineMonotonicNanoseconds: UInt64
  ) throws {
    guard maximumScopes > 0, maximumEntriesPerScope > 0,
      maximumMetadataBytesPerEntry > 0,
      maximumAggregateMetadataBytes >= maximumMetadataBytesPerEntry
    else { throw EvidenceEnrichmentError.invalidBudget }
    self.maximumScopes = maximumScopes
    self.maximumEntriesPerScope = maximumEntriesPerScope
    self.maximumMetadataBytesPerEntry = maximumMetadataBytesPerEntry
    self.maximumAggregateMetadataBytes = maximumAggregateMetadataBytes
    self.deadlineMonotonicNanoseconds = deadlineMonotonicNanoseconds
  }
}

enum ReadOnlyGitCommandKind: String, CaseIterable, Equatable, Hashable, Sendable {
  case status
  case head
  case index
}

struct ReadOnlyGitCommandSpec: Equatable, Sendable {
  static let executablePath = "/usr/bin/git"

  let kind: ReadOnlyGitCommandKind
  let arguments: [String]
  let replacementEnvironment: [String: String]
  let digest: EvidenceDigest

  static func spec(for kind: ReadOnlyGitCommandKind) -> Self {
    let commandArguments: [String]
    switch kind {
    case .status:
      commandArguments = [
        "status", "--porcelain=v2", "-z", "--ignored=matching", "--untracked-files=all",
      ]
    case .head:
      commandArguments = ["rev-parse", "--verify", "HEAD"]
    case .index:
      commandArguments = ["ls-files", "--stage", "-z"]
    }
    let arguments =
      [
        "--no-optional-locks",
        "-c", "core.fsmonitor=false",
        "-c", "credential.helper=",
        "-c", "core.hooksPath=/dev/null",
        "-c", "maintenance.auto=false",
        "-c", "gc.auto=0",
        "-c", "fetch.writeCommitGraph=false",
      ] + commandArguments
    let replacementEnvironment = [
      "GCM_INTERACTIVE": "Never",
      "GIT_CONFIG_GLOBAL": "/dev/null",
      "GIT_CONFIG_NOSYSTEM": "1",
      "GIT_CONFIG_SYSTEM": "/dev/null",
      "GIT_LFS_SKIP_SMUDGE": "1",
      "GIT_NO_LAZY_FETCH": "1",
      "GIT_OPTIONAL_LOCKS": "0",
      "GIT_TERMINAL_PROMPT": "0",
      "LANG": "C",
      "LC_ALL": "C",
      "PATH": "/usr/bin:/bin",
    ]
    return Self(
      kind: kind,
      arguments: arguments,
      replacementEnvironment: replacementEnvironment,
      digest: gitCommandSpecDigest(
        kind: kind,
        arguments: arguments,
        replacementEnvironment: replacementEnvironment
      )
    )
  }
}

final class GitEvidenceSessionBudget: @unchecked Sendable {
  struct TargetReservation: Equatable, Hashable, Sendable {
    let rawValue: UInt64
  }

  private let configuration: GitEvidenceBudget
  private let monotonicNow: @Sendable () -> UInt64
  private let lock = NSLock()
  private var reservedTargets: UInt32 = 0
  private var nextReservationID: UInt64 = 0
  private var perTargetUsage: [TargetReservation: (bytes: UInt64, records: UInt64)] = [:]
  private var aggregateOutputBytes: UInt64 = 0
  private var aggregateStatusRecords: UInt64 = 0

  init(
    configuration: GitEvidenceBudget,
    monotonicNow: @escaping @Sendable () -> UInt64
  ) {
    self.configuration = configuration
    self.monotonicNow = monotonicNow
  }

  func reserveTarget() -> Observation<TargetReservation> {
    lock.withLock {
      guard monotonicNow() < configuration.deadlineMonotonicNanoseconds else {
        return .failed(reason: "Git global deadline exhausted", errorCode: ETIMEDOUT)
      }
      guard reservedTargets < configuration.maximumTargets else {
        return .failed(reason: "Git target budget exhausted", errorCode: EFBIG)
      }
      let (nextID, overflow) = nextReservationID.addingReportingOverflow(1)
      guard !overflow else {
        return .failed(reason: "Git target reservation ID exhausted", errorCode: EOVERFLOW)
      }
      nextReservationID = nextID
      reservedTargets += 1
      let reservation = TargetReservation(rawValue: nextID)
      perTargetUsage[reservation] = (bytes: 0, records: 0)
      return .known(reservation)
    }
  }

  func reserveOutput(
    for reservation: TargetReservation,
    bytes: UInt64,
    statusRecords: UInt64
  ) -> Observation<Bool> {
    lock.withLock {
      guard monotonicNow() < configuration.deadlineMonotonicNanoseconds else {
        return .failed(reason: "Git global deadline exhausted", errorCode: ETIMEDOUT)
      }
      guard let targetUsage = perTargetUsage[reservation] else {
        return .failed(reason: "Git target reservation is unknown", errorCode: EINVAL)
      }
      let (nextTargetBytes, targetBytesOverflow) =
        targetUsage.bytes.addingReportingOverflow(bytes)
      let (nextTargetRecords, targetRecordsOverflow) =
        targetUsage.records.addingReportingOverflow(statusRecords)
      guard !targetBytesOverflow, !targetRecordsOverflow,
        nextTargetBytes <= configuration.maximumOutputBytesPerTarget,
        nextTargetRecords <= configuration.maximumStatusRecordsPerTarget
      else {
        return .failed(reason: "Git per-target budget exhausted", errorCode: EFBIG)
      }
      let (nextBytes, bytesOverflow) = aggregateOutputBytes.addingReportingOverflow(bytes)
      let (nextRecords, recordsOverflow) =
        aggregateStatusRecords.addingReportingOverflow(statusRecords)
      guard !bytesOverflow, !recordsOverflow,
        nextBytes <= configuration.maximumAggregateOutputBytes,
        nextRecords <= configuration.maximumAggregateStatusRecords
      else {
        return .failed(reason: "Git aggregate budget exhausted", errorCode: EFBIG)
      }
      aggregateOutputBytes = nextBytes
      aggregateStatusRecords = nextRecords
      perTargetUsage[reservation] = (bytes: nextTargetBytes, records: nextTargetRecords)
      return .known(true)
    }
  }

  func finish(_ reservation: TargetReservation) {
    lock.withLock { perTargetUsage.removeValue(forKey: reservation) }
  }
}

enum GitPorcelainV2Parser {
  static func parse(
    _ bytes: Data,
    maximumRecords: UInt64,
    maximumBytes: UInt64
  ) -> Observation<GitChangeSummary> {
    guard UInt64(bytes.count) <= maximumBytes else {
      return .failed(reason: "Git status output byte budget exhausted", errorCode: EFBIG)
    }
    var staged: UInt64 = 0
    var unstaged: UInt64 = 0
    var unmerged: UInt64 = 0
    var untracked: UInt64 = 0
    var ignored: UInt64 = 0
    var records: UInt64 = 0
    var hasher = SHA256()
    var start = bytes.startIndex
    var expectsRenameSource = false
    while start < bytes.endIndex {
      guard let terminator = bytes[start...].firstIndex(of: 0) else {
        return .failed(reason: "Git status output lacks NUL framing", errorCode: EPROTO)
      }
      let record = bytes[start..<terminator]
      start = bytes.index(after: terminator)
      if record.isEmpty { continue }
      if expectsRenameSource {
        hasher.update(data: Data(record))
        hasher.update(data: Data([0]))
        expectsRenameSource = false
        continue
      }
      records += 1
      guard records <= maximumRecords else {
        return .failed(reason: "Git status record budget exhausted", errorCode: EFBIG)
      }
      hasher.update(data: Data(record))
      hasher.update(data: Data([0]))
      guard let prefix = record.first else { continue }
      switch prefix {
      case 49, 50:
        guard let xy = porcelainXY(record) else {
          return .failed(reason: "Git ordinary status record is malformed", errorCode: EPROTO)
        }
        if xy.0 != Character(".").asciiValue! { staged += 1 }
        if xy.1 != Character(".").asciiValue! { unstaged += 1 }
        expectsRenameSource = prefix == 50
      case 117:
        unmerged += 1
      case 63:
        untracked += 1
      case 33:
        ignored += 1
      case 35:
        break
      default:
        return .failed(reason: "Git status record type is unsupported", errorCode: EPROTO)
      }
    }
    guard !expectsRenameSource else {
      return .failed(reason: "Git rename record lacks source pathname", errorCode: EPROTO)
    }
    return .known(
      GitChangeSummary(
        staged: staged,
        unstaged: unstaged,
        unmerged: unmerged,
        untracked: untracked,
        ignored: ignored,
        streamedChangeSetDigest: EvidenceDigest(unchecked: Data(hasher.finalize()))
      ))
  }

  private static func porcelainXY(_ record: Data.SubSequence) -> (UInt8, UInt8)? {
    let bytes = Array(record.prefix(4))
    guard bytes.count == 4, bytes[1] == 32 else { return nil }
    return (bytes[2], bytes[3])
  }
}

enum GitMetadataCrossJoin {
  static let maximumRawRegistrationBindingBytes = 64 * 1024

  static func validate(
    registration: GitRegistrationEvidence,
    preflight: GitMetadataSnapshot,
    postflight: GitMetadataSnapshot
  ) -> Observation<Bool> {
    guard registration.rawRegistrationBinding.count <= maximumRawRegistrationBindingBytes else {
      return .failed(reason: "Git raw registration binding exceeds its byte cap", errorCode: EFBIG)
    }
    guard preflight == postflight else {
      return .failed(reason: "Git held metadata changed during collection", errorCode: EAGAIN)
    }
    let seals = [
      preflight.worktreeRoot,
      preflight.administrativeDirectory,
      preflight.commonDirectory,
      preflight.index,
      preflight.head,
      preflight.registration,
    ]
    guard seals.allSatisfy({ $0.contentDigest.value != nil }) else {
      return .unknown(reason: "Git critical held-object content digest is incomplete")
    }
    let rawRegistrationDigest = gitRawRegistrationBindingDigest(
      registration.rawRegistrationBinding)
    guard rawRegistrationDigest == registration.registrationDigest,
      preflight.registration.contentDigest == .known(rawRegistrationDigest)
    else {
      return .failed(
        reason: "Git registration digest does not match the held registration object",
        errorCode: EPROTO
      )
    }
    guard gitMetadataSnapshotDigest(preflight) == registration.metadataDigest else {
      return .failed(
        reason: "Git metadata digest does not match the held metadata bundle",
        errorCode: EPROTO
      )
    }
    guard preflight.worktreeRoot.identity == registration.worktreeIdentity,
      preflight.administrativeDirectory.identity == registration.administrativeDirectoryIdentity,
      preflight.commonDirectory.identity == registration.commonDirectoryIdentity
    else {
      return .failed(
        reason: "Git registration and held-object identities do not cross-join", errorCode: ESTALE)
    }
    guard preflight.administrativeDirectory.identity != preflight.commonDirectory.identity else {
      return .failed(
        reason: "linked Git administrative and common directories are not distinct",
        errorCode: EPROTO)
    }
    return .known(true)
  }
}

func gitRawRegistrationBindingDigest(_ rawBinding: Data) -> EvidenceDigest {
  var input = Data("diskplan/git-raw-registration-binding/v1\0".utf8)
  appendCanonical(rawBinding, to: &input)
  return EvidenceDigest(unchecked: Data(SHA256.hash(data: input)))
}

func gitMetadataSnapshotDigest(_ snapshot: GitMetadataSnapshot) -> EvidenceDigest? {
  let labeledSeals: [(String, GitHeldObjectSeal)] = [
    ("worktree-root", snapshot.worktreeRoot),
    ("administrative-directory", snapshot.administrativeDirectory),
    ("common-directory", snapshot.commonDirectory),
    ("index", snapshot.index),
    ("head", snapshot.head),
    ("registration", snapshot.registration),
  ]
  var input = Data("diskplan/git-held-metadata-bundle/v1\0".utf8)
  for (label, seal) in labeledSeals {
    guard let aclDigest = seal.accessPolicy.aclDigest.value,
      let contentDigest = seal.contentDigest.value
    else { return nil }
    appendCanonical(Data(label.utf8), to: &input)
    appendCanonical(seal.identity.device, to: &input)
    appendCanonical(seal.identity.fileID, to: &input)
    appendCanonical(Data(seal.identity.objectType.rawValue.utf8), to: &input)
    appendCanonical(seal.accessPolicy.ownerUserID, to: &input)
    appendCanonical(seal.accessPolicy.ownerGroupID, to: &input)
    appendCanonical(seal.accessPolicy.mode, to: &input)
    appendCanonical(seal.accessPolicy.flags, to: &input)
    appendCanonical(aclDigest.bytes, to: &input)
    appendCanonical(contentDigest.bytes, to: &input)
  }
  return EvidenceDigest(unchecked: Data(SHA256.hash(data: input)))
}

public enum GitWorktreeEvidenceCollector {
  /// No production subprocess supervisor is connected yet. A typed unavailable result is safer
  /// than accepting caller-assembled command output as authoritative evidence.
  public static func unavailable(
    marker: Observation<GitWorktreeMarkerKind> = .unknown(reason: "Git marker not collected")
  ) -> GitWorktreeScanEvidence {
    GitWorktreeScanEvidence(
      marker: marker,
      headIdentity: .unknown(reason: "supervised Git runner unavailable"),
      indexDigest: .unknown(reason: "supervised Git runner unavailable"),
      changes: .unknown(reason: "supervised Git runner unavailable"),
      registration: .unknown(reason: "supervised Git runner unavailable"),
      nestedRepositories: .unknown(reason: "supervised Git runner unavailable"),
      submodules: .unknown(reason: "supervised Git runner unavailable"),
      sparseCheckout: .unknown(reason: "supervised Git runner unavailable"),
      commandCoverage: Coverage(completeness: .partial, reasons: [.collectorFailed])
    )
  }
}

public enum AdapterProvenance: Equatable, Sendable {
  case configuredBoundScope(scopeID: String)
  case typeHintOnly(reason: String)
}

public struct CodexCleanupScopeEvidence: Equatable, Sendable {
  public let provenance: AdapterProvenance
  public let boundRootIdentity: Observation<ObjectIdentity>
  public let boundRootAccessPolicy: Observation<AccessPolicyEvidence>
  public let helperCapability: Observation<String>
  public let coverage: Coverage
}

public struct VersionedArtifactVersionEvidence: Equatable, Sendable {
  public let rawName: Data
  public let identity: Observation<ObjectIdentity>
  public let metadataDigest: Observation<EvidenceDigest>

  public init(
    rawName: Data,
    identity: Observation<ObjectIdentity>,
    metadataDigest: Observation<EvidenceDigest>
  ) {
    self.rawName = rawName
    self.identity = identity
    self.metadataDigest = metadataDigest
  }
}

public struct ActiveVersionSelectorEvidence: Equatable, Sendable {
  public let rawName: Data
  public let selectorIdentity: ObjectIdentity
  public let selectorAccessPolicy: AccessPolicyEvidence
  public let namespaceIdentity: ObjectIdentity
  public let namespaceAccessPolicy: AccessPolicyEvidence
  public let rawTarget: Data
}

public struct VersionedArtifactScanEvidence: Equatable, Sendable {
  public let provenance: AdapterProvenance
  public let installRootIdentity: Observation<ObjectIdentity>
  public let activeSelector: Observation<ActiveVersionSelectorEvidence>
  public let versions: [VersionedArtifactVersionEvidence]
  public let survivorRawNames: Observation<[Data]>
  public let currentUpdateMarker: Observation<Bool>
  public let coverage: Coverage
}

enum ConfiguredAdapterScopeKind: String, Equatable, Sendable {
  case codexCleanup
  case versionedArtifact
}

struct ConfiguredAdapterScopeDefinition: Equatable, Sendable {
  let scopeID: String
  let kind: ConfiguredAdapterScopeKind
  let rootPath: RawPath
  let helperCapability: String
  let selectorRawName: Data?
}

struct TrustedConfiguredScopeBinding: Equatable, Sendable {
  let rootPath: RawPath
  let rootIdentity: ObjectIdentity
  let rootAccessPolicy: AccessPolicyEvidence
  let selectorNamespaceIdentity: ObjectIdentity?
  let selectorNamespaceAccessPolicy: AccessPolicyEvidence?
  let selectorRawName: Data?
}

final class ConfiguredAdapterScopeToken: Equatable, @unchecked Sendable {
  let tokenDigest: EvidenceDigest
  let scopeID: String
  let kind: ConfiguredAdapterScopeKind
  let rootPath: RawPath
  let rootIdentity: ObjectIdentity
  let rootAccessPolicy: AccessPolicyEvidence
  let helperCapability: String
  let selectorNamespaceIdentity: ObjectIdentity?
  let selectorNamespaceAccessPolicy: AccessPolicyEvidence?
  let selectorRawName: Data?

  fileprivate init(
    definition: ConfiguredAdapterScopeDefinition,
    binding: TrustedConfiguredScopeBinding,
    tokenDigest: EvidenceDigest
  ) {
    self.tokenDigest = tokenDigest
    scopeID = definition.scopeID
    kind = definition.kind
    rootPath = definition.rootPath
    rootIdentity = binding.rootIdentity
    rootAccessPolicy = binding.rootAccessPolicy
    helperCapability = definition.helperCapability
    selectorNamespaceIdentity = binding.selectorNamespaceIdentity
    selectorNamespaceAccessPolicy = binding.selectorNamespaceAccessPolicy
    selectorRawName = definition.selectorRawName
  }

  static func == (lhs: ConfiguredAdapterScopeToken, rhs: ConfiguredAdapterScopeToken) -> Bool {
    lhs.tokenDigest == rhs.tokenDigest
  }
}

final class ConfiguredAdapterScopeRegistry: @unchecked Sendable {
  func bind(
    definition: ConfiguredAdapterScopeDefinition,
    trustedBinding: TrustedConfiguredScopeBinding
  ) -> Observation<ConfiguredAdapterScopeToken> {
    guard !definition.scopeID.isEmpty, !definition.helperCapability.isEmpty else {
      return .failed(reason: "configured adapter scope is invalid", errorCode: EINVAL)
    }
    guard definition.rootPath == trustedBinding.rootPath else {
      return .failed(
        reason: "configured adapter raw root does not match bound root", errorCode: ESTALE)
    }
    guard trustedBinding.rootIdentity.objectType == .directory else {
      return .failed(reason: "configured adapter root is not a directory", errorCode: ENOTDIR)
    }
    guard trustedBinding.rootAccessPolicy.aclDigest.value != nil else {
      return .unknown(reason: "configured adapter root ACL is incomplete")
    }
    switch definition.kind {
    case .codexCleanup:
      guard definition.selectorRawName == nil,
        trustedBinding.selectorRawName == nil,
        trustedBinding.selectorNamespaceIdentity == nil,
        trustedBinding.selectorNamespaceAccessPolicy == nil
      else {
        return .failed(
          reason: "Codex cleanup scope has unexpected selector namespace", errorCode: EINVAL)
      }
    case .versionedArtifact:
      guard let selectorRawName = definition.selectorRawName,
        validRawLeaf(selectorRawName),
        trustedBinding.selectorRawName == selectorRawName,
        trustedBinding.selectorNamespaceIdentity?.objectType == .directory,
        trustedBinding.selectorNamespaceAccessPolicy?.aclDigest.value != nil
      else {
        return .failed(
          reason: "versioned scope selector namespace is incomplete", errorCode: EINVAL)
      }
    }
    return .known(
      ConfiguredAdapterScopeToken(
        definition: definition,
        binding: trustedBinding,
        tokenDigest: configuredScopeTokenDigest(definition: definition, binding: trustedBinding)
      ))
  }
}

final class ConfiguredAdapterEvidenceSessionBudget: @unchecked Sendable {
  private let configuration: ConfiguredAdapterEvidenceBudget
  private let monotonicNow: @Sendable () -> UInt64
  private let lock = NSLock()
  private var scopes: UInt32 = 0
  private var aggregateEntries: UInt64 = 0
  private var aggregateBytes: UInt64 = 0

  init(
    configuration: ConfiguredAdapterEvidenceBudget,
    monotonicNow: @escaping @Sendable () -> UInt64
  ) {
    self.configuration = configuration
    self.monotonicNow = monotonicNow
  }

  func permitsInspection(entryCount: Int) -> Observation<Bool> {
    guard entryCount >= 0,
      UInt64(entryCount) <= UInt64(configuration.maximumEntriesPerScope)
    else {
      return .failed(reason: "configured adapter entry budget exhausted", errorCode: EFBIG)
    }
    guard monotonicNow() < configuration.deadlineMonotonicNanoseconds else {
      return .failed(reason: "configured adapter deadline exhausted", errorCode: ETIMEDOUT)
    }
    return .known(true)
  }

  func reserve(
    entryCount: Int,
    retainedBytes: UInt64,
    maximumEntryBytes: UInt64
  ) -> Observation<Bool> {
    lock.withLock {
      guard monotonicNow() < configuration.deadlineMonotonicNanoseconds else {
        return .failed(reason: "configured adapter deadline exhausted", errorCode: ETIMEDOUT)
      }
      guard entryCount >= 0,
        UInt64(entryCount) <= UInt64(configuration.maximumEntriesPerScope)
      else {
        return .failed(reason: "configured adapter entry budget exhausted", errorCode: EFBIG)
      }
      guard maximumEntryBytes <= configuration.maximumMetadataBytesPerEntry else {
        return .failed(
          reason: "configured adapter per-entry byte budget exhausted", errorCode: EFBIG)
      }
      guard scopes < configuration.maximumScopes else {
        return .failed(reason: "configured adapter scope budget exhausted", errorCode: EFBIG)
      }
      let (nextEntries, entriesOverflow) =
        aggregateEntries.addingReportingOverflow(UInt64(entryCount))
      let (nextBytes, bytesOverflow) = aggregateBytes.addingReportingOverflow(retainedBytes)
      guard !entriesOverflow, !bytesOverflow,
        nextBytes <= configuration.maximumAggregateMetadataBytes
      else {
        return .failed(reason: "configured adapter aggregate budget exhausted", errorCode: EFBIG)
      }
      scopes += 1
      aggregateEntries = nextEntries
      aggregateBytes = nextBytes
      return .known(true)
    }
  }
}

enum AdapterEvidenceBuilder {
  static func typeHintCodexCleanupScope(
    boundRootIdentity: Observation<ObjectIdentity>
  ) -> CodexCleanupScopeEvidence {
    CodexCleanupScopeEvidence(
      provenance: .typeHintOnly(reason: "path name matched without configured cleanup scope"),
      boundRootIdentity: boundRootIdentity,
      boundRootAccessPolicy: .unknown(reason: "type hint cannot bind root access policy"),
      helperCapability: .unknown(reason: "type hint cannot establish helper capability"),
      coverage: Coverage(completeness: .partial, reasons: [.collectorFailed])
    )
  }

  static func codexCleanupScope(
    token: ConfiguredAdapterScopeToken,
    budget: ConfiguredAdapterEvidenceSessionBudget,
    boundRootPath: Observation<RawPath>,
    boundRootIdentity: Observation<ObjectIdentity>,
    boundRootAccessPolicy: Observation<AccessPolicyEvidence>,
    helperCapability: Observation<String>,
    coverage: Coverage
  ) -> CodexCleanupScopeEvidence {
    let retainedBytes = checkedRetainedBytes(
      rawLength: token.scopeID.utf8.count,
      overhead: 64
    ).flatMap { scopeBytes in
      checkedRetainedBytes(
        rawLength: token.helperCapability.utf8.count,
        overhead: scopeBytes
      )
    }
    let budgetAccepted =
      retainedBytes.flatMap { bytes in
        budget.reserve(entryCount: 1, retainedBytes: bytes, maximumEntryBytes: bytes).value
      } != nil
    let exactBinding =
      budgetAccepted && token.kind == .codexCleanup
      && boundRootPath == .known(token.rootPath)
      && boundRootIdentity == .known(token.rootIdentity)
      && boundRootAccessPolicy == .known(token.rootAccessPolicy)
      && helperCapability == .known(token.helperCapability)
    return CodexCleanupScopeEvidence(
      provenance: exactBinding
        ? .configuredBoundScope(scopeID: token.scopeID)
        : .typeHintOnly(reason: "configured Codex scope binding did not revalidate"),
      boundRootIdentity: boundRootIdentity,
      boundRootAccessPolicy: boundRootAccessPolicy,
      helperCapability: helperCapability,
      coverage: exactBinding && coverage.completeness == .complete
        ? .complete
        : Coverage(completeness: .partial, reasons: coverage.reasons + [.collectorFailed])
    )
  }

  static func typeHintVersionedArtifact(
    installRootIdentity: Observation<ObjectIdentity>
  ) -> VersionedArtifactScanEvidence {
    VersionedArtifactScanEvidence(
      provenance: .typeHintOnly(reason: "version-like names lack configured adapter scope"),
      installRootIdentity: installRootIdentity,
      activeSelector: .unknown(reason: "type hint cannot bind active selector"),
      versions: [],
      survivorRawNames: .unknown(reason: "type hint cannot select authoritative survivors"),
      currentUpdateMarker: .unknown(reason: "type hint cannot establish update state"),
      coverage: Coverage(completeness: .partial, reasons: [.collectorFailed])
    )
  }

  static func versionedArtifact(
    token: ConfiguredAdapterScopeToken,
    budget: ConfiguredAdapterEvidenceSessionBudget,
    installRootPath: Observation<RawPath>,
    installRootIdentity: Observation<ObjectIdentity>,
    installRootAccessPolicy: Observation<AccessPolicyEvidence>,
    helperCapability: Observation<String>,
    activeSelector: Observation<ActiveVersionSelectorEvidence>,
    versions: [VersionedArtifactVersionEvidence],
    currentUpdateMarker: Observation<Bool>,
    coverage: Coverage
  ) -> VersionedArtifactScanEvidence {
    let bindingKnown =
      token.kind == .versionedArtifact
      && installRootPath == .known(token.rootPath)
      && token.rootIdentity.objectType == .directory
      && installRootIdentity == .known(token.rootIdentity)
      && installRootAccessPolicy == .known(token.rootAccessPolicy)
      && helperCapability == .known(token.helperCapability)
    let selectorEntryCount = activeSelector.value == nil ? 0 : 1
    let (versionsAndScope, countOverflow) = versions.count.addingReportingOverflow(1)
    let (entryCount, selectorCountOverflow) =
      versionsAndScope.addingReportingOverflow(selectorEntryCount)
    guard !countOverflow, !selectorCountOverflow,
      budget.permitsInspection(entryCount: entryCount).value != nil
    else {
      return incompleteVersionedArtifact(
        token: token,
        bindingKnown: bindingKnown,
        installRootIdentity: installRootIdentity,
        currentUpdateMarker: currentUpdateMarker,
        coverage: coverage,
        reason: "version entry count or deadline budget exhausted"
      )
    }
    guard
      let scopeIDBytes = checkedRetainedBytes(
        rawLength: token.scopeID.utf8.count,
        overhead: 0
      ),
      let helperBytes = checkedRetainedBytes(
        rawLength: token.helperCapability.utf8.count,
        overhead: 64
      ), let scopeBytes = checkedAdd(scopeIDBytes, helperBytes)
    else {
      return incompleteVersionedArtifact(
        token: token,
        bindingKnown: bindingKnown,
        installRootIdentity: installRootIdentity,
        currentUpdateMarker: currentUpdateMarker,
        coverage: coverage,
        reason: "configured scope retained-byte accounting overflow"
      )
    }
    var retainedBytes = scopeBytes
    var maximumEntryBytes = scopeBytes
    if case .known(let selector) = activeSelector {
      guard
        let selectorBytes = checkedRetainedBytes(rawLength: selector.rawName.count, overhead: 64),
        let targetBytes = checkedRetainedBytes(rawLength: selector.rawTarget.count, overhead: 64),
        let combinedSelectorBytes = checkedAdd(selectorBytes, targetBytes),
        let nextRetainedBytes = checkedAdd(retainedBytes, combinedSelectorBytes)
      else {
        return incompleteVersionedArtifact(
          token: token,
          bindingKnown: bindingKnown,
          installRootIdentity: installRootIdentity,
          currentUpdateMarker: currentUpdateMarker,
          coverage: coverage,
          reason: "selector retained-byte accounting overflow"
        )
      }
      retainedBytes = nextRetainedBytes
      maximumEntryBytes = max(maximumEntryBytes, combinedSelectorBytes)
    }
    for version in versions {
      guard
        let entryBytes = checkedRetainedBytes(
          rawLength: version.rawName.count,
          overhead: UInt64(SHA256.byteCount) + 17
        ), let nextRetainedBytes = checkedAdd(retainedBytes, entryBytes)
      else {
        return incompleteVersionedArtifact(
          token: token,
          bindingKnown: bindingKnown,
          installRootIdentity: installRootIdentity,
          currentUpdateMarker: currentUpdateMarker,
          coverage: coverage,
          reason: "version retained-byte accounting overflow"
        )
      }
      retainedBytes = nextRetainedBytes
      maximumEntryBytes = max(maximumEntryBytes, entryBytes)
    }
    guard
      budget.reserve(
        entryCount: entryCount,
        retainedBytes: retainedBytes,
        maximumEntryBytes: maximumEntryBytes
      ).value != nil
    else {
      return incompleteVersionedArtifact(
        token: token,
        bindingKnown: bindingKnown,
        installRootIdentity: installRootIdentity,
        currentUpdateMarker: currentUpdateMarker,
        coverage: coverage,
        reason: "version retained-byte or session budget exhausted"
      )
    }
    let canonical = canonicalVersions(versions)
    let selectorKnown: Bool
    if case .known(let selector) = activeSelector {
      selectorKnown =
        selector.selectorIdentity.objectType == .symbolicLink
        && token.selectorRawName == selector.rawName
        && validLeaf(selector.rawName)
        && selector.selectorAccessPolicy.aclDigest.value != nil
        && token.selectorNamespaceIdentity == selector.namespaceIdentity
        && token.selectorNamespaceAccessPolicy == selector.namespaceAccessPolicy
        && validLeaf(selector.rawTarget)
    } else {
      selectorKnown = false
    }
    let duplicateFree = Set(canonical.map(\.rawName)).count == canonical.count
    let manifestsKnown =
      duplicateFree
      && canonical.allSatisfy({ validLeaf($0.rawName) })
      && canonical.allSatisfy({
        $0.identity.value?.objectType == .directory && $0.metadataDigest.value != nil
      })
    let survivorRawNames: Observation<[Data]>
    if bindingKnown, selectorKnown,
      case .known(let selector) = activeSelector,
      currentUpdateMarker == .known(false), manifestsKnown,
      canonical.contains(where: { $0.rawName == selector.rawTarget })
    {
      survivorRawNames = .known([selector.rawTarget])
    } else {
      survivorRawNames = .unknown(
        reason: "selector, manifest, update, binding, or budget evidence is incomplete")
    }
    let complete = survivorRawNames.value != nil && coverage.completeness == .complete
    return VersionedArtifactScanEvidence(
      provenance: bindingKnown
        ? .configuredBoundScope(scopeID: token.scopeID)
        : .typeHintOnly(reason: "configured versioned scope binding did not revalidate"),
      installRootIdentity: installRootIdentity,
      activeSelector: activeSelector,
      versions: canonical,
      survivorRawNames: survivorRawNames,
      currentUpdateMarker: currentUpdateMarker,
      coverage: complete
        ? .complete
        : Coverage(completeness: .partial, reasons: coverage.reasons + [.collectorFailed])
    )
  }

  private static func canonicalVersions(
    _ versions: [VersionedArtifactVersionEvidence]
  ) -> [VersionedArtifactVersionEvidence] {
    versions.sorted { $0.rawName.lexicographicallyPrecedes($1.rawName) }
  }

  private static func incompleteVersionedArtifact(
    token: ConfiguredAdapterScopeToken,
    bindingKnown: Bool,
    installRootIdentity: Observation<ObjectIdentity>,
    currentUpdateMarker: Observation<Bool>,
    coverage: Coverage,
    reason: String
  ) -> VersionedArtifactScanEvidence {
    VersionedArtifactScanEvidence(
      provenance: bindingKnown
        ? .configuredBoundScope(scopeID: token.scopeID)
        : .typeHintOnly(reason: "configured versioned scope binding did not revalidate"),
      installRootIdentity: installRootIdentity,
      activeSelector: .unknown(reason: reason),
      versions: [],
      survivorRawNames: .unknown(reason: reason),
      currentUpdateMarker: currentUpdateMarker,
      coverage: Coverage(completeness: .partial, reasons: coverage.reasons + [.budgetExhausted])
    )
  }

  private static func checkedRetainedBytes(
    rawLength: Int,
    overhead: UInt64
  ) -> UInt64? {
    guard let rawBytes = UInt64(exactly: rawLength) else { return nil }
    return checkedAdd(rawBytes, overhead)
  }

  private static func checkedAdd(_ lhs: UInt64, _ rhs: UInt64) -> UInt64? {
    let (sum, overflow) = lhs.addingReportingOverflow(rhs)
    return overflow ? nil : sum
  }

  private static func validLeaf(_ raw: Data) -> Bool {
    validRawLeaf(raw)
  }
}

private func gitCommandSpecDigest(
  kind: ReadOnlyGitCommandKind,
  arguments: [String],
  replacementEnvironment: [String: String]
) -> EvidenceDigest {
  var input = Data("diskplan/git-read-command-spec/v1\0".utf8)
  appendCanonical(Data(ReadOnlyGitCommandSpec.executablePath.utf8), to: &input)
  appendCanonical(Data(kind.rawValue.utf8), to: &input)
  for argument in arguments { appendCanonical(Data(argument.utf8), to: &input) }
  for key in replacementEnvironment.keys.sorted() {
    appendCanonical(Data(key.utf8), to: &input)
    appendCanonical(Data(replacementEnvironment[key]!.utf8), to: &input)
  }
  return EvidenceDigest(unchecked: Data(SHA256.hash(data: input)))
}

private func configuredScopeTokenDigest(
  definition: ConfiguredAdapterScopeDefinition,
  binding: TrustedConfiguredScopeBinding
) -> EvidenceDigest {
  var input = Data("diskplan/configured-adapter-scope/v1\0".utf8)
  appendCanonical(Data(definition.scopeID.utf8), to: &input)
  appendCanonical(Data(definition.kind.rawValue.utf8), to: &input)
  appendCanonical(Data(definition.rootPath.rootID.utf8), to: &input)
  for component in definition.rootPath.components {
    appendCanonical(component.bytes, to: &input)
  }
  appendCanonical(binding.rootIdentity.device, to: &input)
  appendCanonical(binding.rootIdentity.fileID, to: &input)
  appendCanonical(Data(binding.rootIdentity.objectType.rawValue.utf8), to: &input)
  appendCanonical(binding.rootAccessPolicy.ownerUserID, to: &input)
  appendCanonical(binding.rootAccessPolicy.ownerGroupID, to: &input)
  appendCanonical(binding.rootAccessPolicy.mode, to: &input)
  appendCanonical(binding.rootAccessPolicy.flags, to: &input)
  if let aclDigest = binding.rootAccessPolicy.aclDigest.value {
    appendCanonical(aclDigest.bytes, to: &input)
  }
  appendCanonical(Data(definition.helperCapability.utf8), to: &input)
  appendCanonical(Data("configured-selector".utf8), to: &input)
  appendCanonical(definition.selectorRawName ?? Data(), to: &input)
  appendCanonical(Data("bound-selector".utf8), to: &input)
  appendCanonical(binding.selectorRawName ?? Data(), to: &input)
  if let selectorNamespaceIdentity = binding.selectorNamespaceIdentity {
    appendCanonical(selectorNamespaceIdentity.device, to: &input)
    appendCanonical(selectorNamespaceIdentity.fileID, to: &input)
    appendCanonical(Data(selectorNamespaceIdentity.objectType.rawValue.utf8), to: &input)
  }
  if let selectorNamespaceAccessPolicy = binding.selectorNamespaceAccessPolicy {
    appendCanonical(selectorNamespaceAccessPolicy.ownerUserID, to: &input)
    appendCanonical(selectorNamespaceAccessPolicy.ownerGroupID, to: &input)
    appendCanonical(selectorNamespaceAccessPolicy.mode, to: &input)
    appendCanonical(selectorNamespaceAccessPolicy.flags, to: &input)
    if let aclDigest = selectorNamespaceAccessPolicy.aclDigest.value {
      appendCanonical(aclDigest.bytes, to: &input)
    }
  }
  return EvidenceDigest(unchecked: Data(SHA256.hash(data: input)))
}

private func saturatingAdd(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
  let (sum, overflow) = lhs.addingReportingOverflow(rhs)
  return overflow ? UInt64.max : sum
}

private func validRawLeaf(_ raw: Data) -> Bool {
  !raw.isEmpty && !raw.contains(0) && !raw.contains(47)
    && raw != Data(".".utf8) && raw != Data("..".utf8)
}

struct DescriptorContentSeal {
  let identity: ObjectIdentity
  let accessPolicy: AccessPolicyEvidence
  let logicalBytes: UInt64
  let modificationTime: timespec
  let statusChangeTime: timespec
}

private func sameTime(_ lhs: timespec, _ rhs: timespec) -> Bool {
  lhs.tv_sec == rhs.tv_sec && lhs.tv_nsec == rhs.tv_nsec
}

func descriptorSeal(
  fileDescriptor: Int32,
  policy: NoMaterializationPolicy
) -> DescriptorContentSeal? {
  guard
    let rawIdentity = FileDescriptorIdentityProbe().probe(
      fileDescriptor: fileDescriptor,
      policy: policy
    ).value
  else { return nil }
  var status = stat()
  guard fstat(fileDescriptor, &status) == 0 else { return nil }
  let type: ScannedObjectType
  switch rawIdentity.objectType {
  case .regular: type = .regular
  case .directory: type = .directory
  case .symbolicLink: type = .symbolicLink
  case .other: type = .other
  }
  return DescriptorContentSeal(
    identity: ObjectIdentity(
      device: rawIdentity.device, fileID: rawIdentity.fileID, objectType: type),
    accessPolicy: AccessPolicyEvidence(
      ownerUserID: status.st_uid,
      ownerGroupID: status.st_gid,
      mode: UInt32(status.st_mode),
      flags: darwinAccessControlFlags(status.st_flags),
      aclDigest: descriptorACLDigest(fileDescriptor)
    ),
    logicalBytes: UInt64(max(0, status.st_size)),
    modificationTime: status.st_mtimespec,
    statusChangeTime: status.st_ctimespec
  )
}

func darwinAccessControlFlags(_ rawFlags: UInt32) -> UInt32 {
  let mask =
    UInt32(UF_IMMUTABLE) | UInt32(UF_APPEND) | UInt32(UF_DATAVAULT)
    | UInt32(SF_IMMUTABLE) | UInt32(SF_APPEND) | UInt32(SF_RESTRICTED)
    | UInt32(SF_NOUNLINK)
  return rawFlags & mask
}

func descriptorACLDigest(_ fileDescriptor: Int32) -> Observation<EvidenceDigest> {
  errno = 0
  guard let acl = acl_get_fd_np(fileDescriptor, ACL_TYPE_EXTENDED) else {
    let code = errno
    if code == ENOENT {
      return .known(EvidenceDigest(unchecked: Data(SHA256.hash(data: Data()))))
    }
    if code == EACCES || code == EPERM {
      return .unreadable(reason: "descriptor ACL unreadable", errorCode: code)
    }
    return .failed(reason: "descriptor ACL unavailable", errorCode: code)
  }
  defer { acl_free(UnsafeMutableRawPointer(acl)) }
  let byteCount = acl_size(acl)
  guard byteCount >= 0 else {
    return .failed(reason: "descriptor ACL size unavailable", errorCode: errno)
  }
  var bytes = Data(count: Int(byteCount))
  let copied = bytes.withUnsafeMutableBytes { raw in
    acl_copy_ext(raw.baseAddress, acl, byteCount)
  }
  guard copied == byteCount else {
    return .failed(reason: "descriptor ACL serialization failed", errorCode: errno)
  }
  return .known(EvidenceDigest(unchecked: Data(SHA256.hash(data: bytes))))
}

func appendAncestorAccessPolicySeal(
  parent: Observation<AncestorAccessPolicySeal>?,
  rootIdentity: ObjectIdentity,
  identity: ObjectIdentity,
  accessPolicy: Observation<AccessPolicyEvidence>,
  pendingCloseEpochID: EvidenceDigest?
) -> Observation<AncestorAccessPolicySeal> {
  guard case .known(let policy) = accessPolicy else {
    return accessPolicy.erasingValue()
  }
  guard case .known(let aclDigest) = policy.aclDigest else {
    return policy.aclDigest.erasingValue()
  }
  let priorDigest: Data
  let depth: UInt32
  var pendingCloseEpochIDs: [EvidenceDigest]
  if let parent {
    guard case .known(let parentSeal) = parent else { return parent.erasingValue() }
    guard parentSeal.rootIdentity == rootIdentity else {
      return .failed(reason: "ancestor seal root identity mismatch", errorCode: ESTALE)
    }
    priorDigest = parentSeal.digest.bytes
    pendingCloseEpochIDs = parentSeal.pendingCloseEpochIDs
    let (nextDepth, overflow) = parentSeal.depth.addingReportingOverflow(1)
    guard !overflow else {
      return .failed(reason: "ancestor seal depth overflow", errorCode: EOVERFLOW)
    }
    depth = nextDepth
  } else {
    priorDigest = Data()
    depth = 0
    pendingCloseEpochIDs = []
  }
  if let pendingCloseEpochID { pendingCloseEpochIDs.append(pendingCloseEpochID) }
  var input = Data("diskplan/ancestor-access-policy/v1\0".utf8)
  appendCanonical(priorDigest, to: &input)
  appendCanonical(identity.device, to: &input)
  appendCanonical(identity.fileID, to: &input)
  appendCanonical(Data(identity.objectType.rawValue.utf8), to: &input)
  appendCanonical(policy.ownerUserID, to: &input)
  appendCanonical(policy.ownerGroupID, to: &input)
  appendCanonical(policy.mode, to: &input)
  appendCanonical(policy.flags, to: &input)
  appendCanonical(aclDigest.bytes, to: &input)
  return .known(
    AncestorAccessPolicySeal(
      rootIdentity: rootIdentity,
      depth: depth,
      digest: EvidenceDigest(unchecked: Data(SHA256.hash(data: input))),
      pendingCloseEpochIDs: pendingCloseEpochIDs
    ))
}

func directoryCloseEpochID(
  rootIdentity: ObjectIdentity,
  path: RawPath,
  identity: ObjectIdentity
) -> EvidenceDigest {
  var input = Data("diskplan/directory-close-epoch/v1\0".utf8)
  appendCanonical(rootIdentity.device, to: &input)
  appendCanonical(rootIdentity.fileID, to: &input)
  appendCanonical(Data(rootIdentity.objectType.rawValue.utf8), to: &input)
  appendCanonical(Data(path.rootID.utf8), to: &input)
  for component in path.components { appendCanonical(component.bytes, to: &input) }
  appendCanonical(identity.device, to: &input)
  appendCanonical(identity.fileID, to: &input)
  appendCanonical(Data(identity.objectType.rawValue.utf8), to: &input)
  return EvidenceDigest(unchecked: Data(SHA256.hash(data: input)))
}

private func appendCanonical(_ value: Data, to target: inout Data) {
  appendCanonical(UInt64(value.count), to: &target)
  target.append(value)
}

private func appendCanonical<T: FixedWidthInteger>(_ value: T, to target: inout Data) {
  var bigEndian = value.bigEndian
  withUnsafeBytes(of: &bigEndian) { target.append(contentsOf: $0) }
}

private func contentFailure(_ code: Int32, operation: String) -> ContentEvidence {
  if code == EACCES || code == EPERM {
    return .unavailable(reason: "\(operation): permission denied", errorCode: code)
  }
  if code == ENOENT {
    return .unavailable(reason: "\(operation): target missing", errorCode: code)
  }
  return .unavailable(reason: operation, errorCode: code)
}
