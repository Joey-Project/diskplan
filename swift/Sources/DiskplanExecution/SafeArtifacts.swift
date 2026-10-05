import CryptoKit
import Darwin
import DiskplanMacOS
import DiskplanPolicy
import Foundation

public indirect enum CanonicalJSONValue: Equatable, Sendable {
  case null
  case bool(Bool)
  case integer(Int64)
  case unsigned(UInt64)
  case string(String)
  case array([CanonicalJSONValue])
  case object([String: CanonicalJSONValue])

  public func canonicalEncoded() throws -> Data {
    try encoded(maximumBytes: Int.max)
  }

  fileprivate func encoded(maximumBytes: Int) throws -> Data {
    try CanonicalJSONStructuralLimits.validate(self, maximumBytes: maximumBytes)
    var accumulator = CanonicalJSONAccumulator(maximumBytes: maximumBytes)
    try append(to: &accumulator)
    return accumulator.data
  }

  private func append(to accumulator: inout CanonicalJSONAccumulator) throws {
    switch self {
    case .null:
      try accumulator.append("null".utf8)
    case .bool(let value):
      try accumulator.append((value ? "true" : "false").utf8)
    case .integer(let value):
      try accumulator.append(String(value).utf8)
    case .unsigned(let value):
      try accumulator.append(String(value).utf8)
    case .string(let value):
      try Self.appendEscaped(value, to: &accumulator)
    case .array(let values):
      try accumulator.append(UInt8(ascii: "["))
      for (index, value) in values.enumerated() {
        if index != 0 { try accumulator.append(UInt8(ascii: ",")) }
        try value.append(to: &accumulator)
      }
      try accumulator.append(UInt8(ascii: "]"))
    case .object(let values):
      try accumulator.append(UInt8(ascii: "{"))
      let keys = values.keys.sorted {
        Data($0.utf8).lexicographicallyPrecedes(Data($1.utf8))
      }
      for (index, key) in keys.enumerated() {
        if index != 0 { try accumulator.append(UInt8(ascii: ",")) }
        try Self.appendEscaped(key, to: &accumulator)
        try accumulator.append(UInt8(ascii: ":"))
        try values[key]!.append(to: &accumulator)
      }
      try accumulator.append(UInt8(ascii: "}"))
    }
  }

  private static func appendEscaped(
    _ value: String,
    to accumulator: inout CanonicalJSONAccumulator
  ) throws {
    try accumulator.append(UInt8(ascii: "\""))
    for byte in value.utf8 {
      switch byte {
      case UInt8(ascii: "\""): try accumulator.append("\\\"".utf8)
      case UInt8(ascii: "\\"): try accumulator.append("\\\\".utf8)
      case 0x08: try accumulator.append("\\b".utf8)
      case 0x09: try accumulator.append("\\t".utf8)
      case 0x0A: try accumulator.append("\\n".utf8)
      case 0x0C: try accumulator.append("\\f".utf8)
      case 0x0D: try accumulator.append("\\r".utf8)
      case 0x00...0x1F:
        try accumulator.append(String(format: "\\u%04x", byte).utf8)
      default:
        try accumulator.append(byte)
      }
    }
    try accumulator.append(UInt8(ascii: "\""))
  }
}

public enum CanonicalArtifactEncodingError: Error, Equatable, Sendable {
  case byteLimitExceeded
  case structuralLimitExceeded
}

private enum CanonicalJSONStructuralLimits {
  static let maximumDepth = 64
  static let maximumNodes = 200_000
  static let maximumCollectionEntries = 100_000

  static func validate(_ root: CanonicalJSONValue, maximumBytes: Int) throws {
    _ = try measure(root, maximumBytes: maximumBytes)
  }

  static func measure(
    _ root: CanonicalJSONValue,
    maximumBytes: Int,
    rootDepth: Int = 1
  ) throws -> (nodes: Int, maximumDepth: Int) {
    guard maximumBytes > 0 else { throw CanonicalArtifactEncodingError.byteLimitExceeded }
    var stack: [(CanonicalJSONValue, Int)] = [(root, rootDepth)]
    var nodes = 0
    var observedMaximumDepth = 0
    while let (value, depth) = stack.popLast() {
      guard depth <= maximumDepth, nodes < maximumNodes else {
        throw CanonicalArtifactEncodingError.structuralLimitExceeded
      }
      nodes += 1
      observedMaximumDepth = max(observedMaximumDepth, depth)
      switch value {
      case .null, .bool, .integer, .unsigned:
        continue
      case .string(let string):
        guard string.utf8.count <= maximumBytes else {
          throw CanonicalArtifactEncodingError.byteLimitExceeded
        }
      case .array(let values):
        guard values.count <= maximumCollectionEntries,
          nodes <= maximumNodes - values.count
        else { throw CanonicalArtifactEncodingError.structuralLimitExceeded }
        for child in values { stack.append((child, depth + 1)) }
      case .object(let values):
        guard values.count <= maximumCollectionEntries,
          nodes <= maximumNodes - values.count,
          values.keys.allSatisfy({ $0.utf8.count <= maximumBytes })
        else { throw CanonicalArtifactEncodingError.structuralLimitExceeded }
        for child in values.values { stack.append((child, depth + 1)) }
      }
    }
    return (nodes, observedMaximumDepth)
  }
}

private struct CanonicalJSONAccumulator {
  var data = Data()
  let maximumBytes: Int

  mutating func append(_ byte: UInt8) throws {
    guard data.count < maximumBytes else { throw CanonicalArtifactEncodingError.byteLimitExceeded }
    data.append(byte)
  }

  mutating func append<Bytes: Collection>(_ bytes: Bytes) throws where Bytes.Element == UInt8 {
    guard bytes.count <= maximumBytes - data.count else {
      throw CanonicalArtifactEncodingError.byteLimitExceeded
    }
    data.append(contentsOf: bytes)
  }
}

public enum SafeArtifactKind: String, CaseIterable, Equatable, Sendable {
  case evidence
  case proposedPlan = "proposed-plan"
  case decision
  case executionRecord = "execution-record"
  case history

  fileprivate var rawFilename: Data { Data("\(rawValue).json".utf8) }
}

public struct CanonicalArtifactDocument: Equatable, Sendable {
  public let kind: SafeArtifactKind
  public let schemaVersion: UInt32
  public let payload: CanonicalJSONValue

  public init(kind: SafeArtifactKind, schemaVersion: UInt32 = 1, payload: CanonicalJSONValue) {
    self.kind = kind
    self.schemaVersion = schemaVersion
    self.payload = payload
  }

  public func canonicalEncoded() throws -> Data {
    try encoded(maximumBytes: Int.max)
  }

  fileprivate func encoded(maximumBytes: Int) throws -> Data {
    try CanonicalJSONValue.object([
      "artifact_kind": .string(kind.rawValue),
      "payload": payload,
      "schema_version": .unsigned(UInt64(schemaVersion)),
    ]).encoded(maximumBytes: maximumBytes)
  }
}

public struct ArtifactHistoryTimestamp: Equatable, Sendable {
  public let secondsSinceEpoch: Int64
  public let nanoseconds: UInt32

  public init(secondsSinceEpoch: Int64, nanoseconds: UInt32) {
    precondition(nanoseconds < 1_000_000_000)
    self.secondsSinceEpoch = secondsSinceEpoch
    self.nanoseconds = nanoseconds
  }

  fileprivate var json: CanonicalJSONValue {
    .object([
      "nanoseconds": .unsigned(UInt64(nanoseconds)),
      "seconds_since_epoch": .integer(secondsSinceEpoch),
    ])
  }
}

public enum ArtifactHistoryObservation: Equatable, Sendable {
  case observed(ArtifactHistoryTimestamp)
  case unavailable(reason: String)

  fileprivate var json: CanonicalJSONValue {
    switch self {
    case .observed(let timestamp):
      return .object(["status": .string("observed"), "value": timestamp.json])
    case .unavailable(let reason):
      return .object(["reason": .string(reason), "status": .string("unavailable")])
    }
  }
}

public struct ArtifactHistoryRecord: Equatable, Sendable {
  public let candidateID: String
  public let firstSeen: ArtifactHistoryObservation
  public let lastSeen: ArtifactHistoryObservation
  public let lastSeenOpen: ArtifactHistoryObservation
  public let lastSeenProcessReference: ArtifactHistoryObservation

  public init(
    candidateID: String,
    firstSeen: ArtifactHistoryObservation,
    lastSeen: ArtifactHistoryObservation,
    lastSeenOpen: ArtifactHistoryObservation,
    lastSeenProcessReference: ArtifactHistoryObservation
  ) {
    self.candidateID = candidateID
    self.firstSeen = firstSeen
    self.lastSeen = lastSeen
    self.lastSeenOpen = lastSeenOpen
    self.lastSeenProcessReference = lastSeenProcessReference
  }

  fileprivate var json: CanonicalJSONValue {
    .object([
      "candidate_id": .string(candidateID),
      "first_seen": firstSeen.json,
      "last_seen": lastSeen.json,
      "last_seen_open": lastSeenOpen.json,
      "last_seen_process_reference": lastSeenProcessReference.json,
    ])
  }
}

extension CanonicalArtifactDocument {
  public static func history(_ records: [ArtifactHistoryRecord]) throws -> Self {
    var candidateIDs = Set<String>()
    guard
      records.allSatisfy({ !$0.candidateID.isEmpty && candidateIDs.insert($0.candidateID).inserted }
      )
    else {
      throw SafeArtifactWarning(code: "artifact-history-candidate-id-invalid-or-duplicate")
    }
    return Self(
      kind: .history,
      payload: .object([
        "records": .array(
          records.sorted {
            Data($0.candidateID.utf8).lexicographicallyPrecedes(Data($1.candidateID.utf8))
          }.map(\.json))
      ])
    )
  }
}

public enum ArtifactDurability: String, Equatable, Sendable {
  case bestEffort
  case full
}

/// This binding is supplied by the engine from an already descriptor-verified scan root.
/// Admission reopens the raw path without following links and requires this exact identity.
struct EngineArtifactExclusionRoot: Equatable, Sendable {
  let rawPath: RawRootPath
  let expectedIdentity: ObjectIdentity
}

/// Enabled admission is deliberately module-internal. A future runtime composition point must
/// derive it from the complete immutable-plan coverage plus descriptor-verified provider roots;
/// a caller-supplied list cannot prove that no active root was omitted.
enum SafeArtifactConfiguration: Equatable, Sendable {
  case disabled
  case enabled(
    destinationParent: RawRootPath,
    taskIdentifier: String,
    excludedScanAndProviderRoots: [EngineArtifactExclusionRoot],
    durability: ArtifactDurability = .bestEffort,
    maximumArtifactBytes: UInt64 = 64 * 1_024 * 1_024
  )
}

public struct ArtifactRecoveryLocator: Equatable, Sendable {
  public let parentIdentity: ObjectIdentity
  public let rawLeaf: Data
  public let leafIdentity: ObjectIdentity
  public let byteCount: UInt64
  public let sha256: String
  public let pathHint: String?
  public let usageRequirement: String

  fileprivate init(
    parentIdentity: ObjectIdentity,
    rawLeaf: Data,
    leafIdentity: ObjectIdentity,
    byteCount: UInt64,
    sha256: String,
    pathHint: String?
  ) {
    self.parentIdentity = parentIdentity
    self.rawLeaf = rawLeaf
    self.leafIdentity = leafIdentity
    self.byteCount = byteCount
    self.sha256 = sha256
    self.pathHint = pathHint
    usageRequirement =
      "path hint is unstable; use only after you revalidate the descriptor-relative parent "
      + "identity, raw leaf, leaf identity/type, size, digest, and access policy"
  }
}

public struct SafeArtifactWarning: Error, Equatable, Sendable {
  public let code: String
  public let errno: Int32?
  public let retainedLocator: ArtifactRecoveryLocator?

  public init(
    code: String,
    errno: Int32? = nil,
    retainedLocator: ArtifactRecoveryLocator? = nil
  ) {
    self.code = code
    self.errno = errno
    self.retainedLocator = retainedLocator
  }
}

public struct SafeArtifactWriteError: Error, Equatable, Sendable {
  public let warning: SafeArtifactWarning
  public init(_ warning: SafeArtifactWarning) { self.warning = warning }
}

public struct ArtifactWriteReceipt: Equatable, Sendable {
  public let locator: ArtifactRecoveryLocator
}

public enum ArtifactWriteOutcome: Equatable, Sendable {
  case disabled
  case published(ArtifactWriteReceipt)
  case warning(SafeArtifactWarning)
}

enum SafeArtifactAdmission: Sendable {
  case disabled
  case admitted(SafeArtifactStore)
  case rejected(SafeArtifactWarning)

  func write(_ document: CanonicalArtifactDocument) async -> ArtifactWriteOutcome {
    switch self {
    case .disabled: return .disabled
    case .admitted(let store): return await store.write(document)
    case .rejected(let warning): return .warning(warning)
    }
  }
}

public enum SafeArtifactCapabilities {
  public static let spill = SafeArtifactWarning(
    code: "spill-unavailable-without-descriptor-bound-stable-sqlite-vfs"
  )
}

/// Buffers one bounded execution transcript and publishes it once `applyFinished` arrives.
/// The sink is constructed for exactly one execution epoch and must not be shared. A terminal
/// writer failure is thrown exactly once; later records become no-ops so persistence cannot
/// amplify failures or affect the coordinator's cancellation and apply state.
public actor CanonicalExecutionAuditSink: ExecutionAuditSink {
  private static let hardMaximumEvents = 100_000
  private static let hardMaximumDocumentBytes = 64 * 1_024 * 1_024

  private enum Phase: Equatable {
    case collecting
    case publishing
    case terminal
  }

  private let store: SafeArtifactStore
  private let expectedEpochID: String
  private let metadata: CanonicalJSONValue
  private let maximumEvents: Int
  private let maximumBufferedBytes: Int
  private let initializationWarning: SafeArtifactWarning?
  private var events: [CanonicalJSONValue] = []
  private var documentBytes: Int
  private var documentNodes: Int
  private var terminalWarning: SafeArtifactWarning?
  private var phase = Phase.collecting
  private var started = false

  public init(
    store: SafeArtifactStore,
    expectedEpochID: String,
    metadata: CanonicalJSONValue = .object([:]),
    maximumEvents: Int = 100_000,
    maximumBufferedBytes: Int = 32 * 1_024 * 1_024
  ) {
    self.store = store
    self.expectedEpochID = expectedEpochID
    self.metadata = metadata
    self.maximumEvents = max(1, maximumEvents)
    self.maximumBufferedBytes = max(1, maximumBufferedBytes)
    let emptyDocument = CanonicalArtifactDocument(
      kind: .executionRecord,
      payload: .object([
        "events": .array([]),
        "metadata": metadata,
      ])
    )
    if expectedEpochID.isEmpty || expectedEpochID.utf8.count > 4_096 || maximumEvents <= 0
      || maximumEvents > Self.hardMaximumEvents || maximumBufferedBytes <= 0
      || maximumBufferedBytes > Self.hardMaximumDocumentBytes
    {
      initializationWarning = SafeArtifactWarning(code: "execution-audit-budget-invalid")
      documentBytes = 0
      documentNodes = 0
    } else if let encoded = try? emptyDocument.encoded(maximumBytes: maximumBufferedBytes),
      let measurement = try? CanonicalJSONStructuralLimits.measure(
        .object([
          "artifact_kind": .string(SafeArtifactKind.executionRecord.rawValue),
          "payload": emptyDocument.payload,
          "schema_version": .unsigned(UInt64(emptyDocument.schemaVersion)),
        ]),
        maximumBytes: maximumBufferedBytes
      )
    {
      initializationWarning = nil
      documentBytes = encoded.count
      documentNodes = measurement.nodes
    } else {
      initializationWarning = SafeArtifactWarning(
        code: "execution-audit-metadata-budget-or-structure-invalid")
      documentBytes = 0
      documentNodes = 0
    }
  }

  public func record(_ event: ExecutionEvent, epochID: String) async throws {
    if let initializationWarning, terminalWarning == nil {
      terminalWarning = initializationWarning
      phase = .terminal
      throw SafeArtifactWriteError(initializationWarning)
    }
    guard phase == .collecting, terminalWarning == nil else { return }
    guard epochID == expectedEpochID else {
      throw SafeArtifactWriteError(
        SafeArtifactWarning(code: "execution-audit-epoch-mismatch"))
    }
    switch event {
    case .applyStarted(let incomingEpochID):
      guard incomingEpochID == epochID else {
        throw SafeArtifactWriteError(
          SafeArtifactWarning(code: "execution-audit-epoch-mismatch"))
      }
      guard !started else {
        throw SafeArtifactWriteError(
          SafeArtifactWarning(code: "execution-audit-duplicate-apply-start"))
      }
      started = true
    default:
      guard started else {
        throw SafeArtifactWriteError(
          SafeArtifactWarning(code: "execution-audit-event-before-apply-start"))
      }
    }
    let value = event.artifactJSON
    let separatorBytes = events.isEmpty ? 0 : 1
    let remainingBytes = maximumBufferedBytes - documentBytes - separatorBytes
    guard events.count < maximumEvents, remainingBytes >= 0,
      let size = try? value.encoded(maximumBytes: remainingBytes).count,
      let measurement = try? CanonicalJSONStructuralLimits.measure(
        value,
        maximumBytes: remainingBytes,
        rootDepth: 4
      ),
      documentNodes <= CanonicalJSONStructuralLimits.maximumNodes - measurement.nodes
    else {
      try failCollection(code: "execution-audit-buffer-budget-exhausted")
      return
    }
    events.append(value)
    documentBytes += separatorBytes + size
    documentNodes += measurement.nodes
    guard case .applyFinished = event else { return }
    let transcript = events
    events.removeAll(keepingCapacity: false)
    documentBytes = 0
    documentNodes = 0
    phase = .publishing
    let document = CanonicalArtifactDocument(
      kind: .executionRecord,
      payload: .object([
        "events": .array(transcript),
        "metadata": metadata,
      ])
    )
    switch await store.write(document) {
    case .published:
      phase = .terminal
    case .warning(let warning):
      terminalWarning = warning
      phase = .terminal
      throw SafeArtifactWriteError(warning)
    case .disabled:
      let warning = SafeArtifactWarning(code: "execution-audit-store-disabled")
      terminalWarning = warning
      phase = .terminal
      throw SafeArtifactWriteError(warning)
    }
  }

  private func failCollection(code: String) throws {
    let warning = SafeArtifactWarning(code: code)
    terminalWarning = warning
    phase = .terminal
    events.removeAll(keepingCapacity: false)
    documentBytes = 0
    documentNodes = 0
    throw SafeArtifactWriteError(warning)
  }
}

extension ExecutionEvent {
  fileprivate var artifactJSON: CanonicalJSONValue {
    switch self {
    case .applyStarted(let epochID):
      return .object(["epoch_id": .string(epochID), "type": .string("apply_started")])
    case .unitStarted(let unit):
      return .object(["type": .string("unit_started"), "unit": unit.artifactJSON])
    case .forceRequiredWarning(let actionID):
      return .object([
        "action_id": .string(actionID.hex),
        "type": .string("force_required_warning"),
      ])
    case .stepFinished(let outcome):
      return .object([
        "action_id": .string(outcome.actionID.hex),
        "adapter_outcome": outcome.adapterOutcome.artifactJSON,
        "post_verification": outcome.postVerification.artifactJSON,
        "status": .string(outcome.status.rawValue),
        "type": .string("step_finished"),
      ])
    case .releasePostVerificationFinished(let outcome):
      return .object([
        "allocation_group_id": .string(outcome.allocationGroupID),
        "outcome": outcome.outcome.artifactJSON,
        "type": .string("release_post_verification_finished"),
      ])
    case .unitFinished(let outcome):
      return .object([
        "status": .string(outcome.status.rawValue),
        "type": .string("unit_finished"),
        "unit": outcome.id.artifactJSON,
      ])
    case .auditWriteFailed(let failure):
      var fields: [String: CanonicalJSONValue] = [
        "code": .string(failure.code),
        "event_index": .integer(Int64(failure.eventIndex)),
        "type": .string("audit_write_failed"),
      ]
      if let value = failure.errno { fields["errno"] = .integer(Int64(value)) }
      if failure.retainedLocator != nil { fields["retained_artifact"] = .bool(true) }
      return .object(fields)
    case .applyFinished:
      return .object(["type": .string("apply_finished")])
    }
  }
}

extension ExecutionUnitID {
  fileprivate var artifactJSON: CanonicalJSONValue {
    switch self {
    case .action(let actionID):
      return .object(["action_id": .string(actionID.hex), "type": .string("action")])
    case .compoundRelease(let groupIDs):
      return .object([
        "allocation_group_ids": .array(groupIDs.sorted().map(CanonicalJSONValue.string)),
        "type": .string("compound_release"),
      ])
    }
  }
}

extension AdapterOperationOutcome {
  fileprivate var artifactJSON: CanonicalJSONValue {
    switch self {
    case .succeeded(let detailCode):
      return .object(["detail_code": .string(detailCode), "status": .string("succeeded")])
    case .failed(let failure):
      return failure.artifactJSON(status: "failed")
    case .cancelled:
      return .object(["status": .string("cancelled")])
    case .timedOut:
      return .object(["status": .string("timed_out")])
    case .notStarted(let reason):
      return .object([
        "reason": .string(reason.rawValue), "status": .string("not_started"),
      ])
    }
  }
}

extension ExecutionAdapterFailure {
  fileprivate func artifactJSON(status: String) -> CanonicalJSONValue {
    var fields: [String: CanonicalJSONValue] = [
      "code": .string(code), "status": .string(status),
    ]
    if let value = errno { fields["errno"] = .integer(Int64(value)) }
    if let value = exitStatus { fields["exit_status"] = .integer(Int64(value)) }
    if let value = terminatingSignal {
      fields["terminating_signal"] = .integer(Int64(value))
    }
    return .object(fields)
  }
}

extension PostVerificationOutcome {
  fileprivate var artifactJSON: CanonicalJSONValue {
    switch self {
    case .satisfied:
      return .object(["status": .string("satisfied")])
    case .expectedResidual(let failure):
      return failure.artifactJSON(status: "expected_residual")
    case .missing:
      return .object(["status": .string("missing")])
    case .notSatisfied(let code):
      return .object(["code": .string(code), "status": .string("not_satisfied")])
    case .unknown(let reason):
      return .object([
        "reason": .string(reason.rawValue), "status": .string("unknown"),
      ])
    case .unreadable(let failure):
      return .object([
        "code": .string(failure.code),
        "collector": .string(failure.collector),
        "status": .string("unreadable"),
      ])
    case .failed(let failure):
      return .object([
        "code": .string(failure.code),
        "collector": .string(failure.collector),
        "status": .string("failed"),
      ])
    }
  }
}

private struct ArtifactAccessSeal: Equatable, Sendable {
  let identity: ObjectIdentity
  let ownerUserID: uid_t
  let ownerGroupID: gid_t
  let mode: mode_t
  let authorizationFlags: UInt32
  let aclDigest: Data
  let hasAllowACL: Bool
}

enum ArtifactReadbackFailure: Error, Equatable, Sendable {
  case unreadable(errno: Int32)
  case failed(errno: Int32?)
  case identityMismatch
  case contentMismatch
  case accessPolicyMismatch

  func warning(stage: String) -> SafeArtifactWarning {
    switch self {
    case .unreadable(let errorNumber):
      return SafeArtifactWarning(code: "\(stage)-readback-unreadable", errno: errorNumber)
    case .failed(let errorNumber):
      return SafeArtifactWarning(code: "\(stage)-readback-failed", errno: errorNumber)
    case .identityMismatch:
      return SafeArtifactWarning(code: "\(stage)-identity-mismatch")
    case .contentMismatch:
      return SafeArtifactWarning(code: "\(stage)-content-mismatch")
    case .accessPolicyMismatch:
      return SafeArtifactWarning(code: "\(stage)-access-policy-mismatch")
    }
  }
}

private struct ArtifactReadbackSnapshot: Equatable, Sendable {
  let seal: ArtifactAccessSeal
  let size: UInt64
  let digest: String
}

private struct BoundArtifactDirectory: Sendable {
  let descriptor: Int32
  let rawName: Data?
  let seal: ArtifactAccessSeal
}

protocol ArtifactLocalityProbing: Sendable {
  func gateBeforePathAccess() -> SafeArtifactWarning?

  func verifyLocalDirectory(
    parentDescriptor: Int32,
    rawName: Data,
    expectedIdentity: ObjectIdentity
  ) -> SafeArtifactWarning?
}

enum ArtifactProviderLocalityAdmission {
  /// File Provider's "identifier absent" response only says that this lookup found no provider
  /// identifier. It is not affirmative proof that the object is local, so v1 fails closed until
  /// the system probe can supply a positive, non-materializing local-origin attestation.
  static func warning(
    for disposition: ProviderIdentityDisposition
  ) -> SafeArtifactWarning {
    switch disposition {
    case .confirmedProvider:
      return SafeArtifactWarning(code: "artifact-ancestor-provider-managed")
    case .identifierAbsent:
      return SafeArtifactWarning(code: "artifact-ancestor-provider-locality-unproven")
    case .indeterminate:
      return SafeArtifactWarning(code: "artifact-ancestor-provider-unverified")
    }
  }
}

private struct ProductionArtifactLocalityProbe: ArtifactLocalityProbing {
  let policy: NoMaterializationPolicy
  let providerProbe: FileProviderBoundaryProbe

  static func make() -> Result<Self, SafeArtifactWarning> {
    let result = MaterializationPolicyInstaller().installBeforePathAccess()
    guard let policy = result.value else {
      return .failure(
        SafeArtifactWarning(
          code: "no-materialization-policy-unavailable",
          errno: result.errorCode
        ))
    }
    return .success(Self(policy: policy, providerProbe: FileProviderBoundaryProbe()))
  }

  func gateBeforePathAccess() -> SafeArtifactWarning? {
    let policyState = policy.revalidateLive()
    guard policyState.value != nil else {
      return SafeArtifactWarning(
        code: "no-materialization-policy-changed", errno: policyState.errorCode)
    }
    return nil
  }

  func verifyLocalDirectory(
    parentDescriptor: Int32,
    rawName: Data,
    expectedIdentity: ObjectIdentity
  ) -> SafeArtifactWarning? {
    if let warning = gateBeforePathAccess() { return warning }
    let item = ItemProbe().probe(
      parentFileDescriptor: parentDescriptor,
      rawName: rawName,
      policy: policy
    )
    guard let evidence = item.value else {
      return SafeArtifactWarning(code: "artifact-locality-probe-failed", errno: item.errorCode)
    }
    guard evidence.objectType.value == .directory else {
      return SafeArtifactWarning(code: "artifact-ancestor-not-directory")
    }
    guard let device = evidence.device.value, let fileID = evidence.fileID.value else {
      return SafeArtifactWarning(code: "artifact-ancestor-identity-unavailable")
    }
    let observedIdentity = ObjectIdentity(
      device: UInt64(UInt32(bitPattern: Int32(truncatingIfNeeded: device))),
      object: fileID,
      generation: .unknown(.unavailableViaPublicAPI),
      type: .directory
    )
    guard Self.localityIdentitiesMatch(observedIdentity, expectedIdentity) else {
      return SafeArtifactWarning(code: "artifact-ancestor-identity-mismatch")
    }
    guard evidence.isDataless.value == false else {
      return SafeArtifactWarning(
        code: evidence.isDataless.value == true
          ? "artifact-ancestor-dataless" : "artifact-ancestor-dataless-unverified",
        errno: evidence.isDataless.errorCode
      )
    }
    guard evidence.isSyncRoot.value == false else {
      return SafeArtifactWarning(
        code: evidence.isSyncRoot.value == true
          ? "artifact-ancestor-provider-capability" : "artifact-ancestor-provider-unverified",
        errno: evidence.isSyncRoot.errorCode
      )
    }
    if let warning = gateBeforePathAccess() { return warning }
    switch providerProbe.probe(
      parentFileDescriptor: parentDescriptor,
      rawName: rawName,
      policy: policy,
      timeout: .milliseconds(250)
    ) {
    case .evidence(let providerEvidence):
      return ArtifactProviderLocalityAdmission.warning(
        for: providerEvidence.identityDisposition)
    case .rejected:
      return SafeArtifactWarning(code: "artifact-ancestor-provider-unverified")
    }
  }

  private static func localityIdentitiesMatch(
    _ lhs: ObjectIdentity,
    _ rhs: ObjectIdentity
  ) -> Bool {
    lhs.device == rhs.device && lhs.object == rhs.object && lhs.type == rhs.type
  }
}

struct ArtifactStoreTestingHooks: Sendable {
  var beforeWrite: @Sendable () -> SafeArtifactWarning? = { nil }
  var beforePublish: @Sendable () -> Void = {}
  var immediatelyBeforeRename: @Sendable () -> Void = {}
  var afterPublish: @Sendable () -> Void = {}
  var betweenSnapshotReads: @Sendable () -> Void = {}
  var forcedReadbackFailure: @Sendable () -> ArtifactReadbackFailure? = { nil }
}

public actor SafeArtifactStore {
  private let directories: [BoundArtifactDirectory]
  private let localityProbe: any ArtifactLocalityProbing
  private let durability: ArtifactDurability
  private let maximumArtifactBytes: UInt64
  private let hooks: ArtifactStoreTestingHooks

  private init(
    directories: [BoundArtifactDirectory],
    localityProbe: any ArtifactLocalityProbing,
    durability: ArtifactDurability,
    maximumArtifactBytes: UInt64,
    hooks: ArtifactStoreTestingHooks
  ) {
    self.directories = directories
    self.localityProbe = localityProbe
    self.durability = durability
    self.maximumArtifactBytes = maximumArtifactBytes
    self.hooks = hooks
  }

  deinit {
    for directory in directories.reversed() { _ = Darwin.close(directory.descriptor) }
  }

  static func admit(_ configuration: SafeArtifactConfiguration) -> SafeArtifactAdmission {
    switch configuration {
    case .disabled:
      return .disabled
    case .enabled:
      switch ProductionArtifactLocalityProbe.make() {
      case .success(let probe):
        return admit(configuration, localityProbe: probe, hooks: ArtifactStoreTestingHooks())
      case .failure(let warning):
        return .rejected(warning)
      }
    }
  }

  static func admit(
    _ configuration: SafeArtifactConfiguration,
    localityProbe: any ArtifactLocalityProbing,
    hooks: ArtifactStoreTestingHooks = ArtifactStoreTestingHooks()
  ) -> SafeArtifactAdmission {
    guard
      case .enabled(
        let destinationParent,
        let taskIdentifier,
        let excludedRoots,
        let durability,
        let maximumArtifactBytes
      ) = configuration
    else { return .disabled }
    guard maximumArtifactBytes > 0, maximumArtifactBytes <= UInt64(Int.max) else {
      return .rejected(SafeArtifactWarning(code: "artifact-byte-budget-invalid"))
    }
    guard let taskName = validatedTaskName(taskIdentifier) else {
      return .rejected(SafeArtifactWarning(code: "artifact-task-identifier-invalid"))
    }

    let destinationComponents = rawComponents(destinationParent)
    guard destinationComponents.count <= 64, excludedRoots.count <= 256,
      excludedRoots.allSatisfy({ rawComponents($0.rawPath).count <= 64 })
    else { return .rejected(SafeArtifactWarning(code: "artifact-admission-budget-exhausted")) }
    guard
      excludedRoots.allSatisfy({
        if case .known = $0.expectedIdentity.generation { return true }
        return false
      })
    else {
      return .rejected(SafeArtifactWarning(code: "excluded-root-generation-unavailable"))
    }
    let finalComponents = destinationComponents + [taskName]
    for root in excludedRoots {
      let rootComponents = rawComponents(root.rawPath)
      if isPrefix(rootComponents, of: finalComponents) {
        return .rejected(SafeArtifactWarning(code: "artifact-destination-inside-excluded-root"))
      }
    }

    let destinationResult = bindDirectoryChain(
      destinationParent,
      requireLocality: true,
      localityProbe: localityProbe
    )
    guard case .success(var destinationDirectories) = destinationResult else {
      return .rejected(destinationResult.failure!)
    }

    func closeDestination() {
      for directory in destinationDirectories.reversed() {
        _ = Darwin.close(directory.descriptor)
      }
      destinationDirectories.removeAll()
    }

    for root in excludedRoots {
      let exclusionResult = bindDirectoryChain(
        root.rawPath,
        requireLocality: false,
        localityProbe: localityProbe
      )
      guard case .success(let exclusionChain) = exclusionResult else {
        closeDestination()
        return .rejected(exclusionResult.failure!)
      }
      defer {
        for directory in exclusionChain.reversed() { _ = Darwin.close(directory.descriptor) }
      }
      guard let actual = exclusionChain.last?.seal.identity,
        exactIdentitiesMatch(actual, root.expectedIdentity)
      else {
        closeDestination()
        return .rejected(SafeArtifactWarning(code: "excluded-root-identity-mismatch"))
      }
      if destinationDirectories.contains(where: {
        exactIdentitiesMatch($0.seal.identity, root.expectedIdentity)
      }) {
        closeDestination()
        return .rejected(SafeArtifactWarning(code: "artifact-destination-inside-excluded-root"))
      }
    }

    guard let destination = destinationDirectories.last else {
      closeDestination()
      return .rejected(SafeArtifactWarning(code: "artifact-destination-binding-empty"))
    }
    if let warning = localityProbe.gateBeforePathAccess() {
      closeDestination()
      return .rejected(warning)
    }
    let createResult = withRawCString(taskName) {
      Darwin.mkdirat(destination.descriptor, $0, 0o700)
    }
    guard createResult == 0 else {
      let code =
        errno == EEXIST
        ? "artifact-task-directory-collision" : "artifact-task-directory-create-failed"
      let failure = SafeArtifactWarning(code: code, errno: errno)
      closeDestination()
      return .rejected(failure)
    }

    if let warning = localityProbe.gateBeforePathAccess() {
      closeDestination()
      return .rejected(warning)
    }
    let openResult = withRawCString(taskName) {
      Darwin.openat(
        destination.descriptor,
        $0,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
      )
    }
    guard openResult >= 0 else {
      let failure = SafeArtifactWarning(code: "artifact-task-directory-open-failed", errno: errno)
      closeDestination()
      return .rejected(failure)
    }

    let taskSealResult = accessSeal(openResult, requireOwnerPrivate: true)
    guard case .success(let taskSeal) = taskSealResult else {
      _ = Darwin.close(openResult)
      closeDestination()
      return .rejected(taskSealResult.failure!)
    }
    if let warning = localityProbe.verifyLocalDirectory(
      parentDescriptor: destination.descriptor,
      rawName: taskName,
      expectedIdentity: taskSeal.identity
    ) {
      _ = Darwin.close(openResult)
      closeDestination()
      return .rejected(warning)
    }
    if durability == .full, Darwin.fsync(destination.descriptor) != 0 {
      let warning = SafeArtifactWarning(code: "artifact-parent-fsync-failed", errno: errno)
      _ = Darwin.close(openResult)
      closeDestination()
      return .rejected(warning)
    }
    destinationDirectories.append(
      BoundArtifactDirectory(descriptor: openResult, rawName: taskName, seal: taskSeal))
    return .admitted(
      SafeArtifactStore(
        directories: destinationDirectories,
        localityProbe: localityProbe,
        durability: durability,
        maximumArtifactBytes: maximumArtifactBytes,
        hooks: hooks
      ))
  }

  func write(_ document: CanonicalArtifactDocument) -> ArtifactWriteOutcome {
    let bytes: Data
    do {
      bytes = try document.encoded(maximumBytes: Int(maximumArtifactBytes))
    } catch {
      return .warning(SafeArtifactWarning(code: "artifact-byte-budget-exhausted"))
    }
    if let warning = revalidateDirectoryChain() { return .warning(warning) }
    guard let taskDirectory = directories.last else {
      return .warning(SafeArtifactWarning(code: "artifact-task-directory-missing"))
    }
    let finalName = document.kind.rawFilename
    if let warning = requireAbsent(finalName, parent: taskDirectory.descriptor) {
      return .warning(warning)
    }

    let temporaryName = Data(".diskplan-write-\(UUID().uuidString.lowercased()).tmp".utf8)
    if let warning = localityProbe.gateBeforePathAccess() { return .warning(warning) }
    let temporaryDescriptor = withRawCString(temporaryName) {
      Darwin.openat(
        taskDirectory.descriptor,
        $0,
        O_CREAT | O_EXCL | O_RDWR | O_NOFOLLOW | O_CLOEXEC,
        0o600
      )
    }
    guard temporaryDescriptor >= 0 else {
      return .warning(SafeArtifactWarning(code: "artifact-temporary-create-failed", errno: errno))
    }

    var published = false
    let expectedDigest = Self.digest(bytes)
    let expectedSize = UInt64(bytes.count)
    var temporarySeal: ArtifactAccessSeal?

    func retainedLocator() -> ArtifactRecoveryLocator? {
      guard let seal = temporarySeal,
        case .success(let current) = stableFileSnapshot(temporaryDescriptor),
        Self.exactIdentitiesMatch(current.seal.identity, seal.identity),
        Self.accessPoliciesMatch(current.seal, seal),
        case .success(let slot) = Self.slotSeal(
          parent: taskDirectory.descriptor,
          rawName: published ? finalName : temporaryName,
          localityProbe: localityProbe
        ),
        Self.exactIdentitiesMatch(slot.identity, seal.identity),
        Self.accessPoliciesMatch(slot, seal)
      else { return nil }
      return recoveryLocator(
        parent: taskDirectory,
        rawLeaf: published ? finalName : temporaryName,
        leafIdentity: seal.identity,
        byteCount: current.size,
        digest: current.digest
      )
    }

    func publishedLocator() -> Result<ArtifactRecoveryLocator, SafeArtifactWarning> {
      guard let seal = temporarySeal else {
        return .failure(SafeArtifactWarning(code: "artifact-published-locator-seal-missing"))
      }
      let current: ArtifactReadbackSnapshot
      switch stableFileSnapshot(temporaryDescriptor) {
      case .failure(let failure):
        return .failure(failure.warning(stage: "artifact-published-locator"))
      case .success(let snapshot): current = snapshot
      }
      guard current.size == expectedSize, current.digest == expectedDigest else {
        return .failure(
          ArtifactReadbackFailure.contentMismatch.warning(stage: "artifact-published-locator"))
      }
      guard Self.exactIdentitiesMatch(current.seal.identity, seal.identity) else {
        return .failure(
          ArtifactReadbackFailure.identityMismatch.warning(stage: "artifact-published-locator"))
      }
      guard Self.accessPoliciesMatch(current.seal, seal) else {
        return .failure(
          ArtifactReadbackFailure.accessPolicyMismatch.warning(
            stage: "artifact-published-locator"))
      }
      let slot: ArtifactAccessSeal
      switch Self.slotSeal(
        parent: taskDirectory.descriptor,
        rawName: finalName,
        localityProbe: localityProbe
      ) {
      case .failure(let warning): return .failure(warning)
      case .success(let value): slot = value
      }
      guard Self.exactIdentitiesMatch(slot.identity, seal.identity) else {
        return .failure(
          ArtifactReadbackFailure.identityMismatch.warning(stage: "artifact-published-locator"))
      }
      guard Self.accessPoliciesMatch(slot, seal) else {
        return .failure(
          ArtifactReadbackFailure.accessPolicyMismatch.warning(
            stage: "artifact-published-locator"))
      }
      return .success(
        recoveryLocator(
          parent: taskDirectory,
          rawLeaf: finalName,
          leafIdentity: seal.identity,
          byteCount: expectedSize,
          digest: expectedDigest
        ))
    }

    func finishFailure(_ warning: SafeArtifactWarning) -> ArtifactWriteOutcome {
      // Failure cleanup intentionally retains the exclusive file. A separate check followed by
      // name-based unlink could delete a same-UID replacement. The locator is useful only after
      // descriptor-relative revalidation; a later scan may safely rediscover an unlocatable file.
      let result =
        warning.retainedLocator == nil
        ? warningWithLocator(warning, retainedLocator()) : warning
      _ = Darwin.close(temporaryDescriptor)
      return .warning(result)
    }

    switch Self.accessSeal(temporaryDescriptor, requireOwnerPrivate: true) {
    case .success(let seal): temporarySeal = seal
    case .failure(let warning): return finishFailure(warning)
    }
    if let warning = hooks.beforeWrite() { return finishFailure(warning) }
    if let warning = writeAll(bytes, to: temporaryDescriptor) { return finishFailure(warning) }
    if durability == .full, Darwin.fsync(temporaryDescriptor) != 0 {
      return finishFailure(
        SafeArtifactWarning(code: "artifact-temporary-fsync-failed", errno: errno))
    }
    let initialReadback: ArtifactReadbackSnapshot
    switch stableFileSnapshot(temporaryDescriptor) {
    case .failure(let failure):
      return finishFailure(failure.warning(stage: "artifact-temporary"))
    case .success(let snapshot):
      initialReadback = snapshot
    }
    guard initialReadback.size == expectedSize, initialReadback.digest == expectedDigest else {
      return finishFailure(
        ArtifactReadbackFailure.contentMismatch.warning(stage: "artifact-temporary"))
    }
    guard let seal = temporarySeal,
      Self.exactIdentitiesMatch(initialReadback.seal.identity, seal.identity)
    else {
      return finishFailure(
        ArtifactReadbackFailure.identityMismatch.warning(stage: "artifact-temporary"))
    }
    guard Self.accessPoliciesMatch(initialReadback.seal, seal) else {
      return finishFailure(
        ArtifactReadbackFailure.accessPolicyMismatch.warning(stage: "artifact-temporary"))
    }

    if let warning = revalidateDirectoryChain() { return finishFailure(warning) }
    if let warning = requireAbsent(finalName, parent: taskDirectory.descriptor) {
      return finishFailure(warning)
    }
    hooks.beforePublish()
    if let warning = revalidateDirectoryChain() { return finishFailure(warning) }
    if let warning = requireAbsent(finalName, parent: taskDirectory.descriptor) {
      return finishFailure(warning)
    }

    hooks.immediatelyBeforeRename()
    if let warning = localityProbe.gateBeforePathAccess() { return finishFailure(warning) }
    let renameResult = withTwoRawCStrings(temporaryName, finalName) {
      Darwin.renameatx_np(
        taskDirectory.descriptor,
        $0,
        taskDirectory.descriptor,
        $1,
        UInt32(RENAME_EXCL)
      )
    }
    guard renameResult == 0 else {
      let code = errno == EEXIST ? "artifact-target-collision" : "artifact-publish-failed"
      return finishFailure(SafeArtifactWarning(code: code, errno: errno))
    }
    published = true
    hooks.afterPublish()

    if let warning = revalidateDirectoryChain() { return finishFailure(warning) }
    let finalSlot: ArtifactAccessSeal
    switch Self.slotSeal(
      parent: taskDirectory.descriptor,
      rawName: finalName,
      localityProbe: localityProbe
    ) {
    case .failure(let warning): return finishFailure(warning)
    case .success(let seal): finalSlot = seal
    }
    guard let initialSeal = temporarySeal,
      Self.exactIdentitiesMatch(finalSlot.identity, initialSeal.identity)
    else {
      return finishFailure(
        ArtifactReadbackFailure.identityMismatch.warning(stage: "artifact-published"))
    }
    guard Self.accessPoliciesMatch(finalSlot, initialSeal) else {
      return finishFailure(
        ArtifactReadbackFailure.accessPolicyMismatch.warning(stage: "artifact-published"))
    }
    let finalReadback: ArtifactReadbackSnapshot
    switch stableFileSnapshot(temporaryDescriptor) {
    case .failure(let failure):
      return finishFailure(failure.warning(stage: "artifact-published"))
    case .success(let snapshot):
      finalReadback = snapshot
    }
    guard finalReadback.size == expectedSize, finalReadback.digest == expectedDigest else {
      return finishFailure(
        ArtifactReadbackFailure.contentMismatch.warning(stage: "artifact-published"))
    }
    guard Self.exactIdentitiesMatch(finalReadback.seal.identity, initialSeal.identity) else {
      return finishFailure(
        ArtifactReadbackFailure.identityMismatch.warning(stage: "artifact-published"))
    }
    guard Self.accessPoliciesMatch(finalReadback.seal, initialSeal) else {
      return finishFailure(
        ArtifactReadbackFailure.accessPolicyMismatch.warning(stage: "artifact-published"))
    }
    if durability == .full, Darwin.fsync(taskDirectory.descriptor) != 0 {
      return finishFailure(
        SafeArtifactWarning(code: "artifact-directory-fsync-failed", errno: errno))
    }
    if durability == .full, directories.count >= 2,
      Darwin.fsync(directories[directories.count - 2].descriptor) != 0
    {
      return finishFailure(
        SafeArtifactWarning(code: "artifact-parent-fsync-failed", errno: errno))
    }
    if let warning = revalidateDirectoryChain() { return finishFailure(warning) }

    let receiptLocator: ArtifactRecoveryLocator
    switch publishedLocator() {
    case .failure(let warning): return finishFailure(warning)
    case .success(let locator): receiptLocator = locator
    }
    guard Darwin.close(temporaryDescriptor) == 0 else {
      return .warning(
        SafeArtifactWarning(
          code: "artifact-descriptor-close-failed",
          errno: errno,
          retainedLocator: receiptLocator
        ))
    }
    return .published(ArtifactWriteReceipt(locator: receiptLocator))
  }

  private func revalidateDirectoryChain() -> SafeArtifactWarning? {
    for (index, directory) in directories.enumerated() {
      switch Self.accessSeal(
        directory.descriptor,
        requireOwnerPrivate: false,
        enforceAdmissionPolicy: false
      ) {
      case .failure(let warning):
        return SafeArtifactWarning(
          code: "artifact-ancestor-revalidation-failed", errno: warning.errno)
      case .success(let current):
        guard Self.exactIdentitiesMatch(current.identity, directory.seal.identity) else {
          return SafeArtifactWarning(code: "artifact-ancestor-identity-mismatch")
        }
        guard current.ownerUserID == directory.seal.ownerUserID,
          current.ownerGroupID == directory.seal.ownerGroupID,
          current.mode == directory.seal.mode,
          current.authorizationFlags == directory.seal.authorizationFlags,
          current.aclDigest == directory.seal.aclDigest,
          current.hasAllowACL == directory.seal.hasAllowACL
        else { return SafeArtifactWarning(code: "artifact-ancestor-access-policy-mismatch") }
      }
      guard index > 0, let rawName = directory.rawName else { continue }
      let parent = directories[index - 1]
      let slotResult = Self.slotSeal(
        parent: parent.descriptor,
        rawName: rawName,
        localityProbe: localityProbe
      )
      guard case .success(let slot) = slotResult else {
        let failure = slotResult.failure!
        if failure.code == "artifact-slot-missing" {
          return SafeArtifactWarning(code: "artifact-ancestor-missing", errno: failure.errno)
        }
        if failure.code == "artifact-slot-unreadable" {
          return SafeArtifactWarning(code: "artifact-ancestor-unreadable", errno: failure.errno)
        }
        return failure
      }
      guard Self.exactIdentitiesMatch(slot.identity, directory.seal.identity) else {
        return SafeArtifactWarning(code: "artifact-ancestor-slot-identity-mismatch")
      }
      guard Self.accessPoliciesMatch(slot, directory.seal) else {
        return SafeArtifactWarning(code: "artifact-ancestor-slot-access-policy-mismatch")
      }
      if let warning = localityProbe.verifyLocalDirectory(
        parentDescriptor: parent.descriptor,
        rawName: rawName,
        expectedIdentity: directory.seal.identity
      ) {
        return warning
      }
    }
    return nil
  }
}

extension SafeArtifactStore {
  fileprivate static func bindDirectoryChain(
    _ rawPath: RawRootPath,
    requireLocality: Bool,
    localityProbe: any ArtifactLocalityProbing
  ) -> Result<[BoundArtifactDirectory], SafeArtifactWarning> {
    if let warning = localityProbe.gateBeforePathAccess() { return .failure(warning) }
    let rootDescriptor = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard rootDescriptor >= 0 else {
      return .failure(SafeArtifactWarning(code: "artifact-root-open-failed", errno: errno))
    }
    let rootSealResult = accessSeal(rootDescriptor, requireOwnerPrivate: false)
    guard case .success(let rootSeal) = rootSealResult else {
      _ = Darwin.close(rootDescriptor)
      return .failure(rootSealResult.failure!)
    }
    var result = [
      BoundArtifactDirectory(descriptor: rootDescriptor, rawName: nil, seal: rootSeal)
    ]
    for rawName in rawComponents(rawPath) {
      guard let parent = result.last else { break }
      if let warning = localityProbe.gateBeforePathAccess() {
        close(result)
        return .failure(warning)
      }
      var slotStatus = stat()
      let statusResult = withRawCString(rawName) {
        Darwin.fstatat(parent.descriptor, $0, &slotStatus, AT_SYMLINK_NOFOLLOW)
      }
      guard statusResult == 0 else {
        let failure = SafeArtifactWarning(
          code: errno == ENOENT ? "artifact-ancestor-missing" : "artifact-ancestor-unreadable",
          errno: errno
        )
        close(result)
        return .failure(failure)
      }
      if objectKind(slotStatus.st_mode) == .symbolicLink {
        close(result)
        return .failure(SafeArtifactWarning(code: "artifact-ancestor-symlink-rejected"))
      }
      guard objectKind(slotStatus.st_mode) == .directory else {
        close(result)
        return .failure(SafeArtifactWarning(code: "artifact-ancestor-not-directory"))
      }
      let initialSlotResult = slotSeal(
        parent: parent.descriptor,
        rawName: rawName,
        localityProbe: localityProbe
      )
      guard case .success(let initialSlot) = initialSlotResult else {
        let slotFailure = initialSlotResult.failure!
        let failure = SafeArtifactWarning(
          code: slotFailure.code == "artifact-slot-missing"
            ? "artifact-ancestor-missing" : "artifact-ancestor-unreadable",
          errno: slotFailure.errno
        )
        close(result)
        return .failure(failure)
      }
      guard initialSlot.identity.type == .directory else {
        close(result)
        return .failure(SafeArtifactWarning(code: "artifact-ancestor-not-directory"))
      }
      if requireLocality,
        let warning = localityProbe.verifyLocalDirectory(
          parentDescriptor: parent.descriptor,
          rawName: rawName,
          expectedIdentity: initialSlot.identity
        )
      {
        close(result)
        return .failure(warning)
      }
      if let warning = localityProbe.gateBeforePathAccess() {
        close(result)
        return .failure(warning)
      }
      let descriptor = withRawCString(rawName) {
        Darwin.openat(
          parent.descriptor,
          $0,
          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
      }
      guard descriptor >= 0 else {
        let failure = SafeArtifactWarning(code: "artifact-ancestor-open-failed", errno: errno)
        close(result)
        return .failure(failure)
      }
      switch accessSeal(descriptor, requireOwnerPrivate: false) {
      case .failure(let warning):
        _ = Darwin.close(descriptor)
        close(result)
        return .failure(warning)
      case .success(let descriptorSeal):
        guard exactIdentitiesMatch(descriptorSeal.identity, initialSlot.identity) else {
          _ = Darwin.close(descriptor)
          close(result)
          return .failure(SafeArtifactWarning(code: "artifact-ancestor-identity-mismatch"))
        }
        guard accessPoliciesMatch(descriptorSeal, initialSlot) else {
          _ = Darwin.close(descriptor)
          close(result)
          return .failure(SafeArtifactWarning(code: "artifact-ancestor-access-policy-mismatch"))
        }
        result.append(
          BoundArtifactDirectory(descriptor: descriptor, rawName: rawName, seal: descriptorSeal))
      }
    }
    return .success(result)
  }

  fileprivate static func accessSeal(
    _ descriptor: Int32,
    requireOwnerPrivate: Bool,
    enforceAdmissionPolicy: Bool = true
  ) -> Result<ArtifactAccessSeal, SafeArtifactWarning> {
    var value = stat()
    guard Darwin.fstat(descriptor, &value) == 0 else {
      return .failure(SafeArtifactWarning(code: "artifact-fstat-failed", errno: errno))
    }
    guard let kind = objectKind(value.st_mode), kind == .directory || kind == .regularFile else {
      return .failure(SafeArtifactWarning(code: "artifact-object-type-rejected"))
    }
    let effectiveUser = Darwin.geteuid()
    if enforceAdmissionPolicy {
      guard value.st_uid == 0 || value.st_uid == effectiveUser else {
        return .failure(SafeArtifactWarning(code: "artifact-ancestor-owner-rejected"))
      }
      // Sticky world-writable ancestors are deliberately not admitted in v1. The held descriptor
      // is not proof that untrusted actors cannot replace a descendant slot.
      guard (value.st_mode & (S_IWGRP | S_IWOTH)) == 0 else {
        return .failure(SafeArtifactWarning(code: "artifact-ancestor-writable-by-others"))
      }
    }
    if requireOwnerPrivate && enforceAdmissionPolicy {
      guard
        ownerPrivatePolicy(
          kind: kind,
          ownerUserID: value.st_uid,
          permissions: value.st_mode & 0o777,
          effectiveUserID: effectiveUser
        )
      else { return .failure(SafeArtifactWarning(code: "artifact-object-not-owner-private")) }
    }
    switch aclSnapshot(descriptor) {
    case .failure(let warning): return .failure(warning)
    case .success(let acl):
      if enforceAdmissionPolicy, acl.hasAllowEntry {
        return .failure(SafeArtifactWarning(code: "artifact-ancestor-allow-acl-rejected"))
      }
      return .success(
        ArtifactAccessSeal(
          identity: identity(value),
          ownerUserID: value.st_uid,
          ownerGroupID: value.st_gid,
          mode: value.st_mode,
          // Only flags that change mutation/replacement authorization are part of the access
          // policy seal. UF_HIDDEN, UF_NODUMP, and archive metadata are intentionally benign.
          authorizationFlags: authorizationFlags(value.st_flags),
          aclDigest: acl.digest,
          hasAllowACL: acl.hasAllowEntry
        ))
    }
  }

  static func ownerPrivatePolicy(
    kind: ObjectKind,
    ownerUserID: uid_t,
    permissions: mode_t,
    effectiveUserID: uid_t
  ) -> Bool {
    guard ownerUserID == effectiveUserID else { return false }
    switch kind {
    case .directory: return permissions == 0o700
    case .regularFile: return permissions == 0o600
    default: return false
    }
  }

  fileprivate static func slotSeal(
    parent: Int32,
    rawName: Data,
    localityProbe: any ArtifactLocalityProbing
  ) -> Result<ArtifactAccessSeal, SafeArtifactWarning> {
    if let warning = localityProbe.gateBeforePathAccess() { return .failure(warning) }
    let descriptor = withRawCString(rawName) {
      Darwin.openat(parent, $0, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard descriptor >= 0 else {
      return .failure(
        SafeArtifactWarning(
          code: errno == ENOENT ? "artifact-slot-missing" : "artifact-slot-unreadable",
          errno: errno
        ))
    }
    defer { _ = Darwin.close(descriptor) }
    switch accessSeal(
      descriptor,
      requireOwnerPrivate: false,
      enforceAdmissionPolicy: false)
    {
    case .success(let seal): return .success(seal)
    case .failure(let warning):
      return .failure(
        SafeArtifactWarning(code: "artifact-slot-revalidation-failed", errno: warning.errno))
    }
  }

  fileprivate static func aclSnapshot(
    _ descriptor: Int32
  ) -> Result<(digest: Data, hasAllowEntry: Bool), SafeArtifactWarning> {
    guard let acl = Darwin.acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
      if errno == ENOENT {
        return .success((Data(SHA256.hash(data: Data())), false))
      }
      return .failure(SafeArtifactWarning(code: "artifact-acl-read-failed", errno: errno))
    }
    defer { _ = Darwin.acl_free(UnsafeMutableRawPointer(acl)) }
    var length: ssize_t = 0
    guard let text = Darwin.acl_to_text(acl, &length) else {
      return .failure(SafeArtifactWarning(code: "artifact-acl-render-failed", errno: errno))
    }
    defer { _ = Darwin.acl_free(text) }
    guard length >= 0 else {
      return .failure(SafeArtifactWarning(code: "artifact-acl-length-invalid"))
    }
    var entry: acl_entry_t?
    var entryID = Int32(ACL_FIRST_ENTRY.rawValue)
    var hasAllowEntry = false
    while Darwin.acl_get_entry(acl, entryID, &entry) == 0 {
      guard let entry else {
        return .failure(SafeArtifactWarning(code: "artifact-acl-entry-missing"))
      }
      var tag = ACL_UNDEFINED_TAG
      guard Darwin.acl_get_tag_type(entry, &tag) == 0 else {
        return .failure(SafeArtifactWarning(code: "artifact-acl-tag-read-failed", errno: errno))
      }
      if tag == ACL_EXTENDED_ALLOW { hasAllowEntry = true }
      entryID = Int32(ACL_NEXT_ENTRY.rawValue)
    }
    guard errno == EINVAL else {
      return .failure(SafeArtifactWarning(code: "artifact-acl-entry-read-failed", errno: errno))
    }
    return .success(
      (Data(SHA256.hash(data: Data(bytes: text, count: Int(length)))), hasAllowEntry))
  }

  fileprivate static func identity(_ value: stat) -> ObjectIdentity {
    ObjectIdentity(
      device: UInt64(UInt32(bitPattern: value.st_dev)),
      object: UInt64(value.st_ino),
      generation: .known(UInt64(value.st_gen)),
      type: objectKind(value.st_mode) ?? .regularFile
    )
  }

  fileprivate static func objectKind(_ mode: mode_t) -> ObjectKind? {
    switch mode & S_IFMT {
    case S_IFDIR: return .directory
    case S_IFREG: return .regularFile
    case S_IFLNK: return .symbolicLink
    default: return nil
    }
  }

  static func authorizationFlags(_ flags: UInt32) -> UInt32 {
    // Raw values are stable Darwin ABI from sys/stat.h and keep older SDK builds best effort even
    // when newer symbolic imports are unavailable: UF_IMMUTABLE, UF_APPEND, UF_DATAVAULT,
    // SF_IMMUTABLE, SF_APPEND, SF_RESTRICTED, and SF_NOUNLINK.
    flags & 0x001E_0086
  }

  fileprivate static func exactIdentitiesMatch(
    _ lhs: ObjectIdentity,
    _ rhs: ObjectIdentity
  ) -> Bool {
    guard lhs.device == rhs.device, lhs.object == rhs.object, lhs.type == rhs.type else {
      return false
    }
    switch (lhs.generation, rhs.generation) {
    case (.known(let left), .known(let right)): return left == right
    default: return false
    }
  }

  fileprivate static func accessPoliciesMatch(
    _ lhs: ArtifactAccessSeal,
    _ rhs: ArtifactAccessSeal
  ) -> Bool {
    lhs.ownerUserID == rhs.ownerUserID
      && lhs.ownerGroupID == rhs.ownerGroupID
      && lhs.mode == rhs.mode
      && lhs.authorizationFlags == rhs.authorizationFlags
      && lhs.aclDigest == rhs.aclDigest
      && lhs.hasAllowACL == rhs.hasAllowACL
  }

  fileprivate static func rawComponents(_ rawPath: RawRootPath) -> [Data] {
    guard rawPath.absoluteBytes != Data("/".utf8) else { return [] }
    return rawPath.absoluteBytes.dropFirst().split(separator: UInt8(ascii: "/")).map { Data($0) }
  }

  fileprivate static func validatedTaskName(_ value: String) -> Data? {
    let bytes = Data(value.utf8)
    guard !bytes.isEmpty, bytes.count <= 80, bytes != Data(".".utf8), bytes != Data("..".utf8),
      bytes.allSatisfy({
        (UInt8(ascii: "a")...UInt8(ascii: "z")).contains($0)
          || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains($0)
          || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0)
          || $0 == UInt8(ascii: "-") || $0 == UInt8(ascii: "_") || $0 == UInt8(ascii: ".")
      })
    else { return nil }
    return bytes
  }

  fileprivate static func isPrefix(_ prefix: [Data], of value: [Data]) -> Bool {
    guard prefix.count <= value.count else { return false }
    return Array(value.prefix(prefix.count)) == prefix
  }

  fileprivate static func close(_ directories: [BoundArtifactDirectory]) {
    for directory in directories.reversed() { _ = Darwin.close(directory.descriptor) }
  }

  fileprivate func requireAbsent(_ rawName: Data, parent: Int32) -> SafeArtifactWarning? {
    if let warning = localityProbe.gateBeforePathAccess() { return warning }
    var value = stat()
    let result = withRawCString(rawName) {
      Darwin.fstatat(parent, $0, &value, AT_SYMLINK_NOFOLLOW)
    }
    if result == 0 { return SafeArtifactWarning(code: "artifact-target-collision", errno: EEXIST) }
    if errno == ENOENT { return nil }
    return SafeArtifactWarning(code: "artifact-target-inspection-failed", errno: errno)
  }

  fileprivate func writeAll(_ data: Data, to descriptor: Int32) -> SafeArtifactWarning? {
    data.withUnsafeBytes { raw -> SafeArtifactWarning? in
      guard let base = raw.baseAddress else { return nil }
      var written = 0
      while written < raw.count {
        let result = Darwin.write(descriptor, base.advanced(by: written), raw.count - written)
        if result > 0 {
          written += result
        } else if result < 0, errno == EINTR {
          continue
        } else {
          return SafeArtifactWarning(code: "artifact-write-failed", errno: errno)
        }
      }
      return nil
    }
  }

  fileprivate func stableFileSnapshot(
    _ descriptor: Int32
  ) -> Result<ArtifactReadbackSnapshot, ArtifactReadbackFailure> {
    if let failure = hooks.forcedReadbackFailure() { return .failure(failure) }
    let beforeSeal: ArtifactAccessSeal
    switch Self.accessSeal(descriptor, requireOwnerPrivate: true) {
    case .failure(let warning): return .failure(Self.readbackFailure(for: warning))
    case .success(let seal): beforeSeal = seal
    }
    guard beforeSeal.identity.type == .regularFile else { return .failure(.identityMismatch) }
    let firstRead: Data
    switch boundedFileRead(descriptor) {
    case .failure(let failure): return .failure(failure)
    case .success(let data): firstRead = data
    }
    hooks.betweenSnapshotReads()
    let middleSeal: ArtifactAccessSeal
    switch Self.accessSeal(descriptor, requireOwnerPrivate: true) {
    case .failure(let warning): return .failure(Self.readbackFailure(for: warning))
    case .success(let seal): middleSeal = seal
    }
    guard Self.exactIdentitiesMatch(beforeSeal.identity, middleSeal.identity) else {
      return .failure(.identityMismatch)
    }
    guard Self.accessPoliciesMatch(beforeSeal, middleSeal) else {
      return .failure(.accessPolicyMismatch)
    }
    let secondRead: Data
    switch boundedFileRead(descriptor) {
    case .failure(let failure): return .failure(failure)
    case .success(let data): secondRead = data
    }
    guard firstRead == secondRead else { return .failure(.contentMismatch) }
    let afterSeal: ArtifactAccessSeal
    switch Self.accessSeal(descriptor, requireOwnerPrivate: true) {
    case .failure(let warning): return .failure(Self.readbackFailure(for: warning))
    case .success(let seal): afterSeal = seal
    }
    guard Self.exactIdentitiesMatch(middleSeal.identity, afterSeal.identity) else {
      return .failure(.identityMismatch)
    }
    guard Self.accessPoliciesMatch(middleSeal, afterSeal) else {
      return .failure(.accessPolicyMismatch)
    }
    return .success(
      ArtifactReadbackSnapshot(
        seal: afterSeal,
        size: UInt64(secondRead.count),
        digest: Self.digest(secondRead)
      ))
  }

  /// Two invocations are compared by `stableFileSnapshot`; each invocation independently binds
  /// its held descriptor before and after the read. This proves content stability directly rather
  /// than treating mtime or unrelated metadata churn as a content mutation.
  fileprivate func boundedFileRead(_ descriptor: Int32) -> Result<Data, ArtifactReadbackFailure> {
    var beforeStatus = stat()
    guard Darwin.fstat(descriptor, &beforeStatus) == 0 else {
      return .failure(Self.readbackSystemFailure(errno))
    }
    guard beforeStatus.st_size >= 0,
      UInt64(beforeStatus.st_size) <= maximumArtifactBytes
    else { return .failure(.failed(errno: nil)) }
    guard Darwin.lseek(descriptor, 0, SEEK_SET) == 0 else {
      return .failure(Self.readbackSystemFailure(errno))
    }
    var data = Data()
    data.reserveCapacity(Int(beforeStatus.st_size))
    var buffer = [UInt8](repeating: 0, count: 64 * 1_024)
    while true {
      let count = Darwin.read(descriptor, &buffer, buffer.count)
      if count == 0 { break }
      if count < 0, errno == EINTR { continue }
      guard count > 0 else { return .failure(Self.readbackSystemFailure(errno)) }
      guard data.count <= Int(maximumArtifactBytes) - count else {
        return .failure(.failed(errno: nil))
      }
      data.append(contentsOf: buffer.prefix(count))
    }
    var afterStatus = stat()
    guard Darwin.fstat(descriptor, &afterStatus) == 0 else {
      return .failure(Self.readbackSystemFailure(errno))
    }
    guard Self.exactIdentitiesMatch(Self.identity(beforeStatus), Self.identity(afterStatus)) else {
      return .failure(.identityMismatch)
    }
    guard data.count == Int(beforeStatus.st_size), afterStatus.st_size == beforeStatus.st_size
    else {
      return .failure(.contentMismatch)
    }
    return .success(data)
  }

  fileprivate static func readbackFailure(
    for warning: SafeArtifactWarning
  ) -> ArtifactReadbackFailure {
    if let errorNumber = warning.errno, errorNumber == EACCES || errorNumber == EPERM {
      return .unreadable(errno: errorNumber)
    }
    switch warning.code {
    case "artifact-object-type-rejected": return .identityMismatch
    case "artifact-ancestor-owner-rejected", "artifact-ancestor-writable-by-others",
      "artifact-object-not-owner-private", "artifact-ancestor-allow-acl-rejected":
      return .accessPolicyMismatch
    default: return .failed(errno: warning.errno)
    }
  }

  fileprivate static func readbackSystemFailure(_ errorNumber: Int32) -> ArtifactReadbackFailure {
    errorNumber == EACCES || errorNumber == EPERM
      ? .unreadable(errno: errorNumber) : .failed(errno: errorNumber)
  }

  fileprivate static func digest(_ data: Data) -> String {
    Data(SHA256.hash(data: data)).map { String(format: "%02x", $0) }.joined()
  }

  fileprivate func recoveryLocator(
    parent: BoundArtifactDirectory,
    rawLeaf: Data,
    leafIdentity: ObjectIdentity,
    byteCount: UInt64,
    digest: String
  ) -> ArtifactRecoveryLocator {
    let slotStillNamesLeaf: Bool
    switch Self.slotSeal(
      parent: parent.descriptor,
      rawName: rawLeaf,
      localityProbe: localityProbe
    ) {
    case .success(let seal):
      slotStillNamesLeaf = Self.exactIdentitiesMatch(seal.identity, leafIdentity)
    case .failure:
      slotStillNamesLeaf = false
    }
    return ArtifactRecoveryLocator(
      parentIdentity: parent.seal.identity,
      rawLeaf: rawLeaf,
      leafIdentity: leafIdentity,
      byteCount: byteCount,
      sha256: digest,
      pathHint: slotStillNamesLeaf
        ? verifiedPathHint(parent: parent, rawLeaf: rawLeaf) : nil
    )
  }

  fileprivate func verifiedPathHint(parent: BoundArtifactDirectory, rawLeaf: Data) -> String? {
    guard
      case .success(let current) = Self.accessSeal(
        parent.descriptor, requireOwnerPrivate: true),
      Self.exactIdentitiesMatch(current.identity, parent.seal.identity),
      Self.accessPoliciesMatch(current, parent.seal)
    else { return nil }
    var path = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    guard Darwin.fcntl(parent.descriptor, F_GETPATH, &path) == 0 else { return nil }
    let parentData = path.withUnsafeBytes { raw -> Data in
      let bytes = raw.bindMemory(to: UInt8.self)
      let length = bytes.firstIndex(of: 0) ?? bytes.count
      return Data(bytes.prefix(length))
    }
    var result = parentData
    if result.last != UInt8(ascii: "/") { result.append(UInt8(ascii: "/")) }
    result.append(rawLeaf)
    return String(data: result, encoding: .utf8)
  }

  fileprivate func warningWithLocator(
    _ warning: SafeArtifactWarning,
    _ locator: ArtifactRecoveryLocator?
  ) -> SafeArtifactWarning {
    SafeArtifactWarning(
      code: warning.code,
      errno: warning.errno,
      retainedLocator: locator
    )
  }
}

private func withRawCString<Result>(
  _ data: Data,
  _ body: (UnsafePointer<CChar>) -> Result
) -> Result {
  var bytes = Array(data)
  bytes.append(0)
  return bytes.withUnsafeBytes {
    body($0.bindMemory(to: CChar.self).baseAddress!)
  }
}

private func withTwoRawCStrings<Result>(
  _ first: Data,
  _ second: Data,
  _ body: (UnsafePointer<CChar>, UnsafePointer<CChar>) -> Result
) -> Result {
  withRawCString(first) { firstPointer in
    withRawCString(second) { secondPointer in
      body(firstPointer, secondPointer)
    }
  }
}

extension Result {
  fileprivate var failure: Failure? {
    if case .failure(let failure) = self { return failure }
    return nil
  }
}
