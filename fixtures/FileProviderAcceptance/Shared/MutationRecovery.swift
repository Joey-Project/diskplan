import Darwin
import Foundation

public enum ExternalMutationKind: String, Codable, CaseIterable, Hashable, Sendable {
  case domainAdd = "domain-add"
  case domainRemove = "domain-remove"
  case extensionAdd = "extension-add"
  case extensionRemove = "extension-remove"

  public var terminalPresence: ExternalMutationPresence {
    switch self {
    case .domainAdd, .extensionAdd: .present
    case .domainRemove, .extensionRemove: .absent
    }
  }

  public var isAdd: Bool {
    switch self {
    case .domainAdd, .extensionAdd: true
    case .domainRemove, .extensionRemove: false
    }
  }

  fileprivate var compensatedAdd: ExternalMutationKind? {
    switch self {
    case .domainRemove: .domainAdd
    case .extensionRemove: .extensionAdd
    case .domainAdd, .extensionAdd: nil
    }
  }
}

public enum ExternalMutationPresence: String, Codable, Hashable, Sendable {
  case present
  case absent
}

public enum ExternalMutationCompletion: String, Codable, Equatable, Sendable {
  case succeeded
  case failed
}

public enum ExternalMutationPhase: String, Codable, Equatable, Sendable {
  case prepared
  case dispatched
  case originalSucceeded = "original-succeeded"
  case originalFailed = "original-failed"

  fileprivate var rank: Int {
    switch self {
    case .prepared: 0
    case .dispatched: 1
    case .originalSucceeded, .originalFailed: 2
    }
  }
}

public struct ExternalMutationRunBinding: Codable, Equatable, Sendable {
  public static let provenance = "diskplan-file-provider-fixture-lifecycle-v2"

  public let version: Int
  public let runID: UUID
  public let domainIdentifier: String
  public let hostBundleIdentifier: String
  public let appPath: String
  public let extensionBundleIdentifier: String
  public let extensionPath: String
  public let lifecycleProvenance: String

  public init(manifest: FixtureManifest) throws {
    try manifest.validate()
    version = 1
    runID = manifest.runID
    domainIdentifier = manifest.domainIdentifier
    hostBundleIdentifier = FixtureContract.hostBundleIdentifier
    appPath = manifest.appPath
    extensionBundleIdentifier = FixtureContract.extensionBundleIdentifier
    extensionPath = manifest.extensionPath
    lifecycleProvenance = Self.provenance
    try validate(runDirectory: URL(fileURLWithPath: manifest.appGroupRunPath))
  }

  init(
    runID: UUID,
    domainIdentifier: String,
    appPath: String,
    extensionPath: String
  ) {
    version = 1
    self.runID = runID
    self.domainIdentifier = domainIdentifier
    hostBundleIdentifier = FixtureContract.hostBundleIdentifier
    self.appPath = appPath
    extensionBundleIdentifier = FixtureContract.extensionBundleIdentifier
    self.extensionPath = extensionPath
    lifecycleProvenance = Self.provenance
  }

  fileprivate func validate(runDirectory: URL) throws {
    let component = runID.uuidString.lowercased()
    guard version == 1, runDirectory.isFileURL,
      runDirectory.lastPathComponent == component,
      domainIdentifier == FixtureContract.domainIdentifier(runID: runID),
      hostBundleIdentifier == FixtureContract.hostBundleIdentifier,
      extensionBundleIdentifier == FixtureContract.extensionBundleIdentifier,
      lifecycleProvenance == Self.provenance,
      appPath.hasPrefix("/"), extensionPath.hasPrefix("/"),
      URL(fileURLWithPath: appPath).standardizedFileURL.path == appPath,
      URL(fileURLWithPath: extensionPath).standardizedFileURL.path == extensionPath,
      URL(fileURLWithPath: extensionPath).deletingLastPathComponent()
        == URL(fileURLWithPath: appPath).appendingPathComponent(
          "Contents/PlugIns", isDirectory: true)
    else { throw ExternalMutationJournalError.bindingMismatch }
  }
}

public enum ExternalMutationBootSession {
  public static func currentGeneration() throws -> String {
    var size = 0
    guard sysctlbyname("kern.bootsessionuuid", nil, &size, nil, 0) == 0, size > 1, size <= 128
    else {
      throw ExternalMutationJournalError.operationFailed(
        "read-boot-generation-size", errno: errno == 0 ? EIO : errno)
    }
    var bytes = [CChar](repeating: 0, count: size)
    let result = bytes.withUnsafeMutableBytes { buffer in
      sysctlbyname("kern.bootsessionuuid", buffer.baseAddress, &size, nil, 0)
    }
    guard result == 0 else {
      throw ExternalMutationJournalError.operationFailed(
        "read-boot-generation", errno: errno == 0 ? EIO : errno)
    }
    let rawBytes = bytes.map { UInt8(bitPattern: $0) }
    let terminator = rawBytes.firstIndex(of: 0) ?? rawBytes.endIndex
    return try normalizeBootGeneration(String(decoding: rawBytes[..<terminator], as: UTF8.self))
  }
}

public struct ExternalMutationRecoveryState: Codable, Equatable, Sendable {
  fileprivate static let maximumPredecessors = 64

  public let version: Int
  public let binding: ExternalMutationRunBinding
  public let kind: ExternalMutationKind
  public let operationID: UUID
  public let predecessorOperationID: UUID?
  fileprivate var predecessorStates: [ExternalMutationPredecessorState]?
  public let bootGeneration: String
  public let beganNanoseconds: UInt64
  public private(set) var phase: ExternalMutationPhase
  public private(set) var dispatchedNanoseconds: UInt64?
  public private(set) var completionNanoseconds: UInt64?

  fileprivate init(
    binding: ExternalMutationRunBinding,
    kind: ExternalMutationKind,
    operationID: UUID = UUID(),
    predecessorStates: [ExternalMutationPredecessorState] = [],
    bootGeneration: String,
    nowNanoseconds: UInt64
  ) {
    version = 2
    self.binding = binding
    self.kind = kind
    self.operationID = operationID
    predecessorOperationID = predecessorStates.last?.operationID
    self.predecessorStates = predecessorStates
    self.bootGeneration = bootGeneration
    beganNanoseconds = nowNanoseconds
    phase = .prepared
    dispatchedNanoseconds = nil
    completionNanoseconds = nil
  }

  fileprivate mutating func markDispatched(at nowNanoseconds: UInt64) throws {
    guard phase == .prepared else { throw ExternalMutationJournalError.invalidTransition }
    phase = .dispatched
    dispatchedNanoseconds = nowNanoseconds
  }

  fileprivate mutating func recordCompletion(
    _ completion: ExternalMutationCompletion,
    at nowNanoseconds: UInt64
  ) throws {
    guard phase == .dispatched else { throw ExternalMutationJournalError.invalidTransition }
    phase = completion == .succeeded ? .originalSucceeded : .originalFailed
    completionNanoseconds = nowNanoseconds
  }

  fileprivate func validate(
    expectedBinding: ExternalMutationRunBinding,
    runDirectory: URL
  ) throws {
    try binding.validate(runDirectory: runDirectory)
    guard version == 2, binding == expectedBinding,
      try normalizeBootGeneration(bootGeneration) == bootGeneration,
      beganNanoseconds > 0,
      predecessorOperationID != operationID,
      unresolvedPredecessors.count <= Self.maximumPredecessors,
      !kind.isAdd || unresolvedPredecessors.isEmpty,
      (phase == .prepared) == (dispatchedNanoseconds == nil),
      (phase == .originalSucceeded || phase == .originalFailed)
        == (completionNanoseconds != nil),
      completionNanoseconds == nil || dispatchedNanoseconds != nil,
      dispatchedNanoseconds == nil || dispatchedNanoseconds! >= beganNanoseconds,
      completionNanoseconds == nil || completionNanoseconds! >= dispatchedNanoseconds!
    else { throw ExternalMutationJournalError.malformedState }
    guard Set(unresolvedPredecessors.map(\.operationID)).count == unresolvedPredecessors.count,
      unresolvedPredecessors.allSatisfy({ $0.operationID != operationID })
    else { throw ExternalMutationJournalError.malformedState }
    for predecessor in unresolvedPredecessors { try predecessor.validate() }
    if let predecessorStates {
      guard predecessorOperationID == predecessorStates.last?.operationID else {
        throw ExternalMutationJournalError.malformedState
      }
    }
  }

  fileprivate func merging(_ other: Self) throws -> Self {
    guard version == other.version, binding == other.binding, kind == other.kind
    else { throw ExternalMutationJournalError.stateMismatch }
    if operationID != other.operationID {
      if unresolvedPredecessors.contains(where: { $0.operationID == other.operationID }) {
        var successor = self
        try successor.mergePredecessor(other)
        return successor
      }
      if other.unresolvedPredecessors.contains(where: { $0.operationID == operationID }) {
        var successor = other
        try successor.mergePredecessor(self)
        return successor
      }
      throw ExternalMutationJournalError.stateMismatch
    }
    guard predecessorOperationID == other.predecessorOperationID,
      bootGeneration == other.bootGeneration,
      beganNanoseconds == other.beganNanoseconds
    else { throw ExternalMutationJournalError.stateMismatch }
    let mergedPredecessors: [ExternalMutationPredecessorState]
    switch (predecessorStates, other.predecessorStates) {
    case (.some(let lhs), .some(let rhs)):
      guard lhs == rhs else { throw ExternalMutationJournalError.stateMismatch }
      mergedPredecessors = lhs
    case (.some(let value), .none), (.none, .some(let value)):
      mergedPredecessors = value
    case (.none, .none):
      mergedPredecessors = unresolvedPredecessors
    }
    if phase.rank == 2, other.phase.rank == 2, phase != other.phase {
      throw ExternalMutationJournalError.stateMismatch
    }
    var result = phase.rank >= other.phase.rank ? self : other
    result.predecessorStates = mergedPredecessors
    return result
  }

  fileprivate var unresolvedPredecessors: [ExternalMutationPredecessorState] {
    if let predecessorStates { return predecessorStates }
    guard let predecessorOperationID else { return [] }
    return [
      ExternalMutationPredecessorState(
        operationID: predecessorOperationID,
        bootGeneration: bootGeneration,
        beganNanoseconds: beganNanoseconds,
        phase: .dispatched,
        dispatchedNanoseconds: beganNanoseconds,
        completionNanoseconds: nil
      )
    ]
  }

  fileprivate var unresolvedRemovalOperations: [ExternalMutationPredecessorState] {
    var result = unresolvedPredecessors
    if phase == .dispatched || phase == .originalSucceeded {
      result.append(ExternalMutationPredecessorState(self))
    }
    return result
  }

  fileprivate var hasPotentialLateEffect: Bool {
    !unresolvedRemovalOperations.isEmpty
  }

  var unresolvedPredecessorOperationIDs: [UUID] {
    unresolvedPredecessors.map(\.operationID)
  }

  fileprivate func canResolveAcrossBoot(_ currentBootGeneration: String) -> Bool {
    let operations = unresolvedRemovalOperations
    return !operations.isEmpty
      && operations.allSatisfy { $0.bootGeneration != currentBootGeneration }
  }

  private mutating func mergePredecessor(_ state: Self) throws {
    guard
      let index = unresolvedPredecessors.firstIndex(where: {
        $0.operationID == state.operationID
      })
    else { throw ExternalMutationJournalError.stateMismatch }
    var values = unresolvedPredecessors
    let exact = ExternalMutationPredecessorState(state)
    let stored = values[index]
    guard stored == exact || predecessorStates == nil else {
      throw ExternalMutationJournalError.stateMismatch
    }
    values[index] = exact
    predecessorStates = values
  }
}

struct ExternalMutationPredecessorState: Codable, Equatable, Sendable {
  let operationID: UUID
  let bootGeneration: String
  let beganNanoseconds: UInt64
  let phase: ExternalMutationPhase
  let dispatchedNanoseconds: UInt64?
  let completionNanoseconds: UInt64?

  init(_ state: ExternalMutationRecoveryState) {
    operationID = state.operationID
    bootGeneration = state.bootGeneration
    beganNanoseconds = state.beganNanoseconds
    phase = state.phase
    dispatchedNanoseconds = state.dispatchedNanoseconds
    completionNanoseconds = state.completionNanoseconds
  }

  init(
    operationID: UUID,
    bootGeneration: String,
    beganNanoseconds: UInt64,
    phase: ExternalMutationPhase,
    dispatchedNanoseconds: UInt64?,
    completionNanoseconds: UInt64?
  ) {
    self.operationID = operationID
    self.bootGeneration = bootGeneration
    self.beganNanoseconds = beganNanoseconds
    self.phase = phase
    self.dispatchedNanoseconds = dispatchedNanoseconds
    self.completionNanoseconds = completionNanoseconds
  }

  func validate() throws {
    guard try normalizeBootGeneration(bootGeneration) == bootGeneration,
      beganNanoseconds > 0,
      phase == .dispatched || phase == .originalSucceeded,
      dispatchedNanoseconds != nil,
      dispatchedNanoseconds! >= beganNanoseconds,
      (phase == .originalSucceeded) == (completionNanoseconds != nil),
      completionNanoseconds == nil || completionNanoseconds! >= dispatchedNanoseconds!
    else { throw ExternalMutationJournalError.malformedState }
  }
}

private struct ExternalPendingMutation: Codable, Equatable, Sendable {
  let state: ExternalMutationRecoveryState
}

private struct ExternalPendingRunGate: Codable, Equatable, Sendable {
  let version: Int
  let binding: ExternalMutationRunBinding
  let mutations: [ExternalPendingMutation]
  let updatedNanoseconds: UInt64

  init(
    binding: ExternalMutationRunBinding,
    states: [ExternalMutationRecoveryState],
    updatedNanoseconds: UInt64
  ) {
    version = 1
    self.binding = binding
    mutations = states.sorted { $0.kind.rawValue < $1.kind.rawValue }.map {
      ExternalPendingMutation(state: $0)
    }
    self.updatedNanoseconds = updatedNanoseconds
  }

  func validate(expectedBinding: ExternalMutationRunBinding, runDirectory: URL) throws {
    try binding.validate(runDirectory: runDirectory)
    guard version == 1, binding == expectedBinding, updatedNanoseconds > 0,
      mutations.count <= ExternalMutationKind.allCases.count
    else { throw ExternalMutationJournalError.malformedState }
    var kinds = Set<ExternalMutationKind>()
    for mutation in mutations {
      try mutation.state.validate(expectedBinding: expectedBinding, runDirectory: runDirectory)
      guard kinds.insert(mutation.state.kind).inserted else {
        throw ExternalMutationJournalError.malformedState
      }
    }
  }
}

public enum ExternalMutationJournalError: Error, Equatable, Sendable {
  case unsafeDirectory
  case bindingMismatch
  case identityChanged
  case contentChanged
  case accessPolicyChanged
  case malformedState
  case stateMismatch
  case invalidTransition
  case unresolvedExternalMutation(ExternalMutationKind, bootGeneration: String)
  case operationFailed(String, errno: Int32)
}

enum ExternalMutationJournalFailureInjection: Equatable, Sendable {
  case none
  case afterGateBeforeState
  case afterStateBeforeGate
  case afterResolutionGateBeforeStateRemoval
}

/// Durable host-global ambiguity evidence. A same-boot add whose original completion was not
/// durably observed is intentionally not resolved by absence polling or compensating removal.
public struct ExternalMutationJournal: Sendable {
  private static let gateName = ".fileprovider-pending-run.json"

  public let runDirectory: URL
  public let binding: ExternalMutationRunBinding
  public let currentBootGeneration: String
  private let failureInjection: ExternalMutationJournalFailureInjection
  private let afterInitialRecordRead:
    @Sendable (_ directory: Int32, _ name: String, _ descriptor: Int32) throws -> Void

  public init(
    runDirectory: URL,
    binding: ExternalMutationRunBinding,
    currentBootGeneration: String
  ) throws {
    try self.init(
      runDirectory: runDirectory,
      binding: binding,
      currentBootGeneration: currentBootGeneration,
      failureInjection: .none,
      afterInitialRecordRead: { _, _, _ in }
    )
  }

  init(
    runDirectory: URL,
    binding: ExternalMutationRunBinding,
    currentBootGeneration: String,
    failureInjection: ExternalMutationJournalFailureInjection,
    afterInitialRecordRead:
      @escaping @Sendable (
        _ directory: Int32,
        _ name: String,
        _ descriptor: Int32
      ) throws -> Void = { _, _, _ in }
  ) throws {
    self.runDirectory = runDirectory
    self.binding = binding
    self.currentBootGeneration = try normalizeBootGeneration(currentBootGeneration)
    self.failureInjection = failureInjection
    self.afterInitialRecordRead = afterInitialRecordRead
    try binding.validate(runDirectory: runDirectory)
  }

  public func begin(
    _ kind: ExternalMutationKind,
    nowNanoseconds: UInt64 = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
  ) throws {
    try finalizeProvablyInactive()
    var records = try loadRecords()
    if records[kind] != nil { return }
    let state = ExternalMutationRecoveryState(
      binding: binding,
      kind: kind,
      bootGeneration: currentBootGeneration,
      nowNanoseconds: nowNanoseconds
    )
    records[kind] = state
    try publishGate(records, nowNanoseconds: nowNanoseconds)
    if failureInjection == .afterGateBeforeState {
      throw ExternalMutationJournalError.operationFailed("injected-after-gate", errno: EIO)
    }
    try publishState(state)
  }

  /// Removal retries replace the leaf operation only after carrying every potentially active
  /// predecessor into the successor. Add operations never use this API.
  public func beginRemovalAttempt(
    _ kind: ExternalMutationKind,
    nowNanoseconds: UInt64 = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
  ) throws {
    guard !kind.isAdd else { throw ExternalMutationJournalError.invalidTransition }
    try finalizeProvablyInactive()
    var records = try loadRecords()
    let predecessors = records[kind]?.unresolvedRemovalOperations ?? []
    guard predecessors.count <= ExternalMutationRecoveryState.maximumPredecessors else {
      throw ExternalMutationJournalError.unresolvedExternalMutation(
        kind,
        bootGeneration: records[kind]?.bootGeneration ?? currentBootGeneration
      )
    }
    let state = ExternalMutationRecoveryState(
      binding: binding,
      kind: kind,
      predecessorStates: predecessors,
      bootGeneration: currentBootGeneration,
      nowNanoseconds: nowNanoseconds
    )
    records[kind] = state
    try publishGate(records, nowNanoseconds: nowNanoseconds)
    if failureInjection == .afterGateBeforeState {
      throw ExternalMutationJournalError.operationFailed("injected-after-gate", errno: EIO)
    }
    try publishState(state)
  }

  public func markDispatched(
    _ kind: ExternalMutationKind,
    nowNanoseconds: UInt64 = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
  ) throws {
    var records = try loadRecords()
    guard var state = records[kind] else { throw ExternalMutationJournalError.stateMismatch }
    try state.markDispatched(at: nowNanoseconds)
    records[kind] = state
    try publishGate(records, nowNanoseconds: nowNanoseconds)
    if failureInjection == .afterGateBeforeState {
      throw ExternalMutationJournalError.operationFailed("injected-after-dispatch-gate", errno: EIO)
    }
    try publishState(state)
  }

  public func recordOriginalCompletion(
    _ kind: ExternalMutationKind,
    completion: ExternalMutationCompletion,
    nowNanoseconds: UInt64 = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
  ) throws {
    var records = try loadRecords()
    guard var state = records[kind] else { throw ExternalMutationJournalError.stateMismatch }
    try state.recordCompletion(completion, at: nowNanoseconds)
    records[kind] = state
    try publishState(state)
    if failureInjection == .afterStateBeforeGate {
      throw ExternalMutationJournalError.operationFailed(
        "injected-after-completion-state", errno: EIO)
    }
    try publishGate(records, nowNanoseconds: nowNanoseconds)
    if completion == .failed, state.unresolvedPredecessors.isEmpty {
      try resolve(kinds: [kind], from: records)
    }
  }

  public func confirmFinished(
    _ kind: ExternalMutationKind,
    observed presence: ExternalMutationPresence
  ) throws {
    try finalizeProvablyInactive()
    let records = try loadRecords()
    guard let state = records[kind], state.phase == .originalSucceeded,
      presence == kind.terminalPresence
    else { throw ExternalMutationJournalError.stateMismatch }
    var resolved: Set<ExternalMutationKind> = [kind]
    if let addKind = kind.compensatedAdd, let add = records[addKind] {
      if add.phase == .originalSucceeded || add.bootGeneration != currentBootGeneration {
        resolved.insert(addKind)
      }
    }
    try resolve(kinds: resolved, from: records)
  }

  @discardableResult
  public func resolveAfterBootIfTerminal(
    _ kind: ExternalMutationKind,
    observed presence: ExternalMutationPresence
  ) throws -> Bool {
    try finalizeProvablyInactive()
    let records = try loadRecords()
    guard let state = records[kind] else { return true }
    guard state.canResolveAcrossBoot(currentBootGeneration) else { return false }
    let terminalAfterReboot = kind.isAdd ? presence == .absent : presence == kind.terminalPresence
    guard terminalAfterReboot else { return false }
    try resolve(kinds: [kind], from: records)
    return true
  }

  public func pendingKinds() throws -> [ExternalMutationKind] {
    try finalizeProvablyInactive()
    return try loadRecords().keys.sorted { $0.rawValue < $1.rawValue }
  }

  public func state(_ kind: ExternalMutationKind) throws -> ExternalMutationRecoveryState? {
    try finalizeProvablyInactive()
    return try loadRecords()[kind]
  }

  public func requireClear() throws {
    try finalizeProvablyInactive()
    let records = try loadRecords()
    if let unresolved = records.values.sorted(by: { $0.kind.rawValue < $1.kind.rawValue }).first {
      throw ExternalMutationJournalError.unresolvedExternalMutation(
        unresolved.kind,
        bootGeneration: unresolved.bootGeneration
      )
    }
    try removeEmptyGateIfPresent()
  }

  public func requireNoSameBootAmbiguousAdd() throws {
    try finalizeProvablyInactive()
    for state in try loadRecords().values where state.kind.isAdd {
      if state.bootGeneration == currentBootGeneration, state.phase == .dispatched {
        throw ExternalMutationJournalError.unresolvedExternalMutation(
          state.kind,
          bootGeneration: state.bootGeneration
        )
      }
    }
  }

  private func finalizeProvablyInactive() throws {
    let records = try loadRecords()
    let inactive = Set(
      records.values.compactMap { state -> ExternalMutationKind? in
        switch state.phase {
        case .prepared, .originalFailed:
          state.hasPotentialLateEffect ? nil : state.kind
        case .dispatched, .originalSucceeded: nil
        }
      })
    if !inactive.isEmpty { try resolve(kinds: inactive, from: records) }
    if try loadRecords().isEmpty { try removeEmptyGateIfPresent() }
  }

  private func resolve(
    kinds: Set<ExternalMutationKind>,
    from existing: [ExternalMutationKind: ExternalMutationRecoveryState]
  ) throws {
    var remaining = existing
    for kind in kinds { remaining.removeValue(forKey: kind) }
    try publishGate(remaining, nowNanoseconds: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW))
    if failureInjection == .afterResolutionGateBeforeStateRemoval {
      throw ExternalMutationJournalError.operationFailed(
        "injected-before-state-removal", errno: EIO)
    }
    for kind in kinds { try removeRecord(fileName(kind)) }
    if remaining.isEmpty { try removeRecord(Self.gateName) }
  }

  private func loadRecords() throws -> [ExternalMutationKind: ExternalMutationRecoveryState] {
    var records: [ExternalMutationKind: ExternalMutationRecoveryState] = [:]
    if let gate: ExternalPendingRunGate = try readRecord(Self.gateName) {
      try gate.validate(expectedBinding: binding, runDirectory: runDirectory)
      for mutation in gate.mutations { records[mutation.state.kind] = mutation.state }
    }
    for kind in ExternalMutationKind.allCases {
      guard let state: ExternalMutationRecoveryState = try readRecord(fileName(kind)) else {
        continue
      }
      try state.validate(expectedBinding: binding, runDirectory: runDirectory)
      if let existing = records[kind] {
        records[kind] = try existing.merging(state)
      } else {
        records[kind] = state
      }
    }
    return records
  }

  private func publishGate(
    _ records: [ExternalMutationKind: ExternalMutationRecoveryState],
    nowNanoseconds: UInt64
  ) throws {
    try publish(
      ExternalPendingRunGate(
        binding: binding,
        states: Array(records.values),
        updatedNanoseconds: max(nowNanoseconds, 1)
      ),
      name: Self.gateName
    )
  }

  private func publishState(_ state: ExternalMutationRecoveryState) throws {
    try publish(state, name: fileName(state.kind))
  }

  private func publish<T: Encodable>(_ value: T, name: String) throws {
    let encoder = JSONEncoder()
    encoder.outputFormatting = [.sortedKeys]
    let data = try encoder.encode(value)
    guard data.count <= SecureFixtureStorage.maximumControlBytes else {
      throw ExternalMutationJournalError.malformedState
    }
    let directory = try openJournalDirectory()
    defer { close(directory) }
    try requireSafeExistingDestination(directory: directory, name: name)
    let temporary = ".external-mutation-publish-\(UUID().uuidString.lowercased())"
    let descriptor = openat(
      directory,
      temporary,
      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
      0o600
    )
    guard descriptor >= 0 else {
      throw ExternalMutationJournalError.operationFailed("create-state", errno: errno)
    }
    var removeTemporary = true
    defer {
      close(descriptor)
      if removeTemporary { _ = unlinkat(directory, temporary, 0) }
    }
    try requirePrivateRegularFile(descriptor)
    try writeAll(data, descriptor: descriptor)
    guard fsync(descriptor) == 0 else {
      throw ExternalMutationJournalError.operationFailed("sync-state", errno: errno)
    }
    guard renameat(directory, temporary, directory, name) == 0 else {
      throw ExternalMutationJournalError.operationFailed("publish-state", errno: errno)
    }
    removeTemporary = false
    guard fsync(directory) == 0 else {
      throw ExternalMutationJournalError.operationFailed("sync-state-parent", errno: errno)
    }
  }

  private func readRecord<T: Decodable>(_ name: String) throws -> T? {
    let directory = try openJournalDirectory()
    defer { close(directory) }
    let descriptor = openat(
      directory,
      name,
      O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
    )
    guard descriptor >= 0 else {
      if errno == ENOENT { return nil }
      throw ExternalMutationJournalError.operationFailed("open-state", errno: errno)
    }
    defer { close(descriptor) }
    var before = stat()
    guard fstat(descriptor, &before) == 0 else {
      throw ExternalMutationJournalError.operationFailed("stat-state", errno: errno)
    }
    try requirePrivateRegularFile(descriptor, metadata: before)
    guard before.st_size >= 0, before.st_size <= SecureFixtureStorage.maximumControlBytes else {
      throw ExternalMutationJournalError.malformedState
    }
    let first = try readExact(descriptor: descriptor, size: Int(before.st_size))
    try afterInitialRecordRead(directory, name, descriptor)
    guard lseek(descriptor, 0, SEEK_SET) == 0 else {
      throw ExternalMutationJournalError.operationFailed("rewind-state", errno: errno)
    }
    let second = try readExact(descriptor: descriptor, size: Int(before.st_size))
    guard first == second else { throw ExternalMutationJournalError.contentChanged }
    var after = stat()
    guard fstat(descriptor, &after) == 0 else {
      throw ExternalMutationJournalError.operationFailed("restat-state", errno: errno)
    }
    try requireSameMutationRecordObject(before, after)
    guard before.st_size == after.st_size else {
      throw ExternalMutationJournalError.contentChanged
    }
    var stableData = second
    var stableMetadata = after
    if mutationRecordMetadataChanged(before, after) {
      guard after.st_size >= 0, after.st_size <= SecureFixtureStorage.maximumControlBytes else {
        throw ExternalMutationJournalError.malformedState
      }
      guard lseek(descriptor, 0, SEEK_SET) == 0 else {
        throw ExternalMutationJournalError.operationFailed(
          "rewind-state-revalidation", errno: errno)
      }
      let third = try readExact(descriptor: descriptor, size: Int(after.st_size))
      var final = stat()
      guard fstat(descriptor, &final) == 0 else {
        throw ExternalMutationJournalError.operationFailed("final-restat-state", errno: errno)
      }
      try requireSameMutationRecordObject(after, final)
      guard after.st_size == final.st_size, second == third else {
        throw ExternalMutationJournalError.contentChanged
      }
      stableData = third
      stableMetadata = final
    }
    try requireMutationJournalNoExtendedACL(descriptor)
    var current = stat()
    guard fstatat(directory, name, &current, AT_SYMLINK_NOFOLLOW) == 0 else {
      throw ExternalMutationJournalError.identityChanged
    }
    try requireSameMutationRecordObject(stableMetadata, current)
    guard let decoded = try? JSONDecoder().decode(T.self, from: stableData) else {
      throw ExternalMutationJournalError.malformedState
    }
    return decoded
  }

  private func removeEmptyGateIfPresent() throws {
    guard let gate: ExternalPendingRunGate = try readRecord(Self.gateName) else { return }
    try gate.validate(expectedBinding: binding, runDirectory: runDirectory)
    guard gate.mutations.isEmpty else { return }
    try removeRecord(Self.gateName)
  }

  private func removeRecord(_ name: String) throws {
    let directory = try openJournalDirectory()
    defer { close(directory) }
    guard let descriptor = try openVerifiedRecord(directory: directory, name: name) else { return }
    defer { close(descriptor) }
    guard unlinkat(directory, name, 0) == 0 else {
      if errno == ENOENT { return }
      throw ExternalMutationJournalError.operationFailed("remove-state", errno: errno)
    }
    guard fsync(directory) == 0 else {
      throw ExternalMutationJournalError.operationFailed("sync-state-removal", errno: errno)
    }
  }

  private func requireSafeExistingDestination(directory: Int32, name: String) throws {
    guard let descriptor = try openVerifiedRecord(directory: directory, name: name) else { return }
    close(descriptor)
  }

  private func openVerifiedRecord(directory: Int32, name: String) throws -> Int32? {
    let descriptor = openat(
      directory,
      name,
      O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
    )
    guard descriptor >= 0 else {
      if errno == ENOENT { return nil }
      throw ExternalMutationJournalError.operationFailed("open-state-mutation", errno: errno)
    }
    do {
      var metadata = stat()
      guard fstat(descriptor, &metadata) == 0 else {
        throw ExternalMutationJournalError.operationFailed("stat-state-mutation", errno: errno)
      }
      try requirePrivateRegularFile(descriptor, metadata: metadata)
      var current = stat()
      guard fstatat(directory, name, &current, AT_SYMLINK_NOFOLLOW) == 0,
        current.st_dev == metadata.st_dev, current.st_ino == metadata.st_ino
      else { throw ExternalMutationJournalError.identityChanged }
      guard current.st_uid == metadata.st_uid, current.st_mode == metadata.st_mode else {
        throw ExternalMutationJournalError.accessPolicyChanged
      }
      return descriptor
    } catch {
      close(descriptor)
      throw error
    }
  }

  private func openJournalDirectory() throws -> Int32 {
    let url = runDirectory.deletingLastPathComponent()
    let component = runDirectory.lastPathComponent
    guard runDirectory.isFileURL, UUID(uuidString: component) != nil,
      component == component.lowercased()
    else { throw ExternalMutationJournalError.unsafeDirectory }
    let descriptor = open(url.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    guard descriptor >= 0 else {
      throw ExternalMutationJournalError.operationFailed("open-state-parent", errno: errno)
    }
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0 else {
      let code = errno
      close(descriptor)
      throw ExternalMutationJournalError.operationFailed("stat-state-parent", errno: code)
    }
    guard metadata.st_uid == geteuid(), metadata.st_mode & S_IFMT == S_IFDIR,
      metadata.st_mode & 0o077 == 0
    else {
      close(descriptor)
      throw ExternalMutationJournalError.accessPolicyChanged
    }
    do {
      try requireMutationJournalNoExtendedACL(descriptor)
    } catch {
      close(descriptor)
      throw error
    }
    var current = stat()
    guard lstat(url.path, &current) == 0 else {
      close(descriptor)
      throw ExternalMutationJournalError.identityChanged
    }
    guard current.st_dev == metadata.st_dev, current.st_ino == metadata.st_ino else {
      close(descriptor)
      throw ExternalMutationJournalError.identityChanged
    }
    guard current.st_uid == metadata.st_uid, current.st_mode == metadata.st_mode else {
      close(descriptor)
      throw ExternalMutationJournalError.accessPolicyChanged
    }
    return descriptor
  }

  private var runIDComponent: String { runDirectory.lastPathComponent.lowercased() }

  private func fileName(_ kind: ExternalMutationKind) -> String {
    ".external-mutation-\(runIDComponent)-\(kind.rawValue).json"
  }
}

private func normalizeBootGeneration(_ value: String) throws -> String {
  guard let parsed = UUID(uuidString: value) else {
    throw ExternalMutationJournalError.malformedState
  }
  return parsed.uuidString.lowercased()
}

private func requireSameMutationRecordObject(_ expected: stat, _ observed: stat) throws {
  guard expected.st_dev == observed.st_dev, expected.st_ino == observed.st_ino else {
    throw ExternalMutationJournalError.identityChanged
  }
  guard expected.st_uid == observed.st_uid, expected.st_gid == observed.st_gid,
    expected.st_mode == observed.st_mode
  else { throw ExternalMutationJournalError.accessPolicyChanged }
}

private func mutationRecordMetadataChanged(_ expected: stat, _ observed: stat) -> Bool {
  expected.st_size != observed.st_size
    || expected.st_mtimespec.tv_sec != observed.st_mtimespec.tv_sec
    || expected.st_mtimespec.tv_nsec != observed.st_mtimespec.tv_nsec
    || expected.st_ctimespec.tv_sec != observed.st_ctimespec.tv_sec
    || expected.st_ctimespec.tv_nsec != observed.st_ctimespec.tv_nsec
}

private func requirePrivateRegularFile(_ descriptor: Int32, metadata supplied: stat? = nil) throws {
  var metadata = supplied ?? stat()
  if supplied == nil, fstat(descriptor, &metadata) != 0 {
    throw ExternalMutationJournalError.operationFailed("stat-state-file", errno: errno)
  }
  guard metadata.st_uid == geteuid(), metadata.st_mode & S_IFMT == S_IFREG,
    metadata.st_mode & 0o077 == 0
  else { throw ExternalMutationJournalError.accessPolicyChanged }
  try requireMutationJournalNoExtendedACL(descriptor)
}

private func requireMutationJournalNoExtendedACL(_ descriptor: Int32) throws {
  errno = 0
  guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
    if errno == ENOENT { return }
    throw ExternalMutationJournalError.operationFailed(
      "inspect-extended-acl",
      errno: errno == 0 ? EIO : errno
    )
  }
  acl_free(UnsafeMutableRawPointer(acl))
  throw ExternalMutationJournalError.accessPolicyChanged
}

private func writeAll(_ data: Data, descriptor: Int32) throws {
  try data.withUnsafeBytes { bytes in
    var remaining = bytes.count
    var pointer = bytes.baseAddress!
    while remaining > 0 {
      let written = Darwin.write(descriptor, pointer, remaining)
      if written < 0, errno == EINTR { continue }
      guard written > 0 else {
        throw ExternalMutationJournalError.operationFailed(
          "write-state", errno: errno == 0 ? EIO : errno)
      }
      remaining -= written
      pointer = pointer.advanced(by: written)
    }
  }
}

private func readExact(descriptor: Int32, size: Int) throws -> Data {
  var data = Data()
  data.reserveCapacity(size)
  var buffer = [UInt8](repeating: 0, count: 4_096)
  while data.count < size {
    let count = buffer.withUnsafeMutableBytes { bytes in
      read(descriptor, bytes.baseAddress, min(bytes.count, size - data.count))
    }
    if count < 0, errno == EINTR { continue }
    if count == 0 { throw ExternalMutationJournalError.contentChanged }
    guard count > 0 else {
      throw ExternalMutationJournalError.operationFailed(
        "read-state", errno: errno == 0 ? EIO : errno)
    }
    data.append(contentsOf: buffer[0..<count])
  }
  var probe = UInt8(0)
  let trailing = Darwin.read(descriptor, &probe, 1)
  guard trailing == 0 else {
    if trailing < 0 {
      throw ExternalMutationJournalError.operationFailed("read-state-trailing", errno: errno)
    }
    throw ExternalMutationJournalError.contentChanged
  }
  return data
}
