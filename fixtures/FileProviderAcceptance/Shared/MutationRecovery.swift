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

  fileprivate var compensatedKind: ExternalMutationKind? {
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

public enum ExternalMutationObservationResult: Equatable, Sendable {
  case pending
  case stableTerminal
}

/// A pure, persisted reconciliation state machine for an external mutation whose completion can
/// outlive the initiating process. An absence is terminal only after repeated observations span a
/// minimum quiet interval; any contradictory observation resets that proof.
public struct ExternalMutationRecoveryState: Codable, Equatable, Sendable {
  public let kind: ExternalMutationKind
  public let operationID: UUID
  public let beganNanoseconds: UInt64
  public private(set) var consecutiveTerminalObservations: Int
  public private(set) var firstTerminalObservationNanoseconds: UInt64?

  public init(kind: ExternalMutationKind, operationID: UUID = UUID(), nowNanoseconds: UInt64) {
    self.kind = kind
    self.operationID = operationID
    beganNanoseconds = nowNanoseconds
    consecutiveTerminalObservations = 0
    firstTerminalObservationNanoseconds = nil
  }

  public mutating func observe(
    _ presence: ExternalMutationPresence,
    nowNanoseconds: UInt64,
    requiredConsecutiveObservations: Int = 3,
    minimumStableNanoseconds: UInt64 = 1_000_000_000
  ) -> ExternalMutationObservationResult {
    precondition(requiredConsecutiveObservations >= 2)
    if presence != kind.terminalPresence {
      consecutiveTerminalObservations = 0
      firstTerminalObservationNanoseconds = nil
      return .pending
    }
    if let first = firstTerminalObservationNanoseconds, nowNanoseconds >= first {
      consecutiveTerminalObservations += 1
      if consecutiveTerminalObservations >= requiredConsecutiveObservations,
        nowNanoseconds - first >= minimumStableNanoseconds
      {
        return .stableTerminal
      }
    } else {
      consecutiveTerminalObservations = 1
      firstTerminalObservationNanoseconds = nowNanoseconds
    }
    return .pending
  }
}

public enum ExternalMutationJournalError: Error, Equatable, Sendable {
  case unsafeDirectory
  case malformedState
  case stateMismatch
  case operationFailed(String, errno: Int32)
}

/// Durable ambiguity evidence stored beside, rather than inside, the run directory so cleanup
/// cannot accidentally erase an unresolved external mutation.
public struct ExternalMutationJournal: Sendable {
  public let runDirectory: URL

  public init(runDirectory: URL) { self.runDirectory = runDirectory }

  public func begin(
    _ kind: ExternalMutationKind,
    nowNanoseconds: UInt64 = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW)
  ) throws {
    if try load(kind) != nil { return }
    try publish(ExternalMutationRecoveryState(kind: kind, nowNanoseconds: nowNanoseconds))
  }

  public func confirmFinished(
    _ kind: ExternalMutationKind,
    observed presence: ExternalMutationPresence
  ) throws {
    guard presence == kind.terminalPresence, try load(kind) != nil else {
      throw ExternalMutationJournalError.stateMismatch
    }
    try remove(kind)
    if let compensated = kind.compensatedKind {
      try remove(compensated)
    }
  }

  @discardableResult
  public func observe(
    _ kind: ExternalMutationKind,
    presence: ExternalMutationPresence,
    nowNanoseconds: UInt64 = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW),
    requiredConsecutiveObservations: Int = 3,
    minimumStableNanoseconds: UInt64 = 1_000_000_000
  ) throws -> ExternalMutationObservationResult {
    guard var state = try load(kind) else {
      throw ExternalMutationJournalError.stateMismatch
    }
    let result = state.observe(
      presence,
      nowNanoseconds: nowNanoseconds,
      requiredConsecutiveObservations: requiredConsecutiveObservations,
      minimumStableNanoseconds: minimumStableNanoseconds
    )
    if result == .stableTerminal {
      try remove(kind)
      if let compensated = kind.compensatedKind {
        try remove(compensated)
      }
    } else {
      try publish(state)
    }
    return result
  }

  public func pendingKinds() throws -> [ExternalMutationKind] {
    try ExternalMutationKind.allCases.filter { try load($0) != nil }
  }

  public func requireClear() throws {
    guard try pendingKinds().isEmpty else { throw ExternalMutationJournalError.stateMismatch }
  }

  func load(_ kind: ExternalMutationKind) throws -> ExternalMutationRecoveryState? {
    let directory = try openJournalDirectory()
    defer { close(directory) }
    let descriptor = openat(directory, fileName(kind), O_RDONLY | O_CLOEXEC | O_NOFOLLOW)
    guard descriptor >= 0 else {
      if errno == ENOENT { return nil }
      throw ExternalMutationJournalError.operationFailed("open-state", errno: errno)
    }
    defer { close(descriptor) }
    var before = stat()
    guard fstat(descriptor, &before) == 0 else {
      throw ExternalMutationJournalError.operationFailed("stat-state", errno: errno)
    }
    guard before.st_uid == geteuid(), before.st_mode & S_IFMT == S_IFREG,
      before.st_mode & 0o077 == 0, before.st_size >= 0,
      before.st_size <= SecureFixtureStorage.maximumControlBytes
    else { throw ExternalMutationJournalError.malformedState }
    try requireMutationJournalNoExtendedACL(descriptor)
    var data = Data()
    data.reserveCapacity(Int(before.st_size))
    var buffer = [UInt8](repeating: 0, count: 4_096)
    while data.count < Int(before.st_size) {
      let count = buffer.withUnsafeMutableBytes { bytes in
        read(descriptor, bytes.baseAddress, min(bytes.count, Int(before.st_size) - data.count))
      }
      if count < 0, errno == EINTR { continue }
      guard count > 0 else {
        throw ExternalMutationJournalError.operationFailed(
          "read-state",
          errno: errno == 0 ? EIO : errno
        )
      }
      data.append(contentsOf: buffer[0..<count])
    }
    var after = stat()
    guard fstat(descriptor, &after) == 0 else {
      throw ExternalMutationJournalError.operationFailed("restat-state", errno: errno)
    }
    guard before.st_dev == after.st_dev, before.st_ino == after.st_ino,
      before.st_size == after.st_size, before.st_mtimespec.tv_sec == after.st_mtimespec.tv_sec,
      before.st_mtimespec.tv_nsec == after.st_mtimespec.tv_nsec
    else { throw ExternalMutationJournalError.malformedState }
    try requireMutationJournalNoExtendedACL(descriptor)
    var current = stat()
    guard fstatat(directory, fileName(kind), &current, AT_SYMLINK_NOFOLLOW) == 0,
      current.st_dev == before.st_dev, current.st_ino == before.st_ino,
      current.st_uid == before.st_uid, current.st_mode == before.st_mode
    else { throw ExternalMutationJournalError.malformedState }
    guard let state = try? JSONDecoder().decode(ExternalMutationRecoveryState.self, from: data),
      state.kind == kind
    else { throw ExternalMutationJournalError.malformedState }
    return state
  }

  private func publish(_ state: ExternalMutationRecoveryState) throws {
    let data = try JSONEncoder().encode(state)
    guard data.count <= SecureFixtureStorage.maximumControlBytes else {
      throw ExternalMutationJournalError.malformedState
    }
    let directory = try openJournalDirectory()
    defer { close(directory) }
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
    try requireMutationJournalNoExtendedACL(descriptor)
    var removeTemporary = true
    defer {
      close(descriptor)
      if removeTemporary { _ = unlinkat(directory, temporary, 0) }
    }
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
    guard fsync(descriptor) == 0 else {
      throw ExternalMutationJournalError.operationFailed("sync-state", errno: errno)
    }
    guard renameat(directory, temporary, directory, fileName(state.kind)) == 0 else {
      throw ExternalMutationJournalError.operationFailed("publish-state", errno: errno)
    }
    removeTemporary = false
    guard fsync(directory) == 0 else {
      throw ExternalMutationJournalError.operationFailed("sync-state-parent", errno: errno)
    }
  }

  private func remove(_ kind: ExternalMutationKind) throws {
    let directory = try openJournalDirectory()
    defer { close(directory) }
    guard unlinkat(directory, fileName(kind), 0) == 0 else {
      if errno == ENOENT { return }
      throw ExternalMutationJournalError.operationFailed("remove-state", errno: errno)
    }
    guard fsync(directory) == 0 else {
      throw ExternalMutationJournalError.operationFailed("sync-state-removal", errno: errno)
    }
  }

  private func openJournalDirectory() throws -> Int32 {
    let url = runDirectory.deletingLastPathComponent()
    let component = runDirectory.lastPathComponent
    guard runDirectory.isFileURL, UUID(uuidString: component) != nil,
      component == component.lowercased()
    else {
      throw ExternalMutationJournalError.unsafeDirectory
    }
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
      throw ExternalMutationJournalError.unsafeDirectory
    }
    do {
      try requireMutationJournalNoExtendedACL(descriptor)
    } catch {
      close(descriptor)
      throw error
    }
    var current = stat()
    guard lstat(url.path, &current) == 0, current.st_dev == metadata.st_dev,
      current.st_ino == metadata.st_ino, current.st_uid == metadata.st_uid,
      current.st_mode == metadata.st_mode
    else {
      close(descriptor)
      throw ExternalMutationJournalError.unsafeDirectory
    }
    return descriptor
  }

  private var runIDComponent: String { runDirectory.lastPathComponent.lowercased() }

  private func fileName(_ kind: ExternalMutationKind) -> String {
    ".external-mutation-\(runIDComponent)-\(kind.rawValue).json"
  }
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
  throw ExternalMutationJournalError.unsafeDirectory
}
