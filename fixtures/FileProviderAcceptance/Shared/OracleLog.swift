import Darwin
import Foundation

public struct OracleLog: Sendable {
  public let runDirectory: URL

  public init(runDirectory: URL) { self.runDirectory = runDirectory }

  public static func appGroup(runID: UUID) throws -> OracleLog {
    guard
      let container = FileManager.default.containerURL(
        forSecurityApplicationGroupIdentifier: FixtureContract.appGroupIdentifier
      )
    else { throw FixtureContractError.unsafePath }
    return try OracleLog(
      runDirectory: FixtureContract.runDirectory(containerURL: container, runID: runID))
  }

  public func prepare() throws {
    let parent = runDirectory.deletingLastPathComponent()
    try makeOwnerPrivateDirectory(parent)
    try makeOwnerPrivateDirectory(runDirectory)
  }

  public func append(_ original: OracleEvent) throws {
    try prepare()
    let path = runDirectory.appendingPathComponent("events.jsonl").path
    let descriptor = open(path, O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW, 0o600)
    guard descriptor >= 0 else { throw makePOSIXError(code: errno) }
    defer { close(descriptor) }
    guard flock(descriptor, LOCK_EX) == 0 else { throw makePOSIXError(code: errno) }
    defer { flock(descriptor, LOCK_UN) }
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0 else { throw makePOSIXError(code: errno) }
    try validateOwnerPrivateRegularFile(metadata)
    guard metadata.st_size >= 0, metadata.st_size <= FixtureContract.maximumOracleBytes else {
      throw FixtureContractError.oracleTooLarge
    }
    let existing = try readAll(descriptor: descriptor, count: Int(metadata.st_size))
    let next = try nextSequence(existing)
    var event = original
    event.sequence = next
    var encoded = try JSONEncoder().encode(event)
    encoded.append(0x0a)
    guard existing.count + encoded.count <= FixtureContract.maximumOracleBytes else {
      throw FixtureContractError.oracleTooLarge
    }
    try encoded.withUnsafeBytes { bytes in
      var remaining = bytes.count
      var pointer = bytes.baseAddress!
      while remaining > 0 {
        let written = Darwin.write(descriptor, pointer, remaining)
        if written < 0, errno == EINTR { continue }
        guard written > 0 else { throw makePOSIXError(code: errno == 0 ? EIO : errno) }
        remaining -= written
        pointer = pointer.advanced(by: written)
      }
    }
  }

  public func events() throws -> [OracleEvent] {
    let url = runDirectory.appendingPathComponent("events.jsonl")
    let data: Data
    do {
      data = try SecureFixtureStorage.readControlFile(
        at: url,
        record: .events,
        maximumBytes: FixtureContract.maximumOracleBytes
      )
    } catch FixtureControlReadError.missing(.events) {
      return []
    }
    do {
      return try data.split(separator: 0x0a).map {
        try JSONDecoder().decode(OracleEvent.self, from: $0)
      }
    } catch {
      throw FixtureControlReadError.mismatch(.events, .malformed)
    }
  }

  public func writeWindow(_ window: OracleWindow) throws {
    try prepare()
    let destination = runDirectory.appendingPathComponent("window.json")
    let temporary = runDirectory.appendingPathComponent("window.json.tmp-\(UUID().uuidString)")
    try secureCreate(JSONEncoder().encode(window), at: temporary)
    guard rename(temporary.path, destination.path) == 0 else {
      throw makePOSIXError(code: errno)
    }
  }

  public func window() throws -> OracleWindow {
    try SecureFixtureStorage.readWindow(runDirectory: runDirectory)
  }

  public func closeWindowAfterQuiescence(
    quietMilliseconds: Int,
    timeoutMilliseconds: Int
  ) throws -> OracleQuiescence {
    guard quietMilliseconds >= 50, quietMilliseconds <= 5_000,
      timeoutMilliseconds >= quietMilliseconds, timeoutMilliseconds <= 30_000
    else { throw OracleQuiescenceError.invalidBounds }
    let openedWindow = try window()
    let start = monotonicNow()
    var quietStart = start
    var fingerprint = try eventFingerprint()
    while true {
      let now = monotonicNow()
      let current = try eventFingerprint()
      if current != fingerprint {
        fingerprint = current
        quietStart = now
      }
      if now - quietStart >= UInt64(quietMilliseconds) * 1_000_000 {
        try writeWindow(
          OracleWindow(beginNanoseconds: openedWindow.beginNanoseconds, endNanoseconds: now)
        )
        return OracleQuiescence(
          eventCount: current.count,
          lastSequence: current.lastSequence,
          quietMilliseconds: quietMilliseconds
        )
      }
      guard now - start < UInt64(timeoutMilliseconds) * 1_000_000 else {
        throw OracleQuiescenceError.timedOut
      }
      usleep(50_000)
    }
  }

  private func eventFingerprint() throws -> (count: Int, lastSequence: UInt64) {
    let values = try events()
    return (values.count, values.last?.sequence ?? 0)
  }
}

private func makeOwnerPrivateDirectory(_ url: URL) throws {
  if mkdir(url.path, 0o700) != 0, errno != EEXIST { throw makePOSIXError(code: errno) }
  var metadata = stat()
  guard lstat(url.path, &metadata) == 0 else { throw makePOSIXError(code: errno) }
  guard metadata.st_uid == geteuid(), metadata.st_mode & S_IFMT == S_IFDIR,
    metadata.st_mode & 0o077 == 0
  else { throw FixtureContractError.unsafePath }
}

private func validateOwnerPrivateRegularFile(_ metadata: stat) throws {
  guard metadata.st_uid == geteuid(), metadata.st_mode & S_IFMT == S_IFREG,
    metadata.st_mode & 0o077 == 0
  else { throw FixtureContractError.unsafePath }
}

private func secureCreate(_ data: Data, at url: URL) throws {
  let descriptor = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
  guard descriptor >= 0 else { throw makePOSIXError(code: errno) }
  defer { close(descriptor) }
  var metadata = stat()
  guard fstat(descriptor, &metadata) == 0 else { throw makePOSIXError(code: errno) }
  try validateOwnerPrivateRegularFile(metadata)
  try writeAll(data, descriptor: descriptor)
}

private func writeAll(_ data: Data, descriptor: Int32) throws {
  try data.withUnsafeBytes { bytes in
    var remaining = bytes.count
    var pointer = bytes.baseAddress!
    while remaining > 0 {
      let written = Darwin.write(descriptor, pointer, remaining)
      if written < 0, errno == EINTR { continue }
      guard written > 0 else { throw makePOSIXError(code: errno == 0 ? EIO : errno) }
      remaining -= written
      pointer = pointer.advanced(by: written)
    }
  }
}

private func readAll(descriptor: Int32, count: Int) throws -> Data {
  guard count > 0 else { return Data() }
  var result = Data(count: count)
  try result.withUnsafeMutableBytes { bytes in
    var offset = 0
    while offset < count {
      let received = pread(
        descriptor, bytes.baseAddress!.advanced(by: offset), count - offset, off_t(offset))
      if received < 0, errno == EINTR { continue }
      guard received > 0 else { throw makePOSIXError(code: errno == 0 ? EIO : errno) }
      offset += received
    }
  }
  return result
}

private func nextSequence(_ data: Data) throws -> UInt64 {
  guard let last = data.split(separator: 0x0a).last else { return 1 }
  let event = try JSONDecoder().decode(OracleEvent.self, from: last)
  guard event.sequence < UInt64.max else { throw FixtureContractError.oracleTooLarge }
  return event.sequence + 1
}

private func makePOSIXError(code: Int32) -> POSIXError {
  POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
}

private func monotonicNow() -> UInt64 { clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) }
