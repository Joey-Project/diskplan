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
    let directory = try openExistingRunDirectory(runDirectory)
    defer { close(directory) }
    let lock = openat(
      directory,
      "recorder.lock",
      O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
      0o600
    )
    guard lock >= 0 else { throw makePOSIXError(code: errno) }
    defer { close(lock) }
    try validateOwnerPrivateRegularFile(descriptor: lock)
  }

  public func append(_ original: OracleEvent) throws {
    try append(original, injecting: nil)
  }

  func append(
    _ original: OracleEvent,
    injecting failure: OracleAppendInjectedFailure?
  ) throws {
    let clock = SystemOracleQuiescenceClock()
    let (deadline, overflow) = clock.nowNanoseconds().addingReportingOverflow(30_000_000_000)
    guard !overflow else { throw OracleRecorderError.lockTimedOut }
    try append(
      original,
      injecting: failure,
      deadlineNanoseconds: deadline,
      clock: clock
    )
  }

  func append(
    _ original: OracleEvent,
    injecting failure: OracleAppendInjectedFailure?,
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock
  ) throws {
    try withRecorderLock(
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .recorder
    ) { directory in
      guard try lockedRecorderState(directory: directory) == .healthy else {
        throw try recorderError(directory: directory)
      }
      try createRecorderMarker(
        "recorder-poisoned",
        directory: directory,
        failBeforeSync: failure == .poisonStorage
      )
      do {
        let descriptor = openat(
          directory,
          "events.jsonl",
          O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
          0o600
        )
        guard descriptor >= 0 else { throw makePOSIXError(code: errno) }
        defer { close(descriptor) }
        try validateOwnerPrivateRegularFile(descriptor: descriptor)
        try acquireBoundedLock(
          descriptor,
          deadlineNanoseconds: deadlineNanoseconds,
          clock: clock,
          timeout: .recorder
        )
        defer { flock(descriptor, LOCK_UN) }
        var metadata = stat()
        guard fstat(descriptor, &metadata) == 0 else { throw makePOSIXError(code: errno) }
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
        try writeAll(encoded, descriptor: descriptor)
        if failure == .eventStorage { throw OracleAppendInjectedFailure.eventStorage }
        guard fsync(descriptor) == 0 else { throw makePOSIXError(code: errno) }
        try removeRecorderMarker("recorder-poisoned", directory: directory)
      } catch {
        throw error
      }
    }
  }

  public func recorderState() throws -> OracleRecorderState {
    try withRecorderLock { try lockedRecorderState(directory: $0) }
  }

  func recorderState(
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock
  ) throws -> OracleRecorderState {
    try withRecorderLock(
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .recorder
    ) { try lockedRecorderState(directory: $0) }
  }

  public func poisonRecorder() throws {
    try withRecorderLock { try createRecorderMarker("recorder-poisoned", directory: $0) }
  }

  public func failRecorder() throws {
    let directory = try openExistingRunDirectory(runDirectory)
    defer { close(directory) }
    try createRecorderMarker("recorder-failed", directory: directory)
  }

  func poisonRecorder(
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock
  ) throws {
    try withRecorderLock(
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .recorder
    ) { try createRecorderMarker("recorder-poisoned", directory: $0) }
  }

  public func sealRecorder() throws {
    try withRecorderLock { try createRecorderMarker("recorder-sealed", directory: $0) }
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

  public func sealedSnapshot() throws -> OracleSealedSnapshot {
    try withRecorderLock { directory in
      guard try lockedRecorderState(directory: directory) == .sealed else {
        throw try recorderError(directory: directory)
      }
      return try OracleSealedSnapshot(
        window: window(),
        events: lockedEvents(directory: directory)
      )
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
    try closeWindowAfterQuiescence(
      quietMilliseconds: quietMilliseconds,
      timeoutMilliseconds: timeoutMilliseconds,
      clock: SystemOracleQuiescenceClock()
    )
  }

  func closeWindowAfterQuiescence(
    quietMilliseconds: Int,
    timeoutMilliseconds: Int,
    clock: any OracleQuiescenceClock,
    onFinalSnapshotLocked: @Sendable () -> Void = {}
  ) throws -> OracleQuiescence {
    guard quietMilliseconds >= 50, quietMilliseconds <= 5_000,
      timeoutMilliseconds >= quietMilliseconds, timeoutMilliseconds <= 30_000
    else { throw OracleQuiescenceError.invalidBounds }
    let openedWindow = try window()
    let start = clock.nowNanoseconds()
    let (deadline, overflow) = start.addingReportingOverflow(
      UInt64(timeoutMilliseconds) * 1_000_000
    )
    guard !overflow else { throw OracleQuiescenceError.invalidBounds }
    var fingerprint = try eventFingerprint(deadlineNanoseconds: deadline, clock: clock)
    var quietStart = clock.nowNanoseconds()
    guard quietStart - start < UInt64(timeoutMilliseconds) * 1_000_000 else {
      throw OracleQuiescenceError.timedOut
    }
    while true {
      guard clock.nowNanoseconds() - start < UInt64(timeoutMilliseconds) * 1_000_000 else {
        throw OracleQuiescenceError.timedOut
      }
      let current = try eventFingerprint(deadlineNanoseconds: deadline, clock: clock)
      let now = clock.nowNanoseconds()
      guard now - start < UInt64(timeoutMilliseconds) * 1_000_000 else {
        throw OracleQuiescenceError.timedOut
      }
      if current != fingerprint {
        fingerprint = current
        quietStart = now
      }
      if now - quietStart >= UInt64(quietMilliseconds) * 1_000_000 {
        switch try sealWindowSnapshotIfQuiet(
          openedWindow: openedWindow,
          expectedFingerprint: current,
          quietStartNanoseconds: quietStart,
          quietMilliseconds: quietMilliseconds,
          deadlineNanoseconds: deadline,
          clock: clock,
          onFinalSnapshotLocked: onFinalSnapshotLocked
        ) {
        case .changed(let changed, let changedAt):
          fingerprint = changed
          quietStart = changedAt
        case .waiting:
          break
        case .sealed(let quiescence):
          return quiescence
        }
      }
      clock.sleepForPoll()
    }
  }

  private func sealWindowSnapshotIfQuiet(
    openedWindow: OracleWindow,
    expectedFingerprint: OracleEventFingerprint,
    quietStartNanoseconds: UInt64,
    quietMilliseconds: Int,
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock,
    onFinalSnapshotLocked: @Sendable () -> Void
  ) throws -> WindowSealAttempt {
    try withRecorderLock(
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .quiescence
    ) { directory in
      guard try lockedRecorderState(directory: directory) == .healthy else {
        throw try recorderError(directory: directory)
      }
      let values = try lockedEvents(directory: directory)
      let current = OracleEventFingerprint(
        count: values.count,
        lastSequence: values.last?.sequence ?? 0
      )
      let now = clock.nowNanoseconds()
      guard now < deadlineNanoseconds else { throw OracleQuiescenceError.timedOut }
      guard current == expectedFingerprint else { return .changed(current, now) }
      guard now >= quietStartNanoseconds,
        now - quietStartNanoseconds >= UInt64(quietMilliseconds) * 1_000_000
      else { return .waiting }
      onFinalSnapshotLocked()
      try writeWindow(
        OracleWindow(
          beginNanoseconds: openedWindow.beginNanoseconds,
          endNanoseconds: now,
          quietMilliseconds: quietMilliseconds,
          eventCount: current.count,
          lastSequence: current.lastSequence
        )
      )
      try createRecorderMarker("recorder-sealed", directory: directory)
      return .sealed(
        OracleQuiescence(
          eventCount: current.count,
          lastSequence: current.lastSequence,
          quietMilliseconds: quietMilliseconds
        )
      )
    }
  }

  private func eventFingerprint(
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock
  ) throws -> OracleEventFingerprint {
    try withRecorderLock(
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .quiescence
    ) { directory in
      guard try lockedRecorderState(directory: directory) == .healthy else {
        throw try recorderError(directory: directory)
      }
      let values = try lockedEvents(directory: directory)
      clock.didReadFingerprint()
      return OracleEventFingerprint(
        count: values.count,
        lastSequence: values.last?.sequence ?? 0
      )
    }
  }

  private func lockedEvents(directory: Int32) throws -> [OracleEvent] {
    let descriptor = openat(
      directory,
      "events.jsonl",
      O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
    )
    if descriptor < 0 {
      if errno == ENOENT { return [] }
      throw makePOSIXError(code: errno)
    }
    defer { close(descriptor) }
    try validateOwnerPrivateRegularFile(descriptor: descriptor)
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0 else { throw makePOSIXError(code: errno) }
    guard metadata.st_size >= 0, metadata.st_size <= FixtureContract.maximumOracleBytes else {
      throw FixtureContractError.oracleTooLarge
    }
    let data = try readAll(descriptor: descriptor, count: Int(metadata.st_size))
    do {
      return try data.split(separator: 0x0a).map {
        try JSONDecoder().decode(OracleEvent.self, from: $0)
      }
    } catch {
      throw FixtureControlReadError.mismatch(.events, .malformed)
    }
  }
}

private struct OracleEventFingerprint: Equatable {
  let count: Int
  let lastSequence: UInt64
}

private enum WindowSealAttempt {
  case changed(OracleEventFingerprint, UInt64)
  case waiting
  case sealed(OracleQuiescence)
}

protocol OracleQuiescenceClock: Sendable {
  func nowNanoseconds() -> UInt64
  func sleepForPoll()
  func didReadFingerprint()
}

extension OracleQuiescenceClock {
  func didReadFingerprint() {}
}

struct SystemOracleQuiescenceClock: OracleQuiescenceClock {
  func nowNanoseconds() -> UInt64 { clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) }
  func sleepForPoll() { usleep(50_000) }
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

private func validateOwnerPrivateRegularFile(descriptor: Int32) throws {
  var metadata = stat()
  guard fstat(descriptor, &metadata) == 0 else { throw makePOSIXError(code: errno) }
  try validateOwnerPrivateRegularFile(metadata)
}

private func openExistingRunDirectory(_ url: URL) throws -> Int32 {
  let descriptor = open(
    url.path,
    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
  )
  guard descriptor >= 0 else { throw makePOSIXError(code: errno) }
  var metadata = stat()
  guard fstat(descriptor, &metadata) == 0 else {
    let code = errno
    close(descriptor)
    throw makePOSIXError(code: code)
  }
  guard metadata.st_uid == geteuid(), metadata.st_mode & S_IFMT == S_IFDIR,
    metadata.st_mode & 0o077 == 0
  else {
    close(descriptor)
    throw FixtureContractError.unsafePath
  }
  return descriptor
}

extension OracleLog {
  fileprivate func withRecorderLock<Result>(
    _ body: (Int32) throws -> Result
  ) throws -> Result {
    let clock = SystemOracleQuiescenceClock()
    let (deadline, overflow) = clock.nowNanoseconds().addingReportingOverflow(30_000_000_000)
    guard !overflow else { throw OracleRecorderError.lockTimedOut }
    return try withRecorderLock(
      deadlineNanoseconds: deadline,
      clock: clock,
      timeout: .recorder,
      body
    )
  }

  fileprivate func withRecorderLock<Result>(
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock,
    timeout: RecorderLockTimeout,
    _ body: (Int32) throws -> Result
  ) throws -> Result {
    let directory = try openExistingRunDirectory(runDirectory)
    defer { close(directory) }
    let lock = openat(directory, "recorder.lock", O_RDWR | O_CLOEXEC | O_NOFOLLOW)
    guard lock >= 0 else { throw makePOSIXError(code: errno) }
    defer { close(lock) }
    try validateOwnerPrivateRegularFile(descriptor: lock)
    try acquireBoundedLock(
      lock,
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: timeout
    )
    defer { flock(lock, LOCK_UN) }
    let result = try body(directory)
    try requireLockDeadline(
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: timeout
    )
    return result
  }
}

private enum RecorderLockTimeout {
  case recorder
  case quiescence
}

private func acquireBoundedLock(
  _ descriptor: Int32,
  deadlineNanoseconds: UInt64,
  clock: any OracleQuiescenceClock,
  timeout: RecorderLockTimeout
) throws {
  while true {
    try requireLockDeadline(
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: timeout
    )
    if flock(descriptor, LOCK_EX | LOCK_NB) == 0 {
      do {
        try requireLockDeadline(
          deadlineNanoseconds: deadlineNanoseconds,
          clock: clock,
          timeout: timeout
        )
        return
      } catch {
        flock(descriptor, LOCK_UN)
        throw error
      }
    }
    let code = errno
    guard code == EWOULDBLOCK || code == EAGAIN else { throw makePOSIXError(code: code) }
    clock.sleepForPoll()
  }
}

private func requireLockDeadline(
  deadlineNanoseconds: UInt64,
  clock: any OracleQuiescenceClock,
  timeout: RecorderLockTimeout
) throws {
  guard clock.nowNanoseconds() < deadlineNanoseconds else {
    switch timeout {
    case .recorder: throw OracleRecorderError.lockTimedOut
    case .quiescence: throw OracleQuiescenceError.timedOut
    }
  }
}

private func lockedRecorderState(directory: Int32) throws -> OracleRecorderState {
  if try recorderMarkerExists("recorder-failed", directory: directory) { return .poisoned }
  if try recorderMarkerExists("recorder-poisoned", directory: directory) { return .poisoned }
  if try recorderMarkerExists("recorder-sealed", directory: directory) { return .sealed }
  return .healthy
}

private func recorderError(directory: Int32) throws -> OracleRecorderError {
  switch try lockedRecorderState(directory: directory) {
  case .healthy: .unavailable
  case .poisoned: .poisoned
  case .sealed: .sealed
  }
}

private func recorderMarkerExists(_ name: String, directory: Int32) throws -> Bool {
  let descriptor = openat(directory, name, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
  if descriptor < 0 {
    if errno == ENOENT { return false }
    throw makePOSIXError(code: errno)
  }
  defer { close(descriptor) }
  try validateOwnerPrivateRegularFile(descriptor: descriptor)
  return true
}

private func createRecorderMarker(
  _ name: String,
  directory: Int32,
  failBeforeSync: Bool = false
) throws {
  let descriptor = openat(
    directory,
    name,
    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
    0o600
  )
  if descriptor < 0 {
    if errno == EEXIST {
      guard try recorderMarkerExists(name, directory: directory) else {
        throw FixtureContractError.unsafePath
      }
      try syncRecorderMarker(name, directory: directory)
      return
    }
    throw makePOSIXError(code: errno)
  }
  defer { close(descriptor) }
  try validateOwnerPrivateRegularFile(descriptor: descriptor)
  try writeAll(Data("diskplan-recorder-state-v1\n".utf8), descriptor: descriptor)
  if failBeforeSync { throw OracleAppendInjectedFailure.poisonStorage }
  guard fsync(descriptor) == 0 else { throw makePOSIXError(code: errno) }
  guard fsync(directory) == 0 else { throw makePOSIXError(code: errno) }
}

private func syncRecorderMarker(_ name: String, directory: Int32) throws {
  let descriptor = openat(
    directory,
    name,
    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
  )
  guard descriptor >= 0 else { throw makePOSIXError(code: errno) }
  defer { close(descriptor) }
  try validateOwnerPrivateRegularFile(descriptor: descriptor)
  guard fsync(descriptor) == 0 else { throw makePOSIXError(code: errno) }
  guard fsync(directory) == 0 else { throw makePOSIXError(code: errno) }
}

private func removeRecorderMarker(_ name: String, directory: Int32) throws {
  guard unlinkat(directory, name, 0) == 0 else { throw makePOSIXError(code: errno) }
  guard fsync(directory) == 0 else { throw makePOSIXError(code: errno) }
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
