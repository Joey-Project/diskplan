import Darwin
import Foundation

enum OracleWindowWriteInjectedFailure: Error, Equatable {
  case afterFileSync
  case afterRenameBeforeDirectorySync
}

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
    let attemptLock = openat(
      directory,
      "recorder-attempt.lock",
      O_RDWR | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
      0o600
    )
    guard attemptLock >= 0 else { throw makePOSIXError(code: errno) }
    defer { close(attemptLock) }
    try validateOwnerPrivateRegularFile(descriptor: attemptLock)
    let admissions = openat(
      directory,
      "recorder-admissions.log",
      O_RDWR | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW,
      0o600
    )
    guard admissions >= 0 else { throw makePOSIXError(code: errno) }
    defer { close(admissions) }
    try validateOwnerPrivateRegularFile(descriptor: admissions)
    guard fsync(lock) == 0, fsync(attemptLock) == 0, fsync(admissions) == 0,
      fsync(directory) == 0
    else { throw makePOSIXError(code: errno) }
  }

  public func append(_ original: OracleEvent) throws {
    try append(original, injecting: nil)
  }

  func append(
    _ original: OracleEvent,
    injecting failure: OracleAppendInjectedFailure?,
    duringRecordAttempt: Bool = false
  ) throws {
    let clock = SystemOracleQuiescenceClock()
    let (deadline, overflow) = clock.nowNanoseconds().addingReportingOverflow(30_000_000_000)
    guard !overflow else { throw OracleRecorderError.lockTimedOut }
    try append(
      original,
      injecting: failure,
      duringRecordAttempt: duringRecordAttempt,
      deadlineNanoseconds: deadline,
      clock: clock
    )
  }

  func append(
    _ original: OracleEvent,
    injecting failure: OracleAppendInjectedFailure?,
    duringRecordAttempt: Bool = false,
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock
  ) throws {
    let directory = try openExistingRunDirectory(runDirectory)
    defer { close(directory) }
    try appendLocked(
      original,
      injecting: failure,
      duringRecordAttempt: duringRecordAttempt,
      directory: directory,
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock
    )
  }

  fileprivate func appendLocked(
    _ original: OracleEvent,
    injecting failure: OracleAppendInjectedFailure?,
    duringRecordAttempt: Bool,
    directory: Int32,
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock
  ) throws {
    try withRecorderLock(
      directory: directory,
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .recorder
    ) { directory in
      guard
        try lockedRecorderState(
          directory: directory,
          includeIncompleteAttempts: !duringRecordAttempt
        ) == .healthy
      else {
        throw try recorderError(
          directory: directory,
          includeIncompleteAttempts: !duringRecordAttempt
        )
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
    try withSynchronizedRecorder { try lockedRecorderState(directory: $0) }
  }

  func recorderStateDuringAttempt(
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock
  ) throws -> OracleRecorderState {
    try withRecorderLock(
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .recorder
    ) {
      try lockedRecorderState(directory: $0, includeIncompleteAttempts: false)
    }
  }

  fileprivate func recorderStateDuringAttempt(
    directory: Int32,
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock
  ) throws -> OracleRecorderState {
    try withRecorderLock(
      directory: directory,
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .recorder
    ) {
      try lockedRecorderState(directory: $0, includeIncompleteAttempts: false)
    }
  }

  func recorderState(
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock
  ) throws -> OracleRecorderState {
    return try withAttemptGate(
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .recorder
    ) { directory in
      try recorderStateDuringAttempt(
        directory: directory,
        deadlineNanoseconds: deadlineNanoseconds,
        clock: clock
      )
    }
  }

  public func poisonRecorder() throws {
    try withRecorderLock { try createRecorderMarker("recorder-poisoned", directory: $0) }
  }

  func failRecorder() throws {
    let clock = SystemOracleQuiescenceClock()
    let (deadline, overflow) = clock.nowNanoseconds().addingReportingOverflow(30_000_000_000)
    guard !overflow else { throw OracleRecorderError.lockTimedOut }
    try failRecorder(deadlineNanoseconds: deadline, clock: clock)
  }

  func failRecorder(
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock
  ) throws {
    try requireLockDeadline(
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .recorder
    )
    let directory = try openExistingRunDirectory(runDirectory)
    defer { close(directory) }
    try requireLockDeadline(
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .recorder
    )
    try createRecorderMarker("recorder-failed", directory: directory)
    try requireLockDeadline(
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .recorder
    )
  }

  fileprivate func failRecorder(
    directory: Int32,
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock
  ) throws {
    try requireLockDeadline(
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .recorder
    )
    try createRecorderMarker("recorder-failed", directory: directory)
    try requireCanonicalRunDirectoryIdentity(runDirectory, descriptor: directory)
    try requireLockDeadline(
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .recorder
    )
  }

  func makeAdmissionChannel(
    injectAttemptMarkerFailure: Bool = false,
    onAdmissionWitnessed: @escaping @Sendable () -> Void = {}
  ) throws
    -> OracleAdmissionChannel
  {
    try OracleAdmissionChannel(
      log: self,
      injectAttemptMarkerFailure: injectAttemptMarkerFailure,
      onAdmissionWitnessed: onAdmissionWitnessed
    )
  }

  func beginRecordAttempt(
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock
  ) throws -> OracleRecordAttempt {
    let directory = try openExistingRunDirectory(runDirectory)
    defer { close(directory) }
    let descriptor = try openAttemptLock(directory: directory)
    do {
      try acquireBoundedLock(
        descriptor,
        operation: LOCK_SH,
        deadlineNanoseconds: deadlineNanoseconds,
        clock: clock,
        timeout: .recorder
      )
      if try recorderMarkerExists("recorder-sealing", directory: directory) {
        throw OracleRecorderError.sealed
      }
      let markerName = try createIncompleteAttemptMarker(directory: directory)
      let runDirectoryDescriptor = dup(directory)
      guard runDirectoryDescriptor >= 0 else { throw makePOSIXError(code: errno) }
      return OracleRecordAttempt(
        descriptor: descriptor,
        runDirectoryDescriptor: runDirectoryDescriptor,
        markerName: markerName
      )
    } catch {
      close(descriptor)
      if (try? recorderMarkerExists("recorder-sealing", directory: directory)) == true
        || (try? recorderMarkerExists("recorder-sealed", directory: directory)) == true
      {
        throw OracleRecorderError.sealed
      }
      throw error
    }
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

  fileprivate func poisonRecorder(
    directory: Int32,
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock
  ) throws {
    try withRecorderLock(
      directory: directory,
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .recorder
    ) { try createRecorderMarker("recorder-poisoned", directory: $0) }
  }

  public func sealRecorder() throws {
    try withSynchronizedRecorder { directory in
      let sealing = try recorderMarkerExists("recorder-sealing", directory: directory)
      let sealed = try recorderMarkerExists("recorder-sealed", directory: directory)
      guard !sealed || sealing else { throw OracleRecorderError.poisoned }
      if !sealing {
        try createRecorderMarker("recorder-sealing", directory: directory)
      }
      var admissions = try recorderAdmissionState(directory: directory)
      if !admissions.hasCutoff {
        try appendAdmissionCutoff(directory: directory)
        admissions = try recorderAdmissionState(directory: directory)
      }
      guard !admissions.poisonedBeforeCutoff else {
        throw OracleRecorderError.poisoned
      }
      if !sealed {
        try createRecorderMarker("recorder-sealed", directory: directory)
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
      return try data.split(separator: 0x0a).map(decodeOracleEventStrict)
    } catch {
      throw FixtureControlReadError.mismatch(.events, .malformed)
    }
  }

  public func sealedSnapshot() throws -> OracleSealedSnapshot {
    try withSynchronizedRecorder { directory in
      guard try lockedRecorderState(directory: directory) == .sealed else {
        throw try recorderError(directory: directory)
      }
      return try OracleSealedSnapshot(
        window: lockedWindow(directory: directory),
        events: lockedEvents(directory: directory)
      )
    }
  }

  public func writeWindow(_ window: OracleWindow) throws {
    try prepare()
    let directory = try openExistingRunDirectory(runDirectory)
    defer { close(directory) }
    try writeWindow(window, directory: directory)
  }

  public func window() throws -> OracleWindow {
    let directory = try openExistingRunDirectory(runDirectory)
    defer { close(directory) }
    return try lockedWindow(directory: directory)
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
    onFinalSnapshotLocked: @Sendable () -> Void = {},
    windowWriteFailure: OracleWindowWriteInjectedFailure? = nil
  ) throws -> OracleQuiescence {
    guard quietMilliseconds >= 50, quietMilliseconds <= 5_000,
      timeoutMilliseconds >= quietMilliseconds, timeoutMilliseconds <= 30_000
    else { throw OracleQuiescenceError.invalidBounds }
    let directory = try openExistingRunDirectory(runDirectory)
    defer { close(directory) }
    try requireCanonicalRunDirectoryIdentity(runDirectory, descriptor: directory)
    let openedWindow = try lockedWindow(directory: directory)
    let start = clock.nowNanoseconds()
    let (deadline, overflow) = start.addingReportingOverflow(
      UInt64(timeoutMilliseconds) * 1_000_000
    )
    guard !overflow else { throw OracleQuiescenceError.invalidBounds }
    var fingerprint = try eventFingerprint(
      directory: directory,
      deadlineNanoseconds: deadline,
      clock: clock
    )
    var quietStart = clock.nowNanoseconds()
    guard quietStart - start < UInt64(timeoutMilliseconds) * 1_000_000 else {
      throw OracleQuiescenceError.timedOut
    }
    while true {
      guard clock.nowNanoseconds() - start < UInt64(timeoutMilliseconds) * 1_000_000 else {
        throw OracleQuiescenceError.timedOut
      }
      let current = try eventFingerprint(
        directory: directory,
        deadlineNanoseconds: deadline,
        clock: clock
      )
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
          directory: directory,
          openedWindow: openedWindow,
          expectedFingerprint: current,
          quietStartNanoseconds: quietStart,
          quietMilliseconds: quietMilliseconds,
          deadlineNanoseconds: deadline,
          clock: clock,
          onFinalSnapshotLocked: onFinalSnapshotLocked,
          windowWriteFailure: windowWriteFailure
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
    directory: Int32,
    openedWindow: OracleWindow,
    expectedFingerprint: OracleEventFingerprint,
    quietStartNanoseconds: UInt64,
    quietMilliseconds: Int,
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock,
    onFinalSnapshotLocked: @Sendable () -> Void,
    windowWriteFailure: OracleWindowWriteInjectedFailure?
  ) throws -> WindowSealAttempt {
    let prepared = try withRecorderLock(
      directory: directory,
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
      guard current == expectedFingerprint else {
        return WindowSealPreparation.changed(current, now)
      }
      guard now >= quietStartNanoseconds,
        now - quietStartNanoseconds >= UInt64(quietMilliseconds) * 1_000_000
      else { return .waiting }
      try createRecorderMarker("recorder-sealing", directory: directory)
      return .ready(current)
    }
    let preparedFingerprint: OracleEventFingerprint
    switch prepared {
    case .changed(let current, let now):
      return .changed(current, now)
    case .waiting:
      return .waiting
    case .ready(let fingerprint):
      preparedFingerprint = fingerprint
    }
    return try withAttemptGate(
      directory: directory,
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .quiescence
    ) { _ in
      try withRecorderLock(
        directory: directory,
        deadlineNanoseconds: deadlineNanoseconds,
        clock: clock,
        timeout: .quiescence
      ) { directory in
        try appendAdmissionCutoff(directory: directory)
        guard try recorderMarkerExists("recorder-sealing", directory: directory),
          try !recorderMarkerExists("recorder-failed", directory: directory),
          try !recorderMarkerExists("recorder-poisoned", directory: directory),
          try !recorderHasIncompleteAttempts(directory: directory),
          try !recorderHasUnresolvedAdmissions(directory: directory),
          try !recorderMarkerExists("recorder-sealed", directory: directory)
        else { throw OracleRecorderError.poisoned }
        let values = try lockedEvents(directory: directory)
        let current = OracleEventFingerprint(
          count: values.count,
          lastSequence: values.last?.sequence ?? 0
        )
        let now = clock.nowNanoseconds()
        guard now < deadlineNanoseconds else { throw OracleQuiescenceError.timedOut }
        guard current == preparedFingerprint else { throw OracleRecorderError.poisoned }
        onFinalSnapshotLocked()
        try writeWindow(
          OracleWindow(
            beginNanoseconds: openedWindow.beginNanoseconds,
            endNanoseconds: now,
            quietMilliseconds: quietMilliseconds,
            eventCount: current.count,
            lastSequence: current.lastSequence
          ),
          directory: directory,
          injecting: windowWriteFailure
        )
        try createRecorderMarker("recorder-sealed", directory: directory)
        return WindowSealAttempt.sealed(
          OracleQuiescence(
            eventCount: current.count,
            lastSequence: current.lastSequence,
            quietMilliseconds: quietMilliseconds
          )
        )
      }
    }
  }

  private func eventFingerprint(
    directory: Int32,
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock
  ) throws -> OracleEventFingerprint {
    try withAttemptGate(
      directory: directory,
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .quiescence
    ) { _ in
      try withRecorderLock(
        directory: directory,
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
      return try data.split(separator: 0x0a).map(decodeOracleEventStrict)
    } catch {
      throw FixtureControlReadError.mismatch(.events, .malformed)
    }
  }

  private func lockedWindow(directory: Int32) throws -> OracleWindow {
    let descriptor = openat(
      directory,
      "window.json",
      O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
    )
    guard descriptor >= 0 else { throw makePOSIXError(code: errno) }
    defer { close(descriptor) }
    try validateOwnerPrivateRegularFile(descriptor: descriptor)
    var metadata = stat()
    guard fstat(descriptor, &metadata) == 0 else { throw makePOSIXError(code: errno) }
    guard metadata.st_size >= 0, metadata.st_size <= SecureFixtureStorage.maximumControlBytes else {
      throw FixtureControlReadError.mismatch(.window, .sizeLimit)
    }
    let data = try readAll(descriptor: descriptor, count: Int(metadata.st_size))
    do {
      let window = try JSONDecoder().decode(OracleWindow.self, from: data)
      try window.validate()
      return window
    } catch let error as FixtureControlReadError {
      throw error
    } catch {
      throw FixtureControlReadError.mismatch(.window, .malformed)
    }
  }

  private func writeWindow(
    _ window: OracleWindow,
    directory: Int32,
    injecting failure: OracleWindowWriteInjectedFailure? = nil
  ) throws {
    let temporary = "window.json.tmp-\(UUID().uuidString.lowercased())"
    let descriptor = openat(
      directory,
      temporary,
      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
      0o600
    )
    guard descriptor >= 0 else { throw makePOSIXError(code: errno) }
    var shouldRemove = true
    defer {
      close(descriptor)
      if shouldRemove { unlinkat(directory, temporary, 0) }
    }
    try validateOwnerPrivateRegularFile(descriptor: descriptor)
    try writeAll(JSONEncoder().encode(window), descriptor: descriptor)
    guard fsync(descriptor) == 0 else { throw makePOSIXError(code: errno) }
    if failure == .afterFileSync { throw OracleWindowWriteInjectedFailure.afterFileSync }
    guard renameat(directory, temporary, directory, "window.json") == 0 else {
      throw makePOSIXError(code: errno)
    }
    shouldRemove = false
    if failure == .afterRenameBeforeDirectorySync {
      throw OracleWindowWriteInjectedFailure.afterRenameBeforeDirectorySync
    }
    guard fsync(directory) == 0 else { throw makePOSIXError(code: errno) }
    try requireCanonicalRunDirectoryIdentity(runDirectory, descriptor: directory)
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

private enum WindowSealPreparation {
  case changed(OracleEventFingerprint, UInt64)
  case waiting
  case ready(OracleEventFingerprint)
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

final class OracleRecordAttempt: @unchecked Sendable {
  private let lock = NSLock()
  private var descriptor: Int32?
  private var runDirectoryDescriptor: Int32?
  private var markerName: String?
  private var resolveAction: (() throws -> Void)?
  private var finishAction: (() -> Void)?

  fileprivate init(
    descriptor: Int32,
    runDirectoryDescriptor: Int32,
    markerName: String
  ) {
    self.descriptor = descriptor
    self.runDirectoryDescriptor = runDirectoryDescriptor
    self.markerName = markerName
  }

  fileprivate init(
    resolve: @escaping () throws -> Void,
    finish: @escaping () -> Void
  ) {
    resolveAction = resolve
    finishAction = finish
  }

  func resolve() throws {
    try lock.withLock {
      if let resolveAction {
        try resolveAction()
        self.resolveAction = nil
        return
      }
      guard let directory = runDirectoryDescriptor, let markerName else { return }
      guard unlinkat(directory, markerName, 0) == 0 else { throw makePOSIXError(code: errno) }
      self.markerName = nil
      guard fsync(directory) == 0 else { throw makePOSIXError(code: errno) }
    }
  }

  func finish() {
    lock.withLock {
      if let finishAction {
        self.finishAction = nil
        finishAction()
        return
      }
      guard let descriptor else { return }
      flock(descriptor, LOCK_UN)
      close(descriptor)
      self.descriptor = nil
      if let runDirectoryDescriptor {
        close(runDirectoryDescriptor)
        self.runDirectoryDescriptor = nil
      }
    }
  }

  deinit { finish() }
}

final class OracleAdmissionChannel: @unchecked Sendable {
  private let localLock = NSLock()
  private let runDirectoryURL: URL
  private let directory: Int32
  private let attemptLock: Int32
  private let admissions: Int32
  private let injectAttemptMarkerFailure: Bool
  private let onAdmissionWitnessed: @Sendable () -> Void

  fileprivate init(
    log: OracleLog,
    injectAttemptMarkerFailure: Bool,
    onAdmissionWitnessed: @escaping @Sendable () -> Void
  ) throws {
    runDirectoryURL = log.runDirectory
    self.injectAttemptMarkerFailure = injectAttemptMarkerFailure
    self.onAdmissionWitnessed = onAdmissionWitnessed
    directory = try openExistingRunDirectory(log.runDirectory)
    do {
      attemptLock = try openAttemptLock(directory: directory)
      admissions = openat(
        directory,
        "recorder-admissions.log",
        O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
      )
      guard admissions >= 0 else { throw makePOSIXError(code: errno) }
      try validateOwnerPrivateRegularFile(descriptor: admissions)
    } catch {
      close(directory)
      throw error
    }
  }

  func append(log: OracleLog, _ event: OracleEvent, deadlineNanoseconds: UInt64) throws {
    try requireCanonicalRunDirectoryIdentity(runDirectoryURL, descriptor: directory)
    try log.appendLocked(
      event,
      injecting: nil,
      duringRecordAttempt: true,
      directory: directory,
      deadlineNanoseconds: deadlineNanoseconds,
      clock: SystemOracleQuiescenceClock()
    )
  }

  func recorderState(log: OracleLog, deadlineNanoseconds: UInt64) throws -> OracleRecorderState {
    try requireCanonicalRunDirectoryIdentity(runDirectoryURL, descriptor: directory)
    return try log.recorderStateDuringAttempt(
      directory: directory,
      deadlineNanoseconds: deadlineNanoseconds,
      clock: SystemOracleQuiescenceClock()
    )
  }

  func poison(log: OracleLog, deadlineNanoseconds: UInt64) throws {
    try requireCanonicalRunDirectoryIdentity(runDirectoryURL, descriptor: directory)
    try log.poisonRecorder(
      directory: directory,
      deadlineNanoseconds: deadlineNanoseconds,
      clock: SystemOracleQuiescenceClock()
    )
  }

  func fail(log: OracleLog, deadlineNanoseconds: UInt64) throws {
    try requireCanonicalRunDirectoryIdentity(runDirectoryURL, descriptor: directory)
    try log.failRecorder(
      directory: directory,
      deadlineNanoseconds: deadlineNanoseconds,
      clock: SystemOracleQuiescenceClock()
    )
  }

  func beginRecordAttempt(
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock
  ) throws -> OracleRecordAttempt {
    let token = UUID().uuidString.lowercased()
    try appendAdmission("begin \(token)\n", deadlineNanoseconds: deadlineNanoseconds, clock: clock)
    onAdmissionWitnessed()
    try acquireLocalLock(deadlineNanoseconds: deadlineNanoseconds, clock: clock)
    var ownsLocalLock = true
    do {
      try acquireBoundedLock(
        attemptLock,
        operation: LOCK_SH,
        deadlineNanoseconds: deadlineNanoseconds,
        clock: clock,
        timeout: .recorder
      )
      var ownsAttemptLock = true
      do {
        if try recorderMarkerExists("recorder-sealing", directory: directory)
          || recorderMarkerExists("recorder-sealed", directory: directory)
        {
          throw OracleRecorderError.sealed
        }
        if injectAttemptMarkerFailure { throw POSIXError(.EMFILE) }
        let markerName = try createIncompleteAttemptMarker(directory: directory)
        let attempt = OracleRecordAttempt(
          resolve: { [self] in
            try requireCanonicalRunDirectoryIdentity(runDirectoryURL, descriptor: directory)
            guard unlinkat(directory, markerName, 0) == 0 else {
              throw makePOSIXError(code: errno)
            }
            guard fsync(directory) == 0 else { throw makePOSIXError(code: errno) }
            try appendAdmission(
              "resolved \(token)\n",
              deadlineNanoseconds: deadlineNanoseconds,
              clock: clock
            )
          },
          finish: { [self] in
            flock(attemptLock, LOCK_UN)
            localLock.unlock()
          }
        )
        ownsAttemptLock = false
        ownsLocalLock = false
        return attempt
      } catch {
        if ownsAttemptLock { flock(attemptLock, LOCK_UN) }
        throw error
      }
    } catch {
      if ownsLocalLock { localLock.unlock() }
      throw error
    }
  }

  private func appendAdmission(
    _ line: String,
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock
  ) throws {
    try requireLockDeadline(
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .recorder
    )
    try writeAll(Data(line.utf8), descriptor: admissions)
    guard fsync(admissions) == 0 else { throw makePOSIXError(code: errno) }
    try requireLockDeadline(
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: .recorder
    )
  }

  private func acquireLocalLock(
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock
  ) throws {
    while true {
      try requireLockDeadline(
        deadlineNanoseconds: deadlineNanoseconds,
        clock: clock,
        timeout: .recorder
      )
      if localLock.try() {
        do {
          try requireLockDeadline(
            deadlineNanoseconds: deadlineNanoseconds,
            clock: clock,
            timeout: .recorder
          )
          return
        } catch {
          localLock.unlock()
          throw error
        }
      }
      clock.sleepForPoll()
    }
  }

  deinit {
    close(admissions)
    close(attemptLock)
    close(directory)
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

private func validateOwnerPrivateRegularFile(descriptor: Int32) throws {
  var metadata = stat()
  guard fstat(descriptor, &metadata) == 0 else { throw makePOSIXError(code: errno) }
  try validateOwnerPrivateRegularFile(metadata)
  try requireNoExtendedACL(descriptor: descriptor)
}

private func requireNoExtendedACL(descriptor: Int32) throws {
  errno = 0
  guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
    if errno == ENOENT { return }
    throw makePOSIXError(code: errno == 0 ? EIO : errno)
  }
  acl_free(UnsafeMutableRawPointer(acl))
  throw FixtureContractError.unsafePath
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
  do {
    try requireNoExtendedACL(descriptor: descriptor)
  } catch {
    close(descriptor)
    throw error
  }
  return descriptor
}

private func requireCanonicalRunDirectoryIdentity(_ url: URL, descriptor: Int32) throws {
  try requireNoExtendedACL(descriptor: descriptor)
  var held = stat()
  guard fstat(descriptor, &held) == 0 else { throw makePOSIXError(code: errno) }
  var canonical = stat()
  guard lstat(url.path, &canonical) == 0 else { throw makePOSIXError(code: errno) }
  guard held.st_dev == canonical.st_dev, held.st_ino == canonical.st_ino,
    canonical.st_uid == geteuid(), canonical.st_mode & S_IFMT == S_IFDIR,
    canonical.st_mode & 0o077 == 0
  else { throw FixtureContractError.unsafePath }
}

private func openAttemptLock(directory: Int32) throws -> Int32 {
  let descriptor = openat(
    directory,
    "recorder-attempt.lock",
    O_RDWR | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
  )
  guard descriptor >= 0 else { throw makePOSIXError(code: errno) }
  do {
    try validateOwnerPrivateRegularFile(descriptor: descriptor)
    return descriptor
  } catch {
    close(descriptor)
    throw error
  }
}

extension OracleLog {
  fileprivate func withSynchronizedRecorder<Result>(
    _ body: (Int32) throws -> Result
  ) throws -> Result {
    let clock = SystemOracleQuiescenceClock()
    let (deadline, overflow) = clock.nowNanoseconds().addingReportingOverflow(30_000_000_000)
    guard !overflow else { throw OracleRecorderError.lockTimedOut }
    return try withAttemptGate(
      deadlineNanoseconds: deadline,
      clock: clock,
      timeout: .recorder
    ) { directory in
      try withRecorderLock(
        directory: directory,
        deadlineNanoseconds: deadline,
        clock: clock,
        timeout: .recorder,
        body
      )
    }
  }

  fileprivate func withAttemptGate<Result>(
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock,
    timeout: RecorderLockTimeout,
    _ body: (Int32) throws -> Result
  ) throws -> Result {
    let directory = try openExistingRunDirectory(runDirectory)
    defer { close(directory) }
    return try withAttemptGate(
      directory: directory,
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: timeout,
      body
    )
  }

  fileprivate func withAttemptGate<Result>(
    directory: Int32,
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock,
    timeout: RecorderLockTimeout,
    _ body: (Int32) throws -> Result
  ) throws -> Result {
    try requireCanonicalRunDirectoryIdentity(runDirectory, descriptor: directory)
    let descriptor = try openAttemptLock(directory: directory)
    defer { close(descriptor) }
    try acquireBoundedLock(
      descriptor,
      operation: LOCK_EX,
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: timeout
    )
    defer { flock(descriptor, LOCK_UN) }
    let result = try body(directory)
    try requireCanonicalRunDirectoryIdentity(runDirectory, descriptor: directory)
    try requireLockDeadline(
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: timeout
    )
    return result
  }

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
    return try withRecorderLock(
      directory: directory,
      deadlineNanoseconds: deadlineNanoseconds,
      clock: clock,
      timeout: timeout,
      body
    )
  }

  fileprivate func withRecorderLock<Result>(
    directory: Int32,
    deadlineNanoseconds: UInt64,
    clock: any OracleQuiescenceClock,
    timeout: RecorderLockTimeout,
    _ body: (Int32) throws -> Result
  ) throws -> Result {
    try requireCanonicalRunDirectoryIdentity(runDirectory, descriptor: directory)
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
    try requireCanonicalRunDirectoryIdentity(runDirectory, descriptor: directory)
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
  operation: Int32 = LOCK_EX,
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
    if flock(descriptor, operation | LOCK_NB) == 0 {
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

private func lockedRecorderState(
  directory: Int32,
  includeIncompleteAttempts: Bool = true
) throws -> OracleRecorderState {
  if try recorderMarkerExists("recorder-failed", directory: directory) { return .poisoned }
  if try recorderMarkerExists("recorder-poisoned", directory: directory) { return .poisoned }
  if includeIncompleteAttempts,
    try recorderHasIncompleteAttempts(directory: directory)
      || recorderHasUnresolvedAdmissions(directory: directory)
  {
    return .poisoned
  }
  if try recorderMarkerExists("recorder-sealed", directory: directory) { return .sealed }
  if try recorderMarkerExists("recorder-sealing", directory: directory) { return .poisoned }
  return .healthy
}

private func recorderHasUnresolvedAdmissions(directory: Int32) throws -> Bool {
  try recorderAdmissionState(directory: directory).poisonedBeforeCutoff
}

private struct RecorderAdmissionState {
  let hasCutoff: Bool
  let poisonedBeforeCutoff: Bool
}

private func recorderAdmissionState(directory: Int32) throws -> RecorderAdmissionState {
  let descriptor = openat(
    directory,
    "recorder-admissions.log",
    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
  )
  guard descriptor >= 0 else { throw makePOSIXError(code: errno) }
  defer { close(descriptor) }
  try validateOwnerPrivateRegularFile(descriptor: descriptor)
  var metadata = stat()
  guard fstat(descriptor, &metadata) == 0 else { throw makePOSIXError(code: errno) }
  guard metadata.st_size >= 0, metadata.st_size <= FixtureContract.maximumOracleBytes else {
    throw FixtureContractError.oracleTooLarge
  }
  let data = try readAll(descriptor: descriptor, count: Int(metadata.st_size))
  guard data.last == nil || data.last == 0x0a else {
    throw FixtureControlReadError.mismatch(.events, .malformed)
  }
  var unresolved = Set<String>()
  var unresolvedAfterCutoff = Set<String>()
  var cutoffSeen = false
  var poisonedBeforeCutoff = false
  for rawLine in data.split(separator: 0x0a) {
    guard let line = String(data: rawLine, encoding: .utf8) else {
      throw FixtureControlReadError.mismatch(.events, .malformed)
    }
    let parts = line.split(separator: " ", omittingEmptySubsequences: false)
    guard parts.count == 2, UUID(uuidString: String(parts[1])) != nil else {
      throw FixtureControlReadError.mismatch(.events, .malformed)
    }
    let token = String(parts[1]).lowercased()
    switch parts[0] {
    case "begin":
      let inserted =
        cutoffSeen
        ? unresolvedAfterCutoff.insert(token).inserted
        : unresolved.insert(token).inserted
      guard inserted else {
        throw FixtureControlReadError.mismatch(.events, .malformed)
      }
    case "resolved":
      let removed =
        cutoffSeen
        ? unresolvedAfterCutoff.remove(token) != nil
        : unresolved.remove(token) != nil
      guard removed else {
        throw FixtureControlReadError.mismatch(.events, .malformed)
      }
    case "cutoff":
      guard !cutoffSeen else {
        throw FixtureControlReadError.mismatch(.events, .malformed)
      }
      cutoffSeen = true
      poisonedBeforeCutoff = !unresolved.isEmpty
      unresolved.removeAll()
    default:
      throw FixtureControlReadError.mismatch(.events, .malformed)
    }
  }
  return RecorderAdmissionState(
    hasCutoff: cutoffSeen,
    poisonedBeforeCutoff: poisonedBeforeCutoff || (!cutoffSeen && !unresolved.isEmpty)
  )
}

private func appendAdmissionCutoff(directory: Int32) throws {
  let descriptor = openat(
    directory,
    "recorder-admissions.log",
    O_WRONLY | O_APPEND | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
  )
  guard descriptor >= 0 else { throw makePOSIXError(code: errno) }
  defer { close(descriptor) }
  try validateOwnerPrivateRegularFile(descriptor: descriptor)
  try writeAll(
    Data("cutoff \(UUID().uuidString.lowercased())\n".utf8),
    descriptor: descriptor
  )
  guard fsync(descriptor) == 0 else { throw makePOSIXError(code: errno) }
}

private let incompleteAttemptPrefix = "recorder-incomplete-attempt-"
private let incompleteAttemptSuffix = ".marker"

private func createIncompleteAttemptMarker(directory: Int32) throws -> String {
  let name = incompleteAttemptPrefix + UUID().uuidString.lowercased() + incompleteAttemptSuffix
  let descriptor = openat(
    directory,
    name,
    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
    0o600
  )
  guard descriptor >= 0 else { throw makePOSIXError(code: errno) }
  defer { close(descriptor) }
  try validateOwnerPrivateRegularFile(descriptor: descriptor)
  guard fsync(descriptor) == 0 else { throw makePOSIXError(code: errno) }
  guard fsync(directory) == 0 else { throw makePOSIXError(code: errno) }
  return name
}

private func recorderHasIncompleteAttempts(directory: Int32) throws -> Bool {
  let duplicate = openat(
    directory,
    ".",
    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
  )
  guard duplicate >= 0 else { throw makePOSIXError(code: errno) }
  guard let stream = fdopendir(duplicate) else {
    let code = errno
    close(duplicate)
    throw makePOSIXError(code: code)
  }
  defer { closedir(stream) }
  var count = 0
  errno = 0
  while let entry = readdir(stream) {
    let name = withUnsafePointer(to: &entry.pointee.d_name) {
      $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) {
        String(cString: $0)
      }
    }
    if name == "." || name == ".." { continue }
    count += 1
    guard count <= FixtureContract.maximumOracleDirectoryEntries else {
      throw FixtureContractError.unsafePath
    }
    if name.hasPrefix(incompleteAttemptPrefix) { return true }
    errno = 0
  }
  guard errno == 0 else { throw makePOSIXError(code: errno) }
  return false
}

private func recorderError(
  directory: Int32,
  includeIncompleteAttempts: Bool = true
) throws -> OracleRecorderError {
  switch try lockedRecorderState(
    directory: directory,
    includeIncompleteAttempts: includeIncompleteAttempts
  ) {
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
  let event = try decodeOracleEventStrict(last)
  guard event.sequence < UInt64.max else { throw FixtureContractError.oracleTooLarge }
  return event.sequence + 1
}

private let oracleEventJSONKeys: Set<String> = [
  "sequence",
  "runID",
  "domainIdentifier",
  "itemIdentifier",
  "kind",
  "processID",
  "monotonicNanoseconds",
  "requestFlags",
]

private func decodeOracleEventStrict(_ data: some DataProtocol) throws -> OracleEvent {
  let value = Data(data)
  var scanner = StrictJSONObjectKeyScanner(bytes: Array(value))
  let keys = try scanner.topLevelKeys()
  guard keys.count == oracleEventJSONKeys.count, Set(keys) == oracleEventJSONKeys else {
    throw FixtureControlReadError.mismatch(.events, .malformed)
  }
  return try JSONDecoder().decode(OracleEvent.self, from: value)
}

private struct StrictJSONObjectKeyScanner {
  private static let maximumNestingDepth = 64
  let bytes: [UInt8]
  var index = 0

  mutating func topLevelKeys() throws -> [String] {
    skipWhitespace()
    try consume(0x7b)
    skipWhitespace()
    var keys: [String] = []
    var seen = Set<String>()
    if consumeIf(0x7d) {
      skipWhitespace()
      try requireEnd()
      return keys
    }
    while true {
      let key = try string()
      guard seen.insert(key).inserted else { throw malformed() }
      keys.append(key)
      skipWhitespace()
      try consume(0x3a)
      skipWhitespace()
      try skipValue(depth: 0)
      skipWhitespace()
      if consumeIf(0x7d) { break }
      try consume(0x2c)
      skipWhitespace()
    }
    skipWhitespace()
    try requireEnd()
    return keys
  }

  private mutating func skipValue(depth: Int) throws {
    guard index < bytes.count, depth <= Self.maximumNestingDepth else { throw malformed() }
    switch bytes[index] {
    case 0x22:
      _ = try string()
    case 0x7b:
      try skipObject(depth: depth + 1)
    case 0x5b:
      try skipArray(depth: depth + 1)
    default:
      let start = index
      while index < bytes.count, ![0x20, 0x09, 0x0a, 0x0d, 0x2c, 0x5d, 0x7d].contains(bytes[index])
      {
        index += 1
      }
      guard index > start else { throw malformed() }
    }
  }

  private mutating func skipObject(depth: Int) throws {
    guard depth <= Self.maximumNestingDepth else { throw malformed() }
    try consume(0x7b)
    skipWhitespace()
    if consumeIf(0x7d) { return }
    while true {
      _ = try string()
      skipWhitespace()
      try consume(0x3a)
      skipWhitespace()
      try skipValue(depth: depth)
      skipWhitespace()
      if consumeIf(0x7d) { return }
      try consume(0x2c)
      skipWhitespace()
    }
  }

  private mutating func skipArray(depth: Int) throws {
    guard depth <= Self.maximumNestingDepth else { throw malformed() }
    try consume(0x5b)
    skipWhitespace()
    if consumeIf(0x5d) { return }
    while true {
      try skipValue(depth: depth)
      skipWhitespace()
      if consumeIf(0x5d) { return }
      try consume(0x2c)
      skipWhitespace()
    }
  }

  private mutating func string() throws -> String {
    let start = index
    try consume(0x22)
    var escaped = false
    while index < bytes.count {
      let byte = bytes[index]
      index += 1
      if escaped {
        escaped = false
        continue
      }
      if byte == 0x5c {
        escaped = true
      } else if byte == 0x22 {
        return try JSONDecoder().decode(String.self, from: Data(bytes[start..<index]))
      } else if byte < 0x20 {
        throw malformed()
      }
    }
    throw malformed()
  }

  private mutating func skipWhitespace() {
    while index < bytes.count, [0x20, 0x09, 0x0a, 0x0d].contains(bytes[index]) {
      index += 1
    }
  }

  private mutating func consume(_ expected: UInt8) throws {
    guard consumeIf(expected) else { throw malformed() }
  }

  private mutating func consumeIf(_ expected: UInt8) -> Bool {
    guard index < bytes.count, bytes[index] == expected else { return false }
    index += 1
    return true
  }

  private func requireEnd() throws {
    guard index == bytes.count else { throw malformed() }
  }

  private func malformed() -> FixtureControlReadError {
    .mismatch(.events, .malformed)
  }
}

private func makePOSIXError(code: Int32) -> POSIXError {
  POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
}
