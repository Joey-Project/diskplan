import Darwin
import Foundation
import Testing

@testable import DiskplanFileProviderFixtureSupport

@Test
func preAttemptEMFILELeavesDurableAdmissionPoison() throws {
  let fixture = try AdmissionFixture()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  let admission = try log.makeAdmissionChannel(injectAttemptMarkerFailure: true)
  let recorder = OracleRecorder(
    append: { _, _ in Issue.record("append must not run") },
    beginAttempt: { deadline in
      try admission.beginRecordAttempt(
        deadlineNanoseconds: deadline,
        clock: SystemOracleQuiescenceClock()
      )
    }
  )

  #expect(throws: POSIXError.self) { try recorder.record(fixture.event(.itemMetadata)) }
  #expect(try log.recorderState() == .poisoned)
}

@Test
func hangingFailurePublisherCannotBecomeCallbackZero() throws {
  let fixture = try AdmissionFixture()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  let admission = try log.makeAdmissionChannel()
  let release = DispatchSemaphore(value: 0)
  let recorder = OracleRecorder(
    append: { _, _ in Issue.record("append must not run") },
    state: { _ in throw POSIXError(.EIO) },
    failure: { _ in release.wait() },
    beginAttempt: { deadline in
      try admission.beginRecordAttempt(
        deadlineNanoseconds: deadline,
        clock: SystemOracleQuiescenceClock()
      )
    },
    timeoutNanoseconds: 50_000_000
  )

  let start = ContinuousClock.now
  #expect(throws: POSIXError.self) {
    try recorder.record(fixture.event(.materializedItemsDidChange))
  }
  #expect(ContinuousClock.now - start < .seconds(1))
  #expect(try log.recorderState() == .poisoned)
  release.signal()
}

@Test
func admittedCallbackCannotDisappearBehindSealingCutoff() throws {
  let fixture = try AdmissionFixture()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  try log.writeWindow(
    OracleWindow(beginNanoseconds: 0, bootGeneration: fixture.bootGeneration))
  let recorder = try OracleRecorder(log: log)
  let admitted = DispatchSemaphore(value: 0)
  let release = DispatchSemaphore(value: 0)
  let finished = DispatchSemaphore(value: 0)
  let result = AdmissionLockedError()

  Thread.detachNewThread {
    do {
      try recorder.record {
        admitted.signal()
        release.wait()
        return fixture.event(.itemMetadata)
      }
    } catch {
      result.store(error)
    }
    finished.signal()
  }
  #expect(admitted.wait(timeout: .now() + 1) == .success)
  release.signal()
  #expect(finished.wait(timeout: .now() + 1) == .success)
  #expect(result.error == nil)
  let closed = try log.closeWindowAfterQuiescence(
    quietMilliseconds: 50,
    timeoutMilliseconds: 2_000
  )
  #expect(closed.eventCount == 1)
  #expect(try log.sealedSnapshot().events.map(\.kind) == [.itemMetadata])
}

@Test
func preCutoffAdmissionCannotBeHiddenWhenSealingWinsBeforeAttemptMarker() throws {
  let fixture = try AdmissionFixture()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  let witnessed = DispatchSemaphore(value: 0)
  let releaseAdmission = DispatchSemaphore(value: 0)
  let admission = try log.makeAdmissionChannel {
    witnessed.signal()
    releaseAdmission.wait()
  }
  let recorder = OracleRecorder(
    append: { _, _ in Issue.record("append must not run after sealing wins") },
    beginAttempt: { deadline in
      try admission.beginRecordAttempt(
        deadlineNanoseconds: deadline,
        clock: SystemOracleQuiescenceClock()
      )
    }
  )
  let finished = DispatchSemaphore(value: 0)
  let result = AdmissionLockedError()
  Thread.detachNewThread {
    do {
      try recorder.record(fixture.event(.itemMetadata))
    } catch {
      result.store(error)
    }
    finished.signal()
  }

  #expect(witnessed.wait(timeout: .now() + 1) == .success)
  #expect(throws: OracleRecorderError.poisoned) { try log.sealRecorder() }
  releaseAdmission.signal()
  #expect(finished.wait(timeout: .now() + 1) == .success)
  #expect(result.error as? OracleRecorderError == .sealed)
  #expect(try log.recorderState() == .poisoned)
}

@Test
func callbackRejectsCanonicalRunDirectoryReplacement() throws {
  let fixture = try AdmissionFixture()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  let recorder = try OracleRecorder(log: log)
  let displaced = fixture.root.appendingPathComponent("displaced", isDirectory: true)
  try FileManager.default.moveItem(at: fixture.runDirectory, to: displaced)
  try FileManager.default.createDirectory(
    at: fixture.runDirectory, withIntermediateDirectories: false)
  guard chmod(fixture.runDirectory.path, 0o700) == 0 else { throw POSIXError(.EACCES) }
  try OracleLog(runDirectory: fixture.runDirectory).prepare()

  #expect(throws: FixtureContractError.self) {
    try recorder.record(fixture.event(.itemMetadata))
  }
  #expect(try OracleLog(runDirectory: fixture.runDirectory).events().isEmpty)
}

@Test
func windowDurabilityFailureCannotPublishSealedRecorder() throws {
  let fixture = try AdmissionFixture()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  try log.append(fixture.event(.itemMetadata))
  try log.writeWindow(
    OracleWindow(beginNanoseconds: 0, bootGeneration: fixture.bootGeneration))

  #expect(throws: OracleWindowWriteInjectedFailure.afterRenameBeforeDirectorySync) {
    _ = try log.closeWindowAfterQuiescence(
      quietMilliseconds: 50,
      timeoutMilliseconds: 1_000,
      clock: AdmissionAdvancingClock(),
      windowWriteFailure: .afterRenameBeforeDirectorySync
    )
  }
  #expect(throws: FixtureControlReadError.self) {
    try SecureFixtureStorage.readControlFile(
      at: fixture.runDirectory.appendingPathComponent("recorder-sealed"),
      record: .events
    )
  }
}

@Test
func teardownSealingIsIdempotentAcrossRecoveryRuns() throws {
  let fixture = try AdmissionFixture()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()

  try log.sealRecorder()
  try log.sealRecorder()

  #expect(try log.recorderState() == .sealed)
  let admissions = try String(
    contentsOf: fixture.runDirectory.appendingPathComponent("recorder-admissions.log"),
    encoding: .utf8
  )
  #expect(admissions.split(separator: "\n").filter { $0.hasPrefix("cutoff ") }.count == 1)
}

@Test
func teardownSealingResumesDurableCutoffIntermediateState() throws {
  let fixture = try AdmissionFixture()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  try fixture.writePrivate(
    Data("diskplan-recorder-state-v1\n".utf8),
    named: "recorder-sealing"
  )
  try fixture.writePrivate(
    Data("cutoff \(UUID().uuidString.lowercased())\n".utf8),
    named: "recorder-admissions.log",
    replace: true
  )

  try log.sealRecorder()
  try log.sealRecorder()

  #expect(try log.recorderState() == .sealed)
  let admissions = try String(
    contentsOf: fixture.runDirectory.appendingPathComponent("recorder-admissions.log"),
    encoding: .utf8
  )
  #expect(admissions.split(separator: "\n").filter { $0.hasPrefix("cutoff ") }.count == 1)
}

private struct AdmissionFixture: @unchecked Sendable {
  let root: URL
  let runDirectory: URL
  let runID = UUID()
  let bootGeneration: String

  init() throws {
    bootGeneration = try ExternalMutationBootSession.currentGeneration()
    root = FileManager.default.temporaryDirectory.appendingPathComponent(
      "diskplan-admission-\(UUID().uuidString.lowercased())",
      isDirectory: true
    )
    runDirectory = root.appendingPathComponent(runID.uuidString.lowercased(), isDirectory: true)
    try FileManager.default.createDirectory(at: runDirectory, withIntermediateDirectories: true)
    guard chmod(root.path, 0o700) == 0, chmod(runDirectory.path, 0o700) == 0 else {
      throw POSIXError(.EACCES)
    }
  }

  func event(_ kind: OracleEventKind) -> OracleEvent {
    OracleEvent(
      runID: runID,
      domainIdentifier: FixtureContract.domainIdentifier(runID: runID),
      bootGeneration: bootGeneration,
      itemIdentifier: FixtureContract.sentinelIdentifier,
      kind: kind,
      processID: getpid(),
      monotonicNanoseconds: max(1, clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW))
    )
  }

  func writePrivate(_ data: Data, named name: String, replace: Bool = false) throws {
    let url = runDirectory.appendingPathComponent(name)
    if replace { try FileManager.default.removeItem(at: url) }
    try data.write(to: url, options: .withoutOverwriting)
    guard chmod(url.path, 0o600) == 0 else { throw POSIXError(.EACCES) }
  }

  func remove() { try? FileManager.default.removeItem(at: root) }
}

private final class AdmissionLockedError: @unchecked Sendable {
  private let lock = NSLock()
  private var stored: Error?
  var error: Error? { lock.withLock { stored } }
  func store(_ error: Error) { lock.withLock { stored = error } }
}

private final class AdmissionAdvancingClock: OracleQuiescenceClock, @unchecked Sendable {
  private let lock = NSLock()
  private var value: UInt64 = 0
  func nowNanoseconds() -> UInt64 { lock.withLock { value } }
  func sleepForPoll() { lock.withLock { value += 50_000_000 } }
  func didReadFingerprint() {}
}
