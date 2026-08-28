import Darwin
import Foundation
import Testing

@testable import DiskplanFileProviderFixtureSupport

@Test
func sentinelHasExactStableSize() {
  let first = FixtureContract.sentinelContents()
  #expect(first.count == 65_536)
  #expect(first == FixtureContract.sentinelContents())
  #expect(
    String(decoding: first.prefix(31), as: UTF8.self).hasPrefix("diskplan-file-provider-fixture"))
}

@Test
func domainRoundTripsOnlyExactUUIDSuffix() throws {
  let runID = UUID()
  let identifier = FixtureContract.domainIdentifier(runID: runID)
  #expect(FixtureContract.runID(domainIdentifier: identifier) == runID)
  #expect(FixtureContract.runID(domainIdentifier: "other-(runID)") == nil)
  #expect(FixtureContract.runID(domainIdentifier: identifier + "-extra") == nil)
}

@Test
func oracleAssignsMonotonicSequenceUnderOneLockedFile() throws {
  let container = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: container) }
  try FileManager.default.createDirectory(at: container, withIntermediateDirectories: false)
  let runID = UUID()
  let root = container.appendingPathComponent("runs").appendingPathComponent(runID.uuidString)
  let log = OracleLog(runDirectory: root)
  try log.prepare()
  for kind in [OracleEventKind.itemMetadata, .fetchContents] {
    try log.append(
      OracleEvent(
        runID: runID,
        domainIdentifier: FixtureContract.domainIdentifier(runID: runID),
        itemIdentifier: FixtureContract.sentinelIdentifier,
        kind: kind,
        processID: 1,
        monotonicNanoseconds: 10
      )
    )
  }
  let events = try log.events()
  #expect(events.map(\.sequence) == [1, 2])
  #expect(events.map(\.kind) == [.itemMetadata, .fetchContents])
}

@Test
func oracleSerializesConcurrentWriters() async throws {
  let container = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: container) }
  try FileManager.default.createDirectory(at: container, withIntermediateDirectories: false)
  let runID = UUID()
  let root = container.appendingPathComponent("runs").appendingPathComponent(runID.uuidString)
  let log = OracleLog(runDirectory: root)
  try log.prepare()
  try await withThrowingTaskGroup(of: Void.self) { group in
    for index in 0..<32 {
      group.addTask {
        try log.append(
          OracleEvent(
            runID: runID,
            domainIdentifier: FixtureContract.domainIdentifier(runID: runID),
            itemIdentifier: String(index),
            kind: .itemMetadata,
            processID: 1,
            monotonicNanoseconds: UInt64(index)
          )
        )
      }
    }
    try await group.waitForAll()
  }
  let events = try log.events()
  #expect(events.count == 32)
  #expect(events.map(\.sequence) == Array(1...32))
}

@Test
func manifestRejectsPathsOutsideItsRunUUID() {
  let runID = UUID()
  let manifest = FixtureManifest(
    runID: runID,
    taskRoot: "/private/tmp/other",
    appPath: "/tmp/fixture.app",
    extensionPath: "/tmp/fixture.app/Contents/PlugIns/fixture.appex",
    appGroupRunPath: "/tmp/group/runs/other"
  )
  #expect(throws: FixtureContractError.unsafePath) { try manifest.validate() }
}

@Test
func readyOverlayIsBoundToManifestAndExactFixtureNames() throws {
  let runID = UUID()
  let runComponent = runID.uuidString.lowercased()
  let manifest = FixtureManifest(
    runID: runID,
    taskRoot: "/private/tmp/group/runs/\(runComponent)",
    appPath: "/tmp/fixture.app",
    extensionPath: "/tmp/fixture.app/Contents/PlugIns/fixture.appex",
    appGroupRunPath: "/private/tmp/group/runs/\(runComponent)"
  )
  let parent = "/Users/test/Library/CloudStorage/fixture"
  let ready = FixtureReadyState(
    runID: runID,
    sentinelPath: "\(parent)/\(FixtureContract.sentinelName)",
    sealedDirectoryPath: "\(parent)/\(FixtureContract.sealedDirectoryName)"
  )
  try ready.validate(manifest: manifest)

  let wrongName = FixtureReadyState(
    runID: runID,
    sentinelPath: "\(parent)/other.txt",
    sealedDirectoryPath: "\(parent)/\(FixtureContract.sealedDirectoryName)"
  )
  #expect(throws: FixtureContractError.invalidManifest) {
    try wrongName.validate(manifest: manifest)
  }
}

@Test
func oracleWindowCountsOnlyForbiddenEventsInsideBounds() {
  let runID = UUID()
  let window = OracleWindow(beginNanoseconds: 20, endNanoseconds: 30)
  let events = [
    OracleEvent(
      runID: runID, domainIdentifier: "d", itemIdentifier: "i", kind: .fetchContents, processID: 1,
      monotonicNanoseconds: 19),
    OracleEvent(
      runID: runID, domainIdentifier: "d", itemIdentifier: "i", kind: .fetchContents, processID: 1,
      monotonicNanoseconds: 20),
    OracleEvent(
      runID: runID, domainIdentifier: "d", itemIdentifier: "i", kind: .rootEnumeration,
      processID: 1, monotonicNanoseconds: 25),
    OracleEvent(
      runID: runID, domainIdentifier: "d", itemIdentifier: "i", kind: .deleteItem, processID: 1,
      monotonicNanoseconds: 31),
  ]
  let rejected = events.filter {
    window.contains($0) && FixtureContract.forbiddenEventKinds.contains($0.kind)
  }
  #expect(rejected.count == 1)
}

@Test
func secureManifestReadKeepsMissingSymlinkAndAccessMismatchDistinct() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let manifestURL = fixture.runDirectory.appendingPathComponent("manifest.json")

  do {
    _ = try SecureFixtureStorage.readManifest(
      at: manifestURL,
      expectedRunDirectory: fixture.runDirectory
    )
    Issue.record("missing manifest unexpectedly loaded")
  } catch let error as FixtureControlReadError {
    #expect(error == .missing(.manifest))
  }

  let target = fixture.runDirectory.appendingPathComponent("target.json")
  try fixture.manifestData.write(to: target)
  try FileManager.default.createSymbolicLink(at: manifestURL, withDestinationURL: target)
  do {
    _ = try SecureFixtureStorage.readManifest(
      at: manifestURL,
      expectedRunDirectory: fixture.runDirectory
    )
    Issue.record("symlink manifest unexpectedly loaded")
  } catch let error as FixtureControlReadError {
    #expect(error == .mismatch(.manifest, .objectType))
  }
  try FileManager.default.removeItem(at: manifestURL)
  try fixture.writePrivate(fixture.manifestData, to: manifestURL)
  guard chmod(manifestURL.path, 0o644) == 0 else { throw POSIXError(.EIO) }
  do {
    _ = try SecureFixtureStorage.readManifest(
      at: manifestURL,
      expectedRunDirectory: fixture.runDirectory
    )
    Issue.record("public manifest unexpectedly loaded")
  } catch let error as FixtureControlReadError {
    #expect(error == .mismatch(.manifest, .accessPolicy))
  }
}

@Test
func secureManifestReadClassifiesMalformedContentAsMismatch() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let manifestURL = fixture.runDirectory.appendingPathComponent("manifest.json")
  try fixture.writePrivate(Data("not-json".utf8), to: manifestURL)
  do {
    _ = try SecureFixtureStorage.readManifest(
      at: manifestURL,
      expectedRunDirectory: fixture.runDirectory
    )
    Issue.record("malformed manifest unexpectedly loaded")
  } catch let error as FixtureControlReadError {
    #expect(error == .mismatch(.manifest, .malformed))
  }
}

@Test
func secureManifestReadKeepsUnreadableOversizeAndSemanticMismatchDistinct() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let manifestURL = fixture.runDirectory.appendingPathComponent("manifest.json")
  try fixture.writePrivate(fixture.manifestData, to: manifestURL)
  guard chmod(manifestURL.path, 0o000) == 0 else { throw POSIXError(.EIO) }
  do {
    _ = try SecureFixtureStorage.readManifest(
      at: manifestURL,
      expectedRunDirectory: fixture.runDirectory
    )
    Issue.record("unreadable manifest unexpectedly loaded")
  } catch let error as FixtureControlReadError {
    if case .unreadable(.manifest, _) = error {
      // Expected typed unreadable result.
    } else {
      Issue.record("expected unreadable, observed \(error)")
    }
  }

  guard chmod(manifestURL.path, 0o600) == 0 else { throw POSIXError(.EIO) }
  try FileManager.default.removeItem(at: manifestURL)
  try fixture.writePrivate(
    Data(count: SecureFixtureStorage.maximumControlBytes + 1),
    to: manifestURL
  )
  do {
    _ = try SecureFixtureStorage.readManifest(
      at: manifestURL,
      expectedRunDirectory: fixture.runDirectory
    )
    Issue.record("oversize manifest unexpectedly loaded")
  } catch let error as FixtureControlReadError {
    #expect(error == .mismatch(.manifest, .sizeLimit))
  }

  try FileManager.default.removeItem(at: manifestURL)
  let otherRoot = "/private/tmp/other/\(fixture.runID.uuidString.lowercased())"
  let semanticMismatch = FixtureManifest(
    runID: fixture.runID,
    taskRoot: fixture.runDirectory.path,
    appPath: "/private/tmp/fixture.app",
    extensionPath: "/private/tmp/fixture.app/Contents/PlugIns/fixture.appex",
    appGroupRunPath: otherRoot
  )
  try fixture.writePrivate(try JSONEncoder().encode(semanticMismatch), to: manifestURL)
  do {
    _ = try SecureFixtureStorage.readManifest(
      at: manifestURL,
      expectedRunDirectory: fixture.runDirectory
    )
    Issue.record("semantic mismatch unexpectedly loaded")
  } catch let error as FixtureControlReadError {
    #expect(error == .mismatch(.manifest, .semantic))
  }
}

@Test
func cleanupRemovesOnlyTheBoundPrivateRunTree() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let manifestURL = fixture.runDirectory.appendingPathComponent("manifest.json")
  try fixture.writePrivate(fixture.manifestData, to: manifestURL)
  try fixture.writePrivate(
    Data("event\n".utf8),
    to: fixture.runDirectory.appendingPathComponent("events.jsonl")
  )
  let nested = fixture.runDirectory.appendingPathComponent("nested")
  try FileManager.default.createDirectory(at: nested, withIntermediateDirectories: false)
  guard chmod(nested.path, 0o700) == 0 else { throw POSIXError(.EIO) }
  try fixture.writePrivate(Data("value".utf8), to: nested.appendingPathComponent("value"))

  try SecureFixtureStorage.cleanupRun(
    manifestURL: manifestURL,
    expectedRunDirectory: fixture.runDirectory
  )
  #expect(!FileManager.default.fileExists(atPath: fixture.runDirectory.path))
}

@Test
func cleanupRejectsSymlinkAndRestoresManifestForRecovery() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let manifestURL = fixture.runDirectory.appendingPathComponent("manifest.json")
  try fixture.writePrivate(fixture.manifestData, to: manifestURL)
  try FileManager.default.createSymbolicLink(
    at: fixture.runDirectory.appendingPathComponent("unexpected-link"),
    withDestinationURL: FileManager.default.temporaryDirectory
  )
  do {
    try SecureFixtureStorage.cleanupRun(
      manifestURL: manifestURL,
      expectedRunDirectory: fixture.runDirectory
    )
    Issue.record("cleanup unexpectedly followed or removed a symlink")
  } catch let error as FixtureCleanupError {
    #expect(error == .treeMismatch("unexpected-link"))
  }
  #expect(FileManager.default.fileExists(atPath: manifestURL.path))
  _ = try SecureFixtureStorage.readManifest(
    at: manifestURL,
    expectedRunDirectory: fixture.runDirectory
  )
}

@Test
func cleanupFinalRemovalFailureRestoresDeterministicRecoveryManifest() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let manifestURL = fixture.runDirectory.appendingPathComponent("manifest.json")
  try fixture.writePrivate(fixture.manifestData, to: manifestURL)
  do {
    try SecureFixtureStorage.cleanupRun(
      manifestURL: manifestURL,
      expectedRunDirectory: fixture.runDirectory,
      injectFinalDirectoryRemovalFailure: true
    )
    Issue.record("cleanup unexpectedly ignored the injected final removal failure")
  } catch let error as FixtureCleanupError {
    #expect(error == .operationFailed("injected-final-directory-removal", errno: EBUSY))
  }
  #expect(FileManager.default.fileExists(atPath: manifestURL.path))
  #expect(
    !FileManager.default.fileExists(
      atPath: fixture.runDirectory.deletingLastPathComponent()
        .appendingPathComponent(".cleanup-\(fixture.runDirectory.lastPathComponent)").path
    )
  )
  _ = try SecureFixtureStorage.readManifest(
    at: manifestURL,
    expectedRunDirectory: fixture.runDirectory
  )
}

@Test
func oracleCloseRequiresTwoSecondsAfterALateCallback() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  try log.append(
    OracleEvent(
      runID: fixture.runID,
      domainIdentifier: FixtureContract.domainIdentifier(runID: fixture.runID),
      itemIdentifier: FixtureContract.sentinelIdentifier,
      kind: .itemMetadata,
      processID: 1,
      monotonicNanoseconds: 1
    )
  )
  try log.writeWindow(OracleWindow(beginNanoseconds: 1))
  let clock = DeterministicOracleClock()
  clock.onAdvance = { nanoseconds in
    guard nanoseconds == 1_000_000_000 else { return }
    try? log.append(
      OracleEvent(
        runID: fixture.runID,
        domainIdentifier: FixtureContract.domainIdentifier(runID: fixture.runID),
        itemIdentifier: FixtureContract.sentinelIdentifier,
        kind: .itemMetadata,
        processID: 2,
        monotonicNanoseconds: nanoseconds
      )
    )
  }
  let result = try log.closeWindowAfterQuiescence(
    quietMilliseconds: 2_000,
    timeoutMilliseconds: 30_000,
    clock: clock
  )
  #expect(result.eventCount == 2)
  #expect(result.lastSequence == 2)
  #expect(clock.nanoseconds == 3_000_000_000)
  #expect(try log.window().endNanoseconds == 3_000_000_000)
}

@Test
func oracleRecorderPoisonsAfterInjectedAppendFailure() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let attempts = LockedCounter()
  let recorder = OracleRecorder { _ in
    attempts.increment()
    throw POSIXError(.EIO)
  }
  let event = OracleEvent(
    runID: fixture.runID,
    domainIdentifier: FixtureContract.domainIdentifier(runID: fixture.runID),
    itemIdentifier: FixtureContract.sentinelIdentifier,
    kind: .fetchContents,
    processID: 1,
    monotonicNanoseconds: 1
  )
  #expect(throws: POSIXError.self) { try recorder.record(event) }
  #expect(throws: OracleRecorderError.poisoned) { try recorder.record(event) }
  #expect(attempts.value == 1)
}

@Test
func recorderPoisonPersistsAcrossRecorderRecreation() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  let eventsURL = fixture.runDirectory.appendingPathComponent("events.jsonl")
  try fixture.writePrivate(Data(), to: eventsURL)
  guard chmod(eventsURL.path, 0o644) == 0 else { throw POSIXError(.EIO) }
  let event = OracleEvent(
    runID: fixture.runID,
    domainIdentifier: FixtureContract.domainIdentifier(runID: fixture.runID),
    itemIdentifier: FixtureContract.sentinelIdentifier,
    kind: .fetchContents,
    processID: 1,
    monotonicNanoseconds: 1
  )
  #expect(throws: FixtureContractError.self) { try OracleRecorder(log: log).record(event) }
  #expect(try log.recorderState() == .poisoned)
  guard chmod(eventsURL.path, 0o600) == 0 else { throw POSIXError(.EIO) }
  #expect(throws: OracleRecorderError.poisoned) {
    try OracleRecorder(log: log).record(event)
  }
}

@Test
func writeAheadPoisonSurvivesInjectedPoisonStorageFailure() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  let event = fixture.oracleEvent(kind: .fetchContents)
  let recorder = OracleRecorder(
    append: { try log.append($0, injecting: .poisonStorage) },
    state: { try log.recorderState() },
    poison: { try log.poisonRecorder() }
  )
  #expect(throws: OracleAppendInjectedFailure.poisonStorage) { try recorder.record(event) }
  #expect(try log.recorderState() == .poisoned)
  #expect(throws: OracleRecorderError.poisoned) {
    try OracleRecorder(log: log).record(event)
  }
}

@Test
func writeAheadPoisonSurvivesInjectedEventStorageFailure() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  let event = fixture.oracleEvent(kind: .fetchContents)
  let recorder = OracleRecorder(
    append: { try log.append($0, injecting: .eventStorage) },
    state: { try log.recorderState() },
    poison: { try log.poisonRecorder() }
  )
  #expect(throws: OracleAppendInjectedFailure.eventStorage) { try recorder.record(event) }
  #expect(try log.recorderState() == .poisoned)
  #expect(throws: OracleRecorderError.poisoned) {
    try OracleRecorder(log: log).record(event)
  }
}

@Test
func appendDoesNotRecreateMissingRunDirectory() throws {
  let container = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
  defer { try? FileManager.default.removeItem(at: container) }
  let runDirectory = container.appendingPathComponent("missing-run")
  let log = OracleLog(runDirectory: runDirectory)
  let event = OracleEvent(
    runID: UUID(),
    domainIdentifier: "missing",
    itemIdentifier: FixtureContract.sentinelIdentifier,
    kind: .itemMetadata,
    processID: 1,
    monotonicNanoseconds: 1
  )
  #expect(throws: POSIXError.self) { try log.append(event) }
  #expect(!FileManager.default.fileExists(atPath: runDirectory.path))
}

@Test
func sealedRecorderRejectsLateAppendWithoutRecreatingState() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  try log.sealRecorder()
  let event = OracleEvent(
    runID: fixture.runID,
    domainIdentifier: FixtureContract.domainIdentifier(runID: fixture.runID),
    itemIdentifier: FixtureContract.sentinelIdentifier,
    kind: .itemMetadata,
    processID: 1,
    monotonicNanoseconds: 1
  )
  #expect(throws: OracleRecorderError.sealed) { try log.append(event) }
  #expect(try log.events().isEmpty)
}

@Test
func oracleDeadlineWinsWhenQuietAndTimeoutBecomeEligibleTogether() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  try log.writeWindow(OracleWindow(beginNanoseconds: 0))
  let clock = DeterministicOracleClock()
  #expect(throws: OracleQuiescenceError.timedOut) {
    try log.closeWindowAfterQuiescence(
      quietMilliseconds: 50,
      timeoutMilliseconds: 50,
      clock: clock
    )
  }
}

@Test
func oracleQuietStartsAfterInitialFingerprintRead() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  try log.writeWindow(OracleWindow(beginNanoseconds: 0))
  let clock = AdvancingOracleClock()
  _ = try log.closeWindowAfterQuiescence(
    quietMilliseconds: 2_000,
    timeoutMilliseconds: 5_000,
    clock: clock
  )
  #expect(try log.window().endNanoseconds == 3_000_000_000)
}

@Test
func recorderLockContentionHonorsAbsoluteDeadline() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  let lockURL = fixture.runDirectory.appendingPathComponent("recorder.lock")
  let descriptor = open(lockURL.path, O_RDWR | O_CLOEXEC | O_NOFOLLOW)
  guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
  defer { close(descriptor) }
  guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
  }
  defer { flock(descriptor, LOCK_UN) }
  let clock = DeterministicOracleClock()
  #expect(throws: OracleRecorderError.lockTimedOut) {
    try log.recorderState(deadlineNanoseconds: 100_000_000, clock: clock)
  }
  #expect(clock.nanoseconds == 100_000_000)
}

@Test
func eventLockContentionUsesTheSameAbsoluteDeadlineAndPoisons() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  let eventsURL = fixture.runDirectory.appendingPathComponent("events.jsonl")
  try fixture.writePrivate(Data(), to: eventsURL)
  let descriptor = open(eventsURL.path, O_RDWR | O_CLOEXEC | O_NOFOLLOW)
  guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
  defer { close(descriptor) }
  guard flock(descriptor, LOCK_EX | LOCK_NB) == 0 else {
    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
  }
  defer { flock(descriptor, LOCK_UN) }
  let clock = DeterministicOracleClock()
  #expect(throws: OracleRecorderError.lockTimedOut) {
    try log.append(
      fixture.oracleEvent(kind: .fetchContents),
      injecting: nil,
      deadlineNanoseconds: 100_000_000,
      clock: clock
    )
  }
  #expect(clock.nanoseconds == 100_000_000)
  #expect(try log.recorderState() == .poisoned)
}

@Test
func callbackGateDeterministicallyRejectsLateAndNeverCallbacks() {
  let lateCallback = OneShotCallbackGate()
  #expect(lateCallback.claimCompletion(from: .callback))
  #expect(!lateCallback.claimCompletion(from: .deadline))
  #expect(lateCallback.completionSource == .callback)

  let neverCallback = OneShotCallbackGate()
  #expect(neverCallback.claimCompletion(from: .deadline))
  #expect(!neverCallback.claimCompletion(from: .callback))
  #expect(neverCallback.completionSource == .deadline)
}

@Test
func secureWindowReadRejectsInvalidClosedWindowSemantics() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let invalid = OracleWindow(
    beginNanoseconds: 20,
    endNanoseconds: 10,
    quietMilliseconds: 2_000,
    eventCount: 0,
    lastSequence: 0
  )
  try fixture.writePrivate(
    try JSONEncoder().encode(invalid),
    to: fixture.runDirectory.appendingPathComponent("window.json")
  )
  #expect(throws: FixtureControlReadError.mismatch(.window, .semantic)) {
    try SecureFixtureStorage.readWindow(runDirectory: fixture.runDirectory)
  }
}

@Test
func cleanupDeviceBoundaryRejectsDifferentDevices() {
  #expect(isSameCleanupDevice(42, 42))
  #expect(!isSameCleanupDevice(42, 43))
}

private final class DeterministicOracleClock: OracleQuiescenceClock {
  var nanoseconds: UInt64 = 0
  var onAdvance: ((UInt64) -> Void)?

  func nowNanoseconds() -> UInt64 { nanoseconds }

  func sleepForPoll() {
    nanoseconds += 50_000_000
    onAdvance?(nanoseconds)
  }
}

private final class AdvancingOracleClock: OracleQuiescenceClock {
  private var next: UInt64 = 0

  func nowNanoseconds() -> UInt64 {
    defer { next += 1_000_000_000 }
    return next
  }

  func sleepForPoll() {}
}

private final class LockedCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var storage = 0

  var value: Int {
    lock.withLock { storage }
  }

  func increment() {
    lock.withLock { storage += 1 }
  }
}

private struct TemporaryFixtureRun {
  let container: URL
  let runID: UUID
  let runDirectory: URL
  let manifestData: Data

  init() throws {
    container = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    runID = UUID()
    let runs = container.appendingPathComponent("runs")
    runDirectory = runs.appendingPathComponent(runID.uuidString.lowercased())
    try FileManager.default.createDirectory(at: runDirectory, withIntermediateDirectories: true)
    guard chmod(container.path, 0o700) == 0, chmod(runs.path, 0o700) == 0,
      chmod(runDirectory.path, 0o700) == 0
    else { throw POSIXError(.EIO) }
    let manifest = FixtureManifest(
      runID: runID,
      taskRoot: runDirectory.path,
      appPath: "/private/tmp/fixture.app",
      extensionPath: "/private/tmp/fixture.app/Contents/PlugIns/fixture.appex",
      appGroupRunPath: runDirectory.path
    )
    manifestData = try JSONEncoder().encode(manifest)
  }

  func writePrivate(_ data: Data, to url: URL) throws {
    try data.write(to: url, options: .withoutOverwriting)
    guard chmod(url.path, 0o600) == 0 else { throw POSIXError(.EIO) }
  }

  func oracleEvent(kind: OracleEventKind) -> OracleEvent {
    OracleEvent(
      runID: runID,
      domainIdentifier: FixtureContract.domainIdentifier(runID: runID),
      itemIdentifier: FixtureContract.sentinelIdentifier,
      kind: kind,
      processID: 1,
      monotonicNanoseconds: 1
    )
  }

  func remove() { try? FileManager.default.removeItem(at: container) }
}
