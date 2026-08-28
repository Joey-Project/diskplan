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
  #expect(
    !FileManager.default.fileExists(
      atPath: SecureFixtureStorage.cleanupRecoveryManifestURL(
        for: fixture.runDirectory
      ).path
    )
  )
}

@Test
func cleanupCrashBeforeFinalRemovalRetainsExternalRecoveryEvidence() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let manifestURL = fixture.runDirectory.appendingPathComponent("manifest.json")
  try fixture.writePrivate(fixture.manifestData, to: manifestURL)
  #expect(throws: Error.self) {
    try SecureFixtureStorage.cleanupRun(
      manifestURL: manifestURL,
      expectedRunDirectory: fixture.runDirectory,
      injectFinalDirectoryRemovalFailure: false,
      injectCrashBeforeFinalDirectoryRemoval: true
    )
  }
  let recoveryURL = SecureFixtureStorage.cleanupRecoveryManifestURL(
    for: fixture.runDirectory
  )
  #expect(!FileManager.default.fileExists(atPath: fixture.runDirectory.path))
  #expect(FileManager.default.fileExists(atPath: recoveryURL.path))
  #expect(
    try SecureFixtureStorage.readControlFile(
      at: recoveryURL,
      record: .manifest
    ) == fixture.manifestData
  )
  #expect(
    try SecureFixtureStorage.readCleanupRecoveryManifest(
      at: recoveryURL,
      expectedRunDirectory: fixture.runDirectory
    ).runID == fixture.runID
  )
  #expect(
    FileManager.default.fileExists(
      atPath: fixture.runDirectory.deletingLastPathComponent()
        .appendingPathComponent(".cleanup-\(fixture.runDirectory.lastPathComponent)").path
    )
  )
}

@Test
func cleanupCrashAfterDurableFinalRemovalRetainsExternalRecoveryEvidence() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let manifestURL = fixture.runDirectory.appendingPathComponent("manifest.json")
  try fixture.writePrivate(fixture.manifestData, to: manifestURL)
  #expect(throws: Error.self) {
    try SecureFixtureStorage.cleanupRun(
      manifestURL: manifestURL,
      expectedRunDirectory: fixture.runDirectory,
      injectFinalDirectoryRemovalFailure: false,
      injectCrashAfterFinalDirectoryRemoval: true
    )
  }
  let recoveryURL = SecureFixtureStorage.cleanupRecoveryManifestURL(
    for: fixture.runDirectory
  )
  let stagingURL = SecureFixtureStorage.cleanupStagingDirectoryURL(
    for: fixture.runDirectory
  )
  #expect(!FileManager.default.fileExists(atPath: fixture.runDirectory.path))
  #expect(!FileManager.default.fileExists(atPath: stagingURL.path))
  #expect(FileManager.default.fileExists(atPath: recoveryURL.path))
  #expect(
    try SecureFixtureStorage.readCleanupRecoveryManifest(
      at: recoveryURL,
      expectedRunDirectory: fixture.runDirectory
    ).runID == fixture.runID
  )
}

@Test
func recoveryCleanupRemovesOnlyExactStagingAndSiblingManifest() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let manifestURL = fixture.runDirectory.appendingPathComponent("manifest.json")
  try fixture.writePrivate(fixture.manifestData, to: manifestURL)
  #expect(throws: Error.self) {
    try SecureFixtureStorage.cleanupRun(
      manifestURL: manifestURL,
      expectedRunDirectory: fixture.runDirectory,
      injectFinalDirectoryRemovalFailure: false,
      injectCrashBeforeFinalDirectoryRemoval: true
    )
  }
  let recoveryURL = SecureFixtureStorage.cleanupRecoveryManifestURL(
    for: fixture.runDirectory
  )
  let stagingURL = SecureFixtureStorage.cleanupStagingDirectoryURL(
    for: fixture.runDirectory
  )
  try SecureFixtureStorage.recoverCleanup(
    recoveryManifestURL: recoveryURL,
    expectedRunDirectory: fixture.runDirectory
  )
  #expect(!FileManager.default.fileExists(atPath: stagingURL.path))
  #expect(!FileManager.default.fileExists(atPath: recoveryURL.path))
}

@Test
func recoveryCleanupAfterDurableRmdirRemovesSiblingManifest() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let manifestURL = fixture.runDirectory.appendingPathComponent("manifest.json")
  try fixture.writePrivate(fixture.manifestData, to: manifestURL)
  #expect(throws: Error.self) {
    try SecureFixtureStorage.cleanupRun(
      manifestURL: manifestURL,
      expectedRunDirectory: fixture.runDirectory,
      injectFinalDirectoryRemovalFailure: false,
      injectCrashAfterFinalDirectoryRemoval: true
    )
  }
  let recoveryURL = SecureFixtureStorage.cleanupRecoveryManifestURL(
    for: fixture.runDirectory
  )
  try SecureFixtureStorage.recoverCleanup(
    recoveryManifestURL: recoveryURL,
    expectedRunDirectory: fixture.runDirectory
  )
  #expect(!FileManager.default.fileExists(atPath: recoveryURL.path))
}

@Test
func recoveryCleanupFailsClosedWhenCanonicalRunStillExists() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let manifestURL = fixture.runDirectory.appendingPathComponent("manifest.json")
  let recoveryURL = SecureFixtureStorage.cleanupRecoveryManifestURL(
    for: fixture.runDirectory
  )
  try fixture.writePrivate(fixture.manifestData, to: manifestURL)
  try fixture.writePrivate(fixture.manifestData, to: recoveryURL)
  #expect(throws: FixtureCleanupError.retained(recoveryURL.path)) {
    try SecureFixtureStorage.recoverCleanup(
      recoveryManifestURL: recoveryURL,
      expectedRunDirectory: fixture.runDirectory
    )
  }
  #expect(FileManager.default.fileExists(atPath: manifestURL.path))
  #expect(FileManager.default.fileExists(atPath: recoveryURL.path))
}

@Test
func recoveryCleanupRejectsAnyNonExactSiblingManifestPath() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let wrongURL = fixture.runDirectory.deletingLastPathComponent().appendingPathComponent(
    ".manifest-recovery-other.json"
  )
  try fixture.writePrivate(fixture.manifestData, to: wrongURL)
  #expect(throws: FixtureCleanupError.unsafeTarget) {
    try SecureFixtureStorage.recoverCleanup(
      recoveryManifestURL: wrongURL,
      expectedRunDirectory: fixture.runDirectory
    )
  }
  #expect(FileManager.default.fileExists(atPath: wrongURL.path))
}

@Test
func recoveryManifestRejectsSymlinkDotDotAliasBeforeOpening() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let runs = fixture.runDirectory.deletingLastPathComponent()
  let recoveryURL = SecureFixtureStorage.cleanupRecoveryManifestURL(
    for: fixture.runDirectory
  )
  try fixture.writePrivate(fixture.manifestData, to: recoveryURL)
  let child = runs.appendingPathComponent("alias-target", isDirectory: true)
  try FileManager.default.createDirectory(at: child, withIntermediateDirectories: false)
  guard chmod(child.path, 0o700) == 0 else { throw POSIXError(.EIO) }
  let alias = runs.appendingPathComponent("alias", isDirectory: true)
  guard symlink(child.path, alias.path) == 0 else {
    throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
  }
  let aliasedURL = URL(
    fileURLWithPath: "\(alias.path)/../\(recoveryURL.lastPathComponent)"
  )
  #expect(aliasedURL.path != recoveryURL.path)
  #expect(aliasedURL.standardizedFileURL == recoveryURL.standardizedFileURL)
  #expect(throws: FixtureControlReadError.mismatch(.manifest, .semantic)) {
    try SecureFixtureStorage.readCleanupRecoveryManifest(
      at: aliasedURL,
      expectedRunDirectory: fixture.runDirectory
    )
  }
  #expect(throws: FixtureCleanupError.unsafeTarget) {
    try SecureFixtureStorage.recoverCleanup(
      recoveryManifestURL: aliasedURL,
      expectedRunDirectory: fixture.runDirectory
    )
  }
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
  let recorder = OracleRecorder { _, _ in
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
    append: { event, deadline in
      try log.append(
        event,
        injecting: .poisonStorage,
        deadlineNanoseconds: deadline,
        clock: SystemOracleQuiescenceClock()
      )
    },
    state: { deadline in
      try log.recorderState(
        deadlineNanoseconds: deadline,
        clock: SystemOracleQuiescenceClock()
      )
    },
    poison: { deadline in
      try log.poisonRecorder(
        deadlineNanoseconds: deadline,
        clock: SystemOracleQuiescenceClock()
      )
    }
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
    append: { event, deadline in
      try log.append(
        event,
        injecting: .eventStorage,
        deadlineNanoseconds: deadline,
        clock: SystemOracleQuiescenceClock()
      )
    },
    state: { deadline in
      try log.recorderState(
        deadlineNanoseconds: deadline,
        clock: SystemOracleQuiescenceClock()
      )
    },
    poison: { deadline in
      try log.poisonRecorder(
        deadlineNanoseconds: deadline,
        clock: SystemOracleQuiescenceClock()
      )
    }
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
func finalSnapshotAndSealExcludeARacingCallback() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  try log.append(fixture.oracleEvent(kind: .itemMetadata))
  try log.writeWindow(OracleWindow(beginNanoseconds: 0))
  let started = DispatchSemaphore(value: 0)
  let finished = DispatchSemaphore(value: 0)
  let result = LockedRecorderResult()
  let recorder = OracleRecorder(log: log)
  _ = try log.closeWindowAfterQuiescence(
    quietMilliseconds: 2_000,
    timeoutMilliseconds: 30_000,
    clock: DeterministicOracleClock(),
    onFinalSnapshotLocked: {
      DispatchQueue.global().async {
        started.signal()
        do {
          try recorder.record(fixture.oracleEvent(kind: .fetchContents))
        } catch {
          result.store(error)
        }
        finished.signal()
      }
      started.wait()
    }
  )
  #expect(finished.wait(timeout: .now() + 2) == .success)
  #expect(result.recorderError == .sealed)
  #expect(try log.recorderState() == .sealed)
  #expect(try log.events().map(\.kind) == [.itemMetadata])
  #expect(try log.window().eventCount == 1)
}

@Test
func sealWaitsForInFlightFailureMarkerPublication() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  try log.writeWindow(OracleWindow(beginNanoseconds: 0))
  let failureStarted = DispatchSemaphore(value: 0)
  let releaseFailure = DispatchSemaphore(value: 0)
  let recordFinished = DispatchSemaphore(value: 0)
  let closeStarted = DispatchSemaphore(value: 0)
  let closeFinished = DispatchSemaphore(value: 0)
  let recordResult = LockedRecorderResult()
  let closeResult = LockedRecorderResult()
  let recorder = OracleRecorder(
    append: { _, _ in Issue.record("append unexpectedly ran after state-read failure") },
    state: { _ in throw POSIXError(.EIO) },
    failure: {
      failureStarted.signal()
      releaseFailure.wait()
      try log.failRecorder()
    },
    beginAttempt: { deadline in
      try log.beginRecordAttempt(
        deadlineNanoseconds: deadline,
        clock: SystemOracleQuiescenceClock()
      )
    }
  )
  DispatchQueue.global().async {
    do {
      try recorder.record(fixture.oracleEvent(kind: .materializedItemsDidChange))
    } catch {
      recordResult.store(error)
    }
    recordFinished.signal()
  }
  #expect(failureStarted.wait(timeout: .now() + 2) == .success)
  DispatchQueue.global().async {
    closeStarted.signal()
    do {
      _ = try log.closeWindowAfterQuiescence(
        quietMilliseconds: 50,
        timeoutMilliseconds: 3_000
      )
    } catch {
      closeResult.store(error)
    }
    closeFinished.signal()
  }
  #expect(closeStarted.wait(timeout: .now() + 2) == .success)
  #expect(closeFinished.wait(timeout: .now() + 0.1) == .timedOut)
  releaseFailure.signal()
  #expect(recordFinished.wait(timeout: .now() + 2) == .success)
  #expect(closeFinished.wait(timeout: .now() + 2) == .success)
  #expect(recordResult.errorIsPOSIX)
  #expect(closeResult.recorderError == .poisoned)
  #expect(try log.recorderState() == .poisoned)
}

@Test
func sealAttemptGateContentionFailsWithinAbsoluteDeadline() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  try log.writeWindow(OracleWindow(beginNanoseconds: 0))
  let attemptClock = DeterministicOracleClock()
  let attempt = try log.beginRecordAttempt(
    deadlineNanoseconds: 1_000_000_000,
    clock: attemptClock
  )
  defer { attempt.finish() }
  let closeClock = DeterministicOracleClock()
  #expect(throws: OracleQuiescenceError.timedOut) {
    _ = try log.closeWindowAfterQuiescence(
      quietMilliseconds: 50,
      timeoutMilliseconds: 50,
      clock: closeClock
    )
  }
  #expect(closeClock.nanoseconds == 50_000_000)
}

@Test
func failedFailureMarkerPublicationLeavesDurableIncompleteAttempt() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  try log.writeWindow(OracleWindow(beginNanoseconds: 0))
  let recorder = OracleRecorder(
    append: { _, _ in Issue.record("append unexpectedly ran after state-read failure") },
    state: { _ in throw POSIXError(.EIO) },
    failure: { throw POSIXError(.ENOSPC) },
    beginAttempt: { deadline in
      try log.beginRecordAttempt(
        deadlineNanoseconds: deadline,
        clock: SystemOracleQuiescenceClock()
      )
    }
  )
  #expect(throws: POSIXError.self) {
    try recorder.record(fixture.oracleEvent(kind: .materializedItemsDidChange))
  }
  #expect(try OracleLog(runDirectory: fixture.runDirectory).recorderState() == .poisoned)
  #expect(throws: OracleRecorderError.poisoned) {
    _ = try log.closeWindowAfterQuiescence(
      quietMilliseconds: 50,
      timeoutMilliseconds: 500
    )
  }
}

@Test
func abandonedRecordAttemptRemainsFailClosedAfterRecorderRecreation() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  try log.writeWindow(OracleWindow(beginNanoseconds: 0))
  let attempt = try log.beginRecordAttempt(
    deadlineNanoseconds: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) + 1_000_000_000,
    clock: SystemOracleQuiescenceClock()
  )
  attempt.finish()
  let recreated = OracleLog(runDirectory: fixture.runDirectory)
  #expect(try recreated.recorderState() == .poisoned)
  #expect(throws: OracleRecorderError.poisoned) {
    _ = try recreated.closeWindowAfterQuiescence(
      quietMilliseconds: 50,
      timeoutMilliseconds: 500
    )
  }
}

@Test
func oracleRecorderUsesOneEntryDeadlineAcrossAllStages() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let clock = SteppingOracleClock(stepNanoseconds: 25)
  let appendAttempts = LockedCounter()
  let poisonAttempts = LockedCounter()
  let recorder = OracleRecorder(
    append: { _, _ in appendAttempts.increment() },
    state: { _ in .healthy },
    poison: { _ in poisonAttempts.increment() },
    clock: clock,
    timeoutNanoseconds: 100
  )
  #expect(throws: OracleRecorderError.lockTimedOut) {
    try recorder.record(fixture.oracleEvent(kind: .fetchContents))
  }
  #expect(appendAttempts.value == 0)
  #expect(poisonAttempts.value == 0)
}

@Test
func oracleRecorderPassesTheSameDeadlineToStateAppendAndPoison() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let deadlines = LockedDeadlines()
  let recorder = OracleRecorder(
    append: { _, deadline in
      deadlines.append(deadline)
      throw POSIXError(.EIO)
    },
    state: { deadline in
      deadlines.append(deadline)
      return .healthy
    },
    poison: { deadline in deadlines.append(deadline) },
    clock: DeterministicOracleClock(),
    timeoutNanoseconds: 100
  )
  #expect(throws: POSIXError.self) {
    try recorder.record(fixture.oracleEvent(kind: .fetchContents))
  }
  #expect(deadlines.values == [100, 100, 100])
}

@Test
func oracleRecorderLocalLockContentionIsDeadlineBoundedAndDurablyPoisons() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  let clock = DeterministicOracleClock()
  let entered = DispatchSemaphore(value: 0)
  let release = DispatchSemaphore(value: 0)
  let finished = DispatchSemaphore(value: 0)
  let firstResult = LockedRecorderResult()
  let recorder = OracleRecorder(
    append: { _, _ in
      entered.signal()
      release.wait()
    },
    failure: { try log.failRecorder() },
    clock: clock,
    timeoutNanoseconds: 100_000_000
  )
  DispatchQueue.global().async {
    do {
      try recorder.record(fixture.oracleEvent(kind: .itemMetadata))
    } catch {
      firstResult.store(error)
    }
    finished.signal()
  }
  #expect(entered.wait(timeout: .now() + 2) == .success)
  #expect(throws: OracleRecorderError.lockTimedOut) {
    try recorder.record(fixture.oracleEvent(kind: .fetchContents))
  }
  release.signal()
  #expect(finished.wait(timeout: .now() + 2) == .success)
  #expect(firstResult.recorderError == .lockTimedOut)
  #expect(clock.nanoseconds == 100_000_000)
  #expect(try log.recorderState() == .poisoned)
  #expect(
    try SecureFixtureStorage.readControlFile(
      at: fixture.runDirectory.appendingPathComponent("recorder-failed"),
      record: .events
    ) == Data("diskplan-recorder-state-v1\n".utf8)
  )
}

@Test
func oracleRecorderStateReadFailureDurablyPoisonsBeforeReturning() throws {
  let fixture = try TemporaryFixtureRun()
  defer { fixture.remove() }
  let log = OracleLog(runDirectory: fixture.runDirectory)
  try log.prepare()
  let recorder = OracleRecorder(
    append: { _, _ in Issue.record("append unexpectedly ran after state-read failure") },
    state: { _ in throw POSIXError(.EIO) },
    failure: { try log.failRecorder() }
  )
  #expect(throws: POSIXError.self) {
    try recorder.record(fixture.oracleEvent(kind: .materializedItemsDidChange))
  }
  #expect(try log.recorderState() == .poisoned)
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
func callbackGateAtomicallyChecksItsOwnedDeadline() {
  let future = ContinuousClock.now + .seconds(10)
  let lateCallback = OneShotCallbackGate(deadline: future)
  #expect(lateCallback.claimCallback() == .callback)
  #expect(!lateCallback.claimDeadline())
  #expect(lateCallback.completionSource == .callback)

  let neverCallback = OneShotCallbackGate(deadline: future)
  #expect(neverCallback.claimDeadline())
  #expect(neverCallback.claimCallback() == nil)
  #expect(neverCallback.completionSource == .deadline)

  let delayedTimeoutTask = OneShotCallbackGate(deadline: ContinuousClock.now - .seconds(1))
  #expect(delayedTimeoutTask.claimCallback() == .deadline)
  #expect(!delayedTimeoutTask.claimDeadline())
  #expect(delayedTimeoutTask.completionSource == .deadline)
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

private final class DeterministicOracleClock: OracleQuiescenceClock, @unchecked Sendable {
  var nanoseconds: UInt64 = 0
  var onAdvance: ((UInt64) -> Void)?

  func nowNanoseconds() -> UInt64 { nanoseconds }

  func sleepForPoll() {
    nanoseconds += 50_000_000
    onAdvance?(nanoseconds)
  }
}

private final class AdvancingOracleClock: OracleQuiescenceClock, @unchecked Sendable {
  private var value: UInt64 = 0

  func nowNanoseconds() -> UInt64 { value }

  func sleepForPoll() {}

  func didReadFingerprint() { value += 1_000_000_000 }
}

private final class SteppingOracleClock: OracleQuiescenceClock, @unchecked Sendable {
  private let lock = NSLock()
  private let stepNanoseconds: UInt64
  private var value: UInt64 = 0

  init(stepNanoseconds: UInt64) { self.stepNanoseconds = stepNanoseconds }

  func nowNanoseconds() -> UInt64 {
    lock.withLock {
      defer { value += stepNanoseconds }
      return value
    }
  }

  func sleepForPoll() {}
}

private final class LockedRecorderResult: @unchecked Sendable {
  private let lock = NSLock()
  private var error: Error?

  var recorderError: OracleRecorderError? {
    lock.withLock { error as? OracleRecorderError }
  }

  var errorIsPOSIX: Bool {
    lock.withLock { error is POSIXError }
  }

  func store(_ error: Error) {
    lock.withLock { self.error = error }
  }
}

private final class LockedDeadlines: @unchecked Sendable {
  private let lock = NSLock()
  private var storage: [UInt64] = []

  var values: [UInt64] { lock.withLock { storage } }

  func append(_ deadline: UInt64) {
    lock.withLock { storage.append(deadline) }
  }
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
