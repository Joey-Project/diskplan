import Darwin
import Foundation
import Testing

@testable import DiskplanFileProviderFixtureSupport

@Test
func initialManifestPublishIsAtomicAndDurableBeforeReturning() throws {
  let fixture = try StorageFixture()
  defer { fixture.remove() }

  try SecureFixtureStorage.publishInitialManifest(
    fixture.manifestData,
    in: fixture.runDirectory
  )

  let manifestURL = fixture.runDirectory.appendingPathComponent("manifest.json")
  #expect(
    try SecureFixtureStorage.readManifest(
      at: manifestURL,
      expectedRunDirectory: fixture.runDirectory
    ).runID == fixture.runID
  )
  #expect(try fixture.entryNames().filter { $0.hasPrefix(".manifest.json.publish-") }.isEmpty)
}

@Test
func initialManifestFileSyncFailureCannotPublishCanonicalManifest() throws {
  let fixture = try StorageFixture()
  defer { fixture.remove() }

  #expect(
    throws: FixtureManifestPublishError.operationFailed("sync-manifest-staging", errno: EIO)
  ) {
    try SecureFixtureStorage.publishInitialManifest(
      fixture.manifestData,
      in: fixture.runDirectory,
      injecting: .failFileSync
    )
  }
  #expect(!FileManager.default.fileExists(atPath: fixture.manifestURL.path))
  #expect(try fixture.entryNames().isEmpty)
}

@Test
func initialManifestCrashAfterFileSyncLeavesOnlyUnpublishedStagingEvidence() throws {
  let fixture = try StorageFixture()
  defer { fixture.remove() }

  #expect(throws: InitialManifestPublishInjectedCrash.afterFileSync) {
    try SecureFixtureStorage.publishInitialManifest(
      fixture.manifestData,
      in: fixture.runDirectory,
      injecting: .crashAfterFileSync
    )
  }
  #expect(!FileManager.default.fileExists(atPath: fixture.manifestURL.path))
  #expect(try fixture.entryNames().count == 1)
  #expect(try fixture.entryNames().first?.hasPrefix(".manifest.json.publish-") == true)
}

@Test(arguments: [
  InitialManifestPublishInjection.failDirectorySync,
  .crashAfterRename,
])
func initialManifestNeverReportsSuccessBeforeDirectorySync(
  injection: InitialManifestPublishInjection
) throws {
  let fixture = try StorageFixture()
  defer { fixture.remove() }

  #expect(throws: Error.self) {
    try SecureFixtureStorage.publishInitialManifest(
      fixture.manifestData,
      in: fixture.runDirectory,
      injecting: injection
    )
  }
  #expect(FileManager.default.fileExists(atPath: fixture.manifestURL.path))
  #expect(try fixture.entryNames() == ["manifest.json"])
}

@Test(arguments: [
  ExistingRecoveryInjection.fileSyncFailure,
  .parentSyncFailure,
])
func existingRecoveryCopyMustBeFreshlySyncedBeforeCleanupCanStage(
  injection: ExistingRecoveryInjection
) throws {
  let fixture = try StorageFixture()
  defer { fixture.remove() }
  try fixture.writePrivate(fixture.manifestData, to: fixture.manifestURL)
  let recoveryURL = SecureFixtureStorage.cleanupRecoveryManifestURL(for: fixture.runDirectory)
  try fixture.writePrivate(fixture.manifestData, to: recoveryURL)
  let expectedError: FixtureCleanupError =
    if injection == .fileSyncFailure {
      .operationFailed("sync-existing-manifest-recovery-copy", errno: EIO)
    } else {
      .operationFailed("sync-manifest-recovery-parent", errno: EIO)
    }

  #expect(throws: expectedError) {
    try SecureFixtureStorage.cleanupRun(
      manifestURL: fixture.manifestURL,
      expectedRunDirectory: fixture.runDirectory,
      injectFinalDirectoryRemovalFailure: false,
      injectExistingRecoveryFileSyncFailure: injection == .fileSyncFailure,
      injectExistingRecoveryParentSyncFailure: injection == .parentSyncFailure
    )
  }
  #expect(FileManager.default.fileExists(atPath: fixture.runDirectory.path))
  #expect(FileManager.default.fileExists(atPath: recoveryURL.path))

  try SecureFixtureStorage.cleanupRun(
    manifestURL: fixture.manifestURL,
    expectedRunDirectory: fixture.runDirectory
  )
  #expect(!FileManager.default.fileExists(atPath: fixture.runDirectory.path))
  #expect(!FileManager.default.fileExists(atPath: recoveryURL.path))
}

@Test
func cleanupCrashAfterDurableStagingRenameOccursBeforeAnyDeletion() throws {
  let fixture = try StorageFixture()
  defer { fixture.remove() }
  try fixture.writePrivate(fixture.manifestData, to: fixture.manifestURL)
  let payload = fixture.runDirectory.appendingPathComponent("payload")
  try fixture.writePrivate(Data("preserved".utf8), to: payload)
  let recoveryURL = SecureFixtureStorage.cleanupRecoveryManifestURL(for: fixture.runDirectory)
  let stagingURL = SecureFixtureStorage.cleanupStagingDirectoryURL(for: fixture.runDirectory)

  #expect(throws: Error.self) {
    try SecureFixtureStorage.cleanupRun(
      manifestURL: fixture.manifestURL,
      expectedRunDirectory: fixture.runDirectory,
      injectFinalDirectoryRemovalFailure: false,
      injectCrashAfterStagingDirectoryParentSync: true
    )
  }
  #expect(!FileManager.default.fileExists(atPath: fixture.runDirectory.path))
  #expect(FileManager.default.fileExists(atPath: recoveryURL.path))
  #expect(
    try String(contentsOf: stagingURL.appendingPathComponent("payload"), encoding: .utf8)
      == "preserved"
  )

  try SecureFixtureStorage.recoverCleanup(
    recoveryManifestURL: recoveryURL,
    expectedRunDirectory: fixture.runDirectory
  )
  #expect(!FileManager.default.fileExists(atPath: stagingURL.path))
  #expect(!FileManager.default.fileExists(atPath: recoveryURL.path))
}

@Test(arguments: [
  RestoredManifestInjection.fileSyncFailure,
  .directorySyncFailure,
  .crashAfterFileSync,
  .canonicalRenameParentSyncFailure,
])
func manifestRestoreCannotRenameBackOrDeleteRecoveryBeforeDurability(
  injection: RestoredManifestInjection
) throws {
  let fixture = try StorageFixture()
  defer { fixture.remove() }
  try fixture.writePrivate(fixture.manifestData, to: fixture.manifestURL)
  let recoveryURL = SecureFixtureStorage.cleanupRecoveryManifestURL(for: fixture.runDirectory)
  let stagingURL = SecureFixtureStorage.cleanupStagingDirectoryURL(for: fixture.runDirectory)

  #expect(throws: Error.self) {
    try SecureFixtureStorage.cleanupRun(
      manifestURL: fixture.manifestURL,
      expectedRunDirectory: fixture.runDirectory,
      injectFinalDirectoryRemovalFailure: true,
      injectRestoredManifestFileSyncFailure: injection == .fileSyncFailure,
      injectRestoredManifestDirectorySyncFailure: injection == .directorySyncFailure,
      injectCrashAfterRestoredManifestFileSync: injection == .crashAfterFileSync,
      injectRestoredCanonicalRenameParentSyncFailure:
        injection == .canonicalRenameParentSyncFailure
    )
  }
  #expect(FileManager.default.fileExists(atPath: recoveryURL.path))
  if injection == .canonicalRenameParentSyncFailure {
    #expect(FileManager.default.fileExists(atPath: fixture.runDirectory.path))
    #expect(!FileManager.default.fileExists(atPath: stagingURL.path))
    try SecureFixtureStorage.cleanupRun(
      manifestURL: fixture.manifestURL,
      expectedRunDirectory: fixture.runDirectory
    )
  } else {
    #expect(!FileManager.default.fileExists(atPath: fixture.runDirectory.path))
    #expect(FileManager.default.fileExists(atPath: stagingURL.path))
    try SecureFixtureStorage.recoverCleanup(
      recoveryManifestURL: recoveryURL,
      expectedRunDirectory: fixture.runDirectory
    )
  }
  #expect(!FileManager.default.fileExists(atPath: stagingURL.path))
  #expect(!FileManager.default.fileExists(atPath: recoveryURL.path))
}

@Test
func controlReadsRejectExtendedACLGrantsOnDirectoriesAndLeaves() throws {
  let fixture = try StorageFixture()
  defer { fixture.remove() }
  try fixture.writePrivate(fixture.manifestData, to: fixture.manifestURL)

  try addReadGrant(to: fixture.manifestURL)
  #expect(throws: FixtureControlReadError.mismatch(.manifest, .accessPolicy)) {
    try SecureFixtureStorage.readManifest(
      at: fixture.manifestURL,
      expectedRunDirectory: fixture.runDirectory
    )
  }
  try removeExtendedACL(from: fixture.manifestURL)

  try addReadGrant(to: fixture.runDirectory)
  #expect(throws: FixtureControlReadError.mismatch(.manifest, .accessPolicy)) {
    try SecureFixtureStorage.readManifest(
      at: fixture.manifestURL,
      expectedRunDirectory: fixture.runDirectory
    )
  }
}

@Test
func cleanupRejectsExtendedACLGrantsInTreeAndRecoveryEvidence() throws {
  let fixture = try StorageFixture()
  defer { fixture.remove() }
  try fixture.writePrivate(fixture.manifestData, to: fixture.manifestURL)
  let protectedLeaf = fixture.runDirectory.appendingPathComponent("protected")
  try fixture.writePrivate(Data("value".utf8), to: protectedLeaf)
  try addReadGrant(to: protectedLeaf)

  #expect(throws: FixtureCleanupError.treeMismatch("protected")) {
    try SecureFixtureStorage.cleanupRun(
      manifestURL: fixture.manifestURL,
      expectedRunDirectory: fixture.runDirectory
    )
  }
  #expect(FileManager.default.fileExists(atPath: fixture.runDirectory.path))

  try removeExtendedACL(from: protectedLeaf)
  let recoveryURL = SecureFixtureStorage.cleanupRecoveryManifestURL(for: fixture.runDirectory)
  try fixture.writePrivate(fixture.manifestData, to: recoveryURL)
  try addReadGrant(to: recoveryURL)
  #expect(throws: FixtureControlReadError.mismatch(.manifest, .accessPolicy)) {
    try SecureFixtureStorage.cleanupRun(
      manifestURL: fixture.manifestURL,
      expectedRunDirectory: fixture.runDirectory
    )
  }
  #expect(FileManager.default.fileExists(atPath: fixture.runDirectory.path))
  #expect(FileManager.default.fileExists(atPath: recoveryURL.path))
}

enum RestoredManifestInjection: CaseIterable, Equatable, Sendable {
  case fileSyncFailure
  case directorySyncFailure
  case crashAfterFileSync
  case canonicalRenameParentSyncFailure
}

enum ExistingRecoveryInjection: CaseIterable, Equatable, Sendable {
  case fileSyncFailure
  case parentSyncFailure
}

private struct StorageFixture {
  let container: URL
  let runID: UUID
  let runDirectory: URL
  let manifestData: Data

  var manifestURL: URL { runDirectory.appendingPathComponent("manifest.json") }

  init() throws {
    container = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    runID = UUID()
    let runs = container.appendingPathComponent("runs")
    runDirectory = runs.appendingPathComponent(runID.uuidString.lowercased())
    try FileManager.default.createDirectory(at: runDirectory, withIntermediateDirectories: true)
    guard chmod(container.path, 0o700) == 0, chmod(runs.path, 0o700) == 0,
      chmod(runDirectory.path, 0o700) == 0
    else { throw POSIXError(.EIO) }
    manifestData = try JSONEncoder().encode(
      FixtureManifest(
        runID: runID,
        taskRoot: runDirectory.path,
        appPath: "/private/tmp/fixture.app",
        extensionPath: "/private/tmp/fixture.app/Contents/PlugIns/fixture.appex",
        appGroupRunPath: runDirectory.path
      )
    )
  }

  func writePrivate(_ data: Data, to url: URL) throws {
    try data.write(to: url, options: .withoutOverwriting)
    guard chmod(url.path, 0o600) == 0 else { throw POSIXError(.EIO) }
  }

  func entryNames() throws -> [String] {
    try FileManager.default.contentsOfDirectory(atPath: runDirectory.path).sorted()
  }

  func remove() {
    try? removeExtendedACL(from: manifestURL)
    try? removeExtendedACL(from: runDirectory)
    try? FileManager.default.removeItem(at: container)
  }
}

private func addReadGrant(to url: URL) throws {
  try runChmod(arguments: ["+a", "everyone allow read", url.path])
}

private func removeExtendedACL(from url: URL) throws {
  guard FileManager.default.fileExists(atPath: url.path) else { return }
  try runChmod(arguments: ["-N", url.path])
}

private func runChmod(arguments: [String]) throws {
  let process = Process()
  process.executableURL = URL(fileURLWithPath: "/bin/chmod")
  process.arguments = arguments
  try process.run()
  process.waitUntilExit()
  guard process.terminationReason == .exit, process.terminationStatus == 0 else {
    throw POSIXError(.EACCES)
  }
}
