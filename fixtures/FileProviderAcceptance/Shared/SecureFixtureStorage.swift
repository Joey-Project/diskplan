import Darwin
import Foundation

public enum FixtureManifestPublishError: Error, Equatable, Sendable {
  case unsafeTarget
  case operationFailed(String, errno: Int32)
  case verificationFailed
}

enum InitialManifestPublishInjection: Equatable, Sendable {
  case none
  case failFileSync
  case crashAfterFileSync
  case failDirectorySync
  case crashAfterRename
}

enum InitialManifestPublishInjectedCrash: Error, Equatable, Sendable {
  case afterFileSync
  case afterRename
}

public enum SecureFixtureStorage {
  public static let maximumControlBytes = 64 * 1_024
  fileprivate static let maximumCleanupEntries = 128
  fileprivate static let maximumCleanupDepth = 8

  /// Durably publishes the canonical manifest before any external registration or domain mutation.
  public static func publishInitialManifest(
    _ data: Data,
    in runDirectory: URL
  ) throws {
    try publishInitialManifest(data, in: runDirectory, injecting: .none)
  }

  static func publishInitialManifest(
    _ data: Data,
    in runDirectory: URL,
    injecting injection: InitialManifestPublishInjection
  ) throws {
    guard data.count <= maximumControlBytes, runDirectory.isFileURL else {
      throw FixtureManifestPublishError.unsafeTarget
    }
    do {
      let manifest = try JSONDecoder().decode(FixtureManifest.self, from: data)
      try manifest.validate(expectedTaskRoot: runDirectory)
      guard
        URL(fileURLWithPath: manifest.appGroupRunPath).standardizedFileURL
          == runDirectory.standardizedFileURL
      else { throw FixtureContractError.unsafePath }
    } catch {
      throw FixtureManifestPublishError.verificationFailed
    }
    let directory: BoundDescriptor
    do {
      directory = try openDirectory(at: runDirectory, cleanupPath: runDirectory.path)
      try requireDirectoryPathIdentity(
        runDirectory,
        descriptor: directory,
        cleanupPath: runDirectory.path
      )
    } catch let error as FixtureCleanupError {
      throw FixtureManifestPublishError.operationFailed(
        "open-run-directory",
        errno: error.errnoValue
      )
    }

    let temporaryName = ".manifest.json.publish-\(UUID().uuidString.lowercased())"
    let descriptor = openat(
      directory.rawValue,
      temporaryName,
      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
      0o600
    )
    guard descriptor >= 0 else {
      throw FixtureManifestPublishError.operationFailed("create-manifest-staging", errno: errno)
    }
    var shouldRemoveTemporary = true
    defer {
      close(descriptor)
      if shouldRemoveTemporary {
        _ = unlinkat(directory.rawValue, temporaryName, 0)
      }
    }
    do {
      let state = try metadata(descriptor: descriptor)
      guard isOwnerPrivateRegularFile(state) else {
        throw FixtureManifestPublishError.verificationFailed
      }
      try writeAll(data, descriptor: descriptor)
      if injection == .failFileSync {
        throw FixtureManifestPublishError.operationFailed("sync-manifest-staging", errno: EIO)
      }
      guard fsync(descriptor) == 0 else {
        throw FixtureManifestPublishError.operationFailed("sync-manifest-staging", errno: errno)
      }
      if injection == .crashAfterFileSync {
        shouldRemoveTemporary = false
        throw InitialManifestPublishInjectedCrash.afterFileSync
      }
      let result = renameatx_np(
        directory.rawValue,
        temporaryName,
        directory.rawValue,
        "manifest.json",
        UInt32(RENAME_EXCL)
      )
      guard result == 0 else {
        throw FixtureManifestPublishError.operationFailed("publish-manifest", errno: errno)
      }
      shouldRemoveTemporary = false
      if injection == .crashAfterRename {
        throw InitialManifestPublishInjectedCrash.afterRename
      }
      if injection == .failDirectorySync {
        throw FixtureManifestPublishError.operationFailed("sync-manifest-parent", errno: EIO)
      }
      guard fsync(directory.rawValue) == 0 else {
        throw FixtureManifestPublishError.operationFailed("sync-manifest-parent", errno: errno)
      }
      let published = try readBoundControlFile(
        directory: directory,
        name: "manifest.json",
        record: .manifest
      )
      guard published == data else { throw FixtureManifestPublishError.verificationFailed }
      try requireDirectoryPathIdentity(
        runDirectory,
        descriptor: directory,
        cleanupPath: runDirectory.path
      )
    } catch let error as FixtureManifestPublishError {
      throw error
    } catch let error as InitialManifestPublishInjectedCrash {
      throw error
    } catch let error as POSIXError {
      throw FixtureManifestPublishError.operationFailed(
        "write-manifest-staging",
        errno: error.code.rawValue
      )
    } catch {
      throw FixtureManifestPublishError.verificationFailed
    }
  }

  public static func readManifest(
    at manifestURL: URL,
    expectedRunDirectory: URL
  ) throws -> FixtureManifest {
    let expectedURL = expectedRunDirectory.appendingPathComponent("manifest.json")
    guard manifestURL.standardizedFileURL == expectedURL.standardizedFileURL else {
      throw FixtureControlReadError.mismatch(.manifest, .semantic)
    }
    let data = try readControlFile(at: manifestURL, record: .manifest)
    let manifest: FixtureManifest
    do {
      manifest = try JSONDecoder().decode(FixtureManifest.self, from: data)
    } catch {
      throw FixtureControlReadError.mismatch(.manifest, .malformed)
    }
    do {
      try manifest.validate(expectedTaskRoot: expectedRunDirectory)
      guard
        URL(fileURLWithPath: manifest.appGroupRunPath).standardizedFileURL
          == expectedRunDirectory.standardizedFileURL
      else { throw FixtureContractError.unsafePath }
    } catch {
      throw FixtureControlReadError.mismatch(.manifest, .semantic)
    }
    return manifest
  }

  public static func readReady(_ manifest: FixtureManifest) throws -> FixtureReadyState {
    let url = URL(fileURLWithPath: manifest.taskRoot).appendingPathComponent("ready.json")
    let data = try readControlFile(at: url, record: .ready)
    let ready: FixtureReadyState
    do {
      ready = try JSONDecoder().decode(FixtureReadyState.self, from: data)
    } catch {
      throw FixtureControlReadError.mismatch(.ready, .malformed)
    }
    do {
      try ready.validate(manifest: manifest)
    } catch {
      throw FixtureControlReadError.mismatch(.ready, .semantic)
    }
    return ready
  }

  public static func readWindow(runDirectory: URL) throws -> OracleWindow {
    let data = try readControlFile(
      at: runDirectory.appendingPathComponent("window.json"),
      record: .window
    )
    let window: OracleWindow
    do {
      window = try JSONDecoder().decode(OracleWindow.self, from: data)
    } catch {
      throw FixtureControlReadError.mismatch(.window, .malformed)
    }
    do {
      try window.validate()
    } catch {
      throw FixtureControlReadError.mismatch(.window, .semantic)
    }
    return window
  }

  public static func cleanupRun(
    manifestURL: URL,
    expectedRunDirectory: URL
  ) throws {
    try cleanupRun(
      manifestURL: manifestURL,
      expectedRunDirectory: expectedRunDirectory,
      injectFinalDirectoryRemovalFailure: false,
      injectCrashBeforeFinalDirectoryRemoval: false,
      injectCrashAfterFinalDirectoryRemoval: false
    )
  }

  static func cleanupRun(
    manifestURL: URL,
    expectedRunDirectory: URL,
    injectFinalDirectoryRemovalFailure: Bool,
    injectCrashBeforeFinalDirectoryRemoval: Bool = false,
    injectCrashAfterFinalDirectoryRemoval: Bool = false,
    injectExistingRecoveryFileSyncFailure: Bool = false,
    injectExistingRecoveryParentSyncFailure: Bool = false,
    injectCrashAfterStagingDirectoryParentSync: Bool = false,
    injectRestoredManifestFileSyncFailure: Bool = false,
    injectRestoredManifestDirectorySyncFailure: Bool = false,
    injectCrashAfterRestoredManifestFileSync: Bool = false,
    injectRestoredCanonicalRenameParentSyncFailure: Bool = false
  ) throws {
    let expectedManifest = expectedRunDirectory.appendingPathComponent("manifest.json")
    guard manifestURL.standardizedFileURL == expectedManifest.standardizedFileURL else {
      throw FixtureCleanupError.unsafeTarget
    }
    let parentURL = expectedRunDirectory.deletingLastPathComponent()
    let runName = expectedRunDirectory.lastPathComponent
    let parent = try openDirectory(at: parentURL, cleanupPath: parentURL.path)
    try requireDirectoryPathIdentity(parentURL, descriptor: parent, cleanupPath: parentURL.path)
    let root = try openChildDirectory(
      parent: parent,
      name: runName,
      depth: 0,
      expectedDevice: parent.metadata.device
    )
    let manifestData = try readBoundControlFile(
      directory: root,
      name: "manifest.json",
      record: .manifest
    )
    let manifest: FixtureManifest
    do {
      manifest = try JSONDecoder().decode(FixtureManifest.self, from: manifestData)
      try manifest.validate(expectedTaskRoot: expectedRunDirectory)
      guard
        URL(fileURLWithPath: manifest.appGroupRunPath).standardizedFileURL
          == expectedRunDirectory.standardizedFileURL
      else { throw FixtureContractError.unsafePath }
    } catch {
      throw FixtureCleanupError.treeMismatch("manifest")
    }

    let stagingName = ".cleanup-\(runName)"
    let recoveryName = ".manifest-recovery-\(runName).json"
    let recoveryURL = parentURL.appendingPathComponent(recoveryName)
    try createExternalManifestRecovery(
      manifestData,
      parent: parent,
      name: recoveryName,
      injectExistingFileSyncFailure: injectExistingRecoveryFileSyncFailure,
      injectExistingParentSyncFailure: injectExistingRecoveryParentSyncFailure
    )
    try requireDirectoryPathIdentity(parentURL, descriptor: parent, cleanupPath: parentURL.path)
    do {
      try renameExclusive(
        parent: parent,
        source: runName,
        destination: stagingName,
        operation: "stage-run-directory"
      )
    } catch {
      let operationError = error
      do {
        try removeExternalManifestRecovery(
          manifestData,
          parent: parent,
          name: recoveryName
        )
      } catch {
        throw FixtureCleanupError.retained(recoveryURL.path)
      }
      throw operationError
    }
    do {
      try requirePathIdentity(parent: parent, name: stagingName, expected: root.metadata)
      try requireDirectoryPathIdentity(parentURL, descriptor: parent, cleanupPath: parentURL.path)
      guard fsync(parent.rawValue) == 0 else {
        throw FixtureCleanupError.operationFailed("sync-staged-run-directory-parent", errno: errno)
      }
      if injectCrashAfterStagingDirectoryParentSync {
        throw FixtureCleanupInjectedCrash.afterStagingDirectoryParentSync
      }
      var remainingEntries = maximumCleanupEntries
      let tree = try inventory(
        directory: root,
        rootDevice: root.metadata.device,
        depth: 0,
        isRoot: true,
        remainingEntries: &remainingEntries
      )
      try delete(entries: tree, from: root)
      if injectCrashBeforeFinalDirectoryRemoval {
        throw FixtureCleanupInjectedCrash.beforeFinalDirectoryRemoval
      }
      if injectFinalDirectoryRemovalFailure {
        throw FixtureCleanupError.operationFailed("injected-final-directory-removal", errno: EBUSY)
      }
      try unlink(parent: parent, name: stagingName, flags: AT_REMOVEDIR)
      guard fsync(parent.rawValue) == 0 else {
        throw FixtureCleanupError.operationFailed("sync-staging-removal-parent", errno: errno)
      }
      if injectCrashAfterFinalDirectoryRemoval {
        throw FixtureCleanupInjectedCrash.afterFinalDirectoryRemovalParentSync
      }
    } catch {
      if error is FixtureCleanupInjectedCrash { throw error }
      let operationError = error
      do {
        try restoreManifest(
          manifestData,
          in: root,
          injectFileSyncFailure: injectRestoredManifestFileSyncFailure,
          injectDirectorySyncFailure: injectRestoredManifestDirectorySyncFailure,
          injectCrashAfterFileSync: injectCrashAfterRestoredManifestFileSync
        )
        try renameExclusive(
          parent: parent,
          source: stagingName,
          destination: runName,
          operation: "restore-run-directory"
        )
        if injectRestoredCanonicalRenameParentSyncFailure {
          throw FixtureCleanupError.operationFailed(
            "sync-restored-run-directory-parent",
            errno: EIO
          )
        }
        guard fsync(parent.rawValue) == 0 else {
          throw FixtureCleanupError.operationFailed(
            "sync-restored-run-directory-parent",
            errno: errno
          )
        }
        _ = try readBoundControlFile(directory: root, name: "manifest.json", record: .manifest)
        try removeExternalManifestRecovery(
          manifestData,
          parent: parent,
          name: recoveryName
        )
      } catch {
        throw FixtureCleanupError.retained(recoveryURL.path)
      }
      throw operationError
    }
    do {
      try removeExternalManifestRecovery(
        manifestData,
        parent: parent,
        name: recoveryName
      )
    } catch {
      throw FixtureCleanupError.retained(recoveryURL.path)
    }
  }

  public static func cleanupRecoveryManifestURL(for expectedRunDirectory: URL) -> URL {
    expectedRunDirectory.deletingLastPathComponent().appendingPathComponent(
      ".manifest-recovery-\(expectedRunDirectory.lastPathComponent).json"
    )
  }

  public static func cleanupStagingDirectoryURL(for expectedRunDirectory: URL) -> URL {
    expectedRunDirectory.deletingLastPathComponent().appendingPathComponent(
      ".cleanup-\(expectedRunDirectory.lastPathComponent)",
      isDirectory: true
    )
  }

  public static func readCleanupRecoveryManifest(
    at recoveryURL: URL,
    expectedRunDirectory: URL
  ) throws -> FixtureManifest {
    let expectedURL = cleanupRecoveryManifestURL(for: expectedRunDirectory)
    guard recoveryURL.isFileURL, recoveryURL.path == expectedURL.path else {
      throw FixtureControlReadError.mismatch(.manifest, .semantic)
    }
    let parentURL = expectedRunDirectory.deletingLastPathComponent()
    let parent = try openControlDirectory(at: parentURL, record: .manifest)
    try requireControlDirectoryPathIdentity(parentURL, descriptor: parent, record: .manifest)
    let data = try readBoundControlFile(
      directory: parent,
      name: expectedURL.lastPathComponent,
      record: .manifest
    )
    try requireControlDirectoryPathIdentity(parentURL, descriptor: parent, record: .manifest)
    let manifest: FixtureManifest
    do {
      manifest = try JSONDecoder().decode(FixtureManifest.self, from: data)
      try manifest.validate(expectedTaskRoot: expectedRunDirectory)
      guard
        URL(fileURLWithPath: manifest.appGroupRunPath).standardizedFileURL
          == expectedRunDirectory.standardizedFileURL
      else { throw FixtureContractError.unsafePath }
    } catch {
      throw FixtureControlReadError.mismatch(.manifest, .semantic)
    }
    return manifest
  }

  public static func recoverCleanup(
    recoveryManifestURL: URL,
    expectedRunDirectory: URL
  ) throws {
    let recoveryURL = cleanupRecoveryManifestURL(for: expectedRunDirectory)
    guard recoveryManifestURL.isFileURL, recoveryManifestURL.path == recoveryURL.path else {
      throw FixtureCleanupError.unsafeTarget
    }
    let parentURL = expectedRunDirectory.deletingLastPathComponent()
    let runName = expectedRunDirectory.lastPathComponent
    let stagingName = cleanupStagingDirectoryURL(for: expectedRunDirectory).lastPathComponent
    let recoveryName = recoveryURL.lastPathComponent
    let parent = try openDirectory(at: parentURL, cleanupPath: parentURL.path)
    try requireDirectoryPathIdentity(parentURL, descriptor: parent, cleanupPath: parentURL.path)

    let manifestData = try readBoundControlFile(
      directory: parent,
      name: recoveryName,
      record: .manifest
    )
    let manifest: FixtureManifest
    do {
      manifest = try JSONDecoder().decode(FixtureManifest.self, from: manifestData)
      try manifest.validate(expectedTaskRoot: expectedRunDirectory)
      guard
        URL(fileURLWithPath: manifest.appGroupRunPath).standardizedFileURL
          == expectedRunDirectory.standardizedFileURL
      else { throw FixtureContractError.unsafePath }
    } catch {
      throw FixtureCleanupError.treeMismatch("external-manifest-recovery-content")
    }

    do {
      try requireMissingPath(parent: parent, name: runName, operation: "canonical-run-directory")
      let staging = try openOptionalChildDirectory(
        parent: parent,
        name: stagingName,
        expectedDevice: parent.metadata.device
      )
      if let staging {
        var remainingEntries = maximumCleanupEntries
        let tree = try inventory(
          directory: staging,
          rootDevice: staging.metadata.device,
          depth: 0,
          isRoot: false,
          remainingEntries: &remainingEntries
        )
        try delete(entries: tree, from: staging)
        try requireStableObject(parent: parent, name: stagingName, descriptor: staging)
        try unlink(parent: parent, name: stagingName, flags: AT_REMOVEDIR)
      }
      guard fsync(parent.rawValue) == 0 else {
        throw FixtureCleanupError.retained(recoveryURL.path)
      }
      try requireDirectoryPathIdentity(parentURL, descriptor: parent, cleanupPath: parentURL.path)
      try removeExternalManifestRecovery(
        manifestData,
        parent: parent,
        name: recoveryName
      )
    } catch let error as FixtureCleanupError {
      if case .retained = error { throw error }
      throw FixtureCleanupError.retained(recoveryURL.path)
    } catch {
      throw FixtureCleanupError.retained(recoveryURL.path)
    }
  }

  public static func readControlFile(
    at url: URL,
    record: FixtureControlRecord,
    maximumBytes: Int = maximumControlBytes
  ) throws -> Data {
    let directoryURL = url.deletingLastPathComponent()
    let directory = try openControlDirectory(at: directoryURL, record: record)
    try requireControlDirectoryPathIdentity(directoryURL, descriptor: directory, record: record)
    let data = try readBoundControlFile(
      directory: directory,
      name: url.lastPathComponent,
      record: record,
      maximumBytes: maximumBytes
    )
    try requireControlDirectoryPathIdentity(directoryURL, descriptor: directory, record: record)
    return data
  }
}

private final class BoundDescriptor: @unchecked Sendable {
  let rawValue: Int32
  let metadata: BoundMetadata

  init(rawValue: Int32, metadata: BoundMetadata) {
    self.rawValue = rawValue
    self.metadata = metadata
  }

  deinit { close(rawValue) }
}

private struct BoundMetadata: Equatable, Sendable {
  let device: dev_t
  let inode: ino_t
  let owner: uid_t
  let group: gid_t
  let mode: mode_t
  let size: off_t
  let modifiedSeconds: Int
  let modifiedNanoseconds: Int
  let changedSeconds: Int
  let changedNanoseconds: Int
  let extendedACL: ExtendedACLState

  init(_ value: stat, extendedACL: ExtendedACLState = .notInspected) {
    device = value.st_dev
    inode = value.st_ino
    owner = value.st_uid
    group = value.st_gid
    mode = value.st_mode
    size = value.st_size
    modifiedSeconds = value.st_mtimespec.tv_sec
    modifiedNanoseconds = value.st_mtimespec.tv_nsec
    changedSeconds = value.st_ctimespec.tv_sec
    changedNanoseconds = value.st_ctimespec.tv_nsec
    self.extendedACL = extendedACL
  }

  func sameIdentityAndAccess(as other: BoundMetadata) -> Bool {
    sameIdentityAndPOSIXAccess(as: other) && extendedACL == other.extendedACL
  }

  func sameIdentityAndPOSIXAccess(as other: BoundMetadata) -> Bool {
    device == other.device && inode == other.inode && owner == other.owner
      && group == other.group && mode == other.mode
  }

  func sameContentState(as other: BoundMetadata) -> Bool {
    size == other.size && modifiedSeconds == other.modifiedSeconds
      && modifiedNanoseconds == other.modifiedNanoseconds
      && changedSeconds == other.changedSeconds && changedNanoseconds == other.changedNanoseconds
  }
}

private enum ExtendedACLState: Equatable, Sendable {
  case notInspected
  case absent
  case present
}

private indirect enum CleanupEntry {
  case file(name: String, descriptor: BoundDescriptor, isManifest: Bool)
  case directory(name: String, descriptor: BoundDescriptor, children: [CleanupEntry])

  var name: String {
    switch self {
    case .file(let name, _, _), .directory(let name, _, _): name
    }
  }

  var isManifest: Bool {
    if case .file(_, _, let isManifest) = self { return isManifest }
    return false
  }
}

private func openControlDirectory(
  at url: URL,
  record: FixtureControlRecord
) throws -> BoundDescriptor {
  let descriptor = open(url.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
  guard descriptor >= 0 else { throw classifyOpenError(record: record, code: errno) }
  do {
    let metadata = try metadata(descriptor: descriptor)
    try validateOwnerPrivateDirectory(metadata, record: record)
    return BoundDescriptor(rawValue: descriptor, metadata: metadata)
  } catch {
    close(descriptor)
    throw error
  }
}

private func openDirectory(at url: URL, cleanupPath: String) throws -> BoundDescriptor {
  let descriptor = open(url.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK)
  guard descriptor >= 0 else {
    throw FixtureCleanupError.operationFailed(cleanupPath, errno: errno)
  }
  do {
    let metadata = try metadata(descriptor: descriptor)
    guard isOwnerPrivateDirectory(metadata) else {
      throw FixtureCleanupError.treeMismatch(cleanupPath)
    }
    return BoundDescriptor(rawValue: descriptor, metadata: metadata)
  } catch {
    close(descriptor)
    throw error
  }
}

private func openChildDirectory(
  parent: BoundDescriptor,
  name: String,
  depth: Int,
  expectedDevice: dev_t
) throws -> BoundDescriptor {
  guard depth <= SecureFixtureStorage.maximumCleanupDepth else {
    throw FixtureCleanupError.treeMismatch(name)
  }
  let descriptor = openat(
    parent.rawValue,
    name,
    O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
  )
  guard descriptor >= 0 else { throw FixtureCleanupError.operationFailed(name, errno: errno) }
  do {
    let metadata = try metadata(descriptor: descriptor)
    guard isOwnerPrivateDirectory(metadata) else {
      throw FixtureCleanupError.treeMismatch(name)
    }
    if !isSameCleanupDevice(expectedDevice, metadata.device) {
      throw FixtureCleanupError.treeMismatch("mount-boundary:\(name)")
    }
    try requirePathIdentity(parent: parent, name: name, expected: metadata)
    return BoundDescriptor(rawValue: descriptor, metadata: metadata)
  } catch {
    close(descriptor)
    throw error
  }
}

private func openOptionalChildDirectory(
  parent: BoundDescriptor,
  name: String,
  expectedDevice: dev_t
) throws -> BoundDescriptor? {
  var entry = stat()
  guard fstatat(parent.rawValue, name, &entry, AT_SYMLINK_NOFOLLOW) == 0 else {
    if errno == ENOENT { return nil }
    throw FixtureCleanupError.operationFailed(name, errno: errno)
  }
  return try openChildDirectory(
    parent: parent,
    name: name,
    depth: 0,
    expectedDevice: expectedDevice
  )
}

private func requireMissingPath(
  parent: BoundDescriptor,
  name: String,
  operation: String
) throws {
  var entry = stat()
  guard fstatat(parent.rawValue, name, &entry, AT_SYMLINK_NOFOLLOW) != 0 else {
    throw FixtureCleanupError.treeMismatch(operation)
  }
  guard errno == ENOENT else {
    throw FixtureCleanupError.operationFailed(operation, errno: errno)
  }
}

private func readBoundControlFile(
  directory: BoundDescriptor,
  name: String,
  record: FixtureControlRecord,
  maximumBytes: Int = SecureFixtureStorage.maximumControlBytes
) throws -> Data {
  let descriptor = openat(
    directory.rawValue,
    name,
    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
  )
  guard descriptor >= 0 else { throw classifyOpenError(record: record, code: errno) }
  defer { close(descriptor) }
  try acquireSharedLock(descriptor, record: record)
  defer { flock(descriptor, LOCK_UN) }
  let before = try controlMetadata(descriptor: descriptor, record: record)
  guard before.size >= 0, before.size <= maximumBytes else {
    throw FixtureControlReadError.mismatch(record, .sizeLimit)
  }
  let data: Data
  do {
    data = try readAll(descriptor: descriptor, count: Int(before.size))
  } catch let error as POSIXError {
    throw FixtureControlReadError.unreadable(record, errno: error.code.rawValue)
  }
  let after = try controlMetadata(descriptor: descriptor, record: record)
  guard before.sameIdentityAndAccess(as: after) else {
    throw FixtureControlReadError.mismatch(record, .identityChanged)
  }
  guard before.sameContentState(as: after) else {
    throw FixtureControlReadError.mismatch(record, .contentChanged)
  }
  var current = stat()
  guard fstatat(directory.rawValue, name, &current, AT_SYMLINK_NOFOLLOW) == 0 else {
    if errno == ENOENT { throw FixtureControlReadError.missing(record) }
    throw FixtureControlReadError.unreadable(record, errno: errno)
  }
  guard before.sameIdentityAndPOSIXAccess(as: BoundMetadata(current)) else {
    throw FixtureControlReadError.mismatch(record, .identityChanged)
  }
  return data
}

private func classifyOpenError(
  record: FixtureControlRecord,
  code: Int32
) -> FixtureControlReadError {
  switch code {
  case ENOENT:
    .missing(record)
  case ELOOP, ENOTDIR:
    .mismatch(record, .objectType)
  default:
    .unreadable(record, errno: code)
  }
}

private func controlMetadata(
  descriptor: Int32,
  record: FixtureControlRecord
) throws -> BoundMetadata {
  let value: BoundMetadata
  do {
    value = try metadata(descriptor: descriptor)
  } catch let error as POSIXError {
    throw FixtureControlReadError.unreadable(record, errno: error.code.rawValue)
  }
  guard value.mode & S_IFMT == S_IFREG else {
    throw FixtureControlReadError.mismatch(record, .objectType)
  }
  guard value.owner == geteuid() else {
    throw FixtureControlReadError.mismatch(record, .owner)
  }
  guard value.mode & 0o077 == 0 else {
    throw FixtureControlReadError.mismatch(record, .accessPolicy)
  }
  guard value.extendedACL == .absent else {
    throw FixtureControlReadError.mismatch(record, .accessPolicy)
  }
  return value
}

private func validateOwnerPrivateDirectory(
  _ metadata: BoundMetadata,
  record: FixtureControlRecord
) throws {
  guard metadata.mode & S_IFMT == S_IFDIR else {
    throw FixtureControlReadError.mismatch(record, .objectType)
  }
  guard metadata.owner == geteuid() else {
    throw FixtureControlReadError.mismatch(record, .owner)
  }
  guard metadata.mode & 0o077 == 0 else {
    throw FixtureControlReadError.mismatch(record, .accessPolicy)
  }
  guard metadata.extendedACL == .absent else {
    throw FixtureControlReadError.mismatch(record, .accessPolicy)
  }
}

private func isOwnerPrivateDirectory(_ metadata: BoundMetadata) -> Bool {
  metadata.mode & S_IFMT == S_IFDIR && metadata.owner == geteuid()
    && metadata.mode & 0o077 == 0 && metadata.extendedACL == .absent
}

private func isOwnerPrivateRegularFile(_ metadata: BoundMetadata) -> Bool {
  metadata.mode & S_IFMT == S_IFREG && metadata.owner == geteuid()
    && metadata.mode & 0o077 == 0 && metadata.extendedACL == .absent
}

private func metadata(descriptor: Int32) throws -> BoundMetadata {
  var value = stat()
  guard fstat(descriptor, &value) == 0 else { throw makePOSIXError(code: errno) }
  return BoundMetadata(value, extendedACL: try extendedACLState(descriptor: descriptor))
}

private func extendedACLState(descriptor: Int32) throws -> ExtendedACLState {
  errno = 0
  guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
    if errno == ENOENT { return .absent }
    throw makePOSIXError(code: errno == 0 ? EIO : errno)
  }
  acl_free(UnsafeMutableRawPointer(acl))
  return .present
}

private func inventory(
  directory: BoundDescriptor,
  rootDevice: dev_t,
  depth: Int,
  isRoot: Bool,
  remainingEntries: inout Int
) throws -> [CleanupEntry] {
  guard depth <= SecureFixtureStorage.maximumCleanupDepth else {
    throw FixtureCleanupError.treeMismatch("depth")
  }
  let names = try directoryEntryNames(directory)
  guard names.count <= remainingEntries else {
    throw FixtureCleanupError.treeMismatch("entry-count")
  }
  remainingEntries -= names.count
  var result: [CleanupEntry] = []
  for name in names.sorted() {
    var current = stat()
    guard fstatat(directory.rawValue, name, &current, AT_SYMLINK_NOFOLLOW) == 0 else {
      throw FixtureCleanupError.operationFailed(name, errno: errno)
    }
    let initial = BoundMetadata(current)
    guard isSameCleanupDevice(rootDevice, initial.device) else {
      throw FixtureCleanupError.treeMismatch("mount-boundary:\(name)")
    }
    switch initial.mode & S_IFMT {
    case S_IFREG:
      let raw = openat(
        directory.rawValue,
        name,
        O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
      )
      guard raw >= 0 else { throw FixtureCleanupError.operationFailed(name, errno: errno) }
      let descriptor: BoundDescriptor
      do {
        let bound = try metadata(descriptor: raw)
        guard bound.sameIdentityAndPOSIXAccess(as: initial), bound.owner == geteuid(),
          bound.mode & 0o077 == 0, bound.extendedACL == .absent
        else { throw FixtureCleanupError.treeMismatch(name) }
        descriptor = BoundDescriptor(rawValue: raw, metadata: bound)
      } catch {
        close(raw)
        throw error
      }
      result.append(
        .file(name: name, descriptor: descriptor, isManifest: isRoot && name == "manifest.json"))
    case S_IFDIR:
      let child = try openChildDirectory(
        parent: directory,
        name: name,
        depth: depth + 1,
        expectedDevice: rootDevice
      )
      let children = try inventory(
        directory: child,
        rootDevice: rootDevice,
        depth: depth + 1,
        isRoot: false,
        remainingEntries: &remainingEntries
      )
      result.append(.directory(name: name, descriptor: child, children: children))
    default:
      throw FixtureCleanupError.treeMismatch(name)
    }
  }
  if isRoot {
    guard result.filter(\.isManifest).count == 1 else {
      throw FixtureCleanupError.treeMismatch("manifest")
    }
  }
  return result
}

func isSameCleanupDevice(_ rootDevice: dev_t, _ candidateDevice: dev_t) -> Bool {
  rootDevice == candidateDevice
}

private func delete(entries: [CleanupEntry], from directory: BoundDescriptor) throws {
  for entry in entries.sorted(by: cleanupOrder) {
    switch entry {
    case .file(let name, let descriptor, _):
      try requireStableObject(parent: directory, name: name, descriptor: descriptor)
      try unlink(parent: directory, name: name, flags: 0)
    case .directory(let name, let descriptor, let children):
      try delete(entries: children, from: descriptor)
      try requireStableObject(parent: directory, name: name, descriptor: descriptor)
      try unlink(parent: directory, name: name, flags: AT_REMOVEDIR)
    }
  }
}

private func cleanupOrder(_ left: CleanupEntry, _ right: CleanupEntry) -> Bool {
  if left.isManifest != right.isManifest { return !left.isManifest }
  return left.name < right.name
}

private func requireStableObject(
  parent: BoundDescriptor,
  name: String,
  descriptor: BoundDescriptor
) throws {
  let current = try metadata(descriptor: descriptor.rawValue)
  guard descriptor.metadata.sameIdentityAndAccess(as: current) else {
    throw FixtureCleanupError.objectChanged(name)
  }
  if descriptor.metadata.mode & S_IFMT == S_IFREG,
    !descriptor.metadata.sameContentState(as: current)
  {
    throw FixtureCleanupError.objectChanged(name)
  }
  try requirePathIdentity(parent: parent, name: name, expected: current)
}

private func requirePathIdentity(
  parent: BoundDescriptor,
  name: String,
  expected: BoundMetadata
) throws {
  var current = stat()
  guard fstatat(parent.rawValue, name, &current, AT_SYMLINK_NOFOLLOW) == 0 else {
    throw FixtureCleanupError.operationFailed(name, errno: errno)
  }
  guard expected.sameIdentityAndPOSIXAccess(as: BoundMetadata(current)) else {
    throw FixtureCleanupError.objectChanged(name)
  }
}

private func requireControlDirectoryPathIdentity(
  _ url: URL,
  descriptor: BoundDescriptor,
  record: FixtureControlRecord
) throws {
  let currentDescriptor: BoundMetadata
  do {
    currentDescriptor = try metadata(descriptor: descriptor.rawValue)
  } catch let error as POSIXError {
    throw FixtureControlReadError.unreadable(record, errno: error.code.rawValue)
  }
  guard descriptor.metadata.sameIdentityAndAccess(as: currentDescriptor) else {
    throw FixtureControlReadError.mismatch(record, .accessPolicy)
  }
  var current = stat()
  guard lstat(url.path, &current) == 0 else {
    if errno == ENOENT { throw FixtureControlReadError.missing(record) }
    throw FixtureControlReadError.unreadable(record, errno: errno)
  }
  let currentMetadata = BoundMetadata(current)
  guard descriptor.metadata.sameIdentityAndPOSIXAccess(as: currentMetadata) else {
    throw FixtureControlReadError.mismatch(record, .identityChanged)
  }
}

private func requireDirectoryPathIdentity(
  _ url: URL,
  descriptor: BoundDescriptor,
  cleanupPath: String
) throws {
  let currentDescriptor: BoundMetadata
  do {
    currentDescriptor = try metadata(descriptor: descriptor.rawValue)
  } catch let error as POSIXError {
    throw FixtureCleanupError.operationFailed(cleanupPath, errno: error.code.rawValue)
  }
  guard descriptor.metadata.sameIdentityAndAccess(as: currentDescriptor) else {
    throw FixtureCleanupError.objectChanged(cleanupPath)
  }
  var current = stat()
  guard lstat(url.path, &current) == 0 else {
    throw FixtureCleanupError.operationFailed(cleanupPath, errno: errno)
  }
  guard descriptor.metadata.sameIdentityAndPOSIXAccess(as: BoundMetadata(current)) else {
    throw FixtureCleanupError.objectChanged(cleanupPath)
  }
}

private func directoryEntryNames(_ directory: BoundDescriptor) throws -> [String] {
  let duplicate = dup(directory.rawValue)
  guard duplicate >= 0 else {
    throw FixtureCleanupError.operationFailed("dup-directory", errno: errno)
  }
  guard let stream = fdopendir(duplicate) else {
    let code = errno
    close(duplicate)
    throw FixtureCleanupError.operationFailed("open-directory-stream", errno: code)
  }
  defer { closedir(stream) }
  var names: [String] = []
  errno = 0
  while let entry = readdir(stream) {
    let name = withUnsafePointer(to: &entry.pointee.d_name) {
      $0.withMemoryRebound(to: CChar.self, capacity: Int(MAXNAMLEN) + 1) {
        String(cString: $0)
      }
    }
    if name == "." || name == ".." { continue }
    guard !name.isEmpty, !name.contains("/") else {
      throw FixtureCleanupError.treeMismatch("entry-name")
    }
    names.append(name)
    if names.count > SecureFixtureStorage.maximumCleanupEntries {
      throw FixtureCleanupError.treeMismatch("entry-count")
    }
    errno = 0
  }
  guard errno == 0 else {
    throw FixtureCleanupError.operationFailed("read-directory", errno: errno)
  }
  return names
}

private func renameExclusive(
  parent: BoundDescriptor,
  source: String,
  destination: String,
  operation: String
) throws {
  let result = renameatx_np(
    parent.rawValue,
    source,
    parent.rawValue,
    destination,
    UInt32(RENAME_EXCL)
  )
  guard result == 0 else { throw FixtureCleanupError.operationFailed(operation, errno: errno) }
}

private func acquireSharedLock(
  _ descriptor: Int32,
  record: FixtureControlRecord
) throws {
  let deadline = clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) + 1_000_000_000
  while flock(descriptor, LOCK_SH | LOCK_NB) != 0 {
    let code = errno
    guard code == EWOULDBLOCK || code == EAGAIN else {
      throw FixtureControlReadError.unreadable(record, errno: code)
    }
    guard clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) < deadline else {
      throw FixtureControlReadError.unreadable(record, errno: code)
    }
    usleep(10_000)
  }
}

private func unlink(
  parent: BoundDescriptor,
  name: String,
  flags: Int32
) throws {
  guard unlinkat(parent.rawValue, name, flags) == 0 else {
    throw FixtureCleanupError.operationFailed(name, errno: errno)
  }
}

private func recreateManifest(
  _ data: Data,
  in directory: BoundDescriptor,
  injectFileSyncFailure: Bool,
  injectDirectorySyncFailure: Bool,
  injectCrashAfterFileSync: Bool
) throws {
  let descriptor = openat(
    directory.rawValue,
    "manifest.json",
    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
    0o600
  )
  guard descriptor >= 0 else {
    throw FixtureCleanupError.operationFailed("recreate-manifest", errno: errno)
  }
  defer { close(descriptor) }
  let state = try metadata(descriptor: descriptor)
  guard isOwnerPrivateRegularFile(state) else {
    throw FixtureCleanupError.treeMismatch("manifest")
  }
  try writeAll(data, descriptor: descriptor)
  if injectFileSyncFailure {
    throw FixtureCleanupError.operationFailed("sync-restored-manifest", errno: EIO)
  }
  guard fsync(descriptor) == 0 else {
    throw FixtureCleanupError.operationFailed("sync-restored-manifest", errno: errno)
  }
  if injectCrashAfterFileSync {
    throw FixtureCleanupInjectedCrash.afterRestoredManifestFileSync
  }
  if injectDirectorySyncFailure {
    throw FixtureCleanupError.operationFailed("sync-restored-manifest-directory", errno: EIO)
  }
  guard fsync(directory.rawValue) == 0 else {
    throw FixtureCleanupError.operationFailed("sync-restored-manifest-directory", errno: errno)
  }
  let restored = try readBoundControlFile(
    directory: directory,
    name: "manifest.json",
    record: .manifest
  )
  guard restored == data else { throw FixtureCleanupError.treeMismatch("manifest-content") }
}

private enum FixtureCleanupInjectedCrash: Error {
  case afterStagingDirectoryParentSync
  case beforeFinalDirectoryRemoval
  case afterFinalDirectoryRemovalParentSync
  case afterRestoredManifestFileSync
}

private func createExternalManifestRecovery(
  _ data: Data,
  parent: BoundDescriptor,
  name: String,
  injectExistingFileSyncFailure: Bool = false,
  injectExistingParentSyncFailure: Bool = false
) throws {
  let descriptor = openat(
    parent.rawValue,
    name,
    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
    0o600
  )
  if descriptor < 0, errno == EEXIST {
    let existing = try syncExistingBoundControlFile(
      directory: parent,
      name: name,
      record: .manifest,
      injectFileSyncFailure: injectExistingFileSyncFailure
    )
    guard existing == data else {
      throw FixtureCleanupError.treeMismatch("external-manifest-recovery-content")
    }
    if injectExistingParentSyncFailure {
      throw FixtureCleanupError.operationFailed("sync-manifest-recovery-parent", errno: EIO)
    }
    guard fsync(parent.rawValue) == 0 else {
      throw FixtureCleanupError.operationFailed("sync-manifest-recovery-parent", errno: errno)
    }
    return
  }
  guard descriptor >= 0 else {
    throw FixtureCleanupError.operationFailed("create-manifest-recovery-copy", errno: errno)
  }
  defer { close(descriptor) }
  let state = try metadata(descriptor: descriptor)
  guard state.mode & S_IFMT == S_IFREG, state.owner == geteuid(), state.mode & 0o077 == 0 else {
    throw FixtureCleanupError.treeMismatch("manifest-recovery-copy")
  }
  try writeAll(data, descriptor: descriptor)
  guard fsync(descriptor) == 0 else {
    throw FixtureCleanupError.operationFailed("sync-manifest-recovery-copy", errno: errno)
  }
  guard fsync(parent.rawValue) == 0 else {
    throw FixtureCleanupError.operationFailed("sync-manifest-recovery-parent", errno: errno)
  }
  let recovered = try readBoundControlFile(
    directory: parent,
    name: name,
    record: .manifest
  )
  guard recovered == data else {
    throw FixtureCleanupError.treeMismatch("external-manifest-recovery-content")
  }
}

private func removeExternalManifestRecovery(
  _ data: Data,
  parent: BoundDescriptor,
  name: String
) throws {
  let recovered = try readBoundControlFile(
    directory: parent,
    name: name,
    record: .manifest
  )
  guard recovered == data else {
    throw FixtureCleanupError.treeMismatch("external-manifest-recovery-content")
  }
  try unlink(parent: parent, name: name, flags: 0)
  guard fsync(parent.rawValue) == 0 else {
    throw FixtureCleanupError.operationFailed("sync-manifest-recovery-removal", errno: errno)
  }
}

private func restoreManifest(
  _ data: Data,
  in directory: BoundDescriptor,
  injectFileSyncFailure: Bool,
  injectDirectorySyncFailure: Bool,
  injectCrashAfterFileSync: Bool
) throws {
  var manifest = stat()
  let manifestResult = fstatat(
    directory.rawValue,
    "manifest.json",
    &manifest,
    AT_SYMLINK_NOFOLLOW
  )
  let manifestError = errno
  if manifestResult == 0 {
    let current = try readBoundControlFile(
      directory: directory,
      name: "manifest.json",
      record: .manifest
    )
    guard current == data else { throw FixtureCleanupError.treeMismatch("manifest-content") }
  } else if manifestError == ENOENT {
    try recreateManifest(
      data,
      in: directory,
      injectFileSyncFailure: injectFileSyncFailure,
      injectDirectorySyncFailure: injectDirectorySyncFailure,
      injectCrashAfterFileSync: injectCrashAfterFileSync
    )
  } else {
    throw FixtureCleanupError.operationFailed("inspect-manifest", errno: manifestError)
  }
  let restored = try readBoundControlFile(
    directory: directory,
    name: "manifest.json",
    record: .manifest
  )
  guard restored == data else { throw FixtureCleanupError.treeMismatch("manifest-content") }
}

private func syncExistingBoundControlFile(
  directory: BoundDescriptor,
  name: String,
  record: FixtureControlRecord,
  injectFileSyncFailure: Bool
) throws -> Data {
  let descriptor = openat(
    directory.rawValue,
    name,
    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK
  )
  guard descriptor >= 0 else { throw classifyOpenError(record: record, code: errno) }
  defer { close(descriptor) }
  try acquireSharedLock(descriptor, record: record)
  defer { flock(descriptor, LOCK_UN) }
  let before = try controlMetadata(descriptor: descriptor, record: record)
  guard before.size >= 0, before.size <= SecureFixtureStorage.maximumControlBytes else {
    throw FixtureControlReadError.mismatch(record, .sizeLimit)
  }
  let data: Data
  do {
    data = try readAll(descriptor: descriptor, count: Int(before.size))
  } catch let error as POSIXError {
    throw FixtureControlReadError.unreadable(record, errno: error.code.rawValue)
  }
  if injectFileSyncFailure {
    throw FixtureCleanupError.operationFailed("sync-existing-manifest-recovery-copy", errno: EIO)
  }
  guard fsync(descriptor) == 0 else {
    throw FixtureCleanupError.operationFailed(
      "sync-existing-manifest-recovery-copy",
      errno: errno
    )
  }
  let after = try controlMetadata(descriptor: descriptor, record: record)
  guard before.sameIdentityAndAccess(as: after) else {
    throw FixtureControlReadError.mismatch(record, .identityChanged)
  }
  guard before.sameContentState(as: after) else {
    throw FixtureControlReadError.mismatch(record, .contentChanged)
  }
  var current = stat()
  guard fstatat(directory.rawValue, name, &current, AT_SYMLINK_NOFOLLOW) == 0 else {
    if errno == ENOENT { throw FixtureControlReadError.missing(record) }
    throw FixtureControlReadError.unreadable(record, errno: errno)
  }
  guard before.sameIdentityAndPOSIXAccess(as: BoundMetadata(current)) else {
    throw FixtureControlReadError.mismatch(record, .identityChanged)
  }
  return data
}

private func readAll(descriptor: Int32, count: Int) throws -> Data {
  guard count > 0 else { return Data() }
  var result = Data(count: count)
  try result.withUnsafeMutableBytes { bytes in
    var offset = 0
    while offset < count {
      let received = pread(
        descriptor,
        bytes.baseAddress!.advanced(by: offset),
        count - offset,
        off_t(offset)
      )
      if received < 0, errno == EINTR { continue }
      guard received > 0 else { throw makePOSIXError(code: errno == 0 ? EIO : errno) }
      offset += received
    }
  }
  return result
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

private func makePOSIXError(code: Int32) -> POSIXError {
  POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
}

extension FixtureCleanupError {
  fileprivate var errnoValue: Int32 {
    if case .operationFailed(_, let code) = self { return code }
    return EINVAL
  }
}
