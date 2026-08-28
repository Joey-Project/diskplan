import Darwin
import Foundation

public enum SecureFixtureStorage {
  public static let maximumControlBytes = 64 * 1_024
  fileprivate static let maximumCleanupEntries = 128
  fileprivate static let maximumCleanupDepth = 8

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
    try requireDirectoryPathIdentity(parentURL, descriptor: parent, cleanupPath: parentURL.path)
    try renameExclusive(
      parent: parent,
      source: runName,
      destination: stagingName,
      operation: "stage-run-directory"
    )
    do {
      try requirePathIdentity(parent: parent, name: stagingName, expected: root.metadata)
      try requireDirectoryPathIdentity(parentURL, descriptor: parent, cleanupPath: parentURL.path)
      var remainingEntries = maximumCleanupEntries
      let tree = try inventory(
        directory: root,
        rootDevice: root.metadata.device,
        depth: 0,
        isRoot: true,
        remainingEntries: &remainingEntries
      )
      try createManifestRecoveryCopy(manifestData, in: root)
      try delete(entries: tree, from: root)
      try unlink(parent: root, name: ".manifest-recovery", flags: 0)
      try unlink(parent: parent, name: stagingName, flags: AT_REMOVEDIR)
    } catch {
      let operationError = error
      do {
        try restoreManifest(manifestData, in: root)
        try renameExclusive(
          parent: parent,
          source: stagingName,
          destination: runName,
          operation: "restore-run-directory"
        )
        _ = try readBoundControlFile(directory: root, name: "manifest.json", record: .manifest)
      } catch {
        throw FixtureCleanupError.retained(
          parentURL.appendingPathComponent(stagingName).path
        )
      }
      throw operationError
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

  init(_ value: stat) {
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
  }

  func sameIdentityAndAccess(as other: BoundMetadata) -> Bool {
    device == other.device && inode == other.inode && owner == other.owner
      && group == other.group && mode == other.mode
  }

  func sameContentState(as other: BoundMetadata) -> Bool {
    size == other.size && modifiedSeconds == other.modifiedSeconds
      && modifiedNanoseconds == other.modifiedNanoseconds
      && changedSeconds == other.changedSeconds && changedNanoseconds == other.changedNanoseconds
  }
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
  guard before.sameIdentityAndAccess(as: BoundMetadata(current)) else {
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
}

private func isOwnerPrivateDirectory(_ metadata: BoundMetadata) -> Bool {
  metadata.mode & S_IFMT == S_IFDIR && metadata.owner == geteuid()
    && metadata.mode & 0o077 == 0
}

private func metadata(descriptor: Int32) throws -> BoundMetadata {
  var value = stat()
  guard fstat(descriptor, &value) == 0 else { throw makePOSIXError(code: errno) }
  return BoundMetadata(value)
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
        guard bound.sameIdentityAndAccess(as: initial), bound.owner == geteuid(),
          bound.mode & 0o077 == 0
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
  guard expected.sameIdentityAndAccess(as: BoundMetadata(current)) else {
    throw FixtureCleanupError.objectChanged(name)
  }
}

private func requireControlDirectoryPathIdentity(
  _ url: URL,
  descriptor: BoundDescriptor,
  record: FixtureControlRecord
) throws {
  var current = stat()
  guard lstat(url.path, &current) == 0 else {
    if errno == ENOENT { throw FixtureControlReadError.missing(record) }
    throw FixtureControlReadError.unreadable(record, errno: errno)
  }
  let currentMetadata = BoundMetadata(current)
  guard descriptor.metadata.sameIdentityAndAccess(as: currentMetadata) else {
    throw FixtureControlReadError.mismatch(record, .identityChanged)
  }
}

private func requireDirectoryPathIdentity(
  _ url: URL,
  descriptor: BoundDescriptor,
  cleanupPath: String
) throws {
  var current = stat()
  guard lstat(url.path, &current) == 0 else {
    throw FixtureCleanupError.operationFailed(cleanupPath, errno: errno)
  }
  guard descriptor.metadata.sameIdentityAndAccess(as: BoundMetadata(current)) else {
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

private func recreateManifest(_ data: Data, in directory: BoundDescriptor) throws {
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
  try writeAll(data, descriptor: descriptor)
  let copy = try readBoundControlFile(
    directory: directory,
    name: ".manifest-recovery",
    record: .manifest
  )
  guard copy == data else { throw FixtureCleanupError.treeMismatch("manifest-recovery-content") }
}

private func createManifestRecoveryCopy(_ data: Data, in directory: BoundDescriptor) throws {
  let descriptor = openat(
    directory.rawValue,
    ".manifest-recovery",
    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
    0o600
  )
  guard descriptor >= 0 else {
    throw FixtureCleanupError.operationFailed("create-manifest-recovery-copy", errno: errno)
  }
  defer { close(descriptor) }
  let state = try metadata(descriptor: descriptor)
  guard state.mode & S_IFMT == S_IFREG, state.owner == geteuid(), state.mode & 0o077 == 0 else {
    throw FixtureCleanupError.treeMismatch("manifest-recovery-copy")
  }
  try writeAll(data, descriptor: descriptor)
}

private func restoreManifest(_ data: Data, in directory: BoundDescriptor) throws {
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
    if pathExists(directory: directory, name: ".manifest-recovery") {
      try unlink(parent: directory, name: ".manifest-recovery", flags: 0)
    }
  } else if manifestError == ENOENT,
    pathExists(directory: directory, name: ".manifest-recovery")
  {
    guard
      renameatx_np(
        directory.rawValue,
        ".manifest-recovery",
        directory.rawValue,
        "manifest.json",
        UInt32(RENAME_EXCL)
      ) == 0
    else { throw FixtureCleanupError.operationFailed("restore-manifest-link", errno: errno) }
  } else if manifestError == ENOENT {
    try recreateManifest(data, in: directory)
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

private func pathExists(directory: BoundDescriptor, name: String) -> Bool {
  var value = stat()
  return fstatat(directory.rawValue, name, &value, AT_SYMLINK_NOFOLLOW) == 0
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
