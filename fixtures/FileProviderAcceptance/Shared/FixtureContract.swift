import Foundation

public enum FixtureContract {
  public static let hostBundleIdentifier = "com.joeyteng.diskplan.fileprovider-fixture"
  public static let extensionBundleIdentifier =
    "com.joeyteng.diskplan.fileprovider-fixture.extension"
  public static let appGroupIdentifier =
    "group.com.joeyteng.diskplan.fileprovider-fixture"
  public static let domainPrefix = "diskplan-fixture-"
  public static let displayName = ".Diskplan File Provider Fixture"
  public static let sentinelIdentifier = "sentinel"
  public static let sentinelName = "sentinel.txt"
  public static let sealedDirectoryIdentifier = "sealed-dir"
  public static let sealedDirectoryName = "sealed-dir"
  public static let forbiddenChildIdentifier = "forbidden-child"
  public static let forbiddenChildName = "must-not-enumerate.txt"
  public static let sentinelByteCount = 65_536
  public static let maximumOracleBytes = 4 * 1_024 * 1_024
  public static let forbiddenEventKinds: Set<OracleEventKind> = [
    .fetchContents,
    .createItem,
    .modifyItem,
    .deleteItem,
    .materializedItemsDidChange,
    .sealedDirectoryEnumeration,
  ]

  public static func domainIdentifier(runID: UUID) -> String {
    domainPrefix + runID.uuidString.lowercased()
  }

  public static func runID(domainIdentifier: String) -> UUID? {
    guard domainIdentifier.hasPrefix(domainPrefix) else { return nil }
    return UUID(uuidString: String(domainIdentifier.dropFirst(domainPrefix.count)))
  }

  public static func sentinelContents() -> Data {
    let pattern = Data("diskplan-file-provider-fixture\n".utf8)
    var result = Data(capacity: sentinelByteCount)
    while result.count < sentinelByteCount { result.append(pattern) }
    return result.prefix(sentinelByteCount)
  }

  public static func runDirectory(containerURL: URL, runID: UUID) throws -> URL {
    guard containerURL.isFileURL else { throw FixtureContractError.nonFileURL }
    let normalized = runID.uuidString.lowercased()
    return
      containerURL
      .appendingPathComponent("runs", isDirectory: true)
      .appendingPathComponent(normalized, isDirectory: true)
  }
}

public enum FixtureContractError: Error, Equatable {
  case nonFileURL
  case invalidManifest
  case oracleTooLarge
  case unsafePath
}

public enum FixtureControlRecord: String, Equatable, Sendable {
  case manifest
  case ready
  case window
  case events
}

public enum FixtureControlMismatch: String, Equatable, Sendable {
  case objectType
  case owner
  case accessPolicy
  case sizeLimit
  case identityChanged
  case contentChanged
  case malformed
  case semantic
}

public enum FixtureControlReadError: Error, Equatable, Sendable {
  case missing(FixtureControlRecord)
  case unreadable(FixtureControlRecord, errno: Int32)
  case mismatch(FixtureControlRecord, FixtureControlMismatch)
}

public enum FixtureCleanupError: Error, Equatable, Sendable {
  case unsafeTarget
  case treeMismatch(String)
  case objectChanged(String)
  case operationFailed(String, errno: Int32)
  case retained(String)
}

public enum OracleQuiescenceError: Error, Equatable, Sendable {
  case invalidBounds
  case timedOut
}

public struct OracleQuiescence: Equatable, Sendable {
  public let eventCount: Int
  public let lastSequence: UInt64
  public let quietMilliseconds: Int

  public init(eventCount: Int, lastSequence: UInt64, quietMilliseconds: Int) {
    self.eventCount = eventCount
    self.lastSequence = lastSequence
    self.quietMilliseconds = quietMilliseconds
  }
}

public struct FixtureManifest: Codable, Equatable, Sendable {
  public let version: Int
  public let runID: UUID
  public let domainIdentifier: String
  public let taskRoot: String
  public let appPath: String
  public let extensionPath: String
  public let appGroupRunPath: String

  public init(
    runID: UUID,
    taskRoot: String,
    appPath: String,
    extensionPath: String,
    appGroupRunPath: String
  ) {
    version = 1
    self.runID = runID
    domainIdentifier = FixtureContract.domainIdentifier(runID: runID)
    self.taskRoot = taskRoot
    self.appPath = appPath
    self.extensionPath = extensionPath
    self.appGroupRunPath = appGroupRunPath
  }

  public func validate(expectedTaskRoot: URL? = nil) throws {
    guard version == 1,
      domainIdentifier == FixtureContract.domainIdentifier(runID: runID)
    else { throw FixtureContractError.invalidManifest }
    let runComponent = runID.uuidString.lowercased()
    let paths = [taskRoot, appGroupRunPath]
    guard
      paths.allSatisfy({
        URL(fileURLWithPath: $0).standardizedFileURL.pathComponents.contains(runComponent)
      })
    else { throw FixtureContractError.unsafePath }
    let appURL = URL(fileURLWithPath: appPath).standardizedFileURL
    let extensionURL = URL(fileURLWithPath: extensionPath).standardizedFileURL
    guard appPath.hasPrefix("/"), extensionPath.hasPrefix("/"),
      appURL.pathExtension == "app", extensionURL.pathExtension == "appex",
      extensionURL.deletingLastPathComponent()
        == appURL.appendingPathComponent("Contents/PlugIns", isDirectory: true)
    else { throw FixtureContractError.unsafePath }
    if let expectedTaskRoot {
      let expected = expectedTaskRoot.standardizedFileURL.path
      guard URL(fileURLWithPath: taskRoot).standardizedFileURL.path == expected else {
        throw FixtureContractError.unsafePath
      }
    }
  }
}

public struct FixtureReadyState: Codable, Equatable, Sendable {
  public let version: Int
  public let runID: UUID
  public let domainIdentifier: String
  public let sentinelPath: String
  public let sealedDirectoryPath: String

  public init(runID: UUID, sentinelPath: String, sealedDirectoryPath: String) {
    version = 1
    self.runID = runID
    domainIdentifier = FixtureContract.domainIdentifier(runID: runID)
    self.sentinelPath = sentinelPath
    self.sealedDirectoryPath = sealedDirectoryPath
  }

  public func validate(manifest: FixtureManifest) throws {
    guard version == 1, runID == manifest.runID,
      domainIdentifier == manifest.domainIdentifier,
      sentinelPath.hasPrefix("/"), sealedDirectoryPath.hasPrefix("/"),
      URL(fileURLWithPath: sentinelPath).lastPathComponent == FixtureContract.sentinelName,
      URL(fileURLWithPath: sealedDirectoryPath).lastPathComponent
        == FixtureContract.sealedDirectoryName
    else { throw FixtureContractError.invalidManifest }
    let sentinelParent = URL(fileURLWithPath: sentinelPath).deletingLastPathComponent()
    let sealedParent = URL(fileURLWithPath: sealedDirectoryPath).deletingLastPathComponent()
    guard sentinelParent.standardizedFileURL == sealedParent.standardizedFileURL else {
      throw FixtureContractError.invalidManifest
    }
  }
}

public enum OracleEventKind: String, Codable, CaseIterable, Sendable {
  case itemMetadata = "item_metadata"
  case rootEnumeration = "root_enumeration"
  case workingSetEnumeration = "working_set_enumeration"
  case sealedDirectoryEnumeration = "sealed_directory_enumeration"
  case fetchContents = "fetch_contents"
  case createItem = "create_item"
  case modifyItem = "modify_item"
  case deleteItem = "delete_item"
  case materializedItemsDidChange = "materialized_items_did_change"
  case changeEnumeration = "change_enumeration"
  case syncAnchor = "sync_anchor"
}

public struct OracleEvent: Codable, Equatable, Sendable {
  public var sequence: UInt64
  public let runID: UUID
  public let domainIdentifier: String
  public let itemIdentifier: String
  public let kind: OracleEventKind
  public let processID: Int32
  public let monotonicNanoseconds: UInt64
  public let requestFlags: [String]

  public init(
    sequence: UInt64 = 0,
    runID: UUID,
    domainIdentifier: String,
    itemIdentifier: String,
    kind: OracleEventKind,
    processID: Int32,
    monotonicNanoseconds: UInt64,
    requestFlags: [String] = []
  ) {
    self.sequence = sequence
    self.runID = runID
    self.domainIdentifier = domainIdentifier
    self.itemIdentifier = itemIdentifier
    self.kind = kind
    self.processID = processID
    self.monotonicNanoseconds = monotonicNanoseconds
    self.requestFlags = requestFlags.sorted()
  }
}

public struct OracleWindow: Codable, Equatable, Sendable {
  public let beginNanoseconds: UInt64
  public let endNanoseconds: UInt64?
  public let quietMilliseconds: Int?
  public let eventCount: Int?
  public let lastSequence: UInt64?

  public init(
    beginNanoseconds: UInt64,
    endNanoseconds: UInt64? = nil,
    quietMilliseconds: Int? = nil,
    eventCount: Int? = nil,
    lastSequence: UInt64? = nil
  ) {
    self.beginNanoseconds = beginNanoseconds
    self.endNanoseconds = endNanoseconds
    self.quietMilliseconds = quietMilliseconds
    self.eventCount = eventCount
    self.lastSequence = lastSequence
  }

  public func validate() throws {
    if let endNanoseconds {
      guard endNanoseconds >= beginNanoseconds,
        let quietMilliseconds, (50...5_000).contains(quietMilliseconds),
        let eventCount, eventCount >= 0,
        let lastSequence,
        lastSequence == UInt64(eventCount),
        endNanoseconds - beginNanoseconds >= UInt64(quietMilliseconds) * 1_000_000
      else { throw FixtureContractError.invalidManifest }
    } else {
      guard quietMilliseconds == nil, eventCount == nil, lastSequence == nil else {
        throw FixtureContractError.invalidManifest
      }
    }
  }

  public func contains(_ event: OracleEvent) -> Bool {
    guard event.monotonicNanoseconds >= beginNanoseconds else { return false }
    guard let endNanoseconds else { return true }
    return event.monotonicNanoseconds <= endNanoseconds
  }
}
