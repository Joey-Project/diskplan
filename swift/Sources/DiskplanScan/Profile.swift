import Foundation

public enum ScanProfile: String, Equatable, Sendable {
  case quick
  case standard
  case deep
  case fullAudit = "full-audit"
}

public struct StructuralBudget: Equatable, Sendable {
  public let maximumEntriesPerRoot: UInt64
  public let maximumDepth: Int
  public let retainedNodeCount: Int
  public let maximumEntriesPerDirectory: UInt64
  public let maximumPendingNameBytes: UInt64

  public init(
    maximumEntriesPerRoot: UInt64,
    maximumDepth: Int,
    retainedNodeCount: Int = 1_000,
    maximumEntriesPerDirectory: UInt64 = 100_000,
    maximumPendingNameBytes: UInt64 = 16 * 1_024 * 1_024
  ) {
    precondition(maximumDepth >= 0 && retainedNodeCount >= 0)
    self.maximumEntriesPerRoot = maximumEntriesPerRoot
    self.maximumDepth = maximumDepth
    self.retainedNodeCount = retainedNodeCount
    self.maximumEntriesPerDirectory = maximumEntriesPerDirectory
    self.maximumPendingNameBytes = maximumPendingNameBytes
  }
}

public struct ScanRootRequest: Equatable, Sendable {
  public let rootID: String
  public let rawAbsolutePath: Data

  public init(rootID: String, rawAbsolutePath: Data) {
    self.rootID = rootID
    self.rawAbsolutePath = rawAbsolutePath
  }
}

public enum ScanRootPathValidationError: Error, Equatable, Sendable {
  case malformed
}

public enum CanonicalScanRootPath: Equatable, Sendable {
  case filesystemRoot
  case parentSlot(parentPath: Data, rawName: Data)

  public static func parse(_ rawPath: Data) throws -> Self {
    let separator = UInt8(ascii: "/")
    guard !rawPath.isEmpty, rawPath.first == separator, !rawPath.contains(0) else {
      throw ScanRootPathValidationError.malformed
    }
    if rawPath == Data([separator]) { return .filesystemRoot }
    guard rawPath.last != separator else { throw ScanRootPathValidationError.malformed }
    let components = rawPath.dropFirst().split(
      separator: separator,
      omittingEmptySubsequences: false
    )
    guard
      !components.isEmpty,
      components.allSatisfy({
        !$0.isEmpty && $0 != Data(".".utf8) && $0 != Data("..".utf8)
      }),
      let finalSeparator = rawPath.lastIndex(of: separator)
    else {
      throw ScanRootPathValidationError.malformed
    }
    let parentPath =
      finalSeparator == rawPath.startIndex
      ? Data([separator]) : Data(rawPath[..<finalSeparator])
    let rawName = Data(rawPath[rawPath.index(after: finalSeparator)...])
    return .parentSlot(parentPath: parentPath, rawName: rawName)
  }
}

public enum ScanScopeValidationError: Error, Equatable, Sendable {
  case duplicateRootID(String)
}

public struct ScanEnvironment: Equatable, Sendable {
  public let adapterRoots: [ScanRootRequest]
  public let homeRoot: ScanRootRequest?
  public let temporaryRoots: [ScanRootRequest]
  public let cacheRoots: [ScanRootRequest]
  public let visibleLocalWritableVolumes: [ScanRootRequest]

  public init(
    adapterRoots: [ScanRootRequest] = [],
    homeRoot: ScanRootRequest? = nil,
    temporaryRoots: [ScanRootRequest] = [],
    cacheRoots: [ScanRootRequest] = [],
    visibleLocalWritableVolumes: [ScanRootRequest] = []
  ) {
    self.adapterRoots = adapterRoots
    self.homeRoot = homeRoot
    self.temporaryRoots = temporaryRoots
    self.cacheRoots = cacheRoots
    self.visibleLocalWritableVolumes = visibleLocalWritableVolumes
  }
}

public struct ResolvedScanScope: Equatable, Sendable {
  public let resolverVersion: UInt32
  public let profile: ScanProfile
  public let roots: [ScanRootRequest]
  public let budget: StructuralBudget
  public let maximumDurationNanoseconds: UInt64?

  public init(
    resolverVersion: UInt32,
    profile: ScanProfile,
    roots: [ScanRootRequest],
    budget: StructuralBudget,
    maximumDurationNanoseconds: UInt64?
  ) throws {
    var seenRootIDs = Set<String>()
    for root in roots where !seenRootIDs.insert(root.rootID).inserted {
      throw ScanScopeValidationError.duplicateRootID(root.rootID)
    }
    self.resolverVersion = resolverVersion
    self.profile = profile
    self.roots = roots
    self.budget = budget
    self.maximumDurationNanoseconds = maximumDurationNanoseconds
  }
}

public struct ScanRootResolver: Sendable {
  public static let version: UInt32 = 1

  public init() {}

  public func resolve(
    profile: ScanProfile,
    environment: ScanEnvironment,
    explicitRoots: [ScanRootRequest] = [],
    maximumDurationNanoseconds: UInt64? = nil
  ) throws -> ResolvedScanScope {
    let roots: [ScanRootRequest]
    let budget: StructuralBudget
    switch profile {
    case .quick:
      roots = environment.adapterRoots
      budget = StructuralBudget(maximumEntriesPerRoot: 0, maximumDepth: 0)
    case .standard:
      roots =
        environment.adapterRoots + [environment.homeRoot].compactMap { $0 }
        + environment.temporaryRoots + environment.cacheRoots
      budget = StructuralBudget(maximumEntriesPerRoot: 2_000_000, maximumDepth: 64)
    case .deep:
      roots = explicitRoots
      budget = StructuralBudget(maximumEntriesPerRoot: 10_000_000, maximumDepth: 128)
    case .fullAudit:
      roots = environment.visibleLocalWritableVolumes
      budget = StructuralBudget(
        maximumEntriesPerRoot: 100_000_000,
        maximumDepth: 128,
        retainedNodeCount: 10_000,
        maximumEntriesPerDirectory: 1_000_000,
        maximumPendingNameBytes: 64 * 1_024 * 1_024
      )
    }
    let canonical = roots.sorted {
      if $0.rawAbsolutePath != $1.rawAbsolutePath {
        return $0.rawAbsolutePath.lexicographicallyPrecedes($1.rawAbsolutePath)
      }
      return $0.rootID < $1.rootID
    }
    return try ResolvedScanScope(
      resolverVersion: Self.version,
      profile: profile,
      roots: canonical,
      budget: budget,
      maximumDurationNanoseconds: maximumDurationNanoseconds
    )
  }
}
