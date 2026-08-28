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

  public init(maximumEntriesPerRoot: UInt64, maximumDepth: Int, retainedNodeCount: Int = 1_000) {
    precondition(maximumDepth >= 0 && retainedNodeCount >= 0)
    self.maximumEntriesPerRoot = maximumEntriesPerRoot
    self.maximumDepth = maximumDepth
    self.retainedNodeCount = retainedNodeCount
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
  ) {
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
  ) -> ResolvedScanScope {
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
        maximumEntriesPerRoot: 100_000_000, maximumDepth: 128, retainedNodeCount: 10_000)
    }
    var seen = Set<String>()
    let canonical = roots.sorted {
      if $0.rawAbsolutePath != $1.rawAbsolutePath {
        return $0.rawAbsolutePath.lexicographicallyPrecedes($1.rawAbsolutePath)
      }
      return $0.rootID < $1.rootID
    }.filter { seen.insert($0.rootID).inserted }
    return ResolvedScanScope(
      resolverVersion: Self.version,
      profile: profile,
      roots: canonical,
      budget: budget,
      maximumDurationNanoseconds: maximumDurationNanoseconds
    )
  }
}
