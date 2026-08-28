import Foundation

public enum ClassificationRank: UInt8, CaseIterable, Comparable, Hashable, Sendable {
  case fallback = 1
  case pathConvention = 2
  case structural = 3
  case authoritative = 4

  public static func < (lhs: Self, rhs: Self) -> Bool {
    lhs.rawValue < rhs.rawValue
  }
}

public enum ClassificationFacet: String, CaseIterable, Comparable, Hashable, Sendable {
  case lifecycle
  case ownership
  case purpose
  case recoverability

  public static func < (lhs: Self, rhs: Self) -> Bool {
    lhs.rawValue < rhs.rawValue
  }
}

public enum ClassificationSource: Equatable, Hashable, Sendable {
  case authoritativeAdapter(String)
  case structuralRecognizer(String)
  case pathConvention(String)
  case genericFallback
  case agentSuggestion(String)

  public var isAgentAssisted: Bool {
    if case .agentSuggestion = self { return true }
    return false
  }

  fileprivate var deterministicRank: ClassificationRank? {
    switch self {
    case .authoritativeAdapter: .authoritative
    case .structuralRecognizer: .structural
    case .pathConvention: .pathConvention
    case .genericFallback: .fallback
    case .agentSuggestion: nil
    }
  }
}

public struct ClassificationClaim: Equatable, Sendable {
  public let facet: ClassificationFacet
  public let value: String
  public let rank: ClassificationRank?
  public let source: ClassificationSource
  public let evidenceKey: String

  public init(
    facet: ClassificationFacet,
    value: String,
    source: ClassificationSource,
    evidenceKey: String
  ) {
    self.facet = facet
    self.value = value
    rank = source.deterministicRank
    self.source = source
    self.evidenceKey = evidenceKey
  }
}

/// A type hint selects recognizers; it is not itself a classification claim.
public struct TypeHintRoute: Equatable, Sendable {
  public let recognizerID: String
  public let hint: String

  public init(recognizerID: String, hint: String) {
    self.recognizerID = recognizerID
    self.hint = hint
  }
}

public struct ResolvedFacet: Equatable, Sendable {
  public let facet: ClassificationFacet
  public let value: String
  public let rank: ClassificationRank
  public let supportingClaims: [ClassificationClaim]

}

public struct ClassificationConflict: Equatable, Sendable {
  public let facet: ClassificationFacet
  public let rank: ClassificationRank
  public let claims: [ClassificationClaim]
}

public struct ClassificationResolution: Equatable, Sendable {
  public let facets: [ResolvedFacet]
  public let conflicts: [ClassificationConflict]
  public let agentSuggestions: [ClassificationClaim]

  public var isConflict: Bool { !conflicts.isEmpty }

  /// Agent output never independently establishes an execution-ready classification.
  public var hasIndependentNonAgentSupport: Bool {
    !facets.isEmpty
  }

  public var deterministicMissingFacets: [ClassificationFacet] {
    ClassificationFacet.allCases.filter { facet in
      !facets.contains(where: { $0.facet == facet })
        && !conflicts.contains(where: { $0.facet == facet })
    }
  }
}

public enum ClassificationResolver {
  public static func resolve(_ claims: [ClassificationClaim]) -> ClassificationResolution {
    var facets: [ResolvedFacet] = []
    var conflicts: [ClassificationConflict] = []

    for facet in ClassificationFacet.allCases {
      let candidates = claims.filter { $0.facet == facet && !$0.source.isAgentAssisted }
      guard let winningRank = candidates.compactMap(\.rank).max() else { continue }
      let winners = deduplicated(candidates.filter { $0.rank == winningRank })
      let values = Set(winners.map { Data($0.value.utf8) })
      if values.count > 1 {
        conflicts.append(
          ClassificationConflict(facet: facet, rank: winningRank, claims: winners)
        )
      } else if let value = winners.first?.value {
        facets.append(
          ResolvedFacet(
            facet: facet,
            value: value,
            rank: winningRank,
            supportingClaims: winners
          )
        )
      }
    }

    let resolvedFacets = Set(facets.map(\.facet))
    let conflictedFacets = Set(conflicts.map(\.facet))
    let reviewableMissingFacets = Set(ClassificationFacet.allCases)
      .subtracting(resolvedFacets)
      .subtracting(conflictedFacets)

    return ClassificationResolution(
      facets: facets.sorted { $0.facet < $1.facet },
      conflicts: conflicts.sorted { $0.facet < $1.facet },
      agentSuggestions: deduplicated(
        claims.filter {
          $0.source.isAgentAssisted && reviewableMissingFacets.contains($0.facet)
        }
      )
    )
  }

  private static func claimOrder(_ lhs: ClassificationClaim, _ rhs: ClassificationClaim) -> Bool {
    let left = claimKey(lhs)
    let right = claimKey(rhs)
    return left.lexicographicallyPrecedes(right) { left, right in
      left.lexicographicallyPrecedes(right)
    }
  }

  private static func deduplicated(_ claims: [ClassificationClaim]) -> [ClassificationClaim] {
    var result: [ClassificationClaim] = []
    var previousKey: [Data]?
    for claim in claims.sorted(by: claimOrder) {
      let key = claimKey(claim)
      if key != previousKey {
        result.append(claim)
        previousKey = key
      }
    }
    return result
  }

  private static func claimKey(_ claim: ClassificationClaim) -> [Data] {
    [claim.facet.rawValue, claim.value, claim.evidenceKey, sourceKey(claim.source)]
      .map { Data($0.utf8) }
  }

  private static func sourceKey(_ source: ClassificationSource) -> String {
    switch source {
    case .authoritativeAdapter(let value): "0:\(value)"
    case .structuralRecognizer(let value): "1:\(value)"
    case .pathConvention(let value): "2:\(value)"
    case .genericFallback: "3"
    case .agentSuggestion(let value): "4:\(value)"
    }
  }
}
