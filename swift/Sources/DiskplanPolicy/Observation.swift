import Foundation

/// A policy input whose absence and collection failures remain distinguishable.
public enum Observation<Value: Equatable & Sendable>: Equatable, Sendable {
  case absent
  case known(Value)
  case unknown(UnknownReason)
  case unreadable(ObservationFailure)
  case failed(ObservationFailure)

  public var knownValue: Value? {
    guard case .known(let value) = self else { return nil }
    return value
  }

  public func map<Mapped: Equatable & Sendable>(
    _ transform: (Value) -> Mapped
  ) -> Observation<Mapped> {
    switch self {
    case .absent: .absent
    case .known(let value): .known(transform(value))
    case .unknown(let reason): .unknown(reason)
    case .unreadable(let failure): .unreadable(failure)
    case .failed(let failure): .failed(failure)
    }
  }
}

public enum UnknownReason: String, CaseIterable, Equatable, Sendable {
  case notRequested
  case unsupported
  case budgetExhausted
  case timedOut
  case incompleteCoverage
  case unavailableViaPublicAPI
}

public struct ObservationFailure: Equatable, Sendable {
  public let code: String
  public let collector: String

  public init(code: String, collector: String) {
    self.code = code
    self.collector = collector
  }
}

/// A sortable value that never turns unknown evidence into a numeric sentinel.
public enum KnownOrUnknown<Value: Comparable & Sendable>: Equatable, Sendable {
  case known(Value)
  case unknown(UnknownReason)
}

extension KnownOrUnknown: Comparable {
  public static func < (lhs: Self, rhs: Self) -> Bool {
    switch (lhs, rhs) {
    case (.known(let left), .known(let right)):
      left < right
    case (.known, .unknown):
      true
    case (.unknown, .known):
      false
    case (.unknown(let left), .unknown(let right)):
      left.rawValue < right.rawValue
    }
  }
}
