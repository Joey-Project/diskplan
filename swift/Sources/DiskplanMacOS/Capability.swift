import Foundation

public enum CapabilityStatus: String, Codable, Equatable, Sendable {
  case known
  case unsupported
  case permissionDenied
  case unavailable
  case failed
  case inconsistent
}

public struct Capability<Value: Equatable & Sendable>: Equatable, Sendable {
  public let status: CapabilityStatus
  public let value: Value?
  public let detail: String?
  public let errorCode: Int32?

  public init(
    status: CapabilityStatus,
    value: Value? = nil,
    detail: String? = nil,
    errorCode: Int32? = nil
  ) {
    precondition(status == .known ? value != nil : value == nil)
    self.status = status
    self.value = value
    self.detail = detail
    self.errorCode = errorCode
  }

  public static func known(_ value: Value) -> Self {
    Self(status: .known, value: value)
  }

  public static func unavailable(_ detail: String) -> Self {
    Self(status: .unavailable, detail: detail)
  }
}

enum POSIXFailure {
  static func capability<Value>(
    _ code: Int32,
    operation: String,
    as: Value.Type = Value.self
  ) -> Capability<Value> where Value: Equatable & Sendable {
    let status: CapabilityStatus
    switch code {
    case ENOTSUP, EOPNOTSUPP, ENOSYS:
      status = .unsupported
    case EACCES, EPERM:
      status = .permissionDenied
    default:
      status = .failed
    }
    return Capability(status: status, detail: operation, errorCode: code)
  }
}
