import Darwin
import DiskplanMacOS
@preconcurrency import Foundation

public enum DoctorProbeKind: String, CaseIterable, Comparable, Equatable, Hashable, Sendable {
  case apfs
  case effectiveUser = "effective-user"
  case fileProvider = "file-provider"
  case filesystemPermission = "filesystem-permission"
  case materializationPolicy = "materialization-policy"
  case processProbe = "process-probe"
  case sip
  case tcc

  public static func < (lhs: Self, rhs: Self) -> Bool { lhs.rawValue < rhs.rawValue }
}

public enum DoctorStatus: String, Equatable, Hashable, Sendable {
  case known
  case unknown
  case unsupported
  case permissionDenied = "permission-denied"
  case unavailable
  case unreadable
  case failed
  case inconsistent
}

public struct DoctorObservation: Equatable, Sendable {
  public let kind: DoctorProbeKind
  public let status: DoctorStatus
  public let value: String?
  public let detailCode: String?
  public let errorCode: Int32?

  public init(
    kind: DoctorProbeKind,
    status: DoctorStatus,
    value: String? = nil,
    detailCode: String? = nil,
    errorCode: Int32? = nil
  ) {
    self.kind = kind
    if (status == .known) != (value != nil) {
      self.status = .inconsistent
      self.value = nil
      self.detailCode = "malformed-doctor-observation"
    } else {
      self.status = status
      self.value = value
      self.detailCode = detailCode
    }
    self.errorCode = errorCode
  }
}

public struct DoctorReport: Equatable, Sendable {
  public static let schemaVersion = "diskplan.doctor.v1"

  public let schemaVersion: String
  public let observations: [DoctorObservation]

  fileprivate init(observations: [DoctorObservation]) {
    schemaVersion = Self.schemaVersion
    self.observations = observations.sorted { $0.kind < $1.kind }
  }
}

/// The doctor boundary intentionally exposes only reads. Implementations cannot receive a
/// configuration writer, cache writer, path materializer, or process-launch authority.
protocol ReadOnlyDoctorProbing: Sendable {
  func observe(_ kind: DoctorProbeKind) -> DoctorObservation
}

public struct DiskplanDoctorService: Sendable {
  private let probe: any ReadOnlyDoctorProbing

  public init() {
    probe = SystemReadOnlyDoctorProbe()
  }

  init(probe: any ReadOnlyDoctorProbing) {
    self.probe = probe
  }

  /// Returns a typed report in stable kind order. The operation performs no persistence.
  public func inspect() -> DoctorReport {
    let observations = DoctorProbeKind.allCases.map { expected in
      let observed = probe.observe(expected)
      guard observed.kind == expected else {
        return DoctorObservation(
          kind: expected,
          status: .inconsistent,
          detailCode: "probe-returned-mismatched-kind"
        )
      }
      return observed
    }
    return DoctorReport(observations: observations)
  }
}

struct SystemReadOnlyDoctorProbe: ReadOnlyDoctorProbing {
  private let operations: SystemDoctorReadOperations

  init() {
    operations = .production
  }

  init(operations: SystemDoctorReadOperations) {
    self.operations = operations
  }

  func observe(_ kind: DoctorProbeKind) -> DoctorObservation {
    switch kind {
    case .materializationPolicy:
      return materializationPolicy()
    case .fileProvider:
      if operations.fileProviderAPIPresent() {
        return DoctorObservation(
          kind: kind,
          status: .known,
          value: "api-available",
          detailCode: "framework-api-presence-only"
        )
      }
      return DoctorObservation(
        kind: kind,
        status: .unsupported,
        detailCode: "framework-api-unavailable"
      )
    case .apfs:
      return DoctorObservation(
        kind: kind,
        status: .unavailable,
        detailCode: "bound-volume-descriptor-required"
      )
    case .processProbe:
      return executableProbe(kind: kind, path: "/usr/sbin/lsof")
    case .effectiveUser:
      return DoctorObservation(
        kind: kind,
        status: .known,
        value: operations.effectiveUserID() == 0 ? "root" : "current-user",
        detailCode: "effective-user-only"
      )
    case .filesystemPermission:
      return DoctorObservation(
        kind: kind,
        status: .unavailable,
        detailCode: "bound-resource-permission-probe-required"
      )
    case .sip:
      return DoctorObservation(
        kind: kind,
        status: .unknown,
        detailCode: "no-authoritative-read-only-public-api"
      )
    case .tcc:
      return DoctorObservation(
        kind: kind,
        status: .unavailable,
        detailCode: "resource-specific-probe-not-requested"
      )
    }
  }

  private func materializationPolicy() -> DoctorObservation {
    let capability = operations.materializationPolicy()
    guard capability.status == .known, let value = capability.value else {
      return DoctorObservation(
        kind: .materializationPolicy,
        status: Self.map(capability.status),
        detailCode: "materialization-policy-read",
        errorCode: capability.errorCode
      )
    }
    return DoctorObservation(
      kind: .materializationPolicy,
      status: .known,
      value: value ? "off" : "not-off",
      detailCode: "read-only-process-policy"
    )
  }

  private func executableProbe(kind: DoctorProbeKind, path: String) -> DoctorObservation {
    let accessResult = operations.executableAccess(path)
    let result = accessResult.result
    if result == 0 {
      return DoctorObservation(
        kind: kind,
        status: .known,
        value: "available",
        detailCode: "executable-presence-only"
      )
    }
    let code = accessResult.errorCode
    switch code {
    case EACCES, EPERM:
      return DoctorObservation(
        kind: kind, status: .permissionDenied,
        detailCode: "executable-access-denied", errorCode: code)
    case ENOENT:
      return DoctorObservation(
        kind: kind, status: .unsupported,
        detailCode: "executable-not-installed", errorCode: code)
    default:
      return DoctorObservation(
        kind: kind, status: .unreadable,
        detailCode: "executable-presence-unreadable", errorCode: code)
    }
  }

  private static func map(_ status: CapabilityStatus) -> DoctorStatus {
    switch status {
    case .known: .known
    case .unsupported: .unsupported
    case .permissionDenied: .permissionDenied
    case .unavailable: .unavailable
    case .failed: .failed
    case .inconsistent: .inconsistent
    }
  }
}

struct SystemDoctorReadOperations: Sendable {
  let materializationPolicy: @Sendable () -> Capability<Bool>
  let fileProviderAPIPresent: @Sendable () -> Bool
  let executableAccess: @Sendable (String) -> (result: Int32, errorCode: Int32)
  let effectiveUserID: @Sendable () -> uid_t

  static let production = Self(
    materializationPolicy: { MaterializationPolicyReader().read() },
    fileProviderAPIPresent: { NSClassFromString("NSFileProviderManager") != nil },
    executableAccess: { path in
      let result = path.withCString { access($0, X_OK) }
      return (result, result == 0 ? 0 : errno)
    },
    effectiveUserID: { geteuid() }
  )
}
