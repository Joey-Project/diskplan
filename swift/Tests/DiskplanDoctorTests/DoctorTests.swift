import Foundation
import Testing

@testable import DiskplanDoctor
@testable import DiskplanMacOS

@Test
func doctorPreservesTypedStatesAndStableOrder() {
  let recorder = RecordingDoctorProbe()
  let report = DiskplanDoctorService(probe: recorder).inspect()
  #expect(report.schemaVersion == "diskplan.doctor.v1")
  #expect(report.observations.map(\.kind) == DoctorProbeKind.allCases.sorted())
  #expect(Set(report.observations.map(\.status)).contains(.unreadable))
  #expect(Set(report.observations.map(\.status)).contains(.unsupported))
  #expect(Set(report.observations.map(\.status)).contains(.permissionDenied))
  #expect(DoctorStatus.unknown != .unsupported)
  #expect(recorder.calls.withLock { $0 } == DoctorProbeKind.allCases)
}

@Test
func doctorBoundaryHasNoWriteMaterializationOrProcessLaunchAuthority() {
  let recorder = RecordingDoctorProbe()
  _ = DiskplanDoctorService(probe: recorder).inspect()
  #expect(recorder.calls.withLock(\.count) == DoctorProbeKind.allCases.count)
  #expect(recorder.writeAttempts.withLock { $0 } == 0)
  #expect(recorder.materializationAttempts.withLock { $0 } == 0)
  #expect(recorder.processLaunchAttempts.withLock { $0 } == 0)
}

@Test
func malformedAndMismatchedDoctorObservationsBecomeTypedInconsistentResults() {
  let malformed = DoctorObservation(kind: .apfs, status: .known)
  #expect(malformed.status == .inconsistent)
  #expect(malformed.detailCode == "malformed-doctor-observation")

  let report = DiskplanDoctorService(probe: MismatchedDoctorProbe()).inspect()
  #expect(report.observations.first(where: { $0.kind == .effectiveUser })?.status == .inconsistent)
  #expect(
    report.observations.first(where: { $0.kind == .effectiveUser })?.detailCode
      == "probe-returned-mismatched-kind"
  )
}

@Test
func systemDoctorUsesOnlyInjectedReadOperations() {
  let reads = Locked<[String]>([])
  let operations = SystemDoctorReadOperations(
    materializationPolicy: {
      reads.withLock { $0.append("materialization-policy") }
      return .known(true)
    },
    fileProviderAPIPresent: {
      reads.withLock { $0.append("file-provider-api") }
      return true
    },
    executableAccess: { path in
      reads.withLock { $0.append("access:" + path) }
      return (0, 0)
    },
    effectiveUserID: {
      reads.withLock { $0.append("effective-user") }
      return 501
    }
  )
  let report = DiskplanDoctorService(
    probe: SystemReadOnlyDoctorProbe(operations: operations)
  ).inspect()
  #expect(report.observations.count == DoctorProbeKind.allCases.count)
  #expect(
    reads.withLock { $0 }
      == [
        "effective-user", "file-provider-api", "materialization-policy",
        "access:/usr/sbin/lsof",
      ]
  )
}

private final class Locked<Value>: @unchecked Sendable {
  private let lock = NSLock()
  private var value: Value

  init(_ value: Value) { self.value = value }

  func withLock<Result>(_ body: (inout Value) -> Result) -> Result {
    lock.withLock { body(&value) }
  }

  func withLock<Result>(_ keyPath: KeyPath<Value, Result>) -> Result {
    lock.withLock { value[keyPath: keyPath] }
  }
}

private struct RecordingDoctorProbe: ReadOnlyDoctorProbing {
  let calls = Locked<[DoctorProbeKind]>([])
  let writeAttempts = Locked(0)
  let materializationAttempts = Locked(0)
  let processLaunchAttempts = Locked(0)

  func observe(_ kind: DoctorProbeKind) -> DoctorObservation {
    calls.withLock { $0.append(kind) }
    let status: DoctorStatus
    switch kind {
    case .apfs: status = .unsupported
    case .fileProvider: status = .permissionDenied
    case .filesystemPermission: status = .unreadable
    default: status = .unavailable
    }
    return DoctorObservation(kind: kind, status: status, detailCode: "fixture")
  }
}

private struct MismatchedDoctorProbe: ReadOnlyDoctorProbing {
  func observe(_ kind: DoctorProbeKind) -> DoctorObservation {
    if kind == .effectiveUser {
      return DoctorObservation(kind: .apfs, status: .unavailable, detailCode: "wrong-kind")
    }
    return DoctorObservation(kind: kind, status: .unavailable, detailCode: "fixture")
  }
}
