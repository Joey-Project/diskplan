import Darwin
import DiskplanMacOS
import Foundation

public enum ProcessReferenceKind: String, Equatable, Hashable, Sendable {
  case openFile = "open_file"
  case currentWorkingDirectory = "current_working_directory"
  case mappedImage = "mapped_image"
  case other
}

public struct ProcessActivityRecord: Equatable, Hashable, Sendable, Comparable {
  public let processID: Int32
  public let command: String?
  public let fileDescriptor: String?
  public let rawPath: Data

  public init(processID: Int32, command: String?, fileDescriptor: String?, rawPath: Data) {
    self.processID = processID
    self.command = command
    self.fileDescriptor = fileDescriptor
    self.rawPath = rawPath
  }

  public var referenceKind: ProcessReferenceKind {
    switch fileDescriptor {
    case "cwd": .currentWorkingDirectory
    case "txt", "mem", "mmap", "ltx": .mappedImage
    case .some(let descriptor) where descriptor.isLsofHexMappedRegionDescriptor:
      .mappedImage
    case .some(let descriptor) where descriptor.utf8.first.map({ (48...57).contains($0) }) == true:
      .openFile
    default: .other
    }
  }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    if lhs.processID != rhs.processID { return lhs.processID < rhs.processID }
    if lhs.rawPath != rhs.rawPath { return lhs.rawPath.lexicographicallyPrecedes(rhs.rawPath) }
    if lhs.fileDescriptor != rhs.fileDescriptor {
      return (lhs.fileDescriptor ?? "") < (rhs.fileDescriptor ?? "")
    }
    return (lhs.command ?? "") < (rhs.command ?? "")
  }
}

public enum ProcessActivityObservation: Equatable, Sendable {
  case complete([ProcessActivityRecord])
  case degraded(records: [ProcessActivityRecord], reason: String)
  case absent(reason: String)
  case unknown(reason: String)
  case unreadable(reason: String, errorCode: Int32?)
  case failed(reason: String, errorCode: Int32?)

  public var positiveRecords: [ProcessActivityRecord] {
    switch self {
    case .complete(let records), .degraded(let records, _): records
    default: []
    }
  }

  public var hasCompleteCoverage: Bool {
    if case .complete = self { return true }
    return false
  }
}

public enum ProcessActivityCoverage: Equatable, Sendable {
  case complete
  case incomplete(reason: String)
}

extension String {
  fileprivate var isLsofHexMappedRegionDescriptor: Bool {
    let bytes = Array(utf8)
    guard bytes.count >= 2, bytes.first == UInt8(ascii: "M") else { return false }
    return bytes.dropFirst().allSatisfy { byte in
      (48...57).contains(byte) || (65...70).contains(byte) || (97...102).contains(byte)
    }
  }
}

public enum LsofFieldParser {
  public static func parse(_ data: Data) -> Observation<[ProcessActivityRecord]> {
    let fields = data.split(separator: 0, omittingEmptySubsequences: true)
    var processID: Int32?
    var command: String?
    var descriptor: String?
    var records: [ProcessActivityRecord] = []
    for rawField in fields {
      let field = rawField.drop { $0 == UInt8(ascii: "\n") || $0 == UInt8(ascii: "\r") }
      guard let tag = field.first else { continue }
      let value = field.dropFirst()
      switch tag {
      case UInt8(ascii: "p"):
        guard let text = String(data: value, encoding: .utf8), let parsed = Int32(text) else {
          return .failed(reason: "lsof emitted an invalid process identifier", errorCode: nil)
        }
        processID = parsed
        command = nil
        descriptor = nil
      case UInt8(ascii: "c"):
        command = String(data: value, encoding: .utf8)
      case UInt8(ascii: "f"):
        descriptor = String(data: value, encoding: .utf8)
      case UInt8(ascii: "n"):
        guard let processID else {
          return .failed(reason: "lsof path field preceded its process field", errorCode: nil)
        }
        records.append(
          ProcessActivityRecord(
            processID: processID,
            command: command,
            fileDescriptor: descriptor,
            rawPath: Data(value)
          )
        )
      default:
        continue
      }
    }
    return .known(Array(Set(records)).sorted())
  }
}

public struct ProcessActivityAncestorIndex: Equatable, Sendable {
  private let snapshot: ProcessActivityObservation

  public init(snapshot: Observation<[ProcessActivityRecord]>) {
    switch snapshot {
    case .known(let records): self.snapshot = .complete(records)
    case .absent(let reason): self.snapshot = .absent(reason: reason)
    case .unknown(let reason): self.snapshot = .unknown(reason: reason)
    case .unreadable(let reason, let errorCode):
      self.snapshot = .unreadable(reason: reason, errorCode: errorCode)
    case .failed(let reason, let errorCode):
      self.snapshot = .failed(reason: reason, errorCode: errorCode)
    }
  }

  public init(activity: ProcessActivityObservation) {
    snapshot = activity
  }

  public var coverage: ProcessActivityCoverage {
    switch snapshot {
    case .complete: return .complete
    case .degraded(_, let reason), .absent(let reason), .unknown(let reason):
      return .incomplete(reason: reason)
    case .unreadable(let reason, _), .failed(let reason, _):
      return .incomplete(reason: reason)
    }
  }

  /// Returns positive process references whose raw path is the candidate itself or a descendant.
  /// A known empty result is weak negative evidence only; callers must retain the snapshot coverage.
  public func references(
    toCandidateAt rawAbsolutePath: Data
  ) -> Observation<[ProcessActivityRecord]> {
    if case .degraded(_, let reason) = snapshot {
      switch positiveReferencesByCandidateAncestor(rawAbsolutePaths: [rawAbsolutePath]) {
      case .known(let references):
        guard let candidate = normalizedAbsolutePath(rawAbsolutePath) else {
          return .failed(
            reason: "candidate path is not a canonical absolute raw path", errorCode: EINVAL)
        }
        let matches = references[candidate] ?? []
        return matches.isEmpty ? .unknown(reason: reason) : .known(matches)
      case .absent(let reason): return .absent(reason: reason)
      case .unknown(let reason): return .unknown(reason: reason)
      case .unreadable(let reason, let errorCode):
        return .unreadable(reason: reason, errorCode: errorCode)
      case .failed(let reason, let errorCode):
        return .failed(reason: reason, errorCode: errorCode)
      }
    }
    switch referencesByCandidateAncestor(rawAbsolutePaths: [rawAbsolutePath]) {
    case .known(let references):
      guard let candidate = normalizedAbsolutePath(rawAbsolutePath) else {
        return .failed(
          reason: "candidate path is not a canonical absolute raw path", errorCode: EINVAL)
      }
      return .known(references[candidate] ?? [])
    case .absent(let reason): return .absent(reason: reason)
    case .unknown(let reason): return .unknown(reason: reason)
    case .unreadable(let reason, let errorCode):
      return .unreadable(reason: reason, errorCode: errorCode)
    case .failed(let reason, let errorCode):
      return .failed(reason: reason, errorCode: errorCode)
    }
  }

  /// Maps one frozen snapshot to all candidate ancestors in a single path-depth-bounded pass.
  /// Output keys are canonical raw absolute paths; known empty arrays remain weak negative evidence.
  public func referencesByCandidateAncestor(
    rawAbsolutePaths: [Data]
  ) -> Observation<[Data: [ProcessActivityRecord]]> {
    if case .degraded(_, let reason) = snapshot {
      switch positiveReferencesByCandidateAncestor(rawAbsolutePaths: rawAbsolutePaths) {
      case .known: return .unknown(reason: reason)
      case .absent(let reason): return .absent(reason: reason)
      case .unknown(let reason): return .unknown(reason: reason)
      case .unreadable(let reason, let errorCode):
        return .unreadable(reason: reason, errorCode: errorCode)
      case .failed(let reason, let errorCode):
        return .failed(reason: reason, errorCode: errorCode)
      }
    }
    return positiveReferencesByCandidateAncestor(rawAbsolutePaths: rawAbsolutePaths)
  }

  /// Returns positive matches without claiming that empty entries are negative evidence.
  /// Callers must inspect `coverage` before using any empty entry for staging or cleanup.
  public func positiveReferencesByCandidateAncestor(
    rawAbsolutePaths: [Data]
  ) -> Observation<[Data: [ProcessActivityRecord]]> {
    var references: [Data: [ProcessActivityRecord]] = [:]
    for rawPath in rawAbsolutePaths {
      guard let normalized = normalizedAbsolutePath(rawPath) else {
        return .failed(
          reason: "candidate path is not a canonical absolute raw path", errorCode: EINVAL)
      }
      references[normalized] = []
    }
    switch snapshot {
    case .complete(let records), .degraded(let records, _):
      for record in records.sorted() where record.referenceKind != .other {
        guard var ancestor = normalizedAbsolutePath(record.rawPath) else { continue }
        while true {
          if references[ancestor] != nil { references[ancestor, default: []].append(record) }
          guard ancestor.count > 1,
            let separator = ancestor.lastIndex(of: UInt8(ascii: "/"))
          else { break }
          ancestor =
            separator == ancestor.startIndex
            ? Data([UInt8(ascii: "/")]) : Data(ancestor[..<separator])
        }
      }
      for path in Array(references.keys) {
        references[path] = Array(Set(references[path] ?? [])).sorted()
      }
      return .known(references)
    case .absent(let reason): return .absent(reason: reason)
    case .unknown(let reason): return .unknown(reason: reason)
    case .unreadable(let reason, let errorCode):
      return .unreadable(reason: reason, errorCode: errorCode)
    case .failed(let reason, let errorCode):
      return .failed(reason: reason, errorCode: errorCode)
    }
  }

  private func normalizedAbsolutePath(_ path: Data) -> Data? {
    guard path.first == UInt8(ascii: "/"), !path.contains(0) else { return nil }
    var normalized = path
    while normalized.count > 1, normalized.last == UInt8(ascii: "/") {
      normalized.removeLast()
    }
    if normalized.count > 1 {
      let components = normalized.dropFirst().split(
        separator: UInt8(ascii: "/"),
        omittingEmptySubsequences: false
      )
      guard
        components.allSatisfy({ component in
          !component.isEmpty
            && !component.elementsEqual(Data(".".utf8))
            && !component.elementsEqual(Data("..".utf8))
        })
      else { return nil }
    }
    return normalized
  }

}

public protocol ProcessActivityCollecting: Sendable {
  /// Implementations run one bounded `lsof -nP -Di -F0pcfn` snapshot, never recursive per-path probes.
  func collect(deadlineNanoseconds: UInt64) async -> ProcessActivityObservation
}

public enum ProcessSnapshotGroupCleanupState: Equatable, Sendable {
  case quiescent
  case residual
  case observationFailed(errorCode: Int32)
}

public struct ProcessSnapshotCleanupReport: Equatable, Sendable {
  public let processGroupState: ProcessSnapshotGroupCleanupState

  public var residualProcessGroup: Bool {
    processGroupState == .residual
  }

  public init(residualProcessGroup: Bool) {
    processGroupState = residualProcessGroup ? .residual : .quiescent
  }

  public init(processGroupState: ProcessSnapshotGroupCleanupState) {
    self.processGroupState = processGroupState
  }
}

public struct ProcessStandardErrorSummary: Equatable, Sendable {
  public let observedByteCount: Int

  public init(observedByteCount: Int) {
    precondition(observedByteCount >= 0)
    self.observedByteCount = observedByteCount
  }

  public static let empty = Self(observedByteCount: 0)
}

public struct ProcessLaunchFailure: Equatable, Sendable {
  public let reason: String
  public let errorDomain: String
  public let errorCode: Int32?
  public let underlyingPOSIXErrorCode: Int32?

  public init(
    reason: String,
    errorDomain: String,
    errorCode: Int32?,
    underlyingPOSIXErrorCode: Int32?
  ) {
    self.reason = reason
    self.errorDomain = errorDomain
    self.errorCode = errorCode
    self.underlyingPOSIXErrorCode = underlyingPOSIXErrorCode
  }

  public init(error: any Error, operation: String) {
    let nsError = error as NSError
    reason = "\(operation): \(nsError.localizedDescription)"
    errorDomain = nsError.domain
    errorCode = Int32(exactly: nsError.code)
    underlyingPOSIXErrorCode = Self.findPOSIXErrorCode(nsError)
  }

  private static func findPOSIXErrorCode(_ error: NSError) -> Int32? {
    if error.domain == NSPOSIXErrorDomain, let code = Int32(exactly: error.code) {
      return code
    }
    guard let underlying = error.userInfo[NSUnderlyingErrorKey] as? NSError else { return nil }
    return findPOSIXErrorCode(underlying)
  }
}

public enum ProcessSnapshotExecution: Equatable, Sendable {
  case completed(
    exitStatus: Int32,
    standardOutput: Data,
    standardError: ProcessStandardErrorSummary
  )
  case deadlineExceeded(cleanup: ProcessSnapshotCleanupReport)
  case outputLimitExceeded(cleanup: ProcessSnapshotCleanupReport)
  case cancelled(cleanup: ProcessSnapshotCleanupReport)
  case supervisionFailed(
    reason: String,
    errorCode: Int32?,
    cleanup: ProcessSnapshotCleanupReport
  )
  case launchFailed(ProcessLaunchFailure)
}

public protocol ProcessSnapshotRunning: Sendable {
  func run(
    executableURL: URL,
    arguments: [String],
    environment: [String: String],
    deadlineNanoseconds: UInt64,
    maximumOutputBytes: Int
  ) async -> ProcessSnapshotExecution
}

public struct BoundedLsofProcessActivityCollector: ProcessActivityCollecting {
  public static let collectorID = "lsof-nP-Di-F0pcfn-v1"
  public static let sanitizedEnvironment = [
    "LANG": "C",
    "LC_ALL": "C",
    "PATH": "/usr/bin:/bin:/usr/sbin:/sbin",
  ]

  private let executableURL: URL
  private let runner: any ProcessSnapshotRunning
  private let maximumOutputBytes: Int

  public init(maximumOutputBytes: Int = 64 * 1_024 * 1_024) {
    precondition(maximumOutputBytes > 0)
    executableURL = URL(fileURLWithPath: "/usr/sbin/lsof")
    runner = FoundationProcessSnapshotRunner()
    self.maximumOutputBytes = maximumOutputBytes
  }

  package init(
    executableURL: URL,
    runner: any ProcessSnapshotRunning,
    maximumOutputBytes: Int = 64 * 1_024 * 1_024
  ) {
    precondition(maximumOutputBytes > 0)
    self.executableURL = executableURL
    self.runner = runner
    self.maximumOutputBytes = maximumOutputBytes
  }

  public func collect(deadlineNanoseconds: UInt64) async -> ProcessActivityObservation {
    let execution = await runner.run(
      executableURL: executableURL,
      arguments: ["-nP", "-Di", "-F0pcfn"],
      environment: Self.sanitizedEnvironment,
      deadlineNanoseconds: deadlineNanoseconds,
      maximumOutputBytes: maximumOutputBytes
    )
    switch execution {
    case .completed(let status, let output, let error):
      guard status == 0 else {
        return .failed(
          reason: processFailureReason(status: status, standardError: error),
          errorCode: nil
        )
      }
      switch LsofFieldParser.parse(output) {
      case .known(let records):
        if error.observedByteCount == 0 { return .complete(records) }
        return .degraded(records: records, reason: standardErrorSummary(error))
      case .absent(let reason): return .absent(reason: reason)
      case .unknown(let reason): return .unknown(reason: reason)
      case .unreadable(let reason, let errorCode):
        return .unreadable(reason: reason, errorCode: errorCode)
      case .failed(let reason, let errorCode):
        return .failed(reason: reason, errorCode: errorCode)
      }
    case .deadlineExceeded(let cleanup):
      return .failed(
        reason: cleanupReason(
          "bounded lsof process snapshot timed out", cleanup: cleanup),
        errorCode: ETIMEDOUT
      )
    case .outputLimitExceeded(let cleanup):
      return .failed(
        reason: cleanupReason(
          "bounded lsof process snapshot exceeded its output limit", cleanup: cleanup),
        errorCode: EFBIG
      )
    case .cancelled(let cleanup):
      return .failed(
        reason: cleanupReason(
          "bounded lsof process snapshot was cancelled", cleanup: cleanup),
        errorCode: ECANCELED
      )
    case .supervisionFailed(let reason, let errorCode, let cleanup):
      return .failed(
        reason: cleanupReason(reason, cleanup: cleanup),
        errorCode: errorCode ?? ECHILD
      )
    case .launchFailed(let failure):
      switch failure.underlyingPOSIXErrorCode {
      case ENOENT:
        return .absent(reason: failure.reason)
      case EACCES, EPERM:
        return .unreadable(
          reason: failure.reason,
          errorCode: failure.underlyingPOSIXErrorCode
        )
      default:
        return .failed(reason: failure.reason, errorCode: failure.underlyingPOSIXErrorCode)
      }
    }
  }

  private func cleanupReason(
    _ reason: String,
    cleanup: ProcessSnapshotCleanupReport
  ) -> String {
    switch cleanup.processGroupState {
    case .quiescent:
      return reason
    case .residual:
      return "\(reason); residual process group remains"
    case .observationFailed:
      return "\(reason); process-group quiescence was not verified"
    }
  }

  private func processFailureReason(
    status: Int32,
    standardError: ProcessStandardErrorSummary
  ) -> String {
    guard standardError.observedByteCount > 0 else { return "lsof exited with status \(status)" }
    return "lsof exited with status \(status); \(standardErrorSummary(standardError))"
  }

  private func standardErrorSummary(_ standardError: ProcessStandardErrorSummary) -> String {
    let retainedCount = min(standardError.observedByteCount, 4_096)
    let suffix = standardError.observedByteCount > retainedCount ? ", truncated" : ""
    return
      "standard error contained \(retainedCount) bytes\(suffix); diagnostic content withheld"
  }
}

public struct FoundationProcessSnapshotRunner: ProcessSnapshotRunning {
  private let spawner: POSIXProcessGroupSpawner

  public init() {
    spawner = POSIXProcessGroupSpawner()
  }

  public func run(
    executableURL: URL,
    arguments: [String],
    environment: [String: String],
    deadlineNanoseconds: UInt64,
    maximumOutputBytes: Int
  ) async -> ProcessSnapshotExecution {
    precondition(maximumOutputBytes > 0)
    if Task.isCancelled {
      return .cancelled(cleanup: ProcessSnapshotCleanupReport(residualProcessGroup: false))
    }
    if deadlineNanoseconds <= DispatchTime.now().uptimeNanoseconds {
      return .deadlineExceeded(
        cleanup: ProcessSnapshotCleanupReport(residualProcessGroup: false)
      )
    }
    let cancellation = ProcessSnapshotCancellationRelay()
    return await withTaskCancellationHandler {
      await withCheckedContinuation { continuation in
        do {
          let process = try spawner.spawn(
            executableURL: executableURL,
            arguments: arguments,
            environment: environment
          )
          let state = BoundedProcessGroupSnapshotState(
            completion: { continuation.resume(returning: $0) },
            backend: POSIXProcessGroupSnapshotBackend(process: process),
            executionDeadlineNanoseconds: deadlineNanoseconds,
            maximumOutputBytes: maximumOutputBytes
          )
          state.start()
          cancellation.install(state)
        } catch {
          let result: ProcessSnapshotExecution =
            Task.isCancelled
            ? .cancelled(
              cleanup: ProcessSnapshotCleanupReport(residualProcessGroup: false)
            )
            : .launchFailed(ProcessLaunchFailure(error: error, operation: "failed to launch lsof"))
          continuation.resume(returning: result)
        }
      }
    } onCancel: {
      cancellation.cancel()
    }
  }
}

protocol ProcessSnapshotCancellationRequesting: AnyObject, Sendable {
  func requestCancellation()
}

private final class ProcessSnapshotCancellationRelay: @unchecked Sendable {
  private let lock = NSLock()
  private weak var target: (any ProcessSnapshotCancellationRequesting)?
  private var cancellationRequested = false

  func install(_ target: any ProcessSnapshotCancellationRequesting) {
    let shouldCancel = lock.withLock {
      self.target = target
      return cancellationRequested
    }
    if shouldCancel { target.requestCancellation() }
  }

  func cancel() {
    let installedTarget = lock.withLock {
      cancellationRequested = true
      return self.target
    }
    installedTarget?.requestCancellation()
  }
}

public struct UnavailableProcessActivityCollector: ProcessActivityCollecting {
  public init() {}
  public func collect(deadlineNanoseconds: UInt64) async -> ProcessActivityObservation {
    .unknown(reason: "bounded process snapshot collector is unavailable")
  }
}
