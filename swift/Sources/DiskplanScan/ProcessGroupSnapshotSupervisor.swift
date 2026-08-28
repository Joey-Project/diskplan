import Darwin
import DiskplanMacOS
import Foundation

package enum ProcessGroupSnapshotSignal: Equatable, Sendable {
  case terminate
  case kill
}

package enum ProcessGroupSnapshotReapOutcome: Equatable, Sendable {
  case reaped(exitStatus: Int32)
  case failed(errorCode: Int32)
}

package protocol ProcessGroupSnapshotTimer: AnyObject, Sendable {
  func activate()
  func cancel()
}

/// Closed supervision seam shared by the production POSIX adapter and deterministic package tests.
/// Public process-snapshot callers cannot inject an alternate backend.
package protocol ProcessGroupSnapshotBackend: AnyObject, Sendable {
  var nowNanoseconds: UInt64 { get }

  func startReading(
    standardOutput: @escaping @Sendable (Data) -> Void,
    standardError: @escaping @Sendable (Data) -> Void
  )
  func startReaping(
    _ completion: @escaping @Sendable (ProcessGroupSnapshotReapOutcome) -> Void
  )
  func makeTimer(
    deadlineNanoseconds: UInt64,
    handler: @escaping @Sendable () -> Void
  ) -> any ProcessGroupSnapshotTimer
  /// Must be bounded and must not invoke installed reader or reap callbacks synchronously.
  func signalProcessGroup(_ signal: ProcessGroupSnapshotSignal)
  /// Must be bounded and must not invoke installed reader or reap callbacks synchronously.
  func processGroupExists() -> Bool
  func closeReaders()
}

package final class BoundedProcessGroupSnapshotState: ProcessSnapshotCancellationRequesting,
  @unchecked Sendable
{
  private enum Stream {
    case standardOutput
    case standardError
  }

  private enum CleanupTrigger {
    case deadline
    case outputLimit
    case cancellation
    case unexpectedResidualGroup
    case reapFailure
  }

  private struct TerminalClaim {
    let result: ProcessSnapshotExecution
    let timers: [any ProcessGroupSnapshotTimer]
  }

  private enum CompletionEvaluation {
    case none
    case beginUnexpectedResidualCleanup
    case complete(TerminalClaim)
  }

  package static let termGraceNanoseconds: UInt64 = 100_000_000
  package static let cleanupAllowanceNanoseconds: UInt64 = 500_000_000

  private let lock = NSLock()
  private let completion: @Sendable (ProcessSnapshotExecution) -> Void
  private let backend: any ProcessGroupSnapshotBackend
  private let executionDeadlineNanoseconds: UInt64
  private let maximumOutputBytes: Int
  private var standardOutput = Data()
  private var standardErrorByteCount = 0
  private var outputClosed = false
  private var errorClosed = false
  private var terminationStatus: Int32?
  private var reapFailureCode: Int32?
  private var cleanupTrigger: CleanupTrigger?
  private var cleanupGeneration: UInt64 = 0
  private var executionDeadlineTimer: (any ProcessGroupSnapshotTimer)?
  private var killTimer: (any ProcessGroupSnapshotTimer)?
  private var cleanupDeadlineTimer: (any ProcessGroupSnapshotTimer)?
  private var resumed = false

  package init(
    completion: @escaping @Sendable (ProcessSnapshotExecution) -> Void,
    backend: any ProcessGroupSnapshotBackend,
    executionDeadlineNanoseconds: UInt64,
    maximumOutputBytes: Int
  ) {
    precondition(maximumOutputBytes > 0)
    self.completion = completion
    self.backend = backend
    self.executionDeadlineNanoseconds = executionDeadlineNanoseconds
    self.maximumOutputBytes = maximumOutputBytes
  }

  package func start() {
    backend.startReading(
      standardOutput: { [weak self] in self?.receive($0, stream: .standardOutput) },
      standardError: { [weak self] in self?.receive($0, stream: .standardError) }
    )
    backend.startReaping { [weak self] in self?.processReaped($0) }

    // This timer is the supervisor's lifetime anchor. `finish` cancels and releases it.
    let timer = backend.makeTimer(deadlineNanoseconds: executionDeadlineNanoseconds) { [self] in
      beginCleanup(.deadline)
    }
    let installed = lock.withLock { () -> Bool in
      guard !resumed else { return false }
      executionDeadlineTimer = timer
      return true
    }
    guard installed else {
      timer.cancel()
      timer.activate()
      return
    }
    timer.activate()
  }

  package func requestCancellation() {
    beginCleanup(.cancellation)
  }

  private func receive(_ data: Data, stream: Stream) {
    var exceededLimit = false
    lock.withLock {
      guard !resumed else { return }
      if data.isEmpty {
        switch stream {
        case .standardOutput: outputClosed = true
        case .standardError: errorClosed = true
        }
      } else if cleanupTrigger == nil {
        let currentCount = standardOutput.count + standardErrorByteCount
        if data.count > maximumOutputBytes - min(currentCount, maximumOutputBytes) {
          exceededLimit = true
        } else {
          switch stream {
          case .standardOutput: standardOutput.append(data)
          case .standardError: standardErrorByteCount += data.count
          }
        }
      }
    }
    if exceededLimit { beginCleanup(.outputLimit) }
    evaluateCompletion()
  }

  private func processReaped(_ outcome: ProcessGroupSnapshotReapOutcome) {
    var shouldStartFailureCleanup = false
    lock.withLock {
      guard !resumed else { return }
      switch outcome {
      case .reaped(let exitStatus):
        terminationStatus = exitStatus
      case .failed(let errorCode):
        reapFailureCode = errorCode
        shouldStartFailureCleanup = cleanupTrigger == nil
      }
    }
    if shouldStartFailureCleanup { beginCleanup(.reapFailure) }
    evaluateCompletion()
  }

  private func evaluateCompletion() {
    let evaluation = lock.withLock { () -> CompletionEvaluation in
      guard !resumed, terminationStatus != nil || reapFailureCode != nil,
        outputClosed, errorClosed
      else { return .none }
      if backend.processGroupExists() {
        return cleanupTrigger == nil ? .beginUnexpectedResidualCleanup : .none
      }
      let result = self.result(
        trigger: cleanupTrigger,
        cleanup: ProcessSnapshotCleanupReport(residualProcessGroup: false),
        terminationStatus: terminationStatus ?? ECHILD
      )
      guard let terminal = claimTerminalLocked(result) else { return .none }
      return .complete(terminal)
    }
    switch evaluation {
    case .none:
      return
    case .beginUnexpectedResidualCleanup:
      beginCleanup(.unexpectedResidualGroup)
    case .complete(let terminal):
      complete(terminal)
    }
  }

  private func beginCleanup(_ trigger: CleanupTrigger) {
    let setup = lock.withLock { () -> (generation: UInt64, kill: UInt64, finish: UInt64)? in
      guard !resumed, cleanupTrigger == nil else { return nil }
      cleanupTrigger = trigger
      cleanupGeneration &+= 1
      let generation = cleanupGeneration
      let now = backend.nowNanoseconds
      let supervisorDeadline = Self.saturatingAdd(
        executionDeadlineNanoseconds,
        Self.cleanupAllowanceNanoseconds
      )
      let localDeadline = Self.saturatingAdd(now, Self.cleanupAllowanceNanoseconds)
      let finish = min(supervisorDeadline, localDeadline)
      backend.signalProcessGroup(.terminate)
      return (
        generation: generation,
        kill: min(Self.saturatingAdd(now, Self.termGraceNanoseconds), finish),
        finish: finish
      )
    }
    guard let setup else { return }

    let kill = backend.makeTimer(deadlineNanoseconds: setup.kill) { [weak self] in
      self?.signalKillAtGrace(generation: setup.generation)
    }
    let finish = backend.makeTimer(deadlineNanoseconds: setup.finish) { [weak self] in
      self?.finishCleanupAtHardDeadline(generation: setup.generation)
    }
    let installed = lock.withLock { () -> Bool in
      guard !resumed, cleanupGeneration == setup.generation else { return false }
      killTimer = kill
      cleanupDeadlineTimer = finish
      return true
    }
    guard installed else {
      kill.cancel()
      finish.cancel()
      kill.activate()
      finish.activate()
      return
    }
    kill.activate()
    finish.activate()
    evaluateCompletion()
  }

  private func signalKillAtGrace(generation: UInt64) {
    let sent = lock.withLock { () -> Bool in
      guard !resumed, cleanupGeneration == generation else { return false }
      backend.signalProcessGroup(.kill)
      return true
    }
    if sent { evaluateCompletion() }
  }

  private func finishCleanupAtHardDeadline(generation: UInt64) {
    let terminal = lock.withLock { () -> TerminalClaim? in
      guard !resumed, cleanupGeneration == generation else { return nil }
      backend.signalProcessGroup(.kill)
      let residual = backend.processGroupExists()
      let result = self.result(
        trigger: cleanupTrigger ?? .unexpectedResidualGroup,
        cleanup: ProcessSnapshotCleanupReport(residualProcessGroup: residual),
        terminationStatus: terminationStatus ?? ECHILD
      )
      return claimTerminalLocked(result)
    }
    if let terminal { complete(terminal) }
  }

  private func result(
    trigger: CleanupTrigger?,
    cleanup: ProcessSnapshotCleanupReport,
    terminationStatus: Int32
  ) -> ProcessSnapshotExecution {
    if let reapFailureCode {
      return .supervisionFailed(
        reason: "waitpid failed with POSIX error \(reapFailureCode)",
        errorCode: reapFailureCode,
        cleanup: cleanup
      )
    }
    switch trigger {
    case nil:
      return .completed(
        exitStatus: terminationStatus,
        standardOutput: standardOutput,
        standardError: ProcessStandardErrorSummary(
          observedByteCount: standardErrorByteCount
        )
      )
    case .deadline: return .deadlineExceeded(cleanup: cleanup)
    case .outputLimit: return .outputLimitExceeded(cleanup: cleanup)
    case .cancellation: return .cancelled(cleanup: cleanup)
    case .unexpectedResidualGroup:
      return .supervisionFailed(
        reason: "lsof exited while its process group remained active",
        errorCode: nil,
        cleanup: cleanup
      )
    case .reapFailure:
      return .supervisionFailed(
        reason: "waitpid failed without a POSIX error code",
        errorCode: nil,
        cleanup: cleanup
      )
    }
  }

  private func claimTerminalLocked(_ result: ProcessSnapshotExecution) -> TerminalClaim? {
    guard !resumed else { return nil }
    resumed = true
    let timers = [executionDeadlineTimer, killTimer, cleanupDeadlineTimer].compactMap { $0 }
    executionDeadlineTimer = nil
    killTimer = nil
    cleanupDeadlineTimer = nil
    return TerminalClaim(result: result, timers: timers)
  }

  private func complete(_ terminal: TerminalClaim) {
    for timer in terminal.timers { timer.cancel() }
    backend.closeReaders()
    completion(terminal.result)
  }

  private static func saturatingAdd(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
    let (value, overflow) = lhs.addingReportingOverflow(rhs)
    return overflow ? UInt64.max : value
  }
}

final class POSIXProcessGroupSnapshotBackend: ProcessGroupSnapshotBackend,
  @unchecked Sendable
{
  private let process: SpawnedPOSIXProcessGroup
  private let outputHandle: FileHandle
  private let errorHandle: FileHandle
  private let readerLock = NSLock()
  private var readersClosed = false

  init(process: SpawnedPOSIXProcessGroup) {
    self.process = process
    outputHandle = FileHandle(
      fileDescriptor: process.standardOutputFileDescriptor,
      closeOnDealloc: true
    )
    errorHandle = FileHandle(
      fileDescriptor: process.standardErrorFileDescriptor,
      closeOnDealloc: true
    )
  }

  var nowNanoseconds: UInt64 {
    DispatchTime.now().uptimeNanoseconds
  }

  func startReading(
    standardOutput: @escaping @Sendable (Data) -> Void,
    standardError: @escaping @Sendable (Data) -> Void
  ) {
    readerLock.withLock {
      guard !readersClosed else { return }
      outputHandle.readabilityHandler = { [weak self] handle in
        guard let self else { return }
        let data = readerLock.withLock { () -> Data? in
          guard !readersClosed else { return nil }
          let data = handle.availableData
          if data.isEmpty { handle.readabilityHandler = nil }
          return data
        }
        if let data { standardOutput(data) }
      }
      errorHandle.readabilityHandler = { [weak self] handle in
        guard let self else { return }
        let data = readerLock.withLock { () -> Data? in
          guard !readersClosed else { return nil }
          let data = handle.availableData
          if data.isEmpty { handle.readabilityHandler = nil }
          return data
        }
        if let data { standardError(data) }
      }
    }
  }

  func startReaping(
    _ completion: @escaping @Sendable (ProcessGroupSnapshotReapOutcome) -> Void
  ) {
    // The owned child must eventually be reaped; abandoning this wait can create a zombie. The
    // state supplies a weak completion, so a residual child does not retain the caller-visible
    // supervisor after its hard deadline.
    DispatchQueue.global(qos: .utility).async { [process] in
      var rawStatus: Int32 = 0
      var result: Int32
      repeat {
        result = waitpid(process.processID, &rawStatus, 0)
      } while result < 0 && errno == EINTR
      let errorCode = errno
      completion(
        Self.classifyWaitResult(
          processID: process.processID,
          waitResult: result,
          rawStatus: rawStatus,
          errorCode: errorCode
        )
      )
    }
  }

  func makeTimer(
    deadlineNanoseconds: UInt64,
    handler: @escaping @Sendable () -> Void
  ) -> any ProcessGroupSnapshotTimer {
    DispatchProcessGroupSnapshotTimer(
      deadlineNanoseconds: deadlineNanoseconds,
      handler: handler
    )
  }

  func signalProcessGroup(_ signal: ProcessGroupSnapshotSignal) {
    guard process.processID > 0 else { return }
    let rawSignal: Int32 = signal == .terminate ? SIGTERM : SIGKILL
    _ = Darwin.kill(-process.processID, rawSignal)
  }

  func processGroupExists() -> Bool {
    guard process.processID > 0 else { return false }
    if Darwin.kill(-process.processID, 0) == 0 { return true }
    return errno == EPERM
  }

  func closeReaders() {
    readerLock.withLock {
      guard !readersClosed else { return }
      readersClosed = true
      outputHandle.readabilityHandler = nil
      errorHandle.readabilityHandler = nil
      try? outputHandle.close()
      try? errorHandle.close()
    }
  }

  static func classifyWaitResult(
    processID: Int32,
    waitResult: Int32,
    rawStatus: Int32,
    errorCode: Int32
  ) -> ProcessGroupSnapshotReapOutcome {
    guard waitResult == processID else { return .failed(errorCode: errorCode) }
    return .reaped(exitStatus: decodeWaitStatus(rawStatus))
  }

  private static func decodeWaitStatus(_ status: Int32) -> Int32 {
    let signal = status & 0x7f
    return signal == 0 ? (status >> 8) & 0xff : signal
  }
}

private final class DispatchProcessGroupSnapshotTimer: ProcessGroupSnapshotTimer,
  @unchecked Sendable
{
  private let timer: DispatchSourceTimer

  init(
    deadlineNanoseconds: UInt64,
    handler: @escaping @Sendable () -> Void
  ) {
    timer = DispatchSource.makeTimerSource(queue: .global(qos: .utility))
    let now = DispatchTime.now().uptimeNanoseconds
    timer.schedule(
      deadline: deadlineNanoseconds > now
        ? DispatchTime(uptimeNanoseconds: deadlineNanoseconds) : .now()
    )
    timer.setEventHandler(handler: handler)
  }

  func activate() {
    timer.resume()
  }

  func cancel() {
    timer.cancel()
  }
}
