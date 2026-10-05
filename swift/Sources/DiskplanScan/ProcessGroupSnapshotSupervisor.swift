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

package enum ProcessGroupSnapshotLiveness: Equatable, Sendable {
  case live
  case absent
  case failed(errorCode: Int32)
}

package enum ProcessGroupMemberBufferPlan: Equatable, Sendable {
  case allocate(pidCount: Int)
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
  func processGroupLiveness() -> ProcessGroupSnapshotLiveness
  /// Releases the owned leader generation only after the terminal claim prevents more PGID use.
  func releaseProcessGroupIdentity()
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
    case livenessFailure
  }

  private struct TerminalClaim {
    let result: ProcessSnapshotExecution
    let timers: [any ProcessGroupSnapshotTimer]
  }

  private enum CompletionEvaluation {
    case none
    case beginUnexpectedResidualCleanup
    case beginLivenessFailureCleanup
    case complete(TerminalClaim)
  }

  package static let termGraceNanoseconds: UInt64 = 100_000_000
  package static let cleanupAllowanceNanoseconds: UInt64 = 500_000_000
  package static let postKillQuiescenceNanoseconds: UInt64 = 100_000_000

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
  private var livenessFailureCode: Int32?
  private var cleanupTrigger: CleanupTrigger?
  private var cleanupGeneration: UInt64 = 0
  private var executionDeadlineTimer: (any ProcessGroupSnapshotTimer)?
  private var killTimer: (any ProcessGroupSnapshotTimer)?
  private var cleanupDeadlineTimer: (any ProcessGroupSnapshotTimer)?
  private var killSentAtNanoseconds: UInt64?
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
      switch backend.processGroupLiveness() {
      case .live:
        return cleanupTrigger == nil ? .beginUnexpectedResidualCleanup : .none
      case .failed(let errorCode):
        if livenessFailureCode == nil { livenessFailureCode = errorCode }
        return cleanupTrigger == nil ? .beginLivenessFailureCleanup : .none
      case .absent:
        break
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
    case .beginLivenessFailureCleanup:
      beginCleanup(.livenessFailure)
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
      guard !resumed, cleanupGeneration == generation, killSentAtNanoseconds == nil else {
        return false
      }
      backend.signalProcessGroup(.kill)
      killSentAtNanoseconds = backend.nowNanoseconds
      return true
    }
    if sent { evaluateCompletion() }
  }

  private func finishCleanupAtHardDeadline(generation: UInt64) {
    var followupTimer: (any ProcessGroupSnapshotTimer)?
    let terminal = lock.withLock { () -> TerminalClaim? in
      guard !resumed, cleanupGeneration == generation else { return nil }
      if killSentAtNanoseconds == nil {
        backend.signalProcessGroup(.kill)
        killSentAtNanoseconds = backend.nowNanoseconds
      }
      let now = backend.nowNanoseconds
      let quiescenceDeadline = Self.saturatingAdd(
        killSentAtNanoseconds ?? now,
        Self.postKillQuiescenceNanoseconds
      )
      let liveness = backend.processGroupLiveness()
      if liveness == .live, now < quiescenceDeadline {
        let timer = backend.makeTimer(deadlineNanoseconds: quiescenceDeadline) { [weak self] in
          self?.finishCleanupAtHardDeadline(generation: generation)
        }
        cleanupDeadlineTimer = timer
        followupTimer = timer
        return nil
      }
      let processGroupState: ProcessSnapshotGroupCleanupState
      let effectiveTrigger: CleanupTrigger
      switch liveness {
      case .absent:
        processGroupState = .quiescent
        effectiveTrigger = cleanupTrigger ?? .unexpectedResidualGroup
      case .live:
        processGroupState = .residual
        effectiveTrigger = cleanupTrigger ?? .unexpectedResidualGroup
      case .failed(let errorCode):
        if livenessFailureCode == nil { livenessFailureCode = errorCode }
        processGroupState = .observationFailed(errorCode: errorCode)
        effectiveTrigger = .livenessFailure
      }
      let result = self.result(
        trigger: effectiveTrigger,
        cleanup: ProcessSnapshotCleanupReport(processGroupState: processGroupState),
        terminationStatus: terminationStatus ?? ECHILD
      )
      return claimTerminalLocked(result)
    }
    followupTimer?.activate()
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
    if let livenessFailureCode {
      return .supervisionFailed(
        reason: "process-group liveness check failed with POSIX error \(livenessFailureCode)",
        errorCode: livenessFailureCode,
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
    case .livenessFailure:
      return .supervisionFailed(
        reason: "process-group liveness check failed without a POSIX error code",
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
    backend.releaseProcessGroupIdentity()
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
  private let leaderRelease = ProcessGroupLeaderReleaseGate()
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
    // `WNOWAIT` observes exit without reaping the process-group leader. Retaining that exact child
    // generation prevents its numeric PID/PGID from being reused while cleanup may still signal or
    // query the group. The terminal claim releases the leader for the final blocking reap only after
    // every timer has lost signal authority.
    DispatchQueue.global(qos: .utility).async { [process, leaderRelease] in
      var information = siginfo_t()
      var result: Int32
      repeat {
        result = waitid(P_PID, id_t(process.processID), &information, WEXITED | WNOWAIT)
      } while result < 0 && errno == EINTR
      let errorCode = errno
      if result == 0, information.si_pid == process.processID {
        leaderRelease.markExitObserved()
      } else {
        leaderRelease.markIdentityLost(errorCode: errorCode == 0 ? ECHILD : errorCode)
      }
      completion(
        Self.classifyWaitIDResult(
          processID: process.processID,
          waitIDResult: result,
          observedProcessID: information.si_pid,
          observedStatus: information.si_status,
          errorCode: errorCode
        )
      )
      leaderRelease.waitUntilReleased()
      Self.reapReleasedLeader(processID: process.processID)
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
    leaderRelease.withSignalAuthority {
      _ = Darwin.kill(-process.processID, rawSignal)
    }
  }

  func processGroupLiveness() -> ProcessGroupSnapshotLiveness {
    guard process.processID > 0 else { return .absent }
    return leaderRelease.withLivenessAuthority { observation in
      switch observation {
      case .exitObserved:
        return Self.classifyHeldLeaderProcessGroup(
          processGroupID: process.processID,
          leaderProcessID: process.processID
        )
      case .active:
        let result = Darwin.kill(-process.processID, 0)
        return Self.classifyGroupLiveness(killResult: result, errorCode: errno)
      case .identityLost:
        preconditionFailure("identity loss is rejected by the authority gate")
      }
    }
  }

  func releaseProcessGroupIdentity() {
    leaderRelease.release()
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

  static func classifyWaitIDResult(
    processID: Int32,
    waitIDResult: Int32,
    observedProcessID: pid_t,
    observedStatus: Int32,
    errorCode: Int32
  ) -> ProcessGroupSnapshotReapOutcome {
    guard waitIDResult == 0, observedProcessID == processID else {
      return .failed(errorCode: errorCode == 0 ? ECHILD : errorCode)
    }
    return .reaped(exitStatus: observedStatus)
  }

  static func classifyGroupLiveness(
    killResult: Int32,
    errorCode: Int32
  ) -> ProcessGroupSnapshotLiveness {
    if killResult == 0 { return .live }
    switch errorCode {
    case ESRCH: return .absent
    case EPERM: return .live
    default: return .failed(errorCode: errorCode)
    }
  }

  private static func classifyHeldLeaderProcessGroup(
    processGroupID: Int32,
    leaderProcessID: Int32
  ) -> ProcessGroupSnapshotLiveness {
    errno = 0
    let requiredPIDCount = Int(proc_listpgrppids(processGroupID, nil, 0))
    let probeErrorCode = errno
    let bufferPIDCount: Int
    switch groupMemberBufferPlan(
      requiredPIDCount: requiredPIDCount,
      errorCode: probeErrorCode
    ) {
    case .allocate(let pidCount):
      bufferPIDCount = pidCount
    case .failed(let errorCode):
      return .failed(errorCode: errorCode)
    }
    var members = [pid_t](repeating: 0, count: bufferPIDCount)
    errno = 0
    let returnedCount = members.withUnsafeMutableBytes { buffer in
      Int(proc_listpgrppids(processGroupID, buffer.baseAddress, Int32(buffer.count)))
    }
    let enumerationErrorCode = errno
    return classifyGroupMembers(
      members,
      returnedCount: returnedCount,
      bufferPIDCount: bufferPIDCount,
      errorCode: enumerationErrorCode,
      leaderProcessID: leaderProcessID
    )
  }

  static func groupMemberBufferPlan(
    requiredPIDCount: Int,
    errorCode: Int32
  ) -> ProcessGroupMemberBufferPlan {
    let maximumPIDCount = 4_096
    let sparePIDCount = 64
    if requiredPIDCount < 0 || (requiredPIDCount == 0 && errorCode != 0) {
      return .failed(errorCode: errorCode == 0 ? EIO : errorCode)
    }
    guard requiredPIDCount <= maximumPIDCount else {
      return .failed(errorCode: EOVERFLOW)
    }
    return .allocate(
      pidCount: min(
        maximumPIDCount,
        max(sparePIDCount, requiredPIDCount + sparePIDCount)
      )
    )
  }

  static func classifyGroupMembers(
    _ members: [pid_t],
    returnedCount: Int,
    bufferPIDCount: Int,
    errorCode: Int32,
    leaderProcessID: Int32
  ) -> ProcessGroupSnapshotLiveness {
    if returnedCount < 0 || (returnedCount == 0 && errorCode != 0) {
      return .failed(errorCode: errorCode == 0 ? EIO : errorCode)
    }
    guard returnedCount < bufferPIDCount, returnedCount <= members.count else {
      return .failed(errorCode: EOVERFLOW)
    }
    return members.prefix(returnedCount).contains(where: { member in
      member > 0 && member != leaderProcessID
    }) ? .live : .absent
  }

  private static func reapReleasedLeader(processID: Int32) {
    var rawStatus: Int32 = 0
    var result: Int32
    repeat {
      result = waitpid(processID, &rawStatus, 0)
    } while result < 0 && errno == EINTR
  }
}

private final class ProcessGroupLeaderReleaseGate: @unchecked Sendable {
  enum Observation {
    case active
    case exitObserved
    case identityLost(errorCode: Int32)
  }

  private let condition = NSCondition()
  private var released = false
  private var storedObservation = Observation.active

  func markExitObserved() {
    condition.withLock { storedObservation = .exitObserved }
  }

  func markIdentityLost(errorCode: Int32) {
    condition.withLock { storedObservation = .identityLost(errorCode: errorCode) }
  }

  func withSignalAuthority(_ operation: () -> Void) {
    condition.lock()
    defer { condition.unlock() }
    guard !released else { return }
    if case .identityLost = storedObservation { return }
    operation()
  }

  func withLivenessAuthority(
    _ operation: (Observation) -> ProcessGroupSnapshotLiveness
  ) -> ProcessGroupSnapshotLiveness {
    condition.lock()
    defer { condition.unlock() }
    guard !released else { return .failed(errorCode: ECHILD) }
    if case .identityLost(let errorCode) = storedObservation {
      return .failed(errorCode: errorCode)
    }
    return operation(storedObservation)
  }

  func release() {
    condition.lock()
    released = true
    condition.broadcast()
    condition.unlock()
  }

  func waitUntilReleased() {
    condition.lock()
    while !released { condition.wait() }
    condition.unlock()
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
