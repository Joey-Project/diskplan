import Foundation

public enum OracleRecorderError: Error, Equatable, Sendable {
  case unavailable
  case poisoned
  case sealed
  case lockTimedOut
}

enum OracleAppendInjectedFailure: Error, Equatable {
  case poisonStorage
  case eventStorage
}

public enum OracleRecorderState: Equatable, Sendable {
  case healthy
  case poisoned
  case sealed
}

public final class OracleRecorder: @unchecked Sendable {
  typealias Append = @Sendable (OracleEvent, UInt64) throws -> Void
  typealias RecorderState = @Sendable (UInt64) throws -> OracleRecorderState
  typealias Poison = @Sendable (UInt64) throws -> Void
  typealias Failure = @Sendable (UInt64) throws -> Void
  typealias BeginAttempt = @Sendable (UInt64) throws -> OracleRecordAttempt?

  private let lock = NSLock()
  private let clock: any OracleQuiescenceClock
  private let timeoutNanoseconds: UInt64
  private let appendEvent: Append
  private let recorderState: RecorderState
  private let poisonRecorder: Poison
  private let failRecorder: Failure
  private let beginAttempt: BeginAttempt
  private var poisoned = false

  init(
    append: @escaping Append,
    state: @escaping RecorderState = { _ in .healthy },
    poison: @escaping Poison = { _ in },
    failure: @escaping Failure = { _ in },
    beginAttempt: @escaping BeginAttempt = { _ in nil },
    clock: any OracleQuiescenceClock = SystemOracleQuiescenceClock(),
    timeoutNanoseconds: UInt64 = 30_000_000_000
  ) {
    appendEvent = append
    recorderState = state
    poisonRecorder = poison
    failRecorder = failure
    self.beginAttempt = beginAttempt
    self.clock = clock
    self.timeoutNanoseconds = timeoutNanoseconds
  }

  public convenience init(log: OracleLog) throws {
    let admission = try log.makeAdmissionChannel()
    self.init(
      append: { event, deadline in
        try admission.append(
          log: log,
          event,
          deadlineNanoseconds: deadline
        )
      },
      state: { deadline in
        try admission.recorderState(log: log, deadlineNanoseconds: deadline)
      },
      poison: { deadline in
        try admission.poison(log: log, deadlineNanoseconds: deadline)
      },
      failure: { deadline in
        try admission.fail(log: log, deadlineNanoseconds: deadline)
      },
      beginAttempt: { deadline in
        try admission.beginRecordAttempt(
          deadlineNanoseconds: deadline,
          clock: SystemOracleQuiescenceClock()
        )
      }
    )
  }

  public func record(_ event: OracleEvent) throws {
    try record { event }
  }

  public func record(_ makeEvent: @Sendable () -> OracleEvent) throws {
    let start = clock.nowNanoseconds()
    let (deadline, overflow) = start.addingReportingOverflow(timeoutNanoseconds)
    guard !overflow else {
      throw OracleRecorderError.lockTimedOut
    }
    let attempt: OracleRecordAttempt?
    do {
      attempt = try beginAttempt(deadline)
    } catch let error as OracleRecorderError where error == .sealed {
      throw error
    } catch {
      _ = try? publishFailureBounded(deadlineNanoseconds: deadline)
      throw error
    }
    defer { attempt?.finish() }
    do {
      try recordAttempt(makeEvent(), deadlineNanoseconds: deadline)
      try attempt?.resolve()
    } catch let error as OracleRecorderError where error == .sealed {
      try attempt?.resolve()
      throw error
    } catch {
      do {
        try publishFailureBounded(deadlineNanoseconds: deadline)
        try attempt?.resolve()
      } catch {
        // The durable admission/incomplete-attempt evidence remains unresolved.
      }
      throw error
    }
  }

  private func publishFailureBounded(deadlineNanoseconds deadline: UInt64) throws {
    try requireBeforeDeadline(deadline)
    let semaphore = DispatchSemaphore(value: 0)
    let result = LockedFailureResult()
    Thread.detachNewThread { [failRecorder] in
      do {
        try failRecorder(deadline)
        result.store(.success(()))
      } catch {
        result.store(.failure(error))
      }
      semaphore.signal()
    }
    while semaphore.wait(timeout: .now()) != .success {
      try requireBeforeDeadline(deadline)
      clock.sleepForPoll()
    }
    try requireBeforeDeadline(deadline)
    try result.get().get()
  }

  private func recordAttempt(_ event: OracleEvent, deadlineNanoseconds deadline: UInt64) throws {
    try acquireLocalLock(deadlineNanoseconds: deadline)
    defer { lock.unlock() }
    guard !poisoned else { throw OracleRecorderError.poisoned }
    try requireBeforeDeadline(deadline)
    let state = try recorderState(deadline)
    try requireBeforeDeadline(deadline)
    switch state {
    case .healthy:
      break
    case .poisoned:
      poisoned = true
      throw OracleRecorderError.poisoned
    case .sealed:
      throw OracleRecorderError.sealed
    }
    do {
      try requireBeforeDeadline(deadline)
      try appendEvent(event, deadline)
      try requireBeforeDeadline(deadline)
    } catch let error as OracleRecorderError where error == .sealed || error == .poisoned {
      if error == .poisoned { poisoned = true }
      throw error
    } catch {
      poisoned = true
      try requireBeforeDeadline(deadline)
      try poisonRecorder(deadline)
      try requireBeforeDeadline(deadline)
      throw error
    }
  }

  private func acquireLocalLock(deadlineNanoseconds: UInt64) throws {
    while true {
      try requireBeforeDeadline(deadlineNanoseconds)
      if lock.try() {
        do {
          try requireBeforeDeadline(deadlineNanoseconds)
          return
        } catch {
          lock.unlock()
          throw error
        }
      }
      clock.sleepForPoll()
    }
  }

  private func requireBeforeDeadline(_ deadlineNanoseconds: UInt64) throws {
    guard clock.nowNanoseconds() < deadlineNanoseconds else {
      throw OracleRecorderError.lockTimedOut
    }
  }
}

private final class LockedFailureResult: @unchecked Sendable {
  private let lock = NSLock()
  private var value: Result<Void, Error>?

  func store(_ value: Result<Void, Error>) { lock.withLock { self.value = value } }

  func get() throws -> Result<Void, Error> {
    try lock.withLock {
      guard let value else { throw OracleRecorderError.unavailable }
      return value
    }
  }
}

public enum CallbackCompletionSource: Equatable, Sendable {
  case callback
  case deadline
}

public final class OneShotCallbackGate: @unchecked Sendable {
  private let lock = NSLock()
  private let clock = ContinuousClock()
  private let deadline: ContinuousClock.Instant
  private var source: CallbackCompletionSource?

  public init(deadline: ContinuousClock.Instant) {
    self.deadline = deadline
  }

  @discardableResult
  public func claimDeadline() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard source == nil else { return false }
    source = .deadline
    return true
  }

  public func claimCallback() -> CallbackCompletionSource? {
    lock.lock()
    defer { lock.unlock() }
    guard source == nil else { return nil }
    let candidate: CallbackCompletionSource = clock.now < deadline ? .callback : .deadline
    source = candidate
    return candidate
  }

  public var completionSource: CallbackCompletionSource? {
    lock.lock()
    defer { lock.unlock() }
    return source
  }
}
