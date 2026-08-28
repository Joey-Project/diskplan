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
  typealias Failure = @Sendable () throws -> Void

  private let lock = NSLock()
  private let clock: any OracleQuiescenceClock
  private let timeoutNanoseconds: UInt64
  private let appendEvent: Append
  private let recorderState: RecorderState
  private let poisonRecorder: Poison
  private let failRecorder: Failure
  private var poisoned = false

  init(
    append: @escaping Append,
    state: @escaping RecorderState = { _ in .healthy },
    poison: @escaping Poison = { _ in },
    failure: @escaping Failure = {},
    clock: any OracleQuiescenceClock = SystemOracleQuiescenceClock(),
    timeoutNanoseconds: UInt64 = 30_000_000_000
  ) {
    appendEvent = append
    recorderState = state
    poisonRecorder = poison
    failRecorder = failure
    self.clock = clock
    self.timeoutNanoseconds = timeoutNanoseconds
  }

  public convenience init(log: OracleLog) {
    self.init(
      append: { event, deadline in
        try log.append(
          event,
          injecting: nil,
          deadlineNanoseconds: deadline,
          clock: SystemOracleQuiescenceClock()
        )
      },
      state: { deadline in
        try log.recorderState(
          deadlineNanoseconds: deadline,
          clock: SystemOracleQuiescenceClock()
        )
      },
      poison: { deadline in
        try log.poisonRecorder(
          deadlineNanoseconds: deadline,
          clock: SystemOracleQuiescenceClock()
        )
      },
      failure: { try log.failRecorder() }
    )
  }

  public func record(_ event: OracleEvent) throws {
    do {
      try recordAttempt(event)
    } catch let error as OracleRecorderError where error == .sealed {
      throw error
    } catch {
      try failRecorder()
      throw error
    }
  }

  private func recordAttempt(_ event: OracleEvent) throws {
    let start = clock.nowNanoseconds()
    let (deadline, overflow) = start.addingReportingOverflow(timeoutNanoseconds)
    guard !overflow else { throw OracleRecorderError.lockTimedOut }
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
