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
  public typealias Append = @Sendable (OracleEvent) throws -> Void

  private let lock = NSLock()
  private let appendEvent: Append
  private let recorderState: @Sendable () throws -> OracleRecorderState
  private let poisonRecorder: @Sendable () throws -> Void
  private var poisoned = false

  public init(
    append: @escaping Append,
    state: @escaping @Sendable () throws -> OracleRecorderState = { .healthy },
    poison: @escaping @Sendable () throws -> Void = {}
  ) {
    appendEvent = append
    recorderState = state
    poisonRecorder = poison
  }

  public convenience init(log: OracleLog) {
    self.init(
      append: { event in try log.append(event) },
      state: { try log.recorderState() },
      poison: { try log.poisonRecorder() }
    )
  }

  public func record(_ event: OracleEvent) throws {
    lock.lock()
    defer { lock.unlock() }
    guard !poisoned else { throw OracleRecorderError.poisoned }
    switch try recorderState() {
    case .healthy:
      break
    case .poisoned:
      poisoned = true
      throw OracleRecorderError.poisoned
    case .sealed:
      throw OracleRecorderError.sealed
    }
    do {
      try appendEvent(event)
    } catch {
      poisoned = true
      try poisonRecorder()
      throw error
    }
  }
}

public enum CallbackCompletionSource: Equatable, Sendable {
  case callback
  case deadline
}

public final class OneShotCallbackGate: @unchecked Sendable {
  private let lock = NSLock()
  private var source: CallbackCompletionSource?

  public init() {}

  @discardableResult
  public func claimCompletion(from candidate: CallbackCompletionSource) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard source == nil else { return false }
    source = candidate
    return true
  }

  public var completionSource: CallbackCompletionSource? {
    lock.lock()
    defer { lock.unlock() }
    return source
  }
}
