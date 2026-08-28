import Foundation

public enum OracleRecorderError: Error, Equatable, Sendable {
  case unavailable
  case poisoned
}

public final class OracleRecorder: @unchecked Sendable {
  public typealias Append = @Sendable (OracleEvent) throws -> Void

  private let lock = NSLock()
  private let appendEvent: Append
  private var poisoned = false

  public init(append: @escaping Append) {
    appendEvent = append
  }

  public convenience init(log: OracleLog) {
    self.init { event in try log.append(event) }
  }

  public func record(_ event: OracleEvent) throws {
    lock.lock()
    defer { lock.unlock() }
    guard !poisoned else { throw OracleRecorderError.poisoned }
    do {
      try appendEvent(event)
    } catch {
      poisoned = true
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
