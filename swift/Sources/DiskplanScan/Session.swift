import Foundation

public enum ScanControlKind: String, Equatable, Sendable {
  case started
  case advanced
  case paused
  case checkpointed
  case provisionalBuilt = "provisional_built"
  case resumed
  case finalizedPartial = "finalized_partial"
  case cancelled
  case completed
}

public struct ScanControlRecord: Equatable, Sendable {
  public let sequence: UInt64
  public let kind: ScanControlKind
  public let entriesObserved: UInt64
}

public struct ScanCheckpoint: Equatable, Sendable {
  public let result: ScanResult
  public let transcript: [ScanControlRecord]
  public let resumableInProcess: Bool
}

public enum ScanSessionState: String, Equatable, Sendable {
  case ready
  case running
  case paused
  case complete
  case finalizedPartial = "finalized_partial"
  case cancelled
}

public actor ScanSession {
  private let scanner: DeterministicScanner
  private var state: ScanSessionState = .ready
  private var sequence: UInt64 = 0
  private var transcript: [ScanControlRecord] = []

  public init(scanner: sending DeterministicScanner) { self.scanner = scanner }

  public func start() -> ScanCheckpoint {
    guard state == .ready else { return checkpointWithoutRecord() }
    state = .running
    record(.started)
    return checkpointWithoutRecord()
  }

  public func advance(maximumEntries: Int = 512) -> ScanCheckpoint {
    guard state == .running else { return checkpointWithoutRecord() }
    let result = scanner.advance(maximumEntries: maximumEntries)
    record(.advanced, result: result)
    if result.state == .complete {
      state = .complete
      record(.completed, result: result)
    } else if result.state == .partial {
      state = .finalizedPartial
      record(.finalizedPartial, result: result)
    }
    return checkpointWithoutRecord()
  }

  public func pause() -> ScanCheckpoint {
    guard state == .running else { return checkpointWithoutRecord() }
    state = .paused
    record(.paused)
    return checkpointWithoutRecord()
  }

  public func checkpoint() -> ScanCheckpoint {
    record(.checkpointed)
    return checkpointWithoutRecord()
  }

  public func provisional() -> ScanCheckpoint {
    guard state == .paused else { return checkpointWithoutRecord() }
    record(.provisionalBuilt)
    return checkpointWithoutRecord()
  }

  public func resume() -> ScanCheckpoint {
    guard state == .paused else { return checkpointWithoutRecord() }
    state = .running
    record(.resumed)
    return checkpointWithoutRecord()
  }

  public func finalizePartial() -> ScanCheckpoint {
    guard state == .running || state == .paused else { return checkpointWithoutRecord() }
    let result = scanner.finalizePartial()
    state = .finalizedPartial
    record(.finalizedPartial, result: result)
    return checkpointWithoutRecord()
  }

  public func cancel() -> ScanCheckpoint {
    guard state != .complete && state != .cancelled else { return checkpointWithoutRecord() }
    let result = scanner.cancel()
    state = .cancelled
    record(.cancelled, result: result)
    return checkpointWithoutRecord()
  }

  public func currentState() -> ScanSessionState { state }

  private func record(_ kind: ScanControlKind, result: ScanResult? = nil) {
    sequence += 1
    transcript.append(
      ScanControlRecord(
        sequence: sequence,
        kind: kind,
        entriesObserved: (result ?? scanner.snapshot()).progress.entriesObserved
      )
    )
  }

  private func checkpointWithoutRecord() -> ScanCheckpoint {
    ScanCheckpoint(
      result: scanner.snapshot(),
      transcript: transcript,
      resumableInProcess: state == .running || state == .paused
    )
  }
}
