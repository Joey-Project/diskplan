import DiskplanCore
import DiskplanProto
import Foundation
import SwiftProtobuf

enum EventBrokerError: Error, Equatable {
  case closed
  case outputFailed(String)
}

enum BrokerRuntimeBatchPreparationError: Error {
  case semanticCapacityExceeded
  case eventSequenceExhausted
  case serializationFailed(String)
}

struct BrokerRuntimeRecord: Sendable {
  let requestID: UInt64
  let runtimeSessionID: Data
  let body: Diskplan_V1_RuntimeEvent.OneOf_Body
}

private enum PendingOutput: @unchecked Sendable {
  case envelope(sequence: UInt64, body: Diskplan_V1_Envelope.OneOf_Body)
  case event(
    requestID: UInt64,
    scanSessionID: String,
    body: Diskplan_V1_EngineEvent.OneOf_Body,
    telemetry: Bool,
    writeAcknowledgement: BrokerWriteAcknowledgement?
  )
  case runtimeEvent(
    requestID: UInt64,
    runtimeSessionID: Data,
    body: Diskplan_V1_RuntimeEvent.OneOf_Body
  )
  case serializedRuntimeBatch([Data], BrokerWriteAcknowledgement)

  var isTelemetry: Bool {
    if case .event(_, _, _, let telemetry, _) = self { return telemetry }
    return false
  }

  var writeAcknowledgement: BrokerWriteAcknowledgement? {
    switch self {
    case .event(_, _, _, _, let acknowledgement): acknowledgement
    case .serializedRuntimeBatch(_, let acknowledgement): acknowledgement
    default: nil
    }
  }

  var semanticWeight: Int {
    switch self {
    case .serializedRuntimeBatch(let envelopes, _): envelopes.count
    case .envelope, .event, .runtimeEvent: 1
    }
  }
}

private final class BrokerWriteAcknowledgement: @unchecked Sendable {
  private let condition = NSCondition()
  private var result: Result<Void, EventBrokerError>?

  func resolve(_ result: Result<Void, EventBrokerError>) {
    condition.lock()
    guard self.result == nil else {
      condition.unlock()
      return
    }
    self.result = result
    condition.broadcast()
    condition.unlock()
  }

  func wait() throws {
    condition.lock()
    while result == nil { condition.wait() }
    let result = self.result!
    condition.unlock()
    try result.get()
  }
}

/// The sole post-handshake stdout writer. Semantic events block at a finite
/// queue boundary; only a contiguous pending telemetry run may be replaced.
final class SerialEventBroker: @unchecked Sendable {
  typealias Writer = @Sendable (Data) throws -> Void

  private let condition = NSCondition()
  private let semanticCapacity: Int
  private let writer: Writer
  private var pending: [PendingOutput] = []
  private var semanticCount = 0
  private var inFlightCount = 0
  private var closing = false
  private var finished = false
  private var failure: EventBrokerError?
  private var nextEventSequence: UInt64 = 1

  init(
    semanticCapacity: Int = 128,
    writer: @escaping Writer
  ) {
    precondition(semanticCapacity > 0)
    self.semanticCapacity = semanticCapacity
    self.writer = writer
    Thread { [self] in drain() }.start()
  }

  convenience init(
    output: FileHandle,
    semanticCapacity: Int = 128
  ) {
    self.init(semanticCapacity: semanticCapacity) { data in
      try FrameCodec.write(data, to: output)
    }
  }

  func sendEnvelope(
    sequence: UInt64,
    body: Diskplan_V1_Envelope.OneOf_Body
  ) throws {
    try enqueue(.envelope(sequence: sequence, body: body), semantic: true)
  }

  func sendSemantic(
    requestID: UInt64,
    scanSessionID: String = "",
    body: Diskplan_V1_EngineEvent.OneOf_Body
  ) throws {
    try enqueue(
      .event(
        requestID: requestID,
        scanSessionID: scanSessionID,
        body: body,
        telemetry: false,
        writeAcknowledgement: nil
      ),
      semantic: true
    )
  }

  func sendRuntime(
    requestID: UInt64,
    runtimeSessionID: Data,
    body: Diskplan_V1_RuntimeEvent.OneOf_Body
  ) throws {
    try enqueue(
      .runtimeEvent(
        requestID: requestID,
        runtimeSessionID: runtimeSessionID,
        body: body
      ),
      semantic: true
    )
  }

  /// Enqueues a prevalidated mirrored runtime emission as one queue item and
  /// waits for the writer to process every contained envelope. A writer error
  /// may leave a physical prefix on a transport that is immediately failed
  /// and closed, but the shared acknowledgement never reports success.
  func sendRuntimeBatchAwaitingWrite(_ records: [BrokerRuntimeRecord]) throws {
    guard !records.isEmpty, records.count <= semanticCapacity else {
      throw BrokerRuntimeBatchPreparationError.semanticCapacityExceeded
    }
    let acknowledgement = BrokerWriteAcknowledgement()
    condition.lock()
    while (!pending.isEmpty || inFlightCount != 0) && failure == nil && !closing {
      condition.wait()
    }
    do {
      try checkOpen()
      let serializedBatch: ([Data], UInt64)
      do {
        serializedBatch = try serializedRuntimeBatch(
          records,
          startingAt: nextEventSequence
        )
      } catch let error as BrokerRuntimeBatchPreparationError {
        throw error
      } catch {
        throw BrokerRuntimeBatchPreparationError.serializationFailed(
          String(describing: error)
        )
      }
      let (serialized, nextSequence) = serializedBatch
      nextEventSequence = nextSequence
      pending.append(.serializedRuntimeBatch(serialized, acknowledgement))
      semanticCount += records.count
      condition.signal()
      condition.unlock()
    } catch {
      condition.unlock()
      throw error
    }
    try acknowledgement.wait()
  }

  func sendSemanticAwaitingWrite(
    requestID: UInt64,
    scanSessionID: String = "",
    body: Diskplan_V1_EngineEvent.OneOf_Body
  ) throws {
    let acknowledgement = BrokerWriteAcknowledgement()
    try enqueue(
      .event(
        requestID: requestID,
        scanSessionID: scanSessionID,
        body: body,
        telemetry: false,
        writeAcknowledgement: acknowledgement
      ),
      semantic: true
    )
    try acknowledgement.wait()
  }

  func sendProgress(
    scanSessionID: String,
    progress: Diskplan_V1_ScanProgress
  ) throws {
    condition.lock()
    defer { condition.unlock() }
    try checkOpen()
    if let last = pending.indices.last,
      pending[last].isTelemetry
    {
      pending[last] = .event(
        requestID: 0,
        scanSessionID: scanSessionID,
        body: .scanProgress(progress),
        telemetry: true,
        writeAcknowledgement: nil
      )
    } else {
      pending.append(
        .event(
          requestID: 0,
          scanSessionID: scanSessionID,
          body: .scanProgress(progress),
          telemetry: true,
          writeAcknowledgement: nil
        ))
    }
    condition.signal()
  }

  func finish() throws {
    condition.lock()
    closing = true
    condition.broadcast()
    while !finished { condition.wait() }
    let failure = failure
    condition.unlock()
    if let failure { throw failure }
  }

  func failClosed(_ summary: String) {
    let outputFailure = EventBrokerError.outputFailed(summary)
    condition.lock()
    guard failure == nil, !finished else {
      condition.unlock()
      return
    }
    failure = outputFailure
    closing = true
    let pendingAcknowledgements = pending.compactMap(\.writeAcknowledgement)
    pending.removeAll()
    semanticCount = 0
    condition.broadcast()
    condition.unlock()
    for acknowledgement in pendingAcknowledgements {
      acknowledgement.resolve(.failure(outputFailure))
    }
  }

  /// Waits until every output accepted before this call has completed its
  /// actual writer invocation. Runtime authority receipts commit only after
  /// this barrier succeeds.
  func flush() throws {
    condition.lock()
    while (!pending.isEmpty || inFlightCount != 0) && failure == nil && !finished {
      condition.wait()
    }
    let failure = failure
    condition.unlock()
    if let failure { throw failure }
  }

  private func enqueue(_ output: PendingOutput, semantic: Bool) throws {
    condition.lock()
    defer { condition.unlock() }
    while semantic && semanticCount >= semanticCapacity && failure == nil && !closing {
      condition.wait()
    }
    try checkOpen()
    pending.append(output)
    if semantic { semanticCount += 1 }
    condition.signal()
  }

  private func checkOpen() throws {
    if let failure { throw failure }
    if closing { throw EventBrokerError.closed }
  }

  private func drain() {
    while true {
      condition.lock()
      while pending.isEmpty && !closing { condition.wait() }
      if pending.isEmpty && closing {
        finished = true
        condition.broadcast()
        condition.unlock()
        return
      }
      let output = pending.removeFirst()
      inFlightCount += 1
      if !output.isTelemetry { semanticCount -= output.semanticWeight }
      condition.broadcast()
      condition.unlock()

      do {
        for data in try serialized(output) {
          try writer(data)
        }
        condition.lock()
        inFlightCount -= 1
        condition.broadcast()
        condition.unlock()
        output.writeAcknowledgement?.resolve(.success(()))
      } catch {
        let outputFailure = EventBrokerError.outputFailed(String(describing: error))
        condition.lock()
        inFlightCount -= 1
        failure = outputFailure
        let pendingAcknowledgements = pending.compactMap(\.writeAcknowledgement)
        pending.removeAll()
        semanticCount = 0
        closing = true
        finished = true
        condition.broadcast()
        condition.unlock()
        output.writeAcknowledgement?.resolve(.failure(outputFailure))
        for acknowledgement in pendingAcknowledgements {
          acknowledgement.resolve(.failure(outputFailure))
        }
        return
      }
    }
  }

  private func serialized(_ output: PendingOutput) throws -> [Data] {
    var envelope = Diskplan_V1_Envelope()
    switch output {
    case .envelope(let sequence, let body):
      envelope.sequence = sequence
      envelope.body = body
    case .event(let requestID, let scanSessionID, let body, _, _):
      let sequence = try consumeEventSequence()
      var event = Diskplan_V1_EngineEvent()
      event.eventSequence = sequence
      event.requestID = requestID
      event.scanSessionID = scanSessionID
      event.body = body
      envelope.sequence = sequence
      envelope.body = .engineEvent(event)
    case .runtimeEvent(let requestID, let runtimeSessionID, let body):
      let sequence = try consumeEventSequence()
      var sessionID = Diskplan_V1_OpaqueIdentifier()
      sessionID.value = runtimeSessionID
      var event = Diskplan_V1_RuntimeEvent()
      event.eventSequence = sequence
      event.requestID = requestID
      event.runtimeSessionID = sessionID
      event.body = body
      envelope.sequence = sequence
      envelope.body = .runtimeEvent(event)
    case .serializedRuntimeBatch(let envelopes, _):
      return envelopes
    }
    return [try envelope.serializedData()]
  }

  private func serializedRuntimeBatch(
    _ records: [BrokerRuntimeRecord],
    startingAt initialSequence: UInt64
  ) throws -> ([Data], UInt64) {
    var sequence = initialSequence
    var serialized: [Data] = []
    serialized.reserveCapacity(records.count)
    for record in records {
      guard sequence != 0 else {
        throw BrokerRuntimeBatchPreparationError.eventSequenceExhausted
      }
      var event = Diskplan_V1_RuntimeEvent()
      event.eventSequence = sequence
      event.requestID = record.requestID
      event.runtimeSessionID.value = record.runtimeSessionID
      event.body = record.body
      var envelope = Diskplan_V1_Envelope()
      envelope.sequence = sequence
      envelope.body = .runtimeEvent(event)
      serialized.append(try envelope.serializedData())
      sequence = sequence == UInt64.max ? 0 : sequence + 1
    }
    return (serialized, sequence)
  }

  private func consumeEventSequence() throws -> UInt64 {
    let sequence = nextEventSequence
    guard sequence != 0 else {
      throw EventBrokerError.outputFailed("event sequence space exhausted")
    }
    nextEventSequence = sequence == UInt64.max ? 0 : sequence + 1
    return sequence
  }
}
