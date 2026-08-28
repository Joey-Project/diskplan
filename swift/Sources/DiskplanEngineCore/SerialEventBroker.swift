import DiskplanCore
import DiskplanProto
import Foundation
import SwiftProtobuf

enum EventBrokerError: Error, Equatable {
  case closed
  case outputFailed(String)
}

private enum PendingOutput: @unchecked Sendable {
  case envelope(sequence: UInt64, body: Diskplan_V1_Envelope.OneOf_Body)
  case event(
    requestID: UInt64,
    scanSessionID: String,
    body: Diskplan_V1_EngineEvent.OneOf_Body,
    telemetry: Bool
  )

  var isTelemetry: Bool {
    if case .event(_, _, _, let telemetry) = self { return telemetry }
    return false
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
        telemetry: false
      ),
      semantic: true
    )
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
        telemetry: true
      )
    } else {
      pending.append(
        .event(
          requestID: 0,
          scanSessionID: scanSessionID,
          body: .scanProgress(progress),
          telemetry: true
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
      if !output.isTelemetry { semanticCount -= 1 }
      condition.broadcast()
      condition.unlock()

      do {
        try writer(serialized(output))
      } catch {
        condition.lock()
        failure = .outputFailed(String(describing: error))
        pending.removeAll()
        semanticCount = 0
        closing = true
        finished = true
        condition.broadcast()
        condition.unlock()
        return
      }
    }
  }

  private func serialized(_ output: PendingOutput) throws -> Data {
    var envelope = Diskplan_V1_Envelope()
    switch output {
    case .envelope(let sequence, let body):
      envelope.sequence = sequence
      envelope.body = body
    case .event(let requestID, let scanSessionID, let body, _):
      let sequence = nextEventSequence
      guard sequence != 0 else {
        throw EventBrokerError.outputFailed("event sequence space exhausted")
      }
      nextEventSequence = sequence == UInt64.max ? 0 : sequence + 1
      var event = Diskplan_V1_EngineEvent()
      event.eventSequence = sequence
      event.requestID = requestID
      event.scanSessionID = scanSessionID
      event.body = body
      envelope.sequence = sequence
      envelope.body = .engineEvent(event)
    }
    return try envelope.serializedData()
  }
}
