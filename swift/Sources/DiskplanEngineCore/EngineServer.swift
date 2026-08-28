import DiskplanCore
import DiskplanProto
import Foundation
import SwiftProtobuf

public enum EngineServer {
  public static func run(
    input: FileHandle = .standardInput,
    output: FileHandle = .standardOutput
  ) throws {
    guard let payload = try FrameCodec.read(from: input) else { return }
    let request: Diskplan_V1_Envelope
    do {
      request = try Diskplan_V1_Envelope(serializedBytes: payload)
    } catch {
      try writeDirect(
        sequence: 0,
        body: .helloRejected(
          Handshake.rejection(.malformedEnvelope, detail: "invalid protobuf envelope")
        ),
        output: output
      )
      return
    }

    guard case .hello(let peer) = request.body else {
      let code: Diskplan_V1_RejectCode
      let detail: String
      switch request.body {
      case .business, .startScanRequest, .scanControlRequest:
        code = .businessBeforeHandshake
        detail = "business envelope received before handshake"
      default:
        code = .malformedEnvelope
        detail = "expected client hello"
      }
      try writeDirect(
        sequence: request.sequence,
        body: .helloRejected(Handshake.rejection(code, detail: detail)),
        output: output
      )
      return
    }

    switch Handshake.negotiate(local: Handshake.swiftEngineHello(), peer: peer) {
    case .rejected(let rejected):
      try writeDirect(
        sequence: request.sequence,
        body: .helloRejected(rejected),
        output: output
      )
    case .accepted(let accepted):
      try writeDirect(
        sequence: request.sequence,
        body: .helloAccepted(accepted),
        output: output
      )
      try runReadyLoop(
        input: input,
        output: output,
        negotiatedCapabilities: Set(accepted.negotiatedCapabilities)
      )
    }
  }

  private static func runReadyLoop(
    input: FileHandle,
    output: FileHandle,
    negotiatedCapabilities: Set<String>
  ) throws {
    let broker = SerialEventBroker(output: output)
    let coordinator = ScanCoordinator(broker: broker)
    var requestIDHighWaterMark: UInt64 = 0
    defer { coordinator.stopAndWait() }

    while let payload = try FrameCodec.read(from: input) {
      let request: Diskplan_V1_Envelope
      do {
        request = try Diskplan_V1_Envelope(serializedBytes: payload)
      } catch {
        try broker.sendEnvelope(
          sequence: 0,
          body: .helloRejected(
            Handshake.rejection(.malformedEnvelope, detail: "invalid protobuf envelope")
          )
        )
        continue
      }

      switch request.body {
      case .business:
        try broker.sendEnvelope(
          sequence: request.sequence,
          body: .helloRejected(
            Handshake.rejection(
              .businessUnsupported,
              detail: "business messages are not implemented in the Phase 1 engine"
            ))
        )
      case .startScanRequest(let start):
        if let rejection = consumeRequestID(start.requestID, highWaterMark: &requestIDHighWaterMark)
        {
          try coordinator.rejectControl(
            requestID: start.requestID,
            control: .startScan,
            code: rejection.code,
            detail: rejection.detail
          )
        } else if request.sequence != start.requestID {
          try coordinator.rejectMalformed(
            requestID: start.requestID,
            control: .startScan,
            detail: "envelope sequence must equal request_id"
          )
        } else if !scanStreamIsNegotiated(negotiatedCapabilities) {
          try coordinator.rejectControl(
            requestID: start.requestID,
            control: .startScan,
            code: .unavailable,
            detail: "scan-control-v1, scan-stream-v1, and raw-path-bytes-v1 must be negotiated",
            setupCode: .capabilityNotNegotiated
          )
        } else {
          try coordinator.start(start)
        }
      case .scanControlRequest(let control):
        if let rejection = consumeRequestID(
          control.requestID,
          highWaterMark: &requestIDHighWaterMark
        ) {
          try coordinator.rejectControl(
            requestID: control.requestID,
            control: control.control,
            code: rejection.code,
            detail: rejection.detail
          )
        } else if request.sequence != control.requestID {
          try coordinator.rejectMalformed(
            requestID: control.requestID,
            control: control.control,
            detail: "envelope sequence must equal request_id"
          )
        } else {
          try coordinator.control(control)
        }
      case .hello, .helloAccepted, .helloRejected, .engineEvent, .none:
        try broker.sendEnvelope(
          sequence: request.sequence,
          body: .helloRejected(
            Handshake.rejection(.malformedEnvelope, detail: "expected business envelope")
          )
        )
      }
    }
    coordinator.stopAndWait()
    try broker.finish()
  }

  private static func consumeRequestID(
    _ requestID: UInt64,
    highWaterMark: inout UInt64
  ) -> (code: Diskplan_V1_ControlRejectCode, detail: String)? {
    guard requestID != 0 else {
      return (.malformedRequest, "request_id must be non-zero")
    }
    guard requestID > highWaterMark else {
      return (
        .duplicateRequestID,
        "request_id must be strictly greater than the previous request_id"
      )
    }
    highWaterMark = requestID
    return nil
  }

  private static func scanStreamIsNegotiated(_ capabilities: Set<String>) -> Bool {
    ["scan-control-v1", "scan-stream-v1", "raw-path-bytes-v1"].allSatisfy {
      capabilities.contains($0)
    }
  }

  private static func writeDirect(
    sequence: UInt64,
    body: Diskplan_V1_Envelope.OneOf_Body,
    output: FileHandle
  ) throws {
    var response = Diskplan_V1_Envelope()
    response.sequence = sequence
    response.body = body
    try FrameCodec.write(try response.serializedData(), to: output)
  }
}
