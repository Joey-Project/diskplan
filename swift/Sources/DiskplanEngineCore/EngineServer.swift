import DiskplanCore
import DiskplanProto
import Foundation
import SwiftProtobuf

public enum EngineServer {
  public static func run(
    input: FileHandle = .standardInput,
    output: FileHandle = .standardOutput,
    runtimeHandler: (any RuntimeBusinessHandler)? = nil
  ) throws {
    let runtimeCapabilities =
      runtimeHandler.map {
        $0.supportedCapabilities.intersection(protocol14RuntimeCapabilities)
      } ?? []
    guard let payload = try FrameCodec.read(from: input) else { return }
    let request: Diskplan_V1_Envelope
    do {
      request = try decodeCanonicalEnvelope(payload)
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
      case .business, .startScanRequest, .scanControlRequest, .buildPlanRequest,
        .decisionOverlayEditRequest, .prepareDryRunRequest, .prepareApplyReviewRequest,
        .confirmApplyRequest, .cancelExecutionRequest:
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

    switch Handshake.negotiate(
      local: Handshake.swiftEngineHello(runtimeCapabilities: runtimeCapabilities),
      peer: peer
    ) {
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
        negotiatedCapabilities: Set(accepted.negotiatedCapabilities),
        advertisedRuntimeCapabilities: runtimeCapabilities,
        runtimeHandler: runtimeHandler
      )
    }
  }

  private static func runReadyLoop(
    input: FileHandle,
    output: FileHandle,
    negotiatedCapabilities: Set<String>,
    advertisedRuntimeCapabilities: Set<String>,
    runtimeHandler: (any RuntimeBusinessHandler)?
  ) throws {
    let broker = SerialEventBroker(output: output)
    let coordinator = ScanCoordinator(broker: broker)
    let runtimeSessionID = Data(UUID().uuidString.lowercased().utf8)
    let runtimeAuthority = RuntimeBusinessAuthorityState()
    var requestIDHighWaterMark: UInt64 = 0
    defer { coordinator.stopAndWait() }

    while let payload = try FrameCodec.read(from: input) {
      let request: Diskplan_V1_Envelope
      do {
        request = try decodeCanonicalEnvelope(payload)
      } catch {
        try broker.sendEnvelope(
          sequence: 0,
          body: .helloRejected(
            Handshake.rejection(.malformedEnvelope, detail: "invalid protobuf envelope")
          )
        )
        continue
      }

      let envelopeSequence = request.sequence
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
      case .buildPlanRequest(let request):
        try dispatchRuntime(
          .buildPlan(request),
          envelopeSequence: envelopeSequence,
          handler: runtimeHandler,
          advertisedCapabilities: advertisedRuntimeCapabilities,
          negotiatedCapabilities: negotiatedCapabilities,
          runtimeSessionID: runtimeSessionID,
          runtimeAuthority: runtimeAuthority,
          requestIDHighWaterMark: &requestIDHighWaterMark,
          broker: broker
        )
      case .decisionOverlayEditRequest(let request):
        try dispatchRuntime(
          .editDecisionOverlay(request),
          envelopeSequence: envelopeSequence,
          handler: runtimeHandler,
          advertisedCapabilities: advertisedRuntimeCapabilities,
          negotiatedCapabilities: negotiatedCapabilities,
          runtimeSessionID: runtimeSessionID,
          runtimeAuthority: runtimeAuthority,
          requestIDHighWaterMark: &requestIDHighWaterMark,
          broker: broker
        )
      case .prepareDryRunRequest(let request):
        try dispatchRuntime(
          .prepareDryRun(request),
          envelopeSequence: envelopeSequence,
          handler: runtimeHandler,
          advertisedCapabilities: advertisedRuntimeCapabilities,
          negotiatedCapabilities: negotiatedCapabilities,
          runtimeSessionID: runtimeSessionID,
          runtimeAuthority: runtimeAuthority,
          requestIDHighWaterMark: &requestIDHighWaterMark,
          broker: broker
        )
      case .prepareApplyReviewRequest(let request):
        try dispatchRuntime(
          .prepareApplyReview(request),
          envelopeSequence: envelopeSequence,
          handler: runtimeHandler,
          advertisedCapabilities: advertisedRuntimeCapabilities,
          negotiatedCapabilities: negotiatedCapabilities,
          runtimeSessionID: runtimeSessionID,
          runtimeAuthority: runtimeAuthority,
          requestIDHighWaterMark: &requestIDHighWaterMark,
          broker: broker
        )
      case .confirmApplyRequest(let request):
        try dispatchRuntime(
          .confirmApply(request),
          envelopeSequence: envelopeSequence,
          handler: runtimeHandler,
          advertisedCapabilities: advertisedRuntimeCapabilities,
          negotiatedCapabilities: negotiatedCapabilities,
          runtimeSessionID: runtimeSessionID,
          runtimeAuthority: runtimeAuthority,
          requestIDHighWaterMark: &requestIDHighWaterMark,
          broker: broker
        )
      case .cancelExecutionRequest(let request):
        try dispatchRuntime(
          .cancelExecution(request),
          envelopeSequence: envelopeSequence,
          handler: runtimeHandler,
          advertisedCapabilities: advertisedRuntimeCapabilities,
          negotiatedCapabilities: negotiatedCapabilities,
          runtimeSessionID: runtimeSessionID,
          runtimeAuthority: runtimeAuthority,
          requestIDHighWaterMark: &requestIDHighWaterMark,
          broker: broker
        )
      case .hello, .helloAccepted, .helloRejected, .engineEvent, .runtimeEvent, .none:
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

  private static func dispatchRuntime(
    _ request: RuntimeBusinessRequest,
    envelopeSequence: UInt64,
    handler: (any RuntimeBusinessHandler)?,
    advertisedCapabilities: Set<String>,
    negotiatedCapabilities: Set<String>,
    runtimeSessionID: Data,
    runtimeAuthority: RuntimeBusinessAuthorityState,
    requestIDHighWaterMark: inout UInt64,
    broker: SerialEventBroker
  ) throws {
    if let rejection = consumeRequestID(
      request.requestID,
      highWaterMark: &requestIDHighWaterMark
    ) {
      let code: Diskplan_V1_RuntimeRejectCode =
        rejection.code == .duplicateRequestID ? .duplicateRequestID : .malformedRequest
      try rejectRuntime(
        requestID: request.requestID,
        runtimeSessionID: runtimeSessionID,
        code: code,
        summary: rejection.detail,
        broker: broker
      )
      return
    }
    guard envelopeSequence == request.requestID else {
      try rejectRuntime(
        requestID: request.requestID,
        runtimeSessionID: runtimeSessionID,
        code: .malformedRequest,
        summary: "envelope sequence must equal request_id",
        broker: broker
      )
      return
    }
    if case .cancelExecution = request {
      try rejectRuntime(
        requestID: request.requestID,
        runtimeSessionID: runtimeSessionID,
        code: .businessUnsupported,
        summary: "midstream execution cancellation is not supported by the batch runtime",
        broker: broker
      )
      return
    }
    guard let handler else {
      try rejectRuntime(
        requestID: request.requestID,
        runtimeSessionID: runtimeSessionID,
        code: .businessUnsupported,
        summary: "runtime business handling is not installed",
        broker: broker
      )
      return
    }
    guard advertisedCapabilities.contains(request.requiredCapability),
      negotiatedCapabilities.contains(request.requiredCapability)
    else {
      try rejectRuntime(
        requestID: request.requestID,
        runtimeSessionID: runtimeSessionID,
        code: .capabilityNotNegotiated,
        summary: "\(request.requiredCapability) was not negotiated",
        broker: broker
      )
      return
    }
    if let rejection = runtimeAuthority.claim(request) {
      try rejectRuntime(
        requestID: request.requestID,
        runtimeSessionID: runtimeSessionID,
        code: rejection.code,
        summary: rejection.summary,
        broker: broker
      )
      return
    }

    let responder = RuntimeBusinessResponder(
      broker: broker,
      request: request,
      runtimeSessionID: runtimeSessionID,
      authority: runtimeAuthority
    )
    do {
      try handler.handle(request, responder: responder)
    } catch {
      try responder.rejectHandlerFailure()
    }
  }

  private static func rejectRuntime(
    requestID: UInt64,
    runtimeSessionID: Data,
    code: Diskplan_V1_RuntimeRejectCode,
    summary: String,
    broker: SerialEventBroker
  ) throws {
    var rejected = Diskplan_V1_RuntimeRejected()
    rejected.code = code
    rejected.summary = summary
    try broker.sendRuntime(
      requestID: requestID,
      runtimeSessionID: runtimeSessionID,
      body: .runtimeRejected(rejected)
    )
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

  /// Canonical admission happens before dispatch so protobuf unknown fields,
  /// duplicate encodings, and noncanonical nested messages cannot be discarded
  /// before the request reaches a safety-sensitive validator.
  private static func decodeCanonicalEnvelope(_ payload: Data) throws -> Diskplan_V1_Envelope {
    let envelope = try Diskplan_V1_Envelope(serializedBytes: payload)
    guard try envelope.serializedData() == payload,
      !containsUnknownProtobufFields(envelope)
    else {
      throw CanonicalEnvelopeError.noncanonicalOrUnknownField
    }
    return envelope
  }

  private static func containsUnknownProtobufFields(_ value: Any) -> Bool {
    if let message = value as? any SwiftProtobuf.Message,
      !message.unknownFields.data.isEmpty
    {
      return true
    }
    if value is Data || value is String { return false }
    let mirror = Mirror(reflecting: value)
    switch mirror.displayStyle {
    case .struct, .class, .enum, .tuple, .collection, .dictionary, .optional:
      return mirror.children.contains { containsUnknownProtobufFields($0.value) }
    #if compiler(>=6.3)
      case .foreignReference:
        return true
    #endif
    case .set, .none:
      return false
    @unknown default:
      return true
    }
  }

  private enum CanonicalEnvelopeError: Error {
    case noncanonicalOrUnknownField
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
