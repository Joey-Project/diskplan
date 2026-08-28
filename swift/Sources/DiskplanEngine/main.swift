import DiskplanCore
import DiskplanProto
import Foundation
import SwiftProtobuf

@main
struct DiskplanEngine {
    static func main() {
        if CommandLine.arguments == [CommandLine.arguments[0], "--version-json"] {
            print(
                "{\"component\":\"diskplan-engine\",\"product_version\":\"\(productVersion)\",\"protocol_major\":\(protocolMajor),\"protocol_minor\":\(protocolMinor)}"
            )
            return
        }
        guard CommandLine.arguments.count == 1 else {
            FileHandle.standardError.write(
                Data("usage: diskplan-engine [--version-json]\n".utf8)
            )
            Foundation.exit(64)
        }
        do {
            try run()
        } catch {
            FileHandle.standardError.write(Data("diskplan-engine: \(error)\n".utf8))
            Foundation.exit(1)
        }
    }

    private static func run() throws {
        guard let payload = try FrameCodec.read(from: .standardInput) else {
            return
        }
        let request: Diskplan_V1_Envelope
        do {
            request = try Diskplan_V1_Envelope(serializedBytes: payload)
        } catch {
            try writeRejection(
                sequence: 0,
                Handshake.rejection(.malformedEnvelope, detail: "invalid protobuf envelope")
            )
            return
        }

        switch request.body {
        case .hello(let peer):
            switch Handshake.negotiate(local: Handshake.swiftEngineHello(), peer: peer) {
            case .accepted(let accepted):
                try writeResponse(sequence: request.sequence, body: .helloAccepted(accepted))
                try runReadyLoop()
            case .rejected(let rejected):
                try writeRejection(sequence: request.sequence, rejected)
            }
        case .business, .startScanRequest, .scanControlRequest:
            try writeRejection(
                sequence: request.sequence,
                Handshake.rejection(
                    .businessBeforeHandshake,
                    detail: "business envelope received before handshake"
                )
            )
        case .helloAccepted, .helloRejected, .engineEvent, .none:
            try writeRejection(
                sequence: request.sequence,
                Handshake.rejection(.malformedEnvelope, detail: "expected client hello")
            )
        }
    }

    private static func runReadyLoop() throws {
        var scanSession = ScanSession()
        while let payload = try FrameCodec.read(from: .standardInput) {
            let request: Diskplan_V1_Envelope
            do {
                request = try Diskplan_V1_Envelope(serializedBytes: payload)
            } catch {
                try writeRejection(
                    sequence: 0,
                    Handshake.rejection(.malformedEnvelope, detail: "invalid protobuf envelope")
                )
                continue
            }

            switch request.body {
            case .business:
                try writeRejection(
                    sequence: request.sequence,
                    Handshake.rejection(
                        .businessUnsupported,
                        detail: "business messages are not implemented in the foundation engine"
                    )
                )
            case .startScanRequest(let start):
                if request.sequence == start.requestID {
                    try writeEvents(scanSession.start(start))
                } else {
                    try writeEvents(
                        scanSession.rejectMalformed(
                            requestID: start.requestID,
                            control: .startScan,
                            detail: "envelope sequence must equal request_id"
                        )
                    )
                }
            case .scanControlRequest(let control):
                if request.sequence == control.requestID {
                    try writeEvents(scanSession.control(control))
                } else {
                    try writeEvents(
                        scanSession.rejectMalformed(
                            requestID: control.requestID,
                            control: control.control,
                            detail: "envelope sequence must equal request_id"
                        )
                    )
                }
                if scanSession.state == .cancelled {
                    return
                }
            case .hello, .helloAccepted, .helloRejected, .engineEvent, .none:
                try writeRejection(
                    sequence: request.sequence,
                    Handshake.rejection(.malformedEnvelope, detail: "expected business envelope")
                )
            }
        }
    }

    private static func writeEvents(_ events: [Diskplan_V1_EngineEvent]) throws {
        for event in events {
            try writeResponse(sequence: event.eventSequence, body: .engineEvent(event))
        }
    }

    private static func writeRejection(
        sequence: UInt64,
        _ rejected: Diskplan_V1_HelloRejected
    ) throws {
        try writeResponse(sequence: sequence, body: .helloRejected(rejected))
    }

    private static func writeResponse(
        sequence: UInt64,
        body: Diskplan_V1_Envelope.OneOf_Body
    ) throws {
        var response = Diskplan_V1_Envelope()
        response.sequence = sequence
        response.body = body
        try FrameCodec.write(try response.serializedData(), to: .standardOutput)
    }
}
