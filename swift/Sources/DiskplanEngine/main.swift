import DiskplanCore
import DiskplanProto
import Foundation
import SwiftProtobuf

@main
struct DiskplanEngine {
    static func main() {
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
        case .business:
            try writeRejection(
                sequence: request.sequence,
                Handshake.rejection(
                    .businessBeforeHandshake,
                    detail: "business envelope received before handshake"
                )
            )
        case .helloAccepted, .helloRejected, .none:
            try writeRejection(
                sequence: request.sequence,
                Handshake.rejection(.malformedEnvelope, detail: "expected client hello")
            )
        }
    }

    private static func runReadyLoop() throws {
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
            case .hello, .helloAccepted, .helloRejected, .none:
                try writeRejection(
                    sequence: request.sequence,
                    Handshake.rejection(.malformedEnvelope, detail: "expected business envelope")
                )
            }
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
