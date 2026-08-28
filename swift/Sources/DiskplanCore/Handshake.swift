import DiskplanProto

public let protocolMajor: UInt32 = 1
public let protocolMinor: UInt32 = 3
public let productVersion = "0.1.0"

public enum HandshakeResult: Equatable {
    case accepted(Diskplan_V1_HelloAccepted)
    case rejected(Diskplan_V1_HelloRejected)
}

public enum Handshake {
    public static func swiftEngineHello() -> Diskplan_V1_Hello {
        var version = Diskplan_V1_ProtocolVersion()
        version.major = protocolMajor
        version.minor = protocolMinor

        var hello = Diskplan_V1_Hello()
        hello.version = version
        hello.requiredCapabilities = ["framing-v1"]
        hello.optionalCapabilities = [
            "canonical-binary-v1",
            "plan-bootstrap",
            "raw-path-bytes-v1",
            "scan-control-v1",
            "scan-stream-v1",
        ]
        hello.implementation = "diskplan-swift-engine"
        return hello
    }

    public static func negotiate(
        local: Diskplan_V1_Hello,
        peer: Diskplan_V1_Hello
    ) -> HandshakeResult {
        guard local.hasVersion else {
            return reject(.malformedEnvelope, detail: "local hello has no version", peer: peer)
        }
        guard peer.hasVersion else {
            return reject(.malformedEnvelope, detail: "peer hello has no version", peer: peer)
        }
        guard local.version.major == peer.version.major else {
            return reject(
                .protocolMajorMismatch,
                detail: "protocol major versions differ",
                peer: peer
            )
        }

        let localOffered = Set(local.requiredCapabilities + local.optionalCapabilities)
        let peerOffered = Set(peer.requiredCapabilities + peer.optionalCapabilities)
        if let missing = peer.requiredCapabilities.sorted().first(where: { !localOffered.contains($0) }) {
            return reject(
                .missingRequiredCapability,
                detail: "local implementation does not offer required capability: \(missing)",
                peer: peer
            )
        }
        if let missing = local.requiredCapabilities.sorted().first(where: { !peerOffered.contains($0) }) {
            return reject(
                .missingRequiredCapability,
                detail: "peer does not offer required capability: \(missing)",
                peer: peer
            )
        }

        var version = Diskplan_V1_ProtocolVersion()
        version.major = local.version.major
        version.minor = min(local.version.minor, peer.version.minor)
        var accepted = Diskplan_V1_HelloAccepted()
        accepted.selectedVersion = version
        accepted.negotiatedCapabilities = localOffered.intersection(peerOffered).sorted()
        return .accepted(accepted)
    }

    public static func rejection(
        _ code: Diskplan_V1_RejectCode,
        detail: String,
        peerVersion: Diskplan_V1_ProtocolVersion? = nil
    ) -> Diskplan_V1_HelloRejected {
        var rejected = Diskplan_V1_HelloRejected()
        rejected.code = code
        rejected.detail = detail
        if let peerVersion {
            rejected.peerVersion = peerVersion
        }
        return rejected
    }

    private static func reject(
        _ code: Diskplan_V1_RejectCode,
        detail: String,
        peer: Diskplan_V1_Hello
    ) -> HandshakeResult {
        .rejected(rejection(code, detail: detail, peerVersion: peer.hasVersion ? peer.version : nil))
    }
}
