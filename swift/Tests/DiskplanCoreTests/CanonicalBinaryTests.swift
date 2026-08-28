import DiskplanCore
import Foundation
import Testing

private struct Fixture: Decodable {
    struct Timestamp: Decodable {
        let seconds: Int64
        let nanos: UInt32

        enum CodingKeys: String, CodingKey, CaseIterable {
            case seconds
            case nanos
        }

        init(from decoder: Decoder) throws {
            try rejectUnknownKeys(from: decoder, allowed: CodingKeys.self)
            let container = try decoder.container(keyedBy: CodingKeys.self)
            seconds = try container.decode(Int64.self, forKey: .seconds)
            nanos = try container.decode(UInt32.self, forKey: .nanos)
        }
    }

    let schema: String
    let bindingKind: String
    let candidateID: String
    let rawPathHex: String
    let logicalBytes: UInt64
    let observedAt: Timestamp?
    let activity: String
    let coverage: String
    let labels: [String]

    enum CodingKeys: String, CodingKey, CaseIterable {
        case schema
        case bindingKind = "binding_kind"
        case candidateID = "candidate_id"
        case rawPathHex = "raw_path_hex"
        case logicalBytes = "logical_bytes"
        case observedAt = "observed_at"
        case activity
        case coverage
        case labels
    }

    init(from decoder: Decoder) throws {
        try rejectUnknownKeys(from: decoder, allowed: CodingKeys.self)
        let container = try decoder.container(keyedBy: CodingKeys.self)
        schema = try container.decode(String.self, forKey: .schema)
        bindingKind = try container.decode(String.self, forKey: .bindingKind)
        guard schema == "canonical-binary-v1", bindingKind == "evidence" else {
            throw DecodingError.dataCorrupted(
                .init(
                    codingPath: decoder.codingPath,
                    debugDescription: "unsupported fixture schema or binding kind"
                )
            )
        }
        candidateID = try container.decode(String.self, forKey: .candidateID)
        rawPathHex = try container.decode(String.self, forKey: .rawPathHex)
        logicalBytes = try container.decode(UInt64.self, forKey: .logicalBytes)
        observedAt = try container.decodeIfPresent(Timestamp.self, forKey: .observedAt)
        activity = try container.decode(String.self, forKey: .activity)
        coverage = try container.decode(String.self, forKey: .coverage)
        labels = try container.decode([String].self, forKey: .labels)
    }
}

@Test
func canonicalEvidenceMatchesGoldenBytesAndDigest() throws {
    let directory = fixtureDirectory()
    let fixture = try JSONDecoder().decode(
        Fixture.self,
        from: Data(contentsOf: directory.appendingPathComponent("evidence.json"))
    )
    let value = EvidenceBinding(
        candidateID: fixture.candidateID,
        rawPath: try #require(Data(hex: fixture.rawPathHex)),
        logicalBytes: fixture.logicalBytes,
        observedAt: fixture.observedAt.map {
            CanonicalTimestamp(seconds: $0.seconds, nanos: $0.nanos)
        },
        activity: try #require(activity(named: fixture.activity)),
        coverage: try #require(coverage(named: fixture.coverage)),
        labels: fixture.labels
    )
    let golden = try Data(contentsOf: directory.appendingPathComponent("evidence.bin"))
    let expectedDigest = try String(
        contentsOf: directory.appendingPathComponent("evidence.sha256"),
        encoding: .utf8
    ).trimmingCharacters(in: .whitespacesAndNewlines)

    let authored = try CanonicalBinaryV1.bindEvidence(value)
    #expect(authored.bytes == golden)
    #expect(authored.digest.hexString == expectedDigest)
    let verified = try CanonicalBinaryV1.verifyEvidence(golden)
    #expect(verified.bytes == golden)
    #expect(verified.digest == authored.digest)
    #expect(verified.binding == authored.binding)
    #expect(try CanonicalBinaryV1.encodeEvidence(verified.binding) == golden)
}

@Test
func canonicalDecoderFailsClosedOnTrailingBytes() throws {
    var bytes = try Data(contentsOf: fixtureDirectory().appendingPathComponent("evidence.bin"))
    bytes.append(0)
    #expect(throws: CanonicalBinaryError.trailingBytes) {
        try CanonicalBinaryV1.decodeEvidence(bytes)
    }
    #expect(throws: CanonicalBinaryError.trailingBytes) {
        try CanonicalBinaryV1.verifyEvidence(bytes)
    }
}

@Test
func canonicalEncodingKeepsTypedAbsenceAndSignedTime() throws {
    let absent = EvidenceBinding(
        candidateID: "absent",
        rawPath: Data(),
        logicalBytes: 0,
        observedAt: nil,
        activity: .absent,
        coverage: .unreadable,
        labels: []
    )
    #expect(try CanonicalBinaryV1.decodeEvidence(CanonicalBinaryV1.encodeEvidence(absent)) == absent)

    let beforeEpoch = EvidenceBinding(
        candidateID: "before-epoch",
        rawPath: Data([0]),
        logicalBytes: 1,
        observedAt: CanonicalTimestamp(seconds: -1, nanos: 999_999_999),
        activity: .unknown,
        coverage: .failed,
        labels: ["x"]
    )
    #expect(
        try CanonicalBinaryV1.decodeEvidence(CanonicalBinaryV1.encodeEvidence(beforeEpoch))
            == beforeEpoch
    )
}

@Test
func canonicalDecoderRejectsImpossibleCollectionCountBeforeAllocation() throws {
    var bytes = try Data(contentsOf: fixtureDirectory().appendingPathComponent("evidence.bin"))
    bytes.removeLast(22)
    bytes.append(Data([0xff, 0xff, 0xff, 0xff]))
    #expect(throws: CanonicalBinaryError.truncated(field: "labels")) {
        try CanonicalBinaryV1.decodeEvidence(bytes)
    }
}

@Test
func canonicalLabelsUseRawUTF8OrderingAndIdentity() throws {
    let decomposed = "e\u{301}"
    let composed = "\u{e9}"
    #expect(decomposed == composed)

    let binding = EvidenceBinding(
        candidateID: "unicode-labels",
        rawPath: Data(),
        logicalBytes: 0,
        observedAt: nil,
        activity: .unknown,
        coverage: .complete,
        labels: [composed, decomposed, composed, decomposed]
    )
    let verified = try CanonicalBinaryV1.verifyEvidence(
        CanonicalBinaryV1.bindEvidence(binding).bytes
    )
    #expect(verified.binding.labels.count == 2)
    #expect(verified.binding.labels.map { Data($0.utf8) } == [Data(decomposed.utf8), Data(composed.utf8)])
}

@Test
func fixtureJSONRejectsUnknownFieldsAndUnsupportedTypeTags() throws {
    let source = try Data(contentsOf: fixtureDirectory().appendingPathComponent("evidence.json"))
    var object = try #require(JSONSerialization.jsonObject(with: source) as? [String: Any])
    object["unexpected"] = true
    #expect(throws: DecodingError.self) {
        try JSONDecoder().decode(Fixture.self, from: JSONSerialization.data(withJSONObject: object))
    }

    object.removeValue(forKey: "unexpected")
    object["binding_kind"] = "other"
    #expect(throws: DecodingError.self) {
        try JSONDecoder().decode(Fixture.self, from: JSONSerialization.data(withJSONObject: object))
    }

    object["binding_kind"] = "evidence"
    object["schema"] = "other"
    #expect(throws: DecodingError.self) {
        try JSONDecoder().decode(Fixture.self, from: JSONSerialization.data(withJSONObject: object))
    }

    object["schema"] = "canonical-binary-v1"
    var timestamp = try #require(object["observed_at"] as? [String: Any])
    timestamp["unexpected"] = true
    object["observed_at"] = timestamp
    #expect(throws: DecodingError.self) {
        try JSONDecoder().decode(Fixture.self, from: JSONSerialization.data(withJSONObject: object))
    }
}

private func fixtureDirectory() -> URL {
    URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .deletingLastPathComponent()
        .appendingPathComponent("proto/fixtures/canonical-binary-v1")
}

private func activity(named value: String) -> CanonicalActivity? {
    switch value {
    case "absent": .absent
    case "unknown": .unknown
    case "inactive": .inactive
    case "active": .active
    default: nil
    }
}

private func coverage(named value: String) -> CanonicalCoverage? {
    switch value {
    case "unknown": .unknown
    case "complete": .complete
    case "partial": .partial
    case "unreadable": .unreadable
    case "failed": .failed
    default: nil
    }
}

private struct AnyCodingKey: CodingKey {
    let stringValue: String
    let intValue: Int? = nil

    init?(stringValue: String) {
        self.stringValue = stringValue
    }

    init?(intValue: Int) {
        return nil
    }
}

private func rejectUnknownKeys<Key>(from decoder: Decoder, allowed: Key.Type) throws
where Key: CodingKey & CaseIterable, Key.AllCases: Sequence {
    let allowedNames = Set(Key.allCases.map(\.stringValue))
    let container = try decoder.container(keyedBy: AnyCodingKey.self)
    if let unknown = container.allKeys.first(where: { !allowedNames.contains($0.stringValue) }) {
        throw DecodingError.dataCorrupted(
            .init(
                codingPath: decoder.codingPath + [unknown],
                debugDescription: "unknown field \(unknown.stringValue)"
            )
        )
    }
}

private extension Data {
    init?(hex: String) {
        guard hex.count.isMultiple(of: 2) else { return nil }
        var bytes: [UInt8] = []
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let byte = UInt8(hex[index..<next], radix: 16) else { return nil }
            bytes.append(byte)
            index = next
        }
        self.init(bytes)
    }

    var hexString: String {
        map { String(format: "%02x", $0) }.joined()
    }
}
