import DiskplanCore
import Foundation

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

@main
struct DiskplanFixtureGenerator {
    static func main() throws {
        let arguments = CommandLine.arguments
        guard arguments.count == 3 else {
            FileHandle.standardError.write(
                Data("usage: diskplan-fixture-generator <input.json> <output-directory>\n".utf8)
            )
            Foundation.exit(64)
        }
        let inputURL = URL(fileURLWithPath: arguments[1])
        let outputURL = URL(fileURLWithPath: arguments[2], isDirectory: true)
        let fixture = try JSONDecoder().decode(Fixture.self, from: Data(contentsOf: inputURL))
        guard let rawPath = Data(hex: fixture.rawPathHex) else {
            throw GeneratorError.invalidHex
        }
        guard let activity = activity(named: fixture.activity),
              let coverage = coverage(named: fixture.coverage)
        else {
            throw GeneratorError.unknownVariant
        }
        let binding = EvidenceBinding(
            candidateID: fixture.candidateID,
            rawPath: rawPath,
            logicalBytes: fixture.logicalBytes,
            observedAt: fixture.observedAt.map {
                CanonicalTimestamp(seconds: $0.seconds, nanos: $0.nanos)
            },
            activity: activity,
            coverage: coverage,
            labels: fixture.labels
        )
        let authored = try CanonicalBinaryV1.bindEvidence(binding)
        try FileManager.default.createDirectory(at: outputURL, withIntermediateDirectories: true)
        try authored.bytes.write(to: outputURL.appendingPathComponent("evidence.bin"), options: .atomic)
        try Data((authored.digest.hexString + "\n").utf8).write(
            to: outputURL.appendingPathComponent("evidence.sha256"),
            options: .atomic
        )
    }

    private static func activity(named value: String) -> CanonicalActivity? {
        switch value {
        case "absent": .absent
        case "unknown": .unknown
        case "inactive": .inactive
        case "active": .active
        default: nil
        }
    }

    private static func coverage(named value: String) -> CanonicalCoverage? {
        switch value {
        case "unknown": .unknown
        case "complete": .complete
        case "partial": .partial
        case "unreadable": .unreadable
        case "failed": .failed
        default: nil
        }
    }
}

private enum GeneratorError: Error {
    case invalidHex
    case unknownVariant
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
        bytes.reserveCapacity(hex.count / 2)
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
