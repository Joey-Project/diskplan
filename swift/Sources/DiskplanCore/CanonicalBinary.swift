import CryptoKit
import Foundation

public struct CanonicalTimestamp: Codable, Equatable, Sendable {
    public let seconds: Int64
    public let nanos: UInt32

    public init(seconds: Int64, nanos: UInt32) {
        self.seconds = seconds
        self.nanos = nanos
    }
}

public enum CanonicalActivity: UInt8, Codable, Sendable {
    case absent = 0
    case unknown = 1
    case inactive = 2
    case active = 3
}

public enum CanonicalCoverage: UInt8, Codable, Sendable {
    case unknown = 0
    case complete = 1
    case partial = 2
    case unreadable = 3
    case failed = 4
}

public struct EvidenceBinding: Equatable, Sendable {
    public let candidateID: String
    public let rawPath: Data
    public let logicalBytes: UInt64
    public let observedAt: CanonicalTimestamp?
    public let activity: CanonicalActivity
    public let coverage: CanonicalCoverage
    public let labels: [String]

    public init(
        candidateID: String,
        rawPath: Data,
        logicalBytes: UInt64,
        observedAt: CanonicalTimestamp?,
        activity: CanonicalActivity,
        coverage: CanonicalCoverage,
        labels: [String]
    ) {
        self.candidateID = candidateID
        self.rawPath = rawPath
        self.logicalBytes = logicalBytes
        self.observedAt = observedAt
        self.activity = activity
        self.coverage = coverage
        self.labels = labels
    }
}

public enum CanonicalBinaryError: Error, Equatable, CustomStringConvertible {
    case truncated(field: String)
    case invalidMagic
    case unsupportedVersion(UInt16)
    case unknownVariant(field: String, value: UInt8)
    case invalidUTF8(field: String)
    case nonCanonicalLabels
    case invalidNanoseconds
    case nonCanonicalEncoding
    case trailingBytes
    case fieldTooLong(field: String)

    public var description: String {
        switch self {
        case .truncated(let field): "input ended while decoding \(field)"
        case .invalidMagic: "invalid canonical magic"
        case .unsupportedVersion(let version): "unsupported canonical version \(version)"
        case .unknownVariant(let field, let value): "unknown \(field) variant \(value)"
        case .invalidUTF8(let field): "invalid UTF-8 in \(field)"
        case .nonCanonicalLabels: "non-canonical label ordering"
        case .invalidNanoseconds: "timestamp nanoseconds out of range"
        case .nonCanonicalEncoding: "input is not the canonical encoding of its decoded value"
        case .trailingBytes: "trailing bytes after canonical record"
        case .fieldTooLong(let field): "field \(field) is too long"
        }
    }
}

public struct CanonicalEvidence: Equatable, Sendable {
    public let binding: EvidenceBinding
    public let bytes: Data
    public let digest: Data

    fileprivate init(binding: EvidenceBinding, bytes: Data, digest: Data) {
        self.binding = binding
        self.bytes = bytes
        self.digest = digest
    }
}

public enum CanonicalBinaryV1 {
    private static let magic = Data("DPCB".utf8)
    private static let version: UInt16 = 1
    private static let evidenceDomain = Data("diskplan/evidence/v1\0".utf8)

    public static func encodeEvidence(_ value: EvidenceBinding) throws -> Data {
        if let observedAt = value.observedAt, observedAt.nanos >= 1_000_000_000 {
            throw CanonicalBinaryError.invalidNanoseconds
        }
        var encoder = Encoder()
        encoder.append(magic)
        encoder.append(version)
        try encoder.append(value.candidateID, field: "candidate_id")
        try encoder.append(value.rawPath, field: "raw_path")
        encoder.append(value.logicalBytes)
        if let observedAt = value.observedAt {
            encoder.append(UInt8(1))
            encoder.append(observedAt.seconds)
            encoder.append(observedAt.nanos)
        } else {
            encoder.append(UInt8(0))
        }
        encoder.append(value.activity.rawValue)
        encoder.append(value.coverage.rawValue)
        let labels = canonicalLabels(value.labels)
        try encoder.appendCount(labels.count, field: "labels")
        for label in labels {
            try encoder.append(label, field: "label")
        }
        return encoder.data
    }

    public static func decodeEvidence(_ bytes: Data) throws -> EvidenceBinding {
        var decoder = Decoder(bytes)
        guard try decoder.take(4, field: "magic") == magic else {
            throw CanonicalBinaryError.invalidMagic
        }
        let decodedVersion: UInt16 = try decoder.integer(field: "version")
        guard decodedVersion == version else {
            throw CanonicalBinaryError.unsupportedVersion(decodedVersion)
        }
        let candidateID = try decoder.string(field: "candidate_id")
        let rawPath = try decoder.lengthPrefixed(field: "raw_path")
        let logicalBytes: UInt64 = try decoder.integer(field: "logical_bytes")
        let observedAt: CanonicalTimestamp?
        switch try decoder.byte(field: "observed_at variant") {
        case 0:
            observedAt = nil
        case 1:
            let seconds: Int64 = try decoder.integer(field: "observed_at seconds")
            let nanos: UInt32 = try decoder.integer(field: "observed_at nanos")
            guard nanos < 1_000_000_000 else {
                throw CanonicalBinaryError.invalidNanoseconds
            }
            observedAt = CanonicalTimestamp(seconds: seconds, nanos: nanos)
        case let value:
            throw CanonicalBinaryError.unknownVariant(field: "observed_at", value: value)
        }
        let activityValue = try decoder.byte(field: "activity")
        guard let activity = CanonicalActivity(rawValue: activityValue) else {
            throw CanonicalBinaryError.unknownVariant(field: "activity", value: activityValue)
        }
        let coverageValue = try decoder.byte(field: "coverage")
        guard let coverage = CanonicalCoverage(rawValue: coverageValue) else {
            throw CanonicalBinaryError.unknownVariant(field: "coverage", value: coverageValue)
        }
        let labelCount: UInt32 = try decoder.integer(field: "labels")
        guard UInt64(labelCount) <= UInt64(decoder.remainingCount / 4) else {
            throw CanonicalBinaryError.truncated(field: "labels")
        }
        var labels: [String] = []
        labels.reserveCapacity(Int(labelCount))
        for _ in 0..<labelCount {
            labels.append(try decoder.string(field: "label"))
        }
        let labelBytes = labels.map { Data($0.utf8) }
        guard zip(labelBytes, labelBytes.dropFirst()).allSatisfy({ $0.lexicographicallyPrecedes($1) }) else {
            throw CanonicalBinaryError.nonCanonicalLabels
        }
        guard decoder.isEmpty else {
            throw CanonicalBinaryError.trailingBytes
        }
        let binding = EvidenceBinding(
            candidateID: candidateID,
            rawPath: rawPath,
            logicalBytes: logicalBytes,
            observedAt: observedAt,
            activity: activity,
            coverage: coverage,
            labels: labels
        )
        guard try encodeEvidence(binding) == bytes else {
            throw CanonicalBinaryError.nonCanonicalEncoding
        }
        return binding
    }

    public static func bindEvidence(_ binding: EvidenceBinding) throws -> CanonicalEvidence {
        let bytes = try encodeEvidence(binding)
        let canonicalBinding = try decodeEvidence(bytes)
        return CanonicalEvidence(binding: canonicalBinding, bytes: bytes, digest: digest(bytes))
    }

    public static func verifyEvidence(_ bytes: Data) throws -> CanonicalEvidence {
        let binding = try decodeEvidence(bytes)
        return CanonicalEvidence(binding: binding, bytes: bytes, digest: digest(bytes))
    }

    private static func digest(_ canonicalBytes: Data) -> Data {
        var input = evidenceDomain
        input.append(canonicalBytes)
        return Data(SHA256.hash(data: input))
    }

    private static func canonicalLabels(_ labels: [String]) -> [String] {
        let sorted = labels.sorted {
            Data($0.utf8).lexicographicallyPrecedes(Data($1.utf8))
        }
        var result: [String] = []
        var previousBytes: Data?
        for label in sorted {
            let bytes = Data(label.utf8)
            if bytes != previousBytes {
                result.append(label)
                previousBytes = bytes
            }
        }
        return result
    }
}

private struct Encoder {
    var data = Data()

    mutating func append(_ bytes: Data) {
        data.append(bytes)
    }

    mutating func append<T: FixedWidthInteger>(_ value: T) {
        var value = value.bigEndian
        withUnsafeBytes(of: &value) { data.append(contentsOf: $0) }
    }

    mutating func appendCount(_ value: Int, field: String) throws {
        guard let value = UInt32(exactly: value) else {
            throw CanonicalBinaryError.fieldTooLong(field: field)
        }
        append(value)
    }

    mutating func append(_ bytes: Data, field: String) throws {
        try appendCount(bytes.count, field: field)
        append(bytes)
    }

    mutating func append(_ value: String, field: String) throws {
        try append(Data(value.utf8), field: field)
    }
}

private struct Decoder {
    private var bytes: Data
    private var offset = 0

    init(_ bytes: Data) {
        self.bytes = bytes
    }

    var isEmpty: Bool { offset == bytes.count }
    var remainingCount: Int { bytes.count - offset }

    mutating func take(_ count: Int, field: String) throws -> Data {
        guard count <= bytes.count - offset else {
            throw CanonicalBinaryError.truncated(field: field)
        }
        defer { offset += count }
        return bytes.subdata(in: offset..<(offset + count))
    }

    mutating func byte(field: String) throws -> UInt8 {
        try take(1, field: field).first!
    }

    mutating func integer<T: FixedWidthInteger>(field: String) throws -> T {
        let data = try take(MemoryLayout<T>.size, field: field)
        return data.reduce(T.zero) { ($0 << 8) | T($1) }
    }

    mutating func lengthPrefixed(field: String) throws -> Data {
        let length: UInt32 = try integer(field: field)
        guard let count = Int(exactly: length) else {
            throw CanonicalBinaryError.fieldTooLong(field: field)
        }
        return try take(count, field: field)
    }

    mutating func string(field: String) throws -> String {
        let data = try lengthPrefixed(field: field)
        guard let value = String(data: data, encoding: .utf8) else {
            throw CanonicalBinaryError.invalidUTF8(field: field)
        }
        return value
    }
}
