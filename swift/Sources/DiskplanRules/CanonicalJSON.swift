import Foundation

public enum CanonicalJSONError: Error, Equatable, Sendable {
  case emptyInput
  case inputTooLarge
  case invalidUTF8
  case unexpectedByte(offset: Int)
  case unexpectedEnd
  case depthLimitExceeded
  case collectionLimitExceeded
  case stringLimitExceeded
  case nonCanonicalEscape(offset: Int)
  case nonCanonicalInteger(offset: Int)
  case integerOutOfRange(offset: Int)
  case duplicateOrUnsortedKey(String)
  case trailingData(offset: Int)
  case nonCanonicalDocumentTermination
}

enum CanonicalJSONValue: Sendable {
  struct Entry: Sendable {
    let key: String
    let value: CanonicalJSONValue
  }

  case object([Entry])
  case array([CanonicalJSONValue])
  case string(String)
  case integer(Int64)
  case bool(Bool)
  case null
}

/// A deliberately small canonical JSON parser for security-sensitive policy input.
///
/// It accepts no insignificant whitespace, requires object keys to be in strictly increasing
/// decoded UTF-8 byte order, rejects duplicate keys before constructing an object, accepts only
/// signed 64-bit integers, and permits only shortest string escapes. Floats, NaN, Infinity,
/// non-minimal integers, escaped solidus, and non-ASCII `\u` escapes are outside this format.
struct CanonicalJSONParser {
  static let maximumInputBytes = 1_048_576
  static let maximumDepth = 32
  static let maximumCollectionEntries = 4_096
  static let maximumStringBytes = 65_536

  private let bytes: [UInt8]
  private var offset = 0

  init(data: Data) throws {
    guard !data.isEmpty else { throw CanonicalJSONError.emptyInput }
    guard data.count <= Self.maximumInputBytes else { throw CanonicalJSONError.inputTooLarge }
    guard data.last == UInt8(ascii: "\n"),
      data.dropLast().last != UInt8(ascii: "\n")
    else { throw CanonicalJSONError.nonCanonicalDocumentTermination }
    let document = data.dropLast()
    guard !document.isEmpty else { throw CanonicalJSONError.emptyInput }
    guard String(data: document, encoding: .utf8) != nil else {
      throw CanonicalJSONError.invalidUTF8
    }
    bytes = Array(document)
  }

  mutating func parse() throws -> CanonicalJSONValue {
    let value = try parseValue(depth: 0)
    guard offset == bytes.count else { throw CanonicalJSONError.trailingData(offset: offset) }
    return value
  }

  private mutating func parseValue(depth: Int) throws -> CanonicalJSONValue {
    guard depth <= Self.maximumDepth else { throw CanonicalJSONError.depthLimitExceeded }
    guard offset < bytes.count else { throw CanonicalJSONError.unexpectedEnd }
    switch bytes[offset] {
    case UInt8(ascii: "{"):
      return try parseObject(depth: depth)
    case UInt8(ascii: "["):
      return try parseArray(depth: depth)
    case UInt8(ascii: "\""):
      return .string(try parseString())
    case UInt8(ascii: "t"):
      try consumeLiteral("true")
      return .bool(true)
    case UInt8(ascii: "f"):
      try consumeLiteral("false")
      return .bool(false)
    case UInt8(ascii: "n"):
      try consumeLiteral("null")
      return .null
    case UInt8(ascii: "-"), UInt8(ascii: "0")...UInt8(ascii: "9"):
      return .integer(try parseInteger())
    default:
      throw CanonicalJSONError.unexpectedByte(offset: offset)
    }
  }

  private mutating func parseObject(depth: Int) throws -> CanonicalJSONValue {
    offset += 1
    if consume(UInt8(ascii: "}")) { return .object([]) }
    var entries: [CanonicalJSONValue.Entry] = []
    var previousKeyBytes: Data?
    while true {
      guard entries.count < Self.maximumCollectionEntries else {
        throw CanonicalJSONError.collectionLimitExceeded
      }
      guard offset < bytes.count, bytes[offset] == UInt8(ascii: "\"") else {
        throw CanonicalJSONError.unexpectedByte(offset: offset)
      }
      let key = try parseString()
      let keyBytes = Data(key.utf8)
      if let previousKeyBytes,
        !previousKeyBytes.lexicographicallyPrecedes(keyBytes)
      {
        throw CanonicalJSONError.duplicateOrUnsortedKey(key)
      }
      previousKeyBytes = keyBytes
      guard consume(UInt8(ascii: ":")) else {
        throw offset < bytes.count
          ? CanonicalJSONError.unexpectedByte(offset: offset)
          : CanonicalJSONError.unexpectedEnd
      }
      entries.append(
        CanonicalJSONValue.Entry(key: key, value: try parseValue(depth: depth + 1))
      )
      if consume(UInt8(ascii: "}")) { break }
      guard consume(UInt8(ascii: ",")) else {
        throw offset < bytes.count
          ? CanonicalJSONError.unexpectedByte(offset: offset)
          : CanonicalJSONError.unexpectedEnd
      }
    }
    return .object(entries)
  }

  private mutating func parseArray(depth: Int) throws -> CanonicalJSONValue {
    offset += 1
    if consume(UInt8(ascii: "]")) { return .array([]) }
    var values: [CanonicalJSONValue] = []
    while true {
      guard values.count < Self.maximumCollectionEntries else {
        throw CanonicalJSONError.collectionLimitExceeded
      }
      values.append(try parseValue(depth: depth + 1))
      if consume(UInt8(ascii: "]")) { break }
      guard consume(UInt8(ascii: ",")) else {
        throw offset < bytes.count
          ? CanonicalJSONError.unexpectedByte(offset: offset)
          : CanonicalJSONError.unexpectedEnd
      }
    }
    return .array(values)
  }

  private mutating func parseString() throws -> String {
    precondition(offset < bytes.count && bytes[offset] == UInt8(ascii: "\""))
    offset += 1
    var decoded: [UInt8] = []
    decoded.reserveCapacity(32)
    while offset < bytes.count {
      let byte = bytes[offset]
      offset += 1
      if byte == UInt8(ascii: "\"") {
        guard let string = String(bytes: decoded, encoding: .utf8) else {
          throw CanonicalJSONError.invalidUTF8
        }
        return string
      }
      if byte == UInt8(ascii: "\\") {
        let escapeOffset = offset - 1
        guard offset < bytes.count else { throw CanonicalJSONError.unexpectedEnd }
        let escaped = bytes[offset]
        offset += 1
        switch escaped {
        case UInt8(ascii: "\""):
          decoded.append(UInt8(ascii: "\""))
        case UInt8(ascii: "\\"):
          decoded.append(UInt8(ascii: "\\"))
        case UInt8(ascii: "b"):
          decoded.append(0x08)
        case UInt8(ascii: "f"):
          decoded.append(0x0C)
        case UInt8(ascii: "n"):
          decoded.append(0x0A)
        case UInt8(ascii: "r"):
          decoded.append(0x0D)
        case UInt8(ascii: "t"):
          decoded.append(0x09)
        case UInt8(ascii: "u"):
          let value = try parseCanonicalControlEscape(at: escapeOffset)
          decoded.append(value)
        default:
          throw CanonicalJSONError.nonCanonicalEscape(offset: escapeOffset)
        }
      } else {
        guard byte >= 0x20 else {
          throw CanonicalJSONError.nonCanonicalEscape(offset: offset - 1)
        }
        decoded.append(byte)
      }
      guard decoded.count <= Self.maximumStringBytes else {
        throw CanonicalJSONError.stringLimitExceeded
      }
    }
    throw CanonicalJSONError.unexpectedEnd
  }

  private mutating func parseCanonicalControlEscape(at escapeOffset: Int) throws -> UInt8 {
    guard offset + 4 <= bytes.count else { throw CanonicalJSONError.unexpectedEnd }
    let digits = bytes[offset..<(offset + 4)]
    offset += 4
    guard digits[digits.startIndex] == UInt8(ascii: "0"),
      digits[digits.index(after: digits.startIndex)] == UInt8(ascii: "0"),
      let high = uppercaseHex(digits[digits.index(digits.startIndex, offsetBy: 2)]),
      let low = uppercaseHex(digits[digits.index(digits.startIndex, offsetBy: 3)])
    else {
      throw CanonicalJSONError.nonCanonicalEscape(offset: escapeOffset)
    }
    let value = high << 4 | low
    guard value < 0x20, ![0x08, 0x09, 0x0A, 0x0C, 0x0D].contains(value) else {
      throw CanonicalJSONError.nonCanonicalEscape(offset: escapeOffset)
    }
    return value
  }

  private func uppercaseHex(_ byte: UInt8) -> UInt8? {
    switch byte {
    case UInt8(ascii: "0")...UInt8(ascii: "9"):
      byte - UInt8(ascii: "0")
    case UInt8(ascii: "A")...UInt8(ascii: "F"):
      byte - UInt8(ascii: "A") + 10
    default:
      nil
    }
  }

  private mutating func parseInteger() throws -> Int64 {
    let start = offset
    if consume(UInt8(ascii: "-")) {
      guard offset < bytes.count else { throw CanonicalJSONError.unexpectedEnd }
      guard bytes[offset] != UInt8(ascii: "0") else {
        throw CanonicalJSONError.nonCanonicalInteger(offset: start)
      }
    }
    guard offset < bytes.count else { throw CanonicalJSONError.unexpectedEnd }
    if bytes[offset] == UInt8(ascii: "0") {
      offset += 1
    } else {
      guard (UInt8(ascii: "1")...UInt8(ascii: "9")).contains(bytes[offset]) else {
        throw CanonicalJSONError.nonCanonicalInteger(offset: start)
      }
      while offset < bytes.count,
        (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(bytes[offset])
      {
        offset += 1
      }
    }
    if offset < bytes.count,
      bytes[offset] == UInt8(ascii: ".") || bytes[offset] == UInt8(ascii: "e")
        || bytes[offset] == UInt8(ascii: "E")
    {
      throw CanonicalJSONError.nonCanonicalInteger(offset: start)
    }
    let text = String(decoding: bytes[start..<offset], as: UTF8.self)
    guard let value = Int64(text) else {
      throw CanonicalJSONError.integerOutOfRange(offset: start)
    }
    return value
  }

  private mutating func consumeLiteral(_ literal: String) throws {
    let expected = Array(literal.utf8)
    guard offset + expected.count <= bytes.count else {
      throw CanonicalJSONError.unexpectedEnd
    }
    guard Array(bytes[offset..<(offset + expected.count)]) == expected else {
      throw CanonicalJSONError.unexpectedByte(offset: offset)
    }
    offset += expected.count
  }

  private mutating func consume(_ byte: UInt8) -> Bool {
    guard offset < bytes.count, bytes[offset] == byte else { return false }
    offset += 1
    return true
  }
}

extension CanonicalJSONValue {
  var objectEntries: [Entry]? {
    guard case .object(let entries) = self else { return nil }
    return entries
  }

  var arrayValues: [CanonicalJSONValue]? {
    guard case .array(let values) = self else { return nil }
    return values
  }

  var stringValue: String? {
    guard case .string(let value) = self else { return nil }
    return value
  }

  var integerValue: Int64? {
    guard case .integer(let value) = self else { return nil }
    return value
  }

  var boolValue: Bool? {
    guard case .bool(let value) = self else { return nil }
    return value
  }
}
