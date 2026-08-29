import Foundation

enum CredentialShapeClassifier {
  enum AuthorizationScheme: String, Equatable, Sendable {
    case apiKey = "api-key"
    case basic
    case bearer
    case digest
  }

  enum Reason: Equatable, Sendable {
    case authorizationScheme(AuthorizationScheme)
    case explicitPrefix
    case jwt
    case opaqueToken
    case standardBase64
  }

  private static let explicitPrefixes = [
    Data("ghp_".utf8), Data("gho_".utf8), Data("ghu_".utf8), Data("ghs_".utf8),
    Data("ghr_".utf8), Data("github_pat_".utf8), Data("sk-".utf8), Data("AKIA".utf8),
    Data("ASIA".utf8), Data("codex_synth_v1_".utf8), Data("-----BEGIN ".utf8),
  ]
  private static let authorizationPatterns: [(AuthorizationScheme, [UInt8])] = [
    (.apiKey, Array("api-key".utf8)),
    (.apiKey, Array("api_key".utf8)),
    (.apiKey, Array("apikey".utf8)),
    (.apiKey, Array("x-api-key".utf8)),
    (.basic, Array("basic".utf8)),
    (.bearer, Array("bearer".utf8)),
    (.digest, Array("digest".utf8)),
  ]

  static func containsCredentialLikeSequence(_ value: Data) -> Bool {
    classify(value) != nil
  }

  static func containsIdentifierAuthorizationScheme(_ value: Data) -> Bool {
    let bytes = Array(value)
    for start in bytes.indices {
      guard start == bytes.startIndex || isIdentifierSeparator(bytes[bytes.index(before: start)])
      else { continue }
      for (_, pattern) in authorizationPatterns {
        guard matchesASCIICaseInsensitive(bytes, pattern: pattern, at: start) else { continue }
        let end = start + pattern.count
        guard end < bytes.count, isIdentifierSeparator(bytes[end]) else { continue }
        var payload = end
        while payload < bytes.count, isIdentifierSeparator(bytes[payload]) { payload += 1 }
        if payload < bytes.count { return true }
      }
    }
    return false
  }

  static func classify(_ value: Data) -> Reason? {
    guard !value.isEmpty else { return nil }
    if containsExplicitPrefix(value) { return .explicitPrefix }
    if let scheme = authorizationScheme(in: value) { return .authorizationScheme(scheme) }
    if jwtLike(value) { return .jwt }
    if standardBase64Like(value) { return .standardBase64 }

    var runLength = 0
    var hasLetter = false
    var hasDigit = false
    var isHexadecimal = true
    for byte in value {
      if isTokenByte(byte) {
        runLength += 1
        hasLetter = hasLetter || isASCIILetter(byte)
        hasDigit = hasDigit || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
        isHexadecimal = isHexadecimal && isASCIIHex(byte)
      } else {
        if opaqueRunIsCredentialLike(
          length: runLength,
          hasLetter: hasLetter,
          hasDigit: hasDigit,
          isHexadecimal: isHexadecimal
        ) {
          return .opaqueToken
        }
        runLength = 0
        hasLetter = false
        hasDigit = false
        isHexadecimal = true
      }
    }
    return opaqueRunIsCredentialLike(
      length: runLength,
      hasLetter: hasLetter,
      hasDigit: hasDigit,
      isHexadecimal: isHexadecimal
    ) ? .opaqueToken : nil
  }

  private static func authorizationScheme(in value: Data) -> AuthorizationScheme? {
    let bytes = Array(value)
    for start in bytes.indices {
      guard start == bytes.startIndex || isSchemeBoundary(bytes[bytes.index(before: start)]) else {
        continue
      }
      for (scheme, pattern) in authorizationPatterns {
        guard matchesASCIICaseInsensitive(bytes, pattern: pattern, at: start) else { continue }
        let end = start + pattern.count
        if payloadFollows(bytes, after: end, allowsColon: scheme == .apiKey) { return scheme }
      }
    }
    return nil
  }

  private static func containsExplicitPrefix(_ value: Data) -> Bool {
    let bytes = Array(value)
    for start in bytes.indices {
      guard start == bytes.startIndex || isSchemeBoundary(bytes[bytes.index(before: start)]) else {
        continue
      }
      for prefix in explicitPrefixes {
        let pattern = Array(prefix)
        guard start + pattern.count < bytes.count else { continue }
        if Array(bytes[start..<(start + pattern.count)]) == pattern { return true }
      }
    }
    return false
  }

  private static func matchesASCIICaseInsensitive(
    _ bytes: [UInt8], pattern: [UInt8], at start: Int
  ) -> Bool {
    guard start + pattern.count <= bytes.count else { return false }
    return pattern.indices.allSatisfy {
      asciiLowercased(bytes[start + $0]) == pattern[$0]
    }
  }

  private static func payloadFollows(
    _ bytes: [UInt8], after patternEnd: Int, allowsColon: Bool
  ) -> Bool {
    guard patternEnd < bytes.count else { return false }
    var cursor = patternEnd
    if allowsColon,
      bytes[cursor] == UInt8(ascii: ":") || bytes[cursor] == UInt8(ascii: "=")
    {
      cursor += 1
    } else {
      guard isHorizontalWhitespace(bytes[cursor]) else { return false }
    }
    while cursor < bytes.count, isHorizontalWhitespace(bytes[cursor]) { cursor += 1 }
    return cursor < bytes.count
  }

  private static func asciiLowercased(_ byte: UInt8) -> UInt8 {
    if (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte) {
      return byte + (UInt8(ascii: "a") - UInt8(ascii: "A"))
    }
    return byte
  }

  private static func isHorizontalWhitespace(_ byte: UInt8) -> Bool {
    byte == UInt8(ascii: " ") || byte == UInt8(ascii: "\t")
  }

  private static func isSchemeBoundary(_ byte: UInt8) -> Bool {
    !isASCIILetter(byte) && !(UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
      && byte != UInt8(ascii: "_") && byte != UInt8(ascii: "-")
  }

  private static func isIdentifierSeparator(_ byte: UInt8) -> Bool {
    [UInt8(ascii: "."), UInt8(ascii: "_"), UInt8(ascii: "/"), UInt8(ascii: "-")]
      .contains(byte)
  }

  private static func jwtLike(_ value: Data) -> Bool {
    let segments = value.split(separator: UInt8(ascii: "."), omittingEmptySubsequences: false)
    return segments.count == 3
      && segments.allSatisfy { segment in
        segment.count >= 8 && segment.allSatisfy(Self.isTokenByte)
      }
  }

  private static func standardBase64Like(_ value: Data) -> Bool {
    value.split(omittingEmptySubsequences: true, whereSeparator: { !isStandardBase64Byte($0) })
      .contains { run in
        guard run.count >= 32, run.count % 4 != 1 else { return false }
        let paddingCount = run.reversed().prefix(while: { $0 == UInt8(ascii: "=") }).count
        guard paddingCount <= 2,
          !run.dropLast(paddingCount).contains(UInt8(ascii: "="))
        else { return false }
        let body = run.dropLast(paddingCount)
        if paddingCount > 0 {
          guard run.count.isMultiple(of: 4),
            body.count % 4 == (paddingCount == 2 ? 2 : 3)
          else { return false }
        }
        return body.contains(where: isASCIIUppercase)
          && body.contains(where: isASCIILowercase)
          && body.contains(where: isASCIIDigit)
          && (paddingCount > 0
            || body.contains(UInt8(ascii: "+")) || body.contains(UInt8(ascii: "/")))
      }
  }

  private static func opaqueRunIsCredentialLike(
    length: Int,
    hasLetter: Bool,
    hasDigit: Bool,
    isHexadecimal: Bool
  ) -> Bool {
    guard length >= 32, hasLetter, hasDigit else { return false }
    let commonHexDigestLengths: Set<Int> = [32, 40, 56, 64, 96, 128]
    return !isHexadecimal || !commonHexDigestLengths.contains(length)
  }

  private static func isStandardBase64Byte(_ byte: UInt8) -> Bool {
    isASCIILetter(byte) || isASCIIDigit(byte) || byte == UInt8(ascii: "+")
      || byte == UInt8(ascii: "/") || byte == UInt8(ascii: "=")
  }

  private static func isASCIIHex(_ byte: UInt8) -> Bool {
    isASCIIDigit(byte) || (UInt8(ascii: "a")...UInt8(ascii: "f")).contains(byte)
      || (UInt8(ascii: "A")...UInt8(ascii: "F")).contains(byte)
  }

  private static func isASCIIUppercase(_ byte: UInt8) -> Bool {
    (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte)
  }

  private static func isASCIILowercase(_ byte: UInt8) -> Bool {
    (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte)
  }

  private static func isASCIIDigit(_ byte: UInt8) -> Bool {
    (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
  }

  private static func isTokenByte(_ byte: UInt8) -> Bool {
    isASCIILetter(byte) || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains(byte)
      || byte == UInt8(ascii: "_") || byte == UInt8(ascii: "-")
  }

  private static func isASCIILetter(_ byte: UInt8) -> Bool {
    (UInt8(ascii: "a")...UInt8(ascii: "z")).contains(byte)
      || (UInt8(ascii: "A")...UInt8(ascii: "Z")).contains(byte)
  }
}
