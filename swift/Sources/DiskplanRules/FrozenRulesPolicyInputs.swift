import CryptoKit
import Foundation

/// Closed, path-neutral reasons why a policy input could not be verified.
public enum FrozenRulesPolicyInputFailure: String, Equatable, Sendable {
  case missing
  case unreadable
  case invalidCanonicalDocument = "invalid-canonical-document"
  case invalidPolicy
  case oversized
  case invalidSourceIdentity = "invalid-source-identity"
  case unavailable
}

/// A required policy input supplied as bytes by its caller, or an already classified failure.
/// Construction interprets data only; it does not read a path or grant filesystem authority.
public enum FrozenRulesRequiredInput: Equatable, Sendable {
  case canonicalBytes(Data)
  case unavailable(FrozenRulesPolicyInputFailure)
}

public enum FrozenRulesPolicySourceIdentityError: Error, Equatable, Sendable {
  case empty
  case containsNUL
  case tooLong
}

/// Bounded provenance bytes for an explicitly requested overlay. They are not a path capability.
public struct FrozenRulesPolicySourceIdentity: Equatable, Sendable {
  public static let maximumByteCount = 4_096

  public let rawBytes: Data

  public init(rawBytes: Data) throws {
    guard !rawBytes.isEmpty else { throw FrozenRulesPolicySourceIdentityError.empty }
    guard rawBytes.count <= Self.maximumByteCount else {
      throw FrozenRulesPolicySourceIdentityError.tooLong
    }
    guard !rawBytes.contains(0) else { throw FrozenRulesPolicySourceIdentityError.containsNUL }
    self.rawBytes = rawBytes
  }
}

/// An optional overlay request. `notRequested` is an explicit, valid no-overlay state.
public enum FrozenRulesOverlayInput: Equatable, Sendable {
  case notRequested
  case requested(canonicalBytes: Data, sourceIdentity: FrozenRulesPolicySourceIdentity)
  case requestedUnavailable(
    sourceIdentity: FrozenRulesPolicySourceIdentity?, failure: FrozenRulesPolicyInputFailure)
}

public enum FrozenRulesRequiredInputState: Equatable, Sendable {
  case verified(assetDigest: RulesDigest, rawInputDigest: Data)
  case unusable(
    failure: FrozenRulesPolicyInputFailure,
    byteCount: UInt64,
    rawInputDigest: Data?
  )

}

public enum FrozenRulesOverlayState: Equatable, Sendable {
  case none
  case verified(sourceIdentity: FrozenRulesPolicySourceIdentity, assetDigest: RulesDigest)
  case policyUnverified(
    sourceIdentity: FrozenRulesPolicySourceIdentity?,
    failure: FrozenRulesPolicyInputFailure,
    byteCount: UInt64?,
    rejectedInputDigest: Data?
  )
}

public enum FrozenRulesPolicyInputsState: Equatable, Sendable {
  case verifiedNone
  case verifiedOverlay
  case policyUnverified
  case requiredBaselineUnusable
}

/// Digest for the complete, framed Rules input snapshot, including overlay intent and provenance.
public struct FrozenRulesPolicyInputsDigest: Equatable, Hashable, Sendable, CustomStringConvertible
{
  public let bytes: Data

  fileprivate init(fields: [Data]) {
    var framed = Data("diskplan/rules-policy-inputs/v1\0".utf8)
    var fieldCount = UInt64(fields.count).bigEndian
    withUnsafeBytes(of: &fieldCount) { framed.append(contentsOf: $0) }
    for field in fields {
      var byteCount = UInt64(field.count).bigEndian
      withUnsafeBytes(of: &byteCount) { framed.append(contentsOf: $0) }
      framed.append(field)
    }
    bytes = Data(SHA256.hash(data: framed))
  }

  public var description: String { bytes.map { String(format: "%02x", $0) }.joined() }
}

/// Immutable interpretation of required bundled policy inputs and an optional user overlay.
/// It carries no file-reading, path, environment, or execution permission.
public struct FrozenRulesPolicyInputs: Equatable, Sendable {
  public static let maximumCanonicalInputBytes = CanonicalJSONParser.maximumInputBytes

  public let builtInRulesState: FrozenRulesRequiredInputState
  public let defaultPolicyState: FrozenRulesRequiredInputState
  public let overlayState: FrozenRulesOverlayState
  public let state: FrozenRulesPolicyInputsState
  public let planningConfiguration: RulesConfiguration?
  public let mutationConfiguration: RulesConfiguration?
  public let bindingDigest: FrozenRulesPolicyInputsDigest

  // Retain accepted bytes as part of the immutable snapshot. Oversized inputs are never retained.
  private let builtInRulesBytes: Data?
  private let defaultPolicyBytes: Data?
  private let overlayBytes: Data?

  public var isMutationEligible: Bool { mutationConfiguration != nil }

  /// Uses the generated, compile-time asset bytes as the required baseline.
  public init(overlayInput: FrozenRulesOverlayInput = .notRequested) {
    self.init(
      builtInRulesInput: .canonicalBytes(BundledRuleAssets.builtInRulesData),
      defaultPolicyInput: .canonicalBytes(BundledRuleAssets.defaultPolicyData),
      overlayInput: overlayInput
    )
  }

  /// Interprets caller-bound bytes. The caller owns acquisition and custody of those bytes.
  public init(
    builtInRulesInput: FrozenRulesRequiredInput,
    defaultPolicyInput: FrozenRulesRequiredInput,
    overlayInput: FrozenRulesOverlayInput = .notRequested
  ) {
    let builtIn = Self.loadBuiltInRules(builtInRulesInput)
    let defaultPolicy = Self.loadDefaultPolicy(defaultPolicyInput)
    let baselineConfiguration: RulesConfiguration?
    if let rules = builtIn.policy, let policy = defaultPolicy.policy {
      baselineConfiguration = RulesConfiguration(bundled: rules, user: policy)
    } else {
      baselineConfiguration = nil
    }

    let loadedOverlay = Self.loadOverlay(overlayInput)
    let selectedConfiguration: RulesConfiguration?
    if let rules = builtIn.policy {
      if let overlay = loadedOverlay.policy {
        selectedConfiguration = RulesConfiguration(bundled: rules, user: overlay)
      } else {
        selectedConfiguration = baselineConfiguration
      }
    } else {
      selectedConfiguration = nil
    }

    let baselineUsable = baselineConfiguration != nil
    let mutationConfiguration: RulesConfiguration?
    switch loadedOverlay.state {
    case .none, .verified:
      mutationConfiguration = baselineUsable ? selectedConfiguration : nil
    case .policyUnverified:
      mutationConfiguration = nil
    }

    builtInRulesState = builtIn.state
    defaultPolicyState = defaultPolicy.state
    overlayState = loadedOverlay.state
    planningConfiguration = selectedConfiguration
    self.mutationConfiguration = mutationConfiguration
    builtInRulesBytes = builtIn.retainedBytes
    defaultPolicyBytes = defaultPolicy.retainedBytes
    overlayBytes = loadedOverlay.retainedBytes

    if !baselineUsable {
      state = .requiredBaselineUnusable
    } else {
      switch loadedOverlay.state {
      case .none: state = .verifiedNone
      case .verified: state = .verifiedOverlay
      case .policyUnverified: state = .policyUnverified
      }
    }

    bindingDigest = Self.makeBindingDigest(
      builtInState: builtIn.state,
      defaultPolicyState: defaultPolicy.state,
      overlayState: loadedOverlay.state,
      effectiveConfigurationDigest: selectedConfiguration?.effectiveDigest,
      mutationEligible: mutationConfiguration != nil
    )
  }

  private struct LoadedBuiltInRules {
    let state: FrozenRulesRequiredInputState
    let policy: BundledRuleSet?
    let retainedBytes: Data?
  }

  private struct LoadedDefaultPolicy {
    let state: FrozenRulesRequiredInputState
    let policy: RestrictedUserPolicy?
    let retainedBytes: Data?
  }

  private struct LoadedOverlay {
    let state: FrozenRulesOverlayState
    let policy: RestrictedUserPolicy?
    let retainedBytes: Data?
  }

  private static func loadBuiltInRules(_ input: FrozenRulesRequiredInput) -> LoadedBuiltInRules {
    switch input {
    case .unavailable(let failure):
      return LoadedBuiltInRules(
        state: .unusable(failure: failure, byteCount: 0, rawInputDigest: nil),
        policy: nil,
        retainedBytes: nil
      )
    case .canonicalBytes(let bytes):
      guard bytes.count <= maximumCanonicalInputBytes else {
        return LoadedBuiltInRules(
          state: .unusable(
            failure: .oversized, byteCount: UInt64(bytes.count), rawInputDigest: nil),
          policy: nil,
          retainedBytes: nil
        )
      }
      let rawDigest = Self.sha256(bytes)
      do {
        let rules = try BundledRuleSetLoader.load(canonicalData: bytes)
        return LoadedBuiltInRules(
          state: .verified(assetDigest: rules.digest, rawInputDigest: rawDigest),
          policy: rules,
          retainedBytes: bytes
        )
      } catch let error as RulesLoadError {
        return LoadedBuiltInRules(
          state: .unusable(
            failure: Self.failureCode(for: error),
            byteCount: UInt64(bytes.count),
            rawInputDigest: rawDigest
          ),
          policy: nil,
          retainedBytes: bytes
        )
      } catch {
        return LoadedBuiltInRules(
          state: .unusable(
            failure: .invalidPolicy, byteCount: UInt64(bytes.count), rawInputDigest: rawDigest),
          policy: nil,
          retainedBytes: bytes
        )
      }
    }
  }

  private static func loadDefaultPolicy(_ input: FrozenRulesRequiredInput) -> LoadedDefaultPolicy {
    switch input {
    case .unavailable(let failure):
      return LoadedDefaultPolicy(
        state: .unusable(failure: failure, byteCount: 0, rawInputDigest: nil),
        policy: nil,
        retainedBytes: nil
      )
    case .canonicalBytes(let bytes):
      guard bytes.count <= maximumCanonicalInputBytes else {
        return LoadedDefaultPolicy(
          state: .unusable(
            failure: .oversized, byteCount: UInt64(bytes.count), rawInputDigest: nil),
          policy: nil,
          retainedBytes: nil
        )
      }
      let rawDigest = Self.sha256(bytes)
      do {
        let policy = try RestrictedUserPolicyLoader.load(canonicalData: bytes)
        return LoadedDefaultPolicy(
          state: .verified(assetDigest: policy.digest, rawInputDigest: rawDigest),
          policy: policy,
          retainedBytes: bytes
        )
      } catch let error as RulesLoadError {
        return LoadedDefaultPolicy(
          state: .unusable(
            failure: Self.failureCode(for: error),
            byteCount: UInt64(bytes.count),
            rawInputDigest: rawDigest
          ),
          policy: nil,
          retainedBytes: bytes
        )
      } catch {
        return LoadedDefaultPolicy(
          state: .unusable(
            failure: .invalidPolicy, byteCount: UInt64(bytes.count), rawInputDigest: rawDigest),
          policy: nil,
          retainedBytes: bytes
        )
      }
    }
  }

  private static func loadOverlay(_ input: FrozenRulesOverlayInput) -> LoadedOverlay {
    switch input {
    case .notRequested:
      return LoadedOverlay(state: .none, policy: nil, retainedBytes: nil)
    case .requestedUnavailable(let sourceIdentity, let failure):
      return LoadedOverlay(
        state: .policyUnverified(
          sourceIdentity: sourceIdentity,
          failure: failure,
          byteCount: nil,
          rejectedInputDigest: nil
        ),
        policy: nil,
        retainedBytes: nil
      )
    case .requested(let bytes, let sourceIdentity):
      guard bytes.count <= maximumCanonicalInputBytes else {
        return LoadedOverlay(
          state: .policyUnverified(
            sourceIdentity: sourceIdentity,
            failure: .oversized,
            byteCount: UInt64(bytes.count),
            rejectedInputDigest: nil
          ),
          policy: nil,
          retainedBytes: nil
        )
      }
      let rawDigest = Self.sha256(bytes)
      do {
        let policy = try RestrictedUserPolicyLoader.load(canonicalData: bytes)
        return LoadedOverlay(
          state: .verified(sourceIdentity: sourceIdentity, assetDigest: policy.digest),
          policy: policy,
          retainedBytes: bytes
        )
      } catch let error as RulesLoadError {
        return LoadedOverlay(
          state: .policyUnverified(
            sourceIdentity: sourceIdentity,
            failure: Self.failureCode(for: error),
            byteCount: UInt64(bytes.count),
            rejectedInputDigest: rawDigest
          ),
          policy: nil,
          retainedBytes: bytes
        )
      } catch {
        return LoadedOverlay(
          state: .policyUnverified(
            sourceIdentity: sourceIdentity,
            failure: .invalidPolicy,
            byteCount: UInt64(bytes.count),
            rejectedInputDigest: rawDigest
          ),
          policy: nil,
          retainedBytes: bytes
        )
      }
    }
  }

  private static func failureCode(for error: RulesLoadError) -> FrozenRulesPolicyInputFailure {
    if case .malformedCanonicalJSON = error { return .invalidCanonicalDocument }
    return .invalidPolicy
  }

  private static func sha256(_ bytes: Data) -> Data {
    Data(SHA256.hash(data: bytes))
  }

  private static func makeBindingDigest(
    builtInState: FrozenRulesRequiredInputState,
    defaultPolicyState: FrozenRulesRequiredInputState,
    overlayState: FrozenRulesOverlayState,
    effectiveConfigurationDigest: RulesDigest?,
    mutationEligible: Bool
  ) -> FrozenRulesPolicyInputsDigest {
    var fields: [Data] = []
    appendRequiredState(builtInState, label: "built-in-rules", to: &fields)
    appendRequiredState(defaultPolicyState, label: "default-policy", to: &fields)

    switch overlayState {
    case .none:
      fields.append(Data("overlay-state".utf8))
      fields.append(Data("none".utf8))
      fields.append(Data("overlay-source-identity".utf8))
      fields.append(Data())
      fields.append(Data("overlay-input-byte-count".utf8))
      fields.append(Data())
      fields.append(Data("overlay-input-digest".utf8))
      fields.append(Data())
      fields.append(Data("overlay-asset-digest".utf8))
      fields.append(Data())
    case .verified(let sourceIdentity, let assetDigest):
      fields.append(Data("overlay-state".utf8))
      fields.append(Data("verified".utf8))
      fields.append(Data("overlay-source-identity".utf8))
      fields.append(sourceIdentity.rawBytes)
      fields.append(Data("overlay-input-byte-count".utf8))
      fields.append(Data())
      fields.append(Data("overlay-input-digest".utf8))
      fields.append(Data())
      fields.append(Data("overlay-asset-digest".utf8))
      fields.append(assetDigest.bytes)
    case .policyUnverified(let sourceIdentity, let failure, let byteCount, let rejectedDigest):
      fields.append(Data("overlay-state".utf8))
      fields.append(Data("policy-unverified".utf8))
      fields.append(Data("overlay-failure".utf8))
      fields.append(Data(failure.rawValue.utf8))
      fields.append(Data("overlay-source-identity".utf8))
      fields.append(sourceIdentity?.rawBytes ?? Data())
      fields.append(Data("overlay-input-byte-count".utf8))
      fields.append(byteCount.map(Self.encodeUInt64) ?? Data())
      fields.append(Data("overlay-input-digest".utf8))
      fields.append(rejectedDigest ?? Data())
      fields.append(Data("overlay-asset-digest".utf8))
      fields.append(Data())
    }

    fields.append(Data("effective-configuration-digest".utf8))
    fields.append(effectiveConfigurationDigest?.bytes ?? Data())
    fields.append(Data("mutation-eligible".utf8))
    fields.append(Data((mutationEligible ? "true" : "false").utf8))
    return FrozenRulesPolicyInputsDigest(fields: fields)
  }

  private static func appendRequiredState(
    _ state: FrozenRulesRequiredInputState,
    label: String,
    to fields: inout [Data]
  ) {
    fields.append(Data((label + ".state").utf8))
    switch state {
    case .verified(let assetDigest, let rawInputDigest):
      fields.append(Data("verified".utf8))
      fields.append(Data((label + ".asset-digest").utf8))
      fields.append(assetDigest.bytes)
      fields.append(Data((label + ".raw-input-digest").utf8))
      fields.append(rawInputDigest)
      fields.append(Data((label + ".byte-count").utf8))
      fields.append(Data())
    case .unusable(let failure, let byteCount, let rawInputDigest):
      fields.append(Data("unusable".utf8))
      fields.append(Data((label + ".failure").utf8))
      fields.append(Data(failure.rawValue.utf8))
      fields.append(Data((label + ".asset-digest").utf8))
      fields.append(Data())
      fields.append(Data((label + ".raw-input-digest").utf8))
      fields.append(rawInputDigest ?? Data())
      fields.append(Data((label + ".byte-count").utf8))
      fields.append(Self.encodeUInt64(byteCount))
    }
  }

  private static func encodeUInt64(_ value: UInt64) -> Data {
    var bigEndian = value.bigEndian
    return withUnsafeBytes(of: &bigEndian) { Data($0) }
  }
}
