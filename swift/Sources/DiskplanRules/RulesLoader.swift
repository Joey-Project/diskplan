import DiskplanPolicy
import Foundation

public enum RulesLoadError: Error, Equatable, Sendable {
  case malformedCanonicalJSON(CanonicalJSONError)
  case expectedObject(String)
  case expectedArray(String)
  case expectedString(String)
  case expectedInteger(String)
  case expectedBoolean(String)
  case invalidFields(path: String, expected: [String], actual: [String])
  case invalidSchemaVersion(String)
  case invalidIdentifier(String)
  case invalidEnum(path: String, value: String)
  case invalidHex(path: String)
  case invalidRawPath(String)
  case limitExceeded(String)
  case duplicateOrUnsortedValue(String)
}

public enum BundledRuleSetLoader {
  public static func load(canonicalData: Data) throws -> BundledRuleSet {
    let root = try parseCanonical(canonicalData)
    let object = try StrictObject(root, path: "$", fields: ["rules", "schema_version"])
    let schema = try object.string("schema_version")
    guard schema == RulesSchema.bundledVersion else {
      throw RulesLoadError.invalidSchemaVersion(schema)
    }
    let rawRules = try object.array("rules")
    guard rawRules.count <= 512 else { throw RulesLoadError.limitExceeded("rules") }
    var rules: [DeclarativeRule] = []
    rules.reserveCapacity(rawRules.count)
    var previousID: String?
    for (index, value) in rawRules.enumerated() {
      let path = "$.rules[\(index)]"
      let ruleObject = try StrictObject(
        value,
        path: path,
        fields: ["candidate_kind", "handling", "id", "managed_action", "matcher"]
      )
      let id = try ruleObject.string("id")
      guard validIdentifier(id) else { throw RulesLoadError.invalidIdentifier(id) }
      if let previousID, !(previousID < id) {
        throw RulesLoadError.duplicateOrUnsortedValue(path + ".id")
      }
      previousID = id
      let candidateText = try ruleObject.string("candidate_kind")
      guard let candidateKind = DeclarativeCandidateKind(rawValue: candidateText) else {
        throw RulesLoadError.invalidEnum(path: path + ".candidate_kind", value: candidateText)
      }
      let handlingText = try ruleObject.string("handling")
      guard let handling = CandidateHandling(rawValue: handlingText) else {
        throw RulesLoadError.invalidEnum(path: path + ".handling", value: handlingText)
      }
      let managedAction: ManagedActionKind?
      switch try ruleObject.value("managed_action") {
      case .null:
        managedAction = nil
      case .string(let text):
        guard let parsed = ManagedActionKind(rawValue: text) else {
          throw RulesLoadError.invalidEnum(path: path + ".managed_action", value: text)
        }
        managedAction = parsed
      default:
        throw RulesLoadError.expectedString(path + ".managed_action")
      }
      switch candidateKind {
      case .managedMaintenance:
        guard managedAction != nil else {
          throw RulesLoadError.invalidFields(
            path: path,
            expected: ["managed-maintenance-with-managed-action"],
            actual: ["managed-maintenance-with-null-action"]
          )
        }
      case .ordinaryCache, .buildOutput, .temporaryData:
        guard managedAction == nil else {
          throw RulesLoadError.invalidFields(
            path: path,
            expected: ["ordinary-kind-with-null-action"],
            actual: ["ordinary-kind-with-managed-action"]
          )
        }
      }
      let matcher = try parseMatcher(try ruleObject.value("matcher"), path: path + ".matcher")
      rules.append(
        DeclarativeRule(
          id: id,
          candidateKind: candidateKind,
          matcher: matcher,
          managedAction: managedAction,
          handling: handling
        )
      )
    }
    return BundledRuleSet(
      schemaVersion: schema,
      digest: RulesDigest.bundledAsset(schemaVersion: schema, canonicalBytes: canonicalData),
      rules: rules
    )
  }

  private static func parseMatcher(
    _ value: CanonicalJSONValue,
    path: String
  ) throws -> RawMatcher {
    guard let entries = value.objectEntries else { throw RulesLoadError.expectedObject(path) }
    let keys = entries.map(\.key)
    guard let kindEntry = entries.first(where: { $0.key == "kind" }),
      let kind = kindEntry.value.stringValue
    else { throw RulesLoadError.expectedString(path + ".kind") }
    switch kind {
    case "root-relative-prefix":
      let object = try StrictObject(
        value, path: path, fields: ["components_hex", "kind"])
      let components = try parseComponents(
        object.array("components_hex"), path: path + ".components_hex")
      return .rootRelativePrefix(components)
    case "name-exact", "name-suffix":
      let object = try StrictObject(value, path: path, fields: ["kind", "value_hex"])
      let raw = try parseRawComponent(object.string("value_hex"), path: path + ".value_hex")
      return kind == "name-exact" ? .nameExact(raw) : .nameSuffix(raw)
    default:
      if keys != ["kind"] {
        throw RulesLoadError.invalidFields(path: path, expected: ["kind"], actual: keys)
      }
      throw RulesLoadError.invalidEnum(path: path + ".kind", value: kind)
    }
  }
}

public enum RestrictedUserPolicyLoader {
  public static func load(canonicalData: Data) throws -> RestrictedUserPolicy {
    let root = try parseCanonical(canonicalData)
    let object = try StrictObject(
      root,
      path: "$",
      fields: [
        "adapter_enablement", "agent", "budgets", "profile", "protections", "schema_version",
        "thresholds",
      ]
    )
    let schema = try object.string("schema_version")
    guard schema == RulesSchema.userPolicyVersion else {
      throw RulesLoadError.invalidSchemaVersion(schema)
    }
    let adapters = try parseSortedEnumArray(
      object.array("adapter_enablement"),
      path: "$.adapter_enablement",
      transform: ConfigurableAdapter.init(rawValue:)
    )
    let agent = try parseAgent(object.value("agent"))
    let budgets = try parseBudgets(object.value("budgets"))
    let profileText = try object.string("profile")
    guard let profile = PolicyProfile(rawValue: profileText) else {
      throw RulesLoadError.invalidEnum(path: "$.profile", value: profileText)
    }
    let protections = try parseProtections(object.array("protections"))
    let thresholds = try parseThresholds(object.value("thresholds"))
    return RestrictedUserPolicy(
      schemaVersion: schema,
      digest: RulesDigest.userPolicyAsset(schemaVersion: schema, canonicalBytes: canonicalData),
      enabledAdapters: adapters,
      agent: agent,
      budgets: budgets,
      profile: profile,
      protections: protections,
      thresholds: thresholds
    )
  }

  private static func parseAgent(_ value: CanonicalJSONValue) throws -> AgentPolicy {
    let object = try StrictObject(
      value, path: "$.agent", fields: ["cache_enabled", "disclosure", "mode"])
    let modeText = try object.string("mode")
    guard let mode = AgentMode(rawValue: modeText) else {
      throw RulesLoadError.invalidEnum(path: "$.agent.mode", value: modeText)
    }
    let disclosure = try parseSortedEnumArray(
      object.array("disclosure"),
      path: "$.agent.disclosure",
      transform: AgentMetadataField.init(rawValue:)
    )
    return AgentPolicy(
      mode: mode,
      disclosure: disclosure,
      cacheEnabled: try object.boolean("cache_enabled")
    )
  }

  private static func parseBudgets(_ value: CanonicalJSONValue) throws -> PolicyBudgets {
    let path = "$.budgets"
    let object = try StrictObject(
      value,
      path: path,
      fields: [
        "maximum_candidates", "maximum_entries_per_root", "maximum_owner_references",
        "maximum_retained_bytes", "maximum_shared_object_keys",
      ]
    )
    return PolicyBudgets(
      maximumEntriesPerRoot: try boundedUnsigned(
        object.integer("maximum_entries_per_root"), path: path + ".maximum_entries_per_root",
        maximum: 100_000_000),
      maximumCandidates: try boundedUnsigned(
        object.integer("maximum_candidates"), path: path + ".maximum_candidates",
        maximum: 1_000_000),
      maximumSharedObjectKeys: try boundedUnsigned(
        object.integer("maximum_shared_object_keys"), path: path + ".maximum_shared_object_keys",
        maximum: 10_000_000),
      maximumOwnerReferences: try boundedUnsigned(
        object.integer("maximum_owner_references"), path: path + ".maximum_owner_references",
        maximum: 20_000_000),
      maximumRetainedBytes: try boundedUnsigned(
        object.integer("maximum_retained_bytes"), path: path + ".maximum_retained_bytes",
        maximum: 2 * 1_024 * 1_024 * 1_024)
    )
  }

  private static func parseThresholds(_ value: CanonicalJSONValue) throws -> PolicyThresholds {
    let path = "$.thresholds"
    let object = try StrictObject(
      value,
      path: path,
      fields: ["minimum_inactive_seconds", "minimum_reclaim_bytes"]
    )
    return PolicyThresholds(
      minimumInactiveSeconds: try boundedUnsigned(
        object.integer("minimum_inactive_seconds"), path: path + ".minimum_inactive_seconds",
        maximum: 10 * 365 * 24 * 60 * 60),
      minimumReclaimBytes: try boundedUnsigned(
        object.integer("minimum_reclaim_bytes"), path: path + ".minimum_reclaim_bytes",
        maximum: Int64.max)
    )
  }

  private static func parseProtections(
    _ values: [CanonicalJSONValue]
  ) throws -> [ProtectedRawPath] {
    guard values.count <= 256 else { throw RulesLoadError.limitExceeded("protections") }
    var result: [ProtectedRawPath] = []
    var previousBinding: Data?
    for (index, value) in values.enumerated() {
      let path = "$.protections[\(index)]"
      let object = try StrictObject(value, path: path, fields: ["effect", "path"])
      let effect = try object.string("effect")
      guard effect == "protect" else {
        throw RulesLoadError.invalidEnum(path: path + ".effect", value: effect)
      }
      let pathObject = try StrictObject(
        object.value("path"), path: path + ".path", fields: ["components_hex", "root_binding"])
      let rootBytes = try parseFixedHex(
        pathObject.string("root_binding"), byteCount: 32, path: path + ".path.root_binding")
      let rootBinding: PolicyDigest
      do {
        rootBinding = try PolicyDigest(bytes: rootBytes)
      } catch {
        throw RulesLoadError.invalidHex(path: path + ".path.root_binding")
      }
      let components = try parseProtectionComponents(
        pathObject.array("components_hex"), path: path + ".path.components_hex")
      guard components.reduce(0, { $0 + $1.count }) <= 4_096 else {
        throw RulesLoadError.limitExceeded(path + ".path.components_hex")
      }
      var binding = rootBytes
      for component in components {
        binding.append(0)
        binding.append(component)
      }
      if let previousBinding, !previousBinding.lexicographicallyPrecedes(binding) {
        throw RulesLoadError.duplicateOrUnsortedValue(path)
      }
      previousBinding = binding
      result.append(ProtectedRawPath(rootBinding: rootBinding, components: components))
    }
    return result
  }
}

private struct StrictObject {
  let path: String
  let entries: [CanonicalJSONValue.Entry]

  init(_ value: CanonicalJSONValue, path: String, fields: [String]) throws {
    guard let entries = value.objectEntries else { throw RulesLoadError.expectedObject(path) }
    let actual = entries.map(\.key)
    guard actual == fields.sorted() else {
      throw RulesLoadError.invalidFields(path: path, expected: fields.sorted(), actual: actual)
    }
    self.path = path
    self.entries = entries
  }

  func value(_ key: String) throws -> CanonicalJSONValue {
    guard let value = entries.first(where: { $0.key == key })?.value else {
      throw RulesLoadError.invalidFields(
        path: path, expected: entries.map(\.key) + [key], actual: entries.map(\.key))
    }
    return value
  }

  func string(_ key: String) throws -> String {
    guard let value = try value(key).stringValue else {
      throw RulesLoadError.expectedString(path + "." + key)
    }
    return value
  }

  func array(_ key: String) throws -> [CanonicalJSONValue] {
    guard let values = try value(key).arrayValues else {
      throw RulesLoadError.expectedArray(path + "." + key)
    }
    return values
  }

  func integer(_ key: String) throws -> Int64 {
    guard let value = try value(key).integerValue else {
      throw RulesLoadError.expectedInteger(path + "." + key)
    }
    return value
  }

  func boolean(_ key: String) throws -> Bool {
    guard let value = try value(key).boolValue else {
      throw RulesLoadError.expectedBoolean(path + "." + key)
    }
    return value
  }
}

private func parseCanonical(_ data: Data) throws -> CanonicalJSONValue {
  do {
    var parser = try CanonicalJSONParser(data: data)
    return try parser.parse()
  } catch let error as CanonicalJSONError {
    throw RulesLoadError.malformedCanonicalJSON(error)
  }
}

private func parseComponents(
  _ values: [CanonicalJSONValue],
  path: String
) throws -> [Data] {
  guard !values.isEmpty, values.count <= 128 else {
    throw RulesLoadError.limitExceeded(path)
  }
  let components = try values.enumerated().map { index, value -> Data in
    guard let text = value.stringValue else {
      throw RulesLoadError.expectedString("\(path)[\(index)]")
    }
    return try parseRawComponent(text, path: "\(path)[\(index)]")
  }
  guard DeclarativeRecognizer.validRawComponents(components) else {
    throw RulesLoadError.invalidRawPath(path)
  }
  return components
}

private func parseProtectionComponents(
  _ values: [CanonicalJSONValue],
  path: String
) throws -> [Data] {
  guard values.count <= 128 else { throw RulesLoadError.limitExceeded(path) }
  if values.isEmpty { return [] }
  return try parseComponents(values, path: path)
}

private func parseRawComponent(_ text: String, path: String) throws -> Data {
  let data = try parseHex(text, path: path)
  guard !data.isEmpty, data.count <= 255, !data.contains(0),
    !data.contains(UInt8(ascii: "/")), data != Data(".".utf8), data != Data("..".utf8)
  else { throw RulesLoadError.invalidRawPath(path) }
  return data
}

private func parseHex(_ text: String, path: String) throws -> Data {
  guard !text.isEmpty, text.utf8.count.isMultiple(of: 2) else {
    throw RulesLoadError.invalidHex(path: path)
  }
  let bytes = Array(text.utf8)
  var output = Data()
  output.reserveCapacity(bytes.count / 2)
  for offset in stride(from: 0, to: bytes.count, by: 2) {
    guard let high = lowercaseHex(bytes[offset]), let low = lowercaseHex(bytes[offset + 1]) else {
      throw RulesLoadError.invalidHex(path: path)
    }
    output.append(high << 4 | low)
  }
  return output
}

private func parseFixedHex(_ text: String, byteCount: Int, path: String) throws -> Data {
  let data = try parseHex(text, path: path)
  guard data.count == byteCount else { throw RulesLoadError.invalidHex(path: path) }
  return data
}

private func lowercaseHex(_ byte: UInt8) -> UInt8? {
  switch byte {
  case UInt8(ascii: "0")...UInt8(ascii: "9"):
    byte - UInt8(ascii: "0")
  case UInt8(ascii: "a")...UInt8(ascii: "f"):
    byte - UInt8(ascii: "a") + 10
  default:
    nil
  }
}

private func validIdentifier(_ value: String) -> Bool {
  let bytes = Array(value.utf8)
  guard !bytes.isEmpty, bytes.count <= 64 else { return false }
  return bytes.allSatisfy {
    (UInt8(ascii: "a")...UInt8(ascii: "z")).contains($0)
      || (UInt8(ascii: "0")...UInt8(ascii: "9")).contains($0)
      || $0 == UInt8(ascii: "-") || $0 == UInt8(ascii: ".")
  }
}

private func boundedUnsigned(_ value: Int64, path: String, maximum: Int64) throws -> UInt64 {
  guard value >= 0, value <= maximum else { throw RulesLoadError.limitExceeded(path) }
  return UInt64(value)
}

private func parseSortedEnumArray<Value>(
  _ values: [CanonicalJSONValue],
  path: String,
  transform: (String) -> Value?
) throws -> [Value] {
  var result: [Value] = []
  var previous: String?
  for (index, value) in values.enumerated() {
    guard let text = value.stringValue else {
      throw RulesLoadError.expectedString("\(path)[\(index)]")
    }
    if let previous, !(previous < text) {
      throw RulesLoadError.duplicateOrUnsortedValue(path)
    }
    guard let parsed = transform(text) else {
      throw RulesLoadError.invalidEnum(path: "\(path)[\(index)]", value: text)
    }
    previous = text
    result.append(parsed)
  }
  return result
}
