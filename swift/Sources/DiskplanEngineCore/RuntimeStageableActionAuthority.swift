import CryptoKit
import Darwin
import DiskplanPolicy
import DiskplanRules
import DiskplanScan
import Foundation

enum RuntimeStageableActionConfigurationState: Sendable {
  case unavailable(RuntimeAuthorityReason)
  case ready(RuntimeStageableActionAuthority)

  var bindingBytes: Data {
    switch self {
    case .unavailable(let reason):
      return runtimeStageableBinding(
        domain: "diskplan/runtime-stageable-configuration/v1\0",
        parts: [Data("unavailable".utf8), Data(reason.rawValue.utf8)]
      )
    case .ready(let authority):
      return authority.bindingBytes
    }
  }
}

struct RuntimeStageableActionAuthority: Sendable {
  static let adapterID = "foundation-user-cache-root-v1"

  let rules: RulesConfiguration
  let rawCacheRoot: Data
  let cacheRootIdentity: DiskplanScan.ObjectIdentity
  let effectiveUserID: UInt32
  let rootBinding: PolicyDigest

  init(
    rules: RulesConfiguration,
    rawCacheRoot: Data,
    cacheRootIdentity: DiskplanScan.ObjectIdentity,
    effectiveUserID: UInt32
  ) {
    self.rules = rules
    self.rawCacheRoot = rawCacheRoot
    self.cacheRootIdentity = cacheRootIdentity
    self.effectiveUserID = effectiveUserID
    rootBinding = runtimeStageablePolicyDigest(
      domain: "diskplan/system-user-cache-root/v1\0",
      parts: [
        Data(Self.adapterID.utf8), rawCacheRoot,
        runtimeStageableUInt64(UInt64(bitPattern: cacheRootIdentity.device)),
        runtimeStageableUInt64(cacheRootIdentity.fileID),
        Data(cacheRootIdentity.objectType.rawValue.utf8),
        runtimeStageableUInt64(UInt64(effectiveUserID)),
      ]
    )
  }

  var bindingBytes: Data {
    runtimeStageableBinding(
      domain: "diskplan/runtime-stageable-configuration/v1\0",
      parts: [
        Data("ready".utf8), Data(Self.adapterID.utf8), rawCacheRoot,
        rootBinding.bytes, rules.effectiveDigest.bytes,
        runtimeStageableUInt64(UInt64(effectiveUserID)),
      ]
    )
  }

  var genericRemoveEnabled: Bool {
    rules.user.enabledAdapters.contains(.genericRemove)
  }

  func isExactCacheRoot(_ root: RootScanResult) -> Bool {
    root.binding.rawAbsolutePath == rawCacheRoot
      && root.binding.identity == cacheRootIdentity
  }

  func protects(_ candidate: RecognizedRuntimeCandidate) -> Bool {
    let target = candidate.node.path.components.map(\.bytes)
    return rules.user.protections.contains {
      guard $0.rootBinding == rootBinding else { return false }
      return rawComponents($0.components, prefix: target)
        || rawComponents(target, prefix: $0.components)
    }
  }

  static func production(
    bundledRulesData: Data?,
    userPolicyData: Data?
  ) -> RuntimeStageableActionConfigurationState {
    guard let bundledRulesData, let userPolicyData else {
      return .unavailable(.rulesConfigurationUnavailable)
    }
    let rules: RulesConfiguration
    do {
      rules = RulesConfiguration(
        bundled: try BundledRuleSetLoader.load(canonicalData: bundledRulesData),
        user: try RestrictedUserPolicyLoader.load(canonicalData: userPolicyData)
      )
    } catch {
      return .unavailable(.rulesConfigurationUnavailable)
    }
    guard let discovery = discoverSystemUserCacheRoot() else {
      return .unavailable(.systemCacheRootUnavailable)
    }
    return .ready(
      Self(
        rules: rules,
        rawCacheRoot: discovery.rawPath,
        cacheRootIdentity: discovery.identity,
        effectiveUserID: geteuid()
      )
    )
  }
}

private func rawComponents(_ candidate: [Data], prefix: [Data]) -> Bool {
  guard candidate.count >= prefix.count else { return false }
  return zip(prefix, candidate).allSatisfy { $0.0 == $0.1 }
}

private struct RuntimeSystemCacheRootDiscovery {
  let rawPath: Data
  let identity: DiskplanScan.ObjectIdentity
}

private func discoverSystemUserCacheRoot() -> RuntimeSystemCacheRootDiscovery? {
  guard let url = FileManager.default.urls(for: .cachesDirectory, in: .userDomainMask).first
  else { return nil }
  return url.withUnsafeFileSystemRepresentation { representation in
    guard let representation else { return nil }
    let rawPath = Data(bytes: representation, count: strlen(representation))
    guard !rawPath.isEmpty, rawPath.first == UInt8(ascii: "/"), !rawPath.contains(0) else {
      return nil
    }
    let descriptor = open(representation, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { return nil }
    defer { Darwin.close(descriptor) }
    var status = stat()
    guard fstat(descriptor, &status) == 0, status.st_mode & S_IFMT == S_IFDIR else {
      return nil
    }
    return RuntimeSystemCacheRootDiscovery(
      rawPath: rawPath,
      identity: DiskplanScan.ObjectIdentity(
        device: Int64(status.st_dev),
        fileID: status.st_ino,
        objectType: .directory
      )
    )
  }
}

private func runtimeStageablePolicyDigest(domain: String, parts: [Data]) -> PolicyDigest {
  try! PolicyDigest(
    bytes: Data(
      SHA256.hash(data: runtimeStageableBinding(domain: domain, parts: parts))
    )
  )
}

private func runtimeStageableBinding(domain: String, parts: [Data]) -> Data {
  var result = Data(domain.utf8)
  for part in parts {
    result.append(runtimeStageableUInt64(UInt64(part.count)))
    result.append(part)
  }
  return result
}

func runtimeStageableAuthorityConfigurationBinding(
  scanConfiguration: Data,
  stageableConfiguration: RuntimeStageableActionConfigurationState
) -> Data {
  runtimeStageableBinding(
    domain: "diskplan/runtime-policy-authority-configuration/v1\0",
    parts: [scanConfiguration, stageableConfiguration.bindingBytes]
  )
}

private func runtimeStageableUInt64(_ value: UInt64) -> Data {
  var value = value.bigEndian
  return withUnsafeBytes(of: &value) { Data($0) }
}
