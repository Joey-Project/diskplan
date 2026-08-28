import CDiskplanMacOS
import Darwin
import Foundation

public struct VolumeCapabilityEvidence: Equatable, Sendable {
  public let filesystemType: String
  public let returnedAttributes: ReturnedAttributeMasks
  public let validCapabilityMasks: Capability<[UInt32]>
  public let capabilityMasks: Capability<[UInt32]>
  public let validAttributeMasks: Capability<[UInt32]>
  public let nativeAttributeMasks: Capability<[UInt32]>
  public let supportsClone: Capability<Bool>
  public let supportsSnapshot: Capability<Bool>
  public let supportsCloneMapping: Capability<Bool>

  public static func interpret(
    filesystemType: String,
    returned: ReturnedAttributeMasks,
    validCapabilities: [UInt32],
    capabilities: [UInt32],
    validAttributes: [UInt32],
    nativeAttributes: [UInt32]
  ) -> Self {
    let hasCapabilities = returned.volume & UInt32(ATTR_VOL_CAPABILITIES) != 0
    func interface(_ mask: UInt32) -> Capability<Bool> {
      guard hasCapabilities,
        validCapabilities.count > Int(VOL_CAPABILITIES_INTERFACES),
        validCapabilities[Int(VOL_CAPABILITIES_INTERFACES)] & mask != 0,
        capabilities.count > Int(VOL_CAPABILITIES_INTERFACES)
      else {
        return .unavailable("volume interface capability mask was not returned as valid")
      }
      return .known(capabilities[Int(VOL_CAPABILITIES_INTERFACES)] & mask != 0)
    }
    func format(_ mask: UInt32) -> Capability<Bool> {
      guard hasCapabilities,
        validCapabilities.count > Int(VOL_CAPABILITIES_FORMAT),
        validCapabilities[Int(VOL_CAPABILITIES_FORMAT)] & mask != 0,
        capabilities.count > Int(VOL_CAPABILITIES_FORMAT)
      else {
        return .unavailable("volume format capability mask was not returned as valid")
      }
      return .known(capabilities[Int(VOL_CAPABILITIES_FORMAT)] & mask != 0)
    }

    return Self(
      filesystemType: filesystemType,
      returnedAttributes: returned,
      validCapabilityMasks: hasCapabilities
        ? .known(validCapabilities)
        : .unavailable("volume capability attributes were not returned"),
      capabilityMasks: hasCapabilities
        ? .known(capabilities)
        : .unavailable("volume capability attributes were not returned"),
      validAttributeMasks: returned.volume & UInt32(ATTR_VOL_ATTRIBUTES) != 0
        ? .known(validAttributes)
        : .unavailable("volume attribute masks were not returned"),
      nativeAttributeMasks: returned.volume & UInt32(ATTR_VOL_ATTRIBUTES) != 0
        ? .known(nativeAttributes)
        : .unavailable("volume attribute masks were not returned"),
      supportsClone: interface(dp_volume_clone_interface()),
      supportsSnapshot: interface(dp_volume_snapshot_interface()),
      supportsCloneMapping: format(dp_volume_clone_mapping_format())
    )
  }
}

public struct VolumeProbe: Sendable {
  public init() {}

  public func probe(
    fileDescriptor: Int32,
    policy: NoMaterializationPolicy
  ) -> Capability<VolumeCapabilityEvidence> {
    _ = policy
    var raw = dp_volume_evidence_v1()
    guard dp_probe_volume_fd(fileDescriptor, &raw) == 0 else {
      return POSIXFailure.capability(errno, operation: "fgetattrlist volume capabilities")
    }
    let type = withUnsafeBytes(of: raw.filesystem_type) { bytes -> String in
      let prefix = bytes.prefix { $0 != 0 }
      return String(decoding: prefix, as: UTF8.self)
    }
    let validCapabilities = withUnsafeBytes(of: raw.valid_capabilities) {
      Array($0.bindMemory(to: UInt32.self))
    }
    let capabilities = withUnsafeBytes(of: raw.capabilities) {
      Array($0.bindMemory(to: UInt32.self))
    }
    let validAttributes = withUnsafeBytes(of: raw.valid_attributes) {
      Array($0.bindMemory(to: UInt32.self))
    }
    let nativeAttributes = withUnsafeBytes(of: raw.native_attributes) {
      Array($0.bindMemory(to: UInt32.self))
    }
    return .known(
      VolumeCapabilityEvidence.interpret(
        filesystemType: type,
        returned: ReturnedAttributeMasks(
          common: raw.returned_common,
          volume: raw.returned_volume,
          directory: raw.returned_directory,
          file: raw.returned_file,
          extended: raw.returned_extended
        ),
        validCapabilities: validCapabilities,
        capabilities: capabilities,
        validAttributes: validAttributes,
        nativeAttributes: nativeAttributes
      )
    )
  }
}
