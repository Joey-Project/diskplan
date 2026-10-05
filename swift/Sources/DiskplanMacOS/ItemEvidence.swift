import CDiskplanMacOS
import Darwin
import Foundation

public struct ReturnedAttributeMasks: Equatable, Sendable {
  public let common: UInt32
  public let volume: UInt32
  public let directory: UInt32
  public let file: UInt32
  public let extended: UInt32

  public init(
    common: UInt32,
    volume: UInt32,
    directory: UInt32,
    file: UInt32,
    extended: UInt32
  ) {
    self.common = common
    self.volume = volume
    self.directory = directory
    self.file = file
    self.extended = extended
  }
}

public enum FileSystemObjectType: UInt32, Equatable, Sendable {
  case regular = 1
  case directory = 2
  case symbolicLink = 5
  case other = 0

  init(rawKernelValue: UInt32) {
    self = Self(rawValue: rawKernelValue) ?? .other
  }
}

public struct SharingEvidence: Equatable, Sendable {
  public let mayShareBlocks: Capability<Bool>
  public let sharesAllBlocks: Capability<Bool>
  public let cloneID: Capability<UInt64>
  public let cloneRefcount: Capability<UInt32>
  public let conditionalGroupReclaimBytes: Capability<UInt64>
}

public struct ItemStorageEvidence: Equatable, Sendable {
  public let returnedAttributes: ReturnedAttributeMasks
  public let device: Capability<Int64>
  public let objectType: Capability<FileSystemObjectType>
  public let fileID: Capability<UInt64>
  public let linkCount: Capability<UInt32>
  public let logicalBytes: Capability<UInt64>
  public let nominalAllocatedBytes: Capability<UInt64>
  public let immediatePrivateReclaimBytes: Capability<UInt64>
  public let sharing: SharingEvidence
  public let vfsFlags: Capability<UInt32>
  public let isDataless: Capability<Bool>
  public let isSyncRoot: Capability<Bool>
  public let providerHiddenFootprint: Capability<UInt64>
  public let snapshotAttributedBytes: Capability<UInt64>
}

public enum ItemWireError: Error, Equatable {
  case truncated
  case invalidLength(declared: UInt32, actual: Int)
  case unexpectedReturnedAttributes(ReturnedAttributeMasks)
  case negative(field: String)
  case overflow(field: String)
}

public enum ItemWireV1 {
  public static let size = Int(DP_ITEM_WIRE_V1_SIZE)

  public static func parse(_ data: Data) throws -> ItemStorageEvidence {
    guard data.count >= 4 else { throw ItemWireError.truncated }
    let declared = try readUInt32(data, at: 0)
    guard declared == data.count, data.count == size else {
      throw ItemWireError.invalidLength(declared: declared, actual: data.count)
    }

    let masks = ReturnedAttributeMasks(
      common: try readUInt32(data, at: 4),
      volume: try readUInt32(data, at: 8),
      directory: try readUInt32(data, at: 12),
      file: try readUInt32(data, at: 16),
      extended: try readUInt32(data, at: 20)
    )
    let common = masks.common
    let file = masks.file
    let extended = masks.extended
    let allowedCommon =
      UInt32(ATTR_CMN_RETURNED_ATTRS) | dp_attr_common_device()
      | dp_attr_common_object_type() | dp_attr_common_flags() | dp_attr_common_file_id()
    let allowedFile =
      dp_attr_file_link_count() | dp_attr_file_total_size()
      | dp_attr_file_allocated_size()
    let allowedExtended =
      dp_attr_extended_private_size() | dp_attr_extended_clone_id()
      | dp_attr_extended_flags() | dp_attr_extended_clone_refcount()
    guard masks.volume == 0, masks.directory == 0,
      common & ~allowedCommon == 0,
      file & ~allowedFile == 0,
      extended & ~allowedExtended == 0
    else {
      throw ItemWireError.unexpectedReturnedAttributes(masks)
    }

    let device = capability(
      present: common & dp_attr_common_device() != 0,
      value: Int64(bitPattern: try readUInt64(data, at: 24))
    )
    let objectType = capability(
      present: common & dp_attr_common_object_type() != 0,
      value: FileSystemObjectType(rawKernelValue: try readUInt32(data, at: 32))
    )
    let flagsValue = try readUInt32(data, at: 36)
    let flags = capability(present: common & dp_attr_common_flags() != 0, value: flagsValue)
    let fileID = capability(
      present: common & dp_attr_common_file_id() != 0,
      value: try readUInt64(data, at: 40)
    )
    let linkCount = capability(
      present: file & dp_attr_file_link_count() != 0,
      value: try readUInt32(data, at: 48)
    )
    let logical = try sizeCapability(
      present: file & dp_attr_file_total_size() != 0,
      raw: try readUInt64(data, at: 52),
      field: "logical_bytes"
    )
    let allocated = try sizeCapability(
      present: file & dp_attr_file_allocated_size() != 0,
      raw: try readUInt64(data, at: 60),
      field: "nominal_allocated_bytes"
    )
    let privateSize = try sizeCapability(
      present: extended & dp_attr_extended_private_size() != 0,
      raw: try readUInt64(data, at: 68),
      field: "immediate_private_reclaim_bytes"
    )
    let extendedFlags = try readUInt64(data, at: 84)
    let extendedFlagsKnown = extended & dp_attr_extended_flags() != 0
    let cloneID = capability(
      present: extended & dp_attr_extended_clone_id() != 0,
      value: try readUInt64(data, at: 76)
    )
    let cloneRefcount = capability(
      present: extended & dp_attr_extended_clone_refcount() != 0,
      value: try readUInt32(data, at: 92)
    )

    return ItemStorageEvidence(
      returnedAttributes: masks,
      device: device,
      objectType: objectType,
      fileID: fileID,
      linkCount: linkCount,
      logicalBytes: logical,
      nominalAllocatedBytes: allocated,
      immediatePrivateReclaimBytes: privateSize,
      sharing: SharingEvidence(
        mayShareBlocks: capability(
          present: extendedFlagsKnown,
          value: extendedFlags & dp_flag_may_share_blocks() != 0
        ),
        sharesAllBlocks: capability(
          present: extendedFlagsKnown,
          value: extendedFlags & dp_flag_shares_all_blocks() != 0
        ),
        cloneID: cloneID,
        cloneRefcount: cloneRefcount,
        conditionalGroupReclaimBytes: .unavailable(
          "shared allocation bytes and complete release-set ownership are unavailable from this item probe"
        )
      ),
      vfsFlags: flags,
      isDataless: flags.map { $0 & dp_flag_dataless() != 0 },
      isSyncRoot: capability(
        present: extendedFlagsKnown,
        value: extendedFlags & dp_flag_sync_root() != 0
      ),
      providerHiddenFootprint: .unavailable("unavailable via public API"),
      snapshotAttributedBytes: .unavailable("snapshot attribution is unavailable via public API")
    )
  }

  private static func capability<Value: Equatable & Sendable>(
    present: Bool,
    value: Value
  ) -> Capability<Value> {
    present ? .known(value) : .unavailable("attribute was not returned by the filesystem")
  }

  private static func sizeCapability(
    present: Bool,
    raw: UInt64,
    field: String
  ) throws -> Capability<UInt64> {
    guard present else { return .unavailable("attribute was not returned by the filesystem") }
    if raw == UInt64.max { throw ItemWireError.negative(field: field) }
    guard raw <= UInt64(Int64.max) else { throw ItemWireError.overflow(field: field) }
    return .known(raw)
  }

  private static func readUInt32(_ data: Data, at offset: Int) throws -> UInt32 {
    guard offset <= data.count, data.count - offset >= 4 else { throw ItemWireError.truncated }
    return data.withUnsafeBytes { raw in
      UInt32(littleEndian: raw.loadUnaligned(fromByteOffset: offset, as: UInt32.self))
    }
  }

  private static func readUInt64(_ data: Data, at offset: Int) throws -> UInt64 {
    guard offset <= data.count, data.count - offset >= 8 else { throw ItemWireError.truncated }
    return data.withUnsafeBytes { raw in
      UInt64(littleEndian: raw.loadUnaligned(fromByteOffset: offset, as: UInt64.self))
    }
  }

}

extension Capability {
  fileprivate func map<M: Equatable & Sendable>(_ transform: (Value) -> M) -> Capability<M> {
    guard status == .known, let value else {
      return Capability<M>(status: status, detail: detail, errorCode: errorCode)
    }
    return .known(transform(value))
  }
}

public struct ItemProbe: Sendable {
  public init() {}

  public func probe(
    parentFileDescriptor: Int32,
    rawName: Data,
    policy: NoMaterializationPolicy
  ) -> Capability<ItemStorageEvidence> {
    let livePolicy = policy.revalidateLive()
    guard livePolicy.status == .known else {
      return Capability(
        status: livePolicy.status,
        detail: livePolicy.detail,
        errorCode: livePolicy.errorCode
      )
    }
    var wire = Data(count: ItemWireV1.size)
    var written = 0
    let result = wire.withUnsafeMutableBytes { output in
      rawName.withUnsafeBytes { name in
        dp_probe_item_at(
          parentFileDescriptor,
          name.bindMemory(to: UInt8.self).baseAddress,
          rawName.count,
          output.bindMemory(to: UInt8.self).baseAddress,
          output.count,
          &written
        )
      }
    }
    guard result == 0 else {
      return POSIXFailure.capability(errno, operation: "getattrlistat item metadata")
    }
    guard written <= wire.count else {
      return Capability(status: .inconsistent, detail: "item probe returned an oversized buffer")
    }
    wire.removeSubrange(written..<wire.count)
    do {
      return .known(try ItemWireV1.parse(wire))
    } catch {
      return Capability(status: .inconsistent, detail: "malformed item attribute buffer: \(error)")
    }
  }

  public func displayName(for rawName: Data) -> Capability<String> {
    guard let string = String(data: rawName, encoding: .utf8) else {
      return .unavailable("raw filename is not valid UTF-8")
    }
    return .known(string)
  }
}

/// Reads descriptor identity in the same real-device namespace as `ItemProbe`.
public struct FileDescriptorIdentityProbe: Sendable {
  public init() {}

  public func probe(
    fileDescriptor: Int32,
    policy: NoMaterializationPolicy
  ) -> Capability<FileObjectIdentity> {
    let livePolicy = policy.revalidateLive()
    guard livePolicy.value != nil else {
      return Capability(
        status: livePolicy.status,
        detail: livePolicy.detail,
        errorCode: livePolicy.errorCode
      )
    }
    var raw = dp_fd_identity_v1()
    guard dp_probe_fd_identity(fileDescriptor, &raw) == 0 else {
      return POSIXFailure.capability(errno, operation: "probe file descriptor identity")
    }
    let common = raw.returned_common
    guard common & dp_attr_common_device() != 0 else {
      return .unavailable("real device identity was not returned")
    }
    guard common & dp_attr_common_file_id() != 0 else {
      return .unavailable("file ID was not returned")
    }
    guard common & dp_attr_common_object_type() != 0 else {
      return .unavailable("object type was not returned")
    }
    return .known(
      FileObjectIdentity(
        device: raw.real_device,
        fileID: raw.file_id,
        objectType: FileSystemObjectType(rawKernelValue: raw.object_type)
      )
    )
  }
}
