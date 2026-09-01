import CDiskplanMacOS
import Foundation

public struct SnapshotListProbe: Sendable {
  public init() {}

  /// Lists public snapshot name attributes through an already-open volume-root descriptor.
  /// The syscall may advance only the borrowed descriptor's enumeration offset.
  public func list(
    fileDescriptor: Int32,
    buffer: inout Data
  ) -> Capability<Int32> {
    guard !buffer.isEmpty else {
      return Capability(status: .failed, detail: "snapshot list buffer is empty", errorCode: EINVAL)
    }
    let count = buffer.withUnsafeMutableBytes { bytes in
      dp_list_snapshot_attributes(
        fileDescriptor,
        bytes.bindMemory(to: UInt8.self).baseAddress,
        bytes.count
      )
    }
    guard count >= 0 else {
      return POSIXFailure.capability(errno, operation: "fs_snapshot_list")
    }
    return .known(Int32(count))
  }
}
