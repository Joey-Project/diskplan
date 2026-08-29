import CDiskplanMacOS
import Darwin
import Foundation

public struct SpawnedPOSIXProcessGroup: Equatable, Sendable {
  public let processID: Int32
  public let standardOutputFileDescriptor: Int32
  public let standardErrorFileDescriptor: Int32

  public init(
    processID: Int32,
    standardOutputFileDescriptor: Int32,
    standardErrorFileDescriptor: Int32
  ) {
    self.processID = processID
    self.standardOutputFileDescriptor = standardOutputFileDescriptor
    self.standardErrorFileDescriptor = standardErrorFileDescriptor
  }
}

package struct POSIXSpawnInheritedFileDescriptor: Equatable, Sendable {
  package let sourceFileDescriptor: Int32
  package let childFileDescriptor: Int32

  package init(sourceFileDescriptor: Int32, childFileDescriptor: Int32) {
    self.sourceFileDescriptor = sourceFileDescriptor
    self.childFileDescriptor = childFileDescriptor
  }
}

public struct POSIXProcessGroupSpawner: Sendable {
  public init() {}

  /// Atomically launches the executable as the leader of a new process group.
  /// The caller owns the returned read descriptors and must reap `processID`.
  public func spawn(
    executableURL: URL,
    arguments: [String],
    environment: [String: String]
  ) throws -> SpawnedPOSIXProcessGroup {
    try spawn(
      executableURL: executableURL,
      arguments: arguments,
      environment: environment,
      consumingInheritedFileDescriptors: []
    )
  }

  /// Consumes every source descriptor on success or failure. Child descriptors are created only by
  /// the atomic spawn file actions and remain closed in the parent.
  package func spawn(
    executableURL: URL,
    arguments: [String],
    environment: [String: String],
    consumingInheritedFileDescriptors inheritedDescriptors: [POSIXSpawnInheritedFileDescriptor]
  ) throws -> SpawnedPOSIXProcessGroup {
    defer {
      let uniqueSources = Set(inheritedDescriptors.map(\.sourceFileDescriptor))
      for sourceFileDescriptor in uniqueSources {
        Darwin.close(sourceFileDescriptor)
      }
    }
    try Self.validate(inheritedDescriptors: inheritedDescriptors)
    guard executableURL.isFileURL else {
      throw NSError(
        domain: NSPOSIXErrorDomain,
        code: Int(EINVAL),
        userInfo: [NSLocalizedDescriptionKey: "process executable URL is not a file URL"]
      )
    }
    var argumentBytes = Data()
    for argument in arguments {
      let bytes = Data(argument.utf8)
      guard !bytes.contains(0) else {
        throw NSError(
          domain: NSPOSIXErrorDomain,
          code: Int(EINVAL),
          userInfo: [NSLocalizedDescriptionKey: "process argument contains a NUL byte"]
        )
      }
      argumentBytes.append(bytes)
      argumentBytes.append(0)
    }
    var environmentBytes = Data()
    for key in environment.keys.sorted() {
      guard !key.isEmpty, !key.contains("="), !key.utf8.contains(0),
        let value = environment[key], !value.utf8.contains(0)
      else {
        throw NSError(
          domain: NSPOSIXErrorDomain,
          code: Int(EINVAL),
          userInfo: [NSLocalizedDescriptionKey: "process environment is malformed"]
        )
      }
      environmentBytes.append(Data("\(key)=\(value)".utf8))
      environmentBytes.append(0)
    }

    let inherited = inheritedDescriptors.map { descriptor in
      dp_spawn_inherited_fd_v1(
        source_fd: descriptor.sourceFileDescriptor,
        child_fd: descriptor.childFileDescriptor
      )
    }
    var result = dp_spawned_process_group_v1()
    let status = executableURL.path.withCString { executable in
      argumentBytes.withUnsafeBytes { bytes in
        environmentBytes.withUnsafeBytes { environmentBytes in
          inherited.withUnsafeBufferPointer { inherited in
            dp_spawn_process_group_with_inherited_fds(
              executable,
              bytes.bindMemory(to: UInt8.self).baseAddress,
              bytes.count,
              arguments.count,
              environmentBytes.bindMemory(to: UInt8.self).baseAddress,
              environmentBytes.count,
              environment.count,
              inherited.baseAddress,
              inherited.count,
              &result
            )
          }
        }
      }
    }
    guard status == 0 else {
      let code = errno
      throw NSError(
        domain: NSPOSIXErrorDomain,
        code: Int(code),
        userInfo: [
          NSLocalizedDescriptionKey:
            "posix_spawn failed: \(String(cString: strerror(code)))"
        ]
      )
    }
    return SpawnedPOSIXProcessGroup(
      processID: result.process_id,
      standardOutputFileDescriptor: result.standard_output_fd,
      standardErrorFileDescriptor: result.standard_error_fd
    )
  }

  private static func validate(
    inheritedDescriptors: [POSIXSpawnInheritedFileDescriptor]
  ) throws {
    guard inheritedDescriptors.count <= 16 else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(EINVAL))
    }
    var sourceDescriptors = Set<Int32>()
    var childDescriptors = Set<Int32>()
    for descriptor in inheritedDescriptors {
      guard descriptor.sourceFileDescriptor >= 3, descriptor.childFileDescriptor >= 3,
        sourceDescriptors.insert(descriptor.sourceFileDescriptor).inserted,
        childDescriptors.insert(descriptor.childFileDescriptor).inserted
      else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(EINVAL))
      }
    }
    guard sourceDescriptors.isDisjoint(with: childDescriptors) else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(EINVAL))
    }
  }
}
