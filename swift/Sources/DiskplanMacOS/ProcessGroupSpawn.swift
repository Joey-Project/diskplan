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

public struct POSIXProcessGroupSpawner: Sendable {
  public init() {}

  /// Atomically launches the executable as the leader of a new process group.
  /// The caller owns the returned read descriptors and must reap `processID`.
  public func spawn(
    executableURL: URL,
    arguments: [String],
    environment: [String: String]
  ) throws -> SpawnedPOSIXProcessGroup {
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

    var result = dp_spawned_process_group_v1()
    let status = executableURL.path.withCString { executable in
      argumentBytes.withUnsafeBytes { bytes in
        environmentBytes.withUnsafeBytes { environmentBytes in
          dp_spawn_process_group(
            executable,
            bytes.bindMemory(to: UInt8.self).baseAddress,
            bytes.count,
            arguments.count,
            environmentBytes.bindMemory(to: UInt8.self).baseAddress,
            environmentBytes.count,
            environment.count,
            &result
          )
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
}
