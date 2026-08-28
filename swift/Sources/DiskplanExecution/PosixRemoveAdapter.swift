import Darwin
import DiskplanPolicy
import Foundation

/// Generic cleanup uses `/bin/rm` through raw argv bytes, never a shell command string.
/// Descriptor-relative no-follow identity checks fence the known path-race residual immediately
/// before spawn; the policy contract still records that the spawn pathname itself can race.
final class PosixRemoveAdapter: ExecutionMutationAdapter, @unchecked Sendable {
  private enum Inspection {
    case present
    case missing
  }

  private let beforeFinalPreflight: @Sendable () -> Void

  init() {
    beforeFinalPreflight = {}
  }

  init(beforeFinalPreflight: @escaping @Sendable () -> Void) {
    self.beforeFinalPreflight = beforeFinalPreflight
  }

  public func apply(_ operation: ExecutionAdapterOperation) async -> AdapterOperationOutcome {
    guard case .genericRemove(let target, let contract) = operation else {
      return .failed(ExecutionAdapterFailure(code: "unsupported-action-adapter"))
    }
    guard contract.pathRaceResidual,
      contract.removalPathSlot == .prototypeRawTargetPath,
      contract.targetKind == target.expectedIdentity.type
    else {
      return .failed(ExecutionAdapterFailure(code: "invalid-generic-remove-contract"))
    }
    do {
      guard try inspect(target) == .present else {
        return .failed(ExecutionAdapterFailure(code: "preflight-target-missing"))
      }
      beforeFinalPreflight()
      guard try inspect(target) == .present else {
        return .failed(ExecutionAdapterFailure(code: "preflight-target-missing"))
      }
      let status = try Self.spawnRM(arguments: Self.arguments(target: target, contract: contract))
      guard status == 0 else {
        return .failed(
          ExecutionAdapterFailure(code: "rm-exit-status", errno: status))
      }
      return .succeeded(detailCode: "rm-completed")
    } catch let failure as ExecutionAdapterFailure {
      return .failed(failure)
    } catch {
      return .failed(
        ExecutionAdapterFailure(code: String(reflecting: type(of: error))))
    }
  }

  public func postverify(_ operation: ExecutionAdapterOperation) async
    -> PostVerificationOutcome
  {
    guard case .genericRemove(let target, _) = operation else {
      return .unknown(.unsupported)
    }
    do {
      switch try inspect(target, allowMissingTarget: true) {
      case .missing: return .satisfied
      case .present: return .notSatisfied(code: "target-still-present")
      }
    } catch let failure as ExecutionAdapterFailure {
      if failure.errno == EACCES || failure.errno == EPERM {
        return .unreadable(
          ObservationFailure(code: failure.code, collector: "posix-remove-postverify"))
      }
      return .failed(
        ObservationFailure(code: failure.code, collector: "posix-remove-postverify"))
    } catch {
      return .failed(
        ObservationFailure(
          code: String(reflecting: type(of: error)), collector: "posix-remove-postverify"))
    }
  }

  static func arguments(
    target: BoundMutationTarget,
    contract: GenericRemoveContract
  ) throws -> [Data] {
    let path = try absolutePath(target)
    let option: String?
    switch (contract.targetKind, contract.forceRequirement) {
    case (.directory, .notRequired): option = "-Rx"
    case (.directory, .requiresForceWithWarning): option = "-Rfx"
    case (_, .notRequired): option = nil
    case (_, .requiresForceWithWarning): option = "-f"
    }
    var result = [Data("rm".utf8)]
    if let option { result.append(Data(option.utf8)) }
    result.append(Data("--".utf8))
    result.append(path)
    return result
  }

  private func inspect(
    _ target: BoundMutationTarget,
    allowMissingTarget: Bool = false
  ) throws -> Inspection {
    try Self.validateRawPath(target)
    var descriptors: [Int32] = []
    let inspection: Result<Inspection, Error>
    do {
      inspection = .success(
        try inspectOpen(
          target, allowMissingTarget: allowMissingTarget, descriptors: &descriptors))
    } catch {
      inspection = .failure(error)
    }
    var closeFailure: ExecutionAdapterFailure?
    for descriptor in descriptors.reversed() where Darwin.close(descriptor) != 0 {
      if closeFailure == nil {
        closeFailure = ExecutionAdapterFailure(code: "close-preflight-descriptor", errno: errno)
      }
    }
    switch inspection {
    case .success(let result):
      if let closeFailure { throw closeFailure }
      return result
    case .failure(let error):
      throw error
    }
  }

  private func inspectOpen(
    _ target: BoundMutationTarget,
    allowMissingTarget: Bool,
    descriptors: inout [Int32]
  ) throws -> Inspection {

    let rootDescriptor = try Self.withRawCString(target.rawRoot.absoluteBytes) { path in
      let descriptor = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      guard descriptor >= 0 else {
        throw ExecutionAdapterFailure(code: "open-root", errno: errno)
      }
      return descriptor
    }
    descriptors.append(rootDescriptor)
    try Self.requireIdentity(
      descriptor: rootDescriptor,
      expected: target.expectedRootIdentity,
      code: "root-identity-mismatch"
    )

    var parentDescriptor = rootDescriptor
    let parentComponents = target.targetPath.components.dropLast()
    guard parentComponents.count == target.expectedParentIdentities.count else {
      throw ExecutionAdapterFailure(code: "parent-binding-count-mismatch")
    }
    for (component, expectedIdentity) in zip(
      parentComponents, target.expectedParentIdentities)
    {
      let next = try Self.withRawCString(component) { name in
        let descriptor = Darwin.openat(
          parentDescriptor,
          name,
          O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
        )
        guard descriptor >= 0 else {
          throw ExecutionAdapterFailure(code: "open-parent", errno: errno)
        }
        return descriptor
      }
      descriptors.append(next)
      try Self.requireIdentity(
        descriptor: next,
        expected: expectedIdentity,
        code: "parent-identity-mismatch"
      )
      parentDescriptor = next
    }

    guard let leaf = target.targetPath.components.last else {
      throw ExecutionAdapterFailure(code: "empty-target-path")
    }
    var status = stat()
    let result = try Self.withRawCString(leaf) { name in
      Darwin.fstatat(parentDescriptor, name, &status, AT_SYMLINK_NOFOLLOW)
    }
    if result != 0 {
      let currentErrno = errno
      if allowMissingTarget && currentErrno == ENOENT { return .missing }
      throw ExecutionAdapterFailure(code: "stat-target", errno: currentErrno)
    }
    try Self.requireIdentity(
      status: status,
      expected: target.expectedIdentity,
      code: "target-identity-mismatch"
    )
    return .present
  }

  private static func requireIdentity(
    descriptor: Int32,
    expected: ObjectIdentity,
    code: String
  ) throws {
    var status = stat()
    guard Darwin.fstat(descriptor, &status) == 0 else {
      throw ExecutionAdapterFailure(code: "fstat", errno: errno)
    }
    try requireIdentity(status: status, expected: expected, code: code)
  }

  private static func requireIdentity(
    status: stat,
    expected: ObjectIdentity,
    code: String
  ) throws {
    let device = UInt64(UInt32(bitPattern: status.st_dev))
    let object = UInt64(status.st_ino)
    guard device == expected.device,
      object == expected.object,
      objectKind(status.st_mode) == expected.type
    else { throw ExecutionAdapterFailure(code: code) }
    if case .known(let generation) = expected.generation {
      guard generation == UInt64(status.st_gen) else {
        throw ExecutionAdapterFailure(code: "\(code)-generation")
      }
    }
  }

  private static func objectKind(_ mode: mode_t) -> ObjectKind? {
    switch mode & S_IFMT {
    case S_IFREG: return .regularFile
    case S_IFDIR: return .directory
    case S_IFLNK: return .symbolicLink
    default: return nil
    }
  }

  private static func validateRawPath(_ target: BoundMutationTarget) throws {
    guard target.rawRoot.absoluteBytes.first == UInt8(ascii: "/"),
      !target.rawRoot.absoluteBytes.contains(0),
      !target.targetPath.components.isEmpty,
      target.targetPath.components.allSatisfy({
        !$0.isEmpty && !$0.contains(0) && !$0.contains(UInt8(ascii: "/"))
      })
    else { throw ExecutionAdapterFailure(code: "invalid-raw-path") }
  }

  private static func absolutePath(_ target: BoundMutationTarget) throws -> Data {
    try validateRawPath(target)
    var result = target.rawRoot.absoluteBytes
    while result.count > 1 && result.last == UInt8(ascii: "/") { result.removeLast() }
    for component in target.targetPath.components {
      if result.last != UInt8(ascii: "/") { result.append(UInt8(ascii: "/")) }
      result.append(component)
    }
    return result
  }

  private static func spawnRM(arguments: [Data]) throws -> Int32 {
    let executable = Data("/bin/rm".utf8)
    return try withRawCString(executable) { executablePath in
      var allocations: [UnsafeMutablePointer<CChar>] = []
      defer { allocations.forEach { $0.deallocate() } }
      for argument in arguments {
        guard !argument.contains(0) else {
          throw ExecutionAdapterFailure(code: "nul-in-argv")
        }
        let allocation = UnsafeMutablePointer<CChar>.allocate(capacity: argument.count + 1)
        for (index, byte) in argument.enumerated() {
          allocation[index] = CChar(bitPattern: byte)
        }
        allocation[argument.count] = 0
        allocations.append(allocation)
      }
      var argv = allocations.map(Optional.some)
      argv.append(nil)
      var environment: [UnsafeMutablePointer<CChar>?] = [nil]
      var processID = pid_t()
      let spawnStatus = argv.withUnsafeMutableBufferPointer { argumentsBuffer in
        environment.withUnsafeMutableBufferPointer { environmentBuffer in
          posix_spawn(
            &processID,
            executablePath,
            nil,
            nil,
            argumentsBuffer.baseAddress!,
            environmentBuffer.baseAddress!
          )
        }
      }
      guard spawnStatus == 0 else {
        throw ExecutionAdapterFailure(code: "posix-spawn-rm", errno: spawnStatus)
      }
      var waitStatus: Int32 = 0
      while Darwin.waitpid(processID, &waitStatus, 0) == -1 {
        guard errno == EINTR else {
          throw ExecutionAdapterFailure(code: "waitpid-rm", errno: errno)
        }
      }
      let terminatingSignal = waitStatus & 0x7f
      if terminatingSignal == 0 { return (waitStatus >> 8) & 0xff }
      if terminatingSignal != 0x7f { return 128 + terminatingSignal }
      return 255
    }
  }

  private static func withRawCString<Result>(
    _ bytes: Data,
    _ body: (UnsafePointer<CChar>) throws -> Result
  ) throws -> Result {
    guard !bytes.contains(0) else {
      throw ExecutionAdapterFailure(code: "nul-in-path")
    }
    var storage = bytes.map { CChar(bitPattern: $0) }
    storage.append(0)
    return try storage.withUnsafeBufferPointer { buffer in
      try body(buffer.baseAddress!)
    }
  }
}
