import Darwin
import DiskplanPolicy
import Foundation

/// Generic cleanup uses `/bin/rm` through raw argv bytes, never a shell command string.
/// Descriptor-relative no-follow identity checks fence the known path-race residual immediately
/// before spawn; the policy contract still records that the spawn pathname itself can race.
@_spi(DiskplanEngine)
public final class PosixRemoveAdapter: ExecutionMutationAdapter, @unchecked Sendable {
  private enum Inspection {
    case present
    case missing
  }

  private struct OpenBinding {
    let inspection: Inspection
    let descriptors: [Int32]
    let rootDescriptor: Int32
    let parentDescriptors: [Int32]
    let parentDescriptor: Int32
    let targetDescriptor: Int32?
    let leaf: Data
  }

  private let beforeFinalPreflight: @Sendable () -> Void

  public init() {
    beforeFinalPreflight = {}
  }

  init(beforeFinalPreflight: @escaping @Sendable () -> Void) {
    self.beforeFinalPreflight = beforeFinalPreflight
  }

  public func apply(
    _ operation: ExecutionAdapterOperation,
    context: MutationExecutionContext
  ) async -> AdapterOperationOutcome {
    guard case .genericRemove(let target, let contract) = operation else {
      return .failed(ExecutionAdapterFailure(code: "unsupported-action-adapter"))
    }
    guard contract.pathRaceResidual,
      contract.removalPathSlot == .prototypeRawTargetPath,
      contract.targetKind == target.expectedIdentity.type,
      contract.trustedNamespace == target.expectedRootSeal.trustedNamespace,
      target.expectedParentSeals.allSatisfy({
        $0.trustedNamespace == contract.trustedNamespace
      }),
      Self.hasBoundLocalNamespaceSeals(target),
      case .explicitlyNotApplicable = target.expectedContent
    else {
      return .failed(ExecutionAdapterFailure(code: "invalid-generic-remove-contract"))
    }
    do {
      if Task.isCancelled { return .cancelled }
      if context.isExpired { return .timedOut }
      guard try inspect(target) == .present else {
        return .failed(ExecutionAdapterFailure(code: "preflight-target-missing"))
      }
      beforeFinalPreflight()
      if Task.isCancelled { return .cancelled }
      if context.isExpired { return .timedOut }
      let binding = try openBinding(target, allowMissingTarget: false)
      guard binding.inspection == .present else {
        return .failed(ExecutionAdapterFailure(code: "preflight-target-missing"))
      }
      guard let targetDescriptor = binding.targetDescriptor else {
        _ = Self.closeDescriptors(binding.descriptors)
        return .failed(ExecutionAdapterFailure(code: "preflight-target-unreadable"))
      }
      let finalPreflight = await context.finalDescriptorPreflight(
        FinalDescriptorPreflightRequest(
          target: target,
          rootDescriptor: binding.rootDescriptor,
          parentDescriptors: binding.parentDescriptors,
          targetDescriptor: targetDescriptor,
          rawLeafName: binding.leaf
        ))
      guard finalPreflight == .verified else {
        _ = Self.closeDescriptors(binding.descriptors)
        return .failed(Self.finalPreflightFailure(finalPreflight))
      }
      if Task.isCancelled {
        _ = Self.closeDescriptors(binding.descriptors)
        return .cancelled
      }
      if context.isExpired {
        _ = Self.closeDescriptors(binding.descriptors)
        return .timedOut
      }
      let processID: pid_t
      do {
        processID = try Self.spawnRM(
          arguments: Self.relativeArguments(
            leaf: binding.leaf,
            kind: contract.targetKind,
            force: contract.forceRequirement
          ),
          workingDirectoryDescriptor: binding.parentDescriptor
        )
      } catch {
        _ = Self.closeDescriptors(binding.descriptors)
        throw error
      }
      let closeFailure = Self.closeDescriptors(binding.descriptors)
      let outcome = await Self.waitForRM(processID, context: context)
      if let closeFailure, case .succeeded = outcome { return .failed(closeFailure) }
      return outcome
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
    return commandArguments(
      path: path,
      kind: contract.targetKind,
      force: contract.forceRequirement
    )
  }

  static func relativeArguments(
    leaf: Data,
    kind: ObjectKind,
    force: ForceRequirement
  ) -> [Data] {
    var path = Data("./".utf8)
    path.append(leaf)
    return commandArguments(path: path, kind: kind, force: force)
  }

  private static func commandArguments(
    path: Data,
    kind: ObjectKind,
    force: ForceRequirement
  ) -> [Data] {
    let option: String?
    switch (kind, force) {
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
    let binding = try openBinding(target, allowMissingTarget: allowMissingTarget)
    if let closeFailure = Self.closeDescriptors(binding.descriptors) { throw closeFailure }
    return binding.inspection
  }

  private func openBinding(
    _ target: BoundMutationTarget,
    allowMissingTarget: Bool
  ) throws -> OpenBinding {
    try Self.validateRawPath(target)
    var descriptors: [Int32] = []
    do {
      let inspection = try inspectOpen(
        target,
        allowMissingTarget: allowMissingTarget,
        descriptors: &descriptors
      )
      let namespaceDescriptorCount = 1 + target.expectedParentIdentities.count
      guard descriptors.count >= namespaceDescriptorCount,
        let rootDescriptor = descriptors.first,
        let leaf = target.targetPath.components.last
      else { throw ExecutionAdapterFailure(code: "empty-target-path") }
      let parentDescriptor = descriptors[namespaceDescriptorCount - 1]
      let parentDescriptors = Array(
        descriptors.dropFirst().prefix(target.expectedParentIdentities.count))
      let targetDescriptor =
        descriptors.count > namespaceDescriptorCount
        ? descriptors[namespaceDescriptorCount]
        : nil
      return OpenBinding(
        inspection: inspection,
        descriptors: descriptors,
        rootDescriptor: rootDescriptor,
        parentDescriptors: parentDescriptors,
        parentDescriptor: parentDescriptor,
        targetDescriptor: targetDescriptor,
        leaf: leaf
      )
    } catch {
      _ = Self.closeDescriptors(descriptors)
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
    let targetDescriptor = try Self.withRawCString(leaf) { name in
      let openFlags: Int32
      switch target.expectedIdentity.type {
      case .directory:
        openFlags = O_EVTONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
      case .regularFile:
        openFlags = O_EVTONLY | O_NOFOLLOW | O_CLOEXEC
      case .symbolicLink:
        openFlags = O_SYMLINK | O_CLOEXEC
      }
      let descriptor = Darwin.openat(parentDescriptor, name, openFlags)
      guard descriptor >= 0 else {
        throw ExecutionAdapterFailure(code: "open-target", errno: errno)
      }
      return descriptor
    }
    descriptors.append(targetDescriptor)
    try Self.requireIdentity(
      descriptor: targetDescriptor,
      expected: target.expectedIdentity,
      code: "target-descriptor-identity-mismatch"
    )
    return .present
  }

  private static func finalPreflightFailure(
    _ outcome: FinalDescriptorPreflightOutcome
  ) -> ExecutionAdapterFailure {
    switch outcome {
    case .verified:
      return ExecutionAdapterFailure(code: "invalid-final-preflight-state")
    case .missing:
      return ExecutionAdapterFailure(code: "final-preflight-target-missing")
    case .unreadable(let failure):
      return ExecutionAdapterFailure(code: "final-preflight-unreadable-\(failure.code)")
    case .failed(let failure):
      return ExecutionAdapterFailure(code: "final-preflight-failed-\(failure.code)")
    case .identityMismatch:
      return ExecutionAdapterFailure(code: "final-preflight-identity-mismatch")
    case .contentMismatch:
      return ExecutionAdapterFailure(code: "final-preflight-content-mismatch")
    case .accessPolicyMismatch:
      return ExecutionAdapterFailure(code: "final-preflight-access-policy-mismatch")
    case .namespaceIdentityMismatch:
      return ExecutionAdapterFailure(code: "final-preflight-namespace-identity-mismatch")
    case .namespaceAccessPolicyMismatch:
      return ExecutionAdapterFailure(
        code: "final-preflight-namespace-access-policy-mismatch")
    }
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

  private static func hasBoundLocalNamespaceSeals(_ target: BoundMutationTarget) -> Bool {
    let seals = [target.expectedRootSeal] + target.expectedParentSeals
    guard target.expectedTargetAccessPolicy.providerState == .local,
      !target.expectedTargetAccessPolicy.accessPolicyBytes.isEmpty,
      !target.expectedTargetAccessPolicy.mountIdentityBytes.isEmpty,
      let rootMount = target.expectedRootSeal.mountIdentity.knownValue,
      Data(rootMount.utf8) == target.expectedTargetAccessPolicy.mountIdentityBytes
    else { return false }
    return seals.allSatisfy { seal in
      seal.accessPolicy.knownValue != nil
        && seal.aclDigest.knownValue != nil
        && seal.providerBoundary == .known(.local)
        && seal.mountIdentity == .known(rootMount)
    }
  }

  private static func closeDescriptors(_ descriptors: [Int32]) -> ExecutionAdapterFailure? {
    var firstFailure: ExecutionAdapterFailure?
    for descriptor in descriptors.reversed() where Darwin.close(descriptor) != 0 {
      if firstFailure == nil {
        firstFailure = ExecutionAdapterFailure(
          code: "close-preflight-descriptor",
          errno: errno
        )
      }
    }
    return firstFailure
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

  private static func spawnRM(
    arguments: [Data],
    workingDirectoryDescriptor: Int32
  ) throws -> pid_t {
    let executable = Data("/bin/rm".utf8)
    return try withRawCString(executable) { executablePath in
      var allocations: [UnsafeMutablePointer<CChar>] = []
      defer {
        for allocation in allocations { allocation.deallocate() }
      }
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
      var fileActions: posix_spawn_file_actions_t?
      var spawnAttributes: posix_spawnattr_t?
      var actionStatus = posix_spawn_file_actions_init(&fileActions)
      guard actionStatus == 0 else {
        throw ExecutionAdapterFailure(code: "spawn-actions-init", errno: actionStatus)
      }
      defer { _ = posix_spawn_file_actions_destroy(&fileActions) }
      actionStatus = "/dev/null".withCString { path in
        posix_spawn_file_actions_addopen(
          &fileActions,
          STDIN_FILENO,
          path,
          O_RDONLY,
          0
        )
      }
      guard actionStatus == 0 else {
        throw ExecutionAdapterFailure(code: "spawn-actions-stdin", errno: actionStatus)
      }
      actionStatus = posix_spawn_file_actions_addfchdir_np(
        &fileActions,
        workingDirectoryDescriptor
      )
      guard actionStatus == 0 else {
        throw ExecutionAdapterFailure(code: "spawn-actions-fchdir", errno: actionStatus)
      }
      var attributeStatus = posix_spawnattr_init(&spawnAttributes)
      guard attributeStatus == 0 else {
        throw ExecutionAdapterFailure(code: "spawn-attributes-init", errno: attributeStatus)
      }
      defer { _ = posix_spawnattr_destroy(&spawnAttributes) }
      attributeStatus = posix_spawnattr_setpgroup(&spawnAttributes, 0)
      guard attributeStatus == 0 else {
        throw ExecutionAdapterFailure(code: "spawn-attributes-pgroup", errno: attributeStatus)
      }
      attributeStatus = posix_spawnattr_setflags(
        &spawnAttributes,
        Int16(POSIX_SPAWN_SETPGROUP)
      )
      guard attributeStatus == 0 else {
        throw ExecutionAdapterFailure(code: "spawn-attributes-flags", errno: attributeStatus)
      }
      var processID = pid_t()
      let spawnStatus = argv.withUnsafeMutableBufferPointer { argumentsBuffer in
        environment.withUnsafeMutableBufferPointer { environmentBuffer in
          posix_spawn(
            &processID,
            executablePath,
            &fileActions,
            &spawnAttributes,
            argumentsBuffer.baseAddress!,
            environmentBuffer.baseAddress!
          )
        }
      }
      guard spawnStatus == 0 else {
        throw ExecutionAdapterFailure(code: "posix-spawn-rm", errno: spawnStatus)
      }
      return processID
    }
  }

  private static func waitForRM(
    _ processID: pid_t,
    context: MutationExecutionContext
  ) async -> AdapterOperationOutcome {
    while true {
      var waitStatus: Int32 = 0
      let result = Darwin.waitpid(processID, &waitStatus, WNOHANG)
      if result == processID { return terminationOutcome(waitStatus) }
      if result == -1, errno != EINTR {
        return .failed(ExecutionAdapterFailure(code: "waitpid-rm", errno: errno))
      }
      if Task.isCancelled {
        if let failure = await terminateAndReap(processID) { return .failed(failure) }
        return .cancelled
      }
      if context.isExpired {
        if let failure = await terminateAndReap(processID) { return .failed(failure) }
        return .timedOut
      }
      try? await Task.sleep(for: .milliseconds(10))
    }
  }

  private static func terminateAndReap(_ processID: pid_t) async -> ExecutionAdapterFailure? {
    var signalFailure: ExecutionAdapterFailure?
    if Darwin.kill(-processID, SIGTERM) != 0, errno != ESRCH {
      signalFailure = ExecutionAdapterFailure(code: "terminate-rm", errno: errno)
    }
    let graceDeadline = DispatchTime.now().uptimeNanoseconds + 200_000_000
    while DispatchTime.now().uptimeNanoseconds < graceDeadline {
      var status: Int32 = 0
      let result = Darwin.waitpid(processID, &status, WNOHANG)
      if result == processID { return signalFailure }
      if result == -1, errno != EINTR {
        return ExecutionAdapterFailure(code: "waitpid-rm-cleanup", errno: errno)
      }
      try? await Task.sleep(for: .milliseconds(10))
    }
    if Darwin.kill(-processID, SIGKILL) != 0, errno != ESRCH, signalFailure == nil {
      signalFailure = ExecutionAdapterFailure(code: "kill-rm", errno: errno)
    }
    while true {
      var status: Int32 = 0
      let result = Darwin.waitpid(processID, &status, 0)
      if result == processID { return signalFailure }
      if result == -1, errno != EINTR {
        return ExecutionAdapterFailure(code: "waitpid-rm-cleanup", errno: errno)
      }
    }
  }

  private static func terminationOutcome(_ waitStatus: Int32) -> AdapterOperationOutcome {
    let terminatingSignal = waitStatus & 0x7f
    if terminatingSignal == 0 {
      let exitStatus = (waitStatus >> 8) & 0xff
      if exitStatus == 0 { return .succeeded(detailCode: "rm-completed") }
      return .failed(
        ExecutionAdapterFailure(code: "rm-exit-status", exitStatus: exitStatus))
    }
    if terminatingSignal != 0x7f {
      return .failed(
        ExecutionAdapterFailure(
          code: "rm-terminated-by-signal",
          terminatingSignal: terminatingSignal
        ))
    }
    return .failed(ExecutionAdapterFailure(code: "rm-unexpected-wait-status"))
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
