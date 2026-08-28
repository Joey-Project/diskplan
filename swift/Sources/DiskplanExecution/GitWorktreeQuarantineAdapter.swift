import CryptoKit
import Darwin
import DiskplanPolicy
import Foundation

@_spi(DiskplanEngine)
public struct GitWorktreeRecoveryLocator: Equatable, Sendable {
  public let rawRoot: RawRootPath
  public let sourceParentComponents: [Data]
  public let quarantineDirectoryName: Data
  public let quarantineLeafName: Data
  public let identity: ObjectIdentity
}

@_spi(DiskplanEngine)
public struct GitWorktreeAdministrativeResidual: Equatable, Sendable {
  public let registrationID: PolicyDigest
  public let administrativeDirectoryIdentity: ObjectIdentity
  public let commonDirectoryIdentity: ObjectIdentity
  public let failure: ExecutionAdapterFailure
}

@_spi(DiskplanEngine)
public enum GitWorktreeMutationDisposition: Equatable, Sendable {
  case removed
  case localChangesDiscarded
  case restoredAfterVerificationFailure(code: String)
  case quarantineRetained(locator: GitWorktreeRecoveryLocator, failureCode: String)
  case removedWithAdministrativeResidual(GitWorktreeAdministrativeResidual)
}

/// The Git adapter never delegates root removal to Git or to generic `rm`.
///
/// It binds the source path through held no-follow descriptors, moves the exact object into an
/// owner-private same-filesystem namespace with `RENAME_EXCL`, proves that the held source and
/// destination descriptors name the same object, and only then recursively deletes the verified
/// quarantine snapshot. Git is used afterwards solely to prune administrative metadata.
@_spi(DiskplanEngine)
public final class GitWorktreeQuarantineAdapter: ExecutionMutationAdapter, @unchecked Sendable {
  static let quarantineDirectoryName = Data(".diskplan-quarantine".utf8)
  private static let maximumCoverageEntries = 1_000_000
  private static let maximumCoverageBytes: UInt64 = 1 << 40

  struct Hooks: Sendable {
    var beforeQuarantine: @Sendable () -> Void = {}
    var beforePostQuarantineVerification: @Sendable () -> Void = {}
    var beforeRestore: @Sendable () -> Void = {}
    var beforeRecursiveDelete: @Sendable () -> Void = {}
    var beforeAdministrativeCleanup: @Sendable () -> Void = {}
  }

  typealias GitRunner =
    @Sendable (
      _ arguments: [Data], _ workingDirectoryDescriptor: Int32,
      _ context: MutationExecutionContext
    ) async -> AdapterOperationOutcome

  private actor ResultStore {
    var values: [ActionID: GitWorktreeMutationDisposition] = [:]

    func set(_ value: GitWorktreeMutationDisposition, for actionID: ActionID) {
      values[actionID] = value
    }

    func value(for actionID: ActionID) -> GitWorktreeMutationDisposition? {
      values[actionID]
    }
  }

  private struct DescriptorBinding {
    let descriptors: [Int32]
    let rootDescriptor: Int32
    let parentDescriptors: [Int32]
    let parentDescriptor: Int32
    let sourceDescriptor: Int32
    let leaf: Data
  }

  private struct GitAdministrativeBinding {
    let descriptors: [Int32]
    let commonDirectoryDescriptor: Int32
    let registration: GitWorktreeRegistrationEvidence
  }

  private struct QuarantineBinding {
    let descriptor: Int32
    let leaf: Data
    let locator: GitWorktreeRecoveryLocator
  }

  private struct NodeRecord: Equatable {
    let path: [Data]
    let identity: ObjectIdentity
    let mode: UInt32
    let owner: UInt32
    let group: UInt32
    let flags: UInt32
    let size: UInt64
    let payloadDigest: Data
  }

  private struct CoverageToken {
    let records: [NodeRecord]
  }

  private enum AdapterError: Error {
    case failure(ExecutionAdapterFailure)
  }

  private let hooks: Hooks
  private let gitRunner: GitRunner
  private let results = ResultStore()

  public init() {
    hooks = Hooks()
    gitRunner = Self.runGit
  }

  init(hooks: Hooks, gitRunner: @escaping GitRunner) {
    self.hooks = hooks
    self.gitRunner = gitRunner
  }

  public func disposition(for actionID: ActionID) async -> GitWorktreeMutationDisposition? {
    await results.value(for: actionID)
  }

  public func apply(
    _ operation: ExecutionAdapterOperation,
    context: MutationExecutionContext
  ) async -> AdapterOperationOutcome {
    switch operation {
    case .gitWorktreeRemove(let target, let contract):
      return await remove(target: target, contract: contract, context: context)
    case .gitWorktreeDiscardLocalChanges(let target, let contract):
      return await discard(target: target, contract: contract, context: context)
    default:
      return .failed(ExecutionAdapterFailure(code: "unsupported-action-adapter"))
    }
  }

  public func postverify(_ operation: ExecutionAdapterOperation) async
    -> PostVerificationOutcome
  {
    switch operation {
    case .gitWorktreeRemove(let target, _):
      if let disposition = await results.value(for: target.actionID) {
        switch disposition {
        case .removed:
          return sourceIsAbsent(target)
        case .removedWithAdministrativeResidual(let residual):
          return .expectedResidual(residual.failure)
        case .quarantineRetained:
          return .notSatisfied(code: "verified-quarantine-retained")
        case .restoredAfterVerificationFailure:
          return .notSatisfied(code: "source-restored-after-verification-failure")
        case .localChangesDiscarded:
          return .notSatisfied(code: "operation-result-type-mismatch")
        }
      }
      return .unknown(.notRequested)
    case .gitWorktreeDiscardLocalChanges(let target, let contract):
      guard await results.value(for: target.actionID) == .localChangesDiscarded else {
        return .notSatisfied(code: "discard-not-completed")
      }
      do {
        let binding = try openSourceBinding(target)
        defer { Self.close(binding.descriptors) }
        _ = try verifyCoverage(
          rootDescriptor: binding.sourceDescriptor,
          expectedIdentity: target.expectedIdentity,
          expectedContent: contract.successorBaseline.contentProtection,
          expectedAccess: target.expectedTargetAccessPolicy
        )
        return .satisfied
      } catch let AdapterError.failure(failure) {
        return .failed(
          ObservationFailure(code: failure.code, collector: "git-worktree-postverify"))
      } catch {
        return .failed(
          ObservationFailure(
            code: String(reflecting: type(of: error)), collector: "git-worktree-postverify"))
      }
    default:
      return .unknown(.unsupported)
    }
  }

  private func remove(
    target: BoundMutationTarget,
    contract: GitWorktreeRemoveContract,
    context: MutationExecutionContext
  ) async -> AdapterOperationOutcome {
    do {
      try validateRemoveContract(target, contract)
      if Task.isCancelled { return .cancelled }
      if context.isExpired { return .timedOut }

      let source = try openSourceBinding(target)
      defer { Self.close(source.descriptors) }
      let administrative = try openGitAdministrativeBinding(
        worktreeDescriptor: source.sourceDescriptor,
        evidence: contract.verifiedEvidence
      )
      defer { Self.close(administrative.descriptors) }

      let finalPreflight = await context.finalDescriptorPreflight(
        FinalDescriptorPreflightRequest(
          target: target,
          rootDescriptor: source.rootDescriptor,
          parentDescriptors: source.parentDescriptors,
          targetDescriptor: source.sourceDescriptor,
          rawLeafName: source.leaf
        ))
      guard finalPreflight == .verified else {
        return .failed(Self.finalPreflightFailure(finalPreflight))
      }
      if Task.isCancelled { return .cancelled }
      if context.isExpired { return .timedOut }

      _ = try verifyCoverage(
        rootDescriptor: source.sourceDescriptor,
        expectedIdentity: target.expectedIdentity,
        expectedContent: contract.executionBaseline.contentProtection,
        expectedAccess: target.expectedTargetAccessPolicy
      )
      if Task.isCancelled { return .cancelled }
      if context.isExpired { return .timedOut }

      let quarantine = try openQuarantine(
        target: target,
        sourceParentDescriptor: source.parentDescriptor
      )
      defer { _ = Darwin.close(quarantine.descriptor) }

      hooks.beforeQuarantine()
      try requireSourceSlotIdentity(
        parentDescriptor: source.parentDescriptor,
        leaf: source.leaf,
        expected: target.expectedIdentity
      )
      if Task.isCancelled { return .cancelled }
      if context.isExpired { return .timedOut }

      try renameExclusive(
        fromDirectory: source.parentDescriptor,
        from: source.leaf,
        toDirectory: quarantine.descriptor,
        to: quarantine.leaf,
        code: "quarantine-rename"
      )

      let token: CoverageToken
      var destinationDescriptor: Int32?
      defer {
        if let destinationDescriptor { _ = Darwin.close(destinationDescriptor) }
      }
      do {
        try requireSourceSlotMissing(
          parentDescriptor: source.parentDescriptor,
          leaf: source.leaf
        )
        let openedDestination = try openDirectory(
          at: quarantine.descriptor,
          name: quarantine.leaf,
          code: "open-quarantine-destination"
        )
        destinationDescriptor = openedDestination
        try requireSameIdentity(
          sourceDescriptor: source.sourceDescriptor,
          destinationDescriptor: openedDestination,
          expected: target.expectedIdentity
        )

        hooks.beforePostQuarantineVerification()
        token = try verifyCoverage(
          rootDescriptor: openedDestination,
          expectedIdentity: target.expectedIdentity,
          expectedContent: contract.executionBaseline.contentProtection,
          expectedAccess: target.expectedTargetAccessPolicy
        )

        if Task.isCancelled {
          return await restoreAfterInterruption(
            target: target,
            source: source,
            quarantine: quarantine,
            outcome: .cancelled,
            failureCode: "cancelled-after-quarantine"
          )
        }
        if context.isExpired {
          return await restoreAfterInterruption(
            target: target,
            source: source,
            quarantine: quarantine,
            outcome: .timedOut,
            failureCode: "deadline-after-quarantine"
          )
        }

      } catch let AdapterError.failure(verificationFailure) {
        return await restoreAfterVerificationFailure(
          target: target,
          source: source,
          quarantine: quarantine,
          failure: verificationFailure
        )
      }
      guard let destinationDescriptor else {
        return .failed(ExecutionAdapterFailure(code: "missing-quarantine-destination-binding"))
      }

      hooks.beforeRecursiveDelete()
      do {
        try requireSnapshotStillCurrent(token, rootDescriptor: destinationDescriptor)
      } catch let AdapterError.failure(verificationFailure) {
        return await restoreAfterVerificationFailure(
          target: target,
          source: source,
          quarantine: quarantine,
          failure: verificationFailure
        )
      }
      do {
        try recursivelyDeleteVerifiedTree(
          token,
          rootDescriptor: destinationDescriptor,
          quarantineDescriptor: quarantine.descriptor,
          quarantineLeaf: quarantine.leaf
        )
      } catch let AdapterError.failure(deletionFailure) {
        await results.set(
          .quarantineRetained(
            locator: quarantine.locator,
            failureCode: deletionFailure.code
          ),
          for: target.actionID
        )
        return .failed(
          ExecutionAdapterFailure(
            code: "verified-quarantine-deletion-residual",
            errno: deletionFailure.errno
          ))
      }

      hooks.beforeAdministrativeCleanup()
      if Task.isCancelled {
        return await recordAdministrativeResidual(
          target: target,
          administrative: administrative,
          failure: ExecutionAdapterFailure(code: "git-administrative-cleanup-cancelled")
        )
      }
      if context.isExpired {
        return await recordAdministrativeResidual(
          target: target,
          administrative: administrative,
          failure: ExecutionAdapterFailure(code: "git-administrative-cleanup-deadline")
        )
      }

      let administrativeOutcome = await gitRunner(
        [
          Data("git".utf8), Data("--git-dir=.".utf8), Data("worktree".utf8),
          Data("prune".utf8), Data("--expire".utf8), Data("now".utf8),
        ],
        administrative.commonDirectoryDescriptor,
        context
      )
      guard case .succeeded = administrativeOutcome else {
        let failure = Self.failureFromGitOutcome(
          administrativeOutcome,
          defaultCode: "git-administrative-cleanup-failed"
        )
        return await recordAdministrativeResidual(
          target: target,
          administrative: administrative,
          failure: failure
        )
      }

      await results.set(.removed, for: target.actionID)
      return .succeeded(detailCode: "git-worktree-quarantine-removed")
    } catch let AdapterError.failure(failure) {
      return .failed(failure)
    } catch {
      return .failed(ExecutionAdapterFailure(code: String(reflecting: type(of: error))))
    }
  }

  private func recordAdministrativeResidual(
    target: BoundMutationTarget,
    administrative: GitAdministrativeBinding,
    failure: ExecutionAdapterFailure
  ) async -> AdapterOperationOutcome {
    let residual = GitWorktreeAdministrativeResidual(
      registrationID: administrative.registration.registrationID,
      administrativeDirectoryIdentity:
        administrative.registration.administrativeDirectoryIdentity,
      commonDirectoryIdentity: administrative.registration.commonDirectoryIdentity,
      failure: failure
    )
    await results.set(.removedWithAdministrativeResidual(residual), for: target.actionID)
    return .succeeded(detailCode: "git-worktree-removed-with-administrative-residual")
  }

  private func discard(
    target: BoundMutationTarget,
    contract: GitWorktreeDiscardLocalChangesContract,
    context: MutationExecutionContext
  ) async -> AdapterOperationOutcome {
    do {
      try validateDiscardContract(target, contract)
      if Task.isCancelled { return .cancelled }
      if context.isExpired { return .timedOut }

      let source = try openSourceBinding(target)
      defer { Self.close(source.descriptors) }
      let administrative = try openGitAdministrativeBinding(
        worktreeDescriptor: source.sourceDescriptor,
        evidence: contract.verifiedEvidence
      )
      Self.close(administrative.descriptors)
      let finalPreflight = await context.finalDescriptorPreflight(
        FinalDescriptorPreflightRequest(
          target: target,
          rootDescriptor: source.rootDescriptor,
          parentDescriptors: source.parentDescriptors,
          targetDescriptor: source.sourceDescriptor,
          rawLeafName: source.leaf
        ))
      guard finalPreflight == .verified else {
        return .failed(Self.finalPreflightFailure(finalPreflight))
      }
      if Task.isCancelled { return .cancelled }
      if context.isExpired { return .timedOut }
      _ = try verifyCoverage(
        rootDescriptor: source.sourceDescriptor,
        expectedIdentity: target.expectedIdentity,
        expectedContent: target.expectedContent,
        expectedAccess: target.expectedTargetAccessPolicy
      )
      if Task.isCancelled { return .cancelled }
      if context.isExpired { return .timedOut }

      var outcome = await gitRunner(
        [Data("git".utf8), Data("reset".utf8), Data("--hard".utf8), Data("HEAD".utf8)],
        source.sourceDescriptor,
        context
      )
      guard case .succeeded = outcome else { return outcome }
      if Task.isCancelled { return .cancelled }
      if context.isExpired { return .timedOut }
      outcome = await gitRunner(
        [Data("git".utf8), Data("clean".utf8), Data("-ffdx".utf8)],
        source.sourceDescriptor,
        context
      )
      guard case .succeeded = outcome else { return outcome }

      _ = try verifyCoverage(
        rootDescriptor: source.sourceDescriptor,
        expectedIdentity: target.expectedIdentity,
        expectedContent: contract.successorBaseline.contentProtection,
        expectedAccess: target.expectedTargetAccessPolicy
      )
      await results.set(.localChangesDiscarded, for: target.actionID)
      return .succeeded(detailCode: "git-worktree-local-changes-discarded")
    } catch let AdapterError.failure(failure) {
      return .failed(failure)
    } catch {
      return .failed(ExecutionAdapterFailure(code: String(reflecting: type(of: error))))
    }
  }

  private func restoreAfterVerificationFailure(
    target: BoundMutationTarget,
    source: DescriptorBinding,
    quarantine: QuarantineBinding,
    failure: ExecutionAdapterFailure
  ) async -> AdapterOperationOutcome {
    hooks.beforeRestore()
    do {
      try renameExclusive(
        fromDirectory: quarantine.descriptor,
        from: quarantine.leaf,
        toDirectory: source.parentDescriptor,
        to: source.leaf,
        code: "restore-source-slot"
      )
      await results.set(
        .restoredAfterVerificationFailure(code: failure.code),
        for: target.actionID
      )
      return .failed(
        ExecutionAdapterFailure(
          code: "quarantine-verification-failed-restored",
          errno: failure.errno
        ))
    } catch {
      await results.set(
        .quarantineRetained(locator: quarantine.locator, failureCode: failure.code),
        for: target.actionID
      )
      return .failed(
        ExecutionAdapterFailure(code: "quarantine-verification-failed-retained"))
    }
  }

  private func restoreAfterInterruption(
    target: BoundMutationTarget,
    source: DescriptorBinding,
    quarantine: QuarantineBinding,
    outcome: AdapterOperationOutcome,
    failureCode: String
  ) async -> AdapterOperationOutcome {
    hooks.beforeRestore()
    do {
      try renameExclusive(
        fromDirectory: quarantine.descriptor,
        from: quarantine.leaf,
        toDirectory: source.parentDescriptor,
        to: source.leaf,
        code: "restore-source-slot"
      )
      await results.set(
        .restoredAfterVerificationFailure(code: failureCode),
        for: target.actionID
      )
      return outcome
    } catch {
      await results.set(
        .quarantineRetained(locator: quarantine.locator, failureCode: failureCode),
        for: target.actionID
      )
      return .failed(ExecutionAdapterFailure(code: "interrupted-quarantine-retained"))
    }
  }

  private func validateRemoveContract(
    _ target: BoundMutationTarget,
    _ contract: GitWorktreeRemoveContract
  ) throws {
    guard let head = contract.verifiedEvidence.headIdentity.knownValue,
      let index = contract.verifiedEvidence.indexDigest.knownValue,
      let localChanges = contract.verifiedEvidence.localChanges.knownValue
    else { throw failure("invalid-git-worktree-remove-contract") }
    let baselineMatches: Bool
    switch localChanges {
    case .clean:
      baselineMatches =
        !contract.requiresDiscardLocalChanges
        && contract.executionBaseline.headIdentity == head
        && contract.executionBaseline.indexDigest == index
    case .present:
      baselineMatches =
        contract.requiresDiscardLocalChanges
        && contract.verifiedEvidence.postDiscardSuccessor
          == .known(contract.executionBaseline)
    }
    guard contract.quarantineRequired,
      baselineMatches,
      contract.executionBaseline.localChanges == .clean,
      target.expectedContent == contract.executionBaseline.contentProtection,
      target.expectedIdentity.type == .directory,
      target.postcondition == .worktreeQuarantinedThenAbsent,
      target.expectedRootSeal.trustedNamespace == .ownerPrivate,
      target.expectedParentSeals.allSatisfy({ $0.trustedNamespace == .ownerPrivate }),
      hasBoundLocalNamespaceSeals(target),
      contract.verifiedEvidence.trustedExclusiveNamespace == .known(true),
      contract.verifiedEvidence.noFollowTraversalComplete == .known(true),
      contract.verifiedEvidence.postQuarantineCoverage == .known(.complete),
      Self.hasExecutableLinkedRegistration(contract.verifiedEvidence),
      contract.verifiedEvidence.sparseCheckout == .known(.disabled),
      contract.verifiedEvidence.nestedRepositories == .known(.none),
      contract.verifiedEvidence.submodules == .known(.none),
      contract.verifiedEvidence.registration.knownValue?.registeredWorktreeIdentity
        == target.expectedIdentity
    else { throw failure("invalid-git-worktree-remove-contract") }
  }

  private func validateDiscardContract(
    _ target: BoundMutationTarget,
    _ contract: GitWorktreeDiscardLocalChangesContract
  ) throws {
    guard target.expectedIdentity.type == .directory,
      target.postcondition
        == .gitWorktreeLocalChangesDiscarded(
          changeSetDigest: contract.changeSetDigest,
          successor: contract.successorBaseline
        ),
      target.expectedRootSeal.trustedNamespace == .ownerPrivate,
      target.expectedParentSeals.allSatisfy({ $0.trustedNamespace == .ownerPrivate }),
      hasBoundLocalNamespaceSeals(target),
      contract.verifiedEvidence.trustedExclusiveNamespace == .known(true),
      contract.verifiedEvidence.noFollowTraversalComplete == .known(true),
      contract.verifiedEvidence.postQuarantineCoverage == .known(.complete),
      Self.hasExecutableLinkedRegistration(contract.verifiedEvidence),
      contract.verifiedEvidence.sparseCheckout == .known(.disabled),
      contract.verifiedEvidence.nestedRepositories == .known(.none),
      contract.verifiedEvidence.submodules == .known(.none),
      contract.verifiedEvidence.registration.knownValue?.registeredWorktreeIdentity
        == target.expectedIdentity,
      case .some(.present(let digest)) = contract.verifiedEvidence.localChanges.knownValue,
      digest == contract.changeSetDigest,
      contract.verifiedEvidence.postDiscardSuccessor == .known(contract.successorBaseline)
    else { throw failure("invalid-git-worktree-discard-contract") }
  }

  static func hasExecutableLinkedRegistration(_ evidence: GitWorktreeEvidence) -> Bool {
    guard case .known(let registration) = evidence.registration,
      case .known(.linked(let registrationID)) = evidence.linkage
    else { return false }
    return registrationID == registration.registrationID
      && registration.administrativeDirectoryIdentity
        != registration.commonDirectoryIdentity
  }

  private func openSourceBinding(_ target: BoundMutationTarget) throws -> DescriptorBinding {
    try validateRawPath(target)
    var descriptors: [Int32] = []
    do {
      let root = try Self.withRawCString(target.rawRoot.absoluteBytes) { path -> Int32 in
        let descriptor = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw failure("open-root", errno) }
        return descriptor
      }
      descriptors.append(root)
      try requireIdentity(
        root, expected: target.expectedRootIdentity, code: "root-identity-mismatch")
      try requireOwnerPrivateDirectory(root, expectedDevice: target.expectedRootIdentity.device)
      try requireSeal(target.expectedRootSeal, access: target.expectedTargetAccessPolicy)

      var parent = root
      let parentComponents = target.targetPath.components.dropLast()
      guard parentComponents.count == target.expectedParentIdentities.count,
        target.expectedParentIdentities.count == target.expectedParentSeals.count
      else { throw failure("parent-binding-count-mismatch") }
      for index in parentComponents.indices {
        let descriptor = try openDirectory(
          at: parent,
          name: parentComponents[index],
          code: "open-parent"
        )
        descriptors.append(descriptor)
        try requireIdentity(
          descriptor,
          expected: target.expectedParentIdentities[index],
          code: "parent-identity-mismatch"
        )
        try requireOwnerPrivateDirectory(
          descriptor,
          expectedDevice: target.expectedRootIdentity.device
        )
        try requireSeal(
          target.expectedParentSeals[index], access: target.expectedTargetAccessPolicy)
        parent = descriptor
      }

      guard let leaf = target.targetPath.components.last else {
        throw failure("empty-target-path")
      }
      let source = try openDirectory(at: parent, name: leaf, code: "open-worktree-root")
      descriptors.append(source)
      try requireIdentity(
        source, expected: target.expectedIdentity, code: "target-identity-mismatch")
      try requireOwnerPrivateDirectory(source, expectedDevice: target.expectedRootIdentity.device)
      return DescriptorBinding(
        descriptors: descriptors,
        rootDescriptor: root,
        parentDescriptors: Array(descriptors.dropFirst().dropLast()),
        parentDescriptor: parent,
        sourceDescriptor: source,
        leaf: leaf
      )
    } catch {
      Self.close(descriptors)
      throw error
    }
  }

  private func openGitAdministrativeBinding(
    worktreeDescriptor: Int32,
    evidence: GitWorktreeEvidence
  ) throws -> GitAdministrativeBinding {
    guard let registration = evidence.registration.knownValue else {
      throw failure("missing-git-registration")
    }
    var status = stat()
    let statResult = try Self.withRawCString(Data(".git".utf8)) { name in
      Darwin.fstatat(worktreeDescriptor, name, &status, AT_SYMLINK_NOFOLLOW)
    }
    guard statResult == 0, (status.st_mode & S_IFMT) == S_IFREG else {
      throw failure("git-link-file-invalid", statResult == 0 ? nil : errno)
    }
    let linkDescriptor = try Self.withRawCString(Data(".git".utf8)) { name -> Int32 in
      let descriptor = Darwin.openat(
        worktreeDescriptor, name, O_RDONLY | O_NOFOLLOW | O_CLOEXEC
      )
      guard descriptor >= 0 else { throw failure("open-git-link-file", errno) }
      return descriptor
    }
    defer { _ = Darwin.close(linkDescriptor) }
    let link = try readAll(linkDescriptor, maximumBytes: 64 * 1024)
    guard link.starts(with: Data("gitdir: ".utf8)) else {
      throw failure("git-link-file-format")
    }
    var adminPath = Data(link.dropFirst("gitdir: ".utf8.count))
    while adminPath.last == UInt8(ascii: "\n") || adminPath.last == UInt8(ascii: "\r") {
      adminPath.removeLast()
    }
    guard adminPath.first == UInt8(ascii: "/"), !adminPath.contains(0) else {
      throw failure("git-administrative-path-not-absolute")
    }

    var descriptors: [Int32] = []
    do {
      let admin = try Self.withRawCString(adminPath) { path -> Int32 in
        let descriptor = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw failure("open-git-administrative-directory", errno) }
        return descriptor
      }
      descriptors.append(admin)
      try requireIdentity(
        admin,
        expected: registration.administrativeDirectoryIdentity,
        code: "git-administrative-identity-mismatch"
      )
      try requireOwnerPrivateDirectory(
        admin,
        expectedDevice: registration.administrativeDirectoryIdentity.device
      )

      let worktrees = try openDirectory(at: admin, name: Data("..".utf8), code: "open-worktrees")
      descriptors.append(worktrees)
      let common = try openDirectory(at: worktrees, name: Data("..".utf8), code: "open-common-git")
      descriptors.append(common)
      try requireIdentity(
        common,
        expected: registration.commonDirectoryIdentity,
        code: "git-common-identity-mismatch"
      )
      try requireOwnerPrivateDirectory(
        common,
        expectedDevice: registration.commonDirectoryIdentity.device
      )
      return GitAdministrativeBinding(
        descriptors: descriptors,
        commonDirectoryDescriptor: common,
        registration: registration
      )
    } catch {
      Self.close(descriptors)
      throw error
    }
  }

  private func openQuarantine(
    target: BoundMutationTarget,
    sourceParentDescriptor: Int32
  ) throws -> QuarantineBinding {
    let name = Self.quarantineDirectoryName
    let mkdirResult = try Self.withRawCString(name) {
      Darwin.mkdirat(sourceParentDescriptor, $0, 0o700)
    }
    if mkdirResult != 0, errno != EEXIST {
      throw failure("create-quarantine-directory", errno)
    }
    let descriptor = try openDirectory(
      at: sourceParentDescriptor,
      name: name,
      code: "open-quarantine-directory"
    )
    do {
      try requireOwnerPrivateDirectory(descriptor, expectedDevice: target.expectedIdentity.device)
      let leaf = Data(target.actionID.hex.utf8)
      let locator = GitWorktreeRecoveryLocator(
        rawRoot: target.rawRoot,
        sourceParentComponents: Array(target.targetPath.components.dropLast()),
        quarantineDirectoryName: name,
        quarantineLeafName: leaf,
        identity: target.expectedIdentity
      )
      return QuarantineBinding(descriptor: descriptor, leaf: leaf, locator: locator)
    } catch {
      _ = Darwin.close(descriptor)
      throw error
    }
  }

  private func verifyCoverage(
    rootDescriptor: Int32,
    expectedIdentity: ObjectIdentity,
    expectedContent: ContentProtectionBaseline,
    expectedAccess: RequiredAccessPolicyBaseline
  ) throws -> CoverageToken {
    guard expectedAccess.providerState == .local,
      !expectedAccess.accessPolicyBytes.isEmpty,
      !expectedAccess.mountIdentityBytes.isEmpty
    else { throw failure("unbound-worktree-access-policy") }
    try requireIdentity(
      rootDescriptor,
      expected: expectedIdentity,
      code: "coverage-root-identity-mismatch"
    )
    try requireOwnerPrivateDirectory(rootDescriptor, expectedDevice: expectedIdentity.device)

    let first = try collectSnapshot(rootDescriptor: rootDescriptor)
    let second = try collectSnapshot(rootDescriptor: rootDescriptor)
    guard first == second else { throw failure("post-quarantine-coverage-raced") }
    let actualDigest = try digest(first)
    guard case .requiredDigest(let expectedDigest) = expectedContent,
      actualDigest == expectedDigest
    else { throw failure("worktree-content-mismatch") }
    return CoverageToken(records: second)
  }

  private func collectSnapshot(rootDescriptor: Int32) throws -> [NodeRecord] {
    var records: [NodeRecord] = []
    var remainingEntries = Self.maximumCoverageEntries
    var remainingBytes = Self.maximumCoverageBytes
    try collectDirectory(
      descriptor: rootDescriptor,
      path: [],
      expectedDevice: try device(rootDescriptor),
      remainingEntries: &remainingEntries,
      remainingBytes: &remainingBytes,
      records: &records
    )
    return records.sorted { Self.comparePaths($0.path, $1.path) }
  }

  private func collectDirectory(
    descriptor: Int32,
    path: [Data],
    expectedDevice: UInt64,
    remainingEntries: inout Int,
    remainingBytes: inout UInt64,
    records: inout [NodeRecord]
  ) throws {
    guard remainingEntries > 0 else { throw failure("coverage-entry-budget-exhausted") }
    remainingEntries -= 1
    let directoryStatus = try status(descriptor)
    guard Self.kind(directoryStatus.st_mode) == .directory,
      Self.device(directoryStatus) == expectedDevice
    else { throw failure("coverage-mount-or-type-mismatch") }
    records.append(try record(path: path, status: directoryStatus, payload: Data()))

    let duplicate = try openDirectory(
      at: descriptor,
      name: Data(".".utf8),
      code: "open-coverage-enumeration-directory"
    )
    guard let stream = Darwin.fdopendir(duplicate) else {
      let currentErrno = errno
      _ = Darwin.close(duplicate)
      throw failure("fdopendir-coverage", currentErrno)
    }
    defer { _ = Darwin.closedir(stream) }

    var names: [Data] = []
    errno = 0
    while let entry = Darwin.readdir(stream) {
      let name = withUnsafeBytes(of: entry.pointee.d_name) { raw -> Data in
        let length = raw.firstIndex(of: 0) ?? raw.count
        return Data(raw.prefix(length))
      }
      if name == Data(".".utf8) || name == Data("..".utf8) { continue }
      guard !name.isEmpty, !name.contains(0), !name.contains(UInt8(ascii: "/")) else {
        throw failure("invalid-directory-entry-name")
      }
      names.append(name)
      errno = 0
    }
    guard errno == 0 else { throw failure("readdir-coverage", errno) }
    names.sort { $0.lexicographicallyPrecedes($1) }

    for name in names {
      var childStatus = stat()
      let result = try Self.withRawCString(name) {
        Darwin.fstatat(descriptor, $0, &childStatus, AT_SYMLINK_NOFOLLOW)
      }
      guard result == 0 else { throw failure("stat-coverage-entry", errno) }
      guard Self.device(childStatus) == expectedDevice,
        let childKind = Self.kind(childStatus.st_mode)
      else { throw failure("coverage-mount-or-type-mismatch") }
      let childPath = path + [name]
      switch childKind {
      case .directory:
        let child = try openDirectory(at: descriptor, name: name, code: "open-coverage-directory")
        defer { _ = Darwin.close(child) }
        try requireIdentity(
          child,
          expected: Self.identity(childStatus),
          code: "coverage-directory-replaced"
        )
        try collectDirectory(
          descriptor: child,
          path: childPath,
          expectedDevice: expectedDevice,
          remainingEntries: &remainingEntries,
          remainingBytes: &remainingBytes,
          records: &records
        )
      case .regularFile:
        guard remainingEntries > 0 else { throw failure("coverage-entry-budget-exhausted") }
        remainingEntries -= 1
        let payload = try digestRegularFile(
          parentDescriptor: descriptor,
          name: name,
          expected: childStatus,
          remainingBytes: &remainingBytes
        )
        records.append(try record(path: childPath, status: childStatus, payload: payload))
      case .symbolicLink:
        guard remainingEntries > 0 else { throw failure("coverage-entry-budget-exhausted") }
        remainingEntries -= 1
        let payload = try readSymbolicLink(
          parentDescriptor: descriptor,
          name: name,
          expected: childStatus,
          remainingBytes: &remainingBytes
        )
        records.append(try record(path: childPath, status: childStatus, payload: payload))
      }
    }
  }

  private func requireSnapshotStillCurrent(
    _ token: CoverageToken,
    rootDescriptor: Int32
  ) throws {
    let current = try collectSnapshot(rootDescriptor: rootDescriptor)
    guard current == token.records else {
      throw failure("verified-quarantine-changed-before-delete")
    }
  }

  private func recursivelyDeleteVerifiedTree(
    _ token: CoverageToken,
    rootDescriptor: Int32,
    quarantineDescriptor: Int32,
    quarantineLeaf: Data
  ) throws {
    for record in token.records.dropFirst().sorted(by: { lhs, rhs in
      if lhs.path.count != rhs.path.count { return lhs.path.count > rhs.path.count }
      return Self.comparePaths(rhs.path, lhs.path)
    }) {
      let parentPath = Array(record.path.dropLast())
      guard let leaf = record.path.last else { throw failure("invalid-coverage-token") }
      let opened = try openRelativeDirectory(rootDescriptor, components: parentPath)
      defer { Self.close(opened.dropFirst()) }
      let parent = opened.last ?? rootDescriptor
      try requireSourceSlotIdentity(parentDescriptor: parent, leaf: leaf, expected: record.identity)
      let flags = record.identity.type == .directory ? AT_REMOVEDIR : 0
      let result = try Self.withRawCString(leaf) { Darwin.unlinkat(parent, $0, flags) }
      guard result == 0 else { throw failure("delete-verified-quarantine-entry", errno) }
    }
    let result = try Self.withRawCString(quarantineLeaf) {
      Darwin.unlinkat(quarantineDescriptor, $0, AT_REMOVEDIR)
    }
    guard result == 0 else { throw failure("delete-verified-quarantine-root", errno) }
  }

  private func openRelativeDirectory(
    _ root: Int32,
    components: [Data]
  ) throws -> [Int32] {
    var descriptors = [root]
    do {
      for component in components {
        let next = try openDirectory(
          at: descriptors.last!,
          name: component,
          code: "open-delete-parent"
        )
        descriptors.append(next)
      }
      return descriptors
    } catch {
      Self.close(descriptors.dropFirst())
      throw error
    }
  }

  private func sourceIsAbsent(_ target: BoundMutationTarget) -> PostVerificationOutcome {
    do {
      try validateRawPath(target)
      let root = try Self.withRawCString(target.rawRoot.absoluteBytes) { path -> Int32 in
        let descriptor = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw failure("postverify-open-root", errno) }
        return descriptor
      }
      defer { _ = Darwin.close(root) }
      var parent = root
      var opened: [Int32] = []
      defer { Self.close(opened) }
      for component in target.targetPath.components.dropLast() {
        let next = try openDirectory(at: parent, name: component, code: "postverify-open-parent")
        opened.append(next)
        parent = next
      }
      guard let leaf = target.targetPath.components.last else {
        return .failed(
          ObservationFailure(code: "empty-target-path", collector: "git-worktree-postverify"))
      }
      var status = stat()
      let result = try Self.withRawCString(leaf) {
        Darwin.fstatat(parent, $0, &status, AT_SYMLINK_NOFOLLOW)
      }
      if result != 0, errno == ENOENT { return .satisfied }
      if result == 0 { return .notSatisfied(code: "worktree-root-still-present") }
      return .failed(
        ObservationFailure(code: "postverify-stat-target", collector: "git-worktree-postverify"))
    } catch let AdapterError.failure(failure) {
      return .failed(
        ObservationFailure(code: failure.code, collector: "git-worktree-postverify"))
    } catch {
      return .failed(
        ObservationFailure(
          code: String(reflecting: type(of: error)), collector: "git-worktree-postverify"))
    }
  }

  static func measuredContentDigest(atRawPath path: Data) throws -> PolicyDigest {
    let descriptor = try withRawCString(path) { pathPointer -> Int32 in
      let value = Darwin.open(pathPointer, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      guard value >= 0 else { throw failure("open-content-measurement-root", errno) }
      return value
    }
    defer { _ = Darwin.close(descriptor) }
    let adapter = GitWorktreeQuarantineAdapter()
    return try adapter.digest(adapter.collectSnapshot(rootDescriptor: descriptor))
  }

  private func digest(_ records: [NodeRecord]) throws -> PolicyDigest {
    var data = Data("diskplan/git-worktree-content/v1\0".utf8)
    Self.append(UInt64(records.count), to: &data)
    for record in records {
      Self.append(UInt64(record.path.count), to: &data)
      for component in record.path {
        Self.append(UInt64(component.count), to: &data)
        data.append(component)
      }
      Self.append(record.identity.device, to: &data)
      Self.append(record.identity.object, to: &data)
      switch record.identity.generation {
      case .known(let generation):
        data.append(1)
        Self.append(generation, to: &data)
      default:
        data.append(0)
      }
      data.append(Data(record.identity.type.rawValue.utf8))
      data.append(0)
      Self.append(UInt64(record.mode), to: &data)
      Self.append(UInt64(record.owner), to: &data)
      Self.append(UInt64(record.group), to: &data)
      Self.append(UInt64(record.flags), to: &data)
      Self.append(record.size, to: &data)
      Self.append(UInt64(record.payloadDigest.count), to: &data)
      data.append(record.payloadDigest)
    }
    return try PolicyDigest(bytes: Data(SHA256.hash(data: data)))
  }

  private func record(path: [Data], status: stat, payload: Data) throws -> NodeRecord {
    guard let kind = Self.kind(status.st_mode) else {
      throw failure("unsupported-filesystem-entry-type")
    }
    let digest: Data
    if kind == .directory {
      digest = Data()
    } else if kind == .regularFile {
      digest = payload
    } else {
      digest = Data(SHA256.hash(data: payload))
    }
    return NodeRecord(
      path: path,
      identity: Self.identity(status),
      mode: UInt32(status.st_mode),
      owner: UInt32(status.st_uid),
      group: UInt32(status.st_gid),
      flags: UInt32(status.st_flags),
      size: UInt64(max(status.st_size, 0)),
      payloadDigest: digest
    )
  }

  private func digestRegularFile(
    parentDescriptor: Int32,
    name: Data,
    expected: stat,
    remainingBytes: inout UInt64
  ) throws -> Data {
    let descriptor = try Self.withRawCString(name) { namePointer -> Int32 in
      let value = Darwin.openat(
        parentDescriptor,
        namePointer,
        O_RDONLY | O_NOFOLLOW | O_CLOEXEC
      )
      guard value >= 0 else { throw failure("open-coverage-file", errno) }
      return value
    }
    defer { _ = Darwin.close(descriptor) }
    try requireIdentity(
      descriptor,
      expected: Self.identity(expected),
      code: "coverage-file-replaced"
    )
    let before = try status(descriptor)
    var hasher = SHA256()
    var buffer = [UInt8](repeating: 0, count: 64 * 1024)
    while true {
      let count = buffer.withUnsafeMutableBytes {
        Darwin.read(descriptor, $0.baseAddress, $0.count)
      }
      if count == 0 { break }
      if count < 0 {
        if errno == EINTR { continue }
        throw failure("read-coverage-file", errno)
      }
      guard UInt64(count) <= remainingBytes else {
        throw failure("coverage-byte-budget-exhausted")
      }
      remainingBytes -= UInt64(count)
      hasher.update(data: Data(buffer.prefix(count)))
    }
    let after = try status(descriptor)
    guard Self.stableFile(before, after), Self.stableFile(expected, after) else {
      throw failure("coverage-file-content-raced")
    }
    return Data(hasher.finalize())
  }

  private func readSymbolicLink(
    parentDescriptor: Int32,
    name: Data,
    expected: stat,
    remainingBytes: inout UInt64
  ) throws -> Data {
    var capacity = max(Int(expected.st_size) + 1, 256)
    while capacity <= 1024 * 1024 {
      var buffer = [UInt8](repeating: 0, count: capacity)
      let count = try Self.withRawCString(name) { namePointer in
        buffer.withUnsafeMutableBytes { raw in
          Darwin.readlinkat(
            parentDescriptor,
            namePointer,
            raw.baseAddress!.assumingMemoryBound(to: CChar.self),
            raw.count
          )
        }
      }
      guard count >= 0 else { throw failure("readlink-coverage", errno) }
      if count < capacity {
        guard UInt64(count) <= remainingBytes else {
          throw failure("coverage-byte-budget-exhausted")
        }
        remainingBytes -= UInt64(count)
        var current = stat()
        let result = try Self.withRawCString(name) {
          Darwin.fstatat(parentDescriptor, $0, &current, AT_SYMLINK_NOFOLLOW)
        }
        guard result == 0, Self.identity(current) == Self.identity(expected),
          current.st_mode == expected.st_mode,
          current.st_uid == expected.st_uid,
          current.st_gid == expected.st_gid,
          current.st_flags == expected.st_flags
        else { throw failure("coverage-symlink-raced", result == 0 ? nil : errno) }
        return Data(buffer.prefix(count))
      }
      capacity *= 2
    }
    throw failure("symlink-target-too-large")
  }

  private func requireSourceSlotIdentity(
    parentDescriptor: Int32,
    leaf: Data,
    expected: ObjectIdentity
  ) throws {
    var current = stat()
    let result = try Self.withRawCString(leaf) {
      Darwin.fstatat(parentDescriptor, $0, &current, AT_SYMLINK_NOFOLLOW)
    }
    guard result == 0 else { throw failure("stat-source-slot", errno) }
    try requireIdentity(current, expected: expected, code: "source-slot-identity-mismatch")
  }

  private func requireSourceSlotMissing(
    parentDescriptor: Int32,
    leaf: Data
  ) throws {
    var current = stat()
    let result = try Self.withRawCString(leaf) {
      Darwin.fstatat(parentDescriptor, $0, &current, AT_SYMLINK_NOFOLLOW)
    }
    guard result != 0, errno == ENOENT else {
      throw failure("source-slot-not-empty-after-quarantine", result == 0 ? nil : errno)
    }
  }

  private func requireSameIdentity(
    sourceDescriptor: Int32,
    destinationDescriptor: Int32,
    expected: ObjectIdentity
  ) throws {
    let source = try status(sourceDescriptor)
    let destination = try status(destinationDescriptor)
    try requireIdentity(source, expected: expected, code: "held-source-identity-mismatch")
    try requireIdentity(
      destination,
      expected: expected,
      code: "quarantine-destination-identity-mismatch"
    )
    guard Self.identity(source) == Self.identity(destination) else {
      throw failure("source-destination-object-mismatch")
    }
  }

  private func requireSeal(
    _ seal: NamespaceSealEvidence,
    access: RequiredAccessPolicyBaseline
  ) throws {
    guard seal.trustedNamespace == .ownerPrivate,
      seal.accessPolicy.knownValue != nil,
      seal.aclDigest.knownValue != nil,
      seal.providerBoundary == .known(.local),
      seal.mountIdentity.knownValue != nil,
      access.providerState == .local
    else { throw failure("untrusted-source-namespace") }
  }

  private func hasBoundLocalNamespaceSeals(_ target: BoundMutationTarget) -> Bool {
    let seals = [target.expectedRootSeal] + target.expectedParentSeals
    guard target.expectedTargetAccessPolicy.providerState == .local,
      !target.expectedTargetAccessPolicy.accessPolicyBytes.isEmpty,
      !target.expectedTargetAccessPolicy.mountIdentityBytes.isEmpty,
      let rootMount = target.expectedRootSeal.mountIdentity.knownValue,
      Data(rootMount.utf8) == target.expectedTargetAccessPolicy.mountIdentityBytes
    else { return false }
    return seals.allSatisfy {
      $0.trustedNamespace == .ownerPrivate
        && $0.accessPolicy.knownValue != nil
        && $0.aclDigest.knownValue != nil
        && $0.providerBoundary == .known(.local)
        && $0.mountIdentity == .known(rootMount)
    }
  }

  private func requireOwnerPrivateDirectory(
    _ descriptor: Int32,
    expectedDevice: UInt64
  ) throws {
    let value = try status(descriptor)
    guard Self.kind(value.st_mode) == .directory,
      Self.device(value) == expectedDevice,
      value.st_uid == Darwin.geteuid(),
      (value.st_mode & (S_IWGRP | S_IWOTH)) == 0
    else { throw failure("namespace-not-owner-private") }
  }

  private func requireIdentity(
    _ descriptor: Int32,
    expected: ObjectIdentity,
    code: String
  ) throws {
    try requireIdentity(try status(descriptor), expected: expected, code: code)
  }

  private func requireIdentity(
    _ status: stat,
    expected: ObjectIdentity,
    code: String
  ) throws {
    guard Self.identity(status).device == expected.device,
      Self.identity(status).object == expected.object,
      Self.identity(status).type == expected.type
    else { throw failure(code) }
    if case .known(let generation) = expected.generation {
      guard generation == UInt64(status.st_gen) else { throw failure("\(code)-generation") }
    }
  }

  private func status(_ descriptor: Int32) throws -> stat {
    var value = stat()
    guard Darwin.fstat(descriptor, &value) == 0 else { throw failure("fstat", errno) }
    return value
  }

  private func device(_ descriptor: Int32) throws -> UInt64 {
    Self.device(try status(descriptor))
  }

  private static func device(_ status: stat) -> UInt64 {
    UInt64(UInt32(bitPattern: status.st_dev))
  }

  private static func identity(_ status: stat) -> ObjectIdentity {
    ObjectIdentity(
      device: device(status),
      object: UInt64(status.st_ino),
      generation: .known(UInt64(status.st_gen)),
      type: kind(status.st_mode) ?? .regularFile
    )
  }

  private static func kind(_ mode: mode_t) -> ObjectKind? {
    switch mode & S_IFMT {
    case S_IFDIR: return .directory
    case S_IFREG: return .regularFile
    case S_IFLNK: return .symbolicLink
    default: return nil
    }
  }

  private static func stableFile(_ lhs: stat, _ rhs: stat) -> Bool {
    identity(lhs) == identity(rhs)
      && lhs.st_size == rhs.st_size
      && lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec
      && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
      && lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec
      && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
      && lhs.st_mode == rhs.st_mode
      && lhs.st_uid == rhs.st_uid
      && lhs.st_gid == rhs.st_gid
      && lhs.st_flags == rhs.st_flags
  }

  private static func comparePaths(_ lhs: [Data], _ rhs: [Data]) -> Bool {
    for (left, right) in zip(lhs, rhs) {
      if left == right { continue }
      return left.lexicographicallyPrecedes(right)
    }
    return lhs.count < rhs.count
  }

  private static func append(_ value: UInt64, to data: inout Data) {
    var bigEndian = value.bigEndian
    withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
  }

  private func validateRawPath(_ target: BoundMutationTarget) throws {
    guard target.rawRoot.absoluteBytes.first == UInt8(ascii: "/"),
      !target.rawRoot.absoluteBytes.contains(0),
      !target.targetPath.components.isEmpty,
      target.targetPath.components.allSatisfy({
        !$0.isEmpty && !$0.contains(0) && !$0.contains(UInt8(ascii: "/"))
          && $0 != Data(".".utf8) && $0 != Data("..".utf8)
      })
    else { throw failure("invalid-raw-path") }
  }

  private func openDirectory(at descriptor: Int32, name: Data, code: String) throws -> Int32 {
    try Self.withRawCString(name) { pointer in
      let value = Darwin.openat(
        descriptor,
        pointer,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
      )
      guard value >= 0 else { throw failure(code, errno) }
      return value
    }
  }

  private func renameExclusive(
    fromDirectory: Int32,
    from: Data,
    toDirectory: Int32,
    to: Data,
    code: String
  ) throws {
    let result = try Self.withRawCString(from) { source in
      try Self.withRawCString(to) { destination in
        Darwin.renameatx_np(
          fromDirectory,
          source,
          toDirectory,
          destination,
          UInt32(RENAME_EXCL)
        )
      }
    }
    guard result == 0 else { throw failure(code, errno) }
  }

  private func readAll(_ descriptor: Int32, maximumBytes: Int) throws -> Data {
    var result = Data()
    var buffer = [UInt8](repeating: 0, count: 64 * 1024)
    while true {
      let count = buffer.withUnsafeMutableBytes {
        Darwin.read(descriptor, $0.baseAddress, $0.count)
      }
      if count == 0 { return result }
      if count < 0 {
        if errno == EINTR { continue }
        throw failure("read-file", errno)
      }
      guard result.count <= maximumBytes - count else { throw failure("file-read-budget-exceeded") }
      result.append(contentsOf: buffer.prefix(count))
    }
  }

  private static func runGit(
    arguments: [Data],
    workingDirectoryDescriptor: Int32,
    context: MutationExecutionContext
  ) async -> AdapterOperationOutcome {
    do {
      let executable = Data("/usr/bin/git".utf8)
      let processID = try withRawCString(executable) { executablePath -> pid_t in
        var allocations: [UnsafeMutablePointer<CChar>] = []
        defer {
          for allocation in allocations { allocation.deallocate() }
        }
        for argument in arguments {
          guard !argument.contains(0) else { throw failure("nul-in-git-argv") }
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
        var actions: posix_spawn_file_actions_t?
        var status = posix_spawn_file_actions_init(&actions)
        guard status == 0 else { throw failure("git-spawn-actions-init", status) }
        defer { _ = posix_spawn_file_actions_destroy(&actions) }
        status = "/dev/null".withCString {
          posix_spawn_file_actions_addopen(&actions, STDIN_FILENO, $0, O_RDONLY, 0)
        }
        guard status == 0 else { throw failure("git-spawn-actions-stdin", status) }
        status = posix_spawn_file_actions_addfchdir_np(&actions, workingDirectoryDescriptor)
        guard status == 0 else { throw failure("git-spawn-actions-fchdir", status) }
        var attributes: posix_spawnattr_t?
        status = posix_spawnattr_init(&attributes)
        guard status == 0 else { throw failure("git-spawn-attributes-init", status) }
        defer { _ = posix_spawnattr_destroy(&attributes) }
        status = posix_spawnattr_setpgroup(&attributes, 0)
        guard status == 0 else { throw failure("git-spawn-attributes-pgroup", status) }
        status = posix_spawnattr_setflags(&attributes, Int16(POSIX_SPAWN_SETPGROUP))
        guard status == 0 else { throw failure("git-spawn-attributes-flags", status) }
        var processID = pid_t()
        status = argv.withUnsafeMutableBufferPointer { argvBuffer in
          environment.withUnsafeMutableBufferPointer { environmentBuffer in
            posix_spawn(
              &processID,
              executablePath,
              &actions,
              &attributes,
              argvBuffer.baseAddress!,
              environmentBuffer.baseAddress!
            )
          }
        }
        guard status == 0 else { throw failure("posix-spawn-git", status) }
        return processID
      }
      return await waitForGit(processID, context: context)
    } catch let AdapterError.failure(value) {
      return .failed(value)
    } catch {
      return .failed(ExecutionAdapterFailure(code: String(reflecting: type(of: error))))
    }
  }

  private static func waitForGit(
    _ processID: pid_t,
    context: MutationExecutionContext
  ) async -> AdapterOperationOutcome {
    while true {
      var waitStatus: Int32 = 0
      let result = Darwin.waitpid(processID, &waitStatus, WNOHANG)
      if result == processID { return gitTerminationOutcome(waitStatus) }
      if result == -1, errno != EINTR {
        return .failed(ExecutionAdapterFailure(code: "waitpid-git", errno: errno))
      }
      if Task.isCancelled {
        if let failure = await terminateAndReapGit(processID) { return .failed(failure) }
        return .cancelled
      }
      if context.isExpired {
        if let failure = await terminateAndReapGit(processID) { return .failed(failure) }
        return .timedOut
      }
      try? await Task.sleep(for: .milliseconds(10))
    }
  }

  private static func terminateAndReapGit(
    _ processID: pid_t
  ) async -> ExecutionAdapterFailure? {
    var signalFailure: ExecutionAdapterFailure?
    if Darwin.kill(-processID, SIGTERM) != 0, errno != ESRCH {
      signalFailure = ExecutionAdapterFailure(code: "terminate-git", errno: errno)
    }
    let graceDeadline = DispatchTime.now().uptimeNanoseconds + 200_000_000
    while DispatchTime.now().uptimeNanoseconds < graceDeadline {
      var status: Int32 = 0
      let result = Darwin.waitpid(processID, &status, WNOHANG)
      if result == processID { return signalFailure }
      if result == -1, errno != EINTR {
        return ExecutionAdapterFailure(code: "waitpid-git-cleanup", errno: errno)
      }
      try? await Task.sleep(for: .milliseconds(10))
    }
    if Darwin.kill(-processID, SIGKILL) != 0, errno != ESRCH, signalFailure == nil {
      signalFailure = ExecutionAdapterFailure(code: "kill-git", errno: errno)
    }
    while true {
      var status: Int32 = 0
      let result = Darwin.waitpid(processID, &status, 0)
      if result == processID { return signalFailure }
      if result == -1, errno != EINTR {
        return ExecutionAdapterFailure(code: "waitpid-git-cleanup", errno: errno)
      }
    }
  }

  private static func gitTerminationOutcome(_ waitStatus: Int32) -> AdapterOperationOutcome {
    let signal = waitStatus & 0x7f
    if signal == 0 {
      let exitStatus = (waitStatus >> 8) & 0xff
      return exitStatus == 0
        ? .succeeded(detailCode: "git-command-completed")
        : .failed(ExecutionAdapterFailure(code: "git-exit-status", exitStatus: exitStatus))
    }
    return .failed(
      ExecutionAdapterFailure(code: "git-terminated-by-signal", terminatingSignal: signal))
  }

  private static func failureFromGitOutcome(
    _ outcome: AdapterOperationOutcome,
    defaultCode: String
  ) -> ExecutionAdapterFailure {
    switch outcome {
    case .failed(let failure): return failure
    case .cancelled: return ExecutionAdapterFailure(code: "git-admin-cleanup-cancelled")
    case .timedOut: return ExecutionAdapterFailure(code: "git-admin-cleanup-timed-out")
    case .notStarted(let reason):
      return ExecutionAdapterFailure(code: "git-admin-cleanup-not-started-\(reason.rawValue)")
    case .succeeded: return ExecutionAdapterFailure(code: defaultCode)
    }
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

  private static func close<S: Sequence>(_ descriptors: S) where S.Element == Int32 {
    for descriptor in Array(descriptors).reversed() { _ = Darwin.close(descriptor) }
  }

  private static func withRawCString<Result>(
    _ bytes: Data,
    _ body: (UnsafePointer<CChar>) throws -> Result
  ) throws -> Result {
    guard !bytes.contains(0) else { throw failure("nul-in-path") }
    var storage = bytes.map { CChar(bitPattern: $0) }
    storage.append(0)
    return try storage.withUnsafeBufferPointer { buffer in
      try body(buffer.baseAddress!)
    }
  }

  private static func failure(_ code: String, _ value: Int32? = nil) -> AdapterError {
    .failure(ExecutionAdapterFailure(code: code, errno: value))
  }

  private func failure(_ code: String, _ value: Int32? = nil) -> AdapterError {
    Self.failure(code, value)
  }
}
