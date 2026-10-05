import CryptoKit
import Darwin
import DiskplanPolicy
import Foundation

public struct GitWorktreeRecoveryLocator: Equatable, Sendable {
  public let rawRoot: RawRootPath
  public let sourceParentComponents: [Data]
  public let quarantineDirectoryName: Data
  public let quarantineLeafName: Data
  public let identity: ObjectIdentity
}

public struct GitWorktreeAdministrativeResidual: Equatable, Sendable {
  public let registrationID: PolicyDigest
  public let administrativeDirectoryIdentity: ObjectIdentity
  public let commonDirectoryIdentity: ObjectIdentity
  public let failure: ExecutionAdapterFailure
}

public struct GitWorktreeAttemptDirectoryLocator: Equatable, Sendable {
  public let rawRoot: RawRootPath
  public let sourceParentComponents: [Data]
  public let quarantineDirectoryName: Data
  public let identity: ObjectIdentity
}

public enum GitWorktreeAttemptCleanupDisposition: Equatable, Sendable {
  case retained(
    locator: GitWorktreeAttemptDirectoryLocator,
    failure: ExecutionAdapterFailure
  )
  case bindingUnverified(failure: ExecutionAdapterFailure)

  var failure: ExecutionAdapterFailure {
    switch self {
    case .retained(_, let failure), .bindingUnverified(let failure): return failure
    }
  }
}

struct GitWorktreePostVerificationDirectoryBinding: Equatable, Sendable {
  let identity: ObjectIdentity
  let owner: UInt32
  let group: UInt32
  let mode: UInt32
  let flags: UInt32
  let device: UInt64
  let aclDigest: Data
  let mountIdentity: Data
}

struct GitWorktreePostVerificationNamespaceBinding: Equatable, Sendable {
  let root: GitWorktreePostVerificationDirectoryBinding
  let parents: [GitWorktreePostVerificationDirectoryBinding]
}

public enum GitWorktreeMutationDisposition: Equatable, Sendable {
  case removed
  case localChangesDiscarded
  case restoredAfterVerificationFailure(code: String)
  case quarantineRetained(locator: GitWorktreeRecoveryLocator, failureCode: String)
  case quarantineBindingUnverified(failureCode: String)
  case removedWithAdministrativeResidual(GitWorktreeAdministrativeResidual)
}

/// The Git adapter never delegates root removal to Git or to generic `rm`.
///
/// It binds the source path through held no-follow descriptors, moves the exact object into an
/// owner-private same-filesystem namespace with `RENAME_EXCL`, proves that the held source and
/// destination descriptors name the same object, and only then recursively deletes the verified
/// quarantine snapshot. Exact descriptor-bound registration cleanup never prunes sibling
/// worktrees and never executes repository configuration.
@_spi(DiskplanEngine)
public final class GitWorktreeQuarantineAdapter: ExecutionMutationAdapter, @unchecked Sendable {
  static let quarantineDirectoryPrefix = Data(".diskplan-quarantine-".utf8)
  private static let maximumCoverageEntries = 1_000_000
  private static let maximumCoverageBytes: UInt64 = 1 << 40

  struct Hooks: Sendable {
    var beforeQuarantine: @Sendable () -> Void = {}
    var beforePostQuarantineVerification: @Sendable () -> Void = {}
    var beforeRestore: @Sendable () -> Void = {}
    var beforeRestoreCommit: @Sendable () -> Void = {}
    var afterRestoreCommit: @Sendable () -> Void = {}
    var beforeRecursiveDelete: @Sendable () -> Void = {}
    var beforeRecursiveDeleteCommit: @Sendable () -> Void = {}
    var beforeRecursiveDeleteRootRemoval: @Sendable () -> Void = {}
    var beforeAdministrativeCleanup: @Sendable () -> Void = {}
    var beforeUnusedQuarantineCleanup: @Sendable () -> Void = {}
    var quarantinePreparationFailureCode: @Sendable () -> String? = { nil }
    var afterCoverageFileFirstRead: @Sendable (Int32, [Data]) -> Void = { _, _ in }
    var quarantineNonce: @Sendable () -> Data = {
      Data(UUID().uuidString.lowercased().utf8)
    }
  }

  private actor ResultStore {
    private struct AttemptValue {
      var mutation: GitWorktreeMutationDisposition?
      var cleanup: GitWorktreeAttemptCleanupDisposition?
      var postVerificationBinding: GitWorktreePostVerificationNamespaceBinding?
    }

    private var attemptValues: [UUID: AttemptValue] = [:]
    private var legacyValues: [ActionID: GitWorktreeMutationDisposition] = [:]
    private var legacyPostVerificationBindings:
      [ActionID: GitWorktreePostVerificationNamespaceBinding] = [:]

    func set(_ value: GitWorktreeMutationDisposition, for actionID: ActionID) {
      if let attemptID = GitWorktreeQuarantineAdapter.currentAttemptID {
        var attempt = attemptValues[attemptID] ?? AttemptValue()
        attempt.mutation = value
        attemptValues[attemptID] = attempt
      }
      // Compatibility for existing adapter-level SPI tests only. The production execution path
      // consumes `attemptValues` and never resolves a disposition by ActionID.
      legacyValues[actionID] = value
    }

    func setCleanup(_ value: GitWorktreeAttemptCleanupDisposition) {
      guard let attemptID = GitWorktreeQuarantineAdapter.currentAttemptID else { return }
      var attempt = attemptValues[attemptID] ?? AttemptValue()
      attempt.cleanup = value
      attemptValues[attemptID] = attempt
    }

    func setPostVerificationBinding(
      _ value: GitWorktreePostVerificationNamespaceBinding,
      for actionID: ActionID
    ) {
      if let attemptID = GitWorktreeQuarantineAdapter.currentAttemptID {
        var attempt = attemptValues[attemptID] ?? AttemptValue()
        attempt.postVerificationBinding = value
        attemptValues[attemptID] = attempt
      }
      legacyPostVerificationBindings[actionID] = value
    }

    func value(for actionID: ActionID) -> GitWorktreeMutationDisposition? {
      legacyValues[actionID]
    }

    func postVerificationBinding(
      for actionID: ActionID
    ) -> GitWorktreePostVerificationNamespaceBinding? {
      legacyPostVerificationBindings[actionID]
    }

    func takeValue(for attemptID: UUID) -> (
      mutation: GitWorktreeMutationDisposition?,
      cleanup: GitWorktreeAttemptCleanupDisposition?,
      postVerificationBinding: GitWorktreePostVerificationNamespaceBinding?
    ) {
      let value = attemptValues.removeValue(forKey: attemptID)
      return (value?.mutation, value?.cleanup, value?.postVerificationBinding)
    }
  }

  @TaskLocal private static var currentAttemptID: UUID?

  private struct DescriptorBinding {
    let descriptors: [Int32]
    let rootDescriptor: Int32
    let rootSeal: QuarantineNamespaceSeal
    let parentDescriptors: [Int32]
    let parentNamespaceSeals: [QuarantineNamespaceSeal]
    let parentDescriptor: Int32
    let sourceDescriptor: Int32
    let leaf: Data
    let parentSeal: QuarantineNamespaceSeal
    let sourceSeal: QuarantineNamespaceSeal
  }

  private struct GitAdministrativeBinding {
    let descriptors: [Int32]
    let administrativeDirectoryDescriptor: Int32
    let worktreesDirectoryDescriptor: Int32
    let commonDirectoryDescriptor: Int32
    let administrativeLeaf: Data
    let coverage: CoverageToken
    let registration: GitWorktreeRegistrationEvidence
    let administrativeSeal: QuarantineNamespaceSeal
    let worktreesSeal: QuarantineNamespaceSeal
    let commonSeal: QuarantineNamespaceSeal
  }

  private struct QuarantineBinding {
    let descriptor: Int32
    let leaf: Data
    let locator: GitWorktreeRecoveryLocator
    let attemptLocator: GitWorktreeAttemptDirectoryLocator
    let seal: QuarantineNamespaceSeal
  }

  private struct QuarantineNamespaceSeal: Equatable {
    let identity: ObjectIdentity
    let owner: UInt32
    let group: UInt32
    let mode: UInt32
    let flags: UInt32
    let device: UInt64
    let aclDigest: Data
    let mountIdentity: Data
  }

  private struct NodeRecord: Equatable {
    let path: [Data]
    let identity: ObjectIdentity
    let mode: UInt32
    let owner: UInt32
    let group: UInt32
    let flags: UInt32
    let aclDigest: Data
    let size: UInt64
    let payloadDigest: Data
  }

  private struct NodePath: Hashable {
    let components: [Data]
  }

  private struct NodeIdentityKey: Hashable {
    let device: UInt64
    let object: UInt64
    let generation: UInt64?
    let type: String

    init(_ identity: ObjectIdentity) {
      device = identity.device
      object = identity.object
      if case .known(let value) = identity.generation {
        generation = value
      } else {
        generation = nil
      }
      type = identity.type.rawValue
    }
  }

  private struct FileMeasurement {
    let payloadDigest: Data
    let aclDigest: Data
  }

  private struct SymbolicLinkMeasurement {
    let target: Data
    let aclDigest: Data
  }

  private struct ACLSnapshot {
    let digest: Data
    let hasEntries: Bool
  }

  private struct CoverageToken {
    let records: [NodeRecord]
  }

  private enum RecoverySafety: Equatable {
    case automaticRestoreAllowed
    case manualRecoveryRequired
  }

  private struct AdapterError: Error {
    let failure: ExecutionAdapterFailure
    let recoverySafety: RecoverySafety
  }

  private struct QuarantinePreparationError: Error {
    let failure: ExecutionAdapterFailure
    let cleanup: GitWorktreeAttemptCleanupDisposition?
  }

  private let hooks: Hooks
  private let results = ResultStore()

  public init() {
    hooks = Hooks()
  }

  init(hooks: Hooks) {
    self.hooks = hooks
  }

  public func disposition(for actionID: ActionID) async -> GitWorktreeMutationDisposition? {
    await results.value(for: actionID)
  }

  public func apply(
    _ operation: ExecutionAdapterOperation,
    context: MutationExecutionContext
  ) async -> AdapterOperationOutcome {
    await applyResult(operation, context: context).outcome
  }

  public func applyResult(
    _ operation: ExecutionAdapterOperation,
    context: MutationExecutionContext
  ) async -> AdapterOperationResult {
    let attemptID = UUID()
    let outcome = await Self.$currentAttemptID.withValue(attemptID) {
      await applyAttempt(operation, context: context)
    }
    let disposition = await results.takeValue(for: attemptID)
    return AdapterOperationResult(
      outcome: outcome,
      mutationDisposition: disposition.mutation.map(ExecutionMutationDisposition.gitWorktree),
      cleanupDisposition: disposition.cleanup.map(
        ExecutionCleanupDisposition.gitWorktreeAttemptDirectory),
      gitWorktreePostVerificationBinding: disposition.postVerificationBinding
    )
  }

  private func applyAttempt(
    _ operation: ExecutionAdapterOperation,
    context: MutationExecutionContext
  ) async -> AdapterOperationOutcome {
    switch operation {
    case .gitWorktreeRemove(let target, let contract):
      guard !contract.requiresDiscardLocalChanges else {
        return .failed(ExecutionAdapterFailure(code: "git-worktree-dirty-report-only"))
      }
      return await remove(target: target, contract: contract, context: context)
    case .gitWorktreeDiscardLocalChanges:
      return .failed(ExecutionAdapterFailure(code: "git-worktree-dirty-report-only"))
    default:
      return .failed(ExecutionAdapterFailure(code: "unsupported-action-adapter"))
    }
  }

  public func postverify(_ operation: ExecutionAdapterOperation) async
    -> PostVerificationOutcome
  {
    let disposition: GitWorktreeMutationDisposition?
    let binding: GitWorktreePostVerificationNamespaceBinding?
    if case .gitWorktreeRemove(let target, _) = operation {
      disposition = await results.value(for: target.actionID)
      binding = await results.postVerificationBinding(for: target.actionID)
    } else {
      disposition = nil
      binding = nil
    }
    return postverify(operation, disposition: disposition, binding: binding)
  }

  public func postverify(
    _ operation: ExecutionAdapterOperation,
    result: AdapterOperationResult
  ) async -> PostVerificationOutcome {
    let disposition: GitWorktreeMutationDisposition?
    if case .gitWorktree(let value)? = result.mutationDisposition {
      disposition = value
    } else {
      disposition = nil
    }
    return postverify(
      operation,
      disposition: disposition,
      binding: result.gitWorktreePostVerificationBinding
    )
  }

  private func postverify(
    _ operation: ExecutionAdapterOperation,
    disposition: GitWorktreeMutationDisposition?,
    binding: GitWorktreePostVerificationNamespaceBinding?
  ) -> PostVerificationOutcome {
    switch operation {
    case .gitWorktreeRemove(let target, _):
      if let disposition {
        switch disposition {
        case .removed:
          return sourceIsAbsent(target, binding: binding)
        case .removedWithAdministrativeResidual(let residual):
          let absence = sourceIsAbsent(target, binding: binding)
          guard absence == .satisfied else { return absence }
          return .expectedResidual(residual.failure)
        case .quarantineRetained:
          return .notSatisfied(code: "verified-quarantine-retained")
        case .quarantineBindingUnverified(let failureCode):
          return .failed(
            ObservationFailure(
              code: "quarantine-binding-unverified-\(failureCode)",
              collector: "git-worktree-postverify"
            )
          )
        case .restoredAfterVerificationFailure:
          return .notSatisfied(code: "source-restored-after-verification-failure")
        case .localChangesDiscarded:
          return .notSatisfied(code: "operation-result-type-mismatch")
        }
      }
      return .unknown(.notRequested)
    case .gitWorktreeDiscardLocalChanges:
      return .notSatisfied(code: "git-worktree-dirty-report-only")
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

      let preQuarantineToken = try verifyCoverage(
        rootDescriptor: source.sourceDescriptor,
        expectedIdentity: target.expectedIdentity,
        expectedContent: contract.executionBaseline.contentProtection,
        expectedAccess: target.expectedTargetAccessPolicy
      )
      if Task.isCancelled { return .cancelled }
      if context.isExpired { return .timedOut }

      let quarantine = try openQuarantine(
        target: target,
        source: source
      )
      defer { _ = Darwin.close(quarantine.descriptor) }
      do {
        hooks.beforeQuarantine()
        try requireGitCommitPointStillCurrent(administrative)
        try requireQuarantineSeal(quarantine)
        try requireDirectorySeal(
          source.parentDescriptor,
          expected: source.parentSeal,
          code: "source-parent-seal-mismatch-before-quarantine"
        )
        try requireDirectorySeal(
          source.sourceDescriptor,
          expected: source.sourceSeal,
          code: "source-seal-mismatch-before-quarantine"
        )
        try requireSourceSlotIdentity(
          parentDescriptor: source.parentDescriptor,
          leaf: source.leaf,
          expected: target.expectedIdentity
        )
        if Task.isCancelled {
          await recordUnusedQuarantineCleanup(
            target: target,
            source: source,
            quarantine: quarantine
          )
          return .cancelled
        }
        if context.isExpired {
          await recordUnusedQuarantineCleanup(
            target: target,
            source: source,
            quarantine: quarantine
          )
          return .timedOut
        }

        try renameExclusive(
          fromDirectory: source.parentDescriptor,
          from: source.leaf,
          toDirectory: quarantine.descriptor,
          to: quarantine.leaf,
          code: "quarantine-rename"
        )
      } catch let error as AdapterError {
        await recordUnusedQuarantineCleanup(
          target: target,
          source: source,
          quarantine: quarantine
        )
        return .failed(error.failure)
      } catch {
        await recordUnusedQuarantineCleanup(
          target: target,
          source: source,
          quarantine: quarantine
        )
        return .failed(ExecutionAdapterFailure(code: String(reflecting: type(of: error))))
      }

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
        try requireQuarantineSeal(quarantine)
        try requireSameIdentity(
          sourceDescriptor: source.sourceDescriptor,
          destinationDescriptor: openedDestination,
          expected: target.expectedIdentity
        )

        hooks.beforePostQuarantineVerification()
        try requireDirectorySeal(
          openedDestination,
          expected: source.sourceSeal,
          code: "source-seal-mismatch-after-quarantine"
        )
        token = try verifyCoverage(
          rootDescriptor: openedDestination,
          expectedIdentity: target.expectedIdentity,
          expectedContent: contract.executionBaseline.contentProtection,
          expectedAccess: target.expectedTargetAccessPolicy
        )
        try requireMatchingSnapshot(
          preQuarantineToken,
          actual: token,
          mismatchCode: "post-quarantine-protected-properties-mismatch"
        )

        if Task.isCancelled {
          return await restoreAfterInterruption(
            target: target,
            source: source,
            quarantine: quarantine,
            expectedSnapshot: preQuarantineToken,
            outcome: .cancelled,
            failureCode: "cancelled-after-quarantine"
          )
        }
        if context.isExpired {
          return await restoreAfterInterruption(
            target: target,
            source: source,
            quarantine: quarantine,
            expectedSnapshot: preQuarantineToken,
            outcome: .timedOut,
            failureCode: "deadline-after-quarantine"
          )
        }
      } catch let verificationError as AdapterError {
        return await restoreAfterVerificationFailure(
          target: target,
          source: source,
          quarantine: quarantine,
          protectedAccessBaseline: preQuarantineToken,
          error: verificationError
        )
      }
      guard let destinationDescriptor else {
        return .failed(ExecutionAdapterFailure(code: "missing-quarantine-destination-binding"))
      }

      hooks.beforeRecursiveDelete()
      do {
        try requireQuarantineSeal(quarantine)
        try requireDirectorySeal(
          destinationDescriptor,
          expected: source.sourceSeal,
          code: "source-seal-mismatch-before-delete"
        )
        try requireSnapshotStillCurrent(token, rootDescriptor: destinationDescriptor)
      } catch let verificationError as AdapterError {
        return await restoreAfterVerificationFailure(
          target: target,
          source: source,
          quarantine: quarantine,
          protectedAccessBaseline: token,
          error: verificationError
        )
      }
      hooks.beforeRecursiveDeleteCommit()
      do {
        try requireGitCommitPointStillCurrent(administrative)
        try requireQuarantineSeal(quarantine)
        try requireDirectorySeal(
          destinationDescriptor,
          expected: source.sourceSeal,
          code: "source-seal-mismatch-at-delete-commit"
        )
        try requireSnapshotStillCurrent(token, rootDescriptor: destinationDescriptor)
        try recursivelyDeleteVerifiedTree(
          token,
          rootDescriptor: destinationDescriptor,
          quarantineDescriptor: quarantine.descriptor,
          quarantineLeaf: quarantine.leaf,
          expectedParentSeal: quarantine.seal
        )
      } catch let deletionError as AdapterError {
        let recovery = verifiedRecoveryDisposition(
          target: target,
          source: source,
          quarantine: quarantine,
          failureCode: deletionError.failure.code
        )
        await results.set(recovery, for: target.actionID)
        let code =
          switch recovery {
          case .quarantineRetained:
            "verified-quarantine-deletion-residual"
          case .quarantineBindingUnverified:
            "verified-quarantine-deletion-binding-unverified"
          default:
            "invalid-quarantine-recovery-state"
          }
        return .failed(
          ExecutionAdapterFailure(
            code: code,
            errno: deletionError.failure.errno
          ))
      }

      await results.setPostVerificationBinding(
        postVerificationBinding(source),
        for: target.actionID
      )

      await recordUnusedQuarantineCleanup(
        target: target,
        source: source,
        quarantine: quarantine
      )

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

      do {
        try requireDirectorySeal(
          administrative.worktreesDirectoryDescriptor,
          expected: administrative.worktreesSeal,
          code: "git-worktrees-parent-seal-mismatch-before-cleanup"
        )
        try requireDirectorySeal(
          administrative.administrativeDirectoryDescriptor,
          expected: administrative.administrativeSeal,
          code: "git-administrative-seal-mismatch-before-cleanup"
        )
        try requireIdentity(
          administrative.administrativeDirectoryDescriptor,
          expected: administrative.registration.administrativeDirectoryIdentity,
          code: "git-administrative-identity-mismatch-before-cleanup"
        )
        try requireSnapshotStillCurrent(
          administrative.coverage,
          rootDescriptor: administrative.administrativeDirectoryDescriptor
        )
        try recursivelyDeleteVerifiedTree(
          administrative.coverage,
          rootDescriptor: administrative.administrativeDirectoryDescriptor,
          quarantineDescriptor: administrative.worktreesDirectoryDescriptor,
          quarantineLeaf: administrative.administrativeLeaf,
          expectedParentSeal: administrative.worktreesSeal
        )
      } catch let error as AdapterError {
        return await recordAdministrativeResidual(
          target: target,
          administrative: administrative,
          failure: error.failure
        )
      }

      await results.set(.removed, for: target.actionID)
      return .succeeded(detailCode: "git-worktree-quarantine-removed")
    } catch let error as QuarantinePreparationError {
      if let cleanup = error.cleanup { await results.setCleanup(cleanup) }
      return .failed(error.failure)
    } catch let error as AdapterError {
      return .failed(error.failure)
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

  private func postVerificationBinding(
    _ source: DescriptorBinding
  ) -> GitWorktreePostVerificationNamespaceBinding {
    GitWorktreePostVerificationNamespaceBinding(
      root: postVerificationDirectoryBinding(source.rootSeal),
      parents: source.parentNamespaceSeals.map(postVerificationDirectoryBinding)
    )
  }

  private func postVerificationDirectoryBinding(
    _ seal: QuarantineNamespaceSeal
  ) -> GitWorktreePostVerificationDirectoryBinding {
    GitWorktreePostVerificationDirectoryBinding(
      identity: seal.identity,
      owner: seal.owner,
      group: seal.group,
      mode: seal.mode,
      flags: seal.flags,
      device: seal.device,
      aclDigest: seal.aclDigest,
      mountIdentity: seal.mountIdentity
    )
  }

  private func restoreAfterVerificationFailure(
    target: BoundMutationTarget,
    source: DescriptorBinding,
    quarantine: QuarantineBinding,
    protectedAccessBaseline: CoverageToken,
    error: AdapterError
  ) async -> AdapterOperationOutcome {
    let failure = error.failure
    if error.recoverySafety == .manualRecoveryRequired {
      let recovery = verifiedRecoveryDisposition(
        target: target,
        source: source,
        quarantine: quarantine,
        failureCode: failure.code
      )
      await results.set(recovery, for: target.actionID)
      let code =
        switch recovery {
        case .quarantineRetained:
          "quarantine-verification-failed-retained"
        case .quarantineBindingUnverified:
          "quarantine-verification-failed-unverified"
        default:
          "invalid-quarantine-recovery-state"
        }
      return .failed(ExecutionAdapterFailure(code: code))
    }
    do {
      try requireRecoveryNamespaceBinding(
        target: target,
        source: source,
        quarantine: quarantine
      )
      let baselinePayload = try openQuarantinePayload(
        target: target,
        source: source,
        quarantine: quarantine
      )
      let restoreBaseline: CoverageToken
      do {
        restoreBaseline = try stableSnapshot(
          rootDescriptor: baselinePayload,
          mismatchCode: "restore-baseline-raced"
        )
      } catch {
        _ = Darwin.close(baselinePayload)
        throw error
      }
      _ = Darwin.close(baselinePayload)
      try requireNoAccessPolicyDrift(
        protectedAccessBaseline,
        actual: restoreBaseline
      )

      hooks.beforeRestore()
      try requireRecoveryNamespaceBinding(
        target: target,
        source: source,
        quarantine: quarantine
      )
      let payload = try openQuarantinePayloadForRestore(
        target: target,
        source: source,
        quarantine: quarantine,
        expectedSnapshot: restoreBaseline
      )
      defer { _ = Darwin.close(payload) }
      hooks.beforeRestoreCommit()
      try requireRestoreCommitBinding(
        target: target,
        source: source,
        quarantine: quarantine,
        payloadDescriptor: payload,
        expectedSnapshot: restoreBaseline
      )
      try requireSourceSlotMissing(parentDescriptor: source.parentDescriptor, leaf: source.leaf)
      try renameExclusive(
        fromDirectory: quarantine.descriptor,
        from: quarantine.leaf,
        toDirectory: source.parentDescriptor,
        to: source.leaf,
        code: "restore-source-slot"
      )
      hooks.afterRestoreCommit()
      try requireRestoredPayloadBinding(
        target: target,
        source: source,
        quarantine: quarantine,
        payloadDescriptor: payload,
        expectedSnapshot: restoreBaseline
      )
      await recordUnusedQuarantineCleanup(
        target: target,
        source: source,
        quarantine: quarantine
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
      let recoveryFailure = (error as? AdapterError)?.failure ?? failure
      let recovery = verifiedRecoveryDisposition(
        target: target,
        source: source,
        quarantine: quarantine,
        failureCode: recoveryFailure.code
      )
      await results.set(recovery, for: target.actionID)
      let code =
        switch recovery {
        case .quarantineRetained:
          "quarantine-verification-failed-retained"
        case .quarantineBindingUnverified:
          "quarantine-verification-failed-unverified"
        default:
          "invalid-quarantine-recovery-state"
        }
      return .failed(ExecutionAdapterFailure(code: code, errno: recoveryFailure.errno))
    }
  }

  private func restoreAfterInterruption(
    target: BoundMutationTarget,
    source: DescriptorBinding,
    quarantine: QuarantineBinding,
    expectedSnapshot: CoverageToken,
    outcome: AdapterOperationOutcome,
    failureCode: String
  ) async -> AdapterOperationOutcome {
    hooks.beforeRestore()
    do {
      try requireRecoveryNamespaceBinding(
        target: target,
        source: source,
        quarantine: quarantine
      )
      let payload = try openQuarantinePayloadForRestore(
        target: target,
        source: source,
        quarantine: quarantine,
        expectedSnapshot: expectedSnapshot
      )
      defer { _ = Darwin.close(payload) }
      hooks.beforeRestoreCommit()
      try requireRestoreCommitBinding(
        target: target,
        source: source,
        quarantine: quarantine,
        payloadDescriptor: payload,
        expectedSnapshot: expectedSnapshot
      )
      try requireSourceSlotMissing(parentDescriptor: source.parentDescriptor, leaf: source.leaf)
      try renameExclusive(
        fromDirectory: quarantine.descriptor,
        from: quarantine.leaf,
        toDirectory: source.parentDescriptor,
        to: source.leaf,
        code: "restore-source-slot"
      )
      hooks.afterRestoreCommit()
      try requireRestoredPayloadBinding(
        target: target,
        source: source,
        quarantine: quarantine,
        payloadDescriptor: payload,
        expectedSnapshot: expectedSnapshot
      )
      await recordUnusedQuarantineCleanup(
        target: target,
        source: source,
        quarantine: quarantine
      )
      await results.set(
        .restoredAfterVerificationFailure(code: failureCode),
        for: target.actionID
      )
      return outcome
    } catch {
      let recoveryFailure =
        (error as? AdapterError)?.failure
        ?? ExecutionAdapterFailure(code: failureCode)
      let recovery = verifiedRecoveryDisposition(
        target: target,
        source: source,
        quarantine: quarantine,
        failureCode: recoveryFailure.code
      )
      await results.set(recovery, for: target.actionID)
      let code =
        switch recovery {
        case .quarantineRetained:
          "interrupted-quarantine-retained"
        case .quarantineBindingUnverified:
          "interrupted-quarantine-binding-unverified"
        default:
          "invalid-quarantine-recovery-state"
        }
      return .failed(ExecutionAdapterFailure(code: code, errno: recoveryFailure.errno))
    }
  }

  private func requireQuarantinePayloadIdentity(
    target: BoundMutationTarget,
    source: DescriptorBinding,
    quarantine: QuarantineBinding
  ) throws {
    try requireIdentity(
      try status(source.sourceDescriptor),
      expected: target.expectedIdentity,
      code: "held-source-identity-mismatch-before-recovery-publication"
    )
    try requireSourceSlotIdentity(
      parentDescriptor: quarantine.descriptor,
      leaf: quarantine.leaf,
      expected: target.expectedIdentity
    )
  }

  private func openQuarantinePayloadForRestore(
    target: BoundMutationTarget,
    source: DescriptorBinding,
    quarantine: QuarantineBinding,
    expectedSnapshot: CoverageToken
  ) throws -> Int32 {
    let payload = try openQuarantinePayload(
      target: target,
      source: source,
      quarantine: quarantine
    )
    do {
      let current = try stableSnapshot(
        rootDescriptor: payload,
        mismatchCode: "restore-coverage-raced"
      )
      try requireMatchingSnapshot(
        expectedSnapshot,
        actual: current,
        mismatchCode: "restore-protected-properties-mismatch"
      )
      return payload
    } catch {
      _ = Darwin.close(payload)
      throw error
    }
  }

  private func openQuarantinePayload(
    target: BoundMutationTarget,
    source: DescriptorBinding,
    quarantine: QuarantineBinding
  ) throws -> Int32 {
    let payload = try openDirectory(
      at: quarantine.descriptor,
      name: quarantine.leaf,
      code: "open-quarantine-payload-before-restore"
    )
    do {
      try requireSameIdentity(
        sourceDescriptor: source.sourceDescriptor,
        destinationDescriptor: payload,
        expected: target.expectedIdentity
      )
      return payload
    } catch {
      _ = Darwin.close(payload)
      throw error
    }
  }

  private func stableSnapshot(
    rootDescriptor: Int32,
    mismatchCode: String
  ) throws -> CoverageToken {
    let first = CoverageToken(records: try collectSnapshot(rootDescriptor: rootDescriptor))
    let second = CoverageToken(records: try collectSnapshot(rootDescriptor: rootDescriptor))
    try requireMatchingSnapshot(first, actual: second, mismatchCode: mismatchCode)
    return second
  }

  private func requireNoAccessPolicyDrift(
    _ expected: CoverageToken,
    actual: CoverageToken
  ) throws {
    var expectedByPath: [NodePath: NodeRecord] = [:]
    var expectedByIdentity: [NodeIdentityKey: [NodeRecord]] = [:]
    for record in expected.records {
      guard
        expectedByPath.updateValue(
          record,
          forKey: NodePath(components: record.path)
        ) == nil
      else { throw failure("invalid-coverage-token") }
      expectedByIdentity[NodeIdentityKey(record.identity), default: []].append(record)
    }

    for currentRecord in actual.records {
      let pathMatch = expectedByPath[NodePath(components: currentRecord.path)]
      let identityMatches = expectedByIdentity[NodeIdentityKey(currentRecord.identity)] ?? []
      guard
        let expectedRecord = pathMatch ?? (identityMatches.count == 1 ? identityMatches[0] : nil)
      else { continue }
      guard expectedRecord.mode == currentRecord.mode,
        expectedRecord.owner == currentRecord.owner,
        expectedRecord.group == currentRecord.group,
        expectedRecord.flags == currentRecord.flags,
        expectedRecord.aclDigest == currentRecord.aclDigest
      else { throw accessPolicyFailure("recovery-access-policy-mismatch") }
    }
  }

  private func requireRestoreCommitBinding(
    target: BoundMutationTarget,
    source: DescriptorBinding,
    quarantine: QuarantineBinding,
    payloadDescriptor: Int32,
    expectedSnapshot: CoverageToken
  ) throws {
    try requireRecoveryNamespaceBinding(
      target: target,
      source: source,
      quarantine: quarantine
    )
    try requireDirectorySeal(
      payloadDescriptor,
      expected: source.sourceSeal,
      code: "restore-payload-seal-mismatch"
    )
    try requireSameIdentity(
      sourceDescriptor: source.sourceDescriptor,
      destinationDescriptor: payloadDescriptor,
      expected: target.expectedIdentity
    )
    try requireSnapshotStillCurrent(
      expectedSnapshot,
      rootDescriptor: payloadDescriptor,
      mismatchCode: "restore-protected-properties-mismatch-at-commit"
    )
    try requireSourceSlotIdentity(
      parentDescriptor: quarantine.descriptor,
      leaf: quarantine.leaf,
      expected: target.expectedIdentity
    )
  }

  private func requireRestoredPayloadBinding(
    target: BoundMutationTarget,
    source: DescriptorBinding,
    quarantine: QuarantineBinding,
    payloadDescriptor: Int32,
    expectedSnapshot: CoverageToken
  ) throws {
    try requireSourceSlotMissing(
      parentDescriptor: quarantine.descriptor,
      leaf: quarantine.leaf
    )
    let restored = try openDirectory(
      at: source.parentDescriptor,
      name: source.leaf,
      code: "open-restored-source"
    )
    defer { _ = Darwin.close(restored) }
    try requireSameIdentity(
      sourceDescriptor: payloadDescriptor,
      destinationDescriptor: restored,
      expected: target.expectedIdentity
    )
    try requireDirectorySeal(
      restored,
      expected: source.sourceSeal,
      code: "restored-source-seal-mismatch"
    )
    try requireSnapshotStillCurrent(
      expectedSnapshot,
      rootDescriptor: restored,
      mismatchCode: "restored-protected-properties-mismatch"
    )
  }

  private func requireRecoveryNamespaceBinding(
    target: BoundMutationTarget,
    source: DescriptorBinding,
    quarantine: QuarantineBinding
  ) throws {
    let expectedParentComponents = Array(target.targetPath.components.dropLast())
    guard quarantine.locator.rawRoot == target.rawRoot,
      quarantine.locator.sourceParentComponents == expectedParentComponents,
      expectedParentComponents.count == source.parentDescriptors.count,
      source.parentDescriptors.count == source.parentNamespaceSeals.count
    else { throw failure("recovery-namespace-binding-invalid") }

    var reboundDescriptors: [Int32] = []
    defer { Self.close(reboundDescriptors) }
    let root = try Self.withRawCString(target.rawRoot.absoluteBytes) { path -> Int32 in
      let descriptor = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      guard descriptor >= 0 else { throw failure("reopen-recovery-root", errno) }
      return descriptor
    }
    reboundDescriptors.append(root)
    try requireSameIdentity(
      sourceDescriptor: source.rootDescriptor,
      destinationDescriptor: root,
      expected: target.expectedRootIdentity
    )
    try requireDirectorySeal(
      root,
      expected: source.rootSeal,
      code: "recovery-root-seal-mismatch"
    )

    var parent = root
    for index in expectedParentComponents.indices {
      let descriptor = try openDirectory(
        at: parent,
        name: expectedParentComponents[index],
        code: "reopen-recovery-parent"
      )
      reboundDescriptors.append(descriptor)
      try requireSameIdentity(
        sourceDescriptor: source.parentDescriptors[index],
        destinationDescriptor: descriptor,
        expected: target.expectedParentIdentities[index]
      )
      try requireDirectorySeal(
        descriptor,
        expected: source.parentNamespaceSeals[index],
        code: "recovery-parent-seal-mismatch"
      )
      parent = descriptor
    }

    let expectedParentIdentity =
      target.expectedParentIdentities.last ?? target.expectedRootIdentity
    try requireSameIdentity(
      sourceDescriptor: source.parentDescriptor,
      destinationDescriptor: parent,
      expected: expectedParentIdentity
    )
    try requireDirectorySeal(
      parent,
      expected: source.parentSeal,
      code: "source-parent-seal-mismatch-before-restore"
    )

    let reboundQuarantine = try openDirectory(
      at: parent,
      name: quarantine.locator.quarantineDirectoryName,
      code: "reopen-quarantine-directory"
    )
    reboundDescriptors.append(reboundQuarantine)
    try requireSameIdentity(
      sourceDescriptor: quarantine.descriptor,
      destinationDescriptor: reboundQuarantine,
      expected: quarantine.seal.identity
    )
    try requireDirectorySeal(
      reboundQuarantine,
      expected: quarantine.seal,
      code: "rebound-quarantine-seal-mismatch"
    )
  }

  private func verifiedRecoveryDisposition(
    target: BoundMutationTarget,
    source: DescriptorBinding,
    quarantine: QuarantineBinding,
    failureCode: String
  ) -> GitWorktreeMutationDisposition {
    do {
      try requireRecoveryNamespaceBinding(
        target: target,
        source: source,
        quarantine: quarantine
      )
      try requireQuarantinePayloadIdentity(
        target: target,
        source: source,
        quarantine: quarantine
      )
      return .quarantineRetained(
        locator: quarantine.locator,
        failureCode: failureCode
      )
    } catch {
      return .quarantineBindingUnverified(failureCode: failureCode)
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
      !contract.requiresDiscardLocalChanges,
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
      let rootSeal = try directorySeal(root)

      var parent = root
      var parentNamespaceSeals: [QuarantineNamespaceSeal] = []
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
        parentNamespaceSeals.append(try directorySeal(descriptor))
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
      let parentSeal = try directorySeal(parent)
      let sourceSeal = try directorySeal(source)
      return DescriptorBinding(
        descriptors: descriptors,
        rootDescriptor: root,
        rootSeal: rootSeal,
        parentDescriptors: Array(descriptors.dropFirst().dropLast()),
        parentNamespaceSeals: parentNamespaceSeals,
        parentDescriptor: parent,
        sourceDescriptor: source,
        leaf: leaf,
        parentSeal: parentSeal,
        sourceSeal: sourceSeal
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
    guard
      let administrativeLeaf = [UInt8](adminPath).split(
        separator: UInt8(ascii: "/"), omittingEmptySubsequences: true
      ).last.map({ Data($0) }),
      !administrativeLeaf.isEmpty,
      administrativeLeaf != Data(".".utf8),
      administrativeLeaf != Data("..".utf8)
    else { throw failure("git-administrative-leaf-invalid") }

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
      let administrativeSeal = try trustedOwnerPrivateSeal(admin)

      let worktrees = try openDirectory(at: admin, name: Data("..".utf8), code: "open-worktrees")
      descriptors.append(worktrees)
      try requireOwnerPrivateDirectory(
        worktrees,
        expectedDevice: registration.administrativeDirectoryIdentity.device
      )
      let worktreesSeal = try trustedOwnerPrivateSeal(worktrees)
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
      let commonSeal = try trustedOwnerPrivateSeal(common)
      let coverage = CoverageToken(records: try collectSnapshot(rootDescriptor: admin))
      guard try administrativeDigest(coverage.records) == registration.metadataDigest else {
        throw failure("git-administrative-metadata-mismatch")
      }
      guard
        try headResolutionDigest(
          administrativeDescriptor: admin,
          commonDescriptor: common
        ) == registration.headResolutionDigest
      else { throw failure("git-head-resolution-mismatch") }
      return GitAdministrativeBinding(
        descriptors: descriptors,
        administrativeDirectoryDescriptor: admin,
        worktreesDirectoryDescriptor: worktrees,
        commonDirectoryDescriptor: common,
        administrativeLeaf: administrativeLeaf,
        coverage: coverage,
        registration: registration,
        administrativeSeal: administrativeSeal,
        worktreesSeal: worktreesSeal,
        commonSeal: commonSeal
      )
    } catch {
      Self.close(descriptors)
      throw error
    }
  }

  private func requireGitCommitPointStillCurrent(
    _ administrative: GitAdministrativeBinding
  ) throws {
    try requireDirectorySeal(
      administrative.administrativeDirectoryDescriptor,
      expected: administrative.administrativeSeal,
      code: "git-administrative-seal-mismatch-at-mutation-commit"
    )
    try requireDirectorySeal(
      administrative.worktreesDirectoryDescriptor,
      expected: administrative.worktreesSeal,
      code: "git-worktrees-seal-mismatch-at-mutation-commit"
    )
    try requireDirectorySeal(
      administrative.commonDirectoryDescriptor,
      expected: administrative.commonSeal,
      code: "git-common-seal-mismatch-at-mutation-commit"
    )
    try requireSnapshotStillCurrent(
      administrative.coverage,
      rootDescriptor: administrative.administrativeDirectoryDescriptor
    )
    guard
      try headResolutionDigest(
        administrativeDescriptor: administrative.administrativeDirectoryDescriptor,
        commonDescriptor: administrative.commonDirectoryDescriptor
      ) == administrative.registration.headResolutionDigest
    else { throw failure("git-head-resolution-mismatch-at-mutation-commit") }
  }

  private func openQuarantine(
    target: BoundMutationTarget,
    source: DescriptorBinding
  ) throws -> QuarantineBinding {
    var name = Self.quarantineDirectoryPrefix
    name.append(Data(target.actionID.hex.utf8))
    let nonce = hooks.quarantineNonce()
    guard !nonce.isEmpty,
      nonce.count <= 128,
      !nonce.contains(0),
      !nonce.contains(UInt8(ascii: "/")),
      nonce != Data(".".utf8),
      nonce != Data("..".utf8)
    else { throw failure("invalid-quarantine-nonce") }
    name.append(UInt8(ascii: "-"))
    name.append(nonce)
    let mkdirResult = try Self.withRawCString(name) {
      Darwin.mkdirat(source.parentDescriptor, $0, 0o700)
    }
    guard mkdirResult == 0 else {
      throw failure(
        errno == EEXIST
          ? "quarantine-execution-directory-exists"
          : "create-quarantine-directory",
        errno
      )
    }

    let createdIdentity: ObjectIdentity
    do {
      createdIdentity = try sourceSlotIdentity(
        parentDescriptor: source.parentDescriptor,
        leaf: name,
        code: "bind-created-quarantine-directory"
      )
      guard createdIdentity.type == .directory else {
        throw failure("created-quarantine-slot-not-directory")
      }
    } catch {
      let primary =
        (error as? AdapterError)?.failure
        ?? ExecutionAdapterFailure(code: String(reflecting: type(of: error)))
      throw QuarantinePreparationError(
        failure: primary,
        cleanup: .bindingUnverified(
          failure: ExecutionAdapterFailure(
            code: "quarantine-preparation-cleanup-binding-unverified"
          ))
      )
    }

    var descriptor: Int32?
    var binding: QuarantineBinding?
    do {
      let opened = try openDirectory(
        at: source.parentDescriptor,
        name: name,
        code: "open-quarantine-directory"
      )
      descriptor = opened
      let seal = try directorySeal(opened)
      let leaf = Data("payload".utf8)
      let locator = GitWorktreeRecoveryLocator(
        rawRoot: target.rawRoot,
        sourceParentComponents: Array(target.targetPath.components.dropLast()),
        quarantineDirectoryName: name,
        quarantineLeafName: leaf,
        identity: target.expectedIdentity
      )
      let attemptLocator = GitWorktreeAttemptDirectoryLocator(
        rawRoot: target.rawRoot,
        sourceParentComponents: Array(target.targetPath.components.dropLast()),
        quarantineDirectoryName: name,
        identity: seal.identity
      )
      let prepared = QuarantineBinding(
        descriptor: opened,
        leaf: leaf,
        locator: locator,
        attemptLocator: attemptLocator,
        seal: seal
      )
      binding = prepared
      if let code = hooks.quarantinePreparationFailureCode() {
        throw failure(code)
      }
      guard seal.identity.type == .directory,
        seal.device == target.expectedIdentity.device
      else { throw failure("quarantine-identity-or-mount-mismatch") }
      guard seal.owner == Darwin.geteuid(),
        seal.mode == 0o700,
        seal.flags == 0,
        !(try aclSnapshot(opened).hasEntries)
      else { throw accessPolicyFailure("quarantine-access-policy-mismatch") }
      return prepared
    } catch {
      let primary =
        (error as? AdapterError)?.failure
        ?? ExecutionAdapterFailure(code: String(reflecting: type(of: error)))
      var cleanup: GitWorktreeAttemptCleanupDisposition?
      if let binding {
        hooks.beforeUnusedQuarantineCleanup()
        do {
          try removeUnusedQuarantine(
            binding,
            sourceParentDescriptor: source.parentDescriptor,
            expectedSourceParentSeal: source.parentSeal
          )
        } catch let cleanupError as AdapterError {
          cleanup = verifiedAttemptCleanupDisposition(
            target: target,
            source: source,
            quarantine: binding,
            failure: cleanupError.failure
          )
        } catch {
          cleanup = .bindingUnverified(
            failure: ExecutionAdapterFailure(code: String(reflecting: type(of: error)))
          )
        }
      } else {
        hooks.beforeUnusedQuarantineCleanup()
        do {
          try requireDirectorySeal(
            source.parentDescriptor,
            expected: source.parentSeal,
            code: "source-parent-seal-mismatch-before-unused-quarantine-cleanup"
          )
          try requireSourceSlotIdentity(
            parentDescriptor: source.parentDescriptor,
            leaf: name,
            expected: createdIdentity
          )
          let result = try Self.withRawCString(name) {
            Darwin.unlinkat(source.parentDescriptor, $0, AT_REMOVEDIR)
          }
          guard result == 0 else { throw failure("remove-unused-quarantine", errno) }
        } catch let cleanupError as AdapterError {
          cleanup = .bindingUnverified(failure: cleanupError.failure)
        } catch {
          cleanup = .bindingUnverified(
            failure: ExecutionAdapterFailure(code: String(reflecting: type(of: error)))
          )
        }
      }
      if let descriptor { _ = Darwin.close(descriptor) }
      throw QuarantinePreparationError(failure: primary, cleanup: cleanup)
    }
  }

  private func removeUnusedQuarantine(
    _ quarantine: QuarantineBinding,
    sourceParentDescriptor: Int32,
    expectedSourceParentSeal: QuarantineNamespaceSeal
  ) throws {
    try requireDirectorySeal(
      sourceParentDescriptor,
      expected: expectedSourceParentSeal,
      code: "source-parent-seal-mismatch-before-unused-quarantine-cleanup"
    )
    try requireQuarantineSeal(quarantine)
    try requireSourceSlotIdentity(
      parentDescriptor: sourceParentDescriptor,
      leaf: quarantine.locator.quarantineDirectoryName,
      expected: quarantine.seal.identity
    )
    let result = try Self.withRawCString(quarantine.locator.quarantineDirectoryName) {
      Darwin.unlinkat(sourceParentDescriptor, $0, AT_REMOVEDIR)
    }
    guard result == 0 else { throw failure("remove-unused-quarantine", errno) }
  }

  private func recordUnusedQuarantineCleanup(
    target: BoundMutationTarget,
    source: DescriptorBinding,
    quarantine: QuarantineBinding
  ) async {
    hooks.beforeUnusedQuarantineCleanup()
    do {
      try removeUnusedQuarantine(
        quarantine,
        sourceParentDescriptor: source.parentDescriptor,
        expectedSourceParentSeal: source.parentSeal
      )
    } catch let error as AdapterError {
      await results.setCleanup(
        verifiedAttemptCleanupDisposition(
          target: target,
          source: source,
          quarantine: quarantine,
          failure: error.failure
        ))
    } catch {
      await results.setCleanup(
        .bindingUnverified(
          failure: ExecutionAdapterFailure(code: String(reflecting: type(of: error)))
        ))
    }
  }

  private func verifiedAttemptCleanupDisposition(
    target: BoundMutationTarget,
    source: DescriptorBinding,
    quarantine: QuarantineBinding,
    failure: ExecutionAdapterFailure
  ) -> GitWorktreeAttemptCleanupDisposition {
    do {
      try requireRecoveryNamespaceBinding(
        target: target,
        source: source,
        quarantine: quarantine
      )
      return .retained(locator: quarantine.attemptLocator, failure: failure)
    } catch {
      return .bindingUnverified(failure: failure)
    }
  }

  private func requireQuarantineSeal(_ quarantine: QuarantineBinding) throws {
    try requireDirectorySeal(
      quarantine.descriptor,
      expected: quarantine.seal,
      code: "quarantine-seal-mismatch"
    )
    guard !(try aclSnapshot(quarantine.descriptor).hasEntries) else {
      throw accessPolicyFailure("quarantine-seal-mismatch")
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
    let rootSeal = try directorySeal(rootDescriptor)
    guard rootSeal.flags == 0,
      try PolicyDigest(bytes: rootSeal.aclDigest) == expectedAccess.aclDigest
    else { throw accessPolicyFailure("worktree-access-policy-mismatch") }

    let first = try collectSnapshot(rootDescriptor: rootDescriptor)
    let second = try collectSnapshot(rootDescriptor: rootDescriptor)
    try requireMatchingSnapshot(
      CoverageToken(records: first),
      actual: CoverageToken(records: second),
      mismatchCode: "coverage-raced"
    )
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
    records.append(
      try record(
        path: path,
        status: directoryStatus,
        payload: Data(),
        aclDigest: aclDigest(descriptor)
      ))

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
        let measurement = try digestRegularFile(
          parentDescriptor: descriptor,
          name: name,
          path: childPath,
          expected: childStatus,
          remainingBytes: &remainingBytes
        )
        records.append(
          try record(
            path: childPath,
            status: childStatus,
            payload: measurement.payloadDigest,
            aclDigest: measurement.aclDigest
          ))
      case .symbolicLink:
        guard remainingEntries > 0 else { throw failure("coverage-entry-budget-exhausted") }
        remainingEntries -= 1
        let measurement = try measureSymbolicLink(
          parentDescriptor: descriptor,
          name: name,
          expected: childStatus,
          remainingBytes: &remainingBytes
        )
        records.append(
          try record(
            path: childPath,
            status: childStatus,
            payload: measurement.target,
            aclDigest: measurement.aclDigest
          ))
      }
    }
  }

  private func requireSnapshotStillCurrent(
    _ token: CoverageToken,
    rootDescriptor: Int32,
    mismatchCode: String = "verified-quarantine-changed-before-delete"
  ) throws {
    let current = try collectSnapshot(rootDescriptor: rootDescriptor)
    try requireMatchingSnapshot(
      token,
      actual: CoverageToken(records: current),
      mismatchCode: mismatchCode
    )
  }

  private func requireMatchingSnapshot(
    _ expected: CoverageToken,
    actual: CoverageToken,
    mismatchCode: String
  ) throws {
    guard expected.records.count == actual.records.count else {
      throw failure("\(mismatchCode)-entry-set")
    }
    for (expectedRecord, actualRecord) in zip(expected.records, actual.records) {
      guard expectedRecord.path == actualRecord.path else {
        throw failure("\(mismatchCode)-entry-set")
      }
      guard expectedRecord.identity == actualRecord.identity else {
        throw failure("\(mismatchCode)-identity")
      }
      guard expectedRecord.mode == actualRecord.mode,
        expectedRecord.owner == actualRecord.owner,
        expectedRecord.group == actualRecord.group,
        expectedRecord.flags == actualRecord.flags,
        expectedRecord.aclDigest == actualRecord.aclDigest
      else {
        throw accessPolicyFailure("\(mismatchCode)-access-policy")
      }
      if expectedRecord.identity.type != .directory {
        guard expectedRecord.size == actualRecord.size,
          expectedRecord.payloadDigest == actualRecord.payloadDigest
        else {
          throw failure("\(mismatchCode)-content")
        }
      }
    }
  }

  private func recursivelyDeleteVerifiedTree(
    _ token: CoverageToken,
    rootDescriptor: Int32,
    quarantineDescriptor: Int32,
    quarantineLeaf: Data,
    expectedParentSeal: QuarantineNamespaceSeal
  ) throws {
    guard let rootRecord = token.records.first, rootRecord.path.isEmpty else {
      throw failure("invalid-coverage-token")
    }
    var recordsByPath: [NodePath: NodeRecord] = [:]
    for record in token.records {
      guard
        recordsByPath.updateValue(
          record,
          forKey: NodePath(components: record.path)
        ) == nil
      else { throw failure("invalid-coverage-token") }
    }
    try requireDeletionDirectoryRecordStillCurrent(
      rootRecord,
      descriptor: rootDescriptor,
      code: "delete-commit-root"
    )

    var remainingBytes = Self.maximumCoverageBytes
    for record in token.records.dropFirst().sorted(by: { lhs, rhs in
      if lhs.path.count != rhs.path.count { return lhs.path.count > rhs.path.count }
      return Self.comparePaths(rhs.path, lhs.path)
    }) {
      let parentPath = Array(record.path.dropLast())
      guard let leaf = record.path.last else { throw failure("invalid-coverage-token") }
      let opened = try openDeletionParentDirectory(
        rootDescriptor,
        components: parentPath,
        recordsByPath: recordsByPath
      )
      defer { Self.close(opened.dropFirst()) }
      let parent = opened.last ?? rootDescriptor
      try requireDeletionRecordStillCurrent(
        record,
        parentDescriptor: parent,
        leaf: leaf,
        remainingBytes: &remainingBytes
      )
      let flags = record.identity.type == .directory ? AT_REMOVEDIR : 0
      let result = try Self.withRawCString(leaf) { Darwin.unlinkat(parent, $0, flags) }
      guard result == 0 else { throw failure("delete-verified-quarantine-entry", errno) }
    }
    hooks.beforeRecursiveDeleteRootRemoval()
    try requireDirectorySeal(
      quarantineDescriptor,
      expected: expectedParentSeal,
      code: "delete-commit-parent-namespace-seal-mismatch"
    )
    try requireDeletionDirectoryRecordStillCurrent(
      rootRecord,
      descriptor: rootDescriptor,
      code: "delete-commit-root"
    )
    try requireSourceSlotIdentity(
      parentDescriptor: quarantineDescriptor,
      leaf: quarantineLeaf,
      expected: rootRecord.identity
    )
    let result = try Self.withRawCString(quarantineLeaf) {
      Darwin.unlinkat(quarantineDescriptor, $0, AT_REMOVEDIR)
    }
    guard result == 0 else { throw failure("delete-verified-quarantine-root", errno) }
  }

  private func requireDeletionRecordStillCurrent(
    _ record: NodeRecord,
    parentDescriptor: Int32,
    leaf: Data,
    remainingBytes: inout UInt64
  ) throws {
    var current = stat()
    let result = try Self.withRawCString(leaf) {
      Darwin.fstatat(parentDescriptor, $0, &current, AT_SYMLINK_NOFOLLOW)
    }
    guard result == 0 else {
      throw failure(
        errno == ENOENT ? "delete-commit-entry-missing" : "delete-commit-entry-unreadable",
        errno
      )
    }
    try requireIdentity(
      current,
      expected: record.identity,
      code: "delete-commit-entry-identity-mismatch"
    )
    try requireDeletionAccessPolicy(
      record,
      status: current,
      aclDigest: nil,
      code: "delete-commit-entry-access-policy-mismatch"
    )

    switch record.identity.type {
    case .directory:
      let descriptor = try openDirectory(
        at: parentDescriptor,
        name: leaf,
        code: "open-delete-commit-directory"
      )
      defer { _ = Darwin.close(descriptor) }
      try requireDeletionDirectoryRecordStillCurrent(
        record,
        descriptor: descriptor,
        code: "delete-commit-entry"
      )
    case .regularFile:
      let measurement = try digestRegularFile(
        parentDescriptor: parentDescriptor,
        name: leaf,
        path: record.path,
        expected: current,
        remainingBytes: &remainingBytes
      )
      try requireDeletionAccessPolicy(
        record,
        status: current,
        aclDigest: measurement.aclDigest,
        code: "delete-commit-entry-access-policy-mismatch"
      )
      guard record.size == UInt64(max(current.st_size, 0)),
        record.payloadDigest == measurement.payloadDigest
      else { throw failure("delete-commit-entry-content-mismatch") }
    case .symbolicLink:
      let measurement = try measureSymbolicLink(
        parentDescriptor: parentDescriptor,
        name: leaf,
        expected: current,
        remainingBytes: &remainingBytes
      )
      try requireDeletionAccessPolicy(
        record,
        status: current,
        aclDigest: measurement.aclDigest,
        code: "delete-commit-entry-access-policy-mismatch"
      )
      guard record.size == UInt64(max(current.st_size, 0)),
        record.payloadDigest == Data(SHA256.hash(data: measurement.target))
      else { throw failure("delete-commit-entry-content-mismatch") }
    }

    try requireSourceSlotIdentity(
      parentDescriptor: parentDescriptor,
      leaf: leaf,
      expected: record.identity
    )
  }

  private func requireDeletionDirectoryRecordStillCurrent(
    _ record: NodeRecord,
    descriptor: Int32,
    code: String
  ) throws {
    let current = try status(descriptor)
    try requireIdentity(
      current,
      expected: record.identity,
      code: "\(code)-identity-mismatch"
    )
    try requireDeletionAccessPolicy(
      record,
      status: current,
      aclDigest: aclDigest(descriptor),
      code: "\(code)-access-policy-mismatch"
    )
  }

  private func requireDeletionAccessPolicy(
    _ record: NodeRecord,
    status current: stat,
    aclDigest: Data?,
    code: String
  ) throws {
    guard record.mode == UInt32(current.st_mode),
      record.owner == UInt32(current.st_uid),
      record.group == UInt32(current.st_gid),
      record.flags == UInt32(current.st_flags)
    else { throw accessPolicyFailure(code) }
    if let aclDigest {
      guard record.aclDigest == aclDigest else { throw accessPolicyFailure(code) }
    }
  }

  private func openDeletionParentDirectory(
    _ root: Int32,
    components: [Data],
    recordsByPath: [NodePath: NodeRecord]
  ) throws -> [Int32] {
    var descriptors = [root]
    var path: [Data] = []
    do {
      for component in components {
        let next = try openDirectory(
          at: descriptors.last!,
          name: component,
          code: "open-delete-parent"
        )
        descriptors.append(next)
        path.append(component)
        guard let record = recordsByPath[NodePath(components: path)] else {
          throw failure("invalid-coverage-token")
        }
        try requireDeletionDirectoryRecordStillCurrent(
          record,
          descriptor: next,
          code: "delete-commit-parent"
        )
      }
      return descriptors
    } catch {
      Self.close(descriptors.dropFirst())
      throw error
    }
  }

  private func sourceIsAbsent(
    _ target: BoundMutationTarget,
    binding: GitWorktreePostVerificationNamespaceBinding?
  ) -> PostVerificationOutcome {
    do {
      try validateRawPath(target)
      guard let binding,
        binding.root.identity == target.expectedRootIdentity,
        binding.parents.map(\.identity) == target.expectedParentIdentities,
        binding.parents.count == target.targetPath.components.dropLast().count
      else { throw failure("postverify-namespace-binding-missing-or-invalid") }
      let root = try Self.withRawCString(target.rawRoot.absoluteBytes) { path -> Int32 in
        let descriptor = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
        guard descriptor >= 0 else { throw failure("postverify-open-root", errno) }
        return descriptor
      }
      defer { _ = Darwin.close(root) }
      try requirePostVerificationDirectoryBinding(
        root,
        expected: binding.root,
        code: "postverify-root-binding-mismatch"
      )
      var parent = root
      var opened: [Int32] = []
      defer { Self.close(opened) }
      for (index, component) in target.targetPath.components.dropLast().enumerated() {
        let next = try openDirectory(at: parent, name: component, code: "postverify-open-parent")
        opened.append(next)
        try requirePostVerificationDirectoryBinding(
          next,
          expected: binding.parents[index],
          code: "postverify-parent-binding-mismatch"
        )
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
      if errno == EACCES || errno == EPERM {
        return .unreadable(
          ObservationFailure(
            code: "postverify-stat-target",
            collector: "git-worktree-postverify"
          ))
      }
      return .failed(
        ObservationFailure(code: "postverify-stat-target", collector: "git-worktree-postverify"))
    } catch let error as AdapterError {
      if error.failure.errno == ENOENT { return .missing }
      if error.failure.errno == EACCES || error.failure.errno == EPERM {
        return .unreadable(
          ObservationFailure(code: error.failure.code, collector: "git-worktree-postverify"))
      }
      return .failed(
        ObservationFailure(code: error.failure.code, collector: "git-worktree-postverify"))
    } catch {
      return .failed(
        ObservationFailure(
          code: String(reflecting: type(of: error)), collector: "git-worktree-postverify"))
    }
  }

  private func requirePostVerificationDirectoryBinding(
    _ descriptor: Int32,
    expected: GitWorktreePostVerificationDirectoryBinding,
    code: String
  ) throws {
    try requireDirectorySeal(
      descriptor,
      expected: QuarantineNamespaceSeal(
        identity: expected.identity,
        owner: expected.owner,
        group: expected.group,
        mode: expected.mode,
        flags: expected.flags,
        device: expected.device,
        aclDigest: expected.aclDigest,
        mountIdentity: expected.mountIdentity
      ),
      code: code
    )
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

  static func measuredAdministrativeDigest(atRawPath path: Data) throws -> PolicyDigest {
    let descriptor = try withRawCString(path) { pathPointer -> Int32 in
      let value = Darwin.open(pathPointer, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      guard value >= 0 else { throw failure("open-administrative-measurement-root", errno) }
      return value
    }
    defer { _ = Darwin.close(descriptor) }
    let adapter = GitWorktreeQuarantineAdapter()
    return try adapter.administrativeDigest(
      adapter.collectSnapshot(rootDescriptor: descriptor))
  }

  static func measuredACLDigest(atRawPath path: Data) throws -> PolicyDigest {
    let descriptor = try withRawCString(path) { pathPointer -> Int32 in
      let value = Darwin.open(pathPointer, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      guard value >= 0 else { throw failure("open-acl-measurement-root", errno) }
      return value
    }
    defer { _ = Darwin.close(descriptor) }
    return try PolicyDigest(bytes: GitWorktreeQuarantineAdapter().aclDigest(descriptor))
  }

  static func measuredHeadResolutionDigest(
    administrativeRawPath: Data,
    commonRawPath: Data
  ) throws -> PolicyDigest {
    let administrative = try withRawCString(administrativeRawPath) { path -> Int32 in
      let value = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      guard value >= 0 else { throw failure("open-head-resolution-administrative", errno) }
      return value
    }
    defer { _ = Darwin.close(administrative) }
    let common = try withRawCString(commonRawPath) { path -> Int32 in
      let value = Darwin.open(path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
      guard value >= 0 else { throw failure("open-head-resolution-common", errno) }
      return value
    }
    defer { _ = Darwin.close(common) }
    return try GitWorktreeQuarantineAdapter().headResolutionDigest(
      administrativeDescriptor: administrative,
      commonDescriptor: common
    )
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
      data.append(Data(record.identity.type.rawValue.utf8))
      data.append(0)
      Self.append(record.identity.type == .directory ? 0 : record.size, to: &data)
      Self.append(UInt64(record.payloadDigest.count), to: &data)
      data.append(record.payloadDigest)
    }
    return try PolicyDigest(bytes: Data(SHA256.hash(data: data)))
  }

  private func administrativeDigest(_ records: [NodeRecord]) throws -> PolicyDigest {
    var data = Data("diskplan/git-administrative-metadata/v1\0".utf8)
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
      Self.append(UInt64(record.aclDigest.count), to: &data)
      data.append(record.aclDigest)
      Self.append(record.identity.type == .directory ? 0 : record.size, to: &data)
      Self.append(UInt64(record.payloadDigest.count), to: &data)
      data.append(record.payloadDigest)
    }
    return try PolicyDigest(bytes: Data(SHA256.hash(data: data)))
  }

  private func headResolutionDigest(
    administrativeDescriptor: Int32,
    commonDescriptor: Int32
  ) throws -> PolicyDigest {
    let head = try readStableMetadataFile(
      parentDescriptor: administrativeDescriptor,
      name: Data("HEAD".utf8),
      maximumBytes: 4 * 1024,
      code: "git-head"
    )
    var normalizedHead = head
    while normalizedHead.last == UInt8(ascii: "\n")
      || normalizedHead.last == UInt8(ascii: "\r")
    {
      normalizedHead.removeLast()
    }
    guard !normalizedHead.isEmpty else { throw failure("git-head-empty") }

    var data = Data("diskplan/git-head-resolution/v1\0".utf8)
    Self.append(UInt64(normalizedHead.count), to: &data)
    data.append(normalizedHead)
    let refPrefix = Data("ref: ".utf8)
    if normalizedHead.starts(with: refPrefix) {
      let rawRef = Data(normalizedHead.dropFirst(refPrefix.count))
      guard rawRef.count <= 4 * 1024,
        !rawRef.isEmpty,
        !rawRef.contains(0),
        rawRef.first != UInt8(ascii: "/")
      else { throw failure("git-head-reference-invalid") }
      let components = [UInt8](rawRef).split(
        separator: UInt8(ascii: "/"),
        omittingEmptySubsequences: false
      ).map { Data($0) }
      guard !components.isEmpty,
        components.allSatisfy({
          !$0.isEmpty && $0 != Data(".".utf8) && $0 != Data("..".utf8)
        }),
        let leaf = components.last
      else { throw failure("git-head-reference-invalid") }

      var opened: [Int32] = []
      defer { Self.close(opened) }
      var parent = commonDescriptor
      for component in components.dropLast() {
        let next = try openDirectory(
          at: parent,
          name: component,
          code: "open-git-head-reference-parent"
        )
        opened.append(next)
        parent = next
      }
      let resolved = try readStableMetadataFile(
        parentDescriptor: parent,
        name: leaf,
        maximumBytes: 4 * 1024,
        code: "git-head-reference"
      )
      Self.append(UInt64(rawRef.count), to: &data)
      data.append(rawRef)
      Self.append(UInt64(resolved.count), to: &data)
      data.append(resolved)
    } else {
      Self.append(0, to: &data)
      Self.append(0, to: &data)
    }
    return try PolicyDigest(bytes: Data(SHA256.hash(data: data)))
  }

  private func readStableMetadataFile(
    parentDescriptor: Int32,
    name: Data,
    maximumBytes: Int,
    code: String
  ) throws -> Data {
    let descriptor = try Self.withRawCString(name) { namePointer -> Int32 in
      let value = Darwin.openat(
        parentDescriptor,
        namePointer,
        O_RDONLY | O_NOFOLLOW | O_CLOEXEC
      )
      guard value >= 0 else { throw failure("open-\(code)", errno) }
      return value
    }
    defer { _ = Darwin.close(descriptor) }
    let before = try status(descriptor)
    guard Self.kind(before.st_mode) == .regularFile else {
      throw failure("\(code)-not-regular")
    }
    let beforeACL = try aclDigest(descriptor)
    let bytes = try readAll(descriptor, maximumBytes: maximumBytes)
    let after = try status(descriptor)
    try requireSameProtectedFileState(
      before,
      before: after,
      descriptor: descriptor,
      expectedACLDigest: beforeACL
    )
    guard UInt64(max(after.st_size, 0)) == UInt64(bytes.count) else {
      throw failure("\(code)-content-raced")
    }
    return bytes
  }

  private func record(
    path: [Data],
    status: stat,
    payload: Data,
    aclDigest: Data
  ) throws -> NodeRecord {
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
      aclDigest: aclDigest,
      size: UInt64(max(status.st_size, 0)),
      payloadDigest: digest
    )
  }

  private func digestRegularFile(
    parentDescriptor: Int32,
    name: Data,
    path: [Data],
    expected: stat,
    remainingBytes: inout UInt64
  ) throws -> FileMeasurement {
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
    try requireSameProtectedFileState(
      expected, before: before, descriptor: descriptor, expectedACLDigest: nil)
    let beforeACL = try aclDigest(descriptor)
    let firstDigest = try readRegularFileDigest(
      descriptor, remainingBytes: &remainingBytes)
    hooks.afterCoverageFileFirstRead(descriptor, path)
    let after = try status(descriptor)
    try requireSameProtectedFileState(
      before, before: after, descriptor: descriptor, expectedACLDigest: beforeACL)
    guard UInt64(max(after.st_size, 0)) == UInt64(max(expected.st_size, 0)) else {
      throw failure("coverage-file-content-raced")
    }
    let timestampChanged =
      !Self.sameTimestamps(expected, before)
      || !Self.sameTimestamps(before, after)
    guard timestampChanged else {
      return FileMeasurement(payloadDigest: firstDigest, aclDigest: beforeACL)
    }

    guard Darwin.lseek(descriptor, 0, SEEK_SET) == 0 else {
      throw failure("rewind-coverage-file", errno)
    }
    let rereadBefore = try status(descriptor)
    try requireSameProtectedFileState(
      after, before: rereadBefore, descriptor: descriptor, expectedACLDigest: beforeACL)
    let secondDigest = try readRegularFileDigest(
      descriptor, remainingBytes: &remainingBytes)
    let rereadAfter = try status(descriptor)
    try requireSameProtectedFileState(
      rereadBefore,
      before: rereadAfter,
      descriptor: descriptor,
      expectedACLDigest: beforeACL
    )
    guard firstDigest == secondDigest,
      UInt64(max(rereadAfter.st_size, 0)) == UInt64(max(expected.st_size, 0))
    else { throw failure("coverage-file-content-raced") }
    return FileMeasurement(payloadDigest: secondDigest, aclDigest: beforeACL)
  }

  private func readRegularFileDigest(
    _ descriptor: Int32,
    remainingBytes: inout UInt64
  ) throws -> Data {
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
    return Data(hasher.finalize())
  }

  private func requireSameProtectedFileState(
    _ expected: stat,
    before current: stat,
    descriptor: Int32,
    expectedACLDigest: Data?
  ) throws {
    guard Self.identity(expected) == Self.identity(current) else {
      throw failure("coverage-file-replaced")
    }
    guard expected.st_mode == current.st_mode,
      expected.st_uid == current.st_uid,
      expected.st_gid == current.st_gid,
      expected.st_flags == current.st_flags
    else { throw accessPolicyFailure("coverage-file-access-policy-raced") }
    if let expectedACLDigest {
      guard try aclDigest(descriptor) == expectedACLDigest else {
        throw accessPolicyFailure("coverage-file-access-policy-raced")
      }
    }
  }

  private func measureSymbolicLink(
    parentDescriptor: Int32,
    name: Data,
    expected: stat,
    remainingBytes: inout UInt64
  ) throws -> SymbolicLinkMeasurement {
    let descriptor = try Self.withRawCString(name) { namePointer -> Int32 in
      let value = Darwin.openat(
        parentDescriptor,
        namePointer,
        O_RDONLY | O_SYMLINK | O_CLOEXEC
      )
      guard value >= 0 else { throw failure("open-coverage-symlink", errno) }
      return value
    }
    defer { _ = Darwin.close(descriptor) }
    let before = try status(descriptor)
    guard Self.kind(before.st_mode) == .symbolicLink else {
      throw failure("coverage-symlink-replaced")
    }
    try requireSameProtectedFileState(
      expected,
      before: before,
      descriptor: descriptor,
      expectedACLDigest: nil
    )
    let beforeACL = try aclDigest(descriptor)

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
        let after = try status(descriptor)
        try requireSameProtectedFileState(
          before,
          before: after,
          descriptor: descriptor,
          expectedACLDigest: beforeACL
        )
        var slot = stat()
        let result = try Self.withRawCString(name) {
          Darwin.fstatat(parentDescriptor, $0, &slot, AT_SYMLINK_NOFOLLOW)
        }
        guard result == 0 else {
          throw failure("coverage-symlink-unreadable", errno)
        }
        guard Self.identity(slot) == Self.identity(after) else {
          throw failure("coverage-symlink-replaced")
        }
        guard slot.st_mode == after.st_mode,
          slot.st_uid == after.st_uid,
          slot.st_gid == after.st_gid,
          slot.st_flags == after.st_flags
        else { throw accessPolicyFailure("coverage-symlink-access-policy-raced") }
        return SymbolicLinkMeasurement(
          target: Data(buffer.prefix(count)),
          aclDigest: beforeACL
        )
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
    let current = try sourceSlotIdentity(
      parentDescriptor: parentDescriptor,
      leaf: leaf,
      code: "stat-source-slot"
    )
    guard current.device == expected.device,
      current.object == expected.object,
      current.type == expected.type
    else { throw failure("source-slot-identity-mismatch") }
    if case .known(let generation) = expected.generation {
      guard current.generation == .known(generation) else {
        throw failure("source-slot-identity-mismatch-generation")
      }
    }
  }

  private func sourceSlotIdentity(
    parentDescriptor: Int32,
    leaf: Data,
    code: String
  ) throws -> ObjectIdentity {
    var current = stat()
    let result = try Self.withRawCString(leaf) {
      Darwin.fstatat(parentDescriptor, $0, &current, AT_SYMLINK_NOFOLLOW)
    }
    guard result == 0, Self.kind(current.st_mode) != nil else {
      throw failure(code, result == 0 ? nil : errno)
    }
    return Self.identity(current)
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
      Self.device(value) == expectedDevice
    else { throw failure("coverage-mount-or-type-mismatch") }
    guard value.st_uid == Darwin.geteuid(),
      (value.st_mode & (S_IWGRP | S_IWOTH)) == 0
    else { throw accessPolicyFailure("namespace-not-owner-private") }
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

  private func directorySeal(_ descriptor: Int32) throws -> QuarantineNamespaceSeal {
    let value = try status(descriptor)
    let acl = try aclSnapshot(descriptor)
    return QuarantineNamespaceSeal(
      identity: Self.identity(value),
      owner: UInt32(value.st_uid),
      group: UInt32(value.st_gid),
      mode: UInt32(value.st_mode) & 0o7777,
      flags: UInt32(value.st_flags),
      device: Self.device(value),
      aclDigest: acl.digest,
      mountIdentity: try mountIdentity(descriptor)
    )
  }

  private func trustedOwnerPrivateSeal(
    _ descriptor: Int32
  ) throws -> QuarantineNamespaceSeal {
    let seal = try directorySeal(descriptor)
    guard seal.identity.type == .directory,
      seal.owner == Darwin.geteuid(),
      seal.mode & UInt32(S_IWGRP | S_IWOTH) == 0,
      seal.flags == 0,
      !(try aclSnapshot(descriptor).hasEntries)
    else { throw accessPolicyFailure("namespace-access-policy-not-owner-private") }
    return seal
  }

  private func requireDirectorySeal(
    _ descriptor: Int32,
    expected: QuarantineNamespaceSeal,
    code: String
  ) throws {
    let current = try directorySeal(descriptor)
    guard current.identity == expected.identity,
      current.device == expected.device
    else { throw failure(code) }
    guard current.mountIdentity == expected.mountIdentity else {
      throw accessPolicyFailure("\(code)-mount-identity")
    }
    guard current.owner == expected.owner,
      current.group == expected.group,
      current.mode == expected.mode,
      current.flags == expected.flags,
      current.aclDigest == expected.aclDigest
    else { throw accessPolicyFailure(code) }
  }

  private func mountIdentity(_ descriptor: Int32) throws -> Data {
    var value = statfs()
    guard Darwin.fstatfs(descriptor, &value) == 0 else {
      throw failure("fstatfs-mount-identity", errno)
    }
    return withUnsafeBytes(of: value.f_fsid) { Data($0) }
  }

  private func aclDigest(_ descriptor: Int32) throws -> Data {
    try aclSnapshot(descriptor).digest
  }

  private func aclSnapshot(_ descriptor: Int32) throws -> ACLSnapshot {
    errno = 0
    guard let acl = acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
      if errno == ENOENT {
        return ACLSnapshot(
          digest: Data(SHA256.hash(data: Data("diskplan/empty-acl/v1".utf8))),
          hasEntries: false
        )
      }
      throw failure("read-extended-acl", errno)
    }
    defer { _ = acl_free(UnsafeMutableRawPointer(acl)) }
    var entry: acl_entry_t?
    let entryResult = acl_get_entry(acl, 0, &entry)
    guard entryResult >= 0 else { throw failure("enumerate-extended-acl", errno) }
    let hasEntries = entryResult == 1
    var textLength: ssize_t = 0
    guard let text = acl_to_text(acl, &textLength), textLength >= 0 else {
      throw failure("serialize-extended-acl", errno)
    }
    defer { _ = acl_free(text) }
    let bytes = Data(bytes: text, count: Int(textLength))
    return ACLSnapshot(
      digest: Data(SHA256.hash(data: bytes)),
      hasEntries: hasEntries
    )
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

  private static func sameTimestamps(_ lhs: stat, _ rhs: stat) -> Bool {
    lhs.st_mtimespec.tv_sec == rhs.st_mtimespec.tv_sec
      && lhs.st_mtimespec.tv_nsec == rhs.st_mtimespec.tv_nsec
      && lhs.st_ctimespec.tv_sec == rhs.st_ctimespec.tv_sec
      && lhs.st_ctimespec.tv_nsec == rhs.st_ctimespec.tv_nsec
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

  private func openDirectoryIfPresent(
    at descriptor: Int32,
    name: Data,
    code: String
  ) throws -> Int32? {
    do {
      return try openDirectory(at: descriptor, name: name, code: code)
    } catch let error as AdapterError where error.failure.errno == ENOENT {
      return nil
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

  private static func failure(
    _ code: String,
    _ value: Int32? = nil,
    recoverySafety: RecoverySafety = .automaticRestoreAllowed
  ) -> AdapterError {
    AdapterError(
      failure: ExecutionAdapterFailure(code: code, errno: value),
      recoverySafety: recoverySafety
    )
  }

  private func failure(_ code: String, _ value: Int32? = nil) -> AdapterError {
    Self.failure(code, value)
  }

  private static func accessPolicyFailure(
    _ code: String,
    _ value: Int32? = nil
  ) -> AdapterError {
    failure(code, value, recoverySafety: .manualRecoveryRequired)
  }

  private func accessPolicyFailure(_ code: String, _ value: Int32? = nil) -> AdapterError {
    Self.accessPolicyFailure(code, value)
  }
}
