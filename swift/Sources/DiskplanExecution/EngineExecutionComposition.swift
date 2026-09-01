import DiskplanPolicy
import Foundation

/// Engine-owned Phase 4/5 composition. The frontend receives reports and opaque authority,
/// never collectors or mutation adapters.
@_spi(DiskplanEngine)
public final class EngineExecutionComposition: @unchecked Sendable {
  public let preparation: ExecutionPreparationEngine
  public let applyCoordinator: BestEffortApplyCoordinator

  private let adapter: any ExecutionMutationAdapter
  private let eventSink: any ExecutionEventSink
  private let auditSink: (any ExecutionAuditSink)?

  public init(
    collector: EngineRevalidationCollector,
    eventSink: any ExecutionEventSink = ShellExecutionEventSink(),
    auditSink: (any ExecutionAuditSink)? = nil
  ) {
    let adapter = ProductionExecutionAdapter(
      genericRemove: PosixRemoveAdapter(),
      gitWorktree: GitWorktreeQuarantineAdapter()
    )
    self.adapter = adapter
    self.eventSink = eventSink
    self.auditSink = auditSink
    preparation = ExecutionPreparationEngine(collector: collector)
    applyCoordinator = BestEffortApplyCoordinator(
      adapter: adapter,
      eventSink: eventSink,
      auditSink: auditSink
    )
  }

  /// Creates one coordinator whose events remain visible to the configured shell sink while an
  /// executable composition root observes the exact same authoritative Phase 5 stream.
  public func makeApplyCoordinator(
    observing observer: any ExecutionEventSink
  ) -> BestEffortApplyCoordinator {
    BestEffortApplyCoordinator(
      adapter: adapter,
      eventSink: TeeExecutionEventSink(primary: eventSink, observer: observer),
      auditSink: auditSink
    )
  }
}

private actor TeeExecutionEventSink: ExecutionEventSink {
  private let primary: any ExecutionEventSink
  private let observer: any ExecutionEventSink

  init(primary: any ExecutionEventSink, observer: any ExecutionEventSink) {
    self.primary = primary
    self.observer = observer
  }

  func emit(_ event: ExecutionEvent) async {
    await primary.emit(event)
    await observer.emit(event)
  }
}

/// A typed router prevents a specialized action from reaching generic `/bin/rm`.
final class ProductionExecutionAdapter: ExecutionMutationAdapter, @unchecked Sendable {
  private let genericRemove: PosixRemoveAdapter
  private let gitWorktree: GitWorktreeQuarantineAdapter

  init(
    genericRemove: PosixRemoveAdapter,
    gitWorktree: GitWorktreeQuarantineAdapter
  ) {
    self.genericRemove = genericRemove
    self.gitWorktree = gitWorktree
  }

  func apply(
    _ operation: ExecutionAdapterOperation,
    context: MutationExecutionContext
  ) async -> AdapterOperationOutcome {
    switch operation {
    case .genericRemove:
      return await genericRemove.apply(operation, context: context)
    case .gitWorktreeRemove(_, let contract):
      guard !contract.requiresDiscardLocalChanges else {
        return .failed(ExecutionAdapterFailure(code: "git-worktree-dirty-report-only"))
      }
      return await gitWorktree.apply(operation, context: context)
    case .gitWorktreeDiscardLocalChanges:
      return .failed(ExecutionAdapterFailure(code: "git-worktree-dirty-report-only"))
    case .codexCleanTemporary:
      return .failed(
        ExecutionAdapterFailure(code: "codex-temporary-adapter-not-configured"))
    case .versionedArtifactRemove:
      return .failed(
        ExecutionAdapterFailure(code: "versioned-artifact-adapter-not-configured"))
    }
  }

  func applyResult(
    _ operation: ExecutionAdapterOperation,
    context: MutationExecutionContext
  ) async -> AdapterOperationResult {
    switch operation {
    case .genericRemove:
      return await genericRemove.applyResult(operation, context: context)
    case .gitWorktreeRemove(_, let contract):
      guard !contract.requiresDiscardLocalChanges else {
        return AdapterOperationResult(
          outcome: .failed(
            ExecutionAdapterFailure(code: "git-worktree-dirty-report-only")))
      }
      return await gitWorktree.applyResult(operation, context: context)
    case .gitWorktreeDiscardLocalChanges:
      return AdapterOperationResult(
        outcome: .failed(
          ExecutionAdapterFailure(code: "git-worktree-dirty-report-only")))
    case .codexCleanTemporary:
      return AdapterOperationResult(
        outcome: .failed(
          ExecutionAdapterFailure(code: "codex-temporary-adapter-not-configured")))
    case .versionedArtifactRemove:
      return AdapterOperationResult(
        outcome: .failed(
          ExecutionAdapterFailure(code: "versioned-artifact-adapter-not-configured")))
    }
  }

  func postverify(_ operation: ExecutionAdapterOperation) async -> PostVerificationOutcome {
    switch operation {
    case .genericRemove:
      return await genericRemove.postverify(operation)
    case .gitWorktreeRemove(_, let contract):
      guard !contract.requiresDiscardLocalChanges else {
        return .notSatisfied(code: "git-worktree-dirty-report-only")
      }
      return await gitWorktree.postverify(operation)
    case .gitWorktreeDiscardLocalChanges:
      return .notSatisfied(code: "git-worktree-dirty-report-only")
    case .codexCleanTemporary, .versionedArtifactRemove:
      return .unknown(.unsupported)
    }
  }

  func postverify(
    _ operation: ExecutionAdapterOperation,
    result: AdapterOperationResult
  ) async -> PostVerificationOutcome {
    switch operation {
    case .genericRemove:
      return await genericRemove.postverify(operation, result: result)
    case .gitWorktreeRemove(_, let contract):
      guard !contract.requiresDiscardLocalChanges else {
        return .notSatisfied(code: "git-worktree-dirty-report-only")
      }
      return await gitWorktree.postverify(operation, result: result)
    case .gitWorktreeDiscardLocalChanges:
      return .notSatisfied(code: "git-worktree-dirty-report-only")
    case .codexCleanTemporary, .versionedArtifactRemove:
      return .unknown(.unsupported)
    }
  }
}
