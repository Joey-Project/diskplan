import Darwin
import DiskplanPolicy
import Foundation

struct JITRevalidationRequest: Equatable, Sendable {
  let plan: ImmutablePlan
  let validatedOverlay: ValidatedDecisionOverlay
  let epoch: ExecutionEpochContext
  let actionIDs: [ActionID]
  let releaseGroupIDs: [String]

  init(
    plan: ImmutablePlan,
    validatedOverlay: ValidatedDecisionOverlay,
    epoch: ExecutionEpochContext,
    actionIDs: [ActionID],
    releaseGroupIDs: [String]
  ) {
    self.plan = plan
    self.validatedOverlay = validatedOverlay
    self.epoch = epoch
    self.actionIDs = actionIDs
    self.releaseGroupIDs = releaseGroupIDs
  }
}

/// A read-only collector used at the last possible boundary before one execution unit.
protocol JITRevalidationEvidenceSource: Sendable {
  func collectJITEvidence(for request: JITRevalidationRequest) async throws
    -> CurrentRevalidationSnapshot
}

public struct JITRevalidationReport: Equatable, Sendable {
  public let actionOutcomes: [ActionRevalidationOutcome]
  public let globalFindings: [RevalidationFinding]

  public var isCurrent: Bool {
    actionOutcomes.allSatisfy(\.isCurrent) && globalFindings.isEmpty
  }

  public init(
    actionOutcomes: [ActionRevalidationOutcome],
    globalFindings: [RevalidationFinding]
  ) {
    self.actionOutcomes = actionOutcomes
    self.globalFindings = globalFindings
  }
}

public enum ExecutionUnitID: Equatable, Hashable, Sendable {
  case action(ActionID)
  case compoundRelease([String])
}

public struct BoundMutationTarget: Equatable, Sendable {
  public let actionID: ActionID
  public let rawRoot: RawRootPath
  public let targetPath: RawTargetPath
  public let expectedIdentity: ObjectIdentity
  public let expectedRootIdentity: ObjectIdentity
  public let expectedParentIdentities: [ObjectIdentity]
  public let postcondition: ActionPostcondition

  public init(action: ActionDefinition) {
    let namespace = action.prototype.namespaceBinding
    actionID = action.id
    rawRoot = namespace.rawRoot
    targetPath = namespace.targetPath
    expectedIdentity = action.prototype.targetIdentity
    expectedRootIdentity = namespace.rootIdentity
    expectedParentIdentities = namespace.parentChain.map(\.identity)
    postcondition = action.prototype.postcondition
  }
}

/// Every mutation reaches an adapter through one policy-derived typed operation.
public enum ExecutionAdapterOperation: Equatable, Sendable {
  case genericRemove(BoundMutationTarget, GenericRemoveContract)
  case gitWorktreeRemove(BoundMutationTarget, GitWorktreeRemoveContract)
  case gitWorktreeDiscardLocalChanges(
    BoundMutationTarget,
    GitWorktreeDiscardLocalChangesContract
  )
  case codexCleanTemporary(BoundMutationTarget, CodexTemporaryRemoveContract)
  case versionedArtifactRemove(BoundMutationTarget, VersionedArtifactRemoveContract)

  public var actionID: ActionID { target.actionID }

  public var target: BoundMutationTarget {
    switch self {
    case .genericRemove(let target, _),
      .gitWorktreeRemove(let target, _),
      .gitWorktreeDiscardLocalChanges(let target, _),
      .codexCleanTemporary(let target, _),
      .versionedArtifactRemove(let target, _):
      target
    }
  }

  public var forceRequirement: ForceRequirement {
    if case .genericRemove(_, let contract) = self { return contract.forceRequirement }
    return .notRequired
  }
}

public struct ExecutionAdapterFailure: Error, Equatable, Sendable {
  public let code: String
  public let errno: Int32?

  public init(code: String, errno: Int32? = nil) {
    self.code = code
    self.errno = errno
  }
}

public enum AdapterOperationOutcome: Equatable, Sendable {
  case succeeded(detailCode: String)
  case failed(ExecutionAdapterFailure)
  case cancelled
}

public enum PostVerificationOutcome: Equatable, Sendable {
  case satisfied
  case notSatisfied(code: String)
  case unknown(UnknownReason)
  case unreadable(ObservationFailure)
  case failed(ObservationFailure)
}

public protocol ExecutionMutationAdapter: Sendable {
  func apply(_ operation: ExecutionAdapterOperation) async -> AdapterOperationOutcome
  func postverify(_ operation: ExecutionAdapterOperation) async -> PostVerificationOutcome
}

public enum ExecutionStepStatus: String, Equatable, Sendable {
  case succeeded
  case failed
  case cancelled
  case expired
}

public struct ExecutionStepOutcome: Equatable, Sendable {
  public let actionID: ActionID
  public let status: ExecutionStepStatus
  public let adapterOutcome: AdapterOperationOutcome
  public let postVerification: PostVerificationOutcome

  public init(
    actionID: ActionID,
    status: ExecutionStepStatus,
    adapterOutcome: AdapterOperationOutcome,
    postVerification: PostVerificationOutcome
  ) {
    self.actionID = actionID
    self.status = status
    self.adapterOutcome = adapterOutcome
    self.postVerification = postVerification
  }
}

public enum ExecutionUnitStatus: String, Equatable, Sendable {
  case succeeded
  case partiallyFailed
  case failed
  case cancelled
  case skippedPrerequisite
  case jitRejected
  case expired
}

public struct ExecutionUnitOutcome: Equatable, Sendable {
  public let id: ExecutionUnitID
  public let logicalActionIDs: [ActionID]
  public let prerequisiteActionIDs: [ActionID]
  public let status: ExecutionUnitStatus
  public let jitReport: JITRevalidationReport?
  public let steps: [ExecutionStepOutcome]

  public init(
    id: ExecutionUnitID,
    logicalActionIDs: [ActionID],
    prerequisiteActionIDs: [ActionID],
    status: ExecutionUnitStatus,
    jitReport: JITRevalidationReport?,
    steps: [ExecutionStepOutcome]
  ) {
    self.id = id
    self.logicalActionIDs = logicalActionIDs
    self.prerequisiteActionIDs = prerequisiteActionIDs
    self.status = status
    self.jitReport = jitReport
    self.steps = steps
  }
}

public enum ApplyStartFailure: Equatable, Sendable {
  case authorizationAlreadyClaimed
  case invalidOverlay
  case manifestBindingMismatch
  case expired
  case invalidExecutionGraph
}

public struct AuditWriteFailure: Equatable, Sendable {
  public let eventIndex: Int
  public let code: String

  public init(eventIndex: Int, code: String) {
    self.eventIndex = eventIndex
    self.code = code
  }
}

public struct BestEffortApplyReport: Equatable, Sendable {
  public let manifest: ExecutionManifest?
  public let startFailure: ApplyStartFailure?
  public let unitOutcomes: [ExecutionUnitOutcome]
  public let auditFailures: [AuditWriteFailure]

  public var didStart: Bool { manifest != nil && startFailure == nil }

  public init(
    manifest: ExecutionManifest?,
    startFailure: ApplyStartFailure?,
    unitOutcomes: [ExecutionUnitOutcome],
    auditFailures: [AuditWriteFailure]
  ) {
    self.manifest = manifest
    self.startFailure = startFailure
    self.unitOutcomes = unitOutcomes
    self.auditFailures = auditFailures
  }
}

public enum ExecutionEvent: Equatable, Sendable {
  case applyStarted(epochID: String)
  case unitStarted(ExecutionUnitID)
  case forceRequiredWarning(ActionID)
  case stepFinished(ActionID, ExecutionStepStatus)
  case unitFinished(ExecutionUnitID, ExecutionUnitStatus)
  case auditWriteFailed(AuditWriteFailure)
  case applyFinished
}

public protocol ExecutionEventSink: Sendable {
  func emit(_ event: ExecutionEvent) async
}

public protocol ExecutionAuditSink: Sendable {
  func record(_ event: ExecutionEvent) async throws
}

public actor NoOpExecutionEventSink: ExecutionEventSink {
  public init() {}
  public func emit(_: ExecutionEvent) {}
}

/// The default sink keeps an observable shell transcript without requiring persistent storage.
public actor ShellExecutionEventSink: ExecutionEventSink {
  public init() {}

  public func emit(_ event: ExecutionEvent) {
    let line = "diskplan: \(Self.describe(event))\n"
    Data(line.utf8).withUnsafeBytes { bytes in
      guard let baseAddress = bytes.baseAddress else { return }
      _ = Darwin.write(STDERR_FILENO, baseAddress, bytes.count)
    }
  }

  private static func describe(_ event: ExecutionEvent) -> String {
    switch event {
    case .applyStarted(let epochID): return "apply-started epoch=\(epochID)"
    case .unitStarted(let id): return "unit-started id=\(unitLabel(id))"
    case .forceRequiredWarning(let actionID):
      return "force-required action=\(actionID.hex)"
    case .stepFinished(let actionID, let status):
      return "step-finished action=\(actionID.hex) status=\(status.rawValue)"
    case .unitFinished(let id, let status):
      return "unit-finished id=\(unitLabel(id)) status=\(status.rawValue)"
    case .auditWriteFailed(let failure):
      return "audit-write-failed event=\(failure.eventIndex) code=\(failure.code)"
    case .applyFinished: return "apply-finished"
    }
  }

  private static func unitLabel(_ id: ExecutionUnitID) -> String {
    switch id {
    case .action(let actionID): return actionID.hex
    case .compoundRelease(let groups): return groups.joined(separator: ",")
    }
  }
}
