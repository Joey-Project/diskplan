import Darwin
import DiskplanPolicy
import Foundation

struct JITRevalidationRequest: Equatable, Sendable {
  let plan: ImmutablePlan
  let validatedOverlay: ValidatedDecisionOverlay
  let manifest: ExecutionManifest
  let actionIDs: [ActionID]
  let releaseGroupIDs: [String]
  let authorizationCurrentBindingHash: PolicyDigest
  let preparationGeneration: UInt64
  let oneShotNonce: Data

  var epoch: ExecutionEpochContext { manifest.epoch }

  init(
    plan: ImmutablePlan,
    validatedOverlay: ValidatedDecisionOverlay,
    manifest: ExecutionManifest,
    actionIDs: [ActionID],
    releaseGroupIDs: [String],
    preparationGeneration: UInt64,
    oneShotNonce: Data
  ) {
    self.plan = plan
    self.validatedOverlay = validatedOverlay
    self.manifest = manifest
    self.actionIDs = actionIDs
    self.releaseGroupIDs = releaseGroupIDs
    self.authorizationCurrentBindingHash = manifest.currentBindingHash
    self.preparationGeneration = preparationGeneration
    self.oneShotNonce = oneShotNonce
  }
}

struct JITRevalidationSnapshot: Equatable, Sendable {
  let oneShotNonce: Data
  let authorizationCurrentBindingHash: PolicyDigest
  let preparationGeneration: UInt64
  let epochID: String
  let snapshot: CurrentRevalidationSnapshot
}

/// A read-only collector used at the last possible boundary before one execution unit.
protocol JITRevalidationEvidenceSource: Sendable {
  func collectJITEvidence(for request: JITRevalidationRequest) async throws
    -> JITRevalidationSnapshot

  func collectReleasePostVerification(
    for request: ReleasePostVerificationRequest
  ) async throws -> [CurrentReleasePostcondition]

  /// Recollects the selected protected properties through descriptors held by the adapter.
  /// Implementations must not resolve the target through an unbound absolute pathname.
  func collectFinalDescriptorEvidence(
    for request: FinalDescriptorPreflightRequest
  ) async throws -> FinalDescriptorEvidenceSnapshot
}

struct ReleasePostVerificationRequest: Equatable, Sendable {
  let plan: ImmutablePlan
  let manifest: ExecutionManifest
  let allocationGroupIDs: [String]

  static func == (lhs: Self, rhs: Self) -> Bool {
    lhs.plan == rhs.plan
      && lhs.manifest == rhs.manifest
      && lhs.allocationGroupIDs.map(RawUTF8Key.init)
        == rhs.allocationGroupIDs.map(RawUTF8Key.init)
  }
}

struct CurrentReleasePostcondition: Equatable, Sendable {
  let allocationGroupID: String
  let released: Observation<Bool>

  static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.allocationGroupID) == RawUTF8Key(rhs.allocationGroupID)
      && lhs.released == rhs.released
  }
}

public struct JITRevalidationReport: Equatable, Sendable {
  public let captureID: PolicyDigest?
  public let oneShotNonce: Data
  public let actionOutcomes: [ActionRevalidationOutcome]
  public let globalFindings: [RevalidationFinding]

  public var isCurrent: Bool {
    captureID != nil && actionOutcomes.allSatisfy(\.isCurrent) && globalFindings.isEmpty
  }

  public init(
    captureID: PolicyDigest?,
    oneShotNonce: Data,
    actionOutcomes: [ActionRevalidationOutcome],
    globalFindings: [RevalidationFinding]
  ) {
    self.captureID = captureID
    self.oneShotNonce = oneShotNonce
    self.actionOutcomes = actionOutcomes
    self.globalFindings = globalFindings
  }
}

public enum ExecutionUnitID: Equatable, Hashable, Sendable {
  case action(ActionID)
  case compoundRelease([String])

  public static func == (lhs: Self, rhs: Self) -> Bool {
    switch (lhs, rhs) {
    case (.action(let left), .action(let right)):
      left == right
    case (.compoundRelease(let left), .compoundRelease(let right)):
      left.map(RawUTF8Key.init) == right.map(RawUTF8Key.init)
    default:
      false
    }
  }

  public func hash(into hasher: inout Hasher) {
    switch self {
    case .action(let actionID):
      hasher.combine(0 as UInt8)
      hasher.combine(actionID)
    case .compoundRelease(let groupIDs):
      hasher.combine(1 as UInt8)
      hasher.combine(groupIDs.count)
      for groupID in groupIDs { hasher.combine(RawUTF8Key(groupID)) }
    }
  }
}

public struct BoundMutationTarget: Equatable, Sendable {
  public let actionID: ActionID
  public let rawRoot: RawRootPath
  public let targetPath: RawTargetPath
  public let expectedIdentity: ObjectIdentity
  public let expectedRootIdentity: ObjectIdentity
  public let expectedRootSeal: NamespaceSealEvidence
  public let expectedParentIdentities: [ObjectIdentity]
  public let expectedParentSeals: [NamespaceSealEvidence]
  public let expectedTargetAccessPolicy: RequiredAccessPolicyBaseline
  public let expectedContent: ContentProtectionBaseline
  public let postcondition: ActionPostcondition

  public init(action: ActionDefinition) {
    let namespace = action.prototype.namespaceBinding
    actionID = action.id
    rawRoot = namespace.rawRoot
    targetPath = namespace.targetPath
    expectedIdentity = action.prototype.targetIdentity
    expectedRootIdentity = namespace.rootIdentity
    expectedRootSeal = namespace.rootSeal
    expectedParentIdentities = namespace.parentChain.map(\.identity)
    expectedParentSeals = namespace.parentChain.map(\.seal)
    expectedTargetAccessPolicy = action.prototype.protectedProperties.accessPolicy.requiredBaseline
    expectedContent = action.prototype.protectedProperties.content.expectedBaseline
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
  public let exitStatus: Int32?
  public let terminatingSignal: Int32?

  public init(
    code: String,
    errno: Int32? = nil,
    exitStatus: Int32? = nil,
    terminatingSignal: Int32? = nil
  ) {
    self.code = code
    self.errno = errno
    self.exitStatus = exitStatus
    self.terminatingSignal = terminatingSignal
  }
}

public enum AdapterOperationOutcome: Equatable, Sendable {
  case succeeded(detailCode: String)
  case failed(ExecutionAdapterFailure)
  case cancelled
  case timedOut
  case notStarted(ExecutionNotStartedReason)
}

/// One adapter invocation's mutation result. The disposition belongs to this exact invocation;
/// callers must not recover it later through an action-keyed cache.
public struct AdapterOperationResult: Equatable, Sendable {
  public let outcome: AdapterOperationOutcome
  public let mutationDisposition: ExecutionMutationDisposition?
  public let cleanupDisposition: ExecutionCleanupDisposition?
  let gitWorktreePostVerificationBinding: GitWorktreePostVerificationNamespaceBinding?

  public init(
    outcome: AdapterOperationOutcome,
    mutationDisposition: ExecutionMutationDisposition? = nil,
    cleanupDisposition: ExecutionCleanupDisposition? = nil
  ) {
    self.outcome = outcome
    self.mutationDisposition = mutationDisposition
    self.cleanupDisposition = cleanupDisposition
    self.gitWorktreePostVerificationBinding = nil
  }

  init(
    outcome: AdapterOperationOutcome,
    mutationDisposition: ExecutionMutationDisposition?,
    cleanupDisposition: ExecutionCleanupDisposition?,
    gitWorktreePostVerificationBinding: GitWorktreePostVerificationNamespaceBinding?
  ) {
    self.outcome = outcome
    self.mutationDisposition = mutationDisposition
    self.cleanupDisposition = cleanupDisposition
    self.gitWorktreePostVerificationBinding = gitWorktreePostVerificationBinding
  }
}

/// Adapter-specific recovery information surfaced through the ordinary step/event/report path.
public enum ExecutionMutationDisposition: Equatable, Sendable {
  case gitWorktree(GitWorktreeMutationDisposition)
}

/// Cleanup information that is orthogonal to the mutation's primary outcome.
public enum ExecutionCleanupDisposition: Equatable, Sendable {
  case gitWorktreeAttemptDirectory(GitWorktreeAttemptCleanupDisposition)
}

public enum ExecutionNotStartedReason: String, Equatable, Sendable {
  case taskCancelled
  case epochExpired
  case preparationSuperseded
  case prerequisiteFailed
}

public enum PostVerificationOutcome: Equatable, Sendable {
  case satisfied
  case expectedResidual(ExecutionAdapterFailure)
  case missing
  case notSatisfied(code: String)
  case unknown(UnknownReason)
  case unreadable(ObservationFailure)
  case failed(ObservationFailure)
}

struct FinalDescriptorPreflightRequest: Sendable {
  let target: BoundMutationTarget
  let rootDescriptor: Int32
  let parentDescriptors: [Int32]
  let targetDescriptor: Int32
  let rawLeafName: Data
}

struct FinalDescriptorEvidenceSnapshot: Equatable, Sendable {
  let targetIdentity: Observation<ObjectIdentity>
  let targetAccessPolicy: Observation<RequiredAccessPolicyBaseline>
  let targetContent: Observation<ContentProtectionBaseline>
  let root: CurrentNamespaceComponent
  let parents: [CurrentNamespaceComponent]
}

enum FinalDescriptorPreflightOutcome: Equatable, Sendable {
  case verified
  case missing
  case unreadable(ObservationFailure)
  case failed(ObservationFailure)
  case identityMismatch
  case contentMismatch
  case accessPolicyMismatch
  case namespaceIdentityMismatch
  case namespaceAccessPolicyMismatch
}

public struct MutationExecutionContext: Sendable {
  public let deadlineSeconds: Int64
  let nowSeconds: @Sendable () -> Int64
  let finalDescriptorPreflight:
    @Sendable (FinalDescriptorPreflightRequest) async -> FinalDescriptorPreflightOutcome

  init(
    deadlineSeconds: Int64,
    nowSeconds: @escaping @Sendable () -> Int64,
    finalDescriptorPreflight:
      @escaping @Sendable (FinalDescriptorPreflightRequest) async
      -> FinalDescriptorPreflightOutcome
  ) {
    self.deadlineSeconds = deadlineSeconds
    self.nowSeconds = nowSeconds
    self.finalDescriptorPreflight = finalDescriptorPreflight
  }

  var isExpired: Bool { nowSeconds() >= deadlineSeconds }
}

public protocol ExecutionMutationAdapter: Sendable {
  func apply(
    _ operation: ExecutionAdapterOperation,
    context: MutationExecutionContext
  ) async -> AdapterOperationOutcome
  func postverify(_ operation: ExecutionAdapterOperation) async -> PostVerificationOutcome

  /// Returns the outcome and any recovery disposition as one attempt-scoped value.
  func applyResult(
    _ operation: ExecutionAdapterOperation,
    context: MutationExecutionContext
  ) async -> AdapterOperationResult

  /// Post-verifies against the result of the exact adapter invocation being reported.
  func postverify(
    _ operation: ExecutionAdapterOperation,
    result: AdapterOperationResult
  ) async -> PostVerificationOutcome
}

extension ExecutionMutationAdapter {
  public func applyResult(
    _ operation: ExecutionAdapterOperation,
    context: MutationExecutionContext
  ) async -> AdapterOperationResult {
    AdapterOperationResult(outcome: await apply(operation, context: context))
  }

  public func postverify(
    _ operation: ExecutionAdapterOperation,
    result _: AdapterOperationResult
  ) async -> PostVerificationOutcome {
    await postverify(operation)
  }
}

public enum ExecutionStepStatus: String, Equatable, Sendable {
  case succeeded
  case partiallySucceeded
  case failed
  case cancelled
  case expired
  case superseded
  case skippedPrerequisite
}

public struct ExecutionStepOutcome: Equatable, Sendable {
  public let actionID: ActionID
  public let status: ExecutionStepStatus
  public let adapterOutcome: AdapterOperationOutcome
  public let mutationDisposition: ExecutionMutationDisposition?
  public let cleanupDisposition: ExecutionCleanupDisposition?
  public let postVerification: PostVerificationOutcome

  public init(
    actionID: ActionID,
    status: ExecutionStepStatus,
    adapterOutcome: AdapterOperationOutcome,
    mutationDisposition: ExecutionMutationDisposition? = nil,
    cleanupDisposition: ExecutionCleanupDisposition? = nil,
    postVerification: PostVerificationOutcome
  ) {
    self.actionID = actionID
    self.status = status
    self.adapterOutcome = adapterOutcome
    self.mutationDisposition = mutationDisposition
    self.cleanupDisposition = cleanupDisposition
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
  case superseded
}

public struct ExecutionUnitOutcome: Equatable, Sendable {
  public let id: ExecutionUnitID
  public let logicalActionIDs: [ActionID]
  public let prerequisiteActionIDs: [ActionID]
  public let status: ExecutionUnitStatus
  public let jitReport: JITRevalidationReport?
  public let steps: [ExecutionStepOutcome]
  public let releasePostVerification: [ReleasePostVerificationOutcome]

  public init(
    id: ExecutionUnitID,
    logicalActionIDs: [ActionID],
    prerequisiteActionIDs: [ActionID],
    status: ExecutionUnitStatus,
    jitReport: JITRevalidationReport?,
    steps: [ExecutionStepOutcome],
    releasePostVerification: [ReleasePostVerificationOutcome] = []
  ) {
    self.id = id
    self.logicalActionIDs = logicalActionIDs
    self.prerequisiteActionIDs = prerequisiteActionIDs
    self.status = status
    self.jitReport = jitReport
    self.steps = steps
    self.releasePostVerification = releasePostVerification
  }
}

public struct ReleasePostVerificationOutcome: Equatable, Sendable {
  public let allocationGroupID: String
  public let outcome: PostVerificationOutcome

  public init(allocationGroupID: String, outcome: PostVerificationOutcome) {
    self.allocationGroupID = allocationGroupID
    self.outcome = outcome
  }

  public static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.allocationGroupID) == RawUTF8Key(rhs.allocationGroupID)
      && lhs.outcome == rhs.outcome
  }
}

public enum ApplyStartFailure: Equatable, Sendable {
  case authorizationAlreadyClaimed
  case invalidOverlay
  case manifestBindingMismatch
  case expired
  case invalidExecutionGraph
  case preparationSuperseded
  case forceConfirmationBindingMismatch
}

public struct AuditWriteFailure: Equatable, Sendable {
  public let eventIndex: Int
  public let code: String
  public let errno: Int32?
  public let retainedLocator: ArtifactRecoveryLocator?

  public init(
    eventIndex: Int,
    code: String,
    errno: Int32? = nil,
    retainedLocator: ArtifactRecoveryLocator? = nil
  ) {
    self.eventIndex = eventIndex
    self.code = code
    self.errno = errno
    self.retainedLocator = retainedLocator
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
  case stepFinished(ExecutionStepOutcome)
  case releasePostVerificationFinished(ReleasePostVerificationOutcome)
  case unitFinished(ExecutionUnitOutcome)
  case auditWriteFailed(AuditWriteFailure)
  case applyFinished
}

public protocol ExecutionEventSink: Sendable {
  func emit(_ event: ExecutionEvent) async
}

public protocol ExecutionAuditSink: Sendable {
  func record(_ event: ExecutionEvent, epochID: String) async throws
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
    case .stepFinished(let outcome):
      return
        "step-finished action=\(outcome.actionID.hex) status=\(outcome.status.rawValue) adapter=\(adapterLabel(outcome.adapterOutcome)) disposition=\(dispositionLabel(outcome.mutationDisposition)) cleanup=\(cleanupDispositionLabel(outcome.cleanupDisposition)) postverify=\(postverifyLabel(outcome.postVerification))"
    case .releasePostVerificationFinished(let outcome):
      return
        "release-postverify group=\(outcome.allocationGroupID) outcome=\(postverifyLabel(outcome.outcome))"
    case .unitFinished(let outcome):
      return "unit-finished id=\(unitLabel(outcome.id)) status=\(outcome.status.rawValue)"
    case .auditWriteFailed(let failure):
      let retained =
        failure.retainedLocator == nil
        ? "" : " retained-artifact=true revalidate-required=true"
      return "audit-write-failed event=\(failure.eventIndex) code=\(failure.code)\(retained)"
    case .applyFinished: return "apply-finished"
    }
  }

  private static func unitLabel(_ id: ExecutionUnitID) -> String {
    switch id {
    case .action(let actionID): return actionID.hex
    case .compoundRelease(let groups): return groups.joined(separator: ",")
    }
  }

  private static func adapterLabel(_ outcome: AdapterOperationOutcome) -> String {
    switch outcome {
    case .succeeded(let detailCode): return "succeeded:\(detailCode)"
    case .failed(let failure): return "failed:\(failure.code)"
    case .cancelled: return "cancelled"
    case .timedOut: return "timed-out"
    case .notStarted(let reason): return "not-started:\(reason.rawValue)"
    }
  }

  private static func dispositionLabel(_ disposition: ExecutionMutationDisposition?) -> String {
    guard let disposition else { return "none" }
    switch disposition {
    case .gitWorktree(let disposition):
      switch disposition {
      case .removed: return "git-worktree:removed"
      case .localChangesDiscarded: return "git-worktree:local-changes-discarded"
      case .restoredAfterVerificationFailure(let code):
        return "git-worktree:restored:\(code)"
      case .quarantineRetained(_, let failureCode):
        return "git-worktree:quarantine-retained:\(failureCode)"
      case .quarantineBindingUnverified(let failureCode):
        return "git-worktree:quarantine-binding-unverified:\(failureCode)"
      case .removedWithAdministrativeResidual(let residual):
        return "git-worktree:administrative-residual:\(residual.failure.code)"
      }
    }
  }

  private static func cleanupDispositionLabel(
    _ disposition: ExecutionCleanupDisposition?
  ) -> String {
    guard let disposition else { return "none" }
    switch disposition {
    case .gitWorktreeAttemptDirectory(let value):
      switch value {
      case .retained(_, let failure):
        return "git-worktree:attempt-directory-retained:\(failure.code)"
      case .bindingUnverified(let failure):
        return "git-worktree:attempt-directory-binding-unverified:\(failure.code)"
      }
    }
  }

  private static func postverifyLabel(_ outcome: PostVerificationOutcome) -> String {
    switch outcome {
    case .satisfied: return "satisfied"
    case .expectedResidual(let failure): return "expected-residual:\(failure.code)"
    case .missing: return "missing"
    case .notSatisfied(let code): return "not-satisfied:\(code)"
    case .unknown(let reason): return "unknown:\(String(describing: reason))"
    case .unreadable(let failure): return "unreadable:\(failure.code)"
    case .failed(let failure): return "failed:\(failure.code)"
    }
  }
}
