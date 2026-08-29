import DiskplanPolicy
import Foundation

struct RawUTF8Key: Equatable, Hashable, Comparable, Sendable {
  let bytes: Data

  init(_ value: String) { bytes = Data(value.utf8) }

  static func < (lhs: Self, rhs: Self) -> Bool {
    lhs.bytes.lexicographicallyPrecedes(rhs.bytes)
  }
}

public enum PreparationMode: Equatable, Sendable {
  case dryRun
  case apply
}

struct CurrentNamespaceComponent: Equatable, Sendable {
  let relativePath: RawTargetPath?
  let identity: Observation<ObjectIdentity>
  let seal: Observation<NamespaceSealEvidence>
}

/// A collector result containing only properties selected by the immutable action contract.
/// Timestamps and directory-entry metadata are deliberately absent.
struct CurrentActionEvidence: Equatable, Sendable {
  let actionID: ActionID
  let targetIdentity: Observation<ObjectIdentity>
  let targetContent: Observation<ContentProtectionBaseline>
  let targetAccessPolicy: Observation<RequiredAccessPolicyBaseline>
  let coverage: Observation<EvidenceCoverage>
  let collectorStatus: Observation<CollectorCompletionState>
  let activity: Observation<ActivityState>
  let explicitProtection: Observation<ExplicitProtectionState>
  let providerState: Observation<ProviderState>
  let recoverability: Observation<RecoverabilityState>
  let dependencyState: Observation<DependencyState>
  let freshPolicyEvidence: Observation<FreshPolicyEvidence>
  let root: CurrentNamespaceComponent
  let parents: [CurrentNamespaceComponent]
  let gitWorktree: Observation<GitWorktreeEvidence>

  init(
    actionID: ActionID,
    targetIdentity: Observation<ObjectIdentity>,
    targetContent: Observation<ContentProtectionBaseline>,
    targetAccessPolicy: Observation<RequiredAccessPolicyBaseline>,
    coverage: Observation<EvidenceCoverage>,
    collectorStatus: Observation<CollectorCompletionState>,
    activity: Observation<ActivityState>,
    explicitProtection: Observation<ExplicitProtectionState>,
    providerState: Observation<ProviderState>,
    recoverability: Observation<RecoverabilityState>,
    dependencyState: Observation<DependencyState>,
    freshPolicyEvidence: Observation<FreshPolicyEvidence>,
    root: CurrentNamespaceComponent,
    parents: [CurrentNamespaceComponent],
    gitWorktree: Observation<GitWorktreeEvidence> = .absent
  ) {
    self.actionID = actionID
    self.targetIdentity = targetIdentity
    self.targetContent = targetContent
    self.targetAccessPolicy = targetAccessPolicy
    self.coverage = coverage
    self.collectorStatus = collectorStatus
    self.activity = activity
    self.explicitProtection = explicitProtection
    self.providerState = providerState
    self.recoverability = recoverability
    self.dependencyState = dependencyState
    self.freshPolicyEvidence = freshPolicyEvidence
    self.root = root
    self.parents = parents
    self.gitWorktree = gitWorktree
  }
}

struct FreshPolicyEvidence: Equatable, Sendable {
  let evidence: FrozenEvidenceSnapshot
  let globalFacts: FrozenGlobalFacts
}

struct CurrentReleaseTopology: Equatable, Sendable {
  let allocationGroupID: String
  let topology: Observation<ReleaseTopologyExpectation>

  static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.allocationGroupID) == RawUTF8Key(rhs.allocationGroupID)
      && lhs.topology == rhs.topology
  }
}

struct CurrentPlanInvariants: Equatable, Sendable {
  let duplicateSurvivorsPreserved: Observation<Bool>
  let terminalNamespacesExclusive: Observation<Bool>
}

struct CurrentRevalidationSnapshot: Equatable, Sendable {
  let captureID: PolicyDigest
  let actions: [CurrentActionEvidence]
  let releaseTopologies: [CurrentReleaseTopology]
  let invariants: CurrentPlanInvariants
}

struct RevalidationRequest: Equatable, Sendable {
  let plan: ImmutablePlan
  let validatedOverlay: ValidatedDecisionOverlay
  let epoch: ExecutionEpochContext
}

/// Read-only collection boundary. Implementations must not expose mutation adapters.
protocol RevalidationEvidenceSource: Sendable {
  func collectCurrentEvidence(for request: RevalidationRequest) async throws
    -> CurrentRevalidationSnapshot
}

/// The only production collector accepted by `ExecutionPreparationEngine`.
/// Its factory is internal; the engine SPI exposes only the sealed collector handle.
@_spi(DiskplanEngine) public final class EngineRevalidationCollector: @unchecked Sendable {
  private let collectCurrent:
    @Sendable (RevalidationRequest) async throws
      -> CurrentRevalidationSnapshot
  private let collectJIT:
    @Sendable (JITRevalidationRequest) async throws
      -> JITRevalidationSnapshot
  private let collectReleasePostconditions:
    @Sendable (ReleasePostVerificationRequest) async throws
      -> [CurrentReleasePostcondition]
  private let collectFinalDescriptors:
    @Sendable (FinalDescriptorPreflightRequest) async throws
      -> FinalDescriptorEvidenceSnapshot

  init(
    collect:
      @escaping @Sendable (RevalidationRequest) async throws
      -> CurrentRevalidationSnapshot
  ) {
    self.collectCurrent = collect
    self.collectJIT = { _ in throw EngineCollectorError.jitUnavailable }
    self.collectReleasePostconditions = { _ in
      throw EngineCollectorError.releasePostVerificationUnavailable
    }
    self.collectFinalDescriptors = { _ in
      throw EngineCollectorError.finalDescriptorPreflightUnavailable
    }
  }

  init(
    collectCurrent:
      @escaping @Sendable (RevalidationRequest) async throws
      -> CurrentRevalidationSnapshot,
    collectJIT:
      @escaping @Sendable (JITRevalidationRequest) async throws
      -> JITRevalidationSnapshot,
    collectReleasePostconditions:
      @escaping @Sendable (ReleasePostVerificationRequest) async throws
      -> [CurrentReleasePostcondition],
    collectFinalDescriptors:
      @escaping @Sendable (FinalDescriptorPreflightRequest) async throws
      -> FinalDescriptorEvidenceSnapshot
  ) {
    self.collectCurrent = collectCurrent
    self.collectJIT = collectJIT
    self.collectReleasePostconditions = collectReleasePostconditions
    self.collectFinalDescriptors = collectFinalDescriptors
  }

  init(
    currentSource: any RevalidationEvidenceSource,
    jitSource: (any JITRevalidationEvidenceSource)? = nil
  ) {
    self.collectCurrent = { request in
      try await currentSource.collectCurrentEvidence(for: request)
    }
    self.collectJIT = { request in
      guard let jitSource else { throw EngineCollectorError.jitUnavailable }
      return try await jitSource.collectJITEvidence(for: request)
    }
    self.collectReleasePostconditions = { request in
      guard let jitSource else {
        throw EngineCollectorError.releasePostVerificationUnavailable
      }
      return try await jitSource.collectReleasePostVerification(for: request)
    }
    self.collectFinalDescriptors = { request in
      guard let jitSource else {
        throw EngineCollectorError.finalDescriptorPreflightUnavailable
      }
      return try await jitSource.collectFinalDescriptorEvidence(for: request)
    }
  }

  func collectCurrentEvidence(for request: RevalidationRequest) async throws
    -> CurrentRevalidationSnapshot
  {
    try await collectCurrent(request)
  }

  func collectJITEvidence(for request: JITRevalidationRequest) async throws
    -> JITRevalidationSnapshot
  {
    try await collectJIT(request)
  }

  func collectReleasePostVerification(
    for request: ReleasePostVerificationRequest
  ) async throws -> [CurrentReleasePostcondition] {
    try await collectReleasePostconditions(request)
  }

  func finalDescriptorPreflight(
    for request: FinalDescriptorPreflightRequest
  ) async -> FinalDescriptorPreflightOutcome {
    do {
      let snapshot = try await collectFinalDescriptors(request)
      return Self.evaluateFinalDescriptorEvidence(snapshot, target: request.target)
    } catch is CancellationError {
      return .failed(
        ObservationFailure(
          code: "cancelled", collector: "final-descriptor-revalidation-source"))
    } catch {
      return .failed(
        ObservationFailure(
          code: String(reflecting: type(of: error)),
          collector: "final-descriptor-revalidation-source"
        ))
    }
  }

  static func evaluateFinalDescriptorEvidence(
    _ snapshot: FinalDescriptorEvidenceSnapshot,
    target: BoundMutationTarget
  ) -> FinalDescriptorPreflightOutcome {
    switch snapshot.targetIdentity {
    case .absent: return .missing
    case .unknown(let reason):
      return .failed(
        ObservationFailure(
          code: "unknown-\(String(describing: reason))",
          collector: "final-descriptor-revalidation-source"))
    case .unreadable(let failure): return .unreadable(failure)
    case .failed(let failure): return .failed(failure)
    case .known(let identity):
      guard identity == target.expectedIdentity else { return .identityMismatch }
    }
    switch snapshot.targetAccessPolicy {
    case .known(let baseline):
      guard baseline == target.expectedTargetAccessPolicy else {
        return .accessPolicyMismatch
      }
    case .unreadable(let failure): return .unreadable(failure)
    case .failed(let failure): return .failed(failure)
    case .absent, .unknown: return .accessPolicyMismatch
    }
    switch snapshot.targetContent {
    case .known(let baseline):
      guard baseline == target.expectedContent else { return .contentMismatch }
    case .unreadable(let failure): return .unreadable(failure)
    case .failed(let failure): return .failed(failure)
    case .absent, .unknown: return .contentMismatch
    }
    guard snapshot.root.relativePath == nil else { return .namespaceIdentityMismatch }
    switch snapshot.root.identity {
    case .known(let identity):
      guard identity == target.expectedRootIdentity else {
        return .namespaceIdentityMismatch
      }
    case .unreadable(let failure): return .unreadable(failure)
    case .failed(let failure): return .failed(failure)
    case .absent, .unknown: return .namespaceIdentityMismatch
    }
    switch snapshot.root.seal {
    case .known(let seal):
      guard seal == target.expectedRootSeal else {
        return .namespaceAccessPolicyMismatch
      }
    case .unreadable(let failure): return .unreadable(failure)
    case .failed(let failure): return .failed(failure)
    case .absent, .unknown: return .namespaceAccessPolicyMismatch
    }
    guard snapshot.parents.count == target.expectedParentIdentities.count,
      snapshot.parents.count == target.expectedParentSeals.count
    else { return .namespaceIdentityMismatch }
    for (index, parent) in snapshot.parents.enumerated() {
      let expectedPath = try? RawTargetPath(
        components: Array(target.targetPath.components.prefix(index + 1)))
      guard parent.relativePath == expectedPath else { return .namespaceIdentityMismatch }
      switch parent.identity {
      case .known(let identity):
        guard identity == target.expectedParentIdentities[index] else {
          return .namespaceIdentityMismatch
        }
      case .unreadable(let failure): return .unreadable(failure)
      case .failed(let failure): return .failed(failure)
      case .absent, .unknown: return .namespaceIdentityMismatch
      }
      switch parent.seal {
      case .known(let seal):
        guard seal == target.expectedParentSeals[index] else {
          return .namespaceAccessPolicyMismatch
        }
      case .unreadable(let failure): return .unreadable(failure)
      case .failed(let failure): return .failed(failure)
      case .absent, .unknown: return .namespaceAccessPolicyMismatch
      }
    }
    return .verified
  }
}

extension EngineRevalidationCollector: RevalidationEvidenceSource {}

private enum EngineCollectorError: Error {
  case jitUnavailable
  case releasePostVerificationUnavailable
  case finalDescriptorPreflightUnavailable
}

public enum RevalidationFailureKind: String, CaseIterable, Equatable, Hashable, Sendable {
  case missing
  case unknown
  case unreadable
  case collectionFailed
  case cancelled
  case identityMismatch
  case contentMismatch
  case accessPolicyMismatch
  case namespaceIdentityMismatch
  case namespaceAccessPolicyMismatch
  case coverageMismatch
  case activityMismatch
  case protectionMismatch
  case providerMismatch
  case recoverabilityMismatch
  case dependencyMismatch
  case gitPrerequisiteMismatch
  case releaseTopologyMismatch
  case survivorInvariantViolated
  case terminalNamespaceInvariantViolated
  case incompleteCompoundReleaseUnit
  case duplicateObservation
  case unexpectedObservation
  case policyEvidenceMismatch
  case policyThresholdCrossed
  case staleConsent
}

public enum RevalidationSubject: Equatable, Sendable {
  case targetIdentity
  case targetContent
  case targetAccessPolicy
  case coverage
  case collectorStatus
  case activity
  case explicitProtection
  case providerState
  case recoverability
  case dependency
  case rootIdentity
  case rootAccessPolicy
  case parentIdentity(RawTargetPath)
  case parentAccessPolicy(RawTargetPath)
  case gitPrerequisites
  case releaseTopology(String)
  case duplicateSurvivors
  case terminalNamespaces
  case compoundReleaseUnit([String])
  case collector
  case policyEvidence
  case waiverConsent(WaiverKind)

  public static func == (lhs: Self, rhs: Self) -> Bool {
    switch (lhs, rhs) {
    case (.targetIdentity, .targetIdentity),
      (.targetContent, .targetContent),
      (.targetAccessPolicy, .targetAccessPolicy),
      (.coverage, .coverage),
      (.collectorStatus, .collectorStatus),
      (.activity, .activity),
      (.explicitProtection, .explicitProtection),
      (.providerState, .providerState),
      (.recoverability, .recoverability),
      (.dependency, .dependency),
      (.rootIdentity, .rootIdentity),
      (.rootAccessPolicy, .rootAccessPolicy),
      (.gitPrerequisites, .gitPrerequisites),
      (.duplicateSurvivors, .duplicateSurvivors),
      (.terminalNamespaces, .terminalNamespaces),
      (.collector, .collector),
      (.policyEvidence, .policyEvidence):
      true
    case (.parentIdentity(let left), .parentIdentity(let right)),
      (.parentAccessPolicy(let left), .parentAccessPolicy(let right)):
      left == right
    case (.releaseTopology(let left), .releaseTopology(let right)):
      RawUTF8Key(left) == RawUTF8Key(right)
    case (.compoundReleaseUnit(let left), .compoundReleaseUnit(let right)):
      left.map(RawUTF8Key.init) == right.map(RawUTF8Key.init)
    case (.waiverConsent(let left), .waiverConsent(let right)):
      left == right
    default:
      false
    }
  }
}

public struct RevalidationFinding: Equatable, Sendable {
  public let actionID: ActionID?
  public let subject: RevalidationSubject
  public let kind: RevalidationFailureKind
  public let observationFailure: ObservationFailure?
  public let unknownReason: UnknownReason?

  public init(
    actionID: ActionID?,
    subject: RevalidationSubject,
    kind: RevalidationFailureKind,
    observationFailure: ObservationFailure? = nil,
    unknownReason: UnknownReason? = nil
  ) {
    self.actionID = actionID
    self.subject = subject
    self.kind = kind
    self.observationFailure = observationFailure
    self.unknownReason = unknownReason
  }
}

public struct ActionRevalidationOutcome: Equatable, Sendable {
  public let actionID: ActionID
  public let findings: [RevalidationFinding]
  public var isCurrent: Bool { findings.isEmpty }

  public init(actionID: ActionID, findings: [RevalidationFinding]) {
    self.actionID = actionID
    self.findings = findings
  }
}

public struct CompoundReleaseUnit: Equatable, Sendable {
  public let allocationGroupIDs: [String]
  public let ownerActionIDs: [ActionID]

  public init(allocationGroupIDs: [String], ownerActionIDs: [ActionID]) {
    self.allocationGroupIDs = allocationGroupIDs
    self.ownerActionIDs = ownerActionIDs
  }

  public static func == (lhs: Self, rhs: Self) -> Bool {
    lhs.allocationGroupIDs.map(RawUTF8Key.init)
      == rhs.allocationGroupIDs.map(RawUTF8Key.init)
      && lhs.ownerActionIDs == rhs.ownerActionIDs
  }
}

public struct CurrentPolicyBinding: Equatable, Sendable {
  public let actionID: ActionID
  public let captureID: PolicyDigest
  public let evidenceID: PolicyDigest
  public let globalFactsHash: PolicyDigest
  public let requiredWaivers: [WaiverPredicate]

  public init(
    actionID: ActionID,
    captureID: PolicyDigest,
    evidenceID: PolicyDigest,
    globalFactsHash: PolicyDigest,
    requiredWaivers: [WaiverPredicate]
  ) {
    self.actionID = actionID
    self.captureID = captureID
    self.evidenceID = evidenceID
    self.globalFactsHash = globalFactsHash
    self.requiredWaivers = requiredWaivers
  }
}

public struct ExecutionConsentRequirement: Equatable, Sendable {
  public let consentHash: PolicyDigest
  public let actionID: ActionID
  public let planHash: PolicyDigest
  public let planEvidenceHash: PolicyDigest
  public let overlayHash: PolicyDigest
  public let originalSemanticReferenceTimeSeconds: Int64
  public let executionReferenceTimeSeconds: Int64
  public let currentEvidenceID: PolicyDigest
  public let currentGlobalFactsHash: PolicyDigest
  public let currentPredicate: WaiverPredicate

  public init(
    consentHash: PolicyDigest,
    actionID: ActionID,
    planHash: PolicyDigest,
    planEvidenceHash: PolicyDigest,
    overlayHash: PolicyDigest,
    originalSemanticReferenceTimeSeconds: Int64,
    executionReferenceTimeSeconds: Int64,
    currentEvidenceID: PolicyDigest,
    currentGlobalFactsHash: PolicyDigest,
    currentPredicate: WaiverPredicate
  ) {
    self.consentHash = consentHash
    self.actionID = actionID
    self.planHash = planHash
    self.planEvidenceHash = planEvidenceHash
    self.overlayHash = overlayHash
    self.originalSemanticReferenceTimeSeconds = originalSemanticReferenceTimeSeconds
    self.executionReferenceTimeSeconds = executionReferenceTimeSeconds
    self.currentEvidenceID = currentEvidenceID
    self.currentGlobalFactsHash = currentGlobalFactsHash
    self.currentPredicate = currentPredicate
  }
}

public struct ExecutionManifest: Equatable, Sendable {
  public let planHash: PolicyDigest
  public let overlayHash: PolicyDigest
  public let epoch: ExecutionEpochContext
  public let currentCaptureID: PolicyDigest
  public let executionActionIDs: [ActionID]
  public let jitRevalidationActionIDs: [[ActionID]]
  public let compoundReleaseUnits: [CompoundReleaseUnit]
  public let currentPolicyBindings: [CurrentPolicyBinding]
  public let consentRequirements: [ExecutionConsentRequirement]
  public let currentBindingHash: PolicyDigest

  public init(
    planHash: PolicyDigest,
    overlayHash: PolicyDigest,
    epoch: ExecutionEpochContext,
    currentCaptureID: PolicyDigest,
    executionActionIDs: [ActionID],
    jitRevalidationActionIDs: [[ActionID]],
    compoundReleaseUnits: [CompoundReleaseUnit],
    currentPolicyBindings: [CurrentPolicyBinding],
    consentRequirements: [ExecutionConsentRequirement],
    currentBindingHash: PolicyDigest
  ) {
    self.planHash = planHash
    self.overlayHash = overlayHash
    self.epoch = epoch
    self.currentCaptureID = currentCaptureID
    self.executionActionIDs = executionActionIDs
    self.jitRevalidationActionIDs = jitRevalidationActionIDs
    self.compoundReleaseUnits = compoundReleaseUnits
    self.currentPolicyBindings = currentPolicyBindings
    self.consentRequirements = consentRequirements
    self.currentBindingHash = currentBindingHash
  }
}

public struct RevalidationReport: Equatable, Sendable {
  public let planHash: PolicyDigest
  public let overlayHash: PolicyDigest
  public let epoch: ExecutionEpochContext
  public let actionOutcomes: [ActionRevalidationOutcome]
  public let globalFindings: [RevalidationFinding]
  public let manifest: ExecutionManifest?
  public var isCurrent: Bool {
    guard let manifest else { return false }
    return manifest.planHash == planHash
      && manifest.overlayHash == overlayHash
      && manifest.epoch == epoch
      && globalFindings.isEmpty
      && actionOutcomes.allSatisfy(\.isCurrent)
  }

  public init(
    planHash: PolicyDigest,
    overlayHash: PolicyDigest,
    epoch: ExecutionEpochContext,
    actionOutcomes: [ActionRevalidationOutcome],
    globalFindings: [RevalidationFinding],
    manifest: ExecutionManifest?
  ) {
    self.planHash = planHash
    self.overlayHash = overlayHash
    self.epoch = epoch
    self.actionOutcomes = actionOutcomes
    self.globalFindings = globalFindings
    self.manifest = manifest
  }
}

/// A dry-run result has no capability field and cannot be passed to apply authorization.
public struct DryRunReport: Equatable, Sendable {
  public let revalidation: RevalidationReport
  public let forceWarningActionIDs: [ActionID]

  public init(
    revalidation: RevalidationReport,
    forceWarningActionIDs: [ActionID] = []
  ) {
    self.revalidation = revalidation
    self.forceWarningActionIDs = forceWarningActionIDs
  }
}

public struct ApplyReadyReport: Equatable, Sendable {
  public let revalidation: RevalidationReport
  public let forceWarningActionIDs: [ActionID]
  public let reviewBindingHash: PolicyDigest

  public init(
    revalidation: RevalidationReport,
    forceWarningActionIDs: [ActionID] = [],
    reviewBindingHash: PolicyDigest? = nil
  ) {
    self.revalidation = revalidation
    self.forceWarningActionIDs = forceWarningActionIDs
    self.reviewBindingHash = reviewBindingHash ?? revalidation.overlayHash
  }
}

public struct ApplyReviewConfirmation: Equatable, Sendable {
  public let reviewBindingHash: PolicyDigest
  public let confirmedForceActionIDs: [ActionID]

  private init(
    reviewBindingHash: PolicyDigest,
    confirmedForceActionIDs: [ActionID]
  ) {
    self.reviewBindingHash = reviewBindingHash
    self.confirmedForceActionIDs = confirmedForceActionIDs
  }

  /// The frontend calls this only after rendering and confirming every force warning.
  public static func confirm(_ ready: ApplyReadyReport) -> Self {
    Self(
      reviewBindingHash: ready.reviewBindingHash,
      confirmedForceActionIDs: ready.forceWarningActionIDs
    )
  }
}

/// Opaque, registry-backed, non-Codable capability. Its bytes never leave this module.
public final class ApplyCapability: @unchecked Sendable {
  let opaqueBytes: Data
  init(opaqueBytes: Data) { self.opaqueBytes = opaqueBytes }
}

struct ClaimedApplyAuthorization: Sendable {
  let manifest: ExecutionManifest
  let collector: EngineRevalidationCollector
  let generation: UInt64
  let confirmedForceActionIDs: [ActionID]
  let generationIsCurrent: @Sendable () async -> Bool
}

enum ApplyAuthorizationClaimResult: Sendable {
  case claimed(ClaimedApplyAuthorization)
  case replayed
  case superseded
  case expired
  case bindingMismatch
}

public actor ApplyAuthorization {
  private var claim: (@Sendable () async -> ApplyAuthorizationClaimResult)?

  init(
    claim: @escaping @Sendable () async -> ApplyAuthorizationClaimResult
  ) {
    self.claim = claim
  }

  func claimForExecution() async -> ApplyAuthorizationClaimResult {
    guard let pendingClaim = claim else { return .replayed }
    claim = nil
    return await pendingClaim()
  }

  /// Phase 5 may claim the authorization once. A second claim is a replay and returns nil.
  public func claimManifest() async -> ExecutionManifest? {
    guard case .claimed(let candidate) = await claimForExecution() else { return nil }
    return candidate.manifest
  }
}

public enum PreparationResult: Sendable {
  case rejected(RevalidationReport)
  case dryRun(DryRunReport)
  case applyReady(ApplyReadyReport, ApplyCapability)
}

public enum ExecutionPreparationError: Error, Equatable {
  case invalidLifetime
  case entropyFailure
  case capabilityUnknown
  case capabilityExpired
  case capabilityBindingMismatch
  case applyReportNotCurrent
  case preparationSuperseded
  case generationExhausted
  case forceConfirmationRequired
  case forceConfirmationMismatch
}
