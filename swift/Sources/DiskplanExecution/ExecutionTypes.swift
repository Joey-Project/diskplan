import DiskplanPolicy
import Foundation

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
  private let collect:
    @Sendable (RevalidationRequest) async throws
      -> CurrentRevalidationSnapshot

  init(
    collect:
      @escaping @Sendable (RevalidationRequest) async throws
      -> CurrentRevalidationSnapshot
  ) {
    self.collect = collect
  }

  func collectCurrentEvidence(for request: RevalidationRequest) async throws
    -> CurrentRevalidationSnapshot
  {
    try await collect(request)
  }
}

extension EngineRevalidationCollector: RevalidationEvidenceSource {}

public enum RevalidationFailureKind: String, CaseIterable, Equatable, Hashable, Sendable {
  case missing
  case unknown
  case unreadable
  case collectionFailed
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
  public init(revalidation: RevalidationReport) { self.revalidation = revalidation }
}

public struct ApplyReadyReport: Equatable, Sendable {
  public let revalidation: RevalidationReport
}

/// Opaque, registry-backed, non-Codable capability. Its bytes never leave this module.
public final class ApplyCapability: @unchecked Sendable {
  let opaqueBytes: Data
  init(opaqueBytes: Data) { self.opaqueBytes = opaqueBytes }
}

public actor ApplyAuthorization {
  private var manifest: ExecutionManifest?

  init(manifest: ExecutionManifest) { self.manifest = manifest }

  /// Phase 5 may claim the authorization once. A second claim is a replay and returns nil.
  public func claimManifest() -> ExecutionManifest? {
    defer { manifest = nil }
    return manifest
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
}
