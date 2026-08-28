import DiskplanPolicy
import Foundation

public enum PreparationMode: Equatable, Sendable {
  case dryRun
  case apply
}

public struct CurrentNamespaceComponent: Equatable, Sendable {
  public let relativePath: RawTargetPath?
  public let identity: Observation<ObjectIdentity>
  public let seal: Observation<NamespaceSealEvidence>

  public init(
    relativePath: RawTargetPath?,
    identity: Observation<ObjectIdentity>,
    seal: Observation<NamespaceSealEvidence>
  ) {
    self.relativePath = relativePath
    self.identity = identity
    self.seal = seal
  }
}

/// A collector result containing only properties selected by the immutable action contract.
/// Timestamps and directory-entry metadata are deliberately absent.
public struct CurrentActionEvidence: Equatable, Sendable {
  public let actionID: ActionID
  public let targetIdentity: Observation<ObjectIdentity>
  public let targetContent: Observation<ContentProtectionBaseline>
  public let targetAccessPolicy: Observation<RequiredAccessPolicyBaseline>
  public let coverage: Observation<EvidenceCoverage>
  public let collectorStatus: Observation<CollectorCompletionState>
  public let activity: Observation<ActivityState>
  public let explicitProtection: Observation<ExplicitProtectionState>
  public let providerState: Observation<ProviderState>
  public let recoverability: Observation<RecoverabilityState>
  public let dependencyState: Observation<DependencyState>
  public let root: CurrentNamespaceComponent
  public let parents: [CurrentNamespaceComponent]
  public let gitWorktree: Observation<GitWorktreeEvidence>

  public init(
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
    self.root = root
    self.parents = parents
    self.gitWorktree = gitWorktree
  }
}

public struct CurrentReleaseTopology: Equatable, Sendable {
  public let allocationGroupID: String
  public let topology: Observation<ReleaseTopologyExpectation>

  public init(
    allocationGroupID: String,
    topology: Observation<ReleaseTopologyExpectation>
  ) {
    self.allocationGroupID = allocationGroupID
    self.topology = topology
  }
}

public struct CurrentPlanInvariants: Equatable, Sendable {
  public let duplicateSurvivorsPreserved: Observation<Bool>
  public let terminalNamespacesExclusive: Observation<Bool>

  public init(
    duplicateSurvivorsPreserved: Observation<Bool>,
    terminalNamespacesExclusive: Observation<Bool>
  ) {
    self.duplicateSurvivorsPreserved = duplicateSurvivorsPreserved
    self.terminalNamespacesExclusive = terminalNamespacesExclusive
  }
}

public struct CurrentRevalidationSnapshot: Equatable, Sendable {
  public let actions: [CurrentActionEvidence]
  public let releaseTopologies: [CurrentReleaseTopology]
  public let invariants: CurrentPlanInvariants

  public init(
    actions: [CurrentActionEvidence],
    releaseTopologies: [CurrentReleaseTopology],
    invariants: CurrentPlanInvariants
  ) {
    self.actions = actions
    self.releaseTopologies = releaseTopologies
    self.invariants = invariants
  }
}

public struct RevalidationRequest: Equatable, Sendable {
  public let plan: ImmutablePlan
  public let validatedOverlay: ValidatedDecisionOverlay
  public let epoch: ExecutionEpochContext

  public init(
    plan: ImmutablePlan,
    validatedOverlay: ValidatedDecisionOverlay,
    epoch: ExecutionEpochContext
  ) {
    self.plan = plan
    self.validatedOverlay = validatedOverlay
    self.epoch = epoch
  }
}

/// Read-only collection boundary. Implementations must not expose mutation adapters.
public protocol RevalidationEvidenceSource: Sendable {
  func collectCurrentEvidence(for request: RevalidationRequest) async throws
    -> CurrentRevalidationSnapshot
}

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

public struct ExecutionManifest: Equatable, Sendable {
  public let planHash: PolicyDigest
  public let overlayHash: PolicyDigest
  public let epoch: ExecutionEpochContext
  public let executionActionIDs: [ActionID]
  public let jitRevalidationActionIDs: [[ActionID]]
  public let compoundReleaseUnits: [CompoundReleaseUnit]
  public let currentBindingHash: PolicyDigest

  public init(
    planHash: PolicyDigest,
    overlayHash: PolicyDigest,
    epoch: ExecutionEpochContext,
    executionActionIDs: [ActionID],
    jitRevalidationActionIDs: [[ActionID]],
    compoundReleaseUnits: [CompoundReleaseUnit],
    currentBindingHash: PolicyDigest
  ) {
    self.planHash = planHash
    self.overlayHash = overlayHash
    self.epoch = epoch
    self.executionActionIDs = executionActionIDs
    self.jitRevalidationActionIDs = jitRevalidationActionIDs
    self.compoundReleaseUnits = compoundReleaseUnits
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
}
