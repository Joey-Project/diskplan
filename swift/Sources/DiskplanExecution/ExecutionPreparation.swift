import CryptoKit
import DiskplanPolicy
import Foundation

public actor ExecutionPreparationEngine {
  private struct CapabilityRecord: Sendable {
    let planHash: PolicyDigest
    let overlayHash: PolicyDigest
    let epochID: String
    let deadlineSeconds: Int64
    let generation: UInt64
    let forceWarningActionIDs: [ActionID]
    let reviewBindingHash: PolicyDigest
    let manifest: ExecutionManifest
  }

  private let collector: EngineRevalidationCollector
  private let randomBytes: @Sendable (Int) throws -> Data
  private let clock: @Sendable () -> Int64
  private var capabilities: [Data: CapabilityRecord] = [:]
  private var preparationGeneration: UInt64 = 0
  private var preparationGenerationExhausted = false

  @_spi(DiskplanEngine) public init(collector: EngineRevalidationCollector) {
    self.collector = collector
    self.randomBytes = { count in
      var generator = SystemRandomNumberGenerator()
      return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }
    self.clock = { Int64(Date().timeIntervalSince1970.rounded(.down)) }
  }

  init(
    evidenceSource: any RevalidationEvidenceSource,
    jitEvidenceSource: (any JITRevalidationEvidenceSource)? = nil,
    randomBytes: @escaping @Sendable (Int) throws -> Data,
    clock: @escaping @Sendable () -> Int64 = {
      Int64(Date().timeIntervalSince1970.rounded(.down))
    }
  ) {
    self.collector = EngineRevalidationCollector(
      currentSource: evidenceSource,
      jitSource: jitEvidenceSource
    )
    self.randomBytes = randomBytes
    self.clock = clock
  }

  public func prepare(
    plan: ImmutablePlan,
    overlay: DecisionOverlay,
    mode: PreparationMode,
    lifetimeSeconds: Int64
  ) async throws -> PreparationResult {
    try await prepare(
      plan: plan,
      overlay: overlay,
      mode: mode,
      issuedAtSeconds: clock(),
      lifetimeSeconds: lifetimeSeconds
    )
  }

  func prepare(
    plan: ImmutablePlan,
    overlay: DecisionOverlay,
    mode: PreparationMode,
    issuedAtSeconds: Int64,
    lifetimeSeconds: Int64
  ) async throws -> PreparationResult {
    guard !preparationGenerationExhausted else {
      invalidateAllCapabilities()
      throw ExecutionPreparationError.generationExhausted
    }
    let nextGeneration = preparationGeneration.addingReportingOverflow(1)
    guard !nextGeneration.overflow else {
      preparationGenerationExhausted = true
      invalidateAllCapabilities()
      throw ExecutionPreparationError.generationExhausted
    }
    preparationGeneration = nextGeneration.partialValue
    let generation = preparationGeneration
    invalidateAllCapabilities()
    purgeExpired(at: issuedAtSeconds)
    guard lifetimeSeconds > 0,
      issuedAtSeconds.addingReportingOverflow(lifetimeSeconds).overflow == false
    else { throw ExecutionPreparationError.invalidLifetime }
    let validated = try DecisionOverlayValidator.validate(overlay, against: plan)

    let epochBytes = try entropy(count: 16)
    let epoch = try ExecutionEpochContext(
      epochID: epochBytes.map { String(format: "%02x", $0) }.joined(),
      semanticReferenceTimeSeconds: issuedAtSeconds,
      issuedAtSeconds: issuedAtSeconds,
      deadlineSeconds: issuedAtSeconds + lifetimeSeconds
    )
    let request = RevalidationRequest(plan: plan, validatedOverlay: validated, epoch: epoch)

    let report: RevalidationReport
    do {
      let snapshot = try await collector.collectCurrentEvidence(for: request)
      guard generationIsCurrent(generation) else {
        throw ExecutionPreparationError.preparationSuperseded
      }
      report = Revalidator.evaluate(request: request, snapshot: snapshot)
    } catch {
      guard generationIsCurrent(generation) else {
        throw ExecutionPreparationError.preparationSuperseded
      }
      if let error = error as? ExecutionPreparationError,
        error == .preparationSuperseded
      {
        throw error
      }
      let finding = RevalidationFinding(
        actionID: nil,
        subject: .collector,
        kind: .collectionFailed,
        observationFailure: ObservationFailure(
          code: String(reflecting: type(of: error)), collector: "revalidation-source")
      )
      report = RevalidationReport(
        planHash: plan.planHash,
        overlayHash: overlay.overlayHash,
        epoch: epoch,
        actionOutcomes: [],
        globalFindings: [finding],
        manifest: nil
      )
    }

    guard report.isCurrent, let manifest = report.manifest else {
      return .rejected(report)
    }
    guard generationIsCurrent(generation) else {
      throw ExecutionPreparationError.preparationSuperseded
    }
    let forceWarningActionIDs = Set<ActionID>(
      validated.executionSteps.flatMap(\.jitRevalidationActions).compactMap { action in
        guard
          case .genericRemove(let contract) = action.prototype.adapterContract,
          contract.forceRequirement == .requiresForceWithWarning
        else { return nil }
        return action.id
      }
    ).sorted()
    let reviewBindingHash = applyReviewBindingHash(
      manifest: manifest,
      forceWarningActionIDs: forceWarningActionIDs
    )
    switch mode {
    case .dryRun:
      return .dryRun(
        DryRunReport(
          revalidation: report,
          forceWarningActionIDs: forceWarningActionIDs
        ))
    case .apply:
      guard generationIsCurrent(generation) else {
        throw ExecutionPreparationError.preparationSuperseded
      }
      var token: Data?
      for _ in 0..<8 {
        let candidate = try entropy(count: 32)
        if capabilities[candidate] == nil {
          token = candidate
          break
        }
      }
      guard let token else { throw ExecutionPreparationError.entropyFailure }
      guard generationIsCurrent(generation) else {
        throw ExecutionPreparationError.preparationSuperseded
      }
      capabilities[token] = CapabilityRecord(
        planHash: plan.planHash,
        overlayHash: overlay.overlayHash,
        epochID: epoch.epochID,
        deadlineSeconds: epoch.deadlineSeconds,
        generation: generation,
        forceWarningActionIDs: forceWarningActionIDs,
        reviewBindingHash: reviewBindingHash,
        manifest: manifest
      )
      return .applyReady(
        ApplyReadyReport(
          revalidation: report,
          forceWarningActionIDs: forceWarningActionIDs,
          reviewBindingHash: reviewBindingHash
        ),
        ApplyCapability(opaqueBytes: token)
      )
    }
  }

  public func authorizeApply(
    _ capability: ApplyCapability,
    ready: ApplyReadyReport,
    plan: ImmutablePlan,
    overlay: DecisionOverlay,
    confirmation: ApplyReviewConfirmation? = nil
  ) throws -> ApplyAuthorization {
    try authorizeApply(
      capability,
      ready: ready,
      plan: plan,
      overlay: overlay,
      confirmation: confirmation,
      nowSeconds: clock()
    )
  }

  func authorizeApply(
    _ capability: ApplyCapability,
    ready: ApplyReadyReport,
    plan: ImmutablePlan,
    overlay: DecisionOverlay,
    confirmation: ApplyReviewConfirmation? = nil,
    nowSeconds: Int64
  ) throws -> ApplyAuthorization {
    guard let record = capabilities.removeValue(forKey: capability.opaqueBytes) else {
      throw ExecutionPreparationError.capabilityUnknown
    }
    guard generationIsCurrent(record.generation) else {
      throw ExecutionPreparationError.preparationSuperseded
    }
    guard nowSeconds < record.deadlineSeconds else {
      throw ExecutionPreparationError.capabilityExpired
    }
    guard ready.revalidation.isCurrent, let readyManifest = ready.revalidation.manifest else {
      throw ExecutionPreparationError.applyReportNotCurrent
    }
    guard record.planHash == plan.planHash,
      record.overlayHash == overlay.overlayHash,
      record.epochID == ready.revalidation.epoch.epochID,
      record.manifest == readyManifest,
      record.forceWarningActionIDs == ready.forceWarningActionIDs,
      record.reviewBindingHash == ready.reviewBindingHash
    else { throw ExecutionPreparationError.capabilityBindingMismatch }
    if !record.forceWarningActionIDs.isEmpty, confirmation == nil {
      throw ExecutionPreparationError.forceConfirmationRequired
    }
    if let confirmation {
      guard confirmation.reviewBindingHash == record.reviewBindingHash,
        confirmation.confirmedForceActionIDs == record.forceWarningActionIDs
      else { throw ExecutionPreparationError.forceConfirmationMismatch }
    }
    let authorizedGeneration = record.generation
    return ApplyAuthorization(
      manifest: record.manifest,
      collector: collector,
      generation: authorizedGeneration,
      confirmedForceActionIDs: record.forceWarningActionIDs,
      generationIsCurrent: { [self] in
        return await self.generationIsCurrent(authorizedGeneration)
      }
    )
  }

  private func entropy(count: Int) throws -> Data {
    let bytes = try randomBytes(count)
    guard bytes.count == count else { throw ExecutionPreparationError.entropyFailure }
    return bytes
  }

  private func applyReviewBindingHash(
    manifest: ExecutionManifest,
    forceWarningActionIDs: [ActionID]
  ) -> PolicyDigest {
    var bytes = Data("diskplan/apply-review/v1\0".utf8)
    bytes.append(manifest.currentBindingHash.bytes)
    bytes.append(manifest.planHash.bytes)
    bytes.append(manifest.overlayHash.bytes)
    bytes.append(Data(manifest.epoch.epochID.utf8))
    for actionID in forceWarningActionIDs { bytes.append(actionID.digest.bytes) }
    return try! PolicyDigest(bytes: Data(SHA256.hash(data: bytes)))
  }

  private func invalidateAllCapabilities() { capabilities.removeAll(keepingCapacity: true) }

  private func generationIsCurrent(_ generation: UInt64) -> Bool {
    !preparationGenerationExhausted && generation == preparationGeneration
  }

  private func purgeExpired(at now: Int64) {
    capabilities = capabilities.filter { $0.value.deadlineSeconds > now }
  }
}

enum Revalidator {
  private struct WaiverRequirementKey: Hashable {
    let actionID: ActionID
    let consentHash: PolicyDigest
  }

  static func evaluate(
    request: RevalidationRequest,
    snapshot: CurrentRevalidationSnapshot
  ) -> RevalidationReport {
    let actions = uniqueJITActions(request.validatedOverlay)
    var globalFindings: [RevalidationFinding] = []
    let currentByID = observationsByActionID(snapshot.actions, findings: &globalFindings)
    let expectedIDs = Set(actions.map(\.id))
    for extra in currentByID.keys where !expectedIDs.contains(extra) {
      globalFindings.append(
        RevalidationFinding(
          actionID: extra, subject: .collector, kind: .unexpectedObservation))
    }

    var policyBindings: [CurrentPolicyBinding] = []
    var consentRequirements: [ExecutionConsentRequirement] = []
    let outcomes = actions.map { action in
      guard let current = currentByID[action.id] else {
        return ActionRevalidationOutcome(
          actionID: action.id,
          findings: [
            RevalidationFinding(actionID: action.id, subject: .collector, kind: .missing)
          ]
        )
      }
      var outcome = evaluateAction(action, current: current)
      let policy = evaluateFreshPolicy(
        action,
        current: current,
        request: request
      )
      outcome = ActionRevalidationOutcome(
        actionID: outcome.actionID,
        findings: (outcome.findings + policy.findings).sorted(by: findingPrecedes)
      )
      if let binding = policy.binding { policyBindings.append(binding) }
      consentRequirements.append(contentsOf: policy.consentRequirements)
      return outcome
    }
    policyBindings.sort { $0.actionID < $1.actionID }
    consentRequirements.sort(by: consentRequirementPrecedes)
    let expectedRequirementKeys = Set(
      request.validatedOverlay.epochRequirements.map {
        WaiverRequirementKey(actionID: $0.actionID, consentHash: $0.consentHash)
      })
    let currentRequirementKeys = Set(
      consentRequirements.map {
        WaiverRequirementKey(actionID: $0.actionID, consentHash: $0.consentHash)
      })
    if consentRequirements.count != request.validatedOverlay.epochRequirements.count
      || expectedRequirementKeys.count != request.validatedOverlay.epochRequirements.count
      || currentRequirementKeys != expectedRequirementKeys
    {
      globalFindings.append(
        RevalidationFinding(
          actionID: nil,
          subject: .policyEvidence,
          kind: .staleConsent
        ))
    }
    if snapshot.captureID == request.plan.globalFacts.captureID
      || policyBindings.contains(where: { $0.captureID != snapshot.captureID })
      || Set(policyBindings.map(\.captureID)).count > 1
      || Set(policyBindings.map(\.globalFactsHash)).count > 1
    {
      globalFindings.append(
        RevalidationFinding(
          actionID: nil,
          subject: .policyEvidence,
          kind: .policyEvidenceMismatch
        ))
    }

    globalFindings.append(
      contentsOf: evaluateInvariant(
        snapshot.invariants.duplicateSurvivorsPreserved,
        subject: .duplicateSurvivors,
        violation: .survivorInvariantViolated
      ))
    globalFindings.append(
      contentsOf: evaluateInvariant(
        snapshot.invariants.terminalNamespacesExclusive,
        subject: .terminalNamespaces,
        violation: .terminalNamespaceInvariantViolated
      ))

    let units = compoundUnits(request.plan.releaseSets)
    let selectedReleaseGroupIDs = Set(
      request.validatedOverlay.executionSteps.compactMap { $0.releaseSet?.allocationGroupID })
    let observedReleaseGroupIDs = snapshot.releaseTopologies.map(\.allocationGroupID)
    for groupID in Set(observedReleaseGroupIDs) where !selectedReleaseGroupIDs.contains(groupID) {
      globalFindings.append(
        RevalidationFinding(
          actionID: nil,
          subject: .releaseTopology(groupID),
          kind: .unexpectedObservation
        ))
    }
    for unit in units where !selectedReleaseGroupIDs.isDisjoint(with: unit.allocationGroupIDs) {
      guard Set(unit.allocationGroupIDs).isSubset(of: selectedReleaseGroupIDs) else {
        globalFindings.append(
          RevalidationFinding(
            actionID: nil,
            subject: .compoundReleaseUnit(unit.allocationGroupIDs),
            kind: .incompleteCompoundReleaseUnit
          ))
        continue
      }
      for groupID in unit.allocationGroupIDs {
        guard
          let expected = request.plan.releaseSets.first(where: {
            $0.allocationGroupID == groupID
          })?.topologyExpectation
        else { continue }
        let matches = snapshot.releaseTopologies.filter { $0.allocationGroupID == groupID }
        if matches.count != 1 {
          globalFindings.append(
            RevalidationFinding(
              actionID: nil,
              subject: .releaseTopology(groupID),
              kind: matches.isEmpty ? .missing : .duplicateObservation
            ))
        } else {
          globalFindings.append(
            contentsOf: compareObservation(
              matches[0].topology,
              expected: expected,
              actionID: nil,
              subject: .releaseTopology(groupID),
              mismatch: .releaseTopologyMismatch
            ))
        }
      }
    }

    let sortedOutcomes = outcomes.sorted { $0.actionID < $1.actionID }
    globalFindings.sort(by: findingPrecedes)
    let allCurrent = sortedOutcomes.allSatisfy(\.isCurrent) && globalFindings.isEmpty
    let manifest: ExecutionManifest?
    if allCurrent {
      let actionIDs = request.validatedOverlay.executionSteps.map(\.action.id)
      let jit = request.validatedOverlay.executionSteps.map { $0.jitRevalidationActions.map(\.id) }
      let binding = manifestDigest(
        request: request,
        actionOutcomes: sortedOutcomes,
        units: units,
        currentCaptureID: snapshot.captureID,
        policyBindings: policyBindings,
        consentRequirements: consentRequirements
      )
      manifest = ExecutionManifest(
        planHash: request.plan.planHash,
        overlayHash: request.validatedOverlay.overlayHash,
        epoch: request.epoch,
        currentCaptureID: snapshot.captureID,
        executionActionIDs: actionIDs,
        jitRevalidationActionIDs: jit,
        compoundReleaseUnits: units.filter {
          !selectedReleaseGroupIDs.isDisjoint(with: $0.allocationGroupIDs)
        },
        currentPolicyBindings: policyBindings,
        consentRequirements: consentRequirements,
        currentBindingHash: binding
      )
    } else {
      manifest = nil
    }
    return RevalidationReport(
      planHash: request.plan.planHash,
      overlayHash: request.validatedOverlay.overlayHash,
      epoch: request.epoch,
      actionOutcomes: sortedOutcomes,
      globalFindings: globalFindings,
      manifest: manifest
    )
  }

  static func evaluateJIT(
    request: JITRevalidationRequest,
    collected: JITRevalidationSnapshot
  ) -> JITRevalidationReport {
    let snapshot = collected.snapshot
    let expectedIDs = Set(request.actionIDs)
    let actionByID = Dictionary(uniqueKeysWithValues: request.plan.actions.map { ($0.id, $0) })
    var globalFindings: [RevalidationFinding] = []
    if request.oneShotNonce.count != 32
      || collected.oneShotNonce != request.oneShotNonce
      || collected.authorizationCurrentBindingHash
        != request.authorizationCurrentBindingHash
      || request.authorizationCurrentBindingHash != request.manifest.currentBindingHash
      || collected.preparationGeneration != request.preparationGeneration
      || collected.epochID != request.epoch.epochID
      || request.epoch.semanticReferenceTimeSeconds != request.epoch.issuedAtSeconds
    {
      globalFindings.append(
        RevalidationFinding(
          actionID: nil,
          subject: .policyEvidence,
          kind: .policyEvidenceMismatch
        ))
    }
    if expectedIDs.count != request.actionIDs.count {
      globalFindings.append(
        RevalidationFinding(
          actionID: nil, subject: .collector, kind: .duplicateObservation))
    }
    let currentByID = observationsByActionID(snapshot.actions, findings: &globalFindings)
    for extra in currentByID.keys where !expectedIDs.contains(extra) {
      globalFindings.append(
        RevalidationFinding(
          actionID: extra, subject: .collector, kind: .unexpectedObservation))
    }

    let policyRequest = RevalidationRequest(
      plan: request.plan,
      validatedOverlay: request.validatedOverlay,
      epoch: request.epoch
    )
    var policyBindings: [CurrentPolicyBinding] = []
    var consentRequirements: [ExecutionConsentRequirement] = []
    let outcomes = expectedIDs.sorted().map { actionID -> ActionRevalidationOutcome in
      guard let expected = actionByID[actionID] else {
        globalFindings.append(
          RevalidationFinding(
            actionID: actionID, subject: .collector, kind: .unexpectedObservation))
        return ActionRevalidationOutcome(actionID: actionID, findings: [])
      }
      guard let current = currentByID[actionID] else {
        return ActionRevalidationOutcome(
          actionID: actionID,
          findings: [
            RevalidationFinding(actionID: actionID, subject: .collector, kind: .missing)
          ])
      }
      let actionOutcome = evaluateAction(expected, current: current)
      let policy = evaluateFreshPolicy(
        expected,
        current: current,
        request: policyRequest
      )
      if let binding = policy.binding { policyBindings.append(binding) }
      consentRequirements.append(contentsOf: policy.consentRequirements)
      return ActionRevalidationOutcome(
        actionID: actionID,
        findings: (actionOutcome.findings + policy.findings).sorted(by: findingPrecedes)
      )
    }

    let authorizedBindings = request.manifest.currentPolicyBindings.filter {
      expectedIDs.contains($0.actionID)
    }
    if snapshot.captureID == request.plan.globalFacts.captureID
      || snapshot.captureID == request.manifest.currentCaptureID
      || policyBindings.count != expectedIDs.count
      || authorizedBindings.count != expectedIDs.count
      || policyBindings.contains(where: { $0.captureID != snapshot.captureID })
      || !policyBindings.allSatisfy({ current in
        authorizedBindings.contains(where: {
          $0.actionID == current.actionID && $0.requiredWaivers == current.requiredWaivers
        })
      })
    {
      globalFindings.append(
        RevalidationFinding(
          actionID: nil,
          subject: .policyEvidence,
          kind: .policyEvidenceMismatch
        ))
    }
    let authorizedConsents = request.manifest.consentRequirements.filter {
      expectedIDs.contains($0.actionID)
    }
    if consentRequirements.count != authorizedConsents.count
      || !consentRequirements.allSatisfy({ current in
        authorizedConsents.contains(where: { jitConsentMatches(current, authorized: $0) })
      })
    {
      globalFindings.append(
        RevalidationFinding(
          actionID: nil,
          subject: .policyEvidence,
          kind: .staleConsent
        ))
    }

    globalFindings.append(
      contentsOf: evaluateInvariant(
        snapshot.invariants.duplicateSurvivorsPreserved,
        subject: .duplicateSurvivors,
        violation: .survivorInvariantViolated
      ))
    globalFindings.append(
      contentsOf: evaluateInvariant(
        snapshot.invariants.terminalNamespacesExclusive,
        subject: .terminalNamespaces,
        violation: .terminalNamespaceInvariantViolated
      ))

    let expectedGroups = Set(request.releaseGroupIDs)
    let observedGroups = snapshot.releaseTopologies.map(\.allocationGroupID)
    for groupID in Set(observedGroups) where !expectedGroups.contains(groupID) {
      globalFindings.append(
        RevalidationFinding(
          actionID: nil,
          subject: .releaseTopology(groupID),
          kind: .unexpectedObservation
        ))
    }
    for groupID in request.releaseGroupIDs {
      let matches = snapshot.releaseTopologies.filter { $0.allocationGroupID == groupID }
      guard
        let expected = request.plan.releaseSets.first(where: {
          $0.allocationGroupID == groupID
        })?.topologyExpectation
      else {
        globalFindings.append(
          RevalidationFinding(
            actionID: nil,
            subject: .releaseTopology(groupID),
            kind: .unexpectedObservation
          ))
        continue
      }
      guard matches.count == 1 else {
        globalFindings.append(
          RevalidationFinding(
            actionID: nil,
            subject: .releaseTopology(groupID),
            kind: matches.isEmpty ? .missing : .duplicateObservation
          ))
        continue
      }
      globalFindings.append(
        contentsOf: compareObservation(
          matches[0].topology,
          expected: expected,
          actionID: nil,
          subject: .releaseTopology(groupID),
          mismatch: .releaseTopologyMismatch
        ))
    }
    globalFindings.sort(by: findingPrecedes)
    return JITRevalidationReport(
      captureID: snapshot.captureID,
      oneShotNonce: request.oneShotNonce,
      actionOutcomes: outcomes.sorted { $0.actionID < $1.actionID },
      globalFindings: globalFindings
    )
  }

  private static func jitConsentMatches(
    _ current: ExecutionConsentRequirement,
    authorized: ExecutionConsentRequirement
  ) -> Bool {
    current.consentHash == authorized.consentHash
      && current.actionID == authorized.actionID
      && current.planHash == authorized.planHash
      && current.planEvidenceHash == authorized.planEvidenceHash
      && current.overlayHash == authorized.overlayHash
      && current.originalSemanticReferenceTimeSeconds
        == authorized.originalSemanticReferenceTimeSeconds
      && current.executionReferenceTimeSeconds == authorized.executionReferenceTimeSeconds
      && current.currentPredicate == authorized.currentPredicate
  }

  private static func uniqueJITActions(
    _ overlay: ValidatedDecisionOverlay
  ) -> [ActionDefinition] {
    var byID: [ActionID: ActionDefinition] = [:]
    for action in overlay.executionSteps.flatMap(\.jitRevalidationActions) {
      byID[action.id] = action
    }
    return byID.values.sorted { $0.id < $1.id }
  }

  private static func observationsByActionID(
    _ observations: [CurrentActionEvidence],
    findings: inout [RevalidationFinding]
  ) -> [ActionID: CurrentActionEvidence] {
    let groups = Dictionary(grouping: observations, by: \.actionID)
    for (id, group) in groups where group.count != 1 {
      findings.append(
        RevalidationFinding(actionID: id, subject: .collector, kind: .duplicateObservation))
    }
    return groups.compactMapValues { $0.count == 1 ? $0[0] : nil }
  }

  private static func evaluateAction(
    _ action: ActionDefinition,
    current: CurrentActionEvidence
  ) -> ActionRevalidationOutcome {
    var findings: [RevalidationFinding] = []
    findings += compareObservation(
      current.targetIdentity,
      expected: action.prototype.protectedProperties.identity.expectedIdentity,
      actionID: action.id,
      subject: .targetIdentity,
      mismatch: .identityMismatch
    )
    if case .requiredDigest = action.prototype.protectedProperties.content.expectedBaseline {
      findings += compareObservation(
        current.targetContent,
        expected: action.prototype.protectedProperties.content.expectedBaseline,
        actionID: action.id,
        subject: .targetContent,
        mismatch: .contentMismatch
      )
    }
    findings += compareObservation(
      current.targetAccessPolicy,
      expected: action.prototype.protectedProperties.accessPolicy.requiredBaseline,
      actionID: action.id,
      subject: .targetAccessPolicy,
      mismatch: .accessPolicyMismatch
    )
    findings += compareObservation(
      current.coverage,
      expected: action.evidence.coverage,
      actionID: action.id,
      subject: .coverage,
      mismatch: .coverageMismatch
    )
    findings += compareFrozenObservation(
      current.collectorStatus,
      expected: action.evidence.collectorStatus,
      actionID: action.id,
      subject: .collectorStatus,
      mismatch: .collectionFailed
    )
    findings += compareFrozenObservation(
      current.activity,
      expected: action.evidence.activity,
      actionID: action.id,
      subject: .activity,
      mismatch: .activityMismatch
    )
    findings += compareFrozenObservation(
      current.explicitProtection,
      expected: action.evidence.explicitProtection,
      actionID: action.id,
      subject: .explicitProtection,
      mismatch: .protectionMismatch
    )
    findings += compareFrozenObservation(
      current.providerState,
      expected: action.evidence.providerState,
      actionID: action.id,
      subject: .providerState,
      mismatch: .providerMismatch
    )
    findings += compareFrozenObservation(
      current.recoverability,
      expected: action.evidence.recoverability,
      actionID: action.id,
      subject: .recoverability,
      mismatch: .recoverabilityMismatch
    )
    findings += compareFrozenObservation(
      current.dependencyState,
      expected: action.evidence.dependencyState,
      actionID: action.id,
      subject: .dependency,
      mismatch: .dependencyMismatch
    )

    let namespace = action.prototype.namespaceBinding
    if current.root.relativePath != nil {
      findings.append(
        RevalidationFinding(
          actionID: action.id,
          subject: .rootIdentity,
          kind: .namespaceIdentityMismatch
        ))
    }
    findings += compareObservation(
      current.root.identity,
      expected: namespace.rootIdentity,
      actionID: action.id,
      subject: .rootIdentity,
      mismatch: .namespaceIdentityMismatch
    )
    findings += compareObservation(
      current.root.seal,
      expected: namespace.rootSeal,
      actionID: action.id,
      subject: .rootAccessPolicy,
      mismatch: .namespaceAccessPolicyMismatch
    )
    if current.parents.count != namespace.parentChain.count {
      findings.append(
        RevalidationFinding(actionID: action.id, subject: .collector, kind: .missing))
    } else {
      for (expected, observed) in zip(namespace.parentChain, current.parents) {
        if observed.relativePath != expected.relativePath {
          findings.append(
            RevalidationFinding(
              actionID: action.id,
              subject: .parentIdentity(expected.relativePath),
              kind: .namespaceIdentityMismatch
            ))
          continue
        }
        findings += compareObservation(
          observed.identity,
          expected: expected.identity,
          actionID: action.id,
          subject: .parentIdentity(expected.relativePath),
          mismatch: .namespaceIdentityMismatch
        )
        findings += compareObservation(
          observed.seal,
          expected: expected.seal,
          actionID: action.id,
          subject: .parentAccessPolicy(expected.relativePath),
          mismatch: .namespaceAccessPolicyMismatch
        )
      }
    }

    let expectedGit: GitWorktreeEvidence?
    switch action.prototype.adapterContract {
    case .gitWorktreeRemove(let contract): expectedGit = contract.verifiedEvidence
    case .gitWorktreeDiscardLocalChanges(let contract): expectedGit = contract.verifiedEvidence
    default: expectedGit = nil
    }
    if let expectedGit {
      findings += compareObservation(
        current.gitWorktree,
        expected: expectedGit,
        actionID: action.id,
        subject: .gitPrerequisites,
        mismatch: .gitPrerequisiteMismatch
      )
    }
    findings.sort(by: findingPrecedes)
    return ActionRevalidationOutcome(actionID: action.id, findings: findings)
  }

  private struct FreshPolicyResult {
    let findings: [RevalidationFinding]
    let binding: CurrentPolicyBinding?
    let consentRequirements: [ExecutionConsentRequirement]
  }

  private static func evaluateFreshPolicy(
    _ action: ActionDefinition,
    current: CurrentActionEvidence,
    request: RevalidationRequest
  ) -> FreshPolicyResult {
    let unavailable:
      (RevalidationFailureKind, ObservationFailure?, UnknownReason?) ->
        FreshPolicyResult = { kind, failure, reason in
          FreshPolicyResult(
            findings: [
              RevalidationFinding(
                actionID: action.id,
                subject: .policyEvidence,
                kind: kind,
                observationFailure: failure,
                unknownReason: reason
              )
            ],
            binding: nil,
            consentRequirements: []
          )
        }
    let fresh: FreshPolicyEvidence
    switch current.freshPolicyEvidence {
    case .known(let value): fresh = value
    case .absent: return unavailable(.missing, nil, nil)
    case .unknown(let reason): return unavailable(.unknown, nil, reason)
    case .unreadable(let failure): return unavailable(.unreadable, failure, nil)
    case .failed(let failure): return unavailable(.collectionFailed, failure, nil)
    }

    let evidence = fresh.evidence
    let facts = fresh.globalFacts
    guard evidence.semanticReferenceTimeSeconds == request.epoch.semanticReferenceTimeSeconds,
      facts.semanticReferenceTimeSeconds == request.epoch.semanticReferenceTimeSeconds,
      evidence.captureID == facts.captureID,
      evidence.captureID != request.plan.globalFacts.captureID,
      evidence.globalFactsHash == facts.globalFactsHash,
      evidence.policyVersion == request.plan.policyVersion,
      evidence.schemaVersion == request.plan.schemaVersion,
      facts.policyVersion == request.plan.policyVersion,
      facts.schemaVersion == request.plan.schemaVersion,
      Data(evidence.candidateID.utf8) == Data(action.evidence.candidateID.utf8),
      evidence.namespaceBinding == action.prototype.namespaceBinding,
      evidence.identity == current.targetIdentity,
      freshContentMatchesCurrent(action, evidence: evidence, current: current.targetContent),
      evidence.coverage == current.coverage.knownValue,
      evidence.collectorStatus == current.collectorStatus,
      evidence.activity == current.activity,
      evidence.explicitProtection == current.explicitProtection,
      evidence.providerState == current.providerState,
      evidence.recoverability == current.recoverability,
      evidence.dependencyState == current.dependencyState,
      freshGitEvidenceMatchesCurrent(evidence, current: current.gitWorktree),
      freshAccessPolicyMatchesCurrent(evidence, current: current.targetAccessPolicy)
    else { return unavailable(.policyEvidenceMismatch, nil, nil) }

    do {
      let prototype = try ActionPrototype.build(
        request: adapterRequest(for: action.prototype.adapterContract),
        evidence: evidence
      )
      guard prototype == action.prototype else {
        return unavailable(.policyEvidenceMismatch, nil, nil)
      }
      let evaluation = try OneVotePolicy.evaluate(
        OneVotePolicyInputs.build(evidence: evidence, globalFacts: facts)
      )
      let currentPredicates: [WaiverPredicate]
      switch evaluation.stageability {
      case .stageable:
        currentPredicates = []
      case .requiresConsents(let predicates):
        currentPredicates = Array(Set(predicates)).sorted()
      case .blocked:
        return unavailable(.policyThresholdCrossed, nil, nil)
      }
      let plannedPredicates: [WaiverPredicate]
      switch action.evaluation.stageability {
      case .stageable:
        plannedPredicates = []
      case .requiresConsents(let predicates):
        plannedPredicates = Array(Set(predicates)).sorted()
      case .blocked:
        return unavailable(.policyThresholdCrossed, nil, nil)
      }
      guard currentPredicates == plannedPredicates else {
        return unavailable(.staleConsent, nil, nil)
      }

      let consents = request.validatedOverlay.waiverConsents.filter {
        $0.actionLineageID == action.lineageID
      }
      var requirements: [ExecutionConsentRequirement] = []
      var findings: [RevalidationFinding] = []
      for predicate in currentPredicates {
        let matches = consents.filter { $0.predicate == predicate }
        guard matches.count == 1, let consent = matches.first,
          let epochRequirement = request.validatedOverlay.epochRequirements.first(where: {
            $0.actionID == action.id && $0.consentHash == consent.consentHash
          }),
          epochRequirement.planHash == request.plan.planHash,
          epochRequirement.evidenceHash == request.plan.evidenceHash,
          epochRequirement.semanticReferenceTimeSeconds
            == request.plan.globalFacts.semanticReferenceTimeSeconds
        else {
          findings.append(
            RevalidationFinding(
              actionID: action.id,
              subject: .waiverConsent(predicate.kind),
              kind: .staleConsent
            ))
          continue
        }
        requirements.append(
          ExecutionConsentRequirement(
            consentHash: consent.consentHash,
            actionID: action.id,
            planHash: epochRequirement.planHash,
            planEvidenceHash: epochRequirement.evidenceHash,
            overlayHash: request.validatedOverlay.overlayHash,
            originalSemanticReferenceTimeSeconds:
              epochRequirement.semanticReferenceTimeSeconds,
            executionReferenceTimeSeconds: request.epoch.semanticReferenceTimeSeconds,
            currentEvidenceID: evidence.evidenceID,
            currentGlobalFactsHash: facts.globalFactsHash,
            currentPredicate: predicate
          ))
      }
      return FreshPolicyResult(
        findings: findings,
        binding: CurrentPolicyBinding(
          actionID: action.id,
          captureID: evidence.captureID,
          evidenceID: evidence.evidenceID,
          globalFactsHash: facts.globalFactsHash,
          requiredWaivers: currentPredicates
        ),
        consentRequirements: requirements.sorted(by: consentRequirementPrecedes)
      )
    } catch {
      return unavailable(
        .policyEvidenceMismatch,
        ObservationFailure(
          code: String(reflecting: type(of: error)), collector: "fresh-policy-evaluation"),
        nil
      )
    }
  }

  private static func adapterRequest(
    for contract: ActionAdapterContract
  ) -> ActionAdapterRequest {
    switch contract {
    case .genericRemove: return .genericRemove
    case .gitWorktreeRemove: return .gitWorktreeRemove
    case .gitWorktreeDiscardLocalChanges: return .gitWorktreeDiscardLocalChanges
    case .codexCleanTemporary(let contract):
      return .codexCleanTemporary(cleanupScopeID: contract.cleanupScopeID)
    case .versionedArtifactRemove(let contract):
      return .versionedArtifactRemove(
        artifactKind: contract.artifactKind, version: contract.version)
    case .completeReleaseSetRemove(let contract):
      return .completeReleaseSetRemove(binding: contract.binding)
    }
  }

  private static func freshAccessPolicyMatchesCurrent(
    _ evidence: FrozenEvidenceSnapshot,
    current: Observation<RequiredAccessPolicyBaseline>
  ) -> Bool {
    guard case .known(let accessPolicy) = evidence.accessPolicy,
      case .known(let aclDigest) = evidence.aclDigest,
      case .known(let providerState) = evidence.providerState,
      case .known(let mountIdentity) = evidence.targetMountIdentity
    else { return false }
    return current
      == .known(
        RequiredAccessPolicyBaseline(
          accessPolicyBytes: Data(accessPolicy.utf8),
          aclDigest: aclDigest,
          providerState: providerState,
          mountIdentityBytes: Data(mountIdentity.utf8)
        ))
  }

  private static func freshContentMatchesCurrent(
    _ action: ActionDefinition,
    evidence: FrozenEvidenceSnapshot,
    current: Observation<ContentProtectionBaseline>
  ) -> Bool {
    switch action.prototype.protectedProperties.content.expectedBaseline {
    case .requiredDigest:
      return evidence.contentProtection == current
    case .explicitlyNotApplicable:
      return true
    }
  }

  private static func freshGitEvidenceMatchesCurrent(
    _ evidence: FrozenEvidenceSnapshot,
    current: Observation<GitWorktreeEvidence>
  ) -> Bool {
    guard let gitWorktree = evidence.gitWorktree else { return current == .absent }
    return current == .known(gitWorktree)
  }

  private static func compareObservation<Value: Equatable & Sendable>(
    _ observation: Observation<Value>,
    expected: Value,
    actionID: ActionID?,
    subject: RevalidationSubject,
    mismatch: RevalidationFailureKind
  ) -> [RevalidationFinding] {
    switch observation {
    case .known(let value):
      return value == expected
        ? []
        : [RevalidationFinding(actionID: actionID, subject: subject, kind: mismatch)]
    case .absent:
      return [RevalidationFinding(actionID: actionID, subject: subject, kind: .missing)]
    case .unknown(let reason):
      return [
        RevalidationFinding(
          actionID: actionID, subject: subject, kind: .unknown, unknownReason: reason)
      ]
    case .unreadable(let failure):
      return [
        RevalidationFinding(
          actionID: actionID, subject: subject, kind: .unreadable,
          observationFailure: failure)
      ]
    case .failed(let failure):
      return [
        RevalidationFinding(
          actionID: actionID, subject: subject, kind: .collectionFailed,
          observationFailure: failure)
      ]
    }
  }

  private static func compareFrozenObservation<Value: Equatable & Sendable>(
    _ current: Observation<Value>,
    expected: Observation<Value>,
    actionID: ActionID?,
    subject: RevalidationSubject,
    mismatch: RevalidationFailureKind
  ) -> [RevalidationFinding] {
    guard case .known(let expectedValue) = expected else {
      return [
        RevalidationFinding(
          actionID: actionID,
          subject: subject,
          kind: .collectionFailed,
          observationFailure: ObservationFailure(
            code: "non-current-frozen-baseline", collector: "immutable-plan")
        )
      ]
    }
    return compareObservation(
      current,
      expected: expectedValue,
      actionID: actionID,
      subject: subject,
      mismatch: mismatch
    )
  }

  private static func evaluateInvariant(
    _ observation: Observation<Bool>,
    subject: RevalidationSubject,
    violation: RevalidationFailureKind
  ) -> [RevalidationFinding] {
    switch observation {
    case .known(true): return []
    case .known(false):
      return [RevalidationFinding(actionID: nil, subject: subject, kind: violation)]
    default:
      return compareObservation(
        observation, expected: true, actionID: nil, subject: subject, mismatch: violation)
    }
  }

  private static func compoundUnits(_ releaseSets: [PlanReleaseSet]) -> [CompoundReleaseUnit] {
    guard !releaseSets.isEmpty else { return [] }
    var remaining = Set(releaseSets.indices)
    var result: [CompoundReleaseUnit] = []
    while let seed = remaining.min() {
      var component: Set<Int> = [seed]
      var frontier = [seed]
      remaining.remove(seed)
      while let index = frontier.popLast() {
        let ownerIDs = Set(releaseSets[index].ownerActionIDs)
        let fileIDs = Set(releaseSets[index].topologyExpectation.fileObjects.map(\.fileObjectID))
        let connected = remaining.filter { candidate in
          !ownerIDs.isDisjoint(with: releaseSets[candidate].ownerActionIDs)
            || !fileIDs.isDisjoint(
              with: releaseSets[candidate].topologyExpectation.fileObjects.map(\.fileObjectID))
        }
        for candidate in connected {
          component.insert(candidate)
          frontier.append(candidate)
          remaining.remove(candidate)
        }
      }
      let groups = component.map { releaseSets[$0].allocationGroupID }.sorted(by: rawUTF8Precedes)
      let owners = Set(component.flatMap { releaseSets[$0].ownerActionIDs }).sorted()
      result.append(CompoundReleaseUnit(allocationGroupIDs: groups, ownerActionIDs: owners))
    }
    return result.sorted {
      rawUTF8Precedes(
        $0.allocationGroupIDs.joined(separator: "\u{0}"),
        $1.allocationGroupIDs.joined(separator: "\u{0}"))
    }
  }

  private static func manifestDigest(
    request: RevalidationRequest,
    actionOutcomes: [ActionRevalidationOutcome],
    units: [CompoundReleaseUnit],
    currentCaptureID: PolicyDigest,
    policyBindings: [CurrentPolicyBinding],
    consentRequirements: [ExecutionConsentRequirement]
  ) -> PolicyDigest {
    var encoder = BindingEncoder(domain: "diskplan-current-execution-binding-v1")
    encoder.data(request.plan.planHash.bytes)
    encoder.data(request.validatedOverlay.overlayHash.bytes)
    encoder.data(currentCaptureID.bytes)
    encoder.string(request.epoch.epochID)
    encoder.int64(request.epoch.semanticReferenceTimeSeconds)
    encoder.int64(request.epoch.issuedAtSeconds)
    encoder.int64(request.epoch.deadlineSeconds)
    encoder.array(actionOutcomes) { $0.actionID.digest.bytes }
    encoder.array(units) { unit in
      var nested = BindingEncoder(domain: "compound-release-unit-v1")
      nested.array(unit.allocationGroupIDs) { Data($0.utf8) }
      nested.array(unit.ownerActionIDs) { $0.digest.bytes }
      return nested.bytes
    }
    encoder.array(policyBindings) { binding in
      var nested = BindingEncoder(domain: "current-policy-binding-v1")
      nested.data(binding.actionID.digest.bytes)
      nested.data(binding.captureID.bytes)
      nested.data(binding.evidenceID.bytes)
      nested.data(binding.globalFactsHash.bytes)
      nested.array(binding.requiredWaivers) { predicate in
        encode(predicate: predicate)
      }
      return nested.bytes
    }
    encoder.array(consentRequirements) { requirement in
      var nested = BindingEncoder(domain: "execution-consent-requirement-v1")
      nested.data(requirement.consentHash.bytes)
      nested.data(requirement.actionID.digest.bytes)
      nested.data(requirement.planHash.bytes)
      nested.data(requirement.planEvidenceHash.bytes)
      nested.data(requirement.overlayHash.bytes)
      nested.int64(requirement.originalSemanticReferenceTimeSeconds)
      nested.int64(requirement.executionReferenceTimeSeconds)
      nested.data(requirement.currentEvidenceID.bytes)
      nested.data(requirement.currentGlobalFactsHash.bytes)
      nested.data(encode(predicate: requirement.currentPredicate))
      nested.string(request.epoch.epochID)
      nested.int64(request.epoch.deadlineSeconds)
      return nested.bytes
    }
    return encoder.digest
  }

  private static func encode(predicate: WaiverPredicate) -> Data {
    var encoder = BindingEncoder(domain: "waiver-predicate-v1")
    encoder.string(predicate.kind.rawValue)
    encoder.string(predicate.predicate)
    encoder.string(predicate.valueBucket)
    encoder.data(predicate.semanticEvidenceHash.bytes)
    return encoder.bytes
  }

  private static func findingPrecedes(
    _ lhs: RevalidationFinding,
    _ rhs: RevalidationFinding
  ) -> Bool {
    let leftID = lhs.actionID?.hex ?? ""
    let rightID = rhs.actionID?.hex ?? ""
    if leftID != rightID { return leftID < rightID }
    if lhs.kind.rawValue != rhs.kind.rawValue { return lhs.kind.rawValue < rhs.kind.rawValue }
    return subjectKey(lhs.subject).lexicographicallyPrecedes(subjectKey(rhs.subject))
  }

  private static func subjectKey(_ subject: RevalidationSubject) -> Data {
    var encoder = BindingEncoder(domain: "revalidation-subject-v1")
    switch subject {
    case .targetIdentity: encoder.string("target-identity")
    case .targetContent: encoder.string("target-content")
    case .targetAccessPolicy: encoder.string("target-access-policy")
    case .coverage: encoder.string("coverage")
    case .collectorStatus: encoder.string("collector-status")
    case .activity: encoder.string("activity")
    case .explicitProtection: encoder.string("explicit-protection")
    case .providerState: encoder.string("provider-state")
    case .recoverability: encoder.string("recoverability")
    case .dependency: encoder.string("dependency")
    case .rootIdentity: encoder.string("root-identity")
    case .rootAccessPolicy: encoder.string("root-access-policy")
    case .parentIdentity(let path):
      encoder.string("parent-identity")
      encoder.array(path.components) { $0 }
    case .parentAccessPolicy(let path):
      encoder.string("parent-access-policy")
      encoder.array(path.components) { $0 }
    case .gitPrerequisites: encoder.string("git-prerequisites")
    case .releaseTopology(let groupID):
      encoder.string("release-topology")
      encoder.string(groupID)
    case .duplicateSurvivors: encoder.string("duplicate-survivors")
    case .terminalNamespaces: encoder.string("terminal-namespaces")
    case .compoundReleaseUnit(let groupIDs):
      encoder.string("compound-release-unit")
      encoder.array(groupIDs) { Data($0.utf8) }
    case .collector: encoder.string("collector")
    case .policyEvidence: encoder.string("policy-evidence")
    case .waiverConsent(let kind):
      encoder.string("waiver-consent")
      encoder.string(kind.rawValue)
    }
    return encoder.bytes
  }

  private static func rawUTF8Precedes(_ lhs: String, _ rhs: String) -> Bool {
    Data(lhs.utf8).lexicographicallyPrecedes(Data(rhs.utf8))
  }

  private static func consentRequirementPrecedes(
    _ lhs: ExecutionConsentRequirement,
    _ rhs: ExecutionConsentRequirement
  ) -> Bool {
    if lhs.actionID != rhs.actionID { return lhs.actionID < rhs.actionID }
    return lhs.consentHash < rhs.consentHash
  }
}

private struct BindingEncoder {
  private(set) var bytes = Data()

  init(domain: String) { string(domain) }

  mutating func data(_ value: Data) {
    uint64(UInt64(value.count))
    bytes.append(value)
  }

  mutating func string(_ value: String) { data(Data(value.utf8)) }

  mutating func uint64(_ value: UInt64) {
    var bigEndian = value.bigEndian
    withUnsafeBytes(of: &bigEndian) { bytes.append(contentsOf: $0) }
  }

  mutating func int64(_ value: Int64) { uint64(UInt64(bitPattern: value)) }

  mutating func array<Element>(_ values: [Element], encode: (Element) -> Data) {
    uint64(UInt64(values.count))
    for value in values { data(encode(value)) }
  }

  var digest: PolicyDigest {
    try! PolicyDigest(bytes: Data(SHA256.hash(data: bytes)))
  }
}
