import DiskplanPolicy
import Foundation

private enum ReleasePostverificationRuntimeError: Error {
  case topologyCollectorUnavailable
}

public actor BestEffortApplyCoordinator {
  private struct AuditFailureAccumulator {
    let epochID: String
    var values: [AuditWriteFailure] = []
    var persistenceEnabled = true
  }

  private struct MutationStep: Sendable {
    let action: ActionDefinition
    let operation: ExecutionAdapterOperation
    let prerequisiteActionIDs: [ActionID]
  }

  private struct RuntimeUnit: Sendable {
    let id: ExecutionUnitID
    let logicalActionIDs: [ActionID]
    let prerequisiteActionIDs: [ActionID]
    let jitActionIDs: [ActionID]
    let releaseGroupIDs: [String]
    let mutationSteps: [MutationStep]
  }

  private let adapter: any ExecutionMutationAdapter
  private let eventSink: any ExecutionEventSink
  private let auditSink: (any ExecutionAuditSink)?
  private let clock: @Sendable () -> Int64
  private let nonceGenerator: @Sendable () -> Data
  private let releasePostverificationCore: DescriptorBoundReleasePostverificationCore
  #if DEBUG
    private let testingLegacyReleasePostverification: Bool
  #endif

  @_spi(DiskplanEngine)
  public init(
    adapter: any ExecutionMutationAdapter,
    eventSink: any ExecutionEventSink = ShellExecutionEventSink(),
    auditSink: (any ExecutionAuditSink)? = nil
  ) {
    self.adapter = adapter
    self.eventSink = eventSink
    self.auditSink = auditSink
    self.releasePostverificationCore = Self.failClosedReleasePostverificationCore()
    #if DEBUG
      self.testingLegacyReleasePostverification = false
    #endif
    self.clock = { Int64(Date().timeIntervalSince1970.rounded(.down)) }
    self.nonceGenerator = {
      var generator = SystemRandomNumberGenerator()
      return Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }
  }

  init(
    adapter: any ExecutionMutationAdapter,
    eventSink: any ExecutionEventSink,
    auditSink: (any ExecutionAuditSink)?,
    releasePostverificationCore: DescriptorBoundReleasePostverificationCore? = nil,
    clock: @escaping @Sendable () -> Int64,
    nonceGenerator: @escaping @Sendable () -> Data = {
      var generator = SystemRandomNumberGenerator()
      return Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }
  ) {
    self.adapter = adapter
    self.eventSink = eventSink
    self.auditSink = auditSink
    self.releasePostverificationCore =
      releasePostverificationCore ?? Self.failClosedReleasePostverificationCore()
    #if DEBUG
      self.testingLegacyReleasePostverification = false
    #endif
    self.clock = clock
    self.nonceGenerator = nonceGenerator
  }

  #if DEBUG
    init(
      adapter: any ExecutionMutationAdapter,
      eventSink: any ExecutionEventSink,
      auditSink: (any ExecutionAuditSink)?,
      releasePostverificationCore: DescriptorBoundReleasePostverificationCore? = nil,
      testingLegacyReleasePostverification: Bool,
      clock: @escaping @Sendable () -> Int64,
      nonceGenerator: @escaping @Sendable () -> Data = {
        var generator = SystemRandomNumberGenerator()
        return Data(
          (0..<32).map {
            _ in UInt8.random(in: .min ... .max, using: &generator)
          })
      }
    ) {
      self.adapter = adapter
      self.eventSink = eventSink
      self.auditSink = auditSink
      self.releasePostverificationCore =
        releasePostverificationCore ?? Self.failClosedReleasePostverificationCore()
      self.testingLegacyReleasePostverification = testingLegacyReleasePostverification
      self.clock = clock
      self.nonceGenerator = nonceGenerator
    }
  #endif

  /// Claims one Phase 4 authorization and never accepts a dry-run report or serialized token.
  public func apply(
    authorization: ApplyAuthorization,
    plan: ImmutablePlan,
    overlay: DecisionOverlay
  ) async -> BestEffortApplyReport {
    let claimed: ClaimedApplyAuthorization
    switch await authorization.claimForExecution() {
    case .claimed(let value): claimed = value
    case .replayed: return startFailure(.authorizationAlreadyClaimed)
    case .superseded: return startFailure(.preparationSuperseded)
    case .expired: return startFailure(.expired)
    case .bindingMismatch: return startFailure(.manifestBindingMismatch)
    }
    let manifest = claimed.manifest
    guard clock() < manifest.epoch.deadlineSeconds else {
      return startFailure(.expired, manifest: manifest)
    }

    let validated: ValidatedDecisionOverlay
    do {
      validated = try DecisionOverlayValidator.validate(overlay, against: plan)
    } catch {
      return startFailure(.invalidOverlay, manifest: manifest)
    }
    guard
      manifestMatches(
        manifest, plan: plan, overlay: overlay, validated: validated)
    else {
      return startFailure(.manifestBindingMismatch, manifest: manifest)
    }

    let units: [RuntimeUnit]
    do {
      units = try buildRuntimeUnits(
        manifest: manifest, plan: plan, validated: validated)
    } catch {
      return startFailure(.invalidExecutionGraph, manifest: manifest)
    }
    let forceWarningActionIDs = Set(
      units.flatMap(\.mutationSteps).compactMap { step -> ActionID? in
        guard step.operation.forceRequirement == .requiresForceWithWarning else {
          return nil
        }
        return step.action.id
      }
    ).sorted()
    guard forceWarningActionIDs == claimed.confirmedForceActionIDs else {
      return startFailure(.forceConfirmationBindingMismatch, manifest: manifest)
    }
    let releaseAuthority: EngineReleasePostverificationManifestAuthority?
    if units.contains(where: { !$0.releaseGroupIDs.isEmpty }) {
      do {
        releaseAuthority = try EngineReleasePostverificationManifestAuthority(
          claimedAuthorization: claimed,
          plan: plan
        )
      } catch {
        return startFailure(.manifestBindingMismatch, manifest: manifest)
      }
    } else {
      releaseAuthority = nil
    }

    var auditFailures = AuditFailureAccumulator(epochID: manifest.epoch.epochID)
    var eventIndex = 0
    await emit(
      .applyStarted(epochID: manifest.epoch.epochID),
      index: &eventIndex,
      auditFailures: &auditFailures
    )

    var outcomes: [ExecutionUnitOutcome] = []
    var statusByLogicalActionID: [ActionID: ExecutionUnitStatus] = [:]
    var usedJITCaptureIDs = Set<PolicyDigest>()
    var usedJITNonces = Set<Data>()
    for unit in units {
      if unit.prerequisiteActionIDs.contains(where: {
        statusByLogicalActionID[$0] != .succeeded
      }) {
        let outcome = unitOutcome(unit, status: .skippedPrerequisite)
        outcomes.append(outcome)
        record(outcome.status, for: unit.logicalActionIDs, in: &statusByLogicalActionID)
        await emit(
          .unitFinished(outcome),
          index: &eventIndex,
          auditFailures: &auditFailures
        )
        continue
      }
      if Task.isCancelled {
        let outcome = unitOutcome(unit, status: .cancelled)
        outcomes.append(outcome)
        record(outcome.status, for: unit.logicalActionIDs, in: &statusByLogicalActionID)
        await emit(
          .unitFinished(outcome),
          index: &eventIndex,
          auditFailures: &auditFailures
        )
        continue
      }
      guard await claimed.generationIsCurrent() else {
        let outcome = unitOutcome(unit, status: .superseded)
        outcomes.append(outcome)
        record(outcome.status, for: unit.logicalActionIDs, in: &statusByLogicalActionID)
        await emit(
          .unitFinished(outcome),
          index: &eventIndex,
          auditFailures: &auditFailures
        )
        continue
      }
      guard clock() < manifest.epoch.deadlineSeconds else {
        let outcome = unitOutcome(unit, status: .expired)
        outcomes.append(outcome)
        record(outcome.status, for: unit.logicalActionIDs, in: &statusByLogicalActionID)
        await emit(
          .unitFinished(outcome),
          index: &eventIndex,
          auditFailures: &auditFailures
        )
        continue
      }

      await emit(
        .unitStarted(unit.id), index: &eventIndex, auditFailures: &auditFailures)
      for mutationStep in unit.mutationSteps {
        let action = mutationStep.action
        guard
          case .genericRemove(let contract) = action.prototype.adapterContract,
          contract.forceRequirement == .requiresForceWithWarning
        else { continue }
        await emit(
          .forceRequiredWarning(action.id),
          index: &eventIndex,
          auditFailures: &auditFailures
        )
      }

      let oneShotNonce = nonceGenerator()
      let jitRequest: JITRevalidationRequest
      do {
        jitRequest = try JITRevalidationRequest.authoritative(
          plan: plan,
          validatedOverlay: validated,
          claimedAuthorization: claimed,
          unitID: unit.id,
          oneShotNonce: oneShotNonce
        )
        guard jitRequest.actionIDs == unit.jitActionIDs,
          jitRequest.releaseGroupIDs.map(RawUTF8Key.init)
            == unit.releaseGroupIDs.map(RawUTF8Key.init)
        else { throw EngineJITExecutionClaimError.unitBindingMismatch }
      } catch {
        let report = invalidJITReport(
          oneShotNonce: oneShotNonce,
          code: "invalid-authoritative-jit-unit-binding"
        )
        let outcome = ExecutionUnitOutcome(
          id: unit.id,
          logicalActionIDs: unit.logicalActionIDs,
          prerequisiteActionIDs: unit.prerequisiteActionIDs,
          status: .jitRejected,
          jitReport: report,
          steps: []
        )
        outcomes.append(outcome)
        record(outcome.status, for: unit.logicalActionIDs, in: &statusByLogicalActionID)
        await emit(
          .unitFinished(outcome),
          index: &eventIndex,
          auditFailures: &auditFailures
        )
        continue
      }
      var jitReport: JITRevalidationReport
      if oneShotNonce.count != 32 || !usedJITNonces.insert(oneShotNonce).inserted {
        jitReport = invalidJITReport(
          oneShotNonce: oneShotNonce,
          code: "invalid-or-reused-jit-nonce"
        )
      } else {
        jitReport = await collectJITReport(
          jitRequest,
          collector: claimed.collector
        )
      }
      if let captureID = jitReport.captureID,
        !usedJITCaptureIDs.insert(captureID).inserted
      {
        jitReport = appendingJITFinding(
          jitReport,
          code: "reused-jit-capture"
        )
      }
      if Task.isCancelled {
        let outcome = unitOutcome(unit, status: .cancelled, jitReport: jitReport)
        outcomes.append(outcome)
        record(outcome.status, for: unit.logicalActionIDs, in: &statusByLogicalActionID)
        await emit(
          .unitFinished(outcome),
          index: &eventIndex,
          auditFailures: &auditFailures
        )
        continue
      }
      guard await claimed.generationIsCurrent() else {
        let outcome = unitOutcome(unit, status: .superseded, jitReport: jitReport)
        outcomes.append(outcome)
        record(outcome.status, for: unit.logicalActionIDs, in: &statusByLogicalActionID)
        await emit(
          .unitFinished(outcome),
          index: &eventIndex,
          auditFailures: &auditFailures
        )
        continue
      }
      guard clock() < manifest.epoch.deadlineSeconds else {
        let outcome = unitOutcome(unit, status: .expired, jitReport: jitReport)
        outcomes.append(outcome)
        record(outcome.status, for: unit.logicalActionIDs, in: &statusByLogicalActionID)
        await emit(
          .unitFinished(outcome),
          index: &eventIndex,
          auditFailures: &auditFailures
        )
        continue
      }
      guard jitReport.isCurrent else {
        let outcome = ExecutionUnitOutcome(
          id: unit.id,
          logicalActionIDs: unit.logicalActionIDs,
          prerequisiteActionIDs: unit.prerequisiteActionIDs,
          status: .jitRejected,
          jitReport: jitReport,
          steps: []
        )
        outcomes.append(outcome)
        record(outcome.status, for: unit.logicalActionIDs, in: &statusByLogicalActionID)
        await emit(
          .unitFinished(outcome),
          index: &eventIndex,
          auditFailures: &auditFailures
        )
        continue
      }
      let jitExecutionClaim: EngineJITExecutionClaim
      do {
        jitExecutionClaim = try EngineJITExecutionClaim.issue(
          after: jitRequest,
          report: jitReport
        )
      } catch {
        jitReport = appendingJITFinding(
          jitReport,
          code: "jit-execution-claim-rejected"
        )
        let outcome = ExecutionUnitOutcome(
          id: unit.id,
          logicalActionIDs: unit.logicalActionIDs,
          prerequisiteActionIDs: unit.prerequisiteActionIDs,
          status: .jitRejected,
          jitReport: jitReport,
          steps: []
        )
        outcomes.append(outcome)
        record(outcome.status, for: unit.logicalActionIDs, in: &statusByLogicalActionID)
        await emit(
          .unitFinished(outcome),
          index: &eventIndex,
          auditFailures: &auditFailures
        )
        continue
      }
      let frozenReleaseComponent: FrozenReleasePostverificationComponent?
      #if DEBUG
        var usesTestingLegacyReleasePostverification = false
      #endif
      if unit.releaseGroupIDs.isEmpty {
        do {
          try jitExecutionClaim.consumeForMutation(unitID: unit.id)
          frozenReleaseComponent = nil
        } catch {
          jitReport = appendingJITFinding(
            jitReport,
            code: "jit-execution-claim-consumption-rejected"
          )
          let outcome = ExecutionUnitOutcome(
            id: unit.id,
            logicalActionIDs: unit.logicalActionIDs,
            prerequisiteActionIDs: unit.prerequisiteActionIDs,
            status: .jitRejected,
            jitReport: jitReport,
            steps: []
          )
          outcomes.append(outcome)
          record(outcome.status, for: unit.logicalActionIDs, in: &statusByLogicalActionID)
          await emit(
            .unitFinished(outcome),
            index: &eventIndex,
            auditFailures: &auditFailures
          )
          continue
        }
      } else {
        do {
          #if DEBUG
            if testingLegacyReleasePostverification {
              try jitExecutionClaim.consumeForMutation(unitID: unit.id)
              frozenReleaseComponent = nil
              usesTestingLegacyReleasePostverification = true
            } else {
              frozenReleaseComponent = try freezeReleaseComponent(
                authority: releaseAuthority,
                jitClaim: jitExecutionClaim,
                unit: unit
              )
            }
          #else
            frozenReleaseComponent = try freezeReleaseComponent(
              authority: releaseAuthority,
              jitClaim: jitExecutionClaim,
              unit: unit
            )
          #endif
        } catch {
          jitReport = appendingJITFinding(
            jitReport,
            code: "release-postverification-freeze-rejected"
          )
          let outcome = ExecutionUnitOutcome(
            id: unit.id,
            logicalActionIDs: unit.logicalActionIDs,
            prerequisiteActionIDs: unit.prerequisiteActionIDs,
            status: .jitRejected,
            jitReport: jitReport,
            steps: []
          )
          outcomes.append(outcome)
          record(outcome.status, for: unit.logicalActionIDs, in: &statusByLogicalActionID)
          await emit(
            .unitFinished(outcome),
            index: &eventIndex,
            auditFailures: &auditFailures
          )
          continue
        }
      }

      var stepOutcomes: [ExecutionStepOutcome] = []
      var stepStatusByActionID: [ActionID: ExecutionStepStatus] = [:]
      for mutationStep in unit.mutationSteps {
        let action = mutationStep.action
        if mutationStep.prerequisiteActionIDs.contains(where: {
          stepStatusByActionID[$0] != .succeeded
        }) {
          let step = ExecutionStepOutcome(
            actionID: action.id,
            status: .skippedPrerequisite,
            adapterOutcome: .notStarted(.prerequisiteFailed),
            postVerification: .unknown(.notRequested)
          )
          stepOutcomes.append(step)
          stepStatusByActionID[action.id] = step.status
          await emit(
            .stepFinished(step),
            index: &eventIndex,
            auditFailures: &auditFailures
          )
          continue
        }
        if Task.isCancelled {
          let step = ExecutionStepOutcome(
            actionID: action.id,
            status: .cancelled,
            adapterOutcome: .notStarted(.taskCancelled),
            postVerification: .unknown(.notRequested)
          )
          stepOutcomes.append(step)
          stepStatusByActionID[action.id] = step.status
          await emit(
            .stepFinished(step),
            index: &eventIndex,
            auditFailures: &auditFailures
          )
          continue
        }
        guard await claimed.generationIsCurrent() else {
          let step = ExecutionStepOutcome(
            actionID: action.id,
            status: .superseded,
            adapterOutcome: .notStarted(.preparationSuperseded),
            postVerification: .unknown(.notRequested)
          )
          stepOutcomes.append(step)
          stepStatusByActionID[action.id] = step.status
          await emit(
            .stepFinished(step),
            index: &eventIndex,
            auditFailures: &auditFailures
          )
          continue
        }
        guard clock() < manifest.epoch.deadlineSeconds else {
          let step = ExecutionStepOutcome(
            actionID: action.id,
            status: .expired,
            adapterOutcome: .notStarted(.epochExpired),
            postVerification: .unknown(.timedOut)
          )
          stepOutcomes.append(step)
          stepStatusByActionID[action.id] = step.status
          await emit(
            .stepFinished(step),
            index: &eventIndex,
            auditFailures: &auditFailures
          )
          continue
        }
        let operation = mutationStep.operation
        let adapterResult = await adapter.applyResult(
          operation,
          context: MutationExecutionContext(
            deadlineSeconds: manifest.epoch.deadlineSeconds,
            nowSeconds: clock,
            finalDescriptorPreflight: { request in
              await claimed.collector.finalDescriptorPreflight(for: request)
            }
          )
        )
        let adapterOutcome = adapterResult.outcome
        var postVerification = await adapter.postverify(
          operation,
          result: adapterResult
        )
        if case .satisfied = postVerification,
          let cleanupFailure = cleanupFailure(adapterResult.cleanupDisposition)
        {
          postVerification = .expectedResidual(cleanupFailure)
        }
        let stepStatus = stepStatus(
          adapterOutcome: adapterOutcome, postVerification: postVerification)
        let step = ExecutionStepOutcome(
          actionID: action.id,
          status: stepStatus,
          adapterOutcome: adapterOutcome,
          mutationDisposition: adapterResult.mutationDisposition,
          cleanupDisposition: adapterResult.cleanupDisposition,
          postVerification: postVerification
        )
        stepOutcomes.append(step)
        stepStatusByActionID[action.id] = step.status
        await emit(
          .stepFinished(step),
          index: &eventIndex,
          auditFailures: &auditFailures
        )
      }

      let releasePostVerification: [ReleasePostVerificationOutcome]
      #if DEBUG
        if usesTestingLegacyReleasePostverification {
          releasePostVerification = await collectTestingReleasePostVerification(
            groupIDs: unit.releaseGroupIDs,
            plan: plan,
            manifest: manifest,
            collector: claimed.collector
          )
        } else if let frozenReleaseComponent {
          releasePostVerification = await releasePostverificationCore.postverify(
            frozenReleaseComponent
          ).groups.map { group in
            ReleasePostVerificationOutcome(
              allocationGroupID: group.allocationGroupID,
              outcome: releasePostVerificationOutcome(group.outcome)
            )
          }
        } else {
          releasePostVerification = []
        }
      #else
        if let frozenReleaseComponent {
          releasePostVerification = await releasePostverificationCore.postverify(
            frozenReleaseComponent
          ).groups.map { group in
            ReleasePostVerificationOutcome(
              allocationGroupID: group.allocationGroupID,
              outcome: releasePostVerificationOutcome(group.outcome)
            )
          }
        } else {
          releasePostVerification = []
        }
      #endif
      for releaseOutcome in releasePostVerification {
        await emit(
          .releasePostVerificationFinished(releaseOutcome),
          index: &eventIndex,
          auditFailures: &auditFailures
        )
      }
      let status = unitStatus(
        stepOutcomes,
        releasePostVerification: releasePostVerification
      )
      let outcome = ExecutionUnitOutcome(
        id: unit.id,
        logicalActionIDs: unit.logicalActionIDs,
        prerequisiteActionIDs: unit.prerequisiteActionIDs,
        status: status,
        jitReport: jitReport,
        steps: stepOutcomes,
        releasePostVerification: releasePostVerification
      )
      outcomes.append(outcome)
      record(status, for: unit.logicalActionIDs, in: &statusByLogicalActionID)
      await emit(
        .unitFinished(outcome),
        index: &eventIndex,
        auditFailures: &auditFailures
      )
    }

    await emit(.applyFinished, index: &eventIndex, auditFailures: &auditFailures)
    return BestEffortApplyReport(
      manifest: manifest,
      startFailure: nil,
      unitOutcomes: outcomes,
      auditFailures: auditFailures.values
    )
  }

  private func cleanupFailure(
    _ disposition: ExecutionCleanupDisposition?
  ) -> ExecutionAdapterFailure? {
    guard let disposition else { return nil }
    switch disposition {
    case .gitWorktreeAttemptDirectory(let value): return value.failure
    }
  }

  private func freezeReleaseComponent(
    authority: EngineReleasePostverificationManifestAuthority?,
    jitClaim: EngineJITExecutionClaim,
    unit: RuntimeUnit
  ) throws -> FrozenReleasePostverificationComponent {
    guard let authority else {
      throw ReleasePostverificationLocatorError.operationMembershipMismatch
    }
    return try authority.authorizeAndFreeze(
      jitClaim: jitClaim,
      mutationOperations: unit.mutationSteps.map(\.operation),
      core: releasePostverificationCore
    )
  }

  private func collectJITReport(
    _ request: JITRevalidationRequest,
    collector: EngineRevalidationCollector
  ) async
    -> JITRevalidationReport
  {
    do {
      let collected = try await collector.collectJITEvidence(for: request)
      return Revalidator.evaluateJIT(request: request, collected: collected)
    } catch {
      return JITRevalidationReport(
        captureID: nil,
        oneShotNonce: request.oneShotNonce,
        actionOutcomes: [],
        globalFindings: [
          RevalidationFinding(
            actionID: nil,
            subject: .collector,
            kind: error is CancellationError ? .cancelled : .collectionFailed,
            observationFailure: ObservationFailure(
              code: String(reflecting: type(of: error)), collector: "jit-revalidation-source")
          )
        ]
      )
    }
  }

  private func invalidJITReport(
    oneShotNonce: Data,
    code: String
  ) -> JITRevalidationReport {
    JITRevalidationReport(
      captureID: nil,
      oneShotNonce: oneShotNonce,
      actionOutcomes: [],
      globalFindings: [
        RevalidationFinding(
          actionID: nil,
          subject: .collector,
          kind: .policyEvidenceMismatch,
          observationFailure: ObservationFailure(
            code: code,
            collector: "jit-revalidation-source"
          )
        )
      ]
    )
  }

  private func appendingJITFinding(
    _ report: JITRevalidationReport,
    code: String
  ) -> JITRevalidationReport {
    JITRevalidationReport(
      captureID: report.captureID,
      oneShotNonce: report.oneShotNonce,
      actionOutcomes: report.actionOutcomes,
      globalFindings: report.globalFindings + [
        RevalidationFinding(
          actionID: nil,
          subject: .collector,
          kind: .policyEvidenceMismatch,
          observationFailure: ObservationFailure(
            code: code,
            collector: "jit-revalidation-source"
          )
        )
      ]
    )
  }

  private func releasePostVerificationOutcome(
    _ outcome: DescriptorBoundAllocationGroupOutcome
  ) -> PostVerificationOutcome {
    switch outcome {
    case .allocationGroupReleased: return .satisfied
    case .rejected(let failure):
      switch failure {
      case .namespaceMissing, .topologyMissing:
        return .missing
      case .namespaceUnreadable(_, _, let value),
        .ownerSlotUnreadable(_, let value),
        .topologyUnreadable(let value):
        return .unreadable(value)
      case .namespaceUnknown(_, _, let reason),
        .ownerSlotUnknown(_, let reason),
        .topologyUnknown(let reason):
        return .unknown(reason)
      case .namespaceCollectionFailed(_, _, let value),
        .ownerSlotCollectionFailed(_, let value),
        .topologyCollectorFailed(let value):
        return .failed(value)
      case .leaseAlreadyConsumed:
        return releasePostverificationFailure("lease-already-consumed")
      case .namespaceIdentityMismatch:
        return releasePostverificationMismatch("namespace-identity-mismatch")
      case .namespaceAccessMismatch:
        return releasePostverificationMismatch("namespace-access-mismatch")
      case .namespaceContainmentMismatch:
        return releasePostverificationMismatch("namespace-containment-mismatch")
      case .ownerSlotStillReferencesExpectedObject:
        return releasePostverificationMismatch("owner-slot-still-references-expected-object")
      case .ownerSlotChangedAfterTopology:
        return releasePostverificationMismatch("owner-slot-changed-after-topology")
      case .topologyReceiptBindingMismatch:
        return releasePostverificationMismatch("topology-receipt-binding-mismatch")
      case .topologyReceiptNotFresh:
        return releasePostverificationMismatch("topology-receipt-not-fresh")
      case .topologyCaptureReused:
        return releasePostverificationMismatch("topology-capture-reused")
      case .allocationGroupStillAllocated:
        return releasePostverificationMismatch("allocation-group-still-allocated")
      case .invalidAllocationGroupReleaseEvidence:
        return releasePostverificationMismatch("invalid-allocation-group-release-evidence")
      }
    }
  }

  #if DEBUG
    private func collectTestingReleasePostVerification(
      groupIDs: [String],
      plan: ImmutablePlan,
      manifest: ExecutionManifest,
      collector: EngineRevalidationCollector
    ) async -> [ReleasePostVerificationOutcome] {
      do {
        let observations = try await collector.collectReleasePostVerification(
          for: ReleasePostVerificationRequest(
            plan: plan,
            manifest: manifest,
            allocationGroupIDs: groupIDs
          ))
        let groups = Dictionary(grouping: observations) {
          RawUTF8Key($0.allocationGroupID)
        }
        let expectedGroupKeys = Set(groupIDs.map(RawUTF8Key.init))
        let hasUnexpected = groups.keys.contains { !expectedGroupKeys.contains($0) }
        return groupIDs.map { groupID in
          guard !hasUnexpected else {
            return ReleasePostVerificationOutcome(
              allocationGroupID: groupID,
              outcome: releasePostverificationFailure(
                "unexpected-release-postverification"
              ))
          }
          guard let matches = groups[RawUTF8Key(groupID)] else {
            return ReleasePostVerificationOutcome(
              allocationGroupID: groupID,
              outcome: .missing
            )
          }
          guard matches.count == 1, let observation = matches.first else {
            return ReleasePostVerificationOutcome(
              allocationGroupID: groupID,
              outcome: releasePostverificationFailure(
                "duplicate-release-postverification"
              ))
          }
          let outcome: PostVerificationOutcome
          switch observation.released {
          case .known(true): outcome = .satisfied
          case .known(false):
            outcome = .notSatisfied(code: "allocation-group-not-released")
          case .absent: outcome = .missing
          case .unknown(let reason): outcome = .unknown(reason)
          case .unreadable(let failure): outcome = .unreadable(failure)
          case .failed(let failure): outcome = .failed(failure)
          }
          return ReleasePostVerificationOutcome(
            allocationGroupID: groupID,
            outcome: outcome
          )
        }
      } catch {
        return groupIDs.map {
          ReleasePostVerificationOutcome(
            allocationGroupID: $0,
            outcome: releasePostverificationFailure(
              String(reflecting: type(of: error))
            ))
        }
      }
    }
  #endif

  private func releasePostverificationMismatch(_ code: String) -> PostVerificationOutcome {
    .notSatisfied(code: code)
  }

  private func releasePostverificationFailure(_ code: String) -> PostVerificationOutcome {
    .failed(
      ObservationFailure(
        code: code,
        collector: "descriptor-bound-release-postverification"
      ))
  }

  private static func failClosedReleasePostverificationCore()
    -> DescriptorBoundReleasePostverificationCore
  {
    DescriptorBoundReleasePostverificationCore(
      topologyCollector: EngineReleasePostverificationTopologyCollector {
        _ in throw ReleasePostverificationRuntimeError.topologyCollectorUnavailable
      }
    )
  }

  private func emit(
    _ event: ExecutionEvent,
    index: inout Int,
    auditFailures: inout AuditFailureAccumulator
  ) async {
    let currentIndex = index
    index += 1
    await eventSink.emit(event)
    guard let auditSink, auditFailures.persistenceEnabled else { return }
    do {
      try await auditSink.record(event, epochID: auditFailures.epochID)
    } catch {
      // Optional persistence is latched off after the first failure for this apply epoch. Shell/TUI
      // delivery remains independent above, while a failing sink cannot amplify one storage fault
      // into an event-sized failure transcript.
      auditFailures.persistenceEnabled = false
      let artifactWarning = (error as? SafeArtifactWriteError)?.warning
      let errorValue = error as NSError
      let posixErrno =
        artifactWarning?.errno
        ?? (errorValue.domain == NSPOSIXErrorDomain ? Int32(exactly: errorValue.code) : nil)
      let failure = AuditWriteFailure(
        eventIndex: currentIndex,
        code: artifactWarning?.code ?? String(reflecting: type(of: error)),
        errno: posixErrno,
        retainedLocator: artifactWarning?.retainedLocator
      )
      auditFailures.values.append(failure)
      await eventSink.emit(.auditWriteFailed(failure))
    }
  }

  private func startFailure(
    _ failure: ApplyStartFailure,
    manifest: ExecutionManifest? = nil
  ) -> BestEffortApplyReport {
    BestEffortApplyReport(
      manifest: manifest,
      startFailure: failure,
      unitOutcomes: [],
      auditFailures: []
    )
  }

  private func manifestMatches(
    _ manifest: ExecutionManifest,
    plan: ImmutablePlan,
    overlay: DecisionOverlay,
    validated: ValidatedDecisionOverlay
  ) -> Bool {
    manifest.planHash == plan.planHash
      && manifest.overlayHash == overlay.overlayHash
      && manifest.epoch.semanticReferenceTimeSeconds == manifest.epoch.issuedAtSeconds
      && manifest.currentCaptureID != plan.globalFacts.captureID
      && manifest.consentRequirements.allSatisfy {
        $0.originalSemanticReferenceTimeSeconds
          == plan.globalFacts.semanticReferenceTimeSeconds
          && $0.executionReferenceTimeSeconds
            == manifest.epoch.semanticReferenceTimeSeconds
      }
      && manifest.executionActionIDs == validated.executionSteps.map(\.action.id)
      && manifest.jitRevalidationActionIDs
        == validated.executionSteps.map { $0.jitRevalidationActions.map(\.id) }
  }

  private func buildRuntimeUnits(
    manifest: ExecutionManifest,
    plan: ImmutablePlan,
    validated: ValidatedDecisionOverlay
  ) throws -> [RuntimeUnit] {
    enum GraphError: Error { case invalid }

    let actionByID = Dictionary(uniqueKeysWithValues: plan.actions.map { ($0.id, $0) })
    let releaseSteps = validated.executionSteps.filter { $0.releaseSet != nil }
    let selectedGroups = Set(
      releaseSteps.compactMap { $0.releaseSet.map { RawUTF8Key($0.allocationGroupID) } })
    var compoundByGroup: [RawUTF8Key: CompoundReleaseUnit] = [:]
    for compound in manifest.compoundReleaseUnits {
      guard !compound.allocationGroupIDs.isEmpty, !compound.ownerActionIDs.isEmpty else {
        throw GraphError.invalid
      }
      for groupID in compound.allocationGroupIDs {
        let groupKey = RawUTF8Key(groupID)
        guard selectedGroups.contains(groupKey), compoundByGroup[groupKey] == nil else {
          throw GraphError.invalid
        }
        compoundByGroup[groupKey] = compound
      }
      let expectedOwners = Set(
        plan.releaseSets.filter {
          Set(compound.allocationGroupIDs.map(RawUTF8Key.init)).contains(
            RawUTF8Key($0.allocationGroupID))
        }.flatMap(\.ownerActionIDs)
      ).sorted()
      guard expectedOwners == compound.ownerActionIDs else { throw GraphError.invalid }
    }
    guard Set(compoundByGroup.keys) == selectedGroups else { throw GraphError.invalid }

    var units: [RuntimeUnit] = []
    var emittedCompounds = Set<ExecutionUnitID>()
    var mutationActionIDs = Set<ActionID>()
    for step in validated.executionSteps {
      guard let releaseSet = step.releaseSet else {
        guard mutationActionIDs.insert(step.action.id).inserted else {
          throw GraphError.invalid
        }
        units.append(
          RuntimeUnit(
            id: .action(step.action.id),
            logicalActionIDs: [step.action.id],
            prerequisiteActionIDs: step.prerequisiteStepActionIDs,
            jitActionIDs: Set(step.jitRevalidationActions.map(\.id)).sorted(),
            releaseGroupIDs: [],
            mutationSteps: [
              try mutationStep(for: step.action, internalPrerequisiteIDs: [])
            ]
          ))
        continue
      }
      guard let compound = compoundByGroup[RawUTF8Key(releaseSet.allocationGroupID)] else {
        throw GraphError.invalid
      }
      let unitID = ExecutionUnitID.compoundRelease(compound.allocationGroupIDs)
      guard emittedCompounds.insert(unitID).inserted else { continue }
      let memberSteps = releaseSteps.filter {
        guard let groupID = $0.releaseSet?.allocationGroupID else { return false }
        return compound.allocationGroupIDs.map(RawUTF8Key.init).contains(RawUTF8Key(groupID))
      }
      let logicalIDs = memberSteps.map(\.action.id)
      let prerequisiteIDs = Set(
        memberSteps.flatMap(\.prerequisiteStepActionIDs)
      ).subtracting(logicalIDs).sorted()
      let jitIDs = Set(memberSteps.flatMap { $0.jitRevalidationActions.map(\.id) }).sorted()
      let ownerActions = try compound.ownerActionIDs.map { actionID -> ActionDefinition in
        guard mutationActionIDs.insert(actionID).inserted,
          let action = actionByID[actionID]
        else { throw GraphError.invalid }
        return action
      }
      let ownerIDs = Set(ownerActions.map(\.id))
      let orderedOwnerActions = try topologicallyOrderedOwnerActions(ownerActions)
      units.append(
        RuntimeUnit(
          id: unitID,
          logicalActionIDs: logicalIDs,
          prerequisiteActionIDs: prerequisiteIDs,
          jitActionIDs: jitIDs,
          releaseGroupIDs: compound.allocationGroupIDs,
          mutationSteps: try orderedOwnerActions.map {
            try mutationStep(
              for: $0,
              internalPrerequisiteIDs: $0.prerequisiteActionIDs.filter(ownerIDs.contains)
            )
          }
        ))
    }

    var unitByLogicalID: [ActionID: ExecutionUnitID] = [:]
    for unit in units {
      for actionID in unit.logicalActionIDs {
        guard unitByLogicalID.updateValue(unit.id, forKey: actionID) == nil else {
          throw GraphError.invalid
        }
      }
    }
    guard
      units.allSatisfy({ unit in
        unit.prerequisiteActionIDs.allSatisfy { unitByLogicalID[$0] != nil }
      })
    else { throw GraphError.invalid }

    var remaining = units
    var emittedLogicalIDs = Set<ActionID>()
    var ordered: [RuntimeUnit] = []
    while !remaining.isEmpty {
      guard
        let index = remaining.firstIndex(where: { unit in
          Set(unit.prerequisiteActionIDs).isSubset(of: emittedLogicalIDs)
        })
      else { throw GraphError.invalid }
      let next = remaining.remove(at: index)
      ordered.append(next)
      emittedLogicalIDs.formUnion(next.logicalActionIDs)
    }
    return ordered
  }

  private func mutationStep(
    for action: ActionDefinition,
    internalPrerequisiteIDs: [ActionID]
  ) throws -> MutationStep {
    enum OperationError: Error { case unsupported }
    let target = BoundMutationTarget(action: action)
    let operation: ExecutionAdapterOperation
    switch action.prototype.adapterContract {
    case .genericRemove(let contract):
      guard case .explicitlyNotApplicable = target.expectedContent else {
        throw OperationError.unsupported
      }
      operation = .genericRemove(target, contract)
    case .gitWorktreeRemove(let contract): operation = .gitWorktreeRemove(target, contract)
    case .gitWorktreeDiscardLocalChanges(let contract):
      operation = .gitWorktreeDiscardLocalChanges(target, contract)
    case .codexCleanTemporary(let contract): operation = .codexCleanTemporary(target, contract)
    case .versionedArtifactRemove(let contract):
      operation = .versionedArtifactRemove(target, contract)
    case .completeReleaseSetRemove: throw OperationError.unsupported
    }
    return MutationStep(
      action: action,
      operation: operation,
      prerequisiteActionIDs: internalPrerequisiteIDs.sorted()
    )
  }

  private func topologicallyOrderedOwnerActions(
    _ actions: [ActionDefinition]
  ) throws -> [ActionDefinition] {
    enum OwnerGraphError: Error { case invalid }
    let actionIDs = Set(actions.map(\.id))
    guard actionIDs.count == actions.count else { throw OwnerGraphError.invalid }
    var remaining = actions.sorted { $0.id < $1.id }
    var emitted = Set<ActionID>()
    var result: [ActionDefinition] = []
    while !remaining.isEmpty {
      guard
        let index = remaining.firstIndex(where: {
          Set($0.prerequisiteActionIDs.filter(actionIDs.contains)).isSubset(of: emitted)
        })
      else { throw OwnerGraphError.invalid }
      let next = remaining.remove(at: index)
      result.append(next)
      emitted.insert(next.id)
    }
    return result
  }

  private func stepStatus(
    adapterOutcome: AdapterOperationOutcome,
    postVerification: PostVerificationOutcome
  ) -> ExecutionStepStatus {
    if case .cancelled = adapterOutcome { return .cancelled }
    if case .timedOut = adapterOutcome { return .expired }
    if case .notStarted(let reason) = adapterOutcome {
      switch reason {
      case .taskCancelled: return .cancelled
      case .epochExpired: return .expired
      case .preparationSuperseded: return .superseded
      case .prerequisiteFailed: return .skippedPrerequisite
      }
    }
    if case .succeeded = adapterOutcome {
      switch postVerification {
      case .satisfied:
        return .succeeded
      case .expectedResidual:
        return .partiallySucceeded
      default:
        return .failed
      }
    }
    return .failed
  }

  private func unitStatus(
    _ steps: [ExecutionStepOutcome],
    releasePostVerification: [ReleasePostVerificationOutcome]
  ) -> ExecutionUnitStatus {
    guard !steps.isEmpty else { return .failed }
    if steps.allSatisfy({ $0.status == .succeeded }) {
      if releasePostVerification.allSatisfy({ $0.outcome == .satisfied }) {
        return .succeeded
      }
      if releasePostVerification.contains(where: { $0.outcome == .satisfied }) {
        return .partiallyFailed
      }
      return .failed
    }
    if steps.allSatisfy({ $0.status == .expired }) { return .expired }
    if steps.allSatisfy({ $0.status == .superseded }) { return .superseded }
    if steps.allSatisfy({ $0.status == .cancelled }) { return .cancelled }
    if steps.contains(where: {
      $0.status == .succeeded || $0.status == .partiallySucceeded
    }) {
      return .partiallyFailed
    }
    return .failed
  }

  private func unitOutcome(
    _ unit: RuntimeUnit,
    status: ExecutionUnitStatus,
    jitReport: JITRevalidationReport? = nil
  ) -> ExecutionUnitOutcome {
    ExecutionUnitOutcome(
      id: unit.id,
      logicalActionIDs: unit.logicalActionIDs,
      prerequisiteActionIDs: unit.prerequisiteActionIDs,
      status: status,
      jitReport: jitReport,
      steps: []
    )
  }

  private func record(
    _ status: ExecutionUnitStatus,
    for actionIDs: [ActionID],
    in statuses: inout [ActionID: ExecutionUnitStatus]
  ) {
    for actionID in actionIDs { statuses[actionID] = status }
  }
}
