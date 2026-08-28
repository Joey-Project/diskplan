import DiskplanPolicy
import Foundation

/// Engine composition may pass this handle across its target boundary, but cannot construct or
/// inspect its source. Snapshot construction remains inside DiskplanExecution.
@_spi(DiskplanEngine)
public final class EngineJITRevalidationCollector: @unchecked Sendable {
  private let source: any JITRevalidationEvidenceSource

  init(source: any JITRevalidationEvidenceSource) { self.source = source }

  fileprivate func collect(_ request: JITRevalidationRequest) async throws
    -> CurrentRevalidationSnapshot
  {
    try await source.collectJITEvidence(for: request)
  }
}

public actor BestEffortApplyCoordinator {
  private struct RuntimeUnit: Sendable {
    let id: ExecutionUnitID
    let logicalActionIDs: [ActionID]
    let prerequisiteActionIDs: [ActionID]
    let jitActionIDs: [ActionID]
    let releaseGroupIDs: [String]
    let mutationActions: [ActionDefinition]
  }

  private let collector: EngineJITRevalidationCollector
  private let adapter: any ExecutionMutationAdapter
  private let eventSink: any ExecutionEventSink
  private let auditSink: (any ExecutionAuditSink)?
  private let clock: @Sendable () -> Int64

  @_spi(DiskplanEngine)
  public init(
    collector: EngineJITRevalidationCollector,
    adapter: any ExecutionMutationAdapter,
    eventSink: any ExecutionEventSink = ShellExecutionEventSink(),
    auditSink: (any ExecutionAuditSink)? = nil
  ) {
    self.collector = collector
    self.adapter = adapter
    self.eventSink = eventSink
    self.auditSink = auditSink
    self.clock = { Int64(Date().timeIntervalSince1970.rounded(.down)) }
  }

  init(
    collector: EngineJITRevalidationCollector,
    adapter: any ExecutionMutationAdapter,
    eventSink: any ExecutionEventSink,
    auditSink: (any ExecutionAuditSink)?,
    clock: @escaping @Sendable () -> Int64
  ) {
    self.collector = collector
    self.adapter = adapter
    self.eventSink = eventSink
    self.auditSink = auditSink
    self.clock = clock
  }

  /// Claims one Phase 4 authorization and never accepts a dry-run report or serialized token.
  public func apply(
    authorization: ApplyAuthorization,
    plan: ImmutablePlan,
    overlay: DecisionOverlay
  ) async -> BestEffortApplyReport {
    guard let manifest = await authorization.claimManifest() else {
      return startFailure(.authorizationAlreadyClaimed)
    }
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

    var auditFailures: [AuditWriteFailure] = []
    var eventIndex = 0
    await emit(
      .applyStarted(epochID: manifest.epoch.epochID),
      index: &eventIndex,
      auditFailures: &auditFailures
    )

    var outcomes: [ExecutionUnitOutcome] = []
    var statusByLogicalActionID: [ActionID: ExecutionUnitStatus] = [:]
    for unit in units {
      if unit.prerequisiteActionIDs.contains(where: {
        statusByLogicalActionID[$0] != .succeeded
      }) {
        let outcome = unitOutcome(unit, status: .skippedPrerequisite)
        outcomes.append(outcome)
        record(outcome.status, for: unit.logicalActionIDs, in: &statusByLogicalActionID)
        await emit(
          .unitFinished(unit.id, outcome.status),
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
          .unitFinished(unit.id, outcome.status),
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
          .unitFinished(unit.id, outcome.status),
          index: &eventIndex,
          auditFailures: &auditFailures
        )
        continue
      }

      await emit(
        .unitStarted(unit.id), index: &eventIndex, auditFailures: &auditFailures)
      for action in unit.mutationActions {
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

      let jitRequest = JITRevalidationRequest(
        plan: plan,
        validatedOverlay: validated,
        epoch: manifest.epoch,
        actionIDs: unit.jitActionIDs,
        releaseGroupIDs: unit.releaseGroupIDs
      )
      let jitReport = await collectJITReport(jitRequest)
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
          .unitFinished(unit.id, outcome.status),
          index: &eventIndex,
          auditFailures: &auditFailures
        )
        continue
      }

      var stepOutcomes: [ExecutionStepOutcome] = []
      for action in unit.mutationActions {
        guard clock() < manifest.epoch.deadlineSeconds else {
          stepOutcomes.append(
            ExecutionStepOutcome(
              actionID: action.id,
              status: .expired,
              adapterOutcome: .cancelled,
              postVerification: .unknown(.timedOut)
            ))
          continue
        }
        guard let operation = operation(for: action) else {
          stepOutcomes.append(
            ExecutionStepOutcome(
              actionID: action.id,
              status: .failed,
              adapterOutcome: .failed(
                ExecutionAdapterFailure(code: "unsupported-action-adapter")),
              postVerification: .unknown(.unsupported)
            ))
          continue
        }
        let adapterOutcome = await adapter.apply(operation)
        let postVerification = await adapter.postverify(operation)
        let stepStatus = stepStatus(
          adapterOutcome: adapterOutcome, postVerification: postVerification)
        let step = ExecutionStepOutcome(
          actionID: action.id,
          status: stepStatus,
          adapterOutcome: adapterOutcome,
          postVerification: postVerification
        )
        stepOutcomes.append(step)
        await emit(
          .stepFinished(action.id, stepStatus),
          index: &eventIndex,
          auditFailures: &auditFailures
        )
      }

      let status = unitStatus(stepOutcomes)
      let outcome = ExecutionUnitOutcome(
        id: unit.id,
        logicalActionIDs: unit.logicalActionIDs,
        prerequisiteActionIDs: unit.prerequisiteActionIDs,
        status: status,
        jitReport: jitReport,
        steps: stepOutcomes
      )
      outcomes.append(outcome)
      record(status, for: unit.logicalActionIDs, in: &statusByLogicalActionID)
      await emit(
        .unitFinished(unit.id, status),
        index: &eventIndex,
        auditFailures: &auditFailures
      )
    }

    await emit(.applyFinished, index: &eventIndex, auditFailures: &auditFailures)
    return BestEffortApplyReport(
      manifest: manifest,
      startFailure: nil,
      unitOutcomes: outcomes,
      auditFailures: auditFailures
    )
  }

  private func collectJITReport(_ request: JITRevalidationRequest) async
    -> JITRevalidationReport
  {
    do {
      let snapshot = try await collector.collect(request)
      return Revalidator.evaluateJIT(request: request, snapshot: snapshot)
    } catch {
      return JITRevalidationReport(
        actionOutcomes: [],
        globalFindings: [
          RevalidationFinding(
            actionID: nil,
            subject: .collector,
            kind: .collectionFailed,
            observationFailure: ObservationFailure(
              code: String(reflecting: type(of: error)), collector: "jit-revalidation-source")
          )
        ]
      )
    }
  }

  private func emit(
    _ event: ExecutionEvent,
    index: inout Int,
    auditFailures: inout [AuditWriteFailure]
  ) async {
    let currentIndex = index
    index += 1
    await eventSink.emit(event)
    guard let auditSink else { return }
    do {
      try await auditSink.record(event)
    } catch {
      let failure = AuditWriteFailure(
        eventIndex: currentIndex,
        code: String(reflecting: type(of: error))
      )
      auditFailures.append(failure)
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
      && manifest.epoch.semanticReferenceTimeSeconds
        == plan.globalFacts.semanticReferenceTimeSeconds
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
    let selectedGroups = Set(releaseSteps.compactMap { $0.releaseSet?.allocationGroupID })
    var compoundByGroup: [String: CompoundReleaseUnit] = [:]
    for compound in manifest.compoundReleaseUnits {
      guard !compound.allocationGroupIDs.isEmpty, !compound.ownerActionIDs.isEmpty else {
        throw GraphError.invalid
      }
      for groupID in compound.allocationGroupIDs {
        guard selectedGroups.contains(groupID), compoundByGroup[groupID] == nil else {
          throw GraphError.invalid
        }
        compoundByGroup[groupID] = compound
      }
      let expectedOwners = Set(
        plan.releaseSets.filter {
          compound.allocationGroupIDs.contains($0.allocationGroupID)
        }.flatMap(\.ownerActionIDs)
      ).sorted()
      guard expectedOwners == compound.ownerActionIDs else { throw GraphError.invalid }
    }
    guard Set(compoundByGroup.keys) == selectedGroups else { throw GraphError.invalid }

    var units: [RuntimeUnit] = []
    var emittedCompounds = Set<ExecutionUnitID>()
    var mutationOwnerIDs = Set<ActionID>()
    for step in validated.executionSteps {
      guard let releaseSet = step.releaseSet else {
        units.append(
          RuntimeUnit(
            id: .action(step.action.id),
            logicalActionIDs: [step.action.id],
            prerequisiteActionIDs: step.prerequisiteStepActionIDs,
            jitActionIDs: step.jitRevalidationActions.map(\.id),
            releaseGroupIDs: [],
            mutationActions: [step.action]
          ))
        continue
      }
      guard let compound = compoundByGroup[releaseSet.allocationGroupID] else {
        throw GraphError.invalid
      }
      let unitID = ExecutionUnitID.compoundRelease(compound.allocationGroupIDs)
      guard emittedCompounds.insert(unitID).inserted else { continue }
      let memberSteps = releaseSteps.filter {
        guard let groupID = $0.releaseSet?.allocationGroupID else { return false }
        return compound.allocationGroupIDs.contains(groupID)
      }
      let logicalIDs = memberSteps.map(\.action.id)
      let prerequisiteIDs = Set(
        memberSteps.flatMap(\.prerequisiteStepActionIDs)
      ).subtracting(logicalIDs).sorted()
      let jitIDs = Set(memberSteps.flatMap { $0.jitRevalidationActions.map(\.id) }).sorted()
      let ownerActions = try compound.ownerActionIDs.map { actionID -> ActionDefinition in
        guard mutationOwnerIDs.insert(actionID).inserted,
          let action = actionByID[actionID]
        else { throw GraphError.invalid }
        return action
      }
      units.append(
        RuntimeUnit(
          id: unitID,
          logicalActionIDs: logicalIDs,
          prerequisiteActionIDs: prerequisiteIDs,
          jitActionIDs: jitIDs,
          releaseGroupIDs: compound.allocationGroupIDs,
          mutationActions: ownerActions
        ))
    }

    let unitByLogicalID = Dictionary(
      uniqueKeysWithValues: units.flatMap { unit in
        unit.logicalActionIDs.map { ($0, unit.id) }
      })
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

  private func operation(for action: ActionDefinition) -> ExecutionAdapterOperation? {
    let target = BoundMutationTarget(action: action)
    switch action.prototype.adapterContract {
    case .genericRemove(let contract): return .genericRemove(target, contract)
    case .gitWorktreeRemove(let contract): return .gitWorktreeRemove(target, contract)
    case .gitWorktreeDiscardLocalChanges(let contract):
      return .gitWorktreeDiscardLocalChanges(target, contract)
    case .codexCleanTemporary(let contract): return .codexCleanTemporary(target, contract)
    case .versionedArtifactRemove(let contract):
      return .versionedArtifactRemove(target, contract)
    case .completeReleaseSetRemove: return nil
    }
  }

  private func stepStatus(
    adapterOutcome: AdapterOperationOutcome,
    postVerification: PostVerificationOutcome
  ) -> ExecutionStepStatus {
    if case .cancelled = adapterOutcome { return .cancelled }
    guard case .succeeded = adapterOutcome, case .satisfied = postVerification else {
      return .failed
    }
    return .succeeded
  }

  private func unitStatus(_ steps: [ExecutionStepOutcome]) -> ExecutionUnitStatus {
    guard !steps.isEmpty else { return .failed }
    if steps.allSatisfy({ $0.status == .succeeded }) { return .succeeded }
    if steps.allSatisfy({ $0.status == .expired }) { return .expired }
    if steps.allSatisfy({ $0.status == .cancelled }) { return .cancelled }
    if steps.contains(where: { $0.status == .succeeded }) { return .partiallyFailed }
    return .failed
  }

  private func unitOutcome(
    _ unit: RuntimeUnit,
    status: ExecutionUnitStatus
  ) -> ExecutionUnitOutcome {
    ExecutionUnitOutcome(
      id: unit.id,
      logicalActionIDs: unit.logicalActionIDs,
      prerequisiteActionIDs: unit.prerequisiteActionIDs,
      status: status,
      jitReport: nil,
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
