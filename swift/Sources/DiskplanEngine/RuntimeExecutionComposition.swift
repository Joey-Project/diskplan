import DiskplanEngineCore
@_spi(DiskplanEngine) import DiskplanExecution
import DiskplanPolicy
import DiskplanProto
import Foundation

package final class DiskplanRuntimeExecutionBackend: RuntimeExecutionBackend, @unchecked Sendable {
  private let composition: EngineExecutionComposition
  private let idGenerator: @Sendable () -> Data

  package init(
    composition: EngineExecutionComposition,
    idGenerator: @escaping @Sendable () -> Data = {
      Data(UUID().uuidString.lowercased().utf8)
    }
  ) {
    self.composition = composition
    self.idGenerator = idGenerator
  }

  package func prepareDryRun(
    context: RuntimeExecutionPlanContext,
    lifetimeSeconds: Int64
  ) async throws -> RuntimePreparedDryRun {
    let result = try await composition.preparation.prepare(
      plan: context.plan,
      overlay: context.overlay,
      mode: .dryRun,
      lifetimeSeconds: lifetimeSeconds
    )
    let report: DryRunReport
    switch result {
    case .dryRun(let value):
      report = value
    case .rejected(let revalidation):
      report = DryRunReport(revalidation: revalidation)
    case .applyReady:
      throw DiskplanRuntimeExecutionProjectionError.unexpectedPreparationResult
    }
    return try RuntimeExecutionProjector(context: context, nextID: idGenerator)
      .dryRun(report)
  }

  package func prepareApplyReview(
    context: RuntimeExecutionPlanContext,
    lifetimeSeconds: Int64
  ) async throws -> RuntimePreparedApplyReview {
    let result = try await composition.preparation.prepare(
      plan: context.plan,
      overlay: context.overlay,
      mode: .apply,
      lifetimeSeconds: lifetimeSeconds
    )
    guard case .applyReady(let ready, let capability) = result else {
      if case .rejected = result { throw RuntimeExecutionBackendFailure.revalidationFailed }
      throw DiskplanRuntimeExecutionProjectionError.unexpectedPreparationResult
    }
    let projector = try RuntimeExecutionProjector(context: context, nextID: idGenerator)
    let review = try projector.applyReview(ready)
    let composition = composition
    let executionID = try projector.generatedIdentifier()
    return RuntimePreparedApplyReview(
      projection: review,
      attempt: RuntimePreparedApplyAttempt { confirmation, exactContext in
        guard
          exactContext.plan.planHash == context.plan.planHash,
          exactContext.overlay.overlayHash == context.overlay.overlayHash,
          confirmation.review.applyReviewID == review.applyReviewID,
          confirmation.review.reviewBindingSha256.value == ready.reviewBindingHash.bytes,
          confirmation.review.projectionID == review.projectionID,
          confirmation.review.planSha256 == review.planSha256,
          confirmation.review.overlaySha256 == review.overlaySha256,
          runtimeForceConfirmationMatches(
            confirmed: confirmation.confirmedForceActionIDs.map(\.value),
            expected: ready.forceWarningActionIDs.map(\.digest.bytes)
          )
        else { throw DiskplanRuntimeExecutionProjectionError.confirmationBindingMismatch }

        let authorization = try await composition.preparation.authorizeApply(
          capability,
          ready: ready,
          plan: exactContext.plan,
          overlay: exactContext.overlay,
          confirmation: .confirm(ready)
        )
        return try await RuntimeApplyRun.start(
          executionID: executionID,
          composition: composition,
          authorization: authorization,
          plan: exactContext.plan,
          overlay: exactContext.overlay,
          review: confirmation.review,
          projector: projector
        )
      }
    )
  }
}

func runtimeForceConfirmationMatches(confirmed: [Data], expected: [Data]) -> Bool {
  Set(confirmed).count == confirmed.count
    && Set(expected).count == expected.count
    && Set(confirmed) == Set(expected)
}

enum DiskplanRuntimeExecutionProjectionError: Error, Equatable {
  case unexpectedPreparationResult
  case missingActionPreview
  case missingReleaseSet
  case confirmationBindingMismatch
  case eventStreamInvariant
  case invalidGeneratedIdentifier
}

struct RuntimeApplyCaptureBudget: Equatable, Sendable {
  static let runtimeDefault = RuntimeApplyCaptureBudget(
    maximumEventCount: 25_000,
    maximumAccountedBytes: 32 * 1_024 * 1_024,
    perEventOverheadBytes: 512,
    terminalReserveBytes: 4 * 1_024
  )

  let maximumEventCount: UInt64
  let maximumAccountedBytes: UInt64
  let perEventOverheadBytes: UInt64
  let terminalReserveBytes: UInt64
}

struct RuntimeSourceEventEstimate: Equatable, Sendable {
  let projectedEventCount: UInt64
  let accountedUpperBoundBytes: UInt64
}

private struct RuntimeSourceBudgetCounter {
  private static let fixedEventOverhead: UInt64 = 1_024
  private static let fixedFieldOverhead: UInt64 = 256
  private static let maximumNestedElementCount = 25_000
  private static let maximumDynamicBytes = 4_096

  private(set) var accountedBytes = fixedEventOverhead
  private var nestedElementCount = 0

  mutating func collection(_ count: Int) -> Bool {
    guard count >= 0,
      count <= Self.maximumNestedElementCount,
      nestedElementCount <= Self.maximumNestedElementCount - count
    else { return false }
    nestedElementCount += count
    add(UInt64(count), multipliedBy: Self.fixedFieldOverhead)
    return accountedBytes != .max
  }

  mutating func dynamicString(_ value: String) -> Bool {
    let count = value.utf8.count
    guard count <= Self.maximumDynamicBytes else { return false }
    add(Self.fixedFieldOverhead)
    add(UInt64(count))
    return accountedBytes != .max
  }

  mutating func rawComponent(_ value: Data) -> Bool {
    guard !value.isEmpty, value.count <= Self.maximumDynamicBytes else { return false }
    add(Self.fixedFieldOverhead)
    add(UInt64(value.count))
    return accountedBytes != .max
  }

  mutating func digest(_ value: Data) -> Bool {
    guard value.count == 32 else { return false }
    add(Self.fixedFieldOverhead + 32)
    return accountedBytes != .max
  }

  mutating func optionalScalarField(_ present: Bool = true) {
    if present { add(Self.fixedFieldOverhead) }
  }

  private mutating func add(_ value: UInt64) {
    let result = accountedBytes.addingReportingOverflow(value)
    accountedBytes = result.overflow ? .max : result.partialValue
  }

  private mutating func add(_ lhs: UInt64, multipliedBy rhs: UInt64) {
    let product = lhs.multipliedReportingOverflow(by: rhs)
    guard !product.overflow else {
      accountedBytes = .max
      return
    }
    add(product.partialValue)
  }
}

enum RuntimeSourceEventPreflight {
  static func estimate(_ event: ExecutionEvent) -> RuntimeSourceEventEstimate? {
    var counter = RuntimeSourceBudgetCounter()
    let projectedEventCount: UInt64
    switch event {
    case .applyStarted(let epochID):
      guard counter.dynamicString(epochID) else { return nil }
      projectedEventCount = 1
    case .unitStarted(let executionUnit):
      guard unit(executionUnit, counter: &counter) else { return nil }
      projectedEventCount = 1
    case .forceRequiredWarning(let actionID):
      guard counter.digest(actionID.digest.bytes) else { return nil }
      projectedEventCount = 1
    case .stepFinished(let outcome):
      guard step(outcome, counter: &counter) else { return nil }
      projectedEventCount = 1
    case .releasePostVerificationFinished(let outcome):
      guard release(outcome, counter: &counter) else { return nil }
      projectedEventCount = 1
    case .unitFinished(let outcome):
      guard unitOutcome(outcome, counter: &counter) else { return nil }
      projectedEventCount =
        outcome.status == .skippedPrerequisite
          || (outcome.status == .jitRejected && outcome.jitReport != nil) ? 2 : 1
    case .auditWriteFailed(let failure):
      guard counter.dynamicString(failure.code) else { return nil }
      counter.optionalScalarField(failure.errno != nil)
      projectedEventCount = 1
    case .applyFinished:
      projectedEventCount = 1
    }
    let eventOverhead = projectedEventCount.multipliedReportingOverflow(by: 512)
    let total = counter.accountedBytes.addingReportingOverflow(eventOverhead.partialValue)
    guard !eventOverhead.overflow, !total.overflow else { return nil }
    return RuntimeSourceEventEstimate(
      projectedEventCount: projectedEventCount,
      accountedUpperBoundBytes: total.partialValue
    )
  }

  private static func unit(
    _ unit: ExecutionUnitID,
    counter: inout RuntimeSourceBudgetCounter
  ) -> Bool {
    switch unit {
    case .action(let actionID):
      counter.digest(actionID.digest.bytes)
    case .compoundRelease(let allocationGroupIDs):
      counter.collection(allocationGroupIDs.count)
        && allocationGroupIDs.allSatisfy { counter.dynamicString($0) }
    }
  }

  private static func unitOutcome(
    _ outcome: ExecutionUnitOutcome,
    counter: inout RuntimeSourceBudgetCounter
  ) -> Bool {
    guard unit(outcome.id, counter: &counter),
      counter.collection(outcome.logicalActionIDs.count),
      outcome.logicalActionIDs.allSatisfy({ counter.digest($0.digest.bytes) }),
      counter.collection(outcome.prerequisiteActionIDs.count),
      outcome.prerequisiteActionIDs.allSatisfy({ counter.digest($0.digest.bytes) }),
      counter.collection(outcome.steps.count),
      outcome.steps.allSatisfy({ step($0, counter: &counter) }),
      counter.collection(outcome.releasePostVerification.count),
      outcome.releasePostVerification.allSatisfy({ release($0, counter: &counter) })
    else { return false }
    return outcome.jitReport.map { jit($0, counter: &counter) } ?? true
  }

  private static func jit(
    _ report: JITRevalidationReport,
    counter: inout RuntimeSourceBudgetCounter
  ) -> Bool {
    counter.optionalScalarField(report.captureID != nil)
    guard counter.collection(report.actionOutcomes.count),
      report.actionOutcomes.allSatisfy({ outcome in
        counter.digest(outcome.actionID.digest.bytes)
          && counter.collection(outcome.findings.count)
          && outcome.findings.allSatisfy { finding($0, counter: &counter) }
      }),
      counter.collection(report.globalFindings.count),
      report.globalFindings.allSatisfy({ finding($0, counter: &counter) })
    else { return false }
    return true
  }

  private static func finding(
    _ finding: RevalidationFinding,
    counter: inout RuntimeSourceBudgetCounter
  ) -> Bool {
    if let actionID = finding.actionID,
      !counter.digest(actionID.digest.bytes)
    {
      return false
    }
    guard subject(finding.subject, counter: &counter) else { return false }
    if let failure = finding.observationFailure {
      guard counter.dynamicString(failure.code),
        counter.dynamicString(failure.collector)
      else { return false }
    }
    counter.optionalScalarField(finding.unknownReason != nil)
    return true
  }

  private static func subject(
    _ subject: RevalidationSubject,
    counter: inout RuntimeSourceBudgetCounter
  ) -> Bool {
    switch subject {
    case .parentIdentity(let path), .parentAccessPolicy(let path):
      return counter.collection(path.components.count)
        && path.components.allSatisfy { counter.rawComponent($0) }
    case .releaseTopology(let allocationGroupID):
      return counter.dynamicString(allocationGroupID)
    case .compoundReleaseUnit(let allocationGroupIDs):
      return counter.collection(allocationGroupIDs.count)
        && allocationGroupIDs.allSatisfy { counter.dynamicString($0) }
    default:
      counter.optionalScalarField()
      return true
    }
  }

  private static func step(
    _ outcome: ExecutionStepOutcome,
    counter: inout RuntimeSourceBudgetCounter
  ) -> Bool {
    guard counter.digest(outcome.actionID.digest.bytes),
      adapter(outcome.adapterOutcome, counter: &counter),
      postVerification(outcome.postVerification, counter: &counter)
    else { return false }
    return true
  }

  private static func adapter(
    _ outcome: AdapterOperationOutcome,
    counter: inout RuntimeSourceBudgetCounter
  ) -> Bool {
    switch outcome {
    case .succeeded(let detailCode):
      return counter.dynamicString(detailCode)
    case .failed(let failure):
      return failureDetail(failure, counter: &counter)
    case .cancelled, .timedOut, .notStarted:
      counter.optionalScalarField()
      return true
    }
  }

  private static func release(
    _ outcome: ReleasePostVerificationOutcome,
    counter: inout RuntimeSourceBudgetCounter
  ) -> Bool {
    counter.dynamicString(outcome.allocationGroupID)
      && postVerification(outcome.outcome, counter: &counter)
  }

  private static func postVerification(
    _ outcome: PostVerificationOutcome,
    counter: inout RuntimeSourceBudgetCounter
  ) -> Bool {
    switch outcome {
    case .expectedResidual(let failure):
      return failureDetail(failure, counter: &counter)
    case .notSatisfied(let code):
      return counter.dynamicString(code)
    case .unreadable(let failure), .failed(let failure):
      return counter.dynamicString(failure.code) && counter.dynamicString(failure.collector)
    case .satisfied, .missing, .unknown:
      counter.optionalScalarField()
      return true
    }
  }

  private static func failureDetail(
    _ failure: ExecutionAdapterFailure,
    counter: inout RuntimeSourceBudgetCounter
  ) -> Bool {
    guard counter.dynamicString(failure.code) else { return false }
    counter.optionalScalarField(failure.errno != nil)
    counter.optionalScalarField(failure.exitStatus != nil)
    counter.optionalScalarField(failure.terminatingSignal != nil)
    return true
  }
}

struct RuntimeProjectedExecutionBuffer: Sendable {
  private(set) var events: [Diskplan_V1_ExecutionStreamEvent] = []
  private(set) var observedEventCount: UInt64 = 0
  private(set) var observedEncodedBytes: UInt64 = 0
  private var accountedBytes: UInt64
  private var preflightAccountedBytes: UInt64
  private let budget: RuntimeApplyCaptureBudget

  init(budget: RuntimeApplyCaptureBudget = .runtimeDefault) {
    self.budget = budget
    accountedBytes = budget.terminalReserveBytes
    preflightAccountedBytes = budget.terminalReserveBytes
  }

  mutating func reserve(_ estimate: RuntimeSourceEventEstimate) -> RuntimeExecutionTailFailure? {
    guard let nextCount = adding(observedEventCount, estimate.projectedEventCount),
      let nextBytes = adding(preflightAccountedBytes, estimate.accountedUpperBoundBytes)
    else { return .projectionLimitExceeded(observedEventCount: .max, observedEncodedBytes: .max) }
    guard nextCount <= budget.maximumEventCount, nextBytes <= budget.maximumAccountedBytes else {
      return .projectionLimitExceeded(
        observedEventCount: nextCount,
        observedEncodedBytes: nextBytes
      )
    }
    preflightAccountedBytes = nextBytes
    return nil
  }

  mutating func append(
    _ candidates: [Diskplan_V1_ExecutionStreamEvent],
    reservedEstimate: RuntimeSourceEventEstimate
  ) -> RuntimeExecutionTailFailure? {
    guard UInt64(candidates.count) <= reservedEstimate.projectedEventCount else {
      return .backendContractViolation
    }
    for candidate in candidates {
      let encodedCount: UInt64
      do {
        encodedCount = UInt64(try candidate.serializedData().count)
      } catch {
        return .projectionValidationFailed
      }
      guard let nextCount = adding(observedEventCount, 1),
        let nextEncodedBytes = adding(observedEncodedBytes, encodedCount),
        let withPayload = adding(accountedBytes, encodedCount),
        let nextAccountedBytes = adding(withPayload, budget.perEventOverheadBytes)
      else { return .projectionLimitExceeded(observedEventCount: .max, observedEncodedBytes: .max) }
      observedEventCount = nextCount
      observedEncodedBytes = nextEncodedBytes
      guard nextCount <= budget.maximumEventCount,
        nextAccountedBytes <= budget.maximumAccountedBytes
      else {
        return .projectionLimitExceeded(
          observedEventCount: nextCount,
          observedEncodedBytes: nextEncodedBytes
        )
      }
      accountedBytes = nextAccountedBytes
      events.append(candidate)
    }
    return nil
  }

  mutating func clear() {
    events.removeAll(keepingCapacity: false)
  }

  private func adding(_ lhs: UInt64, _ rhs: UInt64) -> UInt64? {
    let result = lhs.addingReportingOverflow(rhs)
    return result.overflow ? nil : result.partialValue
  }
}

final class RuntimeApplyTaskControl: @unchecked Sendable {
  private let lock = NSLock()
  private var task: Task<BestEffortApplyReport, Never>?
  private var cancellationRequested = false
  private var cancellationDelivered = false

  func install(_ task: Task<BestEffortApplyReport, Never>) {
    lock.lock()
    self.task = task
    let shouldCancel = cancellationRequested && !cancellationDelivered
    if shouldCancel { cancellationDelivered = true }
    lock.unlock()
    if shouldCancel { task.cancel() }
  }

  func cancel() {
    lock.lock()
    cancellationRequested = true
    let task = cancellationDelivered ? nil : task
    if task != nil { cancellationDelivered = true }
    lock.unlock()
    task?.cancel()
  }
}

protocol RuntimeExecutionEventProjecting: Sendable {
  var negotiatedProtocolMinor: UInt32 { get }
  func project(
    _ event: ExecutionEvent,
    executionID: Data,
    review: Diskplan_V1_ApplyReviewProjection
  ) -> [Diskplan_V1_ExecutionStreamEvent]
}

actor RuntimeApplyEventCapture: ExecutionEventSink {
  enum Start: Sendable {
    case started(Diskplan_V1_ExecutionStreamEvent)
    case completed(BestEffortApplyReport)
    case failed(RuntimeExecutionTailFailure)
  }

  private let executionID: Data
  private let review: Diskplan_V1_ApplyReviewProjection
  private let projector: any RuntimeExecutionEventProjecting
  private let taskControl: RuntimeApplyTaskControl
  private var buffer = RuntimeProjectedExecutionBuffer()
  private var started: Diskplan_V1_ExecutionStreamEvent?
  private var completion: BestEffortApplyReport?
  private var failure: RuntimeExecutionTailFailure?
  private var terminalSeen = false
  private var startWaiters: [CheckedContinuation<Start, Never>] = []

  init(
    executionID: Data,
    review: Diskplan_V1_ApplyReviewProjection,
    projector: any RuntimeExecutionEventProjecting,
    taskControl: RuntimeApplyTaskControl,
    budget: RuntimeApplyCaptureBudget = .runtimeDefault
  ) {
    self.executionID = executionID
    self.review = review
    self.projector = projector
    self.taskControl = taskControl
    buffer = RuntimeProjectedExecutionBuffer(budget: budget)
  }

  func emit(_ event: ExecutionEvent) {
    guard failure == nil else { return }
    guard let estimate = RuntimeSourceEventPreflight.estimate(event) else {
      fail(.projectionLimitExceeded(observedEventCount: .max, observedEncodedBytes: .max))
      return
    }
    if let reservationFailure = buffer.reserve(estimate) {
      fail(reservationFailure)
      return
    }
    if started == nil, case .applyStarted(let epochID) = event {
      guard Data(epochID.utf8) == review.epoch.epochID.value else {
        fail(.backendContractViolation)
        return
      }
      let projected = projector.project(event, executionID: executionID, review: review)
      guard projected.count == 1, case .applyStarted? = projected[0].body else {
        fail(.backendContractViolation)
        return
      }
      guard let projectionFailure = buffer.append(projected, reservedEstimate: estimate) else {
        started = projected[0]
        resumeStartWaiters(.started(projected[0]))
        return
      }
      fail(projectionFailure)
      return
    }
    guard started != nil else {
      fail(.backendContractViolation)
      return
    }
    guard !terminalSeen else {
      fail(.backendContractViolation)
      return
    }
    if case .applyStarted = event {
      fail(.backendContractViolation)
      return
    }
    let projected = projector.project(event, executionID: executionID, review: review)
    if let projectionFailure = buffer.append(projected, reservedEstimate: estimate) {
      fail(projectionFailure)
    } else if case .applyFinished = event {
      terminalSeen = true
    }
  }

  func complete(_ report: BestEffortApplyReport) {
    completion = report
    if let failure {
      resumeStartWaiters(.failed(failure))
    } else if started == nil {
      resumeStartWaiters(.completed(report))
    }
  }

  func awaitStart() async -> Start {
    if let failure { return .failed(failure) }
    if let started { return .started(started) }
    if let completion { return .completed(completion) }
    return await withCheckedContinuation { startWaiters.append($0) }
  }

  func tailOutcome(for report: BestEffortApplyReport) -> RuntimeExecutionTailOutcome {
    if let failure { return .failed(failure) }
    guard report.startFailure == nil, report.manifest != nil, terminalSeen, let started,
      buffer.events.first == started
    else { return .failed(.backendContractViolation) }
    let projection = RuntimeAuthoritativeExecutionProjection.validating(
      applyStarted: started,
      remainingEvents: Array(buffer.events.dropFirst()),
      requiredForceWarningActionIDs: review.forceWarningActionIds,
      negotiatedProtocolMinor: projector.negotiatedProtocolMinor
    )
    return RuntimeExecutionTail.outcome(authoritativeProjection: projection)
  }

  private func fail(_ value: RuntimeExecutionTailFailure) {
    guard failure == nil else { return }
    failure = value
    buffer.clear()
    taskControl.cancel()
    resumeStartWaiters(.failed(value))
  }

  private func resumeStartWaiters(_ value: Start) {
    let waiters = startWaiters
    startWaiters.removeAll()
    for waiter in waiters { waiter.resume(returning: value) }
  }
}

private enum RuntimeApplyRun {
  static func start(
    executionID: Data,
    composition: EngineExecutionComposition,
    authorization: ApplyAuthorization,
    plan: ImmutablePlan,
    overlay: DecisionOverlay,
    review: Diskplan_V1_ApplyReviewProjection,
    projector: RuntimeExecutionProjector
  ) async throws -> RuntimeApplyLaunchResult {
    let taskControl = RuntimeApplyTaskControl()
    let capture = RuntimeApplyEventCapture(
      executionID: executionID,
      review: review,
      projector: projector,
      taskControl: taskControl
    )
    let coordinator = composition.makeApplyCoordinator(observing: capture)
    let applyTask = Task {
      let report = await coordinator.apply(
        authorization: authorization,
        plan: plan,
        overlay: overlay
      )
      await capture.complete(report)
      return report
    }
    taskControl.install(applyTask)
    switch await capture.awaitStart() {
    case .completed(let report):
      _ = await applyTask.value
      guard let failure = report.startFailure, report.unitOutcomes.isEmpty,
        report.auditFailures.isEmpty
      else { throw DiskplanRuntimeExecutionProjectionError.eventStreamInvariant }
      return .startFailed(
        try projector.applyStartFailureTerminal(
          executionID: executionID,
          review: review,
          failure: failure
        ))
    case .failed:
      taskControl.cancel()
      _ = await applyTask.value
      throw DiskplanRuntimeExecutionProjectionError.eventStreamInvariant
    case .started(let started):
      guard case .applyStarted(let projectedStart)? = started.body,
        projectedStart.epoch.epochID == review.epoch.epochID
      else {
        taskControl.cancel()
        _ = await applyTask.value
        throw DiskplanRuntimeExecutionProjectionError.eventStreamInvariant
      }
      return .started(
        try await RuntimeExecutionRunHandle.start(
          executionID: executionID,
          applyStarted: started,
          awaitTail: {
            let report = await applyTask.value
            return await capture.tailOutcome(for: report)
          },
          cancel: { taskControl.cancel() }
        ))
    }
  }
}

struct RuntimeExecutionProjector: Sendable {
  let context: RuntimeExecutionPlanContext
  let nextID: @Sendable () -> Data
  let actions: [Data: Diskplan_V1_PlanActionProjection]
  let releaseSetIDsByGroup: [String: Data]

  init(
    context: RuntimeExecutionPlanContext,
    nextID: @escaping @Sendable () -> Data
  ) throws {
    self.context = context
    self.nextID = nextID
    var actions: [Data: Diskplan_V1_PlanActionProjection] = [:]
    var releaseSets: [Data: Diskplan_V1_PlanReleaseSetProjection] = [:]
    for record in context.planRecords {
      switch record.body {
      case .action(let action)?: actions[action.actionID.value] = action
      case .releaseSet(let releaseSet)?: releaseSets[releaseSet.releaseSetID.value] = releaseSet
      case .target, nil: break
      }
    }
    self.actions = actions
    releaseSetIDsByGroup = try runtimeExactReleaseSetBindings(
      domains: context.plan.releaseSets.map {
        RuntimeReleaseSetDomainBinding(
          allocationGroupID: $0.allocationGroupID,
          ownerActionIDs: $0.ownerActionIDs.sorted().map { $0.digest.bytes }
        )
      },
      exactIDsByAllocationGroup: context.releaseSetIDByAllocationGroup,
      wireReleaseSets: releaseSets
    )
  }

  func dryRun(_ report: DryRunReport) throws -> RuntimePreparedDryRun {
    let revalidation = project(report.revalidation)
    let actionIDs = selectedActionIDs()
    var payload = Diskplan_V1_DryRunProjectionPayload()
    payload.revalidation = revalidation
    payload.actions = try actionIDs.map { actionID in
      guard let source = actions[actionID], source.hasExecutionPreview else {
        throw DiskplanRuntimeExecutionProjectionError.missingActionPreview
      }
      var value = Diskplan_V1_DryRunActionProjection()
      value.actionID.value = actionID
      value.executionPreview = source.executionPreview
      return value
    }

    var manifest = Diskplan_V1_DryRunProjectionManifest()
    manifest.projectionID = context.planManifest.projectionID
    manifest.planSha256.value = report.revalidation.planHash.bytes
    manifest.overlaySha256.value = report.revalidation.overlayHash.bytes
    manifest.epoch = epoch(report.revalidation.epoch)
    manifest.current = report.revalidation.isCurrent
    manifest.dryRunID.value = try generatedIdentifier()
    manifest.selectedActionCount = UInt64(actionIDs.count)
    manifest.overlayID = context.overlayProjection.overlayID
    manifest.planID = context.planManifest.planID
    manifest.evidenceID = context.planManifest.evidenceID
    manifest.evidenceSha256 = context.planManifest.evidenceSha256
    if let currentBinding = report.revalidation.manifest?.currentBindingHash {
      manifest.currentBindingSha256.value = currentBinding.bytes
    }
    manifest.overlayRevision = context.overlayProjection.revision
    manifest.scanSessionID = context.planManifest.scanSessionID
    manifest.scanCheckpointID = context.planManifest.scanCheckpointID
    manifest.scanCheckpointEvidenceSha256 = context.planManifest.scanCheckpointEvidenceSha256
    return RuntimePreparedDryRun(payload: payload, manifest: manifest)
  }

  func applyReview(_ ready: ApplyReadyReport) throws -> Diskplan_V1_ApplyReviewProjection {
    guard ready.revalidation.isCurrent, let manifest = ready.revalidation.manifest else {
      throw RuntimeExecutionBackendFailure.revalidationFailed
    }
    let actionIDs = selectedActionIDs()
    let forceIDs = Set(ready.forceWarningActionIDs.map { $0.digest.bytes })
    var projection = Diskplan_V1_ApplyReviewProjection()
    projection.applyReviewID.value = try generatedIdentifier()
    projection.projectionID = context.planManifest.projectionID
    projection.planSha256.value = ready.revalidation.planHash.bytes
    projection.overlaySha256.value = ready.revalidation.overlayHash.bytes
    projection.epoch = epoch(ready.revalidation.epoch)
    projection.revalidation = project(ready.revalidation)
    projection.actions = try actionIDs.map { actionID in
      guard let source = actions[actionID], source.hasExecutionPreview else {
        throw DiskplanRuntimeExecutionProjectionError.missingActionPreview
      }
      var action = Diskplan_V1_ApplyReviewActionProjection()
      action.actionID.value = actionID
      action.requiresForce = forceIDs.contains(actionID)
      action.executionPreview = source.executionPreview
      return action
    }
    projection.forceWarningActionIds = ready.forceWarningActionIDs.map { opaque($0.digest.bytes) }
    projection.reviewBindingSha256.value = ready.reviewBindingHash.bytes
    projection.overlayID = context.overlayProjection.overlayID
    projection.selectedActionCount = UInt64(actionIDs.count)
    projection.planID = context.planManifest.planID
    projection.evidenceID = context.planManifest.evidenceID
    projection.evidenceSha256 = context.planManifest.evidenceSha256
    projection.currentBindingSha256.value = manifest.currentBindingHash.bytes
    projection.overlayRevision = context.overlayProjection.revision
    projection.scanSessionID = context.planManifest.scanSessionID
    projection.scanCheckpointID = context.planManifest.scanCheckpointID
    projection.scanCheckpointEvidenceSha256 = context.planManifest.scanCheckpointEvidenceSha256
    return projection
  }

  func applyStarted(
    executionID: Data,
    review: Diskplan_V1_ApplyReviewProjection
  ) -> Diskplan_V1_ExecutionStreamEvent {
    var started = Diskplan_V1_ApplyStartedProjection()
    started.epoch = review.epoch
    started.applyReviewID = review.applyReviewID
    started.projectionID = review.projectionID
    started.planSha256 = review.planSha256
    started.overlayID = review.overlayID
    started.overlaySha256 = review.overlaySha256
    started.reviewBindingSha256 = review.reviewBindingSha256
    started.selectedActionCount = review.selectedActionCount
    started.planID = review.planID
    started.evidenceID = review.evidenceID
    started.evidenceSha256 = review.evidenceSha256
    started.currentBindingSha256 = review.currentBindingSha256
    started.revalidationSha256 = review.revalidationSha256
    started.overlayRevision = review.overlayRevision
    started.scanSessionID = review.scanSessionID
    started.scanCheckpointID = review.scanCheckpointID
    started.scanCheckpointEvidenceSha256 = review.scanCheckpointEvidenceSha256
    var event = Diskplan_V1_ExecutionStreamEvent()
    event.executionID.value = executionID
    event.body = .applyStarted(started)
    return event
  }

  func project(
    _ event: ExecutionEvent,
    executionID: Data,
    review: Diskplan_V1_ApplyReviewProjection
  ) -> [Diskplan_V1_ExecutionStreamEvent] {
    switch event {
    case .applyStarted:
      return [applyStarted(executionID: executionID, review: review)]
    case .unitFinished(let outcome):
      var projected: [Diskplan_V1_ExecutionStreamEvent] = []
      if outcome.status == .jitRejected, let jit = outcome.jitReport {
        projected.append(
          streamEvent(executionID, .unitJitRejected(jitRejected(outcome.id, jit))))
      } else if outcome.status == .skippedPrerequisite {
        projected.append(streamEvent(executionID, .unitSkippedPrerequisite(skipped(outcome))))
      }
      projected.append(
        streamEvent(
          executionID,
          .unitFinished(unitFinished(outcome.id, outcome.status))
        ))
      return projected
    case .unitStarted(let id):
      return [streamEvent(executionID, .unitStarted(unitStarted(id)))]
    case .forceRequiredWarning(let actionID):
      return [streamEvent(executionID, .forceRequiredWarning(forceWarning(actionID)))]
    case .stepFinished(let outcome):
      return [streamEvent(executionID, .stepFinished(step(outcome)))]
    case .releasePostVerificationFinished(let outcome):
      return [
        streamEvent(executionID, .releasePostVerificationFinished(releasePostverify(outcome)))
      ]
    case .auditWriteFailed(let failure):
      return [streamEvent(executionID, .auditWriteFailed(auditFailure(failure)))]
    case .applyFinished:
      return [streamEvent(executionID, .applyFinished(applyFinished(review, failure: nil)))]
    }
  }

  func applyStartFailureTerminal(
    executionID: Data,
    review: Diskplan_V1_ApplyReviewProjection,
    failure: ApplyStartFailure
  ) throws -> RuntimeApplyStartFailureTerminal {
    try RuntimeApplyStartFailureTerminal(
      validating: streamEvent(
        executionID,
        .applyFinished(applyFinished(review, failure: failure))
      ),
      negotiatedProtocolMinor: context.negotiatedProtocolMinor
    )
  }

  private func selectedActionIDs() -> [Data] {
    context.overlayProjection.selectedActionIds.map(\.value)
  }

  func generatedIdentifier() throws -> Data {
    let value = nextID()
    guard !value.isEmpty, value.count <= SealedRuntimeWire.maximumOpaqueIdentifierBytes else {
      throw DiskplanRuntimeExecutionProjectionError.invalidGeneratedIdentifier
    }
    return value
  }

  private func project(_ report: RevalidationReport) -> Diskplan_V1_RevalidationProjectionPayload {
    project(
      actionOutcomes: report.actionOutcomes,
      globalFindings: report.globalFindings
    )
  }

  private func project(
    actionOutcomes: [ActionRevalidationOutcome],
    globalFindings: [RevalidationFinding]
  ) -> Diskplan_V1_RevalidationProjectionPayload {
    var findingSequence: UInt64 = 0
    func finding(_ source: RevalidationFinding) -> Diskplan_V1_RevalidationFindingProjection {
      findingSequence += 1
      var value = Diskplan_V1_RevalidationFindingProjection()
      value.findingID.value = Data("finding-\(findingSequence)".utf8)
      if let actionID = source.actionID { value.actionID.value = actionID.digest.bytes }
      let subject = projectRevalidationSubject(source.subject)
      value.subject = subject.value
      value.subjectParameter = subject.parameter
      value.kind = projectRevalidationFailureKind(source.kind)
      value.summary = source.kind.rawValue
      if let failure = source.observationFailure {
        var detail = Diskplan_V1_ObservationFailureProjection()
        detail.code = nonempty(failure.code, fallback: "observation-failed")
        detail.collector = nonempty(failure.collector, fallback: "unknown-collector")
        value.detail = .observationFailure(detail)
      } else if let unknown = source.unknownReason {
        var detail = Diskplan_V1_UnknownProjectionValue()
        detail.code = unknown.rawValue
        detail.summary = unknown.rawValue
        value.detail = .unknown(detail)
      } else if source.kind == .unknown {
        var detail = Diskplan_V1_UnknownProjectionValue()
        detail.code = "unspecified-unknown"
        detail.summary = "unspecified unknown observation"
        value.detail = .unknown(detail)
      } else if source.kind == .unreadable || source.kind == .collectionFailed {
        var detail = Diskplan_V1_ObservationFailureProjection()
        detail.code = source.kind.rawValue
        detail.collector = "unspecified-collector"
        value.detail = .observationFailure(detail)
      }
      return value
    }
    var payload = Diskplan_V1_RevalidationProjectionPayload()
    payload.actionOutcomes = actionOutcomes.map { source in
      var outcome = Diskplan_V1_ActionRevalidationProjection()
      outcome.actionID.value = source.actionID.digest.bytes
      outcome.current = source.isCurrent
      outcome.findings = source.findings.map(finding)
      return outcome
    }
    payload.globalFindings = globalFindings.map(finding)
    return payload
  }

  private func project(_ report: JITRevalidationReport) -> Diskplan_V1_RevalidationProjectionPayload
  {
    project(
      actionOutcomes: report.actionOutcomes,
      globalFindings: report.globalFindings
    )
  }

  private func epoch(_ source: ExecutionEpochContext) -> Diskplan_V1_ExecutionEpochProjection {
    var value = Diskplan_V1_ExecutionEpochProjection()
    value.epochID.value = Data(source.epochID.utf8)
    value.semanticReferenceTimeSeconds = source.semanticReferenceTimeSeconds
    value.issuedAtSeconds = source.issuedAtSeconds
    value.deadlineSeconds = source.deadlineSeconds
    return value
  }

  private func unit(_ source: ExecutionUnitID) -> Diskplan_V1_ExecutionUnitProjection {
    var value = Diskplan_V1_ExecutionUnitProjection()
    switch source {
    case .action(let actionID):
      value.unit = .actionID(opaque(actionID.digest.bytes))
    case .compoundRelease(let groupIDs):
      var compound = Diskplan_V1_CompoundReleaseUnitProjection()
      compound.releaseSetIds = groupIDs.map { opaque(releaseSetIDsByGroup[$0] ?? Data()) }
      value.unit = .compoundRelease(compound)
    }
    return value
  }

  private func releaseSetID(for allocationGroupID: String) -> Data? {
    releaseSetIDsByGroup[allocationGroupID]
  }

  private func unitStarted(_ id: ExecutionUnitID) -> Diskplan_V1_UnitStartedProjection {
    var value = Diskplan_V1_UnitStartedProjection()
    value.unit = unit(id)
    return value
  }

  private func unitFinished(
    _ id: ExecutionUnitID,
    _ status: ExecutionUnitStatus
  ) -> Diskplan_V1_UnitFinishedProjection {
    var value = Diskplan_V1_UnitFinishedProjection()
    value.unit = unit(id)
    value.status = projectExecutionUnitStatus(status)
    return value
  }

  private func forceWarning(_ actionID: ActionID) -> Diskplan_V1_ForceRequiredWarningProjection {
    var value = Diskplan_V1_ForceRequiredWarningProjection()
    value.actionID.value = actionID.digest.bytes
    value.preview =
      actions[actionID.digest.bytes]?.executionPreview
      ?? Diskplan_V1_ActionExecutionPreviewProjection()
    return value
  }

  private func step(_ source: ExecutionStepOutcome) -> Diskplan_V1_ExecutionStepFinishedProjection {
    var value = Diskplan_V1_ExecutionStepFinishedProjection()
    value.actionID.value = source.actionID.digest.bytes
    value.status = projectExecutionStepStatus(source.status)
    value.adapterOutcome = projectAdapterOutcome(source.adapterOutcome)
    value.postVerification = projectPostVerification(source.postVerification)
    return value
  }

  private func releasePostverify(
    _ source: ReleasePostVerificationOutcome
  ) -> Diskplan_V1_ReleasePostVerificationProjection {
    var value = Diskplan_V1_ReleasePostVerificationProjection()
    value.releaseSetID.value = releaseSetIDsByGroup[source.allocationGroupID] ?? Data()
    value.outcome = projectPostVerification(source.outcome)
    return value
  }

  private func auditFailure(
    _ source: AuditWriteFailure
  ) -> Diskplan_V1_AuditWriteFailureProjection {
    var value = Diskplan_V1_AuditWriteFailureProjection()
    value.eventIndex = UInt64(max(0, source.eventIndex))
    value.code = nonempty(source.code, fallback: "audit-write-failed")
    if let errorCode = source.errno {
      value.errorCode = errorCode
      value.hasErrorCode_p = true
    }
    return value
  }

  private func jitRejected(
    _ id: ExecutionUnitID,
    _ report: JITRevalidationReport
  ) -> Diskplan_V1_UnitJITRejectedProjection {
    var value = Diskplan_V1_UnitJITRejectedProjection()
    value.unit = unit(id)
    value.revalidation = project(report)
    return value
  }

  private func skipped(
    _ outcome: ExecutionUnitOutcome
  ) -> Diskplan_V1_UnitSkippedPrerequisiteProjection {
    var value = Diskplan_V1_UnitSkippedPrerequisiteProjection()
    value.unit = unit(outcome.id)
    value.blockingPrerequisites = outcome.prerequisiteActionIDs.map {
      unit(.action($0))
    }
    return value
  }

  private func applyFinished(
    _ review: Diskplan_V1_ApplyReviewProjection,
    failure: ApplyStartFailure?
  ) -> Diskplan_V1_ApplyFinishedProjection {
    var value = Diskplan_V1_ApplyFinishedProjection()
    if let failure {
      value.startFailure = projectApplyStartFailure(failure)
    }
    value.applyReviewID = review.applyReviewID
    value.reviewBindingSha256 = review.reviewBindingSha256
    return value
  }

  private func streamEvent(
    _ executionID: Data,
    _ body: Diskplan_V1_ExecutionStreamEvent.OneOf_Body
  ) -> Diskplan_V1_ExecutionStreamEvent {
    var event = Diskplan_V1_ExecutionStreamEvent()
    event.executionID.value = executionID
    event.body = body
    return event
  }
}

extension RuntimeExecutionProjector: RuntimeExecutionEventProjecting {
  var negotiatedProtocolMinor: UInt32 { context.negotiatedProtocolMinor }
}

struct RuntimeReleaseSetDomainBinding: Equatable, Sendable {
  let allocationGroupID: String
  let ownerActionIDs: [Data]
}

func runtimeExactReleaseSetBindings(
  domains: [RuntimeReleaseSetDomainBinding],
  exactIDsByAllocationGroup: [Data: Data],
  wireReleaseSets: [Data: Diskplan_V1_PlanReleaseSetProjection]
) throws -> [String: Data] {
  guard exactIDsByAllocationGroup.count == domains.count,
    Set(exactIDsByAllocationGroup.values).count == domains.count,
    wireReleaseSets.count == domains.count
  else { throw DiskplanRuntimeExecutionProjectionError.missingReleaseSet }
  var result: [String: Data] = [:]
  for domain in domains {
    let allocationGroupID = Data(domain.allocationGroupID.utf8)
    guard let releaseSetID = exactIDsByAllocationGroup[allocationGroupID],
      let wire = wireReleaseSets[releaseSetID],
      wire.releaseSetID.value == releaseSetID,
      wire.actionIds.map(\.value) == domain.ownerActionIDs,
      result.updateValue(releaseSetID, forKey: domain.allocationGroupID) == nil
    else { throw DiskplanRuntimeExecutionProjectionError.missingReleaseSet }
  }
  guard Set(result.values) == Set(wireReleaseSets.keys) else {
    throw DiskplanRuntimeExecutionProjectionError.missingReleaseSet
  }
  return result
}

private func opaque(_ value: Data) -> Diskplan_V1_OpaqueIdentifier {
  var result = Diskplan_V1_OpaqueIdentifier()
  result.value = value
  return result
}

private let maximumRuntimeDynamicTextBytes = 4_096

private func nonempty(_ value: String, fallback: String) -> String {
  let source = value.isEmpty ? fallback : value
  guard source.utf8.count > maximumRuntimeDynamicTextBytes else { return source }
  var result = ""
  result.reserveCapacity(maximumRuntimeDynamicTextBytes)
  for scalar in source.unicodeScalars {
    let fragment = String(scalar)
    guard result.utf8.count + fragment.utf8.count <= maximumRuntimeDynamicTextBytes else { break }
    result.unicodeScalars.append(scalar)
  }
  return result.isEmpty ? fallback : result
}

private func projectRevalidationSubject(
  _ source: RevalidationSubject
) -> (value: Diskplan_V1_RevalidationSubject, parameter: Data) {
  switch source {
  case .targetIdentity: (.targetIdentity, Data())
  case .targetContent: (.targetContent, Data())
  case .targetAccessPolicy: (.targetAccessPolicy, Data())
  case .coverage: (.coverage, Data())
  case .collectorStatus: (.collectorStatus, Data())
  case .activity: (.activity, Data())
  case .explicitProtection: (.explicitProtection, Data())
  case .providerState: (.providerState, Data())
  case .recoverability: (.recoverability, Data())
  case .dependency: (.dependency, Data())
  case .rootIdentity: (.rootIdentity, Data())
  case .rootAccessPolicy: (.rootAccessPolicy, Data())
  case .parentIdentity(let path): (.parentIdentity, path.components.joinedPathBytes)
  case .parentAccessPolicy(let path): (.parentAccessPolicy, path.components.joinedPathBytes)
  case .gitPrerequisites: (.gitPrerequisites, Data())
  case .releaseTopology(let group): (.releaseTopology, Data(group.utf8))
  case .duplicateSurvivors: (.duplicateSurvivors, Data())
  case .terminalNamespaces: (.terminalNamespaces, Data())
  case .compoundReleaseUnit(let groups):
    (.compoundReleaseUnit, Data(groups.joined(separator: "\0").utf8))
  case .collector: (.collector, Data())
  case .policyEvidence: (.policyEvidence, Data())
  case .waiverConsent(let waiver): (.waiverConsent, Data(waiver.rawValue.utf8))
  }
}

private func projectRevalidationFailureKind(
  _ source: RevalidationFailureKind
) -> Diskplan_V1_RevalidationFailureKind {
  switch source {
  case .missing: .missing
  case .unknown: .unknown
  case .unreadable: .unreadable
  case .collectionFailed: .collectionFailed
  case .cancelled: .cancelled
  case .identityMismatch: .identityMismatch
  case .contentMismatch: .contentMismatch
  case .accessPolicyMismatch: .accessPolicyMismatch
  case .namespaceIdentityMismatch: .namespaceIdentityMismatch
  case .namespaceAccessPolicyMismatch: .namespaceAccessPolicyMismatch
  case .coverageMismatch: .coverageMismatch
  case .activityMismatch: .activityMismatch
  case .protectionMismatch: .protectionMismatch
  case .providerMismatch: .providerMismatch
  case .recoverabilityMismatch: .recoverabilityMismatch
  case .dependencyMismatch: .dependencyMismatch
  case .gitPrerequisiteMismatch: .gitPrerequisiteMismatch
  case .releaseTopologyMismatch: .releaseTopologyMismatch
  case .survivorInvariantViolated: .survivorInvariantViolated
  case .terminalNamespaceInvariantViolated: .terminalNamespaceInvariantViolated
  case .incompleteCompoundReleaseUnit: .incompleteCompoundReleaseUnit
  case .duplicateObservation: .duplicateObservation
  case .unexpectedObservation: .unexpectedObservation
  case .policyEvidenceMismatch: .policyEvidenceMismatch
  case .policyThresholdCrossed: .policyThresholdCrossed
  case .staleConsent: .staleConsent
  }
}

private func projectExecutionStepStatus(
  _ source: ExecutionStepStatus
) -> Diskplan_V1_ExecutionStepStatus {
  switch source {
  case .succeeded: .succeeded
  case .partiallySucceeded: .partiallySucceeded
  case .failed: .failed
  case .cancelled: .cancelled
  case .expired: .expired
  case .superseded: .superseded
  case .skippedPrerequisite: .skippedPrerequisite
  }
}

private func projectExecutionUnitStatus(
  _ source: ExecutionUnitStatus
) -> Diskplan_V1_ExecutionUnitStatus {
  switch source {
  case .succeeded: .succeeded
  case .partiallyFailed: .partiallyFailed
  case .failed: .failed
  case .cancelled: .cancelled
  case .skippedPrerequisite: .skippedPrerequisite
  case .jitRejected: .jitRejected
  case .expired: .expired
  case .superseded: .superseded
  }
}

private func projectAdapterOutcome(
  _ source: AdapterOperationOutcome
) -> Diskplan_V1_AdapterOutcomeProjection {
  var value = Diskplan_V1_AdapterOutcomeProjection()
  switch source {
  case .succeeded(let detailCode):
    value.kind = .succeeded
    value.detailCode = nonempty(detailCode, fallback: "succeeded")
  case .failed(let failure):
    value.kind = .failed
    value.detailCode = nonempty(failure.code, fallback: "failed")
    value.detail = .failure(projectAdapterFailure(failure))
  case .cancelled:
    value.kind = .cancelled
    value.detailCode = "cancelled"
  case .timedOut:
    value.kind = .timedOut
    value.detailCode = "timed-out"
    value.detail = .failure(
      projectAdapterFailure(ExecutionAdapterFailure(code: "timed-out")))
  case .notStarted(let reason):
    value.kind = .notStarted
    value.detailCode = reason.rawValue
    value.detail = .notStartedReason(reason.rawValue)
  }
  return value
}

private func projectAdapterFailure(_ source: ExecutionAdapterFailure)
  -> Diskplan_V1_ExecutionAdapterFailureProjection
{
  var value = Diskplan_V1_ExecutionAdapterFailureProjection()
  value.code = nonempty(source.code, fallback: "adapter-failed")
  if let errorCode = source.errno {
    value.errorCode = errorCode
    value.hasErrorCode_p = true
  }
  if let status = source.exitStatus {
    value.exitStatus = status
    value.hasExitStatus_p = true
  }
  if let signal = source.terminatingSignal {
    value.terminatingSignal = signal
    value.hasTerminatingSignal_p = true
  }
  return value
}

private func projectPostVerification(
  _ source: PostVerificationOutcome
) -> Diskplan_V1_PostVerificationProjection {
  var value = Diskplan_V1_PostVerificationProjection()
  switch source {
  case .satisfied:
    value.kind = .satisfied
    value.code = "satisfied"
  case .expectedResidual(let failure):
    value.kind = .expectedResidual
    value.code = nonempty(failure.code, fallback: "expected-residual")
    value.detail = .residual(projectAdapterFailure(failure))
  case .missing:
    value.kind = .missing
    value.code = "missing"
  case .notSatisfied(let code):
    value.kind = .notSatisfied
    value.code = nonempty(code, fallback: "not-satisfied")
  case .unknown(let reason):
    value.kind = .unknown
    value.code = reason.rawValue
    var unknown = Diskplan_V1_UnknownProjectionValue()
    unknown.code = reason.rawValue
    unknown.summary = reason.rawValue
    value.detail = .unknown(unknown)
  case .unreadable(let failure):
    value.kind = .unreadable
    value.code = nonempty(failure.code, fallback: "unreadable")
    value.detail = .observationFailure(projectObservationFailure(failure))
  case .failed(let failure):
    value.kind = .failed
    value.code = nonempty(failure.code, fallback: "postverification-failed")
    value.detail = .observationFailure(projectObservationFailure(failure))
  }
  return value
}

private func projectObservationFailure(
  _ source: ObservationFailure
) -> Diskplan_V1_ObservationFailureProjection {
  var value = Diskplan_V1_ObservationFailureProjection()
  value.code = nonempty(source.code, fallback: "observation-failed")
  value.collector = nonempty(source.collector, fallback: "unknown-collector")
  return value
}

private func projectApplyStartFailure(
  _ source: ApplyStartFailure
) -> Diskplan_V1_ApplyStartFailureKind {
  switch source {
  case .authorizationAlreadyClaimed: .authorizationAlreadyClaimed
  case .invalidOverlay: .invalidOverlay
  case .manifestBindingMismatch: .manifestBindingMismatch
  case .expired: .expired
  case .invalidExecutionGraph: .invalidExecutionGraph
  case .preparationSuperseded: .preparationSuperseded
  case .forceConfirmationBindingMismatch: .forceConfirmationBindingMismatch
  }
}

extension Array where Element == Data {
  fileprivate var joinedPathBytes: Data {
    var result = Data()
    for (index, component) in enumerated() {
      if index > 0 { result.append(47) }
      result.append(component)
    }
    return result
  }
}
