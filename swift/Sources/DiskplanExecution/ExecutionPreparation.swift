import CryptoKit
import DiskplanPolicy
import Foundation

public actor ExecutionPreparationEngine {
  private struct CapabilityRecord: Sendable {
    let planHash: PolicyDigest
    let overlayHash: PolicyDigest
    let epochID: String
    let deadlineSeconds: Int64
    let manifest: ExecutionManifest
  }

  private let evidenceSource: any RevalidationEvidenceSource
  private let randomBytes: @Sendable (Int) throws -> Data
  private let clock: @Sendable () -> Int64
  private var capabilities: [Data: CapabilityRecord] = [:]

  public init(evidenceSource: any RevalidationEvidenceSource) {
    self.evidenceSource = evidenceSource
    self.randomBytes = { count in
      var generator = SystemRandomNumberGenerator()
      return Data((0..<count).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }
    self.clock = { Int64(Date().timeIntervalSince1970.rounded(.down)) }
  }

  init(
    evidenceSource: any RevalidationEvidenceSource,
    randomBytes: @escaping @Sendable (Int) throws -> Data,
    clock: @escaping @Sendable () -> Int64 = {
      Int64(Date().timeIntervalSince1970.rounded(.down))
    }
  ) {
    self.evidenceSource = evidenceSource
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
    guard lifetimeSeconds > 0,
      issuedAtSeconds.addingReportingOverflow(lifetimeSeconds).overflow == false
    else { throw ExecutionPreparationError.invalidLifetime }

    let validated = try DecisionOverlayValidator.validate(overlay, against: plan)
    invalidateAllCapabilities()
    purgeExpired(at: issuedAtSeconds)

    let epochBytes = try entropy(count: 16)
    let epoch = try ExecutionEpochContext(
      epochID: epochBytes.map { String(format: "%02x", $0) }.joined(),
      semanticReferenceTimeSeconds: plan.globalFacts.semanticReferenceTimeSeconds,
      issuedAtSeconds: issuedAtSeconds,
      deadlineSeconds: issuedAtSeconds + lifetimeSeconds
    )
    let request = RevalidationRequest(plan: plan, validatedOverlay: validated, epoch: epoch)

    let report: RevalidationReport
    do {
      let snapshot = try await evidenceSource.collectCurrentEvidence(for: request)
      report = Revalidator.evaluate(request: request, snapshot: snapshot)
    } catch {
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
    switch mode {
    case .dryRun:
      return .dryRun(DryRunReport(revalidation: report))
    case .apply:
      var token: Data?
      for _ in 0..<8 {
        let candidate = try entropy(count: 32)
        if capabilities[candidate] == nil {
          token = candidate
          break
        }
      }
      guard let token else { throw ExecutionPreparationError.entropyFailure }
      capabilities[token] = CapabilityRecord(
        planHash: plan.planHash,
        overlayHash: overlay.overlayHash,
        epochID: epoch.epochID,
        deadlineSeconds: epoch.deadlineSeconds,
        manifest: manifest
      )
      return .applyReady(
        ApplyReadyReport(revalidation: report),
        ApplyCapability(opaqueBytes: token)
      )
    }
  }

  public func authorizeApply(
    _ capability: ApplyCapability,
    ready: ApplyReadyReport,
    plan: ImmutablePlan,
    overlay: DecisionOverlay
  ) throws -> ApplyAuthorization {
    try authorizeApply(
      capability,
      ready: ready,
      plan: plan,
      overlay: overlay,
      nowSeconds: clock()
    )
  }

  func authorizeApply(
    _ capability: ApplyCapability,
    ready: ApplyReadyReport,
    plan: ImmutablePlan,
    overlay: DecisionOverlay,
    nowSeconds: Int64
  ) throws -> ApplyAuthorization {
    guard let record = capabilities.removeValue(forKey: capability.opaqueBytes) else {
      throw ExecutionPreparationError.capabilityUnknown
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
      record.manifest == readyManifest
    else { throw ExecutionPreparationError.capabilityBindingMismatch }
    return ApplyAuthorization(manifest: record.manifest)
  }

  private func entropy(count: Int) throws -> Data {
    let bytes = try randomBytes(count)
    guard bytes.count == count else { throw ExecutionPreparationError.entropyFailure }
    return bytes
  }

  private func invalidateAllCapabilities() { capabilities.removeAll(keepingCapacity: true) }

  private func purgeExpired(at now: Int64) {
    capabilities = capabilities.filter { $0.value.deadlineSeconds > now }
  }
}

enum Revalidator {
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

    let outcomes = actions.map { action in
      guard let current = currentByID[action.id] else {
        return ActionRevalidationOutcome(
          actionID: action.id,
          findings: [
            RevalidationFinding(actionID: action.id, subject: .collector, kind: .missing)
          ]
        )
      }
      return evaluateAction(action, current: current)
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
        units: units
      )
      manifest = ExecutionManifest(
        planHash: request.plan.planHash,
        overlayHash: request.validatedOverlay.overlayHash,
        epoch: request.epoch,
        executionActionIDs: actionIDs,
        jitRevalidationActionIDs: jit,
        compoundReleaseUnits: units.filter {
          !selectedReleaseGroupIDs.isDisjoint(with: $0.allocationGroupIDs)
        },
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
    snapshot: CurrentRevalidationSnapshot
  ) -> JITRevalidationReport {
    let expectedIDs = Set(request.actionIDs)
    let actionByID = Dictionary(uniqueKeysWithValues: request.plan.actions.map { ($0.id, $0) })
    var globalFindings: [RevalidationFinding] = []
    let currentByID = observationsByActionID(snapshot.actions, findings: &globalFindings)
    for extra in currentByID.keys where !expectedIDs.contains(extra) {
      globalFindings.append(
        RevalidationFinding(
          actionID: extra, subject: .collector, kind: .unexpectedObservation))
    }

    let outcomes = request.actionIDs.sorted().map { actionID -> ActionRevalidationOutcome in
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
      return evaluateAction(expected, current: current)
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
      actionOutcomes: outcomes.sorted { $0.actionID < $1.actionID },
      globalFindings: globalFindings
    )
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
    units: [CompoundReleaseUnit]
  ) -> PolicyDigest {
    var encoder = BindingEncoder(domain: "diskplan-current-execution-binding-v1")
    encoder.data(request.plan.planHash.bytes)
    encoder.data(request.validatedOverlay.overlayHash.bytes)
    encoder.string(request.epoch.epochID)
    encoder.int64(request.epoch.issuedAtSeconds)
    encoder.int64(request.epoch.deadlineSeconds)
    encoder.array(actionOutcomes) { $0.actionID.digest.bytes }
    encoder.array(units) { unit in
      var nested = BindingEncoder(domain: "compound-release-unit-v1")
      nested.array(unit.allocationGroupIDs) { Data($0.utf8) }
      nested.array(unit.ownerActionIDs) { $0.digest.bytes }
      return nested.bytes
    }
    return encoder.digest
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
    }
    return encoder.bytes
  }

  private static func rawUTF8Precedes(_ lhs: String, _ rhs: String) -> Bool {
    Data(lhs.utf8).lexicographicallyPrecedes(Data(rhs.utf8))
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
