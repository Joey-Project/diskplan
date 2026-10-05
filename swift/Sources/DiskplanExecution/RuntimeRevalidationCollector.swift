import Darwin
import DiskplanEngineCore
import DiskplanMacOS
import DiskplanPolicy
import DiskplanScan
import Foundation

/// Combines a concrete EngineCore fresh scan with Scan-owned descriptor evidence. Production has
/// no closure seam capable of relabeling immutable evidence as a current capture.
final class RuntimeRevalidationCollector: @unchecked Sendable {
  private let session: RuntimeEvidenceSession
  private let policyAuthority: RuntimeFreshPolicyAuthority

  init(session: RuntimeEvidenceSession, policyAuthority: RuntimeFreshPolicyAuthority) {
    self.session = session
    self.policyAuthority = policyAuthority
  }

  deinit { session.close() }

  func sealedCollector() -> EngineRevalidationCollector {
    EngineRevalidationCollector(
      collectCurrent: { [self] request in
        try await collectCurrent(request)
      },
      collectJIT: { [self] request in
        try await collectJIT(request)
      },
      collectReleasePostconditions: { _ in
        throw RuntimeRevalidationCollectorError.releasePostconditionCollectionUnavailable
      },
      collectFinalDescriptors: { [self] request in
        try await collectFinalDescriptors(request)
      }
    )
  }

  func invalidate() { session.close() }

  private func collectCurrent(
    _ request: RevalidationRequest
  ) async throws -> CurrentRevalidationSnapshot {
    try await withTaskCancellationHandler {
      let lease = try session.beginCapture(
        .wholePlan,
        excluding: [request.plan.globalFacts.captureID.bytes]
      )
      defer { lease.finish() }
      let actions = uniqueActions(request.validatedOverlay)
      let fresh = try await policyAuthority.collect(
        authorization: lease.authorization,
        request: freshPolicyRequest(actions)
      )
      let captureID = fresh.result.plan.globalFacts.captureID
      try requireFreshCapture(
        captureID,
        excluding: [
          request.plan.globalFacts.captureID,
          try PolicyDigest(bytes: lease.captureID.bytes),
        ]
      )
      let base = try currentSnapshot(
        freshCapture: fresh,
        actions: actions,
        captureID: captureID
      )
      let paths = try lease.collectPaths(actions.map(pathRequest))
      return try replacingProtectedEvidence(
        base,
        actions: actions,
        paths: paths,
        captureID: captureID
      )
    } onCancel: { [session] in
      session.close()
    }
  }

  private func collectJIT(
    _ request: JITRevalidationRequest
  ) async throws -> JITRevalidationSnapshot {
    try await withTaskCancellationHandler {
      let lease = try session.beginCapture(
        .jitUnit,
        excluding: [
          request.plan.globalFacts.captureID.bytes,
          request.manifest.currentCaptureID.bytes,
        ]
      )
      defer { lease.finish() }
      let actionByID = Dictionary(
        uniqueKeysWithValues: request.plan.actions.map { ($0.id, $0) })
      let actions = try request.actionIDs.map { identifier in
        guard let action = actionByID[identifier] else {
          throw RuntimeRevalidationCollectorError.actionMissing(identifier)
        }
        return action
      }
      let fresh = try await policyAuthority.collect(
        authorization: lease.authorization,
        request: freshPolicyRequest(actions)
      )
      let captureID = fresh.result.plan.globalFacts.captureID
      try requireFreshCapture(
        captureID,
        excluding: [
          request.plan.globalFacts.captureID,
          request.manifest.currentCaptureID,
          try PolicyDigest(bytes: lease.captureID.bytes),
        ]
      )
      let base = try currentSnapshot(
        freshCapture: fresh,
        actions: actions,
        captureID: captureID
      )
      let paths = try lease.collectPaths(actions.map(pathRequest))
      let snapshot = try replacingProtectedEvidence(
        base,
        actions: actions,
        paths: paths,
        captureID: captureID
      )
      return JITRevalidationSnapshot(
        oneShotNonce: request.oneShotNonce,
        authorizationCurrentBindingHash: request.authorizationCurrentBindingHash,
        preparationGeneration: request.preparationGeneration,
        epochID: request.epoch.epochID,
        snapshot: snapshot
      )
    } onCancel: { [session] in
      session.close()
    }
  }

  private func collectFinalDescriptors(
    _ request: FinalDescriptorPreflightRequest
  ) async throws -> FinalDescriptorEvidenceSnapshot {
    try await withTaskCancellationHandler {
      let lease = try session.beginCapture(
        .finalDescriptor,
        excluding: Set(request.priorCaptureIDs.map(\.bytes))
      )
      defer { lease.finish() }
      let descriptors = try duplicateDescriptors(
        [request.rootDescriptor] + request.parentDescriptors + [request.targetDescriptor])
      var transfersDescriptors = true
      defer {
        if transfersDescriptors {
          for descriptor in descriptors { Darwin.close(descriptor) }
        }
      }
      let parentCount = request.parentDescriptors.count
      let evidence = try lease.collectTransferredDescriptors(
        RuntimeTransferredDescriptorRequest(
          rootID: runtimeRootID(request.target.rawRoot),
          targetComponents: request.target.targetPath.components,
          rootDescriptor: descriptors[0],
          parentDescriptors: Array(descriptors.dropFirst().prefix(parentCount)),
          targetDescriptor: descriptors[parentCount + 1],
          requiresContent: requiresContent(request.target.expectedContent)
        ))
      transfersDescriptors = false
      return FinalDescriptorEvidenceSnapshot(
        captureID: try PolicyDigest(bytes: lease.captureID.bytes),
        targetIdentity: mapIdentity(
          evidence.target.identity,
          expected: request.target.expectedIdentity
        ),
        targetAccessPolicy: mapAccessPolicy(evidence.target),
        targetContent: mapContent(
          evidence.target.content,
          expected: request.target.expectedContent
        ),
        root: mapRoot(
          evidence.root,
          expectedIdentity: request.target.expectedRootIdentity,
          expected: request.target.expectedRootSeal
        ),
        parents: zip(
          request.target.targetPath.components.dropLast().indices,
          zip(
            evidence.parents,
            zip(
              request.target.expectedParentIdentities,
              request.target.expectedParentSeals
            )
          )
        ).map { index, pair in
          let (current, expectedPair) = pair
          let (expectedIdentity, expectedSeal) = expectedPair
          return CurrentNamespaceComponent(
            relativePath: try? RawTargetPath(
              components: Array(request.target.targetPath.components.prefix(index + 1))),
            identity: mapIdentity(current.identity, expected: expectedIdentity),
            seal: mapNamespaceSeal(current, expected: expectedSeal)
          )
        }
      )
    } onCancel: { [session] in
      session.close()
    }
  }

  private func replacingProtectedEvidence(
    _ base: CurrentRevalidationSnapshot,
    actions: [ActionDefinition],
    paths: [RuntimePathEvidence],
    captureID: PolicyDigest
  ) throws -> CurrentRevalidationSnapshot {
    guard actions.count == paths.count else {
      throw RuntimeRevalidationCollectorError.pathCountMismatch
    }
    let baseByID = Dictionary(grouping: base.actions, by: \.actionID)
    let replacements = try zip(actions, paths).map { action, path in
      guard let matches = baseByID[action.id], matches.count == 1, let current = matches.first
      else { throw RuntimeRevalidationCollectorError.baseActionMissing(action.id) }
      let namespace = action.prototype.namespaceBinding
      guard path.parents.count == namespace.parentChain.count else {
        throw RuntimeRevalidationCollectorError.pathCountMismatch
      }
      return CurrentActionEvidence(
        actionID: action.id,
        targetIdentity: mapIdentity(
          path.target.identity,
          expected: action.prototype.protectedProperties.identity.expectedIdentity
        ),
        targetContent: mapContent(
          path.target.content,
          expected: action.prototype.protectedProperties.content.expectedBaseline
        ),
        targetAccessPolicy: mapAccessPolicy(path.target),
        coverage: current.coverage,
        collectorStatus: current.collectorStatus,
        activity: current.activity,
        explicitProtection: current.explicitProtection,
        providerState: mapProvider(path.target.providerBoundary),
        recoverability: current.recoverability,
        dependencyState: current.dependencyState,
        freshPolicyEvidence: current.freshPolicyEvidence,
        root: mapRoot(
          path.root,
          expectedIdentity: namespace.rootIdentity,
          expected: namespace.rootSeal
        ),
        parents: zip(path.parents, namespace.parentChain).map { current, expected in
          CurrentNamespaceComponent(
            relativePath: expected.relativePath,
            identity: mapIdentity(current.identity, expected: expected.identity),
            seal: mapNamespaceSeal(current, expected: expected.seal)
          )
        },
        gitWorktree: current.gitWorktree
      )
    }
    return CurrentRevalidationSnapshot(
      captureID: captureID,
      actions: replacements,
      releaseTopologies: base.releaseTopologies,
      invariants: base.invariants
    )
  }
}

extension EngineRevalidationCollector {
  /// The only production composition path for live revalidation. It constructs both concrete
  /// authorities internally and exposes only the sealed collector handle.
  public static func productionRuntime(
    contentBudget: ContentCollectionBudget
  ) throws -> EngineRevalidationCollector {
    let installed = MaterializationPolicyInstaller().installBeforePathAccess()
    guard let policy = installed.value else {
      throw RuntimeRevalidationCollectorError.materializationPolicyUnavailable
    }
    let session = RuntimeEvidenceSession(
      policy: policy,
      contentBudget: contentBudget
    )
    return RuntimeRevalidationCollector(
      session: session,
      policyAuthority: RuntimeFreshPolicyAuthority(policy: policy)
    ).sealedCollector()
  }
}

private enum RuntimeRevalidationCollectorError: Error, Equatable {
  case actionMissing(ActionID)
  case baseActionMissing(ActionID)
  case freshCaptureCollision
  case freshPolicyActionMissing(ActionID)
  case pathCountMismatch
  case duplicateDescriptorFailed(Int32)
  case materializationPolicyUnavailable
  case releasePostconditionCollectionUnavailable
}

private func freshPolicyRequest(
  _ actions: [ActionDefinition]
) -> RuntimeFreshPolicyRequest {
  var rootsByPath: [Data: ScanRootRequest] = [:]
  for action in actions {
    let root = action.prototype.namespaceBinding.rawRoot
    rootsByPath[root.absoluteBytes] = ScanRootRequest(
      rootID: runtimeRootID(root),
      rawAbsolutePath: root.absoluteBytes
    )
  }
  return RuntimeFreshPolicyRequest(
    roots: rootsByPath.values.sorted { lhs, rhs in
      lhs.rawAbsolutePath.lexicographicallyPrecedes(rhs.rawAbsolutePath)
    },
    terminalNamespaces: actions.map {
      RuntimeFreshTerminalNamespace(
        rawRoot: $0.prototype.namespaceBinding.rawRoot,
        targetPath: $0.prototype.namespaceBinding.targetPath
      )
    }
  )
}

private func requireFreshCapture(
  _ captureID: PolicyDigest,
  excluding forbidden: [PolicyDigest]
) throws {
  guard !forbidden.contains(captureID) else {
    throw RuntimeRevalidationCollectorError.freshCaptureCollision
  }
}

private func currentSnapshot(
  freshCapture: RuntimeFreshPolicyCapture,
  actions: [ActionDefinition],
  captureID: PolicyDigest
) throws -> CurrentRevalidationSnapshot {
  let freshPlan = freshCapture.result.plan
  let currentActions = try actions.map { action in
    let expected = action.prototype.namespaceBinding
    let matches = freshPlan.evidenceSnapshots.filter {
      $0.namespaceBinding.rawRoot == expected.rawRoot
        && $0.namespaceBinding.targetPath == expected.targetPath
    }
    guard matches.count == 1, let evidence = matches.first else {
      throw RuntimeRevalidationCollectorError.freshPolicyActionMissing(action.id)
    }
    return CurrentActionEvidence(
      actionID: action.id,
      targetIdentity: .unknown(.incompleteCoverage),
      targetContent: .unknown(.incompleteCoverage),
      targetAccessPolicy: .unknown(.incompleteCoverage),
      coverage: .known(evidence.coverage),
      collectorStatus: evidence.collectorStatus,
      activity: evidence.activity,
      explicitProtection: evidence.explicitProtection,
      providerState: evidence.providerState,
      recoverability: evidence.recoverability,
      dependencyState: evidence.dependencyState,
      freshPolicyEvidence: .known(
        FreshPolicyEvidence(evidence: evidence, globalFacts: freshPlan.globalFacts)
      ),
      root: CurrentNamespaceComponent(
        relativePath: nil,
        identity: .unknown(.incompleteCoverage),
        seal: .unknown(.incompleteCoverage)
      ),
      parents: expected.parentChain.map {
        CurrentNamespaceComponent(
          relativePath: $0.relativePath,
          identity: .unknown(.incompleteCoverage),
          seal: .unknown(.incompleteCoverage)
        )
      },
      gitWorktree: evidence.gitWorktree.map(Observation.known) ?? .absent
    )
  }
  return CurrentRevalidationSnapshot(
    captureID: captureID,
    actions: currentActions,
    releaseTopologies: freshPlan.releaseSets.map {
      CurrentReleaseTopology(
        allocationGroupID: $0.allocationGroupID,
        topology: .unknown(.incompleteCoverage)
      )
    },
    invariants: CurrentPlanInvariants(
      duplicateSurvivorsPreserved: .unknown(.incompleteCoverage),
      terminalNamespacesExclusive: .unknown(.incompleteCoverage)
    )
  )
}

private func uniqueActions(_ overlay: ValidatedDecisionOverlay) -> [ActionDefinition] {
  var byID: [ActionID: ActionDefinition] = [:]
  for action in overlay.executionSteps.flatMap(\.jitRevalidationActions) {
    byID[action.id] = action
  }
  return byID.values.sorted { $0.id < $1.id }
}

private func pathRequest(_ action: ActionDefinition) -> RuntimePathEvidenceRequest {
  let binding = action.prototype.namespaceBinding
  return RuntimePathEvidenceRequest(
    rootID: runtimeRootID(binding.rawRoot),
    rawRoot: binding.rawRoot.absoluteBytes,
    targetComponents: binding.targetPath.components,
    requiresContent: requiresContent(
      action.prototype.protectedProperties.content.expectedBaseline)
  )
}

private func runtimeRootID(_ root: RawRootPath) -> String {
  root.absoluteBytes.map { String(format: "%02x", $0) }.joined()
}

private func requiresContent(_ baseline: ContentProtectionBaseline) -> Bool {
  if case .requiredDigest = baseline { return true }
  return false
}

private func mapIdentity(
  _ observation: DiskplanScan.Observation<RuntimeObjectIdentity>,
  expected: DiskplanPolicy.ObjectIdentity
) -> DiskplanPolicy.Observation<DiskplanPolicy.ObjectIdentity> {
  let current = mapObservation(
    observation,
    collector: "runtime.identity"
  ) { (identity: RuntimeObjectIdentity) -> DiskplanPolicy.ObjectIdentity? in
    guard identity.device >= 0 else { return nil }
    let kind: ObjectKind
    switch identity.objectType {
    case .regular: kind = .regularFile
    case .directory: kind = .directory
    case .symbolicLink: kind = .symbolicLink
    case .other: return nil
    }
    return DiskplanPolicy.ObjectIdentity(
      device: UInt64(identity.device),
      object: identity.fileID,
      generation: mapObservation(
        identity.generation,
        collector: "runtime.identity-generation",
        transform: Optional.some
      ),
      type: kind
    )
  }
  guard case .known(let identity) = current else { return current }
  let generation: DiskplanPolicy.Observation<UInt64>
  if case .known = expected.generation {
    generation = identity.generation
  } else {
    generation = expected.generation
  }
  return .known(
    ObjectIdentity(
      device: identity.device,
      object: identity.object,
      generation: generation,
      type: identity.type
    ))
}

private func mapContent(
  _ evidence: ContentEvidence,
  expected: ContentProtectionBaseline
) -> DiskplanPolicy.Observation<ContentProtectionBaseline> {
  switch evidence {
  case .collected(let baseline) where baseline.algorithm == "sha256":
    guard let digest = try? PolicyDigest(bytes: baseline.protectionDigest.bytes) else {
      return .failed(
        ObservationFailure(code: "invalid-digest", collector: "runtime.content"))
    }
    return .known(.requiredDigest(digest))
  case .notApplicable where !requiresContent(expected):
    return .known(expected)
  case .notRequested:
    return .unknown(.notRequested)
  case .notApplicable:
    return .unknown(.incompleteCoverage)
  case .absent:
    return .absent
  case .unknown:
    return .unknown(.incompleteCoverage)
  case .unreadable(_, let code):
    return .unreadable(
      ObservationFailure(code: runtimeErrorCode(code), collector: "runtime.content"))
  case .failed(_, let code):
    return .failed(
      ObservationFailure(code: runtimeErrorCode(code), collector: "runtime.content"))
  case .collected:
    return .failed(
      ObservationFailure(code: "unsupported-digest", collector: "runtime.content"))
  }
}

private func mapAccessPolicy(
  _ evidence: RuntimeProtectedObjectEvidence
) -> DiskplanPolicy.Observation<RequiredAccessPolicyBaseline> {
  mapAccessPolicy(
    evidence.accessPolicy,
    provider: evidence.providerBoundary,
    mountDevice: evidence.mountDevice
  )
}

private func mapAccessPolicy(
  _ access: DiskplanScan.Observation<AccessPolicyEvidence>,
  provider: DiskplanScan.Observation<ProviderBoundary>,
  mountDevice: DiskplanScan.Observation<Int64>
) -> DiskplanPolicy.Observation<RequiredAccessPolicyBaseline> {
  guard case .known(let accessValue) = access else {
    return mapFailure(access, collector: "runtime.access-policy")
  }
  guard case .known(let acl) = accessValue.aclDigest else {
    return mapFailure(accessValue.aclDigest, collector: "runtime.acl")
  }
  let providerObservation = mapProvider(provider)
  guard case .known(let providerValue) = providerObservation else {
    return providerObservation.erasingValue()
  }
  guard case .known(let device) = mountDevice, device >= 0 else {
    return mapFailure(mountDevice, collector: "runtime.mount")
  }
  guard let aclDigest = try? PolicyDigest(bytes: acl.bytes) else {
    return .failed(
      ObservationFailure(code: "invalid-acl-digest", collector: "runtime.acl"))
  }
  let accessBytes = Data(
    "uid=\(accessValue.ownerUserID);gid=\(accessValue.ownerGroupID);mode=\(accessValue.mode);flags=\(accessValue.flags)"
      .utf8)
  return .known(
    RequiredAccessPolicyBaseline(
      accessPolicyBytes: accessBytes,
      aclDigest: aclDigest,
      providerState: providerValue,
      mountIdentityBytes: Data("real-device:\(device)".utf8)
    ))
}

private func mapRoot(
  _ evidence: RuntimeNamespaceEvidence,
  expectedIdentity: DiskplanPolicy.ObjectIdentity,
  expected: NamespaceSealEvidence
) -> CurrentNamespaceComponent {
  CurrentNamespaceComponent(
    relativePath: nil,
    identity: mapIdentity(evidence.identity, expected: expectedIdentity),
    seal: mapNamespaceSeal(evidence, expected: expected)
  )
}

private func mapNamespaceSeal(
  _ evidence: RuntimeNamespaceEvidence,
  expected: NamespaceSealEvidence
) -> DiskplanPolicy.Observation<NamespaceSealEvidence> {
  let accessPolicy = mapObservation(
    evidence.accessPolicy,
    collector: "runtime.namespace-access"
  ) { access in
    "uid=\(access.ownerUserID);gid=\(access.ownerGroupID);mode=\(access.mode);flags=\(access.flags)"
  }
  let aclDigest: DiskplanPolicy.Observation<PolicyDigest>
  switch evidence.accessPolicy {
  case .known(let access):
    aclDigest = mapObservation(
      access.aclDigest,
      collector: "runtime.namespace-acl"
    ) { try? PolicyDigest(bytes: $0.bytes) }
  case .absent: aclDigest = .absent
  case .unknown: aclDigest = .unknown(.incompleteCoverage)
  case .unreadable(_, let code):
    aclDigest = .unreadable(
      ObservationFailure(code: runtimeErrorCode(code), collector: "runtime.namespace-acl"))
  case .failed(_, let code):
    aclDigest = .failed(
      ObservationFailure(code: runtimeErrorCode(code), collector: "runtime.namespace-acl"))
  }
  let provider = mapProvider(evidence.providerBoundary)
  let mountIdentity = mapObservation(
    evidence.mountDevice,
    collector: "runtime.namespace-mount"
  ) { device in
    device >= 0 ? "real-device:\(device)" : nil
  }
  let selectedAccessPolicy = selectedObservation(
    accessPolicy,
    expected: expected.accessPolicy
  )
  let selectedACLDigest = selectedObservation(aclDigest, expected: expected.aclDigest)
  let selectedProvider = selectedObservation(
    provider,
    expected: expected.providerBoundary
  )
  let selectedMountIdentity = selectedObservation(
    mountIdentity,
    expected: expected.mountIdentity
  )
  for failure in [
    selectedFailure(selectedAccessPolicy, expected: expected.accessPolicy),
    selectedFailure(selectedACLDigest, expected: expected.aclDigest),
    selectedFailure(selectedProvider, expected: expected.providerBoundary),
    selectedFailure(selectedMountIdentity, expected: expected.mountIdentity),
  ].compactMap({ $0 }) {
    return failure
  }
  return .known(
    NamespaceSealEvidence(
      trustedNamespace: expected.trustedNamespace,
      accessPolicy: selectedAccessPolicy,
      aclDigest: selectedACLDigest,
      providerBoundary: selectedProvider,
      mountIdentity: selectedMountIdentity
    ))
}

private func selectedFailure<Value>(
  _ observation: DiskplanPolicy.Observation<Value>,
  expected: DiskplanPolicy.Observation<Value>
) -> DiskplanPolicy.Observation<NamespaceSealEvidence>?
where Value: Equatable & Sendable {
  guard case .known = expected else { return nil }
  switch observation {
  case .known: return nil
  case .absent: return .absent
  case .unknown(let reason): return .unknown(reason)
  case .unreadable(let failure): return .unreadable(failure)
  case .failed(let failure): return .failed(failure)
  }
}

private func selectedObservation<Value>(
  _ current: DiskplanPolicy.Observation<Value>,
  expected: DiskplanPolicy.Observation<Value>
) -> DiskplanPolicy.Observation<Value> where Value: Equatable & Sendable {
  if case .known = expected { return current }
  return expected
}

private func mapProvider(
  _ observation: DiskplanScan.Observation<ProviderBoundary>
) -> DiskplanPolicy.Observation<ProviderState> {
  mapObservation(observation, collector: "runtime.file-provider") { boundary in
    switch boundary {
    case .localOrUnindicated: .local
    case .metadataOnly, .rejected: .fileProviderManaged
    case .unverified: nil
    }
  }
}

private func mapObservation<Source, Target>(
  _ observation: DiskplanScan.Observation<Source>,
  collector: String,
  transform: (Source) -> Target?
) -> DiskplanPolicy.Observation<Target>
where Source: Equatable & Sendable, Target: Equatable & Sendable {
  switch observation {
  case .known(let value):
    guard let mapped = transform(value) else { return .unknown(.incompleteCoverage) }
    return .known(mapped)
  case .absent: return .absent
  case .unknown: return .unknown(.incompleteCoverage)
  case .unreadable(_, let code):
    return .unreadable(
      ObservationFailure(code: runtimeErrorCode(code), collector: collector))
  case .failed(_, let code):
    return .failed(
      ObservationFailure(code: runtimeErrorCode(code), collector: collector))
  }
}

private func mapFailure<Source, Target>(
  _ observation: DiskplanScan.Observation<Source>,
  collector: String
) -> DiskplanPolicy.Observation<Target>
where Source: Equatable & Sendable, Target: Equatable & Sendable {
  mapObservation(observation, collector: collector) { _ in nil }
}

private func policyFailure<Target>(
  _ code: Int32?,
  collector: String
) -> DiskplanPolicy.Observation<Target> where Target: Equatable & Sendable {
  guard let code else { return .unknown(.incompleteCoverage) }
  if code == ENOENT { return .absent }
  let failure = ObservationFailure(code: runtimeErrorCode(code), collector: collector)
  return code == EACCES || code == EPERM ? .unreadable(failure) : .failed(failure)
}

private func runtimeErrorCode(_ code: Int32?) -> String {
  code.map { "errno:\($0)" } ?? "unavailable"
}

private func duplicateDescriptors(_ descriptors: [Int32]) throws -> [Int32] {
  var duplicates: [Int32] = []
  do {
    for descriptor in descriptors {
      let duplicate = Darwin.fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
      guard duplicate >= 0 else {
        throw RuntimeRevalidationCollectorError.duplicateDescriptorFailed(errno)
      }
      duplicates.append(duplicate)
    }
    return duplicates
  } catch {
    for duplicate in duplicates { Darwin.close(duplicate) }
    throw error
  }
}

extension DiskplanPolicy.Observation {
  fileprivate func erasingValue<NewValue: Equatable & Sendable>()
    -> DiskplanPolicy.Observation<NewValue>
  {
    switch self {
    case .absent: .absent
    case .known: .unknown(.incompleteCoverage)
    case .unknown(let reason): .unknown(reason)
    case .unreadable(let failure): .unreadable(failure)
    case .failed(let failure): .failed(failure)
    }
  }
}
