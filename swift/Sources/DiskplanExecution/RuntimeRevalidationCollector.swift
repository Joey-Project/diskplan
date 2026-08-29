import Darwin
import DiskplanPolicy
import DiskplanScan
import Foundation

struct RuntimeRevalidationBacking: Sendable {
  let collectCurrent:
    @Sendable (RevalidationRequest, PolicyDigest) async throws -> CurrentRevalidationSnapshot
  let collectJIT:
    @Sendable (JITRevalidationRequest, PolicyDigest) async throws -> JITRevalidationSnapshot
  let collectReleasePostconditions:
    @Sendable (ReleasePostVerificationRequest) async throws -> [CurrentReleasePostcondition]

  init(
    collectCurrent:
      @escaping @Sendable (RevalidationRequest, PolicyDigest) async throws
      -> CurrentRevalidationSnapshot,
    collectJIT:
      @escaping @Sendable (JITRevalidationRequest, PolicyDigest) async throws
      -> JITRevalidationSnapshot,
    collectReleasePostconditions:
      @escaping @Sendable (ReleasePostVerificationRequest) async throws
      -> [CurrentReleasePostcondition]
  ) {
    self.collectCurrent = collectCurrent
    self.collectJIT = collectJIT
    self.collectReleasePostconditions = collectReleasePostconditions
  }
}

/// Combines fresh policy/global evidence with Scan-owned descriptor evidence. The backing must
/// rebuild fresh policy evidence with the supplied capture ID; this layer never copies immutable
/// scan evidence forward as if it were current.
final class RuntimeRevalidationCollector: @unchecked Sendable {
  private let session: RuntimeEvidenceSession
  private let backing: RuntimeRevalidationBacking

  init(session: RuntimeEvidenceSession, backing: RuntimeRevalidationBacking) {
    self.session = session
    self.backing = backing
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
      collectReleasePostconditions: { [backing] request in
        try await backing.collectReleasePostconditions(request)
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
      let captureID = try PolicyDigest(bytes: lease.captureID.bytes)
      let base = try await backing.collectCurrent(request, captureID)
      guard base.captureID == captureID else {
        throw RuntimeRevalidationCollectorError.backingCaptureMismatch
      }
      let actions = uniqueActions(request.validatedOverlay)
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
      let captureID = try PolicyDigest(bytes: lease.captureID.bytes)
      let base = try await backing.collectJIT(request, captureID)
      guard base.snapshot.captureID == captureID else {
        throw RuntimeRevalidationCollectorError.backingCaptureMismatch
      }
      let actionByID = Dictionary(
        uniqueKeysWithValues: request.plan.actions.map { ($0.id, $0) })
      let actions = try request.actionIDs.map { identifier in
        guard let action = actionByID[identifier] else {
          throw RuntimeRevalidationCollectorError.actionMissing(identifier)
        }
        return action
      }
      let paths = try lease.collectPaths(actions.map(pathRequest))
      let snapshot = try replacingProtectedEvidence(
        base.snapshot,
        actions: actions,
        paths: paths,
        captureID: captureID
      )
      return JITRevalidationSnapshot(
        oneShotNonce: base.oneShotNonce,
        authorizationCurrentBindingHash: base.authorizationCurrentBindingHash,
        preparationGeneration: base.preparationGeneration,
        epochID: base.epochID,
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
        targetIdentity: mapIdentity(evidence.target.identity),
        targetAccessPolicy: mapAccessPolicy(evidence.target),
        targetContent: mapContent(
          evidence.target.content,
          expected: request.target.expectedContent
        ),
        root: mapRoot(
          evidence.root,
          expected: request.target.expectedRootSeal
        ),
        parents: zip(
          request.target.targetPath.components.dropLast().indices,
          zip(evidence.parents, request.target.expectedParentSeals)
        ).map { index, pair in
          let (current, expected) = pair
          return CurrentNamespaceComponent(
            relativePath: try? RawTargetPath(
              components: Array(request.target.targetPath.components.prefix(index + 1))),
            identity: mapIdentity(current.identity),
            seal: mapNamespaceSeal(current, expected: expected)
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
        targetIdentity: mapIdentity(path.target.identity),
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
        root: mapRoot(path.root, expected: namespace.rootSeal),
        parents: zip(path.parents, namespace.parentChain).map { current, expected in
          CurrentNamespaceComponent(
            relativePath: expected.relativePath,
            identity: mapIdentity(current.identity),
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

private enum RuntimeRevalidationCollectorError: Error, Equatable {
  case actionMissing(ActionID)
  case baseActionMissing(ActionID)
  case backingCaptureMismatch
  case pathCountMismatch
  case duplicateDescriptorFailed(Int32)
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
  _ observation: DiskplanScan.Observation<RuntimeObjectIdentity>
) -> DiskplanPolicy.Observation<DiskplanPolicy.ObjectIdentity> {
  mapObservation(observation, collector: "runtime.identity") { identity in
    guard identity.device >= 0 else { return nil }
    let kind: ObjectKind
    switch identity.objectType {
    case .regular: kind = .regularFile
    case .directory: kind = .directory
    case .symbolicLink: kind = .symbolicLink
    case .other: return nil
    }
    return ObjectIdentity(
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
  case .unavailable(_, let code):
    return policyFailure(code, collector: "runtime.content")
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
  expected: NamespaceSealEvidence
) -> CurrentNamespaceComponent {
  CurrentNamespaceComponent(
    relativePath: nil,
    identity: mapIdentity(evidence.identity),
    seal: mapNamespaceSeal(evidence, expected: expected)
  )
}

private func mapNamespaceSeal(
  _ evidence: RuntimeNamespaceEvidence,
  expected: NamespaceSealEvidence
) -> DiskplanPolicy.Observation<NamespaceSealEvidence> {
  guard case .known(let access) = evidence.accessPolicy else {
    return mapFailure(evidence.accessPolicy, collector: "runtime.namespace-access")
  }
  guard case .known(let acl) = access.aclDigest else {
    return mapFailure(access.aclDigest, collector: "runtime.namespace-acl")
  }
  let provider = mapProvider(evidence.providerBoundary)
  guard case .known(let providerValue) = provider else { return provider.erasingValue() }
  guard case .known(let device) = evidence.mountDevice, device >= 0 else {
    return mapFailure(evidence.mountDevice, collector: "runtime.namespace-mount")
  }
  guard let aclDigest = try? PolicyDigest(bytes: acl.bytes) else {
    return .failed(
      ObservationFailure(code: "invalid-acl-digest", collector: "runtime.namespace-acl"))
  }
  return .known(
    NamespaceSealEvidence(
      trustedNamespace: expected.trustedNamespace,
      accessPolicy: .known(
        "uid=\(access.ownerUserID);gid=\(access.ownerGroupID);mode=\(access.mode);flags=\(access.flags)"
      ),
      aclDigest: .known(aclDigest),
      providerBoundary: .known(providerValue),
      mountIdentity: .known("real-device:\(device)")
    ))
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
