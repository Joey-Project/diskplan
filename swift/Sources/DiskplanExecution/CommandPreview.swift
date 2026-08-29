import DiskplanPolicy
import Foundation

/// An engine-issued execution preview. The frontend renders this value verbatim and never
/// reconstructs an executable, argument, target path, or safety classification.
public struct AuthoritativeCommandPreview: Equatable, Sendable {
  public enum Kind: String, Equatable, Sendable {
    case command
    case nativeAdapter
    case compoundReleaseVerification
    case reportOnly
  }

  public enum Adapter: String, Equatable, Sendable {
    case genericRemove
    case gitWorktreeRemove
    case gitWorktreeDiscardLocalChanges
    case codexCleanTemporary
    case versionedArtifactRemove
    case completeReleaseSetRemove
  }

  public let actionID: ActionID
  public let kind: Kind
  public let adapter: Adapter
  public let executableRawPath: Data?
  public let arguments: [Data]
  public let workingDirectoryRawPath: Data?
  public let requiresForceWarning: Bool
  public let pathRaceResidual: Bool
  public let compoundReleaseGroupIDs: [String]
  public let compoundOwnerActionIDs: [ActionID]
  public let detailCode: String

  init(
    actionID: ActionID,
    kind: Kind,
    adapter: Adapter,
    executableRawPath: Data? = nil,
    arguments: [Data] = [],
    workingDirectoryRawPath: Data? = nil,
    requiresForceWarning: Bool = false,
    pathRaceResidual: Bool = false,
    compoundReleaseGroupIDs: [String] = [],
    compoundOwnerActionIDs: [ActionID] = [],
    detailCode: String
  ) {
    self.actionID = actionID
    self.kind = kind
    self.adapter = adapter
    self.executableRawPath = executableRawPath
    self.arguments = arguments
    self.workingDirectoryRawPath = workingDirectoryRawPath
    self.requiresForceWarning = requiresForceWarning
    self.pathRaceResidual = pathRaceResidual
    self.compoundReleaseGroupIDs = compoundReleaseGroupIDs
    self.compoundOwnerActionIDs = compoundOwnerActionIDs
    self.detailCode = detailCode
  }
}

enum AuthoritativeCommandPreviewBuilder {
  private struct ReleaseContext: Equatable {
    let groupIDs: [String]
    let ownerActionIDs: [ActionID]
  }

  static func previews(
    for overlay: ValidatedDecisionOverlay
  ) -> [AuthoritativeCommandPreview] {
    var actionByID: [ActionID: ActionDefinition] = [:]
    var releaseContextByActionID: [ActionID: ReleaseContext] = [:]
    for step in overlay.executionSteps {
      let releaseContext: ReleaseContext? =
        step.releaseSets.isEmpty
        ? nil
        : ReleaseContext(
          groupIDs: step.releaseSets.map(\.allocationGroupID).sorted {
            Data($0.utf8).lexicographicallyPrecedes(Data($1.utf8))
          },
          ownerActionIDs: Array(Set(step.releaseSets.flatMap(\.ownerActionIDs))).sorted()
        )
      for action in step.jitRevalidationActions {
        actionByID[action.id] = action
        if let releaseContext { releaseContextByActionID[action.id] = releaseContext }
      }
    }
    return actionByID.keys.sorted().compactMap { id in
      actionByID[id].map { preview($0, releaseContext: releaseContextByActionID[id]) }
    }
  }

  private static func preview(
    _ action: ActionDefinition,
    releaseContext: ReleaseContext? = nil
  ) -> AuthoritativeCommandPreview {
    let target = BoundMutationTarget(action: action)
    switch action.prototype.adapterContract {
    case .genericRemove(let contract):
      guard case .explicitlyNotApplicable = target.expectedContent else {
        return AuthoritativeCommandPreview(
          actionID: action.id,
          kind: .reportOnly,
          adapter: .genericRemove,
          requiresForceWarning:
            contract.forceRequirement == .requiresForceWithWarning,
          compoundReleaseGroupIDs: releaseContext?.groupIDs ?? [],
          compoundOwnerActionIDs: releaseContext?.ownerActionIDs ?? [],
          detailCode: "content-stability-native-adapter-required"
        )
      }
      return rmPreview(
        actionID: action.id,
        adapter: .genericRemove,
        target: target,
        kind: contract.targetKind,
        force: contract.forceRequirement,
        releaseContext: releaseContext,
        detailCode: "generic-path-slot-remove"
      )
    case .codexCleanTemporary(let contract):
      return rmPreview(
        actionID: action.id,
        adapter: .codexCleanTemporary,
        target: target,
        kind: target.expectedIdentity.type,
        force: contract.forceRequirement,
        releaseContext: releaseContext,
        detailCode: "codex-clean-temporary-scope"
      )
    case .versionedArtifactRemove(let contract):
      return rmPreview(
        actionID: action.id,
        adapter: .versionedArtifactRemove,
        target: target,
        kind: target.expectedIdentity.type,
        force: contract.forceRequirement,
        releaseContext: releaseContext,
        detailCode: "versioned-artifact-slot-remove"
      )
    case .gitWorktreeRemove:
      return AuthoritativeCommandPreview(
        actionID: action.id,
        kind: .nativeAdapter,
        adapter: .gitWorktreeRemove,
        compoundReleaseGroupIDs: releaseContext?.groupIDs ?? [],
        compoundOwnerActionIDs: releaseContext?.ownerActionIDs ?? [],
        detailCode: "descriptor-bound-quarantine-remove"
      )
    case .gitWorktreeDiscardLocalChanges:
      return AuthoritativeCommandPreview(
        actionID: action.id,
        kind: .nativeAdapter,
        adapter: .gitWorktreeDiscardLocalChanges,
        compoundReleaseGroupIDs: releaseContext?.groupIDs ?? [],
        compoundOwnerActionIDs: releaseContext?.ownerActionIDs ?? [],
        detailCode: "descriptor-bound-git-discard"
      )
    case .completeReleaseSetRemove:
      return AuthoritativeCommandPreview(
        actionID: action.id,
        kind: .compoundReleaseVerification,
        adapter: .completeReleaseSetRemove,
        compoundReleaseGroupIDs: releaseContext?.groupIDs ?? [],
        compoundOwnerActionIDs: releaseContext?.ownerActionIDs ?? [],
        detailCode: "all-owners-revalidate-before-first-mutation"
      )
    }
  }

  private static func rmPreview(
    actionID: ActionID,
    adapter: AuthoritativeCommandPreview.Adapter,
    target: BoundMutationTarget,
    kind: ObjectKind,
    force: ForceRequirement,
    releaseContext: ReleaseContext?,
    detailCode: String
  ) -> AuthoritativeCommandPreview {
    let leaf = target.targetPath.components.last ?? Data()
    return AuthoritativeCommandPreview(
      actionID: actionID,
      kind: .command,
      adapter: adapter,
      executableRawPath: Data("/bin/rm".utf8),
      arguments: PosixRemoveAdapter.relativeArguments(
        leaf: leaf,
        kind: kind,
        force: force
      ),
      workingDirectoryRawPath: parentRawPath(target),
      requiresForceWarning: force == .requiresForceWithWarning,
      pathRaceResidual: true,
      compoundReleaseGroupIDs: releaseContext?.groupIDs ?? [],
      compoundOwnerActionIDs: releaseContext?.ownerActionIDs ?? [],
      detailCode: detailCode
    )
  }

  private static func parentRawPath(_ target: BoundMutationTarget) -> Data {
    var path = target.rawRoot.absoluteBytes
    while path.count > 1 && path.last == UInt8(ascii: "/") { path.removeLast() }
    for component in target.targetPath.components.dropLast() {
      if path.last != UInt8(ascii: "/") { path.append(UInt8(ascii: "/")) }
      path.append(component)
    }
    return path
  }
}
