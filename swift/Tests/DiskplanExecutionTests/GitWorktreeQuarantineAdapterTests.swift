import Darwin
@_spi(DiskplanEngine) @testable import DiskplanExecution
import DiskplanPolicy
import Foundation
import Testing

@Test
func gitWorktreeQuarantineDeletesOnlyTheVerifiedTree() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let adapter = testAdapter()

  #expect(
    await adapter.apply(fixture.removeOperation, context: gitTestContext())
      == .succeeded(detailCode: "git-worktree-quarantine-removed")
  )
  #expect(await adapter.postverify(fixture.removeOperation) == .satisfied)
  #expect(!slotExists(fixture.worktree))
  #expect(FileManager.default.fileExists(atPath: fixture.outsideFile.path))
  #expect(await adapter.disposition(for: fixture.action.id) == .removed)
}

@Test
func gitWorktreeQuarantineRejectsSourceReplacementBeforeRename() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let adapter = testAdapter(
    hooks: .init(beforeQuarantine: {
      try? FileManager.default.removeItem(at: fixture.worktree)
      try? FileManager.default.createSymbolicLink(
        at: fixture.worktree,
        withDestinationURL: fixture.outsideDirectory
      )
    }))

  guard
    case .failed(let failure) = await adapter.apply(
      fixture.removeOperation,
      context: gitTestContext()
    )
  else {
    Issue.record("replacement must fail before quarantine")
    return
  }
  #expect(failure.code == "source-slot-identity-mismatch")
  #expect(FileManager.default.fileExists(atPath: fixture.outsideFile.path))
}

@Test
func gitWorktreeQuarantineDoesNotFollowNamespaceSymlink() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let quarantine = fixture.root.appendingPathComponent(".diskplan-quarantine")
  try FileManager.default.createSymbolicLink(
    at: quarantine,
    withDestinationURL: fixture.outsideDirectory
  )

  guard
    case .failed(let failure) = await testAdapter().apply(
      fixture.removeOperation,
      context: gitTestContext()
    )
  else {
    Issue.record("a symlink cannot serve as the quarantine namespace")
    return
  }
  #expect(failure.code == "open-quarantine-directory")
  #expect(slotExists(fixture.worktree))
  #expect(FileManager.default.fileExists(atPath: fixture.outsideFile.path))
}

@Test
func gitWorktreeQuarantineRenameIsExclusiveAndNoClobber() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let quarantine = fixture.root.appendingPathComponent(".diskplan-quarantine")
  try createPrivateDirectory(quarantine)
  let collision = quarantine.appendingPathComponent(fixture.action.id.hex)
  try createPrivateDirectory(collision)
  let marker = collision.appendingPathComponent("keep")
  try Data("collision".utf8).write(to: marker)

  guard
    case .failed(let failure) = await testAdapter().apply(
      fixture.removeOperation,
      context: gitTestContext()
    )
  else {
    Issue.record("RENAME_EXCL must reject a pre-existing destination")
    return
  }
  #expect(failure.code == "quarantine-rename")
  #expect(slotExists(fixture.worktree))
  #expect(FileManager.default.fileExists(atPath: marker.path))
}

@Test
func gitWorktreeVerificationFailureRestoresTheExactSourceSlot() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let quarantined = fixture.quarantinedURL
  let adapter = testAdapter(
    hooks: .init(beforePostQuarantineVerification: {
      try? Data("unexpected".utf8).write(
        to: quarantined.appendingPathComponent("new-local-data")
      )
    }))

  guard
    case .failed(let failure) = await adapter.apply(
      fixture.removeOperation,
      context: gitTestContext()
    )
  else {
    Issue.record("coverage mismatch must prevent deletion")
    return
  }
  #expect(failure.code == "quarantine-verification-failed-restored")
  #expect(slotExists(fixture.worktree))
  #expect(!slotExists(quarantined))
  #expect(
    await adapter.disposition(for: fixture.action.id)
      == .restoredAfterVerificationFailure(code: "worktree-content-mismatch")
  )
}

@Test
func gitWorktreeRestoreCollisionRetainsTypedRecoveryLocator() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let quarantined = fixture.quarantinedURL
  let adapter = testAdapter(
    hooks: .init(
      beforePostQuarantineVerification: {
        try? Data("unexpected".utf8).write(
          to: quarantined.appendingPathComponent("new-local-data")
        )
      },
      beforeRestore: {
        try? createPrivateDirectory(fixture.worktree)
        try? Data("replacement".utf8).write(
          to: fixture.worktree.appendingPathComponent("keep")
        )
      }
    ))

  guard
    case .failed(let failure) = await adapter.apply(
      fixture.removeOperation,
      context: gitTestContext()
    )
  else {
    Issue.record("restore collision must retain the verified quarantine")
    return
  }
  #expect(failure.code == "quarantine-verification-failed-retained")
  #expect(slotExists(quarantined))
  #expect(
    FileManager.default.fileExists(atPath: fixture.worktree.appendingPathComponent("keep").path))
  guard
    case .some(.quarantineRetained(let locator, let failureCode)) =
      await adapter.disposition(for: fixture.action.id)
  else {
    Issue.record("missing typed recovery locator")
    return
  }
  #expect(locator.quarantineDirectoryName == Data(".diskplan-quarantine".utf8))
  #expect(locator.quarantineLeafName == Data(fixture.action.id.hex.utf8))
  #expect(locator.identity == fixture.action.prototype.targetIdentity)
  #expect(failureCode == "worktree-content-mismatch")
}

@Test
func gitAdministrativeCleanupFailureIsTypedResidualAfterRootDeletion() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let adapter = testAdapter(gitOutcome: .failed(ExecutionAdapterFailure(code: "git-prune-failed")))

  guard
    case .succeeded(let detailCode) = await adapter.apply(
      fixture.removeOperation,
      context: gitTestContext()
    )
  else {
    Issue.record("Git metadata cleanup failure must report a partial residual")
    return
  }
  #expect(detailCode == "git-worktree-removed-with-administrative-residual")
  #expect(!slotExists(fixture.worktree))
  guard
    case .some(.removedWithAdministrativeResidual(let residual)) =
      await adapter.disposition(for: fixture.action.id)
  else {
    Issue.record("missing typed Git administrative residual")
    return
  }
  #expect(residual.failure.code == "git-prune-failed")
  #expect(await adapter.postverify(fixture.removeOperation) == .expectedResidual(residual.failure))
  #expect(
    residual.registrationID
      == fixture.registration.registrationID
  )
}

@Test
func gitWorktreeDeadlineStopsBeforeMutation() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }

  #expect(
    await testAdapter().apply(
      fixture.removeOperation,
      context: MutationExecutionContext(
        deadlineSeconds: 5,
        nowSeconds: { 5 },
        finalDescriptorPreflight: { _ in .verified }
      )
    ) == .timedOut
  )
  #expect(slotExists(fixture.worktree))
}

@Test
func gitWorktreeDeadlineAfterRootDeletionLeavesTypedAdministrativeResidual() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let clock = LockedGitTestClock()
  var hooks = GitWorktreeQuarantineAdapter.Hooks()
  hooks.beforeAdministrativeCleanup = { clock.set(5) }
  let adapter = testAdapter(hooks: hooks)

  #expect(
    await adapter.apply(
      fixture.removeOperation,
      context: MutationExecutionContext(
        deadlineSeconds: 5,
        nowSeconds: { clock.value() },
        finalDescriptorPreflight: { _ in .verified }
      )
    ) == .succeeded(detailCode: "git-worktree-removed-with-administrative-residual")
  )
  #expect(!slotExists(fixture.worktree))
  guard
    case .some(.removedWithAdministrativeResidual(let residual)) =
      await adapter.disposition(for: fixture.action.id)
  else {
    Issue.record("missing deadline administrative residual")
    return
  }
  #expect(residual.failure.code == "git-administrative-cleanup-deadline")
  #expect(await adapter.postverify(fixture.removeOperation) == .expectedResidual(residual.failure))
}

@Test
func gitWorktreeCancellationAfterRootDeletionLeavesTypedAdministrativeResidual() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  var hooks = GitWorktreeQuarantineAdapter.Hooks()
  hooks.beforeAdministrativeCleanup = {
    withUnsafeCurrentTask { task in task?.cancel() }
  }
  let adapter = testAdapter(hooks: hooks)

  let outcome = await Task {
    await adapter.apply(fixture.removeOperation, context: gitTestContext())
  }.value
  #expect(outcome == .succeeded(detailCode: "git-worktree-removed-with-administrative-residual"))
  #expect(!slotExists(fixture.worktree))
  guard
    case .some(.removedWithAdministrativeResidual(let residual)) =
      await adapter.disposition(for: fixture.action.id)
  else {
    Issue.record("missing cancellation administrative residual")
    return
  }
  #expect(residual.failure.code == "git-administrative-cleanup-cancelled")
  #expect(await adapter.postverify(fixture.removeOperation) == .expectedResidual(residual.failure))
}

@Test
func gitDiscardUsesOnlyTypedGitCommandsAndVerifiesSuccessorCoverage() async throws {
  let fixture = try GitQuarantineFixture(discardLocalChanges: true)
  defer { fixture.cleanup() }
  let adapter = GitWorktreeQuarantineAdapter(
    hooks: .init(),
    gitRunner: { arguments, _, _ in
      if arguments.dropFirst().first == Data("reset".utf8) {
        try? Data("clean".utf8).write(to: fixture.payload)
      }
      return .succeeded(detailCode: "test-git")
    }
  )

  #expect(
    await adapter.apply(fixture.discardOperation, context: gitTestContext())
      == .succeeded(detailCode: "git-worktree-local-changes-discarded")
  )
  #expect(await adapter.postverify(fixture.discardOperation) == .satisfied)
  #expect(try Data(contentsOf: fixture.payload) == Data("clean".utf8))
  #expect(slotExists(fixture.worktree))
}

@Test
func gitExecutionGuardRequiresExactLinkedRegistrationAndDistinctObjects() throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let registration = fixture.registration
  let exact = gitRegistrationGuardEvidence(
    registration: registration,
    linkage: .known(.linked(registrationID: registration.registrationID))
  )
  #expect(GitWorktreeQuarantineAdapter.hasExecutableLinkedRegistration(exact))

  let mismatchedID = gitRegistrationGuardEvidence(
    registration: registration,
    linkage: .known(.linked(registrationID: gitDigest(76)))
  )
  #expect(!GitWorktreeQuarantineAdapter.hasExecutableLinkedRegistration(mismatchedID))

  let ordinary = gitRegistrationGuardEvidence(
    registration: registration,
    linkage: .known(.ordinary)
  )
  #expect(!GitWorktreeQuarantineAdapter.hasExecutableLinkedRegistration(ordinary))

  let sameIdentity = try GitWorktreeRegistrationEvidence(
    registeredWorktreeIdentity: registration.registeredWorktreeIdentity,
    administrativeDirectoryIdentity: registration.administrativeDirectoryIdentity,
    commonDirectoryIdentity: registration.administrativeDirectoryIdentity,
    registrationID: registration.registrationID,
    metadataDigest: registration.metadataDigest
  )
  let aliased = gitRegistrationGuardEvidence(
    registration: sameIdentity,
    linkage: .known(.linked(registrationID: sameIdentity.registrationID))
  )
  #expect(!GitWorktreeQuarantineAdapter.hasExecutableLinkedRegistration(aliased))
}

private struct GitQuarantineFixture: @unchecked Sendable {
  let container: URL
  let root: URL
  let worktree: URL
  let payload: URL
  let outsideDirectory: URL
  let outsideFile: URL
  let registration: GitWorktreeRegistrationEvidence
  let action: ActionDefinition
  let removeOperation: ExecutionAdapterOperation
  let discardOperation: ExecutionAdapterOperation

  var quarantinedURL: URL {
    root.appendingPathComponent(".diskplan-quarantine")
      .appendingPathComponent(action.id.hex)
  }

  init(discardLocalChanges: Bool = false) throws {
    container = FileManager.default.temporaryDirectory
      .appendingPathComponent("diskplan-git-quarantine-\(UUID().uuidString)")
      .resolvingSymlinksInPath()
    root = container.appendingPathComponent("scan-root")
    worktree = root.appendingPathComponent("worktree")
    payload = worktree.appendingPathComponent("payload")
    outsideDirectory = container.appendingPathComponent("outside")
    outsideFile = outsideDirectory.appendingPathComponent("keep")

    try createPrivateDirectory(container)
    try createPrivateDirectory(root)
    try createPrivateDirectory(worktree)
    try createPrivateDirectory(outsideDirectory)
    try Data("keep".utf8).write(to: outsideFile)
    try FileManager.default.createSymbolicLink(
      at: worktree.appendingPathComponent("outside-link"),
      withDestinationURL: outsideFile
    )

    let common = root.appendingPathComponent("git-common")
    let worktrees = common.appendingPathComponent("worktrees")
    let administrative = worktrees.appendingPathComponent("fixture")
    try createPrivateDirectory(common)
    try createPrivateDirectory(worktrees)
    try createPrivateDirectory(administrative)
    try Data("gitdir: \(administrative.path)\n".utf8)
      .write(to: worktree.appendingPathComponent(".git"))

    let successorDigest: PolicyDigest?
    if discardLocalChanges {
      try Data("clean".utf8).write(to: payload)
      successorDigest = try GitWorktreeQuarantineAdapter.measuredContentDigest(
        atRawPath: Data(worktree.path.utf8)
      )
      try Data("dirty".utf8).write(to: payload)
    } else {
      try Data("payload".utf8).write(to: payload)
      successorDigest = nil
    }
    let currentDigest = try GitWorktreeQuarantineAdapter.measuredContentDigest(
      atRawPath: Data(worktree.path.utf8)
    )
    let worktreeIdentity = try gitFilesystemIdentity(worktree, kind: .directory)
    registration = try GitWorktreeRegistrationEvidence(
      registeredWorktreeIdentity: worktreeIdentity,
      administrativeDirectoryIdentity: try gitFilesystemIdentity(
        administrative,
        kind: .directory
      ),
      commonDirectoryIdentity: try gitFilesystemIdentity(common, kind: .directory),
      registrationID: gitDigest(75),
      metadataDigest: gitDigest(74)
    )
    let successor = try successorDigest.map {
      try GitWorktreeExecutionBaseline(
        headIdentity: gitDigest(70),
        indexDigest: gitDigest(72),
        localChanges: .clean,
        contentProtection: .requiredDigest($0)
      )
    }
    let localChanges: GitLocalChangesState =
      discardLocalChanges
      ? .present(changeSetDigest: gitDigest(73))
      : .clean
    let gitEvidence = GitWorktreeEvidence(
      noFollowTraversalComplete: .known(true),
      headIdentity: .known(gitDigest(70)),
      indexDigest: .known(gitDigest(71)),
      localChanges: .known(localChanges),
      registration: .known(registration),
      linkage: .known(.linked(registrationID: registration.registrationID)),
      sparseCheckout: .known(.disabled),
      nestedRepositories: .known(.none),
      submodules: .known(.none),
      trustedExclusiveNamespace: .known(true),
      postQuarantineCoverage: .known(.complete),
      postDiscardSuccessor: successor.map { Observation.known($0) } ?? .absent
    )

    let rawRoot = try RawRootPath(absoluteBytes: Data(root.path.utf8))
    let rootIdentity = try gitFilesystemIdentity(root, kind: .directory)
    let seal = NamespaceSealEvidence(
      trustedNamespace: .ownerPrivate,
      accessPolicy: .known("owner-private"),
      aclDigest: .known(gitDigest(91)),
      providerBoundary: .known(.local),
      mountIdentity: .known("test-mount")
    )
    let namespace = try ProtectedNamespaceBinding(
      rawRoot: rawRoot,
      rootIdentity: rootIdentity,
      rootSeal: seal,
      targetPath: try RawTargetPath(components: [Data("worktree".utf8)]),
      targetIdentity: worktreeIdentity,
      parentChain: []
    )
    let facts = FrozenGlobalFacts(
      captureID: gitDigest(89),
      profile: "standard",
      configuration: Data("git-quarantine-test".utf8),
      coverage: [
        GlobalCoverageFact(rawRoot: rawRoot, coverage: .complete, reasons: ["complete"])
      ],
      semanticReferenceTimeSeconds: 100,
      policyVersion: "policy-1",
      schemaVersion: "schema-1"
    )
    let evidence = try FrozenEvidenceSnapshot(
      captureID: facts.captureID,
      globalFactsHash: facts.globalFactsHash,
      candidateID: "worktree",
      namespaceBinding: namespace,
      identity: .known(worktreeIdentity),
      coverage: .complete,
      collectorStatus: .known(.complete),
      activity: .known(.inactive),
      explicitProtection: .known(.notProtected),
      providerState: .known(.local),
      recoverability: .known(.recoverable),
      recoverabilityReviewFacts: [],
      dependencyState: .known(.complete),
      semanticReviewFacts: [],
      accessPolicy: .known("owner-private"),
      contentProtection: .known(.requiredDigest(currentDigest)),
      aclDigest: .known(gitDigest(93)),
      targetMountIdentity: .known("test-mount"),
      removalForceRequirement: .known(.notRequired),
      quarantineCapability: .known(true),
      gitWorktree: gitEvidence,
      adapterScope: .gitWorktree,
      additionalAdapterScopes: [],
      classificationClaims: ClassificationFacet.allCases.map {
        ClassificationClaim(
          facet: $0,
          value: "known-\($0.rawValue)",
          source: .genericFallback,
          evidenceKey: "fixture-\($0.rawValue)"
        )
      },
      semanticReferenceTimeSeconds: 100,
      policyVersion: "policy-1",
      schemaVersion: "schema-1"
    )
    let request: ActionAdapterRequest =
      discardLocalChanges
      ? .gitWorktreeDiscardLocalChanges
      : .gitWorktreeRemove
    let prototype = try ActionPrototype.build(request: request, evidence: evidence)
    let evaluation = try OneVotePolicy.evaluate(
      OneVotePolicyInputs.build(evidence: evidence, globalFacts: facts)
    )
    action = try ActionDefinition.build(
      prototype: prototype,
      evidence: evidence,
      globalFacts: facts,
      prerequisites: [],
      evaluation: evaluation,
      displayMetrics: ActionDisplayMetrics(
        immediateReclaimBytes: .known(1),
        inactiveDurationSeconds: .known(1),
        rebuildCost: .known(1),
        cleanupCost: .known(1),
        canonicalRawPath: Data("worktree".utf8)
      )
    )
    switch action.prototype.adapterContract {
    case .gitWorktreeRemove(let contract):
      removeOperation = .gitWorktreeRemove(BoundMutationTarget(action: action), contract)
      discardOperation = removeOperation
    case .gitWorktreeDiscardLocalChanges(let contract):
      discardOperation = .gitWorktreeDiscardLocalChanges(
        BoundMutationTarget(action: action),
        contract
      )
      removeOperation = discardOperation
    default:
      throw GitFixtureError.invalidContract
    }
  }

  func cleanup() {
    try? FileManager.default.removeItem(at: container)
  }
}

private enum GitFixtureError: Error {
  case invalidContract
}

private func gitRegistrationGuardEvidence(
  registration: GitWorktreeRegistrationEvidence,
  linkage: Observation<GitWorktreeLinkageState>
) -> GitWorktreeEvidence {
  GitWorktreeEvidence(
    noFollowTraversalComplete: .absent,
    headIdentity: .absent,
    indexDigest: .absent,
    localChanges: .absent,
    registration: .known(registration),
    linkage: linkage,
    sparseCheckout: .absent,
    nestedRepositories: .absent,
    submodules: .absent,
    trustedExclusiveNamespace: .absent,
    postQuarantineCoverage: .absent,
    postDiscardSuccessor: .absent
  )
}

private final class LockedGitTestClock: @unchecked Sendable {
  private let lock = NSLock()
  private var now: Int64 = 0

  func set(_ value: Int64) {
    lock.lock()
    now = value
    lock.unlock()
  }

  func value() -> Int64 {
    lock.lock()
    defer { lock.unlock() }
    return now
  }
}

private func testAdapter(
  hooks: GitWorktreeQuarantineAdapter.Hooks = .init(),
  gitOutcome: AdapterOperationOutcome = .succeeded(detailCode: "test-git")
) -> GitWorktreeQuarantineAdapter {
  GitWorktreeQuarantineAdapter(
    hooks: hooks,
    gitRunner: { _, _, _ in gitOutcome }
  )
}

private func gitTestContext() -> MutationExecutionContext {
  MutationExecutionContext(
    deadlineSeconds: 1_000,
    nowSeconds: { 0 },
    finalDescriptorPreflight: { _ in .verified }
  )
}

private func createPrivateDirectory(_ url: URL) throws {
  try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
  guard url.path.withCString({ Darwin.chmod($0, 0o700) }) == 0 else {
    throw GitFixtureError.invalidContract
  }
}

private func slotExists(_ url: URL) -> Bool {
  var value = stat()
  return url.path.withCString { Darwin.lstat($0, &value) == 0 }
}

private func gitFilesystemIdentity(_ url: URL, kind: ObjectKind) throws -> ObjectIdentity {
  var value = stat()
  guard url.path.withCString({ Darwin.lstat($0, &value) }) == 0 else {
    throw GitFixtureError.invalidContract
  }
  return ObjectIdentity(
    device: UInt64(UInt32(bitPattern: value.st_dev)),
    object: UInt64(value.st_ino),
    generation: .known(UInt64(value.st_gen)),
    type: kind
  )
}

private func gitDigest(_ byte: UInt8) -> PolicyDigest {
  try! PolicyDigest(bytes: Data(repeating: byte, count: 32))
}
