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
  let quarantine = fixture.quarantineDirectory
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
  #expect(failure.code == "quarantine-execution-directory-exists")
  #expect(slotExists(fixture.worktree))
  #expect(FileManager.default.fileExists(atPath: fixture.outsideFile.path))
}

@Test
func gitWorktreeQuarantineExecutionDirectoryIsExclusiveAndNoClobber() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let quarantine = fixture.quarantineDirectory
  try createPrivateDirectory(quarantine)
  let collision = quarantine.appendingPathComponent("payload")
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
  #expect(failure.code == "quarantine-execution-directory-exists")
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
  #expect(
    locator.quarantineDirectoryName == Data(fixture.quarantineDirectory.lastPathComponent.utf8))
  #expect(locator.quarantineLeafName == Data("payload".utf8))
  #expect(locator.identity == fixture.action.prototype.targetIdentity)
  #expect(failureCode == "worktree-content-mismatch")
}

@Test
func gitWorktreeRestoreRejectsReplacedQuarantinePayloadWithoutPublishingLocator() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let quarantined = fixture.quarantinedURL
  let displaced = fixture.quarantineDirectory.appendingPathComponent("displaced-payload")
  let adapter = testAdapter(
    hooks: .init(
      beforePostQuarantineVerification: {
        try? Data("unexpected".utf8).write(
          to: quarantined.appendingPathComponent("new-local-data")
        )
      },
      beforeRestore: {
        try? FileManager.default.moveItem(at: quarantined, to: displaced)
        try? createPrivateDirectory(quarantined)
        try? Data("replacement".utf8).write(
          to: quarantined.appendingPathComponent("keep")
        )
      }
    ))

  guard
    case .failed(let failure) = await adapter.apply(
      fixture.removeOperation,
      context: gitTestContext()
    )
  else {
    Issue.record("a replaced quarantine payload must not be restored")
    return
  }
  #expect(failure.code == "quarantine-verification-failed-unverified")
  #expect(!slotExists(fixture.worktree))
  #expect(slotExists(quarantined))
  #expect(slotExists(displaced))
  #expect(
    await adapter.disposition(for: fixture.action.id)
      == .quarantineBindingUnverified(failureCode: "worktree-content-mismatch")
  )
  guard case .failed(let postFailure) = await adapter.postverify(fixture.removeOperation) else {
    Issue.record("an unverified recovery binding must remain a typed post-verification failure")
    return
  }
  #expect(
    postFailure.code == "quarantine-binding-unverified-worktree-content-mismatch"
  )
}

@Test
func gitWorktreeRestoreRejectsMovedRawRootWithoutPublishingLocator() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let displacedRoot = fixture.container.appendingPathComponent("displaced-scan-root")
  let displacedQuarantine =
    displacedRoot
    .appendingPathComponent(fixture.quarantineDirectory.lastPathComponent)
    .appendingPathComponent("payload")
  let adapter = testAdapter(
    hooks: .init(
      beforePostQuarantineVerification: {
        try? Data("unexpected".utf8).write(
          to: fixture.quarantinedURL.appendingPathComponent("new-local-data")
        )
      },
      beforeRestore: {
        try? FileManager.default.moveItem(at: fixture.root, to: displacedRoot)
        try? createPrivateDirectory(fixture.root)
      }
    ))

  guard
    case .failed(let failure) = await adapter.apply(
      fixture.removeOperation,
      context: gitTestContext()
    )
  else {
    Issue.record("a moved raw root must not receive a restore or publish a stale locator")
    return
  }
  #expect(failure.code == "quarantine-verification-failed-unverified")
  #expect(!slotExists(fixture.worktree))
  #expect(slotExists(displacedQuarantine))
  #expect(
    await adapter.disposition(for: fixture.action.id)
      == .quarantineBindingUnverified(failureCode: "worktree-content-mismatch")
  )
}

@Test
func gitAdministrativeMetadataDriftIsTypedResidualAfterRootDeletion() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  var hooks = GitWorktreeQuarantineAdapter.Hooks()
  hooks.beforeAdministrativeCleanup = {
    try? Data("drift".utf8).write(
      to: fixture.administrative.appendingPathComponent("concurrent"))
  }
  let adapter = testAdapter(hooks: hooks)

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
  #expect(residual.failure.code == "verified-quarantine-changed-before-delete")
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
func dirtyGitWorktreeOperationsAreReportOnlyAndNeverInvokeGit() async throws {
  let fixture = try GitQuarantineFixture(discardLocalChanges: true)
  defer { fixture.cleanup() }
  let adapter = GitWorktreeQuarantineAdapter(hooks: .init())
  let production = ProductionExecutionAdapter(
    genericRemove: PosixRemoveAdapter(),
    gitWorktree: adapter
  )

  for operation in [fixture.discardOperation, fixture.removeOperation] {
    #expect(
      await adapter.apply(operation, context: gitTestContext())
        == .failed(ExecutionAdapterFailure(code: "git-worktree-dirty-report-only"))
    )
    #expect(
      await production.apply(operation, context: gitTestContext())
        == .failed(ExecutionAdapterFailure(code: "git-worktree-dirty-report-only"))
    )
    #expect(
      await production.postverify(operation)
        == .notSatisfied(code: "git-worktree-dirty-report-only")
    )
  }
  #expect(try Data(contentsOf: fixture.payload) == Data("dirty".utf8))
  #expect(slotExists(fixture.worktree))
}

@Test
func productionRouterKeepsCleanWorktreeQuarantineRemovalExecutable() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let production = ProductionExecutionAdapter(
    genericRemove: PosixRemoveAdapter(),
    gitWorktree: testAdapter()
  )

  #expect(
    await production.apply(fixture.removeOperation, context: gitTestContext())
      == .succeeded(detailCode: "git-worktree-quarantine-removed")
  )
  #expect(await production.postverify(fixture.removeOperation) == .satisfied)
  #expect(!slotExists(fixture.worktree))
}

@Test
func gitAdministrativeCleanupDeletesOnlyTheExactRegistration() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let sibling = fixture.worktrees.appendingPathComponent("unrelated-stale")
  try createPrivateDirectory(sibling)
  let marker = sibling.appendingPathComponent("keep")
  try Data("unrelated".utf8).write(to: marker)

  #expect(
    await testAdapter().apply(fixture.removeOperation, context: gitTestContext())
      == .succeeded(detailCode: "git-worktree-quarantine-removed")
  )
  #expect(!slotExists(fixture.administrative))
  #expect(FileManager.default.fileExists(atPath: marker.path))
}

@Test
func gitAdministrativeMetadataDriftBeforeApplyRejectsTheBoundRegistration() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  try Data("unexpected".utf8).write(
    to: fixture.administrative.appendingPathComponent("drift"))

  guard
    case .failed(let failure) = await testAdapter().apply(
      fixture.removeOperation, context: gitTestContext())
  else {
    Issue.record("pre-apply administrative drift must reject")
    return
  }
  #expect(failure.code == "git-administrative-metadata-mismatch")
  #expect(slotExists(fixture.worktree))
  #expect(slotExists(fixture.administrative))
}

@Test
func gitAdministrativeRootReplacementCannotBeUnlinkedAsTheBoundRegistration() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let displaced = fixture.worktrees.appendingPathComponent("displaced-fixture")
  var hooks = GitWorktreeQuarantineAdapter.Hooks()
  hooks.beforeAdministrativeCleanup = {
    try? FileManager.default.moveItem(at: fixture.administrative, to: displaced)
    try? createPrivateDirectory(fixture.administrative)
  }
  let adapter = testAdapter(hooks: hooks)

  #expect(
    await adapter.apply(fixture.removeOperation, context: gitTestContext())
      == .succeeded(detailCode: "git-worktree-removed-with-administrative-residual")
  )
  #expect(slotExists(fixture.administrative))
  #expect(slotExists(displaced))
  guard
    case .some(.removedWithAdministrativeResidual(let residual)) =
      await adapter.disposition(for: fixture.action.id)
  else {
    Issue.record("registration replacement must be a typed residual")
    return
  }
  #expect(residual.failure.code == "source-slot-identity-mismatch")
}

@Test
func gitWorktreesParentACLDriftBecomesAdministrativeResidual() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  var hooks = GitWorktreeQuarantineAdapter.Hooks()
  hooks.beforeAdministrativeCleanup = {
    try! addEveryoneWriteACL(to: fixture.worktrees)
  }
  let adapter = testAdapter(hooks: hooks)

  #expect(
    await adapter.apply(fixture.removeOperation, context: gitTestContext())
      == .succeeded(detailCode: "git-worktree-removed-with-administrative-residual")
  )
  guard
    case .some(.removedWithAdministrativeResidual(let residual)) =
      await adapter.disposition(for: fixture.action.id)
  else {
    Issue.record("worktrees access drift must be a typed residual")
    return
  }
  #expect(residual.failure.code == "git-worktrees-parent-seal-mismatch-before-cleanup")
}

@Test
func quarantineFlagDriftAfterCreationRetainsTheSource() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let adapter = testAdapter(
    hooks: .init(beforeQuarantine: {
      _ = fixture.quarantineDirectory.path.withCString { Darwin.chflags($0, UInt32(UF_HIDDEN)) }
    }))

  guard
    case .failed(let failure) = await adapter.apply(
      fixture.removeOperation, context: gitTestContext())
  else {
    Issue.record("quarantine access-policy drift must fail before rename")
    return
  }
  #expect(failure.code == "quarantine-seal-mismatch")
  #expect(slotExists(fixture.worktree))
}

@Test
func quarantineACLDriftAfterCreationRetainsTheSource() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let adapter = testAdapter(
    hooks: .init(beforeQuarantine: {
      try! addEveryoneWriteACL(to: fixture.quarantineDirectory)
    }))

  guard
    case .failed(let failure) = await adapter.apply(
      fixture.removeOperation, context: gitTestContext())
  else {
    Issue.record("quarantine ACL drift must fail before rename")
    return
  }
  #expect(failure.code == "quarantine-seal-mismatch")
  #expect(slotExists(fixture.worktree))
}

@Test
func sourceParentACLDriftBeforeRenameRetainsTheSource() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let adapter = testAdapter(
    hooks: .init(beforeQuarantine: {
      try! addEveryoneWriteACL(to: fixture.root)
    }))

  guard
    case .failed(let failure) = await adapter.apply(
      fixture.removeOperation, context: gitTestContext())
  else {
    Issue.record("source parent ACL drift must fail before rename")
    return
  }
  #expect(failure.code == "source-parent-seal-mismatch-before-quarantine")
  #expect(slotExists(fixture.worktree))
}

@Test
func sourceAccessPolicyDriftBeforeRenameRetainsTheSource() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let adapter = testAdapter(
    hooks: .init(beforeQuarantine: {
      _ = fixture.worktree.path.withCString { Darwin.chmod($0, 0o750) }
    }))

  guard
    case .failed(let failure) = await adapter.apply(
      fixture.removeOperation, context: gitTestContext())
  else {
    Issue.record("source access-policy drift must fail before rename")
    return
  }
  #expect(failure.code == "source-seal-mismatch-before-quarantine")
  #expect(slotExists(fixture.worktree))
  #expect(!slotExists(fixture.quarantinedURL))
}

@Test
func targetACLDriftIsReportedAsAccessPolicyRatherThanContent() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  try addEveryoneWriteACL(to: fixture.worktree)

  guard
    case .failed(let failure) = await testAdapter().apply(
      fixture.removeOperation, context: gitTestContext())
  else {
    Issue.record("target ACL drift must reject")
    return
  }
  #expect(failure.code == "worktree-access-policy-mismatch")
  #expect(slotExists(fixture.worktree))
}

@Test
func postQuarantineTargetModeDriftRestoresTheSource() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  var hooks = GitWorktreeQuarantineAdapter.Hooks()
  hooks.beforePostQuarantineVerification = {
    _ = fixture.quarantinedURL.path.withCString { Darwin.chmod($0, 0o500) }
  }
  let adapter = testAdapter(hooks: hooks)

  guard
    case .failed(let failure) = await adapter.apply(
      fixture.removeOperation, context: gitTestContext())
  else {
    Issue.record("post-quarantine access drift must reject")
    return
  }
  #expect(failure.code == "quarantine-verification-failed-restored")
  #expect(slotExists(fixture.worktree))
  #expect(
    await adapter.disposition(for: fixture.action.id)
      == .restoredAfterVerificationFailure(code: "source-seal-mismatch-after-quarantine"))
}

@Test
func coverageAcceptsTimestampOnlyChurnAfterOneBoundedReread() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  var hooks = GitWorktreeQuarantineAdapter.Hooks()
  hooks.afterCoverageFileFirstRead = { descriptor, path in
    guard path.last == Data("payload".utf8) else { return }
    var times = [timeval(tv_sec: 10, tv_usec: 0), timeval(tv_sec: 10, tv_usec: 0)]
    _ = times.withUnsafeMutableBufferPointer { buffer in
      Darwin.futimes(descriptor, buffer.baseAddress)
    }
  }
  let adapter = testAdapter(hooks: hooks)

  #expect(
    await adapter.apply(fixture.removeOperation, context: gitTestContext())
      == .succeeded(detailCode: "git-worktree-quarantine-removed")
  )
}

@Test
func coverageRejectsByteDriftEvenWhenTheFileIdentityIsStable() async throws {
  let fixture = try GitQuarantineFixture()
  defer { fixture.cleanup() }
  let mutation = LockedOneShotMutation()
  var hooks = GitWorktreeQuarantineAdapter.Hooks()
  hooks.afterCoverageFileFirstRead = { _, path in
    guard path.last == Data("payload".utf8) else { return }
    guard mutation.claim() else { return }
    try? Data("changed".utf8).write(to: fixture.payload)
  }
  let adapter = testAdapter(hooks: hooks)

  guard
    case .failed(let failure) = await adapter.apply(
      fixture.removeOperation, context: gitTestContext())
  else {
    Issue.record("byte drift must reject the coverage proof")
    return
  }
  #expect(failure.code == "coverage-file-content-raced")
  #expect(slotExists(fixture.worktree))
}

private struct GitQuarantineFixture: @unchecked Sendable {
  let container: URL
  let root: URL
  let worktree: URL
  let payload: URL
  let outsideDirectory: URL
  let outsideFile: URL
  let common: URL
  let worktrees: URL
  let administrative: URL
  let registration: GitWorktreeRegistrationEvidence
  let action: ActionDefinition
  let removeOperation: ExecutionAdapterOperation
  let discardOperation: ExecutionAdapterOperation

  var quarantinedURL: URL {
    quarantineDirectory.appendingPathComponent("payload")
  }

  var quarantineDirectory: URL {
    root.appendingPathComponent(".diskplan-quarantine-\(action.id.hex)")
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

    common = root.appendingPathComponent("git-common")
    worktrees = common.appendingPathComponent("worktrees")
    administrative = worktrees.appendingPathComponent("fixture")
    try createPrivateDirectory(common)
    try createPrivateDirectory(worktrees)
    try createPrivateDirectory(administrative)
    try Data("[core]\n\tbare = false\n".utf8)
      .write(to: common.appendingPathComponent("config"))
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
    let administrativeDigest = try GitWorktreeQuarantineAdapter.measuredAdministrativeDigest(
      atRawPath: Data(administrative.path.utf8)
    )
    let worktreeACLDigest = try GitWorktreeQuarantineAdapter.measuredACLDigest(
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
      metadataDigest: administrativeDigest
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
      linkage: .known(.ordinary),
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
      aclDigest: .known(worktreeACLDigest),
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
        tier: .safe,
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
      let removePrototype = try ActionPrototype.build(
        request: .gitWorktreeRemove,
        evidence: evidence
      )
      let removeAction = try ActionDefinition.build(
        prototype: removePrototype,
        evidence: evidence,
        globalFacts: facts,
        prerequisites: [action],
        evaluation: evaluation,
        displayMetrics: ActionDisplayMetrics(
          tier: .safe,
          immediateReclaimBytes: .known(1),
          inactiveDurationSeconds: .known(1),
          rebuildCost: .known(1),
          cleanupCost: .known(1),
          canonicalRawPath: Data("worktree".utf8)
        )
      )
      guard case .gitWorktreeRemove(let removeContract) = removeAction.prototype.adapterContract
      else { throw GitFixtureError.invalidContract }
      removeOperation = .gitWorktreeRemove(
        BoundMutationTarget(action: removeAction),
        removeContract
      )
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

private final class LockedOneShotMutation: @unchecked Sendable {
  private let lock = NSLock()
  private var available = true

  func claim() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard available else { return false }
    available = false
    return true
  }
}

private func testAdapter(
  hooks: GitWorktreeQuarantineAdapter.Hooks = .init()
) -> GitWorktreeQuarantineAdapter {
  GitWorktreeQuarantineAdapter(hooks: hooks)
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

private func addEveryoneWriteACL(to url: URL) throws {
  let process = Process()
  process.executableURL = URL(fileURLWithPath: "/bin/chmod")
  process.arguments = ["+a", "everyone allow write", url.path]
  try process.run()
  process.waitUntilExit()
  guard process.terminationReason == .exit, process.terminationStatus == 0 else {
    throw POSIXError(.EACCES)
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
