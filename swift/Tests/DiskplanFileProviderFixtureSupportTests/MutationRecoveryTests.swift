import Foundation
import Testing

@testable import DiskplanFileProviderFixtureSupport

private let firstBoot = "11111111-1111-4111-8111-111111111111"
private let secondBoot = "22222222-2222-4222-8222-222222222222"

@Test
func sameBootAbsenceAndCompletedRemovalDoNotResolveUnknownAddCompletion() throws {
  let fixture = try TemporaryMutationJournal()
  defer { fixture.remove() }
  let journal = try fixture.journal(boot: firstBoot)

  try journal.begin(.domainAdd, nowNanoseconds: 10)
  try journal.markDispatched(.domainAdd, nowNanoseconds: 20)
  try journal.begin(.domainRemove, nowNanoseconds: 30)
  try journal.markDispatched(.domainRemove, nowNanoseconds: 40)
  try journal.recordOriginalCompletion(
    .domainRemove,
    completion: .succeeded,
    nowNanoseconds: 50
  )
  try journal.confirmFinished(.domainRemove, observed: .absent)

  #expect(try journal.pendingKinds() == [.domainAdd])
  #expect(
    throws: ExternalMutationJournalError.unresolvedExternalMutation(
      .domainAdd,
      bootGeneration: firstBoot
    )
  ) {
    try journal.requireClear()
  }
}

@Test
func lateOriginalSuccessAfterTimeoutRemainsVisibleAfterEarlierRemoval() throws {
  let fixture = try TemporaryMutationJournal()
  defer { fixture.remove() }
  let journal = try fixture.journal(boot: firstBoot)

  try journal.begin(.domainAdd, nowNanoseconds: 10)
  try journal.markDispatched(.domainAdd, nowNanoseconds: 20)
  try journal.begin(.domainRemove, nowNanoseconds: 30)
  try journal.markDispatched(.domainRemove, nowNanoseconds: 40)
  try journal.recordOriginalCompletion(
    .domainRemove,
    completion: .succeeded,
    nowNanoseconds: 50
  )
  try journal.confirmFinished(.domainRemove, observed: .absent)

  // The old non-cancellable add reports success after the compensating removal completed.
  try journal.recordOriginalCompletion(.domainAdd, completion: .succeeded, nowNanoseconds: 60)
  #expect(try journal.state(.domainAdd)?.phase == .originalSucceeded)
  #expect(try journal.pendingKinds() == [.domainAdd])
}

@Test
func authoritativeOriginalFailureClearsThePendingRunGate() throws {
  let fixture = try TemporaryMutationJournal()
  defer { fixture.remove() }
  let journal = try fixture.journal(boot: firstBoot)

  try journal.begin(.extensionAdd, nowNanoseconds: 10)
  try journal.markDispatched(.extensionAdd, nowNanoseconds: 20)
  try journal.recordOriginalCompletion(
    .extensionAdd,
    completion: .failed,
    nowNanoseconds: 30
  )

  try journal.requireClear()
  #expect(try fixture.evidenceNames().isEmpty)
}

@Test
func authoritativeAddSuccessThenAuthoritativeRemovalClearsSameBoot() throws {
  let fixture = try TemporaryMutationJournal()
  defer { fixture.remove() }
  let journal = try fixture.journal(boot: firstBoot)

  try journal.begin(.domainAdd, nowNanoseconds: 10)
  try journal.markDispatched(.domainAdd, nowNanoseconds: 20)
  try journal.recordOriginalCompletion(.domainAdd, completion: .succeeded, nowNanoseconds: 30)
  try journal.begin(.domainRemove, nowNanoseconds: 40)
  try journal.markDispatched(.domainRemove, nowNanoseconds: 50)
  try journal.recordOriginalCompletion(
    .domainRemove,
    completion: .succeeded,
    nowNanoseconds: 60
  )
  try journal.confirmFinished(.domainRemove, observed: .absent)

  try journal.requireClear()
  #expect(try fixture.evidenceNames().isEmpty)
}

@Test
func rebootAndExactAbsenceResolveUnknownAddWithoutGracePeriod() throws {
  let fixture = try TemporaryMutationJournal()
  defer { fixture.remove() }
  let first = try fixture.journal(boot: firstBoot)
  try first.begin(.domainAdd, nowNanoseconds: 10)
  try first.markDispatched(.domainAdd, nowNanoseconds: 20)

  let afterReboot = try fixture.journal(boot: secondBoot)
  #expect(try afterReboot.resolveAfterBootIfTerminal(.domainAdd, observed: .absent))
  try afterReboot.requireClear()
}

@Test
func rebootAndPresentAddRequireCompletedRemoveBeforeResolution() throws {
  let fixture = try TemporaryMutationJournal()
  defer { fixture.remove() }
  let first = try fixture.journal(boot: firstBoot)
  try first.begin(.domainAdd, nowNanoseconds: 10)
  try first.markDispatched(.domainAdd, nowNanoseconds: 20)

  let afterReboot = try fixture.journal(boot: secondBoot)
  #expect(!(try afterReboot.resolveAfterBootIfTerminal(.domainAdd, observed: .present)))
  try afterReboot.begin(.domainRemove, nowNanoseconds: 30)
  try afterReboot.markDispatched(.domainRemove, nowNanoseconds: 40)
  try afterReboot.recordOriginalCompletion(
    .domainRemove,
    completion: .succeeded,
    nowNanoseconds: 50
  )
  try afterReboot.confirmFinished(.domainRemove, observed: .absent)
  try afterReboot.requireClear()
}

@Test
func extensionAddUsesTheSameRebootBarrier() throws {
  let fixture = try TemporaryMutationJournal()
  defer { fixture.remove() }
  let first = try fixture.journal(boot: firstBoot)
  try first.begin(.extensionAdd, nowNanoseconds: 10)
  try first.markDispatched(.extensionAdd, nowNanoseconds: 20)

  let sameBoot = try fixture.journal(boot: firstBoot)
  #expect(!(try sameBoot.resolveAfterBootIfTerminal(.extensionAdd, observed: .absent)))
  let afterReboot = try fixture.journal(boot: secondBoot)
  #expect(try afterReboot.resolveAfterBootIfTerminal(.extensionAdd, observed: .absent))
  try afterReboot.requireClear()
}

@Test
func independentRecoveryInstancesSeeOneDurableOperationState() async throws {
  let fixture = try TemporaryMutationJournal()
  defer { fixture.remove() }
  let first = try fixture.journal(boot: firstBoot)
  let second = try fixture.journal(boot: firstBoot)

  try first.begin(.extensionAdd, nowNanoseconds: 10)
  try first.markDispatched(.extensionAdd, nowNanoseconds: 20)
  #expect(try second.state(.extensionAdd)?.phase == .dispatched)
  try second.recordOriginalCompletion(.extensionAdd, completion: .failed, nowNanoseconds: 30)
  try first.requireClear()
}

@Test
func anotherRunCannotReplaceTheHostGlobalPendingGate() throws {
  let firstFixture = try TemporaryMutationJournal()
  defer { firstFixture.remove() }
  let first = try firstFixture.journal(boot: firstBoot)
  try first.begin(.domainAdd, nowNanoseconds: 10)
  try first.markDispatched(.domainAdd, nowNanoseconds: 20)

  let other = try firstFixture.journalForDifferentRun(boot: firstBoot)
  #expect(throws: ExternalMutationJournalError.bindingMismatch) {
    try other.begin(.extensionAdd, nowNanoseconds: 30)
  }
}

@Test
func durableGateBindsExactRunBundleMutationBootAndProvenance() throws {
  let fixture = try TemporaryMutationJournal()
  defer { fixture.remove() }
  let journal = try fixture.journal(boot: firstBoot)
  try journal.begin(.extensionAdd, nowNanoseconds: 10)
  try journal.markDispatched(.extensionAdd, nowNanoseconds: 20)

  let object = try #require(
    JSONSerialization.jsonObject(with: Data(contentsOf: fixture.gateURL))
      as? [String: Any]
  )
  let binding = try #require(object["binding"] as? [String: Any])
  #expect(binding["runID"] as? String == fixture.runID.uuidString.uppercased())
  #expect(binding["domainIdentifier"] as? String == fixture.binding.domainIdentifier)
  #expect(binding["hostBundleIdentifier"] as? String == FixtureContract.hostBundleIdentifier)
  #expect(
    binding["extensionBundleIdentifier"] as? String
      == FixtureContract.extensionBundleIdentifier
  )
  #expect(binding["extensionPath"] as? String == fixture.binding.extensionPath)
  #expect(binding["lifecycleProvenance"] as? String == ExternalMutationRunBinding.provenance)
  let mutations = try #require(object["mutations"] as? [[String: Any]])
  let state = try #require(mutations.first?["state"] as? [String: Any])
  #expect(state["kind"] as? String == ExternalMutationKind.extensionAdd.rawValue)
  #expect(state["phase"] as? String == ExternalMutationPhase.dispatched.rawValue)
  #expect(state["bootGeneration"] as? String == firstBoot)
  #expect(UUID(uuidString: try #require(state["operationID"] as? String)) != nil)
}

@Test
func pendingGateAccessPolicyDriftIsNotMisreportedAsMissing() throws {
  let fixture = try TemporaryMutationJournal()
  defer { fixture.remove() }
  let journal = try fixture.journal(boot: firstBoot)
  try journal.begin(.domainAdd, nowNanoseconds: 10)
  try journal.markDispatched(.domainAdd, nowNanoseconds: 20)
  guard chmod(fixture.gateURL.path, 0o644) == 0 else { throw POSIXError(.EIO) }

  #expect(throws: ExternalMutationJournalError.accessPolicyChanged) {
    _ = try journal.pendingKinds()
  }
}

@Test
func crashAfterDispatchedGateCannotRegressToPrepared() throws {
  let fixture = try TemporaryMutationJournal()
  defer { fixture.remove() }
  let ordinary = try fixture.journal(boot: firstBoot)
  try ordinary.begin(.domainAdd, nowNanoseconds: 10)
  let crashing = try fixture.journal(
    boot: firstBoot,
    failureInjection: .afterGateBeforeState
  )
  #expect(
    throws: ExternalMutationJournalError.operationFailed(
      "injected-after-dispatch-gate",
      errno: EIO
    )
  ) {
    try crashing.markDispatched(.domainAdd, nowNanoseconds: 20)
  }

  #expect(try ordinary.state(.domainAdd)?.phase == .dispatched)
}

@Test
func crashAfterPreparedGateIsProvablyNondispatched() throws {
  let fixture = try TemporaryMutationJournal()
  defer { fixture.remove() }
  let crashing = try fixture.journal(
    boot: firstBoot,
    failureInjection: .afterGateBeforeState
  )
  #expect(
    throws: ExternalMutationJournalError.operationFailed(
      "injected-after-gate",
      errno: EIO
    )
  ) {
    try crashing.begin(.domainAdd, nowNanoseconds: 10)
  }

  let recovery = try fixture.journal(boot: firstBoot)
  try recovery.requireClear()
  #expect(try fixture.evidenceNames().isEmpty)
}

@Test
func crashAfterCompletionStateRetainsAuthoritativeSuccess() throws {
  let fixture = try TemporaryMutationJournal()
  defer { fixture.remove() }
  let ordinary = try fixture.journal(boot: firstBoot)
  try ordinary.begin(.domainAdd, nowNanoseconds: 10)
  try ordinary.markDispatched(.domainAdd, nowNanoseconds: 20)
  let crashing = try fixture.journal(
    boot: firstBoot,
    failureInjection: .afterStateBeforeGate
  )
  #expect(
    throws: ExternalMutationJournalError.operationFailed(
      "injected-after-completion-state",
      errno: EIO
    )
  ) {
    try crashing.recordOriginalCompletion(.domainAdd, completion: .succeeded, nowNanoseconds: 30)
  }

  #expect(try ordinary.state(.domainAdd)?.phase == .originalSucceeded)
}

@Test
func crashAfterResolutionGateLeavesStateFailClosedAndRecoverable() throws {
  let fixture = try TemporaryMutationJournal()
  defer { fixture.remove() }
  let ordinary = try fixture.journal(boot: firstBoot)
  try ordinary.begin(.extensionAdd, nowNanoseconds: 10)
  try ordinary.markDispatched(.extensionAdd, nowNanoseconds: 20)
  let crashing = try fixture.journal(
    boot: firstBoot,
    failureInjection: .afterResolutionGateBeforeStateRemoval
  )
  #expect(
    throws: ExternalMutationJournalError.operationFailed(
      "injected-before-state-removal",
      errno: EIO
    )
  ) {
    try crashing.recordOriginalCompletion(.extensionAdd, completion: .failed, nowNanoseconds: 30)
  }

  // The operation file survived the interrupted directory-durability sequence. A clean
  // recovery instance observes its authoritative failure and completes the idempotent removal.
  try ordinary.requireClear()
  #expect(try fixture.evidenceNames().isEmpty)
}

@Test
func crashAfterSuccessfulCompensationResolutionCanBeReconfirmed() throws {
  let fixture = try TemporaryMutationJournal()
  defer { fixture.remove() }
  let ordinary = try fixture.journal(boot: firstBoot)
  try ordinary.begin(.domainAdd, nowNanoseconds: 10)
  try ordinary.markDispatched(.domainAdd, nowNanoseconds: 20)
  try ordinary.recordOriginalCompletion(
    .domainAdd,
    completion: .succeeded,
    nowNanoseconds: 30
  )
  try ordinary.beginRemovalAttempt(.domainRemove, nowNanoseconds: 40)
  try ordinary.markDispatched(.domainRemove, nowNanoseconds: 50)
  try ordinary.recordOriginalCompletion(
    .domainRemove,
    completion: .succeeded,
    nowNanoseconds: 60
  )

  let crashing = try fixture.journal(
    boot: firstBoot,
    failureInjection: .afterResolutionGateBeforeStateRemoval
  )
  #expect(
    throws: ExternalMutationJournalError.operationFailed(
      "injected-before-state-removal",
      errno: EIO
    )
  ) {
    try crashing.confirmFinished(.domainRemove, observed: .absent)
  }

  try ordinary.confirmFinished(.domainRemove, observed: .absent)
  try ordinary.requireClear()
  #expect(try fixture.evidenceNames().isEmpty)
}

private struct TemporaryMutationJournal {
  let root: URL
  let runs: URL
  let runID: UUID
  let runDirectory: URL
  let binding: ExternalMutationRunBinding

  var gateURL: URL { runs.appendingPathComponent(".fileprovider-pending-run.json") }

  init() throws {
    root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    runs = root.appendingPathComponent("runs")
    runID = UUID()
    runDirectory = runs.appendingPathComponent(runID.uuidString.lowercased())
    let appPath = root.appendingPathComponent("Fixture.app").path
    let extensionPath = URL(fileURLWithPath: appPath)
      .appendingPathComponent("Contents/PlugIns/Fixture.appex").path
    binding = ExternalMutationRunBinding(
      runID: runID,
      domainIdentifier: FixtureContract.domainIdentifier(runID: runID),
      appPath: appPath,
      extensionPath: extensionPath
    )
    try FileManager.default.createDirectory(at: runs, withIntermediateDirectories: true)
    guard chmod(root.path, 0o700) == 0, chmod(runs.path, 0o700) == 0 else {
      throw POSIXError(.EIO)
    }
  }

  func journal(
    boot: String,
    failureInjection: ExternalMutationJournalFailureInjection = .none
  ) throws -> ExternalMutationJournal {
    try ExternalMutationJournal(
      runDirectory: runDirectory,
      binding: binding,
      currentBootGeneration: boot,
      failureInjection: failureInjection
    )
  }

  func journalForDifferentRun(boot: String) throws -> ExternalMutationJournal {
    let otherID = UUID()
    let otherRun = runs.appendingPathComponent(otherID.uuidString.lowercased())
    let otherBinding = ExternalMutationRunBinding(
      runID: otherID,
      domainIdentifier: FixtureContract.domainIdentifier(runID: otherID),
      appPath: binding.appPath,
      extensionPath: binding.extensionPath
    )
    return try ExternalMutationJournal(
      runDirectory: otherRun,
      binding: otherBinding,
      currentBootGeneration: boot
    )
  }

  func evidenceNames() throws -> [String] {
    try FileManager.default.contentsOfDirectory(atPath: runs.path).filter {
      $0.hasPrefix(".external-mutation-") || $0.hasPrefix(".fileprovider-pending-run")
    }.sorted()
  }

  func remove() { try? FileManager.default.removeItem(at: root) }
}
