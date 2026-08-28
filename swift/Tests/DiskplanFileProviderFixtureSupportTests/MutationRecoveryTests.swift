import Foundation
import Testing

@testable import DiskplanFileProviderFixtureSupport

@Test
func absenceDoesNotResolveAnAmbiguousRemovalUntilItIsStable() {
  var state = ExternalMutationRecoveryState(
    kind: .domainRemove,
    nowNanoseconds: 10
  )
  #expect(
    state.observe(
      .absent,
      nowNanoseconds: 100,
      requiredConsecutiveObservations: 3,
      minimumStableNanoseconds: 100
    ) == .pending
  )
  #expect(
    state.observe(
      .absent,
      nowNanoseconds: 150,
      requiredConsecutiveObservations: 3,
      minimumStableNanoseconds: 100
    ) == .pending
  )
  #expect(
    state.observe(
      .absent,
      nowNanoseconds: 199,
      requiredConsecutiveObservations: 3,
      minimumStableNanoseconds: 100
    ) == .pending
  )
  #expect(
    state.observe(
      .absent,
      nowNanoseconds: 200,
      requiredConsecutiveObservations: 3,
      minimumStableNanoseconds: 100
    ) == .stableTerminal
  )
}

@Test
func lateSuccessAfterTimeoutResetsTheAbsenceProof() {
  var state = ExternalMutationRecoveryState(
    kind: .extensionRemove,
    nowNanoseconds: 10
  )
  #expect(
    state.observe(
      .absent,
      nowNanoseconds: 100,
      requiredConsecutiveObservations: 3,
      minimumStableNanoseconds: 100
    ) == .pending
  )
  #expect(
    state.observe(
      .absent,
      nowNanoseconds: 150,
      requiredConsecutiveObservations: 3,
      minimumStableNanoseconds: 100
    ) == .pending
  )

  // A delayed registry success contradicts both earlier absence observations.
  #expect(
    state.observe(
      .present,
      nowNanoseconds: 175,
      requiredConsecutiveObservations: 3,
      minimumStableNanoseconds: 100
    ) == .pending
  )
  #expect(state.consecutiveTerminalObservations == 0)
  #expect(state.firstTerminalObservationNanoseconds == nil)

  #expect(
    state.observe(
      .absent,
      nowNanoseconds: 200,
      requiredConsecutiveObservations: 3,
      minimumStableNanoseconds: 100
    ) == .pending
  )
  #expect(
    state.observe(
      .absent,
      nowNanoseconds: 250,
      requiredConsecutiveObservations: 3,
      minimumStableNanoseconds: 100
    ) == .pending
  )
  #expect(
    state.observe(
      .absent,
      nowNanoseconds: 300,
      requiredConsecutiveObservations: 3,
      minimumStableNanoseconds: 100
    ) == .stableTerminal
  )
}

@Test
func journalPersistsAmbiguityAndCompensatingRemovalClearsBothOperations() throws {
  let fixture = try TemporaryMutationJournal()
  defer { fixture.remove() }
  let journal = ExternalMutationJournal(runDirectory: fixture.runDirectory)

  try journal.begin(.domainAdd, nowNanoseconds: 10)
  #expect(try journal.pendingKinds() == [.domainAdd])

  // Simulate a crashed setup followed by recovery beginning a compensating removal.
  try journal.begin(.domainRemove, nowNanoseconds: 20)
  #expect(Set(try journal.pendingKinds()) == Set([.domainAdd, .domainRemove]))

  #expect(
    try journal.observe(
      .domainRemove,
      presence: .absent,
      nowNanoseconds: 100,
      requiredConsecutiveObservations: 2,
      minimumStableNanoseconds: 100
    ) == .pending
  )
  #expect(Set(try journal.pendingKinds()) == Set([.domainAdd, .domainRemove]))
  #expect(
    try journal.observe(
      .domainRemove,
      presence: .absent,
      nowNanoseconds: 200,
      requiredConsecutiveObservations: 2,
      minimumStableNanoseconds: 100
    ) == .stableTerminal
  )
  #expect(try journal.pendingKinds().isEmpty)
}

@Test
func journalRejectsCleanupWhileAnExternalMutationIsAmbiguous() throws {
  let fixture = try TemporaryMutationJournal()
  defer { fixture.remove() }
  let journal = ExternalMutationJournal(runDirectory: fixture.runDirectory)
  try journal.begin(.extensionAdd, nowNanoseconds: 10)

  #expect(throws: ExternalMutationJournalError.stateMismatch) {
    try journal.requireClear()
  }
  try journal.begin(.extensionRemove, nowNanoseconds: 20)
  try journal.confirmFinished(.extensionRemove, observed: .absent)
  try journal.requireClear()
}

private struct TemporaryMutationJournal {
  let root: URL
  let runDirectory: URL

  init() throws {
    root = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    let runs = root.appendingPathComponent("runs")
    runDirectory = runs.appendingPathComponent(UUID().uuidString.lowercased())
    try FileManager.default.createDirectory(at: runs, withIntermediateDirectories: true)
    guard chmod(root.path, 0o700) == 0, chmod(runs.path, 0o700) == 0 else {
      throw POSIXError(.EIO)
    }
  }

  func remove() { try? FileManager.default.removeItem(at: root) }
}
