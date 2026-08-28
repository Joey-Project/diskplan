import Foundation
import Testing

@testable import DiskplanFileProviderFixtureSupport

@Test
func sealedSnapshotValidatesEveryEventIdentityAndExactSequence() throws {
  let runID = UUID()
  let domainIdentifier = FixtureContract.domainIdentifier(runID: runID)
  let validEvents = [
    event(runID: runID, domainIdentifier: domainIdentifier, sequence: 1),
    event(
      runID: runID,
      domainIdentifier: domainIdentifier,
      sequence: 2,
      kind: .rootEnumeration
    ),
  ]
  try sealedSnapshot(events: validEvents).validate(
    runID: runID,
    domainIdentifier: domainIdentifier
  )

  let wrongRunID = UUID()
  let foreignEventOutsideWindow = event(
    runID: wrongRunID,
    domainIdentifier: FixtureContract.domainIdentifier(runID: wrongRunID),
    sequence: 1,
    monotonicNanoseconds: 1
  )
  #expect(throws: OracleAcceptanceError.identityMismatch(sequence: 1)) {
    try sealedSnapshot(events: [foreignEventOutsideWindow]).validate(
      runID: runID,
      domainIdentifier: domainIdentifier
    )
  }

  let sequenceGap = event(
    runID: runID,
    domainIdentifier: domainIdentifier,
    sequence: 2
  )
  #expect(throws: OracleAcceptanceError.sequenceMismatch(expected: 1, actual: 2)) {
    try sealedSnapshot(events: [sequenceGap]).validate(
      runID: runID,
      domainIdentifier: domainIdentifier
    )
  }
}

@Test
func sealedSnapshotRejectsMalformedEventStructure() {
  let runID = UUID()
  let domainIdentifier = FixtureContract.domainIdentifier(runID: runID)
  let malformed = event(
    runID: runID,
    domainIdentifier: domainIdentifier,
    sequence: 1,
    itemIdentifier: ""
  )
  #expect(throws: OracleAcceptanceError.malformedEvent(sequence: 1)) {
    try sealedSnapshot(events: [malformed]).validate(
      runID: runID,
      domainIdentifier: domainIdentifier
    )
  }

  let outsideWindow = event(
    runID: runID,
    domainIdentifier: domainIdentifier,
    sequence: 1,
    monotonicNanoseconds: 1
  )
  #expect(throws: OracleAcceptanceError.malformedEvent(sequence: 1)) {
    try sealedSnapshot(events: [outsideWindow]).validate(
      runID: runID,
      domainIdentifier: domainIdentifier
    )
  }
}

@Test
func sealedDirectoryRejectsEveryEnumeratorLifecycleOperation() {
  let runID = UUID()
  let domainIdentifier = FixtureContract.domainIdentifier(runID: runID)
  let lifecycleKinds: [OracleEventKind] = [
    .enumeratorAcquisition,
    .rootEnumeration,
    .workingSetEnumeration,
    .sealedDirectoryEnumeration,
    .changeEnumeration,
    .syncAnchor,
  ]

  for (index, kind) in lifecycleKinds.enumerated() {
    let sealedEvent = event(
      runID: runID,
      domainIdentifier: domainIdentifier,
      sequence: UInt64(index + 1),
      itemIdentifier: FixtureContract.sealedDirectoryIdentifier,
      kind: kind
    )
    #expect(FixtureContract.isForbiddenEvent(sealedEvent))
  }

  for kind in [
    OracleEventKind.enumeratorAcquisition,
    .rootEnumeration,
    .workingSetEnumeration,
    .changeEnumeration,
    .syncAnchor,
  ] {
    let rootEvent = event(
      runID: runID,
      domainIdentifier: domainIdentifier,
      sequence: 1,
      itemIdentifier: "root",
      kind: kind
    )
    #expect(!FixtureContract.isForbiddenEvent(rootEvent))
  }

  let fetch = event(
    runID: runID,
    domainIdentifier: domainIdentifier,
    sequence: 1,
    kind: .fetchContents
  )
  #expect(FixtureContract.isForbiddenEvent(fetch))
}

@Test
func oracleEventJSONRejectsUnknownAndDuplicateTopLevelKeys() throws {
  let root = FileManager.default.temporaryDirectory.appendingPathComponent(
    "diskplan-strict-event-\(UUID().uuidString.lowercased())",
    isDirectory: true
  )
  let runDirectory = root.appendingPathComponent(UUID().uuidString.lowercased(), isDirectory: true)
  try FileManager.default.createDirectory(at: runDirectory, withIntermediateDirectories: true)
  defer { try? FileManager.default.removeItem(at: root) }
  guard chmod(root.path, 0o700) == 0, chmod(runDirectory.path, 0o700) == 0 else {
    throw POSIXError(.EACCES)
  }
  let log = OracleLog(runDirectory: runDirectory)
  try log.prepare()
  let encoded = try JSONEncoder().encode(
    event(
      runID: UUID(),
      domainIdentifier: "com.joeyteng.diskplan.fileprovider-fixture.test",
      sequence: 1
    )
  )
  guard let object = String(data: encoded, encoding: .utf8), object.first == "{" else {
    throw POSIXError(.EINVAL)
  }
  let requestFlags = "\"requestFlags\":[\"system:false\"]"
  guard let requestFlagsRange = object.range(of: requestFlags) else { throw POSIXError(.EINVAL) }
  let deeplyNested =
    String(repeating: "[", count: 128) + "\"system:false\""
    + String(repeating: "]", count: 128)
  let deepObject = object.replacingCharacters(
    in: requestFlagsRange,
    with: "\"requestFlags\":\(deeplyNested)"
  )
  let eventURL = runDirectory.appendingPathComponent("events.jsonl")

  for tampered in [
    "{\"unexpected\":true," + object.dropFirst(),
    "{\"sequence\":1," + object.dropFirst(),
    deepObject,
  ] {
    try? FileManager.default.removeItem(at: eventURL)
    try Data((tampered + "\n").utf8).write(to: eventURL, options: .withoutOverwriting)
    guard chmod(eventURL.path, 0o600) == 0 else { throw POSIXError(.EACCES) }
    #expect(throws: FixtureControlReadError.self) { try log.events() }
  }
}

private func sealedSnapshot(events: [OracleEvent]) -> OracleSealedSnapshot {
  OracleSealedSnapshot(
    window: OracleWindow(
      beginNanoseconds: 100_000_000,
      endNanoseconds: 200_000_000,
      quietMilliseconds: 50,
      eventCount: events.count,
      lastSequence: UInt64(events.count)
    ),
    events: events
  )
}

private func event(
  runID: UUID,
  domainIdentifier: String,
  sequence: UInt64,
  itemIdentifier: String = FixtureContract.sentinelIdentifier,
  kind: OracleEventKind = .itemMetadata,
  monotonicNanoseconds: UInt64 = 150_000_000
) -> OracleEvent {
  OracleEvent(
    sequence: sequence,
    runID: runID,
    domainIdentifier: domainIdentifier,
    itemIdentifier: itemIdentifier,
    kind: kind,
    processID: 1,
    monotonicNanoseconds: monotonicNanoseconds,
    requestFlags: ["system:false"]
  )
}
