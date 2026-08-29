import Darwin
import DiskplanMacOS
import DiskplanPolicy
import Foundation
import Testing

@testable import DiskplanExecution

private struct AlwaysLocalArtifactProbe: ArtifactLocalityProbing {
  func gateBeforePathAccess() -> SafeArtifactWarning? { nil }

  func verifyLocalDirectory(
    parentDescriptor _: Int32,
    rawName _: Data,
    expectedIdentity _: ObjectIdentity
  ) -> SafeArtifactWarning? { nil }
}

private struct RejectingArtifactProbe: ArtifactLocalityProbing {
  let warning: SafeArtifactWarning

  func gateBeforePathAccess() -> SafeArtifactWarning? { warning }

  func verifyLocalDirectory(
    parentDescriptor _: Int32,
    rawName _: Data,
    expectedIdentity _: ObjectIdentity
  ) -> SafeArtifactWarning? { warning }
}

private final class SwitchableArtifactProbe: ArtifactLocalityProbing, @unchecked Sendable {
  private let lock = NSLock()
  private var currentWarning: SafeArtifactWarning?

  func set(_ warning: SafeArtifactWarning?) {
    lock.withLock { currentWarning = warning }
  }

  func gateBeforePathAccess() -> SafeArtifactWarning? {
    lock.withLock { currentWarning }
  }

  func verifyLocalDirectory(
    parentDescriptor _: Int32,
    rawName _: Data,
    expectedIdentity _: ObjectIdentity
  ) -> SafeArtifactWarning? {
    lock.withLock { currentWarning }
  }
}

private final class OneShotArtifactMutation: @unchecked Sendable {
  private let lock = NSLock()
  private var performed = false

  func perform(_ body: () -> Void) {
    lock.withLock {
      guard !performed else { return }
      performed = true
      body()
    }
  }
}

private final class NthReadbackFailure: @unchecked Sendable {
  private let lock = NSLock()
  private let target: Int
  private let failure: ArtifactReadbackFailure
  private var count = 0

  init(target: Int, failure: ArtifactReadbackFailure) {
    self.target = target
    self.failure = failure
  }

  func next() -> ArtifactReadbackFailure? {
    lock.withLock {
      count += 1
      return count == target ? failure : nil
    }
  }
}

@Test func canonicalArtifactJSONIsStableAndCarriesAllHistoryDimensions() throws {
  let timestamp = ArtifactHistoryTimestamp(secondsSinceEpoch: 123, nanoseconds: 456)
  let document = try CanonicalArtifactDocument.history([
    ArtifactHistoryRecord(
      candidateID: "candidate-b",
      firstSeen: .observed(timestamp),
      lastSeen: .unavailable(reason: "history unavailable"),
      lastSeenOpen: .observed(timestamp),
      lastSeenProcessReference: .unavailable(reason: "not observed")
    ),
    ArtifactHistoryRecord(
      candidateID: "candidate-a",
      firstSeen: .observed(timestamp),
      lastSeen: .observed(timestamp),
      lastSeenOpen: .unavailable(reason: "not observed"),
      lastSeenProcessReference: .observed(timestamp)
    ),
  ])

  let encoded = try document.canonicalEncoded()
  let text = try #require(String(data: encoded, encoding: .utf8))
  #expect(text.hasPrefix("{\"artifact_kind\":\"history\",\"payload\":"))
  #expect(
    text.firstRange(of: "candidate-a")!.lowerBound
      < text.firstRange(of: "candidate-b")!.lowerBound)
  #expect(text.contains("\"first_seen\""))
  #expect(text.contains("\"last_seen\""))
  #expect(text.contains("\"last_seen_open\""))
  #expect(text.contains("\"last_seen_process_reference\""))
  #expect(encoded == (try document.canonicalEncoded()))
}

@Test func duplicateHistoryCandidateIDsAreRejected() {
  let unavailable = ArtifactHistoryObservation.unavailable(reason: "not observed")
  let record = ArtifactHistoryRecord(
    candidateID: "duplicate",
    firstSeen: unavailable,
    lastSeen: unavailable,
    lastSeenOpen: unavailable,
    lastSeenProcessReference: unavailable
  )

  #expect(throws: SafeArtifactWarning.self) {
    try CanonicalArtifactDocument.history([record, record])
  }
}

@Test func publicCanonicalEncoderReturnsTypedStructuralErrors() {
  var tooDeep = CanonicalJSONValue.null
  for _ in 0..<65 { tooDeep = .array([tooDeep]) }
  do {
    _ = try tooDeep.canonicalEncoded()
    Issue.record("expected a typed depth error")
  } catch let error as CanonicalArtifactEncodingError {
    #expect(error == .structuralLimitExceeded)
  } catch {
    Issue.record("unexpected canonical encoding error: \(error)")
  }

  let tooManyNodes = CanonicalJSONValue.array(
    (0..<100_000).map { _ in .array([CanonicalJSONValue.null]) })
  do {
    _ = try tooManyNodes.canonicalEncoded()
    Issue.record("expected a typed node-count error")
  } catch let error as CanonicalArtifactEncodingError {
    #expect(error == .structuralLimitExceeded)
  } catch {
    Issue.record("unexpected canonical encoding error: \(error)")
  }
}

@Test func disabledArtifactStorePerformsNoWrite() async throws {
  let root = try makeArtifactTestRoot()
  defer { try? FileManager.default.removeItem(at: root) }
  let before = try FileManager.default.contentsOfDirectory(atPath: root.path).sorted()

  let outcome = await SafeArtifactStore.admit(.disabled).write(testDocument())

  #expect(outcome == .disabled)
  #expect(try FileManager.default.contentsOfDirectory(atPath: root.path).sorted() == before)
}

@Test func writerPublishesCanonicalBytesAndNeverClobbersFinalName() async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: AlwaysLocalArtifactProbe()
  )

  let first = await admission.write(testDocument())
  guard case .published(let receipt) = first else {
    Issue.record("expected a published artifact, got \(first)")
    return
  }
  #expect(receipt.locator.usageRequirement.contains("revalidate"))
  #expect(receipt.locator.pathHint != nil)
  let artifact = fixture.taskDirectory.appendingPathComponent("evidence.json")
  #expect(try Data(contentsOf: artifact) == testDocument().canonicalEncoded())

  let second = await admission.write(testDocument())
  guard case .warning(let warning) = second else {
    Issue.record("expected a collision warning, got \(second)")
    return
  }
  #expect(warning.code == "artifact-target-collision")
  #expect(try Data(contentsOf: artifact) == testDocument().canonicalEncoded())
}

@Test func fullDurabilityPublishesThroughTheRealDirectoryFsyncChain() async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let configuration = SafeArtifactConfiguration.enabled(
    destinationParent: try rawRoot(fixture.destinationParent),
    taskIdentifier: fixture.taskIdentifier,
    excludedScanAndProviderRoots: [],
    durability: .full
  )
  let admission = SafeArtifactStore.admit(
    configuration,
    localityProbe: AlwaysLocalArtifactProbe()
  )

  let outcome = await admission.write(testDocument())
  guard case .published = outcome else {
    Issue.record("expected a fully durable publication, got \(outcome)")
    return
  }
  let artifact = fixture.taskDirectory.appendingPathComponent("evidence.json")
  #expect(try Data(contentsOf: artifact) == testDocument().canonicalEncoded())
}

@Test func renameExclRejectsALastMomentCompetitorWithoutClobberingIt() async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let final = fixture.taskDirectory.appendingPathComponent("evidence.json")
  let competitor = Data("competitor".utf8)
  let hooks = ArtifactStoreTestingHooks(immediatelyBeforeRename: {
    _ = FileManager.default.createFile(atPath: final.path, contents: competitor)
  })
  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: AlwaysLocalArtifactProbe(),
    hooks: hooks
  )

  let outcome = await admission.write(testDocument())
  guard case .warning(let warning) = outcome else {
    Issue.record("expected an exclusive-rename collision, got \(outcome)")
    return
  }
  #expect(warning.code == "artifact-target-collision")
  #expect(try Data(contentsOf: final) == competitor)
}

@Test func changedNoMaterializationPolicyStopsBeforeTheNextPathAccess() async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let probe = SwitchableArtifactProbe()
  let admission = SafeArtifactStore.admit(try fixture.configuration, localityProbe: probe)
  probe.set(SafeArtifactWarning(code: "no-materialization-policy-changed", errno: EPERM))

  let outcome = await admission.write(testDocument())
  guard case .warning(let warning) = outcome else {
    Issue.record("expected a live no-materialization policy rejection, got \(outcome)")
    return
  }
  #expect(warning.code == "no-materialization-policy-changed")
  #expect(try FileManager.default.contentsOfDirectory(atPath: fixture.taskDirectory.path).isEmpty)
}

@Test func symlinkedDestinationAncestorIsRejectedWithoutFollowingIt() throws {
  let root = try makeArtifactTestRoot()
  defer { try? FileManager.default.removeItem(at: root) }
  let real = root.appendingPathComponent("real")
  let link = root.appendingPathComponent("link")
  try FileManager.default.createDirectory(at: real, withIntermediateDirectories: false)
  try FileManager.default.createSymbolicLink(at: link, withDestinationURL: real)
  let configuration = SafeArtifactConfiguration.enabled(
    destinationParent: try rawRoot(link, resolveSymlinks: false),
    taskIdentifier: "task",
    excludedScanAndProviderRoots: []
  )

  let admission = SafeArtifactStore.admit(
    configuration,
    localityProbe: AlwaysLocalArtifactProbe()
  )
  guard case .rejected(let warning) = admission else {
    Issue.record("expected symlink rejection")
    return
  }
  #expect(warning.code == "artifact-ancestor-symlink-rejected")
}

@Test(arguments: [
  "artifact-ancestor-provider-managed",
  "artifact-ancestor-dataless",
  "artifact-ancestor-provider-unverified",
]) func providerAndDatalessAmbiguityFailClosed(code: String) throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: RejectingArtifactProbe(warning: SafeArtifactWarning(code: code))
  )

  guard case .rejected(let warning) = admission else {
    Issue.record("expected locality rejection")
    return
  }
  #expect(warning.code == code)
  #expect(!FileManager.default.fileExists(atPath: fixture.taskDirectory.path))
}

@Test func fileProviderIdentifierAbsenceDoesNotProveLocality() {
  let warning = ArtifactProviderLocalityAdmission.warning(for: .identifierAbsent)
  #expect(warning.code == "artifact-ancestor-provider-locality-unproven")
}

@Test func descriptorVerifiedExcludedRootRejectsContainedDestination() throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let excluded = EngineArtifactExclusionRoot(
    rawPath: try rawRoot(fixture.root),
    expectedIdentity: try artifactIdentity(fixture.root)
  )
  let configuration = SafeArtifactConfiguration.enabled(
    destinationParent: try rawRoot(fixture.destinationParent),
    taskIdentifier: fixture.taskIdentifier,
    excludedScanAndProviderRoots: [excluded]
  )

  let admission = SafeArtifactStore.admit(
    configuration,
    localityProbe: AlwaysLocalArtifactProbe()
  )
  guard case .rejected(let warning) = admission else {
    Issue.record("expected excluded-root rejection")
    return
  }
  #expect(warning.code == "artifact-destination-inside-excluded-root")
}

@Test func excludedRootWithoutKnownGenerationFailsClosed() throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let observed = try artifactIdentity(fixture.root)
  let excluded = EngineArtifactExclusionRoot(
    rawPath: try rawRoot(fixture.root),
    expectedIdentity: ObjectIdentity(
      device: observed.device,
      object: observed.object,
      generation: .unknown(.unavailableViaPublicAPI),
      type: observed.type
    )
  )
  let configuration = SafeArtifactConfiguration.enabled(
    destinationParent: try rawRoot(fixture.destinationParent),
    taskIdentifier: fixture.taskIdentifier,
    excludedScanAndProviderRoots: [excluded]
  )

  let admission = SafeArtifactStore.admit(
    configuration,
    localityProbe: AlwaysLocalArtifactProbe()
  )
  guard case .rejected(let warning) = admission else {
    Issue.record("expected generation-unavailable rejection")
    return
  }
  #expect(warning.code == "excluded-root-generation-unavailable")
}

@Test func ancestorReplacementIsDifferentFromMissingAndDoesNotPublish() async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let moved = fixture.root.appendingPathComponent("destination-moved")
  let destination = fixture.destinationParent
  let hooks = ArtifactStoreTestingHooks(beforePublish: {
    _ = destination.path.withCString { source in
      moved.path.withCString { Darwin.rename(source, $0) }
    }
    _ = destination.path.withCString { Darwin.mkdir($0, 0o700) }
  })
  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: AlwaysLocalArtifactProbe(),
    hooks: hooks
  )

  let outcome = await admission.write(testDocument())
  guard case .warning(let warning) = outcome else {
    Issue.record("expected replacement warning")
    return
  }
  #expect(warning.code == "artifact-ancestor-slot-identity-mismatch")
  #expect(
    !FileManager.default.fileExists(
      atPath: moved.appendingPathComponent("task/evidence.json").path))
}

@Test func missingAncestorHasItsOwnRevalidationResult() async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let moved = fixture.root.appendingPathComponent("destination-moved")
  let destination = fixture.destinationParent
  let hooks = ArtifactStoreTestingHooks(beforePublish: {
    _ = destination.path.withCString { source in
      moved.path.withCString { Darwin.rename(source, $0) }
    }
  })
  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: AlwaysLocalArtifactProbe(),
    hooks: hooks
  )

  let outcome = await admission.write(testDocument())
  guard case .warning(let warning) = outcome else {
    Issue.record("expected missing warning")
    return
  }
  #expect(warning.code == "artifact-ancestor-missing")
}

@Test func ancestorAccessPolicyChangeIsNotTreatedAsIdentityMutation() async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let destination = fixture.destinationParent
  let hooks = ArtifactStoreTestingHooks(beforePublish: {
    _ = destination.path.withCString { Darwin.chmod($0, 0o770) }
  })
  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: AlwaysLocalArtifactProbe(),
    hooks: hooks
  )

  let outcome = await admission.write(testDocument())
  guard case .warning(let warning) = outcome else {
    Issue.record("expected access-policy warning")
    return
  }
  #expect(warning.code == "artifact-ancestor-access-policy-mismatch")
}

@Test func benignAncestorChildChurnDoesNotInvalidateAccessPolicy() async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let sibling = fixture.destinationParent.appendingPathComponent("benign-sibling")
  let hooks = ArtifactStoreTestingHooks(beforePublish: {
    _ = sibling.path.withCString { Darwin.mkdir($0, 0o700) }
  })
  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: AlwaysLocalArtifactProbe(),
    hooks: hooks
  )

  let outcome = await admission.write(testDocument())
  guard case .published = outcome else {
    Issue.record("expected child-entry churn to remain benign, got \(outcome)")
    return
  }
}

@Test func benignPresentationFlagChangeDoesNotInvalidateAccessPolicy() async throws {
  let fixture = try ArtifactWriterFixture()
  defer {
    _ = fixture.destinationParent.path.withCString { Darwin.chflags($0, 0) }
    fixture.remove()
  }
  let destination = fixture.destinationParent
  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: AlwaysLocalArtifactProbe()
  )
  let flagResult = destination.path.withCString { Darwin.chflags($0, UInt32(UF_HIDDEN)) }
  try #require(flagResult == 0)

  let outcome = await admission.write(testDocument())
  guard case .published = outcome else {
    Issue.record("expected presentation-only flag churn to remain benign, got \(outcome)")
    return
  }
}

@Test func accessSealKeepsAuthorizationFlagsAndDropsPresentationFlags() {
  let authorization: UInt32 = 0x001E_0086
  let presentation = UInt32(UF_HIDDEN | UF_NODUMP)

  #expect(SafeArtifactStore.authorizationFlags(authorization | presentation) == authorization)
  #expect(SafeArtifactStore.authorizationFlags(presentation) == 0)
}

@Test func sameUIDFinalLeafReplacementIsDetectedAndNeverOverwritten() async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let final = fixture.taskDirectory.appendingPathComponent("evidence.json")
  let displaced = fixture.taskDirectory.appendingPathComponent("displaced.json")
  let replacement = Data("replacement".utf8)
  let hooks = ArtifactStoreTestingHooks(afterPublish: {
    _ = final.path.withCString { source in
      displaced.path.withCString { Darwin.rename(source, $0) }
    }
    FileManager.default.createFile(atPath: final.path, contents: replacement)
  })
  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: AlwaysLocalArtifactProbe(),
    hooks: hooks
  )

  let outcome = await admission.write(testDocument())
  guard case .warning(let warning) = outcome else {
    Issue.record("expected published-leaf mismatch")
    return
  }
  #expect(warning.code == "artifact-published-identity-mismatch")
  #expect(try Data(contentsOf: final) == replacement)
  #expect(try Data(contentsOf: displaced) == testDocument().canonicalEncoded())
  #expect(warning.retainedLocator == nil)
}

@Test func sameInodePublishedContentMutationCannotProduceSuccessReceipt() async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let final = fixture.taskDirectory.appendingPathComponent("evidence.json")
  let replacement = Data("same-inode-replacement".utf8)
  let hooks = ArtifactStoreTestingHooks(afterPublish: {
    let descriptor = final.path.withCString {
      Darwin.open($0, O_WRONLY | O_TRUNC | O_CLOEXEC)
    }
    guard descriptor >= 0 else { return }
    replacement.withUnsafeBytes { bytes in
      if let base = bytes.baseAddress { _ = Darwin.write(descriptor, base, bytes.count) }
    }
    _ = Darwin.close(descriptor)
  })
  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: AlwaysLocalArtifactProbe(),
    hooks: hooks
  )

  let outcome = await admission.write(testDocument())
  guard case .warning(let warning) = outcome else {
    Issue.record("expected content-mutation warning")
    return
  }
  #expect(warning.code == "artifact-published-content-mismatch")
  #expect(try Data(contentsOf: final) == replacement)
}

@Test func mutationBetweenHeldDescriptorReadsCannotProduceSuccessReceipt() async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let final = fixture.taskDirectory.appendingPathComponent("evidence.json")
  let replacement = Data("between-read-replacement".utf8)
  let mutation = OneShotArtifactMutation()
  let hooks = ArtifactStoreTestingHooks(betweenSnapshotReads: {
    guard FileManager.default.fileExists(atPath: final.path) else { return }
    mutation.perform {
      let descriptor = final.path.withCString {
        Darwin.open($0, O_WRONLY | O_TRUNC | O_CLOEXEC)
      }
      guard descriptor >= 0 else { return }
      replacement.withUnsafeBytes { bytes in
        if let base = bytes.baseAddress { _ = Darwin.write(descriptor, base, bytes.count) }
      }
      _ = Darwin.close(descriptor)
    }
  })
  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: AlwaysLocalArtifactProbe(),
    hooks: hooks
  )

  let outcome = await admission.write(testDocument())
  guard case .warning(let warning) = outcome else {
    Issue.record("expected between-read content-mutation warning")
    return
  }
  #expect(warning.code == "artifact-published-content-mismatch")
  #expect(try Data(contentsOf: final) == replacement)
}

@Test func publishedLeafAccessPolicyMutationCannotProduceSuccessReceipt() async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let final = fixture.taskDirectory.appendingPathComponent("evidence.json")
  let hooks = ArtifactStoreTestingHooks(afterPublish: {
    _ = final.path.withCString { Darwin.chmod($0, 0o400) }
  })
  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: AlwaysLocalArtifactProbe(),
    hooks: hooks
  )

  let outcome = await admission.write(testDocument())
  guard case .warning(let warning) = outcome else {
    Issue.record("expected published access-policy warning")
    return
  }
  #expect(warning.code == "artifact-published-access-policy-mismatch")
}

@Test func heldDescriptorReadbackPreservesTypedFailureCategories() async throws {
  let cases: [(ArtifactReadbackFailure, String, Int32?)] = [
    (.unreadable(errno: EACCES), "artifact-temporary-readback-unreadable", EACCES),
    (.failed(errno: EIO), "artifact-temporary-readback-failed", EIO),
    (.identityMismatch, "artifact-temporary-identity-mismatch", nil),
    (.contentMismatch, "artifact-temporary-content-mismatch", nil),
    (.accessPolicyMismatch, "artifact-temporary-access-policy-mismatch", nil),
  ]

  for (failure, expectedCode, expectedErrno) in cases {
    let fixture = try ArtifactWriterFixture()
    defer { fixture.remove() }
    let admission = SafeArtifactStore.admit(
      try fixture.configuration,
      localityProbe: AlwaysLocalArtifactProbe(),
      hooks: ArtifactStoreTestingHooks(forcedReadbackFailure: { failure })
    )

    let outcome = await admission.write(testDocument())
    guard case .warning(let warning) = outcome else {
      Issue.record("expected typed readback warning for \(failure), got \(outcome)")
      continue
    }
    #expect(warning.code == expectedCode)
    #expect(warning.errno == expectedErrno)
  }
}

@Test func publishedLocatorReadbackPreservesTypedFailureCategories() async throws {
  let cases: [(ArtifactReadbackFailure, String, Int32?)] = [
    (.unreadable(errno: EACCES), "artifact-published-locator-readback-unreadable", EACCES),
    (.failed(errno: EIO), "artifact-published-locator-readback-failed", EIO),
    (.identityMismatch, "artifact-published-locator-identity-mismatch", nil),
    (.contentMismatch, "artifact-published-locator-content-mismatch", nil),
    (.accessPolicyMismatch, "artifact-published-locator-access-policy-mismatch", nil),
  ]

  for (injected, expectedCode, expectedErrno) in cases {
    let fixture = try ArtifactWriterFixture()
    defer { fixture.remove() }
    let failure = NthReadbackFailure(target: 3, failure: injected)
    let admission = SafeArtifactStore.admit(
      try fixture.configuration,
      localityProbe: AlwaysLocalArtifactProbe(),
      hooks: ArtifactStoreTestingHooks(forcedReadbackFailure: { failure.next() })
    )

    let outcome = await admission.write(testDocument())
    guard case .warning(let warning) = outcome else {
      Issue.record("expected typed published-locator warning for \(injected), got \(outcome)")
      continue
    }
    #expect(warning.code == expectedCode)
    #expect(warning.errno == expectedErrno)
    #expect(warning.retainedLocator != nil)
  }
}

@Test func ownerPrivatePolicyRequiresEffectiveUIDAndTypeSpecificMode() {
  let effectiveUser = Darwin.geteuid()
  let otherUser = effectiveUser == uid_t.max ? effectiveUser - 1 : effectiveUser + 1
  let cases: [(ObjectKind, uid_t, mode_t, Bool)] = [
    (.directory, effectiveUser, 0o700, true),
    (.directory, effectiveUser, 0o600, false),
    (.regularFile, effectiveUser, 0o600, true),
    (.regularFile, effectiveUser, 0o700, false),
    (.directory, otherUser, 0o700, false),
    (.regularFile, otherUser, 0o600, false),
    (.symbolicLink, effectiveUser, 0o700, false),
  ]

  for (kind, ownerUser, mode, expected) in cases {
    #expect(
      SafeArtifactStore.ownerPrivatePolicy(
        kind: kind,
        ownerUserID: ownerUser,
        permissions: mode,
        effectiveUserID: effectiveUser
      ) == expected)
  }
}

@Test(arguments: [
  SafeArtifactWarning(code: "artifact-write-failed", errno: ENOSPC),
  SafeArtifactWarning(code: "artifact-write-failed", errno: EROFS),
  SafeArtifactWarning(code: "artifact-write-failed", errno: EACCES),
]) func storageFailuresAreTypedNonfatalWarnings(injected: SafeArtifactWarning) async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: AlwaysLocalArtifactProbe(),
    hooks: ArtifactStoreTestingHooks(beforeWrite: { injected })
  )

  let outcome = await admission.write(testDocument())
  guard case .warning(let warning) = outcome else {
    Issue.record("expected injected storage warning")
    return
  }
  #expect(warning.code == injected.code)
  #expect(warning.errno == injected.errno)
  #expect(
    !FileManager.default.fileExists(
      atPath: fixture.taskDirectory.appendingPathComponent("evidence.json").path))
}

@Test func permissionReadOnlyDestinationRejectsAdmissionWithoutAffectingCaller() throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  try FileManager.default.setAttributes(
    [.posixPermissions: 0o500],
    ofItemAtPath: fixture.destinationParent.path
  )

  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: AlwaysLocalArtifactProbe()
  )
  guard case .rejected(let warning) = admission else {
    Issue.record("expected read-only admission rejection")
    return
  }
  #expect(warning.code == "artifact-task-directory-create-failed")
  #expect(warning.errno == EACCES || warning.errno == EPERM)
}

@Test(arguments: [
  "artifact-ancestor-unreadable",
  "artifact-locality-probe-failed",
]) func failedAndUnreadableLocalityRevalidationStayDistinct(code: String) async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let probe = SwitchableArtifactProbe()
  let admission = SafeArtifactStore.admit(try fixture.configuration, localityProbe: probe)
  probe.set(SafeArtifactWarning(code: code, errno: EACCES))

  let outcome = await admission.write(testDocument())
  guard case .warning(let warning) = outcome else {
    Issue.record("expected revalidation warning")
    return
  }
  #expect(warning.code == code)
  #expect(warning.code != "artifact-ancestor-missing")
  #expect(warning.code != "artifact-ancestor-identity-mismatch")
}

@Test func canonicalExecutionAuditSinkPublishesOnlyAtApplyFinished() async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: AlwaysLocalArtifactProbe()
  )
  guard case .admitted(let store) = admission else {
    Issue.record("expected admitted store")
    return
  }
  let sink = CanonicalExecutionAuditSink(store: store, expectedEpochID: "epoch-1")

  try await sink.record(.applyStarted(epochID: "epoch-1"), epochID: "epoch-1")
  #expect(
    !FileManager.default.fileExists(
      atPath: fixture.taskDirectory.appendingPathComponent("execution-record.json").path))
  try await sink.record(.applyFinished, epochID: "epoch-1")

  let data = try Data(
    contentsOf: fixture.taskDirectory.appendingPathComponent("execution-record.json"))
  let text = try #require(String(data: data, encoding: .utf8))
  #expect(text.contains("\"apply_started\""))
  #expect(text.contains("\"apply_finished\""))
}

@Test func auditSinkSurfacesOneBoundedTypedFailureWithoutCancellingCaller() async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let warning = SafeArtifactWarning(code: "artifact-write-failed", errno: ENOSPC)
  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: AlwaysLocalArtifactProbe(),
    hooks: ArtifactStoreTestingHooks(beforeWrite: { warning })
  )
  guard case .admitted(let store) = admission else {
    Issue.record("expected admitted store")
    return
  }
  let sink = CanonicalExecutionAuditSink(store: store, expectedEpochID: "epoch-1")
  try await sink.record(.applyStarted(epochID: "epoch-1"), epochID: "epoch-1")

  do {
    try await sink.record(.applyFinished, epochID: "epoch-1")
    Issue.record("expected audit write error")
  } catch let error as SafeArtifactWriteError {
    #expect(error.warning.code == warning.code)
    #expect(error.warning.errno == ENOSPC)
  }
  try await sink.record(.applyFinished, epochID: "epoch-1")
}

@Test func auditSinkRejectsASecondEpochWithoutDiscardingItsBoundOwner() async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: AlwaysLocalArtifactProbe()
  )
  guard case .admitted(let store) = admission else {
    Issue.record("expected admitted store")
    return
  }
  let sink = CanonicalExecutionAuditSink(store: store, expectedEpochID: "epoch-1")
  try await sink.record(.applyStarted(epochID: "epoch-1"), epochID: "epoch-1")

  do {
    try await sink.record(.applyStarted(epochID: "epoch-2"), epochID: "epoch-2")
    Issue.record("expected an epoch-mismatch audit warning")
  } catch let error as SafeArtifactWriteError {
    #expect(error.warning.code == "execution-audit-epoch-mismatch")
  }
  do {
    try await sink.record(.applyFinished, epochID: "epoch-2")
    Issue.record("expected every mismatched-epoch event to be rejected")
  } catch let error as SafeArtifactWriteError {
    #expect(error.warning.code == "execution-audit-epoch-mismatch")
  }
  try await sink.record(.applyFinished, epochID: "epoch-1")
  let data = try Data(
    contentsOf: fixture.taskDirectory.appendingPathComponent("execution-record.json"))
  let text = try #require(String(data: data, encoding: .utf8))
  #expect(text.contains("epoch-1"))
  #expect(!text.contains("epoch-2"))
}

@Test func auditSinkRejectsDeepMetadataBeforeCollectingEvents() async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: AlwaysLocalArtifactProbe()
  )
  guard case .admitted(let store) = admission else {
    Issue.record("expected admitted store")
    return
  }
  var metadata = CanonicalJSONValue.null
  for _ in 0..<80 { metadata = .array([metadata]) }
  let sink = CanonicalExecutionAuditSink(
    store: store,
    expectedEpochID: "epoch-1",
    metadata: metadata
  )

  do {
    try await sink.record(.applyStarted(epochID: "epoch-1"), epochID: "epoch-1")
    Issue.record("expected metadata structure warning")
  } catch let error as SafeArtifactWriteError {
    #expect(error.warning.code == "execution-audit-metadata-budget-or-structure-invalid")
  }
}

@Test func auditBudgetIncludesCanonicalEnvelopeAndMetadata() async throws {
  let fixture = try ArtifactWriterFixture()
  defer { fixture.remove() }
  let admission = SafeArtifactStore.admit(
    try fixture.configuration,
    localityProbe: AlwaysLocalArtifactProbe()
  )
  guard case .admitted(let store) = admission else {
    Issue.record("expected admitted store")
    return
  }
  let emptyDocumentBytes = try CanonicalArtifactDocument(
    kind: .executionRecord,
    payload: .object([
      "events": .array([]),
      "metadata": .object([:]),
    ])
  ).canonicalEncoded().count
  let sink = CanonicalExecutionAuditSink(
    store: store,
    expectedEpochID: "epoch-1",
    maximumBufferedBytes: emptyDocumentBytes
  )

  do {
    try await sink.record(.applyStarted(epochID: "epoch-1"), epochID: "epoch-1")
    Issue.record("expected full-document budget warning")
  } catch let error as SafeArtifactWriteError {
    #expect(error.warning.code == "execution-audit-buffer-budget-exhausted")
  }
}

private struct ArtifactWriterFixture {
  let root: URL
  let destinationParent: URL
  let taskIdentifier = "task"

  init() throws {
    root = try makeArtifactTestRoot()
    destinationParent = root.appendingPathComponent("destination")
    try FileManager.default.createDirectory(
      at: destinationParent,
      withIntermediateDirectories: false,
      attributes: [.posixPermissions: 0o700]
    )
  }

  var taskDirectory: URL { destinationParent.appendingPathComponent(taskIdentifier) }

  var configuration: SafeArtifactConfiguration {
    get throws {
      .enabled(
        destinationParent: try rawRoot(destinationParent),
        taskIdentifier: taskIdentifier,
        excludedScanAndProviderRoots: []
      )
    }
  }

  func remove() { try? FileManager.default.removeItem(at: root) }
}

private func testDocument() -> CanonicalArtifactDocument {
  CanonicalArtifactDocument(
    kind: .evidence,
    payload: .object([
      "count": .unsigned(2),
      "state": .string("complete"),
    ])
  )
}

private func makeArtifactTestRoot() throws -> URL {
  let root = FileManager.default.temporaryDirectory.appendingPathComponent(
    "diskplan-safe-artifacts-\(UUID().uuidString)",
    isDirectory: true
  )
  try FileManager.default.createDirectory(
    at: root,
    withIntermediateDirectories: false,
    attributes: [.posixPermissions: 0o700]
  )
  return try canonicalTestURL(root)
}

private func canonicalTestURL(_ url: URL) throws -> URL {
  var buffer = [CChar](repeating: 0, count: Int(MAXPATHLEN))
  guard url.path.withCString({ Darwin.realpath($0, &buffer) }) != nil else {
    throw SafeArtifactWarning(code: "test-realpath-failed", errno: errno)
  }
  return URL(fileURLWithFileSystemRepresentation: buffer, isDirectory: true, relativeTo: nil)
}

private func rawRoot(_ url: URL, resolveSymlinks: Bool = true) throws -> RawRootPath {
  let selected = resolveSymlinks ? try canonicalTestURL(url) : url
  let bytes = selected.withUnsafeFileSystemRepresentation { representation -> Data? in
    guard let representation else { return nil }
    return Data(bytes: representation, count: strlen(representation))
  }
  return try RawRootPath(absoluteBytes: #require(bytes))
}

private func artifactIdentity(_ url: URL) throws -> ObjectIdentity {
  var value = stat()
  guard url.path.withCString({ Darwin.lstat($0, &value) }) == 0 else {
    throw SafeArtifactWarning(code: "test-lstat-failed", errno: errno)
  }
  let type: ObjectKind
  switch value.st_mode & S_IFMT {
  case S_IFDIR: type = .directory
  case S_IFREG: type = .regularFile
  case S_IFLNK: type = .symbolicLink
  default: throw SafeArtifactWarning(code: "test-object-type-unsupported")
  }
  return ObjectIdentity(
    device: UInt64(UInt32(bitPattern: value.st_dev)),
    object: UInt64(value.st_ino),
    generation: .known(UInt64(value.st_gen)),
    type: type
  )
}
