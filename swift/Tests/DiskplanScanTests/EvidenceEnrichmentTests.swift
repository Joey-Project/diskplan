import CryptoKit
import Darwin
import Foundation
import Testing

@testable import DiskplanMacOS
@testable import DiskplanScan

private func evidenceDigest(_ bytes: Data) -> EvidenceDigest {
  EvidenceDigest(unchecked: Data(SHA256.hash(data: bytes)))
}

private let rootIdentity = ObjectIdentity(device: 7, fileID: 11, objectType: .directory)
private let rootPath = RawPath(rootID: "root")

private func policy(
  mode: UInt32 = UInt32(S_IFDIR | S_IRWXU),
  acl: Observation<EvidenceDigest> = .known(evidenceDigest(Data("acl".utf8)))
) -> AccessPolicyEvidence {
  AccessPolicyEvidence(
    ownerUserID: 501,
    ownerGroupID: 20,
    mode: mode,
    flags: 0,
    aclDigest: acl
  )
}

private func adapterToken(
  kind: ConfiguredAdapterScopeKind,
  selectorNamespaceIdentity: ObjectIdentity? = nil,
  selectorNamespaceAccessPolicy: AccessPolicyEvidence? = nil
) throws -> ConfiguredAdapterScopeToken {
  try #require(
    ConfiguredAdapterScopeRegistry().bind(
      definition: ConfiguredAdapterScopeDefinition(
        scopeID: "scope",
        kind: kind,
        rootPath: rootPath,
        helperCapability: "helper-v1",
        selectorRawName: kind == .versionedArtifact ? Data("current".utf8) : nil
      ),
      trustedBinding: TrustedConfiguredScopeBinding(
        rootPath: rootPath,
        rootIdentity: rootIdentity,
        rootAccessPolicy: policy(),
        selectorNamespaceIdentity: selectorNamespaceIdentity,
        selectorNamespaceAccessPolicy: selectorNamespaceAccessPolicy,
        selectorRawName: kind == .versionedArtifact ? Data("current".utf8) : nil
      )
    ).value
  )
}

private func heldGitSeal(
  _ identity: ObjectIdentity,
  digest: Observation<EvidenceDigest> = .known(evidenceDigest(Data("content".utf8)))
) -> GitHeldObjectSeal {
  let typeMode: UInt32 =
    switch identity.objectType {
    case .directory: UInt32(S_IFDIR | S_IRWXU)
    case .regular: UInt32(S_IFREG | S_IRUSR | S_IWUSR)
    case .symbolicLink: UInt32(S_IFLNK | S_IRWXU)
    case .other: UInt32(S_IFIFO | S_IRUSR | S_IWUSR)
    }
  return GitHeldObjectSeal(
    identity: identity,
    accessPolicy: policy(mode: typeMode),
    contentDigest: digest
  )
}

private func gitSnapshot(
  worktree: ObjectIdentity,
  administrative: ObjectIdentity,
  common: ObjectIdentity,
  registrationContentDigest: EvidenceDigest = evidenceDigest(Data("registration".utf8)),
  missingHeadDigest: Bool = false
) -> GitMetadataSnapshot {
  GitMetadataSnapshot(
    worktreeRoot: heldGitSeal(worktree),
    administrativeDirectory: heldGitSeal(administrative),
    commonDirectory: heldGitSeal(common),
    index: heldGitSeal(ObjectIdentity(device: 7, fileID: 40, objectType: .regular)),
    head: heldGitSeal(
      ObjectIdentity(device: 7, fileID: 41, objectType: .regular),
      digest: missingHeadDigest
        ? .unknown(reason: "not collected") : .known(evidenceDigest(Data("head".utf8)))
    ),
    registration: heldGitSeal(
      ObjectIdentity(device: 7, fileID: 42, objectType: .regular),
      digest: .known(registrationContentDigest)
    )
  )
}

private final class LockedCounter: @unchecked Sendable {
  private let lock = NSLock()
  private var stored = 0

  func increment() { lock.withLock { stored += 1 } }
  var value: Int { lock.withLock { stored } }
}

private final class LockedProviderSequence: @unchecked Sendable {
  private let lock = NSLock()
  private let values: [Observation<ProviderBoundary>]
  private var index = 0

  init(_ values: [Observation<ProviderBoundary>]) { self.values = values }

  func next() -> Observation<ProviderBoundary> {
    lock.withLock {
      let value = values[min(index, values.count - 1)]
      index += 1
      return value
    }
  }
}

private final class LockedObservationSequence<Value: Equatable & Sendable>: @unchecked Sendable {
  private let lock = NSLock()
  private let values: [Observation<Value>]
  private var index = 0

  init(_ values: [Observation<Value>]) { self.values = values }

  func next() -> Observation<Value> {
    lock.withLock {
      let value = values[min(index, values.count - 1)]
      index += 1
      return value
    }
  }
}

private func contentBudget(maximumFiles: UInt32 = 8) throws -> ContentCollectionBudget {
  try ContentCollectionBudget(
    maximumBytesPerFile: 256 * 1_024,
    maximumAggregateBytes: UInt64(maximumFiles) * 256 * 1_024,
    maximumFiles: maximumFiles,
    deadlineMonotonicNanoseconds: 100
  )
}

private func registerContentRequest(
  authority: ScannerContentCollectionAuthority,
  transferring fileDescriptor: Int32,
  seal: DescriptorContentSeal,
  target: RawPath,
  providerObservation: @escaping @Sendable () -> Observation<ProviderBoundary>
) -> Observation<ContentCollectionRequestID> {
  let rootAccessPolicy = policy()
  return authority.bindScannerDescriptor(
    transferring: fileDescriptor,
    target: target,
    rootIdentity: rootIdentity,
    rootAccessPolicy: rootAccessPolicy,
    expectedIdentity: seal.identity,
    expectedAccessPolicy: seal.accessPolicy,
    rootIdentityObservation: { .known(rootIdentity) },
    rootAccessPolicyObservation: { .known(rootAccessPolicy) },
    slotPathObservation: { .known(target) },
    slotIdentityObservation: { .known(seal.identity) },
    slotAccessPolicyObservation: { .known(seal.accessPolicy) },
    providerObservation: providerObservation
  )
}

@Test func ancestorSealSeparatesAccessPolicyFromObjectIdentity() {
  let base = appendAncestorAccessPolicySeal(
    parent: nil,
    rootIdentity: rootIdentity,
    identity: rootIdentity,
    accessPolicy: .known(policy()),
    pendingCloseEpochID: evidenceDigest(Data("root-close".utf8))
  )
  let changedMode = appendAncestorAccessPolicySeal(
    parent: nil,
    rootIdentity: rootIdentity,
    identity: rootIdentity,
    accessPolicy: .known(policy(mode: UInt32(S_IFDIR | S_IRUSR))),
    pendingCloseEpochID: evidenceDigest(Data("root-close".utf8))
  )
  #expect(base.value?.rootIdentity == changedMode.value?.rootIdentity)
  #expect(base.value?.digest != changedMode.value?.digest)
}

@Test func unknownACLKeepsAncestorSealUnknown() {
  let seal = appendAncestorAccessPolicySeal(
    parent: nil,
    rootIdentity: rootIdentity,
    identity: rootIdentity,
    accessPolicy: .known(policy(acl: .unreadable(reason: "denied", errorCode: EACCES))),
    pendingCloseEpochID: evidenceDigest(Data("root-close".utf8))
  )
  #expect(seal == .unreadable(reason: "denied", errorCode: EACCES))
}

@Test func providerBoundaryDriftPreventsAnyContentRead() throws {
  let temporaryURL = FileManager.default.temporaryDirectory.appendingPathComponent(
    "diskplan-content-evidence-\(UUID().uuidString)")
  try Data(repeating: 7, count: 128 * 1_024).write(to: temporaryURL, options: .withoutOverwriting)
  defer { try? FileManager.default.removeItem(at: temporaryURL) }
  let fileDescriptor = open(temporaryURL.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
  #expect(fileDescriptor >= 0)
  guard fileDescriptor >= 0 else { return }
  defer { Darwin.close(fileDescriptor) }
  let noMaterializationPolicy = try #require(
    MaterializationPolicyInstaller().installBeforePathAccess().value)
  let seal = try #require(
    descriptorSeal(fileDescriptor: fileDescriptor, policy: noMaterializationPolicy))
  let target = RawPath(rootID: "root", components: [RawPathComponent(Data("candidate".utf8))])
  let providers = LockedProviderSequence([
    .known(.localOrUnindicated),
    .known(.metadataOnly(reason: "provider ownership became authoritative")),
  ])
  let firstOwnedDescriptor = dup(fileDescriptor)
  #expect(firstOwnedDescriptor >= 0)
  guard firstOwnedDescriptor >= 0 else { return }
  let reads = LockedCounter()
  let authority = ScannerContentCollectionAuthority(
    policy: noMaterializationPolicy,
    budget: try contentBudget(maximumFiles: 1),
    monotonicNow: { 1 },
    descriptorReader: { descriptor, buffer, count, offset in
      reads.increment()
      return Darwin.pread(descriptor, buffer, count, offset)
    }
  )
  let requestID = try #require(
    registerContentRequest(
      authority: authority,
      transferring: firstOwnedDescriptor,
      seal: seal,
      target: target,
      providerObservation: providers.next
    ).value)
  #expect(authority.evidenceConsumer.collect(requestID) == .notApplicable(.providerManaged))
  #expect(reads.value == 0)
  errno = 0
  #expect(fcntl(firstOwnedDescriptor, F_GETFD) == -1)
  #expect(errno == EBADF)
  let replacementDescriptor = open("/dev/null", O_RDONLY | O_CLOEXEC)
  let replacement = try #require(replacementDescriptor >= 0 ? replacementDescriptor : nil)
  if replacement != firstOwnedDescriptor {
    #expect(dup2(replacement, firstOwnedDescriptor) == firstOwnedDescriptor)
    Darwin.close(replacement)
  }
  defer { Darwin.close(firstOwnedDescriptor) }
  #expect(
    authority.evidenceConsumer.collect(requestID)
      == .unavailable(
        reason: "content collection request is already consumed", errorCode: EALREADY))
  #expect(fcntl(firstOwnedDescriptor, F_GETFD) >= 0)
  #expect(reads.value == 0)
  let secondOwnedDescriptor = dup(fileDescriptor)
  #expect(secondOwnedDescriptor >= 0)
  guard secondOwnedDescriptor >= 0 else { return }
  let mismatchedAuthority = ScannerContentCollectionAuthority(
    policy: noMaterializationPolicy,
    budget: try contentBudget(maximumFiles: 1),
    monotonicNow: { 1 },
    descriptorReader: { descriptor, buffer, count, offset in
      reads.increment()
      return Darwin.pread(descriptor, buffer, count, offset)
    }
  )
  let rootAccessPolicy = policy()
  #expect(
    mismatchedAuthority.bindScannerDescriptor(
      transferring: secondOwnedDescriptor,
      target: target,
      rootIdentity: rootIdentity,
      rootAccessPolicy: rootAccessPolicy,
      expectedIdentity: seal.identity,
      expectedAccessPolicy: seal.accessPolicy,
      rootIdentityObservation: { .known(rootIdentity) },
      rootAccessPolicyObservation: { .known(rootAccessPolicy) },
      slotPathObservation: { .known(RawPath(rootID: "wrong")) },
      slotIdentityObservation: { .known(seal.identity) },
      slotAccessPolicyObservation: { .known(seal.accessPolicy) },
      providerObservation: { .known(.localOrUnindicated) }
    ).value == nil)
  #expect(reads.value == 0)
  errno = 0
  #expect(fcntl(secondOwnedDescriptor, F_GETFD) == -1)
  #expect(errno == EBADF)
}

@Test func providerUncertaintyAfterRegistrationPreventsAnyContentRead() throws {
  let temporaryURL = FileManager.default.temporaryDirectory.appendingPathComponent(
    "diskplan-provider-uncertain-content-\(UUID().uuidString)")
  try Data("content".utf8).write(to: temporaryURL, options: .withoutOverwriting)
  defer { try? FileManager.default.removeItem(at: temporaryURL) }
  let descriptor = open(temporaryURL.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
  let ownedDescriptor = try #require(descriptor >= 0 ? descriptor : nil)
  let noMaterializationPolicy = try #require(
    MaterializationPolicyInstaller().installBeforePathAccess().value)
  let seal = try #require(
    descriptorSeal(fileDescriptor: ownedDescriptor, policy: noMaterializationPolicy))
  let providers = LockedProviderSequence([
    .known(.localOrUnindicated),
    .unknown(reason: "provider ownership unavailable"),
  ])
  let reads = LockedCounter()
  let authority = ScannerContentCollectionAuthority(
    policy: noMaterializationPolicy,
    budget: try contentBudget(),
    monotonicNow: { 1 },
    descriptorReader: { descriptor, buffer, count, offset in
      reads.increment()
      return Darwin.pread(descriptor, buffer, count, offset)
    }
  )
  let requestID = try #require(
    registerContentRequest(
      authority: authority,
      transferring: ownedDescriptor,
      seal: seal,
      target: RawPath(rootID: "root"),
      providerObservation: providers.next
    ).value)
  #expect(authority.evidenceConsumer.collect(requestID) == .notApplicable(.providerStateUnverified))
  #expect(reads.value == 0)
  errno = 0
  #expect(fcntl(ownedDescriptor, F_GETFD) == -1)
  #expect(errno == EBADF)
}

@Test func rootAccessReceiptDriftAfterRegistrationPreventsAnyContentRead() throws {
  let temporaryURL = FileManager.default.temporaryDirectory.appendingPathComponent(
    "diskplan-root-policy-drift-content-\(UUID().uuidString)")
  try Data("content".utf8).write(to: temporaryURL, options: .withoutOverwriting)
  defer { try? FileManager.default.removeItem(at: temporaryURL) }
  let descriptor = open(temporaryURL.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
  let ownedDescriptor = try #require(descriptor >= 0 ? descriptor : nil)
  let noMaterializationPolicy = try #require(
    MaterializationPolicyInstaller().installBeforePathAccess().value)
  let seal = try #require(
    descriptorSeal(fileDescriptor: ownedDescriptor, policy: noMaterializationPolicy))
  let rootAccessPolicy = policy()
  let rootPolicies = LockedObservationSequence<AccessPolicyEvidence>([
    .known(rootAccessPolicy),
    .known(policy(mode: UInt32(S_IFDIR | S_IRUSR))),
  ])
  let target = RawPath(rootID: "root")
  let reads = LockedCounter()
  let authority = ScannerContentCollectionAuthority(
    policy: noMaterializationPolicy,
    budget: try contentBudget(),
    monotonicNow: { 1 },
    descriptorReader: { descriptor, buffer, count, offset in
      reads.increment()
      return Darwin.pread(descriptor, buffer, count, offset)
    }
  )
  let requestID = try #require(
    authority.bindScannerDescriptor(
      transferring: ownedDescriptor,
      target: target,
      rootIdentity: rootIdentity,
      rootAccessPolicy: rootAccessPolicy,
      expectedIdentity: seal.identity,
      expectedAccessPolicy: seal.accessPolicy,
      rootIdentityObservation: { .known(rootIdentity) },
      rootAccessPolicyObservation: rootPolicies.next,
      slotPathObservation: { .known(target) },
      slotIdentityObservation: { .known(seal.identity) },
      slotAccessPolicyObservation: { .known(seal.accessPolicy) },
      providerObservation: { .known(.localOrUnindicated) }
    ).value)
  #expect(
    authority.evidenceConsumer.collect(requestID)
      == .unavailable(reason: "bound content root or slot receipt changed", errorCode: ESTALE))
  #expect(reads.value == 0)
  errno = 0
  #expect(fcntl(ownedDescriptor, F_GETFD) == -1)
  #expect(errno == EBADF)
}

@Test func registrationBudgetRejectsAndClosesExcessDescriptor() throws {
  let temporaryURL = FileManager.default.temporaryDirectory.appendingPathComponent(
    "diskplan-unregistered-content-\(UUID().uuidString)")
  try Data("content".utf8).write(to: temporaryURL, options: .withoutOverwriting)
  defer { try? FileManager.default.removeItem(at: temporaryURL) }
  let descriptor = open(temporaryURL.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
  let ownedDescriptor = try #require(descriptor >= 0 ? descriptor : nil)
  let noMaterializationPolicy = try #require(
    MaterializationPolicyInstaller().installBeforePathAccess().value)
  let seal = try #require(
    descriptorSeal(fileDescriptor: ownedDescriptor, policy: noMaterializationPolicy))
  let authority = ScannerContentCollectionAuthority(
    policy: noMaterializationPolicy,
    budget: try contentBudget(maximumFiles: 1),
    monotonicNow: { 1 }
  )
  let firstDescriptor = dup(ownedDescriptor)
  let firstOwnedDescriptor = try #require(firstDescriptor >= 0 ? firstDescriptor : nil)
  _ = try #require(
    registerContentRequest(
      authority: authority,
      transferring: firstOwnedDescriptor,
      seal: seal,
      target: RawPath(rootID: "root"),
      providerObservation: { .known(.localOrUnindicated) }
    ).value)
  #expect(
    registerContentRequest(
      authority: authority,
      transferring: ownedDescriptor,
      seal: seal,
      target: RawPath(rootID: "root"),
      providerObservation: { .known(.localOrUnindicated) }
    ).value == nil)
  errno = 0
  #expect(fcntl(ownedDescriptor, F_GETFD) == -1)
  #expect(errno == EBADF)
}

@Test func contentSessionCloseAndEpochAdvanceDrainRequestsAndRejectIDs() throws {
  let temporaryURL = FileManager.default.temporaryDirectory.appendingPathComponent(
    "diskplan-session-content-\(UUID().uuidString)")
  try Data("content".utf8).write(to: temporaryURL, options: .withoutOverwriting)
  defer { try? FileManager.default.removeItem(at: temporaryURL) }
  let sourceDescriptor = open(temporaryURL.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
  let source = try #require(sourceDescriptor >= 0 ? sourceDescriptor : nil)
  defer { Darwin.close(source) }
  let noMaterializationPolicy = try #require(
    MaterializationPolicyInstaller().installBeforePathAccess().value)
  let seal = try #require(descriptorSeal(fileDescriptor: source, policy: noMaterializationPolicy))

  let epochAuthority = ScannerContentCollectionAuthority(
    policy: noMaterializationPolicy,
    budget: try contentBudget(),
    monotonicNow: { 1 }
  )
  let epochRaw = dup(source)
  let epochDescriptor = try #require(epochRaw >= 0 ? epochRaw : nil)
  let epochID = try #require(
    registerContentRequest(
      authority: epochAuthority,
      transferring: epochDescriptor,
      seal: seal,
      target: RawPath(rootID: "root"),
      providerObservation: { .known(.localOrUnindicated) }
    ).value)
  #expect(epochAuthority.advanceEpoch())
  #expect(
    epochAuthority.evidenceConsumer.collect(epochID)
      == .unavailable(reason: "content collection epoch changed", errorCode: ESTALE))
  errno = 0
  #expect(fcntl(epochDescriptor, F_GETFD) == -1)
  #expect(errno == EBADF)

  let closeAuthority = ScannerContentCollectionAuthority(
    policy: noMaterializationPolicy,
    budget: try contentBudget(),
    monotonicNow: { 1 }
  )
  let closeRaw = dup(source)
  let closeDescriptor = try #require(closeRaw >= 0 ? closeRaw : nil)
  let closeID = try #require(
    registerContentRequest(
      authority: closeAuthority,
      transferring: closeDescriptor,
      seal: seal,
      target: RawPath(rootID: "root"),
      providerObservation: { .known(.localOrUnindicated) }
    ).value)
  closeAuthority.close()
  #expect(
    closeAuthority.evidenceConsumer.collect(closeID)
      == .unavailable(reason: "content collection session is closed", errorCode: ECANCELED))
  errno = 0
  #expect(fcntl(closeDescriptor, F_GETFD) == -1)
  #expect(errno == EBADF)
}

@Test func contentRequestMisrouteCannotConsumeAnotherSessionReceipt() throws {
  let temporaryURL = FileManager.default.temporaryDirectory.appendingPathComponent(
    "diskplan-misroute-content-\(UUID().uuidString)")
  try Data("content".utf8).write(to: temporaryURL, options: .withoutOverwriting)
  defer { try? FileManager.default.removeItem(at: temporaryURL) }
  let descriptor = open(temporaryURL.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
  let ownedDescriptor = try #require(descriptor >= 0 ? descriptor : nil)
  let noMaterializationPolicy = try #require(
    MaterializationPolicyInstaller().installBeforePathAccess().value)
  let seal = try #require(
    descriptorSeal(fileDescriptor: ownedDescriptor, policy: noMaterializationPolicy))
  let first = ScannerContentCollectionAuthority(
    policy: noMaterializationPolicy,
    budget: try contentBudget(),
    monotonicNow: { 1 }
  )
  let second = ScannerContentCollectionAuthority(
    policy: noMaterializationPolicy,
    budget: try contentBudget(),
    monotonicNow: { 1 }
  )
  let requestID = try #require(
    registerContentRequest(
      authority: first,
      transferring: ownedDescriptor,
      seal: seal,
      target: RawPath(rootID: "root"),
      providerObservation: { .known(.localOrUnindicated) }
    ).value)
  #expect(
    second.evidenceConsumer.collect(requestID)
      == .unavailable(reason: "content collection request is unknown", errorCode: ENOENT))
  #expect(fcntl(ownedDescriptor, F_GETFD) >= 0)
  _ = first.evidenceConsumer.collect(requestID)
  errno = 0
  #expect(fcntl(ownedDescriptor, F_GETFD) == -1)
  #expect(errno == EBADF)
}

@Test func gitStatusParserStreamsCountsWithoutRetainingPaths() {
  let status = Data(
    "1 M. N... 100644 100644 100644 aaa bbb tracked\0? untracked\0! ignored\0".utf8)
  let result = GitPorcelainV2Parser.parse(
    status,
    maximumRecords: 10,
    maximumBytes: 4_096
  )
  #expect(result.value?.staged == 1)
  #expect(result.value?.unstaged == 0)
  #expect(result.value?.untracked == 1)
  #expect(result.value?.ignored == 1)
}

@Test func gitRenameConsumesSecondNULPathAsPartOfOneRecord() {
  let status = Data(
    "2 R. N... 100644 100644 100644 aaa bbb R100 destination\0source\0".utf8)
  let result = GitPorcelainV2Parser.parse(
    status,
    maximumRecords: 1,
    maximumBytes: 4_096
  )
  #expect(result.value?.staged == 1)
}

@Test func gitCommandContractDisablesMutableAndInteractiveFeatures() {
  let status = ReadOnlyGitCommandSpec.spec(for: .status)
  #expect(ReadOnlyGitCommandSpec.executablePath == "/usr/bin/git")
  #expect(status.arguments.first == "--no-optional-locks")
  #expect(status.arguments.contains("core.fsmonitor=false"))
  #expect(status.arguments.contains("maintenance.auto=false"))
  #expect(status.arguments.contains("gc.auto=0"))
  #expect(status.replacementEnvironment["GIT_OPTIONAL_LOCKS"] == "0")
  #expect(status.replacementEnvironment["GIT_TERMINAL_PROMPT"] == "0")
  #expect(status.replacementEnvironment["GIT_CONFIG_GLOBAL"] == "/dev/null")
  #expect(status.replacementEnvironment["GIT_CONFIG_NOSYSTEM"] == "1")
  #expect(status == ReadOnlyGitCommandSpec.spec(for: .status))
}

@Test func gitEvidenceStaysUnavailableWithoutSupervisedRunnerReceipt() {
  let evidence = GitWorktreeEvidenceCollector.unavailable(marker: .known(.linkedGitdirFile))
  #expect(evidence.commandCoverage.completeness == .partial)
  #expect(evidence.changes.value == nil)
  #expect(evidence.registration.value == nil)
}

@Test func gitMetadataCrossJoinBindsRawRegistrationAndExactHeldMetadata() throws {
  let administrative = ObjectIdentity(device: 7, fileID: 20, objectType: .directory)
  let common = ObjectIdentity(device: 7, fileID: 21, objectType: .directory)
  let rawRegistrationBinding = Data("worktrees/one".utf8)
  let registrationDigest = gitRawRegistrationBindingDigest(rawRegistrationBinding)
  let incomplete = gitSnapshot(
    worktree: rootIdentity,
    administrative: administrative,
    common: common,
    registrationContentDigest: registrationDigest,
    missingHeadDigest: true
  )
  let incompleteRegistration = GitRegistrationEvidence(
    worktreeIdentity: rootIdentity,
    administrativeDirectoryIdentity: administrative,
    commonDirectoryIdentity: common,
    rawRegistrationBinding: rawRegistrationBinding,
    registrationDigest: registrationDigest,
    metadataDigest: evidenceDigest(Data("incomplete-metadata".utf8))
  )
  #expect(
    GitMetadataCrossJoin.validate(
      registration: incompleteRegistration, preflight: incomplete, postflight: incomplete
    ).value == nil)

  let complete = gitSnapshot(
    worktree: rootIdentity,
    administrative: administrative,
    common: common,
    registrationContentDigest: registrationDigest
  )
  let metadataDigest = try #require(gitMetadataSnapshotDigest(complete))
  let registration = GitRegistrationEvidence(
    worktreeIdentity: rootIdentity,
    administrativeDirectoryIdentity: administrative,
    commonDirectoryIdentity: common,
    rawRegistrationBinding: rawRegistrationBinding,
    registrationDigest: registrationDigest,
    metadataDigest: metadataDigest
  )
  #expect(
    GitMetadataCrossJoin.validate(
      registration: registration, preflight: complete, postflight: complete
    ) == .known(true))
  let rawMismatch = GitRegistrationEvidence(
    worktreeIdentity: rootIdentity,
    administrativeDirectoryIdentity: administrative,
    commonDirectoryIdentity: common,
    rawRegistrationBinding: Data("worktrees/two".utf8),
    registrationDigest: registrationDigest,
    metadataDigest: metadataDigest
  )
  #expect(
    GitMetadataCrossJoin.validate(
      registration: rawMismatch, preflight: complete, postflight: complete
    ).value == nil)
  let metadataMismatch = GitRegistrationEvidence(
    worktreeIdentity: rootIdentity,
    administrativeDirectoryIdentity: administrative,
    commonDirectoryIdentity: common,
    rawRegistrationBinding: rawRegistrationBinding,
    registrationDigest: registrationDigest,
    metadataDigest: evidenceDigest(Data("other-metadata".utf8))
  )
  #expect(
    GitMetadataCrossJoin.validate(
      registration: metadataMismatch, preflight: complete, postflight: complete
    ).value == nil)
  let spliced = GitRegistrationEvidence(
    worktreeIdentity: rootIdentity,
    administrativeDirectoryIdentity: ObjectIdentity(
      device: 7, fileID: 99, objectType: .directory),
    commonDirectoryIdentity: common,
    rawRegistrationBinding: rawRegistrationBinding,
    registrationDigest: registrationDigest,
    metadataDigest: metadataDigest
  )
  #expect(
    GitMetadataCrossJoin.validate(
      registration: spliced, preflight: complete, postflight: complete
    ).value == nil)
}

@Test func gitSessionBudgetCannotResetTargetOrAggregateCapsPerCall() throws {
  let configuration = try GitEvidenceBudget(
    maximumTargets: 1,
    maximumOutputBytesPerTarget: 10,
    maximumAggregateOutputBytes: 10,
    maximumStatusRecordsPerTarget: 2,
    maximumAggregateStatusRecords: 2,
    deadlineMonotonicNanoseconds: 100
  )
  let budget = GitEvidenceSessionBudget(configuration: configuration, monotonicNow: { 1 })
  let reservation = try #require(budget.reserveTarget().value)
  #expect(budget.reserveTarget().value == nil)
  #expect(budget.reserveOutput(for: reservation, bytes: 6, statusRecords: 1) == .known(true))
  #expect(budget.reserveOutput(for: reservation, bytes: 5, statusRecords: 1).value == nil)
  budget.finish(reservation)
  #expect(budget.reserveOutput(for: reservation, bytes: 1, statusRecords: 0).value == nil)
}

@Test func filesystemAccessFlagMaskExcludesAdvisoryAndStorageFlags() {
  let advisory = UInt32(UF_NODUMP) | UInt32(UF_COMPRESSED) | UInt32(UF_HIDDEN)
  #expect(darwinAccessControlFlags(advisory) == 0)
  let access =
    UInt32(UF_IMMUTABLE) | UInt32(UF_APPEND) | UInt32(UF_DATAVAULT)
    | UInt32(SF_IMMUTABLE) | UInt32(SF_APPEND) | UInt32(SF_RESTRICTED)
    | UInt32(SF_NOUNLINK)
  #expect(darwinAccessControlFlags(access | advisory) == access)
  let metadata = FilesystemFlagMetadataEvidence(rawFlags: access | advisory)
  #expect(metadata.nonAccessControlFlags == advisory)
}

@Test func accessPolicyEpochLedgerRequiresSuccessfulCloseReceipt() {
  let epochID = evidenceDigest(Data("root-close".utf8))
  let provisional = appendAncestorAccessPolicySeal(
    parent: nil,
    rootIdentity: rootIdentity,
    identity: rootIdentity,
    accessPolicy: .known(policy()),
    pendingCloseEpochID: epochID
  )
  let ledger = AccessPolicyEpochLedger()
  #expect(ledger.finalize(provisional).value == nil)
  ledger.receive(
    DirectoryCloseEpochReceipt(
      epochID: epochID,
      result: .failed(reason: "access policy changed", errorCode: EAGAIN)
    ))
  #expect(ledger.finalize(provisional).value == nil)
}

@Test func configuredScopeRegistryRejectsRawRootMismatchAndNonDirectoryRoot() {
  let definition = ConfiguredAdapterScopeDefinition(
    scopeID: "scope",
    kind: .codexCleanup,
    rootPath: rootPath,
    helperCapability: "helper-v1",
    selectorRawName: nil
  )
  let mismatched = ConfiguredAdapterScopeRegistry().bind(
    definition: definition,
    trustedBinding: TrustedConfiguredScopeBinding(
      rootPath: RawPath(rootID: "other"),
      rootIdentity: rootIdentity,
      rootAccessPolicy: policy(),
      selectorNamespaceIdentity: nil,
      selectorNamespaceAccessPolicy: nil,
      selectorRawName: nil
    )
  )
  #expect(mismatched.value == nil)
  let regular = ConfiguredAdapterScopeRegistry().bind(
    definition: definition,
    trustedBinding: TrustedConfiguredScopeBinding(
      rootPath: rootPath,
      rootIdentity: ObjectIdentity(device: 7, fileID: 11, objectType: .regular),
      rootAccessPolicy: policy(),
      selectorNamespaceIdentity: nil,
      selectorNamespaceAccessPolicy: nil,
      selectorRawName: nil
    )
  )
  #expect(regular.value == nil)

  let versionDefinition = ConfiguredAdapterScopeDefinition(
    scopeID: "version-scope",
    kind: .versionedArtifact,
    rootPath: rootPath,
    helperCapability: "helper-v1",
    selectorRawName: Data("current".utf8)
  )
  let selectorMismatch = ConfiguredAdapterScopeRegistry().bind(
    definition: versionDefinition,
    trustedBinding: TrustedConfiguredScopeBinding(
      rootPath: rootPath,
      rootIdentity: rootIdentity,
      rootAccessPolicy: policy(),
      selectorNamespaceIdentity: ObjectIdentity(
        device: 7, fileID: 12, objectType: .directory),
      selectorNamespaceAccessPolicy: policy(),
      selectorRawName: Data("previous".utf8)
    )
  )
  #expect(selectorMismatch.value == nil)
}

@Test func codexScopeRequiresTokenBoundIdentityAccessAndHelper() throws {
  let token = try adapterToken(kind: .codexCleanup)
  let configuration = try ConfiguredAdapterEvidenceBudget(
    maximumScopes: 1,
    maximumEntriesPerScope: 1,
    maximumMetadataBytesPerEntry: 1_024,
    maximumAggregateMetadataBytes: 1_024,
    deadlineMonotonicNanoseconds: 100
  )
  let evidence = AdapterEvidenceBuilder.codexCleanupScope(
    token: token,
    budget: ConfiguredAdapterEvidenceSessionBudget(
      configuration: configuration,
      monotonicNow: { 1 }
    ),
    boundRootPath: .known(rootPath),
    boundRootIdentity: .known(rootIdentity),
    boundRootAccessPolicy: .known(policy()),
    helperCapability: .known("wrong-helper"),
    coverage: .complete
  )
  #expect(evidence.coverage.completeness == .partial)
  #expect(
    evidence.provenance
      == .typeHintOnly(
        reason: "configured Codex scope binding did not revalidate"))
  let misrouted = AdapterEvidenceBuilder.codexCleanupScope(
    token: token,
    budget: ConfiguredAdapterEvidenceSessionBudget(
      configuration: configuration,
      monotonicNow: { 1 }
    ),
    boundRootPath: .known(RawPath(rootID: "other")),
    boundRootIdentity: .known(rootIdentity),
    boundRootAccessPolicy: .known(policy()),
    helperCapability: .known("helper-v1"),
    coverage: .complete
  )
  #expect(misrouted.coverage.completeness == .partial)
}

@Test func versionedArtifactSurvivorRequiresConfiguredCompleteEvidence() throws {
  let versionIdentity = ObjectIdentity(device: 7, fileID: 12, objectType: .directory)
  let namespaceIdentity = ObjectIdentity(device: 7, fileID: 14, objectType: .directory)
  let namespacePolicy = policy()
  let token = try adapterToken(
    kind: .versionedArtifact,
    selectorNamespaceIdentity: namespaceIdentity,
    selectorNamespaceAccessPolicy: namespacePolicy
  )
  let selector = ActiveVersionSelectorEvidence(
    rawName: Data("current".utf8),
    selectorIdentity: ObjectIdentity(device: 7, fileID: 13, objectType: .symbolicLink),
    selectorAccessPolicy: policy(),
    namespaceIdentity: namespaceIdentity,
    namespaceAccessPolicy: namespacePolicy,
    rawTarget: Data("1.0.0".utf8)
  )
  let version = VersionedArtifactVersionEvidence(
    rawName: Data("1.0.0".utf8),
    identity: .known(versionIdentity),
    metadataDigest: .known(evidenceDigest(Data("manifest".utf8)))
  )
  let budgetConfiguration = try ConfiguredAdapterEvidenceBudget(
    maximumScopes: 2,
    maximumEntriesPerScope: 4,
    maximumMetadataBytesPerEntry: 1_024,
    maximumAggregateMetadataBytes: 2_048,
    deadlineMonotonicNanoseconds: 100
  )
  let budget = ConfiguredAdapterEvidenceSessionBudget(
    configuration: budgetConfiguration,
    monotonicNow: { 1 }
  )
  let known = AdapterEvidenceBuilder.versionedArtifact(
    token: token,
    budget: budget,
    installRootPath: .known(rootPath),
    installRootIdentity: .known(rootIdentity),
    installRootAccessPolicy: .known(policy()),
    helperCapability: .known("helper-v1"),
    activeSelector: .known(selector),
    versions: [version],
    currentUpdateMarker: .known(false),
    coverage: .complete
  )
  #expect(known.survivorRawNames == .known([Data("1.0.0".utf8)]))

  let helperDrift = AdapterEvidenceBuilder.versionedArtifact(
    token: token,
    budget: ConfiguredAdapterEvidenceSessionBudget(
      configuration: budgetConfiguration,
      monotonicNow: { 1 }
    ),
    installRootPath: .known(rootPath),
    installRootIdentity: .known(rootIdentity),
    installRootAccessPolicy: .known(policy()),
    helperCapability: .known("helper-v2"),
    activeSelector: .known(selector),
    versions: [version],
    currentUpdateMarker: .known(false),
    coverage: .complete
  )
  #expect(helperDrift.survivorRawNames.value == nil)
  let misrouted = AdapterEvidenceBuilder.versionedArtifact(
    token: token,
    budget: ConfiguredAdapterEvidenceSessionBudget(
      configuration: budgetConfiguration,
      monotonicNow: { 1 }
    ),
    installRootPath: .known(RawPath(rootID: "other")),
    installRootIdentity: .known(rootIdentity),
    installRootAccessPolicy: .known(policy()),
    helperCapability: .known("helper-v1"),
    activeSelector: .known(selector),
    versions: [version],
    currentUpdateMarker: .known(false),
    coverage: .complete
  )
  #expect(misrouted.survivorRawNames.value == nil)

  let hintOnly = AdapterEvidenceBuilder.typeHintVersionedArtifact(
    installRootIdentity: .known(rootIdentity)
  )
  #expect(hintOnly.survivorRawNames.value == nil)
  #expect(hintOnly.coverage.completeness == .partial)
}

@Test func versionedArtifactDuplicateManifestNamesAndBudgetExhaustionStayUnknown() throws {
  let namespaceIdentity = ObjectIdentity(device: 7, fileID: 14, objectType: .directory)
  let token = try adapterToken(
    kind: .versionedArtifact,
    selectorNamespaceIdentity: namespaceIdentity,
    selectorNamespaceAccessPolicy: policy()
  )
  let selector = ActiveVersionSelectorEvidence(
    rawName: Data("current".utf8),
    selectorIdentity: ObjectIdentity(device: 7, fileID: 15, objectType: .symbolicLink),
    selectorAccessPolicy: policy(),
    namespaceIdentity: namespaceIdentity,
    namespaceAccessPolicy: policy(),
    rawTarget: Data("1".utf8)
  )
  let duplicate = VersionedArtifactVersionEvidence(
    rawName: Data("1".utf8),
    identity: .known(ObjectIdentity(device: 7, fileID: 16, objectType: .directory)),
    metadataDigest: .known(evidenceDigest(Data("manifest".utf8)))
  )
  let configuration = try ConfiguredAdapterEvidenceBudget(
    maximumScopes: 1,
    maximumEntriesPerScope: 4,
    maximumMetadataBytesPerEntry: 256,
    maximumAggregateMetadataBytes: 1_024,
    deadlineMonotonicNanoseconds: 100
  )
  let budget = ConfiguredAdapterEvidenceSessionBudget(
    configuration: configuration,
    monotonicNow: { 1 }
  )
  let evidence = AdapterEvidenceBuilder.versionedArtifact(
    token: token,
    budget: budget,
    installRootPath: .known(rootPath),
    installRootIdentity: .known(rootIdentity),
    installRootAccessPolicy: .known(policy()),
    helperCapability: .known("helper-v1"),
    activeSelector: .known(selector),
    versions: [duplicate, duplicate],
    currentUpdateMarker: .known(false),
    coverage: .complete
  )
  #expect(evidence.survivorRawNames.value == nil)
  #expect(evidence.coverage.completeness == .partial)

  let constrainedConfiguration = try ConfiguredAdapterEvidenceBudget(
    maximumScopes: 1,
    maximumEntriesPerScope: 1,
    maximumMetadataBytesPerEntry: 64,
    maximumAggregateMetadataBytes: 64,
    deadlineMonotonicNanoseconds: 100
  )
  let constrained = AdapterEvidenceBuilder.versionedArtifact(
    token: token,
    budget: ConfiguredAdapterEvidenceSessionBudget(
      configuration: constrainedConfiguration,
      monotonicNow: { 1 }
    ),
    installRootPath: .known(rootPath),
    installRootIdentity: .known(rootIdentity),
    installRootAccessPolicy: .known(policy()),
    helperCapability: .known("helper-v1"),
    activeSelector: .known(selector),
    versions: [duplicate],
    currentUpdateMarker: .known(false),
    coverage: .complete
  )
  #expect(constrained.versions.isEmpty)
  #expect(constrained.survivorRawNames.value == nil)
}
