import Darwin
import DiskplanMacOS
import Foundation
import Testing

@testable import DiskplanScan

@Test
func freshScanReceiptBindsConcreteRootIdentityAndConsumesOnce() async throws {
  let session = try runtimeFreshSession()
  let lease = try session.beginCapture(.wholePlan)
  let descriptor = try openSystemRoot()

  let receipt = try await lease.collectFreshScan(
    systemRootFreshRequest(descriptor: descriptor)
  )
  let payload = try lease.consumeFreshScanReceipt(
    receipt,
    expectedKind: .wholePlan,
    expectedRoots: [systemRootRequest],
    expectedVolumes: [],
    expectedCaptureID: lease.captureID
  )

  #expect(payload.captureID == lease.captureID)
  #expect(payload.kind == .wholePlan)
  #expect(payload.rootBindingDigest == receipt.rootBindingDigest)
  #expect(payload.volumeBindingDigest == receipt.volumeBindingDigest)
  #expect(payload.rootBindingValidation == .known(true))
  #expect(
    payload.volumeBindingValidation
      == .absent(reason: "fresh scan request declared no volume scope")
  )
  #expect(
    payload.scanResult.globalFacts.apfsSnapshots
      == .unavailable(reason: "no bound volume scope was collected")
  )
  #expect(payload.scanResult.state == .partial)
  guard case .known(let events) = payload.events else {
    Issue.record("expected a complete Scan-owned event corpus")
    return
  }
  #expect(events.isEmpty)
  #expect(throws: RuntimeFreshScanError.receiptConsumed) {
    try lease.consumeFreshScanReceipt(
      receipt,
      expectedKind: .wholePlan,
      expectedRoots: [systemRootRequest],
      expectedVolumes: [],
      expectedCaptureID: lease.captureID
    )
  }
  lease.finish()
}

@Test(arguments: [ReceiptMismatchKind.kind, .root, .capture, .lease])
func receiptMismatchFailsClosedAndDrainsReceipt(mismatch: ReceiptMismatchKind) async throws {
  let session = try runtimeFreshSession()
  let lease = try session.beginCapture(.wholePlan)
  let receipt = try await lease.collectFreshScan(
    systemRootFreshRequest(descriptor: try openSystemRoot())
  )
  let otherSession = try runtimeFreshSession()
  let otherLease = try otherSession.beginCapture(.wholePlan)
  defer {
    lease.finish()
    otherLease.finish()
  }

  let consumingLease = mismatch == .lease ? otherLease : lease
  let expectedKind: RuntimeEvidenceCaptureKind = mismatch == .kind ? .jitUnit : .wholePlan
  let expectedRoots =
    mismatch == .root
    ? [ScanRootRequest(rootID: "system-root", rawAbsolutePath: Data("/private".utf8))]
    : [systemRootRequest]
  let expectedCaptureID = mismatch == .capture ? otherLease.captureID : lease.captureID

  #expect(throws: RuntimeFreshScanError.receiptBindingMismatch) {
    try consumingLease.consumeFreshScanReceipt(
      receipt,
      expectedKind: expectedKind,
      expectedRoots: expectedRoots,
      expectedVolumes: [],
      expectedCaptureID: expectedCaptureID
    )
  }
  #expect(throws: RuntimeFreshScanError.receiptConsumed) {
    try lease.consumeFreshScanReceipt(
      receipt,
      expectedKind: .wholePlan,
      expectedRoots: [systemRootRequest],
      expectedVolumes: [],
      expectedCaptureID: lease.captureID
    )
  }
}

@Test
func concurrentReceiptConsumersProduceExactlyOnePayload() async throws {
  let session = try runtimeFreshSession()
  let lease = try session.beginCapture(.jitUnit)
  defer { lease.finish() }
  let receipt = try await lease.collectFreshScan(
    systemRootFreshRequest(descriptor: try openSystemRoot())
  )

  let successes = await withTaskGroup(of: Bool.self, returning: Int.self) { group in
    for _ in 0..<8 {
      group.addTask {
        (try? lease.consumeFreshScanReceipt(
          receipt,
          expectedKind: .jitUnit,
          expectedRoots: [systemRootRequest],
          expectedVolumes: [],
          expectedCaptureID: lease.captureID
        )) != nil
      }
    }
    var successes = 0
    for await success in group where success { successes += 1 }
    return successes
  }
  #expect(successes == 1)
}

@Test
func cancellationBeforePublicationRetiresCaptureAndPublishesNoReceipt() async throws {
  let fixture = try RuntimeFreshRootFixture()
  defer { fixture.remove() }
  let gate = RuntimeFreshCollectorGate()
  let ownership = DescriptorOwnershipRecorder()
  let session = try runtimeFreshSession(
    activity: BlockingActivityCollector(gate: gate),
    transferredDescriptorObserver: ownership.record
  )
  let lease = try session.beginCapture(.wholePlan)
  defer { lease.finish() }
  let descriptor = try fixture.openRoot()
  let request = runtimeFreshRequest(fixture: fixture, descriptor: descriptor)

  let collection = Task { try await lease.collectFreshScan(request) }
  await gate.waitUntilEntered()
  collection.cancel()
  await gate.release()
  do {
    _ = try await collection.value
    Issue.record("cancelled fresh scan unexpectedly published a receipt")
  } catch is CancellationError {
    // Expected cancellation classification.
  }
  #expect(ownership.descriptors == [descriptor])
  await #expect(throws: RuntimeFreshScanError.captureRetired) {
    try await lease.collectFreshScan(
      runtimeFreshRequest(fixture: fixture, descriptor: try fixture.openRoot())
    )
  }
}

@Test
func sessionCloseCancelsCollectionAndUsesABoundedDrain() async throws {
  let gate = RuntimeFreshCollectorGate()
  let session = try runtimeFreshSession(activity: BlockingActivityCollector(gate: gate))
  let lease = try session.beginCapture(.wholePlan)
  let collection = Task {
    try await lease.collectFreshScan(
      systemRootFreshRequest(descriptor: try openSystemRoot())
    )
  }
  await gate.waitUntilEntered()

  let started = DispatchTime.now().uptimeNanoseconds
  session.close()
  let elapsed = DispatchTime.now().uptimeNanoseconds - started
  #expect(elapsed < 1_000_000_000)

  await gate.release()
  do {
    _ = try await collection.value
    Issue.record("collection published after its session was closed")
  } catch is CancellationError {
    // The Scan-owned task observed the session cancellation after the blocking collector returned.
  } catch {
    Issue.record("session cancellation lost its typed classification: \(error)")
  }
  #expect(throws: RuntimeFreshScanError.closed) {
    try session.beginCapture(.wholePlan)
  }
  lease.finish()
}

@Test
func rootPathReplacementCannotRelabelAnotherDirectoryAsTheBoundRoot() async throws {
  let bound = try RuntimeFreshRootFixture()
  defer { bound.remove() }
  let session = try runtimeFreshSession()
  let lease = try session.beginCapture(.wholePlan)
  defer { lease.finish() }
  let request = RuntimeFreshScanRequest(
    roots: [
      RuntimeFreshRootDescriptor(
        rootID: bound.rootID,
        rawAbsolutePath: systemRootRequest.rawAbsolutePath,
        fileDescriptor: try bound.openRoot()
      )
    ],
    maximumDurationNanoseconds: nil,
    processDeadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 1_000_000_000
  )
  let receipt = try await lease.collectFreshScan(request)
  let payload = try lease.consumeFreshScanReceipt(
    receipt,
    expectedKind: .wholePlan,
    expectedRoots: [
      ScanRootRequest(rootID: bound.rootID, rawAbsolutePath: systemRootRequest.rawAbsolutePath)
    ],
    expectedVolumes: [],
    expectedCaptureID: lease.captureID
  )

  guard case .failed(_, let code) = payload.rootBindingValidation else {
    Issue.record("descriptor/path root substitution was not rejected")
    return
  }
  #expect(code == ESTALE)
}

@Test
func deepFreshScanFinalizesAncestorCloseEpochsForTheFullEventCorpus() async throws {
  let session = try runtimeFreshSession(
    scanProfile: .deep,
    structuralBudget: StructuralBudget(
      maximumEntriesPerRoot: 64,
      maximumDepth: 1,
      retainedNodeCount: 1
    )
  )
  let lease = try session.beginCapture(.wholePlan)
  defer { lease.finish() }
  let receipt = try await lease.collectFreshScan(
    systemRootFreshRequest(descriptor: try openSystemRoot())
  )
  let payload = try lease.consumeFreshScanReceipt(
    receipt,
    expectedKind: .wholePlan,
    expectedRoots: [systemRootRequest],
    expectedVolumes: [],
    expectedCaptureID: lease.captureID
  )

  #expect(payload.scanResult.reference.profileID == ScanProfile.deep.rawValue)
  guard case .known(let events) = payload.events else {
    Issue.record("deep fresh scan did not publish a finalized event corpus")
    return
  }
  #expect(!events.isEmpty)
  #expect(events.count > payload.scanResult.progress.retainedNodes.count)
  var finalizedKnownAncestorCount = 0
  for event in events {
    let node: ScannedNode
    switch event {
    case .observed(let value), .directoryClosed(let value): node = value
    }
    if case .known(let seal) = node.ancestorAccessPolicy {
      finalizedKnownAncestorCount += 1
      #expect(seal.pendingCloseEpochIDs.isEmpty)
    }
  }
  #expect(finalizedKnownAncestorCount > 0)
}

@Test
func volumeDescriptorIsCopiedCloseOnExecAndInputOwnershipIsConsumed() async throws {
  let rootDescriptor = try openSystemRoot()
  let volumeDescriptor = try openSystemRoot()
  let ownership = DescriptorOwnershipRecorder()
  let lister = CLOEXECRecordingSnapshotLister()
  let session = try runtimeFreshSession(
    snapshotLister: lister,
    transferredDescriptorObserver: ownership.record
  )
  let lease = try session.beginCapture(.wholePlan)
  defer { lease.finish() }
  let request = RuntimeFreshScanRequest(
    roots: [
      RuntimeFreshRootDescriptor(
        rootID: systemRootRequest.rootID,
        rawAbsolutePath: systemRootRequest.rawAbsolutePath,
        fileDescriptor: rootDescriptor
      )
    ],
    volumes: [
      RuntimeFreshVolumeDescriptor(
        volumeID: "fixture-volume",
        rawAbsolutePath: systemRootRequest.rawAbsolutePath,
        fileDescriptor: volumeDescriptor
      )
    ],
    maximumDurationNanoseconds: nil,
    processDeadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 1_000_000_000
  )

  let receipt = try await lease.collectFreshScan(request)
  #expect(ownership.descriptors == [rootDescriptor, volumeDescriptor].sorted())
  #expect(lister.observedCloseOnExec)
  let payload = try lease.consumeFreshScanReceipt(
    receipt,
    expectedKind: .wholePlan,
    expectedRoots: [systemRootRequest],
    expectedVolumes: [systemVolumeScope],
    expectedCaptureID: lease.captureID
  )
  #expect(payload.volumeBindingDigest == receipt.volumeBindingDigest)
  #expect(payload.volumeBindingValidation == .known(true))
  #expect(payload.scanResult.globalFacts.apfsSnapshots == .known([]))
}

@Test
func volumeScopeMismatchFailsClosedAndDrainsReceipt() async throws {
  let session = try runtimeFreshSession()
  let lease = try session.beginCapture(.wholePlan)
  defer { lease.finish() }
  let receipt = try await lease.collectFreshScan(
    systemRootAndVolumeFreshRequest(
      rootDescriptor: try openSystemRoot(),
      volumeDescriptor: try openSystemRoot()
    )
  )

  #expect(throws: RuntimeFreshScanError.receiptBindingMismatch) {
    try lease.consumeFreshScanReceipt(
      receipt,
      expectedKind: .wholePlan,
      expectedRoots: [systemRootRequest],
      expectedVolumes: [
        RuntimeFreshVolumeScope(
          volumeID: systemVolumeScope.volumeID,
          rawAbsolutePath: Data("/private".utf8)
        )
      ],
      expectedCaptureID: lease.captureID
    )
  }
  #expect(throws: RuntimeFreshScanError.receiptConsumed) {
    try lease.consumeFreshScanReceipt(
      receipt,
      expectedKind: .wholePlan,
      expectedRoots: [systemRootRequest],
      expectedVolumes: [systemVolumeScope],
      expectedCaptureID: lease.captureID
    )
  }
}

@Test
func volumeDescriptorMustIdentifyItsCanonicalBoundRoot() async throws {
  let rootFixture = try RuntimeFreshRootFixture()
  defer { rootFixture.remove() }
  let session = try runtimeFreshSession()
  let lease = try session.beginCapture(.wholePlan)
  defer { lease.finish() }

  do {
    _ = try await lease.collectFreshScan(
      RuntimeFreshScanRequest(
        roots: [
          RuntimeFreshRootDescriptor(
            rootID: rootFixture.rootID,
            rawAbsolutePath: rootFixture.rawPath,
            fileDescriptor: try rootFixture.openRoot()
          )
        ],
        volumes: [
          RuntimeFreshVolumeDescriptor(
            volumeID: systemVolumeScope.volumeID,
            rawAbsolutePath: systemVolumeScope.rawAbsolutePath,
            fileDescriptor: try openSystemRoot()
          )
        ],
        maximumDurationNanoseconds: nil,
        processDeadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 1_000_000_000
      )
    )
    Issue.record("unrelated volume descriptor unexpectedly matched a bound root")
  } catch let RuntimeFreshScanError.descriptorFailure(scopeID, observation) {
    #expect(scopeID == systemVolumeScope.volumeID)
    guard case .failed(_, let code) = observation else {
      Issue.record("volume/root identity mismatch lost its typed classification")
      return
    }
    #expect(code == EXDEV)
  }
}

@Test
func volumeRevalidationClassifiesDescriptorReplacementAsIdentityChange() async throws {
  let replacement = try RuntimeFreshRootFixture()
  defer { replacement.remove() }
  let session = try runtimeFreshSession(
    snapshotLister: try IdentityReplacingSnapshotLister(replacement: replacement)
  )
  let lease = try session.beginCapture(.wholePlan)
  defer { lease.finish() }
  let receipt = try await lease.collectFreshScan(
    systemRootAndVolumeFreshRequest(
      rootDescriptor: try openSystemRoot(),
      volumeDescriptor: try openSystemRoot()
    )
  )
  let payload = try lease.consumeFreshScanReceipt(
    receipt,
    expectedKind: .wholePlan,
    expectedRoots: [systemRootRequest],
    expectedVolumes: [systemVolumeScope],
    expectedCaptureID: lease.captureID
  )

  guard case .failed(_, let code) = payload.volumeBindingValidation else {
    Issue.record("volume descriptor replacement was not rejected")
    return
  }
  #expect(code == ESTALE)
  guard
    case .failed(_, let snapshotCode) =
      payload.collectors.globalFacts.apfsSnapshotsByVolume[systemVolumeScope.volumeID]
  else {
    Issue.record("volume snapshot fact lost its identity-change classification")
    return
  }
  #expect(snapshotCode == ESTALE)
}

@Test
func invalidatedHeldVolumeDescriptorIsFailedNotAbsent() async throws {
  let session = try runtimeFreshSession(snapshotLister: try NonReadOnlySnapshotLister())
  let lease = try session.beginCapture(.wholePlan)
  defer { lease.finish() }
  let receipt = try await lease.collectFreshScan(
    systemRootAndVolumeFreshRequest(
      rootDescriptor: try openSystemRoot(),
      volumeDescriptor: try openSystemRoot()
    )
  )
  let payload = try lease.consumeFreshScanReceipt(
    receipt,
    expectedKind: .wholePlan,
    expectedRoots: [systemRootRequest],
    expectedVolumes: [systemVolumeScope],
    expectedCaptureID: lease.captureID
  )

  #expect(
    payload.volumeBindingValidation
      == .failed(
        reason: "fresh scan descriptor is not read-only", errorCode: EACCES)
  )
  #expect(
    payload.collectors.globalFacts.apfsSnapshotsByVolume[systemVolumeScope.volumeID]
      == .failed(
        reason: "fresh scan descriptor is not read-only", errorCode: EACCES)
  )
}

@Test
func descriptorOnlyFailuresNeverClaimAuthoritativeAbsence() {
  #expect(
    runtimeDescriptorFailure(EBADF, operation: "fixture")
      == .failed(reason: "fixture: held descriptor failure", errorCode: EBADF)
  )
  #expect(
    runtimeDescriptorFailure(ENOENT, operation: "fixture")
      == .failed(reason: "fixture: held descriptor failure", errorCode: ENOENT)
  )
}

@Test
func volumeSealValidationSeparatesIdentityFromAccessPolicy() throws {
  let aclDigest = try EvidenceDigest(bytes: Data(repeating: 0xA5, count: 32))
  let identity = ObjectIdentity(device: 7, fileID: 11, objectType: .directory)
  let initialAccess = AccessPolicyEvidence(
    ownerUserID: 501,
    ownerGroupID: 20,
    mode: 0o755,
    flags: 0,
    aclDigest: .known(aclDigest)
  )
  let changedAccess = AccessPolicyEvidence(
    ownerUserID: 501,
    ownerGroupID: 20,
    mode: 0o700,
    flags: 0,
    aclDigest: .known(aclDigest)
  )
  let initial = RuntimeFreshDescriptorSeal(identity: identity, accessPolicy: initialAccess)

  #expect(
    runtimeVolumeSealValidation(
      expected: initial,
      current: RuntimeFreshDescriptorSeal(identity: identity, accessPolicy: changedAccess)
    ) == .failed(reason: "fresh scan volume access policy changed", errorCode: EAGAIN)
  )
  #expect(
    runtimeVolumeSealValidation(
      expected: initial,
      current: RuntimeFreshDescriptorSeal(
        identity: ObjectIdentity(device: 7, fileID: 12, objectType: .directory),
        accessPolicy: changedAccess
      )
    ) == .failed(reason: "fresh scan volume descriptor identity changed", errorCode: ESTALE)
  )
}

@Test
func nonDirectoryRootDescriptorPreservesTypedFailureAndOwnership() async throws {
  let ownership = DescriptorOwnershipRecorder()
  let session = try runtimeFreshSession(transferredDescriptorObserver: ownership.record)
  let lease = try session.beginCapture(.wholePlan)
  defer { lease.finish() }
  let descriptor = Darwin.open("/dev/null", O_RDONLY | O_CLOEXEC)
  #expect(descriptor >= 0)
  guard descriptor >= 0 else { return }
  let request = RuntimeFreshScanRequest(
    roots: [
      RuntimeFreshRootDescriptor(
        rootID: "not-a-directory",
        rawAbsolutePath: Data("/dev".utf8),
        fileDescriptor: descriptor
      )
    ],
    maximumDurationNanoseconds: nil,
    processDeadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 1_000_000_000
  )

  do {
    _ = try await lease.collectFreshScan(request)
    Issue.record("non-directory root descriptor unexpectedly produced a receipt")
  } catch let RuntimeFreshScanError.descriptorFailure(scopeID, observation) {
    #expect(scopeID == "not-a-directory")
    #expect(
      observation
        == .failed(reason: "fresh scan root is not a directory", errorCode: ENOTDIR)
    )
  }
  #expect(ownership.descriptors == [descriptor])
}

enum ReceiptMismatchKind: CaseIterable, Sendable {
  case kind
  case root
  case capture
  case lease
}

private final class RuntimeFreshRootFixture: @unchecked Sendable {
  let url: URL
  let rootID = "fixture-root"

  init() throws {
    url = FileManager.default.temporaryDirectory.appendingPathComponent(
      "diskplan-runtime-fresh-scan-\(UUID().uuidString)",
      isDirectory: true
    )
    try FileManager.default.createDirectory(at: url, withIntermediateDirectories: false)
    try Data("fixture".utf8).write(to: url.appendingPathComponent("entry"))
  }

  var rawPath: Data { Data(url.path.utf8) }
  var rootRequest: ScanRootRequest {
    ScanRootRequest(rootID: rootID, rawAbsolutePath: rawPath)
  }
  var volumeScope: RuntimeFreshVolumeScope {
    RuntimeFreshVolumeScope(volumeID: "fixture-volume", rawAbsolutePath: rawPath)
  }

  func openRoot() throws -> Int32 {
    let descriptor = Darwin.open(url.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
    return descriptor
  }

  func remove() { try? FileManager.default.removeItem(at: url) }
}

private func runtimeFreshRequest(
  fixture: RuntimeFreshRootFixture,
  descriptor: Int32
) -> RuntimeFreshScanRequest {
  RuntimeFreshScanRequest(
    roots: [
      RuntimeFreshRootDescriptor(
        rootID: fixture.rootID,
        rawAbsolutePath: fixture.rawPath,
        fileDescriptor: descriptor
      )
    ],
    maximumDurationNanoseconds: nil,
    processDeadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 1_000_000_000
  )
}

private func runtimeFreshVolumeRequest(
  fixture: RuntimeFreshRootFixture,
  rootDescriptor: Int32,
  volumeDescriptor: Int32
) -> RuntimeFreshScanRequest {
  RuntimeFreshScanRequest(
    roots: [
      RuntimeFreshRootDescriptor(
        rootID: fixture.rootID,
        rawAbsolutePath: fixture.rawPath,
        fileDescriptor: rootDescriptor
      )
    ],
    volumes: [
      RuntimeFreshVolumeDescriptor(
        volumeID: fixture.volumeScope.volumeID,
        rawAbsolutePath: fixture.rawPath,
        fileDescriptor: volumeDescriptor
      )
    ],
    maximumDurationNanoseconds: nil,
    processDeadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 1_000_000_000
  )
}

private func runtimeFreshSession(
  activity: any ProcessActivityCollecting = FixedActivityCollector(),
  snapshotLister: any APFSSnapshotListing = FixedSnapshotLister(),
  scanProfile: ScanProfile = .quick,
  structuralBudget: StructuralBudget? = nil,
  transferredDescriptorObserver: @escaping @Sendable ([Int32]) -> Void = { _ in }
) throws -> RuntimeEvidenceSession {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  return RuntimeEvidenceSession(
    policy: policy,
    testingCollectorBundle: ProductionScanCollectorBundle(
      processActivity: activity,
      vm: FixedVMCollector(),
      swap: FixedSwapCollector(),
      snapshots: snapshotLister
    ),
    testingScanProfile: scanProfile,
    testingStructuralBudget: structuralBudget,
    testingTransferredDescriptorObserver: transferredDescriptorObserver
  )
}

private let systemRootRequest = ScanRootRequest(
  rootID: "system-root",
  rawAbsolutePath: Data("/".utf8)
)

private let systemVolumeScope = RuntimeFreshVolumeScope(
  volumeID: "fixture-volume",
  rawAbsolutePath: systemRootRequest.rawAbsolutePath
)

private func openSystemRoot() throws -> Int32 {
  let descriptor = Darwin.open("/", O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
  guard descriptor >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
  return descriptor
}

private func systemRootFreshRequest(descriptor: Int32) -> RuntimeFreshScanRequest {
  RuntimeFreshScanRequest(
    roots: [
      RuntimeFreshRootDescriptor(
        rootID: systemRootRequest.rootID,
        rawAbsolutePath: systemRootRequest.rawAbsolutePath,
        fileDescriptor: descriptor
      )
    ],
    maximumDurationNanoseconds: nil,
    processDeadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 1_000_000_000
  )
}

private func systemRootAndVolumeFreshRequest(
  rootDescriptor: Int32,
  volumeDescriptor: Int32
) -> RuntimeFreshScanRequest {
  RuntimeFreshScanRequest(
    roots: [
      RuntimeFreshRootDescriptor(
        rootID: systemRootRequest.rootID,
        rawAbsolutePath: systemRootRequest.rawAbsolutePath,
        fileDescriptor: rootDescriptor
      )
    ],
    volumes: [
      RuntimeFreshVolumeDescriptor(
        volumeID: systemVolumeScope.volumeID,
        rawAbsolutePath: systemVolumeScope.rawAbsolutePath,
        fileDescriptor: volumeDescriptor
      )
    ],
    maximumDurationNanoseconds: nil,
    processDeadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 1_000_000_000
  )
}

private struct FixedActivityCollector: ProcessActivityCollecting {
  func collect(deadlineNanoseconds: UInt64) async -> ProcessActivityObservation { .complete([]) }
}

private struct FixedVMCollector: VMGlobalFactCollecting {
  func collect() -> Observation<[String: UInt64]> { .known(["free_bytes": 1]) }
}

private struct FixedSwapCollector: SwapGlobalFactCollecting {
  func collect() -> Observation<[String: UInt64]> { .known(["used_bytes": 0]) }
}

private struct FixedSnapshotLister: APFSSnapshotListing {
  func list(volumeFileDescriptor: Int32, maximumEntries: Int) -> Observation<[Data]> {
    .known([])
  }
}

private final class CLOEXECRecordingSnapshotLister: APFSSnapshotListing, @unchecked Sendable {
  private let lock = NSLock()
  private var closeOnExecStorage = false

  var observedCloseOnExec: Bool { lock.withLock { closeOnExecStorage } }

  func list(volumeFileDescriptor: Int32, maximumEntries: Int) -> Observation<[Data]> {
    lock.withLock {
      let flags = Darwin.fcntl(volumeFileDescriptor, F_GETFD)
      closeOnExecStorage = flags >= 0 && flags & FD_CLOEXEC != 0
    }
    return .known([])
  }
}

private final class IdentityReplacingSnapshotLister: APFSSnapshotListing, @unchecked Sendable {
  private let replacementDescriptor: Int32

  init(replacement: RuntimeFreshRootFixture) throws {
    replacementDescriptor = try replacement.openRoot()
  }

  deinit { Darwin.close(replacementDescriptor) }

  func list(volumeFileDescriptor: Int32, maximumEntries: Int) -> Observation<[Data]> {
    guard Darwin.dup2(replacementDescriptor, volumeFileDescriptor) >= 0 else {
      return .failed(reason: "test identity replacement failed", errorCode: errno)
    }
    guard Darwin.fcntl(volumeFileDescriptor, F_SETFD, FD_CLOEXEC) >= 0 else {
      return .failed(reason: "test close-on-exec restoration failed", errorCode: errno)
    }
    return .known([])
  }
}

private final class NonReadOnlySnapshotLister: APFSSnapshotListing, @unchecked Sendable {
  private let writeDescriptor: Int32

  init() throws {
    var descriptors = [Int32](repeating: -1, count: 2)
    guard Darwin.pipe(&descriptors) == 0 else {
      throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO)
    }
    Darwin.close(descriptors[0])
    writeDescriptor = descriptors[1]
  }

  deinit { Darwin.close(writeDescriptor) }

  func list(volumeFileDescriptor: Int32, maximumEntries: Int) -> Observation<[Data]> {
    guard Darwin.dup2(writeDescriptor, volumeFileDescriptor) >= 0 else {
      return .failed(reason: "test descriptor replacement failed", errorCode: errno)
    }
    guard Darwin.fcntl(volumeFileDescriptor, F_SETFD, FD_CLOEXEC) >= 0 else {
      return .failed(reason: "test close-on-exec restoration failed", errorCode: errno)
    }
    return .known([])
  }
}

private final class DescriptorOwnershipRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var storage: [Int32] = []

  var descriptors: [Int32] { lock.withLock { storage } }
  func record(_ descriptors: [Int32]) { lock.withLock { storage = descriptors } }
}

private struct BlockingActivityCollector: ProcessActivityCollecting {
  let gate: RuntimeFreshCollectorGate

  func collect(deadlineNanoseconds: UInt64) async -> ProcessActivityObservation {
    await gate.block()
    return .complete([])
  }
}

private actor RuntimeFreshCollectorGate {
  private var entered = false
  private var released = false
  private var enteredWaiters: [CheckedContinuation<Void, Never>] = []
  private var releaseWaiters: [CheckedContinuation<Void, Never>] = []

  func block() async {
    entered = true
    let waiters = enteredWaiters
    enteredWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
    guard !released else { return }
    await withCheckedContinuation { releaseWaiters.append($0) }
  }

  func waitUntilEntered() async {
    guard !entered else { return }
    await withCheckedContinuation { enteredWaiters.append($0) }
  }

  func release() {
    released = true
    let waiters = releaseWaiters
    releaseWaiters.removeAll()
    for waiter in waiters { waiter.resume() }
  }
}
