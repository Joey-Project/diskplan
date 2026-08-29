import CryptoKit
import Darwin
import Foundation
import Testing

@testable import DiskplanMacOS
@testable import DiskplanScan

@Test func runtimeEvidenceCaptureIDsAreUniqueAndLifecycleBound() throws {
  let session = try runtimeEvidenceSession()
  let forbidden = Data(repeating: 0x71, count: 32)
  let first = try session.beginCapture(.wholePlan, excluding: [forbidden])

  #expect(first.captureID.bytes != forbidden)
  #expect(throws: RuntimeEvidenceSessionError.captureAlreadyActive) {
    try session.beginCapture(.jitUnit)
  }
  #expect(!session.advanceEpoch())

  first.finish()
  #expect(session.advanceEpoch())
  let second = try session.beginCapture(.jitUnit, excluding: [first.captureID.bytes])
  #expect(second.captureID != first.captureID)
  second.finish()

  session.close()
  #expect(throws: RuntimeEvidenceSessionError.closed) {
    try session.beginCapture(.finalDescriptor)
  }
}

@Test func retiredRuntimeEvidenceLeaseCannotBeReplayed() throws {
  let session = try runtimeEvidenceSession()
  let lease = try session.beginCapture(.wholePlan)
  lease.finish()

  #expect(throws: RuntimeEvidenceSessionError.closed) {
    try lease.collectPaths([])
  }
}

@Test func transferredRegularDescriptorCollectsGenerationAccessAndSizeBoundDigest() throws {
  let parent = FileManager.default.temporaryDirectory.appendingPathComponent(
    "diskplan-runtime-evidence-\(UUID().uuidString)",
    isDirectory: true
  )
  try FileManager.default.createDirectory(at: parent, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: parent) }
  let target = parent.appendingPathComponent("target")
  let bytes = Data("descriptor-bound-content".utf8)
  try bytes.write(to: target)

  let rootDescriptor = Darwin.open(parent.path, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
  let targetDescriptor = Darwin.open(target.path, O_RDONLY | O_NOFOLLOW | O_CLOEXEC)
  #expect(rootDescriptor >= 0)
  #expect(targetDescriptor >= 0)
  guard rootDescriptor >= 0, targetDescriptor >= 0 else {
    if rootDescriptor >= 0 { Darwin.close(rootDescriptor) }
    if targetDescriptor >= 0 { Darwin.close(targetDescriptor) }
    return
  }

  let session = try runtimeEvidenceSession()
  let lease = try session.beginCapture(.finalDescriptor)
  let evidence = try lease.collectTransferredDescriptors(
    RuntimeTransferredDescriptorRequest(
      rootID: "test-root",
      targetComponents: [Data("target".utf8)],
      rootDescriptor: rootDescriptor,
      parentDescriptors: [],
      targetDescriptor: targetDescriptor,
      requiresContent: true
    ))
  lease.finish()

  guard case .known(let identity) = evidence.target.identity else {
    Issue.record("target identity must be descriptor-bound")
    return
  }
  #expect(identity.objectType == .regular)
  #expect(identity.generation.value != nil)
  #expect(evidence.target.accessPolicy.value?.aclDigest.value != nil)
  #expect(evidence.target.mountDevice == .known(identity.device))
  guard case .collected(let content) = evidence.target.content else {
    Issue.record("regular target content must be collected")
    return
  }
  #expect(content.logicalBytes == UInt64(bytes.count))
  #expect(content.digest.bytes == Data(SHA256.hash(data: bytes)))
}

private func runtimeEvidenceSession() throws -> RuntimeEvidenceSession {
  let policy = try #require(
    MaterializationPolicyInstaller().installBeforePathAccess().value)
  return RuntimeEvidenceSession(
    policy: policy,
    contentBudget: try ContentCollectionBudget(
      maximumBytesPerFile: 1024 * 1024,
      maximumAggregateBytes: 4 * 1024 * 1024,
      maximumFiles: 16,
      deadlineMonotonicNanoseconds: DispatchTime.now().uptimeNanoseconds + 10_000_000_000
    ),
    providerReader: { _, _, _ in .known(.localOrUnindicated) }
  )
}
