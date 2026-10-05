import Darwin
import DiskplanPolicy
import DiskplanScan
import Foundation
import Testing

@testable import DiskplanEngineCore
@testable import DiskplanMacOS

private typealias ScanObjectIdentity = DiskplanScan.ObjectIdentity

@Test func freshInvariantCollectorProvesEnumeratedHardlinkSurvivorClosure() async throws {
  let fixture = try RuntimeFreshAuthorityFixture(hiddenOwnerOutsideRoot: false)
  defer { fixture.remove() }

  let capture = try await fixture.collect()
  #expect(capture.duplicateSurvivorsPreserved == .known(true))
  #expect(capture.terminalNamespacesExclusive == .known(true))
}

@Test func freshInvariantCollectorRejectsUnenumeratedHardlinkOwner() async throws {
  let fixture = try RuntimeFreshAuthorityFixture(hiddenOwnerOutsideRoot: true)
  defer { fixture.remove() }

  let capture = try await fixture.collect()
  #expect(capture.duplicateSurvivorsPreserved == .known(false))
}

@Test func freshInvariantMechanismProvesEnumeratedHardlinkSurvivorClosure() throws {
  let fixture = try FreshInvariantMechanismFixture()
  let fileIdentity = ScanObjectIdentity(device: 7, fileID: 30, objectType: .regular)
  fixture.addFile(["terminal", "owned"], identity: fileIdentity, linkCount: 2)
  fixture.addFile(["survivor"], identity: fileIdentity, linkCount: 2)

  let proof = fixture.accumulator.proof(snapshots: [])
  #expect(proof.duplicateSurvivorsPreserved == .known(true))
  #expect(proof.terminalNamespacesExclusive == .known(true))
}

@Test func freshInvariantMechanismRejectsUnenumeratedHardlinkOwner() throws {
  let fixture = try FreshInvariantMechanismFixture()
  fixture.addFile(
    ["terminal", "owned"],
    identity: ScanObjectIdentity(device: 7, fileID: 31, objectType: .regular),
    linkCount: 2
  )

  #expect(fixture.accumulator.proof(snapshots: []).duplicateSurvivorsPreserved == .known(false))
}

@Test func freshInvariantMechanismKeepsProviderUncertaintyUnknown() throws {
  let fixture = try FreshInvariantMechanismFixture()
  fixture.addFile(
    ["terminal", "owned"],
    identity: ScanObjectIdentity(device: 7, fileID: 32, objectType: .regular),
    linkCount: 1,
    providerBoundary: .unverified(reason: "test fixture does not establish host admission")
  )

  #expect(
    fixture.accumulator.proof(snapshots: []).duplicateSurvivorsPreserved
      == .unknown(.incompleteCoverage)
  )
}

private struct FreshInvariantMechanismFixture {
  let accumulator: RuntimeFreshInvariantAccumulator
  let rootIdentity = ScanObjectIdentity(device: 7, fileID: 10, objectType: .directory)
  let terminalIdentity = ScanObjectIdentity(device: 7, fileID: 11, objectType: .directory)

  init() throws {
    let rawRoot = try RawRootPath(absoluteBytes: Data("/mechanism-only-root".utf8))
    let targetPath = try RawTargetPath(components: [Data("terminal".utf8)])
    let binding = RuntimeFreshTerminalNamespace(rawRoot: rawRoot, targetPath: targetPath)
    let terminal = ResolvedRuntimeFreshTerminal(
      binding: binding,
      path: RawPath(
        rootID: "fixture-root",
        components: [RawPathComponent(Data("terminal".utf8))]
      )
    )
    accumulator = RuntimeFreshInvariantAccumulator(
      terminals: [terminal],
      allTerminalsResolved: true,
      maximumEntries: 32
    )
    accumulator.receive(.directoryClosed(node([], identity: rootIdentity)))
    accumulator.receive(.directoryClosed(node(["terminal"], identity: terminalIdentity)))
  }

  func addFile(
    _ components: [String],
    identity: ScanObjectIdentity,
    linkCount: UInt32,
    providerBoundary: ProviderBoundary = .localOrUnindicated
  ) {
    let topology = StorageTopologyEvidence(
      linkCount: .known(linkCount),
      mayShareBlocks: .known(false),
      sharesAllBlocks: .known(false),
      cloneID: .absent(reason: "not cloned"),
      cloneRefcount: .absent(reason: "not cloned"),
      conditionalGroupReclaim: .exact(0)
    )
    accumulator.receive(
      .observed(
        node(
          components,
          identity: identity,
          storageTopology: topology,
          providerBoundary: providerBoundary
        )
      )
    )
  }

  private func node(
    _ components: [String],
    identity: ScanObjectIdentity,
    storageTopology: StorageTopologyEvidence = .unknown,
    providerBoundary: ProviderBoundary = .localOrUnindicated
  ) -> ScannedNode {
    ScannedNode(
      path: RawPath(
        rootID: "fixture-root",
        components: components.map { RawPathComponent(Data($0.utf8)) }
      ),
      identity: .known(identity),
      bytes: ItemByteEvidence(
        logical: .exact(1),
        nominalAllocated: .exact(1),
        immediatePrivateReclaim: .exact(0)
      ),
      storageTopology: storageTopology,
      coverage: .complete,
      providerBoundary: providerBoundary
    )
  }
}

private struct RuntimeFreshAuthorityFixture {
  let root: URL
  let outsideRoot: URL?
  let session: RuntimeEvidenceSession
  let authority: RuntimeFreshPolicyAuthority

  init(hiddenOwnerOutsideRoot: Bool) throws {
    root = FileManager.default.temporaryDirectory.appendingPathComponent(
      "diskplan-runtime-invariant-\(UUID().uuidString)",
      isDirectory: true
    )
    try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
    let terminal = root.appendingPathComponent("terminal", isDirectory: true)
    try FileManager.default.createDirectory(at: terminal, withIntermediateDirectories: false)
    let owned = terminal.appendingPathComponent("owned")
    try Data("owner-closure".utf8).write(to: owned)

    if hiddenOwnerOutsideRoot {
      let outside = FileManager.default.temporaryDirectory.appendingPathComponent(
        "diskplan-runtime-invariant-outside-\(UUID().uuidString)",
        isDirectory: true
      )
      try FileManager.default.createDirectory(at: outside, withIntermediateDirectories: false)
      guard Darwin.link(owned.path, outside.appendingPathComponent("survivor").path) == 0 else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
      }
      outsideRoot = outside
    } else {
      guard Darwin.link(owned.path, root.appendingPathComponent("survivor").path) == 0 else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
      }
      outsideRoot = nil
    }

    let policy = try #require(
      MaterializationPolicyInstaller().installBeforePathAccess().value
    )
    session = RuntimeEvidenceSession(
      policy: policy,
      contentBudget: try ContentCollectionBudget(
        maximumBytesPerFile: 1024 * 1024,
        maximumAggregateBytes: 4 * 1024 * 1024,
        maximumFiles: 16,
        deadlineMonotonicNanoseconds: DispatchTime.now().uptimeNanoseconds
          + 10_000_000_000
      )
    )
    authority = RuntimeFreshPolicyAuthority(policy: policy)
  }

  func collect() async throws -> RuntimeFreshPolicyCapture {
    let lease = try session.beginCapture(.wholePlan)
    defer { lease.finish() }
    let rawRoot = try RawRootPath(absoluteBytes: Data(root.path.utf8))
    let capture = try await authority.collect(
      authorization: lease.authorization,
      request: RuntimeFreshPolicyRequest(
        roots: [
          ScanRootRequest(rootID: "fixture-root", rawAbsolutePath: rawRoot.absoluteBytes)
        ],
        terminalNamespaces: [
          RuntimeFreshTerminalNamespace(
            rawRoot: rawRoot,
            targetPath: try RawTargetPath(components: [Data("terminal".utf8)])
          )
        ]
      )
    )
    _ = try lease.collectPaths([])
    return capture
  }

  func remove() {
    try? FileManager.default.removeItem(at: root)
    if let outsideRoot { try? FileManager.default.removeItem(at: outsideRoot) }
  }
}
