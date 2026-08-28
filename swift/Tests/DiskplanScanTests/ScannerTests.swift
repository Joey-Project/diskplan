import Darwin
import DiskplanMacOS
import DiskplanScan
import Foundation
import Testing

private struct FakeNode: Sendable {
  let identity: ObjectIdentity
  let bytes: ItemByteEvidence
  let boundary: ProviderBoundary
  let children: [RawPathComponent]
  let openFailure: Observation<DirectoryHandle>?
  let enumerateFailure: Observation<[RawPathComponent]>?
  let providerEvidence: Observation<ProviderScanEvidence>

  init(
    identity: ObjectIdentity,
    bytes: ItemByteEvidence,
    boundary: ProviderBoundary,
    children: [RawPathComponent],
    openFailure: Observation<DirectoryHandle>?,
    enumerateFailure: Observation<[RawPathComponent]>?,
    providerEvidence: Observation<ProviderScanEvidence> = .unknown(reason: "not observed")
  ) {
    self.identity = identity
    self.bytes = bytes
    self.boundary = boundary
    self.children = children
    self.openFailure = openFailure
    self.enumerateFailure = enumerateFailure
    self.providerEvidence = providerEvidence
  }
}

private final class FakeFilesystem: ScanFilesystem, @unchecked Sendable {
  private let lock = NSLock()
  private let rootRequest: ScanRootRequest
  private let rootIdentity: ObjectIdentity
  private let nodes: [RawPath: FakeNode]
  private let rootChildren: [RawPathComponent]
  private var handles: [Int32: RawPath] = [:]
  private var nextHandle: Int32 = 10
  private(set) var openedPaths = 0
  private(set) var closedHandles = 0
  private(set) var enumerationCalls = 0

  init(rootID: String = "root", rootChildren: [RawPathComponent], nodes: [RawPath: FakeNode]) {
    rootRequest = ScanRootRequest(rootID: rootID, rawAbsolutePath: Data("/fixture".utf8))
    rootIdentity = ObjectIdentity(device: 1, fileID: 1, objectType: .directory)
    self.rootChildren = rootChildren
    self.nodes = nodes
  }

  var request: ScanRootRequest { rootRequest }

  func bindRoot(_ request: ScanRootRequest, resolverVersion: UInt32) -> Observation<BoundScanRoot> {
    guard request == rootRequest else { return .absent(reason: "unknown root") }
    let handle = allocate(RawPath(rootID: request.rootID))
    return .known(
      BoundScanRoot(
        binding: RootBinding(
          resolverVersion: resolverVersion,
          rootID: request.rootID,
          rawAbsolutePath: request.rawAbsolutePath,
          identity: rootIdentity
        ),
        directory: handle
      )
    )
  }

  func enumerate(_ directory: DirectoryHandle) -> Observation<[RawPathComponent]> {
    lock.withLock { enumerationCalls += 1 }
    guard let path = lock.withLock({ handles[directory.rawValue] }) else {
      return .failed(reason: "closed handle", errorCode: nil)
    }
    if path.components.isEmpty { return .known(rootChildren) }
    guard let node = nodes[path] else { return .absent(reason: "missing directory") }
    return node.enumerateFailure ?? .known(node.children)
  }

  func inspect(
    parent: DirectoryHandle,
    name: RawPathComponent,
    inheritedProviderBoundary: Bool
  ) -> Observation<InspectedObject> {
    guard let parentPath = lock.withLock({ handles[parent.rawValue] }) else {
      return .failed(reason: "closed parent", errorCode: nil)
    }
    let path = parentPath.appending(name)
    guard let node = nodes[path] else { return .absent(reason: "disappeared") }
    return .known(
      InspectedObject(
        identity: node.identity,
        bytes: node.bytes,
        providerBoundary: node.boundary,
        providerEvidence: node.providerEvidence
      )
    )
  }

  func openDirectory(
    parent: DirectoryHandle,
    name: RawPathComponent,
    expectedIdentity: ObjectIdentity
  ) -> Observation<DirectoryHandle> {
    guard let parentPath = lock.withLock({ handles[parent.rawValue] }) else {
      return .failed(reason: "closed parent", errorCode: nil)
    }
    let path = parentPath.appending(name)
    guard let node = nodes[path] else { return .absent(reason: "disappeared") }
    if let failure = node.openFailure { return failure }
    guard node.identity == expectedIdentity else {
      return .failed(reason: "identity changed", errorCode: ESTALE)
    }
    lock.withLock { openedPaths += 1 }
    return .known(allocate(path))
  }

  func close(_ directory: DirectoryHandle) {
    lock.withLock {
      if handles.removeValue(forKey: directory.rawValue) != nil { closedHandles += 1 }
    }
  }

  private func allocate(_ path: RawPath) -> DirectoryHandle {
    lock.withLock {
      defer { nextHandle += 1 }
      handles[nextHandle] = path
      return DirectoryHandle(rawValue: nextHandle)
    }
  }
}

private struct FixedClock: ScanClock {
  let times: [UInt64]
  private let index = LockedIndex()
  func wallClockNow() -> Date { Date(timeIntervalSince1970: 1_700_000_000) }
  func monotonicNowNanoseconds() -> UInt64 {
    index.next(times)
  }
}

private final class LockedIndex: @unchecked Sendable {
  private let lock = NSLock()
  private var value = 0
  func next(_ values: [UInt64]) -> UInt64 {
    lock.withLock {
      let result = values[min(value, values.count - 1)]
      value += 1
      return result
    }
  }
}

private final class CapturingSink: ScanNodeSink, @unchecked Sendable {
  private let lock = NSLock()
  private var stored: [ScanNodeEvent] = []
  func receive(_ event: ScanNodeEvent) { lock.withLock { stored.append(event) } }
  var events: [ScanNodeEvent] { lock.withLock { stored } }
}

private func component(_ string: String) -> RawPathComponent { RawPathComponent(Data(string.utf8)) }
private func rawComponent(_ bytes: [UInt8]) -> RawPathComponent { RawPathComponent(Data(bytes)) }
private func file(_ id: UInt64, bytes: UInt64, device: Int64 = 1) -> FakeNode {
  FakeNode(
    identity: ObjectIdentity(device: device, fileID: id, objectType: .regular),
    bytes: ItemByteEvidence(
      logical: .exact(bytes), nominalAllocated: .exact(bytes),
      immediatePrivateReclaim: .exact(bytes)
    ),
    boundary: .localOrUnindicated,
    children: [],
    openFailure: nil,
    enumerateFailure: nil
  )
}
private func directory(
  _ id: UInt64,
  children: [RawPathComponent],
  boundary: ProviderBoundary = .localOrUnindicated,
  openFailure: Observation<DirectoryHandle>? = nil,
  enumerateFailure: Observation<[RawPathComponent]>? = nil
) -> FakeNode {
  FakeNode(
    identity: ObjectIdentity(device: 1, fileID: id, objectType: .directory),
    bytes: ItemByteEvidence(
      logical: .exact(0), nominalAllocated: .exact(0), immediatePrivateReclaim: .exact(0)
    ),
    boundary: boundary,
    children: children,
    openFailure: openFailure,
    enumerateFailure: enumerateFailure
  )
}

private func run(_ filesystem: FakeFilesystem, budget: StructuralBudget? = nil) -> ScanResult {
  let scope = ResolvedScanScope(
    resolverVersion: 1,
    profile: .deep,
    roots: [filesystem.request],
    budget: budget
      ?? StructuralBudget(maximumEntriesPerRoot: 100, maximumDepth: 10, retainedNodeCount: 100),
    maximumDurationNanoseconds: nil
  )
  let scanner = DeterministicScanner(
    filesystem: filesystem, scope: scope, clock: FixedClock(times: [100]))
  while scanner.snapshot().state != .complete && scanner.snapshot().state != .partial {
    _ = scanner.advance(maximumEntries: 2)
  }
  return scanner.snapshot()
}

@Test func invalidUTF8NamesRemainRawAndDeterministicallySorted() {
  let invalid = rawComponent([0xff, 0x61])
  let ascii = component("a")
  let root = RawPath(rootID: "root")
  let fs = FakeFilesystem(
    rootChildren: [invalid, ascii],
    nodes: [root.appending(invalid): file(2, bytes: 2), root.appending(ascii): file(3, bytes: 3)]
  )
  let result = run(fs)
  #expect(
    result.progress.retainedNodes.map(\.path) == [root.appending(ascii), root.appending(invalid)])
  #expect(invalid.displayName == "\\xff\\x61")
}

@Test func enumerationPermutationDoesNotChangeResult() {
  let a = component("a")
  let b = component("b")
  let root = RawPath(rootID: "root")
  let nodes = [root.appending(a): file(2, bytes: 7), root.appending(b): file(3, bytes: 7)]
  let lhs = run(FakeFilesystem(rootChildren: [b, a], nodes: nodes))
  let rhs = run(FakeFilesystem(rootChildren: [a, b], nodes: nodes))
  #expect(lhs.progress.retainedNodes == rhs.progress.retainedNodes)
  #expect(lhs.roots == rhs.roots)
}

@Test func missingMismatchAndUnreadableRemainDistinct() {
  let missing = component("missing")
  let mismatch = component("mismatch")
  let denied = component("denied")
  let root = RawPath(rootID: "root")
  let fs = FakeFilesystem(
    rootChildren: [missing, mismatch, denied],
    nodes: [
      root.appending(mismatch): directory(
        3, children: [], openFailure: .failed(reason: "replaced", errorCode: ESTALE)
      ),
      root.appending(denied): directory(
        4, children: [], openFailure: .unreadable(reason: "denied", errorCode: EACCES)
      ),
    ]
  )
  let result = run(fs)
  #expect(result.coverage.reasons.contains(.missing))
  #expect(result.coverage.reasons.contains(.identityMismatch))
  #expect(result.coverage.reasons.contains(.permissionDenied))
}

@Test func accessPolicyMutationIsNotCollapsedIntoIdentityMismatch() {
  let changed = component("changed")
  let root = RawPath(rootID: "root")
  let fs = FakeFilesystem(
    rootChildren: [changed],
    nodes: [
      root.appending(changed): directory(
        2,
        children: [],
        openFailure: .failed(reason: "access policy changed", errorCode: EAGAIN)
      )
    ]
  )
  let result = run(fs)
  #expect(result.coverage.reasons.contains(.accessPolicyChanged))
  #expect(!result.coverage.reasons.contains(.identityMismatch))
}

@Test func budgetCreatesExplicitPartialCoverage() {
  let names = [component("a"), component("b"), component("c")]
  let root = RawPath(rootID: "root")
  let nodes = Dictionary(
    uniqueKeysWithValues: names.enumerated().map {
      (root.appending($0.element), file(UInt64($0.offset + 2), bytes: 1))
    })
  let result = run(
    FakeFilesystem(rootChildren: names, nodes: nodes),
    budget: StructuralBudget(maximumEntriesPerRoot: 2, maximumDepth: 10)
  )
  #expect(result.state == .partial)
  #expect(result.roots[0].coverage.completeness == .partial)
  #expect(result.roots[0].coverage.reasons == [.budgetExhausted])
  #expect(result.progress.entriesObserved == 2)
}

@Test func openDirectoryEvidenceRemainsIncompleteUntilClosed() {
  let directoryName = component("dir")
  let childName = component("child")
  let root = RawPath(rootID: "root")
  let directoryPath = root.appending(directoryName)
  let fs = FakeFilesystem(
    rootChildren: [directoryName],
    nodes: [
      directoryPath: directory(2, children: [childName]),
      directoryPath.appending(childName): file(3, bytes: 1),
    ]
  )
  let scope = ResolvedScanScope(
    resolverVersion: 1,
    profile: .deep,
    roots: [fs.request],
    budget: StructuralBudget(maximumEntriesPerRoot: 10, maximumDepth: 2),
    maximumDurationNanoseconds: nil
  )
  let scanner = DeterministicScanner(
    filesystem: fs, scope: scope, clock: FixedClock(times: [100]))
  let inProgress = scanner.advance(maximumEntries: 1)
  #expect(inProgress.progress.retainedNodes.first?.coverage.reasons == [.subtreeIncomplete])
  let partial = scanner.finalizePartial()
  #expect(partial.state == .partial)
  #expect(partial.coverage.reasons.contains(.userFinalizedPartial))
}

@Test func providerBoundaryIsMetadataOnlyAndNeverOpened() {
  let provider = component("provider")
  let child = component("cloud")
  let root = RawPath(rootID: "root")
  let fs = FakeFilesystem(
    rootChildren: [provider],
    nodes: [
      root.appending(provider): directory(
        2, children: [child], boundary: .rejected(reason: "dataless")
      ),
      root.appending(provider).appending(child): file(3, bytes: 100),
    ]
  )
  let result = run(fs)
  #expect(fs.openedPaths == 0)
  #expect(result.coverage.reasons.contains(.providerMetadataOnly))
  #expect(result.progress.entriesObserved == 1)
}

@Test func materializedProviderBoundaryDescendsMetadataOnlyAndRemainsPartial() {
  let provider = component("provider")
  let child = component("cloud")
  let root = RawPath(rootID: "root")
  let fs = FakeFilesystem(
    rootChildren: [provider],
    nodes: [
      root.appending(provider): directory(
        2, children: [child], boundary: .metadataOnly(reason: "sync root")
      ),
      root.appending(provider).appending(child): file(3, bytes: 100),
    ]
  )
  let result = run(fs)
  #expect(fs.openedPaths == 1)
  #expect(result.state == .partial)
  #expect(result.coverage.reasons.contains(.providerMetadataOnly))
  #expect(result.progress.entriesObserved == 2)
}

@Test func providerEvidencePropagatesThroughObservedAndClosedEvents() {
  let provider = component("provider")
  let root = RawPath(rootID: "root")
  let evidence = ProviderScanEvidence(
    identity: .known(
      ProviderObjectIdentity(itemIdentifier: "fixture-item", domainIdentifier: "fixture-domain")),
    promisedMetadata: .known(["is_directory": "true"]),
    hiddenBackingBytes: .unknown(reason: "public API unavailable"),
    controlledNonMaterializationAcceptance: .known(true)
  )
  let node = FakeNode(
    identity: ObjectIdentity(device: 1, fileID: 2, objectType: .directory),
    bytes: .unknown,
    boundary: .metadataOnly(reason: "sync root"),
    children: [],
    openFailure: nil,
    enumerateFailure: nil,
    providerEvidence: .known(evidence)
  )
  let fs = FakeFilesystem(rootChildren: [provider], nodes: [root.appending(provider): node])
  let scope = ResolvedScanScope(
    resolverVersion: 1,
    profile: .deep,
    roots: [fs.request],
    budget: StructuralBudget(maximumEntriesPerRoot: 10, maximumDepth: 2),
    maximumDurationNanoseconds: nil
  )
  let sink = CapturingSink()
  let scanner = DeterministicScanner(
    filesystem: fs, scope: scope, clock: FixedClock(times: [100]), nodeSink: sink)
  _ = scanner.advance(maximumEntries: 10)
  let providerEvidence = sink.events.compactMap { event -> Observation<ProviderScanEvidence>? in
    switch event {
    case .observed(let node), .directoryClosed(let node): node.providerEvidence
    }
  }
  #expect(providerEvidence == [.known(evidence), .known(evidence)])
}

@Test func symlinkAndMountBoundaryAreNotTraversed() {
  let link = component("link")
  let mount = component("mount")
  let root = RawPath(rootID: "root")
  let fs = FakeFilesystem(
    rootChildren: [link, mount],
    nodes: [
      root.appending(link): FakeNode(
        identity: ObjectIdentity(device: 1, fileID: 2, objectType: .symbolicLink),
        bytes: .unknown,
        boundary: .localOrUnindicated,
        children: [], openFailure: nil, enumerateFailure: nil
      ),
      root.appending(mount): FakeNode(
        identity: ObjectIdentity(device: 2, fileID: 3, objectType: .directory),
        bytes: .unknown,
        boundary: .localOrUnindicated,
        children: [], openFailure: nil, enumerateFailure: nil
      ),
    ]
  )
  let result = run(fs)
  #expect(fs.openedPaths == 0)
  #expect(result.coverage.reasons.contains(.mountBoundary))
}

@Test func topKUsesPrivateLowerBoundThenRawPath() {
  let names = [component("c"), component("a"), component("b")]
  let root = RawPath(rootID: "root")
  let fs = FakeFilesystem(
    rootChildren: names,
    nodes: [
      root.appending(names[0]): file(2, bytes: 10),
      root.appending(names[1]): file(3, bytes: 20),
      root.appending(names[2]): file(4, bytes: 20),
    ]
  )
  let result = run(
    fs,
    budget: StructuralBudget(maximumEntriesPerRoot: 100, maximumDepth: 10, retainedNodeCount: 2)
  )
  #expect(
    result.progress.retainedNodes.map(\.path) == [
      root.appending(component("a")), root.appending(component("b")),
    ])
}

@Test func closedDirectoryAggregationCountsEachObjectOnce() {
  let directoryName = component("dir")
  let fileName = component("file")
  let root = RawPath(rootID: "root")
  let directoryPath = root.appending(directoryName)
  let fs = FakeFilesystem(
    rootChildren: [directoryName],
    nodes: [
      directoryPath: directory(2, children: [fileName]),
      directoryPath.appending(fileName): file(3, bytes: 10),
    ]
  )
  let result = run(fs)
  #expect(result.roots[0].aggregateBytes.immediatePrivateReclaim.conservativeLowerBound == 10)
  #expect(result.progress.retainedNodes.map(\.path).filter { $0 == directoryPath }.count == 1)
}

@Test func boundedRetentionDoesNotDropStreamingEvidence() {
  let names = [component("a"), component("b"), component("c")]
  let root = RawPath(rootID: "root")
  let fs = FakeFilesystem(
    rootChildren: names,
    nodes: Dictionary(
      uniqueKeysWithValues: names.enumerated().map {
        (root.appending($0.element), file(UInt64($0.offset + 2), bytes: UInt64($0.offset + 1)))
      })
  )
  let scope = ResolvedScanScope(
    resolverVersion: 1,
    profile: .deep,
    roots: [fs.request],
    budget: StructuralBudget(maximumEntriesPerRoot: 10, maximumDepth: 1, retainedNodeCount: 1),
    maximumDurationNanoseconds: nil
  )
  let sink = CapturingSink()
  let scanner = DeterministicScanner(
    filesystem: fs, scope: scope, clock: FixedClock(times: [100]), nodeSink: sink)
  _ = scanner.advance(maximumEntries: 10)
  #expect(scanner.snapshot().progress.retainedNodes.count == 1)
  #expect(sink.events.count == 3)
}

@Test func timeBoundedScanIsNeverComplete() {
  let name = component("a")
  let root = RawPath(rootID: "root")
  let fs = FakeFilesystem(rootChildren: [name], nodes: [root.appending(name): file(2, bytes: 1)])
  let scope = ResolvedScanScope(
    resolverVersion: 1,
    profile: .deep,
    roots: [fs.request],
    budget: StructuralBudget(maximumEntriesPerRoot: 10, maximumDepth: 1),
    maximumDurationNanoseconds: 5
  )
  let scanner = DeterministicScanner(
    filesystem: fs, scope: scope, clock: FixedClock(times: [100, 106]))
  let result = scanner.advance(maximumEntries: 10)
  #expect(result.state == .partial)
  #expect(result.coverage.reasons.contains(.timedOut))
}

@Test func pauseProvisionalResumeTranscriptIsMonotonic() async {
  let name = component("a")
  let root = RawPath(rootID: "root")
  let fs = FakeFilesystem(rootChildren: [name], nodes: [root.appending(name): file(2, bytes: 1)])
  let scope = ResolvedScanScope(
    resolverVersion: 1, profile: .deep, roots: [fs.request],
    budget: StructuralBudget(maximumEntriesPerRoot: 10, maximumDepth: 1),
    maximumDurationNanoseconds: nil
  )
  let session = ScanSession(
    scanner: DeterministicScanner(filesystem: fs, scope: scope, clock: FixedClock(times: [100])))
  _ = await session.start()
  _ = await session.pause()
  _ = await session.provisional()
  _ = await session.resume()
  let done = await session.advance(maximumEntries: 10)
  #expect(
    done.transcript.map(\.kind) == [
      .started, .paused, .provisionalBuilt, .resumed, .advanced, .completed,
    ])
  #expect(done.transcript.map(\.sequence) == [1, 2, 3, 4, 5, 6])
}

@Test func finalizeAndCancelProduceDistinctTerminalTranscripts() async {
  let child = component("child")
  let root = RawPath(rootID: "root")
  let partialFS = FakeFilesystem(
    rootChildren: [child], nodes: [root.appending(child): file(2, bytes: 1)])
  let scope = ResolvedScanScope(
    resolverVersion: 1,
    profile: .deep,
    roots: [partialFS.request],
    budget: StructuralBudget(maximumEntriesPerRoot: 10, maximumDepth: 1),
    maximumDurationNanoseconds: nil
  )
  let partialSession = ScanSession(
    scanner: DeterministicScanner(
      filesystem: partialFS, scope: scope, clock: FixedClock(times: [100])))
  _ = await partialSession.start()
  let partial = await partialSession.finalizePartial()
  #expect(partial.transcript.map(\.kind) == [.started, .finalizedPartial])
  #expect(partial.result.coverage.reasons.contains(.userFinalizedPartial))

  let cancelFS = FakeFilesystem(
    rootChildren: [child], nodes: [root.appending(child): file(2, bytes: 1)])
  let cancelScope = ResolvedScanScope(
    resolverVersion: 1,
    profile: .deep,
    roots: [cancelFS.request],
    budget: StructuralBudget(maximumEntriesPerRoot: 10, maximumDepth: 1),
    maximumDurationNanoseconds: nil
  )
  let cancelSession = ScanSession(
    scanner: DeterministicScanner(
      filesystem: cancelFS, scope: cancelScope, clock: FixedClock(times: [100])))
  _ = await cancelSession.start()
  let cancelled = await cancelSession.cancel()
  #expect(cancelled.transcript.map(\.kind) == [.started, .cancelled])
  #expect(cancelled.result.state == .cancelled)
  #expect(cancelled.result.coverage.reasons.contains(.cancelled))
}

@Test func fakeTraversalDoesNotConstructOrOpenChildPaths() {
  let fileName = component("file")
  let root = RawPath(rootID: "root")
  let fs = FakeFilesystem(
    rootChildren: [fileName], nodes: [root.appending(fileName): file(2, bytes: 1)])
  _ = run(fs)
  #expect(fs.openedPaths == 0)
  #expect(fs.closedHandles == 1)
}

@Test func lsofParserIsTypedAndCanonical() {
  let bytes = Data("p20\0czed\0f5\0n/tmp/z\0\np10\0calpha\0fcwd\0n/tmp/a\0\n".utf8)
  let parsed = LsofFieldParser.parse(bytes)
  #expect(parsed.value?.map(\.processID) == [10, 20])
  #expect(parsed.value?.map(\.rawPath) == [Data("/tmp/a".utf8), Data("/tmp/z".utf8)])
}

@Test func profileResolverIsVersionedAndContainsNoProviderNameRules() {
  let home = ScanRootRequest(rootID: "home", rawAbsolutePath: Data("/Users/test".utf8))
  let scope = ScanRootResolver().resolve(
    profile: .standard,
    environment: ScanEnvironment(homeRoot: home)
  )
  #expect(scope.resolverVersion == 1)
  #expect(scope.roots == [home])
  #expect(scope.budget.maximumEntriesPerRoot == 2_000_000)
}

@Test func quickProfileBindsAdapterRootsWithoutGenericTraversal() {
  let child = component("child")
  let root = RawPath(rootID: "root")
  let fs = FakeFilesystem(rootChildren: [child], nodes: [root.appending(child): file(2, bytes: 1)])
  let scope = ScanRootResolver().resolve(
    profile: .quick,
    environment: ScanEnvironment(adapterRoots: [fs.request])
  )
  let scanner = DeterministicScanner(
    filesystem: fs, scope: scope, clock: FixedClock(times: [100]))
  let result = scanner.advance(maximumEntries: 1)
  #expect(result.state == .partial)
  #expect(fs.enumerationCalls == 0)
  #expect(result.roots[0].coverage.reasons == [.notRequestedByProfile])
}

@Test func darwinWalkerUsesDescriptorRelativeInspectionForAControlledRoot() throws {
  let installed = MaterializationPolicyInstaller().installBeforePathAccess()
  let policy = try #require(installed.value)
  let rootURL = FileManager.default.temporaryDirectory
    .appendingPathComponent("diskplan-scan-test-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: rootURL) }
  let rootFD = rootURL.withUnsafeFileSystemRepresentation {
    open($0!, O_RDONLY | O_DIRECTORY | O_CLOEXEC)
  }
  #expect(rootFD >= 0)
  defer { if rootFD >= 0 { close(rootFD) } }
  let rawName = Data("child".utf8)
  var terminated = Array(rawName) + [0]
  let childFD = terminated.withUnsafeMutableBytes { raw in
    openat(
      rootFD,
      raw.bindMemory(to: CChar.self).baseAddress!,
      O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
      mode_t(S_IRUSR | S_IWUSR)
    )
  }
  #expect(childFD >= 0)
  if childFD >= 0 { close(childFD) }
  let rawRoot = rootURL.withUnsafeFileSystemRepresentation {
    Data(bytes: $0!, count: strlen($0!))
  }
  let request = ScanRootRequest(rootID: "darwin", rawAbsolutePath: rawRoot)
  let scope = ResolvedScanScope(
    resolverVersion: 1,
    profile: .deep,
    roots: [request],
    budget: StructuralBudget(maximumEntriesPerRoot: 10, maximumDepth: 2, retainedNodeCount: 10),
    maximumDurationNanoseconds: nil
  )
  let scanner = DeterministicScanner(
    filesystem: DarwinScanFilesystem(policy: policy),
    scope: scope,
    clock: FixedClock(times: [100])
  )
  let result = scanner.advance(maximumEntries: 10)
  #expect(result.rootFailures.isEmpty)
  #expect(result.progress.entriesObserved == 1)
  #expect(result.progress.retainedNodes.first?.path.components == [RawPathComponent(rawName)])
}
