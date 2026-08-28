import Darwin
import Foundation
import Testing

@testable import DiskplanMacOS
@testable import DiskplanScan

private struct FakeNode: Sendable {
  let identity: ObjectIdentity
  let bytes: ItemByteEvidence
  let boundary: ProviderBoundary
  let children: [RawPathComponent]
  let openFailure: Observation<BoundDirectory>?
  let enumerateFailure: Observation<DirectoryEnumeration>?
  let closeFailure: DirectoryCloseEvidence?
  let providerEvidence: Observation<ProviderScanEvidence>

  init(
    identity: ObjectIdentity,
    bytes: ItemByteEvidence,
    boundary: ProviderBoundary,
    children: [RawPathComponent],
    openFailure: Observation<BoundDirectory>?,
    enumerateFailure: Observation<DirectoryEnumeration>?,
    closeFailure: DirectoryCloseEvidence? = nil,
    providerEvidence: Observation<ProviderScanEvidence> = .unknown(reason: "not observed")
  ) {
    self.identity = identity
    self.bytes = bytes
    self.boundary = boundary
    self.children = children
    self.openFailure = openFailure
    self.enumerateFailure = enumerateFailure
    self.closeFailure = closeFailure
    self.providerEvidence = providerEvidence
  }
}

private final class FakeFilesystem: ScanFilesystem, @unchecked Sendable {
  private let lock = NSLock()
  private let rootRequest: ScanRootRequest
  private let rootIdentity: ObjectIdentity
  private let nodes: [RawPath: FakeNode]
  private let rootChildren: [RawPathComponent]
  private let rootCloseFailure: DirectoryCloseEvidence?
  private var handles: [Int32: RawPath] = [:]
  private var nextHandle: Int32 = 10
  private(set) var openedPaths = 0
  private(set) var closedHandles = 0
  private(set) var enumerationCalls = 0

  init(
    rootID: String = "root",
    rootChildren: [RawPathComponent],
    nodes: [RawPath: FakeNode],
    rootCloseFailure: DirectoryCloseEvidence? = nil
  ) {
    rootRequest = ScanRootRequest(rootID: rootID, rawAbsolutePath: Data("/fixture".utf8))
    rootIdentity = ObjectIdentity(device: 1, fileID: 1, objectType: .directory)
    self.rootChildren = rootChildren
    self.nodes = nodes
    self.rootCloseFailure = rootCloseFailure
  }

  var request: ScanRootRequest { rootRequest }

  func bindRoot(_ request: ScanRootRequest, resolverVersion: UInt32) -> Observation<BoundScanRoot> {
    guard request == rootRequest else { return .absent(reason: "unknown root") }
    let parent = allocate(RawPath(rootID: "\(request.rootID)-parent"))
    let handle = allocate(RawPath(rootID: request.rootID))
    return .known(
      BoundScanRoot(
        binding: RootBinding(
          resolverVersion: resolverVersion,
          rootID: request.rootID,
          rawAbsolutePath: request.rawAbsolutePath,
          identity: rootIdentity
        ),
        directory: BoundDirectory(
          handle: handle,
          slotBinding: DirectorySlotBinding(
            parent: parent,
            name: RawPathComponent(Data("fixture".utf8)),
            expectedIdentity: rootIdentity,
            expectedAccessPolicy: fakeAccessPolicy,
            ownsParent: true
          )
        ),
        accessPolicy: .known(fakeAccessPolicy)
      )
    )
  }

  func enumerate(
    _ directory: DirectoryHandle,
    limits: EnumerationLimits
  ) -> Observation<DirectoryEnumeration> {
    lock.withLock { enumerationCalls += 1 }
    guard let path = lock.withLock({ handles[directory.rawValue] }) else {
      return .failed(reason: "closed handle", errorCode: nil)
    }
    if path.components.isEmpty { return .known(boundedEnumeration(rootChildren, limits: limits)) }
    guard let node = nodes[path] else { return .absent(reason: "missing directory") }
    return node.enumerateFailure ?? .known(boundedEnumeration(node.children, limits: limits))
  }

  func inspect(
    parent: DirectoryHandle,
    name: RawPathComponent,
    inheritedProviderBoundary: Bool,
    requiresAuthoritativeProviderEvidence: Bool
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
        accessPolicy: .known(fakeAccessPolicy),
        providerBoundary: node.boundary,
        providerEvidence: node.providerEvidence
      )
    )
  }

  func openDirectory(
    parent: DirectoryHandle,
    name: RawPathComponent,
    expectedIdentity: ObjectIdentity,
    expectedAccessPolicy: AccessPolicyEvidence
  ) -> Observation<BoundDirectory> {
    guard let parentPath = lock.withLock({ handles[parent.rawValue] }) else {
      return .failed(reason: "closed parent", errorCode: nil)
    }
    let path = parentPath.appending(name)
    guard let node = nodes[path] else { return .absent(reason: "disappeared") }
    if let failure = node.openFailure { return failure }
    guard node.identity == expectedIdentity else {
      return .failed(reason: "identity changed", errorCode: ESTALE)
    }
    guard expectedAccessPolicy == fakeAccessPolicy else {
      return .failed(reason: "access policy changed", errorCode: EAGAIN)
    }
    lock.withLock { openedPaths += 1 }
    return .known(
      BoundDirectory(
        handle: allocate(path),
        slotBinding: DirectorySlotBinding(
          parent: parent,
          name: name,
          expectedIdentity: expectedIdentity,
          expectedAccessPolicy: expectedAccessPolicy,
          ownsParent: false
        )
      )
    )
  }

  func close(_ directory: BoundDirectory) -> DirectoryCloseEvidence {
    let path = lock.withLock { handles[directory.handle.rawValue] }
    lock.withLock {
      if handles.removeValue(forKey: directory.handle.rawValue) != nil { closedHandles += 1 }
      if case .parentSlot(let parent, _, let ownsParent) = directory.slotBinding.namespace,
        ownsParent,
        handles.removeValue(forKey: parent.rawValue) != nil
      {
        closedHandles += 1
      }
    }
    if path?.components.isEmpty == true, let rootCloseFailure { return rootCloseFailure }
    if let path, let failure = nodes[path]?.closeFailure { return failure }
    return DirectoryCloseEvidence(
      identity: .known(directory.slotBinding.expectedIdentity),
      accessPolicy: .known(directory.slotBinding.expectedAccessPolicy)
    )
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

private final class LockedPolicyGate: @unchecked Sendable {
  private let lock = NSLock()
  private let policy: NoMaterializationPolicy
  private let failingCall: Int?
  private var calls = 0

  init(policy: NoMaterializationPolicy, failingCall: Int? = nil) {
    self.policy = policy
    self.failingCall = failingCall
  }

  func validate() -> Capability<NoMaterializationPolicy> {
    lock.withLock {
      calls += 1
      if calls == failingCall {
        return Capability(
          status: .inconsistent,
          detail: "injected live policy drift"
        )
      }
      return .known(policy)
    }
  }

  var callCount: Int { lock.withLock { calls } }
}

private final class LockedRootOpener: @unchecked Sendable {
  private let lock = NSLock()
  private let openBody: @Sendable (Data) -> Int32
  private var calls = 0
  private var policyWasValidated = false

  init(
    policyGate: LockedPolicyGate? = nil,
    openBody: @escaping @Sendable (Data) -> Int32 = openDirectoryForTest
  ) {
    self.openBody = openBody
    self.policyGate = policyGate
  }

  private let policyGate: LockedPolicyGate?

  func open(_ path: Data) -> Int32 {
    lock.withLock {
      calls += 1
      if let policyGate { policyWasValidated = policyGate.callCount > 0 }
    }
    return openBody(path)
  }

  var callCount: Int { lock.withLock { calls } }
  var observedValidatedPolicy: Bool { lock.withLock { policyWasValidated } }
}

private func openDirectoryForTest(_ rawPath: Data) -> Int32 {
  var terminated = Array(rawPath) + [0]
  return terminated.withUnsafeMutableBytes { raw in
    open(
      raw.bindMemory(to: CChar.self).baseAddress!,
      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
    )
  }
}

private func accessPolicyForTest(_ fileDescriptor: Int32) -> AccessPolicyEvidence? {
  var value = stat()
  guard fstat(fileDescriptor, &value) == 0 else { return nil }
  return AccessPolicyEvidence(
    ownerUserID: value.st_uid,
    ownerGroupID: value.st_gid,
    mode: UInt32(value.st_mode),
    flags: value.st_flags
  )
}

private final class LockedItemEvidenceSequence: @unchecked Sendable {
  private let lock = NSLock()
  private let values: [ItemStorageEvidence]
  private var index = 0

  init(_ values: [ItemStorageEvidence]) { self.values = values }

  func read() -> Capability<ItemStorageEvidence> {
    lock.withLock {
      let value = values[min(index, values.count - 1)]
      index += 1
      return .known(value)
    }
  }
}

private final class LockedProviderOutcome: @unchecked Sendable {
  private let lock = NSLock()
  private let outcome: FileProviderProbeOutcome
  private var calls = 0

  init(_ outcome: FileProviderProbeOutcome) { self.outcome = outcome }

  func probe() -> FileProviderProbeOutcome {
    lock.withLock {
      calls += 1
      return outcome
    }
  }

  var callCount: Int { lock.withLock { calls } }
}

private final class CapturingSink: ScanNodeSink, @unchecked Sendable {
  private let lock = NSLock()
  private var stored: [ScanNodeEvent] = []
  func receive(_ event: ScanNodeEvent) { lock.withLock { stored.append(event) } }
  var events: [ScanNodeEvent] { lock.withLock { stored } }
}

private func component(_ string: String) -> RawPathComponent { RawPathComponent(Data(string.utf8)) }
private func rawComponent(_ bytes: [UInt8]) -> RawPathComponent { RawPathComponent(Data(bytes)) }
private func renameSlot(
  parentFD: Int32,
  from: Data,
  to: Data
) -> Int32 {
  var fromBytes = Array(from) + [0]
  var toBytes = Array(to) + [0]
  return fromBytes.withUnsafeMutableBytes { fromRaw in
    toBytes.withUnsafeMutableBytes { toRaw in
      renameat(
        parentFD,
        fromRaw.bindMemory(to: CChar.self).baseAddress!,
        parentFD,
        toRaw.bindMemory(to: CChar.self).baseAddress!
      )
    }
  }
}

private func openDirectorySlot(parentFD: Int32, name: Data) -> Int32 {
  var bytes = Array(name) + [0]
  return bytes.withUnsafeMutableBytes { raw in
    openat(
      parentFD,
      raw.bindMemory(to: CChar.self).baseAddress!,
      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
    )
  }
}

private func openReplacementThenRestore(
  parentFD: Int32,
  slotName: Data,
  replacementName: Data,
  parkedName: Data
) -> Int32 {
  guard renameSlot(parentFD: parentFD, from: slotName, to: parkedName) == 0 else {
    return -1
  }
  guard renameSlot(parentFD: parentFD, from: replacementName, to: slotName) == 0 else {
    let code = errno
    _ = renameSlot(parentFD: parentFD, from: parkedName, to: slotName)
    errno = code
    return -1
  }
  let replacementFD = openDirectorySlot(parentFD: parentFD, name: slotName)
  let openCode = errno
  guard renameSlot(parentFD: parentFD, from: slotName, to: replacementName) == 0 else {
    let code = errno
    if replacementFD >= 0 { close(replacementFD) }
    errno = code
    return -1
  }
  guard renameSlot(parentFD: parentFD, from: parkedName, to: slotName) == 0 else {
    let code = errno
    if replacementFD >= 0 { close(replacementFD) }
    errno = code
    return -1
  }
  errno = openCode
  return replacementFD
}

private let fakeAccessPolicy = AccessPolicyEvidence(
  ownerUserID: 501,
  ownerGroupID: 20,
  mode: UInt32(S_IFDIR | S_IRWXU),
  flags: 0
)

private func replacingItemEvidence(
  _ item: ItemStorageEvidence,
  device: Capability<Int64>? = nil,
  objectType: Capability<FileSystemObjectType>? = nil,
  fileID: Capability<UInt64>? = nil,
  logicalBytes: Capability<UInt64>? = nil,
  sharing: SharingEvidence? = nil,
  isDataless: Capability<Bool>? = nil,
  isSyncRoot: Capability<Bool>? = nil
) -> ItemStorageEvidence {
  ItemStorageEvidence(
    returnedAttributes: item.returnedAttributes,
    device: device ?? item.device,
    objectType: objectType ?? item.objectType,
    fileID: fileID ?? item.fileID,
    linkCount: item.linkCount,
    logicalBytes: logicalBytes ?? item.logicalBytes,
    nominalAllocatedBytes: item.nominalAllocatedBytes,
    immediatePrivateReclaimBytes: item.immediatePrivateReclaimBytes,
    sharing: sharing ?? item.sharing,
    vfsFlags: item.vfsFlags,
    isDataless: isDataless ?? item.isDataless,
    isSyncRoot: isSyncRoot ?? item.isSyncRoot,
    providerHiddenFootprint: item.providerHiddenFootprint,
    snapshotAttributedBytes: item.snapshotAttributedBytes
  )
}

private func confirmedProviderEvidence() -> FileProviderProbeOutcome {
  .evidence(
    FileProviderEvidence(
      identity: .known(
        ProviderIdentity(itemIdentifier: "fixture-item", domainIdentifier: "fixture-domain")
      ),
      identityDisposition: .confirmedProvider,
      providerCapabilities: .unavailable("fixture"),
      promisedMetadata: .unavailable("fixture"),
      traversal: .descendMetadataOnlyProviderBoundary,
      handling: .reportOnly,
      hiddenBackingBytes: .unavailable("fixture"),
      controlledNonMaterializationAcceptance: .unavailable("fixture")
    )
  )
}

private func fixtureItemEvidence() -> ItemStorageEvidence {
  ItemStorageEvidence(
    returnedAttributes: ReturnedAttributeMasks(
      common: 0,
      volume: 0,
      directory: 0,
      file: 0,
      extended: 0
    ),
    device: .known(1),
    objectType: .known(.directory),
    fileID: .known(1),
    linkCount: .known(1),
    logicalBytes: .known(1),
    nominalAllocatedBytes: .known(1),
    immediatePrivateReclaimBytes: .known(1),
    sharing: SharingEvidence(
      mayShareBlocks: .known(false),
      sharesAllBlocks: .known(false),
      cloneID: .known(0),
      cloneRefcount: .known(1),
      conditionalGroupReclaimBytes: .unavailable("fixture")
    ),
    vfsFlags: .known(0),
    isDataless: .known(false),
    isSyncRoot: .known(false),
    providerHiddenFootprint: .unavailable("fixture"),
    snapshotAttributedBytes: .unavailable("fixture")
  )
}

private func boundedEnumeration(
  _ names: [RawPathComponent],
  limits: EnumerationLimits
) -> DirectoryEnumeration {
  var accumulator = BoundedRawNameAccumulator(limits: limits)
  for name in names { accumulator.insert(name) }
  return accumulator.result()
}

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
  device: Int64 = 1,
  boundary: ProviderBoundary = .localOrUnindicated,
  openFailure: Observation<BoundDirectory>? = nil,
  enumerateFailure: Observation<DirectoryEnumeration>? = nil,
  closeFailure: DirectoryCloseEvidence? = nil
) -> FakeNode {
  FakeNode(
    identity: ObjectIdentity(device: device, fileID: id, objectType: .directory),
    bytes: ItemByteEvidence(
      logical: .exact(0), nominalAllocated: .exact(0), immediatePrivateReclaim: .exact(0)
    ),
    boundary: boundary,
    children: children,
    openFailure: openFailure,
    enumerateFailure: enumerateFailure,
    closeFailure: closeFailure
  )
}

private func run(_ filesystem: FakeFilesystem, budget: StructuralBudget? = nil) -> ScanResult {
  let scope = try! ResolvedScanScope(
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
  let scope = try! ResolvedScanScope(
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

@Test func rejectedProviderBoundaryIsUnverifiedAndNeverOpened() {
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
  #expect(result.coverage.reasons.contains(.providerStateUnverified))
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
  let scope = try! ResolvedScanScope(
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
  let scope = try! ResolvedScanScope(
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
  let scope = try! ResolvedScanScope(
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
  let scope = try! ResolvedScanScope(
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

@Test func provisionalCoverageIncludesActiveFrontierAndUnstartedRoots() async {
  let directoryName = component("directory")
  let fileName = component("file")
  let root = RawPath(rootID: "root")
  let directoryPath = root.appending(directoryName)
  let filesystem = FakeFilesystem(
    rootChildren: [directoryName],
    nodes: [
      directoryPath: directory(2, children: [fileName]),
      directoryPath.appending(fileName): file(3, bytes: 1),
    ]
  )
  let unstarted = ScanRootRequest(
    rootID: "unstarted",
    rawAbsolutePath: Data("/unstarted".utf8)
  )
  let scope = try! ResolvedScanScope(
    resolverVersion: 1,
    profile: .deep,
    roots: [filesystem.request, unstarted],
    budget: StructuralBudget(maximumEntriesPerRoot: 10, maximumDepth: 2),
    maximumDurationNanoseconds: nil
  )
  let session = ScanSession(
    scanner: DeterministicScanner(
      filesystem: filesystem,
      scope: scope,
      clock: FixedClock(times: [100])
    )
  )
  _ = await session.start()
  _ = await session.advance(maximumEntries: 1)
  _ = await session.pause()
  let provisional = await session.provisional()
  #expect(provisional.result.coverage.completeness == .partial)
  #expect(provisional.result.coverage.reasons.contains(.subtreeIncomplete))
  #expect(provisional.result.progress.rootsPartial == 2)
  #expect(
    provisional.result.progress.retainedNodes.first(where: { $0.path == directoryPath })?
      .coverage.reasons.contains(.subtreeIncomplete) == true
  )
  _ = await session.cancel()
}

@Test func finalizeAndCancelProduceDistinctTerminalTranscripts() async {
  let child = component("child")
  let root = RawPath(rootID: "root")
  let partialFS = FakeFilesystem(
    rootChildren: [child], nodes: [root.appending(child): file(2, bytes: 1)])
  let scope = try! ResolvedScanScope(
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
  let cancelScope = try! ResolvedScanScope(
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

@Test func cancelPreservesProviderMountAndActiveFrontierCoverage() {
  let provider = component("provider")
  let providerRoot = RawPath(rootID: "root")
  let providerFS = FakeFilesystem(
    rootChildren: [provider],
    nodes: [
      providerRoot.appending(provider): directory(
        2,
        children: [],
        boundary: .metadataOnly(reason: "sync root")
      )
    ]
  )
  let providerScope = try! ResolvedScanScope(
    resolverVersion: 1,
    profile: .deep,
    roots: [providerFS.request],
    budget: StructuralBudget(maximumEntriesPerRoot: 10, maximumDepth: 2),
    maximumDurationNanoseconds: nil
  )
  let providerScanner = DeterministicScanner(
    filesystem: providerFS,
    scope: providerScope,
    clock: FixedClock(times: [100])
  )
  _ = providerScanner.advance(maximumEntries: 1)
  let providerCancelled = providerScanner.cancel()
  #expect(providerCancelled.coverage.reasons.contains(.providerMetadataOnly))
  #expect(providerCancelled.coverage.reasons.contains(.subtreeIncomplete))

  let mount = component("mount")
  let mountRoot = RawPath(rootID: "root")
  let mountFS = FakeFilesystem(
    rootChildren: [mount],
    nodes: [mountRoot.appending(mount): directory(3, children: [], device: 2)]
  )
  let mountScope = try! ResolvedScanScope(
    resolverVersion: 1,
    profile: .deep,
    roots: [mountFS.request],
    budget: StructuralBudget(maximumEntriesPerRoot: 10, maximumDepth: 2),
    maximumDurationNanoseconds: nil
  )
  let mountScanner = DeterministicScanner(
    filesystem: mountFS,
    scope: mountScope,
    clock: FixedClock(times: [100])
  )
  _ = mountScanner.advance(maximumEntries: 1)
  let mountCancelled = mountScanner.cancel()
  #expect(mountCancelled.coverage.reasons.contains(.mountBoundary))
  #expect(mountCancelled.coverage.reasons.contains(.subtreeIncomplete))
}

@Test func fakeTraversalDoesNotConstructOrOpenChildPaths() {
  let fileName = component("file")
  let root = RawPath(rootID: "root")
  let fs = FakeFilesystem(
    rootChildren: [fileName], nodes: [root.appending(fileName): file(2, bytes: 1)])
  _ = run(fs)
  #expect(fs.openedPaths == 0)
  #expect(fs.closedHandles == 2)
}

@Test func lsofParserIsTypedAndCanonical() {
  let bytes = Data("p20\0czed\0f5\0n/tmp/z\0\np10\0calpha\0fcwd\0n/tmp/a\0\n".utf8)
  let parsed = LsofFieldParser.parse(bytes)
  #expect(parsed.value?.map(\.processID) == [10, 20])
  #expect(parsed.value?.map(\.rawPath) == [Data("/tmp/a".utf8), Data("/tmp/z".utf8)])
}

@Test func profileResolverIsVersionedAndContainsNoProviderNameRules() {
  let home = ScanRootRequest(rootID: "home", rawAbsolutePath: Data("/Users/test".utf8))
  let scope = try! ScanRootResolver().resolve(
    profile: .standard,
    environment: ScanEnvironment(homeRoot: home)
  )
  #expect(scope.resolverVersion == 1)
  #expect(scope.roots == [home])
  #expect(scope.budget.maximumEntriesPerRoot == 2_000_000)
}

@Test func fullAuditResolverPreservesCanonicalFilesystemRootsAndDistinctRootIDs() throws {
  let later = ScanRootRequest(rootID: "volume-z", rawAbsolutePath: Data("/".utf8))
  let earlier = ScanRootRequest(rootID: "volume-a", rawAbsolutePath: Data("/".utf8))
  let scope = try ScanRootResolver().resolve(
    profile: .fullAudit,
    environment: ScanEnvironment(visibleLocalWritableVolumes: [later, earlier])
  )
  #expect(scope.roots == [earlier, later])
  #expect(scope.budget.maximumEntriesPerRoot == 100_000_000)
  #expect(scope.budget.maximumDepth == 128)
}

@Test func canonicalFilesystemRootBindsAfterPolicyValidationAndClosesStable() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let policyGate = LockedPolicyGate(policy: policy)
  let opener = LockedRootOpener(policyGate: policyGate)
  let filesystem = DarwinScanFilesystem(
    policy: policy,
    pathAccessValidator: { policyGate.validate() },
    rootDirectoryOpener: { opener.open($0) }
  )
  let request = ScanRootRequest(rootID: "system-root", rawAbsolutePath: Data("/".utf8))
  let root = try #require(filesystem.bindRoot(request, resolverVersion: 1).value)
  #expect(policyGate.callCount >= 1)
  #expect(opener.callCount == 1)
  #expect(opener.observedValidatedPolicy)
  #expect(root.binding.rawAbsolutePath == Data("/".utf8))
  #expect(root.binding.identity.objectType == .directory)
  #expect(root.directory.slotBinding.namespace == .canonicalFilesystemRoot)
  #expect(root.providerBoundary == .localOrUnindicated)
  let closeEvidence = filesystem.close(root.directory)
  #expect(closeEvidence.identity.value == root.binding.identity)
  #expect(closeEvidence.accessPolicy.value == root.accessPolicy.value)
}

@Test func canonicalFilesystemRootIsNotTouchedWhenLivePolicyValidationFails() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let policyGate = LockedPolicyGate(policy: policy, failingCall: 1)
  let opener = LockedRootOpener(openBody: { _ in
    errno = EIO
    return -1
  })
  let filesystem = DarwinScanFilesystem(
    policy: policy,
    pathAccessValidator: { policyGate.validate() },
    rootDirectoryOpener: { opener.open($0) }
  )
  let result = filesystem.bindRoot(
    ScanRootRequest(rootID: "blocked-root", rawAbsolutePath: Data("/".utf8)),
    resolverVersion: 1
  )
  #expect(result.value == nil)
  #expect(policyGate.callCount == 1)
  #expect(opener.callCount == 0)
}

@Test func malformedAndAliasRootPathsFailBeforePolicyOrFilesystemTouch() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let policyGate = LockedPolicyGate(policy: policy)
  let opener = LockedRootOpener(openBody: { _ in
    errno = EIO
    return -1
  })
  let filesystem = DarwinScanFilesystem(
    policy: policy,
    pathAccessValidator: { policyGate.validate() },
    rootDirectoryOpener: { opener.open($0) }
  )
  let invalidPaths = [
    Data(), Data("relative".utf8), Data("//".utf8), Data("/tmp/".utf8),
    Data("/tmp//child".utf8), Data("/tmp/./child".utf8), Data("/tmp/../child".utf8),
    Data([UInt8(ascii: "/"), 0]),
  ]
  for (index, path) in invalidPaths.enumerated() {
    let result = filesystem.bindRoot(
      ScanRootRequest(rootID: "invalid-\(index)", rawAbsolutePath: path),
      resolverVersion: 1
    )
    guard case .failed(_, let code) = result else {
      Issue.record("malformed root path was accepted")
      continue
    }
    #expect(code == EINVAL)
  }
  #expect(policyGate.callCount == 0)
  #expect(opener.callCount == 0)
}

@Test func canonicalFilesystemRootRefusesIdentityAndAccessPolicyChangesAtClose() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let rootURL = FileManager.default.temporaryDirectory
    .appendingPathComponent("diskplan-direct-root-close-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: rootURL) }

  func openBoundDirectory() throws -> (Int32, ObjectIdentity, AccessPolicyEvidence) {
    let fd = rootURL.withUnsafeFileSystemRepresentation {
      open($0!, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    let opened = try #require(fd >= 0 ? fd : nil)
    let identity = try #require(
      FileDescriptorIdentityProbe().probe(fileDescriptor: opened, policy: policy).value
    )
    let accessPolicy = try #require(accessPolicyForTest(opened))
    return (
      opened,
      ObjectIdentity(
        device: identity.device,
        fileID: identity.fileID,
        objectType: .directory
      ),
      accessPolicy
    )
  }

  let filesystem = DarwinScanFilesystem(policy: policy)
  let (replacementFD, actualIdentity, accessPolicy) = try openBoundDirectory()
  let mismatched = BoundDirectory(
    handle: DirectoryHandle(rawValue: replacementFD),
    slotBinding: DirectorySlotBinding(
      canonicalFilesystemRootIdentity: ObjectIdentity(
        device: actualIdentity.device,
        fileID: actualIdentity.fileID &+ 1,
        objectType: actualIdentity.objectType
      ),
      expectedAccessPolicy: accessPolicy
    )
  )
  let replacementEvidence = filesystem.close(mismatched)
  guard case .failed(_, let replacementCode) = replacementEvidence.identity else {
    Issue.record("canonical root identity mismatch was accepted")
    return
  }
  #expect(replacementCode == ESTALE)

  let (policyFD, stableIdentity, originalPolicy) = try openBoundDirectory()
  #expect(fchmod(policyFD, mode_t(S_IRUSR | S_IXUSR)) == 0)
  let changedPolicy = BoundDirectory(
    handle: DirectoryHandle(rawValue: policyFD),
    slotBinding: DirectorySlotBinding(
      canonicalFilesystemRootIdentity: stableIdentity,
      expectedAccessPolicy: originalPolicy
    )
  )
  let policyEvidence = filesystem.close(changedPolicy)
  #expect(policyEvidence.identity.value == stableIdentity)
  guard case .failed(_, let policyCode) = policyEvidence.accessPolicy else {
    Issue.record("canonical root access-policy mutation was accepted")
    return
  }
  #expect(policyCode == EAGAIN)
}

@Test func duplicateRootIDsAreRejectedBeforeScopeFreeze() {
  let first = ScanRootRequest(rootID: "duplicate", rawAbsolutePath: Data("/first".utf8))
  let second = ScanRootRequest(rootID: "duplicate", rawAbsolutePath: Data("/second".utf8))
  #expect(throws: ScanScopeValidationError.duplicateRootID("duplicate")) {
    try ResolvedScanScope(
      resolverVersion: 1,
      profile: .deep,
      roots: [first, second],
      budget: StructuralBudget(maximumEntriesPerRoot: 1, maximumDepth: 1),
      maximumDurationNanoseconds: nil
    )
  }
  #expect(throws: ScanScopeValidationError.duplicateRootID("duplicate")) {
    try ScanRootResolver().resolve(
      profile: .deep,
      environment: ScanEnvironment(),
      explicitRoots: [first, second]
    )
  }
}

@Test func enumerationBudgetRetainsCanonicalNamesAcrossPermutations() {
  let names = [component("z"), component("b"), component("a")]
  let root = RawPath(rootID: "root")
  let nodes = Dictionary(
    uniqueKeysWithValues: names.enumerated().map {
      (root.appending($0.element), file(UInt64($0.offset + 2), bytes: 1))
    }
  )
  let budget = StructuralBudget(
    maximumEntriesPerRoot: 10,
    maximumDepth: 1,
    maximumEntriesPerDirectory: 2,
    maximumPendingNameBytes: 2
  )
  let lhs = run(FakeFilesystem(rootChildren: names, nodes: nodes), budget: budget)
  let rhs = run(FakeFilesystem(rootChildren: names.reversed(), nodes: nodes), budget: budget)
  #expect(lhs.progress.retainedNodes.map(\.path) == rhs.progress.retainedNodes.map(\.path))
  #expect(
    lhs.progress.retainedNodes.map(\.path) == [
      root.appending(component("a")), root.appending(component("b")),
    ]
  )
  #expect(lhs.coverage.reasons.contains(.budgetExhausted))
  #expect(lhs.progress.entriesObserved == 2)
}

@Test func closeRevalidationKeepsMissingMismatchUnreadableAndPolicyChangeDistinct() {
  let child = component("child")
  let root = RawPath(rootID: "root")
  let identity = ObjectIdentity(device: 1, fileID: 2, objectType: .directory)
  let cases: [(DirectoryCloseEvidence, CoverageReason)] = [
    (
      DirectoryCloseEvidence(
        identity: .absent(reason: "removed before close"),
        accessPolicy: .absent(reason: "removed before close")
      ),
      .missing
    ),
    (
      DirectoryCloseEvidence(
        identity: .failed(reason: "replaced before close", errorCode: ESTALE),
        accessPolicy: .unknown(reason: "replacement policy is not comparable")
      ),
      .identityMismatch
    ),
    (
      DirectoryCloseEvidence(
        identity: .unreadable(reason: "denied before close", errorCode: EACCES),
        accessPolicy: .unreadable(reason: "denied before close", errorCode: EACCES)
      ),
      .permissionDenied
    ),
    (
      DirectoryCloseEvidence(
        identity: .known(identity),
        accessPolicy: .failed(reason: "policy changed before close", errorCode: EAGAIN)
      ),
      .accessPolicyChanged
    ),
  ]
  for (failure, reason) in cases {
    let fs = FakeFilesystem(
      rootChildren: [child],
      nodes: [root.appending(child): directory(2, children: [], closeFailure: failure)]
    )
    let result = run(fs)
    #expect(result.coverage.reasons.contains(reason))
  }
}

@Test func scanReferenceBindsFullScopeBudgetsAndCollectorConfiguration() {
  let fs = FakeFilesystem(rootChildren: [], nodes: [:])
  let unstarted = ScanRootRequest(
    rootID: "unstarted",
    rawAbsolutePath: Data("/never-started".utf8)
  )
  let budget = StructuralBudget(
    maximumEntriesPerRoot: 7,
    maximumDepth: 3,
    retainedNodeCount: 2,
    maximumEntriesPerDirectory: 5,
    maximumPendingNameBytes: 128
  )
  let scope = try! ResolvedScanScope(
    resolverVersion: 9,
    profile: .deep,
    roots: [fs.request, unstarted],
    budget: budget,
    maximumDurationNanoseconds: 55
  )
  let collectors = ScanCollectorConfiguration(
    processActivityCollectorID: "lsof-nP-F0-v1",
    processActivityDeadlineNanoseconds: 10,
    globalFactCollectorIDs: ["swap-v1", "vm-v1", "swap-v1"]
  )
  let scanner = DeterministicScanner(
    filesystem: fs,
    scope: scope,
    clock: FixedClock(times: [100]),
    collectorConfiguration: collectors
  )
  let partial = scanner.finalizePartial()
  #expect(partial.reference.resolvedScope == scope)
  #expect(partial.reference.resolvedScope.roots == [fs.request, unstarted])
  #expect(partial.reference.resolvedScope.budget == budget)
  #expect(partial.reference.collectorConfiguration == collectors)
  #expect(partial.reference.collectorConfiguration.globalFactCollectorIDs == ["swap-v1", "vm-v1"])
  #expect(partial.rootFailures.map(\.rootID) == ["root", "unstarted"])
}

@Test func quickProfileBindsAdapterRootsWithoutGenericTraversal() {
  let child = component("child")
  let root = RawPath(rootID: "root")
  let fs = FakeFilesystem(rootChildren: [child], nodes: [root.appending(child): file(2, bytes: 1)])
  let scope = try! ScanRootResolver().resolve(
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

@Test func darwinReaddirIsGatedAndEnumerationDeadlineIsInternal() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let rootURL = FileManager.default.temporaryDirectory
    .appendingPathComponent("diskplan-enumeration-test-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: rootURL) }
  try Data([1]).write(to: rootURL.appendingPathComponent("a"))
  try Data([2]).write(to: rootURL.appendingPathComponent("b"))
  let rootFD = rootURL.withUnsafeFileSystemRepresentation {
    open($0!, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  }
  let fd = try #require(rootFD >= 0 ? rootFD : nil)
  defer { close(fd) }

  let failingGate = LockedPolicyGate(policy: policy, failingCall: 2)
  let gatedFilesystem = DarwinScanFilesystem(
    policy: policy,
    pathAccessValidator: { failingGate.validate() }
  )
  let gated = gatedFilesystem.enumerate(
    DirectoryHandle(rawValue: fd),
    limits: EnumerationLimits(
      maximumNames: 10,
      maximumNameBytes: 1_024,
      deadlineMonotonicNanoseconds: nil
    )
  )
  #expect(gated.value == nil)
  #expect(failingGate.callCount == 2)

  let timedFilesystem = DarwinScanFilesystem(
    policy: policy,
    pathAccessValidator: { .known(policy) },
    monotonicNow: { 100 }
  )
  let timed = try #require(
    timedFilesystem.enumerate(
      DirectoryHandle(rawValue: fd),
      limits: EnumerationLimits(
        maximumNames: 10,
        maximumNameBytes: 1_024,
        deadlineMonotonicNanoseconds: 50
      )
    ).value
  )
  #expect(timed.coverage.reasons == [.timedOut])
  #expect(timed.names.isEmpty)
}

@Test func darwinPathTouchEntryPointsRejectInjectedLivePolicyDrift() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let rootURL = FileManager.default.temporaryDirectory
    .appendingPathComponent("diskplan-policy-gate-test-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: rootURL) }
  let childName = RawPathComponent(Data("child".utf8))
  try FileManager.default.createDirectory(
    at: rootURL.appendingPathComponent("child"),
    withIntermediateDirectories: false
  )
  let rootFD = rootURL.withUnsafeFileSystemRepresentation {
    open($0!, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  }
  let fd = try #require(rootFD >= 0 ? rootFD : nil)
  defer { close(fd) }
  let parent = DirectoryHandle(rawValue: fd)
  let normal = DarwinScanFilesystem(policy: policy)
  let inspected = try #require(
    normal.inspect(
      parent: parent,
      name: childName,
      inheritedProviderBoundary: false,
      requiresAuthoritativeProviderEvidence: false
    ).value
  )
  let accessPolicy = try #require(inspected.accessPolicy.value)

  let inspectGate = LockedPolicyGate(policy: policy, failingCall: 1)
  let inspectFilesystem = DarwinScanFilesystem(
    policy: policy,
    pathAccessValidator: { inspectGate.validate() }
  )
  #expect(
    inspectFilesystem.inspect(
      parent: parent,
      name: childName,
      inheritedProviderBoundary: false,
      requiresAuthoritativeProviderEvidence: false
    ).value == nil
  )
  #expect(inspectGate.callCount == 1)

  let openGate = LockedPolicyGate(policy: policy, failingCall: 1)
  let openFilesystem = DarwinScanFilesystem(
    policy: policy,
    pathAccessValidator: { openGate.validate() }
  )
  #expect(
    openFilesystem.openDirectory(
      parent: parent,
      name: childName,
      expectedIdentity: inspected.identity,
      expectedAccessPolicy: accessPolicy
    ).value == nil
  )
  #expect(openGate.callCount == 1)

  let opened = try #require(
    normal.openDirectory(
      parent: parent,
      name: childName,
      expectedIdentity: inspected.identity,
      expectedAccessPolicy: accessPolicy
    ).value
  )
  let closeGate = LockedPolicyGate(policy: policy, failingCall: 1)
  let closeFilesystem = DarwinScanFilesystem(
    policy: policy,
    pathAccessValidator: { closeGate.validate() }
  )
  let closeEvidence = closeFilesystem.close(opened)
  #expect(closeEvidence.identity.value == inspected.identity)
  #expect(closeEvidence.accessPolicy.value == nil)
  #expect(closeGate.callCount == 1)

  let bindGate = LockedPolicyGate(policy: policy, failingCall: 1)
  let bindFilesystem = DarwinScanFilesystem(
    policy: policy,
    pathAccessValidator: { bindGate.validate() }
  )
  let rawRoot = rootURL.withUnsafeFileSystemRepresentation {
    Data(bytes: $0!, count: strlen($0!))
  }
  #expect(
    bindFilesystem.bindRoot(
      ScanRootRequest(rootID: "gated", rawAbsolutePath: rawRoot),
      resolverVersion: 1
    ).value == nil
  )
  #expect(bindGate.callCount == 1)
}

@Test func unavailableProviderFlagsCannotFallThroughToLocalEvidence() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let rootURL = FileManager.default.temporaryDirectory
    .appendingPathComponent("diskplan-provider-flags-test-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: rootURL) }
  try FileManager.default.createDirectory(
    at: rootURL.appendingPathComponent("child"),
    withIntermediateDirectories: false
  )
  let rootFD = rootURL.withUnsafeFileSystemRepresentation {
    open($0!, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  }
  let fd = try #require(rootFD >= 0 ? rootFD : nil)
  defer { close(fd) }
  let before = try #require(
    ItemProbe().probe(
      parentFileDescriptor: fd,
      rawName: Data("child".utf8),
      policy: policy
    ).value
  )
  let variants = [
    replacingItemEvidence(
      before,
      isDataless: .unavailable("dataless state unavailable")
    ),
    replacingItemEvidence(
      before,
      isSyncRoot: Capability(
        status: .failed,
        detail: "sync-root state failed",
        errorCode: EIO
      )
    ),
  ]

  for item in variants {
    let provider = LockedProviderOutcome(
      .rejected(
        .contentStateUnavailable(
          stage: .preflight,
          status: .unavailable,
          detail: "provider flags are not authoritative",
          errorCode: nil
        )
      )
    )
    let filesystem = DarwinScanFilesystem(
      policy: policy,
      pathAccessValidator: { .known(policy) },
      itemEvidenceReader: { _, _, _ in .known(item) },
      providerEvidenceReader: { _, _, _, _ in provider.probe() }
    )
    let observation = filesystem.inspect(
      parent: DirectoryHandle(rawValue: fd),
      name: component("child"),
      inheritedProviderBoundary: false,
      requiresAuthoritativeProviderEvidence: false
    )
    #expect(observation.value == nil)
    guard case .unknown = observation else {
      Issue.record("unavailable provider flags did not remain typed unknown")
      continue
    }
    #expect(provider.callCount == 1)
  }
}

@Test func authoritativeProviderEvidenceCannotOverrideUnknownSyncRootState() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let rootURL = FileManager.default.temporaryDirectory
    .appendingPathComponent(
      "diskplan-provider-sync-state-test-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: rootURL) }
  try FileManager.default.createDirectory(
    at: rootURL.appendingPathComponent("child"),
    withIntermediateDirectories: false
  )
  let rootFD = rootURL.withUnsafeFileSystemRepresentation {
    open($0!, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  }
  let fd = try #require(rootFD >= 0 ? rootFD : nil)
  defer { close(fd) }
  let actualItem = try #require(
    ItemProbe().probe(
      parentFileDescriptor: fd,
      rawName: Data("child".utf8),
      policy: policy
    ).value
  )
  let item = replacingItemEvidence(
    actualItem,
    isSyncRoot: .unavailable("sync-root state unavailable")
  )
  let provider = LockedProviderOutcome(confirmedProviderEvidence())
  let filesystem = DarwinScanFilesystem(
    policy: policy,
    pathAccessValidator: { .known(policy) },
    itemEvidenceReader: { _, _, _ in .known(item) },
    providerEvidenceReader: { _, _, _, _ in provider.probe() }
  )

  let observation = filesystem.inspect(
    parent: DirectoryHandle(rawValue: fd),
    name: component("child"),
    inheritedProviderBoundary: false,
    requiresAuthoritativeProviderEvidence: false
  )
  guard case .unknown = observation else {
    Issue.record("authoritative provider evidence overrode unknown sync-root state")
    return
  }
  #expect(provider.callCount == 1)
}

@Test func rejectedProviderBoundaryCannotRetainExactByteCredit() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let rootURL = FileManager.default.temporaryDirectory
    .appendingPathComponent(
      "diskplan-provider-rejected-bytes-test-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: rootURL) }
  try FileManager.default.createDirectory(
    at: rootURL.appendingPathComponent("child"),
    withIntermediateDirectories: false
  )
  let rootFD = rootURL.withUnsafeFileSystemRepresentation {
    open($0!, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  }
  let fd = try #require(rootFD >= 0 ? rootFD : nil)
  defer { close(fd) }
  let actualItem = try #require(
    ItemProbe().probe(
      parentFileDescriptor: fd,
      rawName: Data("child".utf8),
      policy: policy
    ).value
  )
  let item = replacingItemEvidence(
    fixtureItemEvidence(),
    device: actualItem.device,
    objectType: actualItem.objectType,
    fileID: actualItem.fileID,
    isDataless: .known(true)
  )
  let rejectedBoundary = FileProviderProbeOutcome.evidence(
    FileProviderEvidence(
      identity: .known(
        ProviderIdentity(itemIdentifier: "fixture-item", domainIdentifier: "fixture-domain")
      ),
      identityDisposition: .confirmedProvider,
      providerCapabilities: .unavailable("fixture"),
      promisedMetadata: .unavailable("fixture"),
      traversal: .doNotDescendDataless,
      handling: .reportOnly,
      hiddenBackingBytes: .unavailable("fixture"),
      controlledNonMaterializationAcceptance: .unavailable("fixture")
    )
  )
  let filesystem = DarwinScanFilesystem(
    policy: policy,
    pathAccessValidator: { .known(policy) },
    itemEvidenceReader: { _, _, _ in .known(item) },
    providerEvidenceReader: { _, _, _, _ in rejectedBoundary }
  )

  let inspected = try #require(
    filesystem.inspect(
      parent: DirectoryHandle(rawValue: fd),
      name: component("child"),
      inheritedProviderBoundary: false,
      requiresAuthoritativeProviderEvidence: false
    ).value
  )
  #expect(inspected.providerBoundary.preventsNormalDescent)
  guard case .unknown = inspected.bytes.logical else {
    Issue.record("rejected provider boundary retained exact logical bytes")
    return
  }
  guard case .unknown = inspected.bytes.nominalAllocated else {
    Issue.record("rejected provider boundary retained exact allocated bytes")
    return
  }
  guard case .unknown = inspected.bytes.immediatePrivateReclaim else {
    Issue.record("rejected provider boundary retained exact reclaim bytes")
    return
  }
}

@Test func providerPostflightRejectsChangedPolicyStateAndExactByteCredit() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let rootURL = FileManager.default.temporaryDirectory
    .appendingPathComponent("diskplan-provider-state-test-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: rootURL) }
  let scanRootURL = rootURL.appendingPathComponent("scan-root", isDirectory: true)
  try FileManager.default.createDirectory(at: scanRootURL, withIntermediateDirectories: false)
  let rawRoot = scanRootURL.withUnsafeFileSystemRepresentation {
    Data(bytes: $0!, count: strlen($0!))
  }
  let rootFD = rootURL.withUnsafeFileSystemRepresentation {
    open($0!, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  }
  let fd = try #require(rootFD >= 0 ? rootFD : nil)
  defer { close(fd) }
  let before = try #require(
    ItemProbe().probe(
      parentFileDescriptor: fd,
      rawName: Data("scan-root".utf8),
      policy: policy
    ).value
  )
  let changedSharing = SharingEvidence(
    mayShareBlocks: before.sharing.mayShareBlocks,
    sharesAllBlocks: before.sharing.sharesAllBlocks,
    cloneID: before.sharing.cloneID,
    cloneRefcount: .known(2),
    conditionalGroupReclaimBytes: before.sharing.conditionalGroupReclaimBytes
  )
  let mutations = [
    replacingItemEvidence(before, logicalBytes: .known(2)),
    replacingItemEvidence(before, sharing: changedSharing),
    replacingItemEvidence(before, isSyncRoot: .known(true)),
  ]

  for (index, after) in mutations.enumerated() {
    let items = LockedItemEvidenceSequence([before, after])
    let filesystem = DarwinScanFilesystem(
      policy: policy,
      pathAccessValidator: { .known(policy) },
      itemEvidenceReader: { _, _, _ in items.read() },
      providerEvidenceReader: { _, _, _, _ in confirmedProviderEvidence() }
    )
    let scope = try ResolvedScanScope(
      resolverVersion: 1,
      profile: .deep,
      roots: [ScanRootRequest(rootID: "mutation-\(index)", rawAbsolutePath: rawRoot)],
      budget: StructuralBudget(maximumEntriesPerRoot: 10, maximumDepth: 1),
      maximumDurationNanoseconds: nil
    )
    let result = DeterministicScanner(
      filesystem: filesystem,
      scope: scope,
      clock: FixedClock(times: [100])
    ).advance(maximumEntries: 1)
    guard case .failed(_, let code) = result.rootFailures.first?.observation else {
      Issue.record("policy-relevant provider postflight mutation was not rejected")
      continue
    }
    #expect(code == EBUSY)
    #expect(result.coverage.reasons.contains(.unstableDuringScan))
    #expect(result.coverage.reasons.contains(.providerStateUnverified))
    #expect(result.progress.entriesObserved == 0)
  }
}

@Test func providerProbeRejectionsRemainTypedThroughObservationAndCoverage() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let rootURL = FileManager.default.temporaryDirectory
    .appendingPathComponent(
      "diskplan-provider-rejection-test-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: rootURL) }
  let scanRootURL = rootURL.appendingPathComponent("scan-root", isDirectory: true)
  try FileManager.default.createDirectory(at: scanRootURL, withIntermediateDirectories: false)
  let rawRoot = scanRootURL.withUnsafeFileSystemRepresentation {
    Data(bytes: $0!, count: strlen($0!))
  }
  let rootFD = rootURL.withUnsafeFileSystemRepresentation {
    open($0!, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  }
  let fd = try #require(rootFD >= 0 ? rootFD : nil)
  defer { close(fd) }
  let item = try #require(
    ItemProbe().probe(
      parentFileDescriptor: fd,
      rawName: Data("scan-root".utf8),
      policy: policy
    ).value
  )
  let expected = FileObjectIdentity(device: 1, fileID: 1, objectType: .directory)
  let observed = FileObjectIdentity(device: 1, fileID: 2, objectType: .directory)

  func scan(
    _ rejection: FileProviderProbeRejection,
    rootID: String
  ) throws -> ScanResult {
    let filesystem = DarwinScanFilesystem(
      policy: policy,
      pathAccessValidator: { .known(policy) },
      itemEvidenceReader: { _, _, _ in .known(item) },
      providerEvidenceReader: { _, _, _, _ in .rejected(rejection) }
    )
    let scope = try ResolvedScanScope(
      resolverVersion: 1,
      profile: .deep,
      roots: [ScanRootRequest(rootID: rootID, rawAbsolutePath: rawRoot)],
      budget: StructuralBudget(maximumEntriesPerRoot: 10, maximumDepth: 1),
      maximumDurationNanoseconds: nil
    )
    return DeterministicScanner(
      filesystem: filesystem,
      scope: scope,
      clock: FixedClock(times: [100])
    ).advance(maximumEntries: 1)
  }

  let missing = try scan(.missing(stage: .preflight), rootID: "missing")
  guard case .absent = missing.rootFailures.first?.observation else {
    Issue.record("provider missing rejection was collapsed")
    return
  }
  #expect(missing.coverage.reasons.contains(.missing))

  let unreadable = try scan(
    .unreadable(stage: .derivedPathPreflight, errorCode: EACCES),
    rootID: "unreadable"
  )
  guard case .unreadable(_, let unreadableCode) = unreadable.rootFailures.first?.observation else {
    Issue.record("provider unreadable rejection was collapsed")
    return
  }
  #expect(unreadableCode == EACCES)
  #expect(unreadable.coverage.reasons.contains(.permissionDenied))

  let identity = try scan(
    .identityMismatch(stage: .postflight, expected: expected, observed: observed),
    rootID: "identity"
  )
  guard case .failed(_, let identityCode) = identity.rootFailures.first?.observation else {
    Issue.record("provider identity rejection was collapsed")
    return
  }
  #expect(identityCode == ESTALE)
  #expect(identity.coverage.reasons.contains(.identityMismatch))

  let content = try scan(
    .contentStateMismatch(
      stage: .postflight,
      expectedDataless: false,
      observedDataless: true
    ),
    rootID: "content"
  )
  guard case .failed(_, let contentCode) = content.rootFailures.first?.observation else {
    Issue.record("provider content-state rejection was collapsed")
    return
  }
  #expect(contentCode == EBUSY)
  #expect(content.coverage.reasons.contains(.unstableDuringScan))

  let timeout = try scan(.timedOut(stage: .identityLookup), rootID: "timeout")
  guard case .failed(_, let timeoutCode) = timeout.rootFailures.first?.observation else {
    Issue.record("provider timeout rejection was collapsed")
    return
  }
  #expect(timeoutCode == ETIMEDOUT)
  #expect(timeout.coverage.reasons.contains(.timedOut))

  for result in [missing, unreadable, identity, content, timeout] {
    #expect(result.coverage.reasons.contains(.providerStateUnverified))
    #expect(result.progress.entriesObserved == 0)
  }
}

@Test func darwinDirectoryUsesRealDeviceIdentityAndRevalidatesParentSlotAtClose() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let rootURL = FileManager.default.temporaryDirectory
    .appendingPathComponent("diskplan-close-test-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: rootURL) }
  let rootFD = rootURL.withUnsafeFileSystemRepresentation {
    open($0!, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  }
  let fd = try #require(rootFD >= 0 ? rootFD : nil)
  defer { close(fd) }
  let filesystem = DarwinScanFilesystem(policy: policy)
  let parent = DirectoryHandle(rawValue: fd)

  for rawName in [Data("stable".utf8), Data("missing".utf8), Data("policy".utf8)] {
    let name = RawPathComponent(rawName)
    var terminated = Array(rawName) + [0]
    let created = terminated.withUnsafeMutableBytes { raw in
      mkdirat(fd, raw.bindMemory(to: CChar.self).baseAddress!, mode_t(S_IRWXU))
    }
    #expect(created == 0)
    let inspected = try #require(
      filesystem.inspect(
        parent: parent,
        name: name,
        inheritedProviderBoundary: false,
        requiresAuthoritativeProviderEvidence: false
      ).value
    )
    let accessPolicy = try #require(inspected.accessPolicy.value)
    let directory = try #require(
      filesystem.openDirectory(
        parent: parent,
        name: name,
        expectedIdentity: inspected.identity,
        expectedAccessPolicy: accessPolicy
      ).value
    )
    let descriptorIdentity = try #require(
      FileDescriptorIdentityProbe().probe(
        fileDescriptor: directory.handle.rawValue,
        policy: policy
      ).value
    )
    #expect(descriptorIdentity.device == inspected.identity.device)
    #expect(descriptorIdentity.fileID == inspected.identity.fileID)

    if rawName == Data("missing".utf8) {
      let removed = terminated.withUnsafeMutableBytes { raw in
        unlinkat(fd, raw.bindMemory(to: CChar.self).baseAddress!, AT_REMOVEDIR)
      }
      #expect(removed == 0)
      let closeEvidence = filesystem.close(directory)
      guard case .absent = closeEvidence.identity else {
        Issue.record("missing parent slot was not preserved at close")
        continue
      }
      guard case .absent = closeEvidence.accessPolicy else {
        Issue.record("missing access-policy slot was not preserved at close")
        continue
      }
    } else if rawName == Data("policy".utf8) {
      let changed = terminated.withUnsafeMutableBytes { raw in
        fchmodat(fd, raw.bindMemory(to: CChar.self).baseAddress!, mode_t(S_IRUSR), 0)
      }
      #expect(changed == 0)
      let closeEvidence = filesystem.close(directory)
      #expect(closeEvidence.identity.value == inspected.identity)
      guard case .failed(_, let code) = closeEvidence.accessPolicy else {
        Issue.record("access-policy mutation was not preserved at close")
        continue
      }
      #expect(code == EAGAIN)
    } else {
      let closeEvidence = filesystem.close(directory)
      #expect(closeEvidence.identity.value == inspected.identity)
      #expect(closeEvidence.accessPolicy.value == accessPolicy)
    }
  }
}

@Test func childDirectoryRejectsAccessPolicyChangeBeforeFirstEnumeration() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let rootURL = FileManager.default.temporaryDirectory
    .appendingPathComponent(
      "diskplan-open-policy-seal-test-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: rootURL) }
  let childURL = rootURL.appendingPathComponent("child", isDirectory: true)
  try FileManager.default.createDirectory(at: childURL, withIntermediateDirectories: false)
  try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: childURL.path)
  let parentFD = rootURL.withUnsafeFileSystemRepresentation {
    open($0!, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  }
  let fd = try #require(parentFD >= 0 ? parentFD : nil)
  defer { close(fd) }
  let parent = DirectoryHandle(rawValue: fd)
  let name = component("child")
  let filesystem = DarwinScanFilesystem(policy: policy)
  let inspected = try #require(
    filesystem.inspect(
      parent: parent,
      name: name,
      inheritedProviderBoundary: false,
      requiresAuthoritativeProviderEvidence: false
    ).value
  )
  let expectedPolicy = try #require(inspected.accessPolicy.value)
  #expect(chmod(childURL.path, mode_t(0o500)) == 0)

  let opened = filesystem.openDirectory(
    parent: parent,
    name: name,
    expectedIdentity: inspected.identity,
    expectedAccessPolicy: expectedPolicy
  )
  guard case .failed(_, let code) = opened else {
    Issue.record("child directory accepted a changed access-policy seal before enumeration")
    return
  }
  #expect(code == EAGAIN)
}

@Test func nonRootBindingRejectsAccessPolicyChangeDuringDescriptorOpen() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let rootURL = FileManager.default.temporaryDirectory
    .appendingPathComponent(
      "diskplan-root-open-policy-seal-test-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: rootURL) }
  try FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: rootURL.path)
  let rawPath = try #require(rootURL.path.data(using: .utf8))
  let filesystem = DarwinScanFilesystem(
    policy: policy,
    pathAccessValidator: { .known(policy) },
    providerEvidenceReader: { _, _, _, _ in confirmedProviderEvidence() },
    directorySlotOpener: { parentFD, name in
      var bytes = Array(name) + [0]
      let changed = bytes.withUnsafeMutableBytes { raw in
        fchmodat(parentFD, raw.bindMemory(to: CChar.self).baseAddress!, mode_t(0o500), 0)
      }
      guard changed == 0 else { return -1 }
      return openDirectorySlot(parentFD: parentFD, name: name)
    }
  )

  let bound = filesystem.bindRoot(
    ScanRootRequest(rootID: "policy-race", rawAbsolutePath: rawPath),
    resolverVersion: 1
  )
  guard case .failed(_, let code) = bound else {
    Issue.record("non-root binding accepted a changed access-policy seal")
    return
  }
  #expect(code == EAGAIN)
}

@Test func descriptorOpenTreatsTimestampChangeAsAdvisory() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let rootURL = FileManager.default.temporaryDirectory
    .appendingPathComponent(
      "diskplan-open-time-advisory-test-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: rootURL) }
  let childURL = rootURL.appendingPathComponent("child", isDirectory: true)
  try FileManager.default.createDirectory(at: childURL, withIntermediateDirectories: false)
  let parentFD = rootURL.withUnsafeFileSystemRepresentation {
    open($0!, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  }
  let fd = try #require(parentFD >= 0 ? parentFD : nil)
  defer { close(fd) }
  let parent = DirectoryHandle(rawValue: fd)
  let name = component("child")
  let baseline = DarwinScanFilesystem(policy: policy)
  let inspected = try #require(
    baseline.inspect(
      parent: parent,
      name: name,
      inheritedProviderBoundary: false,
      requiresAuthoritativeProviderEvidence: false
    ).value
  )
  let expectedPolicy = try #require(inspected.accessPolicy.value)
  let changingTimes = DarwinScanFilesystem(
    policy: policy,
    pathAccessValidator: { .known(policy) },
    directorySlotOpener: { parentFD, name in
      let opened = openDirectorySlot(parentFD: parentFD, name: name)
      guard opened >= 0 else { return opened }
      let times = [
        timespec(tv_sec: 1_700_000_001, tv_nsec: 0),
        timespec(tv_sec: 1_700_000_002, tv_nsec: 0),
      ]
      let changed = times.withUnsafeBufferPointer { futimens(opened, $0.baseAddress!) }
      guard changed == 0 else {
        let code = errno
        close(opened)
        errno = code
        return -1
      }
      return opened
    }
  )
  let directory = try #require(
    changingTimes.openDirectory(
      parent: parent,
      name: name,
      expectedIdentity: inspected.identity,
      expectedAccessPolicy: expectedPolicy
    ).value
  )
  let closeEvidence = changingTimes.close(directory)
  #expect(closeEvidence.identity.value == inspected.identity)
  #expect(closeEvidence.accessPolicy.value == expectedPolicy)
}

@Test func closeAccessPolicyObservationIsBracketedByParentSlotIdentity() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let rootURL = FileManager.default.temporaryDirectory
    .appendingPathComponent("diskplan-close-bracket-test-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: rootURL) }
  try FileManager.default.createDirectory(
    at: rootURL.appendingPathComponent("child"),
    withIntermediateDirectories: false
  )
  let rootFD = rootURL.withUnsafeFileSystemRepresentation {
    open($0!, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  }
  let fd = try #require(rootFD >= 0 ? rootFD : nil)
  defer { close(fd) }
  let parent = DirectoryHandle(rawValue: fd)
  let name = component("child")
  let normal = DarwinScanFilesystem(policy: policy)
  let inspected = try #require(
    normal.inspect(
      parent: parent,
      name: name,
      inheritedProviderBoundary: false,
      requiresAuthoritativeProviderEvidence: false
    ).value
  )
  let accessPolicy = try #require(inspected.accessPolicy.value)
  let directory = try #require(
    normal.openDirectory(
      parent: parent,
      name: name,
      expectedIdentity: inspected.identity,
      expectedAccessPolicy: accessPolicy
    ).value
  )
  let actualItem = try #require(
    ItemProbe().probe(
      parentFileDescriptor: fd,
      rawName: name.bytes,
      policy: policy
    ).value
  )
  let actualFileID = try #require(actualItem.fileID.value)
  let slotSequence = LockedItemEvidenceSequence([
    actualItem,
    replacingItemEvidence(actualItem, fileID: .known(actualFileID &+ 1)),
  ])
  let racingFilesystem = DarwinScanFilesystem(
    policy: policy,
    pathAccessValidator: { .known(policy) },
    itemEvidenceReader: { _, _, _ in slotSequence.read() }
  )
  let closeEvidence = racingFilesystem.close(directory)
  guard case .failed(_, let identityCode) = closeEvidence.identity else {
    Issue.record("post-policy parent-slot replacement was not detected")
    return
  }
  #expect(identityCode == ESTALE)
  guard case .unknown = closeEvidence.accessPolicy else {
    Issue.record("replacement access policy was accepted as identity-bound")
    return
  }
}

@Test func closeRejectsReplacePolicyRestoreFromIdentityBoundObservation() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let rootURL = FileManager.default.temporaryDirectory
    .appendingPathComponent(
      "diskplan-close-replace-policy-restore-test-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: rootURL) }
  let childName = Data("child".utf8)
  let replacementName = Data("replacement".utf8)
  let parkedName = Data("parked-original".utf8)
  try FileManager.default.createDirectory(
    at: rootURL.appendingPathComponent("child"),
    withIntermediateDirectories: false
  )
  try FileManager.default.setAttributes(
    [.posixPermissions: 0o700],
    ofItemAtPath: rootURL.appendingPathComponent("child").path
  )
  let replacementURL = rootURL.appendingPathComponent("replacement")
  try FileManager.default.createDirectory(
    at: replacementURL,
    withIntermediateDirectories: false
  )
  try FileManager.default.setAttributes(
    [.posixPermissions: 0o500],
    ofItemAtPath: replacementURL.path
  )
  let rootFD = rootURL.withUnsafeFileSystemRepresentation {
    open($0!, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  }
  let fd = try #require(rootFD >= 0 ? rootFD : nil)
  defer { close(fd) }
  let parent = DirectoryHandle(rawValue: fd)
  let name = RawPathComponent(childName)
  let normal = DarwinScanFilesystem(policy: policy)
  let inspected = try #require(
    normal.inspect(
      parent: parent,
      name: name,
      inheritedProviderBoundary: false,
      requiresAuthoritativeProviderEvidence: false
    ).value
  )
  let accessPolicy = try #require(inspected.accessPolicy.value)
  #expect(accessPolicy.mode & 0o777 == 0o700)
  let directory = try #require(
    normal.openDirectory(
      parent: parent,
      name: name,
      expectedIdentity: inspected.identity,
      expectedAccessPolicy: accessPolicy
    ).value
  )
  let replacingFilesystem = DarwinScanFilesystem(
    policy: policy,
    pathAccessValidator: { .known(policy) },
    slotSealOpener: { parentFD, observedName in
      guard observedName == childName else {
        errno = EINVAL
        return -1
      }
      return openReplacementThenRestore(
        parentFD: parentFD,
        slotName: childName,
        replacementName: replacementName,
        parkedName: parkedName
      )
    }
  )

  let closeEvidence = replacingFilesystem.close(directory)
  guard case .failed(_, let identityCode) = closeEvidence.identity else {
    Issue.record("replace-policy-restore was not attributed to identity instability")
    return
  }
  #expect(identityCode == ESTALE)
  guard case .failed(_, let policyCode) = closeEvidence.accessPolicy else {
    Issue.record("replacement policy was not attributed to the bound slot identity")
    return
  }
  #expect(policyCode == ESTALE)
  let restoredItem = try #require(
    ItemProbe().probe(
      parentFileDescriptor: fd,
      rawName: childName,
      policy: policy
    ).value
  )
  #expect(restoredItem.fileID.value == inspected.identity.fileID)
}

@Test func inspectRejectsIdentityBytesWithReplacementPolicyTimesSeal() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let rootURL = FileManager.default.temporaryDirectory
    .appendingPathComponent(
      "diskplan-inspect-seal-interleaving-test-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: rootURL) }
  let childName = Data("child".utf8)
  let replacementName = Data("replacement".utf8)
  let parkedName = Data("parked-original".utf8)
  try FileManager.default.createDirectory(
    at: rootURL.appendingPathComponent("child"),
    withIntermediateDirectories: false
  )
  try FileManager.default.createDirectory(
    at: rootURL.appendingPathComponent("replacement"),
    withIntermediateDirectories: false
  )
  try FileManager.default.setAttributes(
    [.posixPermissions: 0o500],
    ofItemAtPath: rootURL.appendingPathComponent("replacement").path
  )
  let rootFD = rootURL.withUnsafeFileSystemRepresentation {
    open($0!, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  }
  let fd = try #require(rootFD >= 0 ? rootFD : nil)
  defer { close(fd) }
  let original = try #require(
    ItemProbe().probe(
      parentFileDescriptor: fd,
      rawName: childName,
      policy: policy
    ).value
  )
  let filesystem = DarwinScanFilesystem(
    policy: policy,
    pathAccessValidator: { .known(policy) },
    slotSealOpener: { parentFD, observedName in
      guard observedName == childName else {
        errno = EINVAL
        return -1
      }
      return openReplacementThenRestore(
        parentFD: parentFD,
        slotName: childName,
        replacementName: replacementName,
        parkedName: parkedName
      )
    }
  )

  let observation = filesystem.inspect(
    parent: DirectoryHandle(rawValue: fd),
    name: RawPathComponent(childName),
    inheritedProviderBoundary: false,
    requiresAuthoritativeProviderEvidence: false
  )
  guard case .failed(_, let code) = observation else {
    Issue.record("replacement policy/times seal was combined with original identity")
    return
  }
  #expect(code == ESTALE)
  let restored = try #require(
    ItemProbe().probe(
      parentFileDescriptor: fd,
      rawName: childName,
      policy: policy
    ).value
  )
  #expect(restored.fileID.value == original.fileID.value)
}

@Test func darwinInspectBindsPolicyAndTimesAcrossNoFollowObjectTypes() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  let rootURL = FileManager.default.temporaryDirectory
    .appendingPathComponent(
      "diskplan-inspect-bound-seal-types-test-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
  defer { try? FileManager.default.removeItem(at: rootURL) }
  try FileManager.default.createDirectory(
    at: rootURL.appendingPathComponent("directory"),
    withIntermediateDirectories: false
  )
  try Data([1]).write(to: rootURL.appendingPathComponent("regular"))
  try FileManager.default.createSymbolicLink(
    at: rootURL.appendingPathComponent("symlink"),
    withDestinationURL: rootURL.appendingPathComponent("regular")
  )
  let rootFD = rootURL.withUnsafeFileSystemRepresentation {
    open($0!, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
  }
  let fd = try #require(rootFD >= 0 ? rootFD : nil)
  defer { close(fd) }
  let filesystem = DarwinScanFilesystem(policy: policy)
  let fixtures: [(Data, ScannedObjectType)] = [
    (Data("directory".utf8), .directory),
    (Data("regular".utf8), .regular),
    (Data("symlink".utf8), .symbolicLink),
  ]

  for (rawName, expectedType) in fixtures {
    let observation = filesystem.inspect(
      parent: DirectoryHandle(rawValue: fd),
      name: RawPathComponent(rawName),
      inheritedProviderBoundary: false,
      requiresAuthoritativeProviderEvidence: false
    )
    guard let inspected = observation.value else {
      Issue.record(
        "bound seal failed for \(String(decoding: rawName, as: UTF8.self)): \(observation)")
      continue
    }
    #expect(inspected.identity.objectType == expectedType)
    #expect(inspected.accessPolicy.value != nil)
    #expect(inspected.filesystemTimes.accessTime.value != nil)
    #expect(inspected.filesystemTimes.modificationTime.value != nil)
    #expect(inspected.filesystemTimes.statusChangeTime.value != nil)
    #expect(inspected.filesystemTimes.birthTime.value != nil)
  }
}

@Test func closeClassifiesTemporarySymlinkAndRegularReplacementsAsIdentityMismatch() throws {
  let policy = try #require(MaterializationPolicyInstaller().installBeforePathAccess().value)
  for kind in ["symlink", "regular"] {
    let rootURL = FileManager.default.temporaryDirectory
      .appendingPathComponent(
        "diskplan-close-type-replacement-\(kind)-\(UUID().uuidString)", isDirectory: true)
    try FileManager.default.createDirectory(at: rootURL, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: rootURL) }
    let childName = Data("child".utf8)
    let replacementName = Data("replacement".utf8)
    let parkedName = Data("parked-original".utf8)
    try FileManager.default.createDirectory(
      at: rootURL.appendingPathComponent("child"),
      withIntermediateDirectories: false
    )
    let replacementURL = rootURL.appendingPathComponent("replacement")
    if kind == "symlink" {
      try FileManager.default.createSymbolicLink(
        at: replacementURL,
        withDestinationURL: rootURL.appendingPathComponent("missing-target")
      )
    } else {
      try Data([1]).write(to: replacementURL)
    }
    let rootFD = rootURL.withUnsafeFileSystemRepresentation {
      open($0!, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    }
    let fd = try #require(rootFD >= 0 ? rootFD : nil)
    defer { close(fd) }
    let parent = DirectoryHandle(rawValue: fd)
    let name = RawPathComponent(childName)
    let normal = DarwinScanFilesystem(policy: policy)
    let inspected = try #require(
      normal.inspect(
        parent: parent,
        name: name,
        inheritedProviderBoundary: false,
        requiresAuthoritativeProviderEvidence: false
      ).value
    )
    let accessPolicy = try #require(inspected.accessPolicy.value)
    let directory = try #require(
      normal.openDirectory(
        parent: parent,
        name: name,
        expectedIdentity: inspected.identity,
        expectedAccessPolicy: accessPolicy
      ).value
    )
    let replacingFilesystem = DarwinScanFilesystem(
      policy: policy,
      pathAccessValidator: { .known(policy) },
      slotSealOpener: { parentFD, observedName in
        guard observedName == childName else {
          errno = EINVAL
          return -1
        }
        return openReplacementThenRestore(
          parentFD: parentFD,
          slotName: childName,
          replacementName: replacementName,
          parkedName: parkedName
        )
      }
    )

    let closeEvidence = replacingFilesystem.close(directory)
    guard case .failed(_, let identityCode) = closeEvidence.identity else {
      Issue.record("temporary \(kind) replacement was not an identity mismatch")
      continue
    }
    #expect(identityCode == ESTALE)
    guard case .failed(_, let policyCode) = closeEvidence.accessPolicy else {
      Issue.record("temporary \(kind) replacement remained a generic policy failure")
      continue
    }
    #expect(policyCode == ESTALE)
    let restored = try #require(
      ItemProbe().probe(
        parentFileDescriptor: fd,
        rawName: childName,
        policy: policy
      ).value
    )
    #expect(restored.fileID.value == inspected.identity.fileID)
  }
}

@Test func configuredDarwinRootFailsClosedWithoutAuthoritativeProviderOwnership() throws {
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
  let scope = try! ResolvedScanScope(
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
  #expect(result.progress.entriesObserved == 0)
  #expect(result.coverage.reasons.contains(.providerStateUnverified))
  guard case .failed = result.rootFailures.first?.observation else {
    Issue.record("configured root did not preserve its provider-proof failure")
    return
  }
}
