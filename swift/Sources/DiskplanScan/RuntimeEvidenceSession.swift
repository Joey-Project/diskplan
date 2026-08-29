import CryptoKit
import Darwin
import DiskplanMacOS
import Foundation

package enum RuntimeEvidenceCaptureKind: UInt8, Equatable, Sendable {
  case wholePlan = 1
  case jitUnit = 2
  case finalDescriptor = 3
}

package struct RuntimeEvidenceCaptureID: Equatable, Hashable, Sendable {
  package let bytes: Data

  fileprivate init(bytes: Data) { self.bytes = bytes }
}

package struct RuntimeObjectIdentity: Equatable, Sendable {
  package let device: Int64
  package let fileID: UInt64
  package let objectType: ScannedObjectType
  package let generation: Observation<UInt64>
}

package struct RuntimeNamespaceEvidence: Equatable, Sendable {
  package let identity: Observation<RuntimeObjectIdentity>
  package let accessPolicy: Observation<AccessPolicyEvidence>
  package let providerBoundary: Observation<ProviderBoundary>
  package let mountDevice: Observation<Int64>
}

package struct RuntimeProtectedObjectEvidence: Equatable, Sendable {
  package let identity: Observation<RuntimeObjectIdentity>
  package let content: ContentEvidence
  package let accessPolicy: Observation<AccessPolicyEvidence>
  package let providerBoundary: Observation<ProviderBoundary>
  package let mountDevice: Observation<Int64>
}

package struct RuntimePathEvidence: Equatable, Sendable {
  package let target: RuntimeProtectedObjectEvidence
  package let root: RuntimeNamespaceEvidence
  package let parents: [RuntimeNamespaceEvidence]
}

package struct RuntimePathEvidenceRequest: Equatable, Sendable {
  package let rootID: String
  package let rawRoot: Data
  package let targetComponents: [Data]
  package let requiresContent: Bool

  package init(
    rootID: String,
    rawRoot: Data,
    targetComponents: [Data],
    requiresContent: Bool
  ) {
    self.rootID = rootID
    self.rawRoot = rawRoot
    self.targetComponents = targetComponents
    self.requiresContent = requiresContent
  }
}

/// Ownership of every descriptor transfers to DiskplanScan when this value is consumed.
package struct RuntimeTransferredDescriptorRequest: Sendable {
  package let rootID: String
  package let targetComponents: [Data]
  package let rootDescriptor: Int32
  package let parentDescriptors: [Int32]
  package let targetDescriptor: Int32
  package let requiresContent: Bool

  package init(
    rootID: String,
    targetComponents: [Data],
    rootDescriptor: Int32,
    parentDescriptors: [Int32],
    targetDescriptor: Int32,
    requiresContent: Bool
  ) {
    self.rootID = rootID
    self.targetComponents = targetComponents
    self.rootDescriptor = rootDescriptor
    self.parentDescriptors = parentDescriptors
    self.targetDescriptor = targetDescriptor
    self.requiresContent = requiresContent
  }
}

package enum RuntimeEvidenceSessionError: Error, Equatable {
  case closed
  case captureAlreadyActive
  case captureRetired
  case invalidPath
  case invalidDescriptorSet
  case captureSequenceExhausted
}

private final class RuntimeEvidenceLeaseState: @unchecked Sendable {
  private let lock = NSLock()
  private var active = true

  func retire() -> Bool {
    lock.withLock {
      guard active else { return false }
      active = false
      return true
    }
  }

  var isActive: Bool { lock.withLock { active } }
}

/// One scanner-owned authority lifetime spans whole-plan, JIT, and final descriptor captures.
/// A capture lease is single-use and retires every pending descriptor receipt on finish.
package final class RuntimeEvidenceSession: @unchecked Sendable {
  package typealias ProviderReader =
    @Sendable (
      Int32, Data, NoMaterializationPolicy
    ) -> Observation<ProviderBoundary>

  private let lock = NSLock()
  private let policy: NoMaterializationPolicy
  private let contentAuthority: ScannerContentCollectionAuthority
  private let filesystem: DarwinScanFilesystem
  private let providerReader: ProviderReader
  private let sessionNonce: Data
  private var issuedCaptureIDs = Set<RuntimeEvidenceCaptureID>()
  private var sequence: UInt64 = 0
  private var activeLease: RuntimeEvidenceLeaseState?
  private var closed = false

  package init(
    policy: NoMaterializationPolicy,
    contentBudget: ContentCollectionBudget,
    providerReader: @escaping ProviderReader = runtimeProviderBoundary
  ) {
    self.policy = policy
    contentAuthority = ScannerContentCollectionAuthority(
      policy: policy,
      budget: contentBudget
    )
    filesystem = DarwinScanFilesystem(policy: policy)
    self.providerReader = providerReader
    var nonce = Data(count: 32)
    nonce.withUnsafeMutableBytes { raw in
      arc4random_buf(raw.baseAddress, raw.count)
    }
    sessionNonce = nonce
  }

  deinit { close() }

  package func beginCapture(
    _ kind: RuntimeEvidenceCaptureKind,
    excluding forbidden: Set<Data> = []
  ) throws -> RuntimeEvidenceCaptureLease {
    let leaseState = RuntimeEvidenceLeaseState()
    let captureID: RuntimeEvidenceCaptureID = try lock.withLock {
      guard !closed else { throw RuntimeEvidenceSessionError.closed }
      guard activeLease == nil else { throw RuntimeEvidenceSessionError.captureAlreadyActive }
      guard contentAuthority.advanceEpoch() else { throw RuntimeEvidenceSessionError.closed }
      let identifier = try nextCaptureID(kind: kind, excluding: forbidden)
      activeLease = leaseState
      return identifier
    }
    return RuntimeEvidenceCaptureLease(
      captureID: captureID,
      state: leaseState,
      session: self
    )
  }

  package func advanceEpoch() -> Bool {
    lock.withLock {
      guard !closed, activeLease == nil else { return false }
      return contentAuthority.advanceEpoch()
    }
  }

  package func close() {
    let lease = lock.withLock { () -> RuntimeEvidenceLeaseState? in
      guard !closed else { return nil }
      closed = true
      defer { activeLease = nil }
      return activeLease
    }
    _ = lease?.retire()
    contentAuthority.close()
  }

  fileprivate func finish(_ lease: RuntimeEvidenceLeaseState) {
    guard lease.retire() else { return }
    let shouldDrain = lock.withLock { () -> Bool in
      guard activeLease === lease else { return false }
      activeLease = nil
      return !closed
    }
    if shouldDrain { _ = contentAuthority.advanceEpoch() }
  }

  fileprivate func collectPaths(
    _ requests: [RuntimePathEvidenceRequest],
    lease: RuntimeEvidenceLeaseState
  ) throws -> [RuntimePathEvidence] {
    try requireActive(lease)
    var result: [RuntimePathEvidence] = []
    result.reserveCapacity(requests.count)
    for request in requests {
      try requireActive(lease)
      result.append(try collectPath(request, lease: lease))
    }
    return result
  }

  fileprivate func collectTransferredDescriptors(
    _ request: RuntimeTransferredDescriptorRequest,
    lease: RuntimeEvidenceLeaseState
  ) throws -> RuntimePathEvidence {
    let descriptors =
      [request.rootDescriptor] + request.parentDescriptors + [request.targetDescriptor]
    var ownsDescriptors = true
    defer {
      if ownsDescriptors {
        for descriptor in descriptors where descriptor >= 0 { Darwin.close(descriptor) }
      }
    }
    try requireActive(lease)
    guard !request.targetComponents.isEmpty,
      request.parentDescriptors.count == request.targetComponents.count - 1,
      descriptors.allSatisfy({ $0 >= 0 }),
      Set(descriptors).count == descriptors.count,
      validRuntimeComponents(request.targetComponents)
    else { throw RuntimeEvidenceSessionError.invalidDescriptorSet }

    let root = namespaceEvidence(descriptor: request.rootDescriptor, provider: .localOrUnindicated)
    var parents: [RuntimeNamespaceEvidence] = []
    parents.reserveCapacity(request.parentDescriptors.count)
    for (index, descriptor) in request.parentDescriptors.enumerated() {
      let parentDescriptor =
        index == 0 ? request.rootDescriptor : request.parentDescriptors[index - 1]
      let boundary = providerBoundary(
        parentDescriptor: parentDescriptor,
        name: request.targetComponents[index]
      )
      parents.append(namespaceEvidence(descriptor: descriptor, provider: boundary))
    }
    let targetParent = request.parentDescriptors.last ?? request.rootDescriptor
    let targetBoundary = providerBoundary(
      parentDescriptor: targetParent,
      name: request.targetComponents.last!
    )
    let path = RawPath(
      rootID: request.rootID,
      components: request.targetComponents.map(RawPathComponent.init)
    )
    let target = protectedObjectEvidence(
      transferring: request.targetDescriptor,
      path: path,
      rootDescriptor: request.rootDescriptor,
      targetParentDescriptor: targetParent,
      rawLeaf: request.targetComponents.last!,
      provider: targetBoundary,
      requiresContent: request.requiresContent
    )
    ownsDescriptors = false
    for descriptor in [request.rootDescriptor] + request.parentDescriptors {
      Darwin.close(descriptor)
    }
    return RuntimePathEvidence(target: target, root: root, parents: parents)
  }

  private func collectPath(
    _ request: RuntimePathEvidenceRequest,
    lease: RuntimeEvidenceLeaseState
  ) throws -> RuntimePathEvidence {
    guard !request.targetComponents.isEmpty, validRuntimeComponents(request.targetComponents)
    else { throw RuntimeEvidenceSessionError.invalidPath }
    let rootObservation = filesystem.bindRoot(
      ScanRootRequest(rootID: request.rootID, rawAbsolutePath: request.rawRoot),
      resolverVersion: 1
    )
    guard let boundRoot = rootObservation.value else {
      let failure = rootObservation.erasingValue() as Observation<RuntimeObjectIdentity>
      let namespace = RuntimeNamespaceEvidence(
        identity: failure,
        accessPolicy: rootObservation.erasingValue(),
        providerBoundary: rootObservation.erasingValue(),
        mountDevice: rootObservation.erasingValue()
      )
      return RuntimePathEvidence(
        target: RuntimeProtectedObjectEvidence(
          identity: failure,
          content: .unavailable(reason: "runtime root binding unavailable", errorCode: nil),
          accessPolicy: rootObservation.erasingValue(),
          providerBoundary: rootObservation.erasingValue(),
          mountDevice: rootObservation.erasingValue()
        ),
        root: namespace,
        parents: []
      )
    }

    var openedDirectories = [boundRoot.directory]
    var namespaceEvidenceValues = [
      RuntimeNamespaceEvidence(
        identity: runtimeIdentity(
          descriptor: boundRoot.directory.handle.rawValue,
          fallback: boundRoot.binding.identity
        ),
        accessPolicy: boundRoot.accessPolicy,
        providerBoundary: .known(boundRoot.providerBoundary),
        mountDevice: .known(boundRoot.binding.identity.device)
      )
    ]
    defer {
      for directory in openedDirectories.reversed() { _ = filesystem.close(directory) }
    }

    var current = boundRoot.directory
    for rawComponent in request.targetComponents.dropLast() {
      try requireActive(lease)
      let name = RawPathComponent(rawComponent)
      let inspected = filesystem.inspect(
        parent: current.handle,
        name: name,
        inheritedProviderBoundary: namespaceEvidenceValues.last?.providerBoundary.value?
          .isProviderManaged ?? false,
        requiresAuthoritativeProviderEvidence: true
      )
      guard let item = inspected.value, let access = item.accessPolicy.value else {
        let failure = inspected.erasingValue() as Observation<RuntimeObjectIdentity>
        namespaceEvidenceValues.append(
          RuntimeNamespaceEvidence(
            identity: failure,
            accessPolicy: inspected.erasingValue(),
            providerBoundary: inspected.erasingValue(),
            mountDevice: inspected.erasingValue()
          ))
        return failedPathEvidence(
          root: namespaceEvidenceValues[0],
          parents: Array(namespaceEvidenceValues.dropFirst()),
          failure: failure,
          reason: "runtime parent binding unavailable"
        )
      }
      let opened = filesystem.openDirectory(
        parent: current.handle,
        name: name,
        expectedIdentity: item.identity,
        expectedAccessPolicy: access
      )
      guard let directory = opened.value else {
        let failure = opened.erasingValue() as Observation<RuntimeObjectIdentity>
        namespaceEvidenceValues.append(
          RuntimeNamespaceEvidence(
            identity: failure,
            accessPolicy: opened.erasingValue(),
            providerBoundary: .known(item.providerBoundary),
            mountDevice: opened.erasingValue()
          ))
        return failedPathEvidence(
          root: namespaceEvidenceValues[0],
          parents: Array(namespaceEvidenceValues.dropFirst()),
          failure: failure,
          reason: "runtime parent descriptor unavailable"
        )
      }
      openedDirectories.append(directory)
      current = directory
      namespaceEvidenceValues.append(
        RuntimeNamespaceEvidence(
          identity: runtimeIdentity(
            descriptor: directory.handle.rawValue,
            fallback: item.identity
          ),
          accessPolicy: .known(access),
          providerBoundary: .known(item.providerBoundary),
          mountDevice: .known(item.identity.device)
        ))
    }

    let rawLeaf = request.targetComponents.last!
    let leaf = RawPathComponent(rawLeaf)
    let inspected = filesystem.inspect(
      parent: current.handle,
      name: leaf,
      inheritedProviderBoundary: namespaceEvidenceValues.last?.providerBoundary.value?
        .isProviderManaged ?? false,
      requiresAuthoritativeProviderEvidence: true
    )
    guard let item = inspected.value else {
      return failedPathEvidence(
        root: namespaceEvidenceValues[0],
        parents: Array(namespaceEvidenceValues.dropFirst()),
        failure: inspected.erasingValue(),
        reason: "runtime target inspection unavailable"
      )
    }
    let targetDescriptor = withNullTerminated(rawLeaf) {
      Darwin.openat(current.handle.rawValue, $0, runtimeOpenFlags(item.identity.objectType))
    }
    guard targetDescriptor >= 0 else {
      return failedPathEvidence(
        root: namespaceEvidenceValues[0],
        parents: Array(namespaceEvidenceValues.dropFirst()),
        failure: posixRuntimeObservation(errno, operation: "open runtime target"),
        reason: "runtime target descriptor unavailable"
      )
    }
    let target = protectedObjectEvidence(
      transferring: targetDescriptor,
      path: RawPath(
        rootID: request.rootID,
        components: request.targetComponents.map(RawPathComponent.init)
      ),
      rootDescriptor: boundRoot.directory.handle.rawValue,
      targetParentDescriptor: current.handle.rawValue,
      rawLeaf: rawLeaf,
      provider: item.providerBoundary,
      requiresContent: request.requiresContent
    )
    return RuntimePathEvidence(
      target: target,
      root: namespaceEvidenceValues[0],
      parents: Array(namespaceEvidenceValues.dropFirst())
    )
  }

  private func protectedObjectEvidence(
    transferring targetDescriptor: Int32,
    path: RawPath,
    rootDescriptor: Int32,
    targetParentDescriptor: Int32,
    rawLeaf: Data,
    provider: ProviderBoundary,
    requiresContent: Bool
  ) -> RuntimeProtectedObjectEvidence {
    guard let targetSeal = descriptorSeal(fileDescriptor: targetDescriptor, policy: policy) else {
      let code = errno
      Darwin.close(targetDescriptor)
      let failed: Observation<RuntimeObjectIdentity> = posixRuntimeObservation(
        code, operation: "seal runtime target")
      return RuntimeProtectedObjectEvidence(
        identity: failed,
        content: .unavailable(reason: "runtime target seal unavailable", errorCode: code),
        accessPolicy: failed.erasingValue(),
        providerBoundary: .known(provider),
        mountDevice: failed.erasingValue()
      )
    }
    let targetIdentity = runtimeIdentity(
      descriptor: targetDescriptor,
      fallback: targetSeal.identity
    )
    let rootSeal = descriptorSeal(fileDescriptor: rootDescriptor, policy: policy)
    let content: ContentEvidence
    if !requiresContent {
      Darwin.close(targetDescriptor)
      content = .notApplicable(.planContractDoesNotRequireContent)
    } else if targetSeal.identity.objectType != .regular {
      Darwin.close(targetDescriptor)
      content = .notApplicable(.notRegularFile)
    } else {
      let consumer = contentAuthority.evidenceConsumer
      let registration = contentAuthority.bindScannerDescriptor(
        transferring: targetDescriptor,
        target: path,
        rootIdentity: rootSeal?.identity
          ?? ObjectIdentity(device: -1, fileID: 0, objectType: .other),
        rootAccessPolicy: rootSeal?.accessPolicy ?? targetSeal.accessPolicy,
        expectedIdentity: targetSeal.identity,
        expectedAccessPolicy: targetSeal.accessPolicy,
        rootIdentityObservation: { [policy] in
          guard let seal = descriptorSeal(fileDescriptor: rootDescriptor, policy: policy) else {
            return posixRuntimeObservation(errno, operation: "revalidate runtime root")
          }
          return .known(seal.identity)
        },
        rootAccessPolicyObservation: { [policy] in
          guard let seal = descriptorSeal(fileDescriptor: rootDescriptor, policy: policy) else {
            return posixRuntimeObservation(errno, operation: "revalidate runtime root policy")
          }
          return .known(seal.accessPolicy)
        },
        slotPathObservation: { .known(path) },
        slotIdentityObservation: { [policy] in
          guard let seal = descriptorSeal(fileDescriptor: targetDescriptor, policy: policy) else {
            return posixRuntimeObservation(errno, operation: "revalidate runtime target")
          }
          return .known(seal.identity)
        },
        slotAccessPolicyObservation: { [policy] in
          guard let seal = descriptorSeal(fileDescriptor: targetDescriptor, policy: policy) else {
            return posixRuntimeObservation(errno, operation: "revalidate runtime target policy")
          }
          return .known(seal.accessPolicy)
        },
        providerObservation: { [policy, providerReader] in
          providerReader(targetParentDescriptor, rawLeaf, policy)
        }
      )
      switch registration {
      case .known(let requestID): content = consumer.collect(requestID)
      case .absent(let reason):
        content = .unavailable(reason: reason, errorCode: ENOENT)
      case .unknown(let reason):
        content = .unavailable(reason: reason, errorCode: nil)
      case .unreadable(let reason, let code), .failed(let reason, let code):
        content = .unavailable(reason: reason, errorCode: code)
      }
    }
    return RuntimeProtectedObjectEvidence(
      identity: targetIdentity,
      content: content,
      accessPolicy: .known(targetSeal.accessPolicy),
      providerBoundary: .known(provider),
      mountDevice: .known(targetSeal.identity.device)
    )
  }

  private func namespaceEvidence(
    descriptor: Int32,
    provider: ProviderBoundary
  ) -> RuntimeNamespaceEvidence {
    guard let seal = descriptorSeal(fileDescriptor: descriptor, policy: policy) else {
      let failed: Observation<RuntimeObjectIdentity> = posixRuntimeObservation(
        errno, operation: "seal runtime namespace")
      return RuntimeNamespaceEvidence(
        identity: failed,
        accessPolicy: failed.erasingValue(),
        providerBoundary: .known(provider),
        mountDevice: failed.erasingValue()
      )
    }
    return RuntimeNamespaceEvidence(
      identity: runtimeIdentity(descriptor: descriptor, fallback: seal.identity),
      accessPolicy: .known(seal.accessPolicy),
      providerBoundary: .known(provider),
      mountDevice: .known(seal.identity.device)
    )
  }

  private func failedPathEvidence(
    root: RuntimeNamespaceEvidence,
    parents: [RuntimeNamespaceEvidence],
    failure: Observation<RuntimeObjectIdentity>,
    reason: String
  ) -> RuntimePathEvidence {
    RuntimePathEvidence(
      target: RuntimeProtectedObjectEvidence(
        identity: failure,
        content: .unavailable(reason: reason, errorCode: nil),
        accessPolicy: failure.erasingValue(),
        providerBoundary: failure.erasingValue(),
        mountDevice: failure.erasingValue()
      ),
      root: root,
      parents: parents
    )
  }

  private func providerBoundary(parentDescriptor: Int32, name: Data) -> ProviderBoundary {
    providerReader(parentDescriptor, name, policy).value
      ?? .unverified(reason: "runtime provider observation unavailable")
  }

  private func requireActive(_ lease: RuntimeEvidenceLeaseState) throws {
    let valid = lock.withLock { !closed && activeLease === lease && lease.isActive }
    guard valid else { throw RuntimeEvidenceSessionError.captureRetired }
    try Task.checkCancellation()
  }

  private func nextCaptureID(
    kind: RuntimeEvidenceCaptureKind,
    excluding forbidden: Set<Data>
  ) throws -> RuntimeEvidenceCaptureID {
    while true {
      let next = sequence.addingReportingOverflow(1)
      guard !next.overflow else { throw RuntimeEvidenceSessionError.captureSequenceExhausted }
      sequence = next.partialValue
      var input = Data("diskplan/runtime-evidence-capture/v1\0".utf8)
      input.append(sessionNonce)
      input.append(kind.rawValue)
      var bigEndian = sequence.bigEndian
      withUnsafeBytes(of: &bigEndian) { input.append(contentsOf: $0) }
      let identifier = RuntimeEvidenceCaptureID(
        bytes: Data(SHA256.hash(data: input)))
      guard !forbidden.contains(identifier.bytes), !issuedCaptureIDs.contains(identifier) else {
        continue
      }
      issuedCaptureIDs.insert(identifier)
      return identifier
    }
  }
}

package final class RuntimeEvidenceCaptureLease: @unchecked Sendable {
  package let captureID: RuntimeEvidenceCaptureID
  private let state: RuntimeEvidenceLeaseState
  private var session: RuntimeEvidenceSession?

  fileprivate init(
    captureID: RuntimeEvidenceCaptureID,
    state: RuntimeEvidenceLeaseState,
    session: RuntimeEvidenceSession
  ) {
    self.captureID = captureID
    self.state = state
    self.session = session
  }

  deinit { finish() }

  package func collectPaths(
    _ requests: [RuntimePathEvidenceRequest]
  ) throws -> [RuntimePathEvidence] {
    guard let session else { throw RuntimeEvidenceSessionError.closed }
    return try session.collectPaths(requests, lease: state)
  }

  package func collectTransferredDescriptors(
    _ request: RuntimeTransferredDescriptorRequest
  ) throws -> RuntimePathEvidence {
    guard let session else { throw RuntimeEvidenceSessionError.closed }
    return try session.collectTransferredDescriptors(request, lease: state)
  }

  package func finish() {
    session?.finish(state)
    session = nil
  }
}

private func validRuntimeComponents(_ components: [Data]) -> Bool {
  components.allSatisfy {
    !$0.isEmpty && !$0.contains(0) && !$0.contains(47)
      && $0 != Data(".".utf8) && $0 != Data("..".utf8)
  }
}

private func runtimeOpenFlags(_ objectType: ScannedObjectType) -> Int32 {
  switch objectType {
  case .regular: O_RDONLY | O_NOFOLLOW | O_CLOEXEC
  case .directory: O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
  case .symbolicLink: O_RDONLY | O_SYMLINK | O_CLOEXEC
  case .other: O_RDONLY | O_NOFOLLOW | O_CLOEXEC
  }
}

private func runtimeIdentity(
  descriptor: Int32,
  fallback: ObjectIdentity
) -> Observation<RuntimeObjectIdentity> {
  var status = stat()
  guard Darwin.fstat(descriptor, &status) == 0 else {
    return posixRuntimeObservation(errno, operation: "read runtime object generation")
  }
  return .known(
    RuntimeObjectIdentity(
      device: fallback.device,
      fileID: fallback.fileID,
      objectType: fallback.objectType,
      generation: .known(UInt64(status.st_gen))
    ))
}

private func runtimeProviderBoundary(
  parentDescriptor: Int32,
  name: Data,
  policy: NoMaterializationPolicy
) -> Observation<ProviderBoundary> {
  switch FileProviderBoundaryProbe().probe(
    parentFileDescriptor: parentDescriptor,
    rawName: name,
    policy: policy
  ) {
  case .evidence(let evidence):
    switch evidence.traversal {
    case .descendMetadataOnlyProviderBoundary:
      return .known(.metadataOnly(reason: evidence.traversal.rawValue))
    case .doNotDescendDataless, .doNotDescendNonDirectory,
      .doNotDescendUnverifiedItemType, .doNotDescendUnverifiedContentState,
      .doNotDescendUnverifiedProviderOwnership:
      return .known(.rejected(reason: evidence.traversal.rawValue))
    }
  case .rejected(let rejection):
    return .unknown(reason: "runtime File Provider probe rejected: \(rejection)")
  }
}

private func posixRuntimeObservation<Value>(
  _ code: Int32,
  operation: String
) -> Observation<Value> where Value: Equatable & Sendable {
  if code == ENOENT { return .absent(reason: "\(operation): missing") }
  if code == EACCES || code == EPERM {
    return .unreadable(reason: "\(operation): permission denied", errorCode: code)
  }
  return .failed(reason: "\(operation): POSIX failure", errorCode: code)
}

private func withNullTerminated<Result>(
  _ data: Data,
  _ body: (UnsafePointer<CChar>) -> Result
) -> Result {
  var bytes = Array(data) + [0]
  return bytes.withUnsafeMutableBytes { raw in
    body(raw.bindMemory(to: CChar.self).baseAddress!)
  }
}
