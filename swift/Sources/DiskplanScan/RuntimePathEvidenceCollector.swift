import CryptoKit
import Darwin
import DiskplanMacOS
import Foundation

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

/// Scan-private descriptor/content machinery. The enclosing RuntimeEvidenceSession owns its
/// epoch and exposes it only through the session's opaque capture lease.
final class RuntimePathEvidenceCollector: @unchecked Sendable {
  typealias DescriptorCloser = @Sendable (Int32) -> Void

  private let policy: NoMaterializationPolicy
  private let contentAuthority: ScannerContentCollectionAuthority
  private let filesystem: DarwinScanFilesystem
  private let descriptorCloser: DescriptorCloser

  convenience init(policy: NoMaterializationPolicy, contentBudget: ContentCollectionBudget) {
    self.init(
      policy: policy,
      contentBudget: contentBudget,
      descriptorCloser: runtimeDescriptorClose
    )
  }

  /// Test-only descriptor ownership seam; provider admission stays concrete.
  convenience init(
    policy: NoMaterializationPolicy,
    contentBudget: ContentCollectionBudget,
    testingDescriptorCloser: @escaping DescriptorCloser
  ) {
    self.init(
      policy: policy,
      contentBudget: contentBudget,
      descriptorCloser: testingDescriptorCloser
    )
  }

  private init(
    policy: NoMaterializationPolicy,
    contentBudget: ContentCollectionBudget,
    descriptorCloser: @escaping DescriptorCloser
  ) {
    self.policy = policy
    contentAuthority = ScannerContentCollectionAuthority(policy: policy, budget: contentBudget)
    filesystem = DarwinScanFilesystem(policy: policy)
    self.descriptorCloser = descriptorCloser
  }

  func advanceEpoch() -> Bool { contentAuthority.advanceEpoch() }

  func close() { contentAuthority.close() }

  func collectPaths(
    _ requests: [RuntimePathEvidenceRequest],
    checkActive: () throws -> Void
  ) throws -> [RuntimePathEvidence] {
    var result: [RuntimePathEvidence] = []
    result.reserveCapacity(requests.count)
    for request in requests {
      try checkActive()
      result.append(try collectPath(request, checkActive: checkActive))
    }
    try checkActive()
    return result
  }

  func collectTransferredDescriptors(
    _ request: RuntimeTransferredDescriptorRequest,
    checkActive: () throws -> Void
  ) throws -> RuntimePathEvidence {
    let descriptors =
      [request.rootDescriptor] + request.parentDescriptors + [request.targetDescriptor]
    var ownsDescriptors = true
    defer {
      if ownsDescriptors {
        for descriptor in Set(descriptors) where descriptor >= 0 {
          descriptorCloser(descriptor)
        }
      }
    }
    try checkActive()
    guard !request.targetComponents.isEmpty,
      request.parentDescriptors.count == request.targetComponents.count - 1,
      descriptors.allSatisfy({ $0 >= 0 }),
      Set(descriptors).count == descriptors.count,
      validRuntimeComponents(request.targetComponents)
    else { throw RuntimeEvidenceSessionError.invalidDescriptorSet }

    let root = namespaceEvidence(
      descriptor: request.rootDescriptor,
      provider: .known(.localOrUnindicated)
    )
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
      descriptorCloser(descriptor)
    }
    try checkActive()
    return RuntimePathEvidence(target: target, root: root, parents: parents)
  }

  private func collectPath(
    _ request: RuntimePathEvidenceRequest,
    checkActive: () throws -> Void
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
          content: runtimeContentFailure(
            rootObservation,
            fallbackReason: "runtime root binding unavailable"
          ),
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

    var current = boundRoot.directory
    for rawComponent in request.targetComponents.dropLast() {
      try checkActive()
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
        return closeBoundNamespaces(
          failedPathEvidence(
            root: namespaceEvidenceValues[0],
            parents: Array(namespaceEvidenceValues.dropFirst()),
            failure: failure,
            reason: "runtime parent binding unavailable"
          ),
          directories: openedDirectories
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
        return closeBoundNamespaces(
          failedPathEvidence(
            root: namespaceEvidenceValues[0],
            parents: Array(namespaceEvidenceValues.dropFirst()),
            failure: failure,
            reason: "runtime parent descriptor unavailable"
          ),
          directories: openedDirectories
        )
      }
      openedDirectories.append(directory)
      current = directory
      namespaceEvidenceValues.append(
        RuntimeNamespaceEvidence(
          identity: runtimeIdentity(descriptor: directory.handle.rawValue, fallback: item.identity),
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
      return closeBoundNamespaces(
        failedPathEvidence(
          root: namespaceEvidenceValues[0],
          parents: Array(namespaceEvidenceValues.dropFirst()),
          failure: inspected.erasingValue(),
          reason: "runtime target inspection unavailable"
        ),
        directories: openedDirectories
      )
    }
    let targetDescriptor = withNullTerminated(rawLeaf) {
      Darwin.openat(current.handle.rawValue, $0, runtimeOpenFlags(item.identity.objectType))
    }
    guard targetDescriptor >= 0 else {
      return closeBoundNamespaces(
        failedPathEvidence(
          root: namespaceEvidenceValues[0],
          parents: Array(namespaceEvidenceValues.dropFirst()),
          failure: posixRuntimeObservation(errno, operation: "open runtime target"),
          reason: "runtime target descriptor unavailable"
        ),
        directories: openedDirectories
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
      provider: .known(item.providerBoundary),
      requiresContent: request.requiresContent
    )
    return closeBoundNamespaces(
      RuntimePathEvidence(
        target: target,
        root: namespaceEvidenceValues[0],
        parents: Array(namespaceEvidenceValues.dropFirst())
      ),
      directories: openedDirectories
    )
  }

  private func closeBoundNamespaces(
    _ evidence: RuntimePathEvidence,
    directories: [BoundDirectory]
  ) -> RuntimePathEvidence {
    var namespaces = [evidence.root] + evidence.parents
    for index in directories.indices.reversed() {
      let provider = revalidateProviderBoundary(directories[index])
      let closeEvidence = filesystem.close(directories[index])
      guard index < namespaces.count else { continue }
      let prior = namespaces[index]
      namespaces[index] = RuntimeNamespaceEvidence(
        identity: revalidatedRuntimeIdentity(closeEvidence.identity, prior: prior.identity),
        accessPolicy: closeEvidence.accessPolicy,
        providerBoundary: provider,
        mountDevice: prior.mountDevice
      )
    }
    return RuntimePathEvidence(
      target: evidence.target,
      root: namespaces[0],
      parents: Array(namespaces.dropFirst())
    )
  }

  private func revalidateProviderBoundary(
    _ directory: BoundDirectory
  ) -> Observation<ProviderBoundary> {
    switch directory.slotBinding.namespace {
    case .canonicalFilesystemRoot:
      return .known(.localOrUnindicated)
    case .parentSlot(let parent, let name, _):
      return runtimeProviderBoundary(
        parentDescriptor: parent.rawValue,
        name: name.bytes,
        policy: policy
      )
    }
  }

  private func protectedObjectEvidence(
    transferring targetDescriptor: Int32,
    path: RawPath,
    rootDescriptor: Int32,
    targetParentDescriptor: Int32,
    rawLeaf: Data,
    provider: Observation<ProviderBoundary>,
    requiresContent: Bool
  ) -> RuntimeProtectedObjectEvidence {
    guard let targetSeal = descriptorSeal(fileDescriptor: targetDescriptor, policy: policy) else {
      let code = errno
      descriptorCloser(targetDescriptor)
      let failed: Observation<RuntimeObjectIdentity> = posixRuntimeObservation(
        code, operation: "seal runtime target")
      return RuntimeProtectedObjectEvidence(
        identity: failed,
        content: runtimeContentFailure(
          failed,
          fallbackReason: "runtime target seal unavailable"
        ),
        accessPolicy: failed.erasingValue(),
        providerBoundary: provider,
        mountDevice: failed.erasingValue()
      )
    }
    let targetIdentity = runtimeIdentity(descriptor: targetDescriptor, fallback: targetSeal.identity)
    let rootSeal = descriptorSeal(fileDescriptor: rootDescriptor, policy: policy)
    let content: ContentEvidence
    if !requiresContent {
      descriptorCloser(targetDescriptor)
      content = .notApplicable(.planContractDoesNotRequireContent)
    } else if targetSeal.identity.objectType != .regular {
      descriptorCloser(targetDescriptor)
      content = .notApplicable(.notRegularFile)
    } else {
      let consumer = contentAuthority.evidenceConsumer
      let currentSlot: @Sendable () -> Observation<InspectedObject> = {
        [filesystem, targetParentDescriptor, rawLeaf, provider] in
        filesystem.inspect(
          parent: DirectoryHandle(rawValue: targetParentDescriptor),
          name: RawPathComponent(rawLeaf),
          inheritedProviderBoundary: provider.value?.isProviderManaged ?? false,
          requiresAuthoritativeProviderEvidence: true
        )
      }
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
        slotIdentityObservation: {
          let inspected = currentSlot()
          guard let current = inspected.value else {
            return inspected.erasingValue() as Observation<ObjectIdentity>
          }
          return .known(current.identity)
        },
        slotAccessPolicyObservation: {
          let inspected = currentSlot()
          guard let current = inspected.value else {
            return inspected.erasingValue() as Observation<AccessPolicyEvidence>
          }
          return current.accessPolicy
        },
        providerObservation: { [policy] in
          runtimeProviderBoundary(
            parentDescriptor: targetParentDescriptor,
            name: rawLeaf,
            policy: policy
          )
        }
      )
      switch registration {
      case .known(let requestID): content = consumer.collect(requestID)
      case .absent(let reason): content = .absent(reason: reason)
      case .unknown(let reason): content = .unknown(reason: reason)
      case .unreadable(let reason, let code):
        content = .unreadable(reason: reason, errorCode: code)
      case .failed(let reason, let code):
        content = .failed(reason: reason, errorCode: code)
      }
    }
    return RuntimeProtectedObjectEvidence(
      identity: targetIdentity,
      content: content,
      accessPolicy: .known(targetSeal.accessPolicy),
      providerBoundary: provider,
      mountDevice: .known(targetSeal.identity.device)
    )
  }

  private func namespaceEvidence(
    descriptor: Int32,
    provider: Observation<ProviderBoundary>
  ) -> RuntimeNamespaceEvidence {
    guard let seal = descriptorSeal(fileDescriptor: descriptor, policy: policy) else {
      let failed: Observation<RuntimeObjectIdentity> = posixRuntimeObservation(
        errno, operation: "seal runtime namespace")
      return RuntimeNamespaceEvidence(
        identity: failed,
        accessPolicy: failed.erasingValue(),
        providerBoundary: provider,
        mountDevice: failed.erasingValue()
      )
    }
    return RuntimeNamespaceEvidence(
      identity: runtimeIdentity(descriptor: descriptor, fallback: seal.identity),
      accessPolicy: .known(seal.accessPolicy),
      providerBoundary: provider,
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
        content: runtimeContentFailure(failure, fallbackReason: reason),
        accessPolicy: failure.erasingValue(),
        providerBoundary: failure.erasingValue(),
        mountDevice: failure.erasingValue()
      ),
      root: root,
      parents: parents
    )
  }

  private func providerBoundary(
    parentDescriptor: Int32,
    name: Data
  ) -> Observation<ProviderBoundary> {
    runtimeProviderBoundary(parentDescriptor: parentDescriptor, name: name, policy: policy)
  }
}

private func runtimeContentFailure<Value>(
  _ observation: Observation<Value>,
  fallbackReason: String
) -> ContentEvidence where Value: Equatable & Sendable {
  switch observation {
  case .known: return .unknown(reason: fallbackReason)
  case .absent(let reason): return .absent(reason: reason)
  case .unknown(let reason): return .unknown(reason: reason)
  case .unreadable(let reason, let code): return .unreadable(reason: reason, errorCode: code)
  case .failed(let reason, let code): return .failed(reason: reason, errorCode: code)
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

private func revalidatedRuntimeIdentity(
  _ closeObservation: Observation<ObjectIdentity>,
  prior: Observation<RuntimeObjectIdentity>
) -> Observation<RuntimeObjectIdentity> {
  switch closeObservation {
  case .known(let current):
    guard case .known(let expected) = prior,
      current.device == expected.device,
      current.fileID == expected.fileID,
      current.objectType == expected.objectType
    else {
      return .failed(
        reason: "runtime namespace identity changed before descriptor close",
        errorCode: ESTALE
      )
    }
    return prior
  case .absent(let reason): return .absent(reason: reason)
  case .unknown(let reason): return .unknown(reason: reason)
  case .unreadable(let reason, let code): return .unreadable(reason: reason, errorCode: code)
  case .failed(let reason, let code): return .failed(reason: reason, errorCode: code)
  }
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

private func runtimeDescriptorClose(_ descriptor: Int32) {
  Darwin.close(descriptor)
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
