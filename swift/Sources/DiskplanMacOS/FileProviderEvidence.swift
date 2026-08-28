import CDiskplanMacOS
import Darwin
@preconcurrency import FileProvider
@preconcurrency import Foundation

public enum TraversalDecision: String, Equatable, Sendable {
  case descendMetadataOnlyProviderBoundary
  case doNotDescendDataless
  case doNotDescendNonDirectory
  case doNotDescendUnverifiedItemType
  case doNotDescendUnverifiedContentState
  case doNotDescendUnverifiedProviderOwnership
}

public enum ProviderHandling: String, Equatable, Sendable { case reportOnly }

public struct ProviderIdentity: Equatable, Sendable {
  public let itemIdentifier: String
  public let domainIdentifier: String

  public init(itemIdentifier: String, domainIdentifier: String) {
    self.itemIdentifier = itemIdentifier
    self.domainIdentifier = domainIdentifier
  }
}

public enum ProviderIdentityDisposition: Equatable, Sendable {
  case confirmedProvider
  case identifierAbsent
  case indeterminate(CapabilityStatus)
}

public struct FileObjectIdentity: Equatable, Sendable {
  public let device: Int64
  public let fileID: UInt64
  public let objectType: FileSystemObjectType
}

public enum FileProviderProbeStage: String, Equatable, Sendable {
  case heldParentPreflight
  case derivedParentPreflight
  case preflight
  case derivedPathPreflight
  case identityLookup
  case heldParentPostflight
  case derivedParentPostflight
  case postflight
  case derivedPathPostflight
}

public enum FileProviderProbeRejection: Error, Equatable, Sendable {
  case policyUnavailable(status: CapabilityStatus, detail: String?, errorCode: Int32?)
  case rawNameUnavailable
  case missing(stage: FileProviderProbeStage)
  case unreadable(stage: FileProviderProbeStage, errorCode: Int32?)
  case failed(
    stage: FileProviderProbeStage,
    status: CapabilityStatus,
    detail: String?,
    errorCode: Int32?
  )
  case identityMismatch(
    stage: FileProviderProbeStage,
    expected: FileObjectIdentity,
    observed: FileObjectIdentity
  )
  case parentIdentityMismatch(
    stage: FileProviderProbeStage,
    expected: FileObjectIdentity,
    observed: FileObjectIdentity
  )
  case contentStateUnavailable(
    stage: FileProviderProbeStage,
    status: CapabilityStatus,
    detail: String?,
    errorCode: Int32?
  )
  case contentStateMismatch(
    stage: FileProviderProbeStage,
    expectedDataless: Bool,
    observedDataless: Bool
  )
  case timedOut(stage: FileProviderProbeStage)
}

public struct FileProviderEvidence: Equatable, Sendable {
  public let identity: Capability<ProviderIdentity>
  public let identityDisposition: ProviderIdentityDisposition
  public let providerCapabilities: Capability<[String]>
  public let promisedMetadata: Capability<[String: String]>
  public let traversal: TraversalDecision
  public let handling: ProviderHandling
  public let hiddenBackingBytes: Capability<UInt64>
  public let controlledNonMaterializationAcceptance: Capability<Bool>
}

public enum FileProviderProbeOutcome: Equatable, Sendable {
  case evidence(FileProviderEvidence)
  case rejected(FileProviderProbeRejection)

  public var traversal: TraversalDecision {
    switch self {
    case .evidence(let evidence): evidence.traversal
    case .rejected(.contentStateMismatch), .rejected(.contentStateUnavailable):
      .doNotDescendUnverifiedContentState
    case .rejected: .doNotDescendUnverifiedProviderOwnership
    }
  }

  public var handling: ProviderHandling { .reportOnly }
}

enum ProviderIdentityOperationResult: Equatable, Sendable {
  case known(ProviderIdentity)
  case identifierAbsent
  case rejected(status: CapabilityStatus, detail: String?, errorCode: Int32?)
}

struct FileProviderProbeOperations: Sendable {
  typealias IdentityStarter =
    @Sendable (
      URL,
      @escaping @Sendable (ProviderIdentityOperationResult) -> Void
    ) -> Void
  typealias ItemReader =
    @Sendable (Int32, Data, NoMaterializationPolicy) -> Capability<ItemStorageEvidence>

  let startIdentity: IdentityStarter
  let readItem: ItemReader

  init(
    startIdentity: @escaping IdentityStarter,
    readItem: @escaping ItemReader = FileProviderProbeOperations.productionItemReader
  ) {
    self.startIdentity = startIdentity
    self.readItem = readItem
  }

  private static let productionItemReader: ItemReader = {
    parentFileDescriptor, rawName, policy in
    ItemProbe().probe(
      parentFileDescriptor: parentFileDescriptor,
      rawName: rawName,
      policy: policy
    )
  }

  static let production = Self(
    startIdentity: { url, completion in
      NSFileProviderManager.getIdentifierForUserVisibleFile(at: url) {
        itemIdentifier, domainIdentifier, error in
        if let itemIdentifier, let domainIdentifier {
          completion(
            .known(
              ProviderIdentity(
                itemIdentifier: itemIdentifier.rawValue,
                domainIdentifier: domainIdentifier.rawValue
              )
            )
          )
        } else if let error = error as NSError? {
          if error.domain == NSCocoaErrorDomain, error.code == NSFileNoSuchFileError {
            completion(.identifierAbsent)
          } else if error.domain == NSCocoaErrorDomain,
            error.code == NSFileReadNoPermissionError
          {
            completion(
              .rejected(
                status: .permissionDenied,
                detail: "File Provider identity denied",
                errorCode: Int32(clamping: error.code)
              )
            )
          } else {
            completion(
              .rejected(
                status: .failed,
                detail: "File Provider identity lookup failed",
                errorCode: Int32(clamping: error.code)
              )
            )
          }
        } else {
          completion(
            .rejected(
              status: .inconsistent,
              detail: "File Provider identity callback was empty",
              errorCode: nil
            )
          )
        }
      }
    },
    readItem: productionItemReader
  )
}

final class DeadlineResultBox<Value: Sendable>: @unchecked Sendable {
  private let lock = NSLock()
  private let semaphore = DispatchSemaphore(value: 0)
  private var accepting = true
  private var value: Value?

  func complete(_ value: Value) {
    let accepted = lock.withLock { () -> Bool in
      guard accepting, self.value == nil else { return false }
      self.value = value
      return true
    }
    if accepted { semaphore.signal() }
  }

  func wait(
    until deadline: DispatchTime,
    onTimedOutBeforeClose: (() -> Void)? = nil
  ) -> Value? {
    if semaphore.wait(timeout: deadline) == .success {
      return lock.withLock {
        accepting = false
        return value
      }
    }
    onTimedOutBeforeClose?()
    lock.withLock {
      accepting = false
      value = nil
    }
    return nil
  }
}

private struct OperationDeadline: Sendable {
  let dispatchTime: DispatchTime

  init(timeout: Duration) {
    let nanoseconds = Self.nanoseconds(timeout)
    let now = DispatchTime.now().uptimeNanoseconds
    let (sum, overflow) = now.addingReportingOverflow(nanoseconds)
    dispatchTime = DispatchTime(uptimeNanoseconds: overflow ? UInt64.max : sum)
  }

  private static func nanoseconds(_ duration: Duration) -> UInt64 {
    guard duration > .zero else { return 0 }
    let components = duration.components
    guard components.seconds >= 0, components.attoseconds >= 0 else { return 0 }
    let seconds = UInt64(components.seconds)
    let (whole, overflow) = seconds.multipliedReportingOverflow(by: 1_000_000_000)
    if overflow { return UInt64.max }
    let fractional = UInt64(components.attoseconds / 1_000_000_000)
    let (total, additionOverflow) = whole.addingReportingOverflow(fractional)
    return additionOverflow ? UInt64.max : total
  }
}

private struct DerivedSlot: Sendable {
  let url: URL
  let parentURL: URL
  let heldParentIdentity: FileObjectIdentity
}

private struct ProbedItem: Sendable {
  let evidence: ItemStorageEvidence
  let identity: FileObjectIdentity
  let isDataless: Bool
}

public struct FileProviderBoundaryProbe: Sendable {
  private let operations: FileProviderProbeOperations

  public init() { operations = .production }

  init(operations: FileProviderProbeOperations) { self.operations = operations }

  public func probe(
    parentFileDescriptor: Int32,
    rawName: Data,
    policy: NoMaterializationPolicy,
    inheritedProviderBoundary: Bool = false,
    timeout: Duration = .seconds(2)
  ) -> FileProviderProbeOutcome {
    let initialPolicy = policy.revalidateLive()
    guard let livePolicy = initialPolicy.value else {
      return .rejected(policyRejection(initialPolicy))
    }

    let preflight = probeItem(
      parentFileDescriptor: parentFileDescriptor,
      rawName: rawName,
      policy: livePolicy,
      stage: .preflight
    )
    guard case .success(let before) = preflight else {
      return .rejected(preflight.failure!)
    }

    guard String(data: rawName, encoding: .utf8) != nil else {
      return .rejected(.rawNameUnavailable)
    }
    let derived = deriveAndValidateSlot(
      heldParentFileDescriptor: parentFileDescriptor,
      rawName: rawName,
      expected: before,
      isDirectory: before.evidence.objectType.value == .directory,
      policy: livePolicy
    )
    guard case .success(let slot) = derived else {
      return .rejected(derived.failure!)
    }

    let operationResult = runIdentityOperation(
      url: slot.url,
      policy: livePolicy,
      deadline: OperationDeadline(timeout: timeout)
    )

    let postflight = probeItem(
      parentFileDescriptor: parentFileDescriptor,
      rawName: rawName,
      policy: livePolicy,
      stage: .postflight
    )
    guard case .success(let after) = postflight else {
      return .rejected(postflight.failure!)
    }
    guard before.identity == after.identity else {
      return .rejected(
        .identityMismatch(
          stage: .postflight,
          expected: before.identity,
          observed: after.identity
        )
      )
    }
    if let mismatch = contentStateMismatch(
      expected: before,
      observed: after,
      stage: .postflight
    ) {
      return .rejected(mismatch)
    }

    let derivedPostflight = validateDerivedSlot(
      slot,
      heldParentFileDescriptor: parentFileDescriptor,
      rawName: rawName,
      expected: after,
      policy: livePolicy,
      heldParentStage: .heldParentPostflight,
      derivedParentStage: .derivedParentPostflight,
      itemStage: .derivedPathPostflight
    )
    if case .failure(let failure) = derivedPostflight { return .rejected(failure) }

    switch operationResult {
    case .failure(let failure):
      return .rejected(failure)
    case .success(let result):
      let disposition = identityDisposition(result)
      let decision = Self.decideBoundary(
        item: after.evidence,
        identityDisposition: disposition,
        inheritedProviderBoundary: inheritedProviderBoundary
      )
      return .evidence(
        FileProviderEvidence(
          identity: identityCapability(result),
          identityDisposition: disposition,
          providerCapabilities: .unavailable(
            "capabilities for an arbitrary File Provider domain are not exposed by public API"
          ),
          promisedMetadata: .unavailable(
            "in-process metadata coordination is disabled because a timed-out accessor cannot be killed and reaped safely"
          ),
          traversal: decision.traversal,
          handling: decision.handling,
          hiddenBackingBytes: .unavailable("unavailable via public API"),
          controlledNonMaterializationAcceptance: .unavailable(
            "requires the controlled File Provider extension fixture on India-mac-mini-m4-hoteng"
          )
        )
      )
    }
  }

  public static func decideBoundary(
    item: ItemStorageEvidence,
    identityDisposition: ProviderIdentityDisposition,
    inheritedProviderBoundary: Bool = false
  ) -> (traversal: TraversalDecision, handling: ProviderHandling) {
    guard let objectType = item.objectType.value else {
      return (.doNotDescendUnverifiedItemType, .reportOnly)
    }
    guard objectType == .directory else {
      return (.doNotDescendNonDirectory, .reportOnly)
    }
    guard let isDataless = item.isDataless.value else {
      return (.doNotDescendUnverifiedContentState, .reportOnly)
    }
    if isDataless {
      return (.doNotDescendDataless, .reportOnly)
    }
    let providerBound =
      inheritedProviderBoundary || item.isSyncRoot.value == true
      || identityDisposition == .confirmedProvider
    if providerBound { return (.descendMetadataOnlyProviderBoundary, .reportOnly) }
    return (.doNotDescendUnverifiedProviderOwnership, .reportOnly)
  }

  private func runIdentityOperation(
    url: URL,
    policy: NoMaterializationPolicy,
    deadline: OperationDeadline
  ) -> Result<ProviderIdentityOperationResult, FileProviderProbeRejection> {
    let identityPolicy = policy.revalidateLive()
    guard identityPolicy.value != nil else { return .failure(policyRejection(identityPolicy)) }
    let identityBox = DeadlineResultBox<ProviderIdentityOperationResult>()
    operations.startIdentity(url) { result in identityBox.complete(result) }
    guard let identity = identityBox.wait(until: deadline.dispatchTime) else {
      return .failure(.timedOut(stage: .identityLookup))
    }
    return .success(identity)
  }

  private func identityCapability(
    _ result: ProviderIdentityOperationResult
  ) -> Capability<ProviderIdentity> {
    switch result {
    case .known(let identity): return .known(identity)
    case .identifierAbsent:
      return .unavailable(
        "File Provider identifier is absent; the item may still be provider-owned"
      )
    case .rejected(let status, let detail, let errorCode):
      return Capability(status: status, detail: detail, errorCode: errorCode)
    }
  }

  private func identityDisposition(
    _ result: ProviderIdentityOperationResult
  ) -> ProviderIdentityDisposition {
    switch result {
    case .known: .confirmedProvider
    case .identifierAbsent: .identifierAbsent
    case .rejected(let status, _, _): .indeterminate(status)
    }
  }

  private func probeItem(
    parentFileDescriptor: Int32,
    rawName: Data,
    policy: NoMaterializationPolicy,
    stage: FileProviderProbeStage
  ) -> Result<
    ProbedItem, FileProviderProbeRejection
  > {
    let result = operations.readItem(parentFileDescriptor, rawName, policy)
    guard let evidence = result.value else {
      return .failure(rejection(for: result, stage: stage))
    }
    guard let device = evidence.device.value else {
      return .failure(
        .failed(
          stage: stage,
          status: requiredFieldStatus(evidence.device.status),
          detail: evidence.device.detail ?? "real device identity is required for URL binding",
          errorCode: evidence.device.errorCode
        )
      )
    }
    guard let fileID = evidence.fileID.value else {
      return .failure(
        .failed(
          stage: stage,
          status: requiredFieldStatus(evidence.fileID.status),
          detail: evidence.fileID.detail ?? "file ID is required for URL binding",
          errorCode: evidence.fileID.errorCode
        )
      )
    }
    guard let objectType = evidence.objectType.value else {
      return .failure(
        .failed(
          stage: stage,
          status: requiredFieldStatus(evidence.objectType.status),
          detail: evidence.objectType.detail ?? "object type is required for URL binding",
          errorCode: evidence.objectType.errorCode
        )
      )
    }
    guard let isDataless = evidence.isDataless.value else {
      let status =
        evidence.isDataless.status == .known ? .inconsistent : evidence.isDataless.status
      return .failure(
        .contentStateUnavailable(
          stage: stage,
          status: status,
          detail: evidence.isDataless.detail ?? "dataless state is required for safe probing",
          errorCode: evidence.isDataless.errorCode
        )
      )
    }
    return .success(
      ProbedItem(
        evidence: evidence,
        identity: FileObjectIdentity(device: device, fileID: fileID, objectType: objectType),
        isDataless: isDataless
      )
    )
  }

  private func probeFDIdentity(
    fileDescriptor: Int32,
    policy: NoMaterializationPolicy,
    stage: FileProviderProbeStage
  ) -> Result<FileObjectIdentity, FileProviderProbeRejection> {
    let livePolicy = policy.revalidateLive()
    guard livePolicy.value != nil else { return .failure(policyRejection(livePolicy)) }
    var raw = dp_fd_identity_v1()
    guard dp_probe_fd_identity(fileDescriptor, &raw) == 0 else {
      return .failure(posixRejection(errno, stage: stage))
    }
    let common = raw.returned_common
    guard common & dp_attr_common_device() != 0 else {
      return .failure(
        .failed(
          stage: stage,
          status: .unavailable,
          detail: "real parent device identity was not returned",
          errorCode: nil
        )
      )
    }
    guard common & dp_attr_common_file_id() != 0 else {
      return .failure(
        .failed(
          stage: stage,
          status: .unavailable,
          detail: "parent file ID was not returned",
          errorCode: nil
        )
      )
    }
    guard common & dp_attr_common_object_type() != 0 else {
      return .failure(
        .failed(
          stage: stage,
          status: .unavailable,
          detail: "parent object type was not returned",
          errorCode: nil
        )
      )
    }
    let objectType = FileSystemObjectType(rawKernelValue: raw.object_type)
    guard objectType == .directory else {
      return .failure(
        .failed(
          stage: stage,
          status: .inconsistent,
          detail: "bound parent descriptor does not identify a directory",
          errorCode: nil
        )
      )
    }
    return .success(
      FileObjectIdentity(
        device: raw.real_device,
        fileID: raw.file_id,
        objectType: objectType
      )
    )
  }

  func rejection<Value: Equatable & Sendable>(
    for capability: Capability<Value>,
    stage: FileProviderProbeStage
  ) -> FileProviderProbeRejection {
    if capability.errorCode == ENOENT { return .missing(stage: stage) }
    if capability.status == .permissionDenied || capability.errorCode == EACCES
      || capability.errorCode == EPERM
    {
      return .unreadable(stage: stage, errorCode: capability.errorCode)
    }
    return .failed(
      stage: stage,
      status: capability.status,
      detail: capability.detail,
      errorCode: capability.errorCode
    )
  }

  private func deriveAndValidateSlot(
    heldParentFileDescriptor: Int32,
    rawName: Data,
    expected: ProbedItem,
    isDirectory: Bool,
    policy: NoMaterializationPolicy
  ) -> Result<DerivedSlot, FileProviderProbeRejection> {
    let heldParent = probeFDIdentity(
      fileDescriptor: heldParentFileDescriptor,
      policy: policy,
      stage: .heldParentPreflight
    )
    guard case .success(let heldParentIdentity) = heldParent else {
      return .failure(heldParent.failure!)
    }
    let pathPolicy = policy.revalidateLive()
    guard pathPolicy.value != nil else { return .failure(policyRejection(pathPolicy)) }
    var parentPath = [CChar](repeating: 0, count: Int(MAXPATHLEN))
    guard fcntl(heldParentFileDescriptor, F_GETPATH, &parentPath) == 0 else {
      return .failure(posixRejection(errno, stage: .derivedParentPreflight))
    }
    let parentURL = parentPath.withUnsafeBufferPointer { buffer in
      URL(
        fileURLWithFileSystemRepresentation: buffer.baseAddress!,
        isDirectory: true,
        relativeTo: nil
      )
    }
    guard let name = String(data: rawName, encoding: .utf8) else {
      return .failure(.rawNameUnavailable)
    }
    let url = parentURL.appendingPathComponent(name, isDirectory: isDirectory)
    guard filesystemRepresentation(of: url) == expectedChildPath(parentPath, rawName: rawName)
    else {
      return .failure(.rawNameUnavailable)
    }
    let slot = DerivedSlot(
      url: url,
      parentURL: parentURL,
      heldParentIdentity: heldParentIdentity
    )
    return validateDerivedSlot(
      slot,
      heldParentFileDescriptor: heldParentFileDescriptor,
      rawName: rawName,
      expected: expected,
      policy: policy,
      heldParentStage: .heldParentPreflight,
      derivedParentStage: .derivedParentPreflight,
      itemStage: .derivedPathPreflight
    ).map { slot }
  }

  private func validateDerivedSlot(
    _ slot: DerivedSlot,
    heldParentFileDescriptor: Int32,
    rawName: Data,
    expected: ProbedItem,
    policy: NoMaterializationPolicy,
    heldParentStage: FileProviderProbeStage,
    derivedParentStage: FileProviderProbeStage,
    itemStage: FileProviderProbeStage
  ) -> Result<Void, FileProviderProbeRejection> {
    let heldParent = probeFDIdentity(
      fileDescriptor: heldParentFileDescriptor,
      policy: policy,
      stage: heldParentStage
    )
    guard case .success(let observedHeldParent) = heldParent else {
      return .failure(heldParent.failure!)
    }
    guard observedHeldParent == slot.heldParentIdentity else {
      return .failure(
        .parentIdentityMismatch(
          stage: heldParentStage,
          expected: slot.heldParentIdentity,
          observed: observedHeldParent
        )
      )
    }
    let pathPolicy = policy.revalidateLive()
    guard pathPolicy.value != nil else { return .failure(policyRejection(pathPolicy)) }
    let pathFD = slot.parentURL.withUnsafeFileSystemRepresentation { representation -> Int32 in
      guard let representation else { return -1 }
      return open(representation, O_EVTONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard pathFD >= 0 else {
      return .failure(posixRejection(errno, stage: derivedParentStage))
    }
    defer { close(pathFD) }
    let derivedParent = probeFDIdentity(
      fileDescriptor: pathFD,
      policy: policy,
      stage: derivedParentStage
    )
    guard case .success(let observedDerivedParent) = derivedParent else {
      return .failure(derivedParent.failure!)
    }
    guard observedDerivedParent == slot.heldParentIdentity else {
      return .failure(
        .parentIdentityMismatch(
          stage: derivedParentStage,
          expected: slot.heldParentIdentity,
          observed: observedDerivedParent
        )
      )
    }
    let result = probeItem(
      parentFileDescriptor: pathFD,
      rawName: rawName,
      policy: policy,
      stage: itemStage
    )
    guard case .success(let observed) = result else { return .failure(result.failure!) }
    guard observed.identity == expected.identity else {
      return .failure(
        .identityMismatch(
          stage: itemStage,
          expected: expected.identity,
          observed: observed.identity
        )
      )
    }
    if let mismatch = contentStateMismatch(
      expected: expected,
      observed: observed,
      stage: itemStage
    ) {
      return .failure(mismatch)
    }
    return .success(())
  }

  private func contentStateMismatch(
    expected: ProbedItem,
    observed: ProbedItem,
    stage: FileProviderProbeStage
  ) -> FileProviderProbeRejection? {
    guard expected.isDataless != observed.isDataless else { return nil }
    return .contentStateMismatch(
      stage: stage,
      expectedDataless: expected.isDataless,
      observedDataless: observed.isDataless
    )
  }

  private func requiredFieldStatus(_ status: CapabilityStatus) -> CapabilityStatus {
    status == .known ? .inconsistent : status
  }

  private func policyRejection(
    _ capability: Capability<NoMaterializationPolicy>
  ) -> FileProviderProbeRejection {
    .policyUnavailable(
      status: capability.status,
      detail: capability.detail,
      errorCode: capability.errorCode
    )
  }

  func posixRejection(
    _ code: Int32,
    stage: FileProviderProbeStage
  ) -> FileProviderProbeRejection {
    if code == ENOENT { return .missing(stage: stage) }
    if code == EACCES || code == EPERM { return .unreadable(stage: stage, errorCode: code) }
    return .failed(
      stage: stage,
      status: .failed,
      detail: "derive or reopen descriptor-bound File Provider URL",
      errorCode: code
    )
  }

  private func filesystemRepresentation(of url: URL) -> Data? {
    url.withUnsafeFileSystemRepresentation { representation in
      guard let representation else { return nil }
      return Data(bytes: representation, count: strlen(representation))
    }
  }

  private func expectedChildPath(_ parent: [CChar], rawName: Data) -> Data {
    let parentLength = parent.firstIndex(of: 0) ?? parent.count
    var result = parent.withUnsafeBytes { Data($0.prefix(parentLength)) }
    if result.last != UInt8(ascii: "/") { result.append(UInt8(ascii: "/")) }
    result.append(rawName)
    return result
  }
}

extension Result {
  fileprivate var failure: Failure? {
    if case .failure(let failure) = self { return failure }
    return nil
  }
}
