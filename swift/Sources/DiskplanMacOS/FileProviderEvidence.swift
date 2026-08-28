@preconcurrency import FileProvider
@preconcurrency import Foundation

public enum TraversalDecision: String, Equatable, Sendable {
  case descendLocal
  case descendMetadataOnlyProviderBoundary
  case doNotDescendDataless
  case doNotDescendUnverifiedProviderOwnership
}

public enum ProviderHandling: String, Equatable, Sendable {
  case normal
  case reportOnly
}

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
  case confirmedLocal
  case indeterminate(CapabilityStatus)
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

public struct FileProviderBoundaryProbe: Sendable {
  public init() {}

  public func probe(
    url: URL,
    item: ItemStorageEvidence,
    policy: NoMaterializationPolicy,
    inheritedProviderBoundary: Bool = false,
    callbackTimeout: Duration = .seconds(2)
  ) -> FileProviderEvidence {
    _ = policy
    let identity = providerIdentity(at: url, timeout: callbackTimeout)
    let identityDisposition = Self.identityDisposition(for: identity)
    let promisedMetadata = metadataOnly(at: url)
    let decision = Self.decideBoundary(
      item: item,
      identityDisposition: identityDisposition,
      inheritedProviderBoundary: inheritedProviderBoundary
    )
    return FileProviderEvidence(
      identity: identity,
      identityDisposition: identityDisposition,
      providerCapabilities: .unavailable(
        "capabilities for an arbitrary File Provider domain are not exposed by public API"
      ),
      promisedMetadata: promisedMetadata,
      traversal: decision.traversal,
      handling: decision.handling,
      hiddenBackingBytes: .unavailable("unavailable via public API"),
      controlledNonMaterializationAcceptance: .unavailable(
        "requires the controlled File Provider extension fixture on India-mac-mini-m4-hoteng"
      )
    )
  }

  public static func decideBoundary(
    item: ItemStorageEvidence,
    identityDisposition: ProviderIdentityDisposition,
    inheritedProviderBoundary: Bool = false
  ) -> (traversal: TraversalDecision, handling: ProviderHandling) {
    let dataless = item.isDataless.value == true
    let syncRoot = item.isSyncRoot.value == true
    let providerBound =
      inheritedProviderBoundary || syncRoot || dataless
      || identityDisposition == .confirmedProvider
    if dataless, item.objectType.value == .directory {
      return (.doNotDescendDataless, .reportOnly)
    }
    if providerBound {
      return (.descendMetadataOnlyProviderBoundary, .reportOnly)
    }
    switch identityDisposition {
    case .confirmedLocal:
      return (.descendLocal, .normal)
    case .confirmedProvider:
      return (.descendMetadataOnlyProviderBoundary, .reportOnly)
    case .indeterminate:
      return (.doNotDescendUnverifiedProviderOwnership, .reportOnly)
    }
  }

  public static func identityDisposition(
    for identity: Capability<ProviderIdentity>
  ) -> ProviderIdentityDisposition {
    switch identity.status {
    case .known:
      return .confirmedProvider
    case .unsupported:
      // providerIdentity(at:) reserves unsupported for NSFileNoSuchFileError,
      // the public API's authoritative "not provider-owned" result.
      return .confirmedLocal
    case .permissionDenied, .unavailable, .failed, .inconsistent:
      return .indeterminate(identity.status)
    }
  }

  private func providerIdentity(
    at url: URL,
    timeout: Duration
  ) -> Capability<ProviderIdentity> {
    final class Box: @unchecked Sendable {
      let lock = NSLock()
      var value: Capability<ProviderIdentity>?
    }
    let box = Box()
    let signal = DispatchSemaphore(value: 0)
    NSFileProviderManager.getIdentifierForUserVisibleFile(at: url) {
      itemIdentifier, domainIdentifier, error in
      let result: Capability<ProviderIdentity>
      if let itemIdentifier, let domainIdentifier {
        result = .known(
          ProviderIdentity(
            itemIdentifier: itemIdentifier.rawValue,
            domainIdentifier: domainIdentifier.rawValue
          )
        )
      } else if let error = error as NSError? {
        if error.domain == NSCocoaErrorDomain,
          error.code == NSFileNoSuchFileError
        {
          result = Capability(status: .unsupported, detail: "URL is not owned by a File Provider")
        } else if error.domain == NSCocoaErrorDomain,
          error.code == NSFileReadNoPermissionError
        {
          result = Capability(status: .permissionDenied, detail: "File Provider identity denied")
        } else {
          result = Capability(
            status: .failed,
            detail: "File Provider identity lookup failed",
            errorCode: Int32(clamping: error.code)
          )
        }
      } else {
        result = Capability(
          status: .inconsistent, detail: "File Provider identity callback was empty")
      }
      box.lock.withLock { box.value = result }
      signal.signal()
    }
    let seconds = max(0, timeout.components.seconds)
    guard signal.wait(timeout: .now() + .seconds(Int(seconds))) == .success else {
      return Capability(status: .unavailable, detail: "File Provider identity callback timed out")
    }
    return box.lock.withLock {
      box.value
        ?? Capability(status: .inconsistent, detail: "File Provider callback result was lost")
    }
  }

  private func metadataOnly(at url: URL) -> Capability<[String: String]> {
    let coordinator = NSFileCoordinator(filePresenter: nil)
    var coordinationError: NSError?
    var result: Capability<[String: String]>?
    coordinator.coordinate(
      readingItemAt: url,
      options: .immediatelyAvailableMetadataOnly,
      error: &coordinationError
    ) { coordinatedURL in
      do {
        let values = try (coordinatedURL as NSURL).promisedItemResourceValues(
          forKeys: [.isDirectoryKey, .fileSizeKey, .isUbiquitousItemKey]
        )
        var metadata: [String: String] = [:]
        if let value = values[.isDirectoryKey] as? NSNumber {
          metadata["is_directory"] = value.boolValue.description
        }
        if let value = values[.fileSizeKey] as? NSNumber {
          metadata["file_size"] = value.uint64Value.description
        }
        if let value = values[.isUbiquitousItemKey] as? NSNumber {
          metadata["is_ubiquitous"] = value.boolValue.description
        }
        result = .known(metadata)
      } catch let error as NSError {
        result = Self.foundationFailure(error, operation: "promised metadata lookup")
      }
    }
    if let result { return result }
    if let coordinationError {
      return Self.foundationFailure(coordinationError, operation: "metadata-only coordination")
    }
    return Capability(
      status: .inconsistent, detail: "metadata-only coordinator did not invoke its accessor")
  }

  private static func foundationFailure<Value: Equatable & Sendable>(
    _ error: NSError,
    operation: String
  ) -> Capability<Value> {
    let status: CapabilityStatus
    if error.domain == NSCocoaErrorDomain,
      error.code == NSFileReadNoPermissionError
    {
      status = .permissionDenied
    } else if error.domain == NSCocoaErrorDomain,
      error.code == NSFeatureUnsupportedError
    {
      status = .unsupported
    } else {
      status = .failed
    }
    return Capability(
      status: status,
      detail: operation,
      errorCode: Int32(clamping: error.code)
    )
  }
}
