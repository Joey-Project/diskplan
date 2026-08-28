import Darwin
import DiskplanFileProviderFixtureSupport
import FileProvider
import Foundation

@objc(FileProviderExtension)
final class FileProviderExtension: NSObject, NSFileProviderReplicatedExtension, @unchecked Sendable
{
  private let domain: NSFileProviderDomain
  private let runID: UUID?

  required init(domain: NSFileProviderDomain) {
    self.domain = domain
    runID = FixtureContract.runID(domainIdentifier: domain.identifier.rawValue)
    super.init()
  }

  func invalidate() {}

  func item(
    for identifier: NSFileProviderItemIdentifier,
    request: NSFileProviderRequest,
    completionHandler: @escaping (NSFileProviderItem?, Error?) -> Void
  ) -> Progress {
    record(.itemMetadata, item: identifier, request: request)
    guard let item = FixtureItem.resolve(identifier) else {
      completionHandler(nil, NSFileProviderError(.noSuchItem))
      return completedProgress()
    }
    completionHandler(item, nil)
    return completedProgress()
  }

  func fetchContents(
    for itemIdentifier: NSFileProviderItemIdentifier,
    version requestedVersion: NSFileProviderItemVersion?,
    request: NSFileProviderRequest,
    completionHandler: @escaping (URL?, NSFileProviderItem?, Error?) -> Void
  ) -> Progress {
    record(.fetchContents, item: itemIdentifier, request: request)
    guard itemIdentifier.rawValue == FixtureContract.sentinelIdentifier,
      let manager = NSFileProviderManager(for: domain),
      let temporaryDirectory = try? manager.temporaryDirectoryURL()
    else {
      completionHandler(nil, nil, NSFileProviderError(.noSuchItem))
      return completedProgress()
    }
    do {
      let contents = temporaryDirectory.appendingPathComponent("sentinel-\(UUID().uuidString)")
      try FixtureContract.sentinelContents().write(to: contents, options: .withoutOverwriting)
      completionHandler(contents, FixtureItem.sentinel, nil)
    } catch {
      completionHandler(nil, nil, error)
    }
    return completedProgress()
  }

  func createItem(
    basedOn itemTemplate: NSFileProviderItem,
    fields: NSFileProviderItemFields,
    contents url: URL?,
    options: NSFileProviderCreateItemOptions,
    request: NSFileProviderRequest,
    completionHandler:
      @escaping (
        NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?
      ) -> Void
  ) -> Progress {
    record(
      .createItem, item: itemTemplate.itemIdentifier, request: request,
      flags: ["fields:\(fields.rawValue)", "options:\(options.rawValue)"])
    completionHandler(nil, [], false, NSFileProviderError(.excludedFromSync))
    return completedProgress()
  }

  func modifyItem(
    _ item: NSFileProviderItem,
    baseVersion version: NSFileProviderItemVersion,
    changedFields: NSFileProviderItemFields,
    contents newContents: URL?,
    options: NSFileProviderModifyItemOptions,
    request: NSFileProviderRequest,
    completionHandler:
      @escaping (
        NSFileProviderItem?, NSFileProviderItemFields, Bool, Error?
      ) -> Void
  ) -> Progress {
    record(
      .modifyItem, item: item.itemIdentifier, request: request,
      flags: ["fields:\(changedFields.rawValue)", "options:\(options.rawValue)"])
    completionHandler(nil, [], false, NSFileProviderError(.excludedFromSync))
    return completedProgress()
  }

  func deleteItem(
    identifier: NSFileProviderItemIdentifier,
    baseVersion version: NSFileProviderItemVersion,
    options: NSFileProviderDeleteItemOptions,
    request: NSFileProviderRequest,
    completionHandler: @escaping (Error?) -> Void
  ) -> Progress {
    record(.deleteItem, item: identifier, request: request, flags: ["options:\(options.rawValue)"])
    completionHandler(NSFileProviderError(.excludedFromSync))
    return completedProgress()
  }

  func enumerator(
    for containerItemIdentifier: NSFileProviderItemIdentifier,
    request: NSFileProviderRequest
  ) throws -> NSFileProviderEnumerator {
    let requestFlags = flags(for: request)
    return FixtureEnumerator(container: containerItemIdentifier) { [weak self] kind, item, flags in
      self?.record(
        kind,
        item: NSFileProviderItemIdentifier(item),
        flags: requestFlags + flags
      )
    }
  }

  func materializedItemsDidChange(completionHandler: @escaping () -> Void) {
    record(.materializedItemsDidChange, item: .rootContainer)
    completionHandler()
  }

  private func record(
    _ kind: OracleEventKind,
    item: NSFileProviderItemIdentifier,
    request: NSFileProviderRequest? = nil,
    flags: [String] = []
  ) {
    guard let runID else { return }
    var requestFlags = flags
    if let request { requestFlags.append(contentsOf: self.flags(for: request)) }
    let event = OracleEvent(
      runID: runID,
      domainIdentifier: domain.identifier.rawValue,
      itemIdentifier: item.rawValue,
      kind: kind,
      processID: getpid(),
      monotonicNanoseconds: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW),
      requestFlags: requestFlags
    )
    try? OracleLog.appGroup(runID: runID).append(event)
  }

  private func flags(for request: NSFileProviderRequest) -> [String] {
    [
      "system:\(request.isSystemRequest)",
      "fileViewer:\(request.isFileViewerRequest)",
      "requestingExecutablePresent:\(request.requestingExecutable != nil)",
    ]
  }
}

private func completedProgress() -> Progress {
  let progress = Progress(totalUnitCount: 1)
  progress.completedUnitCount = 1
  return progress
}
