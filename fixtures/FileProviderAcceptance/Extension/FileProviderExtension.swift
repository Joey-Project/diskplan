import Darwin
import DiskplanFileProviderFixtureSupport
import FileProvider
import Foundation

@objc(FileProviderExtension)
final class FileProviderExtension: NSObject, NSFileProviderReplicatedExtension, @unchecked Sendable
{
  private let domain: NSFileProviderDomain
  private let runID: UUID?
  private let recorder: OracleRecorder?

  required init(domain: NSFileProviderDomain) {
    self.domain = domain
    let resolvedRunID = FixtureContract.runID(domainIdentifier: domain.identifier.rawValue)
    runID = resolvedRunID
    if let resolvedRunID {
      recorder = try? OracleRecorder(log: OracleLog.appGroup(runID: resolvedRunID))
    } else {
      recorder = nil
    }
    super.init()
  }

  func invalidate() {}

  func item(
    for identifier: NSFileProviderItemIdentifier,
    request: NSFileProviderRequest,
    completionHandler: @escaping (NSFileProviderItem?, Error?) -> Void
  ) -> Progress {
    do {
      try record(.itemMetadata, item: identifier, request: request)
    } catch {
      completionHandler(nil, error)
      return completedProgress()
    }
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
    do {
      try record(.fetchContents, item: itemIdentifier, request: request)
    } catch {
      completionHandler(nil, nil, error)
      return completedProgress()
    }
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
    do {
      try record(
        .createItem, item: itemTemplate.itemIdentifier, request: request,
        flags: ["fields:\(fields.rawValue)", "options:\(options.rawValue)"])
    } catch {
      completionHandler(nil, [], false, error)
      return completedProgress()
    }
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
    do {
      try record(
        .modifyItem, item: item.itemIdentifier, request: request,
        flags: ["fields:\(changedFields.rawValue)", "options:\(options.rawValue)"])
    } catch {
      completionHandler(nil, [], false, error)
      return completedProgress()
    }
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
    do {
      try record(
        .deleteItem,
        item: identifier,
        request: request,
        flags: ["options:\(options.rawValue)"]
      )
    } catch {
      completionHandler(error)
      return completedProgress()
    }
    completionHandler(NSFileProviderError(.excludedFromSync))
    return completedProgress()
  }

  func enumerator(
    for containerItemIdentifier: NSFileProviderItemIdentifier,
    request: NSFileProviderRequest
  ) throws -> NSFileProviderEnumerator {
    let requestFlags = flags(for: request)
    return FixtureEnumerator(container: containerItemIdentifier) { [weak self] kind, item, flags in
      guard let self else { throw OracleRecorderError.unavailable }
      try self.record(
        kind,
        item: NSFileProviderItemIdentifier(item),
        flags: requestFlags + flags
      )
    }
  }

  func materializedItemsDidChange(completionHandler: @escaping () -> Void) {
    guard (try? record(.materializedItemsDidChange, item: .rootContainer)) != nil else {
      return
    }
    completionHandler()
  }

  private func record(
    _ kind: OracleEventKind,
    item: NSFileProviderItemIdentifier,
    request: NSFileProviderRequest? = nil,
    flags: [String] = []
  ) throws {
    guard let runID, let recorder else { throw OracleRecorderError.unavailable }
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
    try recorder.record(event)
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
