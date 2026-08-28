import Darwin
import DiskplanFileProviderFixtureSupport
import FileProvider
import Foundation

@objc(FileProviderExtension)
final class FileProviderExtension: NSObject, NSFileProviderReplicatedExtension, @unchecked Sendable
{
  private let domain: NSFileProviderDomain
  private let recordingCapability: RecordingCapability?

  required init(domain: NSFileProviderDomain) {
    self.domain = domain
    if let runID = FixtureContract.runID(domainIdentifier: domain.identifier.rawValue) {
      do {
        recordingCapability = RecordingCapability(
          runID: runID,
          domainIdentifier: domain.identifier.rawValue,
          recorder: try OracleRecorder(log: OracleLog.appGroup(runID: runID))
        )
      } catch {
        fatalError("fixture recorder admission channel unavailable: \(error)")
      }
    } else {
      recordingCapability = nil
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
    guard let recordingCapability else { throw OracleRecorderError.unavailable }
    let requestFlags = flags(for: request)
    try recordingCapability.record(
      .enumeratorAcquisition,
      item: containerItemIdentifier.rawValue,
      flags: requestFlags
    )
    return FixtureEnumerator(container: containerItemIdentifier) { kind, item, flags in
      try recordingCapability.record(kind, item: item, flags: requestFlags + flags)
    }
  }

  func materializedItemsDidChange(completionHandler: @escaping () -> Void) {
    defer { completionHandler() }
    try? record(.materializedItemsDidChange, item: .rootContainer)
  }

  private func record(
    _ kind: OracleEventKind,
    item: NSFileProviderItemIdentifier,
    request: NSFileProviderRequest? = nil,
    flags: [String] = []
  ) throws {
    guard let recordingCapability else { throw OracleRecorderError.unavailable }
    var requestFlags = flags
    if let request { requestFlags.append(contentsOf: self.flags(for: request)) }
    try recordingCapability.record(kind, item: item.rawValue, flags: requestFlags)
  }

  private func flags(for request: NSFileProviderRequest) -> [String] {
    [
      "system:\(request.isSystemRequest)",
      "fileViewer:\(request.isFileViewerRequest)",
      "requestingExecutablePresent:\(request.requestingExecutable != nil)",
    ]
  }
}

private final class RecordingCapability: @unchecked Sendable {
  private let runID: UUID
  private let domainIdentifier: String
  private let recorder: OracleRecorder

  init(runID: UUID, domainIdentifier: String, recorder: OracleRecorder) {
    self.runID = runID
    self.domainIdentifier = domainIdentifier
    self.recorder = recorder
  }

  func record(_ kind: OracleEventKind, item: String, flags: [String] = []) throws {
    try recorder.record { [runID, domainIdentifier] in
      OracleEvent(
        runID: runID,
        domainIdentifier: domainIdentifier,
        itemIdentifier: item,
        kind: kind,
        processID: getpid(),
        monotonicNanoseconds: clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW),
        requestFlags: flags
      )
    }
  }
}

private func completedProgress() -> Progress {
  let progress = Progress(totalUnitCount: 1)
  progress.completedUnitCount = 1
  return progress
}
