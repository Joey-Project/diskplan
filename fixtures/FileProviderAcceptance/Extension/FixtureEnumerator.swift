import DiskplanFileProviderFixtureSupport
import FileProvider
import Foundation

final class FixtureEnumerator: NSObject, NSFileProviderEnumerator {
  private let container: NSFileProviderItemIdentifier
  private let record: @Sendable (OracleEventKind, String, [String]) throws -> Void

  init(
    container: NSFileProviderItemIdentifier,
    record: @escaping @Sendable (OracleEventKind, String, [String]) throws -> Void
  ) {
    self.container = container
    self.record = record
  }

  func invalidate() {}

  func enumerateItems(
    for observer: NSFileProviderEnumerationObserver,
    startingAt page: NSFileProviderPage
  ) {
    do {
      let items: [FixtureItem]
      switch container.rawValue {
      case NSFileProviderItemIdentifier.rootContainer.rawValue:
        try record(.rootEnumeration, container.rawValue, ["page:\(String(describing: page))"])
        items = [.sentinel, .sealedDirectory]
      case NSFileProviderItemIdentifier.workingSet.rawValue:
        try record(.workingSetEnumeration, container.rawValue, ["page:\(String(describing: page))"])
        items = [.sentinel, .sealedDirectory]
      case FixtureContract.sealedDirectoryIdentifier:
        try record(
          .sealedDirectoryEnumeration,
          container.rawValue,
          ["page:\(String(describing: page))"]
        )
        items = [.forbiddenChild]
      default:
        observer.finishEnumeratingWithError(NSFileProviderError(.noSuchItem))
        return
      }
      observer.didEnumerate(items)
      observer.finishEnumerating(upTo: nil)
    } catch {
      observer.finishEnumeratingWithError(error)
    }
  }

  func enumerateChanges(
    for observer: NSFileProviderChangeObserver,
    from syncAnchor: NSFileProviderSyncAnchor
  ) {
    do {
      try record(.changeEnumeration, container.rawValue, [])
      observer.finishEnumeratingChanges(upTo: syncAnchor, moreComing: false)
    } catch {
      observer.finishEnumeratingWithError(error)
    }
  }

  func currentSyncAnchor(completionHandler: @escaping (NSFileProviderSyncAnchor?) -> Void) {
    do {
      try record(.syncAnchor, container.rawValue, [])
      completionHandler(NSFileProviderSyncAnchor(Data("fixture-v1".utf8)))
    } catch {
      completionHandler(nil)
    }
  }
}
