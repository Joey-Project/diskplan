import DiskplanFileProviderFixtureSupport
import FileProvider
import Foundation

final class FixtureEnumerator: NSObject, NSFileProviderEnumerator {
  private let container: NSFileProviderItemIdentifier
  private let record: @Sendable (OracleEventKind, String, [String]) -> Void

  init(
    container: NSFileProviderItemIdentifier,
    record: @escaping @Sendable (OracleEventKind, String, [String]) -> Void
  ) {
    self.container = container
    self.record = record
  }

  func invalidate() {}

  func enumerateItems(
    for observer: NSFileProviderEnumerationObserver,
    startingAt page: NSFileProviderPage
  ) {
    let items: [FixtureItem]
    switch container.rawValue {
    case NSFileProviderItemIdentifier.rootContainer.rawValue:
      record(.rootEnumeration, container.rawValue, ["page:\(String(describing: page))"])
      items = [.sentinel, .sealedDirectory]
    case NSFileProviderItemIdentifier.workingSet.rawValue:
      record(.workingSetEnumeration, container.rawValue, ["page:\(String(describing: page))"])
      items = [.sentinel, .sealedDirectory]
    case FixtureContract.sealedDirectoryIdentifier:
      record(.sealedDirectoryEnumeration, container.rawValue, ["page:\(String(describing: page))"])
      items = [.forbiddenChild]
    default:
      observer.finishEnumeratingWithError(
        NSFileProviderError(.noSuchItem)
      )
      return
    }
    observer.didEnumerate(items)
    observer.finishEnumerating(upTo: nil)
  }

  func enumerateChanges(
    for observer: NSFileProviderChangeObserver,
    from syncAnchor: NSFileProviderSyncAnchor
  ) {
    observer.finishEnumeratingChanges(upTo: syncAnchor, moreComing: false)
  }

  func currentSyncAnchor(completionHandler: @escaping (NSFileProviderSyncAnchor?) -> Void) {
    completionHandler(NSFileProviderSyncAnchor(Data("fixture-v1".utf8)))
  }
}
