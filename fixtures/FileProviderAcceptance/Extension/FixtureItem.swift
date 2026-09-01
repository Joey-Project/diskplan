import DiskplanFileProviderFixtureSupport
import FileProvider
import Foundation
import UniformTypeIdentifiers

final class FixtureItem: NSObject, NSFileProviderItem, @unchecked Sendable {
  let itemIdentifier: NSFileProviderItemIdentifier
  let parentItemIdentifier: NSFileProviderItemIdentifier
  let filename: String
  let contentType: UTType
  let documentSize: NSNumber?
  let childItemCount: NSNumber?
  let itemVersion: NSFileProviderItemVersion
  let capabilities: NSFileProviderItemCapabilities

  init(
    identifier: NSFileProviderItemIdentifier,
    parent: NSFileProviderItemIdentifier,
    filename: String,
    contentType: UTType,
    documentSize: NSNumber? = nil,
    childItemCount: NSNumber? = nil
  ) {
    itemIdentifier = identifier
    parentItemIdentifier = parent
    self.filename = filename
    self.contentType = contentType
    self.documentSize = documentSize
    self.childItemCount = childItemCount
    let version = Data("fixture-v1".utf8)
    itemVersion = NSFileProviderItemVersion(contentVersion: version, metadataVersion: version)
    capabilities = contentType.conforms(to: .folder) ? [.allowsReading] : [.allowsReading]
  }

  static let root = FixtureItem(
    identifier: .rootContainer,
    parent: .rootContainer,
    filename: FixtureContract.displayName,
    contentType: .folder,
    childItemCount: 2
  )

  static let sentinel = FixtureItem(
    identifier: NSFileProviderItemIdentifier(FixtureContract.sentinelIdentifier),
    parent: .rootContainer,
    filename: FixtureContract.sentinelName,
    contentType: .plainText,
    documentSize: NSNumber(value: FixtureContract.sentinelByteCount)
  )

  static let sealedDirectory = FixtureItem(
    identifier: NSFileProviderItemIdentifier(FixtureContract.sealedDirectoryIdentifier),
    parent: .rootContainer,
    filename: FixtureContract.sealedDirectoryName,
    contentType: .folder,
    childItemCount: 1
  )

  static let forbiddenChild = FixtureItem(
    identifier: NSFileProviderItemIdentifier(FixtureContract.forbiddenChildIdentifier),
    parent: NSFileProviderItemIdentifier(FixtureContract.sealedDirectoryIdentifier),
    filename: FixtureContract.forbiddenChildName,
    contentType: .plainText,
    documentSize: 1
  )

  static func resolve(_ identifier: NSFileProviderItemIdentifier) -> FixtureItem? {
    switch identifier.rawValue {
    case NSFileProviderItemIdentifier.rootContainer.rawValue: root
    case FixtureContract.sentinelIdentifier: sentinel
    case FixtureContract.sealedDirectoryIdentifier: sealedDirectory
    case FixtureContract.forbiddenChildIdentifier: forbiddenChild
    default: nil
    }
  }
}
