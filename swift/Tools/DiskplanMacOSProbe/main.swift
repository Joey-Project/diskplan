import Darwin
import DiskplanMacOS
import Foundation

guard CommandLine.arguments == [CommandLine.arguments[0], "--self-test"] else {
  FileHandle.standardError.write(
    Data("usage: diskplan-macos-probe --self-test\n".utf8)
  )
  exit(64)
}

let installer = MaterializationPolicyInstaller()
let installed = installer.installBeforePathAccess()
guard let policy = installed.value else {
  FileHandle.standardError.write(
    Data("materialization-policy: \(installed.status.rawValue) \(installed.detail ?? "")\n".utf8)
  )
  exit(1)
}

let manager = FileManager.default
let root = manager.temporaryDirectory.appendingPathComponent(
  "diskplan-macos-probe-\(UUID().uuidString)",
  isDirectory: true
)
try manager.createDirectory(at: root, withIntermediateDirectories: false)
defer { try? manager.removeItem(at: root) }

let file = root.appendingPathComponent("sample.bin")
try Data(repeating: 0x5a, count: 4096).write(to: file, options: .withoutOverwriting)
let parentFD = open(root.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
guard parentFD >= 0 else { throw POSIXError(.init(rawValue: errno) ?? .EIO) }
defer { close(parentFD) }

let item = ItemProbe().probe(
  parentFileDescriptor: parentFD,
  rawName: Data("sample.bin".utf8),
  policy: policy
)
let volume = VolumeProbe().probe(fileDescriptor: parentFD, policy: policy)
guard let evidence = item.value, let volumeEvidence = volume.value else {
  FileHandle.standardError.write(
    Data("item=\(item.status.rawValue) volume=\(volume.status.rawValue)\n".utf8)
  )
  exit(1)
}

let provider = FileProviderBoundaryProbe().probe(
  parentFileDescriptor: parentFD,
  rawName: Data("sample.bin".utf8),
  policy: policy
)
let providerIdentityStatus: String
let providerFixtureAcceptance: String
switch provider {
case .evidence(let providerEvidence):
  providerIdentityStatus = providerEvidence.identity.status.rawValue
  providerFixtureAcceptance =
    providerEvidence.controlledNonMaterializationAcceptance.status.rawValue
case .rejected:
  providerIdentityStatus = "rejected"
  providerFixtureAcceptance = "unavailable"
}
let fields = [
  "\"materialization_policy\":\"off\"",
  "\"filesystem\":\"\(volumeEvidence.filesystemType)\"",
  "\"logical_status\":\"\(evidence.logicalBytes.status.rawValue)\"",
  "\"private_reclaim_status\":\"\(evidence.immediatePrivateReclaimBytes.status.rawValue)\"",
  "\"provider_identity_status\":\"\(providerIdentityStatus)\"",
  "\"provider_fixture_acceptance\":\"\(providerFixtureAcceptance)\"",
]
print("{\(fields.joined(separator: ","))}")
