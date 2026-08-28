import Darwin
import DiskplanScan
import Dispatch
import Foundation
import Testing

private let collectScannerBoundContent:
  @Sendable (
    ContentEvidenceConsumer,
    ContentCollectionRequestID
  ) -> ContentEvidence = { consumer, requestID in
    consumer.collect(requestID)
  }

@Test func scannerContentAuthorityCapabilitiesCompileAcrossTargets() {
  let collectionType = String(reflecting: type(of: collectScannerBoundContent))
  #expect(collectionType.contains("ContentCollectionRequestID"))
  #expect(!collectionType.contains("FileDescriptor"))
}

private func repositoryRoot() -> URL? {
  var candidate = URL(fileURLWithPath: #filePath).deletingLastPathComponent()
  for _ in 0..<8 {
    if FileManager.default.fileExists(
      atPath: candidate.appendingPathComponent("Package.swift").path)
    {
      return candidate
    }
    candidate.deleteLastPathComponent()
  }
  return nil
}

private final class ContentAuthorityTestBundleMarker: NSObject {}

private func builtModulesDirectory() -> URL? {
  var candidate = Bundle(for: ContentAuthorityTestBundleMarker.self).bundleURL
  for _ in 0..<8 {
    let modules = candidate.appendingPathComponent("Modules", isDirectory: true)
    if FileManager.default.fileExists(
      atPath: modules.appendingPathComponent("DiskplanScan.swiftmodule").path)
    {
      return modules
    }
    candidate.deleteLastPathComponent()
  }
  return nil
}

private final class BoundedDiagnosticCapture: @unchecked Sendable {
  private static let limit = 64 * 1_024
  private let lock = NSLock()
  private var retained = Data()

  func append(_ data: Data) {
    lock.withLock {
      let remaining = Self.limit - retained.count
      if remaining > 0 { retained.append(data.prefix(remaining)) }
    }
  }

  var text: String {
    lock.withLock { String(decoding: retained, as: UTF8.self) }
  }
}

private func typecheckForbiddenFixture(
  _ fixture: URL,
  modules: URL,
  clangModules: URL,
  packageName: String
) throws -> (status: Int32, diagnostics: String, timedOut: Bool) {
  let process = Process()
  let diagnosticsPipe = Pipe()
  let diagnostics = BoundedDiagnosticCapture()
  let drain = DispatchGroup()
  let isolatedExec = fixture.deletingLastPathComponent().appendingPathComponent("isolated_exec.py")
  process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
  process.arguments = [
    isolatedExec.path, "/usr/bin/swiftc", "-typecheck", "-I", modules.path, "-I",
    clangModules.path, "-package-name", packageName, fixture.path,
  ]
  process.standardOutput = diagnosticsPipe
  process.standardError = diagnosticsPipe
  let completion = DispatchSemaphore(value: 0)
  process.terminationHandler = { _ in completion.signal() }
  drain.enter()
  DispatchQueue.global().async {
    defer { drain.leave() }
    while let chunk = try? diagnosticsPipe.fileHandleForReading.read(upToCount: 4 * 1_024),
      !chunk.isEmpty
    {
      diagnostics.append(chunk)
    }
  }
  do {
    try process.run()
  } catch {
    try? diagnosticsPipe.fileHandleForWriting.close()
    try? diagnosticsPipe.fileHandleForReading.close()
    _ = drain.wait(timeout: .now() + .seconds(1))
    throw error
  }
  try? diagnosticsPipe.fileHandleForWriting.close()
  let timedOut = completion.wait(timeout: .now() + .seconds(10)) == .timedOut
  if timedOut {
    Darwin.kill(-process.processIdentifier, SIGTERM)
    process.terminate()
    _ = completion.wait(timeout: .now() + .seconds(2))
    Darwin.kill(-process.processIdentifier, SIGKILL)
    if process.isRunning {
      Darwin.kill(process.processIdentifier, SIGKILL)
    }
    _ = completion.wait(timeout: .now() + .seconds(2))
  }
  if drain.wait(timeout: .now() + .seconds(2)) == .timedOut {
    try? diagnosticsPipe.fileHandleForReading.close()
    _ = drain.wait(timeout: .now() + .seconds(1))
  }
  return (timedOut ? ETIMEDOUT : process.terminationStatus, diagnostics.text, timedOut)
}

@Test func scannerContentAuthorityForbiddenSurfacesFailToCompile() throws {
  let root = try #require(repositoryRoot())
  let modules = try #require(builtModulesDirectory())
  let clangModules = modules.deletingLastPathComponent().appendingPathComponent(
    "CDiskplanMacOS.build", isDirectory: true)
  #expect(
    FileManager.default.fileExists(
      atPath: clangModules.appendingPathComponent("module.modulemap").path))
  let fixtures = root.appendingPathComponent(
    "fixtures/CompileFail/ContentAuthority", isDirectory: true)
  let cases = [
    ("ForgeRequestID.swift", "diskplan"),
    ("ConstructConsumer.swift", "diskplan"),
    ("AccessScannerAuthority.swift", "diskplan"),
    ("ExternalPackageConsumer.swift", "external_content_client"),
  ]
  for (name, packageName) in cases {
    let result = try typecheckForbiddenFixture(
      fixtures.appendingPathComponent(name),
      modules: modules,
      clangModules: clangModules,
      packageName: packageName
    )
    #expect(!result.timedOut, "Forbidden fixture typecheck timed out: \(name)")
    #expect(result.status != 0, "Forbidden fixture unexpectedly compiled: \(name)")
    #expect(
      result.diagnostics.contains("inaccessible")
        || result.diagnostics.contains("cannot find type")
        || result.diagnostics.contains("cannot find '"),
      "Forbidden fixture failed for an unexpected reason: \(name): \(result.diagnostics)"
    )
  }
}
