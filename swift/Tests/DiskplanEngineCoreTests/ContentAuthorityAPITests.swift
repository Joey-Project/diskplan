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

private func readBoundedFile(_ url: URL, maximumBytes: Int) -> Data? {
  guard maximumBytes >= 0, let handle = try? FileHandle(forReadingFrom: url) else { return nil }
  defer { try? handle.close() }
  var retained = Data()
  do {
    while retained.count <= maximumBytes {
      let remaining = maximumBytes - retained.count
      guard let chunk = try handle.read(upToCount: min(64 * 1_024, remaining + 1)),
        !chunk.isEmpty
      else {
        return retained
      }
      retained.append(chunk)
      if retained.count > maximumBytes { return nil }
    }
  } catch {
    return nil
  }
  return nil
}

private func builtPackageName(for moduleName: String, modulesDirectory: URL) -> String? {
  let description = modulesDirectory.deletingLastPathComponent().appendingPathComponent(
    "description.json")
  guard
    let data = readBoundedFile(description, maximumBytes: 16 * 1_024 * 1_024),
    let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
    let commands = root["swiftCommands"] as? [String: Any]
  else {
    return nil
  }
  for case let command as [String: Any] in commands.values {
    guard command["moduleName"] as? String == moduleName,
      let arguments = command["otherArguments"] as? [String],
      let optionIndex = arguments.firstIndex(of: "-package-name"),
      arguments.indices.contains(optionIndex + 1)
    else {
      continue
    }
    return arguments[optionIndex + 1]
  }
  return nil
}

private final class BoundedDiagnosticCapture: @unchecked Sendable {
  private static let limit = 64 * 1_024
  private let lock = NSLock()
  private var retained = Data()
  private var didTruncate = false

  func append(_ data: Data) {
    lock.withLock {
      let remaining = Self.limit - retained.count
      if remaining > 0 { retained.append(data.prefix(remaining)) }
      if data.count > remaining { didTruncate = true }
    }
  }

  var snapshot: CompileOutputSnapshot {
    lock.withLock {
      CompileOutputSnapshot(
        text: String(decoding: retained, as: UTF8.self),
        truncated: didTruncate
      )
    }
  }
}

private struct CompileOutputSnapshot: Sendable {
  let text: String
  let truncated: Bool
}

private enum CompileTerminationReason: String, Sendable {
  case exit
  case uncaughtSignal
  case unavailable
}

private enum CompileDrainCompletion: Equatable, Sendable {
  case eof
  case readError(String)
  case timedOut

  var report: String {
    switch self {
    case .eof: "eof"
    case .readError(let message): "readError(\(String(reflecting: message)))"
    case .timedOut: "timedOut"
    }
  }
}

private final class CompileDrainRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var completion: CompileDrainCompletion?

  func record(_ completion: CompileDrainCompletion) {
    lock.withLock { self.completion = completion }
  }

  var snapshot: CompileDrainCompletion {
    lock.withLock { completion ?? .readError("drain completed without a terminal state") }
  }
}

private struct CompileProcessResult: Sendable {
  let setupError: String?
  let timedOut: Bool
  let terminationReason: CompileTerminationReason
  let terminationStatus: Int32?
  let stdout: CompileOutputSnapshot
  let stderr: CompileOutputSnapshot
  let stdoutDrain: CompileDrainCompletion
  let stderrDrain: CompileDrainCompletion

  var report: String {
    "setupError=\(setupError ?? "none") timedOut=\(timedOut) "
      + "termination=\(terminationReason.rawValue) "
      + "status=\(terminationStatus.map { String($0) } ?? "none") "
      + "stdoutTruncated=\(stdout.truncated) stderrTruncated=\(stderr.truncated) "
      + "stdoutDrain=\(stdoutDrain.report) stderrDrain=\(stderrDrain.report) "
      + "stdout=\(String(reflecting: stdout.text)) stderr=\(String(reflecting: stderr.text))"
  }
}

private enum ExpectedAccessFailure: Sendable {
  case inaccessible
  case notVisible

  func matches(_ diagnostic: String) -> Bool {
    switch self {
    case .inaccessible:
      diagnostic.contains("inaccessible") || diagnostic.contains("protection level")
    case .notVisible:
      diagnostic.contains("inaccessible")
        || diagnostic.contains("protection level")
        || diagnostic.contains("cannot find type")
        || diagnostic.contains("cannot find '")
    }
  }
}

private enum CompilePackageContext: Sendable {
  case currentPackage
  case external(String)
}

private struct CompileFailExpectation: Sendable {
  let fixtureName: String
  let packageContext: CompilePackageContext
  let markerFile: String
  let markerLine: Int
  let expectedSymbol: String
  let expectedFailure: ExpectedAccessFailure
}

private let forbiddenSurfaceExpectations = [
  CompileFailExpectation(
    fixtureName: "ForgeRequestID.swift",
    packageContext: .currentPackage,
    markerFile: "DiskplanCompileFail-ForgeRequestID.swift",
    markerLine: 1001,
    expectedSymbol: "ContentCollectionRequestID",
    expectedFailure: .inaccessible
  ),
  CompileFailExpectation(
    fixtureName: "ConstructConsumer.swift",
    packageContext: .currentPackage,
    markerFile: "DiskplanCompileFail-ConstructConsumer.swift",
    markerLine: 1002,
    expectedSymbol: "ContentEvidenceConsumer",
    expectedFailure: .inaccessible
  ),
  CompileFailExpectation(
    fixtureName: "AccessScannerAuthority.swift",
    packageContext: .currentPackage,
    markerFile: "DiskplanCompileFail-AccessScannerAuthority.swift",
    markerLine: 1003,
    expectedSymbol: "ScannerContentCollectionAuthority",
    expectedFailure: .notVisible
  ),
  CompileFailExpectation(
    fixtureName: "ExternalPackageConsumer.swift",
    packageContext: .external("external_content_client"),
    markerFile: "DiskplanCompileFail-ExternalPackageConsumer.swift",
    markerLine: 1004,
    expectedSymbol: "ContentEvidenceConsumer",
    expectedFailure: .notVisible
  ),
]

private func compileFailRejection(
  result: CompileProcessResult,
  expectation: CompileFailExpectation
) -> String? {
  if let setupError = result.setupError { return "compiler setup failed: \(setupError)" }
  if result.timedOut { return "compiler timed out" }
  guard result.terminationReason == .exit else {
    return "compiler did not exit normally: \(result.terminationReason.rawValue)"
  }
  guard let status = result.terminationStatus, status != 0 else {
    return "fixture unexpectedly typechecked"
  }
  if result.stdout.truncated || result.stderr.truncated {
    return "compiler output was truncated"
  }
  guard result.stdoutDrain == .eof, result.stderrDrain == .eof else {
    return "compiler output did not drain to EOF"
  }
  guard result.stdout.text.isEmpty else {
    return "compiler emitted unexpected standard output"
  }

  let lines = result.stderr.text.split(whereSeparator: \.isNewline).map(String.init)
  let errorIndexes = lines.indices.filter { lines[$0].contains("error:") }
  let marker = "\(expectation.markerFile):\(expectation.markerLine):"
  guard errorIndexes.count == 1, let markerErrorIndex = errorIndexes.first else {
    return "compiler did not emit exactly one error diagnostic"
  }
  guard lines[markerErrorIndex].hasPrefix(marker) else {
    return "compiler error diagnostic was not prefixed by the exact source marker"
  }
  let diagnosticBlock = lines[markerErrorIndex...].joined(separator: "\n")
  guard diagnosticBlock.contains(expectation.expectedSymbol) else {
    return "source marker diagnostic did not identify the expected inaccessible symbol"
  }
  guard expectation.expectedFailure.matches(lines[markerErrorIndex]) else {
    return "source marker diagnostic was not the expected access-control failure"
  }
  return nil
}

private func startDrain(
  pipe: Pipe,
  capture: BoundedDiagnosticCapture,
  recorder: CompileDrainRecorder,
  group: DispatchGroup
) {
  group.enter()
  DispatchQueue.global().async {
    defer { group.leave() }
    do {
      while let chunk = try pipe.fileHandleForReading.read(upToCount: 4 * 1_024),
        !chunk.isEmpty
      {
        capture.append(chunk)
      }
      recorder.record(.eof)
    } catch {
      recorder.record(.readError(String(reflecting: error)))
    }
  }
}

private func typecheckForbiddenFixture(
  _ fixture: URL,
  modules: URL,
  clangModules: URL,
  packageName: String
) -> CompileProcessResult {
  let process = Process()
  let stdoutPipe = Pipe()
  let stderrPipe = Pipe()
  let stdout = BoundedDiagnosticCapture()
  let stderr = BoundedDiagnosticCapture()
  let stdoutDrain = DispatchGroup()
  let stderrDrain = DispatchGroup()
  let stdoutDrainRecorder = CompileDrainRecorder()
  let stderrDrainRecorder = CompileDrainRecorder()
  let isolatedExec = fixture.deletingLastPathComponent().appendingPathComponent("isolated_exec.py")
  process.executableURL = URL(fileURLWithPath: "/usr/bin/python3")
  process.arguments = [
    isolatedExec.path, "/usr/bin/swiftc", "-typecheck", "-diagnostic-style", "llvm",
    "-no-color-diagnostics", "-I", modules.path, "-I", clangModules.path,
    "-package-name", packageName, fixture.path,
  ]
  process.standardOutput = stdoutPipe
  process.standardError = stderrPipe
  let completion = DispatchSemaphore(value: 0)
  process.terminationHandler = { _ in completion.signal() }
  startDrain(
    pipe: stdoutPipe, capture: stdout, recorder: stdoutDrainRecorder, group: stdoutDrain)
  startDrain(
    pipe: stderrPipe, capture: stderr, recorder: stderrDrainRecorder, group: stderrDrain)
  do {
    try process.run()
  } catch {
    try? stdoutPipe.fileHandleForWriting.close()
    try? stderrPipe.fileHandleForWriting.close()
    try? stdoutPipe.fileHandleForReading.close()
    try? stderrPipe.fileHandleForReading.close()
    let stdoutDrainTimedOut = stdoutDrain.wait(timeout: .now() + .seconds(1)) == .timedOut
    let stderrDrainTimedOut = stderrDrain.wait(timeout: .now() + .seconds(1)) == .timedOut
    return CompileProcessResult(
      setupError: String(reflecting: error),
      timedOut: false,
      terminationReason: .unavailable,
      terminationStatus: nil,
      stdout: stdout.snapshot,
      stderr: stderr.snapshot,
      stdoutDrain: stdoutDrainTimedOut ? .timedOut : stdoutDrainRecorder.snapshot,
      stderrDrain: stderrDrainTimedOut ? .timedOut : stderrDrainRecorder.snapshot
    )
  }
  try? stdoutPipe.fileHandleForWriting.close()
  try? stderrPipe.fileHandleForWriting.close()
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
  let stdoutDrainTimedOut = stdoutDrain.wait(timeout: .now() + .seconds(2)) == .timedOut
  if stdoutDrainTimedOut {
    Darwin.kill(-process.processIdentifier, SIGKILL)
    try? stdoutPipe.fileHandleForReading.close()
    _ = stdoutDrain.wait(timeout: .now() + .seconds(1))
  }
  let stderrDrainTimedOut = stderrDrain.wait(timeout: .now() + .seconds(2)) == .timedOut
  if stderrDrainTimedOut {
    Darwin.kill(-process.processIdentifier, SIGKILL)
    try? stderrPipe.fileHandleForReading.close()
    _ = stderrDrain.wait(timeout: .now() + .seconds(1))
  }
  let didTerminate = !process.isRunning
  let terminationReason: CompileTerminationReason
  if didTerminate {
    switch process.terminationReason {
    case .exit: terminationReason = .exit
    case .uncaughtSignal: terminationReason = .uncaughtSignal
    @unknown default: terminationReason = .unavailable
    }
  } else {
    terminationReason = .unavailable
  }
  return CompileProcessResult(
    setupError: nil,
    timedOut: timedOut,
    terminationReason: terminationReason,
    terminationStatus: didTerminate ? process.terminationStatus : nil,
    stdout: stdout.snapshot,
    stderr: stderr.snapshot,
    stdoutDrain: stdoutDrainTimedOut ? .timedOut : stdoutDrainRecorder.snapshot,
    stderrDrain: stderrDrainTimedOut ? .timedOut : stderrDrainRecorder.snapshot
  )
}

@Test func compileFailClassifierRejectsInfrastructureFailures() {
  let expectation = forbiddenSurfaceExpectations[0]
  let diagnostic =
    "\(expectation.markerFile):\(expectation.markerLine):1: error: initializer is inaccessible due to 'fileprivate' protection level\n"
    + "let request = ContentCollectionRequestID(rawValue: value)\n"
  func result(
    setupError: String? = nil,
    timedOut: Bool = false,
    terminationReason: CompileTerminationReason = .exit,
    terminationStatus: Int32? = 1,
    stdout: String = "",
    stderr: String = diagnostic,
    stdoutTruncated: Bool = false,
    stderrTruncated: Bool = false,
    stdoutDrain: CompileDrainCompletion = .eof,
    stderrDrain: CompileDrainCompletion = .eof
  ) -> CompileProcessResult {
    CompileProcessResult(
      setupError: setupError,
      timedOut: timedOut,
      terminationReason: terminationReason,
      terminationStatus: terminationStatus,
      stdout: CompileOutputSnapshot(text: stdout, truncated: stdoutTruncated),
      stderr: CompileOutputSnapshot(text: stderr, truncated: stderrTruncated),
      stdoutDrain: stdoutDrain,
      stderrDrain: stderrDrain
    )
  }

  #expect(compileFailRejection(result: result(), expectation: expectation) == nil)
  #expect(compileFailRejection(result: result(stderr: ""), expectation: expectation) != nil)
  #expect(
    compileFailRejection(
      result: result(
        stderr:
          "\(expectation.markerFile):\(expectation.markerLine):1: error: initializer is inaccessible due to 'fileprivate' protection level\n"
          + "let request = DifferentRequestID(rawValue: value)\n"),
      expectation: expectation
    ) != nil)
  #expect(
    compileFailRejection(
      result: result(timedOut: true, terminationReason: .uncaughtSignal),
      expectation: expectation
    ) != nil)
  #expect(
    compileFailRejection(
      result: result(terminationReason: .uncaughtSignal, terminationStatus: SIGKILL),
      expectation: expectation
    ) != nil)
  #expect(
    compileFailRejection(
      result: result(stderr: "<unknown>:0: error: no such module 'DiskplanScan'\n"),
      expectation: expectation
    ) != nil)
  #expect(
    compileFailRejection(
      result: result(
        stderr: diagnostic + "<unknown>:0: error: no such module 'OtherModule'\n"),
      expectation: expectation
    ) != nil)
  #expect(
    compileFailRejection(
      result: result(
        stderr: diagnostic
          + "\(expectation.markerFile):\(expectation.markerLine):2: error: unrelated semantic error\n"
      ),
      expectation: expectation
    ) != nil)
  #expect(
    compileFailRejection(
      result: result(
        stderr:
          "<unknown>:0:1: error: referenced \(expectation.markerFile):\(expectation.markerLine): in a message\n"
          + "ContentCollectionRequestID\n"),
      expectation: expectation
    ) != nil)
  #expect(
    compileFailRejection(
      result: result(stdout: diagnostic, stderr: ""),
      expectation: expectation
    ) != nil)
  #expect(
    compileFailRejection(
      result: result(setupError: "launch denied", stderr: ""),
      expectation: expectation
    ) != nil)
  #expect(
    compileFailRejection(
      result: result(stderrTruncated: true),
      expectation: expectation
    ) != nil)
  #expect(
    compileFailRejection(
      result: result(stderrDrain: .timedOut),
      expectation: expectation
    ) != nil)
  #expect(
    compileFailRejection(
      result: result(stderrDrain: .readError("simulated EIO")),
      expectation: expectation
    ) != nil)
}

@Test func scannerContentAuthorityForbiddenSurfacesFailToCompile() throws {
  let root = try #require(repositoryRoot())
  let modules = try #require(builtModulesDirectory())
  let currentPackageName = try #require(
    builtPackageName(for: "DiskplanScan", modulesDirectory: modules))
  let clangModules = modules.deletingLastPathComponent().appendingPathComponent(
    "CDiskplanMacOS.build", isDirectory: true)
  #expect(
    FileManager.default.fileExists(
      atPath: clangModules.appendingPathComponent("module.modulemap").path))
  let fixtures = root.appendingPathComponent(
    "fixtures/CompileFail/ContentAuthority", isDirectory: true)
  for expectation in forbiddenSurfaceExpectations {
    let packageName: String
    switch expectation.packageContext {
    case .currentPackage: packageName = currentPackageName
    case .external(let externalPackageName): packageName = externalPackageName
    }
    let result = typecheckForbiddenFixture(
      fixtures.appendingPathComponent(expectation.fixtureName),
      modules: modules,
      clangModules: clangModules,
      packageName: packageName
    )
    let rejection = compileFailRejection(result: result, expectation: expectation)
    #expect(
      rejection == nil,
      "Forbidden fixture did not prove the expected semantic rejection: \(expectation.fixtureName): \(rejection ?? "accepted"); \(result.report)"
    )
  }
}
