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

private enum CompileProcessGroupCleanup: String, Sendable {
  case notRequired
  case termSent
  case killSent
}

private enum CompileProcessGroupQuiescence: String, Sendable {
  case confirmed
  case notStarted
  case timedOut
  case probeFailed
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
  let processGroupCleanup: CompileProcessGroupCleanup
  let processGroupQuiescence: CompileProcessGroupQuiescence

  var report: String {
    "setupError=\(setupError ?? "none") timedOut=\(timedOut) "
      + "termination=\(terminationReason.rawValue) "
      + "status=\(terminationStatus.map { String($0) } ?? "none") "
      + "stdoutTruncated=\(stdout.truncated) stderrTruncated=\(stderr.truncated) "
      + "stdoutDrain=\(stdoutDrain.report) stderrDrain=\(stderrDrain.report) "
      + "processGroupCleanup=\(processGroupCleanup.rawValue) "
      + "processGroupQuiescence=\(processGroupQuiescence.rawValue) "
      + "stdout=\(String(reflecting: stdout.text)) stderr=\(String(reflecting: stderr.text))"
  }
}

private final class AtomicCaptureChannel: @unchecked Sendable {
  let reader: FileHandle
  private let lock = NSLock()
  private var childWriter: Int32?

  init(endpointCreated: () throws -> Void) throws {
    var directoryTemplate = Array(
      (NSTemporaryDirectory() + "diskplan-compile-capture.XXXXXX").utf8CString)
    let directoryPath = directoryTemplate.withUnsafeMutableBufferPointer { buffer -> String? in
      guard Darwin.mkdtemp(buffer.baseAddress!) != nil else { return nil }
      return String(cString: buffer.baseAddress!)
    }
    guard let directoryPath else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    let fifoPath = directoryPath + "/capture"
    var cleanupRequired = true
    defer {
      if cleanupRequired {
        _ = fifoPath.withCString(Darwin.unlink)
        _ = directoryPath.withCString(Darwin.rmdir)
      }
    }
    let fifoStatus = fifoPath.withCString {
      Darwin.mkfifo($0, mode_t(S_IRUSR | S_IWUSR))
    }
    guard fifoStatus == 0 else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }

    var readerDescriptor = fifoPath.withCString {
      Darwin.open($0, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
    }
    guard readerDescriptor >= 0 else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    var writerDescriptor: Int32 = -1
    do {
      try endpointCreated()
      writerDescriptor = fifoPath.withCString {
        Darwin.open($0, O_WRONLY | O_CLOEXEC)
      }
      guard writerDescriptor >= 0 else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
      }
      try endpointCreated()
      let readerFlags = Darwin.fcntl(readerDescriptor, F_GETFL)
      guard readerFlags >= 0,
        Darwin.fcntl(readerDescriptor, F_SETFL, readerFlags & ~O_NONBLOCK) == 0
      else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
      }
    } catch {
      if writerDescriptor >= 0 { Darwin.close(writerDescriptor) }
      Darwin.close(readerDescriptor)
      throw error
    }
    if readerDescriptor < STDERR_FILENO + 1 {
      let duplicated = Darwin.fcntl(readerDescriptor, F_DUPFD_CLOEXEC, STDERR_FILENO + 1)
      guard duplicated >= 0 else {
        let failure = errno
        Darwin.close(writerDescriptor)
        Darwin.close(readerDescriptor)
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(failure))
      }
      Darwin.close(readerDescriptor)
      readerDescriptor = duplicated
    }
    if writerDescriptor < STDERR_FILENO + 1 {
      let duplicated = Darwin.fcntl(writerDescriptor, F_DUPFD_CLOEXEC, STDERR_FILENO + 1)
      guard duplicated >= 0 else {
        let failure = errno
        Darwin.close(writerDescriptor)
        Darwin.close(readerDescriptor)
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(failure))
      }
      Darwin.close(writerDescriptor)
      writerDescriptor = duplicated
    }
    let unlinkStatus = fifoPath.withCString(Darwin.unlink)
    guard unlinkStatus == 0 else {
      let failure = errno
      Darwin.close(writerDescriptor)
      Darwin.close(readerDescriptor)
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(failure))
    }
    let rmdirStatus = directoryPath.withCString(Darwin.rmdir)
    guard rmdirStatus == 0 else {
      let failure = errno
      Darwin.close(writerDescriptor)
      Darwin.close(readerDescriptor)
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(failure))
    }
    cleanupRequired = false
    reader = FileHandle(fileDescriptor: readerDescriptor, closeOnDealloc: true)
    childWriter = writerDescriptor
  }

  deinit {
    closeChildWriter()
    try? reader.close()
  }

  var writerDescriptor: Int32 {
    lock.withLock {
      precondition(childWriter != nil, "capture writer already closed")
      return childWriter!
    }
  }

  func closeChildWriter() {
    let descriptor = lock.withLock { () -> Int32? in
      defer { childWriter = nil }
      return childWriter
    }
    if let descriptor { Darwin.close(descriptor) }
  }

  func closeReader() { try? reader.close() }
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
  guard result.processGroupQuiescence == .confirmed else {
    return "compiler process group did not reach confirmed quiescence"
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
  reader: FileHandle,
  capture: BoundedDiagnosticCapture,
  recorder: CompileDrainRecorder,
  group: DispatchGroup
) {
  group.enter()
  DispatchQueue.global().async {
    defer { group.leave() }
    do {
      while let chunk = try reader.read(upToCount: 4 * 1_024),
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

private func drainCompleted(_ group: DispatchGroup, within deadline: DispatchTime) -> Bool {
  group.wait(timeout: deadline) == .success
}

private func emptyCompileProcessResult(setupError: String) -> CompileProcessResult {
  CompileProcessResult(
    setupError: setupError,
    timedOut: false,
    terminationReason: .unavailable,
    terminationStatus: nil,
    stdout: CompileOutputSnapshot(text: "", truncated: false),
    stderr: CompileOutputSnapshot(text: "", truncated: false),
    stdoutDrain: .readError("stdout capture was not started"),
    stderrDrain: .readError("stderr capture was not started"),
    processGroupCleanup: .notRequired,
    processGroupQuiescence: .notStarted
  )
}

private func compileProcessFailure(_ operation: String, _ code: Int32) -> NSError {
  NSError(
    domain: "DiskplanCompileHarness.\(operation)",
    code: Int(code),
    userInfo: [NSLocalizedDescriptionKey: "\(operation) failed with errno \(code)"]
  )
}

private func spawnIsolatedProcess(
  isolatedExec: URL,
  executable: String,
  arguments: [String],
  launcherExecutable: String,
  stdoutWriter: Int32,
  stderrWriter: Int32
) throws -> pid_t {
  let command = [launcherExecutable, isolatedExec.path, executable] + arguments
  var allocations: [UnsafeMutablePointer<CChar>] = []
  defer {
    for allocation in allocations { Darwin.free(allocation) }
  }
  for argument in command {
    guard !argument.utf8.contains(0),
      let allocation = argument.withCString({ Darwin.strdup($0) })
    else {
      throw compileProcessFailure("allocate-argv", ENOMEM)
    }
    allocations.append(allocation)
  }
  var argv = allocations.map(Optional.some)
  argv.append(nil)
  var environmentAllocations: [UnsafeMutablePointer<CChar>] = []
  defer {
    for allocation in environmentAllocations { Darwin.free(allocation) }
  }
  for entry in ProcessInfo.processInfo.environment.map({ "\($0.key)=\($0.value)" }).sorted() {
    guard let allocation = entry.withCString({ Darwin.strdup($0) }) else {
      throw compileProcessFailure("allocate-environment", ENOMEM)
    }
    environmentAllocations.append(allocation)
  }
  var environment = environmentAllocations.map(Optional.some)
  environment.append(nil)

  var fileActions: posix_spawn_file_actions_t?
  var status = posix_spawn_file_actions_init(&fileActions)
  guard status == 0 else { throw compileProcessFailure("file-actions-init", status) }
  defer { _ = posix_spawn_file_actions_destroy(&fileActions) }
  status = "/dev/null".withCString {
    posix_spawn_file_actions_addopen(&fileActions, STDIN_FILENO, $0, O_RDONLY, 0)
  }
  guard status == 0 else { throw compileProcessFailure("file-actions-stdin", status) }
  status = posix_spawn_file_actions_adddup2(&fileActions, stdoutWriter, STDOUT_FILENO)
  guard status == 0 else { throw compileProcessFailure("file-actions-stdout", status) }
  status = posix_spawn_file_actions_adddup2(&fileActions, stderrWriter, STDERR_FILENO)
  guard status == 0 else { throw compileProcessFailure("file-actions-stderr", status) }
  status = posix_spawn_file_actions_addclose(&fileActions, stdoutWriter)
  guard status == 0 else { throw compileProcessFailure("file-actions-close-stdout", status) }
  status = posix_spawn_file_actions_addclose(&fileActions, stderrWriter)
  guard status == 0 else { throw compileProcessFailure("file-actions-close-stderr", status) }

  var attributes: posix_spawnattr_t?
  status = posix_spawnattr_init(&attributes)
  guard status == 0 else { throw compileProcessFailure("attributes-init", status) }
  defer { _ = posix_spawnattr_destroy(&attributes) }
  status = posix_spawnattr_setpgroup(&attributes, 0)
  guard status == 0 else { throw compileProcessFailure("attributes-pgroup", status) }
  status = posix_spawnattr_setflags(
    &attributes,
    Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT)
  )
  guard status == 0 else { throw compileProcessFailure("attributes-flags", status) }

  var processID = pid_t()
  status = argv.withUnsafeMutableBufferPointer { argvBuffer in
    environment.withUnsafeMutableBufferPointer { environmentBuffer in
      posix_spawn(
        &processID,
        allocations[0],
        &fileActions,
        &attributes,
        argvBuffer.baseAddress!,
        environmentBuffer.baseAddress!
      )
    }
  }
  guard status == 0 else { throw compileProcessFailure("posix-spawn", status) }
  return processID
}

private enum CompileChildWait {
  case exited(Int32)
  case timedOut
  case failed(Int32)
}

private func waitForCompileChild(
  _ processID: pid_t,
  until deadline: DispatchTime
) -> CompileChildWait {
  let poll = DispatchSemaphore(value: 0)
  while true {
    var status: Int32 = 0
    let result = Darwin.waitpid(processID, &status, WNOHANG)
    if result == processID { return .exited(status) }
    if result == -1 {
      if errno == EINTR { continue }
      return .failed(errno)
    }
    if DispatchTime.now().uptimeNanoseconds >= deadline.uptimeNanoseconds {
      return .timedOut
    }
    _ = poll.wait(timeout: .now() + .milliseconds(10))
  }
}

private func decodedCompileTermination(
  _ waitStatus: Int32?
) -> (reason: CompileTerminationReason, status: Int32?) {
  guard let waitStatus else { return (.unavailable, nil) }
  let signal = waitStatus & 0x7f
  if signal == 0 { return (.exit, (waitStatus >> 8) & 0xff) }
  if signal != 0x7f { return (.uncaughtSignal, signal) }
  return (.unavailable, nil)
}

private func runIsolatedProcess(
  isolatedExec: URL,
  executable: String,
  arguments: [String],
  launcherExecutable: String = "/usr/bin/python3",
  leaderTimeout: DispatchTimeInterval = .seconds(10),
  postExitDrainGrace: DispatchTimeInterval = .milliseconds(250),
  termGrace: DispatchTimeInterval = .milliseconds(250),
  finalDrainGrace: DispatchTimeInterval = .seconds(2),
  endpointCreated: () throws -> Void = {}
) -> CompileProcessResult {
  let stdoutChannel: AtomicCaptureChannel
  let stderrChannel: AtomicCaptureChannel
  do {
    stdoutChannel = try AtomicCaptureChannel(endpointCreated: endpointCreated)
    stderrChannel = try AtomicCaptureChannel(endpointCreated: endpointCreated)
  } catch {
    return emptyCompileProcessResult(setupError: String(reflecting: error))
  }

  let stdout = BoundedDiagnosticCapture()
  let stderr = BoundedDiagnosticCapture()
  let stdoutDrain = DispatchGroup()
  let stderrDrain = DispatchGroup()
  let stdoutDrainRecorder = CompileDrainRecorder()
  let stderrDrainRecorder = CompileDrainRecorder()
  startDrain(
    reader: stdoutChannel.reader,
    capture: stdout,
    recorder: stdoutDrainRecorder,
    group: stdoutDrain
  )
  startDrain(
    reader: stderrChannel.reader,
    capture: stderr,
    recorder: stderrDrainRecorder,
    group: stderrDrain
  )
  let processID: pid_t
  do {
    processID = try spawnIsolatedProcess(
      isolatedExec: isolatedExec,
      executable: executable,
      arguments: arguments,
      launcherExecutable: launcherExecutable,
      stdoutWriter: stdoutChannel.writerDescriptor,
      stderrWriter: stderrChannel.writerDescriptor
    )
  } catch {
    stdoutChannel.closeChildWriter()
    stderrChannel.closeChildWriter()
    var stdoutFinished = drainCompleted(stdoutDrain, within: .now() + .seconds(1))
    var stderrFinished = drainCompleted(stderrDrain, within: .now() + .seconds(1))
    if !stdoutFinished {
      stdoutChannel.closeReader()
      stdoutFinished = drainCompleted(stdoutDrain, within: .now() + .seconds(1))
    }
    if !stderrFinished {
      stderrChannel.closeReader()
      stderrFinished = drainCompleted(stderrDrain, within: .now() + .seconds(1))
    }
    return CompileProcessResult(
      setupError: String(reflecting: error),
      timedOut: false,
      terminationReason: .unavailable,
      terminationStatus: nil,
      stdout: stdout.snapshot,
      stderr: stderr.snapshot,
      stdoutDrain: stdoutFinished ? stdoutDrainRecorder.snapshot : .timedOut,
      stderrDrain: stderrFinished ? stderrDrainRecorder.snapshot : .timedOut,
      processGroupCleanup: .notRequired,
      processGroupQuiescence: .notStarted
    )
  }

  // The child receives only dup2-created descriptors 1 and 2. The parent closes
  // both child endpoints immediately after posix_spawn returns successfully.
  stdoutChannel.closeChildWriter()
  stderrChannel.closeChildWriter()

  var timedOut = false
  var cleanup: CompileProcessGroupCleanup = .notRequired
  var setupError: String?
  var waitStatus: Int32?
  switch waitForCompileChild(processID, until: .now() + leaderTimeout) {
  case .exited(let status):
    waitStatus = status
  case .failed(let code):
    setupError = String(reflecting: compileProcessFailure("waitpid", code))
  case .timedOut:
    timedOut = true
    cleanup = .termSent
    if Darwin.kill(-processID, SIGTERM) != 0, errno != ESRCH {
      setupError = String(reflecting: compileProcessFailure("terminate-group", errno))
    }
    switch waitForCompileChild(processID, until: .now() + .seconds(2)) {
    case .exited(let status): waitStatus = status
    case .failed(let code):
      setupError = String(reflecting: compileProcessFailure("waitpid-after-term", code))
    case .timedOut:
      cleanup = .killSent
      if Darwin.kill(-processID, SIGKILL) != 0, errno != ESRCH {
        setupError = String(reflecting: compileProcessFailure("kill-group", errno))
      }
      if Darwin.kill(processID, SIGKILL) != 0, errno != ESRCH {
        setupError = String(reflecting: compileProcessFailure("kill-leader", errno))
      }
      switch waitForCompileChild(processID, until: .now() + .seconds(2)) {
      case .exited(let status): waitStatus = status
      case .failed(let code):
        setupError = String(reflecting: compileProcessFailure("waitpid-after-kill", code))
      case .timedOut:
        setupError = "compile supervisor did not reap after SIGKILL"
      }
    }
  }

  var stdoutFinished = drainCompleted(stdoutDrain, within: .now() + postExitDrainGrace)
  var stderrFinished = drainCompleted(stderrDrain, within: .now() + postExitDrainGrace)
  if !stdoutFinished {
    stdoutFinished = drainCompleted(stdoutDrain, within: .now() + termGrace)
  }
  if !stderrFinished {
    stderrFinished = drainCompleted(stderrDrain, within: .now() + termGrace)
  }
  if !stdoutFinished {
    stdoutFinished = drainCompleted(stdoutDrain, within: .now() + finalDrainGrace)
  }
  if !stderrFinished {
    stderrFinished = drainCompleted(stderrDrain, within: .now() + finalDrainGrace)
  }
  if !stdoutFinished { stdoutChannel.closeReader() }
  if !stderrFinished { stderrChannel.closeReader() }
  if !stdoutFinished { _ = drainCompleted(stdoutDrain, within: .now() + .seconds(1)) }
  if !stderrFinished { _ = drainCompleted(stderrDrain, within: .now() + .seconds(1)) }

  let termination = decodedCompileTermination(waitStatus)
  let terminationReason = termination.reason
  let terminationStatus = termination.status
  let quiescence: CompileProcessGroupQuiescence
  if timedOut || waitStatus == nil || terminationReason != .exit {
    quiescence = .notStarted
  } else if terminationReason == .exit && terminationStatus == 252 {
    quiescence = .timedOut
  } else if terminationReason == .exit && terminationStatus == 253 {
    quiescence = .probeFailed
  } else if terminationReason == .exit && terminationStatus == 254 {
    quiescence = .notStarted
  } else {
    quiescence = .confirmed
  }
  return CompileProcessResult(
    setupError: setupError,
    timedOut: timedOut,
    terminationReason: terminationReason,
    terminationStatus: terminationStatus,
    stdout: stdout.snapshot,
    stderr: stderr.snapshot,
    stdoutDrain: stdoutFinished ? stdoutDrainRecorder.snapshot : .timedOut,
    stderrDrain: stderrFinished ? stderrDrainRecorder.snapshot : .timedOut,
    processGroupCleanup: cleanup,
    processGroupQuiescence: quiescence
  )
}

private func typecheckForbiddenFixture(
  _ fixture: URL,
  modules: URL,
  clangModules: URL,
  packageName: String
) -> CompileProcessResult {
  let isolatedExec = fixture.deletingLastPathComponent().appendingPathComponent("isolated_exec.py")
  return runIsolatedProcess(
    isolatedExec: isolatedExec,
    executable: "/usr/bin/swiftc",
    arguments: [
      "-typecheck", "-diagnostic-style", "llvm",
      "-no-color-diagnostics", "-I", modules.path, "-I", clangModules.path,
      "-package-name", packageName, fixture.path,
    ]
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
    stderrDrain: CompileDrainCompletion = .eof,
    processGroupQuiescence: CompileProcessGroupQuiescence = .confirmed
  ) -> CompileProcessResult {
    CompileProcessResult(
      setupError: setupError,
      timedOut: timedOut,
      terminationReason: terminationReason,
      terminationStatus: terminationStatus,
      stdout: CompileOutputSnapshot(text: stdout, truncated: stdoutTruncated),
      stderr: CompileOutputSnapshot(text: stderr, truncated: stderrTruncated),
      stdoutDrain: stdoutDrain,
      stderrDrain: stderrDrain,
      processGroupCleanup: .notRequired,
      processGroupQuiescence: processGroupQuiescence
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
  #expect(
    compileFailRejection(
      result: result(processGroupQuiescence: .timedOut),
      expectation: expectation
    ) != nil)
}

@Test func compileProcessSupervisorClosesWritersAndReapsWriterDescendants() throws {
  let root = try #require(repositoryRoot())
  let fixtures = root.appendingPathComponent(
    "fixtures/CompileFail/ContentAuthority", isDirectory: true)
  let isolatedExec = fixtures.appendingPathComponent("isolated_exec.py")

  var unrelatedProcesses: [Process] = []
  defer {
    for process in unrelatedProcesses where process.isRunning {
      process.terminate()
      process.waitUntilExit()
    }
  }
  let unrelatedSpawnResult = runIsolatedProcess(
    isolatedExec: isolatedExec,
    executable: "/usr/bin/true",
    arguments: [],
    leaderTimeout: .seconds(2),
    postExitDrainGrace: .milliseconds(100),
    termGrace: .milliseconds(100),
    finalDrainGrace: .seconds(1),
    endpointCreated: {
      let process = Process()
      process.executableURL = URL(fileURLWithPath: "/bin/sleep")
      process.arguments = ["60"]
      try process.run()
      unrelatedProcesses.append(process)
    }
  )
  #expect(unrelatedProcesses.count == 4 && unrelatedProcesses.allSatisfy(\.isRunning))
  #expect(
    unrelatedSpawnResult.setupError == nil && !unrelatedSpawnResult.timedOut
      && unrelatedSpawnResult.terminationReason == .exit
      && unrelatedSpawnResult.terminationStatus == 0
      && unrelatedSpawnResult.stdout.text.isEmpty
      && unrelatedSpawnResult.stderr.text.isEmpty
      && unrelatedSpawnResult.stdoutDrain == .eof
      && unrelatedSpawnResult.stderrDrain == .eof
      && unrelatedSpawnResult.processGroupCleanup == .notRequired
      && unrelatedSpawnResult.processGroupQuiescence == .confirmed,
    "Unrelated spawns inherited an atomic CLOEXEC capture endpoint: \(unrelatedSpawnResult.report)"
  )

  for iteration in 0..<32 {
    let result = runIsolatedProcess(
      isolatedExec: isolatedExec,
      executable: "/usr/bin/true",
      arguments: [],
      leaderTimeout: .seconds(2),
      postExitDrainGrace: .seconds(1),
      termGrace: .milliseconds(100),
      finalDrainGrace: .seconds(1)
    )
    #expect(
      result.setupError == nil && !result.timedOut
        && result.terminationReason == .exit && result.terminationStatus == 0
        && result.stdout.text.isEmpty && result.stderr.text.isEmpty
        && result.stdoutDrain == .eof && result.stderrDrain == .eof
        && result.processGroupCleanup == .notRequired
        && result.processGroupQuiescence == .confirmed,
      "Zero-output iteration \(iteration) did not close both parent writers: \(result.report)"
    )
  }

  let heldWriterResult = runIsolatedProcess(
    isolatedExec: isolatedExec,
    executable: "/usr/bin/python3",
    arguments: [fixtures.appendingPathComponent("hold_stdout_writer.py").path, "writer"],
    leaderTimeout: .seconds(2),
    postExitDrainGrace: .milliseconds(100),
    termGrace: .milliseconds(100),
    finalDrainGrace: .seconds(1)
  )
  #expect(
    heldWriterResult.setupError == nil && !heldWriterResult.timedOut
      && heldWriterResult.terminationReason == .exit && heldWriterResult.terminationStatus == 0
      && heldWriterResult.stdout.text.isEmpty && heldWriterResult.stderr.text.isEmpty
      && heldWriterResult.stdoutDrain == .eof && heldWriterResult.stderrDrain == .eof
      && heldWriterResult.processGroupCleanup == .notRequired
      && heldWriterResult.processGroupQuiescence == .confirmed,
    "Inherited stdout writer did not converge through bounded group cleanup: \(heldWriterResult.report)"
  )

  let silentDescendantResult = runIsolatedProcess(
    isolatedExec: isolatedExec,
    executable: "/usr/bin/python3",
    arguments: [fixtures.appendingPathComponent("hold_stdout_writer.py").path, "silent"],
    leaderTimeout: .seconds(2),
    postExitDrainGrace: .milliseconds(100),
    termGrace: .milliseconds(100),
    finalDrainGrace: .seconds(1)
  )
  #expect(
    silentDescendantResult.setupError == nil && !silentDescendantResult.timedOut
      && silentDescendantResult.terminationReason == .exit
      && silentDescendantResult.terminationStatus == 0
      && silentDescendantResult.stdout.text.isEmpty
      && silentDescendantResult.stderr.text.isEmpty
      && silentDescendantResult.stdoutDrain == .eof
      && silentDescendantResult.stderrDrain == .eof
      && silentDescendantResult.processGroupCleanup == .notRequired
      && silentDescendantResult.processGroupQuiescence == .confirmed,
    "Silent descendant was not quiesced independently of pipe EOF: \(silentDescendantResult.report)"
  )

  let setupFailureResult = runIsolatedProcess(
    isolatedExec: isolatedExec,
    executable: "/usr/bin/true",
    arguments: [],
    launcherExecutable: fixtures.path
  )
  #expect(
    setupFailureResult.setupError != nil && !setupFailureResult.timedOut
      && setupFailureResult.terminationReason == .unavailable
      && setupFailureResult.terminationStatus == nil
      && setupFailureResult.stdout.text.isEmpty && setupFailureResult.stderr.text.isEmpty
      && setupFailureResult.stdoutDrain == .eof && setupFailureResult.stderrDrain == .eof
      && setupFailureResult.processGroupCleanup == .notRequired
      && setupFailureResult.processGroupQuiescence == .notStarted,
    "Partial launch cleanup did not close both capture writers: \(setupFailureResult.report)"
  )
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
