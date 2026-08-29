import CDiskplanTestSupport
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

private enum CompileStartupState: String, Sendable {
  case notStarted
  case startupNotReady
  case failed
  case ready
}

private enum CompileStartupMilestone: String, CaseIterable, Sendable {
  case spawned
  case writerReady
  case drainsStarted
  case grantSent
  case grantAccepted
  case targetForkPermitted
  case targetForkedGated
  case targetLaunchPermitted
  case targetLaunchAcknowledged
}

private enum CompileStartupFailure: Error, CustomStringConvertible {
  case notReady(stage: String)
  case injectedNotReady(stage: String, after: CompileStartupMilestone)

  var description: String {
    switch self {
    case .notReady(let stage): "startup-not-ready(stage=\(stage))"
    case .injectedNotReady(let stage, let milestone):
      "startup-not-ready(stage=\(stage),injected-after=\(milestone.rawValue))"
    }
  }
}

private enum CompileStartupDeadlineInjection: Sendable {
  case none
  case afterGrantAccepted
  case afterTargetForkedGated
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
  private var started = false
  private var completion: CompileDrainCompletion?

  func recordStarted() {
    lock.withLock { started = true }
  }

  func record(_ completion: CompileDrainCompletion) {
    lock.withLock { self.completion = completion }
  }

  var didStart: Bool { lock.withLock { started } }

  var snapshot: CompileDrainCompletion {
    lock.withLock { completion ?? .readError("drain completed without a terminal state") }
  }
}

private struct CompileProcessResult: Sendable {
  let setupError: String?
  let startupState: CompileStartupState
  let startupMilestones: [CompileStartupMilestone]
  let timedOut: Bool
  let terminationReason: CompileTerminationReason
  let terminationStatus: Int32?
  let stdout: CompileOutputSnapshot
  let stderr: CompileOutputSnapshot
  let stdoutDrain: CompileDrainCompletion
  let stderrDrain: CompileDrainCompletion
  let stdoutDrainStarted: Bool
  let stderrDrainStarted: Bool
  let captureOwnership: String
  let processGroupCleanup: CompileProcessGroupCleanup
  let processGroupQuiescence: CompileProcessGroupQuiescence

  var report: String {
    "setupError=\(setupError ?? "none") startupState=\(startupState.rawValue) "
      + "startupMilestones=[\(startupMilestones.map(\.rawValue).joined(separator: ","))] "
      + "timedOut=\(timedOut) "
      + "termination=\(terminationReason.rawValue) "
      + "status=\(terminationStatus.map { String($0) } ?? "none") "
      + "stdoutTruncated=\(stdout.truncated) stderrTruncated=\(stderr.truncated) "
      + "stdoutDrain=\(stdoutDrain.report) stderrDrain=\(stderrDrain.report) "
      + "stdoutDrainStarted=\(stdoutDrainStarted) stderrDrainStarted=\(stderrDrainStarted) "
      + "captureOwnership=\(String(reflecting: captureOwnership)) "
      + "processGroupCleanup=\(processGroupCleanup.rawValue) "
      + "processGroupQuiescence=\(processGroupQuiescence.rawValue) "
      + "stdout=\(String(reflecting: stdout.text)) stderr=\(String(reflecting: stderr.text))"
  }
}

private final class AtomicCaptureChannel: @unchecked Sendable {
  let reader: FileHandle
  let fifoPath: String
  private let directoryPath: String
  private let lock = NSLock()
  private var readerActivated = false

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

    try endpointCreated()
    var readerDescriptor = fifoPath.withCString {
      Darwin.open($0, O_RDONLY | O_NONBLOCK | O_CLOEXEC)
    }
    guard readerDescriptor >= 0 else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    do {
      try endpointCreated()
    } catch {
      Darwin.close(readerDescriptor)
      throw error
    }
    if readerDescriptor < STDERR_FILENO + 1 {
      let duplicated = Darwin.fcntl(readerDescriptor, F_DUPFD_CLOEXEC, STDERR_FILENO + 1)
      guard duplicated >= 0 else {
        let failure = errno
        Darwin.close(readerDescriptor)
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(failure))
      }
      Darwin.close(readerDescriptor)
      readerDescriptor = duplicated
    }
    cleanupRequired = false
    self.directoryPath = directoryPath
    self.fifoPath = fifoPath
    reader = FileHandle(fileDescriptor: readerDescriptor, closeOnDealloc: true)
  }

  deinit {
    try? reader.close()
    _ = fifoPath.withCString(Darwin.unlink)
    _ = directoryPath.withCString(Darwin.rmdir)
  }

  func activateReader() throws {
    try lock.withLock {
      precondition(!readerActivated, "capture reader already activated")
      let descriptor = reader.fileDescriptor
      let readerFlags = Darwin.fcntl(descriptor, F_GETFL)
      guard readerFlags >= 0,
        Darwin.fcntl(descriptor, F_SETFL, readerFlags & ~O_NONBLOCK) == 0
      else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
      }
      readerActivated = true
    }
  }

  func closeReader() { try? reader.close() }
}

private final class CompileCaptureControl: @unchecked Sendable {
  static let childDescriptor: Int32 = 3

  private let lock = NSLock()
  private var parentDescriptor: Int32?
  private var childSourceDescriptor: Int32?

  init() throws {
    // The control pair carries seven one-byte startup frames and never carries
    // captured output.
    // Its endpoints may be inherited across a concurrent fork, but capture EOF
    // cannot depend on them because the test runner never owns a FIFO writer.
    var descriptors: [Int32] = [-1, -1]
    guard Darwin.socketpair(AF_UNIX, SOCK_STREAM, 0, &descriptors) == 0 else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    do {
      var noSignal: Int32 = 1
      guard
        Darwin.setsockopt(
          descriptors[0], SOL_SOCKET, SO_NOSIGPIPE, &noSignal,
          socklen_t(MemoryLayout.size(ofValue: noSignal))) == 0
      else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
      }
      for index in descriptors.indices {
        let duplicated = Darwin.fcntl(descriptors[index], F_DUPFD_CLOEXEC, 10)
        guard duplicated >= 0 else {
          throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
        Darwin.close(descriptors[index])
        descriptors[index] = duplicated
      }
    } catch {
      for descriptor in descriptors where descriptor >= 0 { Darwin.close(descriptor) }
      throw error
    }
    parentDescriptor = descriptors[0]
    childSourceDescriptor = descriptors[1]
  }

  deinit {
    closeParent()
    closeChildSource()
  }

  var childSource: Int32 {
    lock.withLock {
      precondition(childSourceDescriptor != nil, "capture control child source already closed")
      return childSourceDescriptor!
    }
  }

  func closeChildSource() {
    let descriptor = lock.withLock { () -> Int32? in
      defer { childSourceDescriptor = nil }
      return childSourceDescriptor
    }
    if let descriptor { Darwin.close(descriptor) }
  }

  func closeParent() {
    let descriptor = lock.withLock { () -> Int32? in
      defer { parentDescriptor = nil }
      return parentDescriptor
    }
    if let descriptor { Darwin.close(descriptor) }
  }

  private func waitForFrame(
    _ expected: UInt8,
    stage: String,
    until deadline: DispatchTime
  ) throws {
    let descriptor = try lock.withLock { () throws -> Int32 in
      guard let parentDescriptor else {
        throw compileProcessFailure("capture-control-closed", EBADF)
      }
      return parentDescriptor
    }
    var pollDescriptor = pollfd(fd: descriptor, events: Int16(POLLIN | POLLHUP), revents: 0)
    while true {
      let now = DispatchTime.now().uptimeNanoseconds
      guard now < deadline.uptimeNanoseconds else {
        throw CompileStartupFailure.notReady(stage: stage)
      }
      let remainingNanoseconds = deadline.uptimeNanoseconds - now
      let remainingMilliseconds = min(
        UInt64(Int32.max), (remainingNanoseconds + 999_999) / 1_000_000)
      let result = Darwin.poll(&pollDescriptor, 1, Int32(remainingMilliseconds))
      if result == -1, errno == EINTR { continue }
      guard result > 0 else {
        if result == 0 { throw CompileStartupFailure.notReady(stage: stage) }
        throw compileProcessFailure("capture-control-ready-poll", errno)
      }
      var ready: UInt8 = 0
      let count = Darwin.read(descriptor, &ready, 1)
      guard count == 1, ready == expected else {
        throw compileProcessFailure("capture-control-ready-frame", EPROTO)
      }
      return
    }
  }

  func waitForWriterReady(until deadline: DispatchTime) throws {
    try waitForFrame(0x52, stage: "writer-ready", until: deadline)
  }

  func waitForGrantAccepted(until deadline: DispatchTime) throws {
    try waitForFrame(0x41, stage: "grant-accepted", until: deadline)
  }

  func waitForTargetForkedGated(until deadline: DispatchTime) throws {
    try waitForFrame(0x46, stage: "target-forked-gated", until: deadline)
  }

  func waitForTargetLaunch(until deadline: DispatchTime) throws {
    try waitForFrame(0x4c, stage: "target-launch", until: deadline)
  }

  private func sendFrame(_ frame: UInt8, operation: String) throws {
    let descriptor = try lock.withLock { () throws -> Int32 in
      guard let parentDescriptor else {
        throw compileProcessFailure("capture-control-closed", EBADF)
      }
      return parentDescriptor
    }
    var frame = frame
    while Darwin.write(descriptor, &frame, 1) == -1 {
      if errno == EINTR { continue }
      throw compileProcessFailure(operation, errno)
    }
  }

  func grantExecution() throws {
    try sendFrame(0x47, operation: "capture-control-grant")
  }

  func permitTargetFork() throws {
    try sendFrame(0x50, operation: "capture-control-target-fork")
  }

  func permitTargetLaunch() throws {
    try sendFrame(0x43, operation: "capture-control-target-launch")
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
  guard result.startupState == .ready else {
    return "compiler startup did not become ready: \(result.startupState.rawValue)"
  }
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
  guard result.stdoutDrainStarted, result.stderrDrainStarted else {
    return "compiler output drains did not start"
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
  group: DispatchGroup,
  name: String
) -> DispatchSemaphore {
  let started = DispatchSemaphore(value: 0)
  group.enter()
  let thread = Thread {
    defer { group.leave() }
    recorder.recordStarted()
    started.signal()
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
  thread.name = name
  thread.qualityOfService = .userInitiated
  thread.start()
  return started
}

private func drainCompleted(_ group: DispatchGroup, within deadline: DispatchTime) -> Bool {
  group.wait(timeout: deadline) == .success
}

private func boundedCaptureOwnershipDiagnostic(paths: [String]) -> String {
  var outputTemplate = Array(
    (NSTemporaryDirectory() + "diskplan-capture-owners.XXXXXX").utf8CString)
  let descriptor = outputTemplate.withUnsafeMutableBufferPointer {
    Darwin.mkstemp($0.baseAddress!)
  }
  guard descriptor >= 0 else { return "lsofOutputCreateFailed(errno=\(errno))" }
  _ = outputTemplate.withUnsafeMutableBufferPointer { Darwin.unlink($0.baseAddress!) }
  defer { Darwin.close(descriptor) }
  guard Darwin.fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else {
    return "lsofOutputCloexecFailed(errno=\(errno))"
  }

  let processID: pid_t
  do {
    processID = try spawnOwnershipDiagnostic(
      arguments: ["-nP", "-F0pcfDino", "--"] + paths,
      outputDescriptor: descriptor
    )
  } catch {
    return "lsofLaunchFailed(\(String(reflecting: error)))"
  }
  let initialWait = waitForCompileChild(processID, until: .now() + .seconds(2))
  let waitStatus: Int32
  switch initialWait {
  case .exited(let status):
    waitStatus = status
  case .failed(let code):
    return "lsofWaitFailed(errno=\(code))"
  case .timedOut:
    let forced = forceStopCompileChild(processID)
    guard let status = forced.waitStatus else {
      return "lsofTimedOut(\(forced.report))"
    }
    waitStatus = status
  }

  guard Darwin.lseek(descriptor, 0, SEEK_SET) == 0 else {
    return "lsofOutputSeekFailed(errno=\(errno))"
  }
  var retained = [UInt8](repeating: 0, count: 16 * 1_024 + 1)
  let count = retained.withUnsafeMutableBytes {
    Darwin.read(descriptor, $0.baseAddress, $0.count)
  }
  guard count >= 0 else { return "lsofOutputReadFailed(errno=\(errno))" }
  let truncated = count > 16 * 1_024
  let boundedCount = min(Int(count), 16 * 1_024)
  let termination = decodedCompileTermination(waitStatus)
  return "lsofTermination=\(termination.reason.rawValue) status="
    + "\(termination.status.map(String.init) ?? "none") truncated=\(truncated) output="
    + String(reflecting: String(decoding: retained.prefix(boundedCount), as: UTF8.self))
}

private func emptyCompileProcessResult(
  setupError: String,
  startupState: CompileStartupState = .notStarted,
  startupMilestones: [CompileStartupMilestone] = []
) -> CompileProcessResult {
  CompileProcessResult(
    setupError: setupError,
    startupState: startupState,
    startupMilestones: startupMilestones,
    timedOut: false,
    terminationReason: .unavailable,
    terminationStatus: nil,
    stdout: CompileOutputSnapshot(text: "", truncated: false),
    stderr: CompileOutputSnapshot(text: "", truncated: false),
    stdoutDrain: .readError("stdout capture was not started"),
    stderrDrain: .readError("stderr capture was not started"),
    stdoutDrainStarted: false,
    stderrDrainStarted: false,
    captureOwnership: "notRequested",
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

private func spawnOwnershipDiagnostic(
  arguments: [String],
  outputDescriptor: Int32
) throws -> pid_t {
  let command = ["/usr/sbin/lsof"] + arguments
  var allocations: [UnsafeMutablePointer<CChar>] = []
  defer { for allocation in allocations { Darwin.free(allocation) } }
  for argument in command {
    guard let allocation = argument.withCString({ Darwin.strdup($0) }) else {
      throw compileProcessFailure("lsof-allocate-argv", ENOMEM)
    }
    allocations.append(allocation)
  }
  var argv = allocations.map(Optional.some)
  argv.append(nil)

  var environmentAllocations: [UnsafeMutablePointer<CChar>] = []
  defer { for allocation in environmentAllocations { Darwin.free(allocation) } }
  for entry in ProcessInfo.processInfo.environment.map({ "\($0.key)=\($0.value)" }).sorted() {
    guard let allocation = entry.withCString({ Darwin.strdup($0) }) else {
      throw compileProcessFailure("lsof-allocate-environment", ENOMEM)
    }
    environmentAllocations.append(allocation)
  }
  var environment = environmentAllocations.map(Optional.some)
  environment.append(nil)

  var fileActions: posix_spawn_file_actions_t?
  var status = posix_spawn_file_actions_init(&fileActions)
  guard status == 0 else { throw compileProcessFailure("lsof-file-actions-init", status) }
  defer { _ = posix_spawn_file_actions_destroy(&fileActions) }
  status = "/dev/null".withCString {
    posix_spawn_file_actions_addopen(&fileActions, STDIN_FILENO, $0, O_RDONLY, 0)
  }
  guard status == 0 else { throw compileProcessFailure("lsof-file-actions-stdin", status) }
  status = posix_spawn_file_actions_adddup2(&fileActions, outputDescriptor, STDOUT_FILENO)
  guard status == 0 else { throw compileProcessFailure("lsof-file-actions-stdout", status) }
  status = posix_spawn_file_actions_adddup2(&fileActions, outputDescriptor, STDERR_FILENO)
  guard status == 0 else { throw compileProcessFailure("lsof-file-actions-stderr", status) }
  status = posix_spawn_file_actions_addclose(&fileActions, outputDescriptor)
  guard status == 0 else { throw compileProcessFailure("lsof-file-actions-close", status) }

  var attributes: posix_spawnattr_t?
  status = posix_spawnattr_init(&attributes)
  guard status == 0 else { throw compileProcessFailure("lsof-attributes-init", status) }
  defer { _ = posix_spawnattr_destroy(&attributes) }
  status = posix_spawnattr_setpgroup(&attributes, 0)
  guard status == 0 else { throw compileProcessFailure("lsof-attributes-pgroup", status) }
  status = posix_spawnattr_setflags(
    &attributes,
    Int16(POSIX_SPAWN_SETPGROUP | POSIX_SPAWN_CLOEXEC_DEFAULT)
  )
  guard status == 0 else { throw compileProcessFailure("lsof-attributes-flags", status) }

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
  guard status == 0 else { throw compileProcessFailure("lsof-posix-spawn", status) }
  return processID
}

private func spawnIsolatedProcess(
  isolatedExec: URL,
  executable: String,
  arguments: [String],
  launcherExecutable: String,
  controlSource: Int32,
  stdoutFIFO: String,
  stderrFIFO: String,
  startupDelayMilliseconds: Int
) throws -> pid_t {
  let command =
    [
      launcherExecutable, isolatedExec.path,
      "--capture-control-fd", String(CompileCaptureControl.childDescriptor),
      "--stdout-fifo", stdoutFIFO,
      "--stderr-fifo", stderrFIFO,
      "--startup-delay-milliseconds", String(startupDelayMilliseconds),
      "--", executable,
    ] + arguments
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
  status = "/dev/null".withCString {
    posix_spawn_file_actions_addopen(&fileActions, STDOUT_FILENO, $0, O_WRONLY, 0)
  }
  guard status == 0 else { throw compileProcessFailure("file-actions-stdout", status) }
  status = "/dev/null".withCString {
    posix_spawn_file_actions_addopen(&fileActions, STDERR_FILENO, $0, O_WRONLY, 0)
  }
  guard status == 0 else { throw compileProcessFailure("file-actions-stderr", status) }
  status = posix_spawn_file_actions_adddup2(
    &fileActions, controlSource, CompileCaptureControl.childDescriptor)
  guard status == 0 else { throw compileProcessFailure("file-actions-control", status) }
  status = posix_spawn_file_actions_addclose(&fileActions, controlSource)
  guard status == 0 else { throw compileProcessFailure("file-actions-close-control", status) }

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

private struct ForcedCompileCleanup {
  let cleanup: CompileProcessGroupCleanup
  let waitStatus: Int32?
  let report: String
}

private func signalCompileChild(_ processID: pid_t, signal: Int32) -> String {
  if Darwin.kill(-processID, signal) == 0 { return "group-sent" }
  let groupError = errno
  if Darwin.kill(processID, signal) == 0 {
    return "pid-sent(group-errno=\(groupError))"
  }
  return "signal-failed(group-errno=\(groupError),pid-errno=\(errno))"
}

private func forceStopCompileChild(_ processID: pid_t) -> ForcedCompileCleanup {
  switch waitForCompileChild(processID, until: .now()) {
  case .exited(let status):
    return ForcedCompileCleanup(
      cleanup: .notRequired, waitStatus: status, report: "already-reaped")
  case .failed(let code):
    return ForcedCompileCleanup(
      cleanup: .notRequired, waitStatus: nil, report: "initial-wait-failed(errno=\(code))")
  case .timedOut:
    break
  }

  let termReport = signalCompileChild(processID, signal: SIGTERM)
  switch waitForCompileChild(processID, until: .now() + .milliseconds(250)) {
  case .exited(let status):
    return ForcedCompileCleanup(
      cleanup: .termSent,
      waitStatus: status,
      report: "term=\(termReport),reaped-after-term"
    )
  case .failed(let code):
    return ForcedCompileCleanup(
      cleanup: .termSent,
      waitStatus: nil,
      report: "term=\(termReport),wait-after-term-failed(errno=\(code))"
    )
  case .timedOut:
    break
  }

  let killReport = signalCompileChild(processID, signal: SIGKILL)
  switch waitForCompileChild(processID, until: .now() + .seconds(2)) {
  case .exited(let status):
    return ForcedCompileCleanup(
      cleanup: .killSent,
      waitStatus: status,
      report: "term=\(termReport),kill=\(killReport),reaped-after-kill"
    )
  case .failed(let code):
    return ForcedCompileCleanup(
      cleanup: .killSent,
      waitStatus: nil,
      report:
        "term=\(termReport),kill=\(killReport),wait-after-kill-failed(errno=\(code))"
    )
  case .timedOut:
    return ForcedCompileCleanup(
      cleanup: .killSent,
      waitStatus: nil,
      report: "term=\(termReport),kill=\(killReport),unreaped-residual-pid=\(processID)"
    )
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
  startupTimeout: DispatchTimeInterval = .seconds(15),
  startupDelayMilliseconds: Int = 0,
  deadlineInjection: CompileStartupDeadlineInjection = .none,
  leaderTimeout: DispatchTimeInterval = .seconds(10),
  postExitDrainGrace: DispatchTimeInterval = .milliseconds(250),
  termGrace: DispatchTimeInterval = .milliseconds(250),
  finalDrainGrace: DispatchTimeInterval = .seconds(2),
  endpointCreated: () throws -> Void = {},
  beforeSpawn: () throws -> Void = {}
) -> CompileProcessResult {
  guard (0...60_000).contains(startupDelayMilliseconds) else {
    return emptyCompileProcessResult(setupError: "invalid startup delay")
  }
  let stdoutChannel: AtomicCaptureChannel
  let stderrChannel: AtomicCaptureChannel
  let captureControl: CompileCaptureControl
  do {
    stdoutChannel = try AtomicCaptureChannel(endpointCreated: endpointCreated)
    stderrChannel = try AtomicCaptureChannel(endpointCreated: endpointCreated)
    captureControl = try CompileCaptureControl()
    try beforeSpawn()
  } catch {
    return emptyCompileProcessResult(setupError: String(reflecting: error))
  }

  let stdout = BoundedDiagnosticCapture()
  let stderr = BoundedDiagnosticCapture()
  let stdoutDrain = DispatchGroup()
  let stderrDrain = DispatchGroup()
  let stdoutDrainRecorder = CompileDrainRecorder()
  let stderrDrainRecorder = CompileDrainRecorder()
  var startupMilestones: [CompileStartupMilestone] = []
  let processID: pid_t
  // One absolute deadline covers process launch, writer readiness, both drain
  // start acknowledgements, the execution grant, and the grant, gated-fork, and
  // target-launch acknowledgements. The required macOS lane runs the complete
  // suite at maximum parallelism, so startup is allowed a bounded 15-second
  // scheduling window instead of several independent short phase timeouts.
  let startupDeadline = DispatchTime.now() + startupTimeout
  do {
    processID = try spawnIsolatedProcess(
      isolatedExec: isolatedExec,
      executable: executable,
      arguments: arguments,
      launcherExecutable: launcherExecutable,
      controlSource: captureControl.childSource,
      stdoutFIFO: stdoutChannel.fifoPath,
      stderrFIFO: stderrChannel.fifoPath,
      startupDelayMilliseconds: startupDelayMilliseconds
    )
    startupMilestones.append(.spawned)
  } catch {
    captureControl.closeChildSource()
    captureControl.closeParent()
    stdoutChannel.closeReader()
    stderrChannel.closeReader()
    return emptyCompileProcessResult(
      setupError: String(reflecting: error),
      startupMilestones: startupMilestones
    )
  }
  captureControl.closeChildSource()

  do {
    try captureControl.waitForWriterReady(until: startupDeadline)
    startupMilestones.append(.writerReady)
    try stdoutChannel.activateReader()
    try stderrChannel.activateReader()
    let stdoutStarted = startDrain(
      reader: stdoutChannel.reader,
      capture: stdout,
      recorder: stdoutDrainRecorder,
      group: stdoutDrain,
      name: "diskplan-compile-stdout"
    )
    let stderrStarted = startDrain(
      reader: stderrChannel.reader,
      capture: stderr,
      recorder: stderrDrainRecorder,
      group: stderrDrain,
      name: "diskplan-compile-stderr"
    )
    guard stdoutStarted.wait(timeout: startupDeadline) == .success,
      stderrStarted.wait(timeout: startupDeadline) == .success
    else {
      throw CompileStartupFailure.notReady(stage: "drain-start")
    }
    startupMilestones.append(.drainsStarted)
    guard DispatchTime.now().uptimeNanoseconds < startupDeadline.uptimeNanoseconds else {
      throw CompileStartupFailure.notReady(stage: "execution-grant")
    }
    try captureControl.grantExecution()
    startupMilestones.append(.grantSent)
    try captureControl.waitForGrantAccepted(until: startupDeadline)
    startupMilestones.append(.grantAccepted)
    if case .afterGrantAccepted = deadlineInjection {
      throw CompileStartupFailure.injectedNotReady(
        stage: "target-launch",
        after: .grantAccepted
      )
    }
    try captureControl.permitTargetFork()
    startupMilestones.append(.targetForkPermitted)
    try captureControl.waitForTargetForkedGated(until: startupDeadline)
    startupMilestones.append(.targetForkedGated)
    if case .afterTargetForkedGated = deadlineInjection {
      throw CompileStartupFailure.injectedNotReady(
        stage: "target-launch",
        after: .targetForkedGated
      )
    }
    try captureControl.permitTargetLaunch()
    startupMilestones.append(.targetLaunchPermitted)
    try captureControl.waitForTargetLaunch(until: startupDeadline)
    startupMilestones.append(.targetLaunchAcknowledged)
    captureControl.closeParent()
  } catch {
    let forcedCleanup = forceStopCompileChild(processID)
    captureControl.closeParent()
    stdoutChannel.closeReader()
    stderrChannel.closeReader()
    let stdoutFinished = drainCompleted(stdoutDrain, within: .now() + .seconds(1))
    let stderrFinished = drainCompleted(stderrDrain, within: .now() + .seconds(1))
    let startupState: CompileStartupState =
      error is CompileStartupFailure ? .startupNotReady : .failed
    let errorReport =
      (error as? CompileStartupFailure)?.description ?? String(reflecting: error)
    return CompileProcessResult(
      setupError: errorReport + "; cleanup=" + forcedCleanup.report,
      startupState: startupState,
      startupMilestones: startupMilestones,
      timedOut: false,
      terminationReason: .unavailable,
      terminationStatus: nil,
      stdout: stdout.snapshot,
      stderr: stderr.snapshot,
      stdoutDrain: stdoutFinished ? stdoutDrainRecorder.snapshot : .timedOut,
      stderrDrain: stderrFinished ? stderrDrainRecorder.snapshot : .timedOut,
      stdoutDrainStarted: stdoutDrainRecorder.didStart,
      stderrDrainStarted: stderrDrainRecorder.didStart,
      captureOwnership: "notRequested",
      processGroupCleanup: forcedCleanup.cleanup,
      processGroupQuiescence: .notStarted
    )
  }

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
  let captureOwnership =
    stdoutFinished && stderrFinished
    ? "notRequested"
    : boundedCaptureOwnershipDiagnostic(paths: [stdoutChannel.fifoPath, stderrChannel.fifoPath])
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
    startupState: .ready,
    startupMilestones: startupMilestones,
    timedOut: timedOut,
    terminationReason: terminationReason,
    terminationStatus: terminationStatus,
    stdout: stdout.snapshot,
    stderr: stderr.snapshot,
    stdoutDrain: stdoutFinished ? stdoutDrainRecorder.snapshot : .timedOut,
    stderrDrain: stderrFinished ? stderrDrainRecorder.snapshot : .timedOut,
    stdoutDrainStarted: stdoutDrainRecorder.didStart,
    stderrDrainStarted: stderrDrainRecorder.didStart,
    captureOwnership: captureOwnership,
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

private final class ForkOnlyChildren: @unchecked Sendable {
  private let lock = NSLock()
  private var processIDs: [pid_t] = []

  func spawn() throws {
    let processID = diskplan_test_fork_and_pause()
    guard processID >= 0 else {
      throw compileProcessFailure("fork-only-child", errno)
    }
    if processID == 0 {
      while true { _ = Darwin.pause() }
    }
    lock.withLock { processIDs.append(processID) }
  }

  func stopAndReap() {
    let identifiers = lock.withLock { () -> [pid_t] in
      defer { processIDs.removeAll(keepingCapacity: false) }
      return processIDs
    }
    for processID in identifiers { _ = Darwin.kill(processID, SIGKILL) }
    for processID in identifiers {
      var status: Int32 = 0
      while Darwin.waitpid(processID, &status, 0) == -1, errno == EINTR {}
    }
  }
}

private final class CompileProcessResults: @unchecked Sendable {
  private let lock = NSLock()
  private var results: [CompileProcessResult] = []

  func append(_ result: CompileProcessResult) {
    lock.withLock { results.append(result) }
  }

  var snapshot: [CompileProcessResult] { lock.withLock { results } }
}

@Test func compileFailClassifierRejectsInfrastructureFailures() {
  let expectation = forbiddenSurfaceExpectations[0]
  let diagnostic =
    "\(expectation.markerFile):\(expectation.markerLine):1: error: initializer is inaccessible due to 'fileprivate' protection level\n"
    + "let request = ContentCollectionRequestID(rawValue: value)\n"
  func result(
    setupError: String? = nil,
    startupState: CompileStartupState = .ready,
    startupMilestones: [CompileStartupMilestone] = CompileStartupMilestone.allCases,
    timedOut: Bool = false,
    terminationReason: CompileTerminationReason = .exit,
    terminationStatus: Int32? = 1,
    stdout: String = "",
    stderr: String = diagnostic,
    stdoutTruncated: Bool = false,
    stderrTruncated: Bool = false,
    stdoutDrain: CompileDrainCompletion = .eof,
    stderrDrain: CompileDrainCompletion = .eof,
    stdoutDrainStarted: Bool = true,
    stderrDrainStarted: Bool = true,
    processGroupQuiescence: CompileProcessGroupQuiescence = .confirmed
  ) -> CompileProcessResult {
    CompileProcessResult(
      setupError: setupError,
      startupState: startupState,
      startupMilestones: startupMilestones,
      timedOut: timedOut,
      terminationReason: terminationReason,
      terminationStatus: terminationStatus,
      stdout: CompileOutputSnapshot(text: stdout, truncated: stdoutTruncated),
      stderr: CompileOutputSnapshot(text: stderr, truncated: stderrTruncated),
      stdoutDrain: stdoutDrain,
      stderrDrain: stderrDrain,
      stdoutDrainStarted: stdoutDrainStarted,
      stderrDrainStarted: stderrDrainStarted,
      captureOwnership: "notRequested",
      processGroupCleanup: .notRequired,
      processGroupQuiescence: processGroupQuiescence
    )
  }

  #expect(compileFailRejection(result: result(), expectation: expectation) == nil)
  #expect(
    compileFailRejection(
      result: result(startupState: .startupNotReady),
      expectation: expectation
    ) != nil)
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
      result: result(stdoutDrainStarted: false),
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

  let delayedStartupResult = runIsolatedProcess(
    isolatedExec: isolatedExec,
    executable: "/usr/bin/true",
    arguments: [],
    startupDelayMilliseconds: 3_000,
    leaderTimeout: .seconds(2)
  )
  #expect(
    delayedStartupResult.startupState == .ready
      && delayedStartupResult.startupMilestones == CompileStartupMilestone.allCases
      && delayedStartupResult.setupError == nil && !delayedStartupResult.timedOut
      && delayedStartupResult.terminationReason == .exit
      && delayedStartupResult.terminationStatus == 0
      && delayedStartupResult.stdoutDrain == .eof
      && delayedStartupResult.stderrDrain == .eof,
    "An in-budget delayed wrapper did not complete startup: \(delayedStartupResult.report)"
  )

  let neverReadyResult = runIsolatedProcess(
    isolatedExec: isolatedExec,
    executable: "/usr/bin/true",
    arguments: [],
    startupTimeout: .milliseconds(100),
    startupDelayMilliseconds: 5_000,
    leaderTimeout: .seconds(2)
  )
  #expect(
    neverReadyResult.startupState == .startupNotReady
      && neverReadyResult.setupError?.contains("startup-not-ready(stage=writer-ready)") == true
      && neverReadyResult.startupMilestones == [.spawned]
      && !neverReadyResult.timedOut
      && neverReadyResult.terminationReason == .unavailable
      && !neverReadyResult.stdoutDrainStarted && !neverReadyResult.stderrDrainStarted
      && neverReadyResult.captureOwnership == "notRequested"
      && neverReadyResult.processGroupCleanup != .notRequired,
    "A wrapper that never became ready was not bounded and typed: \(neverReadyResult.report)"
  )

  let neverLaunchedResult = runIsolatedProcess(
    isolatedExec: isolatedExec,
    executable: "/usr/bin/true",
    arguments: [],
    deadlineInjection: .afterGrantAccepted,
    leaderTimeout: .seconds(2)
  )
  #expect(
    neverLaunchedResult.startupState == .startupNotReady
      && neverLaunchedResult.setupError?.contains(
        "startup-not-ready(stage=target-launch,injected-after=grantAccepted)") == true
      && neverLaunchedResult.startupMilestones == [
        .spawned, .writerReady, .drainsStarted, .grantSent, .grantAccepted,
      ]
      && !neverLaunchedResult.timedOut
      && neverLaunchedResult.terminationReason == .unavailable
      && neverLaunchedResult.stdoutDrainStarted && neverLaunchedResult.stderrDrainStarted
      && neverLaunchedResult.stdoutDrain == .eof
      && neverLaunchedResult.stderrDrain == .eof
      && neverLaunchedResult.captureOwnership == "notRequested"
      && neverLaunchedResult.processGroupCleanup != .notRequired,
    "A granted wrapper that never launched its target was not bounded and typed: \(neverLaunchedResult.report)"
  )

  let postForkMarker = FileManager.default.temporaryDirectory.appendingPathComponent(
    "diskplan-post-fork-target-\(UUID().uuidString)"
  )
  defer { try? FileManager.default.removeItem(at: postForkMarker) }
  let neverAcknowledgedResult = runIsolatedProcess(
    isolatedExec: isolatedExec,
    executable: "/usr/bin/touch",
    arguments: [postForkMarker.path],
    deadlineInjection: .afterTargetForkedGated,
    leaderTimeout: .seconds(2)
  )
  #expect(
    neverAcknowledgedResult.startupState == .startupNotReady
      && neverAcknowledgedResult.setupError?.contains(
        "startup-not-ready(stage=target-launch,injected-after=targetForkedGated)") == true
      && neverAcknowledgedResult.startupMilestones == [
        .spawned, .writerReady, .drainsStarted, .grantSent, .grantAccepted,
        .targetForkPermitted, .targetForkedGated,
      ]
      && !neverAcknowledgedResult.timedOut
      && neverAcknowledgedResult.terminationReason == .unavailable
      && neverAcknowledgedResult.stdoutDrainStarted
      && neverAcknowledgedResult.stderrDrainStarted
      && neverAcknowledgedResult.stdoutDrain == .eof
      && neverAcknowledgedResult.stderrDrain == .eof
      && neverAcknowledgedResult.captureOwnership == "notRequested"
      && neverAcknowledgedResult.processGroupCleanup != .notRequired
      && !FileManager.default.fileExists(atPath: postForkMarker.path),
    "A forked gated target survived before launch acknowledgement: \(neverAcknowledgedResult.report)"
  )

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
    unrelatedSpawnResult.startupState == .ready
      && unrelatedSpawnResult.setupError == nil && !unrelatedSpawnResult.timedOut
      && unrelatedSpawnResult.terminationReason == .exit
      && unrelatedSpawnResult.terminationStatus == 0
      && unrelatedSpawnResult.stdout.text.isEmpty
      && unrelatedSpawnResult.stderr.text.isEmpty
      && unrelatedSpawnResult.stdoutDrainStarted
      && unrelatedSpawnResult.stderrDrainStarted
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
      result.startupState == .ready && result.setupError == nil && !result.timedOut
        && result.terminationReason == .exit && result.terminationStatus == 0
        && result.stdout.text.isEmpty && result.stderr.text.isEmpty
        && result.stdoutDrainStarted && result.stderrDrainStarted
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
    heldWriterResult.startupState == .ready
      && heldWriterResult.setupError == nil && !heldWriterResult.timedOut
      && heldWriterResult.terminationReason == .exit && heldWriterResult.terminationStatus == 0
      && heldWriterResult.stdout.text.isEmpty && heldWriterResult.stderr.text.isEmpty
      && heldWriterResult.stdoutDrainStarted && heldWriterResult.stderrDrainStarted
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
    silentDescendantResult.startupState == .ready
      && silentDescendantResult.setupError == nil && !silentDescendantResult.timedOut
      && silentDescendantResult.terminationReason == .exit
      && silentDescendantResult.terminationStatus == 0
      && silentDescendantResult.stdout.text.isEmpty
      && silentDescendantResult.stderr.text.isEmpty
      && silentDescendantResult.stdoutDrainStarted
      && silentDescendantResult.stderrDrainStarted
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
    setupFailureResult.startupState == .notStarted
      && setupFailureResult.setupError != nil && !setupFailureResult.timedOut
      && setupFailureResult.terminationReason == .unavailable
      && setupFailureResult.terminationStatus == nil
      && setupFailureResult.stdout.text.isEmpty && setupFailureResult.stderr.text.isEmpty
      && !setupFailureResult.stdoutDrainStarted && !setupFailureResult.stderrDrainStarted
      && setupFailureResult.processGroupCleanup == .notRequired
      && setupFailureResult.processGroupQuiescence == .notStarted,
    "Partial launch cleanup did not close both capture writers: \(setupFailureResult.report)"
  )

  let handshakeFailureResult = runIsolatedProcess(
    isolatedExec: isolatedExec,
    executable: "/usr/bin/true",
    arguments: [],
    launcherExecutable: "/usr/bin/true"
  )
  #expect(
    handshakeFailureResult.startupState == .failed
      && handshakeFailureResult.setupError != nil && !handshakeFailureResult.timedOut
      && handshakeFailureResult.terminationReason == .unavailable
      && handshakeFailureResult.terminationStatus == nil
      && !handshakeFailureResult.stdoutDrainStarted
      && !handshakeFailureResult.stderrDrainStarted
      && handshakeFailureResult.processGroupQuiescence == .notStarted,
    "A launcher that skipped the capture handshake was accepted: \(handshakeFailureResult.report)"
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

@Test func concurrentForkOnlyChildrenCannotInheritCaptureWriters() throws {
  let root = try #require(repositoryRoot())
  let isolatedExec = root.appendingPathComponent(
    "fixtures/CompileFail/ContentAuthority/isolated_exec.py")
  let results = CompileProcessResults()

  DispatchQueue.concurrentPerform(iterations: 8) { _ in
    let children = ForkOnlyChildren()
    defer { children.stopAndReap() }
    results.append(
      runIsolatedProcess(
        isolatedExec: isolatedExec,
        executable: "/usr/bin/true",
        arguments: [],
        leaderTimeout: .seconds(2),
        postExitDrainGrace: .milliseconds(100),
        termGrace: .milliseconds(100),
        finalDrainGrace: .seconds(1),
        beforeSpawn: { try children.spawn() }
      ))
  }

  let snapshot = results.snapshot
  #expect(snapshot.count == 8)
  for result in snapshot {
    #expect(
      result.startupState == .ready,
      "A capture supervisor did not complete startup: \(result.report)"
    )
    guard result.startupState == .ready else { continue }
    #expect(
      result.setupError == nil && !result.timedOut
        && result.terminationReason == .exit && result.terminationStatus == 0
        && result.processGroupQuiescence == .confirmed,
      "A capture supervisor failed after startup: \(result.report)"
    )
    guard
      result.setupError == nil && !result.timedOut
        && result.terminationReason == .exit && result.terminationStatus == 0
        && result.processGroupQuiescence == .confirmed
    else {
      continue
    }
    #expect(
      result.stdout.text.isEmpty && result.stderr.text.isEmpty
        && result.stdoutDrainStarted && result.stderrDrainStarted
        && result.stdoutDrain == .eof && result.stderrDrain == .eof
        && result.captureOwnership == "notRequested",
      "A concurrent fork-only child retained a capture writer: \(result.report)"
    )
  }
}
