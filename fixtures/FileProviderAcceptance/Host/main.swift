import Darwin
import DiskplanFileProviderFixtureSupport
import DiskplanMacOS
@preconcurrency import FileProvider
import Foundation

@main
enum FixtureHost {
  static func main() async {
    let installed = MaterializationPolicyInstaller().installBeforePathAccess()
    guard let policy = installed.value else {
      fail("materialization_policy", detail: installed.detail ?? installed.status.rawValue)
    }
    do {
      try await run(arguments: Array(CommandLine.arguments.dropFirst()), policy: policy)
    } catch {
      fail("fixture_host", detail: String(describing: error))
    }
  }

  private static func run(arguments: [String], policy: NoMaterializationPolicy) async throws {
    guard let command = arguments.first else { throw HostError.usage }
    let options = try Options(arguments: Array(arguments.dropFirst()))
    switch command {
    case "prepare":
      let appPath = try options.required("app-path")
      let extensionPath = try options.required("extension-path")
      let runID = try options.requiredUUID("run-id")
      try prepare(runID: runID, appPath: appPath, extensionPath: extensionPath)
    case "setup":
      let manifest = try loadManifest(try options.requiredURL("manifest"))
      try await setup(manifest: manifest)
    case "probe":
      let manifest = try loadManifest(try options.requiredURL("manifest"))
      try probe(manifest: manifest, policy: policy)
    case "oracle-begin":
      let manifest = try loadManifest(try options.requiredURL("manifest"))
      try OracleLog(runDirectory: URL(fileURLWithPath: manifest.appGroupRunPath)).writeWindow(
        OracleWindow(beginNanoseconds: monotonicNow())
      )
      printJSON(["status": "oracle-open", "run_id": manifest.runID.uuidString.lowercased()])
    case "oracle-end":
      let manifest = try loadManifest(try options.requiredURL("manifest"))
      let log = OracleLog(runDirectory: URL(fileURLWithPath: manifest.appGroupRunPath))
      let quietMilliseconds = try options.optionalInt("quiet-ms", default: 2_000)
      let timeoutMilliseconds = try options.optionalInt("timeout-ms", default: 30_000)
      let quiescence = try log.closeWindowAfterQuiescence(
        quietMilliseconds: quietMilliseconds,
        timeoutMilliseconds: timeoutMilliseconds
      )
      printJSON([
        "status": "oracle-closed",
        "run_id": manifest.runID.uuidString.lowercased(),
        "event_count": String(quiescence.eventCount),
        "last_sequence": String(quiescence.lastSequence),
        "quiet_ms": String(quiescence.quietMilliseconds),
      ])
    case "oracle-health":
      let manifest = try loadManifest(try options.requiredURL("manifest"))
      try await assertOracleHealth(manifest: manifest)
    case "assert":
      let manifest = try loadManifest(try options.requiredURL("manifest"))
      try assertAcceptance(manifest: manifest)
    case "status":
      let manifest = try loadManifest(try options.requiredURL("manifest"))
      try await status(manifest: manifest)
    case "teardown":
      let manifest = try loadManifest(try options.requiredURL("manifest"))
      try await teardown(manifest: manifest)
    case "cleanup":
      let manifestURL = try options.requiredURL("manifest")
      let manifest = try loadManifest(manifestURL)
      try cleanup(manifest: manifest, manifestURL: manifestURL)
    case "extension-path":
      let manifest = try loadManifest(try options.requiredURL("manifest"))
      print(manifest.extensionPath)
    case "app-path":
      let manifest = try loadManifest(try options.requiredURL("manifest"))
      print(manifest.appPath)
    case "manifest-path":
      let runID = try options.requiredUUID("run-id")
      let log = try OracleLog.appGroup(runID: runID)
      print(log.runDirectory.appendingPathComponent("manifest.json").path)
    default:
      throw HostError.usage
    }
  }

  private static func prepare(runID: UUID, appPath: String, extensionPath: String) throws {
    let log = try OracleLog.appGroup(runID: runID)
    try log.prepare()
    let taskRoot = log.runDirectory
    let manifestURL = taskRoot.appendingPathComponent("manifest.json")
    let manifest = FixtureManifest(
      runID: runID,
      taskRoot: taskRoot.path,
      appPath: appPath,
      extensionPath: extensionPath,
      appGroupRunPath: log.runDirectory.path
    )
    try manifest.validate(expectedTaskRoot: taskRoot)
    try secureWrite(try JSONEncoder().encode(manifest), to: manifestURL)
    printJSON(["status": "prepared", "manifest": manifestURL.path])
  }

  private static func setup(manifest: FixtureManifest) async throws {
    let deadline = ContinuousClock.now + .seconds(20)
    let runID = manifest.runID
    let taskRoot = URL(fileURLWithPath: manifest.taskRoot)
    let domainIdentifier = manifest.domainIdentifier
    let domain = NSFileProviderDomain(
      identifier: NSFileProviderDomainIdentifier(domainIdentifier),
      displayName: FixtureContract.displayName
    )
    domain.isHidden = true
    domain.testingModes = []
    try await addDomain(domain, deadline: deadline)
    guard let manager = NSFileProviderManager(for: domain) else {
      throw HostError.managerUnavailable
    }
    try await signal(manager: manager, identifier: .rootContainer, deadline: deadline)
    let visibleSentinel = try await waitForURL(
      manager: manager,
      identifier: NSFileProviderItemIdentifier(FixtureContract.sentinelIdentifier),
      deadline: deadline
    )
    let visibleSealed = try await waitForURL(
      manager: manager,
      identifier: NSFileProviderItemIdentifier(FixtureContract.sealedDirectoryIdentifier),
      deadline: deadline
    )
    let ready = FixtureReadyState(
      runID: runID,
      sentinelPath: visibleSentinel.path,
      sealedDirectoryPath: visibleSealed.path
    )
    try ready.validate(manifest: manifest)
    try secureWrite(
      try JSONEncoder().encode(ready),
      to: taskRoot.appendingPathComponent("ready.json")
    )
    printJSON([
      "status": "ready",
      "manifest": taskRoot.appendingPathComponent("manifest.json").path,
      "domain": domainIdentifier,
    ])
  }

  private static func probe(manifest: FixtureManifest, policy: NoMaterializationPolicy) throws {
    let ready = try loadReady(manifest)
    let sentinel = URL(fileURLWithPath: ready.sentinelPath)
    let sealed = URL(fileURLWithPath: ready.sealedDirectoryPath)
    try requireDataless(sentinel)
    try requireDataless(sealed)
    let parent = sentinel.deletingLastPathComponent()
    guard sealed.deletingLastPathComponent().standardizedFileURL == parent.standardizedFileURL
    else {
      throw FixtureContractError.invalidManifest
    }
    let parentFD = open(parent.path, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
    guard parentFD >= 0 else { throw makePOSIXError(code: errno) }
    defer { close(parentFD) }
    let probe = FileProviderBoundaryProbe()
    for (url, expectsDatalessDirectory) in [(sentinel, false), (sealed, true)] {
      let outcome = probe.probe(
        parentFileDescriptor: parentFD,
        rawName: Data(url.lastPathComponent.utf8),
        policy: policy,
        timeout: .seconds(5)
      )
      guard case .evidence(let evidence) = outcome,
        evidence.identityDisposition == .confirmedProvider,
        evidence.identity.value?.domainIdentifier == manifest.domainIdentifier,
        evidence.handling == .reportOnly
      else { throw HostError.providerEvidenceRejected(String(describing: outcome)) }
      if expectsDatalessDirectory {
        guard evidence.traversal == .doNotDescendDataless else {
          throw HostError.providerEvidenceRejected("dataless directory traversal was not rejected")
        }
      }
    }
    printJSON(["status": "provider-evidence-accepted", "domain": manifest.domainIdentifier])
  }

  private static func assertAcceptance(manifest: FixtureManifest) throws {
    let log = OracleLog(runDirectory: URL(fileURLWithPath: manifest.appGroupRunPath))
    let window = try log.window()
    guard window.endNanoseconds != nil else { throw HostError.oracleWindowOpen }
    let events = try log.events()
    guard try log.recorderState() == .healthy else { throw HostError.oracleRecorderUnhealthy }
    guard window.eventCount == events.count,
      window.lastSequence == (events.last?.sequence ?? 0)
    else { throw HostError.oracleWindowMismatch }
    let matching = events.filter {
      $0.runID == manifest.runID && $0.domainIdentifier == manifest.domainIdentifier
    }
    let observed = matching.filter {
      $0.runID == manifest.runID && $0.domainIdentifier == manifest.domainIdentifier
        && window.contains($0)
    }
    let forbidden = observed.filter {
      FixtureContract.forbiddenEventKinds.contains($0.kind)
    }
    let liveness = observed.filter {
      !FixtureContract.forbiddenEventKinds.contains($0.kind)
    }
    guard !liveness.isEmpty else { throw HostError.oracleSilent }
    guard forbidden.isEmpty else {
      throw HostError.forbiddenCallbacks(forbidden.map { "\($0.sequence):\($0.kind.rawValue)" })
    }
    printJSON([
      "status": "accepted",
      "domain": manifest.domainIdentifier,
      "forbidden_callbacks": "0",
      "oracle_liveness_events": String(liveness.count),
      "window_events": String(observed.count),
      "sf_dataless": "sentinel,sealed-dir",
      "provider_identity": "matched",
      "plan_handling": "report-only",
    ])
  }

  private static func status(manifest: FixtureManifest) async throws {
    let deadline = ContinuousClock.now + .seconds(20)
    let domains = try await registeredDomainIdentifiers(deadline: deadline)
    let present = domains.contains(manifest.domainIdentifier)
    printJSON(["status": present ? "present" : "absent", "domain": manifest.domainIdentifier])
  }

  private static func teardown(manifest: FixtureManifest) async throws {
    let deadline = ContinuousClock.now + .seconds(20)
    try OracleLog(
      runDirectory: URL(fileURLWithPath: manifest.appGroupRunPath)
    ).sealRecorder()
    let matches = try await registeredDomainIdentifiers(deadline: deadline).filter {
      $0 == manifest.domainIdentifier
    }
    guard matches.count <= 1 else { throw HostError.duplicateExactDomain }
    if matches.first != nil {
      let domain = NSFileProviderDomain(
        identifier: NSFileProviderDomainIdentifier(manifest.domainIdentifier),
        displayName: FixtureContract.displayName
      )
      try await removeExactDomain(domain, deadline: deadline)
    }
    while ContinuousClock.now < deadline {
      if try await !registeredDomainIdentifiers(deadline: deadline).contains(
        manifest.domainIdentifier
      ) {
        printJSON(["status": "removed", "domain": manifest.domainIdentifier])
        return
      }
      try await sleepForPolling(.milliseconds(200), until: deadline)
    }
    throw HostError.domainRemovalTimedOut
  }

  private static func assertOracleHealth(manifest: FixtureManifest) async throws {
    let deadline = ContinuousClock.now + .seconds(20)
    let log = OracleLog(runDirectory: URL(fileURLWithPath: manifest.appGroupRunPath))
    let window = try log.window()
    guard window.endNanoseconds == nil else { throw HostError.oracleWindowClosed }
    guard try log.recorderState() == .healthy else { throw HostError.oracleRecorderUnhealthy }
    let baseline = try log.events().last?.sequence ?? 0
    let domain = NSFileProviderDomain(
      identifier: NSFileProviderDomainIdentifier(manifest.domainIdentifier),
      displayName: FixtureContract.displayName
    )
    guard let manager = NSFileProviderManager(for: domain) else {
      throw HostError.managerUnavailable
    }
    try await signal(manager: manager, identifier: .rootContainer, deadline: deadline)
    while ContinuousClock.now < deadline {
      let healthy = try log.events().contains {
        $0.sequence > baseline && $0.runID == manifest.runID
          && $0.domainIdentifier == manifest.domainIdentifier && window.contains($0)
          && !FixtureContract.forbiddenEventKinds.contains($0.kind)
      }
      if healthy, try log.recorderState() == .healthy {
        printJSON(["status": "oracle-healthy", "domain": manifest.domainIdentifier])
        return
      }
      try await sleepForPolling(.milliseconds(100), until: deadline)
    }
    throw HostError.oracleHealthTimedOut
  }

  private static func cleanup(manifest: FixtureManifest, manifestURL: URL) throws {
    let expectedLog = try OracleLog.appGroup(runID: manifest.runID)
    let expectedTaskRoot = expectedLog.runDirectory.standardizedFileURL
    try manifest.validate(expectedTaskRoot: expectedTaskRoot)
    try SecureFixtureStorage.cleanupRun(
      manifestURL: manifestURL,
      expectedRunDirectory: expectedTaskRoot
    )
    printJSON(["status": "cleaned", "run_id": manifest.runID.uuidString.lowercased()])
  }

  private static func requireDataless(_ url: URL) throws {
    var info = stat()
    guard lstat(url.path, &info) == 0 else { throw makePOSIXError(code: errno) }
    guard UInt32(info.st_flags) & UInt32(SF_DATALESS) != 0 else {
      throw HostError.notDataless(url.lastPathComponent)
    }
  }

  private static func loadManifest(_ url: URL) throws -> FixtureManifest {
    let runDirectory = url.deletingLastPathComponent()
    guard let runID = UUID(uuidString: runDirectory.lastPathComponent) else {
      throw FixtureControlReadError.mismatch(.manifest, .semantic)
    }
    let expectedTaskRoot = try OracleLog.appGroup(runID: runID).runDirectory
    return try SecureFixtureStorage.readManifest(
      at: url,
      expectedRunDirectory: expectedTaskRoot
    )
  }

  private static func loadReady(_ manifest: FixtureManifest) throws -> FixtureReadyState {
    try SecureFixtureStorage.readReady(manifest)
  }
}

private struct Options {
  private let values: [String: String]

  init(arguments: [String]) throws {
    guard arguments.count.isMultiple(of: 2) else { throw HostError.usage }
    var parsed: [String: String] = [:]
    for index in stride(from: 0, to: arguments.count, by: 2) {
      let key = arguments[index]
      guard key.hasPrefix("--"), parsed[String(key.dropFirst(2))] == nil else {
        throw HostError.usage
      }
      parsed[String(key.dropFirst(2))] = arguments[index + 1]
    }
    values = parsed
  }

  func required(_ key: String) throws -> String {
    guard let value = values[key], !value.isEmpty else { throw HostError.usage }
    return value
  }

  func requiredURL(_ key: String) throws -> URL {
    let value = try required(key)
    guard value.hasPrefix("/") else { throw FixtureContractError.unsafePath }
    return URL(fileURLWithPath: value)
  }

  func requiredUUID(_ key: String) throws -> UUID {
    guard let value = UUID(uuidString: try required(key)) else { throw HostError.usage }
    return value
  }

  func optionalInt(_ key: String, default defaultValue: Int) throws -> Int {
    guard let value = values[key] else { return defaultValue }
    guard let parsed = Int(value) else { throw HostError.usage }
    return parsed
  }
}

private enum HostError: Error {
  case usage
  case managerUnavailable
  case userVisibleURLTimedOut
  case providerEvidenceRejected(String)
  case notDataless(String)
  case oracleWindowOpen
  case oracleWindowClosed
  case oracleWindowMismatch
  case oracleSilent
  case oracleHealthTimedOut
  case oracleRecorderUnhealthy
  case callbackTimedOut
  case forbiddenCallbacks([String])
  case duplicateExactDomain
  case domainRemovalTimedOut
}

private func addDomain(
  _ domain: NSFileProviderDomain,
  deadline: ContinuousClock.Instant
) async throws {
  try await boundedCallback(deadline: deadline) { completion in
    NSFileProviderManager.add(domain) { error in
      completion(error.map(Result.failure) ?? .success(()))
    }
  }
}

private func registeredDomainIdentifiers(
  deadline: ContinuousClock.Instant
) async throws -> [String] {
  try await boundedCallback(deadline: deadline) { completion in
    NSFileProviderManager.getDomainsWithCompletionHandler { domains, error in
      if let error {
        completion(.failure(error))
      } else {
        completion(.success(domains.map { $0.identifier.rawValue }))
      }
    }
  }
}

private func removeExactDomain(
  _ domain: NSFileProviderDomain,
  deadline: ContinuousClock.Instant
) async throws {
  try await boundedCallback(deadline: deadline) { completion in
    NSFileProviderManager.remove(domain, mode: .removeAll) { _, error in
      completion(error.map(Result.failure) ?? .success(()))
    }
  }
}

private func signal(
  manager: NSFileProviderManager,
  identifier: NSFileProviderItemIdentifier,
  deadline: ContinuousClock.Instant
) async throws {
  try await boundedCallback(deadline: deadline) { completion in
    manager.signalEnumerator(for: identifier) { error in
      completion(error.map(Result.failure) ?? .success(()))
    }
  }
}

private func waitForURL(
  manager: NSFileProviderManager,
  identifier: NSFileProviderItemIdentifier,
  deadline: ContinuousClock.Instant
) async throws -> URL {
  while ContinuousClock.now < deadline {
    do {
      return try await boundedCallback(deadline: deadline) { completion in
        manager.getUserVisibleURL(for: identifier) { url, error in
          if let url {
            completion(.success(url))
          } else {
            completion(.failure(error ?? HostError.managerUnavailable))
          }
        }
      }
    } catch {
      try await sleepForPolling(.milliseconds(200), until: deadline)
    }
  }
  throw HostError.userVisibleURLTimedOut
}

private func sleepForPolling(
  _ interval: Duration,
  until deadline: ContinuousClock.Instant
) async throws {
  let clock = ContinuousClock()
  let next = min(clock.now + interval, deadline)
  try await clock.sleep(until: next)
}

private func boundedCallback<Value: Sendable>(
  deadline: ContinuousClock.Instant,
  start: (@escaping @Sendable (Result<Value, Error>) -> Void) -> Void
) async throws -> Value {
  let gate = OneShotCallbackGate()
  return try await withCheckedThrowingContinuation { continuation in
    Task {
      try? await ContinuousClock().sleep(until: deadline)
      if gate.claimCompletion(from: .deadline) {
        continuation.resume(throwing: HostError.callbackTimedOut)
      }
    }
    start { result in
      if gate.claimCompletion(from: .callback) { continuation.resume(with: result) }
    }
  }
}

private func secureWrite(_ data: Data, to url: URL) throws {
  let descriptor = open(url.path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0o600)
  guard descriptor >= 0 else { throw makePOSIXError(code: errno) }
  defer { close(descriptor) }
  try data.withUnsafeBytes { bytes in
    var remaining = bytes.count
    var pointer = bytes.baseAddress!
    while remaining > 0 {
      let written = Darwin.write(descriptor, pointer, remaining)
      if written < 0, errno == EINTR { continue }
      guard written > 0 else { throw makePOSIXError(code: errno == 0 ? EIO : errno) }
      remaining -= written
      pointer = pointer.advanced(by: written)
    }
  }
}

private func monotonicNow() -> UInt64 { clock_gettime_nsec_np(CLOCK_MONOTONIC_RAW) }

private func printJSON(_ values: [String: String]) {
  let data = try! JSONSerialization.data(withJSONObject: values, options: [.sortedKeys])
  print(String(decoding: data, as: UTF8.self))
}

private func fail(_ reason: String, detail: String) -> Never {
  let data = try! JSONSerialization.data(
    withJSONObject: ["status": "failed", "reason": reason, "detail": detail],
    options: [.sortedKeys]
  )
  FileHandle.standardError.write(data + Data([0x0a]))
  exit(1)
}

private func makePOSIXError(code: Int32) -> POSIXError {
  POSIXError(POSIXErrorCode(rawValue: code) ?? .EIO)
}
