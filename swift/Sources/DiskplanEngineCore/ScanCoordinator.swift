import DiskplanMacOS
import DiskplanProto
import DiskplanScan
import Foundation

enum ScanCoordinatorError: Error, Equatable {
  case malformed(Diskplan_V1_ScanSetupRejectCode, String)
  case unavailable(Diskplan_V1_ScanSetupRejectCode, String)
}

private struct ConfiguredScan: @unchecked Sendable {
  let scanner: DeterministicScanner
  let sink: StreamingNodeSink
  let authoritySession: RuntimePolicyAuthoritySession?
  let batchSize: Int
}

final class AuthorityTeeNodeSink: ScanNodeSink, @unchecked Sendable {
  private let authority: RuntimePolicyAuthoritySession
  private let streaming: StreamingNodeSink

  init(authority: RuntimePolicyAuthoritySession, streaming: StreamingNodeSink) {
    self.authority = authority
    self.streaming = streaming
  }

  func receive(_ event: ScanNodeEvent) {
    authority.receive(event)
    streaming.receive(event)
  }
}

final class StreamingNodeSink: ScanNodeSink, @unchecked Sendable {
  private let lock = NSLock()
  private let broker: SerialEventBroker
  private let scanSessionID: String
  private let roots: [ScanRootRequest]
  private var sendFailure: String?

  init(broker: SerialEventBroker, scanSessionID: String, roots: [ScanRootRequest]) {
    self.broker = broker
    self.scanSessionID = scanSessionID
    self.roots = roots
  }

  func receive(_ event: ScanNodeEvent) {
    let node: ScannedNode
    let directoryClosed: Bool
    switch event {
    case .observed(let value):
      node = value
      directoryClosed = false
    case .directoryClosed(let value):
      node = value
      directoryClosed = true
    }
    var observed = Diskplan_V1_ScanNodeObserved()
    observed.node = ScanIPCProjection.node(node, roots: roots)
    observed.directoryClosed = directoryClosed
    do {
      try broker.sendSemantic(
        requestID: 0,
        scanSessionID: scanSessionID,
        body: .scanNodeObserved(observed)
      )
    } catch {
      lock.lock()
      if sendFailure == nil { sendFailure = String(describing: error) }
      lock.unlock()
    }
  }

  func failure() -> String? {
    lock.lock()
    defer { lock.unlock() }
    return sendFailure
  }
}

enum WorkerCommand: Sendable {
  case control(requestID: UInt64, kind: Diskplan_V1_ScanControlKind)
  case stop
}

struct BoundedWorkerCommandQueue: Sendable {
  private struct QueuedControl: Sendable {
    let requestID: UInt64
    let kind: Diskplan_V1_ScanControlKind
  }

  let capacity: Int
  private var storage: [QueuedControl?]
  private var head = 0
  private var tail = 0
  private(set) var count = 0
  private(set) var stopRequested = false

  init(capacity: Int) {
    precondition(capacity > 0)
    self.capacity = capacity
    storage = Array(repeating: nil, count: capacity)
  }

  var isEmpty: Bool { count == 0 }

  mutating func enqueueControl(
    requestID: UInt64,
    kind: Diskplan_V1_ScanControlKind
  ) -> Bool {
    guard count < capacity else { return false }
    storage[tail] = QueuedControl(requestID: requestID, kind: kind)
    tail = (tail + 1) % capacity
    count += 1
    return true
  }

  mutating func requestStop() {
    stopRequested = true
  }

  mutating func dequeuePrioritizingStop() -> WorkerCommand? {
    if stopRequested { return .stop }
    return dequeueControl()
  }

  mutating func drainControls() -> [WorkerCommand] {
    var drained: [WorkerCommand] = []
    drained.reserveCapacity(count)
    while let command = dequeueControl() { drained.append(command) }
    return drained
  }

  private mutating func dequeueControl() -> WorkerCommand? {
    guard count > 0 else { return nil }
    guard let control = storage[head] else {
      preconditionFailure("occupied command queue slot is empty")
    }
    storage[head] = nil
    head = (head + 1) % capacity
    count -= 1
    return .control(requestID: control.requestID, kind: control.kind)
  }
}

final class ScanCoordinator: @unchecked Sendable {
  typealias AuthoritySessionFactory = @Sendable (ResolvedScanScope) -> RuntimePolicyAuthoritySession

  private static let maximumCheckpointRootBindingBytes = 1 * 1_024 * 1_024
  static let commandCapacity = 256

  private let condition = NSCondition()
  private let broker: SerialEventBroker
  private let authoritySessionFactory: AuthoritySessionFactory?
  private var commands = BoundedWorkerCommandQueue(capacity: commandCapacity)
  private var state: Diskplan_V1_ScanState = .idle
  private var workerStarted = false
  private var workerFinished = false
  private var sessionID = ""
  private var authoritySession: RuntimePolicyAuthoritySession?

  init(
    broker: SerialEventBroker,
    authoritySessionFactory: AuthoritySessionFactory? = nil,
    authoritySession: RuntimePolicyAuthoritySession? = nil
  ) {
    precondition(authoritySessionFactory == nil || authoritySession == nil)
    self.broker = broker
    self.authoritySessionFactory = authoritySessionFactory
    self.authoritySession = authoritySession
  }

  func start(_ request: Diskplan_V1_StartScanRequest) throws {
    condition.lock()
    let alreadyStarted = workerStarted
    condition.unlock()
    guard !alreadyStarted else {
      try reject(
        requestID: request.requestID,
        control: .startScan,
        code: .invalidState,
        detail: "scan has already started"
      )
      return
    }

    let sessionID = UUID().uuidString.lowercased()
    let configured: ConfiguredScan
    do {
      configured = try Self.buildProductionScan(
        request: request,
        scanSessionID: sessionID,
        broker: broker,
        authoritySessionFactory: authoritySessionFactory
      )
    } catch ScanCoordinatorError.malformed(let setupCode, let detail) {
      try reject(
        requestID: request.requestID,
        control: .startScan,
        code: .malformedRequest,
        detail: detail,
        setupCode: setupCode
      )
      return
    } catch ScanCoordinatorError.unavailable(let setupCode, let detail) {
      try reject(
        requestID: request.requestID,
        control: .startScan,
        code: .unavailable,
        detail: detail,
        setupCode: setupCode
      )
      return
    } catch ScanScopeValidationError.duplicateRootID(let rootID) {
      try reject(
        requestID: request.requestID,
        control: .startScan,
        code: .malformedRequest,
        detail: "duplicate root_id: \(rootID)",
        setupCode: .duplicateRootID
      )
      return
    } catch {
      try reject(
        requestID: request.requestID,
        control: .startScan,
        code: .unavailable,
        detail: "scan setup unavailable: \(error)",
        setupCode: .scannerInitializationFailed
      )
      return
    }

    condition.lock()
    guard !workerStarted else {
      condition.unlock()
      try reject(
        requestID: request.requestID,
        control: .startScan,
        code: .invalidState,
        detail: "scan has already started"
      )
      return
    }
    workerStarted = true
    state = .running
    self.sessionID = sessionID
    authoritySession = configured.authoritySession
    condition.unlock()

    do {
      try accepted(
        requestID: request.requestID,
        control: .startScan,
        resultingState: .running
      )
      try stateChanged(.running, reason: "read-only scan started")
    } catch {
      // No worker exists yet. Mark this attempted session terminal before
      // propagating so EngineServer's deferred stop cannot wait forever.
      markWorkerFinished(state: .failed)
      throw error
    }

    Thread { [self] in
      runWorker(
        configured: configured,
        scanSessionID: sessionID
      )
    }.start()
  }

  func control(_ request: Diskplan_V1_ScanControlRequest) throws {
    condition.lock()
    if !workerStarted || workerFinished || commands.stopRequested
      || (state != .running && state != .paused)
    {
      let current = state
      condition.unlock()
      try reject(
        requestID: request.requestID,
        control: request.control,
        code: .invalidState,
        detail: "control is not valid in the current scan state",
        currentState: current
      )
      return
    }
    guard commands.enqueueControl(requestID: request.requestID, kind: request.control) else {
      let current = state
      condition.unlock()
      try reject(
        requestID: request.requestID,
        control: request.control,
        code: .capacityExceeded,
        detail: "control queue capacity exceeded",
        currentState: current
      )
      return
    }
    condition.signal()
    condition.unlock()
  }

  func rejectMalformed(
    requestID: UInt64,
    control: Diskplan_V1_ScanControlKind,
    detail: String
  ) throws {
    try reject(
      requestID: requestID,
      control: control,
      code: .malformedRequest,
      detail: detail
    )
  }

  func rejectControl(
    requestID: UInt64,
    control: Diskplan_V1_ScanControlKind,
    code: Diskplan_V1_ControlRejectCode,
    detail: String,
    setupCode: Diskplan_V1_ScanSetupRejectCode = .unspecified
  ) throws {
    try reject(
      requestID: requestID,
      control: control,
      code: code,
      detail: detail,
      setupCode: setupCode
    )
  }

  func stopAndWait() {
    condition.lock()
    if workerStarted && !workerFinished {
      commands.requestStop()
      condition.broadcast()
      while !workerFinished { condition.wait() }
    }
    condition.unlock()
  }

  func makePlanForCurrentSession() throws -> RuntimePolicyAuthorityResult {
    condition.lock()
    let authoritySession = self.authoritySession
    let state = self.state
    let workerFinished = self.workerFinished
    condition.unlock()
    guard let authoritySession,
      Self.authorityPlanIsReachable(state: state, workerFinished: workerFinished)
    else {
      throw RuntimePolicyAuthoritySessionError.scanNotFinalized
    }
    return try authoritySession.makePlan()
  }

  static func authorityPlanIsReachable(
    state: Diskplan_V1_ScanState,
    workerFinished: Bool
  ) -> Bool {
    workerFinished && (state == .finished || state == .finalizedPartial)
  }

  private func runWorker(
    configured: ConfiguredScan,
    scanSessionID: String
  ) {
    let scanner = configured.scanner
    let sink = configured.sink
    // Admit controls already queued immediately behind StartScan before a
    // small scan can run to completion. A control signal wakes this wait
    // early, while an ordinary scan pays only the bounded startup interval.
    condition.lock()
    if commands.isEmpty && !commands.stopRequested {
      _ = condition.wait(until: Date(timeIntervalSinceNow: 0.05))
    }
    condition.unlock()
    while true {
      condition.lock()
      while commands.isEmpty && !commands.stopRequested && state == .paused {
        condition.wait()
      }
      if let command = commands.dequeuePrioritizingStop() {
        condition.unlock()
        if handle(
          command,
          scanner: scanner,
          scanSessionID: scanSessionID
        ) {
          return
        }
        continue
      }
      let shouldRun = state == .running
      condition.unlock()

      guard shouldRun else { break }
      let result = scanner.advance(maximumEntries: configured.batchSize)
      if let failure = sink.failure() {
        emitFailure(code: "event_broker_failed", detail: failure)
        break
      }
      emitProgress(result)
      switch result.state {
      case .complete:
        publishFinalizedAuthorityResult(
          result,
          state: .finished,
          reason: "scan complete"
        )
        return
      case .partial:
        publishFinalizedAuthorityResult(
          result,
          state: .finalizedPartial,
          reason: "scan finalized partial"
        )
        return
      case .cancelled:
        guard finishOrFail(result, state: .cancelled, reason: "scan cancelled") else {
          markWorkerFinished(state: .failed)
          return
        }
        rejectQueuedControls(currentState: .cancelled)
        markWorkerFinished(state: .cancelled)
        return
      case .ready, .scanning:
        continue
      }
    }
    _ = scanner.cancel()
    markWorkerFinished(state: state)
  }

  private func handle(
    _ command: WorkerCommand,
    scanner: DeterministicScanner,
    scanSessionID: String
  ) -> Bool {
    switch command {
    case .stop:
      _ = scanner.cancel()
      let current = lockedState()
      rejectQueuedControls(currentState: current)
      markWorkerFinished(state: current)
      return true
    case .control(let requestID, let kind):
      let current = lockedState()
      do {
        switch kind {
        case .pauseScan where current == .running:
          setState(.paused)
          try accepted(requestID: requestID, control: kind, resultingState: .paused)
          try stateChanged(.paused, reason: "pause acknowledged")
        case .resumeScan where current == .paused:
          setState(.running)
          try accepted(requestID: requestID, control: kind, resultingState: .running)
          try stateChanged(.running, reason: "resume acknowledged")
        case .checkpointScan where current == .running || current == .paused:
          try accepted(requestID: requestID, control: kind, resultingState: current)
          try emitCheckpoint(scanner.snapshot(), provisional: false)
        case .checkpointProvisionalEvidence where current == .running || current == .paused:
          setState(.paused)
          try accepted(requestID: requestID, control: kind, resultingState: .paused)
          try stateChanged(.paused, reason: "provisional evidence checkpoint requested")
          try emitCheckpoint(scanner.snapshot(), provisional: true)
        case .finalizePartialScan where current == .running || current == .paused:
          setState(.finalizingPartial)
          try accepted(
            requestID: requestID,
            control: kind,
            resultingState: .finalizingPartial
          )
          try stateChanged(.finalizingPartial, reason: "partial finalization acknowledged")
          let result = scanner.finalizePartial()
          publishFinalizedAuthorityResult(
            result,
            state: .finalizedPartial,
            reason: "finalized by user"
          )
          return true
        case .cancelScan where current == .running || current == .paused:
          setState(.cancelling)
          try accepted(requestID: requestID, control: kind, resultingState: .cancelling)
          try stateChanged(.cancelling, reason: "cancel acknowledged")
          let result = scanner.cancel()
          try finish(result, state: .cancelled, reason: "cancelled by user")
          var cancelled = Diskplan_V1_ScanCancelled()
          cancelled.reason = "cancelled by user"
          try broker.sendSemantic(
            requestID: 0,
            scanSessionID: scanSessionID,
            body: .scanCancelled(cancelled)
          )
          rejectQueuedControls(currentState: .cancelled)
          markWorkerFinished(state: .cancelled)
          return true
        case .pauseAndBuildProvisionalPlan:
          try reject(
            requestID: requestID,
            control: kind,
            code: .unavailable,
            detail: "Phase 1 exposes provisional evidence, not a provisional plan",
            currentState: current
          )
        case .unspecified, .startScan, .UNRECOGNIZED:
          try reject(
            requestID: requestID,
            control: kind,
            code: .malformedRequest,
            detail: "control is not valid in ScanControlRequest",
            currentState: current
          )
        default:
          try reject(
            requestID: requestID,
            control: kind,
            code: .invalidState,
            detail: "control is not valid in the current scan state",
            currentState: current
          )
        }
      } catch {
        let code =
          error is CheckpointWireEncodingError
          ? "checkpoint_encoding_failed" : "event_broker_failed"
        emitFailure(code: code, detail: String(describing: error))
        rejectQueuedControls(currentState: .failed)
        markWorkerFinished(state: .failed)
        return true
      }
      return false
    }
  }

  private func emitProgress(_ result: ScanResult) {
    do {
      try broker.sendProgress(
        scanSessionID: sessionID,
        progress: ScanIPCProjection.progress(result, elapsedMillis: elapsedMillis(result))
      )
    } catch {
      emitFailure(code: "event_broker_failed", detail: String(describing: error))
    }
  }

  private func emitCheckpoint(_ result: ScanResult, provisional: Bool) throws {
    let encoded = try CheckpointWireEncoder.encode(
      ScanIPCProjection.checkpoint(
        result,
        elapsedMillis: elapsedMillis(result),
        resumable: lockedState() == .running || lockedState() == .paused,
        provisional: provisional
      ))
    try emitChunks(encoded.chunks)
    var ready = Diskplan_V1_ScanCheckpointReady()
    ready.canonicalCheckpointPayload = encoded.checkpointPayload
    ready.manifest = encoded.manifest
    try broker.sendSemantic(
      requestID: 0,
      scanSessionID: sessionID,
      body: .scanCheckpointReady(ready)
    )
  }

  private func finish(
    _ result: ScanResult,
    state: Diskplan_V1_ScanState,
    reason: String
  ) throws {
    let encoded = try CheckpointWireEncoder.encode(
      ScanIPCProjection.checkpoint(
        result,
        elapsedMillis: elapsedMillis(result),
        resumable: false,
        provisional: false
      ))
    setState(state)
    try stateChanged(state, reason: reason)
    try emitChunks(encoded.chunks)
    var finalized = Diskplan_V1_ScanFinalized()
    finalized.reason = reason
    finalized.canonicalCheckpointPayload = encoded.checkpointPayload
    finalized.manifest = encoded.manifest
    try broker.sendSemanticAwaitingWrite(
      requestID: 0,
      scanSessionID: sessionID,
      body: .scanFinalized(finalized)
    )
  }

  private func finishOrFail(
    _ result: ScanResult,
    state: Diskplan_V1_ScanState,
    reason: String
  ) -> Bool {
    do {
      try finish(result, state: state, reason: reason)
      return true
    } catch {
      let code =
        error is CheckpointWireEncodingError
        ? "checkpoint_encoding_failed" : "event_broker_failed"
      emitFailure(code: code, detail: String(describing: error))
      return false
    }
  }

  func publishFinalizedAuthorityResult(
    _ result: ScanResult,
    state terminalState: Diskplan_V1_ScanState,
    reason: String
  ) {
    precondition(terminalState == .finished || terminalState == .finalizedPartial)
    do {
      condition.lock()
      let authoritySession = self.authoritySession
      condition.unlock()
      try authoritySession?.finalize(result)
    } catch {
      emitFailure(code: "authority_finalize_failed", detail: String(describing: error))
      rejectQueuedControls(currentState: .failed)
      markWorkerFinished(state: .failed)
      return
    }
    guard finishOrFail(result, state: terminalState, reason: reason) else {
      rejectQueuedControls(currentState: .failed)
      markWorkerFinished(state: .failed)
      return
    }
    rejectQueuedControls(currentState: terminalState)
    markWorkerFinished(state: terminalState)
  }

  private func emitChunks(_ chunks: [Diskplan_V1_ScanCheckpointChunk]) throws {
    for chunk in chunks {
      try broker.sendSemantic(
        requestID: 0,
        scanSessionID: sessionID,
        body: .scanCheckpointChunk(chunk)
      )
    }
  }

  private func accepted(
    requestID: UInt64,
    control: Diskplan_V1_ScanControlKind,
    resultingState: Diskplan_V1_ScanState
  ) throws {
    var accepted = Diskplan_V1_ControlAccepted()
    accepted.control = control
    accepted.resultingState = resultingState
    try broker.sendSemantic(
      requestID: requestID,
      scanSessionID: sessionID,
      body: .controlAccepted(accepted)
    )
  }

  private func reject(
    requestID: UInt64,
    control: Diskplan_V1_ScanControlKind,
    code: Diskplan_V1_ControlRejectCode,
    detail: String,
    currentState: Diskplan_V1_ScanState? = nil,
    setupCode: Diskplan_V1_ScanSetupRejectCode = .unspecified
  ) throws {
    var rejected = Diskplan_V1_ControlRejected()
    rejected.control = control
    rejected.code = code
    rejected.detail = detail
    rejected.currentState = currentState ?? lockedState()
    rejected.setupCode = setupCode
    try broker.sendSemantic(
      requestID: requestID,
      scanSessionID: sessionID,
      body: .controlRejected(rejected)
    )
  }

  private func stateChanged(_ state: Diskplan_V1_ScanState, reason: String) throws {
    var changed = Diskplan_V1_ScanStateChanged()
    changed.state = state
    changed.reason = reason
    try broker.sendSemantic(
      requestID: 0,
      scanSessionID: sessionID,
      body: .scanStateChanged(changed)
    )
  }

  private func emitFailure(code: String, detail: String) {
    var failed = Diskplan_V1_EngineFailed()
    failed.code = code
    failed.detail = detail
    try? broker.sendSemantic(
      requestID: 0,
      scanSessionID: sessionID,
      body: .engineFailed(failed)
    )
    setState(.failed)
  }

  private func rejectQueuedControls(currentState: Diskplan_V1_ScanState) {
    condition.lock()
    let queued = commands.drainControls()
    condition.unlock()
    for command in queued {
      guard case .control(let requestID, let kind) = command else { continue }
      try? reject(
        requestID: requestID,
        control: kind,
        code: .invalidState,
        detail: "control arrived after scan finalization",
        currentState: currentState
      )
    }
  }

  private func lockedState() -> Diskplan_V1_ScanState {
    condition.lock()
    defer { condition.unlock() }
    return state
  }

  private func setState(_ value: Diskplan_V1_ScanState) {
    condition.lock()
    state = value
    condition.broadcast()
    condition.unlock()
  }

  private func markWorkerFinished(state: Diskplan_V1_ScanState) {
    condition.lock()
    self.state = state
    workerFinished = true
    condition.broadcast()
    condition.unlock()
  }

  private func elapsedMillis(_ result: ScanResult) -> UInt64 {
    let now = DispatchTime.now().uptimeNanoseconds
    let start = result.reference.monotonicNanoseconds
    return now >= start ? (now - start) / 1_000_000 : 0
  }

  private static func buildProductionScan(
    request: Diskplan_V1_StartScanRequest,
    scanSessionID: String,
    broker: SerialEventBroker,
    authoritySessionFactory: AuthoritySessionFactory?
  ) throws -> ConfiguredScan {
    guard
      let profile = ScanProfile(rawValue: request.profile.isEmpty ? "standard" : request.profile)
    else {
      throw ScanCoordinatorError.malformed(.invalidProfile, "unknown scan profile")
    }
    let batchSize = request.batchSize == 0 ? 256 : Int(request.batchSize)
    guard (1...4_096).contains(batchSize) else {
      throw ScanCoordinatorError.malformed(
        .invalidBudget,
        "batch_size must be between 1 and 4096"
      )
    }
    guard request.roots.count <= 4_096 else {
      throw ScanCoordinatorError.malformed(
        .invalidBudget,
        "a scan may contain at most 4096 explicit roots"
      )
    }
    let duration: UInt64?
    if request.maximumDurationMillis == 0 {
      duration = nil
    } else {
      let (value, overflow) = request.maximumDurationMillis.multipliedReportingOverflow(
        by: 1_000_000)
      guard !overflow else {
        throw ScanCoordinatorError.malformed(
          .invalidBudget,
          "maximum_duration_millis is too large"
        )
      }
      duration = value
    }

    var seenRootIDs = Set<String>()
    let explicitRoots = try request.roots.map { root -> ScanRootRequest in
      guard isValidRootID(root.rootID) else {
        throw ScanCoordinatorError.malformed(
          .invalidRoot,
          "root_id must be non-empty, bounded, and free of control characters"
        )
      }
      guard seenRootIDs.insert(root.rootID).inserted else {
        throw ScanCoordinatorError.malformed(
          .duplicateRootID,
          "duplicate root_id: \(root.rootID)"
        )
      }
      guard isValidCanonicalRootPath(root.rawAbsolutePath) else {
        throw ScanCoordinatorError.malformed(
          .invalidRoot,
          "raw_absolute_path must be a bounded canonical absolute raw path"
        )
      }
      return ScanRootRequest(rootID: root.rootID, rawAbsolutePath: root.rawAbsolutePath)
    }
    if profile == .deep && explicitRoots.isEmpty {
      throw ScanCoordinatorError.malformed(
        .invalidRoot,
        "deep profile requires at least one explicit root"
      )
    }
    try validateCheckpointRootBindings(explicitRoots)

    let installed = MaterializationPolicyInstaller().installBeforePathAccess()
    guard let policy = installed.value else {
      throw ScanCoordinatorError.unavailable(
        .materializationPolicyUnavailable,
        installed.detail ?? "no-materialization policy is unavailable"
      )
    }

    let scanEnvironment: ScanEnvironment
    do {
      scanEnvironment = try environment(profile: profile, explicitRoots: explicitRoots)
    } catch let error as ScanCoordinatorError {
      throw error
    } catch {
      throw ScanCoordinatorError.unavailable(
        .rootDiscoveryUnavailable,
        "scan root discovery unavailable: \(error)"
      )
    }
    let scope = try ScanRootResolver().resolve(
      profile: profile,
      environment: scanEnvironment,
      explicitRoots: explicitRoots,
      maximumDurationNanoseconds: duration
    )
    try validateCheckpointRootBindings(scope.roots)
    let sink = StreamingNodeSink(
      broker: broker,
      scanSessionID: scanSessionID,
      roots: scope.roots
    )
    let authoritySession = authoritySessionFactory?(scope)
    let nodeSink: any ScanNodeSink =
      if let authoritySession {
        AuthorityTeeNodeSink(authority: authoritySession, streaming: sink)
      } else {
        sink
      }
    return ConfiguredScan(
      scanner: DeterministicScanner(
        filesystem: DarwinScanFilesystem(policy: policy),
        scope: scope,
        nodeSink: nodeSink
      ),
      sink: sink,
      authoritySession: authoritySession,
      batchSize: batchSize
    )
  }

  private static func environment(
    profile: ScanProfile,
    explicitRoots: [ScanRootRequest]
  ) throws -> ScanEnvironment {
    if !explicitRoots.isEmpty {
      switch profile {
      case .quick: return ScanEnvironment(adapterRoots: explicitRoots)
      case .standard: return ScanEnvironment(adapterRoots: explicitRoots)
      case .deep: return ScanEnvironment()
      case .fullAudit: return ScanEnvironment(visibleLocalWritableVolumes: explicitRoots)
      }
    }

    let fileManager = FileManager.default
    switch profile {
    case .quick:
      return ScanEnvironment()
    case .standard:
      var roots: [ScanRootRequest] = []
      roots.append(root(id: "home", url: fileManager.homeDirectoryForCurrentUser))
      if let caches = fileManager.urls(for: .cachesDirectory, in: .userDomainMask).first {
        roots.append(root(id: "user-cache", url: caches))
      }
      roots.append(
        ScanRootRequest(
          rootID: "temporary",
          rawAbsolutePath: Data(NSTemporaryDirectory().utf8).droppingTrailingSlash()
        ))
      return ScanEnvironment(adapterRoots: deduplicated(roots))
    case .deep:
      throw ScanCoordinatorError.malformed(
        .invalidRoot,
        "deep profile requires at least one explicit root"
      )
    case .fullAudit:
      let keys: Set<URLResourceKey> = [.volumeIsLocalKey, .volumeIsReadOnlyKey]
      guard
        let urls = fileManager.mountedVolumeURLs(
          includingResourceValuesForKeys: Array(keys),
          options: [.skipHiddenVolumes]
        )
      else {
        throw ScanCoordinatorError.unavailable(
          .rootDiscoveryUnavailable,
          "mounted volume discovery returned no result"
        )
      }
      let roots = try urls.compactMap { url -> ScanRootRequest? in
        let values = try url.resourceValues(forKeys: keys)
        guard let isLocal = values.volumeIsLocal, let isReadOnly = values.volumeIsReadOnly else {
          throw ScanCoordinatorError.unavailable(
            .rootDiscoveryUnavailable,
            "mounted volume locality or writability is unavailable"
          )
        }
        guard isLocal, !isReadOnly else { return nil }
        return root(id: "volume-\(stableRootID(url))", url: url)
      }
      return ScanEnvironment(visibleLocalWritableVolumes: deduplicated(roots))
    }
  }

  private static func root(id: String, url: URL) -> ScanRootRequest {
    ScanRootRequest(
      rootID: id,
      rawAbsolutePath: rawFileSystemPath(url).droppingTrailingSlash()
    )
  }

  private static func stableRootID(_ url: URL) -> String {
    rawFileSystemPath(url).map { String(format: "%02x", $0) }.joined()
  }

  private static func rawFileSystemPath(_ url: URL) -> Data {
    Data(
      url.withUnsafeFileSystemRepresentation { pointer -> [UInt8] in
        guard let pointer else { return [] }
        return UnsafeBufferPointer(start: pointer, count: strlen(pointer)).map {
          UInt8(bitPattern: $0)
        }
      }
    )
  }

  private static func deduplicated(_ roots: [ScanRootRequest]) -> [ScanRootRequest] {
    var seen = Set<Data>()
    return roots.filter { seen.insert($0.rawAbsolutePath).inserted }
  }

  private static func isValidRootID(_ value: String) -> Bool {
    let bytes = value.utf8
    guard !bytes.isEmpty && bytes.count <= 1_024 else { return false }
    return value.unicodeScalars.allSatisfy { scalar in
      switch scalar.properties.generalCategory {
      case .control, .format, .lineSeparator, .paragraphSeparator, .surrogate:
        false
      default:
        true
      }
    }
  }

  private static func validateCheckpointRootBindings(
    _ roots: [ScanRootRequest]
  ) throws {
    var probe = Diskplan_V1_ScanCheckpointEvidence()
    probe.resolvedRoots = roots.map(ScanIPCProjection.rootRequest)
    probe.completedRoots = probe.resolvedRoots.map { root in
      var completed = Diskplan_V1_RootScanEvidence()
      completed.root = root
      return completed
    }
    if let widestDisplay = probe.resolvedRoots.map(\.displayPath).max(by: {
      $0.utf8.count < $1.utf8.count
    }) {
      var progress = Diskplan_V1_ScanProgress()
      progress.currentRoot = widestDisplay
      probe.progress = progress
    }
    let encodedBytes = try probe.serializedData().count
    guard encodedBytes <= maximumCheckpointRootBindingBytes else {
      throw ScanCoordinatorError.malformed(
        .invalidBudget,
        "checkpoint root bindings exceed the 1 MiB setup budget"
      )
    }
  }

  static func isValidCanonicalRootPath(_ value: Data) -> Bool {
    // This is deliberately far above Darwin's practical path limit while
    // leaving ample room for worst-case byte-escaped display projection inside
    // the independently bounded checkpoint chunk.
    guard value.count <= 256 * 1_024 else { return false }
    return (try? CanonicalScanRootPath.parse(value)) != nil
  }
}

extension Data {
  fileprivate func droppingTrailingSlash() -> Data {
    var result = self
    while result.count > 1 && result.last == UInt8(ascii: "/") { result.removeLast() }
    return result
  }
}
