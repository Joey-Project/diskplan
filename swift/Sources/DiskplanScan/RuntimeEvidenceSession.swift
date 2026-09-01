import CryptoKit
import Darwin
import DiskplanMacOS
import Foundation

package enum RuntimeEvidenceCaptureKind: UInt8, Equatable, Sendable {
  case wholePlan = 1
  case jitUnit = 2
  case finalDescriptor = 3
}

package struct RuntimeEvidenceCaptureID: Equatable, Hashable, Sendable {
  package let bytes: Data

  fileprivate init(bytes: Data) { self.bytes = bytes }
}

/// Ownership of `fileDescriptor` transfers to DiskplanScan when collection starts.
package struct RuntimeFreshRootDescriptor: Sendable {
  package let rootID: String
  package let rawAbsolutePath: Data
  package let fileDescriptor: Int32

  package init(rootID: String, rawAbsolutePath: Data, fileDescriptor: Int32) {
    self.rootID = rootID
    self.rawAbsolutePath = rawAbsolutePath
    self.fileDescriptor = fileDescriptor
  }
}

/// Ownership of `fileDescriptor` transfers to DiskplanScan when collection starts.
package struct RuntimeFreshVolumeDescriptor: Sendable {
  package let volumeID: String
  package let fileDescriptor: Int32

  package init(volumeID: String, fileDescriptor: Int32) {
    self.volumeID = volumeID
    self.fileDescriptor = fileDescriptor
  }
}

/// Raw authority input only. DiskplanScan resolves the scope, selects all structural bounds,
/// owns every sink, and performs the concrete Darwin collection without materializing providers.
package struct RuntimeFreshScanRequest: Sendable {
  package let roots: [RuntimeFreshRootDescriptor]
  package let volumes: [RuntimeFreshVolumeDescriptor]
  package let maximumDurationNanoseconds: UInt64?
  package let processDeadlineNanoseconds: UInt64

  package init(
    roots: [RuntimeFreshRootDescriptor],
    volumes: [RuntimeFreshVolumeDescriptor] = [],
    maximumDurationNanoseconds: UInt64?,
    processDeadlineNanoseconds: UInt64
  ) {
    self.roots = roots
    self.volumes = volumes
    self.maximumDurationNanoseconds = maximumDurationNanoseconds
    self.processDeadlineNanoseconds = processDeadlineNanoseconds
  }
}

package enum RuntimeFreshScanError: Error, Equatable {
  case closed
  case captureAlreadyActive
  case captureRetired
  case captureSequenceExhausted
  case invalidRequest(reason: String)
  case descriptorFailure(scopeID: String, observation: Observation<String>)
  case receiptConsumed
  case receiptBindingMismatch
}

/// The only package-visible fresh scan value. Its initializer and payload stay Scan-private.
/// A successful or failed consume attempt permanently drains the receipt.
package final class RuntimeFreshScanReceipt: @unchecked Sendable {
  package let captureID: RuntimeEvidenceCaptureID
  package let kind: RuntimeEvidenceCaptureKind
  package let rootBindingDigest: EvidenceDigest

  private let lock = NSLock()
  private let session: RuntimeEvidenceSession
  private let leaseState: RuntimeEvidenceLeaseState
  private let rootRequestDigest: EvidenceDigest
  private var payload: RuntimeFreshScanPayload?

  fileprivate init(
    captureID: RuntimeEvidenceCaptureID,
    kind: RuntimeEvidenceCaptureKind,
    rootRequestDigest: EvidenceDigest,
    rootBindingDigest: EvidenceDigest,
    payload: RuntimeFreshScanPayload,
    session: RuntimeEvidenceSession,
    leaseState: RuntimeEvidenceLeaseState
  ) {
    self.captureID = captureID
    self.kind = kind
    self.rootRequestDigest = rootRequestDigest
    self.rootBindingDigest = rootBindingDigest
    self.payload = payload
    self.session = session
    self.leaseState = leaseState
  }

  fileprivate func consume(
    from expectedSession: RuntimeEvidenceSession,
    lease expectedLease: RuntimeEvidenceLeaseState,
    kind expectedKind: RuntimeEvidenceCaptureKind,
    roots expectedRoots: [ScanRootRequest],
    captureID expectedCaptureID: RuntimeEvidenceCaptureID
  ) throws -> RuntimeFreshScanPayload {
    try lock.withLock {
      guard let payload else { throw RuntimeFreshScanError.receiptConsumed }
      self.payload = nil
      guard session === expectedSession, leaseState === expectedLease,
        kind == expectedKind, captureID == expectedCaptureID,
        rootRequestDigest == runtimeRootRequestDigest(expectedRoots),
        payload.rootBindingDigest == rootBindingDigest,
        expectedLease.consumePublishedReceipt(rootBindingDigest: rootBindingDigest)
      else {
        throw RuntimeFreshScanError.receiptBindingMismatch
      }
      return payload
    }
  }
}

/// This type has no package initializer. EngineCore obtains it only by consuming a Scan receipt.
package struct RuntimeFreshScanPayload: Sendable {
  package let captureID: RuntimeEvidenceCaptureID
  package let kind: RuntimeEvidenceCaptureKind
  package let rootBindingDigest: EvidenceDigest
  package let rootBindingValidation: Observation<Bool>
  package let scanResult: ScanResult
  package let events: Observation<[ScanNodeEvent]>
  package let collectors: RuntimeCollectorSnapshot

  fileprivate init(
    captureID: RuntimeEvidenceCaptureID,
    kind: RuntimeEvidenceCaptureKind,
    rootBindingDigest: EvidenceDigest,
    rootBindingValidation: Observation<Bool>,
    scanResult: ScanResult,
    events: Observation<[ScanNodeEvent]>,
    collectors: RuntimeCollectorSnapshot
  ) {
    self.captureID = captureID
    self.kind = kind
    self.rootBindingDigest = rootBindingDigest
    self.rootBindingValidation = rootBindingValidation
    self.scanResult = scanResult
    self.events = events
    self.collectors = collectors
  }
}

private final class RuntimeEvidenceLeaseState: @unchecked Sendable {
  private enum Lifecycle {
    case ready
    case collecting
    case published(rootBindingDigest: EvidenceDigest)
    case retired
  }

  private let condition = NSCondition()
  private var lifecycle = Lifecycle.ready
  private var collectionInFlight = false
  private var receiptConsumed = false

  func beginCollection() throws {
    try condition.withLock {
      guard case .ready = lifecycle else { throw RuntimeFreshScanError.captureRetired }
      lifecycle = .collecting
      collectionInFlight = true
    }
  }

  func publish(rootBindingDigest: EvidenceDigest) -> Bool {
    condition.withLock {
      guard collectionInFlight, case .collecting = lifecycle else { return false }
      collectionInFlight = false
      lifecycle = .published(rootBindingDigest: rootBindingDigest)
      condition.broadcast()
      return true
    }
  }

  func abortCollection() {
    condition.withLock {
      collectionInFlight = false
      lifecycle = .retired
      condition.broadcast()
    }
  }

  func consumePublishedReceipt(rootBindingDigest: EvidenceDigest) -> Bool {
    condition.withLock {
      guard !receiptConsumed,
        case .published(let publishedDigest) = lifecycle,
        publishedDigest == rootBindingDigest
      else { return false }
      receiptConsumed = true
      return true
    }
  }

  func retireAndDrain() -> Bool {
    condition.lock()
    let wasRetired: Bool
    if case .retired = lifecycle { wasRetired = true } else { wasRetired = false }
    lifecycle = .retired
    while collectionInFlight { condition.wait() }
    condition.unlock()
    return !wasRetired
  }
}

/// One Scan-owned session has at most one live capture lease. Every fresh scan uses the concrete
/// Darwin filesystem and production collector bundle selected by this module.
package final class RuntimeEvidenceSession: @unchecked Sendable {
  private let lock = NSLock()
  private let policy: NoMaterializationPolicy
  private let collectorBundle: ProductionScanCollectorBundle
  private let scanProfile: ScanProfile
  private let transferredDescriptorObserver: @Sendable ([Int32]) -> Void
  private let sessionNonce: Data
  private var issuedCaptureIDs = Set<RuntimeEvidenceCaptureID>()
  private var sequence: UInt64 = 0
  private var activeLease: RuntimeEvidenceLeaseState?
  private var closed = false

  package init(policy: NoMaterializationPolicy) {
    self.policy = policy
    collectorBundle = ProductionScanCollectorBundle()
    scanProfile = .deep
    transferredDescriptorObserver = { _ in }
    var nonce = Data(count: 32)
    nonce.withUnsafeMutableBytes { raw in
      arc4random_buf(raw.baseAddress, raw.count)
    }
    sessionNonce = nonce
  }

  /// Test-only module seam. It is `internal`, not `package`, so EngineCore cannot inject a fake
  /// collector into the production provenance boundary.
  init(
    policy: NoMaterializationPolicy,
    testingCollectorBundle: ProductionScanCollectorBundle,
    testingScanProfile: ScanProfile = .deep,
    testingTransferredDescriptorObserver: @escaping @Sendable ([Int32]) -> Void = { _ in }
  ) {
    self.policy = policy
    collectorBundle = testingCollectorBundle
    scanProfile = testingScanProfile
    transferredDescriptorObserver = testingTransferredDescriptorObserver
    var nonce = Data(count: 32)
    nonce.withUnsafeMutableBytes { raw in
      arc4random_buf(raw.baseAddress, raw.count)
    }
    sessionNonce = nonce
  }

  deinit { close() }

  package func beginCapture(
    _ kind: RuntimeEvidenceCaptureKind,
    excluding forbidden: Set<Data> = []
  ) throws -> RuntimeEvidenceCaptureLease {
    let state = RuntimeEvidenceLeaseState()
    let captureID = try lock.withLock { () throws -> RuntimeEvidenceCaptureID in
      guard !closed else { throw RuntimeFreshScanError.closed }
      guard activeLease == nil else { throw RuntimeFreshScanError.captureAlreadyActive }
      let captureID = try nextCaptureID(kind: kind, excluding: forbidden)
      activeLease = state
      return captureID
    }
    return RuntimeEvidenceCaptureLease(
      captureID: captureID,
      kind: kind,
      state: state,
      session: self
    )
  }

  package func close() {
    let state = lock.withLock { () -> RuntimeEvidenceLeaseState? in
      guard !closed else { return nil }
      closed = true
      return activeLease
    }
    _ = state?.retireAndDrain()
    lock.withLock {
      if activeLease === state { activeLease = nil }
    }
  }

  fileprivate func finish(_ state: RuntimeEvidenceLeaseState) {
    _ = state.retireAndDrain()
    lock.withLock {
      if activeLease === state { activeLease = nil }
    }
  }

  fileprivate func collectFreshScan(
    _ request: RuntimeFreshScanRequest,
    captureID: RuntimeEvidenceCaptureID,
    kind: RuntimeEvidenceCaptureKind,
    state: RuntimeEvidenceLeaseState
  ) async throws -> RuntimeFreshScanReceipt {
    try requireActive(state)
    let ownedDescriptors: RuntimeFreshOwnedDescriptors
    do {
      ownedDescriptors = try RuntimeFreshOwnedDescriptors(
        roots: request.roots,
        volumes: request.volumes,
        policy: policy,
        transferredDescriptorObserver: transferredDescriptorObserver
      )
    } catch {
      state.abortCollection()
      throw error
    }

    do {
      try Task.checkCancellation()
      let rootRequests = ownedDescriptors.roots.map {
        ScanRootRequest(rootID: $0.rootID, rawAbsolutePath: $0.rawAbsolutePath)
      }
      let environment =
        scanProfile == .quick ? ScanEnvironment(adapterRoots: rootRequests) : ScanEnvironment()
      let scope = try ScanRootResolver().resolve(
        profile: scanProfile,
        environment: environment,
        explicitRoots: rootRequests,
        maximumDurationNanoseconds: request.maximumDurationNanoseconds
      )
      let collectors = await collectorBundle.collect(
        processDeadlineNanoseconds: request.processDeadlineNanoseconds,
        volumes: ownedDescriptors.volumes.map {
          RuntimeVolumeDescriptor(volumeID: $0.volumeID, fileDescriptor: $0.fileDescriptor)
        }
      )
      try Task.checkCancellation()
      let validatedCollectors = ownedDescriptors.revalidateVolumes(collectors)
      let eventSink = RuntimeFreshEventCaptureSink(
        maximumEvents: runtimeFreshEventLimit(scope: scope)
      )
      let scanner = DeterministicScanner(
        filesystem: DarwinScanFilesystem(policy: policy),
        scope: scope,
        nodeSink: eventSink,
        processActivity: scanProcessActivity(validatedCollectors.processActivity),
        globalFacts: scanGlobalFacts(validatedCollectors.globalFacts),
        collectorConfiguration: collectorBundle.collectorConfiguration(
          processDeadlineNanoseconds: request.processDeadlineNanoseconds
        )
      )
      var result = scanner.snapshot()
      while result.state == .ready || result.state == .scanning {
        try Task.checkCancellation()
        result = scanner.advance(maximumEntries: 512)
      }
      try Task.checkCancellation()
      let rootValidation = ownedDescriptors.validateRoots(scanResult: result)
      let requestDigest = runtimeRootRequestDigest(rootRequests)
      let bindingDigest = ownedDescriptors.rootBindingDigest
      let payload = RuntimeFreshScanPayload(
        captureID: captureID,
        kind: kind,
        rootBindingDigest: bindingDigest,
        rootBindingValidation: rootValidation,
        scanResult: result,
        events: eventSink.snapshot(),
        collectors: validatedCollectors
      )
      guard publish(state, rootBindingDigest: bindingDigest) else {
        throw RuntimeFreshScanError.captureRetired
      }
      return RuntimeFreshScanReceipt(
        captureID: captureID,
        kind: kind,
        rootRequestDigest: requestDigest,
        rootBindingDigest: bindingDigest,
        payload: payload,
        session: self,
        leaseState: state
      )
    } catch {
      state.abortCollection()
      throw error
    }
  }

  private func requireActive(_ state: RuntimeEvidenceLeaseState) throws {
    let active = lock.withLock { !closed && activeLease === state }
    guard active else { throw RuntimeFreshScanError.captureRetired }
    try Task.checkCancellation()
  }

  private func publish(
    _ state: RuntimeEvidenceLeaseState,
    rootBindingDigest: EvidenceDigest
  ) -> Bool {
    lock.withLock {
      guard !closed, activeLease === state, !Task.isCancelled else { return false }
      return state.publish(rootBindingDigest: rootBindingDigest)
    }
  }

  private func nextCaptureID(
    kind: RuntimeEvidenceCaptureKind,
    excluding forbidden: Set<Data>
  ) throws -> RuntimeEvidenceCaptureID {
    while true {
      let next = sequence.addingReportingOverflow(1)
      guard !next.overflow else { throw RuntimeFreshScanError.captureSequenceExhausted }
      sequence = next.partialValue
      var input = Data("diskplan/runtime-fresh-scan-capture/v1\0".utf8)
      input.append(sessionNonce)
      input.append(kind.rawValue)
      appendUInt64(sequence, to: &input)
      let captureID = RuntimeEvidenceCaptureID(bytes: Data(SHA256.hash(data: input)))
      guard !forbidden.contains(captureID.bytes), !issuedCaptureIDs.contains(captureID) else {
        continue
      }
      issuedCaptureIDs.insert(captureID)
      return captureID
    }
  }
}

package final class RuntimeEvidenceCaptureLease: @unchecked Sendable {
  package let captureID: RuntimeEvidenceCaptureID
  package let kind: RuntimeEvidenceCaptureKind
  private let state: RuntimeEvidenceLeaseState
  private let session: RuntimeEvidenceSession

  fileprivate init(
    captureID: RuntimeEvidenceCaptureID,
    kind: RuntimeEvidenceCaptureKind,
    state: RuntimeEvidenceLeaseState,
    session: RuntimeEvidenceSession
  ) {
    self.captureID = captureID
    self.kind = kind
    self.state = state
    self.session = session
  }

  deinit { finish() }

  package func collectFreshScan(
    _ request: RuntimeFreshScanRequest
  ) async throws -> RuntimeFreshScanReceipt {
    try state.beginCollection()
    do {
      return try await session.collectFreshScan(
        request,
        captureID: captureID,
        kind: kind,
        state: state
      )
    } catch {
      state.abortCollection()
      throw error
    }
  }

  package func consumeFreshScanReceipt(
    _ receipt: RuntimeFreshScanReceipt,
    expectedKind: RuntimeEvidenceCaptureKind,
    expectedRoots: [ScanRootRequest],
    expectedCaptureID: RuntimeEvidenceCaptureID
  ) throws -> RuntimeFreshScanPayload {
    try receipt.consume(
      from: session,
      lease: state,
      kind: expectedKind,
      roots: expectedRoots,
      captureID: expectedCaptureID
    )
  }

  package func finish() { session.finish(state) }
}

private struct RuntimeFreshBoundRoot {
  let rootID: String
  let rawAbsolutePath: Data
  let fileDescriptor: Int32
  let seal: RuntimeFreshDescriptorSeal
}

private struct RuntimeFreshBoundVolume {
  let volumeID: String
  let fileDescriptor: Int32
  let seal: RuntimeFreshDescriptorSeal
}

private struct RuntimeFreshDescriptorSeal: Equatable {
  let identity: ObjectIdentity
  let accessPolicy: AccessPolicyEvidence
}

private final class RuntimeFreshOwnedDescriptors {
  let roots: [RuntimeFreshBoundRoot]
  let volumes: [RuntimeFreshBoundVolume]
  let rootBindingDigest: EvidenceDigest
  private let policy: NoMaterializationPolicy
  private let allDescriptors: [Int32]

  init(
    roots sourceRoots: [RuntimeFreshRootDescriptor],
    volumes sourceVolumes: [RuntimeFreshVolumeDescriptor],
    policy: NoMaterializationPolicy,
    transferredDescriptorObserver: @Sendable ([Int32]) -> Void
  ) throws {
    self.policy = policy
    let rootIDs = sourceRoots.map(\.rootID)
    let volumeIDs = sourceVolumes.map(\.volumeID)
    let sourceDescriptors = sourceRoots.map(\.fileDescriptor) + sourceVolumes.map(\.fileDescriptor)
    var transferredDescriptorsClosed = false
    defer {
      if !transferredDescriptorsClosed {
        for descriptor in Set(sourceDescriptors) where descriptor >= 0 { Darwin.close(descriptor) }
      }
    }
    guard rootIDs.allSatisfy({ !$0.isEmpty }), Set(rootIDs).count == rootIDs.count else {
      throw RuntimeFreshScanError.invalidRequest(reason: "fresh scan root IDs must be unique")
    }
    guard volumeIDs.allSatisfy({ !$0.isEmpty }), Set(volumeIDs).count == volumeIDs.count else {
      throw RuntimeFreshScanError.invalidRequest(reason: "fresh scan volume IDs must be unique")
    }
    guard sourceDescriptors.allSatisfy({ $0 >= 0 }),
      Set(sourceDescriptors).count == sourceDescriptors.count
    else {
      throw RuntimeFreshScanError.invalidRequest(
        reason: "fresh scan descriptors must be valid and uniquely owned")
    }
    for root in sourceRoots {
      do { _ = try CanonicalScanRootPath.parse(root.rawAbsolutePath) } catch {
        throw RuntimeFreshScanError.invalidRequest(
          reason: "fresh scan roots must use canonical absolute raw paths")
      }
    }

    var duplicated: [Int32: Int32] = [:]
    do {
      for descriptor in sourceDescriptors {
        let copy = Darwin.fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
        guard copy >= 0 else {
          throw RuntimeFreshScanError.descriptorFailure(
            scopeID: "fd:\(descriptor)",
            observation: runtimeDescriptorFailure(
              errno, operation: "duplicate fresh scan descriptor")
          )
        }
        do {
          try runtimeValidateDescriptorFlags(copy, scopeID: "fd:\(descriptor)")
        } catch {
          Darwin.close(copy)
          throw error
        }
        duplicated[descriptor] = copy
      }
      var closeFailure: (Int32, Int32)?
      for descriptor in sourceDescriptors {
        if Darwin.close(descriptor) != 0, closeFailure == nil {
          closeFailure = (descriptor, errno)
        }
      }
      transferredDescriptorsClosed = true
      if let (descriptor, code) = closeFailure {
        throw RuntimeFreshScanError.descriptorFailure(
          scopeID: "fd:\(descriptor)",
          observation: .failed(
            reason: "close transferred fresh scan descriptor failed", errorCode: code)
        )
      }
      transferredDescriptorObserver(sourceDescriptors.sorted())
      var boundRoots: [RuntimeFreshBoundRoot] = []
      for root in sourceRoots {
        let copy = duplicated[root.fileDescriptor]!
        let seal = try runtimeDescriptorSeal(copy, scopeID: root.rootID, policy: policy)
        guard seal.identity.objectType == .directory else {
          throw RuntimeFreshScanError.descriptorFailure(
            scopeID: root.rootID,
            observation: .failed(reason: "fresh scan root is not a directory", errorCode: ENOTDIR)
          )
        }
        boundRoots.append(
          RuntimeFreshBoundRoot(
            rootID: root.rootID,
            rawAbsolutePath: root.rawAbsolutePath,
            fileDescriptor: copy,
            seal: seal
          ))
      }
      var boundVolumes: [RuntimeFreshBoundVolume] = []
      for volume in sourceVolumes {
        let copy = duplicated[volume.fileDescriptor]!
        let seal = try runtimeDescriptorSeal(copy, scopeID: volume.volumeID, policy: policy)
        guard seal.identity.objectType == .directory else {
          throw RuntimeFreshScanError.descriptorFailure(
            scopeID: volume.volumeID,
            observation: .failed(reason: "fresh scan volume is not a directory", errorCode: ENOTDIR)
          )
        }
        boundVolumes.append(
          RuntimeFreshBoundVolume(
            volumeID: volume.volumeID,
            fileDescriptor: copy,
            seal: seal
          ))
      }
      roots = boundRoots.sorted(by: runtimeBoundRootPrecedes)
      volumes = boundVolumes.sorted { $0.volumeID < $1.volumeID }
      allDescriptors = Array(duplicated.values)
      rootBindingDigest = runtimeRootBindingDigest(roots)
    } catch {
      for descriptor in duplicated.values { Darwin.close(descriptor) }
      throw error
    }
  }

  deinit {
    for descriptor in allDescriptors { Darwin.close(descriptor) }
  }

  func validateRoots(scanResult: ScanResult) -> Observation<Bool> {
    let rootsByID = Dictionary(
      uniqueKeysWithValues: scanResult.roots.map { ($0.binding.rootID, $0) })
    let failuresByID = Dictionary(uniqueKeysWithValues: scanResult.rootFailures)
    for root in roots {
      let current: RuntimeFreshDescriptorSeal
      do {
        current = try runtimeDescriptorSeal(
          root.fileDescriptor, scopeID: root.rootID, policy: policy)
      } catch let RuntimeFreshScanError.descriptorFailure(_, observation) {
        return observation.erasingValue()
      } catch {
        return .failed(reason: "fresh scan root revalidation failed", errorCode: EIO)
      }
      guard current.identity == root.seal.identity else {
        return .failed(reason: "fresh scan root descriptor identity changed", errorCode: ESTALE)
      }
      if let aclFailure = runtimeACLFailure(root.seal.accessPolicy.aclDigest) {
        return aclFailure
      }
      if let aclFailure = runtimeACLFailure(current.accessPolicy.aclDigest) {
        return aclFailure
      }
      guard current.accessPolicy == root.seal.accessPolicy else {
        return .failed(reason: "fresh scan root access policy changed", errorCode: EAGAIN)
      }
      guard let scanned = rootsByID[root.rootID] else {
        return failuresByID[root.rootID]?.erasingValue()
          ?? .failed(reason: "fresh scan omitted a bound root", errorCode: EPROTO)
      }
      guard scanned.binding.rawAbsolutePath == root.rawAbsolutePath,
        scanned.binding.identity == root.seal.identity
      else {
        return .failed(
          reason: "fresh scan root binding does not match its descriptor", errorCode: ESTALE)
      }
      switch scanned.rootAccessPolicy {
      case .known(let access) where access == root.seal.accessPolicy:
        break
      case .known:
        return .failed(reason: "fresh scan root access policy changed", errorCode: EAGAIN)
      case .absent(let reason): return .absent(reason: reason)
      case .unknown(let reason): return .unknown(reason: reason)
      case .unreadable(let reason, let code):
        return .unreadable(reason: reason, errorCode: code)
      case .failed(let reason, let code): return .failed(reason: reason, errorCode: code)
      }
    }
    return .known(true)
  }

  func revalidateVolumes(_ snapshot: RuntimeCollectorSnapshot) -> RuntimeCollectorSnapshot {
    var facts = snapshot.globalFacts.apfsSnapshotsByVolume
    for volume in volumes {
      do {
        let current = try runtimeDescriptorSeal(
          volume.fileDescriptor,
          scopeID: volume.volumeID,
          policy: policy
        )
        if let aclFailure = runtimeACLFailure(volume.seal.accessPolicy.aclDigest) {
          facts[volume.volumeID] = aclFailure.erasingValue()
        } else if let aclFailure = runtimeACLFailure(current.accessPolicy.aclDigest) {
          facts[volume.volumeID] = aclFailure.erasingValue()
        } else if current != volume.seal {
          facts[volume.volumeID] = .failed(
            reason: "fresh scan volume descriptor identity or access policy changed",
            errorCode: ESTALE
          )
        }
      } catch let RuntimeFreshScanError.descriptorFailure(_, observation) {
        facts[volume.volumeID] = observation.erasingValue()
      } catch {
        facts[volume.volumeID] = .failed(
          reason: "fresh scan volume revalidation failed", errorCode: EIO)
      }
    }
    return RuntimeCollectorSnapshot(
      processActivity: snapshot.processActivity,
      globalFacts: RuntimeGlobalFactSnapshot(
        vm: snapshot.globalFacts.vm,
        swap: snapshot.globalFacts.swap,
        apfsSnapshotsByVolume: facts
      )
    )
  }
}

private final class RuntimeFreshEventCaptureSink: ScanNodeSink, @unchecked Sendable {
  private static let maximumEstimatedBytes = 256 * 1_024 * 1_024

  private let lock = NSLock()
  private let maximumEvents: Int
  private var events: [ScanNodeEvent] = []
  private var estimatedBytes = 0
  private var overflowed = false

  init(maximumEvents: Int) {
    precondition(maximumEvents > 0)
    self.maximumEvents = maximumEvents
  }

  func receive(_ event: ScanNodeEvent) {
    lock.withLock {
      guard !overflowed else { return }
      let eventBytes = runtimeEstimatedEventBytes(event)
      let (nextBytes, byteOverflow) = estimatedBytes.addingReportingOverflow(eventBytes)
      guard events.count < maximumEvents, !byteOverflow,
        nextBytes <= Self.maximumEstimatedBytes
      else {
        events.removeAll(keepingCapacity: false)
        estimatedBytes = 0
        overflowed = true
        return
      }
      events.append(event)
      estimatedBytes = nextBytes
    }
  }

  func snapshot() -> Observation<[ScanNodeEvent]> {
    lock.withLock {
      overflowed
        ? .failed(
          reason: "fresh scan event corpus exceeded its Scan-owned limit", errorCode: EOVERFLOW)
        : .known(events)
    }
  }
}

private func runtimeFreshEventLimit(scope: ResolvedScanScope) -> Int {
  let rootCount = UInt64(max(1, scope.roots.count))
  let (entries, overflow) = scope.budget.maximumEntriesPerRoot.multipliedReportingOverflow(
    by: rootCount)
  let boundedEntries = overflow ? UInt64.max : entries
  let (events, eventOverflow) = boundedEntries.multipliedReportingOverflow(by: 2)
  let (requestedCount, countOverflow) = events.addingReportingOverflow(
    UInt64(scope.roots.count))
  let requested = eventOverflow || countOverflow ? UInt64.max : requestedCount
  return Int(max(1, min(1_000_000, requested)))
}

private func runtimeEstimatedEventBytes(_ event: ScanNodeEvent) -> Int {
  let node: ScannedNode
  switch event {
  case .observed(let value), .directoryClosed(let value): node = value
  }
  let pathBytes = node.path.components.reduce(into: node.path.rootID.utf8.count) {
    $0 = $0.addingReportingOverflow($1.bytes.count).overflow ? Int.max : $0 + $1.bytes.count
  }
  let pendingSealBytes =
    node.ancestorAccessPolicy.value.map { seal in
      let result = seal.pendingCloseEpochIDs.count.multipliedReportingOverflow(by: 32)
      return result.overflow ? Int.max : result.partialValue
    } ?? 0
  let (dynamicBytes, dynamicOverflow) = pathBytes.addingReportingOverflow(pendingSealBytes)
  guard !dynamicOverflow else { return Int.max }
  let (estimate, estimateOverflow) = dynamicBytes.addingReportingOverflow(1_024)
  return estimateOverflow ? Int.max : estimate
}

private func runtimeDescriptorSeal(
  _ descriptor: Int32,
  scopeID: String,
  policy: NoMaterializationPolicy
) throws -> RuntimeFreshDescriptorSeal {
  guard descriptor >= 0 else {
    throw RuntimeFreshScanError.descriptorFailure(
      scopeID: scopeID,
      observation: .failed(reason: "fresh scan descriptor is invalid", errorCode: EBADF)
    )
  }
  try runtimeValidateDescriptorFlags(descriptor, scopeID: scopeID)
  errno = 0
  guard let seal = descriptorSeal(fileDescriptor: descriptor, policy: policy) else {
    let code = errno == 0 ? EIO : errno
    throw RuntimeFreshScanError.descriptorFailure(
      scopeID: scopeID,
      observation: runtimeDescriptorFailure(code, operation: "seal fresh scan descriptor")
    )
  }
  return RuntimeFreshDescriptorSeal(
    identity: seal.identity,
    accessPolicy: seal.accessPolicy
  )
}

private func runtimeValidateDescriptorFlags(
  _ descriptor: Int32,
  scopeID: String
) throws {
  errno = 0
  let descriptorFlags = Darwin.fcntl(descriptor, F_GETFD)
  guard descriptorFlags >= 0 else {
    throw RuntimeFreshScanError.descriptorFailure(
      scopeID: scopeID,
      observation: runtimeDescriptorFailure(
        errno, operation: "read fresh scan descriptor flags")
    )
  }
  guard descriptorFlags & FD_CLOEXEC != 0 else {
    throw RuntimeFreshScanError.descriptorFailure(
      scopeID: scopeID,
      observation: .failed(
        reason: "fresh scan descriptor is not close-on-exec", errorCode: EPROTO)
    )
  }
  errno = 0
  let statusFlags = Darwin.fcntl(descriptor, F_GETFL)
  guard statusFlags >= 0 else {
    throw RuntimeFreshScanError.descriptorFailure(
      scopeID: scopeID,
      observation: runtimeDescriptorFailure(
        errno, operation: "read fresh scan descriptor status flags")
    )
  }
  guard statusFlags & O_ACCMODE == O_RDONLY, statusFlags & O_EVTONLY == 0 else {
    throw RuntimeFreshScanError.descriptorFailure(
      scopeID: scopeID,
      observation: .failed(
        reason: "fresh scan descriptor is not read-only", errorCode: EACCES)
    )
  }
}

private func runtimeDescriptorFailure(
  _ code: Int32,
  operation: String
) -> Observation<String> {
  switch code {
  case ENOENT, EBADF: return .absent(reason: "\(operation): descriptor is missing")
  case EACCES, EPERM:
    return .unreadable(reason: "\(operation): permission denied", errorCode: code)
  default: return .failed(reason: "\(operation): POSIX failure", errorCode: code)
  }
}

private func runtimeACLFailure(
  _ observation: Observation<EvidenceDigest>
) -> Observation<Bool>? {
  switch observation {
  case .known: return nil
  case .absent(let reason): return .absent(reason: reason)
  case .unknown(let reason): return .unknown(reason: reason)
  case .unreadable(let reason, let code):
    return .unreadable(reason: reason, errorCode: code)
  case .failed(let reason, let code): return .failed(reason: reason, errorCode: code)
  }
}

private func runtimeBoundRootPrecedes(
  _ lhs: RuntimeFreshBoundRoot,
  _ rhs: RuntimeFreshBoundRoot
) -> Bool {
  if lhs.rawAbsolutePath != rhs.rawAbsolutePath {
    return lhs.rawAbsolutePath.lexicographicallyPrecedes(rhs.rawAbsolutePath)
  }
  return lhs.rootID < rhs.rootID
}

private func runtimeRootRequestDigest(_ roots: [ScanRootRequest]) -> EvidenceDigest {
  var data = Data("diskplan/runtime-fresh-scan-root-request/v1\0".utf8)
  let canonical = roots.sorted {
    if $0.rawAbsolutePath != $1.rawAbsolutePath {
      return $0.rawAbsolutePath.lexicographicallyPrecedes($1.rawAbsolutePath)
    }
    return $0.rootID < $1.rootID
  }
  appendUInt64(UInt64(canonical.count), to: &data)
  for root in canonical {
    appendLengthPrefixed(Data(root.rootID.utf8), to: &data)
    appendLengthPrefixed(root.rawAbsolutePath, to: &data)
  }
  return EvidenceDigest(unchecked: Data(SHA256.hash(data: data)))
}

private func runtimeRootBindingDigest(
  _ roots: [RuntimeFreshBoundRoot]
) -> EvidenceDigest {
  var data = Data("diskplan/runtime-fresh-scan-root-binding/v1\0".utf8)
  appendUInt64(UInt64(roots.count), to: &data)
  for root in roots.sorted(by: runtimeBoundRootPrecedes) {
    appendLengthPrefixed(Data(root.rootID.utf8), to: &data)
    appendLengthPrefixed(root.rawAbsolutePath, to: &data)
    appendInt64(root.seal.identity.device, to: &data)
    appendUInt64(root.seal.identity.fileID, to: &data)
    data.append(runtimeObjectTypeByte(root.seal.identity.objectType))
    appendUInt64(UInt64(root.seal.accessPolicy.ownerUserID), to: &data)
    appendUInt64(UInt64(root.seal.accessPolicy.ownerGroupID), to: &data)
    appendUInt64(UInt64(root.seal.accessPolicy.mode), to: &data)
    appendUInt64(UInt64(root.seal.accessPolicy.flags), to: &data)
    appendObservation(root.seal.accessPolicy.aclDigest, to: &data)
  }
  return EvidenceDigest(unchecked: Data(SHA256.hash(data: data)))
}

private func appendObservation(_ value: Observation<EvidenceDigest>, to data: inout Data) {
  switch value {
  case .known(let digest):
    data.append(1)
    appendLengthPrefixed(digest.bytes, to: &data)
  case .absent(let reason):
    data.append(2)
    appendLengthPrefixed(Data(reason.utf8), to: &data)
  case .unknown(let reason):
    data.append(3)
    appendLengthPrefixed(Data(reason.utf8), to: &data)
  case .unreadable(let reason, let code):
    data.append(4)
    appendLengthPrefixed(Data(reason.utf8), to: &data)
    appendOptionalErrorCode(code, to: &data)
  case .failed(let reason, let code):
    data.append(5)
    appendLengthPrefixed(Data(reason.utf8), to: &data)
    appendOptionalErrorCode(code, to: &data)
  }
}

private func appendOptionalErrorCode(_ code: Int32?, to data: inout Data) {
  data.append(code == nil ? 0 : 1)
  appendUInt64(UInt64(UInt32(bitPattern: code ?? 0)), to: &data)
}

private func runtimeObjectTypeByte(_ type: ScannedObjectType) -> UInt8 {
  switch type {
  case .regular: 1
  case .directory: 2
  case .symbolicLink: 3
  case .other: 4
  }
}

private func appendLengthPrefixed(_ value: Data, to data: inout Data) {
  appendUInt64(UInt64(value.count), to: &data)
  data.append(value)
}

private func appendInt64(_ value: Int64, to data: inout Data) {
  appendUInt64(UInt64(bitPattern: value), to: &data)
}

private func appendUInt64(_ value: UInt64, to data: inout Data) {
  var bigEndian = value.bigEndian
  withUnsafeBytes(of: &bigEndian) { data.append(contentsOf: $0) }
}

private func scanProcessActivity(
  _ observation: ProcessActivityObservation
) -> Observation<[ProcessActivityRecord]> {
  switch observation {
  case .complete(let records): return .known(records)
  case .degraded(_, let reason): return .unknown(reason: reason)
  case .absent(let reason): return .absent(reason: reason)
  case .unknown(let reason): return .unknown(reason: reason)
  case .unreadable(let reason, let code):
    return .unreadable(reason: reason, errorCode: code)
  case .failed(let reason, let code): return .failed(reason: reason, errorCode: code)
  }
}

private func scanGlobalFacts(_ snapshot: RuntimeGlobalFactSnapshot) -> GlobalScanFacts {
  GlobalScanFacts(
    vm: scanGlobalFact(snapshot.vm),
    swap: scanGlobalFact(snapshot.swap),
    apfsSnapshots: scanAPFSSnapshotFact(snapshot.apfsSnapshotsByVolume)
  )
}

private func scanGlobalFact<Value: Equatable & Sendable>(
  _ observation: Observation<Value>
) -> GlobalFact<Value> {
  switch observation {
  case .known(let value): return .known(value)
  case .absent(let reason): return .unavailable(reason: "absent: \(reason)")
  case .unknown(let reason): return .unavailable(reason: "unknown: \(reason)")
  case .unreadable(let reason, _): return .unavailable(reason: "unreadable: \(reason)")
  case .failed(let reason, _): return .unavailable(reason: "failed: \(reason)")
  }
}

private func scanAPFSSnapshotFact(
  _ observations: [String: Observation<[Data]>]
) -> GlobalFact<[String]> {
  var names: [String] = []
  for volumeID in observations.keys.sorted() {
    guard case .known(let volumeNames) = observations[volumeID] else {
      let reason: String
      switch observations[volumeID]! {
      case .known: preconditionFailure("handled above")
      case .absent(let detail): reason = "absent: \(detail)"
      case .unknown(let detail): reason = "unknown: \(detail)"
      case .unreadable(let detail, _): reason = "unreadable: \(detail)"
      case .failed(let detail, _): reason = "failed: \(detail)"
      }
      return .unavailable(reason: "volume \(volumeID): \(reason)")
    }
    names.append(contentsOf: volumeNames.map { "\(volumeID):\(rawDisplay($0))" })
  }
  return .known(names.sorted())
}

private func rawDisplay(_ bytes: Data) -> String {
  bytes.map { String(format: "%02x", $0) }.joined()
}
