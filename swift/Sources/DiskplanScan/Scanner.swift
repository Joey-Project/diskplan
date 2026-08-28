import Foundation

public protocol ScanClock: Sendable {
  func wallClockNow() -> Date
  func monotonicNowNanoseconds() -> UInt64
}

public struct SystemScanClock: ScanClock {
  public init() {}
  public func wallClockNow() -> Date { Date() }
  public func monotonicNowNanoseconds() -> UInt64 { DispatchTime.now().uptimeNanoseconds }
}

public enum ScanMachineState: String, Equatable, Sendable {
  case ready
  case scanning
  case complete
  case partial
  case cancelled
}

public struct ScanResult: Equatable, Sendable {
  public let reference: ScanReference
  public let state: ScanMachineState
  public let roots: [RootScanResult]
  public let rootFailures: [(rootID: String, observation: Observation<String>)]
  public let progress: ScanProgress
  public let coverage: Coverage
  public let globalFacts: GlobalScanFacts
  public let processActivity: Observation<[ProcessActivityRecord]>

  public static func == (lhs: Self, rhs: Self) -> Bool {
    lhs.reference == rhs.reference && lhs.state == rhs.state && lhs.roots == rhs.roots
      && lhs.rootFailures.elementsEqual(rhs.rootFailures, by: { $0.0 == $1.0 && $0.1 == $1.1 })
      && lhs.progress == rhs.progress && lhs.coverage == rhs.coverage
      && lhs.globalFacts == rhs.globalFacts
      && lhs.processActivity == rhs.processActivity
  }
}

private struct DirectoryFrame {
  let directory: BoundDirectory
  let rootBinding: RootBinding
  let path: RawPath
  let identity: ObjectIdentity
  let names: [RawPathComponent]
  let retainedNameBytes: UInt64
  let depth: Int
  let inheritedProviderBoundary: Bool
  let rootProviderBoundary: ProviderBoundary
  let providerEvidence: Observation<ProviderScanEvidence>
  let filesystemTimes: FilesystemTimeEvidence
  let accessPolicy: Observation<AccessPolicyEvidence>
  var nextIndex: Int
  var aggregate: ItemByteEvidence
  let storageTopology: StorageTopologyEvidence
  var coverage: Coverage
}

public final class DeterministicScanner {
  private let filesystem: any ScanFilesystem
  private let scope: ResolvedScanScope
  private let clock: any ScanClock
  private let nodeSink: any ScanNodeSink
  private let processActivity: Observation<[ProcessActivityRecord]>
  private let reference: ScanReference
  private var state: ScanMachineState = .ready
  private var nextRootIndex = 0
  private var stack: [DirectoryFrame] = []
  private var completedRoots: [RootScanResult] = []
  private var rootFailures: [(rootID: String, observation: Observation<String>)] = []
  private var entriesInCurrentRoot: UInt64 = 0
  private var directoriesInCurrentRoot: UInt64 = 0
  private var totalEntries: UInt64 = 0
  private var totalDirectories: UInt64 = 0
  private var retained: [ScannedNode] = []
  private var pendingNameBytes: UInt64 = 0
  private var globalCoverage = Coverage.complete
  private var forcedCoverage = Coverage.complete

  public init(
    filesystem: any ScanFilesystem,
    scope: ResolvedScanScope,
    clock: any ScanClock = SystemScanClock(),
    nodeSink: any ScanNodeSink = DiscardingScanNodeSink(),
    processActivity: Observation<[ProcessActivityRecord]> = .unknown(
      reason: "process activity snapshot not supplied"),
    collectorConfiguration: ScanCollectorConfiguration = .precollectedOrUnavailable
  ) {
    self.filesystem = filesystem
    self.scope = scope
    self.clock = clock
    self.nodeSink = nodeSink
    self.processActivity = processActivity
    let wallClock = clock.wallClockNow()
    let monotonic = clock.monotonicNowNanoseconds()
    reference = ScanReference(
      wallClock: wallClock,
      monotonicNanoseconds: monotonic,
      resolvedScope: scope,
      collectorConfiguration: collectorConfiguration
    )
  }

  deinit { _ = closeOpenDirectories() }

  public func advance(maximumEntries: Int = 512) -> ScanResult {
    precondition(maximumEntries > 0)
    guard state != .complete && state != .partial && state != .cancelled else { return result() }
    state = .scanning
    var processed = 0
    while processed < maximumEntries {
      if durationExceeded() {
        forcedCoverage = forcedCoverage.merging(
          Coverage(completeness: .partial, reasons: [.timedOut])
        )
        finalizeOpenRoot()
        state = .partial
        break
      }
      if stack.isEmpty {
        guard beginNextRoot() else {
          state = hasPartialCoverage ? .partial : .complete
          break
        }
        if stack.isEmpty { continue }
      }
      guard !stack.isEmpty else { continue }
      if stack[stack.count - 1].nextIndex >= stack[stack.count - 1].names.count {
        closeTopDirectory()
        continue
      }
      if entriesInCurrentRoot >= scope.budget.maximumEntriesPerRoot {
        stack[0].coverage = stack[0].coverage.merging(
          Coverage(completeness: .partial, reasons: [.budgetExhausted])
        )
        finalizeOpenRoot()
        continue
      }
      processNextEntry()
      processed += 1
    }
    return result()
  }

  public func finalizePartial(reason: CoverageReason = .userFinalizedPartial) -> ScanResult {
    guard state != .complete && state != .cancelled else { return result() }
    forcedCoverage = forcedCoverage.merging(Coverage(completeness: .partial, reasons: [reason]))
    finalizeOpenRoot()
    while nextRootIndex < scope.roots.count {
      let root = scope.roots[nextRootIndex]
      rootFailures.append(
        (root.rootID, .unknown(reason: "root not scanned before partial finalization")))
      nextRootIndex += 1
    }
    state = .partial
    return result()
  }

  public func cancel() -> ScanResult {
    guard state != .complete && state != .cancelled else { return result() }
    forcedCoverage = forcedCoverage.merging(Coverage(completeness: .partial, reasons: [.cancelled]))
    forcedCoverage = forcedCoverage.merging(closeOpenDirectories())
    state = .cancelled
    return result()
  }

  public func snapshot() -> ScanResult { result() }

  private func beginNextRoot() -> Bool {
    while nextRootIndex < scope.roots.count {
      let request = scope.roots[nextRootIndex]
      nextRootIndex += 1
      entriesInCurrentRoot = 0
      directoriesInCurrentRoot = 0
      switch filesystem.bindRoot(request, resolverVersion: scope.resolverVersion) {
      case .known(let root):
        if root.providerBoundary.preventsNormalDescent {
          let closeCoverage = coverage(for: filesystem.close(root.directory))
          completedRoots.append(
            RootScanResult(
              binding: root.binding,
              providerBoundary: root.providerBoundary,
              aggregateBytes: .lowerBoundZero,
              coverage: Coverage(
                completeness: .partial,
                reasons: coverageReasons(for: root.providerBoundary)
              ).merging(closeCoverage),
              entriesObserved: 0,
              directoriesClosed: 0
            )
          )
          continue
        }
        if scope.budget.maximumEntriesPerRoot == 0 {
          let closeCoverage = coverage(for: filesystem.close(root.directory))
          completedRoots.append(
            RootScanResult(
              binding: root.binding,
              providerBoundary: root.providerBoundary,
              aggregateBytes: .lowerBoundZero,
              coverage: Coverage(
                completeness: .partial,
                reasons: [.notRequestedByProfile]
              ).merging(closeCoverage),
              entriesObserved: 0,
              directoriesClosed: 0
            )
          )
          continue
        }
        switch filesystem.enumerate(
          root.directory.handle,
          limits: enumerationLimits()
        ) {
        case .known(let enumeration):
          pendingNameBytes = addingSaturated(
            pendingNameBytes,
            enumeration.retainedNameBytes
          )
          stack = [
            DirectoryFrame(
              directory: root.directory,
              rootBinding: root.binding,
              path: RawPath(rootID: root.binding.rootID),
              identity: root.binding.identity,
              names: enumeration.names,
              retainedNameBytes: enumeration.retainedNameBytes,
              depth: 0,
              inheritedProviderBoundary: root.providerBoundary.isProviderManaged,
              rootProviderBoundary: root.providerBoundary,
              providerEvidence: root.providerEvidence,
              filesystemTimes: root.filesystemTimes,
              accessPolicy: root.accessPolicy,
              nextIndex: 0,
              aggregate: .lowerBoundZero,
              storageTopology: .unknown,
              coverage: enumeration.coverage.merging(
                Coverage(
                  completeness: .complete,
                  reasons: coverageReasons(for: root.providerBoundary)
                )
              )
            )
          ]
          return true
        case let failure:
          let closeCoverage = coverage(for: filesystem.close(root.directory))
          rootFailures.append((request.rootID, failure.erasingValue()))
          globalCoverage = globalCoverage.merging(
            Coverage(completeness: .partial, reasons: coverageReasons(failure))
              .merging(closeCoverage)
          )
        }
      case let failure:
        rootFailures.append((request.rootID, failure.erasingValue()))
        globalCoverage = globalCoverage.merging(
          Coverage(
            completeness: .partial,
            reasons: coverageReasons(failure) + [.providerStateUnverified]
          )
        )
      }
    }
    return false
  }

  private func processNextEntry() {
    let frameIndex = stack.count - 1
    let name = stack[frameIndex].names[stack[frameIndex].nextIndex]
    stack[frameIndex].nextIndex += 1
    pendingNameBytes -= UInt64(name.bytes.count)
    let path = stack[frameIndex].path.appending(name)
    let parentHandle = stack[frameIndex].directory.handle
    let inheritedProvider = stack[frameIndex].inheritedProviderBoundary
    entriesInCurrentRoot += 1
    totalEntries += 1

    switch filesystem.inspect(
      parent: parentHandle,
      name: name,
      inheritedProviderBoundary: inheritedProvider,
      requiresAuthoritativeProviderEvidence: false
    )
    {
    case .known(let item):
      let providerBoundary: ProviderBoundary =
        inheritedProvider && !item.providerBoundary.isProviderManaged
        ? .metadataOnly(reason: "inherited provider boundary") : item.providerBoundary
      var nodeCoverage = Coverage.complete
      if item.identity.device != stack[0].identity.device {
        nodeCoverage = Coverage(completeness: .partial, reasons: [.mountBoundary])
      }
      let providerCoverageReasons = coverageReasons(for: providerBoundary)
      if !providerCoverageReasons.isEmpty {
        nodeCoverage = nodeCoverage.merging(
          Coverage(completeness: .partial, reasons: providerCoverageReasons)
        )
      }
      let retainedCoverage =
        item.identity.objectType == .directory
        ? nodeCoverage.merging(
          Coverage(completeness: .partial, reasons: [.subtreeIncomplete])) : nodeCoverage
      let node = ScannedNode(
        path: path,
        identity: .known(item.identity),
        bytes: item.bytes,
        storageTopology: item.storageTopology,
        filesystemTimes: item.filesystemTimes,
        accessPolicy: item.accessPolicy,
        coverage: retainedCoverage,
        providerBoundary: providerBoundary,
        providerEvidence: item.providerEvidence
      )
      nodeSink.receive(.observed(node))
      retain(node)
      stack[frameIndex].coverage = stack[frameIndex].coverage.merging(nodeCoverage)
      guard item.identity.objectType == .directory,
        item.identity.device == stack[0].identity.device,
        stack[frameIndex].depth < scope.budget.maximumDepth
      else {
        if item.identity.objectType == .directory
          && stack[frameIndex].depth >= scope.budget.maximumDepth
        {
          stack[frameIndex].coverage = stack[frameIndex].coverage.merging(
            Coverage(completeness: .partial, reasons: [.budgetExhausted])
          )
        }
        stack[frameIndex].aggregate = .adding(stack[frameIndex].aggregate, item.bytes)
        return
      }
      guard !providerBoundary.preventsNormalDescent else {
        stack[frameIndex].aggregate = .adding(stack[frameIndex].aggregate, item.bytes)
        return
      }
      guard let expectedAccessPolicy = item.accessPolicy.value else {
        stack[frameIndex].aggregate = .adding(stack[frameIndex].aggregate, item.bytes)
        stack[frameIndex].coverage = stack[frameIndex].coverage.merging(
          Coverage(completeness: .partial, reasons: [.collectorFailed])
        )
        return
      }
      switch filesystem.openDirectory(
        parent: parentHandle,
        name: name,
        expectedIdentity: item.identity,
        expectedAccessPolicy: expectedAccessPolicy
      )
      {
      case .known(let directory):
        switch filesystem.enumerate(
          directory.handle,
          limits: enumerationLimits()
        ) {
        case .known(let enumeration):
          pendingNameBytes = addingSaturated(
            pendingNameBytes,
            enumeration.retainedNameBytes
          )
          stack.append(
            DirectoryFrame(
              directory: directory,
              rootBinding: stack[frameIndex].rootBinding,
              path: path,
              identity: item.identity,
              names: enumeration.names,
              retainedNameBytes: enumeration.retainedNameBytes,
              depth: stack[frameIndex].depth + 1,
              inheritedProviderBoundary: inheritedProvider
                || providerBoundary.isProviderManaged,
              rootProviderBoundary: stack[frameIndex].rootProviderBoundary,
              providerEvidence: item.providerEvidence,
              filesystemTimes: item.filesystemTimes,
              accessPolicy: item.accessPolicy,
              nextIndex: 0,
              aggregate: item.bytes,
              storageTopology: item.storageTopology,
              coverage: nodeCoverage.merging(enumeration.coverage)
            )
          )
        case let failure:
          let closeCoverage = coverage(for: filesystem.close(directory))
          stack[frameIndex].aggregate = .adding(stack[frameIndex].aggregate, item.bytes)
          stack[frameIndex].coverage = stack[frameIndex].coverage.merging(
            Coverage(completeness: .partial, reasons: coverageReasons(failure))
              .merging(closeCoverage)
          )
        }
      case let failure:
        stack[frameIndex].aggregate = .adding(stack[frameIndex].aggregate, item.bytes)
        stack[frameIndex].coverage = stack[frameIndex].coverage.merging(
          Coverage(completeness: .partial, reasons: coverageReasons(failure))
        )
      }
    case let failure:
      let coverage = Coverage(
        completeness: .partial,
        reasons: coverageReasons(failure) + [.providerStateUnverified]
      )
      let node = ScannedNode(
        path: path,
        identity: failure.erasingValue(),
        bytes: .unknown,
        coverage: coverage,
        providerBoundary: inheritedProvider
          ? .metadataOnly(reason: "inherited provider boundary")
          : .unverified(reason: "item inspection did not establish provider ownership")
      )
      nodeSink.receive(.observed(node))
      retain(node)
      stack[frameIndex].coverage = stack[frameIndex].coverage.merging(coverage)
    }
  }

  private func closeTopDirectory() {
    var frame = stack.removeLast()
    let closeObservation = filesystem.close(frame.directory)
    let closeCoverage = coverage(for: closeObservation)
    frame.coverage = frame.coverage.merging(closeCoverage)
    directoriesInCurrentRoot += 1
    totalDirectories += 1
    if stack.isEmpty {
      completedRoots.append(
        RootScanResult(
          binding: frame.rootBinding,
          providerBoundary: frame.rootProviderBoundary,
          aggregateBytes: frame.aggregate,
          coverage: frame.coverage.merging(forcedCoverage),
          entriesObserved: entriesInCurrentRoot,
          directoriesClosed: directoriesInCurrentRoot
        )
      )
    } else {
      let parent = stack.count - 1
      stack[parent].aggregate = .adding(stack[parent].aggregate, frame.aggregate)
      stack[parent].coverage = stack[parent].coverage.merging(frame.coverage)
      let node = ScannedNode(
        path: frame.path,
        identity: closeObservation.value == nil
          ? closeObservation.erasingValue() : .known(frame.identity),
        bytes: frame.aggregate,
        storageTopology: frame.storageTopology,
        filesystemTimes: frame.filesystemTimes,
        accessPolicy: frame.accessPolicy,
        coverage: frame.coverage,
        providerBoundary: frame.inheritedProviderBoundary
          ? .metadataOnly(reason: "inherited provider boundary") : .localOrUnindicated,
        providerEvidence: frame.providerEvidence
      )
      nodeSink.receive(.directoryClosed(node))
      retain(node)
    }
  }

  private func finalizeOpenRoot() {
    guard !stack.isEmpty else { return }
    let rootFrame = stack[0]
    var aggregate = rootFrame.aggregate
    var coverage = rootFrame.coverage.merging(forcedCoverage)
    for frame in stack.dropFirst() {
      aggregate = .adding(aggregate, frame.aggregate)
      coverage = coverage.merging(frame.coverage)
    }
    coverage = coverage.merging(closeOpenDirectories())
    completedRoots.append(
      RootScanResult(
        binding: rootFrame.rootBinding,
        providerBoundary: rootFrame.rootProviderBoundary,
        aggregateBytes: aggregate,
        coverage: coverage,
        entriesObserved: entriesInCurrentRoot,
        directoriesClosed: directoriesInCurrentRoot
      )
    )
  }

  private func closeOpenDirectories() -> Coverage {
    var closeCoverage = Coverage.complete
    while let frame = stack.popLast() {
      closeCoverage = closeCoverage.merging(coverage(for: filesystem.close(frame.directory)))
    }
    pendingNameBytes = 0
    return closeCoverage
  }

  private func retain(_ node: ScannedNode) {
    guard scope.budget.retainedNodeCount > 0 else { return }
    if let existing = retained.firstIndex(where: { $0.path == node.path }) {
      retained.remove(at: existing)
    } else if retained.count == scope.budget.retainedNodeCount,
      let worst = retained.last, !retentionPrecedes(node, worst)
    {
      return
    }
    var lower = 0
    var upper = retained.count
    while lower < upper {
      let middle = lower + (upper - lower) / 2
      if retentionPrecedes(node, retained[middle]) { upper = middle } else { lower = middle + 1 }
    }
    retained.insert(node, at: lower)
    if retained.count > scope.budget.retainedNodeCount { retained.removeLast() }
  }

  private func retentionPrecedes(_ lhs: ScannedNode, _ rhs: ScannedNode) -> Bool {
    let left = lhs.bytes.immediatePrivateReclaim.conservativeLowerBound
    let right = rhs.bytes.immediatePrivateReclaim.conservativeLowerBound
    if left != right { return left > right }
    return lhs.path < rhs.path
  }

  private func durationExceeded() -> Bool {
    guard let limit = scope.maximumDurationNanoseconds else { return false }
    let now = clock.monotonicNowNanoseconds()
    return now >= reference.monotonicNanoseconds && now - reference.monotonicNanoseconds >= limit
  }

  private func enumerationLimits() -> EnumerationLimits {
    let remainingEntries =
      scope.budget.maximumEntriesPerRoot > entriesInCurrentRoot
      ? scope.budget.maximumEntriesPerRoot - entriesInCurrentRoot : 0
    let remainingNameBytes =
      scope.budget.maximumPendingNameBytes > pendingNameBytes
      ? scope.budget.maximumPendingNameBytes - pendingNameBytes : 0
    return EnumerationLimits(
      maximumNames: min(scope.budget.maximumEntriesPerDirectory, remainingEntries),
      maximumNameBytes: remainingNameBytes,
      deadlineMonotonicNanoseconds: scanDeadlineMonotonicNanoseconds
    )
  }

  private var scanDeadlineMonotonicNanoseconds: UInt64? {
    guard let duration = scope.maximumDurationNanoseconds else { return nil }
    let (deadline, overflow) = reference.monotonicNanoseconds.addingReportingOverflow(duration)
    return overflow ? UInt64.max : deadline
  }

  private func coverage(
    for observation: Observation<DirectoryCloseEvidence>
  ) -> Coverage {
    guard observation.value == nil else { return .complete }
    return Coverage(completeness: .partial, reasons: coverageReasons(observation))
  }

  private func addingSaturated(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
    let (sum, overflow) = lhs.addingReportingOverflow(rhs)
    return overflow ? UInt64.max : sum
  }

  private func coverageReasons<Value>(_ observation: Observation<Value>) -> [CoverageReason] {
    switch observation {
    case .known: [.collectorFailed]
    case .absent: [.missing]
    case .unknown: [.collectorFailed]
    case .unreadable: [.permissionDenied]
    case .failed(_, let code) where code == ESTALE: [.identityMismatch]
    case .failed(_, let code) where code == EAGAIN: [.accessPolicyChanged]
    case .failed(_, let code) where code == EBUSY:
      [.providerStateUnverified, .unstableDuringScan]
    case .failed(_, let code) where code == ETIMEDOUT:
      [.providerStateUnverified, .timedOut]
    case .failed(_, let code) where code == ENODATA: [.providerStateUnverified]
    case .failed: [.collectorFailed]
    }
  }

  private func coverageReasons(for boundary: ProviderBoundary) -> [CoverageReason] {
    switch boundary {
    case .localOrUnindicated: []
    case .metadataOnly: [.providerMetadataOnly]
    case .rejected, .unverified: [.providerStateUnverified]
    }
  }

  private func result() -> ScanResult {
    let partialRoots = UInt64(completedRoots.filter { $0.coverage.completeness == .partial }.count)
    let completeRoots = UInt64(completedRoots.count) - partialRoots
    let allCoverage = completedRoots.reduce(globalCoverage.merging(forcedCoverage)) {
      $0.merging($1.coverage)
    }
    return ScanResult(
      reference: reference,
      state: state,
      roots: completedRoots,
      rootFailures: rootFailures,
      progress: ScanProgress(
        entriesObserved: totalEntries,
        directoriesClosed: totalDirectories,
        rootsComplete: completeRoots,
        rootsPartial: partialRoots + UInt64(rootFailures.count),
        retainedNodes: retained
      ),
      coverage: allCoverage,
      globalFacts: .publicEvidenceUnavailable,
      processActivity: processActivity
    )
  }

  private var hasPartialCoverage: Bool {
    forcedCoverage.completeness == .partial || globalCoverage.completeness == .partial
      || !rootFailures.isEmpty
      || completedRoots.contains { $0.coverage.completeness == .partial }
  }
}
