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
  let handle: DirectoryHandle
  let path: RawPath
  let identity: ObjectIdentity
  let names: [RawPathComponent]
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
  private var globalCoverage = Coverage.complete
  private var forcedCoverage = Coverage.complete

  public init(
    filesystem: any ScanFilesystem,
    scope: ResolvedScanScope,
    clock: any ScanClock = SystemScanClock(),
    nodeSink: any ScanNodeSink = DiscardingScanNodeSink(),
    processActivity: Observation<[ProcessActivityRecord]> = .unknown(
      reason: "process activity snapshot not supplied")
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
      profileID: scope.profile.rawValue,
      resolverVersion: scope.resolverVersion
    )
  }

  deinit { closeOpenDirectories() }

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
    closeOpenDirectories()
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
          filesystem.close(root.directory)
          completedRoots.append(
            RootScanResult(
              binding: root.binding,
              providerBoundary: root.providerBoundary,
              aggregateBytes: .lowerBoundZero,
              coverage: Coverage(completeness: .partial, reasons: [.providerMetadataOnly]),
              entriesObserved: 0,
              directoriesClosed: 0
            )
          )
          continue
        }
        if scope.budget.maximumEntriesPerRoot == 0 {
          filesystem.close(root.directory)
          completedRoots.append(
            RootScanResult(
              binding: root.binding,
              providerBoundary: root.providerBoundary,
              aggregateBytes: .lowerBoundZero,
              coverage: Coverage(completeness: .partial, reasons: [.notRequestedByProfile]),
              entriesObserved: 0,
              directoriesClosed: 0
            )
          )
          continue
        }
        switch filesystem.enumerate(root.directory) {
        case .known(let names):
          stack = [
            DirectoryFrame(
              handle: root.directory,
              path: RawPath(rootID: root.binding.rootID),
              identity: root.binding.identity,
              names: names.sorted(),
              depth: 0,
              inheritedProviderBoundary: root.providerBoundary.isProviderManaged,
              rootProviderBoundary: root.providerBoundary,
              providerEvidence: .unknown(
                reason: "root provider evidence is not retained by binding"),
              filesystemTimes: .unknown,
              accessPolicy: .unknown(reason: "root access policy is not retained by binding"),
              nextIndex: 0,
              aggregate: .lowerBoundZero,
              storageTopology: .unknown,
              coverage: root.providerBoundary.isProviderManaged
                ? Coverage(completeness: .partial, reasons: [.providerMetadataOnly]) : .complete
            )
          ]
          return true
        case let failure:
          filesystem.close(root.directory)
          rootFailures.append((request.rootID, failure.erasingValue()))
          globalCoverage = globalCoverage.merging(
            Coverage(completeness: .partial, reasons: [coverageReason(failure)])
          )
        }
      case let failure:
        rootFailures.append((request.rootID, failure.erasingValue()))
        globalCoverage = globalCoverage.merging(
          Coverage(completeness: .partial, reasons: [coverageReason(failure)])
        )
      }
    }
    return false
  }

  private func processNextEntry() {
    let frameIndex = stack.count - 1
    let name = stack[frameIndex].names[stack[frameIndex].nextIndex]
    stack[frameIndex].nextIndex += 1
    let path = stack[frameIndex].path.appending(name)
    let parentHandle = stack[frameIndex].handle
    let inheritedProvider = stack[frameIndex].inheritedProviderBoundary
    entriesInCurrentRoot += 1
    totalEntries += 1

    switch filesystem.inspect(
      parent: parentHandle, name: name, inheritedProviderBoundary: inheritedProvider)
    {
    case .known(let item):
      let providerBoundary: ProviderBoundary =
        inheritedProvider && !item.providerBoundary.isProviderManaged
        ? .metadataOnly(reason: "inherited provider boundary") : item.providerBoundary
      var nodeCoverage = Coverage.complete
      if item.identity.device != stack[0].identity.device {
        nodeCoverage = Coverage(completeness: .partial, reasons: [.mountBoundary])
      }
      if providerBoundary.isProviderManaged {
        nodeCoverage = nodeCoverage.merging(
          Coverage(completeness: .partial, reasons: [.providerMetadataOnly])
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
      switch filesystem.openDirectory(
        parent: parentHandle, name: name, expectedIdentity: item.identity)
      {
      case .known(let handle):
        switch filesystem.enumerate(handle) {
        case .known(let names):
          stack.append(
            DirectoryFrame(
              handle: handle,
              path: path,
              identity: item.identity,
              names: names.sorted(),
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
              coverage: nodeCoverage
            )
          )
        case let failure:
          filesystem.close(handle)
          stack[frameIndex].aggregate = .adding(stack[frameIndex].aggregate, item.bytes)
          stack[frameIndex].coverage = stack[frameIndex].coverage.merging(
            Coverage(completeness: .partial, reasons: [coverageReason(failure)])
          )
        }
      case let failure:
        stack[frameIndex].aggregate = .adding(stack[frameIndex].aggregate, item.bytes)
        stack[frameIndex].coverage = stack[frameIndex].coverage.merging(
          Coverage(completeness: .partial, reasons: [coverageReason(failure)])
        )
      }
    case let failure:
      let coverage = Coverage(completeness: .partial, reasons: [coverageReason(failure)])
      let node = ScannedNode(
        path: path,
        identity: failure.erasingValue(),
        bytes: .unknown,
        coverage: coverage,
        providerBoundary: inheritedProvider
          ? .metadataOnly(reason: "inherited provider boundary") : .localOrUnindicated
      )
      nodeSink.receive(.observed(node))
      retain(node)
      stack[frameIndex].coverage = stack[frameIndex].coverage.merging(coverage)
    }
  }

  private func closeTopDirectory() {
    let frame = stack.removeLast()
    filesystem.close(frame.handle)
    directoriesInCurrentRoot += 1
    totalDirectories += 1
    if stack.isEmpty {
      let binding = bindingForCompletedRoot(frame)
      completedRoots.append(
        RootScanResult(
          binding: binding,
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
        identity: .known(frame.identity),
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

  private func bindingForCompletedRoot(_ frame: DirectoryFrame) -> RootBinding {
    let root = scope.roots.first { $0.rootID == frame.path.rootID }!
    return RootBinding(
      resolverVersion: scope.resolverVersion,
      rootID: root.rootID,
      rawAbsolutePath: root.rawAbsolutePath,
      identity: frame.identity
    )
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
    closeOpenDirectories()
    completedRoots.append(
      RootScanResult(
        binding: bindingForCompletedRoot(rootFrame),
        providerBoundary: rootFrame.rootProviderBoundary,
        aggregateBytes: aggregate,
        coverage: coverage,
        entriesObserved: entriesInCurrentRoot,
        directoriesClosed: directoriesInCurrentRoot
      )
    )
  }

  private func closeOpenDirectories() {
    for frame in stack.reversed() { filesystem.close(frame.handle) }
    stack.removeAll()
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

  private func coverageReason<Value>(_ observation: Observation<Value>) -> CoverageReason {
    switch observation {
    case .known: .collectorFailed
    case .absent: .missing
    case .unknown: .collectorFailed
    case .unreadable: .permissionDenied
    case .failed(_, let code) where code == ESTALE: .identityMismatch
    case .failed(_, let code) where code == EAGAIN: .accessPolicyChanged
    case .failed: .collectorFailed
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
