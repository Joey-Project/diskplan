import DiskplanMacOS
import DiskplanPolicy
import DiskplanScan
import Foundation

package struct RuntimeFreshPolicyRequest: Equatable, Sendable {
  package let roots: [ScanRootRequest]
  package let terminalNamespaces: [RuntimeFreshTerminalNamespace]
  package let maximumDurationNanoseconds: UInt64

  package init(
    roots: [ScanRootRequest],
    terminalNamespaces: [RuntimeFreshTerminalNamespace],
    maximumDurationNanoseconds: UInt64 = 30_000_000_000
  ) {
    self.roots = roots
    self.terminalNamespaces = terminalNamespaces
    self.maximumDurationNanoseconds = maximumDurationNanoseconds
  }
}

package struct RuntimeFreshTerminalNamespace: Equatable, Sendable {
  package let rawRoot: RawRootPath
  package let targetPath: RawTargetPath

  package init(rawRoot: RawRootPath, targetPath: RawTargetPath) {
    self.rawRoot = rawRoot
    self.targetPath = targetPath
  }
}

package enum RuntimeFreshPolicyAuthorityError: Error, Equatable {
  case unsupportedCaptureKind
  case scanDidNotTerminate
}

package struct RuntimeFreshPolicyCapture: Sendable {
  package let result: RuntimePolicyAuthorityResult
  package let duplicateSurvivorsPreserved: DiskplanPolicy.Observation<Bool>
  package let terminalNamespacesExclusive: DiskplanPolicy.Observation<Bool>
}

/// The production fresh-policy boundary. It owns the concrete Darwin scanner and policy freezer;
/// callers cannot inject a snapshot-producing closure or supply immutable evidence to relabel.
package final class RuntimeFreshPolicyAuthority: @unchecked Sendable {
  private let policy: NoMaterializationPolicy

  package init(policy: NoMaterializationPolicy) {
    self.policy = policy
  }

  package func collect(
    authorization: RuntimeEvidenceCaptureAuthorization,
    request: RuntimeFreshPolicyRequest
  ) async throws -> RuntimeFreshPolicyCapture {
    guard authorization.kind == .wholePlan || authorization.kind == .jitUnit else {
      throw RuntimeFreshPolicyAuthorityError.unsupportedCaptureKind
    }
    let permit = try authorization.beginFreshPolicyCollection()
    do {
      let scope = try ResolvedScanScope(
        resolverVersion: ScanRootResolver.version,
        profile: .standard,
        roots: request.roots,
        budget: StructuralBudget(
          maximumEntriesPerRoot: 2_000_000,
          maximumDepth: 64
        ),
        maximumDurationNanoseconds: request.maximumDurationNanoseconds
      )
      let evidence = BoundedAuthorityEvidenceAccumulator(
        budget: .accepted(for: scope)
      )
      let collectorBundle = ProductionScanCollectorBundle()
      let processDeadline = saturatedRuntimeDeadline(
        now: DispatchTime.now().uptimeNanoseconds,
        duration: min(request.maximumDurationNanoseconds, 10_000_000_000)
      )
      let runtimeCollectors = await collectorBundle.collect(
        processDeadlineNanoseconds: processDeadline,
        volumes: []
      )
      let resolvedTerminals = request.terminalNamespaces.compactMap {
        terminal -> ResolvedRuntimeFreshTerminal? in
        guard
          let root = request.roots.first(where: {
            $0.rawAbsolutePath == terminal.rawRoot.absoluteBytes
          })
        else { return nil }
        return ResolvedRuntimeFreshTerminal(
          binding: terminal,
          path: RawPath(
            rootID: root.rootID,
            components: terminal.targetPath.components.map(RawPathComponent.init)
          )
        )
      }
      let invariantAccumulator = RuntimeFreshInvariantAccumulator(
        terminals: resolvedTerminals,
        allTerminalsResolved: resolvedTerminals.count == request.terminalNamespaces.count,
        maximumEntries: saturatedRuntimeEntryLimit(
          perRoot: scope.budget.maximumEntriesPerRoot,
          rootCount: scope.roots.count
        )
      )
      let scanner = DeterministicScanner(
        filesystem: DarwinScanFilesystem(policy: policy),
        scope: scope,
        nodeSink: RuntimeFreshEvidenceTeeSink(
          policyEvidence: evidence,
          invariants: invariantAccumulator
        ),
        processActivity: runtimeProcessObservation(runtimeCollectors.processActivity),
        globalFacts: GlobalScanFacts(
          vm: runtimeGlobalFact(runtimeCollectors.globalFacts.vm, collector: "runtime.vm"),
          swap: runtimeGlobalFact(
            runtimeCollectors.globalFacts.swap,
            collector: "runtime.swap"
          ),
          apfsSnapshots: .unavailable(
            reason: "fresh runtime scan has no borrowed volume-root snapshot descriptors"
          )
        ),
        collectorConfiguration: collectorBundle.collectorConfiguration(
          processDeadlineNanoseconds: processDeadline
        )
      )
      try permit.checkActive()
      var result = scanner.advance(maximumEntries: 512)
      while result.state == .ready || result.state == .scanning {
        try permit.checkActive()
        result = scanner.advance(maximumEntries: 512)
      }
      guard result.state == .complete || result.state == .partial else {
        throw RuntimeFreshPolicyAuthorityError.scanDidNotTerminate
      }
      let evidenceSnapshot = evidence.snapshot()
      let authorityResult = try RuntimePolicyAuthority().makePlan(
        scanResult: result,
        evidence: evidenceSnapshot
      )
      let invariantProof = runtimeInvariantProof(
        scanResult: result,
        evidence: evidenceSnapshot,
        authorityResult: authorityResult,
        accumulator: invariantAccumulator
      )
      let capture = RuntimeFreshPolicyCapture(
        result: authorityResult,
        duplicateSurvivorsPreserved: invariantProof.duplicateSurvivorsPreserved,
        terminalNamespacesExclusive: invariantProof.terminalNamespacesExclusive
      )
      try permit.complete()
      return capture
    } catch {
      permit.abort()
      throw error
    }
  }
}

struct ResolvedRuntimeFreshTerminal: Sendable {
  let binding: RuntimeFreshTerminalNamespace
  let path: RawPath
}

private struct RuntimeFreshEvidenceTeeSink: ScanNodeSink {
  let policyEvidence: BoundedAuthorityEvidenceAccumulator
  let invariants: RuntimeFreshInvariantAccumulator

  func receive(_ event: ScanNodeEvent) {
    policyEvidence.receive(event)
    invariants.receive(event)
  }
}

private struct RuntimeFreshFileRecord {
  var paths = Set<RawPath>()
  var linkCounts: [DiskplanScan.Observation<UInt32>] = []
  var mayShareBlocks: [DiskplanScan.Observation<Bool>] = []
  var cloneIDs: [DiskplanScan.Observation<UInt64>] = []
  var cloneRefcounts: [DiskplanScan.Observation<UInt32>] = []
  var providerLocal = true
}

private struct RuntimeFreshCloneKey: Hashable {
  let device: Int64
  let cloneID: UInt64
}

private enum RuntimeFreshTerminalSlotKey: Hashable {
  case root(DiskplanScan.ObjectIdentity)
  case child(parent: DiskplanScan.ObjectIdentity, leaf: Data)
}

/// Scan-event invariant mechanism. Kept separate from RuntimeFreshPolicyAuthority so mechanism
/// tests can supply explicit evidence without injecting a provider into the production collector.
final class RuntimeFreshInvariantAccumulator: ScanNodeSink, @unchecked Sendable {
  private let terminals: [ResolvedRuntimeFreshTerminal]
  private let allTerminalsResolved: Bool
  private let maximumEntries: UInt64
  private var seenPaths = Set<RawPath>()
  private var identitiesByPath: [RawPath: DiskplanScan.ObjectIdentity] = [:]
  private var fileRecords: [DiskplanScan.ObjectIdentity: RuntimeFreshFileRecord] = [:]
  private var directoryPaths: [DiskplanScan.ObjectIdentity: Set<RawPath>] = [:]
  private var identitiesAtTerminal: [RawPath: DiskplanScan.ObjectIdentity] = [:]
  private var incomplete = false

  init(
    terminals: [ResolvedRuntimeFreshTerminal],
    allTerminalsResolved: Bool,
    maximumEntries: UInt64
  ) {
    self.terminals = terminals
    self.allTerminalsResolved = allTerminalsResolved
    self.maximumEntries = maximumEntries
  }

  func receive(_ event: ScanNodeEvent) {
    let node: ScannedNode
    switch event {
    case .observed(let observed):
      if observed.identity.value?.objectType == .directory { return }
      node = observed
    case .directoryClosed(let closed):
      node = closed
    }
    guard seenPaths.insert(node.path).inserted else { return }
    guard UInt64(seenPaths.count) <= maximumEntries else {
      incomplete = true
      return
    }
    guard case .known(let identity) = node.identity else {
      if terminals.contains(where: { runtimePathContains($0.path, node.path) }) {
        incomplete = true
      }
      return
    }
    identitiesByPath[node.path] = identity
    if terminals.contains(where: { $0.path == node.path }) {
      identitiesAtTerminal[node.path] = identity
    }
    switch identity.objectType {
    case .regular:
      var record = fileRecords[identity] ?? RuntimeFreshFileRecord()
      record.paths.insert(node.path)
      record.linkCounts.append(node.storageTopology.linkCount)
      record.mayShareBlocks.append(node.storageTopology.mayShareBlocks)
      record.cloneIDs.append(node.storageTopology.cloneID)
      record.cloneRefcounts.append(node.storageTopology.cloneRefcount)
      record.providerLocal = record.providerLocal && node.providerBoundary == .localOrUnindicated
      fileRecords[identity] = record
    case .directory:
      directoryPaths[identity, default: []].insert(node.path)
    case .symbolicLink, .other:
      break
    }
  }

  func proof(
    snapshots: [FrozenEvidenceSnapshot]
  ) -> (
    duplicateSurvivorsPreserved: DiskplanPolicy.Observation<Bool>,
    terminalNamespacesExclusive: DiskplanPolicy.Observation<Bool>
  ) {
    guard allTerminalsResolved, !terminals.isEmpty, !incomplete,
      identitiesAtTerminal.count == terminals.count
    else {
      return (.unknown(.incompleteCoverage), .unknown(.incompleteCoverage))
    }
    return (
      duplicateSurvivorsPreserved: duplicateOwnerProof(),
      terminalNamespacesExclusive: terminalProof(snapshots: snapshots)
    )
  }

  private func duplicateOwnerProof() -> DiskplanPolicy.Observation<Bool> {
    let terminalFileIdentities = Set(
      fileRecords.compactMap { identity, record in
        record.paths.contains(where: { path in
          terminals.contains(where: { runtimePathContains($0.path, path) })
        }) ? identity : nil
      }
    )
    var relevantFileIdentities = terminalFileIdentities
    var relevantCloneKeys = Set<RuntimeFreshCloneKey>()
    var uncertain = false

    for identity in terminalFileIdentities {
      guard let record = fileRecords[identity] else { return .unknown(.incompleteCoverage) }
      switch exactKnown(record.mayShareBlocks) {
      case .known(false): break
      case .known(true):
        switch exactKnown(record.cloneIDs) {
        case .known(let cloneID):
          relevantCloneKeys.insert(
            RuntimeFreshCloneKey(device: identity.device, cloneID: cloneID)
          )
        case .notApplicable, .unknown: uncertain = true
        case .mismatch: return .known(false)
        }
      case .notApplicable, .unknown: uncertain = true
      case .mismatch: return .known(false)
      }
    }
    for (identity, record) in fileRecords {
      if case .known(let cloneID) = exactKnown(record.cloneIDs),
        relevantCloneKeys.contains(
          RuntimeFreshCloneKey(device: identity.device, cloneID: cloneID)
        )
      {
        relevantFileIdentities.insert(identity)
      }
    }

    for identity in relevantFileIdentities {
      guard let record = fileRecords[identity], record.providerLocal else {
        uncertain = true
        continue
      }
      switch exactKnown(record.linkCounts) {
      case .known(let count):
        if Int(count) != record.paths.count { return .known(false) }
      case .notApplicable, .unknown: uncertain = true
      case .mismatch: return .known(false)
      }
    }
    for cloneKey in relevantCloneKeys {
      let members = fileRecords.filter {
        if $0.key.device == cloneKey.device,
          case .known(let observed) = exactKnown($0.value.cloneIDs)
        {
          return observed == cloneKey.cloneID
        }
        return false
      }
      switch exactKnown(members.values.flatMap(\.cloneRefcounts)) {
      case .known(let count):
        if Int(count) != members.count { return .known(false) }
      case .notApplicable, .unknown: uncertain = true
      case .mismatch: return .known(false)
      }
    }
    return uncertain ? .unknown(.incompleteCoverage) : .known(true)
  }

  private func terminalProof(
    snapshots: [FrozenEvidenceSnapshot]
  ) -> DiskplanPolicy.Observation<Bool> {
    var slots = Set<RuntimeFreshTerminalSlotKey>()
    var ancestryByTerminal: [RawPath: Set<DiskplanScan.ObjectIdentity>] = [:]
    for terminal in terminals {
      guard let identity = identitiesAtTerminal[terminal.path] else {
        return .unknown(.incompleteCoverage)
      }
      guard let slot = terminalSlot(for: terminal.path) else {
        return .unknown(.incompleteCoverage)
      }
      guard slots.insert(slot).inserted else { return .known(false) }
      ancestryByTerminal[terminal.path] = terminalAncestorIdentities(for: terminal.path)
      if identity.objectType == .directory,
        directoryPaths[identity]?.count != 1
      {
        return .known(false)
      }
      for snapshot in snapshots {
        let binding = snapshot.namespaceBinding
        guard
          binding.rawRoot != terminal.binding.rawRoot
            || binding.targetPath != terminal.binding.targetPath
        else { continue }
        if runtimeAbsolutePathsOverlap(
          lhsRoot: binding.rawRoot,
          lhsTarget: binding.targetPath,
          rhsRoot: terminal.binding.rawRoot,
          rhsTarget: terminal.binding.targetPath
        ) {
          return .known(false)
        }
      }
    }
    for leftIndex in terminals.indices {
      let left = terminals[leftIndex]
      guard let leftIdentity = identitiesAtTerminal[left.path] else {
        return .unknown(.incompleteCoverage)
      }
      for rightIndex in terminals.indices where rightIndex > leftIndex {
        let right = terminals[rightIndex]
        guard let rightIdentity = identitiesAtTerminal[right.path] else {
          return .unknown(.incompleteCoverage)
        }
        if runtimePathsOverlap(left.path, right.path)
          || (leftIdentity.objectType == .directory
            && ancestryByTerminal[right.path, default: []].contains(leftIdentity))
          || (rightIdentity.objectType == .directory
            && ancestryByTerminal[left.path, default: []].contains(rightIdentity))
        {
          return .known(false)
        }
      }
    }
    return .known(true)
  }

  private func terminalSlot(for path: RawPath) -> RuntimeFreshTerminalSlotKey? {
    guard let leaf = path.components.last else {
      return identitiesByPath[path].map(RuntimeFreshTerminalSlotKey.root)
    }
    let parent = RawPath(rootID: path.rootID, components: Array(path.components.dropLast()))
    guard let parentIdentity = identitiesByPath[parent] else { return nil }
    return .child(parent: parentIdentity, leaf: leaf.bytes)
  }

  private func terminalAncestorIdentities(
    for path: RawPath
  ) -> Set<DiskplanScan.ObjectIdentity> {
    Set(
      (0..<path.components.count).compactMap { count in
        identitiesByPath[
          RawPath(rootID: path.rootID, components: Array(path.components.prefix(count)))
        ]
      })
  }
}

private enum ExactKnown<Value> {
  case known(Value)
  case notApplicable
  case unknown
  case mismatch
}

private func exactKnown<Value: Equatable & Sendable>(
  _ observations: [DiskplanScan.Observation<Value>]
) -> ExactKnown<Value> {
  guard !observations.isEmpty else { return .notApplicable }
  var value: Value?
  for observation in observations {
    guard case .known(let current) = observation else { return .unknown }
    if let value, value != current { return .mismatch }
    value = current
  }
  return value.map(ExactKnown.known) ?? .notApplicable
}

private func runtimeInvariantProof(
  scanResult: ScanResult,
  evidence: AuthorityEvidenceSnapshot,
  authorityResult: RuntimePolicyAuthorityResult,
  accumulator: RuntimeFreshInvariantAccumulator
) -> (
  duplicateSurvivorsPreserved: DiskplanPolicy.Observation<Bool>,
  terminalNamespacesExclusive: DiskplanPolicy.Observation<Bool>
) {
  guard scanResult.state == .complete,
    !evidence.retention.isIncomplete,
    evidence.issues.isEmpty,
    !evidence.topologyCoverageIncomplete
  else {
    return (.unknown(.incompleteCoverage), .unknown(.incompleteCoverage))
  }
  return accumulator.proof(snapshots: authorityResult.plan.evidenceSnapshots)
}

private func runtimePathContains(_ ancestor: RawPath, _ descendant: RawPath) -> Bool {
  ancestor.rootID == descendant.rootID
    && descendant.components.starts(with: ancestor.components)
}

private func runtimePathsOverlap(_ lhs: RawPath, _ rhs: RawPath) -> Bool {
  runtimePathContains(lhs, rhs) || runtimePathContains(rhs, lhs)
}

private func runtimeAbsolutePathsOverlap(
  lhsRoot: RawRootPath,
  lhsTarget: RawTargetPath,
  rhsRoot: RawRootPath,
  rhsTarget: RawTargetPath
) -> Bool {
  let lhs = runtimeAbsoluteComponents(root: lhsRoot, target: lhsTarget)
  let rhs = runtimeAbsoluteComponents(root: rhsRoot, target: rhsTarget)
  let sharedCount = min(lhs.count, rhs.count)
  return Array(lhs.prefix(sharedCount)) == Array(rhs.prefix(sharedCount))
}

private func runtimeAbsoluteComponents(
  root: RawRootPath,
  target: RawTargetPath
) -> [Data] {
  let rootComponents: [Data]
  if root.absoluteBytes == Data("/".utf8) {
    rootComponents = []
  } else {
    rootComponents = root.absoluteBytes.dropFirst().split(separator: 47).map { Data($0) }
  }
  return rootComponents + target.components
}

private func saturatedRuntimeEntryLimit(perRoot: UInt64, rootCount: Int) -> UInt64 {
  let result = perRoot.multipliedReportingOverflow(by: UInt64(max(1, rootCount)))
  return result.overflow ? UInt64.max : result.partialValue
}

private func saturatedRuntimeDeadline(now: UInt64, duration: UInt64) -> UInt64 {
  let result = now.addingReportingOverflow(duration)
  return result.overflow ? UInt64.max : result.partialValue
}

private func runtimeProcessObservation(
  _ observation: ProcessActivityObservation
) -> DiskplanScan.Observation<[ProcessActivityRecord]> {
  switch observation {
  case .complete(let records): return .known(records)
  case .degraded(_, let reason): return .unknown(reason: reason)
  case .absent(let reason): return .absent(reason: reason)
  case .unknown(let reason): return .unknown(reason: reason)
  case .unreadable(let reason, let code):
    return .unreadable(reason: reason, errorCode: code)
  case .failed(let reason, let code):
    return .failed(reason: reason, errorCode: code)
  }
}

private func runtimeGlobalFact<Value: Equatable & Sendable>(
  _ observation: DiskplanScan.Observation<Value>,
  collector: String
) -> GlobalFact<Value> {
  switch observation {
  case .known(let value): return .known(value)
  case .absent(let reason), .unknown(let reason):
    return .unavailable(reason: "\(collector): \(reason)")
  case .unreadable(let reason, let code), .failed(let reason, let code):
    let errorCode = code.map(String.init) ?? "none"
    return .unavailable(reason: "\(collector): \(reason) (errno=\(errorCode))")
  }
}
