import CryptoKit
import DiskplanPolicy
import DiskplanScan
import Foundation

public enum ScanCorpusIssue: Equatable, Sendable {
  case conflictingObservation(RawPath)
  case directoryCloseWithoutObservation(RawPath)
  case conflictingDirectoryClose(RawPath)
  case nonDirectoryClose(RawPath)
}

public enum RuntimeCandidateKind: String, CaseIterable, Equatable, Sendable {
  case codexTemporary = "codex_temporary"
  case gitLinkedWorktree = "git_linked_worktree"
  case versionedArtifact = "versioned_artifact"
  case buildOutput = "build_output"
  case cache = "cache"
  case temporary = "temporary"
  case providerReportOnly = "provider_report_only"
}

public enum RuntimeRecognizerAuthority: String, Equatable, Sendable {
  case structural
  case nameOnlyTypeHint
}

public struct AuthorityRetentionBudget: Equatable, Sendable {
  /// Authority-owned lifecycle estimate, not merely the accumulator payload.
  public static let maximumAcceptedBytes = 768 * 1_024 * 1_024
  // Retained evidence is capped at one eighth below. Six additional bytes are
  // reserved for each retained byte's concurrent indexes, frozen models, and
  // bounded projections; the final eighth remains arithmetic/allocation headroom.
  fileprivate static let planningAmplificationFactor = 6

  public let maximumCandidateSummaries: Int
  public let maximumSharedObjectKeys: Int
  public let maximumOwnerReferences: Int
  public let maximumEstimatedBytes: Int

  public init(
    maximumCandidateSummaries: Int,
    maximumSharedObjectKeys: Int,
    maximumOwnerReferences: Int,
    maximumEstimatedBytes: Int
  ) {
    precondition(maximumCandidateSummaries >= 0)
    precondition(maximumSharedObjectKeys >= 0)
    precondition(maximumOwnerReferences >= 0)
    precondition((0...Self.maximumAcceptedBytes).contains(maximumEstimatedBytes))
    self.maximumCandidateSummaries = maximumCandidateSummaries
    self.maximumSharedObjectKeys = maximumSharedObjectKeys
    self.maximumOwnerReferences = maximumOwnerReferences
    self.maximumEstimatedBytes = maximumEstimatedBytes
  }

  public static func accepted(for scope: ResolvedScanScope) -> Self {
    let rootCount = UInt64(max(1, scope.roots.count))
    let (entryCapacity, overflow) = scope.budget.maximumEntriesPerRoot
      .multipliedReportingOverflow(by: rootCount)
    let boundedEntryCapacity = overflow ? UInt64.max : entryCapacity
    return Self(
      maximumCandidateSummaries: Int(min(250_000, boundedEntryCapacity)),
      maximumSharedObjectKeys: Int(min(2_000_000, boundedEntryCapacity)),
      maximumOwnerReferences: Int(min(5_000_000, boundedEntryCapacity)),
      maximumEstimatedBytes: Self.maximumAcceptedBytes
    )
  }

  fileprivate var maximumRetainedEvidenceBytes: Int {
    maximumEstimatedBytes / 8
  }

  fileprivate var maximumPlanningBytes: Int {
    maximumEstimatedBytes - maximumRetainedEvidenceBytes
  }
}

public struct AuthorityRetentionStatus: Equatable, Sendable {
  public let candidateSummariesOmitted: UInt64
  public let sharedObjectKeysOmitted: UInt64
  public let ownerReferencesOmitted: UInt64
  public let corpusIssuesOmitted: UInt64
  public let finalizationInputsOmitted: UInt64
  public let estimatedRetainedBytes: Int
  public let finalizedInputBytes: Int
  public let estimatedPlanningBytes: Int
  public let maximumPlanningBytes: Int
  public let planningBudgetExceeded: Bool

  public var isIncomplete: Bool {
    candidateSummariesOmitted > 0 || sharedObjectKeysOmitted > 0 || ownerReferencesOmitted > 0
      || corpusIssuesOmitted > 0 || finalizationInputsOmitted > 0 || planningBudgetExceeded
  }
}

public struct AuthorityCandidateRecord: Equatable, Sendable {
  public let node: ScannedNode
  public let ancestors: [ScannedNode]
  public let isClosed: Bool
  public let kind: RuntimeCandidateKind
  public let recognizerAuthority: RuntimeRecognizerAuthority
}

public struct AuthorityEvidenceSnapshot: Equatable, Sendable {
  public let candidatesByPath: [RawPath: AuthorityCandidateRecord]
  public let sharedFileObservationsByPath: [RawPath: ScannedNode]
  public let sharedFileAncestorsByPath: [RawPath: [ScannedNode]]
  public let issues: [ScanCorpusIssue]
  public let retention: AuthorityRetentionStatus
  public let topologyCoverageIncomplete: Bool

  fileprivate init(
    candidatesByPath: [RawPath: AuthorityCandidateRecord],
    sharedFileObservationsByPath: [RawPath: ScannedNode],
    sharedFileAncestorsByPath: [RawPath: [ScannedNode]],
    issues: [ScanCorpusIssue],
    retention: AuthorityRetentionStatus,
    topologyCoverageIncomplete: Bool
  ) {
    self.candidatesByPath = candidatesByPath
    self.sharedFileObservationsByPath = sharedFileObservationsByPath
    self.sharedFileAncestorsByPath = sharedFileAncestorsByPath
    self.issues = issues.sorted(by: scanCorpusIssuePrecedes)
    self.retention = retention
    self.topologyCoverageIncomplete = topologyCoverageIncomplete
  }

  fileprivate func bindingFinalizedInputs(
    bytes: Int,
    omitted: UInt64
  ) -> Self {
    let planningBytes = saturatedSum(retention.estimatedPlanningBytes, bytes)
    return Self(
      candidatesByPath: candidatesByPath,
      sharedFileObservationsByPath: sharedFileObservationsByPath,
      sharedFileAncestorsByPath: sharedFileAncestorsByPath,
      issues: issues,
      retention: AuthorityRetentionStatus(
        candidateSummariesOmitted: retention.candidateSummariesOmitted,
        sharedObjectKeysOmitted: retention.sharedObjectKeysOmitted,
        ownerReferencesOmitted: retention.ownerReferencesOmitted,
        corpusIssuesOmitted: retention.corpusIssuesOmitted,
        finalizationInputsOmitted: omitted,
        estimatedRetainedBytes: retention.estimatedRetainedBytes,
        finalizedInputBytes: bytes,
        estimatedPlanningBytes: planningBytes,
        maximumPlanningBytes: retention.maximumPlanningBytes,
        planningBudgetExceeded: planningBytes > retention.maximumPlanningBytes
      ),
      topologyCoverageIncomplete: topologyCoverageIncomplete || omitted > 0
    )
  }
}

private struct AuthorityScanResult: Sendable {
  let reference: ScanReference
  let state: ScanMachineState
  let roots: [RootScanResult]
  let rootFailures: [(rootID: String, observation: DiskplanScan.Observation<String>)]
  let coverage: Coverage
  let globalFacts: GlobalScanFacts
  let processActivity: DiskplanScan.Observation<[ProcessActivityRecord]>

  init(
    _ result: ScanResult,
    globalFacts: GlobalScanFacts? = nil,
    processActivity: DiskplanScan.Observation<[ProcessActivityRecord]>? = nil
  ) {
    reference = result.reference
    state = result.state
    roots = result.roots
    rootFailures = result.rootFailures
    coverage = result.coverage
    self.globalFacts = globalFacts ?? result.globalFacts
    self.processActivity = processActivity ?? result.processActivity
  }
}

/// Builds bounded policy indexes directly from the complete scanner event stream.
public final class BoundedAuthorityEvidenceAccumulator: ScanNodeSink, @unchecked Sendable {
  private let lock = NSLock()
  private let budget: AuthorityRetentionBudget
  private let namespaceByteBudget: Int
  private let sharedKeyByteBudget: Int
  private let ownerByteBudget: Int
  private var openDirectories: [RawPath: ScannedNode] = [:]
  private var openDirectoryBytes = 0
  private var candidates: [RawPath: AuthorityCandidateRecord] = [:]
  private var candidateHeap: [RawPath] = []
  private var candidateHeapPositions: [RawPath: Int] = [:]
  private var candidateBytes = 0
  private var sharedFileObservations: [RawPath: ScannedNode] = [:]
  private var sharedFileAncestors: [RawPath: [ScannedNode]] = [:]
  private var sharedObjectKeys = Set<String>()
  private var sharedKeyBytes = 0
  private var ownerBytes = 0
  private var retainedIssues: [ScanCorpusIssue] = []
  private var issueBytes = 0
  private var candidateSummariesOmitted: UInt64 = 0
  private var sharedObjectKeysOmitted: UInt64 = 0
  private var ownerReferencesOmitted: UInt64 = 0
  private var corpusIssuesOmitted: UInt64 = 0
  private var topologyCoverageIncomplete = false

  public init(budget: AuthorityRetentionBudget) {
    self.budget = budget
    let retainedBudget = budget.maximumRetainedEvidenceBytes
    namespaceByteBudget = retainedBudget / 3
    sharedKeyByteBudget = retainedBudget / 6
    ownerByteBudget = retainedBudget - namespaceByteBudget - sharedKeyByteBudget
  }

  public convenience init() {
    self.init(
      budget: AuthorityRetentionBudget(
        maximumCandidateSummaries: 250_000,
        maximumSharedObjectKeys: 2_000_000,
        maximumOwnerReferences: 5_000_000,
        maximumEstimatedBytes: AuthorityRetentionBudget.maximumAcceptedBytes
      )
    )
  }

  public convenience init(scope: ResolvedScanScope) {
    self.init(budget: .accepted(for: scope))
  }

  public func receive(_ event: ScanNodeEvent) {
    lock.lock()
    defer { lock.unlock() }
    switch event {
    case .observed(let node):
      if node.identity.value == nil { topologyCoverageIncomplete = true }
      if node.identity.value?.objectType == .directory || node.identity.value == nil {
        retainOpenDirectory(node)
        if let kind = nameOnlyKind(for: node) {
          upsertCandidate(
            node: node,
            isClosed: false,
            kind: kind,
            authority: .nameOnlyTypeHint
          )
        }
      } else if node.identity.value?.objectType == .regular {
        retainSharedObservationIfNeeded(node)
        if asciiLowercased(node.path.components.last?.bytes ?? Data()) == Data(".git".utf8) {
          let parentPath = RawPath(
            rootID: node.path.rootID,
            components: Array(node.path.components.dropLast())
          )
          if let parent = openDirectories[parentPath] ?? candidates[parentPath]?.node {
            upsertCandidate(
              node: parent,
              isClosed: candidates[parentPath]?.isClosed ?? false,
              kind: .gitLinkedWorktree,
              authority: .structural
            )
          }
        }
      }
    case .directoryClosed(let node):
      guard node.identity.value?.objectType == .directory else {
        retainIssue(.nonDirectoryClose(node.path))
        return
      }
      guard let previous = openDirectories[node.path] else {
        retainIssue(.directoryCloseWithoutObservation(node.path))
        if let kind = nameOnlyKind(for: node) {
          upsertCandidate(
            node: node,
            isClosed: false,
            kind: kind,
            authority: .nameOnlyTypeHint
          )
        }
        return
      }
      guard let observedIdentity = previous.identity.value,
        let closedIdentity = node.identity.value,
        observedIdentity == closedIdentity
      else {
        retainIssue(.conflictingDirectoryClose(node.path))
        removeOpenDirectory(node.path)
        return
      }
      let retainedCandidate = candidates[node.path]
      removeOpenDirectory(node.path)
      if let retained = retainedCandidate {
        upsertCandidate(
          node: node,
          isClosed: true,
          kind: retained.kind,
          authority: retained.recognizerAuthority
        )
      } else if let kind = nameOnlyKind(for: node) {
        upsertCandidate(
          node: node,
          isClosed: true,
          kind: kind,
          authority: .nameOnlyTypeHint
        )
      }
    }
  }

  public func snapshot() -> AuthorityEvidenceSnapshot {
    lock.lock()
    defer { lock.unlock() }
    let retainedBytes = saturatedSum(
      candidateBytes, openDirectoryBytes, sharedKeyBytes, ownerBytes, issueBytes)
    let planningBytes = saturatedMultiply(
      retainedBytes,
      by: AuthorityRetentionBudget.planningAmplificationFactor
    )
    return AuthorityEvidenceSnapshot(
      candidatesByPath: candidates,
      sharedFileObservationsByPath: sharedFileObservations,
      sharedFileAncestorsByPath: sharedFileAncestors,
      issues: retainedIssues,
      retention: AuthorityRetentionStatus(
        candidateSummariesOmitted: candidateSummariesOmitted,
        sharedObjectKeysOmitted: sharedObjectKeysOmitted,
        ownerReferencesOmitted: ownerReferencesOmitted,
        corpusIssuesOmitted: corpusIssuesOmitted,
        finalizationInputsOmitted: 0,
        estimatedRetainedBytes: retainedBytes,
        finalizedInputBytes: 0,
        estimatedPlanningBytes: planningBytes,
        maximumPlanningBytes: budget.maximumPlanningBytes,
        planningBudgetExceeded: planningBytes > budget.maximumPlanningBytes
      ),
      topologyCoverageIncomplete: topologyCoverageIncomplete
    )
  }

  private func retainOpenDirectory(_ node: ScannedNode) {
    if let previous = openDirectories[node.path] {
      if previous != node { retainIssue(.conflictingObservation(node.path)) }
      return
    }
    let estimate = estimatedNodeBytes(node)
    guard
      fitsWithinLimit(
        openDirectoryBytes, candidateBytes, issueBytes, estimate, limit: namespaceByteBudget)
    else {
      candidateSummariesOmitted &+= 1
      topologyCoverageIncomplete = true
      return
    }
    openDirectories[node.path] = node
    openDirectoryBytes += estimate
  }

  private func removeOpenDirectory(_ path: RawPath) {
    guard let removed = openDirectories.removeValue(forKey: path) else { return }
    openDirectoryBytes -= estimatedNodeBytes(removed)
  }

  private func upsertCandidate(
    node: ScannedNode,
    isClosed: Bool,
    kind: RuntimeCandidateKind,
    authority: RuntimeRecognizerAuthority
  ) {
    let existing = candidates[node.path]
    let effectiveKind =
      existing?.recognizerAuthority == .structural ? existing?.kind ?? kind : kind
    let effectiveAuthority: RuntimeRecognizerAuthority =
      existing?.recognizerAuthority == .structural ? .structural : authority
    let ancestors = ancestorNodes(for: node.path)
    let record = AuthorityCandidateRecord(
      node: node,
      ancestors: ancestors,
      isClosed: isClosed,
      kind: effectiveKind,
      recognizerAuthority: effectiveAuthority
    )
    retainCandidate(record, replacing: existing)
  }

  private func ancestorNodes(for path: RawPath) -> [ScannedNode] {
    (1..<path.components.count).compactMap { count in
      let ancestorPath = RawPath(
        rootID: path.rootID,
        components: Array(path.components.prefix(count))
      )
      return openDirectories[ancestorPath] ?? candidates[ancestorPath]?.node
    }
  }

  private func retainCandidate(
    _ record: AuthorityCandidateRecord,
    replacing existing: AuthorityCandidateRecord?
  ) {
    let estimate = estimatedCandidateBytes(record)
    guard budget.maximumCandidateSummaries > 0, estimate <= namespaceByteBudget else {
      recordFinalCandidateOmission(record)
      topologyCoverageIncomplete = true
      return
    }
    guard
      let evictions = plannedCandidateEvictions(
        for: record,
        replacing: existing?.node.path,
        replacementBytes: existing.map(estimatedCandidateBytes) ?? 0
      )
    else {
      recordFinalCandidateOmission(record)
      topologyCoverageIncomplete = true
      return
    }
    let closedEvictions = evictions.reduce(into: 0) { count, path in
      if candidates[path]?.isClosed == true { count += 1 }
    }
    if let existing { removeCandidate(existing.node.path) }
    for path in evictions { removeCandidate(path) }
    candidateSummariesOmitted &+= UInt64(closedEvictions)
    if !evictions.isEmpty { topologyCoverageIncomplete = true }
    candidates[record.node.path] = record
    candidateBytes += estimate
    heapInsert(record.node.path)
  }

  private func recordFinalCandidateOmission(_ record: AuthorityCandidateRecord) {
    if record.isClosed { candidateSummariesOmitted &+= 1 }
  }

  private func plannedCandidateEvictions(
    for record: AuthorityCandidateRecord,
    replacing existingPath: RawPath?,
    replacementBytes: Int
  ) -> [RawPath]? {
    let estimate = estimatedCandidateBytes(record)
    var projectedCount = candidates.count - (existingPath == nil ? 0 : 1)
    var projectedBytes = candidateBytes - replacementBytes
    var evictions: [RawPath] = []
    var frontier: [Int] = candidateHeap.isEmpty ? [] : [0]

    while !candidateAdmissionFits(
      existingCount: projectedCount,
      existingBytes: projectedBytes,
      addingBytes: estimate
    ) {
      guard let heapIndex = frontierPopWorst(&frontier) else { return nil }
      let left = heapIndex * 2 + 1
      let right = left + 1
      if left < candidateHeap.count { frontierInsert(left, into: &frontier) }
      if right < candidateHeap.count { frontierInsert(right, into: &frontier) }
      let path = candidateHeap[heapIndex]
      if path == existingPath { continue }
      guard let victim = candidates[path], candidateRetentionPrecedes(record, victim) else {
        return nil
      }
      evictions.append(path)
      projectedCount -= 1
      projectedBytes -= estimatedCandidateBytes(victim)
    }
    return evictions
  }

  private func candidateAdmissionFits(
    existingCount: Int,
    existingBytes: Int,
    addingBytes: Int
  ) -> Bool {
    let (newCount, countOverflow) = existingCount.addingReportingOverflow(1)
    guard !countOverflow, newCount <= budget.maximumCandidateSummaries else { return false }
    return fitsWithinLimit(
      existingBytes, openDirectoryBytes, issueBytes, addingBytes, limit: namespaceByteBudget)
  }

  private func frontierInsert(_ heapIndex: Int, into frontier: inout [Int]) {
    frontier.append(heapIndex)
    var index = frontier.count - 1
    while index > 0 {
      let parent = (index - 1) / 2
      guard frontierIndexIsWorse(frontier[index], than: frontier[parent]) else { return }
      frontier.swapAt(index, parent)
      index = parent
    }
  }

  private func frontierPopWorst(_ frontier: inout [Int]) -> Int? {
    guard !frontier.isEmpty else { return nil }
    let worst = frontier[0]
    let last = frontier.removeLast()
    if !frontier.isEmpty {
      frontier[0] = last
      var index = 0
      while true {
        let left = index * 2 + 1
        guard left < frontier.count else { break }
        let right = left + 1
        var worse = left
        if right < frontier.count,
          frontierIndexIsWorse(frontier[right], than: frontier[left])
        {
          worse = right
        }
        guard frontierIndexIsWorse(frontier[worse], than: frontier[index]) else { break }
        frontier.swapAt(index, worse)
        index = worse
      }
    }
    return worst
  }

  private func frontierIndexIsWorse(_ lhs: Int, than rhs: Int) -> Bool {
    heapPathIsWorse(candidateHeap[lhs], than: candidateHeap[rhs])
  }

  private func removeCandidate(_ path: RawPath) {
    guard let record = candidates.removeValue(forKey: path),
      let position = candidateHeapPositions.removeValue(forKey: path)
    else { return }
    candidateBytes -= estimatedCandidateBytes(record)
    let last = candidateHeap.removeLast()
    if position < candidateHeap.count {
      candidateHeap[position] = last
      candidateHeapPositions[last] = position
      heapSiftUp(from: position)
      heapSiftDown(from: candidateHeapPositions[last] ?? position)
    }
  }

  private func heapInsert(_ path: RawPath) {
    candidateHeapPositions[path] = candidateHeap.count
    candidateHeap.append(path)
    heapSiftUp(from: candidateHeap.count - 1)
  }

  private func heapSiftUp(from start: Int) {
    var index = start
    while index > 0 {
      let parent = (index - 1) / 2
      guard heapPathIsWorse(candidateHeap[index], than: candidateHeap[parent]) else { return }
      heapSwap(index, parent)
      index = parent
    }
  }

  private func heapSiftDown(from start: Int) {
    var index = start
    while true {
      let left = index * 2 + 1
      guard left < candidateHeap.count else { return }
      let right = left + 1
      var worse = left
      if right < candidateHeap.count,
        heapPathIsWorse(candidateHeap[right], than: candidateHeap[left])
      {
        worse = right
      }
      guard heapPathIsWorse(candidateHeap[worse], than: candidateHeap[index]) else { return }
      heapSwap(index, worse)
      index = worse
    }
  }

  private func heapSwap(_ lhs: Int, _ rhs: Int) {
    candidateHeap.swapAt(lhs, rhs)
    candidateHeapPositions[candidateHeap[lhs]] = lhs
    candidateHeapPositions[candidateHeap[rhs]] = rhs
  }

  private func heapPathIsWorse(_ lhs: RawPath, than rhs: RawPath) -> Bool {
    guard let left = candidates[lhs], let right = candidates[rhs] else { return false }
    return candidateRetentionPrecedes(right, left)
  }

  private func retainSharedObservationIfNeeded(_ node: ScannedNode) {
    let explicitlyNonShared: Bool
    if case .known(1) = node.storageTopology.linkCount,
      case .known(false) = node.storageTopology.mayShareBlocks,
      case .absent = node.storageTopology.cloneID,
      case .absent = node.storageTopology.cloneRefcount
    {
      explicitlyNonShared = true
    } else {
      explicitlyNonShared = false
    }
    guard !explicitlyNonShared else { return }
    guard let identity = node.identity.value else {
      topologyCoverageIncomplete = true
      return
    }
    let objectKey = fileObjectID(identity)
    var newKeys = [objectKey]
    if let cloneID = node.storageTopology.cloneID.value {
      newKeys.append(cloneGroupID(device: identity.device, cloneID: cloneID))
    }
    let unseenKeys = newKeys.filter { !sharedObjectKeys.contains($0) }
    let unseenKeyBytes = unseenKeys.reduce(0) {
      saturatedSum($0, 96, $1.utf8.count)
    }
    let (projectedKeyCount, keyCountOverflow) = sharedObjectKeys.count.addingReportingOverflow(
      unseenKeys.count)
    guard !keyCountOverflow, projectedKeyCount <= budget.maximumSharedObjectKeys,
      fitsWithinLimit(sharedKeyBytes, unseenKeyBytes, limit: sharedKeyByteBudget)
    else {
      sharedObjectKeysOmitted &+= UInt64(max(1, unseenKeys.count))
      topologyCoverageIncomplete = true
      return
    }
    let ancestors = ancestorNodes(for: node.path)
    if let previous = sharedFileObservations[node.path] {
      if previous != node || sharedFileAncestors[node.path] != ancestors {
        retainIssue(.conflictingObservation(node.path))
      }
      return
    }
    let ownerEstimate = ancestors.reduce(estimatedNodeBytes(node)) {
      saturatedSum($0, estimatedNodeBytes($1))
    }
    guard sharedFileObservations.count < budget.maximumOwnerReferences,
      fitsWithinLimit(ownerBytes, ownerEstimate, limit: ownerByteBudget)
    else {
      ownerReferencesOmitted &+= 1
      topologyCoverageIncomplete = true
      return
    }
    for key in unseenKeys { sharedObjectKeys.insert(key) }
    sharedKeyBytes += unseenKeyBytes
    sharedFileObservations[node.path] = node
    sharedFileAncestors[node.path] = ancestors
    ownerBytes += ownerEstimate
  }

  private func retainIssue(_ issue: ScanCorpusIssue) {
    let estimate = estimatedIssueBytes(issue)
    guard retainedIssues.count < 1_024,
      fitsWithinLimit(
        candidateBytes, openDirectoryBytes, issueBytes, estimate, limit: namespaceByteBudget)
    else {
      corpusIssuesOmitted &+= 1
      topologyCoverageIncomplete = true
      return
    }
    retainedIssues.append(issue)
    issueBytes += estimate
  }
}

private func nameOnlyKind(for node: ScannedNode) -> RuntimeCandidateKind? {
  guard node.identity.value?.objectType == .directory,
    let leaf = node.path.components.last?.bytes
  else { return nil }
  let folded = asciiLowercased(leaf)
  if folded == Data(".codex-tmp".utf8) { return .codexTemporary }
  if isVersionComponent(folded),
    let parent = node.path.components.dropLast().last?.bytes,
    versionedArtifactParents.contains(asciiLowercased(parent))
  {
    return .versionedArtifact
  }
  if buildNames.contains(folded) { return .buildOutput }
  if cacheNames.contains(folded) { return .cache }
  if temporaryNames.contains(folded) { return .temporary }
  return nil
}

private func candidateRetentionPrecedes(
  _ lhs: AuthorityCandidateRecord,
  _ rhs: AuthorityCandidateRecord
) -> Bool {
  let lhsBytes = lhs.node.bytes.immediatePrivateReclaim.conservativeLowerBound
  let rhsBytes = rhs.node.bytes.immediatePrivateReclaim.conservativeLowerBound
  if lhsBytes != rhsBytes { return lhsBytes > rhsBytes }
  return lhs.node.path < rhs.node.path
}

private func estimatedNodeBytes(_ node: ScannedNode) -> Int {
  var estimate = saturatedSum(768, node.path.rootID.utf8.count)
  for component in node.path.components {
    estimate = saturatedSum(estimate, 32, component.bytes.count)
  }
  return estimate
}

private func estimatedCandidateBytes(_ record: AuthorityCandidateRecord) -> Int {
  var estimate = saturatedSum(512, estimatedNodeBytes(record.node))
  for ancestor in record.ancestors {
    estimate = saturatedSum(estimate, estimatedNodeBytes(ancestor))
  }
  return estimate
}

private func estimatedIssueBytes(_ issue: ScanCorpusIssue) -> Int {
  switch issue {
  case .conflictingObservation(let path), .directoryCloseWithoutObservation(let path),
    .conflictingDirectoryClose(let path), .nonDirectoryClose(let path):
    var estimate = saturatedSum(128, path.rootID.utf8.count)
    for component in path.components {
      estimate = saturatedSum(estimate, 32, component.bytes.count)
    }
    return estimate
  }
}

private func fitsWithinLimit(_ values: Int..., limit: Int) -> Bool {
  saturatedSum(values) <= limit
}

private func saturatedSum(_ values: Int...) -> Int {
  saturatedSum(values)
}

private func saturatedSum(_ values: [Int]) -> Int {
  var total = 0
  for value in values {
    guard value >= 0 else { return Int.max }
    let (sum, overflow) = total.addingReportingOverflow(value)
    if overflow { return Int.max }
    total = sum
  }
  return total
}

private func saturatedMultiply(_ value: Int, by multiplier: Int) -> Int {
  guard value >= 0, multiplier >= 0 else { return Int.max }
  let (product, overflow) = value.multipliedReportingOverflow(by: multiplier)
  return overflow ? Int.max : product
}

private func boundedAuthorityFinalization(
  result: ScanResult,
  evidence: AuthorityEvidenceSnapshot
) -> BoundedAuthorityFinalization {
  var view = AuthorityScanResult(result)
  var omitted: UInt64 = 0
  var sourceBytes = estimatedAuthorityFinalizedInputBytes(view)
  // The source estimate intentionally upper-bounds its canonical encoding.
  // Use it before allocating the one retained configuration artifact.
  var projectedBytes = authorityFinalizationPeakBytes(
    sourceBytes: sourceBytes,
    configurationBytes: sourceBytes
  )
  if !fitsWithinLimit(
    evidence.retention.estimatedPlanningBytes,
    projectedBytes,
    limit: evidence.retention.maximumPlanningBytes
  ) {
    view = AuthorityScanResult(
      result,
      processActivity: .unknown(reason: "authority finalization budget omitted process snapshot")
    )
    omitted &+= 1
    sourceBytes = estimatedAuthorityFinalizedInputBytes(view)
    projectedBytes = authorityFinalizationPeakBytes(
      sourceBytes: sourceBytes,
      configurationBytes: sourceBytes
    )
  }
  if !fitsWithinLimit(
    evidence.retention.estimatedPlanningBytes,
    projectedBytes,
    limit: evidence.retention.maximumPlanningBytes
  ) {
    view = AuthorityScanResult(
      result,
      globalFacts: .publicEvidenceUnavailable,
      processActivity: view.processActivity
    )
    omitted &+= 1
    sourceBytes = estimatedAuthorityFinalizedInputBytes(view)
    projectedBytes = authorityFinalizationPeakBytes(
      sourceBytes: sourceBytes,
      configurationBytes: sourceBytes
    )
  }
  let configuration = encodeAuthorityConfiguration(view)
  let bytes = authorityFinalizationPeakBytes(
    sourceBytes: sourceBytes,
    configurationBytes: configuration.count
  )
  return BoundedAuthorityFinalization(
    result: view,
    evidence: evidence.bindingFinalizedInputs(bytes: bytes, omitted: omitted),
    authorityConfiguration: configuration
  )
}

private struct BoundedAuthorityFinalization: Sendable {
  let result: AuthorityScanResult
  let evidence: AuthorityEvidenceSnapshot
  let authorityConfiguration: Data
}

/// Conservatively accounts for the retained source model plus one transient
/// sorting/index copy, and the canonical artifact plus one downstream COW copy.
func authorityFinalizationPeakBytes(
  sourceBytes: Int,
  configurationBytes: Int
) -> Int {
  saturatedSum(
    saturatedMultiply(sourceBytes, by: 2),
    saturatedMultiply(configurationBytes, by: 2)
  )
}

private func estimatedAuthorityFinalizedInputBytes(_ result: AuthorityScanResult) -> Int {
  var estimate = 4_096
  estimate = saturatedSum(
    estimate,
    256,
    result.reference.collectorConfiguration.processActivityCollectorID.utf8.count,
    result.reference.collectorConfiguration.globalFactCollectorIDs.reduce(0) {
      saturatedSum($0, 32, $1.utf8.count)
    }
  )
  for root in result.reference.resolvedScope.roots {
    estimate = saturatedSum(
      estimate,
      256,
      root.rootID.utf8.count,
      root.rawAbsolutePath.count
    )
  }
  for root in result.roots {
    estimate = saturatedSum(
      estimate,
      512,
      root.binding.rootID.utf8.count,
      root.binding.rawAbsolutePath.count,
      root.coverage.reasons.reduce(0) { saturatedSum($0, 64, $1.rawValue.utf8.count) }
    )
  }
  for failure in result.rootFailures {
    estimate = saturatedSum(
      estimate,
      256,
      failure.rootID.utf8.count,
      estimatedStringObservationBytes(failure.observation)
    )
  }
  estimate = saturatedSum(estimate, estimatedGlobalFactsBytes(result.globalFacts))
  estimate = saturatedSum(estimate, estimatedProcessActivityBytes(result.processActivity))
  return estimate
}

private func estimatedStringObservationBytes(
  _ observation: DiskplanScan.Observation<String>
) -> Int {
  switch observation {
  case .known(let value): return saturatedSum(128, value.utf8.count)
  case .absent(let reason), .unknown(let reason):
    return saturatedSum(128, reason.utf8.count)
  case .unreadable(let reason, _), .failed(let reason, _):
    return saturatedSum(160, reason.utf8.count)
  }
}

private func estimatedGlobalFactsBytes(_ facts: GlobalScanFacts) -> Int {
  func dictionaryBytes(_ fact: GlobalFact<[String: UInt64]>) -> Int {
    switch fact {
    case .known(let values):
      return values.reduce(256) { saturatedSum($0, 96, $1.key.utf8.count) }
    case .unavailable(let reason): return saturatedSum(128, reason.utf8.count)
    }
  }
  let snapshots: Int
  switch facts.apfsSnapshots {
  case .known(let values):
    snapshots = values.reduce(256) { saturatedSum($0, 96, $1.utf8.count) }
  case .unavailable(let reason): snapshots = saturatedSum(128, reason.utf8.count)
  }
  return saturatedSum(dictionaryBytes(facts.vm), dictionaryBytes(facts.swap), snapshots)
}

private func estimatedProcessActivityBytes(
  _ observation: DiskplanScan.Observation<[ProcessActivityRecord]>
) -> Int {
  switch observation {
  case .known(let records):
    return records.reduce(256) { estimate, record in
      saturatedSum(
        estimate,
        256,
        record.command?.utf8.count ?? 0,
        record.fileDescriptor?.utf8.count ?? 0,
        record.rawPath.count
      )
    }
  case .absent(let reason), .unknown(let reason):
    return saturatedSum(128, reason.utf8.count)
  case .unreadable(let reason, _), .failed(let reason, _):
    return saturatedSum(160, reason.utf8.count)
  }
}

private func cloneGroupID(device: Int64, cloneID: UInt64) -> String {
  "clone:device:\(device):id:\(cloneID)"
}

private struct PhysicalPathKey: Hashable {
  let components: [Data]
}

private struct RootAliasPathKey: Hashable {
  let rootIdentity: DiskplanScan.ObjectIdentity
  let relativeComponents: [Data]
}

private struct RuntimeRootPhysicalContext {
  let identity: DiskplanScan.ObjectIdentity
  let absoluteComponents: [Data]
}

private struct RuntimeCandidatePhysicalLocation {
  let candidateID: String
  let rootID: String
  let relativeComponents: [Data]
  let absoluteComponents: [Data]
  let rootIdentity: DiskplanScan.ObjectIdentity
}

private struct RuntimePhysicalCandidateIndexes {
  let rootsByID: [String: RuntimeRootPhysicalContext]
  let locationsByID: [String: RuntimeCandidatePhysicalLocation]
  let candidatesByAbsolutePath: [PhysicalPathKey: [String]]
  let candidatesByAliasPath: [RootAliasPathKey: [String]]
  let absoluteCandidateDepths: [Int]
  let aliasCandidateDepths: [Int]
}

private enum RuntimeObservedPhysicalPathKey: Hashable {
  case absolute(PhysicalPathKey)
  case alias(RootAliasPathKey)
}

private func rawAbsolutePathComponents(_ path: Data) -> [Data] {
  let bytes = [UInt8](path)
  return bytes.split(separator: 47).map { Data($0) }
}

private func makePhysicalCandidateIndexes(
  scanResult: AuthorityScanResult,
  candidates: [RecognizedRuntimeCandidate]
) -> RuntimePhysicalCandidateIndexes {
  let rootsByID = Dictionary(
    uniqueKeysWithValues: scanResult.roots.map {
      (
        $0.binding.rootID,
        RuntimeRootPhysicalContext(
          identity: $0.binding.identity,
          absoluteComponents: rawAbsolutePathComponents($0.binding.rawAbsolutePath)
        )
      )
    }
  )
  var locationsByID: [String: RuntimeCandidatePhysicalLocation] = [:]
  var byAbsolute: [PhysicalPathKey: [String]] = [:]
  var byAlias: [RootAliasPathKey: [String]] = [:]
  locationsByID.reserveCapacity(candidates.count)
  byAbsolute.reserveCapacity(candidates.count)
  byAlias.reserveCapacity(candidates.count)
  for candidate in candidates {
    guard let root = rootsByID[candidate.node.path.rootID] else { continue }
    let relative = candidate.node.path.components.map(\.bytes)
    let absolute = root.absoluteComponents + relative
    let location = RuntimeCandidatePhysicalLocation(
      candidateID: candidate.id,
      rootID: candidate.node.path.rootID,
      relativeComponents: relative,
      absoluteComponents: absolute,
      rootIdentity: root.identity
    )
    locationsByID[candidate.id] = location
    byAbsolute[PhysicalPathKey(components: absolute), default: []].append(candidate.id)
    byAlias[
      RootAliasPathKey(rootIdentity: root.identity, relativeComponents: relative),
      default: []
    ].append(candidate.id)
  }
  for key in byAbsolute.keys { byAbsolute[key]?.sort() }
  for key in byAlias.keys { byAlias[key]?.sort() }
  return RuntimePhysicalCandidateIndexes(
    rootsByID: rootsByID,
    locationsByID: locationsByID,
    candidatesByAbsolutePath: byAbsolute,
    candidatesByAliasPath: byAlias,
    absoluteCandidateDepths: Set(byAbsolute.keys.map { $0.components.count }).sorted(by: >),
    aliasCandidateDepths: Set(byAlias.keys.map { $0.relativeComponents.count }).sorted(by: >)
  )
}

private struct RuntimeCandidateContainment {
  let candidateID: String
  let candidateDepth: Int
  let nodeDepth: Int

  var distance: Int { nodeDepth - candidateDepth }
}

private func candidateContainments(
  nodePath: RawPath,
  indexes: RuntimePhysicalCandidateIndexes,
  includeExactPath: Bool
) -> [RuntimeCandidateContainment] {
  guard let root = indexes.rootsByID[nodePath.rootID] else { return [] }
  let relative = nodePath.components.map(\.bytes)
  let absolute = root.absoluteComponents + relative
  let maximumAbsoluteCount = includeExactPath ? absolute.count : absolute.count - 1
  let maximumRelativeCount = includeExactPath ? relative.count : relative.count - 1
  var containmentsByID: [String: RuntimeCandidateContainment] = [:]
  // Equal root object identity establishes a shared relative coordinate space,
  // regardless of the aliases' raw absolute path lengths.
  if maximumRelativeCount >= 0 {
    for count in indexes.aliasCandidateDepths where count <= maximumRelativeCount {
      let ids =
        indexes.candidatesByAliasPath[
          RootAliasPathKey(
            rootIdentity: root.identity,
            relativeComponents: Array(relative.prefix(count))
          )
        ] ?? []
      for id in ids {
        containmentsByID[id] = RuntimeCandidateContainment(
          candidateID: id,
          candidateDepth: count,
          nodeDepth: relative.count
        )
      }
    }
  }
  // Raw-absolute containment is used only across different root objects. A
  // same-object alias must not acquire a second, contradictory depth ranking.
  if maximumAbsoluteCount >= 0 {
    for count in indexes.absoluteCandidateDepths where count <= maximumAbsoluteCount {
      let ids =
        indexes.candidatesByAbsolutePath[
          PhysicalPathKey(components: Array(absolute.prefix(count)))
        ] ?? []
      for id in ids where indexes.locationsByID[id]?.rootIdentity != root.identity {
        containmentsByID[id] = RuntimeCandidateContainment(
          candidateID: id,
          candidateDepth: count,
          nodeDepth: absolute.count
        )
      }
    }
  }
  return containmentsByID.values.sorted { $0.candidateID < $1.candidateID }
}

private func deepestCandidateID(
  for ownerPath: RawPath,
  indexes: RuntimePhysicalCandidateIndexes
) -> String? {
  candidateContainments(nodePath: ownerPath, indexes: indexes, includeExactPath: false)
    .min {
      $0.distance == $1.distance
        ? $0.candidateID < $1.candidateID : $0.distance < $1.distance
    }?.candidateID
}

private func ownerPathRelativeToCandidate(
  ownerPath: RawPath,
  candidateID: String,
  indexes: RuntimePhysicalCandidateIndexes
) -> [Data]? {
  guard
    let root = indexes.rootsByID[ownerPath.rootID],
    let candidate = indexes.locationsByID[candidateID]
  else { return nil }
  let relative = ownerPath.components.map(\.bytes)
  let absolute = root.absoluteComponents + relative
  if root.identity == candidate.rootIdentity {
    guard relative.starts(with: candidate.relativeComponents) else { return nil }
    return relative
  }
  if absolute.starts(with: candidate.absoluteComponents) {
    return candidate.relativeComponents + absolute.dropFirst(candidate.absoluteComponents.count)
  }
  return nil
}

private func observedPhysicalPathKeys(
  _ path: RawPath,
  indexes: RuntimePhysicalCandidateIndexes
) -> [RuntimeObservedPhysicalPathKey] {
  guard let root = indexes.rootsByID[path.rootID] else { return [] }
  let relative = path.components.map(\.bytes)
  return [
    .absolute(PhysicalPathKey(components: root.absoluteComponents + relative)),
    .alias(RootAliasPathKey(rootIdentity: root.identity, relativeComponents: relative)),
  ]
}

private func candidateOverlaps(
  candidates: [RecognizedRuntimeCandidate],
  indexes: RuntimePhysicalCandidateIndexes
) -> [RuntimeCandidateOverlap] {
  var overlaps = Set<RuntimeCandidateOverlapKey>()
  for candidate in candidates {
    let containing = candidateContainments(
      nodePath: candidate.node.path,
      indexes: indexes,
      includeExactPath: true
    ).filter { $0.candidateID != candidate.id }
    guard !containing.isEmpty else { continue }
    let nearest = containing.min {
      $0.distance == $1.distance
        ? $0.candidateID < $1.candidateID : $0.distance < $1.distance
    }!
    let ancestor: String
    let descendant: String
    if nearest.distance == 0 {
      ancestor = min(nearest.candidateID, candidate.id)
      descendant = max(nearest.candidateID, candidate.id)
    } else {
      ancestor = nearest.candidateID
      descendant = candidate.id
    }
    overlaps.insert(
      RuntimeCandidateOverlapKey(
        ancestorCandidateID: ancestor,
        descendantCandidateID: descendant
      )
    )
  }
  return overlaps.sorted().map {
    RuntimeCandidateOverlap(
      ancestorCandidateID: $0.ancestorCandidateID,
      descendantCandidateID: $0.descendantCandidateID
    )
  }
}

private struct RuntimeCandidateOverlapKey: Hashable, Comparable {
  let ancestorCandidateID: String
  let descendantCandidateID: String

  static func < (lhs: Self, rhs: Self) -> Bool {
    if lhs.ancestorCandidateID != rhs.ancestorCandidateID {
      return lhs.ancestorCandidateID < rhs.ancestorCandidateID
    }
    return lhs.descendantCandidateID < rhs.descendantCandidateID
  }
}

public enum RuntimeAuthorityReason: String, CaseIterable, Equatable, Hashable, Sendable {
  case accessPolicyUnavailable = "access_policy_unavailable"
  case activityActive = "activity_active"
  case activityUnavailable = "activity_unavailable"
  case actionContractEvidenceUnavailable = "action_contract_evidence_unavailable"
  case aclEvidenceUnavailable = "acl_evidence_unavailable"
  case authorityBudgetExhausted = "authority_budget_exhausted"
  case candidateCoverageIncomplete = "candidate_coverage_incomplete"
  case candidateOverlap = "candidate_overlap"
  case collectorIncomplete = "collector_incomplete"
  case corpusIntegrityFailure = "corpus_integrity_failure"
  case dependencyCoverageIncomplete = "dependency_coverage_incomplete"
  case gitExecutionEvidenceUnavailable = "git_execution_evidence_unavailable"
  case identityUnavailable = "identity_unavailable"
  case nameOnlyTypeHint = "name_only_type_hint"
  case namespaceAncestorUnavailable = "namespace_ancestor_unavailable"
  case planningBudgetExhausted = "planning_budget_exhausted"
  case providerManaged = "provider_managed"
  case providerStateUnavailable = "provider_state_unavailable"
  case recoverabilityProvenanceUnavailable = "recoverability_provenance_unavailable"
  case rootCoverageIncomplete = "root_coverage_incomplete"
  case rootNamespaceSealUnavailable = "root_namespace_seal_unavailable"
  case releaseGraphIncomplete = "release_graph_incomplete"
  case scanNotTerminal = "scan_not_terminal"
  case sharedOwnerIncomplete = "shared_owner_incomplete"
}

public struct RecognizedRuntimeCandidate: Equatable, Sendable {
  public let id: String
  public let kind: RuntimeCandidateKind
  public let node: ScannedNode
  public let adapterScope: AdapterScopeEvidence
  public let classificationClaims: [ClassificationClaim]
  public let reasons: [RuntimeAuthorityReason]
  public let ancestors: [ScannedNode]
  public let isClosed: Bool
  public let recognizerAuthority: RuntimeRecognizerAuthority

  fileprivate init(
    id: String,
    kind: RuntimeCandidateKind,
    node: ScannedNode,
    adapterScope: AdapterScopeEvidence,
    classificationClaims: [ClassificationClaim],
    reasons: [RuntimeAuthorityReason],
    ancestors: [ScannedNode],
    isClosed: Bool,
    recognizerAuthority: RuntimeRecognizerAuthority
  ) {
    self.id = id
    self.kind = kind
    self.node = node
    self.adapterScope = adapterScope
    self.classificationClaims = classificationClaims
    self.reasons = Array(Set(reasons)).sorted(by: { $0.rawValue < $1.rawValue })
    self.ancestors = ancestors
    self.isClosed = isClosed
    self.recognizerAuthority = recognizerAuthority
  }
}

public struct RuntimeReleaseOwner: Equatable, Sendable {
  public let fileObjectID: String
  public let candidateID: String
  public let path: RawTargetPath
  public let namespaceBinding: ProtectedNamespaceBinding
  public let linkCount: DiskplanPolicy.Observation<UInt32>
}

public struct RuntimeAllocationGroup: Equatable, Sendable {
  public let id: String
  public let fileObjectIDs: [String]
  public let cloneIdentity: DiskplanPolicy.Observation<ReleaseCloneIdentity>
  public let cloneRefCount: DiskplanPolicy.Observation<UInt32>
  public let sharedBytes: DiskplanPolicy.Observation<UInt64>
}

public struct RuntimeReleaseOwnerIndex: Equatable, Sendable {
  public let owners: [RuntimeReleaseOwner]
  public let allocationGroups: [RuntimeAllocationGroup]
  public let dependencyCompleteByCandidate: [String: Bool]
  public let overlaps: [RuntimeCandidateOverlap]
  public let overlappingCandidateIDs: Set<String>
}

public struct RuntimeCandidateOverlap: Equatable, Sendable {
  public let ancestorCandidateID: String
  public let descendantCandidateID: String
}

public struct ScannerPolicyCandidateEvidence: Equatable, Sendable {
  public let candidate: RecognizedRuntimeCandidate
  public let namespaceBinding: ProtectedNamespaceBinding
  public let identity: DiskplanPolicy.Observation<DiskplanPolicy.ObjectIdentity>
  public let coverage: EvidenceCoverage
  public let collectorStatus: DiskplanPolicy.Observation<CollectorCompletionState>
  public let activity: DiskplanPolicy.Observation<ActivityState>
  public let explicitProtection: DiskplanPolicy.Observation<ExplicitProtectionState>
  public let providerState: DiskplanPolicy.Observation<ProviderState>
  public let recoverability: DiskplanPolicy.Observation<RecoverabilityState>
  public let recoverabilityReviewFacts: [RecoverabilityReviewFact]
  public let dependencyState: DiskplanPolicy.Observation<DependencyState>
  public let accessPolicy: DiskplanPolicy.Observation<String>
  public let contentProtection: DiskplanPolicy.Observation<ContentProtectionBaseline>
  public let aclDigest: DiskplanPolicy.Observation<PolicyDigest>
  public let targetMountIdentity: DiskplanPolicy.Observation<String>
  public let removalForceRequirement: DiskplanPolicy.Observation<ForceRequirement>
  public let authorityReasons: [RuntimeAuthorityReason]
}

public struct ProductionPolicyEvidenceAdapter: PolicyEvidenceAdapter {
  public init() {}

  public func freeze(
    _ evidence: ScannerPolicyCandidateEvidence,
    context: EvidenceFreezeContext
  ) throws -> FrozenEvidenceSnapshot {
    try FrozenEvidenceSnapshot(
      captureID: context.captureID,
      globalFactsHash: context.globalFactsHash,
      candidateID: evidence.candidate.id,
      namespaceBinding: evidence.namespaceBinding,
      identity: evidence.identity,
      coverage: evidence.coverage,
      collectorStatus: evidence.collectorStatus,
      activity: evidence.activity,
      explicitProtection: evidence.explicitProtection,
      providerState: evidence.providerState,
      recoverability: evidence.recoverability,
      recoverabilityReviewFacts: evidence.recoverabilityReviewFacts,
      dependencyState: evidence.dependencyState,
      semanticReviewFacts: [],
      accessPolicy: evidence.accessPolicy,
      contentProtection: evidence.contentProtection,
      aclDigest: evidence.aclDigest,
      targetMountIdentity: evidence.targetMountIdentity,
      removalForceRequirement: evidence.removalForceRequirement,
      quarantineCapability: .unknown(.unavailableViaPublicAPI),
      gitWorktree: nil,
      adapterScope: evidence.candidate.adapterScope,
      additionalAdapterScopes: [],
      classificationClaims: evidence.candidate.classificationClaims,
      semanticReferenceTimeSeconds: context.semanticReferenceTimeSeconds,
      policyVersion: context.policyVersion,
      schemaVersion: context.schemaVersion
    )
  }
}

public struct RuntimePlanItem: Equatable, Sendable {
  public let candidateID: String
  public let kind: RuntimeCandidateKind
  public let rawRoot: Data
  public let target: RawTargetPath
  public let evidenceID: PolicyDigest
  public let actionID: ActionID?
  public let evaluation: PolicyEvaluation
  public let immediateReclaimBytes: KnownOrUnknown<UInt64>
  public let inactiveDurationSeconds: KnownOrUnknown<UInt64>
  public let reasons: [RuntimeAuthorityReason]
}

public struct RuntimePlanProjection: Equatable, Sendable {
  public let entries: [RuntimePlanItem]
  public let rejectedEntries: [RuntimeRejectedCandidate]
  public let totalEntryCount: Int
  public let wasTruncated: Bool
}

public struct RuntimeRejectedCandidate: Equatable, Sendable {
  public let candidateID: String
  public let kind: RuntimeCandidateKind
  public let path: RawPath
  public let reasons: [RuntimeAuthorityReason]
}

public struct RuntimePolicyAuthorityResult: Equatable, Sendable {
  public let plan: ImmutablePlan
  public let items: [RuntimePlanItem]
  public let rejectedCandidates: [RuntimeRejectedCandidate]
  public let releaseOwnerIndex: RuntimeReleaseOwnerIndex
  public let releaseGraph: StorageReleaseGraph?
  public let releaseGraphFailure: RuntimeAuthorityReason?

  public func presentation(maximumEntries: Int = 1_000) -> RuntimePlanProjection {
    let limit = max(0, maximumEntries)
    let retainedItems = Array(items.prefix(limit))
    let remaining = max(0, limit - retainedItems.count)
    return RuntimePlanProjection(
      entries: retainedItems,
      rejectedEntries: Array(rejectedCandidates.prefix(remaining)),
      totalEntryCount: items.count + rejectedCandidates.count,
      wasTruncated: items.count + rejectedCandidates.count > limit
    )
  }
}

public enum RuntimePolicyAuthorityError: Error, Equatable, Sendable {
  case invalidReferenceTime
  case rootBindingMissing(String)
  case invalidObjectIdentity(RawPath)
  case invalidRawPath(RawPath)
  case policyModel(String)
}

enum RuntimePolicyAuthoritySessionError: Error, Equatable {
  case scanNotFinalized
  case scanNotPlannable(ScanMachineState)
}

final class RuntimePolicyAuthoritySession: ScanNodeSink, @unchecked Sendable {
  private let lock = NSLock()
  private let accumulator: BoundedAuthorityEvidenceAccumulator
  private var finalized: BoundedAuthorityFinalization?

  init(scope: ResolvedScanScope, budget: AuthorityRetentionBudget? = nil) {
    accumulator = BoundedAuthorityEvidenceAccumulator(
      budget: budget ?? .accepted(for: scope)
    )
  }

  func receive(_ event: ScanNodeEvent) {
    lock.lock()
    guard finalized == nil else {
      lock.unlock()
      return
    }
    accumulator.receive(event)
    lock.unlock()
  }

  func finalize(_ result: ScanResult) throws {
    guard result.state == .complete || result.state == .partial else {
      throw RuntimePolicyAuthoritySessionError.scanNotPlannable(result.state)
    }
    lock.lock()
    if finalized == nil {
      finalized = boundedAuthorityFinalization(
        result: result,
        evidence: accumulator.snapshot()
      )
    }
    lock.unlock()
  }

  func makePlan() throws -> RuntimePolicyAuthorityResult {
    lock.lock()
    let finalized = self.finalized
    lock.unlock()
    guard let finalized else { throw RuntimePolicyAuthoritySessionError.scanNotFinalized }
    return try RuntimePolicyAuthority().makePlan(
      scanResult: finalized.result,
      evidence: finalized.evidence,
      authorityConfiguration: finalized.authorityConfiguration
    )
  }
}

public struct RuntimePolicyAuthority: Sendable {
  public static let policyVersion = "policy-1"
  public static let schemaVersion = "schema-1"

  private let adapter = ProductionPolicyEvidenceAdapter()

  public init() {}

  public func makePlan(
    scanResult: ScanResult,
    evidence: AuthorityEvidenceSnapshot
  ) throws -> RuntimePolicyAuthorityResult {
    let finalized = boundedAuthorityFinalization(result: scanResult, evidence: evidence)
    return try makePlan(
      scanResult: finalized.result,
      evidence: finalized.evidence,
      authorityConfiguration: finalized.authorityConfiguration
    )
  }

  fileprivate func makePlan(
    scanResult: AuthorityScanResult,
    evidence: AuthorityEvidenceSnapshot,
    authorityConfiguration: Data
  ) throws -> RuntimePolicyAuthorityResult {
    let globalFacts = try freezeGlobalFacts(
      scanResult: scanResult,
      evidence: evidence,
      authorityConfiguration: authorityConfiguration
    )
    let context = EvidenceFreezeContext(globalFacts: globalFacts)
    let rootResultByID = Dictionary(
      uniqueKeysWithValues: scanResult.roots.map { ($0.binding.rootID, $0) }
    )
    let rawRootByID = Dictionary(
      uniqueKeysWithValues: scanResult.reference.resolvedScope.roots.map {
        ($0.rootID, $0.rawAbsolutePath)
      }
    )
    let candidates = recognizeCandidates(
      rootResultByID: rootResultByID,
      rawRootByID: rawRootByID,
      evidence: evidence
    )
    var candidateByID: [Data: RecognizedRuntimeCandidate] = [:]
    candidateByID.reserveCapacity(candidates.count)
    for candidate in candidates { candidateByID[Data(candidate.id.utf8)] = candidate }
    let ownerIndex = try buildReleaseOwnerIndex(
      scanResult: scanResult,
      evidence: evidence,
      candidates: candidates
    )

    var snapshots: [FrozenEvidenceSnapshot] = []
    var evaluations: [Data: PolicyEvaluation] = [:]
    var reasonsByCandidate: [Data: [RuntimeAuthorityReason]] = [:]
    var rejectedCandidates: [RuntimeRejectedCandidate] = []
    for candidate in candidates {
      let key = Data(candidate.id.utf8)
      do {
        guard let rootResult = rootResultByID[candidate.node.path.rootID] else {
          throw RuntimePolicyAuthorityError.rootBindingMissing(candidate.node.path.rootID)
        }
        let input = try makeCandidateEvidence(
          candidate: candidate,
          scanResult: scanResult,
          rootResult: rootResult,
          evidence: evidence,
          ownerIndex: ownerIndex
        )
        let snapshot = try adapter.freeze(input, context: context)
        let evaluation = try OneVotePolicy.evaluate(
          OneVotePolicyInputs.build(evidence: snapshot, globalFacts: globalFacts)
        )
        snapshots.append(snapshot)
        evaluations[key] = evaluation
        reasonsByCandidate[key] = input.authorityReasons
      } catch {
        rejectedCandidates.append(
          RuntimeRejectedCandidate(
            candidateID: candidate.id,
            kind: candidate.kind,
            path: candidate.node.path,
            reasons: Array(Set(candidate.reasons + rejectionReasons(for: error))).sorted {
              $0.rawValue < $1.rawValue
            }
          )
        )
      }
    }

    var actions: [ActionDefinition] = []
    var actionByCandidate: [Data: ActionDefinition] = [:]
    for snapshot in snapshots {
      let key = Data(snapshot.candidateID.utf8)
      guard let candidate = candidateByID[key],
        let evaluation = evaluations[key]
      else { continue }
      if candidate.kind == .gitLinkedWorktree {
        reasonsByCandidate[key, default: []].append(.gitExecutionEvidenceUnavailable)
        continue
      }
      if candidate.kind == .providerReportOnly
        || candidate.recognizerAuthority == .nameOnlyTypeHint
      {
        continue
      }
      do {
        let request = adapterRequest(for: candidate)
        let prototype = try ActionPrototype.build(request: request, evidence: snapshot)
        let displayMetrics = makeDisplayMetrics(
          candidate: candidate,
          referenceTimeSeconds: globalFacts.semanticReferenceTimeSeconds
        )
        let action = try ActionDefinition.build(
          prototype: prototype,
          evidence: snapshot,
          globalFacts: globalFacts,
          prerequisites: [],
          evaluation: evaluation,
          displayMetrics: displayMetrics
        )
        actions.append(action)
        actionByCandidate[key] = action
      } catch {
        reasonsByCandidate[key, default: []].append(.actionContractEvidenceUnavailable)
      }
    }

    let releaseGraph: StorageReleaseGraph?
    var releaseGraphFailure: RuntimeAuthorityReason?
    do {
      releaseGraph = try makeReleaseGraph(
        globalFacts: globalFacts,
        snapshots: snapshots,
        candidates: candidates,
        ownerIndex: ownerIndex
      )
      releaseGraphFailure = nil
    } catch {
      releaseGraph = nil
      releaseGraphFailure = .releaseGraphIncomplete
      for snapshot in snapshots {
        let key = Data(snapshot.candidateID.utf8)
        reasonsByCandidate[key, default: []].append(.releaseGraphIncomplete)
      }
    }
    var releaseBundle: PlanReleaseGraphBundle?
    if let releaseGraph, actionByCandidate.count == snapshots.count,
      !ownerIndex.allocationGroups.isEmpty
    {
      do {
        let bindings = snapshots.compactMap { snapshot -> CandidateActionBinding? in
          let key = Data(snapshot.candidateID.utf8)
          guard let action = actionByCandidate[key] else { return nil }
          return CandidateActionBinding(candidateID: snapshot.candidateID, action: action)
        }
        let evaluation = try releaseGraph.evaluate(selectedCandidateActions: bindings)
        releaseBundle = try PlanReleaseSet.buildAll(
          from: evaluation,
          candidateActions: bindings
        )
      } catch {
        releaseBundle = nil
        releaseGraphFailure = .releaseGraphIncomplete
        for snapshot in snapshots {
          let key = Data(snapshot.candidateID.utf8)
          reasonsByCandidate[key, default: []].append(.releaseGraphIncomplete)
        }
      }
    } else {
      releaseBundle = nil
    }

    let plan = try ImmutablePlan(
      policyVersion: Self.policyVersion,
      schemaVersion: Self.schemaVersion,
      globalFacts: globalFacts,
      evidenceSnapshots: snapshots,
      actions: actions,
      releaseGraphBundle: releaseBundle
    )
    let snapshotByCandidate = Dictionary(
      uniqueKeysWithValues: snapshots.map { (Data($0.candidateID.utf8), $0) }
    )
    let items = candidates.compactMap { candidate -> RuntimePlanItem? in
      let key = Data(candidate.id.utf8)
      guard let snapshot = snapshotByCandidate[key], let evaluation = evaluations[key] else {
        return nil
      }
      let display = makeDisplayMetrics(
        candidate: candidate,
        referenceTimeSeconds: globalFacts.semanticReferenceTimeSeconds
      )
      return RuntimePlanItem(
        candidateID: candidate.id,
        kind: candidate.kind,
        rawRoot: snapshot.namespaceBinding.rawRoot.absoluteBytes,
        target: snapshot.namespaceBinding.targetPath,
        evidenceID: snapshot.evidenceID,
        actionID: actionByCandidate[key]?.id,
        evaluation: evaluation,
        immediateReclaimBytes: display.immediateReclaimBytes,
        inactiveDurationSeconds: display.inactiveDurationSeconds,
        reasons: Array(Set(reasonsByCandidate[key, default: []])).sorted {
          $0.rawValue < $1.rawValue
        }
      )
    }
    return RuntimePolicyAuthorityResult(
      plan: plan,
      items: items,
      rejectedCandidates: rejectedCandidates,
      releaseOwnerIndex: ownerIndex,
      releaseGraph: releaseGraph,
      releaseGraphFailure: releaseGraphFailure
    )
  }

  private func freezeGlobalFacts(
    scanResult: AuthorityScanResult,
    evidence: AuthorityEvidenceSnapshot,
    authorityConfiguration: Data
  ) throws -> FrozenGlobalFacts {
    let seconds = scanResult.reference.wallClock.timeIntervalSince1970
    guard seconds.isFinite,
      let semanticReferenceTimeSeconds = Int64(exactly: seconds.rounded(.down))
    else {
      throw RuntimePolicyAuthorityError.invalidReferenceTime
    }
    let captureID = try encodeCaptureDigest(
      scanResult: scanResult,
      evidence: evidence,
      authorityConfiguration: authorityConfiguration
    )
    let resultByRoot = Dictionary(
      uniqueKeysWithValues: scanResult.roots.map { (Data($0.binding.rootID.utf8), $0) }
    )
    let failureRootIDs = Set(scanResult.rootFailures.map { Data($0.rootID.utf8) })
    let requestsByRawRoot = Dictionary(
      grouping: scanResult.reference.resolvedScope.roots,
      by: \.rawAbsolutePath
    )
    let coverage = try requestsByRawRoot.keys.sorted(by: { $0.lexicographicallyPrecedes($1) })
      .map { rawRoot in
        let requests = requestsByRawRoot[rawRoot]!
        let coverages = requests.compactMap { resultByRoot[Data($0.rootID.utf8)]?.coverage }
        let mapped =
          coverages.count == requests.count
            && coverages.allSatisfy({ $0.completeness == .complete })
          ? EvidenceCoverage.complete : .collectorFailed
        var reasons = coverages.flatMap(\.reasons).map(\.rawValue)
        if requests.contains(where: { failureRootIDs.contains(Data($0.rootID.utf8)) }) {
          reasons.append("root_failure")
        }
        if scanResult.state != .complete { reasons.append("scan_not_complete") }
        if !evidence.issues.isEmpty { reasons.append("corpus_integrity_failure") }
        if evidence.retention.isIncomplete { reasons.append("authority_retention_incomplete") }
        return GlobalCoverageFact(
          rawRoot: try RawRootPath(absoluteBytes: rawRoot),
          coverage: mapped,
          reasons: reasons
        )
      }
    return FrozenGlobalFacts(
      captureID: captureID,
      profile: scanResult.reference.profileID,
      configuration: authorityConfiguration,
      coverage: coverage,
      semanticReferenceTimeSeconds: semanticReferenceTimeSeconds,
      policyVersion: Self.policyVersion,
      schemaVersion: Self.schemaVersion
    )
  }

  private func recognizeCandidates(
    rootResultByID: [String: RootScanResult],
    rawRootByID: [String: Data],
    evidence: AuthorityEvidenceSnapshot
  ) -> [RecognizedRuntimeCandidate] {
    let paths = evidence.candidatesByPath.keys.sorted()
    let recognized = paths.map { path -> RecognizedRuntimeCandidate in
      let record = evidence.candidatesByPath[path]!
      let node = record.node
      let kind = record.kind
      let rootBoundary = rootResultByID[node.path.rootID]?.providerBoundary
      let ancestorBoundaries = record.ancestors.map(\.providerBoundary)
      var boundaries = ancestorBoundaries + [node.providerBoundary]
      if let rootBoundary { boundaries.append(rootBoundary) }
      let providerReportOnly = boundaries.contains(where: isProviderManaged)
      let effectiveKind: RuntimeCandidateKind = providerReportOnly ? .providerReportOnly : kind
      let scope = adapterScope(
        kind: effectiveKind,
        node: node,
        authority: record.recognizerAuthority
      )
      var reasons: [RuntimeAuthorityReason] = providerReportOnly ? [.providerManaged] : []
      if record.recognizerAuthority == .nameOnlyTypeHint {
        reasons.append(.nameOnlyTypeHint)
        reasons.append(.recoverabilityProvenanceUnavailable)
      }
      if evidence.retention.isIncomplete { reasons.append(.authorityBudgetExhausted) }
      return RecognizedRuntimeCandidate(
        id: candidateID(rawRoot: rawRootByID[node.path.rootID], node: node),
        kind: effectiveKind,
        node: node,
        adapterScope: scope,
        classificationClaims: classificationClaims(
          kind: effectiveKind,
          authority: record.recognizerAuthority
        ),
        reasons: reasons,
        ancestors: record.ancestors,
        isClosed: record.isClosed,
        recognizerAuthority: record.recognizerAuthority
      )
    }
    return recognized.sorted(by: recognizedCandidatePrecedes)
  }

  private func makeCandidateEvidence(
    candidate: RecognizedRuntimeCandidate,
    scanResult: AuthorityScanResult,
    rootResult: RootScanResult,
    evidence: AuthorityEvidenceSnapshot,
    ownerIndex: RuntimeReleaseOwnerIndex
  ) throws -> ScannerPolicyCandidateEvidence {
    let namespace = try makeNamespaceBinding(
      candidate: candidate,
      root: rootResult
    )
    var reasons = candidate.reasons
    if !evidence.issues.isEmpty { reasons.append(.corpusIntegrityFailure) }
    if evidence.retention.isIncomplete { reasons.append(.authorityBudgetExhausted) }
    if evidence.retention.planningBudgetExceeded { reasons.append(.planningBudgetExhausted) }
    if scanResult.state != .complete { reasons.append(.scanNotTerminal) }
    if rootResult.coverage.completeness != .complete { reasons.append(.rootCoverageIncomplete) }
    if candidate.node.coverage.completeness != .complete {
      reasons.append(.candidateCoverageIncomplete)
    }
    let isClosed =
      candidate.node.identity.value?.objectType != .directory
      || candidate.isClosed
    if !isClosed { reasons.append(.candidateCoverageIncomplete) }
    let collectorComplete =
      scanResult.state == .complete && evidence.issues.isEmpty && isClosed
      && !evidence.retention.isIncomplete
      && rootResult.coverage.completeness == .complete
      && candidate.node.coverage.completeness == .complete
    if !collectorComplete { reasons.append(.collectorIncomplete) }
    let activity = mapActivity(
      scanResult.processActivity,
      root: rootResult.binding.rawAbsolutePath,
      target: candidate.node.path.components.map(\.bytes)
    )
    switch activity {
    case .known(.active): reasons.append(.activityActive)
    case .known(.inactive): break
    default: reasons.append(.activityUnavailable)
    }
    let provider = mapProviderState(
      rootBoundary: rootResult.providerBoundary,
      node: candidate.node,
      ancestors: candidate.ancestors
    )
    switch provider {
    case .known(.fileProviderManaged): reasons.append(.providerManaged)
    case .known(.local): break
    default: reasons.append(.providerStateUnavailable)
    }
    let identity = mapIdentity(candidate.node.identity)
    if identity.knownValue == nil { reasons.append(.identityUnavailable) }
    let access = mapAccessPolicy(candidate.node.accessPolicy)
    if access.knownValue == nil { reasons.append(.accessPolicyUnavailable) }
    reasons.append(.aclEvidenceUnavailable)
    reasons.append(.rootNamespaceSealUnavailable)
    let dependencyComplete = ownerIndex.dependencyCompleteByCandidate[candidate.id] == true
    if !dependencyComplete {
      reasons.append(.dependencyCoverageIncomplete)
      reasons.append(.sharedOwnerIncomplete)
    }
    if ownerIndex.overlappingCandidateIDs.contains(candidate.id) {
      reasons.append(.candidateOverlap)
    }
    let (recoverability, recoveryFacts) = recoverabilityEvidence(for: candidate)
    if recoverability.knownValue == nil {
      reasons.append(.recoverabilityProvenanceUnavailable)
    }
    return ScannerPolicyCandidateEvidence(
      candidate: candidate,
      namespaceBinding: namespace,
      identity: identity,
      coverage: collectorComplete ? .complete : mapCoverage(candidate.node.coverage),
      collectorStatus: collectorComplete
        ? .known(.complete) : .unknown(.incompleteCoverage),
      activity: activity,
      explicitProtection: mapProtection(candidate.node.accessPolicy),
      providerState: provider,
      recoverability: recoverability,
      recoverabilityReviewFacts: recoveryFacts,
      dependencyState: dependencyComplete
        ? .known(.complete) : .unknown(.incompleteCoverage),
      accessPolicy: access,
      contentProtection: mapContentProtection(candidate.node),
      aclDigest: .unknown(.unavailableViaPublicAPI),
      targetMountIdentity: mapMountIdentity(candidate.node.identity),
      removalForceRequirement: mapForceRequirement(candidate.node.accessPolicy),
      authorityReasons: Array(Set(reasons)).sorted { $0.rawValue < $1.rawValue }
    )
  }

  private func makeNamespaceBinding(
    candidate: RecognizedRuntimeCandidate,
    root: RootScanResult
  ) throws -> ProtectedNamespaceBinding {
    try makeNamespaceBinding(node: candidate.node, ancestors: candidate.ancestors, root: root)
  }

  private func makeNamespaceBinding(
    node: ScannedNode,
    ancestors: [ScannedNode],
    root: RootScanResult
  ) throws -> ProtectedNamespaceBinding {
    guard let rootIdentity = mapIdentity(.known(root.binding.identity)).knownValue else {
      throw RuntimePolicyAuthorityError.invalidObjectIdentity(node.path)
    }
    let targetPath = try RawTargetPath(components: node.path.components.map(\.bytes))
    guard let targetIdentity = mapIdentity(node.identity).knownValue else {
      throw RuntimePolicyAuthorityError.invalidObjectIdentity(node.path)
    }
    let rootSeal = NamespaceSealEvidence(
      trustedNamespace: .unverified,
      accessPolicy: .unknown(.unavailableViaPublicAPI),
      aclDigest: .unknown(.unavailableViaPublicAPI),
      providerBoundary: mapProviderBoundary(root.providerBoundary),
      mountIdentity: .known("real-device:\(root.binding.identity.device)")
    )
    var parents: [ParentNamespaceBinding] = []
    for ancestor in ancestors {
      let components = ancestor.path.components
      guard let identity = mapIdentity(ancestor.identity).knownValue
      else { throw RuntimePolicyAuthorityError.invalidObjectIdentity(ancestor.path) }
      parents.append(
        ParentNamespaceBinding(
          relativePath: try RawTargetPath(components: components.map(\.bytes)),
          identity: identity,
          seal: NamespaceSealEvidence(
            trustedNamespace: .unverified,
            accessPolicy: mapAccessPolicy(ancestor.accessPolicy),
            aclDigest: .unknown(.unavailableViaPublicAPI),
            providerBoundary: mapProviderBoundary(ancestor.providerBoundary),
            mountIdentity: mapMountIdentity(ancestor.identity)
          )
        )
      )
    }
    return try ProtectedNamespaceBinding(
      rawRoot: RawRootPath(absoluteBytes: root.binding.rawAbsolutePath),
      rootIdentity: rootIdentity,
      rootSeal: rootSeal,
      targetPath: targetPath,
      targetIdentity: targetIdentity,
      parentChain: parents
    )
  }

  private func makeOwnerNamespaceBinding(
    node: ScannedNode,
    observedAncestors: [ScannedNode],
    candidate: RecognizedRuntimeCandidate,
    candidateNamespace: ProtectedNamespaceBinding,
    targetPath: RawTargetPath
  ) throws -> ProtectedNamespaceBinding {
    guard targetPath.isWithin(candidateNamespace.targetPath),
      let targetIdentity = mapIdentity(node.identity).knownValue
    else { throw RuntimePolicyAuthorityError.invalidObjectIdentity(node.path) }
    var parents = candidateNamespace.parentChain
    let candidateSeal = NamespaceSealEvidence(
      trustedNamespace: candidateNamespace.trustedNamespace,
      accessPolicy: mapAccessPolicy(candidate.node.accessPolicy),
      aclDigest: .unknown(.unavailableViaPublicAPI),
      providerBoundary: mapProviderBoundary(candidate.node.providerBoundary),
      mountIdentity: mapMountIdentity(candidate.node.identity))
    parents.append(
      ParentNamespaceBinding(
        relativePath: candidateNamespace.targetPath,
        identity: candidateNamespace.targetIdentity,
        seal: candidateSeal))
    let intermediateCount =
      targetPath.components.count - candidateNamespace.targetPath.components.count - 1
    guard intermediateCount >= 0, observedAncestors.count >= intermediateCount else {
      throw RuntimePolicyAuthorityError.invalidObjectIdentity(node.path)
    }
    let intermediateAncestors = observedAncestors.suffix(intermediateCount)
    for (offset, ancestor) in intermediateAncestors.enumerated() {
      let observedDepth = node.path.components.count - intermediateCount + offset
      guard ancestor.path.rootID == node.path.rootID,
        ancestor.path.components == Array(node.path.components.prefix(observedDepth))
      else {
        throw RuntimePolicyAuthorityError.invalidObjectIdentity(node.path)
      }
      guard let identity = mapIdentity(ancestor.identity).knownValue else {
        throw RuntimePolicyAuthorityError.invalidObjectIdentity(ancestor.path)
      }
      let depth = candidateNamespace.targetPath.components.count + offset + 1
      parents.append(
        ParentNamespaceBinding(
          relativePath: try RawTargetPath(
            components: Array(targetPath.components.prefix(depth))),
          identity: identity,
          seal: NamespaceSealEvidence(
            trustedNamespace: candidateNamespace.trustedNamespace,
            accessPolicy: mapAccessPolicy(ancestor.accessPolicy),
            aclDigest: .unknown(.unavailableViaPublicAPI),
            providerBoundary: mapProviderBoundary(ancestor.providerBoundary),
            mountIdentity: mapMountIdentity(ancestor.identity))))
    }
    return try ProtectedNamespaceBinding(
      rawRoot: candidateNamespace.rawRoot,
      rootIdentity: candidateNamespace.rootIdentity,
      rootSeal: candidateNamespace.rootSeal,
      targetPath: targetPath,
      targetIdentity: targetIdentity,
      parentChain: parents)
  }

  private func buildReleaseOwnerIndex(
    scanResult: AuthorityScanResult,
    evidence: AuthorityEvidenceSnapshot,
    candidates: [RecognizedRuntimeCandidate]
  ) throws -> RuntimeReleaseOwnerIndex {
    var owners: [RuntimeReleaseOwner] = []
    let physicalIndexes = makePhysicalCandidateIndexes(
      scanResult: scanResult,
      candidates: candidates
    )
    let overlaps = candidateOverlaps(candidates: candidates, indexes: physicalIndexes)
    let initiallyComplete =
      scanResult.state == .complete && evidence.issues.isEmpty
      && !evidence.retention.isIncomplete && !evidence.topologyCoverageIncomplete
    var dependencyCompleteByCandidate: [String: Bool] = [:]
    dependencyCompleteByCandidate.reserveCapacity(candidates.count)
    for candidate in candidates {
      dependencyCompleteByCandidate[candidate.id] =
        initiallyComplete && candidate.node.coverage.completeness == .complete
        && candidate.isClosed
    }
    for overlap in overlaps {
      dependencyCompleteByCandidate[overlap.ancestorCandidateID] = false
      dependencyCompleteByCandidate[overlap.descendantCandidateID] = false
    }
    var overlappingCandidateIDs = Set<String>()
    overlappingCandidateIDs.reserveCapacity(overlaps.count * 2)
    for overlap in overlaps {
      overlappingCandidateIDs.insert(overlap.ancestorCandidateID)
      overlappingCandidateIDs.insert(overlap.descendantCandidateID)
    }

    var filePathsByID: [String: [RawPath]] = [:]
    var clonePathsByGroup: [String: [RawPath]] = [:]
    var assignedCandidateByPath: [RawPath: String] = [:]
    var seenPhysicalPaths = Set<RuntimeObservedPhysicalPathKey>()
    for node in evidence.sharedFileObservationsByPath.values.sorted(by: { $0.path < $1.path }) {
      let physicalPathKeys = observedPhysicalPathKeys(node.path, indexes: physicalIndexes)
      guard physicalPathKeys.allSatisfy({ !seenPhysicalPaths.contains($0) }) else { continue }
      seenPhysicalPaths.formUnion(physicalPathKeys)
      guard let identity = node.identity.value else { continue }
      let objectID = fileObjectID(identity)
      filePathsByID[objectID, default: []].append(node.path)
      if let cloneID = node.storageTopology.cloneID.value {
        clonePathsByGroup[cloneGroupID(device: identity.device, cloneID: cloneID), default: []]
          .append(node.path)
      }
      guard
        let candidateID = deepestCandidateID(
          for: node.path,
          indexes: physicalIndexes
        ),
        let candidateRelativePath = ownerPathRelativeToCandidate(
          ownerPath: node.path,
          candidateID: candidateID,
          indexes: physicalIndexes
        ),
        let candidate = candidates.first(where: { $0.id == candidateID }),
        let root = scanResult.roots.first(where: {
          $0.binding.rootID == candidate.node.path.rootID
        }),
        let ancestors = evidence.sharedFileAncestorsByPath[node.path]
      else { continue }
      let canonicalOwnerPath = try RawTargetPath(components: candidateRelativePath)
      let candidateNamespace = try makeNamespaceBinding(candidate: candidate, root: root)
      let namespaceBinding: ProtectedNamespaceBinding
      do {
        namespaceBinding = try makeOwnerNamespaceBinding(
          node: node,
          observedAncestors: ancestors,
          candidate: candidate,
          candidateNamespace: candidateNamespace,
          targetPath: canonicalOwnerPath)
      } catch {
        dependencyCompleteByCandidate[candidateID] = false
        continue
      }
      assignedCandidateByPath[node.path] = candidateID
      owners.append(
        RuntimeReleaseOwner(
          fileObjectID: objectID,
          candidateID: candidateID,
          path: canonicalOwnerPath,
          namespaceBinding: namespaceBinding,
          linkCount: mapUInt32Observation(node.storageTopology.linkCount)
        )
      )
    }

    var objectComplete: [String: Bool] = [:]
    for (objectID, paths) in filePathsByID {
      let distinctPaths = Set(paths)
      let members = paths.compactMap { evidence.sharedFileObservationsByPath[$0] }
      let linkCounts = paths.map {
        evidence.sharedFileObservationsByPath[$0]?.storageTopology.linkCount.value
      }
      let knownLinkCounts = Set(linkCounts.compactMap { $0 })
      let allPathsAssigned = distinctPaths.allSatisfy { assignedCandidateByPath[$0] != nil }
      let topologyConsistent =
        members.count == paths.count
        && members.dropFirst().allSatisfy {
          $0.storageTopology == members.first?.storageTopology
        }
      var complete =
        linkCounts.allSatisfy({ $0 != nil }) && knownLinkCounts.count == 1
        && knownLinkCounts.first == UInt32(exactly: distinctPaths.count)
        && allPathsAssigned && topologyConsistent
      for path in distinctPaths {
        guard let member = evidence.sharedFileObservationsByPath[path] else {
          complete = false
          continue
        }
        guard case .known(let mayShare) = member.storageTopology.mayShareBlocks else {
          complete = false
          continue
        }
        if mayShare {
          guard case .known = member.storageTopology.cloneID,
            case .known = member.storageTopology.cloneRefcount
          else {
            complete = false
            continue
          }
        } else {
          guard case .absent = member.storageTopology.cloneID,
            case .absent = member.storageTopology.cloneRefcount
          else {
            complete = false
            continue
          }
        }
      }
      objectComplete[objectID] = complete
      if !complete {
        for path in distinctPaths {
          if let candidateID = assignedCandidateByPath[path] {
            dependencyCompleteByCandidate[candidateID] = false
          }
        }
      }
    }

    var groups: [RuntimeAllocationGroup] = []
    for groupID in clonePathsByGroup.keys.sorted() {
      guard let paths = clonePathsByGroup[groupID] else { continue }
      let members = paths.compactMap { evidence.sharedFileObservationsByPath[$0] }
      let fileIDs = Array(Set(members.compactMap { $0.identity.value.map(fileObjectID) })).sorted()
      let refCountValues = members.map { $0.storageTopology.cloneRefcount.value }
      let refCounts = Set(refCountValues.compactMap { $0 })
      let cloneIdentities = Set(
        members.compactMap { member -> ReleaseCloneIdentity? in
          guard let identity = member.identity.value,
            identity.device >= 0,
            let cloneID = member.storageTopology.cloneID.value,
            cloneID > 0
          else { return nil }
          return ReleaseCloneIdentity(device: UInt64(bitPattern: identity.device), cloneID: cloneID)
        })
      // Clone release credit requires explicit positive sharing evidence. Unknown
      // or false flags cannot be upgraded from clone IDs/refcounts alone.
      let positiveCloneEvidence = members.allSatisfy {
        if case .known(true) = $0.storageTopology.mayShareBlocks { return true }
        return false
      }
      let everyObjectComplete = fileIDs.allSatisfy { objectComplete[$0] == true }
      let cloneRefCount: DiskplanPolicy.Observation<UInt32> =
        positiveCloneEvidence && everyObjectComplete
          && refCountValues.allSatisfy({ $0 != nil }) && refCounts.count == 1
          && refCounts.first == UInt32(exactly: fileIDs.count)
        ? .known(refCounts.first!) : .unknown(.incompleteCoverage)
      let cloneIdentity: DiskplanPolicy.Observation<ReleaseCloneIdentity> =
        positiveCloneEvidence && everyObjectComplete
          && cloneIdentities.count == 1 && fileIDs.count > 1
        ? .known(cloneIdentities.first!) : .unknown(.incompleteCoverage)
      let exactByteValues = members.map { node -> UInt64? in
        if case .exact(let value) = node.storageTopology.conditionalGroupReclaim {
          return value
        }
        return nil
      }
      let exactBytes = Set(exactByteValues.compactMap { $0 })
      let sharedBytes: DiskplanPolicy.Observation<UInt64> =
        cloneRefCount.knownValue != nil && exactByteValues.allSatisfy({ $0 != nil })
          && exactBytes.count == 1
        ? .known(exactBytes.first!) : .unknown(.incompleteCoverage)
      groups.append(
        RuntimeAllocationGroup(
          id: groupID,
          fileObjectIDs: fileIDs,
          cloneIdentity: cloneIdentity,
          cloneRefCount: cloneRefCount,
          sharedBytes: sharedBytes
        )
      )
      if cloneRefCount.knownValue == nil {
        for member in members {
          if let candidateID = assignedCandidateByPath[member.path] {
            dependencyCompleteByCandidate[candidateID] = false
          }
        }
      }
    }
    for fileID in filePathsByID.keys.sorted() {
      guard let paths = filePathsByID[fileID] else { continue }
      let members = paths.compactMap { evidence.sharedFileObservationsByPath[$0] }
      guard
        // Hardlinks prove shared ownership through one exact file-object identity
        // and st_nlink. known(false) here excludes clone-style sharing; it is not
        // a substitute for the positive clone gate above.
        members.allSatisfy({ node in
          guard case .absent = node.storageTopology.cloneID,
            case .known(false) = node.storageTopology.mayShareBlocks
          else { return false }
          return true
        }),
        members.contains(where: { ($0.storageTopology.linkCount.value ?? 0) > 1 })
      else { continue }
      let exactByteValues = members.map { node -> UInt64? in
        if case .exact(let value) = node.storageTopology.conditionalGroupReclaim {
          return value
        }
        return nil
      }
      let exactBytes = Set(exactByteValues.compactMap { $0 })
      let sharedBytes: DiskplanPolicy.Observation<UInt64> =
        objectComplete[fileID] == true && exactByteValues.allSatisfy({ $0 != nil })
          && exactBytes.count == 1
        ? .known(exactBytes.first!) : .unknown(.incompleteCoverage)
      groups.append(
        RuntimeAllocationGroup(
          id: "hardlink:\(fileID)",
          fileObjectIDs: [fileID],
          cloneIdentity: .absent,
          cloneRefCount: .known(1),
          sharedBytes: sharedBytes
        )
      )
    }
    return RuntimeReleaseOwnerIndex(
      owners: owners.sorted(by: runtimeReleaseOwnerPrecedes),
      allocationGroups: groups.sorted { $0.id < $1.id },
      dependencyCompleteByCandidate: dependencyCompleteByCandidate,
      overlaps: overlaps,
      overlappingCandidateIDs: overlappingCandidateIDs
    )
  }

  private func makeReleaseGraph(
    globalFacts: FrozenGlobalFacts,
    snapshots: [FrozenEvidenceSnapshot],
    candidates: [RecognizedRuntimeCandidate],
    ownerIndex: RuntimeReleaseOwnerIndex
  ) throws -> StorageReleaseGraph? {
    guard !snapshots.isEmpty else { return nil }
    let snapshotByID = Dictionary(
      uniqueKeysWithValues: snapshots.map { (Data($0.candidateID.utf8), $0) }
    )
    let candidateByID = Dictionary(
      uniqueKeysWithValues: candidates.map { (Data($0.id.utf8), $0) }
    )
    let storageCandidates = try snapshots.map { snapshot -> StorageCandidate in
      let node = candidateByID[Data(snapshot.candidateID.utf8)]!.node
      return try StorageCandidate(
        id: snapshot.candidateID,
        evidence: snapshot,
        immediatePrivateBytes: mapBytes(node.bytes.immediatePrivateReclaim)
      )
    }
    let provenance = GraphObservationProvenance(globalFacts: globalFacts)
    let ownersByFile = Dictionary(grouping: ownerIndex.owners, by: \.fileObjectID)
    let groupFileIDs = Set(ownerIndex.allocationGroups.flatMap(\.fileObjectIDs))
    let fileObjects = ownersByFile.keys.sorted().compactMap { fileID -> FileObjectNode? in
      guard groupFileIDs.contains(fileID), let owners = ownersByFile[fileID],
        !owners.isEmpty,
        owners.allSatisfy({ snapshotByID[Data($0.candidateID.utf8)] != nil })
      else { return nil }
      let linkCountValues = owners.map(\.linkCount.knownValue)
      let linkCounts = Set(linkCountValues.compactMap { $0 })
      let linkCount: DiskplanPolicy.Observation<UInt32> =
        linkCountValues.allSatisfy({ $0 != nil }) && linkCounts.count == 1
        ? .known(linkCounts.first!) : .unknown(.incompleteCoverage)
      return FileObjectNode(
        provenance: provenance,
        id: fileID,
        observedOwners: owners.map {
          FileOwnerLink(candidateID: $0.candidateID, path: $0.path)
        },
        ownerNamespaces: owners.map {
          FileOwnerNamespaceExpectation(
            link: FileOwnerLink(candidateID: $0.candidateID, path: $0.path),
            namespaceBinding: $0.namespaceBinding)
        },
        linkCount: linkCount
      )
    }
    let availableFiles = Set(fileObjects.map(\.id))
    let allocationGroups = ownerIndex.allocationGroups.compactMap {
      group -> AllocationGroupNode? in
      let fileIDs = group.fileObjectIDs.filter(availableFiles.contains)
      guard !fileIDs.isEmpty else { return nil }
      return AllocationGroupNode(
        provenance: provenance,
        id: group.id,
        ownerFileObjectIDs: fileIDs,
        cloneIdentity: group.cloneIdentity,
        cloneRefCount: group.cloneRefCount,
        sharedBytes: group.sharedBytes,
        snapshotBlocker: .unknown(.unavailableViaPublicAPI)
      )
    }
    return try StorageReleaseGraph(
      globalFacts: globalFacts,
      candidates: storageCandidates,
      fileObjects: fileObjects,
      allocationGroups: allocationGroups
    )
  }
}

private let buildNames = Set(
  ["build", "deriveddata", "dist", "target"].map { Data($0.utf8) })
private let cacheNames = Set(
  [".cache", "cache", "caches"].map { Data($0.utf8) })
private let temporaryNames = Set(
  ["tmp", "temp", "temporary"].map { Data($0.utf8) })
private let versionedArtifactParents = Set(
  ["artifacts", "releases", "versions"].map { Data($0.utf8) })

private func adapterScope(
  kind: RuntimeCandidateKind,
  node: ScannedNode,
  authority: RuntimeRecognizerAuthority
) -> AdapterScopeEvidence {
  // A type hint never selects a specialized mutation adapter. In particular,
  // `.codex-tmp` requires configured cleanup-scope evidence not collected here.
  if authority == .nameOnlyTypeHint { return .genericRemove }
  switch kind {
  case .codexTemporary:
    return .genericRemove
  case .versionedArtifact:
    let version = String(data: node.path.components.last!.bytes, encoding: .utf8) ?? "raw-version"
    return .versionedArtifactRemove(artifactKind: "versioned-artifact", version: version)
  case .gitLinkedWorktree, .buildOutput, .cache, .temporary, .providerReportOnly:
    return .genericRemove
  }
}

private func classificationClaims(
  kind: RuntimeCandidateKind,
  authority: RuntimeRecognizerAuthority
) -> [ClassificationClaim] {
  // Path names only select a report-only recognizer route. They do not establish
  // any semantic classification facet, including purpose or recoverability.
  if authority == .nameOnlyTypeHint || kind == .codexTemporary { return [] }
  let source: ClassificationSource
  switch kind {
  case .codexTemporary, .gitLinkedWorktree:
    source = .structuralRecognizer("runtime-policy-v1")
  case .providerReportOnly:
    source = .authoritativeAdapter("file-provider-api-v1")
  case .versionedArtifact, .buildOutput, .cache, .temporary:
    source = .pathConvention("runtime-policy-v1")
  }
  let values: [(ClassificationFacet, String)]
  switch kind {
  case .codexTemporary:
    values = [
      (.purpose, "codex-temporary-workspace"), (.lifecycle, "ephemeral"),
      (.ownership, "codex-managed"), (.recoverability, "recreatable"),
    ]
  case .gitLinkedWorktree:
    values = [
      (.purpose, "git-linked-worktree"), (.lifecycle, "workspace"),
      (.ownership, "git-managed"), (.recoverability, "requires-git-review"),
    ]
  case .versionedArtifact, .buildOutput, .cache, .temporary:
    values = []
  case .providerReportOnly:
    values = [
      (.purpose, "provider-managed"), (.lifecycle, "provider-controlled"),
      (.ownership, "file-provider"),
    ]
  }
  return values.map { facet, value in
    ClassificationClaim(
      facet: facet,
      value: value,
      source: source,
      evidenceKey: "runtime-policy-v1:\(kind.rawValue):\(facet.rawValue)"
    )
  }
}

private func recoverabilityEvidence(
  for candidate: RecognizedRuntimeCandidate
) -> (
  DiskplanPolicy.Observation<RecoverabilityState>,
  [RecoverabilityReviewFact]
) {
  // A path or structural marker is classification evidence, not a candidate-specific
  // manifest/producer/rebuild provenance chain. This seam never mints a static rebuild waiver.
  _ = candidate
  return (.unknown(.incompleteCoverage), [])
}

private func adapterRequest(for candidate: RecognizedRuntimeCandidate) -> ActionAdapterRequest {
  switch candidate.adapterScope {
  case .genericRemove:
    return .genericRemove
  case .codexCleanTemporary(let cleanupScopeID):
    return .codexCleanTemporary(cleanupScopeID: cleanupScopeID)
  case .versionedArtifactRemove(let kind, let version):
    return .versionedArtifactRemove(artifactKind: kind, version: version)
  case .gitWorktree, .completeReleaseSetRemove:
    return .genericRemove
  }
}

private func mapIdentity(
  _ observation: DiskplanScan.Observation<DiskplanScan.ObjectIdentity>
) -> DiskplanPolicy.Observation<DiskplanPolicy.ObjectIdentity> {
  switch observation {
  case .known(let identity):
    guard identity.device >= 0, let kind = mapObjectKind(identity.objectType) else {
      return .failed(ObservationFailure(code: "invalid_identity", collector: "scanner"))
    }
    return .known(
      DiskplanPolicy.ObjectIdentity(
        device: UInt64(identity.device),
        object: identity.fileID,
        generation: .unknown(.unavailableViaPublicAPI),
        type: kind
      )
    )
  case .absent:
    return .absent
  case .unknown:
    return .unknown(.incompleteCoverage)
  case .unreadable(_, let code):
    return .unreadable(
      ObservationFailure(code: errorCode(code), collector: "scanner.identity"))
  case .failed(_, let code):
    return .failed(ObservationFailure(code: errorCode(code), collector: "scanner.identity"))
  }
}

private func mapObjectKind(_ type: ScannedObjectType) -> ObjectKind? {
  switch type {
  case .regular: .regularFile
  case .directory: .directory
  case .symbolicLink: .symbolicLink
  case .other: nil
  }
}

private func mapCoverage(_ coverage: Coverage) -> EvidenceCoverage {
  guard coverage.completeness == .partial else { return .complete }
  let reasons = Set(coverage.reasons)
  if reasons.contains(.permissionDenied) || reasons.contains(.unreadable) {
    return .permissionDenied
  }
  if reasons.contains(.timedOut) { return .timedOut }
  if reasons.contains(.budgetExhausted) { return .budgetExhausted }
  if reasons.contains(.mountBoundary) { return .mountBoundary }
  if reasons.contains(.providerMetadataOnly) { return .providerMetadataOnly }
  if reasons.contains(.notRequestedByProfile) { return .notRequestedByProfile }
  return .collectorFailed
}

private func mapProviderBoundary(
  _ boundary: ProviderBoundary
) -> DiskplanPolicy.Observation<ProviderState> {
  switch boundary {
  case .localOrUnindicated: .known(.local)
  case .metadataOnly, .rejected: .known(.fileProviderManaged)
  case .unverified: .unknown(.incompleteCoverage)
  }
}

private func mapProviderState(
  rootBoundary: ProviderBoundary,
  node: ScannedNode,
  ancestors: [ScannedNode]
) -> DiskplanPolicy.Observation<ProviderState> {
  let boundaries = [rootBoundary, node.providerBoundary] + ancestors.map(\.providerBoundary)
  if boundaries.contains(where: {
    if case .metadataOnly = $0 { return true }
    if case .rejected = $0 { return true }
    return false
  }) {
    return .known(.fileProviderManaged)
  }
  if boundaries.allSatisfy({ if case .localOrUnindicated = $0 { true } else { false } }) {
    return .known(.local)
  }
  return .unknown(.incompleteCoverage)
}

private func mapAccessPolicy(
  _ observation: DiskplanScan.Observation<AccessPolicyEvidence>
) -> DiskplanPolicy.Observation<String> {
  switch observation {
  case .known(let value):
    return .known(
      "uid=\(value.ownerUserID);gid=\(value.ownerGroupID);mode=\(value.mode);flags=\(value.flags)"
    )
  case .absent:
    return .absent
  case .unknown:
    return .unknown(.incompleteCoverage)
  case .unreadable(_, let code):
    return .unreadable(
      ObservationFailure(code: errorCode(code), collector: "scanner.access-policy"))
  case .failed(_, let code):
    return .failed(
      ObservationFailure(code: errorCode(code), collector: "scanner.access-policy"))
  }
}

private func mapProtection(
  _ observation: DiskplanScan.Observation<AccessPolicyEvidence>
) -> DiskplanPolicy.Observation<ExplicitProtectionState> {
  observationToPolicy(observation) { access in
    let protectedMask: UInt32 =
      0x2 | 0x4 | 0x10 | 0x0002_0000 | 0x0004_0000 | 0x0008_0000
      | 0x0010_0000
    return access.flags & protectedMask == 0 ? .notProtected : .protected
  }
}

private func mapForceRequirement(
  _ observation: DiskplanScan.Observation<AccessPolicyEvidence>
) -> DiskplanPolicy.Observation<ForceRequirement> {
  observationToPolicy(observation) { access in
    access.mode & 0o200 == 0 ? .requiresForceWithWarning : .notRequired
  }
}

private func mapMountIdentity(
  _ observation: DiskplanScan.Observation<DiskplanScan.ObjectIdentity>
) -> DiskplanPolicy.Observation<String> {
  observationToPolicy(observation) { "real-device:\($0.device)" }
}

private func mapContentProtection(
  _ node: ScannedNode
) -> DiskplanPolicy.Observation<ContentProtectionBaseline> {
  switch node.identity.value?.objectType {
  case .directory, .symbolicLink:
    return .known(.explicitlyNotApplicable(.metadataOnlyObject))
  case .regular, .other, nil:
    return .unknown(.unavailableViaPublicAPI)
  }
}

private func mapActivity(
  _ observation: DiskplanScan.Observation<[ProcessActivityRecord]>,
  root: Data,
  target: [Data]
) -> DiskplanPolicy.Observation<ActivityState> {
  switch observation {
  case .known(let records):
    let absolute = joinAbsolutePath(root: root, components: target)
    let active = records.contains { pathContains($0.rawPath, prefix: absolute) }
    return .known(active ? .active : .inactive)
  case .absent:
    return .absent
  case .unknown:
    return .unknown(.incompleteCoverage)
  case .unreadable(_, let code):
    return .unreadable(
      ObservationFailure(code: errorCode(code), collector: "scanner.process-activity"))
  case .failed(_, let code):
    return .failed(
      ObservationFailure(code: errorCode(code), collector: "scanner.process-activity"))
  }
}

private func mapUInt32Observation(
  _ observation: DiskplanScan.Observation<UInt32>
) -> DiskplanPolicy.Observation<UInt32> {
  observationToPolicy(observation) { $0 }
}

private func mapBytes(_ measure: ByteMeasure) -> DiskplanPolicy.Observation<UInt64> {
  switch measure {
  case .exact(let value): .known(value)
  case .lowerBound, .unknown: .unknown(.incompleteCoverage)
  }
}

private func observationToPolicy<Source, Target>(
  _ observation: DiskplanScan.Observation<Source>,
  transform: (Source) -> Target
) -> DiskplanPolicy.Observation<Target>
where Source: Equatable & Sendable, Target: Equatable & Sendable {
  switch observation {
  case .known(let value): .known(transform(value))
  case .absent: .absent
  case .unknown: .unknown(.incompleteCoverage)
  case .unreadable(_, let code):
    .unreadable(ObservationFailure(code: errorCode(code), collector: "scanner"))
  case .failed(_, let code):
    .failed(ObservationFailure(code: errorCode(code), collector: "scanner"))
  }
}

private func makeDisplayMetrics(
  candidate: RecognizedRuntimeCandidate,
  referenceTimeSeconds: Int64
) -> ActionDisplayMetrics {
  let immediate: KnownOrUnknown<UInt64>
  switch candidate.node.bytes.immediatePrivateReclaim {
  case .exact(let value): immediate = .known(value)
  case .lowerBound, .unknown: immediate = .unknown(.incompleteCoverage)
  }
  let inactive = inactiveDuration(
    candidate.node.filesystemTimes,
    referenceTimeSeconds: referenceTimeSeconds
  )
  return ActionDisplayMetrics(
    immediateReclaimBytes: immediate,
    inactiveDurationSeconds: inactive,
    rebuildCost: .unknown(.unavailableViaPublicAPI),
    cleanupCost: .unknown(.unavailableViaPublicAPI),
    canonicalRawPath: candidate.node.path.components.reduce(into: Data()) { result, component in
      if !result.isEmpty { result.append(47) }
      result.append(component.bytes)
    }
  )
}

private func inactiveDuration(
  _ times: FilesystemTimeEvidence,
  referenceTimeSeconds: Int64
) -> KnownOrUnknown<UInt64> {
  let known = [times.accessTime.value, times.modificationTime.value].compactMap { $0 }
  guard
    let latest = known.max(by: {
      ($0.secondsSinceEpoch, $0.nanoseconds) < ($1.secondsSinceEpoch, $1.nanoseconds)
    }), latest.secondsSinceEpoch <= referenceTimeSeconds
  else {
    return .unknown(.incompleteCoverage)
  }
  return .known(UInt64(referenceTimeSeconds - latest.secondsSinceEpoch))
}

private func encodeScanConfiguration(_ reference: ScanReference) -> Data {
  var encoder = RuntimeAuthorityEncoder(domain: "scan-configuration-v1")
  let scope = reference.resolvedScope
  encoder.uint32(scope.resolverVersion)
  encoder.data(Data(scope.profile.rawValue.utf8))
  encoder.uint64(scope.budget.maximumEntriesPerRoot)
  encoder.uint64(UInt64(scope.budget.maximumDepth))
  encoder.uint64(UInt64(scope.budget.retainedNodeCount))
  encoder.uint64(scope.budget.maximumEntriesPerDirectory)
  encoder.uint64(scope.budget.maximumPendingNameBytes)
  encoder.optionalUInt64(scope.maximumDurationNanoseconds)
  encoder.array(scope.roots) { encoder, root in
    encoder.data(Data(root.rootID.utf8))
    encoder.data(root.rawAbsolutePath)
  }
  encoder.data(Data(reference.collectorConfiguration.processActivityCollectorID.utf8))
  encoder.optionalUInt64(reference.collectorConfiguration.processActivityDeadlineNanoseconds)
  encoder.array(reference.collectorConfiguration.globalFactCollectorIDs) { encoder, collectorID in
    encoder.data(Data(collectorID.utf8))
  }
  return encoder.data
}

private func encodeAuthorityConfiguration(_ result: AuthorityScanResult) -> Data {
  var encoder = RuntimeAuthorityEncoder(domain: "authority-configuration-v1")
  encoder.data(encodeScanConfiguration(result.reference))
  encodeGlobalFacts(result.globalFacts, into: &encoder)
  encodeScanObservation(result.processActivity, into: &encoder) { encoder, records in
    encoder.array(records.sorted()) { encoder, record in
      encoder.uint32(UInt32(bitPattern: record.processID))
      encoder.optionalData(record.command.map { Data($0.utf8) })
      encoder.optionalData(record.fileDescriptor.map { Data($0.utf8) })
      encoder.data(record.rawPath)
    }
  }
  return encoder.data
}

private func encodeCaptureDigest(
  scanResult: AuthorityScanResult,
  evidence: AuthorityEvidenceSnapshot,
  authorityConfiguration: Data
) throws -> PolicyDigest {
  var encoder = RuntimeAuthorityEncoder(domain: "scan-capture-v1", hashingOnly: true)
  encoder.data(authorityConfiguration)
  encoder.int64(scanResult.reference.wallClock.timeIntervalSince1970.bitPatternAsInt64)
  encoder.uint64(scanResult.reference.monotonicNanoseconds)
  encoder.data(Data(scanResult.state.rawValue.utf8))
  encoder.data(
    Data(scanResult.coverage.completeness == .complete ? "complete".utf8 : "partial".utf8))
  encoder.array(scanResult.coverage.reasons) { encoder, reason in
    encoder.data(Data(reason.rawValue.utf8))
  }
  let candidatePaths = evidence.candidatesByPath.keys.sorted()
  encoder.array(candidatePaths) { encoder, path in
    let candidate = evidence.candidatesByPath[path]!
    encodeNode(candidate.node, into: &encoder)
    encoder.bool(candidate.isClosed)
    encoder.data(Data(candidate.kind.rawValue.utf8))
    encoder.data(Data(candidate.recognizerAuthority.rawValue.utf8))
    encoder.array(candidate.ancestors) { encoder, node in encodeNode(node, into: &encoder) }
  }
  let sharedFilePaths = evidence.sharedFileObservationsByPath.keys.sorted()
  encoder.array(sharedFilePaths) { encoder, path in
    let node = evidence.sharedFileObservationsByPath[path]!
    encodeNode(node, into: &encoder)
    encoder.array(evidence.sharedFileAncestorsByPath[path] ?? []) { encoder, ancestor in
      encodeNode(ancestor, into: &encoder)
    }
  }
  encoder.array(evidence.issues) { encoder, issue in
    encodeIssue(issue, into: &encoder)
  }
  encoder.uint64(evidence.retention.candidateSummariesOmitted)
  encoder.uint64(evidence.retention.sharedObjectKeysOmitted)
  encoder.uint64(evidence.retention.ownerReferencesOmitted)
  encoder.uint64(evidence.retention.corpusIssuesOmitted)
  encoder.uint64(evidence.retention.finalizationInputsOmitted)
  encoder.uint64(UInt64(evidence.retention.estimatedRetainedBytes))
  encoder.uint64(UInt64(evidence.retention.finalizedInputBytes))
  encoder.uint64(UInt64(evidence.retention.estimatedPlanningBytes))
  encoder.uint64(UInt64(evidence.retention.maximumPlanningBytes))
  encoder.bool(evidence.retention.planningBudgetExceeded)
  encoder.bool(evidence.topologyCoverageIncomplete)
  encoder.array(scanResult.roots.sorted(by: rootResultPrecedes)) { encoder, root in
    encoder.data(Data(root.binding.rootID.utf8))
    encoder.uint32(root.binding.resolverVersion)
    encoder.data(root.binding.rawAbsolutePath)
    encoder.int64(root.binding.identity.device)
    encoder.uint64(root.binding.identity.fileID)
    encoder.data(Data(root.binding.identity.objectType.rawValue.utf8))
    encoder.data(Data(describeProvider(root.providerBoundary).utf8))
    encodeByteMeasure(root.aggregateBytes.logical, into: &encoder)
    encodeByteMeasure(root.aggregateBytes.nominalAllocated, into: &encoder)
    encodeByteMeasure(root.aggregateBytes.immediatePrivateReclaim, into: &encoder)
    encoder.data(
      Data(root.coverage.completeness == .complete ? "complete".utf8 : "partial".utf8))
    encoder.array(root.coverage.reasons) { encoder, reason in
      encoder.data(Data(reason.rawValue.utf8))
    }
    encoder.uint64(root.entriesObserved)
    encoder.uint64(root.directoriesClosed)
  }
  encoder.array(scanResult.rootFailures.sorted(by: rootFailurePrecedes)) { encoder, failure in
    encoder.data(Data(failure.rootID.utf8))
    encodeScanObservation(failure.observation, into: &encoder) { encoder, value in
      encoder.data(Data(value.utf8))
    }
  }
  return try PolicyDigest(bytes: encoder.finalizeHash())
}

private func encodeNode(_ node: ScannedNode, into encoder: inout RuntimeAuthorityEncoder) {
  encodePath(node.path, into: &encoder)
  encodeScanObservation(node.identity, into: &encoder) { encoder, identity in
    encoder.int64(identity.device)
    encoder.uint64(identity.fileID)
    encoder.data(Data(identity.objectType.rawValue.utf8))
  }
  encodeByteMeasure(node.bytes.logical, into: &encoder)
  encodeByteMeasure(node.bytes.nominalAllocated, into: &encoder)
  encodeByteMeasure(node.bytes.immediatePrivateReclaim, into: &encoder)
  encodeScanObservation(node.storageTopology.linkCount, into: &encoder) { encoder, value in
    encoder.uint32(value)
  }
  encodeScanObservation(node.storageTopology.mayShareBlocks, into: &encoder) { encoder, value in
    encoder.bool(value)
  }
  encodeScanObservation(node.storageTopology.sharesAllBlocks, into: &encoder) { encoder, value in
    encoder.bool(value)
  }
  encodeScanObservation(node.storageTopology.cloneID, into: &encoder) { encoder, value in
    encoder.uint64(value)
  }
  encodeScanObservation(node.storageTopology.cloneRefcount, into: &encoder) { encoder, value in
    encoder.uint32(value)
  }
  encodeByteMeasure(node.storageTopology.conditionalGroupReclaim, into: &encoder)
  encodeFilesystemTimes(node.filesystemTimes, into: &encoder)
  encodeScanObservation(node.accessPolicy, into: &encoder) { encoder, policy in
    encoder.uint32(policy.ownerUserID)
    encoder.uint32(policy.ownerGroupID)
    encoder.uint32(policy.mode)
    encoder.uint32(policy.flags)
  }
  encoder.data(Data(node.coverage.completeness == .complete ? "complete".utf8 : "partial".utf8))
  encoder.array(node.coverage.reasons) { encoder, reason in
    encoder.data(Data(reason.rawValue.utf8))
  }
  encoder.data(Data(describeProvider(node.providerBoundary).utf8))
  encodeScanObservation(node.providerEvidence, into: &encoder) { encoder, provider in
    encodeScanObservation(provider.identity, into: &encoder) { encoder, identity in
      encoder.data(Data(identity.itemIdentifier.utf8))
      encoder.data(Data(identity.domainIdentifier.utf8))
    }
    encodeScanObservation(provider.promisedMetadata, into: &encoder) { encoder, metadata in
      encoder.array(metadata.keys.sorted()) { encoder, key in
        encoder.data(Data(key.utf8))
        encoder.data(Data(metadata[key]!.utf8))
      }
    }
    encodeByteMeasure(provider.hiddenBackingBytes, into: &encoder)
    encodeScanObservation(
      provider.controlledNonMaterializationAcceptance,
      into: &encoder
    ) { encoder, accepted in encoder.bool(accepted) }
  }
}

private func encodeFilesystemTimes(
  _ times: FilesystemTimeEvidence,
  into encoder: inout RuntimeAuthorityEncoder
) {
  encoder.data(Data(times.trust.rawValue.utf8))
  for observation in [
    times.accessTime, times.modificationTime, times.statusChangeTime, times.birthTime,
  ] {
    encodeScanObservation(observation, into: &encoder) { encoder, time in
      encoder.int64(time.secondsSinceEpoch)
      encoder.uint32(UInt32(bitPattern: time.nanoseconds))
    }
  }
}

private func encodeGlobalFacts(
  _ facts: GlobalScanFacts,
  into encoder: inout RuntimeAuthorityEncoder
) {
  encodeGlobalFact(facts.vm, into: &encoder) { encoder, values in
    encoder.array(values.keys.sorted()) { encoder, key in
      encoder.data(Data(key.utf8))
      encoder.uint64(values[key]!)
    }
  }
  encodeGlobalFact(facts.swap, into: &encoder) { encoder, values in
    encoder.array(values.keys.sorted()) { encoder, key in
      encoder.data(Data(key.utf8))
      encoder.uint64(values[key]!)
    }
  }
  encodeGlobalFact(facts.apfsSnapshots, into: &encoder) { encoder, snapshots in
    encoder.array(snapshots.sorted()) { encoder, snapshot in
      encoder.data(Data(snapshot.utf8))
    }
  }
}

private func encodeGlobalFact<Value>(
  _ fact: GlobalFact<Value>,
  into encoder: inout RuntimeAuthorityEncoder,
  encodeKnown: (inout RuntimeAuthorityEncoder, Value) -> Void
) where Value: Equatable & Sendable {
  switch fact {
  case .known(let value):
    encoder.byte(0)
    encodeKnown(&encoder, value)
  case .unavailable(let reason):
    encoder.byte(1)
    encoder.data(Data(reason.utf8))
  }
}

private func encodePath(_ path: RawPath, into encoder: inout RuntimeAuthorityEncoder) {
  encoder.data(Data(path.rootID.utf8))
  encoder.array(path.components) { encoder, component in encoder.data(component.bytes) }
}

private func encodeByteMeasure(_ measure: ByteMeasure, into encoder: inout RuntimeAuthorityEncoder)
{
  switch measure {
  case .exact(let value):
    encoder.byte(0)
    encoder.uint64(value)
  case .lowerBound(let value, let reason):
    encoder.byte(1)
    encoder.uint64(value)
    encoder.data(Data(reason.utf8))
  case .unknown(let reason):
    encoder.byte(2)
    encoder.data(Data(reason.utf8))
  }
}

private func encodeScanObservation<Value>(
  _ observation: DiskplanScan.Observation<Value>,
  into encoder: inout RuntimeAuthorityEncoder,
  encodeKnown: (inout RuntimeAuthorityEncoder, Value) -> Void
) where Value: Equatable & Sendable {
  switch observation {
  case .known(let value):
    encoder.byte(0)
    encodeKnown(&encoder, value)
  case .absent(let reason):
    encoder.byte(1)
    encoder.data(Data(reason.utf8))
  case .unknown(let reason):
    encoder.byte(2)
    encoder.data(Data(reason.utf8))
  case .unreadable(let reason, let code):
    encoder.byte(3)
    encoder.data(Data(reason.utf8))
    encoder.optionalInt32(code)
  case .failed(let reason, let code):
    encoder.byte(4)
    encoder.data(Data(reason.utf8))
    encoder.optionalInt32(code)
  }
}

struct RuntimeAuthorityEncoder {
  private var storage = Data()
  private var hasher: SHA256?
  private var hashBuffer = Data()
  private(set) var maximumHashBufferBytes = 0

  var data: Data {
    precondition(hasher == nil, "hash-only encoder does not retain encoded bytes")
    return storage
  }

  init(domain: String, hashingOnly: Bool = false) {
    hasher = hashingOnly ? SHA256() : nil
    self.data(Data(domain.utf8))
  }

  mutating func byte(_ value: UInt8) { appendRaw(Data([value])) }
  mutating func bool(_ value: Bool) { byte(value ? 1 : 0) }
  mutating func uint32(_ value: UInt32) {
    var value = value.bigEndian
    appendRaw(Data(bytes: &value, count: MemoryLayout<UInt32>.size))
  }
  mutating func uint64(_ value: UInt64) {
    var value = value.bigEndian
    appendRaw(Data(bytes: &value, count: MemoryLayout<UInt64>.size))
  }
  mutating func int64(_ value: Int64) { uint64(UInt64(bitPattern: value)) }
  mutating func data(_ value: Data) {
    uint64(UInt64(value.count))
    appendRaw(value)
  }
  mutating func optionalUInt64(_ value: UInt64?) {
    bool(value != nil)
    if let value { uint64(value) }
  }
  mutating func optionalInt32(_ value: Int32?) {
    bool(value != nil)
    if let value { uint32(UInt32(bitPattern: value)) }
  }
  mutating func optionalData(_ value: Data?) {
    bool(value != nil)
    if let value { data(value) }
  }
  mutating func array<Element>(
    _ values: [Element],
    encode: (inout RuntimeAuthorityEncoder, Element) -> Void
  ) {
    uint64(UInt64(values.count))
    for value in values { encode(&self, value) }
  }

  mutating func finalizeHash() -> Data {
    precondition(hasher != nil, "byte-retaining encoder does not own a streaming hash")
    flushHashBuffer()
    guard let currentHasher = hasher else {
      preconditionFailure("hash-only encoder lost its streaming hash")
    }
    let digest = currentHasher.finalize()
    hasher = nil
    return Data(digest)
  }

  private mutating func appendRaw(_ value: Data) {
    guard hasher != nil else {
      storage.append(value)
      return
    }
    if value.count >= 64 * 1_024 {
      flushHashBuffer()
      guard var currentHasher = hasher else {
        preconditionFailure("hash-only encoder lost its streaming hash")
      }
      currentHasher.update(data: value)
      hasher = currentHasher
      return
    }
    if hashBuffer.count >= 64 * 1_024 - value.count { flushHashBuffer() }
    hashBuffer.append(value)
    maximumHashBufferBytes = max(maximumHashBufferBytes, hashBuffer.count)
    if hashBuffer.count >= 64 * 1_024 { flushHashBuffer() }
  }

  private mutating func flushHashBuffer() {
    guard !hashBuffer.isEmpty else { return }
    guard var currentHasher = hasher else {
      preconditionFailure("byte-retaining encoder cannot flush a hash buffer")
    }
    currentHasher.update(data: hashBuffer)
    hasher = currentHasher
    hashBuffer.removeAll(keepingCapacity: true)
  }
}

private func candidateID(rawRoot: Data?, node: ScannedNode) -> String {
  var encoder = RuntimeAuthorityEncoder(domain: "candidate-id-v1")
  encoder.data(Data(node.path.rootID.utf8))
  encoder.data(rawRoot ?? Data(node.path.rootID.utf8))
  encoder.array(node.path.components) { encoder, component in encoder.data(component.bytes) }
  return "candidate-"
    + SHA256.hash(data: encoder.data).map {
      String(format: "%02x", $0)
    }.joined()
}

private func fileObjectID(_ identity: DiskplanScan.ObjectIdentity) -> String {
  "object:\(identity.device):\(identity.fileID):\(identity.objectType.rawValue)"
}

private func asciiLowercased(_ data: Data) -> Data {
  Data(data.map { byte in (65...90).contains(byte) ? byte + 32 : byte })
}

private func isVersionComponent(_ data: Data) -> Bool {
  let bytes = Array(data)
  guard !bytes.isEmpty else { return false }
  var index = bytes.first == UInt8(ascii: "v") ? 1 : 0
  guard index < bytes.count else { return false }
  var sawDigit = false
  while index < bytes.count {
    let byte = bytes[index]
    if (48...57).contains(byte) {
      sawDigit = true
    } else if byte != 46 && byte != 45 && byte != 95 {
      return false
    }
    index += 1
  }
  return sawDigit
}

private func joinAbsolutePath(root: Data, components: [Data]) -> Data {
  var result = root
  for component in components {
    if result.last != UInt8(ascii: "/") { result.append(UInt8(ascii: "/")) }
    result.append(component)
  }
  return result
}

private func pathContains(_ path: Data, prefix: Data) -> Bool {
  guard path.starts(with: prefix) else { return false }
  let boundaryIndex = path.index(path.startIndex, offsetBy: prefix.count)
  return path.count == prefix.count || prefix.last == UInt8(ascii: "/")
    || path[boundaryIndex] == UInt8(ascii: "/")
}

private func errorCode(_ code: Int32?) -> String {
  code.map { "errno:\($0)" } ?? "unavailable"
}

private func describeProvider(_ boundary: ProviderBoundary) -> String {
  switch boundary {
  case .localOrUnindicated: "local_or_unindicated"
  case .metadataOnly(let reason): "metadata_only:\(reason)"
  case .rejected(let reason): "rejected:\(reason)"
  case .unverified(let reason): "unverified:\(reason)"
  }
}

private func isProviderManaged(_ boundary: ProviderBoundary) -> Bool {
  switch boundary {
  case .metadataOnly, .rejected: true
  case .localOrUnindicated, .unverified: false
  }
}

private func encodeIssue(
  _ issue: ScanCorpusIssue,
  into encoder: inout RuntimeAuthorityEncoder
) {
  switch issue {
  case .conflictingObservation(let path):
    encoder.byte(0)
    encodePath(path, into: &encoder)
  case .directoryCloseWithoutObservation(let path):
    encoder.byte(1)
    encodePath(path, into: &encoder)
  case .conflictingDirectoryClose(let path):
    encoder.byte(2)
    encodePath(path, into: &encoder)
  case .nonDirectoryClose(let path):
    encoder.byte(3)
    encodePath(path, into: &encoder)
  }
}

private func scanCorpusIssuePrecedes(_ lhs: ScanCorpusIssue, _ rhs: ScanCorpusIssue) -> Bool {
  var left = RuntimeAuthorityEncoder(domain: "corpus-issue-v1")
  var right = RuntimeAuthorityEncoder(domain: "corpus-issue-v1")
  encodeIssue(lhs, into: &left)
  encodeIssue(rhs, into: &right)
  return left.data.lexicographicallyPrecedes(right.data)
}

private func rootResultPrecedes(_ lhs: RootScanResult, _ rhs: RootScanResult) -> Bool {
  let left = Data(lhs.binding.rootID.utf8)
  let right = Data(rhs.binding.rootID.utf8)
  if left != right { return left.lexicographicallyPrecedes(right) }
  return lhs.binding.rawAbsolutePath.lexicographicallyPrecedes(rhs.binding.rawAbsolutePath)
}

private func rootFailurePrecedes(
  _ lhs: (rootID: String, observation: DiskplanScan.Observation<String>),
  _ rhs: (rootID: String, observation: DiskplanScan.Observation<String>)
) -> Bool {
  Data(lhs.rootID.utf8).lexicographicallyPrecedes(Data(rhs.rootID.utf8))
}

private func recognizedCandidatePrecedes(
  _ lhs: RecognizedRuntimeCandidate,
  _ rhs: RecognizedRuntimeCandidate
) -> Bool {
  if lhs.kind != rhs.kind { return lhs.kind.rawValue < rhs.kind.rawValue }
  return lhs.node.path < rhs.node.path
}

private func runtimeReleaseOwnerPrecedes(
  _ lhs: RuntimeReleaseOwner,
  _ rhs: RuntimeReleaseOwner
) -> Bool {
  if lhs.fileObjectID != rhs.fileObjectID { return lhs.fileObjectID < rhs.fileObjectID }
  if lhs.candidateID != rhs.candidateID { return lhs.candidateID < rhs.candidateID }
  return lhs.path < rhs.path
}

private func rejectionReasons(for error: Error) -> [RuntimeAuthorityReason] {
  guard let error = error as? RuntimePolicyAuthorityError else {
    return [.collectorIncomplete, .namespaceAncestorUnavailable]
  }
  switch error {
  case .rootBindingMissing:
    return [.rootCoverageIncomplete, .namespaceAncestorUnavailable]
  case .invalidObjectIdentity:
    return [.identityUnavailable, .namespaceAncestorUnavailable]
  case .invalidRawPath:
    return [.namespaceAncestorUnavailable]
  case .invalidReferenceTime, .policyModel:
    return [.collectorIncomplete]
  }
}

extension Array where Element: Comparable {
  fileprivate func binarySearch(_ value: Element) -> Bool {
    var lower = startIndex
    var upper = endIndex
    while lower < upper {
      let middle = index(lower, offsetBy: distance(from: lower, to: upper) / 2)
      if self[middle] == value { return true }
      if self[middle] < value {
        lower = index(after: middle)
      } else {
        upper = middle
      }
    }
    return false
  }
}

extension TimeInterval {
  fileprivate var bitPatternAsInt64: Int64 { Int64(bitPattern: bitPattern) }
}
