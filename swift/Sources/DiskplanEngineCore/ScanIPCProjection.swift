import DiskplanProto
import DiskplanScan
import Foundation

enum ScanIPCProjection {
  static func progress(
    _ result: ScanResult,
    elapsedMillis: UInt64
  ) -> Diskplan_V1_ScanProgress {
    var message = Diskplan_V1_ScanProgress()
    message.profile = result.reference.profileID
    message.elapsedMillis = elapsedMillis
    message.entries = result.progress.entriesObserved
    message.directories = result.progress.directoriesClosed
    message.candidates = 0
    message.allocatedBytesObserved = result.roots.reduce(0) {
      addingSaturated($0, $1.aggregateBytes.nominalAllocated.conservativeLowerBound)
    }
    // This compatibility field belongs to the Phase 0 plan shell. Phase 1
    // transports typed byte evidence but does not author a reclaim estimate.
    message.reclaimEstimateBytes = 0
    message.completeRoots = result.progress.rootsComplete
    message.partialRoots = result.progress.rootsPartial
    message.entriesPerSecond = elapsedMillis == 0
      ? 0 : multiplyingSaturated(result.progress.entriesObserved, 1_000) / elapsedMillis
    message.currentRoot = currentRootDisplay(result)
    message.structuralBudget = result.reference.resolvedScope.budget.maximumEntriesPerRoot
    message.retainedNodes = UInt64(result.progress.retainedNodes.count)
    return message
  }

  static func checkpoint(
    _ result: ScanResult,
    elapsedMillis: UInt64,
    resumable: Bool,
    provisional: Bool
  ) -> Diskplan_V1_ScanCheckpointEvidence {
    let scope = result.reference.resolvedScope
    var message = Diskplan_V1_ScanCheckpointEvidence()
    message.profile = result.reference.profileID
    message.resolverVersion = result.reference.resolverVersion
    let wallMillis = result.reference.wallClock.timeIntervalSince1970 * 1_000
    message.wallClockUnixMillis = wallMillis > 0 ? UInt64(wallMillis) : 0
    message.monotonicNanoseconds = result.reference.monotonicNanoseconds
    message.maximumEntriesPerRoot = scope.budget.maximumEntriesPerRoot
    message.maximumDepth = UInt32(clamping: scope.budget.maximumDepth)
    message.maximumEntriesPerDirectory = scope.budget.maximumEntriesPerDirectory
    message.maximumPendingNameBytes = scope.budget.maximumPendingNameBytes
    message.retainedNodeCount = UInt32(clamping: scope.budget.retainedNodeCount)
    if let duration = scope.maximumDurationNanoseconds {
      message.maximumDurationMillis = duration / 1_000_000
    }
    message.resolvedRoots = scope.roots.map(rootRequest)
    message.progress = progress(result, elapsedMillis: elapsedMillis)
    message.coverage = coverage(result.coverage)
    message.retainedNodes = result.progress.retainedNodes.map {
      node($0, roots: scope.roots)
    }
    message.completedRoots = result.roots.map(root)
    message.rootFailures = result.rootFailures.sorted { $0.rootID < $1.rootID }.map {
      rootID, observation in
      var failure = Diskplan_V1_RootFailureEvidence()
      failure.rootID = rootID
      failure.observation = evidenceFailure(observation)
      return failure
    }
    message.processActivityObservation = evidenceFailure(result.processActivity)
    if case .known(let activity) = result.processActivity {
      message.processActivity = activity.map(processActivity)
    }
    message.machineState = machineState(result.state)
    message.resumableInProcess = resumable
    message.provisional = provisional
    message.collectorConfiguration = collectorConfiguration(
      result.reference.collectorConfiguration)
    message.vm = globalUInt64Fact(result.globalFacts.vm)
    message.swap = globalUInt64Fact(result.globalFacts.swap)
    message.apfsSnapshots = globalStringFact(result.globalFacts.apfsSnapshots)
    return message
  }

  static func node(
    _ value: ScannedNode,
    roots: [ScanRootRequest]
  ) -> Diskplan_V1_ScannedNodeEvidence {
    var message = Diskplan_V1_ScannedNodeEvidence()
    message.path = rawPath(value.path, roots: roots)
    message.identity = identity(value.identity)
    message.bytes = bytes(value.bytes)
    message.storageTopology = storageTopology(value.storageTopology)
    message.filesystemTimes = filesystemTimes(value.filesystemTimes)
    message.accessPolicy = accessPolicy(value.accessPolicy)
    message.coverage = coverage(value.coverage)
    let boundary = providerBoundary(value.providerBoundary)
    message.providerBoundary = boundary.kind
    message.providerBoundaryReason = boundary.reason
    message.providerEvidence = providerEvidence(value.providerEvidence)
    return message
  }

  static func displayRawBytes(_ bytes: Data) -> String {
    if let value = String(data: bytes, encoding: .utf8),
      value.unicodeScalars.allSatisfy({ scalar in
        switch scalar.properties.generalCategory {
        case .control, .format, .lineSeparator, .paragraphSeparator, .surrogate:
          return false
        default:
          return true
        }
      })
    {
      return value
    }
    return bytes.map { String(format: "\\x%02x", $0) }.joined()
  }

  private static func root(_ value: RootScanResult) -> Diskplan_V1_RootScanEvidence {
    var message = Diskplan_V1_RootScanEvidence()
    message.root = rootRequest(
      ScanRootRequest(
        rootID: value.binding.rootID,
        rawAbsolutePath: value.binding.rawAbsolutePath
      ))
    message.identity = identity(.known(value.binding.identity))
    let boundary = providerBoundary(value.providerBoundary)
    message.providerBoundary = boundary.kind
    message.providerBoundaryReason = boundary.reason
    message.aggregateBytes = bytes(value.aggregateBytes)
    message.coverage = coverage(value.coverage)
    message.entriesObserved = value.entriesObserved
    message.directoriesClosed = value.directoriesClosed
    return message
  }

  static func rootRequest(_ value: ScanRootRequest) -> Diskplan_V1_ScanRootRequest {
    var message = Diskplan_V1_ScanRootRequest()
    message.rootID = value.rootID
    message.rawAbsolutePath = value.rawAbsolutePath
    message.displayPath = displayRawBytes(value.rawAbsolutePath)
    return message
  }

  private static func rawPath(
    _ value: RawPath,
    roots: [ScanRootRequest]
  ) -> Diskplan_V1_RawPath {
    var message = Diskplan_V1_RawPath()
    message.rootID = value.rootID
    message.components = value.components.map(\.bytes)
    let root =
      roots.first(where: { $0.rootID == value.rootID })
      .map { displayRawBytes($0.rawAbsolutePath) } ?? value.rootID
    message.displayPath = value.components.reduce(root) { partial, component in
      let displayName = displayRawBytes(component.bytes)
      return partial == "/" ? partial + displayName : partial + "/" + displayName
    }
    return message
  }

  private static func identity(
    _ value: Observation<ObjectIdentity>
  ) -> Diskplan_V1_ObjectIdentityEvidence {
    var message = Diskplan_V1_ObjectIdentityEvidence()
    message.observation = evidenceFailure(value)
    if case .known(let identity) = value {
      message.device = identity.device
      message.fileID = identity.fileID
      message.objectType = identity.objectType.rawValue
    }
    return message
  }

  private static func bytes(_ value: ItemByteEvidence) -> Diskplan_V1_ItemByteEvidence {
    var message = Diskplan_V1_ItemByteEvidence()
    message.logical = byteMeasure(value.logical)
    message.nominalAllocated = byteMeasure(value.nominalAllocated)
    message.immediatePrivateReclaim = byteMeasure(value.immediatePrivateReclaim)
    return message
  }

  private static func byteMeasure(_ value: ByteMeasure) -> Diskplan_V1_ByteMeasureEvidence {
    var message = Diskplan_V1_ByteMeasureEvidence()
    switch value {
    case .exact(let bytes):
      message.kind = .exact
      message.bytes = bytes
    case .lowerBound(let bytes, let reason):
      message.kind = .lowerBound
      message.bytes = bytes
      message.reason = reason
    case .unknown(let reason):
      message.kind = .unknown
      message.reason = reason
    }
    return message
  }

  private static func storageTopology(
    _ value: StorageTopologyEvidence
  ) -> Diskplan_V1_StorageTopologyEvidence {
    var message = Diskplan_V1_StorageTopologyEvidence()
    message.linkCount = uint32(value.linkCount)
    message.mayShareBlocks = bool(value.mayShareBlocks)
    message.sharesAllBlocks = bool(value.sharesAllBlocks)
    message.cloneID = uint64(value.cloneID)
    message.cloneRefcount = uint32(value.cloneRefcount)
    message.conditionalGroupReclaim = byteMeasure(value.conditionalGroupReclaim)
    return message
  }

  private static func filesystemTimes(
    _ value: DiskplanScan.FilesystemTimeEvidence
  ) -> Diskplan_V1_FilesystemTimeEvidence {
    var message = Diskplan_V1_FilesystemTimeEvidence()
    message.accessTime = time(value.accessTime)
    message.modificationTime = time(value.modificationTime)
    message.statusChangeTime = time(value.statusChangeTime)
    message.birthTime = time(value.birthTime)
    message.trust = value.trust.rawValue
    return message
  }

  private static func time(
    _ value: Observation<CanonicalFilesystemTime>
  ) -> Diskplan_V1_TimeEvidence {
    var message = Diskplan_V1_TimeEvidence()
    message.observation = evidenceFailure(value)
    if case .known(let value) = value {
      var projected = Diskplan_V1_TimeValue()
      projected.secondsSinceEpoch = value.secondsSinceEpoch
      projected.nanoseconds = value.nanoseconds
      message.value = projected
    }
    return message
  }

  private static func accessPolicy(
    _ value: Observation<DiskplanScan.AccessPolicyEvidence>
  ) -> Diskplan_V1_AccessPolicyEvidence {
    var message = Diskplan_V1_AccessPolicyEvidence()
    message.observation = evidenceFailure(value)
    if case .known(let value) = value {
      message.ownerUserID = value.ownerUserID
      message.ownerGroupID = value.ownerGroupID
      message.mode = value.mode
      message.flags = value.flags
    }
    return message
  }

  private static func providerEvidence(
    _ value: Observation<DiskplanScan.ProviderScanEvidence>
  ) -> Diskplan_V1_ProviderScanEvidence {
    var message = Diskplan_V1_ProviderScanEvidence()
    message.observation = evidenceFailure(value)
    guard case .known(let value) = value else { return message }
    message.identityObservation = evidenceFailure(value.identity)
    if case .known(let identity) = value.identity {
      var projected = Diskplan_V1_ProviderObjectIdentityEvidence()
      projected.itemIdentifier = identity.itemIdentifier
      projected.domainIdentifier = identity.domainIdentifier
      message.identity = projected
    }
    message.promisedMetadataObservation = evidenceFailure(value.promisedMetadata)
    if case .known(let metadata) = value.promisedMetadata {
      message.promisedMetadata = metadata.sorted { $0.key < $1.key }.map { key, value in
        var pair = Diskplan_V1_StringPair()
        pair.key = key
        pair.value = value
        return pair
      }
    }
    message.hiddenBackingBytes = byteMeasure(value.hiddenBackingBytes)
    message.controlledNonMaterializationAcceptance = bool(
      value.controlledNonMaterializationAcceptance)
    return message
  }

  private static func processActivity(
    _ value: ProcessActivityRecord
  ) -> Diskplan_V1_ProcessActivityEvidence {
    var message = Diskplan_V1_ProcessActivityEvidence()
    message.processID = value.processID
    message.command = value.command ?? ""
    message.fileDescriptor = value.fileDescriptor ?? ""
    message.rawPath = value.rawPath
    message.displayPath = displayRawBytes(value.rawPath)
    return message
  }

  private static func collectorConfiguration(
    _ value: ScanCollectorConfiguration
  ) -> Diskplan_V1_ScanCollectorConfigurationEvidence {
    var message = Diskplan_V1_ScanCollectorConfigurationEvidence()
    message.processActivityCollectorID = value.processActivityCollectorID
    if let deadline = value.processActivityDeadlineNanoseconds {
      message.processActivityDeadlineNanoseconds = deadline
      message.hasProcessActivityDeadline_p = true
    }
    message.globalFactCollectorIds = value.globalFactCollectorIDs
    return message
  }

  private static func globalUInt64Fact(
    _ value: GlobalFact<[String: UInt64]>
  ) -> Diskplan_V1_GlobalFactEvidence {
    var message = Diskplan_V1_GlobalFactEvidence()
    switch value {
    case .known(let values):
      message.known = true
      message.uint64Values = values.sorted { $0.key < $1.key }.map { key, value in
        var pair = Diskplan_V1_StringUInt64Pair()
        pair.key = key
        pair.value = value
        return pair
      }
    case .unavailable(let reason):
      message.unavailableReason = reason
    }
    return message
  }

  private static func globalStringFact(
    _ value: GlobalFact<[String]>
  ) -> Diskplan_V1_GlobalFactEvidence {
    var message = Diskplan_V1_GlobalFactEvidence()
    switch value {
    case .known(let values):
      message.known = true
      message.stringValues = values.sorted()
    case .unavailable(let reason):
      message.unavailableReason = reason
    }
    return message
  }

  private static func bool(_ value: Observation<Bool>) -> Diskplan_V1_BoolEvidence {
    var message = Diskplan_V1_BoolEvidence()
    message.observation = evidenceFailure(value)
    if case .known(let value) = value { message.value = value }
    return message
  }

  private static func uint64(_ value: Observation<UInt64>) -> Diskplan_V1_UInt64Evidence {
    var message = Diskplan_V1_UInt64Evidence()
    message.observation = evidenceFailure(value)
    if case .known(let value) = value { message.value = value }
    return message
  }

  private static func uint32(_ value: Observation<UInt32>) -> Diskplan_V1_UInt32Evidence {
    var message = Diskplan_V1_UInt32Evidence()
    message.observation = evidenceFailure(value)
    if case .known(let value) = value { message.value = value }
    return message
  }

  private static func coverage(_ value: Coverage) -> Diskplan_V1_CoverageEvidence {
    var message = Diskplan_V1_CoverageEvidence()
    message.complete = value.completeness == .complete
    message.reasons = value.reasons.map(\.rawValue)
    return message
  }

  private static func providerBoundary(_ value: ProviderBoundary) -> (kind: String, reason: String)
  {
    switch value {
    case .localOrUnindicated: ("local_or_unindicated", "")
    case .metadataOnly(let reason): ("metadata_only", reason)
    case .rejected(let reason): ("rejected", reason)
    case .unverified(let reason): ("unverified", reason)
    }
  }

  private static func evidenceFailure<Value>(
    _ value: Observation<Value>
  ) -> Diskplan_V1_EvidenceFailure {
    var message = Diskplan_V1_EvidenceFailure()
    switch value {
    case .known:
      message.status = .known
    case .absent(let reason):
      message.status = .absent
      message.reason = reason
    case .unknown(let reason):
      message.status = .unknown
      message.reason = reason
    case .unreadable(let reason, let errorCode):
      message.status = .unreadable
      message.reason = reason
      set(errorCode, on: &message)
    case .failed(let reason, let errorCode):
      message.status = .failed
      message.reason = reason
      set(errorCode, on: &message)
    }
    return message
  }

  private static func set(
    _ errorCode: Int32?,
    on message: inout Diskplan_V1_EvidenceFailure
  ) {
    guard let errorCode else { return }
    message.errorCode = errorCode
    message.hasErrorCode_p = true
  }

  private static func currentRootDisplay(_ result: ScanResult) -> String {
    let terminalRoots = Set(
      result.roots.map { $0.binding.rootID } + result.rootFailures.map(\.rootID)
    )
    guard
      let root = result.reference.resolvedScope.roots.first(where: {
        !terminalRoots.contains($0.rootID)
      })
    else { return "" }
    return displayRawBytes(root.rawAbsolutePath)
  }

  private static func machineState(_ value: ScanMachineState) -> Diskplan_V1_ScanMachineState {
    switch value {
    case .ready: .ready
    case .scanning: .scanning
    case .complete: .complete
    case .partial: .partial
    case .cancelled: .cancelled
    }
  }

  private static func addingSaturated(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
    let (sum, overflow) = lhs.addingReportingOverflow(rhs)
    return overflow ? UInt64.max : sum
  }

  private static func multiplyingSaturated(_ lhs: UInt64, _ rhs: UInt64) -> UInt64 {
    let (product, overflow) = lhs.multipliedReportingOverflow(by: rhs)
    return overflow ? UInt64.max : product
  }
}
