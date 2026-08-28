import Foundation

public struct RawTargetPath: Equatable, Hashable, Comparable, Sendable {
  public let components: [Data]

  public init(components: [Data]) throws {
    guard !components.isEmpty,
      components.allSatisfy({ component in
        !component.isEmpty && component != Data(".".utf8) && component != Data("..".utf8)
          && !component.contains(0) && !component.contains(47)
      })
    else { throw PolicyModelError.invalidRawPath }
    self.components = components
  }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    lhs.components.lexicographicallyPrecedes(rhs.components) { left, right in
      left.lexicographicallyPrecedes(right)
    }
  }

  public func overlaps(_ other: Self) -> Bool {
    let sharedCount = Swift.min(components.count, other.components.count)
    return Array(components.prefix(sharedCount)) == Array(other.components.prefix(sharedCount))
  }

  public func isWithin(_ ancestor: Self) -> Bool {
    guard ancestor.components.count <= components.count else { return false }
    return Array(components.prefix(ancestor.components.count)) == ancestor.components
  }
}

public struct RawRootPath: Equatable, Hashable, Comparable, Sendable {
  public let absoluteBytes: Data

  public init(absoluteBytes: Data) throws {
    guard !absoluteBytes.isEmpty, absoluteBytes.first == 47, !absoluteBytes.contains(0) else {
      throw PolicyModelError.invalidRawPath
    }
    if absoluteBytes != Data("/".utf8) {
      guard absoluteBytes.last != 47 else { throw PolicyModelError.invalidRawPath }
      let components = absoluteBytes.dropFirst().split(
        separator: 47, omittingEmptySubsequences: false
      )
      guard components.allSatisfy({ !$0.isEmpty && $0 != Data(".".utf8) && $0 != Data("..".utf8) })
      else { throw PolicyModelError.invalidRawPath }
    }
    self.absoluteBytes = absoluteBytes
  }

  public static func < (lhs: Self, rhs: Self) -> Bool {
    lhs.absoluteBytes.lexicographicallyPrecedes(rhs.absoluteBytes)
  }

  fileprivate var components: [Data] {
    guard absoluteBytes != Data("/".utf8) else { return [] }
    return Array(absoluteBytes).dropFirst().split(separator: 47).map { Data($0) }
  }
}

public struct StorageGraphProvenance: Equatable, Sendable {
  public let globalFactsHash: PolicyDigest
  public let evidenceHash: PolicyDigest
  public let policyVersion: String
  public let schemaVersion: String
  public let semanticReferenceTimeSeconds: Int64

  fileprivate init(
    globalFactsHash: PolicyDigest,
    evidenceHash: PolicyDigest,
    policyVersion: String,
    schemaVersion: String,
    semanticReferenceTimeSeconds: Int64
  ) {
    self.globalFactsHash = globalFactsHash
    self.evidenceHash = evidenceHash
    self.policyVersion = policyVersion
    self.schemaVersion = schemaVersion
    self.semanticReferenceTimeSeconds = semanticReferenceTimeSeconds
  }
}

public struct StorageCandidate: Equatable, Sendable {
  public let id: String
  public let target: RawTargetPath
  public let targetIdentity: ObjectIdentity
  public let namespaceBinding: ProtectedNamespaceBinding
  public let evidence: FrozenEvidenceSnapshot
  public let immediatePrivateBytes: Observation<UInt64>

  public init(
    id: String,
    evidence: FrozenEvidenceSnapshot,
    immediatePrivateBytes: Observation<UInt64>
  ) throws {
    guard rawStringEqual(id, evidence.candidateID), case .known(let identity) = evidence.identity,
      identity == evidence.namespaceBinding.targetIdentity
    else { throw PolicyModelError.actionEvidenceMismatch }
    self.id = id
    self.target = evidence.namespaceBinding.targetPath
    self.targetIdentity = identity
    self.namespaceBinding = evidence.namespaceBinding
    self.evidence = evidence
    self.immediatePrivateBytes = immediatePrivateBytes
  }
}

public struct FileOwnerLink: Equatable, Hashable, Sendable {
  public let candidateID: String
  public let path: RawTargetPath

  public init(candidateID: String, path: RawTargetPath) {
    self.candidateID = candidateID
    self.path = path
  }

  public static func == (lhs: Self, rhs: Self) -> Bool {
    rawStringEqual(lhs.candidateID, rhs.candidateID) && lhs.path == rhs.path
  }

  public func hash(into hasher: inout Hasher) {
    hasher.combine(Data(candidateID.utf8))
    hasher.combine(path)
  }
}

public struct CandidateActionBinding: Equatable, Sendable {
  public let candidateID: String
  public let action: ActionDefinition

  public init(candidateID: String, action: ActionDefinition) {
    self.candidateID = candidateID
    self.action = action
  }
}

public struct GraphObservationProvenance: Equatable, Sendable {
  public let captureID: PolicyDigest
  public let globalFactsHash: PolicyDigest
  public let policyVersion: String
  public let schemaVersion: String
  public let semanticReferenceTimeSeconds: Int64

  public init(globalFacts: FrozenGlobalFacts) {
    captureID = globalFacts.captureID
    globalFactsHash = globalFacts.globalFactsHash
    policyVersion = globalFacts.policyVersion
    schemaVersion = globalFacts.schemaVersion
    semanticReferenceTimeSeconds = globalFacts.semanticReferenceTimeSeconds
  }

  fileprivate var bindingBytes: Data {
    var encoder = PolicyBindingEncoder()
    encoder.data(captureID.bytes)
    encoder.data(globalFactsHash.bytes)
    encoder.string(policyVersion)
    encoder.string(schemaVersion)
    encoder.int64(semanticReferenceTimeSeconds)
    return encoder.data
  }
}

public struct FileObjectNode: Equatable, Sendable {
  public let provenance: GraphObservationProvenance
  public let id: String
  public let observedOwners: [FileOwnerLink]
  public let linkCount: Observation<UInt32>

  public init(
    provenance: GraphObservationProvenance,
    id: String,
    observedOwners: [FileOwnerLink],
    linkCount: Observation<UInt32>
  ) {
    self.provenance = provenance
    self.id = id
    self.observedOwners = observedOwners
    self.linkCount = linkCount
  }
}

public struct AllocationGroupNode: Equatable, Sendable {
  public let provenance: GraphObservationProvenance
  public let id: String
  public let ownerFileObjectIDs: [String]
  public let cloneRefCount: Observation<UInt32>
  public let sharedBytes: Observation<UInt64>
  public let snapshotBlocker: Observation<Bool>

  public init(
    provenance: GraphObservationProvenance,
    id: String,
    ownerFileObjectIDs: [String],
    cloneRefCount: Observation<UInt32>,
    sharedBytes: Observation<UInt64>,
    snapshotBlocker: Observation<Bool>
  ) {
    self.provenance = provenance
    self.id = id
    self.ownerFileObjectIDs = ownerFileObjectIDs
    self.cloneRefCount = cloneRefCount
    self.sharedBytes = sharedBytes
    self.snapshotBlocker = snapshotBlocker
  }
}

public enum ReleaseBlocker: Equatable, Sendable {
  case targetOverlap(String, String)
  case missingCandidate(String)
  case missingFileObject(String)
  case duplicateOwnerPath(String)
  case hardlinkOwnerIncomplete(String)
  case cloneOwnerIncomplete(String)
  case ownerNotSelected(String)
  case unsafeOwner(String)
  case providerOwner(String)
  case providerEvidenceIncomplete(String)
  case hardRejectedOwner(String)
  case privateBytesUnknown(String)
  case snapshotBlocked(String)
  case snapshotEvidenceIncomplete(String)
  case sharedBytesUnknown(String)
  case sharedOwnerInMultipleGroups(String)
}

public struct EvaluatedReleaseSet: Equatable, Sendable {
  public let allocationGroupID: String
  public let graphDigest: PolicyDigest
  public let topologyExpectation: ReleaseTopologyExpectation
  public let owners: [EvaluatedReleaseOwner]
  public let conditionalReclaimBytes: UInt64?
  public let blockers: [ReleaseBlocker]

  public var ownerCandidateIDs: [String] { owners.map(\.candidateID) }

  public var isComplete: Bool {
    blockers.isEmpty && conditionalReclaimBytes != nil
  }
}

public struct FileTopologyExpectation: Equatable, Sendable {
  public let fileObjectID: String
  public let owners: [FileOwnerLink]
  public let linkCount: Observation<UInt32>
}

public struct ReleaseTopologyExpectation: Equatable, Sendable {
  public let allocationGroupID: String
  public let fileObjects: [FileTopologyExpectation]
  public let cloneRefCount: Observation<UInt32>
  public let sharedBytes: Observation<UInt64>
  public let snapshotBlocker: Observation<Bool>
}

public struct EvaluatedReleaseOwner: Equatable, Sendable {
  public let candidateID: String
  public let target: RawTargetPath
  public let targetIdentity: ObjectIdentity
  public let namespaceBinding: ProtectedNamespaceBinding
  public let evidence: FrozenEvidenceSnapshot
  public let evaluatedActionID: ActionID?
}

public struct ReleaseGraphEvaluation: Equatable, Sendable {
  public let graphDigest: PolicyDigest
  public let provenance: StorageGraphProvenance
  public let immediatePrivateReclaimByCandidate: [Data: UInt64]
  public let releaseSets: [EvaluatedReleaseSet]
  public let blockers: [ReleaseBlocker]

  public var immediatePrivateReclaimBytes: Observation<UInt64> {
    checkedSum(immediatePrivateReclaimByCandidate.values)
  }

  public var conditionalGroupReclaimBytes: Observation<UInt64> {
    checkedSum(releaseSets.compactMap(\.conditionalReclaimBytes))
  }

  private func checkedSum<S: Sequence>(_ values: S) -> Observation<UInt64>
  where S.Element == UInt64 {
    var result: UInt64 = 0
    for value in values {
      let addition = result.addingReportingOverflow(value)
      guard !addition.overflow else {
        return .failed(ObservationFailure(code: "integer-overflow", collector: "release-graph"))
      }
      result = addition.partialValue
    }
    return .known(result)
  }
}

public struct StorageReleaseGraph: Equatable, Sendable {
  public let globalFacts: FrozenGlobalFacts
  public let provenance: StorageGraphProvenance
  public let candidates: [StorageCandidate]
  public let fileObjects: [FileObjectNode]
  public let allocationGroups: [AllocationGroupNode]
  public let graphDigest: PolicyDigest

  public init(
    globalFacts: FrozenGlobalFacts,
    candidates: [StorageCandidate],
    fileObjects: [FileObjectNode],
    allocationGroups: [AllocationGroupNode]
  ) throws {
    guard Set(candidates.map { Data($0.id.utf8) }).count == candidates.count,
      Set(candidates.map(\.evidence.evidenceID)).count == candidates.count,
      Set(fileObjects.map { Data($0.id.utf8) }).count == fileObjects.count,
      Set(allocationGroups.map { Data($0.id.utf8) }).count == allocationGroups.count
    else { throw PolicyModelError.duplicateIdentifier }
    let candidateByID = Dictionary(
      uniqueKeysWithValues: candidates.map { (Data($0.id.utf8), $0) }
    )
    let evidence = candidates.map(\.evidence).sorted { $0.evidenceID < $1.evidenceID }
    let evidenceHash = PolicyBindings.digest(kind: "evidence-set") { encoder in
      encoder.array(evidence) { $0.bindingBytes }
    }
    let graphProvenance = StorageGraphProvenance(
      globalFactsHash: globalFacts.globalFactsHash,
      evidenceHash: evidenceHash,
      policyVersion: globalFacts.policyVersion,
      schemaVersion: globalFacts.schemaVersion,
      semanticReferenceTimeSeconds: globalFacts.semanticReferenceTimeSeconds
    )
    for candidate in candidates {
      guard candidate.target == candidate.namespaceBinding.targetPath,
        candidate.targetIdentity == candidate.namespaceBinding.targetIdentity,
        rawStringEqual(candidate.evidence.policyVersion, globalFacts.policyVersion),
        rawStringEqual(candidate.evidence.schemaVersion, globalFacts.schemaVersion),
        candidate.evidence.semanticReferenceTimeSeconds
          == globalFacts.semanticReferenceTimeSeconds,
        candidate.evidence.captureID == globalFacts.captureID,
        candidate.evidence.globalFactsHash == globalFacts.globalFactsHash,
        globalFacts.coverage.contains(where: {
          $0.rawRoot == candidate.namespaceBinding.rawRoot
        })
      else { throw PolicyModelError.invalidStorageGraph("candidate-binding:\(candidate.id)") }
    }
    var ownerFileIDByPath: [FileOwnerLink: String] = [:]
    for file in fileObjects {
      guard
        file.provenance.bindingBytes
          == GraphObservationProvenance(globalFacts: globalFacts).bindingBytes
      else {
        throw PolicyModelError.invalidStorageGraph("file-provenance:\(file.id)")
      }
      guard !file.observedOwners.isEmpty else {
        throw PolicyModelError.invalidStorageGraph("file-object-without-owner:\(file.id)")
      }
      let uniqueOwners = Set(file.observedOwners)
      guard uniqueOwners.count == file.observedOwners.count else {
        throw PolicyModelError.invalidStorageGraph("duplicate-file-owner:\(file.id)")
      }
      if case .known(let count) = file.linkCount {
        guard count > 0, Int(count) >= uniqueOwners.count else {
          throw PolicyModelError.invalidStorageGraph("impossible-link-count:\(file.id)")
        }
      }
      for owner in file.observedOwners {
        guard let candidate = candidateByID[Data(owner.candidateID.utf8)],
          owner.path.isWithin(candidate.target)
        else {
          throw PolicyModelError.invalidStorageGraph("owner-outside-candidate:\(file.id)")
        }
        if let previousFileID = ownerFileIDByPath[owner],
          !rawStringEqual(previousFileID, file.id)
        {
          throw PolicyModelError.invalidStorageGraph(
            "owner-path-in-multiple-file-objects:\(previousFileID):\(file.id)"
          )
        }
        ownerFileIDByPath[owner] = file.id
      }
    }
    var referencedFileIDs = Set<Data>()
    for group in allocationGroups {
      guard
        group.provenance.bindingBytes
          == GraphObservationProvenance(globalFacts: globalFacts).bindingBytes
      else {
        throw PolicyModelError.invalidStorageGraph("group-provenance:\(group.id)")
      }
      let uniqueOwners = Set(group.ownerFileObjectIDs.map { Data($0.utf8) })
      guard !uniqueOwners.isEmpty, uniqueOwners.count == group.ownerFileObjectIDs.count else {
        throw PolicyModelError.invalidStorageGraph("invalid-allocation-owners:\(group.id)")
      }
      if case .known(let count) = group.cloneRefCount {
        guard count > 0, Int(count) >= uniqueOwners.count else {
          throw PolicyModelError.invalidStorageGraph("impossible-clone-count:\(group.id)")
        }
      }
      referencedFileIDs.formUnion(uniqueOwners)
    }
    for file in fileObjects where !referencedFileIDs.contains(Data(file.id.utf8)) {
      throw PolicyModelError.invalidStorageGraph("disconnected-file-object:\(file.id)")
    }
    let canonicalCandidates = candidates.sorted { rawStringPrecedesForGraph($0.id, $1.id) }
    let canonicalFiles = fileObjects.sorted { rawStringPrecedesForGraph($0.id, $1.id) }
    let canonicalGroups = allocationGroups.sorted { rawStringPrecedesForGraph($0.id, $1.id) }
    self.globalFacts = globalFacts
    self.provenance = graphProvenance
    self.candidates = canonicalCandidates
    self.fileObjects = canonicalFiles
    self.allocationGroups = canonicalGroups
    self.graphDigest = PolicyBindings.digest(kind: "storage-release-graph") { encoder in
      encoder.array(canonicalCandidates) { candidate in
        var nested = PolicyBindingEncoder()
        nested.string(candidate.id)
        nested.data(candidate.target.bindingBytes)
        encodeIdentity(candidate.targetIdentity, into: &nested)
        nested.data(candidate.namespaceBinding.bindingBytes)
        nested.data(candidate.evidence.bindingBytes)
        nested.observation(candidate.immediatePrivateBytes) { $0.uint64($1) }
        return nested.data
      }
      encoder.array(canonicalFiles) { file in
        var nested = PolicyBindingEncoder()
        nested.data(file.provenance.bindingBytes)
        nested.string(file.id)
        nested.array(file.observedOwners.sorted(by: ownerLinkPrecedes)) { owner in
          var ownerEncoder = PolicyBindingEncoder()
          ownerEncoder.string(owner.candidateID)
          ownerEncoder.data(owner.path.bindingBytes)
          return ownerEncoder.data
        }
        nested.observation(file.linkCount) { $0.uint64(UInt64($1)) }
        return nested.data
      }
      encoder.array(canonicalGroups) { group in
        var nested = PolicyBindingEncoder()
        nested.data(group.provenance.bindingBytes)
        nested.string(group.id)
        nested.array(group.ownerFileObjectIDs.sorted(by: rawStringPrecedesForGraph)) {
          Data($0.utf8)
        }
        nested.observation(group.cloneRefCount) { $0.uint64(UInt64($1)) }
        nested.observation(group.sharedBytes) { $0.uint64($1) }
        nested.observation(group.snapshotBlocker) { $0.bool($1) }
        return nested.data
      }
      encoder.data(globalFacts.bindingBytes)
      encoder.data(evidenceHash.bytes)
    }
  }

  public func evaluate(
    selectedCandidateActions: [CandidateActionBinding]
  ) throws -> ReleaseGraphEvaluation {
    let candidateByID = Dictionary(
      uniqueKeysWithValues: candidates.map { (Data($0.id.utf8), $0) }
    )
    let selectedActionKeys = selectedCandidateActions.map { Data($0.candidateID.utf8) }
    guard Set(selectedActionKeys).count == selectedCandidateActions.count else {
      throw PolicyModelError.duplicateIdentifier
    }
    let actionByCandidateID = Dictionary(
      uniqueKeysWithValues: zip(selectedActionKeys, selectedCandidateActions.map(\.action))
    )
    for binding in selectedCandidateActions {
      let candidateID = binding.candidateID
      let action = binding.action
      guard let candidate = candidateByID[Data(candidateID.utf8)],
        rawStringEqual(action.evidence.candidateID, candidateID),
        action.evidenceID == candidate.evidence.evidenceID,
        action.globalFactsHash == provenance.globalFactsHash
      else { throw PolicyModelError.releaseOwnerBindingMismatch(candidateID) }
    }
    let selectedCandidateIDs = Set(selectedCandidateActions.map { Data($0.candidateID.utf8) })
    let safeCandidateIDs = Set<Data>(
      selectedCandidateActions.compactMap { binding in
        if case .blocked = binding.action.evaluation.stageability { return nil }
        return Data(binding.candidateID.utf8)
      }
    )
    let fileByID = Dictionary(
      uniqueKeysWithValues: fileObjects.map { (Data($0.id.utf8), $0) }
    )
    let groupMembership = Dictionary(
      grouping: allocationGroups.flatMap { group in
        Set(group.ownerFileObjectIDs.map { Data($0.utf8) }).map {
          ($0, Data(group.id.utf8))
        }
      },
      by: \.0
    ).mapValues { Set($0.map(\.1)) }
    let selectedCandidates = selectedCandidateIDs.compactMap { candidateByID[$0] }.sorted {
      rawStringPrecedesForGraph($0.id, $1.id)
    }
    var globalBlockers =
      selectedCandidateActions.map(\.candidateID)
      .filter { candidateByID[Data($0.utf8)] == nil }
      .sorted(by: rawStringPrecedesForGraph)
      .map(ReleaseBlocker.missingCandidate)
    var overlappingIDs = Set<Data>()
    var overlapPairs: [(String, String)] = []
    let canonicalCandidates = candidates.sorted { rawStringPrecedesForGraph($0.id, $1.id) }
    for leftIndex in canonicalCandidates.indices {
      for rightIndex in canonicalCandidates.indices where rightIndex > leftIndex {
        let left = canonicalCandidates[leftIndex]
        let right = canonicalCandidates[rightIndex]
        guard
          selectedCandidateIDs.contains(Data(left.id.utf8))
            || selectedCandidateIDs.contains(Data(right.id.utf8))
        else { continue }
        if namespacesMayOverlap(left.namespaceBinding, right.namespaceBinding) {
          overlappingIDs.insert(Data(left.id.utf8))
          overlappingIDs.insert(Data(right.id.utf8))
          overlapPairs.append((left.id, right.id))
          globalBlockers.append(.targetOverlap(left.id, right.id))
        }
      }
    }

    var immediate: [Data: UInt64] = [:]
    for candidate in selectedCandidates
    where !overlappingIDs.contains(Data(candidate.id.utf8)) {
      guard safeCandidateIDs.contains(Data(candidate.id.utf8)) else {
        globalBlockers.append(.unsafeOwner(candidate.id))
        continue
      }
      guard candidate.evidence.providerState == .known(.local) else {
        if candidate.evidence.providerState == .known(.fileProviderManaged) {
          globalBlockers.append(.providerOwner(candidate.id))
        } else {
          globalBlockers.append(.providerEvidenceIncomplete(candidate.id))
        }
        continue
      }
      guard case .known(let bytes) = candidate.immediatePrivateBytes else {
        globalBlockers.append(.privateBytesUnknown(candidate.id))
        continue
      }
      immediate[Data(candidate.id.utf8)] = bytes
    }

    var releaseSets: [EvaluatedReleaseSet] = []
    for group in allocationGroups {
      var blockers: [ReleaseBlocker] = []
      var owners: [Data: String] = [:]
      let fileIDByKey = Dictionary(
        uniqueKeysWithValues: group.ownerFileObjectIDs.map { (Data($0.utf8), $0) }
      )
      let uniqueFileIDs = Set(fileIDByKey.keys)
      if uniqueFileIDs.count != group.ownerFileObjectIDs.count {
        blockers.append(.cloneOwnerIncomplete(group.id))
      }
      for fileID in uniqueFileIDs.sorted(by: { $0.lexicographicallyPrecedes($1) }) {
        let fileIDString = fileIDByKey[fileID]!
        if (groupMembership[fileID]?.count ?? 0) > 1 {
          blockers.append(.sharedOwnerInMultipleGroups(fileIDString))
        }
        guard let file = fileByID[fileID] else {
          blockers.append(.missingFileObject(fileIDString))
          continue
        }
        let uniqueOwners = Set(file.observedOwners)
        if uniqueOwners.count != file.observedOwners.count {
          blockers.append(.duplicateOwnerPath(file.id))
        }
        guard case .known(let linkCount) = file.linkCount,
          Int(linkCount) == file.observedOwners.count,
          uniqueOwners.count == file.observedOwners.count
        else {
          blockers.append(.hardlinkOwnerIncomplete(file.id))
          for owner in file.observedOwners {
            owners[Data(owner.candidateID.utf8)] = owner.candidateID
          }
          continue
        }
        for owner in file.observedOwners {
          owners[Data(owner.candidateID.utf8)] = owner.candidateID
        }
      }
      if case .known(let refCount) = group.cloneRefCount,
        Int(refCount) == uniqueFileIDs.count
      {
        // Clone ownership is only one independent release-set gate.
      } else {
        blockers.append(.cloneOwnerIncomplete(group.id))
      }

      for ownerKey in owners.keys.sorted(by: { $0.lexicographicallyPrecedes($1) }) {
        let ownerID = owners[ownerKey]!
        guard let candidate = candidateByID[ownerKey] else {
          blockers.append(.missingCandidate(ownerID))
          continue
        }
        if !selectedCandidateIDs.contains(ownerKey) { blockers.append(.ownerNotSelected(ownerID)) }
        if !safeCandidateIDs.contains(ownerKey) { blockers.append(.unsafeOwner(ownerID)) }
        switch candidate.evidence.providerState {
        case .known(.local): break
        case .known(.fileProviderManaged): blockers.append(.providerOwner(ownerID))
        default: blockers.append(.providerEvidenceIncomplete(ownerID))
        }
        for pair in overlapPairs where pair.0 == ownerID || pair.1 == ownerID {
          blockers.append(.targetOverlap(pair.0, pair.1))
        }
      }

      switch group.snapshotBlocker {
      case .known(false): break
      case .known(true): blockers.append(.snapshotBlocked(group.id))
      default: blockers.append(.snapshotEvidenceIncomplete(group.id))
      }

      let sharedBytes: UInt64?
      if case .known(let bytes) = group.sharedBytes {
        sharedBytes = bytes
      } else {
        blockers.append(.sharedBytesUnknown(group.id))
        sharedBytes = nil
      }
      releaseSets.append(
        makeReleaseSet(
          group: group,
          topology: ReleaseTopologyExpectation(
            allocationGroupID: group.id,
            fileObjects: uniqueFileIDs.sorted(by: { $0.lexicographicallyPrecedes($1) }).compactMap {
              fileID in
              guard let file = fileByID[fileID] else { return nil }
              return FileTopologyExpectation(
                fileObjectID: fileIDByKey[fileID]!,
                owners: file.observedOwners.sorted(by: ownerLinkPrecedes),
                linkCount: file.linkCount
              )
            },
            cloneRefCount: group.cloneRefCount,
            sharedBytes: group.sharedBytes,
            snapshotBlocker: group.snapshotBlocker
          ),
          owners: owners,
          blockers: blockers,
          sharedBytes: sharedBytes,
          selectedCandidateActions: actionByCandidateID
        )
      )
    }

    return ReleaseGraphEvaluation(
      graphDigest: graphDigest,
      provenance: provenance,
      immediatePrivateReclaimByCandidate: immediate,
      releaseSets: releaseSets,
      blockers: globalBlockers
    )
  }

  private func makeReleaseSet(
    group: AllocationGroupNode,
    topology: ReleaseTopologyExpectation,
    owners: [Data: String],
    blockers: [ReleaseBlocker],
    sharedBytes: UInt64?,
    selectedCandidateActions: [Data: ActionDefinition]
  ) -> EvaluatedReleaseSet {
    let evaluatedOwners = owners.keys.sorted(by: { $0.lexicographicallyPrecedes($1) }).compactMap {
      ownerKey -> EvaluatedReleaseOwner? in
      guard let ownerID = owners[ownerKey],
        let candidate = candidates.first(where: { Data($0.id.utf8) == ownerKey })
      else { return nil }
      return EvaluatedReleaseOwner(
        candidateID: ownerID,
        target: candidate.target,
        targetIdentity: candidate.targetIdentity,
        namespaceBinding: candidate.namespaceBinding,
        evidence: candidate.evidence,
        evaluatedActionID: selectedCandidateActions[ownerKey]?.id
      )
    }
    return EvaluatedReleaseSet(
      allocationGroupID: group.id,
      graphDigest: graphDigest,
      topologyExpectation: topology,
      owners: evaluatedOwners,
      conditionalReclaimBytes: blockers.isEmpty ? sharedBytes : nil,
      blockers: blockers
    )
  }
}

extension RawTargetPath {
  var displayBytes: Data {
    var result = Data()
    for (index, component) in components.enumerated() {
      if index > 0 { result.append(47) }
      result.append(component)
    }
    return result
  }

  var bindingBytes: Data {
    var encoder = PolicyBindingEncoder()
    encoder.array(components) { $0 }
    return encoder.data
  }
}

private func ownerLinkPrecedes(_ lhs: FileOwnerLink, _ rhs: FileOwnerLink) -> Bool {
  if !rawStringEqual(lhs.candidateID, rhs.candidateID) {
    return rawStringPrecedesForGraph(lhs.candidateID, rhs.candidateID)
  }
  return lhs.path < rhs.path
}

private func rawStringPrecedesForGraph(_ lhs: String, _ rhs: String) -> Bool {
  Data(lhs.utf8).lexicographicallyPrecedes(Data(rhs.utf8))
}

private func namespacesMayOverlap(
  _ lhs: ProtectedNamespaceBinding,
  _ rhs: ProtectedNamespaceBinding
) -> Bool {
  let leftAbsolute = lhs.rawRoot.components + lhs.targetPath.components
  let rightAbsolute = rhs.rawRoot.components + rhs.targetPath.components
  if componentsOverlap(leftAbsolute, rightAbsolute) { return true }

  if identitiesMayMatch(lhs.rootIdentity, rhs.rootIdentity),
    lhs.targetPath.overlaps(rhs.targetPath)
  {
    return true
  }
  let leftAncestors = [lhs.rootIdentity] + lhs.parentChain.map(\.identity)
  let rightAncestors = [rhs.rootIdentity] + rhs.parentChain.map(\.identity)
  return identitiesMayMatch(lhs.targetIdentity, rhs.targetIdentity)
    || rightAncestors.contains { identitiesMayMatch(lhs.targetIdentity, $0) }
    || leftAncestors.contains { identitiesMayMatch(rhs.targetIdentity, $0) }
}

private func componentsOverlap(_ lhs: [Data], _ rhs: [Data]) -> Bool {
  let sharedCount = Swift.min(lhs.count, rhs.count)
  return Array(lhs.prefix(sharedCount)) == Array(rhs.prefix(sharedCount))
}

private func generationsMayMatch(
  _ lhs: Observation<UInt64>,
  _ rhs: Observation<UInt64>
) -> Bool {
  switch (lhs, rhs) {
  case (.known(let left), .known(let right)): left == right
  default: true
  }
}

private func identitiesMayMatch(_ lhs: ObjectIdentity, _ rhs: ObjectIdentity) -> Bool {
  lhs.device == rhs.device && lhs.object == rhs.object
    && generationsMayMatch(lhs.generation, rhs.generation)
}
