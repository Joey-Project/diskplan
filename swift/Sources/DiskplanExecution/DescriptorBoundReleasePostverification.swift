import CryptoKit
import Darwin
import DiskplanPolicy
import Foundation

struct ReleaseDescriptorAccessSeal: Equatable, Sendable {
  let mode: UInt32
  let ownerUserID: UInt32
  let ownerGroupID: UInt32
  let authorizationFlags: UInt32
  let aclDigest: PolicyDigest
  let mountIdentity: Data
}

struct ReleaseDescriptorNamespaceSeal: Equatable, Sendable {
  let identity: ObjectIdentity
  let access: ReleaseDescriptorAccessSeal
}

enum ReleasePostverificationNamespaceLocation: Equatable, Sendable {
  case root
  case parentChain(index: Int)
}

enum ReleaseOwnerSlotTransition: Equatable, Sendable {
  case missing
  case identityChanged(current: ObjectIdentity)
}

struct AuthorizedReleaseNamespaceComponent: Sendable {
  let rawNameFromParent: Data?
  let descriptor: Int32
  let authorizedSeal: ReleaseDescriptorNamespaceSeal
}

struct ReleasePostverificationOwnerLocator: Sendable {
  let actionID: ActionID
  let candidateID: String
  let expectedIdentity: ObjectIdentity
  let namespace: [AuthorizedReleaseNamespaceComponent]
  let rawLeafName: Data
}

struct ReleaseFileTopologyExpectation: Equatable, Sendable {
  let fileObjectID: String
  let owners: [FileOwnerLink]
  let linkCount: Observation<UInt32>

  init(
    fileObjectID: String,
    owners: [FileOwnerLink],
    linkCount: Observation<UInt32>
  ) {
    self.fileObjectID = fileObjectID
    self.owners = owners
    self.linkCount = linkCount
  }

  init(_ value: FileTopologyExpectation) {
    fileObjectID = value.fileObjectID
    owners = value.owners
    linkCount = value.linkCount
  }

  static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.fileObjectID) == RawUTF8Key(rhs.fileObjectID)
      && lhs.owners == rhs.owners
      && lhs.linkCount == rhs.linkCount
  }
}

struct ReleaseAllocationTopologyExpectation: Equatable, Sendable {
  let allocationGroupID: String
  let fileObjects: [ReleaseFileTopologyExpectation]
  let cloneRefCount: Observation<UInt32>
  let sharedBytes: Observation<UInt64>
  let snapshotBlocker: Observation<Bool>

  init(_ value: ReleaseTopologyExpectation) {
    allocationGroupID = value.allocationGroupID
    fileObjects = value.fileObjects.map(ReleaseFileTopologyExpectation.init)
    cloneRefCount = value.cloneRefCount
    sharedBytes = value.sharedBytes
    snapshotBlocker = value.snapshotBlocker
  }

  init(
    allocationGroupID: String,
    fileObjects: [ReleaseFileTopologyExpectation],
    cloneRefCount: Observation<UInt32>,
    sharedBytes: Observation<UInt64>,
    snapshotBlocker: Observation<Bool>
  ) {
    self.allocationGroupID = allocationGroupID
    self.fileObjects = fileObjects
    self.cloneRefCount = cloneRefCount
    self.sharedBytes = sharedBytes
    self.snapshotBlocker = snapshotBlocker
  }

  static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.allocationGroupID) == RawUTF8Key(rhs.allocationGroupID)
      && lhs.fileObjects == rhs.fileObjects
      && lhs.cloneRefCount == rhs.cloneRefCount
      && lhs.sharedBytes == rhs.sharedBytes
      && lhs.snapshotBlocker == rhs.snapshotBlocker
  }
}

struct ReleasePostverificationGroupExpectation: Equatable, Sendable {
  let allocationGroupID: String
  let topology: ReleaseAllocationTopologyExpectation
  let ownerActionIDs: [ActionID]

  static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.allocationGroupID) == RawUTF8Key(rhs.allocationGroupID)
      && lhs.topology == rhs.topology
      && lhs.ownerActionIDs == rhs.ownerActionIDs
  }
}

struct ReleasePostverificationExecutionBinding: Equatable, Sendable {
  let executionBindingHash: PolicyDigest
  let applyClaimIDHash: PolicyDigest
  let preparationGeneration: UInt64
  let epoch: ExecutionEpochContext
  let jitOneShotNonce: Data
  let planCaptureID: PolicyDigest
  let wholePlanCaptureID: PolicyDigest
  let jitCaptureID: PolicyDigest
  let freshnessLimitSeconds: Int64
}

final class EngineReleasePostverificationComponentHandle: @unchecked Sendable {
  private let lock = NSLock()
  private var binding: TrustedReleasePostverificationComponentBinding?

  fileprivate init(binding: TrustedReleasePostverificationComponentBinding) {
    self.binding = binding
  }

  fileprivate func claim() -> TrustedReleasePostverificationComponentBinding? {
    lock.lock()
    defer { lock.unlock() }
    defer { binding = nil }
    return binding
  }
}

private struct TrustedReleasePostverificationComponentBinding: Sendable {
  let execution: ReleasePostverificationExecutionBinding
  let componentID: PolicyDigest
  let schema: ReleasePostverificationComponentBindingV1
  let groups: [ReleasePostverificationGroupExpectation]
}

enum ReleasePostverificationManifestClaimError: Error, Equatable, Sendable {
  case manifestPlanMismatch
  case claimBindingMismatch
  case invalidExecutionBinding
  case unitNotInClaimedManifest
  case unitAlreadyAuthorized
  case jitClaimUnknownOrReplayed
  case jitClaimBindingMismatch
  case invalidConnectedClosure
  case descriptorLocatorMembershipMismatch
  case descriptorLocatorBindingMismatch(ActionID)
}

enum ReleasePostverificationLocatorError: Error, Equatable, Sendable {
  case operationMembershipMismatch
  case namespaceOpenFailed(
    ActionID, ReleasePostverificationNamespaceLocation, Int32
  )
  case namespaceSealUnavailable(
    ActionID, ReleasePostverificationNamespaceLocation
  )
}

/// Versioned, engine-internal schema. It is never serialized over IPC, so `ipc.proto` does not
/// carry a duplicate representation; the shared compatibility fixture freezes these exact bytes.
struct ReleasePostverificationComponentBindingV1: Equatable, Sendable {
  static let bindingKind = "release-postverification-component"
  let manifestCurrentBindingHash: PolicyDigest
  let planHash: PolicyDigest
  let overlayHash: PolicyDigest
  let epoch: ExecutionEpochContext
  let applyClaimIDHash: PolicyDigest
  let preparationGeneration: UInt64
  let jitOneShotNonce: Data
  let planCaptureID: PolicyDigest
  let wholePlanCaptureID: PolicyDigest
  let jitCaptureID: PolicyDigest
  let allocationGroupIDs: [String]
  let ownerActionIDs: [ActionID]
  let jitActionIDs: [ActionID]

  func canonicalBytes(
    execution: ReleasePostverificationExecutionBinding,
    owners: [ReleasePostverificationOwnerLocator],
    groups: [ReleasePostverificationGroupExpectation]
  ) -> Data {
    var encoder = VersionedExecutionBindingEncoderV1(bindingKind: Self.bindingKind)
    encoder.data(manifestCurrentBindingHash.bytes)
    encoder.data(planHash.bytes)
    encoder.data(overlayHash.bytes)
    encoder.string(epoch.epochID)
    encoder.int64(epoch.semanticReferenceTimeSeconds)
    encoder.int64(epoch.issuedAtSeconds)
    encoder.int64(epoch.deadlineSeconds)
    encoder.data(applyClaimIDHash.bytes)
    encoder.uint64(preparationGeneration)
    encoder.data(jitOneShotNonce)
    encoder.data(planCaptureID.bytes)
    encoder.data(wholePlanCaptureID.bytes)
    encoder.data(jitCaptureID.bytes)
    encoder.array(allocationGroupIDs) { Data($0.utf8) }
    encoder.array(ownerActionIDs) { $0.digest.bytes }
    encoder.array(jitActionIDs) { $0.digest.bytes }
    encoder.data(execution.executionBindingHash.bytes)
    encoder.int64(execution.freshnessLimitSeconds)
    encoder.array(owners.sorted { $0.actionID < $1.actionID }) { owner in
      var nested = VersionedExecutionBindingEncoderV1(bindingKind: "release-owner-locator")
      nested.data(owner.actionID.digest.bytes)
      nested.string(owner.candidateID)
      Self.encode(owner.expectedIdentity, into: &nested)
      nested.array(owner.namespace) { component in
        var namespace = VersionedExecutionBindingEncoderV1(
          bindingKind: "release-namespace-locator")
        namespace.uint8(component.rawNameFromParent == nil ? 0 : 1)
        if let rawName = component.rawNameFromParent { namespace.data(rawName) }
        Self.encode(component.authorizedSeal, into: &namespace)
        return namespace.bytes
      }
      nested.data(owner.rawLeafName)
      return nested.bytes
    }
    encoder.array(
      groups.sorted {
        RawUTF8Key($0.allocationGroupID) < RawUTF8Key($1.allocationGroupID)
      }
    ) { group in
      var nested = VersionedExecutionBindingEncoderV1(bindingKind: "release-group-expectation")
      nested.string(group.allocationGroupID)
      nested.array(group.ownerActionIDs.sorted()) { $0.digest.bytes }
      let topology = group.topology
      nested.string(topology.allocationGroupID)
      nested.array(
        topology.fileObjects.sorted {
          Data($0.fileObjectID.utf8).lexicographicallyPrecedes(Data($1.fileObjectID.utf8))
        }
      ) { fileObject in
        var file = VersionedExecutionBindingEncoderV1(bindingKind: "release-file-expectation")
        file.string(fileObject.fileObjectID)
        file.array(
          fileObject.owners.sorted {
            let left = Data($0.candidateID.utf8)
            let right = Data($1.candidateID.utf8)
            return left == right ? $0.path < $1.path : left.lexicographicallyPrecedes(right)
          }
        ) { link in
          var owner = VersionedExecutionBindingEncoderV1(bindingKind: "release-file-owner")
          owner.string(link.candidateID)
          owner.array(link.path.components) { $0 }
          return owner.bytes
        }
        Self.encode(fileObject.linkCount, into: &file)
        return file.bytes
      }
      Self.encode(topology.cloneRefCount, into: &nested)
      Self.encode(topology.sharedBytes, into: &nested)
      Self.encode(topology.snapshotBlocker, into: &nested)
      return nested.bytes
    }
    return encoder.bytes
  }

  func digest(
    execution: ReleasePostverificationExecutionBinding,
    owners: [ReleasePostverificationOwnerLocator],
    groups: [ReleasePostverificationGroupExpectation]
  ) -> PolicyDigest {
    try! PolicyDigest(
      bytes: Data(
        SHA256.hash(
          data: canonicalBytes(
            execution: execution, owners: owners, groups: groups))))
  }

  private static func encode(
    _ value: ObjectIdentity,
    into encoder: inout VersionedExecutionBindingEncoderV1
  ) {
    encoder.uint64(value.device)
    encoder.uint64(value.object)
    encode(value.generation, into: &encoder)
    encoder.string(value.type.rawValue)
  }

  private static func encode(
    _ value: ReleaseDescriptorNamespaceSeal,
    into encoder: inout VersionedExecutionBindingEncoderV1
  ) {
    encode(value.identity, into: &encoder)
    encoder.uint64(UInt64(value.access.mode))
    encoder.uint64(UInt64(value.access.ownerUserID))
    encoder.uint64(UInt64(value.access.ownerGroupID))
    encoder.uint64(UInt64(value.access.authorizationFlags))
    encoder.data(value.access.aclDigest.bytes)
    encoder.data(value.access.mountIdentity)
  }

  private static func encode<Value: FixedWidthInteger & Equatable & Sendable>(
    _ observation: Observation<Value>,
    into encoder: inout VersionedExecutionBindingEncoderV1
  ) {
    encodeObservation(observation, into: &encoder) { value, nested in
      nested.uint64(UInt64(truncatingIfNeeded: value))
    }
  }

  private static func encode(
    _ observation: Observation<Bool>,
    into encoder: inout VersionedExecutionBindingEncoderV1
  ) {
    encodeObservation(observation, into: &encoder) { value, nested in
      nested.uint8(value ? 1 : 0)
    }
  }

  private static func encodeObservation<Value: Equatable & Sendable>(
    _ observation: Observation<Value>,
    into encoder: inout VersionedExecutionBindingEncoderV1,
    known: (Value, inout VersionedExecutionBindingEncoderV1) -> Void
  ) {
    switch observation {
    case .absent: encoder.uint8(0)
    case .known(let value):
      encoder.uint8(1)
      known(value, &encoder)
    case .unknown(let reason):
      encoder.uint8(2)
      encoder.string(reason.rawValue)
    case .unreadable(let failure):
      encoder.uint8(3)
      encoder.string(failure.code)
      encoder.string(failure.collector)
    case .failed(let failure):
      encoder.uint8(4)
      encoder.string(failure.code)
      encoder.string(failure.collector)
    }
  }
}

final class EngineReleasePostverificationManifestAuthority: @unchecked Sendable {
  private let manifest: ExecutionManifest
  private let plan: ImmutablePlan
  private let registryClaimIDHash: PolicyDigest
  private let registryGeneration: UInt64
  private let lock = NSLock()
  private var authorizedUnits = Set<ExecutionUnitID>()

  func authorizeAndFreeze(
    jitClaim: EngineJITExecutionClaim,
    mutationOperations: [ExecutionAdapterOperation],
    core: DescriptorBoundReleasePostverificationCore
  ) throws -> FrozenReleasePostverificationComponent {
    let locators: [ReleasePostverificationOwnerLocator]
    do {
      locators = try descriptorLocators(for: mutationOperations)
    } catch {
      jitClaim.consumeOnFailure()
      throw error
    }
    defer {
      for locator in locators {
        for component in locator.namespace.reversed() {
          _ = Darwin.close(component.descriptor)
        }
      }
    }
    let handle = try authorizeTrusted(
      jitClaim: jitClaim,
      descriptorLocators: locators
    )
    return try core.freeze(
      ReleasePostverificationComponentRequest(
        componentHandle: handle,
        owners: locators
      ))
  }

  convenience init(
    claimedAuthorization: ClaimedApplyAuthorization,
    plan: ImmutablePlan
  ) throws {
    try self.init(
      claimedManifest: claimedAuthorization.manifest,
      registryCurrentBindingHash: claimedAuthorization.registryCurrentBindingHash,
      registryClaimIDHash: claimedAuthorization.registryClaimIDHash,
      registryGeneration: claimedAuthorization.generation,
      plan: plan
    )
  }

  #if DEBUG
    convenience init(
      testingClaimedManifest: ExecutionManifest,
      registryCurrentBindingHash: PolicyDigest? = nil,
      registryClaimIDHash: PolicyDigest = try! PolicyDigest(
        bytes: Data(repeating: 0x71, count: 32)
      ),
      registryGeneration: UInt64 = 1,
      plan: ImmutablePlan
    ) throws {
      try self.init(
        claimedManifest: testingClaimedManifest,
        registryCurrentBindingHash: registryCurrentBindingHash
          ?? testingClaimedManifest.currentBindingHash,
        registryClaimIDHash: registryClaimIDHash,
        registryGeneration: registryGeneration,
        plan: plan
      )
    }
  #endif

  private init(
    claimedManifest manifest: ExecutionManifest,
    registryCurrentBindingHash: PolicyDigest,
    registryClaimIDHash: PolicyDigest,
    registryGeneration: UInt64,
    plan: ImmutablePlan
  ) throws {
    guard manifest.planHash == plan.planHash else {
      throw ReleasePostverificationManifestClaimError.manifestPlanMismatch
    }
    guard registryCurrentBindingHash == manifest.currentBindingHash,
      Revalidator.manifestCurrentBindingMatchesPlan(manifest, plan: plan)
    else {
      throw ReleasePostverificationManifestClaimError.claimBindingMismatch
    }
    guard manifest.currentCaptureID != plan.globalFacts.captureID,
      manifest.epoch.deadlineSeconds > manifest.epoch.issuedAtSeconds
    else {
      throw ReleasePostverificationManifestClaimError.invalidExecutionBinding
    }
    self.manifest = manifest
    self.plan = plan
    self.registryClaimIDHash = registryClaimIDHash
    self.registryGeneration = registryGeneration
  }

  #if DEBUG
    func authorize(
      jitClaim: EngineJITExecutionClaim,
      descriptorLocators: [ReleasePostverificationOwnerLocator]
    ) throws -> EngineReleasePostverificationComponentHandle {
      try authorizeTrusted(
        jitClaim: jitClaim,
        descriptorLocators: descriptorLocators
      )
    }
  #endif

  private func authorizeTrusted(
    jitClaim: EngineJITExecutionClaim,
    descriptorLocators: [ReleasePostverificationOwnerLocator]
  ) throws -> EngineReleasePostverificationComponentHandle {
    let jit: EngineJITExecutionClaimRecord
    do {
      jit = try jitClaim.claim()
    } catch EngineJITExecutionClaimError.claimUnknownOrReplayed {
      throw ReleasePostverificationManifestClaimError.jitClaimUnknownOrReplayed
    } catch {
      throw ReleasePostverificationManifestClaimError.jitClaimBindingMismatch
    }
    let unitID = jit.unit.unitID
    let derivedJITBinding: EngineJITExecutionUnitBinding
    do {
      derivedJITBinding = try EngineJITExecutionUnitBinding.derive(
        unitID: unitID,
        plan: plan,
        manifest: manifest
      )
    } catch {
      throw ReleasePostverificationManifestClaimError.jitClaimBindingMismatch
    }
    guard jit.applyClaimIDHash == registryClaimIDHash,
      jit.currentBindingHash == manifest.currentBindingHash,
      jit.preparationGeneration == registryGeneration,
      jit.epoch == manifest.epoch,
      jit.oneShotNonce.count == 32,
      jit.planCaptureID == plan.globalFacts.captureID,
      jit.wholePlanCaptureID == manifest.currentCaptureID,
      jit.jitCaptureID != jit.planCaptureID,
      jit.jitCaptureID != jit.wholePlanCaptureID,
      jit.planCaptureID != jit.wholePlanCaptureID,
      jit.unit == derivedJITBinding
    else {
      throw ReleasePostverificationManifestClaimError.jitClaimBindingMismatch
    }
    guard case .compoundRelease = unitID else {
      throw ReleasePostverificationManifestClaimError.unitNotInClaimedManifest
    }
    let matches = manifest.compoundReleaseUnits.filter {
      ExecutionUnitID.compoundRelease($0.allocationGroupIDs) == unitID
    }
    guard matches.count == 1, let unit = matches.first else {
      throw ReleasePostverificationManifestClaimError.unitNotInClaimedManifest
    }
    let groupKeys = Set(unit.allocationGroupIDs.map(RawUTF8Key.init))
    let graphComponents =
      plan.releaseGraphManifest?.connectedComponents.filter {
        Set($0.allocationGroupIDs.map(RawUTF8Key.init)) == groupKeys
      } ?? []
    guard graphComponents.count == 1 else {
      throw ReleasePostverificationManifestClaimError.invalidConnectedClosure
    }
    let releaseSets = plan.releaseSets.filter {
      groupKeys.contains(RawUTF8Key($0.allocationGroupID))
    }.sorted { RawUTF8Key($0.allocationGroupID) < RawUTF8Key($1.allocationGroupID) }
    guard releaseSets.count == unit.allocationGroupIDs.count,
      Set(releaseSets.map { RawUTF8Key($0.allocationGroupID) }) == groupKeys
    else {
      throw ReleasePostverificationManifestClaimError.invalidConnectedClosure
    }
    var ownerBindings: [ActionID: ReleaseSetOwnerBinding] = [:]
    for owner in releaseSets.flatMap(\.owners) {
      if let existing = ownerBindings[owner.actionID], existing != owner {
        throw ReleasePostverificationManifestClaimError.invalidConnectedClosure
      }
      ownerBindings[owner.actionID] = owner
    }
    guard Set(ownerBindings.keys) == Set(unit.ownerActionIDs),
      Set(graphComponents[0].candidateIDs.map(RawUTF8Key.init))
        == Set(ownerBindings.values.map { RawUTF8Key($0.candidateID) }),
      Set(descriptorLocators.map(\.actionID)) == Set(unit.ownerActionIDs),
      Set(descriptorLocators.map(\.actionID)).count == descriptorLocators.count
    else {
      throw ReleasePostverificationManifestClaimError.descriptorLocatorMembershipMismatch
    }
    for locator in descriptorLocators {
      guard let expected = ownerBindings[locator.actionID],
        Self.locator(locator, matches: expected)
      else {
        throw ReleasePostverificationManifestClaimError.descriptorLocatorBindingMismatch(
          locator.actionID
        )
      }
    }
    let groups = releaseSets.map {
      ReleasePostverificationGroupExpectation(
        allocationGroupID: $0.allocationGroupID,
        topology: ReleaseAllocationTopologyExpectation($0.topologyExpectation),
        ownerActionIDs: $0.ownerActionIDs.sorted()
      )
    }
    let execution = ReleasePostverificationExecutionBinding(
      executionBindingHash: manifest.currentBindingHash,
      applyClaimIDHash: jit.applyClaimIDHash,
      preparationGeneration: jit.preparationGeneration,
      epoch: manifest.epoch,
      jitOneShotNonce: jit.oneShotNonce,
      planCaptureID: plan.globalFacts.captureID,
      wholePlanCaptureID: manifest.currentCaptureID,
      jitCaptureID: jit.jitCaptureID,
      freshnessLimitSeconds: manifest.epoch.deadlineSeconds - manifest.epoch.issuedAtSeconds
    )
    let schema = ReleasePostverificationComponentBindingV1(
      manifestCurrentBindingHash: manifest.currentBindingHash,
      planHash: manifest.planHash,
      overlayHash: manifest.overlayHash,
      epoch: manifest.epoch,
      applyClaimIDHash: jit.applyClaimIDHash,
      preparationGeneration: jit.preparationGeneration,
      jitOneShotNonce: jit.oneShotNonce,
      planCaptureID: plan.globalFacts.captureID,
      wholePlanCaptureID: manifest.currentCaptureID,
      jitCaptureID: jit.jitCaptureID,
      allocationGroupIDs: unit.allocationGroupIDs,
      ownerActionIDs: unit.ownerActionIDs,
      jitActionIDs: jit.unit.actionIDs
    )
    let componentID = schema.digest(
      execution: execution,
      owners: descriptorLocators,
      groups: groups
    )
    lock.lock()
    defer { lock.unlock() }
    guard authorizedUnits.insert(unitID).inserted else {
      throw ReleasePostverificationManifestClaimError.unitAlreadyAuthorized
    }
    return EngineReleasePostverificationComponentHandle(
      binding: TrustedReleasePostverificationComponentBinding(
        execution: execution,
        componentID: componentID,
        schema: schema,
        groups: groups
      ))
  }

  private static func locator(
    _ locator: ReleasePostverificationOwnerLocator,
    matches expected: ReleaseSetOwnerBinding
  ) -> Bool {
    let namespace = expected.namespaceBinding
    let expectedNames: [Data?] =
      [nil]
      + namespace.parentChain.map {
        $0.relativePath.components.last
      }
    let expectedIdentities = [namespace.rootIdentity] + namespace.parentChain.map(\.identity)
    let expectedSeals = [namespace.rootSeal] + namespace.parentChain.map(\.seal)
    guard Data(locator.candidateID.utf8) == Data(expected.candidateID.utf8),
      locator.expectedIdentity == expected.targetIdentity,
      locator.rawLeafName == namespace.targetPath.components.last,
      locator.namespace.count == expectedNames.count
    else { return false }
    for index in locator.namespace.indices {
      let component = locator.namespace[index]
      guard component.rawNameFromParent == expectedNames[index],
        component.authorizedSeal.identity == expectedIdentities[index],
        sealAccess(component.authorizedSeal.access, matches: expectedSeals[index])
      else { return false }
    }
    return true
  }

  private func descriptorLocators(
    for operations: [ExecutionAdapterOperation]
  ) throws -> [ReleasePostverificationOwnerLocator] {
    let planActions = Dictionary(uniqueKeysWithValues: plan.actions.map { ($0.id, $0) })
    var operationsByActionID: [ActionID: ExecutionAdapterOperation] = [:]
    for operation in operations {
      guard operationsByActionID[operation.actionID] == nil,
        let action = planActions[operation.actionID],
        operation.target == BoundMutationTarget(action: action)
      else { throw ReleasePostverificationLocatorError.operationMembershipMismatch }
      operationsByActionID[operation.actionID] = operation
    }
    let ownersByActionID = Dictionary(grouping: plan.releaseSets.flatMap(\.owners), by: \.actionID)
    var openedDescriptors: [Int32] = []
    do {
      let locators = try operationsByActionID.keys.sorted().map {
        actionID -> ReleasePostverificationOwnerLocator in
        guard let operation = operationsByActionID[actionID],
          let matches = ownersByActionID[actionID],
          let owner = matches.first,
          matches.allSatisfy({ $0 == owner })
        else { throw ReleasePostverificationLocatorError.operationMembershipMismatch }
        let target = operation.target
        guard target.targetPath.components == owner.target.components,
          target.rawRoot == owner.namespaceBinding.rawRoot,
          target.expectedIdentity == owner.targetIdentity,
          target.targetPath.components.count
            == owner.namespaceBinding.parentChain.count + 1
        else { throw ReleasePostverificationLocatorError.operationMembershipMismatch }
        var namespace: [AuthorizedReleaseNamespaceComponent] = []
        let root = try Self.openDirectory(
          path: target.rawRoot.absoluteBytes,
          actionID: actionID,
          location: .root
        )
        openedDescriptors.append(root)
        namespace.append(
          try Self.authorizedComponent(
            rawNameFromParent: nil,
            descriptor: root,
            actionID: actionID,
            location: .root
          ))
        var parent = root
        for (index, rawName) in target.targetPath.components.dropLast().enumerated() {
          let location = ReleasePostverificationNamespaceLocation.parentChain(index: index)
          let descriptor = try Self.openDirectory(
            at: parent,
            rawName: rawName,
            actionID: actionID,
            location: location
          )
          openedDescriptors.append(descriptor)
          namespace.append(
            try Self.authorizedComponent(
              rawNameFromParent: rawName,
              descriptor: descriptor,
              actionID: actionID,
              location: location
            ))
          parent = descriptor
        }
        return ReleasePostverificationOwnerLocator(
          actionID: actionID,
          candidateID: owner.candidateID,
          expectedIdentity: owner.targetIdentity,
          namespace: namespace,
          rawLeafName: target.targetPath.components.last!
        )
      }
      openedDescriptors.removeAll(keepingCapacity: false)
      return locators
    } catch {
      for descriptor in openedDescriptors.reversed() { _ = Darwin.close(descriptor) }
      throw error
    }
  }

  private static func authorizedComponent(
    rawNameFromParent: Data?,
    descriptor: Int32,
    actionID: ActionID,
    location: ReleasePostverificationNamespaceLocation
  ) throws -> AuthorizedReleaseNamespaceComponent {
    let probe = POSIXReleasePostverificationDescriptorProbe()
    guard case .known(let seal) = probe.namespaceSeal(descriptor: descriptor) else {
      throw ReleasePostverificationLocatorError.namespaceSealUnavailable(
        actionID, location
      )
    }
    return AuthorizedReleaseNamespaceComponent(
      rawNameFromParent: rawNameFromParent,
      descriptor: descriptor,
      authorizedSeal: seal
    )
  }

  private static func openDirectory(
    path: Data,
    actionID: ActionID,
    location: ReleasePostverificationNamespaceLocation
  ) throws -> Int32 {
    let descriptor = withRawCString(path) {
      Darwin.open($0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard descriptor >= 0 else {
      throw ReleasePostverificationLocatorError.namespaceOpenFailed(
        actionID, location, errno
      )
    }
    return descriptor
  }

  private static func openDirectory(
    at parent: Int32,
    rawName: Data,
    actionID: ActionID,
    location: ReleasePostverificationNamespaceLocation
  ) throws -> Int32 {
    let descriptor = withRawCString(rawName) {
      Darwin.openat(parent, $0, O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC)
    }
    guard descriptor >= 0 else {
      throw ReleasePostverificationLocatorError.namespaceOpenFailed(
        actionID, location, errno
      )
    }
    return descriptor
  }

  private static func withRawCString<Result>(
    _ bytes: Data,
    _ body: (UnsafePointer<CChar>) -> Result
  ) -> Result {
    var terminated = [UInt8](bytes)
    terminated.append(0)
    return terminated.withUnsafeBufferPointer { buffer in
      body(UnsafeRawPointer(buffer.baseAddress!).assumingMemoryBound(to: CChar.self))
    }
  }

  private static func sealAccess(
    _ access: ReleaseDescriptorAccessSeal,
    matches expected: NamespaceSealEvidence
  ) -> Bool {
    guard expected.trustedNamespace == .ownerPrivate,
      expected.providerBoundary == .known(.local),
      case .known(let accessPolicy) = expected.accessPolicy,
      Data(accessPolicy.utf8) == Data("owner-private".utf8),
      case .known(let aclDigest) = expected.aclDigest,
      case .known(let mountIdentity) = expected.mountIdentity
    else { return false }
    return access.ownerUserID == Darwin.geteuid()
      && access.mode & UInt32(S_IFMT) == UInt32(S_IFDIR)
      && access.mode & 0o7777 == 0o700
      && access.aclDigest == aclDigest
      && access.mountIdentity.base64EncodedString() == mountIdentity
  }
}

struct ReleasePostverificationComponentRequest: Sendable {
  let componentHandle: EngineReleasePostverificationComponentHandle
  let owners: [ReleasePostverificationOwnerLocator]
}

enum ReleasePostverificationFreezeError: Error, Equatable, Sendable {
  case emptyComponent
  case componentHandleUnknownOrReplayed
  case componentBindingMismatch
  case invalidExecutionBinding
  case duplicateOwner(ActionID)
  case duplicateAllocationGroup(String)
  case invalidOwnerMembership(String)
  case invalidOwnerLeaf(ActionID)
  case invalidNamespaceChain(ActionID)
  case descriptorDuplicationFailed(ActionID, ReleasePostverificationNamespaceLocation, Int32)
  case namespaceMissing(ActionID, ReleasePostverificationNamespaceLocation)
  case namespaceUnreadable(
    ActionID, ReleasePostverificationNamespaceLocation, ObservationFailure
  )
  case namespaceCollectionFailed(
    ActionID, ReleasePostverificationNamespaceLocation, ObservationFailure
  )
  case namespaceUnknown(ActionID, ReleasePostverificationNamespaceLocation, UnknownReason)
  case namespaceIdentityMismatch(ActionID, ReleasePostverificationNamespaceLocation)
  case namespaceAccessMismatch(ActionID, ReleasePostverificationNamespaceLocation)
  case namespaceContainmentMismatch(ActionID, ReleasePostverificationNamespaceLocation)
  case targetMissing(ActionID)
  case targetUnreadable(ActionID, ObservationFailure)
  case targetCollectionFailed(ActionID, ObservationFailure)
  case targetUnknown(ActionID, UnknownReason)
  case targetIdentityMismatch(ActionID)
}

enum ReleasePostverificationFailure: Error, Equatable, Sendable {
  case leaseAlreadyConsumed
  case namespaceMissing(ActionID, ReleasePostverificationNamespaceLocation)
  case namespaceUnreadable(
    ActionID, ReleasePostverificationNamespaceLocation, ObservationFailure
  )
  case namespaceIdentityMismatch(ActionID, ReleasePostverificationNamespaceLocation)
  case namespaceAccessMismatch(ActionID, ReleasePostverificationNamespaceLocation)
  case namespaceContainmentMismatch(ActionID, ReleasePostverificationNamespaceLocation)
  case namespaceCollectionFailed(
    ActionID, ReleasePostverificationNamespaceLocation, ObservationFailure
  )
  case namespaceUnknown(ActionID, ReleasePostverificationNamespaceLocation, UnknownReason)
  case ownerSlotUnreadable(ActionID, ObservationFailure)
  case ownerSlotCollectionFailed(ActionID, ObservationFailure)
  case ownerSlotUnknown(ActionID, UnknownReason)
  case ownerSlotStillReferencesExpectedObject(ActionID)
  case ownerSlotChangedAfterTopology(ActionID)
  case topologyMissing
  case topologyUnreadable(ObservationFailure)
  case topologyCollectorFailed(ObservationFailure)
  case topologyUnknown(UnknownReason)
  case topologyReceiptBindingMismatch
  case topologyReceiptNotFresh
  case topologyCaptureReused
  case allocationGroupStillAllocated(String)
  case invalidAllocationGroupReleaseEvidence(String)
}

struct ReleasedFileObjectTopologyEvidence: Equatable, Sendable {
  let fileObjectID: Data
  let remainingOwnerCount: UInt32
}

struct AllocationGroupReleasedTopologyEvidence: Equatable, Sendable {
  let allocationGroupID: String
  let allocationGroupPresent: Bool
  let fileObjects: [ReleasedFileObjectTopologyEvidence]

  static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.allocationGroupID) == RawUTF8Key(rhs.allocationGroupID)
      && lhs.allocationGroupPresent == rhs.allocationGroupPresent
      && lhs.fileObjects == rhs.fileObjects
  }
}

enum CurrentAllocationGroupReleaseTopology: Equatable, Sendable {
  case allocationGroupReleased(AllocationGroupReleasedTopologyEvidence)
  case allocationGroupStillAllocated
}

struct CurrentReleaseTopologyGroup: Equatable, Sendable {
  let allocationGroupID: String
  let topology: CurrentAllocationGroupReleaseTopology

  static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.allocationGroupID) == RawUTF8Key(rhs.allocationGroupID)
      && lhs.topology == rhs.topology
  }
}

struct CurrentReleaseTopologyCapture: Equatable, Sendable {
  let captureID: PolicyDigest
  let executionBindingHash: PolicyDigest
  let componentID: PolicyDigest
  let epochID: String
  let oneShotNonce: Data
  let capturedAtSeconds: Int64
  let groups: [CurrentReleaseTopologyGroup]
}

struct ReleasePostverificationTopologyOwner: Sendable {
  let actionID: ActionID
  let candidateID: String
  let expectedIdentity: ObjectIdentity
  let namespaceComponentCount: Int
  let rawLeafName: Data
  let transition: ReleaseOwnerSlotTransition
}

struct ReleasePostverificationTopologyRequest: Sendable {
  let executionBindingHash: PolicyDigest
  let componentID: PolicyDigest
  let epoch: ExecutionEpochContext
  let oneShotNonce: Data
  let groups: [ReleasePostverificationGroupExpectation]
  let owners: [ReleasePostverificationTopologyOwner]
}

final class EngineReleaseTopologyCollectionOperation: @unchecked Sendable {
  let request: ReleasePostverificationTopologyRequest
  private let descriptorOwner: EngineReleaseTopologyDescriptorOwner

  fileprivate init(
    request: ReleasePostverificationTopologyRequest,
    descriptorOwner: EngineReleaseTopologyDescriptorOwner
  ) {
    self.request = request
    self.descriptorOwner = descriptorOwner
  }

  /// The collector can inspect descriptor capabilities without receiving closeable descriptor
  /// integers. Raw descriptor access remains inside the engine-owned collector implementation.
  func allNamespaceDescriptorsAreCloseOnExec() -> Bool {
    descriptorOwner.allCloseOnExec()
  }

  func namespaceDescriptorCount(for actionID: ActionID) -> Int {
    descriptorOwner.count(for: actionID)
  }

  fileprivate func finish() { descriptorOwner.closeAll() }
}

final class EngineReleasePostverificationTopologyCollector: @unchecked Sendable {
  typealias Collection =
    @Sendable (
      EngineReleaseTopologyCollectionOperation
    ) async throws -> Observation<CurrentReleaseTopologyCapture>

  private let collection: Collection

  init(engineOwnedCollection: @escaping Collection) {
    collection = engineOwnedCollection
  }

  fileprivate func collect(
    _ operation: EngineReleaseTopologyCollectionOperation
  ) async throws -> Observation<CurrentReleaseTopologyCapture> {
    defer { operation.finish() }
    return try await collection(operation)
  }
}

enum ReleaseOwnerSlotObservation: Equatable, Sendable {
  case missing
  case present(ObjectIdentity)
  case unknown(UnknownReason)
  case unreadable(ObservationFailure)
  case failed(ObservationFailure)
}

protocol ReleasePostverificationDescriptorProbing: Sendable {
  func namespaceSeal(descriptor: Int32) -> Observation<ReleaseDescriptorNamespaceSeal>
  func ownerSlot(
    parentDescriptor: Int32,
    rawLeafName: Data
  ) -> ReleaseOwnerSlotObservation
  func descendantDirectory(
    parentDescriptor: Int32,
    rawName: Data
  ) -> Observation<Int32>
}

struct POSIXReleasePostverificationDescriptorProbe: ReleasePostverificationDescriptorProbing {
  private let betweenAccessSamples: @Sendable (Int32) -> Void

  init(betweenAccessSamples: @escaping @Sendable (Int32) -> Void = { _ in }) {
    self.betweenAccessSamples = betweenAccessSamples
  }

  private enum SealSubcollectionResult<Value> {
    case success(Value)
    case failure(Observation<ReleaseDescriptorNamespaceSeal>)
  }

  func namespaceSeal(descriptor: Int32) -> Observation<ReleaseDescriptorNamespaceSeal> {
    var before = stat()
    guard Darwin.fstat(descriptor, &before) == 0 else {
      return Self.observationFailure(errno, operation: "fstat-namespace")
    }
    guard let identity = Self.identity(before) else {
      return .failed(
        ObservationFailure(
          code: "unsupported-namespace-object-kind",
          collector: "release-postverification-descriptor"
        ))
    }
    let firstACLDigest: PolicyDigest
    switch Self.aclDigest(descriptor) {
    case .success(let value): firstACLDigest = value
    case .failure(let observation): return observation
    }
    let firstMountIdentity: Data
    switch Self.mountIdentity(descriptor) {
    case .success(let value): firstMountIdentity = value
    case .failure(let observation): return observation
    }
    betweenAccessSamples(descriptor)
    var middle = stat()
    guard Darwin.fstat(descriptor, &middle) == 0 else {
      return Self.observationFailure(errno, operation: "fstat-namespace-after-access")
    }
    guard Self.accessSignals(middle) == Self.accessSignals(before),
      Self.identity(middle) == identity
    else {
      return .failed(
        ObservationFailure(
          code: "namespace-access-changed-during-seal",
          collector: "release-postverification-descriptor"
        ))
    }
    let secondACLDigest: PolicyDigest
    switch Self.aclDigest(descriptor) {
    case .success(let value): secondACLDigest = value
    case .failure(let observation): return observation
    }
    let secondMountIdentity: Data
    switch Self.mountIdentity(descriptor) {
    case .success(let value): secondMountIdentity = value
    case .failure(let observation): return observation
    }
    var after = stat()
    guard Darwin.fstat(descriptor, &after) == 0 else {
      return Self.observationFailure(errno, operation: "fstat-namespace-final")
    }
    guard Self.identity(after) == identity,
      Self.accessSignals(after) == Self.accessSignals(before),
      firstACLDigest == secondACLDigest,
      firstMountIdentity == secondMountIdentity
    else {
      return .failed(
        ObservationFailure(
          code: "namespace-access-changed-during-seal",
          collector: "release-postverification-descriptor"
        ))
    }
    return .known(
      ReleaseDescriptorNamespaceSeal(
        identity: identity,
        access: ReleaseDescriptorAccessSeal(
          mode: UInt32(before.st_mode),
          ownerUserID: before.st_uid,
          ownerGroupID: before.st_gid,
          authorizationFlags: Self.authorizationFlags(before.st_flags),
          aclDigest: firstACLDigest,
          mountIdentity: firstMountIdentity
        )
      ))
  }

  func ownerSlot(
    parentDescriptor: Int32,
    rawLeafName: Data
  ) -> ReleaseOwnerSlotObservation {
    var value = stat()
    let result = Self.withRawCString(rawLeafName) { name in
      Darwin.fstatat(parentDescriptor, name, &value, AT_SYMLINK_NOFOLLOW)
    }
    guard result == 0 else {
      let currentErrno = errno
      if currentErrno == ENOENT { return .missing }
      let failure = ObservationFailure(
        code: "fstatat-owner-slot-errno-\(currentErrno)",
        collector: "release-postverification-descriptor"
      )
      return currentErrno == EACCES || currentErrno == EPERM
        ? .unreadable(failure)
        : .failed(failure)
    }
    guard let identity = Self.identity(value) else {
      return .failed(
        ObservationFailure(
          code: "unsupported-owner-object-kind",
          collector: "release-postverification-descriptor"
        ))
    }
    return .present(identity)
  }

  func descendantDirectory(
    parentDescriptor: Int32,
    rawName: Data
  ) -> Observation<Int32> {
    let descriptor = Self.withRawCString(rawName) { name in
      Darwin.openat(
        parentDescriptor,
        name,
        O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC
      )
    }
    guard descriptor >= 0 else {
      return Self.observationFailure(errno, operation: "open-namespace-descendant")
    }
    return .known(descriptor)
  }

  private static func aclDigest(
    _ descriptor: Int32
  ) -> SealSubcollectionResult<PolicyDigest> {
    errno = 0
    guard let acl = Darwin.acl_get_fd_np(descriptor, ACL_TYPE_EXTENDED) else {
      if errno == ENOENT {
        return .success(
          try! PolicyDigest(
            bytes: Data(SHA256.hash(data: Data("diskplan/empty-acl/v1".utf8)))
          )
        )
      }
      return .failure(observationFailure(errno, operation: "read-namespace-acl"))
    }
    defer { _ = Darwin.acl_free(UnsafeMutableRawPointer(acl)) }
    var length: ssize_t = 0
    guard let text = Darwin.acl_to_text(acl, &length), length >= 0 else {
      return .failure(observationFailure(errno, operation: "serialize-namespace-acl"))
    }
    defer { _ = Darwin.acl_free(text) }
    return .success(
      try! PolicyDigest(
        bytes: Data(SHA256.hash(data: Data(bytes: text, count: Int(length))))
      )
    )
  }

  private static func mountIdentity(
    _ descriptor: Int32
  ) -> SealSubcollectionResult<Data> {
    var value = statfs()
    guard Darwin.fstatfs(descriptor, &value) == 0 else {
      return .failure(observationFailure(errno, operation: "fstatfs-namespace-mount"))
    }
    return .success(withUnsafeBytes(of: value.f_fsid) { Data($0) })
  }

  private static func observationFailure<Value: Equatable & Sendable>(
    _ currentErrno: Int32,
    operation: String
  ) -> Observation<Value> {
    if currentErrno == ENOENT { return .absent }
    let failure = ObservationFailure(
      code: "\(operation)-errno-\(currentErrno)",
      collector: "release-postverification-descriptor"
    )
    return currentErrno == EACCES || currentErrno == EPERM
      ? .unreadable(failure)
      : .failed(failure)
  }

  fileprivate static func identity(_ value: stat) -> ObjectIdentity? {
    let kind: ObjectKind
    switch value.st_mode & S_IFMT {
    case S_IFREG: kind = .regularFile
    case S_IFDIR: kind = .directory
    case S_IFLNK: kind = .symbolicLink
    default: return nil
    }
    return ObjectIdentity(
      device: UInt64(UInt32(bitPattern: value.st_dev)),
      object: UInt64(value.st_ino),
      generation: .known(UInt64(value.st_gen)),
      type: kind
    )
  }

  private static func authorizationFlags(_ flags: UInt32) -> UInt32 {
    flags & 0x001E_0086
  }

  private static func accessSignals(_ value: stat) -> (UInt32, UInt32, UInt32, UInt32) {
    (
      UInt32(value.st_mode),
      value.st_uid,
      value.st_gid,
      authorizationFlags(value.st_flags)
    )
  }

  private static func withRawCString<Result>(
    _ bytes: Data,
    _ body: (UnsafePointer<CChar>) -> Result
  ) -> Result {
    var terminated = [UInt8](bytes)
    terminated.append(0)
    return terminated.withUnsafeBufferPointer { buffer in
      body(UnsafeRawPointer(buffer.baseAddress!).assumingMemoryBound(to: CChar.self))
    }
  }
}

struct EngineAllocationGroupReleaseReceipt: Equatable, Sendable {
  let allocationGroupID: String
  let captureID: PolicyDigest
  let executionBindingHash: PolicyDigest
  let componentID: PolicyDigest
  let epochID: String
  let capturedAtSeconds: Int64
  let releasedFileObjectIDs: [Data]

  fileprivate init(
    allocationGroupID: String,
    captureID: PolicyDigest,
    executionBindingHash: PolicyDigest,
    componentID: PolicyDigest,
    epochID: String,
    capturedAtSeconds: Int64,
    releasedFileObjectIDs: [Data]
  ) {
    self.allocationGroupID = allocationGroupID
    self.captureID = captureID
    self.executionBindingHash = executionBindingHash
    self.componentID = componentID
    self.epochID = epochID
    self.capturedAtSeconds = capturedAtSeconds
    self.releasedFileObjectIDs = releasedFileObjectIDs
  }

  static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.allocationGroupID) == RawUTF8Key(rhs.allocationGroupID)
      && lhs.captureID == rhs.captureID
      && lhs.executionBindingHash == rhs.executionBindingHash
      && lhs.componentID == rhs.componentID
      && lhs.epochID == rhs.epochID
      && lhs.capturedAtSeconds == rhs.capturedAtSeconds
      && lhs.releasedFileObjectIDs == rhs.releasedFileObjectIDs
  }
}

struct DescriptorBoundAllocationGroupPostverification: Equatable, Sendable {
  let allocationGroupID: String
  let outcome: DescriptorBoundAllocationGroupOutcome

  static func == (lhs: Self, rhs: Self) -> Bool {
    RawUTF8Key(lhs.allocationGroupID) == RawUTF8Key(rhs.allocationGroupID)
      && lhs.outcome == rhs.outcome
  }
}

enum DescriptorBoundAllocationGroupOutcome: Equatable, Sendable {
  case allocationGroupReleased(EngineAllocationGroupReleaseReceipt)
  case rejected(ReleasePostverificationFailure)
}

struct DescriptorBoundReleasePostverificationReport: Equatable, Sendable {
  let ownerTransitions: [ActionID: ReleaseOwnerSlotTransition]
  let groups: [DescriptorBoundAllocationGroupPostverification]
}

private struct FrozenReleaseNamespaceComponent: Sendable {
  let rawNameFromParent: Data?
  let descriptor: Int32
  let authorizedSeal: ReleaseDescriptorNamespaceSeal
}

private struct FrozenReleasePostverificationOwner: Sendable {
  let actionID: ActionID
  let candidateID: String
  let expectedIdentity: ObjectIdentity
  let namespace: [FrozenReleaseNamespaceComponent]
  let rawLeafName: Data
}

final class FrozenReleasePostverificationComponent: @unchecked Sendable {
  fileprivate let execution: ReleasePostverificationExecutionBinding
  fileprivate let componentID: PolicyDigest
  fileprivate let frozenAtSeconds: Int64
  fileprivate let owners: [FrozenReleasePostverificationOwner]
  fileprivate let groups: [ReleasePostverificationGroupExpectation]
  private let lock = NSLock()
  private var consumed = false
  private var descriptorsClosed = false

  fileprivate init(
    execution: ReleasePostverificationExecutionBinding,
    componentID: PolicyDigest,
    frozenAtSeconds: Int64,
    owners: [FrozenReleasePostverificationOwner],
    groups: [ReleasePostverificationGroupExpectation]
  ) {
    self.execution = execution
    self.componentID = componentID
    self.frozenAtSeconds = frozenAtSeconds
    self.owners = owners
    self.groups = groups
  }

  deinit { closeOwnedDescriptors() }

  var ownedDescriptorValues: [Int32] {
    owners.flatMap { $0.namespace.map(\.descriptor) }
  }

  fileprivate func claim() -> Bool {
    lock.lock()
    defer { lock.unlock() }
    guard !consumed else { return false }
    consumed = true
    return true
  }

  fileprivate func finishConsumption() {
    closeOwnedDescriptors()
  }

  private func closeOwnedDescriptors() {
    lock.lock()
    guard !descriptorsClosed else {
      lock.unlock()
      return
    }
    descriptorsClosed = true
    let descriptors = owners.flatMap { $0.namespace.map(\.descriptor) }
    lock.unlock()
    for descriptor in descriptors { _ = Darwin.close(descriptor) }
  }
}

private final class EngineReleaseTopologyDescriptorOwner: @unchecked Sendable {
  private struct Entry {
    let actionID: ActionID
    let descriptor: Int32
  }

  private var entries: [Entry]
  private let lock = NSLock()
  private var closed = false

  init(entries: [(ActionID, Int32)]) {
    self.entries = entries.map { Entry(actionID: $0.0, descriptor: $0.1) }
  }

  deinit { closeAll() }

  func allCloseOnExec() -> Bool {
    lock.lock()
    let pending = entries
    let isClosed = closed
    lock.unlock()
    guard !isClosed else { return false }
    return pending.allSatisfy { entry in
      let flags = Darwin.fcntl(entry.descriptor, F_GETFD)
      return flags >= 0 && flags & FD_CLOEXEC != 0
    }
  }

  func count(for actionID: ActionID) -> Int {
    lock.lock()
    defer { lock.unlock() }
    return closed ? 0 : entries.filter { $0.actionID == actionID }.count
  }

  func closeAll() {
    lock.lock()
    guard !closed else {
      lock.unlock()
      return
    }
    closed = true
    let pending = entries
    entries.removeAll()
    lock.unlock()
    for entry in pending { _ = Darwin.close(entry.descriptor) }
  }
}

private final class ReleaseTopologyCaptureRegistry: @unchecked Sendable {
  private let lock = NSLock()
  private var used = Set<PolicyDigest>()

  func claim(_ captureID: PolicyDigest) -> Bool {
    lock.lock()
    defer { lock.unlock() }
    return used.insert(captureID).inserted
  }
}

struct DescriptorBoundReleasePostverificationCore: Sendable {
  private let descriptorProbe: any ReleasePostverificationDescriptorProbing
  private let topologyCollector: EngineReleasePostverificationTopologyCollector
  private let nowSeconds: @Sendable () -> Int64
  private let nonceGenerator: @Sendable () -> Data
  private let captureRegistry: ReleaseTopologyCaptureRegistry

  init(
    topologyCollector: EngineReleasePostverificationTopologyCollector,
    descriptorProbe: any ReleasePostverificationDescriptorProbing =
      POSIXReleasePostverificationDescriptorProbe(),
    nowSeconds: @escaping @Sendable () -> Int64 = {
      Int64(Date().timeIntervalSince1970.rounded(.down))
    },
    nonceGenerator: @escaping @Sendable () -> Data = {
      var generator = SystemRandomNumberGenerator()
      return Data((0..<32).map { _ in UInt8.random(in: .min ... .max, using: &generator) })
    }
  ) {
    self.topologyCollector = topologyCollector
    self.descriptorProbe = descriptorProbe
    self.nowSeconds = nowSeconds
    self.nonceGenerator = nonceGenerator
    self.captureRegistry = ReleaseTopologyCaptureRegistry()
  }

  func freeze(
    _ request: ReleasePostverificationComponentRequest
  ) throws -> FrozenReleasePostverificationComponent {
    let frozenAtSeconds = nowSeconds()
    guard let trusted = request.componentHandle.claim() else {
      throw ReleasePostverificationFreezeError.componentHandleUnknownOrReplayed
    }
    guard
      trusted.schema.digest(
        execution: trusted.execution,
        owners: request.owners,
        groups: trusted.groups
      ) == trusted.componentID
    else {
      throw ReleasePostverificationFreezeError.componentBindingMismatch
    }
    guard !request.owners.isEmpty, !trusted.groups.isEmpty else {
      throw ReleasePostverificationFreezeError.emptyComponent
    }
    guard trusted.execution.planCaptureID != trusted.execution.wholePlanCaptureID,
      trusted.execution.planCaptureID != trusted.execution.jitCaptureID,
      trusted.execution.wholePlanCaptureID != trusted.execution.jitCaptureID,
      trusted.execution.jitOneShotNonce.count == 32,
      trusted.execution.freshnessLimitSeconds > 0,
      frozenAtSeconds >= trusted.execution.epoch.issuedAtSeconds,
      frozenAtSeconds < trusted.execution.epoch.deadlineSeconds
    else {
      throw ReleasePostverificationFreezeError.invalidExecutionBinding
    }
    var seenOwners = Set<ActionID>()
    for owner in request.owners {
      guard seenOwners.insert(owner.actionID).inserted else {
        throw ReleasePostverificationFreezeError.duplicateOwner(owner.actionID)
      }
      guard Self.isValidLeaf(owner.rawLeafName) else {
        throw ReleasePostverificationFreezeError.invalidOwnerLeaf(owner.actionID)
      }
      guard !owner.namespace.isEmpty,
        owner.namespace[0].rawNameFromParent == nil,
        owner.namespace[0].authorizedSeal.identity.type == .directory,
        owner.namespace.dropFirst().allSatisfy({
          $0.authorizedSeal.identity.type == .directory
            && $0.rawNameFromParent.map(Self.isValidLeaf) == true
        })
      else {
        throw ReleasePostverificationFreezeError.invalidNamespaceChain(owner.actionID)
      }
    }
    let allOwnerIDs = seenOwners
    var seenGroups = Set<RawUTF8Key>()
    for group in trusted.groups {
      guard seenGroups.insert(RawUTF8Key(group.allocationGroupID)).inserted else {
        throw ReleasePostverificationFreezeError.duplicateAllocationGroup(
          group.allocationGroupID
        )
      }
      guard
        RawUTF8Key(group.topology.allocationGroupID)
          == RawUTF8Key(group.allocationGroupID),
        !group.ownerActionIDs.isEmpty,
        Set(group.ownerActionIDs).count == group.ownerActionIDs.count,
        Set(group.ownerActionIDs).isSubset(of: allOwnerIDs)
      else {
        throw ReleasePostverificationFreezeError.invalidOwnerMembership(
          group.allocationGroupID
        )
      }
    }

    var frozenOwners: [FrozenReleasePostverificationOwner] = []
    do {
      for owner in request.owners.sorted(by: { $0.actionID < $1.actionID }) {
        frozenOwners.append(try freezeOwner(owner))
      }
    } catch {
      for owner in frozenOwners {
        for component in owner.namespace { _ = Darwin.close(component.descriptor) }
      }
      throw error
    }
    return FrozenReleasePostverificationComponent(
      execution: trusted.execution,
      componentID: trusted.componentID,
      frozenAtSeconds: frozenAtSeconds,
      owners: frozenOwners,
      groups: trusted.groups.sorted {
        RawUTF8Key($0.allocationGroupID) < RawUTF8Key($1.allocationGroupID)
      }
    )
  }

  func postverify(
    _ component: FrozenReleasePostverificationComponent
  ) async -> DescriptorBoundReleasePostverificationReport {
    guard component.claim() else {
      return rejectedReport(
        groups: component.groups,
        transitions: [:],
        failure: .leaseAlreadyConsumed
      )
    }
    defer { component.finishConsumption() }

    var transitions: [ActionID: ReleaseOwnerSlotTransition] = [:]
    var ownerFailures: [ActionID: ReleasePostverificationFailure] = [:]
    for owner in component.owners {
      if let failure = verifyNamespace(owner) {
        ownerFailures[owner.actionID] = failure
        continue
      }
      switch descriptorProbe.ownerSlot(
        parentDescriptor: owner.namespace.last!.descriptor,
        rawLeafName: owner.rawLeafName
      ) {
      case .missing:
        transitions[owner.actionID] = .missing
      case .present(let identity):
        if identity == owner.expectedIdentity {
          ownerFailures[owner.actionID] =
            .ownerSlotStillReferencesExpectedObject(owner.actionID)
        } else {
          transitions[owner.actionID] = .identityChanged(current: identity)
        }
      case .unknown(let reason):
        ownerFailures[owner.actionID] = .ownerSlotUnknown(owner.actionID, reason)
      case .unreadable(let failure):
        ownerFailures[owner.actionID] = .ownerSlotUnreadable(owner.actionID, failure)
      case .failed(let failure):
        ownerFailures[owner.actionID] = .ownerSlotCollectionFailed(owner.actionID, failure)
      }
    }
    if let failure = component.owners.map(\.actionID).sorted()
      .compactMap({ ownerFailures[$0] }).first
    {
      return rejectedReport(
        groups: component.groups,
        transitions: transitions,
        failure: failure
      )
    }

    switch await collectTopology(component: component, transitions: transitions) {
    case .failure(let failure):
      return rejectedReport(
        groups: component.groups,
        transitions: transitions,
        failure: failure
      )
    case .success(let receipts):
      let receiptByGroup = Dictionary(
        uniqueKeysWithValues: receipts.map { (RawUTF8Key($0.allocationGroupID), $0) }
      )
      return DescriptorBoundReleasePostverificationReport(
        ownerTransitions: transitions,
        groups: component.groups.map { group in
          DescriptorBoundAllocationGroupPostverification(
            allocationGroupID: group.allocationGroupID,
            outcome: .allocationGroupReleased(
              receiptByGroup[RawUTF8Key(group.allocationGroupID)]!
            )
          )
        }
      )
    }
  }

  private func freezeOwner(
    _ owner: ReleasePostverificationOwnerLocator
  ) throws -> FrozenReleasePostverificationOwner {
    var frozen: [FrozenReleaseNamespaceComponent] = []
    do {
      for (index, authorized) in owner.namespace.enumerated() {
        let location = Self.location(index)
        let descriptor = try duplicate(
          authorized.descriptor,
          ownerID: owner.actionID,
          location: location
        )
        do {
          try requireAuthorizedSeal(
            descriptorProbe.namespaceSeal(descriptor: descriptor),
            authorized: authorized.authorizedSeal,
            ownerID: owner.actionID,
            location: location
          )
          frozen.append(
            FrozenReleaseNamespaceComponent(
              rawNameFromParent: authorized.rawNameFromParent,
              descriptor: descriptor,
              authorizedSeal: authorized.authorizedSeal
            )
          )
        } catch {
          _ = Darwin.close(descriptor)
          throw error
        }
      }
      try requireContainedChain(frozen, ownerID: owner.actionID, freeze: true)
      switch descriptorProbe.ownerSlot(
        parentDescriptor: frozen.last!.descriptor,
        rawLeafName: owner.rawLeafName
      ) {
      case .missing:
        throw ReleasePostverificationFreezeError.targetMissing(owner.actionID)
      case .unknown(let reason):
        throw ReleasePostverificationFreezeError.targetUnknown(owner.actionID, reason)
      case .unreadable(let failure):
        throw ReleasePostverificationFreezeError.targetUnreadable(owner.actionID, failure)
      case .failed(let failure):
        throw ReleasePostverificationFreezeError.targetCollectionFailed(
          owner.actionID, failure
        )
      case .present(let identity):
        guard identity == owner.expectedIdentity else {
          throw ReleasePostverificationFreezeError.targetIdentityMismatch(owner.actionID)
        }
      }
      return FrozenReleasePostverificationOwner(
        actionID: owner.actionID,
        candidateID: owner.candidateID,
        expectedIdentity: owner.expectedIdentity,
        namespace: frozen,
        rawLeafName: owner.rawLeafName
      )
    } catch {
      for component in frozen { _ = Darwin.close(component.descriptor) }
      throw error
    }
  }

  private func verifyNamespace(
    _ owner: FrozenReleasePostverificationOwner
  ) -> ReleasePostverificationFailure? {
    for (index, component) in owner.namespace.enumerated() {
      let location = Self.location(index)
      switch descriptorProbe.namespaceSeal(descriptor: component.descriptor) {
      case .absent:
        return .namespaceMissing(owner.actionID, location)
      case .unknown(let reason):
        return .namespaceUnknown(owner.actionID, location, reason)
      case .unreadable(let failure):
        return .namespaceUnreadable(owner.actionID, location, failure)
      case .failed(let failure):
        return .namespaceCollectionFailed(owner.actionID, location, failure)
      case .known(let current):
        guard current.identity == component.authorizedSeal.identity else {
          return .namespaceIdentityMismatch(owner.actionID, location)
        }
        guard current.access == component.authorizedSeal.access else {
          return .namespaceAccessMismatch(owner.actionID, location)
        }
      }
    }
    do {
      try requireContainedChain(owner.namespace, ownerID: owner.actionID, freeze: false)
      return nil
    } catch let failure as ReleasePostverificationFailure {
      return failure
    } catch {
      return .namespaceCollectionFailed(
        owner.actionID,
        .root,
        ObservationFailure(
          code: String(reflecting: type(of: error)),
          collector: "release-postverification-descriptor"
        )
      )
    }
  }

  private func requireContainedChain(
    _ chain: [FrozenReleaseNamespaceComponent],
    ownerID: ActionID,
    freeze: Bool
  ) throws {
    guard chain.count > 1 else { return }
    for index in 1..<chain.count {
      let location = Self.location(index)
      let expected = chain[index].authorizedSeal
      guard let name = chain[index].rawNameFromParent else {
        if freeze {
          throw ReleasePostverificationFreezeError.invalidNamespaceChain(ownerID)
        }
        throw ReleasePostverificationFailure.namespaceContainmentMismatch(ownerID, location)
      }
      let opened: Int32
      switch descriptorProbe.descendantDirectory(
        parentDescriptor: chain[index - 1].descriptor,
        rawName: name
      ) {
      case .known(let descriptor):
        opened = descriptor
      case .absent:
        if freeze {
          throw ReleasePostverificationFreezeError.namespaceMissing(ownerID, location)
        }
        throw ReleasePostverificationFailure.namespaceMissing(ownerID, location)
      case .unknown(let reason):
        if freeze {
          throw ReleasePostverificationFreezeError.namespaceUnknown(ownerID, location, reason)
        }
        throw ReleasePostverificationFailure.namespaceUnknown(ownerID, location, reason)
      case .unreadable(let failure):
        if freeze {
          throw ReleasePostverificationFreezeError.namespaceUnreadable(
            ownerID, location, failure
          )
        }
        throw ReleasePostverificationFailure.namespaceUnreadable(ownerID, location, failure)
      case .failed(let failure):
        if freeze {
          throw ReleasePostverificationFreezeError.namespaceCollectionFailed(
            ownerID, location, failure
          )
        }
        throw ReleasePostverificationFailure.namespaceCollectionFailed(
          ownerID, location, failure
        )
      }
      defer { _ = Darwin.close(opened) }
      switch descriptorProbe.namespaceSeal(descriptor: opened) {
      case .known(let current):
        guard current.identity == expected.identity else {
          if freeze {
            throw ReleasePostverificationFreezeError.namespaceContainmentMismatch(
              ownerID, location
            )
          }
          throw ReleasePostverificationFailure.namespaceContainmentMismatch(
            ownerID, location
          )
        }
        guard current.access == expected.access else {
          if freeze {
            throw ReleasePostverificationFreezeError.namespaceAccessMismatch(
              ownerID, location
            )
          }
          throw ReleasePostverificationFailure.namespaceAccessMismatch(ownerID, location)
        }
      case .absent:
        if freeze {
          throw ReleasePostverificationFreezeError.namespaceMissing(ownerID, location)
        }
        throw ReleasePostverificationFailure.namespaceMissing(ownerID, location)
      case .unknown(let reason):
        if freeze {
          throw ReleasePostverificationFreezeError.namespaceUnknown(ownerID, location, reason)
        }
        throw ReleasePostverificationFailure.namespaceUnknown(ownerID, location, reason)
      case .unreadable(let failure):
        if freeze {
          throw ReleasePostverificationFreezeError.namespaceUnreadable(
            ownerID, location, failure
          )
        }
        throw ReleasePostverificationFailure.namespaceUnreadable(ownerID, location, failure)
      case .failed(let failure):
        if freeze {
          throw ReleasePostverificationFreezeError.namespaceCollectionFailed(
            ownerID, location, failure
          )
        }
        throw ReleasePostverificationFailure.namespaceCollectionFailed(
          ownerID, location, failure
        )
      }
    }
  }

  private func collectTopology(
    component: FrozenReleasePostverificationComponent,
    transitions: [ActionID: ReleaseOwnerSlotTransition]
  ) async -> Result<[EngineAllocationGroupReleaseReceipt], ReleasePostverificationFailure> {
    let nonce = nonceGenerator()
    guard nonce.count == 32 else { return .failure(.topologyReceiptBindingMismatch) }
    let operation: EngineReleaseTopologyCollectionOperation
    do {
      operation = try makeTopologyOperation(
        component: component,
        nonce: nonce,
        component.owners,
        transitions: transitions
      )
    } catch let failure as ReleasePostverificationFailure {
      return .failure(failure)
    } catch {
      return .failure(
        .topologyCollectorFailed(
          ObservationFailure(
            code: String(reflecting: type(of: error)),
            collector: "release-topology-descriptor-duplication"
          )
        )
      )
    }
    let observation: Observation<CurrentReleaseTopologyCapture>
    do {
      observation = try await topologyCollector.collect(operation)
    } catch {
      return .failure(
        .topologyCollectorFailed(
          ObservationFailure(
            code: error is CancellationError
              ? "cancelled" : String(reflecting: type(of: error)),
            collector: "release-topology-collector"
          )
        )
      )
    }
    switch observation {
    case .absent:
      return .failure(.topologyMissing)
    case .unknown(let reason):
      return .failure(.topologyUnknown(reason))
    case .unreadable(let failure):
      return .failure(.topologyUnreadable(failure))
    case .failed(let failure):
      return .failure(.topologyCollectorFailed(failure))
    case .known(let capture):
      if let failure = revalidateAfterTopology(
        component: component,
        transitions: transitions
      ) {
        return .failure(failure)
      }
      return validateCapture(capture, component: component, nonce: nonce)
    }
  }

  private func revalidateAfterTopology(
    component: FrozenReleasePostverificationComponent,
    transitions: [ActionID: ReleaseOwnerSlotTransition]
  ) -> ReleasePostverificationFailure? {
    for owner in component.owners {
      if let failure = verifyNamespace(owner) { return failure }
      guard let expected = transitions[owner.actionID] else {
        return .ownerSlotChangedAfterTopology(owner.actionID)
      }
      switch (
        expected,
        descriptorProbe.ownerSlot(
          parentDescriptor: owner.namespace.last!.descriptor,
          rawLeafName: owner.rawLeafName
        )
      ) {
      case (.missing, .missing):
        continue
      case (.identityChanged(let expectedIdentity), .present(let currentIdentity))
      where expectedIdentity == currentIdentity:
        continue
      case (_, .unreadable(let failure)):
        return .ownerSlotUnreadable(owner.actionID, failure)
      case (_, .failed(let failure)):
        return .ownerSlotCollectionFailed(owner.actionID, failure)
      case (_, .unknown(let reason)):
        return .ownerSlotUnknown(owner.actionID, reason)
      default:
        return .ownerSlotChangedAfterTopology(owner.actionID)
      }
    }
    return nil
  }

  private func validateCapture(
    _ capture: CurrentReleaseTopologyCapture,
    component: FrozenReleasePostverificationComponent,
    nonce: Data
  ) -> Result<[EngineAllocationGroupReleaseReceipt], ReleasePostverificationFailure> {
    let now = nowSeconds()
    let execution = component.execution
    guard capture.executionBindingHash == execution.executionBindingHash,
      capture.componentID == component.componentID,
      capture.epochID == execution.epoch.epochID,
      capture.oneShotNonce == nonce
    else {
      return .failure(.topologyReceiptBindingMismatch)
    }
    guard capture.captureID != execution.planCaptureID,
      capture.captureID != execution.wholePlanCaptureID,
      capture.captureID != execution.jitCaptureID
    else {
      return .failure(.topologyCaptureReused)
    }
    let captureAge = now.subtractingReportingOverflow(capture.capturedAtSeconds)
    guard capture.capturedAtSeconds >= component.frozenAtSeconds,
      capture.capturedAtSeconds >= execution.epoch.issuedAtSeconds,
      capture.capturedAtSeconds < execution.epoch.deadlineSeconds,
      capture.capturedAtSeconds <= now,
      !captureAge.overflow,
      captureAge.partialValue <= execution.freshnessLimitSeconds
    else {
      return .failure(.topologyReceiptNotFresh)
    }
    let capturesByGroup = Dictionary(grouping: capture.groups) {
      RawUTF8Key($0.allocationGroupID)
    }
    let expectedGroupKeys = Set(
      component.groups.map {
        RawUTF8Key($0.allocationGroupID)
      })
    guard capturesByGroup.count == component.groups.count,
      Set(capturesByGroup.keys) == expectedGroupKeys,
      capturesByGroup.values.allSatisfy({ $0.count == 1 })
    else {
      return .failure(.topologyReceiptBindingMismatch)
    }

    var receipts: [EngineAllocationGroupReleaseReceipt] = []
    for expected in component.groups {
      let groupID = expected.allocationGroupID
      let captured = capturesByGroup[RawUTF8Key(groupID)]!.first!
      switch captured.topology {
      case .allocationGroupStillAllocated:
        return .failure(.allocationGroupStillAllocated(groupID))
      case .allocationGroupReleased(let evidence):
        guard RawUTF8Key(evidence.allocationGroupID) == RawUTF8Key(groupID),
          !evidence.allocationGroupPresent
        else {
          return .failure(.invalidAllocationGroupReleaseEvidence(groupID))
        }
        let expectedFileIDs = expected.topology.fileObjects.map {
          Data($0.fileObjectID.utf8)
        }.sorted(by: { $0.lexicographicallyPrecedes($1) })
        let capturedFileIDs = evidence.fileObjects.map(\.fileObjectID)
          .sorted(by: { $0.lexicographicallyPrecedes($1) })
        guard Set(expectedFileIDs).count == expectedFileIDs.count,
          Set(capturedFileIDs).count == capturedFileIDs.count,
          expectedFileIDs == capturedFileIDs,
          evidence.fileObjects.allSatisfy({ $0.remainingOwnerCount == 0 })
        else {
          return .failure(.invalidAllocationGroupReleaseEvidence(groupID))
        }
        receipts.append(
          EngineAllocationGroupReleaseReceipt(
            allocationGroupID: groupID,
            captureID: capture.captureID,
            executionBindingHash: capture.executionBindingHash,
            componentID: capture.componentID,
            epochID: capture.epochID,
            capturedAtSeconds: capture.capturedAtSeconds,
            releasedFileObjectIDs: capturedFileIDs
          )
        )
      }
    }
    guard captureRegistry.claim(capture.captureID) else {
      return .failure(.topologyCaptureReused)
    }
    return .success(receipts)
  }

  private func makeTopologyOperation(
    component: FrozenReleasePostverificationComponent,
    nonce: Data,
    _ owners: [FrozenReleasePostverificationOwner],
    transitions: [ActionID: ReleaseOwnerSlotTransition]
  ) throws -> EngineReleaseTopologyCollectionOperation {
    var owned: [(ActionID, Int32)] = []
    var topologyOwners: [ReleasePostverificationTopologyOwner] = []
    do {
      for owner in owners {
        guard let transition = transitions[owner.actionID] else {
          throw ReleasePostverificationFailure.invalidAllocationGroupReleaseEvidence(
            "missing-owner-transition"
          )
        }
        for component in owner.namespace {
          let duplicate = Darwin.fcntl(component.descriptor, F_DUPFD_CLOEXEC, 0)
          guard duplicate >= 0 else {
            throw ReleasePostverificationFailure.topologyCollectorFailed(
              ObservationFailure(
                code: "duplicate-topology-descriptor-errno-\(errno)",
                collector: "release-topology-descriptor-duplication"
              )
            )
          }
          owned.append((owner.actionID, duplicate))
        }
        topologyOwners.append(
          ReleasePostverificationTopologyOwner(
            actionID: owner.actionID,
            candidateID: owner.candidateID,
            expectedIdentity: owner.expectedIdentity,
            namespaceComponentCount: owner.namespace.count,
            rawLeafName: owner.rawLeafName,
            transition: transition
          )
        )
      }
    } catch {
      EngineReleaseTopologyDescriptorOwner(entries: owned).closeAll()
      throw error
    }
    return EngineReleaseTopologyCollectionOperation(
      request: ReleasePostverificationTopologyRequest(
        executionBindingHash: component.execution.executionBindingHash,
        componentID: component.componentID,
        epoch: component.execution.epoch,
        oneShotNonce: nonce,
        groups: component.groups,
        owners: topologyOwners
      ),
      descriptorOwner: EngineReleaseTopologyDescriptorOwner(entries: owned)
    )
  }

  private func rejectedReport(
    groups: [ReleasePostverificationGroupExpectation],
    transitions: [ActionID: ReleaseOwnerSlotTransition],
    failure: ReleasePostverificationFailure
  ) -> DescriptorBoundReleasePostverificationReport {
    DescriptorBoundReleasePostverificationReport(
      ownerTransitions: transitions,
      groups: groups.map {
        DescriptorBoundAllocationGroupPostverification(
          allocationGroupID: $0.allocationGroupID,
          outcome: .rejected(failure)
        )
      }
    )
  }

  private func requireAuthorizedSeal(
    _ observation: Observation<ReleaseDescriptorNamespaceSeal>,
    authorized: ReleaseDescriptorNamespaceSeal,
    ownerID: ActionID,
    location: ReleasePostverificationNamespaceLocation
  ) throws {
    switch observation {
    case .known(let current):
      guard current.identity == authorized.identity else {
        throw ReleasePostverificationFreezeError.namespaceIdentityMismatch(ownerID, location)
      }
      guard current.access == authorized.access else {
        throw ReleasePostverificationFreezeError.namespaceAccessMismatch(ownerID, location)
      }
    case .absent:
      throw ReleasePostverificationFreezeError.namespaceMissing(ownerID, location)
    case .unknown(let reason):
      throw ReleasePostverificationFreezeError.namespaceUnknown(ownerID, location, reason)
    case .unreadable(let failure):
      throw ReleasePostverificationFreezeError.namespaceUnreadable(
        ownerID, location, failure
      )
    case .failed(let failure):
      throw ReleasePostverificationFreezeError.namespaceCollectionFailed(
        ownerID, location, failure
      )
    }
  }

  private func duplicate(
    _ descriptor: Int32,
    ownerID: ActionID,
    location: ReleasePostverificationNamespaceLocation
  ) throws -> Int32 {
    let duplicate = Darwin.fcntl(descriptor, F_DUPFD_CLOEXEC, 0)
    guard duplicate >= 0 else {
      throw ReleasePostverificationFreezeError.descriptorDuplicationFailed(
        ownerID, location, errno
      )
    }
    return duplicate
  }

  private static func location(_ index: Int) -> ReleasePostverificationNamespaceLocation {
    index == 0 ? .root : .parentChain(index: index - 1)
  }

  private static func isValidLeaf(_ leaf: Data) -> Bool {
    !leaf.isEmpty && leaf != Data(".".utf8) && leaf != Data("..".utf8)
      && !leaf.contains(0) && !leaf.contains(47)
  }
}
