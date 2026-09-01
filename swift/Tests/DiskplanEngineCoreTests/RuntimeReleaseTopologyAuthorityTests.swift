import Darwin
import DiskplanPolicy
import Foundation
import Testing

@testable import DiskplanEngineCore

private struct StaticReleaseTopologyProbe: RuntimeReleaseTopologyReadOnlyProbing {
  let owners: [Int32: RuntimeReleaseTopologyOwnerProbe]
  let volumes: [Int32: RuntimeReleaseTopologyVolumeProbe]

  func probeOwner(fileDescriptor: Int32) -> RuntimeReleaseTopologyOwnerProbe {
    owners[fileDescriptor]!
  }

  func probeVolume(rootFileDescriptor: Int32) -> RuntimeReleaseTopologyVolumeProbe {
    volumes[rootFileDescriptor]!
  }
}

@Test func hardlinksCountOnceInCloneClosureAndExactPublicBytesReceiveCredit() throws {
  let fileA = RuntimeReleaseFileObjectIdentity(device: 7, fileID: 100)
  let fileB = RuntimeReleaseFileObjectIdentity(device: 7, fileID: 200)
  let clone = RuntimeReleaseCloneIdentity(device: 7, cloneID: 900)
  let source = StaticReleaseTopologyProbe(
    owners: [
      10: releaseOwnerProbe(identity: fileA, linkCount: 2, clone: clone, cloneRefCount: 2),
      11: releaseOwnerProbe(identity: fileA, linkCount: 2, clone: clone, cloneRefCount: 2),
      12: releaseOwnerProbe(identity: fileB, linkCount: 1, clone: clone, cloneRefCount: 2),
    ],
    volumes: [70: releaseVolumeProbe(device: 7, snapshotBlocker: false)]
  )

  let report = RuntimeReleaseTopologyAuthority().collect(
    owners: [
      try releaseOwner("cache-a", ["first"], fileA, 10),
      try releaseOwner("cache-a", ["second"], fileA, 11),
      try releaseOwner("cache-b", ["third"], fileB, 12),
    ],
    volumes: [BoundRuntimeReleaseVolumeDescriptor(expectedDevice: 7, rootFileDescriptor: 70)],
    scopeCoverage: .known(true),
    probe: source
  )

  #expect(report.collection == .known(true))
  #expect(report.seal.fileObjects.count == 2)
  let group = try #require(report.seal.cloneGroups.first)
  #expect(group.ownerFileObjects == [fileA, fileB])
  #expect(group.owners.count == 3)
  #expect(group.ownerClosure == .known(true))
  #expect(group.conditionalSharedReclaimCredit == 4_096)
  #expect(report.conditionalSharedReclaimCredit == 4_096)
  let component = try #require(report.seal.components.first)
  #expect(component.ownerCandidateIDsAtMostOnce == ["cache-a", "cache-b"])
  #expect(component.isExecutable)
}

@Test func hardlinkCountMismatchIsKnownFalseEvenWhenScopeCoverageIsUnknown() throws {
  let file = RuntimeReleaseFileObjectIdentity(device: 7, fileID: 100)
  let report = RuntimeReleaseTopologyAuthority().collect(
    owners: [try releaseOwner("cache", ["only-observed-link"], file, 10)],
    volumes: [],
    scopeCoverage: .unknown(.incompleteCoverage),
    probe: StaticReleaseTopologyProbe(
      owners: [10: releaseOwnerProbe(identity: file, linkCount: 2)], volumes: [:])
  )

  #expect(report.seal.fileObjects.first?.ownerClosure == .known(false))
  #expect(
    report.issues.contains(
      .hardlinkOwnerCountMismatch(file, observed: 1, linkCount: 2)))
}

@Test func providerAndPermissionCoverageRemainTyped() throws {
  let providerFile = RuntimeReleaseFileObjectIdentity(device: 7, fileID: 100)
  let unreadableFile = RuntimeReleaseFileObjectIdentity(device: 7, fileID: 200)
  let permissionFailure = RuntimeReleaseTopologyFailure(
    kind: .probeFailed, collector: "descriptor-stat", errorCode: EACCES)
  let source = StaticReleaseTopologyProbe(
    owners: [
      10: releaseOwnerProbe(
        identity: providerFile,
        linkCount: 1,
        coverage: .unknown(.providerBoundary)
      ),
      11: RuntimeReleaseTopologyOwnerProbe(
        identity: .unreadable(permissionFailure),
        coverage: .unreadable(permissionFailure),
        linkCount: .unreadable(permissionFailure),
        cloneAssociation: .unreadable(permissionFailure),
        cloneRefCount: .unreadable(permissionFailure),
        sharesAllBlocks: .unreadable(permissionFailure),
        exactSharedBytes: .unreadable(permissionFailure)
      ),
    ],
    volumes: [:]
  )

  let report = RuntimeReleaseTopologyAuthority().collect(
    owners: [
      try releaseOwner("provider", ["file"], providerFile, 10),
      try releaseOwner("unreadable", ["file"], unreadableFile, 11),
    ],
    volumes: [],
    scopeCoverage: .known(true),
    probe: source
  )

  #expect(report.seal.fileObjects[0].ownerClosure == .unknown(.providerBoundary))
  #expect(report.seal.fileObjects[1].ownerClosure == .unreadable(permissionFailure))
  #expect(report.collection == .unreadable(permissionFailure))
}

@Test func invalidDescriptorProducesTypedFailureWithoutCallingProbe() throws {
  let file = RuntimeReleaseFileObjectIdentity(device: 7, fileID: 100)
  let report = RuntimeReleaseTopologyAuthority().collect(
    owners: [try releaseOwner("cache", ["file"], file, -1)],
    volumes: [],
    scopeCoverage: .known(true),
    probe: StaticReleaseTopologyProbe(owners: [:], volumes: [:])
  )

  guard case .failed(let failure) = report.seal.fileObjects[0].ownerClosure else {
    Issue.record("invalid descriptor did not remain a typed failure")
    return
  }
  #expect(failure.kind == .invalidDescriptor)
}

@Test func unknownCloneAssociationCannotPassCollectionOrRevalidation() throws {
  let file = RuntimeReleaseFileObjectIdentity(device: 7, fileID: 100)
  let probe = RuntimeReleaseTopologyOwnerProbe(
    identity: .known(file),
    coverage: .known(true),
    linkCount: .known(1),
    cloneAssociation: .unknown(.unavailableViaPublicAPI),
    cloneRefCount: .unknown(.unavailableViaPublicAPI),
    sharesAllBlocks: .unknown(.unavailableViaPublicAPI),
    exactSharedBytes: .unknown(.unavailableViaPublicAPI)
  )
  let authority = RuntimeReleaseTopologyAuthority()
  let report = authority.collect(
    owners: [try releaseOwner("cache", ["file"], file, 10)],
    volumes: [],
    scopeCoverage: .known(true),
    probe: StaticReleaseTopologyProbe(owners: [10: probe], volumes: [:])
  )

  #expect(
    report.seal.fileObjects.first?.topologyCompleteness
      == .unknown(.unavailableViaPublicAPI))
  #expect(report.collection == .unknown(.unavailableViaPublicAPI))
  #expect(authority.validate(report, against: report.seal).topologyMatches == report.collection)
}

@Test func notClonedAssociationRejectsContradictoryCloneFields() throws {
  let file = RuntimeReleaseFileObjectIdentity(device: 7, fileID: 100)
  let probe = RuntimeReleaseTopologyOwnerProbe(
    identity: .known(file),
    coverage: .known(true),
    linkCount: .known(1),
    cloneAssociation: .known(.notCloned),
    cloneRefCount: .known(2),
    sharesAllBlocks: .known(true),
    exactSharedBytes: .known(
      RuntimeReleaseExactSharedBytes(bytes: 4_096, source: .exactPublicFilesystemAPI))
  )
  let report = RuntimeReleaseTopologyAuthority().collect(
    owners: [try releaseOwner("cache", ["file"], file, 10)],
    volumes: [],
    scopeCoverage: .known(true),
    probe: StaticReleaseTopologyProbe(owners: [10: probe], volumes: [:])
  )

  #expect(report.seal.fileObjects.first?.topologyCompleteness == .known(false))
  #expect(report.collection == .known(false))
  #expect(report.issues.contains(.inconsistentFileEvidence(file)))
}

@Test func externalCloneOwnerAndPartialCloneFailClosed() throws {
  let fileA = RuntimeReleaseFileObjectIdentity(device: 7, fileID: 100)
  let fileB = RuntimeReleaseFileObjectIdentity(device: 7, fileID: 200)
  let clone = RuntimeReleaseCloneIdentity(device: 7, cloneID: 900)
  let source = StaticReleaseTopologyProbe(
    owners: [
      10: releaseOwnerProbe(
        identity: fileA, linkCount: 1, clone: clone, cloneRefCount: 3,
        sharesAllBlocks: false),
      11: releaseOwnerProbe(
        identity: fileB, linkCount: 1, clone: clone, cloneRefCount: 3,
        sharesAllBlocks: false),
    ],
    volumes: [70: releaseVolumeProbe(device: 7, snapshotBlocker: false)]
  )

  let report = RuntimeReleaseTopologyAuthority().collect(
    owners: [
      try releaseOwner("cache-a", ["file"], fileA, 10),
      try releaseOwner("cache-b", ["file"], fileB, 11),
    ],
    volumes: [BoundRuntimeReleaseVolumeDescriptor(expectedDevice: 7, rootFileDescriptor: 70)],
    scopeCoverage: .known(true),
    probe: source
  )

  let group = try #require(report.seal.cloneGroups.first)
  #expect(group.ownerClosure == .known(false))
  #expect(group.sharesAllBlocks == .known(false))
  #expect(group.conditionalSharedReclaimCredit == nil)
  #expect(
    report.issues.contains(.cloneOwnerCountMismatch(clone, observed: 2, refCount: 3)))
  #expect(report.issues.contains(.partialClone(clone)))
}

@Test func duplicateOwnerBindingCannotRetainOtherwiseExactSharedCredit() throws {
  let file = RuntimeReleaseFileObjectIdentity(device: 7, fileID: 100)
  let clone = RuntimeReleaseCloneIdentity(device: 7, cloneID: 900)
  let duplicate = try releaseOwner("cache", ["file"], file, 10)
  let report = RuntimeReleaseTopologyAuthority().collect(
    owners: [duplicate, duplicate],
    volumes: [BoundRuntimeReleaseVolumeDescriptor(expectedDevice: 7, rootFileDescriptor: 70)],
    scopeCoverage: .known(true),
    probe: StaticReleaseTopologyProbe(
      owners: [
        10: releaseOwnerProbe(
          identity: file, linkCount: 1, clone: clone, cloneRefCount: 1)
      ],
      volumes: [70: releaseVolumeProbe(device: 7, snapshotBlocker: false)]
    )
  )

  #expect(report.issues.contains(.duplicateOwnerBinding(duplicate.owner)))
  #expect(report.seal.cloneGroups.first?.conditionalSharedReclaimCredit == nil)
}

@Test func unavailablePublicSharedByteEvidenceNeverReceivesCredit() throws {
  let file = RuntimeReleaseFileObjectIdentity(device: 7, fileID: 100)
  let clone = RuntimeReleaseCloneIdentity(device: 7, cloneID: 900)
  let source = StaticReleaseTopologyProbe(
    owners: [
      10: releaseOwnerProbe(
        identity: file,
        linkCount: 1,
        clone: clone,
        cloneRefCount: 1,
        exactSharedBytes: .unknown(.unavailableViaPublicAPI)
      )
    ],
    volumes: [70: releaseVolumeProbe(device: 7, snapshotBlocker: false)]
  )

  let report = RuntimeReleaseTopologyAuthority().collect(
    owners: [try releaseOwner("cache", ["file"], file, 10)],
    volumes: [BoundRuntimeReleaseVolumeDescriptor(expectedDevice: 7, rootFileDescriptor: 70)],
    scopeCoverage: .known(true),
    probe: source
  )

  let group = try #require(report.seal.cloneGroups.first)
  #expect(group.exactSharedBytes == .unknown(.unavailableViaPublicAPI))
  #expect(group.conditionalSharedReclaimCredit == nil)
  #expect(report.issues.contains(.sharedBytesUnavailable(clone)))
}

@Test func snapshotBlockerIsTypedVolumeEvidenceAndPreventsCredit() throws {
  let file = RuntimeReleaseFileObjectIdentity(device: 7, fileID: 100)
  let clone = RuntimeReleaseCloneIdentity(device: 7, cloneID: 900)
  let report = RuntimeReleaseTopologyAuthority().collect(
    owners: [try releaseOwner("cache", ["file"], file, 10)],
    volumes: [BoundRuntimeReleaseVolumeDescriptor(expectedDevice: 7, rootFileDescriptor: 70)],
    scopeCoverage: .known(true),
    probe: StaticReleaseTopologyProbe(
      owners: [
        10: releaseOwnerProbe(
          identity: file, linkCount: 1, clone: clone, cloneRefCount: 1)
      ],
      volumes: [70: releaseVolumeProbe(device: 7, snapshotBlocker: true)]
    )
  )

  let group = try #require(report.seal.cloneGroups.first)
  #expect(group.snapshotBlocker == .known(true))
  #expect(group.conditionalSharedReclaimCredit == nil)
  #expect(report.issues.contains(.snapshotBlocked(clone)))
}

@Test func cloneIdentityIncludesDeviceAndDoesNotCollideAcrossVolumes() throws {
  let firstFile = RuntimeReleaseFileObjectIdentity(device: 7, fileID: 100)
  let secondFile = RuntimeReleaseFileObjectIdentity(device: 8, fileID: 100)
  let firstClone = RuntimeReleaseCloneIdentity(device: 7, cloneID: 900)
  let secondClone = RuntimeReleaseCloneIdentity(device: 8, cloneID: 900)
  let report = RuntimeReleaseTopologyAuthority().collect(
    owners: [
      try releaseOwner("first", ["file"], firstFile, 10),
      try releaseOwner("second", ["file"], secondFile, 11),
    ],
    volumes: [
      BoundRuntimeReleaseVolumeDescriptor(expectedDevice: 7, rootFileDescriptor: 70),
      BoundRuntimeReleaseVolumeDescriptor(expectedDevice: 8, rootFileDescriptor: 80),
    ],
    scopeCoverage: .known(true),
    probe: StaticReleaseTopologyProbe(
      owners: [
        10: releaseOwnerProbe(
          identity: firstFile, linkCount: 1, clone: firstClone, cloneRefCount: 1),
        11: releaseOwnerProbe(
          identity: secondFile, linkCount: 1, clone: secondClone, cloneRefCount: 1),
      ],
      volumes: [
        70: releaseVolumeProbe(device: 7, snapshotBlocker: false),
        80: releaseVolumeProbe(device: 8, snapshotBlocker: false),
      ]
    )
  )

  #expect(report.seal.cloneGroups.map(\.identity) == [firstClone, secondClone])
}

@Test func groupsSharingCandidateFormOneAtMostOnceExecutionComponent() throws {
  let firstFile = RuntimeReleaseFileObjectIdentity(device: 7, fileID: 100)
  let secondFile = RuntimeReleaseFileObjectIdentity(device: 7, fileID: 200)
  let firstClone = RuntimeReleaseCloneIdentity(device: 7, cloneID: 900)
  let secondClone = RuntimeReleaseCloneIdentity(device: 7, cloneID: 901)
  let report = RuntimeReleaseTopologyAuthority().collect(
    owners: [
      try releaseOwner("bundle", ["first"], firstFile, 10),
      try releaseOwner("bundle", ["second"], secondFile, 11),
    ],
    volumes: [BoundRuntimeReleaseVolumeDescriptor(expectedDevice: 7, rootFileDescriptor: 70)],
    scopeCoverage: .known(true),
    probe: StaticReleaseTopologyProbe(
      owners: [
        10: releaseOwnerProbe(
          identity: firstFile, linkCount: 1, clone: firstClone, cloneRefCount: 1),
        11: releaseOwnerProbe(
          identity: secondFile, linkCount: 1, clone: secondClone, cloneRefCount: 1),
      ],
      volumes: [70: releaseVolumeProbe(device: 7, snapshotBlocker: false)]
    )
  )

  let component = try #require(report.seal.components.first)
  #expect(report.seal.components.count == 1)
  #expect(component.cloneGroups == [firstClone, secondClone])
  #expect(component.ownerCandidateIDsAtMostOnce == ["bundle"])
  #expect(component.observedOwnerLinks.count == 2)
}

@Test func revalidationRejectsAnyTopologySealChange() throws {
  let file = RuntimeReleaseFileObjectIdentity(device: 7, fileID: 100)
  let clone = RuntimeReleaseCloneIdentity(device: 7, cloneID: 900)
  let owner = try releaseOwner("cache", ["file"], file, 10)
  let baseOwners = [
    10: releaseOwnerProbe(identity: file, linkCount: 1, clone: clone, cloneRefCount: 1)
  ]
  let authority = RuntimeReleaseTopologyAuthority()
  let expected = authority.collect(
    owners: [owner],
    volumes: [BoundRuntimeReleaseVolumeDescriptor(expectedDevice: 7, rootFileDescriptor: 70)],
    scopeCoverage: .known(true),
    probe: StaticReleaseTopologyProbe(
      owners: baseOwners,
      volumes: [70: releaseVolumeProbe(device: 7, snapshotBlocker: false)]
    )
  )
  let changed = authority.collect(
    owners: [owner],
    volumes: [BoundRuntimeReleaseVolumeDescriptor(expectedDevice: 7, rootFileDescriptor: 70)],
    scopeCoverage: .known(true),
    probe: StaticReleaseTopologyProbe(
      owners: baseOwners,
      volumes: [70: releaseVolumeProbe(device: 7, snapshotBlocker: true)]
    )
  )

  #expect(authority.validate(changed, against: expected.seal).topologyMatches == .known(false))
}

private func releaseOwner(
  _ candidateID: String,
  _ components: [String],
  _ identity: RuntimeReleaseFileObjectIdentity,
  _ fileDescriptor: Int32
) throws -> BoundRuntimeReleaseOwnerDescriptor {
  BoundRuntimeReleaseOwnerDescriptor(
    owner: FileOwnerLink(
      candidateID: candidateID,
      path: try RawTargetPath(components: components.map { Data($0.utf8) })
    ),
    expectedIdentity: identity,
    fileDescriptor: fileDescriptor
  )
}

private func releaseOwnerProbe(
  identity: RuntimeReleaseFileObjectIdentity,
  linkCount: UInt32,
  coverage: RuntimeReleaseTopologyObservation<Bool> = .known(true),
  clone: RuntimeReleaseCloneIdentity? = nil,
  cloneRefCount: UInt32? = nil,
  sharesAllBlocks: Bool = true,
  exactSharedBytes: RuntimeReleaseTopologyObservation<RuntimeReleaseExactSharedBytes> = .known(
    RuntimeReleaseExactSharedBytes(bytes: 4_096, source: .exactPublicFilesystemAPI)
  )
) -> RuntimeReleaseTopologyOwnerProbe {
  RuntimeReleaseTopologyOwnerProbe(
    identity: .known(identity),
    coverage: coverage,
    linkCount: .known(linkCount),
    cloneAssociation: .known(clone.map(RuntimeReleaseCloneAssociation.clone) ?? .notCloned),
    cloneRefCount: cloneRefCount.map(RuntimeReleaseTopologyObservation.known) ?? .absent,
    sharesAllBlocks: clone == nil ? .absent : .known(sharesAllBlocks),
    exactSharedBytes: clone == nil ? .absent : exactSharedBytes
  )
}

private func releaseVolumeProbe(
  device: UInt64,
  snapshotBlocker: Bool
) -> RuntimeReleaseTopologyVolumeProbe {
  RuntimeReleaseTopologyVolumeProbe(
    device: .known(device),
    snapshotBlocker: .known(snapshotBlocker)
  )
}
