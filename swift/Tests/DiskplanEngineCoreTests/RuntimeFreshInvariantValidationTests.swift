import DiskplanPolicy
import Foundation
import Testing

@testable import DiskplanEngineCore

@Test func freshInvariantsAcceptContinuousSurvivorAndDisjointTerminals() throws {
  let survivorNamespace = try invariantNamespace(
    root: "/fixture",
    target: ["survivor"],
    targetIdentity: invariantIdentity(10, type: .regularFile)
  )
  let evidence = invariantEvidence(candidateID: "survivor", namespace: survivorNamespace)
  let result = RuntimeFreshInvariantValidator.validate(
    immutableDuplicateGroups: [invariantDuplicateExpectation(evidence)],
    duplicateSurvivors: [
      RuntimeFreshDuplicateSurvivor(
        groupID: "duplicates",
        candidateID: "survivor",
        currentMemberCandidateIDs: ["survivor", "duplicate"],
        current: evidence
      )
    ],
    terminalMutations: [
      RuntimeFreshTerminalMutation(
        actionID: invariantActionID(1),
        namespace: .known(
          try invariantNamespace(
            root: "/fixture",
            target: ["trash"],
            targetIdentity: invariantIdentity(11, type: .directory)
          )
        )
      )
    ]
  )

  #expect(result.isSatisfied)
  #expect(result.duplicateSurvivorsPreserved.verdict == .satisfied)
  #expect(result.terminalNamespacesExclusive.verdict == .satisfied)
}

@Test func survivorContinuityRejectsIdentityContentAndAccessChangesIndependently() throws {
  let namespace = try invariantNamespace(
    root: "/fixture",
    target: ["survivor"],
    targetIdentity: invariantIdentity(10, type: .regularFile)
  )
  let immutable = invariantEvidence(candidateID: "survivor", namespace: namespace)
  let current = RuntimeFreshInvariantEvidence(
    candidateID: "survivor",
    namespace: .known(
      try invariantNamespace(
        root: "/fixture",
        target: ["survivor"],
        targetIdentity: invariantIdentity(99, type: .regularFile)
      )
    ),
    identity: .known(invariantIdentity(99, type: .regularFile)),
    content: .known(.requiredDigest(invariantDigest(43))),
    accessPolicy: .known("uid=501;gid=20;mode=0600"),
    aclDigest: .known(invariantDigest(3)),
    providerState: .known(.local),
    mountIdentity: .known("mount-a")
  )

  let result = RuntimeFreshInvariantValidator.validate(
    immutableDuplicateGroups: [invariantDuplicateExpectation(immutable)],
    duplicateSurvivors: [
      RuntimeFreshDuplicateSurvivor(
        groupID: "duplicates",
        candidateID: "survivor",
        currentMemberCandidateIDs: ["survivor", "duplicate"],
        current: current
      )
    ],
    terminalMutations: []
  )

  #expect(!result.duplicateSurvivorsPreserved.isSatisfied)
  #expect(
    result.duplicateSurvivorsPreserved.findings.contains {
      $0.component == .survivorIdentity
        && $0.rejection == .mismatch(.objectIdentityChanged)
    }
  )
  #expect(
    result.duplicateSurvivorsPreserved.findings.contains {
      $0.component == .survivorContent && $0.rejection == .mismatch(.contentChanged)
    }
  )
  #expect(
    result.duplicateSurvivorsPreserved.findings.contains {
      $0.component == .survivorAccessPolicy
        && $0.rejection == .mismatch(.accessPolicyChanged)
    }
  )
}

@Test func survivorUnavailableEvidenceRetainsTypedRejections() throws {
  let namespace = try invariantNamespace(
    root: "/fixture",
    target: ["survivor"],
    targetIdentity: invariantIdentity(10, type: .regularFile)
  )
  let immutable = invariantEvidence(candidateID: "survivor", namespace: namespace)
  let failure = ObservationFailure(code: "EACCES", collector: "fresh-invariant")

  let cases: [(Observation<String>, RuntimeFreshInvariantRejection)] = [
    (.absent, .missing),
    (.unknown(.incompleteCoverage), .unknown(.incompleteCoverage)),
    (.unreadable(failure), .unreadable(failure)),
    (.failed(failure), .failed(failure)),
  ]
  for (access, rejection) in cases {
    let current = RuntimeFreshInvariantEvidence(
      candidateID: "survivor",
      namespace: .known(namespace),
      identity: immutable.identity,
      content: immutable.content,
      accessPolicy: access,
      aclDigest: immutable.aclDigest,
      providerState: immutable.providerState,
      mountIdentity: immutable.mountIdentity
    )
    let result = RuntimeFreshInvariantValidator.validate(
      immutableDuplicateGroups: [invariantDuplicateExpectation(immutable)],
      duplicateSurvivors: [
        RuntimeFreshDuplicateSurvivor(
          groupID: "duplicates",
          candidateID: "survivor",
          currentMemberCandidateIDs: ["survivor", "duplicate"],
          current: current
        )
      ],
      terminalMutations: []
    )
    #expect(
      result.duplicateSurvivorsPreserved.findings.contains {
        $0.component == .survivorAccessPolicy && $0.rejection == rejection
      }
    )
    #expect(!result.duplicateSurvivorsPreserved.isSatisfied)
  }
}

@Test func survivorRejectsDirectAncestorDescendantAndPathAliasMutations() throws {
  let survivorNamespace = try invariantNamespace(
    root: "/fixture",
    target: ["kept", "survivor"],
    targetIdentity: invariantIdentity(10, type: .directory),
    rootIdentity: invariantIdentity(1, type: .directory),
    parentIdentities: [invariantIdentity(2, type: .directory)]
  )
  let evidence = invariantEvidence(candidateID: "survivor", namespace: survivorNamespace)
  let mutations = [
    try invariantNamespace(
      root: "/fixture",
      target: ["kept", "survivor"],
      targetIdentity: invariantIdentity(10, type: .directory),
      rootIdentity: invariantIdentity(1, type: .directory),
      parentIdentities: [invariantIdentity(2, type: .directory)]
    ),
    try invariantNamespace(
      root: "/fixture",
      target: ["kept"],
      targetIdentity: invariantIdentity(2, type: .directory),
      rootIdentity: invariantIdentity(1, type: .directory)
    ),
    try invariantNamespace(
      root: "/fixture",
      target: ["kept", "survivor", "child"],
      targetIdentity: invariantIdentity(12, type: .regularFile),
      rootIdentity: invariantIdentity(1, type: .directory),
      parentIdentities: [
        invariantIdentity(2, type: .directory),
        invariantIdentity(10, type: .directory),
      ]
    ),
    try invariantNamespace(
      root: "/alias",
      target: ["kept", "survivor"],
      targetIdentity: invariantIdentity(10, type: .directory),
      rootIdentity: invariantIdentity(1, type: .directory),
      parentIdentities: [invariantIdentity(2, type: .directory)]
    ),
  ]

  for (index, mutation) in mutations.enumerated() {
    let result = RuntimeFreshInvariantValidator.validate(
      immutableDuplicateGroups: [invariantDuplicateExpectation(evidence)],
      duplicateSurvivors: [
        RuntimeFreshDuplicateSurvivor(
          groupID: "duplicates",
          candidateID: "survivor",
          currentMemberCandidateIDs: ["survivor", "duplicate"],
          current: evidence
        )
      ],
      terminalMutations: [
        RuntimeFreshTerminalMutation(
          actionID: invariantActionID(UInt8(index + 1)),
          namespace: .known(mutation)
        )
      ]
    )
    #expect(
      result.duplicateSurvivorsPreserved.findings.contains {
        $0.rejection == .mismatch(.survivorNamespaceMutated)
      }
    )
  }
}

@Test func terminalExclusivityDetectsDirectoryAndRegularFileIdentityAliases() throws {
  let directoryAliasA = try invariantNamespace(
    root: "/one",
    target: ["directory-a"],
    targetIdentity: invariantIdentity(50, type: .directory),
    rootIdentity: invariantIdentity(1, type: .directory)
  )
  let directoryAliasB = try invariantNamespace(
    root: "/two",
    target: ["directory-b"],
    targetIdentity: invariantIdentity(50, type: .directory),
    rootIdentity: invariantIdentity(2, type: .directory)
  )
  let regularAliasA = try invariantNamespace(
    root: "/one",
    target: ["file-a"],
    targetIdentity: invariantIdentity(60, type: .regularFile),
    rootIdentity: invariantIdentity(1, type: .directory)
  )
  let regularAliasB = try invariantNamespace(
    root: "/two",
    target: ["file-b"],
    targetIdentity: invariantIdentity(60, type: .regularFile),
    rootIdentity: invariantIdentity(2, type: .directory)
  )

  for pair in [(directoryAliasA, directoryAliasB), (regularAliasA, regularAliasB)] {
    let result = RuntimeFreshInvariantValidator.validate(
      immutableDuplicateGroups: [],
      duplicateSurvivors: [],
      terminalMutations: [
        RuntimeFreshTerminalMutation(
          actionID: invariantActionID(1), namespace: .known(pair.0)),
        RuntimeFreshTerminalMutation(
          actionID: invariantActionID(2), namespace: .known(pair.1)),
      ]
    )
    #expect(!result.terminalNamespacesExclusive.isSatisfied)
    #expect(
      result.terminalNamespacesExclusive.findings.contains {
        $0.rejection == .mismatch(.overlappingTerminalMutation)
      }
    )
  }
}

@Test func terminalExclusivityAllowsOnlyExactOwnerToReleaseCompositeReplacement() throws {
  let namespace = try invariantNamespace(
    root: "/fixture",
    target: ["release-owner"],
    targetIdentity: invariantIdentity(70, type: .regularFile)
  )
  let ownerID = invariantActionID(1)
  let releaseID = invariantActionID(2)

  let allowed = RuntimeFreshInvariantValidator.validate(
    immutableDuplicateGroups: [],
    duplicateSurvivors: [],
    terminalMutations: [
      RuntimeFreshTerminalMutation(actionID: ownerID, namespace: .known(namespace)),
      RuntimeFreshTerminalMutation(
        actionID: releaseID,
        namespace: .known(namespace),
        kind: .releaseComposite(
          ownerBindings: [
            RuntimeFreshReleaseOwnerMutationBinding(
              actionID: ownerID,
              namespace: namespace
            )
          ]
        )
      ),
    ]
  )
  #expect(allowed.terminalNamespacesExclusive.verdict == .satisfied)

  let unrelated = RuntimeFreshInvariantValidator.validate(
    immutableDuplicateGroups: [],
    duplicateSurvivors: [],
    terminalMutations: [
      RuntimeFreshTerminalMutation(actionID: ownerID, namespace: .known(namespace)),
      RuntimeFreshTerminalMutation(
        actionID: releaseID,
        namespace: .known(namespace),
        kind: .releaseComposite(
          ownerBindings: [
            RuntimeFreshReleaseOwnerMutationBinding(
              actionID: invariantActionID(9),
              namespace: namespace
            )
          ]
        )
      ),
    ]
  )
  #expect(!unrelated.terminalNamespacesExclusive.isSatisfied)
}

@Test func releaseReplacementRejectsNonExactOwnerNamespaceAndIdentityAliases() throws {
  let exactOwner = try invariantNamespace(
    root: "/fixture",
    target: ["parent", "release-owner"],
    targetIdentity: invariantIdentity(70, type: .regularFile),
    parentIdentities: [invariantIdentity(71, type: .directory)]
  )
  let nonExactOwners = [
    try invariantNamespace(
      root: "/fixture",
      target: ["parent"],
      targetIdentity: invariantIdentity(71, type: .directory)
    ),
    try invariantNamespace(
      root: "/alias",
      target: ["identity-alias"],
      targetIdentity: invariantIdentity(70, type: .regularFile),
      rootIdentity: invariantIdentity(80, type: .directory)
    ),
  ]
  let ownerID = invariantActionID(1)

  for currentOwner in nonExactOwners {
    let result = RuntimeFreshInvariantValidator.validate(
      immutableDuplicateGroups: [],
      duplicateSurvivors: [],
      terminalMutations: [
        RuntimeFreshTerminalMutation(actionID: ownerID, namespace: .known(currentOwner)),
        RuntimeFreshTerminalMutation(
          actionID: invariantActionID(2),
          namespace: .known(exactOwner),
          kind: .releaseComposite(
            ownerBindings: [
              RuntimeFreshReleaseOwnerMutationBinding(
                actionID: ownerID,
                namespace: exactOwner
              )
            ]
          )
        ),
      ]
    )

    #expect(
      result.terminalNamespacesExclusive.findings.contains {
        $0.rejection == .mismatch(.overlappingTerminalMutation)
      }
    )
  }
}

@Test func immutableDuplicateGroupsRejectMissingUnrelatedAndChangedFreshDeclarations() throws {
  let namespace = try invariantNamespace(
    root: "/fixture",
    target: ["survivor"],
    targetIdentity: invariantIdentity(10, type: .regularFile)
  )
  let evidence = invariantEvidence(candidateID: "survivor", namespace: namespace)
  let expected = invariantDuplicateExpectation(evidence)

  let missing = RuntimeFreshInvariantValidator.validate(
    immutableDuplicateGroups: [expected],
    duplicateSurvivors: [],
    terminalMutations: []
  )
  #expect(
    missing.duplicateSurvivorsPreserved.findings.contains {
      $0.component == .duplicateGroup && $0.rejection == .missing
    }
  )

  let unrelatedEvidence = invariantEvidence(candidateID: "other", namespace: namespace)
  let unrelated = RuntimeFreshInvariantValidator.validate(
    immutableDuplicateGroups: [expected],
    duplicateSurvivors: [
      RuntimeFreshDuplicateSurvivor(
        groupID: "unrelated",
        candidateID: "other",
        currentMemberCandidateIDs: ["other", "other-copy"],
        current: unrelatedEvidence
      )
    ],
    terminalMutations: []
  )
  #expect(
    unrelated.duplicateSurvivorsPreserved.findings.contains {
      $0.rejection == .mismatch(.duplicateGroupSetChanged)
    }
  )

  let changedMembers = RuntimeFreshInvariantValidator.validate(
    immutableDuplicateGroups: [expected],
    duplicateSurvivors: [
      RuntimeFreshDuplicateSurvivor(
        groupID: "duplicates",
        candidateID: "survivor",
        currentMemberCandidateIDs: ["duplicate"],
        current: evidence
      )
    ],
    terminalMutations: []
  )
  #expect(
    changedMembers.duplicateSurvivorsPreserved.findings.contains {
      $0.rejection == .mismatch(.duplicateMemberSetChanged)
    }
  )
  #expect(
    changedMembers.duplicateSurvivorsPreserved.findings.contains {
      $0.rejection == .mismatch(.designatedSurvivorNotMember)
    }
  )
}

@Test func authoritativeVerdictRetainsMixedTypedFailures() throws {
  let namespace = try invariantNamespace(
    root: "/fixture",
    target: ["survivor"],
    targetIdentity: invariantIdentity(10, type: .regularFile)
  )
  let immutable = invariantEvidence(candidateID: "survivor", namespace: namespace)
  let failure = ObservationFailure(code: "collector-failed", collector: "fresh-invariant")
  let current = RuntimeFreshInvariantEvidence(
    candidateID: "survivor",
    namespace: .known(
      try invariantNamespace(
        root: "/fixture",
        target: ["survivor"],
        targetIdentity: invariantIdentity(99, type: .regularFile)
      )
    ),
    identity: .known(invariantIdentity(99, type: .regularFile)),
    content: immutable.content,
    accessPolicy: .failed(failure),
    aclDigest: immutable.aclDigest,
    providerState: immutable.providerState,
    mountIdentity: immutable.mountIdentity
  )
  let result = RuntimeFreshInvariantValidator.validate(
    immutableDuplicateGroups: [invariantDuplicateExpectation(immutable)],
    duplicateSurvivors: [
      RuntimeFreshDuplicateSurvivor(
        groupID: "duplicates",
        candidateID: "survivor",
        currentMemberCandidateIDs: ["survivor", "duplicate"],
        current: current
      )
    ],
    terminalMutations: []
  )

  guard case .rejected(let findings) = result.duplicateSurvivorsPreserved.verdict else {
    Issue.record("expected authoritative typed rejection")
    return
  }
  #expect(findings.contains { $0.rejection == .mismatch(.objectIdentityChanged) })
  #expect(findings.contains { $0.rejection == .failed(failure) })
}

@Test func terminalUnavailableNamespaceAndConflictingSurvivorsFailClosed() throws {
  let namespace = try invariantNamespace(
    root: "/fixture",
    target: ["survivor"],
    targetIdentity: invariantIdentity(10, type: .regularFile)
  )
  let first = invariantEvidence(candidateID: "first", namespace: namespace)
  let second = invariantEvidence(candidateID: "second", namespace: namespace)
  let result = RuntimeFreshInvariantValidator.validate(
    immutableDuplicateGroups: [
      RuntimeFreshDuplicateGroupExpectation(
        groupID: "duplicates",
        memberCandidateIDs: ["first", "second"],
        survivorCandidateID: "first",
        immutableSurvivor: first
      )
    ],
    duplicateSurvivors: [
      RuntimeFreshDuplicateSurvivor(
        groupID: "duplicates",
        candidateID: "first",
        currentMemberCandidateIDs: ["first", "second"],
        current: first
      ),
      RuntimeFreshDuplicateSurvivor(
        groupID: "duplicates",
        candidateID: "second",
        currentMemberCandidateIDs: ["first", "second"],
        current: second
      ),
    ],
    terminalMutations: [
      RuntimeFreshTerminalMutation(
        actionID: invariantActionID(1), namespace: .unknown(.incompleteCoverage))
    ]
  )

  #expect(!result.duplicateSurvivorsPreserved.isSatisfied)
  #expect(
    result.duplicateSurvivorsPreserved.findings.contains {
      $0.rejection == .mismatch(.conflictingDesignatedSurvivor)
    }
  )
  #expect(
    result.terminalNamespacesExclusive.findings.contains {
      $0.rejection == .unknown(.incompleteCoverage)
    }
  )
}

@Test func duplicateSurvivorRegistrationCannotMasqueradeAsOneSurvivor() throws {
  let namespace = try invariantNamespace(
    root: "/fixture",
    target: ["survivor"],
    targetIdentity: invariantIdentity(10, type: .regularFile)
  )
  let evidence = invariantEvidence(candidateID: "survivor", namespace: namespace)
  let duplicate = RuntimeFreshDuplicateSurvivor(
    groupID: "duplicates",
    candidateID: "survivor",
    currentMemberCandidateIDs: ["survivor", "duplicate"],
    current: evidence
  )

  let result = RuntimeFreshInvariantValidator.validate(
    immutableDuplicateGroups: [invariantDuplicateExpectation(evidence)],
    duplicateSurvivors: [duplicate, duplicate],
    terminalMutations: []
  )

  #expect(!result.duplicateSurvivorsPreserved.isSatisfied)
  #expect(
    result.duplicateSurvivorsPreserved.findings.contains {
      $0.rejection == .mismatch(.conflictingDesignatedSurvivor)
    }
  )
}

private func invariantEvidence(
  candidateID: String,
  namespace: ProtectedNamespaceBinding
) -> RuntimeFreshInvariantEvidence {
  RuntimeFreshInvariantEvidence(
    candidateID: candidateID,
    namespace: .known(namespace),
    identity: .known(namespace.targetIdentity),
    content: .known(.requiredDigest(invariantDigest(42))),
    accessPolicy: .known("uid=501;gid=20;mode=0700"),
    aclDigest: .known(invariantDigest(3)),
    providerState: .known(.local),
    mountIdentity: .known("mount-a")
  )
}

private func invariantDuplicateExpectation(
  _ immutableSurvivor: RuntimeFreshInvariantEvidence
) -> RuntimeFreshDuplicateGroupExpectation {
  RuntimeFreshDuplicateGroupExpectation(
    groupID: "duplicates",
    memberCandidateIDs: ["survivor", "duplicate"],
    survivorCandidateID: "survivor",
    immutableSurvivor: immutableSurvivor
  )
}

private func invariantNamespace(
  root: String,
  target: [String],
  targetIdentity: ObjectIdentity,
  rootIdentity: ObjectIdentity = invariantIdentity(1, type: .directory),
  parentIdentities: [ObjectIdentity]? = nil
) throws -> ProtectedNamespaceBinding {
  let path = try RawTargetPath(components: target.map { Data($0.utf8) })
  let parents = Array(target.dropLast())
  let identities =
    parentIdentities
    ?? parents.indices.map { invariantIdentity(UInt64(100 + $0), type: .directory) }
  #expect(identities.count == parents.count)
  return try ProtectedNamespaceBinding(
    rawRoot: RawRootPath(absoluteBytes: Data(root.utf8)),
    rootIdentity: rootIdentity,
    rootSeal: invariantSeal(),
    targetPath: path,
    targetIdentity: targetIdentity,
    parentChain: parents.indices.map { index in
      ParentNamespaceBinding(
        relativePath: try! RawTargetPath(
          components: target.prefix(index + 1).map { Data($0.utf8) }
        ),
        identity: identities[index],
        seal: invariantSeal()
      )
    }
  )
}

private func invariantIdentity(
  _ object: UInt64,
  type: ObjectKind
) -> ObjectIdentity {
  ObjectIdentity(device: 7, object: object, generation: .known(1), type: type)
}

private func invariantSeal() -> NamespaceSealEvidence {
  NamespaceSealEvidence(
    trustedNamespace: .ownerPrivate,
    accessPolicy: .known("uid=501;gid=20;mode=0700"),
    aclDigest: .known(invariantDigest(4)),
    providerBoundary: .known(.local),
    mountIdentity: .known("mount-a")
  )
}

private func invariantDigest(_ byte: UInt8) -> PolicyDigest {
  try! PolicyDigest(bytes: Data(repeating: byte, count: 32))
}

private func invariantActionID(_ byte: UInt8) -> ActionID {
  ActionID(digest: invariantDigest(byte))
}
