import DiskplanPolicy
import Foundation

package struct RuntimeFreshInvariantEvidence: Equatable, Sendable {
  package let candidateID: String
  package let namespace: Observation<ProtectedNamespaceBinding>
  package let identity: Observation<ObjectIdentity>
  package let content: Observation<ContentProtectionBaseline>
  package let accessPolicy: Observation<String>
  package let aclDigest: Observation<PolicyDigest>
  package let providerState: Observation<ProviderState>
  package let mountIdentity: Observation<String>

  package init(
    candidateID: String,
    namespace: Observation<ProtectedNamespaceBinding>,
    identity: Observation<ObjectIdentity>,
    content: Observation<ContentProtectionBaseline>,
    accessPolicy: Observation<String>,
    aclDigest: Observation<PolicyDigest>,
    providerState: Observation<ProviderState>,
    mountIdentity: Observation<String>
  ) {
    self.candidateID = candidateID
    self.namespace = namespace
    self.identity = identity
    self.content = content
    self.accessPolicy = accessPolicy
    self.aclDigest = aclDigest
    self.providerState = providerState
    self.mountIdentity = mountIdentity
  }

  package init(snapshot: FrozenEvidenceSnapshot) {
    self.init(
      candidateID: snapshot.candidateID,
      namespace: .known(snapshot.namespaceBinding),
      identity: snapshot.identity,
      content: snapshot.contentProtection,
      accessPolicy: snapshot.accessPolicy,
      aclDigest: snapshot.aclDigest,
      providerState: snapshot.providerState,
      mountIdentity: snapshot.targetMountIdentity
    )
  }
}

package struct RuntimeFreshDuplicateSurvivor: Equatable, Sendable {
  package let groupID: String
  package let candidateID: String
  package let immutable: RuntimeFreshInvariantEvidence
  package let current: RuntimeFreshInvariantEvidence

  package init(
    groupID: String,
    candidateID: String,
    immutable: RuntimeFreshInvariantEvidence,
    current: RuntimeFreshInvariantEvidence
  ) {
    self.groupID = groupID
    self.candidateID = candidateID
    self.immutable = immutable
    self.current = current
  }
}

package enum RuntimeFreshTerminalMutationKind: Equatable, Sendable {
  case ordinary
  case releaseComposite(ownerActionIDs: [ActionID])
}

package struct RuntimeFreshTerminalMutation: Equatable, Sendable {
  package let actionID: ActionID
  package let namespace: Observation<ProtectedNamespaceBinding>
  package let kind: RuntimeFreshTerminalMutationKind

  package init(
    actionID: ActionID,
    namespace: Observation<ProtectedNamespaceBinding>,
    kind: RuntimeFreshTerminalMutationKind = .ordinary
  ) {
    self.actionID = actionID
    self.namespace = namespace
    self.kind = kind
  }
}

package enum RuntimeFreshInvariantKind: String, Equatable, Sendable {
  case duplicateSurvivorsPreserved
  case terminalNamespacesExclusive
}

package enum RuntimeFreshInvariantComponent: String, Equatable, Sendable {
  case duplicateGroup
  case survivorRegistration
  case survivorNamespace
  case survivorIdentity
  case survivorContent
  case survivorAccessPolicy
  case survivorACLDigest
  case survivorProviderState
  case survivorMountIdentity
  case survivorRootIdentity
  case survivorRootAccessPolicy
  case survivorRootACLDigest
  case survivorRootProviderState
  case survivorRootMountIdentity
  case survivorAncestorIdentity
  case survivorAncestorAccessPolicy
  case survivorAncestorACLDigest
  case survivorAncestorProviderState
  case survivorAncestorMountIdentity
  case survivorMutationOverlap
  case terminalRegistration
  case terminalNamespace
  case terminalMutationOverlap
}

package enum RuntimeFreshInvariantMismatch: String, Equatable, Sendable {
  case conflictingDesignatedSurvivor
  case candidateBindingChanged
  case rawNamespaceChanged
  case objectIdentityChanged
  case contentChanged
  case accessPolicyChanged
  case aclChanged
  case providerStateChanged
  case mountIdentityChanged
  case namespaceTrustChanged
  case namespaceStructureChanged
  case duplicateTerminalAction
  case overlappingTerminalMutation
  case survivorNamespaceMutated
}

package enum RuntimeFreshInvariantRejection: Equatable, Sendable {
  case missing
  case unknown(UnknownReason)
  case unreadable(ObservationFailure)
  case failed(ObservationFailure)
  case mismatch(RuntimeFreshInvariantMismatch)
}

package struct RuntimeFreshInvariantFinding: Equatable, Sendable {
  package let invariant: RuntimeFreshInvariantKind
  package let component: RuntimeFreshInvariantComponent
  package let subjectID: String
  package let rejection: RuntimeFreshInvariantRejection

  package init(
    invariant: RuntimeFreshInvariantKind,
    component: RuntimeFreshInvariantComponent,
    subjectID: String,
    rejection: RuntimeFreshInvariantRejection
  ) {
    self.invariant = invariant
    self.component = component
    self.subjectID = subjectID
    self.rejection = rejection
  }
}

package struct RuntimeFreshInvariantOutcome: Equatable, Sendable {
  package let findings: [RuntimeFreshInvariantFinding]

  package var isSatisfied: Bool { findings.isEmpty }

  /// Compatibility projection for the existing execution preparation boundary. Detailed
  /// diagnostics remain in `findings`; this projection never turns an unavailable proof into
  /// a successful invariant.
  package var observation: Observation<Bool> {
    if findings.isEmpty { return .known(true) }
    if findings.contains(where: {
      if case .mismatch = $0.rejection { return true }
      return false
    }) {
      return .known(false)
    }
    if let failure = findings.compactMap({ finding -> ObservationFailure? in
      if case .failed(let failure) = finding.rejection { return failure }
      return nil
    }).first {
      return .failed(failure)
    }
    if let failure = findings.compactMap({ finding -> ObservationFailure? in
      if case .unreadable(let failure) = finding.rejection { return failure }
      return nil
    }).first {
      return .unreadable(failure)
    }
    if let reason = findings.compactMap({ finding -> UnknownReason? in
      if case .unknown(let reason) = finding.rejection { return reason }
      return nil
    }).first {
      return .unknown(reason)
    }
    return .absent
  }
}

package struct RuntimeFreshInvariantValidation: Equatable, Sendable {
  package let duplicateSurvivorsPreserved: RuntimeFreshInvariantOutcome
  package let terminalNamespacesExclusive: RuntimeFreshInvariantOutcome

  package var isSatisfied: Bool {
    duplicateSurvivorsPreserved.isSatisfied && terminalNamespacesExclusive.isSatisfied
  }
}

/// Pure semantic validation for current whole-plan invariants. Storage-owner closure is an
/// independent input to release-topology validation and deliberately does not participate here.
package enum RuntimeFreshInvariantValidator {
  package static func validate(
    duplicateSurvivors: [RuntimeFreshDuplicateSurvivor],
    terminalMutations: [RuntimeFreshTerminalMutation]
  ) -> RuntimeFreshInvariantValidation {
    let terminals = terminalMutations.sorted { $0.actionID < $1.actionID }
    let terminalResult = validateTerminalNamespaces(terminals)
    let survivorResult = validateDuplicateSurvivors(
      duplicateSurvivors.sorted(by: survivorPrecedes),
      terminals: terminals
    )
    return RuntimeFreshInvariantValidation(
      duplicateSurvivorsPreserved: RuntimeFreshInvariantOutcome(findings: survivorResult),
      terminalNamespacesExclusive: RuntimeFreshInvariantOutcome(findings: terminalResult)
    )
  }

  private static func validateDuplicateSurvivors(
    _ survivors: [RuntimeFreshDuplicateSurvivor],
    terminals: [RuntimeFreshTerminalMutation]
  ) -> [RuntimeFreshInvariantFinding] {
    var findings: [RuntimeFreshInvariantFinding] = []
    let grouped = Dictionary(grouping: survivors, by: { Data($0.groupID.utf8) })

    for groupKey in grouped.keys.sorted(by: { $0.lexicographicallyPrecedes($1) }) {
      guard let members = grouped[groupKey], let first = members.first else { continue }
      let candidateIDs = Set(members.map { Data($0.candidateID.utf8) })
      if members.count != 1 || candidateIDs.count != 1 {
        findings.append(
          finding(
            .duplicateSurvivorsPreserved,
            .duplicateGroup,
            first.groupID,
            .mismatch(.conflictingDesignatedSurvivor)
          )
        )
        continue
      }

      let survivor = first
      let subject = survivorSubject(survivor)
      if !rawStringEqual(survivor.candidateID, survivor.immutable.candidateID)
        || !rawStringEqual(survivor.candidateID, survivor.current.candidateID)
      {
        findings.append(
          finding(
            .duplicateSurvivorsPreserved,
            .survivorRegistration,
            subject,
            .mismatch(.candidateBindingChanged)
          )
        )
      }

      findings.append(
        contentsOf: validateSurvivorContinuity(
          immutable: survivor.immutable,
          current: survivor.current,
          subject: subject
        )
      )

      guard case .known(let survivorNamespace) = survivor.current.namespace else { continue }
      for terminal in terminals {
        let terminalSubject = terminal.actionID.hex
        switch terminal.namespace {
        case .known(let mutationNamespace):
          if namespacesMaySemanticallyOverlap(mutationNamespace, survivorNamespace) {
            findings.append(
              finding(
                .duplicateSurvivorsPreserved,
                .survivorMutationOverlap,
                "\(subject):\(terminalSubject)",
                .mismatch(.survivorNamespaceMutated)
              )
            )
          }
        case .absent:
          findings.append(
            finding(
              .duplicateSurvivorsPreserved,
              .survivorMutationOverlap,
              "\(subject):\(terminalSubject)",
              .missing
            )
          )
        case .unknown(let reason):
          findings.append(
            finding(
              .duplicateSurvivorsPreserved,
              .survivorMutationOverlap,
              "\(subject):\(terminalSubject)",
              .unknown(reason)
            )
          )
        case .unreadable(let failure):
          findings.append(
            finding(
              .duplicateSurvivorsPreserved,
              .survivorMutationOverlap,
              "\(subject):\(terminalSubject)",
              .unreadable(failure)
            )
          )
        case .failed(let failure):
          findings.append(
            finding(
              .duplicateSurvivorsPreserved,
              .survivorMutationOverlap,
              "\(subject):\(terminalSubject)",
              .failed(failure)
            )
          )
        }
      }
    }
    return findings
  }

  private static func validateSurvivorContinuity(
    immutable: RuntimeFreshInvariantEvidence,
    current: RuntimeFreshInvariantEvidence,
    subject: String
  ) -> [RuntimeFreshInvariantFinding] {
    var findings: [RuntimeFreshInvariantFinding] = []
    let invariant = RuntimeFreshInvariantKind.duplicateSurvivorsPreserved

    findings.append(
      contentsOf: compareObservation(
        immutable.namespace,
        current.namespace,
        invariant: invariant,
        component: .survivorNamespace,
        subject: subject,
        mismatch: .rawNamespaceChanged,
        compareKnown: { expected, observed in
          compareNamespaces(expected, observed, subject: subject)
        }
      )
    )
    findings.append(
      contentsOf: compareObservation(
        immutable.identity,
        current.identity,
        invariant: invariant,
        component: .survivorIdentity,
        subject: subject,
        mismatch: .objectIdentityChanged,
        compareKnown: { expected, observed in
          compareIdentity(
            expected,
            observed,
            invariant: invariant,
            component: .survivorIdentity,
            subject: subject
          )
        }
      )
    )
    findings.append(
      contentsOf: compareObservation(
        immutable.content,
        current.content,
        invariant: invariant,
        component: .survivorContent,
        subject: subject,
        mismatch: .contentChanged
      )
    )
    findings.append(
      contentsOf: compareObservation(
        immutable.accessPolicy,
        current.accessPolicy,
        invariant: invariant,
        component: .survivorAccessPolicy,
        subject: subject,
        mismatch: .accessPolicyChanged
      )
    )
    findings.append(
      contentsOf: compareObservation(
        immutable.aclDigest,
        current.aclDigest,
        invariant: invariant,
        component: .survivorACLDigest,
        subject: subject,
        mismatch: .aclChanged
      )
    )
    findings.append(
      contentsOf: compareObservation(
        immutable.providerState,
        current.providerState,
        invariant: invariant,
        component: .survivorProviderState,
        subject: subject,
        mismatch: .providerStateChanged
      )
    )
    findings.append(
      contentsOf: compareObservation(
        immutable.mountIdentity,
        current.mountIdentity,
        invariant: invariant,
        component: .survivorMountIdentity,
        subject: subject,
        mismatch: .mountIdentityChanged
      )
    )
    return findings
  }

  private static func validateTerminalNamespaces(
    _ terminals: [RuntimeFreshTerminalMutation]
  ) -> [RuntimeFreshInvariantFinding] {
    var findings: [RuntimeFreshInvariantFinding] = []
    var seenActions = Set<ActionID>()
    var known: [(RuntimeFreshTerminalMutation, ProtectedNamespaceBinding)] = []

    for terminal in terminals {
      let subject = terminal.actionID.hex
      if !seenActions.insert(terminal.actionID).inserted {
        findings.append(
          finding(
            .terminalNamespacesExclusive,
            .terminalRegistration,
            subject,
            .mismatch(.duplicateTerminalAction)
          )
        )
      }
      switch terminal.namespace {
      case .known(let namespace): known.append((terminal, namespace))
      case .absent:
        findings.append(
          finding(.terminalNamespacesExclusive, .terminalNamespace, subject, .missing)
        )
      case .unknown(let reason):
        findings.append(
          finding(.terminalNamespacesExclusive, .terminalNamespace, subject, .unknown(reason))
        )
      case .unreadable(let failure):
        findings.append(
          finding(
            .terminalNamespacesExclusive,
            .terminalNamespace,
            subject,
            .unreadable(failure)
          )
        )
      case .failed(let failure):
        findings.append(
          finding(.terminalNamespacesExclusive, .terminalNamespace, subject, .failed(failure))
        )
      }
    }

    for leftIndex in known.indices {
      for rightIndex in known.indices where rightIndex > leftIndex {
        let left = known[leftIndex]
        let right = known[rightIndex]
        guard namespacesMaySemanticallyOverlap(left.1, right.1) else { continue }
        guard exactReleaseReplacement(left.0, right.0) else {
          findings.append(
            finding(
              .terminalNamespacesExclusive,
              .terminalMutationOverlap,
              "\(left.0.actionID.hex):\(right.0.actionID.hex)",
              .mismatch(.overlappingTerminalMutation)
            )
          )
          continue
        }
      }
    }
    return findings
  }

  private static func compareNamespaces(
    _ expected: ProtectedNamespaceBinding,
    _ observed: ProtectedNamespaceBinding,
    subject: String
  ) -> [RuntimeFreshInvariantFinding] {
    let invariant = RuntimeFreshInvariantKind.duplicateSurvivorsPreserved
    var findings: [RuntimeFreshInvariantFinding] = []
    if expected.rawRoot != observed.rawRoot || expected.targetPath != observed.targetPath {
      findings.append(
        finding(
          invariant,
          .survivorNamespace,
          subject,
          .mismatch(.rawNamespaceChanged)
        )
      )
    }
    findings.append(
      contentsOf: compareIdentity(
        expected.rootIdentity,
        observed.rootIdentity,
        invariant: invariant,
        component: .survivorRootIdentity,
        subject: subject
      )
    )
    findings.append(
      contentsOf: compareSeal(
        expected.rootSeal,
        observed.rootSeal,
        invariant: invariant,
        subject: subject,
        components: (
          .survivorRootAccessPolicy,
          .survivorRootACLDigest,
          .survivorRootProviderState,
          .survivorRootMountIdentity
        )
      )
    )
    guard expected.parentChain.count == observed.parentChain.count else {
      findings.append(
        finding(
          invariant,
          .survivorAncestorIdentity,
          subject,
          .mismatch(.namespaceStructureChanged)
        )
      )
      return findings
    }
    for (index, pair) in zip(expected.parentChain, observed.parentChain).enumerated() {
      let expectedParent = pair.0
      let observedParent = pair.1
      let parentSubject = "\(subject):ancestor:\(index)"
      if expectedParent.relativePath != observedParent.relativePath {
        findings.append(
          finding(
            invariant,
            .survivorAncestorIdentity,
            parentSubject,
            .mismatch(.namespaceStructureChanged)
          )
        )
      }
      findings.append(
        contentsOf: compareIdentity(
          expectedParent.identity,
          observedParent.identity,
          invariant: invariant,
          component: .survivorAncestorIdentity,
          subject: parentSubject
        )
      )
      findings.append(
        contentsOf: compareSeal(
          expectedParent.seal,
          observedParent.seal,
          invariant: invariant,
          subject: parentSubject,
          components: (
            .survivorAncestorAccessPolicy,
            .survivorAncestorACLDigest,
            .survivorAncestorProviderState,
            .survivorAncestorMountIdentity
          )
        )
      )
    }
    findings.append(
      contentsOf: compareIdentity(
        expected.targetIdentity,
        observed.targetIdentity,
        invariant: invariant,
        component: .survivorIdentity,
        subject: subject
      )
    )
    return findings
  }

  private static func compareSeal(
    _ expected: NamespaceSealEvidence,
    _ observed: NamespaceSealEvidence,
    invariant: RuntimeFreshInvariantKind,
    subject: String,
    components: (
      access: RuntimeFreshInvariantComponent,
      acl: RuntimeFreshInvariantComponent,
      provider: RuntimeFreshInvariantComponent,
      mount: RuntimeFreshInvariantComponent
    )
  ) -> [RuntimeFreshInvariantFinding] {
    var findings: [RuntimeFreshInvariantFinding] = []
    if expected.trustedNamespace != observed.trustedNamespace {
      findings.append(
        finding(
          invariant,
          components.access,
          subject,
          .mismatch(.namespaceTrustChanged)
        )
      )
    }
    findings.append(
      contentsOf: compareObservation(
        expected.accessPolicy,
        observed.accessPolicy,
        invariant: invariant,
        component: components.access,
        subject: subject,
        mismatch: .accessPolicyChanged
      )
    )
    findings.append(
      contentsOf: compareObservation(
        expected.aclDigest,
        observed.aclDigest,
        invariant: invariant,
        component: components.acl,
        subject: subject,
        mismatch: .aclChanged
      )
    )
    findings.append(
      contentsOf: compareObservation(
        expected.providerBoundary,
        observed.providerBoundary,
        invariant: invariant,
        component: components.provider,
        subject: subject,
        mismatch: .providerStateChanged
      )
    )
    findings.append(
      contentsOf: compareObservation(
        expected.mountIdentity,
        observed.mountIdentity,
        invariant: invariant,
        component: components.mount,
        subject: subject,
        mismatch: .mountIdentityChanged
      )
    )
    return findings
  }

  private static func compareIdentity(
    _ expected: ObjectIdentity,
    _ observed: ObjectIdentity,
    invariant: RuntimeFreshInvariantKind,
    component: RuntimeFreshInvariantComponent,
    subject: String
  ) -> [RuntimeFreshInvariantFinding] {
    guard expected.device == observed.device, expected.object == observed.object,
      expected.type == observed.type
    else {
      return [finding(invariant, component, subject, .mismatch(.objectIdentityChanged))]
    }
    guard case .known(let expectedGeneration) = expected.generation else {
      if case .unreadable(let failure) = expected.generation {
        return [finding(invariant, component, subject, .unreadable(failure))]
      }
      if case .failed(let failure) = expected.generation {
        return [finding(invariant, component, subject, .failed(failure))]
      }
      return []
    }
    switch observed.generation {
    case .known(let generation):
      return generation == expectedGeneration
        ? []
        : [finding(invariant, component, subject, .mismatch(.objectIdentityChanged))]
    case .absent:
      return [finding(invariant, component, subject, .missing)]
    case .unknown(let reason):
      return [finding(invariant, component, subject, .unknown(reason))]
    case .unreadable(let failure):
      return [finding(invariant, component, subject, .unreadable(failure))]
    case .failed(let failure):
      return [finding(invariant, component, subject, .failed(failure))]
    }
  }

  private static func compareObservation<Value: Equatable & Sendable>(
    _ expected: Observation<Value>,
    _ observed: Observation<Value>,
    invariant: RuntimeFreshInvariantKind,
    component: RuntimeFreshInvariantComponent,
    subject: String,
    mismatch: RuntimeFreshInvariantMismatch,
    compareKnown: ((Value, Value) -> [RuntimeFreshInvariantFinding])? = nil
  ) -> [RuntimeFreshInvariantFinding] {
    switch expected {
    case .known(let expectedValue):
      switch observed {
      case .known(let observedValue):
        if let compareKnown { return compareKnown(expectedValue, observedValue) }
        return expectedValue == observedValue
          ? []
          : [finding(invariant, component, subject, .mismatch(mismatch))]
      case .absent:
        return [finding(invariant, component, subject, .missing)]
      case .unknown(let reason):
        return [finding(invariant, component, subject, .unknown(reason))]
      case .unreadable(let failure):
        return [finding(invariant, component, subject, .unreadable(failure))]
      case .failed(let failure):
        return [finding(invariant, component, subject, .failed(failure))]
      }
    case .absent:
      return [finding(invariant, component, subject, .missing)]
    case .unknown(let reason):
      return [finding(invariant, component, subject, .unknown(reason))]
    case .unreadable(let failure):
      return [finding(invariant, component, subject, .unreadable(failure))]
    case .failed(let failure):
      return [finding(invariant, component, subject, .failed(failure))]
    }
  }

  private static func exactReleaseReplacement(
    _ lhs: RuntimeFreshTerminalMutation,
    _ rhs: RuntimeFreshTerminalMutation
  ) -> Bool {
    switch (lhs.kind, rhs.kind) {
    case (.releaseComposite(let owners), .ordinary):
      return owners.contains(rhs.actionID)
    case (.ordinary, .releaseComposite(let owners)):
      return owners.contains(lhs.actionID)
    default:
      return false
    }
  }

  private static func namespacesMaySemanticallyOverlap(
    _ lhs: ProtectedNamespaceBinding,
    _ rhs: ProtectedNamespaceBinding
  ) -> Bool {
    let leftAbsolute = rawRootComponents(lhs.rawRoot) + lhs.targetPath.components
    let rightAbsolute = rawRootComponents(rhs.rawRoot) + rhs.targetPath.components
    if pathComponentsOverlap(leftAbsolute, rightAbsolute) { return true }
    if identitiesMayAlias(lhs.rootIdentity, rhs.rootIdentity),
      lhs.targetPath.overlaps(rhs.targetPath)
    {
      return true
    }
    let leftAncestors = [lhs.rootIdentity] + lhs.parentChain.map(\.identity)
    let rightAncestors = [rhs.rootIdentity] + rhs.parentChain.map(\.identity)
    return identitiesMayAlias(lhs.targetIdentity, rhs.targetIdentity)
      || rightAncestors.contains { identitiesMayAlias(lhs.targetIdentity, $0) }
      || leftAncestors.contains { identitiesMayAlias(rhs.targetIdentity, $0) }
  }

  private static func identitiesMayAlias(_ lhs: ObjectIdentity, _ rhs: ObjectIdentity) -> Bool {
    guard lhs.device == rhs.device, lhs.object == rhs.object else { return false }
    switch (lhs.generation, rhs.generation) {
    case (.known(let left), .known(let right)): return left == right
    default: return true
    }
  }

  private static func rawRootComponents(_ root: RawRootPath) -> [Data] {
    guard root.absoluteBytes != Data("/".utf8) else { return [] }
    return root.absoluteBytes.dropFirst().split(separator: 47).map { Data($0) }
  }

  private static func pathComponentsOverlap(_ lhs: [Data], _ rhs: [Data]) -> Bool {
    let sharedCount = min(lhs.count, rhs.count)
    return Array(lhs.prefix(sharedCount)) == Array(rhs.prefix(sharedCount))
  }

  private static func survivorPrecedes(
    _ lhs: RuntimeFreshDuplicateSurvivor,
    _ rhs: RuntimeFreshDuplicateSurvivor
  ) -> Bool {
    let leftGroup = Data(lhs.groupID.utf8)
    let rightGroup = Data(rhs.groupID.utf8)
    if leftGroup != rightGroup { return leftGroup.lexicographicallyPrecedes(rightGroup) }
    return Data(lhs.candidateID.utf8).lexicographicallyPrecedes(Data(rhs.candidateID.utf8))
  }

  private static func survivorSubject(_ survivor: RuntimeFreshDuplicateSurvivor) -> String {
    "\(survivor.groupID):\(survivor.candidateID)"
  }

  private static func finding(
    _ invariant: RuntimeFreshInvariantKind,
    _ component: RuntimeFreshInvariantComponent,
    _ subject: String,
    _ rejection: RuntimeFreshInvariantRejection
  ) -> RuntimeFreshInvariantFinding {
    RuntimeFreshInvariantFinding(
      invariant: invariant,
      component: component,
      subjectID: subject,
      rejection: rejection
    )
  }

  private static func rawStringEqual(_ lhs: String, _ rhs: String) -> Bool {
    Data(lhs.utf8) == Data(rhs.utf8)
  }
}
