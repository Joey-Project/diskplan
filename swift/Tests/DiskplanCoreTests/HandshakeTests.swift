import DiskplanCore
import DiskplanProto
import Testing

@Test
func handshakeSelectsMinorAndSortedIntersection() throws {
  var local = Diskplan_V1_Hello()
  local.version = version(major: 1, minor: 4)
  local.requiredCapabilities = ["base"]
  local.optionalCapabilities = ["zeta", "alpha"]
  var peer = Diskplan_V1_Hello()
  peer.version = version(major: 1, minor: 2)
  peer.requiredCapabilities = ["zeta"]
  peer.optionalCapabilities = ["base", "alpha"]

  guard case .accepted(let accepted) = Handshake.negotiate(local: local, peer: peer) else {
    Issue.record("expected acceptance")
    return
  }
  #expect(accepted.selectedVersion.minor == 2)
  #expect(accepted.negotiatedCapabilities == ["alpha", "base", "zeta"])
}

@Test
func protocol16EndpointNegotiatesProtocol14WithoutChangingTheCurrentMinor() throws {
  #expect(protocolMinor == protocol16Minor)
  var peer = Handshake.swiftEngineHello(runtimeCapabilities: protocol14RuntimeCapabilities)
  peer.version.minor = protocol14Minor
  guard
    case .accepted(let accepted) = Handshake.negotiate(
      local: Handshake.swiftEngineHello(runtimeCapabilities: protocol14RuntimeCapabilities),
      peer: peer
    )
  else {
    Issue.record("expected protocol 1.4 negotiation")
    return
  }
  #expect(accepted.selectedVersion.minor == protocol14Minor)
}

@Test
func handshakeRejectsMajorMismatchAndMissingCapabilities() {
  var peer = Handshake.swiftEngineHello()
  peer.version = version(major: 2, minor: 0)
  guard
    case .rejected(let majorRejected) = Handshake.negotiate(
      local: Handshake.swiftEngineHello(),
      peer: peer
    )
  else {
    Issue.record("expected major rejection")
    return
  }
  #expect(majorRejected.code == .protocolMajorMismatch)

  peer = Handshake.swiftEngineHello()
  peer.requiredCapabilities.append("missing")
  guard
    case .rejected(let capabilityRejected) = Handshake.negotiate(
      local: Handshake.swiftEngineHello(),
      peer: peer
    )
  else {
    Issue.record("expected capability rejection")
    return
  }
  #expect(capabilityRejected.code == .missingRequiredCapability)
}

@Test
func engineHelloAdvertisesOnlyImplementedRuntimeCapabilities() {
  let scanOnly = Handshake.swiftEngineHello()
  #expect(Set(scanOnly.optionalCapabilities).isDisjoint(with: protocol14RuntimeCapabilities))

  let implemented: Set<String> = ["plan-projection-v1", "unknown-runtime-v1"]
  let withRuntimeHandler = Handshake.swiftEngineHello(runtimeCapabilities: implemented)
  #expect(withRuntimeHandler.optionalCapabilities.contains("plan-projection-v1"))
  #expect(!withRuntimeHandler.optionalCapabilities.contains("unknown-runtime-v1"))
}

private func version(major: UInt32, minor: UInt32) -> Diskplan_V1_ProtocolVersion {
  var value = Diskplan_V1_ProtocolVersion()
  value.major = major
  value.minor = minor
  return value
}
