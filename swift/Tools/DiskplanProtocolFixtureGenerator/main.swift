import DiskplanEngineCore
import DiskplanProto
import Foundation

private struct FixtureSpec: Decodable {
  let schema: String
  let cases: [FixtureCase]
}

private struct FixtureCase: Decodable {
  let name: String
  let terminal: String
  let chunkPayloadTargetBytes: Int
  let nodeComponentsHex: [[String]]

  enum CodingKeys: String, CodingKey {
    case name
    case terminal
    case chunkPayloadTargetBytes = "chunk_payload_target_bytes"
    case nodeComponentsHex = "node_components_hex"
  }
}

private enum GeneratorError: Error, CustomStringConvertible {
  case usage
  case invalidSchema(String)
  case invalidTerminal(String)
  case invalidHex(String)

  var description: String {
    switch self {
    case .usage:
      "usage: diskplan-protocol-fixture-generator <fixture.json> <output-directory>"
    case .invalidSchema(let schema):
      "unsupported fixture schema: \(schema)"
    case .invalidTerminal(let terminal):
      "unsupported fixture terminal: \(terminal)"
    case .invalidHex(let value):
      "invalid fixture hex: \(value)"
    }
  }
}

@main
private enum DiskplanProtocolFixtureGenerator {
  static func main() throws {
    guard CommandLine.arguments.count == 3 else { throw GeneratorError.usage }
    let input = URL(fileURLWithPath: CommandLine.arguments[1])
    let output = URL(fileURLWithPath: CommandLine.arguments[2], isDirectory: true)
    let spec = try JSONDecoder().decode(FixtureSpec.self, from: Data(contentsOf: input))
    guard spec.schema == "scan-stream-v1.3" else {
      throw GeneratorError.invalidSchema(spec.schema)
    }
    try FileManager.default.createDirectory(at: output, withIntermediateDirectories: true)
    for fixture in spec.cases {
      let frames = try frames(for: fixture)
      let contents = frames.map(hex).joined(separator: "\n") + "\n"
      try Data(contents.utf8).write(
        to: output.appendingPathComponent("\(fixture.name).frames.hex"),
        options: .atomic
      )
    }
  }

  private static func frames(for fixture: FixtureCase) throws -> [Data] {
    var checkpoint = Diskplan_V1_ScanCheckpointEvidence()
    checkpoint.profile = "full-audit"
    checkpoint.resolverVersion = 1
    checkpoint.retainedNodeCount = 10_000
    checkpoint.maximumDepth = 128
    checkpoint.coverage.complete = fixture.terminal == "finalized"
    checkpoint.coverage.reasons = fixture.terminal == "finalized" ? [] : ["subtree_incomplete"]
    checkpoint.machineState = fixture.terminal == "finalized" ? .complete : .scanning
    checkpoint.resumableInProcess = fixture.terminal == "ready"
    checkpoint.progress.profile = "full-audit"
    checkpoint.progress.retainedNodes = UInt64(fixture.nodeComponentsHex.count)
    checkpoint.progress.structuralBudget = 10_000
    checkpoint.retainedNodes = try fixture.nodeComponentsHex.enumerated().map { index, components in
      var node = Diskplan_V1_ScannedNodeEvidence()
      node.path.rootID = "fixture-root"
      node.path.components = try components.map(data(hex:))
      node.path.displayPath = "/fixture/node-\(index)"
      return node
    }
    let encoded = try CheckpointWireEncoder.encode(
      checkpoint,
      chunkPayloadTargetBytes: fixture.chunkPayloadTargetBytes
    )
    var bodies = encoded.chunks.map(Diskplan_V1_EngineEvent.OneOf_Body.scanCheckpointChunk)
    switch fixture.terminal {
    case "ready":
      var ready = Diskplan_V1_ScanCheckpointReady()
      ready.canonicalCheckpointPayload = encoded.checkpointPayload
      ready.manifest = encoded.manifest
      bodies.append(.scanCheckpointReady(ready))
    case "finalized":
      var finalized = Diskplan_V1_ScanFinalized()
      finalized.reason = "fixture finalized"
      finalized.canonicalCheckpointPayload = encoded.checkpointPayload
      finalized.manifest = encoded.manifest
      bodies.append(.scanFinalized(finalized))
    default:
      throw GeneratorError.invalidTerminal(fixture.terminal)
    }
    return try bodies.enumerated().map { index, body in
      let sequence = UInt64(index + 1)
      var event = Diskplan_V1_EngineEvent()
      event.eventSequence = sequence
      event.scanSessionID = "fixture-session"
      event.body = body
      var envelope = Diskplan_V1_Envelope()
      envelope.sequence = sequence
      envelope.body = .engineEvent(event)
      let payload = try envelope.serializedData()
      var frame = Data()
      appendBigEndian(UInt32(payload.count), to: &frame)
      frame.append(payload)
      return frame
    }
  }

  private static func data(hex: String) throws -> Data {
    guard hex.count.isMultiple(of: 2) else { throw GeneratorError.invalidHex(hex) }
    var data = Data()
    var index = hex.startIndex
    while index < hex.endIndex {
      let end = hex.index(index, offsetBy: 2)
      guard let byte = UInt8(hex[index..<end], radix: 16) else {
        throw GeneratorError.invalidHex(hex)
      }
      data.append(byte)
      index = end
    }
    return data
  }

  private static func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
  }

  private static func appendBigEndian(_ value: UInt32, to output: inout Data) {
    withUnsafeBytes(of: value.bigEndian) { output.append(contentsOf: $0) }
  }
}
