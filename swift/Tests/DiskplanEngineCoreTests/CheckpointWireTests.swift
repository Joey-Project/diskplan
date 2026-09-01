import DiskplanCore
import DiskplanProto
import Foundation
import Testing

@testable import DiskplanEngineCore

@Test func maximumDepthRawByteCheckpointStaysBelowEveryFrameBudget() throws {
  var checkpoint = checkpointFixture(entryBudget: 10_000)
  var node = Diskplan_V1_ScannedNodeEvidence()
  node.path.rootID = "raw-root"
  node.path.components = (0..<128).map { index in
    Data([0xff, UInt8(truncatingIfNeeded: index), 0x1b, 0x7f])
  }
  node.path.displayPath = node.path.components
    .flatMap { $0.map { String(format: "\\x%02x", $0) } }
    .joined(separator: "/")
  checkpoint.retainedNodes = [node]

  let encoded = try CheckpointWireEncoder.encode(checkpoint)

  #expect(encoded.chunks.count == 1)
  #expect(
    encoded.chunks[0].canonicalNodePayload.count
      <= CheckpointWireEncoder.maximumChunkPayloadBytes
  )
  #expect(try eventEnvelopeSize(.scanCheckpointChunk(encoded.chunks[0])) < maximumFrameLength)
  #expect(try readyEnvelopeSize(encoded) < maximumFrameLength)

  let payload = encoded.chunks[0].canonicalNodePayload
  let recordLength = payload.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
  let record = payload.dropFirst(4).prefix(Int(recordLength))
  let decoded = try Diskplan_V1_ScannedNodeEvidence(serializedBytes: record)
  #expect(decoded.path.components == node.path.components)
}

@Test func tenThousandRetainedNodesUseOnlyBoundedFramesAndCanonicalManifest() throws {
  var checkpoint = checkpointFixture(entryBudget: 10_000)
  checkpoint.retainedNodes = (0..<10_000).map { index in
    var node = Diskplan_V1_ScannedNodeEvidence()
    node.path.rootID = "full-root"
    var component = Data("node-\(index)".utf8)
    component.append(0xff)
    node.path.components = [component]
    node.path.displayPath = "/fixture/node-\(index)\\xff"
    return node
  }
  checkpoint.progress.retainedNodes = 10_000

  let encoded = try CheckpointWireEncoder.encode(checkpoint)

  #expect(encoded.manifest.retainedNodeCount == 10_000)
  #expect(encoded.manifest.retainedNodeEntryBudget == 10_000)
  #expect(encoded.manifest.chunkCount == UInt32(encoded.chunks.count))
  #expect(encoded.manifest.chunks.count == encoded.chunks.count)
  #expect(
    encoded.manifest.maximumRetainedNodePayloadBytes
      == CheckpointWireEncoder.maximumRetainedNodePayloadBytes
  )
  #expect(try encoded.manifest.serializedData().count <= CheckpointWireEncoder.maximumManifestEncodedBytes)
  for chunk in encoded.chunks {
    #expect(chunk.canonicalNodePayload.count <= CheckpointWireEncoder.maximumChunkPayloadBytes)
    #expect(try eventEnvelopeSize(.scanCheckpointChunk(chunk)) < maximumFrameLength)
  }
  #expect(try readyEnvelopeSize(encoded) < maximumFrameLength)
}

private func checkpointFixture(entryBudget: UInt32) -> Diskplan_V1_ScanCheckpointEvidence {
  var checkpoint = Diskplan_V1_ScanCheckpointEvidence()
  checkpoint.profile = "full-audit"
  checkpoint.retainedNodeCount = entryBudget
  checkpoint.maximumDepth = 128
  checkpoint.coverage.complete = false
  checkpoint.coverage.reasons = ["subtree_incomplete"]
  checkpoint.machineState = .scanning
  checkpoint.resumableInProcess = true
  checkpoint.progress.profile = "full-audit"
  checkpoint.progress.structuralBudget = 100_000_000
  return checkpoint
}

private func readyEnvelopeSize(_ encoded: EncodedCheckpointWire) throws -> Int {
  var ready = Diskplan_V1_ScanCheckpointReady()
  ready.canonicalCheckpointPayload = encoded.checkpointPayload
  ready.manifest = encoded.manifest
  return try eventEnvelopeSize(.scanCheckpointReady(ready))
}

private func eventEnvelopeSize(_ body: Diskplan_V1_EngineEvent.OneOf_Body) throws -> Int {
  var event = Diskplan_V1_EngineEvent()
  event.eventSequence = 1
  event.requestID = 0
  event.scanSessionID = "fixture-session"
  event.body = body
  var envelope = Diskplan_V1_Envelope()
  envelope.sequence = 1
  envelope.body = .engineEvent(event)
  return try envelope.serializedData().count
}
