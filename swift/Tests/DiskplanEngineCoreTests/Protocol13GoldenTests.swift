import CryptoKit
import DiskplanProto
import Foundation
import Testing

private enum Protocol13FixtureError: Error {
  case invalid(String)
}

@Test func protocol13GoldenFramesDecodeValidateAndReencodeExactly() throws {
  for name in ["zero-ready", "single-ready", "multi-finalized"] {
    let frames = try protocol13Frames(name)
    try validateProtocol13Frames(frames)
  }
}

@Test func protocol13GoldenFramesRejectTruncationCountHashAndFrontierMutations() throws {
  let original = try protocol13Frames("multi-finalized")
  var truncated = original
  truncated[0].removeLast()
  #expect(throws: Protocol13FixtureError.self) { try validateProtocol13Frames(truncated) }

  var countMismatch = original
  try mutateTerminalFrame(&countMismatch) { $0.chunkCount &+= 1 }
  #expect(throws: Protocol13FixtureError.self) { try validateProtocol13Frames(countMismatch) }

  var hashMismatch = original
  try mutateTerminalFrame(&hashMismatch) { $0.finalEvidenceSha256[0] ^= 0xff }
  #expect(throws: Protocol13FixtureError.self) { try validateProtocol13Frames(hashMismatch) }

  var frontierMismatch = original
  try mutateTerminalFrame(&frontierMismatch) { $0.frontier.retainedNodes &+= 1 }
  #expect(throws: Protocol13FixtureError.self) { try validateProtocol13Frames(frontierMismatch) }
}

private func validateProtocol13Frames(_ frames: [Data]) throws {
  var chunks: [Diskplan_V1_ScanCheckpointChunk] = []
  var terminal: (Data, Diskplan_V1_ScanCheckpointManifest)?
  for (index, frame) in frames.enumerated() {
    let payload = try framedPayload(frame)
    let envelope = try Diskplan_V1_Envelope(serializedBytes: payload)
    guard try envelope.serializedData() == payload,
      envelope.sequence == UInt64(index + 1),
      case .engineEvent(let event) = envelope.body,
      event.eventSequence == envelope.sequence,
      event.requestID == 0,
      event.scanSessionID == "fixture-session"
    else {
      throw Protocol13FixtureError.invalid("non-canonical event envelope")
    }
    switch event.body {
    case .scanCheckpointChunk(let chunk):
      let digest = Data(SHA256.hash(data: chunk.canonicalNodePayload))
      guard chunk.chunkIndex == UInt32(chunks.count),
        chunk.payloadSha256 == digest,
        chunk.chunkID == "\(chunk.chunkIndex)-\(hex(digest))",
        try canonicalNodeCount(chunk.canonicalNodePayload) == Int(chunk.nodeCount)
      else {
        throw Protocol13FixtureError.invalid("invalid checkpoint chunk")
      }
      chunks.append(chunk)
    case .scanCheckpointReady(let ready):
      guard !ready.hasCheckpoint, ready.hasManifest else {
        throw Protocol13FixtureError.invalid("invalid ready terminal")
      }
      terminal = (ready.canonicalCheckpointPayload, ready.manifest)
    case .scanFinalized(let finalized):
      guard !finalized.hasCheckpoint, finalized.hasManifest else {
        throw Protocol13FixtureError.invalid("invalid finalized terminal")
      }
      terminal = (finalized.canonicalCheckpointPayload, finalized.manifest)
    default:
      throw Protocol13FixtureError.invalid("unexpected fixture event")
    }
  }
  guard let (payload, manifest) = terminal, manifest.manifestVersion == 1 else {
    throw Protocol13FixtureError.invalid("missing terminal manifest")
  }
  let checkpoint = try Diskplan_V1_ScanCheckpointEvidence(serializedBytes: payload)
  guard try checkpoint.serializedData() == payload,
    checkpoint.retainedNodes.isEmpty,
    manifest.chunkCount == UInt32(chunks.count),
    manifest.retainedNodeCount == chunks.reduce(0, { $0 + UInt64($1.nodeCount) }),
    manifest.retainedNodePayloadBytes
      == chunks.reduce(0, { $0 + UInt64($1.canonicalNodePayload.count) }),
    manifest.chunks.count == chunks.count,
    manifest.checkpointEvidenceSha256 == checkpointDigest(payload),
    manifest.finalEvidenceSha256 == finalDigest(manifest),
    manifest.checkpointID == hex(manifest.finalEvidenceSha256),
    manifest.frontier == checkpoint.progress,
    manifest.coverage == checkpoint.coverage,
    manifest.machineState == checkpoint.machineState,
    manifest.resumableInProcess == checkpoint.resumableInProcess,
    manifest.provisional == checkpoint.provisional,
    manifest.frontier.retainedNodes == manifest.retainedNodeCount
  else {
    throw Protocol13FixtureError.invalid("invalid terminal manifest")
  }
  for (chunk, descriptor) in zip(chunks, manifest.chunks) {
    guard chunk.checkpointID == manifest.checkpointID,
      descriptor.chunkIndex == chunk.chunkIndex,
      descriptor.chunkID == chunk.chunkID,
      descriptor.nodeCount == chunk.nodeCount,
      descriptor.payloadBytes == UInt64(chunk.canonicalNodePayload.count),
      descriptor.payloadSha256 == chunk.payloadSha256
    else {
      throw Protocol13FixtureError.invalid("chunk descriptor mismatch")
    }
  }
}

private func mutateTerminalFrame(
  _ frames: inout [Data],
  mutation: (inout Diskplan_V1_ScanCheckpointManifest) -> Void
) throws {
  let index = frames.count - 1
  let envelopePayload = try framedPayload(frames[index])
  var envelope = try Diskplan_V1_Envelope(serializedBytes: envelopePayload)
  guard case .engineEvent(var event) = envelope.body else {
    throw Protocol13FixtureError.invalid("missing terminal event")
  }
  switch event.body {
  case .scanCheckpointReady(var ready):
    mutation(&ready.manifest)
    event.body = .scanCheckpointReady(ready)
  case .scanFinalized(var finalized):
    mutation(&finalized.manifest)
    event.body = .scanFinalized(finalized)
  default:
    throw Protocol13FixtureError.invalid("missing terminal manifest")
  }
  envelope.body = .engineEvent(event)
  frames[index] = try framed(try envelope.serializedData())
}

private func protocol13Frames(_ name: String) throws -> [Data] {
  let url = URL(fileURLWithPath: #filePath)
    .deletingLastPathComponent().deletingLastPathComponent().deletingLastPathComponent()
    .deletingLastPathComponent()
    .appendingPathComponent("proto/fixtures/scan-stream-v1.3/\(name).frames.hex")
  return try String(contentsOf: url, encoding: .utf8).split(whereSeparator: \.isNewline).map {
    try data(hex: String($0))
  }
}

private func framedPayload(_ frame: Data) throws -> Data {
  guard frame.count >= 4 else { throw Protocol13FixtureError.invalid("truncated frame prefix") }
  let length = frame.prefix(4).reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
  guard frame.count == Int(length) + 4 else {
    throw Protocol13FixtureError.invalid("truncated frame payload")
  }
  return frame.dropFirst(4)
}

private func framed(_ payload: Data) throws -> Data {
  guard let count = UInt32(exactly: payload.count) else {
    throw Protocol13FixtureError.invalid("frame length overflow")
  }
  var result = Data()
  appendBigEndian(count, to: &result)
  result.append(payload)
  return result
}

private func canonicalNodeCount(_ payload: Data) throws -> Int {
  var index = payload.startIndex
  var count = 0
  while index < payload.endIndex {
    guard payload.distance(from: index, to: payload.endIndex) >= 4 else {
      throw Protocol13FixtureError.invalid("truncated node record length")
    }
    let lengthEnd = payload.index(index, offsetBy: 4)
    let length = payload[index..<lengthEnd].reduce(UInt32(0)) { ($0 << 8) | UInt32($1) }
    let recordEnd = payload.index(lengthEnd, offsetBy: Int(length), limitedBy: payload.endIndex)
    guard let recordEnd else { throw Protocol13FixtureError.invalid("truncated node record") }
    let record = payload[lengthEnd..<recordEnd]
    let node = try Diskplan_V1_ScannedNodeEvidence(serializedBytes: record)
    guard try node.serializedData() == record else {
      throw Protocol13FixtureError.invalid("non-canonical node record")
    }
    count += 1
    index = recordEnd
  }
  return count
}

private func checkpointDigest(_ payload: Data) -> Data {
  var canonical = Data("diskplan/scan-checkpoint-evidence/v1\0".utf8)
  canonical.append(payload)
  return Data(SHA256.hash(data: canonical))
}

private func finalDigest(_ manifest: Diskplan_V1_ScanCheckpointManifest) -> Data {
  var canonical = Data("diskplan/scan-checkpoint-final/v1\0".utf8)
  appendBigEndian(manifest.manifestVersion, to: &canonical)
  appendLengthPrefixed(manifest.checkpointEvidenceSha256, to: &canonical)
  appendBigEndian(manifest.chunkCount, to: &canonical)
  appendBigEndian(manifest.retainedNodeCount, to: &canonical)
  appendBigEndian(manifest.retainedNodeEntryBudget, to: &canonical)
  appendBigEndian(manifest.retainedNodePayloadBytes, to: &canonical)
  appendBigEndian(manifest.maximumCheckpointPayloadBytes, to: &canonical)
  appendBigEndian(manifest.maximumChunkPayloadBytes, to: &canonical)
  appendBigEndian(manifest.maximumManifestEncodedBytes, to: &canonical)
  appendBigEndian(manifest.maximumRetainedNodePayloadBytes, to: &canonical)
  for descriptor in manifest.chunks {
    appendBigEndian(descriptor.chunkIndex, to: &canonical)
    appendLengthPrefixed(Data(descriptor.chunkID.utf8), to: &canonical)
    appendBigEndian(descriptor.nodeCount, to: &canonical)
    appendBigEndian(descriptor.payloadBytes, to: &canonical)
    appendLengthPrefixed(descriptor.payloadSha256, to: &canonical)
  }
  return Data(SHA256.hash(data: canonical))
}

private func appendLengthPrefixed(_ data: Data, to output: inout Data) {
  appendBigEndian(UInt32(data.count), to: &output)
  output.append(data)
}

private func appendBigEndian<T: FixedWidthInteger>(_ value: T, to output: inout Data) {
  var value = value.bigEndian
  withUnsafeBytes(of: &value) { output.append(contentsOf: $0) }
}

private func data(hex: String) throws -> Data {
  guard hex.count.isMultiple(of: 2) else { throw Protocol13FixtureError.invalid("odd hex") }
  var result = Data()
  var index = hex.startIndex
  while index < hex.endIndex {
    let end = hex.index(index, offsetBy: 2)
    guard let byte = UInt8(hex[index..<end], radix: 16) else {
      throw Protocol13FixtureError.invalid("invalid hex")
    }
    result.append(byte)
    index = end
  }
  return result
}

private func hex(_ data: Data) -> String {
  data.map { String(format: "%02x", $0) }.joined()
}
