import CryptoKit
import DiskplanProto
import Foundation

enum CheckpointWireEncodingError: Error, Equatable, CustomStringConvertible {
  case checkpointPayloadTooLarge(actual: Int, maximum: Int)
  case manifestTooLarge(actual: Int, maximum: Int)
  case nodeRecordTooLarge(actual: Int, maximum: Int)
  case retainedNodeCountExceedsBudget(actual: Int, budget: UInt32)
  case retainedNodeCountExceedsProtocolMaximum(actual: Int, maximum: Int)
  case retainedNodePayloadTooLarge(actual: UInt64, maximum: UInt64)
  case countOverflow(field: String)

  var description: String {
    switch self {
    case .checkpointPayloadTooLarge(let actual, let maximum):
      return "checkpoint payload is \(actual) bytes; maximum is \(maximum)"
    case .manifestTooLarge(let actual, let maximum):
      return "checkpoint manifest is \(actual) bytes; maximum is \(maximum)"
    case .nodeRecordTooLarge(let actual, let maximum):
      return "retained-node record is \(actual) bytes; chunk maximum is \(maximum)"
    case .retainedNodeCountExceedsBudget(let actual, let budget):
      return "checkpoint retained \(actual) nodes; entry budget is \(budget)"
    case .retainedNodeCountExceedsProtocolMaximum(let actual, let maximum):
      return "checkpoint retained \(actual) nodes; protocol maximum is \(maximum)"
    case .retainedNodePayloadTooLarge(let actual, let maximum):
      return "retained-node payload is \(actual) bytes; maximum is \(maximum)"
    case .countOverflow(let field):
      return "checkpoint \(field) exceeds the protocol integer range"
    }
  }
}

struct EncodedCheckpointWire {
  let checkpointPayload: Data
  let chunks: [Diskplan_V1_ScanCheckpointChunk]
  let manifest: Diskplan_V1_ScanCheckpointManifest
}

enum CheckpointWireEncoder {
  static let manifestVersion: UInt32 = 1
  static let maximumCheckpointPayloadBytes = 4 * 1_024 * 1_024
  static let maximumChunkPayloadBytes = 4 * 1_024 * 1_024
  static let maximumManifestEncodedBytes = 2 * 1_024 * 1_024
  static let maximumRetainedNodeCount = 10_000
  static let maximumRetainedNodePayloadBytes: UInt64 = 768 * 1_024 * 1_024

  private static let finalDigestDomain = Data("diskplan/scan-checkpoint-final/v1\0".utf8)
  private static let checkpointDigestDomain = Data(
    "diskplan/scan-checkpoint-evidence/v1\0".utf8)

  static func encode(
    _ checkpointWithRetainedNodes: Diskplan_V1_ScanCheckpointEvidence
  ) throws -> EncodedCheckpointWire {
    let retainedNodes = checkpointWithRetainedNodes.retainedNodes
    guard retainedNodes.count <= maximumRetainedNodeCount else {
      throw CheckpointWireEncodingError.retainedNodeCountExceedsProtocolMaximum(
        actual: retainedNodes.count,
        maximum: maximumRetainedNodeCount
      )
    }
    guard retainedNodes.count <= Int(checkpointWithRetainedNodes.retainedNodeCount) else {
      throw CheckpointWireEncodingError.retainedNodeCountExceedsBudget(
        actual: retainedNodes.count,
        budget: checkpointWithRetainedNodes.retainedNodeCount
      )
    }
    var checkpoint = checkpointWithRetainedNodes
    checkpoint.retainedNodes.removeAll(keepingCapacity: false)
    let checkpointPayload = try checkpoint.serializedData()
    guard checkpointPayload.count <= maximumCheckpointPayloadBytes else {
      throw CheckpointWireEncodingError.checkpointPayloadTooLarge(
        actual: checkpointPayload.count,
        maximum: maximumCheckpointPayloadBytes
      )
    }

    let chunkPayloads = try chunkedNodePayloads(retainedNodes)
    var descriptors: [Diskplan_V1_ScanCheckpointChunkDescriptor] = []
    var chunks: [Diskplan_V1_ScanCheckpointChunk] = []
    descriptors.reserveCapacity(chunkPayloads.count)
    chunks.reserveCapacity(chunkPayloads.count)

    var totalNodeCount: UInt64 = 0
    var totalPayloadBytes: UInt64 = 0
    for (index, value) in chunkPayloads.enumerated() {
      guard let chunkIndex = UInt32(exactly: index) else {
        throw CheckpointWireEncodingError.countOverflow(field: "chunk_count")
      }
      let payloadDigest = digest(value.payload)
      let chunkID = "\(chunkIndex)-\(hex(payloadDigest))"

      var descriptor = Diskplan_V1_ScanCheckpointChunkDescriptor()
      descriptor.chunkIndex = chunkIndex
      descriptor.chunkID = chunkID
      descriptor.nodeCount = value.nodeCount
      descriptor.payloadBytes = UInt64(value.payload.count)
      descriptor.payloadSha256 = payloadDigest
      descriptors.append(descriptor)

      var chunk = Diskplan_V1_ScanCheckpointChunk()
      chunk.chunkIndex = chunkIndex
      chunk.chunkID = chunkID
      chunk.nodeCount = value.nodeCount
      chunk.canonicalNodePayload = value.payload
      chunk.payloadSha256 = payloadDigest
      chunks.append(chunk)

      totalNodeCount = try addingExact(
        totalNodeCount,
        UInt64(value.nodeCount),
        field: "retained_node_count"
      )
      totalPayloadBytes = try addingExact(
        totalPayloadBytes,
        UInt64(value.payload.count),
        field: "retained_node_payload_bytes"
      )
      guard totalPayloadBytes <= maximumRetainedNodePayloadBytes else {
        throw CheckpointWireEncodingError.retainedNodePayloadTooLarge(
          actual: totalPayloadBytes,
          maximum: maximumRetainedNodePayloadBytes
        )
      }
    }

    guard let chunkCount = UInt32(exactly: chunks.count) else {
      throw CheckpointWireEncodingError.countOverflow(field: "chunk_count")
    }
    var manifest = Diskplan_V1_ScanCheckpointManifest()
    manifest.manifestVersion = manifestVersion
    manifest.chunkCount = chunkCount
    manifest.retainedNodeCount = totalNodeCount
    manifest.retainedNodeEntryBudget = checkpoint.retainedNodeCount
    manifest.retainedNodePayloadBytes = totalPayloadBytes
    manifest.maximumCheckpointPayloadBytes = UInt32(maximumCheckpointPayloadBytes)
    manifest.maximumChunkPayloadBytes = UInt32(maximumChunkPayloadBytes)
    manifest.maximumManifestEncodedBytes = UInt32(maximumManifestEncodedBytes)
    manifest.maximumRetainedNodePayloadBytes = maximumRetainedNodePayloadBytes
    manifest.chunks = descriptors
    manifest.checkpointEvidenceSha256 = checkpointEvidenceDigest(checkpointPayload)
    manifest.frontier = checkpoint.progress
    manifest.coverage = checkpoint.coverage
    manifest.completedRootIds = checkpoint.completedRoots.map { $0.root.rootID }
    manifest.failedRootIds = checkpoint.rootFailures.map(\.rootID)
    manifest.machineState = checkpoint.machineState
    manifest.resumableInProcess = checkpoint.resumableInProcess
    manifest.provisional = checkpoint.provisional
    manifest.finalEvidenceSha256 = finalEvidenceDigest(manifest)
    manifest.checkpointID = hex(manifest.finalEvidenceSha256)

    for index in chunks.indices {
      chunks[index].checkpointID = manifest.checkpointID
    }
    let manifestSize = try manifest.serializedData().count
    guard manifestSize <= maximumManifestEncodedBytes else {
      throw CheckpointWireEncodingError.manifestTooLarge(
        actual: manifestSize,
        maximum: maximumManifestEncodedBytes
      )
    }
    return EncodedCheckpointWire(
      checkpointPayload: checkpointPayload,
      chunks: chunks,
      manifest: manifest
    )
  }

  private static func chunkedNodePayloads(
    _ nodes: [Diskplan_V1_ScannedNodeEvidence]
  ) throws -> [(payload: Data, nodeCount: UInt32)] {
    var result: [(Data, UInt32)] = []
    var payload = Data()
    var nodeCount: UInt32 = 0

    for node in nodes {
      let encoded = try node.serializedData()
      guard let encodedCount = UInt32(exactly: encoded.count) else {
        throw CheckpointWireEncodingError.countOverflow(field: "node_record_bytes")
      }
      var record = Data()
      appendBigEndian(encodedCount, to: &record)
      record.append(encoded)
      guard record.count <= maximumChunkPayloadBytes else {
        throw CheckpointWireEncodingError.nodeRecordTooLarge(
          actual: record.count,
          maximum: maximumChunkPayloadBytes
        )
      }

      if !payload.isEmpty && payload.count + record.count > maximumChunkPayloadBytes {
        result.append((payload, nodeCount))
        payload = Data()
        nodeCount = 0
      }
      payload.append(record)
      let (nextCount, overflow) = nodeCount.addingReportingOverflow(1)
      guard !overflow else {
        throw CheckpointWireEncodingError.countOverflow(field: "chunk_node_count")
      }
      nodeCount = nextCount
    }
    if !payload.isEmpty {
      result.append((payload, nodeCount))
    }
    return result
  }

  private static func finalEvidenceDigest(
    _ manifest: Diskplan_V1_ScanCheckpointManifest
  ) -> Data {
    var canonical = finalDigestDomain
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
    return digest(canonical)
  }

  private static func addingExact(
    _ lhs: UInt64,
    _ rhs: UInt64,
    field: String
  ) throws -> UInt64 {
    let (value, overflow) = lhs.addingReportingOverflow(rhs)
    guard !overflow else { throw CheckpointWireEncodingError.countOverflow(field: field) }
    return value
  }

  private static func digest(_ data: Data) -> Data {
    Data(SHA256.hash(data: data))
  }

  private static func checkpointEvidenceDigest(_ payload: Data) -> Data {
    var canonical = checkpointDigestDomain
    canonical.append(payload)
    return digest(canonical)
  }

  private static func hex(_ data: Data) -> String {
    data.map { String(format: "%02x", $0) }.joined()
  }

  private static func appendLengthPrefixed(_ data: Data, to output: inout Data) {
    precondition(data.count <= Int(UInt32.max))
    appendBigEndian(UInt32(data.count), to: &output)
    output.append(data)
  }

  private static func appendBigEndian<T: FixedWidthInteger>(_ value: T, to data: inout Data) {
    var encoded = value.bigEndian
    withUnsafeBytes(of: &encoded) { data.append(contentsOf: $0) }
  }
}
