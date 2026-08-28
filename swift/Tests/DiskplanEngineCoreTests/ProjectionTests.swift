import DiskplanProto
import DiskplanScan
import Foundation
import SwiftProtobuf
import Testing

@testable import DiskplanEngineCore

@Test func rawPathProjectionPreservesBytesAndSeparatesDisplay() {
  let component = RawPathComponent(Data([0x66, 0xff]))
  let node = ScannedNode(
    path: RawPath(rootID: "fixture", components: [component]),
    identity: .unknown(reason: "fixture"),
    bytes: .unknown,
    coverage: Coverage(completeness: .partial, reasons: [.collectorFailed]),
    providerBoundary: .unverified(reason: "fixture")
  )
  let projected = ScanIPCProjection.node(
    node,
    roots: [ScanRootRequest(rootID: "fixture", rawAbsolutePath: Data("/tmp/root".utf8))]
  )

  #expect(projected.path.components == [Data([0x66, 0xff])])
  #expect(projected.path.displayPath == "/tmp/root/\\x66\\xff")
  #expect(projected.identity.observation.status == .unknown)
  #expect(projected.coverage.reasons == ["collector_failed"])
}

@Test func displayProjectionEscapesTerminalControlAndFormatCharacters() {
  #expect(
    ScanIPCProjection.displayRawBytes(Data([0x66, 0x1b, 0x5b, 0x32, 0x4a]))
      == "\\x66\\x1b\\x5b\\x32\\x4a"
  )
  #expect(
    ScanIPCProjection.displayRawBytes(Data("safe-name".utf8)) == "safe-name"
  )
  #expect(
    ScanIPCProjection.displayRawBytes(Data("left\u{202e}right".utf8))
      == Data("left\u{202e}right".utf8).map { String(format: "\\x%02x", $0) }.joined()
  )
}

@Test func brokerCoalescesOnlyPendingProgressAndPreservesSemantics() throws {
  let gate = TestGate()
  let output = LockedValues<Data>()
  let broker = SerialEventBroker(semanticCapacity: 4) { data in
    gate.wait()
    output.append(data)
  }

  var accepted = Diskplan_V1_ControlAccepted()
  accepted.control = .startScan
  accepted.resultingState = .running
  try broker.sendSemantic(requestID: 1, scanSessionID: "session", body: .controlAccepted(accepted))
  for entries in 1...100 {
    var progress = Diskplan_V1_ScanProgress()
    progress.entries = UInt64(entries)
    try broker.sendProgress(scanSessionID: "session", progress: progress)
  }
  var checkpoint = Diskplan_V1_ScanCheckpointReady()
  checkpoint.checkpoint.profile = "standard"
  try broker.sendSemantic(
    requestID: 0,
    scanSessionID: "session",
    body: .scanCheckpointReady(checkpoint)
  )

  gate.open()
  try broker.finish()

  let envelopes: [Diskplan_V1_Envelope] = try output.snapshot().map { data in
    try Diskplan_V1_Envelope(serializedBytes: data)
  }
  #expect(envelopes.count == 3)
  #expect(envelopes.map(\.sequence) == [1, 2, 3])
  guard case .engineEvent(let progressEvent) = envelopes[1].body,
    case .scanProgress(let progress) = progressEvent.body
  else {
    Issue.record("expected coalesced progress between semantic events")
    return
  }
  #expect(progress.entries == 100)
  #expect(progressEvent.requestID == 0)
  #expect(progressEvent.scanSessionID == "session")
}

@Test func brokerAppliesBoundedSemanticBackpressureWithoutLoss() throws {
  let writerGate = TestGate()
  let writerEntered = TestFlag()
  let broker = SerialEventBroker(semanticCapacity: 1) { _ in
    writerEntered.set()
    writerGate.wait()
  }

  let changed: Diskplan_V1_ScanStateChanged = {
    var value = Diskplan_V1_ScanStateChanged()
    value.state = .running
    return value
  }()
  try broker.sendSemantic(requestID: 0, scanSessionID: "session", body: .scanStateChanged(changed))
  #expect(writerEntered.wait(timeout: 1.0))
  try broker.sendSemantic(requestID: 0, scanSessionID: "session", body: .scanStateChanged(changed))

  let producerFinished = TestFlag()
  Thread {
    try? broker.sendSemantic(
      requestID: 0,
      scanSessionID: "session",
      body: .scanStateChanged(changed)
    )
    producerFinished.set()
  }.start()

  Thread.sleep(forTimeInterval: 0.025)
  #expect(!producerFinished.value())

  writerGate.open()
  #expect(producerFinished.wait(timeout: 1.0))
  try broker.finish()
}

@Test func brokerDoesNotCoalesceProgressAcrossSemanticEvidence() throws {
  let gate = TestGate()
  let output = LockedValues<Data>()
  let broker = SerialEventBroker(semanticCapacity: 4) { data in
    gate.wait()
    output.append(data)
  }

  var first = Diskplan_V1_ScanProgress()
  first.entries = 1
  try broker.sendProgress(scanSessionID: "session", progress: first)
  var checkpoint = Diskplan_V1_ScanCheckpointReady()
  checkpoint.checkpoint.profile = "standard"
  try broker.sendSemantic(
    requestID: 0,
    scanSessionID: "session",
    body: .scanCheckpointReady(checkpoint)
  )
  var second = Diskplan_V1_ScanProgress()
  second.entries = 2
  try broker.sendProgress(scanSessionID: "session", progress: second)

  gate.open()
  try broker.finish()

  let envelopes: [Diskplan_V1_Envelope] = try output.snapshot().map { data in
    try Diskplan_V1_Envelope(serializedBytes: data)
  }
  #expect(envelopes.count == 3)
  #expect(envelopes.map(\.sequence) == [1, 2, 3])
  guard case .engineEvent(let firstEvent) = envelopes[0].body,
    case .scanProgress(let firstProgress) = firstEvent.body,
    case .engineEvent(let secondEvent) = envelopes[2].body,
    case .scanProgress(let secondProgress) = secondEvent.body
  else {
    Issue.record("expected progress on both sides of semantic evidence")
    return
  }
  #expect(firstProgress.entries == 1)
  #expect(secondProgress.entries == 2)
}

@Test func brokerFailureUnblocksBackpressuredSemanticProducer() throws {
  let writerGate = TestGate()
  let writerEntered = TestFlag()
  let producerFinished = TestFlag()
  let producerObservedFailure = TestFlag()
  let broker = SerialEventBroker(semanticCapacity: 1) { _ in
    writerEntered.set()
    writerGate.wait()
    throw FixtureWriterError.failed
  }
  let changed: Diskplan_V1_ScanStateChanged = {
    var value = Diskplan_V1_ScanStateChanged()
    value.state = .running
    return value
  }()

  try broker.sendSemantic(requestID: 0, scanSessionID: "session", body: .scanStateChanged(changed))
  #expect(writerEntered.wait(timeout: 1.0))
  try broker.sendSemantic(requestID: 0, scanSessionID: "session", body: .scanStateChanged(changed))
  Thread {
    do {
      try broker.sendSemantic(
        requestID: 0,
        scanSessionID: "session",
        body: .scanStateChanged(changed)
      )
    } catch {
      producerObservedFailure.set()
    }
    producerFinished.set()
  }.start()

  Thread.sleep(forTimeInterval: 0.025)
  #expect(!producerFinished.value())
  writerGate.open()
  #expect(producerFinished.wait(timeout: 1.0))
  #expect(producerObservedFailure.value())
  do {
    try broker.finish()
    Issue.record("broker finish unexpectedly succeeded after writer failure")
  } catch let error as EventBrokerError {
    guard case .outputFailed = error else {
      Issue.record("unexpected broker error: \(error)")
      return
    }
  }
}

private enum FixtureWriterError: Error {
  case failed
}

private final class TestGate: @unchecked Sendable {
  private let condition = NSCondition()
  private var opened = false

  func wait() {
    condition.lock()
    while !opened { condition.wait() }
    condition.unlock()
  }

  func open() {
    condition.lock()
    opened = true
    condition.broadcast()
    condition.unlock()
  }
}

private final class TestFlag: @unchecked Sendable {
  private let condition = NSCondition()
  private var setValue = false

  func set() {
    condition.lock()
    setValue = true
    condition.broadcast()
    condition.unlock()
  }

  func value() -> Bool {
    condition.lock()
    defer { condition.unlock() }
    return setValue
  }

  func wait(timeout: TimeInterval) -> Bool {
    condition.lock()
    let deadline = Date(timeIntervalSinceNow: timeout)
    while !setValue && condition.wait(until: deadline) {}
    let result = setValue
    condition.unlock()
    return result
  }
}

private final class LockedValues<Value>: @unchecked Sendable {
  private let lock = NSLock()
  private var values: [Value] = []

  func append(_ value: Value) {
    lock.lock()
    values.append(value)
    lock.unlock()
  }

  func snapshot() -> [Value] {
    lock.lock()
    defer { lock.unlock() }
    return values
  }
}
