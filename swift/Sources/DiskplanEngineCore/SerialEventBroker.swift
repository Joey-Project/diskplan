import DiskplanCore
import DiskplanProto
import Darwin
import Foundation
import SwiftProtobuf

enum EventBrokerError: Error, Equatable {
  case closed
  case outputFailed(String)
}

enum BrokerRuntimeBatchPreparationError: Error {
  case mirroredEnvelopeCountExceeded(actual: Int, maximum: Int)
  case mirroredEncodedBytesExceeded(actual: UInt64, maximum: UInt64)
  case reservationSequenceExhausted
  case eventSequenceExhausted
  case serializationFailed(String)
}

struct BrokerRuntimeRecord: Sendable {
  let requestID: UInt64
  let runtimeSessionID: Data
  let body: Diskplan_V1_RuntimeEvent.OneOf_Body
}

private enum PendingOutput: @unchecked Sendable {
  case envelope(sequence: UInt64, body: Diskplan_V1_Envelope.OneOf_Body)
  case event(
    requestID: UInt64,
    scanSessionID: String,
    body: Diskplan_V1_EngineEvent.OneOf_Body,
    telemetry: Bool,
    writeAcknowledgement: BrokerWriteAcknowledgement?
  )
  case runtimeEvent(
    requestID: UInt64,
    runtimeSessionID: Data,
    body: Diskplan_V1_RuntimeEvent.OneOf_Body
  )
  case serializedRuntimeBatch([Data], BrokerWriteAcknowledgement)

  var isTelemetry: Bool {
    if case .event(_, _, _, let telemetry, _) = self { return telemetry }
    return false
  }

  var writeAcknowledgement: BrokerWriteAcknowledgement? {
    switch self {
    case .event(_, _, _, _, let acknowledgement): acknowledgement
    case .serializedRuntimeBatch(_, let acknowledgement): acknowledgement
    default: nil
    }
  }

  var semanticWeight: Int {
    switch self {
    case .serializedRuntimeBatch: 1
    case .envelope, .event, .runtimeEvent: 1
    }
  }
}

private final class BrokerWriteAcknowledgement: @unchecked Sendable {
  private let condition = NSCondition()
  private var result: Result<Void, EventBrokerError>?

  func resolve(_ result: Result<Void, EventBrokerError>) {
    condition.lock()
    guard self.result == nil else {
      condition.unlock()
      return
    }
    self.result = result
    condition.broadcast()
    condition.unlock()
  }

  func wait() throws {
    condition.lock()
    while result == nil { condition.wait() }
    let result = self.result!
    condition.unlock()
    try result.get()
  }
}

enum RuntimeResponderWorkerError: Error, Equatable {
  case closed
  case capacityExceeded(maximumPending: Int)
}

private protocol RuntimeResponderQueuedOperation: AnyObject, Sendable {
  func execute() -> () -> Void
  func cancelBeforeExecution(_ error: any Error)
}

private final class RuntimeResponderOperation<Value: Sendable>: RuntimeResponderQueuedOperation,
  @unchecked Sendable
{
  private let lock = NSLock()
  private var operation: (@Sendable () throws -> Value)?
  private var continuation: CheckedContinuation<Value, any Error>?

  init(
    operation: @escaping @Sendable () throws -> Value,
    continuation: CheckedContinuation<Value, any Error>
  ) {
    self.operation = operation
    self.continuation = continuation
  }

  func execute() -> () -> Void {
    let operation: (@Sendable () throws -> Value)? = lock.withLock {
      defer { self.operation = nil }
      return self.operation
    }
    guard let operation else { return {} }
    do {
      let result = try operation()
      return { self.complete(.success(result)) }
    } catch {
      return { self.complete(.failure(error)) }
    }
  }

  func cancelBeforeExecution(_ error: any Error) {
    lock.withLock { operation = nil }
    complete(.failure(error))
  }

  private func complete(_ result: Result<Value, any Error>) {
    let continuation = lock.withLock {
      defer { self.continuation = nil }
      return self.continuation
    }
    continuation?.resume(with: result)
  }
}

private final class RuntimeResponderCancellationRegistration: @unchecked Sendable {
  private let lock = NSLock()
  private var action: (@Sendable () -> Void)?
  private var cancellationRequested = false

  func install(_ action: @escaping @Sendable () -> Void) {
    let cancelImmediately = lock.withLock {
      if cancellationRequested { return true }
      self.action = action
      return false
    }
    if cancelImmediately { action() }
  }

  func cancel() {
    let action = lock.withLock {
      cancellationRequested = true
      defer { self.action = nil }
      return self.action
    }
    action?()
  }
}

private enum RuntimeResponderCancellationOutcome {
  case cancelledBeforeExecution
  case executing
  case completed
}

private final class RuntimeResponderWorker: @unchecked Sendable {
  private let condition = NSCondition()
  private let maximumPending: Int
  private let beforeCompletionResumeForTesting: (@Sendable () -> Void)?
  private var pending: [any RuntimeResponderQueuedOperation] = []
  private var active: (any RuntimeResponderQueuedOperation)?
  private var accepting = true
  private var finished = false
  private var threadStartCount = 0
  private var maximumObservedActiveCount = 0

  init(
    maximumPending: Int,
    beforeCompletionResumeForTesting: (@Sendable () -> Void)? = nil
  ) {
    precondition(maximumPending > 0)
    self.maximumPending = maximumPending
    self.beforeCompletionResumeForTesting = beforeCompletionResumeForTesting
    let thread = Thread { [self] in drain() }
    thread.name = "diskplan-runtime-responder-worker"
    condition.lock()
    threadStartCount = 1
    condition.unlock()
    thread.start()
  }

  func perform<Value: Sendable>(
    _ operation: @escaping @Sendable () throws -> Value,
    onExecutingCancellation: @escaping @Sendable () -> Void
  ) async throws -> Value {
    let registration = RuntimeResponderCancellationRegistration()
    return try await withTaskCancellationHandler {
      try Task.checkCancellation()
      return try await withCheckedThrowingContinuation { continuation in
        let item = RuntimeResponderOperation(
          operation: operation,
          continuation: continuation
        )
        enqueue(item)
        registration.install { [weak self, weak item] in
          guard let self, let item else { return }
          if self.cancel(item) == .executing {
            onExecutingCancellation()
          }
        }
      }
    } onCancel: {
      registration.cancel()
    }
  }

  func beginStop() -> Bool {
    condition.lock()
    guard accepting else {
      let hasActive = active != nil
      condition.unlock()
      return hasActive
    }
    accepting = false
    let cancelled = pending
    pending.removeAll(keepingCapacity: false)
    let hasActive = active != nil
    condition.broadcast()
    condition.unlock()
    for item in cancelled {
      item.cancelBeforeExecution(CancellationError())
    }
    return hasActive
  }

  func waitUntilStopped() {
    condition.lock()
    while !finished { condition.wait() }
    condition.unlock()
  }

  var threadStartCountForTesting: Int {
    condition.withLock { threadStartCount }
  }

  var maximumObservedActiveCountForTesting: Int {
    condition.withLock { maximumObservedActiveCount }
  }

  var pendingCountForTesting: Int {
    condition.withLock { pending.count }
  }

  var isAcceptingForTesting: Bool {
    condition.withLock { accepting }
  }

  private func enqueue(_ item: any RuntimeResponderQueuedOperation) {
    condition.lock()
    if !accepting {
      condition.unlock()
      item.cancelBeforeExecution(RuntimeResponderWorkerError.closed)
      return
    }
    guard pending.count < maximumPending else {
      condition.unlock()
      item.cancelBeforeExecution(
        RuntimeResponderWorkerError.capacityExceeded(maximumPending: maximumPending)
      )
      return
    }
    pending.append(item)
    condition.signal()
    condition.unlock()
  }

  private func cancel(
    _ item: any RuntimeResponderQueuedOperation
  ) -> RuntimeResponderCancellationOutcome {
    condition.lock()
    if let index = pending.firstIndex(where: { $0 === item }) {
      let cancelled = pending.remove(at: index)
      condition.unlock()
      cancelled.cancelBeforeExecution(CancellationError())
      return .cancelledBeforeExecution
    }
    if active === item {
      condition.unlock()
      return .executing
    }
    condition.unlock()
    return .completed
  }

  private func drain() {
    while true {
      condition.lock()
      while pending.isEmpty && accepting { condition.wait() }
      guard !pending.isEmpty else {
        finished = true
        condition.broadcast()
        condition.unlock()
        return
      }
      let item = pending.removeFirst()
      active = item
      maximumObservedActiveCount = max(maximumObservedActiveCount, 1)
      condition.unlock()

      let complete = item.execute()

      condition.lock()
      if active === item { active = nil }
      condition.broadcast()
      condition.unlock()

      beforeCompletionResumeForTesting?()
      complete()
    }
  }
}

private enum InterruptibleFrameWriterError: Error, CustomStringConvertible {
  case setupFailed(Int32)
  case interrupted
  case writeFailed(Int32)

  var description: String {
    switch self {
    case .setupFailed(let code):
      "could not configure nonblocking engine output: errno \(code)"
    case .interrupted:
      "engine output was interrupted during lifecycle teardown"
    case .writeFailed(let code):
      "engine output write failed: errno \(code)"
    }
  }
}

/// The production stdout writer never enters a blocking write syscall. When
/// pipe capacity is exhausted it waits on this condition in short readiness
/// probes, so lifecycle interruption wakes it without closing a FileHandle
/// concurrently with Foundation I/O.
private final class InterruptibleFrameWriter: @unchecked Sendable {
  private let condition = NSCondition()
  private let fileDescriptor: Int32
  private let setupError: Int32?
  private var interrupted = false
  private var waitingForCapacity = false

  init(output: FileHandle) {
    fileDescriptor = output.fileDescriptor
    let flags = fcntl(fileDescriptor, F_GETFL)
    if flags == -1 || fcntl(fileDescriptor, F_SETFL, flags | O_NONBLOCK) == -1
      || fcntl(fileDescriptor, F_SETNOSIGPIPE, 1) == -1
    {
      setupError = errno
    } else {
      setupError = nil
    }
  }

  func write(_ payload: Data) throws {
    if let setupError { throw InterruptibleFrameWriterError.setupFailed(setupError) }
    guard payload.count <= maximumFrameLength else {
      throw FrameError.oversized(length: payload.count, maximum: maximumFrameLength)
    }
    var length = UInt32(payload.count).bigEndian
    try Swift.withUnsafeBytes(of: &length) { bytes in
      try writeAll(bytes)
    }
    try payload.withUnsafeBytes { bytes in
      try writeAll(bytes)
    }
  }

  func interrupt() {
    condition.lock()
    interrupted = true
    condition.broadcast()
    condition.unlock()
  }

  var isBlocked: Bool {
    condition.withLock { waitingForCapacity }
  }

  private func writeAll(_ bytes: UnsafeRawBufferPointer) throws {
    var offset = 0
    while offset < bytes.count {
      try checkInterrupted()
      let count = Darwin.write(
        fileDescriptor,
        bytes.baseAddress!.advanced(by: offset),
        bytes.count - offset
      )
      if count > 0 {
        offset += count
        continue
      }
      if count == -1, errno == EINTR { continue }
      if count == -1, errno == EAGAIN || errno == EWOULDBLOCK {
        condition.lock()
        waitingForCapacity = true
        if !interrupted {
          _ = condition.wait(until: Date(timeIntervalSinceNow: 0.01))
        }
        waitingForCapacity = false
        let wasInterrupted = interrupted
        condition.unlock()
        if wasInterrupted { throw InterruptibleFrameWriterError.interrupted }
        continue
      }
      throw InterruptibleFrameWriterError.writeFailed(errno)
    }
  }

  private func checkInterrupted() throws {
    condition.lock()
    let wasInterrupted = interrupted
    condition.unlock()
    if wasInterrupted { throw InterruptibleFrameWriterError.interrupted }
  }
}

/// The sole post-handshake stdout writer. Semantic events block at a finite
/// queue boundary; only a contiguous pending telemetry run may be replaced.
final class SerialEventBroker: @unchecked Sendable {
  typealias Writer = @Sendable (Data) throws -> Void

  private let condition = NSCondition()
  private let semanticCapacity: Int
  private let writer: Writer
  private let interruptWriter: @Sendable () -> Void
  private let writerIsBlocked: @Sendable () -> Bool
  private let runtimeResponderWorker: RuntimeResponderWorker
  private var pending: [PendingOutput] = []
  private var semanticCount = 0
  private var inFlightCount = 0
  private var inFlightWriteAcknowledgement: BrokerWriteAcknowledgement?
  private var closing = false
  private var finished = false
  private var writerInterrupted = false
  private var failure: EventBrokerError?
  private var nextEventSequence: UInt64 = 1
  private var nextRuntimeBatchReservation: UInt64 = 1
  private var runtimeBatchReservations: [UInt64] = []

  init(
    semanticCapacity: Int = 128,
    writer: @escaping Writer,
    interruptWriter: @escaping @Sendable () -> Void = {},
    writerIsBlocked: @escaping @Sendable () -> Bool = { false },
    responderCompletionHookForTesting: (@Sendable () -> Void)? = nil
  ) {
    precondition(semanticCapacity > 0)
    self.semanticCapacity = semanticCapacity
    self.writer = writer
    self.interruptWriter = interruptWriter
    self.writerIsBlocked = writerIsBlocked
    runtimeResponderWorker = RuntimeResponderWorker(
      maximumPending: 128,
      beforeCompletionResumeForTesting: responderCompletionHookForTesting
    )
    Thread { [self] in drain() }.start()
  }

  convenience init(
    output: FileHandle,
    semanticCapacity: Int = 128
  ) {
    let outputWriter = InterruptibleFrameWriter(output: output)
    self.init(
      semanticCapacity: semanticCapacity,
      writer: { data in
        try outputWriter.write(data)
      },
      interruptWriter: {
        outputWriter.interrupt()
      },
      writerIsBlocked: {
        outputWriter.isBlocked
      }
    )
  }

  func performRuntimeResponderOperation<Value: Sendable>(
    _ operation: @escaping @Sendable () throws -> Value
  ) async throws -> Value {
    try await runtimeResponderWorker.perform(
      operation,
      onExecutingCancellation: { [weak self] in
        self?.failAndInterrupt(
          "runtime responder operation was cancelled during transport"
        )
      }
    )
  }

  /// Stops the fixed-size runtime responder executor. If one transaction is
  /// already executing, the transport is failed closed and its writer is
  /// interrupted before joining the worker so lifecycle shutdown cannot wait
  /// behind an unread stdout pipe.
  func stopRuntimeResponderOperationsAndWait(
    interruptingInFlightWriter: Bool = false
  ) {
    let hadActiveOperation = runtimeResponderWorker.beginStop()
    let hadInFlightWriter = condition.withLock { inFlightCount != 0 }
    let hadBlockedWriter = hadInFlightWriter && writerIsBlocked()
    let shouldInterrupt = hadActiveOperation || (interruptingInFlightWriter && hadBlockedWriter)
    if shouldInterrupt {
      failAndInterrupt("runtime responder lifecycle stopped during transport")
    }
    runtimeResponderWorker.waitUntilStopped()
    if shouldInterrupt { waitUntilFinished() }
  }

  func runtimeResponderWorkerThreadStartCountForTesting() -> Int {
    runtimeResponderWorker.threadStartCountForTesting
  }

  func runtimeResponderMaximumActiveCountForTesting() -> Int {
    runtimeResponderWorker.maximumObservedActiveCountForTesting
  }

  func runtimeResponderPendingCountForTesting() -> Int {
    runtimeResponderWorker.pendingCountForTesting
  }

  func runtimeResponderIsAcceptingForTesting() -> Bool {
    runtimeResponderWorker.isAcceptingForTesting
  }

  func sendEnvelope(
    sequence: UInt64,
    body: Diskplan_V1_Envelope.OneOf_Body
  ) throws {
    try enqueue(.envelope(sequence: sequence, body: body), semantic: true)
  }

  func sendSemantic(
    requestID: UInt64,
    scanSessionID: String = "",
    body: Diskplan_V1_EngineEvent.OneOf_Body
  ) throws {
    try enqueue(
      .event(
        requestID: requestID,
        scanSessionID: scanSessionID,
        body: body,
        telemetry: false,
        writeAcknowledgement: nil
      ),
      semantic: true
    )
  }

  func sendRuntime(
    requestID: UInt64,
    runtimeSessionID: Data,
    body: Diskplan_V1_RuntimeEvent.OneOf_Body
  ) throws {
    try enqueue(
      .runtimeEvent(
        requestID: requestID,
        runtimeSessionID: runtimeSessionID,
        body: body
      ),
      semantic: true
    )
  }

  /// Enqueues a prevalidated mirrored runtime emission as one queue item and
  /// waits for the writer to process every contained envelope. A writer error
  /// may leave a physical prefix on a transport that is immediately failed
  /// and closed, but the shared acknowledgement never reports success.
  func sendRuntimeBatchAwaitingWrite(_ records: [BrokerRuntimeRecord]) throws {
    guard !records.isEmpty,
      records.count <= RuntimeEmissionBudget.maximumMirroredBatchEnvelopeCount
    else {
      throw BrokerRuntimeBatchPreparationError.mirroredEnvelopeCountExceeded(
        actual: records.count,
        maximum: RuntimeEmissionBudget.maximumMirroredBatchEnvelopeCount
      )
    }
    let acknowledgement = BrokerWriteAcknowledgement()
    condition.lock()
    let reservation: UInt64
    do {
      reservation = try reserveRuntimeBatch()
    } catch {
      condition.unlock()
      throw error
    }
    while (runtimeBatchReservations.first != reservation || !pending.isEmpty
      || inFlightCount != 0) && failure == nil && !closing
    {
      condition.wait()
    }
    do {
      try checkOpen()
      let serializedBatch: ([Data], UInt64)
      do {
        serializedBatch = try serializedRuntimeBatch(
          records,
          startingAt: nextEventSequence
        )
      } catch let error as BrokerRuntimeBatchPreparationError {
        throw error
      } catch {
        throw BrokerRuntimeBatchPreparationError.serializationFailed(
          String(describing: error)
        )
      }
      let (serialized, nextSequence) = serializedBatch
      nextEventSequence = nextSequence
      pending.append(.serializedRuntimeBatch(serialized, acknowledgement))
      semanticCount += 1
      releaseRuntimeBatchReservation(reservation)
      condition.broadcast()
      condition.unlock()
    } catch {
      releaseRuntimeBatchReservation(reservation)
      condition.unlock()
      throw error
    }
    try acknowledgement.wait()
  }

  func sendSemanticAwaitingWrite(
    requestID: UInt64,
    scanSessionID: String = "",
    body: Diskplan_V1_EngineEvent.OneOf_Body
  ) throws {
    let acknowledgement = BrokerWriteAcknowledgement()
    try enqueue(
      .event(
        requestID: requestID,
        scanSessionID: scanSessionID,
        body: body,
        telemetry: false,
        writeAcknowledgement: acknowledgement
      ),
      semantic: true
    )
    try acknowledgement.wait()
  }

  func sendProgress(
    scanSessionID: String,
    progress: Diskplan_V1_ScanProgress
  ) throws {
    condition.lock()
    defer { condition.unlock() }
    while !runtimeBatchReservations.isEmpty && failure == nil && !closing {
      condition.wait()
    }
    try checkOpen()
    if let last = pending.indices.last,
      pending[last].isTelemetry
    {
      pending[last] = .event(
        requestID: 0,
        scanSessionID: scanSessionID,
        body: .scanProgress(progress),
        telemetry: true,
        writeAcknowledgement: nil
      )
    } else {
      pending.append(
        .event(
          requestID: 0,
          scanSessionID: scanSessionID,
          body: .scanProgress(progress),
          telemetry: true,
          writeAcknowledgement: nil
        ))
    }
    condition.signal()
  }

  func finish() throws {
    stopRuntimeResponderOperationsAndWait()
    condition.lock()
    closing = true
    condition.broadcast()
    while !finished { condition.wait() }
    let failure = failure
    condition.unlock()
    if let failure { throw failure }
  }

  /// Hard lifecycle teardown used after the input side reaches EOF or fails.
  /// A healthy writer drains normally. A writer waiting on transport capacity
  /// is failed closed and interrupted so teardown never waits behind a peer
  /// that no longer reads the transport.
  func finishForLifecycleTeardown() throws {
    stopRuntimeResponderOperationsAndWait(interruptingInFlightWriter: true)
    condition.lock()
    closing = true
    condition.broadcast()
    condition.unlock()
    while true {
      condition.lock()
      if finished {
        condition.unlock()
        break
      }
      _ = condition.wait(until: Date(timeIntervalSinceNow: 0.01))
      condition.unlock()
      if writerIsBlocked() {
        failAndInterrupt("broker lifecycle stopped with blocked output")
      }
    }
    let terminalFailure: EventBrokerError? = condition.withLock { self.failure }
    if let terminalFailure { throw terminalFailure }
  }

  func failClosed(_ summary: String) {
    let outputFailure = EventBrokerError.outputFailed(summary)
    condition.lock()
    guard failure == nil, !finished else {
      condition.unlock()
      return
    }
    failure = outputFailure
    closing = true
    let pendingAcknowledgements = pending.compactMap(\.writeAcknowledgement)
    let inFlightAcknowledgement = inFlightWriteAcknowledgement
    pending.removeAll()
    semanticCount = 0
    condition.broadcast()
    condition.unlock()
    inFlightAcknowledgement?.resolve(.failure(outputFailure))
    for acknowledgement in pendingAcknowledgements {
      acknowledgement.resolve(.failure(outputFailure))
    }
  }

  /// Waits until every output accepted before this call has completed its
  /// actual writer invocation. Runtime authority receipts commit only after
  /// this barrier succeeds.
  func flush() throws {
    condition.lock()
    while (!pending.isEmpty || inFlightCount != 0) && failure == nil && !finished {
      condition.wait()
    }
    let failure = failure
    condition.unlock()
    if let failure { throw failure }
  }

  func runtimeBatchReservationCountForTesting() -> Int {
    condition.lock()
    defer { condition.unlock() }
    return runtimeBatchReservations.count
  }

  private func failAndInterrupt(_ summary: String) {
    failClosed(summary)
    condition.lock()
    let shouldInterrupt = !writerInterrupted
    writerInterrupted = true
    condition.unlock()
    if shouldInterrupt { interruptWriter() }
  }

  private func waitUntilFinished() {
    condition.lock()
    while !finished { condition.wait() }
    condition.unlock()
  }

  private func enqueue(_ output: PendingOutput, semantic: Bool) throws {
    condition.lock()
    defer { condition.unlock() }
    while semantic && (semanticCount >= semanticCapacity || !runtimeBatchReservations.isEmpty)
      && failure == nil && !closing
    {
      condition.wait()
    }
    try checkOpen()
    pending.append(output)
    if semantic { semanticCount += 1 }
    condition.signal()
  }

  private func reserveRuntimeBatch() throws -> UInt64 {
    let reservation = nextRuntimeBatchReservation
    guard reservation != 0 else {
      throw BrokerRuntimeBatchPreparationError.reservationSequenceExhausted
    }
    nextRuntimeBatchReservation =
      reservation == UInt64.max ? 0 : reservation + 1
    runtimeBatchReservations.append(reservation)
    condition.broadcast()
    return reservation
  }

  private func releaseRuntimeBatchReservation(_ reservation: UInt64) {
    guard let index = runtimeBatchReservations.firstIndex(of: reservation) else { return }
    runtimeBatchReservations.remove(at: index)
    condition.broadcast()
  }

  private func checkOpen() throws {
    if let failure { throw failure }
    if closing { throw EventBrokerError.closed }
  }

  private func drain() {
    while true {
      condition.lock()
      while pending.isEmpty && !closing { condition.wait() }
      if pending.isEmpty && closing {
        finished = true
        condition.broadcast()
        condition.unlock()
        return
      }
      let output = pending.removeFirst()
      inFlightCount += 1
      inFlightWriteAcknowledgement = output.writeAcknowledgement
      if !output.isTelemetry { semanticCount -= output.semanticWeight }
      condition.broadcast()
      condition.unlock()

      do {
        for data in try serialized(output) {
          try writer(data)
        }
        condition.lock()
        inFlightCount -= 1
        inFlightWriteAcknowledgement = nil
        condition.broadcast()
        condition.unlock()
        output.writeAcknowledgement?.resolve(.success(()))
      } catch {
        let outputFailure = EventBrokerError.outputFailed(String(describing: error))
        condition.lock()
        inFlightCount -= 1
        inFlightWriteAcknowledgement = nil
        failure = outputFailure
        let pendingAcknowledgements = pending.compactMap(\.writeAcknowledgement)
        pending.removeAll()
        semanticCount = 0
        closing = true
        finished = true
        condition.broadcast()
        condition.unlock()
        output.writeAcknowledgement?.resolve(.failure(outputFailure))
        for acknowledgement in pendingAcknowledgements {
          acknowledgement.resolve(.failure(outputFailure))
        }
        return
      }
    }
  }

  private func serialized(_ output: PendingOutput) throws -> [Data] {
    var envelope = Diskplan_V1_Envelope()
    switch output {
    case .envelope(let sequence, let body):
      envelope.sequence = sequence
      envelope.body = body
    case .event(let requestID, let scanSessionID, let body, _, _):
      let sequence = try consumeEventSequence()
      var event = Diskplan_V1_EngineEvent()
      event.eventSequence = sequence
      event.requestID = requestID
      event.scanSessionID = scanSessionID
      event.body = body
      envelope.sequence = sequence
      envelope.body = .engineEvent(event)
    case .runtimeEvent(let requestID, let runtimeSessionID, let body):
      let sequence = try consumeEventSequence()
      var sessionID = Diskplan_V1_OpaqueIdentifier()
      sessionID.value = runtimeSessionID
      var event = Diskplan_V1_RuntimeEvent()
      event.eventSequence = sequence
      event.requestID = requestID
      event.runtimeSessionID = sessionID
      event.body = body
      envelope.sequence = sequence
      envelope.body = .runtimeEvent(event)
    case .serializedRuntimeBatch(let envelopes, _):
      return envelopes
    }
    return [try envelope.serializedData()]
  }

  private func serializedRuntimeBatch(
    _ records: [BrokerRuntimeRecord],
    startingAt initialSequence: UInt64
  ) throws -> ([Data], UInt64) {
    var sequence = initialSequence
    var serialized: [Data] = []
    serialized.reserveCapacity(records.count)
    var framedBytes: UInt64 = 0
    for record in records {
      guard sequence != 0 else {
        throw BrokerRuntimeBatchPreparationError.eventSequenceExhausted
      }
      var event = Diskplan_V1_RuntimeEvent()
      event.eventSequence = sequence
      event.requestID = record.requestID
      event.runtimeSessionID.value = record.runtimeSessionID
      event.body = record.body
      var envelope = Diskplan_V1_Envelope()
      envelope.sequence = sequence
      envelope.body = .runtimeEvent(event)
      let encoded = try envelope.serializedData()
      let (framedLength, frameOverflow) = UInt64(encoded.count).addingReportingOverflow(4)
      let (nextFramedBytes, aggregateOverflow) = framedBytes.addingReportingOverflow(framedLength)
      guard !frameOverflow, !aggregateOverflow,
        nextFramedBytes <= RuntimeEmissionBudget.maximumMirroredBatchFramedBytes
      else {
        throw BrokerRuntimeBatchPreparationError.mirroredEncodedBytesExceeded(
          actual: aggregateOverflow ? UInt64.max : nextFramedBytes,
          maximum: RuntimeEmissionBudget.maximumMirroredBatchFramedBytes
        )
      }
      framedBytes = nextFramedBytes
      serialized.append(encoded)
      sequence = sequence == UInt64.max ? 0 : sequence + 1
    }
    return (serialized, sequence)
  }

  private func consumeEventSequence() throws -> UInt64 {
    let sequence = nextEventSequence
    guard sequence != 0 else {
      throw EventBrokerError.outputFailed("event sequence space exhausted")
    }
    nextEventSequence = sequence == UInt64.max ? 0 : sequence + 1
    return sequence
  }
}
