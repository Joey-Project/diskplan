import Darwin
import DiskplanMacOS
import Foundation
import Testing

@testable import DiskplanScan

@Test
func lsofParserClassifiesAndCanonicalizesProcessReferences() throws {
  let payload = Data(
    [
      "p42\0cworker\0fcwd\0n/tmp/work\0",
      "f3u\0n/tmp/work/open\0",
      "ftxt\0n/tmp/work/bin\0",
      "ftxt\0n/tmp/work/bin\0",
      "fmem\0n/tmp/work/mem\0",
      "fmmap\0n/tmp/work/mmap\0",
      "fltx\0n/tmp/work/linker-text\0",
      "fM0a\0n/tmp/work/region-lower\0",
      "fMFF\0n/tmp/work/region-upper\0",
      "frtd\0n/\0",
    ].joined().utf8)
  let records = try #require(LsofFieldParser.parse(payload).value)
  #expect(records.count == 9)
  #expect(records.first?.referenceKind == .other)
  #expect(records.filter { $0.referenceKind == .mappedImage }.count == 6)
  #expect(
    Dictionary(uniqueKeysWithValues: records.map { ($0.fileDescriptor ?? "", $0.referenceKind) })
      == [
        "cwd": .currentWorkingDirectory,
        "3u": .openFile,
        "txt": .mappedImage,
        "mem": .mappedImage,
        "mmap": .mappedImage,
        "ltx": .mappedImage,
        "M0a": .mappedImage,
        "MFF": .mappedImage,
        "rtd": .other,
      ])
}

@Test
func processAncestorIndexUsesRawComponentBoundariesAndPreservesTypedFailure() throws {
  let records = [
    ProcessActivityRecord(
      processID: 1,
      command: "open",
      fileDescriptor: "7u",
      rawPath: Data("/tmp/cache/file".utf8)
    ),
    ProcessActivityRecord(
      processID: 2,
      command: "sibling",
      fileDescriptor: "cwd",
      rawPath: Data("/tmp/cache-other".utf8)
    ),
    ProcessActivityRecord(
      processID: 3,
      command: "unclassified",
      fileDescriptor: "rtd",
      rawPath: Data("/tmp/cache/ignored".utf8)
    ),
  ]
  let index = ProcessActivityAncestorIndex(snapshot: .known(records))
  let matches = try #require(index.references(toCandidateAt: Data("/tmp/cache/".utf8)).value)
  #expect(matches.map(\.processID) == [1])
  let mapped = try #require(
    index.referencesByCandidateAncestor(rawAbsolutePaths: [
      Data("/".utf8),
      Data("/tmp".utf8),
      Data("/tmp/cache".utf8),
      Data("/tmp/cache/empty".utf8),
    ]).value
  )
  #expect(mapped[Data("/".utf8)]?.map(\.processID) == [1, 2])
  #expect(mapped[Data("/tmp".utf8)]?.map(\.processID) == [1, 2])
  #expect(mapped[Data("/tmp/cache".utf8)]?.map(\.processID) == [1])
  #expect(mapped[Data("/tmp/cache/empty".utf8)] == [])

  let unreadable = ProcessActivityAncestorIndex(
    snapshot: .unreadable(reason: "visibility denied", errorCode: EACCES)
  ).references(toCandidateAt: Data("/tmp/cache".utf8))
  #expect(unreadable == .unreadable(reason: "visibility denied", errorCode: EACCES))

  #expect(
    ProcessActivityAncestorIndex(snapshot: .known([]))
      .references(toCandidateAt: Data("relative".utf8))
      == .failed(reason: "candidate path is not a canonical absolute raw path", errorCode: EINVAL)
  )
  #expect(
    ProcessActivityAncestorIndex(snapshot: .known([]))
      .references(toCandidateAt: Data("/tmp//cache".utf8))
      == .failed(reason: "candidate path is not a canonical absolute raw path", errorCode: EINVAL)
  )
}

@Test
func boundedLsofCollectorRunsOneNormalizedSnapshotAndParsesIt() async throws {
  let recorder = ProcessInvocationRecorder()
  let runner = RecordingProcessRunner(
    recorder: recorder,
    result: .completed(
      exitStatus: 0,
      standardOutput: Data("p7\0capp\0f4u\0n/tmp/open\0".utf8),
      standardError: .empty
    )
  )
  let collector = BoundedLsofProcessActivityCollector(
    executableURL: URL(fileURLWithPath: "/bin/echo"),
    runner: runner,
    maximumOutputBytes: 123
  )
  guard case .complete(let records) = await collector.collect(deadlineNanoseconds: 456) else {
    Issue.record("expected a complete process snapshot")
    return
  }
  #expect(records.map(\.processID) == [7])
  #expect(recorder.arguments == ["-nP", "-Di", "-F0pcfn"])
  #expect(recorder.environment == BoundedLsofProcessActivityCollector.sanitizedEnvironment)
  #expect(Set(recorder.environment.keys) == ["LANG", "LC_ALL", "PATH"])
  #expect(recorder.environment["HOME"] == nil)
  #expect(recorder.environment["LSOFDEVCACHE"] == nil)
  #expect(recorder.environment["TMPDIR"] == nil)
  #expect(recorder.deadlineNanoseconds == 456)
  #expect(recorder.maximumOutputBytes == 123)
}

@Test
func boundedLsofCollectorKeepsDeadlineLimitAndPermissionFailuresDistinct() async {
  let clean = ProcessSnapshotCleanupReport(residualProcessGroup: false)
  let unknown = ProcessSnapshotCleanupReport(
    processGroupState: .observationFailed(errorCode: EIO)
  )
  let cases: [(ProcessSnapshotExecution, ProcessActivityObservation)] = [
    (
      .deadlineExceeded(cleanup: clean),
      .failed(reason: "bounded lsof process snapshot timed out", errorCode: ETIMEDOUT)
    ),
    (
      .outputLimitExceeded(cleanup: clean),
      .failed(
        reason: "bounded lsof process snapshot exceeded its output limit",
        errorCode: EFBIG
      )
    ),
    (
      .supervisionFailed(reason: "waitpid failed", errorCode: EIO, cleanup: clean),
      .failed(reason: "waitpid failed", errorCode: EIO)
    ),
    (
      .supervisionFailed(reason: "liveness failed", errorCode: EIO, cleanup: unknown),
      .failed(
        reason: "liveness failed; process-group quiescence was not verified",
        errorCode: EIO
      )
    ),
    (
      .launchFailed(
        ProcessLaunchFailure(
          reason: "denied",
          errorDomain: NSPOSIXErrorDomain,
          errorCode: EACCES,
          underlyingPOSIXErrorCode: EACCES
        )),
      .unreadable(reason: "denied", errorCode: EACCES)
    ),
  ]
  for (execution, expected) in cases {
    let collector = BoundedLsofProcessActivityCollector(
      executableURL: URL(fileURLWithPath: "/bin/echo"),
      runner: RecordingProcessRunner(
        recorder: ProcessInvocationRecorder(),
        result: execution
      )
    )
    #expect(await collector.collect(deadlineNanoseconds: 1) == expected)
  }
}

@Test
func successfulLsofWithStandardErrorIsDegradedAndRetainsOnlyPositiveEvidence() async throws {
  let warningByteCount = 5_000
  let collector = BoundedLsofProcessActivityCollector(
    executableURL: URL(fileURLWithPath: "/bin/echo"),
    runner: RecordingProcessRunner(
      recorder: ProcessInvocationRecorder(),
      result: .completed(
        exitStatus: 0,
        standardOutput: Data("p7\0capp\0f4u\0n/tmp/open\0".utf8),
        standardError: ProcessStandardErrorSummary(observedByteCount: warningByteCount)
      )
    )
  )
  guard
    case .degraded(let records, let reason) =
      await collector.collect(deadlineNanoseconds: 456)
  else {
    Issue.record("expected successful lsof diagnostics to degrade coverage")
    return
  }
  #expect(records.map(\.processID) == [7])
  #expect(reason.contains("standard error contained 4096 bytes, truncated"))
  #expect(reason.contains("diagnostic content withheld"))

  let index = ProcessActivityAncestorIndex(
    activity: .degraded(records: records, reason: reason)
  )
  #expect(index.coverage == .incomplete(reason: reason))
  let positive = try #require(index.references(toCandidateAt: Data("/tmp".utf8)).value)
  #expect(positive.map(\.processID) == [7])
  #expect(
    index.references(toCandidateAt: Data("/unobserved".utf8)) == .unknown(reason: reason)
  )
  #expect(
    index.referencesByCandidateAncestor(rawAbsolutePaths: [Data("/tmp".utf8)])
      == .unknown(reason: reason)
  )
}

@Test
func processGroupSpawnerReceivesOnlyTheExplicitSanitizedEnvironment() async {
  let environment = BoundedLsofProcessActivityCollector.sanitizedEnvironment
  let result = await FoundationProcessSnapshotRunner().run(
    executableURL: URL(fileURLWithPath: "/usr/bin/env"),
    arguments: [],
    environment: environment,
    deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 2_000_000_000,
    maximumOutputBytes: 4_096
  )
  guard case .completed(let status, let output, let error) = result else {
    Issue.record("expected the explicit-environment probe to complete")
    return
  }
  #expect(status == 0)
  #expect(error == .empty)
  let lines = Set(
    String(decoding: output, as: UTF8.self).split(whereSeparator: \.isNewline).map(String.init)
  )
  #expect(lines == Set(environment.map { "\($0.key)=\($0.value)" }))
}

@Test
func boundedLsofCollectorLaunchesWithoutAPathPreflightAndClassifiesUnderlyingPOSIXErrors() async {
  let recorder = ProcessInvocationRecorder()
  let missing = NSError(
    domain: NSCocoaErrorDomain,
    code: 4,
    userInfo: [
      NSUnderlyingErrorKey: NSError(domain: NSPOSIXErrorDomain, code: Int(ENOENT))
    ]
  )
  let collector = BoundedLsofProcessActivityCollector(
    executableURL: URL(fileURLWithPath: "/path/that/is/intentionally/not-preflighted"),
    runner: RecordingProcessRunner(
      recorder: recorder,
      result: .launchFailed(ProcessLaunchFailure(error: missing, operation: "launch"))
    )
  )
  guard case .absent(let reason) = await collector.collect(deadlineNanoseconds: 42) else {
    Issue.record("expected underlying ENOENT to classify as absent")
    return
  }
  #expect(reason.hasPrefix("launch:"))
  #expect(recorder.deadlineNanoseconds == 42)

  let unclassified = NSError(domain: NSCocoaErrorDomain, code: 99)
  let failed = BoundedLsofProcessActivityCollector(
    executableURL: URL(fileURLWithPath: "/also-not-preflighted"),
    runner: RecordingProcessRunner(
      recorder: ProcessInvocationRecorder(),
      result: .launchFailed(ProcessLaunchFailure(error: unclassified, operation: "launch"))
    )
  )
  guard case .failed(_, let errorCode) = await failed.collect(deadlineNanoseconds: 43) else {
    Issue.record("expected a typed failed launch observation")
    return
  }
  #expect(errorCode == nil)
}

@Test
func processGroupSupervisorBoundsDescendantHeldEOFAndReportsDeadlineCleanup() async {
  let runner = FoundationProcessSnapshotRunner()
  let result = await runner.run(
    executableURL: URL(fileURLWithPath: "/bin/sh"),
    arguments: ["-c", "(sleep 30) & exit 0"],
    environment: BoundedLsofProcessActivityCollector.sanitizedEnvironment,
    deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 150_000_000,
    maximumOutputBytes: 4_096
  )
  guard case .deadlineExceeded(let cleanup) = result else {
    Issue.record("expected the absolute supervisor deadline to end descendant-held EOF")
    return
  }
  #expect(!cleanup.residualProcessGroup)
}

@Test
func processGroupSupervisorDetectsRedirectedDescendantBeforeLeaderRelease() async throws {
  let fixture = try AnonymousDescendantReadinessFixture()
  defer { fixture.cleanup() }
  let deadlineNanoseconds = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
  let process = try fixture.spawn(mode: .stableDescendant)
  let session = FoundationProcessSnapshotRunner.startSupervision(
    process: process,
    deadlineNanoseconds: deadlineNanoseconds,
    maximumOutputBytes: 4_096
  )
  let readiness = fixture.waitForReadiness(
    deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 1_000_000_000,
    observer: DarwinProcessReadinessObserver()
  )
  guard case .success(let validated) = readiness else {
    session.cancel()
    _ = await session.value()
    Issue.record("redirected-descendant readiness failed: \(readiness.failureDescription)")
    return
  }
  let release = fixture.release(
    validated,
    observer: DarwinProcessReadinessObserver()
  )
  guard case .success = release else {
    session.cancel()
    _ = await session.value()
    Issue.record("redirected-descendant release failed: \(release.failureDescription)")
    return
  }

  let result = await session.value()
  guard case .supervisionFailed(let reason, _, let cleanup) = result else {
    Issue.record(
      "expected the held leader generation to expose its redirected descendant; got \(result)"
    )
    return
  }
  #expect(reason.contains("process group remained active"))
  #expect(cleanup.processGroupState == .quiescent)
}

@Test
func redirectedDescendantReadinessHasABoundedTypedTimeout() throws {
  let fixture = try AnonymousDescendantReadinessFixture()
  defer { fixture.cleanup() }

  let result = fixture.waitForReadiness(
    deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 20_000_000,
    observer: DarwinProcessReadinessObserver()
  )

  #expect(result == .failure(.timeout))
}

@Test
func redirectedDescendantReadinessReportsEarlyExit() async throws {
  let fixture = try AnonymousDescendantReadinessFixture()
  defer { fixture.cleanup() }
  let deadlineNanoseconds = DispatchTime.now().uptimeNanoseconds + 2_000_000_000
  let process = try fixture.spawn(mode: .earlyDescendantExit)
  let session = FoundationProcessSnapshotRunner.startSupervision(
    process: process,
    deadlineNanoseconds: deadlineNanoseconds,
    maximumOutputBytes: 4_096
  )

  let readiness = fixture.waitForReadiness(
    deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 1_000_000_000,
    observer: DarwinProcessReadinessObserver()
  )
  guard case .failure(.earlyDescendantExit) = readiness else {
    session.cancel()
    _ = await session.value()
    Issue.record("expected typed early-descendant-exit readiness failure")
    return
  }
  guard case .completed(let exitStatus, _, _) = await session.value() else {
    Issue.record("expected the early-exit fixture leader to complete")
    return
  }
  #expect(exitStatus == 42)
}

@Test
func redirectedDescendantReadinessRejectsWrongProcessGroup() {
  let leaderPID: Int32 = 100
  let descendantPID: Int32 = 101
  let observer = FixedProcessReadinessObserver(observations: [
    leaderPID: ProcessReadinessIdentity(
      processID: leaderPID,
      processGroupID: leaderPID,
      startTimeSeconds: 10,
      startTimeMicroseconds: 20
    ),
    descendantPID: ProcessReadinessIdentity(
      processID: descendantPID,
      processGroupID: 999,
      startTimeSeconds: 30,
      startTimeMicroseconds: 40
    ),
  ])

  let result = AnonymousDescendantReadinessFixture.validate(
    record: .ready(leaderProcessID: leaderPID, descendantProcessID: descendantPID),
    observer: observer
  )

  #expect(
    result
      == .failure(
        .wrongProcessGroup(
          processID: descendantPID,
          expectedProcessGroupID: leaderPID,
          actualProcessGroupID: 999
        ))
  )
}

@Test
func anonymousReadinessDecoderCoversBothSchedulingPermutations() {
  let record = Data("ready 100 101\n".utf8)
  var childFirst = ReadinessRecordAccumulator()
  let childFirstResult = childFirst.consume(.bytes(record))

  var parentFirst = ReadinessRecordAccumulator()
  guard case .success(nil) = parentFirst.consume(.wouldBlock) else {
    Issue.record("expected a parent-first nonblocking read to remain pending")
    return
  }
  let parentFirstResult = parentFirst.consume(.bytes(record))

  #expect(childFirstResult == parentFirstResult)
  guard case .success(.some(let parsed)) = childFirstResult else {
    Issue.record("expected the buffered readiness record to parse")
    return
  }
  #expect(parsed == .ready(leaderProcessID: 100, descendantProcessID: 101))
}

@Test
func anonymousReadinessChildDescriptorsAvoidSourceCollisions() throws {
  let sourceFileDescriptors: Set<Int32> = [40, 41, 44]

  let childFileDescriptors =
    try AnonymousDescendantReadinessFixture
    .chooseChildFileDescriptors(
      excludingSourceFileDescriptors: sourceFileDescriptors
    )

  #expect(childFileDescriptors == .init(ready: 42, acknowledgement: 43))
  #expect(
    sourceFileDescriptors.isDisjoint(with: [
      childFileDescriptors.ready,
      childFileDescriptors.acknowledgement,
    ]))
}

@Test
func anonymousReadinessPipeReportsEOFWhenUntransferredChildEndCloses() throws {
  let fixture = try AnonymousDescendantReadinessFixture()
  defer { fixture.cleanup() }
  fixture.closeUntransferredChildEndsForTest()

  let result = fixture.waitForReadiness(
    deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 100_000_000,
    observer: DarwinProcessReadinessObserver()
  )

  #expect(result == .failure(.earlyDescendantExit))
}

@Test
func anonymousAcknowledgementPipeReturnsTypedEPIPEWithoutSIGPIPE() throws {
  let fixture = try AnonymousDescendantReadinessFixture()
  defer { fixture.cleanup() }
  fixture.closeUntransferredChildEndsForTest()

  guard case .failure(.io(errorCode: EPIPE)) = fixture.writeAcknowledgementForTest() else {
    Issue.record("expected a typed EPIPE acknowledgement failure")
    return
  }
}

@Test
func inheritedSpawnValidationConsumesEveryTransferredSourceOnFailure() throws {
  var first: [Int32] = [-1, -1]
  var second: [Int32] = [-1, -1]
  try #require(Darwin.pipe(&first) == 0)
  do {
    try #require(Darwin.pipe(&second) == 0)
  } catch {
    Darwin.close(first[0])
    Darwin.close(first[1])
    throw error
  }
  defer {
    Darwin.close(first[0])
    Darwin.close(second[0])
  }
  let transferred = [first[1], second[1]]

  do {
    _ = try POSIXProcessGroupSpawner().spawn(
      executableURL: URL(fileURLWithPath: "/usr/bin/true"),
      arguments: [],
      environment: BoundedLsofProcessActivityCollector.sanitizedEnvironment,
      consumingInheritedFileDescriptors: [
        POSIXSpawnInheritedFileDescriptor(
          sourceFileDescriptor: first[1],
          childFileDescriptor: 40
        ),
        POSIXSpawnInheritedFileDescriptor(
          sourceFileDescriptor: second[1],
          childFileDescriptor: 40
        ),
      ]
    )
    Issue.record("expected duplicate child descriptors to fail before spawn")
  } catch let error as NSError {
    #expect(error.domain == NSPOSIXErrorDomain)
    #expect(error.code == Int(EINVAL))
  }

  for descriptor in transferred {
    errno = 0
    #expect(Darwin.fcntl(descriptor, F_GETFD) == -1)
    #expect(errno == EBADF)
  }
}

@Test
func inheritedSpawnValidationClosesADuplicateSourceOnlyOnce() throws {
  var descriptors: [Int32] = [-1, -1]
  try #require(Darwin.pipe(&descriptors) == 0)
  defer { Darwin.close(descriptors[0]) }

  do {
    _ = try POSIXProcessGroupSpawner().spawn(
      executableURL: URL(fileURLWithPath: "/usr/bin/true"),
      arguments: [],
      environment: BoundedLsofProcessActivityCollector.sanitizedEnvironment,
      consumingInheritedFileDescriptors: [
        POSIXSpawnInheritedFileDescriptor(
          sourceFileDescriptor: descriptors[1],
          childFileDescriptor: 40
        ),
        POSIXSpawnInheritedFileDescriptor(
          sourceFileDescriptor: descriptors[1],
          childFileDescriptor: 41
        ),
      ]
    )
    Issue.record("expected duplicate source descriptors to fail before spawn")
  } catch let error as NSError {
    #expect(error.domain == NSPOSIXErrorDomain)
    #expect(error.code == Int(EINVAL))
  }

  errno = 0
  #expect(Darwin.fcntl(descriptors[1], F_GETFD) == -1)
  #expect(errno == EBADF)
}

@Test
func processGroupSupervisorUsesTheSameBoundedCleanupForCancellation() async throws {
  let runner = FoundationProcessSnapshotRunner()
  let task = Task {
    await runner.run(
      executableURL: URL(fileURLWithPath: "/bin/sh"),
      arguments: ["-c", "sleep 30"],
      environment: BoundedLsofProcessActivityCollector.sanitizedEnvironment,
      deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 5_000_000_000,
      maximumOutputBytes: 4_096
    )
  }
  try await Task.sleep(for: .milliseconds(50))
  task.cancel()
  guard case .cancelled(let cleanup) = await task.value else {
    Issue.record("expected a typed cancellation outcome")
    return
  }
  #expect(!cleanup.residualProcessGroup)
}

@Test
func processGroupSupervisorAppliesTheAggregateOutputLimitToTheWholeGroup() async {
  let runner = FoundationProcessSnapshotRunner()
  let result = await runner.run(
    executableURL: URL(fileURLWithPath: "/usr/bin/yes"),
    arguments: [],
    environment: BoundedLsofProcessActivityCollector.sanitizedEnvironment,
    deadlineNanoseconds: DispatchTime.now().uptimeNanoseconds + 2_000_000_000,
    maximumOutputBytes: 1_024
  )
  guard case .outputLimitExceeded(let cleanup) = result else {
    Issue.record("expected aggregate output-limit cleanup")
    return
  }
  #expect(!cleanup.residualProcessGroup)
}

@Test
func deterministicProcessGroupSupervisorEscalatesAtTheExactGraceDeadline() throws {
  let backend = DeterministicProcessGroupSnapshotBackend(
    nowNanoseconds: 10,
    killBehavior: .becomesQuiescent
  )
  let result = FixtureValueRecorder<ProcessSnapshotExecution>()
  let executionDeadline: UInt64 = 1_000
  let graceDeadline =
    executionDeadline + BoundedProcessGroupSnapshotState.termGraceNanoseconds
  let hardDeadline =
    executionDeadline + BoundedProcessGroupSnapshotState.cleanupAllowanceNanoseconds
  let state = BoundedProcessGroupSnapshotState(
    completion: { result.record($0) },
    backend: backend,
    executionDeadlineNanoseconds: executionDeadline,
    maximumOutputBytes: 4_096
  )

  state.start()
  #expect(backend.scheduledDeadlines == [executionDeadline])
  backend.advance(to: executionDeadline - 1)
  #expect(backend.signalEvents.isEmpty)
  backend.advance(to: executionDeadline)
  #expect(
    backend.signalEvents == [
      .init(timeNanoseconds: executionDeadline, signal: .terminate)
    ]
  )
  #expect(
    backend.scheduledDeadlines == [executionDeadline, graceDeadline, hardDeadline]
  )
  backend.advance(to: graceDeadline - 1)
  #expect(result.value == nil)
  backend.advance(to: graceDeadline)

  #expect(
    backend.signalEvents == [
      .init(timeNanoseconds: executionDeadline, signal: .terminate),
      .init(timeNanoseconds: graceDeadline, signal: .kill),
    ]
  )
  #expect(result.value == nil)
  backend.deliverReaped(status: SIGKILL)
  backend.deliverStandardOutput(Data())
  backend.deliverStandardError(Data())
  #expect(backend.reapedStatuses == [SIGKILL])
  #expect(backend.closeReaderTimes == [graceDeadline])
  guard case .deadlineExceeded(let cleanup) = try #require(result.value) else {
    Issue.record("expected a typed deadline cleanup result")
    return
  }
  #expect(!cleanup.residualProcessGroup)
}

@Test
func deterministicProcessGroupSupervisorKeepsMonotonicTimeForOverdueDeadline() {
  let now: UInt64 = 1_000
  let executionDeadline: UInt64 = 500
  let backend = DeterministicProcessGroupSnapshotBackend(
    nowNanoseconds: now,
    killBehavior: .remainsLive
  )
  let state = BoundedProcessGroupSnapshotState(
    completion: { _ in },
    backend: backend,
    executionDeadlineNanoseconds: executionDeadline,
    maximumOutputBytes: 4_096
  )
  let graceDeadline = now + BoundedProcessGroupSnapshotState.termGraceNanoseconds
  let hardDeadline =
    executionDeadline + BoundedProcessGroupSnapshotState.cleanupAllowanceNanoseconds

  state.start()
  backend.advance(to: now)

  #expect(backend.nowNanoseconds == now)
  #expect(
    backend.signalEvents == [
      .init(timeNanoseconds: now, signal: .terminate)
    ]
  )
  #expect(
    backend.scheduledDeadlines == [executionDeadline, graceDeadline, hardDeadline]
  )
  backend.advance(to: hardDeadline)
}

@Test
func deterministicProcessGroupSupervisorHardFinishesRetainedReaders() throws {
  let start: UInt64 = 2_000
  let backend = DeterministicProcessGroupSnapshotBackend(
    nowNanoseconds: start,
    killBehavior: .becomesQuiescent
  )
  let result = FixtureValueRecorder<ProcessSnapshotExecution>()
  let executionDeadline: UInt64 = 2_000_000_000
  let graceDeadline = start + BoundedProcessGroupSnapshotState.termGraceNanoseconds
  let hardDeadline = start + BoundedProcessGroupSnapshotState.cleanupAllowanceNanoseconds
  let state = BoundedProcessGroupSnapshotState(
    completion: { result.record($0) },
    backend: backend,
    executionDeadlineNanoseconds: executionDeadline,
    maximumOutputBytes: 4_096
  )

  state.start()
  state.requestCancellation()
  backend.advance(to: graceDeadline)
  backend.deliverReaped(status: SIGKILL)
  #expect(result.value == nil)
  #expect(backend.reapedStatuses == [SIGKILL])
  #expect(backend.closeReaderTimes.isEmpty)
  backend.advance(to: hardDeadline - 1)
  #expect(result.value == nil)
  backend.advance(to: hardDeadline)

  #expect(
    backend.signalEvents == [
      .init(timeNanoseconds: start, signal: .terminate),
      .init(timeNanoseconds: graceDeadline, signal: .kill),
    ]
  )
  #expect(backend.closeReaderTimes == [hardDeadline])
  guard case .cancelled(let cleanup) = try #require(result.value) else {
    Issue.record("expected bounded cancellation after the reader hard deadline")
    return
  }
  #expect(!cleanup.residualProcessGroup)
}

@Test
func deterministicProcessGroupSupervisorReportsBoundedResidualGroup() throws {
  let executionDeadline: UInt64 = 3_000
  let backend = DeterministicProcessGroupSnapshotBackend(
    nowNanoseconds: 100,
    killBehavior: .remainsLive
  )
  let result = FixtureValueRecorder<ProcessSnapshotExecution>()
  let graceDeadline =
    executionDeadline + BoundedProcessGroupSnapshotState.termGraceNanoseconds
  let hardDeadline =
    executionDeadline + BoundedProcessGroupSnapshotState.cleanupAllowanceNanoseconds
  let state = BoundedProcessGroupSnapshotState(
    completion: { result.record($0) },
    backend: backend,
    executionDeadlineNanoseconds: executionDeadline,
    maximumOutputBytes: 4_096
  )

  state.start()
  backend.advance(to: hardDeadline)

  #expect(
    backend.signalEvents == [
      .init(timeNanoseconds: executionDeadline, signal: .terminate),
      .init(timeNanoseconds: graceDeadline, signal: .kill),
    ]
  )
  #expect(backend.reapedStatuses.isEmpty)
  #expect(backend.closeReaderTimes == [hardDeadline])
  guard case .deadlineExceeded(let cleanup) = try #require(result.value) else {
    Issue.record("expected a bounded deadline result for a residual group")
    return
  }
  #expect(cleanup.residualProcessGroup)
}

@Test
func deterministicProcessGroupSupervisorProvesDelayedQuiescenceAfterCoalescedTimers() throws {
  let executionDeadline: UInt64 = 1_000
  let backend = DeterministicProcessGroupSnapshotBackend(
    nowNanoseconds: 100,
    killBehavior: .becomesQuiescentAfter(nanoseconds: 50_000_000)
  )
  let result = FixtureValueRecorder<ProcessSnapshotExecution>()
  let graceDeadline =
    executionDeadline + BoundedProcessGroupSnapshotState.termGraceNanoseconds
  let hardDeadline =
    executionDeadline + BoundedProcessGroupSnapshotState.cleanupAllowanceNanoseconds
  let coalescedDelivery = hardDeadline + 1_000_000
  let quiescenceDeadline =
    coalescedDelivery + BoundedProcessGroupSnapshotState.postKillQuiescenceNanoseconds
  let state = BoundedProcessGroupSnapshotState(
    completion: { result.record($0) },
    backend: backend,
    executionDeadlineNanoseconds: executionDeadline,
    maximumOutputBytes: 4_096
  )

  state.start()
  backend.deliverTimer(deadlineNanoseconds: executionDeadline, at: executionDeadline)
  backend.deliverTimer(deadlineNanoseconds: graceDeadline, at: coalescedDelivery)
  backend.deliverReaped(status: SIGKILL)
  backend.deliverStandardOutput(Data())
  backend.deliverStandardError(Data())
  backend.deliverTimer(deadlineNanoseconds: hardDeadline, at: coalescedDelivery)

  #expect(result.value == nil)
  #expect(backend.scheduledDeadlines.contains(quiescenceDeadline))
  backend.advance(to: quiescenceDeadline)

  #expect(
    backend.signalEvents == [
      .init(timeNanoseconds: executionDeadline, signal: .terminate),
      .init(timeNanoseconds: coalescedDelivery, signal: .kill),
    ]
  )
  #expect(backend.closeReaderTimes == [quiescenceDeadline])
  guard case .deadlineExceeded(let cleanup) = try #require(result.value) else {
    Issue.record("expected delayed group disappearance to complete within the bounded proof window")
    return
  }
  #expect(!cleanup.residualProcessGroup)
}

@Test
func deterministicProcessGroupSupervisorPreservesLivenessFailureAfterCancellationWins() throws {
  let start: UInt64 = 4_000
  let backend = DeterministicProcessGroupSnapshotBackend(
    nowNanoseconds: start,
    killBehavior: .remainsLive
  )
  let result = FixtureValueRecorder<ProcessSnapshotExecution>()
  let hardDeadline = start + BoundedProcessGroupSnapshotState.cleanupAllowanceNanoseconds
  let state = BoundedProcessGroupSnapshotState(
    completion: { result.record($0) },
    backend: backend,
    executionDeadlineNanoseconds: 2_000_000_000,
    maximumOutputBytes: 4_096
  )

  state.start()
  state.requestCancellation()
  backend.setLivenessFailureCode(EIO)
  backend.deliverReaped(status: 0)
  backend.deliverStandardOutput(Data())
  backend.deliverStandardError(Data())
  backend.setLivenessFailureCode(nil)
  backend.setGroupIsLive(false)
  backend.advance(to: hardDeadline)

  guard
    case .supervisionFailed(let reason, let errorCode, let cleanup) =
      try #require(result.value)
  else {
    Issue.record("expected the first liveness failure to remain authoritative")
    return
  }
  #expect(reason.contains("liveness check failed"))
  #expect(errorCode == EIO)
  #expect(cleanup.processGroupState == .quiescent)
}

@Test
func deterministicProcessGroupSupervisorPreservesLivenessFailureAfterDeadlineWins() throws {
  let executionDeadline: UInt64 = 6_000
  let backend = DeterministicProcessGroupSnapshotBackend(
    nowNanoseconds: 100,
    killBehavior: .remainsLive
  )
  let result = FixtureValueRecorder<ProcessSnapshotExecution>()
  let hardDeadline =
    executionDeadline + BoundedProcessGroupSnapshotState.cleanupAllowanceNanoseconds
  let state = BoundedProcessGroupSnapshotState(
    completion: { result.record($0) },
    backend: backend,
    executionDeadlineNanoseconds: executionDeadline,
    maximumOutputBytes: 4_096
  )

  state.start()
  backend.advance(to: executionDeadline)
  backend.setLivenessFailureCode(EIO)
  backend.deliverReaped(status: 0)
  backend.deliverStandardOutput(Data())
  backend.deliverStandardError(Data())
  backend.setLivenessFailureCode(nil)
  backend.setGroupIsLive(false)
  backend.advance(to: hardDeadline)

  guard
    case .supervisionFailed(let reason, let errorCode, let cleanup) =
      try #require(result.value)
  else {
    Issue.record("expected deadline cleanup to retain the observed liveness failure")
    return
  }
  #expect(reason.contains("liveness check failed"))
  #expect(errorCode == EIO)
  #expect(cleanup.processGroupState == .quiescent)
}

@Test
func deterministicProcessGroupSupervisorKeepsFailedQuiescenceUnknown() throws {
  let executionDeadline: UInt64 = 5_000
  let backend = DeterministicProcessGroupSnapshotBackend(
    nowNanoseconds: 100,
    killBehavior: .remainsLive
  )
  let result = FixtureValueRecorder<ProcessSnapshotExecution>()
  let graceDeadline =
    executionDeadline + BoundedProcessGroupSnapshotState.termGraceNanoseconds
  let hardDeadline =
    executionDeadline + BoundedProcessGroupSnapshotState.cleanupAllowanceNanoseconds
  let state = BoundedProcessGroupSnapshotState(
    completion: { result.record($0) },
    backend: backend,
    executionDeadlineNanoseconds: executionDeadline,
    maximumOutputBytes: 4_096
  )

  state.start()
  backend.advance(to: graceDeadline)
  backend.setLivenessFailureCode(EINVAL)
  backend.advance(to: hardDeadline)

  guard
    case .supervisionFailed(let reason, let errorCode, let cleanup) =
      try #require(result.value)
  else {
    Issue.record("expected a typed liveness observation failure")
    return
  }
  #expect(reason.contains("liveness check failed"))
  #expect(errorCode == EINVAL)
  #expect(cleanup.processGroupState == .observationFailed(errorCode: EINVAL))
  #expect(!cleanup.residualProcessGroup)
}

@Test
func deterministicProcessGroupSupervisorIgnoresLateTimersAfterTerminalClaim() throws {
  let start: UInt64 = 7_000
  let executionDeadline: UInt64 = 2_000_000_000
  let backend = DeterministicProcessGroupSnapshotBackend(
    nowNanoseconds: start,
    killBehavior: .becomesQuiescent
  )
  let result = FixtureValueRecorder<ProcessSnapshotExecution>()
  let graceDeadline = start + BoundedProcessGroupSnapshotState.termGraceNanoseconds
  let hardDeadline = start + BoundedProcessGroupSnapshotState.cleanupAllowanceNanoseconds
  let state = BoundedProcessGroupSnapshotState(
    completion: { result.record($0) },
    backend: backend,
    executionDeadlineNanoseconds: executionDeadline,
    maximumOutputBytes: 4_096
  )

  state.start()
  state.requestCancellation()
  backend.setGroupIsLive(false)
  backend.deliverReaped(status: 0)
  backend.deliverStandardOutput(Data())
  backend.deliverStandardError(Data())
  guard case .cancelled(let cleanup) = try #require(result.value) else {
    Issue.record("expected TERM convergence to finish cancellation")
    return
  }
  #expect(!cleanup.residualProcessGroup)
  #expect(
    backend.signalEvents == [
      .init(timeNanoseconds: start, signal: .terminate)
    ]
  )

  backend.deliverCancelledTimer(
    deadlineNanoseconds: graceDeadline,
    at: graceDeadline + 1
  )
  backend.deliverCancelledTimer(
    deadlineNanoseconds: hardDeadline,
    at: hardDeadline + 1
  )
  #expect(
    backend.signalEvents == [
      .init(timeNanoseconds: start, signal: .terminate)
    ]
  )
}

@Test
func deterministicProcessGroupSupervisorIgnoresLateDeadlineAfterNormalCompletion() throws {
  let start: UInt64 = 11_000
  let executionDeadline: UInt64 = 1_000_000
  let backend = DeterministicProcessGroupSnapshotBackend(
    nowNanoseconds: start,
    initialGroupIsLive: false,
    killBehavior: .remainsLive
  )
  let result = FixtureValueRecorder<ProcessSnapshotExecution>()
  let state = BoundedProcessGroupSnapshotState(
    completion: { result.record($0) },
    backend: backend,
    executionDeadlineNanoseconds: executionDeadline,
    maximumOutputBytes: 4_096
  )

  state.start()
  backend.deliverReaped(status: 0)
  backend.deliverStandardOutput(Data("complete".utf8))
  backend.deliverStandardOutput(Data())
  backend.deliverStandardError(Data())
  guard case .completed(let status, let output, _) = try #require(result.value) else {
    Issue.record("expected normal completion before the execution deadline")
    return
  }
  #expect(status == 0)
  #expect(output == Data("complete".utf8))

  backend.deliverCancelledTimer(
    deadlineNanoseconds: executionDeadline,
    at: executionDeadline + 1
  )
  #expect(backend.signalEvents.isEmpty)
}

@Test
func deterministicProcessGroupSupervisorClassifiesUnexpectedResidualDescendant() throws {
  let start: UInt64 = 13_000
  let executionDeadline: UInt64 = 3_000_000_000
  let backend = DeterministicProcessGroupSnapshotBackend(
    nowNanoseconds: start,
    killBehavior: .remainsLive
  )
  let result = FixtureValueRecorder<ProcessSnapshotExecution>()
  let graceDeadline = start + BoundedProcessGroupSnapshotState.termGraceNanoseconds
  let hardDeadline = start + BoundedProcessGroupSnapshotState.cleanupAllowanceNanoseconds
  let state = BoundedProcessGroupSnapshotState(
    completion: { result.record($0) },
    backend: backend,
    executionDeadlineNanoseconds: executionDeadline,
    maximumOutputBytes: 4_096
  )

  state.start()
  backend.deliverReaped(status: 0)
  backend.deliverStandardOutput(Data())
  backend.deliverStandardError(Data())
  #expect(result.value == nil)
  #expect(
    backend.signalEvents == [
      .init(timeNanoseconds: start, signal: .terminate)
    ]
  )
  backend.advance(to: hardDeadline)

  #expect(
    backend.signalEvents == [
      .init(timeNanoseconds: start, signal: .terminate),
      .init(timeNanoseconds: graceDeadline, signal: .kill),
    ]
  )
  guard
    case .supervisionFailed(let reason, let errorCode, let cleanup) =
      try #require(result.value)
  else {
    Issue.record("expected typed unexpected-residual supervision failure")
    return
  }
  #expect(reason.contains("process group remained active"))
  #expect(errorCode == nil)
  #expect(cleanup.residualProcessGroup)
  #expect(backend.closeReaderTimes == [hardDeadline])
}

@Test
func deterministicProcessGroupSupervisorPreservesWaitpidFailure() throws {
  let start: UInt64 = 17_000
  let backend = DeterministicProcessGroupSnapshotBackend(
    nowNanoseconds: start,
    initialGroupIsLive: false,
    killBehavior: .remainsLive
  )
  let result = FixtureValueRecorder<ProcessSnapshotExecution>()
  let state = BoundedProcessGroupSnapshotState(
    completion: { result.record($0) },
    backend: backend,
    executionDeadlineNanoseconds: 4_000_000_000,
    maximumOutputBytes: 4_096
  )

  state.start()
  backend.deliverReapFailure(errorCode: ECHILD)
  backend.deliverStandardOutput(Data())
  backend.deliverStandardError(Data())

  guard
    case .supervisionFailed(let reason, let errorCode, let cleanup) =
      try #require(result.value)
  else {
    Issue.record("expected a typed waitpid supervision failure")
    return
  }
  #expect(reason.contains("waitpid failed"))
  #expect(errorCode == ECHILD)
  #expect(!cleanup.residualProcessGroup)
  #expect(
    backend.signalEvents == [
      .init(timeNanoseconds: start, signal: .terminate)
    ]
  )
  #expect(backend.closeReaderTimes == [start])
}

@Test
func posixReapBridgeKeepsWaitpidErrorsSeparateFromExitStatus() {
  #expect(
    POSIXProcessGroupSnapshotBackend.classifyWaitIDResult(
      processID: 42,
      waitIDResult: -1,
      observedProcessID: 0,
      observedStatus: 0,
      errorCode: ECHILD
    ) == .failed(errorCode: ECHILD)
  )
  #expect(
    POSIXProcessGroupSnapshotBackend.classifyWaitIDResult(
      processID: 42,
      waitIDResult: 0,
      observedProcessID: 42,
      observedStatus: 7,
      errorCode: 0
    ) == .reaped(exitStatus: 7)
  )
}

@Test
func posixGroupLivenessBridgeKeepsAbsentPermissionAndFailureDistinct() {
  #expect(
    POSIXProcessGroupSnapshotBackend.classifyGroupLiveness(
      killResult: -1,
      errorCode: ESRCH
    ) == .absent
  )
  #expect(
    POSIXProcessGroupSnapshotBackend.classifyGroupLiveness(
      killResult: -1,
      errorCode: EPERM
    ) == .live
  )
  #expect(
    POSIXProcessGroupSnapshotBackend.classifyGroupLiveness(
      killResult: -1,
      errorCode: EINVAL
    ) == .failed(errorCode: EINVAL)
  )
  #expect(
    POSIXProcessGroupSnapshotBackend.groupMemberBufferPlan(
      requiredPIDCount: 100,
      errorCode: 0
    ) == .allocate(pidCount: 164)
  )
  #expect(
    POSIXProcessGroupSnapshotBackend.groupMemberBufferPlan(
      requiredPIDCount: 0,
      errorCode: EIO
    ) == .failed(errorCode: EIO)
  )
  #expect(
    POSIXProcessGroupSnapshotBackend.classifyGroupMembers(
      [],
      returnedCount: 0,
      bufferPIDCount: 64,
      errorCode: EIO,
      leaderProcessID: 42
    ) == .failed(errorCode: EIO)
  )
  #expect(
    POSIXProcessGroupSnapshotBackend.classifyGroupMembers(
      [42, 99],
      returnedCount: 2,
      bufferPIDCount: 64,
      errorCode: 0,
      leaderProcessID: 42
    ) == .live
  )
  #expect(
    POSIXProcessGroupSnapshotBackend.classifyGroupMembers(
      [42],
      returnedCount: 1,
      bufferPIDCount: 64,
      errorCode: 0,
      leaderProcessID: 42
    ) == .absent
  )
}

@Test
func productionRunnerRejectsExpiredDeadlineBeforeSpawn() async {
  let result = await FoundationProcessSnapshotRunner().run(
    executableURL: URL(fileURLWithPath: "/path/that/must-not-be-spawned"),
    arguments: [],
    environment: BoundedLsofProcessActivityCollector.sanitizedEnvironment,
    deadlineNanoseconds: 0,
    maximumOutputBytes: 4_096
  )
  guard case .deadlineExceeded(let cleanup) = result else {
    Issue.record("expected an expired deadline to reject launch")
    return
  }
  #expect(!cleanup.residualProcessGroup)
}

@Test
func productionSpawnerPreservesRealENOENTAndNonExecutablePOSIXLaunchErrors() async throws {
  let root = try makeTaskScopedTemporaryDirectory(label: "spawn-errors")
  defer { try? FileManager.default.removeItem(at: root) }
  let environment = BoundedLsofProcessActivityCollector.sanitizedEnvironment
  let deadline = DispatchTime.now().uptimeNanoseconds + 2_000_000_000

  let missing = await FoundationProcessSnapshotRunner().run(
    executableURL: root.appendingPathComponent("missing-executable"),
    arguments: [],
    environment: environment,
    deadlineNanoseconds: deadline,
    maximumOutputBytes: 4_096
  )
  guard case .launchFailed(let missingFailure) = missing else {
    Issue.record("expected real posix_spawn ENOENT")
    return
  }
  #expect(missingFailure.errorDomain == NSPOSIXErrorDomain)
  #expect(missingFailure.errorCode == ENOENT)
  #expect(missingFailure.underlyingPOSIXErrorCode == ENOENT)

  let nonExecutable = root.appendingPathComponent("not-executable")
  try Data("not an executable".utf8).write(to: nonExecutable, options: .atomic)
  try FileManager.default.setAttributes(
    [.posixPermissions: 0o600],
    ofItemAtPath: nonExecutable.path
  )
  let denied = await FoundationProcessSnapshotRunner().run(
    executableURL: nonExecutable,
    arguments: [],
    environment: environment,
    deadlineNanoseconds: deadline,
    maximumOutputBytes: 4_096
  )
  guard case .launchFailed(let deniedFailure) = denied else {
    Issue.record("expected a real non-executable posix_spawn failure")
    return
  }
  #expect(deniedFailure.errorDomain == NSPOSIXErrorDomain)
  #expect(deniedFailure.errorCode == EACCES || deniedFailure.errorCode == EPERM)
  #expect(deniedFailure.underlyingPOSIXErrorCode == deniedFailure.errorCode)
}

@Test
func publicVMCollectorUsesExactPageAccountingAndRejectsOverflow() throws {
  let sample = VMStatisticsSample(
    pageSize: 4_096,
    freePages: 1,
    activePages: 2,
    inactivePages: 3,
    wiredPages: 4,
    speculativePages: 5,
    compressedPages: 6,
    purgeablePages: 7
  )
  let facts = try #require(
    PublicVMGlobalFactCollector(provider: FixedVMProvider(result: .known(sample)))
      .collect().value
  )
  #expect(facts["page_size_bytes"] == 4_096)
  #expect(facts["active_bytes"] == 8_192)
  #expect(facts["compressed_bytes"] == 24_576)

  let overflow = VMStatisticsSample(
    pageSize: 2,
    freePages: UInt64.max,
    activePages: 0,
    inactivePages: 0,
    wiredPages: 0,
    speculativePages: 0,
    compressedPages: 0,
    purgeablePages: 0
  )
  #expect(
    PublicVMGlobalFactCollector(provider: FixedVMProvider(result: .known(overflow))).collect()
      == .failed(reason: "VM byte count overflow", errorCode: EOVERFLOW)
  )
}

@Test
func publicSwapCollectorPreservesUnavailableAndUnreadableStates() throws {
  let known = try #require(
    PublicSwapGlobalFactCollector(
      provider: FixedSwapProvider(
        result: .known(
          SwapUsageSample(
            totalBytes: 9,
            usedBytes: 4,
            availableBytes: 5,
            encrypted: true
          )))
    ).collect().value
  )
  #expect(known == ["total_bytes": 9, "used_bytes": 4, "available_bytes": 5, "encrypted": 1])

  let unreadable: Observation<SwapUsageSample> = .unreadable(
    reason: "sysctl denied",
    errorCode: EPERM
  )
  #expect(
    PublicSwapGlobalFactCollector(provider: FixedSwapProvider(result: unreadable)).collect()
      == .unreadable(reason: "sysctl denied", errorCode: EPERM)
  )
}

@Test
func snapshotAttributeParserRetainsRawNamesAndRejectsMalformedBounds() throws {
  let rawName = Data([0x66, 0x80])
  let record = snapshotRecord(name: rawName)
  let parsed = try #require(SnapshotAttributeBufferParser.parse(record, entryCount: 1).value)
  #expect(parsed == [rawName])

  var malformed = record
  malformed.storeUInt32(4_096, at: 28)
  #expect(
    SnapshotAttributeBufferParser.parse(malformed, entryCount: 1)
      == .failed(reason: "snapshot name attribute has invalid bounds", errorCode: EPROTO)
  )
}

@Test
func productionBundleIsInjectableCanonicalAndKeepsPerVolumeCoverage() async throws {
  let process = RecordingActivityCollector(result: .unknown(reason: "process visibility unknown"))
  let snapshots = RecordingSnapshotLister(results: [
    10: .known([Data("z".utf8), Data("a".utf8)]),
    11: .unreadable(reason: "snapshot entitlement denied", errorCode: EPERM),
  ])
  let bundle = ProductionScanCollectorBundle(
    processActivity: process,
    vm: FixedVMFactCollector(result: .known(["free_bytes": 1])),
    swap: FixedSwapFactCollector(result: .absent(reason: "swap disabled")),
    snapshots: snapshots,
    maximumSnapshotEntriesPerVolume: 8
  )
  let result = await bundle.collect(
    processDeadlineNanoseconds: 99,
    volumes: [
      RuntimeVolumeDescriptor(volumeID: "b", fileDescriptor: 11),
      RuntimeVolumeDescriptor(volumeID: "a", fileDescriptor: 10),
    ]
  )
  #expect(result.processActivity == .unknown(reason: "process visibility unknown"))
  #expect(result.globalFacts.vm == .known(["free_bytes": 1]))
  #expect(result.globalFacts.swap == .absent(reason: "swap disabled"))
  #expect(
    result.globalFacts.apfsSnapshotsByVolume["a"] == .known([Data("a".utf8), Data("z".utf8)]))
  #expect(
    result.globalFacts.apfsSnapshotsByVolume["b"]
      == .unreadable(reason: "snapshot entitlement denied", errorCode: EPERM)
  )
  #expect(process.deadlines == [99])
  #expect(snapshots.descriptors == [10, 11])
  #expect(
    bundle.collectorConfiguration(processDeadlineNanoseconds: 99).globalFactCollectorIDs.count == 3)
}

private final class ProcessInvocationRecorder: @unchecked Sendable {
  private let lock = NSLock()
  private var storage:
    (arguments: [String], environment: [String: String], deadline: UInt64, limit: Int)?

  var arguments: [String] { lock.withLock { storage?.arguments ?? [] } }
  var environment: [String: String] { lock.withLock { storage?.environment ?? [:] } }
  var deadlineNanoseconds: UInt64? { lock.withLock { storage?.deadline } }
  var maximumOutputBytes: Int? { lock.withLock { storage?.limit } }

  func record(
    arguments: [String],
    environment: [String: String],
    deadline: UInt64,
    limit: Int
  ) {
    lock.withLock { storage = (arguments, environment, deadline, limit) }
  }
}

private struct RecordingProcessRunner: ProcessSnapshotRunning {
  let recorder: ProcessInvocationRecorder
  let result: ProcessSnapshotExecution

  func run(
    executableURL: URL,
    arguments: [String],
    environment: [String: String],
    deadlineNanoseconds: UInt64,
    maximumOutputBytes: Int
  ) async -> ProcessSnapshotExecution {
    recorder.record(
      arguments: arguments,
      environment: environment,
      deadline: deadlineNanoseconds,
      limit: maximumOutputBytes
    )
    return result
  }
}

private struct FixedVMProvider: VMStatisticsProviding {
  let result: Observation<VMStatisticsSample>
  func read() -> Observation<VMStatisticsSample> { result }
}

private struct FixedSwapProvider: SwapUsageProviding {
  let result: Observation<SwapUsageSample>
  func read() -> Observation<SwapUsageSample> { result }
}

private final class RecordingActivityCollector: ProcessActivityCollecting, @unchecked Sendable {
  private let lock = NSLock()
  private let result: ProcessActivityObservation
  private var storage: [UInt64] = []

  init(result: ProcessActivityObservation) { self.result = result }

  var deadlines: [UInt64] { lock.withLock { storage } }

  func collect(deadlineNanoseconds: UInt64) async -> ProcessActivityObservation {
    lock.withLock { storage.append(deadlineNanoseconds) }
    return result
  }
}

private struct FixedVMFactCollector: VMGlobalFactCollecting {
  let result: Observation<[String: UInt64]>
  func collect() -> Observation<[String: UInt64]> { result }
}

private struct FixedSwapFactCollector: SwapGlobalFactCollecting {
  let result: Observation<[String: UInt64]>
  func collect() -> Observation<[String: UInt64]> { result }
}

private final class RecordingSnapshotLister: APFSSnapshotListing, @unchecked Sendable {
  private let lock = NSLock()
  private let results: [Int32: Observation<[Data]>]
  private var storage: [Int32] = []

  init(results: [Int32: Observation<[Data]>]) { self.results = results }

  var descriptors: [Int32] { lock.withLock { storage } }

  func list(volumeFileDescriptor: Int32, maximumEntries: Int) -> Observation<[Data]> {
    lock.withLock { storage.append(volumeFileDescriptor) }
    return results[volumeFileDescriptor] ?? .absent(reason: "volume not configured")
  }
}

private func snapshotRecord(name: Data) -> Data {
  var record = Data(repeating: 0, count: 32 + name.count + 1)
  record.storeUInt32(UInt32(record.count), at: 0)
  record.storeUInt32(UInt32(ATTR_CMN_RETURNED_ATTRS) | UInt32(ATTR_CMN_NAME), at: 4)
  record.storeUInt32(8, at: 24)
  record.storeUInt32(UInt32(name.count + 1), at: 28)
  record.replaceSubrange(32..<(32 + name.count), with: name)
  return record
}

extension Data {
  fileprivate mutating func storeUInt32(_ value: UInt32, at offset: Int) {
    var littleEndian = value.littleEndian
    Swift.withUnsafeBytes(of: &littleEndian) { bytes in
      replaceSubrange(offset..<(offset + 4), with: bytes)
    }
  }
}

private final class FixtureValueRecorder<Value: Sendable>: @unchecked Sendable {
  private let lock = NSLock()
  private var storage: Value?

  func record(_ value: Value) {
    lock.withLock { storage = value }
  }

  var value: Value? {
    lock.withLock { storage }
  }
}

private final class DeterministicProcessGroupSnapshotBackend: ProcessGroupSnapshotBackend,
  @unchecked Sendable
{
  struct SignalEvent: Equatable {
    let timeNanoseconds: UInt64
    let signal: ProcessGroupSnapshotSignal
  }

  enum KillBehavior {
    case becomesQuiescent
    case becomesQuiescentAfter(nanoseconds: UInt64)
    case remainsLive
  }

  private(set) var nowNanoseconds: UInt64
  private(set) var signalEvents: [SignalEvent] = []
  private(set) var reapedStatuses: [Int32] = []
  private(set) var closeReaderTimes: [UInt64] = []
  private(set) var releaseIdentityTimes: [UInt64] = []
  private var groupIsLive: Bool
  private var readersAreClosed = false
  private var standardOutputHandler: (@Sendable (Data) -> Void)?
  private var standardErrorHandler: (@Sendable (Data) -> Void)?
  private var reapHandler: (@Sendable (ProcessGroupSnapshotReapOutcome) -> Void)?
  private var timers: [DeterministicProcessGroupSnapshotTimer] = []
  private let killBehavior: KillBehavior
  private var groupQuiescenceDeadline: UInt64?
  private var livenessFailureCode: Int32?

  init(
    nowNanoseconds: UInt64,
    initialGroupIsLive: Bool = true,
    killBehavior: KillBehavior
  ) {
    self.nowNanoseconds = nowNanoseconds
    groupIsLive = initialGroupIsLive
    self.killBehavior = killBehavior
  }

  var scheduledDeadlines: [UInt64] {
    timers.map(\.deadlineNanoseconds)
  }

  func startReading(
    standardOutput: @escaping @Sendable (Data) -> Void,
    standardError: @escaping @Sendable (Data) -> Void
  ) {
    standardOutputHandler = standardOutput
    standardErrorHandler = standardError
  }

  func startReaping(
    _ completion: @escaping @Sendable (ProcessGroupSnapshotReapOutcome) -> Void
  ) {
    reapHandler = completion
  }

  func makeTimer(
    deadlineNanoseconds: UInt64,
    handler: @escaping @Sendable () -> Void
  ) -> any ProcessGroupSnapshotTimer {
    let timer = DeterministicProcessGroupSnapshotTimer(
      deadlineNanoseconds: deadlineNanoseconds,
      handler: handler
    )
    timers.append(timer)
    return timer
  }

  func signalProcessGroup(_ signal: ProcessGroupSnapshotSignal) {
    signalEvents.append(.init(timeNanoseconds: nowNanoseconds, signal: signal))
    guard signal == .kill, groupIsLive else { return }
    switch killBehavior {
    case .becomesQuiescent:
      groupIsLive = false
    case .becomesQuiescentAfter(let delay):
      groupQuiescenceDeadline = nowNanoseconds + delay
    case .remainsLive:
      return
    }
  }

  func processGroupLiveness() -> ProcessGroupSnapshotLiveness {
    if let livenessFailureCode { return .failed(errorCode: livenessFailureCode) }
    if let deadline = groupQuiescenceDeadline, nowNanoseconds >= deadline {
      groupIsLive = false
      groupQuiescenceDeadline = nil
    }
    return groupIsLive ? .live : .absent
  }

  func closeReaders() {
    guard !readersAreClosed else { return }
    readersAreClosed = true
    closeReaderTimes.append(nowNanoseconds)
  }

  func releaseProcessGroupIdentity() {
    releaseIdentityTimes.append(nowNanoseconds)
  }

  func setGroupIsLive(_ isLive: Bool) {
    groupIsLive = isLive
    groupQuiescenceDeadline = nil
  }

  func setLivenessFailureCode(_ errorCode: Int32?) {
    livenessFailureCode = errorCode
  }

  func deliverReaped(status: Int32) {
    reapedStatuses.append(status)
    reapHandler?(.reaped(exitStatus: status))
  }

  func deliverReapFailure(errorCode: Int32) {
    reapHandler?(.failed(errorCode: errorCode))
  }

  func deliverStandardOutput(_ data: Data) {
    standardOutputHandler?(data)
  }

  func deliverStandardError(_ data: Data) {
    standardErrorHandler?(data)
  }

  func advance(to targetNanoseconds: UInt64) {
    precondition(targetNanoseconds >= nowNanoseconds)
    while let timer =
      timers
      .filter({ $0.shouldFire(noLaterThan: targetNanoseconds) })
      .min(by: { $0.deadlineNanoseconds < $1.deadlineNanoseconds })
    {
      nowNanoseconds = max(nowNanoseconds, timer.deadlineNanoseconds)
      timer.fire()
    }
    nowNanoseconds = targetNanoseconds
  }

  func deliverCancelledTimer(deadlineNanoseconds: UInt64, at deliveryNanoseconds: UInt64) {
    precondition(deliveryNanoseconds >= nowNanoseconds)
    guard let timer = timers.first(where: { $0.deadlineNanoseconds == deadlineNanoseconds }) else {
      Issue.record("deterministic timer was not scheduled")
      return
    }
    nowNanoseconds = deliveryNanoseconds
    timer.deliverEvenIfCancelled()
  }

  func deliverTimer(deadlineNanoseconds: UInt64, at deliveryNanoseconds: UInt64) {
    precondition(deliveryNanoseconds >= nowNanoseconds)
    guard let timer = timers.first(where: { $0.deadlineNanoseconds == deadlineNanoseconds }) else {
      Issue.record("deterministic timer was not scheduled")
      return
    }
    nowNanoseconds = deliveryNanoseconds
    timer.fire()
  }
}

private final class DeterministicProcessGroupSnapshotTimer: ProcessGroupSnapshotTimer,
  @unchecked Sendable
{
  let deadlineNanoseconds: UInt64
  private let handler: @Sendable () -> Void
  private var isActive = false
  private var isCancelled = false
  private var hasFired = false

  init(deadlineNanoseconds: UInt64, handler: @escaping @Sendable () -> Void) {
    self.deadlineNanoseconds = deadlineNanoseconds
    self.handler = handler
  }

  func activate() {
    isActive = true
  }

  func cancel() {
    isCancelled = true
  }

  func shouldFire(noLaterThan deadline: UInt64) -> Bool {
    isActive && !isCancelled && !hasFired && deadlineNanoseconds <= deadline
  }

  func fire() {
    guard isActive, !isCancelled, !hasFired else { return }
    hasFired = true
    handler()
  }

  func deliverEvenIfCancelled() {
    guard isActive, !hasFired else { return }
    hasFired = true
    handler()
  }
}

private enum RedirectedDescendantFixtureMode {
  case stableDescendant
  case earlyDescendantExit

  fileprivate func shellScript(
    childReadyFileDescriptor: Int32,
    childAcknowledgementFileDescriptor: Int32
  ) -> String {
    switch self {
    case .stableDescendant:
      return """
        leader=$$
        (
          exec /bin/sh -c '
            leader=$1
            exec </dev/null >/dev/null 2>/dev/null
            printf "ready %s %s\\n" "$leader" "$$" >&\(childReadyFileDescriptor) || exit 91
            exec \(childReadyFileDescriptor)>&-
            IFS= read -r token <&\(childAcknowledgementFileDescriptor) || exit 92
            [ "$token" = go ] || exit 93
            kill -KILL "$leader" || exit 94
            IFS= read -r unexpected <&\(childAcknowledgementFileDescriptor)
            exit 95
          ' diskplan-descendant "$leader"
        ) &
        child=$!
        exec \(childReadyFileDescriptor)>&-
        exec \(childAcknowledgementFileDescriptor)<&-
        wait "$child"
        exit $?
        """
    case .earlyDescendantExit:
      return """
        (
          exec /bin/sh -c '
            exec </dev/null >/dev/null 2>/dev/null
            exec \(childReadyFileDescriptor)>&-
            exec \(childAcknowledgementFileDescriptor)<&-
            exit 42
          ' diskplan-descendant
        ) &
        child=$!
        exec \(childReadyFileDescriptor)>&-
        exec \(childAcknowledgementFileDescriptor)<&-
        wait "$child"
        status=$?
        exit "$status"
        """
    }
  }
}

private enum RedirectedDescendantReadinessRecord: Equatable, Sendable {
  case ready(leaderProcessID: Int32, descendantProcessID: Int32)
}

private struct ProcessReadinessIdentity: Equatable, Sendable {
  let processID: Int32
  let processGroupID: Int32
  let startTimeSeconds: UInt64
  let startTimeMicroseconds: UInt64
}

private struct ValidatedRedirectedDescendantReadiness: Equatable, Sendable {
  let record: RedirectedDescendantReadinessRecord
  let leaderIdentity: ProcessReadinessIdentity
  let descendantIdentity: ProcessReadinessIdentity
}

private enum RedirectedDescendantReadinessFailure: Error, Equatable {
  case timeout
  case malformedRecord
  case earlyDescendantExit
  case observationFailed(processID: Int32, errorCode: Int32)
  case identityChanged(processID: Int32)
  case wrongProcessGroup(
    processID: Int32,
    expectedProcessGroupID: Int32,
    actualProcessGroupID: Int32
  )
  case io(errorCode: Int32)
}

private protocol ProcessReadinessObserving: Sendable {
  func observe(processID: Int32) -> Result<
    ProcessReadinessIdentity, RedirectedDescendantReadinessFailure
  >
}

private struct DarwinProcessReadinessObserver: ProcessReadinessObserving {
  func observe(
    processID: Int32
  ) -> Result<ProcessReadinessIdentity, RedirectedDescendantReadinessFailure> {
    var information = proc_bsdinfo()
    errno = 0
    let expectedSize = MemoryLayout<proc_bsdinfo>.size
    let returnedSize = proc_pidinfo(
      processID,
      PROC_PIDTBSDINFO,
      0,
      &information,
      Int32(expectedSize)
    )
    guard Int(returnedSize) == expectedSize, information.pbi_pid == UInt32(processID) else {
      return .failure(
        .observationFailed(
          processID: processID,
          errorCode: errno == 0 ? ESRCH : errno
        ))
    }
    return .success(
      ProcessReadinessIdentity(
        processID: processID,
        processGroupID: Int32(bitPattern: information.pbi_pgid),
        startTimeSeconds: information.pbi_start_tvsec,
        startTimeMicroseconds: information.pbi_start_tvusec
      ))
  }
}

private struct FixedProcessReadinessObserver: ProcessReadinessObserving {
  let observations: [Int32: ProcessReadinessIdentity]

  func observe(
    processID: Int32
  ) -> Result<ProcessReadinessIdentity, RedirectedDescendantReadinessFailure> {
    guard let observation = observations[processID] else {
      return .failure(.observationFailed(processID: processID, errorCode: ESRCH))
    }
    return .success(observation)
  }
}

private enum ReadinessStreamEvent: Equatable {
  case wouldBlock
  case bytes(Data)
  case endOfFile
}

private struct ReadinessRecordAccumulator {
  private static let maximumRecordBytes = 256
  private var bytes = Data()

  mutating func consume(
    _ event: ReadinessStreamEvent
  ) -> Result<RedirectedDescendantReadinessRecord?, RedirectedDescendantReadinessFailure> {
    switch event {
    case .wouldBlock:
      return .success(nil)
    case .endOfFile:
      return bytes.isEmpty ? .failure(.earlyDescendantExit) : .failure(.malformedRecord)
    case .bytes(let data):
      bytes.append(data)
    }
    guard bytes.count <= Self.maximumRecordBytes else {
      return .failure(.malformedRecord)
    }
    guard let newline = bytes.firstIndex(of: 0x0A) else { return .success(nil) }
    guard newline == bytes.index(before: bytes.endIndex) else {
      return .failure(.malformedRecord)
    }
    let fields = String(decoding: bytes.prefix(upTo: newline), as: UTF8.self)
      .split(separator: " ")
    guard fields.count == 3, fields[0] == "ready",
      let leader = Int32(String(fields[1])), let descendant = Int32(String(fields[2]))
    else {
      return .failure(.malformedRecord)
    }
    return .success(.ready(leaderProcessID: leader, descendantProcessID: descendant))
  }
}

private final class AnonymousDescendantReadinessFixture {
  struct ChildFileDescriptors: Equatable {
    let ready: Int32
    let acknowledgement: Int32
  }

  private var readyReadFileDescriptor: Int32
  private var readyWriteFileDescriptor: Int32
  private var acknowledgementReadFileDescriptor: Int32
  private var acknowledgementWriteFileDescriptor: Int32
  private let childFileDescriptors: ChildFileDescriptors

  init() throws {
    let ready = try Self.makePipe(parentEnd: 0)
    do {
      let acknowledgement = try Self.makePipe(parentEnd: 1)
      do {
        let selectedChildFileDescriptors = try Self.chooseChildFileDescriptors(
          excludingSourceFileDescriptors: Set(ready + acknowledgement)
        )
        readyReadFileDescriptor = ready[0]
        readyWriteFileDescriptor = ready[1]
        acknowledgementReadFileDescriptor = acknowledgement[0]
        acknowledgementWriteFileDescriptor = acknowledgement[1]
        childFileDescriptors = selectedChildFileDescriptors
      } catch {
        Darwin.close(acknowledgement[0])
        Darwin.close(acknowledgement[1])
        throw error
      }
    } catch {
      Darwin.close(ready[0])
      Darwin.close(ready[1])
      throw error
    }
  }

  func spawn(mode: RedirectedDescendantFixtureMode) throws -> SpawnedPOSIXProcessGroup {
    guard readyWriteFileDescriptor >= 0, acknowledgementReadFileDescriptor >= 0 else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(EALREADY))
    }
    let inherited = [
      POSIXSpawnInheritedFileDescriptor(
        sourceFileDescriptor: readyWriteFileDescriptor,
        childFileDescriptor: childFileDescriptors.ready
      ),
      POSIXSpawnInheritedFileDescriptor(
        sourceFileDescriptor: acknowledgementReadFileDescriptor,
        childFileDescriptor: childFileDescriptors.acknowledgement
      ),
    ]
    readyWriteFileDescriptor = -1
    acknowledgementReadFileDescriptor = -1
    return try POSIXProcessGroupSpawner().spawn(
      executableURL: URL(fileURLWithPath: "/bin/sh"),
      arguments: [
        "-c",
        mode.shellScript(
          childReadyFileDescriptor: childFileDescriptors.ready,
          childAcknowledgementFileDescriptor: childFileDescriptors.acknowledgement
        ),
        "diskplan-readiness-fixture",
      ],
      environment: BoundedLsofProcessActivityCollector.sanitizedEnvironment,
      consumingInheritedFileDescriptors: inherited
    )
  }

  func cleanup() {
    for descriptor in [
      readyReadFileDescriptor,
      readyWriteFileDescriptor,
      acknowledgementReadFileDescriptor,
      acknowledgementWriteFileDescriptor,
    ] where descriptor >= 0 {
      Darwin.close(descriptor)
    }
    readyReadFileDescriptor = -1
    readyWriteFileDescriptor = -1
    acknowledgementReadFileDescriptor = -1
    acknowledgementWriteFileDescriptor = -1
  }

  func closeUntransferredChildEndsForTest() {
    if readyWriteFileDescriptor >= 0 {
      Darwin.close(readyWriteFileDescriptor)
      readyWriteFileDescriptor = -1
    }
    if acknowledgementReadFileDescriptor >= 0 {
      Darwin.close(acknowledgementReadFileDescriptor)
      acknowledgementReadFileDescriptor = -1
    }
  }

  func waitForReadiness(
    deadlineNanoseconds: UInt64,
    observer: some ProcessReadinessObserving
  ) -> Result<ValidatedRedirectedDescendantReadiness, RedirectedDescendantReadinessFailure> {
    let record: RedirectedDescendantReadinessRecord
    switch readRecord(deadlineNanoseconds: deadlineNanoseconds) {
    case .success(let parsed):
      record = parsed
    case .failure(let failure):
      return .failure(failure)
    }
    return Self.validate(record: record, observer: observer)
  }

  func release(
    _ validated: ValidatedRedirectedDescendantReadiness,
    observer: some ProcessReadinessObserving
  ) -> Result<Void, RedirectedDescendantReadinessFailure> {
    switch Self.validate(record: validated.record, observer: observer) {
    case .success(let current) where current == validated:
      break
    case .success:
      return .failure(
        .identityChanged(processID: validated.descendantIdentity.processID)
      )
    case .failure(let failure):
      return .failure(failure)
    }

    return writeAcknowledgement()
  }

  func writeAcknowledgementForTest()
    -> Result<Void, RedirectedDescendantReadinessFailure>
  {
    writeAcknowledgement()
  }

  private func writeAcknowledgement()
    -> Result<Void, RedirectedDescendantReadinessFailure>
  {
    let acknowledgement = Data("go\n".utf8)
    errno = 0
    let written = acknowledgement.withUnsafeBytes { bytes in
      Darwin.write(
        acknowledgementWriteFileDescriptor,
        bytes.baseAddress,
        bytes.count
      )
    }
    guard written == acknowledgement.count else {
      return .failure(.io(errorCode: errno == 0 ? EIO : errno))
    }
    return .success(())
  }

  static func validate(
    record: RedirectedDescendantReadinessRecord,
    observer: some ProcessReadinessObserving
  ) -> Result<ValidatedRedirectedDescendantReadiness, RedirectedDescendantReadinessFailure> {
    let leaderProcessID: Int32
    let descendantProcessID: Int32
    switch record {
    case .ready(let leader, let descendant):
      leaderProcessID = leader
      descendantProcessID = descendant
    }
    guard leaderProcessID > 0, descendantProcessID > 0,
      leaderProcessID != descendantProcessID
    else {
      return .failure(.malformedRecord)
    }

    let firstLeader: ProcessReadinessIdentity
    let firstDescendant: ProcessReadinessIdentity
    let secondLeader: ProcessReadinessIdentity
    let secondDescendant: ProcessReadinessIdentity
    switch observer.observe(processID: leaderProcessID) {
    case .success(let identity): firstLeader = identity
    case .failure(let failure): return .failure(failure)
    }
    switch observer.observe(processID: descendantProcessID) {
    case .success(let identity): firstDescendant = identity
    case .failure(let failure): return .failure(failure)
    }
    switch observer.observe(processID: leaderProcessID) {
    case .success(let identity): secondLeader = identity
    case .failure(let failure): return .failure(failure)
    }
    switch observer.observe(processID: descendantProcessID) {
    case .success(let identity): secondDescendant = identity
    case .failure(let failure): return .failure(failure)
    }

    guard firstLeader == secondLeader else {
      return .failure(.identityChanged(processID: leaderProcessID))
    }
    guard firstDescendant == secondDescendant else {
      return .failure(.identityChanged(processID: descendantProcessID))
    }
    guard firstLeader.processGroupID == leaderProcessID else {
      return .failure(
        .wrongProcessGroup(
          processID: leaderProcessID,
          expectedProcessGroupID: leaderProcessID,
          actualProcessGroupID: firstLeader.processGroupID
        ))
    }
    guard firstDescendant.processGroupID == leaderProcessID else {
      return .failure(
        .wrongProcessGroup(
          processID: descendantProcessID,
          expectedProcessGroupID: leaderProcessID,
          actualProcessGroupID: firstDescendant.processGroupID
        ))
    }
    return .success(
      ValidatedRedirectedDescendantReadiness(
        record: record,
        leaderIdentity: firstLeader,
        descendantIdentity: firstDescendant
      ))
  }

  private func readRecord(
    deadlineNanoseconds: UInt64
  ) -> Result<RedirectedDescendantReadinessRecord, RedirectedDescendantReadinessFailure> {
    var accumulator = ReadinessRecordAccumulator()
    while true {
      let now = DispatchTime.now().uptimeNanoseconds
      guard now < deadlineNanoseconds else { return .failure(.timeout) }
      let remaining = deadlineNanoseconds - now
      let roundedMilliseconds = max(UInt64(1), (remaining + 999_999) / 1_000_000)
      let timeoutMilliseconds = Int32(min(UInt64(Int32.max), roundedMilliseconds))
      var descriptor = pollfd(fd: readyReadFileDescriptor, events: Int16(POLLIN), revents: 0)
      errno = 0
      let pollResult = Darwin.poll(&descriptor, 1, timeoutMilliseconds)
      if pollResult < 0 {
        if errno == EINTR { continue }
        return .failure(.io(errorCode: errno == 0 ? EIO : errno))
      }
      if pollResult == 0 { return .failure(.timeout) }
      if descriptor.revents & Int16(POLLERR | POLLNVAL) != 0 {
        return .failure(.io(errorCode: EIO))
      }
      if descriptor.revents & Int16(POLLIN) != 0 {
        var buffer = [UInt8](repeating: 0, count: 256)
        errno = 0
        let count = buffer.withUnsafeMutableBytes { buffer in
          Darwin.read(readyReadFileDescriptor, buffer.baseAddress, buffer.count)
        }
        if count < 0 {
          if errno == EINTR { continue }
          if errno == EAGAIN {
            switch accumulator.consume(.wouldBlock) {
            case .success: continue
            case .failure(let failure): return .failure(failure)
            }
          }
          return .failure(.io(errorCode: errno == 0 ? EIO : errno))
        }
        let event: ReadinessStreamEvent =
          count == 0 ? .endOfFile : .bytes(Data(buffer.prefix(count)))
        switch accumulator.consume(event) {
        case .success(.some(let record)): return .success(record)
        case .success(.none): break
        case .failure(let failure): return .failure(failure)
        }
      }
      if descriptor.revents & Int16(POLLHUP) != 0 {
        switch accumulator.consume(.endOfFile) {
        case .success(.some(let record)): return .success(record)
        case .success(.none): continue
        case .failure(let failure): return .failure(failure)
        }
      }
    }
  }

  private static func makePipe(parentEnd: Int) throws -> [Int32] {
    var descriptors: [Int32] = [-1, -1]
    errno = 0
    guard Darwin.pipe(&descriptors) == 0 else {
      throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
    }
    do {
      for descriptor in descriptors {
        guard Darwin.fcntl(descriptor, F_SETFD, FD_CLOEXEC) == 0 else {
          throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
      }
      let flags = Darwin.fcntl(descriptors[parentEnd], F_GETFL)
      guard flags >= 0,
        Darwin.fcntl(descriptors[parentEnd], F_SETFL, flags | O_NONBLOCK) == 0
      else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
      }
      if parentEnd == 1 {
        guard Darwin.fcntl(descriptors[parentEnd], F_SETNOSIGPIPE, 1) == 0 else {
          throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
      }
      return descriptors
    } catch {
      Darwin.close(descriptors[0])
      Darwin.close(descriptors[1])
      throw error
    }
  }

  static func chooseChildFileDescriptors(
    excludingSourceFileDescriptors sourceFileDescriptors: Set<Int32>
  ) throws -> ChildFileDescriptors {
    var excluded = sourceFileDescriptors
    excluded.formUnion([STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO])
    var selected: [Int32] = []
    var candidate: Int32 = 40
    while selected.count < 2 {
      if !excluded.contains(candidate) {
        selected.append(candidate)
        excluded.insert(candidate)
      }
      guard candidate < Int32.max else {
        throw NSError(domain: NSPOSIXErrorDomain, code: Int(EMFILE))
      }
      candidate += 1
    }
    return ChildFileDescriptors(ready: selected[0], acknowledgement: selected[1])
  }
}

extension Result where Failure == RedirectedDescendantReadinessFailure {
  fileprivate var failureDescription: String {
    switch self {
    case .success:
      return "none"
    case .failure(let failure):
      return String(describing: failure)
    }
  }
}

private func makeTaskScopedTemporaryDirectory(label: String) throws -> URL {
  let root = FileManager.default.temporaryDirectory
    .appendingPathComponent("diskplan-\(label)-\(UUID().uuidString)", isDirectory: true)
  try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
  return root
}
