import DiskplanCore
import DiskplanProto
import Testing

@Test
func scanControlsAreAcknowledgedBeforeStateChanges() {
    var session = ScanSession()
    let start = session.start(startRequest(id: 10))

    #expect(start.map(\.eventSequence) == [1, 2, 3])
    #expect(start.map(\.requestID) == [10, 10, 10])
    #expect(start[0].controlAccepted.control == .startScan)
    #expect(start[1].scanStateChanged.state == .running)
    #expect(start[2].scanProgress.entries == 12_480)

    let pause = session.control(controlRequest(id: 11, .pauseScan))
    #expect(pause.map(\.eventSequence) == [4, 5])
    #expect(pause[0].controlAccepted.resultingState == .paused)
    #expect(pause[1].scanStateChanged.state == .paused)
}

@Test
func provisionalPlanIsInvalidatedWhenResumeIsAcknowledged() {
    var session = ScanSession()
    _ = session.start(startRequest(id: 1))

    let plan = session.control(controlRequest(id: 2, .pauseAndBuildProvisionalPlan))
    #expect(plan.count == 4)
    #expect(plan[0].controlAccepted.resultingState == .buildingProvisionalPlan)
    #expect(plan[2].scanStateChanged.state == .provisionalPlanReady)
    #expect(plan[3].provisionalPlanReady.groups.map(\.groupID) == ["ready", "conditional"])

    let resume = session.control(controlRequest(id: 3, .resumeScan))
    #expect(resume[0].controlAccepted.resultingState == .running)
    #expect(resume[1].provisionalPlanInvalidated.previousPlanID == "phase0-provisional-0001")
    #expect(resume[2].scanStateChanged.state == .running)
    #expect(resume[3].scanProgress.profile == "standard")
}

@Test
func duplicateAndInvalidControlsAreRejectedWithoutChangingState() {
    var session = ScanSession()
    _ = session.start(startRequest(id: 1))

    let invalid = session.control(controlRequest(id: 2, .resumeScan))
    #expect(invalid[0].controlRejected.code == .invalidState)
    #expect(invalid[0].controlRejected.currentState == .running)

    let duplicate = session.control(controlRequest(id: 2, .cancelScan))
    #expect(duplicate[0].controlRejected.code == .duplicateRequestID)
    #expect(session.state == .running)
}

@Test
func cancelProducesTerminalEventAndMonotonicSequence() {
    var session = ScanSession()
    let start = session.start(startRequest(id: 41))
    let cancel = session.control(controlRequest(id: 42, .cancelScan))
    let sequences = (start + cancel).map(\.eventSequence)

    #expect(sequences == Array(1 ... UInt64(sequences.count)))
    #expect(cancel[0].controlAccepted.resultingState == .cancelling)
    #expect(cancel[2].scanStateChanged.state == .cancelled)
    #expect(cancel[3].scanCancelled.reason == "cancelled by user")
    #expect(session.state == .cancelled)
}

private func startRequest(id: UInt64) -> Diskplan_V1_StartScanRequest {
    var request = Diskplan_V1_StartScanRequest()
    request.requestID = id
    request.profile = "standard"
    return request
}

private func controlRequest(
    id: UInt64,
    _ control: Diskplan_V1_ScanControlKind
) -> Diskplan_V1_ScanControlRequest {
    var request = Diskplan_V1_ScanControlRequest()
    request.requestID = id
    request.control = control
    return request
}
