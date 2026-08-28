import DiskplanProto

/// Phase 0's deterministic protocol fixture. It exercises the scan control
/// contract without touching the filesystem; Phase 1 replaces its facts with
/// the read-only scanner while preserving the event surface.
public struct ScanSession {
    public private(set) var state: Diskplan_V1_ScanState = .idle
    public private(set) var eventSequence: UInt64 = 0

    private var profile = "standard"
    private var seenRequestIDs: Set<UInt64> = []
    private var provisionalPlanID: String?

    public init() {}

    public mutating func start(
        _ request: Diskplan_V1_StartScanRequest
    ) -> [Diskplan_V1_EngineEvent] {
        let requestID = request.requestID
        guard validateRequestID(requestID) else {
            return reject(
                requestID: requestID,
                control: .startScan,
                code: requestID == 0 ? .malformedRequest : .duplicateRequestID,
                detail: requestID == 0 ? "request_id must be non-zero" : "request_id was already used"
            )
        }
        seenRequestIDs.insert(requestID)
        guard state == .idle else {
            return reject(
                requestID: requestID,
                control: .startScan,
                code: .invalidState,
                detail: "scan has already started"
            )
        }

        profile = request.profile.isEmpty ? "standard" : request.profile
        state = .running
        return [
            accepted(requestID: requestID, control: .startScan, resultingState: .running),
            stateChanged(requestID: requestID, state: .running, reason: "scan started"),
            progress(requestID: requestID),
        ]
    }

    public mutating func control(
        _ request: Diskplan_V1_ScanControlRequest
    ) -> [Diskplan_V1_EngineEvent] {
        let requestID = request.requestID
        guard validateRequestID(requestID) else {
            return reject(
                requestID: requestID,
                control: request.control,
                code: requestID == 0 ? .malformedRequest : .duplicateRequestID,
                detail: requestID == 0 ? "request_id must be non-zero" : "request_id was already used"
            )
        }
        seenRequestIDs.insert(requestID)

        switch request.control {
        case .pauseScan where state == .running:
            state = .paused
            return [
                accepted(requestID: requestID, control: .pauseScan, resultingState: .paused),
                stateChanged(requestID: requestID, state: .paused, reason: "pause acknowledged"),
            ]

        case .resumeScan where state == .paused || state == .provisionalPlanReady:
            let invalidatedPlanID = provisionalPlanID
            provisionalPlanID = nil
            state = .running
            var events = [
                accepted(requestID: requestID, control: .resumeScan, resultingState: .running),
            ]
            if let invalidatedPlanID {
                var invalidated = Diskplan_V1_ProvisionalPlanInvalidated()
                invalidated.previousPlanID = invalidatedPlanID
                events.append(event(requestID: requestID, body: .provisionalPlanInvalidated(invalidated)))
            }
            events.append(stateChanged(requestID: requestID, state: .running, reason: "resume acknowledged"))
            events.append(progress(requestID: requestID))
            return events

        case .pauseAndBuildProvisionalPlan where state == .running || state == .paused:
            state = .buildingProvisionalPlan
            var events = [
                accepted(
                    requestID: requestID,
                    control: .pauseAndBuildProvisionalPlan,
                    resultingState: .buildingProvisionalPlan
                ),
                stateChanged(
                    requestID: requestID,
                    state: .buildingProvisionalPlan,
                    reason: "provisional plan requested"
                ),
            ]
            let plan = makeProvisionalPlan()
            provisionalPlanID = plan.planID
            state = .provisionalPlanReady
            events.append(
                stateChanged(
                    requestID: requestID,
                    state: .provisionalPlanReady,
                    reason: "provisional plan ready"
                )
            )
            events.append(event(requestID: requestID, body: .provisionalPlanReady(plan)))
            return events

        case .cancelScan
            where state == .running || state == .paused || state == .buildingProvisionalPlan
                || state == .provisionalPlanReady:
            state = .cancelling
            var cancelled = Diskplan_V1_ScanCancelled()
            cancelled.reason = "cancelled by user"
            let events = [
                accepted(requestID: requestID, control: .cancelScan, resultingState: .cancelling),
                stateChanged(requestID: requestID, state: .cancelling, reason: "cancel acknowledged"),
                stateChanged(requestID: requestID, state: .cancelled, reason: "scan cancelled"),
                event(requestID: requestID, body: .scanCancelled(cancelled)),
            ]
            state = .cancelled
            return events

        case .unspecified, .startScan, .UNRECOGNIZED:
            return reject(
                requestID: requestID,
                control: request.control,
                code: .malformedRequest,
                detail: "control is not valid in ScanControlRequest"
            )

        default:
            return reject(
                requestID: requestID,
                control: request.control,
                code: .invalidState,
                detail: "control is not valid in the current scan state"
            )
        }
    }

    public mutating func rejectMalformed(
        requestID: UInt64,
        control: Diskplan_V1_ScanControlKind,
        detail: String
    ) -> [Diskplan_V1_EngineEvent] {
        reject(
            requestID: requestID,
            control: control,
            code: .malformedRequest,
            detail: detail
        )
    }

    private func validateRequestID(_ requestID: UInt64) -> Bool {
        requestID != 0 && !seenRequestIDs.contains(requestID)
    }

    private mutating func accepted(
        requestID: UInt64,
        control: Diskplan_V1_ScanControlKind,
        resultingState: Diskplan_V1_ScanState
    ) -> Diskplan_V1_EngineEvent {
        var accepted = Diskplan_V1_ControlAccepted()
        accepted.control = control
        accepted.resultingState = resultingState
        return event(requestID: requestID, body: .controlAccepted(accepted))
    }

    private mutating func reject(
        requestID: UInt64,
        control: Diskplan_V1_ScanControlKind,
        code: Diskplan_V1_ControlRejectCode,
        detail: String
    ) -> [Diskplan_V1_EngineEvent] {
        var rejected = Diskplan_V1_ControlRejected()
        rejected.control = control
        rejected.code = code
        rejected.detail = detail
        rejected.currentState = state
        return [event(requestID: requestID, body: .controlRejected(rejected))]
    }

    private mutating func stateChanged(
        requestID: UInt64,
        state: Diskplan_V1_ScanState,
        reason: String
    ) -> Diskplan_V1_EngineEvent {
        var changed = Diskplan_V1_ScanStateChanged()
        changed.state = state
        changed.reason = reason
        return event(requestID: requestID, body: .scanStateChanged(changed))
    }

    private mutating func progress(requestID: UInt64) -> Diskplan_V1_EngineEvent {
        var progress = Diskplan_V1_ScanProgress()
        progress.profile = profile
        progress.elapsedMillis = 1_250
        progress.entries = 12_480
        progress.directories = 920
        progress.candidates = 37
        progress.allocatedBytesObserved = 8_589_934_592
        progress.reclaimEstimateBytes = 1_610_612_736
        progress.completeRoots = 2
        progress.partialRoots = 1
        progress.entriesPerSecond = 9_984
        progress.currentRoot = "phase0://deterministic-fixture"
        progress.structuralBudget = 2_000_000
        return event(requestID: requestID, body: .scanProgress(progress))
    }

    private func makeProvisionalPlan() -> Diskplan_V1_ProvisionalPlanReady {
        var ready = Diskplan_V1_ProvisionalPlanReady()
        ready.planID = "phase0-provisional-0001"
        ready.actionCount = 11
        ready.immediateReclaimBytes = 1_342_177_280
        ready.conditionalReclaimBytes = 268_435_456

        var readyGroup = Diskplan_V1_ProvisionalPlanGroupSummary()
        readyGroup.groupID = "ready"
        readyGroup.title = "Ready"
        readyGroup.actionCount = 8
        readyGroup.immediateReclaimBytes = 1_073_741_824
        readyGroup.status = "ready"

        var conditionalGroup = Diskplan_V1_ProvisionalPlanGroupSummary()
        conditionalGroup.groupID = "conditional"
        conditionalGroup.title = "Conditional"
        conditionalGroup.actionCount = 3
        conditionalGroup.immediateReclaimBytes = 268_435_456
        conditionalGroup.conditionalReclaimBytes = 268_435_456
        conditionalGroup.status = "needs complete release set"

        ready.groups = [readyGroup, conditionalGroup]
        return ready
    }

    private mutating func event(
        requestID: UInt64,
        body: Diskplan_V1_EngineEvent.OneOf_Body
    ) -> Diskplan_V1_EngineEvent {
        eventSequence += 1
        var engineEvent = Diskplan_V1_EngineEvent()
        engineEvent.eventSequence = eventSequence
        engineEvent.requestID = requestID
        engineEvent.body = body
        return engineEvent
    }
}
