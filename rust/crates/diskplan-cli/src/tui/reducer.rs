use crossterm::event::{KeyCode, KeyEventKind};
use diskplan_proto::diskplan::v1::{ControlRejectCode, ScanControlKind, ScanState, engine_event};

use super::model::{
    ActiveRequest, AppState, Effect, EngineDelivery, RequestPhase, Screen, TerminalState, UiEvent,
};

pub fn reduce(state: &mut AppState, event: UiEvent) -> Vec<Effect> {
    match event {
        UiEvent::Key(key) => reduce_key(state, key.code, key.kind),
        UiEvent::Resize => Vec::new(),
        UiEvent::Engine(delivery) if state.terminal.is_none() => {
            reduce_engine_event(state, delivery)
        }
        UiEvent::Engine(_) => Vec::new(),
        UiEvent::DriverExited(result) => {
            state.driver_exited = true;
            if let Err(detail) = result {
                state.scan_state = ScanState::Failed;
                state.terminal = Some(TerminalState::Failed(detail.clone()));
                state.banner = Some(detail);
            } else if state.terminal.is_none() {
                let detail = "engine exited before a terminal scan event".to_owned();
                state.scan_state = ScanState::Failed;
                state.terminal = Some(TerminalState::Failed(detail.clone()));
                state.banner = Some(detail);
            }
            Vec::new()
        }
    }
}

fn reduce_key(state: &mut AppState, code: KeyCode, kind: KeyEventKind) -> Vec<Effect> {
    if kind != KeyEventKind::Press || state.terminal.is_some() {
        return Vec::new();
    }

    match code {
        KeyCode::Char('?') => {
            state.help_visible = !state.help_visible;
            Vec::new()
        }
        KeyCode::Char('/') if state.screen == Screen::Scan => {
            state.help_visible = !state.help_visible;
            Vec::new()
        }
        KeyCode::Char('q') => request_once(state, ScanControlKind::CancelScan),
        KeyCode::Char(' ') if state.screen == Screen::Scan => match state.scan_state {
            ScanState::Running => request_once(state, ScanControlKind::PauseScan),
            ScanState::Paused => request_once(state, ScanControlKind::ResumeScan),
            _ => Vec::new(),
        },
        KeyCode::Char('p') if state.screen == Screen::Scan => match state.scan_state {
            ScanState::Running | ScanState::Paused => {
                request_once(state, ScanControlKind::PauseAndBuildProvisionalPlan)
            }
            _ => Vec::new(),
        },
        KeyCode::Char('r')
            if state.screen == Screen::ProvisionalPlan || state.scan_state == ScanState::Paused =>
        {
            request_once(state, ScanControlKind::ResumeScan)
        }
        _ => Vec::new(),
    }
}

fn request_once(state: &mut AppState, kind: ScanControlKind) -> Vec<Effect> {
    if state.has_pending(kind) || (kind == ScanControlKind::CancelScan && state.cancel_requested) {
        return Vec::new();
    }
    match state.try_next_control(kind) {
        Ok(command) => {
            if kind == ScanControlKind::CancelScan {
                state.cancel_requested = true;
                state.banner = Some("Cancellation requested; waiting for the engine…".into());
            }
            vec![Effect::SendControl(command)]
        }
        Err(_) => protocol_failure(state, "request ID space exhausted".into()),
    }
}

fn reduce_engine_event(state: &mut AppState, delivery: EngineDelivery) -> Vec<Effect> {
    let event = delivery.event;
    let is_progress = matches!(event.body, Some(engine_event::Body::ScanProgress(_)));
    let Some(expected) = state.last_event_sequence.checked_add(1) else {
        return protocol_failure(state, "event sequence space exhausted".into());
    };
    let Some(accepted_sequence) = expected.checked_add(delivery.skipped_progress_events) else {
        return protocol_failure(state, "coalesced event sequence overflow".into());
    };
    if delivery.skipped_progress_events > 0 && !is_progress {
        return protocol_failure(
            state,
            "non-progress event claimed a coalesced progress gap".into(),
        );
    }
    if event.event_sequence != accepted_sequence {
        return protocol_failure(
            state,
            format!(
                "event sequence mismatch: expected {accepted_sequence}, received {}",
                event.event_sequence
            ),
        );
    }
    state.last_event_sequence = event.event_sequence;

    match event.body {
        Some(engine_event::Body::ControlAccepted(accepted)) => {
            let Some(pending) = state
                .pending_controls
                .iter()
                .find(|pending| pending.request_id == event.request_id)
                .cloned()
            else {
                return protocol_failure(
                    state,
                    format!("engine acknowledged unknown request {}", event.request_id),
                );
            };
            if pending.kind as i32 != accepted.control {
                return protocol_failure(
                    state,
                    format!(
                        "engine acknowledged request {} with a different control",
                        event.request_id
                    ),
                );
            }
            let Ok(resulting_state) = ScanState::try_from(accepted.resulting_state) else {
                return protocol_failure(state, "engine acknowledged an unknown scan state".into());
            };
            if resulting_state == ScanState::Unspecified {
                return protocol_failure(
                    state,
                    "engine acknowledged an unspecified scan state".into(),
                );
            }
            if !accepted_transition_is_valid(pending.kind, state.scan_state, resulting_state) {
                return protocol_failure(
                    state,
                    format!(
                        "engine acknowledged {:?} with impossible transition {:?} -> {:?}",
                        pending.kind, state.scan_state, resulting_state
                    ),
                );
            }
            let phase = match pending.kind {
                ScanControlKind::ResumeScan if state.provisional_plan.is_some() => {
                    RequestPhase::AwaitingInvalidation
                }
                ScanControlKind::ResumeScan => RequestPhase::AwaitingResumeState,
                _ => RequestPhase::AwaitingStateConfirmation,
            };
            state.take_pending(event.request_id);
            state.active_request = Some(ActiveRequest {
                request_id: event.request_id,
                kind: pending.kind,
                phase,
            });
            state.scan_state = resulting_state;
            state.banner = Some(format!("{} acknowledged", control_label(pending.kind)));
        }
        Some(engine_event::Body::ControlRejected(rejected)) => {
            let Some(pending) = state
                .pending_controls
                .iter()
                .find(|pending| pending.request_id == event.request_id)
                .cloned()
            else {
                return protocol_failure(
                    state,
                    format!("engine rejected unknown request {}", event.request_id),
                );
            };
            if rejected.control != pending.kind as i32 {
                return protocol_failure(
                    state,
                    format!(
                        "engine rejected request {} with a different control",
                        event.request_id
                    ),
                );
            }
            let Ok(code) = ControlRejectCode::try_from(rejected.code) else {
                return protocol_failure(state, "engine returned an unknown rejection code".into());
            };
            if code == ControlRejectCode::Unspecified {
                return protocol_failure(
                    state,
                    "engine returned an unspecified rejection code".into(),
                );
            }
            let Ok(current_state) = ScanState::try_from(rejected.current_state) else {
                return protocol_failure(state, "engine rejected in an unknown scan state".into());
            };
            if current_state == ScanState::Unspecified {
                return protocol_failure(
                    state,
                    "engine rejected in an unspecified scan state".into(),
                );
            }
            if current_state != state.scan_state {
                return protocol_failure(
                    state,
                    format!(
                        "engine rejected request {} in a different scan state",
                        event.request_id
                    ),
                );
            }
            state.take_pending(event.request_id);
            if pending.kind == ScanControlKind::CancelScan {
                state.cancel_requested = false;
            }
            state.banner = Some(format!("control rejected: {}", rejected.detail));
        }
        Some(body) => {
            if event.request_id == 0 {
                return protocol_failure(state, "non-ack event has zero request_id".into());
            }
            let Some(origin) = state.active_request.clone() else {
                return protocol_failure(
                    state,
                    format!(
                        "event for request {} has no acknowledged origin",
                        event.request_id
                    ),
                );
            };
            if origin.request_id != event.request_id {
                return protocol_failure(
                    state,
                    format!(
                        "event request {} does not match active origin {}",
                        event.request_id, origin.request_id
                    ),
                );
            }
            return reduce_origin_event(state, origin, body);
        }
        None => {
            return protocol_failure(state, "engine emitted an empty event".into());
        }
    }
    Vec::new()
}

fn accepted_transition_is_valid(
    control: ScanControlKind,
    current: ScanState,
    resulting: ScanState,
) -> bool {
    match control {
        ScanControlKind::StartScan => current == ScanState::Idle && resulting == ScanState::Running,
        ScanControlKind::PauseScan => {
            current == ScanState::Running && resulting == ScanState::Paused
        }
        ScanControlKind::ResumeScan => {
            matches!(current, ScanState::Paused | ScanState::ProvisionalPlanReady)
                && resulting == ScanState::Running
        }
        ScanControlKind::PauseAndBuildProvisionalPlan => {
            matches!(current, ScanState::Running | ScanState::Paused)
                && resulting == ScanState::BuildingProvisionalPlan
        }
        ScanControlKind::CancelScan => {
            matches!(
                current,
                ScanState::Running
                    | ScanState::Paused
                    | ScanState::BuildingProvisionalPlan
                    | ScanState::ProvisionalPlanReady
            ) && resulting == ScanState::Cancelling
        }
        ScanControlKind::Unspecified => false,
    }
}

fn reduce_origin_event(
    state: &mut AppState,
    origin: ActiveRequest,
    body: engine_event::Body,
) -> Vec<Effect> {
    match body {
        engine_event::Body::ScanStateChanged(changed) => {
            let Ok(next) = ScanState::try_from(changed.state) else {
                return protocol_failure(state, "engine reported an unknown scan state".into());
            };
            if next == ScanState::Unspecified {
                return protocol_failure(state, "engine reported an unspecified scan state".into());
            }
            let next_phase = match (origin.kind, origin.phase, state.scan_state, next) {
                (
                    ScanControlKind::StartScan,
                    RequestPhase::AwaitingStateConfirmation,
                    ScanState::Running,
                    ScanState::Running,
                )
                | (
                    ScanControlKind::PauseScan,
                    RequestPhase::AwaitingStateConfirmation,
                    ScanState::Paused,
                    ScanState::Paused,
                ) => RequestPhase::Steady,
                (
                    ScanControlKind::PauseAndBuildProvisionalPlan,
                    RequestPhase::AwaitingStateConfirmation,
                    ScanState::BuildingProvisionalPlan,
                    ScanState::BuildingProvisionalPlan,
                ) => RequestPhase::AwaitingPlanReadyState,
                (
                    ScanControlKind::PauseAndBuildProvisionalPlan,
                    RequestPhase::AwaitingPlanReadyState,
                    ScanState::BuildingProvisionalPlan,
                    ScanState::ProvisionalPlanReady,
                ) => RequestPhase::AwaitingPlanProjection,
                (
                    ScanControlKind::ResumeScan,
                    RequestPhase::AwaitingResumeState,
                    ScanState::Running,
                    ScanState::Running,
                ) => RequestPhase::AwaitingResumeProgress,
                (
                    ScanControlKind::CancelScan,
                    RequestPhase::AwaitingStateConfirmation,
                    ScanState::Cancelling,
                    ScanState::Cancelling,
                ) => RequestPhase::AwaitingCancelledState,
                (
                    ScanControlKind::CancelScan,
                    RequestPhase::AwaitingCancelledState,
                    ScanState::Cancelling,
                    ScanState::Cancelled,
                ) => RequestPhase::AwaitingCancelledTerminal,
                _ => {
                    return protocol_failure(
                        state,
                        format!(
                            "state change {:?} -> {:?} is invalid for {:?} in {:?}",
                            state.scan_state, next, origin.kind, origin.phase
                        ),
                    );
                }
            };
            state.scan_state = next;
            state.banner = Some(changed.reason);
            set_active_phase(state, &origin, next_phase);
        }
        engine_event::Body::ScanProgress(progress) => {
            let valid = state.scan_state == ScanState::Running
                && matches!(
                    (origin.kind, origin.phase),
                    (ScanControlKind::StartScan, RequestPhase::Steady)
                        | (
                            ScanControlKind::ResumeScan,
                            RequestPhase::AwaitingResumeProgress | RequestPhase::Steady
                        )
                );
            if !valid {
                return invalid_origin_event(state, &origin, "ScanProgress");
            }
            state.progress = Some(progress);
            set_active_phase(state, &origin, RequestPhase::Steady);
        }
        engine_event::Body::ProvisionalPlanReady(plan) => {
            if origin.kind != ScanControlKind::PauseAndBuildProvisionalPlan
                || origin.phase != RequestPhase::AwaitingPlanProjection
                || state.scan_state != ScanState::ProvisionalPlanReady
                || state.provisional_plan.is_some()
                || plan.plan_id.is_empty()
            {
                return invalid_origin_event(state, &origin, "ProvisionalPlanReady");
            }
            state.provisional_plan = Some(plan);
            state.screen = Screen::ProvisionalPlan;
            state.help_visible = false;
            set_active_phase(state, &origin, RequestPhase::Steady);
        }
        engine_event::Body::ProvisionalPlanInvalidated(invalidated) => {
            let Some(current_plan) = state.provisional_plan.as_ref() else {
                return protocol_failure(state, "engine invalidated an unknown plan".into());
            };
            if origin.kind != ScanControlKind::ResumeScan
                || origin.phase != RequestPhase::AwaitingInvalidation
                || invalidated.previous_plan_id != current_plan.plan_id
            {
                return protocol_failure(
                    state,
                    format!(
                        "plan invalidation {:?} does not match active plan {:?}",
                        invalidated.previous_plan_id, current_plan.plan_id
                    ),
                );
            }
            state.provisional_plan = None;
            state.screen = Screen::Scan;
            state.help_visible = false;
            set_active_phase(state, &origin, RequestPhase::AwaitingResumeState);
        }
        engine_event::Body::ScanCancelled(cancelled) => {
            if origin.kind != ScanControlKind::CancelScan
                || origin.phase != RequestPhase::AwaitingCancelledTerminal
                || state.scan_state != ScanState::Cancelled
            {
                return invalid_origin_event(state, &origin, "ScanCancelled");
            }
            state.terminal = Some(TerminalState::Cancelled(cancelled.reason));
        }
        engine_event::Body::ScanFinished(finished) => {
            if !matches!(
                origin.kind,
                ScanControlKind::StartScan | ScanControlKind::ResumeScan
            ) || origin.phase != RequestPhase::Steady
                || state.scan_state != ScanState::Running
            {
                return invalid_origin_event(state, &origin, "ScanFinished");
            }
            state.scan_state = ScanState::Finished;
            state.terminal = Some(TerminalState::Finished(finished.summary));
        }
        engine_event::Body::EngineFailed(failed) => {
            state.scan_state = ScanState::Failed;
            state.terminal = Some(TerminalState::Failed(format!(
                "{}: {}",
                failed.code, failed.detail
            )));
        }
        engine_event::Body::ControlAccepted(_) | engine_event::Body::ControlRejected(_) => {
            return protocol_failure(
                state,
                "ack event bypassed acknowledgement validation".into(),
            );
        }
    }
    Vec::new()
}

fn set_active_phase(state: &mut AppState, origin: &ActiveRequest, phase: RequestPhase) {
    state.active_request = Some(ActiveRequest {
        request_id: origin.request_id,
        kind: origin.kind,
        phase,
    });
}

fn invalid_origin_event(state: &mut AppState, origin: &ActiveRequest, event: &str) -> Vec<Effect> {
    protocol_failure(
        state,
        format!(
            "{event} is invalid for {:?} request {} in {:?}",
            origin.kind, origin.request_id, origin.phase
        ),
    )
}

fn protocol_failure(state: &mut AppState, detail: String) -> Vec<Effect> {
    state.scan_state = ScanState::Failed;
    state.terminal = Some(TerminalState::Failed(detail.clone()));
    state.banner = Some(detail);
    vec![Effect::StopDriver]
}

fn control_label(kind: ScanControlKind) -> &'static str {
    match kind {
        ScanControlKind::StartScan => "Start",
        ScanControlKind::PauseScan => "Pause",
        ScanControlKind::ResumeScan => "Resume",
        ScanControlKind::PauseAndBuildProvisionalPlan => "Provisional plan",
        ScanControlKind::CancelScan => "Cancel",
        ScanControlKind::Unspecified => "Unknown control",
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyEvent, KeyEventState, KeyModifiers};
    use diskplan_proto::diskplan::v1::{
        ControlAccepted, ControlRejected, EngineEvent, EngineFailed, ProvisionalPlanInvalidated,
        ProvisionalPlanReady, ScanCancelled, ScanFinished, ScanProgress, ScanState,
        ScanStateChanged, engine_event,
    };

    use super::super::model::PendingControl;
    use super::*;

    #[test]
    fn input_table_waits_for_ack_and_suppresses_repeat_release_and_duplicates() {
        let cases = [
            (KeyEventKind::Press, 1),
            (KeyEventKind::Repeat, 0),
            (KeyEventKind::Release, 0),
        ];
        for (kind, expected_effects) in cases {
            let mut state = running_state();
            let effects = reduce(&mut state, key(' ', kind));
            assert_eq!(effects.len(), expected_effects);
            assert_eq!(state.scan_state, ScanState::Running);
        }

        let mut state = running_state();
        assert_eq!(reduce(&mut state, key(' ', KeyEventKind::Press)).len(), 1);
        assert!(reduce(&mut state, key(' ', KeyEventKind::Press)).is_empty());
        assert_eq!(state.scan_state, ScanState::Running);
    }

    #[test]
    fn reducer_table_applies_ack_then_plan_and_resume_invalidation() {
        let mut state = running_state();
        let effect = reduce(&mut state, key('p', KeyEventKind::Press));
        let Effect::SendControl(command) = effect[0] else {
            panic!("expected control effect");
        };
        assert_eq!(command.kind, ScanControlKind::PauseAndBuildProvisionalPlan);

        reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                1,
                command.request_id,
                engine_event::Body::ControlAccepted(ControlAccepted {
                    control: command.kind as i32,
                    resulting_state: ScanState::BuildingProvisionalPlan as i32,
                }),
            ))),
        );
        assert_eq!(state.scan_state, ScanState::BuildingProvisionalPlan);
        assert!(state.pending_controls.is_empty());

        reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                2,
                command.request_id,
                engine_event::Body::ScanStateChanged(ScanStateChanged {
                    state: ScanState::BuildingProvisionalPlan as i32,
                    reason: "building".into(),
                }),
            ))),
        );
        reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                3,
                command.request_id,
                engine_event::Body::ScanStateChanged(ScanStateChanged {
                    state: ScanState::ProvisionalPlanReady as i32,
                    reason: "ready".into(),
                }),
            ))),
        );
        reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                4,
                command.request_id,
                engine_event::Body::ProvisionalPlanReady(ProvisionalPlanReady {
                    plan_id: "p1".into(),
                    ..Default::default()
                }),
            ))),
        );
        assert_eq!(state.screen, Screen::ProvisionalPlan);

        let resume = reduce(&mut state, key('r', KeyEventKind::Press));
        assert_eq!(resume.len(), 1);
        assert_eq!(state.screen, Screen::ProvisionalPlan);
        let Effect::SendControl(resume_command) = resume[0] else {
            panic!("expected resume control");
        };
        reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                5,
                resume_command.request_id,
                engine_event::Body::ControlAccepted(ControlAccepted {
                    control: ScanControlKind::ResumeScan as i32,
                    resulting_state: ScanState::Running as i32,
                }),
            ))),
        );
        let effects = reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                6,
                resume_command.request_id,
                engine_event::Body::ProvisionalPlanInvalidated(ProvisionalPlanInvalidated {
                    previous_plan_id: "p1".into(),
                }),
            ))),
        );
        assert!(effects.is_empty());
        assert_eq!(state.screen, Screen::Scan);
        assert!(state.provisional_plan.is_none());
    }

    #[test]
    fn question_mark_is_contextual_and_slash_is_scan_only_alias() {
        let mut state = running_state();
        reduce(&mut state, key('?', KeyEventKind::Press));
        assert!(state.help_visible);
        reduce(&mut state, key('/', KeyEventKind::Press));
        assert!(!state.help_visible);

        state.screen = Screen::ProvisionalPlan;
        reduce(&mut state, key('/', KeyEventKind::Press));
        assert!(!state.help_visible);
        reduce(&mut state, key('?', KeyEventKind::Press));
        assert!(state.help_visible);
    }

    #[test]
    fn q_is_emitted_once_even_when_another_control_is_pending() {
        let mut state = running_state();
        assert_eq!(reduce(&mut state, key(' ', KeyEventKind::Press)).len(), 1);
        assert_eq!(reduce(&mut state, key('q', KeyEventKind::Press)).len(), 1);
        assert!(reduce(&mut state, key('q', KeyEventKind::Press)).is_empty());
        assert_eq!(state.pending_controls.len(), 2);
    }

    #[test]
    fn malformed_semantic_event_table_fails_terminally_and_stops_driver() {
        let mut mismatch_state = pending_state(2, ScanControlKind::PauseScan);
        mismatch_state.scan_state = ScanState::Running;
        let cases = vec![
            (
                "unknown request ack",
                running_state(),
                EngineDelivery::exact(engine_event(
                    1,
                    99,
                    engine_event::Body::ControlAccepted(ControlAccepted {
                        control: ScanControlKind::PauseScan as i32,
                        resulting_state: ScanState::Paused as i32,
                    }),
                )),
            ),
            (
                "control mismatch",
                mismatch_state,
                EngineDelivery::exact(engine_event(
                    1,
                    2,
                    engine_event::Body::ControlAccepted(ControlAccepted {
                        control: ScanControlKind::ResumeScan as i32,
                        resulting_state: ScanState::Paused as i32,
                    }),
                )),
            ),
            (
                "unknown resulting state",
                pending_state(2, ScanControlKind::PauseScan),
                EngineDelivery::exact(engine_event(
                    1,
                    2,
                    engine_event::Body::ControlAccepted(ControlAccepted {
                        control: ScanControlKind::PauseScan as i32,
                        resulting_state: 999,
                    }),
                )),
            ),
            (
                "empty event",
                running_state(),
                EngineDelivery::exact(EngineEvent {
                    event_sequence: 1,
                    request_id: 0,
                    body: None,
                }),
            ),
            (
                "rejection without matching pending request",
                running_state(),
                EngineDelivery::exact(engine_event(
                    1,
                    77,
                    engine_event::Body::ControlRejected(ControlRejected {
                        control: ScanControlKind::PauseScan as i32,
                        detail: "no".into(),
                        current_state: ScanState::Running as i32,
                        ..Default::default()
                    }),
                )),
            ),
        ];

        for (name, mut state, delivery) in cases {
            let effects = reduce(&mut state, UiEvent::Engine(delivery));
            assert_eq!(effects, vec![Effect::StopDriver], "{name}");
            assert_eq!(state.scan_state, ScanState::Failed, "{name}");
            assert!(
                matches!(state.terminal, Some(TerminalState::Failed(_))),
                "{name}"
            );
        }
    }

    #[test]
    fn matching_control_rejection_is_non_terminal() {
        let mut state = pending_state(2, ScanControlKind::CancelScan);
        state.cancel_requested = true;
        let effects = reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                1,
                2,
                engine_event::Body::ControlRejected(ControlRejected {
                    control: ScanControlKind::CancelScan as i32,
                    code: ControlRejectCode::InvalidState as i32,
                    detail: "too late".into(),
                    current_state: ScanState::Running as i32,
                }),
            ))),
        );

        assert!(effects.is_empty());
        assert!(state.terminal.is_none());
        assert!(!state.cancel_requested);
        assert!(state.pending_controls.is_empty());
        assert_eq!(state.scan_state, ScanState::Running);
    }

    #[test]
    fn invalid_control_rejection_code_table_fails_terminally() {
        for code in [ControlRejectCode::Unspecified as i32, 999] {
            let mut state = pending_state(2, ScanControlKind::CancelScan);
            state.cancel_requested = true;
            let effects = reduce(
                &mut state,
                UiEvent::Engine(EngineDelivery::exact(engine_event(
                    1,
                    2,
                    engine_event::Body::ControlRejected(ControlRejected {
                        control: ScanControlKind::CancelScan as i32,
                        code,
                        detail: "invalid rejection code".into(),
                        current_state: ScanState::Running as i32,
                    }),
                ))),
            );

            assert_eq!(effects, vec![Effect::StopDriver], "code {code}");
            assert!(matches!(state.terminal, Some(TerminalState::Failed(_))));
            assert!(
                state.cancel_requested,
                "failed ack must not mutate pending state"
            );
            assert_eq!(state.pending_controls.len(), 1);
        }
    }

    #[test]
    fn accepted_transition_table_is_exhaustive() {
        let controls = [
            ScanControlKind::Unspecified,
            ScanControlKind::StartScan,
            ScanControlKind::PauseScan,
            ScanControlKind::ResumeScan,
            ScanControlKind::PauseAndBuildProvisionalPlan,
            ScanControlKind::CancelScan,
        ];
        let states = [
            ScanState::Unspecified,
            ScanState::Idle,
            ScanState::Running,
            ScanState::Paused,
            ScanState::BuildingProvisionalPlan,
            ScanState::ProvisionalPlanReady,
            ScanState::Cancelling,
            ScanState::Cancelled,
            ScanState::Finished,
            ScanState::Failed,
        ];
        let valid = [
            (
                ScanControlKind::StartScan,
                ScanState::Idle,
                ScanState::Running,
            ),
            (
                ScanControlKind::PauseScan,
                ScanState::Running,
                ScanState::Paused,
            ),
            (
                ScanControlKind::ResumeScan,
                ScanState::Paused,
                ScanState::Running,
            ),
            (
                ScanControlKind::ResumeScan,
                ScanState::ProvisionalPlanReady,
                ScanState::Running,
            ),
            (
                ScanControlKind::PauseAndBuildProvisionalPlan,
                ScanState::Running,
                ScanState::BuildingProvisionalPlan,
            ),
            (
                ScanControlKind::PauseAndBuildProvisionalPlan,
                ScanState::Paused,
                ScanState::BuildingProvisionalPlan,
            ),
            (
                ScanControlKind::CancelScan,
                ScanState::Running,
                ScanState::Cancelling,
            ),
            (
                ScanControlKind::CancelScan,
                ScanState::Paused,
                ScanState::Cancelling,
            ),
            (
                ScanControlKind::CancelScan,
                ScanState::BuildingProvisionalPlan,
                ScanState::Cancelling,
            ),
            (
                ScanControlKind::CancelScan,
                ScanState::ProvisionalPlanReady,
                ScanState::Cancelling,
            ),
        ];

        for control in controls {
            for current in states {
                for resulting in states {
                    assert_eq!(
                        accepted_transition_is_valid(control, current, resulting),
                        valid.contains(&(control, current, resulting)),
                        "{control:?}: {current:?} -> {resulting:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn impossible_control_acceptance_fails_terminally() {
        let mut state = pending_state(2, ScanControlKind::PauseScan);
        let effects = reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                1,
                2,
                engine_event::Body::ControlAccepted(ControlAccepted {
                    control: ScanControlKind::PauseScan as i32,
                    resulting_state: ScanState::Running as i32,
                }),
            ))),
        );

        assert_eq!(effects, vec![Effect::StopDriver]);
        assert!(matches!(state.terminal, Some(TerminalState::Failed(_))));
    }

    #[test]
    fn every_non_ack_variant_requires_the_active_nonzero_request() {
        let bodies = vec![
            engine_event::Body::ScanStateChanged(ScanStateChanged {
                state: ScanState::Running as i32,
                ..Default::default()
            }),
            engine_event::Body::ScanProgress(ScanProgress::default()),
            engine_event::Body::ProvisionalPlanReady(ProvisionalPlanReady::default()),
            engine_event::Body::ProvisionalPlanInvalidated(ProvisionalPlanInvalidated::default()),
            engine_event::Body::ScanCancelled(ScanCancelled::default()),
            engine_event::Body::ScanFinished(ScanFinished::default()),
            engine_event::Body::EngineFailed(EngineFailed::default()),
        ];

        for (index, body) in bodies.into_iter().enumerate() {
            for request_id in [0, 99] {
                let mut state = running_state();
                let effects = reduce(
                    &mut state,
                    UiEvent::Engine(EngineDelivery::exact(engine_event(
                        1,
                        request_id,
                        body.clone(),
                    ))),
                );
                assert_eq!(
                    effects,
                    vec![Effect::StopDriver],
                    "body {index}, id {request_id}"
                );
                assert!(matches!(state.terminal, Some(TerminalState::Failed(_))));
            }
        }
    }

    #[test]
    fn plan_invalidation_requires_the_exact_active_plan_id() {
        for plan_id in ["stale", ""] {
            let mut state = AppState {
                screen: Screen::ProvisionalPlan,
                scan_state: ScanState::Running,
                provisional_plan: Some(ProvisionalPlanReady {
                    plan_id: "current".into(),
                    ..Default::default()
                }),
                active_request: Some(ActiveRequest {
                    request_id: 3,
                    kind: ScanControlKind::ResumeScan,
                    phase: RequestPhase::AwaitingInvalidation,
                }),
                pending_controls: Vec::new(),
                banner: None,
                ..AppState::default()
            };
            let effects = reduce(
                &mut state,
                UiEvent::Engine(EngineDelivery::exact(engine_event(
                    1,
                    3,
                    engine_event::Body::ProvisionalPlanInvalidated(ProvisionalPlanInvalidated {
                        previous_plan_id: plan_id.into(),
                    }),
                ))),
            );
            assert_eq!(effects, vec![Effect::StopDriver]);
            assert!(matches!(state.terminal, Some(TerminalState::Failed(_))));
        }

        let mut unknown = AppState {
            scan_state: ScanState::Running,
            active_request: Some(ActiveRequest {
                request_id: 3,
                kind: ScanControlKind::ResumeScan,
                phase: RequestPhase::AwaitingInvalidation,
            }),
            pending_controls: Vec::new(),
            ..AppState::default()
        };
        let effects = reduce(
            &mut unknown,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                1,
                3,
                engine_event::Body::ProvisionalPlanInvalidated(ProvisionalPlanInvalidated {
                    previous_plan_id: "missing".into(),
                }),
            ))),
        );
        assert_eq!(effects, vec![Effect::StopDriver]);
        assert!(matches!(unknown.terminal, Some(TerminalState::Failed(_))));
    }

    #[test]
    fn reducer_accepts_only_exactly_proven_progress_gaps() {
        let mut state = running_state();
        let accepted = reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery {
                event: engine_event(
                    3,
                    1,
                    engine_event::Body::ScanProgress(ScanProgress {
                        entries: 3,
                        ..Default::default()
                    }),
                ),
                skipped_progress_events: 2,
            }),
        );
        assert!(accepted.is_empty());
        assert_eq!(state.last_event_sequence, 3);
        assert_eq!(
            state.progress.as_ref().map(|progress| progress.entries),
            Some(3)
        );

        for (sequence, skipped) in [(3, 0), (2, 0), (6, 1)] {
            let mut invalid = AppState {
                last_event_sequence: 3,
                ..running_state()
            };
            let effects = reduce(
                &mut invalid,
                UiEvent::Engine(EngineDelivery {
                    event: engine_event(
                        sequence,
                        1,
                        engine_event::Body::ScanProgress(ScanProgress::default()),
                    ),
                    skipped_progress_events: skipped,
                }),
            );
            assert_eq!(effects, vec![Effect::StopDriver]);
            assert!(matches!(invalid.terminal, Some(TerminalState::Failed(_))));
        }
    }

    #[test]
    fn request_id_overflow_fails_without_emitting_a_duplicate() {
        let mut state = running_state();
        state.next_request_id = u64::MAX;

        let effects = reduce(&mut state, key(' ', KeyEventKind::Press));

        assert_eq!(effects, vec![Effect::StopDriver]);
        assert!(state.pending_controls.is_empty());
        assert!(matches!(state.terminal, Some(TerminalState::Failed(_))));
    }

    fn running_state() -> AppState {
        let mut state = AppState {
            scan_state: ScanState::Running,
            banner: None,
            ..AppState::default()
        };
        state.pending_controls.clear();
        state.active_request = Some(ActiveRequest {
            request_id: 1,
            kind: ScanControlKind::StartScan,
            phase: RequestPhase::Steady,
        });
        state
    }

    fn pending_state(request_id: u64, kind: ScanControlKind) -> AppState {
        let mut state = running_state();
        state
            .pending_controls
            .push(PendingControl { request_id, kind });
        state
    }

    fn key(value: char, kind: KeyEventKind) -> UiEvent {
        UiEvent::Key(KeyEvent {
            code: KeyCode::Char(value),
            modifiers: KeyModifiers::NONE,
            kind,
            state: KeyEventState::NONE,
        })
    }

    fn engine_event(sequence: u64, request_id: u64, body: engine_event::Body) -> EngineEvent {
        EngineEvent {
            event_sequence: sequence,
            request_id,
            body: Some(body),
        }
    }
}
