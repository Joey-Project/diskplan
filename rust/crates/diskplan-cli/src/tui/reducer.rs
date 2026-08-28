use crossterm::event::{KeyCode, KeyEventKind};
use diskplan_proto::diskplan::v1::{ScanControlKind, ScanState, engine_event};

use super::model::{AppState, Effect, EngineDelivery, Screen, TerminalState, UiEvent};

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
            state.take_pending(event.request_id);
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
        Some(engine_event::Body::ScanStateChanged(changed)) => {
            let Ok(scan_state) = ScanState::try_from(changed.state) else {
                return protocol_failure(state, "engine reported an unknown scan state".into());
            };
            if scan_state == ScanState::Unspecified {
                return protocol_failure(state, "engine reported an unspecified scan state".into());
            }
            state.scan_state = scan_state;
            state.banner = Some(changed.reason);
        }
        Some(engine_event::Body::ScanProgress(progress)) => {
            state.progress = Some(progress);
        }
        Some(engine_event::Body::ProvisionalPlanReady(plan)) => {
            state.provisional_plan = Some(plan);
            state.screen = Screen::ProvisionalPlan;
            state.help_visible = false;
        }
        Some(engine_event::Body::ProvisionalPlanInvalidated(_)) => {
            state.provisional_plan = None;
            state.screen = Screen::Scan;
            state.help_visible = false;
        }
        Some(engine_event::Body::ScanCancelled(cancelled)) => {
            state.scan_state = ScanState::Cancelled;
            state.terminal = Some(TerminalState::Cancelled(cancelled.reason));
        }
        Some(engine_event::Body::ScanFinished(finished)) => {
            state.scan_state = ScanState::Finished;
            state.terminal = Some(TerminalState::Finished(finished.summary));
        }
        Some(engine_event::Body::EngineFailed(failed)) => {
            state.scan_state = ScanState::Failed;
            state.terminal = Some(TerminalState::Failed(format!(
                "{}: {}",
                failed.code, failed.detail
            )));
        }
        None => {
            return protocol_failure(state, "engine emitted an empty event".into());
        }
    }
    Vec::new()
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
        ControlAccepted, ControlRejected, EngineEvent, ProvisionalPlanReady, ScanProgress,
        ScanState, engine_event,
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
                    detail: "too late".into(),
                    current_state: ScanState::Running as i32,
                    ..Default::default()
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
    fn reducer_accepts_only_exactly_proven_progress_gaps() {
        let mut state = running_state();
        let accepted = reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery {
                event: engine_event(
                    3,
                    0,
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
                        0,
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
