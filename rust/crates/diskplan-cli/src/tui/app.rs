use std::io;

use ratatui::Terminal;
use ratatui::backend::Backend;

use super::event::EventSource;
use super::model::{AppState, ControlCommand, Effect, TerminalState, UiEvent};
use super::reducer::reduce;
use super::render::render;

pub trait ControlSink {
    fn send(&mut self, command: ControlCommand) -> io::Result<()>;
    fn stop(&mut self) -> io::Result<()>;
}

pub async fn run_application<B, S, C>(
    terminal: &mut Terminal<B>,
    source: &mut S,
    controls: &mut C,
) -> io::Result<AppState>
where
    B: Backend,
    B::Error: std::error::Error + Send + Sync + 'static,
    S: EventSource,
    C: ControlSink,
{
    let mut state = AppState::default();
    loop {
        terminal
            .draw(|frame| {
                state.resize_plan_layout(frame.area().width, frame.area().height);
                render(frame, &state);
            })
            .map_err(io::Error::other)?;
        if state.should_exit() {
            return Ok(state);
        }

        let event = source.next_event().await?;
        for effect in reduce(&mut state, event) {
            let result = match effect {
                Effect::SendControl(command) => controls
                    .send(command)
                    .map_err(|error| format!("failed to send engine control: {error}")),
                Effect::StopDriver => controls
                    .stop()
                    .map_err(|error| format!("failed to stop engine driver: {error}")),
            };
            if let Err(detail) = result {
                reduce(&mut state, UiEvent::DriverExited(Err(detail.clone())));
                state.terminal = Some(TerminalState::Failed(detail));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyCode, KeyEvent, KeyEventKind, KeyEventState, KeyModifiers};
    use diskplan_proto::diskplan::v1::{
        ControlAccepted, EngineEvent, ScanCancelled, ScanCheckpointEvidence, ScanControlKind,
        ScanFinalized, ScanMachineState, ScanProgress, ScanState, ScanStateChanged, engine_event,
    };
    use ratatui::backend::TestBackend;

    use super::super::event::ScriptedEventSource;
    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn scripted_engine_barriers_hold_each_transition_until_ack() {
        let events = vec![
            engine(
                1,
                1,
                engine_event::Body::ControlAccepted(ControlAccepted {
                    control: ScanControlKind::StartScan as i32,
                    resulting_state: ScanState::Running as i32,
                }),
            ),
            engine(2, 1, state_changed(ScanState::Running, "scan started")),
            engine(
                3,
                1,
                engine_event::Body::ScanProgress(ScanProgress::default()),
            ),
            key(' '),
            engine(
                4,
                2,
                engine_event::Body::ControlAccepted(ControlAccepted {
                    control: ScanControlKind::PauseScan as i32,
                    resulting_state: ScanState::Paused as i32,
                }),
            ),
            engine(5, 2, state_changed(ScanState::Paused, "pause acknowledged")),
            key(' '),
            engine(
                6,
                3,
                engine_event::Body::ControlAccepted(ControlAccepted {
                    control: ScanControlKind::ResumeScan as i32,
                    resulting_state: ScanState::Running as i32,
                }),
            ),
            engine(
                7,
                3,
                state_changed(ScanState::Running, "resume acknowledged"),
            ),
            engine(
                8,
                3,
                engine_event::Body::ScanProgress(ScanProgress::default()),
            ),
            key('q'),
            engine(
                9,
                4,
                engine_event::Body::ControlAccepted(ControlAccepted {
                    control: ScanControlKind::CancelScan as i32,
                    resulting_state: ScanState::Cancelling as i32,
                }),
            ),
            engine(
                10,
                4,
                state_changed(ScanState::Cancelling, "cancel acknowledged"),
            ),
            engine(11, 4, state_changed(ScanState::Cancelled, "scan cancelled")),
            engine(
                12,
                0,
                engine_event::Body::ScanFinalized(ScanFinalized {
                    checkpoint: Some(ScanCheckpointEvidence {
                        profile: "standard".into(),
                        machine_state: ScanMachineState::Cancelled as i32,
                        ..Default::default()
                    }),
                    reason: "scan cancelled".into(),
                    ..Default::default()
                }),
            ),
            engine(
                13,
                0,
                engine_event::Body::ScanCancelled(ScanCancelled {
                    reason: "script complete".into(),
                }),
            ),
            key('q'),
            UiEvent::DriverExited(Ok(())),
        ];
        let mut source = ScriptedEventSource::new(events);
        let mut sink = RecordingSink::default();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        let state = run_application(&mut terminal, &mut source, &mut sink)
            .await
            .unwrap();

        assert_eq!(
            sink.controls
                .iter()
                .map(|command| command.kind)
                .collect::<Vec<_>>(),
            [
                ScanControlKind::PauseScan,
                ScanControlKind::ResumeScan,
                ScanControlKind::CancelScan,
            ]
        );
        assert_eq!(state.scan_state, ScanState::Cancelled);
        assert!(state.should_exit());
    }

    #[tokio::test(flavor = "current_thread")]
    async fn protocol_failure_requests_driver_stop_and_waits_for_exit() {
        let events = vec![
            UiEvent::Engine(super::super::model::EngineDelivery::exact(EngineEvent {
                event_sequence: 1,
                request_id: 99,
                body: None,
                ..Default::default()
            })),
            UiEvent::DriverExited(Ok(())),
        ];
        let mut source = ScriptedEventSource::new(events);
        let mut sink = RecordingSink::default();
        let mut terminal = Terminal::new(TestBackend::new(80, 24)).unwrap();

        let state = run_application(&mut terminal, &mut source, &mut sink)
            .await
            .unwrap();

        assert!(sink.stopped);
        assert!(matches!(state.terminal, Some(TerminalState::Failed(_))));
        assert!(state.should_exit());
    }

    #[derive(Default)]
    struct RecordingSink {
        controls: Vec<ControlCommand>,
        stopped: bool,
    }

    impl ControlSink for RecordingSink {
        fn send(&mut self, command: ControlCommand) -> io::Result<()> {
            self.controls.push(command);
            Ok(())
        }

        fn stop(&mut self) -> io::Result<()> {
            self.stopped = true;
            Ok(())
        }
    }

    fn key(value: char) -> UiEvent {
        UiEvent::Key(KeyEvent {
            code: KeyCode::Char(value),
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        })
    }

    fn engine(sequence: u64, request_id: u64, body: engine_event::Body) -> UiEvent {
        UiEvent::Engine(super::super::model::EngineDelivery::exact(EngineEvent {
            event_sequence: sequence,
            request_id,
            body: Some(body),
            ..Default::default()
        }))
    }

    fn state_changed(state: ScanState, reason: &str) -> engine_event::Body {
        engine_event::Body::ScanStateChanged(ScanStateChanged {
            state: state as i32,
            reason: reason.into(),
        })
    }
}
