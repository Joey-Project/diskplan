use std::io;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use diskplan_proto::diskplan::v1::engine_event;

use crate::{BoundEngine, ClientError, EngineSession};

use super::event::{EngineEventIngress, EngineEventStream, engine_event_channel};
use super::model::ControlCommand;

const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(50);
const SEMANTIC_EVENT_CAPACITY: usize = 16;

enum DriverCommand {
    Control(ControlCommand),
    Stop,
}

pub struct EngineDriver {
    commands: Option<Sender<DriverCommand>>,
    worker: Option<JoinHandle<()>>,
}

impl EngineDriver {
    pub fn spawn(engine: &BoundEngine) -> io::Result<(Self, EngineEventStream)> {
        let engine = engine.clone();
        let (command_tx, command_rx) = mpsc::channel();
        let (event_tx, event_rx) = engine_event_channel(SEMANTIC_EVENT_CAPACITY)?;
        let worker = thread::Builder::new()
            .name("diskplan-engine-driver".into())
            .spawn(move || {
                let result = run_engine(&engine, command_rx, &event_tx);
                let _ = event_tx.send_driver_exited(result.map_err(|error| error.to_string()));
            })?;
        Ok((
            Self {
                commands: Some(command_tx),
                worker: Some(worker),
            },
            event_rx,
        ))
    }

    pub fn send_control(&self, control: ControlCommand) -> io::Result<()> {
        self.commands
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "engine driver stopped"))?
            .send(DriverCommand::Control(control))
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "engine driver stopped"))
    }

    pub fn request_stop(&self) -> io::Result<()> {
        self.commands
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "engine driver stopped"))?
            .send(DriverCommand::Stop)
            .map_err(|_| io::Error::new(io::ErrorKind::BrokenPipe, "engine driver stopped"))
    }
}

impl Drop for EngineDriver {
    fn drop(&mut self) {
        if let Some(commands) = self.commands.take() {
            let _ = commands.send(DriverCommand::Stop);
        }
        if let Some(worker) = self.worker.take() {
            let _ = worker.join();
        }
    }
}

fn run_engine(
    engine: &BoundEngine,
    commands: Receiver<DriverCommand>,
    events: &EngineEventIngress,
) -> Result<(), ClientError> {
    let mut session = EngineSession::connect_bound(engine)?;
    if !session
        .accepted()
        .negotiated_capabilities
        .iter()
        .any(|capability| capability == "scan-control-v1")
    {
        return Err(ClientError::MissingScanControlCapability);
    }
    session.send_start_scan(1, "standard")?;

    loop {
        loop {
            match commands.try_recv() {
                Ok(DriverCommand::Control(control)) => {
                    session.send_scan_control(control.request_id, control.kind)?;
                }
                Ok(DriverCommand::Stop) | Err(TryRecvError::Disconnected) => {
                    return session.shutdown();
                }
                Err(TryRecvError::Empty) => break,
            }
        }

        match session.read_engine_event_with_timeout(EVENT_POLL_INTERVAL) {
            Ok(event) => {
                let terminal = matches!(
                    event.body,
                    Some(engine_event::Body::ScanCancelled(_))
                        | Some(engine_event::Body::ScanFinished(_))
                        | Some(engine_event::Body::EngineFailed(_))
                );
                if events.send_engine_event(event).is_err() {
                    return session.shutdown();
                }
                if terminal {
                    return session.shutdown();
                }
            }
            Err(ClientError::Timeout {
                phase: "engine event",
                ..
            }) => {}
            Err(error) => return Err(error),
        }
    }
}

impl super::app::ControlSink for EngineDriver {
    fn send(&mut self, command: ControlCommand) -> io::Result<()> {
        self.send_control(command)
    }

    fn stop(&mut self) -> io::Result<()> {
        self.request_stop()
    }
}

#[cfg(test)]
mod tests {
    use diskplan_proto::diskplan::v1::ScanControlKind;

    use super::*;

    #[test]
    fn stop_message_variant_remains_distinct_from_scan_controls() {
        let stop = DriverCommand::Stop;
        assert!(matches!(stop, DriverCommand::Stop));
        let control = DriverCommand::Control(ControlCommand {
            request_id: 2,
            kind: ScanControlKind::PauseScan,
        });
        assert!(matches!(control, DriverCommand::Control(_)));
    }
}
