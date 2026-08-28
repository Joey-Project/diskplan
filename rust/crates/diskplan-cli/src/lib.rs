#![forbid(unsafe_code)]

pub mod tui;

use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError, SyncSender};
use std::thread;
use std::time::{Duration, Instant};

use diskplan_core::framing::{FrameError, read_frame, write_frame};
use diskplan_core::handshake::{AcceptedHandshakeError, rust_client_hello, validate_accepted};
use diskplan_proto::diskplan::v1::{
    BusinessEnvelope, EngineEvent, Envelope, HelloAccepted, ScanControlKind, ScanControlRequest,
    StartScanRequest, envelope,
};
use prost::Message;
use thiserror::Error;

pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_GRACE: Duration = Duration::from_millis(250);
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);
const EXIT_OBSERVATION_GRACE: Duration = Duration::from_millis(50);
const HANDSHAKE_SEQUENCE: u64 = 1;
const FRAME_QUEUE_CAPACITY: usize = 1;

type FrameResult = Result<Option<Vec<u8>>, FrameError>;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("I/O error: {0}")]
    Io(#[from] io::Error),
    #[error("framing error: {0}")]
    Frame(#[from] FrameError),
    #[error("protobuf decode error: {0}")]
    Protobuf(#[from] prost::DecodeError),
    #[error("engine closed stdout before sending a complete response")]
    CleanEof,
    #[error("timed out waiting for engine {phase} after {timeout:?}")]
    Timeout {
        phase: &'static str,
        timeout: Duration,
    },
    #[error("engine sent an unexpected response during {phase}")]
    UnexpectedResponse { phase: &'static str },
    #[error("request_id must be non-zero")]
    InvalidRequestId,
    #[error("engine response sequence {actual} does not match request sequence {expected}")]
    ResponseSequenceMismatch { expected: u64, actual: u64 },
    #[error("engine event sequence {actual} does not immediately follow {previous}")]
    EventSequenceMismatch { previous: u64, actual: u64 },
    #[error("engine event sequence space is exhausted after {previous}")]
    EventSequenceExhausted { previous: u64 },
    #[error("engine event envelope sequence {envelope} does not match event sequence {event}")]
    EventEnvelopeSequenceMismatch { envelope: u64, event: u64 },
    #[error("engine rejected the request with code {code}: {detail}")]
    Rejected { code: i32, detail: String },
    #[error("engine handshake acceptance is invalid: {0}")]
    InvalidAcceptance(#[from] AcceptedHandshakeError),
    #[error("engine exited with status {code:?}")]
    EngineFailure { code: Option<i32> },
    #[error("engine exited after handshake instead of entering the ready state")]
    EngineExitedAfterHandshake,
    #[error("engine did not negotiate the required scan-control-v1 capability")]
    MissingScanControlCapability,
    #[error("engine emitted an extra framed message while shutting down")]
    ExtraFrameAfterShutdown,
    #[error("engine stdout decoder disconnected without reporting clean EOF")]
    DecoderDisconnected,
    #[error(
        "engine cleanup is incomplete: child {child_process_id} in process group \
         {process_group_id} did not exit after SIGKILL within {timeout:?}; reaping continues in \
         the background"
    )]
    CleanupIncomplete {
        child_process_id: u32,
        process_group_id: u32,
        timeout: Duration,
    },
    #[error(
        "engine cleanup is incomplete: process group {process_group_id} still exists after \
         SIGKILL and {timeout:?}"
    )]
    ProcessGroupCleanupIncomplete {
        process_group_id: u32,
        timeout: Duration,
    },
}

pub struct EngineSession {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    frames: Receiver<FrameResult>,
    response_timeout: Duration,
    accepted: HelloAccepted,
    last_event_sequence: u64,
    process_group_id: u32,
    reaper: SyncSender<Child>,
}

impl EngineSession {
    pub fn connect(engine: &Path) -> Result<Self, ClientError> {
        Self::connect_with_timeout(engine, DEFAULT_HANDSHAKE_TIMEOUT)
    }

    pub fn connect_with_timeout(engine: &Path, timeout: Duration) -> Result<Self, ClientError> {
        let mut command = Command::new(engine);
        Self::spawn_command(&mut command, timeout)
    }

    pub fn spawn_command(command: &mut Command, timeout: Duration) -> Result<Self, ClientError> {
        let reaper = spawn_reaper()?;
        command.process_group(0);
        let mut child = command
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;
        let stdin = child
            .stdin
            .take()
            .expect("Stdio::piped must create an engine stdin handle");
        let mut stdout = child
            .stdout
            .take()
            .expect("Stdio::piped must create an engine stdout handle");
        let (sender, frames) = mpsc::sync_channel(FRAME_QUEUE_CAPACITY);
        let process_group_id = child.id();
        thread::spawn(move || {
            loop {
                let result = read_frame(&mut stdout);
                let terminal = !matches!(result, Ok(Some(_)));
                if sender.send(result).is_err() || terminal {
                    break;
                }
            }
        });

        let mut session = Self {
            child: Some(child),
            stdin: Some(stdin),
            frames,
            response_timeout: timeout,
            accepted: HelloAccepted::default(),
            last_event_sequence: 0,
            process_group_id,
            reaper,
        };
        session.perform_handshake()?;
        Ok(session)
    }

    pub fn accepted(&self) -> &HelloAccepted {
        &self.accepted
    }

    pub fn request_business(
        &mut self,
        sequence: u64,
        message_type: impl Into<String>,
        payload: Vec<u8>,
    ) -> Result<Envelope, ClientError> {
        let request = Envelope {
            sequence,
            body: Some(envelope::Body::Business(BusinessEnvelope {
                r#type: message_type.into(),
                payload,
            })),
        };
        self.write_envelope(&request)?;
        let response = self.read_envelope("business response")?;
        if response.sequence != sequence {
            return Err(ClientError::ResponseSequenceMismatch {
                expected: sequence,
                actual: response.sequence,
            });
        }
        Ok(response)
    }

    pub fn send_start_scan(
        &mut self,
        request_id: u64,
        profile: impl Into<String>,
    ) -> Result<(), ClientError> {
        if request_id == 0 {
            return Err(ClientError::InvalidRequestId);
        }
        self.write_envelope(&Envelope {
            sequence: request_id,
            body: Some(envelope::Body::StartScanRequest(StartScanRequest {
                request_id,
                profile: profile.into(),
            })),
        })
    }

    pub fn send_scan_control(
        &mut self,
        request_id: u64,
        control: ScanControlKind,
    ) -> Result<(), ClientError> {
        if request_id == 0 {
            return Err(ClientError::InvalidRequestId);
        }
        self.write_envelope(&Envelope {
            sequence: request_id,
            body: Some(envelope::Body::ScanControlRequest(ScanControlRequest {
                request_id,
                control: control as i32,
            })),
        })
    }

    pub fn read_engine_event(&mut self) -> Result<EngineEvent, ClientError> {
        self.read_engine_event_with_timeout(self.response_timeout)
    }

    pub fn read_engine_event_with_timeout(
        &mut self,
        timeout: Duration,
    ) -> Result<EngineEvent, ClientError> {
        let envelope = self.read_envelope_with_timeout("engine event", timeout)?;
        let Some(envelope::Body::EngineEvent(event)) = envelope.body else {
            return Err(ClientError::UnexpectedResponse {
                phase: "engine event",
            });
        };
        if envelope.sequence != event.event_sequence {
            return Err(ClientError::EventEnvelopeSequenceMismatch {
                envelope: envelope.sequence,
                event: event.event_sequence,
            });
        }
        let expected =
            self.last_event_sequence
                .checked_add(1)
                .ok_or(ClientError::EventSequenceExhausted {
                    previous: self.last_event_sequence,
                })?;
        if event.event_sequence != expected {
            return Err(ClientError::EventSequenceMismatch {
                previous: self.last_event_sequence,
                actual: event.event_sequence,
            });
        }
        self.last_event_sequence = event.event_sequence;
        Ok(event)
    }

    pub fn shutdown(mut self) -> Result<(), ClientError> {
        self.stdin.take();
        let status = self.wait_or_terminate();
        let drain = self.drain_stdout();
        let status = status?;
        drain?;
        match status {
            status if status.success() => Ok(()),
            status => Err(ClientError::EngineFailure {
                code: status.code(),
            }),
        }
    }

    fn perform_handshake(&mut self) -> Result<(), ClientError> {
        let hello = rust_client_hello();
        let request = Envelope {
            sequence: HANDSHAKE_SEQUENCE,
            body: Some(envelope::Body::Hello(hello.clone())),
        };
        self.write_envelope(&request)?;
        let response = self.read_envelope("handshake response")?;
        if response.sequence != HANDSHAKE_SEQUENCE {
            return Err(ClientError::ResponseSequenceMismatch {
                expected: HANDSHAKE_SEQUENCE,
                actual: response.sequence,
            });
        }
        match response.body {
            Some(envelope::Body::HelloAccepted(accepted)) => {
                validate_accepted(&hello, HANDSHAKE_SEQUENCE, response.sequence, &accepted)?;
                if self.child_mut()?.try_wait()?.is_some() {
                    return Err(ClientError::EngineExitedAfterHandshake);
                }
                self.accepted = accepted;
                Ok(())
            }
            Some(envelope::Body::HelloRejected(rejected)) => Err(ClientError::Rejected {
                code: rejected.code,
                detail: rejected.detail,
            }),
            _ => Err(ClientError::UnexpectedResponse { phase: "handshake" }),
        }
    }

    fn write_envelope(&mut self, envelope: &Envelope) -> Result<(), ClientError> {
        let mut payload = Vec::new();
        envelope
            .encode(&mut payload)
            .expect("encoding into Vec cannot fail");
        let stdin = self.stdin.as_mut().ok_or_else(|| {
            ClientError::Io(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "engine stdin is closed",
            ))
        })?;
        write_frame(stdin, &payload)?;
        Ok(())
    }

    fn read_envelope(&mut self, phase: &'static str) -> Result<Envelope, ClientError> {
        self.read_envelope_with_timeout(phase, self.response_timeout)
    }

    fn read_envelope_with_timeout(
        &mut self,
        phase: &'static str,
        timeout: Duration,
    ) -> Result<Envelope, ClientError> {
        match self.frames.recv_timeout(timeout) {
            Ok(Ok(Some(payload))) => Ok(Envelope::decode(payload.as_slice())?),
            Ok(Ok(None)) | Err(RecvTimeoutError::Disconnected) => {
                if let Some(status) = self.observe_exit()? {
                    return Err(ClientError::EngineFailure {
                        code: status.code(),
                    });
                }
                Err(ClientError::CleanEof)
            }
            Ok(Err(error)) => Err(ClientError::Frame(error)),
            Err(RecvTimeoutError::Timeout) => Err(ClientError::Timeout { phase, timeout }),
        }
    }

    fn observe_exit(&mut self) -> Result<Option<ExitStatus>, io::Error> {
        let deadline = Instant::now() + EXIT_OBSERVATION_GRACE;
        loop {
            if let Some(status) = self.child_mut()?.try_wait()? {
                return Ok(Some(status));
            }
            if Instant::now() >= deadline {
                return Ok(None);
            }
            thread::sleep(Duration::from_millis(2));
        }
    }

    fn child_mut(&mut self) -> Result<&mut Child, io::Error> {
        self.child.as_mut().ok_or_else(|| {
            io::Error::new(io::ErrorKind::BrokenPipe, "engine process is unavailable")
        })
    }

    fn wait_or_terminate(&mut self) -> Result<ExitStatus, ClientError> {
        if let Ok(Some(status)) = wait_for_exit(self.child_mut()?, SHUTDOWN_GRACE) {
            return self.finish_reaped_child(status);
        }

        // Group signalling is best-effort until the directly owned child has either been
        // reaped or handed to the reaper. The child may have left the group, and an I/O
        // error while invoking `kill` must not make us drop its only wait handle.
        let _ = signal_process_group(self.process_group_id, "-TERM");
        if let Ok(Some(status)) = wait_for_exit(self.child_mut()?, SHUTDOWN_GRACE) {
            return self.finish_reaped_child(status);
        }

        let _ = signal_process_group(self.process_group_id, "-KILL");
        if let Ok(Some(status)) = wait_for_exit(self.child_mut()?, SHUTDOWN_GRACE) {
            return self.finish_reaped_child(status);
        }

        // The process-group kill cannot prove anything about a child that escaped the
        // original group. Target the Child itself, then poll only for a bounded interval.
        // Child::kill errors are followed by the same bounded observation because the
        // process may have exited concurrently.
        let _ = self.child_mut()?.kill();
        if let Ok(Some(status)) = wait_for_exit(self.child_mut()?, SHUTDOWN_GRACE) {
            return self.finish_reaped_child(status);
        }

        let child_process_id = self.handoff_live_child()?;
        let _ = terminate_remaining_process_group(self.process_group_id);
        Err(ClientError::CleanupIncomplete {
            child_process_id,
            process_group_id: self.process_group_id,
            timeout: SHUTDOWN_GRACE,
        })
    }

    fn finish_reaped_child(&mut self, status: ExitStatus) -> Result<ExitStatus, ClientError> {
        // try_wait already reaped the process, so releasing this handle cannot abandon a
        // live direct child even if descendant process-group cleanup fails afterwards.
        self.child.take();
        terminate_remaining_process_group(self.process_group_id)?;
        Ok(status)
    }

    fn handoff_live_child(&mut self) -> Result<u32, io::Error> {
        if let Ok(process_id) = self.try_handoff_child() {
            return Ok(process_id);
        }

        // A disconnected per-session reaper is not expected, but replace it before
        // retrying. try_handoff_child restores ownership on every failed send.
        self.reaper = spawn_reaper()?;
        self.try_handoff_child()
    }

    fn try_handoff_child(&mut self) -> Result<u32, io::Error> {
        let child = self
            .child
            .take()
            .expect("a running engine child must still be owned by the session");
        let process_id = child.id();
        match self.reaper.send(child) {
            Ok(()) => Ok(process_id),
            Err(error) => {
                self.child = Some(error.0);
                Err(io::Error::new(
                    io::ErrorKind::BrokenPipe,
                    "engine background reaper stopped unexpectedly",
                ))
            }
        }
    }

    fn drain_stdout(&mut self) -> Result<(), ClientError> {
        match self.frames.recv_timeout(SHUTDOWN_DRAIN_TIMEOUT) {
            Ok(Ok(Some(_))) => Err(ClientError::ExtraFrameAfterShutdown),
            Ok(Ok(None)) => Ok(()),
            Ok(Err(error)) => Err(ClientError::Frame(error)),
            Err(RecvTimeoutError::Disconnected) => Err(ClientError::DecoderDisconnected),
            Err(RecvTimeoutError::Timeout) => Err(ClientError::Timeout {
                phase: "shutdown stdout drain",
                timeout: SHUTDOWN_DRAIN_TIMEOUT,
            }),
        }
    }
}

impl Drop for EngineSession {
    fn drop(&mut self) {
        self.stdin.take();
        if self.child.is_some() {
            let _ = self.wait_or_terminate();
        }
    }
}

#[cfg(test)]
mod event_sequence_tests {
    use super::*;

    #[test]
    fn sequence_exhaustion_rejects_a_repeated_u64_max_event() {
        let repeated = Envelope {
            sequence: u64::MAX,
            body: Some(envelope::Body::EngineEvent(EngineEvent {
                event_sequence: u64::MAX,
                ..Default::default()
            })),
        };
        let (frame_sender, frames) = mpsc::sync_channel(FRAME_QUEUE_CAPACITY);
        frame_sender
            .send(Ok(Some(repeated.encode_to_vec())))
            .unwrap();
        let (reaper, _reaper_receiver) = mpsc::sync_channel(1);
        let mut session = EngineSession {
            child: None,
            stdin: None,
            frames,
            response_timeout: Duration::from_secs(1),
            accepted: HelloAccepted::default(),
            last_event_sequence: u64::MAX,
            process_group_id: 0,
            reaper,
        };

        let error = session
            .read_engine_event()
            .expect_err("u64::MAX cannot immediately follow itself");

        assert!(matches!(
            error,
            ClientError::EventSequenceExhausted { previous: u64::MAX }
        ));
        assert_eq!(session.last_event_sequence, u64::MAX);
    }
}

fn spawn_reaper() -> io::Result<SyncSender<Child>> {
    let (sender, receiver) = mpsc::sync_channel::<Child>(1);
    thread::Builder::new()
        .name("diskplan-engine-reaper".into())
        .spawn(move || {
            if let Ok(mut child) = receiver.recv() {
                let _ = child.wait();
            }
        })?;
    Ok(sender)
}

pub fn handshake_with_engine(engine: &Path) -> Result<Vec<String>, ClientError> {
    let session = EngineSession::connect(engine)?;
    let capabilities = session.accepted().negotiated_capabilities.clone();
    session.shutdown()?;
    Ok(capabilities)
}

fn wait_for_exit(child: &mut Child, timeout: Duration) -> io::Result<Option<ExitStatus>> {
    let deadline = Instant::now() + timeout;
    loop {
        if let Some(status) = child.try_wait()? {
            return Ok(Some(status));
        }
        if Instant::now() >= deadline {
            return Ok(None);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn terminate_remaining_process_group(process_group_id: u32) -> Result<(), ClientError> {
    if !process_group_exists(process_group_id)? {
        return Ok(());
    }
    signal_process_group(process_group_id, "-TERM")?;
    if wait_for_process_group_exit(process_group_id, SHUTDOWN_GRACE)? {
        return Ok(());
    }
    signal_process_group(process_group_id, "-KILL")?;
    if wait_for_process_group_exit(process_group_id, SHUTDOWN_GRACE)? {
        Ok(())
    } else {
        Err(ClientError::ProcessGroupCleanupIncomplete {
            process_group_id,
            timeout: SHUTDOWN_GRACE,
        })
    }
}

fn signal_process_group(process_group_id: u32, signal: &str) -> io::Result<()> {
    let group = format!("-{process_group_id}");
    let status = Command::new("/bin/kill")
        .args([signal, "--", &group])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() || !process_group_exists(process_group_id)? {
        Ok(())
    } else {
        Err(io::Error::other(format!(
            "/bin/kill {signal} failed for engine process group {process_group_id}"
        )))
    }
}

fn process_group_exists(process_group_id: u32) -> io::Result<bool> {
    let group = format!("-{process_group_id}");
    Ok(Command::new("/bin/kill")
        .args(["-0", "--", &group])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?
        .success())
}

fn wait_for_process_group_exit(process_group_id: u32, timeout: Duration) -> io::Result<bool> {
    let deadline = Instant::now() + timeout;
    loop {
        if !process_group_exists(process_group_id)? {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        thread::sleep(Duration::from_millis(5));
    }
}

#[cfg(test)]
mod cleanup_tests {
    use super::*;
    use std::io::Read;
    use std::os::unix::process::ExitStatusExt;

    const NONEXISTENT_PROCESS_GROUP: u32 = 2_000_000_000;

    #[test]
    fn direct_child_outside_recorded_group_is_killed_and_reaped_within_bound() {
        let child = spawn_blocking_fake_engine();
        let process_id = child.id();
        let mut session = test_session(child, spawn_reaper().unwrap());

        let started = Instant::now();
        let status = session
            .wait_or_terminate()
            .expect("direct child cleanup must complete");

        assert!(!status.success());
        assert_eq!(
            status.signal(),
            Some(9),
            "a child outside the recorded group must reach direct Child::kill"
        );
        assert!(session.child.is_none(), "the reaped Child must be released");
        assert!(
            started.elapsed() < Duration::from_secs(5),
            "direct child cleanup exceeded its bounded TERM/KILL windows"
        );
        assert!(
            !process_exists(process_id),
            "fake engine {process_id} survived direct Child::kill cleanup"
        );
    }

    #[test]
    fn failed_reaper_handoff_restores_child_ownership() {
        let child = spawn_blocking_fake_engine();
        let process_id = child.id();
        let (disconnected_reaper, receiver) = mpsc::sync_channel(1);
        drop(receiver);
        let mut session = test_session(child, disconnected_reaper);

        let error = session
            .try_handoff_child()
            .expect_err("the disconnected reaper must reject the child");

        assert_eq!(error.kind(), io::ErrorKind::BrokenPipe);
        assert_eq!(
            session.child.as_ref().map(Child::id),
            Some(process_id),
            "failed handoff must restore the exact Child handle"
        );

        session.child_mut().unwrap().kill().unwrap();
        let status = wait_for_exit(session.child_mut().unwrap(), Duration::from_secs(1))
            .unwrap()
            .expect("test cleanup must reap the fake engine");
        assert!(!status.success());
        session.child.take();
    }

    fn spawn_blocking_fake_engine() -> Child {
        let mut child = Command::new("/bin/bash")
            .args(["-c", "trap '' TERM; printf r; read -r _"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .expect("fake engine must start");
        let mut ready = [0_u8; 1];
        child
            .stdout
            .take()
            .unwrap()
            .read_exact(&mut ready)
            .expect("fake engine must install its TERM handler before blocking");
        assert_eq!(&ready, b"r");
        child
    }

    fn test_session(child: Child, reaper: SyncSender<Child>) -> EngineSession {
        let (_frame_sender, frames) = mpsc::sync_channel(FRAME_QUEUE_CAPACITY);
        EngineSession {
            child: Some(child),
            stdin: None,
            frames,
            response_timeout: Duration::from_secs(1),
            accepted: HelloAccepted::default(),
            last_event_sequence: 0,
            process_group_id: NONEXISTENT_PROCESS_GROUP,
            reaper,
        }
    }

    fn process_exists(process_id: u32) -> bool {
        Command::new("/bin/kill")
            .args(["-0", &process_id.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success())
    }
}
