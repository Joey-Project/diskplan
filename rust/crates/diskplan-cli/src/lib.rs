#![forbid(unsafe_code)]

use std::io;
use std::os::unix::process::CommandExt;
use std::path::Path;
use std::process::{Child, ChildStdin, Command, ExitStatus, Stdio};
use std::sync::mpsc::{self, Receiver, RecvTimeoutError};
use std::thread;
use std::time::{Duration, Instant};

use diskplan_core::framing::{FrameError, read_frame, write_frame};
use diskplan_core::handshake::{AcceptedHandshakeError, rust_client_hello, validate_accepted};
use diskplan_proto::diskplan::v1::{BusinessEnvelope, Envelope, HelloAccepted, envelope};
use prost::Message;
use thiserror::Error;

pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_GRACE: Duration = Duration::from_millis(250);
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);
const EXIT_OBSERVATION_GRACE: Duration = Duration::from_millis(50);
const HANDSHAKE_SEQUENCE: u64 = 1;

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
    #[error("engine response sequence {actual} does not match request sequence {expected}")]
    ResponseSequenceMismatch { expected: u64, actual: u64 },
    #[error("engine rejected the request with code {code}: {detail}")]
    Rejected { code: i32, detail: String },
    #[error("engine handshake acceptance is invalid: {0}")]
    InvalidAcceptance(#[from] AcceptedHandshakeError),
    #[error("engine exited with status {code:?}")]
    EngineFailure { code: Option<i32> },
    #[error("engine exited after handshake instead of entering the ready state")]
    EngineExitedAfterHandshake,
    #[error("engine emitted an extra framed message while shutting down")]
    ExtraFrameAfterShutdown,
    #[error("engine stdout decoder disconnected without reporting clean EOF")]
    DecoderDisconnected,
}

pub struct EngineSession {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    frames: Receiver<FrameResult>,
    response_timeout: Duration,
    accepted: HelloAccepted,
    process_group_id: u32,
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
        let (sender, frames) = mpsc::channel();
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
            process_group_id,
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

    pub fn shutdown(mut self) -> Result<(), ClientError> {
        self.stdin.take();
        let status = self.wait_or_terminate();
        let drain = self.drain_stdout();
        self.child.take();
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
        match self.frames.recv_timeout(self.response_timeout) {
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
            Err(RecvTimeoutError::Timeout) => Err(ClientError::Timeout {
                phase,
                timeout: self.response_timeout,
            }),
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

    fn wait_or_terminate(&mut self) -> Result<ExitStatus, io::Error> {
        if let Some(status) = wait_for_exit(self.child_mut()?, SHUTDOWN_GRACE)? {
            terminate_remaining_process_group(self.process_group_id)?;
            return Ok(status);
        }

        signal_process_group(self.process_group_id, "-TERM")?;
        if let Some(status) = wait_for_exit(self.child_mut()?, SHUTDOWN_GRACE)? {
            terminate_remaining_process_group(self.process_group_id)?;
            return Ok(status);
        }

        signal_process_group(self.process_group_id, "-KILL")?;
        let status = self.child_mut()?.wait()?;
        if wait_for_process_group_exit(self.process_group_id, SHUTDOWN_GRACE)? {
            Ok(status)
        } else {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                format!(
                    "engine process group {} remained after SIGKILL",
                    self.process_group_id
                ),
            ))
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
        let _ = self.wait_or_terminate();
    }
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

fn terminate_remaining_process_group(process_group_id: u32) -> io::Result<()> {
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
        Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("engine process group {process_group_id} remained after SIGKILL"),
        ))
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
