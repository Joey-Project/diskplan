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
    BusinessEnvelope, EngineEvent, Envelope, HelloAccepted, ScanCheckpointChunk,
    ScanCheckpointChunkDescriptor, ScanCheckpointEvidence, ScanCheckpointManifest, ScanControlKind,
    ScanControlRequest, ScanRootRequest, ScannedNodeEvidence, StartScanRequest, engine_event,
    envelope,
};
use prost::Message;
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const DEFAULT_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const SHUTDOWN_GRACE: Duration = Duration::from_millis(250);
const SHUTDOWN_DRAIN_TIMEOUT: Duration = Duration::from_millis(250);
const EXIT_OBSERVATION_GRACE: Duration = Duration::from_millis(50);
const HANDSHAKE_SEQUENCE: u64 = 1;
const FRAME_QUEUE_CAPACITY: usize = 1;
const CHECKPOINT_MANIFEST_VERSION: u32 = 1;
const MAXIMUM_CHECKPOINT_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_CHECKPOINT_CHUNK_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
const MAXIMUM_CHECKPOINT_MANIFEST_BYTES: usize = 2 * 1024 * 1024;
const MAXIMUM_RETAINED_NODE_COUNT: usize = 10_000;
const MAXIMUM_RETAINED_NODE_PAYLOAD_BYTES: u64 = 768 * 1024 * 1024;
const CHECKPOINT_EVIDENCE_DIGEST_DOMAIN: &[u8] = b"diskplan/scan-checkpoint-evidence/v1\0";
const CHECKPOINT_FINAL_DIGEST_DOMAIN: &[u8] = b"diskplan/scan-checkpoint-final/v1\0";

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
    #[error("scan request_id {actual} must be greater than the previous request_id {previous}")]
    ScanRequestIdNotIncreasing { previous: u64, actual: u64 },
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
    #[error("engine did not negotiate the required scan-stream-v1 capability")]
    MissingScanStreamCapability,
    #[error("engine did not negotiate the required raw-path-bytes-v1 capability")]
    MissingRawPathCapability,
    #[error("engine event provenance is invalid: {0}")]
    InvalidEventProvenance(String),
    #[error("engine checkpoint stream is invalid: {0}")]
    InvalidCheckpointStream(String),
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

#[derive(Debug)]
struct CheckpointAccumulator {
    checkpoint_id: String,
    next_chunk_index: u32,
    descriptors: Vec<ScanCheckpointChunkDescriptor>,
    retained_nodes: Vec<ScannedNodeEvidence>,
    payload_bytes: u64,
}

pub struct EngineSession {
    child: Option<Child>,
    stdin: Option<ChildStdin>,
    frames: Receiver<FrameResult>,
    response_timeout: Duration,
    accepted: HelloAccepted,
    last_event_sequence: u64,
    scan_session_id: Option<String>,
    last_scan_request_id: u64,
    checkpoint_accumulator: Option<CheckpointAccumulator>,
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
            scan_session_id: None,
            last_scan_request_id: 0,
            checkpoint_accumulator: None,
            process_group_id,
            reaper,
        };
        session.perform_handshake()?;
        Ok(session)
    }

    pub fn accepted(&self) -> &HelloAccepted {
        &self.accepted
    }

    pub fn scan_session_id(&self) -> Option<&str> {
        self.scan_session_id.as_deref()
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
        self.send_start_scan_request(StartScanRequest {
            request_id,
            profile: profile.into(),
            roots: Vec::new(),
            maximum_duration_millis: 0,
            batch_size: 0,
        })
    }

    pub fn send_start_scan_request(
        &mut self,
        request: StartScanRequest,
    ) -> Result<(), ClientError> {
        self.reserve_scan_request_id(request.request_id)?;
        self.write_envelope(&Envelope {
            sequence: request.request_id,
            body: Some(envelope::Body::StartScanRequest(request)),
        })
    }

    pub fn scan_root(root_id: impl Into<String>, raw_absolute_path: Vec<u8>) -> ScanRootRequest {
        ScanRootRequest {
            root_id: root_id.into(),
            display_path: String::new(),
            raw_absolute_path,
        }
    }

    pub fn send_scan_control(
        &mut self,
        request_id: u64,
        control: ScanControlKind,
    ) -> Result<(), ClientError> {
        self.reserve_scan_request_id(request_id)?;
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
        let Some(envelope::Body::EngineEvent(mut event)) = envelope.body else {
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
        self.validate_event_provenance(&event)?;
        self.validate_checkpoint_event(&mut event)?;
        self.last_event_sequence = event.event_sequence;
        Ok(event)
    }

    fn validate_checkpoint_event(&mut self, event: &mut EngineEvent) -> Result<(), ClientError> {
        let Some(body) = event.body.take() else {
            return Err(ClientError::InvalidCheckpointStream(
                "engine event has no body".into(),
            ));
        };
        event.body = Some(match body {
            engine_event::Body::ScanCheckpointChunk(chunk) => {
                self.accept_checkpoint_chunk(&chunk)?;
                engine_event::Body::ScanCheckpointChunk(chunk)
            }
            engine_event::Body::ScanCheckpointReady(mut ready) => {
                if ready.checkpoint.is_some() {
                    return Err(ClientError::InvalidCheckpointStream(
                        "protocol 1.3 checkpoint populated the deprecated inline field".into(),
                    ));
                }
                let manifest = ready.manifest.as_ref().ok_or_else(|| {
                    ClientError::InvalidCheckpointStream(
                        "checkpoint-ready omitted its manifest".into(),
                    )
                })?;
                let checkpoint =
                    self.complete_checkpoint(&ready.canonical_checkpoint_payload, manifest)?;
                ready.checkpoint = Some(checkpoint);
                engine_event::Body::ScanCheckpointReady(ready)
            }
            engine_event::Body::ScanFinalized(mut finalized) => {
                if finalized.checkpoint.is_some() {
                    return Err(ClientError::InvalidCheckpointStream(
                        "protocol 1.3 finalization populated the deprecated inline field".into(),
                    ));
                }
                let manifest = finalized.manifest.as_ref().ok_or_else(|| {
                    ClientError::InvalidCheckpointStream("finalization omitted its manifest".into())
                })?;
                let checkpoint =
                    self.complete_checkpoint(&finalized.canonical_checkpoint_payload, manifest)?;
                finalized.checkpoint = Some(checkpoint);
                engine_event::Body::ScanFinalized(finalized)
            }
            engine_event::Body::EngineFailed(failed) => {
                self.checkpoint_accumulator = None;
                engine_event::Body::EngineFailed(failed)
            }
            other => other,
        });
        Ok(())
    }

    fn accept_checkpoint_chunk(&mut self, chunk: &ScanCheckpointChunk) -> Result<(), ClientError> {
        if chunk.checkpoint_id.is_empty() {
            return Err(invalid_checkpoint("chunk omitted checkpoint_id"));
        }
        if chunk.canonical_node_payload.is_empty() || chunk.node_count == 0 {
            return Err(invalid_checkpoint("checkpoint chunk is empty"));
        }
        if chunk.canonical_node_payload.len() > MAXIMUM_CHECKPOINT_CHUNK_PAYLOAD_BYTES {
            return Err(invalid_checkpoint(format!(
                "chunk payload is {} bytes; maximum is {}",
                chunk.canonical_node_payload.len(),
                MAXIMUM_CHECKPOINT_CHUNK_PAYLOAD_BYTES
            )));
        }
        let payload_digest = Sha256::digest(&chunk.canonical_node_payload).to_vec();
        if chunk.payload_sha256 != payload_digest {
            return Err(invalid_checkpoint("checkpoint chunk digest mismatch"));
        }
        let expected_chunk_id = format!("{}-{}", chunk.chunk_index, hex::encode(&payload_digest));
        if chunk.chunk_id != expected_chunk_id {
            return Err(invalid_checkpoint("checkpoint chunk_id is not canonical"));
        }
        let nodes = decode_canonical_node_payload(&chunk.canonical_node_payload)?;
        if nodes.len() != chunk.node_count as usize {
            return Err(invalid_checkpoint("checkpoint chunk node_count mismatch"));
        }

        let accumulator =
            self.checkpoint_accumulator
                .get_or_insert_with(|| CheckpointAccumulator {
                    checkpoint_id: chunk.checkpoint_id.clone(),
                    next_chunk_index: 0,
                    descriptors: Vec::new(),
                    retained_nodes: Vec::new(),
                    payload_bytes: 0,
                });
        if accumulator.checkpoint_id != chunk.checkpoint_id {
            return Err(invalid_checkpoint(
                "checkpoint chunks from different checkpoints were interleaved",
            ));
        }
        if chunk.chunk_index != accumulator.next_chunk_index {
            return Err(invalid_checkpoint(format!(
                "checkpoint chunk index {} did not match contiguous index {}",
                chunk.chunk_index, accumulator.next_chunk_index
            )));
        }
        if accumulator.retained_nodes.len() + nodes.len() > MAXIMUM_RETAINED_NODE_COUNT {
            return Err(invalid_checkpoint(format!(
                "checkpoint exceeds the {} retained-node protocol limit",
                MAXIMUM_RETAINED_NODE_COUNT
            )));
        }

        accumulator.next_chunk_index = accumulator
            .next_chunk_index
            .checked_add(1)
            .ok_or_else(|| invalid_checkpoint("checkpoint chunk index overflow"))?;
        accumulator.payload_bytes = accumulator
            .payload_bytes
            .checked_add(chunk.canonical_node_payload.len() as u64)
            .ok_or_else(|| invalid_checkpoint("checkpoint payload byte count overflow"))?;
        if accumulator.payload_bytes > MAXIMUM_RETAINED_NODE_PAYLOAD_BYTES {
            return Err(invalid_checkpoint(format!(
                "retained-node payload exceeds the {} byte protocol limit",
                MAXIMUM_RETAINED_NODE_PAYLOAD_BYTES
            )));
        }
        accumulator.descriptors.push(ScanCheckpointChunkDescriptor {
            chunk_index: chunk.chunk_index,
            chunk_id: chunk.chunk_id.clone(),
            node_count: chunk.node_count,
            payload_bytes: chunk.canonical_node_payload.len() as u64,
            payload_sha256: payload_digest,
        });
        accumulator.retained_nodes.extend(nodes);
        Ok(())
    }

    fn complete_checkpoint(
        &mut self,
        canonical_checkpoint_payload: &[u8],
        manifest: &ScanCheckpointManifest,
    ) -> Result<ScanCheckpointEvidence, ClientError> {
        validate_manifest_limits(manifest, canonical_checkpoint_payload)?;
        let checkpoint_digest = checkpoint_evidence_digest(canonical_checkpoint_payload);
        if manifest.checkpoint_evidence_sha256 != checkpoint_digest {
            return Err(invalid_checkpoint("checkpoint evidence digest mismatch"));
        }
        if manifest.final_evidence_sha256 != final_evidence_digest(manifest) {
            return Err(invalid_checkpoint(
                "checkpoint final evidence digest mismatch",
            ));
        }
        if manifest.checkpoint_id != hex::encode(&manifest.final_evidence_sha256) {
            return Err(invalid_checkpoint("checkpoint_id is not canonical"));
        }

        let mut checkpoint =
            ScanCheckpointEvidence::decode(canonical_checkpoint_payload).map_err(|error| {
                invalid_checkpoint(format!("checkpoint protobuf decode failed: {error}"))
            })?;
        if checkpoint.encode_to_vec() != canonical_checkpoint_payload {
            return Err(invalid_checkpoint(
                "checkpoint payload is not the canonical protobuf encoding",
            ));
        }
        if !checkpoint.retained_nodes.is_empty() {
            return Err(invalid_checkpoint(
                "checkpoint payload duplicated retained nodes outside chunks",
            ));
        }
        validate_manifest_frontier(manifest, &checkpoint)?;

        let accumulator = self.checkpoint_accumulator.take();
        let (descriptors, retained_nodes, payload_bytes, checkpoint_id) = match accumulator {
            Some(value) => (
                value.descriptors,
                value.retained_nodes,
                value.payload_bytes,
                Some(value.checkpoint_id),
            ),
            None => (Vec::new(), Vec::new(), 0, None),
        };
        if let Some(checkpoint_id) = checkpoint_id
            && checkpoint_id != manifest.checkpoint_id
        {
            return Err(invalid_checkpoint(
                "checkpoint manifest does not match accumulated chunks",
            ));
        }
        if manifest.chunks != descriptors {
            return Err(invalid_checkpoint(
                "checkpoint descriptors do not exactly match the contiguous chunk stream",
            ));
        }
        if manifest.chunk_count as usize != descriptors.len() {
            return Err(invalid_checkpoint("checkpoint chunk_count mismatch"));
        }
        if manifest.retained_node_count as usize != retained_nodes.len() {
            return Err(invalid_checkpoint(
                "checkpoint retained_node_count mismatch",
            ));
        }
        if manifest.retained_node_payload_bytes != payload_bytes {
            return Err(invalid_checkpoint(
                "checkpoint retained_node_payload_bytes mismatch",
            ));
        }
        checkpoint.retained_nodes = retained_nodes;
        Ok(checkpoint)
    }

    fn validate_event_provenance(&mut self, event: &EngineEvent) -> Result<(), ClientError> {
        let acknowledgement = matches!(
            event.body,
            Some(engine_event::Body::ControlAccepted(_))
                | Some(engine_event::Body::ControlRejected(_))
        );
        if acknowledgement {
            if event.request_id == 0 {
                return Err(ClientError::InvalidEventProvenance(
                    "control acknowledgement has request_id=0".into(),
                ));
            }
        } else if event.request_id != 0 {
            return Err(ClientError::InvalidEventProvenance(format!(
                "natural event has request_id={}",
                event.request_id
            )));
        }

        match self.scan_session_id.as_deref() {
            Some(expected) => {
                if event.scan_session_id.is_empty() {
                    return Err(ClientError::InvalidEventProvenance(
                        "event omitted the established scan_session_id".into(),
                    ));
                }
                if expected != event.scan_session_id {
                    return Err(ClientError::InvalidEventProvenance(
                        "scan_session_id changed during the session".into(),
                    ));
                }
            }
            None if !event.scan_session_id.is_empty() => {
                let starts_scan = matches!(
                    event.body,
                    Some(engine_event::Body::ControlAccepted(ref accepted))
                        if accepted.control == ScanControlKind::StartScan as i32
                );
                if !starts_scan {
                    return Err(ClientError::InvalidEventProvenance(
                        "scan_session_id was established outside an accepted StartScan".into(),
                    ));
                }
                self.scan_session_id = Some(event.scan_session_id.clone());
            }
            None if !acknowledgement => {
                return Err(ClientError::InvalidEventProvenance(
                    "natural event has no scan_session_id".into(),
                ));
            }
            None => {}
        }
        Ok(())
    }

    fn reserve_scan_request_id(&mut self, request_id: u64) -> Result<(), ClientError> {
        if request_id == 0 {
            return Err(ClientError::InvalidRequestId);
        }
        if request_id <= self.last_scan_request_id {
            return Err(ClientError::ScanRequestIdNotIncreasing {
                previous: self.last_scan_request_id,
                actual: request_id,
            });
        }
        // Reserve before writing: a failed or ambiguous write must not make an
        // already-used identifier locally retryable.
        self.last_scan_request_id = request_id;
        Ok(())
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

fn invalid_checkpoint(detail: impl Into<String>) -> ClientError {
    ClientError::InvalidCheckpointStream(detail.into())
}

fn decode_canonical_node_payload(payload: &[u8]) -> Result<Vec<ScannedNodeEvidence>, ClientError> {
    let mut offset = 0_usize;
    let mut nodes = Vec::new();
    while offset < payload.len() {
        let length_end = offset
            .checked_add(4)
            .ok_or_else(|| invalid_checkpoint("retained-node record offset overflow"))?;
        let length_bytes: [u8; 4] = payload
            .get(offset..length_end)
            .ok_or_else(|| invalid_checkpoint("truncated retained-node record length"))?
            .try_into()
            .expect("the checked slice has exactly four bytes");
        let record_length = u32::from_be_bytes(length_bytes) as usize;
        if record_length == 0 {
            return Err(invalid_checkpoint("retained-node record is empty"));
        }
        let record_end = length_end
            .checked_add(record_length)
            .ok_or_else(|| invalid_checkpoint("retained-node record length overflow"))?;
        let record = payload
            .get(length_end..record_end)
            .ok_or_else(|| invalid_checkpoint("truncated retained-node record"))?;
        let node = ScannedNodeEvidence::decode(record).map_err(|error| {
            invalid_checkpoint(format!("retained-node protobuf decode failed: {error}"))
        })?;
        if node.encode_to_vec() != record {
            return Err(invalid_checkpoint(
                "retained-node record is not the canonical protobuf encoding",
            ));
        }
        nodes.push(node);
        if nodes.len() > MAXIMUM_RETAINED_NODE_COUNT {
            return Err(invalid_checkpoint(format!(
                "checkpoint exceeds the {} retained-node protocol limit",
                MAXIMUM_RETAINED_NODE_COUNT
            )));
        }
        offset = record_end;
    }
    Ok(nodes)
}

fn validate_manifest_limits(
    manifest: &ScanCheckpointManifest,
    canonical_checkpoint_payload: &[u8],
) -> Result<(), ClientError> {
    if manifest.manifest_version != CHECKPOINT_MANIFEST_VERSION {
        return Err(invalid_checkpoint(format!(
            "unsupported checkpoint manifest version {}",
            manifest.manifest_version
        )));
    }
    if manifest.checkpoint_id.is_empty() {
        return Err(invalid_checkpoint(
            "checkpoint manifest omitted checkpoint_id",
        ));
    }
    if manifest.maximum_checkpoint_payload_bytes as usize != MAXIMUM_CHECKPOINT_PAYLOAD_BYTES
        || manifest.maximum_chunk_payload_bytes as usize != MAXIMUM_CHECKPOINT_CHUNK_PAYLOAD_BYTES
        || manifest.maximum_manifest_encoded_bytes as usize != MAXIMUM_CHECKPOINT_MANIFEST_BYTES
        || manifest.maximum_retained_node_payload_bytes != MAXIMUM_RETAINED_NODE_PAYLOAD_BYTES
    {
        return Err(invalid_checkpoint(
            "checkpoint manifest declared unsupported byte budgets",
        ));
    }
    if canonical_checkpoint_payload.len() > MAXIMUM_CHECKPOINT_PAYLOAD_BYTES {
        return Err(invalid_checkpoint(format!(
            "checkpoint payload is {} bytes; maximum is {}",
            canonical_checkpoint_payload.len(),
            MAXIMUM_CHECKPOINT_PAYLOAD_BYTES
        )));
    }
    if manifest.encode_to_vec().len() > MAXIMUM_CHECKPOINT_MANIFEST_BYTES {
        return Err(invalid_checkpoint(
            "checkpoint manifest exceeds its encoded budget",
        ));
    }
    if manifest.chunks.len() > MAXIMUM_RETAINED_NODE_COUNT
        || manifest.chunk_count as usize != manifest.chunks.len()
    {
        return Err(invalid_checkpoint(
            "checkpoint manifest chunk count is invalid",
        ));
    }
    if manifest.retained_node_entry_budget as usize > MAXIMUM_RETAINED_NODE_COUNT
        || manifest.retained_node_count > manifest.retained_node_entry_budget as u64
        || manifest.retained_node_payload_bytes > MAXIMUM_RETAINED_NODE_PAYLOAD_BYTES
    {
        return Err(invalid_checkpoint(
            "checkpoint manifest retained-node entry budget is invalid",
        ));
    }
    if manifest.checkpoint_evidence_sha256.len() != 32 || manifest.final_evidence_sha256.len() != 32
    {
        return Err(invalid_checkpoint(
            "checkpoint manifest SHA-256 fields must be 32 bytes",
        ));
    }
    Ok(())
}

fn validate_manifest_frontier(
    manifest: &ScanCheckpointManifest,
    checkpoint: &ScanCheckpointEvidence,
) -> Result<(), ClientError> {
    if manifest.frontier != checkpoint.progress
        || manifest.coverage != checkpoint.coverage
        || manifest.machine_state != checkpoint.machine_state
        || manifest.resumable_in_process != checkpoint.resumable_in_process
        || manifest.provisional != checkpoint.provisional
        || manifest.retained_node_entry_budget != checkpoint.retained_node_count
    {
        return Err(invalid_checkpoint(
            "checkpoint manifest coverage/frontier does not match checkpoint evidence",
        ));
    }
    let retained_nodes = checkpoint
        .progress
        .as_ref()
        .ok_or_else(|| invalid_checkpoint("checkpoint evidence omitted progress frontier"))?
        .retained_nodes;
    if retained_nodes != manifest.retained_node_count {
        return Err(invalid_checkpoint(
            "checkpoint frontier retained-node count does not match the chunk manifest",
        ));
    }
    let completed_root_ids = checkpoint
        .completed_roots
        .iter()
        .map(|root| {
            root.root
                .as_ref()
                .map(|root| root.root_id.clone())
                .ok_or_else(|| invalid_checkpoint("completed root omitted its root binding"))
        })
        .collect::<Result<Vec<_>, _>>()?;
    let failed_root_ids = checkpoint
        .root_failures
        .iter()
        .map(|failure| failure.root_id.clone())
        .collect::<Vec<_>>();
    if manifest.completed_root_ids != completed_root_ids
        || manifest.failed_root_ids != failed_root_ids
    {
        return Err(invalid_checkpoint(
            "checkpoint manifest root frontier does not match checkpoint evidence",
        ));
    }
    Ok(())
}

fn final_evidence_digest(manifest: &ScanCheckpointManifest) -> Vec<u8> {
    let mut canonical = Vec::from(CHECKPOINT_FINAL_DIGEST_DOMAIN);
    append_u32(manifest.manifest_version, &mut canonical);
    append_length_prefixed(&manifest.checkpoint_evidence_sha256, &mut canonical);
    append_u32(manifest.chunk_count, &mut canonical);
    append_u64(manifest.retained_node_count, &mut canonical);
    append_u32(manifest.retained_node_entry_budget, &mut canonical);
    append_u64(manifest.retained_node_payload_bytes, &mut canonical);
    append_u32(manifest.maximum_checkpoint_payload_bytes, &mut canonical);
    append_u32(manifest.maximum_chunk_payload_bytes, &mut canonical);
    append_u32(manifest.maximum_manifest_encoded_bytes, &mut canonical);
    append_u64(manifest.maximum_retained_node_payload_bytes, &mut canonical);
    for descriptor in &manifest.chunks {
        append_u32(descriptor.chunk_index, &mut canonical);
        append_length_prefixed(descriptor.chunk_id.as_bytes(), &mut canonical);
        append_u32(descriptor.node_count, &mut canonical);
        append_u64(descriptor.payload_bytes, &mut canonical);
        append_length_prefixed(&descriptor.payload_sha256, &mut canonical);
    }
    Sha256::digest(canonical).to_vec()
}

fn checkpoint_evidence_digest(payload: &[u8]) -> Vec<u8> {
    let mut canonical = Vec::with_capacity(CHECKPOINT_EVIDENCE_DIGEST_DOMAIN.len() + payload.len());
    canonical.extend_from_slice(CHECKPOINT_EVIDENCE_DIGEST_DOMAIN);
    canonical.extend_from_slice(payload);
    Sha256::digest(canonical).to_vec()
}

fn append_length_prefixed(value: &[u8], output: &mut Vec<u8>) {
    debug_assert!(u32::try_from(value.len()).is_ok());
    append_u32(value.len() as u32, output);
    output.extend_from_slice(value);
}

fn append_u32(value: u32, output: &mut Vec<u8>) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn append_u64(value: u64, output: &mut Vec<u8>) {
    output.extend_from_slice(&value.to_be_bytes());
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
    use diskplan_proto::diskplan::v1::{
        ControlAccepted, CoverageEvidence, RawPath, ScanCheckpointReady, ScanMachineState,
        ScanProgress, ScanState,
    };

    fn session_with_events(events: impl IntoIterator<Item = EngineEvent>) -> EngineSession {
        let (frame_sender, frames) = mpsc::sync_channel(16);
        for event in events {
            frame_sender
                .send(Ok(Some(
                    Envelope {
                        sequence: event.event_sequence,
                        body: Some(envelope::Body::EngineEvent(event)),
                    }
                    .encode_to_vec(),
                )))
                .unwrap();
        }
        let (reaper, _reaper_receiver) = mpsc::sync_channel(1);
        EngineSession {
            child: None,
            stdin: None,
            frames,
            response_timeout: Duration::from_secs(1),
            accepted: HelloAccepted::default(),
            last_event_sequence: 0,
            scan_session_id: None,
            last_scan_request_id: 0,
            checkpoint_accumulator: None,
            process_group_id: 0,
            reaper,
        }
    }

    fn accepted_start(sequence: u64) -> EngineEvent {
        EngineEvent {
            event_sequence: sequence,
            request_id: 1,
            scan_session_id: "scan-a".into(),
            body: Some(engine_event::Body::ControlAccepted(ControlAccepted {
                control: ScanControlKind::StartScan as i32,
                resulting_state: ScanState::Running as i32,
            })),
        }
    }

    fn valid_checkpoint_stream() -> (ScanCheckpointChunk, ScanCheckpointReady) {
        let node = ScannedNodeEvidence {
            path: Some(RawPath {
                root_id: "fixture".into(),
                components: vec![vec![0xff, 0x1b, 0x7f]],
                display_path: "\\xff\\x1b\\x7f".into(),
            }),
            ..Default::default()
        };
        let encoded_node = node.encode_to_vec();
        let mut node_payload = Vec::with_capacity(4 + encoded_node.len());
        append_u32(encoded_node.len() as u32, &mut node_payload);
        node_payload.extend_from_slice(&encoded_node);
        let payload_sha256 = Sha256::digest(&node_payload).to_vec();
        let chunk_id = format!("0-{}", hex::encode(&payload_sha256));

        let checkpoint = ScanCheckpointEvidence {
            profile: "full-audit".into(),
            retained_node_count: 10_000,
            progress: Some(ScanProgress {
                profile: "full-audit".into(),
                retained_nodes: 1,
                ..Default::default()
            }),
            coverage: Some(CoverageEvidence {
                complete: false,
                reasons: vec!["subtree_incomplete".into()],
            }),
            machine_state: ScanMachineState::Scanning as i32,
            resumable_in_process: true,
            ..Default::default()
        };
        let checkpoint_payload = checkpoint.encode_to_vec();
        let descriptor = ScanCheckpointChunkDescriptor {
            chunk_index: 0,
            chunk_id: chunk_id.clone(),
            node_count: 1,
            payload_bytes: node_payload.len() as u64,
            payload_sha256: payload_sha256.clone(),
        };
        let mut manifest = ScanCheckpointManifest {
            manifest_version: CHECKPOINT_MANIFEST_VERSION,
            chunk_count: 1,
            retained_node_count: 1,
            retained_node_entry_budget: 10_000,
            retained_node_payload_bytes: node_payload.len() as u64,
            maximum_checkpoint_payload_bytes: MAXIMUM_CHECKPOINT_PAYLOAD_BYTES as u32,
            maximum_chunk_payload_bytes: MAXIMUM_CHECKPOINT_CHUNK_PAYLOAD_BYTES as u32,
            maximum_manifest_encoded_bytes: MAXIMUM_CHECKPOINT_MANIFEST_BYTES as u32,
            chunks: vec![descriptor],
            checkpoint_evidence_sha256: checkpoint_evidence_digest(&checkpoint_payload),
            frontier: checkpoint.progress.clone(),
            coverage: checkpoint.coverage.clone(),
            machine_state: checkpoint.machine_state,
            resumable_in_process: checkpoint.resumable_in_process,
            provisional: checkpoint.provisional,
            maximum_retained_node_payload_bytes: MAXIMUM_RETAINED_NODE_PAYLOAD_BYTES,
            ..Default::default()
        };
        manifest.final_evidence_sha256 = final_evidence_digest(&manifest);
        manifest.checkpoint_id = hex::encode(&manifest.final_evidence_sha256);
        let chunk = ScanCheckpointChunk {
            checkpoint_id: manifest.checkpoint_id.clone(),
            chunk_index: 0,
            chunk_id,
            node_count: 1,
            canonical_node_payload: node_payload,
            payload_sha256,
        };
        let ready = ScanCheckpointReady {
            canonical_checkpoint_payload: checkpoint_payload,
            manifest: Some(manifest),
            ..Default::default()
        };
        (chunk, ready)
    }

    fn natural_event(sequence: u64, body: engine_event::Body) -> EngineEvent {
        EngineEvent {
            event_sequence: sequence,
            request_id: 0,
            scan_session_id: "scan-a".into(),
            body: Some(body),
        }
    }

    #[test]
    fn checkpoint_manifest_reassembles_raw_node_evidence_only_after_validation() {
        let (chunk, ready) = valid_checkpoint_stream();
        let mut session = session_with_events([
            accepted_start(1),
            natural_event(2, engine_event::Body::ScanCheckpointChunk(chunk)),
            natural_event(3, engine_event::Body::ScanCheckpointReady(ready)),
        ]);

        session.read_engine_event().unwrap();
        assert!(matches!(
            session.read_engine_event().unwrap().body,
            Some(engine_event::Body::ScanCheckpointChunk(_))
        ));
        let event = session.read_engine_event().unwrap();
        let Some(engine_event::Body::ScanCheckpointReady(ready)) = event.body else {
            panic!("expected verified checkpoint-ready event");
        };
        let checkpoint = ready.checkpoint.expect("verified checkpoint evidence");
        assert_eq!(checkpoint.retained_nodes.len(), 1);
        assert_eq!(
            checkpoint.retained_nodes[0]
                .path
                .as_ref()
                .unwrap()
                .components,
            [vec![0xff, 0x1b, 0x7f]]
        );
    }

    #[test]
    fn checkpoint_chunk_gap_or_duplicate_fails_before_manifest_visibility() {
        let (mut chunk, _) = valid_checkpoint_stream();
        chunk.chunk_index = 1;
        chunk.chunk_id = format!("1-{}", hex::encode(&chunk.payload_sha256));
        let mut session = session_with_events([
            accepted_start(1),
            natural_event(2, engine_event::Body::ScanCheckpointChunk(chunk)),
        ]);

        session.read_engine_event().unwrap();
        assert!(matches!(
            session.read_engine_event(),
            Err(ClientError::InvalidCheckpointStream(_))
        ));

        let (chunk, _) = valid_checkpoint_stream();
        let mut session = session_with_events([
            accepted_start(1),
            natural_event(2, engine_event::Body::ScanCheckpointChunk(chunk.clone())),
            natural_event(3, engine_event::Body::ScanCheckpointChunk(chunk)),
        ]);
        session.read_engine_event().unwrap();
        session.read_engine_event().unwrap();
        assert!(matches!(
            session.read_engine_event(),
            Err(ClientError::InvalidCheckpointStream(_))
        ));
    }

    #[test]
    fn checkpoint_digest_corruption_and_missing_chunk_fail_closed() {
        let (mut chunk, ready) = valid_checkpoint_stream();
        chunk.canonical_node_payload[4] ^= 0x01;
        let mut session = session_with_events([
            accepted_start(1),
            natural_event(2, engine_event::Body::ScanCheckpointChunk(chunk)),
        ]);
        session.read_engine_event().unwrap();
        assert!(matches!(
            session.read_engine_event(),
            Err(ClientError::InvalidCheckpointStream(_))
        ));

        let mut session = session_with_events([
            accepted_start(1),
            natural_event(2, engine_event::Body::ScanCheckpointReady(ready)),
        ]);
        session.read_engine_event().unwrap();
        assert!(matches!(
            session.read_engine_event(),
            Err(ClientError::InvalidCheckpointStream(_))
        ));
    }

    #[test]
    fn checkpoint_frontier_retained_count_must_match_verified_chunks() {
        let (mut chunk, mut ready) = valid_checkpoint_stream();
        let mut checkpoint =
            ScanCheckpointEvidence::decode(ready.canonical_checkpoint_payload.as_slice()).unwrap();
        checkpoint.progress.as_mut().unwrap().retained_nodes = 0;
        ready.canonical_checkpoint_payload = checkpoint.encode_to_vec();
        let manifest = ready.manifest.as_mut().unwrap();
        manifest.frontier = checkpoint.progress.clone();
        manifest.checkpoint_evidence_sha256 =
            checkpoint_evidence_digest(&ready.canonical_checkpoint_payload);
        manifest.final_evidence_sha256 = final_evidence_digest(manifest);
        manifest.checkpoint_id = hex::encode(&manifest.final_evidence_sha256);
        chunk.checkpoint_id = manifest.checkpoint_id.clone();

        let mut session = session_with_events([
            accepted_start(1),
            natural_event(2, engine_event::Body::ScanCheckpointChunk(chunk)),
            natural_event(3, engine_event::Body::ScanCheckpointReady(ready)),
        ]);
        session.read_engine_event().unwrap();
        session.read_engine_event().unwrap();
        let error = session.read_engine_event().unwrap_err();
        let ClientError::InvalidCheckpointStream(detail) = error else {
            panic!("expected invalid checkpoint stream, got {error:?}");
        };
        assert!(detail.contains("frontier retained-node count"));
    }

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
            scan_session_id: None,
            last_scan_request_id: 0,
            checkpoint_accumulator: None,
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

    #[test]
    fn natural_event_rejects_nonzero_request_provenance() {
        let mut session = session_with_events([EngineEvent {
            event_sequence: 1,
            request_id: 7,
            scan_session_id: "scan-a".into(),
            body: Some(engine_event::Body::ScanProgress(Default::default())),
        }]);

        let error = session
            .read_engine_event()
            .expect_err("natural events must not inherit a control request ID");

        assert!(matches!(error, ClientError::InvalidEventProvenance(_)));
        assert_eq!(session.last_event_sequence, 0);
        assert!(session.scan_session_id.is_none());
    }

    #[test]
    fn natural_event_cannot_establish_scan_session_identity() {
        let mut session = session_with_events([EngineEvent {
            event_sequence: 1,
            request_id: 0,
            scan_session_id: "scan-a".into(),
            body: Some(engine_event::Body::ScanProgress(Default::default())),
        }]);

        let error = session
            .read_engine_event()
            .expect_err("only an accepted StartScan may establish scan_session_id");

        assert!(matches!(error, ClientError::InvalidEventProvenance(_)));
        assert_eq!(session.last_event_sequence, 0);
        assert!(session.scan_session_id.is_none());
    }

    #[test]
    fn natural_event_rejects_scan_session_replacement() {
        let accepted_start = EngineEvent {
            event_sequence: 1,
            request_id: 1,
            scan_session_id: "scan-a".into(),
            body: Some(engine_event::Body::ControlAccepted(ControlAccepted {
                control: ScanControlKind::StartScan as i32,
                resulting_state: ScanState::Running as i32,
            })),
        };
        let event = |event_sequence, scan_session_id: &str| EngineEvent {
            event_sequence,
            request_id: 0,
            scan_session_id: scan_session_id.into(),
            body: Some(engine_event::Body::ScanProgress(Default::default())),
        };
        let mut session =
            session_with_events([accepted_start, event(2, "scan-a"), event(3, "scan-b")]);

        session.read_engine_event().unwrap();
        session.read_engine_event().unwrap();
        let error = session
            .read_engine_event()
            .expect_err("scan session identity must remain stable");

        assert!(matches!(error, ClientError::InvalidEventProvenance(_)));
        assert_eq!(session.last_event_sequence, 2);
        assert_eq!(session.scan_session_id.as_deref(), Some("scan-a"));
    }

    #[test]
    fn established_scan_session_is_required_on_later_acknowledgements() {
        let mut session = session_with_events([
            EngineEvent {
                event_sequence: 1,
                request_id: 1,
                scan_session_id: "scan-a".into(),
                body: Some(engine_event::Body::ControlAccepted(ControlAccepted {
                    control: ScanControlKind::StartScan as i32,
                    resulting_state: ScanState::Running as i32,
                })),
            },
            EngineEvent {
                event_sequence: 2,
                request_id: 9,
                scan_session_id: String::new(),
                body: Some(engine_event::Body::ControlRejected(Default::default())),
            },
        ]);

        session.read_engine_event().unwrap();
        assert_eq!(session.scan_session_id(), Some("scan-a"));
        let error = session
            .read_engine_event()
            .expect_err("an acknowledgement must retain established session identity");

        assert!(matches!(error, ClientError::InvalidEventProvenance(_)));
        assert_eq!(session.last_event_sequence, 1);
    }

    #[test]
    fn scan_request_id_is_reserved_before_an_ambiguous_write() {
        let mut session = session_with_events([]);

        assert!(matches!(
            session.send_scan_control(7, ScanControlKind::PauseScan),
            Err(ClientError::Io(_))
        ));
        assert!(matches!(
            session.send_scan_control(7, ScanControlKind::PauseScan),
            Err(ClientError::ScanRequestIdNotIncreasing {
                previous: 7,
                actual: 7
            })
        ));
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
            scan_session_id: None,
            last_scan_request_id: 0,
            checkpoint_accumulator: None,
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
