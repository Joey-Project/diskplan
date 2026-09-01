use std::io;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use diskplan_proto::diskplan::v1::{
    AgentMode, BuildPlanRequest, DecisionEditKind, DecisionOverlayAcknowledged,
    DecisionOverlayEdit, Digest256, OpaqueIdentifier, PrepareDryRunRequest, ScanMachineState,
    StageActionEdit, decision_overlay_edit, engine_event, runtime_event,
};
use diskplan_proto::runtime::PROTOCOL16_MINOR;
use diskplan_proto::sealed::RuntimeChainVerifier;

use crate::runtime_client::{
    PlanScanBinding, RuntimeClientError, edit_overlay, prepare_dry_run, receive_plan,
};
use crate::{BoundEngine, ClientError, EngineSession, SessionEvent};

use super::event::{EngineEventIngress, EngineEventStream, engine_event_channel};
use super::model::{ControlCommand, PlanCommand};
use super::plan::{
    ActionId, EngineOverlaySnapshot, PlanId, PlanIntentKind, PlanRuntimeEvent,
    snapshot_from_verified,
};

const EVENT_POLL_INTERVAL: Duration = Duration::from_millis(50);
const SEMANTIC_EVENT_CAPACITY: usize = 16;
const EXECUTION_STREAM_CAPABILITY: &str = "execution-stream-v1";

enum DriverCommand {
    Control(ControlCommand),
    Plan(PlanCommand),
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

    pub fn send_plan_command(&self, command: PlanCommand) -> io::Result<()> {
        self.commands
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "engine driver stopped"))?
            .send(DriverCommand::Plan(command))
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
    let mut session = EngineSession::connect_bound_with_runtime_capabilities(
        engine,
        Duration::from_secs(30),
        &[
            "plan-projection-v1",
            "decision-overlay-v1",
            "dry-run-projection-v1",
            EXECUTION_STREAM_CAPABILITY,
        ],
    )?;
    if !session
        .accepted()
        .negotiated_capabilities
        .iter()
        .any(|capability| capability == "scan-control-v1")
    {
        return Err(ClientError::MissingScanControlCapability);
    }
    if !session
        .accepted()
        .negotiated_capabilities
        .iter()
        .any(|capability| capability == "scan-stream-v1")
    {
        return Err(ClientError::MissingScanStreamCapability);
    }
    if !session
        .accepted()
        .negotiated_capabilities
        .iter()
        .any(|capability| capability == "raw-path-bytes-v1")
    {
        return Err(ClientError::MissingRawPathCapability);
    }
    session.send_start_scan(1, "standard")?;
    let mut runtime = DriverRuntime::new(&session);

    loop {
        loop {
            match commands.try_recv() {
                Ok(DriverCommand::Control(control)) => {
                    runtime.observe_external_request_id(control.request_id)?;
                    session.send_scan_control(control.request_id, control.kind)?;
                }
                Ok(DriverCommand::Plan(command)) => {
                    runtime.handle_plan_command(&mut session, events, command)?;
                }
                Ok(DriverCommand::Stop) | Err(TryRecvError::Disconnected) => {
                    return session.shutdown();
                }
                Err(TryRecvError::Empty) => break,
            }
        }

        match session.read_session_event_with_timeout(EVENT_POLL_INTERVAL) {
            Ok(SessionEvent::Scan(event)) => {
                let finalized = match event.body.as_ref() {
                    Some(engine_event::Body::ScanFinalized(finalized)) => {
                        Some((event.scan_session_id.clone(), finalized.clone()))
                    }
                    _ => None,
                };
                if events.send_engine_event(event).is_err() {
                    return session.shutdown();
                }
                if let Some((scan_session_id, finalized)) = finalized {
                    runtime.build_plan(&mut session, events, scan_session_id, &finalized)?;
                }
            }
            Ok(SessionEvent::Runtime(event)) => {
                runtime.handle_unsolicited_runtime(events, event)?
            }
            Err(ClientError::Timeout {
                phase: "session event",
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

    fn send_plan(&mut self, command: PlanCommand) -> io::Result<()> {
        self.send_plan_command(command)
    }

    fn stop(&mut self) -> io::Result<()> {
        self.request_stop()
    }
}

struct PlanAuthority {
    projection_id: OpaqueIdentifier,
    plan_id: PlanId,
    evidence_reference: String,
    chain: RuntimeChainVerifier,
    overlay: Option<DecisionOverlayAcknowledged>,
    build_request_id: u64,
}

struct DriverRuntime {
    next_request_id: u64,
    selected_minor: u32,
    capabilities: Vec<String>,
    plan: Option<PlanAuthority>,
}

impl DriverRuntime {
    fn new(session: &EngineSession) -> Self {
        Self {
            next_request_id: 2,
            selected_minor: session
                .accepted()
                .selected_version
                .as_ref()
                .map_or(0, |version| version.minor),
            capabilities: session.accepted().negotiated_capabilities.clone(),
            plan: None,
        }
    }

    fn observe_external_request_id(&mut self, request_id: u64) -> Result<(), ClientError> {
        if request_id < self.next_request_id {
            return Err(ClientError::RequestIdNotIncreasing {
                previous: self.next_request_id.saturating_sub(1),
                actual: request_id,
            });
        }
        self.next_request_id = request_id
            .checked_add(1)
            .ok_or(ClientError::InvalidRequestId)?;
        Ok(())
    }

    fn reserve_request_id(&mut self) -> Result<u64, ClientError> {
        let request_id = self.next_request_id;
        self.next_request_id = request_id
            .checked_add(1)
            .ok_or(ClientError::InvalidRequestId)?;
        Ok(request_id)
    }

    fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|value| value == capability)
    }

    fn build_plan(
        &mut self,
        session: &mut EngineSession,
        events: &EngineEventIngress,
        scan_session_id: String,
        finalized: &diskplan_proto::diskplan::v1::ScanFinalized,
    ) -> Result<(), ClientError> {
        if !self.has_capability("plan-projection-v1") {
            return events
                .send_plan_event(PlanRuntimeEvent::OperationRejected {
                    operation: "plan",
                    summary: "plan-projection-v1 was not negotiated".into(),
                })
                .map_err(ClientError::Io);
        }
        let checkpoint = finalized.checkpoint.as_ref().ok_or_else(|| {
            ClientError::InvalidRuntimeStream("finalized scan omitted checkpoint".into())
        })?;
        let manifest = finalized.manifest.as_ref().ok_or_else(|| {
            ClientError::InvalidRuntimeStream("finalized scan omitted manifest".into())
        })?;
        let machine_state = ScanMachineState::try_from(checkpoint.machine_state).map_err(|_| {
            ClientError::InvalidRuntimeStream("finalized scan has unknown state".into())
        })?;
        let allow_partial_evidence = match machine_state {
            ScanMachineState::Complete => false,
            ScanMachineState::Partial => true,
            _ => return Ok(()),
        };
        let request_id = self.reserve_request_id()?;
        session.send_build_plan_request(BuildPlanRequest {
            request_id,
            scan_session_id: Some(opaque(scan_session_id.as_bytes())),
            scan_checkpoint_id: Some(opaque(manifest.checkpoint_id.as_bytes())),
            scan_evidence_sha256: Some(Digest256 {
                value: manifest.final_evidence_sha256.clone(),
            }),
            allow_partial_evidence,
            agent_mode: AgentMode::Ask as i32,
        })?;
        let plan_scan_binding = PlanScanBinding {
            scan_session_id: scan_session_id.as_bytes().to_vec(),
            scan_checkpoint_id: manifest.checkpoint_id.as_bytes().to_vec(),
            scan_checkpoint_evidence_sha256: manifest.checkpoint_evidence_sha256.clone(),
            final_evidence_sha256: manifest.final_evidence_sha256.clone(),
        };
        let receipt = match receive_plan(session, request_id, &plan_scan_binding) {
            Ok(receipt) => receipt,
            Err(error) if error.is_unavailable() => {
                return events
                    .send_plan_event(PlanRuntimeEvent::OperationRejected {
                        operation: "plan",
                        summary: error.to_string(),
                    })
                    .map_err(ClientError::Io);
            }
            Err(error) => return Err(runtime_error(error)),
        };
        let snapshot = snapshot_from_verified(receipt.projection(), false)
            .map_err(|error| ClientError::InvalidRuntimeStream(error.to_string()))?;
        let projection_id = receipt
            .projection()
            .manifest()
            .projection_id
            .clone()
            .ok_or_else(|| {
                ClientError::InvalidRuntimeStream("plan omitted projection_id".into())
            })?;
        let plan_id = snapshot.projection.id.clone();
        let evidence_reference = snapshot.evidence_reference.clone();
        let chain = receipt.into_chain();
        self.plan = Some(PlanAuthority {
            projection_id,
            plan_id,
            evidence_reference,
            chain,
            overlay: None,
            build_request_id: request_id,
        });
        events
            .send_plan_event(PlanRuntimeEvent::Load(snapshot))
            .map_err(ClientError::Io)
    }

    fn handle_plan_command(
        &mut self,
        session: &mut EngineSession,
        events: &EngineEventIngress,
        command: PlanCommand,
    ) -> Result<(), ClientError> {
        match command {
            PlanCommand::EditStage(edit) => {
                if !self.has_capability("decision-overlay-v1") {
                    return send_rejection(events, "overlay edit", "capability was not negotiated");
                }
                let request_id = self.reserve_request_id()?;
                let plan = self.plan.as_mut().ok_or_else(|| {
                    ClientError::InvalidRuntimeStream("overlay edit has no plan".into())
                })?;
                let expected_revision = plan.overlay.as_ref().map_or(0, |value| value.revision);
                if edit.base_revision() != expected_revision {
                    return Err(ClientError::InvalidRuntimeStream(
                        "overlay edit base revision is stale".into(),
                    ));
                }
                let action_id = decode_action_id(edit.action_id())?;
                let edit_body = StageActionEdit {
                    action_id: Some(opaque(&action_id)),
                };
                let edit = DecisionOverlayEdit {
                    kind: if edit.stage() {
                        DecisionEditKind::StageAction as i32
                    } else {
                        DecisionEditKind::UnstageAction as i32
                    },
                    edit: Some(if edit.stage() {
                        decision_overlay_edit::Edit::StageAction(edit_body)
                    } else {
                        decision_overlay_edit::Edit::UnstageAction(edit_body)
                    }),
                };
                let predecessor = plan.overlay.clone();
                let acknowledged = match edit_overlay(
                    session,
                    request_id,
                    plan.projection_id.clone(),
                    expected_revision,
                    vec![edit],
                    predecessor.as_ref(),
                    &mut plan.chain,
                ) {
                    Ok(value) => value,
                    Err(error) if error.is_unavailable() => {
                        return send_rejection(events, "overlay edit", &error.to_string());
                    }
                    Err(error) => return Err(runtime_error(error)),
                };
                let snapshot = overlay_snapshot(plan, &acknowledged)?;
                plan.overlay = Some(acknowledged);
                events
                    .send_plan_event(PlanRuntimeEvent::OverlayAcknowledged(snapshot))
                    .map_err(ClientError::Io)
            }
            PlanCommand::Prepare(PlanIntentKind::DryRun) => {
                if !self.has_capability("dry-run-projection-v1") {
                    return send_rejection(events, "dry-run", "capability was not negotiated");
                }
                let request_id = self.reserve_request_id()?;
                let plan = self.plan.as_ref().ok_or_else(|| {
                    ClientError::InvalidRuntimeStream("dry-run has no plan".into())
                })?;
                let overlay = plan.overlay.as_ref().ok_or_else(|| {
                    ClientError::InvalidRuntimeStream("dry-run has no acknowledged overlay".into())
                })?;
                let receipt = match prepare_dry_run(
                    session,
                    PrepareDryRunRequest {
                        request_id,
                        projection_id: overlay.projection_id.clone(),
                        overlay_revision: overlay.revision,
                        overlay_sha256: overlay.overlay_sha256.clone(),
                        overlay_id: overlay.overlay_id.clone(),
                    },
                    &plan.chain,
                ) {
                    Ok(value) => value,
                    Err(error) if error.is_unavailable() => {
                        return send_rejection(events, "dry-run", &error.to_string());
                    }
                    Err(error) => return Err(runtime_error(error)),
                };
                events
                    .send_plan_event(PlanRuntimeEvent::DryRunReady {
                        current: receipt.manifest().current,
                        action_count: receipt.manifest().action_count,
                        finding_count: receipt.manifest().finding_count,
                    })
                    .map_err(ClientError::Io)
            }
            PlanCommand::Prepare(PlanIntentKind::ApplyReview) => {
                if let Err(reason) = validate_apply_review_transport(
                    self.selected_minor,
                    self.has_capability(EXECUTION_STREAM_CAPABILITY),
                ) {
                    return send_rejection(events, "apply review", reason);
                }
                send_rejection(
                    events,
                    "apply review",
                    "the authoritative apply-review transport is not implemented by this frontend",
                )
            }
        }
    }

    fn handle_unsolicited_runtime(
        &mut self,
        events: &EngineEventIngress,
        event: diskplan_proto::diskplan::v1::RuntimeEvent,
    ) -> Result<(), ClientError> {
        match event.body {
            Some(runtime_event::Body::PlanProjectionInvalidated(invalidated)) => {
                let plan = self.plan.take().ok_or_else(|| {
                    ClientError::InvalidRuntimeStream("invalidation has no live plan".into())
                })?;
                if event.request_id != plan.build_request_id
                    || invalidated.projection_id.as_ref() != Some(&plan.projection_id)
                {
                    return Err(ClientError::InvalidRuntimeStream(
                        "invalidation does not bind the live plan".into(),
                    ));
                }
                events
                    .send_plan_event(PlanRuntimeEvent::Invalidate {
                        plan_id: plan.plan_id,
                        reason: invalidated.summary,
                    })
                    .map_err(ClientError::Io)
            }
            _ => Err(ClientError::InvalidRuntimeStream(
                "unexpected asynchronous runtime event".into(),
            )),
        }
    }
}

fn validate_apply_review_transport(
    selected_minor: u32,
    has_execution_stream_capability: bool,
) -> Result<(), &'static str> {
    if selected_minor != PROTOCOL16_MINOR {
        return Err("exact protocol minor 1.6 is required for mutation review");
    }
    if !has_execution_stream_capability {
        return Err("execution-stream-v1 was not negotiated by the runtime controller");
    }
    Ok(())
}

fn send_rejection(
    events: &EngineEventIngress,
    operation: &'static str,
    summary: &str,
) -> Result<(), ClientError> {
    events
        .send_plan_event(PlanRuntimeEvent::OperationRejected {
            operation,
            summary: summary.into(),
        })
        .map_err(ClientError::Io)
}

fn overlay_snapshot(
    plan: &PlanAuthority,
    overlay: &DecisionOverlayAcknowledged,
) -> Result<EngineOverlaySnapshot, ClientError> {
    let digest = overlay
        .overlay_sha256
        .as_ref()
        .map(|value| value.value.as_slice())
        .filter(|value| value.len() == 32)
        .ok_or_else(|| ClientError::InvalidRuntimeStream("overlay omitted digest".into()))?;
    Ok(EngineOverlaySnapshot {
        plan_id: plan.plan_id.clone(),
        evidence_reference: plan.evidence_reference.clone(),
        selected_action_ids: overlay
            .selected_action_ids
            .iter()
            .map(|value| ActionId::new(hex::encode(&value.value)))
            .collect(),
        revision: overlay.revision,
        digest: hex::encode(digest),
    })
}

fn opaque(value: impl AsRef<[u8]>) -> OpaqueIdentifier {
    OpaqueIdentifier {
        value: value.as_ref().to_vec(),
    }
}

fn decode_action_id(action_id: &ActionId) -> Result<Vec<u8>, ClientError> {
    let decoded = hex::decode(action_id.as_str()).map_err(|_| {
        ClientError::InvalidRuntimeStream("plan action_id is not canonical hex".into())
    })?;
    if decoded.len() != 32 {
        return Err(ClientError::InvalidRuntimeStream(
            "plan action_id is not a digest".into(),
        ));
    }
    Ok(decoded)
}

fn runtime_error(error: RuntimeClientError) -> ClientError {
    match error {
        RuntimeClientError::Transport(error) => error,
        other => ClientError::InvalidRuntimeStream(other.to_string()),
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

    #[test]
    fn apply_review_transport_requires_exact_minor_and_execution_capability() {
        assert_eq!(
            validate_apply_review_transport(4, true),
            Err("exact protocol minor 1.6 is required for mutation review")
        );
        assert_eq!(
            validate_apply_review_transport(6, true),
            Err("exact protocol minor 1.6 is required for mutation review")
        );
        assert_eq!(
            validate_apply_review_transport(PROTOCOL16_MINOR, false),
            Err("execution-stream-v1 was not negotiated by the runtime controller")
        );
        assert_eq!(
            validate_apply_review_transport(PROTOCOL16_MINOR, true),
            Ok(())
        );
    }
}
