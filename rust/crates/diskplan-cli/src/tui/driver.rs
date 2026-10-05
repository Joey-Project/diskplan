use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::sync::mpsc::{self, Receiver, Sender, TryRecvError};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use diskplan_proto::diskplan::v1::{
    ApplyReviewProjection, BuildPlanRequest, CancelExecutionRequest, ConfirmApplyRequest,
    DecisionEditKind, DecisionOverlayAcknowledged, DecisionOverlayEdit, Digest256, Envelope,
    ExecutionStreamEvent, OpaqueIdentifier, PrepareApplyReviewRequest, PrepareDryRunRequest,
    RuntimeEvent, RuntimeRejectCode, ScanMachineState, StageActionEdit, decision_overlay_edit,
    engine_event, envelope, execution_stream_event, runtime_event,
};
use diskplan_proto::runtime::PROTOCOL16_MINOR;
use diskplan_proto::sealed::{
    MAXIMUM_EXECUTION_ENCODED_BYTES, MAXIMUM_EXECUTION_EVENT_COUNT, RuntimeChainVerifier,
};
use diskplan_proto::{CanonicalEnvelopeReceipt, decode_canonical_envelope};
use prost::Message;
use sha2::{Digest as ShaDigest, Sha256};

use crate::runtime_client::{
    PlanScanBinding, RuntimeClientError, edit_overlay_routed, prepare_apply_review_routed,
    prepare_dry_run_routed, receive_plan,
};
use crate::tui::InteractiveRuntimeOptions;
use crate::{BoundEngine, ClientError, EngineSession, SessionEvent};

use super::event::{EngineEventIngress, EngineEventStream, engine_event_channel};
use super::model::{ControlCommand, PlanCommand};
use super::plan::{
    ActionId, EngineApplyReviewSnapshot, EngineOverlaySnapshot, ExecutionCancelBinding,
    ExecutionPreviewProjection, ExecutionStatusProjection, ExecutionUnitId,
    ExecutionUnitProjection, ExecutionWarningId, ExecutionWarningProjection, PlanId, PlanIntent,
    PlanIntentKind, PlanRuntimeEvent, snapshot_from_verified,
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
    pub fn spawn(
        engine: &BoundEngine,
        options: InteractiveRuntimeOptions,
    ) -> io::Result<(Self, EngineEventStream)> {
        let engine = engine.clone();
        let (command_tx, command_rx) = mpsc::channel();
        let (event_tx, event_rx) = engine_event_channel(SEMANTIC_EVENT_CAPACITY)?;
        let worker = thread::Builder::new()
            .name("diskplan-engine-driver".into())
            .spawn(move || {
                let result = run_engine(&engine, options, command_rx, &event_tx);
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
    options: InteractiveRuntimeOptions,
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
    session.send_start_scan(1, options.profile.as_str())?;
    let mut runtime = DriverRuntime::new(&session, options.agent_mode);

    loop {
        loop {
            match commands.try_recv() {
                Ok(DriverCommand::Control(control)) => {
                    runtime.send_scan_control(&mut session, control)?;
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
            Ok(event) => runtime.handle_session_event(&mut session, events, event)?,
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
    review: Option<ApplyReviewProjection>,
    execution: Option<ExecutionAuthority>,
}

struct ExecutionAuthority {
    confirm_request_id: u64,
    confirm_envelope: CanonicalEnvelopeReceipt,
    cancel: Option<CancelMirrorAuthority>,
    execution_id: Option<Vec<u8>>,
    canonical_events: Vec<Vec<u8>>,
    canonical_event_count: u64,
    canonical_event_bytes: u64,
    canonical_digest: Sha256,
    cancel_requested: bool,
    pending_terminal: Option<ExecutionStatusProjection>,
}

struct CancelMirrorAuthority {
    request_id: u64,
    event_count: u64,
    encoded_bytes: u64,
    digest: Sha256,
    acknowledgement_seen: bool,
    terminal_seen: bool,
}

struct DriverRuntime {
    next_request_id: u64,
    selected_minor: u32,
    capabilities: Vec<String>,
    agent_mode: crate::batch::PlanningAgentMode,
    control_request_ids: BTreeMap<u64, u64>,
    plan: Option<PlanAuthority>,
}

impl DriverRuntime {
    fn new(session: &EngineSession, agent_mode: crate::batch::PlanningAgentMode) -> Self {
        let mut control_request_ids = BTreeMap::new();
        control_request_ids.insert(1, 1);
        Self {
            next_request_id: 2,
            selected_minor: session
                .accepted()
                .selected_version
                .as_ref()
                .map_or(0, |version| version.minor),
            capabilities: session.accepted().negotiated_capabilities.clone(),
            agent_mode,
            control_request_ids,
            plan: None,
        }
    }

    fn reserve_request_id(&mut self) -> Result<u64, ClientError> {
        let request_id = self.next_request_id;
        self.next_request_id = request_id
            .checked_add(1)
            .ok_or(ClientError::InvalidRequestId)?;
        Ok(request_id)
    }

    fn send_scan_control(
        &mut self,
        session: &mut EngineSession,
        control: ControlCommand,
    ) -> Result<(), ClientError> {
        let engine_request_id = self.reserve_control_request_id(control.request_id)?;
        if let Err(error) = session.send_scan_control(engine_request_id, control.kind) {
            self.control_request_ids.remove(&engine_request_id);
            return Err(error);
        }
        Ok(())
    }

    fn reserve_control_request_id(&mut self, local_request_id: u64) -> Result<u64, ClientError> {
        let engine_request_id = self.reserve_request_id()?;
        self.control_request_ids
            .insert(engine_request_id, local_request_id);
        Ok(engine_request_id)
    }

    fn project_control_request_id(&self, event: &mut diskplan_proto::diskplan::v1::EngineEvent) {
        if let Some(local_request_id) = self.control_request_ids.get(&event.request_id) {
            event.request_id = *local_request_id;
        }
    }

    fn has_capability(&self, capability: &str) -> bool {
        self.capabilities.iter().any(|value| value == capability)
    }

    fn handle_session_event(
        &mut self,
        session: &mut EngineSession,
        events: &EngineEventIngress,
        event: SessionEvent,
    ) -> Result<(), ClientError> {
        match event {
            SessionEvent::Scan(mut event) => {
                let plan_source = match event.body.as_ref() {
                    Some(engine_event::Body::ScanFinalized(finalized)) => Some((
                        event.scan_session_id.clone(),
                        finalized.checkpoint.clone(),
                        finalized.manifest.clone(),
                    )),
                    _ => None,
                };
                self.project_control_request_id(&mut event);
                events.send_engine_event(event).map_err(ClientError::Io)?;
                if let Some((scan_session_id, checkpoint, manifest)) = plan_source {
                    self.build_plan(
                        session,
                        events,
                        scan_session_id,
                        checkpoint.as_ref(),
                        manifest.as_ref(),
                    )?;
                }
                Ok(())
            }
            SessionEvent::Runtime(event) => self.handle_unsolicited_runtime(session, events, event),
        }
    }

    fn replay_pending_events(
        &mut self,
        session: &mut EngineSession,
        events: &EngineEventIngress,
        pending: Vec<SessionEvent>,
    ) -> Result<(), ClientError> {
        for event in pending {
            self.handle_session_event(session, events, event)?;
        }
        Ok(())
    }

    fn build_plan(
        &mut self,
        session: &mut EngineSession,
        events: &EngineEventIngress,
        scan_session_id: String,
        checkpoint: Option<&diskplan_proto::diskplan::v1::ScanCheckpointEvidence>,
        manifest: Option<&diskplan_proto::diskplan::v1::ScanCheckpointManifest>,
    ) -> Result<(), ClientError> {
        if !self.has_capability("plan-projection-v1") {
            return events
                .send_plan_event(PlanRuntimeEvent::OperationRejected {
                    operation: "plan",
                    summary: "plan-projection-v1 was not negotiated".into(),
                })
                .map_err(ClientError::Io);
        }
        let checkpoint = checkpoint.ok_or_else(|| {
            ClientError::InvalidRuntimeStream("plan source omitted checkpoint".into())
        })?;
        let manifest = manifest.ok_or_else(|| {
            ClientError::InvalidRuntimeStream("plan source omitted manifest".into())
        })?;
        let machine_state = ScanMachineState::try_from(checkpoint.machine_state).map_err(|_| {
            ClientError::InvalidRuntimeStream("finalized scan has unknown state".into())
        })?;
        let allow_partial_evidence = match machine_state {
            ScanMachineState::Complete => false,
            ScanMachineState::Partial => true,
            _ => return Ok(()),
        };
        let plan_scan_binding = PlanScanBinding {
            scan_session_id: scan_session_id.as_bytes().to_vec(),
            scan_checkpoint_id: manifest.checkpoint_id.as_bytes().to_vec(),
            scan_checkpoint_evidence_sha256: manifest.checkpoint_evidence_sha256.clone(),
            final_evidence_sha256: manifest.final_evidence_sha256.clone(),
        };
        let mut agent_mode = self.agent_mode;
        let (receipt, request_id) = loop {
            let request_id = self.reserve_request_id()?;
            session.send_build_plan_request(BuildPlanRequest {
                request_id,
                scan_session_id: Some(opaque(scan_session_id.as_bytes())),
                scan_checkpoint_id: Some(opaque(manifest.checkpoint_id.as_bytes())),
                scan_evidence_sha256: Some(Digest256 {
                    value: manifest.final_evidence_sha256.clone(),
                }),
                allow_partial_evidence,
                agent_mode: agent_mode.wire() as i32,
            })?;
            match receive_plan(session, request_id, &plan_scan_binding) {
                Ok(receipt) => break (receipt, request_id),
                Err(error)
                    if agent_mode != crate::batch::PlanningAgentMode::Off
                        && error.permits_agent_fallback() =>
                {
                    agent_mode = crate::batch::PlanningAgentMode::Off;
                }
                Err(error) if error.is_unavailable() => {
                    return events
                        .send_plan_event(PlanRuntimeEvent::OperationRejected {
                            operation: "plan",
                            summary: error.to_string(),
                        })
                        .map_err(ClientError::Io);
                }
                Err(error) => return Err(runtime_error(error)),
            }
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
            review: None,
            execution: None,
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
            PlanCommand::EditStage(visible_edit) => {
                if !self.has_capability("decision-overlay-v1") {
                    return send_rejection(events, "overlay edit", "capability was not negotiated");
                }
                if !self
                    .plan
                    .as_ref()
                    .is_some_and(|plan| overlay_stage_edit_matches(plan, &visible_edit))
                {
                    return send_rejection(
                        events,
                        "overlay edit",
                        "stale UI plan or overlay was not edited",
                    );
                }
                let request_id = self.reserve_request_id()?;
                let action_id = decode_action_id(visible_edit.action_id())?;
                let edit_body = StageActionEdit {
                    action_id: Some(opaque(&action_id)),
                };
                let wire_edit = DecisionOverlayEdit {
                    kind: if visible_edit.stage() {
                        DecisionEditKind::StageAction as i32
                    } else {
                        DecisionEditKind::UnstageAction as i32
                    },
                    edit: Some(if visible_edit.stage() {
                        decision_overlay_edit::Edit::StageAction(edit_body)
                    } else {
                        decision_overlay_edit::Edit::UnstageAction(edit_body)
                    }),
                };
                let mut pending = Vec::new();
                let result = {
                    let plan = self.plan.as_mut().expect("matching edit retains plan");
                    let expected_revision = plan.overlay.as_ref().map_or(0, |value| value.revision);
                    debug_assert_eq!(visible_edit.base_revision(), expected_revision);
                    let predecessor = plan.overlay.clone();
                    edit_overlay_routed(
                        session,
                        request_id,
                        plan.projection_id.clone(),
                        expected_revision,
                        vec![wire_edit],
                        predecessor.as_ref(),
                        &mut plan.chain,
                        &mut pending,
                    )
                };
                self.replay_pending_events(session, events, pending)?;
                let acknowledged = match result {
                    Ok(value) => value,
                    Err(error) if error.is_recoverable_operation_rejection() => {
                        return send_rejection(events, "overlay edit", &error.to_string());
                    }
                    Err(error) => return Err(runtime_error(error)),
                };
                if !self
                    .plan
                    .as_ref()
                    .is_some_and(|plan| overlay_stage_edit_matches(plan, &visible_edit))
                {
                    return send_rejection(
                        events,
                        "overlay edit",
                        "plan changed before the overlay acknowledgement was committed",
                    );
                }
                let plan = self.plan.as_mut().expect("rechecked edit retains plan");
                let snapshot = overlay_snapshot(plan, &acknowledged)?;
                plan.overlay = Some(acknowledged);
                plan.review = None;
                plan.execution = None;
                events
                    .send_plan_event(PlanRuntimeEvent::OverlayAcknowledged(snapshot))
                    .map_err(ClientError::Io)
            }
            PlanCommand::Prepare(intent) if intent.kind() == PlanIntentKind::DryRun => {
                if !self.has_capability("dry-run-projection-v1") {
                    return send_rejection(events, "dry-run", "capability was not negotiated");
                }
                if !self
                    .plan
                    .as_ref()
                    .is_some_and(|plan| plan_intent_matches(plan, &intent))
                {
                    return send_rejection(
                        events,
                        "dry-run",
                        "stale UI plan or overlay was not dry-run",
                    );
                }
                let request_id = self.reserve_request_id()?;
                let mut pending = Vec::new();
                let result = {
                    let plan = self.plan.as_ref().expect("matching dry-run retains plan");
                    let overlay = plan
                        .overlay
                        .as_ref()
                        .expect("matching dry-run retains overlay");
                    prepare_dry_run_routed(
                        session,
                        PrepareDryRunRequest {
                            request_id,
                            projection_id: overlay.projection_id.clone(),
                            overlay_revision: overlay.revision,
                            overlay_sha256: overlay.overlay_sha256.clone(),
                            overlay_id: overlay.overlay_id.clone(),
                        },
                        &plan.chain,
                        &mut pending,
                    )
                };
                self.replay_pending_events(session, events, pending)?;
                let receipt = match result {
                    Ok(value) => value,
                    Err(error) if error.is_recoverable_operation_rejection() => {
                        return send_rejection(events, "dry-run", &error.to_string());
                    }
                    Err(error) => return Err(runtime_error(error)),
                };
                if !self
                    .plan
                    .as_ref()
                    .is_some_and(|plan| plan_intent_matches(plan, &intent))
                {
                    return send_rejection(
                        events,
                        "dry-run",
                        "plan changed before the dry-run result was committed",
                    );
                }
                events
                    .send_plan_event(PlanRuntimeEvent::DryRunReady {
                        current: receipt.manifest().current,
                        action_count: receipt.manifest().action_count,
                        finding_count: receipt.manifest().finding_count,
                    })
                    .map_err(ClientError::Io)
            }
            PlanCommand::Prepare(intent) if intent.kind() == PlanIntentKind::ApplyReview => {
                if let Err(reason) = validate_apply_review_transport(
                    self.selected_minor,
                    self.has_capability(EXECUTION_STREAM_CAPABILITY),
                ) {
                    return send_rejection(events, "apply review", reason);
                }
                if !self
                    .plan
                    .as_ref()
                    .is_some_and(|plan| plan_intent_matches(plan, &intent))
                {
                    return send_rejection(
                        events,
                        "apply review",
                        "stale UI plan or overlay was not reviewed",
                    );
                }
                let request_id = self.reserve_request_id()?;
                if self
                    .plan
                    .as_ref()
                    .is_some_and(|plan| plan.execution.is_some())
                {
                    return send_rejection(events, "apply review", "execution is already active");
                }
                let mut pending = Vec::new();
                let result = {
                    let plan = self.plan.as_mut().expect("matching review retains plan");
                    let overlay = plan
                        .overlay
                        .as_ref()
                        .expect("matching review retains overlay");
                    prepare_apply_review_routed(
                        session,
                        PrepareApplyReviewRequest {
                            request_id,
                            projection_id: overlay.projection_id.clone(),
                            overlay_revision: overlay.revision,
                            overlay_sha256: overlay.overlay_sha256.clone(),
                            overlay_id: overlay.overlay_id.clone(),
                        },
                        &mut plan.chain,
                        &mut pending,
                    )
                };
                self.replay_pending_events(session, events, pending)?;
                let review = match result {
                    Ok(value) => value,
                    Err(error) if error.is_recoverable_operation_rejection() => {
                        return send_rejection(events, "apply review", &error.to_string());
                    }
                    Err(error) => return Err(runtime_error(error)),
                };
                if !self
                    .plan
                    .as_ref()
                    .is_some_and(|plan| plan_intent_matches(plan, &intent))
                {
                    return send_rejection(
                        events,
                        "apply review",
                        "plan changed before the apply review was committed",
                    );
                }
                let plan = self.plan.as_mut().expect("rechecked review retains plan");
                let (review_snapshot, preview) = apply_review_snapshot(plan, &review)?;
                plan.review = Some(review);
                events
                    .send_plan_event(PlanRuntimeEvent::ApplyReviewReady {
                        review: review_snapshot,
                        preview,
                    })
                    .map_err(ClientError::Io)
            }
            PlanCommand::ConfirmApply(visible_review) => {
                let review_matches = self.plan.as_ref().is_some_and(|plan| {
                    plan.execution.is_none()
                        && plan.review.as_ref().is_some_and(|review| {
                            apply_review_snapshot(plan, review)
                                .map(|(snapshot, _)| {
                                    exact_review_binding_matches(&snapshot, &visible_review)
                                })
                                .unwrap_or(false)
                        })
                });
                if !review_matches {
                    return send_rejection(
                        events,
                        "confirm apply",
                        "stale or replaced UI review was not confirmed",
                    );
                }
                let request_id = self.reserve_request_id()?;
                let plan = self.plan.as_mut().expect("matching review retains plan");
                let review = plan.review.as_ref().expect("matching review remains live");
                let confirm = ConfirmApplyRequest {
                    request_id,
                    apply_review_id: review.apply_review_id.clone(),
                    review_binding_sha256: review.review_binding_sha256.clone(),
                    confirmed_force_action_ids: review.force_warning_action_ids.clone(),
                };
                let confirm_envelope = canonical_envelope_receipt(Envelope {
                    sequence: request_id,
                    body: Some(envelope::Body::ConfirmApplyRequest(confirm.clone())),
                })?;
                session.send_confirm_apply_request(confirm)?;
                plan.execution = Some(ExecutionAuthority {
                    confirm_request_id: request_id,
                    confirm_envelope,
                    cancel: None,
                    execution_id: None,
                    canonical_events: Vec::new(),
                    canonical_event_count: 0,
                    canonical_event_bytes: 0,
                    canonical_digest: Sha256::new(),
                    cancel_requested: false,
                    pending_terminal: None,
                });
                events
                    .send_plan_event(PlanRuntimeEvent::ExecutionStatus(
                        ExecutionStatusProjection {
                            authority_generation: request_id,
                            execution_id: None,
                            event_count: 0,
                            summary: "Apply confirmed; waiting for ApplyStarted".into(),
                            cancel_requested: false,
                            terminal: false,
                            verified: false,
                        },
                    ))
                    .map_err(ClientError::Io)
            }
            PlanCommand::DismissApplyReview(visible_review) => {
                let review_matches = self.plan.as_ref().is_some_and(|plan| {
                    plan.execution.is_none()
                        && plan.review.as_ref().is_some_and(|review| {
                            apply_review_snapshot(plan, review)
                                .map(|(snapshot, _)| {
                                    exact_review_binding_matches(&snapshot, &visible_review)
                                })
                                .unwrap_or(false)
                        })
                });
                if !review_matches {
                    return send_rejection(
                        events,
                        "dismiss apply review",
                        "stale or replaced UI review was not dismissed",
                    );
                }
                let plan = self.plan.as_mut().expect("matching dismiss retains plan");
                plan.review = None;
                events
                    .send_plan_event(PlanRuntimeEvent::ApplyReviewDismissed)
                    .map_err(ClientError::Io)
            }
            PlanCommand::Prepare(_) => unreachable!("all plan intent kinds are handled"),
            PlanCommand::CancelExecution(visible_binding) => {
                let binding_matches = self
                    .plan
                    .as_ref()
                    .is_some_and(|plan| cancel_binding_matches(plan, &visible_binding));
                if !binding_matches {
                    return send_rejection(
                        events,
                        "cancel execution",
                        "stale UI execution authority; execution may already be terminal",
                    );
                }
                let (authority_generation, execution_id, event_count) = {
                    let plan = self.plan.as_mut().expect("matching cancel retains plan");
                    let execution = plan
                        .execution
                        .as_mut()
                        .expect("matching cancel retains execution");
                    if execution.cancel_requested {
                        return Ok(());
                    }
                    execution.cancel_requested = true;
                    (
                        execution.confirm_request_id,
                        execution.execution_id.clone(),
                        execution.canonical_events.len() as u64,
                    )
                };
                if let Some(execution_id) = execution_id.clone() {
                    let request_id = self.reserve_request_id()?;
                    session.send_cancel_execution_request(CancelExecutionRequest {
                        request_id,
                        execution_id: Some(opaque(execution_id)),
                    })?;
                    self.plan
                        .as_mut()
                        .and_then(|plan| plan.execution.as_mut())
                        .expect("active execution remains while cancellation is sent")
                        .cancel = Some(CancelMirrorAuthority {
                        request_id,
                        event_count: 0,
                        encoded_bytes: 0,
                        digest: Sha256::new(),
                        acknowledgement_seen: false,
                        terminal_seen: false,
                    });
                }
                events
                    .send_plan_event(PlanRuntimeEvent::ExecutionStatus(
                        ExecutionStatusProjection {
                            authority_generation,
                            execution_id: execution_id.as_ref().map(hex::encode),
                            event_count,
                            summary: if execution_id.is_some() {
                                "Cancellation sent; no new action should start".into()
                            } else {
                                "Cancellation queued until ApplyStarted supplies execution_id"
                                    .into()
                            },
                            cancel_requested: true,
                            terminal: false,
                            verified: false,
                        },
                    ))
                    .map_err(ClientError::Io)
            }
        }
    }

    fn handle_unsolicited_runtime(
        &mut self,
        session: &mut EngineSession,
        events: &EngineEventIngress,
        event: RuntimeEvent,
    ) -> Result<(), ClientError> {
        let request_id = event.request_id;
        let event_sequence = event.event_sequence;
        let runtime_session_id = event.runtime_session_id.clone();
        match event.body {
            Some(runtime_event::Body::PlanProjectionInvalidated(invalidated)) => {
                let plan = self.plan.take().ok_or_else(|| {
                    ClientError::InvalidRuntimeStream("invalidation has no live plan".into())
                })?;
                if request_id != plan.build_request_id
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
            Some(runtime_event::Body::ExecutionStreamEvent(stream)) => {
                self.handle_execution_event(session, events, request_id, stream)
            }
            Some(runtime_event::Body::RuntimeRejected(rejected)) => {
                let plan = self.plan.as_mut().ok_or_else(|| {
                    ClientError::InvalidRuntimeStream("runtime rejection has no live plan".into())
                })?;
                let execution = plan.execution.as_ref().ok_or_else(|| {
                    ClientError::InvalidRuntimeStream(
                        "runtime rejection has no active execution".into(),
                    )
                })?;
                let is_confirm = request_id == execution.confirm_request_id;
                let is_cancel = execution
                    .cancel
                    .as_ref()
                    .is_some_and(|cancel| cancel.request_id == request_id);
                let execution_id = execution.execution_id.as_ref().map(hex::encode);
                let event_count = execution.canonical_events.len() as u64;
                let authority_generation = execution.confirm_request_id;
                if is_confirm {
                    if rejected.code == RuntimeRejectCode::ConfirmationMismatch as i32 {
                        let rejection_envelope = canonical_envelope_receipt(Envelope {
                            sequence: event_sequence,
                            body: Some(envelope::Body::RuntimeEvent(RuntimeEvent {
                                event_sequence,
                                request_id,
                                runtime_session_id: runtime_session_id.clone(),
                                body: Some(runtime_event::Body::RuntimeRejected(rejected.clone())),
                            })),
                        })?;
                        let expected_session_id = runtime_session_id
                            .as_ref()
                            .map(|identifier| identifier.value.as_slice())
                            .filter(|value| !value.is_empty())
                            .ok_or_else(|| {
                                ClientError::InvalidRuntimeStream(
                                    "confirm rejection omitted runtime_session_id".into(),
                                )
                            })?;
                        let plan = self.plan.as_mut().expect("live plan was verified above");
                        let confirm_envelope = plan
                            .execution
                            .as_ref()
                            .expect("live execution was verified above")
                            .confirm_envelope
                            .clone();
                        plan.chain
                            .verify_rejected_confirm(
                                &confirm_envelope,
                                &rejection_envelope,
                                expected_session_id,
                            )
                            .map_err(|error| {
                                ClientError::InvalidRuntimeStream(error.to_string())
                            })?;
                        plan.execution = None;
                        plan.review = None;
                        events
                            .send_plan_event(PlanRuntimeEvent::ExecutionStatus(
                                ExecutionStatusProjection {
                                    authority_generation,
                                    execution_id: None,
                                    event_count: 0,
                                    summary: format!(
                                        "Apply confirmation rejected by verified binding: {}",
                                        rejected.summary
                                    ),
                                    cancel_requested: false,
                                    terminal: true,
                                    verified: true,
                                },
                            ))
                            .map_err(ClientError::Io)
                    } else {
                        let plan = self.plan.as_mut().expect("live plan was verified above");
                        plan.execution = None;
                        events
                            .send_plan_event(PlanRuntimeEvent::ConfirmApplyRejected {
                                summary: rejected.summary,
                            })
                            .map_err(ClientError::Io)
                    }
                } else if is_cancel {
                    self.plan
                        .as_mut()
                        .and_then(|plan| plan.execution.as_mut())
                        .expect("live execution was verified above")
                        .cancel = None;
                    if let Some(terminal) = take_ready_execution_terminal(&mut self.plan)? {
                        events
                            .send_plan_event(PlanRuntimeEvent::ExecutionStatus(terminal))
                            .map_err(ClientError::Io)
                    } else {
                        events
                            .send_plan_event(PlanRuntimeEvent::ExecutionStatus(
                                ExecutionStatusProjection {
                                    authority_generation,
                                    execution_id,
                                    event_count,
                                    summary: format!("Cancellation rejected: {}", rejected.summary),
                                    cancel_requested: true,
                                    terminal: false,
                                    verified: false,
                                },
                            ))
                            .map_err(ClientError::Io)
                    }
                } else {
                    Err(ClientError::InvalidRuntimeStream(
                        "runtime rejection has an unrelated request ID".into(),
                    ))
                }
            }
            _ => Err(ClientError::InvalidRuntimeStream(
                "unexpected asynchronous runtime event".into(),
            )),
        }
    }

    fn handle_execution_event(
        &mut self,
        session: &mut EngineSession,
        events: &EngineEventIngress,
        request_id: u64,
        stream: ExecutionStreamEvent,
    ) -> Result<(), ClientError> {
        let is_cancel_stream = self
            .plan
            .as_ref()
            .and_then(|plan| plan.execution.as_ref())
            .and_then(|execution| execution.cancel.as_ref())
            .is_some_and(|cancel| cancel.request_id == request_id);
        if is_cancel_stream {
            let plan = self.plan.as_mut().ok_or_else(|| {
                ClientError::InvalidRuntimeStream("cancel stream has no live plan".into())
            })?;
            let execution = plan.execution.as_mut().ok_or_else(|| {
                ClientError::InvalidRuntimeStream("cancel stream has no active execution".into())
            })?;
            let encoded = stream.encode_to_vec();
            validate_execution_id(execution, &stream)?;
            let cancel = execution
                .cancel
                .as_mut()
                .expect("cancel route was verified");
            admit_execution_record(
                &mut cancel.event_count,
                &mut cancel.encoded_bytes,
                &mut cancel.digest,
                &encoded,
                execution_event_is_terminal(&stream),
            )?;
            if matches!(
                stream.body.as_ref(),
                Some(execution_stream_event::Body::CancellationAcknowledged(_))
            ) {
                if cancel.acknowledgement_seen {
                    return Err(ClientError::InvalidRuntimeStream(
                        "cancel stream repeated its typed acknowledgement".into(),
                    ));
                }
                cancel.acknowledgement_seen = true;
            }
            if execution_event_is_terminal(&stream) {
                cancel.terminal_seen = true;
            }
            let summary = execution_event_summary(&stream);
            let waiting_status = ExecutionStatusProjection {
                authority_generation: execution.confirm_request_id,
                execution_id: execution.execution_id.as_ref().map(hex::encode),
                event_count: execution.canonical_events.len() as u64,
                summary: format!("{summary}; verifying mirrored cancel stream"),
                cancel_requested: true,
                terminal: false,
                verified: false,
            };
            if let Some(terminal) = take_ready_execution_terminal(&mut self.plan)? {
                return events
                    .send_plan_event(PlanRuntimeEvent::ExecutionStatus(terminal))
                    .map_err(ClientError::Io);
            }
            return events
                .send_plan_event(PlanRuntimeEvent::ExecutionStatus(waiting_status))
                .map_err(ClientError::Io);
        }

        let mut cancel_after_started = None;
        let status = {
            let plan = self.plan.as_mut().ok_or_else(|| {
                ClientError::InvalidRuntimeStream("execution event has no live plan".into())
            })?;
            let execution = plan.execution.as_mut().ok_or_else(|| {
                ClientError::InvalidRuntimeStream("execution event has no active execution".into())
            })?;
            if request_id != execution.confirm_request_id {
                return Err(ClientError::InvalidRuntimeStream(
                    "execution event has an unrelated request ID".into(),
                ));
            }
            let encoded = stream.encode_to_vec();
            let outer_execution_id = validate_execution_id(execution, &stream)?;
            if let Some(execution_stream_event::Body::ApplyStarted(_)) = stream.body.as_ref()
                && execution.cancel_requested
                && execution.cancel.is_none()
            {
                cancel_after_started = Some(outer_execution_id);
            }
            admit_execution_record(
                &mut execution.canonical_event_count,
                &mut execution.canonical_event_bytes,
                &mut execution.canonical_digest,
                &encoded,
                execution_event_is_terminal(&stream),
            )?;
            execution.canonical_events.push(encoded);
            let summary = execution_event_summary(&stream);
            if execution_event_is_terminal(&stream) {
                plan.chain
                    .verify_execution_stream(&execution.canonical_events)
                    .map_err(|error| ClientError::InvalidRuntimeStream(error.to_string()))?;
                execution.pending_terminal = Some(ExecutionStatusProjection {
                    authority_generation: execution.confirm_request_id,
                    execution_id: execution.execution_id.as_ref().map(hex::encode),
                    event_count: execution.canonical_events.len() as u64,
                    summary: format!("{summary}; complete stream binding verified"),
                    cancel_requested: execution.cancel_requested,
                    terminal: true,
                    verified: true,
                });
            }
            ExecutionStatusProjection {
                authority_generation: execution.confirm_request_id,
                execution_id: execution.execution_id.as_ref().map(hex::encode),
                event_count: execution.canonical_events.len() as u64,
                summary,
                cancel_requested: execution.cancel_requested,
                terminal: false,
                verified: false,
            }
        };

        if let Some(execution_id) = cancel_after_started {
            let cancel_request_id = self.reserve_request_id()?;
            session.send_cancel_execution_request(CancelExecutionRequest {
                request_id: cancel_request_id,
                execution_id: Some(opaque(execution_id)),
            })?;
            let execution = self
                .plan
                .as_mut()
                .and_then(|plan| plan.execution.as_mut())
                .ok_or_else(|| {
                    ClientError::InvalidRuntimeStream(
                        "execution disappeared before cancellation".into(),
                    )
                })?;
            execution.cancel = Some(CancelMirrorAuthority {
                request_id: cancel_request_id,
                event_count: 0,
                encoded_bytes: 0,
                digest: Sha256::new(),
                acknowledgement_seen: false,
                terminal_seen: false,
            });
        }

        if let Some(terminal_status) = take_ready_execution_terminal(&mut self.plan)? {
            events
                .send_plan_event(PlanRuntimeEvent::ExecutionStatus(terminal_status))
                .map_err(ClientError::Io)
        } else {
            events
                .send_plan_event(PlanRuntimeEvent::ExecutionStatus(status))
                .map_err(ClientError::Io)
        }
    }
}

fn cancel_binding_matches(plan: &PlanAuthority, visible: &ExecutionCancelBinding) -> bool {
    let Some(review) = plan.review.as_ref() else {
        return false;
    };
    let Some(execution) = plan.execution.as_ref() else {
        return false;
    };
    let Ok(review_id) = required_opaque_hex(review.apply_review_id.as_ref(), "apply review ID")
    else {
        return false;
    };
    let Ok(review_digest) = required_digest_hex(
        review.review_binding_sha256.as_ref(),
        "apply review binding digest",
    ) else {
        return false;
    };
    exact_cancel_binding_matches(
        &ExecutionCancelBinding {
            review_id,
            review_binding_digest: review_digest,
            authority_generation: execution.confirm_request_id,
            execution_id: execution.execution_id.as_ref().map(hex::encode),
        },
        visible,
    )
}

fn overlay_stage_edit_matches(plan: &PlanAuthority, edit: &super::plan::OverlayStageEdit) -> bool {
    if &plan.plan_id != edit.plan_id() || plan.evidence_reference != edit.evidence_reference() {
        return false;
    }
    match plan.overlay.as_ref() {
        Some(overlay) => {
            overlay.revision == edit.base_revision()
                && required_digest_hex(overlay.overlay_sha256.as_ref(), "overlay digest")
                    .is_ok_and(|digest| digest == edit.overlay_digest())
        }
        None => edit.base_revision() == 0,
    }
}

fn plan_intent_matches(plan: &PlanAuthority, intent: &PlanIntent) -> bool {
    if &plan.plan_id != intent.plan_id() || plan.evidence_reference != intent.evidence_reference() {
        return false;
    }
    let Some(overlay) = plan.overlay.as_ref() else {
        return false;
    };
    if overlay.revision != intent.overlay_revision()
        || !required_digest_hex(overlay.overlay_sha256.as_ref(), "overlay digest")
            .is_ok_and(|digest| digest == intent.overlay_digest())
    {
        return false;
    }
    let current = overlay
        .selected_action_ids
        .iter()
        .map(|identifier| ActionId::new(hex::encode(&identifier.value)))
        .collect::<BTreeSet<_>>();
    let visible = intent
        .selected_action_ids()
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>();
    current.len() == overlay.selected_action_ids.len()
        && visible.len() == intent.selected_action_ids().len()
        && current == visible
}

fn exact_review_binding_matches(
    current: &EngineApplyReviewSnapshot,
    visible: &EngineApplyReviewSnapshot,
) -> bool {
    current == visible
}

fn exact_cancel_binding_matches(
    current: &ExecutionCancelBinding,
    visible: &ExecutionCancelBinding,
) -> bool {
    current == visible
}

fn validate_execution_id(
    execution: &mut ExecutionAuthority,
    stream: &ExecutionStreamEvent,
) -> Result<Vec<u8>, ClientError> {
    let execution_id = stream
        .execution_id
        .as_ref()
        .map(|identifier| identifier.value.clone())
        .filter(|value| !value.is_empty())
        .ok_or_else(|| {
            ClientError::InvalidRuntimeStream("execution event omitted execution_id".into())
        })?;
    if execution
        .execution_id
        .as_ref()
        .is_some_and(|current| current != &execution_id)
    {
        return Err(ClientError::InvalidRuntimeStream(
            "execution_id changed".into(),
        ));
    }
    execution.execution_id = Some(execution_id.clone());
    Ok(execution_id)
}

fn admit_execution_record(
    event_count: &mut u64,
    encoded_bytes: &mut u64,
    digest: &mut Sha256,
    encoded: &[u8],
    terminal: bool,
) -> Result<(), ClientError> {
    if *event_count >= MAXIMUM_EXECUTION_EVENT_COUNT {
        return Err(ClientError::InvalidRuntimeStream(
            "execution stream exceeded its event-count limit".into(),
        ));
    }
    let encoded_len = u64::try_from(encoded.len()).map_err(|_| {
        ClientError::InvalidRuntimeStream("execution record length overflow".into())
    })?;
    let record_bytes = encoded_len.checked_add(4).ok_or_else(|| {
        ClientError::InvalidRuntimeStream("execution record framing overflow".into())
    })?;
    let next_bytes = encoded_bytes.checked_add(record_bytes).ok_or_else(|| {
        ClientError::InvalidRuntimeStream("execution stream byte count overflow".into())
    })?;
    let maximum_bytes = MAXIMUM_EXECUTION_ENCODED_BYTES
        .checked_add(if terminal { 64 } else { 0 })
        .expect("execution byte constants fit u64");
    if next_bytes > maximum_bytes {
        return Err(ClientError::InvalidRuntimeStream(
            "execution stream exceeded its encoded-byte limit".into(),
        ));
    }
    digest.update(encoded_len.to_be_bytes());
    digest.update(encoded);
    *event_count += 1;
    *encoded_bytes = next_bytes;
    Ok(())
}

fn take_ready_execution_terminal(
    plan: &mut Option<PlanAuthority>,
) -> Result<Option<ExecutionStatusProjection>, ClientError> {
    let Some(plan) = plan.as_mut() else {
        return Ok(None);
    };
    let Some(execution) = plan.execution.as_mut() else {
        return Ok(None);
    };
    if execution.pending_terminal.is_none() {
        return Ok(None);
    }
    if let Some(cancel) = execution.cancel.as_ref() {
        if !cancel.terminal_seen {
            return Ok(None);
        }
        let mirrored = cancel_mirror_is_exact(
            execution.canonical_event_count,
            execution.canonical_event_bytes,
            &execution.canonical_digest,
            cancel,
        );
        if !mirrored {
            return Err(ClientError::InvalidRuntimeStream(
                "cancel stream did not exactly mirror the verified confirm stream with a typed acknowledgement"
                    .into(),
            ));
        }
    }
    let terminal = execution
        .pending_terminal
        .take()
        .expect("terminal presence was checked");
    plan.execution = None;
    plan.review = None;
    Ok(Some(terminal))
}

fn cancel_mirror_is_exact(
    canonical_event_count: u64,
    canonical_event_bytes: u64,
    canonical_digest: &Sha256,
    cancel: &CancelMirrorAuthority,
) -> bool {
    cancel.acknowledgement_seen
        && cancel.event_count == canonical_event_count
        && cancel.encoded_bytes == canonical_event_bytes
        && cancel.digest.clone().finalize() == canonical_digest.clone().finalize()
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

fn apply_review_snapshot(
    plan: &PlanAuthority,
    review: &ApplyReviewProjection,
) -> Result<(EngineApplyReviewSnapshot, ExecutionPreviewProjection), ClientError> {
    let overlay = plan.overlay.as_ref().ok_or_else(|| {
        ClientError::InvalidRuntimeStream("apply review has no overlay predecessor".into())
    })?;
    let overlay_digest = required_digest_hex(overlay.overlay_sha256.as_ref(), "overlay digest")?;
    let review_id = required_opaque_hex(review.apply_review_id.as_ref(), "apply review ID")?;
    let review_binding_digest = required_digest_hex(
        review.review_binding_sha256.as_ref(),
        "apply review binding digest",
    )?;
    let epoch = review.epoch.as_ref().ok_or_else(|| {
        ClientError::InvalidRuntimeStream("apply review omitted execution epoch".into())
    })?;
    let revalidation = review.revalidation.as_ref().ok_or_else(|| {
        ClientError::InvalidRuntimeStream("apply review omitted revalidation".into())
    })?;
    let finding_count = revalidation
        .action_outcomes
        .iter()
        .try_fold(
            revalidation.global_findings.len() as u64,
            |count, outcome| count.checked_add(outcome.findings.len() as u64),
        )
        .ok_or_else(|| {
            ClientError::InvalidRuntimeStream("apply review finding count overflow".into())
        })?;

    let mut ordered_units = Vec::with_capacity(review.actions.len());
    for action in &review.actions {
        let action_id = ActionId::new(required_opaque_hex(
            action.action_id.as_ref(),
            "apply review action ID",
        )?);
        let execution_preview = action.execution_preview.as_ref().ok_or_else(|| {
            ClientError::InvalidRuntimeStream(
                "apply review action omitted execution preview".into(),
            )
        })?;
        let label = if execution_preview.display_argv.is_empty() {
            format!("Engine action {action_id}")
        } else {
            execution_preview.display_argv.join(" ")
        };
        let execution_status = if execution_preview.postcondition.trim().is_empty() {
            if execution_preview.mutation_supported {
                "engine-authorized mutation preview".into()
            } else {
                "non-mutating preview".into()
            }
        } else {
            execution_preview.postcondition.clone()
        };
        ordered_units.push(ExecutionUnitProjection {
            id: ExecutionUnitId::new(format!("action:{}", action_id.as_str())),
            covered_action_ids: vec![action_id.clone()],
            label,
            prerequisite_unit_ids: Vec::new(),
            prerequisite_status: execution_status,
        });
    }
    let force_action_ids = review
        .force_warning_action_ids
        .iter()
        .map(|identifier| {
            required_opaque_hex(Some(identifier), "force warning action ID").map(ActionId::new)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let final_warnings = force_action_ids
        .iter()
        .map(|action_id| ExecutionWarningProjection {
            id: ExecutionWarningId::new(format!("force:{}", action_id.as_str())),
            message: format!(
                "Force confirmation is required for engine action {action_id}; Enter confirms the exact complete force set"
            ),
        })
        .collect();

    Ok((
        EngineApplyReviewSnapshot {
            plan_id: plan.plan_id.clone(),
            overlay_digest: overlay_digest.clone(),
            review_id,
            review_binding_digest,
            force_action_ids,
            selected_action_count: review.selected_action_count,
            finding_count,
            deadline_seconds: epoch.deadline_seconds,
        },
        ExecutionPreviewProjection {
            plan_id: plan.plan_id.clone(),
            overlay_digest,
            ordered_units,
            final_warnings,
        },
    ))
}

fn required_opaque_hex(
    value: Option<&OpaqueIdentifier>,
    field: &'static str,
) -> Result<String, ClientError> {
    value
        .map(|identifier| identifier.value.as_slice())
        .filter(|value| !value.is_empty())
        .map(hex::encode)
        .ok_or_else(|| ClientError::InvalidRuntimeStream(format!("{field} is missing")))
}

fn required_digest_hex(
    value: Option<&Digest256>,
    field: &'static str,
) -> Result<String, ClientError> {
    value
        .map(|digest| digest.value.as_slice())
        .filter(|value| value.len() == 32)
        .map(hex::encode)
        .ok_or_else(|| ClientError::InvalidRuntimeStream(format!("{field} is invalid")))
}

fn execution_event_summary(event: &ExecutionStreamEvent) -> String {
    match event.body.as_ref() {
        Some(execution_stream_event::Body::ApplyStarted(_)) => {
            "ApplyStarted received; stream binding pending terminal verification".into()
        }
        Some(execution_stream_event::Body::UnitStarted(_)) => {
            "Execution unit started; stream binding pending terminal verification".into()
        }
        Some(execution_stream_event::Body::ForceRequiredWarning(_)) => {
            "Engine repeated a force-required warning during execution".into()
        }
        Some(execution_stream_event::Body::StepFinished(step)) => {
            format!("Execution step finished with typed status {}", step.status)
        }
        Some(execution_stream_event::Body::ReleasePostVerificationFinished(_)) => {
            "Release-set post-verification finished".into()
        }
        Some(execution_stream_event::Body::UnitFinished(unit)) => {
            format!("Execution unit finished with typed status {}", unit.status)
        }
        Some(execution_stream_event::Body::AuditWriteFailed(failure)) => {
            format!("Optional audit write failed: {}", failure.code)
        }
        Some(execution_stream_event::Body::UnitJitRejected(_)) => {
            "Execution unit rejected by just-in-time revalidation".into()
        }
        Some(execution_stream_event::Body::UnitSkippedPrerequisite(_)) => {
            "Execution unit skipped because a prerequisite did not succeed".into()
        }
        Some(execution_stream_event::Body::CancellationAcknowledged(acknowledgement)) => {
            format!("Cancellation acknowledged: {}", acknowledgement.reason)
        }
        Some(execution_stream_event::Body::ApplyFinished(finished)) => format!(
            "ApplyFinished: succeeded={}, partial={}, failed={}, cancelled={}, skipped={}, jit-rejected={}, expired={}, superseded={}",
            finished.succeeded_unit_count,
            finished.partial_unit_count,
            finished.failed_unit_count,
            finished.cancelled_unit_count,
            finished.skipped_unit_count,
            finished.jit_rejected_unit_count,
            finished.expired_unit_count,
            finished.superseded_unit_count,
        ),
        Some(execution_stream_event::Body::ExecutionStreamFailure(failure)) => format!(
            "Execution stream failed closed with kind {} (mutation_may_have_occurred={})",
            failure.kind, failure.mutation_may_have_occurred
        ),
        None => "Execution event omitted its typed body".into(),
    }
}

fn execution_event_is_terminal(event: &ExecutionStreamEvent) -> bool {
    matches!(
        event.body,
        Some(
            execution_stream_event::Body::ApplyFinished(_)
                | execution_stream_event::Body::ExecutionStreamFailure(_)
        )
    )
}

fn canonical_envelope_receipt(envelope: Envelope) -> Result<CanonicalEnvelopeReceipt, ClientError> {
    decode_canonical_envelope(&envelope.encode_to_vec())
        .map_err(|error| ClientError::InvalidRuntimeStream(error.to_string()))
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
    fn driver_allocates_engine_request_ids_and_projects_control_correlations() {
        let mut control_request_ids = BTreeMap::new();
        control_request_ids.insert(1, 1);
        let mut runtime = DriverRuntime {
            next_request_id: 2,
            selected_minor: PROTOCOL16_MINOR,
            capabilities: Vec::new(),
            agent_mode: crate::batch::PlanningAgentMode::Ask,
            control_request_ids,
            plan: None,
        };

        let first_control = runtime.reserve_control_request_id(2).unwrap();
        assert_eq!(first_control, 2);
        assert_eq!(runtime.reserve_request_id().unwrap(), 3);
        assert_eq!(runtime.reserve_request_id().unwrap(), 4);
        let second_control = runtime.reserve_control_request_id(3).unwrap();
        assert_eq!(second_control, 5);

        let mut event = diskplan_proto::diskplan::v1::EngineEvent {
            request_id: second_control,
            ..Default::default()
        };
        runtime.project_control_request_id(&mut event);
        assert_eq!(event.request_id, 3);
    }

    #[test]
    fn apply_review_transport_requires_exact_minor_and_execution_capability() {
        assert_eq!(
            validate_apply_review_transport(PROTOCOL16_MINOR - 1, true),
            Err("exact protocol minor 1.6 is required for mutation review")
        );
        assert_eq!(
            validate_apply_review_transport(PROTOCOL16_MINOR + 1, true),
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

    #[test]
    fn confirmation_and_cancellation_require_the_exact_visible_generation() {
        let review_1 = EngineApplyReviewSnapshot {
            plan_id: PlanId::new("plan-1"),
            overlay_digest: "11".repeat(32),
            review_id: "review-1".into(),
            review_binding_digest: "22".repeat(32),
            force_action_ids: vec![ActionId::new("action-1")],
            selected_action_count: 1,
            finding_count: 0,
            deadline_seconds: 300,
        };
        assert!(exact_review_binding_matches(&review_1, &review_1));
        let mut review_2 = review_1.clone();
        review_2.review_id = "review-2".into();
        review_2.review_binding_digest = "33".repeat(32);
        assert!(!exact_review_binding_matches(&review_2, &review_1));

        let current = ExecutionCancelBinding {
            review_id: review_2.review_id,
            review_binding_digest: review_2.review_binding_digest,
            authority_generation: 17,
            execution_id: Some("execution-2".into()),
        };
        assert!(exact_cancel_binding_matches(&current, &current));
        let mut stale_generation = current.clone();
        stale_generation.authority_generation = 16;
        assert!(!exact_cancel_binding_matches(&current, &stale_generation));
        let mut pre_start = current.clone();
        pre_start.execution_id = None;
        assert!(!exact_cancel_binding_matches(&current, &pre_start));
    }

    #[test]
    fn execution_record_limits_are_enforced_before_state_changes() {
        let mut count = 0;
        let mut bytes = 0;
        let mut digest = Sha256::new();
        admit_execution_record(&mut count, &mut bytes, &mut digest, b"record", false).unwrap();
        assert_eq!(count, 1);
        assert_eq!(bytes, 10);

        let before_digest = digest.clone().finalize();
        count = MAXIMUM_EXECUTION_EVENT_COUNT;
        assert!(admit_execution_record(&mut count, &mut bytes, &mut digest, b"x", false).is_err());
        assert_eq!(count, MAXIMUM_EXECUTION_EVENT_COUNT);
        assert_eq!(bytes, 10);
        assert_eq!(digest.clone().finalize(), before_digest);

        count = 0;
        bytes = MAXIMUM_EXECUTION_ENCODED_BYTES;
        assert!(admit_execution_record(&mut count, &mut bytes, &mut digest, b"x", false).is_err());
        assert_eq!(count, 0);
        assert_eq!(bytes, MAXIMUM_EXECUTION_ENCODED_BYTES);
        assert_eq!(digest.clone().finalize(), before_digest);

        let mut terminal_digest = Sha256::new();
        admit_execution_record(&mut count, &mut bytes, &mut terminal_digest, &[0; 60], true)
            .unwrap();
        assert_eq!(bytes, MAXIMUM_EXECUTION_ENCODED_BYTES + 64);
        let terminal_digest = terminal_digest.finalize();
        assert_ne!(terminal_digest, Sha256::new().finalize());

        count = 0;
        bytes = MAXIMUM_EXECUTION_ENCODED_BYTES;
        let mut oversized_terminal_digest = Sha256::new();
        assert!(
            admit_execution_record(
                &mut count,
                &mut bytes,
                &mut oversized_terminal_digest,
                &[0; 61],
                true,
            )
            .is_err()
        );
        assert_eq!(count, 0);
        assert_eq!(bytes, MAXIMUM_EXECUTION_ENCODED_BYTES);
        assert_eq!(
            oversized_terminal_digest.finalize(),
            Sha256::new().finalize()
        );
    }

    #[test]
    fn cancel_mirror_requires_typed_acknowledgement_and_exact_canonical_bytes() {
        let mut canonical_digest = Sha256::new();
        let mut canonical_count = 0;
        let mut canonical_bytes = 0;
        admit_execution_record(
            &mut canonical_count,
            &mut canonical_bytes,
            &mut canonical_digest,
            b"same",
            false,
        )
        .unwrap();
        let mut cancel = CancelMirrorAuthority {
            request_id: 9,
            event_count: 0,
            encoded_bytes: 0,
            digest: Sha256::new(),
            acknowledgement_seen: false,
            terminal_seen: true,
        };
        admit_execution_record(
            &mut cancel.event_count,
            &mut cancel.encoded_bytes,
            &mut cancel.digest,
            b"same",
            false,
        )
        .unwrap();
        assert!(!cancel_mirror_is_exact(
            canonical_count,
            canonical_bytes,
            &canonical_digest,
            &cancel
        ));
        cancel.acknowledgement_seen = true;
        assert!(cancel_mirror_is_exact(
            canonical_count,
            canonical_bytes,
            &canonical_digest,
            &cancel
        ));
        cancel.encoded_bytes += 1;
        assert!(!cancel_mirror_is_exact(
            canonical_count,
            canonical_bytes,
            &canonical_digest,
            &cancel
        ));
    }
}
