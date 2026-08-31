use std::ffi::OsString;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;
use std::time::Duration;

use diskplan_proto::diskplan::v1::{
    AgentMode, ApplyBatchSelectionPresetEdit, BatchSelectionPreset as WireBatchSelectionPreset,
    BuildPlanRequest, DecisionEditKind, DecisionOverlayAcknowledged, DecisionOverlayEdit,
    Digest256, OpaqueIdentifier, PrepareDryRunRequest, ScanCheckpointEvidence,
    ScanCheckpointManifest, ScanMachineState, StartScanRequest, decision_overlay_edit,
    engine_event,
};
use thiserror::Error;

use crate::runtime_client::{
    PlanScanBinding, RuntimeClientError, edit_overlay, prepare_dry_run, receive_plan,
};
use crate::{BoundEngine, ClientError, EngineSession, SessionEvent};

const REPORT_SCHEMA: u32 = 1;
const MAXIMUM_IDENTIFIER_BYTES: usize = 256;
const MAXIMUM_ROOT_BYTES: usize = 16 * 1024;
const PLAN_HASH_BYTES: usize = 32;
const BATCH_RESPONSE_TIMEOUT: Duration = Duration::from_secs(30);
const SCAN_CONTROL_CAPABILITY: &str = "scan-control-v1";
const SCAN_STREAM_CAPABILITY: &str = "scan-stream-v1";
const RAW_PATH_CAPABILITY: &str = "raw-path-bytes-v1";
const PLAN_CAPABILITY: &str = "plan-projection-v1";
const OVERLAY_CAPABILITY: &str = "decision-overlay-v1";
const DRY_RUN_CAPABILITY: &str = "dry-run-projection-v1";

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchProfile {
    FullAudit,
}

impl BatchProfile {
    const fn as_str(self) -> &'static str {
        match self {
            Self::FullAudit => "full-audit",
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum BatchSelectionPreset {
    SafeStageableWithoutWaiver,
}

impl BatchSelectionPreset {
    const fn as_str(self) -> &'static str {
        match self {
            Self::SafeStageableWithoutWaiver => "safe-stageable-without-waiver",
        }
    }
}

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum PlanningAgentMode {
    Off,
    #[default]
    Ask,
    Auto,
}

impl PlanningAgentMode {
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Ask => "ask",
            Self::Auto => "auto",
        }
    }

    const fn wire(self) -> AgentMode {
        match self {
            Self::Off => AgentMode::Off,
            Self::Ask => AgentMode::Ask,
            Self::Auto => AgentMode::Auto,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchOptions {
    pub profile: BatchProfile,
    pub root: OsString,
    pub agent_mode: PlanningAgentMode,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchRequest {
    pub profile: BatchProfile,
    pub raw_absolute_root: Vec<u8>,
    pub selection_preset: BatchSelectionPreset,
    pub history_enabled: bool,
    pub audit_file_enabled: bool,
    pub dry_run: bool,
    pub agent_mode: PlanningAgentMode,
}

impl From<&BatchOptions> for BatchRequest {
    fn from(options: &BatchOptions) -> Self {
        Self {
            profile: options.profile,
            raw_absolute_root: options.root.as_os_str().as_bytes().to_vec(),
            selection_preset: BatchSelectionPreset::SafeStageableWithoutWaiver,
            history_enabled: false,
            audit_file_enabled: false,
            dry_run: true,
            agent_mode: options.agent_mode,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanEvidenceBinding {
    pub scan_session_id: String,
    pub scan_checkpoint_id: String,
    pub checkpoint_evidence_sha256: [u8; PLAN_HASH_BYTES],
    pub final_evidence_sha256: [u8; PLAN_HASH_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ScanSummary {
    pub evidence: ScanEvidenceBinding,
    pub completed_root_count: u64,
    pub partial_root_count: u64,
    pub observed_entry_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthoritativePlanSummary {
    pub scan_evidence: ScanEvidenceBinding,
    pub evidence_id: [u8; PLAN_HASH_BYTES],
    pub evidence_hash: [u8; PLAN_HASH_BYTES],
    pub projection_id: Vec<u8>,
    pub projection_hash: [u8; PLAN_HASH_BYTES],
    pub plan_id: [u8; PLAN_HASH_BYTES],
    pub plan_hash: [u8; PLAN_HASH_BYTES],
    pub action_count: u64,
    pub cleanup_candidate_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanReference {
    pub scan_evidence: ScanEvidenceBinding,
    pub evidence_id: [u8; PLAN_HASH_BYTES],
    pub evidence_hash: [u8; PLAN_HASH_BYTES],
    pub projection_id: Vec<u8>,
    pub projection_hash: [u8; PLAN_HASH_BYTES],
    pub plan_id: [u8; PLAN_HASH_BYTES],
    pub plan_hash: [u8; PLAN_HASH_BYTES],
}

impl From<&AuthoritativePlanSummary> for PlanReference {
    fn from(plan: &AuthoritativePlanSummary) -> Self {
        Self {
            scan_evidence: plan.scan_evidence.clone(),
            evidence_id: plan.evidence_id,
            evidence_hash: plan.evidence_hash,
            projection_id: plan.projection_id.clone(),
            projection_hash: plan.projection_hash,
            plan_id: plan.plan_id,
            plan_hash: plan.plan_hash,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct OverlayReference {
    pub overlay_id: Vec<u8>,
    pub revision: u64,
    pub overlay_hash: [u8; PLAN_HASH_BYTES],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DecisionOverlaySummary {
    pub plan: PlanReference,
    pub overlay: OverlayReference,
    pub selected_action_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DryRunSummary {
    pub plan: PlanReference,
    pub overlay: OverlayReference,
    pub execution_epoch_id: Vec<u8>,
    pub current_binding_hash: [u8; PLAN_HASH_BYTES],
    /// Wire `DryRunProjectionManifest.projection_sha256`, the sealed manifest digest.
    pub projection_hash: [u8; PLAN_HASH_BYTES],
    pub revalidation_hash: [u8; PLAN_HASH_BYTES],
    pub revalidated_action_count: u64,
    pub would_apply_action_count: u64,
    pub blocked_action_count: u64,
    pub mutation_attempt_count: u64,
    pub history_persistence_attempt_count: u64,
    pub audit_file_persistence_attempt_count: u64,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchCompletion {
    pub scan: ScanSummary,
    pub plan: AuthoritativePlanSummary,
    pub overlay: DecisionOverlaySummary,
    pub dry_run: DryRunSummary,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum BatchEngineResult {
    Completed(Box<BatchCompletion>),
    ScanOnly(ScanSummary),
}

pub trait BatchEngineClient {
    fn execute(&mut self, request: &BatchRequest) -> Result<BatchEngineResult, BatchClientError>;
}

#[derive(Debug, Error)]
pub enum BatchClientError {
    #[error("authoritative batch dry-run protocol is unavailable")]
    Unavailable,
    #[error("engine batch protocol failed")]
    Protocol,
    #[error("engine batch transport failed: {0}")]
    Io(#[from] io::Error),
}

#[derive(Debug, Error)]
pub enum BatchRunError {
    #[error("invalid batch request: {0}")]
    InvalidRequest(&'static str),
    #[error("batch output failed: {0}")]
    Output(#[source] io::Error),
    #[error("engine batch transport failed: {0}")]
    Transport(#[source] io::Error),
    #[error("authoritative batch dry-run protocol is unavailable")]
    Unavailable,
    #[error("engine batch protocol failed")]
    Protocol,
    #[error("engine returned scan evidence without an authoritative plan and dry-run")]
    ScanOnly,
    #[error("engine returned an invalid authoritative batch completion: {0}")]
    InvalidCompletion(&'static str),
}

impl BatchRunError {
    pub const fn exit_code(&self) -> i32 {
        match self {
            Self::InvalidRequest(_) => 64,
            Self::ScanOnly | Self::InvalidCompletion(_) => 65,
            Self::Unavailable => 69,
            Self::Protocol => 70,
            Self::Output(_) | Self::Transport(_) => 74,
        }
    }
}

pub fn run(
    client: &mut dyn BatchEngineClient,
    options: &BatchOptions,
    output: &mut dyn Write,
) -> Result<(), BatchRunError> {
    let request = BatchRequest::from(options);
    validate_request(&request)?;
    write_started(output, &request).map_err(BatchRunError::Output)?;

    let result = client.execute(&request).map_err(|error| match error {
        BatchClientError::Unavailable => BatchRunError::Unavailable,
        BatchClientError::Protocol => BatchRunError::Protocol,
        BatchClientError::Io(error) => BatchRunError::Transport(error),
    })?;
    let BatchEngineResult::Completed(completion) = result else {
        return Err(BatchRunError::ScanOnly);
    };
    validate_completion(&completion)?;
    write_completed(output, &completion).map_err(BatchRunError::Output)?;
    output.flush().map_err(BatchRunError::Output)
}

fn validate_request(request: &BatchRequest) -> Result<(), BatchRunError> {
    if request.raw_absolute_root.is_empty()
        || request.raw_absolute_root.len() > MAXIMUM_ROOT_BYTES
        || request.raw_absolute_root[0] != b'/'
        || request.raw_absolute_root.contains(&0)
    {
        return Err(BatchRunError::InvalidRequest(
            "root is not a bounded raw absolute path",
        ));
    }
    if request.history_enabled || request.audit_file_enabled || !request.dry_run {
        return Err(BatchRunError::InvalidRequest(
            "batch request is not a no-persistence dry-run",
        ));
    }
    Ok(())
}

fn validate_completion(completion: &BatchCompletion) -> Result<(), BatchRunError> {
    validate_identifier(
        &completion.scan.evidence.scan_session_id,
        "invalid scan session id",
    )?;
    validate_identifier(
        &completion.scan.evidence.scan_checkpoint_id,
        "invalid scan checkpoint id",
    )?;
    validate_hash(
        &completion.scan.evidence.checkpoint_evidence_sha256,
        "invalid checkpoint evidence hash",
    )?;
    validate_hash(
        &completion.scan.evidence.final_evidence_sha256,
        "invalid final evidence hash",
    )?;
    if completion.scan.evidence.scan_checkpoint_id
        != hex::encode(completion.scan.evidence.final_evidence_sha256)
    {
        return Err(BatchRunError::InvalidCompletion(
            "scan checkpoint ID is not the lowercase final evidence digest",
        ));
    }
    if completion.plan.scan_evidence != completion.scan.evidence {
        return Err(BatchRunError::InvalidCompletion(
            "plan evidence binding does not match finalized scan evidence",
        ));
    }
    validate_hash(&completion.plan.evidence_id, "invalid evidence id")?;
    validate_hash(&completion.plan.evidence_hash, "invalid evidence hash")?;
    if completion.plan.evidence_id != completion.plan.evidence_hash
        || completion.plan.evidence_hash != completion.scan.evidence.final_evidence_sha256
    {
        return Err(BatchRunError::InvalidCompletion(
            "plan evidence ID/hash does not match finalized scan evidence",
        ));
    }
    validate_opaque_identifier(&completion.plan.projection_id, "invalid projection id")?;
    validate_hash(&completion.plan.plan_id, "invalid plan id")?;
    validate_hash(
        &completion.plan.projection_hash,
        "invalid plan projection hash",
    )?;
    validate_hash(&completion.plan.plan_hash, "invalid plan hash")?;
    if completion.plan.plan_id != completion.plan.plan_hash {
        return Err(BatchRunError::InvalidCompletion(
            "plan ID does not match the authoritative plan hash",
        ));
    }
    let plan_reference = PlanReference::from(&completion.plan);
    if completion.overlay.plan != plan_reference {
        return Err(BatchRunError::InvalidCompletion(
            "overlay acknowledgement does not match the authoritative plan",
        ));
    }
    validate_opaque_identifier(
        &completion.overlay.overlay.overlay_id,
        "invalid decision overlay id",
    )?;
    if completion.overlay.overlay.revision == 0 {
        return Err(BatchRunError::InvalidCompletion(
            "invalid decision overlay revision",
        ));
    }
    validate_hash(
        &completion.overlay.overlay.overlay_hash,
        "invalid decision overlay hash",
    )?;
    if completion.dry_run.plan != plan_reference {
        return Err(BatchRunError::InvalidCompletion(
            "dry-run plan binding does not match the authoritative plan",
        ));
    }
    if completion.dry_run.overlay != completion.overlay.overlay {
        return Err(BatchRunError::InvalidCompletion(
            "dry-run overlay binding does not match the acknowledged overlay",
        ));
    }
    validate_opaque_identifier(
        &completion.dry_run.execution_epoch_id,
        "invalid dry-run execution epoch id",
    )?;
    validate_hash(
        &completion.dry_run.current_binding_hash,
        "invalid current binding hash",
    )?;
    validate_hash(
        &completion.dry_run.projection_hash,
        "invalid dry-run manifest hash",
    )?;
    validate_hash(
        &completion.dry_run.revalidation_hash,
        "invalid revalidation hash",
    )?;
    if completion.plan.cleanup_candidate_count > completion.plan.action_count {
        return Err(BatchRunError::InvalidCompletion(
            "cleanup candidate count exceeds plan action count",
        ));
    }
    if completion.overlay.selected_action_count > completion.plan.action_count {
        return Err(BatchRunError::InvalidCompletion(
            "selected action count exceeds plan action count",
        ));
    }
    let dry_run_total = completion
        .dry_run
        .would_apply_action_count
        .checked_add(completion.dry_run.blocked_action_count)
        .ok_or(BatchRunError::InvalidCompletion(
            "dry-run action count overflow",
        ))?;
    if completion.dry_run.revalidated_action_count != completion.overlay.selected_action_count
        || dry_run_total != completion.overlay.selected_action_count
    {
        return Err(BatchRunError::InvalidCompletion(
            "dry-run action counts do not cover the selected plan",
        ));
    }
    if completion.dry_run.mutation_attempt_count != 0 {
        return Err(BatchRunError::InvalidCompletion(
            "dry-run reported a mutation attempt",
        ));
    }
    if completion.dry_run.history_persistence_attempt_count != 0
        || completion.dry_run.audit_file_persistence_attempt_count != 0
    {
        return Err(BatchRunError::InvalidCompletion(
            "no-persistence batch reported an artifact write attempt",
        ));
    }
    Ok(())
}

fn validate_hash(value: &[u8; PLAN_HASH_BYTES], error: &'static str) -> Result<(), BatchRunError> {
    if value.iter().all(|byte| *byte == 0) {
        Err(BatchRunError::InvalidCompletion(error))
    } else {
        Ok(())
    }
}

fn validate_identifier(value: &str, error: &'static str) -> Result<(), BatchRunError> {
    if value.is_empty()
        || value.len() > MAXIMUM_IDENTIFIER_BYTES
        || value
            .bytes()
            .any(|byte| !(0x20..=0x7e).contains(&byte) || byte == b'"' || byte == b'\\')
    {
        Err(BatchRunError::InvalidCompletion(error))
    } else {
        Ok(())
    }
}

fn validate_opaque_identifier(value: &[u8], error: &'static str) -> Result<(), BatchRunError> {
    if value.is_empty() || value.len() > MAXIMUM_IDENTIFIER_BYTES {
        Err(BatchRunError::InvalidCompletion(error))
    } else {
        Ok(())
    }
}

fn write_started(output: &mut dyn Write, request: &BatchRequest) -> io::Result<()> {
    writeln!(
        output,
        "{{\"schema\":{REPORT_SCHEMA},\"event\":\"batch_started\",\"profile\":\"{}\",\"selection_preset\":\"{}\",\"agent_mode\":\"{}\",\"root_hex\":\"{}\",\"dry_run\":true,\"history\":false,\"audit_file\":false}}",
        request.profile.as_str(),
        request.selection_preset.as_str(),
        request.agent_mode.as_str(),
        hex::encode(&request.raw_absolute_root),
    )
}

fn write_completed(output: &mut dyn Write, completion: &BatchCompletion) -> io::Result<()> {
    writeln!(
        output,
        concat!(
            "{{\"schema\":{},\"event\":\"batch_completed\",",
            "\"status\":\"success\",\"authoritative_plan\":true,",
            "\"dry_run_complete\":true,\"scan_session_id\":\"{}\",",
            "\"scan_checkpoint_id\":\"{}\",\"checkpoint_evidence_hash\":\"{}\",",
            "\"evidence_id\":\"{}\",\"evidence_hash\":\"{}\",",
            "\"completed_roots\":{},\"partial_roots\":{},\"observed_entries\":{},",
            "\"projection_id\":\"{}\",\"projection_hash\":\"{}\",",
            "\"plan_id\":\"{}\",\"plan_hash\":\"{}\",",
            "\"plan_actions\":{},\"cleanup_candidates\":{},",
            "\"overlay_id\":\"{}\",\"overlay_revision\":{},\"overlay_hash\":\"{}\",",
            "\"selected_actions\":{},",
            "\"execution_epoch_id\":\"{}\",\"current_binding_hash\":\"{}\",",
            "\"dry_run_manifest_hash\":\"{}\",\"revalidation_hash\":\"{}\",",
            "\"revalidated_actions\":{},",
            "\"would_apply_actions\":{},\"blocked_actions\":{},",
            "\"mutation_attempts\":{},\"history_persistence_attempts\":{},",
            "\"audit_file_persistence_attempts\":{}}}"
        ),
        REPORT_SCHEMA,
        completion.scan.evidence.scan_session_id,
        completion.scan.evidence.scan_checkpoint_id,
        hex::encode(completion.scan.evidence.checkpoint_evidence_sha256),
        hex::encode(completion.plan.evidence_id),
        hex::encode(completion.plan.evidence_hash),
        completion.scan.completed_root_count,
        completion.scan.partial_root_count,
        completion.scan.observed_entry_count,
        hex::encode(&completion.plan.projection_id),
        hex::encode(completion.plan.projection_hash),
        hex::encode(completion.plan.plan_id),
        hex::encode(completion.plan.plan_hash),
        completion.plan.action_count,
        completion.plan.cleanup_candidate_count,
        hex::encode(&completion.overlay.overlay.overlay_id),
        completion.overlay.overlay.revision,
        hex::encode(completion.overlay.overlay.overlay_hash),
        completion.overlay.selected_action_count,
        hex::encode(&completion.dry_run.execution_epoch_id),
        hex::encode(completion.dry_run.current_binding_hash),
        hex::encode(completion.dry_run.projection_hash),
        hex::encode(completion.dry_run.revalidation_hash),
        completion.dry_run.revalidated_action_count,
        completion.dry_run.would_apply_action_count,
        completion.dry_run.blocked_action_count,
        completion.dry_run.mutation_attempt_count,
        completion.dry_run.history_persistence_attempt_count,
        completion.dry_run.audit_file_persistence_attempt_count,
    )
}

/// A single, mixed-stream transport from scan evidence through a sealed dry-run.
///
/// This client does not construct local plan or overlay authority. Missing protocol
/// versions, capabilities, receipts, or persistence-attempt evidence fail closed.
pub struct ProtocolBatchEngineClient {
    engine: BoundEngine,
}

impl ProtocolBatchEngineClient {
    pub fn new(engine: &BoundEngine) -> Self {
        Self {
            engine: engine.clone(),
        }
    }
}

impl BatchEngineClient for ProtocolBatchEngineClient {
    fn execute(&mut self, request: &BatchRequest) -> Result<BatchEngineResult, BatchClientError> {
        let mut session = EngineSession::connect_bound_with_runtime_capabilities(
            &self.engine,
            BATCH_RESPONSE_TIMEOUT,
            &[PLAN_CAPABILITY, OVERLAY_CAPABILITY, DRY_RUN_CAPABILITY],
        )
        .map_err(map_client_error)?;
        let result = execute_protocol_batch(&mut session, request);
        let shutdown = session.shutdown().map_err(map_client_error);
        match result {
            Err(error) => Err(error),
            Ok(completion) => {
                shutdown?;
                Ok(BatchEngineResult::Completed(Box::new(completion)))
            }
        }
    }
}

fn execute_protocol_batch(
    session: &mut EngineSession,
    request: &BatchRequest,
) -> Result<BatchCompletion, BatchClientError> {
    require_capability(session, SCAN_CONTROL_CAPABILITY)?;
    require_capability(session, SCAN_STREAM_CAPABILITY)?;
    require_capability(session, RAW_PATH_CAPABILITY)?;
    require_capability(session, PLAN_CAPABILITY)?;
    require_capability(session, OVERLAY_CAPABILITY)?;
    require_capability(session, DRY_RUN_CAPABILITY)?;

    session
        .send_start_scan_request(StartScanRequest {
            request_id: 1,
            profile: request.profile.as_str().into(),
            roots: vec![EngineSession::scan_root(
                "batch-root",
                request.raw_absolute_root.clone(),
            )],
            maximum_duration_millis: 0,
            batch_size: 1_024,
        })
        .map_err(map_client_error)?;
    let scan = receive_finalized_scan(session)?;
    let plan_scan_binding = PlanScanBinding {
        scan_session_id: scan.summary.evidence.scan_session_id.as_bytes().to_vec(),
        scan_checkpoint_id: scan.summary.evidence.scan_checkpoint_id.as_bytes().to_vec(),
        scan_checkpoint_evidence_sha256: scan.summary.evidence.checkpoint_evidence_sha256.to_vec(),
        final_evidence_sha256: scan.summary.evidence.final_evidence_sha256.to_vec(),
    };

    session
        .send_build_plan_request(BuildPlanRequest {
            request_id: 2,
            scan_session_id: Some(opaque(scan.summary.evidence.scan_session_id.as_bytes())),
            scan_checkpoint_id: Some(opaque(scan.summary.evidence.scan_checkpoint_id.as_bytes())),
            scan_evidence_sha256: Some(digest(scan.summary.evidence.final_evidence_sha256)),
            allow_partial_evidence: scan.allow_partial_evidence,
            agent_mode: request.agent_mode.wire() as i32,
        })
        .map_err(map_client_error)?;
    let plan_receipt = receive_plan(session, 2, &plan_scan_binding).map_err(map_runtime_error)?;
    let plan = summarize_plan(&scan.summary.evidence, plan_receipt.projection())?;
    let projection_id =
        required_opaque(plan_receipt.projection().manifest().projection_id.as_ref())?;
    let mut chain = plan_receipt.into_chain();

    let overlay = edit_overlay(
        session,
        3,
        opaque(&projection_id),
        0,
        vec![DecisionOverlayEdit {
            kind: DecisionEditKind::ApplyBatchSelectionPreset as i32,
            edit: Some(decision_overlay_edit::Edit::ApplyBatchSelectionPreset(
                ApplyBatchSelectionPresetEdit {
                    preset: WireBatchSelectionPreset::SafeStageableWithoutWaiver as i32,
                },
            )),
        }],
        None,
        &mut chain,
    )
    .map_err(map_runtime_error)?;
    let overlay_summary = summarize_overlay(&plan, &overlay)?;

    let dry_run_receipt = prepare_dry_run(
        session,
        PrepareDryRunRequest {
            request_id: 4,
            projection_id: overlay.projection_id.clone(),
            overlay_revision: overlay.revision,
            overlay_sha256: overlay.overlay_sha256.clone(),
            overlay_id: overlay.overlay_id.clone(),
        },
        &chain,
    )
    .map_err(map_runtime_error)?;
    let dry_run = summarize_dry_run(&plan, &overlay_summary, &dry_run_receipt)?;

    Ok(BatchCompletion {
        scan: scan.summary,
        plan,
        overlay: overlay_summary,
        dry_run,
    })
}

struct FinalizedScan {
    summary: ScanSummary,
    allow_partial_evidence: bool,
}

fn receive_finalized_scan(session: &mut EngineSession) -> Result<FinalizedScan, BatchClientError> {
    loop {
        let event = match session.read_session_event().map_err(map_client_error)? {
            SessionEvent::Scan(event) => event,
            SessionEvent::Runtime(_) => return Err(BatchClientError::Protocol),
        };
        match event.body {
            Some(engine_event::Body::ScanFinalized(finalized)) => {
                let checkpoint = finalized
                    .checkpoint
                    .as_ref()
                    .ok_or(BatchClientError::Protocol)?;
                let manifest = finalized
                    .manifest
                    .as_ref()
                    .ok_or(BatchClientError::Protocol)?;
                return finalized_scan(event.scan_session_id, checkpoint, manifest);
            }
            Some(
                engine_event::Body::ControlRejected(_)
                | engine_event::Body::EngineFailed(_)
                | engine_event::Body::ScanCancelled(_),
            ) => return Err(BatchClientError::Protocol),
            _ => {}
        }
    }
}

fn finalized_scan(
    scan_session_id: String,
    checkpoint: &ScanCheckpointEvidence,
    manifest: &ScanCheckpointManifest,
) -> Result<FinalizedScan, BatchClientError> {
    let machine_state = ScanMachineState::try_from(checkpoint.machine_state)
        .map_err(|_| BatchClientError::Protocol)?;
    let allow_partial_evidence = match machine_state {
        ScanMachineState::Complete => false,
        ScanMachineState::Partial => true,
        _ => return Err(BatchClientError::Protocol),
    };
    let progress = checkpoint
        .progress
        .as_ref()
        .ok_or(BatchClientError::Protocol)?;
    Ok(FinalizedScan {
        summary: ScanSummary {
            evidence: ScanEvidenceBinding {
                scan_session_id,
                scan_checkpoint_id: manifest.checkpoint_id.clone(),
                checkpoint_evidence_sha256: fixed_digest(&manifest.checkpoint_evidence_sha256)?,
                final_evidence_sha256: fixed_digest(&manifest.final_evidence_sha256)?,
            },
            completed_root_count: progress.complete_roots,
            partial_root_count: progress.partial_roots,
            observed_entry_count: progress.entries,
        },
        allow_partial_evidence,
    })
}

fn summarize_plan(
    scan_evidence: &ScanEvidenceBinding,
    projection: &diskplan_proto::runtime::VerifiedPlanProjection,
) -> Result<AuthoritativePlanSummary, BatchClientError> {
    let manifest = projection.manifest();
    Ok(AuthoritativePlanSummary {
        scan_evidence: scan_evidence.clone(),
        evidence_id: fixed_opaque_digest(manifest.evidence_id.as_ref())?,
        evidence_hash: fixed_message_digest(manifest.evidence_sha256.as_ref())?,
        projection_id: required_opaque(manifest.projection_id.as_ref())?,
        projection_hash: fixed_message_digest(manifest.projection_sha256.as_ref())?,
        plan_id: fixed_opaque_digest(manifest.plan_id.as_ref())?,
        plan_hash: fixed_message_digest(manifest.plan_sha256.as_ref())?,
        action_count: manifest.action_count,
        cleanup_candidate_count: manifest.cleanup_candidate_count,
    })
}

fn summarize_overlay(
    plan: &AuthoritativePlanSummary,
    overlay: &DecisionOverlayAcknowledged,
) -> Result<DecisionOverlaySummary, BatchClientError> {
    Ok(DecisionOverlaySummary {
        plan: PlanReference::from(plan),
        overlay: OverlayReference {
            overlay_id: required_opaque(overlay.overlay_id.as_ref())?,
            revision: overlay.revision,
            overlay_hash: fixed_message_digest(overlay.overlay_sha256.as_ref())?,
        },
        selected_action_count: overlay.selected_action_count,
    })
}

fn summarize_dry_run(
    plan: &AuthoritativePlanSummary,
    overlay: &DecisionOverlaySummary,
    receipt: &diskplan_proto::sealed::VerifiedDryRunProjection,
) -> Result<DryRunSummary, BatchClientError> {
    let manifest = receipt.manifest();
    let revalidation = receipt
        .payload()
        .revalidation
        .as_ref()
        .ok_or(BatchClientError::Protocol)?;
    let current_actions = revalidation
        .action_outcomes
        .iter()
        .filter(|outcome| outcome.current)
        .count() as u64;
    let blocked_actions = revalidation.action_outcomes.len() as u64 - current_actions;
    let epoch = manifest.epoch.as_ref().ok_or(BatchClientError::Protocol)?;
    Ok(DryRunSummary {
        plan: PlanReference::from(plan),
        overlay: overlay.overlay.clone(),
        execution_epoch_id: required_opaque(epoch.epoch_id.as_ref())?,
        current_binding_hash: fixed_message_digest(manifest.current_binding_sha256.as_ref())?,
        projection_hash: fixed_message_digest(manifest.projection_sha256.as_ref())?,
        revalidation_hash: fixed_message_digest(manifest.revalidation_sha256.as_ref())?,
        revalidated_action_count: revalidation.action_outcomes.len() as u64,
        would_apply_action_count: current_actions,
        blocked_action_count: blocked_actions,
        // These are frontend-side attempt counters. The dry-run path does not send
        // mutation requests and has no history/audit-file writer to invoke.
        mutation_attempt_count: 0,
        history_persistence_attempt_count: 0,
        audit_file_persistence_attempt_count: 0,
    })
}

fn require_capability(session: &EngineSession, capability: &str) -> Result<(), BatchClientError> {
    if session
        .accepted()
        .negotiated_capabilities
        .iter()
        .any(|value| value == capability)
    {
        Ok(())
    } else {
        Err(BatchClientError::Unavailable)
    }
}

fn opaque(value: impl AsRef<[u8]>) -> OpaqueIdentifier {
    OpaqueIdentifier {
        value: value.as_ref().to_vec(),
    }
}

fn digest(value: [u8; PLAN_HASH_BYTES]) -> Digest256 {
    Digest256 {
        value: value.to_vec(),
    }
}

fn required_opaque(value: Option<&OpaqueIdentifier>) -> Result<Vec<u8>, BatchClientError> {
    value
        .map(|identifier| identifier.value.clone())
        .filter(|identifier| !identifier.is_empty() && identifier.len() <= MAXIMUM_IDENTIFIER_BYTES)
        .ok_or(BatchClientError::Protocol)
}

fn fixed_opaque_digest(
    value: Option<&OpaqueIdentifier>,
) -> Result<[u8; PLAN_HASH_BYTES], BatchClientError> {
    fixed_digest(&required_opaque(value)?)
}

fn fixed_message_digest(
    value: Option<&Digest256>,
) -> Result<[u8; PLAN_HASH_BYTES], BatchClientError> {
    value
        .map(|digest| digest.value.as_slice())
        .ok_or(BatchClientError::Protocol)
        .and_then(fixed_digest)
}

fn fixed_digest(value: &[u8]) -> Result<[u8; PLAN_HASH_BYTES], BatchClientError> {
    value.try_into().map_err(|_| BatchClientError::Protocol)
}

fn map_runtime_error(error: RuntimeClientError) -> BatchClientError {
    if error.is_unavailable() {
        BatchClientError::Unavailable
    } else {
        match error {
            RuntimeClientError::Transport(error) => map_client_error(error),
            _ => BatchClientError::Protocol,
        }
    }
}

fn map_client_error(error: ClientError) -> BatchClientError {
    match error {
        ClientError::Io(error) => BatchClientError::Io(error),
        _ => BatchClientError::Protocol,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct FakeClient(Result<BatchEngineResult, BatchClientError>);

    impl BatchEngineClient for FakeClient {
        fn execute(
            &mut self,
            request: &BatchRequest,
        ) -> Result<BatchEngineResult, BatchClientError> {
            assert_eq!(request.profile, BatchProfile::FullAudit);
            assert_eq!(
                request.selection_preset,
                BatchSelectionPreset::SafeStageableWithoutWaiver
            );
            assert!(!request.history_enabled);
            assert!(!request.audit_file_enabled);
            assert!(request.dry_run);
            assert_eq!(request.agent_mode, PlanningAgentMode::Ask);
            std::mem::replace(&mut self.0, Err(BatchClientError::Protocol))
        }
    }

    fn options() -> BatchOptions {
        BatchOptions {
            profile: BatchProfile::FullAudit,
            root: OsString::from("/private/tmp/fixture"),
            agent_mode: PlanningAgentMode::Ask,
        }
    }

    fn completion() -> BatchCompletion {
        let evidence = ScanEvidenceBinding {
            scan_session_id: "scan-1".into(),
            scan_checkpoint_id: "22".repeat(PLAN_HASH_BYTES),
            checkpoint_evidence_sha256: [0x11; PLAN_HASH_BYTES],
            final_evidence_sha256: [0x22; PLAN_HASH_BYTES],
        };
        let plan = AuthoritativePlanSummary {
            scan_evidence: evidence.clone(),
            evidence_id: evidence.final_evidence_sha256,
            evidence_hash: evidence.final_evidence_sha256,
            projection_id: b"projection-1".to_vec(),
            projection_hash: [0x33; PLAN_HASH_BYTES],
            plan_hash: [0x5a; PLAN_HASH_BYTES],
            plan_id: [0x5a; PLAN_HASH_BYTES],
            action_count: 3,
            cleanup_candidate_count: 2,
        };
        let plan_reference = PlanReference::from(&plan);
        let overlay_reference = OverlayReference {
            overlay_id: b"overlay-1".to_vec(),
            revision: 1,
            overlay_hash: [0xa5; PLAN_HASH_BYTES],
        };
        BatchCompletion {
            scan: ScanSummary {
                evidence,
                completed_root_count: 1,
                partial_root_count: 0,
                observed_entry_count: 42,
            },
            plan,
            overlay: DecisionOverlaySummary {
                plan: plan_reference.clone(),
                overlay: overlay_reference.clone(),
                selected_action_count: 2,
            },
            dry_run: DryRunSummary {
                plan: plan_reference,
                overlay: overlay_reference,
                execution_epoch_id: b"epoch-1".to_vec(),
                current_binding_hash: [0x44; PLAN_HASH_BYTES],
                projection_hash: [0x55; PLAN_HASH_BYTES],
                revalidation_hash: [0x66; PLAN_HASH_BYTES],
                revalidated_action_count: 2,
                would_apply_action_count: 1,
                blocked_action_count: 1,
                mutation_attempt_count: 0,
                history_persistence_attempt_count: 0,
                audit_file_persistence_attempt_count: 0,
            },
        }
    }

    #[test]
    fn success_report_is_bounded_deterministic_ndjson() {
        let mut output = Vec::new();
        run(
            &mut FakeClient(Ok(BatchEngineResult::Completed(Box::new(completion())))),
            &options(),
            &mut output,
        )
        .expect("valid authoritative completion");
        let report = String::from_utf8(output).expect("ASCII report");
        let lines: Vec<&str> = report.lines().collect();
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "{\"schema\":1,\"event\":\"batch_started\",\"profile\":\"full-audit\",\"selection_preset\":\"safe-stageable-without-waiver\",\"agent_mode\":\"ask\",\"root_hex\":\"2f707269766174652f746d702f66697874757265\",\"dry_run\":true,\"history\":false,\"audit_file\":false}"
        );
        assert!(lines[1].contains("\"authoritative_plan\":true"));
        assert!(lines[1].contains("\"dry_run_complete\":true"));
        assert!(lines[1].contains("\"mutation_attempts\":0"));
        assert!(lines[1].contains("\"history_persistence_attempts\":0"));
        assert!(lines[1].contains("\"audit_file_persistence_attempts\":0"));
        assert!(report.len() < 4 * 1024);
    }

    #[test]
    fn scan_only_result_cannot_be_reported_as_dry_run_success() {
        let mut output = Vec::new();
        let error = run(
            &mut FakeClient(Ok(BatchEngineResult::ScanOnly(completion().scan))),
            &options(),
            &mut output,
        )
        .expect_err("scan-only result must fail closed");
        assert!(matches!(error, BatchRunError::ScanOnly));
        assert_eq!(error.exit_code(), 65);
        assert!(
            !String::from_utf8(output)
                .expect("ASCII report")
                .contains("batch_completed")
        );
    }

    #[test]
    fn dry_run_must_cover_the_selected_plan_without_mutations() {
        let mutations: [fn(&mut BatchCompletion); 6] = [
            |value: &mut BatchCompletion| value.dry_run.revalidated_action_count = 1,
            |value: &mut BatchCompletion| value.dry_run.mutation_attempt_count = 1,
            |value: &mut BatchCompletion| value.dry_run.history_persistence_attempt_count = 1,
            |value: &mut BatchCompletion| value.dry_run.audit_file_persistence_attempt_count = 1,
            |value: &mut BatchCompletion| value.plan.plan_hash = [0; PLAN_HASH_BYTES],
            |value: &mut BatchCompletion| value.overlay.overlay.overlay_hash = [0; PLAN_HASH_BYTES],
        ];
        for mutate in mutations {
            let mut invalid = completion();
            mutate(&mut invalid);
            let error = run(
                &mut FakeClient(Ok(BatchEngineResult::Completed(Box::new(invalid)))),
                &options(),
                &mut Vec::new(),
            )
            .expect_err("invalid completion must fail closed");
            assert_eq!(error.exit_code(), 65);
        }
    }

    #[test]
    fn every_authority_transition_requires_the_exact_upstream_binding() {
        let mutations: [fn(&mut BatchCompletion); 17] = [
            |value| {
                let noncanonical = "11".repeat(PLAN_HASH_BYTES);
                value.scan.evidence.scan_checkpoint_id = noncanonical.clone();
                value.plan.scan_evidence.scan_checkpoint_id = noncanonical;
            },
            |value| value.plan.scan_evidence.scan_session_id.push_str("-other"),
            |value| value.plan.scan_evidence.final_evidence_sha256 = [0x77; PLAN_HASH_BYTES],
            |value| value.plan.evidence_id = [0x77; PLAN_HASH_BYTES],
            |value| value.plan.plan_id = [0x77; PLAN_HASH_BYTES],
            |value| {
                value.overlay.plan.scan_evidence.checkpoint_evidence_sha256 =
                    [0x77; PLAN_HASH_BYTES]
            },
            |value| value.overlay.plan.evidence_hash = [0x77; PLAN_HASH_BYTES],
            |value| {
                value
                    .overlay
                    .plan
                    .projection_id
                    .extend_from_slice(b"-other")
            },
            |value| value.overlay.plan.plan_hash = [0x77; PLAN_HASH_BYTES],
            |value| value.overlay.overlay.revision = 0,
            |value| {
                value
                    .dry_run
                    .plan
                    .scan_evidence
                    .scan_session_id
                    .push_str("-other")
            },
            |value| value.dry_run.plan.evidence_id = [0x77; PLAN_HASH_BYTES],
            |value| value.dry_run.plan.projection_hash = [0x77; PLAN_HASH_BYTES],
            |value| value.dry_run.overlay.overlay_hash = [0x77; PLAN_HASH_BYTES],
            |value| value.dry_run.current_binding_hash = [0; PLAN_HASH_BYTES],
            |value| value.dry_run.projection_hash = [0; PLAN_HASH_BYTES],
            |value| value.dry_run.revalidation_hash = [0; PLAN_HASH_BYTES],
        ];
        for mutate in mutations {
            let mut invalid = completion();
            mutate(&mut invalid);
            let error = run(
                &mut FakeClient(Ok(BatchEngineResult::Completed(Box::new(invalid)))),
                &options(),
                &mut Vec::new(),
            )
            .expect_err("mismatched authority chain must fail closed");
            assert_eq!(error.exit_code(), 65);
        }
    }

    #[test]
    fn unavailable_protocol_uses_the_stable_batch_exit() {
        let error = run(
            &mut FakeClient(Err(BatchClientError::Unavailable)),
            &options(),
            &mut Vec::new(),
        )
        .expect_err("missing runtime capability must not pass batch acceptance");
        assert!(matches!(error, BatchRunError::Unavailable));
        assert_eq!(error.exit_code(), 69);
    }

    #[test]
    fn invalid_engine_protocol_uses_the_stable_batch_exit() {
        let error = run(
            &mut FakeClient(Err(BatchClientError::Protocol)),
            &options(),
            &mut Vec::new(),
        )
        .expect_err("invalid engine protocol must fail closed");
        assert!(matches!(error, BatchRunError::Protocol));
        assert_eq!(error.exit_code(), 70);
    }
}
