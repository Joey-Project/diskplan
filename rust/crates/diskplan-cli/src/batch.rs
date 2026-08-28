use std::ffi::OsString;
use std::io::{self, Write};
use std::os::unix::ffi::OsStrExt;

use thiserror::Error;

const REPORT_SCHEMA: u32 = 1;
const MAXIMUM_IDENTIFIER_BYTES: usize = 256;
const MAXIMUM_ROOT_BYTES: usize = 16 * 1024;
const PLAN_HASH_BYTES: usize = 32;

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

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchOptions {
    pub profile: BatchProfile,
    pub root: OsString,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BatchRequest {
    pub profile: BatchProfile,
    pub raw_absolute_root: Vec<u8>,
    pub selection_preset: BatchSelectionPreset,
    pub history_enabled: bool,
    pub audit_file_enabled: bool,
    pub dry_run: bool,
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
    pub projection_id: String,
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
    pub projection_id: String,
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
    pub overlay_id: String,
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
    pub execution_epoch_id: String,
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
    validate_identifier(&completion.plan.projection_id, "invalid projection id")?;
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
    validate_identifier(
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
    validate_identifier(
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

fn write_started(output: &mut dyn Write, request: &BatchRequest) -> io::Result<()> {
    writeln!(
        output,
        "{{\"schema\":{REPORT_SCHEMA},\"event\":\"batch_started\",\"profile\":\"{}\",\"selection_preset\":\"{}\",\"root_hex\":\"{}\",\"dry_run\":true,\"history\":false,\"audit_file\":false}}",
        request.profile.as_str(),
        request.selection_preset.as_str(),
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
        completion.plan.projection_id,
        hex::encode(completion.plan.projection_hash),
        hex::encode(completion.plan.plan_id),
        hex::encode(completion.plan.plan_hash),
        completion.plan.action_count,
        completion.plan.cleanup_candidate_count,
        completion.overlay.overlay.overlay_id,
        completion.overlay.overlay.revision,
        hex::encode(completion.overlay.overlay.overlay_hash),
        completion.overlay.selected_action_count,
        completion.dry_run.execution_epoch_id,
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

/// The protocol-1.3 engine cannot prove an authoritative plan or dry-run.
/// The protocol-1.4 adapter replaces this fail-closed seam without changing argv or reporting.
pub struct ProtocolBatchEngineClient;

impl BatchEngineClient for ProtocolBatchEngineClient {
    fn execute(&mut self, _request: &BatchRequest) -> Result<BatchEngineResult, BatchClientError> {
        Err(BatchClientError::Unavailable)
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
            std::mem::replace(&mut self.0, Err(BatchClientError::Protocol))
        }
    }

    fn options() -> BatchOptions {
        BatchOptions {
            profile: BatchProfile::FullAudit,
            root: OsString::from("/private/tmp/fixture"),
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
            projection_id: "projection-1".into(),
            projection_hash: [0x33; PLAN_HASH_BYTES],
            plan_hash: [0x5a; PLAN_HASH_BYTES],
            plan_id: [0x5a; PLAN_HASH_BYTES],
            action_count: 3,
            cleanup_candidate_count: 2,
        };
        let plan_reference = PlanReference::from(&plan);
        let overlay_reference = OverlayReference {
            overlay_id: "overlay-1".into(),
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
                execution_epoch_id: "epoch-1".into(),
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
            "{\"schema\":1,\"event\":\"batch_started\",\"profile\":\"full-audit\",\"selection_preset\":\"safe-stageable-without-waiver\",\"root_hex\":\"2f707269766174652f746d702f66697874757265\",\"dry_run\":true,\"history\":false,\"audit_file\":false}"
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
            |value| value.overlay.plan.projection_id.push_str("-other"),
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
    fn protocol_1_3_seam_is_explicitly_unavailable() {
        let error = run(&mut ProtocolBatchEngineClient, &options(), &mut Vec::new())
            .expect_err("scan-only protocol must not pass batch acceptance");
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
