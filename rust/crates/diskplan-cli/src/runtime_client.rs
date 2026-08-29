use std::collections::BTreeSet;

use diskplan_proto::diskplan::v1::{
    BatchSelectionPreset, DecisionEditKind, DecisionOverlayAcknowledged, DecisionOverlayEdit,
    DecisionOverlayEditRequest, DecisionOverlayRejected, Digest256, DryRunProjection,
    OpaqueIdentifier, PlanProjectionManifest, PrepareDryRunRequest, RuntimeRejectCode,
    RuntimeRejected, decision_overlay_edit, runtime_event,
};
use diskplan_proto::runtime::{
    MAXIMUM_PLAN_PROJECTION_MANIFEST_BYTES, MAXIMUM_PLAN_PROJECTION_RAW_BYTES,
    MAXIMUM_PLAN_PROJECTION_RAW_CHUNK_BYTES, MAXIMUM_PLAN_PROJECTION_RECORD_COUNT,
    RuntimeProjectionError, VerifiedPlanProjection, decode_and_verify_plan_projection,
};
use diskplan_proto::sealed::{RuntimeChainVerifier, VerifiedDryRunProjection};
use prost::Message;
use thiserror::Error;

use crate::{ClientError, EngineSession, SessionEvent};

#[derive(Debug, Error)]
pub enum RuntimeClientError {
    #[error(transparent)]
    Transport(#[from] ClientError),
    #[error("engine rejected runtime request with code {code}: {summary}")]
    Rejected { code: i32, summary: String },
    #[error("engine rejected the decision overlay with code {code}: {summary}")]
    OverlayRejected { code: i32, summary: String },
    #[error("runtime projection is invalid: {0}")]
    Projection(#[from] RuntimeProjectionError),
    #[error("runtime authority binding is invalid: {0}")]
    Binding(&'static str),
    #[error("runtime projection exceeded its negotiated limit: {0}")]
    Limit(&'static str),
    #[error("runtime stream violated the expected {0} response sequence")]
    Unexpected(&'static str),
}

impl RuntimeClientError {
    pub fn is_unavailable(&self) -> bool {
        matches!(
            self,
            Self::Rejected { code, .. }
                if *code == RuntimeRejectCode::CapabilityNotNegotiated as i32
                    || *code == RuntimeRejectCode::BusinessUnsupported as i32
        )
    }
}

#[derive(Clone, Debug)]
pub struct RuntimePlanReceipt {
    projection: VerifiedPlanProjection,
    scan_binding: PlanScanBinding,
}

impl RuntimePlanReceipt {
    pub fn projection(&self) -> &VerifiedPlanProjection {
        &self.projection
    }

    pub fn into_chain(self) -> RuntimeChainVerifier {
        RuntimeChainVerifier::new(self.projection)
    }

    pub fn scan_binding(&self) -> &PlanScanBinding {
        &self.scan_binding
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PlanScanBinding {
    pub scan_session_id: Vec<u8>,
    pub scan_checkpoint_id: Vec<u8>,
    pub scan_checkpoint_evidence_sha256: Vec<u8>,
    pub final_evidence_sha256: Vec<u8>,
}

pub fn receive_plan(
    session: &mut EngineSession,
    request_id: u64,
    expected_scan: &PlanScanBinding,
) -> Result<RuntimePlanReceipt, RuntimeClientError> {
    let mut accepted = false;
    let mut chunks = Vec::new();
    let mut admitted_chunk_bytes = 0_u64;
    loop {
        let event = runtime_event_for_request(session, request_id, "plan")?;
        match event.body {
            Some(runtime_event::Body::BuildPlanAccepted(_)) if !accepted && chunks.is_empty() => {
                accepted = true;
            }
            Some(runtime_event::Body::PlanProjectionChunk(chunk)) if accepted => {
                admit_plan_chunk(
                    &mut chunks,
                    &mut admitted_chunk_bytes,
                    chunk.encode_to_vec(),
                )?;
            }
            Some(runtime_event::Body::PlanProjection(projection)) if accepted => {
                let manifest = projection
                    .manifest
                    .ok_or(RuntimeClientError::Unexpected("plan manifest"))?;
                let verified =
                    decode_and_verify_plan_projection(&chunks, &manifest.encode_to_vec())?;
                verify_plan_scan_binding(verified.manifest(), expected_scan)?;
                return Ok(RuntimePlanReceipt {
                    projection: verified,
                    scan_binding: expected_scan.clone(),
                });
            }
            Some(runtime_event::Body::PlanProjectionInvalidated(_)) => {
                return Err(RuntimeClientError::Unexpected("live plan invalidation"));
            }
            Some(runtime_event::Body::RuntimeRejected(rejected)) => {
                return Err(runtime_rejected(rejected));
            }
            _ => return Err(RuntimeClientError::Unexpected("plan")),
        }
    }
}

fn admit_plan_chunk(
    chunks: &mut Vec<Vec<u8>>,
    admitted_bytes: &mut u64,
    encoded: Vec<u8>,
) -> Result<(), RuntimeClientError> {
    if chunks.len() >= MAXIMUM_PLAN_PROJECTION_RECORD_COUNT {
        return Err(RuntimeClientError::Limit("plan projection chunk count"));
    }
    if encoded.len() > MAXIMUM_PLAN_PROJECTION_RAW_CHUNK_BYTES {
        return Err(RuntimeClientError::Limit("plan projection chunk bytes"));
    }
    let encoded_bytes = u64::try_from(encoded.len())
        .map_err(|_| RuntimeClientError::Limit("plan projection chunk bytes"))?;
    let maximum_chunk_bytes = MAXIMUM_PLAN_PROJECTION_RAW_BYTES
        .checked_sub(MAXIMUM_PLAN_PROJECTION_MANIFEST_BYTES as u64)
        .ok_or(RuntimeClientError::Limit("plan projection byte budget"))?;
    let next = admitted_bytes
        .checked_add(encoded_bytes)
        .ok_or(RuntimeClientError::Limit("plan projection byte budget"))?;
    if next > maximum_chunk_bytes {
        return Err(RuntimeClientError::Limit("plan projection byte budget"));
    }
    chunks.push(encoded);
    *admitted_bytes = next;
    Ok(())
}

pub fn edit_overlay(
    session: &mut EngineSession,
    request_id: u64,
    projection_id: diskplan_proto::diskplan::v1::OpaqueIdentifier,
    base_revision: u64,
    edits: Vec<DecisionOverlayEdit>,
    predecessor: Option<&DecisionOverlayAcknowledged>,
    chain: &mut RuntimeChainVerifier,
) -> Result<DecisionOverlayAcknowledged, RuntimeClientError> {
    validate_overlay_predecessor(base_revision, predecessor)?;
    session.send_decision_overlay_edit_request(DecisionOverlayEditRequest {
        request_id,
        projection_id: Some(projection_id),
        base_revision,
        edits: edits.clone(),
    })?;
    let event = runtime_event_for_request(session, request_id, "decision overlay")?;
    match event.body {
        Some(runtime_event::Body::DecisionOverlayAcknowledged(overlay)) => {
            verify_overlay_transition(base_revision, &edits, predecessor, &overlay)?;
            chain.verify_overlay(&overlay.encode_to_vec())?;
            Ok(overlay)
        }
        Some(runtime_event::Body::DecisionOverlayRejected(rejected)) => {
            Err(overlay_rejected(rejected))
        }
        Some(runtime_event::Body::RuntimeRejected(rejected)) => Err(runtime_rejected(rejected)),
        _ => Err(RuntimeClientError::Unexpected("decision overlay")),
    }
}

fn verify_plan_scan_binding(
    manifest: &PlanProjectionManifest,
    expected: &PlanScanBinding,
) -> Result<(), RuntimeClientError> {
    if expected.scan_session_id.is_empty()
        || expected.scan_checkpoint_id.is_empty()
        || expected.scan_checkpoint_evidence_sha256.len() != 32
        || expected.final_evidence_sha256.len() != 32
        || expected.scan_checkpoint_id.as_slice()
            != hex::encode(&expected.final_evidence_sha256).as_bytes()
    {
        return Err(RuntimeClientError::Binding(
            "invalid requested scan binding",
        ));
    }
    if opaque_value(manifest.scan_session_id.as_ref()) != Some(expected.scan_session_id.as_slice())
        || opaque_value(manifest.scan_checkpoint_id.as_ref())
            != Some(expected.scan_checkpoint_id.as_slice())
        || digest_value(manifest.scan_checkpoint_evidence_sha256.as_ref())
            != Some(expected.scan_checkpoint_evidence_sha256.as_slice())
        || digest_value(manifest.evidence_sha256.as_ref())
            != Some(expected.final_evidence_sha256.as_slice())
    {
        return Err(RuntimeClientError::Binding(
            "plan does not repeat the requested scan binding",
        ));
    }
    Ok(())
}

fn validate_overlay_predecessor(
    base_revision: u64,
    predecessor: Option<&DecisionOverlayAcknowledged>,
) -> Result<(), RuntimeClientError> {
    match predecessor {
        Some(value) if value.revision == base_revision => Ok(()),
        None if base_revision == 0 => Ok(()),
        _ => Err(RuntimeClientError::Binding(
            "overlay predecessor revision does not match the edit",
        )),
    }
}

fn verify_overlay_transition(
    base_revision: u64,
    edits: &[DecisionOverlayEdit],
    predecessor: Option<&DecisionOverlayAcknowledged>,
    acknowledged: &DecisionOverlayAcknowledged,
) -> Result<(), RuntimeClientError> {
    if acknowledged.revision
        != base_revision
            .checked_add(1)
            .ok_or(RuntimeClientError::Binding(
                "overlay revision space is exhausted",
            ))?
    {
        return Err(RuntimeClientError::Binding(
            "overlay acknowledgement did not advance exactly one revision",
        ));
    }

    let mut selected =
        opaque_set(predecessor.map_or(&[][..], |value| value.selected_action_ids.as_slice()));
    let mut waivers =
        waiver_set(predecessor.map_or(&[][..], |value| value.acknowledged_waivers.as_slice()))?;
    let mut notes = predecessor.map_or_else(Vec::new, |value| value.user_notes.clone());
    let mut engine_owned_preset = false;
    for edit in edits {
        let expected_kind = match edit.edit.as_ref() {
            Some(decision_overlay_edit::Edit::StageAction(_)) => DecisionEditKind::StageAction,
            Some(decision_overlay_edit::Edit::UnstageAction(_)) => DecisionEditKind::UnstageAction,
            Some(decision_overlay_edit::Edit::AllowWaiver(_)) => DecisionEditKind::AllowWaiver,
            Some(decision_overlay_edit::Edit::RevokeWaiver(_)) => DecisionEditKind::RevokeWaiver,
            Some(decision_overlay_edit::Edit::ReplaceNotes(_)) => DecisionEditKind::ReplaceNotes,
            Some(decision_overlay_edit::Edit::ApplyBatchSelectionPreset(_)) => {
                DecisionEditKind::ApplyBatchSelectionPreset
            }
            None => return Err(RuntimeClientError::Binding("overlay edit body is missing")),
        };
        if edit.kind != expected_kind as i32 {
            return Err(RuntimeClientError::Binding(
                "overlay edit kind does not match its body",
            ));
        }
        match edit.edit.as_ref() {
            Some(decision_overlay_edit::Edit::StageAction(stage)) => {
                selected.insert(required_opaque(
                    stage.action_id.as_ref(),
                    "stage action_id",
                )?);
            }
            Some(decision_overlay_edit::Edit::UnstageAction(stage)) => {
                let action_id = required_opaque(stage.action_id.as_ref(), "unstage action_id")?;
                selected.remove(&action_id);
                waivers.retain(|(waiver_action_id, _)| waiver_action_id != &action_id);
            }
            Some(decision_overlay_edit::Edit::AllowWaiver(waiver)) => {
                waivers.insert((
                    required_opaque(waiver.action_id.as_ref(), "waiver action_id")?,
                    required_opaque(waiver.waiver_id.as_ref(), "waiver_id")?,
                ));
            }
            Some(decision_overlay_edit::Edit::RevokeWaiver(waiver)) => {
                waivers.remove(&(
                    required_opaque(waiver.action_id.as_ref(), "waiver action_id")?,
                    required_opaque(waiver.waiver_id.as_ref(), "waiver_id")?,
                ));
            }
            Some(decision_overlay_edit::Edit::ReplaceNotes(replacement)) => {
                notes.clone_from(&replacement.user_notes);
            }
            Some(decision_overlay_edit::Edit::ApplyBatchSelectionPreset(preset)) => {
                if edits.len() != 1
                    || preset.preset != BatchSelectionPreset::SafeStageableWithoutWaiver as i32
                {
                    return Err(RuntimeClientError::Binding(
                        "engine-owned preset request is invalid",
                    ));
                }
                engine_owned_preset = true;
                waivers.clear();
            }
            None => unreachable!("overlay edit body was checked above"),
        }
    }

    if (!engine_owned_preset && selected != opaque_set(&acknowledged.selected_action_ids))
        || waivers != waiver_set(&acknowledged.acknowledged_waivers)?
        || notes != acknowledged.user_notes
    {
        return Err(RuntimeClientError::Binding(
            "overlay acknowledgement does not match the requested edit transition",
        ));
    }
    Ok(())
}

fn opaque_value(value: Option<&OpaqueIdentifier>) -> Option<&[u8]> {
    value.map(|value| value.value.as_slice())
}

fn digest_value(value: Option<&Digest256>) -> Option<&[u8]> {
    value.map(|value| value.value.as_slice())
}

fn opaque_set(values: &[OpaqueIdentifier]) -> BTreeSet<Vec<u8>> {
    values.iter().map(|value| value.value.clone()).collect()
}

fn waiver_set(
    values: &[diskplan_proto::diskplan::v1::AcknowledgedWaiver],
) -> Result<BTreeSet<(Vec<u8>, Vec<u8>)>, RuntimeClientError> {
    values
        .iter()
        .map(|value| {
            Ok((
                required_opaque(value.action_id.as_ref(), "waiver action_id")?,
                required_opaque(value.waiver_id.as_ref(), "waiver_id")?,
            ))
        })
        .collect()
}

fn required_opaque(
    value: Option<&OpaqueIdentifier>,
    field: &'static str,
) -> Result<Vec<u8>, RuntimeClientError> {
    value
        .map(|value| value.value.clone())
        .filter(|value| !value.is_empty())
        .ok_or(RuntimeClientError::Binding(field))
}

pub fn prepare_dry_run(
    session: &mut EngineSession,
    request: PrepareDryRunRequest,
    chain: &RuntimeChainVerifier,
) -> Result<VerifiedDryRunProjection, RuntimeClientError> {
    let request_id = request.request_id;
    session.send_prepare_dry_run_request(request)?;
    let event = runtime_event_for_request(session, request_id, "dry-run")?;
    match event.body {
        Some(runtime_event::Body::DryRunProjection(projection)) => {
            verify_dry_run(chain, projection)
        }
        Some(runtime_event::Body::RuntimeRejected(rejected)) => Err(runtime_rejected(rejected)),
        _ => Err(RuntimeClientError::Unexpected("dry-run")),
    }
}

fn verify_dry_run(
    chain: &RuntimeChainVerifier,
    projection: DryRunProjection,
) -> Result<VerifiedDryRunProjection, RuntimeClientError> {
    Ok(chain.verify_dry_run(&projection.encode_to_vec())?)
}

fn runtime_event_for_request(
    session: &mut EngineSession,
    request_id: u64,
    phase: &'static str,
) -> Result<diskplan_proto::diskplan::v1::RuntimeEvent, RuntimeClientError> {
    match session.read_session_event()? {
        SessionEvent::Runtime(event) if event.request_id == request_id => Ok(event),
        SessionEvent::Runtime(_) | SessionEvent::Scan(_) => {
            Err(RuntimeClientError::Unexpected(phase))
        }
    }
}

fn runtime_rejected(rejected: RuntimeRejected) -> RuntimeClientError {
    RuntimeClientError::Rejected {
        code: rejected.code,
        summary: rejected.summary,
    }
}

fn overlay_rejected(rejected: DecisionOverlayRejected) -> RuntimeClientError {
    RuntimeClientError::OverlayRejected {
        code: rejected.code,
        summary: rejected.summary,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use diskplan_proto::diskplan::v1::StageActionEdit;

    fn opaque(value: impl AsRef<[u8]>) -> OpaqueIdentifier {
        OpaqueIdentifier {
            value: value.as_ref().to_vec(),
        }
    }

    fn digest(value: impl AsRef<[u8]>) -> Digest256 {
        Digest256 {
            value: value.as_ref().to_vec(),
        }
    }

    #[test]
    fn plan_chunk_admission_is_incrementally_bounded() {
        let mut chunks = Vec::new();
        let mut admitted = 0_u64;
        admit_plan_chunk(&mut chunks, &mut admitted, vec![0x41; 16]).unwrap();
        assert_eq!(chunks.len(), 1);
        assert_eq!(admitted, 16);

        let mut count_limited = vec![Vec::new(); MAXIMUM_PLAN_PROJECTION_RECORD_COUNT];
        let mut count_bytes = 0;
        assert!(matches!(
            admit_plan_chunk(&mut count_limited, &mut count_bytes, Vec::new()),
            Err(RuntimeClientError::Limit("plan projection chunk count"))
        ));

        let mut byte_limited = Vec::new();
        let mut byte_count = 0;
        assert!(matches!(
            admit_plan_chunk(
                &mut byte_limited,
                &mut byte_count,
                vec![0; MAXIMUM_PLAN_PROJECTION_RAW_CHUNK_BYTES + 1]
            ),
            Err(RuntimeClientError::Limit("plan projection chunk bytes"))
        ));
        assert!(byte_limited.is_empty());

        let mut aggregate_limited = Vec::new();
        let mut aggregate_bytes =
            MAXIMUM_PLAN_PROJECTION_RAW_BYTES - MAXIMUM_PLAN_PROJECTION_MANIFEST_BYTES as u64;
        assert!(matches!(
            admit_plan_chunk(&mut aggregate_limited, &mut aggregate_bytes, vec![0]),
            Err(RuntimeClientError::Limit("plan projection byte budget"))
        ));
        assert!(aggregate_limited.is_empty());
    }

    #[test]
    fn plan_binding_repeats_the_exact_scan_authority() {
        let final_evidence = [0x41; 32];
        let checkpoint_evidence = [0x42; 32];
        let checkpoint_id = hex::encode(final_evidence).into_bytes();
        let expected = PlanScanBinding {
            scan_session_id: b"scan-session".to_vec(),
            scan_checkpoint_id: checkpoint_id.clone(),
            scan_checkpoint_evidence_sha256: checkpoint_evidence.to_vec(),
            final_evidence_sha256: final_evidence.to_vec(),
        };
        let mut manifest = PlanProjectionManifest {
            scan_session_id: Some(opaque(&expected.scan_session_id)),
            scan_checkpoint_id: Some(opaque(&checkpoint_id)),
            scan_checkpoint_evidence_sha256: Some(digest(checkpoint_evidence)),
            evidence_sha256: Some(digest(final_evidence)),
            ..Default::default()
        };

        verify_plan_scan_binding(&manifest, &expected).unwrap();
        manifest.scan_session_id = Some(opaque(b"other-scan"));
        assert!(matches!(
            verify_plan_scan_binding(&manifest, &expected),
            Err(RuntimeClientError::Binding(_))
        ));
    }

    #[test]
    fn overlay_acknowledgement_must_match_the_exact_requested_delta() {
        let action_id = b"action";
        let edit = DecisionOverlayEdit {
            kind: DecisionEditKind::StageAction as i32,
            edit: Some(decision_overlay_edit::Edit::StageAction(StageActionEdit {
                action_id: Some(opaque(action_id)),
            })),
        };
        let mut acknowledged = DecisionOverlayAcknowledged {
            revision: 1,
            selected_action_ids: vec![opaque(action_id)],
            ..Default::default()
        };

        verify_overlay_transition(0, std::slice::from_ref(&edit), None, &acknowledged).unwrap();
        acknowledged.revision = 2;
        assert!(matches!(
            verify_overlay_transition(0, std::slice::from_ref(&edit), None, &acknowledged),
            Err(RuntimeClientError::Binding(_))
        ));
        acknowledged.revision = 1;
        acknowledged.selected_action_ids.clear();
        assert!(matches!(
            verify_overlay_transition(0, &[edit], None, &acknowledged),
            Err(RuntimeClientError::Binding(_))
        ));
    }
}
