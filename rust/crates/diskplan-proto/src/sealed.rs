use std::collections::{BTreeMap, BTreeSet};

use prost::Message;
use sha2::{Digest, Sha256};

use crate::CanonicalEnvelopeReceipt;
use crate::diskplan::v1::{
    ActionExecutionPreviewProjection, AdapterOutcomeKind, ApplyReviewProjection,
    ApplyStartFailureKind, DecisionOverlayAcknowledged, Digest256, DryRunProjection,
    DryRunProjectionManifest, DryRunProjectionPayload, ExecutionStepStatus, ExecutionStreamEvent,
    ExecutionUnitProjection, ExecutionUnitStatus, OpaqueIdentifier, PlanActionKind,
    PlanActionProjection, PlanProjectionManifest, PlanStageability, PostVerificationKind,
    RevalidationFailureKind, RevalidationProjectionPayload, RevalidationSubject, RuntimeRejectCode,
    adapter_outcome_projection, envelope, execution_stream_event, execution_unit_projection,
    plan_projection_record, post_verification_projection, revalidation_finding_projection,
    runtime_event,
};
use crate::runtime::{RuntimeProjectionError, VerifiedPlanProjection};

pub const RUNTIME_MANIFEST_VERSION: u32 = 1;
pub const MAXIMUM_RUNTIME_ACTION_COUNT: u32 = 100_000;
pub const MAXIMUM_RUNTIME_FINDING_COUNT: u32 = 1_000_000;
pub const MAXIMUM_RUNTIME_PROJECTION_BYTES: u32 = 12 * 1024 * 1024;
pub const MAXIMUM_OVERLAY_WAIVER_COUNT: u32 = 100_000;
pub const MAXIMUM_OVERLAY_NOTE_COUNT: u32 = 10_000;
pub const MAXIMUM_OVERLAY_NOTE_BYTES: u32 = 1024 * 1024;
pub const MAXIMUM_EXECUTION_EVENT_COUNT: u64 = 1_000_000;
pub const MAXIMUM_EXECUTION_ENCODED_BYTES: u64 = 768 * 1024 * 1024;
pub const MAXIMUM_OPAQUE_IDENTIFIER_BYTES: usize = 256;
const MAXIMUM_CONSUMED_REVIEW_BINDINGS: usize = 100_000;

const DRY_RUN_PAYLOAD_DOMAIN: &[u8] = b"diskplan/dry-run-projection-payload/v1\0";
const DRY_RUN_FINAL_DOMAIN: &[u8] = b"diskplan/dry-run-projection-final/v1\0";
const REVALIDATION_DOMAIN: &[u8] = b"diskplan/revalidation-projection/v1\0";
const OVERLAY_PROJECTION_DOMAIN: &[u8] = b"diskplan/decision-overlay-projection/v1\0";
const APPLY_REVIEW_DOMAIN: &[u8] = b"diskplan/apply-review-projection/v1\0";
const EXECUTION_RECORD_DOMAIN: &[u8] = b"diskplan/execution-record/v1\0";

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedDryRunProjection {
    payload: DryRunProjectionPayload,
    manifest: DryRunProjectionManifest,
}

impl VerifiedDryRunProjection {
    pub fn payload(&self) -> &DryRunProjectionPayload {
        &self.payload
    }

    pub fn manifest(&self) -> &DryRunProjectionManifest {
        &self.manifest
    }
}

/// Stateful verifier for the immutable plan plus overlay chain.
///
/// Intrinsic digest verification is necessary but not sufficient because an
/// untrusted frontend can splice two independently valid projections. This
/// object retains the exact predecessor and rejects any cross-plan, cross-
/// overlay, or cross-review substitution.
#[derive(Clone, Debug)]
pub struct RuntimeChainVerifier {
    plan: VerifiedPlanProjection,
    overlay: Option<DecisionOverlayAcknowledged>,
    apply_review: Option<ApplyReviewProjection>,
    consumed_review_bindings: BTreeSet<Vec<u8>>,
}

impl RuntimeChainVerifier {
    pub fn new(plan: VerifiedPlanProjection) -> Self {
        Self {
            plan,
            overlay: None,
            apply_review: None,
            consumed_review_bindings: BTreeSet::new(),
        }
    }

    pub fn plan(&self) -> &VerifiedPlanProjection {
        &self.plan
    }

    pub fn verify_overlay(
        &mut self,
        canonical_overlay: &[u8],
    ) -> Result<(), RuntimeProjectionError> {
        let overlay = decode_and_verify_decision_overlay(canonical_overlay)?;
        validate_exact_plan_reference(
            &self.plan.manifest,
            overlay.projection_id.as_ref(),
            overlay.plan_id.as_ref(),
            overlay.plan_sha256.as_ref(),
            overlay.evidence_id.as_ref(),
            overlay.evidence_sha256.as_ref(),
            overlay.scan_session_id.as_ref(),
            overlay.scan_checkpoint_id.as_ref(),
            overlay.scan_checkpoint_evidence_sha256.as_ref(),
        )?;

        let actions = plan_actions(&self.plan);
        let selected = opaque_digest_set(&overlay.selected_action_ids, "selected action_id")?;
        if selected
            .iter()
            .any(|action_id| !actions.contains_key(action_id))
        {
            return Err(RuntimeProjectionError::UnknownReference(
                "overlay selected action_id",
            ));
        }
        let mut acknowledged_by_action: BTreeMap<Vec<u8>, BTreeSet<Vec<u8>>> = BTreeMap::new();
        for waiver in &overlay.acknowledged_waivers {
            let action_id = digest_opaque(waiver.action_id.as_ref(), "waiver action_id")?;
            let waiver_id = opaque_value(waiver.waiver_id.as_ref(), "waiver_id")?;
            acknowledged_by_action
                .entry(action_id.to_vec())
                .or_default()
                .insert(waiver_id.to_vec());
        }
        for action_id in &selected {
            let action = actions
                .get(action_id)
                .expect("selected action membership was validated");
            let stageability = PlanStageability::try_from(action.stageability).map_err(|_| {
                RuntimeProjectionError::InvalidManifest("selected action has unknown stageability")
            })?;
            let required: BTreeSet<Vec<u8>> = action
                .required_waivers
                .iter()
                .map(|waiver| {
                    opaque_value(waiver.waiver_id.as_ref(), "required waiver_id")
                        .map(ToOwned::to_owned)
                })
                .collect::<Result<_, _>>()?;
            let acknowledged = acknowledged_by_action.remove(action_id).unwrap_or_default();
            match stageability {
                PlanStageability::Stageable if required.is_empty() && acknowledged.is_empty() => {}
                PlanStageability::RequiresWaivers
                    if acknowledged == required && !required.is_empty() => {}
                PlanStageability::NotStageable => {
                    return Err(RuntimeProjectionError::InvalidManifest(
                        "overlay selects a not-stageable action",
                    ));
                }
                _ => {
                    return Err(RuntimeProjectionError::InvalidManifest(
                        "overlay waiver set differs from authoritative plan",
                    ));
                }
            }
        }
        if !acknowledged_by_action.is_empty() {
            return Err(RuntimeProjectionError::InvalidManifest(
                "overlay waiver belongs to an unselected action",
            ));
        }
        let expected_force: BTreeSet<_> = selected
            .iter()
            .filter(|action_id| {
                actions
                    .get(*action_id)
                    .is_some_and(|action| action.requires_force)
            })
            .cloned()
            .collect();
        let actual_force =
            opaque_digest_set(&overlay.force_warning_action_ids, "force warning action_id")?;
        if actual_force != expected_force {
            return Err(RuntimeProjectionError::InvalidManifest(
                "overlay force warning list differs from plan",
            ));
        }
        for waiver in &overlay.acknowledged_waivers {
            let action_id = digest_opaque(waiver.action_id.as_ref(), "waiver action_id")?;
            let waiver_id = opaque_value(waiver.waiver_id.as_ref(), "waiver_id")?;
            let Some(action) = actions.get(action_id) else {
                return Err(RuntimeProjectionError::UnknownReference(
                    "overlay waiver action_id",
                ));
            };
            if !action.required_waivers.iter().any(|required| {
                required
                    .waiver_id
                    .as_ref()
                    .is_some_and(|identifier| identifier.value.as_slice() == waiver_id)
            }) {
                return Err(RuntimeProjectionError::UnknownReference(
                    "overlay waiver_id",
                ));
            }
        }
        self.overlay = Some(overlay);
        self.apply_review = None;
        Ok(())
    }

    pub fn verify_dry_run(
        &self,
        canonical_projection: &[u8],
    ) -> Result<VerifiedDryRunProjection, RuntimeProjectionError> {
        let verified = decode_and_verify_dry_run_projection(canonical_projection)?;
        let overlay = self
            .overlay
            .as_ref()
            .ok_or(RuntimeProjectionError::InvalidManifest(
                "dry-run has no accepted overlay predecessor",
            ))?;
        validate_exact_plan_reference(
            &self.plan.manifest,
            verified.manifest.projection_id.as_ref(),
            verified.manifest.plan_id.as_ref(),
            verified.manifest.plan_sha256.as_ref(),
            verified.manifest.evidence_id.as_ref(),
            verified.manifest.evidence_sha256.as_ref(),
            verified.manifest.scan_session_id.as_ref(),
            verified.manifest.scan_checkpoint_id.as_ref(),
            verified.manifest.scan_checkpoint_evidence_sha256.as_ref(),
        )?;
        validate_exact_overlay_reference(
            overlay,
            verified.manifest.overlay_id.as_ref(),
            verified.manifest.overlay_revision,
            verified.manifest.overlay_sha256.as_ref(),
            verified.manifest.selected_action_count,
        )?;
        validate_selected_action_projection(
            &self.plan,
            overlay,
            verified.payload.actions.iter().map(|action| {
                (
                    action.action_id.as_ref(),
                    action.execution_preview.as_ref(),
                    None,
                )
            }),
        )?;
        Ok(verified)
    }

    pub fn verify_apply_review(
        &mut self,
        canonical_projection: &[u8],
    ) -> Result<ApplyReviewProjection, RuntimeProjectionError> {
        let review = decode_and_verify_apply_review(canonical_projection)?;
        let review_binding = digest_value(
            review.review_binding_sha256.as_ref(),
            "review_binding_sha256",
        )?;
        if self.consumed_review_bindings.len() >= MAXIMUM_CONSUMED_REVIEW_BINDINGS {
            return Err(RuntimeProjectionError::InvalidManifest(
                "consumed apply review binding budget is exhausted",
            ));
        }
        if self.consumed_review_bindings.contains(review_binding) {
            return Err(RuntimeProjectionError::InvalidManifest(
                "apply review binding was already consumed",
            ));
        }
        let overlay = self
            .overlay
            .as_ref()
            .ok_or(RuntimeProjectionError::InvalidManifest(
                "apply review has no accepted overlay predecessor",
            ))?;
        validate_exact_plan_reference(
            &self.plan.manifest,
            review.projection_id.as_ref(),
            review.plan_id.as_ref(),
            review.plan_sha256.as_ref(),
            review.evidence_id.as_ref(),
            review.evidence_sha256.as_ref(),
            review.scan_session_id.as_ref(),
            review.scan_checkpoint_id.as_ref(),
            review.scan_checkpoint_evidence_sha256.as_ref(),
        )?;
        validate_exact_overlay_reference(
            overlay,
            review.overlay_id.as_ref(),
            review.overlay_revision,
            review.overlay_sha256.as_ref(),
            review.selected_action_count,
        )?;
        validate_selected_action_projection(
            &self.plan,
            overlay,
            review.actions.iter().map(|action| {
                (
                    action.action_id.as_ref(),
                    action.execution_preview.as_ref(),
                    Some(action.requires_force),
                )
            }),
        )?;
        let review_force =
            opaque_digest_set(&review.force_warning_action_ids, "review force action_id")?;
        let overlay_force =
            opaque_digest_set(&overlay.force_warning_action_ids, "overlay force action_id")?;
        if review_force != overlay_force {
            return Err(RuntimeProjectionError::InvalidManifest(
                "apply-review force list differs from overlay",
            ));
        }
        self.apply_review = Some(review.clone());
        Ok(review)
    }

    /// Consumes a live apply review after the engine terminally rejects the
    /// exact confirmation request. Both messages must first pass canonical
    /// envelope admission, so callers cannot manufacture a decoded rejection
    /// or discard unknown nested fields before changing verifier state.
    pub fn verify_rejected_confirm(
        &mut self,
        confirm_envelope: &CanonicalEnvelopeReceipt,
        rejection_envelope: &CanonicalEnvelopeReceipt,
        expected_runtime_session_id: &[u8],
    ) -> Result<(), RuntimeProjectionError> {
        let confirm = match confirm_envelope.envelope().body.as_ref() {
            Some(envelope::Body::ConfirmApplyRequest(confirm))
                if confirm.request_id != 0
                    && confirm_envelope.envelope().sequence == confirm.request_id =>
            {
                confirm
            }
            _ => {
                return Err(RuntimeProjectionError::InvalidManifest(
                    "confirm request envelope binding is invalid",
                ));
            }
        };
        let event = match rejection_envelope.envelope().body.as_ref() {
            Some(envelope::Body::RuntimeEvent(event))
                if event.request_id == confirm.request_id
                    && rejection_envelope.envelope().sequence == event.event_sequence
                    && opaque_value(event.runtime_session_id.as_ref(), "runtime_session_id")?
                        == expected_runtime_session_id =>
            {
                event
            }
            _ => {
                return Err(RuntimeProjectionError::InvalidManifest(
                    "confirm rejection envelope binding is invalid",
                ));
            }
        };
        let rejected = match event.body.as_ref() {
            Some(runtime_event::Body::RuntimeRejected(rejected))
                if rejected.code == RuntimeRejectCode::ConfirmationMismatch as i32
                    && !rejected.summary.is_empty() =>
            {
                rejected
            }
            _ => {
                return Err(RuntimeProjectionError::InvalidManifest(
                    "confirm response is not a typed rejection",
                ));
            }
        };
        let _ = rejected;
        let review = self
            .apply_review
            .as_ref()
            .ok_or(RuntimeProjectionError::InvalidManifest(
                "confirm rejection has no accepted apply-review predecessor",
            ))?;
        let review_binding = digest_value(
            review.review_binding_sha256.as_ref(),
            "review_binding_sha256",
        )?;
        if opaque_value(confirm.apply_review_id.as_ref(), "confirm apply_review_id")?
            != opaque_value(review.apply_review_id.as_ref(), "expected apply_review_id")?
            || digest_value(
                confirm.review_binding_sha256.as_ref(),
                "confirm review_binding_sha256",
            )? != review_binding
        {
            return Err(RuntimeProjectionError::InvalidManifest(
                "confirm request differs from accepted apply review",
            ));
        }
        let confirmed_force = opaque_digest_set(
            &confirm.confirmed_force_action_ids,
            "confirmed force action_id",
        )?;
        let review_force =
            opaque_digest_set(&review.force_warning_action_ids, "review force action_id")?;
        if confirmed_force != review_force {
            return Err(RuntimeProjectionError::InvalidManifest(
                "confirm force set differs from accepted apply review",
            ));
        }
        self.consumed_review_bindings
            .insert(review_binding.to_vec());
        self.apply_review = None;
        Ok(())
    }

    pub fn verify_execution_stream(
        &mut self,
        canonical_events: &[Vec<u8>],
    ) -> Result<Vec<ExecutionStreamEvent>, RuntimeProjectionError> {
        let events = decode_and_verify_execution_stream(canonical_events)?;
        let review = self
            .apply_review
            .as_ref()
            .ok_or(RuntimeProjectionError::InvalidManifest(
                "execution has no accepted apply-review predecessor",
            ))?;
        validate_execution_predecessor(&self.plan, review, &events)?;
        let review_binding = digest_value(
            review.review_binding_sha256.as_ref(),
            "review_binding_sha256",
        )?
        .to_vec();
        self.consumed_review_bindings.insert(review_binding);
        self.apply_review = None;
        Ok(events)
    }
}

fn plan_actions(plan: &VerifiedPlanProjection) -> BTreeMap<Vec<u8>, PlanActionProjection> {
    plan.records
        .iter()
        .filter_map(|record| match record.body.as_ref() {
            Some(plan_projection_record::Body::Action(action)) => Some((
                action
                    .action_id
                    .as_ref()
                    .expect("verified plan action has an ID")
                    .value
                    .clone(),
                action.clone(),
            )),
            _ => None,
        })
        .collect()
}

fn opaque_digest_set(
    values: &[OpaqueIdentifier],
    field: &'static str,
) -> Result<BTreeSet<Vec<u8>>, RuntimeProjectionError> {
    let mut output = BTreeSet::new();
    for value in values {
        let value = digest_opaque(Some(value), field)?.to_vec();
        if !output.insert(value) {
            return Err(RuntimeProjectionError::DuplicateIdentifier(field));
        }
    }
    Ok(output)
}

#[allow(clippy::too_many_arguments)]
fn validate_exact_plan_reference(
    expected: &PlanProjectionManifest,
    projection_id: Option<&OpaqueIdentifier>,
    plan_id: Option<&OpaqueIdentifier>,
    plan_sha256: Option<&Digest256>,
    evidence_id: Option<&OpaqueIdentifier>,
    evidence_sha256: Option<&Digest256>,
    scan_session_id: Option<&OpaqueIdentifier>,
    scan_checkpoint_id: Option<&OpaqueIdentifier>,
    scan_checkpoint_evidence_sha256: Option<&Digest256>,
) -> Result<(), RuntimeProjectionError> {
    if opaque_value(projection_id, "projection_id")?
        != opaque_value(expected.projection_id.as_ref(), "expected projection_id")?
        || digest_opaque(plan_id, "plan_id")?
            != digest_opaque(expected.plan_id.as_ref(), "expected plan_id")?
        || digest_value(plan_sha256, "plan_sha256")?
            != digest_value(expected.plan_sha256.as_ref(), "expected plan_sha256")?
        || digest_opaque(evidence_id, "evidence_id")?
            != digest_opaque(expected.evidence_id.as_ref(), "expected evidence_id")?
        || digest_value(evidence_sha256, "evidence_sha256")?
            != digest_value(
                expected.evidence_sha256.as_ref(),
                "expected evidence_sha256",
            )?
        || opaque_value(scan_session_id, "scan_session_id")?
            != opaque_value(
                expected.scan_session_id.as_ref(),
                "expected scan_session_id",
            )?
        || opaque_value(scan_checkpoint_id, "scan_checkpoint_id")?
            != opaque_value(
                expected.scan_checkpoint_id.as_ref(),
                "expected scan_checkpoint_id",
            )?
        || digest_value(
            scan_checkpoint_evidence_sha256,
            "scan_checkpoint_evidence_sha256",
        )? != digest_value(
            expected.scan_checkpoint_evidence_sha256.as_ref(),
            "expected scan_checkpoint_evidence_sha256",
        )?
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "runtime plan predecessor differs from accepted plan",
        ));
    }
    Ok(())
}

fn validate_exact_overlay_reference(
    expected: &DecisionOverlayAcknowledged,
    overlay_id: Option<&OpaqueIdentifier>,
    revision: u64,
    overlay_sha256: Option<&Digest256>,
    selected_action_count: u64,
) -> Result<(), RuntimeProjectionError> {
    if opaque_value(overlay_id, "overlay_id")?
        != opaque_value(expected.overlay_id.as_ref(), "expected overlay_id")?
        || revision != expected.revision
        || digest_value(overlay_sha256, "overlay_sha256")?
            != digest_value(expected.overlay_sha256.as_ref(), "expected overlay_sha256")?
        || selected_action_count != expected.selected_action_count
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "runtime overlay predecessor differs from accepted overlay",
        ));
    }
    Ok(())
}

fn validate_selected_action_projection<'a>(
    plan: &VerifiedPlanProjection,
    overlay: &DecisionOverlayAcknowledged,
    projections: impl Iterator<
        Item = (
            Option<&'a OpaqueIdentifier>,
            Option<&'a ActionExecutionPreviewProjection>,
            Option<bool>,
        ),
    >,
) -> Result<(), RuntimeProjectionError> {
    let actions = plan_actions(plan);
    let expected = opaque_digest_set(&overlay.selected_action_ids, "selected action_id")?;
    let mut actual = BTreeSet::new();
    for (action_id, preview, requires_force) in projections {
        let action_id = digest_opaque(action_id, "projected action_id")?.to_vec();
        if !actual.insert(action_id.clone()) {
            return Err(RuntimeProjectionError::DuplicateIdentifier(
                "projected action_id",
            ));
        }
        let action = actions
            .get(&action_id)
            .ok_or(RuntimeProjectionError::UnknownReference(
                "projected action_id",
            ))?;
        if preview != action.execution_preview.as_ref()
            || requires_force.is_some_and(|value| value != action.requires_force)
        {
            return Err(RuntimeProjectionError::InvalidManifest(
                "runtime action projection differs from accepted plan",
            ));
        }
    }
    if actual != expected {
        return Err(RuntimeProjectionError::InvalidManifest(
            "runtime selected actions differ from accepted overlay",
        ));
    }
    Ok(())
}

fn validate_execution_predecessor(
    plan: &VerifiedPlanProjection,
    review: &ApplyReviewProjection,
    events: &[ExecutionStreamEvent],
) -> Result<(), RuntimeProjectionError> {
    let terminal = match events.last().and_then(|event| event.body.as_ref()) {
        Some(execution_stream_event::Body::ApplyFinished(terminal)) => terminal,
        _ => unreachable!("intrinsic execution verification requires a terminal"),
    };
    if opaque_value(
        terminal.apply_review_id.as_ref(),
        "terminal apply_review_id",
    )? != opaque_value(review.apply_review_id.as_ref(), "expected apply_review_id")?
        || digest_value(
            terminal.review_binding_sha256.as_ref(),
            "terminal review_binding_sha256",
        )? != digest_value(
            review.review_binding_sha256.as_ref(),
            "expected review_binding_sha256",
        )?
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "execution terminal differs from accepted apply review",
        ));
    }

    let start_failure = ApplyStartFailureKind::try_from(terminal.start_failure)
        .map_err(|_| RuntimeProjectionError::InvalidManifest("unknown apply start failure"))?;
    if start_failure == ApplyStartFailureKind::Unspecified {
        let Some(execution_stream_event::Body::ApplyStarted(started)) =
            events.first().and_then(|event| event.body.as_ref())
        else {
            return Err(RuntimeProjectionError::InvalidManifest(
                "execution has no apply-started predecessor binding",
            ));
        };
        validate_exact_plan_reference(
            &plan.manifest,
            started.projection_id.as_ref(),
            started.plan_id.as_ref(),
            started.plan_sha256.as_ref(),
            started.evidence_id.as_ref(),
            started.evidence_sha256.as_ref(),
            started.scan_session_id.as_ref(),
            started.scan_checkpoint_id.as_ref(),
            started.scan_checkpoint_evidence_sha256.as_ref(),
        )?;
        if opaque_value(started.apply_review_id.as_ref(), "apply_review_id")?
            != opaque_value(review.apply_review_id.as_ref(), "expected apply_review_id")?
            || opaque_value(started.overlay_id.as_ref(), "overlay_id")?
                != opaque_value(review.overlay_id.as_ref(), "expected overlay_id")?
            || digest_value(started.overlay_sha256.as_ref(), "overlay_sha256")?
                != digest_value(review.overlay_sha256.as_ref(), "expected overlay_sha256")?
            || started.overlay_revision != review.overlay_revision
            || started.selected_action_count != review.selected_action_count
            || digest_value(
                started.review_binding_sha256.as_ref(),
                "review_binding_sha256",
            )? != digest_value(
                review.review_binding_sha256.as_ref(),
                "expected review_binding_sha256",
            )?
            || digest_value(
                started.current_binding_sha256.as_ref(),
                "current_binding_sha256",
            )? != digest_value(
                review.current_binding_sha256.as_ref(),
                "expected current_binding_sha256",
            )?
            || digest_value(started.revalidation_sha256.as_ref(), "revalidation_sha256")?
                != digest_value(
                    review.revalidation_sha256.as_ref(),
                    "expected revalidation_sha256",
                )?
            || started.epoch != review.epoch
        {
            return Err(RuntimeProjectionError::InvalidManifest(
                "execution start differs from accepted apply review",
            ));
        }
    }

    let selected: BTreeSet<Vec<u8>> = review
        .actions
        .iter()
        .map(|action| {
            digest_opaque(action.action_id.as_ref(), "review action_id").map(|value| value.to_vec())
        })
        .collect::<Result<_, _>>()?;
    let allowed_release_sets: BTreeMap<Vec<u8>, BTreeSet<Vec<u8>>> = plan
        .records
        .iter()
        .filter_map(|record| match record.body.as_ref() {
            Some(plan_projection_record::Body::ReleaseSet(release_set))
                if release_set
                    .action_ids
                    .iter()
                    .all(|action_id| selected.contains(action_id.value.as_slice())) =>
            {
                Some((
                    release_set
                        .release_set_id
                        .as_ref()
                        .expect("verified release set has an ID")
                        .value
                        .clone(),
                    release_set
                        .action_ids
                        .iter()
                        .map(|action_id| action_id.value.clone())
                        .collect(),
                ))
            }
            _ => None,
        })
        .collect();
    let review_actions: BTreeMap<_, _> = review
        .actions
        .iter()
        .map(|action| {
            (
                action
                    .action_id
                    .as_ref()
                    .expect("verified review action has an ID")
                    .value
                    .clone(),
                action,
            )
        })
        .collect();
    let expected_force_warnings: BTreeSet<Vec<u8>> = review
        .force_warning_action_ids
        .iter()
        .map(|value| digest_opaque(Some(value), "review force action_id").map(ToOwned::to_owned))
        .collect::<Result<_, _>>()?;
    let mut observed_force_warnings = BTreeSet::new();
    for event in events.iter().take(events.len() - 1) {
        match event.body.as_ref() {
            Some(execution_stream_event::Body::UnitStarted(started)) => {
                validate_execution_unit_membership(
                    started.unit.as_ref(),
                    &selected,
                    &allowed_release_sets,
                )?;
            }
            Some(execution_stream_event::Body::UnitFinished(finished)) => {
                validate_execution_unit_membership(
                    finished.unit.as_ref(),
                    &selected,
                    &allowed_release_sets,
                )?;
            }
            Some(execution_stream_event::Body::UnitJitRejected(rejected)) => {
                let unit_actions = validate_execution_unit_membership(
                    rejected.unit.as_ref(),
                    &selected,
                    &allowed_release_sets,
                )?;
                validate_jit_revalidation_membership(rejected, &unit_actions)?;
            }
            Some(execution_stream_event::Body::UnitSkippedPrerequisite(skipped)) => {
                validate_execution_unit_membership(
                    skipped.unit.as_ref(),
                    &selected,
                    &allowed_release_sets,
                )?;
                for prerequisite in &skipped.blocking_prerequisites {
                    validate_execution_unit_membership(
                        Some(prerequisite),
                        &selected,
                        &allowed_release_sets,
                    )?;
                }
            }
            Some(execution_stream_event::Body::StepFinished(step)) => {
                let action_id = digest_opaque(step.action_id.as_ref(), "step action_id")?;
                if !selected.contains(action_id) {
                    return Err(RuntimeProjectionError::UnknownReference(
                        "execution step action_id",
                    ));
                }
            }
            Some(execution_stream_event::Body::ForceRequiredWarning(warning)) => {
                let action_id = digest_opaque(warning.action_id.as_ref(), "force action_id")?;
                if !observed_force_warnings.insert(action_id.to_vec()) {
                    return Err(RuntimeProjectionError::DuplicateIdentifier(
                        "execution force action_id",
                    ));
                }
                let Some(action) = review_actions.get(action_id) else {
                    return Err(RuntimeProjectionError::UnknownReference(
                        "execution force action_id",
                    ));
                };
                if !action.requires_force
                    || warning.preview.as_ref() != action.execution_preview.as_ref()
                {
                    return Err(RuntimeProjectionError::InvalidManifest(
                        "execution force warning differs from apply review",
                    ));
                }
            }
            Some(execution_stream_event::Body::ReleasePostVerificationFinished(release)) => {
                let release_set_id =
                    opaque_value(release.release_set_id.as_ref(), "release_set_id")?;
                if !allowed_release_sets.contains_key(release_set_id) {
                    return Err(RuntimeProjectionError::UnknownReference(
                        "execution release_set_id",
                    ));
                }
            }
            _ => {}
        }
    }
    if observed_force_warnings != expected_force_warnings {
        return Err(RuntimeProjectionError::InvalidManifest(
            "execution force warnings differ from apply review",
        ));
    }
    Ok(())
}

fn validate_jit_revalidation_membership(
    rejected: &crate::diskplan::v1::UnitJitRejectedProjection,
    unit_actions: &BTreeSet<Vec<u8>>,
) -> Result<(), RuntimeProjectionError> {
    let revalidation =
        rejected
            .revalidation
            .as_ref()
            .ok_or(RuntimeProjectionError::InvalidManifest(
                "JIT rejection has no revalidation",
            ))?;
    let outcome_actions: BTreeSet<Vec<u8>> = revalidation
        .action_outcomes
        .iter()
        .map(|outcome| {
            digest_opaque(outcome.action_id.as_ref(), "JIT outcome action_id")
                .map(ToOwned::to_owned)
        })
        .collect::<Result<_, _>>()?;
    if outcome_actions.len() != revalidation.action_outcomes.len()
        || &outcome_actions != unit_actions
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "JIT revalidation actions differ from execution unit",
        ));
    }
    Ok(())
}

fn validate_execution_unit_membership(
    unit: Option<&ExecutionUnitProjection>,
    selected: &BTreeSet<Vec<u8>>,
    allowed_release_sets: &BTreeMap<Vec<u8>, BTreeSet<Vec<u8>>>,
) -> Result<BTreeSet<Vec<u8>>, RuntimeProjectionError> {
    match unit.and_then(|unit| unit.unit.as_ref()) {
        Some(execution_unit_projection::Unit::ActionId(action_id)) => {
            let action_id = digest_opaque(Some(action_id), "execution action_id")?;
            if !selected.contains(action_id) {
                return Err(RuntimeProjectionError::UnknownReference(
                    "execution action_id",
                ));
            }
            Ok(BTreeSet::from([action_id.to_vec()]))
        }
        Some(execution_unit_projection::Unit::CompoundRelease(compound)) => {
            if compound.release_set_ids.is_empty() {
                return Err(RuntimeProjectionError::InvalidManifest(
                    "execution compound release set is empty",
                ));
            }
            let mut actions = BTreeSet::new();
            let mut seen_release_sets = BTreeSet::new();
            for release_set_id in &compound.release_set_ids {
                if !seen_release_sets.insert(release_set_id.value.as_slice()) {
                    return Err(RuntimeProjectionError::DuplicateIdentifier(
                        "execution compound release_set_id",
                    ));
                }
                let Some(release_actions) =
                    allowed_release_sets.get(release_set_id.value.as_slice())
                else {
                    return Err(RuntimeProjectionError::UnknownReference(
                        "execution compound release_set_id",
                    ));
                };
                actions.extend(release_actions.iter().cloned());
            }
            Ok(actions)
        }
        None => Err(RuntimeProjectionError::InvalidManifest(
            "execution unit is missing",
        )),
    }
}

fn verify_decision_overlay_acknowledged(
    overlay: &DecisionOverlayAcknowledged,
) -> Result<(), RuntimeProjectionError> {
    if overlay.maximum_selected_actions != MAXIMUM_RUNTIME_ACTION_COUNT
        || overlay.maximum_waiver_consents != MAXIMUM_OVERLAY_WAIVER_COUNT
        || overlay.maximum_user_notes != MAXIMUM_OVERLAY_NOTE_COUNT
        || overlay.maximum_note_bytes != MAXIMUM_OVERLAY_NOTE_BYTES
        || overlay.maximum_encoded_bytes != MAXIMUM_RUNTIME_PROJECTION_BYTES
        || overlay.selected_action_count != overlay.selected_action_ids.len() as u64
        || overlay.selected_action_ids.len() > MAXIMUM_RUNTIME_ACTION_COUNT as usize
        || overlay.acknowledged_waivers.len() > MAXIMUM_OVERLAY_WAIVER_COUNT as usize
        || overlay.user_notes.len() > MAXIMUM_OVERLAY_NOTE_COUNT as usize
        || overlay.encode_to_vec().len() > MAXIMUM_RUNTIME_PROJECTION_BYTES as usize
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "decision overlay count or byte budget is invalid",
        ));
    }
    opaque_value(overlay.projection_id.as_ref(), "projection_id")?;
    opaque_value(overlay.overlay_id.as_ref(), "overlay_id")?;
    digest_value(overlay.overlay_sha256.as_ref(), "overlay_sha256")?;
    validate_plan_evidence_binding(
        overlay.plan_id.as_ref(),
        overlay.plan_sha256.as_ref(),
        overlay.evidence_id.as_ref(),
        overlay.evidence_sha256.as_ref(),
    )?;
    validate_scan_binding(
        overlay.scan_session_id.as_ref(),
        overlay.scan_checkpoint_id.as_ref(),
        overlay.scan_checkpoint_evidence_sha256.as_ref(),
        overlay.evidence_sha256.as_ref(),
    )?;
    let selected: Vec<_> = overlay
        .selected_action_ids
        .iter()
        .map(|value| digest_opaque(Some(value), "selected action_id"))
        .collect::<Result<_, _>>()?;
    validate_unique(&selected, "selected action_id")?;
    let selected_set: BTreeSet<_> = selected.iter().copied().collect();
    let force: Vec<_> = overlay
        .force_warning_action_ids
        .iter()
        .map(|value| digest_opaque(Some(value), "force warning action_id"))
        .collect::<Result<_, _>>()?;
    validate_unique(&force, "force warning action_id")?;
    if force.iter().any(|value| !selected_set.contains(value)) {
        return Err(RuntimeProjectionError::InvalidManifest(
            "force warning is not selected",
        ));
    }
    let mut waiver_pairs = BTreeSet::new();
    for waiver in &overlay.acknowledged_waivers {
        let action_id = digest_opaque(waiver.action_id.as_ref(), "waiver action_id")?;
        let waiver_id = opaque_value(waiver.waiver_id.as_ref(), "waiver_id")?;
        digest_value(waiver.consent_sha256.as_ref(), "consent_sha256")?;
        if !selected_set.contains(action_id)
            || !waiver_pairs.insert((action_id.to_vec(), waiver_id.to_vec()))
        {
            return Err(RuntimeProjectionError::InvalidManifest(
                "acknowledged waiver binding is invalid",
            ));
        }
    }
    let note_bytes = overlay.user_notes.iter().try_fold(0_usize, |total, note| {
        total
            .checked_add(note.len())
            .ok_or(RuntimeProjectionError::InvalidManifest(
                "overlay note byte count overflow",
            ))
    })?;
    if note_bytes > MAXIMUM_OVERLAY_NOTE_BYTES as usize {
        return Err(RuntimeProjectionError::InvalidManifest(
            "overlay note bytes exceed maximum",
        ));
    }
    let expected = digest_value(
        overlay.projection_sha256.as_ref(),
        "overlay projection_sha256",
    )?;
    let mut unsigned = overlay.clone();
    unsigned.projection_sha256 = None;
    let digest = Sha256::digest(
        [
            OVERLAY_PROJECTION_DOMAIN,
            unsigned.encode_to_vec().as_slice(),
        ]
        .concat(),
    );
    if expected != digest.as_slice() {
        return Err(RuntimeProjectionError::InvalidManifest(
            "overlay projection digest mismatch",
        ));
    }
    Ok(())
}

pub fn decode_and_verify_decision_overlay(
    canonical_overlay: &[u8],
) -> Result<DecisionOverlayAcknowledged, RuntimeProjectionError> {
    if canonical_overlay.len() > MAXIMUM_RUNTIME_PROJECTION_BYTES as usize {
        return Err(RuntimeProjectionError::InvalidManifest(
            "decision overlay exceeds maximum",
        ));
    }
    let overlay = DecisionOverlayAcknowledged::decode(canonical_overlay)
        .map_err(|error| RuntimeProjectionError::Protobuf(error.to_string()))?;
    if overlay.encode_to_vec() != canonical_overlay {
        return Err(RuntimeProjectionError::InvalidManifest(
            "decision overlay is not canonical protobuf",
        ));
    }
    verify_decision_overlay_acknowledged(&overlay)?;
    Ok(overlay)
}

fn verify_dry_run_projection(
    projection: &DryRunProjection,
) -> Result<VerifiedDryRunProjection, RuntimeProjectionError> {
    let manifest = projection
        .manifest
        .as_ref()
        .ok_or(RuntimeProjectionError::InvalidManifest(
            "missing dry-run manifest",
        ))?;
    validate_dry_run_manifest(manifest)?;
    if projection.canonical_projection_payload.len() > MAXIMUM_RUNTIME_PROJECTION_BYTES as usize {
        return Err(RuntimeProjectionError::InvalidManifest(
            "dry-run payload exceeds maximum",
        ));
    }
    let payload =
        DryRunProjectionPayload::decode(projection.canonical_projection_payload.as_slice())
            .map_err(|error| RuntimeProjectionError::Protobuf(error.to_string()))?;
    if payload.encode_to_vec() != projection.canonical_projection_payload {
        return Err(RuntimeProjectionError::InvalidManifest(
            "dry-run payload is not canonical protobuf",
        ));
    }
    let revalidation =
        payload
            .revalidation
            .as_ref()
            .ok_or(RuntimeProjectionError::InvalidManifest(
                "missing dry-run revalidation",
            ))?;
    let action_ids: Vec<_> = payload
        .actions
        .iter()
        .map(|action| digest_opaque(action.action_id.as_ref(), "dry-run action_id"))
        .collect::<Result<_, _>>()?;
    validate_unique(&action_ids, "dry-run action_id")?;
    for action in &payload.actions {
        validate_preview(action.execution_preview.as_ref())?;
    }
    let summary = validate_revalidation(revalidation, &action_ids, manifest.current)?;
    if manifest.action_count != action_ids.len() as u64
        || manifest.selected_action_count != manifest.action_count
        || manifest.finding_count != summary.finding_count
        || manifest.current != summary.current
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "dry-run semantic counts are invalid",
        ));
    }
    let payload_digest = Sha256::digest(
        [
            DRY_RUN_PAYLOAD_DOMAIN,
            projection.canonical_projection_payload.as_slice(),
        ]
        .concat(),
    );
    if digest_value(manifest.payload_sha256.as_ref(), "dry-run payload_sha256")?
        != payload_digest.as_slice()
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "dry-run payload digest mismatch",
        ));
    }
    let revalidation_digest =
        Sha256::digest([REVALIDATION_DOMAIN, revalidation.encode_to_vec().as_slice()].concat());
    if digest_value(manifest.revalidation_sha256.as_ref(), "revalidation_sha256")?
        != revalidation_digest.as_slice()
        || digest_value(
            manifest.projection_sha256.as_ref(),
            "dry-run projection_sha256",
        )? != dry_run_final_digest(manifest)?.as_slice()
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "dry-run sealed digest mismatch",
        ));
    }
    Ok(VerifiedDryRunProjection {
        payload,
        manifest: manifest.clone(),
    })
}

pub fn decode_and_verify_dry_run_projection(
    canonical_projection: &[u8],
) -> Result<VerifiedDryRunProjection, RuntimeProjectionError> {
    if canonical_projection.len() > MAXIMUM_RUNTIME_PROJECTION_BYTES as usize {
        return Err(RuntimeProjectionError::InvalidManifest(
            "dry-run projection exceeds maximum",
        ));
    }
    let projection = DryRunProjection::decode(canonical_projection)
        .map_err(|error| RuntimeProjectionError::Protobuf(error.to_string()))?;
    if projection.encode_to_vec() != canonical_projection {
        return Err(RuntimeProjectionError::InvalidManifest(
            "dry-run projection is not canonical protobuf",
        ));
    }
    verify_dry_run_projection(&projection)
}

pub fn decode_and_verify_apply_review(
    canonical_projection: &[u8],
) -> Result<ApplyReviewProjection, RuntimeProjectionError> {
    if canonical_projection.len() > MAXIMUM_RUNTIME_PROJECTION_BYTES as usize {
        return Err(RuntimeProjectionError::InvalidManifest(
            "apply-review projection exceeds maximum",
        ));
    }
    let projection = ApplyReviewProjection::decode(canonical_projection)
        .map_err(|error| RuntimeProjectionError::Protobuf(error.to_string()))?;
    if projection.encode_to_vec() != canonical_projection {
        return Err(RuntimeProjectionError::InvalidManifest(
            "apply-review projection is not canonical protobuf",
        ));
    }
    validate_apply_review(&projection)?;
    let expected = digest_value(
        projection.projection_sha256.as_ref(),
        "apply-review projection_sha256",
    )?;
    let mut unsigned = projection.clone();
    unsigned.projection_sha256 = None;
    let digest =
        Sha256::digest([APPLY_REVIEW_DOMAIN, unsigned.encode_to_vec().as_slice()].concat());
    if expected != digest.as_slice() {
        return Err(RuntimeProjectionError::InvalidManifest(
            "apply-review projection digest mismatch",
        ));
    }
    Ok(projection)
}

pub fn decode_and_verify_execution_stream(
    canonical_events: &[Vec<u8>],
) -> Result<Vec<ExecutionStreamEvent>, RuntimeProjectionError> {
    if canonical_events.is_empty() || canonical_events.len() as u64 > MAXIMUM_EXECUTION_EVENT_COUNT
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "execution event count is invalid",
        ));
    }
    let mut events = Vec::with_capacity(canonical_events.len());
    let mut admitted_bytes = 0_u64;
    for bytes in canonical_events {
        admitted_bytes = admitted_bytes
            .checked_add(4_u64 + bytes.len() as u64)
            .ok_or(RuntimeProjectionError::InvalidManifest(
                "execution input byte count overflow",
            ))?;
        if admitted_bytes > MAXIMUM_EXECUTION_ENCODED_BYTES + 64 {
            return Err(RuntimeProjectionError::InvalidManifest(
                "execution input exceeds byte budget",
            ));
        }
        let event = ExecutionStreamEvent::decode(bytes.as_slice())
            .map_err(|error| RuntimeProjectionError::Protobuf(error.to_string()))?;
        if event.encode_to_vec() != *bytes {
            return Err(RuntimeProjectionError::InvalidManifest(
                "execution event is not canonical protobuf",
            ));
        }
        events.push(event);
    }
    let execution_id = opaque_value(events[0].execution_id.as_ref(), "execution_id")?;
    for (offset, event) in events.iter().enumerate() {
        if event.execution_event_index != offset as u64 + 1
            || opaque_value(event.execution_id.as_ref(), "execution_id")? != execution_id
            || event.body.is_none()
            || (offset + 1 != events.len()
                && matches!(
                    event.body.as_ref(),
                    Some(execution_stream_event::Body::ApplyFinished(_))
                ))
        {
            return Err(RuntimeProjectionError::InvalidRecord {
                index: event.execution_event_index,
                reason: "invalid execution event sequence",
            });
        }
        validate_execution_event_body(offset, event.body.as_ref())?;
    }
    let Some(execution_stream_event::Body::ApplyFinished(terminal)) =
        events.last().and_then(|e| e.body.as_ref())
    else {
        return Err(RuntimeProjectionError::InvalidManifest(
            "execution stream has no terminal",
        ));
    };
    validate_execution_summary(&events, terminal)?;

    let mut canonical = Vec::new();
    for (index, bytes) in canonical_events.iter().enumerate() {
        if index + 1 == canonical_events.len() {
            let mut terminal_event = events[index].clone();
            let Some(execution_stream_event::Body::ApplyFinished(finished)) =
                terminal_event.body.as_mut()
            else {
                unreachable!("the last event was validated as apply-finished")
            };
            finished.execution_record_sha256 = None;
            append_framed(&terminal_event.encode_to_vec(), &mut canonical)?;
        } else {
            append_framed(bytes, &mut canonical)?;
        }
    }
    if canonical.len() as u64 != terminal.encoded_event_bytes
        || terminal.maximum_event_count != MAXIMUM_EXECUTION_EVENT_COUNT
        || terminal.maximum_encoded_event_bytes != MAXIMUM_EXECUTION_ENCODED_BYTES
        || canonical.len() as u64 > MAXIMUM_EXECUTION_ENCODED_BYTES
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "execution byte budget is invalid",
        ));
    }
    let digest = Sha256::digest([EXECUTION_RECORD_DOMAIN, canonical.as_slice()].concat());
    if digest_value(
        terminal.execution_record_sha256.as_ref(),
        "execution_record_sha256",
    )? != digest.as_slice()
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "execution record digest mismatch",
        ));
    }
    Ok(events)
}

fn validate_execution_event_body(
    offset: usize,
    body: Option<&execution_stream_event::Body>,
) -> Result<(), RuntimeProjectionError> {
    match body {
        Some(execution_stream_event::Body::ApplyStarted(_)) if offset != 0 => Err(
            RuntimeProjectionError::InvalidManifest("apply-started is not the first event"),
        ),
        Some(execution_stream_event::Body::ApplyStarted(_))
        | Some(execution_stream_event::Body::ApplyFinished(_)) => Ok(()),
        Some(execution_stream_event::Body::UnitStarted(started)) => {
            validate_unit(started.unit.as_ref())
        }
        Some(execution_stream_event::Body::ForceRequiredWarning(warning)) => {
            digest_opaque(warning.action_id.as_ref(), "force warning action_id")?;
            validate_preview(warning.preview.as_ref())
        }
        Some(execution_stream_event::Body::StepFinished(step)) => {
            digest_opaque(step.action_id.as_ref(), "step action_id")?;
            if ExecutionStepStatus::try_from(step.status).is_err()
                || step.status == ExecutionStepStatus::Unspecified as i32
            {
                return Err(RuntimeProjectionError::InvalidManifest(
                    "execution step status is invalid",
                ));
            }
            validate_adapter_outcome(step.adapter_outcome.as_ref())?;
            validate_post_verification(step.post_verification.as_ref())
        }
        Some(execution_stream_event::Body::ReleasePostVerificationFinished(release)) => {
            opaque_value(release.release_set_id.as_ref(), "release_set_id")?;
            validate_post_verification(release.outcome.as_ref())
        }
        Some(execution_stream_event::Body::UnitFinished(finished)) => {
            validate_unit(finished.unit.as_ref())
        }
        Some(execution_stream_event::Body::AuditWriteFailed(failure)) => {
            if failure.code.is_empty() {
                Err(RuntimeProjectionError::InvalidManifest(
                    "audit failure has no code",
                ))
            } else {
                Ok(())
            }
        }
        Some(execution_stream_event::Body::UnitJitRejected(rejected)) => {
            validate_unit(rejected.unit.as_ref())?;
            let revalidation =
                rejected
                    .revalidation
                    .as_ref()
                    .ok_or(RuntimeProjectionError::InvalidManifest(
                        "missing JIT revalidation",
                    ))?;
            let action_ids: Vec<_> = revalidation
                .action_outcomes
                .iter()
                .map(|value| digest_opaque(value.action_id.as_ref(), "JIT action_id"))
                .collect::<Result<_, _>>()?;
            let summary = validate_revalidation(revalidation, &action_ids, true)?;
            if summary.current {
                return Err(RuntimeProjectionError::InvalidManifest(
                    "JIT rejection is current",
                ));
            }
            Ok(())
        }
        Some(execution_stream_event::Body::UnitSkippedPrerequisite(skipped)) => {
            validate_unit(skipped.unit.as_ref())?;
            if skipped.blocking_prerequisites.is_empty() {
                return Err(RuntimeProjectionError::InvalidManifest(
                    "prerequisite skip has no blocker",
                ));
            }
            for unit in &skipped.blocking_prerequisites {
                validate_unit(Some(unit))?;
            }
            Ok(())
        }
        Some(execution_stream_event::Body::CancellationAcknowledged(acknowledgement)) => {
            if acknowledgement.reason.is_empty() {
                Err(RuntimeProjectionError::InvalidManifest(
                    "cancellation acknowledgement has no reason",
                ))
            } else {
                Ok(())
            }
        }
        None => Err(RuntimeProjectionError::InvalidManifest(
            "execution event has no body",
        )),
    }
}

fn validate_adapter_outcome(
    outcome: Option<&crate::diskplan::v1::AdapterOutcomeProjection>,
) -> Result<(), RuntimeProjectionError> {
    let outcome = outcome.ok_or(RuntimeProjectionError::InvalidManifest(
        "missing adapter outcome",
    ))?;
    let kind = AdapterOutcomeKind::try_from(outcome.kind)
        .map_err(|_| RuntimeProjectionError::InvalidManifest("unknown adapter outcome"))?;
    match (kind, outcome.detail.as_ref()) {
        (AdapterOutcomeKind::Succeeded, None) => Ok(()),
        (
            AdapterOutcomeKind::Failed | AdapterOutcomeKind::TimedOut,
            Some(adapter_outcome_projection::Detail::Failure(failure)),
        ) if !failure.code.is_empty() => Ok(()),
        (AdapterOutcomeKind::Cancelled, None)
        | (AdapterOutcomeKind::Cancelled, Some(adapter_outcome_projection::Detail::Failure(_))) => {
            Ok(())
        }
        (
            AdapterOutcomeKind::NotStarted,
            Some(adapter_outcome_projection::Detail::NotStartedReason(reason)),
        ) if !reason.is_empty() => Ok(()),
        _ => Err(RuntimeProjectionError::InvalidManifest(
            "adapter outcome detail is invalid",
        )),
    }
}

fn validate_post_verification(
    verification: Option<&crate::diskplan::v1::PostVerificationProjection>,
) -> Result<(), RuntimeProjectionError> {
    let verification = verification.ok_or(RuntimeProjectionError::InvalidManifest(
        "missing post-verification",
    ))?;
    if verification.code.is_empty() {
        return Err(RuntimeProjectionError::InvalidManifest(
            "post-verification has no code",
        ));
    }
    let kind = PostVerificationKind::try_from(verification.kind)
        .map_err(|_| RuntimeProjectionError::InvalidManifest("unknown post-verification"))?;
    match (kind, verification.detail.as_ref()) {
        (
            PostVerificationKind::Satisfied
            | PostVerificationKind::Missing
            | PostVerificationKind::NotSatisfied,
            None,
        ) => Ok(()),
        (
            PostVerificationKind::ExpectedResidual,
            Some(post_verification_projection::Detail::Residual(residual)),
        ) if !residual.code.is_empty() => Ok(()),
        (
            PostVerificationKind::Unknown,
            Some(post_verification_projection::Detail::Unknown(unknown)),
        ) if !unknown.code.is_empty() && !unknown.summary.is_empty() => Ok(()),
        (
            PostVerificationKind::Unreadable | PostVerificationKind::Failed,
            Some(post_verification_projection::Detail::ObservationFailure(failure)),
        ) if !failure.code.is_empty() && !failure.collector.is_empty() => Ok(()),
        _ => Err(RuntimeProjectionError::InvalidManifest(
            "post-verification detail is invalid",
        )),
    }
}

struct RevalidationSummary {
    finding_count: u64,
    current: bool,
}

fn validate_dry_run_manifest(
    manifest: &DryRunProjectionManifest,
) -> Result<(), RuntimeProjectionError> {
    if manifest.manifest_version != RUNTIME_MANIFEST_VERSION
        || manifest.maximum_action_count != MAXIMUM_RUNTIME_ACTION_COUNT
        || manifest.maximum_finding_count != MAXIMUM_RUNTIME_FINDING_COUNT
        || manifest.maximum_projection_payload_bytes != MAXIMUM_RUNTIME_PROJECTION_BYTES
        || manifest.action_count > MAXIMUM_RUNTIME_ACTION_COUNT as u64
        || manifest.finding_count > MAXIMUM_RUNTIME_FINDING_COUNT as u64
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "dry-run manifest version or budget is invalid",
        ));
    }
    opaque_value(manifest.projection_id.as_ref(), "projection_id")?;
    opaque_value(manifest.dry_run_id.as_ref(), "dry_run_id")?;
    opaque_value(manifest.overlay_id.as_ref(), "overlay_id")?;
    digest_value(manifest.overlay_sha256.as_ref(), "overlay_sha256")?;
    if manifest.current {
        digest_value(
            manifest.current_binding_sha256.as_ref(),
            "current_binding_sha256",
        )?;
    } else if manifest.current_binding_sha256.is_some() {
        return Err(RuntimeProjectionError::InvalidManifest(
            "non-current dry-run has a current binding",
        ));
    }
    validate_plan_evidence_binding(
        manifest.plan_id.as_ref(),
        manifest.plan_sha256.as_ref(),
        manifest.evidence_id.as_ref(),
        manifest.evidence_sha256.as_ref(),
    )?;
    validate_scan_binding(
        manifest.scan_session_id.as_ref(),
        manifest.scan_checkpoint_id.as_ref(),
        manifest.scan_checkpoint_evidence_sha256.as_ref(),
        manifest.evidence_sha256.as_ref(),
    )?;
    validate_epoch(manifest.epoch.as_ref())
}

fn validate_apply_review(projection: &ApplyReviewProjection) -> Result<(), RuntimeProjectionError> {
    if projection.maximum_action_count != MAXIMUM_RUNTIME_ACTION_COUNT
        || projection.maximum_finding_count != MAXIMUM_RUNTIME_FINDING_COUNT
        || projection.maximum_encoded_bytes != MAXIMUM_RUNTIME_PROJECTION_BYTES
        || projection.selected_action_count != projection.actions.len() as u64
        || projection.actions.len() > MAXIMUM_RUNTIME_ACTION_COUNT as usize
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "apply-review budget or selected count is invalid",
        ));
    }
    opaque_value(projection.apply_review_id.as_ref(), "apply_review_id")?;
    opaque_value(projection.projection_id.as_ref(), "projection_id")?;
    opaque_value(projection.overlay_id.as_ref(), "overlay_id")?;
    digest_value(projection.overlay_sha256.as_ref(), "overlay_sha256")?;
    digest_value(
        projection.review_binding_sha256.as_ref(),
        "review_binding_sha256",
    )?;
    digest_value(
        projection.current_binding_sha256.as_ref(),
        "current_binding_sha256",
    )?;
    validate_plan_evidence_binding(
        projection.plan_id.as_ref(),
        projection.plan_sha256.as_ref(),
        projection.evidence_id.as_ref(),
        projection.evidence_sha256.as_ref(),
    )?;
    validate_scan_binding(
        projection.scan_session_id.as_ref(),
        projection.scan_checkpoint_id.as_ref(),
        projection.scan_checkpoint_evidence_sha256.as_ref(),
        projection.evidence_sha256.as_ref(),
    )?;
    validate_epoch(projection.epoch.as_ref())?;
    let action_ids: Vec<_> = projection
        .actions
        .iter()
        .map(|action| digest_opaque(action.action_id.as_ref(), "apply-review action_id"))
        .collect::<Result<_, _>>()?;
    validate_unique(&action_ids, "apply-review action_id")?;
    for action in &projection.actions {
        validate_preview(action.execution_preview.as_ref())?;
    }
    let revalidation =
        projection
            .revalidation
            .as_ref()
            .ok_or(RuntimeProjectionError::InvalidManifest(
                "missing apply-review revalidation",
            ))?;
    let summary = validate_revalidation(revalidation, &action_ids, true)?;
    if !summary.current {
        return Err(RuntimeProjectionError::InvalidManifest(
            "apply-review revalidation is not current",
        ));
    }
    let mut expected_force: Vec<_> = projection
        .actions
        .iter()
        .filter(|action| action.requires_force)
        .map(|action| {
            action
                .action_id
                .as_ref()
                .expect("validated action ID")
                .value
                .as_slice()
        })
        .collect();
    expected_force.sort_unstable();
    let actual_force: Vec<_> = projection
        .force_warning_action_ids
        .iter()
        .map(|value| value.value.as_slice())
        .collect();
    if actual_force != expected_force {
        return Err(RuntimeProjectionError::InvalidManifest(
            "apply-review force warning list is invalid",
        ));
    }
    let revalidation_digest =
        Sha256::digest([REVALIDATION_DOMAIN, revalidation.encode_to_vec().as_slice()].concat());
    if digest_value(
        projection.revalidation_sha256.as_ref(),
        "revalidation_sha256",
    )? != revalidation_digest.as_slice()
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "apply-review revalidation digest mismatch",
        ));
    }
    Ok(())
}

fn validate_revalidation(
    revalidation: &RevalidationProjectionPayload,
    selected_action_ids: &[&[u8]],
    require_complete_outcomes: bool,
) -> Result<RevalidationSummary, RuntimeProjectionError> {
    let selected: BTreeSet<_> = selected_action_ids.iter().copied().collect();
    let mut outcomes = BTreeSet::new();
    let mut finding_ids = BTreeSet::new();
    let mut finding_count = revalidation.global_findings.len() as u64;
    for finding in &revalidation.global_findings {
        validate_finding(finding, None)?;
        if !finding_ids.insert(opaque_value(finding.finding_id.as_ref(), "finding_id")?) {
            return Err(RuntimeProjectionError::DuplicateIdentifier("finding_id"));
        }
    }
    for outcome in &revalidation.action_outcomes {
        let action_id = digest_opaque(outcome.action_id.as_ref(), "outcome action_id")?;
        if !selected.contains(action_id) || !outcomes.insert(action_id) {
            return Err(RuntimeProjectionError::InvalidManifest(
                "revalidation outcome membership is invalid",
            ));
        }
        if outcome.current != outcome.findings.is_empty() {
            return Err(RuntimeProjectionError::InvalidManifest(
                "revalidation current flag is invalid",
            ));
        }
        finding_count = finding_count
            .checked_add(outcome.findings.len() as u64)
            .ok_or(RuntimeProjectionError::InvalidManifest(
                "revalidation finding count overflow",
            ))?;
        for finding in &outcome.findings {
            validate_finding(finding, Some(action_id))?;
            if !finding_ids.insert(opaque_value(finding.finding_id.as_ref(), "finding_id")?) {
                return Err(RuntimeProjectionError::DuplicateIdentifier("finding_id"));
            }
        }
    }
    if !outcomes.is_subset(&selected)
        || (require_complete_outcomes && outcomes != selected)
        || finding_count > MAXIMUM_RUNTIME_FINDING_COUNT as u64
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "revalidation coverage or finding budget is invalid",
        ));
    }
    Ok(RevalidationSummary {
        finding_count,
        current: outcomes == selected
            && revalidation.global_findings.is_empty()
            && revalidation
                .action_outcomes
                .iter()
                .all(|value| value.current),
    })
}

fn validate_finding(
    finding: &crate::diskplan::v1::RevalidationFindingProjection,
    expected_action_id: Option<&[u8]>,
) -> Result<(), RuntimeProjectionError> {
    opaque_value(finding.finding_id.as_ref(), "finding_id")?;
    match expected_action_id {
        Some(expected)
            if digest_opaque(finding.action_id.as_ref(), "finding action_id")? != expected =>
        {
            return Err(RuntimeProjectionError::InvalidManifest(
                "finding action binding is invalid",
            ));
        }
        None if finding.action_id.is_some() => {
            return Err(RuntimeProjectionError::InvalidManifest(
                "global finding has an action ID",
            ));
        }
        _ => {}
    }
    let kind = RevalidationFailureKind::try_from(finding.kind)
        .map_err(|_| RuntimeProjectionError::InvalidManifest("unknown revalidation kind"))?;
    if RevalidationSubject::try_from(finding.subject).is_err()
        || finding.subject == RevalidationSubject::Unspecified as i32
        || kind == RevalidationFailureKind::Unspecified
        || finding.summary.is_empty()
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "typed revalidation finding is invalid",
        ));
    }
    match (kind, finding.detail.as_ref()) {
        (
            RevalidationFailureKind::Unknown,
            Some(revalidation_finding_projection::Detail::Unknown(unknown)),
        ) if !unknown.code.is_empty() && !unknown.summary.is_empty() => {}
        (
            RevalidationFailureKind::Unreadable | RevalidationFailureKind::CollectionFailed,
            Some(revalidation_finding_projection::Detail::ObservationFailure(failure)),
        ) if !failure.code.is_empty() && !failure.collector.is_empty() => {}
        (
            RevalidationFailureKind::Unknown
            | RevalidationFailureKind::Unreadable
            | RevalidationFailureKind::CollectionFailed,
            _,
        ) => {
            return Err(RuntimeProjectionError::InvalidManifest(
                "revalidation finding detail is invalid",
            ));
        }
        (_, None) => {}
        (_, Some(_)) => {
            return Err(RuntimeProjectionError::InvalidManifest(
                "revalidation finding has unexpected detail",
            ));
        }
    }
    Ok(())
}

fn validate_execution_summary(
    events: &[ExecutionStreamEvent],
    terminal: &crate::diskplan::v1::ApplyFinishedProjection,
) -> Result<(), RuntimeProjectionError> {
    let mut counts = [0_u64; 8];
    let mut audit_count = 0_u64;
    let mut cancellation_count = 0_u64;
    for event in &events[..events.len() - 1] {
        match event.body.as_ref() {
            Some(execution_stream_event::Body::UnitFinished(finished)) => {
                validate_unit(finished.unit.as_ref())?;
                let status = ExecutionUnitStatus::try_from(finished.status).map_err(|_| {
                    RuntimeProjectionError::InvalidManifest("unknown execution unit status")
                })?;
                let index = match status {
                    ExecutionUnitStatus::Succeeded => 0,
                    ExecutionUnitStatus::PartiallyFailed => 1,
                    ExecutionUnitStatus::Failed => 2,
                    ExecutionUnitStatus::Cancelled => 3,
                    ExecutionUnitStatus::SkippedPrerequisite => 4,
                    ExecutionUnitStatus::JitRejected => 5,
                    ExecutionUnitStatus::Expired => 6,
                    ExecutionUnitStatus::Superseded => 7,
                    ExecutionUnitStatus::Unspecified => {
                        return Err(RuntimeProjectionError::InvalidManifest(
                            "unspecified execution unit status",
                        ));
                    }
                };
                counts[index] += 1;
            }
            Some(execution_stream_event::Body::AuditWriteFailed(failure)) => {
                if failure.code.is_empty() {
                    return Err(RuntimeProjectionError::InvalidManifest(
                        "audit failure has no code",
                    ));
                }
                audit_count += 1;
            }
            Some(execution_stream_event::Body::CancellationAcknowledged(_)) => {
                cancellation_count += 1;
            }
            _ => {}
        }
    }
    if cancellation_count > 1 {
        return Err(RuntimeProjectionError::InvalidManifest(
            "execution has duplicate cancellation acknowledgements",
        ));
    }
    let terminal_apply_review_id = opaque_value(
        terminal.apply_review_id.as_ref(),
        "terminal apply_review_id",
    )?;
    let terminal_review_binding = digest_value(
        terminal.review_binding_sha256.as_ref(),
        "terminal review_binding_sha256",
    )?;
    let unit_count: u64 = counts.iter().sum();
    if terminal.event_count != events.len() as u64
        || terminal.unit_count != unit_count
        || terminal.succeeded_unit_count != counts[0]
        || terminal.partial_unit_count != counts[1]
        || terminal.failed_unit_count != counts[2]
        || terminal.cancelled_unit_count != counts[3]
        || terminal.skipped_unit_count != counts[4]
        || terminal.jit_rejected_unit_count != counts[5]
        || terminal.expired_unit_count != counts[6]
        || terminal.superseded_unit_count != counts[7]
        || terminal.audit_failure_count != audit_count
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "execution terminal summary is invalid",
        ));
    }
    let start_failure = ApplyStartFailureKind::try_from(terminal.start_failure)
        .map_err(|_| RuntimeProjectionError::InvalidManifest("unknown apply start failure"))?;
    if start_failure == ApplyStartFailureKind::Unspecified {
        let Some(execution_stream_event::Body::ApplyStarted(started)) =
            events.first().and_then(|event| event.body.as_ref())
        else {
            return Err(RuntimeProjectionError::InvalidManifest(
                "normal execution has no apply-started event",
            ));
        };
        validate_epoch(started.epoch.as_ref())?;
        opaque_value(started.apply_review_id.as_ref(), "apply_review_id")?;
        opaque_value(started.projection_id.as_ref(), "projection_id")?;
        opaque_value(started.overlay_id.as_ref(), "overlay_id")?;
        digest_value(started.overlay_sha256.as_ref(), "overlay_sha256")?;
        digest_value(
            started.review_binding_sha256.as_ref(),
            "review_binding_sha256",
        )?;
        digest_value(
            started.current_binding_sha256.as_ref(),
            "current_binding_sha256",
        )?;
        digest_value(started.revalidation_sha256.as_ref(), "revalidation_sha256")?;
        validate_plan_evidence_binding(
            started.plan_id.as_ref(),
            started.plan_sha256.as_ref(),
            started.evidence_id.as_ref(),
            started.evidence_sha256.as_ref(),
        )?;
        validate_scan_binding(
            started.scan_session_id.as_ref(),
            started.scan_checkpoint_id.as_ref(),
            started.scan_checkpoint_evidence_sha256.as_ref(),
            started.evidence_sha256.as_ref(),
        )?;
        if opaque_value(started.apply_review_id.as_ref(), "apply_review_id")?
            != terminal_apply_review_id
            || digest_value(
                started.review_binding_sha256.as_ref(),
                "review_binding_sha256",
            )? != terminal_review_binding
        {
            return Err(RuntimeProjectionError::InvalidManifest(
                "execution terminal apply authority mismatch",
            ));
        }
    } else if events.len() != 1 || unit_count != 0 || audit_count != 0 {
        return Err(RuntimeProjectionError::InvalidManifest(
            "apply start failure stream is invalid",
        ));
    }
    Ok(())
}

fn validate_unit(
    unit: Option<&crate::diskplan::v1::ExecutionUnitProjection>,
) -> Result<(), RuntimeProjectionError> {
    match unit.and_then(|value| value.unit.as_ref()) {
        Some(execution_unit_projection::Unit::ActionId(action_id)) => {
            digest_opaque(Some(action_id), "execution unit action_id")?;
        }
        Some(execution_unit_projection::Unit::CompoundRelease(compound)) => {
            let ids: Vec<_> = compound
                .release_set_ids
                .iter()
                .map(|value| value.value.as_slice())
                .collect();
            if ids.is_empty() {
                return Err(RuntimeProjectionError::InvalidManifest(
                    "compound release unit is empty",
                ));
            }
            validate_unique(&ids, "compound release-set ID")?;
        }
        None => {
            return Err(RuntimeProjectionError::InvalidManifest(
                "execution unit is missing",
            ));
        }
    }
    Ok(())
}

fn validate_preview(
    preview: Option<&crate::diskplan::v1::ActionExecutionPreviewProjection>,
) -> Result<(), RuntimeProjectionError> {
    let preview = preview.ok_or(RuntimeProjectionError::InvalidManifest(
        "missing execution preview",
    ))?;
    if PlanActionKind::try_from(preview.adapter).is_err()
        || preview.adapter == PlanActionKind::Unspecified as i32
        || (preview.mutation_supported
            && (preview.raw_executable.is_empty()
                || preview.raw_executable.contains(&0)
                || preview.raw_argv.iter().any(|value| value.contains(&0))
                || preview.raw_argv.len() != preview.display_argv.len()
                || preview.postcondition.is_empty()))
        || (!preview.mutation_supported
            && (!preview.raw_executable.is_empty() || !preview.raw_argv.is_empty()))
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "execution preview is invalid",
        ));
    }
    Ok(())
}

fn validate_plan_evidence_binding(
    plan_id: Option<&crate::diskplan::v1::OpaqueIdentifier>,
    plan_digest: Option<&crate::diskplan::v1::Digest256>,
    evidence_id: Option<&crate::diskplan::v1::OpaqueIdentifier>,
    evidence_digest: Option<&crate::diskplan::v1::Digest256>,
) -> Result<(), RuntimeProjectionError> {
    if digest_opaque(plan_id, "plan_id")? != digest_value(plan_digest, "plan_sha256")?
        || digest_opaque(evidence_id, "evidence_id")?
            != digest_value(evidence_digest, "evidence_sha256")?
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "plan or evidence ID differs from digest",
        ));
    }
    Ok(())
}

fn validate_scan_binding(
    session_id: Option<&crate::diskplan::v1::OpaqueIdentifier>,
    checkpoint_id: Option<&crate::diskplan::v1::OpaqueIdentifier>,
    checkpoint_evidence_sha256: Option<&crate::diskplan::v1::Digest256>,
    final_evidence_sha256: Option<&crate::diskplan::v1::Digest256>,
) -> Result<(), RuntimeProjectionError> {
    opaque_value(session_id, "scan_session_id")?;
    let checkpoint_id = opaque_value(checkpoint_id, "scan_checkpoint_id")?;
    digest_value(
        checkpoint_evidence_sha256,
        "scan_checkpoint_evidence_sha256",
    )?;
    if checkpoint_id
        != lowercase_hex(digest_value(final_evidence_sha256, "evidence_sha256")?).as_slice()
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "scan checkpoint ID differs from final evidence digest",
        ));
    }
    Ok(())
}

fn lowercase_hex(value: &[u8]) -> Vec<u8> {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut output = Vec::with_capacity(value.len() * 2);
    for byte in value {
        output.push(DIGITS[(byte >> 4) as usize]);
        output.push(DIGITS[(byte & 0x0f) as usize]);
    }
    output
}

fn validate_epoch(
    epoch: Option<&crate::diskplan::v1::ExecutionEpochProjection>,
) -> Result<(), RuntimeProjectionError> {
    let epoch = epoch.ok_or(RuntimeProjectionError::InvalidManifest(
        "missing execution epoch",
    ))?;
    opaque_value(epoch.epoch_id.as_ref(), "epoch_id")?;
    if epoch.semantic_reference_time_seconds > epoch.issued_at_seconds
        || epoch.issued_at_seconds >= epoch.deadline_seconds
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "execution epoch times are invalid",
        ));
    }
    Ok(())
}

fn dry_run_final_digest(
    manifest: &DryRunProjectionManifest,
) -> Result<Vec<u8>, RuntimeProjectionError> {
    let mut canonical = DRY_RUN_FINAL_DOMAIN.to_vec();
    append_u32(manifest.manifest_version, &mut canonical);
    append_length_prefixed(
        opaque_value(manifest.projection_id.as_ref(), "projection_id")?,
        &mut canonical,
    )?;
    append_length_prefixed(
        digest_value(manifest.plan_sha256.as_ref(), "plan_sha256")?,
        &mut canonical,
    )?;
    append_length_prefixed(
        digest_value(manifest.overlay_sha256.as_ref(), "overlay_sha256")?,
        &mut canonical,
    )?;
    let epoch = manifest
        .epoch
        .as_ref()
        .ok_or(RuntimeProjectionError::InvalidManifest(
            "missing execution epoch",
        ))?;
    append_length_prefixed(
        opaque_value(epoch.epoch_id.as_ref(), "epoch_id")?,
        &mut canonical,
    )?;
    append_i64(epoch.semantic_reference_time_seconds, &mut canonical);
    append_i64(epoch.issued_at_seconds, &mut canonical);
    append_i64(epoch.deadline_seconds, &mut canonical);
    canonical.push(u8::from(manifest.current));
    append_u64(manifest.action_count, &mut canonical);
    append_u64(manifest.finding_count, &mut canonical);
    append_u32(manifest.maximum_action_count, &mut canonical);
    append_u32(manifest.maximum_finding_count, &mut canonical);
    append_u32(manifest.maximum_projection_payload_bytes, &mut canonical);
    append_length_prefixed(
        digest_value(manifest.payload_sha256.as_ref(), "payload_sha256")?,
        &mut canonical,
    )?;
    append_length_prefixed(
        opaque_value(manifest.dry_run_id.as_ref(), "dry_run_id")?,
        &mut canonical,
    )?;
    append_u64(manifest.selected_action_count, &mut canonical);
    append_length_prefixed(
        opaque_value(manifest.overlay_id.as_ref(), "overlay_id")?,
        &mut canonical,
    )?;
    append_length_prefixed(
        digest_opaque(manifest.plan_id.as_ref(), "plan_id")?,
        &mut canonical,
    )?;
    append_length_prefixed(
        digest_opaque(manifest.evidence_id.as_ref(), "evidence_id")?,
        &mut canonical,
    )?;
    append_length_prefixed(
        digest_value(manifest.evidence_sha256.as_ref(), "evidence_sha256")?,
        &mut canonical,
    )?;
    append_length_prefixed(
        manifest
            .current_binding_sha256
            .as_ref()
            .map(|value| value.value.as_slice())
            .unwrap_or_default(),
        &mut canonical,
    )?;
    append_length_prefixed(
        digest_value(manifest.revalidation_sha256.as_ref(), "revalidation_sha256")?,
        &mut canonical,
    )?;
    append_u64(manifest.overlay_revision, &mut canonical);
    append_length_prefixed(
        opaque_value(manifest.scan_session_id.as_ref(), "scan_session_id")?,
        &mut canonical,
    )?;
    append_length_prefixed(
        opaque_value(manifest.scan_checkpoint_id.as_ref(), "scan_checkpoint_id")?,
        &mut canonical,
    )?;
    append_length_prefixed(
        digest_value(
            manifest.scan_checkpoint_evidence_sha256.as_ref(),
            "scan_checkpoint_evidence_sha256",
        )?,
        &mut canonical,
    )?;
    Ok(Sha256::digest(canonical).to_vec())
}

fn append_framed(value: &[u8], output: &mut Vec<u8>) -> Result<(), RuntimeProjectionError> {
    append_length_prefixed(value, output)
}

fn append_length_prefixed(
    value: &[u8],
    output: &mut Vec<u8>,
) -> Result<(), RuntimeProjectionError> {
    let length = u32::try_from(value.len()).map_err(|_| {
        RuntimeProjectionError::InvalidManifest("length-prefixed field exceeds u32")
    })?;
    append_u32(length, output);
    output.extend_from_slice(value);
    Ok(())
}

fn append_u32(value: u32, output: &mut Vec<u8>) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn append_u64(value: u64, output: &mut Vec<u8>) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn append_i64(value: i64, output: &mut Vec<u8>) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn opaque_value<'a>(
    value: Option<&'a crate::diskplan::v1::OpaqueIdentifier>,
    field: &'static str,
) -> Result<&'a [u8], RuntimeProjectionError> {
    value
        .map(|value| value.value.as_slice())
        .filter(|value| !value.is_empty() && value.len() <= MAXIMUM_OPAQUE_IDENTIFIER_BYTES)
        .ok_or(RuntimeProjectionError::InvalidManifest(field))
}

fn digest_opaque<'a>(
    value: Option<&'a crate::diskplan::v1::OpaqueIdentifier>,
    field: &'static str,
) -> Result<&'a [u8], RuntimeProjectionError> {
    value
        .map(|value| value.value.as_slice())
        .filter(|value| value.len() == 32)
        .ok_or(RuntimeProjectionError::InvalidManifest(field))
}

fn digest_value<'a>(
    value: Option<&'a crate::diskplan::v1::Digest256>,
    field: &'static str,
) -> Result<&'a [u8], RuntimeProjectionError> {
    value
        .map(|value| value.value.as_slice())
        .filter(|value| value.len() == 32)
        .ok_or(RuntimeProjectionError::InvalidManifest(field))
}

fn validate_unique(values: &[&[u8]], field: &'static str) -> Result<(), RuntimeProjectionError> {
    if values.iter().any(|value| value.is_empty())
        || values.iter().copied().collect::<BTreeSet<_>>().len() != values.len()
    {
        return Err(RuntimeProjectionError::InvalidManifest(field));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::diskplan::v1::{AcknowledgedWaiver, PlanProjectionRecord, PlanWaiverProjection};

    #[test]
    fn overlay_chain_rejects_not_stageable_and_nonexact_waivers() {
        let action_id = vec![0x31; 32];
        let waiver_id = b"required-waiver".to_vec();

        let mut not_stageable = PlanActionProjection {
            action_id: Some(opaque(action_id.clone())),
            stageability: PlanStageability::NotStageable as i32,
            ..Default::default()
        };
        assert!(
            RuntimeChainVerifier::new(plan_with_action(not_stageable.clone()))
                .verify_overlay(&sealed_overlay(&action_id, &[]))
                .is_err()
        );

        not_stageable.stageability = PlanStageability::RequiresWaivers as i32;
        not_stageable.required_waivers = vec![PlanWaiverProjection {
            waiver_id: Some(opaque(waiver_id.clone())),
            ..Default::default()
        }];
        assert!(
            RuntimeChainVerifier::new(plan_with_action(not_stageable.clone()))
                .verify_overlay(&sealed_overlay(&action_id, &[]))
                .is_err()
        );
        assert!(
            RuntimeChainVerifier::new(plan_with_action(not_stageable.clone()))
                .verify_overlay(&sealed_overlay(
                    &action_id,
                    &[waiver_id.clone(), b"extra-waiver".to_vec()]
                ))
                .is_err()
        );
        RuntimeChainVerifier::new(plan_with_action(not_stageable))
            .verify_overlay(&sealed_overlay(&action_id, &[waiver_id]))
            .unwrap();
    }

    #[test]
    fn execution_membership_rejects_foreign_units_and_jit_outcomes() {
        let selected_id = vec![0x11; 32];
        let foreign_id = vec![0x22; 32];
        let selected = BTreeSet::from([selected_id.clone()]);
        let release_sets = BTreeMap::new();
        let foreign_unit = ExecutionUnitProjection {
            unit: Some(execution_unit_projection::Unit::ActionId(opaque(
                foreign_id.clone(),
            ))),
        };
        assert!(
            validate_execution_unit_membership(Some(&foreign_unit), &selected, &release_sets)
                .is_err()
        );

        let rejected = crate::diskplan::v1::UnitJitRejectedProjection {
            unit: Some(ExecutionUnitProjection {
                unit: Some(execution_unit_projection::Unit::ActionId(opaque(
                    selected_id.clone(),
                ))),
            }),
            revalidation: Some(RevalidationProjectionPayload {
                action_outcomes: vec![crate::diskplan::v1::ActionRevalidationProjection {
                    action_id: Some(opaque(foreign_id)),
                    ..Default::default()
                }],
                ..Default::default()
            }),
        };
        assert!(
            validate_jit_revalidation_membership(&rejected, &BTreeSet::from([selected_id]))
                .is_err()
        );
    }

    #[test]
    fn typed_confirm_rejection_consumes_the_exact_review_binding() {
        let review_binding = vec![0x51; 32];
        let apply_review_id = b"apply-review".to_vec();
        let make_chain = || RuntimeChainVerifier {
            plan: plan_with_action(PlanActionProjection::default()),
            overlay: None,
            apply_review: Some(ApplyReviewProjection {
                apply_review_id: Some(opaque(apply_review_id.clone())),
                review_binding_sha256: Some(digest(review_binding.clone())),
                ..Default::default()
            }),
            consumed_review_bindings: BTreeSet::new(),
        };
        let confirm = crate::diskplan::v1::Envelope {
            sequence: 7,
            body: Some(envelope::Body::ConfirmApplyRequest(
                crate::diskplan::v1::ConfirmApplyRequest {
                    request_id: 7,
                    apply_review_id: Some(opaque(apply_review_id.clone())),
                    review_binding_sha256: Some(digest(review_binding.clone())),
                    confirmed_force_action_ids: vec![],
                },
            )),
        };
        let rejected = crate::diskplan::v1::Envelope {
            sequence: 9,
            body: Some(envelope::Body::RuntimeEvent(
                crate::diskplan::v1::RuntimeEvent {
                    event_sequence: 9,
                    request_id: 7,
                    runtime_session_id: Some(opaque(b"runtime-session".to_vec())),
                    body: Some(runtime_event::Body::RuntimeRejected(
                        crate::diskplan::v1::RuntimeRejected {
                            code: RuntimeRejectCode::ConfirmationMismatch as i32,
                            summary: "confirmation rejected".to_owned(),
                        },
                    )),
                },
            )),
        };
        let confirm_receipt = crate::decode_canonical_envelope(&confirm.encode_to_vec()).unwrap();
        for code in [
            RuntimeRejectCode::DuplicateRequestId,
            RuntimeRejectCode::CapabilityNotNegotiated,
            RuntimeRejectCode::BusinessUnsupported,
            RuntimeRejectCode::InvalidState,
        ] {
            let mut preclaim = rejected.clone();
            let Some(envelope::Body::RuntimeEvent(event)) = preclaim.body.as_mut() else {
                unreachable!()
            };
            let Some(runtime_event::Body::RuntimeRejected(rejection)) = event.body.as_mut() else {
                unreachable!()
            };
            rejection.code = code as i32;
            let receipt = crate::decode_canonical_envelope(&preclaim.encode_to_vec()).unwrap();
            let mut chain = make_chain();
            assert!(
                chain
                    .verify_rejected_confirm(&confirm_receipt, &receipt, b"runtime-session")
                    .is_err()
            );
            assert!(chain.apply_review.is_some());
        }
        let rejected_receipt = crate::decode_canonical_envelope(&rejected.encode_to_vec()).unwrap();
        let mut chain = make_chain();
        chain
            .verify_rejected_confirm(&confirm_receipt, &rejected_receipt, b"runtime-session")
            .unwrap();
        assert!(chain.apply_review.is_none());
        assert!(chain.consumed_review_bindings.contains(&review_binding));
    }

    fn plan_with_action(action: PlanActionProjection) -> VerifiedPlanProjection {
        let record = PlanProjectionRecord {
            body: Some(plan_projection_record::Body::Action(action)),
            ..Default::default()
        };
        VerifiedPlanProjection {
            records: vec![record],
            manifest: plan_manifest(),
        }
    }

    fn plan_manifest() -> PlanProjectionManifest {
        let plan = vec![0x41; 32];
        let evidence = vec![0x42; 32];
        PlanProjectionManifest {
            projection_id: Some(opaque(b"projection".to_vec())),
            plan_id: Some(opaque(plan.clone())),
            plan_sha256: Some(digest(plan)),
            evidence_id: Some(opaque(evidence.clone())),
            evidence_sha256: Some(digest(evidence.clone())),
            scan_session_id: Some(opaque(b"scan-session".to_vec())),
            scan_checkpoint_id: Some(opaque(hex::encode(evidence).into_bytes())),
            scan_checkpoint_evidence_sha256: Some(digest(vec![0x44; 32])),
            ..Default::default()
        }
    }

    fn sealed_overlay(action_id: &[u8], waiver_ids: &[Vec<u8>]) -> Vec<u8> {
        let manifest = plan_manifest();
        let mut overlay = DecisionOverlayAcknowledged {
            projection_id: manifest.projection_id,
            revision: 1,
            overlay_sha256: Some(digest(vec![0x43; 32])),
            selected_action_ids: vec![opaque(action_id.to_vec())],
            acknowledged_waivers: waiver_ids
                .iter()
                .map(|waiver_id| AcknowledgedWaiver {
                    action_id: Some(opaque(action_id.to_vec())),
                    waiver_id: Some(opaque(waiver_id.clone())),
                    consent_sha256: Some(digest(vec![0x91; 32])),
                })
                .collect(),
            maximum_selected_actions: MAXIMUM_RUNTIME_ACTION_COUNT,
            maximum_waiver_consents: MAXIMUM_OVERLAY_WAIVER_COUNT,
            maximum_user_notes: MAXIMUM_OVERLAY_NOTE_COUNT,
            selected_action_count: 1,
            overlay_id: Some(opaque(b"overlay".to_vec())),
            plan_id: manifest.plan_id,
            plan_sha256: manifest.plan_sha256,
            evidence_id: manifest.evidence_id,
            evidence_sha256: manifest.evidence_sha256,
            maximum_encoded_bytes: MAXIMUM_RUNTIME_PROJECTION_BYTES,
            maximum_note_bytes: MAXIMUM_OVERLAY_NOTE_BYTES,
            scan_session_id: manifest.scan_session_id,
            scan_checkpoint_id: manifest.scan_checkpoint_id,
            scan_checkpoint_evidence_sha256: manifest.scan_checkpoint_evidence_sha256,
            ..Default::default()
        };
        let unsigned = overlay.encode_to_vec();
        overlay.projection_sha256 = Some(digest(
            Sha256::digest([OVERLAY_PROJECTION_DOMAIN, unsigned.as_slice()].concat()).to_vec(),
        ));
        overlay.encode_to_vec()
    }

    fn opaque(value: Vec<u8>) -> OpaqueIdentifier {
        OpaqueIdentifier { value }
    }

    fn digest(value: Vec<u8>) -> Digest256 {
        Digest256 { value }
    }
}
