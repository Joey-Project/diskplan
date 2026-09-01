use std::collections::{BTreeMap, BTreeSet};
use std::error::Error;
use std::fmt;

use prost::Message;
use sha2::{Digest, Sha256};

use crate::diskplan::v1::{
    AdapterScopeProvenanceKindProjection, CodexCleanupScopeEvidenceProjection,
    CodexHelperCapabilityKindProjection, ContentBaselineKindProjection,
    ContentNotApplicableReasonProjection, EvidenceCoverageCompletenessProjection,
    EvidenceCoverageProjection, EvidenceCoverageReasonProjection, EvidenceObjectIdentityProjection,
    EvidenceObjectKindProjection, EvidenceObservationProjection, EvidenceStatus,
    EvidenceUnknownReasonProjection, GitFeatureStateProjection, GitLinkageKindProjection,
    GitWorktreeEvidenceProjection, GitWorktreeMarkerKindProjection, PathRaceProjection,
    PlanActionKind, PlanActionProjection, PlanActivity, PlanBlockerDisposition, PlanBlockerKind,
    PlanDisposition, PlanProjectionChunk, PlanProjectionManifest, PlanProjectionRecord,
    PlanRecommendation, PlanRecoverability, PlanReleaseSetProjection, PlanSafetyEvidenceProjection,
    PlanStageability, PlanTargetKind, PlanTargetProjection, VersionedArtifactActiveStateProjection,
    VersionedArtifactSurvivorStateProjection, WaiverKind, byte_estimate_projection,
    plan_projection_record,
};

pub const PLAN_PROJECTION_MANIFEST_VERSION: u32 = 1;
pub const MAXIMUM_PLAN_PROJECTION_RECORD_COUNT: usize = 100_000;
pub const MAXIMUM_PLAN_PROJECTION_RECORD_PAYLOAD_BYTES: u64 = 768 * 1024 * 1024;
pub const MAXIMUM_PLAN_PROJECTION_CHUNK_PAYLOAD_BYTES: usize = 4 * 1024 * 1024;
pub const MAXIMUM_PLAN_PROJECTION_MANIFEST_BYTES: usize = 2 * 1024 * 1024;
pub const MAXIMUM_PLAN_PROJECTION_RAW_CHUNK_BYTES: usize =
    MAXIMUM_PLAN_PROJECTION_CHUNK_PAYLOAD_BYTES + 1024;
pub const MAXIMUM_PLAN_PROJECTION_RAW_BYTES: u64 = MAXIMUM_PLAN_PROJECTION_RECORD_PAYLOAD_BYTES
    + MAXIMUM_PLAN_PROJECTION_MANIFEST_BYTES as u64
    + MAXIMUM_PLAN_PROJECTION_RECORD_COUNT as u64 * 1024;
pub const MAXIMUM_OPAQUE_IDENTIFIER_BYTES: usize = 256;
pub const MAXIMUM_NAMESPACE_ANCESTOR_COUNT: u32 = 1_024;
pub const MAXIMUM_GIT_STATUS_RECORD_COUNT: u64 = 50_000;
pub const MAXIMUM_VERSIONED_ARTIFACT_COUNT: u64 = 4_096;
pub const MAXIMUM_RAW_SELECTOR_TARGET_BYTES: usize = 4_096;
pub const PROTOCOL14_MINOR: u32 = 4;
pub const PROTOCOL15_MINOR: u32 = 5;
pub const PROTOCOL16_MINOR: u32 = 6;

const CHUNK_ID_DOMAIN: &[u8] = b"diskplan/plan-projection-chunk-id/v1\0";
const FINAL_DIGEST_DOMAIN: &[u8] = b"diskplan/plan-projection-final/v1\0";

#[derive(Clone, Debug, PartialEq)]
pub struct VerifiedPlanProjection {
    pub(crate) records: Vec<PlanProjectionRecord>,
    pub(crate) manifest: PlanProjectionManifest,
    pub(crate) negotiated_protocol_minor: u32,
}

impl VerifiedPlanProjection {
    pub fn records(&self) -> &[PlanProjectionRecord] {
        &self.records
    }

    pub fn manifest(&self) -> &PlanProjectionManifest {
        &self.manifest
    }

    pub fn negotiated_protocol_minor(&self) -> u32 {
        self.negotiated_protocol_minor
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum RuntimeProjectionError {
    InvalidManifest(&'static str),
    InvalidChunk { index: usize, reason: &'static str },
    InvalidRecord { index: u64, reason: &'static str },
    DuplicateIdentifier(&'static str),
    UnknownReference(&'static str),
    Protobuf(String),
}

impl fmt::Display for RuntimeProjectionError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::InvalidManifest(reason) => write!(formatter, "invalid plan manifest: {reason}"),
            Self::InvalidChunk { index, reason } => {
                write!(formatter, "invalid plan chunk {index}: {reason}")
            }
            Self::InvalidRecord { index, reason } => {
                write!(formatter, "invalid plan record {index}: {reason}")
            }
            Self::DuplicateIdentifier(field) => {
                write!(formatter, "duplicate plan projection {field}")
            }
            Self::UnknownReference(field) => {
                write!(formatter, "unknown plan projection {field}")
            }
            Self::Protobuf(detail) => write!(formatter, "invalid plan protobuf: {detail}"),
        }
    }
}

impl Error for RuntimeProjectionError {}

#[derive(Default)]
struct ProjectionIndexes {
    actions: BTreeMap<Vec<u8>, usize>,
    targets: BTreeMap<Vec<u8>, usize>,
    release_sets: BTreeMap<Vec<u8>, usize>,
    blocker_count: u64,
    waiver_count: u64,
    dispositions: BTreeMap<i32, u64>,
    recommendations: BTreeMap<i32, u64>,
}

/// Strictly verifies the engine-authored, chunked plan projection before a
/// frontend model can expose any stage operation.
///
/// The verifier validates transport structure and cross-record identity only.
/// It never derives policy, stageability, adapter kinds, paths, or argv.
pub(crate) fn verify_plan_projection(
    negotiated_protocol_minor: u32,
    chunks: &[PlanProjectionChunk],
    manifest: &PlanProjectionManifest,
) -> Result<VerifiedPlanProjection, RuntimeProjectionError> {
    validate_runtime_protocol_minor(negotiated_protocol_minor)?;
    validate_manifest_limits(manifest)?;
    if manifest.chunk_count as usize != chunks.len() || manifest.chunks.len() != chunks.len() {
        return Err(RuntimeProjectionError::InvalidManifest(
            "chunk count does not match stream",
        ));
    }

    let projection_id = opaque_value(manifest.projection_id.as_ref(), "projection_id")?;
    let projection_digest = digest_value(manifest.projection_sha256.as_ref(), "projection_sha256")?;
    if projection_id != projection_digest {
        return Err(RuntimeProjectionError::InvalidManifest(
            "projection ID differs from digest",
        ));
    }

    let mut records = Vec::new();
    let mut total_payload_bytes = 0_u64;
    for (index, (chunk, descriptor)) in chunks.iter().zip(&manifest.chunks).enumerate() {
        validate_chunk(index, chunk, descriptor, projection_id)?;
        total_payload_bytes = total_payload_bytes
            .checked_add(chunk.canonical_record_payload.len() as u64)
            .ok_or(RuntimeProjectionError::InvalidManifest(
                "record payload byte count overflow",
            ))?;
        if total_payload_bytes > MAXIMUM_PLAN_PROJECTION_RECORD_PAYLOAD_BYTES {
            return Err(RuntimeProjectionError::InvalidManifest(
                "record payload exceeds maximum",
            ));
        }
        let chunk_records = decode_canonical_records(&chunk.canonical_record_payload, index)?;
        if chunk_records.len() != chunk.record_count as usize {
            return Err(RuntimeProjectionError::InvalidChunk {
                index,
                reason: "record count does not match payload",
            });
        }
        records.extend(chunk_records);
        if records.len() > MAXIMUM_PLAN_PROJECTION_RECORD_COUNT {
            return Err(RuntimeProjectionError::InvalidManifest(
                "record count exceeds maximum",
            ));
        }
    }
    if total_payload_bytes != manifest.record_payload_bytes
        || records.len() as u64 != manifest.record_count
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "aggregate record totals do not match",
        ));
    }

    let indexes = validate_records(&records, negotiated_protocol_minor)?;
    validate_manifest_summary(manifest, &indexes)?;
    if final_digest(manifest)? != projection_digest {
        return Err(RuntimeProjectionError::InvalidManifest(
            "projection digest mismatch",
        ));
    }
    Ok(VerifiedPlanProjection {
        records,
        manifest: manifest.clone(),
        negotiated_protocol_minor,
    })
}

/// Decodes a complete plan projection from its original sealed submessage
/// bytes. Callers cannot bypass canonical protobuf or unknown-field admission
/// by supplying already-decoded structs.
pub fn decode_and_verify_plan_projection(
    negotiated_protocol_minor: u32,
    canonical_chunks: &[Vec<u8>],
    canonical_manifest: &[u8],
) -> Result<VerifiedPlanProjection, RuntimeProjectionError> {
    validate_runtime_protocol_minor(negotiated_protocol_minor)?;
    preflight_plan_projection_raw_lengths(
        &canonical_chunks.iter().map(Vec::len).collect::<Vec<_>>(),
        canonical_manifest.len(),
    )?;
    let chunks = canonical_chunks
        .iter()
        .map(|bytes| {
            let value = PlanProjectionChunk::decode(bytes.as_slice())
                .map_err(|error| RuntimeProjectionError::Protobuf(error.to_string()))?;
            if value.encode_to_vec() != *bytes {
                return Err(RuntimeProjectionError::InvalidManifest(
                    "plan chunk is not canonical protobuf",
                ));
            }
            Ok(value)
        })
        .collect::<Result<Vec<_>, _>>()?;
    let manifest = PlanProjectionManifest::decode(canonical_manifest)
        .map_err(|error| RuntimeProjectionError::Protobuf(error.to_string()))?;
    if manifest.encode_to_vec() != canonical_manifest {
        return Err(RuntimeProjectionError::InvalidManifest(
            "plan manifest is not canonical protobuf",
        ));
    }
    verify_plan_projection(negotiated_protocol_minor, &chunks, &manifest)
}

fn preflight_plan_projection_raw_lengths(
    chunk_lengths: &[usize],
    manifest_length: usize,
) -> Result<(), RuntimeProjectionError> {
    if manifest_length > MAXIMUM_PLAN_PROJECTION_MANIFEST_BYTES
        || chunk_lengths.len() > MAXIMUM_PLAN_PROJECTION_RECORD_COUNT
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "raw plan message count or manifest bytes exceed maximum",
        ));
    }
    let mut admitted_bytes = manifest_length as u64;
    for length in chunk_lengths {
        if *length > MAXIMUM_PLAN_PROJECTION_RAW_CHUNK_BYTES {
            return Err(RuntimeProjectionError::InvalidManifest(
                "raw plan chunk bytes exceed maximum",
            ));
        }
        admitted_bytes = admitted_bytes.checked_add(*length as u64).ok_or(
            RuntimeProjectionError::InvalidManifest("raw plan byte count overflow"),
        )?;
        if admitted_bytes > MAXIMUM_PLAN_PROJECTION_RAW_BYTES {
            return Err(RuntimeProjectionError::InvalidManifest(
                "raw plan bytes exceed maximum",
            ));
        }
    }
    Ok(())
}

fn validate_manifest_limits(
    manifest: &PlanProjectionManifest,
) -> Result<(), RuntimeProjectionError> {
    if manifest.manifest_version != PLAN_PROJECTION_MANIFEST_VERSION {
        return Err(RuntimeProjectionError::InvalidManifest(
            "unsupported manifest version",
        ));
    }
    digest_value(manifest.plan_sha256.as_ref(), "plan_sha256")?;
    digest_value(manifest.evidence_sha256.as_ref(), "evidence_sha256")?;
    opaque_value(manifest.scan_session_id.as_ref(), "scan_session_id")?;
    opaque_value(manifest.scan_checkpoint_id.as_ref(), "scan_checkpoint_id")?;
    digest_value(
        manifest.scan_checkpoint_evidence_sha256.as_ref(),
        "scan_checkpoint_evidence_sha256",
    )?;
    if opaque_digest_value(manifest.plan_id.as_ref(), "plan_id")?
        != digest_value(manifest.plan_sha256.as_ref(), "plan_sha256")?
        || opaque_digest_value(manifest.evidence_id.as_ref(), "evidence_id")?
            != digest_value(manifest.evidence_sha256.as_ref(), "evidence_sha256")?
        || opaque_value(manifest.scan_checkpoint_id.as_ref(), "scan_checkpoint_id")?
            != lowercase_hex(digest_value(
                manifest.evidence_sha256.as_ref(),
                "evidence_sha256",
            )?)
            .as_slice()
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "plan or evidence ID differs from digest",
        ));
    }
    if manifest.policy_version.is_empty() || manifest.schema_version.is_empty() {
        return Err(RuntimeProjectionError::InvalidManifest(
            "policy or schema version is empty",
        ));
    }
    if manifest.maximum_record_count != MAXIMUM_PLAN_PROJECTION_RECORD_COUNT as u64
        || manifest.maximum_record_payload_bytes != MAXIMUM_PLAN_PROJECTION_RECORD_PAYLOAD_BYTES
        || manifest.maximum_chunk_payload_bytes as usize
            != MAXIMUM_PLAN_PROJECTION_CHUNK_PAYLOAD_BYTES
        || manifest.maximum_manifest_encoded_bytes as usize
            != MAXIMUM_PLAN_PROJECTION_MANIFEST_BYTES
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "declared projection budgets are unsupported",
        ));
    }
    if manifest.record_count > manifest.maximum_record_count
        || manifest.record_payload_bytes > manifest.maximum_record_payload_bytes
        || manifest.encode_to_vec().len() > MAXIMUM_PLAN_PROJECTION_MANIFEST_BYTES
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "manifest exceeds declared projection budget",
        ));
    }
    Ok(())
}

fn validate_chunk(
    index: usize,
    chunk: &PlanProjectionChunk,
    descriptor: &crate::diskplan::v1::PlanProjectionChunkDescriptor,
    projection_id: &[u8],
) -> Result<(), RuntimeProjectionError> {
    let expected_index =
        u32::try_from(index).map_err(|_| RuntimeProjectionError::InvalidChunk {
            index,
            reason: "chunk index exceeds protocol range",
        })?;
    if chunk.chunk_index != expected_index || descriptor.chunk_index != expected_index {
        return Err(RuntimeProjectionError::InvalidChunk {
            index,
            reason: "chunk index is not contiguous",
        });
    }
    if chunk.canonical_record_payload.len() > MAXIMUM_PLAN_PROJECTION_CHUNK_PAYLOAD_BYTES {
        return Err(RuntimeProjectionError::InvalidChunk {
            index,
            reason: "chunk payload exceeds maximum",
        });
    }
    if opaque_value(chunk.projection_id.as_ref(), "chunk projection_id")? != projection_id {
        return Err(RuntimeProjectionError::InvalidChunk {
            index,
            reason: "projection ID mismatch",
        });
    }
    let payload_digest = Sha256::digest(&chunk.canonical_record_payload).to_vec();
    if digest_value(chunk.payload_sha256.as_ref(), "chunk payload_sha256")? != payload_digest {
        return Err(RuntimeProjectionError::InvalidChunk {
            index,
            reason: "payload digest mismatch",
        });
    }
    let expected_chunk_id = chunk_id(expected_index, &payload_digest);
    if opaque_value(chunk.chunk_id.as_ref(), "chunk_id")? != expected_chunk_id
        || opaque_value(descriptor.chunk_id.as_ref(), "descriptor chunk_id")? != expected_chunk_id
        || digest_value(
            descriptor.payload_sha256.as_ref(),
            "descriptor payload_sha256",
        )? != payload_digest
        || descriptor.record_count != chunk.record_count
        || descriptor.payload_bytes != chunk.canonical_record_payload.len() as u64
    {
        return Err(RuntimeProjectionError::InvalidChunk {
            index,
            reason: "descriptor does not match chunk",
        });
    }
    Ok(())
}

fn decode_canonical_records(
    payload: &[u8],
    chunk_index: usize,
) -> Result<Vec<PlanProjectionRecord>, RuntimeProjectionError> {
    let mut offset = 0_usize;
    let mut records = Vec::new();
    while offset < payload.len() {
        let length_end = offset
            .checked_add(4)
            .ok_or(RuntimeProjectionError::InvalidChunk {
                index: chunk_index,
                reason: "record offset overflow",
            })?;
        let length: [u8; 4] = payload
            .get(offset..length_end)
            .ok_or(RuntimeProjectionError::InvalidChunk {
                index: chunk_index,
                reason: "truncated record length",
            })?
            .try_into()
            .expect("the checked slice has four bytes");
        let record_length = u32::from_be_bytes(length) as usize;
        if record_length == 0 {
            return Err(RuntimeProjectionError::InvalidChunk {
                index: chunk_index,
                reason: "empty record",
            });
        }
        let record_end =
            length_end
                .checked_add(record_length)
                .ok_or(RuntimeProjectionError::InvalidChunk {
                    index: chunk_index,
                    reason: "record length overflow",
                })?;
        let record_bytes =
            payload
                .get(length_end..record_end)
                .ok_or(RuntimeProjectionError::InvalidChunk {
                    index: chunk_index,
                    reason: "truncated record",
                })?;
        let record = PlanProjectionRecord::decode(record_bytes)
            .map_err(|error| RuntimeProjectionError::Protobuf(error.to_string()))?;
        if record.encode_to_vec() != record_bytes {
            return Err(RuntimeProjectionError::InvalidChunk {
                index: chunk_index,
                reason: "record is not canonical protobuf",
            });
        }
        records.push(record);
        offset = record_end;
    }
    Ok(records)
}

fn validate_records(
    records: &[PlanProjectionRecord],
    negotiated_protocol_minor: u32,
) -> Result<ProjectionIndexes, RuntimeProjectionError> {
    let mut indexes = ProjectionIndexes::default();
    for (index, record) in records.iter().enumerate() {
        if record.record_index != index as u64 {
            return Err(RuntimeProjectionError::InvalidRecord {
                index: record.record_index,
                reason: "record index is not contiguous",
            });
        }
        match record.body.as_ref() {
            Some(plan_projection_record::Body::Action(action)) => {
                validate_action(record.record_index, action, negotiated_protocol_minor)?;
                insert_unique(
                    &mut indexes.actions,
                    opaque_value(action.action_id.as_ref(), "action_id")?,
                    index,
                    "action_id",
                )?;
                indexes.blocker_count = add_count(indexes.blocker_count, action.blockers.len())?;
                indexes.waiver_count =
                    add_count(indexes.waiver_count, action.required_waivers.len())?;
                *indexes.dispositions.entry(action.disposition).or_default() += 1;
                *indexes
                    .recommendations
                    .entry(action.recommendation)
                    .or_default() += 1;
            }
            Some(plan_projection_record::Body::Target(target)) => {
                validate_target(record.record_index, target)?;
                insert_unique(
                    &mut indexes.targets,
                    opaque_value(target.target_id.as_ref(), "target_id")?,
                    index,
                    "target_id",
                )?;
            }
            Some(plan_projection_record::Body::ReleaseSet(release_set)) => {
                validate_release_set(record.record_index, release_set)?;
                insert_unique(
                    &mut indexes.release_sets,
                    opaque_value(release_set.release_set_id.as_ref(), "release_set_id")?,
                    index,
                    "release_set_id",
                )?;
                indexes.blocker_count =
                    add_count(indexes.blocker_count, release_set.blockers.len())?;
            }
            None => {
                return Err(RuntimeProjectionError::InvalidRecord {
                    index: record.record_index,
                    reason: "missing record body",
                });
            }
        }
    }
    validate_references(records, &indexes)?;
    validate_action_dag(records, &indexes)?;
    Ok(indexes)
}

fn validate_action(
    index: u64,
    action: &PlanActionProjection,
    negotiated_protocol_minor: u32,
) -> Result<(), RuntimeProjectionError> {
    let action_id = opaque_digest_value(action.action_id.as_ref(), "action_id")?;
    opaque_digest_value(action.action_lineage_id.as_ref(), "action_lineage_id")?;
    if PlanDisposition::try_from(action.disposition).is_err()
        || action.disposition == PlanDisposition::Unspecified as i32
        || PlanRecommendation::try_from(action.recommendation).is_err()
        || action.recommendation == PlanRecommendation::Unspecified as i32
        || PlanActionKind::try_from(action.kind).is_err()
        || action.kind == PlanActionKind::Unspecified as i32
        || PlanStageability::try_from(action.stageability).is_err()
        || action.stageability == PlanStageability::Unspecified as i32
        || PlanActivity::try_from(action.activity).is_err()
        || action.activity == PlanActivity::Unspecified as i32
        || PlanRecoverability::try_from(action.recoverability).is_err()
        || action.recoverability == PlanRecoverability::Unspecified as i32
        || PathRaceProjection::try_from(action.path_race).is_err()
        || action.path_race == PathRaceProjection::Unspecified as i32
        || action.kind_label.is_empty()
        || action.label.is_empty()
    {
        return Err(RuntimeProjectionError::InvalidRecord {
            index,
            reason: "missing typed action projection",
        });
    }
    if action.requires_force && action.force_reason.is_empty() {
        return Err(RuntimeProjectionError::InvalidRecord {
            index,
            reason: "force requirement has no reason",
        });
    }
    let requires_waivers = action.stageability == PlanStageability::RequiresWaivers as i32;
    if requires_waivers == action.required_waivers.is_empty() {
        return Err(RuntimeProjectionError::InvalidRecord {
            index,
            reason: "stageability and waiver list disagree",
        });
    }
    unique_message_ids(
        action.target_ids.iter().map(|value| value.value.as_slice()),
        "action target_id",
    )?;
    unique_message_ids(
        action
            .release_set_ids
            .iter()
            .map(|value| value.value.as_slice()),
        "action release_set_id",
    )?;
    unique_message_ids(
        action
            .prerequisites
            .iter()
            .filter_map(|value| value.action_id.as_ref())
            .map(|value| value.value.as_slice()),
        "prerequisite action_id",
    )?;
    unique_message_ids(
        action
            .blockers
            .iter()
            .filter_map(|value| value.blocker_id.as_ref())
            .map(|value| value.value.as_slice()),
        "action blocker_id",
    )?;
    unique_message_ids(
        action
            .required_waivers
            .iter()
            .filter_map(|value| value.waiver_id.as_ref())
            .map(|value| value.value.as_slice()),
        "action waiver_id",
    )?;
    for prerequisite in &action.prerequisites {
        let prerequisite_id = opaque_digest_value(prerequisite.action_id.as_ref(), "prerequisite")?;
        if prerequisite_id == action_id {
            return Err(RuntimeProjectionError::InvalidRecord {
                index,
                reason: "self prerequisite",
            });
        }
    }
    validate_byte_estimate(index, action.immediate_reclaim.as_ref())?;
    validate_byte_estimate(index, action.shared_unlock.as_ref())?;
    for evidence in &action.evidence {
        if EvidenceStatus::try_from(evidence.status).is_err()
            || evidence.status == EvidenceStatus::Unspecified as i32
            || evidence.code.is_empty()
            || evidence.summary.is_empty()
        {
            return Err(RuntimeProjectionError::InvalidRecord {
                index,
                reason: "invalid evidence summary",
            });
        }
    }
    for waiver in &action.required_waivers {
        opaque_value(waiver.waiver_id.as_ref(), "waiver_id")?;
        digest_value(
            waiver.semantic_evidence_sha256.as_ref(),
            "semantic_evidence_sha256",
        )?;
        if WaiverKind::try_from(waiver.kind).is_err()
            || waiver.kind == WaiverKind::Unspecified as i32
            || waiver.predicate.is_empty()
        {
            return Err(RuntimeProjectionError::InvalidRecord {
                index,
                reason: "invalid waiver",
            });
        }
    }
    for blocker in &action.blockers {
        validate_blocker(index, blocker)?;
    }
    let preview =
        action
            .execution_preview
            .as_ref()
            .ok_or(RuntimeProjectionError::InvalidRecord {
                index,
                reason: "missing execution preview",
            })?;
    if preview.adapter != action.kind
        || validate_execution_preview(negotiated_protocol_minor, preview).is_err()
        || (negotiated_protocol_minor >= PROTOCOL15_MINOR && preview.path_race != action.path_race)
    {
        return Err(RuntimeProjectionError::InvalidRecord {
            index,
            reason: "invalid execution preview",
        });
    }
    validate_safety_evidence(index, action.kind, action.safety_evidence.as_ref())?;
    Ok(())
}

pub(crate) fn validate_runtime_protocol_minor(
    negotiated_protocol_minor: u32,
) -> Result<(), RuntimeProjectionError> {
    if matches!(
        negotiated_protocol_minor,
        PROTOCOL14_MINOR | PROTOCOL15_MINOR | PROTOCOL16_MINOR
    ) {
        Ok(())
    } else {
        Err(RuntimeProjectionError::InvalidManifest(
            "unsupported negotiated protocol minor",
        ))
    }
}

pub(crate) fn validate_execution_preview(
    negotiated_protocol_minor: u32,
    preview: &crate::diskplan::v1::ActionExecutionPreviewProjection,
) -> Result<(), RuntimeProjectionError> {
    validate_runtime_protocol_minor(negotiated_protocol_minor)?;
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
    match negotiated_protocol_minor {
        PROTOCOL14_MINOR => {
            if preview.raw_working_directory.is_some()
                || preview.path_race != PathRaceProjection::Unspecified as i32
                || preview.mutation_supported
            {
                return Err(RuntimeProjectionError::InvalidManifest(
                    "protocol 1.4 mutation preview is not safely executable",
                ));
            }
        }
        PROTOCOL15_MINOR | PROTOCOL16_MINOR => {
            let working_directory = preview.raw_working_directory.as_deref().ok_or(
                RuntimeProjectionError::InvalidManifest(
                    "protocol 1.5+ preview omits raw working directory",
                ),
            )?;
            if PathRaceProjection::try_from(preview.path_race).is_err()
                || preview.path_race == PathRaceProjection::Unspecified as i32
                || (preview.mutation_supported
                    && (working_directory.first() != Some(&b'/') || working_directory.contains(&0)))
                || (!preview.mutation_supported && !working_directory.is_empty())
            {
                return Err(RuntimeProjectionError::InvalidManifest(
                    "protocol 1.5+ execution preview is incomplete",
                ));
            }
        }
        _ => unreachable!("the protocol minor was validated"),
    }
    Ok(())
}

/// Renders raw working-directory evidence without filesystem or path-library
/// interpretation. The frontend never joins, normalizes, resolves, or opens
/// these bytes.
pub fn escape_raw_working_directory(raw: &[u8]) -> String {
    let mut escaped = String::with_capacity(raw.len());
    for byte in raw {
        match *byte {
            b' '..=b'~' if *byte != b'\\' => escaped.push(char::from(*byte)),
            b'\\' => escaped.push_str("\\\\"),
            value => {
                use std::fmt::Write as _;
                let _ = write!(escaped, "\\x{value:02x}");
            }
        }
    }
    escaped
}

fn validate_safety_evidence(
    index: u64,
    action_kind: i32,
    evidence: Option<&PlanSafetyEvidenceProjection>,
) -> Result<(), RuntimeProjectionError> {
    let evidence = evidence.ok_or(RuntimeProjectionError::InvalidRecord {
        index,
        reason: "missing safety evidence",
    })?;
    digest_value(
        evidence.policy_evidence_sha256.as_ref(),
        "policy_evidence_sha256",
    )?;
    let namespace =
        evidence
            .namespace_access
            .as_ref()
            .ok_or(RuntimeProjectionError::InvalidRecord {
                index,
                reason: "missing namespace safety evidence",
            })?;
    validate_evidence_observation(index, namespace.target_access_policy.as_ref())?;
    validate_evidence_observation(index, namespace.target_acl_digest.as_ref())?;
    validate_evidence_observation(index, namespace.root_access_policy.as_ref())?;
    validate_evidence_observation(index, namespace.root_acl_digest.as_ref())?;
    validate_evidence_observation(index, namespace.ancestor_access_policy_chain.as_ref())?;
    validate_evidence_observation(index, namespace.root_access_policy_seal.as_ref())?;
    validate_evidence_observation(index, namespace.ancestor_access_policy_seal.as_ref())?;
    digest_value(
        namespace.namespace_binding_sha256.as_ref(),
        "namespace_binding_sha256",
    )?;
    if namespace.maximum_ancestor_count != MAXIMUM_NAMESPACE_ANCESTOR_COUNT
        || namespace.ancestor_count > namespace.maximum_ancestor_count
    {
        return Err(invalid_safety_evidence(index));
    }

    let content =
        evidence
            .content_baseline
            .as_ref()
            .ok_or(RuntimeProjectionError::InvalidRecord {
                index,
                reason: "missing content safety evidence",
            })?;
    validate_evidence_observation(index, content.observation.as_ref())?;
    let content_status = EvidenceStatus::try_from(
        content
            .observation
            .as_ref()
            .expect("validated observation")
            .status,
    )
    .map_err(|_| invalid_safety_evidence(index))?;
    let content_kind = ContentBaselineKindProjection::try_from(content.known_kind)
        .map_err(|_| invalid_safety_evidence(index))?;
    if (content_status == EvidenceStatus::Known)
        != (content_kind != ContentBaselineKindProjection::Unspecified)
    {
        return Err(invalid_safety_evidence(index));
    }
    let not_applicable =
        ContentNotApplicableReasonProjection::try_from(content.not_applicable_reason)
            .map_err(|_| invalid_safety_evidence(index))?;
    if content_status == EvidenceStatus::Known {
        match content_kind {
            ContentBaselineKindProjection::RequiredDigest => {
                if not_applicable != ContentNotApplicableReasonProjection::Unspecified {
                    return Err(invalid_safety_evidence(index));
                }
            }
            ContentBaselineKindProjection::ExplicitlyNotApplicable => {
                if content.logical_bytes != 0
                    || not_applicable == ContentNotApplicableReasonProjection::Unspecified
                {
                    return Err(invalid_safety_evidence(index));
                }
            }
            ContentBaselineKindProjection::Unspecified => {
                return Err(invalid_safety_evidence(index));
            }
        }
    } else if content.logical_bytes != 0
        || not_applicable != ContentNotApplicableReasonProjection::Unspecified
    {
        return Err(invalid_safety_evidence(index));
    }

    let action_kind =
        PlanActionKind::try_from(action_kind).map_err(|_| invalid_safety_evidence(index))?;
    match action_kind {
        PlanActionKind::GitWorktreeRemove | PlanActionKind::GitWorktreeDiscardLocalChanges => {
            let git = evidence
                .git_worktree
                .as_ref()
                .ok_or_else(|| invalid_safety_evidence(index))?;
            if evidence.codex_cleanup_scope.is_some() || evidence.versioned_artifact.is_some() {
                return Err(invalid_safety_evidence(index));
            }
            digest_value(git.bundle_sha256.as_ref(), "git bundle_sha256")?;
            for observation in [
                git.no_follow_traversal_complete.as_ref(),
                git.head_identity.as_ref(),
                git.index_digest.as_ref(),
                git.local_changes.as_ref(),
                git.registration.as_ref(),
                git.linkage.as_ref(),
                git.sparse_checkout.as_ref(),
                git.nested_repositories.as_ref(),
                git.submodules.as_ref(),
                git.trusted_exclusive_namespace.as_ref(),
                git.post_quarantine_coverage.as_ref(),
                git.post_discard_successor.as_ref(),
            ] {
                validate_evidence_observation(index, observation)?;
            }
            validate_git_scan_summary(index, git)?;
        }
        PlanActionKind::CodexCleanTemporary => {
            let codex = evidence
                .codex_cleanup_scope
                .as_ref()
                .ok_or_else(|| invalid_safety_evidence(index))?;
            if evidence.git_worktree.is_some() || evidence.versioned_artifact.is_some() {
                return Err(invalid_safety_evidence(index));
            }
            validate_codex_evidence(index, codex)?;
        }
        PlanActionKind::VersionedArtifactRemove => {
            let versioned = evidence
                .versioned_artifact
                .as_ref()
                .ok_or_else(|| invalid_safety_evidence(index))?;
            if evidence.git_worktree.is_some() || evidence.codex_cleanup_scope.is_some() {
                return Err(invalid_safety_evidence(index));
            }
            opaque_value(versioned.artifact_kind_id.as_ref(), "artifact_kind_id")?;
            opaque_value(versioned.version_id.as_ref(), "version_id")?;
            validate_evidence_observation(index, versioned.inventory_coverage.as_ref())?;
            validate_evidence_observation(index, versioned.provenance.as_ref())?;
            validate_evidence_observation(index, versioned.install_root_identity.as_ref())?;
            validate_evidence_observation(index, versioned.active_selector.as_ref())?;
            validate_evidence_observation(index, versioned.survivor_set.as_ref())?;
            validate_evidence_observation(index, versioned.current_update_marker.as_ref())?;
            validate_coverage(index, versioned.coverage.as_ref())?;
            digest_value(versioned.bundle_sha256.as_ref(), "version bundle_sha256")?;
            validate_provenance(
                index,
                versioned.provenance_kind,
                versioned.configured_scope_id.is_some(),
            )?;
            if observation_status(
                index,
                versioned
                    .provenance
                    .as_ref()
                    .expect("validated observation"),
            )? != EvidenceStatus::Known
            {
                return Err(invalid_safety_evidence(index));
            }
            if let Some(scope_id) = versioned.configured_scope_id.as_ref() {
                opaque_value(Some(scope_id), "configured_scope_id")?;
            }
            require_known_payload(
                index,
                versioned.install_root_identity.as_ref(),
                versioned.known_install_root_identity.is_some(),
            )?;
            require_known_payload(
                index,
                versioned.active_selector.as_ref(),
                versioned.known_active_selector_identity.is_some(),
            )?;
            if let Some(identity) = versioned.known_install_root_identity.as_ref() {
                validate_directory_identity(index, identity)?;
            }
            if let Some(identity) = versioned.known_active_selector_identity.as_ref() {
                validate_identity(index, identity)?;
                if !valid_raw_leaf(
                    &versioned.raw_active_selector_target,
                    MAXIMUM_RAW_SELECTOR_TARGET_BYTES,
                ) {
                    return Err(invalid_safety_evidence(index));
                }
            } else if !versioned.raw_active_selector_target.is_empty() {
                return Err(invalid_safety_evidence(index));
            }
            let survivor_set_status = observation_status(
                index,
                versioned
                    .survivor_set
                    .as_ref()
                    .expect("validated observation"),
            )?;
            if survivor_set_status == EvidenceStatus::Known {
                digest_value(
                    versioned.survivor_set_sha256.as_ref(),
                    "survivor_set_sha256",
                )?;
            } else if versioned.survivor_set_sha256.is_some() {
                return Err(invalid_safety_evidence(index));
            }
            let update_status = observation_status(
                index,
                versioned
                    .current_update_marker
                    .as_ref()
                    .expect("validated observation"),
            )?;
            if update_status != EvidenceStatus::Known && versioned.current_update_in_progress {
                return Err(invalid_safety_evidence(index));
            }
            if versioned.maximum_version_count != MAXIMUM_VERSIONED_ARTIFACT_COUNT
                || versioned.observed_version_count > versioned.maximum_version_count
                || versioned.metadata_complete_count > versioned.observed_version_count
                || versioned.active_version_count > versioned.observed_version_count
                || versioned.survivor_count > versioned.observed_version_count
            {
                return Err(invalid_safety_evidence(index));
            }
            let coverage = EvidenceStatus::try_from(
                versioned
                    .inventory_coverage
                    .as_ref()
                    .expect("validated observation")
                    .status,
            )
            .map_err(|_| invalid_safety_evidence(index))?;
            let active = VersionedArtifactActiveStateProjection::try_from(versioned.active_state)
                .map_err(|_| invalid_safety_evidence(index))?;
            let survivor =
                VersionedArtifactSurvivorStateProjection::try_from(versioned.survivor_state)
                    .map_err(|_| invalid_safety_evidence(index))?;
            if coverage == EvidenceStatus::Known {
                if active == VersionedArtifactActiveStateProjection::Unspecified
                    || survivor == VersionedArtifactSurvivorStateProjection::Unspecified
                {
                    return Err(invalid_safety_evidence(index));
                }
            } else if active != VersionedArtifactActiveStateProjection::Unspecified
                || survivor != VersionedArtifactSurvivorStateProjection::Unspecified
                || versioned.observed_version_count != 0
                || versioned.active_version_count != 0
                || versioned.survivor_count != 0
                || versioned.survivor_evidence_id.is_some()
            {
                return Err(invalid_safety_evidence(index));
            }
            if survivor == VersionedArtifactSurvivorStateProjection::OtherSurvivor {
                opaque_digest_value(
                    versioned.survivor_evidence_id.as_ref(),
                    "survivor_evidence_id",
                )?;
            } else if versioned.survivor_evidence_id.is_some() {
                return Err(invalid_safety_evidence(index));
            }
            let provenance =
                AdapterScopeProvenanceKindProjection::try_from(versioned.provenance_kind)
                    .map_err(|_| invalid_safety_evidence(index))?;
            if provenance == AdapterScopeProvenanceKindProjection::TypeHintOnly {
                let display_coverage = EvidenceCoverageCompletenessProjection::try_from(
                    versioned
                        .coverage
                        .as_ref()
                        .expect("validated coverage")
                        .completeness,
                )
                .map_err(|_| invalid_safety_evidence(index))?;
                if display_coverage != EvidenceCoverageCompletenessProjection::Partial
                    || survivor_set_status == EvidenceStatus::Known
                    || !matches!(
                        survivor,
                        VersionedArtifactSurvivorStateProjection::Unspecified
                            | VersionedArtifactSurvivorStateProjection::Unresolved
                    )
                {
                    return Err(invalid_safety_evidence(index));
                }
            }
        }
        PlanActionKind::GenericRemove
        | PlanActionKind::CompleteReleaseSetRemove
        | PlanActionKind::ReportOnly => {
            if evidence.git_worktree.is_some()
                || evidence.codex_cleanup_scope.is_some()
                || evidence.versioned_artifact.is_some()
            {
                return Err(invalid_safety_evidence(index));
            }
        }
        PlanActionKind::Unspecified => return Err(invalid_safety_evidence(index)),
    }
    Ok(())
}

fn validate_evidence_observation(
    index: u64,
    observation: Option<&EvidenceObservationProjection>,
) -> Result<(), RuntimeProjectionError> {
    let observation = observation.ok_or_else(|| invalid_safety_evidence(index))?;
    if observation.code.is_empty() || observation.summary.is_empty() {
        return Err(invalid_safety_evidence(index));
    }
    let status =
        EvidenceStatus::try_from(observation.status).map_err(|_| invalid_safety_evidence(index))?;
    let unknown_reason = EvidenceUnknownReasonProjection::try_from(observation.unknown_reason)
        .map_err(|_| invalid_safety_evidence(index))?;
    match status {
        EvidenceStatus::Known => {
            if unknown_reason != EvidenceUnknownReasonProjection::Unspecified
                || observation.failure.is_some()
            {
                return Err(invalid_safety_evidence(index));
            }
            digest_value(
                observation.value_sha256.as_ref(),
                "observation value_sha256",
            )?;
        }
        EvidenceStatus::Absent => {
            if unknown_reason != EvidenceUnknownReasonProjection::Unspecified
                || observation.failure.is_some()
                || observation.value_sha256.is_some()
            {
                return Err(invalid_safety_evidence(index));
            }
        }
        EvidenceStatus::Unknown => {
            if unknown_reason == EvidenceUnknownReasonProjection::Unspecified
                || observation.failure.is_some()
                || observation.value_sha256.is_some()
            {
                return Err(invalid_safety_evidence(index));
            }
        }
        EvidenceStatus::Unreadable | EvidenceStatus::Failed => {
            let failure = observation
                .failure
                .as_ref()
                .ok_or_else(|| invalid_safety_evidence(index))?;
            if unknown_reason != EvidenceUnknownReasonProjection::Unspecified
                || observation.value_sha256.is_some()
                || failure.code.is_empty()
                || failure.collector.is_empty()
            {
                return Err(invalid_safety_evidence(index));
            }
        }
        EvidenceStatus::Unspecified => return Err(invalid_safety_evidence(index)),
    }
    Ok(())
}

fn validate_git_scan_summary(
    index: u64,
    git: &GitWorktreeEvidenceProjection,
) -> Result<(), RuntimeProjectionError> {
    let scan = git
        .scan_summary
        .as_ref()
        .ok_or_else(|| invalid_safety_evidence(index))?;
    digest_value(scan.bundle_sha256.as_ref(), "git scan bundle_sha256")?;
    validate_evidence_observation(index, scan.marker.as_ref())?;
    let marker = GitWorktreeMarkerKindProjection::try_from(scan.known_marker_kind)
        .map_err(|_| invalid_safety_evidence(index))?;
    require_known_payload(
        index,
        scan.marker.as_ref(),
        marker != GitWorktreeMarkerKindProjection::Unspecified,
    )?;
    require_known_payload(
        index,
        git.registration.as_ref(),
        scan.registration.is_some(),
    )?;
    require_known_payload(index, git.local_changes.as_ref(), scan.changes.is_some())?;
    if let Some(registration) = scan.registration.as_ref() {
        validate_directory_identity(
            index,
            registration
                .worktree_identity
                .as_ref()
                .ok_or_else(|| invalid_safety_evidence(index))?,
        )?;
        validate_directory_identity(
            index,
            registration
                .administrative_directory_identity
                .as_ref()
                .ok_or_else(|| invalid_safety_evidence(index))?,
        )?;
        validate_directory_identity(
            index,
            registration
                .common_directory_identity
                .as_ref()
                .ok_or_else(|| invalid_safety_evidence(index))?,
        )?;
        digest_value(
            registration.registration_sha256.as_ref(),
            "registration_sha256",
        )?;
        digest_value(registration.metadata_sha256.as_ref(), "metadata_sha256")?;
    }
    if let Some(changes) = scan.changes.as_ref() {
        let total = changes
            .staged
            .checked_add(changes.unstaged)
            .and_then(|value| value.checked_add(changes.unmerged))
            .and_then(|value| value.checked_add(changes.untracked))
            .and_then(|value| value.checked_add(changes.ignored))
            .ok_or_else(|| invalid_safety_evidence(index))?;
        if changes.maximum_status_records != MAXIMUM_GIT_STATUS_RECORD_COUNT
            || total > changes.maximum_status_records
        {
            return Err(invalid_safety_evidence(index));
        }
        digest_value(
            changes.streamed_change_set_sha256.as_ref(),
            "streamed_change_set_sha256",
        )?;
    }
    let linkage = GitLinkageKindProjection::try_from(scan.known_linkage_kind)
        .map_err(|_| invalid_safety_evidence(index))?;
    require_known_payload(
        index,
        git.linkage.as_ref(),
        linkage != GitLinkageKindProjection::Unspecified,
    )?;
    if linkage == GitLinkageKindProjection::Linked {
        digest_value(
            scan.linked_registration_id.as_ref(),
            "linked_registration_id",
        )?;
    } else if scan.linked_registration_id.is_some() {
        return Err(invalid_safety_evidence(index));
    }
    let nested = GitFeatureStateProjection::try_from(scan.known_nested_repositories)
        .map_err(|_| invalid_safety_evidence(index))?;
    let submodules = GitFeatureStateProjection::try_from(scan.known_submodules)
        .map_err(|_| invalid_safety_evidence(index))?;
    let sparse = GitFeatureStateProjection::try_from(scan.known_sparse_checkout)
        .map_err(|_| invalid_safety_evidence(index))?;
    require_known_payload(
        index,
        git.nested_repositories.as_ref(),
        nested != GitFeatureStateProjection::Unspecified,
    )?;
    require_known_payload(
        index,
        git.submodules.as_ref(),
        submodules != GitFeatureStateProjection::Unspecified,
    )?;
    require_known_payload(
        index,
        git.sparse_checkout.as_ref(),
        sparse != GitFeatureStateProjection::Unspecified,
    )?;
    validate_coverage(index, scan.command_coverage.as_ref())
}

fn validate_codex_evidence(
    index: u64,
    evidence: &CodexCleanupScopeEvidenceProjection,
) -> Result<(), RuntimeProjectionError> {
    validate_evidence_observation(index, evidence.provenance.as_ref())?;
    validate_evidence_observation(index, evidence.bound_root_identity.as_ref())?;
    validate_evidence_observation(index, evidence.helper_capability.as_ref())?;
    validate_coverage(index, evidence.coverage.as_ref())?;
    digest_value(
        evidence.scope_binding_sha256.as_ref(),
        "scope_binding_sha256",
    )?;
    validate_provenance(
        index,
        evidence.provenance_kind,
        evidence.cleanup_scope_id.is_some(),
    )?;
    if observation_status(
        index,
        evidence.provenance.as_ref().expect("validated observation"),
    )? != EvidenceStatus::Known
    {
        return Err(invalid_safety_evidence(index));
    }
    if let Some(scope_id) = evidence.cleanup_scope_id.as_ref() {
        opaque_value(Some(scope_id), "cleanup_scope_id")?;
    }
    require_known_payload(
        index,
        evidence.bound_root_identity.as_ref(),
        evidence.known_bound_root_identity.is_some(),
    )?;
    if let Some(identity) = evidence.known_bound_root_identity.as_ref() {
        validate_directory_identity(index, identity)?;
    }
    let helper = CodexHelperCapabilityKindProjection::try_from(evidence.known_helper_capability)
        .map_err(|_| invalid_safety_evidence(index))?;
    require_known_payload(
        index,
        evidence.helper_capability.as_ref(),
        helper != CodexHelperCapabilityKindProjection::Unspecified,
    )?;
    let provenance = AdapterScopeProvenanceKindProjection::try_from(evidence.provenance_kind)
        .map_err(|_| invalid_safety_evidence(index))?;
    if provenance == AdapterScopeProvenanceKindProjection::TypeHintOnly {
        let completeness = EvidenceCoverageCompletenessProjection::try_from(
            evidence
                .coverage
                .as_ref()
                .expect("validated coverage")
                .completeness,
        )
        .map_err(|_| invalid_safety_evidence(index))?;
        if completeness != EvidenceCoverageCompletenessProjection::Partial {
            return Err(invalid_safety_evidence(index));
        }
    }
    Ok(())
}

fn validate_coverage(
    index: u64,
    coverage: Option<&EvidenceCoverageProjection>,
) -> Result<(), RuntimeProjectionError> {
    let coverage = coverage.ok_or_else(|| invalid_safety_evidence(index))?;
    digest_value(coverage.binding_sha256.as_ref(), "coverage binding_sha256")?;
    if coverage.reasons.len() > 16 {
        return Err(invalid_safety_evidence(index));
    }
    let mut previous = None;
    for raw_reason in &coverage.reasons {
        let reason = EvidenceCoverageReasonProjection::try_from(*raw_reason)
            .map_err(|_| invalid_safety_evidence(index))?;
        if reason == EvidenceCoverageReasonProjection::Unspecified
            || previous.is_some_and(|value| *raw_reason <= value)
        {
            return Err(invalid_safety_evidence(index));
        }
        previous = Some(*raw_reason);
    }
    let completeness = EvidenceCoverageCompletenessProjection::try_from(coverage.completeness)
        .map_err(|_| invalid_safety_evidence(index))?;
    match completeness {
        EvidenceCoverageCompletenessProjection::Complete if coverage.reasons.is_empty() => Ok(()),
        EvidenceCoverageCompletenessProjection::Partial if !coverage.reasons.is_empty() => Ok(()),
        _ => Err(invalid_safety_evidence(index)),
    }
}

fn validate_identity(
    index: u64,
    identity: &EvidenceObjectIdentityProjection,
) -> Result<(), RuntimeProjectionError> {
    let kind = EvidenceObjectKindProjection::try_from(identity.kind)
        .map_err(|_| invalid_safety_evidence(index))?;
    if kind == EvidenceObjectKindProjection::Unspecified {
        return Err(invalid_safety_evidence(index));
    }
    digest_value(identity.binding_sha256.as_ref(), "identity binding_sha256").map(|_| ())
}

fn validate_directory_identity(
    index: u64,
    identity: &EvidenceObjectIdentityProjection,
) -> Result<(), RuntimeProjectionError> {
    validate_identity(index, identity)?;
    let kind = EvidenceObjectKindProjection::try_from(identity.kind)
        .map_err(|_| invalid_safety_evidence(index))?;
    if kind != EvidenceObjectKindProjection::Directory {
        return Err(invalid_safety_evidence(index));
    }
    Ok(())
}

fn require_known_payload(
    index: u64,
    observation: Option<&EvidenceObservationProjection>,
    has_payload: bool,
) -> Result<(), RuntimeProjectionError> {
    let status = observation_status(
        index,
        observation.ok_or_else(|| invalid_safety_evidence(index))?,
    )?;
    if (status == EvidenceStatus::Known) != has_payload {
        return Err(invalid_safety_evidence(index));
    }
    Ok(())
}

fn observation_status(
    index: u64,
    observation: &EvidenceObservationProjection,
) -> Result<EvidenceStatus, RuntimeProjectionError> {
    EvidenceStatus::try_from(observation.status).map_err(|_| invalid_safety_evidence(index))
}

fn validate_provenance(
    index: u64,
    raw_provenance: i32,
    has_scope_id: bool,
) -> Result<(), RuntimeProjectionError> {
    let provenance = AdapterScopeProvenanceKindProjection::try_from(raw_provenance)
        .map_err(|_| invalid_safety_evidence(index))?;
    match provenance {
        AdapterScopeProvenanceKindProjection::ConfiguredBoundScope if has_scope_id => Ok(()),
        AdapterScopeProvenanceKindProjection::TypeHintOnly if !has_scope_id => Ok(()),
        _ => Err(invalid_safety_evidence(index)),
    }
}

fn valid_raw_leaf(value: &[u8], maximum: usize) -> bool {
    !value.is_empty()
        && value.len() <= maximum
        && !value.contains(&0)
        && !value.contains(&b'/')
        && value != b"."
        && value != b".."
}

fn invalid_safety_evidence(index: u64) -> RuntimeProjectionError {
    RuntimeProjectionError::InvalidRecord {
        index,
        reason: "invalid safety evidence projection",
    }
}

fn validate_target(
    index: u64,
    target: &PlanTargetProjection,
) -> Result<(), RuntimeProjectionError> {
    let target_id = opaque_value(target.target_id.as_ref(), "target_id")?;
    opaque_digest_value(target.action_id.as_ref(), "target action_id")?;
    match target.parent_target_id.as_ref() {
        Some(parent) if parent.value.is_empty() || parent.value == target_id => {
            return Err(RuntimeProjectionError::InvalidRecord {
                index,
                reason: "invalid target parent",
            });
        }
        None if target.depth != 0 => {
            return Err(RuntimeProjectionError::InvalidRecord {
                index,
                reason: "root target has nonzero depth",
            });
        }
        _ => {}
    }
    let path = target
        .path
        .as_ref()
        .ok_or(RuntimeProjectionError::InvalidRecord {
            index,
            reason: "missing target path",
        })?;
    opaque_value(path.root_id.as_ref(), "target root_id")?;
    if PlanTargetKind::try_from(target.kind).is_err()
        || target.kind == PlanTargetKind::Unspecified as i32
        || path.display_path.is_empty()
        || path
            .components
            .iter()
            .any(|value| value.is_empty() || value.contains(&0) || value.contains(&b'/'))
    {
        return Err(RuntimeProjectionError::InvalidRecord {
            index,
            reason: "invalid target projection",
        });
    }
    Ok(())
}

fn validate_release_set(
    index: u64,
    release_set: &PlanReleaseSetProjection,
) -> Result<(), RuntimeProjectionError> {
    opaque_value(release_set.release_set_id.as_ref(), "release_set_id")?;
    if release_set.action_ids.is_empty() {
        return Err(RuntimeProjectionError::InvalidRecord {
            index,
            reason: "empty release set",
        });
    }
    unique_message_ids(
        release_set
            .action_ids
            .iter()
            .map(|value| value.value.as_slice()),
        "release-set action_id",
    )?;
    unique_message_ids(
        release_set
            .blockers
            .iter()
            .filter_map(|value| value.blocker_id.as_ref())
            .map(|value| value.value.as_slice()),
        "release-set blocker_id",
    )?;
    for blocker in &release_set.blockers {
        validate_blocker(index, blocker)?;
    }
    for action_id in &release_set.action_ids {
        opaque_digest_value(Some(action_id), "release-set action_id")?;
    }
    validate_byte_estimate(index, release_set.shared_unlock.as_ref())?;
    Ok(())
}

fn validate_byte_estimate(
    index: u64,
    estimate: Option<&crate::diskplan::v1::ByteEstimateProjection>,
) -> Result<(), RuntimeProjectionError> {
    match estimate.and_then(|value| value.value.as_ref()) {
        Some(byte_estimate_projection::Value::KnownBytes(_)) => Ok(()),
        Some(byte_estimate_projection::Value::Unknown(unknown))
            if !unknown.code.is_empty() && !unknown.summary.is_empty() =>
        {
            Ok(())
        }
        _ => Err(RuntimeProjectionError::InvalidRecord {
            index,
            reason: "invalid byte estimate",
        }),
    }
}

fn validate_blocker(
    index: u64,
    blocker: &crate::diskplan::v1::PlanBlockerProjection,
) -> Result<(), RuntimeProjectionError> {
    opaque_value(blocker.blocker_id.as_ref(), "blocker_id")?;
    if PlanBlockerKind::try_from(blocker.kind).is_err()
        || blocker.kind == PlanBlockerKind::Unspecified as i32
        || PlanBlockerDisposition::try_from(blocker.disposition).is_err()
        || blocker.disposition == PlanBlockerDisposition::Unspecified as i32
        || blocker.code.is_empty()
        || blocker.summary.is_empty()
    {
        return Err(RuntimeProjectionError::InvalidRecord {
            index,
            reason: "invalid blocker",
        });
    }
    Ok(())
}

fn validate_references(
    records: &[PlanProjectionRecord],
    indexes: &ProjectionIndexes,
) -> Result<(), RuntimeProjectionError> {
    for (action_id, index) in &indexes.actions {
        let action = action_record(records, *index);
        if action.prerequisites.iter().any(|value| {
            value
                .action_id
                .as_ref()
                .is_none_or(|id| !indexes.actions.contains_key(&id.value))
        }) {
            return Err(RuntimeProjectionError::UnknownReference(
                "prerequisite action_id",
            ));
        }
        let projected_targets: BTreeSet<_> = action
            .target_ids
            .iter()
            .map(|value| value.value.as_slice())
            .collect();
        let actual_targets: BTreeSet<_> = indexes
            .targets
            .iter()
            .filter_map(|(target_id, target_index)| {
                (target_record(records, *target_index)
                    .action_id
                    .as_ref()
                    .is_some_and(|value| value.value == *action_id))
                .then_some(target_id.as_slice())
            })
            .collect();
        if projected_targets != actual_targets {
            return Err(RuntimeProjectionError::UnknownReference(
                "action target membership",
            ));
        }
        let projected_release_sets: BTreeSet<_> = action
            .release_set_ids
            .iter()
            .map(|value| value.value.as_slice())
            .collect();
        let actual_release_sets: BTreeSet<_> = indexes
            .release_sets
            .iter()
            .filter_map(|(release_set_id, release_set_index)| {
                release_set_record(records, *release_set_index)
                    .action_ids
                    .iter()
                    .any(|value| value.value == *action_id)
                    .then_some(release_set_id.as_slice())
            })
            .collect();
        if projected_release_sets != actual_release_sets {
            return Err(RuntimeProjectionError::UnknownReference(
                "action release-set membership",
            ));
        }
    }
    for target_index in indexes.targets.values() {
        let target = target_record(records, *target_index);
        let action_id = opaque_digest_value(target.action_id.as_ref(), "target action_id")?;
        if !indexes.actions.contains_key(action_id) {
            return Err(RuntimeProjectionError::UnknownReference("target action_id"));
        }
        if let Some(parent_id) = target.parent_target_id.as_ref() {
            let parent_index = indexes
                .targets
                .get(&parent_id.value)
                .ok_or(RuntimeProjectionError::UnknownReference("parent target_id"))?;
            let parent = target_record(records, *parent_index);
            if parent.action_id.as_ref().map(|value| &value.value)
                != target.action_id.as_ref().map(|value| &value.value)
                || parent.depth.checked_add(1) != Some(target.depth)
            {
                return Err(RuntimeProjectionError::UnknownReference(
                    "target parent binding",
                ));
            }
        }
    }
    for release_set_index in indexes.release_sets.values() {
        let release_set = release_set_record(records, *release_set_index);
        if release_set
            .action_ids
            .iter()
            .any(|value| !indexes.actions.contains_key(&value.value))
        {
            return Err(RuntimeProjectionError::UnknownReference(
                "release-set action_id",
            ));
        }
    }
    Ok(())
}

fn validate_action_dag(
    records: &[PlanProjectionRecord],
    indexes: &ProjectionIndexes,
) -> Result<(), RuntimeProjectionError> {
    let mut indegree: BTreeMap<&[u8], usize> = indexes
        .actions
        .keys()
        .map(|action_id| (action_id.as_slice(), 0))
        .collect();
    let mut dependents: BTreeMap<&[u8], Vec<&[u8]>> = BTreeMap::new();
    for (action_id, index) in &indexes.actions {
        let action = action_record(records, *index);
        for prerequisite in &action.prerequisites {
            let prerequisite_id = prerequisite
                .action_id
                .as_ref()
                .expect("reference validation already required an ID")
                .value
                .as_slice();
            *indegree
                .get_mut(action_id.as_slice())
                .expect("every action has an indegree") += 1;
            dependents
                .entry(prerequisite_id)
                .or_default()
                .push(action_id.as_slice());
        }
    }
    let mut ready: Vec<_> = indegree
        .iter()
        .filter_map(|(action_id, degree)| (*degree == 0).then_some(*action_id))
        .collect();
    let mut visited = 0_usize;
    while let Some(action_id) = ready.pop() {
        visited += 1;
        for dependent in dependents.get(action_id).into_iter().flatten() {
            let degree = indegree
                .get_mut(dependent)
                .expect("every dependent has an indegree");
            *degree -= 1;
            if *degree == 0 {
                ready.push(dependent);
            }
        }
    }
    if visited != indexes.actions.len() {
        return Err(RuntimeProjectionError::InvalidManifest(
            "action prerequisites contain a cycle",
        ));
    }
    Ok(())
}

fn validate_manifest_summary(
    manifest: &PlanProjectionManifest,
    indexes: &ProjectionIndexes,
) -> Result<(), RuntimeProjectionError> {
    if manifest.action_count != indexes.actions.len() as u64
        || manifest.target_count != indexes.targets.len() as u64
        || manifest.release_set_count != indexes.release_sets.len() as u64
        || manifest.blocker_count != indexes.blocker_count
        || manifest.waiver_count != indexes.waiver_count
        || manifest.cleanup_candidate_count > manifest.action_count
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "semantic counts do not match records",
        ));
    }
    let disposition_values = [
        PlanDisposition::Ready,
        PlanDisposition::Conditional,
        PlanDisposition::NeedsReview,
        PlanDisposition::Blocked,
        PlanDisposition::KeepInformational,
    ];
    let recommendation_values = [
        PlanRecommendation::SafeToClean,
        PlanRecommendation::SafeAfterExit,
        PlanRecommendation::LikelyRebuildable,
        PlanRecommendation::NeedsSemanticReview,
        PlanRecommendation::ManagedByProvider,
        PlanRecommendation::Keep,
        PlanRecommendation::ScanIncomplete,
        PlanRecommendation::ClassificationConflict,
    ];
    if manifest.disposition_counts.len() != disposition_values.len()
        || manifest
            .disposition_counts
            .iter()
            .zip(disposition_values)
            .any(|(row, value)| {
                row.disposition != value as i32
                    || row.action_count
                        != indexes
                            .dispositions
                            .get(&(value as i32))
                            .copied()
                            .unwrap_or(0)
            })
        || manifest.recommendation_counts.len() != recommendation_values.len()
        || manifest
            .recommendation_counts
            .iter()
            .zip(recommendation_values)
            .any(|(row, value)| {
                row.recommendation != value as i32
                    || row.action_count
                        != indexes
                            .recommendations
                            .get(&(value as i32))
                            .copied()
                            .unwrap_or(0)
            })
    {
        return Err(RuntimeProjectionError::InvalidManifest(
            "disposition or recommendation counts are invalid",
        ));
    }
    Ok(())
}

fn final_digest(manifest: &PlanProjectionManifest) -> Result<Vec<u8>, RuntimeProjectionError> {
    let mut canonical = FINAL_DIGEST_DOMAIN.to_vec();
    append_u32(manifest.manifest_version, &mut canonical);
    append_length_prefixed(
        digest_value(manifest.plan_sha256.as_ref(), "plan_sha256")?,
        &mut canonical,
    );
    append_length_prefixed(
        digest_value(manifest.evidence_sha256.as_ref(), "evidence_sha256")?,
        &mut canonical,
    );
    append_length_prefixed(manifest.policy_version.as_bytes(), &mut canonical);
    append_length_prefixed(manifest.schema_version.as_bytes(), &mut canonical);
    append_u32(manifest.chunk_count, &mut canonical);
    append_u64(manifest.record_count, &mut canonical);
    append_u64(manifest.action_count, &mut canonical);
    append_u64(manifest.target_count, &mut canonical);
    append_u64(manifest.release_set_count, &mut canonical);
    append_u64(manifest.blocker_count, &mut canonical);
    append_u64(manifest.waiver_count, &mut canonical);
    append_u64(manifest.record_payload_bytes, &mut canonical);
    append_u64(manifest.maximum_record_count, &mut canonical);
    append_u64(manifest.maximum_record_payload_bytes, &mut canonical);
    append_u32(manifest.maximum_chunk_payload_bytes, &mut canonical);
    append_u32(manifest.maximum_manifest_encoded_bytes, &mut canonical);
    for descriptor in &manifest.chunks {
        append_u32(descriptor.chunk_index, &mut canonical);
        append_length_prefixed(
            opaque_value(descriptor.chunk_id.as_ref(), "descriptor chunk_id")?,
            &mut canonical,
        );
        append_u32(descriptor.record_count, &mut canonical);
        append_u64(descriptor.payload_bytes, &mut canonical);
        append_length_prefixed(
            digest_value(
                descriptor.payload_sha256.as_ref(),
                "descriptor payload_sha256",
            )?,
            &mut canonical,
        );
    }
    append_u32(manifest.disposition_counts.len() as u32, &mut canonical);
    for row in &manifest.disposition_counts {
        append_u32(row.disposition as u32, &mut canonical);
        append_u64(row.action_count, &mut canonical);
    }
    append_u32(manifest.recommendation_counts.len() as u32, &mut canonical);
    for row in &manifest.recommendation_counts {
        append_u32(row.recommendation as u32, &mut canonical);
        append_u64(row.action_count, &mut canonical);
    }
    append_u64(manifest.cleanup_candidate_count, &mut canonical);
    append_length_prefixed(
        opaque_value(manifest.scan_session_id.as_ref(), "scan_session_id")?,
        &mut canonical,
    );
    append_length_prefixed(
        opaque_value(manifest.scan_checkpoint_id.as_ref(), "scan_checkpoint_id")?,
        &mut canonical,
    );
    append_length_prefixed(
        opaque_digest_value(manifest.plan_id.as_ref(), "plan_id")?,
        &mut canonical,
    );
    append_length_prefixed(
        opaque_digest_value(manifest.evidence_id.as_ref(), "evidence_id")?,
        &mut canonical,
    );
    append_length_prefixed(
        digest_value(
            manifest.scan_checkpoint_evidence_sha256.as_ref(),
            "scan_checkpoint_evidence_sha256",
        )?,
        &mut canonical,
    );
    Ok(Sha256::digest(canonical).to_vec())
}

fn chunk_id(index: u32, payload_digest: &[u8]) -> Vec<u8> {
    let mut canonical = CHUNK_ID_DOMAIN.to_vec();
    append_u32(index, &mut canonical);
    append_length_prefixed(payload_digest, &mut canonical);
    Sha256::digest(canonical).to_vec()
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

fn digest_value<'a>(
    value: Option<&'a crate::diskplan::v1::Digest256>,
    field: &'static str,
) -> Result<&'a [u8], RuntimeProjectionError> {
    value
        .map(|value| value.value.as_slice())
        .filter(|value| value.len() == 32)
        .ok_or(RuntimeProjectionError::InvalidManifest(field))
}

fn opaque_digest_value<'a>(
    value: Option<&'a crate::diskplan::v1::OpaqueIdentifier>,
    field: &'static str,
) -> Result<&'a [u8], RuntimeProjectionError> {
    value
        .map(|value| value.value.as_slice())
        .filter(|value| value.len() == 32)
        .ok_or(RuntimeProjectionError::InvalidManifest(field))
}

fn unique_message_ids<'a>(
    values: impl Iterator<Item = &'a [u8]>,
    field: &'static str,
) -> Result<(), RuntimeProjectionError> {
    let values: Vec<_> = values.collect();
    if values.iter().any(|value| value.is_empty()) {
        return Err(RuntimeProjectionError::UnknownReference(field));
    }
    if values.iter().copied().collect::<BTreeSet<_>>().len() != values.len() {
        return Err(RuntimeProjectionError::DuplicateIdentifier(field));
    }
    Ok(())
}

fn insert_unique(
    values: &mut BTreeMap<Vec<u8>, usize>,
    key: &[u8],
    index: usize,
    field: &'static str,
) -> Result<(), RuntimeProjectionError> {
    if values.insert(key.to_vec(), index).is_some() {
        return Err(RuntimeProjectionError::DuplicateIdentifier(field));
    }
    Ok(())
}

fn add_count(value: u64, increment: usize) -> Result<u64, RuntimeProjectionError> {
    value
        .checked_add(increment as u64)
        .ok_or(RuntimeProjectionError::InvalidManifest("count overflow"))
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

fn action_record(records: &[PlanProjectionRecord], index: usize) -> &PlanActionProjection {
    let Some(plan_projection_record::Body::Action(action)) = records[index].body.as_ref() else {
        unreachable!("the action index was built from an action record")
    };
    action
}

fn target_record(records: &[PlanProjectionRecord], index: usize) -> &PlanTargetProjection {
    let Some(plan_projection_record::Body::Target(target)) = records[index].body.as_ref() else {
        unreachable!("the target index was built from a target record")
    };
    target
}

fn release_set_record(records: &[PlanProjectionRecord], index: usize) -> &PlanReleaseSetProjection {
    let Some(plan_projection_record::Body::ReleaseSet(release_set)) = records[index].body.as_ref()
    else {
        unreachable!("the release-set index was built from a release-set record")
    };
    release_set
}

fn append_length_prefixed(value: &[u8], output: &mut Vec<u8>) {
    let length = u32::try_from(value.len()).expect("bounded protocol fields fit u32");
    append_u32(length, output);
    output.extend_from_slice(value);
}

fn append_u32(value: u32, output: &mut Vec<u8>) {
    output.extend_from_slice(&value.to_be_bytes());
}

fn append_u64(value: u64, output: &mut Vec<u8>) {
    output.extend_from_slice(&value.to_be_bytes());
}

#[cfg(test)]
mod raw_budget_tests {
    use super::*;

    #[test]
    fn raw_plan_budget_accepts_exact_boundary_and_rejects_one_byte_over() {
        let mut remaining =
            MAXIMUM_PLAN_PROJECTION_RAW_BYTES - MAXIMUM_PLAN_PROJECTION_MANIFEST_BYTES as u64;
        let mut lengths = Vec::new();
        while remaining != 0 {
            let next = remaining.min(MAXIMUM_PLAN_PROJECTION_RAW_CHUNK_BYTES as u64) as usize;
            lengths.push(next);
            remaining -= next as u64;
        }
        preflight_plan_projection_raw_lengths(&lengths, MAXIMUM_PLAN_PROJECTION_MANIFEST_BYTES)
            .unwrap();

        let can_extend_last = lengths
            .last()
            .is_some_and(|last| *last < MAXIMUM_PLAN_PROJECTION_RAW_CHUNK_BYTES);
        if can_extend_last {
            *lengths.last_mut().expect("lengths are nonempty") += 1;
        } else {
            lengths.push(1);
        }
        assert!(
            preflight_plan_projection_raw_lengths(&lengths, MAXIMUM_PLAN_PROJECTION_MANIFEST_BYTES)
                .is_err()
        );
    }
}
