use diskplan_proto::diskplan::v1::{
    AcknowledgedEffectConsent, Digest256, EffectConsentBindingV2, OpaqueIdentifier,
    PlanActionProjection, PlanProjectionManifest,
};
use sha2::{Digest, Sha256};
use thiserror::Error;

pub const EFFECT_REQUIREMENT_DOMAIN_V2: &[u8] = b"diskplan/effect-requirement/v2\0";
pub const EFFECT_CONSENT_DOMAIN_V2: &[u8] = b"diskplan/effect-consent/v2\0";
pub const MAXIMUM_EFFECT_RECORD_BYTES: usize = 4096;
pub const MAXIMUM_EFFECT_TEXT_BYTES: usize = 256;
pub const MAXIMUM_EFFECT_IDENTIFIER_BYTES: usize = 256;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ActionEffectPermission {
    LocalRemoveOnly = 1,
    MayDeleteAcrossDevices = 2,
}

impl TryFrom<u8> for ActionEffectPermission {
    type Error = EffectCanonicalError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::LocalRemoveOnly),
            2 => Ok(Self::MayDeleteAcrossDevices),
            _ => Err(EffectCanonicalError::UnknownPermission(i32::from(value))),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum ActionEffectOperation {
    OrdinaryRemove = 1,
    ProviderEvictLocalCopy = 2,
}

impl TryFrom<u8> for ActionEffectOperation {
    type Error = EffectCanonicalError;

    fn try_from(value: u8) -> Result<Self, Self::Error> {
        match value {
            1 => Ok(Self::OrdinaryRemove),
            2 => Ok(Self::ProviderEvictLocalCopy),
            _ => Err(EffectCanonicalError::UnknownOperation(i32::from(value))),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ActionEffectRequirementV2 {
    pub version: u64,
    pub operation: ActionEffectOperation,
    pub permission: ActionEffectPermission,
    pub variant_group_id: [u8; 32],
    pub target_scope_sha256: [u8; 32],
    pub operation_contract_sha256: [u8; 32],
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct EffectConsentV2 {
    pub version: u64,
    pub permission: ActionEffectPermission,
    pub requirement_sha256: [u8; 32],
    pub action_id: Vec<u8>,
    pub action_lineage_id: Vec<u8>,
    pub target_scope_sha256: [u8; 32],
    pub plan_sha256: [u8; 32],
    pub evidence_sha256: [u8; 32],
    pub policy_version: String,
    pub schema_version: String,
    pub consent_event_id: Vec<u8>,
}

#[derive(Debug, Error, Eq, PartialEq)]
pub enum EffectCanonicalError {
    #[error("effect record exceeds the 4096-byte limit")]
    RecordTooLong,
    #[error("unsupported effect record version {0}")]
    UnsupportedVersion(u64),
    #[error("unknown effect permission {0}")]
    UnknownPermission(i32),
    #[error("unknown effect operation {0}")]
    UnknownOperation(i32),
    #[error("missing or invalid field {0}")]
    InvalidField(&'static str),
    #[error("effect operation and permission conflict")]
    ConflictingOperationPermission,
    #[error("effect record ended while reading {0}")]
    Truncated(&'static str),
    #[error("invalid UTF-8 in {0}")]
    InvalidUtf8(&'static str),
    #[error("trailing bytes after effect record")]
    TrailingBytes,
    #[error("effect record is not its canonical encoding")]
    NonCanonicalEncoding,
    #[error("effect reference differs from {0}")]
    ReferenceMismatch(&'static str),
}

pub fn encode_requirement_v2(
    requirement: &ActionEffectRequirementV2,
) -> Result<Vec<u8>, EffectCanonicalError> {
    validate_requirement(requirement)?;
    let mut output = Vec::with_capacity(114);
    output.extend_from_slice(&requirement.version.to_be_bytes());
    output.push(requirement.operation as u8);
    output.push(requirement.permission as u8);
    put_blob(&mut output, &requirement.variant_group_id);
    put_blob(&mut output, &requirement.target_scope_sha256);
    put_blob(&mut output, &requirement.operation_contract_sha256);
    enforce_record_limit(&output)?;
    Ok(output)
}

pub fn verify_requirement_v2(
    canonical_bytes: &[u8],
) -> Result<ActionEffectRequirementV2, EffectCanonicalError> {
    enforce_input_limit(canonical_bytes)?;
    let mut decoder = Decoder::new(canonical_bytes);
    let version = decoder.u64("version")?;
    let operation = ActionEffectOperation::try_from(decoder.u8("operation")?)?;
    let permission = ActionEffectPermission::try_from(decoder.u8("permission")?)?;
    let variant_group_id = decoder.array32("variant_group_id")?;
    let target_scope_sha256 = decoder.array32("target_scope_sha256")?;
    let operation_contract_sha256 = decoder.array32("operation_contract_sha256")?;
    decoder.finish()?;
    let requirement = ActionEffectRequirementV2 {
        version,
        operation,
        permission,
        variant_group_id,
        target_scope_sha256,
        operation_contract_sha256,
    };
    if encode_requirement_v2(&requirement)? != canonical_bytes {
        return Err(EffectCanonicalError::NonCanonicalEncoding);
    }
    Ok(requirement)
}

pub fn requirement_digest_v2(
    requirement: &ActionEffectRequirementV2,
) -> Result<[u8; 32], EffectCanonicalError> {
    let canonical = encode_requirement_v2(requirement)?;
    Ok(domain_digest(EFFECT_REQUIREMENT_DOMAIN_V2, &canonical))
}

pub fn encode_consent_v2(consent: &EffectConsentV2) -> Result<Vec<u8>, EffectCanonicalError> {
    validate_consent(consent)?;
    let mut output = Vec::with_capacity(512);
    output.extend_from_slice(&consent.version.to_be_bytes());
    output.push(consent.permission as u8);
    put_blob(&mut output, &consent.requirement_sha256);
    put_blob(&mut output, &consent.action_id);
    put_blob(&mut output, &consent.action_lineage_id);
    put_blob(&mut output, &consent.target_scope_sha256);
    put_blob(&mut output, &consent.plan_sha256);
    put_blob(&mut output, &consent.evidence_sha256);
    put_blob(&mut output, consent.policy_version.as_bytes());
    put_blob(&mut output, consent.schema_version.as_bytes());
    put_blob(&mut output, &consent.consent_event_id);
    enforce_record_limit(&output)?;
    Ok(output)
}

pub fn verify_consent_v2(canonical_bytes: &[u8]) -> Result<EffectConsentV2, EffectCanonicalError> {
    enforce_input_limit(canonical_bytes)?;
    let mut decoder = Decoder::new(canonical_bytes);
    let version = decoder.u64("version")?;
    let permission = ActionEffectPermission::try_from(decoder.u8("permission")?)?;
    let requirement_sha256 = decoder.array32("requirement_sha256")?;
    let action_id = decoder.identifier("action_id")?;
    let action_lineage_id = decoder.identifier("action_lineage_id")?;
    let target_scope_sha256 = decoder.array32("target_scope_sha256")?;
    let plan_sha256 = decoder.array32("plan_sha256")?;
    let evidence_sha256 = decoder.array32("evidence_sha256")?;
    let policy_version = decoder.text("policy_version")?;
    let schema_version = decoder.text("schema_version")?;
    let consent_event_id = decoder.event_id("consent_event_id")?;
    decoder.finish()?;
    let consent = EffectConsentV2 {
        version,
        permission,
        requirement_sha256,
        action_id,
        action_lineage_id,
        target_scope_sha256,
        plan_sha256,
        evidence_sha256,
        policy_version,
        schema_version,
        consent_event_id,
    };
    if encode_consent_v2(&consent)? != canonical_bytes {
        return Err(EffectCanonicalError::NonCanonicalEncoding);
    }
    Ok(consent)
}

pub fn consent_digest_v2(consent: &EffectConsentV2) -> Result<[u8; 32], EffectCanonicalError> {
    let canonical = encode_consent_v2(consent)?;
    Ok(domain_digest(EFFECT_CONSENT_DOMAIN_V2, &canonical))
}

/// Re-encodes both v2 bindings and verifies all action and manifest references.
/// Callers must first admit the enclosing protobuf records canonically.
pub fn verify_acknowledged_effect_consent_v2(
    action: &PlanActionProjection,
    manifest: &PlanProjectionManifest,
    acknowledged: &AcknowledgedEffectConsent,
) -> Result<([u8; 32], EffectConsentV2), EffectCanonicalError> {
    if manifest.action_effect_binding_schema_version != 2 {
        return Err(EffectCanonicalError::ReferenceMismatch(
            "action_effect_binding_schema_version",
        ));
    }
    let requirement_wire =
        action
            .action_effect_requirement
            .as_ref()
            .ok_or(EffectCanonicalError::InvalidField(
                "action_effect_requirement",
            ))?;
    let requirement = requirement_from_wire(requirement_wire)?;
    let requirement_digest = requirement_digest_v2(&requirement)?;
    if digest_bytes(
        action.action_effect_requirement_sha256.as_ref(),
        "action_effect_requirement_sha256",
    )? != requirement_digest
    {
        return Err(EffectCanonicalError::ReferenceMismatch(
            "action_effect_requirement_sha256",
        ));
    }
    let action_group = identifier_bytes(
        action.action_effect_variant_group_id.as_ref(),
        "action_effect_variant_group_id",
    )?;
    if action_group != requirement.variant_group_id {
        return Err(EffectCanonicalError::ReferenceMismatch(
            "action_effect_variant_group_id",
        ));
    }

    let consent_wire = acknowledged
        .binding
        .as_ref()
        .ok_or(EffectCanonicalError::InvalidField("binding"))?;
    let consent = consent_from_wire(consent_wire)?;
    let consent_digest = consent_digest_v2(&consent)?;
    if digest_bytes(acknowledged.consent_sha256.as_ref(), "consent_sha256")? != consent_digest {
        return Err(EffectCanonicalError::ReferenceMismatch("consent_sha256"));
    }
    verify_consent_references(
        &consent,
        &requirement,
        &requirement_digest,
        action,
        manifest,
    )?;
    Ok((consent_digest, consent))
}

fn verify_consent_references(
    consent: &EffectConsentV2,
    requirement: &ActionEffectRequirementV2,
    requirement_digest: &[u8; 32],
    action: &PlanActionProjection,
    manifest: &PlanProjectionManifest,
) -> Result<(), EffectCanonicalError> {
    if consent.permission != requirement.permission {
        return Err(EffectCanonicalError::ReferenceMismatch("permission"));
    }
    if consent.requirement_sha256 != *requirement_digest {
        return Err(EffectCanonicalError::ReferenceMismatch(
            "requirement_sha256",
        ));
    }
    if consent.action_id != identifier_bytes(action.action_id.as_ref(), "action_id")? {
        return Err(EffectCanonicalError::ReferenceMismatch("action_id"));
    }
    if consent.action_lineage_id
        != identifier_bytes(action.action_lineage_id.as_ref(), "action_lineage_id")?
    {
        return Err(EffectCanonicalError::ReferenceMismatch("action_lineage_id"));
    }
    if consent.target_scope_sha256 != requirement.target_scope_sha256 {
        return Err(EffectCanonicalError::ReferenceMismatch(
            "target_scope_sha256",
        ));
    }
    if consent.plan_sha256 != digest_bytes(manifest.plan_sha256.as_ref(), "plan_sha256")? {
        return Err(EffectCanonicalError::ReferenceMismatch("plan_sha256"));
    }
    if consent.evidence_sha256
        != digest_bytes(manifest.evidence_sha256.as_ref(), "evidence_sha256")?
    {
        return Err(EffectCanonicalError::ReferenceMismatch("evidence_sha256"));
    }
    if consent.policy_version != manifest.policy_version {
        return Err(EffectCanonicalError::ReferenceMismatch("policy_version"));
    }
    if consent.schema_version != manifest.schema_version {
        return Err(EffectCanonicalError::ReferenceMismatch("schema_version"));
    }
    Ok(())
}

fn requirement_from_wire(
    value: &diskplan_proto::diskplan::v1::ActionEffectRequirementBindingV2,
) -> Result<ActionEffectRequirementV2, EffectCanonicalError> {
    if value.version != 2 {
        return Err(EffectCanonicalError::UnsupportedVersion(
            value.version.into(),
        ));
    }
    let operation = match value.operation {
        Some(1) => ActionEffectOperation::OrdinaryRemove,
        Some(2) => ActionEffectOperation::ProviderEvictLocalCopy,
        Some(value) => return Err(EffectCanonicalError::UnknownOperation(value)),
        None => return Err(EffectCanonicalError::InvalidField("operation")),
    };
    let permission = match value.permission {
        Some(1) => ActionEffectPermission::LocalRemoveOnly,
        Some(2) => ActionEffectPermission::MayDeleteAcrossDevices,
        Some(value) => return Err(EffectCanonicalError::UnknownPermission(value)),
        None => return Err(EffectCanonicalError::InvalidField("permission")),
    };
    let requirement = ActionEffectRequirementV2 {
        version: 2,
        operation,
        permission,
        variant_group_id: identifier_bytes(value.variant_group_id.as_ref(), "variant_group_id")?,
        target_scope_sha256: digest_bytes(
            value.target_scope_sha256.as_ref(),
            "target_scope_sha256",
        )?,
        operation_contract_sha256: digest_bytes(
            value.operation_contract_sha256.as_ref(),
            "operation_contract_sha256",
        )?,
    };
    validate_requirement(&requirement)?;
    Ok(requirement)
}

fn consent_from_wire(
    value: &EffectConsentBindingV2,
) -> Result<EffectConsentV2, EffectCanonicalError> {
    if value.version != 2 {
        return Err(EffectCanonicalError::UnsupportedVersion(
            value.version.into(),
        ));
    }
    let permission = match value.permission {
        Some(1) => ActionEffectPermission::LocalRemoveOnly,
        Some(2) => ActionEffectPermission::MayDeleteAcrossDevices,
        Some(value) => return Err(EffectCanonicalError::UnknownPermission(value)),
        None => return Err(EffectCanonicalError::InvalidField("permission")),
    };
    let consent = EffectConsentV2 {
        version: 2,
        permission,
        requirement_sha256: digest_bytes(value.requirement_sha256.as_ref(), "requirement_sha256")?,
        action_id: identifier_bytes(value.action_id.as_ref(), "action_id")?.to_vec(),
        action_lineage_id: identifier_bytes(value.action_lineage_id.as_ref(), "action_lineage_id")?
            .to_vec(),
        target_scope_sha256: digest_bytes(
            value.target_scope_sha256.as_ref(),
            "target_scope_sha256",
        )?,
        plan_sha256: digest_bytes(value.plan_sha256.as_ref(), "plan_sha256")?,
        evidence_sha256: digest_bytes(value.evidence_sha256.as_ref(), "evidence_sha256")?,
        policy_version: value.policy_version.clone(),
        schema_version: value.schema_version.clone(),
        consent_event_id: value.consent_event_id.clone(),
    };
    validate_consent(&consent)?;
    Ok(consent)
}

fn validate_requirement(value: &ActionEffectRequirementV2) -> Result<(), EffectCanonicalError> {
    if value.version != 2 {
        return Err(EffectCanonicalError::UnsupportedVersion(value.version));
    }
    if value.variant_group_id.len() != 32 || value.target_scope_sha256.len() != 32 {
        return Err(EffectCanonicalError::InvalidField(
            "requirement digest or group",
        ));
    }
    if value.operation == ActionEffectOperation::ProviderEvictLocalCopy
        && value.permission != ActionEffectPermission::LocalRemoveOnly
    {
        return Err(EffectCanonicalError::ConflictingOperationPermission);
    }
    Ok(())
}

fn validate_consent(value: &EffectConsentV2) -> Result<(), EffectCanonicalError> {
    if value.version != 2 {
        return Err(EffectCanonicalError::UnsupportedVersion(value.version));
    }
    for (field, length) in [
        ("requirement_sha256", value.requirement_sha256.len()),
        ("target_scope_sha256", value.target_scope_sha256.len()),
        ("plan_sha256", value.plan_sha256.len()),
        ("evidence_sha256", value.evidence_sha256.len()),
    ] {
        if length != 32 {
            return Err(EffectCanonicalError::InvalidField(field));
        }
    }
    validate_identifier(&value.action_id, "action_id")?;
    validate_identifier(&value.action_lineage_id, "action_lineage_id")?;
    validate_text(&value.policy_version, "policy_version")?;
    validate_text(&value.schema_version, "schema_version")?;
    if value.consent_event_id.is_empty()
        || value.consent_event_id.len() > MAXIMUM_EFFECT_IDENTIFIER_BYTES
    {
        return Err(EffectCanonicalError::InvalidField("consent_event_id"));
    }
    Ok(())
}

fn validate_identifier(value: &[u8], field: &'static str) -> Result<(), EffectCanonicalError> {
    if value.len() != 32 {
        return Err(EffectCanonicalError::InvalidField(field));
    }
    Ok(())
}

fn validate_text(value: &str, field: &'static str) -> Result<(), EffectCanonicalError> {
    if value.is_empty() || value.len() > MAXIMUM_EFFECT_TEXT_BYTES {
        return Err(EffectCanonicalError::InvalidField(field));
    }
    Ok(())
}

fn identifier_bytes(
    value: Option<&OpaqueIdentifier>,
    field: &'static str,
) -> Result<[u8; 32], EffectCanonicalError> {
    let value = value
        .ok_or(EffectCanonicalError::InvalidField(field))?
        .value
        .as_slice();
    if value.len() != 32 {
        return Err(EffectCanonicalError::InvalidField(field));
    }
    let mut output = [0; 32];
    output.copy_from_slice(value);
    Ok(output)
}

fn digest_bytes(
    value: Option<&Digest256>,
    field: &'static str,
) -> Result<[u8; 32], EffectCanonicalError> {
    let value = value
        .ok_or(EffectCanonicalError::InvalidField(field))?
        .value
        .as_slice();
    if value.len() != 32 {
        return Err(EffectCanonicalError::InvalidField(field));
    }
    let mut output = [0; 32];
    output.copy_from_slice(value);
    Ok(output)
}

fn domain_digest(domain: &[u8], canonical_bytes: &[u8]) -> [u8; 32] {
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(canonical_bytes);
    hasher.finalize().into()
}

fn put_blob(output: &mut Vec<u8>, bytes: &[u8]) {
    output.extend_from_slice(&(bytes.len() as u64).to_be_bytes());
    output.extend_from_slice(bytes);
}

fn enforce_record_limit(bytes: &[u8]) -> Result<(), EffectCanonicalError> {
    if bytes.len() > MAXIMUM_EFFECT_RECORD_BYTES {
        return Err(EffectCanonicalError::RecordTooLong);
    }
    Ok(())
}

fn enforce_input_limit(bytes: &[u8]) -> Result<(), EffectCanonicalError> {
    enforce_record_limit(bytes)
}

struct Decoder<'a> {
    bytes: &'a [u8],
    offset: usize,
}

impl<'a> Decoder<'a> {
    fn new(bytes: &'a [u8]) -> Self {
        Self { bytes, offset: 0 }
    }

    fn take(
        &mut self,
        length: usize,
        field: &'static str,
    ) -> Result<&'a [u8], EffectCanonicalError> {
        let end = self
            .offset
            .checked_add(length)
            .ok_or(EffectCanonicalError::Truncated(field))?;
        let value = self
            .bytes
            .get(self.offset..end)
            .ok_or(EffectCanonicalError::Truncated(field))?;
        self.offset = end;
        Ok(value)
    }

    fn u8(&mut self, field: &'static str) -> Result<u8, EffectCanonicalError> {
        Ok(self.take(1, field)?[0])
    }

    fn u64(&mut self, field: &'static str) -> Result<u64, EffectCanonicalError> {
        let bytes = self.take(8, field)?;
        Ok(u64::from_be_bytes(
            bytes.try_into().expect("fixed-width slice"),
        ))
    }

    fn blob(&mut self, field: &'static str) -> Result<&'a [u8], EffectCanonicalError> {
        let length = usize::try_from(self.u64(field)?)
            .map_err(|_| EffectCanonicalError::InvalidField(field))?;
        self.take(length, field)
    }

    fn array32(&mut self, field: &'static str) -> Result<[u8; 32], EffectCanonicalError> {
        let bytes = self.blob(field)?;
        if bytes.len() != 32 {
            return Err(EffectCanonicalError::InvalidField(field));
        }
        let mut output = [0; 32];
        output.copy_from_slice(bytes);
        Ok(output)
    }

    fn identifier(&mut self, field: &'static str) -> Result<Vec<u8>, EffectCanonicalError> {
        let value = self.blob(field)?;
        validate_identifier(value, field)?;
        Ok(value.to_vec())
    }

    fn text(&mut self, field: &'static str) -> Result<String, EffectCanonicalError> {
        let bytes = self.blob(field)?;
        if bytes.is_empty() || bytes.len() > MAXIMUM_EFFECT_TEXT_BYTES {
            return Err(EffectCanonicalError::InvalidField(field));
        }
        let text =
            std::str::from_utf8(bytes).map_err(|_| EffectCanonicalError::InvalidUtf8(field))?;
        Ok(text.to_owned())
    }

    fn event_id(&mut self, field: &'static str) -> Result<Vec<u8>, EffectCanonicalError> {
        let value = self.blob(field)?;
        if value.is_empty() || value.len() > MAXIMUM_EFFECT_IDENTIFIER_BYTES {
            return Err(EffectCanonicalError::InvalidField(field));
        }
        Ok(value.to_vec())
    }

    fn finish(self) -> Result<(), EffectCanonicalError> {
        if self.offset != self.bytes.len() {
            return Err(EffectCanonicalError::TrailingBytes);
        }
        Ok(())
    }
}
