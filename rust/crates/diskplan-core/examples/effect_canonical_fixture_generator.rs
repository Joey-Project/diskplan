use std::env;
use std::fs;
use std::path::PathBuf;

use diskplan_core::effect_canonical::{
    ActionEffectOperation, ActionEffectPermission, ActionEffectRequirementV2, EffectConsentV2,
    consent_digest_v2, encode_consent_v2, encode_requirement_v2, requirement_digest_v2,
};
use serde_json::json;

fn main() {
    let output = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: effect_canonical_fixture_generator OUTPUT.json");
    let requirement = ActionEffectRequirementV2 {
        version: 2,
        operation: ActionEffectOperation::OrdinaryRemove,
        permission: ActionEffectPermission::LocalRemoveOnly,
        variant_group_id: sequence(0x00),
        target_scope_sha256: sequence(0x20),
        operation_contract_sha256: sequence(0x40),
    };
    let requirement_canonical = encode_requirement_v2(&requirement).unwrap();
    let requirement_sha256 = requirement_digest_v2(&requirement).unwrap();
    let consent = EffectConsentV2 {
        version: 2,
        permission: ActionEffectPermission::LocalRemoveOnly,
        requirement_sha256,
        action_id: sequence(0x60).to_vec(),
        action_lineage_id: sequence(0x80).to_vec(),
        target_scope_sha256: sequence(0x20),
        plan_sha256: sequence(0xa0),
        evidence_sha256: sequence(0xc0),
        policy_version: "policy-test-v1".into(),
        schema_version: "schema-test-v1".into(),
        consent_event_id: "approve-é-event".as_bytes().to_vec(),
    };
    let consent_canonical = encode_consent_v2(&consent).unwrap();
    let consent_sha256 = consent_digest_v2(&consent).unwrap();
    let fixture = json!({
        "schema": "canonical-effect-v2",
        "requirement": {
            "version": requirement.version,
            "operation": requirement.operation as u8,
            "permission": requirement.permission as u8,
            "variant_group_id_hex": hex::encode(requirement.variant_group_id),
            "target_scope_sha256_hex": hex::encode(requirement.target_scope_sha256),
            "operation_contract_sha256_hex": hex::encode(requirement.operation_contract_sha256),
            "canonical_hex": hex::encode(requirement_canonical),
            "sha256_hex": hex::encode(requirement_sha256),
        },
        "consent": {
            "version": consent.version,
            "permission": consent.permission as u8,
            "requirement_sha256_hex": hex::encode(consent.requirement_sha256),
            "action_id_hex": hex::encode(consent.action_id),
            "action_lineage_id_hex": hex::encode(consent.action_lineage_id),
            "target_scope_sha256_hex": hex::encode(consent.target_scope_sha256),
            "plan_sha256_hex": hex::encode(consent.plan_sha256),
            "evidence_sha256_hex": hex::encode(consent.evidence_sha256),
            "policy_version": consent.policy_version,
            "schema_version": consent.schema_version,
            "consent_event_id_hex": hex::encode(consent.consent_event_id),
            "canonical_hex": hex::encode(consent_canonical),
            "sha256_hex": hex::encode(consent_sha256),
        },
        "requirement_tamper_fields": [
            "version", "operation", "permission", "variant_group_id",
            "target_scope_sha256", "operation_contract_sha256",
        ],
        "consent_tamper_fields": [
            "version", "permission", "requirement_sha256", "action_id",
            "action_lineage_id", "target_scope_sha256", "plan_sha256",
            "evidence_sha256", "policy_version", "schema_version", "consent_event_id",
        ],
        "rejection_cases": [
            "unknown_operation", "unknown_permission", "missing_operation",
            "missing_permission", "provider_evict_cross_device_permission",
            "missing_digest", "missing_identifier", "missing_text", "empty_event",
            "invalid_utf8", "trailing_bytes", "overlong_record",
        ],
    });
    let mut bytes = serde_json::to_vec_pretty(&fixture).unwrap();
    bytes.push(b'\n');
    fs::write(output, bytes).unwrap();
}

fn sequence(start: u8) -> [u8; 32] {
    std::array::from_fn(|index| start.wrapping_add(index as u8))
}
