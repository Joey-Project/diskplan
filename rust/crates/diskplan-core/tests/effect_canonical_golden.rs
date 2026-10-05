use std::fs;
use std::path::PathBuf;

use diskplan_core::effect_canonical::{
    ActionEffectOperation, ActionEffectPermission, ActionEffectRequirementV2, EffectCanonicalError,
    EffectConsentV2, consent_digest_v2, encode_consent_v2, encode_requirement_v2,
    requirement_digest_v2, verify_acknowledged_effect_consent_v2, verify_consent_v2,
    verify_projected_effect_requirement_v2, verify_requirement_v2,
};
use diskplan_proto::diskplan::v1::{
    AcknowledgedEffectConsent, ActionEffectRequirementBindingV2, Digest256, EffectConsentBindingV2,
    OpaqueIdentifier, PlanActionProjection, PlanProjectionManifest,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    schema: String,
    requirement: RequirementFixture,
    consent: ConsentFixture,
    requirement_tamper_fields: Vec<String>,
    consent_tamper_fields: Vec<String>,
    rejection_cases: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequirementFixture {
    version: u64,
    operation: u8,
    permission: u8,
    variant_group_id_hex: String,
    target_scope_sha256_hex: String,
    operation_contract_sha256_hex: String,
    canonical_hex: String,
    sha256_hex: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ConsentFixture {
    version: u64,
    permission: u8,
    requirement_sha256_hex: String,
    action_id_hex: String,
    action_lineage_id_hex: String,
    target_scope_sha256_hex: String,
    plan_sha256_hex: String,
    evidence_sha256_hex: String,
    policy_version: String,
    schema_version: String,
    consent_event_id_hex: String,
    canonical_hex: String,
    sha256_hex: String,
}

#[test]
fn canonical_effect_v2_matches_shared_golden_bytes_and_digests() {
    let fixture = fixture();
    assert_eq!(fixture.schema, "canonical-effect-v2");
    let requirement = requirement(&fixture.requirement);
    let requirement_bytes = encode_requirement_v2(&requirement).unwrap();
    assert_eq!(
        hex::encode(&requirement_bytes),
        fixture.requirement.canonical_hex
    );
    assert_eq!(
        hex::encode(requirement_digest_v2(&requirement).unwrap()),
        fixture.requirement.sha256_hex
    );
    assert_eq!(
        verify_requirement_v2(&requirement_bytes).unwrap(),
        requirement
    );

    let consent = consent(&fixture.consent);
    let consent_bytes = encode_consent_v2(&consent).unwrap();
    assert_eq!(hex::encode(&consent_bytes), fixture.consent.canonical_hex);
    assert_eq!(
        hex::encode(consent_digest_v2(&consent).unwrap()),
        fixture.consent.sha256_hex
    );
    assert_eq!(verify_consent_v2(&consent_bytes).unwrap(), consent);
    assert_eq!(
        consent.requirement_sha256,
        requirement_digest_v2(&requirement).unwrap()
    );
}

#[test]
fn every_requirement_and_consent_field_changes_canonical_digest() {
    let fixture = fixture();
    let requirement = requirement(&fixture.requirement);
    let original_requirement_digest = requirement_digest_v2(&requirement).unwrap();
    let mut variants = Vec::new();
    let mut value = requirement.clone();
    value.version = 3;
    variants.push(value);
    let mut value = requirement.clone();
    value.operation = ActionEffectOperation::ProviderEvictLocalCopy;
    variants.push(value);
    let mut value = requirement.clone();
    value.permission = ActionEffectPermission::MayDeleteAcrossDevices;
    variants.push(value);
    let mut value = requirement.clone();
    value.variant_group_id[0] ^= 1;
    variants.push(value);
    let mut value = requirement.clone();
    value.target_scope_sha256[0] ^= 1;
    variants.push(value);
    let mut value = requirement.clone();
    value.operation_contract_sha256[0] ^= 1;
    variants.push(value);
    for tampered in variants {
        if requirement_digest_v2(&tampered).is_ok() {
            assert_ne!(
                requirement_digest_v2(&tampered).unwrap(),
                original_requirement_digest
            );
        }
    }
    assert_eq!(fixture.requirement_tamper_fields.len(), 6);

    let consent = consent(&fixture.consent);
    let original_consent_digest = consent_digest_v2(&consent).unwrap();
    let mut variants = Vec::new();
    let mut value = consent.clone();
    value.version = 3;
    variants.push(value);
    let mut value = consent.clone();
    value.permission = ActionEffectPermission::MayDeleteAcrossDevices;
    variants.push(value);
    let mut value = consent.clone();
    value.requirement_sha256[0] ^= 1;
    variants.push(value);
    let mut value = consent.clone();
    value.action_id[0] ^= 1;
    variants.push(value);
    let mut value = consent.clone();
    value.action_lineage_id[0] ^= 1;
    variants.push(value);
    let mut value = consent.clone();
    value.target_scope_sha256[0] ^= 1;
    variants.push(value);
    let mut value = consent.clone();
    value.plan_sha256[0] ^= 1;
    variants.push(value);
    let mut value = consent.clone();
    value.evidence_sha256[0] ^= 1;
    variants.push(value);
    let mut value = consent.clone();
    value.policy_version.push('x');
    variants.push(value);
    let mut value = consent.clone();
    value.schema_version.push('x');
    variants.push(value);
    let mut value = consent.clone();
    value.consent_event_id[0] ^= 1;
    variants.push(value);
    for tampered in variants {
        if let Ok(digest) = consent_digest_v2(&tampered) {
            assert_ne!(digest, original_consent_digest);
        }
    }
    assert_eq!(fixture.consent_tamper_fields.len(), 11);
}

#[test]
fn canonical_decoders_reject_missing_unknown_conflicting_trailing_and_overlong_values() {
    let fixture = fixture();
    let requirement = requirement(&fixture.requirement);
    let encoded_requirement = encode_requirement_v2(&requirement).unwrap();
    assert!(matches!(
        verify_requirement_v2(&encoded_requirement[..8]),
        Err(EffectCanonicalError::Truncated(_))
    ));
    let mut unknown_operation = encoded_requirement.clone();
    unknown_operation[8] = 0;
    assert_eq!(
        verify_requirement_v2(&unknown_operation),
        Err(EffectCanonicalError::UnknownOperation(0))
    );
    let mut unknown_permission = encoded_requirement.clone();
    unknown_permission[9] = 9;
    assert_eq!(
        verify_requirement_v2(&unknown_permission),
        Err(EffectCanonicalError::UnknownPermission(9))
    );
    let mut conflicting = encoded_requirement.clone();
    conflicting[8] = ActionEffectOperation::ProviderEvictLocalCopy as u8;
    conflicting[9] = ActionEffectPermission::MayDeleteAcrossDevices as u8;
    assert_eq!(
        verify_requirement_v2(&conflicting),
        Err(EffectCanonicalError::ConflictingOperationPermission)
    );
    let mut trailing = encoded_requirement;
    trailing.push(0);
    assert_eq!(
        verify_requirement_v2(&trailing),
        Err(EffectCanonicalError::TrailingBytes)
    );
    let mut short_group = encode_requirement_v2(&requirement).unwrap();
    short_group[10..18].copy_from_slice(&31_u64.to_be_bytes());
    assert_eq!(
        verify_requirement_v2(&short_group),
        Err(EffectCanonicalError::InvalidField("variant_group_id"))
    );

    let consent = consent(&fixture.consent);
    let encoded_consent = encode_consent_v2(&consent).unwrap();
    assert!(matches!(
        verify_consent_v2(&encoded_consent[..8]),
        Err(EffectCanonicalError::Truncated(_))
    ));
    let mut unknown_permission = encoded_consent.clone();
    unknown_permission[8] = 0;
    assert_eq!(
        verify_consent_v2(&unknown_permission),
        Err(EffectCanonicalError::UnknownPermission(0))
    );
    let mut trailing = encoded_consent.clone();
    trailing.push(0);
    assert_eq!(
        verify_consent_v2(&trailing),
        Err(EffectCanonicalError::TrailingBytes)
    );
    let mut short_requirement_digest = encoded_consent.clone();
    short_requirement_digest[9..17].copy_from_slice(&31_u64.to_be_bytes());
    assert_eq!(
        verify_consent_v2(&short_requirement_digest),
        Err(EffectCanonicalError::InvalidField("requirement_sha256"))
    );
    for invalid_length in [31, 33] {
        for (field, length_offset) in [("action_id", 49), ("action_lineage_id", 89)] {
            let mut invalid = encoded_consent.clone();
            invalid[length_offset..length_offset + 8]
                .copy_from_slice(&(invalid_length as u64).to_be_bytes());
            assert_eq!(
                verify_consent_v2(&invalid),
                Err(EffectCanonicalError::InvalidField(field)),
                "decoder must reject {field} with length {invalid_length}"
            );
        }
    }
    let mut invalid_utf8 = encoded_consent;
    let policy_start = invalid_utf8
        .windows(b"policy-test-v1".len())
        .position(|window| window == b"policy-test-v1")
        .unwrap();
    invalid_utf8[policy_start] = 0xff;
    assert_eq!(
        verify_consent_v2(&invalid_utf8),
        Err(EffectCanonicalError::InvalidUtf8("policy_version"))
    );

    let mut invalid = consent.clone();
    invalid.consent_event_id.clear();
    assert_eq!(
        encode_consent_v2(&invalid),
        Err(EffectCanonicalError::InvalidField("consent_event_id"))
    );
    let mut invalid = consent.clone();
    invalid.action_id.clear();
    assert_eq!(
        encode_consent_v2(&invalid),
        Err(EffectCanonicalError::InvalidField("action_id"))
    );
    for invalid_length in [31, 33] {
        let mut invalid = consent.clone();
        invalid.action_id.resize(invalid_length, 0);
        assert_eq!(
            encode_consent_v2(&invalid),
            Err(EffectCanonicalError::InvalidField("action_id")),
            "encoder must reject action_id with length {invalid_length}"
        );
        let mut invalid = consent.clone();
        invalid.action_lineage_id.resize(invalid_length, 0);
        assert_eq!(
            encode_consent_v2(&invalid),
            Err(EffectCanonicalError::InvalidField("action_lineage_id")),
            "encoder must reject action_lineage_id with length {invalid_length}"
        );
    }
    let mut invalid = consent.clone();
    invalid.policy_version.clear();
    assert_eq!(
        encode_consent_v2(&invalid),
        Err(EffectCanonicalError::InvalidField("policy_version"))
    );
    let mut invalid = consent.clone();
    invalid.schema_version = "x".repeat(257);
    assert_eq!(
        encode_consent_v2(&invalid),
        Err(EffectCanonicalError::InvalidField("schema_version"))
    );
    let mut invalid = consent;
    invalid.consent_event_id = vec![0; 257];
    assert_eq!(
        encode_consent_v2(&invalid),
        Err(EffectCanonicalError::InvalidField("consent_event_id"))
    );
    assert_eq!(
        verify_requirement_v2(&vec![0; 4097]),
        Err(EffectCanonicalError::RecordTooLong)
    );
    assert_eq!(fixture.rejection_cases.len(), 12);
}

#[test]
fn acknowledged_binding_verifies_all_plan_action_and_consent_references() {
    let fixture = fixture();
    let requirement = requirement(&fixture.requirement);
    let requirement_digest = requirement_digest_v2(&requirement).unwrap();
    let consent = consent(&fixture.consent);
    let consent_digest = consent_digest_v2(&consent).unwrap();
    let mut action = PlanActionProjection {
        action_id: Some(opaque(hex::decode(&fixture.consent.action_id_hex).unwrap())),
        action_lineage_id: Some(opaque(
            hex::decode(&fixture.consent.action_lineage_id_hex).unwrap(),
        )),
        action_effect_requirement: Some(ActionEffectRequirementBindingV2 {
            version: 2,
            operation: Some(fixture.requirement.operation as i32),
            permission: Some(fixture.requirement.permission as i32),
            variant_group_id: Some(opaque(requirement.variant_group_id.to_vec())),
            target_scope_sha256: Some(digest(requirement.target_scope_sha256.to_vec())),
            operation_contract_sha256: Some(digest(requirement.operation_contract_sha256.to_vec())),
        }),
        action_effect_requirement_sha256: Some(digest(requirement_digest.to_vec())),
        action_effect_variant_group_id: Some(opaque(requirement.variant_group_id.to_vec())),
        ..Default::default()
    };
    let manifest = PlanProjectionManifest {
        action_effect_binding_schema_version: 2,
        plan_sha256: Some(digest(consent.plan_sha256.to_vec())),
        evidence_sha256: Some(digest(consent.evidence_sha256.to_vec())),
        policy_version: consent.policy_version.clone(),
        schema_version: consent.schema_version.clone(),
        ..Default::default()
    };
    assert_eq!(
        verify_projected_effect_requirement_v2(&action, &manifest).unwrap(),
        (requirement_digest, requirement.clone())
    );
    let mut acknowledged = AcknowledgedEffectConsent {
        binding: Some(EffectConsentBindingV2 {
            version: 2,
            permission: Some(fixture.consent.permission as i32),
            requirement_sha256: Some(digest(consent.requirement_sha256.to_vec())),
            action_id: Some(opaque(consent.action_id.clone())),
            action_lineage_id: Some(opaque(consent.action_lineage_id.clone())),
            target_scope_sha256: Some(digest(consent.target_scope_sha256.to_vec())),
            plan_sha256: Some(digest(consent.plan_sha256.to_vec())),
            evidence_sha256: Some(digest(consent.evidence_sha256.to_vec())),
            policy_version: consent.policy_version.clone(),
            schema_version: consent.schema_version.clone(),
            consent_event_id: consent.consent_event_id.clone(),
        }),
        consent_sha256: Some(digest(consent_digest.to_vec())),
    };
    assert_eq!(
        verify_acknowledged_effect_consent_v2(&action, &manifest, &acknowledged)
            .unwrap()
            .0,
        consent_digest
    );

    let mut internally_consistent_random_consent = consent.clone();
    internally_consistent_random_consent.requirement_sha256 = [0x77; 32];
    let random_consent_digest = consent_digest_v2(&internally_consistent_random_consent).unwrap();
    let original_acknowledged = acknowledged.clone();
    let binding = acknowledged.binding.as_mut().unwrap();
    binding.requirement_sha256 = Some(digest(vec![0x77; 32]));
    acknowledged.consent_sha256 = Some(digest(random_consent_digest.to_vec()));
    assert_eq!(
        verify_acknowledged_effect_consent_v2(&action, &manifest, &acknowledged),
        Err(EffectCanonicalError::ReferenceMismatch(
            "requirement_sha256"
        )),
        "a canonical random consent digest cannot repair a mismatched requirement reference"
    );
    acknowledged = original_acknowledged;

    let mut invalid_requirement_reference = action.clone();
    invalid_requirement_reference
        .action_effect_requirement_sha256
        .as_mut()
        .unwrap()
        .value[0] ^= 1;
    assert!(
        verify_projected_effect_requirement_v2(&invalid_requirement_reference, &manifest).is_err()
    );
    invalid_requirement_reference = action.clone();
    invalid_requirement_reference
        .action_effect_variant_group_id
        .as_mut()
        .unwrap()
        .value[0] ^= 1;
    assert!(
        verify_projected_effect_requirement_v2(&invalid_requirement_reference, &manifest).is_err()
    );

    for invalid_length in [31, 33] {
        acknowledged
            .binding
            .as_mut()
            .unwrap()
            .action_id
            .as_mut()
            .unwrap()
            .value
            .resize(invalid_length, 0);
        assert_eq!(
            verify_acknowledged_effect_consent_v2(&action, &manifest, &acknowledged),
            Err(EffectCanonicalError::InvalidField("action_id")),
            "public verifier must reject action_id with length {invalid_length}"
        );
        acknowledged.binding.as_mut().unwrap().action_id = Some(opaque(consent.action_id.clone()));
        acknowledged
            .binding
            .as_mut()
            .unwrap()
            .action_lineage_id
            .as_mut()
            .unwrap()
            .value
            .resize(invalid_length, 0);
        assert_eq!(
            verify_acknowledged_effect_consent_v2(&action, &manifest, &acknowledged),
            Err(EffectCanonicalError::InvalidField("action_lineage_id")),
            "public verifier must reject action_lineage_id with length {invalid_length}"
        );
        acknowledged.binding.as_mut().unwrap().action_lineage_id =
            Some(opaque(consent.action_lineage_id.clone()));
    }

    acknowledged
        .binding
        .as_mut()
        .unwrap()
        .consent_event_id
        .push(b'x');
    assert!(verify_acknowledged_effect_consent_v2(&action, &manifest, &acknowledged).is_err());
    acknowledged
        .binding
        .as_mut()
        .unwrap()
        .consent_event_id
        .pop();
    action
        .action_effect_variant_group_id
        .as_mut()
        .unwrap()
        .value[0] ^= 1;
    assert!(verify_acknowledged_effect_consent_v2(&action, &manifest, &acknowledged).is_err());
}

fn fixture() -> Fixture {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../proto/fixtures/canonical-effect-v2/fixtures.json");
    serde_json::from_slice(&fs::read(path).unwrap()).unwrap()
}

fn requirement(value: &RequirementFixture) -> ActionEffectRequirementV2 {
    ActionEffectRequirementV2 {
        version: value.version,
        operation: ActionEffectOperation::try_from(value.operation).unwrap(),
        permission: ActionEffectPermission::try_from(value.permission).unwrap(),
        variant_group_id: hex::decode(&value.variant_group_id_hex)
            .unwrap()
            .try_into()
            .unwrap(),
        target_scope_sha256: hex::decode(&value.target_scope_sha256_hex)
            .unwrap()
            .try_into()
            .unwrap(),
        operation_contract_sha256: hex::decode(&value.operation_contract_sha256_hex)
            .unwrap()
            .try_into()
            .unwrap(),
    }
}

fn consent(value: &ConsentFixture) -> EffectConsentV2 {
    EffectConsentV2 {
        version: value.version,
        permission: ActionEffectPermission::try_from(value.permission).unwrap(),
        requirement_sha256: hex::decode(&value.requirement_sha256_hex)
            .unwrap()
            .try_into()
            .unwrap(),
        action_id: hex::decode(&value.action_id_hex).unwrap(),
        action_lineage_id: hex::decode(&value.action_lineage_id_hex).unwrap(),
        target_scope_sha256: hex::decode(&value.target_scope_sha256_hex)
            .unwrap()
            .try_into()
            .unwrap(),
        plan_sha256: hex::decode(&value.plan_sha256_hex)
            .unwrap()
            .try_into()
            .unwrap(),
        evidence_sha256: hex::decode(&value.evidence_sha256_hex)
            .unwrap()
            .try_into()
            .unwrap(),
        policy_version: value.policy_version.clone(),
        schema_version: value.schema_version.clone(),
        consent_event_id: hex::decode(&value.consent_event_id_hex).unwrap(),
    }
}

fn opaque(value: Vec<u8>) -> OpaqueIdentifier {
    OpaqueIdentifier { value }
}

fn digest(value: Vec<u8>) -> Digest256 {
    Digest256 { value }
}
