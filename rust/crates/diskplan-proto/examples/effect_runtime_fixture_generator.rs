use std::env;
use std::fs;
use std::path::PathBuf;

use diskplan_proto::diskplan::v1::{
    ActionEffectRequirementBindingV2, ApplyReviewActionProjection, Digest256,
    EffectConsentBindingV2, OpaqueIdentifier,
};
use prost::Message;
use serde_json::{Value, json};

fn main() {
    let output = env::args_os()
        .nth(1)
        .map(PathBuf::from)
        .expect("usage: effect_runtime_fixture_generator OUTPUT.json");
    let mut requirement_cases = vec![
        requirement_case(
            "valid-ordinary-local",
            requirement(Some(1), Some(1)),
            true,
            true,
            true,
        ),
        requirement_case(
            "missing-operation",
            requirement(None, Some(1)),
            true,
            true,
            false,
        ),
        requirement_case(
            "missing-permission",
            requirement(Some(1), None),
            true,
            true,
            false,
        ),
        requirement_case(
            "unknown-operation",
            requirement(Some(9), Some(1)),
            true,
            true,
            false,
        ),
        requirement_case(
            "unspecified-operation",
            requirement(Some(0), Some(1)),
            true,
            true,
            false,
        ),
        requirement_case(
            "unknown-permission",
            requirement(Some(1), Some(9)),
            true,
            true,
            false,
        ),
        requirement_case(
            "unspecified-permission",
            requirement(Some(1), Some(0)),
            true,
            true,
            false,
        ),
        requirement_case(
            "provider-cross-device-conflict",
            requirement(Some(2), Some(2)),
            true,
            true,
            false,
        ),
        requirement_case(
            "missing-requirement-digest",
            requirement(Some(1), Some(1)),
            false,
            true,
            false,
        ),
        requirement_case(
            "missing-action-variant-group",
            requirement(Some(1), Some(1)),
            true,
            false,
            false,
        ),
        requirement_case(
            "missing-target-scope-digest",
            {
                let mut value = requirement(Some(1), Some(1));
                value.target_scope_sha256 = None;
                value
            },
            true,
            true,
            false,
        ),
        requirement_case(
            "short-variant-group",
            {
                let mut value = requirement(Some(1), Some(1));
                value.variant_group_id.as_mut().unwrap().value.pop();
                value
            },
            true,
            true,
            false,
        ),
        requirement_case(
            "short-operation-contract-digest",
            {
                let mut value = requirement(Some(1), Some(1));
                value
                    .operation_contract_sha256
                    .as_mut()
                    .unwrap()
                    .value
                    .pop();
                value
            },
            true,
            true,
            false,
        ),
    ];
    let mut mismatch = requirement_case(
        "mismatched-action-variant-group",
        requirement(Some(1), Some(1)),
        true,
        true,
        false,
    );
    mismatch["action_variant_group_hex"] = json!(hex::encode(sequence(0x01)));
    requirement_cases.push(mismatch);
    let consent_cases = vec![
        consent_case(
            "valid-local",
            consent(Some(1), true, true, true, true, true, true),
            true,
        ),
        consent_case(
            "missing-permission",
            consent(None, true, true, true, true, true, true),
            false,
        ),
        consent_case(
            "unknown-permission",
            consent(Some(9), true, true, true, true, true, true),
            false,
        ),
        consent_case(
            "missing-requirement-digest",
            consent(Some(1), false, true, true, true, true, true),
            false,
        ),
        consent_case(
            "missing-action-id",
            consent(Some(1), true, false, true, true, true, true),
            false,
        ),
        consent_case(
            "missing-lineage-id",
            consent(Some(1), true, true, false, true, true, true),
            false,
        ),
        consent_case(
            "missing-target-scope",
            consent(Some(1), true, true, true, false, true, true),
            false,
        ),
        consent_case(
            "missing-policy-version",
            consent(Some(1), true, true, true, true, false, true),
            false,
        ),
        consent_case(
            "missing-schema-version",
            consent(Some(1), true, true, true, true, true, false),
            false,
        ),
        consent_case(
            "empty-event-id",
            {
                let mut value = consent(Some(1), true, true, true, true, true, true);
                value.consent_event_id.clear();
                value
            },
            false,
        ),
        consent_case(
            "short-requirement-digest",
            {
                let mut value = consent(Some(1), true, true, true, true, true, true);
                value.requirement_sha256.as_mut().unwrap().value.pop();
                value
            },
            false,
        ),
        consent_case(
            "overlong-action-id",
            {
                let mut value = consent(Some(1), true, true, true, true, true, true);
                value.action_id.as_mut().unwrap().value = vec![0; 257];
                value
            },
            false,
        ),
        consent_case(
            "overlong-policy-version",
            {
                let mut value = consent(Some(1), true, true, true, true, true, true);
                value.policy_version = "p".repeat(257);
                value
            },
            false,
        ),
        consent_case(
            "overlong-event-id",
            {
                let mut value = consent(Some(1), true, true, true, true, true, true);
                value.consent_event_id = vec![0; 257];
                value
            },
            false,
        ),
    ];
    let review_action_cases = vec![
        review_action_case("valid-local", review_action(Some(1), true, true), true),
        review_action_case("missing-permission", review_action(None, true, true), false),
        review_action_case(
            "unknown-permission",
            review_action(Some(9), true, true),
            false,
        ),
        review_action_case(
            "missing-requirement-digest",
            review_action(Some(1), false, true),
            false,
        ),
        review_action_case(
            "missing-consent-digest",
            review_action(Some(1), true, false),
            false,
        ),
        review_action_case(
            "short-requirement-digest",
            {
                let mut value = review_action(Some(1), true, true);
                value
                    .effect_requirement_sha256
                    .as_mut()
                    .unwrap()
                    .value
                    .pop();
                value
            },
            false,
        ),
    ];
    let fixture = json!({
        "schema": "runtime-v1.7",
        "protocol_minor": 7,
        "effect_binding_schema_version": 2,
        "maximum_effect_consents": 100000,
        "fixture_scope": "component-level additive validators; not a live negotiated or execution-chain fixture",
        "requirement_cases": requirement_cases,
        "consent_cases": consent_cases,
        "review_action_cases": review_action_cases,
    });
    let mut bytes = serde_json::to_vec_pretty(&fixture).unwrap();
    bytes.push(b'\n');
    fs::write(output, bytes).unwrap();
}

fn requirement(
    operation: Option<i32>,
    permission: Option<i32>,
) -> ActionEffectRequirementBindingV2 {
    ActionEffectRequirementBindingV2 {
        version: 2,
        operation,
        permission,
        variant_group_id: Some(opaque(sequence(0x00).to_vec())),
        target_scope_sha256: Some(digest(sequence(0x20).to_vec())),
        operation_contract_sha256: Some(digest(sequence(0x40).to_vec())),
    }
}

fn consent(
    permission: Option<i32>,
    has_requirement_digest: bool,
    has_action_id: bool,
    has_lineage_id: bool,
    has_target_scope: bool,
    has_policy: bool,
    has_schema: bool,
) -> EffectConsentBindingV2 {
    EffectConsentBindingV2 {
        version: 2,
        permission,
        requirement_sha256: has_requirement_digest.then(|| digest(sequence(0x60).to_vec())),
        action_id: has_action_id.then(|| opaque(sequence(0x80).to_vec())),
        action_lineage_id: has_lineage_id.then(|| opaque(sequence(0xa0).to_vec())),
        target_scope_sha256: has_target_scope.then(|| digest(sequence(0x20).to_vec())),
        plan_sha256: Some(digest(sequence(0xc0).to_vec())),
        evidence_sha256: Some(digest(sequence(0xe0).to_vec())),
        policy_version: if has_policy { "policy-test-v1" } else { "" }.into(),
        schema_version: if has_schema { "schema-test-v1" } else { "" }.into(),
        consent_event_id: b"approve-event".to_vec(),
    }
}

fn requirement_case(
    name: &str,
    requirement: ActionEffectRequirementBindingV2,
    has_requirement_digest: bool,
    has_action_variant_group: bool,
    expected_valid: bool,
) -> Value {
    json!({
        "name": name,
        "requirement_wire_hex": hex::encode(requirement.encode_to_vec()),
        "requirement_digest_hex": has_requirement_digest.then(|| hex::encode(sequence(0x60))),
        "action_variant_group_hex": has_action_variant_group.then(|| hex::encode(sequence(0x00))),
        "expected_valid": expected_valid,
    })
}

fn consent_case(name: &str, consent: EffectConsentBindingV2, expected_valid: bool) -> Value {
    json!({
        "name": name,
        "consent_wire_hex": hex::encode(consent.encode_to_vec()),
        "expected_valid": expected_valid,
    })
}

fn review_action(
    permission: Option<i32>,
    has_requirement_digest: bool,
    has_consent_digest: bool,
) -> ApplyReviewActionProjection {
    ApplyReviewActionProjection {
        action_id: Some(opaque(sequence(0x80).to_vec())),
        effect_permission: permission,
        effect_requirement_sha256: has_requirement_digest.then(|| digest(sequence(0x60).to_vec())),
        effect_consent_sha256: has_consent_digest.then(|| digest(sequence(0xa0).to_vec())),
        ..Default::default()
    }
}

fn review_action_case(
    name: &str,
    action: ApplyReviewActionProjection,
    expected_valid: bool,
) -> Value {
    json!({
        "name": name,
        "action_wire_hex": hex::encode(action.encode_to_vec()),
        "expected_valid": expected_valid,
    })
}

fn opaque(value: Vec<u8>) -> OpaqueIdentifier {
    OpaqueIdentifier { value }
}

fn digest(value: Vec<u8>) -> Digest256 {
    Digest256 { value }
}

fn sequence(start: u8) -> [u8; 32] {
    std::array::from_fn(|index| start.wrapping_add(index as u8))
}
