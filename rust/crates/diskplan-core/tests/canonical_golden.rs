use std::fs;
use std::path::PathBuf;

use diskplan_core::canonical::{
    Activity, CanonicalError, Coverage, EvidenceBinding, Timestamp, evidence_digest,
    verify_evidence,
};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Fixture {
    #[serde(deserialize_with = "canonical_schema")]
    schema: String,
    #[serde(deserialize_with = "evidence_binding_kind")]
    binding_kind: String,
    candidate_id: String,
    raw_path_hex: String,
    logical_bytes: u64,
    observed_at: Option<FixtureTimestamp>,
    activity: String,
    coverage: String,
    labels: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FixtureTimestamp {
    seconds: i64,
    nanos: u32,
}

#[test]
fn verifies_swift_authority_golden_bytes_and_digest() {
    let directory = fixture_directory();
    let fixture: Fixture =
        serde_json::from_slice(&fs::read(directory.join("evidence.json")).unwrap()).unwrap();
    assert_eq!(fixture.schema, "canonical-binary-v1");
    assert_eq!(fixture.binding_kind, "evidence");
    let value = EvidenceBinding {
        candidate_id: fixture.candidate_id,
        raw_path: hex::decode(fixture.raw_path_hex).unwrap(),
        logical_bytes: fixture.logical_bytes,
        observed_at: fixture.observed_at.map(|timestamp| Timestamp {
            seconds: timestamp.seconds,
            nanos: timestamp.nanos,
        }),
        activity: activity(&fixture.activity),
        coverage: coverage(&fixture.coverage),
        labels: fixture.labels,
    };
    let golden = fs::read(directory.join("evidence.bin")).unwrap();
    let expected_digest = fs::read_to_string(directory.join("evidence.sha256")).unwrap();

    let encoded = encode_evidence_for_test(&value).unwrap();
    assert_eq!(encoded, golden);
    assert_eq!(
        hex::encode(evidence_digest(&encoded).unwrap()),
        expected_digest.trim()
    );
    let decoded = verify_evidence(&golden).unwrap();
    let mut expected_binding = value;
    expected_binding.labels = vec![
        "cache".into(),
        "e\u{301}".into(),
        "swift".into(),
        "\u{e9}".into(),
    ];
    assert_eq!(decoded, expected_binding);
    assert_eq!(encode_evidence_for_test(&decoded).unwrap(), golden);
    assert_eq!(
        decoded
            .labels
            .iter()
            .map(String::as_bytes)
            .collect::<Vec<_>>(),
        vec![
            b"cache".as_slice(),
            "e\u{301}".as_bytes(),
            b"swift".as_slice(),
            "\u{e9}".as_bytes(),
        ]
    );
}

#[test]
fn canonical_decoder_fails_closed_on_trailing_bytes() {
    let mut bytes = fs::read(fixture_directory().join("evidence.bin")).unwrap();
    bytes.push(0);
    assert_eq!(verify_evidence(&bytes), Err(CanonicalError::TrailingBytes));
    assert_eq!(evidence_digest(&bytes), Err(CanonicalError::TrailingBytes));
}

#[test]
fn typed_absence_and_signed_time_round_trip() {
    let absent = EvidenceBinding {
        candidate_id: "absent".into(),
        raw_path: Vec::new(),
        logical_bytes: 0,
        observed_at: None,
        activity: Activity::Absent,
        coverage: Coverage::Unreadable,
        labels: Vec::new(),
    };
    assert_eq!(
        verify_evidence(&encode_evidence_for_test(&absent).unwrap()).unwrap(),
        absent
    );

    let before_epoch = EvidenceBinding {
        candidate_id: "before-epoch".into(),
        raw_path: vec![0],
        logical_bytes: 1,
        observed_at: Some(Timestamp {
            seconds: -1,
            nanos: 999_999_999,
        }),
        activity: Activity::Unknown,
        coverage: Coverage::Failed,
        labels: vec!["x".into()],
    };
    assert_eq!(
        verify_evidence(&encode_evidence_for_test(&before_epoch).unwrap()).unwrap(),
        before_epoch
    );
}

#[test]
fn fixture_json_rejects_unknown_fields_and_unsupported_type_tags() {
    let source = fs::read(fixture_directory().join("evidence.json")).unwrap();
    let mut value: serde_json::Value = serde_json::from_slice(&source).unwrap();
    value["unexpected"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<Fixture>(value.clone()).is_err());

    value.as_object_mut().unwrap().remove("unexpected");
    value["binding_kind"] = serde_json::Value::String("other".into());
    assert!(serde_json::from_value::<Fixture>(value.clone()).is_err());

    value["binding_kind"] = serde_json::Value::String("evidence".into());
    value["schema"] = serde_json::Value::String("other".into());
    assert!(serde_json::from_value::<Fixture>(value).is_err());

    let mut nested: serde_json::Value = serde_json::from_slice(&source).unwrap();
    nested["observed_at"]["unexpected"] = serde_json::Value::Bool(true);
    assert!(serde_json::from_value::<Fixture>(nested).is_err());
}

#[test]
fn impossible_collection_count_is_rejected_before_allocation() {
    let mut bytes = fs::read(fixture_directory().join("evidence.bin")).unwrap();
    bytes.truncate(bytes.len() - 22);
    bytes.extend_from_slice(&u32::MAX.to_be_bytes());
    assert_eq!(
        verify_evidence(&bytes),
        Err(CanonicalError::Truncated { field: "labels" })
    );
}

fn fixture_directory() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../../proto/fixtures/canonical-binary-v1")
}

fn activity(value: &str) -> Activity {
    match value {
        "absent" => Activity::Absent,
        "unknown" => Activity::Unknown,
        "inactive" => Activity::Inactive,
        "active" => Activity::Active,
        _ => panic!("unknown activity fixture value: {value}"),
    }
}

fn coverage(value: &str) -> Coverage {
    match value {
        "unknown" => Coverage::Unknown,
        "complete" => Coverage::Complete,
        "partial" => Coverage::Partial,
        "unreadable" => Coverage::Unreadable,
        "failed" => Coverage::Failed,
        _ => panic!("unknown coverage fixture value: {value}"),
    }
}

fn canonical_schema<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value == "canonical-binary-v1" {
        Ok(value)
    } else {
        Err(serde::de::Error::custom("unsupported fixture schema"))
    }
}

fn evidence_binding_kind<'de, D>(deserializer: D) -> Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let value = String::deserialize(deserializer)?;
    if value == "evidence" {
        Ok(value)
    } else {
        Err(serde::de::Error::custom("unsupported binding kind"))
    }
}

fn encode_evidence_for_test(value: &EvidenceBinding) -> Result<Vec<u8>, CanonicalError> {
    if value
        .observed_at
        .as_ref()
        .is_some_and(|timestamp| timestamp.nanos >= 1_000_000_000)
    {
        return Err(CanonicalError::InvalidNanoseconds);
    }

    let mut output = Vec::new();
    output.extend_from_slice(b"DPCB");
    output.extend_from_slice(&1_u16.to_be_bytes());
    put_string(&mut output, &value.candidate_id, "candidate_id")?;
    put_bytes(&mut output, &value.raw_path, "raw_path")?;
    output.extend_from_slice(&value.logical_bytes.to_be_bytes());
    match &value.observed_at {
        None => output.push(0),
        Some(timestamp) => {
            output.push(1);
            output.extend_from_slice(&timestamp.seconds.to_be_bytes());
            output.extend_from_slice(&timestamp.nanos.to_be_bytes());
        }
    }
    output.push(value.activity as u8);
    output.push(value.coverage as u8);
    let mut labels: Vec<&str> = value.labels.iter().map(String::as_str).collect();
    labels.sort_unstable_by(|left, right| left.as_bytes().cmp(right.as_bytes()));
    labels.dedup_by(|left, right| left.as_bytes() == right.as_bytes());
    put_u32(&mut output, labels.len(), "labels")?;
    for label in labels {
        put_string(&mut output, label, "label")?;
    }
    Ok(output)
}

fn put_u32(output: &mut Vec<u8>, value: usize, field: &'static str) -> Result<(), CanonicalError> {
    let value = u32::try_from(value).map_err(|_| CanonicalError::FieldTooLong { field })?;
    output.extend_from_slice(&value.to_be_bytes());
    Ok(())
}

fn put_bytes(
    output: &mut Vec<u8>,
    bytes: &[u8],
    field: &'static str,
) -> Result<(), CanonicalError> {
    put_u32(output, bytes.len(), field)?;
    output.extend_from_slice(bytes);
    Ok(())
}

fn put_string(
    output: &mut Vec<u8>,
    value: &str,
    field: &'static str,
) -> Result<(), CanonicalError> {
    put_bytes(output, value.as_bytes(), field)
}
