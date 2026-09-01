use std::fs;
use std::path::PathBuf;

use diskplan_proto::decode_canonical_envelope;
use diskplan_proto::diskplan::v1::{
    Digest256, ExecutionStreamEvent, envelope, execution_stream_event, runtime_event,
};
use diskplan_proto::runtime::{
    MAXIMUM_PLAN_PROJECTION_MANIFEST_BYTES, MAXIMUM_PLAN_PROJECTION_RAW_CHUNK_BYTES,
    MAXIMUM_PLAN_PROJECTION_RECORD_COUNT, PROTOCOL14_MINOR, PROTOCOL15_MINOR,
    decode_and_verify_plan_projection, escape_raw_working_directory,
};
use diskplan_proto::sealed::{
    RuntimeChainVerifier, decode_and_verify_apply_review, decode_and_verify_decision_overlay,
    decode_and_verify_dry_run_projection, decode_and_verify_execution_stream,
};
use prost::Message;
use sha2::{Digest, Sha256};

#[test]
fn swift_runtime_vectors_are_canonical_and_strictly_verified() {
    for name in [
        "empty-batch-dry-run",
        "force-action-execution",
        "git-evidence-action",
        "codex-scope-action",
        "version-survivor-action",
    ] {
        verify_fixture("runtime-v1.5", PROTOCOL15_MINOR, name);
    }

    let accepted = fixture_chain_artifacts("runtime-v1.5", PROTOCOL15_MINOR, "empty-batch-dry-run");
    let foreign =
        fixture_chain_artifacts("runtime-v1.5", PROTOCOL15_MINOR, "force-action-execution");
    let mut chain = RuntimeChainVerifier::new(accepted.plan);
    assert!(chain.verify_overlay(&foreign.overlay).is_err());
    chain.verify_overlay(&accepted.overlay).unwrap();
    assert!(chain.verify_dry_run(&foreign.dry_run).is_err());
    assert!(chain.verify_apply_review(&foreign.apply_review).is_err());
    chain.verify_apply_review(&accepted.apply_review).unwrap();
    assert!(
        chain
            .verify_execution_stream(&foreign.execution_events)
            .is_err()
    );
}

#[test]
fn protocol14_vectors_remain_byte_compatible_but_mutation_is_fail_closed() {
    verify_fixture("runtime-v1.4", PROTOCOL14_MINOR, "empty-batch-dry-run");

    let (chunks, manifest) = fixture_plan_bytes("runtime-v1.4", "force-action-execution");
    assert!(decode_and_verify_plan_projection(PROTOCOL14_MINOR, &chunks, &manifest).is_err());
    assert!(decode_and_verify_plan_projection(PROTOCOL15_MINOR, &chunks, &manifest).is_err());
}

#[test]
fn raw_working_directory_display_is_byte_exact_and_escaped() {
    assert_eq!(
        escape_raw_working_directory(b"/tmp/\\\xff\0"),
        "/tmp/\\\\\\xff\\x00"
    );
}

#[test]
fn preview_bytes_are_bound_across_plan_and_execution_hash_chains() {
    let (mut chunks, manifest) = fixture_plan_bytes("runtime-v1.5", "force-action-execution");
    let mut first_chunk =
        diskplan_proto::diskplan::v1::PlanProjectionChunk::decode(chunks[0].as_slice()).unwrap();
    let record_length = u32::from_be_bytes(
        first_chunk.canonical_record_payload[..4]
            .try_into()
            .unwrap(),
    ) as usize;
    let mut record = diskplan_proto::diskplan::v1::PlanProjectionRecord::decode(
        &first_chunk.canonical_record_payload[4..4 + record_length],
    )
    .unwrap();
    let remaining_records = first_chunk.canonical_record_payload[4 + record_length..].to_vec();
    let Some(diskplan_proto::diskplan::v1::plan_projection_record::Body::Action(action)) =
        record.body.as_mut()
    else {
        panic!("fixture first plan record is not an action")
    };
    action
        .execution_preview
        .as_mut()
        .unwrap()
        .raw_working_directory = Some(b"/changed-plan-cwd".to_vec());
    let encoded_record = record.encode_to_vec();
    first_chunk.canonical_record_payload = (encoded_record.len() as u32)
        .to_be_bytes()
        .into_iter()
        .chain(encoded_record)
        .chain(remaining_records)
        .collect();
    chunks[0] = first_chunk.encode_to_vec();
    assert!(decode_and_verify_plan_projection(PROTOCOL15_MINOR, &chunks, &manifest).is_err());

    let artifacts =
        fixture_chain_artifacts("runtime-v1.5", PROTOCOL15_MINOR, "force-action-execution");
    let mut dry_run =
        diskplan_proto::diskplan::v1::DryRunProjection::decode(artifacts.dry_run.as_slice())
            .unwrap();
    let mut dry_payload = diskplan_proto::diskplan::v1::DryRunProjectionPayload::decode(
        dry_run.canonical_projection_payload.as_slice(),
    )
    .unwrap();
    dry_payload.actions[0]
        .execution_preview
        .as_mut()
        .unwrap()
        .raw_working_directory = Some(b"/changed-dry-cwd".to_vec());
    dry_run.canonical_projection_payload = dry_payload.encode_to_vec();
    assert!(
        decode_and_verify_dry_run_projection(PROTOCOL15_MINOR, &dry_run.encode_to_vec()).is_err()
    );

    let mut apply = diskplan_proto::diskplan::v1::ApplyReviewProjection::decode(
        artifacts.apply_review.as_slice(),
    )
    .unwrap();
    apply.actions[0]
        .execution_preview
        .as_mut()
        .unwrap()
        .path_race = diskplan_proto::diskplan::v1::PathRaceProjection::NoneObserved as i32;
    assert!(decode_and_verify_apply_review(PROTOCOL15_MINOR, &apply.encode_to_vec()).is_err());

    let mut events = artifacts.execution_events.clone();
    let mut warning = events
        .iter_mut()
        .find_map(|bytes| {
            let event = ExecutionStreamEvent::decode(bytes.as_slice()).unwrap();
            matches!(
                event.body.as_ref(),
                Some(execution_stream_event::Body::ForceRequiredWarning(_))
            )
            .then_some((bytes, event))
        })
        .unwrap();
    let Some(execution_stream_event::Body::ForceRequiredWarning(force_warning)) =
        warning.1.body.as_mut()
    else {
        unreachable!()
    };
    force_warning
        .preview
        .as_mut()
        .unwrap()
        .raw_working_directory = Some(b"/changed-warning-cwd".to_vec());
    *warning.0 = warning.1.encode_to_vec();
    reseal_execution_stream(&mut events);
    decode_and_verify_execution_stream(PROTOCOL15_MINOR, &events).unwrap();
    let mut chain = RuntimeChainVerifier::new(artifacts.plan);
    chain.verify_overlay(&artifacts.overlay).unwrap();
    chain.verify_apply_review(&artifacts.apply_review).unwrap();
    assert!(chain.verify_execution_stream(&events).is_err());
}

#[test]
fn canonical_admission_rejects_unknown_fields_at_envelope_and_nested_levels() {
    let frame = fixture_frames("runtime-v1.5", "empty-batch-dry-run").remove(0);
    let mut envelope_unknown = frame[4..].to_vec();
    envelope_unknown.extend_from_slice(&[0x98, 0x06, 0x01]);
    assert!(decode_canonical_envelope(&envelope_unknown).is_err());

    let artifacts =
        fixture_chain_artifacts("runtime-v1.5", PROTOCOL15_MINOR, "force-action-execution");
    let mut overlay_unknown = artifacts.overlay;
    overlay_unknown.extend_from_slice(&[0x98, 0x06, 0x01]);
    assert!(decode_and_verify_decision_overlay(&overlay_unknown).is_err());

    let mut dry_run =
        diskplan_proto::diskplan::v1::DryRunProjection::decode(artifacts.dry_run.as_slice())
            .unwrap();
    dry_run
        .canonical_projection_payload
        .extend_from_slice(&[0x98, 0x06, 0x01]);
    assert!(
        decode_and_verify_dry_run_projection(PROTOCOL15_MINOR, &dry_run.encode_to_vec()).is_err()
    );
}

#[test]
fn execution_force_warning_omission_and_duplication_are_rejected() {
    let artifacts =
        fixture_chain_artifacts("runtime-v1.5", PROTOCOL15_MINOR, "force-action-execution");
    for mutation in ["missing", "duplicate", "extra"] {
        let mut chain = RuntimeChainVerifier::new(artifacts.plan.clone());
        chain.verify_overlay(&artifacts.overlay).unwrap();
        chain.verify_apply_review(&artifacts.apply_review).unwrap();
        let mut events = artifacts.execution_events.clone();
        let warning_index = events
            .iter()
            .position(|bytes| {
                let event = diskplan_proto::diskplan::v1::ExecutionStreamEvent::decode(
                    bytes.as_slice(),
                )
                .unwrap();
                matches!(
                    event.body,
                    Some(
                        diskplan_proto::diskplan::v1::execution_stream_event::Body::ForceRequiredWarning(_)
                    )
                )
            })
            .unwrap();
        match mutation {
            "missing" => {
                events.remove(warning_index);
            }
            "duplicate" => events.insert(warning_index + 1, events[warning_index].clone()),
            "extra" => {
                let mut extra =
                    ExecutionStreamEvent::decode(events[warning_index].as_slice()).unwrap();
                let Some(execution_stream_event::Body::ForceRequiredWarning(warning)) =
                    extra.body.as_mut()
                else {
                    unreachable!()
                };
                warning.action_id.as_mut().unwrap().value = vec![0x99; 32];
                events.insert(warning_index + 1, extra.encode_to_vec());
            }
            _ => unreachable!(),
        }
        reseal_execution_stream(&mut events);
        decode_and_verify_execution_stream(PROTOCOL15_MINOR, &events).unwrap();
        assert!(chain.verify_execution_stream(&events).is_err());
    }
}

#[test]
fn raw_plan_admission_rejects_oversized_inputs_before_decode() {
    assert!(
        decode_and_verify_plan_projection(
            PROTOCOL15_MINOR,
            &vec![Vec::new(); MAXIMUM_PLAN_PROJECTION_RECORD_COUNT + 1],
            &[]
        )
        .is_err()
    );
    assert!(
        decode_and_verify_plan_projection(
            PROTOCOL15_MINOR,
            &[],
            &vec![0; MAXIMUM_PLAN_PROJECTION_MANIFEST_BYTES + 1]
        )
        .is_err()
    );
    assert!(
        decode_and_verify_plan_projection(
            PROTOCOL15_MINOR,
            &[vec![0; MAXIMUM_PLAN_PROJECTION_RAW_CHUNK_BYTES + 1]],
            &[]
        )
        .is_err()
    );
}

fn verify_fixture(schema: &str, protocol_minor: u32, name: &str) {
    let mut chunks: Vec<Vec<u8>> = Vec::new();
    let mut execution_events = Vec::new();
    let mut plan_reference = None;
    let mut overlay_reference = None;
    let mut chain = None;
    let mut saw_dry_run = false;
    let mut saw_apply_review = false;

    for frame in fixture_frames(schema, name) {
        let payload_length = u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize;
        assert_eq!(payload_length, frame.len() - 4);
        let payload = &frame[4..];
        let envelope = decode_canonical_envelope(payload)
            .unwrap()
            .envelope()
            .clone();
        let Some(envelope::Body::RuntimeEvent(event)) = envelope.body else {
            panic!("fixture contains a non-runtime event")
        };
        match event.body.unwrap() {
            runtime_event::Body::PlanProjectionChunk(chunk) => chunks.push(chunk.encode_to_vec()),
            runtime_event::Body::PlanProjection(projection) => {
                let manifest = projection.manifest.unwrap();
                let verified = decode_and_verify_plan_projection(
                    protocol_minor,
                    &chunks,
                    &manifest.encode_to_vec(),
                )
                .unwrap();
                assert_eq!(verified.manifest(), &manifest);
                chain = Some(RuntimeChainVerifier::new(verified));
                plan_reference = Some((
                    manifest.projection_id.unwrap().value,
                    manifest.plan_id.unwrap().value,
                    manifest.plan_sha256.unwrap().value,
                    manifest.evidence_id.unwrap().value,
                    manifest.evidence_sha256.unwrap().value,
                    manifest.scan_session_id.unwrap().value,
                    manifest.scan_checkpoint_id.unwrap().value,
                    manifest.scan_checkpoint_evidence_sha256.unwrap().value,
                ));
            }
            runtime_event::Body::DecisionOverlayAcknowledged(overlay) => {
                let encoded = overlay.encode_to_vec();
                decode_and_verify_decision_overlay(&encoded).unwrap();
                chain.as_mut().unwrap().verify_overlay(&encoded).unwrap();
                let plan = plan_reference.as_ref().unwrap();
                assert_eq!(overlay.projection_id.as_ref().unwrap().value, plan.0);
                assert_eq!(overlay.plan_id.as_ref().unwrap().value, plan.1);
                assert_eq!(overlay.plan_sha256.as_ref().unwrap().value, plan.2);
                assert_eq!(overlay.evidence_id.as_ref().unwrap().value, plan.3);
                assert_eq!(overlay.evidence_sha256.as_ref().unwrap().value, plan.4);
                assert_eq!(overlay.scan_session_id.as_ref().unwrap().value, plan.5);
                assert_eq!(overlay.scan_checkpoint_id.as_ref().unwrap().value, plan.6);
                assert_eq!(
                    overlay
                        .scan_checkpoint_evidence_sha256
                        .as_ref()
                        .unwrap()
                        .value,
                    plan.7
                );
                overlay_reference = Some((
                    overlay.overlay_id.unwrap().value,
                    overlay.revision,
                    overlay.overlay_sha256.unwrap().value,
                    overlay.selected_action_count,
                ));
            }
            runtime_event::Body::DryRunProjection(projection) => {
                let encoded = projection.encode_to_vec();
                let verified =
                    decode_and_verify_dry_run_projection(protocol_minor, &encoded).unwrap();
                chain.as_ref().unwrap().verify_dry_run(&encoded).unwrap();
                let overlay = overlay_reference.as_ref().unwrap();
                assert_eq!(
                    verified.manifest().overlay_id.as_ref().unwrap().value,
                    overlay.0
                );
                assert_eq!(verified.manifest().overlay_revision, overlay.1);
                assert_eq!(
                    verified.manifest().overlay_sha256.as_ref().unwrap().value,
                    overlay.2
                );
                assert_eq!(verified.manifest().selected_action_count, overlay.3);
                let mut forged = projection;
                forged.manifest.as_mut().unwrap().selected_action_count += 1;
                assert!(
                    decode_and_verify_dry_run_projection(protocol_minor, &forged.encode_to_vec())
                        .is_err()
                );
                saw_dry_run = true;
            }
            runtime_event::Body::ApplyReviewProjection(projection) => {
                decode_and_verify_apply_review(protocol_minor, &projection.encode_to_vec())
                    .unwrap();
                chain
                    .as_mut()
                    .unwrap()
                    .verify_apply_review(&projection.encode_to_vec())
                    .unwrap();
                let mut forged = projection;
                forged.overlay_revision += 1;
                assert!(
                    decode_and_verify_apply_review(protocol_minor, &forged.encode_to_vec())
                        .is_err()
                );
                saw_apply_review = true;
            }
            runtime_event::Body::ExecutionStreamEvent(event) => {
                execution_events.push(event.encode_to_vec());
                if matches!(
                    event.body,
                    Some(
                        diskplan_proto::diskplan::v1::execution_stream_event::Body::ApplyFinished(
                            _
                        )
                    )
                ) {
                    decode_and_verify_execution_stream(protocol_minor, &execution_events).unwrap();
                    chain
                        .as_mut()
                        .unwrap()
                        .verify_execution_stream(&execution_events)
                        .unwrap();
                    assert!(
                        chain
                            .as_mut()
                            .unwrap()
                            .verify_execution_stream(&execution_events)
                            .is_err()
                    );
                    let mut forged = execution_events.clone();
                    *forged.last_mut().unwrap().last_mut().unwrap() ^= 1;
                    assert!(decode_and_verify_execution_stream(protocol_minor, &forged).is_err());
                }
            }
            runtime_event::Body::BuildPlanAccepted(_) => {}
            other => panic!("unexpected runtime fixture event: {other:?}"),
        }
    }
    assert!(plan_reference.is_some());
    assert!(overlay_reference.is_some());
    assert!(saw_dry_run);
    assert!(saw_apply_review);
    assert!(!execution_events.is_empty());
}

struct FixtureChainArtifacts {
    plan: diskplan_proto::runtime::VerifiedPlanProjection,
    overlay: Vec<u8>,
    dry_run: Vec<u8>,
    apply_review: Vec<u8>,
    execution_events: Vec<Vec<u8>>,
}

fn fixture_chain_artifacts(schema: &str, protocol_minor: u32, name: &str) -> FixtureChainArtifacts {
    let mut chunks = Vec::new();
    let mut plan = None;
    let mut overlay = None;
    let mut dry_run = None;
    let mut apply_review = None;
    let mut execution_events = Vec::new();
    for frame in fixture_frames(schema, name) {
        let payload = &frame[4..];
        let envelope = decode_canonical_envelope(payload)
            .unwrap()
            .envelope()
            .clone();
        let Some(envelope::Body::RuntimeEvent(event)) = envelope.body else {
            continue;
        };
        match event.body.unwrap() {
            runtime_event::Body::PlanProjectionChunk(chunk) => chunks.push(chunk.encode_to_vec()),
            runtime_event::Body::PlanProjection(projection) => {
                let manifest = projection.manifest.unwrap();
                plan = Some(
                    decode_and_verify_plan_projection(
                        protocol_minor,
                        &chunks,
                        &manifest.encode_to_vec(),
                    )
                    .unwrap(),
                );
            }
            runtime_event::Body::DecisionOverlayAcknowledged(value) => {
                let encoded = value.encode_to_vec();
                decode_and_verify_decision_overlay(&encoded).unwrap();
                overlay = Some(encoded);
            }
            runtime_event::Body::DryRunProjection(value) => {
                let encoded = value.encode_to_vec();
                decode_and_verify_dry_run_projection(protocol_minor, &encoded).unwrap();
                dry_run = Some(encoded);
            }
            runtime_event::Body::ApplyReviewProjection(value) => {
                let encoded = value.encode_to_vec();
                decode_and_verify_apply_review(protocol_minor, &encoded).unwrap();
                apply_review = Some(encoded);
            }
            runtime_event::Body::ExecutionStreamEvent(value) => {
                execution_events.push(value.encode_to_vec());
            }
            _ => {}
        }
    }
    decode_and_verify_execution_stream(protocol_minor, &execution_events).unwrap();
    FixtureChainArtifacts {
        plan: plan.unwrap(),
        overlay: overlay.unwrap(),
        dry_run: dry_run.unwrap(),
        apply_review: apply_review.unwrap(),
        execution_events,
    }
}

fn fixture_frames(schema: &str, name: &str) -> Vec<Vec<u8>> {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../../../proto/fixtures")
        .join(schema)
        .join(format!("{name}.frames.hex"));
    fs::read_to_string(path)
        .unwrap()
        .lines()
        .filter(|line| !line.is_empty())
        .map(|line| hex::decode(line).unwrap())
        .collect()
}

fn fixture_plan_bytes(schema: &str, name: &str) -> (Vec<Vec<u8>>, Vec<u8>) {
    let mut chunks = Vec::new();
    for frame in fixture_frames(schema, name) {
        let envelope = decode_canonical_envelope(&frame[4..])
            .unwrap()
            .envelope()
            .clone();
        let Some(envelope::Body::RuntimeEvent(event)) = envelope.body else {
            continue;
        };
        match event.body.unwrap() {
            runtime_event::Body::PlanProjectionChunk(chunk) => chunks.push(chunk.encode_to_vec()),
            runtime_event::Body::PlanProjection(projection) => {
                return (chunks, projection.manifest.unwrap().encode_to_vec());
            }
            _ => {}
        }
    }
    panic!("fixture contains no plan projection")
}

fn reseal_execution_stream(canonical_events: &mut Vec<Vec<u8>>) {
    let mut events: Vec<ExecutionStreamEvent> = canonical_events
        .iter()
        .map(|bytes| ExecutionStreamEvent::decode(bytes.as_slice()).unwrap())
        .collect();
    for (index, event) in events.iter_mut().enumerate() {
        event.execution_event_index = index as u64 + 1;
    }
    let terminal_index = events.len() - 1;
    let event_count = events.len() as u64;
    let Some(execution_stream_event::Body::ApplyFinished(terminal)) =
        events[terminal_index].body.as_mut()
    else {
        panic!("fixture execution stream omitted terminal")
    };
    terminal.event_count = event_count;
    terminal.execution_record_sha256 = None;

    let mut candidate = 0_u64;
    let mut stable_canonical = None;
    for _ in 0..10 {
        let Some(execution_stream_event::Body::ApplyFinished(terminal)) =
            events[terminal_index].body.as_mut()
        else {
            unreachable!()
        };
        terminal.encoded_event_bytes = candidate;
        terminal.execution_record_sha256 = None;
        let bytes = canonical_execution_bytes(&events);
        let next = bytes.len() as u64;
        if next == candidate {
            stable_canonical = Some(bytes);
            break;
        }
        candidate = next;
    }
    let canonical = stable_canonical.expect("execution byte count did not stabilize");
    let digest = Sha256::digest(
        [
            b"diskplan/execution-record/v1\0".as_slice(),
            canonical.as_slice(),
        ]
        .concat(),
    );
    let Some(execution_stream_event::Body::ApplyFinished(terminal)) =
        events[terminal_index].body.as_mut()
    else {
        unreachable!()
    };
    terminal.execution_record_sha256 = Some(Digest256 {
        value: digest.to_vec(),
    });
    *canonical_events = events
        .into_iter()
        .map(|event| event.encode_to_vec())
        .collect();
}

fn canonical_execution_bytes(events: &[ExecutionStreamEvent]) -> Vec<u8> {
    let mut output = Vec::new();
    for (index, event) in events.iter().enumerate() {
        let mut event = event.clone();
        if index + 1 == events.len() {
            let Some(execution_stream_event::Body::ApplyFinished(terminal)) = event.body.as_mut()
            else {
                panic!("fixture execution stream omitted terminal")
            };
            terminal.execution_record_sha256 = None;
        }
        let bytes = event.encode_to_vec();
        output.extend_from_slice(&(bytes.len() as u32).to_be_bytes());
        output.extend_from_slice(&bytes);
    }
    output
}
