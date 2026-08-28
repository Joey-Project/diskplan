use std::fs;
use std::os::unix::ffi::OsStrExt;
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Child, ChildStdin, Command, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::{Duration, Instant};

use diskplan::{ClientError, EngineSession, handshake_with_engine};
use diskplan_core::framing::{FrameError, read_frame, write_frame};
use diskplan_core::handshake::{AcceptedHandshakeError, rust_client_hello};
use diskplan_proto::diskplan::v1::{
    BusinessEnvelope, ControlAccepted, ControlRejectCode, EngineEvent, Envelope, HelloAccepted,
    HelloRejected, ProtocolVersion, RejectCode, ScanControlKind, ScanControlRequest,
    ScanMachineState, ScanProgress, ScanSetupRejectCode, ScanState, StartScanRequest, engine_event,
    envelope,
};
use prost::Message;
use tempfile::TempDir;

const TEST_TIMEOUT: Duration = Duration::from_secs(10);
const PROCESS_GROUP_TEST_TIMEOUT: Duration = Duration::from_secs(2);
const TEST_OPERATION_BOUND: Duration = Duration::from_secs(15);
const SHUTDOWN_BOUND: Duration = Duration::from_secs(5);

#[test]
#[ignore = "requires DISKPLAN_ENGINE_BIN; run scripts/test-cross-language.sh"]
fn rust_client_negotiates_and_keeps_swift_engine_ready() {
    let engine = required_engine_path();
    let mut session = EngineSession::connect(&engine).unwrap();
    assert_eq!(
        session.accepted().negotiated_capabilities,
        [
            "canonical-binary-v1",
            "framing-v1",
            "plan-bootstrap",
            "raw-path-bytes-v1",
            "scan-control-v1",
            "scan-stream-v1"
        ]
    );
    let response = session.request_business(2, "scan", Vec::new()).unwrap();
    let Some(envelope::Body::HelloRejected(rejected)) = response.body else {
        panic!("expected typed unsupported rejection");
    };
    assert_eq!(rejected.code, RejectCode::BusinessUnsupported as i32);
    session.shutdown().unwrap();
}

#[test]
#[ignore = "requires DISKPLAN_ENGINE_BIN; run scripts/test-cross-language.sh"]
fn swift_engine_rejects_pre_handshake_major_and_capability_errors() {
    let engine = required_engine_path();

    let response = exchange_once(
        &engine,
        Envelope {
            sequence: 7,
            body: Some(envelope::Body::Business(BusinessEnvelope {
                r#type: "scan".into(),
                payload: Vec::new(),
            })),
        },
    );
    assert_rejection(response, RejectCode::BusinessBeforeHandshake);

    let mut hello = rust_client_hello();
    hello.version = Some(ProtocolVersion { major: 2, minor: 0 });
    let response = exchange_once(
        &engine,
        Envelope {
            sequence: 8,
            body: Some(envelope::Body::Hello(hello)),
        },
    );
    assert_rejection(response, RejectCode::ProtocolMajorMismatch);

    let mut hello = rust_client_hello();
    hello.required_capabilities.push("not-offered".into());
    let response = exchange_once(
        &engine,
        Envelope {
            sequence: 9,
            body: Some(envelope::Body::Hello(hello)),
        },
    );
    assert_rejection(response, RejectCode::MissingRequiredCapability);
}

#[test]
#[ignore = "requires DISKPLAN_ENGINE_BIN; run scripts/test-cross-language.sh"]
fn swift_engine_gates_scan_stream_on_negotiated_capabilities() {
    let engine = required_engine_path();
    let mut child = Command::new(&engine)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (sender, frames) = mpsc::channel();
    thread::spawn(move || {
        loop {
            let frame = read_frame(&mut stdout);
            let terminal = !matches!(frame, Ok(Some(_)));
            if sender.send(frame).is_err() || terminal {
                break;
            }
        }
    });

    let mut hello = rust_client_hello();
    hello.optional_capabilities = vec!["scan-control-v1".into()];
    send_raw_envelope(
        &mut stdin,
        Envelope {
            sequence: 1,
            body: Some(envelope::Body::Hello(hello)),
        },
    );
    assert!(matches!(
        receive_raw_envelope(&frames).body,
        Some(envelope::Body::HelloAccepted(_))
    ));

    send_raw_envelope(
        &mut stdin,
        Envelope {
            sequence: 10,
            body: Some(envelope::Body::StartScanRequest(StartScanRequest {
                request_id: 10,
                profile: "standard".into(),
                ..Default::default()
            })),
        },
    );
    assert_control_rejected_with_setup(
        receive_raw_engine_event(&frames),
        10,
        ControlRejectCode::Unavailable,
        ScanSetupRejectCode::CapabilityNotNegotiated,
    );

    send_raw_envelope(
        &mut stdin,
        Envelope {
            sequence: 11,
            body: Some(envelope::Body::Business(BusinessEnvelope {
                r#type: "still-ready".into(),
                payload: Vec::new(),
            })),
        },
    );
    let response = (0..10_000)
        .find_map(|_| {
            let response = receive_raw_envelope(&frames);
            matches!(response.body, Some(envelope::Body::HelloRejected(_))).then_some(response)
        })
        .expect("business rejection must remain observable amid natural scan events");
    assert!(matches!(
        response.body,
        Some(envelope::Body::HelloRejected(_))
    ));
    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
#[ignore = "requires DISKPLAN_ENGINE_BIN; run scripts/test-cross-language.sh"]
fn swift_engine_reports_typed_scan_setup_rejections() {
    let engine = required_engine_path();
    let mut session = EngineSession::connect(&engine).unwrap();
    session
        .send_start_scan_request(StartScanRequest {
            request_id: 10,
            profile: "standard".into(),
            roots: vec![EngineSession::scan_root(
                "relative",
                b"not/absolute".to_vec(),
            )],
            maximum_duration_millis: 0,
            batch_size: 1,
        })
        .unwrap();

    assert_control_rejected_with_setup(
        read_until_event(&mut session, |event| event.request_id == 10),
        10,
        ControlRejectCode::MalformedRequest,
        ScanSetupRejectCode::InvalidRoot,
    );

    let lexical_aliases: [&[u8]; 7] = [
        b"//",
        b"/tmp/",
        b"/tmp//child",
        b"/tmp/./child",
        b"/tmp/../child",
        b"/./tmp",
        b"/../tmp",
    ];
    for (offset, raw_path) in lexical_aliases.into_iter().enumerate() {
        let request_id = 11 + offset as u64;
        session
            .send_start_scan_request(StartScanRequest {
                request_id,
                profile: "standard".into(),
                roots: vec![EngineSession::scan_root(
                    format!("alias-{offset}"),
                    raw_path.to_vec(),
                )],
                maximum_duration_millis: 0,
                batch_size: 1,
            })
            .unwrap();
        assert_control_rejected_with_setup(
            read_until_event(&mut session, |event| event.request_id == request_id),
            request_id,
            ControlRejectCode::MalformedRequest,
            ScanSetupRejectCode::InvalidRoot,
        );
    }

    let oversized_roots = (0..17)
        .map(|index| {
            let mut raw_path = vec![b'a'; 256 * 1_024];
            raw_path[0] = b'/';
            EngineSession::scan_root(format!("oversized-{index}"), raw_path)
        })
        .collect();
    session
        .send_start_scan_request(StartScanRequest {
            request_id: 20,
            profile: "standard".into(),
            roots: oversized_roots,
            maximum_duration_millis: 0,
            batch_size: 1,
        })
        .unwrap();
    assert_control_rejected_with_setup(
        read_until_event(&mut session, |event| event.request_id == 20),
        20,
        ControlRejectCode::MalformedRequest,
        ScanSetupRejectCode::InvalidBudget,
    );

    let response = session
        .request_business(21, "still-ready", Vec::new())
        .unwrap();
    assert!(matches!(
        response.body,
        Some(envelope::Body::HelloRejected(_))
    ));
    session.shutdown().unwrap();

    let mut root_session = EngineSession::connect(&engine).unwrap();
    root_session
        .send_start_scan_request(StartScanRequest {
            request_id: 30,
            profile: "quick".into(),
            roots: vec![EngineSession::scan_root("filesystem-root", b"/".to_vec())],
            maximum_duration_millis: 0,
            batch_size: 1,
        })
        .unwrap();
    assert_control_accepted(
        read_until_event(&mut root_session, |event| event.request_id == 30),
        30,
        ScanControlKind::StartScan,
        ScanState::Running,
    );
    let finalized = read_until_event(&mut root_session, |event| {
        matches!(event.body, Some(engine_event::Body::ScanFinalized(_)))
    });
    let Some(engine_event::Body::ScanFinalized(finalized)) = finalized.body else {
        unreachable!();
    };
    assert_eq!(
        finalized
            .checkpoint
            .expect("filesystem-root final checkpoint")
            .resolved_roots[0]
            .raw_absolute_path,
        b"/"
    );
    root_session.shutdown().unwrap();
}

#[test]
#[ignore = "requires DISKPLAN_ENGINE_BIN; run scripts/test-cross-language.sh"]
fn swift_engine_rejects_legacy_plan_control_without_plan_events() {
    let engine = required_engine_path();
    let fixture = TempDir::new().unwrap();
    for index in 0..900 {
        fs::write(
            fixture.path().join(format!("entry-{index:04}")),
            b"evidence",
        )
        .unwrap();
    }
    let mut session = EngineSession::connect(&engine).unwrap();
    session
        .send_start_scan_request(StartScanRequest {
            request_id: 20,
            profile: "standard".into(),
            roots: vec![EngineSession::scan_root(
                "fixture",
                fixture.path().as_os_str().as_bytes().to_vec(),
            )],
            maximum_duration_millis: 0,
            batch_size: 1,
        })
        .unwrap();
    session
        .send_scan_control(21, ScanControlKind::PauseScan)
        .unwrap();
    assert_control_accepted(
        read_until_event(&mut session, |event| event.request_id == 20),
        20,
        ScanControlKind::StartScan,
        ScanState::Running,
    );
    assert_control_accepted(
        read_until_event(&mut session, |event| event.request_id == 21),
        21,
        ScanControlKind::PauseScan,
        ScanState::Paused,
    );

    session
        .send_scan_control(22, ScanControlKind::PauseAndBuildProvisionalPlan)
        .unwrap();
    assert_control_rejected(
        read_until_event(&mut session, |event| event.request_id == 22),
        22,
        ControlRejectCode::Unavailable,
    );
    session
        .send_scan_control(23, ScanControlKind::CancelScan)
        .unwrap();
    assert_control_accepted(
        read_until_event(&mut session, |event| event.request_id == 23),
        23,
        ScanControlKind::CancelScan,
        ScanState::Cancelling,
    );
    let mut saw_finalized = false;
    loop {
        let event = session.read_engine_event().unwrap();
        match event.body {
            Some(engine_event::Body::ProvisionalPlanReady(_))
            | Some(engine_event::Body::ProvisionalPlanInvalidated(_)) => {
                panic!("Phase 1 emitted a plan event")
            }
            Some(engine_event::Body::ScanFinalized(_)) => saw_finalized = true,
            Some(engine_event::Body::ScanCancelled(_)) => break,
            _ => {}
        }
    }
    assert!(saw_finalized);
    session.shutdown().unwrap();
}

#[test]
#[ignore = "requires DISKPLAN_ENGINE_BIN; run scripts/test-cross-language.sh"]
fn rust_client_drives_swift_scan_control_protocol() {
    let engine = required_engine_path();
    let fixture = TempDir::new().unwrap();
    for index in 0..900 {
        fs::write(
            fixture.path().join(format!("entry-{index:04}")),
            b"evidence",
        )
        .unwrap();
    }
    let mut session = EngineSession::connect(&engine).unwrap();
    session
        .send_start_scan_request(StartScanRequest {
            request_id: 100,
            profile: "standard".into(),
            roots: vec![EngineSession::scan_root(
                "fixture",
                fixture.path().as_os_str().as_bytes().to_vec(),
            )],
            maximum_duration_millis: 0,
            batch_size: 1,
        })
        .unwrap();
    session
        .send_scan_control(101, ScanControlKind::PauseScan)
        .unwrap();

    assert_control_accepted(
        read_until_event(&mut session, |event| {
            matches!(event.body, Some(engine_event::Body::ControlAccepted(_)))
                && event.request_id == 100
        }),
        100,
        ScanControlKind::StartScan,
        ScanState::Running,
    );
    assert_control_accepted(
        read_until_event(&mut session, |event| event.request_id == 101),
        101,
        ScanControlKind::PauseScan,
        ScanState::Paused,
    );

    session
        .send_scan_control(102, ScanControlKind::CheckpointProvisionalEvidence)
        .unwrap();
    assert_control_accepted(
        read_until_event(&mut session, |event| {
            matches!(event.body, Some(engine_event::Body::ControlAccepted(_)))
                && event.request_id == 102
        }),
        102,
        ScanControlKind::CheckpointProvisionalEvidence,
        ScanState::Paused,
    );
    let checkpoint_event = read_until_event(&mut session, |event| {
        matches!(event.body, Some(engine_event::Body::ScanCheckpointReady(_)))
    });
    assert_eq!(checkpoint_event.request_id, 0);
    assert!(!checkpoint_event.scan_session_id.is_empty());
    let Some(engine_event::Body::ScanCheckpointReady(ready)) = checkpoint_event.body else {
        unreachable!();
    };
    let checkpoint = ready.checkpoint.expect("checkpoint evidence");
    assert!(checkpoint.resumable_in_process);
    assert!(checkpoint.provisional);
    assert_eq!(
        checkpoint.progress.as_ref().unwrap().candidates,
        0,
        "Phase 1 must not classify candidates"
    );
    assert_eq!(
        checkpoint.progress.as_ref().unwrap().reclaim_estimate_bytes,
        0,
        "Phase 1 must not project a plan-level reclaim estimate"
    );
    assert_eq!(checkpoint.resolved_roots.len(), 1);
    assert_eq!(
        checkpoint.resolved_roots[0].raw_absolute_path,
        fixture.path().as_os_str().as_bytes()
    );
    assert_eq!(
        checkpoint
            .collector_configuration
            .unwrap()
            .process_activity_collector_id,
        "precollected-or-unavailable"
    );
    assert!(!checkpoint.apfs_snapshots.unwrap().known);

    session
        .send_scan_control(103, ScanControlKind::CheckpointScan)
        .unwrap();
    assert_control_accepted(
        read_until_event(&mut session, |event| {
            matches!(event.body, Some(engine_event::Body::ControlAccepted(_)))
                && event.request_id == 103
        }),
        103,
        ScanControlKind::CheckpointScan,
        ScanState::Paused,
    );
    let checkpoint_event = read_until_event(&mut session, |event| {
        matches!(event.body, Some(engine_event::Body::ScanCheckpointReady(_)))
    });
    let Some(engine_event::Body::ScanCheckpointReady(ready)) = checkpoint_event.body else {
        unreachable!();
    };
    assert!(!ready.checkpoint.unwrap().provisional);

    session
        .send_scan_control(104, ScanControlKind::FinalizePartialScan)
        .unwrap();

    assert_control_accepted(
        read_until_event(&mut session, |event| {
            matches!(event.body, Some(engine_event::Body::ControlAccepted(_)))
                && event.request_id == 104
        }),
        104,
        ScanControlKind::FinalizePartialScan,
        ScanState::FinalizingPartial,
    );
    let finalized_event = read_until_event(&mut session, |event| {
        matches!(event.body, Some(engine_event::Body::ScanFinalized(_)))
    });
    assert_eq!(finalized_event.request_id, 0);
    let Some(engine_event::Body::ScanFinalized(finalized)) = finalized_event.body else {
        unreachable!();
    };
    assert_eq!(
        finalized.checkpoint.unwrap().machine_state,
        ScanMachineState::Partial as i32,
        "explicit finalization must remain typed partial evidence"
    );

    session
        .send_scan_control(105, ScanControlKind::CheckpointScan)
        .unwrap();
    assert_control_rejected(
        read_until_event(&mut session, |event| event.request_id == 105),
        105,
        ControlRejectCode::InvalidState,
    );

    let response = session
        .request_business(106, "still-ready", Vec::new())
        .unwrap();
    assert!(matches!(
        response.body,
        Some(envelope::Body::HelloRejected(_))
    ));
    session.shutdown().unwrap();

    let mut resume_session = EngineSession::connect(&engine).unwrap();
    resume_session
        .send_start_scan_request(StartScanRequest {
            request_id: 200,
            profile: "standard".into(),
            roots: vec![EngineSession::scan_root(
                "resume-fixture",
                fixture.path().as_os_str().as_bytes().to_vec(),
            )],
            maximum_duration_millis: 0,
            batch_size: 1,
        })
        .unwrap();
    resume_session
        .send_scan_control(201, ScanControlKind::PauseScan)
        .unwrap();
    assert_control_accepted(
        read_until_event(&mut resume_session, |event| event.request_id == 200),
        200,
        ScanControlKind::StartScan,
        ScanState::Running,
    );
    assert_control_accepted(
        read_until_event(&mut resume_session, |event| event.request_id == 201),
        201,
        ScanControlKind::PauseScan,
        ScanState::Paused,
    );
    resume_session
        .send_scan_control(202, ScanControlKind::ResumeScan)
        .unwrap();
    assert_control_accepted(
        read_until_event(&mut resume_session, |event| event.request_id == 202),
        202,
        ScanControlKind::ResumeScan,
        ScanState::Running,
    );
    let finalized = read_until_event(&mut resume_session, |event| {
        matches!(event.body, Some(engine_event::Body::ScanFinalized(_)))
    });
    assert_eq!(finalized.request_id, 0);
    let response = resume_session
        .request_business(203, "still-ready-after-resume", Vec::new())
        .unwrap();
    assert!(matches!(
        response.body,
        Some(envelope::Body::HelloRejected(_))
    ));
    resume_session.shutdown().unwrap();
}

#[test]
#[ignore = "requires DISKPLAN_ENGINE_BIN; run scripts/test-cross-language.sh"]
fn rust_client_cancels_scan_with_final_evidence_and_keeps_session_ready() {
    let engine = required_engine_path();
    let fixture = TempDir::new().unwrap();
    for index in 0..900 {
        fs::write(
            fixture.path().join(format!("cancel-{index:04}")),
            b"evidence",
        )
        .unwrap();
    }
    let mut session = EngineSession::connect(&engine).unwrap();
    session
        .send_start_scan_request(StartScanRequest {
            request_id: 200,
            profile: "standard".into(),
            roots: vec![EngineSession::scan_root(
                "cancel-fixture",
                fixture.path().as_os_str().as_bytes().to_vec(),
            )],
            maximum_duration_millis: 0,
            batch_size: 1,
        })
        .unwrap();
    session
        .send_scan_control(201, ScanControlKind::CancelScan)
        .unwrap();
    assert_control_accepted(
        read_until_event(&mut session, |event| event.request_id == 200),
        200,
        ScanControlKind::StartScan,
        ScanState::Running,
    );
    assert_control_accepted(
        read_until_event(&mut session, |event| {
            event.request_id == 201
                && matches!(event.body, Some(engine_event::Body::ControlAccepted(_)))
        }),
        201,
        ScanControlKind::CancelScan,
        ScanState::Cancelling,
    );
    let finalized = read_until_event(&mut session, |event| {
        matches!(event.body, Some(engine_event::Body::ScanFinalized(_)))
    });
    let Some(engine_event::Body::ScanFinalized(finalized)) = finalized.body else {
        unreachable!();
    };
    assert_eq!(
        finalized.checkpoint.unwrap().machine_state,
        ScanMachineState::Cancelled as i32
    );
    let cancelled = read_until_event(&mut session, |event| {
        matches!(event.body, Some(engine_event::Body::ScanCancelled(_)))
    });
    assert_eq!(cancelled.request_id, 0);

    let response = session
        .request_business(202, "still-ready", Vec::new())
        .unwrap();
    assert!(matches!(
        response.body,
        Some(envelope::Body::HelloRejected(_))
    ));
    session.shutdown().unwrap();
}

#[test]
#[ignore = "requires DISKPLAN_ENGINE_BIN; run scripts/test-cross-language.sh"]
fn shutdown_drains_cancelled_terminal_tail_after_finalized_evidence() {
    let engine = required_engine_path();
    let fixture = TempDir::new().unwrap();
    for index in 0..900 {
        fs::write(fixture.path().join(format!("tail-{index:04}")), b"evidence").unwrap();
    }
    let mut session = EngineSession::connect(&engine).unwrap();
    session
        .send_start_scan_request(StartScanRequest {
            request_id: 210,
            profile: "standard".into(),
            roots: vec![EngineSession::scan_root(
                "shutdown-tail-fixture",
                fixture.path().as_os_str().as_bytes().to_vec(),
            )],
            maximum_duration_millis: 0,
            batch_size: 1,
        })
        .unwrap();
    session
        .send_scan_control(211, ScanControlKind::CancelScan)
        .unwrap();
    assert_control_accepted(
        read_until_event(&mut session, |event| event.request_id == 210),
        210,
        ScanControlKind::StartScan,
        ScanState::Running,
    );
    assert_control_accepted(
        read_until_event(&mut session, |event| {
            event.request_id == 211
                && matches!(event.body, Some(engine_event::Body::ControlAccepted(_)))
        }),
        211,
        ScanControlKind::CancelScan,
        ScanState::Cancelling,
    );
    let finalized = read_until_event(&mut session, |event| {
        matches!(event.body, Some(engine_event::Body::ScanFinalized(_)))
    });
    let Some(engine_event::Body::ScanFinalized(finalized)) = finalized.body else {
        unreachable!();
    };
    assert_eq!(
        finalized.checkpoint.unwrap().machine_state,
        ScanMachineState::Cancelled as i32
    );

    // Deliberately leave ScanCancelled in the capacity-one decoder and close stdin as q does.
    // Shutdown must validate that single ordered terminal tail frame while waiting for clean EOF.
    session.shutdown().unwrap();
}

#[test]
#[ignore = "requires DISKPLAN_ENGINE_BIN; run scripts/test-cross-language.sh"]
fn swift_engine_orders_root_failures_deterministically() {
    let engine = required_engine_path();
    let fixture = TempDir::new().unwrap();
    let mut session = EngineSession::connect(&engine).unwrap();
    let root = |root_id: &str, leaf: &str| {
        EngineSession::scan_root(
            root_id,
            fixture.path().join(leaf).as_os_str().as_bytes().to_vec(),
        )
    };
    session
        .send_start_scan_request(StartScanRequest {
            request_id: 300,
            profile: "standard".into(),
            roots: vec![
                root("z-root", "3"),
                root("a-root", "1"),
                root("m-root", "2"),
            ],
            maximum_duration_millis: 0,
            batch_size: 1,
        })
        .unwrap();

    let finalized = read_until_event(&mut session, |event| {
        matches!(event.body, Some(engine_event::Body::ScanFinalized(_)))
    });
    let Some(engine_event::Body::ScanFinalized(finalized)) = finalized.body else {
        unreachable!();
    };
    let checkpoint = finalized.checkpoint.expect("finalized checkpoint evidence");
    assert_eq!(
        checkpoint
            .root_failures
            .iter()
            .map(|failure| failure.root_id.as_str())
            .collect::<Vec<_>>(),
        ["a-root", "m-root", "z-root"]
    );
    session.shutdown().unwrap();
}

#[test]
#[ignore = "requires DISKPLAN_ENGINE_BIN; run scripts/test-cross-language.sh"]
fn swift_engine_malformed_embedding_consumes_request_id() {
    let engine = required_engine_path();
    let mut child = Command::new(engine)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let mut stdout = child.stdout.take().unwrap();
    let (sender, frames) = mpsc::channel();
    thread::spawn(move || {
        loop {
            let frame = read_frame(&mut stdout);
            let terminal = !matches!(frame, Ok(Some(_)));
            if sender.send(frame).is_err() || terminal {
                break;
            }
        }
    });

    send_raw_envelope(
        &mut stdin,
        Envelope {
            sequence: 1,
            body: Some(envelope::Body::Hello(rust_client_hello())),
        },
    );
    assert!(matches!(
        receive_raw_envelope(&frames).body,
        Some(envelope::Body::HelloAccepted(_))
    ));

    send_raw_envelope(
        &mut stdin,
        Envelope {
            sequence: 100,
            body: Some(envelope::Body::StartScanRequest(StartScanRequest {
                request_id: 100,
                profile: "quick".into(),
                roots: Vec::new(),
                maximum_duration_millis: 0,
                batch_size: 1,
            })),
        },
    );
    for _ in 0..3 {
        assert!(matches!(
            receive_raw_envelope(&frames).body,
            Some(envelope::Body::EngineEvent(_))
        ));
    }

    send_raw_envelope(
        &mut stdin,
        Envelope {
            sequence: 999,
            body: Some(envelope::Body::ScanControlRequest(ScanControlRequest {
                request_id: 101,
                control: ScanControlKind::PauseScan as i32,
            })),
        },
    );
    assert_control_rejected(
        receive_raw_control_rejection(&frames, 101),
        101,
        ControlRejectCode::MalformedRequest,
    );

    send_raw_envelope(
        &mut stdin,
        Envelope {
            sequence: 101,
            body: Some(envelope::Body::ScanControlRequest(ScanControlRequest {
                request_id: 101,
                control: ScanControlKind::PauseScan as i32,
            })),
        },
    );
    assert_control_rejected(
        receive_raw_control_rejection(&frames, 101),
        101,
        ControlRejectCode::DuplicateRequestId,
    );

    send_raw_envelope(
        &mut stdin,
        Envelope {
            sequence: 102,
            body: Some(envelope::Body::Business(BusinessEnvelope {
                r#type: "still-ready".into(),
                payload: Vec::new(),
            })),
        },
    );
    let response = (0..10_000)
        .find_map(|_| {
            let response = receive_raw_envelope(&frames);
            matches!(response.body, Some(envelope::Body::HelloRejected(_))).then_some(response)
        })
        .expect("business rejection must remain observable amid natural scan events");
    assert!(matches!(
        response.body,
        Some(envelope::Body::HelloRejected(_))
    ));
    drop(stdin);
    assert!(child.wait().unwrap().success());
}

#[test]
fn fake_engine_acceptance_is_validated_fail_closed() {
    let cases = [
        (accepted_without_version(), ExpectedInvalid::MissingVersion),
        (
            accepted_envelope(2, 1, 1, &["framing-v1"]),
            ExpectedInvalid::Sequence,
        ),
        (
            accepted_envelope(1, 2, 0, &["framing-v1"]),
            ExpectedInvalid::Major,
        ),
        (
            accepted_envelope(1, 1, 4, &["framing-v1"]),
            ExpectedInvalid::Minor,
        ),
        (
            accepted_envelope(1, 1, 1, &["framing-v1", "framing-v1"]),
            ExpectedInvalid::Canonical,
        ),
        (
            accepted_envelope(1, 1, 1, &["framing-v1", "rogue"]),
            ExpectedInvalid::Unoffered,
        ),
        (
            accepted_envelope(1, 1, 1, &["canonical-binary-v1"]),
            ExpectedInvalid::MissingRequired,
        ),
    ];

    for (response, expected) in cases {
        let frame = encode_frame(&response);
        let (_root, path) = fake_engine_script(&emit_then_drain(&frame, false));
        let error = EngineSession::connect_with_timeout(&path, TEST_TIMEOUT)
            .err()
            .expect("invalid acceptance must fail");
        match (error, expected) {
            (
                ClientError::InvalidAcceptance(AcceptedHandshakeError::MissingSelectedVersion),
                ExpectedInvalid::MissingVersion,
            )
            | (ClientError::ResponseSequenceMismatch { .. }, ExpectedInvalid::Sequence)
            | (
                ClientError::InvalidAcceptance(AcceptedHandshakeError::MajorMismatch { .. }),
                ExpectedInvalid::Major,
            )
            | (
                ClientError::InvalidAcceptance(AcceptedHandshakeError::MinorOutOfRange { .. }),
                ExpectedInvalid::Minor,
            )
            | (
                ClientError::InvalidAcceptance(AcceptedHandshakeError::NonCanonicalCapabilities),
                ExpectedInvalid::Canonical,
            )
            | (
                ClientError::InvalidAcceptance(AcceptedHandshakeError::UnofferedCapability(_)),
                ExpectedInvalid::Unoffered,
            )
            | (
                ClientError::InvalidAcceptance(AcceptedHandshakeError::MissingRequiredCapability(
                    _,
                )),
                ExpectedInvalid::MissingRequired,
            ) => {}
            (actual, expected) => panic!("unexpected error for {expected:?}: {actual:?}"),
        }
    }
}

#[test]
fn fake_engine_rejection_sequence_is_validated_before_the_rejection_is_accepted() {
    let response = Envelope {
        sequence: 99,
        body: Some(envelope::Body::HelloRejected(HelloRejected {
            code: RejectCode::ProtocolMajorMismatch as i32,
            detail: "wrong sequence".into(),
            peer_version: None,
        })),
    };
    let frame = encode_frame(&response);
    let (_root, path) = fake_engine_script(&emit_then_drain(&frame, false));

    let error = EngineSession::connect_with_timeout(&path, TEST_TIMEOUT)
        .err()
        .expect("a rejection with the wrong sequence must fail closed");
    assert!(matches!(
        error,
        ClientError::ResponseSequenceMismatch {
            expected: 1,
            actual: 99
        }
    ));
}

#[test]
fn fake_engine_event_sequence_gap_fails_closed() {
    let mut frames = encode_frame(&accepted_envelope(
        1,
        1,
        2,
        &["framing-v1", "scan-control-v1"],
    ));
    frames.extend(encode_frame(&engine_event_envelope(1)));
    frames.extend(encode_frame(&engine_event_envelope(3)));
    let (_root, path) = fake_engine_script(&emit_then_drain(&frames, false));
    let mut session = EngineSession::connect_with_timeout(&path, TEST_TIMEOUT).unwrap();

    assert_eq!(session.read_engine_event().unwrap().event_sequence, 1);
    let error = session
        .read_engine_event()
        .expect_err("a sequence gap must fail closed");
    assert!(matches!(
        error,
        ClientError::EventSequenceMismatch {
            previous: 1,
            actual: 3
        }
    ));
}

#[test]
fn fake_engine_transport_failures_and_exit_are_typed_and_bounded() {
    let cases = [
        (
            "printf '%b' '\\x00\\x00\\x00\\x01\\xff'\n",
            ExpectedFailure::Protobuf,
        ),
        (
            "printf '%b' '\\x00\\x00\\x00\\x03\\x01\\x02'\n",
            ExpectedFailure::Truncated,
        ),
        (
            "printf '%b' '\\x01\\x00\\x00\\x01'\n",
            ExpectedFailure::Oversized,
        ),
        ("exit 17\n", ExpectedFailure::Exit),
    ];

    for (body, expected) in cases {
        let (_root, path) = fake_engine_script(body);
        let started = Instant::now();
        let error = EngineSession::connect_with_timeout(&path, TEST_TIMEOUT)
            .err()
            .expect("fake engine must fail");
        assert!(started.elapsed() < TEST_OPERATION_BOUND);
        match (error, expected) {
            (ClientError::Protobuf(_), ExpectedFailure::Protobuf)
            | (
                ClientError::Frame(FrameError::TruncatedPayload { .. }),
                ExpectedFailure::Truncated,
            )
            | (ClientError::Frame(FrameError::Oversized { .. }), ExpectedFailure::Oversized)
            | (ClientError::EngineFailure { code: Some(17) }, ExpectedFailure::Exit) => {}
            (actual, expected) => panic!("unexpected error for {expected:?}: {actual:?}"),
        }
    }
}

#[test]
fn fake_engine_timeout_is_bounded_and_process_is_terminated() {
    let (_root, path) = fake_engine_script("sleep 10\n");
    let started = Instant::now();
    let error = EngineSession::connect_with_timeout(&path, Duration::from_millis(40))
        .err()
        .expect("silent engine must time out");
    assert!(matches!(error, ClientError::Timeout { .. }));
    assert!(started.elapsed() < SHUTDOWN_BOUND);
}

#[test]
fn timeout_terminates_and_reaps_the_engine_process_group() {
    let root = tempfile::tempdir().unwrap();
    let descendant_pid_path = root.path().join("descendant.pid");
    let body = format!(
        "sleep 10 &\nprintf '%s\\n' \"$!\" > '{}'\nwait\n",
        descendant_pid_path.display()
    );
    let path = write_fake_engine(&root, &body);

    let error = EngineSession::connect_with_timeout(&path, PROCESS_GROUP_TEST_TIMEOUT)
        .err()
        .expect("silent engine must time out");
    assert!(matches!(error, ClientError::Timeout { .. }));
    let descendant_pid: u32 = fs::read_to_string(&descendant_pid_path)
        .expect("fake engine must record its descendant PID")
        .trim()
        .parse()
        .unwrap();
    assert!(
        wait_for_pid_exit(descendant_pid, Duration::from_secs(2)),
        "descendant process {descendant_pid} survived engine-session cleanup"
    );
}

#[test]
fn frame_flood_is_backpressured_and_sigkill_cleanup_remains_bounded() {
    let root = tempfile::tempdir().unwrap();
    let blocker = root.path().join("blocker.fifo");
    let flood_ready = root.path().join("flood.ready");
    let term_seen = root.path().join("term.seen");
    assert!(
        Command::new("/usr/bin/mkfifo")
            .arg(&blocker)
            .status()
            .unwrap()
            .success()
    );
    let accepted = encode_frame(&accepted_envelope(
        1,
        1,
        1,
        &["canonical-binary-v1", "framing-v1", "plan-bootstrap"],
    ));
    let flood = encode_frame(&Envelope {
        sequence: 2,
        body: Some(envelope::Body::Business(BusinessEnvelope {
            r#type: "flood".into(),
            payload: vec![0xa5; 1024],
        })),
    });
    let body = format!(
        "trap 'printf t > \"{}\"' TERM\n\
         printf '%b' '{}'\n\
         for _ in 1 2 3; do printf '%b' '{}'; done\n\
         : > \"{}\"\n\
         exec 3<> \"{}\"\n\
         while :; do read -r _ <&3 || :; done\n",
        term_seen.display(),
        shell_bytes(&accepted),
        shell_bytes(&flood),
        flood_ready.display(),
        blocker.display(),
    );
    let path = write_fake_engine(&root, &body);
    let session = EngineSession::connect_with_timeout(&path, TEST_TIMEOUT).unwrap();
    assert!(
        wait_for_path(&flood_ready, TEST_TIMEOUT),
        "fake engine did not reach the post-flood blocking barrier"
    );

    let started = Instant::now();
    let error = session
        .shutdown()
        .expect_err("the queued flood frame must be reported during shutdown");
    assert!(
        matches!(error, ClientError::ExtraFrameAfterShutdown),
        "unexpected shutdown error: {error:?}"
    );
    let elapsed = started.elapsed();
    assert!(
        fs::read_to_string(&term_seen).is_ok_and(|value| value == "t"),
        "the fake engine did not observe process-group TERM before SIGKILL"
    );
    assert!(
        elapsed < SHUTDOWN_BOUND,
        "shutdown exceeded its bounded TERM/KILL cleanup window"
    );
}

#[test]
fn handshake_helper_rejects_trailing_bytes_and_extra_frames_on_shutdown() {
    let accepted = encode_frame(&accepted_envelope(
        1,
        1,
        1,
        &["canonical-binary-v1", "framing-v1", "plan-bootstrap"],
    ));

    let trailing_body = format!("{}printf '%s' 'oops'\n", emit_then_drain(&accepted, false));
    let (_root, path) = fake_engine_script(&trailing_body);
    let error = handshake_with_engine(&path).expect_err("trailing bytes must fail shutdown");
    assert!(matches!(
        error,
        ClientError::Frame(FrameError::Oversized { .. })
    ));

    let extra_frame_body = format!(
        "{}printf '%b' '{}'\n",
        emit_then_drain(&accepted, false),
        shell_bytes(&accepted)
    );
    let (_root, path) = fake_engine_script(&extra_frame_body);
    let error = handshake_with_engine(&path).expect_err("extra frame must fail shutdown");
    assert!(
        matches!(error, ClientError::ExtraFrameAfterShutdown),
        "unexpected shutdown error: {error:?}"
    );
}

#[test]
fn fake_engine_fragmented_frames_cleanly_shutdown_and_extra_frames_are_not_silent() {
    let accepted = encode_frame(&accepted_envelope(
        1,
        1,
        1,
        &["canonical-binary-v1", "framing-v1", "plan-bootstrap"],
    ));
    let (_root, path) = fake_engine_script(&emit_then_drain(&accepted, true));
    let session = EngineSession::connect_with_timeout(&path, TEST_TIMEOUT).unwrap();
    session.shutdown().unwrap();

    let extra = encode_frame(&accepted_envelope(
        1,
        1,
        1,
        &["canonical-binary-v1", "framing-v1", "plan-bootstrap"],
    ));
    let mut combined = accepted;
    combined.extend(extra);
    let (_root, path) = fake_engine_script(&emit_then_drain(&combined, false));
    let mut session = EngineSession::connect_with_timeout(&path, TEST_TIMEOUT).unwrap();
    let error = session
        .request_business(2, "scan", Vec::new())
        .expect_err("queued extra response must fail sequence validation");
    assert!(matches!(
        error,
        ClientError::ResponseSequenceMismatch {
            expected: 2,
            actual: 1
        }
    ));
}

#[derive(Debug)]
enum ExpectedInvalid {
    MissingVersion,
    Sequence,
    Major,
    Minor,
    Canonical,
    Unoffered,
    MissingRequired,
}

fn accepted_without_version() -> Envelope {
    Envelope {
        sequence: 1,
        body: Some(envelope::Body::HelloAccepted(HelloAccepted {
            selected_version: None,
            negotiated_capabilities: vec!["framing-v1".into()],
        })),
    }
}

#[derive(Debug)]
enum ExpectedFailure {
    Protobuf,
    Truncated,
    Oversized,
    Exit,
}

fn required_engine_path() -> PathBuf {
    std::env::var_os("DISKPLAN_ENGINE_BIN")
        .map(PathBuf::from)
        .expect("DISKPLAN_ENGINE_BIN is required for ignored cross-language tests")
}

fn accepted_envelope(sequence: u64, major: u32, minor: u32, capabilities: &[&str]) -> Envelope {
    Envelope {
        sequence,
        body: Some(envelope::Body::HelloAccepted(HelloAccepted {
            selected_version: Some(ProtocolVersion { major, minor }),
            negotiated_capabilities: capabilities.iter().map(|value| (*value).into()).collect(),
        })),
    }
}

fn engine_event_envelope(sequence: u64) -> Envelope {
    let (request_id, body) = if sequence == 1 {
        (
            1,
            engine_event::Body::ControlAccepted(ControlAccepted {
                control: ScanControlKind::StartScan as i32,
                resulting_state: ScanState::Running as i32,
            }),
        )
    } else {
        (0, engine_event::Body::ScanProgress(ScanProgress::default()))
    };
    Envelope {
        sequence,
        body: Some(envelope::Body::EngineEvent(EngineEvent {
            event_sequence: sequence,
            request_id,
            scan_session_id: "fake-session".into(),
            body: Some(body),
        })),
    }
}

#[track_caller]
fn read_until_event(
    session: &mut EngineSession,
    predicate: impl Fn(&EngineEvent) -> bool,
) -> EngineEvent {
    for _ in 0..10_000 {
        let event = session.read_engine_event().unwrap();
        if predicate(&event) {
            return event;
        }
    }
    panic!("event predicate was not satisfied");
}

fn encode_frame(envelope: &Envelope) -> Vec<u8> {
    let mut payload = Vec::new();
    envelope.encode(&mut payload).unwrap();
    let mut frame = Vec::new();
    write_frame(&mut frame, &payload).unwrap();
    frame
}

fn send_raw_envelope(stdin: &mut ChildStdin, envelope: Envelope) {
    let payload = envelope.encode_to_vec();
    write_frame(stdin, &payload).unwrap();
}

fn receive_raw_envelope(frames: &mpsc::Receiver<Result<Option<Vec<u8>>, FrameError>>) -> Envelope {
    let payload = frames
        .recv_timeout(Duration::from_secs(2))
        .expect("Swift engine frame timed out")
        .expect("Swift engine frame failed")
        .expect("Swift engine closed stdout");
    Envelope::decode(payload.as_slice()).unwrap()
}

fn receive_raw_engine_event(
    frames: &mpsc::Receiver<Result<Option<Vec<u8>>, FrameError>>,
) -> EngineEvent {
    let envelope = receive_raw_envelope(frames);
    let Some(envelope::Body::EngineEvent(event)) = envelope.body else {
        panic!("expected engine event");
    };
    event
}

fn receive_raw_control_rejection(
    frames: &mpsc::Receiver<Result<Option<Vec<u8>>, FrameError>>,
    request_id: u64,
) -> EngineEvent {
    for _ in 0..10_000 {
        let event = receive_raw_engine_event(frames);
        if event.request_id == request_id
            && matches!(event.body, Some(engine_event::Body::ControlRejected(_)))
        {
            return event;
        }
    }
    panic!("control rejection was not observed within the bounded event budget");
}

fn assert_control_rejected(event: EngineEvent, request_id: u64, code: ControlRejectCode) {
    assert_eq!(event.request_id, request_id);
    let Some(engine_event::Body::ControlRejected(rejected)) = event.body else {
        panic!("expected control rejection");
    };
    assert_eq!(rejected.code, code as i32);
}

fn assert_control_rejected_with_setup(
    event: EngineEvent,
    request_id: u64,
    code: ControlRejectCode,
    setup_code: ScanSetupRejectCode,
) {
    assert_eq!(event.request_id, request_id);
    let Some(engine_event::Body::ControlRejected(rejected)) = event.body else {
        panic!("expected control rejection");
    };
    assert_eq!(rejected.code, code as i32);
    assert_eq!(rejected.setup_code, setup_code as i32);
}

fn emit_then_drain(bytes: &[u8], fragmented: bool) -> String {
    let escaped = shell_bytes(bytes);
    if fragmented {
        let midpoint = escaped.len() / 2 / 4 * 4;
        format!(
            "printf '%b' '{}'\nsleep 0.01\nprintf '%b' '{}'\ncat >/dev/null\n",
            &escaped[..midpoint],
            &escaped[midpoint..]
        )
    } else {
        format!("printf '%b' '{escaped}'\ncat >/dev/null\n")
    }
}

fn fake_engine_script(body: &str) -> (TempDir, PathBuf) {
    let root = tempfile::tempdir().unwrap();
    let path = write_fake_engine(&root, body);
    (root, path)
}

fn write_fake_engine(root: &TempDir, body: &str) -> PathBuf {
    let path = root.path().join("fake-engine");
    fs::write(&path, format!("#!/bin/bash\nset -eu\n{body}")).unwrap();
    let mut permissions = fs::metadata(&path).unwrap().permissions();
    permissions.set_mode(0o700);
    fs::set_permissions(&path, permissions).unwrap();
    path
}

fn shell_bytes(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("\\x{byte:02x}")).collect()
}

fn wait_for_pid_exit(process_id: u32, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        let exists = Command::new("/bin/kill")
            .args(["-0", &process_id.to_string()])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .is_ok_and(|status| status.success());
        if !exists {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(10));
    }
}

fn wait_for_path(path: &Path, timeout: Duration) -> bool {
    let deadline = Instant::now() + timeout;
    loop {
        if path.exists() {
            return true;
        }
        if Instant::now() >= deadline {
            return false;
        }
        thread::sleep(Duration::from_millis(5));
    }
}

fn exchange_once(engine: &Path, request: Envelope) -> Envelope {
    let mut child = Command::new(engine)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap();
    let mut payload = Vec::new();
    request.encode(&mut payload).unwrap();
    write_frame(child.stdin.as_mut().unwrap(), &payload).unwrap();
    child.stdin.take();
    let mut stdout = child.stdout.take().unwrap();
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || sender.send(read_frame(&mut stdout)).ok());
    let payload = match receiver.recv_timeout(Duration::from_secs(2)) {
        Ok(Ok(Some(payload))) => payload,
        result => {
            terminate(&mut child);
            panic!("engine did not return one complete frame: {result:?}");
        }
    };
    let status = child.wait().unwrap();
    assert!(status.success());
    Envelope::decode(payload.as_slice()).unwrap()
}

fn terminate(child: &mut Child) {
    let _ = Command::new("kill")
        .args(["-TERM", &child.id().to_string()])
        .status();
    let _ = child.kill();
    let _ = child.wait();
}

fn assert_rejection(response: Envelope, expected: RejectCode) {
    let Some(envelope::Body::HelloRejected(rejected)) = response.body else {
        panic!("expected rejection");
    };
    assert_eq!(rejected.code, expected as i32);
}

fn assert_control_accepted(
    event: diskplan_proto::diskplan::v1::EngineEvent,
    request_id: u64,
    control: ScanControlKind,
    state: ScanState,
) {
    assert_eq!(event.request_id, request_id);
    let body = event.body;
    let Some(engine_event::Body::ControlAccepted(accepted)) = body else {
        panic!("expected control acceptance, got {body:?}");
    };
    assert_eq!(accepted.control, control as i32);
    assert_eq!(accepted.resulting_state, state as i32);
}
