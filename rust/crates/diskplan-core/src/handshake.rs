use std::collections::BTreeSet;

use diskplan_proto::diskplan::v1::{
    Hello, HelloAccepted, HelloRejected, ProtocolVersion, RejectCode,
};
use thiserror::Error;

pub const PROTOCOL_MAJOR: u32 = 1;
pub const PROTOCOL14_MINOR: u32 = 4;
pub const PROTOCOL15_MINOR: u32 = 5;
pub const PROTOCOL16_MINOR: u32 = 6;
pub const PROTOCOL_MINOR: u32 = PROTOCOL16_MINOR;
pub const PROTOCOL14_RUNTIME_CAPABILITIES: [&str; 4] = [
    "decision-overlay-v1",
    "dry-run-projection-v1",
    "execution-stream-v1",
    "plan-projection-v1",
];

#[derive(Debug, PartialEq)]
pub enum HandshakeResult {
    Accepted(HelloAccepted),
    Rejected(HelloRejected),
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum AcceptedHandshakeError {
    #[error("handshake response sequence {actual} does not match request sequence {expected}")]
    SequenceMismatch { expected: u64, actual: u64 },
    #[error("accepted handshake has no selected protocol version")]
    MissingSelectedVersion,
    #[error("accepted protocol major {actual} does not match offered major {expected}")]
    MajorMismatch { expected: u32, actual: u32 },
    #[error("accepted protocol minor {selected} exceeds offered minor {offered}")]
    MinorOutOfRange { offered: u32, selected: u32 },
    #[error("negotiated capabilities are not unique and canonically sorted")]
    NonCanonicalCapabilities,
    #[error("negotiated capability was not offered by the client: {0}")]
    UnofferedCapability(String),
    #[error("required client capability was not negotiated: {0}")]
    MissingRequiredCapability(String),
}

pub fn rust_client_hello() -> Hello {
    rust_client_hello_with_runtime_capabilities(&[])
}

pub fn rust_client_hello_with_runtime_capabilities(runtime_capabilities: &[&str]) -> Hello {
    let requested_runtime_capabilities: BTreeSet<_> = runtime_capabilities
        .iter()
        .copied()
        .filter(|capability| PROTOCOL14_RUNTIME_CAPABILITIES.contains(capability))
        .collect();
    let mut optional_capabilities = vec![
        "canonical-binary-v1".into(),
        "plan-bootstrap".into(),
        "raw-path-bytes-v1".into(),
        "scan-control-v1".into(),
        "scan-stream-v1".into(),
    ];
    optional_capabilities.extend(
        requested_runtime_capabilities
            .into_iter()
            .map(str::to_owned),
    );
    optional_capabilities.sort();

    Hello {
        version: Some(ProtocolVersion {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
        }),
        required_capabilities: vec!["framing-v1".into()],
        optional_capabilities,
        implementation: "diskplan-rust".into(),
    }
}

pub fn negotiate(local: &Hello, peer: &Hello) -> HandshakeResult {
    let Some(local_version) = local.version.as_ref() else {
        return reject(
            RejectCode::MalformedEnvelope,
            "local hello has no version",
            peer,
        );
    };
    let Some(peer_version) = peer.version.as_ref() else {
        return reject(
            RejectCode::MalformedEnvelope,
            "peer hello has no version",
            peer,
        );
    };
    if local_version.major != peer_version.major {
        return reject(
            RejectCode::ProtocolMajorMismatch,
            "protocol major versions differ",
            peer,
        );
    }

    let local_offered = offered_capabilities(local);
    let peer_offered = offered_capabilities(peer);
    if let Some(missing) = peer
        .required_capabilities
        .iter()
        .find(|capability| !local_offered.contains(capability.as_str()))
    {
        return reject(
            RejectCode::MissingRequiredCapability,
            &format!("local implementation does not offer required capability: {missing}"),
            peer,
        );
    }
    if let Some(missing) = local
        .required_capabilities
        .iter()
        .find(|capability| !peer_offered.contains(capability.as_str()))
    {
        return reject(
            RejectCode::MissingRequiredCapability,
            &format!("peer does not offer required capability: {missing}"),
            peer,
        );
    }

    let negotiated_capabilities = local_offered
        .intersection(&peer_offered)
        .map(|value| (*value).to_owned())
        .collect();
    HandshakeResult::Accepted(HelloAccepted {
        selected_version: Some(ProtocolVersion {
            major: local_version.major,
            minor: local_version.minor.min(peer_version.minor),
        }),
        negotiated_capabilities,
    })
}

pub fn validate_accepted(
    local: &Hello,
    request_sequence: u64,
    response_sequence: u64,
    accepted: &HelloAccepted,
) -> Result<(), AcceptedHandshakeError> {
    if response_sequence != request_sequence {
        return Err(AcceptedHandshakeError::SequenceMismatch {
            expected: request_sequence,
            actual: response_sequence,
        });
    }

    let local_version = local
        .version
        .as_ref()
        .expect("the built-in client hello always has a version");
    let selected = accepted
        .selected_version
        .as_ref()
        .ok_or(AcceptedHandshakeError::MissingSelectedVersion)?;
    if selected.major != local_version.major {
        return Err(AcceptedHandshakeError::MajorMismatch {
            expected: local_version.major,
            actual: selected.major,
        });
    }
    if selected.minor > local_version.minor {
        return Err(AcceptedHandshakeError::MinorOutOfRange {
            offered: local_version.minor,
            selected: selected.minor,
        });
    }

    let canonical: Vec<_> = accepted
        .negotiated_capabilities
        .iter()
        .cloned()
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    if canonical != accepted.negotiated_capabilities {
        return Err(AcceptedHandshakeError::NonCanonicalCapabilities);
    }

    let offered = offered_capabilities(local);
    for capability in &accepted.negotiated_capabilities {
        if !offered.contains(capability.as_str()) {
            return Err(AcceptedHandshakeError::UnofferedCapability(
                capability.clone(),
            ));
        }
    }
    let negotiated: BTreeSet<_> = accepted
        .negotiated_capabilities
        .iter()
        .map(String::as_str)
        .collect();
    for required in &local.required_capabilities {
        if !negotiated.contains(required.as_str()) {
            return Err(AcceptedHandshakeError::MissingRequiredCapability(
                required.clone(),
            ));
        }
    }
    Ok(())
}

fn offered_capabilities(hello: &Hello) -> BTreeSet<&str> {
    hello
        .required_capabilities
        .iter()
        .chain(&hello.optional_capabilities)
        .map(String::as_str)
        .collect()
}

fn reject(code: RejectCode, detail: &str, peer: &Hello) -> HandshakeResult {
    HandshakeResult::Rejected(HelloRejected {
        code: code as i32,
        detail: detail.into(),
        peer_version: peer.version,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn local() -> Hello {
        Hello {
            version: Some(ProtocolVersion { major: 1, minor: 4 }),
            required_capabilities: vec!["base".into()],
            optional_capabilities: vec!["zeta".into(), "alpha".into()],
            implementation: "local".into(),
        }
    }

    #[test]
    fn selects_minor_and_sorts_capability_intersection() {
        let peer = Hello {
            version: Some(ProtocolVersion { major: 1, minor: 2 }),
            required_capabilities: vec!["zeta".into()],
            optional_capabilities: vec!["base".into(), "alpha".into()],
            implementation: "peer".into(),
        };
        let HandshakeResult::Accepted(accepted) = negotiate(&local(), &peer) else {
            panic!("expected acceptance");
        };
        assert_eq!(accepted.selected_version.unwrap().minor, 2);
        assert_eq!(accepted.negotiated_capabilities, ["alpha", "base", "zeta"]);
    }

    #[test]
    fn protocol16_client_accepts_a_protocol14_selection() {
        assert_eq!(PROTOCOL_MINOR, PROTOCOL16_MINOR);
        let offered = rust_client_hello_with_runtime_capabilities(&PROTOCOL14_RUNTIME_CAPABILITIES);
        let accepted = HelloAccepted {
            selected_version: Some(ProtocolVersion {
                major: PROTOCOL_MAJOR,
                minor: PROTOCOL14_MINOR,
            }),
            negotiated_capabilities: offered.required_capabilities.clone(),
        };
        assert_eq!(validate_accepted(&offered, 1, 1, &accepted), Ok(()));
    }

    #[test]
    fn client_hello_advertises_only_installed_runtime_capabilities() {
        let scan_only = rust_client_hello();
        assert!(PROTOCOL14_RUNTIME_CAPABILITIES.iter().all(|capability| {
            !scan_only
                .optional_capabilities
                .iter()
                .any(|offered| offered == capability)
        }));

        let with_runtime = rust_client_hello_with_runtime_capabilities(&[
            "plan-projection-v1",
            "unknown-runtime-v1",
        ]);
        assert!(
            with_runtime
                .optional_capabilities
                .contains(&"plan-projection-v1".into())
        );
        assert!(
            !with_runtime
                .optional_capabilities
                .contains(&"unknown-runtime-v1".into())
        );
    }

    #[test]
    fn rejects_major_mismatch_with_stable_code() {
        let peer = Hello {
            version: Some(ProtocolVersion { major: 2, minor: 0 }),
            ..local()
        };
        let HandshakeResult::Rejected(rejected) = negotiate(&local(), &peer) else {
            panic!("expected rejection");
        };
        assert_eq!(rejected.code, RejectCode::ProtocolMajorMismatch as i32);
    }

    #[test]
    fn rejects_missing_required_capability() {
        let peer = Hello {
            version: Some(ProtocolVersion { major: 1, minor: 0 }),
            required_capabilities: vec!["unavailable".into()],
            optional_capabilities: vec!["base".into()],
            implementation: "peer".into(),
        };
        assert!(matches!(
            negotiate(&local(), &peer),
            HandshakeResult::Rejected(_)
        ));
    }

    #[test]
    fn validates_accepted_response_fail_closed() {
        let local = local();
        let accepted = HelloAccepted {
            selected_version: Some(ProtocolVersion { major: 1, minor: 4 }),
            negotiated_capabilities: vec!["alpha".into(), "base".into()],
        };
        assert_eq!(validate_accepted(&local, 1, 1, &accepted), Ok(()));

        let mut invalid = accepted.clone();
        invalid.negotiated_capabilities = vec!["base".into(), "alpha".into()];
        assert_eq!(
            validate_accepted(&local, 1, 1, &invalid),
            Err(AcceptedHandshakeError::NonCanonicalCapabilities)
        );

        let mut invalid = accepted.clone();
        invalid.selected_version = Some(ProtocolVersion { major: 1, minor: 5 });
        assert_eq!(
            validate_accepted(&local, 1, 1, &invalid),
            Err(AcceptedHandshakeError::MinorOutOfRange {
                offered: 4,
                selected: 5,
            })
        );

        assert_eq!(
            validate_accepted(&local, 1, 2, &accepted),
            Err(AcceptedHandshakeError::SequenceMismatch {
                expected: 1,
                actual: 2,
            })
        );
    }
}
