use diskplan_proto::diskplan::v1::{
    DecisionOverlayAcknowledged, DecisionOverlayEdit, DecisionOverlayEditRequest,
    DecisionOverlayRejected, DryRunProjection, PrepareDryRunRequest, RuntimeRejectCode,
    RuntimeRejected, runtime_event,
};
use diskplan_proto::runtime::{
    RuntimeProjectionError, VerifiedPlanProjection, decode_and_verify_plan_projection,
};
use diskplan_proto::sealed::{RuntimeChainVerifier, VerifiedDryRunProjection};
use prost::Message;
use thiserror::Error;

use crate::{ClientError, EngineSession, SessionEvent};

#[derive(Debug, Error)]
pub enum RuntimeClientError {
    #[error(transparent)]
    Transport(#[from] ClientError),
    #[error("engine rejected runtime request with code {code}: {summary}")]
    Rejected { code: i32, summary: String },
    #[error("engine rejected the decision overlay with code {code}: {summary}")]
    OverlayRejected { code: i32, summary: String },
    #[error("runtime projection is invalid: {0}")]
    Projection(#[from] RuntimeProjectionError),
    #[error("runtime stream violated the expected {0} response sequence")]
    Unexpected(&'static str),
}

impl RuntimeClientError {
    pub fn is_unavailable(&self) -> bool {
        matches!(
            self,
            Self::Rejected { code, .. }
                if *code == RuntimeRejectCode::CapabilityNotNegotiated as i32
                    || *code == RuntimeRejectCode::BusinessUnsupported as i32
        )
    }
}

#[derive(Clone, Debug)]
pub struct RuntimePlanReceipt {
    projection: VerifiedPlanProjection,
}

impl RuntimePlanReceipt {
    pub fn projection(&self) -> &VerifiedPlanProjection {
        &self.projection
    }

    pub fn into_chain(self) -> RuntimeChainVerifier {
        RuntimeChainVerifier::new(self.projection)
    }
}

pub fn receive_plan(
    session: &mut EngineSession,
    request_id: u64,
) -> Result<RuntimePlanReceipt, RuntimeClientError> {
    let mut accepted = false;
    let mut chunks = Vec::new();
    loop {
        let event = runtime_event_for_request(session, request_id, "plan")?;
        match event.body {
            Some(runtime_event::Body::BuildPlanAccepted(_)) if !accepted && chunks.is_empty() => {
                accepted = true;
            }
            Some(runtime_event::Body::PlanProjectionChunk(chunk)) if accepted => {
                chunks.push(chunk.encode_to_vec());
            }
            Some(runtime_event::Body::PlanProjection(projection)) if accepted => {
                let manifest = projection
                    .manifest
                    .ok_or(RuntimeClientError::Unexpected("plan manifest"))?;
                let verified =
                    decode_and_verify_plan_projection(&chunks, &manifest.encode_to_vec())?;
                return Ok(RuntimePlanReceipt {
                    projection: verified,
                });
            }
            Some(runtime_event::Body::PlanProjectionInvalidated(_)) => {
                return Err(RuntimeClientError::Unexpected("live plan invalidation"));
            }
            Some(runtime_event::Body::RuntimeRejected(rejected)) => {
                return Err(runtime_rejected(rejected));
            }
            _ => return Err(RuntimeClientError::Unexpected("plan")),
        }
    }
}

pub fn edit_overlay(
    session: &mut EngineSession,
    request_id: u64,
    projection_id: diskplan_proto::diskplan::v1::OpaqueIdentifier,
    base_revision: u64,
    edits: Vec<DecisionOverlayEdit>,
    chain: &mut RuntimeChainVerifier,
) -> Result<DecisionOverlayAcknowledged, RuntimeClientError> {
    session.send_decision_overlay_edit_request(DecisionOverlayEditRequest {
        request_id,
        projection_id: Some(projection_id),
        base_revision,
        edits,
    })?;
    let event = runtime_event_for_request(session, request_id, "decision overlay")?;
    match event.body {
        Some(runtime_event::Body::DecisionOverlayAcknowledged(overlay)) => {
            chain.verify_overlay(&overlay.encode_to_vec())?;
            Ok(overlay)
        }
        Some(runtime_event::Body::DecisionOverlayRejected(rejected)) => {
            Err(overlay_rejected(rejected))
        }
        Some(runtime_event::Body::RuntimeRejected(rejected)) => Err(runtime_rejected(rejected)),
        _ => Err(RuntimeClientError::Unexpected("decision overlay")),
    }
}

pub fn prepare_dry_run(
    session: &mut EngineSession,
    request: PrepareDryRunRequest,
    chain: &RuntimeChainVerifier,
) -> Result<VerifiedDryRunProjection, RuntimeClientError> {
    let request_id = request.request_id;
    session.send_prepare_dry_run_request(request)?;
    let event = runtime_event_for_request(session, request_id, "dry-run")?;
    match event.body {
        Some(runtime_event::Body::DryRunProjection(projection)) => {
            verify_dry_run(chain, projection)
        }
        Some(runtime_event::Body::RuntimeRejected(rejected)) => Err(runtime_rejected(rejected)),
        _ => Err(RuntimeClientError::Unexpected("dry-run")),
    }
}

fn verify_dry_run(
    chain: &RuntimeChainVerifier,
    projection: DryRunProjection,
) -> Result<VerifiedDryRunProjection, RuntimeClientError> {
    Ok(chain.verify_dry_run(&projection.encode_to_vec())?)
}

fn runtime_event_for_request(
    session: &mut EngineSession,
    request_id: u64,
    phase: &'static str,
) -> Result<diskplan_proto::diskplan::v1::RuntimeEvent, RuntimeClientError> {
    match session.read_session_event()? {
        SessionEvent::Runtime(event) if event.request_id == request_id => Ok(event),
        SessionEvent::Runtime(_) | SessionEvent::Scan(_) => {
            Err(RuntimeClientError::Unexpected(phase))
        }
    }
}

fn runtime_rejected(rejected: RuntimeRejected) -> RuntimeClientError {
    RuntimeClientError::Rejected {
        code: rejected.code,
        summary: rejected.summary,
    }
}

fn overlay_rejected(rejected: DecisionOverlayRejected) -> RuntimeClientError {
    RuntimeClientError::OverlayRejected {
        code: rejected.code,
        summary: rejected.summary,
    }
}
