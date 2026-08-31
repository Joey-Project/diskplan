//! Plan-first presentation model.
//!
//! Every safety-relevant value in this module is supplied by the Swift engine.
//! The Rust frontend validates projection structure, but never derives policy,
//! stageability, or reclaim eligibility.

mod model;
mod runtime;
mod types;
mod wire;

#[cfg(test)]
mod tests;

pub use model::{
    InvalidatedPlan, InvalidationError, PLAN_SEARCH_FIELDS, PlanColumn, PlanModel, PlanModelError,
    PlanSearchField, RowKey, RowLevel, SortMode, TargetRowKey, TargetViewRow, ViewRow,
};
pub use runtime::{
    DecisionOverlay, EngineOverlaySnapshot, EnginePlanSnapshot, ExecutionPreviewProjection,
    ExecutionUnitProjection, ExecutionWarningProjection, OverlayStageEdit, OverlayStageResult,
    PlanIntent, PlanIntentKind, PlanProjectionAdapter, PlanRuntime, PlanRuntimeError,
    PlanRuntimeEvent, PlanView,
};
pub use types::{
    ActionId, ActionKindId, ActionKindProjection, ActionProjection, Activity, BlockerId,
    BlockerProjection, ByteValue, DisplayPath, ExecutionUnitId, ExecutionWarningId,
    ForceRequirement, PathRace, PlanDisposition, PlanId, PlanProjection, PrerequisiteProjection,
    Recoverability, ReleaseSetId, ReleaseSetProjection, Stageability, TargetId, TargetKind,
    TargetProjection, WaiverId,
};
pub(crate) use wire::snapshot_from_verified;
