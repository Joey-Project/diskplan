use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;

use sha2::{Digest, Sha256};

use super::{
    ActionId, ExecutionUnitId, ExecutionWarningId, ForceRequirement, PlanId, PlanModel,
    PlanModelError, PlanProjection, RowKey, SortMode, Stageability, WaiverId,
};

/// A complete immutable projection issued by the Swift engine.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EnginePlanSnapshot {
    pub projection: PlanProjection,
    pub evidence_reference: String,
    pub provisional: bool,
}

/// Maps the future protocol 1.4 wire object without putting policy in Rust.
pub trait PlanProjectionAdapter<Wire> {
    type Error: Error + Send + Sync + 'static;

    fn decode(&self, wire: &Wire) -> Result<EnginePlanSnapshot, Self::Error>;
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum PlanView {
    #[default]
    Summary,
    Targets,
    Evidence,
    Dependencies,
    Coverage,
    Revalidation,
    SelectedActions,
    ExecutionPreview,
}

impl PlanView {
    pub fn label(self) -> &'static str {
        match self {
            Self::Summary => "Summary",
            Self::Targets => "Targets",
            Self::Evidence => "Evidence",
            Self::Dependencies => "Dependencies",
            Self::Coverage => "Coverage",
            Self::Revalidation => "Revalidation",
            Self::SelectedActions => "Selected Actions",
            Self::ExecutionPreview => "Execution Preview",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DecisionOverlay {
    plan_id: PlanId,
    evidence_reference: String,
    selected_actions: HashSet<ActionId>,
    selected_action_order: Vec<ActionId>,
    allowed_waivers: HashMap<ActionId, HashSet<WaiverId>>,
    waiver_reasons: HashMap<(ActionId, WaiverId), String>,
    user_notes: HashMap<ActionId, String>,
    revision: u64,
    digest: String,
}

impl DecisionOverlay {
    fn new(plan_id: PlanId, evidence_reference: String) -> Self {
        let mut overlay = Self {
            plan_id,
            evidence_reference,
            selected_actions: HashSet::new(),
            selected_action_order: Vec::new(),
            allowed_waivers: HashMap::new(),
            waiver_reasons: HashMap::new(),
            user_notes: HashMap::new(),
            revision: 0,
            digest: String::new(),
        };
        overlay.refresh_digest();
        overlay
    }

    pub fn plan_id(&self) -> &PlanId {
        &self.plan_id
    }

    pub fn evidence_reference(&self) -> &str {
        &self.evidence_reference
    }

    pub fn selected_actions(&self) -> &HashSet<ActionId> {
        &self.selected_actions
    }

    pub fn is_selected(&self, action_id: &ActionId) -> bool {
        self.selected_actions.contains(action_id)
    }

    pub fn selected_action_order(&self) -> &[ActionId] {
        &self.selected_action_order
    }

    pub fn allowed_waivers(&self, action_id: &ActionId) -> Option<&HashSet<WaiverId>> {
        self.allowed_waivers.get(action_id)
    }

    pub fn waiver_reason(&self, action_id: &ActionId, waiver_id: &WaiverId) -> Option<&str> {
        self.waiver_reasons
            .get(&(action_id.clone(), waiver_id.clone()))
            .map(String::as_str)
    }

    pub fn user_note(&self, action_id: &ActionId) -> Option<&str> {
        self.user_notes.get(action_id).map(String::as_str)
    }

    pub fn revision(&self) -> u64 {
        self.revision
    }

    pub fn digest(&self) -> &str {
        &self.digest
    }

    fn set_user_note(&mut self, action_id: &ActionId, note: String) -> bool {
        if note.trim().is_empty() {
            self.user_notes.remove(action_id).is_some()
        } else if self.user_notes.get(action_id) == Some(&note) {
            false
        } else {
            self.user_notes.insert(action_id.clone(), note);
            true
        }
    }

    /// Waivers enter the overlay only after an engine-owned acknowledgement.
    fn acknowledge_waiver(&mut self, action_id: &ActionId, waiver_id: WaiverId, reason: String) {
        self.allowed_waivers
            .entry(action_id.clone())
            .or_default()
            .insert(waiver_id.clone());
        self.waiver_reasons
            .insert((action_id.clone(), waiver_id), reason);
    }

    fn can_advance(&self) -> bool {
        self.revision < u64::MAX
    }

    fn advance(&mut self) {
        self.revision += 1;
        self.refresh_digest();
    }

    fn refresh_digest(&mut self) {
        let mut digest = Sha256::new();
        hash_field(&mut digest, self.plan_id.as_str());
        hash_field(&mut digest, &self.evidence_reference);
        digest.update(self.revision.to_be_bytes());
        for action_id in &self.selected_action_order {
            hash_field(&mut digest, action_id.as_str());
        }
        let mut waivers = self.waiver_reasons.iter().collect::<Vec<_>>();
        waivers.sort_by(|left, right| left.0.cmp(right.0));
        for ((action_id, waiver_id), reason) in waivers {
            hash_field(&mut digest, action_id.as_str());
            hash_field(&mut digest, waiver_id.as_str());
            hash_field(&mut digest, reason);
        }
        let mut notes = self.user_notes.iter().collect::<Vec<_>>();
        notes.sort_by(|left, right| left.0.cmp(right.0));
        for (action_id, note) in notes {
            hash_field(&mut digest, action_id.as_str());
            hash_field(&mut digest, note);
        }
        self.digest = hex::encode(digest.finalize());
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum OverlayStageResult {
    Staged { force_warning: Option<String> },
    Unstaged,
    RequiresWaivers(Vec<WaiverId>),
    NotStageable,
    NoActionSelected,
    RevisionExhausted,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanIntentKind {
    DryRun,
    ApplyReview,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanIntent {
    kind: PlanIntentKind,
    plan_id: PlanId,
    evidence_reference: String,
    selected_action_ids: Vec<ActionId>,
    overlay_revision: u64,
    overlay_digest: String,
}

impl PlanIntent {
    pub fn kind(&self) -> PlanIntentKind {
        self.kind
    }

    pub fn plan_id(&self) -> &PlanId {
        &self.plan_id
    }

    pub fn evidence_reference(&self) -> &str {
        &self.evidence_reference
    }

    pub fn selected_action_ids(&self) -> &[ActionId] {
        &self.selected_action_ids
    }

    pub fn overlay_revision(&self) -> u64 {
        self.overlay_revision
    }

    pub fn overlay_digest(&self) -> &str {
        &self.overlay_digest
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionUnitProjection {
    pub id: ExecutionUnitId,
    pub covered_action_ids: Vec<ActionId>,
    pub label: String,
    pub prerequisite_unit_ids: Vec<ExecutionUnitId>,
    pub prerequisite_status: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionWarningProjection {
    pub id: ExecutionWarningId,
    pub message: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExecutionPreviewProjection {
    pub plan_id: PlanId,
    pub overlay_digest: String,
    pub ordered_units: Vec<ExecutionUnitProjection>,
    pub final_warnings: Vec<ExecutionWarningProjection>,
}

#[derive(Clone, Debug)]
pub enum PlanRuntimeEvent {
    Load(EnginePlanSnapshot),
    Invalidate {
        plan_id: PlanId,
        reason: String,
    },
    EvidenceChanged {
        plan_id: PlanId,
        evidence_reference: String,
    },
    WaiverAcknowledged {
        plan_id: PlanId,
        action_id: ActionId,
        waiver_id: WaiverId,
        reason: String,
    },
    ExecutionPreviewReady(ExecutionPreviewProjection),
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanRuntimeError {
    InvalidProjection(PlanModelError),
    EmptyEvidenceReference,
    StalePlan {
        expected: PlanId,
        actual: PlanId,
    },
    UnknownAction(ActionId),
    UnknownWaiver {
        action_id: ActionId,
        waiver_id: WaiverId,
    },
    EmptyWaiverReason {
        action_id: ActionId,
        waiver_id: WaiverId,
    },
    NoActionSelected,
    RevisionExhausted,
    InvalidExecutionPreview,
}

impl fmt::Display for PlanRuntimeError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "plan runtime rejected engine data: {self:?}")
    }
}

impl Error for PlanRuntimeError {}

#[derive(Clone, Debug, Default)]
pub struct PlanRuntime {
    model: PlanModel,
    overlay: Option<DecisionOverlay>,
    view: PlanView,
    provisional: bool,
    filter_editing: bool,
    filter_buffer: String,
    pending_intents: Vec<PlanIntent>,
    sort_mode: SortMode,
    sort_modes: HashMap<(super::PlanDisposition, super::ActionKindId), SortMode>,
    compact_columns: bool,
    detail_viewport_top: usize,
    detail_viewport_height: usize,
    execution_preview: Option<ExecutionPreviewProjection>,
}

impl PlanRuntime {
    pub fn model(&self) -> &PlanModel {
        &self.model
    }

    pub fn overlay(&self) -> Option<&DecisionOverlay> {
        self.overlay.as_ref()
    }

    pub fn view(&self) -> PlanView {
        self.view
    }

    pub fn set_view(&mut self, view: PlanView) -> bool {
        if view == PlanView::Targets {
            let Some(action_id) = self.selected_action_id().cloned() else {
                return false;
            };
            if !self.model.open_targets(&action_id) {
                return false;
            }
        } else if view == PlanView::ExecutionPreview && self.execution_preview.is_none() {
            return false;
        } else {
            self.model.close_targets();
        }
        self.view = view;
        self.detail_viewport_top = 0;
        true
    }

    pub fn resize_layout(&mut self, width: u16, height: u16) {
        let body_height = height.saturating_sub(8) as usize;
        let metadata_rows = usize::from(width >= 50);
        let filter_rows = usize::from(self.filter_editing);
        let tree_rows = match self.view {
            PlanView::Summary => body_height
                .saturating_sub(metadata_rows)
                .saturating_sub(filter_rows)
                .saturating_sub(usize::from(width >= 50)),
            PlanView::Targets => body_height
                .saturating_sub(metadata_rows)
                .saturating_sub(filter_rows)
                .saturating_sub(1),
            _ => 0,
        };
        self.model.resize(tree_rows);
        self.model.resize_targets(tree_rows);
        self.detail_viewport_height = body_height
            .saturating_sub(metadata_rows)
            .saturating_sub(filter_rows);
        self.clamp_detail_viewport();
    }

    pub fn move_navigation(&mut self, delta: isize) {
        match self.view {
            PlanView::Summary => self.model.move_cursor(delta),
            PlanView::Targets => self.model.move_target_cursor(delta),
            _ => {
                let maximum = self
                    .detail_row_count()
                    .saturating_sub(self.detail_viewport_height);
                self.detail_viewport_top = self
                    .detail_viewport_top
                    .saturating_add_signed(delta)
                    .min(maximum);
            }
        }
    }

    pub fn expand_navigation(&mut self) -> bool {
        if self.view == PlanView::Targets {
            let Some(key) = self.model.target_cursor().cloned() else {
                return false;
            };
            self.model.set_target_row_expanded(&key, true)
        } else if self.view == PlanView::Summary {
            self.expand_cursor()
        } else {
            false
        }
    }

    pub fn collapse_navigation(&mut self) -> bool {
        if self.view == PlanView::Targets {
            let Some(key) = self.model.target_cursor().cloned() else {
                return false;
            };
            self.model.set_target_row_expanded(&key, false)
        } else if self.view == PlanView::Summary {
            self.collapse_cursor()
        } else {
            false
        }
    }

    pub fn detail_viewport_top(&self) -> usize {
        self.detail_viewport_top
    }

    pub fn detail_viewport_height(&self) -> usize {
        self.detail_viewport_height
    }

    pub fn execution_preview(&self) -> Option<&ExecutionPreviewProjection> {
        self.execution_preview.as_ref()
    }

    pub fn provisional(&self) -> bool {
        self.provisional
    }

    pub fn filter_editing(&self) -> bool {
        self.filter_editing
    }

    pub fn filter_buffer(&self) -> &str {
        &self.filter_buffer
    }

    pub fn begin_filter(&mut self) {
        self.filter_editing = true;
        self.filter_buffer = if self.view == PlanView::Targets {
            self.model.target_filter().to_owned()
        } else {
            self.model.filter().to_owned()
        };
    }

    pub fn cancel_filter(&mut self) {
        self.filter_editing = false;
        self.filter_buffer = if self.view == PlanView::Targets {
            self.model.target_filter().to_owned()
        } else {
            self.model.filter().to_owned()
        };
    }

    pub fn finish_filter(&mut self) {
        self.filter_editing = false;
    }

    pub fn push_filter_char(&mut self, character: char) {
        self.filter_buffer.push(character);
        self.apply_filter_buffer();
    }

    pub fn pop_filter_char(&mut self) {
        self.filter_buffer.pop();
        self.apply_filter_buffer();
    }

    pub fn clear_filter(&mut self) {
        self.filter_buffer.clear();
        self.apply_filter_buffer();
    }

    pub fn selected_action_id(&self) -> Option<&ActionId> {
        match self.model.cursor()? {
            RowKey::Action(action_id) => Some(action_id),
            RowKey::Disposition(_) | RowKey::ActionKind { .. } => None,
        }
    }

    fn expand_cursor(&mut self) -> bool {
        let Some(key) = self.model.cursor().cloned() else {
            return false;
        };
        self.model.set_row_expanded(&key, true)
    }

    fn collapse_cursor(&mut self) -> bool {
        let Some(key) = self.model.cursor().cloned() else {
            return false;
        };
        self.model.set_row_expanded(&key, false)
    }

    pub fn cycle_group_sort(&mut self) -> bool {
        let Some(key) = self.model.cursor().cloned() else {
            return false;
        };
        let (disposition, kind_id) = match key {
            RowKey::ActionKind {
                disposition,
                kind_id,
            } => (disposition, kind_id),
            RowKey::Action(action_id) => {
                let Some(action) = self.model.action(&action_id) else {
                    return false;
                };
                (action.disposition, action.kind.id.clone())
            }
            RowKey::Disposition(_) => return false,
        };
        let group_key = (disposition, kind_id);
        let current = self
            .sort_modes
            .get(&group_key)
            .copied()
            .unwrap_or(SortMode::EngineOrder);
        let next = match current {
            SortMode::EngineOrder => SortMode::ImmediateReclaimDescending,
            SortMode::ImmediateReclaimDescending => SortMode::SharedUnlockDescending,
            SortMode::SharedUnlockDescending => SortMode::LabelAscending,
            SortMode::LabelAscending => SortMode::EngineOrder,
        };
        let changed = self
            .model
            .set_group_sort(group_key.0, group_key.1.clone(), next);
        if changed {
            self.sort_modes.insert(group_key, next);
            self.sort_mode = next;
        }
        changed
    }

    pub fn sort_mode(&self) -> SortMode {
        self.sort_mode
    }

    pub fn toggle_column_profile(&mut self) {
        self.compact_columns = !self.compact_columns;
        for column in [
            super::PlanColumn::SharedUnlock,
            super::PlanColumn::Activity,
            super::PlanColumn::Recoverability,
        ] {
            self.model.set_column_visible(column, !self.compact_columns);
        }
    }

    pub fn compact_columns(&self) -> bool {
        self.compact_columns
    }

    pub fn toggle_selected_stage(&mut self) -> OverlayStageResult {
        let Some(action_id) = self.selected_action_id().cloned() else {
            return OverlayStageResult::NoActionSelected;
        };
        let Some(action) = self.model.action(&action_id) else {
            return OverlayStageResult::NoActionSelected;
        };
        let stageability = action.stageability.clone();
        let force = action.force.clone();
        let Some(overlay) = self.overlay.as_mut() else {
            return OverlayStageResult::NoActionSelected;
        };
        if overlay.selected_actions.contains(&action_id) {
            if !overlay.can_advance() {
                return OverlayStageResult::RevisionExhausted;
            }
            overlay.selected_actions.remove(&action_id);
            overlay
                .selected_action_order
                .retain(|selected| selected != &action_id);
            overlay.advance();
            self.pending_intents.clear();
            self.execution_preview = None;
            return OverlayStageResult::Unstaged;
        }
        match stageability {
            Stageability::Stageable => {
                if !overlay.can_advance() {
                    return OverlayStageResult::RevisionExhausted;
                }
                overlay.selected_action_order.push(action_id.clone());
                overlay.selected_actions.insert(action_id);
                overlay.advance();
                self.pending_intents.clear();
                self.execution_preview = None;
                OverlayStageResult::Staged {
                    force_warning: force_reason(force),
                }
            }
            Stageability::RequiresWaivers(required) => {
                let acknowledged = overlay.allowed_waivers.get(&action_id);
                if required
                    .iter()
                    .all(|waiver| acknowledged.is_some_and(|allowed| allowed.contains(waiver)))
                {
                    if !overlay.can_advance() {
                        return OverlayStageResult::RevisionExhausted;
                    }
                    overlay.selected_action_order.push(action_id.clone());
                    overlay.selected_actions.insert(action_id);
                    overlay.advance();
                    self.pending_intents.clear();
                    self.execution_preview = None;
                    OverlayStageResult::Staged {
                        force_warning: force_reason(force),
                    }
                } else {
                    OverlayStageResult::RequiresWaivers(required)
                }
            }
            Stageability::NotStageable => OverlayStageResult::NotStageable,
        }
    }

    pub fn set_selected_user_note(&mut self, note: String) -> Result<(), PlanRuntimeError> {
        let Some(action_id) = self.selected_action_id().cloned() else {
            return Err(PlanRuntimeError::NoActionSelected);
        };
        let Some(overlay) = self.overlay.as_mut() else {
            return Err(PlanRuntimeError::UnknownAction(action_id));
        };
        let note_changed = overlay.user_note(&action_id) != nonempty_note(&note);
        if note_changed && !overlay.can_advance() {
            return Err(PlanRuntimeError::RevisionExhausted);
        }
        if overlay.set_user_note(&action_id, note) {
            overlay.advance();
            self.pending_intents.clear();
            self.execution_preview = None;
        }
        Ok(())
    }

    pub fn queue_intent(&mut self, kind: PlanIntentKind) -> Result<(), &'static str> {
        if self.provisional {
            return Err("freeze the partial scan before dry-run or apply review");
        }
        let Some(overlay) = self.overlay.as_ref() else {
            return Err("stage at least one engine action first");
        };
        if overlay.selected_actions.is_empty() {
            return Err("stage at least one engine action first");
        }
        if !self
            .pending_intents
            .iter()
            .any(|intent| intent.kind == kind)
        {
            self.pending_intents.push(PlanIntent {
                kind,
                plan_id: overlay.plan_id.clone(),
                evidence_reference: overlay.evidence_reference.clone(),
                selected_action_ids: overlay.selected_action_order.clone(),
                overlay_revision: overlay.revision,
                overlay_digest: overlay.digest.clone(),
            });
        }
        Ok(())
    }

    pub fn pending_intents(&self) -> &[PlanIntent] {
        &self.pending_intents
    }

    pub fn take_pending_intents(&mut self) -> Vec<PlanIntent> {
        std::mem::take(&mut self.pending_intents)
    }

    pub fn apply_event(&mut self, event: PlanRuntimeEvent) -> Result<(), PlanRuntimeError> {
        match event {
            PlanRuntimeEvent::Load(snapshot) => {
                let plan_id = snapshot.projection.id.clone();
                // A replacement attempt revokes the previous consent overlay even
                // when the engine projection or evidence binding is invalid.
                self.model.reset();
                self.overlay = None;
                self.provisional = false;
                self.filter_editing = false;
                self.filter_buffer.clear();
                self.pending_intents.clear();
                self.sort_mode = SortMode::EngineOrder;
                self.sort_modes.clear();
                self.compact_columns = false;
                self.detail_viewport_top = 0;
                self.execution_preview = None;
                self.view = PlanView::Summary;
                if snapshot.evidence_reference.trim().is_empty() {
                    return Err(PlanRuntimeError::EmptyEvidenceReference);
                }
                self.model
                    .load(snapshot.projection)
                    .map_err(PlanRuntimeError::InvalidProjection)?;
                self.overlay = Some(DecisionOverlay::new(plan_id, snapshot.evidence_reference));
                self.provisional = snapshot.provisional;
                Ok(())
            }
            PlanRuntimeEvent::Invalidate { plan_id, reason } => self.invalidate(plan_id, reason),
            PlanRuntimeEvent::EvidenceChanged {
                plan_id,
                evidence_reference,
            } => {
                let Some(overlay) = self.overlay.as_ref() else {
                    return Err(PlanRuntimeError::StalePlan {
                        expected: PlanId::new("<none>"),
                        actual: plan_id,
                    });
                };
                if overlay.plan_id != plan_id {
                    return Err(PlanRuntimeError::StalePlan {
                        expected: overlay.plan_id.clone(),
                        actual: plan_id,
                    });
                }
                if overlay.evidence_reference == evidence_reference {
                    return Ok(());
                }
                self.invalidate(plan_id, "engine evidence reference changed".into())
            }
            PlanRuntimeEvent::WaiverAcknowledged {
                plan_id,
                action_id,
                waiver_id,
                reason,
            } => {
                let Some(overlay) = self.overlay.as_ref() else {
                    return Err(PlanRuntimeError::StalePlan {
                        expected: PlanId::new("<none>"),
                        actual: plan_id,
                    });
                };
                if overlay.plan_id != plan_id {
                    return Err(PlanRuntimeError::StalePlan {
                        expected: overlay.plan_id.clone(),
                        actual: plan_id,
                    });
                }
                if self.model.action(&action_id).is_none() {
                    return Err(PlanRuntimeError::UnknownAction(action_id));
                }
                let waiver_is_declared = self.model.action(&action_id).is_some_and(|action| {
                    matches!(
                        &action.stageability,
                        Stageability::RequiresWaivers(required) if required.contains(&waiver_id)
                    )
                });
                if !waiver_is_declared {
                    return Err(PlanRuntimeError::UnknownWaiver {
                        action_id,
                        waiver_id,
                    });
                }
                if reason.trim().is_empty() {
                    return Err(PlanRuntimeError::EmptyWaiverReason {
                        action_id,
                        waiver_id,
                    });
                }
                let Some(overlay) = self.overlay.as_mut() else {
                    return Err(PlanRuntimeError::StalePlan {
                        expected: plan_id.clone(),
                        actual: plan_id,
                    });
                };
                if !overlay.can_advance() {
                    return Err(PlanRuntimeError::RevisionExhausted);
                }
                overlay.acknowledge_waiver(&action_id, waiver_id, reason);
                overlay.advance();
                self.pending_intents.clear();
                self.execution_preview = None;
                Ok(())
            }
            PlanRuntimeEvent::ExecutionPreviewReady(preview) => {
                let Some(overlay) = self.overlay.as_ref() else {
                    return Err(PlanRuntimeError::InvalidExecutionPreview);
                };
                if preview.plan_id != overlay.plan_id
                    || preview.overlay_digest != overlay.digest
                    || !execution_preview_is_valid(&preview, overlay)
                {
                    return Err(PlanRuntimeError::InvalidExecutionPreview);
                }
                self.execution_preview = Some(preview);
                self.view = PlanView::ExecutionPreview;
                self.detail_viewport_top = 0;
                Ok(())
            }
        }
    }

    fn apply_filter_buffer(&mut self) {
        if self.view == PlanView::Targets {
            self.model.set_target_filter(self.filter_buffer.clone());
        } else {
            self.model.set_filter(self.filter_buffer.clone());
        }
    }

    fn invalidate(&mut self, plan_id: PlanId, reason: String) -> Result<(), PlanRuntimeError> {
        self.model.invalidate(plan_id, reason).map_err(|error| {
            let actual = match error {
                super::InvalidationError::PlanIdMismatch { actual, .. } => actual,
                super::InvalidationError::NoLoadedPlan => PlanId::new("<none>"),
            };
            let expected = self
                .overlay
                .as_ref()
                .map(|overlay| overlay.plan_id.clone())
                .unwrap_or_else(|| PlanId::new("<none>"));
            PlanRuntimeError::StalePlan { expected, actual }
        })?;
        self.overlay = None;
        self.provisional = false;
        self.filter_editing = false;
        self.filter_buffer.clear();
        self.pending_intents.clear();
        self.execution_preview = None;
        Ok(())
    }

    fn detail_row_count(&self) -> usize {
        match self.view {
            PlanView::Evidence => usize::from(self.selected_action_id().is_some()) * 6 + 1,
            PlanView::Dependencies => self.selected_action_id().map_or(1, |action_id| {
                self.model.action(action_id).map_or(1, |action| {
                    let release_rows = action.release_set_ids.iter().fold(0usize, |rows, id| {
                        self.model.release_set(id).map_or(rows, |release| {
                            rows.saturating_add(1)
                                .saturating_add(release.action_ids.len())
                        })
                    });
                    2usize
                        .saturating_add(action.prerequisites.len())
                        .saturating_add(usize::from(!action.release_set_ids.is_empty()))
                        .saturating_add(release_rows)
                })
            }),
            PlanView::Coverage => self.selected_action_id().map_or(1, |action_id| {
                self.model
                    .action(action_id)
                    .map_or(1, |action| 3usize.saturating_add(action.blockers.len()))
            }),
            PlanView::Revalidation => 4usize.saturating_add(self.pending_intents.len().max(1)),
            PlanView::SelectedActions => self.overlay.as_ref().map_or(2, |overlay| {
                overlay.selected_action_order.iter().fold(
                    2usize.saturating_add(overlay.selected_actions.len()),
                    |rows, action_id| {
                        rows.saturating_add(
                            self.model
                                .action(action_id)
                                .map_or(0, action_warning_row_count),
                        )
                    },
                )
            }),
            PlanView::ExecutionPreview => self.execution_preview.as_ref().map_or(1, |preview| {
                preview.ordered_units.iter().fold(
                    2usize.saturating_add(preview.final_warnings.len()),
                    |rows, unit| {
                        rows.saturating_add(1)
                            .saturating_add(unit.covered_action_ids.len())
                            .saturating_add(unit.prerequisite_unit_ids.len())
                    },
                )
            }),
            PlanView::Summary | PlanView::Targets => 0,
        }
    }

    fn clamp_detail_viewport(&mut self) {
        self.detail_viewport_top = self.detail_viewport_top.min(
            self.detail_row_count()
                .saturating_sub(self.detail_viewport_height),
        );
    }
}

fn action_warning_row_count(action: &super::ActionProjection) -> usize {
    let waiver_rows = match &action.stageability {
        Stageability::RequiresWaivers(required) => required.len(),
        Stageability::Stageable | Stageability::NotStageable => 0,
    };
    waiver_rows
        .saturating_add(usize::from(matches!(
            &action.force,
            ForceRequirement::Required { .. }
        )))
        .saturating_add(usize::from(action.path_race == super::PathRace::Residual))
}

fn execution_preview_is_valid(
    preview: &ExecutionPreviewProjection,
    overlay: &DecisionOverlay,
) -> bool {
    if preview.ordered_units.is_empty() {
        return false;
    }

    let mut all_unit_ids = HashSet::with_capacity(preview.ordered_units.len());
    for unit in &preview.ordered_units {
        if unit.id.as_str().trim().is_empty()
            || unit.label.trim().is_empty()
            || unit.prerequisite_status.trim().is_empty()
            || unit.covered_action_ids.is_empty()
            || !all_unit_ids.insert(unit.id.clone())
        {
            return false;
        }
    }

    let mut covered_actions = HashSet::with_capacity(overlay.selected_actions.len());
    let mut prior_units = HashSet::with_capacity(preview.ordered_units.len());
    for unit in &preview.ordered_units {
        if unit.covered_action_ids.iter().any(|action_id| {
            !overlay.is_selected(action_id) || !covered_actions.insert(action_id.clone())
        }) {
            return false;
        }

        let mut unit_prerequisites = HashSet::with_capacity(unit.prerequisite_unit_ids.len());
        if unit.prerequisite_unit_ids.iter().any(|prerequisite_id| {
            prerequisite_id == &unit.id
                || !all_unit_ids.contains(prerequisite_id)
                || !prior_units.contains(prerequisite_id)
                || !unit_prerequisites.insert(prerequisite_id.clone())
        }) {
            return false;
        }
        prior_units.insert(unit.id.clone());
    }

    if covered_actions != overlay.selected_actions {
        return false;
    }

    let mut warning_ids = HashSet::with_capacity(preview.final_warnings.len());
    !preview.final_warnings.iter().any(|warning| {
        warning.id.as_str().trim().is_empty()
            || warning.message.trim().is_empty()
            || !warning_ids.insert(warning.id.clone())
    })
}

fn force_reason(force: ForceRequirement) -> Option<String> {
    match force {
        ForceRequirement::NotRequired => None,
        ForceRequirement::Required { reason } => Some(reason),
    }
}

fn hash_field(digest: &mut Sha256, value: &str) {
    digest.update((value.len() as u64).to_be_bytes());
    digest.update(value.as_bytes());
}

fn nonempty_note(note: &str) -> Option<&str> {
    (!note.trim().is_empty()).then_some(note)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tui::plan::{
        ActionKindId, ActionKindProjection, ActionProjection, Activity, ByteValue, DisplayPath,
        PathRace, PlanDisposition, Recoverability, ReleaseSetProjection, TargetId, TargetKind,
        TargetProjection,
    };

    #[test]
    fn immutable_projection_and_overlay_have_separate_lifetimes() {
        let mut runtime = runtime(
            false,
            Stageability::Stageable,
            ForceRequirement::NotRequired,
        );
        select_action(&mut runtime);

        assert_eq!(
            runtime.toggle_selected_stage(),
            OverlayStageResult::Staged {
                force_warning: None
            }
        );
        assert_eq!(
            runtime
                .model()
                .action(&ActionId::new("action-1"))
                .unwrap()
                .stageability,
            Stageability::Stageable
        );
        assert!(
            runtime
                .overlay()
                .unwrap()
                .is_selected(&ActionId::new("action-1"))
        );
        runtime.queue_intent(PlanIntentKind::DryRun).unwrap();
        let intent = &runtime.pending_intents()[0];
        assert_eq!(intent.plan_id(), &PlanId::new("plan-1"));
        assert_eq!(intent.evidence_reference(), "evidence-1");
        assert_eq!(intent.selected_action_ids(), &[ActionId::new("action-1")]);

        runtime
            .apply_event(PlanRuntimeEvent::Invalidate {
                plan_id: PlanId::new("plan-1"),
                reason: "scan resumed".into(),
            })
            .unwrap();
        assert!(runtime.overlay().is_none());
        assert!(runtime.model().current_plan_id().is_none());
        assert_eq!(
            runtime.model().invalidated().unwrap().reason,
            "scan resumed"
        );
    }

    #[test]
    fn waiver_and_force_are_engine_acknowledged_before_staging() {
        let waiver = WaiverId::new("waiver-1");
        let mut runtime = runtime(
            false,
            Stageability::RequiresWaivers(vec![waiver.clone()]),
            ForceRequirement::Required {
                reason: "immutable flag".into(),
            },
        );
        select_action(&mut runtime);

        assert_eq!(
            runtime.toggle_selected_stage(),
            OverlayStageResult::RequiresWaivers(vec![waiver.clone()])
        );
        assert!(runtime.overlay().unwrap().selected_actions().is_empty());

        runtime
            .apply_event(PlanRuntimeEvent::WaiverAcknowledged {
                plan_id: PlanId::new("plan-1"),
                action_id: ActionId::new("action-1"),
                waiver_id: waiver,
                reason: "user confirmed engine predicate".into(),
            })
            .unwrap();
        assert_eq!(
            runtime.toggle_selected_stage(),
            OverlayStageResult::Staged {
                force_warning: Some("immutable flag".into())
            }
        );

        runtime.queue_intent(PlanIntentKind::ApplyReview).unwrap();
        let acknowledged_revision = runtime.overlay().unwrap().revision();
        runtime
            .apply_event(PlanRuntimeEvent::WaiverAcknowledged {
                plan_id: PlanId::new("plan-1"),
                action_id: ActionId::new("action-1"),
                waiver_id: WaiverId::new("waiver-1"),
                reason: "user confirmed engine predicate".into(),
            })
            .unwrap();
        assert!(runtime.pending_intents().is_empty());
        assert!(runtime.overlay().unwrap().revision() > acknowledged_revision);
    }

    #[test]
    fn provisional_plan_cannot_queue_execution_intents() {
        let mut runtime = runtime(true, Stageability::Stageable, ForceRequirement::NotRequired);
        select_action(&mut runtime);
        assert!(matches!(
            runtime.toggle_selected_stage(),
            OverlayStageResult::Staged { .. }
        ));

        assert_eq!(
            runtime.queue_intent(PlanIntentKind::DryRun),
            Err("freeze the partial scan before dry-run or apply review")
        );
        assert!(runtime.pending_intents().is_empty());
    }

    #[test]
    fn blank_evidence_replacement_fails_closed_and_revokes_consent() {
        for evidence_reference in ["", " \t\n "] {
            let mut runtime = runtime(
                false,
                Stageability::Stageable,
                ForceRequirement::NotRequired,
            );
            select_action(&mut runtime);
            assert!(matches!(
                runtime.toggle_selected_stage(),
                OverlayStageResult::Staged { .. }
            ));
            runtime.queue_intent(PlanIntentKind::ApplyReview).unwrap();

            let error = runtime
                .apply_event(PlanRuntimeEvent::Load(EnginePlanSnapshot {
                    projection: PlanProjection {
                        id: PlanId::new("plan-blank-evidence"),
                        actions: Vec::new(),
                        release_sets: Vec::new(),
                    },
                    evidence_reference: evidence_reference.into(),
                    provisional: false,
                }))
                .unwrap_err();

            assert_eq!(error, PlanRuntimeError::EmptyEvidenceReference);
            assert!(runtime.model().current_plan_id().is_none());
            assert!(runtime.overlay().is_none());
            assert!(runtime.pending_intents().is_empty());
            assert!(runtime.execution_preview().is_none());
            assert_eq!(runtime.view(), PlanView::Summary);
        }
    }

    #[test]
    fn every_overlay_mutation_revokes_bound_intents_and_advances_digest() {
        let mut runtime = runtime(
            false,
            Stageability::Stageable,
            ForceRequirement::NotRequired,
        );
        select_action(&mut runtime);
        let initial_digest = runtime.overlay().unwrap().digest().to_owned();
        assert!(matches!(
            runtime.toggle_selected_stage(),
            OverlayStageResult::Staged { .. }
        ));
        let staged_revision = runtime.overlay().unwrap().revision();
        let staged_digest = runtime.overlay().unwrap().digest().to_owned();
        assert_ne!(staged_digest, initial_digest);

        runtime.queue_intent(PlanIntentKind::DryRun).unwrap();
        let intent = &runtime.pending_intents()[0];
        assert_eq!(intent.overlay_revision(), staged_revision);
        assert_eq!(intent.overlay_digest(), staged_digest);

        runtime
            .set_selected_user_note("reviewed locally".into())
            .unwrap();
        assert!(runtime.pending_intents().is_empty());
        assert!(runtime.overlay().unwrap().revision() > staged_revision);
        assert_ne!(runtime.overlay().unwrap().digest(), staged_digest);

        runtime.queue_intent(PlanIntentKind::ApplyReview).unwrap();
        assert_eq!(runtime.pending_intents().len(), 1);
        assert_eq!(
            runtime.toggle_selected_stage(),
            OverlayStageResult::Unstaged
        );
        assert!(runtime.pending_intents().is_empty());
    }

    #[test]
    fn execution_preview_requires_exact_engine_dag_binding() {
        let mut runtime = runtime_with_action_count(
            3,
            false,
            Stageability::Stageable,
            ForceRequirement::NotRequired,
        );
        select_action(&mut runtime);
        assert!(matches!(
            runtime.toggle_selected_stage(),
            OverlayStageResult::Staged { .. }
        ));
        runtime.move_navigation(1);
        assert!(matches!(
            runtime.toggle_selected_stage(),
            OverlayStageResult::Staged { .. }
        ));
        runtime.move_navigation(1);
        assert!(matches!(
            runtime.toggle_selected_stage(),
            OverlayStageResult::Staged { .. }
        ));
        let overlay = runtime.overlay().unwrap();
        let projection = ExecutionPreviewProjection {
            plan_id: overlay.plan_id().clone(),
            overlay_digest: overlay.digest().into(),
            ordered_units: vec![
                ExecutionUnitProjection {
                    id: ExecutionUnitId::new("unit-apfs-release"),
                    covered_action_ids: vec![ActionId::new("action-1"), ActionId::new("action-2")],
                    label: "Remove complete APFS release set".into(),
                    prerequisite_unit_ids: Vec::new(),
                    prerequisite_status: "ready".into(),
                },
                ExecutionUnitProjection {
                    id: ExecutionUnitId::new("unit-follow-up"),
                    covered_action_ids: vec![ActionId::new("action-3")],
                    label: "Remove dependent target".into(),
                    prerequisite_unit_ids: vec![ExecutionUnitId::new("unit-apfs-release")],
                    prerequisite_status: "unit-apfs-release ready".into(),
                },
            ],
            final_warnings: vec![ExecutionWarningProjection {
                id: ExecutionWarningId::new("warning-path-race"),
                message: "residual pathname race remains".into(),
            }],
        };

        let mut mismatched = projection.clone();
        mismatched.overlay_digest = "different-overlay".into();
        assert_eq!(
            runtime.apply_event(PlanRuntimeEvent::ExecutionPreviewReady(mismatched)),
            Err(PlanRuntimeError::InvalidExecutionPreview)
        );
        assert!(runtime.execution_preview().is_none());

        let mut duplicate_coverage = projection.clone();
        duplicate_coverage.ordered_units[1]
            .covered_action_ids
            .push(ActionId::new("action-2"));
        assert_eq!(
            runtime.apply_event(PlanRuntimeEvent::ExecutionPreviewReady(duplicate_coverage)),
            Err(PlanRuntimeError::InvalidExecutionPreview)
        );

        let mut extra_coverage = projection.clone();
        extra_coverage.ordered_units[1]
            .covered_action_ids
            .push(ActionId::new("action-not-selected"));
        assert_eq!(
            runtime.apply_event(PlanRuntimeEvent::ExecutionPreviewReady(extra_coverage)),
            Err(PlanRuntimeError::InvalidExecutionPreview)
        );

        let mut invalid_dag = projection.clone();
        invalid_dag.ordered_units[0].prerequisite_unit_ids =
            vec![ExecutionUnitId::new("unit-follow-up")];
        assert_eq!(
            runtime.apply_event(PlanRuntimeEvent::ExecutionPreviewReady(invalid_dag)),
            Err(PlanRuntimeError::InvalidExecutionPreview)
        );

        runtime
            .apply_event(PlanRuntimeEvent::ExecutionPreviewReady(projection))
            .unwrap();
        assert_eq!(runtime.view(), PlanView::ExecutionPreview);
        assert!(runtime.execution_preview().is_some());

        runtime.set_view(PlanView::Summary);
        assert_eq!(
            runtime.toggle_selected_stage(),
            OverlayStageResult::Unstaged
        );
        assert!(runtime.execution_preview().is_none());
        assert!(!runtime.set_view(PlanView::ExecutionPreview));
    }

    #[test]
    fn layout_reserves_runtime_headers_before_tree_viewport() {
        let mut runtime = runtime_with_action_count(
            20,
            false,
            Stageability::Stageable,
            ForceRequirement::NotRequired,
        );
        runtime.resize_layout(80, 24);
        assert_eq!(runtime.model().viewport_height(), 14);
        runtime.resize_layout(40, 12);
        assert_eq!(runtime.model().viewport_height(), 4);
        runtime.move_navigation(21);
        assert_eq!(
            runtime.selected_action_id(),
            Some(&ActionId::new("action-20"))
        );
        assert!(runtime.model().viewport_top() > 0);
        assert!(
            runtime
                .model()
                .visible_rows()
                .iter()
                .any(|row| row.key == RowKey::Action(ActionId::new("action-20")))
        );
    }

    #[test]
    fn replacement_attempt_and_evidence_change_revoke_old_consent() {
        let mut changed_runtime = runtime(
            false,
            Stageability::Stageable,
            ForceRequirement::NotRequired,
        );
        select_action(&mut changed_runtime);
        assert!(matches!(
            changed_runtime.toggle_selected_stage(),
            OverlayStageResult::Staged { .. }
        ));

        changed_runtime
            .apply_event(PlanRuntimeEvent::EvidenceChanged {
                plan_id: PlanId::new("plan-1"),
                evidence_reference: "evidence-2".into(),
            })
            .unwrap();
        assert!(changed_runtime.overlay().is_none());
        assert!(changed_runtime.model().current_plan_id().is_none());

        let mut runtime = runtime(
            false,
            Stageability::Stageable,
            ForceRequirement::NotRequired,
        );
        select_action(&mut runtime);
        assert!(matches!(
            runtime.toggle_selected_stage(),
            OverlayStageResult::Staged { .. }
        ));
        let error = runtime
            .apply_event(PlanRuntimeEvent::Load(EnginePlanSnapshot {
                projection: PlanProjection {
                    id: PlanId::new(""),
                    actions: Vec::new(),
                    release_sets: Vec::new(),
                },
                evidence_reference: "invalid".into(),
                provisional: false,
            }))
            .unwrap_err();
        assert!(matches!(error, PlanRuntimeError::InvalidProjection(_)));
        assert!(runtime.overlay().is_none());
        assert!(runtime.model().current_plan_id().is_none());
    }

    fn runtime(
        provisional: bool,
        stageability: Stageability,
        force: ForceRequirement,
    ) -> PlanRuntime {
        runtime_with_action_count(1, provisional, stageability, force)
    }

    fn runtime_with_action_count(
        action_count: usize,
        provisional: bool,
        stageability: Stageability,
        force: ForceRequirement,
    ) -> PlanRuntime {
        let mut runtime = PlanRuntime::default();
        runtime
            .apply_event(PlanRuntimeEvent::Load(EnginePlanSnapshot {
                projection: PlanProjection {
                    id: PlanId::new("plan-1"),
                    actions: (1..=action_count)
                        .map(|index| ActionProjection {
                            id: ActionId::new(format!("action-{index}")),
                            disposition: PlanDisposition::Ready,
                            kind: ActionKindProjection {
                                id: ActionKindId::new("generic-remove"),
                                label: "Generic remove".into(),
                                order: 1,
                            },
                            label: format!("Remove engine candidate {index}"),
                            order: index as u64,
                            stageability: stageability.clone(),
                            immediate_reclaim: ByteValue::Known(4096),
                            shared_unlock: ByteValue::Unknown,
                            activity: Activity::Inactive,
                            recoverability: Recoverability::Rebuildable,
                            blockers: Vec::new(),
                            prerequisites: Vec::new(),
                            release_set_ids: Vec::new(),
                            force: force.clone(),
                            path_race: PathRace::Residual,
                            targets: vec![TargetProjection {
                                id: TargetId::new(format!("target-{index}")),
                                display_path: DisplayPath::new(format!(
                                    "/engine/display/path/{index}"
                                )),
                                kind: TargetKind::Directory,
                                children: Vec::new(),
                            }],
                        })
                        .collect(),
                    release_sets: Vec::<ReleaseSetProjection>::new(),
                },
                evidence_reference: "evidence-1".into(),
                provisional,
            }))
            .unwrap();
        runtime
    }

    fn select_action(runtime: &mut PlanRuntime) {
        runtime.move_navigation(2);
        assert_eq!(
            runtime.selected_action_id(),
            Some(&ActionId::new("action-1"))
        );
    }
}
