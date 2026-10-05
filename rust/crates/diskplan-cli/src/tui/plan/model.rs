use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;

use super::types::{
    ActionId, ActionKindId, ActionKindProjection, ActionProjection, ByteValue, ForceRequirement,
    PlanDisposition, PlanId, PlanProjection, ReleaseSetId, ReleaseSetProjection, Stageability,
    TargetId, TargetKind, TargetProjection, WaiverId,
};

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub enum RowKey {
    Disposition(PlanDisposition),
    ActionKind {
        disposition: PlanDisposition,
        kind_id: ActionKindId,
    },
    Action(ActionId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RowLevel {
    Disposition,
    ActionKind,
    Action,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ViewRow {
    pub key: RowKey,
    pub level: RowLevel,
    pub label: String,
    pub expanded: Option<bool>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum PlanColumn {
    Decision,
    PlanAction,
    ImmediateReclaim,
    SharedUnlock,
    Activity,
    Recoverability,
    StatusBlocker,
}

impl PlanColumn {
    pub const DEFAULT_ORDER: [Self; 7] = [
        Self::Decision,
        Self::PlanAction,
        Self::ImmediateReclaim,
        Self::SharedUnlock,
        Self::Activity,
        Self::Recoverability,
        Self::StatusBlocker,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Decision => "Decision",
            Self::PlanAction => "Plan/action",
            Self::ImmediateReclaim => "Immediate reclaim",
            Self::SharedUnlock => "Shared unlock",
            Self::Activity => "Activity",
            Self::Recoverability => "Recoverability",
            Self::StatusBlocker => "Status/blocker",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PlanSearchField {
    PlanAction,
    ActionKind,
    Disposition,
    StatusBlocker,
}

/// Main-tree filtering is stable across column configuration and never searches target paths.
pub const PLAN_SEARCH_FIELDS: [PlanSearchField; 4] = [
    PlanSearchField::PlanAction,
    PlanSearchField::ActionKind,
    PlanSearchField::Disposition,
    PlanSearchField::StatusBlocker,
];

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct TargetRowKey {
    pub action_id: ActionId,
    pub target_id: TargetId,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetViewRow {
    pub key: TargetRowKey,
    pub depth: usize,
    pub display_path: String,
    pub kind: TargetKind,
    pub expanded: Option<bool>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum SortMode {
    #[default]
    EngineOrder,
    LabelAscending,
    ImmediateReclaimDescending,
    SharedUnlockDescending,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct InvalidatedPlan {
    pub id: PlanId,
    pub reason: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum PlanModelError {
    EmptyPlanId,
    EmptyActionId,
    DuplicateActionId(ActionId),
    EmptyActionLabel(ActionId),
    EmptyActionKindId(ActionId),
    EmptyActionKindLabel(ActionKindId),
    InconsistentActionKind(ActionKindId),
    EmptyReleaseSetId,
    DuplicateReleaseSetId(ReleaseSetId),
    EmptyReleaseSet(ReleaseSetId),
    DuplicateReleaseSetAction {
        release_set_id: ReleaseSetId,
        action_id: ActionId,
    },
    UnknownReleaseSetAction {
        release_set_id: ReleaseSetId,
        action_id: ActionId,
    },
    UnknownActionReleaseSet {
        action_id: ActionId,
        release_set_id: ReleaseSetId,
    },
    DuplicateActionReleaseSet {
        action_id: ActionId,
        release_set_id: ReleaseSetId,
    },
    ReleaseSetMembershipMismatch {
        action_id: ActionId,
        release_set_id: ReleaseSetId,
    },
    EmptyRequiredWaiverSet(ActionId),
    EmptyWaiverId(ActionId),
    DuplicateWaiverId {
        action_id: ActionId,
        waiver_id: WaiverId,
    },
    EmptyBlockerId(ActionId),
    DuplicateBlockerId {
        action_id: ActionId,
        blocker_id: super::types::BlockerId,
    },
    EmptyBlockerSummary {
        action_id: ActionId,
        blocker_id: super::types::BlockerId,
    },
    EmptyForceReason(ActionId),
    EmptyPrerequisiteSummary {
        action_id: ActionId,
        prerequisite_id: ActionId,
    },
    UnknownPrerequisite {
        action_id: ActionId,
        prerequisite_id: ActionId,
    },
    DuplicatePrerequisite {
        action_id: ActionId,
        prerequisite_id: ActionId,
    },
    SelfPrerequisite(ActionId),
    EmptyTargetId(ActionId),
    DuplicateTargetId {
        action_id: ActionId,
        target_id: super::types::TargetId,
    },
    EmptyTargetDisplayPath {
        action_id: ActionId,
        target_id: super::types::TargetId,
    },
}

impl fmt::Display for PlanModelError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(formatter, "invalid engine plan projection: {self:?}")
    }
}

impl Error for PlanModelError {}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum InvalidationError {
    NoLoadedPlan,
    PlanIdMismatch { expected: PlanId, actual: PlanId },
}

impl fmt::Display for InvalidationError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NoLoadedPlan => formatter.write_str("no loaded plan can be invalidated"),
            Self::PlanIdMismatch { expected, actual } => write!(
                formatter,
                "plan invalidation ID mismatch: loaded {expected}, received {actual}"
            ),
        }
    }
}

impl Error for InvalidationError {}

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
struct GroupKey {
    disposition: PlanDisposition,
    kind_id: ActionKindId,
}

#[derive(Clone, Debug)]
struct ActionGroup {
    key: GroupKey,
    kind: ActionKindProjection,
    action_indices: Vec<usize>,
    sort_mode: SortMode,
}

#[derive(Clone, Debug)]
struct TargetNode {
    key: TargetRowKey,
    parent: Option<usize>,
    depth: usize,
    display_path: String,
    kind: TargetKind,
    has_children: bool,
    search_text: String,
}

#[derive(Clone, Debug, Default)]
struct TargetTree {
    nodes: Vec<TargetNode>,
    positions: HashMap<TargetRowKey, usize>,
}

struct ProjectionIndexes {
    action_positions: HashMap<ActionId, usize>,
    release_set_positions: HashMap<ReleaseSetId, usize>,
    target_trees: HashMap<ActionId, TargetTree>,
}

#[derive(Clone, Debug)]
struct LoadedPlan {
    projection: PlanProjection,
    groups: Vec<ActionGroup>,
    group_positions: HashMap<GroupKey, usize>,
    action_positions: HashMap<ActionId, usize>,
    release_set_positions: HashMap<ReleaseSetId, usize>,
    action_search_texts: Vec<String>,
    target_trees: HashMap<ActionId, TargetTree>,
}

#[derive(Clone, Debug)]
enum PlanState {
    Empty,
    Loaded(Box<LoadedPlan>),
    Invalidated(InvalidatedPlan),
}

#[cfg(test)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(super) struct CacheMetrics {
    pub row_cache_rebuilds: usize,
    pub group_sorts: usize,
    pub search_index_builds: usize,
    pub target_row_cache_rebuilds: usize,
}

#[derive(Clone, Debug)]
pub struct PlanModel {
    state: PlanState,
    expanded_dispositions: HashSet<PlanDisposition>,
    expanded_groups: HashSet<GroupKey>,
    filter: String,
    visible_keys: Vec<RowKey>,
    row_positions: HashMap<RowKey, usize>,
    cursor: Option<RowKey>,
    cursor_index_hint: usize,
    viewport_top: usize,
    viewport_height: usize,
    column_order: Vec<PlanColumn>,
    hidden_columns: HashSet<PlanColumn>,
    target_action: Option<ActionId>,
    expanded_targets: HashSet<TargetRowKey>,
    target_filter: String,
    target_visible_indices: Vec<usize>,
    target_row_positions: HashMap<TargetRowKey, usize>,
    target_match_or_ancestor: Vec<bool>,
    target_visible_flags: Vec<bool>,
    target_cursor: Option<TargetRowKey>,
    target_cursor_index_hint: usize,
    target_viewport_top: usize,
    target_viewport_height: usize,
    #[cfg(test)]
    cache_metrics: CacheMetrics,
}

impl Default for PlanModel {
    fn default() -> Self {
        Self {
            state: PlanState::Empty,
            expanded_dispositions: HashSet::new(),
            expanded_groups: HashSet::new(),
            filter: String::new(),
            visible_keys: Vec::new(),
            row_positions: HashMap::new(),
            cursor: None,
            cursor_index_hint: 0,
            viewport_top: 0,
            viewport_height: 0,
            column_order: PlanColumn::DEFAULT_ORDER.to_vec(),
            hidden_columns: HashSet::new(),
            target_action: None,
            expanded_targets: HashSet::new(),
            target_filter: String::new(),
            target_visible_indices: Vec::new(),
            target_row_positions: HashMap::new(),
            target_match_or_ancestor: Vec::new(),
            target_visible_flags: Vec::new(),
            target_cursor: None,
            target_cursor_index_hint: 0,
            target_viewport_top: 0,
            target_viewport_height: 0,
            #[cfg(test)]
            cache_metrics: CacheMetrics::default(),
        }
    }
}

impl PlanModel {
    pub fn load(&mut self, projection: PlanProjection) -> Result<(), PlanModelError> {
        let indexes = match validate_projection(&projection) {
            Ok(indexes) => indexes,
            Err(error) => {
                // A rejected replacement must not leave the previous plan actionable.
                self.reset();
                return Err(error);
            }
        };
        let groups = build_groups(&projection);
        let group_positions = groups
            .iter()
            .enumerate()
            .map(|(index, group)| (group.key.clone(), index))
            .collect();
        let action_search_texts = build_action_search_index(&projection);
        self.expanded_dispositions = groups.iter().map(|group| group.key.disposition).collect();
        self.expanded_groups = groups.iter().map(|group| group.key.clone()).collect();
        self.filter.clear();
        self.state = PlanState::Loaded(Box::new(LoadedPlan {
            projection,
            groups,
            group_positions,
            action_positions: indexes.action_positions,
            release_set_positions: indexes.release_set_positions,
            action_search_texts,
            target_trees: indexes.target_trees,
        }));
        #[cfg(test)]
        {
            self.cache_metrics.search_index_builds += 1;
        }
        self.rebuild_visible_keys();
        self.cursor = self.visible_keys.first().cloned();
        self.cursor_index_hint = 0;
        self.viewport_top = 0;
        self.clear_target_view_state();
        self.ensure_cursor_visible();
        Ok(())
    }

    pub fn invalidate(
        &mut self,
        plan_id: PlanId,
        reason: impl Into<String>,
    ) -> Result<(), InvalidationError> {
        let PlanState::Loaded(loaded) = &self.state else {
            return Err(InvalidationError::NoLoadedPlan);
        };
        if loaded.projection.id != plan_id {
            return Err(InvalidationError::PlanIdMismatch {
                expected: loaded.projection.id.clone(),
                actual: plan_id,
            });
        }
        self.state = PlanState::Invalidated(InvalidatedPlan {
            id: plan_id,
            reason: reason.into(),
        });
        self.clear_view_state();
        Ok(())
    }

    pub fn reset(&mut self) {
        self.state = PlanState::Empty;
        self.clear_view_state();
    }

    pub fn current_plan_id(&self) -> Option<&PlanId> {
        match &self.state {
            PlanState::Loaded(loaded) => Some(&loaded.projection.id),
            PlanState::Empty | PlanState::Invalidated(_) => None,
        }
    }

    pub fn invalidated(&self) -> Option<&InvalidatedPlan> {
        match &self.state {
            PlanState::Invalidated(invalidated) => Some(invalidated),
            PlanState::Empty | PlanState::Loaded(_) => None,
        }
    }

    pub fn cursor(&self) -> Option<&RowKey> {
        self.cursor.as_ref()
    }

    pub fn viewport_top(&self) -> usize {
        self.viewport_top
    }

    pub fn viewport_height(&self) -> usize {
        self.viewport_height
    }

    pub fn row_count(&self) -> usize {
        self.visible_keys.len()
    }

    pub fn column_order(&self) -> &[PlanColumn] {
        &self.column_order
    }

    pub fn visible_columns(&self) -> Vec<PlanColumn> {
        self.column_order
            .iter()
            .copied()
            .filter(|column| !self.hidden_columns.contains(column))
            .collect()
    }

    /// `Plan/action` is the stable hierarchy anchor and cannot be hidden.
    pub fn set_column_visible(&mut self, column: PlanColumn, visible: bool) -> bool {
        if column == PlanColumn::PlanAction && !visible {
            return false;
        }
        if visible {
            self.hidden_columns.remove(&column)
        } else {
            self.hidden_columns.insert(column)
        }
    }

    pub fn move_column(&mut self, column: PlanColumn, new_index: usize) -> bool {
        let Some(old_index) = self
            .column_order
            .iter()
            .position(|candidate| *candidate == column)
        else {
            return false;
        };
        let bounded_index = new_index.min(self.column_order.len().saturating_sub(1));
        if old_index == bounded_index {
            return false;
        }
        self.column_order.remove(old_index);
        self.column_order.insert(bounded_index, column);
        true
    }

    pub fn search_fields(&self) -> &'static [PlanSearchField] {
        &PLAN_SEARCH_FIELDS
    }

    /// Materializes only the current viewport, even when the plan is large.
    pub fn visible_rows(&self) -> Vec<ViewRow> {
        if self.viewport_height == 0 {
            return Vec::new();
        }
        let end = self
            .viewport_top
            .saturating_add(self.viewport_height)
            .min(self.visible_keys.len());
        let available = end.saturating_sub(self.viewport_top);
        let mut rows = Vec::with_capacity(self.viewport_height.min(available));
        rows.extend(
            self.visible_keys[self.viewport_top.min(end)..end]
                .iter()
                .cloned()
                .map(|key| self.materialize_row(key)),
        );
        rows
    }

    pub fn resize(&mut self, viewport_height: usize) {
        self.viewport_height = viewport_height;
        self.ensure_cursor_visible();
    }

    pub fn open_targets(&mut self, action_id: &ActionId) -> bool {
        let Some(tree) = self
            .loaded()
            .and_then(|loaded| loaded.target_trees.get(action_id))
        else {
            return false;
        };
        let action_id = action_id.clone();
        let expanded = tree
            .nodes
            .iter()
            .filter(|node| node.has_children)
            .map(|node| node.key.clone())
            .collect();
        self.clear_target_view_state();
        self.target_action = Some(action_id);
        self.expanded_targets = expanded;
        self.rebuild_target_visible_indices();
        self.target_cursor = self.target_key_at(0);
        self.ensure_target_cursor_visible();
        true
    }

    pub fn close_targets(&mut self) {
        self.clear_target_view_state();
    }

    pub fn target_action_id(&self) -> Option<&ActionId> {
        self.target_action.as_ref()
    }

    pub fn target_cursor(&self) -> Option<&TargetRowKey> {
        self.target_cursor.as_ref()
    }

    pub fn target_row_count(&self) -> usize {
        self.target_visible_indices.len()
    }

    pub fn target_viewport_top(&self) -> usize {
        self.target_viewport_top
    }

    pub fn target_viewport_height(&self) -> usize {
        self.target_viewport_height
    }

    pub fn visible_target_rows(&self) -> Vec<TargetViewRow> {
        if self.target_viewport_height == 0 {
            return Vec::new();
        }
        let end = self
            .target_viewport_top
            .saturating_add(self.target_viewport_height)
            .min(self.target_visible_indices.len());
        let available = end.saturating_sub(self.target_viewport_top);
        let mut rows = Vec::with_capacity(self.target_viewport_height.min(available));
        rows.extend(
            self.target_visible_indices[self.target_viewport_top.min(end)..end]
                .iter()
                .filter_map(|node_index| self.materialize_target_row(*node_index)),
        );
        rows
    }

    pub fn resize_targets(&mut self, viewport_height: usize) {
        self.target_viewport_height = viewport_height;
        self.ensure_target_cursor_visible();
    }

    pub fn move_target_cursor(&mut self, delta: isize) {
        let count = self.target_row_count();
        if count == 0 {
            self.target_cursor = None;
            self.target_cursor_index_hint = 0;
            self.target_viewport_top = 0;
            return;
        }
        let current = self
            .target_cursor_index()
            .unwrap_or(self.target_cursor_index_hint.min(count - 1));
        let next = current.saturating_add_signed(delta).min(count - 1);
        self.target_cursor = self.target_key_at(next);
        self.target_cursor_index_hint = next;
        self.ensure_target_cursor_visible();
    }

    pub fn select_target(&mut self, key: &TargetRowKey) -> bool {
        let Some(index) = self.target_index_of(key) else {
            return false;
        };
        self.target_cursor = Some(key.clone());
        self.target_cursor_index_hint = index;
        self.ensure_target_cursor_visible();
        true
    }

    pub fn toggle_target_expanded(&mut self, key: &TargetRowKey) -> bool {
        self.set_target_expanded(key, None)
    }

    pub fn set_target_row_expanded(&mut self, key: &TargetRowKey, expanded: bool) -> bool {
        self.set_target_expanded(key, Some(expanded))
    }

    fn set_target_expanded(&mut self, key: &TargetRowKey, expanded: Option<bool>) -> bool {
        if self.target_filter_is_active() {
            return false;
        }
        let Some(node) = self.target_node(key) else {
            return false;
        };
        if !node.has_children {
            return false;
        }
        let old_index = self
            .target_cursor_index()
            .unwrap_or(self.target_cursor_index_hint);
        set_membership(&mut self.expanded_targets, key.clone(), expanded);
        self.rebuild_target_visible_indices();
        self.reconcile_target_cursor(old_index);
        true
    }

    /// Target filtering searches display paths only within the selected action.
    pub fn set_target_filter(&mut self, query: impl Into<String>) {
        let old_index = self
            .target_cursor_index()
            .unwrap_or(self.target_cursor_index_hint);
        let filter = query.into().trim().to_lowercase();
        if self.target_filter == filter {
            return;
        }
        self.target_filter = filter;
        self.rebuild_target_visible_indices();
        self.reconcile_target_cursor(old_index);
    }

    pub fn target_filter(&self) -> &str {
        &self.target_filter
    }

    pub fn move_cursor(&mut self, delta: isize) {
        let count = self.row_count();
        if count == 0 {
            self.cursor = None;
            self.cursor_index_hint = 0;
            self.viewport_top = 0;
            return;
        }
        let current = self
            .cursor_index()
            .unwrap_or(self.cursor_index_hint.min(count - 1));
        let next = current.saturating_add_signed(delta).min(count - 1);
        self.cursor = self.row_key_at(next);
        self.cursor_index_hint = next;
        self.ensure_cursor_visible();
    }

    pub fn select(&mut self, key: &RowKey) -> bool {
        let Some(index) = self.index_of(key) else {
            return false;
        };
        self.cursor = Some(key.clone());
        self.cursor_index_hint = index;
        self.ensure_cursor_visible();
        true
    }

    pub fn toggle_expanded(&mut self, key: &RowKey) -> bool {
        self.set_expanded(key, None)
    }

    /// Changes expansion without letting input handling accidentally invert it.
    pub fn set_row_expanded(&mut self, key: &RowKey, expanded: bool) -> bool {
        self.set_expanded(key, Some(expanded))
    }

    fn set_expanded(&mut self, key: &RowKey, expanded: Option<bool>) -> bool {
        let old_index = self.cursor_index().unwrap_or(self.cursor_index_hint);
        let changed = match key {
            RowKey::Disposition(disposition) => {
                set_membership(&mut self.expanded_dispositions, *disposition, expanded)
            }
            RowKey::ActionKind {
                disposition,
                kind_id,
            } => set_membership(
                &mut self.expanded_groups,
                GroupKey {
                    disposition: *disposition,
                    kind_id: kind_id.clone(),
                },
                expanded,
            ),
            RowKey::Action(_) => false,
        };
        if changed {
            self.rebuild_visible_keys();
            self.reconcile_cursor(old_index);
        }
        changed
    }

    pub fn set_filter(&mut self, query: impl Into<String>) {
        let old_index = self.cursor_index().unwrap_or(self.cursor_index_hint);
        let filter = query.into().trim().to_lowercase();
        if self.filter == filter {
            return;
        }
        self.filter = filter;
        self.rebuild_visible_keys();
        self.reconcile_cursor(old_index);
    }

    pub fn filter(&self) -> &str {
        &self.filter
    }

    pub fn set_group_sort(
        &mut self,
        disposition: PlanDisposition,
        kind_id: ActionKindId,
        mode: SortMode,
    ) -> bool {
        let group_key = GroupKey {
            disposition,
            kind_id,
        };
        let old_index = self.cursor_index().unwrap_or(self.cursor_index_hint);
        let changed = {
            let PlanState::Loaded(loaded) = &mut self.state else {
                return false;
            };
            let Some(group_position) = loaded.group_positions.get(&group_key).copied() else {
                return false;
            };
            let group = &mut loaded.groups[group_position];
            if group.sort_mode == mode {
                false
            } else {
                group.sort_mode = mode;
                group.action_indices.sort_by(|left, right| {
                    compare_actions(
                        &loaded.projection.actions[*left],
                        &loaded.projection.actions[*right],
                        mode,
                    )
                });
                true
            }
        };
        if changed {
            #[cfg(test)]
            {
                self.cache_metrics.group_sorts += 1;
            }
            self.rebuild_visible_keys();
            self.reconcile_cursor(old_index);
        }
        true
    }

    /// Returns engine-supplied targets only for an action detail view.
    pub fn action_targets(&self, action_id: &ActionId) -> Option<&[TargetProjection]> {
        self.action(action_id)
            .map(|action| action.targets.as_slice())
    }

    pub fn action(&self, action_id: &ActionId) -> Option<&ActionProjection> {
        let loaded = self.loaded()?;
        let position = loaded.action_positions.get(action_id)?;
        loaded.projection.actions.get(*position)
    }

    pub fn release_set(&self, release_set_id: &ReleaseSetId) -> Option<&ReleaseSetProjection> {
        let loaded = self.loaded()?;
        let position = loaded.release_set_positions.get(release_set_id)?;
        loaded.projection.release_sets.get(*position)
    }

    #[cfg(test)]
    pub(super) fn cache_metrics(&self) -> CacheMetrics {
        self.cache_metrics
    }

    #[cfg(test)]
    pub(super) fn row_cache_capacities(&self) -> (usize, usize) {
        (self.visible_keys.capacity(), self.row_positions.capacity())
    }

    #[cfg(test)]
    pub(super) fn target_cache_capacities(&self) -> (usize, usize, usize) {
        (
            self.target_visible_indices.capacity(),
            self.target_row_positions.capacity(),
            self.target_match_or_ancestor.capacity(),
        )
    }

    fn loaded(&self) -> Option<&LoadedPlan> {
        match &self.state {
            PlanState::Loaded(loaded) => Some(loaded.as_ref()),
            PlanState::Empty | PlanState::Invalidated(_) => None,
        }
    }

    fn clear_view_state(&mut self) {
        self.expanded_dispositions.clear();
        self.expanded_groups.clear();
        self.filter.clear();
        self.visible_keys.clear();
        self.row_positions.clear();
        self.cursor = None;
        self.cursor_index_hint = 0;
        self.viewport_top = 0;
        self.clear_target_view_state();
    }

    fn filter_is_active(&self) -> bool {
        !self.filter.is_empty()
    }

    fn disposition_expanded(&self, disposition: PlanDisposition) -> bool {
        self.filter_is_active() || self.expanded_dispositions.contains(&disposition)
    }

    fn group_expanded(&self, key: &GroupKey) -> bool {
        self.filter_is_active() || self.expanded_groups.contains(key)
    }

    fn rebuild_visible_keys(&mut self) {
        self.visible_keys.clear();
        if let PlanState::Loaded(loaded) = &self.state {
            append_visible_keys(
                loaded,
                &self.expanded_dispositions,
                &self.expanded_groups,
                &self.filter,
                &mut self.visible_keys,
            );
        }
        self.row_positions.clear();
        self.row_positions.extend(
            self.visible_keys
                .iter()
                .cloned()
                .enumerate()
                .map(|(index, key)| (key, index)),
        );
        #[cfg(test)]
        {
            self.cache_metrics.row_cache_rebuilds += 1;
        }
    }

    fn row_key_at(&self, wanted: usize) -> Option<RowKey> {
        self.visible_keys.get(wanted).cloned()
    }

    fn index_of(&self, wanted: &RowKey) -> Option<usize> {
        self.row_positions.get(wanted).copied()
    }

    fn cursor_index(&self) -> Option<usize> {
        self.cursor.as_ref().and_then(|key| self.index_of(key))
    }

    fn reconcile_cursor(&mut self, old_index: usize) {
        if let Some(cursor) = &self.cursor
            && let Some(index) = self.index_of(cursor)
        {
            self.cursor_index_hint = index;
            self.ensure_cursor_visible();
            return;
        }
        let count = self.row_count();
        if count == 0 {
            self.cursor = None;
            self.cursor_index_hint = 0;
            self.viewport_top = 0;
            return;
        }
        let index = old_index.min(count - 1);
        self.cursor = self.row_key_at(index);
        self.cursor_index_hint = index;
        self.ensure_cursor_visible();
    }

    fn ensure_cursor_visible(&mut self) {
        let Some(index) = self.cursor_index() else {
            self.viewport_top = 0;
            return;
        };
        self.cursor_index_hint = index;
        if self.viewport_height == 0 {
            self.viewport_top = index;
            return;
        }
        if index < self.viewport_top {
            self.viewport_top = index;
        } else if index >= self.viewport_top.saturating_add(self.viewport_height) {
            self.viewport_top = index + 1 - self.viewport_height;
        }
        let max_top = self.row_count().saturating_sub(self.viewport_height);
        self.viewport_top = self.viewport_top.min(max_top);
    }

    fn materialize_row(&self, key: RowKey) -> ViewRow {
        match key {
            RowKey::Disposition(disposition) => ViewRow {
                key: RowKey::Disposition(disposition),
                level: RowLevel::Disposition,
                label: disposition.label().to_owned(),
                expanded: Some(self.disposition_expanded(disposition)),
            },
            RowKey::ActionKind {
                disposition,
                kind_id,
            } => {
                let group_key = GroupKey {
                    disposition,
                    kind_id: kind_id.clone(),
                };
                let label = self
                    .loaded()
                    .and_then(|loaded| {
                        loaded
                            .group_positions
                            .get(&group_key)
                            .and_then(|position| loaded.groups.get(*position))
                    })
                    .map(|group| group.kind.label.clone())
                    .unwrap_or_default();
                ViewRow {
                    key: RowKey::ActionKind {
                        disposition,
                        kind_id,
                    },
                    level: RowLevel::ActionKind,
                    label,
                    expanded: Some(self.group_expanded(&group_key)),
                }
            }
            RowKey::Action(action_id) => ViewRow {
                label: self
                    .action(&action_id)
                    .map(|action| action.label.clone())
                    .unwrap_or_default(),
                key: RowKey::Action(action_id),
                level: RowLevel::Action,
                expanded: None,
            },
        }
    }

    fn clear_target_view_state(&mut self) {
        self.target_action = None;
        self.expanded_targets.clear();
        self.target_filter.clear();
        self.target_visible_indices.clear();
        self.target_row_positions.clear();
        self.target_match_or_ancestor.clear();
        self.target_visible_flags.clear();
        self.target_cursor = None;
        self.target_cursor_index_hint = 0;
        self.target_viewport_top = 0;
    }

    fn target_tree(&self) -> Option<&TargetTree> {
        let action_id = self.target_action.as_ref()?;
        self.loaded()?.target_trees.get(action_id)
    }

    fn target_node(&self, key: &TargetRowKey) -> Option<&TargetNode> {
        let tree = self.target_tree()?;
        tree.positions
            .get(key)
            .and_then(|position| tree.nodes.get(*position))
    }

    fn target_filter_is_active(&self) -> bool {
        !self.target_filter.is_empty()
    }

    fn rebuild_target_visible_indices(&mut self) {
        self.target_visible_indices.clear();
        self.target_row_positions.clear();
        let filter_active = !self.target_filter.is_empty();
        let Some(action_id) = self.target_action.as_ref() else {
            self.target_match_or_ancestor.clear();
            self.target_visible_flags.clear();
            return;
        };
        let PlanState::Loaded(loaded) = &self.state else {
            self.target_match_or_ancestor.clear();
            self.target_visible_flags.clear();
            return;
        };
        let Some(tree) = loaded.target_trees.get(action_id) else {
            self.target_match_or_ancestor.clear();
            self.target_visible_flags.clear();
            return;
        };

        let nodes = &tree.nodes;
        self.target_match_or_ancestor.clear();
        self.target_match_or_ancestor.resize(nodes.len(), false);
        if filter_active {
            for (index, node) in nodes.iter().enumerate() {
                self.target_match_or_ancestor[index] =
                    node.search_text.contains(&self.target_filter);
            }
            for index in (0..nodes.len()).rev() {
                if self.target_match_or_ancestor[index]
                    && let Some(parent) = nodes[index].parent
                {
                    self.target_match_or_ancestor[parent] = true;
                }
            }
        }

        self.target_visible_flags.clear();
        self.target_visible_flags.resize(nodes.len(), false);
        for (index, node) in nodes.iter().enumerate() {
            let visible = if filter_active {
                self.target_match_or_ancestor[index]
            } else if let Some(parent) = node.parent {
                self.target_visible_flags[parent]
                    && self.expanded_targets.contains(&nodes[parent].key)
            } else {
                true
            };
            self.target_visible_flags[index] = visible;
            if visible {
                self.target_row_positions
                    .insert(node.key.clone(), self.target_visible_indices.len());
                self.target_visible_indices.push(index);
            }
        }
        #[cfg(test)]
        {
            self.cache_metrics.target_row_cache_rebuilds += 1;
        }
    }

    fn target_key_at(&self, wanted: usize) -> Option<TargetRowKey> {
        let node_index = *self.target_visible_indices.get(wanted)?;
        self.target_tree()?
            .nodes
            .get(node_index)
            .map(|node| node.key.clone())
    }

    fn target_index_of(&self, wanted: &TargetRowKey) -> Option<usize> {
        self.target_row_positions.get(wanted).copied()
    }

    fn target_cursor_index(&self) -> Option<usize> {
        self.target_cursor
            .as_ref()
            .and_then(|key| self.target_index_of(key))
    }

    fn reconcile_target_cursor(&mut self, old_index: usize) {
        if let Some(cursor) = &self.target_cursor
            && let Some(index) = self.target_index_of(cursor)
        {
            self.target_cursor_index_hint = index;
            self.ensure_target_cursor_visible();
            return;
        }
        let count = self.target_row_count();
        if count == 0 {
            self.target_cursor = None;
            self.target_cursor_index_hint = 0;
            self.target_viewport_top = 0;
            return;
        }
        let index = old_index.min(count - 1);
        self.target_cursor = self.target_key_at(index);
        self.target_cursor_index_hint = index;
        self.ensure_target_cursor_visible();
    }

    fn ensure_target_cursor_visible(&mut self) {
        let Some(index) = self.target_cursor_index() else {
            self.target_viewport_top = 0;
            return;
        };
        self.target_cursor_index_hint = index;
        if self.target_viewport_height == 0 {
            self.target_viewport_top = index;
            return;
        }
        if index < self.target_viewport_top {
            self.target_viewport_top = index;
        } else if index
            >= self
                .target_viewport_top
                .saturating_add(self.target_viewport_height)
        {
            self.target_viewport_top = index + 1 - self.target_viewport_height;
        }
        let max_top = self
            .target_row_count()
            .saturating_sub(self.target_viewport_height);
        self.target_viewport_top = self.target_viewport_top.min(max_top);
    }

    fn materialize_target_row(&self, node_index: usize) -> Option<TargetViewRow> {
        let node = self.target_tree()?.nodes.get(node_index)?;
        Some(TargetViewRow {
            key: node.key.clone(),
            depth: node.depth,
            display_path: node.display_path.clone(),
            kind: node.kind,
            expanded: node.has_children.then(|| {
                self.target_filter_is_active() || self.expanded_targets.contains(&node.key)
            }),
        })
    }
}

fn toggle_set<T: Eq + std::hash::Hash + Clone>(set: &mut HashSet<T>, value: T) -> bool {
    if set.remove(&value) {
        true
    } else {
        set.insert(value)
    }
}

fn set_membership<T: Eq + std::hash::Hash + Clone>(
    set: &mut HashSet<T>,
    value: T,
    wanted: Option<bool>,
) -> bool {
    match wanted {
        Some(true) => set.insert(value),
        Some(false) => set.remove(&value),
        None => toggle_set(set, value),
    }
}

fn append_visible_keys(
    loaded: &LoadedPlan,
    expanded_dispositions: &HashSet<PlanDisposition>,
    expanded_groups: &HashSet<GroupKey>,
    filter: &str,
    keys: &mut Vec<RowKey>,
) {
    let filter_active = !filter.is_empty();
    for disposition in PlanDisposition::ORDERED {
        let disposition_expanded = filter_active || expanded_dispositions.contains(&disposition);
        let mut emitted_disposition = false;
        for group in loaded
            .groups
            .iter()
            .filter(|group| group.key.disposition == disposition)
        {
            let mut matching_actions = group
                .action_indices
                .iter()
                .copied()
                .filter(|index| action_matches_filter(loaded, *index, filter))
                .peekable();
            if matching_actions.peek().is_none() {
                continue;
            }
            if !emitted_disposition {
                keys.push(RowKey::Disposition(disposition));
                emitted_disposition = true;
            }
            if !disposition_expanded {
                break;
            }
            keys.push(RowKey::ActionKind {
                disposition,
                kind_id: group.kind.id.clone(),
            });
            if filter_active || expanded_groups.contains(&group.key) {
                keys.extend(
                    matching_actions
                        .map(|index| RowKey::Action(loaded.projection.actions[index].id.clone())),
                );
            }
        }
    }
}

fn action_matches_filter(loaded: &LoadedPlan, action_index: usize, filter: &str) -> bool {
    filter.is_empty() || loaded.action_search_texts[action_index].contains(filter)
}

fn build_action_search_index(projection: &PlanProjection) -> Vec<String> {
    projection
        .actions
        .iter()
        .map(|action| {
            let blocker_bytes = action
                .blockers
                .iter()
                .map(|blocker| blocker.summary.len())
                .sum::<usize>();
            let mut text = String::with_capacity(
                action.label.len()
                    + action.id.as_str().len()
                    + action.kind.label.len()
                    + action.kind.id.as_str().len()
                    + action.disposition.label().len()
                    + blocker_bytes
                    + action.blockers.len()
                    + 4,
            );
            for field in [
                action.label.as_str(),
                action.id.as_str(),
                action.kind.label.as_str(),
                action.kind.id.as_str(),
                action.disposition.label(),
            ] {
                text.push_str(field);
                text.push('\0');
            }
            for blocker in &action.blockers {
                text.push_str(&blocker.summary);
                text.push('\0');
            }
            text.to_lowercase()
        })
        .collect()
}

fn build_groups(projection: &PlanProjection) -> Vec<ActionGroup> {
    let mut groups = Vec::<ActionGroup>::new();
    let mut positions = HashMap::<GroupKey, usize>::new();
    for (action_index, action) in projection.actions.iter().enumerate() {
        let key = GroupKey {
            disposition: action.disposition,
            kind_id: action.kind.id.clone(),
        };
        if let Some(position) = positions.get(&key).copied() {
            groups[position].action_indices.push(action_index);
        } else {
            positions.insert(key.clone(), groups.len());
            groups.push(ActionGroup {
                key,
                kind: action.kind.clone(),
                action_indices: vec![action_index],
                sort_mode: SortMode::EngineOrder,
            });
        }
    }
    for group in &mut groups {
        group.action_indices.sort_by(|left, right| {
            compare_actions(
                &projection.actions[*left],
                &projection.actions[*right],
                SortMode::EngineOrder,
            )
        });
    }
    groups.sort_by(|left, right| {
        left.key
            .disposition
            .cmp(&right.key.disposition)
            .then_with(|| left.kind.order.cmp(&right.kind.order))
            .then_with(|| left.kind.label.cmp(&right.kind.label))
            .then_with(|| left.kind.id.cmp(&right.kind.id))
    });
    groups
}

fn compare_actions(left: &ActionProjection, right: &ActionProjection, mode: SortMode) -> Ordering {
    let ordering = match mode {
        SortMode::EngineOrder => left.order.cmp(&right.order),
        SortMode::LabelAscending => left.label.cmp(&right.label),
        SortMode::ImmediateReclaimDescending => {
            compare_bytes_descending(&left.immediate_reclaim, &right.immediate_reclaim)
        }
        SortMode::SharedUnlockDescending => {
            compare_bytes_descending(&left.shared_unlock, &right.shared_unlock)
        }
    };
    ordering
        .then_with(|| left.order.cmp(&right.order))
        .then_with(|| left.id.cmp(&right.id))
}

fn compare_bytes_descending(left: &ByteValue, right: &ByteValue) -> Ordering {
    match (left, right) {
        (ByteValue::Known(left), ByteValue::Known(right)) => right.cmp(left),
        (ByteValue::Known(_), ByteValue::Unknown) => Ordering::Less,
        (ByteValue::Unknown, ByteValue::Known(_)) => Ordering::Greater,
        (ByteValue::Unknown, ByteValue::Unknown) => Ordering::Equal,
    }
}

fn validate_projection(projection: &PlanProjection) -> Result<ProjectionIndexes, PlanModelError> {
    if projection.id.as_str().trim().is_empty() {
        return Err(PlanModelError::EmptyPlanId);
    }
    let mut action_positions = HashMap::with_capacity(projection.actions.len());
    let mut kinds = HashMap::<ActionKindId, ActionKindProjection>::new();
    let mut target_trees = HashMap::with_capacity(projection.actions.len());
    for (action_position, action) in projection.actions.iter().enumerate() {
        if action.id.as_str().trim().is_empty() {
            return Err(PlanModelError::EmptyActionId);
        }
        if action_positions
            .insert(action.id.clone(), action_position)
            .is_some()
        {
            return Err(PlanModelError::DuplicateActionId(action.id.clone()));
        }
        if action.label.trim().is_empty() {
            return Err(PlanModelError::EmptyActionLabel(action.id.clone()));
        }
        if action.kind.id.as_str().trim().is_empty() {
            return Err(PlanModelError::EmptyActionKindId(action.id.clone()));
        }
        if action.kind.label.trim().is_empty() {
            return Err(PlanModelError::EmptyActionKindLabel(action.kind.id.clone()));
        }
        if let Some(existing) = kinds.get(&action.kind.id) {
            if existing != &action.kind {
                return Err(PlanModelError::InconsistentActionKind(
                    action.kind.id.clone(),
                ));
            }
        } else {
            kinds.insert(action.kind.id.clone(), action.kind.clone());
        }
        if let Stageability::RequiresWaivers(waivers) = &action.stageability {
            if waivers.is_empty() {
                return Err(PlanModelError::EmptyRequiredWaiverSet(action.id.clone()));
            }
            let mut waiver_ids = HashSet::new();
            for waiver_id in waivers {
                if waiver_id.as_str().trim().is_empty() {
                    return Err(PlanModelError::EmptyWaiverId(action.id.clone()));
                }
                if !waiver_ids.insert(waiver_id) {
                    return Err(PlanModelError::DuplicateWaiverId {
                        action_id: action.id.clone(),
                        waiver_id: waiver_id.clone(),
                    });
                }
            }
        }
        let mut blocker_ids = HashSet::new();
        for blocker in &action.blockers {
            if blocker.id.as_str().trim().is_empty() {
                return Err(PlanModelError::EmptyBlockerId(action.id.clone()));
            }
            if !blocker_ids.insert(&blocker.id) {
                return Err(PlanModelError::DuplicateBlockerId {
                    action_id: action.id.clone(),
                    blocker_id: blocker.id.clone(),
                });
            }
            if blocker.summary.trim().is_empty() {
                return Err(PlanModelError::EmptyBlockerSummary {
                    action_id: action.id.clone(),
                    blocker_id: blocker.id.clone(),
                });
            }
        }
        if let ForceRequirement::Required { reason } = &action.force
            && reason.trim().is_empty()
        {
            return Err(PlanModelError::EmptyForceReason(action.id.clone()));
        }
        target_trees.insert(
            action.id.clone(),
            validate_and_index_targets(&action.id, &action.targets)?,
        );
    }

    let mut release_set_positions = HashMap::with_capacity(projection.release_sets.len());
    let mut release_memberships = Vec::with_capacity(projection.release_sets.len());
    for (release_set_position, release_set) in projection.release_sets.iter().enumerate() {
        if release_set.id.as_str().trim().is_empty() {
            return Err(PlanModelError::EmptyReleaseSetId);
        }
        if release_set_positions
            .insert(release_set.id.clone(), release_set_position)
            .is_some()
        {
            return Err(PlanModelError::DuplicateReleaseSetId(
                release_set.id.clone(),
            ));
        }
        if release_set.action_ids.is_empty() {
            return Err(PlanModelError::EmptyReleaseSet(release_set.id.clone()));
        }
        let mut members = HashSet::with_capacity(release_set.action_ids.len());
        for action_id in &release_set.action_ids {
            if !action_positions.contains_key(action_id) {
                return Err(PlanModelError::UnknownReleaseSetAction {
                    release_set_id: release_set.id.clone(),
                    action_id: action_id.clone(),
                });
            }
            if !members.insert(action_id) {
                return Err(PlanModelError::DuplicateReleaseSetAction {
                    release_set_id: release_set.id.clone(),
                    action_id: action_id.clone(),
                });
            }
        }
        release_memberships.push(members);
    }

    let mut action_release_memberships = Vec::with_capacity(projection.actions.len());
    for action in &projection.actions {
        let mut prerequisite_ids = HashSet::new();
        for prerequisite in &action.prerequisites {
            if prerequisite.summary.trim().is_empty() {
                return Err(PlanModelError::EmptyPrerequisiteSummary {
                    action_id: action.id.clone(),
                    prerequisite_id: prerequisite.action_id.clone(),
                });
            }
            if prerequisite.action_id == action.id {
                return Err(PlanModelError::SelfPrerequisite(action.id.clone()));
            }
            if !action_positions.contains_key(&prerequisite.action_id) {
                return Err(PlanModelError::UnknownPrerequisite {
                    action_id: action.id.clone(),
                    prerequisite_id: prerequisite.action_id.clone(),
                });
            }
            if !prerequisite_ids.insert(&prerequisite.action_id) {
                return Err(PlanModelError::DuplicatePrerequisite {
                    action_id: action.id.clone(),
                    prerequisite_id: prerequisite.action_id.clone(),
                });
            }
        }
        let mut action_release_sets = HashSet::with_capacity(action.release_set_ids.len());
        for release_set_id in &action.release_set_ids {
            let Some(release_set_position) = release_set_positions.get(release_set_id).copied()
            else {
                return Err(PlanModelError::UnknownActionReleaseSet {
                    action_id: action.id.clone(),
                    release_set_id: release_set_id.clone(),
                });
            };
            if !action_release_sets.insert(release_set_id) {
                return Err(PlanModelError::DuplicateActionReleaseSet {
                    action_id: action.id.clone(),
                    release_set_id: release_set_id.clone(),
                });
            }
            if !release_memberships[release_set_position].contains(&action.id) {
                return Err(PlanModelError::ReleaseSetMembershipMismatch {
                    action_id: action.id.clone(),
                    release_set_id: release_set_id.clone(),
                });
            }
        }
        action_release_memberships.push(action_release_sets);
    }
    for release_set in &projection.release_sets {
        for action_id in &release_set.action_ids {
            let action_position = action_positions[action_id];
            if !action_release_memberships[action_position].contains(&release_set.id) {
                return Err(PlanModelError::ReleaseSetMembershipMismatch {
                    action_id: action_id.clone(),
                    release_set_id: release_set.id.clone(),
                });
            }
        }
    }
    Ok(ProjectionIndexes {
        action_positions,
        release_set_positions,
        target_trees,
    })
}

fn validate_and_index_targets(
    action_id: &ActionId,
    targets: &[TargetProjection],
) -> Result<TargetTree, PlanModelError> {
    let mut tree = TargetTree::default();
    let mut stack = Vec::with_capacity(targets.len());
    for target in targets.iter().rev() {
        stack.push((target, None, 0usize));
    }
    while let Some((target, parent, depth)) = stack.pop() {
        if target.id.as_str().trim().is_empty() {
            return Err(PlanModelError::EmptyTargetId(action_id.clone()));
        }
        let key = TargetRowKey {
            action_id: action_id.clone(),
            target_id: target.id.clone(),
        };
        if tree.positions.contains_key(&key) {
            return Err(PlanModelError::DuplicateTargetId {
                action_id: action_id.clone(),
                target_id: target.id.clone(),
            });
        }
        if target.display_path.as_str().is_empty() {
            return Err(PlanModelError::EmptyTargetDisplayPath {
                action_id: action_id.clone(),
                target_id: target.id.clone(),
            });
        }
        let node_index = tree.nodes.len();
        tree.positions.insert(key.clone(), node_index);
        tree.nodes.push(TargetNode {
            key,
            parent,
            depth,
            display_path: target.display_path.as_str().to_owned(),
            kind: target.kind,
            has_children: !target.children.is_empty(),
            search_text: target.display_path.as_str().to_lowercase(),
        });
        for child in target.children.iter().rev() {
            stack.push((child, Some(node_index), depth.saturating_add(1)));
        }
    }
    Ok(tree)
}
