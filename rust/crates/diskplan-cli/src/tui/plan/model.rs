use std::cmp::Ordering;
use std::collections::{HashMap, HashSet};
use std::error::Error;
use std::fmt;

use super::types::{
    ActionId, ActionKindId, ActionKindProjection, ActionProjection, ByteValue, ForceRequirement,
    PlanDisposition, PlanId, PlanProjection, ReleaseSetId, Stageability, TargetProjection,
    WaiverId,
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
}

#[derive(Clone, Debug)]
struct LoadedPlan {
    projection: PlanProjection,
    groups: Vec<ActionGroup>,
    action_positions: HashMap<ActionId, usize>,
}

#[derive(Clone, Debug)]
enum PlanState {
    Empty,
    Loaded(LoadedPlan),
    Invalidated(InvalidatedPlan),
}

#[derive(Clone, Debug)]
pub struct PlanModel {
    state: PlanState,
    expanded_dispositions: HashSet<PlanDisposition>,
    expanded_groups: HashSet<GroupKey>,
    group_sorts: HashMap<GroupKey, SortMode>,
    filter: String,
    cursor: Option<RowKey>,
    cursor_index_hint: usize,
    viewport_top: usize,
    viewport_height: usize,
}

impl Default for PlanModel {
    fn default() -> Self {
        Self {
            state: PlanState::Empty,
            expanded_dispositions: HashSet::new(),
            expanded_groups: HashSet::new(),
            group_sorts: HashMap::new(),
            filter: String::new(),
            cursor: None,
            cursor_index_hint: 0,
            viewport_top: 0,
            viewport_height: 0,
        }
    }
}

impl PlanModel {
    pub fn load(&mut self, projection: PlanProjection) -> Result<(), PlanModelError> {
        validate_projection(&projection)?;
        let groups = build_groups(&projection);
        let action_positions = projection
            .actions
            .iter()
            .enumerate()
            .map(|(index, action)| (action.id.clone(), index))
            .collect();
        self.expanded_dispositions = groups.iter().map(|group| group.key.disposition).collect();
        self.expanded_groups = groups.iter().map(|group| group.key.clone()).collect();
        self.group_sorts.clear();
        self.filter.clear();
        self.state = PlanState::Loaded(LoadedPlan {
            projection,
            groups,
            action_positions,
        });
        self.cursor = self.first_row_key();
        self.cursor_index_hint = 0;
        self.viewport_top = 0;
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
        let mut count = 0;
        self.walk_row_keys(|_, _| {
            count += 1;
            true
        });
        count
    }

    /// Materializes only the current viewport, even when the plan is large.
    pub fn visible_rows(&self) -> Vec<ViewRow> {
        if self.viewport_height == 0 {
            return Vec::new();
        }
        let end = self.viewport_top.saturating_add(self.viewport_height);
        let available = self.row_count().saturating_sub(self.viewport_top);
        let mut rows = Vec::with_capacity(self.viewport_height.min(available));
        self.walk_row_keys(|index, key| {
            if index >= end {
                return false;
            }
            if index >= self.viewport_top {
                rows.push(self.materialize_row(key));
            }
            true
        });
        rows
    }

    pub fn resize(&mut self, viewport_height: usize) {
        self.viewport_height = viewport_height;
        self.ensure_cursor_visible();
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
        let old_index = self.cursor_index().unwrap_or(self.cursor_index_hint);
        let changed = match key {
            RowKey::Disposition(disposition) => {
                toggle_set(&mut self.expanded_dispositions, *disposition)
            }
            RowKey::ActionKind {
                disposition,
                kind_id,
            } => toggle_set(
                &mut self.expanded_groups,
                GroupKey {
                    disposition: *disposition,
                    kind_id: kind_id.clone(),
                },
            ),
            RowKey::Action(_) => false,
        };
        if changed {
            self.reconcile_cursor(old_index);
        }
        changed
    }

    pub fn set_filter(&mut self, query: impl Into<String>) {
        let old_index = self.cursor_index().unwrap_or(self.cursor_index_hint);
        self.filter = query.into().trim().to_lowercase();
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
        let Some(loaded) = self.loaded() else {
            return false;
        };
        if !loaded.groups.iter().any(|group| group.key == group_key) {
            return false;
        }
        let old_index = self.cursor_index().unwrap_or(self.cursor_index_hint);
        if mode == SortMode::EngineOrder {
            self.group_sorts.remove(&group_key);
        } else {
            self.group_sorts.insert(group_key, mode);
        }
        self.reconcile_cursor(old_index);
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

    fn loaded(&self) -> Option<&LoadedPlan> {
        match &self.state {
            PlanState::Loaded(loaded) => Some(loaded),
            PlanState::Empty | PlanState::Invalidated(_) => None,
        }
    }

    fn clear_view_state(&mut self) {
        self.expanded_dispositions.clear();
        self.expanded_groups.clear();
        self.group_sorts.clear();
        self.filter.clear();
        self.cursor = None;
        self.cursor_index_hint = 0;
        self.viewport_top = 0;
    }

    fn filter_is_active(&self) -> bool {
        !self.filter.is_empty()
    }

    fn action_matches_filter(&self, action: &ActionProjection) -> bool {
        if !self.filter_is_active() {
            return true;
        }
        let needle = &self.filter;
        action.label.to_lowercase().contains(needle)
            || action.kind.label.to_lowercase().contains(needle)
            || action.kind.id.as_str().to_lowercase().contains(needle)
            || action.disposition.label().to_lowercase().contains(needle)
            || action
                .blockers
                .iter()
                .any(|blocker| blocker.summary.to_lowercase().contains(needle))
    }

    fn disposition_expanded(&self, disposition: PlanDisposition) -> bool {
        self.filter_is_active() || self.expanded_dispositions.contains(&disposition)
    }

    fn group_expanded(&self, key: &GroupKey) -> bool {
        self.filter_is_active() || self.expanded_groups.contains(key)
    }

    fn sorted_matching_indices(&self, group: &ActionGroup) -> Vec<usize> {
        let Some(loaded) = self.loaded() else {
            return Vec::new();
        };
        let mut indices: Vec<_> = group
            .action_indices
            .iter()
            .copied()
            .filter(|index| self.action_matches_filter(&loaded.projection.actions[*index]))
            .collect();
        let mode = self
            .group_sorts
            .get(&group.key)
            .copied()
            .unwrap_or_default();
        indices.sort_by(|left, right| {
            compare_actions(
                &loaded.projection.actions[*left],
                &loaded.projection.actions[*right],
                mode,
            )
        });
        indices
    }

    fn walk_row_keys(&self, mut visitor: impl FnMut(usize, RowKey) -> bool) {
        let Some(loaded) = self.loaded() else {
            return;
        };
        let mut row_index = 0;
        for disposition in PlanDisposition::ORDERED {
            let groups: Vec<_> = loaded
                .groups
                .iter()
                .filter(|group| group.key.disposition == disposition)
                .map(|group| (group, self.sorted_matching_indices(group)))
                .filter(|(_, indices)| !indices.is_empty())
                .collect();
            if groups.is_empty() {
                continue;
            }
            if !visitor(row_index, RowKey::Disposition(disposition)) {
                return;
            }
            row_index += 1;
            if !self.disposition_expanded(disposition) {
                continue;
            }
            for (group, action_indices) in groups {
                let group_key = RowKey::ActionKind {
                    disposition,
                    kind_id: group.kind.id.clone(),
                };
                if !visitor(row_index, group_key) {
                    return;
                }
                row_index += 1;
                if !self.group_expanded(&group.key) {
                    continue;
                }
                for action_index in action_indices {
                    let key = RowKey::Action(loaded.projection.actions[action_index].id.clone());
                    if !visitor(row_index, key) {
                        return;
                    }
                    row_index += 1;
                }
            }
        }
    }

    fn first_row_key(&self) -> Option<RowKey> {
        self.row_key_at(0)
    }

    fn row_key_at(&self, wanted: usize) -> Option<RowKey> {
        let mut found = None;
        self.walk_row_keys(|index, key| {
            if index == wanted {
                found = Some(key);
                false
            } else {
                true
            }
        });
        found
    }

    fn index_of(&self, wanted: &RowKey) -> Option<usize> {
        let mut found = None;
        self.walk_row_keys(|index, key| {
            if &key == wanted {
                found = Some(index);
                false
            } else {
                true
            }
        });
        found
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
                    .and_then(|loaded| loaded.groups.iter().find(|group| group.key == group_key))
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
}

fn toggle_set<T: Eq + std::hash::Hash + Clone>(set: &mut HashSet<T>, value: T) -> bool {
    if set.remove(&value) {
        true
    } else {
        set.insert(value)
    }
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
            });
        }
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

fn validate_projection(projection: &PlanProjection) -> Result<(), PlanModelError> {
    if projection.id.as_str().trim().is_empty() {
        return Err(PlanModelError::EmptyPlanId);
    }
    let mut action_ids = HashSet::new();
    let mut kinds = HashMap::<ActionKindId, ActionKindProjection>::new();
    for action in &projection.actions {
        if action.id.as_str().trim().is_empty() {
            return Err(PlanModelError::EmptyActionId);
        }
        if !action_ids.insert(action.id.clone()) {
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
        validate_targets(&action.id, &action.targets)?;
    }

    let mut release_sets = HashSet::new();
    for release_set in &projection.release_sets {
        if release_set.id.as_str().trim().is_empty() {
            return Err(PlanModelError::EmptyReleaseSetId);
        }
        if !release_sets.insert(release_set.id.clone()) {
            return Err(PlanModelError::DuplicateReleaseSetId(
                release_set.id.clone(),
            ));
        }
        if release_set.action_ids.is_empty() {
            return Err(PlanModelError::EmptyReleaseSet(release_set.id.clone()));
        }
        let mut members = HashSet::new();
        for action_id in &release_set.action_ids {
            if !action_ids.contains(action_id) {
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
    }

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
            if !action_ids.contains(&prerequisite.action_id) {
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
        let mut action_release_sets = HashSet::new();
        for release_set_id in &action.release_set_ids {
            if !release_sets.contains(release_set_id) {
                return Err(PlanModelError::UnknownActionReleaseSet {
                    action_id: action.id.clone(),
                    release_set_id: release_set_id.clone(),
                });
            }
            if !action_release_sets.insert(release_set_id) {
                return Err(PlanModelError::DuplicateActionReleaseSet {
                    action_id: action.id.clone(),
                    release_set_id: release_set_id.clone(),
                });
            }
            let release_set = projection
                .release_sets
                .iter()
                .find(|release_set| &release_set.id == release_set_id)
                .expect("validated release set ID must resolve");
            if !release_set.action_ids.contains(&action.id) {
                return Err(PlanModelError::ReleaseSetMembershipMismatch {
                    action_id: action.id.clone(),
                    release_set_id: release_set_id.clone(),
                });
            }
        }
    }
    for release_set in &projection.release_sets {
        for action_id in &release_set.action_ids {
            let action = projection
                .actions
                .iter()
                .find(|action| &action.id == action_id)
                .expect("validated release set action ID must resolve");
            if !action.release_set_ids.contains(&release_set.id) {
                return Err(PlanModelError::ReleaseSetMembershipMismatch {
                    action_id: action_id.clone(),
                    release_set_id: release_set.id.clone(),
                });
            }
        }
    }
    Ok(())
}

fn validate_targets(
    action_id: &ActionId,
    targets: &[TargetProjection],
) -> Result<(), PlanModelError> {
    fn walk(
        action_id: &ActionId,
        targets: &[TargetProjection],
        ids: &mut HashSet<super::types::TargetId>,
    ) -> Result<(), PlanModelError> {
        for target in targets {
            if target.id.as_str().trim().is_empty() {
                return Err(PlanModelError::EmptyTargetId(action_id.clone()));
            }
            if !ids.insert(target.id.clone()) {
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
            walk(action_id, &target.children, ids)?;
        }
        Ok(())
    }

    walk(action_id, targets, &mut HashSet::new())
}
