use std::fmt;
use std::sync::Arc;

macro_rules! string_id {
    ($name:ident) => {
        #[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(pub Arc<str>);

        impl $name {
            pub fn new(value: impl Into<Arc<str>>) -> Self {
                Self(value.into())
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl fmt::Display for $name {
            fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
                formatter.write_str(&self.0)
            }
        }
    };
}

string_id!(PlanId);
string_id!(ActionId);
string_id!(ActionKindId);
string_id!(TargetId);
string_id!(ReleaseSetId);
string_id!(WaiverId);
string_id!(BlockerId);
string_id!(ExecutionUnitId);
string_id!(ExecutionWarningId);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum PlanDisposition {
    Ready,
    Conditional,
    NeedsReview,
    Blocked,
    KeepInformational,
}

impl PlanDisposition {
    pub const ORDERED: [Self; 5] = [
        Self::Ready,
        Self::Conditional,
        Self::NeedsReview,
        Self::Blocked,
        Self::KeepInformational,
    ];

    pub fn label(self) -> &'static str {
        match self {
            Self::Ready => "Ready",
            Self::Conditional => "Conditional",
            Self::NeedsReview => "Needs review",
            Self::Blocked => "Blocked",
            Self::KeepInformational => "Keep / informational",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionKindProjection {
    pub id: ActionKindId,
    pub label: String,
    /// Engine-provided presentation order. It is not a safety ranking.
    pub order: u32,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ByteValue {
    Known(u64),
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Stageability {
    Stageable,
    RequiresWaivers(Vec<WaiverId>),
    NotStageable,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Activity {
    Inactive,
    Active,
    Mixed,
    Unknown,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Recoverability {
    Rebuildable,
    Restorable,
    Irrecoverable,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ForceRequirement {
    NotRequired,
    Required { reason: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PathRace {
    NoneObserved,
    Residual,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BlockerProjection {
    pub id: BlockerId,
    pub summary: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PrerequisiteProjection {
    pub action_id: ActionId,
    pub summary: String,
}

/// A display-only path supplied by the engine.
///
/// It intentionally exposes no filesystem operations or normalization helpers.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DisplayPath(pub String);

impl DisplayPath {
    pub fn new(value: impl Into<String>) -> Self {
        Self(value.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TargetKind {
    File,
    Directory,
    Symlink,
    Other,
    Unknown,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TargetProjection {
    pub id: TargetId,
    pub display_path: DisplayPath,
    pub kind: TargetKind,
    /// Children are meaningful only in the action's Targets detail view.
    pub children: Vec<TargetProjection>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ActionProjection {
    pub id: ActionId,
    pub disposition: PlanDisposition,
    pub kind: ActionKindProjection,
    pub label: String,
    /// Engine-provided stable order inside an action-kind group.
    pub order: u64,
    pub stageability: Stageability,
    pub immediate_reclaim: ByteValue,
    pub shared_unlock: ByteValue,
    pub activity: Activity,
    pub recoverability: Recoverability,
    pub blockers: Vec<BlockerProjection>,
    pub prerequisites: Vec<PrerequisiteProjection>,
    pub release_set_ids: Vec<ReleaseSetId>,
    pub force: ForceRequirement,
    pub path_race: PathRace,
    pub targets: Vec<TargetProjection>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReleaseSetProjection {
    pub id: ReleaseSetId,
    pub action_ids: Vec<ActionId>,
    pub shared_unlock: ByteValue,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PlanProjection {
    pub id: PlanId,
    pub actions: Vec<ActionProjection>,
    pub release_sets: Vec<ReleaseSetProjection>,
}
