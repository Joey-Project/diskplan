use std::collections::HashMap;
use std::fmt;

use diskplan_proto::diskplan::v1::{
    ByteEstimateProjection, OpaqueIdentifier, PathRaceProjection as WirePathRace,
    PlanActivity as WireActivity, PlanDisposition as WireDisposition, PlanProjectionRecord,
    PlanRecoverability as WireRecoverability, PlanStageability as WireStageability,
    PlanTargetKind as WireTargetKind, byte_estimate_projection, plan_projection_record,
};
use diskplan_proto::runtime::VerifiedPlanProjection;

use super::{
    ActionId, ActionKindId, ActionKindProjection, ActionProjection, Activity, BlockerId,
    BlockerProjection, ByteValue, DisplayPath, EnginePlanSnapshot, ForceRequirement, PathRace,
    PlanDisposition, PlanId, PlanProjection, PrerequisiteProjection, Recoverability, ReleaseSetId,
    ReleaseSetProjection, Stageability, TargetId, TargetKind, TargetProjection, WaiverId,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct WirePlanError(&'static str);

impl fmt::Display for WirePlanError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            formatter,
            "verified wire plan cannot be presented: {}",
            self.0
        )
    }
}

impl std::error::Error for WirePlanError {}

pub(crate) fn snapshot_from_verified(
    verified: &VerifiedPlanProjection,
    provisional: bool,
) -> Result<EnginePlanSnapshot, WirePlanError> {
    let manifest = verified.manifest();
    let plan_id = opaque_hex(manifest.plan_id.as_ref(), "missing plan_id")?;
    let evidence_reference = digest_hex(
        manifest
            .evidence_sha256
            .as_ref()
            .map(|value| value.value.as_slice()),
        "missing evidence digest",
    )?;
    let targets = collect_targets(verified.records())?;
    let actions = verified
        .records()
        .iter()
        .filter_map(|record| match record.body.as_ref() {
            Some(plan_projection_record::Body::Action(action)) => Some(action),
            _ => None,
        })
        .map(|action| map_action(action, &targets))
        .collect::<Result<Vec<_>, _>>()?;
    let release_sets = verified
        .records()
        .iter()
        .filter_map(|record| match record.body.as_ref() {
            Some(plan_projection_record::Body::ReleaseSet(release_set)) => Some(release_set),
            _ => None,
        })
        .map(|release_set| {
            Ok(ReleaseSetProjection {
                id: ReleaseSetId::new(opaque_hex(
                    release_set.release_set_id.as_ref(),
                    "missing release_set_id",
                )?),
                action_ids: release_set
                    .action_ids
                    .iter()
                    .map(|value| ActionId::new(hex::encode(&value.value)))
                    .collect(),
                shared_unlock: byte_value(release_set.shared_unlock.as_ref())?,
            })
        })
        .collect::<Result<Vec<_>, WirePlanError>>()?;

    Ok(EnginePlanSnapshot {
        projection: PlanProjection {
            id: PlanId::new(plan_id),
            actions,
            release_sets,
        },
        evidence_reference,
        provisional,
    })
}

fn map_action(
    action: &diskplan_proto::diskplan::v1::PlanActionProjection,
    targets: &HashMap<Vec<u8>, diskplan_proto::diskplan::v1::PlanTargetProjection>,
) -> Result<ActionProjection, WirePlanError> {
    let action_id = ActionId::new(opaque_hex(action.action_id.as_ref(), "missing action_id")?);
    let stageability = match WireStageability::try_from(action.stageability)
        .map_err(|_| WirePlanError("unknown stageability"))?
    {
        WireStageability::Stageable => Stageability::Stageable,
        WireStageability::RequiresWaivers => Stageability::RequiresWaivers(
            action
                .required_waivers
                .iter()
                .map(|waiver| {
                    opaque_hex(waiver.waiver_id.as_ref(), "missing waiver_id").map(WaiverId::new)
                })
                .collect::<Result<Vec<_>, _>>()?,
        ),
        WireStageability::NotStageable => Stageability::NotStageable,
        WireStageability::Unspecified => return Err(WirePlanError("unspecified stageability")),
    };
    let disposition = match WireDisposition::try_from(action.disposition)
        .map_err(|_| WirePlanError("unknown disposition"))?
    {
        WireDisposition::Ready => PlanDisposition::Ready,
        WireDisposition::Conditional => PlanDisposition::Conditional,
        WireDisposition::NeedsReview => PlanDisposition::NeedsReview,
        WireDisposition::Blocked => PlanDisposition::Blocked,
        WireDisposition::KeepInformational => PlanDisposition::KeepInformational,
        WireDisposition::Unspecified => return Err(WirePlanError("unspecified disposition")),
    };
    let activity = match WireActivity::try_from(action.activity)
        .map_err(|_| WirePlanError("unknown activity"))?
    {
        WireActivity::Inactive => Activity::Inactive,
        WireActivity::Active => Activity::Active,
        WireActivity::Mixed => Activity::Mixed,
        WireActivity::Unknown => Activity::Unknown,
        WireActivity::Unspecified => return Err(WirePlanError("unspecified activity")),
    };
    let recoverability = match WireRecoverability::try_from(action.recoverability)
        .map_err(|_| WirePlanError("unknown recoverability"))?
    {
        WireRecoverability::Rebuildable => Recoverability::Rebuildable,
        WireRecoverability::Restorable => Recoverability::Restorable,
        WireRecoverability::Irrecoverable => Recoverability::Irrecoverable,
        WireRecoverability::ReviewRequired => Recoverability::ReviewRequired,
        WireRecoverability::Unknown => Recoverability::Unknown,
        WireRecoverability::Unspecified => {
            return Err(WirePlanError("unspecified recoverability"));
        }
    };
    let path_race = match WirePathRace::try_from(action.path_race)
        .map_err(|_| WirePlanError("unknown path race"))?
    {
        WirePathRace::NoneObserved => PathRace::NoneObserved,
        WirePathRace::Residual => PathRace::Residual,
        WirePathRace::Unknown => PathRace::Unknown,
        WirePathRace::Unspecified => return Err(WirePlanError("unspecified path race")),
    };
    let roots = action
        .target_ids
        .iter()
        .filter_map(|target_id| {
            targets
                .get(&target_id.value)
                .filter(|target| target.parent_target_id.is_none())
                .map(|target| map_target(target, targets))
        })
        .collect::<Result<Vec<_>, _>>()?;

    Ok(ActionProjection {
        id: action_id,
        disposition,
        kind: ActionKindProjection {
            id: ActionKindId::new(format!("kind-{}", action.kind)),
            label: action.kind_label.clone(),
            order: action.kind_order,
        },
        label: action.label.clone(),
        order: action.order,
        stageability,
        immediate_reclaim: byte_value(action.immediate_reclaim.as_ref())?,
        shared_unlock: byte_value(action.shared_unlock.as_ref())?,
        activity,
        recoverability,
        blockers: action
            .blockers
            .iter()
            .map(|blocker| {
                Ok(BlockerProjection {
                    id: BlockerId::new(opaque_hex(
                        blocker.blocker_id.as_ref(),
                        "missing blocker_id",
                    )?),
                    summary: blocker.summary.clone(),
                })
            })
            .collect::<Result<Vec<_>, WirePlanError>>()?,
        prerequisites: action
            .prerequisites
            .iter()
            .map(|prerequisite| {
                Ok(PrerequisiteProjection {
                    action_id: ActionId::new(opaque_hex(
                        prerequisite.action_id.as_ref(),
                        "missing prerequisite action_id",
                    )?),
                    summary: prerequisite.summary.clone(),
                })
            })
            .collect::<Result<Vec<_>, WirePlanError>>()?,
        release_set_ids: action
            .release_set_ids
            .iter()
            .map(|value| ReleaseSetId::new(hex::encode(&value.value)))
            .collect(),
        force: if action.requires_force {
            ForceRequirement::Required {
                reason: action.force_reason.clone(),
            }
        } else {
            ForceRequirement::NotRequired
        },
        path_race,
        targets: roots,
    })
}

fn collect_targets(
    records: &[PlanProjectionRecord],
) -> Result<HashMap<Vec<u8>, diskplan_proto::diskplan::v1::PlanTargetProjection>, WirePlanError> {
    records
        .iter()
        .filter_map(|record| match record.body.as_ref() {
            Some(plan_projection_record::Body::Target(target)) => Some(target),
            _ => None,
        })
        .map(|target| {
            let id = target
                .target_id
                .as_ref()
                .ok_or(WirePlanError("missing target_id"))?
                .value
                .clone();
            Ok((id, target.clone()))
        })
        .collect()
}

fn map_target(
    target: &diskplan_proto::diskplan::v1::PlanTargetProjection,
    all: &HashMap<Vec<u8>, diskplan_proto::diskplan::v1::PlanTargetProjection>,
) -> Result<TargetProjection, WirePlanError> {
    let target_id = target
        .target_id
        .as_ref()
        .ok_or(WirePlanError("missing target_id"))?;
    let mut children = all
        .values()
        .filter(|candidate| {
            candidate
                .parent_target_id
                .as_ref()
                .is_some_and(|parent| parent.value == target_id.value)
        })
        .collect::<Vec<_>>();
    children.sort_by(|left, right| {
        left.order.cmp(&right.order).then_with(|| {
            left.target_id
                .as_ref()
                .map(|value| value.value.as_slice())
                .cmp(&right.target_id.as_ref().map(|value| value.value.as_slice()))
        })
    });
    let path = target
        .path
        .as_ref()
        .ok_or(WirePlanError("missing target path"))?;
    let kind = match WireTargetKind::try_from(target.kind)
        .map_err(|_| WirePlanError("unknown target kind"))?
    {
        WireTargetKind::File => TargetKind::File,
        WireTargetKind::Directory => TargetKind::Directory,
        WireTargetKind::SymbolicLink => TargetKind::Symlink,
        WireTargetKind::Other => TargetKind::Other,
        WireTargetKind::Unknown => TargetKind::Unknown,
        WireTargetKind::Unspecified => return Err(WirePlanError("unspecified target kind")),
    };
    Ok(TargetProjection {
        id: TargetId::new(hex::encode(&target_id.value)),
        display_path: DisplayPath::new(path.display_path.clone()),
        kind,
        children: children
            .into_iter()
            .map(|child| map_target(child, all))
            .collect::<Result<Vec<_>, _>>()?,
    })
}

fn byte_value(value: Option<&ByteEstimateProjection>) -> Result<ByteValue, WirePlanError> {
    match value.and_then(|value| value.value.as_ref()) {
        Some(byte_estimate_projection::Value::KnownBytes(bytes)) => Ok(ByteValue::Known(*bytes)),
        Some(byte_estimate_projection::Value::Unknown(_)) => Ok(ByteValue::Unknown),
        None => Err(WirePlanError("missing byte estimate")),
    }
}

fn opaque_hex(
    value: Option<&OpaqueIdentifier>,
    missing: &'static str,
) -> Result<String, WirePlanError> {
    value
        .map(|value| hex::encode(&value.value))
        .filter(|value| !value.is_empty())
        .ok_or(WirePlanError(missing))
}

fn digest_hex(value: Option<&[u8]>, missing: &'static str) -> Result<String, WirePlanError> {
    value
        .filter(|value| value.len() == 32)
        .map(hex::encode)
        .ok_or(WirePlanError(missing))
}
