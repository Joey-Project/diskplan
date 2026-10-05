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

const MAXIMUM_PRESENTABLE_TARGET_DEPTH: u32 = 512;

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
    targets: &HashMap<Vec<u8>, TargetProjection>,
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
        .filter_map(|target_id| targets.get(&target_id.value).cloned())
        .collect();

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
) -> Result<HashMap<Vec<u8>, TargetProjection>, WirePlanError> {
    let mut targets = records
        .iter()
        .filter_map(|record| match record.body.as_ref() {
            Some(plan_projection_record::Body::Target(target)) => Some(target),
            _ => None,
        })
        .map(|target| {
            if target.depth > MAXIMUM_PRESENTABLE_TARGET_DEPTH {
                return Err(WirePlanError("target tree exceeds the presentation depth"));
            }
            let id = target
                .target_id
                .as_ref()
                .ok_or(WirePlanError("missing target_id"))?
                .value
                .clone();
            Ok((id, target))
        })
        .collect::<Result<Vec<_>, WirePlanError>>()?;
    let by_id = targets
        .iter()
        .map(|(id, target)| (id.clone(), *target))
        .collect::<HashMap<_, _>>();
    let mut children_by_parent: HashMap<Vec<u8>, Vec<Vec<u8>>> = HashMap::new();
    for (id, target) in &targets {
        if let Some(parent) = target.parent_target_id.as_ref() {
            children_by_parent
                .entry(parent.value.clone())
                .or_default()
                .push(id.clone());
        }
    }
    for children in children_by_parent.values_mut() {
        children.sort_by(|left, right| {
            let left = by_id
                .get(left)
                .expect("verified target child exists in the target index");
            let right = by_id
                .get(right)
                .expect("verified target child exists in the target index");
            left.order.cmp(&right.order).then_with(|| {
                left.target_id
                    .as_ref()
                    .map(|value| value.value.as_slice())
                    .cmp(&right.target_id.as_ref().map(|value| value.value.as_slice()))
            })
        });
    }
    targets.sort_by(|(left_id, left), (right_id, right)| {
        right
            .depth
            .cmp(&left.depth)
            .then_with(|| left_id.cmp(right_id))
    });

    let mut built = HashMap::with_capacity(targets.len());
    for (id, target) in targets {
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
            WireTargetKind::Unspecified => {
                return Err(WirePlanError("unspecified target kind"));
            }
        };
        let children = children_by_parent
            .remove(&id)
            .unwrap_or_default()
            .into_iter()
            .map(|child_id| {
                built
                    .remove(&child_id)
                    .ok_or(WirePlanError("target child was not built"))
            })
            .collect::<Result<Vec<_>, _>>()?;
        built.insert(
            id.clone(),
            TargetProjection {
                id: TargetId::new(hex::encode(id)),
                display_path: DisplayPath::new(path.display_path.clone()),
                kind,
                children,
            },
        );
    }
    Ok(built)
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

#[cfg(test)]
mod tests {
    use super::*;
    use diskplan_proto::diskplan::v1::{
        PlanRawPathProjection, PlanTargetProjection as WireTarget, plan_projection_record,
    };

    fn target_record(
        index: u64,
        id: &[u8],
        parent: Option<&[u8]>,
        depth: u32,
        order: u64,
    ) -> PlanProjectionRecord {
        PlanProjectionRecord {
            record_index: index,
            body: Some(plan_projection_record::Body::Target(WireTarget {
                target_id: Some(OpaqueIdentifier { value: id.to_vec() }),
                parent_target_id: parent.map(|value| OpaqueIdentifier {
                    value: value.to_vec(),
                }),
                depth,
                order,
                path: Some(PlanRawPathProjection {
                    display_path: format!("/{}", hex::encode(id)),
                    ..Default::default()
                }),
                kind: WireTargetKind::Directory as i32,
                ..Default::default()
            })),
        }
    }

    #[test]
    fn target_forest_is_built_bottom_up_in_engine_order() {
        let records = vec![
            target_record(0, b"root", None, 0, 0),
            target_record(1, b"later", Some(b"root"), 1, 2),
            target_record(2, b"earlier", Some(b"root"), 1, 1),
        ];

        let roots = collect_targets(&records).unwrap();
        let root = roots.get(b"root".as_slice()).unwrap();
        assert_eq!(root.children.len(), 2);
        assert_eq!(root.children[0].id, TargetId::new(hex::encode(b"earlier")));
        assert_eq!(root.children[1].id, TargetId::new(hex::encode(b"later")));
    }

    #[test]
    fn target_forest_rejects_unpresentable_depth_before_nesting() {
        let records = vec![target_record(
            0,
            b"too-deep",
            Some(b"parent"),
            MAXIMUM_PRESENTABLE_TARGET_DEPTH + 1,
            0,
        )];

        assert!(matches!(
            collect_targets(&records),
            Err(WirePlanError("target tree exceeds the presentation depth"))
        ));
    }
}
