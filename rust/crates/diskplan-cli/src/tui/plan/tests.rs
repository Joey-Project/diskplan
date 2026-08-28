use super::*;

#[allow(clippy::too_many_arguments)]
fn action(
    id: &str,
    disposition: PlanDisposition,
    kind_id: &str,
    kind_label: &str,
    kind_order: u32,
    order: u64,
    immediate: ByteValue,
    target_path: &str,
) -> ActionProjection {
    ActionProjection {
        id: ActionId::new(id),
        disposition,
        kind: ActionKindProjection {
            id: ActionKindId::new(kind_id),
            label: kind_label.into(),
            order: kind_order,
        },
        label: format!("Action {id}"),
        order,
        stageability: Stageability::Stageable,
        immediate_reclaim: immediate,
        shared_unlock: ByteValue::Unknown,
        activity: Activity::Unknown,
        recoverability: Recoverability::Unknown,
        blockers: Vec::new(),
        prerequisites: Vec::new(),
        release_set_ids: Vec::new(),
        force: ForceRequirement::NotRequired,
        path_race: PathRace::Unknown,
        targets: vec![TargetProjection {
            id: TargetId::new(format!("target-{id}")),
            display_path: DisplayPath::new(target_path),
            kind: TargetKind::Directory,
            children: vec![TargetProjection {
                id: TargetId::new(format!("target-{id}-child")),
                display_path: DisplayPath::new(format!("{target_path}/child")),
                kind: TargetKind::File,
                children: Vec::new(),
            }],
        }],
    }
}

fn projection(actions: Vec<ActionProjection>) -> PlanProjection {
    PlanProjection {
        id: PlanId::new("plan-1"),
        actions,
        release_sets: Vec::new(),
    }
}

fn representative_projection() -> PlanProjection {
    projection(vec![
        action(
            "blocked-cache",
            PlanDisposition::Blocked,
            "cache",
            "Caches",
            10,
            0,
            ByteValue::Known(900),
            "/private/blocked-cache",
        ),
        action(
            "ready-log",
            PlanDisposition::Ready,
            "log",
            "Logs",
            20,
            0,
            ByteValue::Known(300),
            "/private/ready-log",
        ),
        action(
            "ready-cache-b",
            PlanDisposition::Ready,
            "cache",
            "Caches",
            10,
            20,
            ByteValue::Known(700),
            "/private/ready-cache-b",
        ),
        action(
            "ready-cache-a",
            PlanDisposition::Ready,
            "cache",
            "Caches",
            10,
            10,
            ByteValue::Known(100),
            "/private/ready-cache-a",
        ),
    ])
}

fn all_rows(model: &mut PlanModel) -> Vec<ViewRow> {
    model.resize(model.row_count());
    model.visible_rows()
}

#[test]
fn hierarchy_is_disposition_then_action_kind_then_action() {
    let mut model = PlanModel::default();
    model.load(representative_projection()).unwrap();

    let rows = all_rows(&mut model);
    let keys: Vec<_> = rows.iter().map(|row| row.key.clone()).collect();
    assert_eq!(
        keys,
        vec![
            RowKey::Disposition(PlanDisposition::Ready),
            RowKey::ActionKind {
                disposition: PlanDisposition::Ready,
                kind_id: ActionKindId::new("cache"),
            },
            RowKey::Action(ActionId::new("ready-cache-a")),
            RowKey::Action(ActionId::new("ready-cache-b")),
            RowKey::ActionKind {
                disposition: PlanDisposition::Ready,
                kind_id: ActionKindId::new("log"),
            },
            RowKey::Action(ActionId::new("ready-log")),
            RowKey::Disposition(PlanDisposition::Blocked),
            RowKey::ActionKind {
                disposition: PlanDisposition::Blocked,
                kind_id: ActionKindId::new("cache"),
            },
            RowKey::Action(ActionId::new("blocked-cache")),
        ]
    );
}

#[test]
fn directories_exist_only_in_action_targets_detail() {
    let mut model = PlanModel::default();
    model.load(representative_projection()).unwrap();
    let rows = all_rows(&mut model);

    assert!(rows.iter().all(|row| !row.label.contains("/private/")));
    let targets = model
        .action_targets(&ActionId::new("ready-cache-a"))
        .unwrap();
    assert_eq!(targets[0].display_path.as_str(), "/private/ready-cache-a");
    assert_eq!(targets[0].kind, TargetKind::Directory);
    assert_eq!(targets[0].children.len(), 1);

    model.set_filter("/private/ready-cache-a");
    assert_eq!(
        model.row_count(),
        0,
        "target paths are not main-tree search data"
    );
}

#[test]
fn group_sorting_never_moves_actions_across_hierarchy_groups() {
    let mut model = PlanModel::default();
    model.load(representative_projection()).unwrap();
    assert!(model.set_group_sort(
        PlanDisposition::Ready,
        ActionKindId::new("cache"),
        SortMode::ImmediateReclaimDescending,
    ));

    let keys: Vec<_> = all_rows(&mut model)
        .into_iter()
        .map(|row| row.key)
        .collect();
    assert_eq!(keys[2], RowKey::Action(ActionId::new("ready-cache-b")));
    assert_eq!(keys[3], RowKey::Action(ActionId::new("ready-cache-a")));
    assert_eq!(keys[5], RowKey::Action(ActionId::new("ready-log")));
    assert_eq!(keys[8], RowKey::Action(ActionId::new("blocked-cache")));
}

#[test]
fn unknown_bytes_sort_after_known_bytes_with_stable_ties() {
    let mut unknown = action(
        "unknown",
        PlanDisposition::Ready,
        "cache",
        "Caches",
        1,
        1,
        ByteValue::Unknown,
        "/private/unknown",
    );
    unknown.label = "Unknown".into();
    let first = action(
        "first",
        PlanDisposition::Ready,
        "cache",
        "Caches",
        1,
        2,
        ByteValue::Known(10),
        "/private/first",
    );
    let second = action(
        "second",
        PlanDisposition::Ready,
        "cache",
        "Caches",
        1,
        3,
        ByteValue::Known(10),
        "/private/second",
    );
    let mut model = PlanModel::default();
    model
        .load(projection(vec![unknown, second, first]))
        .unwrap();
    model.set_group_sort(
        PlanDisposition::Ready,
        ActionKindId::new("cache"),
        SortMode::ImmediateReclaimDescending,
    );

    let actions: Vec<_> = all_rows(&mut model)
        .into_iter()
        .filter_map(|row| match row.key {
            RowKey::Action(id) => Some(id),
            _ => None,
        })
        .collect();
    assert_eq!(
        actions,
        vec![
            ActionId::new("first"),
            ActionId::new("second"),
            ActionId::new("unknown")
        ]
    );
}

#[test]
fn cursor_key_survives_sort_filter_and_resize() {
    let mut model = PlanModel::default();
    model.load(representative_projection()).unwrap();
    model.resize(3);
    assert!(model.select(&RowKey::Action(ActionId::new("ready-cache-a"))));
    let selected = model.cursor().cloned();

    model.set_group_sort(
        PlanDisposition::Ready,
        ActionKindId::new("cache"),
        SortMode::ImmediateReclaimDescending,
    );
    model.resize(1);
    assert_eq!(model.cursor(), selected.as_ref());
    assert_eq!(model.visible_rows().len(), 1);
    assert_eq!(model.visible_rows()[0].key, selected.unwrap());

    model.set_filter("ready-cache-a");
    assert_eq!(
        model.cursor(),
        Some(&RowKey::Action(ActionId::new("ready-cache-a")))
    );
    assert_eq!(model.row_count(), 3);
}

#[test]
fn cursor_reconciles_when_filter_or_collapse_hides_its_row() {
    let mut model = PlanModel::default();
    model.load(representative_projection()).unwrap();
    model.resize(4);
    model.select(&RowKey::Action(ActionId::new("ready-cache-b")));
    model.set_filter("ready-log");
    assert_eq!(model.row_count(), 3);
    assert_eq!(
        model.cursor(),
        Some(&RowKey::Action(ActionId::new("ready-log")))
    );

    model.set_filter("");
    let cache_group = RowKey::ActionKind {
        disposition: PlanDisposition::Ready,
        kind_id: ActionKindId::new("cache"),
    };
    model.select(&RowKey::Action(ActionId::new("ready-cache-a")));
    assert!(model.toggle_expanded(&cache_group));
    assert_ne!(
        model.cursor(),
        Some(&RowKey::Action(ActionId::new("ready-cache-a")))
    );
    assert!(model.viewport_top() < model.row_count());
}

#[test]
fn visible_rows_materializes_only_the_viewport_for_large_plans() {
    let actions = (0..20_000)
        .map(|index| {
            action(
                &format!("action-{index:05}"),
                PlanDisposition::Ready,
                "cache",
                "Caches",
                1,
                index,
                ByteValue::Known(index),
                &format!("/private/large/{index}"),
            )
        })
        .collect();
    let mut model = PlanModel::default();
    model.load(projection(actions)).unwrap();
    model.resize(7);
    model.move_cursor(19_999);

    let rows = model.visible_rows();
    assert_eq!(model.row_count(), 20_002);
    assert_eq!(rows.len(), 7);
    assert_eq!(
        model.cursor(),
        Some(&RowKey::Action(ActionId::new("action-19997")))
    );
    assert_eq!(rows.last().unwrap().key, model.cursor().unwrap().clone());
}

#[test]
fn oversized_viewport_is_bounded_by_available_rows() {
    let mut model = PlanModel::default();
    model
        .load(projection(vec![action(
            "only",
            PlanDisposition::Ready,
            "cache",
            "Caches",
            1,
            1,
            ByteValue::Known(1),
            "/private/only",
        )]))
        .unwrap();
    model.resize(usize::MAX);
    assert_eq!(model.visible_rows().len(), 3);
}

#[test]
fn duplicate_and_invalid_ids_fail_closed() {
    let duplicate = action(
        "same",
        PlanDisposition::Ready,
        "cache",
        "Caches",
        1,
        1,
        ByteValue::Known(1),
        "/private/a",
    );
    let mut model = PlanModel::default();
    assert_eq!(
        model.load(projection(vec![duplicate.clone(), duplicate])),
        Err(PlanModelError::DuplicateActionId(ActionId::new("same")))
    );

    let mut invalid = projection(vec![action(
        "valid",
        PlanDisposition::Ready,
        "cache",
        "Caches",
        1,
        1,
        ByteValue::Known(1),
        "/private/a",
    )]);
    invalid.id = PlanId::new("   ");
    assert_eq!(model.load(invalid), Err(PlanModelError::EmptyPlanId));
}

#[test]
fn duplicate_target_and_release_set_ids_fail_closed() {
    let mut first = action(
        "first",
        PlanDisposition::Ready,
        "cache",
        "Caches",
        1,
        1,
        ByteValue::Known(1),
        "/private/a",
    );
    first.targets.push(first.targets[0].clone());
    let mut model = PlanModel::default();
    assert!(matches!(
        model.load(projection(vec![first])),
        Err(PlanModelError::DuplicateTargetId { .. })
    ));

    let action = action(
        "member",
        PlanDisposition::Conditional,
        "clone",
        "APFS clones",
        1,
        1,
        ByteValue::Known(1),
        "/private/clone",
    );
    let release_set = ReleaseSetProjection {
        id: ReleaseSetId::new("set-1"),
        action_ids: vec![action.id.clone()],
        shared_unlock: ByteValue::Known(100),
    };
    let mut plan = projection(vec![action]);
    plan.release_sets = vec![release_set.clone(), release_set];
    assert_eq!(
        model.load(plan),
        Err(PlanModelError::DuplicateReleaseSetId(ReleaseSetId::new(
            "set-1"
        )))
    );
}

#[test]
fn duplicate_waiver_blocker_and_prerequisite_ids_fail_closed() {
    let mut candidate = action(
        "candidate",
        PlanDisposition::Conditional,
        "remove",
        "Removal",
        1,
        1,
        ByteValue::Known(1),
        "/private/candidate",
    );
    candidate.stageability =
        Stageability::RequiresWaivers(vec![WaiverId::new("force"), WaiverId::new("force")]);
    let mut model = PlanModel::default();
    assert!(matches!(
        model.load(projection(vec![candidate.clone()])),
        Err(PlanModelError::DuplicateWaiverId { .. })
    ));

    candidate.stageability = Stageability::RequiresWaivers(Vec::new());
    assert_eq!(
        model.load(projection(vec![candidate.clone()])),
        Err(PlanModelError::EmptyRequiredWaiverSet(candidate.id.clone()))
    );

    candidate.stageability = Stageability::Stageable;
    candidate.blockers = vec![
        BlockerProjection {
            id: BlockerId::new("activity"),
            summary: "Active".into(),
        },
        BlockerProjection {
            id: BlockerId::new("activity"),
            summary: "Still active".into(),
        },
    ];
    assert!(matches!(
        model.load(projection(vec![candidate.clone()])),
        Err(PlanModelError::DuplicateBlockerId { .. })
    ));

    candidate.blockers.clear();
    candidate.force = ForceRequirement::Required {
        reason: "   ".into(),
    };
    assert_eq!(
        model.load(projection(vec![candidate.clone()])),
        Err(PlanModelError::EmptyForceReason(candidate.id.clone()))
    );

    candidate.force = ForceRequirement::NotRequired;
    let prerequisite = action(
        "prerequisite",
        PlanDisposition::Ready,
        "remove",
        "Removal",
        1,
        0,
        ByteValue::Known(1),
        "/private/prerequisite",
    );
    candidate.prerequisites = vec![
        PrerequisiteProjection {
            action_id: prerequisite.id.clone(),
            summary: "First".into(),
        },
        PrerequisiteProjection {
            action_id: prerequisite.id.clone(),
            summary: "Duplicate".into(),
        },
    ];
    assert!(matches!(
        model.load(projection(vec![candidate, prerequisite])),
        Err(PlanModelError::DuplicatePrerequisite { .. })
    ));
}

#[test]
fn release_set_membership_must_be_bidirectionally_consistent() {
    let mut member = action(
        "member",
        PlanDisposition::Conditional,
        "clone",
        "APFS clones",
        1,
        1,
        ByteValue::Known(1),
        "/private/member",
    );
    let release_set = ReleaseSetProjection {
        id: ReleaseSetId::new("set-1"),
        action_ids: vec![member.id.clone()],
        shared_unlock: ByteValue::Known(100),
    };
    let mut model = PlanModel::default();
    let mut mismatched = projection(vec![member.clone()]);
    mismatched.release_sets = vec![release_set.clone()];
    assert!(matches!(
        model.load(mismatched),
        Err(PlanModelError::ReleaseSetMembershipMismatch { .. })
    ));

    member.release_set_ids = vec![release_set.id.clone()];
    let mut consistent = projection(vec![member]);
    consistent.release_sets = vec![release_set];
    model.load(consistent).unwrap();
}

#[test]
fn stale_invalidation_is_rejected_and_reset_clears_state() {
    let mut model = PlanModel::default();
    model.load(representative_projection()).unwrap();
    assert_eq!(
        model.invalidate(PlanId::new("other"), "stale"),
        Err(InvalidationError::PlanIdMismatch {
            expected: PlanId::new("plan-1"),
            actual: PlanId::new("other"),
        })
    );
    assert_eq!(model.current_plan_id(), Some(&PlanId::new("plan-1")));

    model
        .invalidate(PlanId::new("plan-1"), "scan resumed")
        .unwrap();
    assert_eq!(model.row_count(), 0);
    assert_eq!(model.invalidated().unwrap().reason, "scan resumed");
    assert!(model.cursor().is_none());

    model.reset();
    assert!(model.invalidated().is_none());
    assert!(model.current_plan_id().is_none());
    assert_eq!(model.viewport_top(), 0);
}

#[test]
fn safety_fields_are_preserved_as_engine_supplied_data() {
    let mut projected = action(
        "conditional",
        PlanDisposition::Conditional,
        "generic-remove",
        "Generic removal",
        1,
        1,
        ByteValue::Unknown,
        "/private/conditional",
    );
    projected.stageability = Stageability::RequiresWaivers(vec![WaiverId::new("force")]);
    projected.activity = Activity::Active;
    projected.recoverability = Recoverability::Irrecoverable;
    projected.blockers = vec![BlockerProjection {
        id: BlockerId::new("open-handle"),
        summary: "Open handle observed".into(),
    }];
    projected.force = ForceRequirement::Required {
        reason: "Engine requires forced removal".into(),
    };
    projected.path_race = PathRace::Residual;

    let mut model = PlanModel::default();
    model.load(projection(vec![projected.clone()])).unwrap();
    assert_eq!(model.action(&projected.id), Some(&projected));
}
