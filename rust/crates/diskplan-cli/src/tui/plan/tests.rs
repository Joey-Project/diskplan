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

#[test]
fn stable_id_clones_share_immutable_storage() {
    let action_id = ActionId::new("shared-action-id");
    let clone = action_id.clone();
    assert!(std::sync::Arc::ptr_eq(&action_id.0, &clone.0));
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
fn invalid_replacement_clears_the_previous_actionable_plan() {
    let mut model = PlanModel::default();
    model.load(representative_projection()).unwrap();
    model.set_filter("ready-cache");
    assert!(model.open_targets(&ActionId::new("ready-cache-a")));
    model.resize_targets(1);

    let duplicate = action(
        "same",
        PlanDisposition::Ready,
        "cache",
        "Caches",
        1,
        1,
        ByteValue::Known(1),
        "/private/replacement",
    );
    assert_eq!(
        model.load(projection(vec![duplicate.clone(), duplicate])),
        Err(PlanModelError::DuplicateActionId(ActionId::new("same")))
    );

    assert!(model.current_plan_id().is_none());
    assert!(model.invalidated().is_none());
    assert!(model.action(&ActionId::new("ready-cache-a")).is_none());
    assert_eq!(model.row_count(), 0);
    assert!(model.cursor().is_none());
    assert!(model.filter().is_empty());
    assert!(model.target_action_id().is_none());
    assert_eq!(model.target_row_count(), 0);
    assert!(model.target_cursor().is_none());
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
    consistent.release_sets = vec![release_set.clone()];
    model.load(consistent).unwrap();
    assert_eq!(model.release_set(&release_set.id), Some(&release_set));
    assert_eq!(model.release_set(&ReleaseSetId::new("missing")), None);
}

#[test]
fn render_queries_reuse_flattened_and_sorted_caches() {
    let mut model = PlanModel::default();
    model.load(representative_projection()).unwrap();
    model.resize(3);
    let loaded = model.cache_metrics();

    for _ in 0..100 {
        assert_eq!(model.row_count(), 9);
        assert_eq!(model.visible_rows().len(), 3);
        assert!(model.cursor().is_some());
        assert!(model.action(&ActionId::new("ready-cache-a")).is_some());
    }
    assert_eq!(model.cache_metrics(), loaded);

    model.set_filter("cache");
    let filtered = model.cache_metrics();
    assert_eq!(filtered.row_cache_rebuilds, loaded.row_cache_rebuilds + 1);
    assert_eq!(filtered.group_sorts, loaded.group_sorts);
    model.set_filter("cache");
    for _ in 0..100 {
        let _ = model.row_count();
        let _ = model.visible_rows();
    }
    assert_eq!(model.cache_metrics(), filtered);

    assert!(model.set_group_sort(
        PlanDisposition::Ready,
        ActionKindId::new("cache"),
        SortMode::ImmediateReclaimDescending,
    ));
    let sorted = model.cache_metrics();
    assert_eq!(sorted.row_cache_rebuilds, filtered.row_cache_rebuilds + 1);
    assert_eq!(sorted.group_sorts, filtered.group_sorts + 1);
    assert!(model.set_group_sort(
        PlanDisposition::Ready,
        ActionKindId::new("cache"),
        SortMode::ImmediateReclaimDescending,
    ));
    for _ in 0..100 {
        let _ = model.row_count();
        let _ = model.visible_rows();
    }
    assert_eq!(model.cache_metrics(), sorted);
}

#[test]
fn large_plan_filter_reuses_search_and_row_allocations() {
    const COUNT: usize = 20_000;
    let actions = (0..COUNT)
        .map(|index| {
            action(
                &format!("action-{index:05}"),
                PlanDisposition::Ready,
                "cache",
                "Caches",
                1,
                index as u64,
                ByteValue::Known(index as u64),
                &format!("/private/large/{index}"),
            )
        })
        .collect();
    let mut model = PlanModel::default();
    model.load(projection(actions)).unwrap();
    let loaded_metrics = model.cache_metrics();
    let loaded_capacities = model.row_cache_capacities();
    assert_eq!(loaded_metrics.search_index_builds, 1);

    model.set_filter("action-12345");
    assert_eq!(model.row_count(), 3);
    assert_eq!(model.cache_metrics().search_index_builds, 1);
    assert_eq!(model.row_cache_capacities(), loaded_capacities);

    model.set_filter("no-match-in-large-plan");
    assert_eq!(model.row_count(), 0);
    assert_eq!(model.cache_metrics().search_index_builds, 1);
    assert_eq!(model.row_cache_capacities(), loaded_capacities);
}

#[test]
fn columns_keep_plan_action_visible_and_do_not_change_search_scope() {
    let mut model = PlanModel::default();
    model.load(representative_projection()).unwrap();
    assert_eq!(model.column_order(), &PlanColumn::DEFAULT_ORDER);
    assert_eq!(model.search_fields(), &PLAN_SEARCH_FIELDS);

    assert!(model.set_column_visible(PlanColumn::StatusBlocker, false));
    assert!(!model.set_column_visible(PlanColumn::PlanAction, false));
    assert!(!model.visible_columns().contains(&PlanColumn::StatusBlocker));
    assert!(model.visible_columns().contains(&PlanColumn::PlanAction));
    assert!(model.move_column(PlanColumn::StatusBlocker, 0));
    assert_eq!(model.column_order()[0], PlanColumn::StatusBlocker);

    let mut blocked = representative_projection();
    blocked.actions[0].blockers = vec![BlockerProjection {
        id: BlockerId::new("open-handle"),
        summary: "Open handle observed".into(),
    }];
    model.load(blocked).unwrap();
    model.set_column_visible(PlanColumn::StatusBlocker, false);
    model.set_filter("open handle");
    assert_eq!(model.row_count(), 3, "hidden columns do not change search");
    model.set_filter("/private/blocked-cache");
    assert_eq!(model.row_count(), 0, "target paths remain target-scoped");
}

#[test]
fn nested_target_expansion_preserves_stable_cursor_and_viewport() {
    let mut projected = action(
        "nested",
        PlanDisposition::Ready,
        "cache",
        "Caches",
        1,
        1,
        ByteValue::Known(10),
        "/private/root",
    );
    projected.targets[0].children = vec![TargetProjection {
        id: TargetId::new("nested-directory"),
        display_path: DisplayPath::new("/private/root/nested"),
        kind: TargetKind::Directory,
        children: vec![TargetProjection {
            id: TargetId::new("nested-leaf"),
            display_path: DisplayPath::new("/private/root/nested/leaf"),
            kind: TargetKind::File,
            children: Vec::new(),
        }],
    }];
    let mut model = PlanModel::default();
    model.load(projection(vec![projected])).unwrap();
    assert!(model.open_targets(&ActionId::new("nested")));
    model.resize_targets(2);
    assert_eq!(model.target_row_count(), 3);

    let leaf = TargetRowKey {
        action_id: ActionId::new("nested"),
        target_id: TargetId::new("nested-leaf"),
    };
    assert!(model.select_target(&leaf));
    assert_eq!(model.visible_target_rows().last().unwrap().key, leaf);
    model.resize_targets(1);
    assert_eq!(model.target_cursor(), Some(&leaf));
    assert_eq!(model.visible_target_rows()[0].key, leaf);

    let nested = TargetRowKey {
        action_id: ActionId::new("nested"),
        target_id: TargetId::new("nested-directory"),
    };
    assert!(model.toggle_target_expanded(&nested));
    assert_eq!(model.target_row_count(), 2);
    assert_ne!(model.target_cursor(), Some(&leaf));
    assert!(model.target_viewport_top() < model.target_row_count());

    model.set_target_filter("nested/leaf");
    assert_eq!(
        model.target_row_count(),
        3,
        "filter exposes matching ancestors"
    );
    assert_eq!(model.target_cursor(), Some(&nested));
    assert!(!model.toggle_target_expanded(&nested));
    model.set_target_filter("no-target-match");
    assert_eq!(model.target_row_count(), 0);
    assert_eq!(
        model.row_count(),
        3,
        "target filtering cannot alter the plan tree"
    );
}

#[test]
fn large_target_tree_is_virtualized_and_reuses_filter_buffers() {
    const COUNT: usize = 20_000;
    let mut projected = action(
        "large-targets",
        PlanDisposition::Ready,
        "cache",
        "Caches",
        1,
        1,
        ByteValue::Known(10),
        "/private/large-targets",
    );
    projected.targets[0].children = (0..COUNT)
        .map(|index| TargetProjection {
            id: TargetId::new(format!("leaf-{index:05}")),
            display_path: DisplayPath::new(format!("/private/large-targets/{index:05}")),
            kind: TargetKind::File,
            children: Vec::new(),
        })
        .collect();
    let mut model = PlanModel::default();
    model.load(projection(vec![projected])).unwrap();
    assert!(model.open_targets(&ActionId::new("large-targets")));
    let loaded_metrics = model.cache_metrics();
    let loaded_capacities = model.target_cache_capacities();
    assert_eq!(loaded_metrics.target_row_cache_rebuilds, 1);
    assert_eq!(model.target_row_count(), COUNT + 1);
    model.resize_targets(6);
    model.move_target_cursor(COUNT as isize);
    assert_eq!(model.visible_target_rows().len(), 6);
    assert_eq!(
        model.target_cursor(),
        Some(&TargetRowKey {
            action_id: ActionId::new("large-targets"),
            target_id: TargetId::new("leaf-19999"),
        })
    );

    model.set_target_filter("/19999");
    assert_eq!(model.target_row_count(), 2);
    assert_eq!(
        model.cache_metrics().target_row_cache_rebuilds,
        loaded_metrics.target_row_cache_rebuilds + 1
    );
    assert_eq!(model.target_cache_capacities(), loaded_capacities);
    model.set_target_filter("no-match");
    assert_eq!(model.target_row_count(), 0);
    assert_eq!(model.target_cache_capacities(), loaded_capacities);
}

#[test]
fn large_nonempty_release_set_index_loads_and_resolves_members() {
    const COUNT: usize = 5_000;
    let mut actions = Vec::with_capacity(COUNT);
    let mut release_sets = Vec::with_capacity(COUNT);
    for index in 0..COUNT {
        let action_id = ActionId::new(format!("action-{index}"));
        let release_set_id = ReleaseSetId::new(format!("release-{index}"));
        let mut projected = action(
            action_id.as_str(),
            PlanDisposition::Conditional,
            "clone",
            "APFS clones",
            1,
            index as u64,
            ByteValue::Known(index as u64),
            &format!("/private/clone/{index}"),
        );
        projected.release_set_ids = vec![release_set_id.clone()];
        actions.push(projected);
        release_sets.push(ReleaseSetProjection {
            id: release_set_id,
            action_ids: vec![action_id],
            shared_unlock: ByteValue::Known((index as u64) * 2),
        });
    }
    let plan = PlanProjection {
        id: PlanId::new("large-release-plan"),
        actions,
        release_sets,
    };
    let mut model = PlanModel::default();
    model.load(plan).unwrap();

    assert_eq!(model.row_count(), COUNT + 2);
    for index in [0, COUNT / 2, COUNT - 1] {
        let release_set = model
            .release_set(&ReleaseSetId::new(format!("release-{index}")))
            .unwrap();
        assert_eq!(
            release_set.action_ids,
            vec![ActionId::new(format!("action-{index}"))]
        );
        assert_eq!(
            release_set.shared_unlock,
            ByteValue::Known((index as u64) * 2)
        );
    }
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
