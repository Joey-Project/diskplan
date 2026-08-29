use crossterm::event::{KeyCode, KeyEventKind};
use diskplan_proto::diskplan::v1::{
    ControlRejectCode, ScanControlKind, ScanMachineState, ScanSetupRejectCode, ScanState,
    engine_event,
};

use super::model::{
    ActiveRequest, AppState, Effect, EngineDelivery, PlanCommand, RequestPhase, Screen,
    TerminalState, UiEvent,
};
use super::plan::{OverlayStageResult, PlanIntentKind, PlanRuntimeEvent, PlanView};

pub fn reduce(state: &mut AppState, event: UiEvent) -> Vec<Effect> {
    match event {
        UiEvent::Key(key) => reduce_key(state, key.code, key.kind),
        UiEvent::Resize => Vec::new(),
        UiEvent::Plan(event) if state.terminal.is_none() => reduce_plan_event(state, event),
        UiEvent::Plan(_) => Vec::new(),
        UiEvent::Engine(delivery) if state.terminal.is_none() => {
            reduce_engine_event(state, delivery)
        }
        UiEvent::Engine(_) => Vec::new(),
        UiEvent::DriverExited(result) => {
            state.driver_exited = true;
            if let Err(detail) = result {
                state.scan_state = ScanState::Failed;
                state.terminal = Some(TerminalState::Failed(detail.clone()));
                state.banner = Some(detail);
            } else if state.terminal.is_none() {
                let detail = "engine exited before a terminal scan event".to_owned();
                state.scan_state = ScanState::Failed;
                state.terminal = Some(TerminalState::Failed(detail.clone()));
                state.banner = Some(detail);
            }
            Vec::new()
        }
    }
}

fn reduce_key(state: &mut AppState, code: KeyCode, kind: KeyEventKind) -> Vec<Effect> {
    if kind != KeyEventKind::Press || state.terminal.is_some() {
        return Vec::new();
    }

    if code == KeyCode::Char('?') {
        state.help_visible = !state.help_visible;
        return Vec::new();
    }
    if state.help_visible {
        if code == KeyCode::Char('/') {
            state.help_visible = false;
        }
        return Vec::new();
    }
    if state.screen == Screen::ProvisionalPlan && state.plan.filter_editing() {
        return reduce_filter_key(state, code);
    }

    match code {
        KeyCode::Char('/') => {
            state.help_visible = !state.help_visible;
            Vec::new()
        }
        KeyCode::Char('q')
            if state.scan_finalized
                && matches!(
                    state.scan_state,
                    ScanState::Finished | ScanState::FinalizedPartial | ScanState::Cancelled
                ) =>
        {
            let summary = state
                .banner
                .clone()
                .unwrap_or_else(|| "scan evidence finalized".into());
            state.terminal = Some(if state.scan_state == ScanState::Cancelled {
                TerminalState::Cancelled(summary)
            } else {
                TerminalState::Finished(summary)
            });
            vec![Effect::StopDriver]
        }
        KeyCode::Char('q')
            if matches!(
                state.scan_state,
                ScanState::Finished | ScanState::FinalizedPartial | ScanState::Cancelled
            ) =>
        {
            Vec::new()
        }
        KeyCode::Char('q') => request_once(state, ScanControlKind::CancelScan),
        KeyCode::Char(' ') if state.screen == Screen::Scan => match state.scan_state {
            ScanState::Running => request_once(state, ScanControlKind::PauseScan),
            ScanState::Paused => request_once(state, ScanControlKind::ResumeScan),
            _ => Vec::new(),
        },
        KeyCode::Char('p') if state.screen == Screen::Scan => match state.scan_state {
            ScanState::Running | ScanState::Paused => {
                request_once(state, ScanControlKind::FinalizePartialScan)
            }
            _ => Vec::new(),
        },
        KeyCode::Char('r')
            if (state.screen == Screen::ProvisionalPlan && state.plan.provisional())
                || state.scan_state == ScanState::Paused =>
        {
            request_once(state, ScanControlKind::ResumeScan)
        }
        KeyCode::Char('j') | KeyCode::Down if state.screen == Screen::ProvisionalPlan => {
            state.plan.move_navigation(1);
            Vec::new()
        }
        KeyCode::Char('k') | KeyCode::Up if state.screen == Screen::ProvisionalPlan => {
            state.plan.move_navigation(-1);
            Vec::new()
        }
        KeyCode::Enter | KeyCode::Char('l') if state.screen == Screen::ProvisionalPlan => {
            state.plan.expand_navigation();
            Vec::new()
        }
        KeyCode::Char('h') | KeyCode::Left if state.screen == Screen::ProvisionalPlan => {
            state.plan.collapse_navigation();
            Vec::new()
        }
        KeyCode::Char(' ') if state.screen == Screen::ProvisionalPlan => {
            match state.plan.queue_selected_stage_edit() {
                Ok(edit) => {
                    state.banner = Some(match (edit.stage(), edit.force_warning()) {
                        (true, Some(reason)) => {
                            format!("Stage requested; apply will require explicit force: {reason}")
                        }
                        (true, None) => {
                            "Stage requested; waiting for engine acknowledgement".into()
                        }
                        (false, _) => {
                            "Unstage requested; waiting for engine acknowledgement".into()
                        }
                    });
                    return vec![Effect::SendPlan(PlanCommand::EditStage(edit))];
                }
                Err(result) => {
                    state.banner = Some(match result {
                        OverlayStageResult::Staged { .. } | OverlayStageResult::Unstaged => {
                            "Unexpected local overlay transition".into()
                        }
                        OverlayStageResult::RequiresWaivers(waivers) => format!(
                            "Engine waiver acknowledgement required: {}",
                            waivers
                                .iter()
                                .map(ToString::to_string)
                                .collect::<Vec<_>>()
                                .join(", ")
                        ),
                        OverlayStageResult::NotStageable => {
                            "Engine marks this action report-only; it cannot be staged".into()
                        }
                        OverlayStageResult::NoActionSelected => {
                            "Select an action row before staging".into()
                        }
                        OverlayStageResult::RevisionExhausted => {
                            "Decision overlay revision space exhausted; reload the plan".into()
                        }
                        OverlayStageResult::AwaitingAcknowledgement => {
                            "An overlay edit is already awaiting engine acknowledgement".into()
                        }
                    });
                }
            }
            Vec::new()
        }
        KeyCode::Char('e') if state.screen == Screen::ProvisionalPlan => {
            select_action_view(state, PlanView::Evidence);
            Vec::new()
        }
        KeyCode::Char('t') if state.screen == Screen::ProvisionalPlan => {
            select_action_view(state, PlanView::Targets);
            Vec::new()
        }
        KeyCode::Char('g') if state.screen == Screen::ProvisionalPlan => {
            select_action_view(state, PlanView::Dependencies);
            Vec::new()
        }
        KeyCode::Char('v') if state.screen == Screen::ProvisionalPlan => {
            select_action_view(state, PlanView::Coverage);
            Vec::new()
        }
        KeyCode::Char('p') if state.screen == Screen::ProvisionalPlan => {
            state.plan.set_view(PlanView::Summary);
            Vec::new()
        }
        KeyCode::Char('c') if state.screen == Screen::ProvisionalPlan => {
            state.plan.toggle_column_profile();
            state.banner = Some(if state.plan.compact_columns() {
                "Compact column profile".into()
            } else {
                "Full column profile".into()
            });
            Vec::new()
        }
        KeyCode::Char('s') if state.screen == Screen::ProvisionalPlan => {
            state.banner = Some(if state.plan.cycle_group_sort() {
                format!(
                    "Current action group sorted by {:?}",
                    state.plan.sort_mode()
                )
            } else {
                "Select an action type or action row before sorting".into()
            });
            Vec::new()
        }
        KeyCode::Char('f') if state.screen == Screen::ProvisionalPlan => {
            state.plan.begin_filter();
            Vec::new()
        }
        KeyCode::Char('D') if state.screen == Screen::ProvisionalPlan => {
            queue_plan_intent(state, PlanIntentKind::DryRun)
        }
        KeyCode::Char('A') if state.screen == Screen::ProvisionalPlan => {
            queue_plan_intent(state, PlanIntentKind::ApplyReview)
        }
        _ => Vec::new(),
    }
}

fn reduce_filter_key(state: &mut AppState, code: KeyCode) -> Vec<Effect> {
    match code {
        KeyCode::Esc => state.plan.cancel_filter(),
        KeyCode::Enter => state.plan.finish_filter(),
        KeyCode::Backspace => state.plan.pop_filter_char(),
        KeyCode::Char(character) => state.plan.push_filter_char(character),
        _ => {}
    }
    Vec::new()
}

fn select_action_view(state: &mut AppState, view: PlanView) {
    if state.plan.selected_action_id().is_none() {
        state.banner = Some("Select an action row first".into());
        return;
    }
    if state.plan.set_view(view) {
        state.banner = Some(format!("{} view", view.label()));
    } else {
        state.banner = Some("Select an action row first".into());
    }
}

fn queue_plan_intent(state: &mut AppState, intent: PlanIntentKind) -> Vec<Effect> {
    let view = match intent {
        PlanIntentKind::DryRun => PlanView::Revalidation,
        PlanIntentKind::ApplyReview => PlanView::SelectedActions,
    };
    match state.plan.queue_intent(intent) {
        Ok(()) => {
            state.plan.set_view(view);
            state.banner = Some(match intent {
                PlanIntentKind::DryRun => "Dry-run queued for the engine adapter".into(),
                PlanIntentKind::ApplyReview => {
                    "Apply review requested; this local selection is not execution authorization"
                        .into()
                }
            });
            vec![Effect::SendPlan(PlanCommand::Prepare(intent))]
        }
        Err(reason) => {
            state.banner = Some(reason.into());
            Vec::new()
        }
    }
}

fn reduce_plan_event(state: &mut AppState, event: PlanRuntimeEvent) -> Vec<Effect> {
    let overlay_acknowledgement = matches!(&event, PlanRuntimeEvent::OverlayAcknowledged(_))
        .then(|| {
            state.plan.pending_overlay_edit().map(|edit| {
                match (edit.stage(), edit.force_warning()) {
                    (true, Some(reason)) => {
                        format!("Action staged; apply will require explicit force: {reason}")
                    }
                    (true, None) => "Action staged by the engine".into(),
                    (false, _) => "Action unstaged by the engine".into(),
                }
            })
        })
        .flatten();
    let status_only = matches!(
        &event,
        PlanRuntimeEvent::DryRunReady { .. }
            | PlanRuntimeEvent::OperationRejected { .. }
            | PlanRuntimeEvent::OverlayAcknowledged(_)
    );
    match &event {
        PlanRuntimeEvent::DryRunReady {
            current,
            action_count,
            finding_count,
        } => {
            state.plan.set_view(PlanView::Revalidation);
            state.banner = Some(format!(
                "Dry-run ready: {action_count} actions, {finding_count} findings, current={current}"
            ));
        }
        PlanRuntimeEvent::OperationRejected { operation, summary } => {
            if *operation == "overlay edit" {
                state.plan.reject_pending_overlay_edit();
            }
            state.banner = Some(format!("{operation} unavailable: {summary}"));
        }
        _ => {}
    }
    let had_plan = state.plan.model().current_plan_id().is_some();
    match state.plan.apply_event(event) {
        Ok(()) => {
            let invalidation = had_plan && state.plan.model().current_plan_id().is_none();
            state.help_visible = false;
            if invalidation {
                state.screen = Screen::Scan;
                state.banner = Some("Plan invalidated because scan evidence changed".into());
                if let Some(origin) = state.active_request.clone()
                    && origin.kind == ScanControlKind::ResumeScan
                    && origin.phase == RequestPhase::AwaitingInvalidation
                {
                    set_active_phase(state, &origin, RequestPhase::AwaitingResumeState);
                }
            } else if let Some(banner) = overlay_acknowledgement {
                state.screen = Screen::ProvisionalPlan;
                state.banner = Some(banner);
            } else if state.plan.model().current_plan_id().is_some() && !status_only {
                state.screen = Screen::ProvisionalPlan;
                state.provisional_plan = None;
                state.banner = Some(if state.plan.provisional() {
                    "Provisional engine plan ready; continuing the scan will invalidate it".into()
                } else {
                    "Immutable engine plan ready".into()
                });
            }
            Vec::new()
        }
        Err(error) => protocol_failure(state, error.to_string()),
    }
}

fn request_once(state: &mut AppState, kind: ScanControlKind) -> Vec<Effect> {
    if state.has_pending(kind) || (kind == ScanControlKind::CancelScan && state.cancel_requested) {
        return Vec::new();
    }
    match state.try_next_control(kind) {
        Ok(command) => {
            if kind == ScanControlKind::CancelScan {
                state.cancel_requested = true;
                state.banner = Some("Cancellation requested; waiting for the engine…".into());
            }
            vec![Effect::SendControl(command)]
        }
        Err(_) => protocol_failure(state, "request ID space exhausted".into()),
    }
}

fn reduce_engine_event(state: &mut AppState, delivery: EngineDelivery) -> Vec<Effect> {
    let event = delivery.event;
    let is_progress = matches!(event.body, Some(engine_event::Body::ScanProgress(_)));
    let Some(expected) = state.last_event_sequence.checked_add(1) else {
        return protocol_failure(state, "event sequence space exhausted".into());
    };
    let Some(accepted_sequence) = expected.checked_add(delivery.skipped_progress_events) else {
        return protocol_failure(state, "coalesced event sequence overflow".into());
    };
    if delivery.skipped_progress_events > 0 && !is_progress {
        return protocol_failure(
            state,
            "non-progress event claimed a coalesced progress gap".into(),
        );
    }
    if event.event_sequence != accepted_sequence {
        return protocol_failure(
            state,
            format!(
                "event sequence mismatch: expected {accepted_sequence}, received {}",
                event.event_sequence
            ),
        );
    }
    state.last_event_sequence = event.event_sequence;

    match event.body {
        Some(engine_event::Body::ControlAccepted(accepted)) => {
            let Some(pending) = state
                .pending_controls
                .iter()
                .find(|pending| pending.request_id == event.request_id)
                .cloned()
            else {
                return protocol_failure(
                    state,
                    format!("engine acknowledged unknown request {}", event.request_id),
                );
            };
            if pending.kind as i32 != accepted.control {
                return protocol_failure(
                    state,
                    format!(
                        "engine acknowledged request {} with a different control",
                        event.request_id
                    ),
                );
            }
            let Ok(resulting_state) = ScanState::try_from(accepted.resulting_state) else {
                return protocol_failure(state, "engine acknowledged an unknown scan state".into());
            };
            if resulting_state == ScanState::Unspecified {
                return protocol_failure(
                    state,
                    "engine acknowledged an unspecified scan state".into(),
                );
            }
            if !accepted_transition_is_valid(pending.kind, state.scan_state, resulting_state) {
                return protocol_failure(
                    state,
                    format!(
                        "engine acknowledged {:?} with impossible transition {:?} -> {:?}",
                        pending.kind, state.scan_state, resulting_state
                    ),
                );
            }
            let phase = match pending.kind {
                ScanControlKind::ResumeScan
                    if state.provisional_plan.is_some()
                        || state.plan.model().current_plan_id().is_some() =>
                {
                    RequestPhase::AwaitingInvalidation
                }
                ScanControlKind::ResumeScan => RequestPhase::AwaitingResumeState,
                _ => RequestPhase::AwaitingStateConfirmation,
            };
            state.take_pending(event.request_id);
            if pending.kind == ScanControlKind::ResumeScan
                && state
                    .latest_checkpoint
                    .as_ref()
                    .is_some_and(|checkpoint| checkpoint.provisional)
            {
                state.latest_checkpoint = None;
            }
            state.active_request = Some(ActiveRequest {
                request_id: event.request_id,
                kind: pending.kind,
                phase,
            });
            state.scan_state = resulting_state;
            state.banner = Some(format!("{} acknowledged", control_label(pending.kind)));
        }
        Some(engine_event::Body::ControlRejected(rejected)) => {
            let Some(pending) = state
                .pending_controls
                .iter()
                .find(|pending| pending.request_id == event.request_id)
                .cloned()
            else {
                return protocol_failure(
                    state,
                    format!("engine rejected unknown request {}", event.request_id),
                );
            };
            if rejected.control != pending.kind as i32 {
                return protocol_failure(
                    state,
                    format!(
                        "engine rejected request {} with a different control",
                        event.request_id
                    ),
                );
            }
            let Ok(code) = ControlRejectCode::try_from(rejected.code) else {
                return protocol_failure(state, "engine returned an unknown rejection code".into());
            };
            if code == ControlRejectCode::Unspecified {
                return protocol_failure(
                    state,
                    "engine returned an unspecified rejection code".into(),
                );
            }
            let Ok(current_state) = ScanState::try_from(rejected.current_state) else {
                return protocol_failure(state, "engine rejected in an unknown scan state".into());
            };
            if current_state == ScanState::Unspecified {
                return protocol_failure(
                    state,
                    "engine rejected in an unspecified scan state".into(),
                );
            }
            if current_state != state.scan_state {
                return protocol_failure(
                    state,
                    format!(
                        "engine rejected request {} in a different scan state",
                        event.request_id
                    ),
                );
            }
            let Ok(setup_code) = ScanSetupRejectCode::try_from(rejected.setup_code) else {
                return protocol_failure(
                    state,
                    "engine returned an unknown scan setup rejection code".into(),
                );
            };
            let setup_code_is_typed = setup_code != ScanSetupRejectCode::Unspecified;
            if setup_code_is_typed
                && (pending.kind != ScanControlKind::StartScan
                    || !matches!(
                        code,
                        ControlRejectCode::MalformedRequest | ControlRejectCode::Unavailable
                    ))
            {
                return protocol_failure(
                    state,
                    "engine returned inconsistent scan setup rejection provenance".into(),
                );
            }
            state.take_pending(event.request_id);
            if pending.kind == ScanControlKind::CancelScan {
                state.cancel_requested = false;
            }
            state.banner = Some(format!("control rejected: {}", rejected.detail));
        }
        Some(body) => {
            if event.request_id == 0 {
                return reduce_natural_event(state, body);
            }
            let Some(origin) = state.active_request.clone() else {
                return protocol_failure(
                    state,
                    format!(
                        "event for request {} has no acknowledged origin",
                        event.request_id
                    ),
                );
            };
            if origin.request_id != event.request_id {
                return protocol_failure(
                    state,
                    format!(
                        "event request {} does not match active origin {}",
                        event.request_id, origin.request_id
                    ),
                );
            }
            return reduce_origin_event(state, origin, body);
        }
        None => {
            return protocol_failure(state, "engine emitted an empty event".into());
        }
    }
    Vec::new()
}

fn accepted_transition_is_valid(
    control: ScanControlKind,
    current: ScanState,
    resulting: ScanState,
) -> bool {
    match control {
        ScanControlKind::StartScan => current == ScanState::Idle && resulting == ScanState::Running,
        ScanControlKind::PauseScan => {
            current == ScanState::Running && resulting == ScanState::Paused
        }
        ScanControlKind::ResumeScan => {
            current == ScanState::Paused && resulting == ScanState::Running
        }
        ScanControlKind::PauseAndBuildProvisionalPlan => false,
        ScanControlKind::CheckpointProvisionalEvidence => {
            matches!(current, ScanState::Running | ScanState::Paused)
                && resulting == ScanState::Paused
        }
        ScanControlKind::CheckpointScan => {
            matches!(current, ScanState::Running | ScanState::Paused) && resulting == current
        }
        ScanControlKind::FinalizePartialScan => {
            matches!(current, ScanState::Running | ScanState::Paused)
                && resulting == ScanState::FinalizingPartial
        }
        ScanControlKind::CancelScan => {
            matches!(current, ScanState::Running | ScanState::Paused)
                && resulting == ScanState::Cancelling
        }
        ScanControlKind::Unspecified => false,
    }
}

fn reduce_natural_event(state: &mut AppState, body: engine_event::Body) -> Vec<Effect> {
    match body {
        engine_event::Body::ScanStateChanged(changed) => {
            let Ok(next) = ScanState::try_from(changed.state) else {
                return protocol_failure(state, "engine reported an unknown scan state".into());
            };
            if next == ScanState::Unspecified
                || !natural_transition_is_valid(state.scan_state, next)
            {
                return protocol_failure(
                    state,
                    format!(
                        "natural state transition {:?} -> {:?} is invalid",
                        state.scan_state, next
                    ),
                );
            }
            state.scan_state = next;
            if next == ScanState::Running
                && state
                    .latest_checkpoint
                    .as_ref()
                    .is_some_and(|checkpoint| checkpoint.provisional)
            {
                state.latest_checkpoint = None;
            }
            state.banner = Some(changed.reason);
            state.active_request = None;
        }
        engine_event::Body::ScanProgress(progress) => {
            if state.scan_state != ScanState::Running {
                return protocol_failure(
                    state,
                    "progress arrived while scan was not running".into(),
                );
            }
            state.progress = Some(progress);
            state.banner = Some("Scanning read-only evidence…".into());
        }
        engine_event::Body::ScanNodeObserved(observed) => {
            if state.scan_state != ScanState::Running {
                return protocol_failure(
                    state,
                    "node evidence arrived while scan was not running".into(),
                );
            }
            let Some(node) = observed.node else {
                return protocol_failure(state, "node event omitted typed evidence".into());
            };
            let Some(path) = node.path else {
                return protocol_failure(state, "node event omitted raw path evidence".into());
            };
            if path.root_id.is_empty() || path.display_path.is_empty() {
                return protocol_failure(state, "node event has incomplete path provenance".into());
            }
        }
        engine_event::Body::ScanCheckpointChunk(_) => {
            if !matches!(
                state.scan_state,
                ScanState::Running
                    | ScanState::Paused
                    | ScanState::Finished
                    | ScanState::FinalizedPartial
                    | ScanState::Cancelled
            ) {
                return protocol_failure(
                    state,
                    "checkpoint chunk arrived outside a checkpoint-capable scan state".into(),
                );
            }
            // EngineSession validates and retains every chunk before the
            // reducer sees it. Evidence becomes UI-visible only when the
            // matching ready/finalized manifest has been verified.
        }
        engine_event::Body::ScanCheckpointReady(ready) => {
            if !matches!(state.scan_state, ScanState::Running | ScanState::Paused) {
                return protocol_failure(state, "checkpoint arrived outside an active scan".into());
            }
            let Some(checkpoint) = ready.checkpoint else {
                return protocol_failure(state, "checkpoint event omitted evidence".into());
            };
            if checkpoint.profile.is_empty() {
                return protocol_failure(state, "checkpoint omitted its scan profile".into());
            }
            if !checkpoint.resumable_in_process {
                return protocol_failure(state, "active checkpoint is not resumable".into());
            }
            let provisional = checkpoint.provisional;
            state.latest_checkpoint = Some(checkpoint);
            state.banner = Some(if provisional {
                "Provisional evidence checkpoint ready; resume to continue scanning".into()
            } else {
                "Evidence checkpoint ready".into()
            });
            state.active_request = None;
        }
        engine_event::Body::ScanFinalized(finalized) => {
            let Some(checkpoint) = finalized.checkpoint else {
                return protocol_failure(state, "finalized event omitted evidence".into());
            };
            if checkpoint.profile.is_empty() {
                return protocol_failure(
                    state,
                    "finalized checkpoint omitted its scan profile".into(),
                );
            }
            if checkpoint.resumable_in_process || checkpoint.provisional {
                return protocol_failure(
                    state,
                    "finalized checkpoint claimed resumable or provisional evidence".into(),
                );
            }
            let Ok(machine_state) = ScanMachineState::try_from(checkpoint.machine_state) else {
                return protocol_failure(
                    state,
                    "finalized checkpoint has an unknown machine state".into(),
                );
            };
            let next = match machine_state {
                ScanMachineState::Complete => ScanState::Finished,
                ScanMachineState::Partial => ScanState::FinalizedPartial,
                ScanMachineState::Cancelled => ScanState::Cancelled,
                ScanMachineState::Unspecified
                | ScanMachineState::Ready
                | ScanMachineState::Scanning => {
                    return protocol_failure(
                        state,
                        "finalized checkpoint has a non-terminal machine state".into(),
                    );
                }
            };
            if !natural_transition_is_valid(state.scan_state, next) {
                return protocol_failure(
                    state,
                    format!(
                        "finalized checkpoint cannot transition {:?} -> {:?}",
                        state.scan_state, next
                    ),
                );
            }
            state.scan_state = next;
            state.latest_checkpoint = Some(checkpoint);
            state.scan_finalized = true;
            state.banner = Some(finalized.reason);
            state.active_request = None;
        }
        engine_event::Body::ScanCancelled(cancelled) => {
            if state.scan_state != ScanState::Cancelled || !state.scan_finalized {
                return protocol_failure(
                    state,
                    "cancellation terminal arrived before finalized cancelled evidence".into(),
                );
            }
            state.scan_state = ScanState::Cancelled;
            state.banner = Some(cancelled.reason);
        }
        engine_event::Body::ScanFinished(_) => {
            return protocol_failure(
                state,
                "protocol 1.3 received legacy ScanFinished without finalized evidence".into(),
            );
        }
        engine_event::Body::EngineFailed(failed) => {
            state.scan_state = ScanState::Failed;
            let detail = format!("{}: {}", failed.code, failed.detail);
            state.terminal = Some(TerminalState::Failed(detail.clone()));
            state.banner = Some(detail);
            return vec![Effect::StopDriver];
        }
        engine_event::Body::ControlAccepted(_) | engine_event::Body::ControlRejected(_) => {
            return protocol_failure(state, "acknowledgement entered natural-event path".into());
        }
        engine_event::Body::ProvisionalPlanReady(_)
        | engine_event::Body::ProvisionalPlanInvalidated(_) => {
            return protocol_failure(
                state,
                "Phase 1 scan stream emitted an unsupported plan projection".into(),
            );
        }
    }
    Vec::new()
}

fn natural_transition_is_valid(current: ScanState, next: ScanState) -> bool {
    current == next
        || matches!(
            (current, next),
            (ScanState::Idle, ScanState::Running)
                | (ScanState::Running, ScanState::Paused)
                | (ScanState::Paused, ScanState::Running)
                | (
                    ScanState::Running | ScanState::Paused,
                    ScanState::FinalizingPartial
                )
                | (ScanState::FinalizingPartial, ScanState::FinalizedPartial)
                | (
                    ScanState::Running | ScanState::Paused,
                    ScanState::Cancelling
                )
                | (ScanState::Cancelling, ScanState::Cancelled)
                | (ScanState::Running, ScanState::Finished)
                | (ScanState::Running, ScanState::FinalizedPartial)
        )
}

fn reduce_origin_event(
    state: &mut AppState,
    origin: ActiveRequest,
    body: engine_event::Body,
) -> Vec<Effect> {
    match body {
        engine_event::Body::ScanStateChanged(changed) => {
            let Ok(next) = ScanState::try_from(changed.state) else {
                return protocol_failure(state, "engine reported an unknown scan state".into());
            };
            if next == ScanState::Unspecified {
                return protocol_failure(state, "engine reported an unspecified scan state".into());
            }
            let next_phase = match (origin.kind, origin.phase, state.scan_state, next) {
                (
                    ScanControlKind::StartScan,
                    RequestPhase::AwaitingStateConfirmation,
                    ScanState::Running,
                    ScanState::Running,
                )
                | (
                    ScanControlKind::PauseScan,
                    RequestPhase::AwaitingStateConfirmation,
                    ScanState::Paused,
                    ScanState::Paused,
                ) => RequestPhase::Steady,
                (
                    ScanControlKind::PauseAndBuildProvisionalPlan,
                    RequestPhase::AwaitingStateConfirmation,
                    ScanState::BuildingProvisionalPlan,
                    ScanState::BuildingProvisionalPlan,
                ) => RequestPhase::AwaitingPlanReadyState,
                (
                    ScanControlKind::PauseAndBuildProvisionalPlan,
                    RequestPhase::AwaitingPlanReadyState,
                    ScanState::BuildingProvisionalPlan,
                    ScanState::ProvisionalPlanReady,
                ) => RequestPhase::AwaitingPlanProjection,
                (
                    ScanControlKind::ResumeScan,
                    RequestPhase::AwaitingResumeState,
                    ScanState::Running,
                    ScanState::Running,
                ) => RequestPhase::AwaitingResumeProgress,
                (
                    ScanControlKind::CancelScan,
                    RequestPhase::AwaitingStateConfirmation,
                    ScanState::Cancelling,
                    ScanState::Cancelling,
                ) => RequestPhase::AwaitingCancelledState,
                (
                    ScanControlKind::CancelScan,
                    RequestPhase::AwaitingCancelledState,
                    ScanState::Cancelling,
                    ScanState::Cancelled,
                ) => RequestPhase::AwaitingCancelledTerminal,
                _ => {
                    return protocol_failure(
                        state,
                        format!(
                            "state change {:?} -> {:?} is invalid for {:?} in {:?}",
                            state.scan_state, next, origin.kind, origin.phase
                        ),
                    );
                }
            };
            state.scan_state = next;
            state.banner = Some(changed.reason);
            set_active_phase(state, &origin, next_phase);
        }
        engine_event::Body::ScanProgress(progress) => {
            let valid = state.scan_state == ScanState::Running
                && matches!(
                    (origin.kind, origin.phase),
                    (ScanControlKind::StartScan, RequestPhase::Steady)
                        | (
                            ScanControlKind::ResumeScan,
                            RequestPhase::AwaitingResumeProgress | RequestPhase::Steady
                        )
                );
            if !valid {
                return invalid_origin_event(state, &origin, "ScanProgress");
            }
            state.progress = Some(progress);
            set_active_phase(state, &origin, RequestPhase::Steady);
        }
        engine_event::Body::ProvisionalPlanReady(plan) => {
            if origin.kind != ScanControlKind::PauseAndBuildProvisionalPlan
                || origin.phase != RequestPhase::AwaitingPlanProjection
                || state.scan_state != ScanState::ProvisionalPlanReady
                || state.provisional_plan.is_some()
                || plan.plan_id.is_empty()
            {
                return invalid_origin_event(state, &origin, "ProvisionalPlanReady");
            }
            state.provisional_plan = Some(plan);
            state.screen = Screen::ProvisionalPlan;
            state.help_visible = false;
            set_active_phase(state, &origin, RequestPhase::Steady);
        }
        engine_event::Body::ProvisionalPlanInvalidated(invalidated) => {
            let current_plan_id = state
                .provisional_plan
                .as_ref()
                .map(|plan| plan.plan_id.clone())
                .or_else(|| {
                    state
                        .plan
                        .model()
                        .current_plan_id()
                        .map(ToString::to_string)
                });
            let Some(current_plan_id) = current_plan_id else {
                return protocol_failure(state, "engine invalidated an unknown plan".into());
            };
            if origin.kind != ScanControlKind::ResumeScan
                || origin.phase != RequestPhase::AwaitingInvalidation
                || invalidated.previous_plan_id != current_plan_id
            {
                return protocol_failure(
                    state,
                    format!(
                        "plan invalidation {:?} does not match active plan {:?}",
                        invalidated.previous_plan_id, current_plan_id
                    ),
                );
            }
            if state.plan.model().current_plan_id().is_some()
                && let Err(error) = state.plan.apply_event(PlanRuntimeEvent::Invalidate {
                    plan_id: super::plan::PlanId::new(invalidated.previous_plan_id.clone()),
                    reason: "scan resumed".into(),
                })
            {
                return protocol_failure(state, error.to_string());
            }
            state.provisional_plan = None;
            state.screen = Screen::Scan;
            state.help_visible = false;
            set_active_phase(state, &origin, RequestPhase::AwaitingResumeState);
        }
        engine_event::Body::ScanCancelled(cancelled) => {
            if origin.kind != ScanControlKind::CancelScan
                || origin.phase != RequestPhase::AwaitingCancelledTerminal
                || state.scan_state != ScanState::Cancelled
            {
                return invalid_origin_event(state, &origin, "ScanCancelled");
            }
            state.terminal = Some(TerminalState::Cancelled(cancelled.reason));
        }
        engine_event::Body::ScanFinished(_) => {
            return protocol_failure(
                state,
                "protocol 1.3 received legacy ScanFinished without finalized evidence".into(),
            );
        }
        engine_event::Body::EngineFailed(failed) => {
            state.scan_state = ScanState::Failed;
            state.terminal = Some(TerminalState::Failed(format!(
                "{}: {}",
                failed.code, failed.detail
            )));
        }
        engine_event::Body::ControlAccepted(_) | engine_event::Body::ControlRejected(_) => {
            return protocol_failure(
                state,
                "ack event bypassed acknowledgement validation".into(),
            );
        }
        engine_event::Body::ScanNodeObserved(_)
        | engine_event::Body::ScanCheckpointChunk(_)
        | engine_event::Body::ScanCheckpointReady(_)
        | engine_event::Body::ScanFinalized(_) => {
            return invalid_origin_event(state, &origin, "natural scan-stream event");
        }
    }
    Vec::new()
}

fn set_active_phase(state: &mut AppState, origin: &ActiveRequest, phase: RequestPhase) {
    state.active_request = Some(ActiveRequest {
        request_id: origin.request_id,
        kind: origin.kind,
        phase,
    });
}

fn invalid_origin_event(state: &mut AppState, origin: &ActiveRequest, event: &str) -> Vec<Effect> {
    protocol_failure(
        state,
        format!(
            "{event} is invalid for {:?} request {} in {:?}",
            origin.kind, origin.request_id, origin.phase
        ),
    )
}

fn protocol_failure(state: &mut AppState, detail: String) -> Vec<Effect> {
    state.scan_state = ScanState::Failed;
    state.terminal = Some(TerminalState::Failed(detail.clone()));
    state.banner = Some(detail);
    vec![Effect::StopDriver]
}

fn control_label(kind: ScanControlKind) -> &'static str {
    match kind {
        ScanControlKind::StartScan => "Start",
        ScanControlKind::PauseScan => "Pause",
        ScanControlKind::ResumeScan => "Resume",
        ScanControlKind::PauseAndBuildProvisionalPlan => "Unsupported legacy provisional plan",
        ScanControlKind::CheckpointProvisionalEvidence => "Provisional evidence",
        ScanControlKind::CheckpointScan => "Checkpoint",
        ScanControlKind::FinalizePartialScan => "Finalize partial scan",
        ScanControlKind::CancelScan => "Cancel",
        ScanControlKind::Unspecified => "Unknown control",
    }
}

#[cfg(test)]
mod tests {
    use crossterm::event::{KeyEvent, KeyEventState, KeyModifiers};
    use diskplan_proto::diskplan::v1::{
        ControlAccepted, ControlRejected, EngineEvent, EngineFailed, ProvisionalPlanInvalidated,
        ProvisionalPlanReady, ScanCancelled, ScanCheckpointChunk, ScanCheckpointEvidence,
        ScanCheckpointReady, ScanFinalized, ScanFinished, ScanMachineState, ScanNodeObserved,
        ScanProgress, ScanRootRequest, ScanState, ScanStateChanged, engine_event,
    };

    use super::super::model::PendingControl;
    use super::*;

    #[test]
    fn input_table_waits_for_ack_and_suppresses_repeat_release_and_duplicates() {
        let cases = [
            (KeyEventKind::Press, 1),
            (KeyEventKind::Repeat, 0),
            (KeyEventKind::Release, 0),
        ];
        for (kind, expected_effects) in cases {
            let mut state = running_state();
            let effects = reduce(&mut state, key(' ', kind));
            assert_eq!(effects.len(), expected_effects);
            assert_eq!(state.scan_state, ScanState::Running);
        }

        let mut state = running_state();
        assert_eq!(reduce(&mut state, key(' ', KeyEventKind::Press)).len(), 1);
        assert!(reduce(&mut state, key(' ', KeyEventKind::Press)).is_empty());
        assert_eq!(state.scan_state, ScanState::Running);
    }

    #[test]
    fn reducer_finalizes_partial_evidence_before_planning() {
        let mut state = running_state();
        let effect = reduce(&mut state, key('p', KeyEventKind::Press));
        let Effect::SendControl(command) = effect[0] else {
            panic!("expected control effect");
        };
        assert_eq!(command.kind, ScanControlKind::FinalizePartialScan);

        let acknowledgement_effects = reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                1,
                command.request_id,
                engine_event::Body::ControlAccepted(ControlAccepted {
                    control: command.kind as i32,
                    resulting_state: ScanState::FinalizingPartial as i32,
                }),
            ))),
        );
        assert_eq!(state.scan_state, ScanState::FinalizingPartial);
        assert!(state.pending_controls.is_empty());
        assert!(acknowledgement_effects.is_empty());

        let effects = reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                2,
                0,
                engine_event::Body::ScanFinalized(ScanFinalized {
                    checkpoint: Some(ScanCheckpointEvidence {
                        profile: "standard".into(),
                        resolved_roots: vec![ScanRootRequest {
                            root_id: "fixture".into(),
                            raw_absolute_path: b"/tmp/fixture".to_vec(),
                            display_path: "/tmp/fixture".into(),
                        }],
                        machine_state: ScanMachineState::Partial as i32,
                        resumable_in_process: false,
                        provisional: false,
                        ..Default::default()
                    }),
                    reason: "partial evidence finalized".into(),
                    ..Default::default()
                }),
            ))),
        );
        assert!(effects.is_empty());
        assert!(!state.latest_checkpoint.as_ref().unwrap().provisional);
        assert_eq!(state.screen, Screen::Scan);
        assert!(state.provisional_plan.is_none());
        assert_eq!(state.scan_state, ScanState::FinalizedPartial);
        assert!(state.scan_finalized);
    }

    #[test]
    fn finalized_scan_keeps_driver_alive_until_explicit_quit() {
        let mut state = running_state();
        state.scan_state = ScanState::FinalizingPartial;
        let effects = reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                1,
                0,
                engine_event::Body::ScanStateChanged(ScanStateChanged {
                    state: ScanState::FinalizedPartial as i32,
                    reason: "evidence finalized".into(),
                }),
            ))),
        );
        assert!(effects.is_empty());
        let effects = reduce(&mut state, key('q', KeyEventKind::Press));
        assert!(effects.is_empty(), "q must wait for ScanFinalized evidence");
        assert!(state.terminal.is_none());

        let effects = reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                2,
                0,
                engine_event::Body::ScanFinalized(ScanFinalized {
                    checkpoint: Some(ScanCheckpointEvidence {
                        profile: "standard".into(),
                        resolved_roots: vec![ScanRootRequest {
                            root_id: "fixture".into(),
                            raw_absolute_path: b"/tmp/fixture".to_vec(),
                            display_path: "/tmp/fixture".into(),
                        }],
                        machine_state: ScanMachineState::Partial as i32,
                        ..Default::default()
                    }),
                    reason: "evidence finalized".into(),
                    ..Default::default()
                }),
            ))),
        );
        assert!(effects.is_empty());
        assert_eq!(state.scan_state, ScanState::FinalizedPartial);
        assert!(state.scan_finalized);
        assert_eq!(
            state.latest_checkpoint.as_ref().unwrap().machine_state,
            ScanMachineState::Partial as i32
        );
        assert!(state.terminal.is_none());

        let effects = reduce(&mut state, key('q', KeyEventKind::Press));
        assert_eq!(effects, vec![Effect::StopDriver]);
        assert!(matches!(state.terminal, Some(TerminalState::Finished(_))));
    }

    #[test]
    fn finalized_cancellation_also_requires_explicit_quit() {
        let mut state = running_state();
        state.scan_state = ScanState::Cancelling;
        assert!(
            reduce(
                &mut state,
                UiEvent::Engine(EngineDelivery::exact(engine_event(
                    1,
                    0,
                    engine_event::Body::ScanStateChanged(ScanStateChanged {
                        state: ScanState::Cancelled as i32,
                        reason: "scan cancelled".into(),
                    }),
                ))),
            )
            .is_empty()
        );
        assert!(
            reduce(
                &mut state,
                UiEvent::Engine(EngineDelivery::exact(engine_event(
                    2,
                    0,
                    engine_event::Body::ScanFinalized(ScanFinalized {
                        checkpoint: Some(ScanCheckpointEvidence {
                            profile: "standard".into(),
                            machine_state: ScanMachineState::Cancelled as i32,
                            ..Default::default()
                        }),
                        reason: "scan cancelled".into(),
                        ..Default::default()
                    }),
                ))),
            )
            .is_empty()
        );
        assert!(
            reduce(
                &mut state,
                UiEvent::Engine(EngineDelivery::exact(engine_event(
                    3,
                    0,
                    engine_event::Body::ScanCancelled(ScanCancelled {
                        reason: "scan cancelled".into(),
                    }),
                ))),
            )
            .is_empty()
        );
        assert!(state.scan_finalized);
        assert!(state.terminal.is_none());

        let effects = reduce(&mut state, key('q', KeyEventKind::Press));
        assert_eq!(effects, vec![Effect::StopDriver]);
        assert!(matches!(state.terminal, Some(TerminalState::Cancelled(_))));
    }

    #[test]
    fn legacy_scan_finished_cannot_bypass_finalized_evidence() {
        let mut active = running_state();
        let effects = reduce(
            &mut active,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                1,
                0,
                engine_event::Body::ScanFinished(ScanFinished {
                    summary: "legacy completion".into(),
                }),
            ))),
        );
        assert_eq!(effects, vec![Effect::StopDriver]);
        assert!(!active.scan_finalized);
        assert!(matches!(active.terminal, Some(TerminalState::Failed(_))));

        let mut natural = running_state();
        natural.active_request = None;
        let effects = reduce(
            &mut natural,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                1,
                0,
                engine_event::Body::ScanFinished(ScanFinished {
                    summary: "legacy completion".into(),
                }),
            ))),
        );
        assert_eq!(effects, vec![Effect::StopDriver]);
        assert!(!natural.scan_finalized);
        assert!(matches!(natural.terminal, Some(TerminalState::Failed(_))));
    }

    #[test]
    fn question_mark_and_slash_are_contextual_help_aliases() {
        let mut state = running_state();
        reduce(&mut state, key('?', KeyEventKind::Press));
        assert!(state.help_visible);
        reduce(&mut state, key('/', KeyEventKind::Press));
        assert!(!state.help_visible);

        state.screen = Screen::ProvisionalPlan;
        reduce(&mut state, key('/', KeyEventKind::Press));
        assert!(state.help_visible);
        reduce(&mut state, key('?', KeyEventKind::Press));
        assert!(!state.help_visible);
    }

    #[test]
    fn q_is_emitted_once_even_when_another_control_is_pending() {
        let mut state = running_state();
        assert_eq!(reduce(&mut state, key(' ', KeyEventKind::Press)).len(), 1);
        assert_eq!(reduce(&mut state, key('q', KeyEventKind::Press)).len(), 1);
        assert!(reduce(&mut state, key('q', KeyEventKind::Press)).is_empty());
        assert_eq!(state.pending_controls.len(), 2);
    }

    #[test]
    fn malformed_semantic_event_table_fails_terminally_and_stops_driver() {
        let mut mismatch_state = pending_state(2, ScanControlKind::PauseScan);
        mismatch_state.scan_state = ScanState::Running;
        let cases = vec![
            (
                "unknown request ack",
                running_state(),
                EngineDelivery::exact(engine_event(
                    1,
                    99,
                    engine_event::Body::ControlAccepted(ControlAccepted {
                        control: ScanControlKind::PauseScan as i32,
                        resulting_state: ScanState::Paused as i32,
                    }),
                )),
            ),
            (
                "control mismatch",
                mismatch_state,
                EngineDelivery::exact(engine_event(
                    1,
                    2,
                    engine_event::Body::ControlAccepted(ControlAccepted {
                        control: ScanControlKind::ResumeScan as i32,
                        resulting_state: ScanState::Paused as i32,
                    }),
                )),
            ),
            (
                "unknown resulting state",
                pending_state(2, ScanControlKind::PauseScan),
                EngineDelivery::exact(engine_event(
                    1,
                    2,
                    engine_event::Body::ControlAccepted(ControlAccepted {
                        control: ScanControlKind::PauseScan as i32,
                        resulting_state: 999,
                    }),
                )),
            ),
            (
                "empty event",
                running_state(),
                EngineDelivery::exact(EngineEvent {
                    event_sequence: 1,
                    request_id: 0,
                    body: None,
                    ..Default::default()
                }),
            ),
            (
                "rejection without matching pending request",
                running_state(),
                EngineDelivery::exact(engine_event(
                    1,
                    77,
                    engine_event::Body::ControlRejected(ControlRejected {
                        control: ScanControlKind::PauseScan as i32,
                        detail: "no".into(),
                        current_state: ScanState::Running as i32,
                        ..Default::default()
                    }),
                )),
            ),
        ];

        for (name, mut state, delivery) in cases {
            let effects = reduce(&mut state, UiEvent::Engine(delivery));
            assert_eq!(effects, vec![Effect::StopDriver], "{name}");
            assert_eq!(state.scan_state, ScanState::Failed, "{name}");
            assert!(
                matches!(state.terminal, Some(TerminalState::Failed(_))),
                "{name}"
            );
        }
    }

    #[test]
    fn matching_control_rejection_is_non_terminal() {
        let mut state = pending_state(2, ScanControlKind::CancelScan);
        state.cancel_requested = true;
        let effects = reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                1,
                2,
                engine_event::Body::ControlRejected(ControlRejected {
                    control: ScanControlKind::CancelScan as i32,
                    code: ControlRejectCode::InvalidState as i32,
                    detail: "too late".into(),
                    current_state: ScanState::Running as i32,
                    ..Default::default()
                }),
            ))),
        );

        assert!(effects.is_empty());
        assert!(state.terminal.is_none());
        assert!(!state.cancel_requested);
        assert!(state.pending_controls.is_empty());
        assert_eq!(state.scan_state, ScanState::Running);
    }

    #[test]
    fn typed_start_setup_rejection_is_non_terminal_and_non_start_setup_code_fails() {
        let mut start_state = AppState::default();
        let effects = reduce(
            &mut start_state,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                1,
                1,
                engine_event::Body::ControlRejected(ControlRejected {
                    control: ScanControlKind::StartScan as i32,
                    code: ControlRejectCode::MalformedRequest as i32,
                    detail: "invalid root".into(),
                    current_state: ScanState::Idle as i32,
                    setup_code: ScanSetupRejectCode::InvalidRoot as i32,
                }),
            ))),
        );
        assert!(effects.is_empty());
        assert!(start_state.terminal.is_none());
        assert!(start_state.pending_controls.is_empty());

        let mut control_state = pending_state(2, ScanControlKind::PauseScan);
        let effects = reduce(
            &mut control_state,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                1,
                2,
                engine_event::Body::ControlRejected(ControlRejected {
                    control: ScanControlKind::PauseScan as i32,
                    code: ControlRejectCode::Unavailable as i32,
                    detail: "wrong provenance".into(),
                    current_state: ScanState::Running as i32,
                    setup_code: ScanSetupRejectCode::InvalidRoot as i32,
                }),
            ))),
        );
        assert_eq!(effects, vec![Effect::StopDriver]);
        assert!(matches!(
            control_state.terminal,
            Some(TerminalState::Failed(_))
        ));
    }

    #[test]
    fn inbound_control_capacity_rejection_is_typed_and_non_terminal() {
        let mut state = pending_state(2, ScanControlKind::CheckpointScan);
        let effects = reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                1,
                2,
                engine_event::Body::ControlRejected(ControlRejected {
                    control: ScanControlKind::CheckpointScan as i32,
                    code: ControlRejectCode::CapacityExceeded as i32,
                    detail: "control queue capacity exceeded".into(),
                    current_state: ScanState::Running as i32,
                    ..Default::default()
                }),
            ))),
        );

        assert!(effects.is_empty());
        assert!(state.terminal.is_none());
        assert!(state.pending_controls.is_empty());
        assert_eq!(state.scan_state, ScanState::Running);
        assert_eq!(
            state.banner.as_deref(),
            Some("control rejected: control queue capacity exceeded")
        );
    }

    #[test]
    fn invalid_control_rejection_code_table_fails_terminally() {
        for code in [ControlRejectCode::Unspecified as i32, 999] {
            let mut state = pending_state(2, ScanControlKind::CancelScan);
            state.cancel_requested = true;
            let effects = reduce(
                &mut state,
                UiEvent::Engine(EngineDelivery::exact(engine_event(
                    1,
                    2,
                    engine_event::Body::ControlRejected(ControlRejected {
                        control: ScanControlKind::CancelScan as i32,
                        code,
                        detail: "invalid rejection code".into(),
                        current_state: ScanState::Running as i32,
                        ..Default::default()
                    }),
                ))),
            );

            assert_eq!(effects, vec![Effect::StopDriver], "code {code}");
            assert!(matches!(state.terminal, Some(TerminalState::Failed(_))));
            assert!(
                state.cancel_requested,
                "failed ack must not mutate pending state"
            );
            assert_eq!(state.pending_controls.len(), 1);
        }
    }

    #[test]
    fn accepted_transition_table_is_exhaustive() {
        let controls = [
            ScanControlKind::Unspecified,
            ScanControlKind::StartScan,
            ScanControlKind::PauseScan,
            ScanControlKind::ResumeScan,
            ScanControlKind::PauseAndBuildProvisionalPlan,
            ScanControlKind::CancelScan,
            ScanControlKind::CheckpointScan,
            ScanControlKind::FinalizePartialScan,
            ScanControlKind::CheckpointProvisionalEvidence,
        ];
        let states = [
            ScanState::Unspecified,
            ScanState::Idle,
            ScanState::Running,
            ScanState::Paused,
            ScanState::BuildingProvisionalPlan,
            ScanState::ProvisionalPlanReady,
            ScanState::Cancelling,
            ScanState::Cancelled,
            ScanState::Finished,
            ScanState::Failed,
            ScanState::FinalizingPartial,
            ScanState::FinalizedPartial,
        ];
        let valid = [
            (
                ScanControlKind::StartScan,
                ScanState::Idle,
                ScanState::Running,
            ),
            (
                ScanControlKind::PauseScan,
                ScanState::Running,
                ScanState::Paused,
            ),
            (
                ScanControlKind::ResumeScan,
                ScanState::Paused,
                ScanState::Running,
            ),
            (
                ScanControlKind::CheckpointProvisionalEvidence,
                ScanState::Running,
                ScanState::Paused,
            ),
            (
                ScanControlKind::CheckpointProvisionalEvidence,
                ScanState::Paused,
                ScanState::Paused,
            ),
            (
                ScanControlKind::CancelScan,
                ScanState::Running,
                ScanState::Cancelling,
            ),
            (
                ScanControlKind::CancelScan,
                ScanState::Paused,
                ScanState::Cancelling,
            ),
            (
                ScanControlKind::CheckpointScan,
                ScanState::Running,
                ScanState::Running,
            ),
            (
                ScanControlKind::CheckpointScan,
                ScanState::Paused,
                ScanState::Paused,
            ),
            (
                ScanControlKind::FinalizePartialScan,
                ScanState::Running,
                ScanState::FinalizingPartial,
            ),
            (
                ScanControlKind::FinalizePartialScan,
                ScanState::Paused,
                ScanState::FinalizingPartial,
            ),
        ];

        for control in controls {
            for current in states {
                for resulting in states {
                    assert_eq!(
                        accepted_transition_is_valid(control, current, resulting),
                        valid.contains(&(control, current, resulting)),
                        "{control:?}: {current:?} -> {resulting:?}"
                    );
                }
            }
        }
    }

    #[test]
    fn impossible_control_acceptance_fails_terminally() {
        let mut state = pending_state(2, ScanControlKind::PauseScan);
        let effects = reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                1,
                2,
                engine_event::Body::ControlAccepted(ControlAccepted {
                    control: ScanControlKind::PauseScan as i32,
                    resulting_state: ScanState::Running as i32,
                }),
            ))),
        );

        assert_eq!(effects, vec![Effect::StopDriver]);
        assert!(matches!(state.terminal, Some(TerminalState::Failed(_))));
    }

    #[test]
    fn natural_events_reject_nonzero_request_ids() {
        let bodies = vec![
            engine_event::Body::ScanStateChanged(ScanStateChanged {
                state: ScanState::Running as i32,
                ..Default::default()
            }),
            engine_event::Body::ScanProgress(ScanProgress::default()),
            engine_event::Body::ScanNodeObserved(ScanNodeObserved::default()),
            engine_event::Body::ScanCheckpointChunk(ScanCheckpointChunk::default()),
            engine_event::Body::ScanCheckpointReady(ScanCheckpointReady::default()),
            engine_event::Body::ScanFinalized(ScanFinalized::default()),
            engine_event::Body::ProvisionalPlanReady(ProvisionalPlanReady::default()),
            engine_event::Body::ProvisionalPlanInvalidated(ProvisionalPlanInvalidated::default()),
            engine_event::Body::ScanCancelled(ScanCancelled::default()),
            engine_event::Body::ScanFinished(ScanFinished::default()),
            engine_event::Body::EngineFailed(EngineFailed::default()),
        ];

        for (index, body) in bodies.into_iter().enumerate() {
            let mut state = running_state();
            let effects = reduce(
                &mut state,
                UiEvent::Engine(EngineDelivery::exact(engine_event(1, 99, body))),
            );
            assert_eq!(effects, vec![Effect::StopDriver], "body {index}");
            assert!(matches!(state.terminal, Some(TerminalState::Failed(_))));
        }

        let mut state = running_state();
        let effects = reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                1,
                0,
                engine_event::Body::ScanProgress(ScanProgress {
                    profile: "standard".into(),
                    ..Default::default()
                }),
            ))),
        );
        assert!(effects.is_empty());
        assert_eq!(state.progress.unwrap().profile, "standard");
    }

    #[test]
    fn plan_invalidation_requires_the_exact_active_plan_id() {
        for plan_id in ["stale", ""] {
            let mut state = AppState {
                screen: Screen::ProvisionalPlan,
                scan_state: ScanState::Running,
                provisional_plan: Some(ProvisionalPlanReady {
                    plan_id: "current".into(),
                    ..Default::default()
                }),
                active_request: Some(ActiveRequest {
                    request_id: 3,
                    kind: ScanControlKind::ResumeScan,
                    phase: RequestPhase::AwaitingInvalidation,
                }),
                pending_controls: Vec::new(),
                banner: None,
                ..AppState::default()
            };
            let effects = reduce(
                &mut state,
                UiEvent::Engine(EngineDelivery::exact(engine_event(
                    1,
                    3,
                    engine_event::Body::ProvisionalPlanInvalidated(ProvisionalPlanInvalidated {
                        previous_plan_id: plan_id.into(),
                    }),
                ))),
            );
            assert_eq!(effects, vec![Effect::StopDriver]);
            assert!(matches!(state.terminal, Some(TerminalState::Failed(_))));
        }

        let mut unknown = AppState {
            scan_state: ScanState::Running,
            active_request: Some(ActiveRequest {
                request_id: 3,
                kind: ScanControlKind::ResumeScan,
                phase: RequestPhase::AwaitingInvalidation,
            }),
            pending_controls: Vec::new(),
            ..AppState::default()
        };
        let effects = reduce(
            &mut unknown,
            UiEvent::Engine(EngineDelivery::exact(engine_event(
                1,
                3,
                engine_event::Body::ProvisionalPlanInvalidated(ProvisionalPlanInvalidated {
                    previous_plan_id: "missing".into(),
                }),
            ))),
        );
        assert_eq!(effects, vec![Effect::StopDriver]);
        assert!(matches!(unknown.terminal, Some(TerminalState::Failed(_))));
    }

    #[test]
    fn reducer_accepts_only_exactly_proven_progress_gaps() {
        let mut state = running_state();
        let accepted = reduce(
            &mut state,
            UiEvent::Engine(EngineDelivery {
                event: engine_event(
                    3,
                    1,
                    engine_event::Body::ScanProgress(ScanProgress {
                        entries: 3,
                        ..Default::default()
                    }),
                ),
                skipped_progress_events: 2,
            }),
        );
        assert!(accepted.is_empty());
        assert_eq!(state.last_event_sequence, 3);
        assert_eq!(
            state.progress.as_ref().map(|progress| progress.entries),
            Some(3)
        );

        for (sequence, skipped) in [(3, 0), (2, 0), (6, 1)] {
            let mut invalid = AppState {
                last_event_sequence: 3,
                ..running_state()
            };
            let effects = reduce(
                &mut invalid,
                UiEvent::Engine(EngineDelivery {
                    event: engine_event(
                        sequence,
                        1,
                        engine_event::Body::ScanProgress(ScanProgress::default()),
                    ),
                    skipped_progress_events: skipped,
                }),
            );
            assert_eq!(effects, vec![Effect::StopDriver]);
            assert!(matches!(invalid.terminal, Some(TerminalState::Failed(_))));
        }
    }

    #[test]
    fn request_id_overflow_fails_without_emitting_a_duplicate() {
        let mut state = running_state();
        state.next_request_id = u64::MAX;

        let effects = reduce(&mut state, key(' ', KeyEventKind::Press));

        assert_eq!(effects, vec![Effect::StopDriver]);
        assert!(state.pending_controls.is_empty());
        assert!(matches!(state.terminal, Some(TerminalState::Failed(_))));
    }

    #[test]
    fn plan_hotkeys_edit_only_the_overlay_and_action_scoped_view() {
        use crate::tui::plan::{
            ActionId, ActionKindId, ActionKindProjection, ActionProjection, Activity, ByteValue,
            DisplayPath, EnginePlanSnapshot, ForceRequirement, PathRace, PlanDisposition, PlanId,
            PlanProjection, Recoverability, Stageability, TargetId, TargetKind, TargetProjection,
        };

        let mut state = AppState::default();
        assert!(
            reduce(
                &mut state,
                UiEvent::Plan(PlanRuntimeEvent::Load(EnginePlanSnapshot {
                    projection: PlanProjection {
                        id: PlanId::new("plan-1"),
                        actions: vec![ActionProjection {
                            id: ActionId::new("action-1"),
                            disposition: PlanDisposition::Ready,
                            kind: ActionKindProjection {
                                id: ActionKindId::new("generic-remove"),
                                label: "Generic remove".into(),
                                order: 1,
                            },
                            label: "Remove candidate".into(),
                            order: 1,
                            stageability: Stageability::Stageable,
                            immediate_reclaim: ByteValue::Known(4096),
                            shared_unlock: ByteValue::Unknown,
                            activity: Activity::Inactive,
                            recoverability: Recoverability::Rebuildable,
                            blockers: Vec::new(),
                            prerequisites: Vec::new(),
                            release_set_ids: Vec::new(),
                            force: ForceRequirement::Required {
                                reason: "engine requires force".into(),
                            },
                            path_race: PathRace::Residual,
                            targets: vec![TargetProjection {
                                id: TargetId::new("target-1"),
                                display_path: DisplayPath::new("/display/only"),
                                kind: TargetKind::Directory,
                                children: Vec::new(),
                            }],
                        }],
                        release_sets: Vec::new(),
                    },
                    evidence_reference: "evidence-1".into(),
                    provisional: false,
                })),
            )
            .is_empty()
        );
        state.resize_plan_layout(80, 28);
        assert_eq!(state.screen, Screen::ProvisionalPlan);

        reduce(&mut state, key('j', KeyEventKind::Press));
        reduce(&mut state, key('j', KeyEventKind::Press));
        assert_eq!(
            state.plan.selected_action_id(),
            Some(&ActionId::new("action-1"))
        );

        let effects = reduce(&mut state, key(' ', KeyEventKind::Press));
        let Effect::SendPlan(PlanCommand::EditStage(edit)) = &effects[0] else {
            panic!("expected authoritative overlay edit");
        };
        assert_eq!(edit.action_id(), &ActionId::new("action-1"));
        assert!(edit.stage());
        assert!(
            !state
                .plan
                .overlay()
                .unwrap()
                .is_selected(&ActionId::new("action-1"))
        );
        assert!(reduce(&mut state, key(' ', KeyEventKind::Press)).is_empty());
        assert!(
            state
                .banner
                .as_deref()
                .unwrap()
                .contains("already awaiting")
        );
        reduce(
            &mut state,
            UiEvent::Plan(PlanRuntimeEvent::OverlayAcknowledged(
                crate::tui::plan::EngineOverlaySnapshot {
                    plan_id: PlanId::new("plan-1"),
                    evidence_reference: "evidence-1".into(),
                    selected_action_ids: vec![ActionId::new("action-1")],
                    revision: 1,
                    digest: "engine-overlay-digest".into(),
                },
            )),
        );
        assert!(
            state
                .plan
                .overlay()
                .unwrap()
                .is_selected(&ActionId::new("action-1"))
        );
        assert_eq!(
            state.banner.as_deref(),
            Some("Action staged; apply will require explicit force: engine requires force")
        );

        reduce(&mut state, key('t', KeyEventKind::Press));
        assert_eq!(state.plan.view(), PlanView::Targets);
        reduce(&mut state, key('f', KeyEventKind::Press));
        reduce(&mut state, key('d', KeyEventKind::Press));
        assert_eq!(state.plan.model().target_filter(), "d");
        reduce(&mut state, key_code(KeyCode::Enter));
        assert!(!state.plan.filter_editing());

        reduce(&mut state, key('p', KeyEventKind::Press));
        assert_eq!(state.plan.view(), PlanView::Summary);
        reduce(&mut state, key('D', KeyEventKind::Press));
        assert_eq!(
            state.plan.pending_intents()[0].kind(),
            PlanIntentKind::DryRun
        );
        assert_eq!(state.plan.view(), PlanView::Revalidation);

        let overlay = state.plan.overlay().unwrap();
        let expected_revision = overlay.revision();
        let expected_digest = overlay.digest().to_owned();
        reduce(&mut state, key('A', KeyEventKind::Press));
        assert_eq!(state.plan.view(), PlanView::SelectedActions);
        assert!(
            state
                .banner
                .as_deref()
                .unwrap()
                .contains("not execution authorization")
        );
        let apply_intent = state
            .plan
            .pending_intents()
            .iter()
            .find(|intent| intent.kind() == PlanIntentKind::ApplyReview)
            .unwrap();
        assert_eq!(apply_intent.overlay_revision(), expected_revision);
        assert_eq!(apply_intent.overlay_digest(), expected_digest);
        assert_eq!(apply_intent.plan_id(), &PlanId::new("plan-1"));
        assert_eq!(apply_intent.evidence_reference(), "evidence-1");
        assert_eq!(
            apply_intent.selected_action_ids(),
            &[ActionId::new("action-1")]
        );
    }

    #[test]
    fn continuing_scan_invalidates_runtime_overlay_by_exact_plan_id() {
        use crate::tui::plan::{EnginePlanSnapshot, PlanId, PlanProjection};

        let mut state = AppState::default();
        reduce(
            &mut state,
            UiEvent::Plan(PlanRuntimeEvent::Load(EnginePlanSnapshot {
                projection: PlanProjection {
                    id: PlanId::new("plan-1"),
                    actions: Vec::new(),
                    release_sets: Vec::new(),
                },
                evidence_reference: "evidence-1".into(),
                provisional: true,
            })),
        );
        reduce(
            &mut state,
            UiEvent::Plan(PlanRuntimeEvent::Invalidate {
                plan_id: PlanId::new("plan-1"),
                reason: "scan resumed".into(),
            }),
        );

        assert_eq!(state.screen, Screen::Scan);
        assert!(state.plan.overlay().is_none());
        assert_eq!(
            state.plan.model().invalidated().unwrap().reason,
            "scan resumed"
        );
    }

    fn running_state() -> AppState {
        let mut state = AppState {
            scan_state: ScanState::Running,
            banner: None,
            ..AppState::default()
        };
        state.pending_controls.clear();
        state.active_request = Some(ActiveRequest {
            request_id: 1,
            kind: ScanControlKind::StartScan,
            phase: RequestPhase::Steady,
        });
        state
    }

    fn pending_state(request_id: u64, kind: ScanControlKind) -> AppState {
        let mut state = running_state();
        state
            .pending_controls
            .push(PendingControl { request_id, kind });
        state
    }

    fn key(value: char, kind: KeyEventKind) -> UiEvent {
        UiEvent::Key(KeyEvent {
            code: KeyCode::Char(value),
            modifiers: KeyModifiers::NONE,
            kind,
            state: KeyEventState::NONE,
        })
    }

    fn key_code(code: KeyCode) -> UiEvent {
        UiEvent::Key(KeyEvent {
            code,
            modifiers: KeyModifiers::NONE,
            kind: KeyEventKind::Press,
            state: KeyEventState::NONE,
        })
    }

    fn engine_event(sequence: u64, request_id: u64, body: engine_event::Body) -> EngineEvent {
        EngineEvent {
            event_sequence: sequence,
            request_id,
            body: Some(body),
            ..Default::default()
        }
    }
}
