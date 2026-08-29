use diskplan_proto::diskplan::v1::ScanState;
use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};
use unicode_width::{UnicodeWidthChar, UnicodeWidthStr};

use super::model::{AppState, Screen};
use super::plan::{
    Activity, ByteValue, ForceRequirement, PathRace, PlanRuntime, PlanView, Recoverability, RowKey,
    RowLevel, Stageability, TargetKind,
};

pub fn render(frame: &mut Frame<'_>, state: &AppState) {
    let area = frame.area();
    if area.width <= 3 || area.height <= 2 {
        frame.render_widget(Paragraph::new("Diskplan"), area);
        return;
    }

    match state.screen {
        Screen::Scan => render_scan(frame, state, area),
        Screen::ProvisionalPlan => render_plan(frame, state, area),
    }
    if state.help_visible {
        render_help(frame, state, area);
    }
}

fn render_scan(frame: &mut Frame<'_>, state: &AppState, area: Rect) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .split(area);
    render_header(frame, state, sections[0], "Read-only scan");

    let body = if area.width >= 100 {
        scan_wide(state)
    } else if area.width >= 60 {
        scan_medium(state)
    } else {
        scan_compact(state)
    };
    frame.render_widget(
        Paragraph::new(body)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Engine facts "),
            )
            .wrap(Wrap { trim: true }),
        sections[1],
    );
    render_footer(frame, state, sections[2]);
}

fn render_plan(frame: &mut Frame<'_>, state: &AppState, area: Rect) {
    let sections = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Length(3),
            Constraint::Min(3),
            Constraint::Length(3),
        ])
        .split(area);
    let title = if state.plan.model().current_plan_id().is_some() && !state.plan.provisional() {
        "Immutable plan"
    } else {
        "Provisional plan"
    };
    render_header(frame, state, sections[0], title);

    let body = if state.plan.model().current_plan_id().is_some() {
        runtime_plan_body(&state.plan, area.width)
    } else {
        match state.provisional_plan.as_ref() {
            Some(plan) if area.width >= 100 => plan_wide(plan),
            Some(plan) if area.width >= 60 => plan_medium(plan),
            Some(plan) => plan_compact(plan),
            None => vec![Line::from("Waiting for the engine projection…")],
        }
    };
    let body_title = if state.plan.model().current_plan_id().is_some() {
        format!(" Plan-first • {} ", state.plan.view().label())
    } else {
        " Plan-first summary ".into()
    };
    frame.render_widget(
        Paragraph::new(body)
            .block(Block::default().borders(Borders::ALL).title(body_title))
            .wrap(Wrap { trim: true }),
        sections[1],
    );
    render_footer(frame, state, sections[2]);
}

fn render_header(frame: &mut Frame<'_>, state: &AppState, area: Rect, title: &str) {
    let state_label = format!("{:?}", state.scan_state);
    let line = Line::from(vec![
        Span::styled(" diskplan ", Style::default().add_modifier(Modifier::BOLD)),
        Span::raw(format!("{title}  •  {state_label}")),
    ]);
    frame.render_widget(
        Paragraph::new(line).block(Block::default().borders(Borders::ALL)),
        area,
    );
}

fn render_footer(frame: &mut Frame<'_>, state: &AppState, area: Rect) {
    let keys = match (state.screen, state.scan_state) {
        (
            Screen::Scan,
            ScanState::Finished | ScanState::FinalizedPartial | ScanState::Cancelled,
        ) if state.scan_finalized => "q quit  ? or / help",
        (
            Screen::Scan,
            ScanState::Finished | ScanState::FinalizedPartial | ScanState::Cancelled,
        ) => "waiting for finalized evidence  ? or / help",
        (Screen::Scan, _) => "q cancel  Space pause/resume  p provisional evidence  ? or / help",
        (Screen::ProvisionalPlan, _) if state.plan.model().current_plan_id().is_none() => {
            "q cancel  r resume + invalidate  ? help"
        }
        (Screen::ProvisionalPlan, _) if state.plan.filter_editing() => {
            "filter: type  Backspace edit  Enter accept  Esc close"
        }
        (Screen::ProvisionalPlan, _) => {
            "j/k move  Enter/l expand  h collapse  Space stage  p plan  / filter  ? help"
        }
    };
    let banner = state
        .banner
        .as_deref()
        .unwrap_or("Waiting for engine events");
    frame.render_widget(
        Paragraph::new(vec![Line::from(keys), Line::from(banner)])
            .block(Block::default().borders(Borders::TOP)),
        area,
    );
}

fn runtime_plan_body(runtime: &PlanRuntime, width: u16) -> Vec<Line<'static>> {
    let content_width = width.saturating_sub(2) as usize;
    let plan_id = runtime
        .model()
        .current_plan_id()
        .map(ToString::to_string)
        .unwrap_or_default();
    let staged = runtime
        .overlay()
        .map(|overlay| overlay.selected_actions().len())
        .unwrap_or_default();
    let mut lines = Vec::new();
    if width >= 50 {
        lines.push(Line::from(truncate_display(
            &format!(
                "Plan {plan_id} • {staged} staged{}",
                if runtime.provisional() {
                    " • PROVISIONAL"
                } else {
                    ""
                }
            ),
            content_width,
        )));
    }
    if runtime.filter_editing() {
        lines.push(Line::styled(
            truncate_display(
                &format!("Filter /{}", runtime.filter_buffer()),
                content_width,
            ),
            Style::default().fg(Color::Yellow),
        ));
    }
    match runtime.view() {
        PlanView::Summary => lines.extend(plan_summary(runtime, width)),
        PlanView::Targets => lines.extend(plan_targets(runtime, width)),
        PlanView::Evidence => lines.extend(plan_evidence(runtime, width)),
        PlanView::Dependencies => lines.extend(plan_dependencies(runtime, width)),
        PlanView::Coverage => lines.extend(plan_coverage(runtime, width)),
        PlanView::Revalidation => lines.extend(plan_revalidation(runtime, width)),
        PlanView::SelectedActions => lines.extend(plan_selected_actions(runtime, width)),
        PlanView::ExecutionPreview => lines.extend(plan_execution_preview(runtime, width)),
    }
    lines
}

fn plan_summary(runtime: &PlanRuntime, width: u16) -> Vec<Line<'static>> {
    let mut lines = Vec::new();
    if width >= 50 {
        lines.push(Line::styled(
            if width >= 96 && !runtime.compact_columns() {
                format!(
                    "{:<8} {:<33} {:>11} {:>11} {:<8} {:<13} {}",
                    "Decision",
                    "Plan/action",
                    "Immediate",
                    "Shared",
                    "Activity",
                    "Recovery",
                    "Status"
                )
            } else if width >= 58 {
                format!(
                    "{:<8} {:<27} {:>11}  {}",
                    "Decision", "Plan/action", "Immediate", "Status"
                )
            } else {
                "    Plan/action • status".into()
            },
            Style::default().add_modifier(Modifier::BOLD),
        ));
    }
    let cursor = runtime.model().cursor();
    for row in runtime.model().visible_rows() {
        let selected = cursor == Some(&row.key);
        let pointer = if selected { ">" } else { " " };
        let decision = match &row.key {
            RowKey::Action(action_id)
                if runtime
                    .overlay()
                    .is_some_and(|overlay| overlay.is_selected(action_id)) =>
            {
                "[x]"
            }
            RowKey::Action(_) => "[ ]",
            RowKey::Disposition(_) | RowKey::ActionKind { .. } => "   ",
        };
        let disclosure = match row.expanded {
            Some(true) => "▾ ",
            Some(false) => "▸ ",
            None => "  ",
        };
        let indent = "  ".repeat(match row.level {
            RowLevel::Disposition => 0,
            RowLevel::ActionKind => 1,
            RowLevel::Action => 2,
        });
        let label = format!("{indent}{disclosure}{}", row.label);
        let text = match &row.key {
            RowKey::Action(action_id) => runtime
                .model()
                .action(action_id)
                .map(|action| {
                    if width >= 96 && !runtime.compact_columns() {
                        format!(
                            "{:<8} {:<33} {:>11} {:>11} {:<8} {:<13} {}",
                            format!("{pointer}{decision}"),
                            truncate_display(&label, 33),
                            bytes(&action.immediate_reclaim),
                            bytes(&action.shared_unlock),
                            activity(action.activity),
                            recovery(action.recoverability),
                            action_status(action, runtime.overlay())
                        )
                    } else if width >= 58 {
                        format!(
                            "{:<8} {:<27} {:>11}  {}",
                            format!("{pointer}{decision}"),
                            truncate_display(&label, 27),
                            bytes(&action.immediate_reclaim),
                            action_status(action, runtime.overlay())
                        )
                    } else {
                        format!(
                            "{pointer}{decision} {} • {label}",
                            action_status(action, runtime.overlay()),
                        )
                    }
                })
                .unwrap_or_default(),
            RowKey::Disposition(_) | RowKey::ActionKind { .. } => {
                format!("{:<8} {label}", format!("{pointer}{decision}"))
            }
        };
        lines.push(Line::styled(
            truncate_display(&text, width.saturating_sub(2) as usize),
            if selected {
                Style::default().fg(Color::Black).bg(Color::Cyan)
            } else {
                Style::default()
            },
        ));
    }
    lines
}

fn plan_targets(runtime: &PlanRuntime, width: u16) -> Vec<Line<'static>> {
    let Some(action_id) = runtime.model().target_action_id() else {
        return vec![Line::from("Select an action and press t.")];
    };
    let mut lines = vec![Line::styled(
        truncate_display(
            &format!("Action {action_id} • paths are display-only engine data"),
            width.saturating_sub(2) as usize,
        ),
        Style::default().fg(Color::DarkGray),
    )];
    let cursor = runtime.model().target_cursor();
    lines.extend(
        runtime
            .model()
            .visible_target_rows()
            .into_iter()
            .map(|row| {
                let pointer = if cursor == Some(&row.key) { ">" } else { " " };
                let disclosure = match row.expanded {
                    Some(true) => "▾",
                    Some(false) => "▸",
                    None => " ",
                };
                Line::from(truncate_display(
                    &format!(
                        "{pointer}{} {disclosure} {}  ({})",
                        "  ".repeat(row.depth),
                        row.display_path,
                        target_kind(row.kind)
                    ),
                    width.saturating_sub(2) as usize,
                ))
            }),
    );
    lines
}

fn plan_evidence(runtime: &PlanRuntime, width: u16) -> Vec<Line<'static>> {
    let mut detail = DetailBuilder::new(runtime, width);
    let Some(action) = selected_action(runtime) else {
        detail.push_static("Select an action and press e.", Style::default());
        return detail.finish();
    };
    detail.push_with(Style::default(), || format!("Action: {}", action.label));
    detail.push_with(Style::default(), || {
        format!("Activity: {}", activity(action.activity))
    });
    detail.push_with(Style::default(), || {
        format!("Recoverability: {}", recovery(action.recoverability))
    });
    detail.push_with(Style::default(), || {
        format!("Immediate reclaim: {}", bytes(&action.immediate_reclaim))
    });
    detail.push_with(Style::default(), || {
        format!("Shared unlock: {}", bytes(&action.shared_unlock))
    });
    detail.push_with(Style::default(), || {
        format!("Path race: {}", path_race(action.path_race))
    });
    detail.push_static(
        "All values above are copied from the engine projection.",
        Style::default().fg(Color::DarkGray),
    );
    detail.finish()
}

fn plan_dependencies(runtime: &PlanRuntime, width: u16) -> Vec<Line<'static>> {
    let mut detail = DetailBuilder::new(runtime, width);
    let Some(action) = selected_action(runtime) else {
        detail.push_static("Select an action and press g.", Style::default());
        return detail.finish();
    };
    detail.push_with(Style::default(), || format!("Action: {}", action.label));
    if action.prerequisites.is_empty() {
        detail.push_static("Prerequisites: none issued", Style::default());
    } else {
        detail.push_static(
            "Prerequisites",
            Style::default().add_modifier(Modifier::BOLD),
        );
        for item in &action.prerequisites {
            if !detail.push_with(Style::default(), || {
                format!("  {} • {}", item.action_id, item.summary)
            }) {
                return detail.finish();
            }
        }
    }
    if !action.release_set_ids.is_empty() {
        detail.push_static(
            "APFS release sets: every owner must be removed to unlock shared blocks",
            Style::default().add_modifier(Modifier::BOLD),
        );
        for release_id in &action.release_set_ids {
            let Some(release) = runtime.model().release_set(release_id) else {
                continue;
            };
            if !detail.push_with(Style::default(), || {
                format!(
                    "  {} • shared unlock {}",
                    release.id,
                    bytes(&release.shared_unlock)
                )
            }) {
                break;
            }
            for member in &release.action_ids {
                if !detail.push_with(Style::default(), || format!("    owner action {member}")) {
                    return detail.finish();
                }
            }
        }
    }
    detail.finish()
}

fn plan_coverage(runtime: &PlanRuntime, width: u16) -> Vec<Line<'static>> {
    let mut detail = DetailBuilder::new(runtime, width);
    let Some(action) = selected_action(runtime) else {
        detail.push_static(
            "Select an action; coverage is engine-issued evidence.",
            Style::default(),
        );
        return detail.finish();
    };
    detail.push_with(Style::default(), || format!("Action: {}", action.label));
    if action.blockers.is_empty() {
        detail.push_static("Coverage blockers: none issued", Style::default());
    } else {
        detail.push_static("Coverage/status blockers:", Style::default());
        for blocker in &action.blockers {
            if !detail.push_with(Style::default(), || {
                format!("  {} • {}", blocker.id, blocker.summary)
            }) {
                return detail.finish();
            }
        }
    }
    detail.push_static(
        "Absence is not inferred here; only engine projection facts are shown.",
        Style::default().fg(Color::DarkGray),
    );
    detail.finish()
}

fn plan_revalidation(runtime: &PlanRuntime, width: u16) -> Vec<Line<'static>> {
    let mut detail = DetailBuilder::new(runtime, width);
    detail.push_static(
        "Revalidation is authoritative in the Swift engine.",
        Style::default(),
    );
    detail.push_with(Style::default(), || {
        format!("Plan: {}", bound_plan(runtime))
    });
    detail.push_with(Style::default(), || {
        format!("Evidence: {}", bound_evidence(runtime))
    });
    detail.push_with(Style::default(), || {
        format!("Staged actions: {}", staged_count(runtime))
    });
    if runtime.pending_intents().is_empty() {
        detail.push_static("Pending engine requests: none", Style::default());
    } else {
        for intent in runtime.pending_intents() {
            if !detail.push_with(Style::default(), || {
                format!(
                    "Pending {} • overlay revision {} • digest {}",
                    intent_kind_label(intent.kind()),
                    intent.overlay_revision(),
                    intent.overlay_digest()
                )
            }) {
                break;
            }
        }
    }
    detail.finish()
}

fn plan_selected_actions(runtime: &PlanRuntime, width: u16) -> Vec<Line<'static>> {
    let mut detail = DetailBuilder::new(runtime, width);
    detail.push_static(
        "Local selection only; apply review is not execution authorization.",
        Style::default().fg(Color::Yellow),
    );
    let Some(overlay) = runtime.overlay() else {
        detail.push_static("No decision overlay loaded.", Style::default());
        return detail.finish();
    };

    for action_id in overlay.selected_action_order() {
        let Some(action) = runtime.model().action(action_id) else {
            continue;
        };
        if !push_action_warning_lines(&mut detail, action, overlay) {
            return detail.finish();
        }
    }

    detail.push_with(Style::default(), || {
        format!(
            "Overlay revision {} • digest {}",
            overlay.revision(),
            overlay.digest()
        )
    });
    for action_id in overlay.selected_action_order() {
        let Some(action) = runtime.model().action(action_id) else {
            continue;
        };
        if !detail.push_with(Style::default(), || {
            format!(
                "{} • {} • {}",
                action.id,
                action.label,
                action_status(action, Some(overlay))
            )
        }) {
            break;
        }
    }
    detail.finish()
}

fn plan_execution_preview(runtime: &PlanRuntime, width: u16) -> Vec<Line<'static>> {
    let mut detail = DetailBuilder::new(runtime, width);
    let Some(preview) = runtime.execution_preview() else {
        detail.push_static(
            "Execution Preview is unavailable until issued by the engine.",
            Style::default(),
        );
        return detail.finish();
    };

    for warning in &preview.final_warnings {
        if !detail.push_with(
            Style::default()
                .fg(Color::Yellow)
                .add_modifier(Modifier::BOLD),
            || bounded_detail_message(format!("FINAL WARNING {}", warning.id), &warning.message),
        ) {
            return detail.finish();
        }
    }

    detail.push_static(
        "Engine-issued execution DAG order and prerequisite status",
        Style::default().add_modifier(Modifier::BOLD),
    );
    detail.push_static(
        "Commands and argv remain engine-owned and are never composed by the TUI.",
        Style::default().fg(Color::DarkGray),
    );
    for (index, unit) in preview.ordered_units.iter().enumerate() {
        if !detail.push_with(Style::default(), || {
            format!(
                "{}. unit {} • {} • prerequisite status {}",
                index + 1,
                unit.id,
                bounded_detail_field(&unit.label),
                bounded_detail_field(&unit.prerequisite_status)
            )
        }) {
            break;
        }
        for action_id in &unit.covered_action_ids {
            if !detail.push_with(Style::default(), || {
                format!("   covers logical action {action_id}")
            }) {
                return detail.finish();
            }
        }
        for prerequisite_id in &unit.prerequisite_unit_ids {
            if !detail.push_with(Style::default(), || {
                format!("   requires execution unit {prerequisite_id}")
            }) {
                return detail.finish();
            }
        }
    }
    detail.finish()
}

fn push_action_warning_lines(
    detail: &mut DetailBuilder,
    action: &super::plan::ActionProjection,
    overlay: &super::plan::DecisionOverlay,
) -> bool {
    let warning_style = Style::default()
        .fg(Color::Yellow)
        .add_modifier(Modifier::BOLD);
    if let Stageability::RequiresWaivers(required) = &action.stageability {
        for waiver_id in required {
            let reason = overlay
                .waiver_reason(&action.id, waiver_id)
                .unwrap_or("engine acknowledgement missing");
            if !detail.push_with(warning_style, || {
                bounded_detail_message(
                    format!("WAIVER {} for action {}", waiver_id, action.id),
                    reason,
                )
            }) {
                return false;
            }
        }
    }
    if let ForceRequirement::Required { reason } = &action.force
        && !detail.push_with(warning_style, || {
            bounded_detail_message(format!("FORCE required for action {}", action.id), reason)
        })
    {
        return false;
    }
    if action.path_race == PathRace::Residual
        && !detail.push_with(warning_style, || {
            bounded_detail_message(
                format!("PATH RACE residual for action {}", action.id),
                "pathname occupant may change after revalidation",
            )
        })
    {
        return false;
    }
    true
}

fn selected_action(runtime: &PlanRuntime) -> Option<&super::plan::ActionProjection> {
    runtime
        .selected_action_id()
        .and_then(|action_id| runtime.model().action(action_id))
}

fn staged_count(runtime: &PlanRuntime) -> usize {
    runtime
        .overlay()
        .map(|overlay| overlay.selected_actions().len())
        .unwrap_or_default()
}

fn bound_plan(runtime: &PlanRuntime) -> String {
    runtime
        .overlay()
        .map(|overlay| overlay.plan_id().to_string())
        .unwrap_or_else(|| "none".into())
}

fn bound_evidence(runtime: &PlanRuntime) -> &str {
    runtime
        .overlay()
        .map(|overlay| overlay.evidence_reference())
        .unwrap_or("none")
}

fn bytes(value: &ByteValue) -> String {
    match value {
        ByteValue::Known(bytes) => format_bytes(*bytes),
        ByteValue::Unknown => "unknown".into(),
    }
}

fn activity(value: Activity) -> &'static str {
    match value {
        Activity::Inactive => "inactive",
        Activity::Active => "active",
        Activity::Mixed => "mixed",
        Activity::Unknown => "unknown",
    }
}

fn recovery(value: Recoverability) -> &'static str {
    match value {
        Recoverability::Rebuildable => "rebuildable",
        Recoverability::Restorable => "restorable",
        Recoverability::Irrecoverable => "irrecoverable",
        Recoverability::Unknown => "unknown",
    }
}

fn target_kind(value: TargetKind) -> &'static str {
    match value {
        TargetKind::File => "file",
        TargetKind::Directory => "directory",
        TargetKind::Symlink => "symlink",
        TargetKind::Other => "other",
        TargetKind::Unknown => "unknown",
    }
}

fn path_race(value: PathRace) -> &'static str {
    match value {
        PathRace::NoneObserved => "none observed",
        PathRace::Residual => "residual",
        PathRace::Unknown => "unknown",
    }
}

const ACTION_STATUS_BYTE_CAP: usize = 1_024;
const DETAIL_ENCODED_BYTE_CAP: usize = 16 * 1_024;
const DETAIL_FIELD_BYTE_CAP: usize = 1_024;
const DETAIL_FIELD_TRUNCATION_MARKER: &str = "… [message truncated]";

fn bounded_detail_message(prefix: String, message: &str) -> String {
    let mut value = prefix;
    value.push_str(" • ");
    value.push_str(&bounded_detail_field(message));
    value
}

fn bounded_detail_field(value: &str) -> String {
    if value.len() <= DETAIL_FIELD_BYTE_CAP {
        return value.into();
    }

    let content_cap = DETAIL_FIELD_BYTE_CAP.saturating_sub(DETAIL_FIELD_TRUNCATION_MARKER.len());
    let mut boundary = 0;
    for (index, character) in value.char_indices() {
        let end = index.saturating_add(character.len_utf8());
        if end > content_cap {
            break;
        }
        boundary = end;
    }
    let mut truncated = String::with_capacity(DETAIL_FIELD_BYTE_CAP);
    truncated.push_str(&value[..boundary]);
    truncated.push_str(DETAIL_FIELD_TRUNCATION_MARKER);
    truncated
}

fn action_status(
    action: &super::plan::ActionProjection,
    overlay: Option<&super::plan::DecisionOverlay>,
) -> String {
    let mut status = BoundedText::new(ACTION_STATUS_BYTE_CAP);
    let staged = overlay.is_some_and(|overlay| overlay.is_selected(&action.id));
    if staged {
        status.push("staged");
        if let Stageability::RequiresWaivers(required) = &action.stageability {
            for waiver_id in required {
                let reason = overlay
                    .and_then(|overlay| overlay.waiver_reason(&action.id, waiver_id))
                    .unwrap_or("engine acknowledgement missing");
                if !status.push(&format!("waiver {waiver_id}: {reason}")) {
                    break;
                }
            }
        }
        if let ForceRequirement::Required { reason } = &action.force {
            status.push(&format!("force required: {reason}"));
        }
        if action.path_race == PathRace::Residual {
            status.push(
                "path race residual: the exact pathname slot may have a new occupant after revalidation",
            );
        }
    } else if !action.blockers.is_empty() {
        for blocker in &action.blockers {
            if !status.push(&blocker.summary) {
                break;
            }
        }
    } else {
        status.push(match &action.stageability {
            Stageability::Stageable => "stageable",
            Stageability::RequiresWaivers(_) => "waiver required",
            Stageability::NotStageable => "report-only",
        });
    }
    status.finish()
}

fn intent_kind_label(kind: super::plan::PlanIntentKind) -> &'static str {
    match kind {
        super::plan::PlanIntentKind::DryRun => "dry-run request",
        super::plan::PlanIntentKind::ApplyReview => "apply-review request",
    }
}

struct BoundedText {
    value: String,
    byte_cap: usize,
    truncated: bool,
}

impl BoundedText {
    fn new(byte_cap: usize) -> Self {
        Self {
            value: String::new(),
            byte_cap,
            truncated: false,
        }
    }

    fn push(&mut self, value: &str) -> bool {
        let separator = usize::from(!self.value.is_empty()) * 3;
        if self
            .value
            .len()
            .saturating_add(separator)
            .saturating_add(value.len())
            > self.byte_cap
        {
            self.truncated = true;
            return false;
        }
        if !self.value.is_empty() {
            self.value.push_str(" • ");
        }
        self.value.push_str(value);
        true
    }

    fn finish(mut self) -> String {
        if self.truncated && self.value.len().saturating_add(14) <= self.byte_cap {
            self.value.push_str(" • [truncated]");
        }
        self.value
    }
}

struct DetailBuilder {
    lines: Vec<Line<'static>>,
    logical_index: usize,
    skip: usize,
    line_cap: usize,
    byte_count: usize,
    width: usize,
    truncated: bool,
}

impl DetailBuilder {
    fn new(runtime: &PlanRuntime, width: u16) -> Self {
        Self::with_viewport(
            runtime.detail_viewport_top(),
            runtime.detail_viewport_height(),
            width,
        )
    }

    fn with_viewport(skip: usize, line_cap: usize, width: u16) -> Self {
        Self {
            lines: Vec::with_capacity(line_cap),
            logical_index: 0,
            skip,
            line_cap,
            byte_count: 0,
            width: width.saturating_sub(2) as usize,
            truncated: false,
        }
    }

    fn push_static(&mut self, value: &'static str, style: Style) -> bool {
        self.push_with(style, || value.into())
    }

    fn push_with(&mut self, style: Style, render: impl FnOnce() -> String) -> bool {
        if self.lines.len() >= self.line_cap || self.truncated {
            return false;
        }
        let logical_index = self.logical_index;
        self.logical_index = self.logical_index.saturating_add(1);
        if logical_index < self.skip {
            return true;
        }

        let value = render();
        let encoded = value.len().saturating_add(1);
        if self.byte_count.saturating_add(encoded) > DETAIL_ENCODED_BYTE_CAP {
            self.truncated = true;
            if self.lines.len() < self.line_cap {
                self.lines.push(Line::styled(
                    "[detail truncated at encoded byte limit]",
                    Style::default().fg(Color::Yellow),
                ));
            }
            return false;
        }
        self.byte_count += encoded;
        self.lines
            .push(Line::styled(truncate_display(&value, self.width), style));
        self.lines.len() < self.line_cap
    }

    fn finish(self) -> Vec<Line<'static>> {
        self.lines
    }
}

fn truncate_display(value: &str, width: usize) -> String {
    if UnicodeWidthStr::width(value) <= width {
        return value.into();
    }
    if width == 0 {
        return String::new();
    }
    let ellipsis_width = UnicodeWidthChar::width('…').unwrap_or(1);
    let target = width.saturating_sub(ellipsis_width);
    let mut used = 0usize;
    let mut output = String::new();
    for character in value.chars() {
        let character_width = UnicodeWidthChar::width(character).unwrap_or(0);
        if used.saturating_add(character_width) > target {
            break;
        }
        output.push(character);
        used += character_width;
    }
    output.push('…');
    output
}

fn scan_wide(state: &AppState) -> Vec<Line<'static>> {
    let Some(progress) = state.progress.as_ref() else {
        return vec![Line::from("Waiting for the first ScanProgress event…")];
    };
    vec![
        Line::from(format!(
            "Profile {:<14} Elapsed {:<12} Rate {} entries/s",
            progress.profile,
            format_duration(progress.elapsed_millis),
            progress.entries_per_second
        )),
        Line::from(format!(
            "Entries {:<14} Directories {:<10} Retained evidence {}",
            progress.entries, progress.directories, progress.retained_nodes
        )),
        Line::from(format!(
            "Allocated observed {:<12} Classification deferred to plan phase",
            format_bytes(progress.allocated_bytes_observed)
        )),
        Line::from(format!(
            "Complete roots {:<9} Partial roots {:<9} Structural budget {}",
            progress.complete_roots, progress.partial_roots, progress.structural_budget
        )),
        Line::from(format!("Current root {}", progress.current_root)),
        Line::from(""),
        Line::styled(
            "Completion percentage is intentionally unavailable: the engine has not proved a denominator.",
            Style::default().fg(Color::DarkGray),
        ),
    ]
}

fn scan_medium(state: &AppState) -> Vec<Line<'static>> {
    let Some(progress) = state.progress.as_ref() else {
        return vec![Line::from("Waiting for ScanProgress…")];
    };
    vec![
        Line::from(format!(
            "{}  {}  {}/s",
            progress.profile,
            format_duration(progress.elapsed_millis),
            progress.entries_per_second
        )),
        Line::from(format!(
            "{} entries  {} dirs  {} retained",
            progress.entries, progress.directories, progress.retained_nodes
        )),
        Line::from(format!(
            "Observed {}  Evidence only",
            format_bytes(progress.allocated_bytes_observed)
        )),
        Line::from(format!(
            "Roots {} complete / {} partial  Budget {}",
            progress.complete_roots, progress.partial_roots, progress.structural_budget
        )),
        Line::from(format!("Root {}", progress.current_root)),
        Line::styled(
            "No completion percentage",
            Style::default().fg(Color::DarkGray),
        ),
    ]
}

fn scan_compact(state: &AppState) -> Vec<Line<'static>> {
    let Some(progress) = state.progress.as_ref() else {
        return vec![Line::from("Waiting for scan facts…")];
    };
    vec![
        Line::from(format!(
            "{} • {}",
            progress.profile,
            format_duration(progress.elapsed_millis)
        )),
        Line::from(format!(
            "{} entries • {}/s",
            progress.entries, progress.entries_per_second
        )),
        Line::from(format!(
            "{} dirs • {} retained",
            progress.directories, progress.retained_nodes
        )),
        Line::from(format!(
            "{} observed • evidence only",
            format_bytes(progress.allocated_bytes_observed)
        )),
        Line::from(format!(
            "roots {}/{} complete/partial",
            progress.complete_roots, progress.partial_roots
        )),
        Line::from(progress.current_root.clone()),
    ]
}

fn plan_wide(plan: &diskplan_proto::diskplan::v1::ProvisionalPlanReady) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(format!(
            "Plan {}  Actions {}  Immediate {}  Shared unlock {}",
            plan.plan_id,
            plan.action_count,
            format_bytes(plan.immediate_reclaim_bytes),
            format_bytes(plan.conditional_reclaim_bytes)
        )),
        Line::from(""),
        Line::styled(
            format!(
                "{:<22} {:>8} {:>14} {:>14}  {}",
                "Plan group", "Actions", "Immediate", "Shared unlock", "Status"
            ),
            Style::default().add_modifier(Modifier::BOLD),
        ),
    ];
    lines.extend(plan.groups.iter().map(|group| {
        Line::from(format!(
            "{:<22} {:>8} {:>14} {:>14}  {}",
            group.title,
            group.action_count,
            format_bytes(group.immediate_reclaim_bytes),
            format_bytes(group.conditional_reclaim_bytes),
            group.status
        ))
    }));
    lines
}

fn plan_medium(plan: &diskplan_proto::diskplan::v1::ProvisionalPlanReady) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(format!("{} • {} actions", plan.plan_id, plan.action_count)),
        Line::from(format!(
            "Immediate {} • Shared unlock {}",
            format_bytes(plan.immediate_reclaim_bytes),
            format_bytes(plan.conditional_reclaim_bytes)
        )),
        Line::from(""),
    ];
    for group in &plan.groups {
        lines.push(Line::styled(
            format!("{} • {} actions", group.title, group.action_count),
            Style::default().add_modifier(Modifier::BOLD),
        ));
        lines.push(Line::from(format!(
            "  {} immediate • {} shared • {}",
            format_bytes(group.immediate_reclaim_bytes),
            format_bytes(group.conditional_reclaim_bytes),
            group.status
        )));
    }
    lines
}

fn plan_compact(plan: &diskplan_proto::diskplan::v1::ProvisionalPlanReady) -> Vec<Line<'static>> {
    let mut lines = vec![
        Line::from(format!("{} actions", plan.action_count)),
        Line::from(format!(
            "{} immediate",
            format_bytes(plan.immediate_reclaim_bytes)
        )),
        Line::from(format!(
            "{} shared unlock",
            format_bytes(plan.conditional_reclaim_bytes)
        )),
    ];
    lines.extend(plan.groups.iter().map(|group| {
        Line::from(format!(
            "{} • {} • {}",
            group.title, group.action_count, group.status
        ))
    }));
    lines
}

fn render_help(frame: &mut Frame<'_>, state: &AppState, area: Rect) {
    if area.width < 18 || area.height < 7 {
        return;
    }
    let popup = centered_rect(70, 60, area);
    let text = match (state.screen, state.scan_state) {
        (
            Screen::Scan,
            ScanState::Finished | ScanState::FinalizedPartial | ScanState::Cancelled,
        ) if state.scan_finalized => vec![
            Line::from("q      quit after finalized evidence"),
            Line::from("? /    close this contextual help"),
        ],
        (
            Screen::Scan,
            ScanState::Finished | ScanState::FinalizedPartial | ScanState::Cancelled,
        ) => vec![
            Line::from("       waiting for finalized evidence"),
            Line::from("? /    close this contextual help"),
        ],
        (Screen::Scan, _) => vec![
            Line::from("q      cancel; press q again after finalized evidence"),
            Line::from("Space  pause/resume after engine acknowledgement"),
            Line::from("p      pause and checkpoint provisional evidence"),
            Line::from("? /    close this contextual help"),
        ],
        (Screen::ProvisionalPlan, _) => vec![
            Line::from("q      cancel; press q again after finalized evidence"),
            Line::from("r      resume and invalidate this projection"),
            Line::from("j/k ↑↓ move     Enter/l expand     h collapse/back"),
            Line::from("Space  stage/unstage engine action"),
            Line::from("e/t/g  Evidence / Targets / Dependencies"),
            Line::from("v      Coverage       p Plan summary"),
            Line::from("c      columns        s group-local sort"),
            Line::from("/      filter         D dry-run     A apply review"),
            Line::from("?      close this contextual help"),
        ],
    };
    frame.render_widget(Clear, popup);
    frame.render_widget(
        Paragraph::new(text)
            .alignment(Alignment::Left)
            .block(Block::default().borders(Borders::ALL).title(" Hotkeys "))
            .wrap(Wrap { trim: true }),
        popup,
    );
}

fn centered_rect(percent_x: u16, percent_y: u16, area: Rect) -> Rect {
    let vertical = Layout::default()
        .direction(Direction::Vertical)
        .constraints([
            Constraint::Percentage((100 - percent_y) / 2),
            Constraint::Percentage(percent_y),
            Constraint::Percentage((100 - percent_y) / 2),
        ])
        .split(area);
    Layout::default()
        .direction(Direction::Horizontal)
        .constraints([
            Constraint::Percentage((100 - percent_x) / 2),
            Constraint::Percentage(percent_x),
            Constraint::Percentage((100 - percent_x) / 2),
        ])
        .split(vertical[1])[1]
}

fn format_duration(milliseconds: u64) -> String {
    let seconds = milliseconds / 1_000;
    format!("{}:{:02}", seconds / 60, seconds % 60)
}

fn format_bytes(bytes: u64) -> String {
    const KIB: u64 = 1_024;
    const MIB: u64 = KIB * 1_024;
    const GIB: u64 = MIB * 1_024;
    if bytes >= GIB {
        format!("{:.1} GiB", bytes as f64 / GIB as f64)
    } else if bytes >= MIB {
        format!("{:.1} MiB", bytes as f64 / MIB as f64)
    } else if bytes >= KIB {
        format!("{:.1} KiB", bytes as f64 / KIB as f64)
    } else {
        format!("{bytes} B")
    }
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;

    use diskplan_proto::diskplan::v1::{
        ProvisionalPlanGroupSummary, ProvisionalPlanReady, ScanProgress, ScanState,
    };
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;
    use crate::tui::plan::{
        ActionId, ActionKindId, ActionKindProjection, ActionProjection, DisplayPath,
        EnginePlanSnapshot, ExecutionPreviewProjection, ExecutionUnitId, ExecutionUnitProjection,
        ExecutionWarningId, ExecutionWarningProjection, PlanDisposition, PlanId, PlanProjection,
        PlanRuntimeEvent, PlanView, TargetId, TargetProjection, WaiverId,
    };

    #[test]
    fn fixed_size_scan_snapshots() {
        let state = sample_scan_state();
        insta::assert_snapshot!("scan_120x34", snapshot(&state, 120, 34));
        insta::assert_snapshot!("scan_80x24", snapshot(&state, 80, 24));
        insta::assert_snapshot!("scan_40x12", snapshot(&state, 40, 12));
    }

    #[test]
    fn fixed_size_plan_snapshots() {
        let state = sample_plan_state();
        insta::assert_snapshot!("plan_120x34", snapshot(&state, 120, 34));
        insta::assert_snapshot!("plan_80x24", snapshot(&state, 80, 24));
        insta::assert_snapshot!("plan_40x12", snapshot(&state, 40, 12));
    }

    #[test]
    fn fixed_size_runtime_plan_snapshots() {
        let state = sample_runtime_plan_state();
        insta::assert_snapshot!("runtime_plan_120x34", snapshot(&state, 120, 34));
        insta::assert_snapshot!("runtime_plan_80x24", snapshot(&state, 80, 24));
        insta::assert_snapshot!("runtime_plan_40x12", snapshot(&state, 40, 12));
    }

    #[test]
    fn warning_views_prioritize_engine_warnings_at_80_columns() {
        let selected = sample_warning_review_state();
        let selected_snapshot = snapshot(&selected, 80, 24);
        let waiver = selected_snapshot.find("WAIVER waiver-force").unwrap();
        let force = selected_snapshot.find("FORCE required").unwrap();
        let path_race = selected_snapshot.find("PATH RACE residual").unwrap();
        let overlay = selected_snapshot.find("Overlay revision").unwrap();
        let label = selected_snapshot.find("Remove protected cache").unwrap();
        assert!(waiver < overlay && force < overlay && path_race < overlay);
        assert!(overlay < label);
        assert!(!selected_snapshot.contains("[detail truncated at encoded byte limit]"));
        insta::assert_snapshot!("selected_warnings_80x24", selected_snapshot);

        let execution = sample_execution_preview_state();
        let execution_snapshot = snapshot(&execution, 80, 24);
        let final_warning = execution_snapshot
            .find("FINAL WARNING final-force")
            .unwrap();
        let dag_header = execution_snapshot
            .find("Engine-issued execution DAG")
            .unwrap();
        let unit = execution_snapshot.find("unit-remove-cache").unwrap();
        assert!(final_warning < dag_header && dag_header < unit);
        assert!(!execution_snapshot.contains("[detail truncated at encoded byte limit]"));
        insta::assert_snapshot!("execution_preview_warnings_80x24", execution_snapshot);
    }

    #[test]
    fn overlong_warning_fields_preserve_identity_and_following_dag_at_80_columns() {
        let selected_snapshot = snapshot(&sample_overlong_warning_review_state(), 80, 24);
        let waiver = selected_snapshot
            .find("WAIVER waiver-overlong for action action-cache-1")
            .unwrap();
        let force = selected_snapshot
            .find("FORCE required for action action-cache-1")
            .unwrap();
        let path_race = selected_snapshot
            .find("PATH RACE residual for action action-cache-1")
            .unwrap();
        let overlay = selected_snapshot.find("Overlay revision").unwrap();
        assert!(waiver < force && force < path_race && path_race < overlay);
        assert!(!selected_snapshot.contains("[detail truncated at encoded byte limit]"));

        let execution_snapshot = snapshot(&sample_overlong_execution_preview_state(), 80, 24);
        let final_warning = execution_snapshot
            .find("FINAL WARNING final-overlong")
            .unwrap();
        let dag_header = execution_snapshot
            .find("Engine-issued execution DAG")
            .unwrap();
        let unit = execution_snapshot.find("unit-overlong").unwrap();
        assert!(final_warning < dag_header && dag_header < unit);
        assert!(!execution_snapshot.contains("[detail truncated at encoded byte limit]"));

        let bounded = bounded_detail_field(&format!("{}TAIL", "警告".repeat(8_192)));
        assert!(bounded.len() <= DETAIL_FIELD_BYTE_CAP);
        assert!(bounded.is_char_boundary(bounded.len()));
        assert!(bounded.ends_with(DETAIL_FIELD_TRUNCATION_MARKER));
    }

    #[test]
    fn every_resize_from_one_by_one_through_160_by_50_is_panic_free() {
        let states = [
            sample_scan_state(),
            sample_plan_state(),
            sample_runtime_plan_state(),
        ];
        for state in &states {
            for width in 1..=160 {
                for height in 1..=50 {
                    let backend = TestBackend::new(width, height);
                    let mut terminal = Terminal::new(backend).unwrap();
                    let mut state = state.clone();
                    state.resize_plan_layout(width, height);
                    terminal.draw(|frame| render(frame, &state)).unwrap();
                }
            }
        }
    }

    #[test]
    fn display_truncation_uses_terminal_cell_width() {
        let truncated = truncate_display("缓存😀abcdef", 6);
        assert!(UnicodeWidthStr::width(truncated.as_str()) <= 6);
        assert!(truncated.ends_with('…'));

        let state = sample_runtime_plan_state();
        let lines = runtime_plan_body(&state.plan, 40);
        assert!(lines.iter().all(|line| {
            line.spans
                .iter()
                .map(|span| UnicodeWidthStr::width(span.content.as_ref()))
                .sum::<usize>()
                <= 38
        }));
    }

    #[test]
    fn detail_builder_caps_rows_and_encoded_bytes() {
        let mut runtime = sample_runtime_plan_state().plan;
        runtime.resize_layout(80, 24);

        let mut row_limited = DetailBuilder::new(&runtime, 80);
        for index in 0..10_000 {
            if !row_limited.push_with(Style::default(), || format!("detail {index}")) {
                break;
            }
        }
        assert_eq!(row_limited.finish().len(), runtime.detail_viewport_height());

        let mut byte_limited = DetailBuilder::new(&runtime, 80);
        assert!(
            !byte_limited.push_with(Style::default(), || { "x".repeat(DETAIL_ENCODED_BYTE_CAP) })
        );
        let lines = byte_limited.finish();
        assert_eq!(lines.len(), 1);
        assert_eq!(
            lines[0].spans[0].content.as_ref(),
            "[detail truncated at encoded byte limit]"
        );

        let formatted = Cell::new(0usize);
        let mut deep_page = DetailBuilder::with_viewport(50_000, 3, 80);
        for index in 0..50_010 {
            if !deep_page.push_with(Style::default(), || {
                formatted.set(formatted.get() + 1);
                format!("deep detail {index}")
            }) {
                break;
            }
        }
        let lines = deep_page.finish();
        assert_eq!(formatted.get(), 3, "skipped rows must not be formatted");
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0].spans[0].content.as_ref(), "deep detail 50000");
        assert_eq!(lines[2].spans[0].content.as_ref(), "deep detail 50002");
    }

    fn sample_scan_state() -> AppState {
        AppState {
            scan_state: ScanState::Running,
            progress: Some(ScanProgress {
                profile: "standard".into(),
                elapsed_millis: 83_000,
                entries: 825_431,
                directories: 37_602,
                candidates: 0,
                allocated_bytes_observed: 24_696_061_952,
                reclaim_estimate_bytes: 0,
                complete_roots: 4,
                partial_roots: 1,
                entries_per_second: 9_945,
                current_root: "/Users/example/Library/Caches/com.example".into(),
                structural_budget: 2_000_000,
                retained_nodes: 148,
            }),
            banner: Some("scan is running".into()),
            ..AppState::default()
        }
    }

    fn sample_plan_state() -> AppState {
        AppState {
            screen: Screen::ProvisionalPlan,
            scan_state: ScanState::ProvisionalPlanReady,
            provisional_plan: Some(ProvisionalPlanReady {
                plan_id: "phase0-provisional-0001".into(),
                action_count: 11,
                immediate_reclaim_bytes: 1_342_177_280,
                conditional_reclaim_bytes: 268_435_456,
                groups: vec![
                    ProvisionalPlanGroupSummary {
                        group_id: "ready".into(),
                        title: "Ready".into(),
                        action_count: 8,
                        immediate_reclaim_bytes: 1_073_741_824,
                        conditional_reclaim_bytes: 0,
                        status: "ready".into(),
                    },
                    ProvisionalPlanGroupSummary {
                        group_id: "conditional".into(),
                        title: "Conditional".into(),
                        action_count: 3,
                        immediate_reclaim_bytes: 268_435_456,
                        conditional_reclaim_bytes: 268_435_456,
                        status: "needs complete release set".into(),
                    },
                ],
            }),
            banner: Some("provisional plan ready".into()),
            ..AppState::default()
        }
    }

    fn sample_runtime_plan_state() -> AppState {
        sample_runtime_state(Stageability::Stageable, ForceRequirement::NotRequired)
    }

    fn sample_warning_review_state() -> AppState {
        let waiver = WaiverId::new("waiver-force");
        let mut state = sample_runtime_state(
            Stageability::RequiresWaivers(vec![waiver.clone()]),
            ForceRequirement::Required {
                reason: "immutable flag requires engine-approved force".into(),
            },
        );
        state
            .plan
            .apply_event(PlanRuntimeEvent::WaiverAcknowledged {
                plan_id: PlanId::new("plan-runtime-0001"),
                action_id: ActionId::new("action-cache-1"),
                waiver_id: waiver,
                reason: "user accepted the engine-issued recovery warning".into(),
            })
            .unwrap();
        assert!(matches!(
            state.plan.toggle_selected_stage(),
            super::super::plan::OverlayStageResult::Staged { .. }
        ));
        assert!(state.plan.set_view(PlanView::SelectedActions));
        state
    }

    fn sample_overlong_warning_review_state() -> AppState {
        let waiver = WaiverId::new("waiver-overlong");
        let mut state = sample_runtime_state(
            Stageability::RequiresWaivers(vec![waiver.clone()]),
            ForceRequirement::Required {
                reason: format!("force warning {}", "F".repeat(20_000)),
            },
        );
        state
            .plan
            .apply_event(PlanRuntimeEvent::WaiverAcknowledged {
                plan_id: PlanId::new("plan-runtime-0001"),
                action_id: ActionId::new("action-cache-1"),
                waiver_id: waiver,
                reason: format!("waiver warning {}", "W".repeat(20_000)),
            })
            .unwrap();
        assert!(matches!(
            state.plan.toggle_selected_stage(),
            super::super::plan::OverlayStageResult::Staged { .. }
        ));
        assert!(state.plan.set_view(PlanView::SelectedActions));
        state
    }

    fn sample_execution_preview_state() -> AppState {
        let mut state = sample_runtime_plan_state();
        let overlay = state.plan.overlay().unwrap();
        let preview = ExecutionPreviewProjection {
            plan_id: overlay.plan_id().clone(),
            overlay_digest: overlay.digest().into(),
            ordered_units: vec![ExecutionUnitProjection {
                id: ExecutionUnitId::new("unit-remove-cache"),
                covered_action_ids: vec![ActionId::new("action-cache-1")],
                label: "Remove cache as one engine execution unit".into(),
                prerequisite_unit_ids: Vec::new(),
                prerequisite_status: "ready".into(),
            }],
            final_warnings: vec![ExecutionWarningProjection {
                id: ExecutionWarningId::new("final-force"),
                message: "engine finalized force and residual path-race warnings".into(),
            }],
        };
        state
            .plan
            .apply_event(PlanRuntimeEvent::ExecutionPreviewReady(preview))
            .unwrap();
        state
    }

    fn sample_overlong_execution_preview_state() -> AppState {
        let mut state = sample_runtime_plan_state();
        let overlay = state.plan.overlay().unwrap();
        let preview = ExecutionPreviewProjection {
            plan_id: overlay.plan_id().clone(),
            overlay_digest: overlay.digest().into(),
            ordered_units: vec![ExecutionUnitProjection {
                id: ExecutionUnitId::new("unit-overlong"),
                covered_action_ids: vec![ActionId::new("action-cache-1")],
                label: format!("execution unit {}", "U".repeat(20_000)),
                prerequisite_unit_ids: Vec::new(),
                prerequisite_status: "ready".into(),
            }],
            final_warnings: vec![ExecutionWarningProjection {
                id: ExecutionWarningId::new("final-overlong"),
                message: format!("final warning {}", "E".repeat(20_000)),
            }],
        };
        state
            .plan
            .apply_event(PlanRuntimeEvent::ExecutionPreviewReady(preview))
            .unwrap();
        state
    }

    fn sample_runtime_state(stageability: Stageability, force: ForceRequirement) -> AppState {
        let mut state = AppState {
            scan_state: ScanState::Paused,
            banner: Some("immutable engine plan ready".into()),
            ..AppState::default()
        };
        state
            .plan
            .apply_event(PlanRuntimeEvent::Load(EnginePlanSnapshot {
                projection: PlanProjection {
                    id: PlanId::new("plan-runtime-0001"),
                    actions: vec![ActionProjection {
                        id: ActionId::new("action-cache-1"),
                        disposition: PlanDisposition::Ready,
                        kind: ActionKindProjection {
                            id: ActionKindId::new("generic-remove"),
                            label: "Generic remove".into(),
                            order: 1,
                        },
                        label: if matches!(&stageability, Stageability::RequiresWaivers(_)) {
                            "Remove protected cache".into()
                        } else {
                            "Remove rebuildable cache".into()
                        },
                        order: 1,
                        stageability,
                        immediate_reclaim: ByteValue::Known(1_073_741_824),
                        shared_unlock: ByteValue::Unknown,
                        activity: Activity::Inactive,
                        recoverability: Recoverability::Rebuildable,
                        blockers: Vec::new(),
                        prerequisites: Vec::new(),
                        release_set_ids: Vec::new(),
                        force,
                        path_race: PathRace::Residual,
                        targets: vec![TargetProjection {
                            id: TargetId::new("target-cache-1"),
                            display_path: DisplayPath::new(
                                "/Users/example/Library/Caches/com.example",
                            ),
                            kind: TargetKind::Directory,
                            children: Vec::new(),
                        }],
                    }],
                    release_sets: Vec::new(),
                },
                evidence_reference: "evidence-runtime-0001".into(),
                provisional: false,
            }))
            .unwrap();
        state.screen = Screen::ProvisionalPlan;
        state.plan.move_navigation(2);
        if matches!(
            state.plan.model().action(&ActionId::new("action-cache-1")),
            Some(action) if matches!(&action.stageability, Stageability::Stageable)
        ) {
            assert!(matches!(
                state.plan.toggle_selected_stage(),
                super::super::plan::OverlayStageResult::Staged { .. }
            ));
        }
        state
    }

    fn snapshot(state: &AppState, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        let mut state = state.clone();
        state.resize_plan_layout(width, height);
        terminal.draw(|frame| render(frame, &state)).unwrap();
        let buffer = terminal.backend().buffer();
        let mut text = String::new();
        for y in 0..height {
            let mut line = String::new();
            for x in 0..width {
                line.push_str(buffer[(x, y)].symbol());
            }
            text.push_str(line.trim_end());
            text.push('\n');
        }
        text
    }
}
