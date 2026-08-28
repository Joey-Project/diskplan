use ratatui::Frame;
use ratatui::layout::{Alignment, Constraint, Direction, Layout, Rect};
use ratatui::style::{Color, Modifier, Style};
use ratatui::text::{Line, Span};
use ratatui::widgets::{Block, Borders, Clear, Paragraph, Wrap};

use super::model::{AppState, Screen};

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
    render_header(frame, state, sections[0], "Provisional plan");

    let body = match state.provisional_plan.as_ref() {
        Some(plan) if area.width >= 100 => plan_wide(plan),
        Some(plan) if area.width >= 60 => plan_medium(plan),
        Some(plan) => plan_compact(plan),
        None => vec![Line::from("Waiting for the engine projection…")],
    };
    frame.render_widget(
        Paragraph::new(body)
            .block(
                Block::default()
                    .borders(Borders::ALL)
                    .title(" Plan-first summary "),
            )
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
    let keys = match state.screen {
        Screen::Scan => "q cancel  Space pause/resume  p provisional plan  ? or / help",
        Screen::ProvisionalPlan => "q cancel  r resume + invalidate  ? help",
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
            "Entries {:<14} Directories {:<10} Candidates {}",
            progress.entries, progress.directories, progress.candidates
        )),
        Line::from(format!(
            "Allocated observed {:<12} Reclaim estimate {}",
            format_bytes(progress.allocated_bytes_observed),
            format_bytes(progress.reclaim_estimate_bytes)
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
            "{} entries  {} dirs  {} candidates",
            progress.entries, progress.directories, progress.candidates
        )),
        Line::from(format!(
            "Observed {}  Estimate {}",
            format_bytes(progress.allocated_bytes_observed),
            format_bytes(progress.reclaim_estimate_bytes)
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
            "{} dirs • {} candidates",
            progress.directories, progress.candidates
        )),
        Line::from(format!(
            "{} observed • {} estimate",
            format_bytes(progress.allocated_bytes_observed),
            format_bytes(progress.reclaim_estimate_bytes)
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
    let text = match state.screen {
        Screen::Scan => vec![
            Line::from("q      cancel once and wait for engine exit"),
            Line::from("Space  pause/resume after engine acknowledgement"),
            Line::from("p      pause and build a provisional plan"),
            Line::from("? /    close this contextual help"),
        ],
        Screen::ProvisionalPlan => vec![
            Line::from("q      cancel once and wait for engine exit"),
            Line::from("r      resume and invalidate this projection"),
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
    use diskplan_proto::diskplan::v1::{
        ProvisionalPlanGroupSummary, ProvisionalPlanReady, ScanProgress, ScanState,
    };
    use ratatui::Terminal;
    use ratatui::backend::TestBackend;

    use super::*;

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
    fn every_resize_from_one_by_one_through_160_by_50_is_panic_free() {
        let states = [sample_scan_state(), sample_plan_state()];
        for state in &states {
            for width in 1..=160 {
                for height in 1..=50 {
                    let backend = TestBackend::new(width, height);
                    let mut terminal = Terminal::new(backend).unwrap();
                    terminal.draw(|frame| render(frame, state)).unwrap();
                }
            }
        }
    }

    fn sample_scan_state() -> AppState {
        AppState {
            scan_state: ScanState::Running,
            progress: Some(ScanProgress {
                profile: "standard".into(),
                elapsed_millis: 83_000,
                entries: 825_431,
                directories: 37_602,
                candidates: 148,
                allocated_bytes_observed: 24_696_061_952,
                reclaim_estimate_bytes: 4_831_838_208,
                complete_roots: 4,
                partial_roots: 1,
                entries_per_second: 9_945,
                current_root: "/Users/example/Library/Caches/com.example".into(),
                structural_budget: 2_000_000,
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

    fn snapshot(state: &AppState, width: u16, height: u16) -> String {
        let backend = TestBackend::new(width, height);
        let mut terminal = Terminal::new(backend).unwrap();
        terminal.draw(|frame| render(frame, state)).unwrap();
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
