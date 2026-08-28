use crossterm::event::KeyEvent;
use diskplan_proto::diskplan::v1::{
    EngineEvent, ProvisionalPlanReady, ScanControlKind, ScanProgress, ScanState,
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Screen {
    Scan,
    ProvisionalPlan,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PendingControl {
    pub request_id: u64,
    pub kind: ScanControlKind,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TerminalState {
    Cancelled(String),
    Finished(String),
    Failed(String),
}

#[derive(Clone, Debug, PartialEq)]
pub struct AppState {
    pub screen: Screen,
    pub scan_state: ScanState,
    pub progress: Option<ScanProgress>,
    pub provisional_plan: Option<ProvisionalPlanReady>,
    pub pending_controls: Vec<PendingControl>,
    pub help_visible: bool,
    pub cancel_requested: bool,
    pub terminal: Option<TerminalState>,
    pub driver_exited: bool,
    pub banner: Option<String>,
    pub last_event_sequence: u64,
    pub(super) next_request_id: u64,
}

impl Default for AppState {
    fn default() -> Self {
        Self {
            screen: Screen::Scan,
            scan_state: ScanState::Idle,
            progress: None,
            provisional_plan: None,
            pending_controls: vec![PendingControl {
                request_id: 1,
                kind: ScanControlKind::StartScan,
            }],
            help_visible: false,
            cancel_requested: false,
            terminal: None,
            driver_exited: false,
            banner: Some("Connecting to the Swift engine…".into()),
            last_event_sequence: 0,
            next_request_id: 2,
        }
    }
}

impl AppState {
    pub fn try_next_control(
        &mut self,
        kind: ScanControlKind,
    ) -> Result<ControlCommand, RequestIdExhausted> {
        let request_id = self.next_request_id;
        self.next_request_id = request_id.checked_add(1).ok_or(RequestIdExhausted)?;
        self.pending_controls
            .push(PendingControl { request_id, kind });
        Ok(ControlCommand { request_id, kind })
    }

    pub fn has_pending(&self, kind: ScanControlKind) -> bool {
        self.pending_controls
            .iter()
            .any(|pending| pending.kind == kind)
    }

    pub fn take_pending(&mut self, request_id: u64) -> Option<PendingControl> {
        let index = self
            .pending_controls
            .iter()
            .position(|pending| pending.request_id == request_id)?;
        Some(self.pending_controls.remove(index))
    }

    pub fn should_exit(&self) -> bool {
        self.terminal.is_some() && self.driver_exited
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RequestIdExhausted;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ControlCommand {
    pub request_id: u64,
    pub kind: ScanControlKind,
}

#[derive(Clone, Debug)]
pub enum UiEvent {
    Key(KeyEvent),
    Resize,
    Engine(EngineDelivery),
    DriverExited(Result<(), String>),
}

#[derive(Clone, Debug, PartialEq)]
pub struct EngineDelivery {
    pub event: EngineEvent,
    pub skipped_progress_events: u64,
}

impl EngineDelivery {
    pub fn exact(event: EngineEvent) -> Self {
        Self {
            event,
            skipped_progress_events: 0,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Effect {
    SendControl(ControlCommand),
    StopDriver,
}
