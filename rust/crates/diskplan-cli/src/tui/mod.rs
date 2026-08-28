mod app;
mod driver;
mod event;
mod model;
mod reducer;
mod render;

use std::io::{self, stdout};
use std::path::Path;

use crossterm::cursor::{Hide, Show};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use thiserror::Error;

use self::app::run_application;
use self::driver::EngineDriver;
use self::event::TerminalEventSource;

#[derive(Debug, Error)]
pub enum TuiError {
    #[error("terminal I/O error: {0}")]
    Io(#[from] io::Error),
}

pub async fn run(engine: &Path) -> Result<(), TuiError> {
    let (mut driver, engine_events) = EngineDriver::spawn(engine)?;
    let mut guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    let mut source = TerminalEventSource::new(engine_events);
    let result = run_application(&mut terminal, &mut source, &mut driver).await;
    guard.restore()?;
    result?;
    Ok(())
}

struct TerminalGuard {
    raw: bool,
    alternate: bool,
    hidden: bool,
}

impl TerminalGuard {
    fn enter() -> io::Result<Self> {
        let mut guard = Self {
            raw: false,
            alternate: false,
            hidden: false,
        };
        enable_raw_mode()?;
        guard.raw = true;
        execute!(stdout(), EnterAlternateScreen)?;
        guard.alternate = true;
        execute!(stdout(), Hide)?;
        guard.hidden = true;
        Ok(guard)
    }

    fn restore(&mut self) -> io::Result<()> {
        let mut first_error = None;
        if self.hidden {
            match execute!(stdout(), Show) {
                Ok(()) => self.hidden = false,
                Err(error) => first_error = Some(error),
            }
        }
        if self.alternate {
            match execute!(stdout(), LeaveAlternateScreen) {
                Ok(()) => self.alternate = false,
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if self.raw {
            match disable_raw_mode() {
                Ok(()) => self.raw = false,
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        match first_error {
            Some(error) => Err(error),
            None => Ok(()),
        }
    }
}

impl Drop for TerminalGuard {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub use model::{AppState, ControlCommand, Screen, TerminalState};
pub use reducer::reduce;
pub use render::render;
