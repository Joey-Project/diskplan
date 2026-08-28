mod app;
mod driver;
mod event;
mod model;
mod reducer;
mod render;

use std::io::{self, Stdout, Write, stdout};
use std::path::Path;

use crossterm::cursor::{Hide, Show};
use crossterm::execute;
use crossterm::terminal::{
    EnterAlternateScreen, LeaveAlternateScreen, disable_raw_mode, enable_raw_mode,
};
use ratatui::Terminal;
use ratatui::backend::CrosstermBackend;
use thiserror::Error;

use crate::BoundEngine;

use self::app::run_application;
use self::driver::EngineDriver;
use self::event::TerminalEventSource;

#[derive(Debug, Error)]
pub enum TuiError {
    #[error("terminal I/O error: {0}")]
    Io(#[from] io::Error),
}

pub async fn run(engine: &Path) -> Result<(), TuiError> {
    let engine = BoundEngine::open(engine)?;
    run_bound(&engine).await
}

pub async fn run_bound(engine: &BoundEngine) -> Result<(), TuiError> {
    let (mut driver, engine_events) = EngineDriver::spawn(engine)?;
    let mut guard = TerminalGuard::enter()?;
    let mut terminal = Terminal::new(CrosstermBackend::new(stdout()))?;
    let mut source = TerminalEventSource::new(engine_events);
    let result = run_application(&mut terminal, &mut source, &mut driver).await;
    guard.restore()?;
    result?;
    Ok(())
}

trait RawMode {
    fn enable(&mut self) -> io::Result<()>;
    fn disable(&mut self) -> io::Result<()>;
}

struct SystemRawMode;

impl RawMode for SystemRawMode {
    fn enable(&mut self) -> io::Result<()> {
        enable_raw_mode()
    }

    fn disable(&mut self) -> io::Result<()> {
        disable_raw_mode()
    }
}

struct TerminalGuard<W: Write, M: RawMode> {
    writer: W,
    mode: M,
    raw: bool,
    alternate: bool,
    hidden: bool,
}

impl TerminalGuard<Stdout, SystemRawMode> {
    fn enter() -> io::Result<Self> {
        Self::enter_with(stdout(), SystemRawMode)
    }
}

impl<W: Write, M: RawMode> TerminalGuard<W, M> {
    fn enter_with(writer: W, mode: M) -> io::Result<Self> {
        let mut guard = Self {
            writer,
            mode,
            raw: false,
            alternate: false,
            hidden: false,
        };
        guard.mode.enable()?;
        guard.raw = true;
        // execute! may write some command bytes and then fail while writing or
        // flushing. Mark the inverse as required before issuing each command.
        guard.alternate = true;
        execute!(&mut guard.writer, EnterAlternateScreen)?;
        guard.hidden = true;
        execute!(&mut guard.writer, Hide)?;
        Ok(guard)
    }

    fn restore(&mut self) -> io::Result<()> {
        let mut first_error = None;
        if self.hidden {
            match execute!(&mut self.writer, Show) {
                Ok(()) => self.hidden = false,
                Err(error) => first_error = Some(error),
            }
        }
        if self.alternate {
            match execute!(&mut self.writer, LeaveAlternateScreen) {
                Ok(()) => self.alternate = false,
                Err(error) if first_error.is_none() => first_error = Some(error),
                Err(_) => {}
            }
        }
        if self.raw {
            match self.mode.disable() {
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

impl<W: Write, M: RawMode> Drop for TerminalGuard<W, M> {
    fn drop(&mut self) {
        let _ = self.restore();
    }
}

pub use model::{AppState, ControlCommand, Screen, TerminalState};
pub use reducer::reduce;
pub use render::render;

#[cfg(test)]
mod terminal_guard_tests {
    use std::sync::{Arc, Mutex};

    use super::*;

    const ENTER_ALTERNATE: &[u8] = b"\x1b[?1049h";
    const LEAVE_ALTERNATE: &[u8] = b"\x1b[?1049l";
    const SHOW_CURSOR: &[u8] = b"\x1b[?25h";

    #[test]
    fn enter_flush_failure_restores_raw_mode_and_alternate_screen() {
        let (writer, output) = FailingWriter::fail_flush(1);
        let (mode, raw_calls) = FakeRawMode::new();

        let error = TerminalGuard::enter_with(writer, mode)
            .err()
            .expect("enter flush must fail");

        assert_eq!(error.kind(), io::ErrorKind::Other);
        let output = output.lock().unwrap();
        assert!(contains(&output.bytes, ENTER_ALTERNATE));
        assert!(contains(&output.bytes, LEAVE_ALTERNATE));
        assert_eq!(*raw_calls.lock().unwrap(), (1, 1));
    }

    #[test]
    fn partial_hide_write_failure_still_shows_cursor_and_leaves_alternate_screen() {
        let fail_after = ENTER_ALTERNATE.len() + 2;
        let (writer, output) = FailingWriter::fail_after_bytes(fail_after);
        let (mode, raw_calls) = FakeRawMode::new();

        let error = TerminalGuard::enter_with(writer, mode)
            .err()
            .expect("partial hide write must fail");

        assert_eq!(error.kind(), io::ErrorKind::Other);
        let output = output.lock().unwrap();
        assert!(output.failed);
        assert!(contains(&output.bytes, ENTER_ALTERNATE));
        assert!(contains(&output.bytes, SHOW_CURSOR));
        assert!(contains(&output.bytes, LEAVE_ALTERNATE));
        assert_eq!(*raw_calls.lock().unwrap(), (1, 1));
    }

    fn contains(haystack: &[u8], needle: &[u8]) -> bool {
        haystack
            .windows(needle.len())
            .any(|window| window == needle)
    }

    #[derive(Clone, Copy)]
    enum FailureMode {
        Flush(usize),
        AfterBytes(usize),
    }

    struct WriterState {
        bytes: Vec<u8>,
        flushes: usize,
        failed: bool,
    }

    struct FailingWriter {
        state: Arc<Mutex<WriterState>>,
        failure: FailureMode,
    }

    impl FailingWriter {
        fn fail_flush(flush: usize) -> (Self, Arc<Mutex<WriterState>>) {
            Self::new(FailureMode::Flush(flush))
        }

        fn fail_after_bytes(bytes: usize) -> (Self, Arc<Mutex<WriterState>>) {
            Self::new(FailureMode::AfterBytes(bytes))
        }

        fn new(failure: FailureMode) -> (Self, Arc<Mutex<WriterState>>) {
            let state = Arc::new(Mutex::new(WriterState {
                bytes: Vec::new(),
                flushes: 0,
                failed: false,
            }));
            (
                Self {
                    state: Arc::clone(&state),
                    failure,
                },
                state,
            )
        }
    }

    impl Write for FailingWriter {
        fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
            let mut state = self.state.lock().unwrap();
            if let FailureMode::AfterBytes(limit) = self.failure
                && !state.failed
            {
                if state.bytes.len() >= limit {
                    state.failed = true;
                    return Err(io::Error::other("injected write failure"));
                }
                if state.bytes.len() + buffer.len() > limit {
                    let written = limit - state.bytes.len();
                    state.bytes.extend_from_slice(&buffer[..written]);
                    return Ok(written);
                }
            }
            state.bytes.extend_from_slice(buffer);
            Ok(buffer.len())
        }

        fn flush(&mut self) -> io::Result<()> {
            let mut state = self.state.lock().unwrap();
            state.flushes += 1;
            if let FailureMode::Flush(target) = self.failure
                && state.flushes == target
                && !state.failed
            {
                state.failed = true;
                return Err(io::Error::other("injected flush failure"));
            }
            Ok(())
        }
    }

    struct FakeRawMode {
        calls: Arc<Mutex<(usize, usize)>>,
    }

    impl FakeRawMode {
        fn new() -> (Self, Arc<Mutex<(usize, usize)>>) {
            let calls = Arc::new(Mutex::new((0, 0)));
            (
                Self {
                    calls: Arc::clone(&calls),
                },
                calls,
            )
        }
    }

    impl RawMode for FakeRawMode {
        fn enable(&mut self) -> io::Result<()> {
            self.calls.lock().unwrap().0 += 1;
            Ok(())
        }

        fn disable(&mut self) -> io::Result<()> {
            self.calls.lock().unwrap().1 += 1;
            Ok(())
        }
    }
}
