use std::collections::VecDeque;
use std::future::Future;
use std::io;
use std::sync::{Arc, Condvar, Mutex, MutexGuard};

use crossterm::event::{Event, EventStream};
use diskplan_proto::diskplan::v1::{EngineEvent, engine_event};
use futures_util::StreamExt;
use tokio::sync::Notify;

use super::model::{EngineDelivery, UiEvent};
use super::plan::PlanRuntimeEvent;

pub trait EventSource {
    fn next_event(&mut self) -> impl Future<Output = io::Result<UiEvent>>;
}

pub struct TerminalEventSource {
    terminal: EventStream,
    engine: EngineEventStream,
}

impl TerminalEventSource {
    pub fn new(engine: EngineEventStream) -> Self {
        Self {
            terminal: EventStream::new(),
            engine,
        }
    }
}

impl EventSource for TerminalEventSource {
    async fn next_event(&mut self) -> io::Result<UiEvent> {
        loop {
            tokio::select! {
                engine = self.engine.next_event() => return engine,
                terminal = self.terminal.next() => {
                    match terminal {
                        Some(Ok(Event::Key(key))) => return Ok(UiEvent::Key(key)),
                        Some(Ok(Event::Resize(_, _))) => return Ok(UiEvent::Resize),
                        Some(Ok(_)) => continue,
                        Some(Err(error)) => return Err(error),
                        None => {
                            return Err(io::Error::new(
                                io::ErrorKind::UnexpectedEof,
                                "terminal event source closed",
                            ));
                        }
                    }
                }
            }
        }
    }
}

struct EventQueueState {
    // A progress run is one queue entry and every two runs are separated by a
    // semantic event, so the total queue stays bounded by 2 * capacity + 1.
    events: VecDeque<UiEvent>,
    semantic_events: usize,
    semantic_capacity: usize,
    producer_closed: bool,
    receiver_closed: bool,
}

struct SharedEventQueue {
    state: Mutex<EventQueueState>,
    space_available: Condvar,
    event_available: Notify,
}

pub struct EngineEventIngress {
    shared: Arc<SharedEventQueue>,
}

pub struct EngineEventStream {
    shared: Arc<SharedEventQueue>,
}

pub fn engine_event_channel(
    semantic_capacity: usize,
) -> io::Result<(EngineEventIngress, EngineEventStream)> {
    if semantic_capacity == 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "semantic event capacity must be positive",
        ));
    }
    let shared = Arc::new(SharedEventQueue {
        state: Mutex::new(EventQueueState {
            events: VecDeque::new(),
            semantic_events: 0,
            semantic_capacity,
            producer_closed: false,
            receiver_closed: false,
        }),
        space_available: Condvar::new(),
        event_available: Notify::new(),
    });
    Ok((
        EngineEventIngress {
            shared: Arc::clone(&shared),
        },
        EngineEventStream { shared },
    ))
}

impl EngineEventIngress {
    pub fn send_engine_event(&self, event: EngineEvent) -> io::Result<()> {
        self.send(UiEvent::Engine(EngineDelivery::exact(event)))
    }

    pub fn send_driver_exited(&self, result: Result<(), String>) -> io::Result<()> {
        self.send(UiEvent::DriverExited(result))
    }

    pub fn send_plan_event(&self, event: PlanRuntimeEvent) -> io::Result<()> {
        self.send(UiEvent::Plan(event))
    }

    fn send(&self, mut event: UiEvent) -> io::Result<()> {
        let is_progress = is_progress_event(&event);
        let mut state = lock_state(&self.shared)?;
        while !is_progress
            && state.semantic_events >= state.semantic_capacity
            && !state.receiver_closed
        {
            state = self
                .shared
                .space_available
                .wait(state)
                .map_err(|_| poisoned_queue())?;
        }
        if state.receiver_closed {
            return Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "engine event receiver closed",
            ));
        }

        if is_progress
            && let Some(UiEvent::Engine(previous)) = state.events.back_mut()
            && matches!(
                previous.event.body,
                Some(engine_event::Body::ScanProgress(_))
            )
        {
            let UiEvent::Engine(next) = &mut event else {
                unreachable!("progress classification requires an engine delivery");
            };
            let expected = previous
                .event
                .event_sequence
                .checked_add(1)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "event sequence overflow")
                })?;
            if next.event.event_sequence != expected {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "non-contiguous progress events cannot be coalesced",
                ));
            }
            next.skipped_progress_events = previous
                .skipped_progress_events
                .checked_add(1)
                .ok_or_else(|| {
                    io::Error::new(io::ErrorKind::InvalidData, "coalesced progress overflow")
                })?;
            *previous = next.clone();
            drop(state);
            self.shared.event_available.notify_one();
            return Ok(());
        }

        if !is_progress {
            state.semantic_events += 1;
        }
        state.events.push_back(event);
        drop(state);
        self.shared.event_available.notify_one();
        Ok(())
    }
}

impl Drop for EngineEventIngress {
    fn drop(&mut self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.producer_closed = true;
        drop(state);
        self.shared.event_available.notify_waiters();
    }
}

impl EngineEventStream {
    pub async fn next_event(&mut self) -> io::Result<UiEvent> {
        loop {
            let notified = self.shared.event_available.notified();
            {
                let mut state = lock_state(&self.shared)?;
                if let Some(event) = state.events.pop_front() {
                    if !is_progress_event(&event) {
                        state.semantic_events -= 1;
                        self.shared.space_available.notify_one();
                    }
                    return Ok(event);
                }
                if state.producer_closed {
                    return Err(io::Error::new(
                        io::ErrorKind::BrokenPipe,
                        "engine event source closed",
                    ));
                }
            }
            notified.await;
        }
    }
}

impl Drop for EngineEventStream {
    fn drop(&mut self) {
        let mut state = self
            .shared
            .state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.receiver_closed = true;
        drop(state);
        self.shared.space_available.notify_all();
    }
}

fn lock_state(shared: &SharedEventQueue) -> io::Result<MutexGuard<'_, EventQueueState>> {
    shared.state.lock().map_err(|_| poisoned_queue())
}

fn poisoned_queue() -> io::Error {
    io::Error::other("engine event queue poisoned")
}

fn is_progress_event(event: &UiEvent) -> bool {
    matches!(
        event,
        UiEvent::Engine(EngineDelivery {
            event: EngineEvent {
                body: Some(engine_event::Body::ScanProgress(_)),
                ..
            },
            ..
        })
    )
}

#[cfg(test)]
pub struct ScriptedEventSource {
    events: VecDeque<UiEvent>,
}

#[cfg(test)]
impl ScriptedEventSource {
    pub fn new(events: impl IntoIterator<Item = UiEvent>) -> Self {
        Self {
            events: events.into_iter().collect(),
        }
    }
}

#[cfg(test)]
impl EventSource for ScriptedEventSource {
    async fn next_event(&mut self) -> io::Result<UiEvent> {
        self.events.pop_front().ok_or_else(|| {
            io::Error::new(io::ErrorKind::UnexpectedEof, "scripted events exhausted")
        })
    }
}

#[cfg(test)]
mod tests {
    use std::sync::mpsc;
    use std::thread;
    use std::time::Duration;

    use diskplan_proto::diskplan::v1::{ControlAccepted, ScanFinished, ScanProgress, ScanState};

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn progress_flood_coalesces_latest_without_dropping_semantics() {
        let (ingress, mut stream) = engine_event_channel(4).unwrap();
        for sequence in 1..=100 {
            ingress.send_engine_event(progress(sequence)).unwrap();
        }
        ingress.send_engine_event(accepted(101)).unwrap();
        for sequence in 102..=200 {
            ingress.send_engine_event(progress(sequence)).unwrap();
        }
        ingress.send_engine_event(finished(201)).unwrap();

        assert_delivery(stream.next_event().await.unwrap(), 100, 99, "progress");
        assert_delivery(stream.next_event().await.unwrap(), 101, 0, "accepted");
        assert_delivery(stream.next_event().await.unwrap(), 200, 98, "progress");
        assert_delivery(stream.next_event().await.unwrap(), 201, 0, "finished");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn semantic_events_apply_bounded_backpressure_without_loss() {
        let (ingress, mut stream) = engine_event_channel(1).unwrap();
        ingress.send_engine_event(accepted(1)).unwrap();
        let (started_tx, started_rx) = mpsc::channel();
        let (done_tx, done_rx) = mpsc::channel();
        let producer = thread::spawn(move || {
            started_tx.send(()).unwrap();
            ingress.send_engine_event(finished(2)).unwrap();
            done_tx.send(()).unwrap();
        });

        started_rx.recv().unwrap();
        assert!(done_rx.recv_timeout(Duration::from_millis(25)).is_err());
        assert_delivery(stream.next_event().await.unwrap(), 1, 0, "accepted");
        done_rx.recv_timeout(Duration::from_secs(1)).unwrap();
        assert_delivery(stream.next_event().await.unwrap(), 2, 0, "finished");
        producer.join().unwrap();
    }

    fn progress(sequence: u64) -> EngineEvent {
        EngineEvent {
            event_sequence: sequence,
            body: Some(engine_event::Body::ScanProgress(ScanProgress {
                entries: sequence,
                ..Default::default()
            })),
            ..Default::default()
        }
    }

    fn accepted(sequence: u64) -> EngineEvent {
        EngineEvent {
            event_sequence: sequence,
            request_id: 1,
            body: Some(engine_event::Body::ControlAccepted(ControlAccepted {
                control: 1,
                resulting_state: ScanState::Running as i32,
            })),
            ..Default::default()
        }
    }

    fn finished(sequence: u64) -> EngineEvent {
        EngineEvent {
            event_sequence: sequence,
            body: Some(engine_event::Body::ScanFinished(ScanFinished {
                summary: "done".into(),
            })),
            ..Default::default()
        }
    }

    fn assert_delivery(event: UiEvent, sequence: u64, skipped_progress_events: u64, body: &str) {
        let UiEvent::Engine(delivery) = event else {
            panic!("expected engine delivery");
        };
        assert_eq!(delivery.event.event_sequence, sequence);
        assert_eq!(delivery.skipped_progress_events, skipped_progress_events);
        match body {
            "progress" => assert!(matches!(
                delivery.event.body,
                Some(engine_event::Body::ScanProgress(_))
            )),
            "accepted" => assert!(matches!(
                delivery.event.body,
                Some(engine_event::Body::ControlAccepted(_))
            )),
            "finished" => assert!(matches!(
                delivery.event.body,
                Some(engine_event::Body::ScanFinished(_))
            )),
            _ => panic!("unknown body assertion"),
        }
    }
}
