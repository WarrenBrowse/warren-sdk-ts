//! Generic connect/shutdown lifecycle for a single proxy session slot.
//!
//! Isolated from the napi/network code so the fail-open race between
//! `connect()` and `shutdown()` can be unit-tested without a live tunnel: the
//! slot only knows how to move between states, not how to dial an exit.

use tokio::sync::Mutex;

/// The lifecycle of one proxy session slot.
enum SlotState<S> {
    /// No connect attempt has ever started (or the previous one failed).
    Idle,
    /// A connect attempt is in flight; no session exists yet.
    Connecting,
    /// A session is live.
    Connected(S),
    /// `shutdown()` was called. Terminal: never leaves this state.
    ShutDown,
}

/// Why [`SessionSlot::begin_connect`] refused to start a new attempt.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BeginConnectError {
    /// A connect attempt is already in flight.
    AlreadyConnecting,
    /// A session is already live.
    AlreadyConnected,
    /// The slot was already shut down.
    ShutDown,
}

/// The outcome of [`SessionSlot::finish_connect`], telling the caller what to
/// do with the connect attempt's result.
pub enum FinishConnect<S, E, R> {
    /// The session is now the slot's live session; `R` is whatever the caller
    /// derived from it (e.g. its public endpoints) while still holding the
    /// lock, so it reflects exactly the stored session.
    Stored(R),
    /// `shutdown()` raced this connect attempt: the freshly built session must
    /// be torn down (fail-closed) instead of ever being observable as
    /// connected. The caller owns it again and must shut it down.
    TornDown(S),
    /// The connect attempt itself failed with `E`; the slot is back to `Idle`
    /// (unless a racing `shutdown()` already made it terminal).
    Failed(E),
}

/// A single proxy session slot with connect/shutdown lifecycle guarantees:
///
/// - Only one connect attempt may be in flight at a time; a second `connect()`
///   while `Connecting` or `Connected` is rejected rather than silently
///   orphaning the first session.
/// - A `shutdown()` that races an in-flight `connect()` is remembered
///   (fail-closed): when the connect attempt completes, it tears the freshly
///   built session down instead of ever storing it, so a live tunnel can never
///   survive a resolved `shutdown()`.
/// - `connect()` after `shutdown()` is rejected.
pub struct SessionSlot<S> {
    state: Mutex<SlotState<S>>,
}

impl<S> SessionSlot<S> {
    /// A fresh, idle slot.
    pub fn new() -> Self {
        Self {
            state: Mutex::new(SlotState::Idle),
        }
    }

    /// Reserves the slot for a new connect attempt. On success the slot is
    /// `Connecting` until [`Self::finish_connect`] is called.
    pub async fn begin_connect(&self) -> Result<(), BeginConnectError> {
        let mut guard = self.state.lock().await;
        match &*guard {
            SlotState::Idle => {
                *guard = SlotState::Connecting;
                Ok(())
            }
            SlotState::Connecting => Err(BeginConnectError::AlreadyConnecting),
            SlotState::Connected(_) => Err(BeginConnectError::AlreadyConnected),
            SlotState::ShutDown => Err(BeginConnectError::ShutDown),
        }
    }

    /// Reports the outcome of the in-flight connect attempt started by
    /// [`Self::begin_connect`]. On success, `derive` runs against the
    /// about-to-be-stored session (under the same lock) to compute the value
    /// handed back to the caller, e.g. the session's public endpoints; this
    /// guarantees the derived value always reflects the session that actually
    /// got stored. See [`FinishConnect`] for what to do with each outcome.
    pub async fn finish_connect<E, R>(
        &self,
        result: Result<S, E>,
        derive: impl FnOnce(&S) -> R,
    ) -> FinishConnect<S, E, R> {
        let mut guard = self.state.lock().await;
        match (&*guard, result) {
            // A shutdown raced us while the session was being built: never let
            // it become observable as connected.
            (SlotState::ShutDown, Ok(session)) => FinishConnect::TornDown(session),
            (SlotState::ShutDown, Err(e)) => FinishConnect::Failed(e),
            (_, Err(e)) => {
                *guard = SlotState::Idle;
                FinishConnect::Failed(e)
            }
            (_, Ok(session)) => {
                let derived = derive(&session);
                *guard = SlotState::Connected(session);
                FinishConnect::Stored(derived)
            }
        }
    }

    /// Runs `f` against the live session, if any. `None` while `Idle`,
    /// `Connecting`, or after `shutdown()`.
    pub async fn with_connected<R>(&self, f: impl FnOnce(&S) -> R) -> Option<R> {
        let guard = self.state.lock().await;
        match &*guard {
            SlotState::Connected(s) => Some(f(s)),
            SlotState::Idle | SlotState::Connecting | SlotState::ShutDown => None,
        }
    }

    /// Shuts the slot down: terminal from here on. Returns the live session if
    /// one existed, so the caller can tear it down outside the lock. A
    /// shutdown while `Idle` or `Connecting` just marks the slot terminal (see
    /// [`Self::finish_connect`] for the `Connecting` race). Idempotent.
    pub async fn shutdown(&self) -> Option<S> {
        let mut guard = self.state.lock().await;
        match std::mem::replace(&mut *guard, SlotState::ShutDown) {
            SlotState::Connected(session) => Some(session),
            SlotState::Idle | SlotState::Connecting | SlotState::ShutDown => None,
        }
    }
}

impl<S> Default for SessionSlot<S> {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;

    /// A fake session that records whether it was torn down, so tests can
    /// assert fail-closed teardown without a real tunnel.
    #[derive(Clone)]
    struct FakeSession(Arc<AtomicBool>);

    impl FakeSession {
        fn new() -> (Self, Arc<AtomicBool>) {
            let flag = Arc::new(AtomicBool::new(false));
            (Self(flag.clone()), flag)
        }

        fn shutdown(self) {
            self.0.store(true, Ordering::SeqCst);
        }
    }

    fn keep(_: &FakeSession) {}

    #[tokio::test]
    async fn connect_then_connect_again_is_rejected() {
        let slot: SessionSlot<FakeSession> = SessionSlot::new();
        slot.begin_connect().await.expect("first connect starts");
        assert_eq!(
            slot.begin_connect().await,
            Err(BeginConnectError::AlreadyConnecting),
            "a second connect while Connecting must be rejected, not orphan the first"
        );
    }

    #[tokio::test]
    async fn connect_after_connected_is_rejected() {
        let slot: SessionSlot<FakeSession> = SessionSlot::new();
        slot.begin_connect().await.expect("starts");
        let (session, _flag) = FakeSession::new();
        let outcome: FinishConnect<FakeSession, (), ()> =
            slot.finish_connect(Ok(session), keep).await;
        assert!(matches!(outcome, FinishConnect::Stored(())));
        assert_eq!(
            slot.begin_connect().await,
            Err(BeginConnectError::AlreadyConnected)
        );
    }

    #[tokio::test]
    async fn a_failed_connect_returns_the_slot_to_idle() {
        let slot: SessionSlot<FakeSession> = SessionSlot::new();
        slot.begin_connect().await.expect("starts");
        let outcome: FinishConnect<FakeSession, &str, ()> =
            slot.finish_connect(Err("boom"), keep).await;
        assert!(matches!(outcome, FinishConnect::Failed("boom")));
        // Idle again: a fresh connect attempt is allowed.
        slot.begin_connect()
            .await
            .expect("failed attempt must return to Idle, allowing a retry");
    }

    #[tokio::test]
    async fn shutdown_while_idle_blocks_future_connects() {
        let slot: SessionSlot<FakeSession> = SessionSlot::new();
        assert!(slot.shutdown().await.is_none());
        assert_eq!(slot.begin_connect().await, Err(BeginConnectError::ShutDown));
    }

    #[tokio::test]
    async fn shutdown_while_connected_tears_the_session_down() {
        let slot: SessionSlot<FakeSession> = SessionSlot::new();
        slot.begin_connect().await.expect("starts");
        let (session, flag) = FakeSession::new();
        let outcome: FinishConnect<FakeSession, (), ()> =
            slot.finish_connect(Ok(session), keep).await;
        assert!(matches!(outcome, FinishConnect::Stored(())));
        let taken = slot.shutdown().await.expect("a live session is returned");
        taken.shutdown();
        assert!(flag.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn shutdown_racing_an_in_flight_connect_fails_closed() {
        // The critical fail-open regression: shutdown() resolves while connect()
        // is still building the tunnel; once connect() finishes, the session it
        // built must be torn down rather than left live and unobserved.
        let slot: SessionSlot<FakeSession> = SessionSlot::new();
        slot.begin_connect().await.expect("starts");

        // shutdown() "wins the race": it observes Connecting and marks ShutDown
        // before the tunnel finishes establishing.
        assert!(
            slot.shutdown().await.is_none(),
            "no session exists yet, so shutdown has nothing to tear down directly"
        );

        // The connect attempt now completes with a freshly built session.
        let (session, flag) = FakeSession::new();
        let outcome: FinishConnect<FakeSession, (), ()> =
            slot.finish_connect(Ok(session), keep).await;
        match outcome {
            FinishConnect::TornDown(s) => s.shutdown(),
            _ => panic!("a connect completing after shutdown must be torn down, never stored"),
        }
        assert!(
            flag.load(Ordering::SeqCst),
            "the tunnel built during the race must end up shut down: never fail-open"
        );

        // The slot stays terminal: no further connects.
        assert_eq!(slot.begin_connect().await, Err(BeginConnectError::ShutDown));
    }

    #[tokio::test]
    async fn shutdown_is_idempotent() {
        let slot: SessionSlot<FakeSession> = SessionSlot::new();
        slot.begin_connect().await.expect("starts");
        let (session, flag) = FakeSession::new();
        let _: FinishConnect<FakeSession, (), ()> = slot.finish_connect(Ok(session), keep).await;
        let taken = slot.shutdown().await.expect("live session");
        taken.shutdown();
        assert!(flag.load(Ordering::SeqCst));
        assert!(
            slot.shutdown().await.is_none(),
            "a second shutdown is a no-op, not a double-teardown"
        );
    }
}
