//! `CffiAppState` — the `AppState` type parameter threaded through the Rust
//! `Connection<AppState>` when used from C.
//!
//! The `Connection` calls `schedule_tick_cb` whenever it needs to fire a timer
//! (TLS retransmit, PMTUD probe, keepalive, etc.).  In the async `lightway-client`
//! world this posts to a `ConnectionTicker` channel; in our synchronous CFFI
//! world we record the pending tick deadline and the C caller drives it via
//! `he_conn_nudge()`.
//!
//! The `ClientIpConfig` callback fires when the server delivers the assigned
//! IPv4 configuration; we store it here and fire the C `network_config_ipv4_cb`
//! immediately afterwards (see `cffi_ip_config.rs`).

use std::ffi::c_void;
use std::time::{Duration, Instant};

use lightway_core::InsideIpConfig;

use crate::conn::{he_conn_t, he_nudge_time_cb_t};

/// Application state carried inside every `Connection<CffiAppState>`.
pub(crate) struct CffiAppState {
    /// The earliest time at which `conn.tick()` should next be called with a
    /// plain `ConnectionTick`.
    /// Set by `schedule_tick_cb`; consumed (and reset) by `he_conn_nudge`.
    pub(crate) next_tick: Option<Instant>,

    /// Payload-carrying ticks (`ExpresslaneKeyShareTick`, `PktCodecTick`)
    /// scheduled by lightway-core, stored as the whole received `TickType` so
    /// `he_conn_nudge` can round-trip each one to `Connection::tick()`
    /// verbatim once its deadline passes. These cannot be folded into
    /// `next_tick`: dispatched as a `ConnectionTick` their retransmit payload
    /// is lost. (`ExpresslaneTickData` is not nameable outside lightway-core,
    /// so the value is stored, never reconstructed.)
    pub(crate) pending_ticks: Vec<(Instant, lightway_core::TickType)>,

    /// Inside IP config received from the server (populated by `CffiIpConfig`).
    pub(crate) ip_config: Option<InsideIpConfig>,

    /// C nudge-time callback to invoke when a tick is scheduled.
    /// Signals the C++ `nudge_event_` so the post-online keepalive loop wakes.
    pub(crate) nudge_time_cb: Option<he_nudge_time_cb_t>,
    /// Back-pointer to the inlined `he_conn_t`; forwarded to `nudge_time_cb`.
    pub(crate) conn_ptr: *mut he_conn_t,
    /// Opaque C context forwarded to `nudge_time_cb`.
    pub(crate) ctx: *mut c_void,
}

impl CffiAppState {
    /// Earliest pending tick deadline across the `ConnectionTick` slot and the
    /// payload ticks — the moment a single-timer host must wake for next.
    pub(crate) fn earliest_tick_deadline(&self) -> Option<Instant> {
        let pending = self.pending_ticks.iter().map(|(t, _)| *t).min();
        match (self.next_tick, pending) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }
}

impl Default for CffiAppState {
    fn default() -> Self {
        Self {
            next_tick: None,
            pending_ticks: Vec::new(),
            ip_config: None,
            nudge_time_cb: None,
            conn_ptr: std::ptr::null_mut(),
            ctx: std::ptr::null_mut(),
        }
    }
}

// SAFETY: raw pointers are only forwarded to C callbacks whose lifetimes
// the C caller guarantees exceed the connection lifetime.
unsafe impl Send for CffiAppState {}
// SAFETY: raw pointers are only forwarded to C callbacks whose lifetimes
// the C caller guarantees exceed the connection lifetime.
unsafe impl Sync for CffiAppState {}

// ──────────────────────────────────────────────────────────────────────────────
// schedule_tick_cb — records the next desired tick time
// ──────────────────────────────────────────────────────────────────────────────

/// `ScheduleTickCb<CffiAppState>` implementation.
///
/// Called by `Connection` when it wants a timer tick after `d`.  We record the
/// deadline; `he_conn_get_nudge_time` exposes it to C, and `he_conn_nudge`
/// calls `conn.tick()` when the deadline has passed.
pub(crate) fn cffi_schedule_tick_cb(
    d: Duration,
    state: &mut CffiAppState,
    tick_type: lightway_core::TickType,
) {
    let now = Instant::now();
    let deadline = now + d;
    match tick_type {
        // ConnectionTick is stateless, so deadlines can be merged: keep the
        // earliest pending one.
        lightway_core::TickType::ConnectionTick => {
            state.next_tick = Some(match state.next_tick {
                Some(existing) if existing <= deadline => existing,
                _ => deadline,
            });
        }
        // Payload-carrying ticks (ExpresslaneKeyShareTick, PktCodecTick) must
        // be round-tripped to Connection::tick() with their original type and
        // payload — dispatched as a plain ConnectionTick their retransmit
        // state is lost, and e.g. a dropped ExpresslaneConfig/ack would then
        // never be retried. Stale entries are harmless (core's handlers drop
        // ticks whose counter / request id no longer matches) and each
        // retransmit only reschedules after its predecessor was consumed, so
        // this list stays tiny.
        other => state.pending_ticks.push((deadline, other)),
    }

    // Notify the C caller so it can wake its nudge thread (e.g. signal
    // nudge_event_ in the C++ lightway_tunnel nudge_thread). The host keeps
    // ONE timer and resets it to whatever timeout we pass, so it must always
    // be told the time to the EARLIEST stored deadline — passing this call's
    // own delay would let a later tick (e.g. a multi-second ConnectionTick)
    // overwrite an earlier pending key-share/codec retransmit deadline and
    // delay that retransmit by seconds.
    if let Some(cb) = state.nudge_time_cb {
        // The deadline just inserted makes the state non-empty; unwrap_or is
        // pure defensiveness.
        let earliest = state.earliest_tick_deadline().unwrap_or(deadline);
        let timeout_ms = earliest
            .saturating_duration_since(now)
            .as_millis()
            .min(i32::MAX as u128) as i32;
        // SAFETY: conn_ptr and ctx are valid C pointers for the connection
        // lifetime; the C callback only uses them to look up its own state.
        unsafe { cb(state.conn_ptr, timeout_ms, state.ctx) };
    }
}
