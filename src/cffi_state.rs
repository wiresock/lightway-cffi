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

use std::time::{Duration, Instant};

use lightway_core::InsideIpConfig;

/// Application state carried inside every `Connection<CffiAppState>`.
#[derive(Default)]
pub(crate) struct CffiAppState {
    /// The earliest time at which `conn.tick()` should next be called.
    /// Set by `schedule_tick_cb`; consumed (and reset) by `he_conn_nudge`.
    pub(crate) next_tick: Option<Instant>,

    /// Inside IP config received from the server (populated by `CffiIpConfig`).
    pub(crate) ip_config: Option<InsideIpConfig>,
}

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
    _tick_type: lightway_core::TickType,
) {
    let deadline = Instant::now() + d;
    // Keep the earliest pending deadline.
    state.next_tick = Some(match state.next_tick {
        Some(existing) if existing <= deadline => existing,
        _ => deadline,
    });
}
