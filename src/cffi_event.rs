//! `EventCallback` implementation that bridges `lightway-core` events to
//! the C function-pointer callbacks stored in `he_ssl_ctx_t`.
//!
//! An instance is created at `he_client_connect()` time and passed to
//! `ClientConnectionBuilder::with_event_cb()`.  When `Connection` fires an
//! event (state change, keepalive reply, etc.) the methods here translate
//! it into the matching C callback invocation.

use lightway_core::{Event, EventCallback, ExpresslaneState, State};

use crate::conn::{
    he_conn_t, he_event_cb_t, he_expresslane_state_change_cb_t, he_pmtud_state_change_cb_t,
    he_state_change_cb_t,
};
use crate::types::{he_conn_event_t, he_conn_state_t, he_expresslane_state_t};

/// Carries the C callback pointers required to deliver events.
pub(crate) struct CffiEventCallback {
    pub(crate) state_change_cb: Option<he_state_change_cb_t>,
    pub(crate) event_cb: Option<he_event_cb_t>,
    #[allow(dead_code)]
    pub(crate) pmtud_state_change_cb: Option<he_pmtud_state_change_cb_t>,
    pub(crate) expresslane_state_change_cb: Option<he_expresslane_state_change_cb_t>,
    /// Raw back-pointer to the inlined `he_conn_t` inside `he_client_t`.
    /// Valid for the lifetime of the connection.
    pub(crate) conn_ptr: *mut he_conn_t,
    /// Opaque C context forwarded to every callback.
    pub(crate) ctx: *mut std::ffi::c_void,
}

// SAFETY: all raw pointers are C-managed and valid for the connection lifetime.
unsafe impl Send for CffiEventCallback {}
unsafe impl Sync for CffiEventCallback {}

impl EventCallback for CffiEventCallback {
    fn event(&mut self, event: Event) {
        match event {
            // ── State transitions ────────────────────────────────────────────
            Event::StateChanged(state) => {
                let c_state = rust_state_to_c(state);
                // Update the cached state visible through he_conn_get_state().
                // SAFETY: conn_ptr is valid for the connection lifetime.
                unsafe { (*self.conn_ptr).state = c_state };

                if let Some(cb) = self.state_change_cb {
                    // SAFETY: conn_ptr and ctx are valid; no Rust data is
                    // dereferenced through them by the callback.
                    unsafe { cb(self.conn_ptr, c_state, self.ctx) };
                }
            }

            // ── Keepalive pong ───────────────────────────────────────────────
            Event::KeepaliveReply => {
                self.fire_event(he_conn_event_t::HE_EVENT_PONG);
            }

            // ── First packet from server ─────────────────────────────────────
            Event::FirstPacketReceived => {
                self.fire_event(he_conn_event_t::HE_EVENT_FIRST_MESSAGE_RECEIVED);
            }

            // ── Session id rotation acknowledged ─────────────────────────────
            Event::SessionIdRotationAcknowledged { .. } => {
                self.fire_event(he_conn_event_t::HE_EVENT_PENDING_SESSION_ACKNOWLEDGED);
            }

            // ── TLS key update ───────────────────────────────────────────────
            Event::TlsKeysUpdateStart => {
                self.fire_event(he_conn_event_t::HE_EVENT_SECURE_RENEGOTIATION_STARTED);
            }
            Event::TlsKeysUpdateCompleted => {
                self.fire_event(he_conn_event_t::HE_EVENT_SECURE_RENEGOTIATION_COMPLETED);
            }

            // ── ExpressLane state change ─────────────────────────────────────
            Event::ExpresslaneStateChanged(state) => {
                if let Some(cb) = self.expresslane_state_change_cb {
                    let c_state = rust_expresslane_state_to_c(state);
                    // SAFETY: conn_ptr and ctx valid for connection lifetime.
                    unsafe { cb(self.conn_ptr, c_state, self.ctx) };
                }
            }

            // ── Events with no direct C mapping — silently ignore ────────────
            Event::EncodingStateChanged { .. } => {}
            Event::SessionIdRotationStarted { .. } => {}
        }
    }
}

impl CffiEventCallback {
    /// Invoke `event_cb` if one is registered.
    fn fire_event(&self, event: he_conn_event_t) {
        if let Some(cb) = self.event_cb {
            // SAFETY: conn_ptr and ctx are valid for the connection lifetime.
            unsafe { cb(self.conn_ptr, event, self.ctx) };
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// State mapping
// ──────────────────────────────────────────────────────────────────────────────

/// Map a `lightway_core::State` to the C `he_conn_state_t`.
///
/// Discriminant values in both enums were chosen to match; the mapping is
/// therefore a straight numeric correspondence.
fn rust_state_to_c(state: State) -> he_conn_state_t {
    match state {
        State::Connecting => he_conn_state_t::HE_STATE_CONNECTING,
        State::LinkUp => he_conn_state_t::HE_STATE_LINK_UP,
        State::Authenticating => he_conn_state_t::HE_STATE_AUTHENTICATING,
        State::Online => he_conn_state_t::HE_STATE_ONLINE,
        State::Disconnecting => he_conn_state_t::HE_STATE_DISCONNECTING,
        State::Disconnected => he_conn_state_t::HE_STATE_DISCONNECTED,
    }
}

/// Map a `lightway_core::ExpresslaneState` to the C `he_expresslane_state_t`.
fn rust_expresslane_state_to_c(state: ExpresslaneState) -> he_expresslane_state_t {
    match state {
        ExpresslaneState::Disabled => he_expresslane_state_t::HE_EXPRESSLANE_STATE_DISABLED,
        ExpresslaneState::Inactive => he_expresslane_state_t::HE_EXPRESSLANE_STATE_INACTIVE,
        ExpresslaneState::WaitingForClient => {
            he_expresslane_state_t::HE_EXPRESSLANE_STATE_WAITING_FOR_CLIENT
        }
        ExpresslaneState::Active => he_expresslane_state_t::HE_EXPRESSLANE_STATE_ACTIVE,
        ExpresslaneState::Degraded => he_expresslane_state_t::HE_EXPRESSLANE_STATE_DEGRADED,
    }
}
