//! `ExpresslaneCb` implementation that delivers key material to the C
//! `he_expresslane_cb_t` callback.
//!
//! When `lightway-core` completes an ExpressLane key exchange it calls
//! `ExpresslaneCb::update` with the session ID and fresh symmetric keys.
//! We package those into `he_expresslane_keys_t` and invoke the C callback,
//! allowing the Windows kernel-mode NDIS driver to install the fast-path keys.

use std::sync::Arc;

use lightway_core::{ExpresslaneCb, ExpresslaneCbData, ExpresslaneCbType, SessionId};

use crate::cffi_state::CffiAppState;
use crate::conn::{he_conn_t, he_expresslane_cb_t};
use crate::types::he_expresslane_keys_t;

/// Bridges `ExpresslaneCb` to the C `he_expresslane_cb_t` function pointer.
pub(crate) struct CffiExpresslaneCb {
    cb: he_expresslane_cb_t,
    conn_ptr: *mut he_conn_t,
    ctx: *mut std::ffi::c_void,
}

// SAFETY: raw pointers are C-managed and valid for the connection lifetime.
unsafe impl Send for CffiExpresslaneCb {}
// SAFETY: same as Send — raw pointers are only forwarded to C callbacks.
unsafe impl Sync for CffiExpresslaneCb {}

impl CffiExpresslaneCb {
    pub(crate) fn create(
        cb: he_expresslane_cb_t,
        conn_ptr: *mut he_conn_t,
        ctx: *mut std::ffi::c_void,
    ) -> ExpresslaneCbType<CffiAppState> {
        Arc::new(Self { cb, conn_ptr, ctx })
    }
}

impl ExpresslaneCb<CffiAppState> for CffiExpresslaneCb {
    fn update(&self, session_id: SessionId, data: ExpresslaneCbData, _state: &CffiAppState) {
        let session_id_bytes: [u8; 8] = *session_id.as_bytes();

        let mut keys = he_expresslane_keys_t {
            session_id: session_id_bytes,
            self_key: data.self_key.0,
            peer_key: data.peer_key.0,
            // Wire byte of the negotiated version (repr(u8): Unknown=0/V1=1/V2=2)
            // so the consumer can create a matching he_expresslane_session_t.
            version: data.version as u8,
        };

        // SAFETY: conn_ptr and ctx are valid for connection lifetime.
        // `keys` is stack-allocated and valid for the duration of this call.
        unsafe {
            (self.cb)(self.conn_ptr, &keys as *const he_expresslane_keys_t, self.ctx);
        }

        // Scrub our copy of the symmetric key material once the callback (which
        // installs it into the NDIS driver) has returned, so the keys do not
        // linger in reused stack memory.
        crate::conn::scrub_bytes(&mut keys.self_key);
        crate::conn::scrub_bytes(&mut keys.peer_key);
    }
}
