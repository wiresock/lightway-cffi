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

        let keys = he_expresslane_keys_t {
            session_id: session_id_bytes,
            self_key: data.self_key.0,
            peer_key: data.peer_key.0,
        };

        // SAFETY: conn_ptr and ctx are valid for connection lifetime.
        // `keys` is stack-allocated and valid for the duration of this call.
        unsafe {
            (self.cb)(self.conn_ptr, &keys as *const he_expresslane_keys_t, self.ctx);
        }
    }
}
