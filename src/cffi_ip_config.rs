//! `ClientIpConfig` implementation that fires the C `network_config_ipv4_cb`
//! and stores the IP config in `CffiAppState`.

use std::ffi::c_char;
use std::net::Ipv4Addr;
use lightway_core::{ClientIpConfig, InsideIpConfig};

use crate::cffi_state::CffiAppState;
use crate::conn::{he_conn_t, he_network_config_ipv4_cb_t};
use crate::types::he_network_config_ipv4_t;

/// Carries the pointers needed to invoke the C network-config callback.
/// Stored inside the `ClientContext` as the `ip_config` argument.
pub(crate) struct CffiIpConfig {
    cb: Option<he_network_config_ipv4_cb_t>,
    conn_ptr: *mut he_conn_t,
    ctx: *mut std::ffi::c_void,
}

// SAFETY: raw pointers are C-managed and valid for the connection lifetime.
unsafe impl Send for CffiIpConfig {}
// SAFETY: same as Send — raw pointers are only forwarded to C callbacks.
unsafe impl Sync for CffiIpConfig {}

impl CffiIpConfig {
    pub(crate) fn new(
        cb: Option<he_network_config_ipv4_cb_t>,
        conn_ptr: *mut he_conn_t,
        ctx: *mut std::ffi::c_void,
    ) -> Self {
        Self { cb, conn_ptr, ctx }
    }
}

impl ClientIpConfig<CffiAppState> for CffiIpConfig {
    fn ip_config(&self, state: &mut CffiAppState, ip_config: InsideIpConfig) {
        state.ip_config = Some(ip_config);

        let Some(cb) = self.cb else {
            return;
        };

        let mut cfg = he_network_config_ipv4_t {
            local_ip: [0i8; 64],
            dns_ip: [0i8; 64],
            peer_ip: [0i8; 64],
            mtu: lightway_core::MAX_INSIDE_MTU as u16,
        };

        copy_ip_str(ip_config.client_ip, &mut cfg.local_ip);
        copy_ip_str(ip_config.dns_ip, &mut cfg.dns_ip);
        copy_ip_str(ip_config.server_ip, &mut cfg.peer_ip);

        // SAFETY: conn_ptr and ctx are valid for connection lifetime; cfg is
        // stack-allocated and valid for the duration of this call.
        unsafe {
            cb(self.conn_ptr, &mut cfg as *mut he_network_config_ipv4_t, self.ctx);
        }
    }
}

/// Copy an `Ipv4Addr` as a dotted-decimal ASCII string into a `[i8; 64]`.
fn copy_ip_str(addr: Ipv4Addr, dst: &mut [c_char; 64]) {
    let s = addr.to_string();
    let bytes = s.as_bytes();
    let len = bytes.len().min(63);
    for (i, &b) in bytes[..len].iter().enumerate() {
        dst[i] = b as c_char;
    }
    dst[len] = 0;
}
