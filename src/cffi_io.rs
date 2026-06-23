//! `OutsideIOSendCallback` and `InsideIOSendCallback` implementations that
//! bridge the Rust `lightway-core` I/O traits to the C function-pointer
//! callbacks stored in `he_ssl_ctx_t` / `he_conn_t`.
//!
//! The CFFI caller owns the network socket and the TUN device; we just
//! forward bytes between the `Connection` and the C callbacks.

use std::net::{SocketAddr, SocketAddrV4};
use bytes::BytesMut;
use lightway_core::{IOCallbackResult, InsideIOSendCallback, OutsideIOSendCallback};

use crate::cffi_state::CffiAppState;
use crate::conn::{he_conn_t, he_outside_write_cb_t};
use crate::types::he_return_code_t;

// ──────────────────────────────────────────────────────────────────────────────
// Outside I/O — encrypted wire packets → C outside_write_cb
// ──────────────────────────────────────────────────────────────────────────────

/// Forwards encrypted wire packets produced by `Connection` to the C
/// `outside_write_cb` registered on `he_ssl_ctx_t`.
pub(crate) struct CffiOutsideIO {
    /// The C callback to invoke when an encrypted packet is ready.
    cb: he_outside_write_cb_t,
    /// Raw pointer to the `he_conn_t` — passed back to the callback.
    conn_ptr: *mut he_conn_t,
    /// Opaque context pointer from `he_conn_t::context`.
    ctx: *mut std::ffi::c_void,
    /// Peer address — required by the trait but not used in the CFFI path
    /// (the C side manages its own socket).
    peer_addr: SocketAddr,
}

// SAFETY: `conn_ptr` and `ctx` are C-managed raw pointers.  We never
// dereference them ourselves — we only pass them back to the C callback, which
// the C side guarantees are valid for the connection lifetime.
unsafe impl Send for CffiOutsideIO {}
// SAFETY: same as Send — raw pointers are only forwarded to C callbacks.
unsafe impl Sync for CffiOutsideIO {}

impl CffiOutsideIO {
    pub(crate) fn new(
        cb: he_outside_write_cb_t,
        conn_ptr: *mut he_conn_t,
        ctx: *mut std::ffi::c_void,
    ) -> Self {
        // Use a dummy peer addr; the C caller manages the actual socket.
        let peer_addr =
            SocketAddr::V4(SocketAddrV4::new(std::net::Ipv4Addr::UNSPECIFIED, 0));
        Self { cb, conn_ptr, ctx, peer_addr }
    }
}

impl OutsideIOSendCallback for CffiOutsideIO {
    fn send(&self, buf: &[u8]) -> IOCallbackResult<usize> {
        // The C `outside_write_cb` typedef takes `uint8_t*` (matching the OSS
        // API), but `buf` is borrowed read-only here. The callback MUST treat
        // the buffer as read-only — writing through this pointer is undefined
        // behaviour, as it aliases a shared `&[u8]`.
        // SAFETY: `conn_ptr` and `ctx` are valid for the lifetime of the C
        // connection, and `buf` is a valid slice for the duration of this call.
        let result = unsafe {
            (self.cb)(
                self.conn_ptr,
                buf.as_ptr() as *mut u8,
                buf.len(),
                self.ctx,
            )
        };
        if result == he_return_code_t::HE_SUCCESS {
            IOCallbackResult::Ok(buf.len())
        } else {
            IOCallbackResult::Err(std::io::Error::other(format!(
                "outside_write_cb returned {:?}",
                result
            )))
        }
    }

    /// GSO (UDP segmentation offload) is not driven by this shim: the C
    /// consumer owns the socket and the data path forwards single packets via
    /// `he_conn_inside_packet_received` / `Connection::inside_data_received`,
    /// which never calls `send_gso`. Report it unsupported, matching
    /// `lightway-core`'s own non-GSO `OutsideIOSendCallback` fakes.
    fn send_gso(
        &self,
        _bufs: &[std::io::IoSlice<'_>],
        _gso_size: u16,
    ) -> IOCallbackResult<usize> {
        IOCallbackResult::Err(std::io::Error::new(
            std::io::ErrorKind::Unsupported,
            "send_gso not supported by lightway-cffi shim",
        ))
    }

    fn peer_addr(&self) -> SocketAddr {
        self.peer_addr
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Inside I/O — decrypted TUN packets → C inside_write_cb
// ──────────────────────────────────────────────────────────────────────────────

use crate::conn::he_inside_write_cb_t;

/// Forwards decrypted inner (TUN) packets produced by `Connection` to the C
/// `inside_write_cb`.
pub(crate) struct CffiInsideIO {
    cb: he_inside_write_cb_t,
    conn_ptr: *mut he_conn_t,
    ctx: *mut std::ffi::c_void,
}

// SAFETY: same as CffiOutsideIO — raw pointers are only forwarded to C callbacks.
unsafe impl Send for CffiInsideIO {}
// SAFETY: same as Send.
unsafe impl Sync for CffiInsideIO {}

impl CffiInsideIO {
    pub(crate) fn new(
        cb: he_inside_write_cb_t,
        conn_ptr: *mut he_conn_t,
        ctx: *mut std::ffi::c_void,
    ) -> Self {
        Self { cb, conn_ptr, ctx }
    }
}

impl InsideIOSendCallback<CffiAppState> for CffiInsideIO {
    fn send(
        &self,
        buf: BytesMut,
        _state: &mut CffiAppState,
    ) -> IOCallbackResult<usize> {
        let len = buf.len();
        // SAFETY: `conn_ptr` and `ctx` valid for connection lifetime.
        // `buf` slice is valid for this call's duration.
        let result = unsafe {
            (self.cb)(
                self.conn_ptr,
                buf.as_ptr() as *mut u8,
                len,
                self.ctx,
            )
        };
        if result == he_return_code_t::HE_SUCCESS {
            IOCallbackResult::Ok(len)
        } else {
            IOCallbackResult::Err(std::io::Error::other(format!(
                "inside_write_cb returned {:?}",
                result
            )))
        }
    }

    fn mtu(&self) -> usize {
        lightway_core::MAX_INSIDE_MTU
    }

    fn if_index(&self) -> std::io::Result<u32> {
        Err(std::io::Error::other("not supported in CFFI"))
    }

    fn name(&self) -> std::io::Result<String> {
        Err(std::io::Error::other("not supported in CFFI"))
    }
}
