//! Opaque connection objects and callback type aliases.
//!
//! `he_client_t` is the top-level object that `lightway_tunnel.h` allocates via
//! `he_client_create()` and frees via `he_client_destroy()`. Internally it holds
//! all per-connection state: the Rust `Connection` (or its builder), the
//! configured callbacks, credential strings, and SSL-context settings.
//!
//! `he_conn_t` and `he_ssl_ctx_t` are embedded inside `he_client_t` to match
//! the memory layout expected by the C API; callers access them exclusively
//! through the exported FFI accessor functions.

use std::ffi::{CString, c_char, c_void};
use std::sync::{Arc, Mutex};

use lightway_core::Connection;

use crate::cffi_state::CffiAppState;

use crate::types::*;

// ──────────────────────────────────────────────────────────────────────────────
// Callback type aliases (cbindgen will emit these as `typedef`s).
// ──────────────────────────────────────────────────────────────────────────────

/// Called whenever the connection state changes.
pub type he_state_change_cb_t = unsafe extern "C" fn(
    conn: *mut he_conn_t,
    new_state: he_conn_state_t,
    context: *mut c_void,
) -> he_return_code_t;

/// Called when a decrypted inside (TUN) packet is ready to inject.
pub type he_inside_write_cb_t = unsafe extern "C" fn(
    conn: *mut he_conn_t,
    packet: *mut u8,
    length: usize,
    context: *mut c_void,
) -> he_return_code_t;

/// Called when an encrypted outside (wire) packet is ready to send.
pub type he_outside_write_cb_t = unsafe extern "C" fn(
    conn: *mut he_conn_t,
    packet: *mut u8,
    length: usize,
    context: *mut c_void,
) -> he_return_code_t;

/// Called when the server delivers IPv4 network configuration.
pub type he_network_config_ipv4_cb_t = unsafe extern "C" fn(
    conn: *mut he_conn_t,
    config: *mut he_network_config_ipv4_t,
    context: *mut c_void,
) -> he_return_code_t;

/// Called when the server delivers opaque server-config data.
pub type he_server_config_cb_t = unsafe extern "C" fn(
    conn: *mut he_conn_t,
    buffer: *mut u8,
    length: usize,
    context: *mut c_void,
) -> he_return_code_t;

/// Called when the keepalive nudge interval changes.
pub type he_nudge_time_cb_t = unsafe extern "C" fn(
    conn: *mut he_conn_t,
    timeout: i32,
    context: *mut c_void,
) -> he_return_code_t;

/// Called on miscellaneous connection events.
pub type he_event_cb_t = unsafe extern "C" fn(
    conn: *mut he_conn_t,
    event: he_conn_event_t,
    context: *mut c_void,
) -> he_return_code_t;

/// Called to authenticate a username / password pair (server role).
pub type he_auth_cb_t = unsafe extern "C" fn(
    conn: *mut he_conn_t,
    username: *const c_char,
    password: *const c_char,
    context: *mut c_void,
) -> bool;

/// Called to authenticate an opaque auth-token (server role).
pub type he_auth_token_cb_t = unsafe extern "C" fn(
    conn: *mut he_conn_t,
    token: *const u8,
    len: usize,
    context: *mut c_void,
) -> bool;

/// Called to authenticate via an arbitrary auth buffer (server role).
pub type he_auth_buf_cb_t = unsafe extern "C" fn(
    conn: *mut he_conn_t,
    auth_type: u8,
    buffer: *mut u8,
    length: u16,
    context: *mut c_void,
) -> bool;

/// Called to let the server-side app populate the network config.
pub type he_populate_network_config_ipv4_cb_t = unsafe extern "C" fn(
    conn: *mut he_conn_t,
    config: *mut he_network_config_ipv4_t,
    context: *mut c_void,
) -> he_return_code_t;

/// Called when the PMTUD state changes.
pub type he_pmtud_state_change_cb_t = unsafe extern "C" fn(
    conn: *mut he_conn_t,
    state: he_pmtud_state_t,
    context: *mut c_void,
) -> he_return_code_t;

/// Called when the PMTUD probe timer fires.
pub type he_pmtud_time_cb_t = unsafe extern "C" fn(
    conn: *mut he_conn_t,
    timeout: i32,
    context: *mut c_void,
) -> he_return_code_t;

/// Called when ExpressLane key material is refreshed.
///
/// `keys` points to a stack-allocated `he_expresslane_keys_t` valid only
/// for the duration of the call — copy the contents if you need to retain them.
pub type he_expresslane_cb_t = unsafe extern "C" fn(
    conn: *mut he_conn_t,
    keys: *const he_expresslane_keys_t,
    context: *mut c_void,
) -> he_return_code_t;

/// Called when the ExpressLane operational state changes.
pub type he_expresslane_state_change_cb_t = unsafe extern "C" fn(
    conn: *mut he_conn_t,
    state: he_expresslane_state_t,
    context: *mut c_void,
) -> he_return_code_t;

// ──────────────────────────────────────────────────────────────────────────────
// SSL context (per-client configuration)
// ──────────────────────────────────────────────────────────────────────────────

/// SSL / protocol context.  Holds per-connection configuration that in the OSS
/// C library lives inside `he_ssl_ctx_t`.  C code accesses this via
/// `client->ssl_ctx`.
pub struct he_ssl_ctx_t {
    // Callbacks — all optional
    pub(crate) state_change_cb: Option<he_state_change_cb_t>,
    pub(crate) inside_write_cb: Option<he_inside_write_cb_t>,
    pub(crate) outside_write_cb: Option<he_outside_write_cb_t>,
    pub(crate) network_config_ipv4_cb: Option<he_network_config_ipv4_cb_t>,
    pub(crate) server_config_cb: Option<he_server_config_cb_t>,
    pub(crate) nudge_time_cb: Option<he_nudge_time_cb_t>,
    pub(crate) event_cb: Option<he_event_cb_t>,
    pub(crate) auth_cb: Option<he_auth_cb_t>,
    pub(crate) auth_token_cb: Option<he_auth_token_cb_t>,
    pub(crate) auth_buf_cb: Option<he_auth_buf_cb_t>,
    pub(crate) populate_network_config_ipv4_cb: Option<he_populate_network_config_ipv4_cb_t>,
    pub(crate) pmtud_state_change_cb: Option<he_pmtud_state_change_cb_t>,
    pub(crate) pmtud_time_cb: Option<he_pmtud_time_cb_t>,
    pub(crate) expresslane_cb: Option<he_expresslane_cb_t>,
    pub(crate) expresslane_state_change_cb: Option<he_expresslane_state_change_cb_t>,

    // Connection-level settings
    pub(crate) enable_expresslane: bool,
    pub(crate) connection_type: he_connection_type_t,
    pub(crate) ca_cert: Option<Vec<u8>>,
    pub(crate) server_dn: Option<CString>,
    pub(crate) use_pqc: bool,
    pub(crate) use_chacha20: bool,
}

impl Default for he_ssl_ctx_t {
    fn default() -> Self {
        Self {
            state_change_cb: None,
            inside_write_cb: None,
            outside_write_cb: None,
            network_config_ipv4_cb: None,
            server_config_cb: None,
            nudge_time_cb: None,
            event_cb: None,
            auth_cb: None,
            auth_token_cb: None,
            auth_buf_cb: None,
            populate_network_config_ipv4_cb: None,
            pmtud_state_change_cb: None,
            pmtud_time_cb: None,
            expresslane_cb: None,
            expresslane_state_change_cb: None,
            enable_expresslane: false,
            connection_type: he_connection_type_t::HE_CONNECTION_TYPE_DATAGRAM,
            ca_cert: None,
            server_dn: None,
            use_pqc: false,
            use_chacha20: false,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Connection object
// ──────────────────────────────────────────────────────────────────────────────

/// Per-connection state embedded inside `he_client_t`.
///
/// Exposed to C via `he_client_get_conn()`; holds credentials and runtime
/// state for a single tunnel connection.
pub struct he_conn_t {
    /// Back-pointer to the owning `he_client_t`.  Set by `he_client_t::new()`
    /// so that functions receiving only a `*mut he_conn_t` can recover the
    /// parent without relying on a specific field offset.
    pub(crate) client_ptr: *mut he_client_t,

    /// Serialises concurrent calls into the owning `he_client_t`.
    /// Lives here so that `with_client` can clone and lock it from
    /// `*mut he_conn_t` before creating `&mut he_client_t`, avoiding any
    /// aliasing between the `MutexGuard` borrow and the mutable reference
    /// handed to the closure.
    pub(crate) arc_lock: Arc<Mutex<()>>,

    // Auth credentials — only one of (username+password) or auth_token is set
    pub(crate) username: Option<CString>,
    pub(crate) password: Option<CString>,
    pub(crate) auth_token: Option<Vec<u8>>,

    // Connection parameters
    pub(crate) sni_hostname: Option<CString>,
    pub(crate) outside_mtu: u16,

    // User-supplied opaque context pointer
    pub(crate) context: *mut c_void,

    // Runtime state (updated during the connection lifecycle)
    pub(crate) state: he_conn_state_t,
    pub(crate) nudge_time_ms: i32,
    pub(crate) outside_mtu_negotiated: u16,
    pub(crate) effective_pmtu: u16,
    pub(crate) current_protocol: he_connection_protocol_t,
    pub(crate) curve_name: Option<CString>,
    pub(crate) cipher_name: Option<CString>,
}

// SAFETY: Both raw pointer fields in he_conn_t are safe to send across threads:
// - `context` is an opaque C pointer forwarded only to C callbacks; it is
//   never dereferenced by Rust code.
// - `client_ptr` points to the owning `he_client_t` allocation; it is written
//   once in `he_client_t::new()` and only dereferenced in this crate after
//   acquiring `arc_lock` (see `with_client`).
// - `arc_lock` is an `Arc<Mutex<()>>` which is itself `Send + Sync`.
// Note: other `he_conn_t` fields (credentials, runtime state) may be read or
// written by FFI setters/getters without holding the lock; thread-safety for
// those accesses is a caller responsibility.
unsafe impl Send for he_conn_t {}
// SAFETY: Same reasoning as Send.
unsafe impl Sync for he_conn_t {}

impl Default for he_conn_t {
    fn default() -> Self {
        Self {
            client_ptr: std::ptr::null_mut(),
            arc_lock: Arc::new(Mutex::new(())),
            username: None,
            password: None,
            auth_token: None,
            sni_hostname: None,
            outside_mtu: 1500,
            context: std::ptr::null_mut(),
            state: he_conn_state_t::HE_STATE_NONE,
            nudge_time_ms: 0,
            outside_mtu_negotiated: 1500,
            effective_pmtu: 0,
            current_protocol: he_connection_protocol_t::HE_CONNECTION_PROTOCOL_NONE,
            curve_name: None,
            cipher_name: None,
        }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Client object (top-level handle)
// ──────────────────────────────────────────────────────────────────────────────

/// Top-level handle allocated by `he_client_create()`.
///
/// C callers treat this struct as opaque and interact with it via the accessor
/// functions declared in `lightway_cffi.h` (e.g. `he_client_get_conn`,
/// `he_client_get_ssl_ctx`).  Concurrent data-path calls (e.g.
/// `he_conn_outside_data_received`, `he_conn_inside_packet_received`,
/// `he_conn_nudge`) are serialised internally by the library before any
/// mutable access to the underlying client state.
///
pub struct he_client_t {
    /// Embedded connection object; exposed to C via accessor functions.
    pub conn: he_conn_t,
    /// Embedded SSL-context object; exposed to C via accessor functions.
    pub ssl_ctx: he_ssl_ctx_t,
    /// Live Rust Connection, present after `he_client_connect()` succeeds.
    pub(crate) connection: Option<Connection<CffiAppState>>,
}


impl he_client_t {
    pub(crate) fn new() -> Box<Self> {
        let mut client = Box::new(Self {
            conn: he_conn_t::default(),
            ssl_ctx: he_ssl_ctx_t::default(),
            connection: None,
        });
        // Store the back-pointer so he_conn_t can recover its parent.
        // SAFETY: the Box address is stable for the lifetime of the allocation.
        client.conn.client_ptr = &raw mut *client;
        client
    }
}
