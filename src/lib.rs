//! lightway-cffi: C ABI shim over the Rust `lightway-core` crate.
//!
//! Exposes a C API source-compatible with the OSS `expressvpn/lightway-core`
//! C library so that `kp_pkf_client` (and its `lightway_tunnel.h`) can swap
//! the underlying implementation without source changes.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
// C-ABI naming uses snake_case types (he_return_code_t etc.) and SCREAMING_SNAKE
// enum variants (HE_SUCCESS etc.) by convention — suppress Rust style lints.
#![allow(non_camel_case_types, non_upper_case_globals, clippy::upper_case_acronyms)]

use std::ffi::{CStr, CString, c_char, c_int, c_void};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

pub mod cffi_event;
pub mod cffi_expresslane;
pub mod cffi_io;
pub mod cffi_ip_config;
pub mod cffi_state;
pub mod conn;
pub mod types;
mod version;

use bytes::BytesMut;
use lightway_core::{
    AuthMethod, ClientContextBuilder, ConnectionType, DEFAULT_EXPRESSLANE_KEYS_ROTATION_INTERVAL,
    Header, OutsideIOSendCallbackArg, OutsidePacket, ProtocolVersion, RootCertificate, SessionId,
    State, TickType,
};

use cffi_expresslane::{CffiExpresslaneCb, CffiExpresslaneMetrics};

use cffi_event::CffiEventCallback;
use cffi_io::{CffiInsideIO, CffiOutsideIO};
use cffi_ip_config::CffiIpConfig;
use cffi_state::{CffiAppState, cffi_schedule_tick_cb};
use conn::{he_client_t, he_conn_t};

use types::*;

// ──────────────────────────────────────────────────────────────────────────────
// FFI boundary helpers: panic isolation + re-entrancy-aware locking
// ──────────────────────────────────────────────────────────────────────────────

/// Run an FFI entry-point body, converting any panic into `default` instead of
/// letting it unwind across the C ABI boundary (which aborts the process).
///
/// Wraps the body in [`AssertUnwindSafe`]: the entry points only capture raw
/// pointers and `Copy` scalars, and any `&mut he_client_t` is created *inside*
/// the closure (under the lock), so there is no broken invariant to leak.
#[inline]
fn ffi_guard<R>(default: R, f: impl FnOnce() -> R) -> R {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(default)
}

static NEXT_THREAD_TOKEN: AtomicU64 = AtomicU64::new(1);
thread_local! {
    /// A process-unique, non-zero token for the current thread.
    static THREAD_TOKEN: u64 = NEXT_THREAD_TOKEN.fetch_add(1, Ordering::Relaxed);
}

#[inline]
fn current_thread_token() -> u64 {
    THREAD_TOKEN.with(|t| *t)
}

/// Clears the per-client lock-owner token on drop, including during a panic
/// unwind, so a future call on the same thread is not mistaken for re-entrancy.
struct OwnerReset<'a>(&'a AtomicU64);
impl Drop for OwnerReset<'_> {
    fn drop(&mut self) {
        self.0.store(0, Ordering::Release);
    }
}

/// Acquire the per-client lock and invoke `f` with an exclusive reference.
///
/// Returns `Err(HE_ERR_NULL_POINTER)` if `client` is null and
/// `Err(HE_ERR_INVALID_CONN_STATE)` if the current thread already holds the
/// lock — i.e. a C callback (fired while the lock is held) tried to re-enter a
/// locking API.  Re-entering would dead-lock the non-reentrant mutex and alias
/// the outstanding `&mut he_client_t`, so it is rejected rather than performed.
///
/// # Safety
/// `client` must be null or a valid pointer from `he_client_create` whose
/// `conn.arc_lock` / `conn.lock_owner` were initialised by `he_client_t::new()`.
/// `f` must not let any reference derived from `&mut he_client_t` escape.
unsafe fn lock_client<F, R>(client: *mut he_client_t, f: F) -> Result<R, he_return_code_t>
where
    F: FnOnce(&mut he_client_t) -> R,
{
    if client.is_null() {
        return Err(he_return_code_t::HE_ERR_NULL_POINTER);
    }
    // SAFETY: client is non-null (checked) and valid per the caller contract.
    // Clone the lock/owner Arcs via the raw pointer *before* creating any
    // reference into the allocation, so the guard's borrow never overlaps the
    // `&mut he_client_t` handed to the closure.
    let (arc_lock, owner) = unsafe { ((*client).conn.arc_lock.clone(), (*client).conn.lock_owner.clone()) };

    let me = current_thread_token();
    if owner.load(Ordering::Acquire) == me {
        return Err(he_return_code_t::HE_ERR_INVALID_CONN_STATE);
    }

    let guard = arc_lock.lock().unwrap_or_else(|e| e.into_inner());
    owner.store(me, Ordering::Release);
    // Cleared on scope exit (and on panic) before `guard` is released.
    let _reset = OwnerReset(&owner);

    // SAFETY: the lock is held and re-entrancy was rejected above, so this is
    // the only live reference into the allocation.
    let out = f(unsafe { &mut *client });
    drop(_reset);
    drop(guard);
    Ok(out)
}

// ──────────────────────────────────────────────────────────────────────────────
// Connection-info snapshot helper
// ──────────────────────────────────────────────────────────────────────────────

/// Snapshot protocol version and curve name from the live Rust connection into
/// `he_conn_t` so that `he_conn_get_current_protocol` / `he_conn_get_curve_name`
/// return correct values once the connection reaches Online.
///
/// Must be called while the caller holds the per-client mutex (`he_conn_t::arc_lock`).
fn sync_conn_info(client: &mut he_client_t) {
    let Some(ref mut connection) = client.connection else {
        return;
    };

    // Protocol / cipher / curve are immutable once the handshake has progressed
    // far enough to expose them.  Capture each *exactly once* so that:
    //   * the `*const c_char` handed to C by `he_conn_get_cipher_name` /
    //     `he_conn_get_curve_name` stays valid for the connection's lifetime
    //     instead of being freed and reallocated on every packet (a
    //     use-after-free for any pointer C had already cached), and
    //   * the hot data path performs no per-packet allocation once Online.
    // These fields are reset by `he_client_connect` so a reconnect re-syncs.
    if client.conn.current_protocol == he_connection_protocol_t::HE_CONNECTION_PROTOCOL_NONE {
        // Map wolfssl ProtocolVersion → our C enum
        let proto = match connection.tls_protocol_version() {
            ProtocolVersion::DtlsV1_2 => he_connection_protocol_t::HE_CONNECTION_PROTOCOL_DTLS_1_2,
            ProtocolVersion::DtlsV1_3 => he_connection_protocol_t::HE_CONNECTION_PROTOCOL_DTLS_1_3,
            ProtocolVersion::TlsV1_2 => he_connection_protocol_t::HE_CONNECTION_PROTOCOL_TLS_1_2,
            ProtocolVersion::TlsV1_3 => he_connection_protocol_t::HE_CONNECTION_PROTOCOL_TLS_1_3,
            _ => he_connection_protocol_t::HE_CONNECTION_PROTOCOL_NONE,
        };
        client.conn.current_protocol = proto;
    }

    if client.conn.curve_name.is_none() {
        client.conn.curve_name = connection.current_curve().and_then(|c| CString::new(c).ok());
    }
    if client.conn.cipher_name.is_none() {
        client.conn.cipher_name = connection.current_cipher().and_then(|c| CString::new(c).ok());
    }
}

/// Tear down a connection that hit a fatal wire error: drop the live
/// `Connection` and deliver a single `HE_STATE_DISCONNECTED` transition so the
/// C side observes the death through its normal state-change channel rather
/// than only via a return code on a connection that is silently left for dead.
///
/// Must be called while the per-client lock is held.
fn fatal_disconnect(client: &mut he_client_t) {
    // Already torn down (e.g. lightway-core already signalled Disconnected):
    // just make sure the live Connection is dropped.
    if client.conn.state == he_conn_state_t::HE_STATE_DISCONNECTED {
        client.connection = None;
        return;
    }
    client.conn.state = he_conn_state_t::HE_STATE_DISCONNECTED;
    let conn_ptr: *mut he_conn_t = &mut client.conn;
    let ctx = client.conn.context;
    if let Some(cb) = client.ssl_ctx.state_change_cb {
        // SAFETY: conn_ptr points into the he_client_t allocation (stable for
        // the client's lifetime) and ctx is caller-managed; both stay valid
        // independent of the live Connection. The state value is a plain C enum.
        unsafe { cb(conn_ptr, he_conn_state_t::HE_STATE_DISCONNECTED, ctx) };
    }
    // Drop the live Connection only *after* the callback, matching the ordering
    // in client_disconnect_locked so the connection stays queryable during the
    // transition.
    client.connection = None;
}

// ──────────────────────────────────────────────────────────────────────────────
// Version / misc
// ──────────────────────────────────────────────────────────────────────────────

/// Return a NUL-terminated C string identifying the lightway build.
///
/// The returned pointer is valid for the lifetime of the process.
/// The caller must not free it.
#[unsafe(no_mangle)]
pub extern "C" fn he_lightway_version() -> *const c_char {
    version::LIGHTWAY_VERSION_CSTR.as_ptr()
}

/// Return a NUL-terminated C string with the WolfSSL version in use.
///
/// The returned pointer is valid for the lifetime of the process.
/// The caller must not free it.
#[unsafe(no_mangle)]
pub extern "C" fn he_wolfssl_version() -> *const c_char {
    version::WOLFSSL_VERSION_CSTR.as_ptr()
}

/// Return a static NUL-terminated name for a return code, suitable for logging.
///
/// Takes the raw integer value (not the `he_return_code_t` enum) so that an
/// out-of-range value from C is reported as `"HE_ERR_UNKNOWN"` rather than
/// being reinterpreted as an invalid enum discriminant (which would be UB).
///
/// # Safety
/// Always returns a valid, non-null pointer regardless of the value passed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_return_code_name(code: c_int) -> *const c_char {
    match he_return_code_t::from_repr(code) {
        Some(c) => c.as_cstr() as *const c_char,
        None => c"HE_ERR_UNKNOWN".as_ptr(),
    }
}

/// Return a static NUL-terminated name for a connection protocol.
///
/// Takes the raw integer value (not the `he_connection_protocol_t` enum) so an
/// out-of-range value from C is reported as `"unknown"` rather than triggering
/// UB on an invalid enum discriminant.
///
/// # Safety
/// Always returns a valid, non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_connection_protocol_name(protocol: c_int) -> *const c_char {
    let s: &[u8] = match protocol {
        0 => b"none\0",
        1 => b"DTLS 1.2\0",
        2 => b"DTLS 1.3\0",
        3 => b"TLS 1.2\0",
        4 => b"TLS 1.3\0",
        _ => b"unknown\0",
    };
    // SAFETY: all byte literals above are valid NUL-terminated ASCII.
    unsafe { &*(s.as_ptr() as *const c_char) }
}

// ──────────────────────────────────────────────────────────────────────────────
// Library init / cleanup
// ──────────────────────────────────────────────────────────────────────────────

/// Initialise the Lightway library.  Must be called once before any other
/// `he_*` function.
///
/// # Safety
/// Must only be called from a single thread during process initialisation.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_init() -> he_return_code_t {
    he_return_code_t::HE_SUCCESS
}

/// Clean up resources allocated by `he_init()`.
///
/// # Safety
/// Must be called after all connections have been destroyed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_cleanup() {}

// ──────────────────────────────────────────────────────────────────────────────
// Client lifecycle
// ──────────────────────────────────────────────────────────────────────────────

/// Allocate a new `he_client_t`.
///
/// Returns a heap-allocated pointer. Aborts on allocation failure.
/// The caller must free it with `he_client_destroy`.
///
/// # Safety
/// The returned pointer must be freed with `he_client_destroy`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_client_create() -> *mut he_client_t {
    Box::into_raw(he_client_t::new())
}

/// Free a `he_client_t` previously allocated by `he_client_create`.
///
/// # Safety
/// `client` must be a valid pointer obtained from `he_client_create` and must
/// not be used after this call.
///
/// Destruction is **not** internally serialised against other calls: the
/// per-client lock cannot protect this because the lock lives *inside* the
/// allocation being freed (and the data path reaches it by dereferencing a
/// `*mut he_conn_t` that points into the same allocation). The caller MUST
/// therefore guarantee that every thread which could call any `he_*` function
/// on this client — in particular the data-path calls
/// `he_conn_outside_data_received`, `he_conn_inside_packet_received` and
/// `he_conn_nudge` — has fully quiesced before calling `he_client_destroy`.
/// Calling a data-path function concurrently with (or after) destruction is a
/// use-after-free. In particular, `he_client_destroy` must not be called from
/// within any callback that runs while the per-client mutex is held (e.g. from
/// a state-change callback triggered by `he_client_disconnect`).
///
/// Enforcing this in-library would require a reference-counted handle (so the
/// allocation outlives in-flight calls); that is a deliberate future change.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_client_destroy(client: *mut he_client_t) {
    if !client.is_null() {
        // SAFETY: pointer was created by Box::into_raw in he_client_create.
        unsafe { drop(Box::from_raw(client)) };
    }
}

/// Return a pointer to the `he_conn_t` embedded inside a `he_client_t`.
///
/// The returned pointer is valid for the lifetime of the client and is stable
/// (never moves).  C code can compare it with the `conn` pointer delivered to
/// callbacks to identify which tunnel fired the event.
///
/// # Safety
/// `client` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_client_get_conn(client: *mut he_client_t) -> *mut he_conn_t {
    if client.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: null check above; client is valid and conn is its first field.
    unsafe { &mut (*client).conn as *mut he_conn_t }
}

/// Return a pointer to the `he_ssl_ctx_t` embedded inside a `he_client_t`.
///
/// # Safety
/// `client` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_client_get_ssl_ctx(
    client: *mut he_client_t,
) -> *mut conn::he_ssl_ctx_t {
    if client.is_null() {
        return std::ptr::null_mut();
    }
    // SAFETY: null check above; client is valid for this call.
    unsafe { &mut (*client).ssl_ctx as *mut conn::he_ssl_ctx_t }
}

/// Validate that a client is fully configured and ready to connect.
///
/// # Safety
/// `client` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_client_is_config_valid(
    client: *const he_client_t,
) -> he_return_code_t {
    if client.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; pointer is valid for the call duration.
    let client = unsafe { &*client };
    // Require at least one auth credential
    let has_user_pass = client.conn.username.is_some() && client.conn.password.is_some();
    let has_token = client.conn.auth_token.is_some();
    if !has_user_pass && !has_token {
        return he_return_code_t::HE_ERR_CONF_NOT_SET;
    }
    // Require the outside-write callback (mandatory in he_client_connect).
    if client.ssl_ctx.outside_write_cb.is_none() {
        return he_return_code_t::HE_ERR_CONF_NOT_SET;
    }
    // Require the CA certificate — he_client_connect rejects its absence, so
    // validation must agree or it would report a config as ready that cannot
    // actually connect.
    if client.ssl_ctx.ca_cert.is_none() {
        return he_return_code_t::HE_ERR_CONF_NOT_SET;
    }
    he_return_code_t::HE_SUCCESS
}

/// Initiate the connection to the Lightway server.
///
/// Builds and starts a `lightway-core` `Connection`, wiring the C callbacks
/// to the Rust I/O traits.  The TLS handshake is not yet complete after this
/// returns — the caller must pump `he_conn_outside_data_received` and
/// `he_conn_nudge` until the state-change callback fires `HE_STATE_ONLINE`.
///
/// # Safety
/// `client` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_client_connect(client: *mut he_client_t) -> he_return_code_t {
    // SAFETY: `client` is null-checked and serialised by lock_client; the body
    // runs with the per-client lock held.  ffi_guard prevents a panic (e.g. from
    // lightway-core or a C callback) from unwinding across the C ABI boundary.
    ffi_guard(he_return_code_t::HE_ERR_FAILED, || {
        // SAFETY: lock_client null-checks `client`, serialises access, and
        // rejects re-entrancy before creating the &mut he_client_t.
        match unsafe { lock_client(client, client_connect_locked) } {
            Ok(code) | Err(code) => code,
        }
    })
}

/// Body of [`he_client_connect`], run with the per-client lock held.
fn client_connect_locked(client: &mut he_client_t) -> he_return_code_t {
    // Reject a second connect on an already-live connection: silently
    // overwriting `client.connection` would drop the live tunnel without a
    // graceful goodbye and leak the server-side session.
    if client.connection.is_some() {
        return he_return_code_t::HE_ERR_INVALID_CONN_STATE;
    }

    // ── 1. Validate ────────────────────────────────────────────────────────
    let Some(outside_write_cb) = client.ssl_ctx.outside_write_cb else {
        return he_return_code_t::HE_ERR_CONF_NOT_SET;
    };
    let Some(ref ca_cert_bytes) = client.ssl_ctx.ca_cert else {
        return he_return_code_t::HE_ERR_CONF_NOT_SET;
    };

    // ── 2. Build auth ───────────────────────────────────────────────────────
    let auth = if let (Some(user), Some(pass)) =
        (&client.conn.username, &client.conn.password)
    {
        match (user.to_str(), pass.to_str()) {
            (Ok(u), Ok(p)) => AuthMethod::UserPass {
                user: u.to_owned(),
                password: p.to_owned(),
            },
            _ => return he_return_code_t::HE_ERR_BAD_PARAM,
        }
    } else if let Some(ref token_bytes) = client.conn.auth_token {
        match std::str::from_utf8(token_bytes) {
            Ok(s) => AuthMethod::Token { token: s.to_owned() },
            Err(_) => return he_return_code_t::HE_ERR_BAD_PARAM,
        }
    } else {
        return he_return_code_t::HE_ERR_CONF_NOT_SET;
    };

    // ── 3. Build I/O callbacks ──────────────────────────────────────────────
    let conn_ptr: *mut he_conn_t = &mut client.conn;
    let ctx = client.conn.context;

    let outside_io: OutsideIOSendCallbackArg =
        Arc::new(CffiOutsideIO::new(outside_write_cb, conn_ptr, ctx));

    let inside_io: Option<lightway_core::InsideIOSendCallbackArg<CffiAppState>> =
        client.ssl_ctx.inside_write_cb.map(|cb| {
            let io: Arc<dyn lightway_core::InsideIOSendCallback<CffiAppState> + Send + Sync> =
                Arc::new(CffiInsideIO::new(cb, conn_ptr, ctx));
            io
        });

    let ip_config_cb: lightway_core::ClientIpConfigArg<CffiAppState> =
        Arc::new(CffiIpConfig::new(
            client.ssl_ctx.network_config_ipv4_cb,
            conn_ptr,
            ctx,
        ));

    // ── 4. CA certificate ───────────────────────────────────────────────────
    let root_ca = RootCertificate::PemBuffer(ca_cert_bytes);

    // ── 5. Connection type ──────────────────────────────────────────────────
    let connection_type = match client.ssl_ctx.connection_type {
        he_connection_type_t::HE_CONNECTION_TYPE_DATAGRAM => ConnectionType::Datagram,
        he_connection_type_t::HE_CONNECTION_TYPE_STREAM => ConnectionType::Stream,
    };

    // ── 6. Build the ClientContext then start_connect ───────────────────────
    let ctx_builder =
        match ClientContextBuilder::new(
            connection_type,
            root_ca,
            inside_io,
            ip_config_cb,
            cffi_schedule_tick_cb,
        ) {
            Ok(b) => b,
            Err(_) => return he_return_code_t::HE_ERR_SSL_ERROR,
        };

    let ctx_builder = if client.ssl_ctx.use_chacha20 {
        use lightway_core::Cipher;
        match ctx_builder.with_cipher(Cipher::Chacha20) {
            Ok(b) => b,
            Err(_) => return he_return_code_t::HE_ERR_SSL_ERROR,
        }
    } else {
        ctx_builder
    };

    let ctx_builder = if client.ssl_ctx.enable_expresslane {
        let mut b = ctx_builder.with_expresslane(DEFAULT_EXPRESSLANE_KEYS_ROTATION_INTERVAL);
        if let Some(el_cb) = client.ssl_ctx.expresslane_cb {
            b = b.with_expresslane_cb(CffiExpresslaneCb::create(el_cb, conn_ptr, ctx));
        }
        // When the data path is offloaded, feed the offload's packet counters to
        // the health monitor so it doesn't read core's zeroed counters as loss.
        if let Some(m_cb) = client.ssl_ctx.expresslane_metrics_cb {
            b = b.with_expresslane_metrics(CffiExpresslaneMetrics::create(m_cb, conn_ptr, ctx));
        }
        b
    } else {
        ctx_builder
    };

    let context = ctx_builder.build();

    let outside_mtu = client.conn.outside_mtu as usize;
    let conn_builder = match context.start_connect(
        outside_io,
        outside_mtu,
    ) {
        Ok(b) => b,
        Err(_) => return he_return_code_t::HE_ERR_SSL_ERROR,
    };

    let event_cb = Box::new(CffiEventCallback {
        state_change_cb: client.ssl_ctx.state_change_cb,
        event_cb: client.ssl_ctx.event_cb,
        expresslane_state_change_cb: client.ssl_ctx.expresslane_state_change_cb,
        conn_ptr,
        ctx,
    });

    let conn_builder = conn_builder.with_auth(auth).with_event_cb(event_cb);

    let conn_builder = if let Some(ref sdn) = client.ssl_ctx.server_dn {
        match sdn.to_str() {
            Ok(s) => conn_builder.with_server_domain_name_validation(s),
            Err(_) => return he_return_code_t::HE_ERR_BAD_PARAM,
        }
    } else {
        conn_builder
    };

    let conn_builder = if let Some(ref sni) = client.conn.sni_hostname {
        match sni.to_str() {
            Ok(s) => conn_builder.with_sni_header(s),
            Err(_) => return he_return_code_t::HE_ERR_BAD_PARAM,
        }
    } else {
        conn_builder
    };

    // Offer a post-quantum key-share group when PQC was requested via
    // `he_ssl_ctx_set_use_pqc`. P521MLKEM1024 matches the reference
    // `lightway-client` default and the server's preferred PQC group; when PQC
    // is disabled the handshake stays on the classical groups.
    let conn_builder = if client.ssl_ctx.use_pqc {
        conn_builder.with_pq_crypto(lightway_core::KeyShare::P521MLKEM1024)
    } else {
        conn_builder
    };

    // ── 7. connect() → live Connection  ────────────────────────────────────
    let app_state = CffiAppState {
        nudge_time_cb: client.ssl_ctx.nudge_time_cb,
        conn_ptr,
        ctx,
        ..CffiAppState::default()
    };
    let connection = match conn_builder.connect(app_state) {
        Ok(c) => c,
        Err(_) => {
            return he_return_code_t::HE_ERR_SSL_ERROR;
        }
    };

    client.connection = Some(connection);

    // Fresh connection: clear cached crypto info (written once by
    // sync_conn_info and otherwise never reset) so a reconnect re-captures it,
    // and reflect the configured outside MTU in the "negotiated" field that
    // `he_conn_get_outside_mtu` returns.
    client.conn.current_protocol = he_connection_protocol_t::HE_CONNECTION_PROTOCOL_NONE;
    client.conn.curve_name = None;
    client.conn.cipher_name = None;
    client.conn.outside_mtu_negotiated = client.conn.outside_mtu;

    // `Connection::new()` initialises `state` to `State::Connecting` directly
    // (not via `set_state()`), so the EventCallback is never invoked for the
    // initial Connecting transition.  Synthesise it here so the C-side state
    // field and state-change callback stay consistent with the Rust state.
    //
    // Guard on an actual state change so the callback is not fired spuriously
    // if `he_client_connect()` is called again without a full teardown.
    if client.conn.state != he_conn_state_t::HE_STATE_CONNECTING {
        client.conn.state = he_conn_state_t::HE_STATE_CONNECTING;
        if let Some(cb) = client.ssl_ctx.state_change_cb {
            // SAFETY: conn_ptr and ctx are valid C pointers for the connection
            // lifetime; no Rust data is dereferenced through them by the callback.
            unsafe { cb(conn_ptr, he_conn_state_t::HE_STATE_CONNECTING, ctx) };
        }
    }

    he_return_code_t::HE_SUCCESS
}

/// Gracefully disconnect a client.
///
/// # Safety
/// `client` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_client_disconnect(client: *mut he_client_t) -> he_return_code_t {
    // SAFETY: `client` is null-checked and serialised by lock_client; ffi_guard
    // contains any panic from the goodbye path or a state-change callback.
    ffi_guard(he_return_code_t::HE_ERR_FAILED, || {
        // SAFETY: lock_client null-checks `client`, serialises access, and
        // rejects re-entrancy before creating the &mut he_client_t.
        match unsafe { lock_client(client, client_disconnect_locked) } {
            Ok(code) | Err(code) => code,
        }
    })
}

/// Body of [`he_client_disconnect`], run with the per-client lock held.
fn client_disconnect_locked(client: &mut he_client_t) -> he_return_code_t {
    // Drive a graceful TLS goodbye if the Connection is live.  For an Online
    // connection, `Connection::disconnect()` itself fires StateChanged
    // (Disconnecting → Disconnected) through the EventCallback, which updates
    // `client.conn.state`.  The `already_disconnected` guard below then sees
    // that and skips the manual synthesis, so the C state-change callback is
    // not invoked twice.  The manual path only runs when the core did *not*
    // emit those transitions (e.g. disconnect() returned InvalidState because
    // the handshake was still in progress, or no Connection was ever built).
    if let Some(ref mut connection) = client.connection {
        let _ = connection.disconnect();
    }

    let conn_ptr: *mut he_conn_t = &mut client.conn;
    let ctx = client.conn.context;

    let already_disconnected = matches!(
        client.conn.state,
        he_conn_state_t::HE_STATE_DISCONNECTING | he_conn_state_t::HE_STATE_DISCONNECTED
    );
    if !already_disconnected {
        for new_state in [
            he_conn_state_t::HE_STATE_DISCONNECTING,
            he_conn_state_t::HE_STATE_DISCONNECTED,
        ] {
            client.conn.state = new_state;
            if let Some(cb) = client.ssl_ctx.state_change_cb {
                // SAFETY: conn_ptr and ctx are valid for the connection lifetime;
                // new_state is a plain C enum value.
                unsafe { cb(conn_ptr, new_state, ctx) };
            }
        }
    }

    client.connection = None;
    he_return_code_t::HE_SUCCESS
}

// ──────────────────────────────────────────────────────────────────────────────
// SSL-context setters
// ──────────────────────────────────────────────────────────────────────────────

/// Set the connection-state-change callback.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_state_change_cb(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    cb: conn::he_state_change_cb_t,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).state_change_cb = Some(cb) };
    he_return_code_t::HE_SUCCESS
}

/// Set the inside-write (decrypted TUN packet ready) callback.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_inside_write_cb(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    cb: conn::he_inside_write_cb_t,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).inside_write_cb = Some(cb) };
    he_return_code_t::HE_SUCCESS
}

/// Set the outside-write (encrypted wire packet ready) callback.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_outside_write_cb(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    cb: conn::he_outside_write_cb_t,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).outside_write_cb = Some(cb) };
    he_return_code_t::HE_SUCCESS
}

/// Set the IPv4 network-config callback.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_network_config_ipv4_cb(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    cb: conn::he_network_config_ipv4_cb_t,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).network_config_ipv4_cb = Some(cb) };
    he_return_code_t::HE_SUCCESS
}

/// Set the server-config callback.
///
/// Accepted for source/ABI compatibility, but this shim does not currently
/// deliver server-config data, so the callback is stored and never invoked.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_server_config_cb(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    cb: conn::he_server_config_cb_t,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).server_config_cb = Some(cb) };
    he_return_code_t::HE_SUCCESS
}

/// Set the nudge-time callback.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_nudge_time_cb(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    cb: conn::he_nudge_time_cb_t,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).nudge_time_cb = Some(cb) };
    he_return_code_t::HE_SUCCESS
}

/// Set the connection-event callback.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_event_cb(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    cb: conn::he_event_cb_t,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).event_cb = Some(cb) };
    he_return_code_t::HE_SUCCESS
}

/// Set the username/password authentication callback (server role).
///
/// Accepted for source/ABI compatibility with the OSS C library.  This is a
/// client-only shim, so the callback is stored but never invoked.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_auth_cb(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    cb: conn::he_auth_cb_t,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).auth_cb = Some(cb) };
    he_return_code_t::HE_SUCCESS
}

/// Set the auth-token callback (server role).
///
/// Accepted for source/ABI compatibility with the OSS C library.  This is a
/// client-only shim, so the callback is stored but never invoked.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_auth_token_cb(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    cb: conn::he_auth_token_cb_t,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).auth_token_cb = Some(cb) };
    he_return_code_t::HE_SUCCESS
}

/// Set the auth-buffer callback (server role).
///
/// Accepted for source/ABI compatibility with the OSS C library.  This is a
/// client-only shim, so the callback is stored but never invoked.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_auth_buf_cb(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    cb: conn::he_auth_buf_cb_t,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).auth_buf_cb = Some(cb) };
    he_return_code_t::HE_SUCCESS
}

/// Set the populate-network-config callback (server role).
///
/// Accepted for source/ABI compatibility with the OSS C library.  This is a
/// client-only shim, so the callback is stored but never invoked.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_populate_network_config_ipv4_cb(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    cb: conn::he_populate_network_config_ipv4_cb_t,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).populate_network_config_ipv4_cb = Some(cb) };
    he_return_code_t::HE_SUCCESS
}

/// Set the PMTUD state-change callback.
///
/// NOTE: PMTUD is not currently driven by this shim, so this callback is stored
/// but never invoked.  Accepted for ABI compatibility; see
/// `he_conn_get_effective_pmtu`.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_pmtud_state_change_cb(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    cb: conn::he_pmtud_state_change_cb_t,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).pmtud_state_change_cb = Some(cb) };
    he_return_code_t::HE_SUCCESS
}

/// Set the PMTUD timer callback.
///
/// NOTE: PMTUD is not currently driven by this shim, so this callback is stored
/// but never invoked.  Accepted for ABI compatibility.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_pmtud_time_cb(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    cb: conn::he_pmtud_time_cb_t,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).pmtud_time_cb = Some(cb) };
    he_return_code_t::HE_SUCCESS
}

/// Set the CA certificate for server verification.
///
/// `ca_cert` is copied; the caller retains ownership of the buffer.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
/// `ca_cert` must point to `length` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_ca(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    ca_cert: *const u8,
    length: usize,
) -> he_return_code_t {
    if ssl_ctx.is_null() || ca_cert.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null checks above; ca_cert points to `length` readable bytes
    // as guaranteed by the C API contract.
    let bytes = unsafe { std::slice::from_raw_parts(ca_cert, length) };
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).ca_cert = Some(bytes.to_vec()) };
    he_return_code_t::HE_SUCCESS
}

/// Set the expected server Distinguished Name for certificate checking.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
/// `server_dn` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_server_dn(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    server_dn: *const c_char,
) -> he_return_code_t {
    if ssl_ctx.is_null() || server_dn.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; server_dn is a valid NUL-terminated C string
    // as required by the function's documented contract.
    let s = unsafe { CStr::from_ptr(server_dn) };
    // The DN is later handed to lightway-core as &str, so validate UTF-8 here.
    // `s` is already a CStr (NUL-terminated, no interior NUL), so clone it with
    // to_owned() rather than re-scanning and reallocating via CString::new.
    match s.to_str() {
        Ok(_) => {
            // SAFETY: null check above; ssl_ctx is valid for this call.
            unsafe { (*ssl_ctx).server_dn = Some(s.to_owned()) };
            he_return_code_t::HE_SUCCESS
        }
        Err(_) => he_return_code_t::HE_ERR_BAD_PARAM,
    }
}

/// Enable or disable post-quantum cryptography.
///
/// When enabled, the client offers a post-quantum key-share group
/// (P521MLKEM1024) during the TLS handshake; when disabled, the handshake uses
/// the classical key-share groups. The group matches the reference Lightway
/// client default and the server's preferred PQC group.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_use_pqc(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    use_pqc: bool,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).use_pqc = use_pqc };
    he_return_code_t::HE_SUCCESS
}

/// Enable or disable ChaCha20 cipher preference.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_use_chacha20(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    use_chacha20: bool,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).use_chacha20 = use_chacha20 };
    he_return_code_t::HE_SUCCESS
}

/// Set the connection transport type (datagram or stream).
///
/// Takes the raw integer value so that an out-of-range value from C is rejected
/// with `HE_ERR_BAD_PARAM` rather than stored as an invalid enum discriminant
/// (which would be UB when later matched on the data path).
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_connection_type(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    connection_type: c_int,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    let connection_type = match connection_type {
        0 => he_connection_type_t::HE_CONNECTION_TYPE_DATAGRAM,
        1 => he_connection_type_t::HE_CONNECTION_TYPE_STREAM,
        _ => return he_return_code_t::HE_ERR_BAD_PARAM,
    };
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).connection_type = connection_type };
    he_return_code_t::HE_SUCCESS
}

/// Enable the ExpressLane fast-path data plane for this connection.
///
/// Must be called before `he_client_connect`. Only effective on DTLS (datagram)
/// connections; silently ignored for TLS (stream) connections.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_enable_expresslane(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    enable: bool,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).enable_expresslane = enable };
    he_return_code_t::HE_SUCCESS
}

/// Register the callback that receives fresh ExpressLane key material.
///
/// Called whenever `lightway-core` completes an ExpressLane key exchange.
/// The `he_expresslane_keys_t` passed to the callback is stack-allocated and
/// valid only for the duration of the call — copy it if you need to retain it.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_expresslane_cb(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    cb: conn::he_expresslane_cb_t,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).expresslane_cb = Some(cb) };
    he_return_code_t::HE_SUCCESS
}

/// Register the callback for ExpressLane operational-state changes.
///
/// Fired with `HE_EXPRESSLANE_STATE_ACTIVE` once the fast path is fully
/// established, and with `HE_EXPRESSLANE_STATE_DEGRADED` or
/// `HE_EXPRESSLANE_STATE_INACTIVE` if it later falls back.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_expresslane_state_change_cb(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    cb: conn::he_expresslane_state_change_cb_t,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).expresslane_state_change_cb = Some(cb) };
    he_return_code_t::HE_SUCCESS
}

/// Register the callback that supplies offloaded ExpressLane packet counters
/// to the health monitor.
///
/// Install this whenever the ExpressLane data path is offloaded (decrypt/encrypt
/// via `he_expresslane_decrypt`/`he_expresslane_encrypt` instead of
/// `he_conn_outside_data_received`/`he_conn_inside_packet_received`). Without it,
/// `lightway-core`'s own packet counters stay at zero while the peer reports the
/// real numbers, so the health monitor sees ~100% loss and degrades the fast
/// path back to D/TLS. See `he_expresslane_metrics_cb_t`.
///
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_expresslane_metrics_cb(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    cb: conn::he_expresslane_metrics_cb_t,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; ssl_ctx is valid for this call.
    unsafe { (*ssl_ctx).expresslane_metrics_cb = Some(cb) };
    he_return_code_t::HE_SUCCESS
}

// ──────────────────────────────────────────────────────────────────────────────
// Connection setters / getters
// ──────────────────────────────────────────────────────────────────────────────

/// Set the username for password-based authentication.
///
/// # Safety
/// `conn` must be a valid non-null pointer.
/// `username` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_set_username(
    conn: *mut he_conn_t,
    username: *const c_char,
) -> he_return_code_t {
    if conn.is_null() || username.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; username is a valid NUL-terminated C string.
    let s = unsafe { CStr::from_ptr(username) };
    match CString::new(s.to_bytes()) {
        Ok(cs) => {
            // SAFETY: null check above; conn is valid for this call.
            unsafe { (*conn).username = Some(cs) };
            he_return_code_t::HE_SUCCESS
        }
        Err(_) => he_return_code_t::HE_ERR_BAD_PARAM,
    }
}

/// Set the password for password-based authentication.
///
/// # Safety
/// `conn` must be a valid non-null pointer.
/// `password` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_set_password(
    conn: *mut he_conn_t,
    password: *const c_char,
) -> he_return_code_t {
    if conn.is_null() || password.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; password is a valid NUL-terminated C string.
    let s = unsafe { CStr::from_ptr(password) };
    match CString::new(s.to_bytes()) {
        Ok(cs) => {
            // SAFETY: null check above; conn is valid for this call.
            unsafe { (*conn).password = Some(cs) };
            he_return_code_t::HE_SUCCESS
        }
        Err(_) => he_return_code_t::HE_ERR_BAD_PARAM,
    }
}

/// Set an opaque auth token.
///
/// `token` is copied; the caller retains ownership of the buffer.
///
/// # Safety
/// `conn` must be a valid non-null pointer.
/// `token` must point to `length` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_set_auth_token(
    conn: *mut he_conn_t,
    token: *const u8,
    length: usize,
) -> he_return_code_t {
    if conn.is_null() || token.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null checks above; token points to `length` readable bytes.
    let bytes = unsafe { std::slice::from_raw_parts(token, length) };
    // SAFETY: null check above; conn is valid for this call.
    unsafe { (*conn).auth_token = Some(bytes.to_vec()) };
    he_return_code_t::HE_SUCCESS
}

/// Set the SNI hostname for TLS server-name indication.
///
/// # Safety
/// `conn` must be a valid non-null pointer.
/// `hostname` must be a valid NUL-terminated C string.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_set_sni_hostname(
    conn: *mut he_conn_t,
    hostname: *const c_char,
) -> he_return_code_t {
    if conn.is_null() || hostname.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; hostname is a valid NUL-terminated C string.
    let s = unsafe { CStr::from_ptr(hostname) };
    match CString::new(s.to_bytes()) {
        Ok(cs) => {
            // SAFETY: null check above; conn is valid for this call.
            unsafe { (*conn).sni_hostname = Some(cs) };
            he_return_code_t::HE_SUCCESS
        }
        Err(_) => he_return_code_t::HE_ERR_BAD_PARAM,
    }
}

/// Set the outside (wire) MTU.
///
/// # Safety
/// `conn` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_set_outside_mtu(
    conn: *mut he_conn_t,
    mtu: u16,
) -> he_return_code_t {
    if conn.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; conn is valid for this call.
    unsafe { (*conn).outside_mtu = mtu };
    he_return_code_t::HE_SUCCESS
}

/// Store an opaque context pointer that is passed back to all callbacks.
///
/// # Safety
/// `conn` must be a valid non-null pointer.
/// `context` lifetime is the caller's responsibility.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_set_context(
    conn: *mut he_conn_t,
    context: *mut c_void,
) -> he_return_code_t {
    if conn.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; conn is valid for this call.
    unsafe { (*conn).context = context };
    he_return_code_t::HE_SUCCESS
}

/// Get the current keepalive nudge interval in milliseconds.
///
/// Returns 0 if `conn` is null.
///
/// # Safety
/// `conn` must be a valid non-null pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_get_nudge_time(conn: *const he_conn_t) -> i32 {
    if conn.is_null() {
        return 0;
    }
    // SAFETY: null check above; conn is valid for this call.
    unsafe { (*conn).nudge_time_ms }
}

/// Get the negotiated outside MTU.
///
/// # Safety
/// `conn` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_get_outside_mtu(conn: *const he_conn_t) -> u16 {
    if conn.is_null() {
        return 0;
    }
    // SAFETY: null check above; conn is valid for this call.
    unsafe { (*conn).outside_mtu_negotiated }
}

/// Get the effective path MTU determined by PMTUD.
///
/// NOTE: this shim does not currently drive Path MTU Discovery (the pinned
/// `lightway-core` requires a PMTUD timer that is not wired here, and exposes no
/// effective-MTU accessor), so this always returns 0.  Retained for ABI
/// compatibility; treat 0 as "PMTUD not available".
///
/// # Safety
/// `conn` must be a valid non-null pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_get_effective_pmtu(conn: *const he_conn_t) -> u16 {
    if conn.is_null() {
        return 0;
    }
    // SAFETY: null check above; conn is valid for this call.
    unsafe { (*conn).effective_pmtu }
}

/// Get the negotiated connection protocol.
///
/// # Safety
/// `conn` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_get_current_protocol(
    conn: *const he_conn_t,
) -> he_connection_protocol_t {
    if conn.is_null() {
        return he_connection_protocol_t::HE_CONNECTION_PROTOCOL_NONE;
    }
    // SAFETY: null check above; conn is valid for this call.
    unsafe { (*conn).current_protocol }
}

/// Get the negotiated cipher suite name, or null if not yet negotiated.
///
/// The value is captured once when the handshake exposes it and is then stable
/// for the connection's lifetime, so the returned pointer remains valid. This
/// getter takes no lock (and so is safe to call from a callback), but for that
/// reason it should be read after the `HE_STATE_ONLINE` transition, by which
/// point the value is fixed.
///
/// # Safety
/// `conn` must be a valid non-null pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_get_cipher_name(conn: *const he_conn_t) -> *const c_char {
    if conn.is_null() {
        return std::ptr::null();
    }
    // SAFETY: null check above; conn is valid for this call.
    match unsafe { &(*conn).cipher_name } {
        Some(cs) => cs.as_ptr(),
        None => std::ptr::null(),
    }
}

/// Get the TLS curve name, or null if not yet negotiated.
///
/// As with `he_conn_get_cipher_name`, the value is captured once and stable for
/// the connection's lifetime; read it after `HE_STATE_ONLINE`.
///
/// # Safety
/// `conn` must be a valid non-null pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_get_curve_name(conn: *const he_conn_t) -> *const c_char {
    if conn.is_null() {
        return std::ptr::null();
    }
    // SAFETY: null check above; conn is valid for this call.
    match unsafe { &(*conn).curve_name } {
        Some(cs) => cs.as_ptr(),
        None => std::ptr::null(),
    }
}

/// Get the current session ID as a little-endian `uint64_t`.
///
/// Returns `0` if no connection is active yet, if `client` is null, or if
/// called re-entrantly from within a callback that already holds the lock.
///
/// # Safety
/// `client` must be null or a valid pointer from `he_client_create`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_get_session_id(client: *const he_client_t) -> u64 {
    ffi_guard(0, || {
        // SAFETY: lock_client null-checks and serialises access; the cast to
        // *mut is sound because we only read the client under the lock.
        unsafe {
            lock_client(client as *mut he_client_t, |client| {
                match client.connection {
                    // SessionId is a [u8; 8] newtype; read it via its safe
                    // accessor and interpret the bytes as little-endian.
                    Some(ref conn) => u64::from_le_bytes(*conn.session_id().as_bytes()),
                    None => 0,
                }
            })
        }
        .unwrap_or(0)
    })
}

/// Classify a raw inbound datagram by its cleartext 16-byte lightway wire
/// header, without any connection state or decryption.
///
/// This is the demux for an ExpressLane data-plane offload: an
/// `HE_PACKET_KIND_EXPRESSLANE` datagram can be decrypted directly with
/// `he_expresslane_decrypt` after stripping the returned `*header_len` bytes
/// (keyed by the returned `session_id`), while an `HE_PACKET_KIND_CONTROL`
/// datagram must be handed unchanged to `he_conn_outside_data_received`.
///
/// Classification is a pure function of the datagram bytes and delegates to
/// `lightway-core`'s own header parser, so it stays correct across wire-format
/// changes. It does NOT run any outside/obfuscation plugins, so it is only
/// valid when no such plugin is configured (this shim configures none).
///
/// On success `*kind` is always written. For `CONTROL`/`EXPRESSLANE`,
/// `session_id` (if non-null) receives the 8-byte session id and `*header_len`
/// (if non-null) receives the header size (16). A datagram that is not a valid
/// lightway frame yields `HE_PACKET_KIND_UNDECIDABLE` and still returns
/// `HE_SUCCESS` — classification succeeded; the packet simply isn't ours.
///
/// # Safety
/// `packet` must point to `len` readable bytes (may be null iff `len == 0`).
/// `kind` must be a valid non-null pointer. `session_id`, if non-null, must be
/// writable for 8 bytes. `header_len`, if non-null, must be writable.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_identify_packet(
    packet: *const u8,
    len: usize,
    kind: *mut he_packet_kind_t,
    session_id: *mut u8,
    header_len: *mut usize,
) -> he_return_code_t {
    if kind.is_null() || (packet.is_null() && len > 0) {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // Default every out-param before the fallible body, so any return (incl. a
    // panic mapped to HE_ERR_FAILED, or the UNDECIDABLE arm) leaves safe values
    // rather than the caller's prior/uninitialised stack contents.
    // SAFETY: kind is non-null (checked); session_id/header_len are written
    // only when non-null, per the documented contract.
    unsafe {
        *kind = he_packet_kind_t::HE_PACKET_KIND_UNDECIDABLE;
        if !session_id.is_null() {
            std::ptr::write_bytes(session_id, 0, 8);
        }
        if !header_len.is_null() {
            *header_len = 0;
        }
    }
    // A datagram shorter than the 16-byte header can't be a lightway frame, so
    // leave it Undecidable (defaulted above) without allocating or parsing.
    // This also guarantees the read below sees a non-null `packet` valid for
    // WIRE_SIZE bytes (a null packet only reaches here with len == 0).
    if len < Header::WIRE_SIZE {
        return he_return_code_t::HE_SUCCESS;
    }
    ffi_guard(he_return_code_t::HE_ERR_FAILED, || {
        // Only the header window is needed; copy it into a BytesMut for the
        // parser (which delegates to lightway-core, the wire-format authority).
        let mut buf = BytesMut::with_capacity(Header::WIRE_SIZE);
        // SAFETY: len >= WIRE_SIZE (checked above) and packet is non-null, so
        // it is valid for WIRE_SIZE readable bytes.
        buf.extend_from_slice(unsafe { std::slice::from_raw_parts(packet, Header::WIRE_SIZE) });
        // A frame that fails to parse keeps the Undecidable / zero defaults
        // written above.
        if let Ok(hdr) = Header::try_from_wire(&mut buf) {
            // SAFETY: kind is non-null (checked above).
            unsafe {
                *kind = if hdr.expresslane_data {
                    he_packet_kind_t::HE_PACKET_KIND_EXPRESSLANE
                } else {
                    he_packet_kind_t::HE_PACKET_KIND_CONTROL
                };
            }
            if !session_id.is_null() {
                // SAFETY: caller guarantees session_id is writable for 8 bytes.
                unsafe {
                    std::ptr::copy_nonoverlapping(hdr.session.as_bytes().as_ptr(), session_id, 8)
                };
            }
            if !header_len.is_null() {
                // SAFETY: caller guarantees header_len is writable.
                unsafe { *header_len = Header::WIRE_SIZE };
            }
        }
        he_return_code_t::HE_SUCCESS
    })
}

/// Build the 16-byte cleartext lightway wire header to prepend to an
/// ExpressLane data datagram produced by `he_expresslane_encrypt`. The header
/// carries the connection's protocol version (fixed for a client), the
/// caller-supplied `session_id`, `expresslane_data = 1`, and
/// `aggressive_mode = 0`.
///
/// # Why the caller supplies `session_id`
/// The offload diverts inbound ExpressLane datagrams straight to
/// `he_expresslane_decrypt`, so `lightway-core` never observes their outer
/// header. If the server rotates the session id and the echo arrives only on
/// ExpressLane traffic, the connection's own `session_id()` lags behind — using
/// it here would keep emitting the stale id and the rotation would never
/// complete. The offload is the authority for the ExpressLane session id, so it
/// passes the current one: initially the id from the `he_expresslane_cb_t` key
/// callback, then updated whenever an inbound ExpressLane datagram's header
/// (via `he_conn_identify_packet`) carries a different, successfully-decrypted
/// session id. (Adopt a new id only AFTER `he_expresslane_decrypt` succeeds, so
/// a forged header cannot steer egress.) The DTLS control channel converges
/// independently — the server tolerates a transient session-id mismatch on
/// control packets — so this only governs the ExpressLane egress framing.
///
/// Returns:
/// - `HE_ERR_NULL_POINTER` if `out`, `session_id`, or `client` is null.
/// - `HE_ERR_BAD_PARAM` if `session_id` is the reserved all-zero / rejected
///   sentinel (a header carrying it is unroutable).
/// - `HE_ERR_INVALID_CONN_STATE` if no connection is active yet, or if called
///   re-entrantly from within a callback that already holds the per-client lock.
///
/// # Safety
/// `client` must be null or a valid pointer from `he_client_create`.
/// `session_id` must point to 8 readable bytes. `out` must be writable for 16
/// bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_build_expresslane_header(
    client: *const he_client_t,
    session_id: *const u8,
    out: *mut u8,
) -> he_return_code_t {
    // Check all null pointers first so HE_ERR_NULL_POINTER always takes
    // precedence over the reserved-session HE_ERR_BAD_PARAM check below (a null
    // `client` is otherwise only caught later, inside lock_client).
    if out.is_null() || session_id.is_null() || client.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: session_id is non-null (checked) and points to 8 readable bytes
    // per the documented contract.
    let sid_bytes: [u8; 8] = unsafe { std::slice::from_raw_parts(session_id, 8) }
        .try_into()
        .expect("slice has exactly 8 bytes");
    let session = SessionId::from_const(sid_bytes);
    // A header carrying the reserved (unassigned / rejected) session is
    // unroutable; reject it rather than emit a packet the peer would drop.
    if session.is_reserved() {
        return he_return_code_t::HE_ERR_BAD_PARAM;
    }
    ffi_guard(he_return_code_t::HE_ERR_FAILED, || {
        // SAFETY: lock_client null-checks and serialises access; the cast to
        // *mut is sound because we only read the connection under the lock.
        let result = unsafe {
            lock_client(client as *mut he_client_t, |client| {
                let Some(ref conn) = client.connection else {
                    return Err(he_return_code_t::HE_ERR_INVALID_CONN_STATE);
                };
                let hdr = Header {
                    // For a client, tunnel_protocol_version is fixed at connect
                    // and equals the version lightway-core stamps on egress.
                    version: conn.tunnel_protocol_version(),
                    aggressive_mode: false,
                    expresslane_data: true,
                    session,
                };
                let mut bm = BytesMut::with_capacity(Header::WIRE_SIZE);
                hdr.append_to_wire(&mut bm);
                Ok(bm)
            })
        };
        match result {
            // `append_to_wire` always writes exactly WIRE_SIZE bytes; the guard
            // makes that a checked precondition of the copy rather than an
            // assumption, so a future change that wrote fewer bytes fails fast
            // instead of copying uninitialised memory across the FFI boundary.
            Ok(Ok(bm)) if bm.len() >= Header::WIRE_SIZE => {
                // SAFETY: out is non-null (checked) and writable for 16 bytes
                // per the documented contract; `bm` holds >= WIRE_SIZE
                // initialised bytes (guard above) and is a distinct buffer.
                unsafe { std::ptr::copy_nonoverlapping(bm.as_ptr(), out, Header::WIRE_SIZE) };
                he_return_code_t::HE_SUCCESS
            }
            Ok(Ok(_)) => he_return_code_t::HE_ERR_FAILED,
            Ok(Err(code)) | Err(code) => code,
        }
    })
}

/// Rotate the ExpressLane send key if the rotation interval has elapsed.
///
/// `lightway-core` normally rotates the ExpressLane key off the back of
/// outbound *inside* traffic (`Connection::inside_data_received`) and off an
/// inbound peer `ExpresslaneConfig`. A data-plane offload bypasses
/// `he_conn_inside_packet_received` for every ExpressLane packet, so on a
/// long-lived, effectively one-directional offloaded egress flow neither
/// trigger fires and the send key is never rotated past its interval. The
/// always-on nudge/keepalive tick does not rotate either.
///
/// Call this once per nudge cycle (next to `he_conn_nudge`) to restore the
/// interval-bounded rotation. It is internally gated by the connection's
/// `time_to_rotate_key()` check, so it is a cheap no-op until the interval
/// elapses and only rotates — sending a single `ExpresslaneConfig` frame —
/// when actually due. A `degraded`/`not-supported` connection is treated as
/// "nothing to rotate" and reported as success. When a rotation is initiated,
/// the value returned by `he_conn_get_nudge_time()` is refreshed to reflect
/// the scheduled key-share retransmit deadline, so a caller that re-reads it
/// after this call wakes in time to drive the retransmit.
///
/// A connection in any state other than `Online` (before it, or after —
/// disconnecting/disconnected) is also a success no-op; rotation only ever
/// happens while `Online`. The pre-`Online` case is the one that matters in
/// practice, because `he_conn_nudge` must also be driven during the handshake:
/// with `last_key_rotation` still unset, a pre-`Online` call would otherwise
/// burn the very first rotation on an `ExpresslaneConfig` the peer cannot
/// receive yet, and the timestamp it sets would suppress the activation-time
/// initial key share at `State::Online` for a full rotation interval — leaving
/// the fast path without keys.
///
/// Returns:
/// - `HE_ERR_NULL_POINTER` for a null `conn`.
/// - `HE_ERR_INVALID_CONN_STATE` if no connection is active yet, or if called
///   re-entrantly from within a callback that already holds the per-client lock.
/// - `HE_SUCCESS` otherwise (including every no-op case above).
///
/// # Safety
/// `conn` must be null or a pointer obtained from `he_client_get_conn()` on a
/// client returned by `he_client_create()` that has not been destroyed. Do not
/// call re-entrantly from within a callback that already holds the per-client
/// lock.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_expresslane_rotate_if_due(conn: *mut he_conn_t) -> he_return_code_t {
    ffi_guard(he_return_code_t::HE_ERR_FAILED, || {
        if conn.is_null() {
            return he_return_code_t::HE_ERR_NULL_POINTER;
        }
        // SAFETY: conn is non-null (checked above) and carries the client
        // back-pointer set by he_client_t::new(); with_client recovers and locks
        // the owning client before handing out the &mut.
        match unsafe {
            with_client(conn, |client| -> Result<(), he_return_code_t> {
                let Some(ref mut connection) = client.connection else {
                    return Err(he_return_code_t::HE_ERR_INVALID_CONN_STATE);
                };
                // Not Online (pre-handshake or tearing down): rotating now would
                // consume the first time_to_rotate_key() pass on an unsendable
                // config and suppress the activation-time initial key share (see
                // doc comment). Treat as "not due yet", like any early wake-up.
                if connection.state() != State::Online {
                    return Ok(());
                }
                // Self-gated by time_to_rotate_key(); the only error it returns is
                // "expresslane degraded", a benign no-op for a periodic caller.
                let _ = connection.rotate_expresslane_key();
                // A rotation schedules a key-share retransmit tick; refresh the
                // cached nudge_time_ms so the caller's next
                // he_conn_get_nudge_time() reflects that short deadline instead
                // of overwriting the wake-up hint with a stale/zero value.
                let now = std::time::Instant::now();
                client.conn.nudge_time_ms =
                    nudge_ms_until(connection.app_state().earliest_tick_deadline(), now);
                Ok(())
            })
        } {
            Ok(Ok(())) => he_return_code_t::HE_SUCCESS,
            Ok(Err(code)) | Err(code) => code,
        }
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// Data path
// ──────────────────────────────────────────────────────────────────────────────

/// Recover the owning [`he_client_t`] from a `*mut he_conn_t` and run `f` with
/// an exclusive reference under the per-client lock (via [`lock_client`]).
///
/// Returns `Err(HE_ERR_FAILED)` if `conn` is null or the back-pointer has not
/// been initialised, and `Err(HE_ERR_INVALID_CONN_STATE)` for a re-entrant call
/// from within a callback (see [`lock_client`]).
///
/// # Safety
/// `conn` must be a valid, non-null pointer to a `he_conn_t` whose
/// `client_ptr` field was set by `he_client_t::new()` and has not been freed.
/// `f` must not let any reference derived from `&mut he_client_t` escape the
/// closure, because the mutex guard is released when this function returns.
#[inline]
unsafe fn with_client<F, R>(conn: *mut he_conn_t, f: F) -> Result<R, he_return_code_t>
where
    F: FnOnce(&mut he_client_t) -> R,
{
    if conn.is_null() {
        return Err(he_return_code_t::HE_ERR_FAILED);
    }
    // SAFETY: conn is non-null (checked above) and valid per caller contract.
    let client_ptr = unsafe { (*conn).client_ptr };
    if client_ptr.is_null() {
        return Err(he_return_code_t::HE_ERR_FAILED);
    }
    // SAFETY: client_ptr is the non-null owning allocation; lock_client clones
    // the lock before creating the &mut, and rejects re-entrancy.
    unsafe { lock_client(client_ptr, f) }
}


/// Feed an encrypted packet received from the wire into the connection.
///
/// The decrypted inner payload will be returned via `inside_write_cb`.
///
/// # Safety
/// `conn` and `buffer` must be valid non-null pointers.
/// `buffer` must point to `length` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_outside_data_received(
    conn: *mut he_conn_t,
    buffer: *mut u8,
    length: usize,
) -> he_return_code_t {
    // ffi_guard: this path parses attacker-controlled wire bytes; contain any
    // panic in lightway-core/wolfSSL rather than aborting the whole process.
    ffi_guard(he_return_code_t::HE_ERR_FAILED, || {
        if conn.is_null() || buffer.is_null() {
            return he_return_code_t::HE_ERR_NULL_POINTER;
        }
        // SAFETY: null check above; buffer points to `length` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(buffer, length) };
        // lightway-core consumes an owned, growable buffer (it decrypts/parses
        // in place), so a per-packet copy here is unavoidable with this API.
        let mut buf = BytesMut::from(bytes);
        // SAFETY: conn is non-null (checked above) and points to a he_conn_t whose
        // client_ptr back-pointer was initialised by he_client_t::new().
        // sync_conn_info runs inside the closure, under the lock.
        match unsafe {
            with_client(conn, |client| {
                let Some(ref mut connection) = client.connection else {
                    return he_return_code_t::HE_ERR_INVALID_CONN_STATE;
                };
                // Use the live connection's transport type rather than the
                // mutable ssl_ctx copy, which a setter could change after
                // connect and leave disagreeing with the actual connection.
                let connection_type = connection.connection_type();
                let pkt = OutsidePacket::Wire(&mut buf, connection_type);
                let mut fatal = false;
                let rc = match connection.outside_data_received(pkt) {
                    Ok(_) => he_return_code_t::HE_SUCCESS,
                    Err(e) if e.is_fatal(connection_type) => {
                        fatal = true;
                        he_return_code_t::HE_ERR_FAILED
                    }
                    Err(_) => he_return_code_t::HE_SUCCESS,
                };
                // A fatal wire error means the tunnel is dead; tear it down and
                // signal the C side instead of leaving a dead connection that
                // every subsequent call would keep hitting.
                if fatal {
                    fatal_disconnect(client);
                } else {
                    sync_conn_info(client);
                }
                rc
            })
        } {
            Ok(r) | Err(r) => r,
        }
    })
}

/// Feed a plaintext inner packet into the connection for encryption and
/// transmission to the server.
///
/// The encrypted payload will be returned via `outside_write_cb`.
///
/// # Safety
/// `conn` and `packet` must be valid non-null pointers.
/// `packet` must point to `length` readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_inside_packet_received(
    conn: *mut he_conn_t,
    packet: *mut u8,
    length: usize,
) -> he_return_code_t {
    ffi_guard(he_return_code_t::HE_ERR_FAILED, || {
        if conn.is_null() || packet.is_null() {
            return he_return_code_t::HE_ERR_NULL_POINTER;
        }
        // SAFETY: null check above; packet points to `length` readable bytes.
        let bytes = unsafe { std::slice::from_raw_parts(packet, length) };
        // Owned, growable buffer required by lightway-core; copy is unavoidable.
        let mut buf = BytesMut::from(bytes);
        // SAFETY: conn is non-null (checked above) and points to a he_conn_t whose
        // client_ptr back-pointer was initialised by he_client_t::new().
        // sync_conn_info runs inside the closure, under the lock.
        match unsafe {
            with_client(conn, |client| {
                let Some(ref mut connection) = client.connection else {
                    return he_return_code_t::HE_ERR_INVALID_CONN_STATE;
                };
                let rc = match connection.inside_data_received(&mut buf) {
                    Ok(()) => he_return_code_t::HE_SUCCESS,
                    Err(lightway_core::ConnectionError::InvalidState) => {
                        he_return_code_t::HE_ERR_INVALID_CONN_STATE
                    }
                    Err(_) => he_return_code_t::HE_ERR_FAILED,
                };
                sync_conn_info(client);
                rc
            })
        } {
            Ok(r) | Err(r) => r,
        }
    })
}

/// Remaining milliseconds from `now` until `deadline`, saturating; 0 when no
/// deadline is pending.
fn nudge_ms_until(deadline: Option<std::time::Instant>, now: std::time::Instant) -> i32 {
    deadline
        .map(|t| {
            let remaining = t.saturating_duration_since(now);
            remaining.as_millis().min(i32::MAX as u128) as i32
        })
        .unwrap_or(0)
}

/// Nudge the connection — retransmit handshake messages if the keepalive
/// timer has expired, and dispatch any due payload ticks (ExpressLane
/// key-share retransmits, codec retransmits) with their original tick type.
///
/// # Safety
/// `conn` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_nudge(conn: *mut he_conn_t) -> he_return_code_t {
    // SAFETY: conn (when non-null) points to a he_conn_t whose client_ptr
    // back-pointer was initialised by he_client_t::new().  All reads/writes to
    // client state (including conn.nudge_time_ms) happen inside the closure,
    // under the per-client mutex (he_conn_t::arc_lock).
    ffi_guard(he_return_code_t::HE_ERR_FAILED, || {
        if conn.is_null() {
            return he_return_code_t::HE_ERR_NULL_POINTER;
        }
        // SAFETY: conn is non-null (checked above) and carries the client
        // back-pointer set by he_client_t::new(); with_client recovers and locks
        // the owning client before handing out the &mut.
        match unsafe {
            with_client(conn, |client| {
                // Capture now after acquiring the lock so tick decisions and
                // nudge_ms computations reflect a consistent, current instant.
                let now = std::time::Instant::now();
                {
                    let Some(ref mut connection) = client.connection else {
                        return Err(he_return_code_t::HE_ERR_INVALID_CONN_STATE);
                    };
                    let should_tick =
                        connection.app_state().next_tick.is_none_or(|t| now >= t);
                    if should_tick {
                        connection.app_state_mut().next_tick = None;
                        match connection.tick(TickType::ConnectionTick) {
                            Ok(()) => {}
                            Err(_) => return Err(he_return_code_t::HE_ERR_FAILED),
                        }
                        sync_conn_info(client);
                    }
                }

                // Dispatch every due payload tick with its original TickType —
                // these carry retransmit state Connection::tick() needs. This
                // runs on every nudge, not only when the ConnectionTick
                // deadline passed: their deadlines (e.g. a 500 ms key-share
                // retransmit) are typically much shorter. The due set is
                // snapshotted in one pass; the not-yet-due remainder is stored
                // back BEFORE dispatching, because a dispatched tick may
                // reschedule its successor via cffi_schedule_tick_cb, which
                // appends to the stored list (those successors wait for the
                // next nudge). Errors are swallowed: core rejects
                // stale/off-state retransmit ticks by design (counter and
                // request-id checks), and a dropped retransmit must not fail
                // the whole nudge.
                {
                    let Some(ref mut connection) = client.connection else {
                        return Err(he_return_code_t::HE_ERR_INVALID_CONN_STATE);
                    };
                    let pending = std::mem::take(&mut connection.app_state_mut().pending_ticks);
                    let (due, remaining): (Vec<_>, Vec<_>) =
                        pending.into_iter().partition(|(t, _)| now >= *t);
                    connection.app_state_mut().pending_ticks = remaining;
                    for (_, tick) in due {
                        let _ = connection.tick(tick);
                    }
                }

                // Recompute nudge_ms from whatever deadlines remain (the ticks
                // above may have rescheduled), using the pre-captured `now`.
                let nudge_ms = client
                    .connection
                    .as_ref()
                    .map(|c| nudge_ms_until(c.app_state().earliest_tick_deadline(), now))
                    .unwrap_or(0);
                client.conn.nudge_time_ms = nudge_ms;
                Ok(())
            })
        } {
            Ok(Ok(())) => he_return_code_t::HE_SUCCESS,
            Ok(Err(e)) => e,
            Err(e) => e,
        }
    })
}

// ──────────────────────────────────────────────────────────────────────────────
// Tests
// ──────────────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    // Test bodies call our own FFI entry points with locally-constructed, valid
    // pointers; the safety contracts are self-evident, so don't require a
    // per-block SAFETY comment here.
    #![allow(clippy::undocumented_unsafe_blocks)]

    use super::*;
    use crate::conn::he_conn_t;

    /// Minimal `outside_write_cb` used to satisfy config validation.
    unsafe extern "C" fn dummy_outside_write(
        _conn: *mut he_conn_t,
        _packet: *mut u8,
        _len: usize,
        _ctx: *mut c_void,
    ) -> he_return_code_t {
        he_return_code_t::HE_SUCCESS
    }

    #[test]
    fn create_get_destroy_roundtrip() {
        unsafe {
            let c = he_client_create();
            assert!(!c.is_null());
            let conn = he_client_get_conn(c);
            assert!(!conn.is_null());
            // The back-pointer recovers the owning client …
            assert_eq!((*conn).client_ptr, c);
            // … and the conn pointer is stable across calls.
            assert_eq!(he_client_get_conn(c), conn);
            assert!(!he_client_get_ssl_ctx(c).is_null());
            he_client_destroy(c);
        }
    }

    #[test]
    fn accessors_handle_null() {
        unsafe {
            assert!(he_client_get_conn(std::ptr::null_mut()).is_null());
            assert!(he_client_get_ssl_ctx(std::ptr::null_mut()).is_null());
            assert_eq!(he_conn_get_nudge_time(std::ptr::null()), 0);
            assert_eq!(he_conn_get_outside_mtu(std::ptr::null()), 0);
            assert_eq!(he_conn_get_effective_pmtu(std::ptr::null()), 0);
            assert!(he_conn_get_cipher_name(std::ptr::null()).is_null());
            assert!(he_conn_get_curve_name(std::ptr::null()).is_null());
            assert_eq!(he_conn_get_session_id(std::ptr::null()), 0);
            assert_eq!(
                he_conn_get_current_protocol(std::ptr::null()),
                he_connection_protocol_t::HE_CONNECTION_PROTOCOL_NONE
            );
        }
    }

    #[test]
    fn is_config_valid_requires_auth_writecb_and_ca() {
        unsafe {
            assert_eq!(
                he_client_is_config_valid(std::ptr::null()),
                he_return_code_t::HE_ERR_NULL_POINTER
            );
            let c = he_client_create();
            assert_eq!(he_client_is_config_valid(c), he_return_code_t::HE_ERR_CONF_NOT_SET);

            let ssl = he_client_get_ssl_ctx(c);
            let conn = he_client_get_conn(c);
            let token = b"token-bytes";
            he_conn_set_auth_token(conn, token.as_ptr(), token.len());
            // auth alone is insufficient
            assert_eq!(he_client_is_config_valid(c), he_return_code_t::HE_ERR_CONF_NOT_SET);
            he_ssl_ctx_set_outside_write_cb(ssl, dummy_outside_write);
            // still missing the CA certificate
            assert_eq!(he_client_is_config_valid(c), he_return_code_t::HE_ERR_CONF_NOT_SET);
            let ca = b"-----DUMMY CA-----";
            he_ssl_ctx_set_ca(ssl, ca.as_ptr(), ca.len());
            assert_eq!(he_client_is_config_valid(c), he_return_code_t::HE_SUCCESS);
            he_client_destroy(c);
        }
    }

    #[test]
    fn return_code_name_handles_out_of_range() {
        unsafe {
            assert_eq!(CStr::from_ptr(he_return_code_name(0)).to_bytes(), b"HE_SUCCESS");
            assert_eq!(
                CStr::from_ptr(he_return_code_name(-13)).to_bytes(),
                b"HE_ERR_INVALID_CONN_STATE"
            );
            // Out-of-range must be handled, not treated as an invalid discriminant.
            assert_eq!(CStr::from_ptr(he_return_code_name(9999)).to_bytes(), b"HE_ERR_UNKNOWN");
        }
    }

    #[test]
    fn protocol_name_handles_out_of_range() {
        unsafe {
            assert_eq!(CStr::from_ptr(he_connection_protocol_name(0)).to_bytes(), b"none");
            assert_eq!(CStr::from_ptr(he_connection_protocol_name(2)).to_bytes(), b"DTLS 1.3");
            assert_eq!(CStr::from_ptr(he_connection_protocol_name(123)).to_bytes(), b"unknown");
        }
    }

    #[test]
    fn use_pqc_roundtrip() {
        unsafe {
            let c = he_client_create();
            assert!(!c.is_null());
            let ssl = he_client_get_ssl_ctx(c);
            assert!(!ssl.is_null());
            // Enabling PQC now succeeds and is recorded (it is honoured at
            // connect time via with_pq_crypto), as does disabling it.
            assert_eq!(he_ssl_ctx_set_use_pqc(ssl, true), he_return_code_t::HE_SUCCESS);
            assert!((*ssl).use_pqc);
            assert_eq!(he_ssl_ctx_set_use_pqc(ssl, false), he_return_code_t::HE_SUCCESS);
            assert!(!(*ssl).use_pqc);
            assert_eq!(
                he_ssl_ctx_set_use_pqc(std::ptr::null_mut(), false),
                he_return_code_t::HE_ERR_NULL_POINTER
            );
            he_client_destroy(c);
        }
    }

    #[test]
    fn connection_type_is_validated() {
        unsafe {
            let c = he_client_create();
            let ssl = he_client_get_ssl_ctx(c);
            assert_eq!(he_ssl_ctx_set_connection_type(ssl, 0), he_return_code_t::HE_SUCCESS);
            assert_eq!(he_ssl_ctx_set_connection_type(ssl, 1), he_return_code_t::HE_SUCCESS);
            assert_eq!(he_ssl_ctx_set_connection_type(ssl, 2), he_return_code_t::HE_ERR_BAD_PARAM);
            assert_eq!(he_ssl_ctx_set_connection_type(ssl, -1), he_return_code_t::HE_ERR_BAD_PARAM);
            he_client_destroy(c);
        }
    }

    #[test]
    fn credential_setters_roundtrip() {
        unsafe {
            let c = he_client_create();
            let conn = he_client_get_conn(c);
            assert_eq!(he_conn_set_username(conn, c"alice".as_ptr()), he_return_code_t::HE_SUCCESS);
            assert_eq!(he_conn_set_password(conn, c"secret".as_ptr()), he_return_code_t::HE_SUCCESS);
            assert_eq!((*conn).username.as_deref(), Some(c"alice"));
            assert_eq!((*conn).password.as_deref(), Some(c"secret"));
            assert_eq!(
                he_conn_set_username(conn, std::ptr::null()),
                he_return_code_t::HE_ERR_NULL_POINTER
            );
            he_client_destroy(c);
        }
    }

    #[test]
    fn outside_mtu_setter_roundtrip() {
        unsafe {
            let c = he_client_create();
            let conn = he_client_get_conn(c);
            assert_eq!(he_conn_set_outside_mtu(conn, 1400), he_return_code_t::HE_SUCCESS);
            assert_eq!((*conn).outside_mtu, 1400);
            he_client_destroy(c);
        }
    }

    #[test]
    fn data_path_without_connection_is_rejected() {
        unsafe {
            let c = he_client_create();
            let conn = he_client_get_conn(c);
            let mut buf = [0u8; 8];
            assert_eq!(
                he_conn_outside_data_received(conn, buf.as_mut_ptr(), buf.len()),
                he_return_code_t::HE_ERR_INVALID_CONN_STATE
            );
            assert_eq!(
                he_conn_inside_packet_received(conn, buf.as_mut_ptr(), buf.len()),
                he_return_code_t::HE_ERR_INVALID_CONN_STATE
            );
            assert_eq!(he_conn_nudge(conn), he_return_code_t::HE_ERR_INVALID_CONN_STATE);
            assert_eq!(
                he_conn_outside_data_received(conn, std::ptr::null_mut(), 0),
                he_return_code_t::HE_ERR_NULL_POINTER
            );
            he_client_destroy(c);
        }
    }

    #[test]
    fn schedule_tick_cb_keeps_payload_ticks_typed() {
        let mut state = CffiAppState::default();
        // A payload tick must be stored verbatim, not folded into next_tick —
        // folding would later dispatch it as a ConnectionTick and silently
        // drop the retransmit it carries. (ExpresslaneKeyShareTick is not
        // constructible outside lightway-core; PktCodecTick exercises the
        // same non-ConnectionTick storage path.)
        cffi_schedule_tick_cb(
            std::time::Duration::from_millis(500),
            &mut state,
            TickType::PktCodecTick(7),
        );
        assert!(state.next_tick.is_none());
        assert_eq!(state.pending_ticks.len(), 1);
        assert!(matches!(
            state.pending_ticks[0].1,
            TickType::PktCodecTick(7)
        ));

        // A ConnectionTick keeps using the merged next_tick slot.
        cffi_schedule_tick_cb(
            std::time::Duration::from_secs(10),
            &mut state,
            TickType::ConnectionTick,
        );
        assert!(state.next_tick.is_some());
        assert_eq!(state.pending_ticks.len(), 1);

        // The wake-up deadline is the earlier of the two — the 500 ms payload
        // tick, not the 10 s connection tick.
        let earliest = state.earliest_tick_deadline().expect("two deadlines pending");
        assert_eq!(earliest, state.pending_ticks[0].0);
        assert!(earliest < state.next_tick.expect("connection tick pending"));
    }

    #[test]
    fn schedule_tick_cb_notifies_earliest_deadline() {
        use std::sync::atomic::{AtomicI32, Ordering};
        static LAST_TIMEOUT_MS: AtomicI32 = AtomicI32::new(-1);
        unsafe extern "C" fn capture(
            _conn: *mut he_conn_t,
            timeout: i32,
            _context: *mut std::ffi::c_void,
        ) -> he_return_code_t {
            LAST_TIMEOUT_MS.store(timeout, Ordering::SeqCst);
            he_return_code_t::HE_SUCCESS
        }
        let mut state = CffiAppState {
            nudge_time_cb: Some(capture),
            ..CffiAppState::default()
        };

        cffi_schedule_tick_cb(
            std::time::Duration::from_millis(500),
            &mut state,
            TickType::PktCodecTick(1),
        );
        assert!((0..=500).contains(&LAST_TIMEOUT_MS.load(Ordering::SeqCst)));

        // The C host keeps a single timer and resets it to every notified
        // timeout, so scheduling a LATER tick must still notify the time to
        // the earlier pending deadline — not this call's own 10 s delay.
        cffi_schedule_tick_cb(
            std::time::Duration::from_secs(10),
            &mut state,
            TickType::ConnectionTick,
        );
        let notified = LAST_TIMEOUT_MS.load(Ordering::SeqCst);
        assert!(
            (0..=500).contains(&notified),
            "notified {notified} ms; expected the earlier (<= 500 ms) pending deadline"
        );
    }

    #[test]
    fn expresslane_rotate_if_due_without_connection_is_rejected() {
        unsafe {
            assert_eq!(
                he_conn_expresslane_rotate_if_due(std::ptr::null_mut()),
                he_return_code_t::HE_ERR_NULL_POINTER
            );
            let c = he_client_create();
            let conn = he_client_get_conn(c);
            assert_eq!(
                he_conn_expresslane_rotate_if_due(conn),
                he_return_code_t::HE_ERR_INVALID_CONN_STATE
            );
            he_client_destroy(c);
        }
    }

    #[test]
    fn ffi_guard_contains_panic() {
        // A panic inside the guarded body must be converted to the default
        // return value, never unwound across the (simulated) FFI boundary.
        // The default panic hook prints one line for the deliberate panic
        // below; that is expected. We avoid mutating the global hook because it
        // would race other tests running in parallel.
        let r = ffi_guard(he_return_code_t::HE_ERR_FAILED, || -> he_return_code_t {
            panic!("ffi_guard test panic (expected)")
        });
        assert_eq!(r, he_return_code_t::HE_ERR_FAILED);
    }

    #[test]
    fn lock_client_rejects_reentrancy() {
        unsafe {
            let c = he_client_create();
            // Re-entering a locking API on the same thread while the lock is
            // held must be rejected, not dead-lock.
            let inner = lock_client(c, |_client| lock_client(c, |_| ()).err());
            assert_eq!(inner.unwrap(), Some(he_return_code_t::HE_ERR_INVALID_CONN_STATE));
            // After the outer guard is released, a fresh top-level call succeeds
            // (the owner token was cleared).
            assert_eq!(lock_client(c, |_| 7i32).ok(), Some(7));
            he_client_destroy(c);
        }
    }

    #[test]
    fn fatal_disconnect_fires_disconnected_once_and_clears_connection() {
        use std::sync::atomic::AtomicU32;
        static DISCONNECTED_HITS: AtomicU32 = AtomicU32::new(0);

        unsafe extern "C" fn count_disconnected(
            _conn: *mut he_conn_t,
            new_state: he_conn_state_t,
            _ctx: *mut c_void,
        ) -> he_return_code_t {
            if new_state == he_conn_state_t::HE_STATE_DISCONNECTED {
                DISCONNECTED_HITS.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            }
            he_return_code_t::HE_SUCCESS
        }

        unsafe {
            DISCONNECTED_HITS.store(0, std::sync::atomic::Ordering::SeqCst);
            let c = he_client_create();
            he_ssl_ctx_set_state_change_cb(he_client_get_ssl_ctx(c), count_disconnected);

            // Drive the teardown directly: producing a *real* fatal wire error
            // needs a live handshake, but this exercises the same state-machine
            // path (fire DISCONNECTED, set state, drop the live Connection).
            let client = &mut *c;
            fatal_disconnect(client);
            assert_eq!(client.conn.state, he_conn_state_t::HE_STATE_DISCONNECTED);
            assert!(client.connection.is_none());

            // Idempotent: a second call must not re-fire the transition.
            fatal_disconnect(client);
            assert_eq!(DISCONNECTED_HITS.load(std::sync::atomic::Ordering::SeqCst), 1);

            he_client_destroy(c);
        }
    }

    #[test]
    fn identify_packet_classifies_control_and_expresslane() {
        use lightway_core::{Header, SessionId, Version};
        let session = SessionId::from_const([1, 2, 3, 4, 5, 6, 7, 8]);

        for (expresslane, expected) in [
            (false, he_packet_kind_t::HE_PACKET_KIND_CONTROL),
            (true, he_packet_kind_t::HE_PACKET_KIND_EXPRESSLANE),
        ] {
            let hdr = Header {
                version: Version::MAXIMUM,
                aggressive_mode: false,
                expresslane_data: expresslane,
                session,
            };
            let mut wire = BytesMut::new();
            hdr.append_to_wire(&mut wire);
            wire.extend_from_slice(b"payload-after-the-header"); // ignored by classify

            let mut kind = he_packet_kind_t::HE_PACKET_KIND_UNDECIDABLE;
            let mut sid = [0u8; 8];
            let mut hlen = 0usize;
            // SAFETY: valid buffer + out-params.
            let rc = unsafe {
                he_conn_identify_packet(wire.as_ptr(), wire.len(), &mut kind, sid.as_mut_ptr(), &mut hlen)
            };
            assert_eq!(rc, he_return_code_t::HE_SUCCESS);
            assert_eq!(kind, expected);
            assert_eq!(sid, [1, 2, 3, 4, 5, 6, 7, 8]);
            assert_eq!(hlen, 16);
        }
    }

    #[test]
    fn identify_packet_rejects_bad_magic_short_and_null() {
        // Bad magic → Undecidable, still HE_SUCCESS; out-params defaulted even
        // though they carried non-default junk before the call.
        let bad = [0u8; 20];
        let mut kind = he_packet_kind_t::HE_PACKET_KIND_CONTROL;
        let mut sid = [0xAAu8; 8];
        let mut hlen = 999usize;
        // SAFETY: valid buffer + out-params.
        let rc = unsafe {
            he_conn_identify_packet(bad.as_ptr(), bad.len(), &mut kind, sid.as_mut_ptr(), &mut hlen)
        };
        assert_eq!(rc, he_return_code_t::HE_SUCCESS);
        assert_eq!(kind, he_packet_kind_t::HE_PACKET_KIND_UNDECIDABLE);
        assert_eq!(sid, [0u8; 8], "session_id defaulted to zero on undecidable");
        assert_eq!(hlen, 0, "header_len defaulted to zero on undecidable");

        // Shorter than the 16-byte header → Undecidable.
        let short = *b"He\x01\x03\x00\x01";
        let mut kind2 = he_packet_kind_t::HE_PACKET_KIND_CONTROL;
        // SAFETY: valid buffer.
        let rc2 = unsafe {
            he_conn_identify_packet(short.as_ptr(), short.len(), &mut kind2, std::ptr::null_mut(), std::ptr::null_mut())
        };
        assert_eq!(rc2, he_return_code_t::HE_SUCCESS);
        assert_eq!(kind2, he_packet_kind_t::HE_PACKET_KIND_UNDECIDABLE);

        // Null kind pointer, and null packet with len > 0 → NULL_POINTER.
        // SAFETY: intentional null args.
        assert_eq!(
            unsafe {
                he_conn_identify_packet(bad.as_ptr(), bad.len(), std::ptr::null_mut(), std::ptr::null_mut(), std::ptr::null_mut())
            },
            he_return_code_t::HE_ERR_NULL_POINTER
        );
        // SAFETY: intentional null packet with non-zero len.
        assert_eq!(
            unsafe {
                he_conn_identify_packet(std::ptr::null(), 20, &mut kind, std::ptr::null_mut(), std::ptr::null_mut())
            },
            he_return_code_t::HE_ERR_NULL_POINTER
        );
    }

    #[test]
    fn build_expresslane_header_rejects_bad_inputs() {
        // SAFETY: create/destroy a client; no connection is established.
        unsafe {
            let c = he_client_create();
            let sid = [1u8; 8];
            let mut out = [0u8; 16];
            // A valid session but no connection yet → not ready.
            assert_eq!(
                he_conn_build_expresslane_header(c, sid.as_ptr(), out.as_mut_ptr()),
                he_return_code_t::HE_ERR_INVALID_CONN_STATE
            );
            // Reserved all-zero session → bad param (rejected before the lock).
            assert_eq!(
                he_conn_build_expresslane_header(c, [0u8; 8].as_ptr(), out.as_mut_ptr()),
                he_return_code_t::HE_ERR_BAD_PARAM
            );
            // Null out / null session_id → null pointer.
            assert_eq!(
                he_conn_build_expresslane_header(c, sid.as_ptr(), std::ptr::null_mut()),
                he_return_code_t::HE_ERR_NULL_POINTER
            );
            assert_eq!(
                he_conn_build_expresslane_header(c, std::ptr::null(), out.as_mut_ptr()),
                he_return_code_t::HE_ERR_NULL_POINTER
            );
            // Null client → NULL_POINTER, and it must win over the reserved-
            // session BAD_PARAM check (both bad here).
            assert_eq!(
                he_conn_build_expresslane_header(std::ptr::null(), [0u8; 8].as_ptr(), out.as_mut_ptr()),
                he_return_code_t::HE_ERR_NULL_POINTER
            );
            he_client_destroy(c);
        }
    }
}
