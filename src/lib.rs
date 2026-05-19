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

use std::ffi::{CStr, CString, c_char, c_void};
use std::sync::Arc;

pub mod cffi_event;
pub mod cffi_expresslane;
pub mod cffi_io;
pub mod cffi_ip_config;
pub mod cffi_state;
pub mod conn;
pub mod threat_manager;
pub mod types;
mod version;

use bytes::BytesMut;
use lightway_core::{
    AuthMethod, ClientContextBuilder, ConnectionType, OutsideIOSendCallbackArg, OutsidePacket,
    ProtocolVersion, RootCertificate, TickType,
};

use cffi_expresslane::CffiExpresslaneCb;

use cffi_event::CffiEventCallback;
use cffi_io::{CffiInsideIO, CffiOutsideIO};
use cffi_ip_config::CffiIpConfig;
use cffi_state::{CffiAppState, cffi_schedule_tick_cb};
use conn::{he_client_t, he_conn_t};

use types::*;

// ──────────────────────────────────────────────────────────────────────────────
// Connection-info snapshot helper
// ──────────────────────────────────────────────────────────────────────────────

/// Snapshot protocol version and curve name from the live Rust connection into
/// `he_conn_t` so that `he_conn_get_current_protocol` / `he_conn_get_curve_name`
/// return correct values once the connection reaches Online.
///
/// Takes a raw pointer to avoid borrow-checker conflicts with `MutexGuard`
/// held on `client.lock` in the caller's scope.
///
/// # Safety
/// `client_ptr` must be a valid non-null pointer to a live `he_client_t`.
unsafe fn sync_conn_info(client_ptr: *mut he_client_t) {
    // SAFETY: caller guarantees client_ptr is non-null and valid.
    let client = unsafe { &mut *client_ptr };
    let Some(ref mut connection) = client.connection else {
        return;
    };
    // Map wolfssl ProtocolVersion → our C enum
    let proto = match connection.tls_protocol_version() {
        ProtocolVersion::DtlsV1_2 => he_connection_protocol_t::HE_CONNECTION_PROTOCOL_DTLS_1_2,
        ProtocolVersion::DtlsV1_3 => he_connection_protocol_t::HE_CONNECTION_PROTOCOL_DTLS_1_3,
        ProtocolVersion::TlsV1_2 => he_connection_protocol_t::HE_CONNECTION_PROTOCOL_TLS_1_2,
        ProtocolVersion::TlsV1_3 => he_connection_protocol_t::HE_CONNECTION_PROTOCOL_TLS_1_3,
        _ => he_connection_protocol_t::HE_CONNECTION_PROTOCOL_NONE,
    };
    client.conn.current_protocol = proto;

    if let Some(curve) = connection.current_curve() {
        client.conn.curve_name = CString::new(curve).ok();
    }
    if let Some(cipher) = connection.current_cipher() {
        client.conn.cipher_name = CString::new(cipher).ok();
    }
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
/// # Safety
/// Always returns a valid, non-null pointer regardless of the value passed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_return_code_name(code: he_return_code_t) -> *const c_char {
    code.as_cstr()
}

/// Return a static NUL-terminated name for a connection protocol.
///
/// # Safety
/// Always returns a valid, non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_connection_protocol_name(
    protocol: he_connection_protocol_t,
) -> *const c_char {
    let s: &[u8] = match protocol {
        he_connection_protocol_t::HE_CONNECTION_PROTOCOL_NONE => b"none\0",
        he_connection_protocol_t::HE_CONNECTION_PROTOCOL_DTLS_1_2 => b"DTLS 1.2\0",
        he_connection_protocol_t::HE_CONNECTION_PROTOCOL_DTLS_1_3 => b"DTLS 1.3\0",
        he_connection_protocol_t::HE_CONNECTION_PROTOCOL_TLS_1_2 => b"TLS 1.2\0",
        he_connection_protocol_t::HE_CONNECTION_PROTOCOL_TLS_1_3 => b"TLS 1.3\0",
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
/// Returns a heap-allocated pointer on success, or null on allocation failure.
/// The caller must free it with `he_client_destroy`.
///
/// # Safety
/// The returned pointer must be freed with `he_client_destroy`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_client_create() -> *mut he_client_t {
    let client = Box::new(he_client_t::new());
    Box::into_raw(client)
}

/// Free a `he_client_t` previously allocated by `he_client_create`.
///
/// # Safety
/// `client` must be a valid pointer obtained from `he_client_create` and must
/// not be used after this call.
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
    // Require at least one write callback
    if client.ssl_ctx.outside_write_cb.is_none() {
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
    if client.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; pointer is valid for the call duration.
    let client = unsafe { &mut *client };
    let _guard = client.lock.lock().unwrap_or_else(|e| e.into_inner());

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
        let b = ctx_builder.with_expresslane();
        if let Some(el_cb) = client.ssl_ctx.expresslane_cb {
            b.with_expresslane_cb(CffiExpresslaneCb::create(el_cb, conn_ptr, ctx))
        } else {
            b
        }
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
        pmtud_state_change_cb: client.ssl_ctx.pmtud_state_change_cb,
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

    // ── 7. connect() → live Connection  ────────────────────────────────────
    let app_state = CffiAppState::default();
    let connection = match conn_builder.connect(app_state) {
        Ok(c) => c,
        Err(_) => return he_return_code_t::HE_ERR_SSL_ERROR,
    };

    client.connection = Some(connection);

    he_return_code_t::HE_SUCCESS
}

/// Gracefully disconnect a client.
///
/// # Safety
/// `client` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_client_disconnect(client: *mut he_client_t) -> he_return_code_t {
    if client.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: null check above; pointer is valid for the call duration.
    let client = unsafe { &mut *client };
    let _guard = client.lock.lock().unwrap_or_else(|e| e.into_inner());

    // Drive a graceful TLS goodbye if the Connection is live.
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
    match s.to_str() {
        Ok(s) => {
            // SAFETY: null check above; ssl_ctx is valid for this call.
            unsafe { (*ssl_ctx).server_dn = Some(CString::new(s).unwrap()) };
            he_return_code_t::HE_SUCCESS
        }
        Err(_) => he_return_code_t::HE_ERR_BAD_PARAM,
    }
}

/// Enable or disable post-quantum cryptography.
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
/// # Safety
/// `ssl_ctx` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_ssl_ctx_set_connection_type(
    ssl_ctx: *mut conn::he_ssl_ctx_t,
    connection_type: he_connection_type_t,
) -> he_return_code_t {
    if ssl_ctx.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
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
/// Returns 0 if PMTUD has not completed.
///
/// # Safety
/// `conn` must be a valid non-null pointer.
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
/// The returned pointer is valid as long as the connection object is alive.
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
/// The returned pointer is valid as long as the connection object is alive.
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
/// Returns `0` if no connection is active yet.
///
/// # Safety
/// `client` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_get_session_id(client: *const he_client_t) -> u64 {
    if client.is_null() {
        return 0;
    }
    // SAFETY: null check above; client is valid for this call.
    let client = unsafe { &*client };
    let _guard = client.lock.lock().unwrap();
    match client.connection {
        Some(ref conn) => {
            let sid = conn.session_id();
            // SessionId is [u8; 8]; interpret as little-endian u64.
            u64::from_le_bytes(
                // SAFETY: SessionId is a [u8; 8] newtype; reading it as [u8; 8]
            // is always valid and correctly sized.
                unsafe { std::ptr::read(&sid as *const _ as *const [u8; 8]) }
            )
        }
        None => 0,
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Data path
// ──────────────────────────────────────────────────────────────────────────────

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
    if conn.is_null() || buffer.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // Reach up to the owning he_client_t via the conn field being first.
    // SAFETY: he_conn_t is the first field of he_client_t (guaranteed by the
    // repr(C) layout in conn.rs), so casting conn to he_client_t* is valid.
    let client = unsafe { &mut *(conn as *mut he_client_t) };
    let _guard = client.lock.lock().unwrap_or_else(|e| e.into_inner());

    // SAFETY: null check above; buffer points to `length` readable bytes.
    let bytes = unsafe { std::slice::from_raw_parts(buffer, length) };
    let mut buf = BytesMut::from(bytes);
    let connection_type = match client.ssl_ctx.connection_type {
        he_connection_type_t::HE_CONNECTION_TYPE_DATAGRAM => ConnectionType::Datagram,
        he_connection_type_t::HE_CONNECTION_TYPE_STREAM => ConnectionType::Stream,
    };
    let result = {
        let Some(ref mut connection) = client.connection else {
            return he_return_code_t::HE_ERR_INVALID_CONN_STATE;
        };
        let pkt = OutsidePacket::Wire(&mut buf, connection_type);
        match connection.outside_data_received(pkt) {
            Ok(_) => he_return_code_t::HE_SUCCESS,
            Err(e) if e.is_fatal(connection_type) => he_return_code_t::HE_ERR_FAILED,
            Err(_) => he_return_code_t::HE_SUCCESS,
        }
    };
    // SAFETY: conn == &client.conn == base of he_client_t; valid for our scope.
    unsafe { sync_conn_info(conn as *mut he_client_t) };
    result
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
    if conn.is_null() || packet.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: he_conn_t is the first field of he_client_t (repr(C) in conn.rs).
    let client = unsafe { &mut *(conn as *mut he_client_t) };
    let _guard = client.lock.lock().unwrap_or_else(|e| e.into_inner());

    // SAFETY: null check above; packet points to `length` readable bytes.
    let bytes = unsafe { std::slice::from_raw_parts(packet, length) };
    let mut buf = BytesMut::from(bytes);
    let result = {
        let Some(ref mut connection) = client.connection else {
            return he_return_code_t::HE_ERR_INVALID_CONN_STATE;
        };
        match connection.inside_data_received(&mut buf) {
            Ok(()) => he_return_code_t::HE_SUCCESS,
            Err(lightway_core::ConnectionError::InvalidState) => {
                he_return_code_t::HE_ERR_INVALID_CONN_STATE
            }
            Err(_) => he_return_code_t::HE_ERR_FAILED,
        }
    };
    // SAFETY: conn == &client.conn == base of he_client_t; valid for our scope.
    unsafe { sync_conn_info(conn as *mut he_client_t) };
    result
}

/// Nudge the connection — retransmit handshake messages if the keepalive
/// timer has expired.
///
/// # Safety
/// `conn` must be a valid non-null pointer.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_conn_nudge(conn: *mut he_conn_t) -> he_return_code_t {
    if conn.is_null() {
        return he_return_code_t::HE_ERR_NULL_POINTER;
    }
    // SAFETY: he_conn_t is the first field of he_client_t (repr(C) in conn.rs).
    let client = unsafe { &mut *(conn as *mut he_client_t) };
    let _guard = client.lock.lock().unwrap_or_else(|e| e.into_inner());

    // Fire a D/TLS retransmit tick if the deadline has passed.
    let now = std::time::Instant::now();

    let ticked = {
        let Some(ref mut connection) = client.connection else {
            return he_return_code_t::HE_ERR_INVALID_CONN_STATE;
        };
        let should_tick = connection.app_state().next_tick.is_none_or(|t| now >= t);
        if should_tick {
            connection.app_state_mut().next_tick = None;
            match connection.tick(TickType::ConnectionTick) {
                Ok(()) => {}
                Err(_) => return he_return_code_t::HE_ERR_FAILED,
            }
        }
        should_tick
    };

    if ticked {
        // SAFETY: conn == &client.conn == base of he_client_t; valid for our scope.
        unsafe { sync_conn_info(conn as *mut he_client_t) };
    }

    // Expose the next nudge deadline as milliseconds for the C caller.
    let nudge_ms = {
        let Some(ref connection) = client.connection else {
            return he_return_code_t::HE_ERR_INVALID_CONN_STATE;
        };
        connection
            .app_state()
            .next_tick
            .map(|t| {
                let remaining = t.saturating_duration_since(now);
                remaining.as_millis().min(i32::MAX as u128) as i32
            })
            .unwrap_or(0)
    };
    // SAFETY: conn is the first field of he_client_t and remains valid
    // throughout this function under the lock held above.
    unsafe { (*conn).nudge_time_ms = nudge_ms };

    he_return_code_t::HE_SUCCESS
}
