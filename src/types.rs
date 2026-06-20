//! C-ABI types that mirror the OSS `lightway-core` C library's public
//! enumeration and struct surface.  cbindgen will pick these up and emit them
//! into `include/lightway_cffi.h`.
#![allow(non_camel_case_types, non_upper_case_globals, clippy::upper_case_acronyms)]

use std::ffi::c_char;

// ──────────────────────────────────────────────────────────────────────────────
// Return codes
// ──────────────────────────────────────────────────────────────────────────────

/// Return codes used by all `he_*` functions.
///
/// Values mirror those in the OSS `lightway-core` C library so that existing
/// `if (result != HE_SUCCESS)` guards continue to work unchanged.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum he_return_code_t {
    /// Operation succeeded.
    HE_SUCCESS = 0,
    /// Generic failure.
    HE_ERR_FAILED = -1,
    /// A null pointer was supplied where one is not permitted.
    HE_ERR_NULL_POINTER = -2,
    /// Memory allocation failed.
    HE_ERR_NO_MEMORY = -3,
    /// Buffer too small.
    HE_ERR_BUFFER_TOO_SMALL = -4,
    /// Bad parameter value.
    HE_ERR_BAD_PARAM = -5,
    /// Server rejected credentials.
    HE_ERR_ACCESS_DENIED = -6,
    /// Payload too large.
    HE_ERR_PAYLOAD_TOO_LARGE = -7,
    /// String was not NUL-terminated or too long.
    HE_ERR_STRING_TOO_LONG = -8,
    /// Connection timed out (used as a non-fatal nudge sentinel).
    HE_CONNECTION_TIMED_OUT = -9,
    /// An incorrect protocol version was received.
    HE_ERR_INCORRECT_PROTOCOL_VERSION = -10,
    /// SSL / crypto error.
    HE_ERR_SSL_ERROR = -11,
    /// Configuration is not yet complete.
    HE_ERR_CONF_NOT_SET = -12,
    /// The operation was called at the wrong connection state.
    HE_ERR_INVALID_CONN_STATE = -13,
}

impl he_return_code_t {
    /// Map a raw C integer back to a known return code, or `None` if it does
    /// not correspond to any defined value.  Used by `he_return_code_name` so
    /// that an out-of-range integer from C is handled safely rather than
    /// reinterpreted as an invalid enum discriminant (which would be UB).
    pub(crate) fn from_repr(v: i32) -> Option<Self> {
        Some(match v {
            0 => Self::HE_SUCCESS,
            -1 => Self::HE_ERR_FAILED,
            -2 => Self::HE_ERR_NULL_POINTER,
            -3 => Self::HE_ERR_NO_MEMORY,
            -4 => Self::HE_ERR_BUFFER_TOO_SMALL,
            -5 => Self::HE_ERR_BAD_PARAM,
            -6 => Self::HE_ERR_ACCESS_DENIED,
            -7 => Self::HE_ERR_PAYLOAD_TOO_LARGE,
            -8 => Self::HE_ERR_STRING_TOO_LONG,
            -9 => Self::HE_CONNECTION_TIMED_OUT,
            -10 => Self::HE_ERR_INCORRECT_PROTOCOL_VERSION,
            -11 => Self::HE_ERR_SSL_ERROR,
            -12 => Self::HE_ERR_CONF_NOT_SET,
            -13 => Self::HE_ERR_INVALID_CONN_STATE,
            _ => return None,
        })
    }

    /// Returns a static C string name for use in log messages, matching
    /// `he_return_code_name()`.
    pub(crate) fn as_cstr(self) -> &'static c_char {
        let s: &'static [u8] = match self {
            Self::HE_SUCCESS => b"HE_SUCCESS\0",
            Self::HE_ERR_FAILED => b"HE_ERR_FAILED\0",
            Self::HE_ERR_NULL_POINTER => b"HE_ERR_NULL_POINTER\0",
            Self::HE_ERR_NO_MEMORY => b"HE_ERR_NO_MEMORY\0",
            Self::HE_ERR_BUFFER_TOO_SMALL => b"HE_ERR_BUFFER_TOO_SMALL\0",
            Self::HE_ERR_BAD_PARAM => b"HE_ERR_BAD_PARAM\0",
            Self::HE_ERR_ACCESS_DENIED => b"HE_ERR_ACCESS_DENIED\0",
            Self::HE_ERR_PAYLOAD_TOO_LARGE => b"HE_ERR_PAYLOAD_TOO_LARGE\0",
            Self::HE_ERR_STRING_TOO_LONG => b"HE_ERR_STRING_TOO_LONG\0",
            Self::HE_CONNECTION_TIMED_OUT => b"HE_CONNECTION_TIMED_OUT\0",
            Self::HE_ERR_INCORRECT_PROTOCOL_VERSION => {
                b"HE_ERR_INCORRECT_PROTOCOL_VERSION\0"
            }
            Self::HE_ERR_SSL_ERROR => b"HE_ERR_SSL_ERROR\0",
            Self::HE_ERR_CONF_NOT_SET => b"HE_ERR_CONF_NOT_SET\0",
            Self::HE_ERR_INVALID_CONN_STATE => b"HE_ERR_INVALID_CONN_STATE\0",
        };
        // SAFETY: all literals above are valid NUL-terminated ASCII.
        unsafe { &*(s.as_ptr() as *const c_char) }
    }
}

// ──────────────────────────────────────────────────────────────────────────────
// Connection state
// ──────────────────────────────────────────────────────────────────────────────

/// Lightway connection state, delivered to `he_state_change_cb_t`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum he_conn_state_t {
    /// Initial / unset state.
    HE_STATE_NONE = 0,
    /// Fully disconnected.
    HE_STATE_DISCONNECTED = 1,
    /// Performing TLS handshake.
    HE_STATE_CONNECTING = 2,
    /// Graceful disconnect in progress.
    HE_STATE_DISCONNECTING = 3,
    /// Authenticating with the server.
    HE_STATE_AUTHENTICATING = 4,
    /// Link layer is up (pre-IP config).
    HE_STATE_LINK_UP = 5,
    /// Receiving IP configuration from server.
    HE_STATE_CONFIGURING = 6,
    /// Fully online — data traffic flowing.
    HE_STATE_ONLINE = 7,
}

// ──────────────────────────────────────────────────────────────────────────────
// Connection events
// ──────────────────────────────────────────────────────────────────────────────

/// Asynchronous events delivered to `he_event_cb_t`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum he_conn_event_t {
    /// First message received from server.
    HE_EVENT_FIRST_MESSAGE_RECEIVED = 1,
    /// Keepalive pong received.
    HE_EVENT_PONG = 2,
    /// Server rejected fragmented packets from host.
    HE_EVENT_REJECTED_FRAGMENTED_PACKETS_SENT_BY_HOST = 3,
    /// Secure renegotiation started.
    HE_EVENT_SECURE_RENEGOTIATION_STARTED = 4,
    /// Secure renegotiation completed.
    HE_EVENT_SECURE_RENEGOTIATION_COMPLETED = 5,
    /// Pending session acknowledged.
    HE_EVENT_PENDING_SESSION_ACKNOWLEDGED = 6,
}

// ──────────────────────────────────────────────────────────────────────────────
// Connection & protocol types
// ──────────────────────────────────────────────────────────────────────────────

/// Transport type for a Lightway connection.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum he_connection_type_t {
    /// UDP / DTLS transport.
    HE_CONNECTION_TYPE_DATAGRAM = 0,
    /// TCP / TLS transport.
    HE_CONNECTION_TYPE_STREAM = 1,
}

/// The negotiated D/TLS protocol version.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum he_connection_protocol_t {
    /// Unspecified / not yet negotiated.
    HE_CONNECTION_PROTOCOL_NONE = 0,
    /// DTLS 1.2.
    HE_CONNECTION_PROTOCOL_DTLS_1_2 = 1,
    /// DTLS 1.3.
    HE_CONNECTION_PROTOCOL_DTLS_1_3 = 2,
    /// TLS 1.2.
    HE_CONNECTION_PROTOCOL_TLS_1_2 = 3,
    /// TLS 1.3.
    HE_CONNECTION_PROTOCOL_TLS_1_3 = 4,
}

// ──────────────────────────────────────────────────────────────────────────────
// Padding
// ──────────────────────────────────────────────────────────────────────────────

/// Packet-padding mode.  Mirrors `he_padding_type` from the OSS C library.
/// The Rust `lightway-core` does not currently expose padding control via its
/// public API; this enum is provided for source-compatibility with consumers
/// that read or pass the value through config structs without calling a setter.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum he_padding_type_t {
    /// No padding applied.
    HE_PADDING_NONE = 0,
    /// Pad every packet to the full MTU.
    HE_PADDING_FULL = 1,
    /// Pad packets to 450 bytes.
    HE_PADDING_450 = 2,
}

// ──────────────────────────────────────────────────────────────────────────────
// PMTUD
// ──────────────────────────────────────────────────────────────────────────────

/// Path MTU Discovery state delivered to `he_pmtud_state_change_cb_t`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum he_pmtud_state_t {
    /// Base / initial state.
    HE_PMTUD_STATE_BASE = 0,
    /// Discovery disabled.
    HE_PMTUD_STATE_DISABLED = 1,
    /// Probing in progress.
    HE_PMTUD_STATE_SEARCHING = 2,
    /// Search complete — effective PMTU is available.
    HE_PMTUD_STATE_SEARCH_COMPLETE = 3,
    /// Error during discovery.
    HE_PMTUD_STATE_ERROR = 4,
}

// ──────────────────────────────────────────────────────────────────────────────
// ExpressLane
// ──────────────────────────────────────────────────────────────────────────────

/// ExpressLane operational state delivered to `he_expresslane_state_change_cb_t`.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum he_expresslane_state_t {
    /// ExpressLane not enabled in the config.
    HE_EXPRESSLANE_STATE_DISABLED = 0,
    /// Enabled but handshake not yet complete or peer has not enabled it.
    HE_EXPRESSLANE_STATE_INACTIVE = 1,
    /// Waiting for the client to respond (server side only).
    HE_EXPRESSLANE_STATE_WAITING_FOR_CLIENT = 2,
    /// ExpressLane active — fast path in use.
    HE_EXPRESSLANE_STATE_ACTIVE = 3,
    /// Degraded — fell back to normal D/TLS for data packets.
    HE_EXPRESSLANE_STATE_DEGRADED = 4,
}

/// Symmetric keys and session ID delivered to `he_expresslane_cb_t` whenever
/// the fast-path key material is refreshed.
///
/// The kernel-mode NDIS driver consumes these to encrypt/decrypt ExpressLane
/// data packets without going through the Lightway userspace stack.
#[repr(C)]
pub struct he_expresslane_keys_t {
    /// Session identifier — 8 bytes, little-endian u64 on the wire.
    pub session_id: [u8; 8],
    /// 256-bit AES/ChaCha key for packets **sent** by this endpoint.
    pub self_key: [u8; 32],
    /// 256-bit AES/ChaCha key for packets **received** by this endpoint.
    pub peer_key: [u8; 32],
}

// ──────────────────────────────────────────────────────────────────────────────
// Network config
// ──────────────────────────────────────────────────────────────────────────────

/// IPv4 network configuration delivered by the server via
/// `he_network_config_ipv4_cb_t`.
///
/// All string fields are NUL-terminated and at most 64 bytes including the
/// terminator (matching the OSS C library layout).
#[repr(C)]
pub struct he_network_config_ipv4_t {
    /// Virtual IP address assigned to this client (dotted-decimal).
    pub local_ip: [c_char; 64],
    /// DNS server IP (dotted-decimal).
    pub dns_ip: [c_char; 64],
    /// VPN gateway / peer IP (dotted-decimal).
    pub peer_ip: [c_char; 64],
    /// Inside MTU for this connection.
    pub mtu: u16,
}
