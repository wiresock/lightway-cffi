//! C-ABI types for the ExpressLane data-plane CFFI.
#![allow(non_camel_case_types, non_upper_case_globals, clippy::upper_case_acronyms)]

/// Return codes used by all `he_expresslane_*` functions.
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum he_expresslane_return_code_t {
    /// Operation succeeded.
    HE_EXPRESSLANE_SUCCESS = 0,
    /// A null pointer was supplied where one is not permitted.
    HE_EXPRESSLANE_ERR_NULL_POINTER = -1,
    /// Caller-provided output buffer is too small.
    HE_EXPRESSLANE_ERR_BUFFER_TOO_SMALL = -2,
    /// Wire packet is shorter than the minimum ExpressLane header.
    HE_EXPRESSLANE_ERR_INSUFFICIENT_DATA = -3,
    /// AEAD authentication failed, or the packet is otherwise malformed.
    HE_EXPRESSLANE_ERR_INVALID_DATA = -4,
    /// Wire counter was rejected by the replay window.
    HE_EXPRESSLANE_ERR_REPLAYED = -5,
    /// No key is installed for this operation.
    HE_EXPRESSLANE_ERR_KEY_NOT_SET = -6,
    /// Key material could not be loaded into the cipher.
    HE_EXPRESSLANE_ERR_INVALID_KEY = -7,
    /// A panic was caught at the FFI boundary.
    HE_EXPRESSLANE_ERR_PANIC = -8,
}

impl From<lightway_expresslane::ExpresslaneError> for he_expresslane_return_code_t {
    fn from(e: lightway_expresslane::ExpresslaneError) -> Self {
        use lightway_expresslane::ExpresslaneError as E;
        match e {
            E::InsufficientData => Self::HE_EXPRESSLANE_ERR_INSUFFICIENT_DATA,
            E::BufferTooSmall => Self::HE_EXPRESSLANE_ERR_BUFFER_TOO_SMALL,
            E::InvalidData => Self::HE_EXPRESSLANE_ERR_INVALID_DATA,
            E::Replayed => Self::HE_EXPRESSLANE_ERR_REPLAYED,
            E::KeyNotSet => Self::HE_EXPRESSLANE_ERR_KEY_NOT_SET,
            E::InvalidKey => Self::HE_EXPRESSLANE_ERR_INVALID_KEY,
        }
    }
}

/// ExpressLane wire-format version, matching `lightway_expresslane::ExpresslaneVersion`.
///
/// `he_expresslane_session_create` takes a raw `uint8_t` rather than this
/// enum type directly, so these constants are provided for callers to use
/// by name; cbindgen forces their emission via `cbindgen.toml`'s
/// `[export] include`.
#[repr(u8)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum he_expresslane_version_t {
    /// Not yet negotiated / not recognised by this build.
    HE_EXPRESSLANE_VERSION_UNKNOWN = 0,
    /// Initial ExpressLane wire format.
    HE_EXPRESSLANE_VERSION_1 = 1,
    /// Flags byte bound into the AEAD AAD.
    HE_EXPRESSLANE_VERSION_2 = 2,
}

// This C enum exists only so cbindgen emits the named version constants; the
// authoritative version type is `lightway_expresslane::ExpresslaneVersion`
// (which `he_expresslane_session_create` converts a raw u8 through). Keep the
// discriminants in lock-step so the constants a C caller passes actually map
// to the intended wire version.
const _: () = {
    use lightway_expresslane::ExpresslaneVersion;
    assert!(
        he_expresslane_version_t::HE_EXPRESSLANE_VERSION_UNKNOWN as u8 == ExpresslaneVersion::Unknown as u8
    );
    assert!(
        he_expresslane_version_t::HE_EXPRESSLANE_VERSION_1 as u8 == ExpresslaneVersion::Version1 as u8
    );
    assert!(
        he_expresslane_version_t::HE_EXPRESSLANE_VERSION_2 as u8 == ExpresslaneVersion::Version2 as u8
    );
};
