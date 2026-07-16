//! lightway-expresslane-cffi: C ABI for `lightway-expresslane`.
//!
//! Exposes ExpressLane data-packet encrypt/decrypt as a standalone C API,
//! independent of the full `lightway-cffi` client (`he_conn_t`), for
//! out-of-process packet crypto (e.g. a Windows driver-adjacent process).
//! Deliberately has no wolfssl/TLS dependency.

#![deny(unsafe_op_in_unsafe_fn)]
#![warn(missing_docs)]
#![allow(non_camel_case_types, non_upper_case_globals, clippy::upper_case_acronyms)]

use std::panic::{AssertUnwindSafe, catch_unwind};

pub mod types;

use lightway_expresslane::{ExpresslaneSession, ExpresslaneVersion};
use types::he_expresslane_version_t;

pub use types::he_expresslane_return_code_t;

/// Run an FFI entry-point body, converting any panic into `default` instead
/// of letting it unwind across the C ABI boundary (which aborts the
/// process).
#[inline]
fn ffi_guard<R>(default: R, f: impl FnOnce() -> R) -> R {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(default)
}

/// Opaque ExpressLane packet-crypto session handle.
pub struct he_expresslane_session_t(ExpresslaneSession);

/// Allocate a new ExpressLane session for the given wire version.
///
/// `version` is a raw byte (0 = unknown, 1 = V1, 2 = V2 — see
/// `he_expresslane_version_t`) rather than the enum type directly, so an
/// out-of-range value from C falls back to `HE_EXPRESSLANE_VERSION_UNKNOWN`
/// instead of being reinterpreted as an invalid discriminant.
///
/// Returns a heap-allocated pointer. The caller must free it with
/// `he_expresslane_session_destroy`.
///
/// # Safety
/// The returned pointer must be freed with `he_expresslane_session_destroy`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_session_create(
    version: u8,
) -> *mut he_expresslane_session_t {
    let version = ExpresslaneVersion::from(version);
    Box::into_raw(Box::new(he_expresslane_session_t(ExpresslaneSession::new(
        version,
    ))))
}

/// Free a session previously allocated by `he_expresslane_session_create`.
///
/// # Safety
/// `session` must be a valid pointer obtained from
/// `he_expresslane_session_create` and must not be used after this call.
/// The caller must ensure no other thread is calling any
/// `he_expresslane_*` function on this handle concurrently with (or after)
/// destruction.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_session_destroy(session: *mut he_expresslane_session_t) {
    if !session.is_null() {
        // SAFETY: pointer was created by Box::into_raw in
        // he_expresslane_session_create.
        unsafe { drop(Box::from_raw(session)) };
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn create_and_destroy() {
        let session = unsafe { he_expresslane_session_create(2) };
        assert!(!session.is_null());
        unsafe { he_expresslane_session_destroy(session) };
    }

    #[test]
    fn destroy_null_is_a_no_op() {
        unsafe { he_expresslane_session_destroy(std::ptr::null_mut()) };
    }

    #[test]
    fn create_with_unknown_version_byte_falls_back_safely() {
        let session = unsafe { he_expresslane_session_create(255) };
        assert!(!session.is_null());
        unsafe { he_expresslane_session_destroy(session) };
    }
}
