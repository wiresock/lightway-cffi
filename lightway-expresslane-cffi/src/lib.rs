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

use lightway_expresslane::{EXPRESSLANE_KEY_SIZE, ExpresslaneKey};

/// Reserve a wire counter value guaranteed unique for this session. Safe to
/// call concurrently from multiple threads on the same session. Returns 0
/// if `session` is null (0 is never a value `reserve_counter` itself would
/// return, since it starts at 1).
///
/// # Safety
/// `session` must be a valid non-null pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_reserve_counter(
    session: *const he_expresslane_session_t,
) -> u64 {
    if session.is_null() {
        return 0;
    }
    // SAFETY: null check above; session is valid for this call.
    unsafe { &*session }.0.reserve_counter()
}

/// Stage a new "next self" key. Call `he_expresslane_promote_self_key` once
/// the peer has acknowledged the rotation to make it the active send key.
/// Safe to call concurrently with `he_expresslane_encrypt` on the same
/// session.
///
/// # Safety
/// `session` must be a valid non-null pointer. `key` must point to 32
/// readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_set_next_self_key(
    session: *const he_expresslane_session_t,
    key: *const u8,
) -> he_expresslane_return_code_t {
    if session.is_null() || key.is_null() {
        return he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_NULL_POINTER;
    }
    ffi_guard(he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_PANIC, || {
        // SAFETY: null checks above; key points to EXPRESSLANE_KEY_SIZE
        // readable bytes per the function's documented contract.
        let key_bytes: [u8; EXPRESSLANE_KEY_SIZE] =
            unsafe { std::slice::from_raw_parts(key, EXPRESSLANE_KEY_SIZE) }
                .try_into()
                .expect("slice has exactly EXPRESSLANE_KEY_SIZE bytes");
        // SAFETY: null check above; session is valid for this call.
        match unsafe { &*session }
            .0
            .update_next_self_key(ExpresslaneKey::from(key_bytes))
        {
            Ok(()) => he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS,
            Err(e) => e.into(),
        }
    })
}

/// Promote the staged "next self" key to the active send key. A no-op if
/// no key is staged. Safe to call concurrently with `he_expresslane_encrypt`
/// on the same session.
///
/// # Safety
/// `session` must be a valid non-null pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_promote_self_key(
    session: *const he_expresslane_session_t,
) {
    if session.is_null() {
        return;
    }
    // SAFETY: null check above; session is valid for this call.
    unsafe { &*session }.0.promote_self_key();
}

/// Total number of packets successfully encrypted so far on this session.
///
/// # Safety
/// `session` must be a valid non-null pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_packets_sent(
    session: *const he_expresslane_session_t,
) -> u64 {
    if session.is_null() {
        return 0;
    }
    // SAFETY: null check above; session is valid for this call.
    unsafe { &*session }.0.packets_sent()
}

/// Encrypt `plain_text` into ExpressLane wire format. Safe to call
/// concurrently from multiple threads on the same session, provided each
/// call uses a unique `counter` (see `he_expresslane_reserve_counter`).
///
/// `out` must have capacity for at least
/// `he_expresslane_wire_overhead() + plain_text_len` bytes. On success,
/// `*out_len` is set to the number of bytes written to `out`.
///
/// # Safety
/// `session` must be a valid non-null pointer. `session_id` must point to 8
/// readable bytes. `plain_text` must point to `plain_text_len` readable
/// bytes. `iv` must point to 12 readable bytes. `out` must point to
/// `out_capacity` writable bytes. `out_len` must be a valid pointer to a
/// `size_t`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_encrypt(
    session: *const he_expresslane_session_t,
    counter: u64,
    session_id: *const u8,
    plain_text: *const u8,
    plain_text_len: usize,
    iv: *const u8,
    is_encoded: bool,
    out: *mut u8,
    out_capacity: usize,
    out_len: *mut usize,
) -> he_expresslane_return_code_t {
    if session.is_null()
        || session_id.is_null()
        || plain_text.is_null()
        || iv.is_null()
        || out.is_null()
        || out_len.is_null()
    {
        return he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_NULL_POINTER;
    }
    ffi_guard(he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_PANIC, || {
        // SAFETY: null checks above; each pointer is valid for the length
        // documented in this function's `# Safety` section.
        let session_id_bytes: [u8; 8] =
            unsafe { std::slice::from_raw_parts(session_id, 8) }.try_into().unwrap();
        let plain_text_slice = unsafe { std::slice::from_raw_parts(plain_text, plain_text_len) };
        let iv_bytes: [u8; 12] = unsafe { std::slice::from_raw_parts(iv, 12) }.try_into().unwrap();
        let out_slice = unsafe { std::slice::from_raw_parts_mut(out, out_capacity) };

        // SAFETY: null check above; session is valid for this call.
        let result = unsafe { &*session }.0.encrypt(
            counter,
            session_id_bytes,
            plain_text_slice,
            iv_bytes,
            is_encoded,
            out_slice,
        );
        match result {
            Ok(written) => {
                // SAFETY: null check above; out_len is a valid pointer to a
                // writable size_t per the function's documented contract.
                unsafe { *out_len = written };
                he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS
            }
            Err(e) => e.into(),
        }
    })
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

    #[test]
    fn reserve_counter_increments() {
        let session = unsafe { he_expresslane_session_create(2) };
        assert_eq!(unsafe { he_expresslane_reserve_counter(session) }, 1);
        assert_eq!(unsafe { he_expresslane_reserve_counter(session) }, 2);
        unsafe { he_expresslane_session_destroy(session) };
    }

    #[test]
    fn reserve_counter_null_session_returns_zero() {
        assert_eq!(unsafe { he_expresslane_reserve_counter(std::ptr::null()) }, 0);
    }

    #[test]
    fn set_next_self_key_null_pointers_return_null_pointer_error() {
        let session = unsafe { he_expresslane_session_create(2) };
        let key = [1u8; 32];
        assert_eq!(
            unsafe { he_expresslane_set_next_self_key(std::ptr::null(), key.as_ptr()) },
            he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_NULL_POINTER
        );
        assert_eq!(
            unsafe { he_expresslane_set_next_self_key(session, std::ptr::null()) },
            he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_NULL_POINTER
        );
        unsafe { he_expresslane_session_destroy(session) };
    }

    #[test]
    fn set_and_promote_key_then_encrypt_succeeds() {
        let session = unsafe { he_expresslane_session_create(2) };
        let key = [1u8; 32];
        assert_eq!(
            unsafe { he_expresslane_set_next_self_key(session, key.as_ptr()) },
            he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS
        );
        unsafe { he_expresslane_promote_self_key(session) };

        let session_id = [1u8; 8];
        let plain_text = b"test data";
        let iv = [0u8; 12];
        let mut out = vec![0u8; lightway_expresslane::ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let mut out_len: usize = 0;

        let counter = unsafe { he_expresslane_reserve_counter(session) };
        let rc = unsafe {
            he_expresslane_encrypt(
                session,
                counter,
                session_id.as_ptr(),
                plain_text.as_ptr(),
                plain_text.len(),
                iv.as_ptr(),
                false,
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
            )
        };
        assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS);
        assert_eq!(out_len, out.len());

        assert_eq!(unsafe { he_expresslane_packets_sent(session) }, 1);
        unsafe { he_expresslane_session_destroy(session) };
    }

    #[test]
    fn encrypt_without_key_returns_key_not_set() {
        let session = unsafe { he_expresslane_session_create(2) };
        let session_id = [1u8; 8];
        let plain_text = b"test";
        let iv = [0u8; 12];
        let mut out = vec![0u8; lightway_expresslane::ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let mut out_len: usize = 0;

        let rc = unsafe {
            he_expresslane_encrypt(
                session,
                1,
                session_id.as_ptr(),
                plain_text.as_ptr(),
                plain_text.len(),
                iv.as_ptr(),
                false,
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
            )
        };
        assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_KEY_NOT_SET);
        unsafe { he_expresslane_session_destroy(session) };
    }

    #[test]
    fn encrypt_buffer_too_small_returns_error() {
        let session = unsafe { he_expresslane_session_create(2) };
        let key = [1u8; 32];
        unsafe { he_expresslane_set_next_self_key(session, key.as_ptr()) };
        unsafe { he_expresslane_promote_self_key(session) };

        let session_id = [1u8; 8];
        let plain_text = b"test";
        let iv = [0u8; 12];
        let mut out = vec![0u8; 4]; // too small
        let mut out_len: usize = 0;

        let rc = unsafe {
            he_expresslane_encrypt(
                session,
                1,
                session_id.as_ptr(),
                plain_text.as_ptr(),
                plain_text.len(),
                iv.as_ptr(),
                false,
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
            )
        };
        assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_BUFFER_TOO_SMALL);
        unsafe { he_expresslane_session_destroy(session) };
    }
}
