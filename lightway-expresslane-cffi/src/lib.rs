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
/// `version` is a raw byte (1 = V1, 2 = V2 — see `he_expresslane_version_t`).
/// The version selects the AEAD AAD layout (V2 binds the flags field, V1 does
/// not), so an unrecognized value — including 0
/// (`HE_EXPRESSLANE_VERSION_UNKNOWN`) — returns **NULL** rather than silently
/// running in V1 mode, which against a peer that negotiated the other version
/// would make every packet fail authentication with no distinguishing error.
///
/// Returns a heap-allocated pointer, or NULL for an unrecognized version.
/// (Allocation failure does not return NULL — Rust's default global allocator
/// aborts the process on OOM, which `ffi_guard` cannot intercept.) The caller
/// must free a non-NULL result with `he_expresslane_session_destroy`.
///
/// # Safety
/// The returned pointer must be freed with `he_expresslane_session_destroy`.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_session_create(
    version: u8,
) -> *mut he_expresslane_session_t {
    let version = ExpresslaneVersion::from(version);
    if version == ExpresslaneVersion::Unknown {
        return std::ptr::null_mut();
    }
    ffi_guard(std::ptr::null_mut(), || {
        Box::into_raw(Box::new(he_expresslane_session_t(ExpresslaneSession::new(
            version,
        ))))
    })
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
    if session.is_null() {
        return;
    }
    ffi_guard((), || {
        // SAFETY: pointer was created by Box::into_raw in
        // he_expresslane_session_create and is not used after this call.
        unsafe { drop(Box::from_raw(session)) };
    });
}

use lightway_expresslane::{EXPRESSLANE_KEY_SIZE, ExpresslaneKey};

/// Reserve a wire counter value for this session — unique per call until the
/// internal 64-bit counter wraps (after 2^64 reservations; unreachable in
/// practice). Safe to call concurrently from multiple threads on the same
/// session. Returns 0 if `session` is null; a live session returns 1, 2, 3, …
/// (0 recurs only after the astronomically distant wrap).
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
    ffi_guard(0, || {
        // SAFETY: null check above; session is valid for this call.
        unsafe { &*session }.0.reserve_counter()
    })
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
    ffi_guard((), || {
        // SAFETY: null check above; session is valid for this call.
        unsafe { &*session }.0.promote_self_key();
    });
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
    ffi_guard(0, || {
        // SAFETY: null check above; session is valid for this call.
        unsafe { &*session }.0.packets_sent()
    })
}

/// Encrypt `plain_text` into ExpressLane wire format. Safe to call
/// concurrently from multiple threads on the same session, provided each
/// call uses a unique `counter` (see `he_expresslane_reserve_counter`).
///
/// `out` must have capacity for at least
/// `he_expresslane_wire_overhead() + plain_text_len` bytes. On success,
/// `*out_len` is set to the number of bytes written to `out`.
///
/// # IV / nonce uniqueness (SECURITY-CRITICAL)
/// `iv` is the AES-GCM nonce. The caller MUST supply a fresh, unpredictable
/// 12-byte `iv` for every packet encrypted under a given key. Reusing a
/// `(key, iv)` pair is catastrophic for AES-GCM — it leaks the XOR of the
/// plaintexts and enables forgery of arbitrary packets. The `counter` is
/// authenticated but is NOT the nonce; a unique `counter` does not make the
/// `iv` unique. This library has no RNG and cannot enforce this.
///
/// # Safety
/// `session` must be a valid non-null pointer. `session_id` must point to 8
/// readable bytes. `plain_text` must point to `plain_text_len` readable
/// bytes (it may be NULL when `plain_text_len` is 0 — the conventional C
/// idiom for an empty payload). `iv` must point to 12 readable bytes. `out`
/// must point to `out_capacity` writable bytes and must NOT overlap any of
/// the input buffers. `out_len` must be a valid pointer to a `size_t`.
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
        || (plain_text.is_null() && plain_text_len > 0)
        || iv.is_null()
        || out.is_null()
        || out_len.is_null()
    {
        return he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_NULL_POINTER;
    }
    ffi_guard(he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_PANIC, || {
        // SAFETY: null checks above; session_id is valid for 8 bytes per
        // this function's documented contract.
        let session_id_bytes: [u8; 8] =
            unsafe { std::slice::from_raw_parts(session_id, 8) }.try_into().unwrap();
        let plain_text_slice: &[u8] = if plain_text_len == 0 {
            // NULL is permitted for an empty payload; from_raw_parts requires
            // a non-null pointer even for len 0, so use a literal empty slice.
            &[]
        } else {
            // SAFETY: null/len checks above; plain_text is non-null and valid
            // for plain_text_len bytes per this function's documented contract.
            unsafe { std::slice::from_raw_parts(plain_text, plain_text_len) }
        };
        // SAFETY: null checks above; iv is valid for 12 bytes per this
        // function's documented contract.
        let iv_bytes: [u8; 12] = unsafe { std::slice::from_raw_parts(iv, 12) }.try_into().unwrap();
        // SAFETY: null checks above; out is valid and writable for
        // out_capacity bytes per this function's documented contract.
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

/// Install a new peer (receive) key. The previous peer key becomes the
/// fallback used by `he_expresslane_decrypt` for packets still in flight
/// from before the peer's rotation. Returns
/// `HE_EXPRESSLANE_ERR_INVALID_KEY` for an all-zero key.
///
/// The receive-side calls (`he_expresslane_decrypt`, this function,
/// `he_expresslane_has_valid_keys`, `he_expresslane_packets_received`) are
/// serialized internally per session, so this is safe to call from any
/// thread; concurrent RX calls simply take turns.
///
/// # Safety
/// `session` must be a valid non-null pointer. `key` must point to 32
/// readable bytes.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_set_peer_key(
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
            .update_peer_key(ExpresslaneKey::from(key_bytes))
        {
            Ok(()) => he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS,
            Err(e) => e.into(),
        }
    })
}

/// True if both a self (send) key and a peer (receive) key are installed.
/// Serialized internally with the other receive-side calls, so safe to call
/// from any thread.
///
/// # Safety
/// `session` must be a valid non-null pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_has_valid_keys(
    session: *const he_expresslane_session_t,
) -> bool {
    if session.is_null() {
        return false;
    }
    ffi_guard(false, || {
        // SAFETY: null check above; session is valid for this call.
        unsafe { &*session }.0.has_valid_keys()
    })
}

/// Total number of packets successfully decrypted so far on this session.
/// Serialized internally with the other receive-side calls, so safe to call
/// from any thread.
///
/// # Safety
/// `session` must be a valid non-null pointer or null.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_packets_received(
    session: *const he_expresslane_session_t,
) -> u64 {
    if session.is_null() {
        return 0;
    }
    ffi_guard(0, || {
        // SAFETY: null check above; session is valid for this call.
        unsafe { &*session }.0.packets_received()
    })
}

/// Decrypt `wire_packet` (ExpressLane wire format) into `out`. `out` must
/// have capacity for at least `wire_packet_len - he_expresslane_wire_overhead()`
/// bytes. On success, `*out_len` is set to the plaintext length and
/// `*is_encoded` to the packet's encoded flag. The receive-side calls
/// (`he_expresslane_set_peer_key`, `he_expresslane_has_valid_keys`,
/// `he_expresslane_packets_received` and this one) are serialized internally
/// per session, so this is safe to call from any thread.
///
/// # Safety
/// `session` must be a valid non-null pointer. `session_id` must point to 8
/// readable bytes. `wire_packet` must point to `wire_packet_len` readable
/// bytes. `out` must point to `out_capacity` writable bytes (it may be NULL
/// when `out_capacity` is 0, e.g. for a packet known to carry an empty
/// payload) and must NOT overlap `wire_packet`. `out_len` and `is_encoded`
/// must be valid pointers.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn he_expresslane_decrypt(
    session: *const he_expresslane_session_t,
    session_id: *const u8,
    wire_packet: *const u8,
    wire_packet_len: usize,
    out: *mut u8,
    out_capacity: usize,
    out_len: *mut usize,
    is_encoded: *mut bool,
) -> he_expresslane_return_code_t {
    if session.is_null()
        || session_id.is_null()
        || wire_packet.is_null()
        || (out.is_null() && out_capacity > 0)
        || out_len.is_null()
        || is_encoded.is_null()
    {
        return he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_NULL_POINTER;
    }
    ffi_guard(he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_PANIC, || {
        // SAFETY: null checks above; session_id is valid for 8 bytes per
        // this function's documented contract.
        let session_id_bytes: [u8; 8] =
            unsafe { std::slice::from_raw_parts(session_id, 8) }.try_into().unwrap();
        // SAFETY: null checks above; wire_packet is valid for
        // wire_packet_len bytes per this function's documented contract.
        let wire_slice = unsafe { std::slice::from_raw_parts(wire_packet, wire_packet_len) };
        let out_slice: &mut [u8] = if out_capacity == 0 {
            // NULL is permitted for a zero-capacity output buffer;
            // from_raw_parts_mut requires a non-null pointer even for len 0.
            &mut []
        } else {
            // SAFETY: null/len checks above; out is non-null, writable for
            // out_capacity bytes per this function's documented contract.
            unsafe { std::slice::from_raw_parts_mut(out, out_capacity) }
        };

        // SAFETY: null check above; session is valid for this call.
        let result = unsafe { &*session }.0.decrypt(session_id_bytes, wire_slice, out_slice);
        match result {
            Ok((len, encoded)) => {
                // SAFETY: null checks above; out_len/is_encoded are valid
                // writable pointers per the function's documented contract.
                unsafe {
                    *out_len = len;
                    *is_encoded = encoded;
                }
                he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS
            }
            Err(e) => e.into(),
        }
    })
}

/// Wire overhead in bytes (40): counter(8) + iv(12) + tag(16) + data_len(2)
/// + flags(2).
///
/// Use this to size buffers for `he_expresslane_encrypt` /
/// `he_expresslane_decrypt` without hardcoding the constant.
#[unsafe(no_mangle)]
pub extern "C" fn he_expresslane_wire_overhead() -> usize {
    ExpresslaneSession::WIRE_OVERHEAD
}

#[cfg(test)]
// Test bodies are dense with FFI calls; a `// SAFETY:` on each `unsafe` block
// would be pure noise. The invariants are the same ones the function docs
// state and the non-test callers must uphold.
#[allow(clippy::undocumented_unsafe_blocks)]
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
    fn create_with_unknown_version_byte_returns_null() {
        // An unrecognized version selects no AAD layout, so it is rejected
        // rather than silently running in V1 mode.
        assert!(unsafe { he_expresslane_session_create(255) }.is_null());
        assert!(unsafe { he_expresslane_session_create(0) }.is_null());
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

    #[test]
    fn wire_overhead_is_40() {
        assert_eq!(he_expresslane_wire_overhead(), 40);
    }

    #[test]
    fn has_valid_keys_false_until_both_keys_set() {
        let session = unsafe { he_expresslane_session_create(2) };
        assert!(!unsafe { he_expresslane_has_valid_keys(session) });

        let key = [1u8; 32];
        unsafe { he_expresslane_set_next_self_key(session, key.as_ptr()) };
        unsafe { he_expresslane_promote_self_key(session) };
        assert!(!unsafe { he_expresslane_has_valid_keys(session) }); // peer still missing

        assert_eq!(
            unsafe { he_expresslane_set_peer_key(session, key.as_ptr()) },
            he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS
        );
        assert!(unsafe { he_expresslane_has_valid_keys(session) });

        unsafe { he_expresslane_session_destroy(session) };
    }

    #[test]
    fn encrypt_then_decrypt_round_trips_through_the_c_api() {
        let sender = unsafe { he_expresslane_session_create(2) };
        let receiver = unsafe { he_expresslane_session_create(2) };
        let key = [42u8; 32];

        unsafe { he_expresslane_set_next_self_key(sender, key.as_ptr()) };
        unsafe { he_expresslane_promote_self_key(sender) };
        unsafe { he_expresslane_set_peer_key(receiver, key.as_ptr()) };

        let session_id = [1u8; 8];
        let plain_text = b"Hello, ExpressLane!";
        let iv = [9u8; 12];
        let overhead = he_expresslane_wire_overhead();

        let mut wire = vec![0u8; overhead + plain_text.len()];
        let mut wire_len: usize = 0;
        let counter = unsafe { he_expresslane_reserve_counter(sender) };
        let rc = unsafe {
            he_expresslane_encrypt(
                sender,
                counter,
                session_id.as_ptr(),
                plain_text.as_ptr(),
                plain_text.len(),
                iv.as_ptr(),
                false,
                wire.as_mut_ptr(),
                wire.len(),
                &mut wire_len,
            )
        };
        assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS);

        let mut out = vec![0u8; plain_text.len()];
        let mut out_len: usize = 0;
        let mut is_encoded = true; // must be overwritten to false
        let rc = unsafe {
            he_expresslane_decrypt(
                receiver,
                session_id.as_ptr(),
                wire.as_ptr(),
                wire_len,
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
                &mut is_encoded,
            )
        };
        assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS);
        assert_eq!(out_len, plain_text.len());
        assert!(!is_encoded);
        assert_eq!(&out[..out_len], plain_text);
        assert_eq!(unsafe { he_expresslane_packets_received(receiver) }, 1);

        unsafe { he_expresslane_session_destroy(sender) };
        unsafe { he_expresslane_session_destroy(receiver) };
    }

    #[test]
    fn decrypt_without_key_returns_key_not_set() {
        let receiver = unsafe { he_expresslane_session_create(2) };
        let session_id = [1u8; 8];
        let wire = vec![0u8; he_expresslane_wire_overhead()];
        let mut out = vec![0u8; 4];
        let mut out_len: usize = 0;
        let mut is_encoded = false;

        let rc = unsafe {
            he_expresslane_decrypt(
                receiver,
                session_id.as_ptr(),
                wire.as_ptr(),
                wire.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
                &mut is_encoded,
            )
        };
        assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_KEY_NOT_SET);
        unsafe { he_expresslane_session_destroy(receiver) };
    }

    #[test]
    fn empty_payload_round_trips_with_null_buffers() {
        // C convention: NULL + len 0 is a valid empty payload on encrypt, and
        // NULL + capacity 0 a valid output buffer for it on decrypt.
        let sender = unsafe { he_expresslane_session_create(2) };
        let receiver = unsafe { he_expresslane_session_create(2) };
        let key = [42u8; 32];
        unsafe { he_expresslane_set_next_self_key(sender, key.as_ptr()) };
        unsafe { he_expresslane_promote_self_key(sender) };
        unsafe { he_expresslane_set_peer_key(receiver, key.as_ptr()) };

        let session_id = [1u8; 8];
        let iv = [7u8; 12];
        let mut wire = vec![0u8; he_expresslane_wire_overhead()];
        let mut wire_len: usize = 0;
        let rc = unsafe {
            he_expresslane_encrypt(
                sender,
                1,
                session_id.as_ptr(),
                std::ptr::null(), // empty payload
                0,
                iv.as_ptr(),
                false,
                wire.as_mut_ptr(),
                wire.len(),
                &mut wire_len,
            )
        };
        assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS);
        assert_eq!(wire_len, he_expresslane_wire_overhead());

        let mut out_len: usize = 99;
        let mut is_encoded = true;
        let rc = unsafe {
            he_expresslane_decrypt(
                receiver,
                session_id.as_ptr(),
                wire.as_ptr(),
                wire_len,
                std::ptr::null_mut(), // zero-capacity output
                0,
                &mut out_len,
                &mut is_encoded,
            )
        };
        assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_SUCCESS);
        assert_eq!(out_len, 0);
        assert!(!is_encoded);

        // NULL with a non-zero length is still rejected.
        let rc = unsafe {
            he_expresslane_encrypt(
                sender,
                2,
                session_id.as_ptr(),
                std::ptr::null(),
                1,
                iv.as_ptr(),
                false,
                wire.as_mut_ptr(),
                wire.len(),
                &mut wire_len,
            )
        };
        assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_NULL_POINTER);

        unsafe { he_expresslane_session_destroy(sender) };
        unsafe { he_expresslane_session_destroy(receiver) };
    }

    #[test]
    fn decrypt_null_pointers_return_null_pointer_error() {
        let receiver = unsafe { he_expresslane_session_create(2) };
        let session_id = [1u8; 8];
        let wire = vec![0u8; he_expresslane_wire_overhead()];
        let mut out = vec![0u8; 4];
        let mut out_len: usize = 0;
        let mut is_encoded = false;

        let rc = unsafe {
            he_expresslane_decrypt(
                std::ptr::null_mut(),
                session_id.as_ptr(),
                wire.as_ptr(),
                wire.len(),
                out.as_mut_ptr(),
                out.len(),
                &mut out_len,
                &mut is_encoded,
            )
        };
        assert_eq!(rc, he_expresslane_return_code_t::HE_EXPRESSLANE_ERR_NULL_POINTER);
        unsafe { he_expresslane_session_destroy(receiver) };
    }
}
