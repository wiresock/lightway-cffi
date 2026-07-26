//! ExpressLane packet session: key rotation state, replay window, and
//! encrypt/decrypt.

use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use crate::cipher::Cipher;
use crate::error::{ExpresslaneError, ExpresslaneResult};
use crate::key::ExpresslaneKey;
use crate::replay_window::ReplayWindow;
use crate::version::ExpresslaneVersion;

/// The `is_encoded` bit within the 16-bit wire flags field.
const FLAG_ENCODED: u16 = 0x8000;

/// Build the AEAD associated data for an ExpressLane data packet.
/// Returns a fixed-size buffer and the number of significant bytes.
///
/// For `Version2` the **full** 16-bit `flags` field — including the 15
/// reserved bits — is bound into the AAD, exactly as `lightway-core` does, so
/// that flipping any flags bit on the wire fails authentication. For
/// `Version1` (and `Unknown`) the flags are not part of the AAD.
fn build_aad(
    version: ExpresslaneVersion,
    session_id: [u8; 8],
    counter: u64,
    flags: u16,
) -> ([u8; 18], usize) {
    let mut buf = [0u8; 18];
    buf[..8].copy_from_slice(&session_id);
    buf[8..16].copy_from_slice(&counter.to_be_bytes());
    if version >= ExpresslaneVersion::Version2 {
        buf[16..].copy_from_slice(&flags.to_be_bytes());
        (buf, 18)
    } else {
        (buf, 16)
    }
}

/// An ExpressLane packet-crypto session: key rotation state, replay
/// window, and encrypt/decrypt.
///
/// Every method takes `&self` and the session is `Sync`, so all methods are
/// safe to call from any thread on a shared handle. The original rationale is
/// `docs/superpowers/specs/2026-07-16-expresslane-data-cffi-design.md`'s
/// "Parallel encrypt" section in the `lightway-cffi` repo — a dated design
/// record, so read it for the reasoning and this doc for the current contract;
/// it predates `has_valid_keys` becoming lock-free and still describes that
/// call as taking the `rx` lock.
///
/// - The `encrypt()` path is read-lock-only on `current_self` plus relaxed
///   atomics, so many threads encrypt concurrently at full throughput. Key
///   installation is NOT lock-free: `update_next_self_key` and
///   `promote_self_key` take the `next_self` mutex, and `promote_self_key`
///   additionally takes the `current_self` write lock, which does briefly block
///   encryptors.
/// - RX state (`current_peer`, `prev_peer`, `replay_window`) is serialized as
///   a unit behind `rx`. The replay-window bitmap update is inherently
///   ordered and a single RX thread per session is the common case, so this
///   lock is uncontended by design; it exists so a stray concurrent RX call
///   is merely serialized rather than undefined behavior.
///
/// (The `rx` mutex is `std::sync::Mutex` for now; a future `no_std`/kernel
/// port would swap it for a `no_std` mutex — see the design doc's "Forward
/// compatibility" section.)
pub struct ExpresslaneSession {
    version: ExpresslaneVersion,

    // TX state — concurrent-safe.
    current_self: RwLock<Option<Cipher>>,
    next_self: Mutex<Option<Cipher>>,
    next_counter: AtomicU64,
    packets_sent: AtomicU64,

    // RX state — serialized as a unit by this mutex.
    rx: Mutex<RxState>,

    // Lock-free mirrors of "a self key / a peer key has been installed", read
    // by `has_valid_keys`. Monotonic (only ever stored `true`, never back) but
    // deliberately NOT in lockstep with the `Option`s above — they are a hint
    // that selects a path, never a fact anything relies on. See that method for
    // the full argument and for why `Relaxed` is the right ordering rather than
    // a weakness to be upgraded away.
    self_key_installed: AtomicBool,
    peer_key_installed: AtomicBool,
}

/// Receive-side session state, serialized as a unit by `ExpresslaneSession::rx`.
struct RxState {
    current_peer: Option<Cipher>,
    prev_peer: Option<Cipher>,
    replay_window: ReplayWindow,
}

impl ExpresslaneSession {
    /// Wire overhead in bytes: 8 (counter) + 12 (iv) + 16 (tag) + 2
    /// (data length) + 2 (flags).
    pub const WIRE_OVERHEAD: usize = 40;

    /// Create a new session with no keys installed.
    pub fn new(version: ExpresslaneVersion) -> Self {
        Self {
            version,
            current_self: RwLock::new(None),
            next_self: Mutex::new(None),
            next_counter: AtomicU64::new(0),
            packets_sent: AtomicU64::new(0),
            rx: Mutex::new(RxState {
                current_peer: None,
                prev_peer: None,
                replay_window: ReplayWindow::default(),
            }),
            self_key_installed: AtomicBool::new(false),
            peer_key_installed: AtomicBool::new(false),
        }
    }

    // ---- TX domain: safe to call concurrently from multiple threads. ----

    /// Reserve a wire counter value for this session: a lock-free atomic
    /// increment, so no two concurrent callers ever receive the same value.
    /// The sequence repeats only after wrapping at `u64::MAX` — deliberate, see
    /// the body and `reserve_counter_wraps_through_zero_without_panicking` — so
    /// this is NOT a uniqueness guarantee a nonce may be derived from; see
    /// `encrypt`'s IV contract. Use the returned value as `counter` in the next
    /// `encrypt()` call, unless the caller has its own uniqueness guarantee
    /// across every thread encrypting on this session.
    pub fn reserve_counter(&self) -> u64 {
        // Matches upstream lightway-core: first packet is counter 1, not 0.
        // `wrapping_add` avoids a debug-build overflow panic at u64::MAX; the
        // release-mode wrap (MAX, 0, 1) matches lightway-core's
        // `wire_counter.wrapping_add(1)` sequence.
        self.next_counter.fetch_add(1, Ordering::Relaxed).wrapping_add(1)
    }

    /// Seed the internal counter (test-only) so the wraparound at `u64::MAX`
    /// can be exercised without 2^64 reservations.
    #[cfg(test)]
    fn seed_counter_for_test(&self, v: u64) {
        self.next_counter.store(v, Ordering::Relaxed);
    }

    /// Stage a new "next self" key. Call `promote_self_key` once the peer
    /// has acknowledged the rotation to make it the active send key.
    ///
    /// Returns [`ExpresslaneError::InvalidKey`] for the all-zero
    /// [`ExpresslaneKey::INVALID`] sentinel, which the upstream key-delivery
    /// callback can emit before the self key has been promoted; installing it
    /// would encrypt under a publicly-known key.
    pub fn update_next_self_key(&self, key: ExpresslaneKey) -> ExpresslaneResult<()> {
        if key.is_invalid() {
            return Err(ExpresslaneError::InvalidKey);
        }
        let cipher = Cipher::new(&key)?;
        *self.next_self.lock().unwrap_or_else(|e| e.into_inner()) = Some(cipher);
        Ok(())
    }

    /// Promote the staged "next self" key to the active send key. A no-op
    /// if no key is staged.
    pub fn promote_self_key(&self) {
        let mut next = self.next_self.lock().unwrap_or_else(|e| e.into_inner());
        if let Some(cipher) = next.take() {
            *self.current_self.write().unwrap_or_else(|e| e.into_inner()) = Some(cipher);
            // Set inside the arm, so a promote with nothing staged stays the
            // no-op it has always been.
            self.self_key_installed.store(true, Ordering::Relaxed);
        }
    }

    /// Total number of packets successfully encrypted so far.
    pub fn packets_sent(&self) -> u64 {
        self.packets_sent.load(Ordering::Relaxed)
    }

    /// Encrypt `plain_text` into ExpressLane wire format, writing into
    /// `out`. `out` must have capacity for at least
    /// `WIRE_OVERHEAD + plain_text.len()` bytes. `counter` must be unique
    /// for this session — see `reserve_counter`. Returns the number of
    /// bytes written to `out`.
    ///
    /// # IV / nonce uniqueness (security-critical)
    ///
    /// `iv` is the AES-GCM nonce. The caller MUST supply a UNIQUE 12-byte
    /// `iv` for every packet encrypted under a given key — either a
    /// deterministic construction that cannot repeat (e.g. derived from a
    /// per-key message counter) or random generation from a CSPRNG when no
    /// such guarantee exists. Predictability is not the concern; repetition
    /// is: reusing a `(key, iv)` pair is catastrophic for AES-GCM — it leaks
    /// the XOR of the two plaintexts and allows recovery of the GHASH
    /// authentication key, i.e. arbitrary packet forgery. The wire `counter`
    /// is authenticated via the AAD but is NOT the nonce and does not by
    /// itself guarantee nonce uniqueness. This crate has no RNG and cannot
    /// enforce this.
    pub fn encrypt(
        &self,
        counter: u64,
        session_id: [u8; 8],
        plain_text: &[u8],
        iv: [u8; 12],
        is_encoded: bool,
        out: &mut [u8],
    ) -> ExpresslaneResult<usize> {
        let needed = Self::WIRE_OVERHEAD + plain_text.len();
        if out.len() < needed {
            return Err(ExpresslaneError::BufferTooSmall);
        }
        if plain_text.len() > u16::MAX as usize {
            return Err(ExpresslaneError::InvalidData);
        }

        let guard = self.current_self.read().unwrap_or_else(|e| e.into_inner());
        let cipher = guard.as_ref().ok_or(ExpresslaneError::KeyNotSet)?;

        // Reserved flag bits are always zero on send; the full 16-bit field is
        // bound into the V2 AAD (see `build_aad`) and written to the wire.
        let flags: u16 = if is_encoded { FLAG_ENCODED } else { 0 };
        let (aad_buf, aad_len) = build_aad(self.version, session_id, counter, flags);

        out[8..20].copy_from_slice(&iv);
        out[40..needed].copy_from_slice(plain_text);
        let tag = match cipher.encrypt(&iv, &aad_buf[..aad_len], &mut out[40..needed]) {
            Ok(tag) => tag,
            Err(e) => {
                // Unreachable in practice (plain_text.len() is capped at
                // u16::MAX, far below AES-GCM's length limit), but never leave
                // the caller's plaintext sitting in `out` on an error return.
                out[40..needed].fill(0);
                return Err(e);
            }
        };
        drop(guard);

        out[0..8].copy_from_slice(&counter.to_be_bytes());
        out[20..36].copy_from_slice(&tag);
        out[36..38].copy_from_slice(&(plain_text.len() as u16).to_be_bytes());
        out[38..40].copy_from_slice(&flags.to_be_bytes());

        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        Ok(needed)
    }

    // ---- RX domain: `update_peer_key`, `packets_received` and `decrypt` take
    // `self.rx` and are serialized as a unit; safe to call from any thread
    // (concurrent RX calls simply take turns). `has_valid_keys` sits below with
    // them for readability but is the exception — it takes no lock and reads TX
    // state as well; see its doc. ----

    /// Install a new peer (receive) key. The previous peer key becomes the
    /// fallback used by `decrypt` for packets still in flight from before
    /// the peer's rotation.
    ///
    /// Returns [`ExpresslaneError::InvalidKey`] for the all-zero
    /// [`ExpresslaneKey::INVALID`] sentinel.
    pub fn update_peer_key(&self, key: ExpresslaneKey) -> ExpresslaneResult<()> {
        if key.is_invalid() {
            return Err(ExpresslaneError::InvalidKey);
        }
        let cipher = Cipher::new(&key)?;
        let mut rx = self.rx.lock().unwrap_or_else(|e| e.into_inner());
        rx.prev_peer = rx.current_peer.replace(cipher);
        self.peer_key_installed.store(true, Ordering::Relaxed);
        Ok(())
    }

    /// True if both a self (send) key and a peer (receive) key are
    /// installed.
    ///
    /// Lock-free by design. The TX path calls this per outbound packet purely
    /// to decide whether to use the fast path, and taking the `rx` mutex to
    /// answer it made every outbound packet contend with an inbound `decrypt`
    /// that holds `rx` across its whole AEAD — a cross-direction coupling that
    /// gets worse as the inbound rate rises.
    ///
    /// What the flags guarantee is MONOTONICITY, not simultaneity. Each is only
    /// ever stored `true` — never back to `false` — by the sole writer of the
    /// `Option` it tracks (`promote_self_key` for `current_self`,
    /// `update_peer_key` for `current_peer`), and neither `Option` ever returns
    /// to `None`. The stores are idempotent and repeat on every rotation, so do
    /// not hang first-install side effects off them; what holds is that the
    /// value transitions at most once, so a `true` answer can never become
    /// `false` again.
    ///
    /// They are NOT in lockstep with those `Option`s, and must not be described
    /// as such: this reads both flags without taking either lock, so it sees two
    /// independent `Relaxed` writes. A caller can therefore observe `false`
    /// briefly after a key really is installed. That is harmless — the TX path
    /// simply does not take the fast path for that packet — and it is the only
    /// direction that can happen in practice.
    ///
    /// The dangerous direction, a `true` answer with no usable key, cannot
    /// mislead anyone: `encrypt` and `decrypt` re-check `Option::is_some` under
    /// their own locks and fail closed with `KeyNotSet`. This is a hint that
    /// selects a path, never a fact anything relies on.
    ///
    /// `Relaxed` is therefore deliberate, and upgrading to `Release`/`Acquire`
    /// would be worse than useless: nothing is published through these flags,
    /// the `Option`s are only ever read under a lock whose acquire already
    /// synchronizes-with the write side, and advertising a publication
    /// guarantee would invite a future caller to read cipher state on the flag
    /// alone — which is exactly the thing that is not safe. Note also that the
    /// answer was already stale the instant the previous lock-taking
    /// implementation released the lock.
    pub fn has_valid_keys(&self) -> bool {
        self.peer_key_installed.load(Ordering::Relaxed)
            && self.self_key_installed.load(Ordering::Relaxed)
    }

    /// Total number of packets successfully decrypted so far.
    pub fn packets_received(&self) -> u64 {
        self.rx
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .replay_window
            .packets_received()
    }

    /// Decrypt `wire_packet` (ExpressLane wire format) into `out`. `out`
    /// must have capacity for at least `wire_packet.len() - WIRE_OVERHEAD`
    /// bytes. Returns `(plaintext_len, is_encoded)`.
    ///
    /// On `Err`, `out` never retains unauthenticated or
    /// authenticated-then-rejected plaintext. Precisely:
    ///
    /// - Every reject *before* the AEAD runs leaves `out` entirely untouched.
    ///   Note these include cases where `data_len` is not usable as an index
    ///   into `out` at all: it is read from the wire before being validated, so
    ///   on `BufferTooSmall` it exceeds `out.len()`, and on the shortest
    ///   `InsufficientData` path it has not been parsed yet.
    /// - The two rejects *after* an AEAD attempt — `InvalidData` when no key
    ///   authenticates, and `Replayed` on the post-commit check — explicitly
    ///   zero `out[..data_len]`, which by that point is known to be in bounds.
    pub fn decrypt(
        &self,
        session_id: [u8; 8],
        wire_packet: &[u8],
        out: &mut [u8],
    ) -> ExpresslaneResult<(usize, bool)> {
        if wire_packet.len() < Self::WIRE_OVERHEAD {
            return Err(ExpresslaneError::InsufficientData);
        }

        let counter = u64::from_be_bytes(wire_packet[0..8].try_into().unwrap());
        let iv: [u8; 12] = wire_packet[8..20].try_into().unwrap();
        let tag: [u8; 16] = wire_packet[20..36].try_into().unwrap();
        let data_len = u16::from_be_bytes(wire_packet[36..38].try_into().unwrap()) as usize;
        let flags = u16::from_be_bytes(wire_packet[38..40].try_into().unwrap());
        let is_encoded = flags & FLAG_ENCODED != 0;

        let mut rx = self.rx.lock().unwrap_or_else(|e| e.into_inner());

        // Replay pre-check first (non-mutating; matches lightway-core's
        // precedence): a replayed counter is rejected before any length work,
        // AAD construction, key lookup, or writing to `out`.
        if rx.replay_window.would_reject(counter) {
            return Err(ExpresslaneError::Replayed);
        }
        if wire_packet.len() < Self::WIRE_OVERHEAD + data_len {
            return Err(ExpresslaneError::InsufficientData);
        }
        if out.len() < data_len {
            return Err(ExpresslaneError::BufferTooSmall);
        }

        // Bind the full received flags into the AAD (V2), matching
        // lightway-core: any modified flag bit — including reserved bits —
        // fails authentication. Built only after the cheap rejects above.
        let (aad_buf, aad_len) = build_aad(self.version, session_id, counter, flags);

        // Try the current peer key, then the previous one (rotation fallback).
        // The caller's `out` is written only from here on, so every error path
        // above leaves it untouched.
        //
        // CONTRACT: a failed `Cipher::decrypt` leaves `out` holding UNSPECIFIED
        // bytes — ring promises only "may have been overwritten in an
        // unspecified way", which permits both scrambling them and leaving them
        // exactly as they were. Because the ciphertext cannot be ASSUMED to have
        // survived, each attempt must start from a fresh copy. Do NOT hoist this
        // second copy out of the fallback arm: it is what keeps in-flight
        // packets recoverable across a peer key rotation. This arm runs only
        // when the current key already failed, so under ring 0.17.14 — which
        // does zero the buffer — dropping the copy turns every rotation with
        // packets still in flight into a burst of loss; a rotation with nothing
        // in flight never reaches here. Sitting inside the arm, it also costs the
        // steady-state path (current key succeeds) exactly nothing — one copy,
        // one AEAD call, same as before.
        let decrypted = {
            let Some(current) = rx.current_peer.as_ref() else {
                return Err(ExpresslaneError::KeyNotSet);
            };
            let ciphertext = &wire_packet[40..40 + data_len];
            let aad = &aad_buf[..aad_len];

            out[..data_len].copy_from_slice(ciphertext);
            current.decrypt(&iv, aad, &mut out[..data_len], &tag).is_ok()
                || rx.prev_peer.as_ref().is_some_and(|prev| {
                    out[..data_len].copy_from_slice(ciphertext);
                    prev.decrypt(&iv, aad, &mut out[..data_len], &tag).is_ok()
                })
        };
        if !decrypted {
            // Scrub before returning: per the contract above `out` now holds
            // bytes that are NOT the authenticated plaintext, and "unspecified"
            // covers leaving the ciphertext there — do not lean on ring's
            // zeroing to have removed it. This buffer crosses the FFI boundary
            // to a C++ caller that reuses it across packets, so leave it
            // deterministically clean. Only the drop path pays, and it just
            // paid for up to two AEAD attempts.
            //
            // NOT BLACK-BOX TESTABLE, and deliberately kept anyway: ring 0.17.14
            // already zeroes on authentication failure, so deleting this line
            // leaves every test green. It guards the documented contract
            // ("unspecified"), not the current implementation. Do not conclude
            // from a green suite that it is dead code.
            out[..data_len].fill(0);
            return Err(ExpresslaneError::InvalidData);
        }

        // Commit only after successful authentication, so a forged packet
        // cannot poison the replay window.
        if !rx.replay_window.commit(counter) {
            // UNREACHABLE BY CONSTRUCTION, not a race: the `rx` guard taken
            // above is held across both `would_reject` and this `commit`, and
            // the two apply identical accept/reject rules to identical state, so
            // a counter that passed the pre-check cannot be refused here. The
            // arm exists so that decoupling them later — dropping the guard
            // between the AEAD and the commit to shorten the critical section is
            // the obvious future change — degrades to a scrubbed drop rather
            // than to authenticated plaintext left in a buffer the caller
            // reuses. Unlike the arm above, that plaintext is real, so keep the
            // scrub if the arm ever does become reachable.
            out[..data_len].fill(0);
            return Err(ExpresslaneError::Replayed);
        }

        Ok((data_len, is_encoded))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::EXPRESSLANE_KEY_SIZE;

    /// Deterministic but unique IV derived from the per-packet counter, so
    /// tests never reuse a `(key, iv)` pair (see `encrypt`'s IV contract).
    fn iv_for(counter: u64) -> [u8; 12] {
        let mut iv = [0u8; 12];
        iv[..8].copy_from_slice(&counter.to_be_bytes());
        iv
    }

    #[test]
    fn reserve_counter_starts_at_one_and_increments() {
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        assert_eq!(session.reserve_counter(), 1);
        assert_eq!(session.reserve_counter(), 2);
        assert_eq!(session.reserve_counter(), 3);
    }

    #[test]
    fn encrypt_without_key_returns_key_not_set() {
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let mut out = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + 4];
        let result = session.encrypt(1, [1u8; 8], b"test", [0u8; 12], false, &mut out);
        assert_eq!(result, Err(ExpresslaneError::KeyNotSet));
    }

    #[test]
    fn update_next_self_key_then_promote_enables_encrypt() {
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let key = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        session.update_next_self_key(key).unwrap();
        session.promote_self_key();

        let plain_text = b"test data";
        let mut out = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = session
            .encrypt(1, [1u8; 8], plain_text, [0u8; 12], false, &mut out)
            .unwrap();
        assert_eq!(n, out.len());
    }

    #[test]
    fn promote_without_staged_key_is_a_no_op() {
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        session.promote_self_key(); // no next_self staged - must not panic
        let mut out = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + 4];
        let result = session.encrypt(1, [1u8; 8], b"test", [0u8; 12], false, &mut out);
        assert_eq!(result, Err(ExpresslaneError::KeyNotSet));
    }

    #[test]
    fn encrypt_writes_expected_wire_layout() {
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let key = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        session.update_next_self_key(key).unwrap();
        session.promote_self_key();

        let session_id = [1u8; 8];
        let plain_text = b"test data";
        let iv = [9u8; 12];
        let mut out = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = session
            .encrypt(5, session_id, plain_text, iv, false, &mut out)
            .unwrap();
        out.truncate(n);

        assert_eq!(u64::from_be_bytes(out[0..8].try_into().unwrap()), 5);
        assert_eq!(&out[8..20], &iv[..]);
        assert_eq!(
            u16::from_be_bytes(out[36..38].try_into().unwrap()) as usize,
            plain_text.len()
        );
        assert_eq!(out.len(), ExpresslaneSession::WIRE_OVERHEAD + plain_text.len());
    }

    #[test]
    fn encrypt_rejects_buffer_too_small() {
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let key = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        session.update_next_self_key(key).unwrap();
        session.promote_self_key();

        let mut out = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD]; // too small for any payload
        let result = session.encrypt(1, [1u8; 8], b"x", [0u8; 12], false, &mut out);
        assert_eq!(result, Err(ExpresslaneError::BufferTooSmall));
    }

    #[test]
    fn packets_sent_counts_successful_encrypts_only() {
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let key = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        session.update_next_self_key(key).unwrap();
        session.promote_self_key();

        assert_eq!(session.packets_sent(), 0);
        let mut out = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + 4];
        session.encrypt(1, [1u8; 8], b"test", [0u8; 12], false, &mut out).unwrap();
        session.encrypt(2, [1u8; 8], b"test", [0u8; 12], false, &mut out).unwrap();
        assert_eq!(session.packets_sent(), 2);

        // A failed encrypt (buffer too small) must not bump the counter.
        let mut too_small = vec![0u8; 4];
        let _ = session.encrypt(3, [1u8; 8], b"test", [0u8; 12], false, &mut too_small);
        assert_eq!(session.packets_sent(), 2);
    }

    #[test]
    fn wire_counter_increments_independently_of_encrypt_calls() {
        // reserve_counter and encrypt's `counter` param are decoupled by
        // design - callers may reserve without encrypting, or supply their
        // own scheme entirely. Verify encrypt() writes exactly the counter
        // it was given, not an internally-tracked one.
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let key = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        session.update_next_self_key(key).unwrap();
        session.promote_self_key();

        let mut out = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + 4];
        session.encrypt(1000, [1u8; 8], b"test", [0u8; 12], false, &mut out).unwrap();
        assert_eq!(u64::from_be_bytes(out[0..8].try_into().unwrap()), 1000);
    }

    #[test]
    fn round_trip_encryption_decryption() {
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

        let key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(key).unwrap();
        sender.promote_self_key();
        receiver.update_peer_key(key).unwrap();

        let session_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        let plain_text = b"Hello, ExpressLane!";
        let iv = [9u8, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20];

        let mut wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(1, session_id, plain_text, iv, false, &mut wire).unwrap();
        wire.truncate(n);

        let mut out = vec![0u8; plain_text.len()];
        let (len, is_encoded) = receiver.decrypt(session_id, &wire, &mut out).unwrap();
        assert_eq!(&out[..len], plain_text);
        assert!(!is_encoded);
    }

    #[test]
    fn round_trip_with_encoded_flag() {
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

        let key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(key).unwrap();
        sender.promote_self_key();
        receiver.update_peer_key(key).unwrap();

        let session_id = [1u8; 8];
        let plain_text = b"Encoded payload";
        let mut wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(1, session_id, plain_text, [0u8; 12], true, &mut wire).unwrap();
        wire.truncate(n);

        let mut out = vec![0u8; plain_text.len()];
        let (len, is_encoded) = receiver.decrypt(session_id, &wire, &mut out).unwrap();
        assert_eq!(&out[..len], plain_text);
        assert!(is_encoded);
    }

    #[test]
    fn decrypt_without_key_returns_key_not_set() {
        let receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD];
        let mut out = vec![0u8; 4];
        let result = receiver.decrypt([1u8; 8], &wire, &mut out);
        assert_eq!(result, Err(ExpresslaneError::KeyNotSet));
    }

    #[test]
    fn decrypt_rejects_insufficient_data() {
        let receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD - 1];
        let mut out = vec![0u8; 4];
        let result = receiver.decrypt([1u8; 8], &wire, &mut out);
        assert_eq!(result, Err(ExpresslaneError::InsufficientData));
    }

    #[test]
    fn decrypt_rejects_replay() {
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

        let key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(key).unwrap();
        sender.promote_self_key();
        receiver.update_peer_key(key).unwrap();

        let session_id = [1u8; 8];
        let plain_text = b"replay me";
        let mut wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(1, session_id, plain_text, [0u8; 12], false, &mut wire).unwrap();
        wire.truncate(n);

        let mut out = vec![0u8; plain_text.len()];
        receiver.decrypt(session_id, &wire, &mut out).unwrap();
        let result = receiver.decrypt(session_id, &wire, &mut out);
        assert_eq!(result, Err(ExpresslaneError::Replayed));
    }

    #[test]
    fn decrypt_falls_back_to_prev_peer_key_during_rotation() {
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

        let old_key = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        let new_key = ExpresslaneKey([2u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(old_key).unwrap();
        sender.promote_self_key();
        receiver.update_peer_key(old_key).unwrap();

        let session_id = [1u8; 8];
        let plain_text = b"in flight during rotation";
        let mut wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(1, session_id, plain_text, [0u8; 12], false, &mut wire).unwrap();
        wire.truncate(n);

        // Receiver rotates to new_key before this in-flight (old_key-encrypted)
        // packet arrives - it must still decrypt via prev_peer.
        receiver.update_peer_key(new_key).unwrap();

        let mut out = vec![0u8; plain_text.len()];
        let (len, _) = receiver.decrypt(session_id, &wire, &mut out).unwrap();
        assert_eq!(&out[..len], plain_text);
    }

    #[test]
    fn failed_decrypt_scrubs_out_without_overrunning_data_len() {
        // Pins the post-AEAD half of `decrypt`'s documented post-condition: on
        // the `InvalidData` return — the only one of the two post-AEAD rejects
        // that is reachable, the other being the post-commit `Replayed` —
        // `out[..data_len]` is zeroed and nothing past `data_len` is touched.
        // The pre-AEAD rejects leave `out` entirely untouched instead and are
        // covered by their own tests; see the post-condition on `decrypt`.
        // Every other test allocates `out` as a fresh zero-filled Vec, so none
        // of them can see this at all. Here `out` starts as 0xCC, which is what
        // the C++ caller's per-packet-reused stack buffer looks like.
        //
        // What it does NOT do — verified by mutation, not assumed — is prove
        // that `decrypt`'s own `fill(0)` is what zeroes the buffer: ring 0.17.14
        // already zeroes on authentication failure, so this test passes with
        // that line deleted. No black-box test can separate the two. It pins the
        // contract the FFI caller depends on, whichever layer supplies it, and
        // the sentinel one byte past `data_len` genuinely does catch a scrub
        // that runs long. MTU-sized so the AEAD spans many blocks.
        let plain_text = vec![0x5Au8; 1350];
        let key_a = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        let key_b = ExpresslaneKey([2u8; EXPRESSLANE_KEY_SIZE]);
        let key_c = ExpresslaneKey([3u8; EXPRESSLANE_KEY_SIZE]);
        let session_id = [7u8; 8];

        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        sender.update_next_self_key(key_a).unwrap();
        sender.promote_self_key();
        let mut wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(1, session_id, &plain_text, iv_for(1), false, &mut wire).unwrap();
        wire.truncate(n);

        // Arm 1: only the current peer key is installed, and it is the wrong one.
        let no_prev = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        no_prev.update_peer_key(key_b).unwrap();

        // Arm 2: current AND prev are both installed and both wrong, so the
        // fallback runs and its re-copy is the last thing to touch `out`.
        let with_prev = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        with_prev.update_peer_key(key_b).unwrap();
        with_prev.update_peer_key(key_c).unwrap();

        for receiver in [&no_prev, &with_prev] {
            let mut out = vec![0xCCu8; plain_text.len() + 1];
            assert_eq!(
                receiver.decrypt(session_id, &wire, &mut out),
                Err(ExpresslaneError::InvalidData)
            );
            assert!(
                out[..plain_text.len()].iter().all(|&b| b == 0),
                "a rejected packet must leave no plaintext-shaped bytes in `out`"
            );
            assert_eq!(out[plain_text.len()], 0xCC, "the scrub must not exceed data_len");
        }

        // The same buffer shape on the success path: plaintext exactly, sentinel
        // intact — so the scrub cannot be "passing" by zeroing unconditionally.
        let good = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        good.update_peer_key(key_a).unwrap();
        let mut out = vec![0xCCu8; plain_text.len() + 1];
        let (len, _) = good.decrypt(session_id, &wire, &mut out).unwrap();
        assert_eq!(&out[..len], &plain_text[..]);
        assert_eq!(out[plain_text.len()], 0xCC);
    }

    #[test]
    fn cross_version_v1_to_v2_fails() {
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version1);
        let receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

        let key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(key).unwrap();
        sender.promote_self_key();
        receiver.update_peer_key(key).unwrap();

        let session_id = [1u8; 8];
        let plain_text = b"v1 to v2";
        let mut wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(1, session_id, plain_text, [0u8; 12], false, &mut wire).unwrap();
        wire.truncate(n);

        let mut out = vec![0u8; plain_text.len()];
        let result = receiver.decrypt(session_id, &wire, &mut out);
        assert_eq!(result, Err(ExpresslaneError::InvalidData));
    }

    #[test]
    fn tampered_flags_rejected_by_aead() {
        // On-path attacker flips the encoded flag. AEAD must reject V2
        // packets because the flags field is bound into the auth tag.
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

        let key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(key).unwrap();
        sender.promote_self_key();
        receiver.update_peer_key(key).unwrap();

        let session_id = [1u8; 8];
        let plain_text = b"sensitive payload";
        let mut wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(1, session_id, plain_text, [0u8; 12], false, &mut wire).unwrap();
        wire.truncate(n);

        assert_eq!(wire[38] & 0x80, 0, "precondition: encoded flag is clear");
        wire[38] |= 0x80;

        let mut out = vec![0u8; plain_text.len()];
        let result = receiver.decrypt(session_id, &wire, &mut out);
        assert_eq!(result, Err(ExpresslaneError::InvalidData));
    }

    #[test]
    fn forged_packet_does_not_poison_replay_window() {
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

        let key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(key).unwrap();
        sender.promote_self_key();
        receiver.update_peer_key(key).unwrap();

        let session_id = [1u8; 8];
        let plain_text = b"hello expresslane";

        let mut wire1 = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(1, session_id, plain_text, [0u8; 12], false, &mut wire1).unwrap();
        wire1.truncate(n);
        let mut out = vec![0u8; plain_text.len()];
        receiver.decrypt(session_id, &wire1, &mut out).unwrap();
        assert_eq!(receiver.packets_received(), 1);

        // Forge a packet with a huge counter and a bogus tag (no key).
        let mut forged = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        forged[0..8].copy_from_slice(&(u64::MAX - 1).to_be_bytes());
        forged[36..38].copy_from_slice(&(plain_text.len() as u16).to_be_bytes());
        let mut out2 = vec![0u8; plain_text.len()];
        let result = receiver.decrypt(session_id, &forged, &mut out2);
        assert_eq!(result, Err(ExpresslaneError::InvalidData));

        // Window state must be untouched by the forgery.
        assert_eq!(receiver.packets_received(), 1);

        // Next valid packet (counter=2) must still be accepted.
        let mut wire2 = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(2, session_id, plain_text, [0u8; 12], false, &mut wire2).unwrap();
        wire2.truncate(n);
        let (len, _) = receiver.decrypt(session_id, &wire2, &mut out).unwrap();
        assert_eq!(&out[..len], plain_text);
        assert_eq!(receiver.packets_received(), 2);
    }

    #[test]
    fn has_valid_keys_requires_both_self_and_peer() {
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        assert!(!session.has_valid_keys());

        session.update_next_self_key(ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE])).unwrap();
        session.promote_self_key();
        assert!(!session.has_valid_keys()); // peer key still missing

        session.update_peer_key(ExpresslaneKey([2u8; EXPRESSLANE_KEY_SIZE])).unwrap();
        assert!(session.has_valid_keys());
    }

    #[test]
    fn concurrent_encrypt_from_multiple_threads_produces_unique_counters_and_decrypts() {
        let key = ExpresslaneKey([7u8; EXPRESSLANE_KEY_SIZE]);
        let tx = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        tx.update_next_self_key(key).unwrap();
        tx.promote_self_key();

        let session_id = [1u8, 2, 3, 4, 5, 6, 7, 8];
        const THREADS: usize = 8;
        const PER_THREAD: usize = 50;

        let packets: Vec<Vec<u8>> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..THREADS)
                .map(|t| {
                    let tx = &tx;
                    scope.spawn(move || {
                        let mut produced = Vec::with_capacity(PER_THREAD);
                        for i in 0..PER_THREAD {
                            let counter = tx.reserve_counter();
                            let plain_text = format!("thread {t} packet {i}");
                            let mut buf =
                                vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
                            let n = tx
                                .encrypt(counter, session_id, plain_text.as_bytes(), iv_for(counter), false, &mut buf)
                                .unwrap();
                            buf.truncate(n);
                            produced.push(buf);
                        }
                        produced
                    })
                })
                .collect();
            handles.into_iter().flat_map(|h| h.join().unwrap()).collect()
        });

        assert_eq!(packets.len(), THREADS * PER_THREAD);

        let mut counters: Vec<u64> = packets
            .iter()
            .map(|p| u64::from_be_bytes(p[0..8].try_into().unwrap()))
            .collect();
        counters.sort_unstable();
        counters.dedup();
        assert_eq!(counters.len(), THREADS * PER_THREAD, "counters must all be unique");

        let rx = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        rx.update_peer_key(key).unwrap();
        for packet in &packets {
            let mut out = vec![0u8; packet.len() - ExpresslaneSession::WIRE_OVERHEAD];
            let (n, _) = rx.decrypt(session_id, packet, &mut out).unwrap();
            assert_eq!(n, out.len());
        }
        assert_eq!(rx.packets_received(), (THREADS * PER_THREAD) as u64);
    }

    #[test]
    fn promote_self_key_concurrent_with_encrypt_does_not_corrupt_packets() {
        // The overlap is BEST-EFFORT, not asserted: the encryptor runs a fixed
        // 200 iterations while the main thread sleeps 1 ms and then promotes,
        // so on a fast box the loop can finish first and every packet is
        // produced under `key_a`. The test still passes — the receiver holds
        // both keys and cannot tell — so a green run is not evidence the
        // rotation landed mid-stream. Making it evidence needs the encryptor to
        // loop until the promote is signalled plus an assertion that both keys
        // are represented; that is a functional change to the test, deliberately
        // not made here. Do not read this name as a pinned interleaving.
        let key_a = ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE]);
        let key_b = ExpresslaneKey([2u8; EXPRESSLANE_KEY_SIZE]);
        let tx = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        tx.update_next_self_key(key_a).unwrap();
        tx.promote_self_key();
        tx.update_next_self_key(key_b).unwrap();

        let session_id = [9u8; 8];
        let plain_text = b"rotate me";

        let packets = std::thread::scope(|scope| {
            let encryptor = {
                let tx = &tx;
                scope.spawn(move || {
                    let mut results = Vec::new();
                    for _ in 0..200 {
                        let counter = tx.reserve_counter();
                        let mut buf = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
                        if let Ok(n) =
                            tx.encrypt(counter, session_id, plain_text, iv_for(counter), false, &mut buf)
                        {
                            buf.truncate(n);
                            results.push(buf);
                        }
                    }
                    results
                })
            };
            std::thread::sleep(std::time::Duration::from_millis(1));
            tx.promote_self_key();
            encryptor.join().unwrap()
        });

        assert!(!packets.is_empty());

        // Every produced packet must decrypt with one of the two known
        // keys - none corrupted by the concurrent rotation.
        let rx = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        rx.update_peer_key(key_a).unwrap();
        rx.update_peer_key(key_b).unwrap(); // key_b current, key_a prev - both tried
        for packet in &packets {
            let mut out = vec![0u8; packet.len() - ExpresslaneSession::WIRE_OVERHEAD];
            rx.decrypt(session_id, packet, &mut out)
                .unwrap_or_else(|e| panic!("packet failed to decrypt: {e}"));
        }
    }

    #[test]
    fn v1_round_trip_without_flags_in_aad() {
        // V1 sender <-> V1 receiver: flags are not part of the AAD, so a
        // clear-flag packet round-trips. Guards the V1 positive path, which
        // the V2-only tests above don't cover.
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version1);
        let receiver = ExpresslaneSession::new(ExpresslaneVersion::Version1);
        let key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(key).unwrap();
        sender.promote_self_key();
        receiver.update_peer_key(key).unwrap();

        let session_id = [1u8; 8];
        let plain_text = b"v1 payload";
        let mut wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(1, session_id, plain_text, [0u8; 12], false, &mut wire).unwrap();
        wire.truncate(n);

        let mut out = vec![0u8; plain_text.len()];
        let (len, is_encoded) = receiver.decrypt(session_id, &wire, &mut out).unwrap();
        assert_eq!(&out[..len], plain_text);
        assert!(!is_encoded);
    }

    #[test]
    fn v2_reserved_flag_bit_tamper_is_rejected() {
        // A reserved (non-encoded) flag bit is bound into the V2 AAD, so
        // flipping one must fail authentication - matching lightway-core.
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(key).unwrap();
        sender.promote_self_key();
        receiver.update_peer_key(key).unwrap();

        let session_id = [1u8; 8];
        let plain_text = b"reserved bit test";
        let mut wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + plain_text.len()];
        let n = sender.encrypt(1, session_id, plain_text, [0u8; 12], false, &mut wire).unwrap();
        wire.truncate(n);

        // Flip a reserved flag bit (LSB of the flags field at wire byte 39).
        assert_eq!(wire[39] & 0x01, 0, "precondition: reserved bit clear");
        wire[39] |= 0x01;

        let mut out = vec![0u8; plain_text.len()];
        assert_eq!(
            receiver.decrypt(session_id, &wire, &mut out),
            Err(ExpresslaneError::InvalidData)
        );
    }

    #[test]
    fn decrypt_rejects_data_len_exceeding_packet() {
        // A data_len field claiming more bytes than the packet carries must be
        // rejected before any AEAD work (bounds the ciphertext slice).
        let receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        receiver.update_peer_key(ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE])).unwrap();

        // Overhead-only frame, but data_len claims 100 bytes of payload.
        let mut wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD];
        wire[36..38].copy_from_slice(&100u16.to_be_bytes());

        let mut out = vec![0u8; 100];
        assert_eq!(
            receiver.decrypt([1u8; 8], &wire, &mut out),
            Err(ExpresslaneError::InsufficientData)
        );
    }

    #[test]
    fn update_key_rejects_all_zero_invalid_sentinel() {
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        assert_eq!(
            session.update_next_self_key(ExpresslaneKey::INVALID),
            Err(ExpresslaneError::InvalidKey)
        );
        assert_eq!(
            session.update_peer_key(ExpresslaneKey::INVALID),
            Err(ExpresslaneError::InvalidKey)
        );
        // A rejected zero key must not leave a usable session behind.
        assert!(!session.has_valid_keys());
    }

    #[test]
    fn decrypt_accepts_out_of_order_within_window() {
        // Packets 3 then 1 (reordered in flight) must both decrypt; the replay
        // window admits earlier-but-unseen counters within its span, and a
        // subsequent replay of 3 is rejected.
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let key = ExpresslaneKey([42u8; EXPRESSLANE_KEY_SIZE]);
        sender.update_next_self_key(key).unwrap();
        sender.promote_self_key();
        receiver.update_peer_key(key).unwrap();

        let session_id = [1u8; 8];
        let make = |counter: u64| {
            let pt = b"ordered";
            let mut wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD + pt.len()];
            let n = sender
                .encrypt(counter, session_id, pt, [counter as u8; 12], false, &mut wire)
                .unwrap();
            wire.truncate(n);
            wire
        };
        let p3 = make(3);
        let p1 = make(1);

        let mut out = vec![0u8; 7];
        receiver.decrypt(session_id, &p3, &mut out).unwrap();
        receiver.decrypt(session_id, &p1, &mut out).unwrap(); // earlier but unseen
        assert_eq!(
            receiver.decrypt(session_id, &p3, &mut out),
            Err(ExpresslaneError::Replayed)
        );
        assert_eq!(receiver.packets_received(), 2);
    }

    #[test]
    fn reserve_counter_wraps_through_zero_without_panicking() {
        // reserve_counter() uses wrapping_add, so at the u64::MAX boundary it
        // must not panic (debug builds) and must produce the sequence
        // MAX, 0, 1 — matching lightway-core's wire_counter.wrapping_add(1).
        let session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        session.seed_counter_for_test(u64::MAX - 1);
        assert_eq!(session.reserve_counter(), u64::MAX);
        assert_eq!(session.reserve_counter(), 0);
        assert_eq!(session.reserve_counter(), 1);
    }
}
