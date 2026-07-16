//! ExpressLane packet session: key rotation state, replay window, and
//! encrypt/decrypt.

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, RwLock};

use crate::cipher::Cipher;
use crate::error::{ExpresslaneError, ExpresslaneResult};
use crate::key::ExpresslaneKey;
use crate::replay_window::ReplayWindow;
use crate::version::ExpresslaneVersion;

/// Build the AEAD associated data for an ExpressLane data packet.
/// Returns a fixed-size buffer and the number of significant bytes.
fn build_aad(
    version: ExpresslaneVersion,
    session_id: [u8; 8],
    counter: u64,
    encoded: bool,
) -> ([u8; 18], usize) {
    let mut buf = [0u8; 18];
    buf[..8].copy_from_slice(&session_id);
    buf[8..16].copy_from_slice(&counter.to_be_bytes());
    if version >= ExpresslaneVersion::Version2 {
        let flags: u16 = if encoded { 0x8000 } else { 0 };
        buf[16..].copy_from_slice(&flags.to_be_bytes());
        (buf, 18)
    } else {
        (buf, 16)
    }
}

/// An ExpressLane packet-crypto session: key rotation state, replay
/// window, and encrypt/decrypt.
///
/// Splits into two independently-synchronized halves — see
/// `docs/superpowers/specs/2026-07-16-expresslane-data-cffi-design.md`'s
/// "Parallel encrypt" section in the `lightway-cffi` repo for the full
/// rationale:
///
/// - TX state (`current_self`, `next_self`, counters): safe to call
///   concurrently from multiple threads on the same session.
/// - RX state (`current_peer`, `prev_peer`, `replay_window`): exclusive
///   access only — callers must externally serialize `decrypt`,
///   `update_peer_key`, `has_valid_keys`, `packets_received`.
pub struct ExpresslaneSession {
    version: ExpresslaneVersion,

    current_self: RwLock<Option<Cipher>>,
    next_self: Mutex<Option<Cipher>>,
    next_counter: AtomicU64,
    packets_sent: AtomicU64,

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
            current_peer: None,
            prev_peer: None,
            replay_window: ReplayWindow::default(),
        }
    }

    // ---- TX domain: safe to call concurrently from multiple threads. ----

    /// Reserve a wire counter value guaranteed unique for this session
    /// (lock-free atomic increment). Use the returned value as `counter`
    /// in the next `encrypt()` call, unless the caller has its own
    /// uniqueness guarantee across every thread encrypting on this
    /// session.
    pub fn reserve_counter(&self) -> u64 {
        // Matches upstream lightway-core: first packet is counter 1, not 0.
        self.next_counter.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// Stage a new "next self" key. Call `promote_self_key` once the peer
    /// has acknowledged the rotation to make it the active send key.
    pub fn update_next_self_key(&self, key: ExpresslaneKey) -> ExpresslaneResult<()> {
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

        let (aad_buf, aad_len) = build_aad(self.version, session_id, counter, is_encoded);

        out[8..20].copy_from_slice(&iv);
        out[40..needed].copy_from_slice(plain_text);
        let tag = cipher.encrypt(&iv, &aad_buf[..aad_len], &mut out[40..needed])?;
        drop(guard);

        out[0..8].copy_from_slice(&counter.to_be_bytes());
        out[20..36].copy_from_slice(&tag);
        out[36..38].copy_from_slice(&(plain_text.len() as u16).to_be_bytes());
        let flags: u16 = if is_encoded { 0x8000 } else { 0 };
        out[38..40].copy_from_slice(&flags.to_be_bytes());

        self.packets_sent.fetch_add(1, Ordering::Relaxed);
        Ok(needed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::key::EXPRESSLANE_KEY_SIZE;

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
}
