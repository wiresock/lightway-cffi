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

    // ---- RX domain: caller must externally serialize all calls in this
    // group against the same session handle. ----

    /// Install a new peer (receive) key. The previous peer key becomes the
    /// fallback used by `decrypt` for packets still in flight from before
    /// the peer's rotation.
    pub fn update_peer_key(&mut self, key: ExpresslaneKey) -> ExpresslaneResult<()> {
        let cipher = Cipher::new(&key)?;
        self.prev_peer = std::mem::replace(&mut self.current_peer, Some(cipher));
        Ok(())
    }

    /// True if both a self (send) key and a peer (receive) key are
    /// installed.
    pub fn has_valid_keys(&mut self) -> bool {
        self.current_peer.is_some()
            && self
                .current_self
                .read()
                .unwrap_or_else(|e| e.into_inner())
                .is_some()
    }

    /// Total number of packets successfully decrypted so far.
    pub fn packets_received(&mut self) -> u64 {
        self.replay_window.packets_received()
    }

    /// Decrypt `wire_packet` (ExpressLane wire format) into `out`. `out`
    /// must have capacity for at least `wire_packet.len() - WIRE_OVERHEAD`
    /// bytes. Returns `(plaintext_len, is_encoded)`.
    pub fn decrypt(
        &mut self,
        session_id: [u8; 8],
        wire_packet: &[u8],
        out: &mut [u8],
    ) -> ExpresslaneResult<(usize, bool)> {
        if wire_packet.len() < Self::WIRE_OVERHEAD {
            return Err(ExpresslaneError::InsufficientData);
        }

        let counter = u64::from_be_bytes(wire_packet[0..8].try_into().unwrap());

        if self.replay_window.would_reject(counter) {
            return Err(ExpresslaneError::Replayed);
        }

        let iv: [u8; 12] = wire_packet[8..20].try_into().unwrap();
        let tag: [u8; 16] = wire_packet[20..36].try_into().unwrap();
        let data_len = u16::from_be_bytes(wire_packet[36..38].try_into().unwrap()) as usize;
        let flags = u16::from_be_bytes(wire_packet[38..40].try_into().unwrap());
        let is_encoded = flags & 0x8000 != 0;

        if wire_packet.len() < Self::WIRE_OVERHEAD + data_len {
            return Err(ExpresslaneError::InsufficientData);
        }
        if out.len() < data_len {
            return Err(ExpresslaneError::BufferTooSmall);
        }

        let (aad_buf, aad_len) = build_aad(self.version, session_id, counter, is_encoded);
        out[..data_len].copy_from_slice(&wire_packet[40..40 + data_len]);

        let current = self.current_peer.as_ref().ok_or(ExpresslaneError::KeyNotSet)?;
        if current.decrypt(&iv, &aad_buf[..aad_len], &mut out[..data_len], &tag).is_err() {
            match self.prev_peer.as_ref() {
                Some(prev) => {
                    prev.decrypt(&iv, &aad_buf[..aad_len], &mut out[..data_len], &tag)?;
                }
                None => return Err(ExpresslaneError::InvalidData),
            }
        }

        if !self.replay_window.commit(counter) {
            return Err(ExpresslaneError::Replayed);
        }

        Ok((data_len, is_encoded))
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

    #[test]
    fn round_trip_encryption_decryption() {
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let mut receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

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
        let mut receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

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
        let mut receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD];
        let mut out = vec![0u8; 4];
        let result = receiver.decrypt([1u8; 8], &wire, &mut out);
        assert_eq!(result, Err(ExpresslaneError::KeyNotSet));
    }

    #[test]
    fn decrypt_rejects_insufficient_data() {
        let mut receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let wire = vec![0u8; ExpresslaneSession::WIRE_OVERHEAD - 1];
        let mut out = vec![0u8; 4];
        let result = receiver.decrypt([1u8; 8], &wire, &mut out);
        assert_eq!(result, Err(ExpresslaneError::InsufficientData));
    }

    #[test]
    fn decrypt_rejects_replay() {
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        let mut receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

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
        let mut receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

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
    fn cross_version_v1_to_v2_fails() {
        let sender = ExpresslaneSession::new(ExpresslaneVersion::Version1);
        let mut receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

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
        let mut receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

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
        let mut receiver = ExpresslaneSession::new(ExpresslaneVersion::Version2);

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
        let mut session = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        assert!(!session.has_valid_keys());

        session.update_next_self_key(ExpresslaneKey([1u8; EXPRESSLANE_KEY_SIZE])).unwrap();
        session.promote_self_key();
        assert!(!session.has_valid_keys()); // peer key still missing

        session.update_peer_key(ExpresslaneKey([2u8; EXPRESSLANE_KEY_SIZE])).unwrap();
        assert!(session.has_valid_keys());
    }
}
