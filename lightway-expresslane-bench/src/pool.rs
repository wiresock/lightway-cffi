//! Packet pools and the per-iteration schedule.
//!
//! Every arm decrypts *real* ExpressLane wire packets, produced by
//! `ExpresslaneSession::encrypt` itself — not synthetic buffers. That matters
//! for three reasons:
//!
//! - **The failure path is cheaper than the success path.** RustCrypto skips
//!   applying the keystream when the tag check fails, so an arm that
//!   accidentally decrypts garbage looks roughly twice as fast as it is, and
//!   the ratio between providers is destroyed because `ring` does not fail the
//!   same way. Every arm therefore restores pristine ciphertext before every
//!   decrypt and the runner asserts every decrypt succeeded.
//! - **The replay window rejects before the AEAD runs.** `would_reject` is a
//!   non-mutating pre-check ahead of all crypto (`session.rs`), so a Layer B
//!   arm that walks the same pool twice measures the *reject* path from pass 2
//!   onward and reports a spectacular, meaningless number. Counters here run
//!   1..=slots strictly increasing and one sample is exactly one pass, with a
//!   fresh session in between.
//! - **Cross-provider identity.** ring and `aes-gcm` produce byte-identical
//!   ciphertext and tags, so the *same* wire pool feeds both. That is what
//!   makes the checksum comparison across arms a proof they did the same
//!   cryptographic work, rather than similarly-named work.

use aes_gcm::{AeadInPlace, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use lightway_expresslane::{ExpresslaneKey, ExpresslaneSession, ExpresslaneVersion};

/// Wire overhead: counter(8) + iv(12) + tag(16) + data_len(2) + flags(2).
pub const WIRE_OVERHEAD: usize = ExpresslaneSession::WIRE_OVERHEAD;

/// Deterministic per-packet nonce, derived from the wire counter exactly as the
/// crate's own tests do, so no `(key, iv)` pair repeats within a pool.
pub fn iv_for(counter: u64) -> [u8; 12] {
    let mut iv = [0u8; 12];
    iv[..8].copy_from_slice(&counter.to_be_bytes());
    iv
}

/// The 18-byte Version2 AAD: session_id || counter_be || flags_be.
///
/// Rebuilt inline by every arm from the packet's own header rather than
/// precomputed into a side table. A side table would add ~100 KiB of cache
/// traffic that Layer B does not pay, biasing the very delta M3 exists to
/// isolate. Its ~5-cycle cost is identical in all arms and therefore cancels.
#[inline(always)]
pub fn aad_v2(session_id: &[u8; 8], counter: u64, flags: u16) -> [u8; 18] {
    let mut aad = [0u8; 18];
    aad[..8].copy_from_slice(session_id);
    aad[8..16].copy_from_slice(&counter.to_be_bytes());
    aad[16..].copy_from_slice(&flags.to_be_bytes());
    aad
}

/// xorshift64*, so two boxes can be proven to have processed identical bytes
/// from a printed seed.
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Rng(seed | 1)
    }
    pub fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
}

/// Read-only side of the benchmark: wire packets and their plaintexts.
///
/// Slots are 64-byte aligned with a deliberately non-power-of-two stride.
/// Power-of-two strides create L1/L2 set-index conflicts and 4 KiB
/// store-to-load aliasing, and there is no reason to expect those to hit every
/// provider equally.
pub struct Src {
    /// AES-256-GCM wire packets, production layout, one per slot.
    pub wire: Vec<u8>,
    /// The same plaintexts under ChaCha20-Poly1305, same wire layout.
    pub wire_cc: Vec<u8>,
    /// Plaintexts, for the encrypt arms.
    pub plain: Vec<u8>,
    pub slots: usize,
    pub len: usize,
    pub stride: usize,
    pub session_id: [u8; 8],
    pub pool_hash: u64,
}

fn align_up(v: usize, a: usize) -> usize {
    v.div_ceil(a) * a
}

impl Src {
    /// Build a pool of `target_bytes` (capped at `max_slots` packets).
    pub fn build(
        len: usize,
        target_bytes: usize,
        max_slots: usize,
        key: ExpresslaneKey,
        session_id: [u8; 8],
        seed: u64,
    ) -> Src {
        let mut stride = align_up(WIRE_OVERHEAD + len + 16, 64) + 128;
        if stride.is_power_of_two() {
            stride += 64;
        }
        // `max_slots.max(64)`: `Ord::clamp` panics when min > max, so a bare
        // `--max-slots 32` would abort the run before a single line reached the
        // operator. 64 slots is the floor the schedule needs; an operator asking
        // for fewer gets the floor, not a crash.
        let slots = (target_bytes / stride).clamp(64, max_slots.max(64));

        let mut plain = vec![0u8; slots * stride];
        let mut wire = vec![0u8; slots * stride];
        let mut wire_cc = vec![0u8; slots * stride];

        let mut rng = Rng::new(seed);
        for i in 0..slots {
            let base = i * stride;
            let p = &mut plain[base..base + len];
            let mut w = 0usize;
            while w < len {
                let bytes = rng.next().to_le_bytes();
                let take = (len - w).min(8);
                p[w..w + take].copy_from_slice(&bytes[..take]);
                w += take;
            }
        }

        let tx = ExpresslaneSession::new(ExpresslaneVersion::Version2);
        tx.update_next_self_key(key).expect("stage self key");
        tx.promote_self_key();
        let cc = <ChaCha20Poly1305 as KeyInit>::new_from_slice(&key.0).expect("chacha key");

        for i in 0..slots {
            let base = i * stride;
            let counter = i as u64 + 1;
            let iv = iv_for(counter);

            // AES arm: produced by the shipping encrypt, so the pool is by
            // construction exactly what the production RX path sees.
            let n = tx
                .encrypt(
                    counter,
                    session_id,
                    &plain[base..base + len],
                    iv,
                    false,
                    &mut wire[base..base + WIRE_OVERHEAD + len],
                )
                .expect("encrypt pool packet");
            debug_assert_eq!(n, WIRE_OVERHEAD + len);

            // ChaCha arm: identical header, identical nonce and AAD, so the
            // only difference between the two arms is the primitive.
            let flags = u16::from_be_bytes(wire[base + 38..base + 40].try_into().unwrap());
            let aad = aad_v2(&session_id, counter, flags);
            wire_cc[base..base + WIRE_OVERHEAD].copy_from_slice(&wire[base..base + WIRE_OVERHEAD]);
            wire_cc[base + WIRE_OVERHEAD..base + WIRE_OVERHEAD + len]
                .copy_from_slice(&plain[base..base + len]);
            let tag = cc
                .encrypt_in_place_detached(
                    aes_gcm::Nonce::from_slice(&iv),
                    &aad,
                    &mut wire_cc[base + WIRE_OVERHEAD..base + WIRE_OVERHEAD + len],
                )
                .expect("chacha seal");
            wire_cc[base + 20..base + 36].copy_from_slice(&tag);
        }

        // FNV-1a over the AES wire pool, so two boxes can be shown to have
        // processed the same bytes.
        let mut h = 0xcbf2_9ce4_8422_2325u64;
        for i in 0..slots {
            let base = i * stride;
            for &b in &wire[base..base + WIRE_OVERHEAD + len] {
                h ^= b as u64;
                h = h.wrapping_mul(0x1000_0000_01b3);
            }
        }

        Src {
            wire,
            wire_cc,
            plain,
            slots,
            len,
            stride,
            session_id,
            pool_hash: h,
        }
    }

    pub fn working_set_bytes(&self) -> usize {
        // src wire + dst, which is what an arm actually walks per pass.
        2 * self.slots * self.stride
    }
}

/// Precomputed per-iteration slot index and checksum-fold offset.
///
/// Precomputed so no division or modulo appears inside a timed loop, and shared
/// unchanged by every arm — which is what makes the folded accumulator directly
/// comparable across arms and therefore usable as proof no arm's work was
/// optimised away.
pub struct Sched {
    pub slot: Vec<u32>,
    pub fold: Vec<u32>,
    pub n: usize,
}

impl Sched {
    /// `hot` collapses every iteration onto slot 0 — same instruction stream,
    /// same iteration count, L1-resident data — so the hot/cold pair brackets
    /// how much of an arm's cost is memory rather than compute.
    pub fn new(src: &Src, hot: bool, seed: u64) -> Sched {
        let n = src.slots;
        let mut slot = Vec::with_capacity(n);
        let mut fold = Vec::with_capacity(n);
        let mut rng = Rng::new(seed);
        let span = (src.len - 8) as u64 + 1;
        for i in 0..n {
            // Sequential traversal by default: production walks the NDIS packet
            // block ring in order and is just as prefetcher-friendly, so a
            // shuffled order would overstate the cold cost.
            slot.push(if hot { 0 } else { i as u32 });
            fold.push((rng.next() % span) as u32);
        }
        Sched { slot, fold, n }
    }
}
