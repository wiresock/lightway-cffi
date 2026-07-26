//! The timed loops. One function per arm, identical skeletons.
//!
//! The duplication is deliberate. Every arm is a copy of the same loop with a
//! single line changed, and each is `#[inline(never)]` so the call overhead is
//! measured identically by the `null` calibration arm and subtracts out by
//! construction. Factoring the body behind a closure or a trait would let the
//! optimiser specialise the arms differently and quietly reintroduce exactly
//! the asymmetry this file exists to avoid.
//!
//! # Why the `black_box` discipline is not optional
//!
//! `aes-gcm` is generic Rust and inlines wholesale into this binary, so LLVM
//! can see the stores into the output buffer; `ring` is opaque assembly behind
//! `extern "C"` and cannot be elided. Left unguarded, the failure mode is
//! therefore not "both arms look fast" — it is *"the incumbent looks fast and
//! the challenger does not"*, which produces exactly the wrong decision. So:
//! the length is laundered so it is not a compile-time constant; the input
//! slices are laundered by reference (never by value — `black_box` of a
//! 1350-byte array copies 1350 bytes and charges that arm for it); eight bytes
//! of the produced plaintext are folded into an accumulator at a per-packet
//! varying offset; and the accumulator is printed. Two arms that folded
//! different bytes would disagree, and the runner treats disagreement as fatal.
//!
//! # Why every arm memcpys first
//!
//! Production copies the whole 1350-byte payload out of the wire buffer and
//! then decrypts the copy in place (`session.rs`), so that is what the copy
//! calibration arm measures and what every AEAD arm pays. Because all three
//! providers are driven through their *detached-tag* entry point, all three
//! copy exactly the same 1350 bytes — one `copy` calibration arm serves all of
//! them, and no arm is credited or charged a byte the others are not.
//! (`ring::aead::LessSafeKey::open_in_place_separate_tag` makes this possible;
//! its contiguous `open_in_place` is a wrapper *on top of* it, not the other
//! way round, so the detached form is also the cheaper one.)

use std::hint::black_box;

use aes_gcm::{AeadInPlace, Aes256Gcm};
use chacha20poly1305::ChaCha20Poly1305;
use lightway_expresslane::ExpresslaneSession;
use ring::aead::{Aad, LessSafeKey};

use crate::pool::{Sched, Src, WIRE_OVERHEAD, aad_v2, iv_for};

/// Everything an arm needs. Built once outside every timed region — a key
/// object constructed inside the loop would add AES key expansion and, for the
/// RustCrypto arms, a `zeroize` on drop.
pub struct Ctx<'a> {
    pub rc: &'a Aes256Gcm,
    pub ring: &'a LessSafeKey,
    pub cc: &'a ChaCha20Poly1305,
    /// Rebuilt fresh before every sample, untimed. See `arm_session_dec`.
    pub rx: &'a ExpresslaneSession,
    pub tx: &'a ExpresslaneSession,
    pub sid: [u8; 8],
}

/// `(folded checksum, successful operations)`.
pub type ArmFn = fn(&Ctx, &Src, &mut [u8], &Sched) -> (u64, u64);

#[inline(always)]
fn fold(acc: u64, buf: &[u8], off: usize) -> u64 {
    acc.rotate_left(1) ^ u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
}

// ---------------------------------------------------------------------------
// Calibration arms — these measure the harness, not a cipher.
// ---------------------------------------------------------------------------

/// Measurement floor: the schedule, the bounds checks, the fold, the call.
/// Must land in single-digit cycles per packet; if it does not, the harness
/// itself is a confound and nothing below it is trustworthy.
#[inline(never)]
pub fn arm_null(_c: &Ctx, s: &Src, dst: &mut [u8], sch: &Sched) -> (u64, u64) {
    let (mut acc, mut ok) = (0u64, 0u64);
    let stride = black_box(s.stride);
    let len = black_box(s.len);
    for i in 0..sch.n {
        let base = sch.slot[i] as usize * stride;
        let out = &mut dst[base..base + len];
        black_box(out.as_mut_ptr());
        acc = fold(acc, out, sch.fold[i] as usize);
        black_box(&mut *out);
        ok += 1;
    }
    (black_box(acc), ok)
}

/// The 1350-byte payload copy on its own — production's step 6. Subtracted
/// from each AEAD arm to derive an AEAD-only figure.
///
/// A *hot* copy should land around 0.03-0.15 cycles/byte. Anything above ~0.5
/// means the harness is broken, so this arm doubles as a known-answer test.
#[inline(never)]
pub fn arm_copy(_c: &Ctx, s: &Src, dst: &mut [u8], sch: &Sched) -> (u64, u64) {
    let (mut acc, mut ok) = (0u64, 0u64);
    let stride = black_box(s.stride);
    let len = black_box(s.len);
    let wire = black_box(&s.wire[..]);
    for i in 0..sch.n {
        let base = sch.slot[i] as usize * stride;
        let w = &wire[base..base + WIRE_OVERHEAD + len];
        let out = &mut dst[base..base + len];
        out.copy_from_slice(black_box(&w[WIRE_OVERHEAD..WIRE_OVERHEAD + len]));
        acc = fold(acc, out, sch.fold[i] as usize);
        black_box(&mut *out);
        ok += 1;
    }
    (black_box(acc), ok)
}

// ---------------------------------------------------------------------------
// Layer A — the raw primitive. This is the question M3 exists to answer.
// ---------------------------------------------------------------------------

/// The incumbent: `aes-gcm` 0.10, detached tag, exactly as `cipher.rs` calls it.
/// Everything in the optimization plan rests on this number.
#[inline(never)]
pub fn arm_rc_aesgcm_dec(c: &Ctx, s: &Src, dst: &mut [u8], sch: &Sched) -> (u64, u64) {
    let (mut acc, mut ok) = (0u64, 0u64);
    let stride = black_box(s.stride);
    let len = black_box(s.len);
    let wire = black_box(&s.wire[..]);
    for i in 0..sch.n {
        let base = sch.slot[i] as usize * stride;
        let w = &wire[base..base + WIRE_OVERHEAD + len];
        let counter = u64::from_be_bytes(w[0..8].try_into().unwrap());
        let flags = u16::from_be_bytes(w[38..40].try_into().unwrap());
        let aad = aad_v2(&c.sid, counter, flags);
        let out = &mut dst[base..base + len];
        out.copy_from_slice(black_box(&w[WIRE_OVERHEAD..WIRE_OVERHEAD + len]));
        let r = c.rc.decrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(black_box(&w[8..20])),
            black_box(&aad[..]),
            out,
            aes_gcm::Tag::from_slice(black_box(&w[20..36])),
        );
        ok += r.is_ok() as u64;
        acc = fold(acc, out, sch.fold[i] as usize);
        black_box(&mut *out);
    }
    (black_box(acc), ok)
}

/// The candidate. Same wire packets, same key, same nonce, same AAD, same
/// 1350-byte copy — ring and `aes-gcm` produce byte-identical ciphertext and
/// tags, so this arm literally decrypts the incumbent's output.
///
/// One structural handicap worth naming: `ring::aead::Nonce` is not `Copy` and
/// is consumed per call, so it must be constructed inside the loop. That is a
/// handful of cycles charged to ring and to nobody else.
#[inline(never)]
pub fn arm_ring_aesgcm_dec(c: &Ctx, s: &Src, dst: &mut [u8], sch: &Sched) -> (u64, u64) {
    let (mut acc, mut ok) = (0u64, 0u64);
    let stride = black_box(s.stride);
    let len = black_box(s.len);
    let wire = black_box(&s.wire[..]);
    for i in 0..sch.n {
        let base = sch.slot[i] as usize * stride;
        let w = &wire[base..base + WIRE_OVERHEAD + len];
        let counter = u64::from_be_bytes(w[0..8].try_into().unwrap());
        let flags = u16::from_be_bytes(w[38..40].try_into().unwrap());
        let aad = aad_v2(&c.sid, counter, flags);
        let iv: [u8; 12] = w[8..20].try_into().unwrap();
        let tag: [u8; 16] = w[20..36].try_into().unwrap();
        let out = &mut dst[base..base + len];
        out.copy_from_slice(black_box(&w[WIRE_OVERHEAD..WIRE_OVERHEAD + len]));
        let r = c.ring.open_in_place_separate_tag(
            ring::aead::Nonce::assume_unique_for_key(iv),
            Aad::from(black_box(&aad[..])),
            ring::aead::Tag::from(tag),
            out,
            0..,
        );
        ok += r.is_ok() as u64;
        acc = fold(acc, out, sch.fold[i] as usize);
        black_box(&mut *out);
    }
    (black_box(acc), ok)
}

/// What a pure-Rust ChaCha20-Poly1305 costs. Reference point, not an option:
/// BoringTun ships its own ChaCha rather than this crate, and on x86_64 with
/// AES-NI the AES arm is the one that decides anything. Reported separately and
/// never folded into the provider comparison.
#[inline(never)]
pub fn arm_rc_chacha_dec(c: &Ctx, s: &Src, dst: &mut [u8], sch: &Sched) -> (u64, u64) {
    let (mut acc, mut ok) = (0u64, 0u64);
    let stride = black_box(s.stride);
    let len = black_box(s.len);
    let wire = black_box(&s.wire_cc[..]);
    for i in 0..sch.n {
        let base = sch.slot[i] as usize * stride;
        let w = &wire[base..base + WIRE_OVERHEAD + len];
        let counter = u64::from_be_bytes(w[0..8].try_into().unwrap());
        let flags = u16::from_be_bytes(w[38..40].try_into().unwrap());
        let aad = aad_v2(&c.sid, counter, flags);
        let out = &mut dst[base..base + len];
        out.copy_from_slice(black_box(&w[WIRE_OVERHEAD..WIRE_OVERHEAD + len]));
        let r = c.cc.decrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(black_box(&w[8..20])),
            black_box(&aad[..]),
            out,
            aes_gcm::Tag::from_slice(black_box(&w[20..36])),
        );
        ok += r.is_ok() as u64;
        acc = fold(acc, out, sch.fold[i] as usize);
        black_box(&mut *out);
    }
    (black_box(acc), ok)
}

// --- encrypt direction (process_out, the unsaturated thread) ---------------

#[inline(never)]
pub fn arm_rc_aesgcm_enc(c: &Ctx, s: &Src, dst: &mut [u8], sch: &Sched) -> (u64, u64) {
    let (mut acc, mut ok) = (0u64, 0u64);
    let stride = black_box(s.stride);
    let len = black_box(s.len);
    let plain = black_box(&s.plain[..]);
    for i in 0..sch.n {
        let slot = sch.slot[i] as usize;
        let base = slot * stride;
        let counter = slot as u64 + 1;
        let iv = iv_for(counter);
        let aad = aad_v2(&c.sid, counter, 0);
        let out = &mut dst[base..base + len];
        out.copy_from_slice(black_box(&plain[base..base + len]));
        match c.rc.encrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(black_box(&iv[..])),
            black_box(&aad[..]),
            out,
        ) {
            Ok(tag) => {
                ok += 1;
                acc = fold(acc, &tag, 0);
            }
            Err(_) => acc = acc.rotate_left(1),
        }
        acc = fold(acc, out, sch.fold[i] as usize);
        black_box(&mut *out);
    }
    (black_box(acc), ok)
}

#[inline(never)]
pub fn arm_ring_aesgcm_enc(c: &Ctx, s: &Src, dst: &mut [u8], sch: &Sched) -> (u64, u64) {
    let (mut acc, mut ok) = (0u64, 0u64);
    let stride = black_box(s.stride);
    let len = black_box(s.len);
    let plain = black_box(&s.plain[..]);
    for i in 0..sch.n {
        let slot = sch.slot[i] as usize;
        let base = slot * stride;
        let counter = slot as u64 + 1;
        let iv = iv_for(counter);
        let aad = aad_v2(&c.sid, counter, 0);
        let out = &mut dst[base..base + len];
        out.copy_from_slice(black_box(&plain[base..base + len]));
        match c.ring.seal_in_place_separate_tag(
            ring::aead::Nonce::assume_unique_for_key(iv),
            Aad::from(black_box(&aad[..])),
            out,
        ) {
            Ok(tag) => {
                ok += 1;
                acc = fold(acc, tag.as_ref(), 0);
            }
            Err(_) => acc = acc.rotate_left(1),
        }
        acc = fold(acc, out, sch.fold[i] as usize);
        black_box(&mut *out);
    }
    (black_box(acc), ok)
}

#[inline(never)]
pub fn arm_rc_chacha_enc(c: &Ctx, s: &Src, dst: &mut [u8], sch: &Sched) -> (u64, u64) {
    let (mut acc, mut ok) = (0u64, 0u64);
    let stride = black_box(s.stride);
    let len = black_box(s.len);
    let plain = black_box(&s.plain[..]);
    for i in 0..sch.n {
        let slot = sch.slot[i] as usize;
        let base = slot * stride;
        let counter = slot as u64 + 1;
        let iv = iv_for(counter);
        let aad = aad_v2(&c.sid, counter, 0);
        let out = &mut dst[base..base + len];
        out.copy_from_slice(black_box(&plain[base..base + len]));
        match c.cc.encrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(black_box(&iv[..])),
            black_box(&aad[..]),
            out,
        ) {
            Ok(tag) => {
                ok += 1;
                acc = fold(acc, &tag, 0);
            }
            Err(_) => acc = acc.rotate_left(1),
        }
        acc = fold(acc, out, sch.fold[i] as usize);
        black_box(&mut *out);
    }
    (black_box(acc), ok)
}

// ---------------------------------------------------------------------------
// Layer B — the real shipping code path.
// ---------------------------------------------------------------------------

/// `ExpresslaneSession::decrypt` from the real rlib: header parse, rx mutex,
/// `would_reject`, bounds checks, the 1350-byte copy, the AEAD, and the replay
/// `commit` (which for in-order counters runs a 128-word `shift_left`).
///
/// `B - A` is the whole point of this arm — it prices everything the cipher
/// swap will *not* fix.
///
/// There is deliberately no hot variant. `would_reject` short-circuits ahead of
/// all crypto, so an arm that reused one buffer would be measuring the reject
/// path and would report a spectacular, meaningless number. The runner gives
/// this arm a fresh session before every sample (untimed) and asserts
/// `packets_received()` equals the pass length afterwards, which proves both
/// that authentication happened and that the window committed.
#[inline(never)]
pub fn arm_session_dec(c: &Ctx, s: &Src, dst: &mut [u8], sch: &Sched) -> (u64, u64) {
    let (mut acc, mut ok) = (0u64, 0u64);
    let stride = black_box(s.stride);
    let len = black_box(s.len);
    let wire = black_box(&s.wire[..]);
    for i in 0..sch.n {
        let base = sch.slot[i] as usize * stride;
        let w = &wire[base..base + WIRE_OVERHEAD + len];
        let out = &mut dst[base..base + len];
        let r = c.rx.decrypt(c.sid, black_box(w), out);
        ok += r.is_ok() as u64;
        acc = fold(acc, out, sch.fold[i] as usize);
        black_box(&mut *out);
    }
    (black_box(acc), ok)
}

/// `ExpresslaneSession::encrypt`: the read-lock on the send key, the AAD build,
/// the payload copy into the wire buffer, the AEAD, and the header writes.
///
/// The fold reaches into `out[WIRE_OVERHEAD + off]` and `out[20..28]` so the
/// checksum covers the same ciphertext and tag bytes the Layer A encrypt arms
/// fold — which is what lets the runner prove all three produce identical
/// output.
#[inline(never)]
pub fn arm_session_enc(c: &Ctx, s: &Src, dst: &mut [u8], sch: &Sched) -> (u64, u64) {
    let (mut acc, mut ok) = (0u64, 0u64);
    let stride = black_box(s.stride);
    let len = black_box(s.len);
    let plain = black_box(&s.plain[..]);
    for i in 0..sch.n {
        let slot = sch.slot[i] as usize;
        let base = slot * stride;
        let counter = slot as u64 + 1;
        let iv = iv_for(counter);
        let out = &mut dst[base..base + WIRE_OVERHEAD + len];
        let r = c.tx.encrypt(
            counter,
            c.sid,
            black_box(&plain[base..base + len]),
            iv,
            false,
            out,
        );
        ok += r.is_ok() as u64;
        acc = fold(acc, out, 20);
        acc = fold(acc, out, WIRE_OVERHEAD + sch.fold[i] as usize);
        black_box(&mut *out);
    }
    (black_box(acc), ok)
}
