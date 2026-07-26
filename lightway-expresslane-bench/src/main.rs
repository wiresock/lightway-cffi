//! M3: what does the ExpressLane AEAD actually cost, on the rig?
//!
//! M1 measured the real per-packet budget on the production rig with
//! `QueryThreadCycleTime`: the inbound worker `process_in_0` sits at 90-99% CPU,
//! sustains 4.02 GHz, and burns **7.66 cycles per inner payload byte** — a
//! single-core ceiling of 4.20 Gbps against BoringTun/WireGuard's 6.33 Gbps on
//! the same box. Matching WireGuard means getting that 7.66 down to roughly 4.8.
//!
//! The entire optimization plan is ranked on one number nobody has measured
//! here: an off-rig benchmark suggesting RustCrypto's `aes-gcm` costs 3.1-3.7
//! cycles/byte for AES-256-GCM — 41-49% of the whole budget — and that `ring`
//! is 3.4-3.6x faster. If that is right, swapping the AEAD provider is the
//! top-ranked change. If it is wrong, the plan is ranked against a fiction and
//! the work belongs somewhere else entirely. **This binary exists to confirm or
//! destroy that single assumption on the actual hardware.**
//!
//! # What it measures
//!
//! - **Layer A** — the raw primitive: `aes-gcm` 0.10 (the incumbent), `ring`'s
//!   AES-256-GCM (the candidate), and RustCrypto ChaCha20-Poly1305 (a reference
//!   point for what BoringTun's primitive family costs), all decrypting the
//!   *same* production wire packets with the same 12-byte nonce, the same
//!   18-byte Version2 AAD and the same detached 16-byte tag, in both
//!   directions.
//! - **Layer B** — `ExpresslaneSession::decrypt`/`::encrypt` from the real
//!   shipping rlib. `B - A` prices everything a cipher swap will *not* fix: the
//!   1350-byte `copy_from_slice`, the rx mutex, the replay window's 128-word
//!   shift, and the AAD build.
//! - A **copy calibration** arm, so each provider's AEAD-only cost can be
//!   derived by subtracting the memcpy every arm pays.
//! - **hot vs cold** working sets, bracketing how much of each figure is memory
//!   rather than compute, and a **payload sweep** separating fixed per-packet
//!   cost from per-byte cost.
//!
//! # Why `QueryThreadCycleTime` and not `__rdtsc`
//!
//! Same reason M1 did it (`netlib/src/tools/perf_probe.h`): the TSC is
//! invariant on modern x86, so an rdtsc-derived cycles/byte silently bakes in
//! an assumed frequency — the exact error M1 was built to eliminate. M3's
//! numbers have to be *subtractable* from M1's 7.66, so they must come from the
//! same clock source, and effective GHz is reported as a measured output so it
//! can be checked against M1's 4.02.
//!
//! # What would make a run worthless
//!
//! Printed as explicit gates at the end, but in short: a checksum that differs
//! between arms (something was optimised away), any decrypt that failed (the
//! cheap authentication-failure path was measured instead of the real one),
//! hardware AES not detected, effective GHz far from M1's, or per-arm spread
//! above 5%. See `doc/perf-m3-aead.md`.

mod arms;
mod cpu;
mod pool;
mod win;

use std::hint::black_box;

use aes_gcm::{AeadInPlace, Aes256Gcm, KeyInit};
use chacha20poly1305::ChaCha20Poly1305;
use lightway_expresslane::{ExpresslaneKey, ExpresslaneSession, ExpresslaneVersion};
use ring::aead::{AES_256_GCM, LessSafeKey, UnboundKey};

use arms::{ArmFn, Ctx};
use pool::{Sched, Src, WIRE_OVERHEAD, aad_v2};

// --- imported constants from M1. Valid only for that rig, that traffic mix, ---
// --- and a 1350-byte mean inner packet. -------------------------------------
const M1_CPB: f64 = 7.66;
const M1_GHZ: f64 = 4.02;
const M1_MEAN_PKT: usize = 1350;
const M1_GOODPUT_GBPS: f64 = 4.0;
const WIREGUARD_GBPS: f64 = 6.33;

const SEED: u64 = 0xC0FF_EE01_5EED_1350;
const SESSION_ID: [u8; 8] = [0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88];
const KEY_BYTES: [u8; 32] = [
    0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    0x76, 0x2e, 0x71, 0x60, 0xf3, 0x8b, 0x4d, 0xa5, 0x6a, 0x78, 0x4d, 0x90, 0x45, 0x19, 0x0c, 0xfe,
];

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Family {
    Null,
    Copy,
    /// Every decrypt arm must recover the identical plaintext.
    Dec,
    /// `aes-gcm`, `ring` and the session must produce identical ciphertext.
    Enc,
    /// ChaCha ciphertext, necessarily different. Its own family.
    EncChaCha,
}

struct Spec {
    name: &'static str,
    f: ArmFn,
    family: Family,
    /// Layer B decrypt has no hot variant — see `arms::arm_session_dec`.
    cold_only: bool,
    /// Subject to the "hardware AES is not engaged" magnitude gate (G5b).
    /// Layer A only: the Layer B session arms lump in the payload copy, the rx
    /// mutex and the replay commit, so folding them into a gate whose trip
    /// point is a *cipher* magnitude leaves almost no margin. They would not
    /// add detection power either — software AES shows up in the Layer A arms
    /// an order of magnitude before it could push a session arm past 10 c/B.
    is_aesgcm: bool,
    /// Needs `packets_received()` verified after every sample.
    is_session_dec: bool,
}

fn specs() -> Vec<Spec> {
    vec![
        Spec { name: "null",                f: arms::arm_null,            family: Family::Null,      cold_only: false, is_aesgcm: false, is_session_dec: false },
        Spec { name: "copy_payload",        f: arms::arm_copy,            family: Family::Copy,      cold_only: false, is_aesgcm: false, is_session_dec: false },
        Spec { name: "rc_aesgcm256_dec",    f: arms::arm_rc_aesgcm_dec,   family: Family::Dec,       cold_only: false, is_aesgcm: true,  is_session_dec: false },
        Spec { name: "ring_aesgcm256_dec",  f: arms::arm_ring_aesgcm_dec, family: Family::Dec,       cold_only: false, is_aesgcm: true,  is_session_dec: false },
        Spec { name: "rc_chacha_dec *",     f: arms::arm_rc_chacha_dec,   family: Family::Dec,       cold_only: false, is_aesgcm: false, is_session_dec: false },
        Spec { name: "session_decrypt",     f: arms::arm_session_dec,     family: Family::Dec,       cold_only: true,  is_aesgcm: false, is_session_dec: true  },
        Spec { name: "rc_aesgcm256_enc",    f: arms::arm_rc_aesgcm_enc,   family: Family::Enc,       cold_only: false, is_aesgcm: true,  is_session_dec: false },
        Spec { name: "ring_aesgcm256_enc",  f: arms::arm_ring_aesgcm_enc, family: Family::Enc,       cold_only: false, is_aesgcm: true,  is_session_dec: false },
        Spec { name: "rc_chacha_enc *",     f: arms::arm_rc_chacha_enc,   family: Family::EncChaCha, cold_only: false, is_aesgcm: false, is_session_dec: false },
        Spec { name: "session_encrypt",     f: arms::arm_session_enc,     family: Family::Enc,       cold_only: false, is_aesgcm: false, is_session_dec: false },
    ]
}

struct Res {
    name: &'static str,
    hot: bool,
    family: Family,
    is_aesgcm: bool,
    /// One entry per sample; a sample is exactly one pass over the pool.
    cpb: Vec<f64>,
    /// Cycles / CPU-time / wall-time accumulated by bracketing each arm-round
    /// block ONCE, not per sample. `GetThreadTimes` and QPC are never read
    /// inside a per-sample cycle window, so this is a strictly separate
    /// accounting from `cpb` and cannot perturb the c/B numbers.
    ///
    /// There is deliberately no per-sample cycle total alongside these: a sum
    /// of per-sample cycle deltas divided by this tick-quantised CPU time is
    /// precisely the quotient that made effective GHz meaningless, and keeping
    /// the numerator around invites someone to recompute it.
    freq_cycles: u64,
    freq_cpu_100ns: u64,
    freq_qpc: i64,
    total_ops: u64,
    expected_ops: u64,
    acc: u64,
    acc_stable: bool,
    payload_len: usize,
}

/// Minimum accumulated CPU time before effective GHz or the preemption ratio
/// may be reported at all, in 100 ns units (500 ms).
///
/// `GetThreadTimes` advances in ~15.6 ms scheduler ticks. Bracketing whole
/// arm-round blocks keeps the number of quantized boundaries down to one pair
/// per round, but a fast arm (`null` runs its whole clamped sample budget in a
/// few ms) can still accumulate less than a single tick — in which case the
/// quotient measures tick quantization, not frequency. Below this floor the
/// honest answer is "not measurable", not a number.
const FREQ_MIN_100NS: u64 = 5_000_000;

impl Res {
    fn median(&self) -> f64 {
        pct(&sorted(&self.cpb), 0.5)
    }
    fn freq_measurable(&self) -> bool {
        self.freq_cpu_100ns >= FREQ_MIN_100NS
    }
    fn cpu_ms(&self) -> f64 {
        self.freq_cpu_100ns as f64 * 1e-4
    }
    /// `None` when too little CPU time accumulated for the quotient to mean
    /// anything. Callers must not substitute 0.0 — that silently drops the arm
    /// from a min/max fold instead of flagging it.
    fn eff_ghz(&self) -> Option<f64> {
        if !self.freq_measurable() {
            return None;
        }
        let cpu_s = self.freq_cpu_100ns as f64 * 100e-9;
        Some(self.freq_cycles as f64 / cpu_s / 1e9)
    }
    /// Wall-vs-CPU divergence over the same bracketed blocks. `None` for the
    /// same reason as `eff_ghz`.
    fn preempt(&self, qpc_freq: f64) -> Option<f64> {
        if !self.freq_measurable() {
            return None;
        }
        let cpu_s = self.freq_cpu_100ns as f64 * 100e-9;
        let wall_s = self.freq_qpc as f64 / qpc_freq;
        Some(((wall_s - cpu_s) / cpu_s).abs())
    }
    fn spread(&self) -> f64 {
        let s = sorted(&self.cpb);
        let m = pct(&s, 0.5);
        if m <= 0.0 {
            0.0
        } else {
            (pct(&s, 0.9) - pct(&s, 0.1)) / m
        }
    }
}

fn sorted(v: &[f64]) -> Vec<f64> {
    let mut s = v.to_vec();
    s.sort_by(|a, b| a.partial_cmp(b).unwrap());
    s
}

fn pct(sorted: &[f64], p: f64) -> f64 {
    if sorted.is_empty() {
        return f64::NAN;
    }
    let idx = ((sorted.len() - 1) as f64 * p).round() as usize;
    sorted[idx]
}

#[derive(Clone, Copy)]
struct Cfg {
    rounds: usize,
    pool_bytes: usize,
    max_slots: usize,
    pin: Option<u32>,
    m1_rig: bool,
    sweep: bool,
    warmup_secs: f64,
    target_ms_per_arm_round: f64,
}

fn parse_args() -> Cfg {
    let mut cfg = Cfg {
        rounds: 5,
        // 8 MiB per pool, matching the order of the NDIS packet-block ring, so
        // src + dst = 16 MiB touched per pass. Comfortably past any per-core L2.
        pool_bytes: 8 * 1024 * 1024,
        max_slots: 16384,
        pin: None,
        m1_rig: false,
        sweep: true,
        warmup_secs: 3.0,
        target_ms_per_arm_round: 250.0,
    };
    let mut it = std::env::args().skip(1);
    while let Some(a) = it.next() {
        match a.as_str() {
            "--rounds" => cfg.rounds = it.next().and_then(|v| v.parse().ok()).unwrap_or(5),
            "--pool-mib" => {
                let m: usize = it.next().and_then(|v| v.parse().ok()).unwrap_or(8);
                cfg.pool_bytes = m * 1024 * 1024;
            }
            "--max-slots" => cfg.max_slots = it.next().and_then(|v| v.parse().ok()).unwrap_or(16384),
            "--pin" => cfg.pin = it.next().and_then(|v| v.parse().ok()),
            "--m1-rig" => cfg.m1_rig = true,
            "--no-sweep" => cfg.sweep = false,
            "--quick" => {
                cfg.rounds = 1;
                cfg.pool_bytes = 2 * 1024 * 1024;
                cfg.sweep = false;
                cfg.warmup_secs = 0.25;
                cfg.target_ms_per_arm_round = 40.0;
            }
            "--help" | "-h" => {
                println!(
                    "m3-aead — AEAD provider benchmark for ExpressLane\n\
                     \n\
                     --rounds N      timing rounds, arms interleaved (default 5)\n\
                     --pool-mib N    cold pool size per buffer (default 8)\n\
                     --max-slots N   cap on packets per pool (default 16384)\n\
                     --pin N         hard-pin to logical CPU N (bare metal only)\n\
                     --m1-rig        assert this IS the M1 rig; drops the projection caveat\n\
                     --no-sweep      skip the payload-size sweep\n\
                     --quick         smoke test, NOT a valid measurement\n\
                     \n\
                     Redirect stdout to capture the report:  m3-aead.exe > m3.txt"
                );
                std::process::exit(0);
            }
            other => eprintln!("warning: ignoring unknown argument {other}"),
        }
    }
    cfg
}

/// Keys and sessions, all built once, before any timing.
struct Keys {
    rc: Aes256Gcm,
    ring: LessSafeKey,
    cc: ChaCha20Poly1305,
    tx: ExpresslaneSession,
    key: ExpresslaneKey,
}

fn build_keys() -> Keys {
    let key = ExpresslaneKey(KEY_BYTES);
    let tx = ExpresslaneSession::new(ExpresslaneVersion::Version2);
    tx.update_next_self_key(key).expect("stage self key");
    tx.promote_self_key();
    Keys {
        rc: Aes256Gcm::new_from_slice(&key.0).expect("aes-gcm key"),
        // LessSafeKey, not OpeningKey: OpeningKey *generates* its nonce from a
        // NonceSequence and has no detached-tag entry point at all. ExpressLane
        // takes the nonce off the wire and tolerates reordering, so a nonce
        // sequence is structurally wrong here. "LessSafe" refers only to ring
        // not policing nonce uniqueness, which the wire protocol already does.
        ring: LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &key.0).expect("ring key")),
        cc: <ChaCha20Poly1305 as KeyInit>::new_from_slice(&key.0).expect("chacha key"),
        tx,
        key,
    }
}

fn fresh_rx(keys: &Keys) -> ExpresslaneSession {
    let rx = ExpresslaneSession::new(ExpresslaneVersion::Version2);
    rx.update_peer_key(keys.key).expect("install peer key");
    rx
}

// ---------------------------------------------------------------------------
// Startup self-test. Cheap, and it is the difference between a benchmark and a
// random-number generator: it proves every arm decrypts to the known plaintext
// and that ring and aes-gcm produce byte-identical output.
// ---------------------------------------------------------------------------

struct SelfTest {
    rc_roundtrip: bool,
    ring_roundtrip: bool,
    cc_roundtrip: bool,
    session_roundtrip: bool,
    cross_provider_ct: bool,
}

fn self_test(keys: &Keys, src: &Src) -> SelfTest {
    let len = src.len;
    let base = 0usize;
    let w = &src.wire[base..base + WIRE_OVERHEAD + len];
    let expected = &src.plain[base..base + len];
    let counter = u64::from_be_bytes(w[0..8].try_into().unwrap());
    let flags = u16::from_be_bytes(w[38..40].try_into().unwrap());
    let aad = aad_v2(&src.session_id, counter, flags);
    let iv: [u8; 12] = w[8..20].try_into().unwrap();
    let tag: [u8; 16] = w[20..36].try_into().unwrap();

    let mut buf = vec![0u8; len];

    buf.copy_from_slice(&w[WIRE_OVERHEAD..WIRE_OVERHEAD + len]);
    let rc_roundtrip = keys
        .rc
        .decrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(&iv),
            &aad,
            &mut buf,
            aes_gcm::Tag::from_slice(&tag),
        )
        .is_ok()
        && buf == expected;

    buf.copy_from_slice(&w[WIRE_OVERHEAD..WIRE_OVERHEAD + len]);
    let ring_roundtrip = keys
        .ring
        .open_in_place_separate_tag(
            ring::aead::Nonce::assume_unique_for_key(iv),
            ring::aead::Aad::from(&aad[..]),
            ring::aead::Tag::from(tag),
            &mut buf,
            0..,
        )
        .is_ok()
        && buf == expected;

    let wc = &src.wire_cc[base..base + WIRE_OVERHEAD + len];
    let cc_tag: [u8; 16] = wc[20..36].try_into().unwrap();
    buf.copy_from_slice(&wc[WIRE_OVERHEAD..WIRE_OVERHEAD + len]);
    let cc_roundtrip = keys
        .cc
        .decrypt_in_place_detached(
            aes_gcm::Nonce::from_slice(&iv),
            &aad,
            &mut buf,
            aes_gcm::Tag::from_slice(&cc_tag),
        )
        .is_ok()
        && buf == expected;

    let rx = fresh_rx(keys);
    let session_roundtrip = match rx.decrypt(src.session_id, w, &mut buf) {
        Ok((n, false)) => n == len && buf == expected,
        _ => false,
    };

    // The load-bearing equivalence: same key, nonce, AAD and plaintext must
    // give the same ciphertext AND the same detached tag under both providers.
    // Without this, the two arms could be doing different work under similar
    // names and the comparison would mean nothing.
    let mut a = expected.to_vec();
    let mut b = expected.to_vec();
    let ta: [u8; 16] = keys
        .rc
        .encrypt_in_place_detached(aes_gcm::Nonce::from_slice(&iv), &aad, &mut a)
        .expect("rc seal")
        .into();
    let tb = keys
        .ring
        .seal_in_place_separate_tag(
            ring::aead::Nonce::assume_unique_for_key(iv),
            ring::aead::Aad::from(&aad[..]),
            &mut b,
        )
        .expect("ring seal");
    let cross_provider_ct = a == b && ta.as_slice() == tb.as_ref();

    SelfTest {
        rc_roundtrip,
        ring_roundtrip,
        cc_roundtrip,
        session_roundtrip,
        cross_provider_ct,
    }
}

// ---------------------------------------------------------------------------
// The runner.
// ---------------------------------------------------------------------------

/// One sample = one pass over the pool. `QueryThreadCycleTime` is read exactly
/// twice per sample, never per packet — and nothing else is read inside the
/// window, so the measured cycles cover the arm and only the arm. CPU time and
/// wall time are accounted separately, once per arm-round block.
fn take_sample(f: ArmFn, ctx: &Ctx, src: &Src, dst: &mut [u8], sch: &Sched) -> (u64, u64, u64) {
    let c0 = win::cycles();
    let (acc, ok) = f(ctx, src, dst, sch);
    let c1 = win::cycles();
    (acc, ok, c1 - c0)
}

/// Returns the per-arm results and the set of logical CPUs the run was
/// observed on (sampled at each arm-round boundary).
#[allow(clippy::too_many_arguments)]
fn run_all(
    cfg: &Cfg,
    keys: &Keys,
    src: &Src,
    dst: &mut [u8],
    specs: &[Spec],
) -> (Vec<Res>, Vec<u32>) {
    let sched_cold = Sched::new(src, false, SEED ^ 0xABCD);
    let sched_hot = Sched::new(src, true, SEED ^ 0xABCD);

    // (spec index, hot) pairs, and a parallel result slot for each.
    let mut jobs: Vec<(usize, bool)> = Vec::new();
    for (i, s) in specs.iter().enumerate() {
        if !s.cold_only {
            jobs.push((i, true));
        }
        jobs.push((i, false));
    }

    let mut results: Vec<Res> = jobs
        .iter()
        .map(|&(i, hot)| Res {
            name: specs[i].name,
            hot,
            family: specs[i].family,
            is_aesgcm: specs[i].is_aesgcm,
            cpb: Vec::with_capacity(cfg.rounds * 600),
            freq_cycles: 0,
            freq_cpu_100ns: 0,
            freq_qpc: 0,
            total_ops: 0,
            expected_ops: 0,
            acc: 0,
            acc_stable: true,
            payload_len: src.len,
        })
        .collect();

    // Sample count is calibrated per job so every arm gets a comparable amount
    // of timed CPU, rather than a fixed count that would leave `null` measuring
    // noise and `session_decrypt` running for a minute.
    let mut n_samples: Vec<usize> = Vec::with_capacity(jobs.len());
    for &(i, hot) in &jobs {
        let sch = if hot { &sched_hot } else { &sched_cold };
        let rx = fresh_rx(keys);
        let ctx = Ctx { rc: &keys.rc, ring: &keys.ring, cc: &keys.cc, rx: &rx, tx: &keys.tx, sid: src.session_id };
        let (_, _, cyc) = take_sample(specs[i].f, &ctx, src, dst, sch);
        let est_ms = cyc as f64 / (M1_GHZ * 1e9) * 1000.0;
        let n = (cfg.target_ms_per_arm_round / est_ms.max(1e-4)).ceil() as usize;
        n_samples.push(n.clamp(8, 512));
    }

    let mut cpus_seen: Vec<u32> = Vec::new();
    let mut order: Vec<usize> = (0..jobs.len()).collect();
    for round in 0..cfg.rounds {
        // Interleave and permute: running all of arm A then all of arm B lets
        // thermal drift masquerade as a provider difference.
        let n_order = order.len().max(1);
        order.rotate_left(round % n_order);
        if round % 2 == 1 {
            order.reverse();
        }

        for &j in &order {
            let (i, hot) = jobs[j];
            let spec = &specs[i];
            let sch = if hot { &sched_hot } else { &sched_cold };
            eprintln!(
                "  round {}/{}  {:<20} {}",
                round + 1,
                cfg.rounds,
                spec.name,
                if hot { "hot" } else { "cold" }
            );

            // Two discarded warm-up samples per arm per round: they re-warm the
            // i-cache and BTB and absorb any AVX frequency-license transition.
            for _ in 0..2 {
                let rx = fresh_rx(keys);
                let ctx = Ctx { rc: &keys.rc, ring: &keys.ring, cc: &keys.cc, rx: &rx, tx: &keys.tx, sid: src.session_id };
                take_sample(spec.f, &ctx, src, dst, sch);
            }

            // Frequency / preemption accounting brackets the WHOLE block of
            // recorded samples exactly once. `GetThreadTimes` moves in ~15.6 ms
            // ticks, so summing per-sample deltas accumulates quantization
            // error rather than recovering the total — a `null` sample brackets
            // ~7 us and almost always lands inside one tick, summing to zero.
            // One pair of reads around ~250 ms of contiguous CPU is the only
            // form in which this API answers the question being asked of it.
            cpus_seen.push(win::current_cpu());
            let fc0 = win::cycles();
            let ft0 = win::cpu_100ns();
            let fq0 = win::qpc();

            for _ in 0..n_samples[j] {
                // Fresh receive session before every sample, untimed. Mandatory
                // for the Layer B decrypt arm (the replay window rejects a
                // second pass); harmless and uniform for the others.
                let rx = fresh_rx(keys);
                let ctx = Ctx { rc: &keys.rc, ring: &keys.ring, cc: &keys.cc, rx: &rx, tx: &keys.tx, sid: src.session_id };
                let (acc, ok, cyc) = take_sample(spec.f, &ctx, src, dst, sch);

                let r = &mut results[j];
                if r.total_ops == 0 {
                    r.acc = acc;
                } else if r.acc != acc {
                    r.acc_stable = false;
                }
                r.total_ops += ok;
                r.expected_ops += sch.n as u64;
                r.cpb.push(cyc as f64 / (sch.n as f64 * src.len as f64));

                if spec.is_session_dec {
                    assert_eq!(
                        rx.packets_received(),
                        sch.n as u64,
                        "session arm did not commit every packet — the replay window \
                         rejected part of the pass and the reject path was measured"
                    );
                }
            }

            let fq1 = win::qpc();
            let ft1 = win::cpu_100ns();
            let fc1 = win::cycles();
            let r = &mut results[j];
            r.freq_cycles += fc1 - fc0;
            r.freq_cpu_100ns += ft1.saturating_sub(ft0);
            r.freq_qpc += fq1 - fq0;
        }
    }
    cpus_seen.sort_unstable();
    cpus_seen.dedup();
    (results, cpus_seen)
}

fn warm_up(cfg: &Cfg, keys: &Keys, src: &Src, dst: &mut [u8]) {
    // Bring the core to its sustained P-state before anything is recorded; M1
    // saw ~4% frequency drift over the first ~15 s.
    let sch = Sched::new(src, false, SEED);
    let f = win::qpc_freq() as f64;
    let t0 = win::qpc();
    let mut sink = 0u64;
    while (win::qpc() - t0) as f64 / f < cfg.warmup_secs {
        let rx = fresh_rx(keys);
        let ctx = Ctx { rc: &keys.rc, ring: &keys.ring, cc: &keys.cc, rx: &rx, tx: &keys.tx, sid: src.session_id };
        let (acc, _) = arms::arm_rc_aesgcm_dec(&ctx, src, dst, &sch);
        sink ^= acc;
    }
    black_box(sink);
}

// ---------------------------------------------------------------------------
// Report.
// ---------------------------------------------------------------------------

fn find<'a>(res: &'a [Res], name: &str, hot: bool) -> Option<&'a Res> {
    res.iter().find(|r| r.name == name && r.hot == hot)
}

fn med(res: &[Res], name: &str, hot: bool) -> f64 {
    find(res, name, hot).map(|r| r.median()).unwrap_or(f64::NAN)
}

/// Standalone throughput a given cycles/byte implies at M1's measured clock.
fn gbps(cpb: f64) -> f64 {
    M1_GHZ * 8.0 / cpb
}

fn main() {
    let cfg = parse_args();
    let sched_note = win::set_scheduling(cfg.pin);
    let info = cpu::detect();
    let timer_ns = win::timer_cost_ns();
    let qfreq = win::qpc_freq() as f64;
    let (sys_idle0, sys_kern0, sys_user0) = win::system_times();
    let run_t0 = win::qpc();

    let keys = build_keys();

    eprintln!("building pools ({} MiB per buffer) ...", cfg.pool_bytes / (1024 * 1024));
    let src = Src::build(M1_MEAN_PKT, cfg.pool_bytes, cfg.max_slots, keys.key, SESSION_ID, SEED);
    let mut dst = vec![0u8; src.slots * src.stride];

    let st = self_test(&keys, &src);

    // Emitted BEFORE any timing. A run that dies late — an assert in the last
    // round, a dropped RDP session, Ctrl-C — otherwise leaves the remote
    // operator with no record at all, not even of which CPU it ran on.
    print_header(&cfg, &info, &src, &st, timer_ns, &sched_note);

    eprintln!("warm-up ({:.1} s) ...", cfg.warmup_secs);
    warm_up(&cfg, &keys, &src, &mut dst);

    let specs = specs();
    eprintln!("main run: {} rounds", cfg.rounds);
    let (res, cpus_seen) = run_all(&cfg, &keys, &src, &mut dst, &specs);
    drop(dst);

    // Payload sweep: separates the fixed per-packet cost (key schedule setup,
    // J0, the length block, the call) from the genuinely per-byte cost. It also
    // doubles as the elision detector — a per-packet cost that does not scale
    // with length is the signature of a deleted keystream.
    let mut sweep: Vec<(usize, f64, f64, f64, f64)> = Vec::new();
    if cfg.sweep {
        for &len in &[64usize, 256, 576, M1_MEAN_PKT] {
            eprintln!("sweep: {len} B");
            let s = Src::build(len, cfg.pool_bytes, cfg.max_slots, keys.key, SESSION_ID, SEED);
            let mut d = vec![0u8; s.slots * s.stride];
            // `crate::` qualified: the `specs` local binding above shadows the
            // function of the same name in this scope.
            let sub: Vec<Spec> = crate::specs()
                .into_iter()
                .filter(|x| x.name == "rc_aesgcm256_dec" || x.name == "ring_aesgcm256_dec")
                .collect();
            let sub_cfg = Cfg { rounds: 3, sweep: false, warmup_secs: 0.0, ..cfg };
            let (r, _) = run_all(&sub_cfg, &keys, &s, &mut d, &sub);
            sweep.push((
                len,
                med(&r, "rc_aesgcm256_dec", false),
                med(&r, "rc_aesgcm256_dec", false) * len as f64,
                med(&r, "ring_aesgcm256_dec", false),
                med(&r, "ring_aesgcm256_dec", false) * len as f64,
            ));
        }
    }

    let run_wall = (win::qpc() - run_t0) as f64 / qfreq;
    let (sys_idle1, sys_kern1, sys_user1) = win::system_times();
    let sys_busy_s = (((sys_kern1 - sys_kern0) - (sys_idle1 - sys_idle0)) + (sys_user1 - sys_user0))
        as f64
        * 100e-9;
    let sys_busy_cores = sys_busy_s / run_wall.max(1e-9);

    print_report(
        &cfg, &info, &src, &res, &sweep, &st, timer_ns, run_wall, sys_busy_cores, &cpus_seen,
    );
}

/// Everything that is knowable before the first timed sample. Printed and
/// flushed immediately so a truncated run still records its own provenance.
fn print_header(
    cfg: &Cfg,
    info: &cpu::CpuInfo,
    src: &Src,
    st: &SelfTest,
    timer_ns: f64,
    sched_note: &str,
) {
    use std::io::Write;

    let host = std::env::var("COMPUTERNAME").unwrap_or_else(|_| "unknown".into());
    let ws_mib = src.working_set_bytes() as f64 / (1024.0 * 1024.0);
    let g = |ok: bool| if ok { "PASS" } else { "**FAIL**" };

    println!("================================================================================");
    println!("M3 AEAD PROVIDER BENCHMARK — ExpressLane");
    println!("================================================================================");
    println!("build     : {}", env!("M3_RUSTC"));
    println!(
        "            target={} profile={} opt-level={} debug_assertions={}",
        env!("M3_TARGET"),
        env!("M3_PROFILE"),
        env!("M3_OPT_LEVEL"),
        cfg!(debug_assertions)
    );
    // Keyed off the real profile directory, not cargo's PROFILE env var — which
    // reports "release" for every profile inheriting release, including
    // [profile.lto].
    match env!("M3_PROFILE") {
        "release" => println!(
            "            lto=off codegen-units=16 (cargo release defaults = shipping profile)"
        ),
        p => {
            println!("            !! profile '{p}' is NOT the shipping release profile.");
            println!("            !! [profile.lto] is lto=fat codegen-units=1; these numbers are");
            println!("            !! NOT directly subtractable from M1's 7.66. Secondary run only.");
        }
    }
    println!("host      : {host}");
    println!("cpu       : {}", info.brand);
    println!("            vendor={} hypervisor={}", info.vendor, info.hypervisor);
    println!("features  : {}", info.feature_line());
    println!("ring path : {}", info.ring_aes_path());
    println!(
        "caches    : L1d {}  L2 {}  L3 {}",
        info.l1d_kib.map(|k| format!("{k} KiB")).unwrap_or("?".into()),
        info.l2_kib.map(|k| format!("{k} KiB")).unwrap_or("?".into()),
        info.l3_kib.map(|k| format!("{k} KiB")).unwrap_or("?".into()),
    );
    println!(
        "workload  : payload={} B (PLAINTEXT denominator, matches M1's el_rx_bytes)",
        src.len
    );
    println!(
        "            aad=18 B (V2) nonce=12 B tag=16 B detached key=256 bit  seed={SEED:#018x}"
    );
    println!("            pool_hash={:#018x}", src.pool_hash);
    println!(
        "layout    : {} slots x {} B stride; cold working set {:.1} MiB (src+dst)",
        src.slots, src.stride, ws_mib
    );
    println!(
        "schedule  : sample = 1 pass = {} packets; rounds={}, 2 warm-up samples/arm/round",
        src.slots, cfg.rounds
    );
    println!("timer     : QueryThreadCycleTime {timer_ns:.1} ns/call, 2 calls per sample");
    println!("priority  : {sched_note}");
    println!();
    println!("=== SELF-TEST (before any timing; repeated as G3/G3b below) ===");
    println!("G3  ring and aes-gcm produce identical ciphertext+tag {}", g(st.cross_provider_ct));
    println!(
        "G3b round-trip vs known plaintext  rc={} ring={} chacha={} session={}",
        g(st.rc_roundtrip), g(st.ring_roundtrip), g(st.cc_roundtrip), g(st.session_roundtrip)
    );
    println!();
    let _ = std::io::stdout().flush();
}

#[allow(clippy::too_many_arguments)]
fn print_report(
    cfg: &Cfg,
    info: &cpu::CpuInfo,
    src: &Src,
    res: &[Res],
    sweep: &[(usize, f64, f64, f64, f64)],
    st: &SelfTest,
    timer_ns: f64,
    run_wall: f64,
    sys_busy_cores: f64,
    cpus_seen: &[u32],
) {
    let ws_mib = src.working_set_bytes() as f64 / (1024.0 * 1024.0);
    let qfreq = win::qpc_freq() as f64;

    println!(
        "run       : wall {run_wall:.1} s; observed on logical CPU(s) {cpus_seen:?}"
    );
    println!();

    // ---- measured -------------------------------------------------------
    println!("=== MEASURED (median over all samples; cycles per PLAINTEXT byte) ===");
    println!(
        "{:<22} {:<5} {:>8} {:>9} {:>8} {:>8} {:>8} {:>8} {:>8} {:>5}  state",
        "arm", "resid", "c/B", "c/pkt", "p10", "p90", "spread", "effGHz", "cpuMs", "N"
    );
    for r in res {
        let s = sorted(&r.cpb);
        let m = pct(&s, 0.5);
        let spread = r.spread();
        let mut state = if spread <= 0.05 { "stable" } else { "UNSTABLE" }.to_string();
        // Only claim preemption when the CPU-time denominator is above the tick
        // floor. Below it the ratio measures GetThreadTimes' quantization and
        // flags arms that were never descheduled.
        if r.preempt(qfreq).is_some_and(|p| p > 0.02) {
            state.push_str(" PREEMPTED");
        }
        if r.total_ops != r.expected_ops {
            state.push_str(" OPS-MISMATCH");
        }
        // `null` writes nothing, so its accumulator is a function of whatever
        // the previously executed arm left in `dst` — and the job order is
        // permuted every round. Drift there is the harness working as designed,
        // not an elided arm. See the G1c comment below.
        if !r.acc_stable && r.family != Family::Null {
            state.push_str(" CHECKSUM-DRIFT");
        }
        println!(
            "{:<22} {:<5} {:>8.4} {:>9.0} {:>8.4} {:>8.4} {:>7.1}% {:>8} {:>8.0} {:>5}  {}",
            r.name,
            if r.hot { "hot" } else { "cold" },
            m,
            m * r.payload_len as f64,
            pct(&s, 0.1),
            pct(&s, 0.9),
            spread * 100.0,
            r.eff_ghz().map(|g| format!("{g:.3}")).unwrap_or_else(|| "-".into()),
            r.cpu_ms(),
            r.cpb.len(),
            state
        );
    }
    println!("  effGHz is '-' where the arm accumulated under 500 ms of CPU: GetThreadTimes");
    println!("  moves in ~15.6 ms ticks, so below that the quotient measures quantization.");
    println!("  * ChaCha20-Poly1305 is a different algorithm and a different wire format —");
    println!("    a reference point for BoringTun's primitive family, not an ExpressLane option.");
    println!();

    // ---- derived --------------------------------------------------------
    let copy_hot = med(res, "copy_payload", true);
    let copy_cold = med(res, "copy_payload", false);
    let aead = |name: &str, hot: bool| med(res, name, hot) - if hot { copy_hot } else { copy_cold };

    let rc_hot = aead("rc_aesgcm256_dec", true);
    let rc_cold = aead("rc_aesgcm256_dec", false);
    let ring_hot = aead("ring_aesgcm256_dec", true);
    let ring_cold = aead("ring_aesgcm256_dec", false);
    let cc_hot = aead("rc_chacha_dec *", true);
    let cc_cold = aead("rc_chacha_dec *", false);
    let sess_overhead = med(res, "session_decrypt", false) - med(res, "rc_aesgcm256_dec", false);

    println!("=== DERIVED (never measured directly; each = arm − its own copy calibration) ===");
    println!("{:<34} {:>10} {:>10}", "line item (cycles/byte)", "hot", "cold");
    println!("{:<34} {:>10.4} {:>10.4}", "aead only  rc_aesgcm256 (decrypt)", rc_hot, rc_cold);
    println!("{:<34} {:>10.4} {:>10.4}", "aead only  ring_aesgcm256 (decrypt)", ring_hot, ring_cold);
    println!("{:<34} {:>10.4} {:>10.4}", "aead only  rc_chacha * (decrypt)", cc_hot, cc_cold);
    println!("{:<34} {:>10.4} {:>10.4}", "payload copy alone", copy_hot, copy_cold);
    println!(
        "{:<34} {:>10} {:>10.4}",
        "session overhead [lump]", "n/a", sess_overhead
    );
    println!("  session overhead lumps header parse + rx mutex + would_reject + bounds checks");
    println!("  + replay commit (128-word shift_left) + AAD build. Splitting it further would");
    println!("  require modifying lightway-expresslane, which is out of M3's scope.");
    // Both forms, deliberately. The derived ratio (rc − c)/(ring − c) is
    // strictly increasing in the subtracted calibration c, with slope
    // (rc − ring)/(ring − c)^2 — and `ring − c` is small, so a modest error in
    // the copy calibration moves the headline ratio by more than the width of
    // the 3.4-3.6x band this run exists to test. The raw ratio has no such
    // sensitivity and is what should carry the comparison against the off-rig
    // claim; the derived one answers "what does the cipher alone cost".
    println!(
        "  ring speedup vs incumbent: {:.2}x hot, {:.2}x cold   (derived, copy subtracted)",
        rc_hot / ring_hot,
        rc_cold / ring_cold
    );
    println!(
        "                             {:.2}x hot, {:.2}x cold   (raw, exactly as measured)",
        med(res, "rc_aesgcm256_dec", true) / med(res, "ring_aesgcm256_dec", true),
        med(res, "rc_aesgcm256_dec", false) / med(res, "ring_aesgcm256_dec", false)
    );
    println!();

    // ---- sweep ----------------------------------------------------------
    if !sweep.is_empty() {
        println!("=== PAYLOAD SWEEP (cold, decrypt; separates fixed per-packet from per-byte) ===");
        println!(
            "{:>7} {:>10} {:>10} {:>10} {:>10}",
            "bytes", "rc c/B", "rc c/pkt", "ring c/B", "ring c/pkt"
        );
        for &(len, rcb, rcp, rgb, rgp) in sweep {
            println!("{len:>7} {rcb:>10.4} {rcp:>10.0} {rgb:>10.4} {rgp:>10.0}");
        }
        if sweep.len() >= 2 {
            let (l0, _, p0, _, q0) = sweep[0];
            let (l1, _, p1, _, q1) = sweep[sweep.len() - 1];
            let db = (l1 - l0) as f64;
            println!(
                "  marginal per-byte slope {}..{} B:  rc {:.4} c/B   ring {:.4} c/B",
                l0,
                l1,
                (p1 - p0) / db,
                (q1 - q0) / db
            );
            println!(
                "  fixed per-packet cost (intercept):  rc {:.0} cyc   ring {:.0} cyc",
                p0 - (p1 - p0) / db * l0 as f64,
                q0 - (q1 - q0) / db * l0 as f64
            );
        }
        println!();
    }

    // ---- projection -----------------------------------------------------
    let target_ceiling = M1_GHZ * 8.0 / WIREGUARD_GBPS;
    let target_measured = M1_CPB * M1_GOODPUT_GBPS / WIREGUARD_GBPS;

    println!("=== PROJECTION ONTO M1 (imported constants: 7.66 c/B, 4.02 GHz, 1350 B mean pkt) ===");
    if !cfg.m1_rig {
        println!("  !! NOT MARKED AS THE M1 RIG (--m1-rig not passed). If this CPU is not the");
        println!("  !! one M1 measured, substituting these numbers into 7.66 is arithmetic,");
        println!("  !! not evidence. CPU here: {}", info.brand);
    }
    println!("  formulas: Gbps = 8 x 4.02 / (c/B)");
    println!("            e2e_after_swap = 7.66 − aead(rc_aesgcm256) + aead(candidate)");
    println!("  hot..cold is the bracket on in-situ cost, not a proof of it. Each end is one");
    println!("  self-consistent substitution — hot minus hot, cold minus cold — never mixed.");
    println!();
    println!(
        "{:<24} {:>16} {:>16} {:>16}",
        "candidate", "share of 7.66", "e2e c/B after", "e2e Gbps after"
    );
    // Each end of the bracket must be a SINGLE self-consistent substitution:
    // subtract the incumbent's hot cost and add the candidate's hot cost, or
    // both cold. Pairing the incumbent's cold with the candidate's hot (as an
    // unconditional min/max fold does) brackets two incompatible memory
    // regimes, not the model — and its optimistic end can clear the WireGuard
    // parity line when neither consistent pairing does.
    let row = |name: &str, c_hot: f64, c_cold: f64| {
        let e_hot = M1_CPB - rc_hot + c_hot;
        let e_cold = M1_CPB - rc_cold + c_cold;
        let (e_lo, e_hi) = (e_hot.min(e_cold), e_hot.max(e_cold));
        println!(
            "{:<24} {:>7.1}%..{:<7.1}% {:>7.2}..{:<7.2} {:>7.2}..{:<7.2}",
            name,
            c_hot.min(c_cold) / M1_CPB * 100.0,
            c_hot.max(c_cold) / M1_CPB * 100.0,
            e_lo,
            e_hi,
            gbps(e_hi),
            gbps(e_lo)
        );
    };
    println!(
        "{:<24} {:>7.1}%..{:<7.1}% {:>7.2}..{:<7.2} {:>7.2}..{:<7.2}",
        "rc_aesgcm256 (current)",
        rc_hot / M1_CPB * 100.0,
        rc_cold / M1_CPB * 100.0,
        M1_CPB,
        M1_CPB,
        gbps(M1_CPB),
        gbps(M1_CPB)
    );
    row("ring_aesgcm256", ring_hot, ring_cold);
    row("rc_chacha *", cc_hot, cc_cold);
    println!(
        "{:<24} {:>16} {:>7.2}..{:<7.2} {:>7.2}..{:<7.2}",
        "cipher cost = ZERO",
        "-",
        (M1_CPB - rc_cold).min(M1_CPB - rc_hot),
        (M1_CPB - rc_cold).max(M1_CPB - rc_hot),
        gbps((M1_CPB - rc_cold).max(M1_CPB - rc_hot)),
        gbps((M1_CPB - rc_cold).min(M1_CPB - rc_hot))
    );
    println!();
    println!(
        "  to match WireGuard's {WIREGUARD_GBPS:.2} Gbps the budget must reach {target_ceiling:.2} c/B"
    );
    println!(
        "  (single-core ceiling basis) or {target_measured:.2} c/B (measured-goodput basis,"
    );
    println!("  scaling M1's observed {M1_GOODPUT_GBPS:.1} Gbps rather than its computed ceiling).");
    println!();

    // ---- validity -------------------------------------------------------
    let hw_aes = info.aes && info.pclmulqdq;
    let worst_aesgcm = res
        .iter()
        .filter(|r| r.is_aesgcm)
        .map(|r| r.median())
        .fold(0.0f64, f64::max);
    // Only arms whose CPU-time denominator cleared the tick floor. An arm that
    // could not be measured is EXCLUDED, not scored as 0.0 — scoring it zero
    // and then filtering `> 0.1` hides the exclusion from the operator.
    let ghz: Vec<f64> = res.iter().filter_map(|r| r.eff_ghz()).collect();
    let ghz_lo = ghz.iter().cloned().fold(f64::INFINITY, f64::min);
    let ghz_hi = ghz.iter().cloned().fold(0.0f64, f64::max);
    let ghz_med = pct(&sorted(&ghz), 0.5);
    let ghz_spread = if ghz_lo.is_finite() && ghz_lo > 0.0 {
        (ghz_hi - ghz_lo) / ghz_lo
    } else {
        1.0
    };
    let all_ok = res.iter().all(|r| r.total_ops == r.expected_ops);
    // `null` is excluded on purpose: it performs no store into `dst`, so its
    // accumulator folds whatever the previously executed arm left there, and
    // the job order is permuted every round. Its drift is guaranteed at
    // `--rounds >= 2` on a perfectly sound run, and G1c is the gate that would
    // otherwise be training the operator to ignore a real elided arm. Folding
    // `src.wire` into `arm_null` instead would add a load per packet to the arm
    // whose entire purpose is to be the floor.
    let all_acc = res
        .iter()
        .filter(|r| r.family != Family::Null)
        .all(|r| r.acc_stable);

    // Every decrypt arm must have folded the same plaintext bytes; every AES
    // encrypt arm the same ciphertext and tag.
    let family_ok = |fam: Family| -> bool {
        for hot in [true, false] {
            let mut seen: Option<u64> = None;
            for r in res.iter().filter(|r| r.family == fam && r.hot == hot) {
                match seen {
                    None => seen = Some(r.acc),
                    Some(v) if v != r.acc => return false,
                    _ => {}
                }
            }
        }
        true
    };
    let dec_identical = family_ok(Family::Dec);
    let enc_identical = family_ok(Family::Enc);

    // Timer overhead, charged the way every other number here is charged: in
    // cycles per plaintext byte. The two QueryThreadCycleTime calls bracket a
    // whole *sample*, i.e. one full pass over `src.slots` packets, so their cost
    // is amortised over `slots * len` bytes and is tiny per byte.
    //
    // Two points matter for what this gate compares against:
    //
    //  - The overhead is a CONSTANT additive offset on every arm (always
    //    exactly two calls, always around one whole pass). It therefore cancels
    //    exactly in every derived figure, all of which are `arm − copy_payload`.
    //    So it cannot bias the "aead only" lines at all.
    //  - What it can bias is an arm's ABSOLUTE value. So the base is the
    //    smallest arm reported as a headline absolute cost — the cipher arms.
    //    `null` and `copy_payload` are excluded: they are the floor and
    //    calibration probes, deliberately near zero, and gating on them made
    //    this unsatisfiable on any rig at any sample count.
    let bytes_per_sample = (src.slots * src.len) as f64;
    let timer_cpb = 2.0 * timer_ns * M1_GHZ / bytes_per_sample.max(1.0);
    let smallest_cipher_arm = res
        .iter()
        .filter(|r| r.name != "null" && r.name != "copy_payload")
        .map(|r| r.median())
        .filter(|v| v.is_finite() && *v > 0.0)
        .fold(f64::INFINITY, f64::min);
    let timer_share = timer_cpb / smallest_cipher_arm.max(f64::MIN_POSITIVE);

    let linear = if sweep.len() >= 2 {
        sweep.windows(2).all(|w| w[1].2 > w[0].2) && sweep.windows(2).all(|w| w[1].4 > w[0].4)
    } else {
        true
    };

    // Qualified with residency, or hot and cold appear as indistinguishable
    // duplicates and the operator cannot tell which variant to re-run.
    let unstable: Vec<String> = res
        .iter()
        .filter(|r| r.spread() > 0.05)
        .map(|r| format!("{}/{}", r.name, if r.hot { "hot" } else { "cold" }))
        .collect();

    let g = |ok: bool| if ok { "PASS" } else { "**FAIL**" };
    println!("=== VALIDITY ===");
    println!("G1  checksum identical across decrypt arms            {}", g(dec_identical));
    println!("G1b checksum identical across AES encrypt arms        {}", g(enc_identical));
    println!(
        "G1c checksum stable sample-to-sample within each arm  {}\n\
         \x20   (`null` exempt: it writes nothing, so it folds its predecessor's output)",
        g(all_acc)
    );
    println!("G2  every operation succeeded (no auth-failure path)  {}", g(all_ok));
    println!("G3  ring and aes-gcm produce identical ciphertext+tag {}", g(st.cross_provider_ct));
    println!(
        "G3b round-trip vs known plaintext  rc={} ring={} chacha={} session={}",
        g(st.rc_roundtrip), g(st.ring_roundtrip), g(st.cc_roundtrip), g(st.session_roundtrip)
    );
    println!("G4  release build (debug_assertions off)              {}", g(!cfg!(debug_assertions)));
    println!("G5  hardware AES-NI + PCLMULQDQ detected              {}", g(hw_aes));
    println!(
        "G5b no Layer A AES-GCM arm above 10 c/B (worst {worst_aesgcm:.2})     {}",
        g(worst_aesgcm < 10.0)
    );
    println!(
        "G6  cycles/packet rises with payload length           {}",
        if sweep.is_empty() { "SKIPPED" } else { g(linear) }
    );
    println!(
        "G7  timer overhead <= 1% of smallest cipher arm ({:.4} c/B = {:.3}%)  {}\n\
         \x20   (constant additive offset; cancels exactly in every derived arm-minus-copy line)",
        timer_cpb,
        timer_share * 100.0,
        g(timer_share <= 0.01)
    );
    println!(
        "G9  system-wide non-idle <= 1.5 cores ({sys_busy_cores:.2})          {}",
        g(sys_busy_cores <= 1.5)
    );
    if ghz.is_empty() {
        println!("G10 effective GHz spread across arms <= 3%            SKIPPED");
        println!("G10b effective GHz vs M1's {M1_GHZ:.2}                       SKIPPED");
        println!("    (no arm accumulated 500 ms of CPU — raise --rounds to measure frequency)");
    } else {
        println!(
            "G10 effective GHz spread across arms <= 3% ({:.1}%, {} of {} arms measurable)  {}",
            ghz_spread * 100.0,
            ghz.len(),
            res.len(),
            g(ghz_spread <= 0.03)
        );
        // Gated on the MEDIAN, not the maximum: one arm's upward quantization
        // noise must not be able to satisfy the check M1 comparability rests on.
        println!(
            "G10b effective GHz median {ghz_med:.2} (range {ghz_lo:.2}..{ghz_hi:.2}) vs M1's \
             {M1_GHZ:.2}  {}",
            g(ghz_med > M1_GHZ * 0.85)
        );
    }
    println!(
        "G11 per-arm relative spread <= 5%                     {}",
        if unstable.is_empty() { "PASS".to_string() } else { format!("**FAIL** {unstable:?}") }
    );
    println!(
        "G14 cold working set {:.1} MiB vs L2 {} / L3 {}",
        ws_mib,
        info.l2_kib.map(|k| format!("{k} KiB")).unwrap_or("?".into()),
        info.l3_kib.map(|k| format!("{k} KiB")).unwrap_or("?".into())
    );
    if let Some(l3) = info.l3_kib
        && (src.working_set_bytes() as u32) < l3 * 1024
    {
        println!("    NOTE: working set still fits in L3 — the cold arm is a LOWER BOUND on");
        println!("    true production cold cost. Re-run with --pool-mib 64 to bracket it.");
    }
    println!("G12 3-run stability: run this exe 3x and compare the run medians by hand;");
    println!("    M1's bar was 2.3% agreement across its three good runs.");
    println!();

    // ---- verdict --------------------------------------------------------
    println!("=== VERDICT ===");
    let claim = if (3.1..=3.7).contains(&rc_cold) {
        "CONFIRMED — dead centre of the off-rig 3.1-3.7 c/B estimate"
    } else if rc_cold >= 3.0 {
        "CONFIRMED in magnitude (>= 3.0 c/B), outside the exact off-rig range"
    } else if rc_cold >= 1.5 {
        "OVERSTATED — the cipher is real but smaller than the plan assumed"
    } else {
        "REFUTED — the cipher is NOT where the 7.66 lives"
    };
    println!(
        "(a) measured cipher share of M1's 7.66 c/B: {:.1}%..{:.1}% ({:.3}..{:.3} c/B).",
        rc_hot / M1_CPB * 100.0,
        rc_cold / M1_CPB * 100.0,
        rc_hot,
        rc_cold
    );
    println!("(b) off-rig 3.1-3.7 c/B claim: {claim}.");
    println!(
        "(c) ring speedup vs the 3.4-3.6x claimed: {:.2}x cold raw ({:.2}x hot raw);",
        med(res, "rc_aesgcm256_dec", false) / med(res, "ring_aesgcm256_dec", false),
        med(res, "rc_aesgcm256_dec", true) / med(res, "ring_aesgcm256_dec", true)
    );
    println!(
        "    {:.2}x cold ({:.2}x hot) after subtracting the copy calibration. Compare the",
        rc_cold / ring_cold,
        rc_hot / ring_hot
    );
    println!("    RAW figures against the off-rig claim — see LIMITS 8.");
    let e2e = M1_CPB - rc_cold + ring_cold;
    println!(
        "(d) e2e after swapping to ring: {:.2} c/B = {:.2} Gbps, vs the {:.2} Gbps target.",
        e2e,
        gbps(e2e),
        WIREGUARD_GBPS
    );
    let free = M1_CPB - rc_cold;
    println!(
        "(e) HARD BOUND — if the cipher cost were ZERO: {:.2} c/B = {:.2} Gbps.",
        free,
        gbps(free)
    );
    if gbps(free) < WIREGUARD_GBPS {
        println!("    That is BELOW {WIREGUARD_GBPS:.2} Gbps: no AEAD change, however perfect,");
        println!("    reaches WireGuard parity on its own. The plan must be re-ranked and the");
        println!("    remaining budget (copy, replay window, mutex, classification) attacked.");
    } else {
        println!("    That is above {WIREGUARD_GBPS:.2} Gbps, so a cipher change alone can in");
        println!("    principle close the gap — subject to the in-situ caveat below.");
    }
    println!();
    println!("Next action, per the decision table:");
    if rc_cold >= 3.0 {
        println!("  Provider swap is the top-ranked change. Proceed to an in-situ A/B on the rig.");
    } else if rc_cold >= 1.5 {
        println!("  Re-rank: the swap yields only part of the needed 2.8 c/B. Keep the replay");
        println!("  window, the payload copy and the checksum work in scope.");
    } else {
        println!("  STOP the provider work. Do M4 (a flat profile) before implementing anything —");
        println!("  the 7.66 is dominated by something nobody has looked at yet.");
    }
    println!();

    println!("=== LIMITS (these belong in any write-up of this run) ===");
    println!("1. M3 measures the primitive in isolation. The substitution model assumes in-situ");
    println!("   cost equals isolated cost; the hot..cold bracket estimates that error, it does");
    println!("   not prove it. Only an in-situ A/B (same rig, LIGHTWAY_PERF_PROBE, one provider");
    println!("   swapped) confirms the projection.");
    println!("2. 7.66 c/B and 4.02 GHz are imported M1 constants, valid for that rig, that");
    println!("   traffic mix and a 1350 B mean packet only.");
    println!("3. session overhead is a lump and cannot be split without editing the shipping");
    println!("   crate.");
    println!("4. The ChaCha arm is a different algorithm AND a different wire overhead; it is");
    println!("   BoringTun context, not an ExpressLane option. BoringTun also ships its own");
    println!("   ChaCha rather than this crate.");
    println!("5. Layer B is the only arm compiled exactly as shipped (real rlib). Layer A arms");
    println!("   inline the AEAD into this binary's own codegen unit — same optimizer settings,");
    println!("   but not the same compilation.");
    println!("6. prev_peer is None throughout, i.e. steady state. During key rotation the");
    println!("   production decrypt can pay the AEAD twice.");
    println!("7. ring's Nonce is consumed per call and must be built inside the loop — a few");
    println!("   cycles charged to ring and to no other arm.");
    println!("8. The DERIVED ring speedup assumes the payload copy's MARGINAL cost inside an");
    println!("   AEAD arm equals its standalone cost in `copy_payload`. No arm here tests that:");
    println!("   standalone, the copy's cache misses are exposed; inside an AEAD arm the");
    println!("   out-of-order window overlaps some of them with the cipher work. If the");
    println!("   subtraction over-charges, it inflates the derived ratio — the derived form is");
    println!("   (rc − c)/(ring − c), increasing in c, and ring − c is small. Both forms are");
    println!("   printed; quote the raw one against the 3.4-3.6x claim.");
    println!("9. Effective GHz comes from GetThreadTimes, whose ~15.6 ms tick is coarse against");
    println!("   the per-arm CPU budget. It is bracketed once per arm-round block and suppressed");
    println!("   below 500 ms accumulated, but residual quantization of a few percent remains.");
}
