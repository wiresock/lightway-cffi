//! Sliding-window replay protection for received ExpressLane packets.

/// Tracks received packet counters to detect and prevent replay attacks
/// while tolerating out-of-order UDP delivery.
///
/// Uses an 8192-bit bitmap (128 × u64) to tolerate significant packet
/// reordering under high-throughput conditions.
///
/// The bitmap is a **ring indexed by the absolute wire counter**, not by a
/// packet's age relative to `max_counter`. An age-indexed bitmap has to be
/// shifted every time the window advances — all 128 words rewritten for the
/// in-order packet that makes up ~99% of traffic — whereas under absolute
/// indexing advancing the window moves no bits at all; it only makes some
/// slots stale, and only the slots of counters that were actually skipped
/// need clearing. Advance is therefore `O(min(jump, NUM_BLOCKS))` instead of
/// an unconditional `O(NUM_BLOCKS)`, and the common case is O(1).
///
/// RING ALIASING INVARIANT: a ring slot is shared by every counter congruent
/// modulo `WINDOW_SIZE`, and is authoritative for exactly one of them — the
/// unique such counter inside `[max_counter - WINDOW_SIZE + 1, max_counter]`.
/// Therefore **(a)** every read of a slot must be guarded by
/// `age < WINDOW_SIZE` (and by the `wire_counter > max_counter` early-out on
/// the high side), and **(b)** every advance must clear the slots of all
/// counters in `(old_max, new_max)` *before* `max_counter` is updated. Both
/// halves are load-bearing: a stale slot that is read without the range check
/// reports a counter as "seen" or "unseen" on the strength of a packet
/// `WINDOW_SIZE` counters ago.
#[derive(Debug, Clone)]
pub(crate) struct ReplayWindow {
    max_counter: u64,
    bitmap: [u64; Self::NUM_BLOCKS],
    packets_received: u64,
    initialized: bool,
}

impl Default for ReplayWindow {
    fn default() -> Self {
        Self {
            max_counter: 0,
            bitmap: [0; Self::NUM_BLOCKS],
            packets_received: 0,
            initialized: false,
        }
    }
}

// The ring index decomposes into two masks — and stays continuous across the
// u64 counter wrap, since 2^64 is an exact multiple of WINDOW_SIZE — only
// because NUM_BLOCKS is a power of two.
const _: () = assert!(ReplayWindow::NUM_BLOCKS.is_power_of_two());

/// Word index within the ring for `counter`, i.e. `(counter mod WINDOW_SIZE)`
/// divided by the word width. Always `< NUM_BLOCKS` by construction, which is
/// why the slot accessors need no bounds branch.
#[inline]
fn ring_index(counter: u64) -> usize {
    ((counter / ReplayWindow::BLOCK_BITS) & ReplayWindow::RING_MASK) as usize
}

/// The single bit within `ring_index(counter)`'s word that belongs to
/// `counter`.
#[inline]
fn bit_of(counter: u64) -> u64 {
    1u64 << (counter & ReplayWindow::BIT_MASK)
}

/// Bits `lo..=hi` set, all others clear. Requires `lo <= hi <= 63`.
#[inline]
fn mask_between(lo: u32, hi: u32) -> u64 {
    debug_assert!(lo <= hi && hi < 64);
    (u64::MAX >> (63 - (hi - lo))) << lo
}

impl ReplayWindow {
    const NUM_BLOCKS: usize = 128;
    const BLOCK_BITS: u64 = 64;
    const WINDOW_SIZE: u64 = (Self::NUM_BLOCKS as u64) * Self::BLOCK_BITS;
    const RING_MASK: u64 = Self::NUM_BLOCKS as u64 - 1;
    const BIT_MASK: u64 = Self::BLOCK_BITS - 1;

    /// Non-mutating pre-check, to short-circuit obvious garbage before
    /// paying the AEAD cost. Returns true iff the packet should be
    /// rejected. Callers MUST NOT treat a `false` result as final
    /// acceptance — [`Self::commit`] must still run after AEAD
    /// verification succeeds.
    pub(crate) fn would_reject(&self, wire_counter: u64) -> bool {
        if !self.initialized {
            return false;
        }
        if wire_counter > self.max_counter {
            return false;
        }
        let age = self.max_counter - wire_counter;
        // Range check strictly before the slot read — half (a) of the RING
        // ALIASING INVARIANT. Reordering these for "speed" makes an ancient
        // counter whose slot happens to be clear look acceptable. See `commit`
        // for which ages this actually decides and what covers it.
        if age >= Self::WINDOW_SIZE {
            return true;
        }
        self.bitmap[ring_index(wire_counter)] & bit_of(wire_counter) != 0
    }

    /// Commit a successfully-deprotected wire counter into the window.
    /// MUST only be called after AEAD verification succeeds. Returns true
    /// if accepted; false if the counter is a replay or too old (state
    /// unchanged in that case).
    pub(crate) fn commit(&mut self, wire_counter: u64) -> bool {
        if !self.initialized {
            self.initialized = true;
            self.max_counter = wire_counter;
            // Absolute indexing means the first packet's slot is generally not
            // slot 0. Clear explicitly rather than leaning on `Default`'s
            // zeros, so the invariant is checkable from this function alone.
            self.bitmap = [0; Self::NUM_BLOCKS];
            self.bitmap[ring_index(wire_counter)] = bit_of(wire_counter);
            self.packets_received += 1;
            return true;
        }

        if wire_counter > self.max_counter {
            let diff = wire_counter - self.max_counter;
            if diff >= Self::WINDOW_SIZE {
                // Nothing previously recorded is still in window.
                self.bitmap = [0; Self::NUM_BLOCKS];
            } else if diff > 1 {
                // Half (b) of the RING ALIASING INVARIANT: counters strictly
                // between the old and new maximum were never seen, but their
                // slots may still hold bits set WINDOW_SIZE counters ago.
                // `wire_counter`'s own slot is excluded because it is set
                // unconditionally below.
                self.clear_range(self.max_counter + 1, wire_counter - 1);
            }
            // diff == 1 clears nothing at all — the ~99% path, and the whole
            // point of indexing by absolute counter.
            self.bitmap[ring_index(wire_counter)] |= bit_of(wire_counter);
            self.max_counter = wire_counter;
            self.packets_received += 1;
            return true;
        }

        let age = self.max_counter - wire_counter;
        // Range check before the slot read — see `would_reject`.
        //
        // WHERE THIS IS ACTUALLY LOAD-BEARING (re-derive if the ring geometry
        // ever changes): only for age STRICTLY GREATER than WINDOW_SIZE. At age
        // exactly WINDOW_SIZE the counter aliases onto `max_counter`'s own word
        // *and* bit — because WINDOW_SIZE == NUM_BLOCKS * BLOCK_BITS — and
        // `max_counter`'s bit is invariantly set (it is set on every accepting
        // path, and `clear_range` only ever spans `(old_max, new_max)`, which
        // excludes both endpoints). So the bit test alone already rejects that
        // case, and `>=` vs `>` is unobservable there.
        //
        // The consequence is that this boundary has exactly ONE covering test:
        // `rejects_counter_far_below_window_whose_slot_is_clear`. Change
        // NUM_BLOCKS, BLOCK_BITS, or the RING_MASK derivation and the alias
        // above may no longer hold; weaken or reorder this check without that
        // test and an ancient counter whose slot happens to be clear is
        // accepted as fresh.
        if age >= Self::WINDOW_SIZE {
            return false;
        }
        let (word, bit) = (ring_index(wire_counter), bit_of(wire_counter));
        if self.bitmap[word] & bit != 0 {
            return false;
        }
        self.bitmap[word] |= bit;
        self.packets_received += 1;
        true
    }

    /// Clear the ring bits for every counter in `[lo, hi]` (inclusive).
    ///
    /// INVARIANT: `lo <= hi` and `hi - lo < WINDOW_SIZE`. That bound is what
    /// holds `hi_word - lo_word <= NUM_BLOCKS`, so the whole-word loop spans at
    /// most `NUM_BLOCKS - 1` distinct slots and can never lap the ring far
    /// enough to erase a slot the masked end-writes are protecting.
    fn clear_range(&mut self, lo: u64, hi: u64) {
        debug_assert!(lo <= hi && hi - lo < Self::WINDOW_SIZE);

        let lo_word = lo / Self::BLOCK_BITS;
        let hi_word = hi / Self::BLOCK_BITS;
        let lo_bit = (lo & Self::BIT_MASK) as u32;
        let hi_bit = (hi & Self::BIT_MASK) as u32;

        if lo_word == hi_word {
            self.bitmap[ring_index(lo)] &= !mask_between(lo_bit, hi_bit);
            return;
        }

        self.bitmap[ring_index(lo)] &= !mask_between(lo_bit, 63);
        for word in (lo_word + 1)..hi_word {
            self.bitmap[(word & Self::RING_MASK) as usize] = 0;
        }
        // `hi_word - lo_word == NUM_BLOCKS` is reachable (a near-maximal jump
        // starting at bit 63), in which case this write and the masked write
        // above land on the same slot. Both are `&= !mask` over disjoint bit
        // ranges, so order is irrelevant and the bits between them — which
        // still belong to in-window counters — correctly survive.
        self.bitmap[ring_index(hi)] &= !mask_between(0, hi_bit);
    }

    /// Total number of packets successfully committed.
    pub(crate) fn packets_received(&self) -> u64 {
        self.packets_received
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Frozen copy of the pre-ring, age-indexed implementation. It exists
    /// solely as a differential oracle for the ring rewrite. Do not refactor
    /// it, do not "fix" it, do not let clippy tidy it — its entire value is
    /// that it is exactly what shipped.
    #[allow(dead_code)]
    mod reference {
        #[derive(Debug, Clone)]
        pub(super) struct ReferenceReplayWindow {
            pub(super) max_counter: u64,
            pub(super) bitmap: [u64; Self::NUM_BLOCKS],
            pub(super) packets_received: u64,
            pub(super) initialized: bool,
        }

        impl Default for ReferenceReplayWindow {
            fn default() -> Self {
                Self {
                    max_counter: 0,
                    bitmap: [0; Self::NUM_BLOCKS],
                    packets_received: 0,
                    initialized: false,
                }
            }
        }

        impl ReferenceReplayWindow {
            const NUM_BLOCKS: usize = 128;
            const WINDOW_SIZE: u64 = (Self::NUM_BLOCKS as u64) * 64;

            fn set_bit(&mut self, position: u64) {
                let block = (position / 64) as usize;
                let bit = position % 64;
                if block < Self::NUM_BLOCKS {
                    self.bitmap[block] |= 1u64 << bit;
                }
            }

            pub(super) fn test_bit(&self, position: u64) -> bool {
                let block = (position / 64) as usize;
                let bit = position % 64;
                if block < Self::NUM_BLOCKS {
                    (self.bitmap[block] & (1u64 << bit)) != 0
                } else {
                    false
                }
            }

            fn shift_left(&mut self, count: u64) {
                if count >= Self::WINDOW_SIZE {
                    self.bitmap = [0; Self::NUM_BLOCKS];
                    return;
                }

                let block_shift = (count / 64) as usize;
                let bit_shift = (count % 64) as u32;

                if bit_shift == 0 {
                    for i in (block_shift..Self::NUM_BLOCKS).rev() {
                        self.bitmap[i] = self.bitmap[i - block_shift];
                    }
                    for slot in self.bitmap.iter_mut().take(block_shift) {
                        *slot = 0;
                    }
                } else {
                    for i in (0..Self::NUM_BLOCKS).rev() {
                        let lower = if i >= block_shift {
                            self.bitmap[i - block_shift] << bit_shift
                        } else {
                            0
                        };
                        let upper = if i > block_shift {
                            self.bitmap[i - block_shift - 1] >> (64 - bit_shift)
                        } else {
                            0
                        };
                        self.bitmap[i] = lower | upper;
                    }
                }
            }

            pub(super) fn would_reject(&self, wire_counter: u64) -> bool {
                if !self.initialized {
                    return false;
                }
                if wire_counter > self.max_counter {
                    return false;
                }
                let age = self.max_counter - wire_counter;
                if age >= Self::WINDOW_SIZE {
                    return true;
                }
                self.test_bit(age)
            }

            pub(super) fn commit(&mut self, wire_counter: u64) -> bool {
                if !self.initialized {
                    self.initialized = true;
                    self.max_counter = wire_counter;
                    self.bitmap[0] = 1;
                    self.packets_received += 1;
                    return true;
                }

                if wire_counter > self.max_counter {
                    let diff = wire_counter - self.max_counter;
                    self.shift_left(diff);
                    self.bitmap[0] |= 1;
                    self.max_counter = wire_counter;
                    self.packets_received += 1;
                    return true;
                }

                let age = self.max_counter - wire_counter;
                if age < Self::WINDOW_SIZE {
                    if self.test_bit(age) {
                        return false;
                    }
                    self.set_bit(age);
                    self.packets_received += 1;
                    return true;
                }

                false
            }

            pub(super) fn packets_received(&self) -> u64 {
                self.packets_received
            }
        }
    }

    use reference::ReferenceReplayWindow;

    /// SplitMix64. Inline rather than a `rand` dev-dependency: the crate has
    /// no dev-dependencies today and one differential test does not justify
    /// changing that.
    struct SplitMix64(u64);

    impl SplitMix64 {
        fn next(&mut self) -> u64 {
            self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut z = self.0;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            z ^ (z >> 31)
        }
    }

    #[test]
    fn accepts_first_packet() {
        let mut window = ReplayWindow::default();
        assert!(window.commit(100));
        assert_eq!(window.packets_received(), 1);
    }

    #[test]
    fn detects_exact_replay() {
        let mut window = ReplayWindow::default();
        assert!(window.commit(100));
        assert!(!window.commit(100));
        assert_eq!(window.packets_received(), 1);
    }

    #[test]
    fn accepts_newer_packets() {
        let mut window = ReplayWindow::default();
        assert!(window.commit(100));
        assert!(window.commit(101));
        assert!(window.commit(102));
        assert_eq!(window.packets_received(), 3);
    }

    #[test]
    fn accepts_out_of_order_within_window() {
        let mut window = ReplayWindow::default();
        assert!(window.commit(100));
        assert!(window.commit(105));
        assert!(window.commit(103));
        assert!(window.commit(102));
        assert_eq!(window.packets_received(), 4);
    }

    #[test]
    fn rejects_replayed_out_of_order_packet() {
        let mut window = ReplayWindow::default();
        assert!(window.commit(100));
        assert!(window.commit(105));
        assert!(window.commit(103));
        assert!(!window.commit(103));
        assert_eq!(window.packets_received(), 3);
    }

    #[test]
    fn rejects_too_old_packets() {
        let mut window = ReplayWindow::default();
        assert!(window.commit(100));
        assert!(window.commit(10000)); // advance window past 8192
        // 10000 - 8192 = 1808, so 1808 is the oldest still-in-window counter.
        assert!(!window.commit(100));
        assert!(!window.commit(1808));
        assert!(window.commit(1809));
        assert_eq!(window.packets_received(), 3);
    }

    #[test]
    fn handles_large_jumps() {
        let mut window = ReplayWindow::default();
        assert!(window.commit(100));
        assert!(window.commit(10000));
        assert!(!window.commit(100));
        assert_eq!(window.packets_received(), 2);
    }

    #[test]
    fn full_scenario() {
        let mut window = ReplayWindow::default();
        for i in 1..=10 {
            assert!(window.commit(i), "failed to accept packet {i}");
        }
        assert!(window.commit(15));
        assert!(window.commit(13));
        assert!(window.commit(11));
        assert!(window.commit(12));
        assert!(window.commit(14));
        assert!(!window.commit(10));
        assert!(!window.commit(13));
        assert!(!window.commit(15));
        assert!(window.commit(16));
        assert!(window.commit(17));
        assert_eq!(window.packets_received(), 17);
    }

    #[test]
    fn would_reject_is_non_mutating() {
        let mut window = ReplayWindow::default();
        assert!(!window.would_reject(100));
        assert_eq!(window.packets_received(), 0);

        assert!(window.commit(100));
        assert!(window.would_reject(100));
        assert_eq!(window.packets_received(), 1);

        assert!(!window.would_reject(u64::MAX));
        assert_eq!(window.packets_received(), 1);
    }

    #[test]
    fn window_size_is_8192() {
        let mut window = ReplayWindow::default();
        assert!(window.commit(0));
        assert!(window.commit(8192));
        // 8192 - 0 = 8192 == WINDOW_SIZE, exactly out of window.
        assert!(!window.commit(0));
        assert!(window.commit(1));
    }

    // ---- Ring-specific coverage: the aliasing invariant and clear_range. ----

    #[test]
    fn advance_within_one_word_clears_only_skipped_counters() {
        // diff == 5 with lo and hi in the same absolute word: a single masked
        // write. Catches a mask that is off by one at either end.
        let mut window = ReplayWindow::default();
        assert!(window.commit(100));
        assert!(window.commit(105));
        assert!(!window.commit(100)); // seen, still in window
        for c in 101..=104 {
            assert!(window.commit(c), "skipped counter {c} must be acceptable");
        }
        assert!(!window.commit(105));
        assert_eq!(window.packets_received(), 6); // 100, 105, 101..104
    }

    #[test]
    fn advance_across_a_word_boundary_clears_only_skipped_counters() {
        // clear_range(61, 69) spans absolute words 0 and 1: two partial writes,
        // empty interior loop.
        let mut window = ReplayWindow::default();
        assert!(window.commit(60));
        assert!(window.commit(70));
        assert!(!window.commit(60));
        for c in 61..=69 {
            assert!(window.commit(c), "skipped counter {c} must be acceptable");
        }
        assert!(!window.commit(70));
        assert_eq!(window.packets_received(), 11);
    }

    #[test]
    fn advance_across_the_ring_wrap_clears_only_skipped_counters() {
        // clear_range(8181, 8199) crosses the end of the ring: low partial in
        // word 127, high partial back at word 0. Catches an interior loop that
        // forgets to mask, or a ring_index built on the wrong quantity.
        let mut window = ReplayWindow::default();
        assert!(window.commit(8180));
        assert!(window.commit(8200));
        assert!(!window.commit(8180)); // bit 52 of word 127 must survive
        assert!(window.commit(8181));
        assert!(window.commit(8190));
        assert!(window.commit(8199));
        assert!(!window.commit(8200));
    }

    #[test]
    fn maximal_partial_clear_preserves_oldest_in_window_bit() {
        // diff == WINDOW_SIZE - 1 starting at bit 63, so hi_word - lo_word is
        // exactly NUM_BLOCKS and the two masked end-writes land on the SAME
        // ring word. The tightest case clear_range has.
        let mut window = ReplayWindow::default();
        assert!(window.commit(62));
        assert!(window.commit(8253));

        assert!(!window.commit(62)); // age 8191: in window, seen, must survive
        assert!(window.commit(63)); // cleared by the mask, acceptable
        assert!(window.commit(8252)); // ditto at the other end
        // Age exactly WINDOW_SIZE is NOT an independent trap: because
        // WINDOW_SIZE == NUM_BLOCKS * BLOCK_BITS, counter 61 aliases onto
        // max_counter's own word AND bit, and that bit is invariantly set. Both
        // the range check and the bit test reject it. See the note on `commit`.
        assert!(!window.commit(61));
        assert!(!window.commit(8253));
        // 59 is the real trap: age 8194, and clear_range(63, 8252) wiped its
        // slot (word 0, bit 59 — shared with 8251) without anything setting it
        // again, so nothing but `age >= WINDOW_SIZE` stands between it and
        // acceptance.
        assert!(!window.commit(59));
        assert_eq!(window.packets_received(), 4);
    }

    #[test]
    fn rejects_counter_far_below_window_whose_slot_is_clear() {
        // After the wholesale wipe only slot 20000 mod 8192 is set, so counter
        // 3000's slot is clear and nothing but `age >= WINDOW_SIZE` rejects it.
        // Fails loudly if the range check is ever moved after the bit test.
        let mut window = ReplayWindow::default();
        assert!(window.commit(0));
        assert!(window.commit(20000));
        assert!(window.would_reject(3000));
        assert!(!window.commit(3000));
        assert_eq!(window.packets_received(), 2);
    }

    #[test]
    fn jump_of_exactly_window_size_invalidates_everything() {
        let mut window = ReplayWindow::default();
        assert!(window.commit(0));
        assert!(window.commit(1));
        assert!(window.commit(2));

        assert!(window.commit(8192)); // diff 8190: partial clear
        assert!(!window.commit(0)); // age 8192, out of window
        assert!(!window.commit(1)); // age 8191, in window and seen
        assert!(window.commit(3)); // in window, never seen

        assert!(window.commit(16384)); // diff 8192: wholesale wipe
        // 8193 and 16383 were recorded before the wipe and are still in window,
        // so their acceptance proves the wipe genuinely erased their bits.
        assert!(window.commit(8193));
        assert!(window.commit(16383));
        // 8192 was erased by the wipe, but it aliases exactly onto max_counter
        // (16384) — same word, same bit — which the wipe then re-set, so the bit
        // test rejects it too. Age exactly WINDOW_SIZE never isolates the range
        // check; see the note on `commit`.
        assert!(!window.commit(8192));
        // Likewise 8191 shares word 127 / bit 63 with 16383.
        assert!(!window.commit(8191));
        // 8190 is the isolating case: age 8194 and its slot (word 127, bit 62)
        // was wiped and never re-set, so only `age >= WINDOW_SIZE` rejects it.
        assert!(!window.commit(8190));
    }

    #[test]
    fn full_window_span_fills_then_replays() {
        // Every one of the 8192 slots must be independently addressable.
        let mut window = ReplayWindow::default();
        assert!(window.commit(0));
        for c in 1..=8191 {
            assert!(window.commit(c), "counter {c} must be acceptable");
        }
        assert_eq!(window.packets_received(), 8192);
        assert_eq!(window.max_counter, 8191);
        for c in 0..=8191 {
            assert!(!window.commit(c), "counter {c} must be a replay");
        }
        // 8192 shares word 0 / bit 0 with counter 0, so committing it leaves
        // that bit set and counter 0 is then rejected by BOTH the range check
        // and the bit test. With every slot in the window occupied there is no
        // age > WINDOW_SIZE counter left to isolate the range check here — that
        // is `rejects_counter_far_below_window_whose_slot_is_clear`'s job.
        assert!(window.commit(8192));
        assert!(!window.commit(0));
    }

    #[test]
    fn first_packet_with_a_large_counter_initializes_correctly() {
        // Guards the init path, which under absolute indexing must place the
        // bit at ring_index(counter) rather than slot 0.
        let base = u64::MAX / 2;
        let mut window = ReplayWindow::default();
        assert!(window.commit(base));
        assert!(!window.commit(base));
        assert!(window.commit(base - 1));
        assert!(window.commit(base + 1));
        assert!(!window.commit(base - 8192));
    }

    #[test]
    fn would_reject_does_not_mutate_any_state() {
        let mut window = ReplayWindow::default();
        assert!(window.commit(1000));
        assert!(window.commit(1005));
        assert!(window.commit(999));
        assert!(window.commit(9000));

        let before = window.clone();
        for c in [
            0,
            1,
            998,
            999,
            1000,
            8999,
            9000,
            9001,
            9000 - 8193,
            9000 - 8192,
            9000 - 8191,
            u64::MAX / 2,
            u64::MAX,
        ] {
            let _ = window.would_reject(c);
        }
        assert_eq!(window.bitmap, before.bitmap);
        assert_eq!(window.max_counter, before.max_counter);
        assert_eq!(window.packets_received, before.packets_received);
        assert_eq!(window.initialized, before.initialized);
    }

    #[test]
    fn window_stalls_after_u64_wraparound_matching_todays_behaviour() {
        // `reserve_counter` wraps (MAX, 0, 1), but the window compares counters
        // with plain `>` rather than serial-number arithmetic, so once
        // max_counter reaches u64::MAX every subsequent counter looks ancient
        // and the RX window stalls permanently.
        //
        // This is DELIBERATELY preserved. It is unreachable in practice (2^64
        // packets at ~370 kpps is ~1.6 million years, and key rotation
        // intervenes long before), upstream lightway-core has the same shape,
        // and fixing it changes accept/reject decisions, so it has to be agreed
        // with the server side rather than smuggled in with a perf rewrite.
        let mut window = ReplayWindow::default();
        assert!(window.commit(u64::MAX - 1));
        assert!(window.commit(u64::MAX));
        assert!(!window.commit(0));
        assert!(!window.commit(1));
        assert!(!window.commit(8191));
        assert!(window.would_reject(0));
    }

    // ---- Differential harness against the frozen pre-ring implementation. ----

    /// Compare the two implementations' bitmaps semantically — the layouts
    /// differ, so the arrays cannot be compared directly. Walks the whole
    /// window so a stale bit is caught at the step it appears, not thousands of
    /// packets later when it finally becomes observable.
    fn assert_bitmaps_agree(
        reference: &ReferenceReplayWindow,
        fresh: &ReplayWindow,
        context: &str,
    ) {
        for age in 0..ReplayWindow::WINDOW_SIZE {
            let Some(c) = fresh.max_counter.checked_sub(age) else {
                break;
            };
            assert_eq!(
                reference.test_bit(age),
                fresh.bitmap[ring_index(c)] & bit_of(c) != 0,
                "bitmap diverged: {context} age {age} counter {c}",
            );
        }
    }

    #[test]
    fn differential_matches_reference_over_mixed_traffic() {
        for seed in [1u64, 2, 3, 0xDEAD_BEEF, 0x5EED_5EED] {
            let mut prng = SplitMix64(seed);
            let mut reference = ReferenceReplayWindow::default();
            let mut fresh = ReplayWindow::default();
            let mut cursor: u64 = 1;
            let mut history: Vec<u64> = Vec::new();

            for step in 0..100_000u32 {
                let counter = match prng.next() % 100 {
                    0..=59 => {
                        cursor += 1;
                        cursor
                    }
                    60..=74 => cursor.saturating_sub(prng.next() % 64),
                    75..=84 => cursor.saturating_sub(prng.next() % 8192),
                    85..=89 if !history.is_empty() => {
                        history[(prng.next() as usize) % history.len()]
                    }
                    85..=89 => cursor,
                    90..=94 => {
                        cursor += 1 + prng.next() % 200;
                        cursor
                    }
                    // Deliberately straddles WINDOW_SIZE: the only generator
                    // that plays `hi_word - lo_word == NUM_BLOCKS` off against
                    // the wholesale wipe.
                    95..=97 => {
                        cursor += 8000 + prng.next() % 400;
                        cursor
                    }
                    _ => cursor.saturating_sub(8192 + prng.next() % 100_000),
                };

                let context = format!("seed {seed} step {step} counter {counter}");
                assert_eq!(
                    reference.would_reject(counter),
                    fresh.would_reject(counter),
                    "would_reject diverged: {context}",
                );
                // Commit unconditionally, not only when would_reject was false:
                // session.rs returns early on the pre-check, but this is
                // strictly stronger and covers commit's own "false on replay"
                // contract, which forged_packet_does_not_poison_replay_window
                // depends on.
                assert_eq!(
                    reference.commit(counter),
                    fresh.commit(counter),
                    "commit diverged: {context}",
                );
                assert_eq!(
                    reference.packets_received(),
                    fresh.packets_received(),
                    "packets_received diverged: {context}",
                );
                assert_eq!(
                    reference.max_counter, fresh.max_counter,
                    "max_counter diverged: {context}",
                );

                if step % 1000 == 0 {
                    assert_bitmaps_agree(&reference, &fresh, &context);
                }
                history.push(counter);
            }

            assert_bitmaps_agree(&reference, &fresh, &format!("seed {seed} final"));
        }
    }

    #[test]
    fn differential_matches_reference_across_u64_wraparound() {
        // Separate and deterministic: saturating_sub and `+=` above are
        // meaningless at the boundary. Proves the rewrite reproduces the stall
        // rather than accidentally repairing it — a silent repair would be a
        // behaviour change relative to the deployed client.
        let mut reference = ReferenceReplayWindow::default();
        let mut fresh = ReplayWindow::default();
        let mut cursor = u64::MAX - 20;

        for step in 0..60u32 {
            cursor = cursor.wrapping_add(1);
            let counter = if step % 5 == 4 {
                cursor.wrapping_sub(3)
            } else {
                cursor
            };

            let context = format!("step {step} counter {counter}");
            assert_eq!(
                reference.would_reject(counter),
                fresh.would_reject(counter),
                "would_reject diverged: {context}",
            );
            assert_eq!(
                reference.commit(counter),
                fresh.commit(counter),
                "commit diverged: {context}",
            );
            assert_eq!(
                reference.packets_received(),
                fresh.packets_received(),
                "packets_received diverged: {context}",
            );
            assert_eq!(
                reference.max_counter, fresh.max_counter,
                "max_counter diverged: {context}",
            );
        }

        assert!(!reference.commit(0));
        assert!(!fresh.commit(0));
        assert!(reference.would_reject(0));
        assert!(fresh.would_reject(0));
    }
}
