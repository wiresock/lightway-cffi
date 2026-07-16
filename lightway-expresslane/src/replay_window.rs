//! Sliding-window replay protection for received ExpressLane packets.

/// Tracks received packet counters to detect and prevent replay attacks
/// while tolerating out-of-order UDP delivery.
///
/// Uses an 8192-bit bitmap (128 × u64) to tolerate significant packet
/// reordering under high-throughput conditions.
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

impl ReplayWindow {
    const NUM_BLOCKS: usize = 128;
    const WINDOW_SIZE: u64 = (Self::NUM_BLOCKS as u64) * 64;

    fn set_bit(&mut self, position: u64) {
        let block = (position / 64) as usize;
        let bit = position % 64;
        if block < Self::NUM_BLOCKS {
            self.bitmap[block] |= 1u64 << bit;
        }
    }

    fn test_bit(&self, position: u64) -> bool {
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

        for i in 0..block_shift.min(Self::NUM_BLOCKS) {
            self.bitmap[i] = 0;
        }
    }

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
        if age >= Self::WINDOW_SIZE {
            return true;
        }
        self.test_bit(age)
    }

    /// Commit a successfully-deprotected wire counter into the window.
    /// MUST only be called after AEAD verification succeeds. Returns true
    /// if accepted; false if the counter is a replay or too old (state
    /// unchanged in that case).
    pub(crate) fn commit(&mut self, wire_counter: u64) -> bool {
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

    /// Total number of packets successfully committed.
    pub(crate) fn packets_received(&self) -> u64 {
        self.packets_received
    }
}

#[cfg(test)]
mod tests {
    use super::*;

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
}
