//! Anti-replay sliding window bitmap (RFC 6479 style).
//!
//! Protects against replayed transport packets by tracking recently seen
//! counter values. Uses a 128-bit bitmap relative to the highest counter
//! seen, allowing out-of-order delivery within the window while rejecting
//! duplicates and counters that are too old.

/// Size of the sliding window in counter values.
const WINDOW_SIZE: u64 = 128;

/// A sliding-window anti-replay filter.
///
/// Tracks the highest counter seen and a bitmap of recently seen counters
/// within [`WINDOW_SIZE`] positions below the top. Rejects counters that
/// are duplicates, too old (below the window), or have already been marked.
pub struct AntiReplayWindow {
    /// Highest counter value seen so far.
    top: u64,
    /// Bitmap of recently seen counters relative to `top`.
    /// Bit `i` represents counter `top - i`.
    bitmap: u128,
}

impl AntiReplayWindow {
    /// Create a new anti-replay window with no counters seen.
    pub fn new() -> Self {
        Self {
            top: 0,
            bitmap: 0,
        }
    }

    /// Check whether a counter value is acceptable and, if so, mark it as seen.
    ///
    /// Returns `true` if the counter is fresh (not replayed), `false` otherwise.
    ///
    /// # Rules
    /// - Counter `0` is always rejected (reserved).
    /// - Counters above `top` advance the window and are accepted.
    /// - Counters within the window are accepted only if not already seen.
    /// - Counters below the window are rejected as too old.
    pub fn check_and_update(&mut self, counter: u64) -> bool {
        // Counter 0 is reserved / invalid
        if counter == 0 {
            return false;
        }

        if counter > self.top {
            // New high-water mark — shift the bitmap
            let shift = counter - self.top;
            if shift >= WINDOW_SIZE {
                // Entire window is obsolete
                self.bitmap = 0;
            } else {
                self.bitmap <<= shift;
            }
            self.top = counter;
            // Mark the new top as seen (bit 0)
            self.bitmap |= 1;
            return true;
        }

        // Counter is at or below top
        let offset = self.top - counter;

        if offset >= WINDOW_SIZE {
            // Too old — outside the window
            return false;
        }

        // Check if already seen
        let bit = 1u128 << offset;
        if self.bitmap & bit != 0 {
            // Duplicate
            return false;
        }

        // Mark as seen
        self.bitmap |= bit;
        true
    }
}

impl Default for AntiReplayWindow {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn counter_zero_rejected() {
        let mut w = AntiReplayWindow::new();
        assert!(!w.check_and_update(0));
    }

    #[test]
    fn sequential_counters_accepted() {
        let mut w = AntiReplayWindow::new();
        for i in 1..=200 {
            assert!(w.check_and_update(i), "counter {} should be accepted", i);
        }
    }

    #[test]
    fn duplicate_rejected() {
        let mut w = AntiReplayWindow::new();
        assert!(w.check_and_update(1));
        assert!(!w.check_and_update(1));
    }

    #[test]
    fn out_of_order_within_window_accepted() {
        let mut w = AntiReplayWindow::new();
        assert!(w.check_and_update(10));
        assert!(w.check_and_update(8)); // out of order but within window
        assert!(w.check_and_update(9));
        assert!(w.check_and_update(7));
    }

    #[test]
    fn out_of_order_duplicate_rejected() {
        let mut w = AntiReplayWindow::new();
        assert!(w.check_and_update(10));
        assert!(w.check_and_update(8));
        assert!(!w.check_and_update(8)); // duplicate
    }

    #[test]
    fn too_old_rejected() {
        let mut w = AntiReplayWindow::new();
        // Advance the window well past counter 1
        assert!(w.check_and_update(1));
        assert!(w.check_and_update(200));
        // Counter 1 is now far outside the window
        assert!(!w.check_and_update(1));
    }

    #[test]
    fn window_boundary_accepted() {
        let mut w = AntiReplayWindow::new();
        // Set top to 128
        assert!(w.check_and_update(128));
        // Counter 1 is exactly at the boundary (offset = 127, still in window)
        assert!(w.check_and_update(1));
    }

    #[test]
    fn window_boundary_plus_one_rejected() {
        let mut w = AntiReplayWindow::new();
        // Set top to 129
        assert!(w.check_and_update(129));
        // Counter 1 is now at offset 128, outside the 128-bit window
        assert!(!w.check_and_update(1));
    }

    #[test]
    fn large_jump_clears_window() {
        let mut w = AntiReplayWindow::new();
        assert!(w.check_and_update(1));
        assert!(w.check_and_update(2));
        // Jump far ahead
        assert!(w.check_and_update(1000));
        // Old counters should be rejected (too old)
        assert!(!w.check_and_update(1));
        assert!(!w.check_and_update(2));
        // Counter just below the new top should still work
        assert!(w.check_and_update(999));
    }

    #[test]
    fn top_counter_duplicate_rejected() {
        let mut w = AntiReplayWindow::new();
        assert!(w.check_and_update(50));
        assert!(!w.check_and_update(50)); // exact top duplicate
    }
}
