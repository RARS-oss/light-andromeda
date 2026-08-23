//! A hashed timing wheel for O(1) idle-timeout expiry.
//!
//! Entries are bucketed by their deadline into a ring of `slots`, each covering `tick`
//! time units, so the wheel spans `slots * tick` before wrapping. [`advance`] drains
//! every bucket whose tick has arrived and returns the keys that were due; the caller
//! decides to expire each or **reschedule** (re-insert) the ones still alive. Insert and
//! reschedule are O(1); advancing costs O(buckets crossed + entries drained), not O(all
//! entries) — the point of the structure.
//!
//! Precision is intentionally not load-bearing: paired with a liveness re-check on the
//! caller's side (compare the entry's real `last_seen`), the wheel only needs to
//! *eventually* surface every entry, which the ring guarantees within one revolution of
//! its deadline.
//!
//! [`advance`]: TimingWheel::advance

/// A single-level hashed timing wheel keyed by `K`.
pub struct TimingWheel<K> {
    slots: Vec<Vec<K>>,
    tick: u64,
    /// Absolute time the hand has advanced to (starts at 0).
    now: u64,
}

impl<K> TimingWheel<K> {
    /// A wheel of `slots` buckets, each `tick` time units wide (spanning `slots * tick`
    /// before it wraps). Pick the span `>=` your idle timeout so a live deadline never
    /// lands a full revolution ahead.
    #[must_use]
    pub fn new(tick: u64, slots: usize) -> Self {
        assert!(tick > 0, "tick must be > 0");
        assert!(slots > 0, "slots must be > 0");
        Self {
            slots: (0..slots).map(|_| Vec::new()).collect(),
            tick,
            now: 0,
        }
    }

    #[inline]
    fn bucket_of(&self, deadline: u64) -> usize {
        ((deadline / self.tick) % self.slots.len() as u64) as usize
    }

    /// Schedule `key` to fire at absolute time `deadline`.
    pub fn insert(&mut self, key: K, deadline: u64) {
        let b = self.bucket_of(deadline);
        self.slots[b].push(key);
    }

    /// Advance the hand to `now`, moving every key whose bucket has arrived into `due`.
    /// Processing is capped at one full revolution (a longer gap expires everything once).
    pub fn advance(&mut self, now: u64, due: &mut Vec<K>) {
        let n = self.slots.len() as u64;
        let cur_tick = now / self.tick;
        let last_tick = self.now / self.tick;
        // Number of new tick boundaries crossed, capped at one full revolution.
        let steps = cur_tick.wrapping_sub(last_tick).min(n);
        for s in 1..=steps {
            let b = (last_tick.wrapping_add(s) % n) as usize;
            due.append(&mut self.slots[b]);
        }
        self.now = now;
    }

    /// Total scheduled entries (for tests/metrics). O(slots).
    #[must_use]
    pub fn len(&self) -> usize {
        self.slots.iter().map(Vec::len).sum()
    }

    /// Whether nothing is scheduled.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.slots.iter().all(Vec::is_empty)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fires_only_after_the_deadline_bucket() {
        let mut w = TimingWheel::new(10, 16); // tick 10, span 160
        w.insert("a", 50);
        w.insert("b", 90);

        let mut due = Vec::new();
        w.advance(40, &mut due); // before either deadline
        assert!(due.is_empty());

        w.advance(55, &mut due); // 'a' (bucket 5) is now due
        assert_eq!(due, vec!["a"]);

        due.clear();
        w.advance(95, &mut due); // 'b' (bucket 9) is now due
        assert_eq!(due, vec!["b"]);
        assert!(w.is_empty());
    }

    #[test]
    fn reschedule_extends_the_deadline() {
        let mut w = TimingWheel::new(10, 16);
        w.insert(1u32, 50);

        let mut due = Vec::new();
        w.advance(55, &mut due); // fires
        assert_eq!(due, vec![1]);

        // Caller decides it is still alive → reschedule further out.
        w.insert(1u32, 150);
        due.clear();
        w.advance(100, &mut due);
        assert!(due.is_empty(), "rescheduled entry must not fire early");
        w.advance(155, &mut due);
        assert_eq!(due, vec![1]);
    }

    #[test]
    fn a_long_gap_drains_at_most_one_revolution() {
        let mut w = TimingWheel::new(1, 8); // span 8
        for i in 0..8u32 {
            w.insert(i, i as u64); // one per bucket
        }
        assert_eq!(w.len(), 8);
        let mut due = Vec::new();
        // Jump far past a full revolution: everything drains exactly once, no double count.
        w.advance(1000, &mut due);
        due.sort_unstable();
        assert_eq!(due, vec![0, 1, 2, 3, 4, 5, 6, 7]);
        assert!(w.is_empty());
    }

    #[test]
    fn many_entries_same_bucket() {
        let mut w = TimingWheel::new(10, 4);
        for k in 0..100u32 {
            w.insert(k, 25); // all in bucket 2
        }
        let mut due = Vec::new();
        w.advance(30, &mut due);
        assert_eq!(due.len(), 100);
    }
}
