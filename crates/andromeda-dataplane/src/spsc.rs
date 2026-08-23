//! A bounded, wait-free single-producer / single-consumer (SPSC) ring buffer.
//!
//! This is the lock-free hand-off used to fan packets between per-core threads in the
//! multi-queue datapath: each `(producer, consumer)` pair is owned by exactly two
//! threads, so no locks and no CAS are needed — only a `Release` store to publish and
//! an `Acquire` load to observe. The single-producer/single-consumer discipline is what
//! makes plain load/store correct here.
//!
//! Correctness is checked two ways: an exhaustive **loom** model-check of the two-thread
//! interleavings (`cfg(loom)`), and a large real-threaded FIFO stress test.

#[cfg(loom)]
use loom::cell::UnsafeCell;
#[cfg(loom)]
use loom::sync::atomic::{AtomicUsize, Ordering};
#[cfg(loom)]
use loom::sync::Arc;

#[cfg(not(loom))]
use std::sync::atomic::{AtomicUsize, Ordering};
#[cfg(not(loom))]
use std::sync::Arc;

/// A `std::cell::UnsafeCell` wrapper exposing loom's `with`/`with_mut` API, so the ring
/// body is written once and compiles under both loom and the real allocator.
#[cfg(not(loom))]
#[derive(Debug)]
struct UnsafeCell<T>(std::cell::UnsafeCell<T>);
#[cfg(not(loom))]
impl<T> UnsafeCell<T> {
    fn new(v: T) -> Self {
        Self(std::cell::UnsafeCell::new(v))
    }
    fn with<R>(&self, f: impl FnOnce(*const T) -> R) -> R {
        f(self.0.get())
    }
    fn with_mut<R>(&self, f: impl FnOnce(*mut T) -> R) -> R {
        f(self.0.get())
    }
}

struct Ring<T> {
    buf: Box<[UnsafeCell<T>]>,
    mask: usize,
    /// Next index the consumer will read. Only the consumer stores to it.
    head: AtomicUsize,
    /// Next index the producer will write. Only the producer stores to it.
    tail: AtomicUsize,
}

// Safety: the SPSC discipline guarantees the producer only ever writes the slot at
// `tail & mask` (which the consumer will not read until `tail` is advanced with a
// `Release` store), and the consumer only reads the slot at `head & mask` (freed for
// reuse only after `head` is advanced with a `Release` store). No two threads touch the
// same slot concurrently, so sharing the cells across the two threads is sound.
unsafe impl<T: Send> Send for Ring<T> {}
unsafe impl<T: Send> Sync for Ring<T> {}

/// The producer half. Owned by exactly one thread.
pub struct Producer<T> {
    ring: Arc<Ring<T>>,
}

/// The consumer half. Owned by exactly one thread.
pub struct Consumer<T> {
    ring: Arc<Ring<T>>,
}

/// Create an SPSC ring holding up to `capacity` elements (rounded up to a power of two,
/// minimum 2). Returns the producer and consumer halves, each movable to its own thread.
pub fn channel<T: Copy + Default>(capacity: usize) -> (Producer<T>, Consumer<T>) {
    let cap = capacity.max(2).next_power_of_two();
    let buf: Box<[UnsafeCell<T>]> = (0..cap).map(|_| UnsafeCell::new(T::default())).collect();
    let ring = Arc::new(Ring {
        buf,
        mask: cap - 1,
        head: AtomicUsize::new(0),
        tail: AtomicUsize::new(0),
    });
    (
        Producer {
            ring: Arc::clone(&ring),
        },
        Consumer { ring },
    )
}

impl<T: Copy> Producer<T> {
    /// Try to push `val`. Returns `Err(val)` if the ring is full (no space right now).
    ///
    /// # Errors
    /// Returns the value back when the buffer is full so the caller can retry or drop it.
    pub fn push(&self, val: T) -> Result<(), T> {
        let r = &*self.ring;
        // Only this thread writes `tail`, so a relaxed load of our own value is fine.
        let tail = r.tail.load(Ordering::Relaxed);
        // Observe the consumer's progress; Acquire pairs with its Release store of `head`.
        let head = r.head.load(Ordering::Acquire);
        if tail.wrapping_sub(head) == r.buf.len() {
            return Err(val); // full
        }
        r.buf[tail & r.mask].with_mut(|p| unsafe { *p = val });
        // Publish the slot write; Release pairs with the consumer's Acquire load of `tail`.
        r.tail.store(tail.wrapping_add(1), Ordering::Release);
        Ok(())
    }
}

impl<T: Copy> Consumer<T> {
    /// Pop the oldest element, or `None` if the ring is empty.
    pub fn pop(&self) -> Option<T> {
        let r = &*self.ring;
        // Only this thread writes `head`; relaxed load of our own value is fine.
        let head = r.head.load(Ordering::Relaxed);
        // Observe the producer's writes; Acquire pairs with its Release store of `tail`.
        let tail = r.tail.load(Ordering::Acquire);
        if head == tail {
            return None; // empty
        }
        let val = r.buf[head & r.mask].with(|p| unsafe { *p });
        // Free the slot for reuse; Release pairs with the producer's Acquire load of `head`.
        r.head.store(head.wrapping_add(1), Ordering::Release);
        Some(val)
    }
}

#[cfg(all(test, not(loom)))]
mod tests {
    use super::*;

    #[test]
    fn empty_pop_is_none_and_wraps_around() {
        let (tx, rx) = channel::<u64>(4); // rounded to 4
        assert_eq!(rx.pop(), None);
        // Fill, drain, and refill several times to exercise index wraparound.
        for round in 0..10u64 {
            for i in 0..4 {
                assert!(tx.push(round * 10 + i).is_ok());
            }
            // Now full: one more push must fail without clobbering anything.
            assert!(tx.push(999).is_err());
            for i in 0..4 {
                assert_eq!(rx.pop(), Some(round * 10 + i));
            }
            assert_eq!(rx.pop(), None);
        }
    }

    #[test]
    fn capacity_is_rounded_up_to_power_of_two() {
        let (tx, _rx) = channel::<u8>(3); // -> 4
        for i in 0..4 {
            assert!(tx.push(i).is_ok());
        }
        assert!(tx.push(4).is_err()); // capacity is exactly 4
    }

    #[test]
    fn two_thread_stress_preserves_fifo() {
        const N: u64 = 200_000;
        let (tx, rx) = channel::<u64>(1024);

        let producer = std::thread::spawn(move || {
            for i in 0..N {
                while tx.push(i).is_err() {
                    std::thread::yield_now();
                }
            }
        });

        // The consumer must observe every value exactly once, in order.
        let mut expected = 0u64;
        while expected < N {
            match rx.pop() {
                Some(v) => {
                    assert_eq!(v, expected, "SPSC must be strict FIFO with no gaps/dupes");
                    expected += 1;
                }
                None => std::thread::yield_now(),
            }
        }
        producer.join().unwrap();
        assert_eq!(expected, N);
    }
}

#[cfg(loom)]
mod loom_tests {
    use super::*;

    /// Exhaustively model-check that a producer and consumer on separate threads never
    /// lose, duplicate, or reorder items across every possible interleaving.
    #[test]
    fn loom_spsc_is_lossless_fifo() {
        loom::model(|| {
            let (tx, rx) = channel::<usize>(2);
            let producer = loom::thread::spawn(move || {
                for i in 0..3usize {
                    while tx.push(i).is_err() {
                        loom::thread::yield_now();
                    }
                }
            });

            let mut got = Vec::new();
            while got.len() < 3 {
                match rx.pop() {
                    Some(v) => got.push(v),
                    None => loom::thread::yield_now(),
                }
            }
            producer.join().unwrap();
            assert_eq!(got, vec![0, 1, 2]);
        });
    }
}
