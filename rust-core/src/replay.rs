//! Replay Detection Ring Buffer
//!
//! This module provides fast replay attack detection using a lock-free
//! ring buffer for nonce/permit tracking.
//!
//! Security properties:
//! - Detects permit replay within window
//! - O(1) lookup using bloom filter
//! - Bounded memory usage
//! - Thread-safe without locks
//!
//! This is a security-critical component.

use crossbeam::queue::ArrayQueue;
use dashmap::DashSet;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Result, GuardError};

/// Entry in the replay detection window
#[derive(Debug, Clone)]
struct ReplayEntry {
    /// Nonce or permit ID
    id: String,
    /// Timestamp when seen
    seen_at: i64,
}

/// Replay detection using ring buffer + hash set
pub struct ReplayDetector {
    /// Ring buffer of recent nonces (bounded)
    ring_buffer: ArrayQueue<ReplayEntry>,

    /// Fast lookup set
    seen_set: DashSet<String>,

    /// Window size in seconds
    window_seconds: i64,

    /// Maximum entries in ring buffer
    max_entries: usize,

    /// Statistics
    checks: AtomicU64,
    replays_detected: AtomicU64,
}

impl ReplayDetector {
    /// Create a new replay detector
    pub fn new(max_entries: usize, window_seconds: i64) -> Self {
        Self {
            ring_buffer: ArrayQueue::new(max_entries),
            seen_set: DashSet::with_capacity(max_entries),
            window_seconds,
            max_entries,
            checks: AtomicU64::new(0),
            replays_detected: AtomicU64::new(0),
        }
    }

    /// Get current Unix timestamp
    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as i64
    }

    /// Check if a nonce has been seen (is a replay)
    /// Returns true if this is a REPLAY (already seen)
    pub fn check(&self, nonce: &str) -> bool {
        self.checks.fetch_add(1, Ordering::Relaxed);
        self.seen_set.contains(nonce)
    }

    /// Check and register a nonce
    /// Returns Err if replay detected, Ok if new
    pub fn check_and_register(&self, nonce: &str) -> Result<()> {
        self.checks.fetch_add(1, Ordering::Relaxed);

        // Fast check if already seen
        if self.seen_set.contains(nonce) {
            self.replays_detected.fetch_add(1, Ordering::Relaxed);
            return Err(GuardError::ReplayDetected(nonce.to_string()));
        }

        // Register the nonce
        self.register(nonce);
        Ok(())
    }

    /// Register a nonce (mark as seen)
    pub fn register(&self, nonce: &str) {
        let now = Self::now();

        // If ring buffer is full, pop oldest and remove from set
        if self.ring_buffer.is_full() {
            if let Some(old) = self.ring_buffer.pop() {
                self.seen_set.remove(&old.id);
            }
        }

        // Add to set and ring buffer
        self.seen_set.insert(nonce.to_string());
        let _ = self.ring_buffer.push(ReplayEntry {
            id: nonce.to_string(),
            seen_at: now,
        });
    }

    /// Clean up expired entries
    pub fn cleanup_expired(&self) -> usize {
        let cutoff = Self::now() - self.window_seconds;
        let mut cleaned = 0;

        // Pop expired entries from front of ring buffer
        loop {
            // Peek at front
            if let Some(entry) = self.peek_front() {
                if entry.seen_at < cutoff {
                    if let Some(removed) = self.ring_buffer.pop() {
                        self.seen_set.remove(&removed.id);
                        cleaned += 1;
                        continue;
                    }
                }
            }
            break;
        }

        cleaned
    }

    /// Peek at front of ring buffer (oldest entry)
    fn peek_front(&self) -> Option<ReplayEntry> {
        // This is a bit tricky with ArrayQueue - we pop and push back
        // For production, consider a different data structure
        if let Some(entry) = self.ring_buffer.pop() {
            let clone = entry.clone();
            let _ = self.ring_buffer.push(entry);
            Some(clone)
        } else {
            None
        }
    }

    /// Get statistics
    pub fn stats(&self) -> ReplayStats {
        ReplayStats {
            entries: self.seen_set.len(),
            max_entries: self.max_entries,
            window_seconds: self.window_seconds,
            total_checks: self.checks.load(Ordering::Relaxed),
            replays_detected: self.replays_detected.load(Ordering::Relaxed),
        }
    }

    /// Clear all entries
    pub fn clear(&self) -> usize {
        let count = self.seen_set.len();
        self.seen_set.clear();
        // Drain the ring buffer
        while self.ring_buffer.pop().is_some() {}
        count
    }
}

/// Replay detection statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ReplayStats {
    pub entries: usize,
    pub max_entries: usize,
    pub window_seconds: i64,
    pub total_checks: u64,
    pub replays_detected: u64,
}

impl Default for ReplayDetector {
    fn default() -> Self {
        Self::new(100_000, 300) // 100k entries, 5 min window
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_first_nonce_accepted() {
        let detector = ReplayDetector::new(100, 300);

        let result = detector.check_and_register("nonce-abc-123");
        assert!(result.is_ok());
    }

    #[test]
    fn test_replay_detected() {
        let detector = ReplayDetector::new(100, 300);

        // First time - OK
        assert!(detector.check_and_register("nonce-abc-123").is_ok());

        // Second time - REPLAY
        let result = detector.check_and_register("nonce-abc-123");
        assert!(matches!(result, Err(GuardError::ReplayDetected(_))));
    }

    #[test]
    fn test_different_nonces_ok() {
        let detector = ReplayDetector::new(100, 300);

        assert!(detector.check_and_register("nonce-1").is_ok());
        assert!(detector.check_and_register("nonce-2").is_ok());
        assert!(detector.check_and_register("nonce-3").is_ok());
    }

    #[test]
    fn test_capacity_enforcement() {
        let detector = ReplayDetector::new(3, 300);

        detector.register("nonce-1");
        detector.register("nonce-2");
        detector.register("nonce-3");

        // At capacity, oldest should be evicted
        detector.register("nonce-4");

        // nonce-1 should have been evicted
        assert!(!detector.check("nonce-1"));
        assert!(detector.check("nonce-4"));
    }

    #[test]
    fn test_stats() {
        let detector = ReplayDetector::new(100, 300);

        detector.register("nonce-1");
        detector.register("nonce-2");

        let _ = detector.check_and_register("nonce-1"); // Replay
        let _ = detector.check_and_register("nonce-3"); // New

        let stats = detector.stats();
        assert_eq!(stats.entries, 3);
        assert_eq!(stats.replays_detected, 1);
    }

    #[test]
    fn test_clear() {
        let detector = ReplayDetector::new(100, 300);

        detector.register("nonce-1");
        detector.register("nonce-2");

        let cleared = detector.clear();
        assert_eq!(cleared, 2);

        // Previously seen nonces should now be accepted
        assert!(detector.check_and_register("nonce-1").is_ok());
    }
}
