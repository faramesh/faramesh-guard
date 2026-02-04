//! Fast Decision Cache (Lock-free)
//!
//! This module provides a high-performance, lock-free decision cache.
//! Uses DashMap for concurrent access without blocking.
//!
//! Performance characteristics:
//! - O(1) lookup
//! - Lock-free reads
//! - Sharded writes
//! - Automatic expiration
//!
//! This is a hot path component - runs on every tool call.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use crate::{Decision, CachedDecision, Result, GuardError};

/// Cache entry with TTL
#[derive(Debug, Clone)]
struct CacheEntry {
    decision: Decision,
    confidence: f64,
    expires_at: i64,
    created_at: i64,
}

/// Fast, lock-free decision cache
pub struct DecisionCache {
    /// Main cache storage (lock-free)
    cache: DashMap<String, CacheEntry>,

    /// Maximum entries
    max_entries: usize,

    /// Default TTL in seconds
    default_ttl: i64,

    /// Statistics
    hits: AtomicU64,
    misses: AtomicU64,
    evictions: AtomicU64,
}

impl DecisionCache {
    /// Create a new decision cache
    pub fn new(max_entries: usize, default_ttl_seconds: i64) -> Self {
        Self {
            cache: DashMap::with_capacity(max_entries),
            max_entries,
            default_ttl: default_ttl_seconds,
            hits: AtomicU64::new(0),
            misses: AtomicU64::new(0),
            evictions: AtomicU64::new(0),
        }
    }

    /// Get current Unix timestamp
    fn now() -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("Time went backwards")
            .as_secs() as i64
    }

    /// Get a cached decision
    pub fn get(&self, car_hash: &str) -> Option<CachedDecision> {
        let now = Self::now();

        if let Some(entry) = self.cache.get(car_hash) {
            // Check expiration
            if entry.expires_at > now {
                self.hits.fetch_add(1, Ordering::Relaxed);
                return Some(CachedDecision {
                    decision: entry.decision,
                    confidence: entry.confidence,
                    expires_at: entry.expires_at,
                    car_hash: car_hash.to_string(),
                });
            } else {
                // Expired - will be cleaned up later
                self.misses.fetch_add(1, Ordering::Relaxed);
                return None;
            }
        }

        self.misses.fetch_add(1, Ordering::Relaxed);
        None
    }

    /// Put a decision in the cache
    pub fn put(&self, car_hash: &str, decision: Decision, confidence: f64, ttl: Option<i64>) {
        let now = Self::now();
        let ttl = ttl.unwrap_or(self.default_ttl);

        // Enforce max entries
        if self.cache.len() >= self.max_entries {
            self.evict_expired();

            // If still at capacity, evict oldest
            if self.cache.len() >= self.max_entries {
                self.evict_oldest();
            }
        }

        self.cache.insert(
            car_hash.to_string(),
            CacheEntry {
                decision,
                confidence,
                expires_at: now + ttl,
                created_at: now,
            },
        );
    }

    /// Invalidate a specific entry
    pub fn invalidate(&self, car_hash: &str) -> bool {
        self.cache.remove(car_hash).is_some()
    }

    /// Clear all entries
    pub fn clear(&self) -> usize {
        let count = self.cache.len();
        self.cache.clear();
        count
    }

    /// Evict expired entries
    pub fn evict_expired(&self) -> usize {
        let now = Self::now();
        let mut evicted = 0;

        self.cache.retain(|_, entry| {
            if entry.expires_at <= now {
                evicted += 1;
                false
            } else {
                true
            }
        });

        self.evictions.fetch_add(evicted as u64, Ordering::Relaxed);
        evicted
    }

    /// Evict oldest entries (when at capacity)
    fn evict_oldest(&self) {
        // Find and remove the oldest entry
        let mut oldest_key: Option<String> = None;
        let mut oldest_time = i64::MAX;

        for entry in self.cache.iter() {
            if entry.created_at < oldest_time {
                oldest_time = entry.created_at;
                oldest_key = Some(entry.key().clone());
            }
        }

        if let Some(key) = oldest_key {
            self.cache.remove(&key);
            self.evictions.fetch_add(1, Ordering::Relaxed);
        }
    }

    /// Get cache statistics
    pub fn stats(&self) -> CacheStats {
        let hits = self.hits.load(Ordering::Relaxed);
        let misses = self.misses.load(Ordering::Relaxed);
        let total = hits + misses;

        CacheStats {
            entries: self.cache.len(),
            max_entries: self.max_entries,
            hits,
            misses,
            hit_rate: if total > 0 { hits as f64 / total as f64 } else { 0.0 },
            evictions: self.evictions.load(Ordering::Relaxed),
        }
    }

    /// Get all entries (for debugging/diagnostics)
    pub fn entries(&self) -> Vec<CachedDecision> {
        let now = Self::now();
        self.cache
            .iter()
            .filter(|e| e.expires_at > now)
            .map(|e| CachedDecision {
                decision: e.decision,
                confidence: e.confidence,
                expires_at: e.expires_at,
                car_hash: e.key().clone(),
            })
            .collect()
    }
}

/// Cache statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CacheStats {
    pub entries: usize,
    pub max_entries: usize,
    pub hits: u64,
    pub misses: u64,
    pub hit_rate: f64,
    pub evictions: u64,
}

impl Default for DecisionCache {
    fn default() -> Self {
        Self::new(10000, 300) // 10k entries, 5 min TTL
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cache_put_get() {
        let cache = DecisionCache::new(100, 300);

        cache.put("sha256:abc123", Decision::Allow, 0.95, None);

        let result = cache.get("sha256:abc123");
        assert!(result.is_some());

        let cached = result.unwrap();
        assert_eq!(cached.decision, Decision::Allow);
        assert!(cached.confidence > 0.9);
    }

    #[test]
    fn test_cache_miss() {
        let cache = DecisionCache::new(100, 300);

        let result = cache.get("sha256:nonexistent");
        assert!(result.is_none());

        let stats = cache.stats();
        assert_eq!(stats.misses, 1);
    }

    #[test]
    fn test_cache_invalidate() {
        let cache = DecisionCache::new(100, 300);

        cache.put("sha256:abc123", Decision::Allow, 0.95, None);
        assert!(cache.get("sha256:abc123").is_some());

        cache.invalidate("sha256:abc123");
        assert!(cache.get("sha256:abc123").is_none());
    }

    #[test]
    fn test_cache_expiration() {
        let cache = DecisionCache::new(100, 1);

        cache.put("sha256:abc123", Decision::Allow, 0.95, Some(-1)); // Already expired

        let result = cache.get("sha256:abc123");
        assert!(result.is_none());
    }

    #[test]
    fn test_cache_stats() {
        let cache = DecisionCache::new(100, 300);

        cache.put("sha256:abc123", Decision::Allow, 0.95, None);
        cache.get("sha256:abc123"); // hit
        cache.get("sha256:abc123"); // hit
        cache.get("sha256:nonexistent"); // miss

        let stats = cache.stats();
        assert_eq!(stats.hits, 2);
        assert_eq!(stats.misses, 1);
        assert_eq!(stats.entries, 1);
    }

    #[test]
    fn test_cache_capacity() {
        let cache = DecisionCache::new(3, 300);

        cache.put("sha256:a", Decision::Allow, 0.9, None);
        cache.put("sha256:b", Decision::Allow, 0.9, None);
        cache.put("sha256:c", Decision::Allow, 0.9, None);

        // This should trigger eviction
        cache.put("sha256:d", Decision::Allow, 0.9, None);

        assert!(cache.stats().entries <= 3);
    }
}
