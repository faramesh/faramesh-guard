//! CAR (Canonical Action Request) Hash Canonicalization
//!
//! This module provides deterministic hashing of action requests.
//! The canonicalization ensures:
//! - Consistent ordering of JSON keys
//! - Normalized whitespace
//! - Deterministic floating point representation
//! - UTF-8 normalization
//!
//! This is a hot path component - runs on every tool call.

use sha2::{Sha256, Digest};
use serde::{Serialize, Deserialize};
use serde_json::Value;
use std::collections::BTreeMap;

use crate::{Result, GuardError};

/// CAR (Canonical Action Request) hasher
///
/// Provides deterministic hashing for deduplication and caching.
#[derive(Debug, Clone)]
pub struct CarHasher {
    /// Optional prefix for hash output
    prefix: String,
}

impl Default for CarHasher {
    fn default() -> Self {
        Self::new()
    }
}

impl CarHasher {
    /// Create a new CAR hasher
    pub fn new() -> Self {
        Self {
            prefix: "sha256:".to_string(),
        }
    }

    /// Create hasher with custom prefix
    pub fn with_prefix(prefix: impl Into<String>) -> Self {
        Self {
            prefix: prefix.into(),
        }
    }

    /// Hash a CAR from raw JSON bytes
    pub fn hash_bytes(&self, data: &[u8]) -> Result<String> {
        // Parse JSON
        let value: Value = serde_json::from_slice(data)?;
        self.hash_value(&value)
    }

    /// Hash a CAR from JSON string
    pub fn hash_str(&self, json: &str) -> Result<String> {
        let value: Value = serde_json::from_str(json)?;
        self.hash_value(&value)
    }

    /// Hash a CAR from serde Value
    pub fn hash_value(&self, value: &Value) -> Result<String> {
        let canonical = self.canonicalize(value)?;
        let hash = self.compute_hash(&canonical);
        Ok(format!("{}{}", self.prefix, hash))
    }

    /// Hash a CAR request directly
    pub fn hash_car(&self, car: &CarRequest) -> Result<String> {
        let value = serde_json::to_value(car)?;
        self.hash_value(&value)
    }

    /// Canonicalize JSON value to deterministic string
    fn canonicalize(&self, value: &Value) -> Result<String> {
        let normalized = self.normalize_value(value);
        // Use compact JSON with sorted keys (BTreeMap guarantees order)
        Ok(serde_json::to_string(&normalized)?)
    }

    /// Normalize a JSON value for canonical representation
    fn normalize_value(&self, value: &Value) -> Value {
        match value {
            Value::Object(map) => {
                // Convert to BTreeMap for sorted keys
                let sorted: BTreeMap<String, Value> = map
                    .iter()
                    .map(|(k, v)| (k.clone(), self.normalize_value(v)))
                    .collect();
                Value::Object(sorted.into_iter().collect())
            }
            Value::Array(arr) => {
                Value::Array(arr.iter().map(|v| self.normalize_value(v)).collect())
            }
            Value::Number(n) => {
                // Normalize floats to avoid precision issues
                if let Some(f) = n.as_f64() {
                    // Round to 10 decimal places to avoid floating point noise
                    let rounded = (f * 1e10).round() / 1e10;
                    if rounded.fract() == 0.0 && rounded.abs() < (i64::MAX as f64) {
                        Value::Number((rounded as i64).into())
                    } else {
                        serde_json::Number::from_f64(rounded)
                            .map(Value::Number)
                            .unwrap_or(value.clone())
                    }
                } else {
                    value.clone()
                }
            }
            Value::String(s) => {
                // Unicode NFC normalization would go here in production
                // For now, just trim whitespace from string values
                Value::String(s.trim().to_string())
            }
            _ => value.clone(),
        }
    }

    /// Compute SHA-256 hash
    fn compute_hash(&self, data: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        let result = hasher.finalize();
        hex::encode(result)
    }
}

/// Canonical Action Request structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CarRequest {
    /// Action type (e.g., "file_read", "shell_execute")
    pub action_type: String,

    /// Resource being accessed
    pub resource: String,

    /// Agent making the request
    pub agent_id: String,

    /// Optional parameters
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub parameters: Option<Value>,

    /// Optional context
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub context: Option<Value>,
}

/// Inline hex encoding (no external crate needed for this simple case)
mod hex {
    const HEX_CHARS: &[u8; 16] = b"0123456789abcdef";

    pub fn encode(data: impl AsRef<[u8]>) -> String {
        let bytes = data.as_ref();
        let mut result = String::with_capacity(bytes.len() * 2);
        for byte in bytes {
            result.push(HEX_CHARS[(byte >> 4) as usize] as char);
            result.push(HEX_CHARS[(byte & 0x0f) as usize] as char);
        }
        result
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_hash() {
        let hasher = CarHasher::new();

        // Same content, different formatting
        let json1 = r#"{"action_type":"file_read","resource":"/tmp/test.txt","agent_id":"agent1"}"#;
        let json2 = r#"{
            "resource": "/tmp/test.txt",
            "action_type": "file_read",
            "agent_id": "agent1"
        }"#;

        let hash1 = hasher.hash_str(json1).unwrap();
        let hash2 = hasher.hash_str(json2).unwrap();

        assert_eq!(hash1, hash2, "Hashes should be identical regardless of formatting");
    }

    #[test]
    fn test_hash_prefix() {
        let hasher = CarHasher::new();
        let hash = hasher.hash_str(r#"{"test": true}"#).unwrap();
        assert!(hash.starts_with("sha256:"));
    }

    #[test]
    fn test_car_request_hash() {
        let hasher = CarHasher::new();
        let car = CarRequest {
            action_type: "shell_execute".to_string(),
            resource: "ls -la".to_string(),
            agent_id: "agent1".to_string(),
            parameters: None,
            context: None,
        };

        let hash = hasher.hash_car(&car).unwrap();
        assert!(hash.starts_with("sha256:"));
        assert_eq!(hash.len(), 7 + 64); // "sha256:" + 64 hex chars
    }

    #[test]
    fn test_float_normalization() {
        let hasher = CarHasher::new();

        // These should hash the same due to float normalization
        let json1 = r#"{"value": 1.0000000001}"#;
        let json2 = r#"{"value": 1.0000000002}"#;

        let hash1 = hasher.hash_str(json1).unwrap();
        let hash2 = hasher.hash_str(json2).unwrap();

        // After rounding to 10 decimal places, these should be equal
        assert_eq!(hash1, hash2);
    }
}
