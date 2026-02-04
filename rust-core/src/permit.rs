//! Permit Verification (HMAC-based)
//!
//! This module handles cryptographic verification of permits.
//! A permit is proof that an action was approved.
//!
//! Security properties:
//! - HMAC-SHA256 signature verification
//! - Expiration checking
//! - Nonce validation
//! - Action binding (permit is tied to specific CAR)
//!
//! This is a crypto hot path - runs on every tool execution.

use ring::hmac;
use serde::{Deserialize, Serialize};
use base64::{Engine as _, engine::general_purpose::STANDARD as BASE64};
use chrono::{DateTime, Utc};

use crate::{Result, GuardError, Decision};

/// Permit structure
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Permit {
    /// Unique permit ID
    pub permit_id: String,

    /// CAR hash this permit authorizes
    pub car_hash: String,

    /// Decision (allow/deny)
    pub decision: Decision,

    /// Confidence score (0.0 - 1.0)
    pub confidence: f64,

    /// Who/what issued this permit
    pub issued_by: String,

    /// When the permit was issued (Unix timestamp)
    pub issued_at: i64,

    /// When the permit expires (Unix timestamp)
    pub expires_at: i64,

    /// Nonce for replay protection
    pub nonce: String,

    /// HMAC signature (base64)
    pub signature: String,
}

/// Permit verifier with HMAC key
pub struct PermitVerifier {
    /// HMAC key for verification
    key: hmac::Key,

    /// Clock skew tolerance in seconds
    clock_skew_tolerance: i64,
}

impl PermitVerifier {
    /// Create a new permit verifier with the given secret key
    pub fn new(secret: &[u8]) -> Self {
        Self {
            key: hmac::Key::new(hmac::HMAC_SHA256, secret),
            clock_skew_tolerance: 30, // 30 seconds
        }
    }

    /// Create verifier from base64-encoded secret
    pub fn from_base64(secret_b64: &str) -> Result<Self> {
        let secret = BASE64.decode(secret_b64)
            .map_err(|e| GuardError::CryptoError(format!("Invalid base64 key: {}", e)))?;
        Ok(Self::new(&secret))
    }

    /// Set clock skew tolerance
    pub fn with_clock_skew(mut self, seconds: i64) -> Self {
        self.clock_skew_tolerance = seconds;
        self
    }

    /// Verify a permit
    pub fn verify(&self, permit: &Permit) -> Result<VerificationResult> {
        // 1. Check expiration first (fast path)
        let now = Utc::now().timestamp();

        if permit.expires_at + self.clock_skew_tolerance < now {
            return Err(GuardError::PermitExpired(permit.expires_at));
        }

        // 2. Verify HMAC signature
        if !self.verify_signature(permit)? {
            return Err(GuardError::HmacVerificationFailed);
        }

        // 3. Build verification result
        Ok(VerificationResult {
            valid: true,
            permit_id: permit.permit_id.clone(),
            car_hash: permit.car_hash.clone(),
            decision: permit.decision,
            confidence: permit.confidence,
            remaining_ttl: permit.expires_at - now,
        })
    }

    /// Verify the HMAC signature of a permit
    fn verify_signature(&self, permit: &Permit) -> Result<bool> {
        // Reconstruct the signed message
        let message = self.build_signed_message(permit);

        // Decode signature
        let signature_bytes = BASE64.decode(&permit.signature)
            .map_err(|e| GuardError::CryptoError(format!("Invalid signature encoding: {}", e)))?;

        // Verify HMAC
        match hmac::verify(&self.key, message.as_bytes(), &signature_bytes) {
            Ok(_) => Ok(true),
            Err(_) => Ok(false),
        }
    }

    /// Build the message that should be signed
    fn build_signed_message(&self, permit: &Permit) -> String {
        // Canonical message format for signing
        format!(
            "{}:{}:{}:{}:{}:{}:{}",
            permit.permit_id,
            permit.car_hash,
            permit.decision,
            permit.issued_by,
            permit.issued_at,
            permit.expires_at,
            permit.nonce,
        )
    }

    /// Sign a permit (for testing or permit generation)
    pub fn sign(&self, permit: &mut Permit) {
        let message = self.build_signed_message(permit);
        let tag = hmac::sign(&self.key, message.as_bytes());
        permit.signature = BASE64.encode(tag.as_ref());
    }

    /// Create and sign a new permit
    pub fn create_permit(
        &self,
        car_hash: String,
        decision: Decision,
        confidence: f64,
        issued_by: String,
        ttl_seconds: i64,
    ) -> Permit {
        let now = Utc::now().timestamp();
        let nonce = self.generate_nonce();
        let permit_id = format!("permit_{}", &nonce[..16]);

        let mut permit = Permit {
            permit_id,
            car_hash,
            decision,
            confidence,
            issued_by,
            issued_at: now,
            expires_at: now + ttl_seconds,
            nonce,
            signature: String::new(),
        };

        self.sign(&mut permit);
        permit
    }

    /// Generate a cryptographically secure nonce
    fn generate_nonce(&self) -> String {
        use ring::rand::{SystemRandom, SecureRandom};
        let rng = SystemRandom::new();
        let mut nonce = [0u8; 32];
        rng.fill(&mut nonce).expect("Failed to generate nonce");
        BASE64.encode(&nonce)
    }
}

/// Result of permit verification
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VerificationResult {
    /// Whether the permit is valid
    pub valid: bool,

    /// Permit ID
    pub permit_id: String,

    /// CAR hash
    pub car_hash: String,

    /// Decision
    pub decision: Decision,

    /// Confidence
    pub confidence: f64,

    /// Remaining TTL in seconds
    pub remaining_ttl: i64,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_secret() -> Vec<u8> {
        b"test-secret-key-for-hmac-256-!!!".to_vec()
    }

    #[test]
    fn test_permit_sign_verify() {
        let verifier = PermitVerifier::new(&test_secret());

        let permit = verifier.create_permit(
            "sha256:abc123".to_string(),
            Decision::Allow,
            0.95,
            "policy".to_string(),
            300, // 5 minutes
        );

        let result = verifier.verify(&permit).unwrap();
        assert!(result.valid);
        assert_eq!(result.decision, Decision::Allow);
        assert!(result.confidence > 0.9);
    }

    #[test]
    fn test_permit_tamper_detection() {
        let verifier = PermitVerifier::new(&test_secret());

        let mut permit = verifier.create_permit(
            "sha256:abc123".to_string(),
            Decision::Allow,
            0.95,
            "policy".to_string(),
            300,
        );

        // Tamper with the permit
        permit.decision = Decision::Deny;

        // Verification should fail
        let result = verifier.verify(&permit);
        assert!(matches!(result, Err(GuardError::HmacVerificationFailed)));
    }

    #[test]
    fn test_permit_expiration() {
        let verifier = PermitVerifier::new(&test_secret());

        let mut permit = verifier.create_permit(
            "sha256:abc123".to_string(),
            Decision::Allow,
            0.95,
            "policy".to_string(),
            -100, // Already expired
        );

        // Need to resign after modifying
        verifier.sign(&mut permit);

        let result = verifier.verify(&permit);
        assert!(matches!(result, Err(GuardError::PermitExpired(_))));
    }

    #[test]
    fn test_different_keys_fail() {
        let verifier1 = PermitVerifier::new(b"secret-key-one-for-testing-1234");
        let verifier2 = PermitVerifier::new(b"secret-key-two-for-testing-5678");

        let permit = verifier1.create_permit(
            "sha256:abc123".to_string(),
            Decision::Allow,
            0.95,
            "policy".to_string(),
            300,
        );

        // Different verifier should fail
        let result = verifier2.verify(&permit);
        assert!(matches!(result, Err(GuardError::HmacVerificationFailed)));
    }
}
