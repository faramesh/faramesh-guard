//! Faramesh Guard Security Kernel
//!
//! This is the Trusted Computing Base (TCB) for Guard.
//! All security-critical operations happen here:
//! - Permit validation (HMAC verification)
//! - CAR hash canonicalization
//! - Fast decision cache (lock-free)
//! - Replay detection ring buffer
//!
//! This core is exposed via:
//! - IPC server (Unix socket / named pipe)
//! - Python FFI bindings (optional)

pub mod car;
pub mod cache;
pub mod permit;
pub mod replay;
pub mod ipc;
pub mod error;

pub use car::CarHasher;
pub use cache::DecisionCache;
pub use permit::PermitVerifier;
pub use replay::ReplayDetector;
pub use error::GuardError;

/// Guard core version
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

/// Default IPC socket path
#[cfg(unix)]
pub const DEFAULT_SOCKET_PATH: &str = "/var/run/faramesh-guard/core.sock";

#[cfg(windows)]
pub const DEFAULT_PIPE_NAME: &str = r"\\.\pipe\faramesh-guard-core";

/// Result type for guard operations
pub type Result<T> = std::result::Result<T, GuardError>;

/// Decision from the security kernel
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Decision {
    Allow,
    Deny,
    Pending,
}

impl std::fmt::Display for Decision {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Decision::Allow => write!(f, "allow"),
            Decision::Deny => write!(f, "deny"),
            Decision::Pending => write!(f, "pending"),
        }
    }
}

/// Cached decision with metadata
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct CachedDecision {
    pub decision: Decision,
    pub confidence: f64,
    pub expires_at: i64,
    pub car_hash: String,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_display() {
        assert_eq!(Decision::Allow.to_string(), "allow");
        assert_eq!(Decision::Deny.to_string(), "deny");
        assert_eq!(Decision::Pending.to_string(), "pending");
    }
}
