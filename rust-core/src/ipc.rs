//! IPC Server and Protocol
//!
//! This module provides the IPC interface for the Python daemon.
//! Uses Unix sockets on *nix and named pipes on Windows.
//!
//! Protocol: JSON-RPC 2.0 over newline-delimited JSON

use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use crate::{
    car::{CarHasher, CarRequest},
    cache::DecisionCache,
    permit::PermitVerifier,
    replay::ReplayDetector,
    Decision, GuardError, Result,
};

/// IPC request (JSON-RPC 2.0)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcRequest {
    pub jsonrpc: String,
    pub id: Option<u64>,
    pub method: String,
    #[serde(default)]
    pub params: serde_json::Value,
}

/// IPC response (JSON-RPC 2.0)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcResponse {
    pub jsonrpc: String,
    pub id: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<IpcError>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IpcError {
    pub code: i32,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Value>,
}

impl IpcResponse {
    pub fn success(id: Option<u64>, result: serde_json::Value) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: Some(result),
            error: None,
        }
    }

    pub fn error(id: Option<u64>, code: i32, message: impl Into<String>) -> Self {
        Self {
            jsonrpc: "2.0".to_string(),
            id,
            result: None,
            error: Some(IpcError {
                code,
                message: message.into(),
                data: None,
            }),
        }
    }
}

/// Guard Core - the security kernel
pub struct GuardCore {
    pub car_hasher: CarHasher,
    pub cache: DecisionCache,
    pub permit_verifier: PermitVerifier,
    pub replay_detector: ReplayDetector,
}

impl GuardCore {
    /// Create a new guard core
    pub fn new(hmac_secret: &[u8]) -> Self {
        Self {
            car_hasher: CarHasher::new(),
            cache: DecisionCache::default(),
            permit_verifier: PermitVerifier::new(hmac_secret),
            replay_detector: ReplayDetector::default(),
        }
    }

    /// Handle an IPC request
    pub async fn handle_request(&self, request: IpcRequest) -> IpcResponse {
        match request.method.as_str() {
            // CAR hashing
            "hash_car" => self.handle_hash_car(request.id, request.params),

            // Cache operations
            "cache_get" => self.handle_cache_get(request.id, request.params),
            "cache_put" => self.handle_cache_put(request.id, request.params),
            "cache_invalidate" => self.handle_cache_invalidate(request.id, request.params),
            "cache_stats" => self.handle_cache_stats(request.id),

            // Permit verification
            "verify_permit" => self.handle_verify_permit(request.id, request.params),
            "create_permit" => self.handle_create_permit(request.id, request.params),

            // Replay detection
            "check_replay" => self.handle_check_replay(request.id, request.params),
            "replay_stats" => self.handle_replay_stats(request.id),

            // Composite operations
            "gate_check" => self.handle_gate_check(request.id, request.params).await,

            // Health
            "ping" => IpcResponse::success(request.id, serde_json::json!("pong")),
            "version" => IpcResponse::success(request.id, serde_json::json!(crate::VERSION)),

            _ => IpcResponse::error(request.id, -32601, "Method not found"),
        }
    }

    fn handle_hash_car(&self, id: Option<u64>, params: serde_json::Value) -> IpcResponse {
        match self.car_hasher.hash_value(&params) {
            Ok(hash) => IpcResponse::success(id, serde_json::json!({ "hash": hash })),
            Err(e) => IpcResponse::error(id, -32000, e.to_string()),
        }
    }

    fn handle_cache_get(&self, id: Option<u64>, params: serde_json::Value) -> IpcResponse {
        let car_hash = match params.get("car_hash").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => return IpcResponse::error(id, -32602, "Missing car_hash parameter"),
        };

        match self.cache.get(car_hash) {
            Some(cached) => IpcResponse::success(id, serde_json::to_value(cached).unwrap()),
            None => IpcResponse::success(id, serde_json::json!(null)),
        }
    }

    fn handle_cache_put(&self, id: Option<u64>, params: serde_json::Value) -> IpcResponse {
        let car_hash = match params.get("car_hash").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => return IpcResponse::error(id, -32602, "Missing car_hash parameter"),
        };

        let decision = match params.get("decision").and_then(|v| v.as_str()) {
            Some("allow") => Decision::Allow,
            Some("deny") => Decision::Deny,
            Some("pending") => Decision::Pending,
            _ => return IpcResponse::error(id, -32602, "Invalid decision parameter"),
        };

        let confidence = params.get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(1.0);

        let ttl = params.get("ttl").and_then(|v| v.as_i64());

        self.cache.put(car_hash, decision, confidence, ttl);
        IpcResponse::success(id, serde_json::json!({ "ok": true }))
    }

    fn handle_cache_invalidate(&self, id: Option<u64>, params: serde_json::Value) -> IpcResponse {
        let car_hash = match params.get("car_hash").and_then(|v| v.as_str()) {
            Some(h) => h,
            None => return IpcResponse::error(id, -32602, "Missing car_hash parameter"),
        };

        let removed = self.cache.invalidate(car_hash);
        IpcResponse::success(id, serde_json::json!({ "removed": removed }))
    }

    fn handle_cache_stats(&self, id: Option<u64>) -> IpcResponse {
        let stats = self.cache.stats();
        IpcResponse::success(id, serde_json::to_value(stats).unwrap())
    }

    fn handle_verify_permit(&self, id: Option<u64>, params: serde_json::Value) -> IpcResponse {
        let permit: crate::permit::Permit = match serde_json::from_value(params) {
            Ok(p) => p,
            Err(e) => return IpcResponse::error(id, -32602, format!("Invalid permit: {}", e)),
        };

        // Check replay first
        if let Err(e) = self.replay_detector.check_and_register(&permit.nonce) {
            return IpcResponse::error(id, -32003, e.to_string());
        }

        match self.permit_verifier.verify(&permit) {
            Ok(result) => IpcResponse::success(id, serde_json::to_value(result).unwrap()),
            Err(e) => IpcResponse::error(id, -32001, e.to_string()),
        }
    }

    fn handle_create_permit(&self, id: Option<u64>, params: serde_json::Value) -> IpcResponse {
        let car_hash = match params.get("car_hash").and_then(|v| v.as_str()) {
            Some(h) => h.to_string(),
            None => return IpcResponse::error(id, -32602, "Missing car_hash parameter"),
        };

        let decision = match params.get("decision").and_then(|v| v.as_str()) {
            Some("allow") => Decision::Allow,
            Some("deny") => Decision::Deny,
            _ => return IpcResponse::error(id, -32602, "Invalid decision parameter"),
        };

        let confidence = params.get("confidence")
            .and_then(|v| v.as_f64())
            .unwrap_or(1.0);

        let issued_by = params.get("issued_by")
            .and_then(|v| v.as_str())
            .unwrap_or("guard")
            .to_string();

        let ttl = params.get("ttl")
            .and_then(|v| v.as_i64())
            .unwrap_or(300);

        let permit = self.permit_verifier.create_permit(
            car_hash,
            decision,
            confidence,
            issued_by,
            ttl,
        );

        IpcResponse::success(id, serde_json::to_value(permit).unwrap())
    }

    fn handle_check_replay(&self, id: Option<u64>, params: serde_json::Value) -> IpcResponse {
        let nonce = match params.get("nonce").and_then(|v| v.as_str()) {
            Some(n) => n,
            None => return IpcResponse::error(id, -32602, "Missing nonce parameter"),
        };

        match self.replay_detector.check_and_register(nonce) {
            Ok(_) => IpcResponse::success(id, serde_json::json!({ "replay": false })),
            Err(_) => IpcResponse::success(id, serde_json::json!({ "replay": true })),
        }
    }

    fn handle_replay_stats(&self, id: Option<u64>) -> IpcResponse {
        let stats = self.replay_detector.stats();
        IpcResponse::success(id, serde_json::to_value(stats).unwrap())
    }

    /// Composite gate check - the main security chokepoint
    async fn handle_gate_check(&self, id: Option<u64>, params: serde_json::Value) -> IpcResponse {
        // 1. Hash the CAR
        let car_hash = match self.car_hasher.hash_value(&params.get("car").unwrap_or(&params)) {
            Ok(h) => h,
            Err(e) => return IpcResponse::error(id, -32000, format!("CAR hash failed: {}", e)),
        };

        // 2. Check cache first (fast path)
        if let Some(cached) = self.cache.get(&car_hash) {
            return IpcResponse::success(id, serde_json::json!({
                "decision": cached.decision,
                "confidence": cached.confidence,
                "car_hash": car_hash,
                "source": "cache"
            }));
        }

        // 3. If permit provided, verify it
        if let Some(permit_value) = params.get("permit") {
            let permit: crate::permit::Permit = match serde_json::from_value(permit_value.clone()) {
                Ok(p) => p,
                Err(e) => return IpcResponse::error(id, -32602, format!("Invalid permit: {}", e)),
            };

            // Check replay
            if let Err(e) = self.replay_detector.check_and_register(&permit.nonce) {
                return IpcResponse::error(id, -32003, e.to_string());
            }

            // Verify permit matches this CAR
            if permit.car_hash != car_hash {
                return IpcResponse::error(id, -32004, "Permit CAR hash mismatch");
            }

            // Verify signature
            match self.permit_verifier.verify(&permit) {
                Ok(result) => {
                    // Cache the decision
                    self.cache.put(&car_hash, result.decision, result.confidence, Some(result.remaining_ttl));

                    return IpcResponse::success(id, serde_json::json!({
                        "decision": result.decision,
                        "confidence": result.confidence,
                        "car_hash": car_hash,
                        "source": "permit"
                    }));
                }
                Err(e) => return IpcResponse::error(id, -32001, e.to_string()),
            }
        }

        // 4. No cached decision, no permit - return pending
        IpcResponse::success(id, serde_json::json!({
            "decision": Decision::Pending,
            "confidence": 0.0,
            "car_hash": car_hash,
            "source": "none"
        }))
    }
}

/// IPC Server configuration
pub struct IpcServerConfig {
    pub socket_path: String,
    pub hmac_secret: Vec<u8>,
}

impl Default for IpcServerConfig {
    fn default() -> Self {
        Self {
            socket_path: crate::DEFAULT_SOCKET_PATH.to_string(),
            hmac_secret: b"default-secret-change-in-production".to_vec(),
        }
    }
}

/// Run the IPC server
#[cfg(unix)]
pub async fn run_server(config: IpcServerConfig) -> Result<()> {
    use tokio::net::UnixListener;
    use std::path::Path;

    let socket_path = Path::new(&config.socket_path);

    // Remove old socket if exists
    if socket_path.exists() {
        std::fs::remove_file(socket_path)?;
    }

    // Create parent directory
    if let Some(parent) = socket_path.parent() {
        std::fs::create_dir_all(parent)?;
    }

    let listener = UnixListener::bind(socket_path)?;
    let core = Arc::new(GuardCore::new(&config.hmac_secret));

    tracing::info!("Guard Core IPC server listening on {}", config.socket_path);

    loop {
        match listener.accept().await {
            Ok((stream, _addr)) => {
                let core = Arc::clone(&core);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, core).await {
                        tracing::error!("Connection error: {}", e);
                    }
                });
            }
            Err(e) => {
                tracing::error!("Accept error: {}", e);
            }
        }
    }
}

#[cfg(unix)]
async fn handle_connection(
    stream: tokio::net::UnixStream,
    core: Arc<GuardCore>,
) -> Result<()> {
    let (reader, mut writer) = stream.into_split();
    let mut reader = BufReader::new(reader);
    let mut line = String::new();

    loop {
        line.clear();
        let n = reader.read_line(&mut line).await?;
        if n == 0 {
            break; // EOF
        }

        // Parse request
        let request: IpcRequest = match serde_json::from_str(&line) {
            Ok(r) => r,
            Err(e) => {
                let response = IpcResponse::error(None, -32700, format!("Parse error: {}", e));
                let response_json = serde_json::to_string(&response)?;
                writer.write_all(response_json.as_bytes()).await?;
                writer.write_all(b"\n").await?;
                continue;
            }
        };

        // Handle request
        let response = core.handle_request(request).await;

        // Send response
        let response_json = serde_json::to_string(&response)?;
        writer.write_all(response_json.as_bytes()).await?;
        writer.write_all(b"\n").await?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_core() -> GuardCore {
        GuardCore::new(b"test-secret-key-for-testing-1234")
    }

    #[tokio::test]
    async fn test_ping() {
        let core = test_core();
        let request = IpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(1),
            method: "ping".to_string(),
            params: serde_json::Value::Null,
        };

        let response = core.handle_request(request).await;
        assert!(response.result.is_some());
        assert_eq!(response.result.unwrap(), "pong");
    }

    #[tokio::test]
    async fn test_hash_car() {
        let core = test_core();
        let request = IpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(1),
            method: "hash_car".to_string(),
            params: serde_json::json!({
                "action_type": "file_read",
                "resource": "/tmp/test.txt",
                "agent_id": "agent1"
            }),
        };

        let response = core.handle_request(request).await;
        assert!(response.result.is_some());
        let result = response.result.unwrap();
        assert!(result.get("hash").unwrap().as_str().unwrap().starts_with("sha256:"));
    }

    #[tokio::test]
    async fn test_cache_roundtrip() {
        let core = test_core();

        // Put
        let put_request = IpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(1),
            method: "cache_put".to_string(),
            params: serde_json::json!({
                "car_hash": "sha256:test123",
                "decision": "allow",
                "confidence": 0.95
            }),
        };
        let response = core.handle_request(put_request).await;
        assert!(response.result.is_some());

        // Get
        let get_request = IpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(2),
            method: "cache_get".to_string(),
            params: serde_json::json!({
                "car_hash": "sha256:test123"
            }),
        };
        let response = core.handle_request(get_request).await;
        assert!(response.result.is_some());
        let cached = response.result.unwrap();
        assert_eq!(cached.get("decision").unwrap(), "allow");
    }

    #[tokio::test]
    async fn test_gate_check_pending() {
        let core = test_core();
        let request = IpcRequest {
            jsonrpc: "2.0".to_string(),
            id: Some(1),
            method: "gate_check".to_string(),
            params: serde_json::json!({
                "car": {
                    "action_type": "shell_execute",
                    "resource": "rm -rf /",
                    "agent_id": "agent1"
                }
            }),
        };

        let response = core.handle_request(request).await;
        assert!(response.result.is_some());
        let result = response.result.unwrap();
        assert_eq!(result.get("decision").unwrap(), "pending");
        assert_eq!(result.get("source").unwrap(), "none");
    }
}
