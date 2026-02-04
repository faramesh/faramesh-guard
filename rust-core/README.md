# Faramesh Guard - Rust Security Kernel

The security-critical hot path components of Guard, implemented in Rust.

## Architecture

```
Rust Core (Security Kernel) - Trusted Computing Base
 ├─ Permit validation (HMAC-SHA256)
 ├─ CAR canonicalization (deterministic hashing)
 ├─ Fast decision cache (lock-free DashMap)
 ├─ Replay detection (ring buffer)
 └─ IPC server (Unix socket)

Python Daemon (Control Plane)
 ├─ Policy evaluation
 ├─ ML / anomaly logic
 ├─ Approval flow
 ├─ Audit log
 ├─ State tracking
 └─ API
```

## Why Rust for the Security Kernel?

1. **Memory Safety** - No segfaults, no buffer overflows
2. **Tamper Resistance** - Harder to exploit than Python
3. **Performance** - Lock-free data structures, zero-cost abstractions
4. **Trust Surface** - Static binary, smaller attack surface
5. **Crypto Performance** - Fast HMAC verification

## Components

### CAR Hasher (`src/car.rs`)
Deterministic canonical hashing of Action Requests.
- JSON key ordering normalization
- Float precision handling
- UTF-8 normalization
- SHA-256 hashing

### Permit Verifier (`src/permit.rs`)
HMAC-SHA256 signature verification for permits.
- Expiration checking
- Nonce binding
- Action binding (CAR hash)

### Decision Cache (`src/cache.rs`)
Lock-free concurrent cache using DashMap.
- O(1) lookups
- Sharded writes
- TTL-based expiration
- LRU eviction

### Replay Detector (`src/replay.rs`)
Ring buffer for replay attack prevention.
- Bounded memory usage
- O(1) lookups via hash set
- Automatic cleanup

### IPC Server (`src/ipc.rs`)
JSON-RPC 2.0 over Unix socket.
- Async Tokio runtime
- Connection multiplexing
- Composable operations

## Building

```bash
# Install Rust
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

# Build release binary
cargo build --release

# Run tests
cargo test

# Run benchmarks
cargo bench
```

## Running

```bash
# Set environment variables
export GUARD_SOCKET_PATH=/var/run/faramesh-guard/core.sock
export GUARD_HMAC_SECRET=$(openssl rand -base64 32)

# Run the IPC server
./target/release/guard-core-ipc
```

## Python Integration

The Python daemon connects to the Rust core via the `service.core.rust_client` module:

```python
from service.core import get_rust_core_client, Decision

async def check_action(car_data: dict):
    client = get_rust_core_client()
    await client.connect()

    result = await client.gate_check(car_data)

    if result.decision == Decision.ALLOW:
        print(f"Allowed from {result.source}")
    elif result.decision == Decision.PENDING:
        print("Awaiting approval")
```

## IPC Protocol

JSON-RPC 2.0 over newline-delimited JSON.

### Methods

| Method | Description |
|--------|-------------|
| `hash_car` | Compute CAR hash |
| `cache_get` | Get cached decision |
| `cache_put` | Cache a decision |
| `cache_invalidate` | Invalidate cache entry |
| `cache_stats` | Get cache statistics |
| `verify_permit` | Verify permit signature |
| `create_permit` | Create signed permit |
| `check_replay` | Check for replay attack |
| `replay_stats` | Get replay statistics |
| `gate_check` | Composite security check |
| `ping` | Health check |
| `version` | Get version |

### Example

```json
// Request
{"jsonrpc":"2.0","id":1,"method":"gate_check","params":{"car":{"action_type":"file_read","resource":"/etc/passwd","agent_id":"agent1"}}}

// Response
{"jsonrpc":"2.0","id":1,"result":{"decision":"pending","confidence":0.0,"car_hash":"sha256:abc123...","source":"none"}}
```

## Performance Targets

| Operation | Target | Typical |
|-----------|--------|---------|
| CAR hash | <50 µs | ~10 µs |
| Cache lookup | <10 µs | ~1 µs |
| Permit verify | <100 µs | ~30 µs |
| Replay check | <10 µs | ~1 µs |
| Full gate check | <200 µs | ~50 µs |

## Security Considerations

1. **HMAC Secret** - Must be cryptographically random, stored securely
2. **Socket Permissions** - Unix socket should have restricted permissions
3. **Replay Window** - Configure based on expected throughput
4. **Cache TTL** - Balance between performance and freshness

## Development

```bash
# Format code
cargo fmt

# Lint
cargo clippy

# Generate docs
cargo doc --open

# Watch mode
cargo watch -x check
```

## License

MIT
