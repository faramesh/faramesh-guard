# Faramesh Guard v1: Permit Artifacts

> **Version**: 1.0.0
> **Status**: Production Ready

This document specifies the permit structure, caveats, validation rules, and signature scheme for Guard v1.

---

## Overview

Permits are cryptographically signed authorization tokens that grant permission to execute specific actions. They implement a **capability-based** authorization model.

```
┌─────────────────────────────────────────────────────────┐
│                      PERMIT                             │
├─────────────────────────────────────────────────────────┤
│  permit_id:  Unique identifier                          │
│  tool:       Authorized tool name                       │
│  car_hash:   Hash of authorized CAR                     │
│  issued_at:  When permit was created                    │
│  caveats:    Constraints on permit use                  │
│  signature:  HMAC-SHA256 of permit data                 │
└─────────────────────────────────────────────────────────┘
```

---

## Permit Structure

### Complete Permit Object

```json
{
  "permit_id": "pmt_a1b2c3d4e5f6",
  "tool": "bash",
  "car_hash": "sha256:abc123def456789...",
  "issued_at": "2026-02-03T12:30:45.123Z",
  "caveats": {
    "expires_at": "2026-02-03T12:31:15.123Z",
    "max_uses": 1,
    "use_count": 0,
    "allowed_commands": ["ls -la", "pwd"],
    "allowed_paths": ["./", "/tmp/**"],
    "scope_limit": "workspace"
  },
  "signature": "base64_encoded_hmac_sha256"
}
```

### Field Specifications

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `permit_id` | string | Yes | Unique permit identifier (format: `pmt_<uuid>`) |
| `tool` | string | Yes | Tool this permit authorizes |
| `car_hash` | string | Yes | SHA-256 hash of the authorized CAR |
| `issued_at` | ISO 8601 | Yes | Timestamp when permit was issued |
| `caveats` | object | Yes | Constraints on permit use |
| `signature` | string | Yes | HMAC-SHA256 signature (base64) |

---

## Caveats

Caveats are constraints that limit permit use. A permit is only valid if ALL caveats are satisfied.

### Time Caveats

```json
{
  "expires_at": "2026-02-03T12:31:15.123Z",
  "not_before": "2026-02-03T12:30:45.123Z"
}
```

| Caveat | Description | Default |
|--------|-------------|---------|
| `expires_at` | Permit invalid after this time | 30 seconds from issue |
| `not_before` | Permit invalid before this time | Issue time |

### Use Count Caveats

```json
{
  "max_uses": 1,
  "use_count": 0
}
```

| Caveat | Description | Default |
|--------|-------------|---------|
| `max_uses` | Maximum number of permit uses | 1 |
| `use_count` | Current use count | 0 |

### Scope Caveats

```json
{
  "allowed_commands": ["ls -la", "pwd"],
  "allowed_paths": ["./", "/tmp/**"],
  "denied_paths": ["/etc/**", "/root/**"],
  "scope_limit": "workspace"
}
```

| Caveat | Description | Default |
|--------|-------------|---------|
| `allowed_commands` | Exact commands permitted | Extracted from CAR |
| `allowed_paths` | Path glob patterns allowed | Workspace only |
| `denied_paths` | Path glob patterns denied | System paths |
| `scope_limit` | Maximum scope (workspace, user, system) | workspace |

### Context Caveats

```json
{
  "agent_id": "claude-3-opus",
  "session_id": "sess_abc123",
  "workspace_id": "proj_xyz789"
}
```

| Caveat | Description | Default |
|--------|-------------|---------|
| `agent_id` | Required agent ID | Requesting agent |
| `session_id` | Required session ID | Current session |
| `workspace_id` | Required workspace ID | Current workspace |

---

## Signature Scheme

### Signature Algorithm

Permits use **HMAC-SHA256** with a locally-generated secret key.

```python
import hmac
import hashlib
import base64
import json

def sign_permit(permit: dict, secret_key: bytes) -> str:
    """Generate HMAC-SHA256 signature for permit."""
    # Remove existing signature if present
    permit_copy = {k: v for k, v in permit.items() if k != 'signature'}

    # Canonical JSON (sorted keys, no whitespace)
    canonical = json.dumps(permit_copy, sort_keys=True, separators=(',', ':'))

    # HMAC-SHA256
    signature = hmac.new(
        secret_key,
        canonical.encode('utf-8'),
        hashlib.sha256
    ).digest()

    return base64.b64encode(signature).decode('ascii')
```

### Verification

```python
def verify_permit(permit: dict, secret_key: bytes) -> bool:
    """Verify permit signature is valid."""
    expected_signature = sign_permit(permit, secret_key)
    actual_signature = permit.get('signature', '')

    # Constant-time comparison to prevent timing attacks
    return hmac.compare_digest(expected_signature, actual_signature)
```

### Key Management

- **Key generation**: 256-bit random key generated on first run
- **Key storage**: `~/.faramesh-guard/secret.key` (mode 0600)
- **Key rotation**: Manual only in v1 (automatic in v2)

---

## Validation Rules

### Complete Validation Flow

```python
def validate_permit(permit: dict, car: dict, context: dict) -> ValidationResult:
    """Validate permit for use with given CAR and context."""

    # 1. Signature validation
    if not verify_permit(permit, secret_key):
        return ValidationResult.INVALID_SIGNATURE

    # 2. CAR hash match
    if permit['car_hash'] != car['car_hash']:
        return ValidationResult.CAR_MISMATCH

    # 3. Tool match
    if permit['tool'] != car['tool']:
        return ValidationResult.TOOL_MISMATCH

    # 4. Time validation
    now = datetime.utcnow()
    caveats = permit['caveats']

    if 'expires_at' in caveats:
        if now > parse_iso(caveats['expires_at']):
            return ValidationResult.EXPIRED

    if 'not_before' in caveats:
        if now < parse_iso(caveats['not_before']):
            return ValidationResult.NOT_YET_VALID

    # 5. Use count validation
    if 'max_uses' in caveats:
        if caveats.get('use_count', 0) >= caveats['max_uses']:
            return ValidationResult.EXHAUSTED

    # 6. Command validation
    if 'allowed_commands' in caveats:
        command = extract_command(car)
        if command not in caveats['allowed_commands']:
            return ValidationResult.COMMAND_NOT_ALLOWED

    # 7. Path validation
    target = car.get('target', '')

    if 'denied_paths' in caveats:
        for pattern in caveats['denied_paths']:
            if glob_match(target, pattern):
                return ValidationResult.PATH_DENIED

    if 'allowed_paths' in caveats:
        allowed = any(glob_match(target, p) for p in caveats['allowed_paths'])
        if not allowed:
            return ValidationResult.PATH_NOT_ALLOWED

    # 8. Context validation
    if 'agent_id' in caveats:
        if context.get('agent_id') != caveats['agent_id']:
            return ValidationResult.AGENT_MISMATCH

    if 'session_id' in caveats:
        if context.get('session_id') != caveats['session_id']:
            return ValidationResult.SESSION_MISMATCH

    return ValidationResult.VALID
```

### Validation Results

| Result | Code | Description |
|--------|------|-------------|
| `VALID` | 200 | Permit is valid for use |
| `INVALID_SIGNATURE` | 401 | Signature verification failed |
| `EXPIRED` | 403 | Permit has expired |
| `NOT_YET_VALID` | 403 | Permit not yet valid |
| `EXHAUSTED` | 403 | Max uses reached |
| `CAR_MISMATCH` | 400 | CAR hash doesn't match |
| `TOOL_MISMATCH` | 400 | Tool doesn't match |
| `COMMAND_NOT_ALLOWED` | 403 | Command not in allow list |
| `PATH_NOT_ALLOWED` | 403 | Path not in allow list |
| `PATH_DENIED` | 403 | Path in deny list |
| `AGENT_MISMATCH` | 403 | Agent ID doesn't match |
| `SESSION_MISMATCH` | 403 | Session ID doesn't match |

---

## Permit Lifecycle

```
┌─────────────────────────────────────────────────────────┐
│                  PERMIT LIFECYCLE                       │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. CREATION                                            │
│     └─► Guard mints permit on ALLOW decision            │
│                                                         │
│  2. DELIVERY                                            │
│     └─► Permit returned in API response                 │
│                                                         │
│  3. STORAGE                                             │
│     └─► Plugin caches permit locally                    │
│                                                         │
│  4. PRESENTATION                                        │
│     └─► Plugin presents permit before execution         │
│                                                         │
│  5. VALIDATION                                          │
│     └─► Guard validates permit and caveats              │
│                                                         │
│  6. USE                                                 │
│     └─► Permit use_count incremented                    │
│                                                         │
│  7. INVALIDATION                                        │
│     └─► Permit invalid after expiry or max_uses         │
│                                                         │
│  8. AUDIT                                               │
│     └─► Permit use recorded in audit log                │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Security Properties

### 1. Unforgeability

Permits cannot be forged without the secret key:
- HMAC-SHA256 provides 256-bit security
- Constant-time comparison prevents timing attacks

### 2. Tamper-Evidence

Any modification invalidates the signature:
- All fields are included in signature
- Canonical serialization prevents reordering attacks

### 3. Replay Protection

Permits cannot be reused:
- Single-use default (`max_uses: 1`)
- Use count tracked and incremented
- CAR hash prevents reuse across different actions

### 4. Time-Bound

Permits have limited validity:
- Default 30-second TTL
- `expires_at` enforced strictly

### 5. Scope-Limited

Permits are constrained to specific operations:
- Exact command matching
- Path restrictions
- Agent/session binding

---

## Examples

### Example 1: Simple Allow

```json
{
  "permit_id": "pmt_12345678",
  "tool": "bash",
  "car_hash": "sha256:abc123...",
  "issued_at": "2026-02-03T12:30:45.123Z",
  "caveats": {
    "expires_at": "2026-02-03T12:31:15.123Z",
    "max_uses": 1,
    "use_count": 0
  },
  "signature": "dGhpcyBpcyBhIHNhbXBsZSBzaWduYXR1cmU="
}
```

### Example 2: Scoped Permit

```json
{
  "permit_id": "pmt_87654321",
  "tool": "fs",
  "car_hash": "sha256:def456...",
  "issued_at": "2026-02-03T12:30:45.123Z",
  "caveats": {
    "expires_at": "2026-02-03T12:35:45.123Z",
    "max_uses": 10,
    "use_count": 0,
    "allowed_paths": ["./src/**", "./tests/**"],
    "denied_paths": ["./.env", "./secrets/**"],
    "scope_limit": "workspace"
  },
  "signature": "YW5vdGhlciBzYW1wbGUgc2lnbmF0dXJl"
}
```

---

## Future Extensions (v2+)

- **Delegatable permits**: Pass permits to sub-agents
- **Attenuation**: Reduce permit scope without re-signing
- **Revocation**: Central revocation list
- **HSM support**: Hardware security module for key storage

---

*Last Updated: 2024*
