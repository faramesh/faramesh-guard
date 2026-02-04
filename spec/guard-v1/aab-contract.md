# Faramesh Guard v1: AAB (Agent-Authority Bridge) Contract

> **Version**: 1.0.0
> **Status**: Production Ready

This document defines the API contract between the OpenClaw Plugin and the Guard Daemon.

---

## Overview

The AAB contract defines how the execution gate (plugin) communicates with the policy enforcer (daemon). This is the critical path where every tool invocation is evaluated.

```
┌─────────────────────┐     HTTP/REST      ┌─────────────────────┐
│   OpenClaw Plugin   │ ◄──────────────────► │   Guard Daemon     │
│  (Execution Gate)   │   /api/v1/guard/*  │  (Policy Enforcer)  │
└─────────────────────┘                    └─────────────────────┘
```

---

## Endpoints

### POST /api/v1/guard/execute

Main authorization endpoint. Called by the plugin before every tool execution.

**Request**:
```http
POST /api/v1/guard/execute HTTP/1.1
Host: 127.0.0.1:8765
Content-Type: application/json

{
  "tool_name": "bash",
  "args": {
    "command": "rm -rf ./temp"
  },
  "agent_id": "claude-3-opus",
  "car_hash": "sha256:abc123def456...",
  "session_key": "sess_abc123"
}
```

**Response (ALLOW)**:
```json
{
  "decision": "ALLOW",
  "permit": {
    "permit_id": "pmt_abc123",
    "tool": "bash",
    "car_hash": "sha256:abc123def456...",
    "caveats": {
      "expires_at": "2026-02-03T13:00:00Z",
      "max_uses": 1,
      "allowed_commands": ["rm -rf ./temp"]
    },
    "signature": "base64_hmac_signature"
  },
  "audit_record_id": "aud_xyz789",
  "risk_level": "low",
  "reason": "safe_readonly_command"
}
```

**Response (DENY)**:
```json
{
  "decision": "DENY",
  "permit": null,
  "audit_record_id": "aud_xyz789",
  "risk_level": "critical",
  "reason": "blocked_by_policy: destructive command detected"
}
```

**Response (PENDING)**:
```json
{
  "decision": "PENDING",
  "permit": null,
  "action_id": "act_xyz789",
  "audit_record_id": "aud_xyz789",
  "risk_level": "medium",
  "reason": "require_approval: docker",
  "approval_url": "http://127.0.0.1:8765/api/v1/guard/pending/act_xyz789"
}
```

---

### GET /api/v1/guard/pending/{action_id}

Poll status of a pending action.

**Response (pending)**:
```json
{
  "action_id": "act_xyz789",
  "status": "pending",
  "tool_name": "bash",
  "args": {"command": "docker build ."},
  "risk_level": "medium",
  "created_at": "2026-02-03T12:30:00Z",
  "expires_at": "2026-02-03T12:35:00Z"
}
```

**Response (approved)**:
```json
{
  "action_id": "act_xyz789",
  "status": "approved",
  "permit": {
    "permit_id": "pmt_abc123",
    "tool": "bash",
    "car_hash": "sha256:abc123...",
    "caveats": {...},
    "signature": "base64..."
  },
  "approved_by": "user",
  "approved_at": "2026-02-03T12:31:00Z"
}
```

**Response (denied)**:
```json
{
  "action_id": "act_xyz789",
  "status": "denied",
  "denied_by": "user",
  "denied_at": "2026-02-03T12:31:00Z",
  "reason": "User rejected"
}
```

---

### POST /api/v1/guard/pending/{action_id}/approve

Approve a pending action (called by UI or CLI).

**Request**:
```http
POST /api/v1/guard/pending/act_xyz789/approve?reason=approved HTTP/1.1
```

**Response**:
```json
{
  "status": "approved",
  "action": {...},
  "permit": {...}
}
```

---

### POST /api/v1/guard/pending/{action_id}/deny

Deny a pending action.

**Request**:
```http
POST /api/v1/guard/pending/act_xyz789/deny?reason=rejected HTTP/1.1
```

**Response**:
```json
{
  "status": "denied",
  "action": {...}
}
```

---

## Decision Pipeline

```
┌─────────────────────────────────────────────────────────────────────┐
│                    DECISION PIPELINE                                │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  1. Receive Request                                                 │
│     └─► Parse tool_name, args, agent_id, car_hash                   │
│                                                                     │
│  2. Policy Evaluation                                               │
│     ├─► Check deny patterns (rm -rf, sudo, etc.)                    │
│     ├─► Check injection patterns (;, &&, |, $(), ``)                │
│     ├─► Check allow patterns (ls, pwd, echo, cat)                   │
│     └─► Check require_approval patterns (docker, pip, npm)          │
│                                                                     │
│  3. Behavioral Anomaly Detection                                    │
│     ├─► Rate spike detection                                        │
│     ├─► Replay variant detection                                    │
│     └─► Time-of-day anomaly                                         │
│                                                                     │
│  4. Adversarial Detection                                           │
│     ├─► Homoglyph detection                                         │
│     ├─► Unicode normalization                                       │
│     └─► Path traversal detection                                    │
│                                                                     │
│  5. Signal Fusion                                                   │
│     └─► Combine policy + behavioral + adversarial signals           │
│                                                                     │
│  6. Final Decision                                                  │
│     ├─► ALLOW → Mint permit, audit, return                          │
│     ├─► DENY  → Audit, return                                       │
│     └─► PENDING → Create pending action, await approval             │
│                                                                     │
│  7. Audit Log Append                                                │
│     └─► Hash-chained entry with decision and permit                 │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Permit Structure

Permits are cryptographically signed authorization tokens.

```json
{
  "permit_id": "pmt_abc123def456",
  "tool": "bash",
  "car_hash": "sha256:abc123def456...",
  "issued_at": "2026-02-03T12:30:45.123Z",
  "caveats": {
    "expires_at": "2026-02-03T12:31:15.123Z",
    "max_uses": 1,
    "allowed_commands": ["rm -rf ./temp"],
    "allowed_paths": ["./temp/**"],
    "use_count": 0
  },
  "signature": "base64_hmac_sha256_signature"
}
```

**Caveat Types**:
- `expires_at`: Permit expires after this time (default: 30s)
- `max_uses`: Maximum number of uses (default: 1)
- `allowed_commands`: Exact commands allowed
- `allowed_paths`: Path patterns allowed
- `use_count`: Current use count

---

## Error Codes

| Code | Meaning |
|------|---------|
| `POLICY_DENY` | Blocked by policy rule |
| `INJECTION_DETECTED` | Command injection attempt |
| `RATE_LIMIT` | Rate limit exceeded |
| `ANOMALY_DETECTED` | Behavioral anomaly |
| `PERMIT_EXPIRED` | Permit has expired |
| `PERMIT_EXHAUSTED` | Permit max uses reached |
| `PERMIT_INVALID` | Invalid permit signature |
| `GUARD_UNAVAILABLE` | Guard daemon unreachable |

---

## Plugin Behavior

### On ALLOW
1. Cache permit locally
2. Execute tool with permit
3. Invalidate permit after use

### On DENY
1. Log denial
2. Return error to agent
3. Do NOT execute tool

### On PENDING
1. Poll `/pending/{action_id}` every 1s
2. Timeout after 5 minutes
3. If approved: execute with permit
4. If denied: return error to agent

### On Guard Unavailable
1. **FAIL CLOSED**: Do not execute tool
2. Retry 3 times with backoff
3. If still unavailable: return error

---

## Security Considerations

1. **Local-only**: Guard listens on 127.0.0.1 only
2. **No external auth**: Local user is trusted
3. **Permit validation**: Always verify signature before use
4. **TTL enforcement**: Reject expired permits
5. **Single-use**: Permits are invalidated after use
6. **Audit trail**: Every decision is logged

---

## Version Compatibility

| Plugin Version | Daemon Version | Compatible |
|---------------|----------------|------------|
| 1.0.x | 1.0.x | ✅ |
| 1.0.x | 1.1.x | ✅ |
| 1.1.x | 1.0.x | ⚠️ May lack features |

---

*Last Updated: 2024*
