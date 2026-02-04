# Faramesh Guard v1: Specification Documents

> **Version**: 1.0.0
> **Status**: Production Ready

This directory contains the formal specifications for Faramesh Guard v1.

---

## Document Index

| Document | Description | Status |
|----------|-------------|--------|
| [threat-model.md](threat-model.md) | Security guarantees, threat boundaries, and attack mitigations | ✅ Complete |
| [CAR-schema.json](CAR-schema.json) | JSON Schema for Canonical Action Representation | ✅ Complete |
| [aab-contract.md](aab-contract.md) | Agent-Authority Bridge API contract | ✅ Complete |
| [canonicalization.md](canonicalization.md) | CAR canonicalization algorithm (CRITICAL) | ✅ Complete |
| [openclaw-tool-mapping.md](openclaw-tool-mapping.md) | Tool → CAR field mapping | ✅ Complete |
| [policy-modes.md](policy-modes.md) | Policy mode definitions | ✅ Complete |
| [permit-artifacts.md](permit-artifacts.md) | Permit structure and validation | ✅ Complete |
| [versioning.md](versioning.md) | Version compatibility rules | ✅ Complete |

---

## Quick Reference

### Security Guarantees

1. **G1: Non-Circumventable Execution** - No tool executes without Guard evaluation
2. **G2: Tamper-Evident Audit** - Any log modification is detectable
3. **G3: Deterministic Identity** - Same action = same CAR hash
4. **G4: Fail-Closed** - Guard failure blocks execution
5. **G5: Human Authority** - Humans retain ultimate control
6. **G6: Policy Integrity** - Policy tampering is detected

### Architecture

```
┌─────────────────┐     ┌─────────────────┐     ┌─────────────────┐
│   AI Agent      │ ──► │  OpenClaw       │ ──► │  Guard Plugin   │
│  (Claude, etc)  │     │  Runtime        │     │  (Execution     │
│                 │     │                 │     │   Gate)         │
└─────────────────┘     └─────────────────┘     └────────┬────────┘
                                                         │
                                                         ▼
                                                ┌─────────────────┐
                                                │  Guard Daemon   │
                                                │  (localhost:    │
                                                │   8765)         │
                                                └────────┬────────┘
                                                         │
                        ┌────────────────────────────────┼────────────────────────────────┐
                        │                                │                                │
                        ▼                                ▼                                ▼
               ┌─────────────────┐              ┌─────────────────┐              ┌─────────────────┐
               │  Policy Engine  │              │  Behavioral     │              │  Audit Log      │
               │  (allow/deny/   │              │  Anomaly        │              │  (Merkle        │
               │   approval)     │              │  Detector       │              │   chain)        │
               └─────────────────┘              └─────────────────┘              └─────────────────┘
```

### Decision Flow

```
1. Tool Invocation
   └─► Plugin intercepts
       └─► Extract CAR
           └─► Send to Guard Daemon
               └─► Policy Evaluation
                   └─► Behavioral Analysis
                       └─► Signal Fusion
                           └─► Decision (ALLOW/DENY/PENDING)
                               └─► Audit Log
                                   └─► Return Permit (if allowed)
```

### Key APIs

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/v1/guard/execute` | POST | Main authorization endpoint |
| `/api/v1/guard/pending/{id}` | GET | Poll pending action |
| `/api/v1/guard/pending/{id}/approve` | POST | Approve action |
| `/api/v1/guard/pending/{id}/deny` | POST | Deny action |
| `/api/v1/guard/health` | GET | Detailed health check |
| `/api/v1/guard/integrity` | GET | Policy integrity |
| `/api/v1/guard/stats` | GET | Statistics |
| `/api/v1/guard/audit` | GET | Audit log |
| `/api/v1/guard/policy` | GET | Current policy |

---

## Implementation Status

### Meta-Layers from guard-plan-v1.md

| Layer | Description | Status |
|-------|-------------|--------|
| 1 | Non-Bypassable Enforcement | ✅ 34/34 tests pass |
| 2 | Behavioral Anomaly Detection | ✅ Implemented |
| 3 | State-Aware Context Model | ✅ Implemented |
| 4 | Cold-Start Policy Templates | ✅ Implemented |
| 5 | Human Authority Semantics | ✅ Implemented |
| 6 | Adversarial Robustness | ✅ Implemented |
| 7 | Guard Self-Integrity | ✅ Implemented |
| 8 | Formal Threat Model | ✅ Documented |

### Core Components

| Component | Location | Status |
|-----------|----------|--------|
| Daemon | `daemon/main.py` | ✅ Production |
| Policy Engine | `daemon/service/policy/` | ✅ Production |
| Behavioral Anomaly | `daemon/service/behavioral_anomaly.py` | ✅ Production |
| Signal Fusion | `daemon/service/signal_fusion.py` | ✅ Production |
| Audit Log | `daemon/service/audit/` | ✅ Production |
| Adversarial Detector | `daemon/service/adversarial_detector.py` | ✅ Production |
| Pending Actions | `daemon/service/pending_actions.py` | ✅ Production |
| Permit System | `daemon/core/permit.py` | ✅ Production |
| CAR Hash | `daemon/core/car_hash.py` | ✅ Production |
| Integrity Monitor | `daemon/service/integrity/` | ✅ Production |
| Auth Module | `daemon/service/auth/` | ✅ Production |

---

## For Developers

### Running Tests

```bash
cd faramesh-guard/daemon
./venv/bin/pytest tests/test_invariants.py -v
```

### Starting Daemon

```bash
cd faramesh-guard/daemon
./venv/bin/python -c "
import sys
sys.path.insert(0, '.')
import uvicorn
uvicorn.run('main:app', host='127.0.0.1', port=8765)
"
```

### Checking Health

```bash
curl http://127.0.0.1:8765/api/v1/guard/health | jq
```

---

## For Security Reviewers

Key documents to review:
1. **threat-model.md** - Security guarantees and threat boundaries
2. **permit-artifacts.md** - Cryptographic signing and validation
3. **canonicalization.md** - Deterministic hashing for audit integrity

Key code to review:
1. `daemon/main.py` - Decision pipeline
2. `daemon/core/permit.py` - Permit minting and validation
3. `daemon/service/audit/merkle_chain.py` - Tamper-evident logging
4. `daemon/service/integrity/` - Self-integrity monitoring

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024 | Initial specification release |

---

*Last Updated: 2024*
