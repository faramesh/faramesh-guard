# TUF Key Management Policy
## Faramesh Guard - Security Infrastructure

### Overview

This document defines the key management policy for The Update Framework (TUF) used by Faramesh Guard to deliver secure updates to all Guard instances worldwide.

---

## Key Hierarchy

```
┌─────────────────────────────────────────────────────────────────┐
│                         ROOT KEY                                 │
│   Trust anchor. Signs all other role keys.                      │
│   🔒 OFFLINE ONLY - Air-gapped machine or HSM                   │
└─────────────────────┬───────────────────────────────────────────┘
                      │ Signs
        ┌─────────────┼─────────────┐
        ▼             ▼             ▼
┌───────────────┐ ┌───────────────┐ ┌───────────────┐
│  TARGETS KEY  │ │ SNAPSHOT KEY  │ │ TIMESTAMP KEY │
│ Signs targets │ │ Signs snapshot│ │ Signs timestamp│
│ (rules, models│ │ metadata      │ │ (freshness)   │
│ policies)     │ │               │ │               │
└───────────────┘ └───────────────┘ └───────────────┘
```

---

## Key Specifications

| Role | Algorithm | Storage | Threshold | Expiry |
|------|-----------|---------|-----------|--------|
| Root | Ed25519 | **Offline HSM / Air-gapped** | 1 | 1 year |
| Targets | Ed25519 | CI/CD Secrets (encrypted) | 1 | 90 days |
| Snapshot | Ed25519 | CI/CD Secrets (encrypted) | 1 | 30 days |
| Timestamp | Ed25519 | Worker Secrets | 1 | 1 day |

---

## Rotation Schedule

### Timestamp Key (Daily)
- **Frequency**: Automated, runs every 24 hours
- **Process**:
  1. CI job generates new timestamp.json
  2. Signs with current timestamp key
  3. Uploads to R2 bucket
- **Automation**: GitHub Actions cron job

### Snapshot Key (Monthly)
- **Frequency**: First Monday of each month
- **Process**:
  1. Generate new snapshot.json
  2. Sign with snapshot key
  3. Update timestamp.json
- **Owner**: Release Engineer

### Targets Key (Quarterly)
- **Frequency**: Every 3 months (Jan 1, Apr 1, Jul 1, Oct 1)
- **Process**:
  1. Notify security team
  2. Rotate key in CI/CD secrets
  3. Re-sign all current targets
  4. Update snapshot and timestamp
- **Owner**: Security Team

### Root Key (Yearly)
- **Frequency**: Annually, during security review
- **Process**:
  1. Schedule key ceremony (2+ people required)
  2. Retrieve root key from offline storage
  3. Generate new root key
  4. Sign new root.json with BOTH old and new keys
  5. Return both keys to offline storage
  6. Update all other role keys
- **Owner**: Security Team Lead + Witness

---

## Key Ceremony Procedures

### Root Key Ceremony

**Participants Required**: 2 (Key Holder + Witness)

**Equipment**:
- Air-gapped laptop (no network capability)
- 2x USB drives (encrypted)
- Paper backup forms
- Video recording (optional)

**Steps**:
1. Boot air-gapped machine from clean OS
2. Insert encrypted USB with current root key
3. Verify key integrity with stored hash
4. Generate new root.json with:
   - New version number
   - Current timestamp
   - All role public keys
5. Sign with current root key
6. Generate new root key (if rotating)
7. Sign new root.json with new key
8. Export to encrypted USB
9. Generate paper backup (QR code or word list)
10. Witness signs ceremony log
11. Store USBs in separate secure locations

### Emergency Root Key Recovery

In case of root key compromise:
1. Activate incident response
2. Retrieve backup from secondary location
3. Perform emergency key ceremony
4. Increment root.json version by 100
5. Revoke all existing role keys
6. Generate new role keys
7. Notify all Guard instances (emergency blocklist)

---

## Storage Locations

### Root Key
- **Primary**: Hardware Security Module (HSM) or encrypted USB
- **Secondary**: Safe deposit box (different location)
- **Paper Backup**: Secure vault (word-based recovery)

### Online Keys (Targets, Snapshot, Timestamp)
- **Primary**: Cloudflare Worker Secrets
- **Backup**: 1Password Team Vault
- **CI/CD**: GitHub Secrets (encrypted)

---

## Compromise Response

### Timestamp Key Compromised
- **Impact**: Low (1-day validity)
- **Action**: Rotate immediately, no client action needed

### Snapshot Key Compromised
- **Impact**: Medium
- **Action**:
  1. Rotate snapshot key
  2. Regenerate all snapshot metadata
  3. Update timestamp

### Targets Key Compromised
- **Impact**: High
- **Action**:
  1. Activate incident response
  2. Rotate targets key
  3. Audit all signed targets
  4. Re-sign legitimate targets
  5. Consider root key ceremony if attacker had persistent access

### Root Key Compromised
- **Impact**: Critical
- **Action**:
  1. Full security incident
  2. Emergency key ceremony
  3. Notify all customers
  4. Release emergency Guard update
  5. Consider full key hierarchy rebuild

---

## Audit Requirements

- All key operations logged to transparency log
- Key ceremonies video recorded (optional)
- Witness signatures required for root operations
- Quarterly audit of key access logs
- Annual penetration test of key infrastructure

---

## TUF Metadata Structure

```
/v1/metadata/
├── root.json          # Trust anchor (yearly updates)
├── targets.json       # What artifacts exist
├── snapshot.json      # Point-in-time reference
└── timestamp.json     # Freshness guarantee (daily)

/v1/targets/
├── rules/             # Detection patterns
├── iocs/              # Threat indicators
├── models/            # ML models
├── policies/          # Policy packs
├── min_versions.json  # Version requirements
└── emergency_blocklist.json  # Kill switch
```

---

## Contact

- **Security Team**: security@faramesh.dev
- **Key Ceremony Scheduling**: ops@faramesh.dev
- **Emergency**: security-emergency@faramesh.dev
