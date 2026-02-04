# Faramesh Guard v1: Version Compatibility

> **Version**: 1.0.0
> **Status**: Production Ready

This document defines version compatibility between Guard components and upgrade procedures.

---

## Component Versions

Guard consists of multiple components that must be compatible:

```
┌─────────────────────────────────────────────────────────┐
│                  GUARD COMPONENTS                       │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  1. Guard Daemon (Python)                               │
│     └─► Runs on localhost:8765                          │
│     └─► Version: 1.0.x                                  │
│                                                         │
│  2. OpenClaw Plugin (TypeScript)                        │
│     └─► Hooks into OpenClaw runtime                     │
│     └─► Version: 0.1.x                                  │
│                                                         │
│  3. Guard CLI (Python)                                  │
│     └─► Command-line interface                          │
│     └─► Version: 1.0.x                                  │
│                                                         │
│  4. Guard UI (Web)                                      │
│     └─► Dashboard for approvals                         │
│     └─► Version: 1.0.x                                  │
│                                                         │
│  5. Policy Files (YAML)                                 │
│     └─► Cold-start templates                            │
│     └─► Format: v1                                      │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

---

## Version Format

Guard uses **Semantic Versioning** (SemVer):

```
MAJOR.MINOR.PATCH
  │     │     │
  │     │     └─ Bug fixes, no API changes
  │     └─────── New features, backwards compatible
  └───────────── Breaking changes
```

### Examples

- `1.0.0` → Initial release
- `1.0.1` → Bug fix
- `1.1.0` → New feature (backwards compatible)
- `2.0.0` → Breaking change

---

## Compatibility Matrix

### Daemon ↔ Plugin

| Daemon Version | Plugin Version | Compatible | Notes |
|---------------|----------------|------------|-------|
| 1.0.x | 0.1.x | ✅ | Fully compatible |
| 1.1.x | 0.1.x | ✅ | Daemon has new features plugin can't use |
| 1.1.x | 0.2.x | ✅ | Full feature support |
| 2.0.x | 0.1.x | ❌ | Plugin must upgrade |
| 2.0.x | 1.0.x | ✅ | New plugin for new daemon |

### Daemon ↔ CLI

| Daemon Version | CLI Version | Compatible | Notes |
|---------------|-------------|------------|-------|
| 1.0.x | 1.0.x | ✅ | Fully compatible |
| 1.1.x | 1.0.x | ⚠️ | CLI may lack new features |
| 2.0.x | 1.0.x | ❌ | CLI must upgrade |

### Policy Format

| Policy Format | Daemon Version | Compatible | Notes |
|--------------|----------------|------------|-------|
| v1 | 1.0.x | ✅ | Fully compatible |
| v1 | 1.1.x | ✅ | Fully compatible |
| v2 | 1.x.x | ❌ | Daemon must upgrade |
| v1 | 2.0.x | ⚠️ | Auto-migrated |

---

## Version Handshake

### Protocol

When plugin connects to daemon, they exchange versions:

**Plugin → Daemon**:
```http
POST /api/v1/guard/handshake HTTP/1.1
Content-Type: application/json

{
  "component": "openclaw-plugin",
  "version": "0.1.0",
  "protocol_version": "1.0",
  "capabilities": ["basic_auth", "permits", "websocket"]
}
```

**Daemon → Plugin**:
```json
{
  "component": "guard-daemon",
  "version": "1.0.0",
  "protocol_version": "1.0",
  "capabilities": ["basic_auth", "permits", "websocket", "behavioral_anomaly"],
  "compatible": true,
  "warnings": []
}
```

### Compatibility Check

```python
def check_compatibility(client_version: str, server_version: str) -> CompatResult:
    """Check if client and server versions are compatible."""
    client = parse_semver(client_version)
    server = parse_semver(server_version)

    # Major version must match
    if client.major != server.major:
        return CompatResult(
            compatible=False,
            reason=f"Major version mismatch: {client_version} vs {server_version}"
        )

    # Server can be newer (minor/patch)
    if server.minor > client.minor:
        return CompatResult(
            compatible=True,
            warnings=[f"Server has newer features (v{server_version})"]
        )

    return CompatResult(compatible=True)
```

---

## Fail-Closed Behavior

### On Version Mismatch

```
┌─────────────────────────────────────────────────────────┐
│            VERSION MISMATCH BEHAVIOR                    │
├─────────────────────────────────────────────────────────┤
│                                                         │
│  MAJOR mismatch → FAIL CLOSED                           │
│     └─► Plugin rejects all tool calls                   │
│     └─► User prompted to upgrade                        │
│                                                         │
│  MINOR mismatch (server newer) → WARN + CONTINUE        │
│     └─► Plugin continues with reduced features          │
│     └─► User notified of available upgrade              │
│                                                         │
│  PATCH mismatch → CONTINUE                              │
│     └─► No action needed                                │
│                                                         │
└─────────────────────────────────────────────────────────┘
```

### Implementation

```typescript
// Plugin behavior on version mismatch
async function handleVersionMismatch(result: CompatResult): Promise<void> {
  if (!result.compatible) {
    // FAIL CLOSED
    console.error(`Guard version incompatible: ${result.reason}`);
    console.error("Please upgrade Guard: npm install -g @faramesh/guard");

    // Block all tool execution
    throw new Error("Guard version incompatible - execution blocked");
  }

  if (result.warnings.length > 0) {
    // WARN
    for (const warning of result.warnings) {
      console.warn(`Guard: ${warning}`);
    }
  }
}
```

---

## Upgrade Procedures

### Upgrading Daemon

```bash
# 1. Stop daemon
guard stop

# 2. Backup configuration
cp -r ~/.faramesh-guard ~/.faramesh-guard.backup

# 3. Upgrade
pip install --upgrade faramesh-guard

# 4. Run migrations (if any)
guard migrate

# 5. Start daemon
guard start

# 6. Verify
guard status
```

### Upgrading Plugin

```bash
# 1. Upgrade plugin
npm install -g @faramesh/guard-openclaw@latest

# 2. Restart OpenClaw
# (plugin loads automatically)

# 3. Verify
guard plugin-status
```

### Rolling Back

```bash
# 1. Stop daemon
guard stop

# 2. Restore backup
rm -rf ~/.faramesh-guard
mv ~/.faramesh-guard.backup ~/.faramesh-guard

# 3. Downgrade
pip install faramesh-guard==1.0.0

# 4. Start
guard start
```

---

## Migration Scripts

### Database Migrations

Migrations are stored in `daemon/migrations/` and run automatically:

```
migrations/
├── 001_initial_schema.sql
├── 002_add_behavioral_anomaly.sql
├── 003_add_integrity_monitoring.sql
└── ...
```

### Configuration Migrations

Config migrations happen on startup:

```python
def migrate_config(config: dict, from_version: str, to_version: str) -> dict:
    """Migrate configuration between versions."""

    # v1.0 → v1.1: Add watchdog settings
    if compare_versions(from_version, "1.1.0") < 0:
        config.setdefault("watchdog", {
            "enabled": True,
            "interval_seconds": 60
        })

    return config
```

---

## Deprecation Policy

1. **Deprecation notice**: Feature marked deprecated in release N
2. **Warning period**: Warnings shown for 2 minor releases
3. **Removal**: Feature removed in release N+3 or major version

### Example

```
v1.0.0: /v1/actions endpoint introduced
v1.2.0: /v1/actions deprecated (use /api/v1/guard/execute)
v1.3.0: /v1/actions shows warning
v1.4.0: /v1/actions shows warning
v2.0.0: /v1/actions removed
```

---

## API Versioning

### URL Versioning

APIs are versioned in the URL path:

```
/api/v1/guard/execute   ← Current stable
/api/v2/guard/execute   ← Future breaking changes
```

### Version Headers

Requests can specify version preferences:

```http
GET /api/guard/execute HTTP/1.1
Accept-Version: 1.0
```

---

## Telemetry (Opt-in)

Version information is included in optional telemetry:

```json
{
  "daemon_version": "1.0.0",
  "plugin_version": "0.1.0",
  "os": "darwin",
  "arch": "arm64"
}
```

This helps us understand upgrade adoption and compatibility issues.

---

## Changelog

All version changes are documented in [CHANGELOG.md](../../CHANGELOG.md):

```markdown
## [1.1.0] - 2024-XX-XX

### Added
- Watchdog self-integrity monitoring
- Policy integrity verification

### Changed
- Improved behavioral anomaly detection

### Deprecated
- /v1/actions endpoint (use /api/v1/guard/execute)

### Fixed
- Race condition in permit validation
```

---

*Last Updated: 2024*
