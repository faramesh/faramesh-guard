# Faramesh Guard Runtime Patcher

**Non-bypassable execution-time authorization for OpenClaw**

---

## 🎯 What This Does

The Faramesh Guard Runtime Patcher makes Guard **non-bypassable** by patching OpenClaw's core execution gate file. Unlike plugins (which can be disabled), this patch directly modifies the tool execution path to require Guard authorization.

### Key Features

- ✅ **Non-bypassable**: Injected into OpenClaw core, not optional plugins
- ✅ **Fail-closed**: Any error = deny (secure defaults)
- ✅ **Reversible**: Full backup/restore system
- ✅ **Verifiable**: Hash-based integrity checking
- ✅ **CAR-based**: Content-addressable records with replay protection
- ✅ **HMAC permits**: Cryptographically signed authorization tokens

---

## 🚀 Quick Start

### Install

```bash
cd guard-patcher
npm install
./scripts/install.sh
```

This will:
1. Detect your OpenClaw installation
2. Create backups
3. Patch the execution gate file
4. Save patch manifest

### Uninstall

```bash
./scripts/uninstall.sh
```

This will:
1. Restore original files from backup
2. Remove patch manifest
3. Leave OpenClaw in original state

---

## 📋 Requirements

- Node.js 18+
- OpenClaw installed (npm global, local, or repo clone)
- Faramesh Guard daemon running

---

## 🔧 How It Works

### 1. Detection Phase

The patcher finds your OpenClaw installation in this order:

1. **Repo clone** (development): `~/openclaw`, `~/Faramesh-Nexus/openclaw-test`
2. **Local npm**: `node_modules/openclaw`
3. **Global npm**: `npm root -g`

### 2. Patch Target

The patcher modifies:

```
src/agents/pi-tools.before-tool-call.ts
```

This is THE execution gate where every tool call passes through.

### 3. Patch Injection

The patcher injects:

```typescript
// Build CAR (Content-Addressable Record)
const car = buildFarameshCAR(toolName, params, ctx);

// Call Guard daemon for authorization
const decision = await callFarameshGuard(car);

if (decision.outcome !== 'EXECUTE') {
  throw new Error(`Blocked: ${decision.reason}`);
}

// Validate permit signature
if (!validateFarameshPermit(decision.permit, car)) {
  throw new Error('Invalid permit');
}

// Continue with tool execution
```

### 4. Backup System

Before patching, creates:

```
~/.faramesh-guard/
├── backup/
│   └── <openclaw-version>/
│       └── pi-tools.before-tool-call.ts
└── patch.json
```

**patch.json** contains:
- File path
- Original SHA256 hash
- Patched SHA256 hash
- Timestamp
- OpenClaw version/commit

---

## 🛠️ CLI Commands

### Install Patch

```bash
faramesh-patch install

# Or specify OpenClaw path
faramesh-patch install --path /path/to/openclaw
```

### Uninstall Patch

```bash
faramesh-patch uninstall
```

### Verify Integrity

```bash
faramesh-patch verify
```

Checks if patched files match expected hashes. Detects tampering.

### Status

```bash
faramesh-patch status
```

Shows:
- Installation status
- OpenClaw version
- Patched files
- Git commit (for repo clones)

---

## 🧪 Testing

### Bypass Test Suite

```bash
cd guard-patcher
npm test
```

This runs 6 tests:

1. **Guard Daemon OFF** → Tool execution fails (fail-closed)
2. **Guard Daemon ON** → Safe tools execute
3. **Tampered Permit** → Blocked (signature validation)
4. **Replay Attack** → Blocked (CAR hash mismatch)
5. **Plugin Removal** → Still enforced (patch is core)
6. **Patch Tampering** → Detected by watchdog

### Expected Results

All tests should PASS, proving Guard is non-bypassable.

---

## 🔒 Security Model

### Non-Bypassability

**CANNOT be bypassed by:**
- Disabling plugins
- Removing plugin folder
- Config changes
- Environment variables

**CAN be bypassed by:**
- Running uninstall script (intentional)
- Manually editing patched file (detected by watchdog)
- Reinstalling OpenClaw (overwrites patch)

### Fail-Closed

When Guard daemon is unreachable:
- All tool executions **DENIED**
- Error message: "Guard unavailable (fail-closed)"
- No fallback to unsafe mode

### Permit Validation

Each permit is:
- **Signed**: HMAC signature verified
- **Time-bound**: TTL checked (default 120s)
- **Action-bound**: CAR hash must match
- **Single-use**: Replay protection

---

## 📁 Directory Structure

```
guard-patcher/
├── src/
│   ├── detector.ts          # Find OpenClaw installation
│   ├── patcher.ts           # Apply/remove patches
│   ├── patch-template.ts    # Injection code
│   ├── backup.ts            # Backup/restore system
│   ├── manifest.ts          # Patch tracking
│   ├── watchdog.ts          # Integrity monitoring
│   ├── cli.ts               # Command-line interface
│   └── index.ts             # Main entry point
├── scripts/
│   ├── install.sh           # Installation script
│   └── uninstall.sh         # Uninstallation script
├── tests/
│   └── bypass_suite.js      # Non-bypassability tests
├── patches/                 # Patch definitions
├── package.json
├── tsconfig.json
└── README.md
```

---

## 🔍 Patch Details

### What Gets Injected

The patch adds three functions to `pi-tools.before-tool-call.ts`:

1. **`buildFarameshCAR()`**
   - Creates content-addressable record
   - Hashes: tool name + args + context
   - Prevents replay attacks

2. **`callFarameshGuard()`**
   - HTTP POST to Guard daemon
   - Sends CAR for evaluation
   - Returns permit or denial

3. **`validateFarameshPermit()`**
   - Checks HMAC signature
   - Verifies TTL
   - Confirms CAR hash binding

### Wrapper Function

Wraps the original `runBeforeToolCallHook()`:

```typescript
export async function runBeforeToolCallHook(args) {
  // FARAMESH: Authorization check
  const car = buildFarameshCAR(args.toolName, args.params, args.ctx);
  const decision = await callFarameshGuard(car);

  if (decision.outcome !== 'EXECUTE') {
    return { blocked: true, reason: decision.reason };
  }

  // Call original hook logic
  return await originalRunBeforeToolCallHook(args);
}
```

---

## 🐕 Integrity Watchdog

### Enable Watchdog

```typescript
import { startWatchdog } from './src/watchdog.js';

const stopWatchdog = startWatchdog({
  autoRepatch: true,        // Re-patch on tampering
  checkIntervalMs: 30000,   // Check every 30s
  onTampering: (file) => {
    console.error(`Tampering detected: ${file}`);
    // Send alert, log, etc.
  },
});

// Later: stop watchdog
stopWatchdog();
```

### What It Does

- Periodically checks file hashes
- Detects tampering/modification
- Optionally re-patches automatically
- Alerts on integrity violations

---

## 🔄 Upgrade Flow

When OpenClaw updates:

1. **Uninstall** old patch
2. **Update** OpenClaw
3. **Reinstall** patch

```bash
faramesh-patch uninstall
npm update openclaw  # or git pull
faramesh-patch install
```

---

## ⚠️ Important Notes

### Rebuild Required

If patching **source files** (repo clone), rebuild OpenClaw:

```bash
cd /path/to/openclaw
npm run build
```

The patch modifies TypeScript source, not JS output.

### Guard Daemon Must Run

Start Guard daemon before using OpenClaw:

```bash
cd ../guard
python3 -m daemon.main
```

Without daemon, all tool calls will fail-closed.

---

## 🧩 Integration with Guard Daemon

The patch expects Guard daemon at:

```
http://localhost:8765
```

Or set environment variable:

```bash
export FARAMESH_GUARD_URL=http://localhost:9000
```

### API Endpoint

POST `/api/v1/guard/execute`

**Request**:
```json
{
  "tool_name": "exec",
  "args": { "command": "ls" },
  "agent_id": "agent-123",
  "car_hash": "abc123..."
}
```

**Response**:
```json
{
  "allowed": true,
  "decision": {
    "outcome": "ALLOW",
    "reason": "Low risk",
    "confidence": 0.9
  },
  "permit": {
    "car_hash": "abc123...",
    "signature": "...",
    "ttl": 120,
    "issued_at": "2026-02-04T10:00:00Z"
  }
}
```

---

## 🎯 Comparison: Plugin vs Patch

| Feature | Plugin | Runtime Patch |
|---------|--------|---------------|
| **Bypassable** | ✅ Yes (disable plugin) | ❌ No (in core) |
| **Installation** | Simple | Requires patching |
| **Reversible** | Always | Yes (backup/restore) |
| **OpenClaw Updates** | Survives | Must re-patch |
| **Detection Difficulty** | Easy | Detectable via hash |

---

## 📝 Troubleshooting

### "OpenClaw not found"

Ensure OpenClaw is installed:
```bash
npm install -g openclaw
# or
git clone https://github.com/OpenClaw/openclaw.git
```

### "Already patched"

Uninstall first:
```bash
faramesh-patch uninstall
```

### "Patch failed"

Check file permissions:
```bash
ls -la /path/to/openclaw/src/agents/pi-tools.before-tool-call.ts
```

### "Guard daemon unreachable"

Start the daemon:
```bash
cd ../guard
python3 -m daemon.main
```

---

## 📚 Related

- **Guard Daemon**: `../guard/` - Authorization service
- **Guard Plan**: `../guard-plan-v1.md` - Architecture doc
- **OpenClaw**: `../openclaw-test/` - Test OpenClaw instance

---

## 🤝 Contributing

This is a security-critical component. All changes must:
1. Maintain non-bypassability
2. Preserve fail-closed semantics
3. Pass bypass test suite
4. Document security implications

---

## 📄 License

MIT

---

## ✅ Checklist Before Use

- [ ] OpenClaw installed and working
- [ ] Guard daemon built and tested
- [ ] Backup strategy understood
- [ ] Bypass tests reviewed
- [ ] Fail-closed behavior accepted
- [ ] Uninstall process understood

---

**Security Notice**: This patcher modifies OpenClaw's core execution path. While designed to be reversible, always backup your OpenClaw installation before patching.

---

## 🚀 Next Steps

1. **Install**: `./scripts/install.sh`
2. **Start Guard**: `cd ../guard && python3 -m daemon.main`
3. **Test**: `npm test`
4. **Run OpenClaw**: Watch Guard enforce every tool call

**The future is non-bypassable. 🛡️**
