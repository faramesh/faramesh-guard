<p align="center">
  <img src="docs/logo.png" alt="Faramesh Guard" width="120" />
</p>

<h1 align="center">Faramesh Guard</h1>
<p align="center"><strong>AI Agent Security Layer</strong></p>

<p align="center">
  <a href="https://github.com/faramesh/faramesh-guard/releases">
    <img src="https://img.shields.io/github/v/release/faramesh/faramesh-guard" alt="Release" />
  </a>
  <a href="LICENSE">
    <img src="https://img.shields.io/badge/license-Apache%202.0-blue" alt="License" />
  </a>
</p>

---

Guard intercepts AI agent actions **before** they execute. Non-bypassable. Real-time.

## Quick Install

### macOS
```bash
# Download latest release
curl -LO https://github.com/faramesh/faramesh-guard/releases/latest/download/guard-macos-arm64.zip
unzip guard-macos-arm64.zip

# First run: Right-click → Open (bypasses Gatekeeper for unsigned app)
open FarameshGuard.app
```

<!-- Screenshot placeholder -->
<!-- ![macOS Install](docs/screenshots/macos-install.png) -->

### Linux
```bash
curl -LO https://github.com/faramesh/faramesh-guard/releases/latest/download/guard-linux-x64.tar.gz
tar -xzf guard-linux-x64.tar.gz
cd faramesh-guard
sudo ./install.sh
```

### Windows
```powershell
# Download from releases page
Expand-Archive guard-windows-x64.zip
cd faramesh-guard
.\guard.bat
```

### Verify Download (Optional)
```bash
# Download checksums
curl -LO https://github.com/faramesh/faramesh-guard/releases/latest/download/checksums.txt
sha256sum -c checksums.txt
```

---

## How It Works

```
┌─────────────┐      ┌─────────────┐      ┌─────────────┐
│  AI Agent   │ ───▶ │    Guard    │ ───▶ │   System    │
│  (Claude,   │      │  (Approve/  │      │   (Files,   │
│   GPT, etc) │      │   Deny)     │      │    APIs)    │
└─────────────┘      └─────────────┘      └─────────────┘
```

Guard sits between AI agents and system resources. Every action requires Guard approval.

---

## CLI Reference

```bash
# Start daemon
guard start

# Check status
guard status

# View live decisions
guard logs --follow

# Approve pending action (from UI or CLI)
guard approve <action-id>

# Deny action
guard deny <action-id>

# Show current policy
guard policy show

# Stop daemon
guard stop
```

---

## Configuration

Guard works with zero configuration. Customize via `~/.guard/config.yaml`:

```yaml
# Policy mode: permissive, standard, strict
mode: standard

# Telemetry (opt-in)
telemetry:
  enabled: false

# Heartbeat interval (seconds)
heartbeat_interval: 60

# API port
port: 8765
```

---

## Integrations

### Python / LangChain
```python
from faramesh import GuardClient

guard = GuardClient()
result = guard.request_action(
    action="file_write",
    resource="/etc/hosts",
    agent_id="my-agent"
)

if result.approved:
    # Proceed with action
    pass
```

### Node.js
```javascript
import { Guard } from '@faramesh/guard';

const guard = new Guard();
const result = await guard.requestAction({
  action: 'execute_code',
  resource: 'shell:rm -rf /',
  agentId: 'code-agent'
});

if (result.approved) {
  // Proceed
}
```

---

## Build from Source

```bash
git clone https://github.com/faramesh/faramesh-guard.git
cd faramesh-guard

# Install daemon
cd daemon
pip install -r requirements.txt
python -m uvicorn main:app --port 8765

# Build Rust core (optional, for ML features)
cd ../rust-core
cargo build --release
```

---

## Security Model

1. **Non-Bypassable**: Guard must be running for agents to function
2. **Permit-Based**: Approvals are cryptographically signed
3. **Audit Trail**: Hash-chained log of all decisions
4. **Risk Scoring**: ML-based risk assessment (optional)

---

## Unsigned Software Notice

This software is currently **unsigned** (no Apple/Microsoft code signing).

**macOS**: Right-click → Open on first launch
**Windows**: Click "More info" → "Run anyway" on SmartScreen
**Linux**: No special steps needed

Verify integrity using checksums:
```bash
sha256sum -c checksums.txt
```

---

## License

[Apache License 2.0](LICENSE)

---

<p align="center">
  <a href="https://faramesh.dev">Website</a> •
  <a href="https://github.com/faramesh/faramesh-guard/issues">Issues</a> •
  <a href="https://discord.gg/faramesh">Discord</a>
</p>
