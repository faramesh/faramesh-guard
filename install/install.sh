#!/bin/bash
# ==============================================================================
# Faramesh Guard - Universal Installer
# Makes AI agents non-bypassable and policy-governed
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD_ROOT="$(dirname "$SCRIPT_DIR")"
DAEMON_DIR="$GUARD_ROOT/daemon"
OPENCLAW_PATCHER="$GUARD_ROOT/integrations/openclaw"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }

# ==============================================================================
# Banner
# ==============================================================================
echo ""
echo -e "${BLUE}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${BLUE}║${NC}          ${GREEN}Faramesh Guard${NC} - Non-Bypassable Agent Safety          ${BLUE}║${NC}"
echo -e "${BLUE}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ==============================================================================
# Check Prerequisites
# ==============================================================================
info "Checking prerequisites..."

# Check Python
if ! command -v python3 &> /dev/null; then
    error "Python 3 is required but not installed."
    echo "  Install with: brew install python3 (macOS) or apt install python3 (Linux)"
    exit 1
fi
PYTHON_VERSION=$(python3 --version 2>&1 | cut -d' ' -f2 | cut -d'.' -f1,2)
success "Python $PYTHON_VERSION found"

# Check Node.js (for OpenClaw integration)
if ! command -v node &> /dev/null; then
    warn "Node.js not found - OpenClaw integration will be skipped"
    HAS_NODE=false
else
    NODE_VERSION=$(node --version 2>&1)
    success "Node.js $NODE_VERSION found"
    HAS_NODE=true
fi

# Check pip
if ! command -v pip3 &> /dev/null; then
    error "pip3 is required but not installed."
    exit 1
fi
success "pip3 found"

# ==============================================================================
# Install Guard Daemon
# ==============================================================================
echo ""
info "Installing Faramesh Guard daemon..."

# Create virtual environment if it doesn't exist
if [ ! -d "$DAEMON_DIR/venv" ]; then
    info "Creating Python virtual environment..."
    python3 -m venv "$DAEMON_DIR/venv"
fi

# Activate and install dependencies
source "$DAEMON_DIR/venv/bin/activate"

if [ -f "$DAEMON_DIR/requirements.txt" ]; then
    info "Installing Python dependencies..."
    pip install -q -r "$DAEMON_DIR/requirements.txt"
fi

deactivate
success "Guard daemon installed"

# ==============================================================================
# Create LaunchDaemon (macOS) or systemd service (Linux)
# ==============================================================================
echo ""
info "Setting up Guard daemon as system service..."

if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS - LaunchAgent
    PLIST_DIR="$HOME/Library/LaunchAgents"
    PLIST_FILE="$PLIST_DIR/ai.faramesh.guard.plist"

    mkdir -p "$PLIST_DIR"

    cat > "$PLIST_FILE" << EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>Label</key>
    <string>ai.faramesh.guard</string>
    <key>ProgramArguments</key>
    <array>
        <string>$DAEMON_DIR/venv/bin/python</string>
        <string>-m</string>
        <string>uvicorn</string>
        <string>main:app</string>
        <string>--host</string>
        <string>127.0.0.1</string>
        <string>--port</string>
        <string>8765</string>
    </array>
    <key>WorkingDirectory</key>
    <string>$DAEMON_DIR</string>
    <key>RunAtLoad</key>
    <true/>
    <key>KeepAlive</key>
    <true/>
    <key>StandardOutPath</key>
    <string>/tmp/faramesh-guard.log</string>
    <key>StandardErrorPath</key>
    <string>/tmp/faramesh-guard.err</string>
</dict>
</plist>
EOF

    launchctl unload "$PLIST_FILE" 2>/dev/null || true
    launchctl load "$PLIST_FILE"
    success "LaunchAgent installed and started"

elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux - systemd user service
    SYSTEMD_DIR="$HOME/.config/systemd/user"
    SERVICE_FILE="$SYSTEMD_DIR/faramesh-guard.service"

    mkdir -p "$SYSTEMD_DIR"

    cat > "$SERVICE_FILE" << EOF
[Unit]
Description=Faramesh Guard - Non-Bypassable Agent Safety Daemon
After=network.target

[Service]
Type=simple
WorkingDirectory=$DAEMON_DIR
ExecStart=$DAEMON_DIR/venv/bin/python -m uvicorn main:app --host 127.0.0.1 --port 8765
Restart=always
RestartSec=5

[Install]
WantedBy=default.target
EOF

    systemctl --user daemon-reload
    systemctl --user enable faramesh-guard
    systemctl --user start faramesh-guard
    success "systemd service installed and started"
fi

# ==============================================================================
# Install OpenClaw Integration (if Node.js available)
# ==============================================================================
if [ "$HAS_NODE" = true ] && [ -d "$OPENCLAW_PATCHER" ]; then
    echo ""
    info "Building OpenClaw integration..."

    cd "$OPENCLAW_PATCHER"

    if [ -f "package.json" ]; then
        npm install --silent 2>/dev/null || npm install
        npm run build 2>/dev/null || true
        success "OpenClaw patcher built"
    fi

    cd "$GUARD_ROOT"
fi

# ==============================================================================
# Verify Installation
# ==============================================================================
echo ""
info "Verifying installation..."

# Wait for daemon to start
sleep 2

# Check daemon health
if curl -s http://127.0.0.1:8765/health > /dev/null 2>&1; then
    HEALTH=$(curl -s http://127.0.0.1:8765/health)
    success "Guard daemon is running and healthy"
    echo "  $HEALTH"
else
    warn "Guard daemon may still be starting..."
    echo "  Check status with: curl http://127.0.0.1:8765/health"
fi

# ==============================================================================
# Complete
# ==============================================================================
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}              Installation Complete! 🎉                        ${GREEN}║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
echo "Next steps:"
echo ""
echo "  1. To protect an OpenClaw installation:"
echo "     cd $OPENCLAW_PATCHER"
echo "     node dist/cli.js install --openclaw-path /path/to/openclaw"
echo ""
echo "  2. Check Guard daemon status:"
echo "     curl http://127.0.0.1:8765/health"
echo ""
echo "  3. View logs:"
if [[ "$OSTYPE" == "darwin"* ]]; then
    echo "     tail -f /tmp/faramesh-guard.log"
else
    echo "     journalctl --user -u faramesh-guard -f"
fi
echo ""
echo "Documentation: $GUARD_ROOT/README.md"
echo ""
