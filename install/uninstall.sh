#!/bin/bash
# ==============================================================================
# Faramesh Guard - Uninstaller
# Removes Guard daemon and all integrations
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GUARD_ROOT="$(dirname "$SCRIPT_DIR")"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${BLUE}[INFO]${NC} $1"; }
success() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
error() { echo -e "${RED}[✗]${NC} $1"; }

echo ""
echo -e "${RED}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${RED}║${NC}              Faramesh Guard - Uninstaller                      ${RED}║${NC}"
echo -e "${RED}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""

# ==============================================================================
# Confirm
# ==============================================================================
read -p "This will remove Faramesh Guard. Continue? (y/N) " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo "Cancelled."
    exit 0
fi

# ==============================================================================
# Stop and remove system service
# ==============================================================================
echo ""
info "Stopping Guard daemon..."

if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    PLIST_FILE="$HOME/Library/LaunchAgents/ai.faramesh.guard.plist"

    if [ -f "$PLIST_FILE" ]; then
        launchctl unload "$PLIST_FILE" 2>/dev/null || true
        rm -f "$PLIST_FILE"
        success "LaunchAgent removed"
    else
        warn "LaunchAgent not found (may not have been installed)"
    fi

elif [[ "$OSTYPE" == "linux-gnu"* ]]; then
    # Linux
    SERVICE_FILE="$HOME/.config/systemd/user/faramesh-guard.service"

    if [ -f "$SERVICE_FILE" ]; then
        systemctl --user stop faramesh-guard 2>/dev/null || true
        systemctl --user disable faramesh-guard 2>/dev/null || true
        rm -f "$SERVICE_FILE"
        systemctl --user daemon-reload
        success "systemd service removed"
    else
        warn "systemd service not found (may not have been installed)"
    fi
fi

# ==============================================================================
# Kill any running daemon process
# ==============================================================================
DAEMON_PID=$(lsof -ti:8765 2>/dev/null || true)
if [ -n "$DAEMON_PID" ]; then
    info "Killing Guard daemon process (PID: $DAEMON_PID)..."
    kill $DAEMON_PID 2>/dev/null || true
    success "Daemon process stopped"
fi

# ==============================================================================
# Unpatch any OpenClaw installations
# ==============================================================================
echo ""
info "Looking for patched OpenClaw installations..."

# Find all .faramesh-backup directories
BACKUP_DIRS=$(find "$HOME" -type d -name ".faramesh-backup" 2>/dev/null | head -20 || true)

if [ -n "$BACKUP_DIRS" ]; then
    for backup_dir in $BACKUP_DIRS; do
        OPENCLAW_DIR=$(dirname "$backup_dir")
        info "Found backup at: $OPENCLAW_DIR"

        # Restore original files
        if [ -d "$backup_dir" ]; then
            for backup_file in "$backup_dir"/*.backup 2>/dev/null; do
                if [ -f "$backup_file" ]; then
                    original_name=$(basename "$backup_file" .backup)
                    # Find where this file should go
                    original_path=$(find "$OPENCLAW_DIR/src" -name "$original_name" -type f 2>/dev/null | head -1)
                    if [ -n "$original_path" ]; then
                        cp "$backup_file" "$original_path"
                        success "Restored: $original_name"
                    fi
                fi
            done
            rm -rf "$backup_dir"
        fi
    done
else
    info "No patched OpenClaw installations found"
fi

# ==============================================================================
# Clean up logs
# ==============================================================================
echo ""
info "Cleaning up log files..."
rm -f /tmp/faramesh-guard.log /tmp/faramesh-guard.err 2>/dev/null || true
success "Logs cleaned"

# ==============================================================================
# Optional: Remove Guard directory
# ==============================================================================
echo ""
read -p "Remove Faramesh Guard directory? ($GUARD_ROOT) (y/N) " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
    rm -rf "$GUARD_ROOT"
    success "Guard directory removed"
else
    info "Guard directory preserved"
fi

# ==============================================================================
# Complete
# ==============================================================================
echo ""
echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════╗${NC}"
echo -e "${GREEN}║${NC}              Uninstallation Complete                          ${GREEN}║${NC}"
echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════╝${NC}"
echo ""
