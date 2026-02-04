#!/bin/bash

# Faramesh Guard Uninstaller Script
# This script removes the Faramesh Guard runtime patch from OpenClaw

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCHER_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🛡️  Faramesh Guard Uninstaller"
echo ""
echo "This will remove the Faramesh Guard patch from OpenClaw."
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "✗ Node.js is not installed"
    exit 1
fi

# Check if patcher is built
if [ ! -d "$PATCHER_ROOT/dist" ]; then
    echo "✗ Patcher not built"
    echo "  Run: cd $PATCHER_ROOT && npm run build"
    exit 1
fi

# Run the uninstaller
cd "$PATCHER_ROOT"
node dist/cli.js uninstall

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  OpenClaw has been restored to its original state."
    echo "  Faramesh Guard is no longer enforced."
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
else
    echo ""
    echo "✗ Uninstallation failed"
    exit $EXIT_CODE
fi
