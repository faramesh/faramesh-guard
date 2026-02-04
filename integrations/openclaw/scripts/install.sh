#!/bin/bash

# Faramesh Guard Installer Script
# This script installs the Faramesh Guard runtime patch for OpenClaw

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PATCHER_ROOT="$(dirname "$SCRIPT_DIR")"

echo "🛡️  Faramesh Guard Installer"
echo ""
echo "This will patch OpenClaw to make Faramesh Guard non-bypassable."
echo ""

# Check if Node.js is installed
if ! command -v node &> /dev/null; then
    echo "✗ Node.js is not installed"
    echo "  Install Node.js first: https://nodejs.org/"
    exit 1
fi

echo "✓ Node.js found: $(node --version)"

# Check if npm dependencies are installed
if [ ! -d "$PATCHER_ROOT/node_modules" ]; then
    echo "📦 Installing patcher dependencies..."
    cd "$PATCHER_ROOT"
    npm install --silent
    echo "✓ Dependencies installed"
fi

# Build patcher if needed
if [ ! -d "$PATCHER_ROOT/dist" ]; then
    echo "🔨 Building patcher..."
    cd "$PATCHER_ROOT"
    npm run build --silent
    echo "✓ Patcher built"
fi

# Run the patcher
echo ""
echo "🔍 Detecting OpenClaw installation..."
echo ""

cd "$PATCHER_ROOT"
node dist/cli.js install "$@"

EXIT_CODE=$?

if [ $EXIT_CODE -eq 0 ]; then
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo "  Next Steps:"
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
    echo "  1. Start Faramesh Guard daemon:"
    echo "     cd ../guard && python3 -m daemon.main"
    echo ""
    echo "  2. Run OpenClaw:"
    echo "     openclaw"
    echo ""
    echo "  3. Verify enforcement:"
    echo "     npm test"
    echo ""
    echo "━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━"
    echo ""
else
    echo ""
    echo "✗ Installation failed"
    exit $EXIT_CODE
fi
