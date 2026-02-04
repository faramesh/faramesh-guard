#!/bin/bash
#
# Bootstrap TUF Repository
# Creates initial TUF metadata structure
#

set -euo pipefail

TUF_DIR="${TUF_DIR:-$HOME/.guard-tuf}"
REPO_DIR="$TUF_DIR/repository"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║       Faramesh Guard - TUF Repository Bootstrap              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo

# Create repository structure
mkdir -p "$REPO_DIR"/{metadata,targets/{rules,iocs,models,policies,calibration}}

# Check for keys
if [ ! -f "$TUF_DIR/keys/root/private.pem" ]; then
    echo "❌ TUF keys not found. Run tuf-keygen.sh first."
    exit 1
fi

# Current timestamp
TIMESTAMP=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EXPIRES_ROOT=$(date -u -v+1y +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -d "+1 year" +"%Y-%m-%dT%H:%M:%SZ")
EXPIRES_TARGETS=$(date -u -v+90d +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -d "+90 days" +"%Y-%m-%dT%H:%M:%SZ")
EXPIRES_SNAPSHOT=$(date -u -v+30d +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -d "+30 days" +"%Y-%m-%dT%H:%M:%SZ")
EXPIRES_TIMESTAMP=$(date -u -v+1d +"%Y-%m-%dT%H:%M:%SZ" 2>/dev/null || date -u -d "+1 day" +"%Y-%m-%dT%H:%M:%SZ")

# Get key IDs
ROOT_KEY_ID=$(cat "$TUF_DIR/keys/root/key_id.txt")
TARGETS_KEY_ID=$(cat "$TUF_DIR/keys/targets/key_id.txt")
SNAPSHOT_KEY_ID=$(cat "$TUF_DIR/keys/snapshot/key_id.txt")
TIMESTAMP_KEY_ID=$(cat "$TUF_DIR/keys/timestamp/key_id.txt")

# Get public keys (base64 encoded)
ROOT_PUBKEY=$(openssl pkey -in "$TUF_DIR/keys/root/private.pem" -pubout 2>/dev/null | grep -v "PUBLIC KEY" | tr -d '\n')
TARGETS_PUBKEY=$(openssl pkey -in "$TUF_DIR/keys/targets/private.pem" -pubout 2>/dev/null | grep -v "PUBLIC KEY" | tr -d '\n')
SNAPSHOT_PUBKEY=$(openssl pkey -in "$TUF_DIR/keys/snapshot/private.pem" -pubout 2>/dev/null | grep -v "PUBLIC KEY" | tr -d '\n')
TIMESTAMP_PUBKEY=$(openssl pkey -in "$TUF_DIR/keys/timestamp/private.pem" -pubout 2>/dev/null | grep -v "PUBLIC KEY" | tr -d '\n')

echo "🔨 Creating initial TUF metadata..."
echo

# Create root.json
cat > "$REPO_DIR/metadata/root.json" << EOF
{
  "signed": {
    "_type": "root",
    "spec_version": "1.0.0",
    "version": 1,
    "expires": "$EXPIRES_ROOT",
    "keys": {
      "$ROOT_KEY_ID": {
        "keytype": "ed25519",
        "scheme": "ed25519",
        "keyval": {"public": "$ROOT_PUBKEY"}
      },
      "$TARGETS_KEY_ID": {
        "keytype": "ed25519",
        "scheme": "ed25519",
        "keyval": {"public": "$TARGETS_PUBKEY"}
      },
      "$SNAPSHOT_KEY_ID": {
        "keytype": "ed25519",
        "scheme": "ed25519",
        "keyval": {"public": "$SNAPSHOT_PUBKEY"}
      },
      "$TIMESTAMP_KEY_ID": {
        "keytype": "ed25519",
        "scheme": "ed25519",
        "keyval": {"public": "$TIMESTAMP_PUBKEY"}
      }
    },
    "roles": {
      "root": {
        "keyids": ["$ROOT_KEY_ID"],
        "threshold": 1
      },
      "targets": {
        "keyids": ["$TARGETS_KEY_ID"],
        "threshold": 1
      },
      "snapshot": {
        "keyids": ["$SNAPSHOT_KEY_ID"],
        "threshold": 1
      },
      "timestamp": {
        "keyids": ["$TIMESTAMP_KEY_ID"],
        "threshold": 1
      }
    },
    "consistent_snapshot": true
  },
  "signatures": []
}
EOF
echo "   ✓ root.json"

# Create initial targets (empty)
cat > "$REPO_DIR/metadata/targets.json" << EOF
{
  "signed": {
    "_type": "targets",
    "spec_version": "1.0.0",
    "version": 1,
    "expires": "$EXPIRES_TARGETS",
    "targets": {}
  },
  "signatures": []
}
EOF
echo "   ✓ targets.json"

# Create snapshot
cat > "$REPO_DIR/metadata/snapshot.json" << EOF
{
  "signed": {
    "_type": "snapshot",
    "spec_version": "1.0.0",
    "version": 1,
    "expires": "$EXPIRES_SNAPSHOT",
    "meta": {
      "targets.json": {
        "version": 1
      }
    }
  },
  "signatures": []
}
EOF
echo "   ✓ snapshot.json"

# Create timestamp
cat > "$REPO_DIR/metadata/timestamp.json" << EOF
{
  "signed": {
    "_type": "timestamp",
    "spec_version": "1.0.0",
    "version": 1,
    "expires": "$EXPIRES_TIMESTAMP",
    "meta": {
      "snapshot.json": {
        "version": 1
      }
    }
  },
  "signatures": []
}
EOF
echo "   ✓ timestamp.json"

# Create initial targets files
cat > "$REPO_DIR/targets/min_versions.json" << EOF
{
  "guard": {
    "minimum": "0.1.0",
    "recommended": "0.1.0",
    "message": "Please update to the latest version for security fixes."
  },
  "daemon": {
    "minimum": "0.1.0",
    "recommended": "0.1.0"
  },
  "updated_at": "$TIMESTAMP"
}
EOF
echo "   ✓ targets/min_versions.json"

cat > "$REPO_DIR/targets/emergency_blocklist.json" << EOF
{
  "version": 1,
  "updated_at": "$TIMESTAMP",
  "entries": [],
  "comment": "Emergency blocklist. Entries here are blocked globally."
}
EOF
echo "   ✓ targets/emergency_blocklist.json"

# Create placeholder rule file
cat > "$REPO_DIR/targets/rules/prompt-injection-v1.json" << EOF
{
  "version": 1,
  "name": "prompt-injection-v1",
  "description": "Prompt injection detection patterns",
  "updated_at": "$TIMESTAMP",
  "patterns": [
    {
      "id": "pi-001",
      "name": "instruction_override",
      "pattern": "ignore (all |your |previous |prior |above )?instructions",
      "severity": "high",
      "enabled": true
    },
    {
      "id": "pi-002",
      "name": "role_manipulation",
      "pattern": "you are now|pretend to be|act as if|from now on you",
      "severity": "high",
      "enabled": true
    },
    {
      "id": "pi-003",
      "name": "system_prompt_extraction",
      "pattern": "show me your (system )?prompt|what are your instructions|reveal your",
      "severity": "medium",
      "enabled": true
    }
  ]
}
EOF
echo "   ✓ targets/rules/prompt-injection-v1.json"

echo
echo "═══════════════════════════════════════════════════════════════"
echo "Next Steps"
echo "═══════════════════════════════════════════════════════════════"
echo
echo "1. Sign metadata files (requires signing tool):"
echo "   python scripts/tuf-sign.py --role root"
echo "   python scripts/tuf-sign.py --role targets"
echo "   python scripts/tuf-sign.py --role snapshot"
echo "   python scripts/tuf-sign.py --role timestamp"
echo
echo "2. Upload to R2 bucket:"
echo "   wrangler r2 object put guard-tuf/metadata/root.json --file $REPO_DIR/metadata/root.json"
echo "   wrangler r2 object put guard-tuf/metadata/targets.json --file $REPO_DIR/metadata/targets.json"
echo "   # ... etc"
echo
echo "3. Deploy guard-updates worker:"
echo "   cd cloud/workers/guard-updates && wrangler deploy"
echo

echo "✅ TUF repository structure created!"
echo "📍 Location: $REPO_DIR"
