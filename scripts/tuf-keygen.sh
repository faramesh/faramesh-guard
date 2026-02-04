#!/bin/bash
#
# TUF Key Generation Script for Faramesh Guard
#
# This script generates the TUF key hierarchy:
# - Root key (offline, highest trust)
# - Targets key (signs artifacts)
# - Snapshot key (signs snapshot metadata)
# - Timestamp key (short-lived, signs timestamp)
#
# SECURITY: Root key MUST be kept offline (air-gapped machine or HSM)
#

set -euo pipefail

# Configuration
TUF_DIR="${TUF_DIR:-$HOME/.guard-tuf}"
KEY_BITS=4096
VALIDITY_DAYS=365

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║       Faramesh Guard - TUF Key Generation                    ║"
echo "║                                                              ║"
echo "║  ⚠️  Store ROOT KEY OFFLINE (air-gapped machine or HSM)      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo

# Create directory structure
mkdir -p "$TUF_DIR"/{keys/{root,targets,snapshot,timestamp},metadata,staged}
chmod 700 "$TUF_DIR/keys"

echo "📁 Key storage: $TUF_DIR"
echo

# Function to generate ED25519 key pair
generate_key() {
    local role=$1
    local key_dir="$TUF_DIR/keys/$role"

    echo "🔑 Generating $role key..."

    # Generate private key
    openssl genpkey -algorithm ED25519 \
        -out "$key_dir/private.pem" 2>/dev/null
    chmod 600 "$key_dir/private.pem"

    # Extract public key
    openssl pkey -in "$key_dir/private.pem" \
        -pubout -out "$key_dir/public.pem" 2>/dev/null

    # Generate key ID (SHA256 of public key)
    local key_id=$(openssl pkey -in "$key_dir/private.pem" -pubout -outform DER 2>/dev/null | \
        openssl dgst -sha256 -hex | awk '{print $2}' | cut -c1-16)
    echo "$key_id" > "$key_dir/key_id.txt"

    echo "   ✓ Key ID: $key_id"
    echo "   ✓ Private: $key_dir/private.pem"
    echo "   ✓ Public:  $key_dir/public.pem"
    echo
}

# Generate all keys
echo "═══════════════════════════════════════════════════════════════"
echo "Generating TUF Key Hierarchy"
echo "═══════════════════════════════════════════════════════════════"
echo

generate_key "root"
generate_key "targets"
generate_key "snapshot"
generate_key "timestamp"

# Create key metadata JSON
cat > "$TUF_DIR/keys/metadata.json" << EOF
{
  "generated_at": "$(date -u +"%Y-%m-%dT%H:%M:%SZ")",
  "algorithm": "ed25519",
  "keys": {
    "root": {
      "key_id": "$(cat $TUF_DIR/keys/root/key_id.txt)",
      "threshold": 1,
      "offline": true,
      "expiry_days": 365
    },
    "targets": {
      "key_id": "$(cat $TUF_DIR/keys/targets/key_id.txt)",
      "threshold": 1,
      "offline": false,
      "expiry_days": 90
    },
    "snapshot": {
      "key_id": "$(cat $TUF_DIR/keys/snapshot/key_id.txt)",
      "threshold": 1,
      "offline": false,
      "expiry_days": 30
    },
    "timestamp": {
      "key_id": "$(cat $TUF_DIR/keys/timestamp/key_id.txt)",
      "threshold": 1,
      "offline": false,
      "expiry_days": 1
    }
  }
}
EOF

echo "═══════════════════════════════════════════════════════════════"
echo "Key Rotation Schedule"
echo "═══════════════════════════════════════════════════════════════"
echo
echo "Role       │ Rotation Frequency │ Storage"
echo "───────────┼────────────────────┼─────────────────────"
echo "Root       │ Yearly             │ OFFLINE / HSM"
echo "Targets    │ Quarterly          │ CI/CD secrets"
echo "Snapshot   │ Monthly            │ CI/CD secrets"
echo "Timestamp  │ Daily (automated)  │ Worker secrets"
echo

echo "═══════════════════════════════════════════════════════════════"
echo "⚠️  CRITICAL SECURITY STEPS"
echo "═══════════════════════════════════════════════════════════════"
echo
echo "1. BACKUP ROOT KEY to offline storage (USB, paper, HSM)"
echo "2. DELETE root/private.pem from this machine after backup"
echo "3. Set these in Cloudflare Worker secrets:"
echo
echo "   wrangler secret put TUF_TARGETS_KEY < $TUF_DIR/keys/targets/private.pem"
echo "   wrangler secret put TUF_SNAPSHOT_KEY < $TUF_DIR/keys/snapshot/private.pem"
echo "   wrangler secret put TUF_TIMESTAMP_KEY < $TUF_DIR/keys/timestamp/private.pem"
echo
echo "4. Store public keys in repository:"
echo "   cp $TUF_DIR/keys/*/public.pem ./cloud/tuf/keys/"
echo

echo "✅ TUF keys generated successfully!"
echo "📍 Location: $TUF_DIR"
