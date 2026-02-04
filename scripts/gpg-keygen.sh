#!/bin/bash
#
# GPG Release Signing Key Generation
#
# Generates a GPG key for signing Faramesh Guard releases.
# This key is used to sign:
# - Release binaries
# - Checksums files
# - Git tags
#

set -euo pipefail

GPG_DIR="${GPG_DIR:-$HOME/.guard-gpg}"
KEY_NAME="Faramesh Guard Release Signing Key"
KEY_EMAIL="releases@faramesh.dev"
KEY_COMMENT="https://faramesh.dev/gpg-key.asc"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║       Faramesh Guard - GPG Release Key Generation            ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo

# Create directory
mkdir -p "$GPG_DIR"
chmod 700 "$GPG_DIR"

# Generate key using batch mode
cat > "$GPG_DIR/keygen-params.txt" << EOF
%echo Generating Faramesh Guard Release Signing Key
Key-Type: EDDSA
Key-Curve: ed25519
Key-Usage: sign
Subkey-Type: ECDH
Subkey-Curve: cv25519
Subkey-Usage: encrypt
Name-Real: $KEY_NAME
Name-Email: $KEY_EMAIL
Name-Comment: $KEY_COMMENT
Expire-Date: 2y
%no-protection
%commit
%echo Done
EOF

echo "🔑 Generating GPG key..."
echo

# Check if key already exists
if gpg --list-keys "$KEY_EMAIL" 2>/dev/null; then
    echo "⚠️  Key for $KEY_EMAIL already exists!"
    echo "   Use 'gpg --delete-secret-and-public-keys $KEY_EMAIL' to remove it first."
    exit 1
fi

# Generate key
gpg --batch --gen-key "$GPG_DIR/keygen-params.txt" 2>&1

# Get key ID
KEY_ID=$(gpg --list-keys --keyid-format=long "$KEY_EMAIL" 2>/dev/null | grep -E "^\s+[A-F0-9]{16}" | awk '{print $1}' | head -1)

if [ -z "$KEY_ID" ]; then
    # Try alternate parsing
    KEY_ID=$(gpg --list-keys --keyid-format=long "$KEY_EMAIL" | grep -oE '[A-F0-9]{40}' | head -1)
fi

echo
echo "✅ GPG Key Generated!"
echo "   Key ID: $KEY_ID"
echo

# Export public key
PUBLIC_KEY_FILE="$GPG_DIR/faramesh-guard-release.asc"
gpg --armor --export "$KEY_EMAIL" > "$PUBLIC_KEY_FILE"
echo "📄 Public key exported to: $PUBLIC_KEY_FILE"

# Export private key (for backup)
PRIVATE_KEY_FILE="$GPG_DIR/faramesh-guard-release.secret.asc"
gpg --armor --export-secret-keys "$KEY_EMAIL" > "$PRIVATE_KEY_FILE"
chmod 600 "$PRIVATE_KEY_FILE"
echo "🔐 Private key exported to: $PRIVATE_KEY_FILE"

# Generate fingerprint file
FINGERPRINT=$(gpg --fingerprint "$KEY_EMAIL" | grep -E "^\s+[A-F0-9 ]{50}" | tr -d ' ')
echo "$FINGERPRINT" > "$GPG_DIR/fingerprint.txt"
echo "🔖 Fingerprint: $FINGERPRINT"

echo
echo "═══════════════════════════════════════════════════════════════"
echo "Publishing Instructions"
echo "═══════════════════════════════════════════════════════════════"
echo
echo "1. Upload public key to website:"
echo "   cp $PUBLIC_KEY_FILE ./docs/gpg-key.asc"
echo "   # Deploy to https://faramesh.dev/gpg-key.asc"
echo
echo "2. Add to GitHub secrets for CI signing:"
echo "   cat $PRIVATE_KEY_FILE | base64 | pbcopy"
echo "   # Paste as GPG_PRIVATE_KEY secret"
echo
echo "3. Configure Git to sign tags:"
echo "   git config --global user.signingkey $KEY_ID"
echo "   git config --global tag.gpgSign true"
echo
echo "4. Sign a release:"
echo "   gpg --armor --detach-sign guard-macos-arm64.zip"
echo
echo "5. Verify a signature:"
echo "   gpg --verify guard-macos-arm64.zip.asc guard-macos-arm64.zip"
echo

# Cleanup
rm -f "$GPG_DIR/keygen-params.txt"

echo "✅ GPG setup complete!"
