# Security & Verification

## Unsigned Software

Faramesh Guard is currently **unsigned** software.

This means:
- **macOS**: Gatekeeper will block it. Right-click → Open to bypass.
- **Windows**: SmartScreen will warn. Click "More info" → "Run anyway"
- **Linux**: No restrictions.

## Verify Downloads

Every release includes `checksums.txt` with SHA256 hashes.

```bash
# Download release + checksums
curl -LO https://github.com/faramesh/faramesh-guard/releases/latest/download/guard-macos-arm64.zip
curl -LO https://github.com/faramesh/faramesh-guard/releases/latest/download/checksums.txt

# Verify
sha256sum -c checksums.txt
```

## GPG Signatures (Coming Soon)

We plan to sign releases with GPG. When available:

### Import Our Public Key
```bash
# From keyserver
gpg --keyserver keyserver.ubuntu.com --recv-keys XXXXXXXX

# Or from file
curl -sSL https://faramesh.dev/gpg-key.asc | gpg --import
```

### Verify Signature
```bash
gpg --verify checksums.txt.sig checksums.txt
```

## Generating Your Own GPG Key (For Forks)

If you fork Guard and want to sign your own releases:

```bash
# Generate key (choose RSA 4096, no expiry for signing)
gpg --full-generate-key

# List keys to get your key ID
gpg --list-secret-keys --keyid-format SHORT
# Output: sec   rsa4096/XXXXXXXX 2024-01-01

# Export public key
gpg --armor --export XXXXXXXX > guard-signing-key.asc

# Sign a file
gpg --detach-sign --armor checksums.txt
# Creates checksums.txt.asc

# Upload public key to keyserver
gpg --keyserver keyserver.ubuntu.com --send-keys XXXXXXXX
```

### Publish Your Key

1. **Keyserver**: `gpg --keyserver keyserver.ubuntu.com --send-keys XXXXXXXX`
2. **Website**: Host the `.asc` file at a stable URL
3. **README**: Document the key fingerprint

### Linux Package Signing

**Debian (.deb):**
```bash
dpkg-sig --sign builder guard.deb
```

**RPM (.rpm):**
```bash
rpm --addsign guard.rpm
```

## Reporting Vulnerabilities

Email: security@faramesh.dev

Do NOT open public issues for security vulnerabilities.

## Trust Model

Guard is designed to be **inspectable**:

1. **Open Source**: All code is public
2. **Deterministic Builds**: (planned) Reproduce binaries from source
3. **Transparency Log**: All decisions are hash-chained
4. **No Hidden Network Calls**: Telemetry is opt-in and documented

## Known Limitations

- No code signing = OS warnings on first run
- No notarization = macOS quarantine flag
- Building from source is the most trusted path
