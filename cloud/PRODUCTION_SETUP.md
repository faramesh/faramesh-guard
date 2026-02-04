# Faramesh Guard - Production Deployment Guide

## What You Need to Provide

To launch Guard to production, you need to set up the following infrastructure and provide the corresponding credentials.

---

## 1. Cloudflare Account Setup

### Required Resources

| Resource | Purpose | Name |
|----------|---------|------|
| **D1 Database** | Fleet management & telemetry metadata | `guard-fleet` |
| **R2 Bucket #1** | Telemetry storage | `guard-telemetry` |
| **R2 Bucket #2** | Support bundles | `guard-support` |
| **Worker #1** | Ingest (heartbeats, telemetry, proofs) | `guard-ingest` |
| **Worker #2** | Device enrollment | `guard-enroll` |
| **Worker #3** | Support bundle uploads | `guard-support` |

### Setup Commands

```bash
# Login to Cloudflare
wrangler login

# Create D1 database
wrangler d1 create guard-fleet
# Note the database_id from output

# Create R2 buckets
wrangler r2 bucket create guard-telemetry
wrangler r2 bucket create guard-support

# Initialize database schema
cd faramesh-guard/cloud/workers/guard-ingest
pnpm install
wrangler d1 execute guard-fleet --file=schema.sql

# Deploy workers (update database_id in each wrangler.toml first!)
cd ../guard-ingest && pnpm install && wrangler deploy
cd ../guard-enroll && pnpm install && wrangler deploy
cd ../guard-support && pnpm install && wrangler deploy

# Set secrets for each worker
wrangler secret put AUTH_TOKEN --name guard-ingest
wrangler secret put AUTH_TOKEN --name guard-enroll
wrangler secret put AUTH_TOKEN --name guard-support
```

---

## 2. Environment Variables for Guard Daemon

After deploying workers, set these in `faramesh-guard/daemon/config/cloud_config.py` or as environment variables:

```bash
# Primary endpoints
export GUARD_INGEST_URL="https://guard-ingest.<your-subdomain>.workers.dev"
export GUARD_ENROLL_URL="https://guard-enroll.<your-subdomain>.workers.dev"
export GUARD_SUPPORT_URL="https://guard-support.<your-subdomain>.workers.dev"

# TUF repository (GitHub Releases or self-hosted)
export GUARD_TUF_METADATA_URL="https://updates.faramesh.dev/guard/v1"
export GUARD_ARTIFACT_BASE_URL="https://github.com/faramesh/faramesh-guard/releases/download"

# Authentication
export GUARD_AUTH_TOKEN="<your-secret-auth-token>"
```

---

## 3. TUF Repository Setup (Secure Updates)

TUF (The Update Framework) ensures signed, tamper-proof updates.

### Option A: GitHub Releases (Recommended)

1. Create GitHub releases with signed artifacts
2. Set `GUARD_ARTIFACT_BASE_URL=https://github.com/your-org/guard/releases/download`
3. TUF metadata hosted alongside or on updates subdomain

### Option B: Self-Hosted on R2

```bash
# Create TUF bucket
wrangler r2 bucket create guard-updates

# Upload signed artifacts
wrangler r2 object put guard-updates/v1.0.0/guard-darwin-arm64.pkg --file=dist/guard.pkg
wrangler r2 object put guard-updates/metadata/root.json --file=tuf/root.json
wrangler r2 object put guard-updates/metadata/targets.json --file=tuf/targets.json
```

---

## 4. Code Signing Requirements

For Guard to appear as legitimate security software:

### macOS
- **Developer ID Application Certificate** - For signing the daemon
- **Developer ID Installer Certificate** - For signing the .pkg
- **Notarization** - Apple's notarization service

```bash
# Sign the app
codesign --sign "Developer ID Application: Your Company" \
  --options runtime \
  --entitlements entitlements.plist \
  --timestamp \
  Guard.app

# Create and sign package
pkgbuild --sign "Developer ID Installer: Your Company" \
  --identifier com.faramesh.guard \
  --version 1.0.0 \
  --root /path/to/files \
  Guard.pkg

# Notarize
xcrun notarytool submit Guard.pkg --apple-id you@company.com --team-id TEAMID --wait
```

### Windows
- **EV Code Signing Certificate** - Extended Validation for SmartScreen reputation
- **Authenticode Signing** - Timestamp the signature

### Linux
- **GPG Key** - For signing packages
- **Package Signing** - dpkg-sig, rpm --addsign

---

## 5. DNS & Domain Setup

| Subdomain | Purpose | Points To |
|-----------|---------|-----------|
| `guard-ingest.company.ai` | Telemetry/heartbeats | Cloudflare Worker |
| `guard-enroll.company.ai` | Device enrollment | Cloudflare Worker |
| `guard-support.company.ai` | Support bundles | Cloudflare Worker |
| `updates.company.ai` | TUF repository | R2 bucket / GitHub |
| `transparency.company.ai` | Audit log (optional) | Rekor / Custom |

### Custom Domains for Workers

Update each `wrangler.toml`:

```toml
routes = [
  { pattern = "guard-ingest.company.ai", custom_domain = true }
]
```

---

## 6. Credentials Checklist

| Credential | Where to Set | Value |
|------------|--------------|-------|
| `AUTH_TOKEN` | Wrangler secrets | Generate: `openssl rand -hex 32` |
| `D1_DATABASE_ID` | wrangler.toml files | From `wrangler d1 create` output |
| Developer ID (macOS) | Apple Developer Portal | Certificate + Private Key |
| Notarization Creds | Keychain / CI | App-specific password |
| EV Code Signing (Win) | Certificate store | .pfx file + password |
| GPG Key (Linux) | GPG keyring | Key ID |

---

## 7. CI/CD Secrets (GitHub Actions)

```yaml
# .github/workflows/release.yml secrets
secrets:
  # Cloudflare
  CLOUDFLARE_API_TOKEN: ${{ secrets.CLOUDFLARE_API_TOKEN }}

  # macOS signing
  APPLE_CERTIFICATE_P12: ${{ secrets.APPLE_CERTIFICATE_P12 }}
  APPLE_CERTIFICATE_PASSWORD: ${{ secrets.APPLE_CERTIFICATE_PASSWORD }}
  APPLE_ID: ${{ secrets.APPLE_ID }}
  APPLE_TEAM_ID: ${{ secrets.APPLE_TEAM_ID }}
  APPLE_APP_PASSWORD: ${{ secrets.APPLE_APP_PASSWORD }}

  # Windows signing
  WINDOWS_CERTIFICATE_P12: ${{ secrets.WINDOWS_CERTIFICATE_P12 }}
  WINDOWS_CERTIFICATE_PASSWORD: ${{ secrets.WINDOWS_CERTIFICATE_PASSWORD }}

  # TUF signing
  TUF_SIGNING_KEY: ${{ secrets.TUF_SIGNING_KEY }}

  # Guard API
  GUARD_AUTH_TOKEN: ${{ secrets.GUARD_AUTH_TOKEN }}
```

---

## 8. Endpoint Summary

After setup, Guard instances connect to:

```
┌─────────────────────────────────────────────────────────────────┐
│                     PULL LANE (Updates)                         │
├─────────────────────────────────────────────────────────────────┤
│  updates.company.ai/guard/v1/                                   │
│    ├── metadata/                                                │
│    │   ├── root.json         (TUF root of trust)               │
│    │   ├── snapshot.json     (Manifest snapshot)               │
│    │   ├── targets.json      (Artifact hashes)                 │
│    │   └── timestamp.json    (Freshness check)                 │
│    └── targets/                                                 │
│        ├── guard-darwin-arm64-1.0.0.pkg                        │
│        └── guard-darwin-x64-1.0.0.pkg                          │
└─────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────┐
│                     PUSH LANE (Telemetry)                       │
├─────────────────────────────────────────────────────────────────┤
│  guard-enroll.company.ai                                        │
│    └── POST /enroll          (New device registration)          │
│                                                                 │
│  guard-ingest.company.ai                                        │
│    ├── POST /heartbeat       (Every 60s, status update)        │
│    ├── POST /telemetry       (Batched events)                  │
│    └── POST /proof           (Interception proofs)             │
│                                                                 │
│  guard-support.company.ai                                       │
│    └── POST /bundle          (Diagnostic uploads)              │
└─────────────────────────────────────────────────────────────────┘
```

---

## 9. Verification Checklist

After deployment, verify:

- [ ] Workers respond to `/health` endpoint
- [ ] D1 database accepts writes (test enrollment)
- [ ] R2 buckets accept uploads (test telemetry)
- [ ] Custom domains have valid SSL certificates
- [ ] Guard daemon can enroll successfully
- [ ] Heartbeats appear in D1 `instances` table
- [ ] macOS package passes `spctl --assess --verbose Guard.pkg`
- [ ] macOS app passes `codesign --verify --deep --strict Guard.app`

---

## 10. Quick Start Commands

```bash
# 1. Deploy infrastructure
cd faramesh-guard/cloud/workers
for worker in guard-ingest guard-enroll guard-support; do
  cd $worker && pnpm install && cd ..
done

# Update database_id in all wrangler.toml files
wrangler d1 execute guard-fleet --file=guard-ingest/schema.sql

# 2. Deploy workers
cd guard-ingest && wrangler deploy && cd ..
cd guard-enroll && wrangler deploy && cd ..
cd guard-support && wrangler deploy && cd ..

# 3. Set secrets
for worker in guard-ingest guard-enroll guard-support; do
  wrangler secret put AUTH_TOKEN --name $worker
done

# 4. Verify
curl https://guard-ingest.<subdomain>.workers.dev/health
curl https://guard-enroll.<subdomain>.workers.dev/health
curl https://guard-support.<subdomain>.workers.dev/health
```

---

## Need Help?

1. **Cloudflare Issues**: Check `wrangler tail <worker-name>` for logs
2. **Signing Issues**: Ensure certificates are properly installed and not expired
3. **TUF Issues**: Verify metadata signatures and delegation chain
