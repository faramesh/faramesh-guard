# Custom Domain Setup for Guard Workers

## DNS Records Required

You need to add these DNS records in your Cloudflare dashboard for `faramesh.dev`:

### 1. updates.faramesh.dev (TUF Repository)

```
Type: CNAME
Name: updates
Target: guard-updates.faramesh.workers.dev
Proxy: Enabled (orange cloud)
```

### 2. transparency.faramesh.dev (Merkle Log)

```
Type: CNAME
Name: transparency
Target: guard-transparency.faramesh.workers.dev
Proxy: Enabled (orange cloud)
```

## Steps in Cloudflare Dashboard

1. Go to https://dash.cloudflare.com
2. Select `faramesh.dev` zone
3. Click "DNS" → "Records"
4. Add the CNAME records above
5. Enable proxy (orange cloud) for both

## Alternative: Using Wrangler Custom Domains

Once DNS is configured and proxied, uncomment these lines in wrangler.toml:

### guard-updates/wrangler.toml
```toml
routes = [
  { pattern = "updates.faramesh.dev", custom_domain = true }
]
```

### guard-transparency/wrangler.toml
```toml
routes = [
  { pattern = "transparency.faramesh.dev", custom_domain = true }
]
```

Then redeploy:
```bash
cd cloud/workers/guard-updates && wrangler deploy
cd cloud/workers/guard-transparency && wrangler deploy
```

## Current Worker URLs (Working Now)

- **TUF Updates**: https://guard-updates.faramesh.workers.dev
- **Transparency Log**: https://guard-transparency.faramesh.workers.dev

## Verification

After DNS setup, test:
```bash
curl https://updates.faramesh.dev/
curl https://transparency.faramesh.dev/
```
