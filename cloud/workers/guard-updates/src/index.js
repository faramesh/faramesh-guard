/**
 * Guard Updates Worker - TUF Repository
 *
 * Hosts The Update Framework (TUF) repository for secure updates.
 * Every Guard instance pulls from here to get:
 * - Signed metadata (root.json, targets.json, snapshot.json, timestamp.json)
 * - Detection rules & prompt injection patterns
 * - Threat intel IOCs
 * - ML models & calibration files
 * - Policy packs
 * - Minimum version requirements
 * - Emergency blocklists (kill-switch)
 *
 * Security: All artifacts are signed. Guards verify signatures locally.
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, HEAD, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, X-Guard-Version, X-Guard-Instance',
};

const CACHE_CONTROL = {
  // TUF metadata - short cache (timestamp changes frequently)
  'timestamp.json': 'public, max-age=60',
  'snapshot.json': 'public, max-age=300',
  'targets.json': 'public, max-age=3600',
  'root.json': 'public, max-age=86400',
  // Targets - longer cache (immutable once published)
  'default': 'public, max-age=3600, immutable',
};

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    // Only allow GET/HEAD
    if (request.method !== 'GET' && request.method !== 'HEAD') {
      return jsonResponse({ error: 'Method not allowed' }, 405);
    }

    // Route handling
    if (path === '/' || path === '/health') {
      return jsonResponse({
        service: 'guard-updates',
        version: '1.0.0',
        status: 'healthy',
        tuf_version: 1,
        endpoints: {
          metadata: '/v1/metadata/',
          targets: '/v1/targets/',
        },
      });
    }

    // TUF Metadata endpoints
    if (path.startsWith('/v1/metadata/')) {
      return await serveTufMetadata(request, env, path);
    }

    // TUF Targets endpoints
    if (path.startsWith('/v1/targets/')) {
      return await serveTufTarget(request, env, path);
    }

    // Legacy paths (redirect to v1)
    if (path === '/metadata' || path.startsWith('/metadata/')) {
      const newPath = path.replace('/metadata', '/v1/metadata');
      return Response.redirect(new URL(newPath, url).toString(), 301);
    }

    return jsonResponse({ error: 'Not found' }, 404);
  },
};

/**
 * Serve TUF metadata files (root.json, targets.json, etc.)
 */
async function serveTufMetadata(request, env, path) {
  // Extract filename: /v1/metadata/timestamp.json -> timestamp.json
  const filename = path.replace('/v1/metadata/', '');

  if (!filename || filename.includes('..')) {
    return jsonResponse({ error: 'Invalid path' }, 400);
  }

  // Valid TUF metadata files
  const validMetadata = [
    'root.json',
    'snapshot.json',
    'targets.json',
    'timestamp.json',
    // Versioned metadata
    /^\d+\.root\.json$/,
    /^\d+\.snapshot\.json$/,
    /^\d+\.targets\.json$/,
  ];

  const isValid = validMetadata.some(pattern =>
    typeof pattern === 'string' ? pattern === filename : pattern.test(filename)
  );

  if (!isValid) {
    return jsonResponse({ error: 'Invalid metadata file' }, 400);
  }

  // Try R2 bucket
  const key = `metadata/${filename}`;
  const object = await env.TUF_BUCKET.get(key);

  if (!object) {
    return jsonResponse({ error: 'Metadata not found' }, 404);
  }

  // Determine cache control
  let cacheControl = CACHE_CONTROL['default'];
  for (const [pattern, cc] of Object.entries(CACHE_CONTROL)) {
    if (filename.endsWith(pattern)) {
      cacheControl = cc;
      break;
    }
  }

  const headers = {
    ...CORS_HEADERS,
    'Content-Type': 'application/json',
    'Cache-Control': cacheControl,
    'X-TUF-Role': filename.replace('.json', '').replace(/^\d+\./, ''),
  };

  return new Response(object.body, { headers });
}

/**
 * Serve TUF target files (rules, models, policies, etc.)
 */
async function serveTufTarget(request, env, path) {
  // Extract target path: /v1/targets/rules/prompt-injection.json -> rules/prompt-injection.json
  const targetPath = path.replace('/v1/targets/', '');

  if (!targetPath || targetPath.includes('..')) {
    return jsonResponse({ error: 'Invalid path' }, 400);
  }

  // Valid target directories
  const validPrefixes = [
    'rules/',           // Detection rules
    'iocs/',            // Threat intel indicators
    'models/',          // ML models
    'policies/',        // Policy packs
    'min_versions.json',
    'emergency_blocklist.json',
    'calibration/',     // Model calibration data
  ];

  const isValid = validPrefixes.some(prefix =>
    targetPath === prefix.replace('/', '') || targetPath.startsWith(prefix)
  );

  if (!isValid) {
    return jsonResponse({ error: 'Invalid target path' }, 400);
  }

  // Try R2 bucket
  const key = `targets/${targetPath}`;
  const object = await env.TUF_BUCKET.get(key);

  if (!object) {
    return jsonResponse({ error: 'Target not found' }, 404);
  }

  // Determine content type
  let contentType = 'application/octet-stream';
  if (targetPath.endsWith('.json')) {
    contentType = 'application/json';
  } else if (targetPath.endsWith('.onnx')) {
    contentType = 'application/x-onnx';
  } else if (targetPath.endsWith('.yaml') || targetPath.endsWith('.yml')) {
    contentType = 'application/x-yaml';
  }

  const headers = {
    ...CORS_HEADERS,
    'Content-Type': contentType,
    'Cache-Control': CACHE_CONTROL['default'],
    'ETag': object.httpEtag,
    'X-TUF-Target': targetPath,
  };

  // Add custom metadata if present
  if (object.customMetadata) {
    if (object.customMetadata.hash_sha256) {
      headers['X-TUF-Hash-SHA256'] = object.customMetadata.hash_sha256;
    }
    if (object.customMetadata.version) {
      headers['X-TUF-Version'] = object.customMetadata.version;
    }
  }

  return new Response(object.body, { headers });
}

function jsonResponse(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), {
    status,
    headers: {
      ...CORS_HEADERS,
      'Content-Type': 'application/json',
    },
  });
}
