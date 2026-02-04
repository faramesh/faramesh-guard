/**
 * Guard Transparency Worker - Public Merkle Log
 *
 * Implements a Certificate Transparency / Rekor style append-only log.
 *
 * What gets logged (hashes only, not data):
 * - Policy packs: Prove rules weren't secretly changed
 * - ML models: Prove no hidden backdoor swaps
 * - Emergency blocklists: Kill-switch use is visible
 * - TUF targets metadata: Prove no targeted update attacks
 * - Guard releases: Supply-chain integrity
 * - Audit log roots: Decision logs are tamper-evident
 *
 * This is PROOF, not control. Anyone can verify.
 */

const CORS_HEADERS = {
  'Access-Control-Allow-Origin': '*',
  'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
  'Access-Control-Allow-Headers': 'Content-Type, Authorization',
};

// Empty SHA-256 hash (precomputed)
const EMPTY_HASH = 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855';

export default {
  async fetch(request, env, ctx) {
    const url = new URL(request.url);
    const path = url.pathname;

    // CORS preflight
    if (request.method === 'OPTIONS') {
      return new Response(null, { headers: CORS_HEADERS });
    }

    try {
      // Health check
      if (path === '/' || path === '/health') {
        const stats = await getTreeStats(env);
        return jsonResponse({
          service: 'guard-transparency',
          version: '1.0.0',
          status: 'healthy',
          tree: {
            size: stats.tree_size,
            root_hash: stats.root_hash,
            timestamp: stats.timestamp,
          },
          endpoints: {
            log: 'GET /v1/log - Current tree state',
            entry: 'GET /v1/log/entry/:index - Get entry by index',
            proof: 'GET /v1/log/proof/:index - Inclusion proof',
            consistency: 'GET /v1/log/consistency/:from/:to - Consistency proof',
            submit: 'POST /v1/submit - Add entry (authenticated)',
          },
        });
      }

      // Public read endpoints
      if (request.method === 'GET') {
        if (path === '/v1/log') {
          return await getLogState(env);
        }
        if (path.startsWith('/v1/log/entry/')) {
          const index = parseInt(path.split('/').pop());
          return await getEntry(env, index);
        }
        if (path.startsWith('/v1/log/proof/')) {
          const index = parseInt(path.split('/').pop());
          return await getInclusionProof(env, index);
        }
        if (path.match(/^\/v1\/log\/consistency\/\d+\/\d+$/)) {
          const parts = path.split('/');
          const from = parseInt(parts[4]);
          const to = parseInt(parts[5]);
          return await getConsistencyProof(env, from, to);
        }
        if (path === '/v1/log/entries') {
          const start = parseInt(url.searchParams.get('start') || '0');
          const count = Math.min(parseInt(url.searchParams.get('count') || '100'), 1000);
          return await getEntries(env, start, count);
        }
      }

      // Authenticated write endpoint
      if (request.method === 'POST' && path === '/v1/submit') {
        return await submitEntry(request, env);
      }

      return jsonResponse({ error: 'Not found' }, 404);

    } catch (error) {
      console.error('Error:', error);
      return jsonResponse({ error: 'Internal server error' }, 500);
    }
  },
};

/**
 * Get current tree state (root hash, size)
 */
async function getLogState(env) {
  const stats = await getTreeStats(env);

  return jsonResponse({
    tree_size: stats.tree_size,
    root_hash: stats.root_hash,
    timestamp: stats.timestamp,
    signed_tree_head: stats.signed_tree_head,
  });
}

/**
 * Get tree statistics from database
 */
async function getTreeStats(env) {
  const result = await env.MERKLE_DB.prepare(`
    SELECT
      (SELECT COUNT(*) FROM log_entries) as tree_size,
      (SELECT value FROM tree_metadata WHERE key = 'root_hash') as root_hash,
      (SELECT value FROM tree_metadata WHERE key = 'timestamp') as timestamp,
      (SELECT value FROM tree_metadata WHERE key = 'signed_tree_head') as signed_tree_head
  `).first();

  return {
    tree_size: result?.tree_size || 0,
    root_hash: result?.root_hash || EMPTY_HASH,
    timestamp: result?.timestamp || new Date().toISOString(),
    signed_tree_head: result?.signed_tree_head || null,
  };
}

/**
 * Get a single log entry by index
 */
async function getEntry(env, index) {
  if (isNaN(index) || index < 0) {
    return jsonResponse({ error: 'Invalid index' }, 400);
  }

  const entry = await env.MERKLE_DB.prepare(`
    SELECT * FROM log_entries WHERE leaf_index = ?
  `).bind(index).first();

  if (!entry) {
    return jsonResponse({ error: 'Entry not found' }, 404);
  }

  return jsonResponse({
    leaf_index: entry.leaf_index,
    leaf_hash: entry.leaf_hash,
    entry_type: entry.entry_type,
    artifact_hash: entry.artifact_hash,
    artifact_type: entry.artifact_type,
    version: entry.version,
    timestamp: entry.timestamp,
    metadata: JSON.parse(entry.metadata || '{}'),
  });
}

/**
 * Get entries in a range
 */
async function getEntries(env, start, count) {
  const entries = await env.MERKLE_DB.prepare(`
    SELECT * FROM log_entries
    WHERE leaf_index >= ?
    ORDER BY leaf_index ASC
    LIMIT ?
  `).bind(start, count).all();

  return jsonResponse({
    entries: entries.results.map(e => ({
      leaf_index: e.leaf_index,
      leaf_hash: e.leaf_hash,
      entry_type: e.entry_type,
      artifact_hash: e.artifact_hash,
      artifact_type: e.artifact_type,
      version: e.version,
      timestamp: e.timestamp,
    })),
  });
}

/**
 * Get Merkle inclusion proof for an entry
 */
async function getInclusionProof(env, index) {
  const stats = await getTreeStats(env);

  if (index >= stats.tree_size) {
    return jsonResponse({ error: 'Index out of range' }, 400);
  }

  // Calculate Merkle audit path
  const proof = await calculateInclusionProof(env, index, stats.tree_size);

  return jsonResponse({
    leaf_index: index,
    tree_size: stats.tree_size,
    root_hash: stats.root_hash,
    audit_path: proof,
  });
}

/**
 * Get consistency proof between two tree sizes
 */
async function getConsistencyProof(env, from, to) {
  const stats = await getTreeStats(env);

  if (from > to || to > stats.tree_size) {
    return jsonResponse({ error: 'Invalid range' }, 400);
  }

  const proof = await calculateConsistencyProof(env, from, to);

  return jsonResponse({
    first_tree_size: from,
    second_tree_size: to,
    consistency_path: proof,
  });
}

/**
 * Submit a new entry to the log (authenticated)
 */
async function submitEntry(request, env) {
  // Verify authentication
  const authHeader = request.headers.get('Authorization');
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return jsonResponse({ error: 'Unauthorized' }, 401);
  }

  const token = authHeader.slice(7);
  if (token !== env.SUBMIT_TOKEN) {
    return jsonResponse({ error: 'Invalid token' }, 403);
  }

  // Parse entry
  const body = await request.json();

  const requiredFields = ['artifact_hash', 'artifact_type'];
  for (const field of requiredFields) {
    if (!body[field]) {
      return jsonResponse({ error: `Missing required field: ${field}` }, 400);
    }
  }

  // Validate artifact type
  const validTypes = [
    'policy',
    'model',
    'blocklist',
    'tuf_targets',
    'release',
    'audit_root',
    'rule',
    'ioc',
  ];

  if (!validTypes.includes(body.artifact_type)) {
    return jsonResponse({ error: `Invalid artifact_type. Must be one of: ${validTypes.join(', ')}` }, 400);
  }

  // Get current tree size
  const stats = await getTreeStats(env);
  const newIndex = stats.tree_size;

  // Create leaf hash (RFC 6962 style)
  const timestamp = new Date().toISOString();
  const leafData = JSON.stringify({
    artifact_hash: body.artifact_hash,
    artifact_type: body.artifact_type,
    version: body.version || null,
    timestamp: timestamp,
  });
  const leafHash = await sha256('\x00' + leafData);

  // Insert entry
  await env.MERKLE_DB.prepare(`
    INSERT INTO log_entries (
      leaf_index, leaf_hash, entry_type, artifact_hash,
      artifact_type, version, timestamp, metadata
    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
  `).bind(
    newIndex,
    leafHash,
    'v1',
    body.artifact_hash,
    body.artifact_type,
    body.version || null,
    timestamp,
    JSON.stringify(body.metadata || {}),
  ).run();

  // Recalculate root hash
  const newRoot = await recalculateRoot(env, newIndex + 1);

  // Update metadata
  await env.MERKLE_DB.batch([
    env.MERKLE_DB.prepare(`
      INSERT OR REPLACE INTO tree_metadata (key, value) VALUES ('root_hash', ?)
    `).bind(newRoot),
    env.MERKLE_DB.prepare(`
      INSERT OR REPLACE INTO tree_metadata (key, value) VALUES ('timestamp', ?)
    `).bind(timestamp),
    env.MERKLE_DB.prepare(`
      INSERT OR REPLACE INTO tree_metadata (key, value) VALUES ('tree_size', ?)
    `).bind(String(newIndex + 1)),
  ]);

  return jsonResponse({
    status: 'logged',
    leaf_index: newIndex,
    leaf_hash: leafHash,
    tree_size: newIndex + 1,
    root_hash: newRoot,
    timestamp: timestamp,
  }, 201);
}

/**
 * Calculate Merkle inclusion proof
 */
async function calculateInclusionProof(env, index, treeSize) {
  const proof = [];
  let n = index;
  let size = treeSize;

  while (size > 1) {
    const siblingIndex = n ^ 1; // XOR to get sibling
    if (siblingIndex < size) {
      const sibling = await env.MERKLE_DB.prepare(`
        SELECT leaf_hash FROM log_entries WHERE leaf_index = ?
      `).bind(siblingIndex).first();

      if (sibling) {
        proof.push({
          hash: sibling.leaf_hash,
          position: n % 2 === 0 ? 'right' : 'left',
        });
      }
    }
    n = Math.floor(n / 2);
    size = Math.ceil(size / 2);
  }

  return proof;
}

/**
 * Calculate consistency proof between tree sizes
 */
async function calculateConsistencyProof(env, from, to) {
  // Simplified consistency proof
  // For production, implement full RFC 6962 algorithm
  const proof = [];

  // Get boundary hashes
  if (from > 0) {
    const boundary = await env.MERKLE_DB.prepare(`
      SELECT leaf_hash FROM log_entries WHERE leaf_index = ?
    `).bind(from - 1).first();

    if (boundary) {
      proof.push({ hash: boundary.leaf_hash, type: 'boundary' });
    }
  }

  return proof;
}

/**
 * Recalculate Merkle root from all entries
 */
async function recalculateRoot(env, treeSize) {
  if (treeSize === 0) {
    return EMPTY_HASH;
  }

  // Get all leaf hashes
  const entries = await env.MERKLE_DB.prepare(`
    SELECT leaf_hash FROM log_entries ORDER BY leaf_index ASC
  `).all();

  let hashes = entries.results.map(e => e.leaf_hash);

  // Build tree bottom-up
  while (hashes.length > 1) {
    const newLevel = [];
    for (let i = 0; i < hashes.length; i += 2) {
      if (i + 1 < hashes.length) {
        newLevel.push(await sha256('\x01' + hashes[i] + hashes[i + 1]));
      } else {
        newLevel.push(hashes[i]); // Odd node promoted
      }
    }
    hashes = newLevel;
  }

  return hashes[0];
}

/**
 * SHA-256 hash helper (Web Crypto API)
 */
async function sha256(data) {
  const encoder = new TextEncoder();
  const dataBuffer = encoder.encode(data);
  const hashBuffer = await crypto.subtle.digest('SHA-256', dataBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
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
