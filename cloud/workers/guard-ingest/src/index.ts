/**
 * Faramesh Guard - Ingest Worker
 *
 * Cloudflare Worker for receiving Guard telemetry, heartbeats, and interception proofs.
 *
 * Endpoints:
 *   POST /heartbeat     - Receive heartbeats from Guard instances
 *   POST /telemetry     - Receive batched telemetry events
 *   POST /proof         - Receive interception proofs (cryptographic evidence)
 *   GET  /health        - Health check
 *
 * Setup:
 *   1. Create R2 bucket: guard-telemetry
 *   2. Create D1 database: guard-fleet
 *   3. Set secrets: AUTH_TOKEN
 *   4. Deploy: wrangler deploy
 */

export interface Env {
  TELEMETRY_BUCKET: R2Bucket;
  FLEET_DB: D1Database;
  AUTH_TOKEN: string;
}

interface HeartbeatPayload {
  instance_id: string;
  version: string;
  platform: string;
  uptime_seconds: number;
  protection_enabled: boolean;
  protection_mode: string;
  stats: {
    total_requests: number;
    approved: number;
    denied: number;
    pending: number;
    cache_hits: number;
  };
  ml_status?: {
    model_version: string;
    avg_risk_score: number;
    evaluations_24h: number;
  };
  policy_hash?: string;
}

interface TelemetryBatch {
  version: string;
  session_id: string;
  instance_id: string;
  timestamp: number;
  events: TelemetryEvent[];
}

interface TelemetryEvent {
  type: string;
  ts: number;
  sid: string;
  data: Record<string, unknown>;
}

interface InterceptionProof {
  instance_id: string;
  timestamp: number;
  action_hash: string;
  decision: 'allow' | 'deny' | 'pending';
  signature: string;
  policy_hash: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);

    // Health check (no auth required)
    if (url.pathname === '/health' && request.method === 'GET') {
      return new Response(JSON.stringify({ status: 'ok', service: 'guard-ingest' }), {
        headers: { 'Content-Type': 'application/json' }
      });
    }

    // Verify auth token
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || authHeader !== `Bearer ${env.AUTH_TOKEN}`) {
      return new Response(JSON.stringify({ error: 'unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' }
      });
    }

    try {
      switch (url.pathname) {
        case '/heartbeat':
          return await handleHeartbeat(request, env, ctx);
        case '/telemetry':
          return await handleTelemetry(request, env, ctx);
        case '/proof':
          return await handleProof(request, env, ctx);
        default:
          return new Response(JSON.stringify({ error: 'not_found' }), {
            status: 404,
            headers: { 'Content-Type': 'application/json' }
          });
      }
    } catch (error) {
      console.error('Ingest error:', error);
      return new Response(JSON.stringify({ error: 'internal_error' }), {
        status: 500,
        headers: { 'Content-Type': 'application/json' }
      });
    }
  },
};

async function handleHeartbeat(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'method_not_allowed' }), { status: 405 });
  }

  const payload = await request.json() as HeartbeatPayload;
  const instanceId = request.headers.get('X-Guard-Instance') || payload.instance_id;
  const version = request.headers.get('X-Guard-Version') || payload.version;
  const platform = request.headers.get('X-Guard-Platform') || payload.platform;

  // Upsert instance in fleet database
  await env.FLEET_DB.prepare(`
    INSERT INTO instances (
      instance_id, version, platform, last_heartbeat,
      protection_enabled, protection_mode, uptime_seconds,
      total_requests, approved, denied, pending,
      policy_hash, ml_model_version
    ) VALUES (?, ?, ?, datetime('now'), ?, ?, ?, ?, ?, ?, ?, ?, ?)
    ON CONFLICT(instance_id) DO UPDATE SET
      version = excluded.version,
      platform = excluded.platform,
      last_heartbeat = excluded.last_heartbeat,
      protection_enabled = excluded.protection_enabled,
      protection_mode = excluded.protection_mode,
      uptime_seconds = excluded.uptime_seconds,
      total_requests = excluded.total_requests,
      approved = excluded.approved,
      denied = excluded.denied,
      pending = excluded.pending,
      policy_hash = excluded.policy_hash,
      ml_model_version = excluded.ml_model_version
  `).bind(
    instanceId,
    version,
    platform,
    payload.protection_enabled ? 1 : 0,
    payload.protection_mode,
    payload.uptime_seconds,
    payload.stats.total_requests,
    payload.stats.approved,
    payload.stats.denied,
    payload.stats.pending,
    payload.policy_hash || null,
    payload.ml_status?.model_version || null
  ).run();

  // Check for any commands to send back (emergency blocklist, forced update, etc.)
  const commands = await getInstanceCommands(env, instanceId);

  return new Response(JSON.stringify({
    status: 'ok',
    server_time: new Date().toISOString(),
    commands
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

async function handleTelemetry(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'method_not_allowed' }), { status: 405 });
  }

  const instanceId = request.headers.get('X-Guard-Instance') || 'unknown';
  const contentEncoding = request.headers.get('Content-Encoding');

  // Handle gzipped data
  let body: ArrayBuffer;
  if (contentEncoding === 'gzip') {
    const stream = new DecompressionStream('gzip');
    const decompressed = request.body?.pipeThrough(stream);
    body = await new Response(decompressed).arrayBuffer();
  } else {
    body = await request.arrayBuffer();
  }

  const batch = JSON.parse(new TextDecoder().decode(body)) as TelemetryBatch;

  // Store in R2 with date-based partitioning
  const date = new Date();
  const key = `telemetry/${date.toISOString().slice(0, 10)}/${instanceId}/${Date.now()}.json`;

  ctx.waitUntil(
    env.TELEMETRY_BUCKET.put(key, JSON.stringify(batch), {
      httpMetadata: { contentType: 'application/json' },
      customMetadata: {
        instance_id: instanceId,
        event_count: String(batch.events.length),
        session_id: batch.session_id,
      }
    })
  );

  // Update aggregate stats (non-blocking)
  ctx.waitUntil(updateAggregateStats(env, batch));

  return new Response(JSON.stringify({
    status: 'ok',
    events_received: batch.events.length
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

async function handleProof(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  if (request.method !== 'POST') {
    return new Response(JSON.stringify({ error: 'method_not_allowed' }), { status: 405 });
  }

  const proof = await request.json() as InterceptionProof;
  const instanceId = request.headers.get('X-Guard-Instance') || proof.instance_id;

  // Store proof in R2 with tamper-evident key
  const date = new Date();
  const proofKey = `proofs/${date.toISOString().slice(0, 10)}/${instanceId}/${proof.action_hash}.json`;

  ctx.waitUntil(
    env.TELEMETRY_BUCKET.put(proofKey, JSON.stringify({
      ...proof,
      received_at: date.toISOString(),
      instance_id: instanceId,
    }), {
      httpMetadata: { contentType: 'application/json' },
      customMetadata: {
        instance_id: instanceId,
        decision: proof.decision,
        action_hash: proof.action_hash,
      }
    })
  );

  // Log to D1 for queryable audit trail
  await env.FLEET_DB.prepare(`
    INSERT INTO interception_proofs (
      instance_id, timestamp, action_hash, decision, signature, policy_hash, received_at
    ) VALUES (?, ?, ?, ?, ?, ?, datetime('now'))
  `).bind(
    instanceId,
    proof.timestamp,
    proof.action_hash,
    proof.decision,
    proof.signature,
    proof.policy_hash
  ).run();

  return new Response(JSON.stringify({
    status: 'ok',
    proof_id: proofKey
  }), {
    headers: { 'Content-Type': 'application/json' }
  });
}

async function getInstanceCommands(env: Env, instanceId: string): Promise<object[]> {
  // Check for pending commands for this instance
  const result = await env.FLEET_DB.prepare(`
    SELECT command_type, command_data, created_at
    FROM pending_commands
    WHERE instance_id = ? OR instance_id = '*'
    AND executed_at IS NULL
    ORDER BY created_at ASC
    LIMIT 10
  `).bind(instanceId).all();

  if (!result.results || result.results.length === 0) {
    return [];
  }

  // Mark commands as sent (don't delete yet - allow retry)
  const commands = result.results.map((row: any) => ({
    type: row.command_type,
    data: JSON.parse(row.command_data || '{}'),
  }));

  return commands;
}

async function updateAggregateStats(env: Env, batch: TelemetryBatch): Promise<void> {
  // Count events by type
  const eventCounts: Record<string, number> = {};
  for (const event of batch.events) {
    eventCounts[event.type] = (eventCounts[event.type] || 0) + 1;
  }

  // Update daily aggregates (non-critical, ignore errors)
  try {
    const date = new Date().toISOString().slice(0, 10);
    for (const [eventType, count] of Object.entries(eventCounts)) {
      await env.FLEET_DB.prepare(`
        INSERT INTO daily_stats (date, event_type, count)
        VALUES (?, ?, ?)
        ON CONFLICT(date, event_type) DO UPDATE SET count = count + excluded.count
      `).bind(date, eventType, count).run();
    }
  } catch (error) {
    console.error('Failed to update aggregate stats:', error);
  }
}
