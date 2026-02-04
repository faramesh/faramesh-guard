/**
 * Faramesh Guard - Ingest Worker
 * Handles heartbeats, telemetry, and interception proofs
 */

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;

    // CORS
    const headers = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Instance-ID',
      'Content-Type': 'application/json'
    };

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers });
    }

    try {
      // Health check
      if (path === '/health') {
        return new Response(JSON.stringify({ status: 'ok', service: 'guard-ingest' }), { headers });
      }

      // Heartbeat - device status update
      if (method === 'POST' && path === '/heartbeat') {
        const body = await req.json();
        const now = new Date().toISOString();

        // Upsert instance
        await env.guard_fleet.prepare(`
          INSERT INTO instances (instance_id, version, platform, last_heartbeat, protection_enabled, uptime_seconds, total_requests, approved, denied, pending)
          VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
          ON CONFLICT(instance_id) DO UPDATE SET
            version = excluded.version,
            last_heartbeat = excluded.last_heartbeat,
            protection_enabled = excluded.protection_enabled,
            uptime_seconds = excluded.uptime_seconds,
            total_requests = excluded.total_requests,
            approved = excluded.approved,
            denied = excluded.denied,
            pending = excluded.pending
        `).bind(
          body.instance_id,
          body.version || '1.0.0',
          body.platform || 'unknown',
          now,
          body.protection_enabled ? 1 : 0,
          body.uptime_seconds || 0,
          body.stats?.total_requests || 0,
          body.stats?.approved || 0,
          body.stats?.denied || 0,
          body.stats?.pending || 0
        ).run();

        // Check for pending commands
        const commands = await env.guard_fleet.prepare(`
          SELECT id, command_type, command_data FROM pending_commands
          WHERE (instance_id = ? OR instance_id = '*')
            AND executed_at IS NULL
            AND (expires_at IS NULL OR expires_at > datetime('now'))
          LIMIT 10
        `).bind(body.instance_id).all();

        return new Response(JSON.stringify({
          status: 'ok',
          commands: commands.results.map(c => ({
            id: c.id,
            type: c.command_type,
            data: c.command_data ? JSON.parse(c.command_data) : null
          }))
        }), { headers });
      }

      // Telemetry - batched events
      if (method === 'POST' && path === '/telemetry') {
        const instanceId = req.headers.get('X-Instance-ID') || 'unknown';
        const id = `${Date.now()}_${instanceId.slice(0, 8)}_${crypto.randomUUID().slice(0, 8)}`;
        const data = await req.arrayBuffer();

        await env.guard_telemetry.put(`telemetry/${id}.bin`, data, {
          customMetadata: {
            instance_id: instanceId,
            uploaded_at: new Date().toISOString()
          }
        });

        return new Response(JSON.stringify({ status: 'stored', id }), { headers });
      }

      // Interception proof - cryptographic evidence
      if (method === 'POST' && path === '/proof') {
        const body = await req.json();

        await env.guard_fleet.prepare(`
          INSERT INTO interception_proofs (instance_id, timestamp, action_hash, decision, signature, policy_hash)
          VALUES (?, ?, ?, ?, ?, ?)
        `).bind(
          body.instance_id,
          body.timestamp,
          body.action_hash,
          body.decision,
          body.signature,
          body.policy_hash || null
        ).run();

        return new Response(JSON.stringify({ status: 'recorded' }), { headers });
      }

      return new Response(JSON.stringify({ error: 'Not found' }), { status: 404, headers });
    } catch (error) {
      console.error('Ingest error:', error);
      return new Response(JSON.stringify({ error: 'Internal error' }), { status: 500, headers });
    }
  }
};
