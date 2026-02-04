/**
 * Faramesh Guard - Enrollment Worker
 * Handles new device registration
 */

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;

    const headers = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
      'Content-Type': 'application/json'
    };

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers });
    }

    try {
      if (path === '/health') {
        return new Response(JSON.stringify({ status: 'ok', service: 'guard-enroll' }), { headers });
      }

      // Enroll new device
      if (method === 'POST' && path === '/enroll') {
        const body = await req.json();

        if (!body.instance_id || !body.version || !body.platform) {
          return new Response(JSON.stringify({
            error: 'Missing required: instance_id, version, platform'
          }), { status: 400, headers });
        }

        const now = new Date().toISOString();

        // Check if already enrolled
        const existing = await env.guard_fleet.prepare(
          'SELECT instance_id FROM instances WHERE instance_id = ?'
        ).bind(body.instance_id).first();

        if (existing) {
          return new Response(JSON.stringify({
            status: 'approved',
            instance_id: body.instance_id,
            message: 'Already enrolled',
            config: { heartbeat_interval: 60, telemetry_enabled: true }
          }), { headers });
        }

        // Create new enrollment
        await env.guard_fleet.prepare(`
          INSERT INTO instances (instance_id, version, platform, first_seen, last_heartbeat, protection_enabled, protection_mode)
          VALUES (?, ?, ?, ?, ?, 1, 'standard')
        `).bind(body.instance_id, body.version, body.platform, now, now).run();

        // Generate simple token
        const token = `guard_${body.instance_id.slice(0, 8)}_${crypto.randomUUID().slice(0, 16)}`;

        return new Response(JSON.stringify({
          status: 'approved',
          instance_id: body.instance_id,
          auth_token: token,
          config: { heartbeat_interval: 60, telemetry_enabled: true }
        }), { headers });
      }

      // Check enrollment status
      if (method === 'GET' && path.startsWith('/enroll/')) {
        const instanceId = path.split('/')[2];
        const instance = await env.guard_fleet.prepare(
          'SELECT * FROM instances WHERE instance_id = ?'
        ).bind(instanceId).first();

        if (!instance) {
          return new Response(JSON.stringify({ status: 'not_found' }), { status: 404, headers });
        }

        return new Response(JSON.stringify({
          status: 'approved',
          instance_id: instance.instance_id,
          version: instance.version,
          platform: instance.platform,
          first_seen: instance.first_seen
        }), { headers });
      }

      return new Response(JSON.stringify({ error: 'Not found' }), { status: 404, headers });
    } catch (error) {
      console.error('Enroll error:', error);
      return new Response(JSON.stringify({ error: 'Internal error' }), { status: 500, headers });
    }
  }
};
