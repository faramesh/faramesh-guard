/**
 * Faramesh Guard - Support Bundle Worker
 * Handles diagnostic bundle uploads
 */

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    const path = url.pathname;
    const method = req.method;

    const headers = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Instance-ID, X-Bundle-Type',
      'Content-Type': 'application/json'
    };

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers });
    }

    try {
      if (path === '/health') {
        return new Response(JSON.stringify({ status: 'ok', service: 'guard-support' }), { headers });
      }

      // Upload support bundle
      if (method === 'POST' && path === '/bundle') {
        const instanceId = req.headers.get('X-Instance-ID') || 'unknown';
        const bundleType = req.headers.get('X-Bundle-Type') || 'diagnostic';
        const id = `${Date.now()}_${instanceId.slice(0, 8)}_${crypto.randomUUID().slice(0, 8)}`;

        const data = await req.arrayBuffer();

        await env.guard_support.put(`bundles/${bundleType}/${id}.zip`, data, {
          customMetadata: {
            instance_id: instanceId,
            bundle_type: bundleType,
            uploaded_at: new Date().toISOString(),
            size: String(data.byteLength)
          }
        });

        return new Response(JSON.stringify({
          status: 'uploaded',
          bundle_id: id,
          message: 'Support bundle received'
        }), { headers });
      }

      return new Response(JSON.stringify({ error: 'Not found' }), { status: 404, headers });
    } catch (error) {
      console.error('Support error:', error);
      return new Response(JSON.stringify({ error: 'Internal error' }), { status: 500, headers });
    }
  }
};
