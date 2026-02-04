/**
 * Faramesh Guard - Device Enrollment Worker
 *
 * Handles:
 * - POST /enroll - New device enrollment
 * - GET /enroll/:id - Get enrollment status
 * - POST /enroll/:id/approve - Manual approval (admin)
 * - POST /verify - License/organization verification
 */

interface Env {
  FLEET_DB: D1Database;
  AUTH_TOKEN: string;
  ENVIRONMENT: string;
}

interface EnrollmentRequest {
  instance_id: string;
  version: string;
  platform: string;
  machine_info?: {
    hostname?: string;
    cpu_count?: number;
    os_version?: string;
    architecture?: string;
  };
  organization_key?: string; // Optional org license key
}

interface EnrollmentResponse {
  status: 'approved' | 'pending' | 'rejected';
  instance_id: string;
  auth_token?: string; // Only if approved
  config?: {
    heartbeat_interval_seconds: number;
    telemetry_enabled: boolean;
    policy_url?: string;
  };
  commands?: Array<{
    type: string;
    data: unknown;
  }>;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    // CORS headers for dashboard
    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, PUT, DELETE, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization',
    };

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    try {
      // Route matching
      if (method === 'POST' && path === '/enroll') {
        return await this.handleEnroll(request, env, ctx);
      }

      if (method === 'GET' && path.startsWith('/enroll/')) {
        const instanceId = path.split('/')[2];
        return await this.handleEnrollStatus(instanceId, env);
      }

      if (method === 'POST' && path === '/verify') {
        return await this.handleVerify(request, env);
      }

      if (method === 'GET' && path === '/health') {
        return Response.json({ status: 'ok', service: 'guard-enroll' });
      }

      return Response.json(
        { error: 'Not found' },
        { status: 404, headers: corsHeaders }
      );
    } catch (error) {
      console.error('Enrollment error:', error);
      return Response.json(
        { error: 'Internal server error' },
        { status: 500, headers: corsHeaders }
      );
    }
  },

  async handleEnroll(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const body = await request.json() as EnrollmentRequest;

    if (!body.instance_id || !body.version || !body.platform) {
      return Response.json(
        { error: 'Missing required fields: instance_id, version, platform' },
        { status: 400 }
      );
    }

    // Check if already enrolled
    const existing = await env.FLEET_DB.prepare(
      'SELECT instance_id, organization_id FROM instances WHERE instance_id = ?'
    ).bind(body.instance_id).first();

    if (existing) {
      // Return existing enrollment
      return Response.json({
        status: 'approved',
        instance_id: body.instance_id,
        config: {
          heartbeat_interval_seconds: 60,
          telemetry_enabled: true,
        },
        message: 'Already enrolled'
      });
    }

    // Verify organization if key provided
    let organizationId: string | null = null;
    if (body.organization_key) {
      organizationId = await this.validateOrgKey(body.organization_key, env);
    }

    // Create new enrollment
    const now = new Date().toISOString();
    await env.FLEET_DB.prepare(`
      INSERT INTO instances (
        instance_id, version, platform, first_seen, last_heartbeat,
        organization_id, protection_enabled, protection_mode
      ) VALUES (?, ?, ?, ?, ?, ?, 1, 'standard')
    `).bind(
      body.instance_id,
      body.version,
      body.platform,
      now,
      now,
      organizationId
    ).run();

    // Generate instance-specific auth token
    const instanceToken = await this.generateInstanceToken(body.instance_id, env);

    const response: EnrollmentResponse = {
      status: 'approved',
      instance_id: body.instance_id,
      auth_token: instanceToken,
      config: {
        heartbeat_interval_seconds: 60,
        telemetry_enabled: true,
      },
    };

    // Check for any pending commands for this instance or broadcast
    const pendingCommands = await env.FLEET_DB.prepare(`
      SELECT command_type, command_data
      FROM pending_commands
      WHERE (instance_id = ? OR instance_id = '*')
        AND executed_at IS NULL
        AND (expires_at IS NULL OR expires_at > datetime('now'))
      ORDER BY created_at ASC
    `).bind(body.instance_id).all();

    if (pendingCommands.results.length > 0) {
      response.commands = pendingCommands.results.map((cmd: any) => ({
        type: cmd.command_type,
        data: cmd.command_data ? JSON.parse(cmd.command_data) : null,
      }));
    }

    return Response.json(response);
  },

  async handleEnrollStatus(instanceId: string, env: Env): Promise<Response> {
    const instance = await env.FLEET_DB.prepare(
      'SELECT instance_id, version, platform, first_seen, protection_enabled FROM instances WHERE instance_id = ?'
    ).bind(instanceId).first();

    if (!instance) {
      return Response.json(
        { error: 'Instance not found', status: 'unknown' },
        { status: 404 }
      );
    }

    return Response.json({
      status: 'approved',
      instance_id: instance.instance_id,
      version: instance.version,
      platform: instance.platform,
      first_seen: instance.first_seen,
      protection_enabled: instance.protection_enabled === 1,
    });
  },

  async handleVerify(request: Request, env: Env): Promise<Response> {
    const body = await request.json() as { license_key?: string };

    if (!body.license_key) {
      return Response.json(
        { valid: false, error: 'No license key provided' },
        { status: 400 }
      );
    }

    // TODO: Implement proper license verification
    // For now, accept any non-empty key
    const isValid = body.license_key.length > 10;

    return Response.json({
      valid: isValid,
      organization: isValid ? 'verified' : null,
      features: isValid ? ['ml_detection', 'advanced_policies', 'support'] : [],
    });
  },

  async validateOrgKey(key: string, env: Env): Promise<string | null> {
    // TODO: Implement proper org key validation
    // This would check against a licensing system
    if (key && key.length > 10) {
      return key.substring(0, 8); // Use first 8 chars as org ID
    }
    return null;
  },

  async generateInstanceToken(instanceId: string, env: Env): Promise<string> {
    // Create a signed token for this instance
    // In production, use proper JWT signing
    const payload = {
      sub: instanceId,
      iat: Date.now(),
      exp: Date.now() + (365 * 24 * 60 * 60 * 1000), // 1 year
    };

    // Simple HMAC-style token (in production use proper JWT)
    const encoder = new TextEncoder();
    const data = encoder.encode(JSON.stringify(payload) + env.AUTH_TOKEN);
    const hashBuffer = await crypto.subtle.digest('SHA-256', data);
    const hashArray = Array.from(new Uint8Array(hashBuffer));
    const hashHex = hashArray.map(b => b.toString(16).padStart(2, '0')).join('');

    return `guard_${instanceId.slice(0, 8)}_${hashHex.slice(0, 32)}`;
  },
};
