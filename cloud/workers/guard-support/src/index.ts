/**
 * Faramesh Guard - Support Bundle Worker
 *
 * Handles:
 * - POST /bundle - Upload encrypted support bundle
 * - GET /bundle/:id - Get bundle status (admin only)
 */

interface Env {
  SUPPORT_BUCKET: R2Bucket;
  FLEET_DB: D1Database;
  AUTH_TOKEN: string;
}

interface BundleUpload {
  instance_id: string;
  bundle_type: 'diagnostic' | 'crash' | 'user_report';
  description?: string;
  version: string;
  platform: string;
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method;

    const corsHeaders = {
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Methods': 'GET, POST, OPTIONS',
      'Access-Control-Allow-Headers': 'Content-Type, Authorization, X-Instance-ID',
    };

    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders });
    }

    try {
      if (method === 'POST' && path === '/bundle') {
        return await this.handleBundleUpload(request, env, ctx);
      }

      if (method === 'GET' && path.startsWith('/bundle/')) {
        const bundleId = path.split('/')[2];
        return await this.handleBundleStatus(bundleId, request, env);
      }

      if (method === 'GET' && path === '/health') {
        return Response.json({ status: 'ok', service: 'guard-support' });
      }

      return Response.json(
        { error: 'Not found' },
        { status: 404, headers: corsHeaders }
      );
    } catch (error) {
      console.error('Support bundle error:', error);
      return Response.json(
        { error: 'Internal server error' },
        { status: 500, headers: corsHeaders }
      );
    }
  },

  async handleBundleUpload(
    request: Request,
    env: Env,
    ctx: ExecutionContext
  ): Promise<Response> {
    const contentType = request.headers.get('Content-Type') || '';

    let metadata: BundleUpload;
    let bundleData: ArrayBuffer;

    if (contentType.includes('multipart/form-data')) {
      // Handle multipart form upload
      const formData = await request.formData();
      const metadataStr = formData.get('metadata') as string;
      const file = formData.get('bundle') as File;

      if (!metadataStr || !file) {
        return Response.json(
          { error: 'Missing metadata or bundle file' },
          { status: 400 }
        );
      }

      metadata = JSON.parse(metadataStr);
      bundleData = await file.arrayBuffer();
    } else {
      // Handle JSON + binary in headers
      const metadataHeader = request.headers.get('X-Bundle-Metadata');
      if (!metadataHeader) {
        return Response.json(
          { error: 'Missing X-Bundle-Metadata header' },
          { status: 400 }
        );
      }

      metadata = JSON.parse(metadataHeader);
      bundleData = await request.arrayBuffer();
    }

    if (!metadata.instance_id || !metadata.bundle_type || !metadata.version) {
      return Response.json(
        { error: 'Missing required fields: instance_id, bundle_type, version' },
        { status: 400 }
      );
    }

    // Generate unique bundle ID
    const bundleId = `${Date.now()}_${metadata.instance_id.slice(0, 8)}_${crypto.randomUUID().slice(0, 8)}`;
    const objectKey = `bundles/${metadata.bundle_type}/${bundleId}.bundle`;

    // Store in R2
    await env.SUPPORT_BUCKET.put(objectKey, bundleData, {
      customMetadata: {
        instance_id: metadata.instance_id,
        bundle_type: metadata.bundle_type,
        version: metadata.version,
        platform: metadata.platform || 'unknown',
        description: metadata.description || '',
        uploaded_at: new Date().toISOString(),
      },
    });

    // Log the upload
    console.log(`Support bundle uploaded: ${bundleId} from ${metadata.instance_id}`);

    return Response.json({
      success: true,
      bundle_id: bundleId,
      message: 'Support bundle uploaded successfully',
    });
  },

  async handleBundleStatus(
    bundleId: string,
    request: Request,
    env: Env
  ): Promise<Response> {
    // Verify admin auth
    const authHeader = request.headers.get('Authorization');
    if (!authHeader || authHeader !== `Bearer ${env.AUTH_TOKEN}`) {
      return Response.json(
        { error: 'Unauthorized' },
        { status: 401 }
      );
    }

    // Try to find the bundle in different type folders
    const bundleTypes = ['diagnostic', 'crash', 'user_report'];

    for (const bundleType of bundleTypes) {
      const objectKey = `bundles/${bundleType}/${bundleId}.bundle`;
      const object = await env.SUPPORT_BUCKET.head(objectKey);

      if (object) {
        return Response.json({
          bundle_id: bundleId,
          bundle_type: bundleType,
          size: object.size,
          uploaded_at: object.uploaded,
          metadata: object.customMetadata,
          status: 'available',
        });
      }
    }

    return Response.json(
      { error: 'Bundle not found', bundle_id: bundleId },
      { status: 404 }
    );
  },
};
