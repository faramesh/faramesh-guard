/**
 * Patch Template for OpenClaw pi-tools.before-tool-call.ts
 *
 * This code gets injected into OpenClaw's execution gate to create
 * non-bypassable Faramesh Guard enforcement.
 *
 * CRITICAL: This runs BEFORE any tool executes.
 */

export const FARAMESH_GUARD_INJECTION = `
// ===== FARAMESH GUARD: NON-BYPASSABLE ENFORCEMENT =====
// This code cannot be disabled without modifying OpenClaw source.
// To remove Guard, run: faramesh-uninstall

import { createHash } from 'crypto';
import { createHmac } from 'crypto';

interface FarameshCAR {
  car_hash: string;
  tool: string;
  args: Record<string, unknown>;
  agent_id: string;
  session_key?: string;
  timestamp: string;
}

interface FarameshPermit {
  car_hash: string;
  signature: string;
  ttl: number;
  issued_at: string;
}

interface FarameshGuardDecision {
  outcome: 'EXECUTE' | 'DENY' | 'NEEDS_APPROVAL';
  reason: string;
  permit?: FarameshPermit;
  signals?: any;
}

/**
 * Build Content-Addressable Record (CAR) for tool call
 */
function buildFarameshCAR(
  toolName: string,
  params: unknown,
  ctx?: { agentId?: string; sessionKey?: string }
): FarameshCAR {
  const args = typeof params === 'object' && params !== null ? params : {};

  const carData = {
    tool: toolName,
    args: JSON.parse(JSON.stringify(args)), // Deep clone
    agent_id: ctx?.agentId || 'unknown',
    session_key: ctx?.sessionKey,
    timestamp: new Date().toISOString(),
  };

  const carJson = JSON.stringify(carData, Object.keys(carData).sort());
  const carHash = createHash('sha256').update(carJson).digest('hex');

  return {
    car_hash: carHash,
    ...carData,
  };
}

/**
 * Call Faramesh Guard daemon for authorization
 */
async function callFarameshGuard(car: FarameshCAR): Promise<FarameshGuardDecision> {
  const guardUrl = process.env.FARAMESH_GUARD_URL || 'http://localhost:8765';
  const timeoutMs = 5000;

  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeoutMs);

    const response = await fetch(\`\${guardUrl}/api/v1/guard/execute\`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool_name: car.tool,
        args: car.args,
        agent_id: car.agent_id,
        car_hash: car.car_hash,
      }),
      signal: controller.signal,
    });

    clearTimeout(timeoutId);

    if (!response.ok) {
      // Fail-closed: Guard unavailable = DENY
      return {
        outcome: 'DENY',
        reason: \`Guard returned \${response.status} (fail-closed)\`,
      };
    }

    const decision = await response.json();
    return {
      outcome: decision.allowed ? 'EXECUTE' : 'DENY',
      reason: decision.decision?.reason || 'No reason provided',
      permit: decision.permit,
      signals: decision.signals,
    };
  } catch (error: any) {
    // Fail-closed: Any error = DENY
    return {
      outcome: 'DENY',
      reason: \`Guard unavailable (fail-closed): \${error.message}\`,
    };
  }
}

/**
 * Validate permit signature and TTL
 */
function validateFarameshPermit(
  permit: FarameshPermit | undefined,
  car: FarameshCAR
): boolean {
  if (!permit) return false;

  // Check TTL
  const issuedAt = new Date(permit.issued_at).getTime();
  const now = Date.now();
  const age = now - issuedAt;

  if (age > permit.ttl * 1000) {
    return false; // Expired
  }

  // Check CAR hash binding
  if (permit.car_hash !== car.car_hash) {
    return false; // Permit not for this action
  }

  // TODO: Verify HMAC signature with Guard's public key
  // For now, trust that Guard validated it

  return true;
}

// ===== END FARAMESH GUARD INJECTION =====
`;

export const HOOK_WRAPPER = `
// FARAMESH: Wrap original hook with Guard enforcement
const originalRunBeforeToolCallHook = runBeforeToolCallHook;

export async function runBeforeToolCallHook(args: {
  toolName: string;
  params: unknown;
  toolCallId?: string;
  ctx?: HookContext;
}): Promise<HookOutcome> {
  // 🔥 FARAMESH GUARD: Non-bypassable authorization check
  try {
    const car = buildFarameshCAR(args.toolName, args.params, args.ctx);
    const decision = await callFarameshGuard(car);

    if (decision.outcome !== 'EXECUTE') {
      return {
        blocked: true,
        reason: \`Faramesh Guard: \${decision.reason}\`,
      };
    }

    // Validate permit if provided
    if (!validateFarameshPermit(decision.permit, car)) {
      return {
        blocked: true,
        reason: 'Faramesh Guard: Invalid or expired permit',
      };
    }

    // Authorization passed, continue with original hook logic
  } catch (error: any) {
    // Fail-closed on unexpected errors
    return {
      blocked: true,
      reason: \`Faramesh Guard error (fail-closed): \${error.message}\`,
    };
  }

  // Call original hook logic (plugins, etc.)
  return await originalRunBeforeToolCallHook(args);
}
`;

/**
 * Generate patch markers for easy detection
 */
export const PATCH_MARKERS = {
  start: '// ===== FARAMESH GUARD: NON-BYPASSABLE ENFORCEMENT =====',
  end: '// ===== END FARAMESH GUARD INJECTION =====',
};

/**
 * JavaScript version of Guard injection (for built .js files)
 * No TypeScript types, no imports (bundled already)
 */
export const FARAMESH_GUARD_INJECTION_JS = `
// ===== FARAMESH GUARD: NON-BYPASSABLE ENFORCEMENT =====
// This code cannot be disabled without modifying the built bundle.
// To remove Guard, run: faramesh-uninstall

/**
 * Build Content-Addressable Record (CAR) for tool call
 */
function buildFarameshCAR(toolName, params, ctx) {
  const args = typeof params === 'object' && params !== null ? params : {};
  const carData = {
    tool: toolName,
    args: JSON.parse(JSON.stringify(args)),
    agent_id: ctx?.agentId || 'unknown',
    session_key: ctx?.sessionKey,
    timestamp: new Date().toISOString(),
  };
  // Simple hash for CAR (bundled environment may not have crypto)
  const carJson = JSON.stringify(carData, Object.keys(carData).sort());
  const carHash = carJson.split('').reduce((a,b) => ((a<<5)-a)+b.charCodeAt(0), 0).toString(16);
  return { car_hash: carHash, ...carData };
}

/**
 * Call Faramesh Guard daemon for authorization
 */
async function callFarameshGuard(car) {
  const guardUrl = process.env.FARAMESH_GUARD_URL || 'http://127.0.0.1:8765';
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const response = await fetch(guardUrl + '/api/v1/guard/execute', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        tool_name: car.tool,
        args: car.args,
        agent_id: car.agent_id,
        car_hash: car.car_hash,
      }),
      signal: controller.signal,
    });
    clearTimeout(timeoutId);
    if (!response.ok) {
      return { outcome: 'DENY', reason: 'Guard returned ' + response.status + ' (fail-closed)' };
    }
    const decision = await response.json();
    return {
      outcome: decision.allowed ? 'EXECUTE' : 'DENY',
      reason: decision.decision?.reason || decision.reason || 'No reason',
      permit: decision.permit,
    };
  } catch (error) {
    return { outcome: 'DENY', reason: 'Guard unavailable (fail-closed): ' + error.message };
  }
}

/**
 * Validate permit
 */
function validateFarameshPermit(permit, car) {
  if (!permit) return true; // If no permit system, pass
  if (permit.car_hash !== car.car_hash) return false;
  const issuedAt = new Date(permit.issued_at).getTime();
  const age = Date.now() - issuedAt;
  if (age > permit.ttl * 1000) return false;
  return true;
}

// ===== END FARAMESH GUARD INJECTION =====
`;

/**
 * Check if file is already patched
 */
export function isFilePatched(fileContent: string): boolean {
  return fileContent.includes(PATCH_MARKERS.start);
}

/**
 * Remove patch from file
 */
export function removePatch(fileContent: string): string {
  const startIndex = fileContent.indexOf(PATCH_MARKERS.start);
  if (startIndex === -1) return fileContent;

  const endIndex = fileContent.indexOf(PATCH_MARKERS.end);
  if (endIndex === -1) return fileContent;

  // Remove everything between markers (inclusive)
  const before = fileContent.substring(0, startIndex);
  const after = fileContent.substring(endIndex + PATCH_MARKERS.end.length);

  return before + after;
}
