/**
 * Patch Applicator
 *
 * Applies Faramesh Guard patch to OpenClaw's execution gate file.
 *
 * STRATEGY: Prefer patching built JS files (no rebuild needed!)
 * - gateway-bundle: Patch dist/gateway-cli-*.js directly (BEST - instant, no rebuild!)
 * - built: Patch dist/*.js individual files (good - no rebuild)
 * - source: Patch src/*.ts files (requires rebuild after)
 */

import { readFileSync, writeFileSync } from 'fs';
import { FARAMESH_GUARD_INJECTION, FARAMESH_GUARD_INJECTION_JS, HOOK_WRAPPER, isFilePatched, PATCH_MARKERS } from './patch-template.js';
import { createBackup } from './backup.js';
import { hashFile, PatchEntry, PatchManifest, saveManifest } from './manifest.js';
import { OpenClawInstallation, getGitCommit } from './detector.js';

export interface PatchResult {
  success: boolean;
  message: string;
  patchEntry?: PatchEntry;
  needsRebuild?: boolean;
}

/**
 * Apply Faramesh Guard patch to OpenClaw file
 */
export function applyPatch(installation: OpenClawInstallation): PatchResult {
  const targetFile = installation.targetFile;
  const patchTarget = installation.patchTarget;

  // Check if file exists
  if (!targetFile || !installation.sourceFiles.exists && !installation.builtFiles.exists && !installation.gatewayBundle) {
    return {
      success: false,
      message: 'Target file not found. Cannot patch.',
    };
  }

  // Read current file content
  let fileContent: string;
  try {
    fileContent = readFileSync(targetFile, 'utf-8');
  } catch (error: any) {
    return {
      success: false,
      message: `Failed to read file: ${error.message}`,
    };
  }

  // Check if already patched
  if (isFilePatched(fileContent)) {
    return {
      success: false,
      message: 'File is already patched. Run uninstall first.',
    };
  }

  // Create backup
  const backup = createBackup(targetFile, installation.version);
  if (!backup.success) {
    return {
      success: false,
      message: `Backup failed: ${backup.error}`,
    };
  }

  let patchedContent: string;

  // ============================================================
  // PATCH MODE C: Gateway Bundle (dist/gateway-cli-*.js)
  // This is the PREFERRED mode - no rebuild needed!
  // ============================================================
  if (patchTarget === 'gateway-bundle') {
    const result = patchGatewayBundle(fileContent);
    if (!result.success) {
      return {
        success: false,
        message: result.error!,
      };
    }
    patchedContent = result.content!;
  }
  // ============================================================
  // PATCH MODE A & B: Source files (src/*.ts) or built files (dist/*.js)
  // ============================================================
  else {
    const result = patchSourceOrBuiltFile(fileContent, patchTarget);
    if (!result.success) {
      return {
        success: false,
        message: result.error!,
      };
    }
    patchedContent = result.content!;
  }

  // Write patched file
  try {
    writeFileSync(targetFile, patchedContent, 'utf-8');
  } catch (error: any) {
    return {
      success: false,
      message: `Failed to write patched file: ${error.message}`,
    };
  }

  // Calculate patched hash
  const patchedHash = hashFile(targetFile);

  // Create patch entry
  const patchEntry: PatchEntry = {
    file: targetFile,
    originalSha256: backup.originalHash!,
    patchedSha256: patchedHash,
    backupPath: backup.backupPath!,
    patchApplied: new Date().toISOString(),
  };

  // Save manifest
  const manifest: PatchManifest = {
    version: '1.0.0',
    timestamp: new Date().toISOString(),
    openclaw: {
      type: installation.type,
      rootPath: installation.rootPath,
      version: installation.version,
      gitCommit: installation.type === 'repo-clone'
        ? getGitCommit(installation.rootPath) || undefined
        : undefined,
    },
    patches: [patchEntry],
  };

  saveManifest(manifest);

  return {
    success: true,
    message: installation.needsRebuild
      ? 'Patch applied successfully. Please rebuild OpenClaw: pnpm build'
      : 'Patch applied successfully! No rebuild needed - Guard is now active.',
    patchEntry,
    needsRebuild: installation.needsRebuild,
  };
}

// ============================================================
// PATCH HELPERS
// ============================================================

interface PatchHelperResult {
  success: boolean;
  content?: string;
  error?: string;
}

/**
 * Patch a gateway bundle (dist/gateway-cli-*.js)
 *
 * This is the PREFERRED patching mode because:
 * 1. No rebuild required - Guard is active immediately
 * 2. Works on any built OpenClaw installation
 * 3. Survives npm installs (bundle is in dist)
 */
function patchGatewayBundle(content: string): PatchHelperResult {
  // In bundled JS, the execution line looks like:
  // result: await tool.execute?.(`http-${Date.now()}`, toolArgs)

  // We need to find the sendJson call that wraps the execute and inject before it
  const execPattern = /sendJson\$?\d*\(res,\s*200,\s*\{\s*ok:\s*true,\s*result:\s*await\s+tool\.execute\?\.\(/;
  const match = content.match(execPattern);

  if (!match || match.index === undefined) {
    return {
      success: false,
      error: 'Could not find tool execution pattern in gateway bundle. Pattern: sendJson(res, 200, { ok: true, result: await tool.execute?.()',
    };
  }

  // Find the line start before the sendJson call
  const beforeMatch = content.substring(0, match.index);
  const lastNewline = beforeMatch.lastIndexOf('\n');
  const lineStart = lastNewline + 1;

  // Get indentation
  const indent = content.substring(lineStart, match.index);

  // Build the guard injection for bundled JS (no TypeScript types)
  const guardCode = `${PATCH_MARKERS.start}
${indent}// 🔥 FARAMESH GUARD: Non-bypassable authorization check
${indent}const __farameshCAR = { tool: toolName, args: toolArgs, context: { agentId, sessionKey } };
${indent}const __farameshDecision = await (async () => {
${indent}  try {
${indent}    const resp = await fetch("http://127.0.0.1:8765/api/v1/guard/execute", {
${indent}      method: "POST",
${indent}      headers: { "Content-Type": "application/json" },
${indent}      body: JSON.stringify(__farameshCAR),
${indent}    });
${indent}    return await resp.json();
${indent}  } catch (e) {
${indent}    return { allowed: false, reason: "Guard unreachable: " + e.message };
${indent}  }
${indent}})();
${indent}if (!__farameshDecision.allowed) {
${indent}  sendJson$1 ? sendJson$1(res, 403, { ok: false, error: { type: "blocked", message: "Faramesh Guard: " + __farameshDecision.reason } })
${indent}             : sendJson(res, 403, { ok: false, error: { type: "blocked", message: "Faramesh Guard: " + __farameshDecision.reason } });
${indent}  return true;
${indent}}
${PATCH_MARKERS.end}
`;

  // Insert guard code before the sendJson call
  const patchedContent = content.substring(0, lineStart) + guardCode + content.substring(lineStart);

  return { success: true, content: patchedContent };
}

/**
 * Patch source (.ts) or individual built (.js) files
 *
 * This handles:
 * - src/gateway/tools-invoke-http.ts (TypeScript source)
 * - dist/gateway/tools-invoke-http.js (individual built file)
 * - src/agents/pi-tools.before-tool-call.ts (legacy hook)
 */
function patchSourceOrBuiltFile(content: string, patchTarget: 'source' | 'built' | 'gateway-bundle'): PatchHelperResult {
  const lines = content.split('\n');
  let insertIndex = 0;

  // Find last import statement
  for (let i = 0; i < lines.length; i++) {
    if (lines[i].startsWith('import ') || lines[i].startsWith('import{')) {
      insertIndex = i + 1;
    }
  }

  // Insert Faramesh Guard code after imports
  const injection = patchTarget === 'source' ? FARAMESH_GUARD_INJECTION : FARAMESH_GUARD_INJECTION_JS;
  lines.splice(insertIndex, 0, '', injection, '');

  // Patch mode A: legacy pi-tools.before-tool-call.ts (wrap runBeforeToolCallHook)
  const functionStartRegex = /export async function runBeforeToolCallHook/;
  let functionIndex = -1;
  for (let i = 0; i < lines.length; i++) {
    if (functionStartRegex.test(lines[i])) {
      functionIndex = i;
      break;
    }
  }

  if (functionIndex !== -1) {
    // Rename original function and add wrapper
    lines[functionIndex] = lines[functionIndex].replace(
      'export async function runBeforeToolCallHook',
      'async function originalRunBeforeToolCallHook'
    );

    // Add wrapper function before the file ends
    const exportIndex = lines.findIndex(line => line.includes('export const __testing'));
    if (exportIndex !== -1) {
      lines.splice(exportIndex, 0, '', HOOK_WRAPPER, '');
    } else {
      lines.push('', HOOK_WRAPPER);
    }
  } else {
    // Patch mode B: gateway HTTP tool invocation gate
    // TypeScript: const result = await (tool as any).execute?.(...
    // JavaScript: const result = await tool.execute?.(...
    const tsPattern = 'const result = await (tool as any).execute?.';
    const jsPattern = 'const result = await tool.execute?.';

    let execLineIndex = lines.findIndex((line) => line.includes(tsPattern));
    if (execLineIndex === -1) {
      execLineIndex = lines.findIndex((line) => line.includes(jsPattern));
    }

    if (execLineIndex === -1) {
      return {
        success: false,
        error: 'Could not find expected tool execution line. Supported targets: runBeforeToolCallHook or POST /tools/invoke handler.',
      };
    }

    const indent = (lines[execLineIndex].match(/^\s*/) || [''])[0];
    const guardLines = [
      `${indent}// 🔥 FARAMESH GUARD: Non-bypassable authorization check`,
      `${indent}const car = buildFarameshCAR(toolName, toolArgs, { agentId, sessionKey });`,
      `${indent}const decision = await callFarameshGuard(car);`,
      `${indent}if (decision.outcome !== 'EXECUTE') {`,
      `${indent}  sendJson(res, 403, {`,
      `${indent}    ok: false,`,
      `${indent}    error: { type: "blocked", message: \`Faramesh Guard: \${decision.reason}\` },`,
      `${indent}  });`,
      `${indent}  return true;`,
      `${indent}}`,
      `${indent}if (!validateFarameshPermit(decision.permit, car)) {`,
      `${indent}  sendJson(res, 403, {`,
      `${indent}    ok: false,`,
      `${indent}    error: { type: "blocked", message: "Faramesh Guard: Invalid or expired permit" },`,
      `${indent}  });`,
      `${indent}  return true;`,
      `${indent}}`,
      '',
    ];

    lines.splice(execLineIndex, 0, ...guardLines);
  }

  return { success: true, content: lines.join('\n') };
}

/**
 * Remove patch from OpenClaw file
 */
export function removePatchFromFile(targetFile: string, backupPath: string): PatchResult {
  try {
    // Read backup
    const backupContent = readFileSync(backupPath, 'utf-8');

    // Restore original file
    writeFileSync(targetFile, backupContent, 'utf-8');

    return {
      success: true,
      message: 'Patch removed successfully',
    };
  } catch (error: any) {
    return {
      success: false,
      message: `Failed to remove patch: ${error.message}`,
    };
  }
}
