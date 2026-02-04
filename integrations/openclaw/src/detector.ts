/**
 * OpenClaw Installation Detector
 *
 * Finds where OpenClaw is installed on the user's machine:
 * 1. Global npm installation
 * 2. Local node_modules (repo clone)
 * 3. Packaged app (.app bundle, AppImage, etc.)
 *
 * STRATEGY: Prefer patching BUILT files (no rebuild needed!)
 */

import { existsSync, readFileSync, readdirSync } from 'fs';
import { join, dirname } from 'path';
import { execSync } from 'child_process';
import { homedir } from 'os';

export interface OpenClawInstallation {
  type: 'npm-global' | 'npm-local' | 'repo-clone' | 'packaged' | 'unknown';
  rootPath: string;
  version: string;
  sourceFiles: {
    beforeToolCall: string;
    exists: boolean;
  };
  builtFiles: {
    beforeToolCall: string;
    exists: boolean;
  };
  /** Bundled gateway CLI file (e.g., dist/gateway-cli-ABC123.js) */
  gatewayBundle?: string;
  /** What type of file to patch */
  patchTarget: 'source' | 'built' | 'gateway-bundle';
  /** The actual file to patch */
  targetFile: string;
  /** If true, user must rebuild after patching (only for source patches) */
  needsRebuild: boolean;
}

/**
 * Find the gateway CLI bundle in dist/ (has hash suffix like gateway-cli-ABC123.js)
 */
function findGatewayCliBundle(distPath: string): string | null {
  if (!existsSync(distPath)) return null;

  try {
    const files = readdirSync(distPath);
    // Look for gateway-cli-*.js (the bundled gateway)
    const gatewayBundle = files.find(f => f.startsWith('gateway-cli-') && f.endsWith('.js'));
    if (gatewayBundle) {
      return join(distPath, gatewayBundle);
    }
  } catch {
    return null;
  }
  return null;
}

/**
 * Try to find OpenClaw via npm global
 */
function detectNpmGlobal(): OpenClawInstallation | null {
  try {
    const npmRoot = execSync('npm root -g', { encoding: 'utf-8' }).trim();
    const openclawPath = join(npmRoot, 'openclaw');

    if (!existsSync(openclawPath)) {
      return null;
    }

    const packageJson = JSON.parse(
      readFileSync(join(openclawPath, 'package.json'), 'utf-8')
    );

    const sourceFile = join(openclawPath, 'src/gateway/tools-invoke-http.ts');
    const builtFile = findGatewayCliBundle(join(openclawPath, 'dist'));

    // PREFER built files (no rebuild needed!)
    const useBuilt = builtFile && existsSync(builtFile);

    return {
      type: 'npm-global',
      rootPath: openclawPath,
      version: packageJson.version || 'unknown',
      sourceFiles: {
        beforeToolCall: sourceFile,
        exists: existsSync(sourceFile),
      },
      builtFiles: {
        beforeToolCall: builtFile || '',
        exists: !!builtFile && existsSync(builtFile),
      },
      patchTarget: useBuilt ? 'built' : 'source',
      targetFile: useBuilt ? builtFile! : sourceFile,
      needsRebuild: !useBuilt,
    };
  } catch {
    return null;
  }
}

/**
 * Try to find OpenClaw in local node_modules
 */
function detectNpmLocal(cwd: string = process.cwd()): OpenClawInstallation | null {
  const nodeModulesPath = join(cwd, 'node_modules', 'openclaw');

  if (!existsSync(nodeModulesPath)) {
    // Try parent directories
    const parent = dirname(cwd);
    if (parent !== cwd) {
      return detectNpmLocal(parent);
    }
    return null;
  }

  const packageJson = JSON.parse(
    readFileSync(join(nodeModulesPath, 'package.json'), 'utf-8')
  );

  const sourceFile = join(nodeModulesPath, 'src/agents/pi-tools.before-tool-call.ts');
  const builtFile = join(nodeModulesPath, 'dist/agents/pi-tools.before-tool-call.js');

  // Check for bundled gateway CLI (already built - no rebuild needed!)
  const distPath = join(nodeModulesPath, 'dist');
  const gatewayBundle = findGatewayCliBundle(distPath);

  // Priority: bundled gateway > individual built file > source
  let patchTarget: 'source' | 'built' | 'gateway-bundle';
  let targetFile: string;
  let needsRebuild: boolean;

  if (gatewayBundle) {
    patchTarget = 'gateway-bundle';
    targetFile = gatewayBundle;
    needsRebuild = false;
  } else if (existsSync(builtFile)) {
    patchTarget = 'built';
    targetFile = builtFile;
    needsRebuild = false;
  } else if (existsSync(sourceFile)) {
    patchTarget = 'source';
    targetFile = sourceFile;
    needsRebuild = true;
  } else {
    return null; // No patchable file found
  }

  return {
    type: 'npm-local',
    rootPath: nodeModulesPath,
    version: packageJson.version || 'unknown',
    sourceFiles: {
      beforeToolCall: sourceFile,
      exists: existsSync(sourceFile),
    },
    builtFiles: {
      beforeToolCall: builtFile,
      exists: existsSync(builtFile),
    },
    gatewayBundle: gatewayBundle || undefined,
    patchTarget,
    targetFile,
    needsRebuild,
  };
}

/**
 * Try to find OpenClaw as a repo clone
 */
function detectRepoClone(searchPath?: string): OpenClawInstallation | null {
  const possiblePaths = [
    searchPath,
    process.cwd(),
    join(homedir(), 'openclaw'),
    join(homedir(), 'projects', 'openclaw'),
    join(homedir(), 'Faramesh-Nexus', 'openclaw-test'),
  ].filter(Boolean) as string[];

  for (const path of possiblePaths) {
    if (!existsSync(path)) continue;

    const packageJsonPath = join(path, 'package.json');
    const gitPath = join(path, '.git');

    if (!existsSync(packageJsonPath) || !existsSync(gitPath)) continue;

    const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));

    // Check if it's actually OpenClaw
    if (!packageJson.name?.includes('openclaw')) continue;

    // IMPORTANT: Prefer tools-invoke-http.ts (HTTP execution gate) over
    // pi-tools.before-tool-call.ts (plugin hook). The HTTP gate is the
    // TRUE non-bypassable interception point because ALL tool calls via
    // the API MUST go through it. The hook can be bypassed by plugins.
    const sourceCandidates = [
      join(path, 'src/gateway/tools-invoke-http.ts'),  // Preferred: HTTP execution gate
      join(path, 'src/agents/pi-tools.before-tool-call.ts'),  // Fallback: hook-based
    ];
    const sourceFile = sourceCandidates.find((candidate) => existsSync(candidate));
    if (!sourceFile) continue;

    // Check for bundled gateway CLI (already built - no rebuild needed!)
    const distPath = join(path, 'dist');
    const gatewayBundle = findGatewayCliBundle(distPath);

    // For repo clones, PREFER the bundled gateway if it exists (no rebuild!)
    // This allows instant patching without requiring user to rebuild
    const builtFile = sourceFile.includes('/src/gateway/')
      ? join(path, 'dist/gateway/tools-invoke-http.js')
      : join(path, 'dist/agents/pi-tools.before-tool-call.js');

    // Priority: bundled gateway > individual built file > source
    let patchTarget: 'source' | 'built' | 'gateway-bundle';
    let targetFile: string;
    let needsRebuild: boolean;

    if (gatewayBundle) {
      // Best option: patch gateway bundle directly - NO REBUILD NEEDED!
      patchTarget = 'gateway-bundle';
      targetFile = gatewayBundle;
      needsRebuild = false;
    } else if (existsSync(builtFile)) {
      // Second best: patch individual built file
      patchTarget = 'built';
      targetFile = builtFile;
      needsRebuild = false;
    } else {
      // Fallback: patch source (requires rebuild)
      patchTarget = 'source';
      targetFile = sourceFile;
      needsRebuild = true;
    }

    return {
      type: 'repo-clone',
      rootPath: path,
      version: packageJson.version || 'dev',
      sourceFiles: {
        beforeToolCall: sourceFile,
        exists: true,
      },
      builtFiles: {
        beforeToolCall: builtFile,
        exists: existsSync(builtFile),
      },
      gatewayBundle: gatewayBundle || undefined,
      patchTarget,
      targetFile,
      needsRebuild,
    };
  }

  return null;
}

/**
 * Detect OpenClaw installation
 */
export async function detectOpenClaw(
  searchPath?: string
): Promise<OpenClawInstallation> {
  // Try repo clone first (most common for development)
  let installation = detectRepoClone(searchPath);
  if (installation) return installation;

  // Try local npm install
  installation = detectNpmLocal();
  if (installation) return installation;

  // Try global npm install
  installation = detectNpmGlobal();
  if (installation) return installation;

  // Not found
  return {
    type: 'unknown',
    rootPath: '',
    version: 'unknown',
    sourceFiles: {
      beforeToolCall: '',
      exists: false,
    },
    builtFiles: {
      beforeToolCall: '',
      exists: false,
    },
    patchTarget: 'source',
    targetFile: '',
    needsRebuild: true,
  };
}

/**
 * Get Git commit hash for repo clone
 */
export function getGitCommit(repoPath: string): string | null {
  try {
    return execSync('git rev-parse HEAD', {
      cwd: repoPath,
      encoding: 'utf-8',
    }).trim();
  } catch {
    return null;
  }
}
