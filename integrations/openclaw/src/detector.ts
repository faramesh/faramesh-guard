/**
 * OpenClaw Installation Detector
 *
 * Finds where OpenClaw is installed on the user's machine:
 * 1. Global npm installation (npm install -g openclaw)
 * 2. Local node_modules (repo clone or npm install)
 * 3. Packaged app (.app bundle, AppImage, .exe)
 * 4. Homebrew (macOS)
 * 5. System package managers (apt, dnf, pacman)
 * 6. Windows installers (chocolatey, scoop, winget)
 *
 * STRATEGY: Prefer patching BUILT files (no rebuild needed!)
 *
 * CROSS-PLATFORM: Works on macOS, Windows, and Linux
 */

import { existsSync, readFileSync, readdirSync, statSync } from 'fs';
import { join, dirname, basename } from 'path';
import { execSync } from 'child_process';
import { homedir, platform } from 'os';

export interface OpenClawInstallation {
  type: 'npm-global' | 'npm-local' | 'repo-clone' | 'packaged' | 'homebrew' | 'system-package' | 'unknown';
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
  /** Operating system */
  platform: 'darwin' | 'win32' | 'linux';
  /** All detected installations (for UI display) */
  allInstallations?: OpenClawInstallation[];
}

const CURRENT_PLATFORM = platform() as 'darwin' | 'win32' | 'linux';

/**
 * Get common OpenClaw installation paths by platform
 */
function getCommonPaths(): string[] {
  const home = homedir();
  const paths: string[] = [];

  // Common dev locations
  paths.push(
    join(home, 'openclaw'),
    join(home, 'OpenClaw'),
    join(home, 'projects', 'openclaw'),
    join(home, 'code', 'openclaw'),
    join(home, 'dev', 'openclaw'),
    join(home, 'src', 'openclaw'),
    join(home, 'Developer', 'openclaw'),
  );

  // Platform-specific paths
  if (CURRENT_PLATFORM === 'darwin') {
    // macOS
    paths.push(
      '/Applications/OpenClaw.app/Contents/Resources/app',
      join(home, 'Applications', 'OpenClaw.app', 'Contents', 'Resources', 'app'),
      '/opt/homebrew/lib/node_modules/openclaw',
      '/usr/local/lib/node_modules/openclaw',
      '/opt/homebrew/Cellar/openclaw',
    );
  } else if (CURRENT_PLATFORM === 'win32') {
    // Windows
    const appData = process.env.APPDATA || join(home, 'AppData', 'Roaming');
    const localAppData = process.env.LOCALAPPDATA || join(home, 'AppData', 'Local');
    const programFiles = process.env.ProgramFiles || 'C:\\Program Files';
    const programFilesX86 = process.env['ProgramFiles(x86)'] || 'C:\\Program Files (x86)';

    paths.push(
      join(programFiles, 'OpenClaw', 'resources', 'app'),
      join(programFilesX86, 'OpenClaw', 'resources', 'app'),
      join(localAppData, 'Programs', 'openclaw'),
      join(appData, 'npm', 'node_modules', 'openclaw'),
      join(home, 'scoop', 'apps', 'openclaw', 'current'),
    );
  } else if (CURRENT_PLATFORM === 'linux') {
    // Linux
    paths.push(
      '/usr/lib/node_modules/openclaw',
      '/usr/local/lib/node_modules/openclaw',
      '/opt/openclaw',
      join(home, '.local', 'lib', 'node_modules', 'openclaw'),
      join(home, '.local', 'share', 'openclaw'),
      // AppImage extracted
      join(home, '.openclaw'),
      // Snap
      '/snap/openclaw/current',
      // Flatpak
      join(home, '.var', 'app', 'dev.openclaw.OpenClaw', 'data'),
    );
  }

  return paths;
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
      platform: CURRENT_PLATFORM,
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
    platform: CURRENT_PLATFORM,
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
      platform: CURRENT_PLATFORM,
    };
  }

  return null;
}

/**
 * Try to find OpenClaw in common installation paths
 */
function detectCommonPaths(): OpenClawInstallation | null {
  const paths = getCommonPaths();

  for (const path of paths) {
    if (!existsSync(path)) continue;

    // Check for package.json
    const packageJsonPath = join(path, 'package.json');
    if (!existsSync(packageJsonPath)) continue;

    try {
      const packageJson = JSON.parse(readFileSync(packageJsonPath, 'utf-8'));

      // Verify it's OpenClaw
      if (!packageJson.name?.toLowerCase().includes('openclaw')) continue;

      // Find patchable files
      const distPath = join(path, 'dist');
      const gatewayBundle = findGatewayCliBundle(distPath);

      const sourceFile = join(path, 'src/gateway/tools-invoke-http.ts');
      const builtFile = gatewayBundle || join(path, 'dist/gateway/tools-invoke-http.js');

      // Determine patch strategy
      let patchTarget: 'source' | 'built' | 'gateway-bundle';
      let targetFile: string;
      let needsRebuild: boolean;
      let type: 'packaged' | 'homebrew' | 'system-package' = 'packaged';

      // Detect installation type from path
      if (path.includes('homebrew') || path.includes('Cellar')) {
        type = 'homebrew';
      } else if (path.includes('/usr/lib') || path.includes('/opt/') || path.includes('snap') || path.includes('flatpak')) {
        type = 'system-package';
      }

      if (gatewayBundle && existsSync(gatewayBundle)) {
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
        continue; // No patchable file
      }

      return {
        type,
        rootPath: path,
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
        platform: CURRENT_PLATFORM,
      };
    } catch {
      continue;
    }
  }

  return null;
}

/**
 * Detect all OpenClaw installations on the system
 */
export async function detectAllInstallations(): Promise<OpenClawInstallation[]> {
  const installations: OpenClawInstallation[] = [];

  // Check repo clone
  const repoClone = detectRepoClone();
  if (repoClone) installations.push(repoClone);

  // Check local npm
  const npmLocal = detectNpmLocal();
  if (npmLocal) installations.push(npmLocal);

  // Check global npm
  const npmGlobal = detectNpmGlobal();
  if (npmGlobal) installations.push(npmGlobal);

  // Check common paths
  const commonPath = detectCommonPaths();
  if (commonPath) installations.push(commonPath);

  return installations;
}

/**
 * Detect OpenClaw installation
 */
export async function detectOpenClaw(
  searchPath?: string
): Promise<OpenClawInstallation> {
  // Try repo clone first (most common for development)
  let installation = detectRepoClone(searchPath);
  if (installation) {
    installation.platform = CURRENT_PLATFORM;
    return installation;
  }

  // Try local npm install
  installation = detectNpmLocal();
  if (installation) {
    installation.platform = CURRENT_PLATFORM;
    return installation;
  }

  // Try global npm install
  installation = detectNpmGlobal();
  if (installation) {
    installation.platform = CURRENT_PLATFORM;
    return installation;
  }

  // Try common installation paths
  installation = detectCommonPaths();
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
    platform: CURRENT_PLATFORM,
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
