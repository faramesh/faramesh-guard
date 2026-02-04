/**
 * Faramesh Guard Patcher - Main Entry Point
 */

import { detectOpenClaw, getGitCommit } from './detector.js';
import { applyPatch, removePatchFromFile } from './patcher.js';
import { loadManifest, hashFile, verifyPatchIntegrity } from './manifest.js';
import { restoreBackup } from './backup.js';

export interface InstallResult {
  success: boolean;
  message: string;
  needsRebuild?: boolean;
}

/**
 * Install Faramesh Guard patch
 */
export async function install(searchPath?: string): Promise<InstallResult> {
  console.log('🔍 Detecting OpenClaw installation...');

  const installation = await detectOpenClaw(searchPath);

  if (installation.type === 'unknown') {
    return {
      success: false,
      message: 'OpenClaw not found. Please install OpenClaw first.',
    };
  }

  console.log(`✓ Found OpenClaw: ${installation.type}`);
  console.log(`  Version: ${installation.version}`);
  console.log(`  Root: ${installation.rootPath}`);
  console.log(`  Patch mode: ${installation.patchTarget}`);
  console.log(`  Target: ${installation.targetFile}`);

  // Check if already patched
  const manifest = loadManifest();
  if (manifest) {
    console.log('⚠️  Faramesh Guard is already installed');
    console.log('   Run uninstall first to re-patch');
    return {
      success: false,
      message: 'Already installed',
    };
  }

  console.log('\n📦 Creating backup...');
  console.log('💉 Applying Faramesh Guard patch...');

  const result = applyPatch(installation);

  if (!result.success) {
    return {
      success: false,
      message: result.message,
    };
  }

  console.log(`✓ Patch applied successfully`);
  console.log(`  Backup: ${result.patchEntry?.backupPath}`);
  console.log(`  Original hash: ${result.patchEntry?.originalSha256.substring(0, 16)}...`);
  console.log(`  Patched hash: ${result.patchEntry?.patchedSha256.substring(0, 16)}...`);

  // Use needsRebuild from installation detection
  const needsRebuild = installation.needsRebuild;

  if (needsRebuild) {
    console.log('\n⚠️  SOURCE FILE PATCHED - REBUILD REQUIRED');
    console.log(`   Run: cd ${installation.rootPath} && pnpm build`);
  } else {
    console.log('\n🎉 NO REBUILD REQUIRED - Guard is active immediately!');
    console.log(`   Patched: ${installation.patchTarget} (built bundle)`);
  }

  console.log('\n✅ Faramesh Guard installed successfully');
  console.log('   Guard is now NON-BYPASSABLE');
  console.log('   All OpenClaw tool calls will be authorized by Guard');

  return {
    success: true,
    message: needsRebuild
      ? 'Installation complete - REBUILD REQUIRED'
      : 'Installation complete - Guard is active immediately!',
    needsRebuild,
  };
}

/**
 * Uninstall Faramesh Guard patch
 */
export async function uninstall(): Promise<InstallResult> {
  console.log('🔍 Checking for Faramesh Guard installation...');

  const manifest = loadManifest();

  if (!manifest) {
    return {
      success: false,
      message: 'Faramesh Guard is not installed',
    };
  }

  console.log(`✓ Found installation: ${manifest.openclaw.type}`);
  console.log(`  OpenClaw version: ${manifest.openclaw.version}`);
  console.log(`  Patches: ${manifest.patches.length}`);

  for (const patch of manifest.patches) {
    console.log(`\n📦 Restoring: ${patch.file}`);

    const result = removePatchFromFile(patch.file, patch.backupPath);

    if (!result.success) {
      console.error(`✗ Failed: ${result.message}`);
      return {
        success: false,
        message: result.message,
      };
    }

    console.log(`✓ Restored from backup`);
  }

  // Remove manifest
  const { unlinkSync, existsSync: fsExistsSync } = await import('fs');
  const { join } = await import('path');
  const { homedir } = await import('os');

  const manifestPath = join(homedir(), '.faramesh-guard', 'patch.json');
  if (fsExistsSync(manifestPath)) {
    unlinkSync(manifestPath);
  }

  const needsRebuild = manifest.openclaw.type === 'repo-clone';

  if (needsRebuild) {
    console.log('\n⚠️  SOURCE FILE RESTORED - REBUILD REQUIRED');
    console.log(`   Run: cd ${manifest.openclaw.rootPath} && npm run build`);
  }

  console.log('\n✅ Faramesh Guard uninstalled successfully');
  console.log('   OpenClaw restored to original state');

  return {
    success: true,
    message: 'Uninstallation complete',
    needsRebuild,
  };
}

/**
 * Verify patch integrity
 */
export async function verify(): Promise<boolean> {
  const manifest = loadManifest();

  if (!manifest) {
    console.log('✗ Faramesh Guard is not installed');
    return false;
  }

  console.log('🔍 Verifying patch integrity...');

  let allValid = true;

  for (const patch of manifest.patches) {
    const valid = verifyPatchIntegrity(patch);

    if (valid) {
      console.log(`✓ ${patch.file}: OK`);
    } else {
      console.log(`✗ ${patch.file}: TAMPERED`);
      allValid = false;
    }
  }

  if (allValid) {
    console.log('\n✅ All patches verified');
  } else {
    console.log('\n⚠️  Patch tampering detected!');
    console.log('   Run: faramesh-install to re-apply patches');
  }

  return allValid;
}

/**
 * Show patch status
 */
export async function status(): Promise<void> {
  const manifest = loadManifest();

  if (!manifest) {
    console.log('Faramesh Guard: NOT INSTALLED');
    return;
  }

  console.log('Faramesh Guard: INSTALLED');
  console.log(`  Version: ${manifest.version}`);
  console.log(`  Installed: ${new Date(manifest.timestamp).toLocaleString()}`);
  console.log(`  OpenClaw: ${manifest.openclaw.type} v${manifest.openclaw.version}`);
  console.log(`  Root: ${manifest.openclaw.rootPath}`);

  if (manifest.openclaw.gitCommit) {
    console.log(`  Git commit: ${manifest.openclaw.gitCommit.substring(0, 12)}`);
  }

  console.log(`\n  Patched files:`);
  for (const patch of manifest.patches) {
    console.log(`    • ${patch.file}`);
    console.log(`      Applied: ${new Date(patch.patchApplied).toLocaleString()}`);
  }
}

// Export all functions
export { detectOpenClaw } from './detector.js';
export { loadManifest, verifyPatchIntegrity } from './manifest.js';
