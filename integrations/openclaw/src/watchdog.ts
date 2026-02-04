/**
 * Integrity Watchdog
 *
 * Monitors patched files for tampering and optionally re-patches.
 */

import { watch } from 'fs';
import { loadManifest, verifyPatchIntegrity } from './manifest.js';
import { applyPatch } from './patcher.js';
import { detectOpenClaw } from './detector.js';

export interface WatchdogOptions {
  autoRepatch?: boolean;
  checkIntervalMs?: number;
  onTampering?: (file: string) => void;
}

const DEFAULT_OPTIONS: Required<WatchdogOptions> = {
  autoRepatch: false,
  checkIntervalMs: 30000, // 30 seconds
  onTampering: (file: string) => {
    console.error(`⚠️  TAMPERING DETECTED: ${file}`);
    console.error('   Run: faramesh-patch verify');
  },
};

/**
 * Start integrity watchdog
 */
export function startWatchdog(options: WatchdogOptions = {}): () => void {
  const opts = { ...DEFAULT_OPTIONS, ...options };

  const manifest = loadManifest();
  if (!manifest) {
    console.error('Watchdog: No patch manifest found');
    return () => {};
  }

  console.log('🐕 Starting integrity watchdog...');
  console.log(`   Check interval: ${opts.checkIntervalMs}ms`);
  console.log(`   Auto-repatch: ${opts.autoRepatch ? 'enabled' : 'disabled'}`);

  const intervalId = setInterval(async () => {
    for (const patch of manifest.patches) {
      const valid = verifyPatchIntegrity(patch);

      if (!valid) {
        console.error(`⚠️  TAMPERING DETECTED: ${patch.file}`);
        opts.onTampering(patch.file);

        if (opts.autoRepatch) {
          console.log('🔧 Auto-repatching...');

          try {
            const installation = await detectOpenClaw();
            const result = await applyPatch(installation);

            if (result.success) {
              console.log('✓ Patch reapplied successfully');
            } else {
              console.error(`✗ Failed to reapply patch: ${result.message}`);
            }
          } catch (error: any) {
            console.error(`✗ Auto-repatch error: ${error.message}`);
          }
        }
      }
    }
  }, opts.checkIntervalMs);

  return () => {
    clearInterval(intervalId);
    console.log('🐕 Watchdog stopped');
  };
}

/**
 * Run a one-time integrity check
 */
export async function checkIntegrity(): Promise<boolean> {
  const manifest = loadManifest();

  if (!manifest) {
    return false;
  }

  let allValid = true;

  for (const patch of manifest.patches) {
    const valid = verifyPatchIntegrity(patch);
    if (!valid) {
      allValid = false;
    }
  }

  return allValid;
}
