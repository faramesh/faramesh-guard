/**
 * Patch Manifest System
 *
 * Tracks what files were patched, their hashes, and backup locations.
 * Stored in ~/.faramesh-guard/patch.json
 */

import { readFileSync, writeFileSync, existsSync, mkdirSync } from 'fs';
import { join } from 'path';
import { homedir } from 'os';
import { createHash } from 'crypto';

export interface PatchManifest {
  version: string;
  timestamp: string;
  openclaw: {
    type: string;
    rootPath: string;
    version: string;
    gitCommit?: string;
  };
  patches: PatchEntry[];
}

export interface PatchEntry {
  file: string;
  originalSha256: string;
  patchedSha256: string;
  backupPath: string;
  patchApplied: string; // ISO timestamp
}

const GUARD_HOME = join(homedir(), '.faramesh-guard');
const MANIFEST_PATH = join(GUARD_HOME, 'patch.json');

/**
 * Calculate SHA256 hash of file
 */
export function hashFile(filePath: string): string {
  const content = readFileSync(filePath);
  return createHash('sha256').update(content).digest('hex');
}

/**
 * Load patch manifest
 */
export function loadManifest(): PatchManifest | null {
  if (!existsSync(MANIFEST_PATH)) {
    return null;
  }

  try {
    return JSON.parse(readFileSync(MANIFEST_PATH, 'utf-8'));
  } catch {
    return null;
  }
}

/**
 * Save patch manifest
 */
export function saveManifest(manifest: PatchManifest): void {
  if (!existsSync(GUARD_HOME)) {
    mkdirSync(GUARD_HOME, { recursive: true });
  }

  writeFileSync(
    MANIFEST_PATH,
    JSON.stringify(manifest, null, 2),
    'utf-8'
  );
}

/**
 * Create backup directory for OpenClaw version
 */
export function getBackupDir(openclawVersion: string): string {
  const backupDir = join(GUARD_HOME, 'backup', openclawVersion);

  if (!existsSync(backupDir)) {
    mkdirSync(backupDir, { recursive: true });
  }

  return backupDir;
}

/**
 * Verify file hash matches manifest
 */
export function verifyPatchIntegrity(entry: PatchEntry): boolean {
  if (!existsSync(entry.file)) {
    return false;
  }

  const currentHash = hashFile(entry.file);
  return currentHash === entry.patchedSha256;
}

/**
 * Check if any patches are applied
 */
export function isPatchedInternal(): boolean {
  const manifest = loadManifest();
  return manifest !== null && manifest.patches.length > 0;
}
