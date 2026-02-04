/**
 * Backup and Restore System
 *
 * Creates backups before patching and restores them on uninstall.
 */

import { copyFileSync, existsSync, readFileSync, writeFileSync } from 'fs';
import { join, basename } from 'path';
import { getBackupDir, hashFile } from './manifest.js';

export interface BackupResult {
  success: boolean;
  backupPath?: string;
  originalHash?: string;
  error?: string;
}

/**
 * Create backup of file before patching
 */
export function createBackup(
  filePath: string,
  openclawVersion: string
): BackupResult {
  try {
    if (!existsSync(filePath)) {
      return {
        success: false,
        error: `File not found: ${filePath}`,
      };
    }

    const backupDir = getBackupDir(openclawVersion);
    const backupPath = join(backupDir, basename(filePath));

    // Calculate hash before backup
    const originalHash = hashFile(filePath);

    // Copy file to backup location
    copyFileSync(filePath, backupPath);

    return {
      success: true,
      backupPath,
      originalHash,
    };
  } catch (error: any) {
    return {
      success: false,
      error: error.message,
    };
  }
}

/**
 * Restore file from backup
 */
export function restoreBackup(
  filePath: string,
  backupPath: string
): boolean {
  try {
    if (!existsSync(backupPath)) {
      console.error(`Backup not found: ${backupPath}`);
      return false;
    }

    // Restore original file
    copyFileSync(backupPath, filePath);

    return true;
  } catch (error: any) {
    console.error(`Failed to restore backup: ${error.message}`);
    return false;
  }
}

/**
 * Verify backup matches original file
 */
export function verifyBackup(
  backupPath: string,
  expectedHash: string
): boolean {
  if (!existsSync(backupPath)) {
    return false;
  }

  const backupHash = hashFile(backupPath);
  return backupHash === expectedHash;
}
