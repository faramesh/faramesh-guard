#!/usr/bin/env node

/**
 * Faramesh Guard Patcher - CLI
 */

import { program } from 'commander';
import chalk from 'chalk';
import { install, uninstall, verify, status } from './index.js';

program
  .name('faramesh-patch')
  .description('Faramesh Guard runtime patcher for OpenClaw')
  .version('1.0.0');

program
  .command('install')
  .description('Install Faramesh Guard patch to OpenClaw')
  .option('-p, --path <path>', 'OpenClaw installation path')
  .action(async (_args, command) => {
    try {
      console.log(chalk.blue('🛡️  Faramesh Guard Installer\n'));

      const opts = command.opts() as { path?: string };
      const result = await install(opts.path);

      if (result.success) {
        console.log(chalk.green('\n✅ Installation successful!'));

        if (result.needsRebuild) {
          console.log(chalk.yellow('\n⚠️  Action required: Rebuild OpenClaw'));
        }
      } else {
        console.log(chalk.red(`\n✗ Installation failed: ${result.message}`));
        process.exit(1);
      }
    } catch (error: any) {
      console.error(chalk.red(`\nError: ${error.message}`));
      process.exit(1);
    }
  });

program
  .command('uninstall')
  .description('Uninstall Faramesh Guard patch from OpenClaw')
  .action(async () => {
    try {
      console.log(chalk.blue('🛡️  Faramesh Guard Uninstaller\n'));

      const result = await uninstall();

      if (result.success) {
        console.log(chalk.green('\n✅ Uninstallation successful!'));

        if (result.needsRebuild) {
          console.log(chalk.yellow('\n⚠️  Action required: Rebuild OpenClaw'));
        }
      } else {
        console.log(chalk.red(`\n✗ Uninstallation failed: ${result.message}`));
        process.exit(1);
      }
    } catch (error: any) {
      console.error(chalk.red(`\nError: ${error.message}`));
      process.exit(1);
    }
  });

program
  .command('verify')
  .description('Verify patch integrity')
  .action(async () => {
    try {
      const valid = await verify();
      process.exit(valid ? 0 : 1);
    } catch (error: any) {
      console.error(chalk.red(`\nError: ${error.message}`));
      process.exit(1);
    }
  });

program
  .command('status')
  .description('Show patch status')
  .action(async () => {
    try {
      await status();
    } catch (error: any) {
      console.error(chalk.red(`\nError: ${error.message}`));
      process.exit(1);
    }
  });

program.parse();
