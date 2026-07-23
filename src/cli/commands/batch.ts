import type { Command } from 'commander';
import { setLocale } from '../../i18n/translate.js';
import { printMessage } from '../output.js';

export function registerBatchCommand(program: Command): void {
  program
    .command('batch <file>')
    .description('Run audits for every row in a CSV of leads (prospect by default)')
    .option(
      '--i-have-authorization',
      'require a populated "consent" column to run audit mode per row',
    )
    .option('--lang <lang>', 'report language: en|pl', 'en')
    .action(async (_file: string, rawOptions: { lang?: 'en' | 'pl' }) => {
      await setLocale(rawOptions.lang ?? 'en');
      // TODO (Phase 3): parse CSV, enforce per-row consent column when --i-have-authorization
      // is set, throttle per BATCH_CONCURRENCY / PER_HOST_DELAY_MS, skip+report rows without consent.
      printMessage('cli.batch.notImplemented');
    });
}
