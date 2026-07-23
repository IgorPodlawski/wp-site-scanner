import type { Command } from 'commander';
import { setLocale } from '../../i18n/translate.js';
import { printMessage } from '../output.js';

export function registerHistoryCommand(program: Command): void {
  program
    .command('history <domain>')
    .description('Show past audit results for a domain')
    .option('--lang <lang>', 'report language: en|pl', 'en')
    .action(async (_domain: string, rawOptions: { lang?: 'en' | 'pl' }) => {
      await setLocale(rawOptions.lang ?? 'en');
      // TODO (Phase 3): read saved AuditResults via storage/json-store for this domain.
      printMessage('cli.history.notImplemented');
    });
}
