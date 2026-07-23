import type { Command } from 'commander';
import { z } from 'zod';
import { setLocale } from '../../i18n/translate.js';
import { printMessage, printError } from '../output.js';
import { buildTarget } from '../../core/types/target.js';
import { AuditOrchestrator } from '../../core/orchestrator/audit-orchestrator.js';
import type { AuditRequest } from '../../core/orchestrator/audit-request.js';
import { createScanners } from '../../scanners/scanner-registry.js';
import {
  createWordPressOrgClient,
  createWpscanClient,
} from '../../integrations/integration-registry.js';
import { loadConfig } from '../../config/load-config.js';
import { createLogger } from '../../utils/logger.js';
import { AuditFailureError } from '../../core/errors.js';
import { auditResultPathForResult } from '../../storage/paths.js';
import { renderHtml } from '../../reports/html-report.js';
import { saveHtmlReport } from '../../reports/report-generator.js';

const auditOptionsSchema = z.object({
  profile: z.enum(['quick', 'standard', 'deep']).default('standard'),
  iHaveAuthorization: z.boolean().default(false),
  lang: z.enum(['en', 'pl']).default('en'),
  cache: z.boolean().default(true),
});

export function registerAuditCommand(program: Command): void {
  program
    .command('audit <url>')
    .description('Run a WordPress quality assessment against a target')
    .option('--profile <profile>', 'quick|standard|deep', 'standard')
    .option('--i-have-authorization', 'unlock audit mode (requires a consent artifact)')
    .option('--lang <lang>', 'report language: en|pl', 'en')
    .option('--no-cache', 'disable cache / force refresh')
    .action(async (url: string, rawOptions: unknown) => {
      const options = auditOptionsSchema.parse(rawOptions);
      await setLocale(options.lang);

      const target = buildTarget(url);
      const request: AuditRequest = {
        targetInput: url,
        requestedMode: options.iHaveAuthorization ? 'audit' : 'prospect',
        profile: options.profile,
        lang: options.lang,
        useCache: options.cache,
        ...(options.iHaveAuthorization
          ? { consent: { confirmed: true, source: 'cli-flag' as const } }
          : {}),
      };

      printMessage('cli.audit.starting', { mode: request.requestedMode, target: target.domain });

      const config = loadConfig();
      const logger = createLogger(config);
      const orchestrator = new AuditOrchestrator(
        createScanners(config),
        config,
        logger,
        createWordPressOrgClient(config),
        createWpscanClient(config),
      );

      try {
        const result = await orchestrator.run(request);
        const savedPath = auditResultPathForResult(result);
        printMessage('cli.audit.done', {
          status: result.status,
          target: result.target.domain,
          path: savedPath,
        });

        const html = await renderHtml(result, options.lang);
        const htmlPath = await saveHtmlReport(result, html);
        printMessage('cli.audit.reportSaved', { path: htmlPath });
      } catch (error) {
        if (error instanceof AuditFailureError) {
          printError(error.message);
          process.exitCode = 1;
          return;
        }
        throw error;
      }
    });
}
