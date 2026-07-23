import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import { NotImplementedError } from '../core/errors.js';

/**
 * Detects the active theme.
 *
 * Same open design question as PluginScanner (see plugin-scanner.ts):
 * Layer-1 slug detection is prospect, Layer-2 style.css header probing is
 * audit-only. Resolve the single-scanner-vs-split-scanner question during
 * Phase 1 implementation, not here.
 */
export class ThemeScanner implements Scanner {
  readonly name = 'theme-scanner';
  readonly minAuthorization = 'prospect' as const;

  supports(context: AuditContext): boolean {
    return context.isWordPress() === true;
  }

  run(_context: AuditContext): Promise<ScannerResult> {
    throw new NotImplementedError('ThemeScanner.run (Phase 1 feature work)');
  }
}
