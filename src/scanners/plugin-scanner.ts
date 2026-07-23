import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import { NotImplementedError } from '../core/errors.js';

/**
 * Detects installed plugins.
 *
 * Open design question for Phase 1 implementation: this scanner spans two
 * authorization layers per CLAUDE.md — Layer-1 slug detection from
 * /wp-content/... paths (prospect) vs. Layer-2 version probing via each
 * plugin's readme.txt (audit only). A Scanner can only declare one
 * minAuthorization, so this must resolve to one of:
 *   (a) minAuthorization: 'prospect', with the run() body checking
 *       context.authorizationMode and skipping the readme.txt probe under
 *       prospect, or
 *   (b) splitting into PluginSlugScanner (prospect) and
 *       PluginVersionProbeScanner (audit) as two separate scanners.
 * Not resolved here — this is real Phase 1 scanner-logic design, not
 * architecture.
 */
export class PluginScanner implements Scanner {
  readonly name = 'plugin-scanner';
  readonly minAuthorization = 'prospect' as const;

  supports(context: AuditContext): boolean {
    return context.isWordPress() === true;
  }

  run(_context: AuditContext): Promise<ScannerResult> {
    throw new NotImplementedError('PluginScanner.run (Phase 1 feature work)');
  }
}
