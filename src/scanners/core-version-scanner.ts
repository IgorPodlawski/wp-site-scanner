import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import { NotImplementedError } from '../core/errors.js';

/** Detects WordPress core version from generator meta / asset query strings. */
export class CoreVersionScanner implements Scanner {
  readonly name = 'core-version-scanner';
  readonly minAuthorization = 'prospect' as const;

  supports(context: AuditContext): boolean {
    return context.isWordPress() === true;
  }

  run(_context: AuditContext): Promise<ScannerResult> {
    // TODO (Phase 1): produce a VersionInfo per src/core/types/version.ts confidence rules.
    throw new NotImplementedError('CoreVersionScanner.run (Phase 1 feature work)');
  }
}
