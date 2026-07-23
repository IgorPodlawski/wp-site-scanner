import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import { NotImplementedError } from '../core/errors.js';

/** Checks HTTP security headers (CSP, HSTS, X-Frame-Options, etc.) from the already-fetched response. */
export class HeaderScanner implements Scanner {
  readonly name = 'header-scanner';
  readonly minAuthorization = 'prospect' as const;

  supports(context: AuditContext): boolean {
    return context.getHttpResponse() !== undefined;
  }

  run(_context: AuditContext): Promise<ScannerResult> {
    throw new NotImplementedError('HeaderScanner.run (Phase 1 feature work)');
  }
}
