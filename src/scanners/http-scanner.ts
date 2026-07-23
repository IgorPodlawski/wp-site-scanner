import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import { NotImplementedError } from '../core/errors.js';

/** Fetches the homepage (+ assets already referenced by the HTML). Foundation for all other scanners. */
export class HttpScanner implements Scanner {
  readonly name = 'http-scanner';
  readonly minAuthorization = 'prospect' as const;

  supports(_context: AuditContext): boolean {
    return true;
  }

  run(_context: AuditContext): Promise<ScannerResult> {
    // TODO (Phase 1): fetch via core/http/http-client, call context.setHttpResponse().
    throw new NotImplementedError('HttpScanner.run (Phase 1 feature work)');
  }
}
