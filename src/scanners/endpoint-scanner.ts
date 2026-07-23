import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import { NotImplementedError } from '../core/errors.js';

/** Audit-only Layer-2 probes: /wp-json/wp/v2/users, xmlrpc.php, /readme.html, directory listing, config backups. */
export class EndpointScanner implements Scanner {
  readonly name = 'endpoint-scanner';
  readonly minAuthorization = 'audit' as const;

  supports(context: AuditContext): boolean {
    return context.isWordPress() === true;
  }

  run(_context: AuditContext): Promise<ScannerResult> {
    throw new NotImplementedError('EndpointScanner.run (Phase 1 feature work)');
  }
}
