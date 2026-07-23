import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import { NotImplementedError } from '../core/errors.js';

/** Checks TLS configuration (protocol version, certificate validity/expiry). */
export class TlsScanner implements Scanner {
  readonly name = 'tls-scanner';
  readonly minAuthorization = 'prospect' as const;

  supports(_context: AuditContext): boolean {
    return true;
  }

  run(_context: AuditContext): Promise<ScannerResult> {
    throw new NotImplementedError('TlsScanner.run (Phase 1 feature work)');
  }
}
