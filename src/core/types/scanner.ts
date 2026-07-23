import type { AuthorizationMode } from './authorization.js';
import type { AuditContext } from './audit-context.js';

export type ScannerStatus = 'ok' | 'error' | 'skipped';

export interface ScannerResult {
  scannerName: string;
  status: ScannerStatus;
  /** Raw observations only — never interpreted findings. */
  data?: unknown;
  error?: { message: string; cause?: unknown };
  durationMs: number;
}

/**
 * One responsibility per scanner. Scanners never call each other — all
 * communication happens through AuditContext. A scanner produces raw
 * observations; findings are derived later by the Finding Engine.
 */
export interface Scanner {
  name: string;
  minAuthorization: AuthorizationMode;
  supports(context: AuditContext): boolean;
  run(context: AuditContext): Promise<ScannerResult>;
}
