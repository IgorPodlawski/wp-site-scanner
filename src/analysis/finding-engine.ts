import type { AuditContext, Finding } from '../core/types/index.js';
import { NotImplementedError } from '../core/errors.js';

/**
 * Interprets raw scanner observations into Findings. Never emit raw scanner
 * output directly — every Finding goes through core/types/finding.ts's
 * createFinding(), which mechanically enforces confidence-caps-severity.
 */
export function generateFindings(_context: AuditContext): Finding[] {
  // TODO (Phase 1): derive findings from context.getScannerResults() + context.getEnrichment(),
  // constructing each via createFinding().
  throw new NotImplementedError('generateFindings (Phase 1 feature work)');
}
