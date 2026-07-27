import type { FindingSeverity } from '../core/types/finding.js';

/**
 * CVSS base score -> FindingSeverity, per the fixed table (never adjusted
 * for account privileges or anything else not present in the score itself):
 * 9.0-10.0 critical, 7.0-8.9 high, 4.0-6.9 medium, 0.1-3.9 low, 0 info.
 */
export function severityFromCvss(score: number): FindingSeverity {
  if (score >= 9.0) return 'critical';
  if (score >= 7.0) return 'high';
  if (score >= 4.0) return 'medium';
  if (score >= 0.1) return 'low';
  return 'info';
}
