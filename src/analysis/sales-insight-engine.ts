import type { Finding } from '../core/types/index.js';
import { NotImplementedError } from '../core/errors.js';

/**
 * Evidence-based only, never exaggerated. Every insight references the
 * finding(s) it is built on via findingIds — no free text, message keys +
 * params like everything else user-facing.
 */
export interface SalesInsight {
  findingIds: string[];
  messageKey: string;
  messageParams?: Record<string, string | number>;
}

export function generateSalesInsights(_findings: readonly Finding[]): SalesInsight[] {
  // TODO (Phase 1): map findings -> evidence-based insights, never inventing claims beyond the evidence.
  throw new NotImplementedError('generateSalesInsights (Phase 1 feature work)');
}
