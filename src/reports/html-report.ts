import type { AuditResult } from '../core/types/index.js';
import type { Locale } from '../i18n/types.js';
import { NotImplementedError } from '../core/errors.js';

export function renderHtml(_result: AuditResult, _lang: Locale): string {
  // TODO (Phase 1): render src/reports/templates/report.html with the locale's messages,
  // summary, scores, findings, detected plugins/theme, recommendations, sales insights,
  // limitations, and disclaimer (+ consent artifact for audit runs).
  throw new NotImplementedError('renderHtml (Phase 1 feature work)');
}
