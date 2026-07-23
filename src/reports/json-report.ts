import type { AuditResult } from '../core/types/index.js';

/**
 * JSON output stays language-neutral (message keys + params) — HTML/PDF are
 * where locale rendering happens. This is genuinely simple, so it's
 * implemented for real rather than stubbed.
 */
export function renderJson(result: AuditResult): string {
  return JSON.stringify(result, null, 2);
}
