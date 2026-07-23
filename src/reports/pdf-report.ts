import { NotImplementedError } from '../core/errors.js';

/**
 * PDF is a Phase 4 feature. Engine choice (Playwright vs. an HTML→PDF
 * library) is deferred to that phase — the signature is fixed now so the
 * report-generator's contract is stable, but the body is intentionally
 * unimplemented.
 */
export function renderPdf(_html: string): Promise<Buffer> {
  throw new NotImplementedError('PDF export is a Phase 4 feature');
}
