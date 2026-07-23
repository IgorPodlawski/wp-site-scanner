import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import { NotImplementedError } from '../core/errors.js';

/** Detects whether the target is WordPress at all. If not, the pipeline short-circuits after this scanner. */
export class WordPressDetector implements Scanner {
  readonly name = 'wordpress-detector';
  readonly minAuthorization = 'prospect' as const;

  supports(context: AuditContext): boolean {
    return context.getHttpResponse() !== undefined;
  }

  run(_context: AuditContext): Promise<ScannerResult> {
    // TODO (Phase 1): inspect generator meta / wp-content paths / REST discovery link,
    // then call context.setDetectedWordPress().
    throw new NotImplementedError('WordPressDetector.run (Phase 1 feature work)');
  }
}
