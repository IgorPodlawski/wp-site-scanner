import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import type { HttpResponse } from '../core/http/http-client.js';

const WORDPRESS_SIGNALS = [
  { name: 'generator-meta', pattern: /<meta[^>]+name=["']generator["'][^>]*wordpress/i },
  { name: 'wp-content-path', pattern: /\/wp-content\// },
  { name: 'wp-includes-path', pattern: /\/wp-includes\// },
  { name: 'rest-api-link', pattern: /rel=["']https:\/\/api\.w\.org\/["']/ },
] as const;

/** Detects whether the target is WordPress at all. If not, the pipeline short-circuits after this scanner. */
export class WordPressDetector implements Scanner {
  readonly name = 'wordpress-detector';
  readonly minAuthorization = 'prospect' as const;

  supports(context: AuditContext): boolean {
    return context.getHttpResponse() !== undefined;
  }

  async run(context: AuditContext): Promise<ScannerResult> {
    const startedAt = Date.now();
    const response = context.getHttpResponse() as HttpResponse;

    const matchedSignals = WORDPRESS_SIGNALS.filter((signal) =>
      signal.pattern.test(response.body),
    ).map((signal) => signal.name);

    const isWordPress = matchedSignals.length > 0;
    context.setDetectedWordPress(isWordPress);

    return {
      scannerName: this.name,
      status: 'ok',
      data: { isWordPress, matchedSignals },
      durationMs: Date.now() - startedAt,
    };
  }
}
