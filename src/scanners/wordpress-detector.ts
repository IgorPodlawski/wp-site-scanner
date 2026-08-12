import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import type { HttpResponse } from '../core/http/http-client.js';

const WORDPRESS_SIGNALS = [
  { name: 'generator-meta', pattern: /<meta[^>]+name=["']generator["'][^>]*wordpress/i },
  { name: 'wp-content-path', pattern: /\/wp-content\// },
  { name: 'wp-includes-path', pattern: /\/wp-includes\// },
  { name: 'rest-api-link', pattern: /rel=["']https:\/\/api\.w\.org\/["']/ },
  // Bedrock (roots.io) and similar boilerplates rename wp-content to app/ —
  // themes/plugins/mu-plugins/uploads as siblings under app/ is still
  // unmistakably WordPress-specific vocabulary, not a generic "app" false
  // positive. Verified live against a real Bedrock+Sage site that the other
  // four signals all missed entirely (it also strips the generator tag and
  // doesn't emit the api.w.org discovery link).
  { name: 'bedrock-content-path', pattern: /\/app\/(?:themes|plugins|mu-plugins|uploads)\// },
  // The REST API root itself — present on virtually every modern WP site
  // regardless of content-directory naming convention.
  { name: 'wp-json-path', pattern: /\/wp-json\// },
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
