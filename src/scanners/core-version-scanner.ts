import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import type { HttpResponse } from '../core/http/http-client.js';
import type { VersionInfo, VersionSource } from '../core/types/version.js';
import { deriveConfidence } from '../analysis/version-confidence.js';

// A real WordPress version is always at least major.minor ("6.4", "5.9.3") —
// requiring the dot rejects the two garbage shapes seen live: a bare cache-busting
// timestamp (no dot at all: `?ver=1774442679`) and a content hash (`?ver=85d537c6`,
// which under a digits-only pattern partial-matches as the bogus version "85").
const VERSION_SHAPE = /\d+\.\d+(?:\.\d+)?/;

const GENERATOR_PATTERN = new RegExp(
  `<meta[^>]+name=["']generator["'][^>]*wordpress\\s+(${VERSION_SHAPE.source})`,
  'i',
);

// Deliberately narrow: matching *any* /wp-includes/...?ver= is a real false-positive
// trap. WordPress bundles third-party libraries under /wp-includes/js/ (jQuery,
// jQuery Migrate, jQuery UI, ...) that carry their own independent version —
// e.g. jquery.min.js?ver=3.7.1 has nothing to do with WP core being "3.7.1"
// (a genuinely ancient, insecure release), it's just jQuery's own current
// version colliding with an old WP release number. Block-editor "dist" bundles
// (wp-includes/js/dist/*, wp-includes/css/dist/*) are just as unsafe — some of
// them use a content-hash as their `?ver=`, not the WP version at all (seen
// live: hooks.min.js?ver=7496969728). Even within this narrow allowlist, a
// caching/optimization plugin (seen live: WP Rocket) can still rewrite the
// `?ver=` of these exact files to its own cache-busting value — the
// VERSION_SHAPE requirement is what catches that, not the allowlist alone.
const CORE_ASSET_QUERY_PATTERN = new RegExp(
  `/wp-includes/(?:js/wp-emoji-release\\.min\\.js|js/wp-embed\\.min\\.js|css/dashicons\\.min\\.css)\\?ver=(${VERSION_SHAPE.source})`,
  'i',
);

/** Detects WordPress core version from generator meta / asset query strings. */
export class CoreVersionScanner implements Scanner {
  readonly name = 'core-version-scanner';
  readonly minAuthorization = 'prospect' as const;

  supports(context: AuditContext): boolean {
    return context.isWordPress() === true;
  }

  async run(context: AuditContext): Promise<ScannerResult> {
    const startedAt = Date.now();
    const response = context.getHttpResponse() as HttpResponse;

    const generatorVersion = response.body.match(GENERATOR_PATTERN)?.[1];
    const assetQueryVersion = response.body.match(CORE_ASSET_QUERY_PATTERN)?.[1];

    const version = this.buildVersionInfo(generatorVersion, assetQueryVersion);

    return {
      scannerName: this.name,
      status: 'ok',
      data: { version },
      durationMs: Date.now() - startedAt,
    };
  }

  private buildVersionInfo(
    generatorVersion: string | undefined,
    assetQueryVersion: string | undefined,
  ): VersionInfo | undefined {
    // Independent sources agreeing is what earns 'confirmed'; a conflict between
    // them means the query-string source is unreliable here, so it's dropped
    // rather than trusted (false positives are worse than misses).
    if (generatorVersion && assetQueryVersion && generatorVersion === assetQueryVersion) {
      return this.toVersionInfo(generatorVersion, ['generator-meta', 'asset-query-string']);
    }
    if (generatorVersion) {
      return this.toVersionInfo(generatorVersion, ['generator-meta']);
    }
    if (assetQueryVersion) {
      return this.toVersionInfo(assetQueryVersion, ['asset-query-string']);
    }
    return undefined;
  }

  private toVersionInfo(value: string, sources: VersionSource[]): VersionInfo {
    return { value, sources, confidence: deriveConfidence(sources) };
  }
}
