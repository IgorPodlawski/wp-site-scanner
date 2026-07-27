import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import type { HttpResponse } from '../core/http/http-client.js';
import type { VersionInfo, VersionSource } from '../core/types/version.js';
import { deriveConfidence, WP_VERSION_SHAPE } from '../analysis/version-confidence.js';

const GENERATOR_PATTERN = new RegExp(
  `<meta[^>]+name=["']generator["'][^>]*wordpress\\s+(${WP_VERSION_SHAPE})`,
  'i',
);

// Deliberately narrow: matching *any* /wp-includes/...?ver= is a real false-positive
// trap. WordPress bundles third-party libraries under /wp-includes/js/ (jQuery,
// jQuery Migrate, jQuery UI, ...) that carry their own independent version —
// e.g. jquery.min.js?ver=3.7.1 has nothing to do with WP core being "3.7.1"
// (a genuinely ancient, insecure release), it's just jQuery's own current
// version colliding with an old WP release number. Most block-editor "dist"
// JS bundles (wp-includes/js/dist/*) are just as unsafe — they're built by
// webpack and some carry a content-hash as their `?ver=`, not the WP version
// at all (seen live: hooks.min.js?ver=7496969728).
//
// Every file actually listed below is registered in WordPress core's
// script-loader.php (wp_default_scripts()/wp_default_styles()) with no
// explicit version argument, which makes WP_Dependencies default it to
// $wp_version — confirmed by reading that source directly, not assumed.
// wp-util.min.js and block-library/style.min.css follow the exact same
// registration pattern as the original three and were added after being
// seen live agreeing with each other (both 6.5.4) on a site whose homepage
// didn't reference any of the original three at all. Even so, a
// caching/optimization plugin (seen live: WP Rocket) can still rewrite the
// `?ver=` of any of these files to its own cache-busting value — the
// VERSION_SHAPE requirement is what catches that, not the allowlist alone.
const CORE_ASSET_QUERY_PATTERN = new RegExp(
  '/wp-includes/(?:' +
    'js/wp-emoji-release\\.min\\.js|' +
    'js/wp-embed\\.min\\.js|' +
    'js/wp-util\\.min\\.js|' +
    'css/dashicons\\.min\\.css|' +
    'css/dist/block-library/style\\.min\\.css' +
    `)\\?ver=(${WP_VERSION_SHAPE})`,
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
