import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import type { HttpClient, HttpClientOptions, HttpResponse } from '../core/http/http-client.js';
import type { VersionInfo } from '../core/types/version.js';
import { deriveVersionInfo } from '../analysis/version-confidence.js';
import { extractAssetUrls, fetchAssetBodies } from '../core/http/asset-links.js';
import { mapWithConcurrency } from '../utils/concurrency.js';

const PLUGIN_PATH_PATTERN = /\/wp-content\/plugins\/([a-z0-9-]+)\//gi;
const STABLE_TAG_PATTERN = /Stable tag:\s*([\d.]+)/i;

const DICTIONARY_CONCURRENCY = 5;

// Layer 3 (audit + deep only): a small, curated list of well-known
// wordpress.org plugin slugs, each verified against the live
// api.wordpress.org/plugins/info/1.0/ endpoint before being added here — a
// typo'd slug would just silently never match anything, so accuracy matters
// more than coverage. Deliberately not a large/generic wordlist per
// CLAUDE.md's "not a brute-force tool" — this exists only to catch plugins
// that Layer 1 misses because their slug never appears in the homepage HTML.
const PLUGIN_DICTIONARY: readonly string[] = [
  'akismet',
  'woocommerce',
  'elementor',
  'wordpress-seo',
  'contact-form-7',
  'jetpack',
  'wp-super-cache',
  'updraftplus',
  'wordfence',
  'all-in-one-seo-pack',
  'classic-editor',
  'wpforms-lite',
  'mailchimp-for-wp',
  'duplicate-post',
  'redirection',
  'wp-mail-smtp',
  'tablepress',
  'really-simple-ssl',
  'litespeed-cache',
  'advanced-custom-fields',
  'w3-total-cache',
  'google-analytics-for-wordpress',
  'autoptimize',
  'wp-optimize',
  'wp-smushit',
  'ninja-forms',
  'wp-fastest-cache',
  'woocommerce-services',
  'google-site-kit',
  'polylang',
  'loco-translate',
  'cookie-notice',
  'complianz-gdpr',
  'wp-google-maps',
  'envira-gallery-lite',
  'regenerate-thumbnails',
  'limit-login-attempts-reloaded',
  'really-simple-captcha',
  'wp-user-avatar',
  'broken-link-checker',
  'query-monitor',
  'code-snippets',
  'custom-post-type-ui',
  'mailpoet',
  'the-events-calendar',
  'buddypress',
  'bbpress',
  'amp',
  'seo-by-rank-math',
  'insert-headers-and-footers',
  'wp-statistics',
  'user-registration',
];

export interface DetectedPlugin {
  slug: string;
  version?: VersionInfo;
}

/**
 * Detects installed plugins. Layer-1 slug detection (from /wp-content/plugins/
 * paths already present in the fetched homepage) runs under both modes;
 * Layer-2 readme.txt version probing only runs when context.authorizationMode
 * is 'audit' — a single scanner branching on mode rather than two scanners,
 * per the project's chosen resolution of the prospect/audit split.
 *
 * At `--profile deep`: Layer 1 also scans CSS/JS assets the homepage already
 * references (still no guessed paths — see core/http/asset-links.ts), and
 * audit+deep additionally runs Layer 3 dictionary enumeration, appending any
 * newly-discovered plugin into this same `plugins` array so it flows through
 * the exact same downstream enrichment (WordPress.org outdated-check, WPScan
 * CVE lookup) as anything Layer 1 found.
 */
export class PluginScanner implements Scanner {
  readonly name = 'plugin-scanner';
  readonly minAuthorization = 'prospect' as const;

  constructor(
    private readonly httpClientOptions?: HttpClientOptions,
    private readonly httpClient?: HttpClient,
  ) {}

  supports(context: AuditContext): boolean {
    return context.isWordPress() === true;
  }

  async run(context: AuditContext): Promise<ScannerResult> {
    const startedAt = Date.now();
    const response = context.getHttpResponse() as HttpResponse;

    const scannedBody = await this.buildScannedBody(context, response);
    const slugs = this.extractSlugs(scannedBody);
    const plugins: DetectedPlugin[] = await Promise.all(
      slugs.map((slug) => this.detectPlugin(context, response, slug, scannedBody)),
    );

    if (context.authorizationMode === 'audit' && context.profile === 'deep') {
      const dictionaryPlugins = await this.enumerateDictionaryPlugins(
        response,
        plugins.map((p) => p.slug),
      );
      plugins.push(...dictionaryPlugins);
    }

    return {
      scannerName: this.name,
      status: 'ok',
      data: { plugins },
      durationMs: Date.now() - startedAt,
    };
  }

  /**
   * At --profile deep, also fetches CSS/JS assets the homepage already
   * references and scans those bodies too — a plugin can enqueue a
   * stylesheet without its slug ever appearing in the raw homepage HTML.
   * Still Layer 1: every URL fetched here was already linked from the page
   * we fetched, never a guessed path.
   */
  private async buildScannedBody(context: AuditContext, response: HttpResponse): Promise<string> {
    if (context.profile !== 'deep' || !this.httpClient || !this.httpClientOptions) {
      return response.body;
    }
    const assetUrls = extractAssetUrls(response.body, response.url);
    const assetBodies = await fetchAssetBodies(this.httpClient, this.httpClientOptions, assetUrls);
    return [response.body, ...assetBodies].join('\n');
  }

  private extractSlugs(body: string): string[] {
    const slugs = new Set<string>();
    for (const match of body.matchAll(PLUGIN_PATH_PATTERN)) {
      slugs.add(match[1]!);
    }
    return [...slugs];
  }

  private async detectPlugin(
    context: AuditContext,
    response: HttpResponse,
    slug: string,
    scannedBody: string,
  ): Promise<DetectedPlugin> {
    const assetQueryVersion = this.extractAssetQueryVersion(scannedBody, slug);
    const readmeVersion =
      context.authorizationMode === 'audit'
        ? await this.probeReadmeVersion(response, slug)
        : undefined;

    const version = deriveVersionInfo([
      readmeVersion ? { value: readmeVersion, source: 'plugin-readme' as const } : undefined,
      assetQueryVersion
        ? { value: assetQueryVersion, source: 'asset-query-string' as const }
        : undefined,
    ]);

    return version ? { slug, version } : { slug };
  }

  private extractAssetQueryVersion(body: string, slug: string): string | undefined {
    const pattern = new RegExp(`/wp-content/plugins/${slug}/[^"'\\s]*\\?ver=([\\d.]+)`, 'i');
    return body.match(pattern)?.[1];
  }

  /** Layer-2, audit only: fetches the plugin's own readme.txt from the target and reads its Stable tag. */
  private async probeReadmeVersion(
    response: HttpResponse,
    slug: string,
  ): Promise<string | undefined> {
    if (!this.httpClient || !this.httpClientOptions) {
      return undefined;
    }
    const readmeUrl = new URL(`/wp-content/plugins/${slug}/readme.txt`, response.url).toString();
    try {
      const readme = await this.httpClient.fetchUrl(readmeUrl, this.httpClientOptions);
      if (readme.status !== 200) {
        return undefined;
      }
      return readme.body.match(STABLE_TAG_PATTERN)?.[1];
    } catch {
      return undefined;
    }
  }

  /**
   * Layer 3, audit + deep only: probes PLUGIN_DICTIONARY's readme.txt for
   * any slug Layer 1/2 didn't already find, throttled to be polite to the
   * target even under audit consent.
   */
  private async enumerateDictionaryPlugins(
    response: HttpResponse,
    alreadyDetectedSlugs: readonly string[],
  ): Promise<DetectedPlugin[]> {
    if (!this.httpClient || !this.httpClientOptions) return [];

    const alreadyDetected = new Set(alreadyDetectedSlugs);
    const candidates = PLUGIN_DICTIONARY.filter((slug) => !alreadyDetected.has(slug));

    const discovered = await mapWithConcurrency(
      candidates,
      DICTIONARY_CONCURRENCY,
      async (slug): Promise<DetectedPlugin | undefined> => {
        const stableTag = await this.probeReadmeVersion(response, slug);
        if (!stableTag) return undefined;
        const version = deriveVersionInfo([{ value: stableTag, source: 'plugin-readme' as const }]);
        return version ? { slug, version } : { slug };
      },
    );

    return discovered.filter((plugin): plugin is DetectedPlugin => plugin !== undefined);
  }
}
