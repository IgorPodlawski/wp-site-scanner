import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import type { HttpClient, HttpClientOptions, HttpResponse } from '../core/http/http-client.js';
import type { VersionInfo } from '../core/types/version.js';
import { deriveVersionInfo } from '../analysis/version-confidence.js';
import { extractAssetUrls, fetchAssetBodies } from '../core/http/asset-links.js';
import { mapWithConcurrency } from '../utils/concurrency.js';

const THEME_PATH_PATTERN = /\/wp-content\/themes\/([a-z0-9-]+)\//gi;
const STYLESHEET_VERSION_PATTERN = /^\s*Version:\s*([\d.]+)/im;

const DICTIONARY_CONCURRENCY = 5;

// Layer 3 (audit + deep only): a small, curated list of well-known
// wordpress.org theme slugs, each verified against the live
// api.wordpress.org/themes/info/1.2/ endpoint before being added here.
// Deliberately not a large/generic wordlist per CLAUDE.md's "not a
// brute-force tool" — this exists only to catch a theme that Layer 1 misses
// because its slug never appears in the homepage HTML.
const THEME_DICTIONARY: readonly string[] = [
  'twentytwentyfour',
  'twentytwentythree',
  'twentytwentytwo',
  'twentytwentyone',
  'twentytwenty',
  'twentynineteen',
  'astra',
  'generatepress',
  'oceanwp',
  'neve',
  'kadence',
  'hello-elementor',
  'storefront',
  'blocksy',
];

export interface DetectedTheme {
  slug: string;
  version?: VersionInfo;
}

/**
 * Detects the active theme (and any referenced parent/child theme). Layer-1
 * slug detection (from /wp-content/themes/ paths already present in the
 * fetched homepage) runs under both modes; Layer-2 style.css header probing
 * only runs when context.authorizationMode is 'audit' — same single-scanner
 * resolution used by PluginScanner.
 *
 * At `--profile deep`: Layer 1 also scans CSS/JS assets the homepage
 * already references (see core/http/asset-links.ts), and audit+deep
 * additionally runs Layer 3 dictionary enumeration, appending any
 * newly-discovered theme into this same `themes` array so it flows through
 * the exact same downstream enrichment as anything Layer 1 found.
 */
export class ThemeScanner implements Scanner {
  readonly name = 'theme-scanner';
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
    const themes: DetectedTheme[] = await Promise.all(
      slugs.map((slug) => this.detectTheme(context, response, slug, scannedBody)),
    );

    if (context.authorizationMode === 'audit' && context.profile === 'deep') {
      const dictionaryThemes = await this.enumerateDictionaryThemes(
        response,
        themes.map((t) => t.slug),
      );
      themes.push(...dictionaryThemes);
    }

    return {
      scannerName: this.name,
      status: 'ok',
      data: { themes },
      durationMs: Date.now() - startedAt,
    };
  }

  /**
   * At --profile deep, also fetches CSS/JS assets the homepage already
   * references and scans those bodies too — still Layer 1: every URL
   * fetched here was already linked from the page we fetched.
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
    for (const match of body.matchAll(THEME_PATH_PATTERN)) {
      slugs.add(match[1]!);
    }
    return [...slugs];
  }

  private async detectTheme(
    context: AuditContext,
    response: HttpResponse,
    slug: string,
    scannedBody: string,
  ): Promise<DetectedTheme> {
    const assetQueryVersion = this.extractAssetQueryVersion(scannedBody, slug);
    const stylesheetVersion =
      context.authorizationMode === 'audit'
        ? await this.probeStylesheetVersion(response, slug)
        : undefined;

    const version = deriveVersionInfo([
      stylesheetVersion
        ? { value: stylesheetVersion, source: 'theme-stylesheet' as const }
        : undefined,
      assetQueryVersion
        ? { value: assetQueryVersion, source: 'asset-query-string' as const }
        : undefined,
    ]);

    return version ? { slug, version } : { slug };
  }

  private extractAssetQueryVersion(body: string, slug: string): string | undefined {
    const pattern = new RegExp(`/wp-content/themes/${slug}/[^"'\\s]*\\?ver=([\\d.]+)`, 'i');
    return body.match(pattern)?.[1];
  }

  /** Layer-2, audit only: fetches the theme's own style.css from the target and reads its Version header. */
  private async probeStylesheetVersion(
    response: HttpResponse,
    slug: string,
  ): Promise<string | undefined> {
    if (!this.httpClient || !this.httpClientOptions) {
      return undefined;
    }
    const styleUrl = new URL(`/wp-content/themes/${slug}/style.css`, response.url).toString();
    try {
      const stylesheet = await this.httpClient.fetchUrl(styleUrl, this.httpClientOptions);
      if (stylesheet.status !== 200) {
        return undefined;
      }
      return stylesheet.body.match(STYLESHEET_VERSION_PATTERN)?.[1];
    } catch {
      return undefined;
    }
  }

  /**
   * Layer 3, audit + deep only: probes THEME_DICTIONARY's style.css for any
   * slug Layer 1/2 didn't already find, throttled to be polite to the
   * target even under audit consent.
   */
  private async enumerateDictionaryThemes(
    response: HttpResponse,
    alreadyDetectedSlugs: readonly string[],
  ): Promise<DetectedTheme[]> {
    if (!this.httpClient || !this.httpClientOptions) return [];

    const alreadyDetected = new Set(alreadyDetectedSlugs);
    const candidates = THEME_DICTIONARY.filter((slug) => !alreadyDetected.has(slug));

    const discovered = await mapWithConcurrency(
      candidates,
      DICTIONARY_CONCURRENCY,
      async (slug): Promise<DetectedTheme | undefined> => {
        const stylesheetVersion = await this.probeStylesheetVersion(response, slug);
        if (!stylesheetVersion) return undefined;
        const version = deriveVersionInfo([
          { value: stylesheetVersion, source: 'theme-stylesheet' as const },
        ]);
        return version ? { slug, version } : { slug };
      },
    );

    return discovered.filter((theme): theme is DetectedTheme => theme !== undefined);
  }
}
