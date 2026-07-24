import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import type { HttpClient, HttpClientOptions, HttpResponse } from '../core/http/http-client.js';
import type { VersionInfo, VersionSource } from '../core/types/version.js';
import { deriveVersionInfo, WP_VERSION_SHAPE } from '../analysis/version-confidence.js';
import { extractAssetUrls, fetchAssetBodies } from '../core/http/asset-links.js';
import { mapWithConcurrency } from '../utils/concurrency.js';

const DICTIONARY_CONCURRENCY = 5;

export interface DetectedComponent {
  slug: string;
  version?: VersionInfo;
}

export interface ComponentScannerConfig {
  name: string;
  /** e.g. 'plugins' or 'themes' — the `/wp-content/<segment>/<slug>/` path fragment. */
  contentPathSegment: string;
  /** e.g. 'readme.txt' or 'style.css' — probed only under audit mode (Layer 2/3). */
  versionProbeFilename: string;
  /** Must have exactly one capture group for the version string. */
  versionLinePattern: RegExp;
  versionSource: VersionSource;
  /**
   * Layer 3 (audit + deep only): a small, curated list of well-known
   * wordpress.org slugs, each verified against the live
   * api.wordpress.org/{plugins,themes}/info/1.2/ endpoint before being added
   * — a typo'd slug would just silently never match anything, so accuracy
   * matters more than coverage. Deliberately not a large/generic wordlist
   * per CLAUDE.md's "not a brute-force tool" — this exists only to catch
   * components that Layer 1 misses because their slug never appears in the
   * homepage HTML.
   */
  dictionary: readonly string[];
}

/**
 * Shared implementation behind PluginScanner and ThemeScanner: the two are
 * otherwise identical (path pattern, version-probe filename/pattern, version
 * source tag, and dictionary are the only real differences). Layer-1 slug
 * detection (from /wp-content/<segment>/ paths already present in the
 * fetched homepage) runs under both modes; Layer-2 version-file probing only
 * runs when context.authorizationMode is 'audit'.
 *
 * At `--profile deep`: Layer 1 also scans CSS/JS assets the homepage already
 * references (still no guessed paths — see core/http/asset-links.ts), and
 * audit+deep additionally runs Layer 3 dictionary enumeration, appending any
 * newly-discovered component into this same array so it flows through the
 * exact same downstream enrichment (WordPress.org outdated-check, WPScan CVE
 * lookup) as anything Layer 1 found.
 */
export class ComponentScanner implements Scanner {
  readonly name: string;
  readonly minAuthorization = 'prospect' as const;

  private readonly slugPattern: RegExp;

  constructor(
    private readonly config: ComponentScannerConfig,
    private readonly httpClientOptions?: HttpClientOptions,
    private readonly httpClient?: HttpClient,
  ) {
    this.name = config.name;
    this.slugPattern = new RegExp(`/wp-content/${config.contentPathSegment}/([a-z0-9-]+)/`, 'gi');
  }

  supports(context: AuditContext): boolean {
    return context.isWordPress() === true;
  }

  async run(context: AuditContext): Promise<ScannerResult> {
    const startedAt = Date.now();
    const response = context.getHttpResponse() as HttpResponse;

    const scannedBody = await this.buildScannedBody(context, response);
    const slugs = this.extractSlugs(scannedBody);
    const components: DetectedComponent[] = await Promise.all(
      slugs.map((slug) => this.detectComponent(context, response, slug, scannedBody)),
    );

    if (context.authorizationMode === 'audit' && context.profile === 'deep') {
      const dictionaryComponents = await this.enumerateDictionary(
        response,
        components.map((c) => c.slug),
      );
      components.push(...dictionaryComponents);
    }

    return {
      scannerName: this.name,
      status: 'ok',
      data: { [this.config.contentPathSegment]: components },
      durationMs: Date.now() - startedAt,
    };
  }

  /**
   * At --profile deep, also fetches CSS/JS assets the homepage already
   * references and scans those bodies too — a component can enqueue a
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
    for (const match of body.matchAll(this.slugPattern)) {
      slugs.add(match[1]!);
    }
    return [...slugs];
  }

  private async detectComponent(
    context: AuditContext,
    response: HttpResponse,
    slug: string,
    scannedBody: string,
  ): Promise<DetectedComponent> {
    const assetQueryVersion = this.extractAssetQueryVersion(scannedBody, slug);
    const probedVersion =
      context.authorizationMode === 'audit' ? await this.probeVersion(response, slug) : undefined;

    const version = deriveVersionInfo([
      probedVersion ? { value: probedVersion, source: this.config.versionSource } : undefined,
      assetQueryVersion
        ? { value: assetQueryVersion, source: 'asset-query-string' as const }
        : undefined,
    ]);

    return version ? { slug, version } : { slug };
  }

  private extractAssetQueryVersion(body: string, slug: string): string | undefined {
    const pattern = new RegExp(
      `/wp-content/${this.config.contentPathSegment}/${slug}/[^"'\\s]*\\?ver=(${WP_VERSION_SHAPE})`,
      'i',
    );
    return body.match(pattern)?.[1];
  }

  /** Layer-2, audit only: fetches the component's own version file from the target and reads its version line. */
  private async probeVersion(response: HttpResponse, slug: string): Promise<string | undefined> {
    if (!this.httpClient || !this.httpClientOptions) {
      return undefined;
    }
    const fileUrl = new URL(
      `/wp-content/${this.config.contentPathSegment}/${slug}/${this.config.versionProbeFilename}`,
      response.url,
    ).toString();
    try {
      const file = await this.httpClient.fetchUrl(fileUrl, this.httpClientOptions);
      if (file.status !== 200) {
        return undefined;
      }
      return file.body.match(this.config.versionLinePattern)?.[1];
    } catch {
      return undefined;
    }
  }

  /**
   * Layer 3, audit + deep only: probes the dictionary's version file for any
   * slug Layer 1/2 didn't already find, throttled to be polite to the
   * target even under audit consent.
   */
  private async enumerateDictionary(
    response: HttpResponse,
    alreadyDetectedSlugs: readonly string[],
  ): Promise<DetectedComponent[]> {
    if (!this.httpClient || !this.httpClientOptions) return [];

    const alreadyDetected = new Set(alreadyDetectedSlugs);
    const candidates = this.config.dictionary.filter((slug) => !alreadyDetected.has(slug));

    const discovered = await mapWithConcurrency(
      candidates,
      DICTIONARY_CONCURRENCY,
      async (slug): Promise<DetectedComponent | undefined> => {
        const probedVersion = await this.probeVersion(response, slug);
        if (!probedVersion) return undefined;
        const version = deriveVersionInfo([
          { value: probedVersion, source: this.config.versionSource },
        ]);
        return version ? { slug, version } : { slug };
      },
    );

    return discovered.filter(
      (component): component is DetectedComponent => component !== undefined,
    );
  }
}
