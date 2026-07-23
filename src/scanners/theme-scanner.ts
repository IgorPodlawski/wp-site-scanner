import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import type { HttpClient, HttpClientOptions, HttpResponse } from '../core/http/http-client.js';
import type { VersionInfo } from '../core/types/version.js';
import { deriveVersionInfo } from '../analysis/version-confidence.js';

const THEME_PATH_PATTERN = /\/wp-content\/themes\/([a-z0-9-]+)\//gi;
const STYLESHEET_VERSION_PATTERN = /^\s*Version:\s*([\d.]+)/im;

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

    const slugs = this.extractSlugs(response.body);
    const themes: DetectedTheme[] = await Promise.all(
      slugs.map((slug) => this.detectTheme(context, response, slug)),
    );

    return {
      scannerName: this.name,
      status: 'ok',
      data: { themes },
      durationMs: Date.now() - startedAt,
    };
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
  ): Promise<DetectedTheme> {
    const assetQueryVersion = this.extractAssetQueryVersion(response.body, slug);
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
}
