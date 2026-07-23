import type { AuditContext, Scanner, ScannerResult } from '../core/types/index.js';
import type { HttpClient, HttpClientOptions, HttpResponse } from '../core/http/http-client.js';
import type { VersionInfo } from '../core/types/version.js';
import { deriveVersionInfo } from '../analysis/version-confidence.js';

const PLUGIN_PATH_PATTERN = /\/wp-content\/plugins\/([a-z0-9-]+)\//gi;
const STABLE_TAG_PATTERN = /Stable tag:\s*([\d.]+)/i;

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

    const slugs = this.extractSlugs(response.body);
    const plugins: DetectedPlugin[] = await Promise.all(
      slugs.map((slug) => this.detectPlugin(context, response, slug)),
    );

    return {
      scannerName: this.name,
      status: 'ok',
      data: { plugins },
      durationMs: Date.now() - startedAt,
    };
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
  ): Promise<DetectedPlugin> {
    const assetQueryVersion = this.extractAssetQueryVersion(response.body, slug);
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
}
