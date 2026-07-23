import { z } from 'zod';
import type { HttpClient, HttpClientOptions } from '../core/http/http-client.js';
import type { CacheStore } from '../storage/cache-store.js';
import { buildCacheKey } from '../storage/cache-key.js';
import { ok, err, type Result } from '../utils/result.js';
import type { WordPressOrgPluginInfo } from './enrichment-types.js';

const PLUGIN_INFO_API = 'https://api.wordpress.org/plugins/info/1.2/';

// wordpress.org's actual wire format (snake_case) — kept local to this
// client rather than in enrichment-types.ts, which holds the clean internal
// shape every caller consumes. `.transform` does the field renaming as part
// of the one Zod validation boundary this external response crosses.
const rawPluginResponseSchema = z
  .object({
    slug: z.string(),
    version: z.string(),
    last_updated: z.string(),
    active_installs: z.number().int().nonnegative(),
    tested: z.string().optional(),
  })
  .transform((raw): WordPressOrgPluginInfo => ({
    slug: raw.slug,
    version: raw.version,
    lastUpdated: raw.last_updated,
    activeInstalls: raw.active_installs,
    ...(raw.tested !== undefined ? { tested: raw.tested } : {}),
  }));

/** WordPress.org — latest core/plugin/theme version, last update, active installs, compatibility. Cache TTL: 24h. */
export class WordPressOrgClient {
  static readonly CACHE_TTL_MS = 24 * 60 * 60 * 1000;

  constructor(
    private readonly httpClient: HttpClient,
    private readonly httpClientOptions: HttpClientOptions,
    private readonly cache: CacheStore,
  ) {}

  /**
   * `{ ok: true, value: undefined }` means the slug simply isn't on
   * wordpress.org (closed/premium/custom plugin — a normal outcome, not a
   * failure). `{ ok: false }` means the API itself couldn't be reached or
   * parsed after a retry — the caller should treat that as a degraded
   * enrichment (audit → 'partial'), not "no such plugin".
   */
  async getPluginInfo(slug: string): Promise<Result<WordPressOrgPluginInfo | undefined, Error>> {
    const cacheKey = buildCacheKey('wordpress-org', 'plugin', slug, 'latest');
    const cached = await this.cache.get<WordPressOrgPluginInfo | null>(cacheKey);
    if (cached !== undefined) {
      return ok(cached ?? undefined);
    }

    const result = await this.fetchWithRetry(slug);
    if (!result.ok) {
      return result;
    }

    await this.cache.set(cacheKey, result.value ?? null, WordPressOrgClient.CACHE_TTL_MS);
    return result;
  }

  private async fetchWithRetry(
    slug: string,
  ): Promise<Result<WordPressOrgPluginInfo | undefined, Error>> {
    try {
      return ok(await this.fetchOnce(slug));
    } catch {
      // one retry, per CLAUDE.md's "retry at most once"
    }
    try {
      return ok(await this.fetchOnce(slug));
    } catch (error) {
      return err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  private async fetchOnce(slug: string): Promise<WordPressOrgPluginInfo | undefined> {
    const params = new URLSearchParams({
      action: 'plugin_information',
      'request[slug]': slug,
      'request[fields][active_installs]': '1',
    });
    const response = await this.httpClient.fetchUrl(
      `${PLUGIN_INFO_API}?${params.toString()}`,
      this.httpClientOptions,
    );

    const parsed = JSON.parse(response.body);
    if (parsed === false || parsed === null || (typeof parsed === 'object' && 'error' in parsed)) {
      return undefined;
    }

    return rawPluginResponseSchema.parse(parsed);
  }
}
