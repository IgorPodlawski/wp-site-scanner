import { z } from 'zod';
import type { HttpClient, HttpClientOptions } from '../core/http/http-client.js';
import type { CacheStore } from '../storage/cache-store.js';
import { buildCacheKey } from '../storage/cache-key.js';
import { ok, err, type Result } from '../utils/result.js';
import {
  coreStableVersionsSchema,
  type CoreStableVersions,
  type WordPressOrgPluginInfo,
  type WordPressOrgThemeInfo,
} from './enrichment-types.js';

const PLUGIN_INFO_API = 'https://api.wordpress.org/plugins/info/1.2/';
const THEME_INFO_API = 'https://api.wordpress.org/themes/info/1.2/';
const CORE_STABLE_CHECK_API = 'https://api.wordpress.org/core/stable-check/1.0/';

// wordpress.org's actual wire format (snake_case) — kept local to this
// client rather than in enrichment-types.ts, which holds the clean internal
// shape every caller consumes. `.transform` does the field renaming as part
// of the one Zod validation boundary each external response crosses.
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

const rawThemeResponseSchema = z
  .object({
    slug: z.string(),
    version: z.string(),
    last_updated: z.string(),
    active_installs: z.number().int().nonnegative(),
  })
  .transform((raw): WordPressOrgThemeInfo => ({
    slug: raw.slug,
    version: raw.version,
    lastUpdated: raw.last_updated,
    activeInstalls: raw.active_installs,
  }));

/** wordpress.org's plugin/theme info APIs return `{"error": "..."}` (not a 404) for an unknown slug. */
function isNotFoundResponse(parsed: unknown): boolean {
  return parsed === false || parsed === null || (typeof parsed === 'object' && 'error' in parsed);
}

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
    return this.cached(buildCacheKey('wordpress-org', 'plugin', slug, 'latest'), () =>
      this.withRetry(() => this.fetchPluginOnce(slug)),
    );
  }

  /** Same not-found/failure semantics as {@link getPluginInfo}, for themes. */
  async getThemeInfo(slug: string): Promise<Result<WordPressOrgThemeInfo | undefined, Error>> {
    return this.cached(buildCacheKey('wordpress-org', 'theme', slug, 'latest'), () =>
      this.withRetry(() => this.fetchThemeOnce(slug)),
    );
  }

  /** The full version -> status map from wordpress.org/core/stable-check/. There is no "not found" case here. */
  async getCoreStableVersions(): Promise<Result<CoreStableVersions, Error>> {
    return this.cached(buildCacheKey('wordpress-org', 'core', 'stable-check', 'latest'), () =>
      this.withRetry(() => this.fetchCoreStableVersionsOnce()),
    );
  }

  private async cached<T>(
    cacheKey: string,
    fetch: () => Promise<Result<T, Error>>,
  ): Promise<Result<T, Error>> {
    const cached = await this.cache.get<{ value: T }>(cacheKey);
    if (cached !== undefined) {
      return ok(cached.value);
    }

    const result = await fetch();
    if (result.ok) {
      await this.cache.set(cacheKey, { value: result.value }, WordPressOrgClient.CACHE_TTL_MS);
    }
    return result;
  }

  /** Retries at most once, per CLAUDE.md's "every external API must ... retry at most once". */
  private async withRetry<T>(fetcher: () => Promise<T>): Promise<Result<T, Error>> {
    try {
      return ok(await fetcher());
    } catch {
      // one retry
    }
    try {
      return ok(await fetcher());
    } catch (error) {
      return err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  private async fetchPluginOnce(slug: string): Promise<WordPressOrgPluginInfo | undefined> {
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
    if (isNotFoundResponse(parsed)) return undefined;
    return rawPluginResponseSchema.parse(parsed);
  }

  private async fetchThemeOnce(slug: string): Promise<WordPressOrgThemeInfo | undefined> {
    const params = new URLSearchParams({
      action: 'theme_information',
      'request[slug]': slug,
      'request[fields][active_installs]': '1',
    });
    const response = await this.httpClient.fetchUrl(
      `${THEME_INFO_API}?${params.toString()}`,
      this.httpClientOptions,
    );

    const parsed = JSON.parse(response.body);
    if (isNotFoundResponse(parsed)) return undefined;
    return rawThemeResponseSchema.parse(parsed);
  }

  private async fetchCoreStableVersionsOnce(): Promise<CoreStableVersions> {
    const response = await this.httpClient.fetchUrl(CORE_STABLE_CHECK_API, this.httpClientOptions);
    return coreStableVersionsSchema.parse(JSON.parse(response.body));
  }
}
