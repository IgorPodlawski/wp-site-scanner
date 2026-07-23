import { z } from 'zod';
import type { HttpClient, HttpClientOptions } from '../core/http/http-client.js';
import type { CacheStore } from '../storage/cache-store.js';
import { buildCacheKey } from '../storage/cache-key.js';
import { ok, err, type Result } from '../utils/result.js';
import type { AppConfig } from '../config/types.js';
import type { PageSpeedResult } from './enrichment-types.js';

const PAGESPEED_API = 'https://www.googleapis.com/pagespeedonline/v5/runPagespeed';

// PageSpeed audits a URL by having Google's own infrastructure load it and
// run Lighthouse — this can take 10-20+ seconds, well past the timeout used
// for our own fast lookups against other APIs, so this client uses its own
// timeout rather than the shared HttpClientOptions.timeoutMs.
const PAGESPEED_TIMEOUT_MS = 30_000;

// pagespeedonline/v5's actual wire format — kept local to this client. Two
// independent sources for performance data: `lighthouseResult` is a lab
// measurement (score, 0-1) from this specific run; `loadingExperience` is
// real-user field data (CrUX) and is the actual source for the three
// official Core Web Vitals — it's entirely absent when a URL doesn't have
// enough real-user traffic for Google to report on, so every field here is
// optional.
const rawCruxMetricSchema = z.object({ percentile: z.number() });

const rawPageSpeedResponseSchema = z
  .object({
    lighthouseResult: z.object({
      categories: z.object({
        performance: z.object({ score: z.number().min(0).max(1) }),
      }),
    }),
    loadingExperience: z
      .object({
        metrics: z
          .object({
            LARGEST_CONTENTFUL_PAINT_MS: rawCruxMetricSchema.optional(),
            CUMULATIVE_LAYOUT_SHIFT_SCORE: rawCruxMetricSchema.optional(),
            INTERACTION_TO_NEXT_PAINT: rawCruxMetricSchema.optional(),
          })
          .partial()
          .optional(),
      })
      .optional(),
  })
  .transform((raw): PageSpeedResult => {
    const metrics = raw.loadingExperience?.metrics;
    return {
      performanceScore: Math.round(raw.lighthouseResult.categories.performance.score * 100),
      coreWebVitals: {
        ...(metrics?.LARGEST_CONTENTFUL_PAINT_MS
          ? { lcpMs: metrics.LARGEST_CONTENTFUL_PAINT_MS.percentile }
          : {}),
        // CrUX reports CLS as a percentile scaled by 100 (e.g. 15 -> a 0.15 CLS score).
        ...(metrics?.CUMULATIVE_LAYOUT_SHIFT_SCORE
          ? { clsScore: metrics.CUMULATIVE_LAYOUT_SHIFT_SCORE.percentile / 100 }
          : {}),
        ...(metrics?.INTERACTION_TO_NEXT_PAINT
          ? { inpMs: metrics.INTERACTION_TO_NEXT_PAINT.percentile }
          : {}),
      },
    };
  });

/** PageSpeed — mobile performance, Core Web Vitals. Google fetches the target, not us. Cache TTL: 12h. */
export class PageSpeedClient {
  static readonly CACHE_TTL_MS = 12 * 60 * 60 * 1000;

  constructor(
    private readonly config: Pick<AppConfig, 'PAGESPEED_API_KEY' | 'pagespeedEnabled'>,
    private readonly httpClient: HttpClient,
    private readonly httpClientOptions: HttpClientOptions,
    private readonly cache: CacheStore,
  ) {}

  /**
   * `{ ok: true, value: undefined }` means PageSpeed is disabled
   * (no `PAGESPEED_API_KEY`) — a normal, expected state, not a failure.
   * `{ ok: false }` means the analysis itself failed (Google couldn't load
   * the page, rate limit, etc.) — the caller should degrade to 'partial'.
   */
  async analyze(url: string): Promise<Result<PageSpeedResult | undefined, Error>> {
    const key = this.config.PAGESPEED_API_KEY;
    if (!this.config.pagespeedEnabled || !key) {
      return ok(undefined);
    }

    const cacheKey = buildCacheKey('pagespeed', 'mobile-performance', url, 'latest');
    const cached = await this.cache.get<{ value: PageSpeedResult }>(cacheKey);
    if (cached !== undefined) {
      return ok(cached.value);
    }

    const result = await this.withRetry(() => this.fetchOnce(url, key));
    if (result.ok) {
      await this.cache.set(cacheKey, { value: result.value }, PageSpeedClient.CACHE_TTL_MS);
    }
    return result;
  }

  /** Retries at most once, per CLAUDE.md's "every external API must ... retry at most once". */
  private async withRetry(
    fetcher: () => Promise<PageSpeedResult>,
  ): Promise<Result<PageSpeedResult, Error>> {
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

  private async fetchOnce(url: string, key: string): Promise<PageSpeedResult> {
    const params = new URLSearchParams({
      url,
      key,
      strategy: 'mobile',
      category: 'performance',
    });
    const response = await this.httpClient.fetchUrl(`${PAGESPEED_API}?${params.toString()}`, {
      ...this.httpClientOptions,
      timeoutMs: PAGESPEED_TIMEOUT_MS,
    });

    if (response.status !== 200) {
      throw new Error(`PageSpeed API responded with status ${response.status}`);
    }

    return rawPageSpeedResponseSchema.parse(JSON.parse(response.body));
  }
}
