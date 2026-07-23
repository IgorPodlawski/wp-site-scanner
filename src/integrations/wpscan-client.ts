import { z } from 'zod';
import type { HttpClient, HttpClientOptions } from '../core/http/http-client.js';
import type { CacheStore } from '../storage/cache-store.js';
import { buildCacheKey } from '../storage/cache-key.js';
import { ok, err, type Result } from '../utils/result.js';
import type { AppConfig } from '../config/types.js';
import type { WpscanVulnerability } from './enrichment-types.js';

const WPSCAN_API_BASE = 'https://wpscan.com/api/v3';

type ComponentKind = 'plugins' | 'themes';

// wpscan.com/api/v3's actual wire format — kept local to this client rather
// than in enrichment-types.ts, which holds the clean internal shape every
// caller consumes. NOTE: unlike wordpress-org-client.ts, this has not been
// smoke-tested against a live response (no WPSCAN_API_TOKEN was available
// while building it) — verify against a real token before relying on it.
const rawVulnerabilitySchema = z
  .object({
    id: z.union([z.string(), z.number()]),
    title: z.string(),
    fixed_in: z.string().nullable().optional(),
    references: z
      .object({
        url: z.array(z.string()).optional(),
        cve: z.array(z.string()).optional(),
      })
      .partial()
      .optional(),
  })
  .transform((raw): WpscanVulnerability => ({
    id: String(raw.id),
    title: raw.title,
    ...(raw.fixed_in ? { fixedIn: raw.fixed_in } : {}),
    references: [
      ...(raw.references?.cve?.map((cve) => `CVE-${cve}`) ?? []),
      ...(raw.references?.url ?? []),
    ],
  }));

// Response is keyed by the requested slug: { "<slug>": { vulnerabilities: [...], ... } }
const rawComponentResponseSchema = z.record(
  z.string(),
  z.object({ vulnerabilities: z.array(rawVulnerabilitySchema).default([]) }).passthrough(),
);

/**
 * WPScan vulnerability database API (data lookup only — never the WPScan CLI
 * scanner, which performs active enumeration). Free tier ~100 req/day, so
 * batch runs must lean on the cache. Cache TTL: 7d. Requires WPSCAN_API_TOKEN
 * — when absent, every call returns `ok([])` immediately (enrichment simply
 * skipped, never a failure). Audit-mode only per CLAUDE.md — the orchestrator
 * enforces that, not this client.
 *
 * CVE assertion rule (enforced by the finding engine, not here): a
 * vulnerability from this client may only be asserted as "confirmed
 * applicable" when the component version is `confirmed` AND falls inside
 * the affected range. Otherwise it must be emitted as "potentially
 * affected" with reduced severity. Never present a CVE as confirmed off an
 * `inferred` version.
 */
export class WpscanClient {
  static readonly CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

  constructor(
    private readonly config: Pick<AppConfig, 'WPSCAN_API_TOKEN' | 'wpscanEnabled'>,
    private readonly httpClient: HttpClient,
    private readonly httpClientOptions: HttpClientOptions,
    private readonly cache: CacheStore,
  ) {}

  async getPluginVulnerabilities(slug: string): Promise<Result<WpscanVulnerability[], Error>> {
    return this.getVulnerabilities('plugins', slug);
  }

  async getThemeVulnerabilities(slug: string): Promise<Result<WpscanVulnerability[], Error>> {
    return this.getVulnerabilities('themes', slug);
  }

  private async getVulnerabilities(
    kind: ComponentKind,
    slug: string,
  ): Promise<Result<WpscanVulnerability[], Error>> {
    const token = this.config.WPSCAN_API_TOKEN;
    if (!this.config.wpscanEnabled || !token) {
      return ok([]);
    }

    const cacheKey = buildCacheKey('wpscan', kind, slug, 'latest');
    const cached = await this.cache.get<{ value: WpscanVulnerability[] }>(cacheKey);
    if (cached !== undefined) {
      return ok(cached.value);
    }

    const result = await this.withRetry(() => this.fetchOnce(kind, slug, token));
    if (result.ok) {
      await this.cache.set(cacheKey, { value: result.value }, WpscanClient.CACHE_TTL_MS);
    }
    return result;
  }

  private async withRetry(
    fetcher: () => Promise<WpscanVulnerability[]>,
  ): Promise<Result<WpscanVulnerability[], Error>> {
    try {
      return ok(await fetcher());
    } catch {
      // one retry, per CLAUDE.md's "retry at most once"
    }
    try {
      return ok(await fetcher());
    } catch (error) {
      return err(error instanceof Error ? error : new Error(String(error)));
    }
  }

  private async fetchOnce(
    kind: ComponentKind,
    slug: string,
    token: string,
  ): Promise<WpscanVulnerability[]> {
    const url = `${WPSCAN_API_BASE}/${kind}/${encodeURIComponent(slug)}`;
    const options: HttpClientOptions = {
      ...this.httpClientOptions,
      headers: { Authorization: `Token token=${token}` },
    };
    const response = await this.httpClient.fetchUrl(url, options);

    // Treat "unknown to WPScan" the same as "no known vulnerabilities" — both
    // mean there is nothing to report, matching "false positives are worse
    // than misses". Only a genuine error status triggers retry/failure.
    if (response.status === 404) {
      return [];
    }
    if (response.status !== 200) {
      throw new Error(`WPScan API responded with status ${response.status}`);
    }

    const parsed = rawComponentResponseSchema.parse(JSON.parse(response.body));
    return parsed[slug]?.vulnerabilities ?? [];
  }
}
