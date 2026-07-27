import { z } from 'zod';
import type { HttpClient, HttpClientOptions } from '../core/http/http-client.js';
import type { CacheStore } from '../storage/cache-store.js';
import { buildCacheKey } from '../storage/cache-key.js';
import { ok, type Result } from '../utils/result.js';
import { withRetry } from '../utils/retry.js';
import { withCache } from '../utils/cache-helper.js';
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

  /**
   * WordPress core, unlike plugins/themes, isn't looked up by slug — verified
   * live against the real API: `GET /wordpresses/{version-with-dots-removed}`
   * (e.g. "6.5.4" -> "654"), and the response is keyed by the canonical
   * dotted version string, not by the numeric key that was requested. Same
   * "not found" (HTTP 404) and wire shape as plugins/themes otherwise.
   */
  async getCoreVulnerabilities(version: string): Promise<Result<WpscanVulnerability[], Error>> {
    const token = this.config.WPSCAN_API_TOKEN;
    if (!this.config.wpscanEnabled || !token) {
      return ok([]);
    }

    const versionKey = version.replace(/\./g, '');
    const cacheKey = buildCacheKey('wpscan', 'core', versionKey, 'latest');
    return withCache(this.cache, cacheKey, WpscanClient.CACHE_TTL_MS, () =>
      withRetry(() => this.fetchCoreOnce(versionKey, token)),
    );
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
    return withCache(this.cache, cacheKey, WpscanClient.CACHE_TTL_MS, () =>
      withRetry(() => this.fetchOnce(kind, slug, token)),
    );
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

  private async fetchCoreOnce(versionKey: string, token: string): Promise<WpscanVulnerability[]> {
    const url = `${WPSCAN_API_BASE}/wordpresses/${encodeURIComponent(versionKey)}`;
    const options: HttpClientOptions = {
      ...this.httpClientOptions,
      headers: { Authorization: `Token token=${token}` },
    };
    const response = await this.httpClient.fetchUrl(url, options);

    if (response.status === 404) {
      return [];
    }
    if (response.status !== 200) {
      throw new Error(`WPScan API responded with status ${response.status}`);
    }

    const parsed = rawComponentResponseSchema.parse(JSON.parse(response.body));
    const [entry] = Object.values(parsed);
    return entry?.vulnerabilities ?? [];
  }
}
