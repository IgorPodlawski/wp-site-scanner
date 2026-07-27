import { z } from 'zod';
import type { HttpClient, HttpClientOptions } from '../core/http/http-client.js';
import type { CacheStore } from '../storage/cache-store.js';
import { buildCacheKey } from '../storage/cache-key.js';
import { ok, err, type Result } from '../utils/result.js';
import { withRetry } from '../utils/retry.js';
import { withCache } from '../utils/cache-helper.js';
import type { AppConfig } from '../config/types.js';
import type { WpscanVulnerability } from './enrichment-types.js';

const WPSCAN_API_BASE = 'https://wpscan.com/api/v3';

type ComponentKind = 'plugins' | 'themes';

/**
 * Distinguished from a generic failure so the client can trip its
 * in-run circuit breaker (see `rateLimited` below) instead of treating
 * this the same as a transient network error worth retrying per-slug.
 */
class WpscanRateLimitError extends Error {
  constructor() {
    super('WPScan API rate limit reached (HTTP 429)');
  }
}

/**
 * WPScan's `cvss` field, when populated, is an object shaped roughly like
 * `{ score: number, vector: string, rating: string }` per WPScan's public
 * v3 docs — but every real vulnerability sampled live this session had
 * `cvss: null` (older, pre-CVSS-tracking entries), so the populated shape
 * is NOT verified against a live example. Extracted defensively (`z.unknown()`
 * + manual numeric check) so a wrong assumption about the shape degrades to
 * "no CVSS score" rather than throwing. Re-verify against a populated
 * example once the free-tier rate limit resets.
 */
function extractCvssScore(rawCvss: unknown): number | undefined {
  if (rawCvss && typeof rawCvss === 'object' && 'score' in rawCvss) {
    const score = (rawCvss as { score: unknown }).score;
    if (typeof score === 'number') return score;
  }
  return undefined;
}

// wpscan.com/api/v3's actual wire format — kept local to this client rather
// than in enrichment-types.ts, which holds the clean internal shape every
// caller consumes.
const rawVulnerabilitySchema = z
  .object({
    id: z.union([z.string(), z.number()]),
    title: z.string(),
    fixed_in: z.string().nullable().optional(),
    introduced_in: z.string().nullable().optional(),
    vuln_type: z.string().nullable().optional(),
    description: z.string().nullable().optional(),
    cvss: z.unknown().optional(),
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
    ...(raw.introduced_in ? { introducedIn: raw.introduced_in } : {}),
    ...(raw.vuln_type ? { vulnType: raw.vuln_type } : {}),
    ...(raw.description ? { description: raw.description } : {}),
    ...(extractCvssScore(raw.cvss) !== undefined ? { cvssScore: extractCvssScore(raw.cvss) } : {}),
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

  /**
   * Tripped for the rest of this client's lifetime (one audit run — a
   * fresh WpscanClient is constructed per CLI invocation) the first time
   * WPScan responds 429. Without this, a `--profile deep` audit-mode run
   * probing dozens of plugin/theme slugs plus core would keep hitting the
   * real API for every remaining slug even after the daily quota was
   * confirmed exhausted — verified live: each of those hits also triggers
   * a "Daily API Limit Reached" notification email from WPScan itself, so
   * one exhausted run without this breaker means dozens of emails, not one.
   */
  private rateLimited = false;

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
    if (this.rateLimited) {
      return err(new WpscanRateLimitError());
    }

    const versionKey = version.replace(/\./g, '');
    const cacheKey = buildCacheKey('wpscan', 'core', versionKey, 'latest');
    const result = await withCache(this.cache, cacheKey, WpscanClient.CACHE_TTL_MS, () =>
      withRetry(() => this.fetchCoreOnce(versionKey, token)),
    );
    this.tripBreakerIfRateLimited(result);
    return result;
  }

  private async getVulnerabilities(
    kind: ComponentKind,
    slug: string,
  ): Promise<Result<WpscanVulnerability[], Error>> {
    const token = this.config.WPSCAN_API_TOKEN;
    if (!this.config.wpscanEnabled || !token) {
      return ok([]);
    }
    if (this.rateLimited) {
      return err(new WpscanRateLimitError());
    }

    const cacheKey = buildCacheKey('wpscan', kind, slug, 'latest');
    const result = await withCache(this.cache, cacheKey, WpscanClient.CACHE_TTL_MS, () =>
      withRetry(() => this.fetchOnce(kind, slug, token)),
    );
    this.tripBreakerIfRateLimited(result);
    return result;
  }

  private tripBreakerIfRateLimited(result: Result<unknown, Error>): void {
    if (!result.ok && result.error instanceof WpscanRateLimitError) {
      this.rateLimited = true;
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
    if (response.status === 429) {
      throw new WpscanRateLimitError();
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
    if (response.status === 429) {
      throw new WpscanRateLimitError();
    }
    if (response.status !== 200) {
      throw new Error(`WPScan API responded with status ${response.status}`);
    }

    const parsed = rawComponentResponseSchema.parse(JSON.parse(response.body));
    const [entry] = Object.values(parsed);
    return entry?.vulnerabilities ?? [];
  }
}
