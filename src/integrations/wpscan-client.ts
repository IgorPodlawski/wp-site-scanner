import { NotImplementedError } from '../core/errors.js';
import type { AppConfig } from '../config/types.js';
import type { WpscanVulnerability } from './enrichment-types.js';

/**
 * WPScan vulnerability database API (data lookup only — never the WPScan CLI
 * scanner, which performs active enumeration). Free tier ~100 req/day, so
 * batch runs must lean on the cache. Cache TTL: 7d. Requires WPSCAN_API_TOKEN
 * — when absent, this client is disabled and the run degrades to 'partial'.
 *
 * CVE assertion rule (enforced by the finding engine, not here): a
 * vulnerability from this client may only be asserted as "confirmed
 * applicable" when the component version is `confirmed` AND falls inside
 * the affected range. Otherwise it must be emitted as "potentially
 * affected" with reduced severity.
 */
export class WpscanClient {
  static readonly CACHE_TTL_MS = 7 * 24 * 60 * 60 * 1000;

  constructor(private readonly config: Pick<AppConfig, 'WPSCAN_API_TOKEN' | 'wpscanEnabled'>) {}

  getVulnerabilities(_componentSlug: string, _version: string): Promise<WpscanVulnerability[]> {
    if (!this.config.wpscanEnabled) {
      throw new NotImplementedError('WpscanClient disabled: WPSCAN_API_TOKEN not configured');
    }
    // TODO (Phase 2): fetch + validate via wpscanVulnerabilitySchema, timeout + single retry, use cache.
    throw new NotImplementedError('WpscanClient.getVulnerabilities (Phase 2 feature work)');
  }
}
