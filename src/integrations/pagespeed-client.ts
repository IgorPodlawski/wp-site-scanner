import { NotImplementedError } from '../core/errors.js';
import type { AppConfig } from '../config/types.js';
import type { PageSpeedResult } from './enrichment-types.js';

/** PageSpeed — mobile performance, Core Web Vitals. Google fetches the target, not us. Cache TTL: 12h. */
export class PageSpeedClient {
  static readonly CACHE_TTL_MS = 12 * 60 * 60 * 1000;

  constructor(private readonly config: Pick<AppConfig, 'PAGESPEED_API_KEY' | 'pagespeedEnabled'>) {}

  analyze(_url: string): Promise<PageSpeedResult> {
    if (!this.config.pagespeedEnabled) {
      throw new NotImplementedError('PageSpeedClient disabled: PAGESPEED_API_KEY not configured');
    }
    // TODO (Phase 2): fetch + validate via pageSpeedResultSchema, timeout + single retry, use cache.
    throw new NotImplementedError('PageSpeedClient.analyze (Phase 2 feature work)');
  }
}
