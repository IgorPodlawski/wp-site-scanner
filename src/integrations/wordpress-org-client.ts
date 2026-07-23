import { NotImplementedError } from '../core/errors.js';
import type { WordPressOrgPluginInfo } from './enrichment-types.js';

/** WordPress.org — latest core/plugin/theme version, last update, active installs, compatibility. Cache TTL: 24h. */
export class WordPressOrgClient {
  static readonly CACHE_TTL_MS = 24 * 60 * 60 * 1000;

  getPluginInfo(_slug: string): Promise<WordPressOrgPluginInfo> {
    // TODO (Phase 1): fetch + validate via wordPressOrgPluginInfoSchema, timeout + single retry, use cache.
    throw new NotImplementedError('WordPressOrgClient.getPluginInfo (Phase 1 feature work)');
  }
}
