import type { AppConfig } from '../config/types.js';
import { UndiciHttpClient, type HttpClientOptions } from '../core/http/http-client.js';
import { FileCacheStore } from '../storage/cache-store.js';
import { resolveCacheDir } from '../storage/paths.js';
import { WordPressOrgClient } from './wordpress-org-client.js';

/** Single place enrichment clients are constructed, mirroring scanners/scanner-registry.ts. */
export function createWordPressOrgClient(config: AppConfig): WordPressOrgClient {
  const httpClientOptions: HttpClientOptions = {
    timeoutMs: config.HTTP_TIMEOUT_MS,
    maxRedirects: config.MAX_REDIRECTS,
    maxResponseBytes: config.MAX_RESPONSE_BYTES,
    userAgent: config.AUDIT_USER_AGENT,
  };
  const cache = new FileCacheStore(resolveCacheDir(config));
  return new WordPressOrgClient(new UndiciHttpClient(), httpClientOptions, cache);
}
