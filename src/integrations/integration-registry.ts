import type { AppConfig } from '../config/types.js';
import { UndiciHttpClient, type HttpClientOptions } from '../core/http/http-client.js';
import { FileCacheStore } from '../storage/cache-store.js';
import { resolveCacheDir } from '../storage/paths.js';
import { WordPressOrgClient } from './wordpress-org-client.js';
import { WpscanClient } from './wpscan-client.js';

function buildHttpClientOptions(config: AppConfig): HttpClientOptions {
  return {
    timeoutMs: config.HTTP_TIMEOUT_MS,
    maxRedirects: config.MAX_REDIRECTS,
    maxResponseBytes: config.MAX_RESPONSE_BYTES,
    userAgent: config.AUDIT_USER_AGENT,
  };
}

/** Single place enrichment clients are constructed, mirroring scanners/scanner-registry.ts. */
export function createWordPressOrgClient(config: AppConfig): WordPressOrgClient {
  const cache = new FileCacheStore(resolveCacheDir(config));
  return new WordPressOrgClient(new UndiciHttpClient(), buildHttpClientOptions(config), cache);
}

export function createWpscanClient(config: AppConfig): WpscanClient {
  const cache = new FileCacheStore(resolveCacheDir(config));
  return new WpscanClient(config, new UndiciHttpClient(), buildHttpClientOptions(config), cache);
}
