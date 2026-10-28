import type { AppConfig } from '../config/types.js';
import { UndiciHttpClient, type HttpClientOptions } from '../core/http/http-client.js';
import { FileCacheStore, NoopCacheStore, type CacheStore } from '../storage/cache-store.js';
import { resolveCacheDir } from '../storage/paths.js';
import { WordPressOrgClient } from './wordpress-org-client.js';
import { WpscanClient } from './wpscan-client.js';
import { PageSpeedClient } from './pagespeed-client.js';
import { PhpVulnerabilityClient } from './php-vulnerability-client.js';

function buildHttpClientOptions(config: AppConfig): HttpClientOptions {
  return {
    timeoutMs: config.HTTP_TIMEOUT_MS,
    maxRedirects: config.MAX_REDIRECTS,
    maxResponseBytes: config.MAX_RESPONSE_BYTES,
    userAgent: config.AUDIT_USER_AGENT,
  };
}

/** `useCache: false` (the CLI's `--no-cache`) backs every enrichment client with a NoopCacheStore instead — a real force-refresh, not just a flag that gets parsed and ignored. */
function buildCache(config: AppConfig, useCache: boolean): CacheStore {
  return useCache ? new FileCacheStore(resolveCacheDir(config)) : new NoopCacheStore();
}

/** Single place enrichment clients are constructed, mirroring scanners/scanner-registry.ts. */
export function createWordPressOrgClient(config: AppConfig, useCache: boolean): WordPressOrgClient {
  const cache = buildCache(config, useCache);
  return new WordPressOrgClient(new UndiciHttpClient(), buildHttpClientOptions(config), cache);
}

export function createWpscanClient(config: AppConfig, useCache: boolean): WpscanClient {
  const cache = buildCache(config, useCache);
  return new WpscanClient(config, new UndiciHttpClient(), buildHttpClientOptions(config), cache);
}

export function createPageSpeedClient(config: AppConfig, useCache: boolean): PageSpeedClient {
  const cache = buildCache(config, useCache);
  return new PageSpeedClient(config, new UndiciHttpClient(), buildHttpClientOptions(config), cache);
}

export function createPhpVulnerabilityClient(
  config: AppConfig,
  useCache: boolean,
): PhpVulnerabilityClient {
  const cache = buildCache(config, useCache);
  return new PhpVulnerabilityClient(
    config.NVD_API_KEY,
    new UndiciHttpClient(),
    buildHttpClientOptions(config),
    cache,
  );
}
