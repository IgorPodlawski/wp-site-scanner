import type { CacheStore } from '../storage/cache-store.js';
import { ok, type Result } from './result.js';

/**
 * Checks the cache first; on a miss, calls `fetch` and populates the cache
 * only on success (a failed fetch is never cached, so the next call retries
 * against the real API rather than replaying a stale failure).
 */
export async function withCache<T>(
  cache: CacheStore,
  cacheKey: string,
  ttlMs: number,
  fetch: () => Promise<Result<T, Error>>,
): Promise<Result<T, Error>> {
  const cached = await cache.get<{ value: T }>(cacheKey);
  if (cached !== undefined) {
    return ok(cached.value);
  }

  const result = await fetch();
  if (result.ok) {
    await cache.set(cacheKey, { value: result.value }, ttlMs);
  }
  return result;
}
