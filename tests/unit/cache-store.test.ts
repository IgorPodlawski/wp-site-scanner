import { describe, expect, it } from 'vitest';
import { NoopCacheStore } from '@storage/cache-store.js';

describe('NoopCacheStore', () => {
  it('always misses on get, even right after a set — backs --no-cache with a genuine force-refresh', async () => {
    const cache = new NoopCacheStore();

    await cache.set('some-key', { value: 42 }, 1000);

    expect(await cache.get('some-key')).toBeUndefined();
  });
});
