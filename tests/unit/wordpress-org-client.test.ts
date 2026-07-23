import { describe, expect, it } from 'vitest';
import { WordPressOrgClient } from '@integrations/wordpress-org-client.js';
import type { CacheStore } from '@storage/cache-store.js';
import type { HttpClient, HttpClientOptions, HttpResponse } from '@core/http/http-client.js';

const OPTIONS: HttpClientOptions = {
  timeoutMs: 1000,
  maxRedirects: 5,
  maxResponseBytes: 1_000_000,
  userAgent: 'wp-audit-test/0.1',
};

function inMemoryCache(): CacheStore {
  const store = new Map<string, unknown>();
  return {
    get: async (key) => store.get(key) as never,
    set: async (key, value) => {
      store.set(key, value);
    },
  };
}

function jsonResponse(body: unknown): HttpResponse {
  return { url: '', status: 200, headers: {}, body: JSON.stringify(body) };
}

const RAW_AKISMET = {
  slug: 'akismet',
  version: '5.3.3',
  last_updated: '2024-08-06 3:00pm GMT',
  active_installs: 5_000_000,
  tested: '6.6.1',
};

describe('WordPressOrgClient.getPluginInfo', () => {
  it('fetches, maps snake_case to the internal shape, and caches the result', async () => {
    let callCount = 0;
    const httpClient: HttpClient = {
      fetchUrl: async (url) => {
        callCount += 1;
        expect(url).toBe(
          'https://api.wordpress.org/plugins/info/1.2/?action=plugin_information&request%5Bslug%5D=akismet&request%5Bfields%5D%5Bactive_installs%5D=1',
        );
        return jsonResponse(RAW_AKISMET);
      },
    };
    const cache = inMemoryCache();
    const client = new WordPressOrgClient(httpClient, OPTIONS, cache);

    const result = await client.getPluginInfo('akismet');

    expect(result).toEqual({
      ok: true,
      value: {
        slug: 'akismet',
        version: '5.3.3',
        lastUpdated: '2024-08-06 3:00pm GMT',
        activeInstalls: 5_000_000,
        tested: '6.6.1',
      },
    });
    expect(callCount).toBe(1);

    await client.getPluginInfo('akismet');
    expect(callCount).toBe(1); // second call served from cache, no new fetch
  });

  it('returns ok(undefined) — not an error — when wordpress.org reports the slug does not exist', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async () => jsonResponse({ error: 'Plugin not found.' }),
    };
    const client = new WordPressOrgClient(httpClient, OPTIONS, inMemoryCache());

    const result = await client.getPluginInfo('some-private-plugin');

    expect(result).toEqual({ ok: true, value: undefined });
  });

  it('caches a "not found" result so a second call does not refetch', async () => {
    let callCount = 0;
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        callCount += 1;
        return jsonResponse({ error: 'Plugin not found.' });
      },
    };
    const client = new WordPressOrgClient(httpClient, OPTIONS, inMemoryCache());

    await client.getPluginInfo('some-private-plugin');
    await client.getPluginInfo('some-private-plugin');

    expect(callCount).toBe(1);
  });

  it('retries once on a transient failure and succeeds on the second attempt', async () => {
    let callCount = 0;
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        callCount += 1;
        if (callCount === 1) throw new Error('timeout');
        return jsonResponse(RAW_AKISMET);
      },
    };
    const client = new WordPressOrgClient(httpClient, OPTIONS, inMemoryCache());

    const result = await client.getPluginInfo('akismet');

    expect(result.ok).toBe(true);
    expect(callCount).toBe(2);
  });

  it('returns err() without throwing when both attempts fail, and never caches it', async () => {
    let callCount = 0;
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        callCount += 1;
        throw new Error('connection reset');
      },
    };
    const cache = inMemoryCache();
    const client = new WordPressOrgClient(httpClient, OPTIONS, cache);

    const result = await client.getPluginInfo('akismet');

    expect(result.ok).toBe(false);
    expect(callCount).toBe(2);

    await client.getPluginInfo('akismet');
    expect(callCount).toBe(4); // no cache entry was written, so it retried from scratch
  });

  it('treats a response missing required fields as a failure rather than trusting a malformed shape', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async () => jsonResponse({ slug: 'akismet' }),
    };
    const client = new WordPressOrgClient(httpClient, OPTIONS, inMemoryCache());

    const result = await client.getPluginInfo('akismet');

    expect(result.ok).toBe(false);
  });
});
