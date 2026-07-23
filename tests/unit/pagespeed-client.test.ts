import { describe, expect, it } from 'vitest';
import { PageSpeedClient } from '@integrations/pagespeed-client.js';
import type { CacheStore } from '@storage/cache-store.js';
import type { HttpClient, HttpClientOptions, HttpResponse } from '@core/http/http-client.js';
import type { AppConfig } from '@config/types.js';

const OPTIONS: HttpClientOptions = {
  timeoutMs: 1000,
  maxRedirects: 5,
  maxResponseBytes: 1_000_000,
  userAgent: 'wp-audit-test/0.1',
};

const ENABLED_CONFIG: Pick<AppConfig, 'PAGESPEED_API_KEY' | 'pagespeedEnabled'> = {
  PAGESPEED_API_KEY: 'test-key',
  pagespeedEnabled: true,
};

const DISABLED_CONFIG: Pick<AppConfig, 'PAGESPEED_API_KEY' | 'pagespeedEnabled'> = {
  pagespeedEnabled: false,
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

function jsonResponse(status: number, body: unknown): HttpResponse {
  return { url: '', status, headers: {}, body: JSON.stringify(body) };
}

const RAW_RESPONSE = {
  lighthouseResult: { categories: { performance: { score: 0.7 } } },
  loadingExperience: {
    metrics: {
      LARGEST_CONTENTFUL_PAINT_MS: { percentile: 3104 },
      CUMULATIVE_LAYOUT_SHIFT_SCORE: { percentile: 0 },
      INTERACTION_TO_NEXT_PAINT: { percentile: 127 },
    },
  },
};

describe('PageSpeedClient.analyze', () => {
  it('fetches with mobile strategy and maps the response, scaling score to 0-100', async () => {
    let receivedUrl: string | undefined;
    const httpClient: HttpClient = {
      fetchUrl: async (url) => {
        receivedUrl = url;
        return jsonResponse(200, RAW_RESPONSE);
      },
    };
    const client = new PageSpeedClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    const result = await client.analyze('https://example.com');

    expect(receivedUrl).toContain('strategy=mobile');
    expect(receivedUrl).toContain('url=https%3A%2F%2Fexample.com');
    expect(result).toEqual({
      ok: true,
      value: {
        performanceScore: 70,
        coreWebVitals: { lcpMs: 3104, clsScore: 0, inpMs: 127 },
      },
    });
  });

  it('caches the result so a second call does not refetch', async () => {
    let callCount = 0;
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        callCount += 1;
        return jsonResponse(200, RAW_RESPONSE);
      },
    };
    const client = new PageSpeedClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    await client.analyze('https://example.com');
    await client.analyze('https://example.com');

    expect(callCount).toBe(1);
  });

  it('omits Core Web Vitals fields when loadingExperience (CrUX field data) is entirely absent', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async () =>
        jsonResponse(200, { lighthouseResult: { categories: { performance: { score: 0.42 } } } }),
    };
    const client = new PageSpeedClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    const result = await client.analyze('https://example.com');

    expect(result).toEqual({
      ok: true,
      value: { performanceScore: 42, coreWebVitals: {} },
    });
  });

  it('returns ok(undefined) immediately without any HTTP call when PageSpeed is disabled', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        throw new Error('should not be called when disabled');
      },
    };
    const client = new PageSpeedClient(DISABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    const result = await client.analyze('https://example.com');

    expect(result).toEqual({ ok: true, value: undefined });
  });

  it('retries once on a transient failure and succeeds on the second attempt', async () => {
    let callCount = 0;
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        callCount += 1;
        if (callCount === 1) throw new Error('timeout');
        return jsonResponse(200, RAW_RESPONSE);
      },
    };
    const client = new PageSpeedClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    const result = await client.analyze('https://example.com');

    expect(result.ok).toBe(true);
    expect(callCount).toBe(2);
  });

  it('returns err() without throwing when Lighthouse cannot load the page, after a retry', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async () =>
        jsonResponse(400, {
          error: { message: 'Lighthouse returned error: FAILED_DOCUMENT_REQUEST' },
        }),
    };
    const client = new PageSpeedClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    const result = await client.analyze('https://unreachable.example');

    expect(result.ok).toBe(false);
  });
});
