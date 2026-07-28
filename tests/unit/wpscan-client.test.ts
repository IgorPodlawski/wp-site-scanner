import { describe, expect, it } from 'vitest';
import { WpscanClient } from '@integrations/wpscan-client.js';
import type { CacheStore } from '@storage/cache-store.js';
import type { HttpClient, HttpClientOptions, HttpResponse } from '@core/http/http-client.js';
import type { AppConfig } from '@config/types.js';

const OPTIONS: HttpClientOptions = {
  timeoutMs: 1000,
  maxRedirects: 5,
  maxResponseBytes: 1_000_000,
  userAgent: 'wp-audit-test/0.1',
};

const ENABLED_CONFIG: Pick<AppConfig, 'WPSCAN_API_TOKEN' | 'wpscanEnabled'> = {
  WPSCAN_API_TOKEN: 'test-token',
  wpscanEnabled: true,
};

const DISABLED_CONFIG: Pick<AppConfig, 'WPSCAN_API_TOKEN' | 'wpscanEnabled'> = {
  wpscanEnabled: false,
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

const RAW_AKISMET_RESPONSE = {
  akismet: {
    vulnerabilities: [
      {
        id: 12345,
        title: 'Akismet <= 5.0 - Some Vulnerability',
        fixed_in: '5.1',
        references: { cve: ['2024-0001'], url: ['https://example.com/advisory'] },
      },
    ],
  },
};

describe('WpscanClient.getPluginVulnerabilities', () => {
  it('fetches with the Authorization header and maps the response', async () => {
    let receivedOptions: HttpClientOptions | undefined;
    const httpClient: HttpClient = {
      fetchUrl: async (url, options) => {
        expect(url).toBe('https://wpscan.com/api/v3/plugins/akismet');
        receivedOptions = options;
        return jsonResponse(200, RAW_AKISMET_RESPONSE);
      },
    };
    const client = new WpscanClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    const result = await client.getPluginVulnerabilities('akismet');

    expect(receivedOptions?.headers).toEqual({ Authorization: 'Token token=test-token' });
    expect(result).toEqual({
      ok: true,
      value: [
        {
          id: '12345',
          title: 'Akismet <= 5.0 - Some Vulnerability',
          fixedIn: '5.1',
          references: ['CVE-2024-0001', 'https://example.com/advisory'],
        },
      ],
    });
  });

  it('caches the result so a second call does not refetch', async () => {
    let callCount = 0;
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        callCount += 1;
        return jsonResponse(200, RAW_AKISMET_RESPONSE);
      },
    };
    const client = new WpscanClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    await client.getPluginVulnerabilities('akismet');
    await client.getPluginVulnerabilities('akismet');

    expect(callCount).toBe(1);
  });

  it('returns ok([]) when the slug has no known vulnerabilities', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async () => jsonResponse(200, { akismet: { vulnerabilities: [] } }),
    };
    const client = new WpscanClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    const result = await client.getPluginVulnerabilities('akismet');

    expect(result).toEqual({ ok: true, value: [] });
  });

  it('returns ok([]) — not an error — on a 404 (slug unknown to WPScan)', async () => {
    const httpClient: HttpClient = { fetchUrl: async () => jsonResponse(404, {}) };
    const client = new WpscanClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    const result = await client.getPluginVulnerabilities('some-obscure-plugin');

    expect(result).toEqual({ ok: true, value: [] });
  });

  it('returns ok([]) immediately without any HTTP call when WPScan is disabled', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        throw new Error('should not be called when disabled');
      },
    };
    const client = new WpscanClient(DISABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    const result = await client.getPluginVulnerabilities('akismet');

    expect(result).toEqual({ ok: true, value: [] });
  });

  it('retries once on a transient failure and succeeds on the second attempt', async () => {
    let callCount = 0;
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        callCount += 1;
        if (callCount === 1) throw new Error('timeout');
        return jsonResponse(200, RAW_AKISMET_RESPONSE);
      },
    };
    const client = new WpscanClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    const result = await client.getPluginVulnerabilities('akismet');

    expect(result.ok).toBe(true);
    expect(callCount).toBe(2);
  });

  it('returns err() without throwing on a rate-limit/auth failure after a retry', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async () => jsonResponse(429, { error: 'rate limited' }),
    };
    const client = new WpscanClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    const result = await client.getPluginVulnerabilities('akismet');

    expect(result.ok).toBe(false);
  });
});

describe('WpscanClient rate-limit circuit breaker', () => {
  it('stops making HTTP calls for the rest of this run after the first 429, real or verified live (dozens of remaining lookups no longer each trigger a WPScan notification email)', async () => {
    let callCount = 0;
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        callCount += 1;
        return jsonResponse(429, { status: 'rate limit hit' });
      },
    };
    const client = new WpscanClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    const first = await client.getPluginVulnerabilities('akismet');
    expect(first.ok).toBe(false);
    const callsAfterFirstLookup = callCount;
    expect(callsAfterFirstLookup).toBe(2); // withRetry's one retry, both 429

    // Simulate the remaining ~63 slugs a --profile deep audit-mode run would
    // otherwise probe — none of these should reach the network at all.
    for (let i = 0; i < 20; i += 1) {
      const result = await client.getPluginVulnerabilities(`plugin-${i}`);
      expect(result.ok).toBe(false);
    }

    expect(callCount).toBe(callsAfterFirstLookup);
  });

  it('gives the real 429 and the subsequent breaker-skips distinct error messages, so a wall of identical warnings in the log does not look like repeated real attempts', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async () => jsonResponse(429, { status: 'rate limit hit' }),
    };
    const client = new WpscanClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    const first = await client.getPluginVulnerabilities('akismet');
    const second = await client.getPluginVulnerabilities('another-plugin');

    expect(first.ok).toBe(false);
    expect(second.ok).toBe(false);
    if (first.ok || second.ok) throw new Error('unreachable');
    expect(first.error.message).toBe('WPScan API rate limit reached (HTTP 429)');
    expect(second.error.message).toBe(
      'WPScan rate limit already reached this run — skipped without contacting the API',
    );
    expect(first.error.message).not.toBe(second.error.message);
  });

  it('shares the breaker across plugin/theme/core lookups — a 429 on one kind stops all of them', async () => {
    let callCount = 0;
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        callCount += 1;
        return jsonResponse(429, { status: 'rate limit hit' });
      },
    };
    const client = new WpscanClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    await client.getCoreVulnerabilities('6.5.4');
    const callsAfterCore = callCount;

    await client.getPluginVulnerabilities('akismet');
    await client.getThemeVulnerabilities('astra');

    expect(callCount).toBe(callsAfterCore);
  });

  it('serializes concurrent calls fired via Promise.all — the real bug: enrichBySlug fires every plugin lookup concurrently, so a naive boolean flag checked before any response arrives lets the whole first wave through to the real API', async () => {
    let callCount = 0;
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        callCount += 1;
        return jsonResponse(429, { status: 'rate limit hit' });
      },
    };
    const client = new WpscanClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    const slugs = Array.from({ length: 10 }, (_, i) => `plugin-${i}`);
    const results = await Promise.all(slugs.map((slug) => client.getPluginVulnerabilities(slug)));

    expect(results.every((r) => !r.ok)).toBe(true);
    // Only the first call to actually run reaches the network (plus its one
    // retry) — every other one of the 10, even though all 10 were fired at
    // the same instant via Promise.all, must be queued behind it and see
    // the tripped breaker before making a request of their own.
    expect(callCount).toBe(2);
  });

  it('never caches a rate-limited response as if it were a real result', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async () => jsonResponse(429, { status: 'rate limit hit' }),
    };
    const cache = inMemoryCache();
    const client = new WpscanClient(ENABLED_CONFIG, httpClient, OPTIONS, cache);

    await client.getPluginVulnerabilities('akismet');

    expect(await cache.get('wpscan:plugins:akismet:latest')).toBeUndefined();
  });
});

describe('WpscanClient.getThemeVulnerabilities', () => {
  it('fetches from the themes endpoint', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async (url) => {
        expect(url).toBe('https://wpscan.com/api/v3/themes/twentytwentyfour');
        return jsonResponse(200, { twentytwentyfour: { vulnerabilities: [] } });
      },
    };
    const client = new WpscanClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    const result = await client.getThemeVulnerabilities('twentytwentyfour');

    expect(result).toEqual({ ok: true, value: [] });
  });
});

describe('WpscanClient.getCoreVulnerabilities', () => {
  it('requests the dots-stripped version and maps the response, which is keyed by the dotted version', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async (url) => {
        expect(url).toBe('https://wpscan.com/api/v3/wordpresses/654');
        return jsonResponse(200, {
          '6.5.4': {
            vulnerabilities: [
              {
                id: 'abc',
                title: 'WordPress < 6.5.5 - Contributor+ Stored XSS',
                fixed_in: '6.5.5',
                references: { url: ['https://wordpress.org/news/2024/06/wordpress-6-5-5/'] },
              },
            ],
          },
        });
      },
    };
    const client = new WpscanClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    const result = await client.getCoreVulnerabilities('6.5.4');

    expect(result).toEqual({
      ok: true,
      value: [
        {
          id: 'abc',
          title: 'WordPress < 6.5.5 - Contributor+ Stored XSS',
          fixedIn: '6.5.5',
          references: ['https://wordpress.org/news/2024/06/wordpress-6-5-5/'],
        },
      ],
    });
  });

  it('returns ok([]) — not an error — on a 404 (version unknown to WPScan)', async () => {
    const httpClient: HttpClient = { fetchUrl: async () => jsonResponse(404, {}) };
    const client = new WpscanClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    const result = await client.getCoreVulnerabilities('9999.0');

    expect(result).toEqual({ ok: true, value: [] });
  });

  it('returns ok([]) immediately without any HTTP call when WPScan is disabled', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        throw new Error('should not be called when disabled');
      },
    };
    const client = new WpscanClient(DISABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    const result = await client.getCoreVulnerabilities('6.5.4');

    expect(result).toEqual({ ok: true, value: [] });
  });

  it('caches the result so a second call for the same version does not refetch', async () => {
    let callCount = 0;
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        callCount += 1;
        return jsonResponse(200, { '6.5.4': { vulnerabilities: [] } });
      },
    };
    const client = new WpscanClient(ENABLED_CONFIG, httpClient, OPTIONS, inMemoryCache());

    await client.getCoreVulnerabilities('6.5.4');
    await client.getCoreVulnerabilities('6.5.4');

    expect(callCount).toBe(1);
  });
});
