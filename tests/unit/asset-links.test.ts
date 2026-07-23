import { describe, expect, it } from 'vitest';
import { extractAssetUrls, fetchAssetBodies } from '@core/http/asset-links.js';
import type { HttpClient, HttpClientOptions } from '@core/http/http-client.js';

const OPTIONS: HttpClientOptions = {
  timeoutMs: 1000,
  maxRedirects: 5,
  maxResponseBytes: 1_000_000,
  userAgent: 'wp-audit-test/0.1',
};

describe('extractAssetUrls', () => {
  it('extracts and resolves both <link href> and <script src> assets, dropping any query string', () => {
    const html =
      '<link rel="stylesheet" href="/wp-content/themes/x/style.css?ver=1.0" />' +
      '<script src="https://cdn.example.com/lib.js"></script>';

    const urls = extractAssetUrls(html, 'https://example.com/');

    // The query string is irrelevant to fetching the asset's content (the
    // cache-buster doesn't change what's served) — only the extension match
    // matters here, so it's intentionally not part of the captured URL.
    expect(urls).toEqual([
      'https://example.com/wp-content/themes/x/style.css',
      'https://cdn.example.com/lib.js',
    ]);
  });

  it('deduplicates repeated references to the same asset', () => {
    const html =
      '<script src="/a.js"></script>' + '<script src="/a.js"></script>' + '<link href="/a.js" />';

    expect(extractAssetUrls(html, 'https://example.com/')).toEqual(['https://example.com/a.js']);
  });

  it('ignores non-CSS/JS references and malformed URLs', () => {
    const html = '<img src="/photo.png" /><a href="/page.html">link</a><script src="::not a url">';

    expect(extractAssetUrls(html, 'https://example.com/')).toEqual([]);
  });

  it('returns an empty array when nothing is referenced', () => {
    expect(extractAssetUrls('<html><body>hi</body></html>', 'https://example.com/')).toEqual([]);
  });
});

describe('fetchAssetBodies', () => {
  it('fetches every URL and returns their bodies', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async (url) => ({ url, status: 200, headers: {}, body: `body-of-${url}` }),
    };

    const bodies = await fetchAssetBodies(httpClient, OPTIONS, [
      'https://example.com/a.js',
      'https://example.com/b.css',
    ]);

    expect(bodies).toEqual([
      'body-of-https://example.com/a.js',
      'body-of-https://example.com/b.css',
    ]);
  });

  it('tolerates an individual fetch failure without throwing or dropping the others', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async (url) => {
        if (url.includes('broken')) throw new Error('network error');
        return { url, status: 200, headers: {}, body: 'ok-body' };
      },
    };

    const bodies = await fetchAssetBodies(httpClient, OPTIONS, [
      'https://example.com/broken.js',
      'https://example.com/fine.js',
    ]);

    expect(bodies).toEqual(['ok-body']);
  });

  it('treats a non-200 response the same as a failure', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async (url) => ({ url, status: 404, headers: {}, body: 'not found' }),
    };

    const bodies = await fetchAssetBodies(httpClient, OPTIONS, ['https://example.com/missing.js']);

    expect(bodies).toEqual([]);
  });
});
