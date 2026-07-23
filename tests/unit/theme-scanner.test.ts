import { describe, expect, it } from 'vitest';
import { ThemeScanner } from '@scanners/theme-scanner.js';
import { DefaultAuditContext } from '@core/types/audit-context.js';
import { buildTarget } from '@core/types/target.js';
import type { AuthorizationMode } from '@core/types/authorization.js';
import type { HttpClient, HttpClientOptions, HttpResponse } from '@core/http/http-client.js';

const OPTIONS: HttpClientOptions = {
  timeoutMs: 1000,
  maxRedirects: 5,
  maxResponseBytes: 1_000_000,
  userAgent: 'wp-audit-test/0.1',
};

function createContext(body: string, authorizationMode: AuthorizationMode = 'prospect') {
  const context = new DefaultAuditContext({
    target: buildTarget('https://example.com'),
    authorizationMode,
    profile: 'standard',
    startedAt: new Date(0).toISOString(),
  });
  const response: HttpResponse = { url: 'https://example.com/', status: 200, headers: {}, body };
  context.setHttpResponse(response);
  context.setDetectedWordPress(true);
  return context;
}

describe('ThemeScanner', () => {
  it('detects a theme slug from a /wp-content/themes/ path with no HTTP client configured', async () => {
    const context = createContext(
      '<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css?ver=1.2" />',
    );
    const scanner = new ThemeScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      themes: [
        {
          slug: 'twentytwentyfour',
          version: { value: '1.2', sources: ['asset-query-string'], confidence: 'inferred' },
        },
      ],
    });
  });

  it('deduplicates repeated references to the same theme slug', async () => {
    const context = createContext(
      '<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" />' +
        '<script src="/wp-content/themes/twentytwentyfour/script.js"></script>',
    );
    const scanner = new ThemeScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({ themes: [{ slug: 'twentytwentyfour' }] });
  });

  it('ignores plain text mentioning no theme paths', async () => {
    const context = createContext('<html><body>Hello</body></html>');
    const scanner = new ThemeScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({ themes: [] });
  });

  it('does not probe style.css under prospect mode even with a client configured', async () => {
    let fetchCalled = false;
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        fetchCalled = true;
        return { url: '', status: 200, headers: {}, body: 'Version: 1.2' };
      },
    };
    const context = createContext(
      '<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" />',
    );
    const scanner = new ThemeScanner(OPTIONS, httpClient);

    await scanner.run(context);

    expect(fetchCalled).toBe(false);
  });

  it('probes style.css under audit mode and confirms an agreeing asset-query version', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async (url) => {
        expect(url).toBe('https://example.com/wp-content/themes/twentytwentyfour/style.css');
        return {
          url,
          status: 200,
          headers: {},
          body: 'Theme Name: Twenty Twenty-Four\nVersion: 1.2\n',
        };
      },
    };
    const context = createContext(
      '<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css?ver=1.2" />',
      'audit',
    );
    const scanner = new ThemeScanner(OPTIONS, httpClient);

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      themes: [
        {
          slug: 'twentytwentyfour',
          version: {
            value: '1.2',
            sources: ['theme-stylesheet', 'asset-query-string'],
            confidence: 'confirmed',
          },
        },
      ],
    });
  });

  it('falls back to the asset-query version alone when the stylesheet fetch fails', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        throw new Error('boom');
      },
    };
    const context = createContext(
      '<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css?ver=1.2" />',
      'audit',
    );
    const scanner = new ThemeScanner(OPTIONS, httpClient);

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      themes: [
        {
          slug: 'twentytwentyfour',
          version: { value: '1.2', sources: ['asset-query-string'], confidence: 'inferred' },
        },
      ],
    });
  });
});
