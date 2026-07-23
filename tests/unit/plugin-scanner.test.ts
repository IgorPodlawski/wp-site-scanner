import { describe, expect, it } from 'vitest';
import { PluginScanner } from '@scanners/plugin-scanner.js';
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

describe('PluginScanner', () => {
  it('detects a plugin slug from a /wp-content/plugins/ path with no HTTP client configured', async () => {
    const context = createContext(
      '<script src="/wp-content/plugins/akismet/akismet.js?ver=5.3"></script>',
    );
    const scanner = new PluginScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      plugins: [
        {
          slug: 'akismet',
          version: { value: '5.3', sources: ['asset-query-string'], confidence: 'inferred' },
        },
      ],
    });
  });

  it('deduplicates repeated references to the same plugin slug', async () => {
    const context = createContext(
      '<link href="/wp-content/plugins/akismet/style.css" />' +
        '<script src="/wp-content/plugins/akismet/akismet.js"></script>',
    );
    const scanner = new PluginScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({ plugins: [{ slug: 'akismet' }] });
  });

  it('ignores plain text mentioning no plugin paths', async () => {
    const context = createContext('<html><body>Hello</body></html>');
    const scanner = new PluginScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({ plugins: [] });
  });

  it('does not probe readme.txt under prospect mode even with a client configured', async () => {
    let fetchCalled = false;
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        fetchCalled = true;
        return { url: '', status: 200, headers: {}, body: 'Stable tag: 5.3' };
      },
    };
    const context = createContext('<script src="/wp-content/plugins/akismet/akismet.js"></script>');
    const scanner = new PluginScanner(OPTIONS, httpClient);

    await scanner.run(context);

    expect(fetchCalled).toBe(false);
  });

  it('probes readme.txt under audit mode and confirms an agreeing asset-query version', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async (url) => {
        expect(url).toBe('https://example.com/wp-content/plugins/akismet/readme.txt');
        return { url, status: 200, headers: {}, body: 'Stable tag: 5.3\n' };
      },
    };
    const context = createContext(
      '<script src="/wp-content/plugins/akismet/akismet.js?ver=5.3"></script>',
      'audit',
    );
    const scanner = new PluginScanner(OPTIONS, httpClient);

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      plugins: [
        {
          slug: 'akismet',
          version: {
            value: '5.3',
            sources: ['plugin-readme', 'asset-query-string'],
            confidence: 'confirmed',
          },
        },
      ],
    });
  });

  it('falls back to the readme version alone when the readme fetch fails', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        throw new Error('boom');
      },
    };
    const context = createContext(
      '<script src="/wp-content/plugins/akismet/akismet.js?ver=5.3"></script>',
      'audit',
    );
    const scanner = new PluginScanner(OPTIONS, httpClient);

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      plugins: [
        {
          slug: 'akismet',
          version: { value: '5.3', sources: ['asset-query-string'], confidence: 'inferred' },
        },
      ],
    });
  });
});
