import { describe, expect, it } from 'vitest';
import { ThemeScanner } from '@scanners/theme-scanner.js';
import type { AuthorizationMode, IntensityProfile } from '@core/types/authorization.js';
import type { HttpClient } from '@core/http/http-client.js';
import {
  TEST_HTTP_OPTIONS as OPTIONS,
  buildTestContext,
  buildHttpResponse,
} from '../support/test-context.js';

function createContext(
  body: string,
  authorizationMode: AuthorizationMode = 'prospect',
  profile: IntensityProfile = 'standard',
) {
  const context = buildTestContext({ authorizationMode, profile });
  context.setHttpResponse(buildHttpResponse(body));
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

  it('detects a theme slug from a Bedrock /app/themes/ path (wp-content renamed to app)', async () => {
    const context = createContext(
      '<link rel="stylesheet" href="/app/themes/mysite/public/build/app.css?ver=1.2" />',
    );
    const scanner = new ThemeScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      themes: [
        {
          slug: 'mysite',
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

  it('ignores a cache-busting timestamp rewritten onto a theme asset ?ver=', async () => {
    // Real-world regression: the exact same failure mode fixed in
    // CoreVersionScanner (a caching plugin rewriting ?ver= to a Unix
    // timestamp) is equally reachable here — this asserts it stays fixed.
    const context = createContext(
      '<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css?ver=1774442679" />',
    );
    const scanner = new ThemeScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({ themes: [{ slug: 'twentytwentyfour' }] });
  });

  it('ignores a content hash rewritten onto a style.css Version line', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        return { url: '', status: 200, headers: {}, body: 'Version: 85d537c6\n' };
      },
    };
    const context = createContext(
      '<link rel="stylesheet" href="/wp-content/themes/twentytwentyfour/style.css" />',
      'audit',
    );
    const scanner = new ThemeScanner(OPTIONS, httpClient);

    const result = await scanner.run(context);

    expect(result.data).toEqual({ themes: [{ slug: 'twentytwentyfour' }] });
  });

  describe('--profile deep asset scanning', () => {
    it('fetches CSS/JS assets referenced from the homepage and scans them too', async () => {
      const httpClient: HttpClient = {
        fetchUrl: async (url) => {
          if (url === 'https://example.com/app.js') {
            return {
              url,
              status: 200,
              headers: {},
              body: '/* @import url(/wp-content/themes/astra/style.css) */',
            };
          }
          throw new Error(`unexpected fetch: ${url}`);
        },
      };
      const context = createContext('<script src="/app.js"></script>', 'prospect', 'deep');
      const scanner = new ThemeScanner(OPTIONS, httpClient);

      const result = await scanner.run(context);

      expect(result.data).toEqual({ themes: [{ slug: 'astra' }] });
    });

    it('does not fetch any assets at the standard profile', async () => {
      const httpClient: HttpClient = {
        fetchUrl: async () => {
          throw new Error('should not fetch assets outside --profile deep');
        },
      };
      const context = createContext('<script src="/app.js"></script>', 'prospect', 'standard');
      const scanner = new ThemeScanner(OPTIONS, httpClient);

      const result = await scanner.run(context);

      expect(result.data).toEqual({ themes: [] });
    });
  });

  describe('--profile deep dictionary enumeration (Layer 3, audit only)', () => {
    it('discovers a dictionary theme via style.css that Layer 1 never referenced', async () => {
      const httpClient: HttpClient = {
        fetchUrl: async (url) => {
          if (url === 'https://example.com/wp-content/themes/astra/style.css') {
            return { url, status: 200, headers: {}, body: 'Theme Name: Astra\nVersion: 4.6\n' };
          }
          return { url, status: 404, headers: {}, body: 'not found' };
        },
      };
      const context = createContext('<html></html>', 'audit', 'deep');
      const scanner = new ThemeScanner(OPTIONS, httpClient);

      const result = await scanner.run(context);

      expect(result.data).toEqual({
        themes: [
          {
            slug: 'astra',
            version: { value: '4.6', sources: ['theme-stylesheet'], confidence: 'corroborated' },
          },
        ],
      });
    });

    it('does not re-probe a slug Layer 1 already detected', async () => {
      let styleProbeCount = 0;
      const httpClient: HttpClient = {
        fetchUrl: async (url) => {
          if (url.endsWith('/astra/style.css')) styleProbeCount += 1;
          return { url, status: 404, headers: {}, body: 'not found' };
        },
      };
      // Detected via a script tag (not the style.css link) so the deep-profile
      // asset scan and the Layer-2 style.css probe hit different URLs —
      // isolating "dictionary enumeration skips it" from the (harmless,
      // separate) fact that deep-profile asset scanning may itself refetch
      // whatever stylesheet the page happens to link.
      const context = createContext(
        '<script src="/wp-content/themes/astra/theme.js"></script>',
        'audit',
        'deep',
      );
      const scanner = new ThemeScanner(OPTIONS, httpClient);

      const result = await scanner.run(context);

      expect(result.data).toEqual({ themes: [{ slug: 'astra' }] });
      // Layer 1 already found it, so only Layer 2's own probe (not the dictionary) runs.
      expect(styleProbeCount).toBe(1);
    });

    it('does not run dictionary enumeration in prospect mode, even at --profile deep', async () => {
      const httpClient: HttpClient = {
        fetchUrl: async () => {
          throw new Error('dictionary enumeration must never run in prospect mode');
        },
      };
      const context = createContext('<html></html>', 'prospect', 'deep');
      const scanner = new ThemeScanner(OPTIONS, httpClient);

      const result = await scanner.run(context);

      expect(result.data).toEqual({ themes: [] });
    });

    it('does not run dictionary enumeration at the standard profile, even in audit mode', async () => {
      const httpClient: HttpClient = {
        fetchUrl: async () => {
          throw new Error('dictionary enumeration must never run outside --profile deep');
        },
      };
      const context = createContext('<html></html>', 'audit', 'standard');
      const scanner = new ThemeScanner(OPTIONS, httpClient);

      const result = await scanner.run(context);

      expect(result.data).toEqual({ themes: [] });
    });
  });
});
