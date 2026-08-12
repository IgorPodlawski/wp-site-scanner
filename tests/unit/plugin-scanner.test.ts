import { describe, expect, it } from 'vitest';
import { PluginScanner } from '@scanners/plugin-scanner.js';
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

  it('detects a plugin slug from a Bedrock /app/plugins/ path (wp-content renamed to app)', async () => {
    const context = createContext(
      '<script src="/app/plugins/akismet/akismet.js?ver=5.3"></script>',
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

  it('probes the Bedrock readme.txt path (/app/plugins/...) once Layer 1 evidence shows app/ is the content root in use', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async (url) => {
        expect(url).toBe('https://example.com/app/plugins/akismet/readme.txt');
        return { url, status: 200, headers: {}, body: 'Stable tag: 5.3\n' };
      },
    };
    const context = createContext(
      '<script src="/app/plugins/akismet/akismet.js?ver=5.3"></script>',
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

  it('ignores a cache-busting timestamp rewritten onto a plugin asset ?ver=', async () => {
    // Real-world regression: the exact same failure mode fixed in
    // CoreVersionScanner (a caching plugin rewriting ?ver= to a Unix
    // timestamp) is equally reachable here — this asserts it stays fixed.
    const context = createContext(
      '<script src="/wp-content/plugins/akismet/akismet.js?ver=1774442679"></script>',
    );
    const scanner = new PluginScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({ plugins: [{ slug: 'akismet' }] });
  });

  it('ignores a content hash rewritten onto a readme.txt Stable tag line', async () => {
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        return { url: '', status: 200, headers: {}, body: 'Stable tag: 85d537c6\n' };
      },
    };
    const context = createContext(
      '<script src="/wp-content/plugins/akismet/akismet.js"></script>',
      'audit',
    );
    const scanner = new PluginScanner(OPTIONS, httpClient);

    const result = await scanner.run(context);

    expect(result.data).toEqual({ plugins: [{ slug: 'akismet' }] });
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
              body: '/* @import url(/wp-content/plugins/akismet/style.css) */',
            };
          }
          throw new Error(`unexpected fetch: ${url}`);
        },
      };
      const context = createContext('<script src="/app.js"></script>', 'prospect', 'deep');
      const scanner = new PluginScanner(OPTIONS, httpClient);

      const result = await scanner.run(context);

      expect(result.data).toEqual({ plugins: [{ slug: 'akismet' }] });
    });

    it('does not fetch any assets at the standard profile', async () => {
      const httpClient: HttpClient = {
        fetchUrl: async () => {
          throw new Error('should not fetch assets outside --profile deep');
        },
      };
      const context = createContext('<script src="/app.js"></script>', 'prospect', 'standard');
      const scanner = new PluginScanner(OPTIONS, httpClient);

      const result = await scanner.run(context);

      expect(result.data).toEqual({ plugins: [] });
    });
  });

  describe('--profile deep dictionary enumeration (Layer 3, audit only)', () => {
    it('discovers a dictionary plugin via readme.txt that Layer 1 never referenced', async () => {
      const httpClient: HttpClient = {
        fetchUrl: async (url) => {
          if (url === 'https://example.com/wp-content/plugins/woocommerce/readme.txt') {
            return { url, status: 200, headers: {}, body: 'Stable tag: 8.0\n' };
          }
          return { url, status: 404, headers: {}, body: 'not found' };
        },
      };
      const context = createContext('<html></html>', 'audit', 'deep');
      const scanner = new PluginScanner(OPTIONS, httpClient);

      const result = await scanner.run(context);

      expect(result.data).toEqual({
        plugins: [
          {
            slug: 'woocommerce',
            version: { value: '8.0', sources: ['plugin-readme'], confidence: 'corroborated' },
          },
        ],
      });
    });

    it('uses the site-wide content root Layer 1 already detected (app/) for dictionary probing too, not wp-content', async () => {
      const httpClient: HttpClient = {
        fetchUrl: async (url) => {
          if (url === 'https://example.com/app/plugins/woocommerce/readme.txt') {
            return { url, status: 200, headers: {}, body: 'Stable tag: 8.0\n' };
          }
          if (url.includes('/wp-content/')) {
            throw new Error(
              'must not probe wp-content once app/ is known to be the real content root',
            );
          }
          return { url, status: 404, headers: {}, body: 'not found' };
        },
      };
      // Layer 1 sees only akismet under app/ — that alone establishes app/
      // as this site's content root for every subsequent probe, including
      // Layer 3 dictionary candidates like woocommerce that Layer 1 itself
      // never referenced.
      const context = createContext(
        '<script src="/app/plugins/akismet/akismet.js"></script>',
        'audit',
        'deep',
      );
      const scanner = new PluginScanner(OPTIONS, httpClient);

      const result = await scanner.run(context);

      const slugs = (result.data as { plugins: Array<{ slug: string }> }).plugins.map(
        (p) => p.slug,
      );
      expect(slugs).toContain('akismet');
      expect(slugs).toContain('woocommerce');
    });

    it('does not re-probe a slug Layer 1 already detected', async () => {
      let woocommerceProbeCount = 0;
      const httpClient: HttpClient = {
        fetchUrl: async (url) => {
          if (url.includes('/woocommerce/readme.txt')) woocommerceProbeCount += 1;
          return { url, status: 404, headers: {}, body: 'not found' };
        },
      };
      const context = createContext(
        '<script src="/wp-content/plugins/woocommerce/app.js"></script>',
        'audit',
        'deep',
      );
      const scanner = new PluginScanner(OPTIONS, httpClient);

      const result = await scanner.run(context);

      expect(result.data).toEqual({ plugins: [{ slug: 'woocommerce' }] });
      // Layer 1 already found it, then Layer 2's own readme probe (not the dictionary) runs once.
      expect(woocommerceProbeCount).toBe(1);
    });

    it('does not run dictionary enumeration in prospect mode, even at --profile deep', async () => {
      const httpClient: HttpClient = {
        fetchUrl: async () => {
          throw new Error('dictionary enumeration must never run in prospect mode');
        },
      };
      const context = createContext('<html></html>', 'prospect', 'deep');
      const scanner = new PluginScanner(OPTIONS, httpClient);

      const result = await scanner.run(context);

      expect(result.data).toEqual({ plugins: [] });
    });

    it('does not run dictionary enumeration at the standard profile, even in audit mode', async () => {
      const httpClient: HttpClient = {
        fetchUrl: async () => {
          throw new Error('dictionary enumeration must never run outside --profile deep');
        },
      };
      const context = createContext('<html></html>', 'audit', 'standard');
      const scanner = new PluginScanner(OPTIONS, httpClient);

      const result = await scanner.run(context);

      expect(result.data).toEqual({ plugins: [] });
    });
  });
});
