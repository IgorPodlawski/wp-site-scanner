import { describe, expect, it } from 'vitest';
import { CoreVersionScanner } from '@scanners/core-version-scanner.js';
import { DefaultAuditContext } from '@core/types/audit-context.js';
import { buildTarget } from '@core/types/target.js';
import type { HttpResponse } from '@core/http/http-client.js';

function createContext(body: string): DefaultAuditContext {
  const context = new DefaultAuditContext({
    target: buildTarget('https://example.com'),
    authorizationMode: 'prospect',
    profile: 'standard',
    startedAt: new Date(0).toISOString(),
  });
  const response: HttpResponse = { url: 'https://example.com/', status: 200, headers: {}, body };
  context.setHttpResponse(response);
  context.setDetectedWordPress(true);
  return context;
}

describe('CoreVersionScanner', () => {
  it('reaches confirmed when generator meta and asset query string agree', async () => {
    const context = createContext(
      '<meta name="generator" content="WordPress 6.5.2" />' +
        '<script src="/wp-includes/js/wp-embed.min.js?ver=6.5.2"></script>',
    );
    const scanner = new CoreVersionScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      version: {
        value: '6.5.2',
        sources: ['generator-meta', 'asset-query-string'],
        confidence: 'confirmed',
      },
    });
  });

  it('caps a lone generator meta tag at corroborated', async () => {
    const context = createContext('<meta name="generator" content="WordPress 6.5.2" />');
    const scanner = new CoreVersionScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      version: { value: '6.5.2', sources: ['generator-meta'], confidence: 'corroborated' },
    });
  });

  it('caps a lone asset query string at inferred (cache-busters lie)', async () => {
    const context = createContext(
      '<script src="/wp-includes/js/wp-embed.min.js?ver=6.4.0"></script>',
    );
    const scanner = new CoreVersionScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      version: { value: '6.4.0', sources: ['asset-query-string'], confidence: 'inferred' },
    });
  });

  it('drops the asset query string when it conflicts with the generator meta tag', async () => {
    const context = createContext(
      '<meta name="generator" content="WordPress 6.5.2" />' +
        '<script src="/wp-includes/js/wp-embed.min.js?ver=6.4.0"></script>',
    );
    const scanner = new CoreVersionScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({
      version: { value: '6.5.2', sources: ['generator-meta'], confidence: 'corroborated' },
    });
  });

  it('returns no version when neither signal is present', async () => {
    const context = createContext('<html><body>Hello</body></html>');
    const scanner = new CoreVersionScanner();

    const result = await scanner.run(context);

    expect(result.data).toEqual({ version: undefined });
  });

  it('supports() is false until WordPress has been detected', () => {
    const freshContext = new DefaultAuditContext({
      target: buildTarget('https://example.com'),
      authorizationMode: 'prospect',
      profile: 'standard',
      startedAt: new Date(0).toISOString(),
    });
    const scanner = new CoreVersionScanner();

    expect(scanner.supports(freshContext)).toBe(false);
  });
});
