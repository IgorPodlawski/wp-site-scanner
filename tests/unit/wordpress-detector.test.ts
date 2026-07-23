import { describe, expect, it } from 'vitest';
import { WordPressDetector } from '@scanners/wordpress-detector.js';
import { DefaultAuditContext } from '@core/types/audit-context.js';
import { buildTarget } from '@core/types/target.js';
import type { HttpResponse } from '@core/http/http-client.js';

function createContext(response: HttpResponse): DefaultAuditContext {
  const context = new DefaultAuditContext({
    target: buildTarget('https://example.com'),
    authorizationMode: 'prospect',
    profile: 'standard',
    startedAt: new Date(0).toISOString(),
  });
  context.setHttpResponse(response);
  return context;
}

function htmlResponse(body: string): HttpResponse {
  return { url: 'https://example.com/', status: 200, headers: {}, body };
}

describe('WordPressDetector', () => {
  it('detects WordPress from the generator meta tag', async () => {
    const context = createContext(
      htmlResponse('<html><head><meta name="generator" content="WordPress 6.5" /></head></html>'),
    );
    const scanner = new WordPressDetector();

    const result = await scanner.run(context);

    expect(result.status).toBe('ok');
    expect(context.isWordPress()).toBe(true);
    expect(result.data).toEqual({ isWordPress: true, matchedSignals: ['generator-meta'] });
  });

  it('detects WordPress from /wp-content/ asset paths when the generator tag is absent', async () => {
    const context = createContext(
      htmlResponse(
        '<html><head><link rel="stylesheet" href="/wp-content/themes/x/style.css" /></head></html>',
      ),
    );
    const scanner = new WordPressDetector();

    await scanner.run(context);

    expect(context.isWordPress()).toBe(true);
  });

  it('reports non-WordPress sites as such, without any false-positive signal', async () => {
    const context = createContext(
      htmlResponse('<html><head><title>Just a plain site</title></head><body>Hello</body></html>'),
    );
    const scanner = new WordPressDetector();

    const result = await scanner.run(context);

    expect(context.isWordPress()).toBe(false);
    expect(result.data).toEqual({ isWordPress: false, matchedSignals: [] });
  });

  it('supports() is false until the HTTP response has been fetched', () => {
    const context = new DefaultAuditContext({
      target: buildTarget('https://example.com'),
      authorizationMode: 'prospect',
      profile: 'standard',
      startedAt: new Date(0).toISOString(),
    });
    const scanner = new WordPressDetector();

    expect(scanner.supports(context)).toBe(false);
  });
});
