import { describe, expect, it } from 'vitest';
import { WordPressDetector } from '@scanners/wordpress-detector.js';
import type { DefaultAuditContext } from '@core/types/audit-context.js';
import type { HttpResponse } from '@core/http/http-client.js';
import { buildTestContext, buildHttpResponse } from '../support/test-context.js';

function createContext(response: HttpResponse): DefaultAuditContext {
  const context = buildTestContext();
  context.setHttpResponse(response);
  return context;
}

function htmlResponse(body: string): HttpResponse {
  return buildHttpResponse(body);
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
    const context = buildTestContext();
    const scanner = new WordPressDetector();

    expect(scanner.supports(context)).toBe(false);
  });
});
