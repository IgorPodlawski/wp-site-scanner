import { describe, expect, it } from 'vitest';
import { HttpScanner } from '@scanners/http-scanner.js';
import { DefaultAuditContext } from '@core/types/audit-context.js';
import { buildTarget } from '@core/types/target.js';
import type { HttpClient, HttpClientOptions, HttpResponse } from '@core/http/http-client.js';

const OPTIONS: HttpClientOptions = {
  timeoutMs: 1000,
  maxRedirects: 5,
  maxResponseBytes: 1_000_000,
  userAgent: 'wp-audit-test/0.1',
};

function createContext(): DefaultAuditContext {
  return new DefaultAuditContext({
    target: buildTarget('https://example.com'),
    authorizationMode: 'prospect',
    profile: 'standard',
    startedAt: new Date(0).toISOString(),
  });
}

describe('HttpScanner', () => {
  it('fetches the target URL and stores the response on the context', async () => {
    const response: HttpResponse = {
      url: 'https://example.com/',
      status: 200,
      headers: { 'content-type': 'text/html' },
      body: '<html></html>',
    };
    const httpClient: HttpClient = { fetchUrl: async () => response };
    const context = createContext();
    const scanner = new HttpScanner(OPTIONS, httpClient);

    const result = await scanner.run(context);

    expect(result.scannerName).toBe('http-scanner');
    expect(result.status).toBe('ok');
    expect(result.data).toEqual({ status: 200, url: 'https://example.com/' });
    expect(context.getHttpResponse()).toBe(response);
  });

  it('fetches using the target normalized URL and the configured options', async () => {
    let receivedUrl: string | undefined;
    let receivedOptions: HttpClientOptions | undefined;
    const httpClient: HttpClient = {
      fetchUrl: async (url, options) => {
        receivedUrl = url;
        receivedOptions = options;
        return { url, status: 200, headers: {}, body: '' };
      },
    };
    const context = createContext();
    const scanner = new HttpScanner(OPTIONS, httpClient);

    await scanner.run(context);

    expect(receivedUrl).toBe('https://example.com/');
    expect(receivedOptions).toEqual(OPTIONS);
  });

  it('propagates http client errors instead of swallowing them', async () => {
    const boom = new Error('boom');
    const httpClient: HttpClient = {
      fetchUrl: async () => {
        throw boom;
      },
    };
    const context = createContext();
    const scanner = new HttpScanner(OPTIONS, httpClient);

    await expect(scanner.run(context)).rejects.toThrow(boom);
    expect(context.getHttpResponse()).toBeUndefined();
  });
});
