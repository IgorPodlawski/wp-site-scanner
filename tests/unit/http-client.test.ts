import { describe, expect, it } from 'vitest';
import { EventEmitter } from 'node:events';
import { MockAgent } from 'undici';
import { UndiciHttpClient, destroyQuietly } from '@core/http/http-client.js';
import { SsrfRejectedError, UnreachableTargetError } from '@core/errors.js';

const BASE_OPTIONS = {
  timeoutMs: 1000,
  maxRedirects: 3,
  maxResponseBytes: 1_000,
  userAgent: 'wp-audit-test/1.0 (+https://example.com/about-this-scan)',
};

/**
 * Production creates a fresh, resolvedIp-pinned Agent per hop and the client
 * closes it after each one. Tests reuse a single MockAgent across hops (its
 * interceptors are configured up front), so `.close()` must be a no-op here
 * to avoid tearing down the shared mock between redirect hops.
 */
function nonClosingDispatcher(mockAgent: MockAgent) {
  return new Proxy(mockAgent, {
    get(target, prop, receiver) {
      if (prop === 'close') return async () => {};
      return Reflect.get(target, prop, receiver);
    },
  });
}

function clientWithMockAgent(mockAgent: MockAgent, resolvedIp = '203.0.113.10') {
  return new UndiciHttpClient(
    async () => [resolvedIp],
    () => nonClosingDispatcher(mockAgent),
  );
}

function neverCalled(label: string): never {
  throw new Error(`${label} should not have been called`);
}

describe('UndiciHttpClient', () => {
  it('fetches a URL and returns status, headers and body', async () => {
    const mockAgent = new MockAgent();
    mockAgent.disableNetConnect();
    mockAgent
      .get('https://example.com')
      .intercept({ path: '/', method: 'GET' })
      .reply(200, '<html>hi</html>', { headers: { 'content-type': 'text/html' } });

    const client = clientWithMockAgent(mockAgent);
    const response = await client.fetchUrl('https://example.com/', BASE_OPTIONS);

    expect(response.status).toBe(200);
    expect(response.body).toBe('<html>hi</html>');
    expect(response.headers['content-type']).toBe('text/html');
    expect(response.url).toBe('https://example.com/');
  });

  it('follows redirects up to maxRedirects and returns the final response', async () => {
    const mockAgent = new MockAgent();
    mockAgent.disableNetConnect();
    mockAgent
      .get('https://example.com')
      .intercept({ path: '/old', method: 'GET' })
      .reply(301, '', { headers: { location: 'https://example.com/new' } });
    mockAgent
      .get('https://example.com')
      .intercept({ path: '/new', method: 'GET' })
      .reply(200, 'landed');

    const client = clientWithMockAgent(mockAgent);
    const response = await client.fetchUrl('https://example.com/old', BASE_OPTIONS);

    expect(response.status).toBe(200);
    expect(response.body).toBe('landed');
    expect(response.url).toBe('https://example.com/new');
  });

  it('rejects a redirect hop that lands on a blocked address', async () => {
    const mockAgent = new MockAgent();
    mockAgent.disableNetConnect();
    mockAgent
      .get('https://example.com')
      .intercept({ path: '/', method: 'GET' })
      .reply(302, '', { headers: { location: 'http://169.254.169.254/latest/meta-data' } });

    const client = clientWithMockAgent(mockAgent);
    await expect(client.fetchUrl('https://example.com/', BASE_OPTIONS)).rejects.toThrow(
      SsrfRejectedError,
    );
  });

  it('throws when redirects exceed maxRedirects', async () => {
    const mockAgent = new MockAgent();
    mockAgent.disableNetConnect();
    const pool = mockAgent.get('https://example.com');
    for (let hop = 0; hop <= BASE_OPTIONS.maxRedirects + 1; hop += 1) {
      pool
        .intercept({ path: `/hop-${hop}`, method: 'GET' })
        .reply(302, '', { headers: { location: `https://example.com/hop-${hop + 1}` } });
    }

    const client = clientWithMockAgent(mockAgent);
    await expect(client.fetchUrl('https://example.com/hop-0', BASE_OPTIONS)).rejects.toThrow(
      UnreachableTargetError,
    );
  });

  it('throws when the response body exceeds maxResponseBytes', async () => {
    const mockAgent = new MockAgent();
    mockAgent.disableNetConnect();
    mockAgent
      .get('https://example.com')
      .intercept({ path: '/', method: 'GET' })
      .reply(200, 'x'.repeat(BASE_OPTIONS.maxResponseBytes + 1));

    const client = clientWithMockAgent(mockAgent);
    await expect(client.fetchUrl('https://example.com/', BASE_OPTIONS)).rejects.toThrow(
      UnreachableTargetError,
    );
  });

  it('rejects before connecting when the URL itself is a blocked literal IP', async () => {
    const client = new UndiciHttpClient(
      () => neverCalled('resolveHostname'),
      () => neverCalled('createDispatcher'),
    );

    await expect(client.fetchUrl('http://127.0.0.1/', BASE_OPTIONS)).rejects.toThrow(
      SsrfRejectedError,
    );
  });

  it('rejects when the hostname resolves to a blocked address (DNS rebinding)', async () => {
    const client = new UndiciHttpClient(
      async () => ['10.0.0.5'],
      () => neverCalled('createDispatcher'),
    );

    await expect(client.fetchUrl('https://example.com/', BASE_OPTIONS)).rejects.toThrow(
      SsrfRejectedError,
    );
  });
});

describe('destroyQuietly', () => {
  it('attaches a listener so an async error emitted after destroy does not crash the process', () => {
    // Regression: undici's BodyReadable can emit an 'error' event (e.g.
    // UND_ERR_ABORTED) asynchronously after .destroy() on a body that was
    // never fully consumed (the redirect-handling path never reads the
    // body at all). With zero listeners, Node's EventEmitter throws
    // synchronously on 'error' — exactly the crash this guards against.
    const body = Object.assign(new EventEmitter(), { destroy: () => {} });

    destroyQuietly(body as never);

    expect(() => body.emit('error', new Error('UND_ERR_ABORTED'))).not.toThrow();
  });
});
